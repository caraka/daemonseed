use super::*;

use std::collections::HashSet;
use std::sync::{Condvar, Mutex, MutexGuard};

use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
use daemonseed_core::identity::mnemonic::Mnemonic;

/// The longest one wait for an event runs under a paused clock.
const PAUSED_BUDGET: Duration = Duration::from_secs(6 * 60 * 60);

/// The longest one wait for an event runs under the real clock.
const REAL_BUDGET: Duration = Duration::from_secs(120);

/// The record kinds the fake network addresses.
const ADVERT: u8 = 0;
const DROP: u8 = 1;
const CHANNEL: u8 = 2;

/// A subkey of a record: its kind, the 32 bytes naming the record, the subkey.
type Key = (u8, [u8; 32], u16);

/// A record store's refusal, for fault injection.
#[derive(Debug)]
struct Refused;

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the fake record store refused this call")
    }
}

impl core::error::Error for Refused {}

/// A record store call that ran out of time, for fault injection.
#[derive(Debug)]
struct TimedOut;

impl core::fmt::Display for TimedOut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the fake record store call ran out of time")
    }
}

impl core::error::Error for TimedOut {}

/// A record store call refused before it reached the network, for fault
/// injection.
#[derive(Debug)]
struct LocalRefusal(u8);

impl core::fmt::Display for LocalRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the fake record store refused this call before the network")
    }
}

impl core::error::Error for LocalRefusal {}

/// The record store operation a planned fault lands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Read,
    Inspect,
    Write,
    Open,
    Erase,
    /// The drop inspect a scan takes before its first slot read.
    Scan,
}

/// How a planned fault fails the call it lands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    TimedOut,
    Refused,
    Local,
    /// Refused before the network, for a reason other than [`Fault::Local`]'s.
    LocalOther,
}

/// The error a planned fault fails its call with.
fn fault_error(fault: Fault) -> RecordError {
    match fault {
        Fault::TimedOut => RecordError::new(TimedOut),
        Fault::Refused => RecordError::new(Refused),
        Fault::Local => RecordError::new(LocalRefusal(0)),
        Fault::LocalOther => RecordError::new(LocalRefusal(1)),
    }
}

/// The network every fake in one test shares: each subkey's bytes and the
/// sequence number of the write that put them there.
#[derive(Default)]
struct Dht {
    records: HashMap<Key, (Vec<u8>, u64)>,
    writes: u64,
    /// Every value ever written, in order, with the subkey it was written to.
    written: Vec<(Key, Vec<u8>)>,
}

impl Dht {
    fn put(&mut self, key: Key, bytes: Vec<u8>) -> u64 {
        self.written.push((key, bytes.clone()));
        self.writes += 1;
        self.records.insert(key, (bytes, self.writes));
        self.writes
    }

    /// Lose a subkey from the network. Whoever wrote it keeps its local copy.
    fn evict(&mut self, key: Key) {
        assert!(
            self.records.remove(&key).is_some(),
            "an eviction names a subkey the network holds"
        );
    }

    /// Another writer's bytes over a subkey, at a higher sequence number than
    /// any node's local copy.
    fn clobber(&mut self, key: Key) {
        assert!(
            self.records.contains_key(&key),
            "a clobber names a held subkey"
        );
        self.put(key, vec![0x5a; 16]);
    }
}

/// One node's local copies: the sequence number and bytes of every subkey it
/// wrote. It outlives a runner, as a node's own storage does.
#[derive(Default)]
struct Node {
    local: HashMap<Key, (u64, Vec<u8>)>,
}

/// What one runner's fake was asked to do. Writes are counted as attempts.
#[derive(Debug, Default, Clone, Copy)]
struct Calls {
    drop_reads: usize,
    hello_writes: usize,
    ring_writes: usize,
    control_writes: usize,
    advert_publishes: usize,
    open_channel: usize,
    channel_reads: usize,
    inspect_channel: usize,
    inspect_advert: usize,
    inspect_drop: usize,
}

/// A barrier a record call waits at until the test releases it.
#[derive(Default)]
struct Gate {
    /// (a call has reached the gate, the test has released it)
    state: Mutex<(bool, bool)>,
    turned: Condvar,
}

impl Gate {
    fn hold(&self) {
        let mut state = self.state.lock().expect("the gate lock");
        state.0 = true;
        self.turned.notify_all();
        while !state.1 {
            state = self.turned.wait(state).expect("the gate lock");
        }
    }

    fn entered(&self) -> bool {
        self.state.lock().expect("the gate lock").0
    }

    fn release(&self) {
        self.state.lock().expect("the gate lock").1 = true;
        self.turned.notify_all();
    }

    /// Wait on the real clock for a call to reach the gate.
    async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !self.entered() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a record call reached the gate");
    }
}

/// Releases a gate when dropped, so a test that fails while a record call is
/// held still lets the runtime shut down.
struct ReleaseOnDrop(Arc<Gate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Default)]
struct Faults {
    /// Planned faults, each failing the first call of its kind and operation
    /// and then gone.
    plan: Vec<(u8, Op, Fault)>,
    /// The failure of the scan the last slot-0 drop read took, until the runner
    /// takes it.
    scan_failure: Option<RecordError>,
    /// Fail the next read of this drop slot as the fault says, then forget it.
    fail_drop_slot_read: Option<(u16, Fault)>,
    /// Writes attempted since the counter was last reset.
    writes: usize,
    /// Refuse the write with this 1-based index.
    fail_write_at: Option<usize>,
    /// Refuse every channel erasure.
    fail_erase: bool,
    /// Refuse every drop slot write.
    fail_drop_writes: bool,
    /// Fail every inspect, as a node that cannot ask the network does.
    unreachable: bool,
    /// Answer every inspect with no network number, as a node whose routing
    /// table is not yet warm gets, whatever the network holds.
    cold: bool,
    /// Report every subkey as still queued for the flush.
    pending: bool,
    /// Hold every drop read at this gate.
    gate_drop: Option<Arc<Gate>>,
    /// Hold every control-subkey write at this gate.
    gate_control: Option<Arc<Gate>>,
    /// Hold every channel inspect at this gate.
    gate_inspect_channel: Option<Arc<Gate>>,
}

/// A record store over a shared [`Dht`] and one [`Node`], counting every call.
#[derive(Clone)]
struct Fake {
    dht: Arc<Mutex<Dht>>,
    node: Arc<Mutex<Node>>,
    calls: Arc<Mutex<Calls>>,
    faults: Arc<Mutex<Faults>>,
}

impl Fake {
    /// A new node on `dht`.
    fn on(dht: &Arc<Mutex<Dht>>) -> Self {
        Self {
            dht: Arc::clone(dht),
            node: Arc::default(),
            calls: Arc::default(),
            faults: Arc::default(),
        }
    }

    /// The same node, for a relaunched runner: its local copies carry over,
    /// the counts and faults do not.
    fn restart(&self) -> Self {
        Self {
            dht: Arc::clone(&self.dht),
            node: Arc::clone(&self.node),
            calls: Arc::default(),
            faults: Arc::default(),
        }
    }

    fn calls(&self) -> Calls {
        *self.calls.lock().expect("the calls lock")
    }

    fn count(&self, bump: impl FnOnce(&mut Calls)) {
        bump(&mut self.calls.lock().expect("the calls lock"));
    }

    fn faults(&self) -> MutexGuard<'_, Faults> {
        self.faults.lock().expect("the faults lock")
    }

    fn net(&self) -> MutexGuard<'_, Dht> {
        self.dht.lock().expect("the network lock")
    }

    /// Arm a refusal of the `index`-th write from now.
    fn fail_write(&self, index: usize) {
        let mut faults = self.faults();
        faults.writes = 0;
        faults.fail_write_at = Some(index);
    }

    /// Fail this call as the first planned fault for its kind and operation
    /// says, consuming that fault.
    fn inject(&self, kind: u8, op: Op) -> Result<(), RecordError> {
        let mut faults = self.faults();
        let Some(at) = faults
            .plan
            .iter()
            .position(|(k, o, _)| *k == kind && *o == op)
        else {
            return Ok(());
        };
        Err(fault_error(faults.plan.remove(at).2))
    }

    fn write(&self, key: Key, bytes: Vec<u8>) -> Result<(), RecordError> {
        self.inject(key.0, Op::Write)?;
        {
            let mut faults = self.faults();
            faults.writes += 1;
            if faults.fail_write_at == Some(faults.writes) {
                return Err(RecordError::new(Refused));
            }
        }
        let seq = self.net().put(key, bytes.clone());
        self.node
            .lock()
            .expect("the node lock")
            .local
            .insert(key, (seq, bytes));
        Ok(())
    }

    fn read(&self, key: Key) -> Option<Vec<u8>> {
        self.net()
            .records
            .get(&key)
            .map(|(bytes, _)| bytes.clone())
            .filter(|bytes| !bytes.is_empty())
    }

    /// Every subkey of a record, or the error a node that cannot ask the
    /// network gets. A record the network holds no copy of reports no network
    /// number for any subkey, as Veilid's does.
    fn inspect(
        &self,
        kind: u8,
        name: [u8; 32],
        subkeys: u16,
    ) -> Result<Vec<SubkeyReport>, RecordError> {
        self.inject(kind, Op::Inspect)?;
        let (unreachable, cold, pending) = {
            let faults = self.faults();
            (faults.unreachable, faults.cold, faults.pending)
        };
        if unreachable {
            return Err(RecordError::new(Refused));
        }
        let network: Vec<Option<u64>> = {
            let net = self.net();
            (0..subkeys)
                .map(|subkey| net.records.get(&(kind, name, subkey)).map(|(_, seq)| *seq))
                .collect()
        };
        let node = self.node.lock().expect("the node lock");
        Ok((0..subkeys)
            .map(|subkey| SubkeyReport {
                local_seq: node.local.get(&(kind, name, subkey)).map(|(seq, _)| *seq),
                network_seq: if cold {
                    None
                } else {
                    network[usize::from(subkey)]
                },
                pending,
            })
            .collect())
    }

    /// A channel's lookup key: a function of the owner seed that is not the
    /// seed itself.
    fn lookup_key(owner: &ChannelOwnerSeed) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        let mut key = [0u8; HELLO_LOOKUP_KEY_LEN];
        for (k, b) in key.iter_mut().zip(owner.as_bytes()) {
            *k = b ^ 0x5a;
        }
        key
    }
}

impl Records for Fake {
    fn read_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        _subkeys: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.inject(ADVERT, Op::Read)?;
        Ok(self.read((ADVERT, *owner.as_bytes(), 0)))
    }

    fn read_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        _subkeys: u16,
        slot: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        let gate = self.faults().gate_drop.clone();
        if let Some(gate) = gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        self.count(|calls| calls.drop_reads += 1);
        if slot == 0 {
            if let Err(failure) = self.inject(DROP, Op::Scan) {
                self.faults().scan_failure = Some(failure);
            }
        }
        self.inject(DROP, Op::Read)?;
        let slot_fault = {
            let mut faults = self.faults();
            match faults.fail_drop_slot_read {
                Some((at, fault)) if at == slot => {
                    faults.fail_drop_slot_read = None;
                    Some(fault)
                }
                _ => None,
            }
        };
        if let Some(fault) = slot_fault {
            return Err(fault_error(fault));
        }
        let key = (DROP, *owner.as_bytes(), slot);
        // A node reading a slot it wrote a hello into is served its own copy,
        // whatever the network holds.
        let own_hello = self
            .node
            .lock()
            .expect("the node lock")
            .local
            .get(&key)
            .map(|(_, bytes)| bytes.clone())
            .filter(|bytes| !bytes.is_empty());
        Ok(own_hello.or_else(|| self.read(key)))
    }

    fn write_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        _subkeys: u16,
        slot: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        self.count(|calls| calls.hello_writes += 1);
        if self.faults().fail_drop_writes {
            return Err(RecordError::new(Refused));
        }
        self.write((DROP, *owner.as_bytes(), slot), bytes.to_vec())
    }

    fn erase_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        _subkeys: u16,
        slot: u16,
    ) -> Result<(), RecordError> {
        self.write((DROP, *owner.as_bytes(), slot), Vec::new())
    }

    fn open_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        _subkeys: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        self.count(|calls| calls.open_channel += 1);
        self.inject(CHANNEL, Op::Open)?;
        Ok(Self::lookup_key(owner))
    }

    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.count(|calls| calls.channel_reads += 1);
        self.inject(CHANNEL, Op::Read)?;
        Ok(self.read((CHANNEL, *lookup_key, subkey)))
    }

    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        if subkey == channel::CONTROL_SUBKEY {
            let gate = self.faults().gate_control.clone();
            if let Some(gate) = gate {
                tokio::task::block_in_place(|| gate.hold());
            }
            self.count(|calls| calls.control_writes += 1);
        } else {
            self.count(|calls| calls.ring_writes += 1);
        }
        self.write((CHANNEL, *lookup_key, subkey), bytes.to_vec())
    }
}

impl RunnerRecords for Fake {
    fn inspect_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Result<Vec<SubkeyReport>, RecordError> {
        let gate = self.faults().gate_inspect_channel.clone();
        if let Some(gate) = gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        self.count(|calls| calls.inspect_channel += 1);
        self.inspect(CHANNEL, *lookup_key, channel::CHANNEL_SUBKEYS)
    }

    fn inspect_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> Result<Vec<SubkeyReport>, RecordError> {
        self.count(|calls| calls.inspect_advert += 1);
        self.inspect(ADVERT, *owner.as_bytes(), subkeys)
    }

    fn inspect_drop(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
    ) -> Result<Vec<SubkeyReport>, RecordError> {
        self.count(|calls| calls.inspect_drop += 1);
        self.inspect(DROP, *owner.as_bytes(), subkeys)
    }

    fn publish_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        _subkeys: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        self.count(|calls| calls.advert_publishes += 1);
        self.write((ADVERT, *owner.as_bytes(), 0), bytes.to_vec())
    }

    fn erase_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Result<(), RecordError> {
        if self.faults().fail_erase {
            return Err(RecordError::new(Refused));
        }
        self.inject(CHANNEL, Op::Erase)?;
        self.net()
            .records
            .retain(|(kind, name, _), _| !(*kind == CHANNEL && name == lookup_key));
        self.node
            .lock()
            .expect("the node lock")
            .local
            .retain(|(kind, name, _), _| !(*kind == CHANNEL && name == lookup_key));
        Ok(())
    }

    fn classify(error: &RecordError) -> RecordFailure {
        let inner = error.inner();
        if inner.downcast_ref::<TimedOut>().is_some() {
            RecordFailure::TimedOut
        } else if inner.downcast_ref::<LocalRefusal>().is_some() {
            RecordFailure::Local
        } else {
            RecordFailure::Refused
        }
    }

    fn take_scan_failure(&mut self) -> Option<RecordError> {
        self.faults().scan_failure.take()
    }

    fn same_local_refusal(scan: &RecordError, read: &RecordError) -> bool {
        match (
            scan.inner().downcast_ref::<LocalRefusal>(),
            read.inner().downcast_ref::<LocalRefusal>(),
        ) {
            (Some(scan), Some(read)) => scan.0 == read.0,
            _ => false,
        }
    }

    fn write_counts(&self) -> WriteCountsSnapshot {
        let calls = self.calls();
        WriteCountsSnapshot {
            hello: calls.hello_writes as u64,
            control: calls.control_writes as u64,
            ring: calls.ring_writes as u64,
            advert: calls.advert_publishes as u64,
            ..WriteCountsSnapshot::default()
        }
    }
}

/// One identity and its profile directory, which outlive any one runner.
struct Profile {
    mnemonic: Mnemonic,
    pk: IdentityPk,
    root: tempfile::TempDir,
}

impl Profile {
    fn new() -> Self {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let mnemonic = Mnemonic::generate().expect("a recovery phrase");
        let keys = derive_identity_keys(&mnemonic, Identity::Primary).expect("the identity");
        Self {
            pk: Box::new(*keys.signing.public_key()),
            mnemonic,
            root: tempfile::tempdir().expect("a profile directory"),
        }
    }

    fn keys(&self) -> IdentityKeys {
        derive_identity_keys(&self.mnemonic, Identity::Primary).expect("the identity")
    }

    fn spawn(&self, fake: &Fake, config: RunnerConfig) -> Watch {
        let keys = self.keys();
        Watch {
            handle: spawn_runner(RunnerParts {
                records: fake.clone(),
                signer: Arc::new(keys.signing),
                channel_root: keys.dm_channel_root,
                at_rest_key: Zeroizing::new([0x42; AEAD_KEY_LEN]),
                profile_root: self.root.path().to_path_buf(),
                config,
            }),
            seen: Vec::new(),
            budget: if config.tick < Duration::from_secs(1) {
                REAL_BUDGET
            } else {
                PAUSED_BUDGET
            },
        }
    }

    /// The lookup key of the channel this identity writes to `peer`.
    fn outgoing_lookup_key(&self, peer: &Profile) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        let owner = channel::derive_owner_seed(
            &self.keys().dm_channel_root,
            &peer.pk,
            flows::FIRST_GENERATION,
        )
        .expect("the channel owner seed");
        Fake::lookup_key(&owner)
    }

    fn advert_key(&self) -> Key {
        let owner = advert::derive_owner_seed(&self.pk).expect("the advert owner seed");
        (ADVERT, *owner.as_bytes(), 0)
    }

    fn drop_name(&self) -> [u8; 32] {
        *drop_plane::derive_owner_seed(&self.pk)
            .expect("the drop owner seed")
            .as_bytes()
    }
}

/// A runner and every event read from it so far.
struct Watch {
    handle: RunnerHandle,
    seen: Vec<RunnerEvent>,
    budget: Duration,
}

impl Watch {
    /// The index of the first event at or after `from`, already read or still
    /// to come, that `matches` accepts.
    async fn wait_from(
        &mut self,
        from: usize,
        what: &str,
        matches: impl Fn(&RunnerEvent) -> bool,
    ) -> usize {
        if let Some(at) = self.seen.iter().skip(from).position(&matches) {
            return from + at;
        }
        loop {
            let event = tokio::time::timeout(self.budget, self.handle.next_event())
                .await
                .unwrap_or_else(|_| panic!("no {what} within the budget; saw {:?}", self.seen))
                .unwrap_or_else(|| panic!("the runner stopped before {what}; saw {:?}", self.seen));
            let hit = self.seen.len() >= from && matches(&event);
            self.seen.push(event);
            if hit {
                return self.seen.len() - 1;
            }
        }
    }

    async fn wait_for(&mut self, what: &str, matches: impl Fn(&RunnerEvent) -> bool) -> usize {
        self.wait_from(0, what, matches).await
    }

    async fn send(&self, command: RunnerCommand) {
        self.handle
            .send(command)
            .await
            .expect("the runner takes commands");
    }

    fn drain(&mut self) {
        while let Some(event) = self.handle.try_next_event() {
            self.seen.push(event);
        }
    }

    async fn stop(self) -> RunnerStop {
        self.handle.shutdown().await
    }
}

fn is_health(event: &RunnerEvent) -> bool {
    matches!(event, RunnerEvent::Health(_))
}

fn is_roster(event: &RunnerEvent) -> bool {
    matches!(event, RunnerEvent::Roster(_))
}

fn sent(token: u64) -> impl Fn(&RunnerEvent) -> bool {
    move |event| matches!(event, RunnerEvent::Sent { token: t, .. } if t.0 == token)
}

fn refused(token: u64) -> impl Fn(&RunnerEvent) -> bool {
    move |event| matches!(event, RunnerEvent::Refused { token: Some(t), .. } if t.0 == token)
}

fn message(
    from: CorrespondenceLabel,
    seq: u64,
    body: &'static [u8],
) -> impl Fn(&RunnerEvent) -> bool {
    move |event| {
        matches!(event, RunnerEvent::Message { from: f, seq: s, body: b, .. }
            if *f == from && *s == seq && b.as_slice() == body)
    }
}

fn delivered(peer: CorrespondenceLabel, through: u64) -> impl Fn(&RunnerEvent) -> bool {
    move |event| {
        matches!(event, RunnerEvent::Delivered { peer: p, through_seq }
            if *p == peer && *through_seq == through)
    }
}

fn accepted(peer: CorrespondenceLabel) -> impl Fn(&RunnerEvent) -> bool {
    move |event| matches!(event, RunnerEvent::Accepted { peer: p } if *p == peer)
}

fn request_from(pk: &IdentityPk) -> impl Fn(&RunnerEvent) -> bool + '_ {
    move |event| {
        matches!(event, RunnerEvent::ContactRequest { from, .. }
            if from.as_slice() == pk.as_slice())
    }
}

fn sent_peer(event: &RunnerEvent) -> CorrespondenceLabel {
    match event {
        RunnerEvent::Sent { peer, .. } => *peer,
        other => panic!("expected Sent, got {other:?}"),
    }
}

fn refusal(event: &RunnerEvent) -> Refusal {
    match event {
        RunnerEvent::Refused { reason, .. } => *reason,
        other => panic!("expected Refused, got {other:?}"),
    }
}

fn request_id(event: &RunnerEvent) -> ContactRequestId {
    match event {
        RunnerEvent::ContactRequest { request, .. } => *request,
        other => panic!("expected ContactRequest, got {other:?}"),
    }
}

fn roster(event: &RunnerEvent) -> &[ConversationSummary] {
    match event {
        RunnerEvent::Roster(rows) => rows,
        other => panic!("expected Roster, got {other:?}"),
    }
}

fn health(event: &RunnerEvent) -> HealthCounters {
    match event {
        RunnerEvent::Health(counters) => *counters,
        other => panic!("expected Health, got {other:?}"),
    }
}

fn network() -> Arc<Mutex<Dht>> {
    Arc::new(Mutex::new(Dht::default()))
}

fn finished(stop: &RunnerStop) -> bool {
    matches!(stop.outcome, ShutdownOutcome::Finished(Ok(())))
}

/// A real-clock schedule, for tests whose record calls block a thread.
fn real_clock() -> RunnerConfig {
    RunnerConfig {
        tick: Duration::from_millis(50),
        grace: Duration::from_secs(5),
    }
}

/// Two runners on one network with a conversation between them.
struct Scene {
    dht: Arc<Mutex<Dht>>,
    a: Profile,
    b: Profile,
    a_fake: Fake,
    b_fake: Fake,
    aw: Watch,
    bw: Watch,
    a_peer: CorrespondenceLabel,
    b_peer: CorrespondenceLabel,
}

/// A opens a conversation with B through both runners' commands and
/// schedules, asserting each event on the way.
async fn establish(config: RunnerConfig) -> Scene {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    let mut bw = b.spawn(&b_fake, config);
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&a_fake, config);
    aw.wait_for("A's startup", is_health).await;

    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body".to_vec(),
    })
    .await;
    let at = aw.wait_for("A's first contact", sent(1)).await;
    let a_peer = sent_peer(&aw.seen[at]);

    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let at = bw.wait_for("B's acceptance", sent(2)).await;
    let b_peer = sent_peer(&bw.seen[at]);
    assert!(
        matches!(bw.seen[at], RunnerEvent::Sent { seq: 0, .. }),
        "the reply is sequence 0 of B's direction"
    );

    let accepted_at = aw.wait_for("A's acceptance", accepted(a_peer)).await;
    let reply_at = aw
        .wait_for("B's reply at A", message(a_peer, 0, b"the reply"))
        .await;
    assert!(
        accepted_at < reply_at,
        "the acceptance precedes the reply it carried"
    );
    bw.wait_for("A's first body at B", message(b_peer, 0, b"the first body"))
        .await;
    aw.wait_for("delivery of A's first body", delivered(a_peer, 0))
        .await;
    Scene {
        dht,
        a,
        b,
        a_fake,
        b_fake,
        aw,
        bw,
        a_peer,
        b_peer,
    }
}

/// Startup reports the roster the store holds and reopens the channel this
/// side owns. The advert is rewritten where the network's copy differs or a
/// node holds none, and left alone where it matches or the network answers
/// nothing.
#[tokio::test(start_paused = true)]
async fn startup_reports_the_roster_reopens_channels_and_repairs_the_advert() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;

    let first = Fake::on(&dht);
    let mut aw = a.spawn(&first, RunnerConfig::default());
    let at = aw.wait_for("the first roster", is_roster).await;
    assert!(
        roster(&aw.seen[at]).is_empty(),
        "a new profile holds nothing"
    );
    aw.wait_for("A's startup", is_health).await;
    assert_eq!(
        first.calls().open_channel,
        0,
        "a new profile owns no channel"
    );
    assert_eq!(
        first.calls().advert_publishes,
        1,
        "minted keys are published"
    );
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    assert!(finished(&aw.stop().await));

    let intact = first.restart();
    let mut aw = a.spawn(&intact, RunnerConfig::default());
    let at = aw.wait_for("the roster", is_roster).await;
    let rows = roster(&aw.seen[at]);
    assert!(!rows.is_empty(), "the store holds A's conversation");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, ConversationState::Pending);
    assert_eq!(rows[0].peer_collected, 0);
    assert_eq!(rows[0].peer_identity_pk.as_slice(), b.pk.as_slice());
    aw.wait_for("A's restart", is_health).await;
    let calls = intact.calls();
    assert_eq!(calls.open_channel, 1, "the one channel A owns is reopened");
    assert!(calls.inspect_advert >= 1, "the advert is inspected");
    assert_eq!(
        calls.advert_publishes, 0,
        "an advert the network holds is not rewritten"
    );
    assert!(finished(&aw.stop().await));

    dht.lock()
        .expect("the network lock")
        .clobber(a.advert_key());
    let clobbered = first.restart();
    let mut aw = a.spawn(&clobbered, RunnerConfig::default());
    aw.wait_for("A's restart over another writer's advert", is_health)
        .await;
    assert_eq!(
        clobbered.calls().advert_publishes,
        1,
        "a differing advert is rewritten"
    );
    assert!(finished(&aw.stop().await));

    dht.lock().expect("the network lock").evict(a.advert_key());
    let unreachable = first.restart();
    unreachable.faults().unreachable = true;
    let mut aw = a.spawn(&unreachable, RunnerConfig::default());
    let at = aw
        .wait_for("A's restart unable to ask the network", is_health)
        .await;
    assert!(unreachable.calls().inspect_advert >= 1);
    assert_eq!(
        unreachable.calls().advert_publishes,
        0,
        "an inspect that could not ask the network writes nothing"
    );
    assert!(health(&aw.seen[at]).advert_inspect_failures >= 1);
    assert!(finished(&aw.stop().await));

    let evicted = first.restart();
    let mut aw = a.spawn(&evicted, RunnerConfig::default());
    aw.wait_for("A's restart with its advert evicted", is_health)
        .await;
    assert_eq!(
        evicted.calls().advert_publishes,
        1,
        "an advert the network holds no copy of is rewritten"
    );
    assert!(finished(&aw.stop().await));

    let moved = Fake::on(&dht);
    let mut aw = a.spawn(&moved, RunnerConfig::default());
    aw.wait_for("A's startup on a node holding no advert", is_health)
        .await;
    assert_eq!(
        moved.calls().advert_publishes,
        1,
        "a node holding no copy publishes"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A first contact, its acceptance with a reply, and both deliveries, each
/// runner driven only by its commands and its schedule. The delivery is part of
/// the conversation record, so the first roster of a relaunch carries it.
#[tokio::test(start_paused = true)]
async fn two_runners_hold_a_first_contact_end_to_end() {
    let Scene {
        a,
        b: _b,
        a_fake,
        aw,
        bw,
        a_peer,
        b_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    let mut bw = bw;
    bw.wait_for("delivery of B's reply", delivered(b_peer, 0))
        .await;
    assert!(finished(&aw.stop().await));

    let mut aw = a.spawn(&a_fake.restart(), RunnerConfig::default());
    let at = aw
        .wait_for("A's roster after the relaunch", is_roster)
        .await;
    let rows = roster(&aw.seen[at]);
    assert!(!rows.is_empty());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer, a_peer);
    assert_eq!(rows[0].state, ConversationState::Established);
    assert_eq!(
        rows[0].peer_collected, 1,
        "the relaunch's roster carries the delivery"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A send to an unknown conversation, an accept under an id this run never
/// issued, and a send into a full ring are refused with the command's token,
/// under different reasons.
#[tokio::test(start_paused = true)]
async fn refusals_carry_the_token_and_name_backpressure_apart() {
    // The profiles are bound so their directories, which hold both stores,
    // live as long as the runners.
    let Scene {
        a: _a,
        b: _b,
        mut aw,
        mut bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;

    aw.send(RunnerCommand::Send {
        token: CommandToken(10),
        peer: CorrespondenceLabel::mint().expect("a label"),
        body: b"to nobody".to_vec(),
    })
    .await;
    let at = aw.wait_for("the unknown-peer refusal", refused(10)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::UnknownConversation);

    bw.send(RunnerCommand::Accept {
        token: CommandToken(11),
        request: ContactRequestId {
            epoch: 0,
            serial: 1,
        },
        reply: b"to nobody".to_vec(),
    })
    .await;
    let at = bw
        .wait_for("the unknown-request refusal", refused(11))
        .await;
    assert_eq!(refusal(&bw.seen[at]), Refusal::UnknownRequest);

    // B stops collecting, so A's ring fills: sequence 0 is collected and 63
    // more fit.
    assert!(finished(&bw.stop().await));
    for i in 0..64u64 {
        aw.send(RunnerCommand::Send {
            token: CommandToken(100 + i),
            peer: a_peer,
            body: format!("message {i}").into_bytes(),
        })
        .await;
    }
    let at = aw.wait_for("the backpressure refusal", refused(163)).await;
    let answers: Vec<String> = aw
        .seen
        .iter()
        .filter_map(|event| match event {
            RunnerEvent::Sent { token, .. }
            | RunnerEvent::Refused {
                token: Some(token), ..
            } if token.0 >= 100 => Some(format!("{event:?}")),
            _ => None,
        })
        .collect();
    assert_eq!(
        refusal(&aw.seen[at]),
        Refusal::RingFull,
        "answers to the sends: {answers:?}"
    );
    let sends = aw
        .seen
        .iter()
        .filter(|event| {
            matches!(event, RunnerEvent::Sent { token, .. } if (100..163).contains(&token.0))
        })
        .count();
    assert!(sends > 0, "the ring took messages before it filled");
    assert_eq!(
        sends, 63,
        "63 messages fit before the ring is full: {answers:?}"
    );
    assert!(finished(&aw.stop().await));
}

/// A request id names the run that issued it: a relaunch surfaces the same
/// hello under a new id, and the earlier one is refused.
#[tokio::test(start_paused = true)]
async fn a_request_id_from_an_earlier_run_is_refused() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    let at = bw
        .wait_for("the first run's request", request_from(&a.pk))
        .await;
    let stale = request_id(&bw.seen[at]);
    assert!(finished(&bw.stop().await));

    let mut bw = b.spawn(&b_fake.restart(), RunnerConfig::default());
    let at = bw
        .wait_for("the second run's request", request_from(&a.pk))
        .await;
    let current = request_id(&bw.seen[at]);
    assert_ne!(stale, current);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(5),
        request: stale,
        reply: b"reply".to_vec(),
    })
    .await;
    let at = bw.wait_for("the stale id's answer", refused(5)).await;
    assert_eq!(refusal(&bw.seen[at]), Refusal::UnknownRequest);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(6),
        request: current,
        reply: b"reply".to_vec(),
    })
    .await;
    bw.wait_for("the current id's acceptance", sent(6)).await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A hello from a blocked identity surfaces nothing and moves the dropped
/// counter; unblocked, the same hello is a contact request.
#[tokio::test(start_paused = true)]
async fn a_blocked_identity_is_dropped_until_unblocked() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;

    bw.send(RunnerCommand::Block { peer: a.pk.clone() }).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    bw.wait_for(
        "the dropped hello",
        |event| matches!(event, RunnerEvent::Health(h) if h.hellos_dropped >= 1),
    )
    .await;
    bw.drain();
    assert!(!bw.seen.is_empty());
    assert!(
        !bw.seen
            .iter()
            .any(|event| matches!(event, RunnerEvent::ContactRequest { .. })),
        "a blocked identity's hello surfaces no request"
    );

    bw.send(RunnerCommand::Unblock { peer: a.pk.clone() }).await;
    bw.wait_for("the request once unblocked", request_from(&a.pk))
        .await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A runner stopped mid-conversation and started again on the same store loses
/// and repeats nothing. Its control subkey and outstanding slots are rewritten
/// only where the network has lost them, at startup and again by the repair
/// poll.
#[tokio::test(start_paused = true)]
async fn a_restart_rewrites_only_lost_subkeys_and_delivers_each_message_once() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        b_fake,
        mut aw,
        bw,
        a_peer,
        b_peer,
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    for (token, body) in [(20u64, b"m1"), (21, b"m2")] {
        aw.send(RunnerCommand::Send {
            token: CommandToken(token),
            peer: a_peer,
            body: body.to_vec(),
        })
        .await;
        aw.wait_for("the send", sent(token)).await;
    }
    assert!(finished(&aw.stop().await));

    let intact = a_fake.restart();
    let mut aw = a.spawn(&intact, RunnerConfig::default());
    let at = aw.wait_for("the roster", is_roster).await;
    let rows = roster(&aw.seen[at]);
    assert!(!rows.is_empty());
    assert_eq!(rows[0].uncollected, 2, "two messages are outstanding");
    aw.wait_for("the restart", is_health).await;
    assert!(
        intact.calls().inspect_channel >= 1,
        "the channel is inspected"
    );
    assert_eq!(
        intact.calls().ring_writes,
        0,
        "slots the network holds are not rewritten"
    );
    assert_eq!(
        intact.calls().control_writes,
        0,
        "a held control subkey is not rewritten"
    );
    assert!(finished(&aw.stop().await));

    let lookup_key = a.outgoing_lookup_key(&b);
    {
        let mut net = dht.lock().expect("the network lock");
        net.evict((CHANNEL, lookup_key, channel::slot_for(1)));
        net.evict((CHANNEL, lookup_key, channel::slot_for(2)));
        net.evict((CHANNEL, lookup_key, channel::CONTROL_SUBKEY));
    }
    let lossy = a_fake.restart();
    let mut aw = a.spawn(&lossy, RunnerConfig::default());
    aw.wait_for("the restart over a lossy network", is_health)
        .await;
    assert_eq!(
        lossy.calls().ring_writes,
        2,
        "each lost slot is rewritten once"
    );
    assert_eq!(
        lossy.calls().control_writes,
        1,
        "the lost control subkey is resealed"
    );

    {
        let mut net = dht.lock().expect("the network lock");
        net.evict((CHANNEL, lookup_key, channel::slot_for(1)));
        net.evict((CHANNEL, lookup_key, channel::slot_for(2)));
    }
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX + Duration::from_secs(60)).await;
    assert_eq!(
        lossy.calls().ring_writes,
        4,
        "the repair poll rewrites slots lost while running"
    );

    let mut bw = b.spawn(&b_fake.restart(), RunnerConfig::default());
    bw.wait_for("m1 at B", message(b_peer, 1, b"m1")).await;
    bw.wait_for("m2 at B", message(b_peer, 2, b"m2")).await;
    aw.wait_for("delivery of both", delivered(a_peer, 2)).await;
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX * 2).await;
    bw.drain();
    let seqs: Vec<u64> = bw
        .seen
        .iter()
        .filter_map(|event| match event {
            RunnerEvent::Message { from, seq, .. } if *from == b_peer => Some(*seq),
            _ => None,
        })
        .collect();
    assert!(!seqs.is_empty());
    assert_eq!(
        seqs,
        vec![1, 2],
        "each message once, none collected before again"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A subkey Veilid still has queued for its flush is not rewritten, and nothing
/// is written by an inspect that could not ask the network. A lost slot is
/// rewritten, and so is every outstanding subkey of a channel the network holds
/// no copy of at all, while this node's own advert shows the network answering;
/// the same report on a node whose look reaches nothing is left alone.
#[tokio::test(start_paused = true)]
async fn a_queued_flush_or_an_unreachable_network_is_not_a_loss_but_an_empty_one_is() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    aw.send(RunnerCommand::Send {
        token: CommandToken(20),
        peer: a_peer,
        body: b"m1".to_vec(),
    })
    .await;
    aw.wait_for("the send", sent(20)).await;
    assert!(finished(&aw.stop().await));
    dht.lock().expect("the network lock").evict((
        CHANNEL,
        a.outgoing_lookup_key(&b),
        channel::slot_for(1),
    ));

    let queued = a_fake.restart();
    queued.faults().pending = true;
    let mut aw = a.spawn(&queued, RunnerConfig::default());
    aw.wait_for("the restart with the slot queued", is_health)
        .await;
    assert!(queued.calls().inspect_channel >= 1);
    assert_eq!(
        queued.calls().ring_writes,
        0,
        "a queued subkey is not rewritten"
    );
    assert!(finished(&aw.stop().await));

    let unreachable = a_fake.restart();
    unreachable.faults().unreachable = true;
    let mut aw = a.spawn(&unreachable, RunnerConfig::default());
    let at = aw
        .wait_for("the restart unable to ask the network", is_health)
        .await;
    assert!(unreachable.calls().inspect_channel >= 1);
    assert_eq!(
        unreachable.calls().ring_writes,
        0,
        "an inspect that could not ask the network writes nothing"
    );
    assert!(health(&aw.seen[at]).channel_inspect_failures >= 1);
    assert!(finished(&aw.stop().await));

    let plain = a_fake.restart();
    let mut aw = a.spawn(&plain, RunnerConfig::default());
    aw.wait_for("the restart with the loss visible", is_health)
        .await;
    assert_eq!(plain.calls().ring_writes, 1, "the lost slot is rewritten");
    assert!(finished(&aw.stop().await));

    let lookup_key = a.outgoing_lookup_key(&b);
    {
        let mut net = dht.lock().expect("the network lock");
        for subkey in [
            channel::CONTROL_SUBKEY,
            channel::slot_for(0),
            channel::slot_for(1),
        ] {
            net.evict((CHANNEL, lookup_key, subkey));
        }
        assert!(
            !net.records
                .keys()
                .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key),
            "the network holds no subkey of A's channel"
        );
    }
    let empty = a_fake.restart();
    let mut aw = a.spawn(&empty, RunnerConfig::default());
    aw.wait_for("the restart over a channel the network dropped", is_health)
        .await;
    assert_eq!(
        empty.calls().ring_writes,
        1,
        "the outstanding slot of a dropped channel is rewritten"
    );
    assert_eq!(
        empty.calls().control_writes,
        1,
        "the control subkey of a dropped channel is resealed"
    );
    assert!(finished(&aw.stop().await));

    // The same drop seen by a node whose look reaches nothing: its own advert
    // shows no network number either, so the network is not answering and the
    // channel is left alone.
    {
        let mut net = dht.lock().expect("the network lock");
        net.evict((CHANNEL, lookup_key, channel::CONTROL_SUBKEY));
        net.evict((CHANNEL, lookup_key, channel::slot_for(1)));
        assert!(
            !net.records
                .keys()
                .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key),
            "the network holds no subkey of A's channel"
        );
    }
    let cold = a_fake.restart();
    cold.faults().cold = true;
    let mut aw = a.spawn(&cold, RunnerConfig::default());
    let at = aw
        .wait_for(
            "the restart on a node whose look reaches nothing",
            is_health,
        )
        .await;
    assert!(cold.calls().inspect_advert >= 1, "the advert was asked");
    assert_eq!(
        cold.calls().ring_writes,
        0,
        "a drop seen while the network does not answer is not rewritten"
    );
    assert_eq!(cold.calls().control_writes, 0);
    assert!(health(&aw.seen[at]).network_not_answering >= 1);
    assert!(finished(&aw.stop().await));
}

/// An outstanding hello is rewritten only where its slot differs from what
/// this node wrote: absent, or overwritten by another writer. A slot that
/// matches is left alone, and so is every slot when the inspect could not ask
/// the network; a drop the network holds no copy of has its hello rewritten.
#[tokio::test(start_paused = true)]
async fn an_outstanding_hello_is_rewritten_only_where_its_slot_differs() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    assert!(finished(&bw.stop().await));

    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    assert!(finished(&aw.stop().await));

    let intact = a_fake.restart();
    let mut aw = a.spawn(&intact, RunnerConfig::default());
    aw.wait_for("A's restart", is_health).await;
    assert!(intact.calls().inspect_drop >= 1, "the drop is inspected");
    assert_eq!(
        intact.calls().hello_writes,
        0,
        "a hello the network holds is not rewritten"
    );
    assert!(finished(&aw.stop().await));

    let drop_name = b.drop_name();
    let (hello, other) = {
        let mut net = dht.lock().expect("the network lock");
        let slots: Vec<Key> = net
            .records
            .keys()
            .filter(|(kind, name, _)| *kind == DROP && *name == drop_name)
            .copied()
            .collect();
        assert_eq!(slots.len(), 1, "A's one hello is in B's drop");
        let hello = slots[0];
        let other = (DROP, drop_name, (hello.2 + 1) % drop_plane::DROP_SUBKEYS);
        net.put(other, vec![0x33; 16]);
        net.evict(hello);
        (hello, other)
    };
    let lost = a_fake.restart();
    let mut aw = a.spawn(&lost, RunnerConfig::default());
    aw.wait_for("A's restart with its hello lost", is_health)
        .await;
    assert_eq!(
        lost.calls().hello_writes,
        1,
        "a lost hello is rewritten once"
    );
    assert!(finished(&aw.stop().await));

    dht.lock().expect("the network lock").clobber(hello);
    let clobbered = a_fake.restart();
    let mut aw = a.spawn(&clobbered, RunnerConfig::default());
    aw.wait_for("A's restart with its hello overwritten", is_health)
        .await;
    assert_eq!(
        clobbered.calls().hello_writes,
        1,
        "a slot another writer holds at a higher number is rewritten"
    );
    assert!(finished(&aw.stop().await));

    {
        let mut net = dht.lock().expect("the network lock");
        net.evict(hello);
        net.evict(other);
    }
    let unreachable = a_fake.restart();
    unreachable.faults().unreachable = true;
    let mut aw = a.spawn(&unreachable, RunnerConfig::default());
    let at = aw
        .wait_for("A's restart unable to ask the network", is_health)
        .await;
    assert!(unreachable.calls().inspect_drop >= 1);
    assert_eq!(
        unreachable.calls().hello_writes,
        0,
        "an inspect that could not ask the network writes no hello"
    );
    assert!(health(&aw.seen[at]).drop_inspect_failures >= 1);
    assert!(finished(&aw.stop().await));

    let empty = a_fake.restart();
    let mut aw = a.spawn(&empty, RunnerConfig::default());
    aw.wait_for("A's restart over a drop the network dropped", is_health)
        .await;
    assert_eq!(
        empty.calls().hello_writes,
        1,
        "a hello in a drop the network holds no copy of is rewritten"
    );
    assert!(finished(&aw.stop().await));

    dht.lock().expect("the network lock").evict(hello);
    let cold = a_fake.restart();
    cold.faults().cold = true;
    let mut aw = a.spawn(&cold, RunnerConfig::default());
    let at = aw
        .wait_for(
            "A's restart on a node whose look reaches nothing",
            is_health,
        )
        .await;
    assert_eq!(
        cold.calls().hello_writes,
        0,
        "a drop seen while the network does not answer is not rewritten"
    );
    assert!(health(&aw.seen[at]).network_not_answering >= 1);
    assert!(finished(&aw.stop().await));
}

/// The correspondent accepted the original hello and then rotated its advert
/// while this side was stopped. Startup recognises the acceptance before it
/// considers re-encapsulating, so the reply opens and no hello is written: a
/// refresh ahead of the scan would re-encapsulate the accepted hello and write
/// it again.
#[tokio::test(start_paused = true)]
async fn an_acceptance_is_recognised_before_a_rotated_advert_is_answered() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    let at = aw.wait_for("A's first contact", sent(1)).await;
    let a_peer = sent_peer(&aw.seen[at]);
    assert!(finished(&aw.stop().await));

    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("B's acceptance", sent(2)).await;
    assert!(finished(&bw.stop().await));

    let rotated = {
        let store = Store::open(b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
            .expect("B's store opens");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        store
            .update_advert_keys(|keys| keys.rotate_now(now, os_fill))
            .expect("B's advert keys load")
            .expect("B's advert keys rotate");
        let keys = AdvertKeys::restore(
            store
                .load_advert_keys()
                .expect("B's advert keys read")
                .expect("B's advert keys exist"),
        );
        keys.advert_bytes(&b.keys().signing)
            .expect("the rotated advert signs")
    };
    dht.lock()
        .expect("the network lock")
        .put(b.advert_key(), rotated);

    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("A's acceptance", accepted(a_peer)).await;
    aw.wait_for("B's reply at A", message(a_peer, 0, b"the reply"))
        .await;
    aw.wait_for("A's startup", is_health).await;
    let calls = relaunched.calls();
    assert!(calls.channel_reads > 0, "the startup scan read B's channel");
    assert_eq!(
        calls.hello_writes, 0,
        "a hello already accepted is recognised, not re-encapsulated and rewritten"
    );
    assert!(finished(&aw.stop().await));
}

/// A re-encapsulated hello persisted and never written is written by the next
/// startup, although the slot still holds the earlier hello at the sequence
/// number this node wrote it under.
#[tokio::test(start_paused = true)]
async fn a_re_encapsulated_hello_persisted_but_not_written_is_written_after_a_relaunch() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    assert!(finished(&bw.stop().await));

    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    assert!(finished(&aw.stop().await));

    let drop_name = b.drop_name();
    let slot_key = {
        let net = dht.lock().expect("the network lock");
        let slots: Vec<Key> = net
            .records
            .keys()
            .filter(|(kind, name, _)| *kind == DROP && *name == drop_name)
            .copied()
            .collect();
        assert_eq!(slots.len(), 1, "A's one hello is in B's drop");
        slots[0]
    };
    let slot_bytes = |dht: &Arc<Mutex<Dht>>| {
        dht.lock()
            .expect("the network lock")
            .records
            .get(&slot_key)
            .map(|(bytes, _)| bytes.clone())
            .expect("the slot holds a hello")
    };
    let persisted = |a: &Profile| {
        let store = Store::open(a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
            .expect("A's store opens");
        let loaded = store.load().expect("A's store loads");
        assert_eq!(loaded.convs.len(), 1);
        let hello = loaded.convs[0]
            .state
            .outstanding_hello
            .as_ref()
            .expect("A's hello is outstanding");
        assert_eq!(hello.slot, slot_key.2, "the rewrite keeps the slot");
        hello.sealed.to_vec()
    };
    let original = slot_bytes(&dht);
    assert_eq!(
        persisted(&a),
        original,
        "the first hello is written as persisted"
    );

    let rotated = {
        let store = Store::open(b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
            .expect("B's store opens");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        store
            .update_advert_keys(|keys| keys.rotate_now(now, os_fill))
            .expect("B's advert keys load")
            .expect("B's advert keys rotate");
        let keys = AdvertKeys::restore(
            store
                .load_advert_keys()
                .expect("B's advert keys read")
                .expect("B's advert keys exist"),
        );
        keys.advert_bytes(&b.keys().signing)
            .expect("the rotated advert signs")
    };
    dht.lock()
        .expect("the network lock")
        .put(b.advert_key(), rotated);

    let stopped = a_fake.restart();
    stopped.faults().fail_drop_writes = true;
    let mut aw = a.spawn(&stopped, RunnerConfig::default());
    let at = aw
        .wait_for("A's restart with drop writes refused", is_health)
        .await;
    assert!(
        stopped.calls().hello_writes >= 1,
        "the rewrite was attempted"
    );
    assert!(health(&aw.seen[at]).drop_write_failures >= 1);
    assert!(finished(&aw.stop().await));
    let rewritten = persisted(&a);
    assert_ne!(
        rewritten, original,
        "the re-encapsulated hello reached the store"
    );
    assert_eq!(slot_bytes(&dht), original, "and not the slot");

    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("A's relaunch", is_health).await;
    assert!(finished(&aw.stop().await));
    assert_eq!(
        slot_bytes(&dht),
        rewritten,
        "the slot holds the persisted hello after the relaunch"
    );
}

/// A first contact refused at each of its writes is carried on by the next
/// startup, and the conversation reaches both sides.
#[tokio::test(start_paused = true)]
async fn a_first_contact_stopped_at_any_write_is_carried_on_after_a_relaunch() {
    for write in 1..=3 {
        let dht = network();
        let (a, b) = (Profile::new(), Profile::new());
        let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
        bw.wait_for("B's startup", is_health).await;
        let a_fake = Fake::on(&dht);
        let mut aw = a.spawn(&a_fake, RunnerConfig::default());
        aw.wait_for("A's startup", is_health).await;

        a_fake.fail_write(write);
        aw.send(RunnerCommand::FirstContact {
            token: CommandToken(1),
            peer_identity_pk: b.pk.clone(),
            body: b"hello".to_vec(),
        })
        .await;
        let at = aw.wait_for("the refused first contact", refused(1)).await;
        assert_eq!(refusal(&aw.seen[at]), Refusal::Network, "write {write}");
        let at = aw
            .wait_from(at, "the roster after the refusal", is_roster)
            .await;
        let rows = roster(&aw.seen[at]);
        assert_eq!(
            rows.len(),
            1,
            "write {write}: the pending conversation is listed"
        );
        assert_eq!(rows[0].state, ConversationState::Pending);
        assert!(finished(&aw.stop().await));

        let mut aw = a.spawn(&a_fake.restart(), RunnerConfig::default());
        let at = bw
            .wait_for("B's contact request", request_from(&a.pk))
            .await;
        let request = request_id(&bw.seen[at]);
        bw.send(RunnerCommand::Accept {
            token: CommandToken(2),
            request,
            reply: b"the reply".to_vec(),
        })
        .await;
        let at = bw.wait_for("B's acceptance", sent(2)).await;
        let b_peer = sent_peer(&bw.seen[at]);
        bw.wait_for("A's first body at B", message(b_peer, 0, b"hello"))
            .await;
        aw.wait_for("A's acceptance", |event| {
            matches!(event, RunnerEvent::Accepted { .. })
        })
        .await;
        assert!(finished(&aw.stop().await));
        assert!(finished(&bw.stop().await));
    }
}

/// An acceptance refused at each of its writes is carried on by the repair
/// poll from the request the runner holds, and the conversation reaches both
/// sides.
#[tokio::test(start_paused = true)]
async fn an_acceptance_refused_at_any_write_is_carried_on_by_the_repair_poll() {
    for write in 1..=4 {
        let dht = network();
        let (a, b) = (Profile::new(), Profile::new());
        let b_fake = Fake::on(&dht);
        let mut bw = b.spawn(&b_fake, RunnerConfig::default());
        bw.wait_for("B's startup", is_health).await;
        let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
        aw.wait_for("A's startup", is_health).await;
        aw.send(RunnerCommand::FirstContact {
            token: CommandToken(1),
            peer_identity_pk: b.pk.clone(),
            body: b"hello".to_vec(),
        })
        .await;
        let at = aw.wait_for("A's first contact", sent(1)).await;
        let a_peer = sent_peer(&aw.seen[at]);
        let at = bw
            .wait_for("B's contact request", request_from(&a.pk))
            .await;
        let request = request_id(&bw.seen[at]);

        b_fake.fail_write(write);
        bw.send(RunnerCommand::Accept {
            token: CommandToken(2),
            request,
            reply: b"the reply".to_vec(),
        })
        .await;
        let at = bw.wait_for("the refused acceptance", refused(2)).await;
        assert_eq!(refusal(&bw.seen[at]), Refusal::Network, "write {write}");

        aw.wait_for("A's acceptance", accepted(a_peer)).await;
        aw.wait_for("B's reply at A", message(a_peer, 0, b"the reply"))
            .await;
        bw.wait_for("B's conversation established", |event| {
            matches!(event, RunnerEvent::Roster(rows)
                if rows.iter().any(|row| row.state == ConversationState::Established))
        })
        .await;
        assert!(finished(&aw.stop().await));
        assert!(finished(&bw.stop().await));
    }
}

/// An acceptance refused part way and then relaunched is carried on from the
/// conversation record alone: the initiator sees it accepted and the acceptor
/// shows the conversation established.
#[tokio::test(start_paused = true)]
async fn an_acceptance_refused_part_way_is_carried_on_after_a_relaunch() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    let at = aw.wait_for("A's first contact", sent(1)).await;
    let a_peer = sent_peer(&aw.seen[at]);
    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    b_fake.fail_write(2);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("the refused acceptance", refused(2)).await;
    assert!(finished(&bw.stop().await));

    let mut bw = b.spawn(&b_fake.restart(), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    aw.wait_for("A's acceptance", accepted(a_peer)).await;
    aw.wait_for("B's reply at A", message(a_peer, 0, b"the reply"))
        .await;
    bw.wait_for("B's conversation established", |event| {
        matches!(event, RunnerEvent::Roster(rows)
            if rows.len() == 1 && rows[0].state == ConversationState::Established)
    })
    .await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A relaunch in the middle of an acceptance surfaces the initiator's first
/// message exactly once across both runs: the refused run records nothing it
/// read, and the relaunch that finishes the acceptance surfaces it.
#[tokio::test(start_paused = true)]
async fn a_relaunch_mid_acceptance_surfaces_message_zero_exactly_once() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"message zero".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    b_fake.fail_write(2);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("the refused acceptance", refused(2)).await;
    let Watch { handle, seen, .. } = bw;
    let first_run = handle.shutdown().await;
    assert!(finished(&first_run));
    let first_events: Vec<&RunnerEvent> = seen.iter().chain(first_run.undelivered.iter()).collect();
    assert!(!first_events.is_empty());
    let messages_in_first_run = first_events
        .iter()
        .filter(|event| matches!(event, RunnerEvent::Message { .. }))
        .count();
    assert_eq!(
        messages_in_first_run, 0,
        "the refused run surfaced no message"
    );

    let mut bw = b.spawn(&b_fake.restart(), RunnerConfig::default());
    let at = bw
        .wait_for("message zero after the relaunch", |event| {
            matches!(event, RunnerEvent::Message { seq: 0, body, .. } if body.as_slice() == b"message zero")
        })
        .await;
    let from = match &bw.seen[at] {
        RunnerEvent::Message { from, .. } => *from,
        other => panic!("expected Message, got {other:?}"),
    };
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX * 2).await;
    bw.drain();
    let seqs = messages_from(&bw.seen, from);
    assert!(!seqs.is_empty());
    assert_eq!(
        seqs,
        vec![0],
        "message zero is surfaced once, and nothing else is"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// Deleting a conversation: a refused closed-marker write or a refused erase
/// stops the delete and leaves the conversation; a delete that goes through is
/// answered with its token, removes the conversation from the roster and the
/// channel from the network, and a second delete is refused.
#[tokio::test(start_paused = true)]
async fn a_delete_is_answered_and_stops_on_any_refused_write() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    let lookup_key = a.outgoing_lookup_key(&b);
    let channel_held = |dht: &Arc<Mutex<Dht>>| {
        dht.lock()
            .expect("the network lock")
            .records
            .keys()
            .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key)
    };
    assert!(channel_held(&dht), "A's channel is on the network");

    a_fake.fail_write(1);
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(41),
        peer: a_peer,
    })
    .await;
    let at = aw.wait_for("the refused marker", refused(41)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    assert!(channel_held(&dht), "a refused marker erases nothing");
    a_fake.faults().fail_write_at = None;

    a_fake.faults().fail_erase = true;
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(42),
        peer: a_peer,
    })
    .await;
    let at = aw.wait_for("the refused erase", refused(42)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    a_fake.faults().fail_erase = false;

    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(43),
        peer: a_peer,
    })
    .await;
    let at = aw
        .wait_for("the delete's answer", |event| {
            matches!(event, RunnerEvent::Deleted { token, peer }
                if token.0 == 43 && *peer == a_peer)
        })
        .await;
    let at = aw
        .wait_from(at, "the roster after the delete", is_roster)
        .await;
    assert!(
        roster(&aw.seen[at]).iter().all(|row| row.peer != a_peer),
        "the conversation is gone from the roster"
    );
    assert!(!channel_held(&dht), "the channel is erased");

    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(44),
        peer: a_peer,
    })
    .await;
    let at = aw.wait_for("the second delete's answer", refused(44)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::UnknownConversation);
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// Shutdown returns within the grace period while a record call is blocked, and
/// once stop is requested the runner reads no ring after the blocked call
/// returns. A runner with nothing in progress finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_returns_within_the_grace_period_while_a_call_blocks() {
    let config = RunnerConfig {
        tick: Duration::from_millis(50),
        grace: Duration::from_millis(500),
    };
    let Scene {
        a: _a,
        b: _b,
        aw,
        bw,
        b_fake,
        ..
    } = establish(config).await;

    let gate = Arc::new(Gate::default());
    let _release_gate = ReleaseOnDrop(Arc::clone(&gate));
    b_fake.faults().gate_drop = Some(Arc::clone(&gate));
    gate.reached().await;
    let reads_before = b_fake.calls().channel_reads;
    let started = std::time::Instant::now();
    let stop = tokio::time::timeout(Duration::from_secs(30), bw.stop()).await;
    let waited = started.elapsed();
    b_fake.faults().gate_drop = None;
    gate.release();
    let stop = stop.expect("shutdown returned while the call was still blocked");
    assert!(
        matches!(stop.outcome, ShutdownOutcome::TimedOut(_)),
        "{stop:?}"
    );
    assert!(
        waited <= config.grace + Duration::from_secs(1),
        "waited {waited:?}"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        b_fake.calls().channel_reads,
        reads_before,
        "no ring is read after stop is requested"
    );

    assert!(
        finished(&aw.stop().await),
        "a runner with nothing in progress finishes"
    );
}

/// A collection in progress when shutdown is asked for delivers its messages
/// through the shutdown, and a command still queued is answered as refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_returns_the_messages_a_collection_in_progress_read() {
    let Scene {
        a: _a,
        b: _b,
        aw,
        bw,
        b_fake,
        a_peer,
        b_peer,
        ..
    } = establish(real_clock()).await;

    let paused = Arc::new(Gate::default());
    let _release_paused = ReleaseOnDrop(Arc::clone(&paused));
    b_fake.faults().gate_drop = Some(Arc::clone(&paused));
    paused.reached().await;
    for (token, body) in [(30u64, b"m1"), (31, b"m2"), (32, b"m3")] {
        aw.send(RunnerCommand::Send {
            token: CommandToken(token),
            peer: a_peer,
            body: body.to_vec(),
        })
        .await;
    }
    let mut aw = aw;
    for token in 30..=32 {
        aw.wait_for("A's send", sent(token)).await;
    }
    let publishing = Arc::new(Gate::default());
    let _release_publishing = ReleaseOnDrop(Arc::clone(&publishing));
    {
        let mut faults = b_fake.faults();
        faults.gate_drop = None;
        faults.gate_control = Some(Arc::clone(&publishing));
    }
    paused.release();
    publishing.reached().await;

    let Watch { handle, .. } = bw;
    handle
        .send(RunnerCommand::Send {
            token: CommandToken(77),
            peer: b_peer,
            body: b"late".to_vec(),
        })
        .await
        .expect("the runner takes commands");
    let stopping = tokio::spawn(handle.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    b_fake.faults().gate_control = None;
    publishing.release();
    let stop = tokio::time::timeout(Duration::from_secs(30), stopping)
        .await
        .expect("shutdown returned")
        .expect("the shutdown task ran");
    assert!(finished(&stop), "{stop:?}");
    let seqs: Vec<u64> = stop
        .undelivered
        .iter()
        .filter_map(|event| match event {
            RunnerEvent::Message { from, seq, .. } if *from == b_peer => Some(*seq),
            _ => None,
        })
        .collect();
    assert!(!seqs.is_empty(), "undelivered: {:?}", stop.undelivered);
    assert_eq!(seqs, vec![1, 2, 3]);
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Refused {
                token: Some(CommandToken(77)),
                reason: Refusal::ShuttingDown
            }
        )),
        "undelivered: {:?}",
        stop.undelivered
    );
    assert!(finished(&aw.stop().await));
}

/// One refused write reads as one failure in the next health report.
#[tokio::test(start_paused = true)]
async fn a_failed_write_is_counted_in_the_next_health_report() {
    let dht = network();
    let faulty = Fake::on(&dht);
    faulty.fail_write(1);
    let a = Profile::new();
    let mut aw = a.spawn(&faulty, RunnerConfig::default());
    let at = aw.wait_for("A's startup", is_health).await;
    assert_eq!(
        faulty.calls().advert_publishes,
        1,
        "the publish was attempted"
    );
    assert_eq!(health(&aw.seen[at]).advert_write_failures, 1);

    let clean = Fake::on(&dht);
    let b = Profile::new();
    let mut bw = b.spawn(&clean, RunnerConfig::default());
    let at = bw.wait_for("B's startup", is_health).await;
    assert_eq!(clean.calls().advert_publishes, 1);
    assert_eq!(health(&bw.seen[at]).advert_write_failures, 0);
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// Every counter of a failed or timed-out record store call, by name.
fn record_call_counters(counters: &HealthCounters) -> [(&'static str, u64); 23] {
    [
        ("advert_read_failures", counters.advert_read_failures),
        ("advert_read_timeouts", counters.advert_read_timeouts),
        ("advert_inspect_failures", counters.advert_inspect_failures),
        ("advert_inspect_timeouts", counters.advert_inspect_timeouts),
        ("advert_write_failures", counters.advert_write_failures),
        ("advert_write_timeouts", counters.advert_write_timeouts),
        ("drop_read_failures", counters.drop_read_failures),
        ("drop_read_timeouts", counters.drop_read_timeouts),
        ("drop_write_failures", counters.drop_write_failures),
        ("drop_write_timeouts", counters.drop_write_timeouts),
        ("drop_inspect_failures", counters.drop_inspect_failures),
        ("drop_inspect_timeouts", counters.drop_inspect_timeouts),
        ("channel_open_failures", counters.channel_open_failures),
        ("channel_open_timeouts", counters.channel_open_timeouts),
        ("channel_read_failures", counters.channel_read_failures),
        ("channel_read_timeouts", counters.channel_read_timeouts),
        (
            "channel_inspect_failures",
            counters.channel_inspect_failures,
        ),
        (
            "channel_inspect_timeouts",
            counters.channel_inspect_timeouts,
        ),
        ("channel_write_failures", counters.channel_write_failures),
        ("channel_write_timeouts", counters.channel_write_timeouts),
        ("channel_erase_failures", counters.channel_erase_failures),
        ("channel_erase_timeouts", counters.channel_erase_timeouts),
        ("local_refusals", counters.local_refusals),
    ]
}

/// Every counter that is not a record store call's, by name.
fn other_counters(counters: &HealthCounters) -> [(&'static str, u64); 8] {
    [
        ("advert_failures", counters.advert_failures),
        ("network_not_answering", counters.network_not_answering),
        ("hellos_dropped", counters.hellos_dropped),
        (
            "hellos_already_collected",
            counters.hellos_already_collected,
        ),
        ("hellos_unsettled", counters.hellos_unsettled),
        ("conversation_failures", counters.conversation_failures),
        ("store_failures", counters.store_failures),
        ("requests_evicted", counters.requests_evicted),
    ]
}

/// A drop holding nothing on the network is left alone, and counted only in
/// `network_not_answering`, by a pass whose own advert the network has lost:
/// a relaunch whose advert rewrite is refused counts that refusal as its one
/// record call failure and does not write the hello. The same relaunch with the
/// advert back on the network writes it.
#[tokio::test(start_paused = true)]
async fn a_lost_advert_leaves_an_empty_drop_alone_and_counts_no_drop_call() {
    let dht = network();
    let (a, c) = (Profile::new(), Profile::new());
    let mut cw = c.spawn(&Fake::on(&dht), RunnerConfig::default());
    cw.wait_for("C's startup", is_health).await;
    assert!(finished(&cw.stop().await));

    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    a_fake.faults().fail_drop_writes = true;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: c.pk.clone(),
        body: b"to C".to_vec(),
    })
    .await;
    aw.wait_for("the refused hello", refused(1)).await;
    assert!(finished(&aw.stop().await));
    let drop_held = |dht: &Arc<Mutex<Dht>>| {
        dht.lock()
            .expect("the network lock")
            .records
            .keys()
            .any(|(kind, name, _)| *kind == DROP && *name == c.drop_name())
    };
    assert!(!drop_held(&dht), "C's drop holds nothing on the network");

    a_fake.net().evict(a.advert_key());
    let unanswered = a_fake.restart();
    unanswered
        .faults()
        .plan
        .push((ADVERT, Op::Write, Fault::Refused));
    let mut aw = a.spawn(&unanswered, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    let report = health(&aw.seen[at]);
    for (counter, count) in record_call_counters(&report) {
        let expected = u64::from(counter == "advert_write_failures");
        assert_eq!(count, expected, "{counter} after the relaunch");
    }
    for (counter, count) in other_counters(&report) {
        let expected = u64::from(counter == "network_not_answering");
        assert_eq!(count, expected, "{counter} after the relaunch");
    }
    assert!(
        unanswered.faults().plan.is_empty(),
        "the advert rewrite was refused"
    );
    assert_eq!(
        unanswered.calls().hello_writes,
        0,
        "the hello is left alone"
    );
    assert!(!drop_held(&dht));
    assert!(finished(&aw.stop().await));

    let answering = a_fake.restart();
    let mut aw = a.spawn(&answering, RunnerConfig::default());
    let at = aw.wait_for("the relaunch with the advert", is_health).await;
    let report = health(&aw.seen[at]);
    for (counter, count) in record_call_counters(&report)
        .into_iter()
        .chain(other_counters(&report))
    {
        assert_eq!(count, 0, "{counter} after the relaunch with the advert");
    }
    assert_eq!(
        answering.calls().advert_publishes,
        1,
        "the advert is put back"
    );
    assert_eq!(answering.calls().hello_writes, 1, "the hello is written");
    assert!(drop_held(&dht), "C's drop holds the hello");
    assert!(finished(&aw.stop().await));
}

/// A scan whose read of a held request's slot runs out of time is partial: the
/// request keeps its id, is not surfaced again, and is accepted under that id.
#[tokio::test(start_paused = true)]
async fn a_held_request_survives_a_scan_whose_read_of_its_slot_times_out() {
    held_request_survives_an_unread_slot(Fault::TimedOut, |counters| counters.drop_read_timeouts)
        .await;
}

/// A scan whose read of a held request's slot is refused before it reaches the
/// network is partial in the same way.
#[tokio::test(start_paused = true)]
async fn a_held_request_survives_a_scan_whose_read_of_its_slot_is_refused_locally() {
    held_request_survives_an_unread_slot(Fault::Local, |counters| counters.local_refusals).await;
}

/// A scan whose drop inspect fails but whose slot reads all answer is complete:
/// a held request whose hello the network no longer holds is withdrawn, and an
/// accept under its id is refused.
#[tokio::test(start_paused = true)]
async fn a_scan_whose_inspect_fails_still_withdraws_a_request_whose_hello_is_gone() {
    withdrawn_after_a_scan_fault(Fault::Refused, |counters| counters.drop_inspect_failures).await;
}

/// A scan whose drop inspect is refused before the network but whose slot
/// reads all answer is complete in the same way.
#[tokio::test(start_paused = true)]
async fn a_scan_whose_inspect_is_refused_locally_still_withdraws_a_request_whose_hello_is_gone() {
    withdrawn_after_a_scan_fault(Fault::Local, |counters| counters.local_refusals).await;
}

/// A drop scan and the slot read after it, each refused before the network but
/// for different reasons, are two local refusals.
#[tokio::test(start_paused = true)]
async fn a_scan_and_its_read_refused_locally_for_different_reasons_count_twice() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    {
        let mut faults = a_fake.faults();
        faults.plan.push((DROP, Op::Scan, Fault::Local));
        faults.plan.push((DROP, Op::Read, Fault::LocalOther));
    }
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    let at = aw.wait_for("A's startup", is_health).await;
    let report = health(&aw.seen[at]);
    for (counter, count) in record_call_counters(&report)
        .into_iter()
        .chain(other_counters(&report))
    {
        let expected = if counter == "local_refusals" { 2 } else { 0 };
        assert_eq!(count, expected, "{counter} after the startup scan");
    }
    assert!(
        a_fake.faults().plan.is_empty(),
        "both refusals landed in the scan"
    );
    assert!(finished(&aw.stop().await));
}

/// B holds A's request; A's hello leaves the network; the next scan's drop
/// inspect fails as `fault` says, which `counted` reads back, while every slot
/// read answers. The scan is complete, so the request is withdrawn and an
/// accept under its id is refused.
async fn withdrawn_after_a_scan_fault(fault: Fault, counted: fn(&HealthCounters) -> u64) {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    assert!(finished(&aw.stop().await));

    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    let slot = hello_slot(&dht, &b);
    dht.lock()
        .expect("the network lock")
        .evict((DROP, b.drop_name(), slot));
    b_fake.faults().plan.push((DROP, Op::Scan, fault));
    let from = bw.seen.len();
    bw.wait_from(
        from,
        "the scan whose inspect failed",
        |event| matches!(event, RunnerEvent::Health(counters) if counted(counters) == 1),
    )
    .await;
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let at = bw
        .wait_for("the answer to the accept", |event| {
            sent(2)(event) || refused(2)(event)
        })
        .await;
    assert_eq!(
        refusal(&bw.seen[at]),
        Refusal::UnknownRequest,
        "the request whose hello is gone was withdrawn"
    );
    assert!(finished(&bw.stop().await));
}

/// A drop scan refused before it reaches the network, followed by the slot read
/// refusing for the same local reason, is one local refusal.
#[tokio::test(start_paused = true)]
async fn a_scan_and_its_read_refused_locally_together_count_once() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    {
        let mut faults = a_fake.faults();
        faults.plan.push((DROP, Op::Scan, Fault::Local));
        faults.plan.push((DROP, Op::Read, Fault::Local));
    }
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    let at = aw.wait_for("A's startup", is_health).await;
    let report = health(&aw.seen[at]);
    for (counter, count) in record_call_counters(&report)
        .into_iter()
        .chain(other_counters(&report))
    {
        assert_eq!(
            count,
            u64::from(counter == "local_refusals"),
            "{counter} after the startup scan"
        );
    }
    assert!(
        a_fake.faults().plan.is_empty(),
        "both refusals landed in the scan"
    );
    assert!(finished(&aw.stop().await));
}

/// A counter a command moves is reported as soon as the command is answered,
/// before the schedule wakes again.
#[tokio::test(start_paused = true)]
async fn a_failure_a_command_counts_is_reported_before_the_next_wake() {
    let Scene {
        a: _a,
        b: _b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    a_fake
        .faults()
        .plan
        .push((CHANNEL, Op::Write, Fault::Refused));
    let asked = tokio::time::Instant::now();
    aw.send(RunnerCommand::Send {
        token: CommandToken(31),
        peer: a_peer,
        body: b"refused".to_vec(),
    })
    .await;
    let from = aw.seen.len();
    aw.wait_from(from, "the report of the refused write", |event| {
        matches!(event, RunnerEvent::Health(counters) if counters.channel_write_failures == 1)
    })
    .await;
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "reported with no wake of the schedule between: {:?}",
        asked.elapsed()
    );
    assert!(finished(&aw.stop().await));
}

/// A counter a pass moves before a stop cuts that pass short is reported among
/// the events the shutdown hands back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_counted_in_a_pass_a_stop_cuts_short_is_reported() {
    let config = real_clock();
    let Scene {
        a: _a,
        b: _b,
        a_fake,
        aw,
        bw,
        ..
    } = establish(config).await;
    assert!(finished(&bw.stop().await));
    let held = Arc::new(Gate::default());
    let _release_held = ReleaseOnDrop(Arc::clone(&held));
    {
        let mut faults = a_fake.faults();
        faults.plan.push((DROP, Op::Read, Fault::Refused));
        faults.gate_drop = Some(Arc::clone(&held));
    }
    let Watch { handle, .. } = aw;
    held.reached().await;
    let mut stopping = Box::pin(handle.shutdown());
    // A shutdown's first poll sets the stop flag before it waits on anything, so
    // polling it once here orders the stop before the held read is released.
    tokio::select! {
        biased;
        _ = &mut stopping => panic!("the shutdown returned while a read was held"),
        () = std::future::ready(()) => {}
    }
    a_fake.faults().gate_drop = None;
    held.release();
    let stop = tokio::time::timeout(Duration::from_secs(30), stopping)
        .await
        .expect("shutdown returned");
    assert!(finished(&stop), "{stop:?}");
    assert!(
        a_fake.faults().plan.is_empty(),
        "the refused read landed in the pass the stop cut short"
    );
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Health(counters) if counters.drop_read_failures == 1
        )),
        "the report of the refused read is among the events the shutdown hands back: {:?}",
        stop.undelivered
    );
}

/// The slot of the one hello in `to`'s drop.
fn hello_slot(dht: &Arc<Mutex<Dht>>, to: &Profile) -> u16 {
    dht.lock()
        .expect("the network lock")
        .records
        .keys()
        .find(|(kind, name, _)| *kind == DROP && *name == to.drop_name())
        .map(|(_, _, slot)| *slot)
        .expect("a hello is in the drop")
}

/// B holds A's request; the next scan fails to read its slot as `fault` says,
/// which `counted` reads back. The scan is partial, so the request keeps its id
/// through later scans, is not surfaced again, and is accepted under that id.
async fn held_request_survives_an_unread_slot(fault: Fault, counted: fn(&HealthCounters) -> u64) {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    assert!(finished(&aw.stop().await));

    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    let slot = hello_slot(&dht, &b);
    b_fake.faults().fail_drop_slot_read = Some((slot, fault));
    let from = bw.seen.len();
    bw.wait_from(
        from,
        "the scan whose read failed",
        |event| matches!(event, RunnerEvent::Health(counters) if counted(counters) == 1),
    )
    .await;
    assert!(
        b_fake.faults().fail_drop_slot_read.is_none(),
        "the read of the request's slot failed"
    );
    let reads_before = b_fake.calls().drop_reads;
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    bw.drain();
    assert!(
        b_fake.calls().drop_reads >= reads_before + usize::from(drop_plane::DROP_SUBKEYS),
        "a later scan read every slot again"
    );
    let surfaced = bw
        .seen
        .iter()
        .filter(|event| request_from(&a.pk)(event))
        .count();
    assert_eq!(
        surfaced, 1,
        "the request is surfaced once, whatever later scans read"
    );

    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let at = bw
        .wait_for("the answer to the accept", |event| {
            sent(2)(event) || refused(2)(event)
        })
        .await;
    assert!(
        matches!(bw.seen[at], RunnerEvent::Sent { .. }),
        "the request is accepted under the id it was first surfaced with: {:?}",
        bw.seen[at]
    );
    assert!(finished(&bw.stop().await));
}

/// A counter a command moves is reported before a shutdown that follows at
/// once: the events the shutdown hands back carry the report.
#[tokio::test(start_paused = true)]
async fn a_failure_a_command_counts_is_reported_before_the_runner_stops() {
    let Scene {
        a: _a,
        b: _b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    a_fake
        .faults()
        .plan
        .push((CHANNEL, Op::Write, Fault::Refused));
    aw.send(RunnerCommand::Send {
        token: CommandToken(30),
        peer: a_peer,
        body: b"refused".to_vec(),
    })
    .await;
    let at = aw.wait_for("the refused send", refused(30)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    let stop = aw.stop().await;
    assert!(finished(&stop));
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Health(counters) if counters.channel_write_failures == 1
        )),
        "the report of the refused write is among the events the shutdown hands back: {:?}",
        stop.undelivered
    );
}

/// Faults of different kinds pending at once are each counted once in the pass
/// they land in, beside exactly the `network_not_answering` that pass must
/// produce. A relaunch whose own channel the network has lost entirely meets
/// three: the startup advert check's inspect refused, the drop scan's first
/// slot read timed out, and the advert inspect the channel repair takes to see
/// whether the network answers timed out, so the channel is left alone.
#[tokio::test(start_paused = true)]
async fn faults_of_different_kinds_pending_in_one_pass_are_each_counted_once() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        aw,
        bw,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    {
        let mut net = dht.lock().expect("the network lock");
        let lost: Vec<Key> = net
            .records
            .keys()
            .filter(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key)
            .copied()
            .collect();
        assert!(
            lost.len() >= 2,
            "A's channel holds its control subkey and a slot"
        );
        for key in lost {
            net.evict(key);
        }
    }
    let relaunched = a_fake.restart();
    {
        let mut faults = relaunched.faults();
        faults.plan.push((ADVERT, Op::Inspect, Fault::Refused));
        faults.plan.push((DROP, Op::Read, Fault::TimedOut));
        faults.plan.push((ADVERT, Op::Inspect, Fault::TimedOut));
    }
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    let report = health(&aw.seen[at]);
    for (counter, count) in record_call_counters(&report)
        .into_iter()
        .chain(other_counters(&report))
    {
        let expected = u64::from(matches!(
            counter,
            "advert_inspect_failures"
                | "advert_inspect_timeouts"
                | "drop_read_timeouts"
                | "network_not_answering"
        ));
        assert_eq!(count, expected, "{counter} after the pass");
    }
    assert!(
        relaunched.faults().plan.is_empty(),
        "every planned fault landed in the pass"
    );
    assert_eq!(
        relaunched.calls().control_writes,
        0,
        "the lost channel is left alone"
    );
    assert_eq!(
        relaunched.calls().ring_writes,
        0,
        "the lost channel is left alone"
    );
    assert!(finished(&aw.stop().await));
}

/// What sets off the record call a planned fault lands on.
#[derive(Debug, Clone, Copy)]
enum Trigger {
    /// The schedule alone: a tick, a repair look or an advert poll.
    Schedule,
    /// A message to B, with this token.
    Send(u64),
    /// A first contact with C, with this token.
    FirstContact(u64),
    /// A delete of the conversation with B, with this token.
    Delete(u64),
    /// The network losing A's advert, which the next advert poll rewrites.
    LoseAdvert,
}

/// Every fetch, inspect, write, open and erasure of an advert, a drop slot or a
/// channel that fails is counted in the next health report: under its
/// `_timeouts` counter where the call ran out of time, under its `_failures`
/// counter where it was refused, under `local_refusals` where it never reached
/// the network, and under no other counter, except that a failed look at this
/// node's own advert may also leave a drop holding nothing alone, which
/// `network_not_answering` counts. The drop inspect a scan takes before its
/// first slot read counts under the drop inspect counters.
#[tokio::test(start_paused = true)]
async fn every_failed_or_timed_out_record_call_is_counted_by_name() {
    let Scene {
        dht,
        a,
        b: _b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    let c = Profile::new();
    let mut cw = c.spawn(&Fake::on(&dht), RunnerConfig::default());
    cw.wait_for("C's startup", is_health).await;
    assert!(finished(&cw.stop().await));

    // B no longer collects, so this message keeps a repair look scheduled.
    aw.send(RunnerCommand::Send {
        token: CommandToken(50),
        peer: a_peer,
        body: b"outstanding".to_vec(),
    })
    .await;
    aw.wait_for("the uncollected send", sent(50)).await;
    let at = aw
        .seen
        .iter()
        .rposition(is_health)
        .expect("A reported its health");
    let mut before = health(&aw.seen[at]);
    for (counter, count) in record_call_counters(&before) {
        assert_eq!(count, 0, "{counter} reads zero before any fault");
    }

    let plan = [
        (
            CHANNEL,
            Op::Read,
            Fault::TimedOut,
            "channel_read_timeouts",
            Trigger::Schedule,
        ),
        (
            CHANNEL,
            Op::Read,
            Fault::Refused,
            "channel_read_failures",
            Trigger::Schedule,
        ),
        (
            DROP,
            Op::Read,
            Fault::TimedOut,
            "drop_read_timeouts",
            Trigger::Schedule,
        ),
        (
            DROP,
            Op::Read,
            Fault::Refused,
            "drop_read_failures",
            Trigger::Schedule,
        ),
        (
            DROP,
            Op::Scan,
            Fault::TimedOut,
            "drop_inspect_timeouts",
            Trigger::Schedule,
        ),
        (
            DROP,
            Op::Scan,
            Fault::Refused,
            "drop_inspect_failures",
            Trigger::Schedule,
        ),
        (
            CHANNEL,
            Op::Write,
            Fault::TimedOut,
            "channel_write_timeouts",
            Trigger::Send(51),
        ),
        (
            CHANNEL,
            Op::Write,
            Fault::Refused,
            "channel_write_failures",
            Trigger::Send(52),
        ),
        (
            CHANNEL,
            Op::Write,
            Fault::Local,
            "local_refusals",
            Trigger::Send(53),
        ),
        (
            CHANNEL,
            Op::Inspect,
            Fault::TimedOut,
            "channel_inspect_timeouts",
            Trigger::Schedule,
        ),
        (
            CHANNEL,
            Op::Inspect,
            Fault::Refused,
            "channel_inspect_failures",
            Trigger::Schedule,
        ),
        (
            CHANNEL,
            Op::Erase,
            Fault::TimedOut,
            "channel_erase_timeouts",
            Trigger::Delete(70),
        ),
        (
            CHANNEL,
            Op::Erase,
            Fault::Refused,
            "channel_erase_failures",
            Trigger::Delete(71),
        ),
        (
            ADVERT,
            Op::Read,
            Fault::TimedOut,
            "advert_read_timeouts",
            Trigger::FirstContact(60),
        ),
        (
            ADVERT,
            Op::Read,
            Fault::Refused,
            "advert_read_failures",
            Trigger::FirstContact(61),
        ),
        (
            CHANNEL,
            Op::Open,
            Fault::TimedOut,
            "channel_open_timeouts",
            Trigger::FirstContact(64),
        ),
        (
            CHANNEL,
            Op::Open,
            Fault::Refused,
            "channel_open_failures",
            Trigger::FirstContact(65),
        ),
        (
            DROP,
            Op::Write,
            Fault::TimedOut,
            "drop_write_timeouts",
            Trigger::FirstContact(62),
        ),
        (
            DROP,
            Op::Write,
            Fault::Refused,
            "drop_write_failures",
            Trigger::FirstContact(63),
        ),
        (
            DROP,
            Op::Inspect,
            Fault::TimedOut,
            "drop_inspect_timeouts",
            Trigger::Schedule,
        ),
        (
            DROP,
            Op::Inspect,
            Fault::Refused,
            "drop_inspect_failures",
            Trigger::Schedule,
        ),
        (
            ADVERT,
            Op::Inspect,
            Fault::TimedOut,
            "advert_inspect_timeouts",
            Trigger::Schedule,
        ),
        (
            ADVERT,
            Op::Inspect,
            Fault::Refused,
            "advert_inspect_failures",
            Trigger::Schedule,
        ),
        (
            ADVERT,
            Op::Write,
            Fault::TimedOut,
            "advert_write_timeouts",
            Trigger::LoseAdvert,
        ),
        (
            ADVERT,
            Op::Write,
            Fault::Refused,
            "advert_write_failures",
            Trigger::Schedule,
        ),
    ];
    for (kind, op, fault, name, trigger) in plan {
        assert!(
            record_call_counters(&before)
                .iter()
                .any(|(counter, _)| *counter == name),
            "{name} is a record call counter"
        );
        // C's drop holds nothing on the network while every write of A's hello
        // to it has failed. A pass that finds it so asks A's own advert whether
        // the network answers; where that inspect fails, or the network has
        // lost the advert, the drop is left alone and counted in
        // `network_not_answering`, never as a drop or channel call. So the
        // advert inspect and advert write cases may move that counter, in the
        // report that carries their fault or in one before it, and no case
        // moves any other counter but its own.
        let liveness_may_fail = kind == ADVERT && op != Op::Read;
        let from = aw.seen.len();
        a_fake.faults().plan.push((kind, op, fault));
        match trigger {
            Trigger::Schedule => {}
            Trigger::Send(token) => {
                aw.send(RunnerCommand::Send {
                    token: CommandToken(token),
                    peer: a_peer,
                    body: b"to B".to_vec(),
                })
                .await
            }
            Trigger::FirstContact(token) => {
                aw.send(RunnerCommand::FirstContact {
                    token: CommandToken(token),
                    peer_identity_pk: c.pk.clone(),
                    body: b"to C".to_vec(),
                })
                .await
            }
            Trigger::Delete(token) => {
                aw.send(RunnerCommand::DeleteConversation {
                    token: CommandToken(token),
                    peer: a_peer,
                })
                .await
            }
            Trigger::LoseAdvert => a_fake.net().evict(a.advert_key()),
        }
        let mut at = aw.wait_from(from, name, is_health).await;
        loop {
            let after = health(&aw.seen[at]);
            let landed = a_fake.faults().plan.is_empty();
            for ((counter, was), (_, now)) in record_call_counters(&before)
                .into_iter()
                .zip(record_call_counters(&after))
            {
                let expected = if counter == name && landed {
                    was + 1
                } else {
                    was
                };
                assert_eq!(
                    now, expected,
                    "{counter} in a report after the fault planned for {name} \
                     (landed: {landed})"
                );
            }
            for ((counter, was), (_, now)) in other_counters(&before)
                .into_iter()
                .zip(other_counters(&after))
            {
                if counter == "network_not_answering" && liveness_may_fail {
                    assert!(now >= was, "{counter} never falls");
                } else {
                    assert_eq!(
                        now, was,
                        "{counter} in a report after the fault planned for {name}"
                    );
                }
            }
            assert!(
                landed || after.network_not_answering > before.network_not_answering,
                "a report before the fault planned for {name} landed moved a counter"
            );
            before = after;
            if landed {
                break;
            }
            at = aw.wait_from(at + 1, name, is_health).await;
        }
    }
    for (counter, count) in record_call_counters(&before) {
        let planned = plan
            .iter()
            .filter(|(_, _, _, name, _)| *name == counter)
            .count() as u64;
        assert_eq!(
            count, planned,
            "{counter} counts exactly its planned faults"
        );
    }
    assert!(finished(&aw.stop().await));
}

/// Every 32-byte window of each of `keys`.
fn key_windows(keys: &[&IdentityPk]) -> HashSet<[u8; 32]> {
    keys.iter()
        .flat_map(|key| key.windows(32))
        .map(|window| <[u8; 32]>::try_from(window).expect("a 32-byte window"))
        .collect()
}

/// How many 32-byte windows of `value` are windows of an identity key, and
/// whether `value` holds any of `keys` whole.
fn key_hits(value: &[u8], windows: &HashSet<[u8; 32]>, keys: &[&IdentityPk]) -> (usize, bool) {
    let hits = value
        .windows(32)
        .filter(|window| windows.contains(*window))
        .count();
    let whole = keys.iter().any(|key| {
        value
            .windows(key.len())
            .any(|window| window == key.as_slice())
    });
    (hits, whole)
}

/// No value either runner writes to a channel or a drop slot carries either
/// identity public key, whole or as any 32-byte window, over a whole
/// conversation: a first contact and its acceptance, messages both ways, a
/// relaunch that reseals the lost control subkey and rewrites a lost slot, and
/// a delete. The same scan finds the keys in the opening those control
/// subkeys seal.
#[tokio::test(start_paused = true)]
async fn no_identity_key_appears_in_any_value_the_runner_writes() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        mut aw,
        mut bw,
        a_peer,
        b_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    aw.send(RunnerCommand::Send {
        token: CommandToken(20),
        peer: a_peer,
        body: b"m1".to_vec(),
    })
    .await;
    aw.wait_for("A's m1", sent(20)).await;
    bw.wait_for("m1 at B", message(b_peer, 1, b"m1")).await;
    bw.send(RunnerCommand::Send {
        token: CommandToken(21),
        peer: b_peer,
        body: b"b1".to_vec(),
    })
    .await;
    bw.wait_for("B's b1", sent(21)).await;
    aw.wait_for("b1 at A", message(a_peer, 1, b"b1")).await;
    aw.wait_for("delivery of m1", delivered(a_peer, 1)).await;
    assert!(finished(&bw.stop().await));
    aw.send(RunnerCommand::Send {
        token: CommandToken(22),
        peer: a_peer,
        body: b"m2".to_vec(),
    })
    .await;
    aw.wait_for("A's m2", sent(22)).await;
    assert!(finished(&aw.stop().await));

    let a_lookup_key = a.outgoing_lookup_key(&b);
    let b_lookup_key = b.outgoing_lookup_key(&a);
    let written_to = |dht: &Arc<Mutex<Dht>>, name: [u8; 32], control: bool| {
        dht.lock()
            .expect("the network lock")
            .written
            .iter()
            .filter(|((kind, n, subkey), _)| {
                *kind == CHANNEL && *n == name && (*subkey == channel::CONTROL_SUBKEY) == control
            })
            .count()
    };
    let setup_controls = written_to(&dht, a_lookup_key, true);
    assert!(setup_controls >= 1, "A's opening was written");
    assert!(
        written_to(&dht, b_lookup_key, true) >= 1,
        "B's control values are among the values scanned"
    );
    assert!(
        written_to(&dht, a_lookup_key, false) + written_to(&dht, b_lookup_key, false) >= 3,
        "message slots of both directions are among the values scanned"
    );

    let opening = {
        let store = Store::open(a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
            .expect("A's store opens");
        let loaded = store.load().expect("A's store loads");
        assert_eq!(loaded.convs.len(), 1);
        loaded.convs[0]
            .state
            .own_opening
            .as_ref()
            .expect("A's opening is recorded")
            .to_vec()
    };

    let lookup_key = a.outgoing_lookup_key(&b);
    {
        let mut net = dht.lock().expect("the network lock");
        net.evict((CHANNEL, lookup_key, channel::CONTROL_SUBKEY));
        net.evict((CHANNEL, lookup_key, channel::slot_for(2)));
    }
    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    assert_eq!(
        relaunched.calls().control_writes,
        1,
        "the lost control subkey is resealed"
    );
    assert_eq!(
        relaunched.calls().ring_writes,
        1,
        "the lost slot is rewritten"
    );
    let before_delete = dht.lock().expect("the network lock").written.len();
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(23),
        peer: a_peer,
    })
    .await;
    aw.wait_for("the delete's answer", |event| {
        matches!(event, RunnerEvent::Deleted { token, peer }
            if token.0 == 23 && *peer == a_peer)
    })
    .await;
    assert_eq!(
        relaunched.calls().control_writes,
        2,
        "the closed marker is written"
    );
    let marker: Vec<(Key, Vec<u8>)> = dht.lock().expect("the network lock").written
        [before_delete..]
        .iter()
        .filter(|((kind, name, subkey), _)| {
            *kind == CHANNEL && *name == a_lookup_key && *subkey == channel::CONTROL_SUBKEY
        })
        .cloned()
        .collect();
    assert_eq!(
        marker.len(),
        1,
        "the delete writes one control value, the closed marker"
    );
    assert!(finished(&aw.stop().await));

    let keys = [&a.pk, &b.pk];
    let windows = key_windows(&keys);
    assert!(
        key_hits(&opening, &windows, &keys).1,
        "the scan finds an identity key whole in a plaintext opening"
    );
    assert!(
        key_hits(&opening, &windows, &keys).0 >= 2 * (a.pk.len() - 31),
        "the scan finds every window of both keys in a plaintext opening"
    );

    let written: Vec<(Key, Vec<u8>)> = dht
        .lock()
        .expect("the network lock")
        .written
        .iter()
        .filter(|((kind, _, _), _)| *kind == CHANNEL || *kind == DROP)
        .cloned()
        .collect();
    let control_writes = written
        .iter()
        .filter(|((kind, name, subkey), _)| {
            *kind == CHANNEL && *name == lookup_key && *subkey == channel::CONTROL_SUBKEY
        })
        .count();
    assert!(
        written.iter().any(|((kind, _, _), _)| *kind == DROP),
        "the hellos are among the values scanned"
    );
    assert_eq!(
        control_writes,
        setup_controls + 2,
        "the setup's control writes, the reseal and the closed marker, and no other"
    );
    assert!(
        written.contains(&marker[0]),
        "the closed marker is among the values scanned"
    );
    for (key, value) in &written {
        assert_eq!(
            key_hits(value, &windows, &keys),
            (0, false),
            "no identity key in the value written to {key:?}"
        );
    }
}

/// The sequence numbers of every message from `from` among `events`.
fn messages_from(events: &[RunnerEvent], from: CorrespondenceLabel) -> Vec<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            RunnerEvent::Message { from: f, seq, .. } if *f == from => Some(*seq),
            _ => None,
        })
        .collect()
}

/// A shutdown whose grace period ends inside a flow call returns with the task
/// still running. The command still queued is answered by the shutdown itself,
/// the task reads as unfinished while its call is held, and the messages that
/// call collected come back through the task's end once it returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_shutdown_hands_back_the_running_task_and_its_messages() {
    let config = RunnerConfig {
        tick: Duration::from_millis(50),
        grace: Duration::from_millis(300),
    };
    let Scene {
        a: _a,
        b: _b,
        aw,
        bw,
        b_fake,
        a_peer,
        b_peer,
        ..
    } = establish(config).await;

    let paused = Arc::new(Gate::default());
    let _release_paused = ReleaseOnDrop(Arc::clone(&paused));
    b_fake.faults().gate_drop = Some(Arc::clone(&paused));
    paused.reached().await;
    let mut aw = aw;
    for (token, body) in [(30u64, b"m1"), (31, b"m2"), (32, b"m3")] {
        aw.send(RunnerCommand::Send {
            token: CommandToken(token),
            peer: a_peer,
            body: body.to_vec(),
        })
        .await;
        aw.wait_for("A's send", sent(token)).await;
    }
    let publishing = Arc::new(Gate::default());
    let _release_publishing = ReleaseOnDrop(Arc::clone(&publishing));
    {
        let mut faults = b_fake.faults();
        faults.gate_drop = None;
        faults.gate_control = Some(Arc::clone(&publishing));
    }
    paused.release();
    publishing.reached().await;

    let Watch { handle, .. } = bw;
    handle
        .send(RunnerCommand::Send {
            token: CommandToken(77),
            peer: b_peer,
            body: b"late".to_vec(),
        })
        .await
        .expect("the runner takes commands");
    let stop = tokio::time::timeout(Duration::from_secs(30), handle.shutdown())
        .await
        .expect("shutdown returned while the call was held");
    assert!(
        messages_from(&stop.undelivered, b_peer).is_empty(),
        "the held call has not handed over its bodies yet: {:?}",
        stop.undelivered
    );
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Refused {
                token: Some(CommandToken(77)),
                reason: Refusal::ShuttingDown
            }
        )),
        "the queued command is answered by the shutdown: {:?}",
        stop.undelivered
    );
    let end = match stop.outcome {
        ShutdownOutcome::TimedOut(end) => end,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !end.is_finished(),
        "the task has not ended while its call is held"
    );

    b_fake.faults().gate_control = None;
    publishing.release();
    let late = tokio::time::timeout(Duration::from_secs(30), end.finish())
        .await
        .expect("the task ended once its call returned");
    assert!(finished(&late), "{late:?}");
    let seqs = messages_from(&late.undelivered, b_peer);
    assert!(!seqs.is_empty(), "late events: {:?}", late.undelivered);
    assert_eq!(seqs, vec![1, 2, 3]);
    assert!(finished(&aw.stop().await));
}

/// Once stop is asked for, the repair steps write nothing further. A relaunch
/// runs them over a channel with two lost slots; its channel inspect is held
/// while stop is requested, and no slot is rewritten after it returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_asked_for_during_the_repair_steps_writes_nothing_further() {
    let config = real_clock();
    let Scene {
        dht,
        a,
        b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(config).await;
    assert!(finished(&bw.stop().await));
    for (token, body) in [(20u64, b"m1"), (21, b"m2")] {
        aw.send(RunnerCommand::Send {
            token: CommandToken(token),
            peer: a_peer,
            body: body.to_vec(),
        })
        .await;
        aw.wait_for("the send", sent(token)).await;
    }
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    {
        let mut net = dht.lock().expect("the network lock");
        net.evict((CHANNEL, lookup_key, channel::slot_for(1)));
        net.evict((CHANNEL, lookup_key, channel::slot_for(2)));
    }

    let held = Arc::new(Gate::default());
    let _release_held = ReleaseOnDrop(Arc::clone(&held));
    let relaunched = a_fake.restart();
    relaunched.faults().gate_inspect_channel = Some(Arc::clone(&held));
    let Watch { handle, .. } = a.spawn(&relaunched, config);
    held.reached().await;
    let stopping = tokio::spawn(handle.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    relaunched.faults().gate_inspect_channel = None;
    held.release();
    let stop = tokio::time::timeout(Duration::from_secs(30), stopping)
        .await
        .expect("shutdown returned")
        .expect("the shutdown task ran");
    assert!(finished(&stop), "{stop:?}");
    assert!(
        relaunched.calls().inspect_channel >= 1,
        "the channel was inspected"
    );
    assert_eq!(
        relaunched.calls().ring_writes,
        0,
        "no lost slot is rewritten once stop is asked for"
    );
    assert_eq!(relaunched.calls().control_writes, 0);
}

/// An acceptor relaunched after the initiator has read its hello back takes
/// the initiator's published cursor before deciding, and writes no hello,
/// although the initiator has erased the slot that hello occupied.
#[tokio::test(start_paused = true)]
async fn an_acceptor_relaunched_after_its_hello_was_read_writes_no_hello() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    let at = aw.wait_for("A's first contact", sent(1)).await;
    let a_peer = sent_peer(&aw.seen[at]);
    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("B's acceptance", sent(2)).await;
    assert!(finished(&bw.stop().await));

    let controls_before = a_fake.calls().control_writes;
    aw.wait_for("A's acceptance", accepted(a_peer)).await;
    tokio::time::sleep(Duration::from_secs(5 * 60)).await;
    assert!(
        a_fake.calls().control_writes > controls_before,
        "A published its cursor over B's reply"
    );

    let relaunched = b_fake.restart();
    let mut bw = b.spawn(&relaunched, RunnerConfig::default());
    bw.wait_for("B's relaunch", is_health).await;
    assert_eq!(
        relaunched.calls().hello_writes,
        0,
        "a hello back the initiator has read is not rewritten"
    );
    assert!(
        relaunched.calls().channel_reads > 0,
        "B read A's published cursor"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// Held requests are kept to a cap by dropping the ones seen longest ago.
#[test]
fn held_requests_beyond_the_cap_are_dropped_oldest_seen_first() {
    let entry = |byte: u8, seen: u64| HeldRequest {
        held: Held::StartedOver(Box::new([byte; IDENTITY_PK_LEN])),
        seen,
    };
    let id = |serial| ContactRequestId { epoch: 7, serial };
    let mut requests = BTreeMap::new();
    requests.insert(id(1), entry(1, 5));
    requests.insert(id(2), entry(2, 1));
    requests.insert(id(3), entry(3, 3));
    assert_eq!(
        retain_newest(&mut requests, 3),
        0,
        "at the cap nothing is dropped"
    );
    assert_eq!(requests.len(), 3);
    assert_eq!(retain_newest(&mut requests, 2), 1);
    let kept: Vec<u64> = requests.keys().map(|id| id.serial).collect();
    assert!(!kept.is_empty());
    assert_eq!(kept, vec![1, 3], "the request seen longest ago goes first");
}

/// A tick of any size is held within its bounds by the configuration, and
/// jitters within its ±20 % band without overflowing.
#[test]
fn a_tick_of_any_size_is_clamped_and_jitters_without_overflow() {
    let grace = DEFAULT_GRACE;
    assert_eq!(
        RunnerConfig {
            tick: Duration::ZERO,
            grace
        }
        .clamped()
        .tick,
        MIN_TICK
    );
    assert_eq!(
        RunnerConfig {
            tick: Duration::MAX,
            grace
        }
        .clamped()
        .tick,
        MAX_TICK
    );
    assert_eq!(
        RunnerConfig {
            tick: DEFAULT_TICK,
            grace
        }
        .clamped()
        .tick,
        DEFAULT_TICK
    );
    for tick in [MIN_TICK, DEFAULT_TICK, MAX_TICK, Duration::MAX] {
        let got = jittered(tick).as_nanos();
        let nanos = tick.as_nanos();
        let low = nanos - nanos / 100 * 20;
        let high = low + nanos / 100 * 40;
        let high = high.min(u128::from(u64::MAX));
        assert!(
            got >= low.min(u128::from(u64::MAX)) && got <= high,
            "{tick:?} jittered to {got} ns, outside {low}..={high}"
        );
    }
}
