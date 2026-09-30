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
    /// Drop reads of slot 0, where a pass over the drop starts.
    drop_passes: usize,
    hello_writes: usize,
    ring_writes: usize,
    control_writes: usize,
    advert_publishes: usize,
    open_channel: usize,
    open_existing: usize,
    erases: usize,
    channel_reads: usize,
    inspect_channel: usize,
    inspect_advert: usize,
    inspect_drop: usize,
    /// Advert and channel reads.
    network_reads: usize,
    /// Advert reads.
    advert_reads: usize,
    /// Ring slot reads that found the slot empty, which is where a ring read
    /// ends: one per established conversation per collection pass.
    ring_ends: usize,
    /// How many of `network_reads` had been made at the first write since the
    /// field was last cleared.
    reads_at_first_write: Option<usize>,
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
    /// Write every advert publish to the network, then report it refused.
    refuse_after_advert_write: bool,
    /// Writes attempted since the counter was last reset.
    writes: usize,
    /// Refuse the write with this 1-based index.
    fail_write_at: Option<usize>,
    /// Refuse every channel erasure.
    fail_erase: bool,
    /// The channels this run opened, where set, as the record store holds them:
    /// a channel write or erase is refused locally unless its channel is here,
    /// a refused erase keeps the channel, and one that goes through ends it.
    owned: Option<HashSet<[u8; HELLO_LOOKUP_KEY_LEN]>>,
    /// Answer an open without create with a lookup key other than the one the
    /// owner seed derives.
    open_under_other_key: bool,
    /// Refuse every drop slot write.
    fail_drop_writes: bool,
    /// Refuse every read of slot 0 of this drop, as a pass whose scan the
    /// record store deferred does.
    fail_slot_zero_of: Option<[u8; 32]>,
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
    /// Hold every channel open that may create the record at this gate.
    gate_open_channel: Option<Arc<Gate>>,
    /// Hold the reads of one slot of one drop at this gate.
    gate_drop_slot: Option<([u8; 32], u16, Arc<Gate>)>,
    /// Hold the scans of one drop at this gate, at their read of slot 0, once
    /// this many scans of it have passed.
    gate_drop_scan: Option<([u8; 32], usize, Arc<Gate>)>,
    /// Hold every ring slot read that finds the slot empty at this gate, after
    /// the read and before it returns.
    gate_empty_ring_read: Option<Arc<Gate>>,
    /// Where set, every drop slot read and ring slot write, in order.
    trail: Option<Vec<Trail>>,
    /// Erase a channel from this node only and leave the network's copies, as
    /// a Veilid record delete does.
    erase_local_only: bool,
    /// Hold a channel read at this gate: the first read of any of these
    /// channels after this many reads of them have passed.
    gate_channel_read: Option<(Vec<[u8; HELLO_LOOKUP_KEY_LEN]>, usize, Arc<Gate>)>,
    /// Hold every ring-slot write at this gate.
    gate_ring_write: Option<Arc<Gate>>,
    /// Hold every ring-slot read of this channel at this gate, before the read.
    gate_ring_read: Option<([u8; HELLO_LOOKUP_KEY_LEN], Arc<Gate>)>,
    /// The push lane the runner takes at startup.
    push: Option<crate::dm::push::PushParts>,
    /// Send commits the live lane refuses as conflicting before it attempts one.
    forced_conflicts: Arc<std::sync::atomic::AtomicUsize>,
    /// The subkeys of every ring read of the channel `gate_ring_read` names,
    /// in order.
    gated_ring_reads: Vec<u16>,
    /// Where set, the lookup key and subkey of every channel write, in order,
    /// logged as the write is made.
    channel_writes: Option<Vec<([u8; HELLO_LOOKUP_KEY_LEN], u16)>>,
}

/// One record call, as [`Faults::trail`] logs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trail {
    /// A read of this slot of the drop the reader owns.
    OwnDrop(u16),
    /// A write to this ring slot of a channel.
    Ring(u16),
    /// A read of a channel, by the first byte of its lookup key.
    ChannelRead(u8),
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
        self.count(|calls| {
            calls
                .reads_at_first_write
                .get_or_insert(calls.network_reads);
        });
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

    /// Record a channel this run opened, where ownership is tracked.
    fn hold(&self, lookup_key: [u8; HELLO_LOOKUP_KEY_LEN]) {
        if let Some(owned) = self.faults().owned.as_mut() {
            owned.insert(lookup_key);
        }
    }

    /// Refuse locally a write or erase of a channel this run did not open,
    /// where ownership is tracked.
    fn refuse_unheld(&self, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> Result<(), RecordError> {
        match &self.faults().owned {
            Some(owned) if !owned.contains(lookup_key) => Err(RecordError::new(LocalRefusal(2))),
            _ => Ok(()),
        }
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
        self.count(|calls| {
            calls.network_reads += 1;
            calls.advert_reads += 1;
        });
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
        let slot_gate = self
            .faults()
            .gate_drop_slot
            .as_ref()
            .filter(|(name, at, _)| name == owner.as_bytes() && *at == slot)
            .map(|(_, _, gate)| Arc::clone(gate));
        if let Some(gate) = slot_gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        let scan_gate = {
            let mut faults = self.faults();
            match faults.gate_drop_scan.as_mut() {
                Some((name, skip, gate)) if name == owner.as_bytes() && slot == 0 => {
                    if *skip == 0 {
                        Some(Arc::clone(gate))
                    } else {
                        *skip -= 1;
                        None
                    }
                }
                _ => None,
            }
        };
        if let Some(gate) = scan_gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        if let Some(trail) = self.faults().trail.as_mut() {
            trail.push(Trail::OwnDrop(slot));
        }
        self.count(|calls| calls.drop_reads += 1);
        if slot == 0 && self.faults().fail_slot_zero_of == Some(*owner.as_bytes()) {
            return Err(RecordError::new(TimedOut));
        }
        if slot == 0 {
            self.count(|calls| calls.drop_passes += 1);
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
        let gate = self.faults().gate_open_channel.clone();
        if let Some(gate) = gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        self.inject(CHANNEL, Op::Open)?;
        let lookup_key = Self::lookup_key(owner);
        self.hold(lookup_key);
        Ok(lookup_key)
    }

    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.count(|calls| {
            calls.channel_reads += 1;
            calls.network_reads += 1;
        });
        let gate = {
            let mut faults = self.faults();
            match faults.gate_channel_read.as_mut() {
                Some((keys, skip, gate)) if keys.contains(lookup_key) => {
                    if *skip == 0 {
                        Some(Arc::clone(gate))
                    } else {
                        *skip -= 1;
                        None
                    }
                }
                _ => None,
            }
        };
        if let Some(gate) = gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        let gate = {
            let mut faults = self.faults();
            match faults.gate_ring_read.clone() {
                Some((key, gate)) if key == *lookup_key && subkey != channel::CONTROL_SUBKEY => {
                    faults.gated_ring_reads.push(subkey);
                    Some(gate)
                }
                _ => None,
            }
        };
        if let Some(gate) = gate {
            tokio::task::block_in_place(|| gate.hold());
        }
        if let Some(trail) = self.faults().trail.as_mut() {
            trail.push(Trail::ChannelRead(lookup_key[0]));
        }
        self.inject(CHANNEL, Op::Read)?;
        let read = self.read((CHANNEL, *lookup_key, subkey));
        if subkey != channel::CONTROL_SUBKEY && read.is_none() {
            self.count(|calls| calls.ring_ends += 1);
            let gate = self.faults().gate_empty_ring_read.clone();
            if let Some(gate) = gate {
                tokio::task::block_in_place(|| gate.hold());
            }
        }
        Ok(read)
    }

    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        if let Some(writes) = self.faults().channel_writes.as_mut() {
            writes.push((*lookup_key, subkey));
        }
        if subkey == channel::CONTROL_SUBKEY {
            let gate = self.faults().gate_control.clone();
            if let Some(gate) = gate {
                tokio::task::block_in_place(|| gate.hold());
            }
            self.count(|calls| calls.control_writes += 1);
        } else {
            let gate = self.faults().gate_ring_write.clone();
            if let Some(gate) = gate {
                tokio::task::block_in_place(|| gate.hold());
            }
            self.count(|calls| calls.ring_writes += 1);
            if let Some(trail) = self.faults().trail.as_mut() {
                trail.push(Trail::Ring(subkey));
            }
        }
        self.refuse_unheld(lookup_key)?;
        self.write((CHANNEL, *lookup_key, subkey), bytes.to_vec())
    }
}

impl RunnerRecords for Fake {
    fn take_push(&mut self) -> Option<crate::dm::push::PushParts> {
        self.faults().push.take()
    }

    fn forced_conflicts(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.faults().forced_conflicts)
    }

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
        self.write((ADVERT, *owner.as_bytes(), 0), bytes.to_vec())?;
        if self.faults().refuse_after_advert_write {
            return Err(RecordError::new(Refused));
        }
        Ok(())
    }

    fn erase_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Result<(), RecordError> {
        self.count(|calls| calls.erases += 1);
        self.refuse_unheld(lookup_key)?;
        if self.faults().fail_erase {
            return Err(RecordError::new(Refused));
        }
        self.inject(CHANNEL, Op::Erase)?;
        if !self.faults().erase_local_only {
            self.net()
                .records
                .retain(|(kind, name, _), _| !(*kind == CHANNEL && name == lookup_key));
        }
        self.node
            .lock()
            .expect("the node lock")
            .local
            .retain(|(kind, name, _), _| !(*kind == CHANNEL && name == lookup_key));
        if let Some(owned) = self.faults().owned.as_mut() {
            owned.remove(lookup_key);
        }
        Ok(())
    }

    fn open_existing_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        _subkeys: u16,
    ) -> Result<Option<[u8; HELLO_LOOKUP_KEY_LEN]>, RecordError> {
        self.count(|calls| calls.open_existing += 1);
        self.inject(CHANNEL, Op::Open)?;
        let lookup_key = Self::lookup_key(owner);
        let on_network = self
            .net()
            .records
            .keys()
            .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key);
        let on_node = self
            .node
            .lock()
            .expect("the node lock")
            .local
            .keys()
            .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key);
        if !on_network && !on_node {
            return Ok(None);
        }
        let mut lookup_key = lookup_key;
        if self.faults().open_under_other_key {
            lookup_key[0] ^= 0xff;
        }
        self.hold(lookup_key);
        Ok(Some(lookup_key))
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

    /// The lookup key of the channel this identity writes to `peer`, derived
    /// under the generation this profile's store holds for the conversation,
    /// or under generation 0 where it holds none.
    fn outgoing_lookup_key(&self, peer: &Profile) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        let generation = Store::open(self.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
            .and_then(|store| store.load())
            .ok()
            .and_then(|loaded| {
                loaded
                    .convs
                    .into_iter()
                    .find(|conv| conv.state.peer_identity_pk.as_slice() == peer.pk.as_slice())
                    .map(|conv| conv.state.generation)
            })
            .unwrap_or(flows::FIRST_GENERATION);
        let owner = channel::derive_owner_seed(&self.keys().dm_channel_root, &peer.pk, generation)
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
    let RunnerEvent::Message {
        sent_at,
        received_at,
        ..
    } = &aw.seen[reply_at]
    else {
        panic!("expected the reply, got {:?}", aw.seen[reply_at]);
    };
    // The sender's clock is sealed in whole seconds, so a time stamped by the
    // reader instead of carried from the sender is visible.
    assert_eq!(sent_at % 1000, 0, "the reply carries its sender's time");
    assert!(
        sent_at <= received_at && received_at - sent_at < 3_600_000,
        "the reply was sent at {sent_at} and collected at {received_at}"
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

/// B's runner holding A's first contact, previewed: both runners, B's fake,
/// the request's id and the index of the preview among B's events.
struct Previewed {
    a: Profile,
    b: Profile,
    b_fake: Fake,
    aw: Watch,
    bw: Watch,
    request: ContactRequestId,
    at: usize,
}

/// A writes a first contact to B, and B's runner surfaces and previews it.
async fn previewed_request() -> Previewed {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    let surfaced = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[surfaced]);
    let at = bw
        .wait_for("B's preview", |event| {
            matches!(event, RunnerEvent::RequestPreview { request: r, .. } if *r == request)
        })
        .await;
    assert!(at > surfaced, "the preview follows the request it previews");
    Previewed {
        a,
        b,
        b_fake,
        aw,
        bw,
        request,
        at,
    }
}

/// A held contact request is previewed before anything accepts it: its
/// message arrives with its sender's time, and nothing is written to the
/// network or stored for it.
#[tokio::test(start_paused = true)]
async fn a_held_request_is_previewed_before_any_accept() {
    let Previewed {
        a: _a,
        b,
        b_fake,
        aw,
        bw,
        at,
        ..
    } = previewed_request().await;
    let RunnerEvent::RequestPreview {
        messages, read_at, ..
    } = &bw.seen[at]
    else {
        panic!("expected a preview, got {:?}", bw.seen[at]);
    };
    assert_eq!(messages.len(), 1, "the one message A wrote");
    assert_eq!(messages[0].body, b"the first body");
    assert_eq!(messages[0].sent_at_ms % 1000, 0, "the sender's time");
    assert!(messages[0].sent_at_ms <= *read_at);
    let calls = b_fake.calls();
    assert_eq!(
        calls.hello_writes + calls.ring_writes + calls.control_writes,
        0,
        "B wrote for a request it has not accepted"
    );
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let store = Store::open(b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("reopen B's store");
    assert_eq!(
        store
            .records()
            .correspondences()
            .expect("list B's correspondences"),
        Vec::new(),
        "a preview stored a correspondence"
    );
}

/// An accept of a previewed request reads nothing from the network before its
/// first write, and reports the previewed message before its reply. Once the
/// preview's reads have expired, the same accept reads before it writes.
#[tokio::test(start_paused = true)]
async fn an_accept_after_a_fresh_preview_reads_nothing_before_it_writes() {
    for expired in [false, true] {
        let Previewed {
            a: _a,
            b: _b,
            b_fake,
            aw,
            mut bw,
            request,
            ..
        } = previewed_request().await;
        if expired {
            tokio::time::sleep(PREVIEW_READS_TTL + Duration::from_secs(60)).await;
        }
        b_fake.count(|calls| {
            calls.network_reads = 0;
            calls.reads_at_first_write = None;
        });
        bw.send(RunnerCommand::Accept {
            token: CommandToken(2),
            request,
            reply: b"the reply".to_vec(),
        })
        .await;
        let answered = bw.wait_for("B's acceptance", sent(2)).await;
        let peer = sent_peer(&bw.seen[answered]);
        let body = bw
            .wait_for("A's first body at B", message(peer, 0, b"the first body"))
            .await;
        assert!(body < answered, "the message precedes the reply");
        let reads = b_fake
            .calls()
            .reads_at_first_write
            .expect("the acceptance wrote");
        if expired {
            assert!(reads > 0, "an expired preview answered the accept");
        } else {
            assert_eq!(reads, 0, "reads before the acceptance's first write");
        }
        assert!(finished(&bw.stop().await));
        assert!(finished(&aw.stop().await));
    }
}

/// B's store, reopened after its runner stopped.
fn reopen_store(profile: &Profile) -> Store {
    Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("reopen the store")
}

/// A request surfaced again keeps its preview while it names the same channel,
/// and is previewed afresh, its reads dropped, when it names another.
#[tokio::test(start_paused = true)]
async fn a_request_naming_another_channel_is_previewed_afresh() {
    let Previewed {
        a: _a,
        b,
        mut b_fake,
        aw,
        bw,
        ..
    } = previewed_request().await;
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let store = reopen_store(&b);
    let advert_keys = AdvertKeys::restore(
        store
            .load()
            .expect("load B's store")
            .advert_keys
            .expect("B's advert keys"),
    );
    let keys = b.keys();
    let me = Me {
        signer: &keys.signing,
        channel_root: &keys.dm_channel_root,
    };
    let mut request = || {
        let surfaced =
            flows::collect(&store, &mut b_fake, &me, &advert_keys, |_| false).expect("B collects");
        assert_eq!(surfaced.len(), 1, "one hello in B's drop");
        match surfaced.into_iter().next() {
            Some(Surfaced::ContactRequest(request)) => request,
            other => panic!("expected a contact request, got {other:?}"),
        }
    };
    let held = |request, due| HeldRequest {
        held: Held::Request(request),
        seen: 1,
        preview_due: due,
        preview: Some((ReadCache::default(), Instant::now())),
    };
    let same = request();
    let (due, kept) = carried_preview(Some(held(request(), false)), &same);
    assert!(!due && kept.is_some(), "the same channel keeps its preview");
    let mut moved = request();
    moved.lookup_key[0] ^= 0xff;
    let (due, kept) = carried_preview(Some(held(request(), false)), &moved);
    assert!(due && kept.is_none(), "another channel is previewed afresh");
    let (due, kept) = carried_preview(None, &same);
    assert!(due && kept.is_none(), "a new request is previewed");
}

/// A preview whose advert read fails is counted, not retried, and leaves no
/// preview: the accept of that request reads the network and succeeds.
#[tokio::test(start_paused = true)]
async fn a_failed_preview_is_counted_and_the_accept_reads_the_network() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    b_fake
        .faults()
        .plan
        .push((ADVERT, Op::Read, Fault::Refused));
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    bw.wait_for(
        "the failed preview counted",
        |event| matches!(event, RunnerEvent::Health(h) if h.previews_failed == 1),
    )
    .await;
    let adverts = b_fake.calls().advert_reads;
    let scans = b_fake.calls().drop_passes;
    tokio::time::sleep(DEFAULT_TICK * DROP_SCAN_TICKS * 3).await;
    bw.drain();
    assert!(
        b_fake.calls().drop_passes >= scans + 2,
        "control: B kept scanning"
    );
    assert_eq!(
        b_fake.calls().advert_reads,
        adverts,
        "the failed preview was tried again"
    );
    assert!(
        !bw.seen
            .iter()
            .any(|event| matches!(event, RunnerEvent::RequestPreview { .. })),
        "a failed preview was reported"
    );
    b_fake.count(|calls| {
        calls.network_reads = 0;
        calls.reads_at_first_write = None;
    });
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let answered = bw.wait_for("B's acceptance", sent(2)).await;
    let peer = sent_peer(&bw.seen[answered]);
    bw.wait_for("A's first body at B", message(peer, 0, b"the first body"))
        .await;
    let reads = b_fake
        .calls()
        .reads_at_first_write
        .expect("the acceptance wrote");
    assert!(reads > 0, "the accept read nothing before it wrote");
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
}

/// Two identities' requests held at once are each previewed under their own
/// id, with their own message.
#[tokio::test(start_paused = true)]
async fn two_requests_are_previewed_each_under_its_own_id() {
    let dht = network();
    let (a, b, c) = (Profile::new(), Profile::new(), Profile::new());
    let (a_fake, b_fake, c_fake) = (Fake::on(&dht), Fake::on(&dht), Fake::on(&dht));
    let mut bw = b.spawn(&b_fake, RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let mut senders = Vec::new();
    for (profile, fake, body) in [(&a, &a_fake, &b"from a"[..]), (&c, &c_fake, &b"from c"[..])] {
        let mut w = profile.spawn(fake, RunnerConfig::default());
        w.wait_for("the sender's startup", is_health).await;
        w.send(RunnerCommand::FirstContact {
            token: CommandToken(1),
            peer_identity_pk: b.pk.clone(),
            body: body.to_vec(),
        })
        .await;
        w.wait_for("the first contact", sent(1)).await;
        senders.push(w);
    }
    let mut expected = Vec::new();
    for (profile, body) in [(&a, &b"from a"[..]), (&c, &b"from c"[..])] {
        let at = bw
            .wait_for("the contact request", request_from(&profile.pk))
            .await;
        expected.push((request_id(&bw.seen[at]), body.to_vec()));
    }
    assert_ne!(expected[0].0, expected[1].0, "two ids");
    for (request, body) in &expected {
        let at = bw
            .wait_for("the preview", |event| {
                matches!(event, RunnerEvent::RequestPreview { request: r, .. } if r == request)
            })
            .await;
        let RunnerEvent::RequestPreview { messages, .. } = &bw.seen[at] else {
            unreachable!("matched above");
        };
        let bodies: Vec<&[u8]> = messages.iter().map(|m| m.body.as_slice()).collect();
        assert_eq!(bodies, [body.as_slice()], "request {request:?}");
    }
    assert!(finished(&bw.stop().await));
    for w in senders {
        assert!(finished(&w.stop().await));
    }
}

/// A message that lands in the requester's ring after B's preview reaches
/// B's thread after the first, at the collection that follows the accept.
#[tokio::test(start_paused = true)]
async fn a_message_after_the_preview_reaches_the_thread_after_the_first() {
    let Previewed {
        a,
        b: _b,
        b_fake,
        aw,
        mut bw,
        request,
        ..
    } = previewed_request().await;
    assert!(finished(&aw.stop().await));
    // A first contact awaiting acceptance sends nothing further, so the second
    // message is sealed on A's own key schedule and placed in its ring.
    let store = reopen_store(&a);
    let conv = store.load().expect("load A's store").convs.remove(0);
    let mut writer = daemonseed_core::dm::chain::Conversation::restore(conv.state.conversation);
    let plaintext = channel::encode_message_plaintext(1_000, b"the second body");
    let (header, sealed) = writer
        .seal(&plaintext, channel::DEVICE_ID_SINGLE_DEVICE, os_fill)
        .expect("seal the second message");
    let mut slot = header.encode();
    slot.extend_from_slice(&sealed);
    b_fake.net().put(
        (
            CHANNEL,
            conv.state.outgoing_lookup_key,
            channel::slot_for(1),
        ),
        slot,
    );
    drop(store);

    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let answered = bw.wait_for("B's acceptance", sent(2)).await;
    let peer = sent_peer(&bw.seen[answered]);
    let first = bw
        .wait_for("A's first body at B", message(peer, 0, b"the first body"))
        .await;
    let second = bw
        .wait_for("A's second body at B", message(peer, 1, b"the second body"))
        .await;
    assert!(
        first < answered && answered < second,
        "first, reply, second"
    );
    assert!(finished(&bw.stop().await));
}

/// A pass reads the established conversations before it scans the drop: with
/// the scan due on every pass, because a first contact awaits acceptance, and
/// the scan held at its first read, a message already written to an
/// established conversation is reported while the scan is still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_collects_its_conversations_before_a_slow_drop_scan() {
    let config = RunnerConfig {
        tick: Duration::from_millis(200),
        grace: Duration::from_secs(5),
    };
    let Scene {
        dht,
        a,
        b: _b,
        a_fake,
        aw,
        mut bw,
        a_peer,
        b_peer,
        ..
    } = establish(config).await;
    let c = Profile::new();
    let mut cw = c.spawn(&Fake::on(&dht), config);
    cw.wait_for("C's startup", is_health).await;
    assert!(finished(&cw.stop().await), "C is away from here on");
    let mut aw = aw;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(50),
        peer_identity_pk: c.pk.clone(),
        body: b"to C".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact to C", sent(50)).await;
    assert!(finished(&aw.stop().await));

    bw.send(RunnerCommand::Send {
        token: CommandToken(51),
        peer: b_peer,
        body: b"while A was away".to_vec(),
    })
    .await;
    bw.wait_for("B's send", sent(51)).await;

    // The relaunch scans once at startup; every scan after that is held.
    let a_fake = a_fake.restart();
    let held = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&held));
    a_fake.faults().gate_drop_scan = Some((a.drop_name(), 1, Arc::clone(&held)));
    let mut aw = a.spawn(&a_fake, config);
    aw.wait_for("A's startup", is_health).await;
    aw.wait_for("B's message at A", message(a_peer, 1, b"while A was away"))
        .await;
    held.reached().await;
    assert!(
        a_fake.faults().gate_drop_scan.is_some(),
        "the scan is held after the message was reported"
    );
    held.release();
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// With nothing awaiting acceptance, the drop is scanned on its own interval,
/// [`DROP_SCAN_TICKS`] collection intervals, while every interval collects the
/// established conversations.
#[tokio::test(start_paused = true)]
async fn the_drop_is_scanned_less_often_than_conversations_are_collected() {
    let Scene {
        a: _a,
        b: _b,
        a_fake,
        aw,
        mut bw,
        b_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    bw.wait_for("delivery of B's reply", delivered(b_peer, 0))
        .await;
    tokio::time::sleep(WAITING_WINDOW).await;
    let (collections, scans) = collections_in(&a_fake, DEFAULT_TICK * 20).await;
    assert!(
        (17..=25).contains(&collections),
        "twenty ticks are seventeen to twenty-five collections, took {collections}"
    );
    assert!(
        (2..=6).contains(&scans),
        "twenty ticks are two to six drop scans, took {scans}"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A message is reported as soon as its slot has opened, while the read of the
/// empty slot after it is still held, and only once it is recorded: a relaunch
/// after a stop inside that read neither reports it again nor loses the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_is_reported_before_the_ring_read_ends_and_once_across_a_restart() {
    let config = RunnerConfig {
        tick: Duration::from_millis(50),
        grace: Duration::from_millis(300),
    };
    let Scene {
        a,
        b: _b,
        a_fake,
        aw,
        mut bw,
        a_peer,
        b_peer,
        ..
    } = establish(config).await;
    assert!(finished(&aw.stop().await));
    bw.send(RunnerCommand::Send {
        token: CommandToken(60),
        peer: b_peer,
        body: b"first".to_vec(),
    })
    .await;
    bw.wait_for("B's first send", sent(60)).await;

    let a_fake = a_fake.restart();
    let held = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&held));
    a_fake.faults().gate_empty_ring_read = Some(Arc::clone(&held));
    let mut aw = a.spawn(&a_fake, config);
    aw.wait_for("the first message at A", message(a_peer, 1, b"first"))
        .await;
    held.reached().await;
    assert!(
        !held.state.lock().expect("the gate lock").1,
        "the message was reported while the read after it was held"
    );

    let Watch { handle, .. } = aw;
    let stop = tokio::time::timeout(Duration::from_secs(30), handle.shutdown())
        .await
        .expect("shutdown returned while the read was held");
    let end = match stop.outcome {
        ShutdownOutcome::TimedOut(end) => end,
        other => panic!("expected TimedOut, got {other:?}"),
    };
    a_fake.faults().gate_empty_ring_read = None;
    held.release();
    let late = tokio::time::timeout(Duration::from_secs(30), end.finish())
        .await
        .expect("the task ended once its read returned");
    assert!(
        messages_from(&late.undelivered, a_peer).is_empty(),
        "a message came back twice: {:?}",
        late.undelivered
    );

    bw.send(RunnerCommand::Send {
        token: CommandToken(61),
        peer: b_peer,
        body: b"second".to_vec(),
    })
    .await;
    bw.wait_for("B's second send", sent(61)).await;
    let a_fake = a_fake.restart();
    let mut aw = a.spawn(&a_fake, config);
    aw.wait_for("the second message at A", message(a_peer, 2, b"second"))
        .await;
    bw.wait_for("delivery of both at B", delivered(b_peer, 2))
        .await;
    // Past the delivery report: every collection that could report again has
    // run.
    tokio::time::sleep(Duration::from_millis(500)).await;
    aw.drain();
    assert_eq!(
        messages_from(&aw.seen, a_peer),
        vec![2],
        "the relaunch reported a recorded message again, or lost one"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// The pass whose scan surfaces a request previews it before the pass ends,
/// without the schedule's next wake.
#[tokio::test(start_paused = true)]
async fn the_pass_whose_scan_surfaces_a_request_previews_it() {
    let Scene {
        dht,
        a,
        b: _b,
        a_fake,
        aw,
        bw,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&aw.stop().await));
    let keys = a.keys();
    let (_command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
    let commands: CommandQueue = Arc::new(tokio::sync::Mutex::new(command_rx));
    let (event_tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let started = Runner::start(
        RunnerParts {
            records: a_fake.restart(),
            signer: Arc::new(keys.signing),
            channel_root: keys.dm_channel_root,
            at_rest_key: Zeroizing::new([0x42; AEAD_KEY_LEN]),
            profile_root: a.root.path().to_path_buf(),
            config: RunnerConfig::default(),
        },
        commands,
        event_tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let Ok(mut runner) = started else {
        panic!("A's runner did not start");
    };

    let c = Profile::new();
    let mut cw = c.spawn(&Fake::on(&dht), RunnerConfig::default());
    cw.wait_for("C's startup", is_health).await;
    cw.send(RunnerCommand::FirstContact {
        token: CommandToken(80),
        peer_identity_pk: a.pk.clone(),
        body: b"from C".to_vec(),
    })
    .await;
    cw.wait_for("C's first contact", sent(80)).await;
    assert!(finished(&cw.stop().await));

    runner.next_drop_scan = Instant::now();
    assert!(runner.collect_tick().await.is_ok(), "the pass ran");
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        seen.push(event);
    }
    let surfaced = seen
        .iter()
        .position(request_from(&c.pk))
        .expect("the pass surfaced C's request");
    assert!(
        seen[surfaced..]
            .iter()
            .any(|event| matches!(event, RunnerEvent::RequestPreview { .. })),
        "the pass ended without previewing the request: {seen:?}"
    );
    drop(runner);
    assert!(finished(&bw.stop().await));
}

/// A request is previewed directly after the scan that surfaced it, before the
/// next read of an established conversation.
#[tokio::test(start_paused = true)]
async fn a_request_is_previewed_before_the_next_conversation_read() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        mut aw,
        bw,
        ..
    } = establish(RunnerConfig::default()).await;
    let c = Profile::new();
    let mut cw = c.spawn(&Fake::on(&dht), RunnerConfig::default());
    cw.wait_for("C's startup", is_health).await;
    cw.send(RunnerCommand::FirstContact {
        token: CommandToken(70),
        peer_identity_pk: a.pk.clone(),
        body: b"from C".to_vec(),
    })
    .await;
    cw.wait_for("C's first contact", sent(70)).await;
    assert!(finished(&cw.stop().await));
    // C's channel is derived under the generation its first contact drew.
    let (from_b, from_c) = (b.outgoing_lookup_key(&a), c.outgoing_lookup_key(&a));
    assert_ne!(from_b[0], from_c[0], "the trail tells the channels apart");
    let hello = dht
        .lock()
        .expect("the network lock")
        .records
        .iter()
        .find(|((kind, name, _), (bytes, _))| {
            *kind == DROP && *name == a.drop_name() && !bytes.is_empty()
        })
        .map(|((_, _, slot), _)| *slot)
        .expect("C's hello is in A's drop");
    a_fake.faults().trail = Some(Vec::new());
    aw.wait_for("C's request at A", request_from(&c.pk)).await;
    aw.wait_for("the preview of C's request", |event| {
        matches!(event, RunnerEvent::RequestPreview { .. })
    })
    .await;
    let trail = a_fake.faults().trail.take().expect("the trail");
    let surfaced = trail
        .iter()
        .position(|step| *step == Trail::OwnDrop(hello))
        .expect("the scan read C's hello");
    // The scan itself reads the channel C's hello names, to verify it, so the
    // read that counts is the first one after the scan's last slot.
    let last_slot = Trail::OwnDrop(drop_plane::DROP_SUBKEYS - 1);
    let ended = surfaced
        + trail[surfaced..]
            .iter()
            .position(|step| *step == last_slot)
            .expect("the scan that read C's hello ended");
    let next = trail[ended..]
        .iter()
        .find(|step| matches!(step, Trail::ChannelRead(_)))
        .expect("a channel read after the scan");
    assert_eq!(
        *next,
        Trail::ChannelRead(from_c[0]),
        "a conversation was read between the scan and the preview: {trail:?}"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// Passes over the drop `fake` takes in `wait` from now.
async fn passes_in(fake: &Fake, wait: Duration) -> usize {
    let before = fake.calls().drop_passes;
    tokio::time::sleep(wait).await;
    fake.calls().drop_passes - before
}

/// Collection passes over one established conversation `fake` takes in `wait`
/// from now, counted by the empty slot each ring read ends at, and passes over
/// the drop in the same time.
async fn collections_in(fake: &Fake, wait: Duration) -> (usize, usize) {
    let before = fake.calls();
    tokio::time::sleep(wait).await;
    let after = fake.calls();
    (
        after.ring_ends - before.ring_ends,
        after.drop_passes - before.drop_passes,
    )
}

/// A first contact awaiting acceptance is collected on the waiting interval,
/// for the waiting window, and on the ordinary tick after it; a conversation
/// waiting on nobody is collected on the ordinary tick.
#[tokio::test(start_paused = true)]
async fn collection_runs_sooner_while_a_first_contact_awaits_acceptance() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    assert!(finished(&bw.stop().await), "B is away from here on");

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

    let waiting = passes_in(&a_fake, DEFAULT_TICK).await;
    assert!(
        waiting >= 4,
        "a minute of waiting on acceptance is at least four passes, took {waiting}"
    );
    tokio::time::sleep(WAITING_WINDOW).await;
    let after = passes_in(&a_fake, DEFAULT_TICK * 3).await;
    assert!(
        (2..=4).contains(&after),
        "past the window three ticks are two to four passes, took {after}"
    );
    assert!(finished(&aw.stop().await));
}

/// Once both sides have seen the other's first message, neither waits on the
/// other, and collection is back on the ordinary tick inside the window.
#[tokio::test(start_paused = true)]
async fn collection_returns_to_the_tick_once_nothing_waits() {
    let started = tokio::time::Instant::now();
    let Scene {
        a: _a,
        b: _b,
        a_fake,
        aw,
        mut bw,
        b_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    bw.wait_for("delivery of B's reply", delivered(b_peer, 0))
        .await;
    let (settled, _) = collections_in(&a_fake, DEFAULT_TICK * 3).await;
    assert!(
        (2..=4).contains(&settled),
        "three ticks with nothing waiting are two to four passes, took {settled}"
    );
    assert!(
        started.elapsed() < WAITING_WINDOW,
        "measured inside the window, where waiting would still have been fast"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// An acceptor whose hello back the correspondent has not yet shown it read
/// collects on the waiting interval, and accepting restarts the window: here
/// the accept comes after the window that started with the runner has closed.
#[tokio::test(start_paused = true)]
async fn collection_runs_sooner_after_an_accept_until_the_hello_back_is_read() {
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
    assert!(finished(&aw.stop().await), "A is away from here on");

    bw.wait_for("B's contact request", request_from(&a.pk))
        .await;
    tokio::time::sleep(WAITING_WINDOW).await;
    bw.drain();
    let at = bw
        .seen
        .iter()
        .rposition(request_from(&a.pk))
        .expect("the request is held");
    let request = request_id(&bw.seen[at]);
    let idle = passes_in(&b_fake, DEFAULT_TICK).await;
    assert!(
        idle <= 1,
        "before the accept B scans on the drop's own interval, took {idle}"
    );
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("B's acceptance", sent(2)).await;
    let (waiting, _) = collections_in(&b_fake, DEFAULT_TICK).await;
    assert!(
        waiting >= 4,
        "a minute waiting on the hello back is at least four passes, took {waiting}"
    );
    assert!(finished(&bw.stop().await));
}

/// A first contact whose acceptance may sit in a slot the last scan could not
/// read is not rewritten; once a scan reads every slot, it is.
#[tokio::test(start_paused = true)]
async fn a_hello_is_not_rewritten_after_a_partial_scan() {
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
    {
        let mut net = dht.lock().expect("the network lock");
        let hello = *net
            .records
            .keys()
            .find(|(kind, name, _)| *kind == DROP && *name == drop_name)
            .expect("A's hello is in B's drop");
        net.evict(hello);
    }
    let deferred = a_fake.restart();
    deferred.faults().fail_slot_zero_of = Some(a.drop_name());
    let mut aw = a.spawn(&deferred, RunnerConfig::default());
    aw.wait_for("A's restart over a deferred scan", is_health)
        .await;
    assert_eq!(
        deferred.calls().hello_writes,
        0,
        "a lost hello is not rewritten after a partial scan"
    );
    assert!(finished(&aw.stop().await));

    let read = a_fake.restart();
    let mut aw = a.spawn(&read, RunnerConfig::default());
    aw.wait_for("A's restart over a full scan", is_health).await;
    assert_eq!(
        read.calls().hello_writes,
        1,
        "the control: a full scan lets the lost hello be rewritten"
    );
    assert!(finished(&aw.stop().await));
}

/// A batched write that fails is counted as the single write it is: the erase
/// of an accept as a drop write, a first contact's opening as a channel write.
#[tokio::test(start_paused = true)]
async fn a_failed_batched_write_is_counted_as_its_own_kind() {
    let dht = network();
    let (a, b, c) = (Profile::new(), Profile::new(), Profile::new());
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
    assert!(finished(&aw.stop().await));

    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    b_fake.faults().plan.push((DROP, Op::Write, Fault::Refused));
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let at = bw.wait_for("B's refused accept", refused(2)).await;
    let at = bw.wait_from(at, "B's health", is_health).await;
    let counted = health(&bw.seen[at]);
    assert_eq!(counted.drop_write_failures, 1, "the erase is a drop write");
    assert_eq!(counted.channel_write_failures, 0);
    assert!(finished(&bw.stop().await));

    let c_fake = Fake::on(&dht);
    let mut cw = c.spawn(&c_fake, RunnerConfig::default());
    cw.wait_for("C's startup", is_health).await;
    c_fake
        .faults()
        .plan
        .push((CHANNEL, Op::Write, Fault::Refused));
    cw.send(RunnerCommand::FirstContact {
        token: CommandToken(3),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    let at = cw.wait_for("C's refused first contact", refused(3)).await;
    let at = cw.wait_from(at, "C's health", is_health).await;
    let counted = health(&cw.seen[at]);
    assert_eq!(
        counted.channel_write_failures, 1,
        "the opening is a channel write"
    );
    assert_eq!(counted.drop_write_failures, 0);
    assert!(finished(&cw.stop().await));
}

/// What a trace must never format: a message body or the bytes of a record,
/// a key or seed, an identity public key, or a conversation's label other
/// than through [`tag`]. A count of any of them, `x.len()`, is allowed.
const UNTRACEABLE: &[&str] = &[
    "body",
    "bodies",
    "bytes",
    "reply",
    "slot_bytes",
    "control",
    "sealed",
    "written",
    "lookup_key",
    "outgoing_lookup_key",
    "owner",
    "owner_seed",
    "identity",
    "peer_identity_pk",
    "pk",
    "secret",
    "signer",
    "keypair",
    "seed",
    "peer",
    "label",
];

/// Every `vtrace!` call in `source` that names something in [`UNTRACEABLE`],
/// as `(line, name)`: in its format string's inline arguments or in its
/// argument list, a `tag(..)` call and anything followed by `.len()` aside.
fn untraceable_in(source: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let bytes = source.as_bytes();
    for (start, _) in source.match_indices("vtrace!(") {
        let open = start + "vtrace!(".len();
        let (mut depth, mut at, mut in_str) = (1usize, open, false);
        let mut outside = String::new();
        let mut inside = String::new();
        while depth > 0 {
            let c = bytes[at] as char;
            if in_str {
                if c == '\\' {
                    at += 1;
                } else if c == '"' {
                    in_str = false;
                    outside.push(' ');
                } else {
                    inside.push(c);
                }
            } else if c == '"' {
                in_str = true;
            } else {
                depth = match c {
                    '(' => depth + 1,
                    ')' => depth - 1,
                    _ => depth,
                };
                outside.push(c);
            }
            at += 1;
        }
        // Strip every `tag(..)` call, which renders only a short form.
        while let Some(t) = outside.find("tag(") {
            let end = outside[t..].find(')').map_or(outside.len(), |e| t + e + 1);
            outside.replace_range(t..end, " ");
        }
        let captures = inside
            .split('{')
            .skip(1)
            .map(|rest| rest.split(['}', ':']).next().unwrap_or(""));
        let named: Vec<String> = captures
            .map(str::to_owned)
            .chain(names_outside(&outside))
            .collect();
        let line = source[..start].matches('\n').count() + 1;
        for name in named {
            if name.split('.').any(|part| UNTRACEABLE.contains(&part)) {
                found.push((line, name));
            }
        }
    }
    found
}

/// The identifiers in an argument list, a name followed by `.len()` aside.
fn names_outside(args: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = args;
    while let Some(i) = rest.find(|c: char| c.is_ascii_alphabetic() || c == '_') {
        let tail = &rest[i..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        if !tail[end..].starts_with(".len()") {
            names.push(tail[..end].to_owned());
        }
        rest = &tail[end..];
    }
    names
}

/// No trace in the runner or the record store formats a body, a key, an
/// identity public key or a full label, and a conversation's tag is two bytes.
#[test]
fn no_trace_formats_a_body_a_key_or_a_label() {
    assert_eq!(
        untraceable_in("crate::vtrace!(\"x {body:?} {}\", tag(&peer)); crate::vtrace!(\"y {}\", lookup_key); crate::vtrace!(\"z {}\", bodies.len());"),
        vec![(1, "body".to_owned()), (1, "lookup_key".to_owned())],
        "the probe finds what it must, and passes a tag and a count"
    );
    for (file, source) in [
        ("runner.rs", include_str!("../runner.rs")),
        ("records.rs", include_str!("../records.rs")),
    ] {
        assert!(
            source.matches("vtrace!(").count() >= 5,
            "{file} is read and holds its traces"
        );
        assert_eq!(untraceable_in(source), Vec::new(), "{file}");
    }
    let label = CorrespondenceLabel::mint().expect("a label");
    let short = tag(&label);
    assert_eq!(short.len(), 4, "two bytes, in hex");
    let [x, y, ..] = *label.as_bytes();
    assert_eq!(short, format!("{x:02x}{y:02x}"));
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

    aw.send(RunnerCommand::Send {
        token: CommandToken(12),
        peer: a_peer,
        body: vec![0x61; channel::MESSAGE_BODY_MAX_LEN + 1],
    })
    .await;
    let at = aw.wait_for("the too-long refusal", refused(12)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::TooLong);

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
    // A send is refused as it is served, and reported sent once the runner has
    // written its slot, so the last send's report may follow the refusal.
    aw.wait_for("the last send that fits", sent(162)).await;
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

/// The sender's time of a received message event.
fn sent_at_of(event: &RunnerEvent) -> u64 {
    match event {
        RunnerEvent::Message { sent_at, .. } => *sent_at,
        other => panic!("expected Message, got {other:?}"),
    }
}

/// A message written at a time no runner's clock reads reaches B with that
/// time through B's acceptance and through B's collection batch, including a
/// stamp ahead of B's clock. A writes through the flows directly, so its
/// stamps are chosen rather than read from a clock. An acceptance whose reply
/// is too long is refused and leaves the request held for another answer.
#[tokio::test(start_paused = true)]
async fn a_senders_stamp_reaches_b_through_its_acceptance_and_its_batch() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;

    // Half an hour before the clock B reads, inside the hour before B's
    // advert comes into force; and a day after it, so a runner that held a
    // stamp at its own clock would not report it.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let (t_first, t_later) = (now - 1_800, now + 86_400);
    let keys = a.keys();
    let me = Me {
        signer: &keys.signing,
        channel_root: &keys.dm_channel_root,
    };
    let store =
        Store::open(a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).expect("A's store opens");
    let mut records = a_fake.restart();
    flows::first_contact(&store, &mut records, &me, &b.pk, b"early", os_fill, t_first)
        .expect("A's first contact");

    let at = bw
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(3),
        request,
        reply: vec![0x61; channel::MESSAGE_BODY_MAX_LEN + 1],
    })
    .await;
    let at = bw
        .wait_for("the too-long reply's refusal", refused(3))
        .await;
    assert_eq!(refusal(&bw.seen[at]), Refusal::TooLong);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("the acceptance of the same request", sent(2))
        .await;
    let at = bw
        .wait_for("A's first message through B's acceptance", |event| {
            matches!(event, RunnerEvent::Message { seq: 0, body, .. } if body.as_slice() == b"early")
        })
        .await;
    assert_eq!(sent_at_of(&bw.seen[at]), t_first * 1000);

    let advert_keys = AdvertKeys::restore(
        store
            .load_advert_keys()
            .expect("A's advert keys read")
            .expect("A's advert keys exist"),
    );
    let surfaced =
        flows::collect(&store, &mut records, &me, &advert_keys, |_| false).expect("A collects");
    let peer_a = match surfaced.as_slice() {
        [Surfaced::Accepted(acceptance)] => acceptance.peer,
        other => panic!("expected the acceptance, got {other:?}"),
    };
    flows::send_message(&store, &mut records, &peer_a, b"later", os_fill, t_later)
        .expect("A sends");
    let at = bw
        .wait_for("A's later message through B's batch", |event| {
            matches!(event, RunnerEvent::Message { seq: 1, body, .. } if body.as_slice() == b"later")
        })
        .await;
    assert_eq!(sent_at_of(&bw.seen[at]), t_later * 1000);
    assert!(finished(&bw.stop().await));
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

fn is_block_list(event: &RunnerEvent) -> bool {
    matches!(event, RunnerEvent::BlockList(_))
}

fn block_list(event: &RunnerEvent) -> Vec<IdentityPk> {
    match event {
        RunnerEvent::BlockList(identities) => identities.clone(),
        other => panic!("expected BlockList, got {other:?}"),
    }
}

/// The runner reports the whole block list: the stored list once at startup,
/// straight after the first roster, and the list as it then stands after each
/// block and unblock, exactly; a relaunch reports what the store kept.
#[tokio::test(start_paused = true)]
async fn the_block_list_is_reported_at_startup_and_after_each_change() {
    let dht = network();
    let (a, b, c) = (Profile::new(), Profile::new(), Profile::new());
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    let at = aw.wait_for("the startup block list", is_block_list).await;
    assert_eq!(at, 1, "straight after the first roster: {:?}", aw.seen);
    assert!(is_roster(&aw.seen[0]), "the roster comes first");
    assert_eq!(block_list(&aw.seen[at]), Vec::<IdentityPk>::new());

    aw.send(RunnerCommand::Block { peer: b.pk.clone() }).await;
    let at = aw
        .wait_from(at + 1, "the list after blocking B", is_block_list)
        .await;
    assert_eq!(block_list(&aw.seen[at]), vec![b.pk.clone()]);

    aw.send(RunnerCommand::Block { peer: c.pk.clone() }).await;
    let at = aw
        .wait_from(at + 1, "the list after blocking C", is_block_list)
        .await;
    let mut both = vec![b.pk.clone(), c.pk.clone()];
    both.sort();
    assert_eq!(block_list(&aw.seen[at]), both, "both, in ascending order");

    aw.send(RunnerCommand::Unblock { peer: b.pk.clone() }).await;
    let at = aw
        .wait_from(at + 1, "the list after unblocking B", is_block_list)
        .await;
    assert_eq!(block_list(&aw.seen[at]), vec![c.pk.clone()]);
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    assert!(
        !aw.seen[at + 1..].iter().any(is_block_list),
        "no further block list before the stop: {:?}",
        &aw.seen[at + 1..]
    );
    assert!(finished(&aw.stop().await));

    let mut aw = a.spawn(&a_fake.restart(), RunnerConfig::default());
    let at = aw
        .wait_for("the relaunch's block list", is_block_list)
        .await;
    assert_eq!(
        block_list(&aw.seen[at]),
        vec![c.pk.clone()],
        "the relaunch reports the list the store kept"
    );
    assert!(finished(&aw.stop().await));
}

/// A block the full list refuses is answered by a refusal and by no block list,
/// before it or after it, so a front end never shows that identity as blocked.
#[tokio::test(start_paused = true)]
async fn a_block_the_full_list_refuses_reports_no_block_list() {
    use daemonseed_core::dm::block_list::BLOCK_LIST_MAX_ENTRIES;
    let dht = network();
    let a = Profile::new();
    let mut aw = a.spawn(&Fake::on(&dht), RunnerConfig::default());
    let mut at = aw.wait_for("the startup block list", is_block_list).await;
    let identity = |n: u16| -> IdentityPk {
        let mut key = Box::new([0u8; IDENTITY_PK_LEN]);
        key[..2].copy_from_slice(&n.to_be_bytes());
        key
    };
    let ceiling = u16::try_from(BLOCK_LIST_MAX_ENTRIES).expect("the ceiling fits a u16");
    for n in 0..ceiling {
        aw.send(RunnerCommand::Block { peer: identity(n) }).await;
        at = aw
            .wait_from(at + 1, "the list after a block", is_block_list)
            .await;
    }
    assert_eq!(
        block_list(&aw.seen[at]).len(),
        BLOCK_LIST_MAX_ENTRIES,
        "the list is full"
    );

    aw.send(RunnerCommand::Block {
        peer: identity(ceiling),
    })
    .await;
    let refused_at = aw
        .wait_from(at + 1, "the refusal of a block past the ceiling", |event| {
            matches!(
                event,
                RunnerEvent::Refused {
                    token: None,
                    reason: Refusal::BlockListFull
                }
            )
        })
        .await;
    assert!(
        !aw.seen[at + 1..refused_at].iter().any(is_block_list),
        "no block list before the refusal: {:?}",
        &aw.seen[at + 1..refused_at]
    );
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    assert!(
        !aw.seen[refused_at + 1..].iter().any(is_block_list),
        "and none after it: {:?}",
        &aw.seen[refused_at + 1..]
    );
    assert!(finished(&aw.stop().await));
}

/// Where `profile`'s block list record lives.
fn block_list_record(profile: &Profile) -> std::path::PathBuf {
    profile.root.path().join(STORE_DIR).join("block-list.bin")
}

/// Overwrite `profile`'s block list record with bytes that are not a sealed
/// record.
fn overwrite_block_list_record(profile: &Profile) {
    let path = block_list_record(profile);
    assert!(
        path.exists(),
        "the block list record is where it is looked for"
    );
    std::fs::write(&path, b"not a sealed block list").expect("the record is overwritten");
}

/// Seal a payload that is not a whole number of keys into `profile`'s block
/// list record.
fn write_undecodable_block_list(profile: &Profile) {
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    store
        .records()
        .profile_critical_section(|guard| -> Result<(), DmStoreError> {
            guard.replace(RecordKind::BlockList, &[1, 2, 3])?;
            Ok(())
        })
        .expect("a payload that is not whole keys is written");
}

/// Delete `profile`'s block list record.
fn remove_block_list_record(profile: &Profile) {
    std::fs::remove_file(block_list_record(profile)).expect("the block list record is removed");
}

/// Store a block list holding only `identity` in `profile`'s record.
fn write_block_list(profile: &Profile, identity: &IdentityPk) {
    let mut list = BlockList::new();
    list.block(identity);
    let encoded = list.encode().expect("one identity encodes");
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    store
        .records()
        .profile_critical_section(|guard| -> Result<(), DmStoreError> {
            guard.replace(RecordKind::BlockList, &encoded)?;
            Ok(())
        })
        .expect("the block list is written");
}

/// A block list whose record will not read at startup is reported unreadable.
#[tokio::test(start_paused = true)]
async fn an_unreadable_block_list_record_at_startup_is_reported_and_counted_once_by_startup() {
    block_list_reported_unreadable_at_startup(overwrite_block_list_record).await;
}

/// A block list whose sealed record holds a payload that does not decode is
/// reported unreadable in the same way.
#[tokio::test(start_paused = true)]
async fn an_undecodable_block_list_at_startup_is_reported_and_counted_once_by_startup() {
    block_list_reported_unreadable_at_startup(write_undecodable_block_list).await;
}

/// A profile whose block list `corrupt` breaks between runs relaunches
/// reporting it unreadable straight after the first roster, in place of any
/// block list; startup counts the failed read once, its own drop scan adding
/// nothing; and no drop is scanned while the list stays unknown.
async fn block_list_reported_unreadable_at_startup(corrupt: fn(&Profile)) {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));
    corrupt(&a);

    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    assert!(is_roster(&aw.seen[0]), "the roster comes first");
    assert!(
        matches!(aw.seen[1], RunnerEvent::BlockListUnreadable),
        "the unreadable list is reported in place of a block list: {:?}",
        aw.seen
    );
    assert!(
        !aw.seen[..at].iter().any(is_block_list),
        "no block list is reported: {:?}",
        aw.seen
    );
    assert_eq!(
        health(&aw.seen[at]).store_failures,
        1,
        "startup counts the failed read once"
    );
    assert_eq!(
        relaunched.calls().drop_reads,
        0,
        "no drop is scanned while the block list is unknown"
    );
    assert!(finished(&aw.stop().await));
}

fn is_block_list_unreadable(event: &RunnerEvent) -> bool {
    matches!(event, RunnerEvent::BlockListUnreadable)
}

/// A block list record deleted while the runner runs is not recreated: the
/// list is reported unreadable, never empty, and B stays blocked.
#[tokio::test(start_paused = true)]
async fn a_block_list_record_deleted_mid_run_is_reported_unreadable_and_not_recreated() {
    let a = block_list_lost_mid_run(remove_block_list_record).await;
    assert!(
        !block_list_record(&a).exists(),
        "the record is not recreated"
    );
}

/// A block list record overwritten while the runner runs is reported
/// unreadable in the same way.
#[tokio::test(start_paused = true)]
async fn a_block_list_record_overwritten_mid_run_is_reported_unreadable() {
    block_list_lost_mid_run(overwrite_block_list_record).await;
}

/// A block list whose sealed record stops decoding while the runner runs is
/// reported unreadable in the same way.
#[tokio::test(start_paused = true)]
async fn a_block_list_that_stops_decoding_mid_run_is_reported_unreadable() {
    block_list_lost_mid_run(write_undecodable_block_list).await;
}

/// A runner that has blocked B and then has its block list broken by
/// `break_list` reports the list unreadable exactly once and never as a list,
/// counts the failure, reads no drop slot from then on, and surfaces no request
/// for a hello B writes to its drop afterwards. Returns A's profile.
async fn block_list_lost_mid_run(break_list: fn(&Profile)) -> Profile {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    let at = aw.wait_for("the startup block list", is_block_list).await;
    aw.send(RunnerCommand::Block { peer: b.pk.clone() }).await;
    let blocked_at = aw
        .wait_from(at + 1, "the list after blocking B", is_block_list)
        .await;
    assert_eq!(block_list(&aw.seen[blocked_at]), vec![b.pk.clone()]);

    break_list(&a);
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    let lost = &aw.seen[blocked_at + 1..];
    assert!(
        lost.iter().any(is_block_list_unreadable),
        "the unreadable list is reported within three ticks: {lost:?}"
    );
    assert!(
        lost.iter()
            .any(|event| matches!(event, RunnerEvent::Health(h) if h.store_failures >= 1)),
        "the failed read is counted: {lost:?}"
    );
    let reads = a_fake.calls().drop_reads;

    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    bw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: a.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    bw.wait_for("B's hello to A", sent(1)).await;
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();

    let after = &aw.seen[blocked_at + 1..];
    assert!(
        !after.iter().any(is_block_list),
        "no block list is reported once the list is lost: {after:?}"
    );
    assert_eq!(
        after.iter().filter(|e| is_block_list_unreadable(e)).count(),
        1,
        "the unreadable list is reported once: {after:?}"
    );
    assert!(
        !after.iter().any(request_from(&b.pk)),
        "B's hello surfaces no request: {after:?}"
    );
    assert_eq!(
        a_fake.calls().drop_reads,
        reads,
        "no drop slot is read while the list is unknown"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
    a
}

/// A profile that blocked `blocked`, relaunched with its block list record
/// overwritten, and whose record is put back exactly as it was once the
/// relaunch has reported the list unreadable. Returns the profile, the
/// relaunch's records, its watch and the index of its startup health report.
async fn relaunch_with_a_block_list_that_reads_again(
    blocked: &IdentityPk,
) -> (Profile, Fake, Watch, usize) {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    let at = aw.wait_for("the startup block list", is_block_list).await;
    aw.send(RunnerCommand::Block {
        peer: blocked.clone(),
    })
    .await;
    aw.wait_from(at + 1, "the list after the block", is_block_list)
        .await;
    assert!(finished(&aw.stop().await));

    let path = block_list_record(&a);
    let stored = std::fs::read(&path).expect("the record reads");
    overwrite_block_list_record(&a);
    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    assert!(
        is_block_list_unreadable(&aw.seen[1]),
        "the relaunch reports the list unreadable: {:?}",
        aw.seen
    );
    std::fs::write(&path, &stored).expect("the record is put back");
    (a, relaunched, aw, at)
}

/// An unreadable block list that reads again is reported by the next
/// collection, exactly once, as the identities the record holds, and the drop
/// is scanned again.
#[tokio::test(start_paused = true)]
async fn an_unreadable_block_list_that_reads_again_is_reported_once() {
    let b = Profile::new();
    let (_a, relaunched, mut aw, at) = relaunch_with_a_block_list_that_reads_again(&b.pk).await;
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    let lists: Vec<&RunnerEvent> = aw.seen[at + 1..]
        .iter()
        .filter(|e| is_block_list(e))
        .collect();
    assert_eq!(lists.len(), 1, "one block list: {:?}", &aw.seen[at + 1..]);
    assert_eq!(block_list(lists[0]), vec![b.pk.clone()]);
    assert!(
        relaunched.calls().drop_reads > 0,
        "the drop is scanned again"
    );
    assert!(finished(&aw.stop().await));
}

/// A block the store accepts while the block list is unknown makes it known:
/// its list is reported, and the next collection reports no second one.
#[tokio::test(start_paused = true)]
async fn a_block_accepted_while_the_list_is_unknown_is_reported_once() {
    let (b, c) = (Profile::new(), Profile::new());
    let (_a, relaunched, mut aw, at) = relaunch_with_a_block_list_that_reads_again(&b.pk).await;
    aw.send(RunnerCommand::Block { peer: c.pk.clone() }).await;
    let at = aw
        .wait_from(at + 1, "the list after blocking C", is_block_list)
        .await;
    let mut both = vec![b.pk.clone(), c.pk.clone()];
    both.sort();
    assert_eq!(block_list(&aw.seen[at]), both);
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    assert!(
        !aw.seen[at + 1..].iter().any(is_block_list),
        "no second block list: {:?}",
        &aw.seen[at + 1..]
    );
    assert!(
        relaunched.calls().drop_reads > 0,
        "the drop is scanned again"
    );
    assert!(finished(&aw.stop().await));
}

/// B's acceptance of A's first contact, refused at its second write so that
/// B's conversation holds the acceptance pending, with both runners stopped.
async fn leave_an_acceptance_pending() -> (Profile, Profile, Fake) {
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
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
    (a, b, b_fake)
}

/// B, relaunched with an acceptance pending after `prepare` changes its block
/// list, surfaces no message across startup and the repair polls that follow,
/// shows the conversation pending throughout, and still holds the acceptance
/// pending once stopped. Returns what the relaunch reported.
async fn a_pending_acceptance_stays_pending(prepare: fn(&Profile, &Profile)) -> Vec<RunnerEvent> {
    let (a, b, b_fake) = leave_an_acceptance_pending().await;
    prepare(&a, &b);
    let mut bw = b.spawn(&b_fake.restart(), RunnerConfig::default());
    bw.wait_for("B's relaunch", is_health).await;
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX * 2).await;
    bw.drain();
    let rows = roster(&bw.seen[0]);
    assert!(
        rows.len() == 1 && rows[0].state == ConversationState::Pending,
        "the relaunch shows the conversation pending: {:?}",
        bw.seen
    );
    assert!(
        !bw.seen
            .iter()
            .any(|event| matches!(event, RunnerEvent::Message { .. })),
        "no message surfaces: {:?}",
        bw.seen
    );
    assert!(
        !bw.seen
            .iter()
            .any(|event| matches!(event, RunnerEvent::Roster(rows)
            if rows.iter().any(|row| row.state == ConversationState::Established))),
        "the conversation is never shown established: {:?}",
        bw.seen
    );
    let Watch { handle, seen, .. } = bw;
    assert!(finished(&handle.shutdown().await));

    let store =
        Store::open(b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).expect("the store opens");
    let Ok(loaded) = store.load() else {
        panic!("the store loads");
    };
    assert!(
        loaded.convs.len() == 1 && loaded.convs[0].state.acceptance_pending,
        "the acceptance is still pending in the store"
    );
    seen
}

/// An acceptance left unfinished is not carried on while the block list will
/// not read.
#[tokio::test(start_paused = true)]
async fn a_pending_acceptance_is_not_carried_on_while_the_block_list_is_unreadable() {
    let seen = a_pending_acceptance_stays_pending(|_, b| overwrite_block_list_record(b)).await;
    assert!(
        is_block_list_unreadable(&seen[1]),
        "the relaunch reports the list unreadable: {seen:?}"
    );
}

/// An acceptance left unfinished is not carried on while the block list holds
/// the correspondent.
#[tokio::test(start_paused = true)]
async fn a_pending_acceptance_of_a_blocked_correspondent_is_not_carried_on() {
    let seen = a_pending_acceptance_stays_pending(|a, b| write_block_list(b, &a.pk)).await;
    assert!(
        is_block_list(&seen[1]) && block_list(&seen[1]).len() == 1,
        "the relaunch reports the one blocked identity: {seen:?}"
    );
}

/// An Accept that arrives while the block list will not read is refused as a
/// store failure and writes nothing: no channel, no reply and no conversation.
#[tokio::test(start_paused = true)]
async fn an_accept_while_the_block_list_is_unreadable_is_refused_and_writes_nothing() {
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
        .wait_for("B's contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);

    overwrite_block_list_record(&b);
    let before = b_fake.calls();
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let at = bw
        .wait_from(at + 1, "the answer to the Accept", |event| {
            sent(2)(event) || refused(2)(event)
        })
        .await;
    assert_eq!(refusal(&bw.seen[at]), Refusal::Store);
    let after = b_fake.calls();
    assert_eq!(
        (after.open_channel, after.control_writes, after.ring_writes),
        (
            before.open_channel,
            before.control_writes,
            before.ring_writes
        ),
        "nothing is written to the network"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));

    let store =
        Store::open(b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).expect("the store opens");
    let Ok(loaded) = store.load() else {
        panic!("the store loads");
    };
    assert!(loaded.convs.is_empty(), "no conversation is recorded");
}

/// A stored block list holding more identities than the maximum is corruption,
/// refused as a store failure; only a change past the maximum is a full list.
#[test]
fn an_oversized_stored_block_list_is_refused_as_a_store_failure() {
    use daemonseed_core::dm::block_list::{BlockListError, BLOCK_LIST_CAPACITY};
    let oversized = vec![0u8; BLOCK_LIST_CAPACITY + IDENTITY_PK_LEN];
    assert!(
        matches!(
            BlockList::decode(&oversized),
            Err(BlockListError::Full { .. })
        ),
        "the decode names the record full"
    );
    let Err(failure) = decode_stored_block_list(&oversized) else {
        panic!("an oversized record does not decode");
    };
    assert_eq!(failure.refusal(), Refusal::Store);
    assert_eq!(BlockListFailure::Full.refusal(), Refusal::BlockListFull);
}

/// A block list event's `Debug` output names how many identities it holds and
/// none of their bytes.
#[test]
fn a_block_list_event_prints_its_count_and_no_key_bytes() {
    let mut key: IdentityPk = Box::new([0u8; IDENTITY_PK_LEN]);
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::try_from(i % 251).expect("below 251") + 1;
    }
    let shown = format!("{:?}", RunnerEvent::BlockList(vec![key.clone(), key]));
    assert_eq!(shown, "BlockList(2 identities)");
    assert_eq!(
        format!("{:?}", RunnerEvent::BlockListUnreadable),
        "BlockListUnreadable"
    );
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

/// The advert keys `profile`'s store holds.
fn stored_advert_keys(profile: &Profile) -> AdvertKeys {
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    AdvertKeys::restore(
        store
            .load_advert_keys()
            .expect("the advert keys read")
            .expect("the advert keys exist"),
    )
}

/// Run a reset over `profile`'s store, as its owner would: between runs, or
/// while a runner holds the same profile.
fn reset_between_runs(profile: &Profile) {
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    flows::reset(&store, os_fill, now).expect("the reset runs");
}

/// The advert bytes the network holds for `profile`.
fn published_advert(dht: &Arc<Mutex<Dht>>, profile: &Profile) -> Option<Vec<u8>> {
    dht.lock()
        .expect("the network lock")
        .records
        .get(&profile.advert_key())
        .map(|(bytes, _)| bytes.clone())
}

/// A reset rotates the advert keys in the store, and the next advert poll finds
/// the network still holding the advert of the key rotated away: its numbers
/// match, its bytes do not. The poll publishes the rotated advert and records it
/// as published, so a later reset rotates again, while a reset repeated before
/// any poll publishes the rotated key does not.
#[tokio::test(start_paused = true)]
async fn a_reset_advert_is_published_by_the_next_poll_so_a_later_reset_rotates() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));
    let minted = stored_advert_keys(&a);
    assert_eq!(
        published_advert(&dht, &a),
        Some(
            minted
                .advert_bytes(&a.keys().signing)
                .expect("the minted advert signs")
        ),
        "the minted advert is on the network"
    );

    reset_between_runs(&a);
    let rotated = stored_advert_keys(&a);
    assert_eq!(
        rotated.serial(),
        minted.serial() + 1,
        "the minted advert was recorded as published, so the reset rotates"
    );
    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    assert!(finished(&aw.stop().await));
    assert_eq!(
        relaunched.calls().advert_publishes,
        1,
        "the rotated advert is published once"
    );
    assert_eq!(
        published_advert(&dht, &a),
        Some(
            rotated
                .advert_bytes(&a.keys().signing)
                .expect("the rotated advert signs")
        ),
        "the network holds the rotated advert"
    );

    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        rotated.serial() + 1,
        "the rotated advert was recorded as published, so a second reset rotates again"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        rotated.serial() + 1,
        "a reset before the newly rotated key is published does not rotate again"
    );
}

/// A profile whose advert reached the network without being recorded as
/// published, here a publish that landed but reported a failure, is recorded as
/// published by the first poll that finds that advert intact, and a reset after
/// that poll rotates. Before it, a reset does not.
#[tokio::test(start_paused = true)]
async fn an_intact_advert_found_by_a_poll_is_recorded_as_published() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    a_fake.faults().refuse_after_advert_write = true;
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    let at = aw.wait_for("A's startup", is_health).await;
    assert_eq!(
        health(&aw.seen[at]).advert_write_failures,
        1,
        "the publish reported a failure"
    );
    assert!(finished(&aw.stop().await));
    let minted = stored_advert_keys(&a);
    assert_eq!(
        published_advert(&dht, &a),
        Some(
            minted
                .advert_bytes(&a.keys().signing)
                .expect("the minted advert signs")
        ),
        "the advert reached the network all the same"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        minted.serial(),
        "an advert never recorded as published is not rotated away"
    );

    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    assert!(finished(&aw.stop().await));
    assert_eq!(
        relaunched.calls().advert_publishes,
        0,
        "the intact advert is not rewritten"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        minted.serial() + 1,
        "the intact advert the poll found was recorded as published, so the reset rotates"
    );
}

/// A reset made while the runner runs is published by the runner's own
/// scheduled advert poll, byte for byte, and recorded as published, with no
/// relaunch: the poll reloads the rotated keys from the store.
#[tokio::test(start_paused = true)]
async fn a_reset_made_while_running_is_published_by_the_scheduled_poll() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    let minted = stored_advert_keys(&a);
    reset_between_runs(&a);
    let rotated = stored_advert_keys(&a);
    assert_eq!(
        rotated.serial(),
        minted.serial() + 1,
        "the reset rotates the keys in the store the runner holds"
    );
    let publishes_before = a_fake.calls().advert_publishes;
    tokio::time::sleep(advert::POLL_INTERVAL_MAX + Duration::from_secs(60)).await;
    assert_eq!(
        a_fake.calls().advert_publishes,
        publishes_before + 1,
        "the scheduled poll publishes the rotated advert once"
    );
    assert_eq!(
        published_advert(&dht, &a),
        Some(
            rotated
                .advert_bytes(&a.keys().signing)
                .expect("the rotated advert signs")
        ),
        "the network holds the rotated advert, byte for byte"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        rotated.serial() + 1,
        "the scheduled poll recorded the rotated advert as published"
    );
    assert!(finished(&aw.stop().await));
}

/// A poll that must replace a rotated-away key's advert and has its rewrite
/// refused records nothing as published: that advert stays on the network, and a
/// reset after that poll does not rotate again.
#[tokio::test(start_paused = true)]
async fn a_refused_rewrite_of_an_old_advert_records_nothing() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));
    let minted = stored_advert_keys(&a);
    reset_between_runs(&a);
    let rotated = stored_advert_keys(&a);
    assert_eq!(rotated.serial(), minted.serial() + 1);

    let relaunched = a_fake.restart();
    relaunched
        .faults()
        .plan
        .push((ADVERT, Op::Write, Fault::Refused));
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    assert_eq!(
        health(&aw.seen[at]).advert_write_failures,
        1,
        "the rewrite was refused"
    );
    assert!(finished(&aw.stop().await));
    assert_eq!(
        published_advert(&dht, &a),
        Some(
            minted
                .advert_bytes(&a.keys().signing)
                .expect("the minted advert signs")
        ),
        "the rotated-away key's advert is still what the network holds"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        rotated.serial(),
        "nothing was recorded as published, so the reset does not rotate again"
    );
}

/// An advert poll whose read of the advert fails counts that failure once and
/// decides from the numbers alone: where they match it neither rewrites nor
/// records anything as published, and where the network holds no number it
/// rewrites the advert as the numbers say.
#[tokio::test(start_paused = true)]
async fn a_failed_advert_read_leaves_the_decision_to_the_numbers() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    a_fake.faults().refuse_after_advert_write = true;
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));
    let minted = stored_advert_keys(&a);

    let matching = a_fake.restart();
    matching
        .faults()
        .plan
        .push((ADVERT, Op::Read, Fault::Refused));
    let mut aw = a.spawn(&matching, RunnerConfig::default());
    let at = aw
        .wait_for("the relaunch with matching numbers", is_health)
        .await;
    assert_eq!(
        health(&aw.seen[at]).advert_read_failures,
        1,
        "the failed read is counted once"
    );
    assert!(finished(&aw.stop().await));
    assert_eq!(
        matching.calls().advert_publishes,
        0,
        "matching numbers and no bytes: no rewrite"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        minted.serial(),
        "a poll that read no bytes records nothing as published"
    );

    a_fake.net().evict(a.advert_key());
    let lost = a_fake.restart();
    lost.faults().plan.push((ADVERT, Op::Read, Fault::Refused));
    let mut aw = a.spawn(&lost, RunnerConfig::default());
    let at = aw
        .wait_for("the relaunch with the advert lost", is_health)
        .await;
    assert_eq!(
        health(&aw.seen[at]).advert_read_failures,
        1,
        "the failed read is counted once"
    );
    assert!(finished(&aw.stop().await));
    assert_eq!(
        lost.calls().advert_publishes,
        1,
        "the network holds no number, so the advert is rewritten"
    );
    assert_eq!(
        published_advert(&dht, &a),
        Some(
            minted
                .advert_bytes(&a.keys().signing)
                .expect("the minted advert signs")
        ),
        "the current key's advert is back on the network"
    );
    reset_between_runs(&a);
    assert_eq!(
        stored_advert_keys(&a).serial(),
        minted.serial() + 1,
        "the rewrite the network took was recorded as published"
    );
}

/// An advert poll that finds the network holding the current key's advert, bytes
/// and numbers both, writes nothing: at a relaunch, and at the schedule's own
/// polls after it.
#[tokio::test(start_paused = true)]
async fn an_intact_advert_of_the_current_key_is_not_rewritten() {
    let dht = network();
    let a = Profile::new();
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));

    let relaunched = a_fake.restart();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    tokio::time::sleep(advert::POLL_INTERVAL_MAX * 2 + Duration::from_secs(60)).await;
    assert!(
        relaunched.calls().inspect_advert >= 3,
        "the relaunch and two later polls inspected the advert"
    );
    assert_eq!(
        relaunched.calls().advert_publishes,
        0,
        "an intact advert is not rewritten"
    );
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

/// Mark `peer`'s conversation in `profile`'s store for delete, as a teardown
/// does before its erase.
fn mark_for_delete(profile: &Profile, peer: CorrespondenceLabel) {
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    delivery::prepare_delete(&store, &peer, false).expect("the conversation is marked");
}

/// The conversations `profile`'s store holds marked for delete.
fn pending_deletes(profile: &Profile) -> Vec<CorrespondenceLabel> {
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    store
        .pending_deletes()
        .expect("the store lists its pending deletes")
}

/// Whether `event` is a roster that does not list `peer`.
fn roster_without(event: &RunnerEvent, peer: CorrespondenceLabel) -> bool {
    matches!(event, RunnerEvent::Roster(rows) if rows.iter().all(|row| row.peer != peer))
}

/// Whether `event` is a roster that lists `peer`.
fn roster_with(event: &RunnerEvent, peer: CorrespondenceLabel) -> bool {
    matches!(event, RunnerEvent::Roster(rows) if rows.iter().any(|row| row.peer == peer))
}

/// `fake` relaunched holding channels as the record store does: a channel
/// write or erase needs a channel this run opened, a refused erase keeps it,
/// and `fail_erase` refuses every erase.
fn relaunch_owning(fake: &Fake, fail_erase: bool) -> Fake {
    let relaunched = fake.restart();
    {
        let mut faults = relaunched.faults();
        faults.owned = Some(HashSet::new());
        faults.fail_erase = fail_erase;
    }
    relaunched
}

/// The one conversation `profile`'s store holds.
fn only_conversation(profile: &Profile) -> CorrespondenceLabel {
    let store = Store::open(profile.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("the store opens");
    let loaded = store.load().expect("the store loads");
    assert_eq!(loaded.convs.len(), 1, "the store holds one conversation");
    loaded.convs[0].peer
}

/// A delete command whose erase is refused keeps the conversation marked, and
/// the repair poll in the same run finishes it, reporting a roster without the
/// conversation and no `Deleted`.
#[tokio::test(start_paused = true)]
async fn a_refused_delete_command_is_finished_by_the_repair_poll() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
    let relaunched = relaunch_owning(&a_fake, false);
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;

    relaunched.faults().fail_erase = true;
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(51),
        peer: a_peer,
    })
    .await;
    let at = aw
        .wait_for("the delete's answer", |event| {
            refused(51)(event)
                || matches!(event, RunnerEvent::Deleted { token, .. } if token.0 == 51)
        })
        .await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    assert_eq!(
        pending_deletes(&a),
        vec![a_peer],
        "the conversation stays marked"
    );

    relaunched.faults().fail_erase = false;
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX * 2).await;
    aw.drain();
    let after = &aw.seen[at + 1..];
    assert!(
        after.iter().any(|event| roster_without(event, a_peer)),
        "the repair poll finishes the delete: {after:?}"
    );
    assert!(
        !after
            .iter()
            .any(|event| matches!(event, RunnerEvent::Deleted { .. })),
        "and no Deleted follows: {after:?}"
    );
    let lookup_key = a.outgoing_lookup_key(&b);
    assert!(
        !dht.lock()
            .expect("the network lock")
            .records
            .keys()
            .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key),
        "the channel is erased"
    );
    assert!(finished(&aw.stop().await));
    assert!(pending_deletes(&a).is_empty(), "no delete is left pending");
}

/// A marked conversation whose channel opens under a lookup key other than the
/// one it recorded has the mismatch counted, erases nothing, and stays marked
/// with its channel on the network.
#[tokio::test(start_paused = true)]
async fn a_marked_channel_opened_under_another_key_is_not_erased() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
    mark_for_delete(&a, a_peer);

    let relaunched = relaunch_owning(&a_fake, false);
    relaunched.faults().open_under_other_key = true;
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    assert!(
        health(&aw.seen[at]).channel_open_failures >= 1,
        "the mismatch is counted: {:?}",
        aw.seen[at]
    );
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    assert!(
        !aw.seen.iter().any(|event| roster_without(event, a_peer)),
        "the conversation stays on the roster: {:?}",
        aw.seen
    );
    assert_eq!(relaunched.calls().erases, 0, "no channel is erased");
    let lookup_key = a.outgoing_lookup_key(&b);
    assert!(
        dht.lock()
            .expect("the network lock")
            .records
            .keys()
            .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key),
        "the recorded channel stays on the network"
    );
    assert!(finished(&aw.stop().await));
    assert_eq!(
        pending_deletes(&a),
        vec![a_peer],
        "the conversation stays marked"
    );
}

/// An acceptance left pending on a conversation marked for delete is not
/// carried on: the next launch reads no ring, writes nothing for it and
/// surfaces no message, and finishes the delete.
#[tokio::test(start_paused = true)]
async fn a_marked_pending_acceptance_is_not_carried_on_and_its_delete_finishes() {
    let (_a, b, b_fake) = leave_an_acceptance_pending().await;
    let peer = only_conversation(&b);
    mark_for_delete(&b, peer);

    let relaunched = relaunch_owning(&b_fake, false);
    let mut bw = b.spawn(&relaunched, RunnerConfig::default());
    let at = bw.wait_for("B's relaunch", is_health).await;
    assert!(
        bw.seen[..at]
            .iter()
            .any(|event| roster_without(event, peer)),
        "the launch finishes the delete: {:?}",
        bw.seen
    );
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    bw.drain();
    assert!(
        !bw.seen
            .iter()
            .any(|event| matches!(event, RunnerEvent::Message { .. })),
        "no message surfaces: {:?}",
        bw.seen
    );
    let calls = relaunched.calls();
    assert_eq!(
        (calls.channel_reads, calls.ring_writes, calls.control_writes),
        (0, 0, 0),
        "no ring is read and no acceptance is written"
    );
    assert!(finished(&bw.stop().await));
    assert!(pending_deletes(&b).is_empty(), "no delete is left pending");
}

/// A conversation marked for delete whose channel was erased before the stop
/// is finished by the next launch, before its first health report: it leaves
/// the roster, nothing is written for it, and no delete is left pending.
#[tokio::test(start_paused = true)]
async fn a_delete_stopped_after_its_erase_is_finished_by_the_next_launch() {
    let Scene {
        a,
        b,
        a_fake,
        aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
    mark_for_delete(&a, a_peer);
    assert!(
        RunnerRecords::erase_channel(&mut a_fake.clone(), &a.outgoing_lookup_key(&b)).is_ok(),
        "the channel is erased"
    );

    let relaunched = relaunch_owning(&a_fake, false);
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    let at = aw.wait_for("the relaunch", is_health).await;
    assert!(
        !roster_without(&aw.seen[0], a_peer),
        "the launch roster still lists the conversation: {:?}",
        aw.seen
    );
    assert!(
        aw.seen[1..at]
            .iter()
            .any(|event| roster_without(event, a_peer)),
        "the conversation leaves the roster during the launch: {:?}",
        aw.seen
    );
    let calls = relaunched.calls();
    assert_eq!(
        (calls.hello_writes, calls.ring_writes, calls.control_writes),
        (0, 0, 0),
        "nothing is written for the conversation"
    );
    assert_eq!(
        (calls.open_channel, calls.open_existing),
        (0, 1),
        "the channel record is looked for without being created"
    );
    assert!(finished(&aw.stop().await));
    assert!(pending_deletes(&a).is_empty(), "no delete is left pending");
}

/// A launch whose erase of a marked conversation's channel is refused leaves
/// the conversation marked and on the roster, and looks at, reads and writes
/// nothing for it; once the network takes the erase, the repair poll finishes
/// the delete in the same run.
#[tokio::test(start_paused = true)]
async fn a_delete_whose_erase_is_refused_at_launch_is_finished_by_the_repair_poll() {
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
    // A message B has not collected leaves a cursor for collection to read.
    assert!(finished(&bw.stop().await));
    aw.send(RunnerCommand::Send {
        token: CommandToken(9),
        peer: a_peer,
        body: b"uncollected".to_vec(),
    })
    .await;
    aw.wait_for("A's message", sent(9)).await;
    assert!(finished(&aw.stop().await));
    mark_for_delete(&a, a_peer);
    let lookup_key = a.outgoing_lookup_key(&b);
    // A control subkey the network has lost is one a rewrite would put back.
    a_fake
        .net()
        .evict((CHANNEL, lookup_key, channel::CONTROL_SUBKEY));

    let relaunched = relaunch_owning(&a_fake, true);
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    aw.send(RunnerCommand::Send {
        token: CommandToken(10),
        peer: a_peer,
        body: b"to a conversation being deleted".to_vec(),
    })
    .await;
    let at = aw
        .wait_for("the answer to the send", |event| {
            sent(10)(event) || refused(10)(event)
        })
        .await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::UnknownConversation);
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    assert!(
        aw.seen.iter().any(|event| roster_with(event, a_peer)),
        "a roster listing the conversation is seen: {:?}",
        aw.seen
    );
    assert!(
        !aw.seen.iter().any(|event| roster_without(event, a_peer)),
        "the conversation stays on the roster: {:?}",
        aw.seen
    );
    assert_eq!(pending_deletes(&a), vec![a_peer], "and stays marked");
    let calls = relaunched.calls();
    assert_eq!(
        (
            calls.ring_writes,
            calls.control_writes,
            calls.inspect_channel,
            calls.channel_reads
        ),
        (0, 0, 0, 0),
        "nothing is looked at, read or written for the conversation"
    );

    relaunched.faults().fail_erase = false;
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX * 2).await;
    aw.drain();
    assert!(
        aw.seen.iter().any(|event| roster_without(event, a_peer)),
        "the repair poll finishes the delete: {:?}",
        aw.seen
    );
    assert!(
        !dht.lock()
            .expect("the network lock")
            .records
            .keys()
            .any(|(kind, name, _)| *kind == CHANNEL && *name == lookup_key),
        "the channel is erased"
    );
    assert!(finished(&aw.stop().await));
    assert!(pending_deletes(&a).is_empty(), "no delete is left pending");
}

/// A marked conversation still awaiting acceptance, relaunched with its erase
/// refused, has its outstanding hello neither looked at nor rewritten, and the
/// acceptance the correspondent wrote meanwhile is not counted as unsettled.
#[tokio::test(start_paused = true)]
async fn a_marked_first_contact_is_left_alone_while_its_erase_is_refused() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
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
    mark_for_delete(&a, a_peer);

    let relaunched = relaunch_owning(&a_fake, true);
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    tokio::time::sleep(DEFAULT_TICK * 3).await;
    aw.drain();
    let calls = relaunched.calls();
    assert_eq!(
        (
            calls.hello_writes,
            calls.inspect_drop,
            calls.ring_writes,
            calls.control_writes,
            calls.inspect_channel
        ),
        (0, 0, 0, 0, 0),
        "the marked conversation's hello and channel are left alone"
    );
    let reports: Vec<HealthCounters> = aw
        .seen
        .iter()
        .filter(|e| is_health(e))
        .map(health)
        .collect();
    assert!(!reports.is_empty(), "a health report is seen");
    assert!(
        reports
            .iter()
            .all(|counters| counters.hellos_unsettled == 0),
        "the acceptance for the marked conversation is not counted unsettled: {reports:?}"
    );
    assert_eq!(
        pending_deletes(&a),
        vec![a_peer],
        "the conversation stays marked"
    );
    assert!(finished(&aw.stop().await));
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

/// The handle a front end notes for a correspondent is stored with the
/// conversation: the roster that follows carries it, a note repeating it
/// reports nothing, a note for an identity with no conversation keeps nothing,
/// and the first roster of a relaunch carries it.
#[tokio::test(start_paused = true)]
async fn a_noted_handle_is_kept_with_the_conversation_across_a_relaunch() {
    let Scene {
        a,
        b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    let handle_of = |event: &RunnerEvent| -> Option<Option<String>> {
        match event {
            RunnerEvent::Roster(rows) => rows
                .iter()
                .find(|row| row.peer_identity_pk == b.pk)
                .map(|row| row.handle.clone()),
            _ => None,
        }
    };
    let from = aw.seen.len();
    aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: b.pk.clone(),
        handle: "bert".to_owned(),
    })
    .await;
    let at = aw
        .wait_from(from, "the roster after the note", |event| {
            handle_of(event).is_some()
        })
        .await;
    assert_eq!(handle_of(&aw.seen[at]), Some(Some("bert".to_owned())));

    let stranger = Profile::new();
    aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: stranger.pk.clone(),
        handle: "nobody".to_owned(),
    })
    .await;
    aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: b.pk.clone(),
        handle: "bert".to_owned(),
    })
    .await;
    // A command after both, answered, so both have been served.
    aw.send(RunnerCommand::Send {
        token: CommandToken(70),
        peer: a_peer,
        body: b"after the notes".to_vec(),
    })
    .await;
    let after = aw.seen.len();
    aw.wait_for("the send after the notes", sent(70)).await;
    assert!(
        !aw.seen[after..]
            .iter()
            .any(|event| handle_of(event).is_some()),
        "neither note changed the store: {:?}",
        &aw.seen[after..]
    );
    assert!(finished(&aw.stop().await));

    let mut aw = a.spawn(&a_fake.restart(), RunnerConfig::default());
    let at = aw.wait_for("the relaunch's roster", is_roster).await;
    assert_eq!(handle_of(&aw.seen[at]), Some(Some("bert".to_owned())));
    assert_eq!(
        roster(&aw.seen[at]).len(),
        1,
        "no conversation for the stranger"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// ISC-C106 — a conversation deleted on both sides and established again
/// names channel records other than the deleted one's, whose network copies a
/// delete leaves behind. The initiator recognises the new acceptance, reads
/// the new reply and then the acceptor's next message, and nothing the deleted
/// conversation left is read.
#[tokio::test(start_paused = true)]
async fn a_conversation_established_again_after_a_delete_is_recognised() {
    let Scene {
        a,
        b,
        a_fake,
        b_fake,
        mut aw,
        mut bw,
        a_peer,
        b_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    bw.send(RunnerCommand::Send {
        token: CommandToken(50),
        peer: b_peer,
        body: b"from the deleted conversation".to_vec(),
    })
    .await;
    bw.wait_for("B's second message", sent(50)).await;
    aw.wait_for(
        "B's second message at A",
        message(a_peer, 1, b"from the deleted conversation"),
    )
    .await;

    a_fake.faults().erase_local_only = true;
    b_fake.faults().erase_local_only = true;
    let b_old = b.outgoing_lookup_key(&a);
    for (watch, token, peer) in [(&mut aw, 51u64, a_peer), (&mut bw, 52, b_peer)] {
        watch
            .send(RunnerCommand::DeleteConversation {
                token: CommandToken(token),
                peer,
            })
            .await;
        watch
            .wait_for(
                "the delete",
                |event| matches!(event, RunnerEvent::Deleted { token: t, .. } if t.0 == token),
            )
            .await;
    }
    let stale = channel::slot_for(1);
    assert!(
        b_fake.read((CHANNEL, b_old, stale)).is_some(),
        "the deleted conversation's second message is still in B's ring"
    );

    let from = aw.seen.len();
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(60),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body again".to_vec(),
    })
    .await;
    let at = aw
        .wait_from(from, "A's second first contact", sent(60))
        .await;
    let a_again = sent_peer(&aw.seen[at]);
    let from_b = bw.seen.len();
    let at = bw
        .wait_from(from_b, "B's second contact request", request_from(&a.pk))
        .await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(61),
        request,
        reply: b"the reply again".to_vec(),
    })
    .await;
    let at = bw
        .wait_from(from_b, "B's second acceptance", sent(61))
        .await;
    let b_again = sent_peer(&bw.seen[at]);

    // Bounded as a whole, since every failed pass reports health and so no
    // single wait for an event runs out. Well past the waiting interval a
    // recognition is collected on.
    tokio::time::timeout(
        Duration::from_secs(5 * 60),
        aw.wait_from(
            from,
            "A's recognition of the second acceptance",
            accepted(a_again),
        ),
    )
    .await
    .expect("A recognised the second acceptance");
    aw.wait_from(
        from,
        "the new reply at A",
        message(a_again, 0, b"the reply again"),
    )
    .await;
    assert_ne!(
        b.outgoing_lookup_key(&a),
        b_old,
        "the new conversation writes a channel record of its own"
    );
    bw.send(RunnerCommand::Send {
        token: CommandToken(62),
        peer: b_again,
        body: b"the second message again".to_vec(),
    })
    .await;
    aw.wait_from(
        from,
        "B's new second message at A",
        message(a_again, 1, b"the second message again"),
    )
    .await;
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// B holding A's request from an earlier scan, and B's next scan held at the
/// slot after A's hello, so the scan has read the hello before it is held.
struct HeldScan {
    a: Profile,
    b: Profile,
    bw: Watch,
    b_fake: Fake,
    request: ContactRequestId,
    held: Arc<Gate>,
}

/// Entropy that is the same on every run: successive bytes of a counter
/// starting at `seed`.
fn counter_fill(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), ()> {
    let mut next = seed;
    move |buf| {
        for byte in buf {
            *byte = next;
            next = next.wrapping_add(1);
        }
        Ok(())
    }
}

/// A's first contact held by B as a request, and B's next drop scan held at
/// the slot after A's hello. A writes its first contact through the flows
/// with [`counter_fill`], so the hello's slot is the same on every run and is
/// not the drop's last.
async fn held_scan_after_a_request() -> HeldScan {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    let mut aw = a.spawn(&a_fake, real_clock());
    aw.wait_for("A's startup", is_health).await;
    assert!(finished(&aw.stop().await));
    let mut bw = b.spawn(&b_fake, real_clock());
    bw.wait_for("B's startup", is_health).await;
    let keys = a.keys();
    let me = Me {
        signer: &keys.signing,
        channel_root: &keys.dm_channel_root,
    };
    let store =
        Store::open(a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).expect("A's store opens");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let mut records = a_fake.restart();
    flows::first_contact(
        &store,
        &mut records,
        &me,
        &b.pk,
        b"the first body",
        counter_fill(0),
        now,
    )
    .expect("A's first contact");
    let at = bw.wait_for("B's request", request_from(&a.pk)).await;
    let request = request_id(&bw.seen[at]);
    let slot = hello_slot(&dht, &b);
    assert!(
        slot + 1 < drop_plane::DROP_SUBKEYS,
        "the hello is in the drop's last slot, {slot}; choose another counter_fill seed"
    );
    let held = Arc::new(Gate::default());
    b_fake.faults().gate_drop_slot = Some((b.drop_name(), slot + 1, Arc::clone(&held)));
    held.reached().await;
    HeldScan {
        a,
        b,
        bw,
        b_fake,
        request,
        held,
    }
}

/// Wait until `fake`'s runner starts its next drop pass after this call.
async fn next_pass(fake: &Fake) {
    let passes = fake.calls().drop_passes;
    tokio::time::timeout(Duration::from_secs(60), async {
        while fake.calls().drop_passes <= passes {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the next pass started");
}

/// An Accept served during a drop scan that read the accepted hello earlier
/// is not surfaced again as a request by that scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_accepted_during_a_scan_is_not_surfaced_again() {
    let mut scan = held_scan_after_a_request().await;
    let _release = ReleaseOnDrop(Arc::clone(&scan.held));
    scan.bw
        .send(RunnerCommand::Accept {
            token: CommandToken(2),
            request: scan.request,
            reply: b"the reply".to_vec(),
        })
        .await;
    scan.held.release();
    let at = scan
        .bw
        .wait_for("B's answer to the accept", |event| {
            sent(2)(event) || refused(2)(event)
        })
        .await;
    assert!(sent(2)(&scan.bw.seen[at]), "{:?}", scan.bw.seen[at]);
    next_pass(&scan.b_fake).await;
    scan.bw.drain();
    assert!(
        !scan.bw.seen[at..].iter().any(request_from(&scan.a.pk)),
        "the accepted request came back: {:?}",
        &scan.bw.seen[at..]
    );
    assert!(finished(&scan.bw.stop().await));
}

/// A Block served during a drop scan that read the blocked identity's hello
/// earlier is not surfaced again as a request by that scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_blocked_during_a_scan_is_not_surfaced_again() {
    let mut scan = held_scan_after_a_request().await;
    let _release = ReleaseOnDrop(Arc::clone(&scan.held));
    let from = scan.bw.seen.len();
    scan.bw
        .send(RunnerCommand::Block {
            peer: scan.a.pk.clone(),
        })
        .await;
    let store = Store::open(scan.b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN])
        .expect("B's store opens");
    tokio::time::timeout(Duration::from_secs(30), async {
        while !read_block_list(&store).is_some_and(|list| list.is_blocked(&scan.a.pk)) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the block is stored while the scan is held");
    scan.held.release();
    scan.bw
        .wait_from(from, "the block", |event| {
            is_block_list(event) && !block_list(event).is_empty()
        })
        .await;
    next_pass(&scan.b_fake).await;
    scan.bw.drain();
    assert!(
        !scan.bw.seen[from..].iter().any(request_from(&scan.a.pk)),
        "the blocked request came back: {:?}",
        &scan.bw.seen[from..]
    );
    assert!(finished(&scan.bw.stop().await));
}

/// A Delete served during the drop scan that recognised the conversation's
/// acceptance earlier reports no acceptance for the deleted conversation and
/// counts no store failure for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conversation_deleted_during_the_scan_that_accepted_it_is_not_reported() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    let mut bw = b.spawn(&b_fake, real_clock());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&a_fake, real_clock());
    aw.wait_for("A's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"the first body".to_vec(),
    })
    .await;
    let at = aw.wait_for("A's first contact", sent(1)).await;
    let a_peer = sent_peer(&aw.seen[at]);
    // A's drop reads wait while B accepts, so A recognises the acceptance in a
    // scan that is then held.
    let paused = Arc::new(Gate::default());
    let _release_paused = ReleaseOnDrop(Arc::clone(&paused));
    a_fake.faults().gate_drop = Some(Arc::clone(&paused));
    let at = bw.wait_for("B's request", request_from(&a.pk)).await;
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request: request_id(&bw.seen[at]),
        reply: b"the reply".to_vec(),
    })
    .await;
    bw.wait_for("B's acceptance", sent(2)).await;
    let slot = hello_slot(&dht, &a);
    if slot + 1 >= drop_plane::DROP_SUBKEYS {
        return;
    }
    let held = Arc::new(Gate::default());
    let _release_held = ReleaseOnDrop(Arc::clone(&held));
    {
        let mut faults = a_fake.faults();
        faults.trail = Some(Vec::new());
        faults.gate_drop_slot = Some((a.drop_name(), slot + 1, Arc::clone(&held)));
        faults.gate_drop = None;
    }
    paused.release();
    held.reached().await;
    let trail = a_fake.faults().trail.clone().expect("the trail");
    assert!(
        trail.contains(&Trail::OwnDrop(slot)),
        "the held pass read the hello back: {trail:?}"
    );
    let from = aw.seen.len();
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(3),
        peer: a_peer,
    })
    .await;
    held.release();
    aw.wait_from(
        from,
        "the delete",
        |event| matches!(event, RunnerEvent::Deleted { token, .. } if token.0 == 3),
    )
    .await;
    next_pass(&a_fake).await;
    aw.drain();
    assert!(
        !aw.seen.iter().any(accepted(a_peer)),
        "an acceptance was reported for the deleted conversation: {:?}",
        aw.seen
    );
    assert!(
        aw.seen
            .iter()
            .filter(|event| is_health(event))
            .all(|event| health(event).store_failures == 0),
        "no store failure is counted for it"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A send issued while a collection pass is reading one conversation has its
/// slot write start before the pass reads the next conversation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_issued_during_a_collection_writes_before_the_next_conversation() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        mut aw,
        bw,
        a_peer,
        ..
    } = establish(real_clock()).await;
    let c = Profile::new();
    let c_fake = Fake::on(&dht);
    let mut cw = c.spawn(&c_fake, real_clock());
    cw.wait_for("C's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(40),
        peer_identity_pk: c.pk.clone(),
        body: b"to C".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact to C", sent(40)).await;
    let at = cw.wait_for("C's request", request_from(&a.pk)).await;
    cw.send(RunnerCommand::Accept {
        token: CommandToken(41),
        request: request_id(&cw.seen[at]),
        reply: b"from C".to_vec(),
    })
    .await;
    cw.wait_for("C's acceptance", sent(41)).await;
    aw.wait_for(
        "C's reply at A",
        |event| matches!(event, RunnerEvent::Message { body, .. } if body.as_slice() == b"from C"),
    )
    .await;

    let (from_b, from_c) = (b.outgoing_lookup_key(&a), c.outgoing_lookup_key(&a));
    assert_ne!(from_b[0], from_c[0], "the trail tells the channels apart");
    let held = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&held));
    {
        let mut faults = a_fake.faults();
        faults.trail = Some(Vec::new());
        faults.gate_channel_read = Some((vec![from_b, from_c], 0, Arc::clone(&held)));
    }
    held.reached().await;
    aw.send(RunnerCommand::Send {
        token: CommandToken(42),
        peer: a_peer,
        body: b"during the collection".to_vec(),
    })
    .await;
    committed(&a, &a_peer, 2).await;
    held.release();
    aw.wait_for("A's send", sent(42)).await;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let done = a_fake.faults().trail.as_ref().is_some_and(|trail| {
                trail.contains(&Trail::ChannelRead(from_b[0]))
                    && trail.contains(&Trail::ChannelRead(from_c[0]))
                    && trail.contains(&Trail::Ring(channel::slot_for(1)))
            });
            if done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both conversations were read and the send written");
    let trail = a_fake.faults().trail.take().expect("the trail");
    let Some(Trail::ChannelRead(first)) = trail.first().copied() else {
        panic!("the held call was a channel read: {trail:?}");
    };
    let other = if first == from_b[0] {
        from_c[0]
    } else {
        from_b[0]
    };
    let write = trail
        .iter()
        .position(|step| *step == Trail::Ring(channel::slot_for(1)))
        .expect("the send's write");
    let next = trail
        .iter()
        .position(|step| *step == Trail::ChannelRead(other))
        .expect("the other conversation's read");
    assert!(
        write < next,
        "the send waited for the next conversation: {trail:?}"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
    assert!(finished(&cw.stop().await));
}

/// A command issued while the first of two contact requests is being
/// previewed is answered before the second preview.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_issued_during_a_preview_is_served_before_the_next_one() {
    let dht = network();
    let (a, b, c) = (Profile::new(), Profile::new(), Profile::new());
    let b_fake = Fake::on(&dht);
    let mut bw = b.spawn(&b_fake, real_clock());
    bw.wait_for("B's startup", is_health).await;
    assert!(finished(&bw.stop().await));
    for (from, token) in [(&a, 1u64), (&c, 2)] {
        let mut w = from.spawn(&Fake::on(&dht), real_clock());
        w.wait_for("startup", is_health).await;
        w.send(RunnerCommand::FirstContact {
            token: CommandToken(token),
            peer_identity_pk: b.pk.clone(),
            body: b"hello".to_vec(),
        })
        .await;
        w.wait_for("the first contact", sent(token)).await;
        assert!(finished(&w.stop().await));
    }
    let b_fake = b_fake.restart();
    let held = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&held));
    // The startup scan reads each hello's opening once; the first preview's
    // first read is held.
    b_fake.faults().gate_channel_read = Some((
        vec![a.outgoing_lookup_key(&b), c.outgoing_lookup_key(&b)],
        2,
        Arc::clone(&held),
    ));
    let mut bw = b.spawn(&b_fake, real_clock());
    held.reached().await;
    let stranger = Profile::new();
    bw.send(RunnerCommand::Block {
        peer: stranger.pk.clone(),
    })
    .await;
    within(Duration::from_secs(10), "the block stored", async {
        while !read_block_list(&reopen_store(&b)).is_some_and(|list| list.is_blocked(&stranger.pk))
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    held.release();
    let previews = |event: &RunnerEvent| matches!(event, RunnerEvent::RequestPreview { .. });
    let first = bw.wait_for("the first preview", previews).await;
    let second = bw
        .wait_from(first + 1, "the second preview", previews)
        .await;
    let blocked = bw
        .wait_for("the block", |event| {
            is_block_list(event) && block_list(event).contains(&stranger.pk)
        })
        .await;
    assert!(
        blocked < second,
        "the block waited for both previews: {:?}",
        bw.seen
    );
    assert!(finished(&bw.stop().await));
}

/// A send issued while a drop scan is in progress has its slot write start
/// between two slot reads of that scan, not after the scan: the scan serves
/// the queued command after the read in progress and resumes at the next slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_issued_during_a_drop_scan_writes_before_the_scan_ends() {
    let Scene {
        a: _a,
        b,
        aw,
        mut bw,
        b_fake,
        b_peer,
        ..
    } = establish(real_clock()).await;
    // A slot inside the drop with slots after it, so the scan is mid-pass.
    const HELD: u16 = 100;
    const _: () = assert!(HELD + 1 < drop_plane::DROP_SUBKEYS);

    let held = Arc::new(Gate::default());
    let _release_held = ReleaseOnDrop(Arc::clone(&held));
    {
        let mut faults = b_fake.faults();
        faults.trail = Some(Vec::new());
        faults.gate_drop_slot = Some((b.drop_name(), HELD, Arc::clone(&held)));
    }
    held.reached().await;
    bw.send(RunnerCommand::Send {
        token: CommandToken(40),
        peer: b_peer,
        body: b"during the scan".to_vec(),
    })
    .await;
    committed(&b, &b_peer, 2).await;
    held.release();
    bw.wait_for("B's send", sent(40)).await;
    // The scan resumes after the send is answered; wait for its next read.
    let ring = Trail::Ring(channel::slot_for(1));
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let resumed = b_fake.faults().trail.as_ref().is_some_and(|trail| {
                trail
                    .iter()
                    .position(|step| *step == ring)
                    .is_some_and(|at| trail.len() > at + 1)
            });
            if resumed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a record call followed the send's write");

    let trail = b_fake.faults().trail.take().expect("the trail was kept");
    let write = trail
        .iter()
        .position(|step| *step == Trail::Ring(channel::slot_for(1)))
        .unwrap_or_else(|| panic!("the send's slot write is in the trail: {trail:?}"));
    let held_read = trail
        .iter()
        .position(|step| *step == Trail::OwnDrop(HELD))
        .expect("the held read is in the trail");
    assert!(held_read < write, "{trail:?}");
    assert_eq!(
        &trail[held_read + 1..=write],
        &[Trail::Ring(channel::slot_for(1))],
        "the write follows the held read with no slot read between"
    );
    assert_eq!(
        trail.get(write + 1),
        Some(&Trail::OwnDrop(HELD + 1)),
        "the scan resumes at the next slot after the write"
    );
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
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
fn other_counters(counters: &HealthCounters) -> [(&'static str, u64); 10] {
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
        ("previews_failed", counters.previews_failed),
        ("slots_unopened", counters.slots_unopened),
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
    tokio::time::sleep(DEFAULT_TICK * DROP_SCAN_TICKS * 2).await;
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
    let writes = a_fake.calls().ring_writes;
    aw.send(RunnerCommand::Send {
        token: CommandToken(30),
        peer: a_peer,
        body: b"refused".to_vec(),
    })
    .await;
    // The message is committed, so a refused first write leaves it to the
    // repair rather than refusing the send.
    while a_fake.calls().ring_writes == writes {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    aw.drain();
    assert!(!aw.seen.iter().any(refused(30)), "the send is not refused");
    let seen = std::mem::take(&mut aw.seen);
    let stop = aw.stop().await;
    assert!(finished(&stop));
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Refused {
                token: Some(CommandToken(30)),
                reason: Refusal::ShuttingDown
            }
        )),
        "the send still pending is answered at the stop: {:?}",
        stop.undelivered
    );
    assert!(
        seen.iter().chain(&stop.undelivered).any(|event| matches!(
            event,
            RunnerEvent::Health(counters) if counters.channel_write_failures == 1
        )),
        "the report of the refused write is among the events read before the stop \
         or handed back by it: {:?}",
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
/// the task reads as unfinished while its call is held, the messages collected
/// before the held call come back with the shutdown, and the one that call
/// collects comes back through the task's end once it returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_shutdown_hands_back_the_running_task_and_its_messages() {
    let config = RunnerConfig {
        tick: Duration::from_millis(50),
        grace: Duration::from_millis(300),
    };
    let Scene {
        a,
        b,
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
    // The third read of A's ring is the read of m3: m1 and m2 have been
    // collected and reported when it is held.
    let reading = Arc::new(Gate::default());
    let _release_reading = ReleaseOnDrop(Arc::clone(&reading));
    {
        let mut faults = b_fake.faults();
        faults.gate_drop = None;
        faults.gate_channel_read = Some((vec![a.outgoing_lookup_key(&b)], 2, Arc::clone(&reading)));
    }
    paused.release();
    reading.reached().await;

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
    assert_eq!(
        messages_from(&stop.undelivered, b_peer),
        vec![1, 2],
        "the messages read before the held call, and not the one it reads: {:?}",
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

    b_fake.faults().gate_channel_read = None;
    reading.release();
    let late = tokio::time::timeout(Duration::from_secs(30), end.finish())
        .await
        .expect("the task ended once its call returned");
    assert!(finished(&late), "{late:?}");
    let seqs = messages_from(&late.undelivered, b_peer);
    assert_eq!(seqs, vec![3], "late events: {:?}", late.undelivered);
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
        preview_due: false,
        preview: None,
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

// ── push delivery ───────────────────────────────────────────────────────────

use crate::dm::push::{
    push_queue, OwnRoute, PushError, PushFuture, PushInbound, PushOutbox, PushParts, PushTransport,
};

/// A fake `app_call` network: routes by blob to the runner that allocated
/// them, calls answered through a one-shot per call.
#[derive(Default)]
struct Board {
    routes: HashMap<Vec<u8>, (String, PushOutbox)>,
    waiting: HashMap<u64, tokio::sync::oneshot::Sender<Vec<u8>>>,
    next: u64,
    /// Fail every call, as a transport that cannot reach the correspondent.
    down: bool,
    /// Calls made.
    calls: usize,
    /// Answers sent.
    replies: usize,
    /// Answer every call with the bare recorded tag, as a node that is not the
    /// correspondent would.
    forge_answer: bool,
    /// Routes released, in order.
    released: Vec<Vec<u8>>,
    /// Fail this many route allocations before allocating any.
    failed_routes: usize,
    /// When each route allocation was asked for, failed or not.
    route_attempts: Vec<Instant>,
}

struct FakePush {
    board: Arc<Mutex<Board>>,
    inbound: PushOutbox,
}

impl PushTransport for FakePush {
    fn call(&self, route: Vec<u8>, request: Vec<u8>) -> PushFuture<Result<Vec<u8>, PushError>> {
        let board = Arc::clone(&self.board);
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let target = {
                let mut board = board.lock().expect("the board lock");
                board.calls += 1;
                if board.down {
                    return Err(PushError("the transport is down".to_owned()));
                }
                board.next += 1;
                let id = board.next;
                board.waiting.insert(id, tx);
                board.routes.get(&route).map(|(_, to)| (id, to.clone()))
            };
            let Some((id, to)) = target else {
                return Err(PushError("no such route".to_owned()));
            };
            if !to.offer(PushInbound::Call {
                id,
                message: request,
                received: std::time::Instant::now(),
            }) {
                return Err(PushError("not admitted".to_owned()));
            }
            match tokio::time::timeout(Duration::from_secs(10), rx).await {
                Ok(Ok(answer)) => Ok(answer),
                _ => Err(PushError("no answer".to_owned())),
            }
        })
    }

    fn new_route(&self) -> PushFuture<Result<OwnRoute, PushError>> {
        let board = Arc::clone(&self.board);
        let inbound = self.inbound.clone();
        Box::pin(async move {
            let mut board = board.lock().expect("the board lock");
            board.route_attempts.push(Instant::now());
            if board.failed_routes > 0 {
                board.failed_routes -= 1;
                return Err(PushError("allocated route failed to test".to_owned()));
            }
            board.next += 1;
            let id = format!("route-{}", board.next);
            let blob = id.clone().into_bytes();
            board.routes.insert(blob.clone(), (id.clone(), inbound));
            Ok(OwnRoute { id, blob })
        })
    }

    fn reply(&self, call: u64, answer: Vec<u8>) -> PushFuture<Result<(), PushError>> {
        let (waiting, answer) = {
            let mut board = self.board.lock().expect("the board lock");
            board.replies += 1;
            let answer = if board.forge_answer {
                daemonseed_core::dm::push::RECORDED.to_vec()
            } else {
                answer
            };
            (board.waiting.remove(&call), answer)
        };
        Box::pin(async move {
            if let Some(waiting) = waiting {
                let _ = waiting.send(answer);
            }
            Ok(())
        })
    }

    fn release(&self, route: &[u8]) {
        self.board
            .lock()
            .expect("the board lock")
            .released
            .push(route.to_vec());
    }
}

/// Give `fake`'s next runner a push lane on `board`.
fn attach_push(fake: &Fake, board: &Arc<Mutex<Board>>) -> PushOutbox {
    let (outbox, inbox) = push_queue();
    fake.faults().push = Some(PushParts {
        transport: Arc::new(FakePush {
            board: Arc::clone(board),
            inbound: outbox.clone(),
        }),
        inbound: inbox,
    });
    outbox
}

/// A collection interval long enough that no collection runs inside a test
/// on the real clock, so what arrives arrives by push.
fn no_collection() -> RunnerConfig {
    RunnerConfig {
        tick: Duration::from_secs(600),
        grace: Duration::from_secs(5),
    }
}

/// A's first contact reaching B through the record store, B's runner holding
/// it: both runners with push lanes on one board.
struct Knocked {
    dht: Arc<Mutex<Dht>>,
    board: Arc<Mutex<Board>>,
    a: Profile,
    b: Profile,
    a_fake: Fake,
    b_fake: Fake,
    aw: Watch,
    bw: Watch,
    a_peer: CorrespondenceLabel,
    request: ContactRequestId,
}

async fn knock(config: RunnerConfig) -> Knocked {
    let dht = network();
    let board = Arc::new(Mutex::new(Board::default()));
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    attach_push(&a_fake, &board);
    attach_push(&b_fake, &board);
    let mut bw = b.spawn(&b_fake, real_clock());
    bw.wait_for("B's startup", is_health).await;
    let mut aw = a.spawn(&a_fake, config);
    // The real clock drives these runners whatever their tick.
    aw.budget = REAL_BUDGET;
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
    Knocked {
        dht,
        board,
        a,
        b,
        a_fake,
        b_fake,
        aw,
        bw,
        a_peer,
        request,
    }
}

/// ISC-C109 — B's acceptance reaches A by push: A's conversation is
/// established and B's reply shown with no network read at A while B's
/// control write is still held, and B's reply is reported delivered before
/// any of B's acceptance writes has completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_acceptance_is_pushed_and_recognised_before_its_writes_complete() {
    let mut k = knock(no_collection()).await;
    let held = Arc::new(Gate::default());
    k.b_fake.faults().gate_control = Some(Arc::clone(&held));
    let _release = ReleaseOnDrop(Arc::clone(&held));
    let reads_before = k.a_fake.calls().network_reads;
    k.bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request: k.request,
        reply: b"the reply".to_vec(),
    })
    .await;
    held.reached().await;
    k.aw.wait_for("A's acceptance", accepted(k.a_peer)).await;
    k.aw.wait_for("B's reply at A", message(k.a_peer, 0, b"the reply"))
        .await;
    assert_eq!(
        k.a_fake.calls().network_reads,
        reads_before,
        "the acceptance was recognised from the push alone"
    );
    let at =
        k.bw.wait_for("B's reply delivered", |event| {
            matches!(event, RunnerEvent::Delivered { through_seq: 0, .. })
        })
        .await;
    assert!(
        !k.bw.seen.iter().any(sent(2)),
        "delivered is reported before the acceptance's writes complete"
    );
    let RunnerEvent::Delivered { peer: b_peer, .. } = k.bw.seen[at] else {
        unreachable!()
    };
    held.release();
    k.bw.wait_for("B's acceptance", sent(2)).await;
    k.bw.wait_for("A's first body at B", message(b_peer, 0, b"the first body"))
        .await;
    assert!(k.board.lock().unwrap().calls >= 1);
    let _ = (&k.dht, &k.b);
}

/// Establish a conversation between two runners with push lanes, the
/// acceptance pushed.
async fn establish_pushed() -> (Knocked, CorrespondenceLabel) {
    let mut k = knock(no_collection()).await;
    k.bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request: k.request,
        reply: b"the reply".to_vec(),
    })
    .await;
    let at = k.bw.wait_for("B's acceptance", sent(2)).await;
    let b_peer = sent_peer(&k.bw.seen[at]);
    k.aw.wait_for("A's acceptance", accepted(k.a_peer)).await;
    k.bw.wait_for("B's reply delivered by A's answer", delivered(b_peer, 0))
        .await;
    (k, b_peer)
}

/// ISC-C107 / ISC-C108 — a message is pushed as its slot is written: B records
/// it and A reports it delivered while A's slot write is still held; the
/// sent report follows the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_message_is_delivered_before_its_write_completes() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = Arc::new(Gate::default());
    k.a_fake.faults().gate_ring_write = Some(Arc::clone(&held));
    let _release = ReleaseOnDrop(Arc::clone(&held));
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"pushed".to_vec(),
    })
    .await;
    held.reached().await;
    k.bw.wait_for("the pushed message at B", message(b_peer, 1, b"pushed"))
        .await;
    k.aw.wait_for("delivery at A", delivered(k.a_peer, 1)).await;
    assert!(
        !k.aw.seen.iter().any(sent(3)),
        "delivered is reported before the write completes"
    );
    held.release();
    k.aw.wait_for("A's send", sent(3)).await;
}

/// ISC-C107 — with the transport down a message is sent and then
/// delivered through the record store as without push, and nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_whose_push_fails_is_delivered_through_the_record_store() {
    let dht = network();
    let board = Arc::new(Mutex::new(Board::default()));
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    attach_push(&a_fake, &board);
    attach_push(&b_fake, &board);
    board.lock().unwrap().down = true;
    let mut bw = b.spawn(&b_fake, real_clock());
    let mut aw = a.spawn(&a_fake, real_clock());
    aw.wait_for("A's startup", is_health).await;
    bw.wait_for("B's startup", is_health).await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"first".to_vec(),
    })
    .await;
    let at = aw.wait_for("A's first contact", sent(1)).await;
    let a_peer = sent_peer(&aw.seen[at]);
    let at = bw.wait_for("B's request", request_from(&a.pk)).await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"reply".to_vec(),
    })
    .await;
    let at = bw.wait_for("B's acceptance", sent(2)).await;
    let b_peer = sent_peer(&bw.seen[at]);
    aw.wait_for("A's acceptance", accepted(a_peer)).await;
    aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: a_peer,
        body: b"through the store".to_vec(),
    })
    .await;
    let sent_at = aw.wait_for("A's send", sent(3)).await;
    bw.wait_for("the message at B", message(b_peer, 1, b"through the store"))
        .await;
    let delivered_at = aw
        .wait_for("delivery by cursor", delivered(a_peer, 1))
        .await;
    assert!(sent_at < delivered_at, "sent, then delivered by the cursor");
    assert!(board.lock().unwrap().calls >= 1, "a push was attempted");
}

/// ISC-C104 — when this node's route dies the runner allocates another and
/// rewrites its control subkey with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_route_is_replaced_and_republished() {
    let (k, _) = establish_pushed().await;
    let (a_route, a_inbound) = {
        let board = k.board.lock().unwrap();
        let mut routes: Vec<_> = board.routes.values().cloned().collect();
        // B started first, so A's route is the second allocated.
        routes.sort_by(|x, y| x.0.cmp(&y.0));
        routes[1].clone()
    };
    let store = Store::open(k.a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).unwrap();
    let state = store.load().unwrap().convs.remove(0).state;
    let published = || {
        let bytes = k
            .dht
            .lock()
            .unwrap()
            .records
            .get(&(CHANNEL, state.outgoing_lookup_key, channel::CONTROL_SUBKEY))
            .expect("A's control")
            .0
            .clone();
        channel::open_control_with_key(state.own_control_key.as_ref().expect("A's key"), &bytes)
            .expect("opens")
            .reach
            .route
    };
    assert_eq!(
        published(),
        Some(a_route.clone().into_bytes()),
        "A's control subkey carries its route"
    );
    assert!(a_inbound.offer(PushInbound::RoutesDied(vec![a_route.clone()])));
    tokio::time::timeout(Duration::from_secs(30), async {
        while published() == Some(a_route.clone().into_bytes()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("A republished its control subkey with a new route");
    let route = published().expect("a route is published");
    assert!(
        k.board.lock().unwrap().routes.contains_key(&route),
        "the published route is one A allocated"
    );
}

/// The route a conversation's control subkey carries, as its writer published
/// it.
fn published_route(dht: &Arc<Mutex<Dht>>, state: &ConvState) -> Option<Vec<u8>> {
    let bytes = dht
        .lock()
        .unwrap()
        .records
        .get(&(CHANNEL, state.outgoing_lookup_key, channel::CONTROL_SUBKEY))
        .expect("the control subkey")
        .0
        .clone();
    channel::open_control_with_key(state.own_control_key.as_ref().expect("the key"), &bytes)
        .expect("opens")
        .reach
        .route
}

/// A route allocation that fails at startup is tried again from the schedule,
/// 5 seconds later and twice as long after each further failure, up to 2
/// minutes, until one succeeds; the route is then published in the control
/// subkey of the established conversation.
#[tokio::test(start_paused = true)]
async fn a_failed_route_allocation_is_retried_until_a_route_is_published() {
    let scene = establish(RunnerConfig::default()).await;
    let (a, a_peer, dht) = (scene.a, scene.a_peer, scene.dht);
    assert!(finished(&scene.aw.stop().await));
    let a_fake = scene.a_fake.restart();
    let board = Arc::new(Mutex::new(Board {
        failed_routes: 7,
        ..Board::default()
    }));
    attach_push(&a_fake, &board);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's restart", is_health).await;
    let state = conv_of(&a, &a_peer);
    tokio::time::timeout(Duration::from_secs(15 * 60), async {
        while published_route(&dht, &state).is_none() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("A allocated a route and republished its control subkey");
    let route = published_route(&dht, &state).expect("a route is published");
    let (attempts, allocated) = {
        let board = board.lock().unwrap();
        (
            board.route_attempts.clone(),
            board.routes.contains_key(&route),
        )
    };
    assert!(allocated, "the published route is the one allocated");
    assert_eq!(attempts.len(), 8, "seven failures, then a route");
    let gaps: Vec<Duration> = attempts.windows(2).map(|pair| pair[1] - pair[0]).collect();
    let slack = Duration::from_secs(1);
    for (gap, secs) in gaps.iter().zip([5, 10, 20, 40, 80, 120, 120]) {
        let want = Duration::from_secs(secs);
        assert!(
            *gap >= want && *gap <= want + slack,
            "the waits between attempts double from 5 s to a 2 minute cap: {gaps:?}"
        );
    }
    assert!(finished(&aw.stop().await));
}

/// A send the live lane commits while the runner is rewriting control subkeys
/// has its slot written before the rewrite of the next conversation, not after
/// the last.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_committed_during_a_control_rewrite_is_written_before_it_ends() {
    let (mut k, b_peer) = establish_pushed().await;
    let c = Profile::new();
    let c_fake = Fake::on(&k.dht);
    attach_push(&c_fake, &k.board);
    let mut cw = c.spawn(&c_fake, real_clock());
    cw.wait_for("C's startup", is_health).await;
    k.aw.send(RunnerCommand::FirstContact {
        token: CommandToken(3),
        peer_identity_pk: c.pk.clone(),
        body: b"to C".to_vec(),
    })
    .await;
    let at = k.aw.wait_for("A's first contact to C", sent(3)).await;
    let a_peer_c = sent_peer(&k.aw.seen[at]);
    let at = cw.wait_for("C's request", request_from(&k.a.pk)).await;
    cw.send(RunnerCommand::Accept {
        token: CommandToken(4),
        request: request_id(&cw.seen[at]),
        reply: b"from C".to_vec(),
    })
    .await;
    cw.wait_for("C's acceptance", sent(4)).await;
    k.aw.wait_for("A's acceptance by C", accepted(a_peer_c))
        .await;
    let route = published_route(&k.dht, &conv_of(&k.a, &k.a_peer)).expect("A's route");
    let a_inbound = k.board.lock().unwrap().routes[&route].1.clone();

    let held = Arc::new(Gate::default());
    {
        let mut faults = k.a_fake.faults();
        faults.gate_control = Some(Arc::clone(&held));
        faults.channel_writes = Some(Vec::new());
    }
    let _release = ReleaseOnDrop(Arc::clone(&held));
    assert!(a_inbound.offer(PushInbound::RoutesDied(vec![
        String::from_utf8(route).expect("a fake route id")
    ])));
    held.reached().await;
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(5),
        peer: k.a_peer,
        body: b"during the rewrite".to_vec(),
    })
    .await;
    k.bw.wait_for(
        "the pushed message at B",
        message(b_peer, 1, b"during the rewrite"),
    )
    .await;
    committed(&k.a, &k.a_peer, 2).await;
    held.release();
    k.aw.wait_for("A's send", sent(5)).await;
    let to_b = conv_of(&k.a, &k.a_peer).outgoing_lookup_key;
    let to_c = conv_of(&k.a, &a_peer_c).outgoing_lookup_key;
    let slot = (to_b, channel::slot_for(1));
    let control = channel::CONTROL_SUBKEY;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let done = k
                .a_fake
                .faults()
                .channel_writes
                .as_ref()
                .is_some_and(|writes| {
                    writes
                        .iter()
                        .filter(|(_, subkey)| *subkey == control)
                        .count()
                        >= 2
                        && writes.contains(&slot)
                });
            if done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both control rewrites and the send's slot write were made");
    let writes = k.a_fake.faults().channel_writes.take().expect("the log");
    let mut controls: Vec<_> = writes
        .iter()
        .filter(|(_, subkey)| *subkey == control)
        .map(|(key, _)| *key)
        .collect();
    controls.sort_unstable();
    let mut rewritten = vec![to_b, to_c];
    rewritten.sort_unstable();
    assert_eq!(
        controls, rewritten,
        "one control rewrite of each conversation: {writes:?}"
    );
    let write = writes
        .iter()
        .position(|entry| *entry == slot)
        .expect("the send's slot write, on the conversation it was sent to");
    let last_control = writes
        .iter()
        .rposition(|(_, subkey)| *subkey == control)
        .expect("a control rewrite");
    assert!(
        write < last_control,
        "the slot is written between two control rewrites: {writes:?}"
    );
    assert!(finished(&cw.stop().await));
}

/// A change of this side's own handle rewrites the control subkey of every
/// established conversation at once, with the new handle, one write each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_own_handle_change_is_republished_to_every_conversation_at_once() {
    let (mut k, _) = establish_pushed().await;
    let c = Profile::new();
    let c_fake = Fake::on(&k.dht);
    attach_push(&c_fake, &k.board);
    let mut cw = c.spawn(&c_fake, real_clock());
    cw.wait_for("C's startup", is_health).await;
    k.aw.send(RunnerCommand::FirstContact {
        token: CommandToken(3),
        peer_identity_pk: c.pk.clone(),
        body: b"to C".to_vec(),
    })
    .await;
    let at = k.aw.wait_for("A's first contact to C", sent(3)).await;
    let a_peer_c = sent_peer(&k.aw.seen[at]);
    let at = cw.wait_for("C's request", request_from(&k.a.pk)).await;
    cw.send(RunnerCommand::Accept {
        token: CommandToken(4),
        request: request_id(&cw.seen[at]),
        reply: b"from C".to_vec(),
    })
    .await;
    cw.wait_for("C's acceptance", sent(4)).await;
    k.aw.wait_for("A's acceptance by C", accepted(a_peer_c))
        .await;

    let store = Store::open(k.a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).unwrap();
    let states: Vec<_> = store
        .load()
        .unwrap()
        .convs
        .into_iter()
        .map(|conv| conv.state)
        .collect();
    assert_eq!(states.len(), 2, "A has two conversations");
    let published = || {
        let dht = k.dht.lock().unwrap();
        states
            .iter()
            .map(|state| {
                let bytes = &dht
                    .records
                    .get(&(CHANNEL, state.outgoing_lookup_key, channel::CONTROL_SUBKEY))
                    .expect("A's control")
                    .0;
                channel::open_control_with_key(
                    state.own_control_key.as_ref().expect("A's key"),
                    bytes,
                )
                .expect("opens")
                .reach
                .handle
            })
            .collect::<Vec<_>>()
    };
    let hash = daemonseed_core::handle::Handle::from_pubkey(None, k.a.pk.as_slice())
        .unwrap()
        .hash_prefix()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (old, new) = (format!("alice#{hash}"), format!("alicia#{hash}"));
    let carries = |handle: &str| {
        let handle = Some(handle.to_owned());
        move || published().iter().all(|published| *published == handle)
    };

    k.aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: k.a.pk.clone(),
        handle: old.clone(),
    })
    .await;
    prod_until(&k.aw, "both controls carry the first handle", carries(&old)).await;
    let mut settled = k.a_fake.calls().control_writes;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = k.a_fake.calls().control_writes;
        if now == settled {
            break;
        }
        settled = now;
    }

    k.aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: k.a.pk.clone(),
        handle: new.clone(),
    })
    .await;
    prod_until(&k.aw, "both controls carry the new handle", carries(&new)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        k.a_fake.calls().control_writes - settled,
        states.len(),
        "one control rewrite per established conversation"
    );
    assert!(finished(&cw.stop().await));
}

/// ISC-C105 — a handle this side sets as its own travels in its control
/// subkey, and the correspondent stores it where its hash names the writer;
/// one naming another identity is not published.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_own_handle_is_published_checked_and_stored() {
    let dht = network();
    let board = Arc::new(Mutex::new(Board::default()));
    let (a, b) = (Profile::new(), Profile::new());
    let (a_fake, b_fake) = (Fake::on(&dht), Fake::on(&dht));
    attach_push(&a_fake, &board);
    attach_push(&b_fake, &board);
    let mut bw = b.spawn(&b_fake, real_clock());
    let mut aw = a.spawn(&a_fake, no_collection());
    aw.budget = REAL_BUDGET;
    aw.wait_for("A's startup", is_health).await;
    bw.wait_for("B's startup", is_health).await;
    let hash = |pk: &IdentityPk| {
        daemonseed_core::handle::Handle::from_pubkey(None, pk.as_slice())
            .unwrap()
            .hash_prefix()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let genuine = format!("alice#{}", hash(&a.pk));
    let forged = format!("mallory#{}", hash(&b.pk));
    aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: a.pk.clone(),
        handle: forged,
    })
    .await;
    aw.send(RunnerCommand::NoteHandle {
        peer_identity_pk: a.pk.clone(),
        handle: genuine.clone(),
    })
    .await;
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hi".to_vec(),
    })
    .await;
    aw.wait_for("A's first contact", sent(1)).await;
    let at = bw.wait_for("B's request", request_from(&a.pk)).await;
    let request = request_id(&bw.seen[at]);
    bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request,
        reply: b"reply".to_vec(),
    })
    .await;
    bw.wait_for("B's acceptance", sent(2)).await;
    bw.wait_for("A's handle in B's roster", |event| {
        matches!(event, RunnerEvent::Roster(rows)
            if rows.iter().any(|row| row.handle.as_deref() == Some(genuine.as_str())))
    })
    .await;
    assert!(
        !bw.seen.iter().any(|event| matches!(event, RunnerEvent::Roster(rows)
            if rows.iter().any(|row| row.handle.as_deref().is_some_and(|h| h.starts_with("mallory"))))),
        "a handle naming another identity is never published"
    );
}

/// Wait on the real clock until `done` holds, prodding `watch`'s runner with a
/// command that changes nothing so its after-command bookkeeping runs.
async fn prod_until(watch: &Watch, what: &str, done: impl Fn() -> bool) {
    let nobody = Profile::new().pk;
    tokio::time::timeout(Duration::from_secs(30), async {
        while !done() {
            watch
                .send(RunnerCommand::NoteHandle {
                    peer_identity_pk: nobody.clone(),
                    handle: "nobody#000000000000".to_owned(),
                })
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// A pushed message from a correspondent this side has blocked is neither
/// recorded nor answered, and is counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_from_a_blocked_correspondent_is_not_recorded() {
    let (mut k, b_peer) = establish_pushed().await;
    k.aw.send(RunnerCommand::Block {
        peer: k.b.pk.clone(),
    })
    .await;
    k.aw.wait_for(
        "A's block list",
        |event| matches!(event, RunnerEvent::BlockList(list) if !list.is_empty()),
    )
    .await;
    let replies = k.board.lock().unwrap().replies;
    let calls = k.board.lock().unwrap().calls;
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(5),
        peer: b_peer,
        body: b"from a blocked sender".to_vec(),
    })
    .await;
    k.bw.wait_for("B's send", sent(5)).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while k.board.lock().unwrap().calls == calls {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("B pushed");
    k.aw.wait_for(
        "the push counted dropped",
        |event| matches!(event, RunnerEvent::Health(h) if h.pushes_dropped >= 1),
    )
    .await;
    assert_eq!(k.board.lock().unwrap().replies, replies, "not answered");
    assert!(
        !k.aw
            .seen
            .iter()
            .any(message(k.a_peer, 1, b"from a blocked sender")),
        "not recorded"
    );
}

/// An answer that is not the one the correspondent makes under the
/// conversation's key does not mark the message delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_answer_does_not_mark_delivered() {
    let (mut k, b_peer) = establish_pushed().await;
    k.board.lock().unwrap().forge_answer = true;
    let held = Arc::new(Gate::default());
    k.a_fake.faults().gate_ring_write = Some(Arc::clone(&held));
    let _release = ReleaseOnDrop(Arc::clone(&held));
    let replies = k.board.lock().unwrap().replies;
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"answered falsely".to_vec(),
    })
    .await;
    held.reached().await;
    k.bw.wait_for("the message at B", message(b_peer, 1, b"answered falsely"))
        .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while k.board.lock().unwrap().replies == replies {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("B answered");
    tokio::time::sleep(Duration::from_millis(300)).await;
    k.aw.drain();
    assert!(
        !k.aw.seen.iter().any(delivered(k.a_peer, 1)),
        "a forged answer marked the message delivered"
    );
}

/// A push the runner reaches after its answer window is dropped unanswered
/// and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_push_is_dropped_unanswered() {
    let (mut k, _) = establish_pushed().await;
    let a_inbound = {
        let board = k.board.lock().unwrap();
        let mut routes: Vec<_> = board.routes.values().cloned().collect();
        routes.sort_by(|x, y| x.0.cmp(&y.0));
        routes[1].1.clone()
    };
    let replies = k.board.lock().unwrap().replies;
    let mut message = daemonseed_core::dm::push::PUSH_TAG.to_vec();
    message.push(2);
    message.extend_from_slice(&[0; 64]);
    let received = std::time::Instant::now()
        .checked_sub(Duration::from_secs(60))
        .expect("an instant a minute ago");
    assert!(a_inbound.offer(PushInbound::Call {
        id: 9_999,
        message,
        received,
    }));
    k.aw.wait_for(
        "the expired push counted",
        |event| matches!(event, RunnerEvent::Health(h) if h.pushes_expired >= 1),
    )
    .await;
    assert_eq!(k.board.lock().unwrap().replies, replies, "not answered");
}

/// After a push fails the correspondent's route is released and forgotten:
/// the next message is not pushed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_push_forgets_and_releases_the_route() {
    let (mut k, _) = establish_pushed().await;
    let b_route = {
        let board = k.board.lock().unwrap();
        let mut routes: Vec<_> = board.routes.keys().cloned().collect();
        routes.sort();
        routes[0].clone()
    };
    k.board.lock().unwrap().down = true;
    let calls = k.board.lock().unwrap().calls;
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"one".to_vec(),
    })
    .await;
    k.aw.wait_for("A's first send", sent(3)).await;
    let board = Arc::clone(&k.board);
    prod_until(&k.aw, "the first is pushed", || {
        board.lock().unwrap().calls == calls + 1
    })
    .await;
    prod_until(&k.aw, "A released B's route", || {
        board.lock().unwrap().released.contains(&b_route)
    })
    .await;
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(4),
        peer: k.a_peer,
        body: b"two".to_vec(),
    })
    .await;
    k.aw.wait_for("A's second send", sent(4)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        k.board.lock().unwrap().calls,
        calls + 1,
        "the second is not pushed"
    );
}

/// A store failure on the push receive path drops the push and is counted as
/// a store failure. Collection meets the same broken store and counts store
/// failures of its own, so the dropped push is what ties the count to the
/// push.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_failure_taking_a_push_is_counted() {
    let (mut k, b_peer) = establish_pushed().await;
    let before =
        k.aw.seen
            .iter()
            .rev()
            .find_map(|event| match event {
                RunnerEvent::Health(h) => Some(h.store_failures),
                _ => None,
            })
            .unwrap_or(0);
    let mut corrupted = 0;
    for entry in walk(&k.a.root.path().join(STORE_DIR)) {
        if entry.file_name().and_then(|name| name.to_str()) == Some("conversation.bin") {
            std::fs::write(&entry, [0x5a; 64]).expect("corrupt the record");
            corrupted += 1;
        }
    }
    assert_eq!(corrupted, 1, "one conversation record");
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(5),
        peer: b_peer,
        body: b"into a broken store".to_vec(),
    })
    .await;
    k.bw.wait_for("B's send", sent(5)).await;
    k.aw.wait_for("the failed push counted", |event| {
        matches!(event, RunnerEvent::Health(h)
            if h.store_failures > before && h.pushes_dropped >= 1)
    })
    .await;
}

/// Every file under `dir`.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .expect("read the directory")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// A handle in a correspondent's control record whose hash names another
/// identity is not recorded; one naming the writer is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_handle_in_a_control_record_is_not_recorded() {
    let mut k = knock(real_clock()).await;
    k.bw.send(RunnerCommand::Accept {
        token: CommandToken(2),
        request: k.request,
        reply: b"the reply".to_vec(),
    })
    .await;
    k.bw.wait_for("B's acceptance", sent(2)).await;
    k.aw.wait_for("A's acceptance", accepted(k.a_peer)).await;
    assert!(finished(&k.bw.stop().await));
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"outstanding".to_vec(),
    })
    .await;
    k.aw.wait_for("A's send", sent(3)).await;

    let b_store = Store::open(k.b.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).unwrap();
    let state = b_store.load().unwrap().convs.remove(0).state;
    let hash = |pk: &IdentityPk| {
        daemonseed_core::handle::Handle::from_pubkey(None, pk.as_slice())
            .unwrap()
            .hash_prefix()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let write_handle = |handle: String| {
        let control = Control {
            opening: Some(
                ChannelOpening::decode(state.own_opening.as_ref().unwrap().as_slice()).unwrap(),
            ),
            collected_cursor: state.cursor_published,
            closed: false,
            generation: state.generation,
            reach: daemonseed_core::dm::channel::Reach {
                route: None,
                handle: Some(handle),
            },
        };
        let sealed =
            channel::seal_control_with_key(state.own_control_key.as_ref().unwrap(), &control)
                .unwrap();
        k.dht.lock().unwrap().put(
            (CHANNEL, state.outgoing_lookup_key, channel::CONTROL_SUBKEY),
            sealed,
        );
    };
    let a_store = Store::open(k.a.root.path().join(STORE_DIR), &[0x42; AEAD_KEY_LEN]).unwrap();
    write_handle(format!("mallory#{}", hash(&k.a.pk)));
    let reads = k.a_fake.calls().channel_reads;
    tokio::time::timeout(Duration::from_secs(30), async {
        while k.a_fake.calls().channel_reads < reads + 10 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("A kept reading");
    assert_eq!(
        a_store.handle(&k.a_peer).unwrap(),
        None,
        "a handle naming another identity is not recorded"
    );
    // The control: a handle naming B is recorded through the same read.
    let genuine = format!("bob#{}", hash(&k.b.pk));
    write_handle(genuine.clone());
    tokio::time::timeout(Duration::from_secs(30), async {
        while a_store.handle(&k.a_peer).unwrap().as_deref() != Some(genuine.as_str()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("A recorded B's genuine handle");
    let _ = &k.aw;
}

// ── the live lane ───────────────────────────────────────────────────────────

/// Wait on the real clock until `profile`'s conversation `peer` has committed
/// sends up to `send_seq`, and then for the live lane to hand the send to the
/// runner, which it does directly after the commit.
async fn committed(profile: &Profile, peer: &CorrespondenceLabel, send_seq: u64) {
    within(Duration::from_secs(10), "the send's commit", async {
        while conv_of(profile, peer).send_seq < send_seq {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Hold `fake`'s next ring read of the channel at `lookup_key`, and wait until
/// its runner is inside that read.
async fn hold_ring_read(fake: &Fake, lookup_key: [u8; HELLO_LOOKUP_KEY_LEN]) -> Arc<Gate> {
    let held = Arc::new(Gate::default());
    fake.faults().gate_ring_read = Some((lookup_key, Arc::clone(&held)));
    held.reached().await;
    held
}

/// How soon a send or a push the live lane serves is seen at the other end
/// while the runner is held: one second in an optimised build, and three in
/// the unoptimised dev profile, whose post-quantum arithmetic is several times
/// slower.
const LIVE_WITHIN: Duration = if cfg!(debug_assertions) {
    Duration::from_secs(3)
} else {
    Duration::from_secs(1)
};

/// `what`, which must happen within `limit` on the real clock.
async fn within<T>(
    limit: Duration,
    what: &str,
    happens: impl core::future::Future<Output = T>,
) -> T {
    tokio::time::timeout(limit, happens)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within {limit:?}"))
}

/// Wait on the real clock until `fake` has ended `more` further ring reads,
/// each the end of one collection pass over one conversation.
async fn passes_after(fake: &Fake, more: usize) {
    let from = fake.calls().ring_ends;
    within(Duration::from_secs(30), "the collection passes", async {
        while fake.calls().ring_ends < from + more {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

/// How many of the events seen report `seq` from `peer`.
fn reported(seen: &[RunnerEvent], peer: CorrespondenceLabel, seq: u64) -> usize {
    seen.iter()
        .filter(|event| {
            matches!(event, RunnerEvent::Message { from, seq: at, .. } if *from == peer && *at == seq)
        })
        .count()
}

/// B's conversation record with A, read from B's store.
fn conv_of(profile: &Profile, peer: &CorrespondenceLabel) -> ConvState {
    reopen_store(profile)
        .load_conv(peer)
        .expect("the store reads")
        .expect("the conversation")
}

/// ISC-C110 — a message pushed to a node whose runner is held inside a record
/// call is recorded, reported and answered within `LIVE_WITHIN`, while the
/// call is still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_is_taken_while_the_runner_is_held_in_a_call() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    let replies = k.board.lock().unwrap().replies;
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"while B is held".to_vec(),
    })
    .await;
    within(
        LIVE_WITHIN,
        "the pushed message at B",
        k.bw.wait_for(
            "the pushed message at B",
            message(b_peer, 1, b"while B is held"),
        ),
    )
    .await;
    within(
        LIVE_WITHIN,
        "B's answer at A",
        k.aw.wait_for("delivery at A", delivered(k.a_peer, 1)),
    )
    .await;
    assert!(k.board.lock().unwrap().replies > replies, "B answered");
    assert_eq!(
        conv_of(&k.b, &b_peer).my_collected,
        2,
        "B recorded the message while its runner was held"
    );
}

/// ISC-C110 — a send issued while the runner is held inside a record call is
/// pushed and answered within `LIVE_WITHIN`. Its slot is written only once
/// the call is released, from the stored outbox bytes, and it is reported sent after
/// that write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_while_the_runner_is_held_is_pushed_at_once_and_written_after() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    let writes = k.b_fake.calls().ring_writes;
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(7),
        peer: b_peer,
        body: b"from a held B".to_vec(),
    })
    .await;
    within(
        LIVE_WITHIN,
        "B's message at A",
        k.aw.wait_for("B's message at A", message(k.a_peer, 1, b"from a held B")),
    )
    .await;
    within(
        LIVE_WITHIN,
        "A's answer at B",
        k.bw.wait_for("delivery at B", delivered(b_peer, 1)),
    )
    .await;
    k.bw.drain();
    assert!(
        !k.bw.seen.iter().any(sent(7)),
        "sent is reported only after the slot write"
    );
    assert_eq!(
        k.b_fake.calls().ring_writes,
        writes,
        "no slot is written while the runner is held"
    );
    let owed = reopen_store(&k.b)
        .load()
        .expect("B's store loads")
        .convs
        .into_iter()
        .find(|conv| conv.peer == b_peer)
        .expect("B's conversation")
        .outstanding_outbox;
    let entry = owed
        .iter()
        .find(|entry| entry.seq == 1)
        .expect("the message is committed and owed")
        .clone();
    held.release();
    k.bw.wait_for("B's send", sent(7)).await;
    assert_eq!(k.b_fake.calls().ring_writes, writes + 1, "one slot write");
    let slot = (CHANNEL, k.b.outgoing_lookup_key(&k.a), channel::slot_for(1));
    assert_eq!(
        k.dht
            .lock()
            .unwrap()
            .records
            .get(&slot)
            .map(|(bytes, _)| bytes.clone()),
        Some(entry.ciphertext),
        "the slot holds the committed outbox bytes"
    );
}

/// ISC-C110 — a pushed message recorded while the runner's collection is
/// reading the same sequence is reported once, and the runner's read of it is
/// discarded rather than recorded again. A restart reports it no more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_recorded_during_a_held_read_of_its_slot_is_reported_once() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"raced".to_vec(),
    })
    .await;
    k.bw.wait_for("the pushed message at B", message(b_peer, 1, b"raced"))
        .await;
    // A's slot is written, so the held read finds the message when released.
    k.aw.wait_for("A's send", sent(3)).await;
    held.release();
    passes_after(&k.b_fake, 3).await;
    k.bw.drain();
    assert_eq!(
        reported(&k.bw.seen, b_peer, 1),
        1,
        "the message is reported once: {:?}",
        k.bw.seen
    );
    let state = conv_of(&k.b, &b_peer);
    assert_eq!(state.my_collected, 2, "one sequence recorded");

    let stop = k.bw.stop().await;
    assert!(finished(&stop));
    let b_fake = k.b_fake.restart();
    attach_push(&b_fake, &k.board);
    let mut bw = k.b.spawn(&b_fake, real_clock());
    bw.wait_for("B's restart", is_health).await;
    passes_after(&b_fake, 3).await;
    bw.drain();
    assert_eq!(
        reported(&bw.seen, b_peer, 1),
        0,
        "the restart reports nothing already recorded"
    );
    assert_eq!(conv_of(&k.b, &b_peer).my_collected, 2);
}

/// ISC-C110 — a send committed while the runner's collection of the same
/// conversation is inside its read loses neither update: the collection is
/// read again, the key schedule the send advanced is kept, and the next send
/// opens at the correspondent. A restart changes neither cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_during_a_held_collection_of_its_conversation_loses_neither_update() {
    let (mut k, b_peer) = establish_pushed().await;
    // A's message reaches B through the record store only.
    k.board.lock().unwrap().down = true;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"collected".to_vec(),
    })
    .await;
    k.aw.wait_for("A's send", sent(3)).await;
    k.board.lock().unwrap().down = false;
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(7),
        peer: b_peer,
        body: b"sent meanwhile".to_vec(),
    })
    .await;
    within(
        LIVE_WITHIN,
        "B's pushed message at A",
        k.aw.wait_for("B's message at A", message(k.a_peer, 1, b"sent meanwhile")),
    )
    .await;
    held.release();
    k.bw.wait_for("B's send", sent(7)).await;
    k.bw.wait_for("A's message at B", message(b_peer, 1, b"collected"))
        .await;
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(8),
        peer: b_peer,
        body: b"after both".to_vec(),
    })
    .await;
    within(
        Duration::from_secs(10),
        "B's next message at A",
        k.aw.wait_for("B's next message at A", message(k.a_peer, 2, b"after both")),
    )
    .await;
    k.bw.wait_for("B's next send", sent(8)).await;
    let state = conv_of(&k.b, &b_peer);
    assert_eq!(state.send_seq, 3, "both sends are counted");
    assert_eq!(state.my_collected, 2, "the collection is recorded");
    assert_eq!(reported(&k.bw.seen, b_peer, 1), 1);

    let stop = k.bw.stop().await;
    assert!(finished(&stop));
    let b_fake = k.b_fake.restart();
    attach_push(&b_fake, &k.board);
    let mut bw = k.b.spawn(&b_fake, real_clock());
    bw.wait_for("B's restart", is_health).await;
    passes_after(&b_fake, 3).await;
    bw.drain();
    let state = conv_of(&k.b, &b_peer);
    assert_eq!((state.send_seq, state.my_collected), (3, 2));
    assert_eq!(
        reported(&bw.seen, b_peer, 1),
        0,
        "nothing is reported twice"
    );
}

/// ISC-C110 — a send committed while the runner is held, and stopped before
/// its slot is written, is answered as shutting down and its slot is written
/// by the next launch from the stored bytes, the message sealed once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_stopped_before_its_write_is_written_by_the_next_launch() {
    let (k, b_peer) = establish_pushed().await;
    k.board.lock().unwrap().down = true;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    let writes = k.b_fake.calls().ring_writes;
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(7),
        peer: b_peer,
        body: b"before the stop".to_vec(),
    })
    .await;
    within(LIVE_WITHIN, "the commit", async {
        while conv_of(&k.b, &b_peer).send_seq != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let committed = reopen_store(&k.b)
        .load()
        .expect("B's store loads")
        .convs
        .into_iter()
        .find(|conv| conv.peer == b_peer)
        .expect("B's conversation")
        .outstanding_outbox
        .into_iter()
        .find(|entry| entry.seq == 1)
        .expect("the message is committed and owed");
    let Watch { handle, .. } = k.bw;
    let stopping = tokio::spawn(handle.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    held.release();
    let stop = stopping.await.expect("the shutdown");
    assert!(finished(&stop));
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Refused {
                token: Some(CommandToken(7)),
                reason: Refusal::ShuttingDown
            }
        )),
        "the send is answered: {:?}",
        stop.undelivered
    );
    assert_eq!(
        k.b_fake.calls().ring_writes,
        writes,
        "no slot is written once stop is asked for"
    );

    let b_fake = k.b_fake.restart();
    let mut bw = k.b.spawn(&b_fake, real_clock());
    bw.wait_for("B's restart", is_health).await;
    let slot = (CHANNEL, k.b.outgoing_lookup_key(&k.a), channel::slot_for(1));
    assert_eq!(
        k.dht
            .lock()
            .unwrap()
            .records
            .get(&slot)
            .map(|(bytes, _)| bytes.clone()),
        Some(committed.ciphertext),
        "the launch wrote the committed bytes"
    );
    assert_eq!(conv_of(&k.b, &b_peer).send_seq, 2, "sealed once");
    let _ = &k.aw;
}

/// ISC-C110 — a send whose commit keeps meeting a changed record is committed
/// on a later attempt within the lane's allowance, and past it is refused and
/// counted as a conversation failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_whose_commits_keep_conflicting_is_retried_then_refused_and_counted() {
    let Scene {
        a: _a,
        b: _b,
        a_fake,
        mut aw,
        a_peer,
        ..
    } = establish(real_clock()).await;
    let forced = Arc::clone(&a_fake.faults().forced_conflicts);
    forced.store(3, std::sync::atomic::Ordering::Relaxed);
    aw.send(RunnerCommand::Send {
        token: CommandToken(50),
        peer: a_peer,
        body: b"after three conflicts".to_vec(),
    })
    .await;
    within(
        Duration::from_secs(20),
        "the send after three conflicts",
        aw.wait_for("the send", sent(50)),
    )
    .await;
    forced.store(4, std::sync::atomic::Ordering::Relaxed);
    aw.send(RunnerCommand::Send {
        token: CommandToken(51),
        peer: a_peer,
        body: b"after four conflicts".to_vec(),
    })
    .await;
    let at = within(
        Duration::from_secs(20),
        "the refusal",
        aw.wait_for("the refusal", refused(51)),
    )
    .await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Flow);
    within(
        Duration::from_secs(20),
        "the failure counted",
        aw.wait_for(
            "the failure counted",
            |event| matches!(event, RunnerEvent::Health(h) if h.conversation_failures >= 1),
        ),
    )
    .await;
}

/// ISC-C110 — sends committed at once from two threads to one conversation
/// never share a sequence, and every one of them opens at the correspondent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_concurrent_senders_never_share_a_sequence() {
    let Scene {
        a,
        b: _b,
        a_fake,
        aw,
        mut bw,
        a_peer,
        b_peer,
        ..
    } = establish(real_clock()).await;
    assert!(finished(&aw.stop().await));
    let keys = a.keys();
    let (events, _events_rx) = mpsc::channel(EVENT_QUEUE);
    let (push, _) = push_hooks::PushState::new(None);
    let share = live_lane::LaneShare::new(
        Arc::new(reopen_store(&a)),
        Arc::new(keys.signing),
        Arc::new(keys.dm_channel_root),
        events,
        push.share.clone(),
        Clock::start(),
    );
    let before = conv_of(&a, &a_peer).send_seq;
    let seqs: Vec<u64> = std::thread::scope(|scope| {
        let senders: Vec<_> = ["x", "y"]
            .into_iter()
            .map(|who| {
                let share = share.clone();
                scope.spawn(move || {
                    (0..20)
                        .map(|i| {
                            share
                                .commit_send(&a_peer, format!("{who}{i}").as_bytes())
                                .expect("the commit")
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        senders
            .into_iter()
            .flat_map(|sender| sender.join().expect("the sender"))
            .collect()
    });
    let distinct: HashSet<u64> = seqs.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        40,
        "no two sends share a sequence: {seqs:?}"
    );
    assert_eq!(conv_of(&a, &a_peer).send_seq, before + 40);
    drop(share);
    // A's next launch writes the committed slots, and B reads every one.
    let _aw = a.spawn(&a_fake.restart(), real_clock());
    for seq in before..before + 40 {
        within(
            Duration::from_secs(60),
            "each message at B",
            bw.wait_for("a message at B", |event| {
                matches!(event, RunnerEvent::Message { from, seq: at, .. } if *from == b_peer && *at == seq)
            }),
        )
        .await;
    }
    let bodies: HashSet<Vec<u8>> = bw
        .seen
        .iter()
        .filter_map(|event| match event {
            RunnerEvent::Message {
                from, seq, body, ..
            } if *from == b_peer && *seq >= before => Some(body.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(bodies.len(), 40, "every committed message opens once");
}

/// ISC-C110 — with the runner held and its command queue full, a send is
/// still read, committed and pushed at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_behind_a_full_runner_queue_is_pushed_at_once() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    for serial in 0..(COMMAND_QUEUE as u64 + 3) {
        k.bw.send(RunnerCommand::Accept {
            token: CommandToken(1_000 + serial),
            request: ContactRequestId { epoch: 0, serial },
            reply: b"to nobody".to_vec(),
        })
        .await;
    }
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(7),
        peer: b_peer,
        body: b"past the queue".to_vec(),
    })
    .await;
    within(
        LIVE_WITHIN,
        "B's message at A",
        k.aw.wait_for("B's message at A", message(k.a_peer, 1, b"past the queue")),
    )
    .await;
    held.release();
    k.bw.wait_for("B's send", sent(7)).await;
    k.bw.wait_for(
        "the last refusal",
        refused(1_000 + COMMAND_QUEUE as u64 + 2),
    )
    .await;
}

/// ISC-C110 — a stop asked for while the runner writes a committed send's
/// slot answers the send and loses nothing: the slot holds the committed
/// bytes once the next launch is up, and the message is sealed once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_during_a_committed_write_answers_the_send_and_loses_nothing() {
    let (k, b_peer) = establish_pushed().await;
    k.board.lock().unwrap().down = true;
    let writing = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&writing));
    k.b_fake.faults().gate_ring_write = Some(Arc::clone(&writing));
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(7),
        peer: b_peer,
        body: b"written while stopping".to_vec(),
    })
    .await;
    writing.reached().await;
    let committed = reopen_store(&k.b)
        .load()
        .expect("B's store loads")
        .convs
        .into_iter()
        .find(|conv| conv.peer == b_peer)
        .expect("B's conversation")
        .outstanding_outbox
        .into_iter()
        .find(|entry| entry.seq == 1)
        .expect("the message is committed and owed");
    let Watch { handle, .. } = k.bw;
    let stopping = tokio::spawn(handle.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    writing.release();
    let stop = stopping.await.expect("the shutdown");
    assert!(finished(&stop));
    assert!(
        stop.undelivered.iter().any(|event| matches!(
            event,
            RunnerEvent::Sent {
                token: CommandToken(7),
                ..
            } | RunnerEvent::Refused {
                token: Some(CommandToken(7)),
                ..
            }
        )),
        "the send is answered: {:?}",
        stop.undelivered
    );
    let mut bw = k.b.spawn(&k.b_fake.restart(), real_clock());
    bw.wait_for("B's restart", is_health).await;
    let slot = (CHANNEL, k.b.outgoing_lookup_key(&k.a), channel::slot_for(1));
    assert_eq!(
        k.dht
            .lock()
            .unwrap()
            .records
            .get(&slot)
            .map(|(bytes, _)| bytes.clone()),
        Some(committed.ciphertext)
    );
    assert_eq!(conv_of(&k.b, &b_peer).send_seq, 2, "sealed once");
    let _ = &k.aw;
}

/// ISC-C110 — a block takes effect at once while the runner is held: a push
/// from the blocked correspondent that follows it is neither recorded nor
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_after_a_block_is_neither_recorded_nor_answered() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    k.bw.send(RunnerCommand::Block {
        peer: k.a.pk.clone(),
    })
    .await;
    let (calls, replies) = {
        let board = k.board.lock().unwrap();
        (board.calls, board.replies)
    };
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"after the block".to_vec(),
    })
    .await;
    within(LIVE_WITHIN, "A's push", async {
        while k.board.lock().unwrap().calls == calls {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    k.bw.drain();
    assert_eq!(k.board.lock().unwrap().replies, replies, "not answered");
    assert_eq!(reported(&k.bw.seen, b_peer, 1), 0, "not recorded");
}

/// ISC-C110 — a delete takes effect at once while the runner is held: a send
/// on the conversation that follows it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_after_a_delete_is_refused() {
    let (mut k, b_peer) = establish_pushed().await;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    k.bw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(20),
        peer: b_peer,
    })
    .await;
    k.bw.send(RunnerCommand::Send {
        token: CommandToken(21),
        peer: b_peer,
        body: b"after the delete".to_vec(),
    })
    .await;
    let at = within(
        LIVE_WITHIN,
        "the refusal",
        k.bw.wait_for("the refusal", refused(21)),
    )
    .await;
    assert_eq!(refusal(&k.bw.seen[at]), Refusal::UnknownConversation);
    assert_eq!(conv_of(&k.b, &b_peer).send_seq, 1, "nothing committed");
}

/// ISC-C110 — sends made while a collection reads the same conversation do
/// not stop the collection: the read held across them records its message,
/// and the slot is not read again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_during_a_collection_do_not_make_it_read_again() {
    let (mut k, b_peer) = establish_pushed().await;
    k.board.lock().unwrap().down = true;
    let held = hold_ring_read(&k.b_fake, k.a.outgoing_lookup_key(&k.b)).await;
    let _release = ReleaseOnDrop(Arc::clone(&held));
    k.aw.send(RunnerCommand::Send {
        token: CommandToken(3),
        peer: k.a_peer,
        body: b"read once".to_vec(),
    })
    .await;
    k.aw.wait_for("A's send", sent(3)).await;
    for token in [7u64, 8] {
        k.bw.send(RunnerCommand::Send {
            token: CommandToken(token),
            peer: b_peer,
            body: b"meanwhile".to_vec(),
        })
        .await;
    }
    committed(&k.b, &b_peer, 3).await;
    held.release();
    k.bw.wait_for("A's message at B", message(b_peer, 1, b"read once"))
        .await;
    passes_after(&k.b_fake, 2).await;
    let reads = k.b_fake.faults().gated_ring_reads.clone();
    assert_eq!(
        reads
            .iter()
            .filter(|subkey| **subkey == channel::slot_for(1))
            .count(),
        1,
        "the held read recorded the message: {reads:?}"
    );
    assert_eq!(conv_of(&k.b, &b_peer).my_collected, 2);
}

/// Whether `fake`'s record store holds the channel at `lookup_key`, as one
/// relaunched by [`relaunch_owning`] tracks it.
fn holds(fake: &Fake, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> bool {
    fake.faults()
        .owned
        .as_ref()
        .is_some_and(|owned| owned.contains(lookup_key))
}

/// The sequence a [`RunnerEvent::Sent`] answers with.
fn sent_seq(event: &RunnerEvent) -> u64 {
    match event {
        RunnerEvent::Sent { seq, .. } => *seq,
        other => panic!("not a sent event: {other:?}"),
    }
}

/// A channel whose reopen fails at launch is left out of the launch's control
/// rewrite and opened again from the schedule: the record store then holds it
/// without any write asking, the control subkey carries the route allocated at
/// launch, a send's slot is written, and a slot and a control subkey the
/// network loses are rewritten by the repair.
#[tokio::test(start_paused = true)]
async fn a_channel_whose_reopen_fails_at_launch_is_reopened_from_the_schedule() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    let relaunched = relaunch_owning(&a_fake, false);
    let board = Arc::new(Mutex::new(Board::default()));
    attach_push(&relaunched, &board);
    relaunched
        .faults()
        .plan
        .push((CHANNEL, Op::Open, Fault::TimedOut));
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    let state = conv_of(&a, &a_peer);
    assert_eq!(
        relaunched.calls().open_channel,
        1,
        "the launch's reopen fails, and its control rewrite opens nothing"
    );
    assert!(!holds(&relaunched, &lookup_key), "the channel is not held");
    assert_eq!(published_route(&dht, &state), None, "no route is published");

    tokio::time::sleep(REOPEN_RETRY_FIRST + Duration::from_secs(1)).await;
    assert!(
        holds(&relaunched, &lookup_key),
        "the scheduled reopen opens the channel"
    );
    assert_eq!(relaunched.calls().open_channel, 2);
    let route = published_route(&dht, &state).expect("the control subkey carries a route");
    assert!(
        board.lock().unwrap().routes.contains_key(&route),
        "the route is the one allocated at launch"
    );

    aw.send(RunnerCommand::Send {
        token: CommandToken(20),
        peer: a_peer,
        body: b"after the reopen".to_vec(),
    })
    .await;
    let at = aw.wait_for("the send", sent(20)).await;
    let slot = channel::slot_for(sent_seq(&aw.seen[at]));
    assert!(dht
        .lock()
        .unwrap()
        .records
        .contains_key(&(CHANNEL, lookup_key, slot)));

    {
        let mut net = dht.lock().unwrap();
        net.evict((CHANNEL, lookup_key, slot));
        net.evict((CHANNEL, lookup_key, channel::CONTROL_SUBKEY));
    }
    tokio::time::sleep(delivery::POLL_INTERVAL_MAX * 2).await;
    {
        let net = dht.lock().unwrap();
        assert!(
            net.records.contains_key(&(CHANNEL, lookup_key, slot)),
            "the repair rewrites the lost slot"
        );
        assert!(
            net.records
                .contains_key(&(CHANNEL, lookup_key, channel::CONTROL_SUBKEY)),
            "the repair rewrites the lost control subkey"
        );
    }
    assert_eq!(
        relaunched.calls().open_channel,
        2,
        "a held channel is not opened again"
    );
    assert!(finished(&aw.stop().await));
}

/// A channel whose reopen fails at launch, on a node with no push transport
/// and so no control rewrite at launch, is opened by a send made at once
/// before its slot write, without waiting for the schedule.
#[tokio::test(start_paused = true)]
async fn a_channel_whose_reopen_fails_at_launch_is_opened_before_it_is_written() {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    let relaunched = relaunch_owning(&a_fake, false);
    relaunched
        .faults()
        .plan
        .push((CHANNEL, Op::Open, Fault::TimedOut));
    let launched = Instant::now();
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    assert_eq!(relaunched.calls().open_channel, 1);
    assert!(!holds(&relaunched, &lookup_key), "the channel is not held");

    aw.send(RunnerCommand::Send {
        token: CommandToken(21),
        peer: a_peer,
        body: b"at once".to_vec(),
    })
    .await;
    let at = aw
        .wait_for("the send", |event| sent(21)(event) || refused(21)(event))
        .await;
    let slot = channel::slot_for(sent_seq(&aw.seen[at]));
    assert!(
        launched.elapsed() < REOPEN_RETRY_FIRST,
        "answered before the scheduled reopen"
    );
    assert_eq!(relaunched.calls().open_channel, 2);
    assert!(holds(&relaunched, &lookup_key), "the channel is held");
    assert!(dht
        .lock()
        .unwrap()
        .records
        .contains_key(&(CHANNEL, lookup_key, slot)));
    assert!(finished(&aw.stop().await));
}

/// A conversation whose channel failed to open at launch, and whose delete
/// then fails to open the record, stays marked, and the scheduled reopen does
/// not open its channel.
#[tokio::test(start_paused = true)]
async fn a_scheduled_reopen_skips_a_conversation_being_deleted() {
    let Scene {
        a,
        b,
        a_fake,
        aw,
        bw,
        a_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    let relaunched = relaunch_owning(&a_fake, true);
    // The launch's reopen fails, and so does the delete's open of the record.
    relaunched
        .faults()
        .plan
        .extend([(CHANNEL, Op::Open, Fault::TimedOut); 2]);
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    assert_eq!(
        relaunched.calls().open_channel,
        1,
        "the launch's reopen fails"
    );
    assert!(!holds(&relaunched, &lookup_key));

    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(22),
        peer: a_peer,
    })
    .await;
    let at = aw
        .wait_for("the delete's answer", |event| {
            refused(22)(event)
                || matches!(event, RunnerEvent::Deleted { token, .. } if token.0 == 22)
        })
        .await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    assert_eq!(
        pending_deletes(&a),
        vec![a_peer],
        "the conversation stays marked"
    );
    assert!(
        relaunched.calls().open_existing >= 1,
        "the delete opened the channel without creating it"
    );

    tokio::time::sleep(REOPEN_RETRY_FIRST * 8).await;
    assert_eq!(
        relaunched.calls().open_channel,
        1,
        "no scheduled reopen is made for a conversation being deleted"
    );

    // The schedule kept the channel for the teardown, so a delete asked for
    // again opens the record without creating it and writes the marker.
    relaunched.faults().fail_erase = false;
    let controls = relaunched.calls().control_writes;
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(23),
        peer: a_peer,
    })
    .await;
    let at = aw
        .wait_for("the second delete's answer", |event| {
            refused(23)(event)
                || matches!(event, RunnerEvent::Deleted { token, .. } if token.0 == 23)
        })
        .await;
    assert!(
        matches!(aw.seen[at], RunnerEvent::Deleted { .. }),
        "{:?}",
        aw.seen[at]
    );
    let calls = relaunched.calls();
    assert_eq!(calls.open_channel, 1, "nothing is created");
    assert_eq!(calls.control_writes, controls + 1, "the marker is written");
    assert!(finished(&aw.stop().await));
}

/// A relaunch admits message pushes from its established
/// correspondent and asks for a route while its channel reopen is still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relaunch_admits_pushes_and_asks_for_a_route_before_its_reopen() {
    let (k, _) = establish_pushed().await;
    assert!(finished(&k.bw.stop().await));
    assert!(finished(&k.aw.stop().await));
    let incoming = conv_of(&k.a, &k.a_peer).incoming_lookup_key;
    let attempts = k.board.lock().unwrap().route_attempts.len();

    let relaunched = k.a_fake.restart();
    let a_inbound = attach_push(&relaunched, &k.board);
    let held = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(Arc::clone(&held));
    relaunched.faults().gate_open_channel = Some(Arc::clone(&held));
    let aw = k.a.spawn(&relaunched, no_collection());
    held.reached().await;

    assert_eq!(
        k.board.lock().unwrap().route_attempts.len(),
        attempts + 1,
        "a route is asked for before the reopen"
    );
    let mut message = daemonseed_core::dm::push::PUSH_TAG.to_vec();
    message.push(1);
    message.extend_from_slice(&incoming);
    assert!(
        a_inbound.offer(PushInbound::Call {
            id: 9_998,
            message,
            received: std::time::Instant::now(),
        }),
        "a message push on the correspondent's channel is admitted"
    );
    assert_eq!(relaunched.calls().open_channel, 1, "the reopen is held");
    assert_eq!(
        relaunched.calls().control_writes,
        0,
        "no control subkey is written before the reopen"
    );
    held.release();
    assert!(finished(&aw.stop().await));
}

/// A relaunch of A after `establish`, holding channels as the record store
/// does, whose first `opens` channel opens fail: what the tests of a failed
/// reopen start from.
struct Unopened {
    dht: Arc<Mutex<Dht>>,
    a: Profile,
    a_peer: CorrespondenceLabel,
    relaunched: Fake,
    lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
}

async fn unopened(opens: usize, send_from_b: bool) -> Unopened {
    let Scene {
        dht,
        a,
        b,
        a_fake,
        aw,
        mut bw,
        a_peer,
        b_peer,
        ..
    } = establish(RunnerConfig::default()).await;
    if send_from_b {
        bw.send(RunnerCommand::Send {
            token: CommandToken(30),
            peer: b_peer,
            body: b"from B".to_vec(),
        })
        .await;
        bw.wait_for("B's send", sent(30)).await;
    }
    assert!(finished(&bw.stop().await));
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    let relaunched = relaunch_owning(&a_fake, false);
    relaunched.faults().plan.extend(std::iter::repeat_n(
        (CHANNEL, Op::Open, Fault::TimedOut),
        opens,
    ));
    Unopened {
        dht,
        a,
        a_peer,
        relaunched,
        lookup_key,
    }
}

/// A channel whose open keeps failing is opened by the schedule 30 seconds
/// after the launch's failure and twice as long after each further failure,
/// up to 10 minutes.
#[tokio::test(start_paused = true)]
async fn a_failed_reopen_is_retried_on_a_doubling_schedule_up_to_its_cap() {
    let u = unopened(20, false).await;
    let launched = Instant::now();
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    let mut seen = Vec::new();
    for (at, opens) in [
        (29, 1),
        (31, 2),
        (89, 2),
        (91, 3),
        (209, 3),
        (211, 4),
        (451, 5),
        (931, 6),
        (1529, 6),
        (1531, 7),
        (2129, 7),
        (2131, 8),
    ] {
        tokio::time::sleep_until(launched + Duration::from_secs(at)).await;
        seen.push((at, u.relaunched.calls().open_channel));
        assert_eq!(
            u.relaunched.calls().open_channel,
            opens,
            "opens by {at} s: {seen:?}"
        );
    }
    assert!(!holds(&u.relaunched, &u.lookup_key));
    assert!(finished(&aw.stop().await));
}

/// A cursor published while the channel's launch reopen has failed opens the
/// channel first, and is written before the scheduled reopen.
#[tokio::test(start_paused = true)]
async fn a_cursor_publish_opens_a_channel_whose_reopen_failed() {
    let u = unopened(1, true).await;
    u.relaunched.faults().channel_writes = Some(Vec::new());
    let before = conv_of(&u.a, &u.a_peer).cursor_published;
    let launched = Instant::now();
    let config = RunnerConfig {
        tick: Duration::from_secs(10),
        grace: DEFAULT_GRACE,
    };
    let mut aw = u.a.spawn(&u.relaunched, config);
    aw.wait_for("the relaunch", is_health).await;
    assert!(!holds(&u.relaunched, &u.lookup_key));
    while conv_of(&u.a, &u.a_peer).cursor_published <= before
        && launched.elapsed() < REOPEN_RETRY_FIRST * 4
    {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        conv_of(&u.a, &u.a_peer).cursor_published > before,
        "the cursor is published"
    );
    assert!(
        launched.elapsed() < REOPEN_RETRY_FIRST,
        "before the scheduled reopen: {:?}",
        launched.elapsed()
    );
    assert!(holds(&u.relaunched, &u.lookup_key));
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        control_writes_to(&u.relaunched, &u.lookup_key),
        1,
        "the publish that opened the channel owes no second control write"
    );
    assert!(finished(&aw.stop().await));
}

/// A first contact stopped before its channel writes, relaunched with its
/// channel's reopen failed, opens the channel before those writes and places
/// its hello during the launch.
#[tokio::test(start_paused = true)]
async fn a_first_contact_carried_on_opens_a_channel_whose_reopen_failed() {
    let dht = network();
    let (a, b) = (Profile::new(), Profile::new());
    let mut bw = b.spawn(&Fake::on(&dht), RunnerConfig::default());
    bw.wait_for("B's startup", is_health).await;
    let a_fake = Fake::on(&dht);
    let mut aw = a.spawn(&a_fake, RunnerConfig::default());
    aw.wait_for("A's startup", is_health).await;
    a_fake.fail_write(1);
    aw.send(RunnerCommand::FirstContact {
        token: CommandToken(1),
        peer_identity_pk: b.pk.clone(),
        body: b"hello".to_vec(),
    })
    .await;
    aw.wait_for("the refused first contact", refused(1)).await;
    assert!(finished(&aw.stop().await));
    let lookup_key = a.outgoing_lookup_key(&b);
    assert_ne!(lookup_key, [0u8; HELLO_LOOKUP_KEY_LEN]);

    let relaunched = relaunch_owning(&a_fake, false);
    relaunched
        .faults()
        .plan
        .push((CHANNEL, Op::Open, Fault::TimedOut));
    let mut aw = a.spawn(&relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    let calls = relaunched.calls();
    assert_eq!(
        calls.open_channel, 2,
        "the launch's reopen, then the flow's"
    );
    assert!(holds(&relaunched, &lookup_key));
    assert!(calls.hello_writes >= 1, "the hello is placed at launch");
    assert!(finished(&aw.stop().await));
    assert!(finished(&bw.stop().await));
}

/// A send that opens a channel whose reopen failed writes its slot before the
/// control subkey the reopen owes.
#[tokio::test(start_paused = true)]
async fn a_send_that_opens_a_channel_writes_its_slot_before_the_control() {
    let u = unopened(1, false).await;
    u.relaunched.faults().channel_writes = Some(Vec::new());
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    aw.send(RunnerCommand::Send {
        token: CommandToken(31),
        peer: u.a_peer,
        body: b"slot first".to_vec(),
    })
    .await;
    let at = aw.wait_for("the send", sent(31)).await;
    let slot = channel::slot_for(sent_seq(&aw.seen[at]));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let writes: Vec<u16> = u
        .relaunched
        .faults()
        .channel_writes
        .clone()
        .expect("writes are logged")
        .into_iter()
        .filter(|(key, _)| *key == u.lookup_key)
        .map(|(_, subkey)| subkey)
        .collect();
    assert_eq!(writes, vec![slot, channel::CONTROL_SUBKEY]);
    assert!(finished(&aw.stop().await));
}

/// While the network does not answer, sends to a channel whose reopen failed
/// open it once, and later sends inside the wait for the scheduled reopen fail
/// at once without opening it again.
#[tokio::test(start_paused = true)]
async fn sends_inside_the_reopen_wait_do_not_open_the_channel() {
    let u = unopened(10, false).await;
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    for (i, token) in [32u64, 33, 34].into_iter().enumerate() {
        aw.send(RunnerCommand::Send {
            token: CommandToken(token),
            peer: u.a_peer,
            body: b"offline".to_vec(),
        })
        .await;
        while u.relaunched.calls().ring_writes <= i {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let calls = u.relaunched.calls();
    assert_eq!(calls.ring_writes, 3, "each send reaches its slot write");
    assert_eq!(
        calls.open_channel, 2,
        "the launch's reopen and the first send's, and no more"
    );
    assert!(finished(&aw.stop().await));
}

/// A delete whose channel failed to open at launch, and whose record the
/// network then reports absent, stops short and stays marked: nothing is
/// created, marked or erased.
#[tokio::test(start_paused = true)]
async fn a_delete_of_an_unopened_channel_not_found_stays_marked() {
    let u = unopened(1, false).await;
    let lookup_key = u.lookup_key;
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    u.dht
        .lock()
        .unwrap()
        .records
        .retain(|(kind, name, _), _| !(*kind == CHANNEL && *name == lookup_key));
    u.relaunched
        .node
        .lock()
        .unwrap()
        .local
        .retain(|(kind, name, _), _| !(*kind == CHANNEL && *name == lookup_key));
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(35),
        peer: u.a_peer,
    })
    .await;
    let at = aw
        .wait_for("the delete's answer", |event| {
            refused(35)(event)
                || matches!(event, RunnerEvent::Deleted { token, .. } if token.0 == 35)
        })
        .await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    assert_eq!(pending_deletes(&u.a), vec![u.a_peer]);
    let calls = u.relaunched.calls();
    assert_eq!(
        (
            calls.open_channel,
            calls.open_existing,
            calls.control_writes,
            calls.erases
        ),
        (1, 1, 0, 0),
        "only the launch's reopen and the delete's open are made"
    );
    assert!(finished(&aw.stop().await));
}

/// How many control subkey writes `fake` logged to the channel at
/// `lookup_key`, refused or not.
fn control_writes_to(fake: &Fake, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> usize {
    fake.faults()
        .channel_writes
        .as_ref()
        .expect("writes are logged")
        .iter()
        .filter(|(key, subkey)| key == lookup_key && *subkey == channel::CONTROL_SUBKEY)
        .count()
}

/// A record store adapter over `fake`, as the runner holds one.
fn tracked(fake: &Fake) -> Tracked<Fake> {
    Tracked {
        inner: fake.clone(),
        health: HealthCounters::default(),
        failed_drop_reads: 0,
        traced: None,
        reopen_pending: HashMap::new(),
        control_owed: HashMap::new(),
        stop: Arc::new(AtomicBool::new(false)),
    }
}

/// An adapter over a fresh fake holding one pending channel, with its lookup
/// key and the profile whose channel it is.
fn tracked_pending() -> (Fake, Tracked<Fake>, [u8; HELLO_LOOKUP_KEY_LEN], Profile) {
    let (a, b) = (Profile::new(), Profile::new());
    let fake = Fake::on(&network());
    let mut records = tracked(&fake);
    let owner =
        channel::derive_owner_seed(&a.keys().dm_channel_root, &b.pk, flows::FIRST_GENERATION)
            .expect("the channel owner seed");
    let lookup_key = Fake::lookup_key(&owner);
    records.hold_unopened(
        lookup_key,
        owner,
        CorrespondenceLabel::mint().expect("a label"),
    );
    (fake, records, lookup_key, a)
}

/// While the runner stops, a write opens no pending channel and no owed
/// control rewrite is due; once it runs, both happen.
#[tokio::test(start_paused = true)]
async fn a_stopping_adapter_opens_nothing_and_owes_no_rewrite() {
    let (fake, mut records, lookup_key, _) = tracked_pending();
    records.control_owed.insert(
        [7; HELLO_LOOKUP_KEY_LEN],
        OwedControl {
            peer: CorrespondenceLabel::mint().expect("a label"),
            due: Instant::now(),
            wait: REOPEN_RETRY_FIRST,
        },
    );
    records.stop.store(true, Ordering::Relaxed);
    let _ = records.write_channel(&lookup_key, channel::slot_for(1), b"slot");
    assert_eq!(fake.calls().open_channel, 0, "no open while stopping");
    assert!(records.owed_due().is_empty(), "no rewrite while stopping");

    records.stop.store(false, Ordering::Relaxed);
    assert_eq!(records.owed_due().len(), 1);
    let _ = records.write_channel(&lookup_key, channel::slot_for(1), b"slot");
    assert_eq!(fake.calls().open_channel, 1);
}

/// A write exactly at the end of the wait after a failed open opens the
/// channel; one a moment before does not.
#[tokio::test(start_paused = true)]
async fn a_write_at_the_end_of_the_reopen_wait_opens_the_channel() {
    let (fake, mut records, lookup_key, _) = tracked_pending();
    fake.faults()
        .plan
        .push((CHANNEL, Op::Open, Fault::TimedOut));
    let _ = records.write_channel(&lookup_key, channel::slot_for(1), b"slot");
    assert_eq!(
        fake.calls().open_channel,
        1,
        "the first write opens, and fails"
    );
    let until = records.reopen_pending[&lookup_key].inline_after;
    assert!(until > Instant::now());
    tokio::time::advance(until - Instant::now() - Duration::from_millis(1)).await;
    let _ = records.write_channel(&lookup_key, channel::slot_for(1), b"slot");
    assert_eq!(fake.calls().open_channel, 1, "not inside the wait");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(Instant::now(), until);
    let _ = records.write_channel(&lookup_key, channel::slot_for(1), b"slot");
    assert_eq!(fake.calls().open_channel, 2, "at its end");
    assert!(!records.reopen_pending.contains_key(&lookup_key));
}

/// A batch whose pending channel write follows another write opens the
/// channel once.
#[tokio::test(start_paused = true)]
async fn a_batch_opens_a_pending_channel_after_its_first_write() {
    let (fake, mut records, lookup_key, a) = tracked_pending();
    let drop_owner = drop_plane::derive_owner_seed(&a.pk).expect("the drop owner seed");
    let results = records.write_batch(&[
        BatchWrite::EraseDropSlot {
            owner: &drop_owner,
            subkeys: drop_plane::DROP_SUBKEYS,
            slot: 0,
        },
        BatchWrite::Channel {
            lookup_key: &lookup_key,
            subkey: channel::slot_for(1),
            bytes: b"slot",
        },
    ]);
    assert_eq!(results.len(), 2);
    assert_eq!(fake.calls().open_channel, 1);
    assert!(!records.reopen_pending.contains_key(&lookup_key));
}

/// An owed control rewrite that fails is tried again on the schedule.
#[tokio::test(start_paused = true)]
async fn a_failed_owed_control_rewrite_is_tried_again() {
    let u = unopened(1, false).await;
    u.relaunched.faults().channel_writes = Some(Vec::new());
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    // The send's slot write goes through; the owed control write after it is
    // refused.
    u.relaunched.fail_write(2);
    aw.send(RunnerCommand::Send {
        token: CommandToken(36),
        peer: u.a_peer,
        body: b"owed".to_vec(),
    })
    .await;
    aw.wait_for("the send", sent(36)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(control_writes_to(&u.relaunched, &u.lookup_key), 1);
    tokio::time::sleep(REOPEN_RETRY_FIRST + Duration::from_secs(2)).await;
    assert_eq!(
        control_writes_to(&u.relaunched, &u.lookup_key),
        2,
        "the refused rewrite is tried again"
    );
    assert!(finished(&aw.stop().await));
}

/// An owed control rewrite is not made over a conversation whose delete is
/// under way after its marker write failed.
#[tokio::test(start_paused = true)]
async fn an_owed_control_is_not_written_over_a_delete_under_way() {
    let u = unopened(1, false).await;
    u.relaunched.faults().channel_writes = Some(Vec::new());
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    u.relaunched.fail_write(2);
    aw.send(RunnerCommand::Send {
        token: CommandToken(37),
        peer: u.a_peer,
        body: b"owed".to_vec(),
    })
    .await;
    aw.wait_for("the send", sent(37)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        control_writes_to(&u.relaunched, &u.lookup_key),
        1,
        "the owed rewrite failed"
    );
    u.relaunched.fail_write(1);
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(38),
        peer: u.a_peer,
    })
    .await;
    let at = aw.wait_for("the delete's answer", refused(38)).await;
    assert_eq!(refusal(&aw.seen[at]), Refusal::Network);
    assert_eq!(pending_deletes(&u.a), vec![u.a_peer]);
    let controls = control_writes_to(&u.relaunched, &u.lookup_key);
    assert_eq!(controls, 2, "the refused marker");
    tokio::time::sleep(REOPEN_RETRY_FIRST * 3).await;
    assert_eq!(
        control_writes_to(&u.relaunched, &u.lookup_key),
        controls,
        "no control is written over the delete"
    );
    assert!(finished(&aw.stop().await));
}

/// A delete of a conversation whose channel failed to open at launch opens
/// the record without creating it and finishes.
#[tokio::test(start_paused = true)]
async fn a_delete_of_an_unopened_channel_is_finished() {
    let u = unopened(1, false).await;
    let mut aw = u.a.spawn(&u.relaunched, RunnerConfig::default());
    aw.wait_for("the relaunch", is_health).await;
    aw.send(RunnerCommand::DeleteConversation {
        token: CommandToken(39),
        peer: u.a_peer,
    })
    .await;
    let at = aw
        .wait_for("the delete's answer", |event| {
            refused(39)(event)
                || matches!(event, RunnerEvent::Deleted { token, .. } if token.0 == 39)
        })
        .await;
    assert!(
        matches!(aw.seen[at], RunnerEvent::Deleted { .. }),
        "{:?}",
        aw.seen[at]
    );
    let calls = u.relaunched.calls();
    assert_eq!((calls.open_channel, calls.open_existing), (1, 1));
    assert!(finished(&aw.stop().await));
}
