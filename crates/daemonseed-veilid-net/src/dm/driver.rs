//! The DM driver's thin async shell.
//!
//! The shell owns the awaits and nothing else: it reads the injected clock, hands
//! the value to the machine, spawns whatever DHT operations the machine asked
//! for off its own loop into a [`JoinSet`], and forwards the machine's events to
//! the front end. Every decision belongs to the machine, so the shell has nothing
//! in it a test would want to reach past.

use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;

use daemonseed_core::dm::admission::AdmissionPolicy;
use daemonseed_core::dm::keyrec::DM_KEYREC_OWNER_SEED_LEN;
use daemonseed_core::dm::persist::DmPersist;
use daemonseed_core::dm::pow::PowDifficulty;
use daemonseed_core::dm::spent_store;
use daemonseed_core::dm::token::SpentTokenSet;
use daemonseed_core::profile::config::ArgonParams;

use crate::dm::machine::{
    ComputeJob, DhtOp, DhtOutcome, DhtResult, DmEffect, DmMachine, DmOutcome, PanickedJob,
    SpentTokens,
};
use crate::dm::seam::DmDht;
use crate::dm::types::{DmCommand, DmEvent, DmIdentity, WallClock};
use crate::{Result, VeilidNetError};

/// Commands the front end may have outstanding before the driver drains them.
const COMMAND_QUEUE: usize = 64;

/// Events the driver may have outstanding before the front end drains them.
const EVENT_QUEUE: usize = 256;

/// The driver's cadence and admission knobs.
///
/// Items 3-4 add acknowledgement and give-up knobs alongside these.
#[derive(Clone, Debug)]
pub struct DmDriverConfig {
    /// How long the driver sleeps when nothing else wakes it, and how often the
    /// doorbell is swept. Must be non-zero.
    pub idle_tick: Duration,
    /// The live first-contact policy this identity enforces.
    ///
    /// The key record's `invite_only` field is what a sender reads; this is
    /// what the recipient enforces, and they may disagree.
    /// [`AdmissionPolicy::InviteOnly`] requires
    /// [`DmDriverParts::spent_tokens`], because a consumed invite nonce that
    /// does not survive a restart is a one-time grant that can be spent twice.
    pub policy: AdmissionPolicy,
    /// The proof-of-work difficulty knocks are verified and minted at.
    ///
    /// A parameter rather than a constant so an oracle can lower it: a mint at
    /// [`PowDifficulty::PRODUCTION`] takes seconds, which no test can afford
    /// per entry.
    pub pow_difficulty: PowDifficulty,
    /// Whether the machine arms receiving-page watches at all (#234).
    ///
    /// **A baseline, not a feature.** A watch changes only *when* a page is read, so
    /// a driver that arms none must reach exactly the same state as one whose
    /// watches are lost or refused — same messages, same cadence, same records
    /// opened and closed. Asserting that needs a run with no watch in it, and that
    /// run cannot be produced from the seam: a transport that answers `Lost` has
    /// still been asked, and being asked is the one difference the comparison must
    /// allow for.
    ///
    /// Test-only, so the shipped configuration has no way to turn watching off.
    #[cfg(test)]
    pub(crate) arm_page_watches: bool,
}

/// Where the profile's consumed invite-token nonces are kept across restarts.
///
/// **Absent means the set lives only in memory, and that is correct only under
/// [`AdmissionPolicy::Open`]**, where the token field is never decoded, never
/// verified and never consumed — so there is no nonce to lose. Under
/// [`AdmissionPolicy::InviteOnly`] a set that does not survive a restart lets
/// every already-spent invite be replayed, so the driver refuses that pairing
/// at construction rather than running with a suppression plane that forgets.
///
/// The file is its own sealed record beside the trust log, keyed by the
/// two-stage KDF over the profile passphrase — independent of the DM store's
/// at-rest key, which is why the passphrase is named here rather than derived
/// from anything the driver already holds.
#[derive(Clone)]
pub struct SpentTokenStore {
    /// The profile root the file sits at, per
    /// [`spent_store::spent_tokens_path`].
    pub profile_root: PathBuf,
    /// The profile passphrase, which the file's key derives from.
    pub passphrase: zeroize::Zeroizing<String>,
    /// The profile id, salted into that derivation and written in the header.
    pub profile_id: uuid::Uuid,
    /// The Argon2id parameters to seal under.
    pub argon2: ArgonParams,
}

impl core::fmt::Debug for SpentTokenStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The passphrase opens the profile; not even its length is shown.
        f.debug_struct("SpentTokenStore")
            .field("profile_root", &self.profile_root)
            .field("profile_id", &self.profile_id)
            .finish_non_exhaustive()
    }
}

impl SpentTokenStore {
    /// Read the stored set.
    ///
    /// **A file that is present and will not open POISONS the store**, rather
    /// than reading as an empty set. The two are not close: an empty set with
    /// a later write behind it silently erases every grant the unreadable file
    /// held, so the first spend after a corrupt read would overwrite the
    /// suppression plane with nothing in it. An absent file is different and is
    /// the ordinary state of a profile that has never redeemed an invite —
    /// [`spent_store::read_from`] separates the two, which is why it is used
    /// rather than a bare read.
    ///
    /// Run once, before the driver task starts: the open derives an Argon2id
    /// key.
    pub(crate) fn load(&self) -> std::result::Result<SpentTokenSet, String> {
        match spent_store::read_from(
            &spent_store::spent_tokens_path(&self.profile_root),
            &self.passphrase,
        ) {
            Ok(Some(set)) => Ok(set),
            Ok(None) => Ok(SpentTokenSet::new()),
            Err(e) => Err(format!("{e}")),
        }
    }

    /// Seal the set back over the file, durably.
    ///
    /// Called only when a nonce was actually consumed or pruned — under
    /// [`AdmissionPolicy::Open`] that is never — and always on a blocking
    /// thread, because the seal derives an Argon2id key.
    ///
    /// [`spent_store::write_to`] replaces atomically: a suppression plane
    /// truncated by a partial write is a set of grants that can be spent twice,
    /// which is the one outcome that must not be reachable.
    pub(crate) fn save(&self, set: &SpentTokenSet) -> std::result::Result<(), String> {
        spent_store::write_to(
            &spent_store::spent_tokens_path(&self.profile_root),
            set,
            &self.passphrase,
            self.profile_id,
            self.argon2,
        )
        .map_err(|e| format!("{e}"))
    }
}

/// Everything the driver owns, constructed by the front end and moved in.
///
/// The front end holds each half already — the profile root and at-rest key for
/// [`DmPersist`], and the identity keys for [`DmIdentity`] — so the driver never
/// derives a secret of its own.
pub struct DmDriverParts<D: DmDht> {
    /// The DHT seam. Production is `VeilidNetHandle`.
    pub dht: Arc<D>,
    /// Unix milliseconds, injected.
    pub clock: WallClock,
    /// The identity halves the driver needs.
    pub identity: DmIdentity,
    /// The profile's DM records.
    pub persist: DmPersist,
    /// The cadence and admission knobs.
    pub cfg: DmDriverConfig,
    /// Where consumed invite-token nonces are kept, when they are kept.
    pub spent_tokens: Option<SpentTokenStore>,
}

/// A cloneable handle onto a running driver.
///
/// Dropping the last one ends the driver, as with
/// [`crate::schedule::WriteSchedulerHandle`].
#[derive(Clone, Debug)]
pub struct DmDriverHandle {
    cmd_tx: mpsc::Sender<DmCommand>,
}

impl DmDriverHandle {
    /// Queue one command for the driver.
    ///
    /// Fails only once the driver has stopped; a full queue applies backpressure
    /// to the caller rather than dropping the command.
    pub async fn send(&self, cmd: DmCommand) -> Result<()> {
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| VeilidNetError::Actor("dm driver stopped".into()))
    }

    /// Queue one command without ever waiting.
    ///
    /// For a caller that must not block: [`Self::send`] applies backpressure to
    /// its caller, which is right for a UI thread and wrong for a shared actor
    /// loop, where a driver busy enough to fill its queue would stall chat,
    /// shares and presence along with the DM command. The command is DROPPED on
    /// [`DmTrySendError::Full`] rather than retried — a re-send would have to be
    /// held somewhere, and the only place is the loop this call exists to keep
    /// free.
    pub fn try_send(&self, cmd: DmCommand) -> core::result::Result<(), DmTrySendError> {
        self.cmd_tx.try_send(cmd).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => DmTrySendError::Full,
            mpsc::error::TrySendError::Closed(_) => DmTrySendError::Stopped,
        })
    }
}

/// Why [`DmDriverHandle::try_send`] did not queue a command.
///
/// The command is gone in both cases; they differ in what the caller should do
/// about the HANDLE, which is nothing for `Full` and drop-it for `Stopped`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmTrySendError {
    /// The driver's queue is full. It is still running.
    Full,
    /// The driver has stopped; this handle reaches nothing.
    Stopped,
}

impl core::fmt::Display for DmTrySendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => f.write_str("the dm driver's command queue is full"),
            Self::Stopped => f.write_str("the dm driver has stopped"),
        }
    }
}

impl std::error::Error for DmTrySendError {}

/// Counters the shell bumps so an oracle can prove the loop ran.
///
/// Without `ticks` an idle-driver test cannot distinguish "the loop woke three
/// times and did nothing" from "the loop never started", and those look identical
/// in every other observable. Each of the others exists for the same reason: an
/// unobserved branch of the shell is a branch no oracle can pin.
pub(crate) struct DmDriverProbe {
    /// Idle cadence wakeups.
    pub ticks: AtomicU64,
    /// The wall time the machine recorded for the last tick.
    pub last_tick_ms: AtomicI64,
    /// The wall time the loop last read to compute a deadline with.
    pub last_due_input_ms: AtomicI64,
    /// DHT operations spawned.
    pub ops_started: AtomicU64,
    /// DHT operations joined.
    pub ops_completed: AtomicU64,
    /// DHT operations whose task panicked.
    pub ops_panicked: AtomicU64,
    /// Blocking compute jobs spawned.
    pub computes_started: AtomicU64,
    /// The sequence number the single live correspondence's next channel send
    /// would take, or `u64::MAX` when there is not exactly one.
    ///
    /// The one observable that can see a ratchet step. A refused send that
    /// stepped anyway writes nothing, emits nothing and changes no record, so
    /// without this the claim that nothing was spent cannot be tested at all.
    pub next_send_seq: AtomicU64,
    /// The probe frontier of the single correspondence recovered from disk at
    /// construction, or `u64::MAX` when there is not exactly one or it reached
    /// no page.
    pub resumed_frontier: AtomicU64,
    /// Loop iterations whose machine step has been APPLIED.
    ///
    /// The one counter an oracle may wait on. `ops_completed` counts a join,
    /// which happens strictly before the step it produced runs and before its
    /// effects are dispatched — so a test that waits on it and then reads the
    /// mock's log is racing the driver by exactly one step.
    pub steps_applied: AtomicU64,
}

impl DmDriverProbe {
    pub(crate) fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            last_tick_ms: AtomicI64::new(0),
            last_due_input_ms: AtomicI64::new(0),
            ops_started: AtomicU64::new(0),
            ops_completed: AtomicU64::new(0),
            ops_panicked: AtomicU64::new(0),
            computes_started: AtomicU64::new(0),
            next_send_seq: AtomicU64::new(u64::MAX),
            resumed_frontier: AtomicU64::new(u64::MAX),
            steps_applied: AtomicU64::new(0),
        }
    }
}

/// The DM driver.
pub struct DmDriver;

impl DmDriver {
    /// Spawn the driver and return the handle plus the event stream, panicking on
    /// any startup condition [`Self::try_spawn`] would report.
    ///
    /// For a caller that must survive a bad profile — a front-end net actor, whose
    /// other work is unrelated to DM — use [`Self::try_spawn`] instead. This one is
    /// for tests and for callers whose whole purpose is the driver.
    ///
    /// # Panics
    ///
    /// If `cfg.idle_tick` is zero. A zero cadence is not a fast driver but a hot
    /// loop, and it is a construction-time mistake rather than a runtime state.
    ///
    /// If `cfg.policy` is [`AdmissionPolicy::InviteOnly`] and
    /// `parts.spent_tokens` is `None`. A one-time grant whose consumed nonce
    /// does not outlive the process is not one-time, and that is a wiring
    /// mistake rather than a state the driver could recover from.
    ///
    /// If this identity's own doorbell or key-record owner seed will not
    /// derive. Both are pure functions of the identity's public key, so a
    /// failure is a crypto-module condition and not a state — and a driver
    /// carrying on without them is permanently deaf, sweeping nothing and
    /// verifying nothing, with no error anywhere saying so.
    ///
    /// If the profile's block list could not be provisioned. Every consult and
    /// every change refuses an absent record, so a driver that started anyway
    /// could neither honour a block nor record one.
    pub fn spawn<D: DmDht>(parts: DmDriverParts<D>) -> (DmDriverHandle, mpsc::Receiver<DmEvent>) {
        let (handle, events, _task) = Self::spawn_with_probe(parts, Arc::new(DmDriverProbe::new()));
        (handle, events)
    }

    /// Spawn the driver, reporting the startup conditions [`Self::spawn`] panics on.
    ///
    /// The three fallible steps all run on the CALLER's thread before the task
    /// exists — two owner-seed derivations and the block-list provision — and the
    /// last of them touches the disk. A profile directory that is read-only, full,
    /// or holding an unreadable store therefore fails here, and a caller doing
    /// other work must not die of it: a front-end net actor serves chat, shares
    /// and presence, none of which need a DM driver.
    ///
    /// # Panics
    ///
    /// On the two *wiring* mistakes [`Self::spawn`] documents — a zero
    /// `cfg.idle_tick`, and [`AdmissionPolicy::InviteOnly`] with no
    /// `parts.spent_tokens`. Neither is a state a caller could recover from by
    /// handling an error, and both are decided by the code that built `parts`.
    pub fn try_spawn<D: DmDht>(
        parts: DmDriverParts<D>,
    ) -> core::result::Result<(DmDriverHandle, mpsc::Receiver<DmEvent>), DmSpawnError> {
        let (handle, events, _task) =
            Self::try_spawn_seeded(parts, Arc::new(DmDriverProbe::new()), Vec::new())?;
        Ok((handle, events))
    }

    /// Spawn the driver against a caller-held probe, returning the task as well.
    pub(crate) fn spawn_with_probe<D: DmDht>(
        parts: DmDriverParts<D>,
        probe: Arc<DmDriverProbe>,
    ) -> (
        DmDriverHandle,
        mpsc::Receiver<DmEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        Self::spawn_seeded(parts, probe, Vec::new())
    }

    /// Spawn the driver with `seed` applied before the first loop iteration.
    ///
    /// The seam over any effect the machine cannot itself produce at
    /// construction: the shell does the one-off work here — deriving the owner
    /// seeds, provisioning the block list, opening the spent-token set — and
    /// whatever the user must be told about it rides out as a seeded event,
    /// because a constructor returns state and not effects. Production seeds
    /// nothing of its own.
    pub(crate) fn spawn_seeded<D: DmDht>(
        parts: DmDriverParts<D>,
        probe: Arc<DmDriverProbe>,
        seed: Vec<DmEffect>,
    ) -> (
        DmDriverHandle,
        mpsc::Receiver<DmEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        Self::try_spawn_seeded(parts, probe, seed).expect("the driver must start")
    }

    /// [`Self::spawn_seeded`], reporting rather than panicking on the three
    /// fallible startup steps. The one place they are performed.
    pub(crate) fn try_spawn_seeded<D: DmDht>(
        parts: DmDriverParts<D>,
        probe: Arc<DmDriverProbe>,
        seed: Vec<DmEffect>,
    ) -> core::result::Result<
        (
            DmDriverHandle,
            mpsc::Receiver<DmEvent>,
            tokio::task::JoinHandle<()>,
        ),
        DmSpawnError,
    > {
        assert!(
            !parts.cfg.idle_tick.is_zero(),
            "DmDriverConfig::idle_tick must be non-zero"
        );
        assert!(
            parts.cfg.policy != AdmissionPolicy::InviteOnly || parts.spent_tokens.is_some(),
            "an invite-only policy needs DmDriverParts::spent_tokens"
        );

        // Every line below runs on the CALLER's thread, before the task exists.
        // Each is one-off and each is expensive or fallible in a way the loop
        // must not carry: two KDF derivations, a store write, and an Argon2id
        // key derivation.
        let public = parts.identity.signing.public_key();
        let doorbell_owner = *daemonseed_core::dm::doorbell::derive_owner_seed(public)
            .map_err(DmSpawnError::DoorbellOwnerSeed)?
            .as_bytes();
        let keyrec_addr = *daemonseed_core::dm::keyrec::derive_owner_seed(public)
            .map_err(DmSpawnError::KeyRecordOwnerSeed)?
            .as_bytes();

        let mut startup = seed;
        let provisioned = parts
            .persist
            .provision_block_list()
            .map_err(DmSpawnError::BlockList)?;
        if provisioned {
            // Loud: the store creates this record at every open, so having had
            // to write it means either that creation was skipped in its
            // documented race window or the record was removed.
            startup.push(DmEffect::Emit(DmEvent::BlockListProvisioned));
        }

        let spent = match parts.spent_tokens.as_ref() {
            None => SpentTokens {
                set: SpentTokenSet::new(),
                store: None,
                poisoned: false,
            },
            Some(store) => match store.load() {
                Ok(set) => SpentTokens {
                    set,
                    store: Some(store.clone()),
                    poisoned: false,
                },
                Err(e) => {
                    crate::vtrace!("dm driver: spent-token set would not open: {e}");
                    startup.push(DmEffect::Emit(DmEvent::SpentTokensNotPersisted));
                    SpentTokens {
                        set: SpentTokenSet::new(),
                        store: Some(store.clone()),
                        poisoned: true,
                    }
                }
            },
        };

        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
        let (evt_tx, evt_rx) = mpsc::channel(EVENT_QUEUE);
        let task = tokio::spawn(run(
            parts,
            cmd_rx,
            evt_tx,
            probe,
            startup,
            Prepared {
                doorbell_owner,
                keyrec_addr,
                spent,
            },
        ));
        Ok((DmDriverHandle { cmd_tx }, evt_rx, task))
    }
}

/// Why a driver did not start.
///
/// Every variant is a condition of THIS machine — its crypto module or its
/// profile directory — never of a peer or the network, and none is transient in
/// a way a retry on the next tick would clear. A caller that has other work
/// carries on without a driver; a caller that is only the driver panics
/// ([`DmDriver::spawn`]).
#[derive(Debug)]
pub enum DmSpawnError {
    /// This identity's doorbell owner seed would not derive, so the driver could
    /// not sweep its own doorbell and would be permanently deaf.
    DoorbellOwnerSeed(daemonseed_core::dm::doorbell::DmDoorbellError),
    /// This identity's key-record owner seed would not derive, so no knock could
    /// be addressed and no key record found.
    KeyRecordOwnerSeed(daemonseed_core::dm::keyrec::DmKeyRecordError),
    /// The profile's block list could not be provisioned. Every consult and every
    /// change refuses an absent record, so a driver started anyway could neither
    /// honour a block nor record one.
    BlockList(daemonseed_core::dm::persist::DmPersistError),
}

impl core::fmt::Display for DmSpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DoorbellOwnerSeed(e) => write!(f, "doorbell owner seed would not derive: {e}"),
            Self::KeyRecordOwnerSeed(e) => {
                write!(f, "key-record owner seed would not derive: {e}")
            }
            Self::BlockList(e) => write!(f, "block list would not provision: {e}"),
        }
    }
}

impl std::error::Error for DmSpawnError {}

/// What the shell worked out before the driver task started.
struct Prepared {
    doorbell_owner: [u8; 32],
    keyrec_addr: [u8; DM_KEYREC_OWNER_SEED_LEN],
    spent: SpentTokens,
}

/// What woke the loop. Named so the clock is re-read *after* the await rather
/// than before it: a value read before a 30-second sleep is 30 seconds stale by
/// the time a step function sees it.
enum Woke {
    Command(DmCommand),
    Outcome(DmOutcome),
    Tick,
    /// A spawned operation's task panicked. Distinct from `Tick`, because a panic
    /// in the seam is not a cadence event: counting it as one would inflate the
    /// tick count and run the machine's idle step at a moment nothing was due.
    ///
    /// It carries what the dead task was doing. Without that the panic is a
    /// no-op, and a no-op is wrong for every job this driver spawns: a dead
    /// mint or DHT task leaves its recipient recorded as in flight for ever,
    /// and a dead spent-token write leaves the file behind the set in memory.
    Panicked(Option<PanickedJob>),
    Stop,
}

async fn run<D: DmDht>(
    parts: DmDriverParts<D>,
    mut cmd_rx: mpsc::Receiver<DmCommand>,
    evt_tx: mpsc::Sender<DmEvent>,
    probe: Arc<DmDriverProbe>,
    seed: Vec<DmEffect>,
    prepared: Prepared,
) {
    let DmDriverParts {
        dht,
        clock,
        identity,
        persist,
        cfg,
        spent_tokens: _,
    } = parts;
    let Prepared {
        doorbell_owner,
        keyrec_addr,
        spent,
    } = prepared;
    let started_ms = clock.now_ms();
    let mut machine = DmMachine::new(identity, persist, cfg, doorbell_owner, keyrec_addr, spent);
    // Read once, here: what the store seeded is a property of construction, and
    // a value re-read later would be a property of whatever has happened since.
    probe.resumed_frontier.store(
        machine.only_resumed_frontier().unwrap_or(u64::MAX),
        Ordering::SeqCst,
    );
    let mut inflight: JoinSet<DmOutcome> = JoinSet::new();
    // What each in-flight task is doing, for the one thing a `JoinError` can be
    // asked: which task died. A `JoinSet` hands back the task's id on both the
    // success and the panic path, so the map is the only route from a dead task
    // to the state it was holding.
    let mut jobs: std::collections::HashMap<tokio::task::Id, PanickedJob> =
        std::collections::HashMap::new();

    // The roster goes out last of the startup effects and before the first
    // wakeup, so a front end has the store's own list of correspondences before
    // anything can report a change to one.
    let mut startup = seed;
    startup.extend(machine.roster());
    if !apply(startup, &dht, &mut inflight, &mut jobs, &evt_tx, &probe).await {
        return;
    }

    loop {
        let now = clock.now_ms();
        probe.last_due_input_ms.store(now, Ordering::SeqCst);
        // The deadline is anchored on the LAST TICK, never on this wakeup. A
        // deadline recomputed from the wake time restarts the idle timer on every
        // command and every completed operation, so a busy driver never reaches
        // its cadence at all — and nothing about it looks wrong.
        let anchor = machine.last_tick_ms().unwrap_or(started_ms);
        // At least one millisecond: a due time already in the past would
        // otherwise spin the loop at the speed of the scheduler.
        let wait = machine.next_due_ms(anchor).saturating_sub(now).max(1);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait as u64);

        let woke = tokio::select! {
            biased;
            cmd = cmd_rx.recv() => match cmd {
                None | Some(DmCommand::Shutdown) => Woke::Stop,
                Some(c) => Woke::Command(c),
            },
            Some(joined) = inflight.join_next_with_id(), if !inflight.is_empty() => {
                probe.ops_completed.fetch_add(1, Ordering::SeqCst);
                match joined {
                    Ok((id, outcome)) => {
                        jobs.remove(&id);
                        Woke::Outcome(outcome)
                    }
                    // A spawned task cannot return an error of its own — every
                    // failure travels inside `DhtOutcome::result` or
                    // `MintOutcome::result` — so a join error is a panic in the
                    // seam. The driver survives it, records it, and releases
                    // whatever introduction the dead task was holding.
                    Err(e) => Woke::Panicked(jobs.remove(&e.id())),
                }
            }
            _ = tokio::time::sleep_until(deadline) => Woke::Tick,
        };

        // Read again on the far side of the await: this is the value every step
        // function sees, and the one an oracle advances.
        let now = clock.now_ms();
        let effects = match woke {
            Woke::Stop => break,
            Woke::Command(cmd) => machine.on_command(now, cmd),
            Woke::Outcome(outcome) => machine.on_outcome(now, outcome),
            Woke::Panicked(job) => {
                probe.ops_panicked.fetch_add(1, Ordering::SeqCst);
                machine.on_outcome(now, DmOutcome::Panicked { job })
            }
            Woke::Tick => {
                let effects = machine.on_tick(now);
                probe.ticks.fetch_add(1, Ordering::SeqCst);
                probe
                    .last_tick_ms
                    .store(machine.last_tick_ms().unwrap_or(0), Ordering::SeqCst);
                effects
            }
        };

        if !apply(effects, &dht, &mut inflight, &mut jobs, &evt_tx, &probe).await {
            return;
        }
        probe.next_send_seq.store(
            machine.only_next_send_seq().unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
        // Bumped LAST, after every effect of this step has been dispatched, so
        // an oracle that waits on it and then reads the mock is reading a
        // settled state rather than racing the dispatch.
        probe.steps_applied.fetch_add(1, Ordering::SeqCst);
    }
    // Dropping `evt_tx` here is what makes the receiver see `None`; it is the
    // front end's only signal that the driver is gone. `inflight` drops with it,
    // which ABORTS whatever was still in flight — see `DmCommand::Shutdown`.
}

/// Spawn each requested operation off the loop and forward each event.
///
/// Returns `false` once the front end has dropped its receiver, which is the
/// driver's signal to stop.
async fn apply<D: DmDht>(
    effects: Vec<DmEffect>,
    dht: &Arc<D>,
    inflight: &mut JoinSet<DmOutcome>,
    jobs: &mut std::collections::HashMap<tokio::task::Id, PanickedJob>,
    evt_tx: &mpsc::Sender<DmEvent>,
    probe: &DmDriverProbe,
) -> bool {
    for effect in effects {
        match effect {
            DmEffect::Dht(op) => {
                probe.ops_started.fetch_add(1, Ordering::SeqCst);
                // Read before the op moves into the task, and recorded for every
                // job that leaves state behind rather than for introductions
                // alone: a sweep the machine is holding open is released by its
                // outcome, and a panic produces no outcome.
                let job = op.panicked_job();
                let dht = dht.clone();
                let handle = inflight.spawn(async move { DmOutcome::Dht(dispatch(dht, op).await) });
                if let Some(job) = job {
                    jobs.insert(handle.id(), job);
                }
            }
            // `spawn_blocking`, never `spawn`: the proof of work inside a mint
            // holds its thread for seconds at production difficulty, and the
            // spent-token seal derives an Argon2id key. On the async pool
            // either is the driver's own loop, plus every other task on the
            // runtime, stopped for the duration.
            DmEffect::Compute(ComputeJob::MintFirstContact(request)) => {
                probe.computes_started.fetch_add(1, Ordering::SeqCst);
                let introduction = Box::new(*request.recipient);
                let handle = inflight.spawn_blocking(move || {
                    DmOutcome::Mint(Box::new(crate::dm::machine::run_mint(*request)))
                });
                jobs.insert(handle.id(), PanickedJob::Mint(introduction));
            }
            DmEffect::Compute(ComputeJob::SaveSpentTokens(request)) => {
                probe.computes_started.fetch_add(1, Ordering::SeqCst);
                let handle = inflight.spawn_blocking(move || {
                    DmOutcome::SpentSaved(request.store.save(&request.set))
                });
                // Tagged like the others: a panicked write leaves the file
                // behind the set in memory, which under an invite-only policy
                // restores every invite spent since the last good write.
                jobs.insert(handle.id(), PanickedJob::SpentSave);
            }
            DmEffect::Emit(event) => {
                if evt_tx.send(event).await.is_err() {
                    return false;
                }
            }
        }
    }
    true
}

/// Run one operation against the seam and tag its result.
///
/// The kind is stamped here, from the op itself, rather than inferred later from
/// the result: four of the ten hold a slot the machine must release — the two
/// sweeps, the page write and the page watch — and on the failure path a result
/// says only that something went wrong.
pub(crate) async fn dispatch<D: DmDht>(dht: Arc<D>, op: DhtOp) -> DhtOutcome {
    let kind = op.kind();
    match op {
        DhtOp::FetchKeyRecord { tag, owner_seed } => DhtOutcome {
            kind,
            tag,
            result: dht
                .fetch_dm_key_record(owner_seed)
                .await
                .map(DhtResult::KeyRecord),
        },
        DhtOp::PublishDoorbell {
            tag,
            owner_seed,
            slot,
            entry,
            dispatch,
        } => DhtOutcome {
            kind,
            tag,
            result: dht
                .publish_doorbell_entry(owner_seed, slot, entry, dispatch)
                .await
                .map(|()| DhtResult::Written),
        },
        DhtOp::SweepDoorbell { tag, owner_seed } => DhtOutcome {
            kind,
            tag,
            result: dht
                .sweep_doorbell(owner_seed)
                .await
                .map(DhtResult::Doorbell),
        },
        DhtOp::PublishPage {
            tag,
            address,
            frame,
        } => DhtOutcome {
            kind,
            tag,
            result: dht
                .publish_dm_page(address, frame)
                .await
                .map(|()| DhtResult::Written),
        },
        DhtOp::SweepPage { tag, address } => DhtOutcome {
            kind,
            tag,
            result: dht.sweep_dm_page(address).await.map(DhtResult::Page),
        },
        // Awaited like every other operation, and pending far longer than any of
        // them: a watch resolves when the record changes, so this task sits in the
        // shell's `JoinSet` for the life of the watch. That is what makes the
        // arrival of a message an outcome the loop wakes on rather than something a
        // tick has to come around to.
        DhtOp::WatchPage { tag, address } => DhtOutcome {
            kind,
            tag,
            result: dht.watch_dm_page(address).await.map(DhtResult::Watch),
        },
        DhtOp::ClosePage { tag, address } => DhtOutcome {
            kind,
            tag,
            result: dht.close_dm_page(address).await.map(DhtResult::Closed),
        },
        DhtOp::PinPages {
            tag,
            statement,
            pages,
        } => DhtOutcome {
            kind,
            tag,
            result: dht
                .pin_dm_pages(statement, pages)
                .await
                .map(|()| DhtResult::Pinned),
        },
        DhtOp::PublishAck {
            tag,
            address,
            record,
        } => DhtOutcome {
            kind,
            tag,
            result: dht
                .publish_dm_ack(address, record)
                .await
                .map(|()| DhtResult::AckWritten),
        },
        DhtOp::FetchAck { tag, address } => DhtOutcome {
            kind,
            tag,
            result: dht.fetch_dm_ack(address).await.map(DhtResult::Ack),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    use daemonseed_core::dm::ack_record::DmAckAddress;
    use daemonseed_core::dm::firstcontact::AR_FINGERPRINT_LEN;
    use daemonseed_core::dm::keyrec::KEM_EK_LEN;
    use daemonseed_core::dm::outbox::DeliveryState;
    use daemonseed_core::dm::paging::{
        DmPageAddress, PagePosition, Receiving, Sending, ADDRESS_ROOT_LEN,
    };
    use daemonseed_core::dm::ratchet::{Direction, Ratchet};
    use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
    use daemonseed_core::identity::mnemonic::Mnemonic;
    use daemonseed_core::storage::seeds::AEAD_KEY_LEN;

    use daemonseed_core::dm::admission::{AdmissionOutcome, Admitter, SeenSet};
    use daemonseed_core::dm::firstcontact::{self, FirstContactRequest};
    use daemonseed_core::dm::keyrec;
    use daemonseed_core::identity::keys::{IdentityKeys, SignKeypair, ML_DSA_SEED_LEN};

    use crate::actor::{DmPageRecord, DmPageWatch, DoorbellDispatch, VeilidNetHandle};
    use crate::dm::machine::{duration_as_ms, OpTag};
    use crate::dm::mock::{Method, MockCall, MockDht};
    use crate::dm::types::{CorrespondentState, RefusalReason};
    use crate::dm::RequestId;

    const IDLE_TICK: Duration = Duration::from_secs(30);
    /// How long [`take_startup_roster`] waits before calling an absent roster
    /// an absent roster.
    ///
    /// Well past anything the startup path does, and it costs no real time:
    /// these oracles run on a paused clock, which advances to the next deadline
    /// only once every task is parked — so this elapses exactly when nothing is
    /// going to emit anything, which is the case it exists to catch.
    const STARTUP_ROSTER_TIMEOUT: Duration = Duration::from_secs(5);
    /// The reduced proof-of-work difficulty every oracle here mints and
    /// verifies at.
    const TEST_POW_BITS: u32 = 4;
    /// The cheapest Argon2id parameters `ArgonParams::is_openable` admits, so
    /// the spent-token oracles pay milliseconds rather than the desktop
    /// default's tenths of a second per seal.
    const TEST_ARGON: ArgonParams = ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    const AT_REST: [u8; AEAD_KEY_LEN] = [7u8; AEAD_KEY_LEN];
    const BASE_MS: i64 = 1_234_567_890_123;

    /// The BIP-39 test vector the crate's other identity fixtures use. Fixed, not
    /// generated: a paused-time oracle whose identity changes per run cannot be
    /// re-run against a failure.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art";

    /// The `ss0` every conversation fixture here derives from.
    const FIXTURE_SS0: [u8; 32] = [0x5c; 32];

    /// The address root of the fixture conversation.
    ///
    /// Derived from the same `ss0` as [`ratchet`], not chosen: an address
    /// derivation refuses a root whose conversation fingerprint is not the
    /// ratchet's, and `AR` is not invertible from a chosen value.
    fn root() -> [u8; ADDRESS_ROOT_LEN] {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        daemonseed_core::dm::firstcontact::derive_channel_roots(&FIXTURE_SS0)
            .expect("channel roots")
            .ar()
    }

    /// A recipient's ratchet: it takes only the PUBLIC half of the opening
    /// ephemeral, so no keygen is needed. Its role fixes both directions, so one
    /// ratchet derives both a sending and a receiving address.
    fn ratchet() -> Ratchet {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        Ratchet::recipient(&FIXTURE_SS0, Box::new([0x11u8; KEM_EK_LEN])).expect("ratchet")
    }

    fn sending_address(r: &Ratchet) -> DmPageAddress<Sending> {
        DmPageAddress::sending(&root(), r, PagePosition::new(0, 1).expect("position"))
            .expect("sending address")
    }

    fn receiving_address(r: &Ratchet) -> DmPageAddress<Receiving> {
        DmPageAddress::receiving(&root(), r, 0).expect("receiving address")
    }

    fn ack_address(direction: Direction) -> DmAckAddress {
        DmAckAddress::for_direction(&root(), direction).expect("ack address")
    }

    fn tag() -> OpTag {
        OpTag::none()
    }

    /// The parts a driver oracle runs on: a fixed identity, a fresh store, the
    /// mock seam, and a clock the test moves by hand.
    fn parts(
        dir: &tempfile::TempDir,
        wall: &Arc<AtomicI64>,
        dht: Arc<MockDht>,
    ) -> DmDriverParts<MockDht> {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let keys = derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Primary,
        )
        .expect("identity");
        let clock = WallClock::from_fn({
            let w = wall.clone();
            move || w.load(Ordering::SeqCst)
        });
        DmDriverParts {
            dht,
            clock,
            identity: DmIdentity {
                signing: Arc::new(keys.signing),
                kem: keys.kem,
                doorbell_slot_secret: keys.dm_doorbell_slot_secret,
            },
            persist: DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist opens"),
            cfg: DmDriverConfig {
                idle_tick: IDLE_TICK,
                policy: AdmissionPolicy::Open,
                // Four bits, not production's: a production mint takes seconds
                // and these oracles mint one entry per knock.
                pow_difficulty: PowDifficulty::reduced_for_test(TEST_POW_BITS),
                arm_page_watches: true,
            },
            // `None` is the memory-only set, which is what an open policy
            // needs: the token field is never decoded, so no nonce exists to
            // outlive the process. `spawn` refuses this pairing under
            // invite-only.
            spent_tokens: None,
        }
    }

    /// Let the driver task run up to its next await point.
    async fn settle() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    /// Move BOTH clocks: the injected wall clock the machine reads, and tokio's
    /// virtual time the shell sleeps on. Advancing one without the other is the
    /// failure this helper exists to make impossible.
    async fn advance(wall: &Arc<AtomicI64>, d: Duration) {
        settle().await;
        wall.fetch_add(duration_as_ms(d), Ordering::SeqCst);
        tokio::time::advance(d).await;
        settle().await;
    }

    /// T1. An idle driver sweeps its own doorbell on the cadence and touches
    /// nothing else.
    ///
    /// `ticks == 3` is the positive control: without it the six zeros below are
    /// satisfied by a loop that never ran at all. The sweep count being equal
    /// to it is the second half — a driver that swept once and then stopped
    /// would satisfy every other assertion here.
    #[tokio::test(start_paused = true)]
    async fn idle_driver_sweeps_its_doorbell_and_touches_nothing_else() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(1_700_000_000_000));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        for _ in 0..3 {
            advance(&wall, IDLE_TICK).await;
            // Room for the completed sweep to be joined without eating the next
            // cadence wakeup: the join arm is biased ahead of the timer, so a
            // single jump past both leaves the tick for the following pass.
            advance(&wall, Duration::from_secs(1)).await;
        }

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            3,
            "the loop woke thrice"
        );
        for method in Method::ALL {
            let expected = u64::from(method == Method::SweepDoorbell) * 3;
            assert_eq!(dht.count(method), expected, "{method:?} call count");
        }
        let log = dht.log();
        assert_eq!(log.len(), 3, "one call per cadence wakeup");
        assert!(
            log.iter().all(|c| c
                == &MockCall::SweepDoorbell {
                    owner_seed: own_doorbell_seed()
                }),
            "the driver swept something other than its own doorbell: {log:?}"
        );
        assert_eq!(probe.ops_started.load(Ordering::SeqCst), 3);
        assert_eq!(probe.ops_panicked.load(Ordering::SeqCst), 0);
        assert_eq!(probe.computes_started.load(Ordering::SeqCst), 0);

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
        // Three sweeps, three health reports and nothing else: an idle driver
        // says only what its own record health was.
        let events = drain(&mut evt_rx);
        assert_eq!(events.len(), 3, "one health report per sweep: {events:?}");
        assert!(
            events
                .iter()
                .all(|e| matches!(e, DmEvent::DoorbellHealth { .. })),
            "an idle driver emitted something else: {events:?}"
        );
        assert!(evt_rx.recv().await.is_none(), "the event channel closes");
    }

    /// A sweep latency longer than the cadence, so a sweep is still open when the
    /// next tick fires. Chosen against [`IDLE_TICK`]: one and a half ticks, so
    /// the sweep started at the first tick lands between the second and the
    /// third.
    const SLOW_SWEEP: Duration = Duration::from_secs(45);

    /// Run to a hundred seconds of virtual time in five-second steps.
    ///
    /// Stepped rather than jumped: a single advance past several deadlines
    /// leaves the order the loop observed them in up to the scheduler, and the
    /// whole claim here is about what happened between two of them.
    async fn run_to_a_hundred_seconds(wall: &Arc<AtomicI64>) {
        for _ in 0..20 {
            advance(wall, Duration::from_secs(5)).await;
        }
    }

    /// T1e. A tick whose doorbell sweep is still in flight asks for nothing.
    ///
    /// **The cadence says how often to look, not how many looks may be open at
    /// once.** A doorbell sweep is one read per subkey of the record, so on a
    /// real distributed hash table it takes far longer than a tick — and a
    /// driver that emitted one per tick regardless would hold a stack of sweeps
    /// of the same record open, every one of them competing with the others for
    /// the same read permits and making all of them slower.
    ///
    /// Three ticks land inside the window and two sweeps come out of them: the
    /// first tick sweeps, the second is suppressed because that sweep is still
    /// open, and the third sweeps because it has since landed. `ticks == 3` is
    /// the positive control — without it "two sweeps" is satisfied by a loop
    /// that woke twice. The control in the other direction is T1, which runs the
    /// same cadence against a sweep that returns in milliseconds and sees one
    /// sweep per tick.
    #[tokio::test(start_paused = true)]
    async fn a_doorbell_sweep_in_flight_suppresses_the_next_tick() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(SLOW_SWEEP));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        run_to_a_hundred_seconds(&wall).await;

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            3,
            "the loop must have woken three times, or two sweeps proves nothing"
        );
        assert_eq!(
            dht.count(Method::SweepDoorbell),
            2,
            "three ticks over a sweep that outlives one of them must ask twice"
        );
        assert_eq!(
            probe.ops_started.load(Ordering::SeqCst),
            2,
            "the suppressed tick must not have spawned anything either"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
        // One health report, from the one sweep that finished inside the window.
        let events = drain(&mut evt_rx);
        assert_eq!(
            events.len(),
            1,
            "exactly one sweep completed inside the window: {events:?}"
        );
    }

    /// T1e-mirror. Only a doorbell SWEEP releases the doorbell's slot — a
    /// doorbell WRITE completing does not.
    ///
    /// **The mirror control on T1e, and it is the half a suppression test cannot
    /// see.** T1e proves the slot is held; it says nothing about what may release
    /// it, and a release keyed one variant too wide passes every assertion T1e
    /// makes. The two doorbell operations are the pair most easily confused —
    /// they name the same record and differ only in direction — so this drives a
    /// real first contact, whose key-record fetch and doorbell write both
    /// complete while the slow sweep started at the first tick is still open, and
    /// asserts the sweep count is unmoved by either.
    ///
    /// Only the sweep is slowed. An introduction is a chain of hops, and one
    /// running at sweep speed would not finish inside the window at all — which
    /// would make this pass for the wrong reason.
    #[tokio::test(start_paused = true)]
    async fn a_doorbell_write_does_not_release_the_sweep_slot() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        dht.slow(Method::SweepDoorbell, SLOW_SWEEP);
        let peer = peer_keys();
        dht.set_key_record(Some(key_record_for(&peer)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        // The first tick, which starts the sweep that outlives the next two.
        advance(&wall, IDLE_TICK).await;
        assert_eq!(dht.count(Method::SweepDoorbell), 1, "the sweep started");

        // A whole first contact, inside that sweep's flight: fetch, mint, write.
        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "knock knock".into(),
            })
            .await
            .expect("first contact");
        // Five steps: the tick that started the sweep, the command, the key
        // record, the mint, and the write's own outcome coming back. The second
        // advance is not decoration — `settle_steps` releases the runtime's
        // thread for the blocking mint but does not move virtual time, so the
        // mock's latency on the write needs its own advance before the fifth
        // step can happen. Without it the fourth step is the mint's join and the
        // write is still asleep, which is the case this control exists to rule
        // out.
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 4).await;
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 5).await;

        // **The fixture is only the case it was written for if those outcomes
        // have actually landed while the sweep is still open.** A driver that
        // had not yet written anything would satisfy every count below for the
        // wrong reason.
        assert_eq!(
            dht.count(Method::PublishDoorbell),
            1,
            "the knock must have been written inside the sweep's flight"
        );
        assert_eq!(
            dht.count(Method::SweepDoorbell),
            1,
            "the sweep must still be the only one, and still open"
        );
        assert!(
            probe.ops_completed.load(Ordering::SeqCst) >= 3,
            "the fetch, the mint and the write must all have come back, or the \
             write's outcome was never offered to the release path"
        );

        // On to a hundred seconds. Same shape as T1e: the second tick is
        // suppressed and the third sweeps, so two sweeps — unless the write that
        // landed between them released the slot.
        for _ in 0..14 {
            advance(&wall, Duration::from_secs(5)).await;
        }

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            3,
            "the loop woke thrice"
        );
        assert_eq!(
            dht.count(Method::SweepDoorbell),
            2,
            "a doorbell write completing must not release the sweep's slot"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
        drain(&mut evt_rx);
    }

    /// T1f. A doorbell sweep that failed on the transport releases the slot.
    ///
    /// The expensive direction of T1e. A sweep held open for ever is a driver
    /// that never reads its own doorbell again — permanently deaf, with nothing
    /// about it looking wrong — so every way a sweep can end has to release it,
    /// and a transport failure carries no result to recognise it by.
    ///
    /// No event is the second half of the claim: a failed sweep reports no
    /// record health, so an event here would mean the sweep succeeded and the
    /// failure path was never exercised.
    #[tokio::test(start_paused = true)]
    async fn a_failed_doorbell_sweep_releases_the_next_tick() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::failing(SLOW_SWEEP, Method::SweepDoorbell));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        run_to_a_hundred_seconds(&wall).await;

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            3,
            "the loop woke thrice"
        );
        assert_eq!(
            dht.count(Method::SweepDoorbell),
            2,
            "the tick after a failed sweep must sweep again"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
        let events = drain(&mut evt_rx);
        assert!(
            events.is_empty(),
            "a failed sweep reports no record health, so the failure path did not run: {events:?}"
        );
    }

    /// T1g. A doorbell sweep whose task panicked releases the slot.
    ///
    /// The third and last way a sweep can end, and the only one that produces no
    /// outcome at all — which is why the shell records what the task was doing
    /// before it spawns it. `ops_panicked == 1` is the positive control: without
    /// it the second sweep is satisfied by a mock that never panicked.
    #[tokio::test(start_paused = true)]
    async fn a_panicked_doorbell_sweep_releases_the_next_tick() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::panicking(SLOW_SWEEP, Method::SweepDoorbell));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        run_to_a_hundred_seconds(&wall).await;

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            3,
            "the loop woke thrice"
        );
        assert_eq!(
            probe.ops_panicked.load(Ordering::SeqCst),
            1,
            "the sweep must actually have panicked"
        );
        assert_eq!(
            dht.count(Method::SweepDoorbell),
            2,
            "the tick after a panicked sweep must sweep again"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        assert!(evt_rx.recv().await.is_none(), "the event channel closes");
        task.await.expect("the driver task ends");
    }

    /// T1b. A command wakeup does not restart the idle timer.
    ///
    /// The deadline is anchored on the last tick, so a driver kept busy still
    /// reaches its cadence. Recomputing it from the wake time instead makes this
    /// driver — woken every ten seconds — tick zero times for ever.
    #[tokio::test(start_paused = true)]
    async fn a_busy_driver_still_reaches_its_cadence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        // Four commands ten seconds apart: every one lands strictly inside the
        // thirty-second cadence, so none of them is itself a tick.
        for _ in 0..4 {
            advance(&wall, Duration::from_secs(10)).await;
            handle
                .send(DmCommand::Block {
                    pk_lt: Box::new([0u8; daemonseed_core::identity::keys::IDENTITY_PK_LEN]),
                })
                .await
                .expect("command");
            settle().await;
        }

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            1,
            "forty seconds of commands still crossed one thirty-second deadline"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
        // Drained rather than asserted empty: that one cadence wakeup swept the
        // doorbell, and a sweep always reports its own record health.
        let events = drain(&mut evt_rx);
        // Length first: `.all()` over an empty list is vacuously true, and an
        // empty list is exactly what a driver that never swept produces.
        assert!(
            !events.is_empty(),
            "the one cadence wakeup reported no record health at all"
        );
        assert!(
            events
                .iter()
                .all(|e| matches!(e, DmEvent::DoorbellHealth { .. })),
            "an idle driver emitted something other than record health: {events:?}"
        );
        assert!(evt_rx.recv().await.is_none(), "the event channel closes");
    }

    /// T2. The mock counts what it is asked for, in call order.
    ///
    /// This is what makes T1's zeros mean zero: a mock that counted nothing would
    /// satisfy T1 while the driver hammered the DHT.
    #[tokio::test(start_paused = true)]
    async fn mock_counts_what_it_is_asked() {
        // On a shared network rather than a private one, so the watch below has
        // something that can answer it: a watch stands until the record changes,
        // and the record is the network's rather than the mock's.
        let net = crate::dm::mock::MockNetwork::new();
        let dht = MockDht::on(net.clone(), Duration::from_millis(50));
        let r = ratchet();
        let conversation: [u8; AR_FINGERPRINT_LEN] = *sending_address(&r).conversation();
        let send_dir = sending_address(&r).direction();
        let recv_dir = receiving_address(&r).direction();

        dht.fetch_dm_key_record([1u8; 32]).await.expect("fetch");
        dht.publish_doorbell_entry([2u8; 32], 5, vec![0u8; 9], DoorbellDispatch::FirstSend)
            .await
            .expect("knock");
        dht.sweep_doorbell([2u8; 32]).await.expect("sweep doorbell");
        dht.publish_dm_page(sending_address(&r), vec![0u8; 11])
            .await
            .expect("publish page");
        dht.sweep_dm_page(receiving_address(&r))
            .await
            .expect("sweep page");
        // Armed before the change is delivered, because a watch answers a change
        // that arrives after it — the call registers, the delivery answers it, and
        // the future resolves.
        let watching = dht.watch_dm_page(receiving_address(&r));
        net.deliver_page_change(conversation, recv_dir, 0);
        assert_eq!(
            watching.await.expect("watch page"),
            DmPageWatch::Changed,
            "the delivered change must be what the watch answers"
        );
        dht.publish_dm_ack(ack_address(Direction::AToB), vec![0u8; 13])
            .await
            .expect("ack");
        dht.fetch_dm_ack(ack_address(Direction::BToA))
            .await
            .expect("fetch ack");
        // The page written above is one this mock is now holding, so the close is
        // asked on a record that exists and answers `true`. Asking it on an
        // unopened page would count the call and prove nothing about the release.
        assert!(
            dht.close_dm_page(DmPageRecord::Sending(sending_address(&r)))
                .await
                .expect("close page"),
            "the page published above must be the one handed back"
        );
        dht.pin_dm_pages(1, vec![DmPageRecord::Receiving(receiving_address(&r))])
            .await
            .expect("pin pages");
        assert_eq!(
            dht.pinned_pages().len(),
            1,
            "the pin must be recorded as the set it named, not merely counted"
        );

        assert_eq!(Method::ALL.len(), 10, "the seam has ten methods");
        for method in Method::ALL {
            assert_eq!(dht.count(method), 1, "{method:?} counted once");
        }

        let log = dht.log();
        assert_eq!(Method::ALL.len(), log.len(), "one entry per method");
        assert_eq!(
            log[0],
            MockCall::FetchKeyRecord {
                owner_seed: [1u8; 32]
            }
        );
        assert_eq!(
            log[1],
            MockCall::PublishDoorbell {
                owner_seed: [2u8; 32],
                slot: 5,
                entry_len: 9,
                dispatch: DoorbellDispatch::FirstSend,
            }
        );
        assert_eq!(
            log[2],
            MockCall::SweepDoorbell {
                owner_seed: [2u8; 32]
            }
        );
        assert_eq!(
            log[3],
            MockCall::PublishPage {
                conversation,
                page: 0,
                slot: 1,
                direction: send_dir,
                frame_len: 11,
            }
        );
        assert_eq!(
            log[4],
            MockCall::SweepPage {
                conversation,
                page: 0,
                direction: recv_dir,
            }
        );
        assert_eq!(
            log[5],
            MockCall::WatchPage {
                conversation,
                page: 0,
                direction: recv_dir,
            }
        );
        assert_eq!(
            log[6],
            MockCall::PublishAck {
                direction: Direction::AToB,
                record_len: 13,
            }
        );
        assert_eq!(
            log[7],
            MockCall::FetchAck {
                direction: Direction::BToA
            }
        );
        assert_eq!(
            log[8],
            MockCall::ClosePage {
                conversation,
                page: 0,
                direction: send_dir,
                closed: true,
            }
        );
        assert_eq!(
            log[9],
            MockCall::PinPages {
                statement: 1,
                pages: vec![(conversation, recv_dir, 0)],
            }
        );
    }

    /// T2c. A pin statement REPLACES the previous one across the seam.
    ///
    /// The mock is the surface a driver oracle reads the statement back from, so
    /// what it does with a second statement has to be the same thing the transport
    /// does: replace. A mock that accumulated would report every page ever pinned
    /// as still pinned, and a driver that had stopped restating a page would look
    /// correct while its record was held open for the session.
    ///
    /// The first statement is the control: without it, an empty set after the
    /// second is satisfied by a mock that records nothing at all.
    #[tokio::test(start_paused = true)]
    async fn a_second_pin_statement_replaces_the_first() {
        let dht = MockDht::new(Duration::from_millis(1));
        let r = ratchet();

        dht.pin_dm_pages(1, vec![DmPageRecord::Receiving(receiving_address(&r))])
            .await
            .expect("pin");
        assert_eq!(
            dht.pinned_pages().len(),
            1,
            "the first statement must have been recorded"
        );

        dht.pin_dm_pages(2, Vec::new()).await.expect("unpin");
        assert!(
            dht.pinned_pages().is_empty(),
            "an empty statement unpins everything — which is what makes a page \
             dropped from the watched window need no separate release"
        );

        // Reordered delivery: statement one arriving after statement two must not
        // reinstate its set. The operations are dispatched as independent tasks, so
        // this ordering is reachable in production and nothing would repair it —
        // the driver does not restate a set it believes it has already sent.
        dht.pin_dm_pages(1, vec![DmPageRecord::Receiving(receiving_address(&r))])
            .await
            .expect("stale pin");
        assert!(
            dht.pinned_pages().is_empty(),
            "a statement older than the last applied must change nothing"
        );
    }

    /// T2d. A page record handed back and named again is simply opened again, and
    /// what it holds is unchanged.
    ///
    /// **This pins the accepted cost of the close path (#252), not a bug.** A
    /// close releases this end's handle on a record; it erases nothing on the
    /// network. Nothing forbids a later plan naming a page that was closed — an
    /// out-of-order arrival cannot cause it, since the positions were settled, but
    /// a restart re-derives a collection from its stored cursor and probes from
    /// there. What the design accepts is one open; what it must NOT be is a page
    /// that comes back empty, which would be a conversation silently losing
    /// messages with no error on any surface.
    ///
    /// The record is read from the network directly rather than through a sweep,
    /// because the claim is about the record while NOBODY holds it open and every
    /// seam method opens one. The state before the close is the control: without
    /// it, "the bytes are still there afterwards" is satisfied by a fixture that
    /// never wrote them.
    #[tokio::test(start_paused = true)]
    async fn a_closed_page_named_again_is_re_opened_with_its_contents_intact() {
        let net = crate::dm::mock::MockNetwork::new();
        let dht = Arc::new(MockDht::on(net.clone(), Duration::from_millis(1)));
        let r = ratchet();
        let slot = sending_address(&r).at().slot();
        let record = DmPageRecord::Sending(sending_address(&r));
        let frame = vec![0xA5u8; 24];

        dht.publish_dm_page(sending_address(&r), frame.clone())
            .await
            .expect("the page is written");
        assert_eq!(dht.open_page_count(), 1, "the write opened the record");
        assert_eq!(
            net.slot_bytes(&record, slot).as_ref(),
            Some(&frame),
            "the record must hold the frame before the close, or nothing below \
             means anything"
        );

        assert!(
            dht.close_dm_page(DmPageRecord::Sending(sending_address(&r)))
                .await
                .expect("the close"),
            "the record the write opened must be the one handed back"
        );
        assert_eq!(
            dht.open_page_count(),
            0,
            "the close must have released the record, not merely been counted"
        );
        assert_eq!(
            net.slot_bytes(&record, slot).as_ref(),
            Some(&frame),
            "a closed record must keep what it held: a close releases a handle and \
             erases nothing"
        );

        dht.publish_dm_page(sending_address(&r), frame.clone())
            .await
            .expect("the page is written again");
        assert_eq!(
            dht.open_page_count(),
            1,
            "a page named again must be opened again — that one open is the \
             accepted cost of the bound"
        );
    }

    /// How many variants [`DhtOp`] has. Its own count, never borrowed from
    /// something that merely has the same one today.
    const DHT_OP_VARIANTS: usize = 10;

    /// Every [`DhtOp`] variant, as an index. Exhaustive by construction: a new
    /// variant fails to compile here rather than silently escaping the dispatch
    /// oracle below.
    fn op_index(op: &DhtOp) -> usize {
        match op {
            DhtOp::FetchKeyRecord { .. } => 0,
            DhtOp::PublishDoorbell { .. } => 1,
            DhtOp::SweepDoorbell { .. } => 2,
            DhtOp::PublishPage { .. } => 3,
            DhtOp::SweepPage { .. } => 4,
            DhtOp::WatchPage { .. } => 5,
            DhtOp::PublishAck { .. } => 6,
            DhtOp::FetchAck { .. } => 7,
            DhtOp::ClosePage { .. } => 8,
            DhtOp::PinPages { .. } => 9,
        }
    }

    /// T2b. `dispatch` routes every op to its own seam method and shapes the
    /// result to match.
    ///
    /// The routing is ten near-identical arms, which is exactly the shape a
    /// copy-paste slip survives in: a `SweepPage` arm calling `sweep_doorbell`
    /// compiles, returns `Ok`, and is invisible everywhere else.
    #[tokio::test(start_paused = true)]
    async fn dispatch_routes_every_op_to_its_own_method() {
        /// One routing case: the op to dispatch, the seam method it must reach,
        /// and the result shape it must come back as.
        struct Case {
            op: DhtOp,
            method: Method,
            shape: fn(&DhtResult) -> bool,
        }

        let r = ratchet();
        let cases: Vec<Case> = vec![
            Case {
                op: DhtOp::FetchKeyRecord {
                    tag: tag(),
                    owner_seed: [1u8; 32],
                },
                method: Method::FetchKeyRecord,
                shape: |res| matches!(res, DhtResult::KeyRecord(None)),
            },
            Case {
                op: DhtOp::PublishDoorbell {
                    tag: tag(),
                    owner_seed: [2u8; 32],
                    slot: 5,
                    entry: vec![0u8; 9],
                    dispatch: DoorbellDispatch::FirstSend,
                },
                method: Method::PublishDoorbell,
                shape: |res| matches!(res, DhtResult::Written),
            },
            Case {
                op: DhtOp::SweepDoorbell {
                    tag: tag(),
                    owner_seed: [2u8; 32],
                },
                method: Method::SweepDoorbell,
                shape: |res| matches!(res, DhtResult::Doorbell(_)),
            },
            Case {
                op: DhtOp::PublishPage {
                    tag: tag(),
                    address: sending_address(&r),
                    frame: vec![0u8; 11],
                },
                method: Method::PublishPage,
                shape: |res| matches!(res, DhtResult::Written),
            },
            Case {
                op: DhtOp::SweepPage {
                    tag: tag(),
                    address: receiving_address(&r),
                },
                method: Method::SweepPage,
                shape: |res| matches!(res, DhtResult::Page(_)),
            },
            Case {
                op: DhtOp::WatchPage {
                    tag: tag(),
                    address: receiving_address(&r),
                },
                method: Method::WatchPage,
                // `Lost`, and the mock is scripted to answer it below. A standing
                // watch resolves when the record changes and this oracle changes
                // nothing, so an unscripted one would never answer at all — which is
                // the production behaviour and useless here. What is under test is
                // that the op reaches its own seam method and comes back shaped as a
                // watch.
                shape: |res| matches!(res, DhtResult::Watch(DmPageWatch::Lost)),
            },
            Case {
                op: DhtOp::PublishAck {
                    tag: tag(),
                    address: ack_address(Direction::AToB),
                    record: vec![0u8; 13],
                },
                method: Method::PublishAck,
                // Its own shape, not `Written`: an acknowledgement write
                // confirms no outbox entry, and what it advances instead is the
                // receiver's standalone cadence.
                shape: |res| matches!(res, DhtResult::AckWritten),
            },
            Case {
                op: DhtOp::FetchAck {
                    tag: tag(),
                    address: ack_address(Direction::BToA),
                },
                method: Method::FetchAck,
                shape: |res| matches!(res, DhtResult::Ack(None)),
            },
            Case {
                op: DhtOp::ClosePage {
                    tag: tag(),
                    address: DmPageRecord::Receiving(receiving_address(&r)),
                },
                method: Method::ClosePage,
                // `false`: nothing opened this page in this mock, which is the
                // transport's own answer for an id the cache does not hold.
                shape: |res| matches!(res, DhtResult::Closed(false)),
            },
            Case {
                op: DhtOp::PinPages {
                    tag: tag(),
                    statement: 1,
                    pages: vec![DmPageRecord::Receiving(receiving_address(&r))],
                },
                method: Method::PinPages,
                shape: |res| matches!(res, DhtResult::Pinned),
            },
        ];

        let mut covered: Vec<usize> = cases.iter().map(|c| op_index(&c.op)).collect();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(
            covered.len(),
            DHT_OP_VARIANTS,
            "every DhtOp variant is covered exactly once"
        );

        for Case { op, method, shape } in cases {
            let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
            // Every case gets it; only the watch reads it. See that case's note.
            dht.set_watches_lost(true);
            let outcome = dispatch(dht.clone(), op).await;
            let result = outcome.result.expect("the mock succeeds");
            assert!(shape(&result), "{method:?} returned the wrong result shape");
            for other in Method::ALL {
                let expected = u64::from(other == method);
                assert_eq!(dht.count(other), expected, "{method:?} called {other:?}");
            }
        }
    }

    /// T2c. Every op the shell must be able to release after a panic records
    /// what it was.
    ///
    /// The shell reads this **before** spawning, because a panicked task returns
    /// no outcome and the map is the only route from a dead task back to the
    /// state the machine is holding for it. Exhaustive over [`DhtOp`] by
    /// construction, on [`op_index`]: a further operation fails to compile here
    /// rather than silently escaping with no recorded job.
    #[test]
    fn every_op_records_what_a_panic_would_have_to_release() {
        /// Whether the job an op records is the one it must.
        type Wants = fn(Option<PanickedJob>) -> bool;

        let r = ratchet();
        let conversation = [7u8; AR_FINGERPRINT_LEN];
        let cases: Vec<(DhtOp, Wants)> = vec![
            (
                DhtOp::FetchKeyRecord {
                    tag: OpTag {
                        introduction: Some(Box::new(*peer_keys().signing.public_key())),
                        ..tag()
                    },
                    owner_seed: [1u8; 32],
                },
                |job| matches!(job, Some(PanickedJob::Dht(_))),
            ),
            (
                DhtOp::PublishDoorbell {
                    tag: tag(),
                    owner_seed: [2u8; 32],
                    slot: 5,
                    entry: vec![0u8; 9],
                    dispatch: DoorbellDispatch::FirstSend,
                },
                |job| job.is_none(),
            ),
            (
                DhtOp::SweepDoorbell {
                    tag: tag(),
                    owner_seed: [2u8; 32],
                },
                |job| matches!(job, Some(PanickedJob::DoorbellSweep)),
            ),
            (
                // A page write holds `publishing_pages` until its outcome lands, so
                // a panicked one has a slot to release exactly as a sweep does.
                DhtOp::PublishPage {
                    tag: OpTag {
                        conversation: Some(conversation),
                        page: Some(5),
                        ..tag()
                    },
                    address: sending_address(&r),
                    frame: vec![0u8; 11],
                },
                |job| matches!(job, Some(PanickedJob::PagePublish { page: 5, .. })),
            ),
            (
                // And one whose tag names no page releases nothing rather than
                // guessing — the same fall-through the sweep side is pinned for.
                DhtOp::PublishPage {
                    tag: tag(),
                    address: sending_address(&r),
                    frame: vec![0u8; 11],
                },
                |job| job.is_none(),
            ),
            (
                DhtOp::SweepPage {
                    tag: OpTag {
                        conversation: Some(conversation),
                        page: Some(3),
                        ..tag()
                    },
                    address: receiving_address(&r),
                },
                |job| matches!(job, Some(PanickedJob::PageSweep { page: 3, .. })),
            ),
            (
                // A watch holds `watched_pages` until its outcome lands, so a
                // panicked one has a slot to release exactly as a sweep does.
                DhtOp::WatchPage {
                    tag: OpTag {
                        conversation: Some(conversation),
                        page: Some(4),
                        ..tag()
                    },
                    address: receiving_address(&r),
                },
                |job| matches!(job, Some(PanickedJob::PageWatch { page: 4, .. })),
            ),
            (
                DhtOp::PublishAck {
                    tag: tag(),
                    address: ack_address(Direction::AToB),
                    record: vec![0u8; 13],
                },
                |job| job.is_none(),
            ),
            (
                DhtOp::FetchAck {
                    tag: tag(),
                    address: ack_address(Direction::BToA),
                },
                |job| job.is_none(),
            ),
            (
                // A close holds no slot of its own — it is what releases one — so a
                // panicked close leaves the machine holding nothing for it.
                DhtOp::ClosePage {
                    tag: OpTag {
                        conversation: Some(conversation),
                        page: Some(3),
                        ..tag()
                    },
                    address: DmPageRecord::Sending(sending_address(&r)),
                },
                |job| job.is_none(),
            ),
            (
                // A pin holds no slot either: it states which records a capacity
                // bound may not choose and starts no operation on any of them.
                DhtOp::PinPages {
                    tag: tag(),
                    statement: 1,
                    pages: vec![DmPageRecord::Receiving(receiving_address(&r))],
                },
                |job| job.is_none(),
            ),
        ];

        // The subject is `DhtOp`'s own arity. `Method` happens to have the same
        // number of variants, and borrowing its count would let a case go missing
        // the day the two stop matching.
        let mut covered: Vec<usize> = cases.iter().map(|(op, _)| op_index(op)).collect();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(
            covered.len(),
            DHT_OP_VARIANTS,
            "every DhtOp variant is covered exactly once"
        );

        for (op, wants) in cases {
            let kind = op.kind();
            let job = op.panicked_job();
            assert!(
                wants(job),
                "{} recorded the wrong panicked job",
                kind.name()
            );
        }

        // A sweep is decided by its kind, never by its tag. The other way round
        // is correct only while no sweep carries an introduction, and the day one
        // did it would report the introduction and leave the record's slot held
        // for ever — with nothing else in the driver ever looking at that slot.
        let tagged_sweep = DhtOp::SweepDoorbell {
            tag: OpTag {
                introduction: Some(Box::new(*peer_keys().signing.public_key())),
                ..tag()
            },
            owner_seed: [2u8; 32],
        };
        assert!(
            matches!(
                tagged_sweep.panicked_job(),
                Some(PanickedJob::DoorbellSweep)
            ),
            "a sweep carrying an introduction must still release the record"
        );

        // The other side of that ordering: a page sweep whose tag names no slot
        // to release must fall through to the introduction rather than to
        // nothing, or deciding the kind first would have made this case narrower
        // than testing the tag first did.
        let untagged_page_sweep = DhtOp::SweepPage {
            tag: OpTag {
                conversation: Some([7u8; AR_FINGERPRINT_LEN]),
                introduction: Some(Box::new(*peer_keys().signing.public_key())),
                ..tag()
            },
            address: receiving_address(&r),
        };
        assert!(
            matches!(
                untagged_page_sweep.panicked_job(),
                Some(PanickedJob::Dht(_))
            ),
            "a sweep with no releasable slot must fall through to its introduction"
        );
    }

    /// T3. The machine sees the injected clock, not the system one.
    ///
    /// Both reads are pinned. `last_due_input_ms` is the value the loop computes
    /// its deadline from, asserted before any time passes; `last_tick_ms` is what
    /// the machine recorded when the deadline fired. Neither literal is one
    /// `SystemTime::now()` can produce, and neither is derived from production's
    /// own arithmetic.
    #[tokio::test(start_paused = true)]
    async fn machine_sees_the_injected_clock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        settle().await;
        assert_eq!(
            probe.last_due_input_ms.load(Ordering::SeqCst),
            BASE_MS,
            "the deadline is computed from the injected wall time"
        );

        advance(&wall, IDLE_TICK).await;

        assert_eq!(probe.ticks.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe.last_tick_ms.load(Ordering::SeqCst),
            1_234_567_920_123i64,
            "the machine recorded the injected wall time"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        assert!(evt_rx.recv().await.is_none());
        task.await.expect("the driver task ends");
    }

    /// T4. Dropping the last handle ends the driver, with no Shutdown command.
    ///
    /// `ticks == 0` is half the claim: the driver must end because its command
    /// channel closed, not because it woke for some other reason on the way out.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_handle_ends_the_driver() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(1_700_000_000_000));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());
        take_startup_roster(&mut evt_rx).await;

        drop(handle);

        assert!(evt_rx.recv().await.is_none(), "the event channel closes");
        task.await.expect("the driver task ends");
        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            0,
            "the driver ended on the closed channel, not on a cadence wakeup"
        );
    }

    /// T4b. A panic inside a spawned operation is counted, not mistaken for a
    /// cadence wakeup, and does not take the driver down.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_operation_is_counted_and_survived() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::panicking(
            Duration::from_millis(50),
            Method::SweepDoorbell,
        ));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) = DmDriver::spawn_seeded(
            parts(&dir, &wall, dht.clone()),
            probe.clone(),
            vec![DmEffect::Dht(DhtOp::SweepDoorbell {
                tag: tag(),
                owner_seed: [2u8; 32],
            })],
        );
        take_startup_roster(&mut evt_rx).await;

        // A hundred milliseconds: past the mock's latency, far short of the
        // thirty-second cadence, so a tick here could only be a mis-attribution.
        advance(&wall, Duration::from_millis(100)).await;

        assert_eq!(probe.ops_started.load(Ordering::SeqCst), 1);
        assert_eq!(probe.ops_completed.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe.ops_panicked.load(Ordering::SeqCst),
            1,
            "the panic was counted as a panic"
        );
        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            0,
            "a seam panic is not a cadence wakeup"
        );
        assert_eq!(dht.count(Method::SweepDoorbell), 1);

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        assert!(evt_rx.recv().await.is_none());
        task.await.expect("the driver task ends");
    }

    /// T4c. An emitted effect reaches the front end.
    #[tokio::test(start_paused = true)]
    async fn an_emitted_effect_reaches_the_front_end() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) = DmDriver::spawn_seeded(
            parts(&dir, &wall, dht),
            probe,
            vec![DmEffect::Emit(DmEvent::DoorbellHealth {
                outcome: crate::SweepOutcome {
                    attempted: 32,
                    failed: 2,
                    timed_out: 0,
                    found: 1,
                },
                admission: Default::default(),
                pending_full: 0,
            })],
        );

        let event = evt_rx.recv().await.expect("one event");
        match event {
            DmEvent::DoorbellHealth { outcome, .. } => {
                assert_eq!(outcome.attempted, 32);
                assert_eq!(outcome.failed, 2);
                assert_eq!(outcome.found, 1);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        // The seed is applied ahead of the roster, so the roster is what is
        // left in the channel.
        take_startup_roster(&mut evt_rx).await;

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        assert!(evt_rx.recv().await.is_none());
        task.await.expect("the driver task ends");
    }

    /// T5. The production handle satisfies the seam, and the production entry
    /// point starts and stops.
    ///
    /// The `DmDht` assertions are compile-time, because the production impl has
    /// no runnable test: every one of its methods needs a live DHT.
    #[tokio::test(start_paused = true)]
    async fn the_production_entry_point_starts_and_stops() {
        fn _assert<D: DmDht>() {}
        _assert::<VeilidNetHandle>();
        _assert::<MockDht>();

        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let (handle, mut evt_rx) = DmDriver::spawn(parts(&dir, &wall, dht));
        take_startup_roster(&mut evt_rx).await;

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        assert!(evt_rx.recv().await.is_none(), "the event channel closes");
    }

    /// T6. A zero cadence is refused at construction.
    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "idle_tick must be non-zero")]
    async fn a_zero_idle_tick_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let mut p = parts(&dir, &wall, dht);
        p.cfg.idle_tick = Duration::ZERO;
        let _ = DmDriver::spawn(p);
    }

    // ---- the doorbell half -------------------------------------------------

    /// The identity every oracle here runs as — the one `parts` builds.
    fn own_keys() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Primary,
        )
        .expect("identity")
    }

    /// A second identity, for the other side of a knock.
    ///
    /// A device identity off the same fixed phrase under a fixed uuid, rather
    /// than a generated one: a paused-time oracle whose identities change per
    /// run cannot be re-run against a failure.
    fn peer_keys() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Device {
                uuid: uuid::Uuid::from_bytes([0x5Au8; 16]),
            },
        )
        .expect("identity")
    }

    /// A third identity, for the two-senders-one-slot case.
    fn other_peer_keys() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Device {
                uuid: uuid::Uuid::from_bytes([0xA5u8; 16]),
            },
        )
        .expect("identity")
    }

    /// A pseudonym keypair from a fixed seed, so a knock's `pk_pc` is a value
    /// the test can name.
    fn pseudonym(tag: u8) -> SignKeypair {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[tag; ML_DSA_SEED_LEN]).expect("pseudonym")
    }

    /// Mint one real knock from `sender` to the oracle identity, at the reduced
    /// difficulty. Returns the sealed entry.
    ///
    /// Everything is the production path: `firstcontact::build` composes, seals
    /// and mints the proof, so what the driver admits is an entry a real sender
    /// would have written.
    fn knock_from(sender: &IdentityKeys, signing_pc: &SignKeypair, body: &str) -> Vec<u8> {
        let own = own_keys();
        let (entry, _state) = firstcontact::build(FirstContactRequest {
            signing_lt: &sender.signing,
            signing_pc,
            recipient_pk_lt: own.signing.public_key(),
            kem_ek_b: own.kem.encapsulation_key(),
            fc_epoch: keyrec::fc_epoch((BASE_MS / 1000) as u64),
            sent_unix_ms: BASE_MS,
            body,
            token: None,
            difficulty: PowDifficulty::reduced_for_test(TEST_POW_BITS),
        })
        .expect("the knock is composed");
        entry
    }

    /// Our own doorbell's owner seed, derived the way a sender would.
    fn own_doorbell_seed() -> [u8; 32] {
        *daemonseed_core::dm::doorbell::derive_owner_seed(own_keys().signing.public_key())
            .expect("doorbell")
            .as_bytes()
    }

    /// Let a blocking compute job finish.
    ///
    /// `spawn_blocking` runs on a real thread and paused virtual time does not
    /// move it: `tokio::time::advance` and `yield_now` both return without
    /// giving that thread any wall clock at all. So this releases the runtime's
    /// own thread for real milliseconds, and polls the driver in between, until
    /// `want` off-loop operations have been joined.
    ///
    /// It panics rather than returning quietly on the bound, because a silent
    /// give-up here would make every assertion downstream read as "the driver
    /// decided not to" when the truth is "the job never finished".
    ///
    /// **It gates on `steps_applied`, never on `ops_completed`.** A join is
    /// counted before the machine step it produced has run and before that
    /// step's effects have been dispatched, so waiting on the join count and
    /// then reading the mock is racing the driver by one whole step. The
    /// applied count is bumped last.
    async fn settle_steps(probe: &DmDriverProbe, want: u64) {
        for _ in 0..2000 {
            if probe.steps_applied.load(Ordering::SeqCst) >= want {
                settle().await;
                return;
            }
            settle().await;
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!(
            "only {} steps applied, wanted {want}",
            probe.steps_applied.load(Ordering::SeqCst)
        );
    }

    /// Drain whatever the driver has emitted so far.
    fn drain(rx: &mut mpsc::Receiver<DmEvent>) -> Vec<DmEvent> {
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            out.push(event);
        }
        out
    }

    /// Take the roster every driver states before its first tick, so a test
    /// about what it says afterwards is not reading the startup statement.
    ///
    /// Awaited rather than drained: the roster is applied before the loop's
    /// first wakeup, so a test that has not yet advanced its clock still finds
    /// it. Asserting the shape here rather than skipping whatever arrives keeps
    /// each of these oracles a control on the roster being emitted at all.
    ///
    /// **A leading [`DmEvent::BlockListUnreadable`] is taken with it**, because
    /// that is the other half of one statement: a roster over a block-list
    /// record that would not read is emitted behind that alarm, and a helper
    /// that insisted on the roster arriving first would fail on a store fault
    /// rather than on the thing under test.
    ///
    /// **Bounded, because a `recv` that never returns is the failure this is
    /// most likely to meet.** A driver that emits no roster at all leaves the
    /// await parked for ever, and under a paused clock that is indistinguishable
    /// from a test that is merely slow — so the absence has to be a panic.
    async fn take_startup_roster(rx: &mut mpsc::Receiver<DmEvent>) {
        let mut alarm_taken = false;
        loop {
            let event = tokio::time::timeout(STARTUP_ROSTER_TIMEOUT, rx.recv())
                .await
                .unwrap_or_else(|_| panic!("no roster arrived within {STARTUP_ROSTER_TIMEOUT:?}"));
            match event {
                Some(DmEvent::Roster { .. }) => return,
                Some(DmEvent::BlockListUnreadable) if !alarm_taken => alarm_taken = true,
                other => panic!("a driver's first word was not its roster: {other:?}"),
            }
        }
    }

    /// The one contact request in `events`, or a panic naming what was there.
    fn only_request(events: &[DmEvent]) -> (RequestId, Vec<u8>, String) {
        let requests: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                DmEvent::ContactRequest {
                    request,
                    from,
                    body,
                    ..
                } => Some((request.clone(), from.to_vec(), body.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one contact request, got {events:?}"
        );
        requests.into_iter().next().expect("length asserted above")
    }

    /// T7. A knock in our doorbell sweeps out as exactly one contact request.
    ///
    /// `SweepDoorbell == 1` against our OWN owner seed is the positive control:
    /// without it the request could have come from anywhere, and a driver that
    /// swept somebody else's doorbell would look identical in every other
    /// assertion.
    #[tokio::test(start_paused = true)]
    async fn a_knock_sweeps_out_as_one_contact_request() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.queue_doorbell(vec![(
            7,
            knock_from(&peer, &pseudonym(0x21), "knock knock"),
        )]);
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;

        assert_eq!(
            dht.count(Method::SweepDoorbell),
            1,
            "the doorbell was swept once"
        );
        assert_eq!(
            dht.log()[0],
            MockCall::SweepDoorbell {
                owner_seed: own_doorbell_seed()
            },
            "the driver swept its own doorbell"
        );

        let events = drain(&mut evt_rx);
        let (request, from, body) = only_request(&events);
        assert_eq!(request.slot, 7, "the request names the slot it arrived in");
        assert_eq!(from.as_slice(), peer.signing.public_key().as_slice());
        assert_eq!(body, "knock knock");

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T8. Accepting that request establishes a correspondence on disk whose
    /// contact record carries the knock's own keys.
    #[tokio::test(start_paused = true)]
    async fn accepting_a_request_establishes_the_correspondence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        let pc = pseudonym(0x21);
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pc, "let me in"))]);
        let probe = Arc::new(DmDriverProbe::new());
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (request, _, _) = only_request(&drain(&mut evt_rx));

        assert!(
            store
                .correspondence_for_pk_lt(peer.signing.public_key())
                .expect("lookup")
                .is_none(),
            "nothing is established before the accept"
        );

        handle
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle().await;

        let label = store
            .correspondence_for_pk_lt(peer.signing.public_key())
            .expect("lookup")
            .expect("the accept established a correspondence");
        let contact = store.read_contact(&label).expect("read").expect("a record");
        assert_eq!(
            contact.pk_lt().as_slice(),
            peer.signing.public_key().as_slice()
        );
        assert_eq!(
            contact
                .pk_pc()
                .expect("the acceptor records a pseudonym")
                .as_slice(),
            pc.public_key().as_slice()
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T9. A knock from a blocked identity surfaces nothing, and the block-list
    /// consult is the reason.
    ///
    /// The pairing is the control: the SAME knock, the same driver, the same
    /// sweep — the only difference is whether the sender was blocked first.
    /// Removing the `suppresses_knock` consult from `on_doorbell` makes the
    /// blocked half fail while the unblocked half still passes, so the test
    /// cannot pass for the reason "no request was ever produced".
    #[tokio::test(start_paused = true)]
    async fn a_blocked_knock_is_dropped_by_the_block_list_consult() {
        for blocked in [false, true] {
            let dir = tempfile::tempdir().expect("temp dir");
            let wall = Arc::new(AtomicI64::new(BASE_MS));
            let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
            let peer = peer_keys();
            dht.queue_doorbell(vec![(7, knock_from(&peer, &pseudonym(0x21), "hello"))]);
            let probe = Arc::new(DmDriverProbe::new());
            let (handle, mut evt_rx, task) =
                DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

            if blocked {
                handle
                    .send(DmCommand::Block {
                        pk_lt: Box::new(*peer.signing.public_key()),
                    })
                    .await
                    .expect("block");
                settle().await;
            }
            advance(&wall, IDLE_TICK).await;
            advance(&wall, Duration::from_secs(1)).await;

            let events = drain(&mut evt_rx);
            let requests = events
                .iter()
                .filter(|e| matches!(e, DmEvent::ContactRequest { .. }))
                .count();
            assert_eq!(
                requests,
                usize::from(!blocked),
                "blocked={blocked}: wrong number of contact requests in {events:?}"
            );

            handle.send(DmCommand::Shutdown).await.expect("shutdown");
            task.await.expect("the driver task ends");
        }
    }

    /// T10. Declining leaves no correspondence for that identity — and no
    /// record of the decline either, which is the whole of what a decline is.
    #[tokio::test(start_paused = true)]
    async fn declining_establishes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pseudonym(0x21), "hi"))]);
        let probe = Arc::new(DmDriverProbe::new());
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (request, _, _) = only_request(&drain(&mut evt_rx));

        handle
            .send(DmCommand::Decline {
                request: request.clone(),
            })
            .await
            .expect("decline");
        settle().await;

        assert!(
            store
                .correspondence_for_pk_lt(peer.signing.public_key())
                .expect("lookup")
                .is_none(),
            "a decline established a correspondence"
        );
        // Positive control on the decline itself: the request is gone, so a
        // later accept of it establishes nothing either.
        handle
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle().await;
        assert!(
            store
                .correspondence_for_pk_lt(peer.signing.public_key())
                .expect("lookup")
                .is_none(),
            "a declined request was still acceptable"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T11. `FirstContact` runs fetch → compute → publish, in that order, and
    /// persists the provisional record before the knock is written.
    ///
    /// The order is asserted on the mock's own call log rather than on counts:
    /// a driver that published before it had a key record would show the same
    /// two counts.
    #[tokio::test(start_paused = true)]
    async fn a_first_contact_fetches_then_mints_then_publishes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.set_key_record(Some(
            keyrec::build_encoded(
                &peer.signing,
                peer.kem.encapsulation_key(),
                keyrec::DM_KEY_RECORD_VERSION,
                keyrec::DM_KEY_RECORD_INVITE_ONLY,
            )
            .expect("key record"),
        ));
        let probe = Arc::new(DmDriverProbe::new());
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "first word".into(),
            })
            .await
            .expect("first contact");
        // Three steps: the command, the key record coming back, and the mint
        // finishing — the publish is dispatched at the end of the third.
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 3).await;

        assert_eq!(probe.computes_started.load(Ordering::SeqCst), 1, "one mint");
        let log = dht.log();
        let fetch = log
            .iter()
            .position(|c| matches!(c, MockCall::FetchKeyRecord { .. }))
            .expect("the key record was fetched");
        let publish = log
            .iter()
            .position(|c| matches!(c, MockCall::PublishDoorbell { .. }))
            .expect("the knock was published");
        assert!(
            fetch < publish,
            "the knock was published before the key record came back: {log:?}"
        );
        let MockCall::PublishDoorbell {
            owner_seed,
            slot,
            dispatch,
            ..
        } = &log[publish]
        else {
            panic!("indexed the wrong call");
        };
        assert_eq!(
            owner_seed,
            daemonseed_core::dm::doorbell::derive_owner_seed(peer.signing.public_key())
                .expect("doorbell")
                .as_bytes(),
            "the knock went to the recipient's doorbell"
        );
        assert_eq!(
            *slot,
            daemonseed_core::dm::doorbell::slot_for(
                &own_keys().dm_doorbell_slot_secret,
                peer.signing.public_key()
            )
            .expect("slot"),
            "the knock went to our own slot at that recipient"
        );
        assert_eq!(*dispatch, DoorbellDispatch::FirstSend);

        // Exactly one correspondence exists — asserted through the store rather
        // than by counting effects, so a driver that emitted the write and
        // skipped the persist fails here.
        let labels = store.store().correspondences().expect("list");
        assert_eq!(labels.len(), 1, "one correspondence was established");

        // **The provisional record was written and SURVIVES the mint.** The
        // frozen design keeps `{ss0, the opening ephemeral DK}` on disk until
        // the acceptance is processed, because without the ephemeral DK this
        // side cannot decapsulate the acceptor's first generation ciphertext —
        // so consuming it here would strand the channel on any restart in the
        // knock-to-acceptance window. Its erasure is a verified acceptance's
        // job and is asserted where that happens
        // (`two_drivers_carry_a_round_trip_end_to_end_exactly_once`).
        //
        // Its PRESENCE is still the evidence the persist ran: a driver that
        // skipped it would have had nothing to derive a ratchet from and would
        // have refused rather than published.
        assert!(
            store
                .store()
                .read_unlocked(
                    &labels[0],
                    daemonseed_core::storage::dm_store::RecordKind::Provisional
                )
                .expect("read")
                .is_some(),
            "the mint consumed the record the acceptance window needs"
        );

        // Sequence zero is in the outbox, carrying the bytes that were
        // published. Without it a failed knock is an orphan: nothing re-seeds it
        // and nothing gives up on it.
        let published_entry = dht.published();
        assert_eq!(published_entry.len(), 1, "one knock was published");
        let queued = store
            .read_outbox(&labels[0], wall.load(Ordering::SeqCst))
            .expect("the outbox reads")
            .expect("the outbox exists");
        assert_eq!(queued.len(), 1, "the outbox holds exactly the knock");
        let zero = queued.entry(0).expect("sequence zero is queued");
        assert_eq!(
            zero.target(),
            daemonseed_core::dm::outbox::OutboxTarget::Doorbell { slot: *slot },
            "the knock is queued against the doorbell slot it was written to"
        );
        assert_eq!(
            zero.frame().expect("the knock keeps its bytes"),
            published_entry[0].1.as_slice(),
            "a re-seed must re-emit the identical bytes, or the far end reads it \
             as this side having lost its state"
        );
        assert!(
            drain(&mut evt_rx)
                .iter()
                .all(|e| !matches!(e, DmEvent::Refused { .. })),
            "a successful first contact refused itself"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T11b. An absent key record publishes nothing and is refused.
    ///
    /// `Ok(None)` is the awaiting-key state, and the front end is told with
    /// `DmEvent::Refused { acceptance: Acceptance::Unconfirmed }` — the same
    /// event a failed write produces, because from the front end's side they
    /// are the same fact.
    #[tokio::test(start_paused = true)]
    async fn an_absent_key_record_publishes_nothing_and_refuses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        // The mock's default: no key record at that address.
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "first word".into(),
            })
            .await
            .expect("first contact");
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 2).await;

        assert_eq!(
            dht.count(Method::FetchKeyRecord),
            1,
            "the fetch was attempted"
        );
        assert_eq!(
            dht.count(Method::PublishDoorbell),
            0,
            "nothing was knocked without a key to seal it to"
        );
        assert_eq!(
            probe.computes_started.load(Ordering::SeqCst),
            0,
            "no proof of work was minted for an entry that cannot exist"
        );
        let events = drain(&mut evt_rx);
        let refusals = events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    DmEvent::Refused {
                        acceptance: daemonseed_core::dm::outbox::Acceptance::Unconfirmed,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(refusals, 1, "expected one refusal, got {events:?}");

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T12. A fresh knock from an identity we already correspond with is state
    /// loss, and it surfaces as `ChannelLost`.
    ///
    /// The two knocks carry different `ss0` values — `firstcontact::build`
    /// encapsulates a fresh one per call — so the second addresses a channel
    /// the contact record does not hold, which is exactly the predicate
    /// `correspondent_state_lost` reads.
    #[tokio::test(start_paused = true)]
    async fn a_re_knock_from_a_known_correspondent_is_channel_lost() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        let pc = pseudonym(0x21);
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pc, "first"))]);
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pc, "again"))]);
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (request, _, _) = only_request(&drain(&mut evt_rx));
        handle
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle().await;

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;

        let events = drain(&mut evt_rx);
        let lost: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                DmEvent::ChannelLost {
                    with,
                    cause,
                    event,
                    surfaced,
                } => Some((
                    with.to_vec(),
                    format!("{cause:?}"),
                    surfaced.clone(),
                    *event,
                )),
                _ => None,
            })
            .collect();
        assert_eq!(lost.len(), 1, "expected one ChannelLost, got {events:?}");
        assert_eq!(lost[0].0.as_slice(), peer.signing.public_key().as_slice());
        assert_eq!(lost[0].1, "CorrespondentStateLost");
        // The loss and its classed trust event travel together: a front end
        // cannot read one without the other (ISC-C28 / ISC-A-C12).
        assert_eq!(
            lost[0].3,
            daemonseed_core::trust_events::TrustEventKey::DmCorrespondentStateLost
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DmEvent::ContactRequest { .. })),
            "a known correspondent's re-knock surfaced a second request"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T12b. A torn-down channel raises its classed trust event on the path a
    /// front end actually sees, and raises it once per process lifetime.
    ///
    /// The knock that loses the channel is queued three times. The doorbell's
    /// per-epoch seen-set answers the repeats, so the teardown is reached once
    /// however often the entry is swept — which is the claim ISC-A-C12 needs:
    /// not "one entry produced one event", but "reaching the teardown again
    /// produces no second one". Driven through the doorbell and the `Accept`
    /// command rather than by calling `Teardown::event` here, so the assertion
    /// is about what the driver emits and not about what core can compute.
    ///
    /// **The bound is this process, and it does not survive a restart.** The
    /// seen set is in memory and retired with its epoch, and
    /// `correspondent_state_lost` neither rebinds the address root nor drops the
    /// correspondence — so a driver restarted inside the same first-contact
    /// epoch, with the entry still live on the doorbell, re-admits it and raises
    /// the event again. The audit log has no dedupe of its own either
    /// (`TrustEventLog::append` records every non-transient event it is given);
    /// only the TUI's `persistent` affordance list collapses the repeat.
    #[tokio::test(start_paused = true)]
    async fn a_torn_down_channel_raises_its_trust_event_exactly_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        let pc = pseudonym(0x21);
        let lost_knock = knock_from(&peer, &pc, "again");
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pc, "first"))]);
        dht.queue_doorbell(vec![(7, lost_knock.clone())]);
        dht.queue_doorbell(vec![(7, lost_knock.clone())]);
        dht.queue_doorbell(vec![(7, lost_knock)]);
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (request, _, _) = only_request(&drain(&mut evt_rx));
        handle
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle().await;

        let mut swept = 0;
        let mut raised = Vec::new();
        for _ in 0..3 {
            advance(&wall, IDLE_TICK).await;
            advance(&wall, Duration::from_secs(1)).await;
            for e in drain(&mut evt_rx) {
                match e {
                    DmEvent::ChannelLost { event, .. } => raised.push(event),
                    DmEvent::DoorbellHealth { outcome, .. } if outcome.attempted > 0 => {
                        swept += 1;
                    }
                    _ => {}
                }
            }
        }
        // **One more window before counting.** The teardown makes the driver hand its
        // page records back (#252), so the tick that raises the loss also spawns
        // closes, and their outcomes sit ahead of the last doorbell sweep's in the
        // loop's queue — the sweep is issued inside the final iteration and its
        // outcome, which carries the health report counted below, lands after that
        // iteration's drain. Without this the count reads two, which looks exactly
        // like a sweep that never ran. What is counted is unchanged: the driver's own
        // reports, not loop iterations.
        advance(&wall, Duration::from_secs(1)).await;
        for e in drain(&mut evt_rx) {
            match e {
                DmEvent::ChannelLost { event, .. } => raised.push(event),
                DmEvent::DoorbellHealth { outcome, .. } if outcome.attempted > 0 => {
                    swept += 1;
                }
                _ => {}
            }
        }

        // The DRIVER swept three times, counted from its own health reports.
        // Counting loop iterations instead would not be a control at all: the
        // `advance` calls could be deleted and the count would still read three,
        // leaving the idempotence assertion below to pass on a driver that never
        // re-read the doorbell.
        assert_eq!(swept, 3, "the re-delivery sweeps did not run");

        assert_eq!(raised.len(), 1, "expected one teardown, got {raised:?}");
        // The cause-to-key mapping itself is core's, pinned there against every
        // cause; this asserts the driver hands over the key that mapping gives
        // for the cause this path produces.
        assert_eq!(
            raised[0],
            daemonseed_core::trust_events::TrustEventKey::DmCorrespondentStateLost
        );
        // Loud is the taxonomy's word: persistent-non-blocking reappears at
        // every start and is written to the audit log, and ISC-A-C12 forbids
        // suppressing either. A transient key would be droppable by the log
        // itself, which is the silence this event exists to end.
        assert_eq!(
            daemonseed_core::trust_events::class_of(raised[0]),
            daemonseed_core::trust_events::TrustEventClass::PersistentNonBlocking
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T13. An invite-only policy with no spent-token store is refused at
    /// construction.
    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "needs DmDriverParts::spent_tokens")]
    async fn invite_only_without_a_spent_store_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let mut p = parts(&dir, &wall, dht);
        p.cfg.policy = AdmissionPolicy::InviteOnly;
        let _ = DmDriver::spawn(p);
    }

    /// Every refusal in `events`, by reason.
    fn refusals(events: &[DmEvent]) -> Vec<RefusalReason> {
        events
            .iter()
            .filter_map(|e| match e {
                DmEvent::Refused { reason, .. } => Some(*reason),
                _ => None,
            })
            .collect()
    }

    /// The parts for a named identity, so two drivers can face each other over
    /// one shared record store.
    ///
    /// [`parts`] is this with the oracle identity fixed; both go through here so
    /// a two-driver oracle and a one-driver one are configured identically.
    fn parts_as(
        keys: IdentityKeys,
        dir: &std::path::Path,
        wall: &Arc<AtomicI64>,
        dht: Arc<MockDht>,
    ) -> DmDriverParts<MockDht> {
        let clock = WallClock::from_fn({
            let w = wall.clone();
            move || w.load(Ordering::SeqCst)
        });
        DmDriverParts {
            dht,
            clock,
            identity: DmIdentity {
                signing: Arc::new(keys.signing),
                kem: keys.kem,
                doorbell_slot_secret: keys.dm_doorbell_slot_secret,
            },
            persist: DmPersist::open(dir.join("dm"), &AT_REST).expect("persist opens"),
            cfg: DmDriverConfig {
                idle_tick: IDLE_TICK,
                policy: AdmissionPolicy::Open,
                pow_difficulty: PowDifficulty::reduced_for_test(TEST_POW_BITS),
                arm_page_watches: true,
            },
            spent_tokens: None,
        }
    }

    /// A key record for `keys`, as that identity would publish it.
    fn key_record_for(keys: &IdentityKeys) -> Vec<u8> {
        keyrec::build_encoded(
            &keys.signing,
            keys.kem.encapsulation_key(),
            keyrec::DM_KEY_RECORD_VERSION,
            keyrec::DM_KEY_RECORD_INVITE_ONLY,
        )
        .expect("key record")
    }

    /// The bodies of every `Message` in `events`.
    fn messages(events: &[DmEvent]) -> Vec<(u64, String)> {
        events
            .iter()
            .filter_map(|e| match e {
                DmEvent::Message { seq, body, .. } => Some((*seq, body.clone())),
                _ => None,
            })
            .collect()
    }

    /// The last `ChannelHealth` in `events`, if the driver emitted one.
    #[allow(clippy::type_complexity)]
    fn last_health(events: &[DmEvent]) -> Option<(u64, u64, u64, u64, u64, u64, u64)> {
        events.iter().rev().find_map(|e| match e {
            DmEvent::ChannelHealth {
                partial_sweeps,
                already_consumed,
                unopenable,
                peer_pseudonym_unknown,
                peer_acks_deferred,
                peer_acks_clipped,
                peer_acks_unverified,
                ..
            } => Some((
                *partial_sweeps,
                *already_consumed,
                *unopenable,
                *peer_pseudonym_unknown,
                *peer_acks_deferred,
                *peer_acks_clipped,
                *peer_acks_unverified,
            )),
            _ => None,
        })
    }

    /// The acknowledgement fetches `with`'s last `ChannelHealth` in `events`
    /// counted as answered with an error, or zero where it emitted none.
    ///
    /// Keyed on the correspondent, because the counters are per-correspondence
    /// and a driver holding two of them interleaves their reports.
    fn failed_ack_fetches(
        events: &[DmEvent],
        with: &[u8; daemonseed_core::identity::keys::IDENTITY_PK_LEN],
    ) -> u64 {
        events
            .iter()
            .rev()
            .find_map(|e| match e {
                DmEvent::ChannelHealth {
                    with: reported,
                    peer_ack_fetches_failed,
                    ..
                } if reported.as_ref() == with => Some(*peer_ack_fetches_failed),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// The sequence numbers reported undelivered in `events`.
    fn undelivered(events: &[DmEvent]) -> Vec<u64> {
        deliveries(events)
            .into_iter()
            .filter(|(_, state)| *state == DeliveryState::Undelivered)
            .map(|(seq, _)| seq)
            .collect()
    }

    /// The delivery states in `events`, as `(seq, state)`.
    fn deliveries(events: &[DmEvent]) -> Vec<(u64, DeliveryState)> {
        events
            .iter()
            .filter_map(|e| match e {
                DmEvent::Delivery { seq, state, .. } => Some((*seq, *state)),
                _ => None,
            })
            .collect()
    }

    /// The one correspondence label in `store`, or a panic naming what was there.
    fn only_label(store: &DmPersist) -> daemonseed_core::storage::dm_store::CorrespondenceLabel {
        let labels = store.store().correspondences().expect("list");
        assert_eq!(labels.len(), 1, "expected exactly one correspondence");
        labels[0]
    }

    /// One cadence, plus enough virtual time for the operations it started to
    /// come back.
    ///
    /// The cadence alone only *starts* a sweep or a publish; the mock's injected
    /// latency has to elapse before its outcome reaches the machine, and a test
    /// that advanced only to the tick would read the state of a driver that had
    /// asked for everything and heard nothing.
    async fn cadence(wall: &Arc<AtomicI64>) {
        advance(wall, IDLE_TICK).await;
        advance(wall, Duration::from_millis(500)).await;
        settle().await;
    }

    /// T23. Two drivers over one record store: A knocks, B accepts, A sends,
    /// B collects the body exactly once.
    ///
    /// **The one oracle where nothing is a fixture.** Every other test here
    /// hands one side a value the other side did not produce. Here the knock B
    /// admits is the knock A's mint wrote, the page B sweeps is the record A's
    /// publish wrote, and the key B opens the frame with is the one B's own
    /// ratchet derived from the secret A encapsulated. A break anywhere in that
    /// chain fails here and, mostly, nowhere else.
    ///
    /// **Exactly once is the property, not merely once.** The second tick
    /// re-sweeps the same page and re-presents the same frame, because a sender
    /// re-seeds until acknowledged — so a driver that folded on arrival rather
    /// than on settlement would emit the body twice. The `already_consumed`
    /// count is what separates "the re-seed was seen and skipped" from "the
    /// re-sweep never happened".
    ///
    /// **Both directions, and the reply direction is the harder one.** A
    /// channel frame carries no pseudonym key, so A cannot verify anything B
    /// writes until B's ACCEPT — the acceptor's own sequence zero, whose sealed
    /// body carries `PK_pc_B` and its long-term binding — reaches A by sweep.
    /// The round trip below is therefore not symmetric: A→B needs only the
    /// knock; B→A needs the acceptance to have landed, been verified against
    /// the key A knocked at, and installed. Every step of that runs here for
    /// real.
    #[tokio::test(start_paused = true)]
    async fn two_drivers_carry_a_round_trip_end_to_end_exactly_once() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        // Each side answers a key-record fetch with the OTHER side's record.
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        dht_b.set_key_record(Some(key_record_for(&a_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let store_a = DmPersist::open(dir_a.path().join("dm"), &AT_REST).expect("persist A");
        let store_b = DmPersist::open(dir_b.path().join("dm"), &AT_REST).expect("persist B");
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );

        // ── A knocks ─────────────────────────────────────────────────────────
        handle_a
            .send(DmCommand::FirstContact {
                recipient: Box::new(*b_keys.signing.public_key()),
                body: "knock knock".into(),
            })
            .await
            .expect("first contact");
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe_a, 3).await;
        assert_eq!(
            dht_a.count(Method::PublishDoorbell),
            1,
            "A must have written the knock into the shared store"
        );
        // **A's provisional record survives its own knock.** The context is
        // proven correct by the fact that it resumes here, which is what makes
        // the same read after the acceptance mean something.
        let label_a = only_label(&store_a);
        let keyrec_addr = *keyrec::derive_owner_seed(b_keys.signing.public_key())
            .expect("keyrec seed")
            .as_bytes();
        let ctx_a = daemonseed_core::dm::provisional::RecordContext {
            recipient_keyrec_addr: &keyrec_addr,
            fc_epoch: keyrec::fc_epoch(u64::try_from(BASE_MS / 1000).unwrap_or(0)),
        };
        assert!(
            matches!(
                store_a.restart_channel(&label_a, &ctx_a),
                daemonseed_core::dm::persist::StoredChannelRestart::HandshakeResumes(_)
            ),
            "A consumed the record the acceptance window needs"
        );

        // ── B sweeps its doorbell and is offered the request ─────────────────
        cadence(&wall).await;
        let events = drain(&mut evt_b);
        let (request, from, body) = only_request(&events);
        assert_eq!(body, "knock knock", "B was shown the body A sent");
        assert_eq!(
            from,
            a_keys.signing.public_key().to_vec(),
            "B was shown A as the sender"
        );

        // ── B accepts ────────────────────────────────────────────────────────
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;
        let label_b = only_label(&store_b);

        // ── A sends on the channel ───────────────────────────────────────────
        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "the first channel message".into(),
            })
            .await
            .expect("send");
        settle().await;
        let composed = deliveries(&drain(&mut evt_a));
        assert!(
            composed.contains(&(1, DeliveryState::Composed)),
            "A must report sequence one composed, got {composed:?}"
        );
        // The tick is what publishes: the send queues, the cadence emits.
        cadence(&wall).await;
        assert!(
            dht_a.count(Method::PublishPage) >= 1,
            "A must have published its channel page"
        );

        // ── B collects ───────────────────────────────────────────────────────
        cadence(&wall).await;
        cadence(&wall).await;
        let collected = drain(&mut evt_b);
        let bodies = messages(&collected);
        assert_eq!(
            bodies.len(),
            1,
            "B must emit exactly one message, got {bodies:?} from {collected:?}"
        );
        assert_eq!(
            bodies[0],
            (1, "the first channel message".to_string()),
            "B must recover the sequence and the body A sent"
        );
        assert!(
            dht_b.count(Method::SweepPage) >= 1,
            "B must actually have swept, or the single message above is vacuous"
        );

        // ── the re-seed is seen and skipped ──────────────────────────────────
        //
        // **The settled set is what skips it, not the ratchet.** A sender
        // re-seeds until acknowledged, so the same bytes sit in the same slot
        // and come back on every sweep; `Collection::observe_page` filters a
        // position it has already settled out of the unsettled list, so the
        // frame is never offered to the ratchet a second time and
        // `RatchetError::AlreadyConsumed` never fires on this path. The count
        // of sweeps is the positive control: without it, "no second message" is
        // satisfied by a driver that stopped sweeping.
        let swept_before = dht_b.count(Method::SweepPage);
        for _ in 0..3 {
            cadence(&wall).await;
        }
        let again = drain(&mut evt_b);
        assert!(
            dht_b.count(Method::SweepPage) > swept_before,
            "B must have kept sweeping the page the re-seed lands in"
        );
        assert_eq!(
            messages(&again),
            Vec::new(),
            "B emitted the same body twice under the sender's re-seed"
        );
        assert_eq!(
            last_health(&again).map_or((0, 0), |h| (h.0, h.2)),
            (0, 0),
            "a re-swept page that folds nothing must report no partial sweep and \
             nothing unopenable"
        );

        // **The piggybacked acknowledgement is folded, not deferred.** A's frame
        // carries A's own collection state, so B has one to merge on the first
        // message of the conversation; a non-zero `peer_acks_deferred` would mean
        // the merge was refused, and B settles nothing when that happens. What
        // the fold then confirms is asserted where a real claim exists —
        // `an_ack_settles_the_senders_outbox_exactly_once` — because A had
        // collected nothing at the moment it sealed this one.
        assert_eq!(
            last_health(&collected).map_or(0, |h| h.4),
            0,
            "B deferred a piggybacked acknowledgement instead of folding it: {collected:?}"
        );

        // ── A collects B's ACCEPT and installs the pseudonym ─────────────────
        //
        // **Nothing here was sent by a command.** B's acceptance was composed
        // by the accept above, published by B's own cadence, and swept by A's
        // — so what A opens is the frame B's `seal_accept` wrote, under a key
        // A's ratchet derived, verified against the long-term key A knocked at
        // and nothing else. It surfaces as a message at sequence zero with an
        // empty body, which is the acceptance's shape.
        for _ in 0..3 {
            cadence(&wall).await;
        }
        let accepted = drain(&mut evt_a);
        assert_eq!(
            messages(&accepted),
            vec![(0, String::new())],
            "A must collect B's acceptance at sequence zero: {accepted:?}"
        );
        assert!(
            dht_a.count(Method::SweepPage) >= 1,
            "A must actually have swept, or the acceptance above is vacuous"
        );
        // **The record the acceptance window existed for is gone**, and only
        // now — the same read resumed before the knock's reply arrived. The
        // answer is `Established` rather than a teardown because the
        // establishment wrote a resume record, and the loader reads that first:
        // a resume record present is authority, whatever is or is not beside it.
        assert!(
            matches!(
                store_a.restart_channel(&label_a, &ctx_a),
                daemonseed_core::dm::persist::StoredChannelRestart::Established(_)
            ),
            "A's correspondence did not become established on a verified acceptance"
        );
        assert!(
            matches!(
                store_a.store().read_unlocked(
                    &label_a,
                    daemonseed_core::storage::dm_store::RecordKind::Provisional,
                ),
                Ok(None)
            ),
            "A's provisional record survived a verified acceptance"
        );

        // ── B replies, and A can now verify it ───────────────────────────────
        //
        // The other half of the round trip, and the half that was unreachable
        // before the acceptance: A verifies this frame under the pseudonym it
        // just installed, so a break anywhere from `seal_accept` through
        // `open_accept` to the pinned `open` lands here.
        handle_b
            .send(DmCommand::Send {
                to: Box::new(*a_keys.signing.public_key()),
                body: "and a reply".into(),
            })
            .await
            .expect("B sends");
        for _ in 0..3 {
            cadence(&wall).await;
        }
        let a_events = drain(&mut evt_a);
        assert_eq!(
            messages(&a_events),
            vec![(1, "and a reply".to_string())],
            "A must recover exactly B's reply, once, with its exact body: {a_events:?}"
        );
        assert!(
            dht_b.count(Method::PublishPage) >= 2,
            "B must have written both its acceptance and its reply"
        );
        // Silence is the healthy state: a `ChannelHealth` fires only when a
        // counter moves, so a fold that refused nothing emits nothing at all.
        assert_eq!(
            last_health(&a_events).map_or((0, 0), |h| (h.0, h.2)),
            (0, 0),
            "A's collection must report no partial sweep and nothing unopenable \
             once the pseudonym is installed: {a_events:?}"
        );
        // And B's own record still holds one correspondence, so the reply went
        // out on the channel rather than establishing a second one.
        assert_eq!(only_label(&store_b), label_b);

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// Establish this driver as the initiator of one correspondence with
    /// `peer`, and hand back the label its records live under.
    ///
    /// The whole outbound first-contact path runs: fetch, mint, persist,
    /// establish, queue sequence zero, publish. Nothing is faked, so an oracle
    /// built on this is testing the channel plane over a channel the driver
    /// really opened.
    async fn establish_as_initiator(
        handle: &DmDriverHandle,
        probe: &DmDriverProbe,
        wall: &Arc<AtomicI64>,
        store: &DmPersist,
        peer: &IdentityKeys,
    ) -> daemonseed_core::storage::dm_store::CorrespondenceLabel {
        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "knock".into(),
            })
            .await
            .expect("first contact");
        advance(wall, Duration::from_millis(100)).await;
        settle_steps(probe, 3).await;
        // A fourth step, on its own advance: the doorbell write's own outcome,
        // which is what confirms sequence zero. Its latency has not elapsed at
        // the third.
        advance(wall, Duration::from_millis(200)).await;
        settle_steps(probe, 4).await;
        only_label(store)
    }

    /// T24. A send onto a full outbox is refused, and refused *before* the
    /// ratchet moves.
    ///
    /// **The second half is the whole point.** `Ratchet::send_next` has no step
    /// backwards, so a refusal taken after it has burnt a sequence number that
    /// will never be transmitted — and a receiver's contiguous prefix then waits
    /// on that number for seven days while every later message piles up beyond
    /// it. So the assertions are: the refusal names the outbox, nothing was
    /// published, and the sequence number the send would have used is still
    /// unspent, which is what a later send proves by taking it.
    ///
    /// The fill loop's own count is the positive control: a record that refused
    /// the first entry would leave `filled` at zero and fail below.
    #[tokio::test(start_paused = true)]
    async fn a_send_onto_a_full_outbox_is_refused_before_the_ratchet_steps() {
        use daemonseed_core::dm::frame::WORST_CASE_SEALED_FRAME_LEN;
        use daemonseed_core::dm::outbox::{OutboxTarget, SealedFrame};
        use daemonseed_core::dm::persist::Mutation;

        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.set_key_record(Some(key_record_for(&peer)));
        let probe = Arc::new(DmDriverProbe::new());
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let (handle, mut evt_rx, task) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir.path(), &wall, dht.clone()),
            probe.clone(),
        );
        let label = establish_as_initiator(&handle, &probe, &wall, &store, &peer).await;
        drop(drain(&mut evt_rx));

        // Fill the record from outside the driver, at sequence numbers well
        // above the one the next send will want, so the refusal below is about
        // capacity and not about the sequence space.
        let now = wall.load(Ordering::SeqCst);
        let direction = store
            .read_outbox(&label, now)
            .expect("the outbox reads")
            .expect("the knock is queued")
            .direction();
        let mut filled = 0u64;
        for seq in 100..1_000u64 {
            let wrote = store.update_outbox(&label, direction, now, |outbox| {
                Ok(Mutation::Changed(
                    outbox
                        .enqueue_sealed(
                            seq,
                            OutboxTarget::ChannelPage,
                            now,
                            SealedFrame::new(vec![0xA5; WORST_CASE_SEALED_FRAME_LEN]),
                            0,
                        )
                        .is_ok(),
                ))
            });
            match wrote {
                Ok(true) => filled += 1,
                _ => break,
            }
        }
        assert!(filled > 50, "the record took only {filled} entries to fill");

        let published_before = dht.count(Method::PublishPage);
        // The ratchet's own position, read before the refusal. It is the only
        // observable that can see a step: a send refused after `send_next` has
        // run writes nothing, emits nothing and changes no record.
        let before_seq = probe.next_send_seq.load(Ordering::SeqCst);
        assert_eq!(
            before_seq,
            daemonseed_core::dm::ratchet::FIRST_INITIATOR_CHANNEL_SEQ,
            "the initiator's first channel sequence is one; sequence zero went by \
             doorbell"
        );
        handle
            .send(DmCommand::Send {
                to: Box::new(*peer.signing.public_key()),
                body: "no room".into(),
            })
            .await
            .expect("send");
        settle().await;
        let events = drain(&mut evt_rx);
        let full: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                DmEvent::Refused {
                    reason: RefusalReason::OutboxFull { needed },
                    ..
                } => Some(*needed),
                _ => None,
            })
            .collect();
        assert_eq!(
            full.len(),
            1,
            "expected exactly one full-outbox refusal, got {events:?}"
        );
        assert!(
            full[0] > daemonseed_core::storage::dm_store::OUTBOX_CAPACITY,
            "the refusal must name what the record would have needed, got {}",
            full[0]
        );
        assert_eq!(
            deliveries(&events),
            Vec::new(),
            "a refused send must report no delivery state at all"
        );
        assert_eq!(
            probe.next_send_seq.load(Ordering::SeqCst),
            before_seq,
            "the refused send stepped the ratchet, burning a sequence number \
             nothing will ever transmit"
        );

        // Nothing went out, and nothing was spent.
        advance(&wall, Duration::from_millis(100)).await;
        settle().await;
        assert_eq!(
            dht.count(Method::PublishPage),
            published_before,
            "a refused send published a page"
        );
        let outbox = store
            .read_outbox(&label, wall.load(Ordering::SeqCst))
            .expect("the outbox reads")
            .expect("the outbox exists");
        assert!(
            outbox.entry(1).is_none(),
            "the refused send left an entry behind at the sequence it would have used"
        );

        // The ratchet did not move: the next send takes the sequence number the
        // refused one would have taken. Asserted through a store that has been
        // emptied of the filler, so this is the same driver and the same
        // ratchet, not a second one.
        for seq in 100..(100 + filled) {
            store
                .update_outbox(&label, direction, wall.load(Ordering::SeqCst), |outbox| {
                    if let Some(entry) = outbox.entry_mut(seq) {
                        let _ = entry.confirm_written(wall.load(Ordering::SeqCst));
                    }
                    Ok(Mutation::Changed(()))
                })
                .expect("the filler confirms");
        }
        // Confirming does not free the frame, so the record is still full; the
        // sequence-number claim is what this asserts, and it is asserted by the
        // refusal naming the same sequence again.
        handle
            .send(DmCommand::Send {
                to: Box::new(*peer.signing.public_key()),
                body: "still no room".into(),
            })
            .await
            .expect("send");
        settle().await;
        let again = drain(&mut evt_rx);
        assert_eq!(
            again
                .iter()
                .filter(|e| matches!(
                    e,
                    DmEvent::Refused {
                        reason: RefusalReason::OutboxFull { .. },
                        ..
                    }
                ))
                .count(),
            1,
            "the second send must be refused the same way, got {again:?}"
        );
        assert!(
            store
                .read_outbox(&label, wall.load(Ordering::SeqCst))
                .expect("the outbox reads")
                .expect("the outbox exists")
                .entry(1)
                .is_none(),
            "two refused sends between them consumed a sequence number"
        );
        assert_eq!(
            probe.next_send_seq.load(Ordering::SeqCst),
            before_seq,
            "two refusals between them moved the ratchet"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T25. A due entry is emitted and confirmed; a write that fails leaves it
    /// due and it is emitted again once the backoff has elapsed.
    ///
    /// **`confirm_written` is what makes an emission stop being a claim.** An
    /// entry whose write was never confirmed re-seeds on the ladder for the
    /// whole seven-day window; one that was confirmed reports `OnDht`. The
    /// failing half is the control for the succeeding half: the same entry, the
    /// same ladder, and the only difference is whether the transport said the
    /// bytes landed.
    #[tokio::test(start_paused = true)]
    async fn a_failed_publish_leaves_the_entry_due_and_re_emits() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        // The doorbell write still succeeds, so first contact establishes; only
        // the channel write fails.
        let dht = Arc::new(MockDht::failing(
            Duration::from_millis(50),
            Method::PublishPage,
        ));
        let peer = peer_keys();
        dht.set_key_record(Some(key_record_for(&peer)));
        let probe = Arc::new(DmDriverProbe::new());
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let (handle, mut evt_rx, task) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir.path(), &wall, dht.clone()),
            probe.clone(),
        );
        let _label = establish_as_initiator(&handle, &probe, &wall, &store, &peer).await;

        // The knock's own write DID land, so sequence zero confirms. That is the
        // positive control for the failing half below: the same code path, the
        // same tick, and a different answer from the transport.
        let established = drain(&mut evt_rx);
        assert!(
            deliveries(&established).contains(&(0, DeliveryState::OnDht)),
            "the knock's confirmed write must report OnDht, got {established:?}"
        );

        handle
            .send(DmCommand::Send {
                to: Box::new(*peer.signing.public_key()),
                body: "into a failing transport".into(),
            })
            .await
            .expect("send");
        settle().await;
        drop(drain(&mut evt_rx));

        cadence(&wall).await;
        let first = dht.count(Method::PublishPage);
        assert_eq!(first, 1, "the due entry must have been emitted once");
        let after_failure = drain(&mut evt_rx);
        assert!(
            !deliveries(&after_failure).contains(&(1, DeliveryState::OnDht)),
            "a failed write must not confirm the entry, got {after_failure:?}"
        );

        // The first rung is sixty seconds, jittered; four cadences of thirty
        // seconds each carry the clock past it whatever the jitter drew.
        for _ in 0..4 {
            cadence(&wall).await;
        }
        assert!(
            dht.count(Method::PublishPage) > first,
            "the unconfirmed entry must be emitted again once its rung elapsed"
        );
        // **The identical bytes, not merely another write.** A re-seed that
        // re-sealed would mint a second authentic frame at one ratchet position;
        // the outbox holds the sealed frame precisely so the second emission is
        // the first one again.
        let written = dht.published_pages();
        assert!(
            written.len() >= 2,
            "expected at least two page writes, got {}",
            written.len()
        );
        assert_eq!(
            written[0].0, written[1].0,
            "the re-seed must land at the position the first write did"
        );
        assert_eq!(
            written[0].1, written[1].1,
            "the re-seed must carry byte-identical bytes"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T26. A partial page sweep folds nothing: no message, and the cursor does
    /// not move.
    ///
    /// **A page the transport did not read every slot of cannot say a position
    /// is absent**, only that it was not seen — and advancing on that reading
    /// walks past messages that were there, which no later sweep revisits. The
    /// bytes ARE in the record and the sweep DOES return them, which is what
    /// makes this a real test: the only thing standing between the driver and a
    /// message it could have emitted is the outcome it was given.
    #[tokio::test(start_paused = true)]
    async fn a_partial_sweep_folds_nothing() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let _a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        // B's sweeps come back incomplete. Its doorbell sweep is unaffected —
        // only page sweeps carry the partial outcome — so the knock still lands.
        let dht_b = Arc::new(MockDht::partial_on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let store_a = DmPersist::open(dir_a.path().join("dm"), &AT_REST).expect("persist A");
        let store_b = DmPersist::open(dir_b.path().join("dm"), &AT_REST).expect("persist B");
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );
        let _ = establish_as_initiator(&handle_a, &probe_a, &wall, &store_a, &b_keys).await;
        drop(drain(&mut evt_a));

        cadence(&wall).await;
        let (request, _, _) = only_request(&drain(&mut evt_b));
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;
        let label_b = only_label(&store_b);

        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "into a half-read page".into(),
            })
            .await
            .expect("send");
        settle().await;
        for _ in 0..4 {
            cadence(&wall).await;
        }

        let events = drain(&mut evt_b);
        assert!(
            dht_b.count(Method::SweepPage) > 0,
            "B must have swept, or folding nothing proves nothing"
        );
        // The call counter alone cannot tell a sweep that returned nothing from
        // one that returned the frame and was refused for its outcome. This
        // does: the bytes really were handed to the driver.
        assert!(
            dht_b.slots_served() > 0,
            "B was never offered a populated slot, so the fold below is vacuous"
        );
        assert_eq!(
            messages(&events),
            Vec::new(),
            "a partial sweep folded a message: {events:?}"
        );
        let health = last_health(&events).expect("B must report the partial sweeps");
        assert!(
            health.0 > 0,
            "B must count the partial sweeps it refused, got {health:?}"
        );
        assert!(
            store_b
                .read_cursor(&label_b, u64::from(u32::MAX))
                .expect("the cursor reads")
                .is_none(),
            "a partial sweep moved the receive cursor"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// T27. An entry past the seven-day window is surfaced as undelivered once
    /// per run, stays owed until the front end answers, and is re-offered to a
    /// driver that restarted before it did.
    ///
    /// **The record's flag is NOT cleared by the sweep that set it** (#279).
    /// Clearing in the same write puts the obligation out of the record while
    /// the notification is still in a `Vec` somebody is carrying, so a crash in
    /// between loses it silently. What stops the same run repeating itself is an
    /// in-memory set, which a restart empties — and the restart half of this
    /// oracle is what separates the two mechanisms: a driver that cleared
    /// durably would be silent after the restart, and one with no suppression at
    /// all would repeat on the very next cadence.
    ///
    /// Run from the ACCEPTOR's side, because that is the side whose
    /// correspondence survives a restart at all: `accept_first_contact` writes a
    /// contact record and an initiator writes none, so a restarted driver has
    /// nothing to recover an initiator's outbox by.
    #[tokio::test(start_paused = true)]
    async fn a_give_up_is_offered_once_per_run_and_re_offered_after_a_restart() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        // B's channel writes never land, so what it sends is never confirmed and
        // crosses the give-up.
        let dht_b = Arc::new(MockDht::failing_on(
            net.clone(),
            Duration::from_millis(50),
            Method::PublishPage,
        ));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let store_a = DmPersist::open(dir_a.path().join("dm"), &AT_REST).expect("persist A");
        let store_b = DmPersist::open(dir_b.path().join("dm"), &AT_REST).expect("persist B");
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );
        let _ = establish_as_initiator(&handle_a, &probe_a, &wall, &store_a, &b_keys).await;
        drop(drain(&mut evt_a));
        cadence(&wall).await;
        let (request, _, _) = only_request(&drain(&mut evt_b));
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;
        let label_b = only_label(&store_b);

        handle_b
            .send(DmCommand::Send {
                to: Box::new(*a_keys.signing.public_key()),
                body: "never collected".into(),
            })
            .await
            .expect("send");
        settle().await;
        drop(drain(&mut evt_b));

        advance(
            &wall,
            Duration::from_millis(daemonseed_core::dm::outbox::GIVE_UP_MS as u64 + 1_000),
        )
        .await;
        cadence(&wall).await;
        let events = drain(&mut evt_b);
        // **Two entries, not one.** Sequence zero is the acceptance the accept
        // itself queued, and sequence one is the message sent above; B's page
        // writes never land, so both cross the window. An acceptance is an
        // outbox entry like any other and gives up on the same ladder.
        assert_eq!(
            undelivered(&events),
            vec![0, 1],
            "the acceptor's acceptance and first message crossed the window: {events:?}"
        );

        // Still owed in the record: the user has not answered yet.
        assert_eq!(
            store_b
                .read_outbox(&label_b, wall.load(Ordering::SeqCst))
                .expect("the outbox reads")
                .expect("the outbox exists")
                .owed_surfacings(),
            vec![0, 1],
            "the sweep cleared the durable flag before the user was told (#279)"
        );

        // Not repeated inside this run. The tick count is the liveness control:
        // without it, "nothing more was said" is satisfied by a driver that
        // stopped ticking.
        let ticks_before = probe_b.ticks.load(Ordering::SeqCst);
        cadence(&wall).await;
        let after = drain(&mut evt_b);
        assert!(
            probe_b.ticks.load(Ordering::SeqCst) > ticks_before,
            "the driver stopped ticking, so the silence below means nothing"
        );
        assert_eq!(
            undelivered(&after),
            Vec::<u64>::new(),
            "the give-up was offered twice in one run: {after:?}"
        );

        // A restart before the front end answered re-offers it.
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_b.await.expect("B ends");
        let probe_b2 = Arc::new(DmDriverProbe::new());
        let (handle_b2, mut evt_b2, task_b2) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b2.clone(),
        );
        cadence(&wall).await;
        let restarted = drain(&mut evt_b2);
        assert_eq!(
            undelivered(&restarted),
            vec![0, 1],
            "a crash between the give-up and the user seeing it lost the \
             notification: {restarted:?}"
        );

        // And the front end's answer clears it for good.
        handle_b2
            .send(DmCommand::Surfaced {
                to: Box::new(*a_keys.signing.public_key()),
                seqs: vec![0, 1],
            })
            .await
            .expect("surfaced");
        settle().await;
        assert_eq!(
            store_b
                .read_outbox(&label_b, wall.load(Ordering::SeqCst))
                .expect("the outbox reads")
                .expect("the outbox exists")
                .owed_surfacings(),
            Vec::<u64>::new(),
            "the front end's answer did not clear the durable flag"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b2.send(DmCommand::Shutdown).await.expect("stop B2");
        task_a.await.expect("A ends");
        task_b2.await.expect("B2 ends");
    }

    /// T28. A driver started over a store that already holds a correspondence
    /// lists it, seeds its collection from the persisted cursor, and refuses to
    /// send on it.
    ///
    /// **A ratchet has no at-rest record**, and the pseudonym pair is homed in a
    /// resume record that cannot be written until the channel has re-established
    /// once — so a correspondence that outlived its process is on disk and
    /// cannot be spoken on. The driver says so in as many words rather than
    /// queueing a message that will never move.
    ///
    /// **The cursor is read against a `read_through` of zero**, which is what
    /// the new session has genuinely swept, so a stored page above zero is
    /// refused rather than believed — the record is unsealed by design and a
    /// number checked against itself is not a bound. The resumed frontier is
    /// therefore page zero rather than the page the file names, and that is the
    /// property asserted here: `Some(0)`, not `None`, which is what a collection
    /// built by `Collection::new()` would report.
    #[tokio::test(start_paused = true)]
    async fn a_correspondence_from_a_previous_session_is_seeded_and_refused() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let store_a = DmPersist::open(dir_a.path().join("dm"), &AT_REST).expect("persist A");
        let store_b = DmPersist::open(dir_b.path().join("dm"), &AT_REST).expect("persist B");
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );
        let _ = establish_as_initiator(&handle_a, &probe_a, &wall, &store_a, &b_keys).await;
        drop(drain(&mut evt_a));
        cadence(&wall).await;
        let (request, _, _) = only_request(&drain(&mut evt_b));
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;
        let label_b = only_label(&store_b);

        // A cursor the previous session genuinely earned: it is written with the
        // same page as its own corroboration, exactly as a driver that had swept
        // through page seven would have written it.
        assert!(
            store_b
                .advance_cursor(&label_b, 7, 7)
                .expect("the cursor writes")
                .moved(),
            "the fixture cursor did not advance, so the restart below reads nothing"
        );

        // A queued knock and a queued channel message, both unconfirmed. The
        // knock's address is a pure function of the correspondent's public key
        // and its bytes are in the record, so a restarted driver can and must
        // keep re-seeding it; the channel entry's address descends from a
        // ratchet nobody holds any more, so it must be left alone rather than
        // having its backoff advanced for a write that cannot happen.
        const RESEED_SLOT: u16 = 3;
        let knock_bytes = vec![0x5Au8; 128];
        let direction_b = store_b
            .read_outbox(&label_b, wall.load(Ordering::SeqCst))
            .expect("the outbox reads")
            .map_or(daemonseed_core::dm::ratchet::Direction::AToB, |o| {
                o.direction()
            });
        for (seq, target) in [
            (
                5u64,
                daemonseed_core::dm::outbox::OutboxTarget::Doorbell { slot: RESEED_SLOT },
            ),
            (6u64, daemonseed_core::dm::outbox::OutboxTarget::ChannelPage),
        ] {
            store_b
                .update_outbox(
                    &label_b,
                    direction_b,
                    wall.load(Ordering::SeqCst),
                    |outbox| {
                        outbox.enqueue_sealed(
                            seq,
                            target,
                            wall.load(Ordering::SeqCst),
                            daemonseed_core::dm::outbox::SealedFrame::new(knock_bytes.clone()),
                            0,
                        )?;
                        Ok(daemonseed_core::dm::persist::Mutation::Changed(()))
                    },
                )
                .expect("the fixture entry is queued");
        }

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
        drop(drain(&mut evt_b));

        let probe_b2 = Arc::new(DmDriverProbe::new());
        let (handle_b2, mut evt_b2, task_b2) = DmDriver::spawn_with_probe(
            parts_as(
                peer_keys(),
                dir_b.path(),
                &wall,
                Arc::new(MockDht::on(net.clone(), Duration::from_millis(50))),
            ),
            probe_b2.clone(),
        );
        // The seeding happens inside the task, so let it start before reading.
        settle().await;
        // The correspondence was recovered and its collection seeded. `Some(0)`
        // rather than `Some(7)` because the stored page has no corroboration a
        // fresh session can offer; `u64::MAX` is the marker for "no seeded
        // correspondence", which is what a driver that skipped the seeding — or
        // one whose collection was built by `Collection::new()` — would report.
        assert_eq!(
            probe_b2.resumed_frontier.load(Ordering::SeqCst),
            0,
            "the restarted driver did not seed a collection from the store"
        );

        handle_b2
            .send(DmCommand::Send {
                to: Box::new(*a_keys.signing.public_key()),
                body: "after the restart".into(),
            })
            .await
            .expect("send");
        settle().await;
        let events = drain(&mut evt_b2);
        assert_eq!(
            refusals(&events),
            vec![RefusalReason::NotEstablishedThisSession],
            "a send on a correspondence from a previous session must be refused \
             in as many words, got {events:?}"
        );
        // The correspondence is still exactly the one that was established: the
        // refusal is about the key schedule, not about a lost record.
        assert_eq!(only_label(&store_b), label_b);

        // The second driver stops before the third starts: two drivers over one
        // store would race for the same due entries, and whichever emitted first
        // would leave the other with nothing to find.
        handle_b2.send(DmCommand::Shutdown).await.expect("stop B2");
        task_b2.await.expect("B2 ends");

        // The queued knock is re-seeded without a key schedule; the queued
        // channel entry is not, because there is no page to write it to.
        let dht_b2 = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let probe_b3 = Arc::new(DmDriverProbe::new());
        let (handle_b3, _evt_b3, task_b3) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b2.clone()),
            probe_b3.clone(),
        );
        for _ in 0..4 {
            cadence(&wall).await;
        }
        let reseeds: Vec<(u16, Vec<u8>)> = dht_b2
            .published()
            .into_iter()
            .filter(|(_, bytes)| bytes == &knock_bytes)
            .collect();
        assert!(
            !reseeds.is_empty(),
            "a queued knock stopped being re-seeded the moment its key schedule \
             was lost, so nothing would ever retry it: {:?}",
            dht_b2.log()
        );
        assert_eq!(
            reseeds[0].0, RESEED_SLOT,
            "the re-seed must go back to the slot the entry names"
        );
        assert_eq!(
            dht_b2.count(Method::PublishPage),
            0,
            "a channel entry was emitted with no ratchet to address it with"
        );

        handle_b3.send(DmCommand::Shutdown).await.expect("stop B3");
        task_b3.await.expect("B3 ends");
    }

    /// T31. A driver states the store's correspondences to the front end
    /// before it says anything else.
    ///
    /// **The seeding is otherwise invisible from outside.** A restarted driver
    /// recovers every correspondence on disk and then waits — nothing is
    /// emitted about one until its correspondent writes, which may be never —
    /// so a client that did not watch the correspondence being made has no list
    /// at all. This is the entry point for that list, and the machine's own
    /// roster is only reached through it.
    #[tokio::test(start_paused = true)]
    async fn a_driver_states_its_stored_correspondences_before_anything_else() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let store_a = DmPersist::open(dir_a.path().join("dm"), &AT_REST).expect("persist A");
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );
        // B's own first roster, over a store nothing has written: an empty list
        // is a statement, and without it "no correspondences" and "no roster"
        // are the same silence.
        settle().await;
        assert!(
            matches!(
                drain(&mut evt_b).first(),
                Some(DmEvent::Roster { correspondents }) if correspondents.is_empty()
            ),
            "a driver over an empty store said nothing about it"
        );

        let _ = establish_as_initiator(&handle_a, &probe_a, &wall, &store_a, &b_keys).await;
        drop(drain(&mut evt_a));
        cadence(&wall).await;
        let (request, _, _) = only_request(&drain(&mut evt_b));
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");

        // The restart, over the store the acceptance wrote.
        let (handle_b2, mut evt_b2, task_b2) = DmDriver::spawn_with_probe(
            parts_as(
                peer_keys(),
                dir_b.path(),
                &wall,
                Arc::new(MockDht::on(net.clone(), Duration::from_millis(50))),
            ),
            Arc::new(DmDriverProbe::new()),
        );
        settle().await;
        let events = drain(&mut evt_b2);
        let Some(DmEvent::Roster { correspondents }) = events.first() else {
            panic!("the restarted driver's first word was not its roster: {events:?}");
        };
        assert_eq!(
            correspondents.len(),
            1,
            "the roster did not name the stored correspondence: {events:?}"
        );
        assert_eq!(
            correspondents[0].pk_lt.as_slice(),
            a_keys.signing.public_key().as_slice(),
            "the roster named an identity this store does not correspond with"
        );
        assert_eq!(
            correspondents[0].state,
            CorrespondentState::Established,
            "an accepted correspondence came back as something else"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, DmEvent::Roster { .. }))
                .count(),
            1,
            "the roster was stated more than once, so a reader cannot tell which is the list"
        );

        handle_b2.send(DmCommand::Shutdown).await.expect("stop B2");
        task_b2.await.expect("B2 ends");
    }

    /// T32. A block-list record that will not read stops the driver starting,
    /// so no roster is stated over one.
    ///
    /// **The startup ordering, pinned where it is decided.** Provisioning runs
    /// on the caller's thread before the task exists and reads the record, so a
    /// record that will not read is a refusal to start rather than a roster
    /// with an empty blocked set. `DmMachine::roster` still reports an
    /// unreadable list, for a read that fails after this check passed; nothing
    /// on this path reaches it, and this test is what says so.
    #[tokio::test(start_paused = true)]
    async fn an_unreadable_block_list_refuses_the_driver_rather_than_the_roster() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));

        // The store's key derivation needs the module, which the identity
        // helpers would otherwise be the first to start.
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        store.provision_block_list().expect("provision");
        let record = store.store().root().join("block-list.bin");
        assert!(
            record.exists(),
            "no block-list record at {}",
            record.display()
        );
        std::fs::write(&record, b"not a block list").expect("the record is wrecked");
        assert!(
            store.read_block_list().is_err(),
            "the fixture's bytes still decode, so nothing below is under test"
        );

        let started = DmDriver::try_spawn_seeded(
            parts(&dir, &wall, dht),
            Arc::new(DmDriverProbe::new()),
            Vec::new(),
        );
        assert!(
            matches!(started, Err(DmSpawnError::BlockList(_))),
            "a driver started over a block-list record it cannot read"
        );
    }

    /// T33. The seeded effects reach the front end ahead of the roster.
    ///
    /// **The ordering `DmMachine::roster` relies on, driven through the seam
    /// that can produce it.** An unreadable block list makes the roster's
    /// blocked set empty because it could not be computed, not because nobody
    /// is blocked, and the alarm arriving first is the only thing separating
    /// those two readings for a front end. T32 shows the startup check refuses
    /// that store outright, so the pair is composed here from the seed instead
    /// of from a wrecked record — the claim under test is the order the shell
    /// applies effects in, which is the same either way.
    #[tokio::test(start_paused = true)]
    async fn a_seeded_event_is_stated_ahead_of_the_roster() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));

        let (handle, mut evt_rx, task) = DmDriver::spawn_seeded(
            parts(&dir, &wall, dht),
            Arc::new(DmDriverProbe::new()),
            vec![DmEffect::Emit(DmEvent::BlockListUnreadable)],
        );
        settle().await;
        let events = drain(&mut evt_rx);
        assert!(
            matches!(events.first(), Some(DmEvent::BlockListUnreadable)),
            "the roster was stated ahead of a seeded event: {events:?}"
        );
        assert!(
            matches!(
                events.get(1),
                Some(DmEvent::Roster { correspondents }) if correspondents.is_empty()
            ),
            "the seeded event was not followed by the roster: {events:?}"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// The control on [`take_startup_roster`]'s own tolerance of that pair.
    ///
    /// Every other oracle here meets a bare roster, so the branch that steps
    /// over a leading [`DmEvent::BlockListUnreadable`] would otherwise never
    /// run — and an untaken branch in a helper ten oracles depend on is a
    /// helper nobody has checked. The alarm is left where the helper consumed
    /// it: a channel that still held it afterwards would fail the emptiness
    /// assertion below.
    #[tokio::test(start_paused = true)]
    async fn the_startup_take_steps_over_a_leading_alarm() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));

        let (handle, mut evt_rx, task) = DmDriver::spawn_seeded(
            parts(&dir, &wall, dht),
            Arc::new(DmDriverProbe::new()),
            vec![DmEffect::Emit(DmEvent::BlockListUnreadable)],
        );
        take_startup_roster(&mut evt_rx).await;
        let left = drain(&mut evt_rx);
        assert!(
            left.is_empty(),
            "the startup statement was not fully consumed: {left:?}"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T29. A fresh store seeds no collection at all.
    ///
    /// The control for T28's `resumed_frontier`: without it, `0` is a number a
    /// driver that never looked at the store could also report.
    #[tokio::test(start_paused = true)]
    async fn a_fresh_store_seeds_no_correspondence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, _evt, task) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir.path(), &wall, dht.clone()),
            probe.clone(),
        );
        settle().await;
        assert_eq!(
            probe.resumed_frontier.load(Ordering::SeqCst),
            u64::MAX,
            "an empty store must seed no correspondence"
        );
        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T30. A frame that does not authenticate is counted and leaves its slot
    /// unsettled.
    ///
    /// **Not abandoned.** Abandonment settles a position permanently and is the
    /// sender's give-up signal, not a reader's verdict on bytes it could not
    /// open. Page owner-write authority is symmetric, so anyone can write a
    /// slot, and a frame that fails the authorship signature says nothing about
    /// the frame that may yet arrive there.
    #[tokio::test(start_paused = true)]
    async fn a_tampered_frame_is_counted_and_settles_nothing() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let _a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::tampering_on(
            net.clone(),
            Duration::from_millis(50),
        ));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let store_a = DmPersist::open(dir_a.path().join("dm"), &AT_REST).expect("persist A");
        let store_b = DmPersist::open(dir_b.path().join("dm"), &AT_REST).expect("persist B");
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );
        let _ = establish_as_initiator(&handle_a, &probe_a, &wall, &store_a, &b_keys).await;
        drop(drain(&mut evt_a));
        cadence(&wall).await;
        let (request, _, _) = only_request(&drain(&mut evt_b));
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;
        let label_b = only_label(&store_b);

        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "tampered in flight".into(),
            })
            .await
            .expect("send");
        settle().await;
        for _ in 0..4 {
            cadence(&wall).await;
        }

        let events = drain(&mut evt_b);
        assert!(
            dht_b.slots_served() > 0,
            "B was never offered the tampered frame, so the silence proves nothing"
        );
        assert_eq!(
            messages(&events),
            Vec::new(),
            "a frame that does not authenticate was emitted as a message: {events:?}"
        );
        let health = last_health(&events).expect("B must report the failure");
        assert!(
            health.2 > 0,
            "B must count the frames it could not open, got {health:?}"
        );
        assert!(
            store_b
                .read_cursor(&label_b, u64::from(u32::MAX))
                .expect("the cursor reads")
                .is_none(),
            "an unopenable frame advanced the receive cursor"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// T14. The entry this driver publishes is one the recipient admits.
    ///
    /// **The two halves of the slice, joined.** Every other oracle here checks
    /// one side against a fixture; this one takes the bytes the outbound path
    /// actually wrote and runs them through the inbound path's own verifier,
    /// with the recipient's real decapsulation key and the recipient's real
    /// key-record address. Nothing in between is mocked, so a knock that is
    /// well-formed by this crate's lights and unreadable by core's fails here
    /// and nowhere else.
    #[tokio::test(start_paused = true)]
    async fn a_published_knock_is_admitted_by_its_recipient() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.set_key_record(Some(
            keyrec::build_encoded(
                &peer.signing,
                peer.kem.encapsulation_key(),
                keyrec::DM_KEY_RECORD_VERSION,
                keyrec::DM_KEY_RECORD_INVITE_ONLY,
            )
            .expect("key record"),
        ));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "over the wire".into(),
            })
            .await
            .expect("first contact");
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 3).await;

        let published = dht.published();
        assert_eq!(published.len(), 1, "one knock was written");
        let (_slot, entry) = &published[0];

        // The recipient's side, with nothing borrowed from the sender.
        let mut seen = SeenSet::new();
        let mut spent = SpentTokenSet::new();
        let addr = daemonseed_core::dm::keyrec::derive_owner_seed(peer.signing.public_key())
            .expect("recipient key-record address");
        let now_secs = (BASE_MS / 1000) as u64;
        let mut admitter = Admitter {
            recipient_dk: peer.kem.decapsulation_key(),
            recipient_pk_lt: peer.signing.public_key(),
            recipient_keyrec_addr: addr.as_bytes(),
            current_fc_epoch: keyrec::fc_epoch(now_secs),
            now_unix_secs: now_secs,
            policy: AdmissionPolicy::Open,
            difficulty: PowDifficulty::reduced_for_test(TEST_POW_BITS),
            seen: &mut seen,
            spent: &mut spent,
            counters: Default::default(),
        };
        let outcome = admitter.admit(entry, None, |_| false);
        let AdmissionOutcome::Admitted {
            verified,
            idempotent,
            ..
        } = outcome
        else {
            panic!("the recipient refused our own knock: {outcome:?}");
        };
        assert!(!idempotent, "a stranger's first knock is not a re-accept");
        assert_eq!(verified.body(), "over the wire");
        assert_eq!(
            verified.pk_lt().as_slice(),
            own_keys().signing.public_key().as_slice(),
            "the knock does not name us as its sender"
        );

        drop(drain(&mut evt_rx));
        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T15. A second `FirstContact` while the first is in flight is refused,
    /// and nothing is minted twice.
    ///
    /// `firstcontact::build` encapsulates a fresh `ss0` per call, which the
    /// recipient reads as the sender having lost their at-rest state — so a
    /// second mint for one introduction would mark the first one's messages
    /// undelivered at the far end.
    #[tokio::test(start_paused = true)]
    async fn a_second_first_contact_in_flight_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.set_key_record(Some(
            keyrec::build_encoded(
                &peer.signing,
                peer.kem.encapsulation_key(),
                keyrec::DM_KEY_RECORD_VERSION,
                keyrec::DM_KEY_RECORD_INVITE_ONLY,
            )
            .expect("key record"),
        ));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        for _ in 0..2 {
            handle
                .send(DmCommand::FirstContact {
                    recipient: Box::new(*peer.signing.public_key()),
                    body: "twice".into(),
                })
                .await
                .expect("first contact");
            settle().await;
        }
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 4).await;

        assert_eq!(
            probe.computes_started.load(Ordering::SeqCst),
            1,
            "the entry was minted more than once"
        );
        assert_eq!(dht.count(Method::FetchKeyRecord), 1, "one fetch");
        assert_eq!(dht.count(Method::PublishDoorbell), 1, "one knock");
        assert_eq!(
            refusals(&drain(&mut evt_rx)),
            vec![RefusalReason::AlreadyInFlight],
            "the duplicate was not refused as a duplicate"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T16. A key-record fetch that fails on the transport refuses the
    /// introduction and releases it, so the front end may ask again.
    #[tokio::test(start_paused = true)]
    async fn a_failed_key_record_fetch_releases_the_introduction() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::failing(
            Duration::from_millis(50),
            Method::FetchKeyRecord,
        ));
        let peer = peer_keys();
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "hello".into(),
            })
            .await
            .expect("first contact");
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 2).await;

        assert_eq!(
            refusals(&drain(&mut evt_rx)),
            vec![RefusalReason::PublishFailed],
            "a failed fetch did not refuse the introduction"
        );

        // Re-issued: a released introduction starts a NEW fetch. Retained, it
        // would be refused as a duplicate and the count would stay at one.
        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "hello again".into(),
            })
            .await
            .expect("second first contact");
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 4).await;
        assert_eq!(
            dht.count(Method::FetchKeyRecord),
            2,
            "the re-issued introduction did not start a new fetch"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T17. A doorbell write that fails refuses exactly once.
    ///
    /// The introduction is still recorded as in flight when the write is
    /// dispatched, which is what makes the failure attributable: draining it at
    /// the mint would leave nothing for the refusal to name and the front end
    /// would be told nothing at all.
    #[tokio::test(start_paused = true)]
    async fn a_failed_doorbell_write_refuses_exactly_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::failing(
            Duration::from_millis(50),
            Method::PublishDoorbell,
        ));
        let peer = peer_keys();
        dht.set_key_record(Some(
            keyrec::build_encoded(
                &peer.signing,
                peer.kem.encapsulation_key(),
                keyrec::DM_KEY_RECORD_VERSION,
                keyrec::DM_KEY_RECORD_INVITE_ONLY,
            )
            .expect("key record"),
        ));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "into the void".into(),
            })
            .await
            .expect("first contact");
        // Four steps: the command, the key record, the mint, and the write's
        // own failure coming back. The advance between them is not decoration:
        // `settle_steps` releases the runtime's own thread for a blocking job
        // but does not move virtual time, so the mock's latency on the write
        // needs its own advance before the fourth step can happen.
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 3).await;
        advance(&wall, Duration::from_millis(100)).await;
        settle_steps(&probe, 4).await;

        assert_eq!(dht.count(Method::PublishDoorbell), 1, "the write was tried");
        assert_eq!(
            refusals(&drain(&mut evt_rx)),
            vec![RefusalReason::PublishFailed],
            "a failed doorbell write did not refuse exactly once"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T18. `FirstContact` to an identity we already correspond with is refused
    /// and never reaches the network.
    ///
    /// Unguarded, it is a way to destroy a live conversation from the wrong
    /// button: a fresh knock from a known identity is read at the far end as
    /// state loss, and their client answers it by ending every message they
    /// have queued for us.
    #[tokio::test(start_paused = true)]
    async fn a_first_contact_to_an_established_peer_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pseudonym(0x21), "hello"))]);
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (request, _, _) = only_request(&drain(&mut evt_rx));
        handle
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle().await;

        // Positive control: the fetch count before is what the assertion after
        // is measured against.
        assert_eq!(dht.count(Method::FetchKeyRecord), 0);
        handle
            .send(DmCommand::FirstContact {
                recipient: Box::new(*peer.signing.public_key()),
                body: "knocking on my own door".into(),
            })
            .await
            .expect("first contact");
        settle().await;

        assert_eq!(
            refusals(&drain(&mut evt_rx)),
            vec![RefusalReason::AlreadyEstablished],
            "first contact to a correspondent was not refused"
        );
        assert_eq!(
            dht.count(Method::FetchKeyRecord),
            0,
            "it reached the network anyway"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T19. Blocking an identity drops its held request, and accepting that
    /// request afterwards establishes nothing.
    #[tokio::test(start_paused = true)]
    async fn blocking_drops_a_held_request_and_the_accept_does_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let peer = peer_keys();
        dht.queue_doorbell(vec![(7, knock_from(&peer, &pseudonym(0x21), "let me in"))]);
        let probe = Arc::new(DmDriverProbe::new());
        let store = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (request, _, _) = only_request(&drain(&mut evt_rx));

        handle
            .send(DmCommand::Block {
                pk_lt: Box::new(*peer.signing.public_key()),
            })
            .await
            .expect("block");
        settle().await;
        handle
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle().await;

        assert!(
            store
                .correspondence_for_pk_lt(peer.signing.public_key())
                .expect("lookup")
                .is_none(),
            "a blocked identity's request was still acceptable"
        );
        assert!(
            store
                .read_block_list()
                .expect("read")
                .is_blocked(peer.signing.public_key()),
            "the block was not recorded"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T20. The request's `entry_hash` is the queued entry's own hash, and a
    /// slot overwritten between sweeps holds only the later request.
    ///
    /// The hash is what makes the id name an *entry* rather than a location:
    /// a slot is overwritable between the sweep that found it and the accept
    /// that acts on it.
    #[tokio::test(start_paused = true)]
    async fn a_request_names_the_exact_entry_it_was_shown() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        // Two DIFFERENT senders landing in one slot — the birthday collision
        // the design prices at around twenty concurrent unknown senders. The
        // same sender knocking twice while its first request is still held is
        // an idempotent re-accept by admission's step 7, which is a different
        // case and not this one.
        let peer = peer_keys();
        let other = other_peer_keys();
        let first = knock_from(&peer, &pseudonym(0x21), "first");
        let second = knock_from(&other, &pseudonym(0x22), "second");
        assert_ne!(first, second, "the two knocks are the same bytes");
        dht.queue_doorbell(vec![(7, first.clone())]);
        dht.queue_doorbell(vec![(7, second.clone())]);
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht), probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (id_a, _, body_a) = only_request(&drain(&mut evt_rx));
        assert_eq!(body_a, "first");

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        let (id_b, _, body_b) = only_request(&drain(&mut evt_rx));
        assert_eq!(body_b, "second", "the overwrite did not surface");

        assert_eq!(id_a.slot, 7);
        assert_eq!(id_b.slot, 7);
        assert_ne!(
            id_a.entry_hash, id_b.entry_hash,
            "two different entries in one slot produced one id"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T21. An unreadable spent-token file poisons the store at startup and
    /// says so.
    ///
    /// Reading it as an empty set would be worse than refusing: the first write
    /// afterwards lays an empty set over a file full of burnt grants, and every
    /// one of them becomes redeemable again.
    #[tokio::test(start_paused = true)]
    async fn an_unreadable_spent_token_file_is_reported_at_startup() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        std::fs::write(
            daemonseed_core::dm::spent_store::spent_tokens_path(dir.path()),
            b"not a spent-token file",
        )
        .expect("write the corrupt file");

        let mut p = parts(&dir, &wall, dht);
        p.spent_tokens = Some(SpentTokenStore {
            profile_root: dir.path().to_path_buf(),
            passphrase: zeroize::Zeroizing::new("hunter2".to_string()),
            profile_id: uuid::Uuid::from_bytes([3u8; 16]),
            argon2: TEST_ARGON,
        });
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) = DmDriver::spawn_with_probe(p, probe);

        let event = evt_rx.recv().await.expect("one event");
        assert!(
            matches!(event, DmEvent::SpentTokensNotPersisted),
            "an unreadable spent-token set was not reported: {event:?}"
        );

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");
    }

    /// T22. Under an invite-only policy a tokened knock is admitted, its nonce
    /// reaches the disk, and a replay of that same knock is refused after a
    /// reload.
    ///
    /// The reload is the whole point: the set is what makes an invite one-time,
    /// and one that lives only in memory makes it one-time per process.
    #[tokio::test(start_paused = true)]
    async fn an_invite_token_is_spent_once_across_a_restart() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let peer = peer_keys();
        let own = own_keys();
        let now_secs = (BASE_MS / 1000) as u64;
        // We are the issuer: an invite is a grant this identity makes to that
        // one, and only the issuer ever verifies it.
        let token = daemonseed_core::dm::token::TokenV1::mint_default(
            &own.signing,
            peer.signing.public_key(),
            now_secs,
        )
        .expect("token");
        let (entry, _state) = firstcontact::build(FirstContactRequest {
            signing_lt: &peer.signing,
            signing_pc: &pseudonym(0x31),
            recipient_pk_lt: own.signing.public_key(),
            kem_ek_b: own.kem.encapsulation_key(),
            fc_epoch: keyrec::fc_epoch(now_secs),
            sent_unix_ms: BASE_MS,
            body: "invited",
            token: Some(&token),
            difficulty: PowDifficulty::reduced_for_test(TEST_POW_BITS),
        })
        .expect("tokened knock");

        let store = SpentTokenStore {
            profile_root: dir.path().to_path_buf(),
            passphrase: zeroize::Zeroizing::new("hunter2".to_string()),
            profile_id: uuid::Uuid::from_bytes([9u8; 16]),
            argon2: TEST_ARGON,
        };
        let path = daemonseed_core::dm::spent_store::spent_tokens_path(dir.path());

        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        dht.queue_doorbell(vec![(7, entry.clone())]);
        let mut p = parts(&dir, &wall, dht.clone());
        p.cfg.policy = AdmissionPolicy::InviteOnly;
        p.spent_tokens = Some(store.clone());
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) = DmDriver::spawn_with_probe(p, probe.clone());

        advance(&wall, IDLE_TICK).await;
        advance(&wall, Duration::from_secs(1)).await;
        // The write is a blocking Argon2id seal, so it needs real time.
        settle_steps(&probe, 3).await;
        let (_id, from, body) = only_request(&drain(&mut evt_rx));
        assert_eq!(from.as_slice(), peer.signing.public_key().as_slice());
        assert_eq!(body, "invited");
        assert!(path.exists(), "the spent-token set never reached the disk");

        handle.send(DmCommand::Shutdown).await.expect("shutdown");
        task.await.expect("the driver task ends");

        // Reload: a fresh driver over the same profile root, and the SAME
        // entry replayed at the same epoch.
        let reloaded = daemonseed_core::dm::spent_store::read_from(&path, "hunter2")
            .expect("the set opens")
            .expect("the set is there");
        assert_eq!(reloaded.len(), 1, "the nonce was not recorded");

        let dht2 = Arc::new(MockDht::new(Duration::from_millis(50)));
        dht2.queue_doorbell(vec![(7, entry)]);
        let wall2 = Arc::new(AtomicI64::new(BASE_MS));
        let mut p2 = parts(&dir, &wall2, dht2);
        p2.cfg.policy = AdmissionPolicy::InviteOnly;
        p2.spent_tokens = Some(store);
        let probe2 = Arc::new(DmDriverProbe::new());
        let (handle2, mut rx2, task2) = DmDriver::spawn_with_probe(p2, probe2.clone());

        advance(&wall2, IDLE_TICK).await;
        advance(&wall2, Duration::from_secs(1)).await;
        settle_steps(&probe2, 2).await;

        let events = drain(&mut rx2);
        assert!(!events.is_empty(), "the second driver did not sweep at all");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DmEvent::ContactRequest { .. })),
            "a spent invite was redeemed a second time: {events:?}"
        );

        handle2.send(DmCommand::Shutdown).await.expect("shutdown");
        task2.await.expect("the driver task ends");
    }

    /// Knock, accept and establish one correspondence between two live drivers,
    /// leaving A holding B's pseudonym.
    ///
    /// The whole path runs for real: A's mint writes the knock into the shared
    /// record store, B's doorbell sweep finds it, B's accept composes the
    /// acceptance, B's cadence publishes it, and A's own sweep opens it. Nothing
    /// below is a fixture.
    ///
    /// Returns A's own events from the whole establishment, drained — the
    /// acceptance's piggyback settles A's knock in that window, so it is the only
    /// place that confirmation can be observed.
    #[allow(clippy::too_many_arguments)]
    async fn establish_between(
        handle_a: &DmDriverHandle,
        probe_a: &DmDriverProbe,
        evt_a: &mut mpsc::Receiver<DmEvent>,
        evt_b: &mut mpsc::Receiver<DmEvent>,
        handle_b: &DmDriverHandle,
        probe_b: &DmDriverProbe,
        wall: &Arc<AtomicI64>,
        b_keys: &IdentityKeys,
    ) -> Vec<DmEvent> {
        handle_a
            .send(DmCommand::FirstContact {
                recipient: Box::new(*b_keys.signing.public_key()),
                body: "knock knock".into(),
            })
            .await
            .expect("first contact");
        advance(wall, Duration::from_millis(100)).await;
        settle_steps(probe_a, 3).await;

        cadence(wall).await;
        let events = drain(evt_b);
        let (request, _, _) = only_request(&events);
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(probe_b, 3).await;
        // Two cadences: B's publishes the acceptance, A's sweeps and opens it.
        cadence(wall).await;
        cadence(wall).await;
        drain(evt_a)
    }

    /// T23c. A page whose sweep is still in flight is not swept again by the
    /// running driver.
    ///
    /// The machine-level test pins `probe`'s decision; this pins the loop that
    /// calls it. A page sweep reads all sixteen subkeys of a record, so on a real
    /// distributed hash table it outlives a tick exactly as the doorbell sweep
    /// does, and the shell has no idea a sweep it spawned is still running.
    ///
    /// **The seam is slowed only after the correspondence is live**, because
    /// establishing one is itself a chain of hops over that seam — the knock, the
    /// sweep that finds it, the acceptance, the sweep that opens it — and a seam
    /// slow enough to make the case would never get through them.
    ///
    /// The plan is the watched pair, so three ticks would ask for six sweeps
    /// without the guard. With it the second tick's plan is wholly in flight and
    /// asks for none, leaving four.
    #[tokio::test(start_paused = true)]
    async fn a_page_sweep_in_flight_is_not_asked_for_twice_by_the_driver() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        dht_b.set_key_record(Some(key_record_for(&a_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );

        establish_between(
            &handle_a, &probe_a, &mut evt_a, &mut evt_b, &handle_b, &probe_b, &wall, &b_keys,
        )
        .await;

        // The case under test starts here.
        dht_b.slow(Method::SweepPage, SLOW_SWEEP);
        let swept_before = dht_b.count(Method::SweepPage);
        let ticks_before = probe_b.ticks.load(Ordering::SeqCst);

        for _ in 0..20 {
            advance(&wall, Duration::from_secs(5)).await;
        }

        assert_eq!(
            probe_b.ticks.load(Ordering::SeqCst) - ticks_before,
            3,
            "three ticks must have landed in the window, or the count below \
             proves nothing"
        );
        assert_eq!(
            dht_b.count(Method::SweepPage) - swept_before,
            4,
            "three ticks over sweeps that outlive one of them must ask for the \
             watched pair twice, not three times"
        );

        handle_a
            .send(DmCommand::Shutdown)
            .await
            .expect("shutdown A");
        handle_b
            .send(DmCommand::Shutdown)
            .await
            .expect("shutdown B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
        drain(&mut evt_a);
        drain(&mut evt_b);
    }

    /// T23d. Two live drivers: B blocks A mid-conversation, A keeps sending, and
    /// nothing A sends reaches B's front end until B unblocks.
    ///
    /// **The machine-level tests pin the decision; this pins the whole loop**,
    /// over a real record store, a real ratchet and A's real publishes — so the
    /// message B does not surface is one that genuinely reached the record B
    /// would have swept.
    ///
    /// Three controls, and none of the assertions means anything without them:
    /// the first message surfaces, so the second one's silence is the block and
    /// not a broken conversation; A's publish count rises across the blocked
    /// window, so the silence is B refusing to read rather than A failing to
    /// write; and B's sweep count does not, so the block reaches the plane it is
    /// supposed to. The unblocked collection at the end is what shows the
    /// message was dropped rather than consumed.
    #[tokio::test(start_paused = true)]
    async fn a_block_stops_a_live_conversation_and_an_unblock_resumes_it() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        dht_b.set_key_record(Some(key_record_for(&a_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );

        establish_between(
            &handle_a, &probe_a, &mut evt_a, &mut evt_b, &handle_b, &probe_b, &wall, &b_keys,
        )
        .await;

        // ── the control: an unblocked A is heard ─────────────────────────────
        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "before the block".into(),
            })
            .await
            .expect("A sends");
        for _ in 0..3 {
            cadence(&wall).await;
        }
        assert_eq!(
            messages(&drain(&mut evt_b)),
            vec![(1, "before the block".to_string())],
            "B did not collect the message that precedes the block"
        );

        // ── B blocks A, and A goes on sending ────────────────────────────────
        handle_b
            .send(DmCommand::Block {
                pk_lt: Box::new(*a_keys.signing.public_key()),
            })
            .await
            .expect("block");
        settle().await;
        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "after the block".into(),
            })
            .await
            .expect("A sends again");

        let published_before = dht_a.count(Method::PublishPage);
        let swept_before = dht_b.count(Method::SweepPage);
        let fetched_before = dht_b.count(Method::FetchAck);
        assert!(
            fetched_before > 0,
            "B was not fetching acknowledgements before the block, so the count \
             below would hold for the wrong reason"
        );
        for _ in 0..8 {
            cadence(&wall).await;
        }
        let blocked_window = drain(&mut evt_b);
        assert_eq!(
            messages(&blocked_window),
            Vec::new(),
            "a blocked correspondent's message reached the front end: {blocked_window:?}"
        );
        // The acknowledgement plane, from B's own side: B has messages of its
        // own outstanding with A, so a fetch would have been asked for and its
        // record folded, reporting a blocked party's collection.
        assert_eq!(
            confirmations(&blocked_window),
            Vec::<u64>::new(),
            "a blocked correspondent's acknowledgement settled B's outbox: {blocked_window:?}"
        );
        assert_eq!(
            dht_b.count(Method::FetchAck),
            fetched_before,
            "B fetched a blocked correspondent's acknowledgement record"
        );
        assert!(
            dht_a.count(Method::PublishPage) > published_before,
            "A never wrote the message the block is supposed to hide, so the \
             silence above proves nothing"
        );
        assert_eq!(
            dht_b.count(Method::SweepPage),
            swept_before,
            "B swept a blocked correspondent's channel"
        );

        // ── a block landing while a sweep is in flight ───────────────────────
        //
        // **The sweep-time refusal cannot reach this case**, and an ordinary
        // cadence cannot produce it: a sweep at the mock's own latency completes
        // inside the tick that asked for it, so a block always lands with nothing
        // outstanding. Slowing the page sweep past one tick is what opens the
        // window the driver meets on a real distributed hash table, where a sweep
        // routinely outlives several.
        //
        // The mock reads the record when the sweep STARTS and sleeps afterwards,
        // so `slots_served` rising says the sweep now in flight read a POPULATED
        // slot — not, on its own, that the slot is the unsurfaced frame. It
        // stands in for that here because the mock serves the whole page map in
        // one sweep and the only frame on B's receiving page that B has not
        // already settled is A's second message. Without it, "nothing surfaced"
        // is satisfied by a sweep that read an empty page.
        dht_b.slow(Method::SweepPage, SLOW_SWEEP);
        handle_b
            .send(DmCommand::Unblock {
                pk_lt: Box::new(*a_keys.signing.public_key()),
            })
            .await
            .expect("unblock for the in-flight case");
        settle().await;
        let served_before = dht_b.slots_served();
        let mut carrying = false;
        for _ in 0..12 {
            advance(&wall, Duration::from_secs(5)).await;
            if dht_b.slots_served() > served_before {
                carrying = true;
                break;
            }
        }
        assert!(
            carrying,
            "no sweep of B's ever read A's frame, so the drop below proves nothing"
        );
        // In flight now, and blocked before it lands.
        let completed_before = probe_b.ops_completed.load(Ordering::SeqCst);
        handle_b
            .send(DmCommand::Block {
                pk_lt: Box::new(*a_keys.signing.public_key()),
            })
            .await
            .expect("block mid-sweep");
        settle().await;
        for _ in 0..12 {
            advance(&wall, Duration::from_secs(5)).await;
        }
        // **The sweep has to have come back inside this window.** A sweep takes
        // `SLOW_SWEEP` and the window is sixty virtual seconds, so the margin is
        // real but not large — and an operation still in flight produces no
        // events at all, which is indistinguishable from one whose frames were
        // dropped.
        assert!(
            probe_b.ops_completed.load(Ordering::SeqCst) > completed_before,
            "no operation of B's completed in the window, so the sweep that was \
             in flight may simply not have landed yet"
        );
        let in_flight = drain(&mut evt_b);
        assert_eq!(
            messages(&in_flight),
            Vec::new(),
            "a sweep in flight when the block landed surfaced its frames: {in_flight:?}"
        );

        // ── unblocked: the same message, from the record it was left in ──────
        dht_b.slow(Method::SweepPage, Duration::from_millis(50));
        handle_b
            .send(DmCommand::Unblock {
                pk_lt: Box::new(*a_keys.signing.public_key()),
            })
            .await
            .expect("unblock");
        settle().await;
        for _ in 0..4 {
            cadence(&wall).await;
        }
        assert_eq!(
            messages(&drain(&mut evt_b)),
            vec![(2, "after the block".to_string())],
            "the message written during the block was lost rather than deferred"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
        drain(&mut evt_a);
    }

    /// Every sequence reported `ConfirmedCollected` in `events`, ascending and
    /// with duplicates kept.
    ///
    /// **A whole vector rather than a count per sequence**, so one assertion
    /// fails on a missing confirmation, a repeated one, and a confirmation for a
    /// sequence that should not have settled. `Composed` and `OnDht` are left out
    /// because a re-seed ladder repeats them by design, and a test that pinned
    /// their multiplicity would be pinning the cadence rather than the
    /// acknowledgement.
    fn confirmations(events: &[DmEvent]) -> Vec<u64> {
        let mut seqs: Vec<u64> = deliveries(events)
            .into_iter()
            .filter(|(_, state)| *state == DeliveryState::ConfirmedCollected)
            .map(|(seq, _)| seq)
            .collect();
        seqs.sort_unstable();
        seqs
    }

    /// T27. The standalone acknowledgement closes the loop: B writes it, A
    /// fetches it, and A's outbox settles once.
    ///
    /// **The one oracle where the acknowledgement itself is nothing's fixture.**
    /// The record A opens is the record B's own cadence built and published, at
    /// an address neither side exchanged and both derived, sealed under a key
    /// that descends from the secret A encapsulated and signed by the pseudonym A
    /// learned from B's acceptance. A break anywhere from `StandaloneAckCadence`
    /// through `ack_record::build_encoded` to `Outbox::settle_from_ack` lands
    /// here.
    ///
    /// **Both directions settle, and the acceptor's own sequence zero is the
    /// harder one.** The acceptance is an ordinary outbox entry: A must collect
    /// it like any message and acknowledge it like any message, or B re-seeds its
    /// acceptance to the seven-day give-up and reports the frame that opened the
    /// conversation undelivered.
    ///
    /// Exactly once is the property, not merely once: the fast path reports a
    /// settled sequence and the tick's owed-surfacing sweep must not report it
    /// again in the same run.
    #[tokio::test(start_paused = true)]
    async fn an_acknowledgement_settles_the_senders_outbox_exactly_once() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        dht_b.set_key_record(Some(key_record_for(&a_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );

        let established = establish_between(
            &handle_a, &probe_a, &mut evt_a, &mut evt_b, &handle_b, &probe_b, &wall, &b_keys,
        )
        .await;
        // **The knock's own sequence zero, and the only oracle for it.** It is
        // carried by doorbell and no page will ever hold it, so the acceptor
        // settles that position at the accept and piggybacks it on the
        // acceptance. Without that, the contiguous prefix never starts and the
        // message that opens every conversation is re-seeded to the give-up and
        // then reported undelivered.
        assert_eq!(
            confirmations(&established),
            vec![0],
            "A's knock must be confirmed by the acceptance it opened: {established:?}"
        );
        let _ = drain(&mut evt_b);

        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "confirm this".into(),
            })
            .await
            .expect("send");
        settle().await;
        // Enough cadences for the whole chain: A publishes, B sweeps and
        // collects, B's floor fires and writes the record, A fetches it.
        for _ in 0..6 {
            cadence(&wall).await;
        }

        let a_events = drain(&mut evt_a);
        let b_events = drain(&mut evt_b);

        assert_eq!(
            messages(&b_events),
            vec![(1, "confirm this".to_string())],
            "B must have collected the message the acknowledgement is about: {b_events:?}"
        );
        assert!(
            dht_b.count(Method::PublishAck) >= 1,
            "B must have written a standalone acknowledgement once its floor fired"
        );
        assert!(
            dht_a.count(Method::FetchAck) >= 1,
            "A must have asked for the acknowledgement, or the settle below is vacuous"
        );
        // Sequence zero is the knock. It is carried by doorbell and no page will
        // ever hold it, so the acceptor settles that position at the accept —
        // and this is the only oracle for that. Without it the contiguous prefix
        // never starts and the message that opens every conversation is
        // re-seeded to the give-up and then reported undelivered.
        assert_eq!(
            confirmations(&a_events),
            vec![1],
            "A must report its message collected exactly once: {a_events:?}"
        );
        assert_eq!(
            confirmations(&b_events),
            vec![0],
            "B's acceptance is an ordinary outbox entry and must settle like one: \
             {b_events:?}"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// T28. A piggybacked acknowledgement settles the sender's outbox on the
    /// page fold alone.
    ///
    /// **A's acknowledgement seam is scripted to fail for the whole test**, so
    /// nothing A settles can have come from a fetched record. That is a stronger
    /// control than counting the fetches: a count of zero would only hold while
    /// the fetch cadence happened not to have fired, and the property under test
    /// is that the piggyback needs no fetch at all — a reply carries the
    /// correspondent's whole collection state, and `on_page` is where it lands.
    ///
    /// The sweep count is the positive control: without it, "A settled without
    /// fetching" is satisfied by a driver that swept nothing and settled nothing.
    #[tokio::test(start_paused = true)]
    async fn a_piggybacked_acknowledgement_settles_without_a_fetch() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();

        let dht_a = Arc::new(MockDht::failing_on(
            net.clone(),
            Duration::from_millis(50),
            Method::FetchAck,
        ));
        let dht_b = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        dht_b.set_key_record(Some(key_record_for(&a_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_as(own_keys(), dir_a.path(), &wall, dht_a.clone()),
            probe_a.clone(),
        );
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(
            parts_as(peer_keys(), dir_b.path(), &wall, dht_b.clone()),
            probe_b.clone(),
        );

        let established = establish_between(
            &handle_a, &probe_a, &mut evt_a, &mut evt_b, &handle_b, &probe_b, &wall, &b_keys,
        )
        .await;
        assert_eq!(
            confirmations(&established),
            vec![0],
            "A's knock must be confirmed by the acceptance it opened: {established:?}"
        );
        let _ = drain(&mut evt_b);

        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "ping".into(),
            })
            .await
            .expect("send");
        settle().await;
        for _ in 0..3 {
            cadence(&wall).await;
        }
        assert_eq!(
            messages(&drain(&mut evt_b)),
            vec![(1, "ping".to_string())],
            "B must have collected the message before it can acknowledge it"
        );

        // B answers rather than writing a standalone record; the reply carries
        // B's whole collection state inside its own signature.
        handle_b
            .send(DmCommand::Send {
                to: Box::new(*a_keys.signing.public_key()),
                body: "pong".into(),
            })
            .await
            .expect("B replies");
        let swept_before = dht_a.count(Method::SweepPage);
        for _ in 0..3 {
            cadence(&wall).await;
        }
        let a_events = drain(&mut evt_a);

        assert_eq!(
            messages(&a_events),
            vec![(1, "pong".to_string())],
            "A must have opened the reply that carried the acknowledgement: {a_events:?}"
        );
        assert!(
            dht_a.count(Method::SweepPage) > swept_before,
            "A must have kept sweeping, or the fold below never had bytes to work on"
        );
        // **The failing path has to have run.** A fetch count of zero would mean
        // the scripted failure was never exercised, which makes "no fetch
        // contributed" true for the wrong reason — the seam was simply never
        // asked.
        assert!(
            dht_a.count(Method::FetchAck) >= 1,
            "A must actually have asked its acknowledgement seam and been refused, \
             or the control below proves nothing"
        );
        assert_eq!(
            confirmations(&a_events),
            vec![1],
            "the piggybacked acknowledgement must settle A's message exactly once, \
             with every fetch on A's seam failing: {a_events:?}"
        );
        assert_eq!(
            last_health(&a_events).map_or(0, |h| h.4),
            0,
            "A deferred the piggybacked acknowledgement instead of folding it: {a_events:?}"
        );
        // The refused fetches reach the counter through the driver's own path —
        // the seam, `dispatch`'s tag, and the machine's fold of the failure —
        // which is the only place that chain is exercised end to end.
        assert!(
            failed_ack_fetches(&a_events, b_keys.signing.public_key()) >= 1,
            "every fetch on A's seam was refused and none of them was counted: \
             {a_events:?}"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// The idle tick A runs on in the watch oracles below — deliberately far
    /// shorter than B's [`IDLE_TICK`], and that difference is the whole
    /// instrument.
    ///
    /// Both drivers read one clock, so equal cadences wake them at the same instant
    /// and every write A makes lands in the step B would have swept in anyway. With
    /// A six times faster, an advance exists that fires A's tick and cannot fire B's
    /// — and then anything B does in that window is something the watch caused,
    /// because B's cadence has not come round.
    ///
    /// A's own probe cadence is unaffected: `Collection::probe_plan` is gated on
    /// `PROBE_INTERVAL_MS` of wall clock, not on the idle tick, so a faster tick
    /// buys more doorbell sweeps and more outbox emissions and no extra sweeps.
    ///
    /// **Chosen so that it does not divide [`IDLE_TICK`], and that is not cosmetic.**
    /// A tick of five seconds divides thirty exactly, so one A tick in six lands on
    /// the same instant as a B tick — and on that instant A's re-seed write and B's
    /// probe are simultaneous, so B's standing watch can be spent by the re-seed
    /// while B's own sweep of the page is in flight. Seven seconds shares no factor
    /// with thirty, so no advance in these oracles puts the two on one instant.
    const A_TICK: Duration = Duration::from_secs(7);

    /// One driver's parts at a chosen idle tick.
    fn parts_ticking(
        keys: IdentityKeys,
        dir: &std::path::Path,
        wall: &Arc<AtomicI64>,
        dht: Arc<MockDht>,
        idle_tick: Duration,
    ) -> DmDriverParts<MockDht> {
        let mut parts = parts_as(keys, dir, wall, dht);
        parts.cfg.idle_tick = idle_tick;
        parts
    }

    /// Advance far enough for B to tick once — and A several times — plus the
    /// latency their operations need to come back.
    ///
    /// It leaves B having just ticked, which is what [`only_a_ticks`] depends on:
    /// B's next deadline is a whole [`IDLE_TICK`] from a point inside this advance,
    /// so the short window that follows cannot reach it.
    async fn both_tick(wall: &Arc<AtomicI64>) {
        advance(wall, IDLE_TICK + Duration::from_millis(500)).await;
        advance(wall, Duration::from_millis(500)).await;
        settle().await;
    }

    /// Advance far enough for A to tick and nowhere near far enough for B, then let
    /// the operations that started come back.
    ///
    /// The margin is what makes it an instrument rather than a coincidence: A's tick
    /// is [`A_TICK`] away and B's is a fresh [`IDLE_TICK`] away by construction, so
    /// this window wakes exactly one of them. The caller reads B's tick counter
    /// across it rather than trusting the arithmetic.
    async fn only_a_ticks(wall: &Arc<AtomicI64>) {
        advance(wall, A_TICK + Duration::from_millis(500)).await;
        advance(wall, Duration::from_millis(500)).await;
        settle().await;
    }

    /// What B's watch seam does in one of the oracles below.
    ///
    /// **`Lost`, `Failing` and `NeverArmed` are separate because the mock and the
    /// configuration can tell them apart and the driver must not.** One is a watch
    /// that is simply not there, one a transport that refused, one a driver that
    /// never asked; a driver that treated any of them as anything but "no watch"
    /// would show up as a difference between runs that must be identical.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum WatchMode {
        /// Watches stand and fire on a write to the page.
        Standing,
        /// Every watch answers `Lost` — an expiry, or a page that cannot be
        /// watched.
        Lost,
        /// Every watch answers a transport error.
        Failing,
        /// The driver arms no watch at all — the baseline the other two are
        /// compared against.
        NeverArmed,
    }

    /// Everything the watch oracles need: two drivers out of phase, an
    /// established correspondence, and both event streams drained.
    ///
    /// Built rather than inlined per test because the oracles differ only in what
    /// they do to B's watch seam, and a fixture written out per test is a fixture
    /// that drifts between them — which is exactly what a control run must not do.
    struct WatchPair {
        handle_a: DmDriverHandle,
        evt_a: mpsc::Receiver<DmEvent>,
        task_a: tokio::task::JoinHandle<()>,
        probe_a: Arc<DmDriverProbe>,
        handle_b: DmDriverHandle,
        evt_b: mpsc::Receiver<DmEvent>,
        task_b: tokio::task::JoinHandle<()>,
        probe_b: Arc<DmDriverProbe>,
        dht_b: Arc<MockDht>,
        /// `dht_b.count(Method::WatchPage)` after the mode took effect and the
        /// fixture settled.
        ///
        /// **Every later assertion about arming is growth against this, never a
        /// cumulative count.** B arms a watch as soon as its collection has a page
        /// to watch, which is before the mode under test is in force, so
        /// `count >= 1` is satisfied by the fixture alone and says nothing about
        /// what happened afterwards.
        watches_at_switch: u64,
    }

    /// The address of the last watch a mock was asked to arm, read out of its own
    /// call log.
    ///
    /// A change delivered to this address reaches the record the driver actually
    /// armed on. Deriving one here instead would be a second answer to the question
    /// the driver already answered, and a decoy sent to the wrong record fires
    /// nothing while looking exactly like a driver that ignored it.
    fn last_watched(dht: &MockDht) -> ([u8; AR_FINGERPRINT_LEN], Direction, u64) {
        dht.log()
            .into_iter()
            .rev()
            .find_map(|call| match call {
                MockCall::WatchPage {
                    conversation,
                    page,
                    direction,
                } => Some((conversation, direction, page)),
                _ => None,
            })
            .expect("the driver must have armed a watch to read one back")
    }

    async fn watch_pair(
        dir_a: &std::path::Path,
        dir_b: &std::path::Path,
        wall: &Arc<AtomicI64>,
        mode: WatchMode,
    ) -> WatchPair {
        let net = crate::dm::mock::MockNetwork::new();
        let a_keys = own_keys();
        let b_keys = peer_keys();
        let dht_a = Arc::new(MockDht::on(net.clone(), Duration::from_millis(50)));
        let dht_b = Arc::new(match mode {
            WatchMode::Failing => {
                MockDht::failing_on(net.clone(), Duration::from_millis(50), Method::WatchPage)
            }
            _ => MockDht::on(net.clone(), Duration::from_millis(50)),
        });
        // Scripted BEFORE the drivers start, so no watch armed during the
        // establishment rounds is left standing under a seam that is supposed to
        // have none. A watch that outlives the switch fires on the first write of
        // the run and buys a sweep the case under test was measuring the absence of
        // — a difference of exactly one sweep between two runs that must match.
        // Nothing in establishing a correspondence goes over this seam.
        dht_b.set_watches_lost(mode == WatchMode::Lost);
        dht_a.set_key_record(Some(key_record_for(&b_keys)));
        dht_b.set_key_record(Some(key_record_for(&a_keys)));

        let probe_a = Arc::new(DmDriverProbe::new());
        let probe_b = Arc::new(DmDriverProbe::new());
        let (handle_a, mut evt_a, task_a) = DmDriver::spawn_with_probe(
            parts_ticking(own_keys(), dir_a, wall, dht_a.clone(), A_TICK),
            probe_a.clone(),
        );
        // The baseline run's driver never arms a watch. Set at construction rather
        // than switched later, because the point of the run is that no watch has
        // existed at any moment of it.
        let mut parts_b = parts_ticking(peer_keys(), dir_b, wall, dht_b.clone(), IDLE_TICK);
        parts_b.cfg.arm_page_watches = mode != WatchMode::NeverArmed;
        let (handle_b, mut evt_b, task_b) = DmDriver::spawn_with_probe(parts_b, probe_b.clone());

        handle_a
            .send(DmCommand::FirstContact {
                recipient: Box::new(*b_keys.signing.public_key()),
                body: "knock knock".into(),
            })
            .await
            .expect("first contact");
        advance(wall, Duration::from_millis(100)).await;
        settle_steps(&probe_a, 3).await;
        both_tick(wall).await;
        let events = drain(&mut evt_b);
        let (request, _, _) = only_request(&events);
        handle_b
            .send(DmCommand::Accept { request })
            .await
            .expect("accept");
        settle_steps(&probe_b, 3).await;
        // Two rounds: B's publishes the acceptance, A's sweeps and opens it.
        both_tick(wall).await;
        both_tick(wall).await;
        // A round with the seam under test in force, so B has re-armed (or failed
        // to) since the conversation was established rather than only during it.
        both_tick(wall).await;
        if mode == WatchMode::Standing {
            // A decoy change, spending whatever watch is standing, so the oracles
            // start from a KNOWN watch state rather than from whichever one the
            // establishment rounds happened to leave. Without it a message write can
            // land while a watch is already spent and its sweep still in flight, and
            // the run then measures the fixture's phase rather than the watch.
            let (conversation, direction, page) = last_watched(&dht_b);
            let before = dht_b.count(Method::WatchPage);
            net.deliver_page_change(conversation, direction, page);
            advance(wall, Duration::from_millis(200)).await;
            advance(wall, Duration::from_millis(200)).await;
            let _ = drain(&mut evt_b);
            assert!(
                dht_b.count(Method::WatchPage) > before,
                "the decoy change must have been answered by a re-arm ({before} -> {}),                  or the watch under test is one this fixture already spent",
                dht_b.count(Method::WatchPage)
            );
        }
        let _ = drain(&mut evt_a);
        let _ = drain(&mut evt_b);
        let watches_at_switch = dht_b.count(Method::WatchPage);
        WatchPair {
            handle_a,
            evt_a,
            task_a,
            probe_a,
            handle_b,
            evt_b,
            task_b,
            probe_b,
            dht_b,
            watches_at_switch,
        }
    }

    /// T34. A value change on a watched page collects the message without B's
    /// probe cadence coming round.
    ///
    /// **The tick count is the instrument.** B is out of phase with A by
    /// construction ([`SLOW_TICK`]), so the advance that makes A publish does not
    /// wake B at all — and B's tick count is read on both sides of it to prove
    /// that. A driver whose only route to a page is the probe plan collects
    /// nothing here; the control below is exactly that driver.
    ///
    /// What the watch decides is *when*, never *what*: the collection still runs
    /// through the ordinary page sweep and the ordinary fold, which is why the
    /// assertion is on the message and not on any watch-specific state.
    #[tokio::test(start_paused = true)]
    async fn a_value_change_collects_the_message_before_the_probe_cadence() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let b_keys = peer_keys();
        let WatchPair {
            handle_a,
            mut evt_a,
            task_a,
            handle_b,
            mut evt_b,
            task_b,
            probe_b,
            ..
        } = watch_pair(dir_a.path(), dir_b.path(), &wall, WatchMode::Standing).await;

        let ticks_before = probe_b.ticks.load(Ordering::SeqCst);
        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "by watch".into(),
            })
            .await
            .expect("send");
        settle().await;
        only_a_ticks(&wall).await;

        assert_eq!(
            probe_b.ticks.load(Ordering::SeqCst),
            ticks_before,
            "B's cadence must not have come round, or the collection below proves \
             nothing about the watch"
        );
        let b_events = drain(&mut evt_b);
        assert_eq!(
            messages(&b_events),
            vec![(1, "by watch".to_string())],
            "the value change must have collected the message on its own: {b_events:?}"
        );

        let _ = drain(&mut evt_a);
        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// T34a. The control: with B's watches lost, the same write is collected on
    /// B's next probe cadence and not before.
    ///
    /// **Two assertions, and the second is what makes the first mean anything.**
    /// Nothing arriving in the un-ticked window would also be satisfied by a
    /// driver that never collects the message at all, so the same fixture is then
    /// run on to B's own cadence and the message must be there.
    #[tokio::test(start_paused = true)]
    async fn without_a_watch_the_message_waits_for_the_probe_cadence() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let b_keys = peer_keys();
        let WatchPair {
            handle_a,
            mut evt_a,
            task_a,
            handle_b,
            mut evt_b,
            task_b,
            probe_b,
            dht_b,
            watches_at_switch,
            ..
        } = watch_pair(dir_a.path(), dir_b.path(), &wall, WatchMode::Lost).await;

        let ticks_before = probe_b.ticks.load(Ordering::SeqCst);
        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "by sweep".into(),
            })
            .await
            .expect("send");
        settle().await;
        only_a_ticks(&wall).await;

        assert_eq!(
            probe_b.ticks.load(Ordering::SeqCst),
            ticks_before,
            "B's cadence must not have come round yet"
        );
        let early = drain(&mut evt_b);
        assert_eq!(
            messages(&early),
            Vec::new(),
            "with no watch standing there is nothing to collect the message early: \
             {early:?}"
        );
        // B's own cadence, and the message must be there — otherwise the emptiness
        // above is a driver that collects nothing rather than one that waits.
        both_tick(&wall).await;
        let late = drain(&mut evt_b);
        assert_eq!(
            messages(&late),
            vec![(1, "by sweep".to_string())],
            "the sweep cadence must collect what the watch did not: {late:?}"
        );
        assert!(
            dht_b.count(Method::WatchPage) > watches_at_switch,
            "B must still have ASKED for a watch AFTER the seam was switched — the \
             case is a watch that is lost, not a driver that stopped arming one. A \
             cumulative count is satisfied by the arming that established the \
             conversation"
        );

        let _ = drain(&mut evt_a);
        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// What one watch-mode run leaves behind, for a comparison between two of
    /// them.
    ///
    /// Every field is something a caller or the transport can actually see: what B
    /// emitted before its cadence came round, what it emitted when it did, what A's
    /// outbox reached, whether B ticked in the window, and what B asked the DHT for.
    /// A difference in any of them is a watch outcome that changed something other
    /// than the timing of a read.
    ///
    /// **The transport counts are here because the caller-visible fields alone are
    /// too coarse.** Two runs can deliver the same messages while one of them swept
    /// twice as many pages or left records open, and a watch outcome that changed
    /// the DHT load is exactly the kind of difference this comparison exists to
    /// catch. `watch_ops` is the one field a run is allowed to differ on — being
    /// asked at all is what separates a lost watch from one that was never armed.
    #[derive(Debug, PartialEq, Eq)]
    struct WatchRun {
        early: Vec<(u64, String)>,
        late: Vec<(u64, String)>,
        confirmed: Vec<u64>,
        next_send_seq: u64,
        ticked_early: bool,
        sweep_ops: u64,
        close_ops: u64,
        held_pages: usize,
    }

    /// Run the whole scenario once under `mode` and report what it left behind, plus
    /// the watch-seam call count the comparison must exclude.
    async fn watch_run(wall: &Arc<AtomicI64>, mode: WatchMode) -> (WatchRun, u64) {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_keys();
        let WatchPair {
            handle_a,
            mut evt_a,
            task_a,
            probe_a,
            handle_b,
            mut evt_b,
            task_b,
            probe_b,
            dht_b,
            ..
        } = watch_pair(dir_a.path(), dir_b.path(), wall, mode).await;
        // The arming control, and it reads differently per mode by design: the
        // baseline never asks, and every other mode must ask after the switch or it
        // is the baseline wearing another name.
        if mode == WatchMode::NeverArmed {
            assert_eq!(
                dht_b.count(Method::WatchPage),
                0,
                "the baseline run must never have reached the watch seam"
            );
        } else {
            assert!(
                dht_b.count(Method::WatchPage) >= 1,
                "B must have asked its watch seam whatever that seam answers"
            );
        }

        let ticks_before = probe_b.ticks.load(Ordering::SeqCst);
        handle_a
            .send(DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "either way".into(),
            })
            .await
            .expect("send");
        settle().await;
        only_a_ticks(wall).await;
        let early = messages(&drain(&mut evt_b));
        let ticked_early = probe_b.ticks.load(Ordering::SeqCst) != ticks_before;
        // B's own cadence, then a round for the acknowledgement to reach A.
        both_tick(wall).await;
        let late = messages(&drain(&mut evt_b));
        both_tick(wall).await;
        both_tick(wall).await;
        let confirmed = confirmations(&drain(&mut evt_a));
        let next_send_seq = probe_a.next_send_seq.load(Ordering::SeqCst);
        // Read before the shutdown, because a shutdown hands pages back and would
        // level `held_pages` across every run whatever it had been.
        let sweep_ops = dht_b.count(Method::SweepPage);
        let close_ops = dht_b.count(Method::ClosePage);
        let held_pages = dht_b.open_page_count();
        let watch_ops = dht_b.count(Method::WatchPage);

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
        (
            WatchRun {
                early,
                late,
                confirmed,
                next_send_seq,
                ticked_early,
                sweep_ops,
                close_ops,
                held_pages,
            },
            watch_ops,
        )
    }

    /// T34b. A watch that fails, a watch that is lost, and a driver that never
    /// armed one all leave the same state, and the next probe collects in every
    /// case.
    ///
    /// **Three runs compared field by field rather than asserted against
    /// written-out values.** What matters is not which messages arrive — the run
    /// beside it pins that — but that a transport error on the watch seam, a watch
    /// that is simply not standing, and a driver that never asked are
    /// indistinguishable downstream. A driver that folded any of them into some
    /// other state would differ here and nowhere else.
    ///
    /// **The never-armed run is the baseline the other two are measured against**,
    /// and it is the one that cannot be produced from the seam: a transport
    /// answering `Lost` has still been asked, so `watch_ops` is the single field the
    /// comparison excludes. Every other field — the messages, the confirmations, the
    /// send cursor, the sweeps, the closes, the records left open — must match a
    /// driver that has no watch code path in it at all.
    ///
    /// The positive control is inside the comparison: every run must collect the
    /// message on the cadence. Three runs that collected nothing would also be
    /// equal.
    #[tokio::test(start_paused = true)]
    async fn a_failed_watch_leaves_what_an_absent_one_leaves() {
        let wall_lost = Arc::new(AtomicI64::new(BASE_MS));
        let (lost, lost_watch_ops) = watch_run(&wall_lost, WatchMode::Lost).await;
        let wall_failing = Arc::new(AtomicI64::new(BASE_MS));
        let (failing, failing_watch_ops) = watch_run(&wall_failing, WatchMode::Failing).await;
        let wall_never = Arc::new(AtomicI64::new(BASE_MS));
        let (never, never_watch_ops) = watch_run(&wall_never, WatchMode::NeverArmed).await;

        assert_eq!(
            failing, lost,
            "a failing watch seam must leave the driver exactly where an absent \
             watch leaves it"
        );
        assert_eq!(
            lost, never,
            "a watch that is never standing must leave the driver exactly where a \
             driver that never armed one leaves it"
        );
        // The excluded field, asserted rather than merely excluded: the three runs
        // must differ on it, or they are the same run and their equality above is
        // about nothing.
        assert_eq!(
            never_watch_ops, 0,
            "the baseline must never reach the watch seam"
        );
        assert!(
            lost_watch_ops > 0 && failing_watch_ops > 0,
            "the other two runs must have asked for a watch ({lost_watch_ops}, \
             {failing_watch_ops}), or nothing distinguishes them from the baseline"
        );
        assert_eq!(
            lost.early,
            Vec::new(),
            "no run has a watch to collect early: {lost:?}"
        );
        assert_eq!(
            lost.late,
            vec![(1, "either way".to_string())],
            "the probe cadence must collect the message in every run: {lost:?}"
        );
        assert!(
            !lost.ticked_early,
            "the early window must be one B never ticked in, or `early` is empty \
             for the wrong reason: {lost:?}"
        );
    }

    /// T34c. A watch seam that answers `Lost` immediately, every time, does not
    /// become a loop.
    ///
    /// **A `Lost` resolves the moment it is asked for, and resolving is what frees
    /// the page to be armed again.** Nothing in that cycle waits, so a machine that
    /// re-armed on the resolution rather than on the cadence would arm without
    /// bound — and it would look exactly like this fixture, with messages still
    /// arriving on the sweep cadence and nothing failing.
    ///
    /// The bound is the collection: one watch per page it names, per cadence. The
    /// assertion is that ceiling, and the second one is the positive control — a
    /// driver that stopped arming altogether would satisfy any ceiling.
    #[tokio::test(start_paused = true)]
    async fn a_lost_watch_seam_arms_within_the_per_cadence_bound() {
        const ROUNDS: u64 = 5;
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let wall = Arc::new(AtomicI64::new(BASE_MS));
        let WatchPair {
            handle_a,
            mut evt_a,
            task_a,
            handle_b,
            mut evt_b,
            task_b,
            dht_b,
            watches_at_switch,
            ..
        } = watch_pair(dir_a.path(), dir_b.path(), &wall, WatchMode::Lost).await;

        for _ in 0..ROUNDS {
            both_tick(&wall).await;
            let _ = drain(&mut evt_a);
            let _ = drain(&mut evt_b);
        }

        let total = dht_b.count(Method::WatchPage);
        let armed = total - watches_at_switch;
        let ceiling = ROUNDS * daemonseed_core::dm::collect::WATCHED_PAGES as u64;
        assert!(
            armed <= ceiling,
            "{armed} watches armed over {ROUNDS} cadences ({watches_at_switch} -> \
             {total}), above the ceiling of {ceiling} — a lost watch is being \
             re-armed on its own resolution"
        );
        assert!(
            armed > 0,
            "no watch was armed over {ROUNDS} cadences ({watches_at_switch} -> \
             {total}), so the ceiling above is satisfied by a driver that stopped \
             arming"
        );

        handle_a.send(DmCommand::Shutdown).await.expect("stop A");
        handle_b.send(DmCommand::Shutdown).await.expect("stop B");
        task_a.await.expect("A ends");
        task_b.await.expect("B ends");
    }

    /// T34d. Closing a page record drops the watch standing on it, so a later
    /// change on that record fires nothing.
    ///
    /// The transport releases a watch with the record's session, and the mock has
    /// to do the same or every oracle above is written against a seam that keeps
    /// answering after the driver has handed the record back.
    ///
    /// The first assertion is the positive control: the record was genuinely held,
    /// so the close closed something.
    #[tokio::test(start_paused = true)]
    async fn a_closed_page_record_fires_no_watch() {
        let net = crate::dm::mock::MockNetwork::new();
        let dht = MockDht::on(net.clone(), Duration::from_millis(50));
        let r = ratchet();
        let conversation: [u8; AR_FINGERPRINT_LEN] = *receiving_address(&r).conversation();
        let recv_dir = receiving_address(&r).direction();

        let watching = dht.watch_dm_page(receiving_address(&r));
        assert!(
            dht.close_dm_page(DmPageRecord::Receiving(receiving_address(&r)))
                .await
                .expect("close"),
            "the watch must have held the record open, or the close below closed \
             nothing and the change has no watch to miss"
        );
        net.deliver_page_change(conversation, recv_dir, 0);

        assert_eq!(
            watching.await.expect("watch page"),
            DmPageWatch::Lost,
            "a change after the record was closed must not be reported as one"
        );
    }
}
