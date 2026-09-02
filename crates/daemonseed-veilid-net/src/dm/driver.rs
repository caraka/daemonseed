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
}

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
            steps_applied: AtomicU64::new(0),
        }
    }
}

/// The DM driver.
pub struct DmDriver;

impl DmDriver {
    /// Spawn the driver and return the handle plus the event stream.
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
            .expect("this identity's doorbell owner seed must derive")
            .as_bytes();
        let keyrec_addr = *daemonseed_core::dm::keyrec::derive_owner_seed(public)
            .expect("this identity's key-record owner seed must derive")
            .as_bytes();

        let mut startup = seed;
        let provisioned = parts
            .persist
            .provision_block_list()
            .expect("the profile's block list must be provisionable");
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
        (DmDriverHandle { cmd_tx }, evt_rx, task)
    }
}

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
    let mut inflight: JoinSet<DmOutcome> = JoinSet::new();
    // What each in-flight task is doing, for the one thing a `JoinError` can be
    // asked: which task died. A `JoinSet` hands back the task's id on both the
    // success and the panic path, so the map is the only route from a dead task
    // to the state it was holding.
    let mut jobs: std::collections::HashMap<tokio::task::Id, PanickedJob> =
        std::collections::HashMap::new();

    if !apply(seed, &dht, &mut inflight, &mut jobs, &evt_tx, &probe).await {
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
                let introduction = op.introduction();
                let dht = dht.clone();
                let handle = inflight.spawn(async move { DmOutcome::Dht(dispatch(dht, op).await) });
                if let Some(pk) = introduction {
                    jobs.insert(handle.id(), PanickedJob::Dht(pk));
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
async fn dispatch<D: DmDht>(dht: Arc<D>, op: DhtOp) -> DhtOutcome {
    match op {
        DhtOp::FetchKeyRecord { tag, owner_seed } => DhtOutcome {
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
            tag,
            result: dht
                .publish_doorbell_entry(owner_seed, slot, entry, dispatch)
                .await
                .map(|()| DhtResult::Written),
        },
        DhtOp::SweepDoorbell { tag, owner_seed } => DhtOutcome {
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
            tag,
            result: dht
                .publish_dm_page(address, frame)
                .await
                .map(|()| DhtResult::Written),
        },
        DhtOp::SweepPage { tag, address } => DhtOutcome {
            tag,
            result: dht.sweep_dm_page(address).await.map(DhtResult::Page),
        },
        DhtOp::PublishAck {
            tag,
            address,
            record,
        } => DhtOutcome {
            tag,
            result: dht
                .publish_dm_ack(address, record)
                .await
                .map(|()| DhtResult::Written),
        },
        DhtOp::FetchAck { tag, address } => DhtOutcome {
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

    use crate::actor::{DoorbellDispatch, VeilidNetHandle};
    use crate::dm::machine::{duration_as_ms, OpTag};
    use crate::dm::mock::{Method, MockCall, MockDht};
    use crate::dm::types::RefusalReason;
    use crate::dm::RequestId;

    const IDLE_TICK: Duration = Duration::from_secs(30);
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
            .ar
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
        let dht = MockDht::new(Duration::from_millis(50));
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
        dht.publish_dm_ack(ack_address(Direction::AToB), vec![0u8; 13])
            .await
            .expect("ack");
        dht.fetch_dm_ack(ack_address(Direction::BToA))
            .await
            .expect("fetch ack");

        assert_eq!(Method::ALL.len(), 7, "the seam has seven methods");
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
            MockCall::PublishAck {
                direction: Direction::AToB,
                record_len: 13,
            }
        );
        assert_eq!(
            log[6],
            MockCall::FetchAck {
                direction: Direction::BToA
            }
        );
    }

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
            DhtOp::PublishAck { .. } => 5,
            DhtOp::FetchAck { .. } => 6,
        }
    }

    /// T2b. `dispatch` routes every op to its own seam method and shapes the
    /// result to match.
    ///
    /// The routing is seven near-identical arms, which is exactly the shape a
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
                op: DhtOp::PublishAck {
                    tag: tag(),
                    address: ack_address(Direction::AToB),
                    record: vec![0u8; 13],
                },
                method: Method::PublishAck,
                shape: |res| matches!(res, DhtResult::Written),
            },
            Case {
                op: DhtOp::FetchAck {
                    tag: tag(),
                    address: ack_address(Direction::BToA),
                },
                method: Method::FetchAck,
                shape: |res| matches!(res, DhtResult::Ack(None)),
            },
        ];

        let mut covered: Vec<usize> = cases.iter().map(|c| op_index(&c.op)).collect();
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(
            covered.len(),
            Method::ALL.len(),
            "every DhtOp variant is covered exactly once"
        );

        for Case { op, method, shape } in cases {
            let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
            let outcome = dispatch(dht.clone(), op).await;
            let result = outcome.result.expect("the mock succeeds");
            assert!(shape(&result), "{method:?} returned the wrong result shape");
            for other in Method::ALL {
                let expected = u64::from(other == method);
                assert_eq!(dht.count(other), expected, "{method:?} called {other:?}");
            }
        }
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
        assert_eq!(contact.pk_pc().as_slice(), pc.public_key().as_slice());

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

        // The provisional record is on disk. Exactly one correspondence exists,
        // and it holds one — asserted through the store rather than by counting
        // effects, so a driver that emitted the write and skipped the persist
        // fails here.
        let labels = store.store().correspondences().expect("list");
        assert_eq!(labels.len(), 1, "one correspondence was established");
        assert!(
            store
                .store()
                .read_unlocked(
                    &labels[0],
                    daemonseed_core::storage::dm_store::RecordKind::Provisional
                )
                .expect("read")
                .is_some(),
            "the provisional record was not written"
        );
        // And it OPENS under the recipient's own context. Presence alone is a
        // weaker claim than it looks: the record's seal binds the recipient's
        // key-record address and the first-contact epoch, so one sealed under
        // the wrong context is a file that exists and a handshake that can
        // never resume — and nothing else in this slice would notice.
        let addr = daemonseed_core::dm::keyrec::derive_owner_seed(peer.signing.public_key())
            .expect("recipient key-record address");
        let restart = store.restart_channel(
            &labels[0],
            &daemonseed_core::dm::provisional::RecordContext {
                recipient_keyrec_addr: addr.as_bytes(),
                fc_epoch: keyrec::fc_epoch((BASE_MS / 1000) as u64),
            },
        );
        assert!(
            matches!(
                restart,
                daemonseed_core::dm::persist::StoredChannelRestart::HandshakeResumes(_)
            ),
            "the provisional record does not open under the recipient's context"
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
                    surfaced,
                } => Some((with.to_vec(), format!("{cause:?}"), surfaced.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(lost.len(), 1, "expected one ChannelLost, got {events:?}");
        assert_eq!(lost[0].0.as_slice(), peer.signing.public_key().as_slice());
        assert_eq!(lost[0].1, "CorrespondentStateLost");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DmEvent::ContactRequest { .. })),
            "a known correspondent's re-knock surfaced a second request"
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
}
