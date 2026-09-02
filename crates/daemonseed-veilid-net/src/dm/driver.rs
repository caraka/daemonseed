//! The DM driver's thin async shell.
//!
//! The shell owns the awaits and nothing else: it reads the injected clock, hands
//! the value to the machine, spawns whatever DHT operations the machine asked
//! for off its own loop into a [`JoinSet`], and forwards the machine's events to
//! the front end. Every decision belongs to the machine, so the shell has nothing
//! in it a test would want to reach past.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;

use daemonseed_core::dm::persist::DmPersist;

use crate::dm::machine::{DhtOp, DhtOutcome, DhtResult, DmEffect, DmMachine};
use crate::dm::seam::DmDht;
use crate::dm::types::{DmCommand, DmEvent, DmIdentity, WallClock};
use crate::{Result, VeilidNetError};

/// Commands the front end may have outstanding before the driver drains them.
const COMMAND_QUEUE: usize = 64;

/// Events the driver may have outstanding before the front end drains them.
const EVENT_QUEUE: usize = 256;

/// The driver's cadence knobs.
///
/// Items 2-4 add sweep, acknowledgement and give-up knobs alongside `idle_tick`.
#[derive(Clone, Debug)]
pub struct DmDriverConfig {
    /// How long the driver sleeps when nothing else wakes it. Must be non-zero.
    pub idle_tick: Duration,
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
    /// The cadence knobs.
    pub cfg: DmDriverConfig,
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
    /// The seam over the machine's silence: item 1 returns no effects, so the
    /// shell's spawn / emit / join paths would otherwise be unreachable by any
    /// oracle. Production seeds nothing.
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
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
        let (evt_tx, evt_rx) = mpsc::channel(EVENT_QUEUE);
        let task = tokio::spawn(run(parts, cmd_rx, evt_tx, probe, seed));
        (DmDriverHandle { cmd_tx }, evt_rx, task)
    }
}

/// What woke the loop. Named so the clock is re-read *after* the await rather
/// than before it: a value read before a 30-second sleep is 30 seconds stale by
/// the time a step function sees it.
enum Woke {
    Command(DmCommand),
    Outcome(DhtOutcome),
    Tick,
    /// A spawned operation's task panicked. Distinct from `Tick`, because a panic
    /// in the seam is not a cadence event: counting it as one would inflate the
    /// tick count and run the machine's idle step at a moment nothing was due.
    Panicked,
    Stop,
}

async fn run<D: DmDht>(
    parts: DmDriverParts<D>,
    mut cmd_rx: mpsc::Receiver<DmCommand>,
    evt_tx: mpsc::Sender<DmEvent>,
    probe: Arc<DmDriverProbe>,
    seed: Vec<DmEffect>,
) {
    let DmDriverParts {
        dht,
        clock,
        identity,
        persist,
        cfg,
    } = parts;
    let started_ms = clock.now_ms();
    let mut machine = DmMachine::new(identity, persist, cfg);
    let mut inflight: JoinSet<DhtOutcome> = JoinSet::new();

    if !apply(seed, &dht, &mut inflight, &evt_tx, &probe).await {
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
            Some(joined) = inflight.join_next(), if !inflight.is_empty() => {
                probe.ops_completed.fetch_add(1, Ordering::SeqCst);
                match joined {
                    Ok(outcome) => Woke::Outcome(outcome),
                    // A DHT task cannot return an error of its own — every failure
                    // travels inside `DhtOutcome::result` — so a join error is a
                    // panic in the seam. The driver survives it and records it.
                    Err(_) => Woke::Panicked,
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
            Woke::Panicked => {
                probe.ops_panicked.fetch_add(1, Ordering::SeqCst);
                Vec::new()
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

        if !apply(effects, &dht, &mut inflight, &evt_tx, &probe).await {
            return;
        }
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
    inflight: &mut JoinSet<DhtOutcome>,
    evt_tx: &mpsc::Sender<DmEvent>,
    probe: &DmDriverProbe,
) -> bool {
    for effect in effects {
        match effect {
            DmEffect::Dht(op) => {
                probe.ops_started.fetch_add(1, Ordering::SeqCst);
                inflight.spawn(dispatch(dht.clone(), op));
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

    use crate::actor::{DoorbellDispatch, VeilidNetHandle};
    use crate::dm::machine::{duration_as_ms, OpTag};
    use crate::dm::mock::{Method, MockCall, MockDht};

    const IDLE_TICK: Duration = Duration::from_secs(30);
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
        OpTag {
            conversation: None,
            seq: None,
        }
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
            },
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

    /// T1. An idle driver wakes on its cadence and touches no record.
    ///
    /// `ticks == 3` is the positive control: without it the seven zeros below are
    /// satisfied by a loop that never ran at all.
    #[tokio::test(start_paused = true)]
    async fn idle_driver_ticks_and_touches_no_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wall = Arc::new(AtomicI64::new(1_700_000_000_000));
        let dht = Arc::new(MockDht::new(Duration::from_millis(50)));
        let probe = Arc::new(DmDriverProbe::new());
        let (handle, mut evt_rx, task) =
            DmDriver::spawn_with_probe(parts(&dir, &wall, dht.clone()), probe.clone());

        for _ in 0..3 {
            advance(&wall, IDLE_TICK).await;
        }

        assert_eq!(
            probe.ticks.load(Ordering::SeqCst),
            3,
            "the loop woke thrice"
        );
        for method in Method::ALL {
            assert_eq!(dht.count(method), 0, "{method:?} was never asked for");
        }
        assert!(dht.log().is_empty(), "no call was recorded");
        assert_eq!(probe.ops_started.load(Ordering::SeqCst), 0);
        assert_eq!(probe.ops_panicked.load(Ordering::SeqCst), 0);

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
        assert!(evt_rx.recv().await.is_none());
        task.await.expect("the driver task ends");
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
            })],
        );

        let event = evt_rx.recv().await.expect("one event");
        match event {
            DmEvent::DoorbellHealth { outcome } => {
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
}
