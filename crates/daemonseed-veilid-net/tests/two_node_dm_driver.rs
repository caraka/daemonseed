//! Integration test (#235, #236): the whole DM driver, end to end, over two real
//! nodes. A knocks at a stranger's doorbell, B is offered the request and accepts,
//! each side sends one channel message to the other, and each side's outbox settles
//! on the acknowledgement the other side wrote.
//!
//! ## What only this oracle can see
//!
//! `dm::driver`'s own `two_drivers_carry_a_round_trip_end_to_end_exactly_once` runs
//! the identical sequence against two drivers in one process, in paused time, over
//! a counting mock of the DHT seam. It proves the sequence. It cannot prove that
//! the sequence survives the network, and four of the ways it would not are silent:
//!
//! 1. **Every address is derived, never exchanged.** The doorbell slot, the key
//!    record, the channel page and the acknowledgement record are all computed
//!    independently at both ends, and the derivation *is* the rendezvous. The mock
//!    hands one shared store to both sides, so a derivation that disagreed between
//!    the writer and the reader would still round-trip there. Here a mismatch
//!    writes a perfectly valid record nobody ever reads.
//! 2. **The real store is eventually consistent and the mock is not.** A write
//!    returns before it has spread, so every hop below is a bounded *poll* rather
//!    than a read. A driver whose cadence only ever re-planned on a change it
//!    could observe locally would converge instantly against the mock and stall
//!    here.
//! 3. **Nothing is advanced by hand.** The mock oracle drives virtual time itself,
//!    so the cadence under test is the test's. This one runs on `WallClock::system`
//!    against a real `idle_tick`, which is the only place the driver's own
//!    scheduling is what moves the conversation forward.
//! 4. **The proof of work is minted and verified at the shipped difficulty.** The
//!    in-process oracles run at a reduced difficulty they configure on both sides.
//!    Here both drivers carry [`PowDifficulty::PRODUCTION`], so the knock B admits
//!    cost what a real knock costs.
//!
//! ## What is driven, and what is not
//!
//! Everything after the nodes are up goes through the drivers' own command and
//! event channels: `FirstContact`, `Accept`, `Send`, and the events each produces.
//! No `VeilidNetHandle` method is called by hand except node start, attach, and the
//! two key-record publishes — and that last one is not a shortcut. The DM seam
//! deliberately omits `publish_dm_key_record` (`dm::seam`: both front ends already
//! spawn that write at connect, and putting it on the seam would give one write two
//! production owners), so publishing each identity's key record is the front end's
//! job here exactly as it is in the app.
//!
//! ## Sequence numbers, because they are not symmetric
//!
//! The initiator's sequence zero is the knock, which travels by doorbell, so A's
//! first channel message is sequence **one**. The acceptor's sequence zero is the
//! acceptance itself — an ordinary outbox entry whose sealed body carries the
//! pseudonym key A needs before it can verify anything B writes — so B's reply is
//! also sequence one. A collects the acceptance as a message at sequence zero with
//! an empty body, which is that frame's shape.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! Where attach is blocked, `attach_and_wait` returns `NotReady` after the full
//! 180 s timeout. Run it on a host that can attach:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_dm_driver -- --ignored --nocapture
//!
//! Expect it to take many minutes: two nodes join the network, a proof of work is
//! minted at the difficulty production uses, and every hop waits for a write to
//! spread across the distributed hash table the records live in. Each hop prints
//! its own elapsed time, so a `--nocapture` run reads as a timeline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_core::dm::admission::AdmissionPolicy;
use daemonseed_core::dm::keyrec;
use daemonseed_core::dm::outbox::DeliveryState;
use daemonseed_core::dm::persist::DmPersist;
use daemonseed_core::dm::pow::PowDifficulty;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use daemonseed_veilid_net::{
    DmCommand, DmDriver, DmDriverConfig, DmDriverParts, DmEvent, DmIdentity, PkLt, RequestId,
    VeilidNet, VeilidNetConfig, VeilidNetHandle, WallClock,
};
use tokio::sync::mpsc::Receiver;

/// The at-rest key each side's `DmPersist` seals under. Per-run scratch profiles in
/// a temp dir, so this is a fixture rather than a secret.
const AT_REST: [u8; AEAD_KEY_LEN] = [0x2b; AEAD_KEY_LEN];

/// The driver's wake cadence. Every sweep, publish, acknowledgement write and
/// acknowledgement fetch below is planned on a tick, so this is what actually
/// moves the conversation — and it is the one knob a live run has to size against
/// the network rather than against a test's patience: fast enough that a hop is
/// not dominated by waiting for the next wakeup, slow enough not to re-read the
/// distributed hash table faster than a write can spread through it.
const IDLE_TICK: Duration = Duration::from_secs(15);

/// The budget for one ordinary hop: a write, its spread, and the correspondent's
/// next sweep of it.
///
/// Sized on what a sweep actually costs against a live distributed hash table
/// rather than against a mock. A doorbell sweep reads all 32 subkeys of the
/// record and a page sweep all 16, each subkey a separate network round trip of
/// several seconds — so a hop is one tick, plus the open, plus a whole sweep,
/// and a budget scaled to an in-process seam expires while the transport is
/// still working correctly.
const HOP: Duration = Duration::from_secs(600);

/// The budget for a hop that waits on an acknowledgement. Longer than [`HOP`] by
/// construction, and by one whole [`HOP`] plus change: the receiver has first to
/// collect the message, which is an ordinary hop; its standalone acknowledgement
/// is then floored at `ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS` (60 s) before
/// the write is even permitted; and the sender reads the record back on its own
/// cadence, which is a tick plus a single GET rather than a whole sweep. One hop,
/// the floor, the write, and that last short leg.
const ACK_HOP: Duration = Duration::from_secs(900);

/// How long both sides keep draining after the last assertion, before the
/// exactly-once counts are read.
///
/// **The counts are vacuous without it.** A sender re-seeds until acknowledged, so
/// the same bytes sit in the same slot and come back on every sweep — a driver that
/// folded on arrival rather than on settlement emits the body again, and would pass
/// a count taken the instant the first copy landed. The re-read that would expose
/// a double fold is a PAGE sweep — 16 subkey reads of several seconds each — and
/// it is not planned until the probe cadence next comes round, so the window has
/// to cover a whole probe interval and then a whole page sweep on top of it. A
/// shorter one closes while that re-read is still in progress, and the count it
/// takes proves nothing. Three hundred seconds covers a probe interval, the page
/// sweep it plans, and a second round of both.
const SETTLE: Duration = Duration::from_secs(300);

/// The bodies under test. Distinct from each other, from the knock, and from
/// anything a zero fill or a padding could produce, so a frame opened at the wrong
/// position could not pass for the right one.
const KNOCK_BODY: &str = "hello";
const A_BODY: &str = "first real message";
const B_BODY: &str = "and a reply";

/// A node config with a fresh daemonseed-derived node identity, a distinct listen
/// port, and its own storage dir — so two can coexist in one process. The node
/// identity is per-node and unrelated to the conversation: nothing about a doorbell
/// slot, a page address or a message key derives from a node key.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_driver{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

/// A throwaway user identity — an ML-DSA-87 signing keypair, an ML-KEM-1024
/// keypair and a doorbell slot secret, derived exactly as a real one is.
///
/// Fresh per run, and that is load-bearing rather than hygiene: the doorbell slot,
/// the key record and every channel address descend from these keys, and the
/// records PERSIST on the public network — so a fixed identity would sweep a
/// previous run's entries back and open stale bytes under a chain that had already
/// moved on.
fn identity() -> IdentityKeys {
    derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).expect("identity")
}

/// One driver's event stream plus every event it has produced so far.
///
/// Retaining them is what makes the waits composable: a hop that arrives while an
/// earlier one is still being waited for is buffered rather than dropped, so the
/// order the assertions are written in does not have to be the order the network
/// delivers in. The same buffer is what the exactly-once counts at the foot read.
struct Side {
    who: &'static str,
    rx: Receiver<DmEvent>,
    seen: Vec<DmEvent>,
    started: Instant,
}

impl Side {
    fn new(who: &'static str, rx: Receiver<DmEvent>) -> Self {
        Self {
            who,
            rx,
            seen: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Seconds since the run began, for the timeline.
    fn at(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Wait until `pick` matches an event this side has produced, or fail naming
    /// the hop.
    ///
    /// Already-buffered events are scanned first, so a hop that completed early is
    /// not waited for a second time.
    async fn wait_for<T>(
        &mut self,
        hop: &str,
        budget: Duration,
        mut pick: impl FnMut(&DmEvent) -> Option<T>,
    ) -> T {
        let hop_started = Instant::now();
        if let Some(found) = self.seen.iter().find_map(&mut pick) {
            eprintln!("[{:>7.1}s] {}: {hop} — already seen", self.at(), self.who);
            return found;
        }
        loop {
            let left = budget.saturating_sub(hop_started.elapsed());
            assert!(
                !left.is_zero(),
                "{}: timed out after {}s waiting for {hop}; events so far: {:?}",
                self.who,
                budget.as_secs(),
                self.seen
            );
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Some(event)) => {
                    let matched = pick(&event);
                    eprintln!("[{:>7.1}s] {}: {event:?}", self.at(), self.who);
                    self.seen.push(event);
                    if let Some(found) = matched {
                        eprintln!(
                            "[{:>7.1}s] {}: {hop} in {:.1}s",
                            self.at(),
                            self.who,
                            hop_started.elapsed().as_secs_f64()
                        );
                        return found;
                    }
                }
                Ok(None) => panic!("{}: the driver stopped before {hop}", self.who),
                Err(_) => panic!(
                    "{}: timed out after {}s waiting for {hop}; events so far: {:?}",
                    self.who,
                    budget.as_secs(),
                    self.seen
                ),
            }
        }
    }

    /// Keep buffering events for `window`, asserting nothing.
    async fn drain_for(&mut self, window: Duration) {
        let until = Instant::now() + window;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Some(event)) => {
                    eprintln!("[{:>7.1}s] {}: {event:?}", self.at(), self.who);
                    self.seen.push(event);
                }
                Ok(None) => return,
                Err(_) => return,
            }
        }
    }

    /// Every `(seq, body)` this side was shown as a message.
    fn messages(&self) -> Vec<(u64, String)> {
        self.seen
            .iter()
            .filter_map(|e| match e {
                DmEvent::Message { seq, body, .. } => Some((*seq, body.clone())),
                _ => None,
            })
            .collect()
    }

    /// How many times this side reported `(seq, state)`.
    fn delivery_count(&self, seq: u64, state: DeliveryState) -> usize {
        self.seen
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    DmEvent::Delivery { seq: s, state: t, .. } if *s == seq && *t == state
                )
            })
            .count()
    }
}

/// The parts one side's driver is built from.
fn parts(
    keys: IdentityKeys,
    node: Arc<VeilidNetHandle>,
    root: &std::path::Path,
) -> DmDriverParts<VeilidNetHandle> {
    DmDriverParts {
        dht: node,
        clock: WallClock::system(),
        identity: DmIdentity {
            signing: Arc::new(keys.signing),
            kem: keys.kem,
            doorbell_slot_secret: keys.dm_doorbell_slot_secret,
        },
        persist: DmPersist::open(root.join("dm"), &AT_REST).expect("persist opens"),
        cfg: DmDriverConfig {
            idle_tick: IDLE_TICK,
            policy: AdmissionPolicy::Open,
            // The shipped difficulty on both sides. A recipient always verifies at
            // production, so a reduced mint would be dropped by the very admission
            // path this oracle exists to run.
            pow_difficulty: PowDifficulty::PRODUCTION,
        },
        spent_tokens: None,
    }
}

/// Publish `keys`' DM key record from `node`, awaited.
///
/// The front end's job, not the driver's — `dm::seam::DmDht` omits this write on
/// purpose. Awaited rather than spawned so the knock below cannot race a record
/// that has not been written yet; a `NoKeyRecord` refusal caused by the test's own
/// ordering would be indistinguishable from the transport losing the write.
async fn publish_key_record(node: &VeilidNetHandle, keys: &IdentityKeys) {
    let record = keyrec::build_encoded(
        &keys.signing,
        keys.kem.encapsulation_key(),
        keyrec::DM_KEY_RECORD_VERSION,
        keyrec::DM_KEY_RECORD_INVITE_ONLY,
    )
    .expect("key record builds");
    let owner_seed = *keyrec::derive_owner_seed(keys.signing.public_key())
        .expect("key-record owner seed")
        .as_bytes();
    node.publish_dm_key_record(owner_seed, record)
        .await
        .expect("key record publishes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "attaches to the public Veilid network; opt-in, run with --ignored"]
async fn two_drivers_carry_a_first_contact_and_a_round_trip_over_the_real_network() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-driver-it");
    let _ = std::fs::remove_dir_all(&base);
    let profile_a = tempfile::tempdir().expect("profile A");
    let profile_b = tempfile::tempdir().expect("profile B");

    let a_keys = identity();
    let b_keys = identity();
    let a_pk: PkLt = Box::new(*a_keys.signing.public_key());
    let b_pk: PkLt = Box::new(*b_keys.signing.public_key());

    // ── the nodes ────────────────────────────────────────────────────────────
    let (node_a, _rx_a) = VeilidNet::start(node_config(":5182", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config(":5183", &base.join("B")))
        .await
        .expect("start B");
    node_a
        .attach_and_wait(180)
        .await
        .expect("A public-internet-ready");
    node_b
        .attach_and_wait(180)
        .await
        .expect("B public-internet-ready");

    // Each side publishes its own key record. A knocks at B's, and B reads A's
    // when it answers, so both are needed before the sequence starts.
    publish_key_record(&node_a, &a_keys).await;
    publish_key_record(&node_b, &b_keys).await;

    // ── the drivers ──────────────────────────────────────────────────────────
    let (handle_a, evt_a) = DmDriver::spawn(parts(a_keys, Arc::new(node_a), profile_a.path()));
    let (handle_b, evt_b) = DmDriver::spawn(parts(b_keys, Arc::new(node_b), profile_b.path()));
    let mut side_a = Side::new("A", evt_a);
    let mut side_b = Side::new("B", evt_b);

    // ── 1. A knocks ──────────────────────────────────────────────────────────
    handle_a
        .send(DmCommand::FirstContact {
            recipient: b_pk.clone(),
            body: KNOCK_BODY.into(),
        })
        .await
        .expect("A queues the first contact");
    side_a
        .wait_for("the knock is composed", HOP, |e| {
            matches!(
                e,
                DmEvent::Delivery {
                    seq: 0,
                    state: DeliveryState::Composed,
                    ..
                }
            )
            .then_some(())
        })
        .await;

    // ── 2. B is offered the request and accepts ──────────────────────────────
    //
    // The knock reaches B by derivation alone: B sweeps the doorbell its own slot
    // secret addresses, and A wrote into the slot A derived from B's public key.
    // Nothing about that slot was exchanged.
    let (request, from, body): (RequestId, PkLt, String) = side_b
        .wait_for("the knock arrives at B's doorbell", HOP, |e| match e {
            DmEvent::ContactRequest {
                request,
                from,
                body,
                ..
            } => Some((request.clone(), from.clone(), body.clone())),
            _ => None,
        })
        .await;
    assert_eq!(body, KNOCK_BODY, "B must be shown the body A sent");
    assert_eq!(from, a_pk, "B must be shown A as the sender");

    handle_b
        .send(DmCommand::Accept { request })
        .await
        .expect("B queues the accept");
    side_b
        .wait_for("B's acceptance is composed", HOP, |e| {
            matches!(
                e,
                DmEvent::Delivery {
                    seq: 0,
                    state: DeliveryState::Composed,
                    ..
                }
            )
            .then_some(())
        })
        .await;

    // ── 3. A collects the acceptance and installs B's pseudonym ──────────────
    //
    // **Nothing here was sent by a command.** B's acceptance was composed by the
    // accept above, published by B's own cadence and swept by A's, so what A opens
    // is the frame B's seal wrote, under a key A's ratchet derived, verified
    // against the long-term key A knocked at and nothing else. It surfaces as a
    // message at sequence zero with an empty body, which is the acceptance's shape
    // — and until it lands A can verify nothing B writes at all.
    let accepted = side_a
        .wait_for("A collects B's acceptance", HOP, |e| match e {
            DmEvent::Message { seq: 0, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(
        accepted, "",
        "the acceptance carries no body; a non-empty one is a different frame"
    );

    // ── 4. A sends on the channel ────────────────────────────────────────────
    handle_a
        .send(DmCommand::Send {
            to: b_pk.clone(),
            body: A_BODY.into(),
        })
        .await
        .expect("A queues the send");
    side_a
        .wait_for("A's message is composed", HOP, |e| {
            matches!(
                e,
                DmEvent::Delivery {
                    seq: 1,
                    state: DeliveryState::Composed,
                    ..
                }
            )
            .then_some(())
        })
        .await;
    let a_to_b = side_b
        .wait_for("B collects A's message", HOP, |e| match e {
            DmEvent::Message { seq: 1, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(a_to_b, A_BODY, "B must recover the exact body A sent");

    // ── 5. B replies, and A can now verify it ────────────────────────────────
    //
    // The harder direction: a channel frame carries no long-term identity, so this
    // is the half that was unreachable until the acceptance installed B's
    // pseudonym at A.
    handle_b
        .send(DmCommand::Send {
            to: a_pk.clone(),
            body: B_BODY.into(),
        })
        .await
        .expect("B queues the reply");
    let b_to_a = side_a
        .wait_for("A collects B's reply", HOP, |e| match e {
            DmEvent::Message { seq: 1, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(b_to_a, B_BODY, "A must recover the exact body B sent");

    // ── 6. both outboxes settle on the correspondent's acknowledgement ───────
    //
    // Either path is a pass and both are real: B's reply carries B's whole
    // collection state inside its own signature, and B's standalone cadence writes
    // the same statement to a record derived from the address root alone. Which
    // one arrives first is a race between two live cadences, and the property here
    // is that the sender's outbox settles — not which mechanism settled it.
    side_a
        .wait_for("A's message is confirmed collected", ACK_HOP, |e| {
            matches!(
                e,
                DmEvent::Delivery {
                    seq: 1,
                    state: DeliveryState::ConfirmedCollected,
                    ..
                }
            )
            .then_some(())
        })
        .await;
    side_b
        .wait_for("B's reply is confirmed collected", ACK_HOP, |e| {
            matches!(
                e,
                DmEvent::Delivery {
                    seq: 1,
                    state: DeliveryState::ConfirmedCollected,
                    ..
                }
            )
            .then_some(())
        })
        .await;

    // ── exactly once, not merely once ────────────────────────────────────────
    //
    // The re-seed is what makes this a real property: a sender rewrites the same
    // bytes into the same slot until it is acknowledged, so the frames asserted
    // above are still on the network and are still being swept during this window.
    // A driver that folded on arrival rather than on settlement emits each body
    // again here.
    //
    // Both sides drain concurrently, so the window is paid once. Sequentially it
    // would be paid twice, and the second side's would start after the first had
    // already run its course — twice the wait for no more evidence.
    tokio::join!(side_a.drain_for(SETTLE), side_b.drain_for(SETTLE));

    assert_eq!(
        side_b.messages(),
        vec![(1, A_BODY.to_string())],
        "B must have been shown A's message exactly once and nothing else"
    );
    assert_eq!(
        side_a.messages(),
        vec![(0, String::new()), (1, B_BODY.to_string())],
        "A must have been shown the acceptance and the reply, each exactly once"
    );
    assert_eq!(
        side_a.delivery_count(1, DeliveryState::ConfirmedCollected),
        1,
        "A must report its message collected exactly once: {:?}",
        side_a.seen
    );
    assert_eq!(
        side_b.delivery_count(1, DeliveryState::ConfirmedCollected),
        1,
        "B must report its reply collected exactly once: {:?}",
        side_b.seen
    );

    eprintln!(
        "live DM driver oracle: knock -> doorbell -> accept -> acceptance -> \
         channel round trip -> both outboxes confirmed collected, in {:.1}s",
        side_a.at()
    );

    handle_a.send(DmCommand::Shutdown).await.expect("stop A");
    handle_b.send(DmCommand::Shutdown).await.expect("stop B");
}
