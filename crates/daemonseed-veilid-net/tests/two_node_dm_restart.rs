//! Integration test (#401, #402): what a direct-message correspondence can and
//! cannot do after the process that owns it has restarted, over two real nodes.
//!
//! Two restarts, and each ends in a message the correspondent opens:
//!
//! 1. **A sender that restarts between its knock and the acceptance carries on.**
//!    Its per-correspondent signing keypair comes back from the provisional
//!    record when the handshake is re-armed, so the new process collects the
//!    acceptance, composes an ordinary frame under the keypair the knock
//!    published, and the correspondent opens it.
//! 2. **A correspondence that restarts after it was established re-establishes
//!    and carries a message each way.** Both sides come back holding every part
//!    a frame needs — the channel roots and the keypair read back from the
//!    resume record — and the three-leg exchange mints the key schedule. The two
//!    sides open the resumed channel at one agreed generation, carried inside
//!    the settling legs, so the number the sender seals under is the number the
//!    correspondent opens at.
//!
//!    **A restart on its own starts nothing.** The exchange has one standing
//!    cause: a message composed while the correspondence holds no key schedule.
//!    Such a message reserves its sequence number at once, holds no frame, and
//!    arms the exchange that will give it a key. So each side is commanded to
//!    send before anything is waited for, and the two waiting messages are what
//!    open the exchange.
//!
//!    **The two sides are not symmetric, and the asymmetry is the second
//!    claim.** The party that asked for the re-establishment owns the only chain
//!    under the re-rooted root, so its waiting message is sealed as the exchange
//!    settles. The answering party holds a receiving chain until that first
//!    frame publishes the ephemeral its own chain steps off, so its own waiting
//!    message is sealed a hop later, when that frame opens. Each keeps the
//!    sequence it reserved.
//!
//! ## What only this oracle can see
//!
//! `dm::machine`'s own `two_drivers_survive_a_restart_of_both_stores` runs the
//! same three-leg exchange between two machines in one process, in paused time,
//! handing each leg from one to the other by hand. It proves the sequence. Four
//! of the ways the sequence would not survive a network are invisible there:
//!
//! 1. **A restart is simulated by dropping a machine and building another over
//!    the same directory; here it is a driver stopping and a second one opening
//!    the store it left behind.** Everything a running driver held in memory —
//!    the collection cursor, the held requests, the pseudonym keypair — is gone,
//!    and what comes back is what the records on disk say.
//! 2. **The re-establishment legs travel by derivation.** Each side addresses
//!    the channel page from the address root it kept, and neither exchanges an
//!    address. In the unit test one machine's write is handed to the other, so a
//!    derivation that disagreed between the writer and the reader would still
//!    round-trip. Here it writes a valid record nobody reads.
//! 3. **A leg carries no discriminator.** The leg kind, the generation and the
//!    attempt each side needs to open a frame come from its own record. The unit
//!    test's hand-off preserves the ordering; a real sweep does not, and a page
//!    holds the dead chain's frames beside the live one's.
//! 4. **The first dispatch is drawn from a band of hours.** The unit test steps
//!    its clock past the band; here the wait is real, which is the only place
//!    the deferral is exercised as scheduling rather than as arithmetic.
//!
//! ## What is asserted, and what it rests on
//!
//! The resume records are read from disk on both sides before any message is
//! followed, because a message crossing says nothing about a re-establishment
//! having produced the keys that carried it:
//!
//! - each side's `reconnect_gen` is 1, which only a completed exchange writes;
//! - each side's committed root is not the one it held before the restart;
//! - the two sides' committed roots are equal, which is the property no
//!   in-process fixture can claim — two independently-derived roots agreeing
//!   after three legs crossed a real network.
//!
//! **Which side asked for the re-establishment is decided by the network, not by
//! this oracle.** Both sides defer a first dispatch into the same band and the
//! exchange runs on whichever draw came up first, so nothing here names a role:
//! every assertion is written per side and holds whichever way the draws fell.
//!
//! Each side's outbox counter is read before and after its send, because the
//! reservation is the claim. The message is reported composed at the sequence
//! the counter held, the counter moves by exactly that one, and nothing further
//! is spent until the exchange's own legs ride the same outbox.
//!
//! Four frames are then followed the whole way. Each side's waiting message is
//! opened by its correspondent at the sequence that side's outbox reported at
//! compose, with the exact body — which is what says the reserved number and the
//! sealed number are one number, since a frame opens only at the position its
//! key was minted for. Each side then sends once more, and that frame takes a
//! position above the ones the exchange's own legs occupy, which is the outbox
//! rather than the key schedule deciding where a resumed chain continues. Every
//! sender's outbox settles on a verified acknowledgement. The bodies and the
//! acknowledgements are counted once more after a settling window, because a
//! sender re-seeds the same bytes into the same slot until it is acknowledged:
//! the frames are still on the network and still being swept while that window
//! runs, so a build that folded on arrival rather than on settlement reports a
//! second copy into it.
//!
//! `#[ignore]` — both tests attach to the PUBLIC Veilid network. Where attach is
//! blocked, `attach_and_wait` returns `NotReady` after the full 180 s timeout.
//! Run them on a host that can attach:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_dm_restart -- \
//!         --ignored --nocapture --test-threads=1
//!
//! One at a time: each test starts two nodes of its own, and the network is the
//! shared resource. **The resumed test takes hours**, and that is the design
//! rather than the transport: a re-establishment leg's first dispatch is drawn
//! from a band centred on `RECONNECT_FIRST_DISPATCH` (four hours, one to seven
//! with its jitter), so that a device coming back with many interrupted
//! correspondences does not first-dispatch all of them from one boot instant.
//! Every hop prints its own elapsed time, so a `--nocapture` run reads as a
//! timeline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_core::dm::admission::AdmissionPolicy;
use daemonseed_core::dm::keyrec;
use daemonseed_core::dm::outbox::{DeliveryState, RECONNECT_FIRST_DISPATCH};
use daemonseed_core::dm::persist::DmPersist;
use daemonseed_core::dm::pow::PowDifficulty;
use daemonseed_core::dm::resume::ResumeRecord;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::storage::dm_store::CorrespondenceLabel;
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use daemonseed_veilid_net::{
    DmCommand, DmDriver, DmDriverConfig, DmDriverHandle, DmDriverParts, DmEvent, DmIdentity, PkLt,
    RefusalReason, RequestId, VeilidNet, VeilidNetConfig, VeilidNetHandle, WallClock,
};
use tokio::sync::mpsc::Receiver;

/// The at-rest key each side's `DmPersist` seals under. Per-run scratch profiles
/// in a temp dir, so this is a fixture rather than a secret.
const AT_REST: [u8; AEAD_KEY_LEN] = [0x2b; AEAD_KEY_LEN];

/// The driver's wake cadence. Every sweep, publish and fetch below is planned on
/// a tick, so this is what moves the conversation — fast enough that a hop is not
/// dominated by waiting for the next wakeup, slow enough not to re-read the
/// distributed hash table faster than a write can spread through it.
const IDLE_TICK: Duration = Duration::from_secs(15);

/// The budget for one ordinary hop: a write, its spread, and the correspondent's
/// next sweep of it. A doorbell sweep reads all 32 subkeys of the record and a
/// page sweep all 16, each subkey a separate network round trip of several
/// seconds, so a hop is one tick plus a whole sweep.
const HOP: Duration = Duration::from_secs(600);

/// The budget for a hop that waits on an acknowledgement. Longer than [`HOP`] by
/// one whole hop plus change: the correspondent has first to collect the frame,
/// which is an ordinary hop; its standalone acknowledgement is then floored at
/// `ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS` (60 s) before the write is even
/// permitted; and the sender reads the record back on its own cadence, which is
/// a tick plus a single GET rather than a whole sweep.
const ACK_HOP: Duration = Duration::from_secs(900);

/// How long a stopping driver is given to end.
///
/// The driver drops its event sender as its loop returns, which is what closes
/// the receiver, so this covers one command hop through a full queue and
/// whatever the last step was still doing.
const STOP: Duration = Duration::from_secs(120);

/// The pause between a driver stopping and a second one opening the store it
/// held.
///
/// The event sender drops as the run loop returns and the store handle drops
/// with the rest of that frame, so the closed receiver is a signal that the
/// store is *about* to be released rather than that it has been. Two drivers
/// over one profile would race for the same due entries.
const HANDOVER: Duration = Duration::from_secs(5);

/// How often the resume record is re-read while waiting for a re-establishment.
///
/// Nothing is driven by this: the exchange runs on the drivers' own cadence and
/// this only decides how soon its completion is noticed. Each interval is spent
/// draining the event streams rather than sleeping — see
/// [`wait_for_reestablishment`].
const POLL: Duration = Duration::from_secs(30);

/// How long both sides keep draining after the last hop, before the
/// exactly-once counts and the refusal list are read.
///
/// **The counts are vacuous without it.** A sender re-seeds until acknowledged,
/// so the same bytes sit in the same slot and come back on every sweep — a fold
/// taken on arrival rather than on settlement emits the body again, and would
/// pass a count read the instant the first copy landed. The re-read that would
/// expose a double fold is a PAGE sweep, 16 subkey reads of several seconds
/// each, and it is not planned until the probe cadence next comes round; so the
/// window has to cover a whole probe interval, the page sweep it plans, and a
/// second round of both. It is what makes an empty refusal list a claim as well:
/// `Side::refusals` reads what has been buffered, so a refusal arriving after
/// the last hop would be invisible to a list read the moment the bodies matched.
const SETTLE: Duration = Duration::from_secs(300);

/// The bodies under test. Distinct from each other, from the knock, and from
/// anything a zero fill or a padding could produce, so a frame opened at the
/// wrong position could not pass for the right one.
///
/// Two per side on the resumed channel, and the pair is what tells the two
/// sealing sites apart: the waiting body was composed while the correspondence
/// held no key schedule and is sealed at the sequence it reserved, and the
/// resumed body is sent once the channel carries keys and takes a position above
/// the exchange's own legs. The body that arrives says which of the two it is.
const KNOCK_BODY: &str = "hello";
const A_BODY: &str = "first real message";
const A_WAITING_BODY: &str = "from A, composed while no key schedule existed";
const B_WAITING_BODY: &str = "from B, composed while no key schedule existed";
const A_RESUMED_BODY: &str = "from A, sent once the resumed channel carried keys";
const B_RESUMED_BODY: &str = "from B, sent once the resumed channel carried keys";

/// The budget for a whole re-establishment: the band a first dispatch is drawn
/// from, then three legs, each of which is a page write and the correspondent's
/// next sweep of it.
///
/// **Twice the band's centre**, which covers its ceiling with room to spare —
/// the band is `RECONNECT_FIRST_DISPATCH` ± `RECONNECT_JITTER_FRAC`, so four
/// hours ± three. Both sides draw independently and either may initiate; the
/// exchange starts on the earlier draw.
fn reestablishment_budget() -> Duration {
    RECONNECT_FIRST_DISPATCH * 2 + HOP * 3
}

/// A node config with a fresh daemonseed-derived node identity, a distinct
/// listen port, and its own storage dir — so two can coexist in one process.
///
/// The node identity is per-node and unrelated to the conversation: nothing
/// about a doorbell slot, a page address or a message key derives from a node
/// key, which is why it is generated here rather than carried with the user
/// identity across a restart.
fn node_config(who: &str, port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_restart_{who}{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

/// A throwaway user identity — an ML-DSA-87 signing keypair, an ML-KEM-1024
/// keypair and a doorbell slot secret, derived exactly as a real one is.
///
/// **The mnemonic is held rather than the keys, because a restart re-derives.**
/// A driver takes its identity by value, so the second driver over one profile
/// needs its own copy, and deriving it the way a front end does at start-up is
/// the faithful version: a restart that kept the first driver's keys alive in a
/// local would not be a restart of the identity at all.
///
/// Fresh per run, and necessarily so: the doorbell
/// slot, the key record and every channel address descend from these keys, and
/// the records PERSIST on the public network — so a fixed identity would sweep a
/// previous run's entries back and open stale bytes under a chain that had
/// already moved on.
fn identity(mnemonic: &Mnemonic) -> IdentityKeys {
    derive_identity_keys(mnemonic, Identity::Primary).expect("identity")
}

/// One driver's event stream plus every event it has produced so far.
///
/// Retaining them is what makes the waits composable: a hop that arrives while
/// an earlier one is still being waited for is buffered rather than dropped, so
/// the order the assertions are written in does not have to be the order the
/// network delivers in.
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

    /// Seconds since this side's driver started, for the timeline.
    fn at(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Wait until `pick` matches an event this side has produced, or fail naming
    /// the hop.
    ///
    /// Already-buffered events are scanned first, so a hop that completed early
    /// is not waited for a second time.
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

    /// Buffer every event for `window`, asserting nothing.
    ///
    /// **A driver that ends during the window is a failure, not the end of the
    /// drain.** Its event stream closes either way, and a drain that returned
    /// quietly on it would hand the caller a silence that reads as patience.
    async fn drain_for(&mut self, window: Duration) {
        let until = Instant::now() + window;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Some(event)) => {
                    eprintln!("[{:>7.1}s] {}: {event:?}", self.at(), self.who);
                    self.seen.push(event);
                }
                Ok(None) => panic!("{}: the driver stopped while it was draining", self.who),
                Err(_) => return,
            }
        }
    }

    /// Every refusal reason this side has been given.
    fn refusals(&self) -> Vec<RefusalReason> {
        self.seen
            .iter()
            .filter_map(|e| match e {
                DmEvent::Refused { reason, .. } => Some(*reason),
                _ => None,
            })
            .collect()
    }

    /// Every message this side has been shown, as `(sequence, body)`.
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
            // The shipped difficulty on both sides. A recipient always verifies
            // at production, so a reduced mint would be dropped by the very
            // admission path this oracle exists to run.
            pow_difficulty: PowDifficulty::PRODUCTION,
        },
        spent_tokens: None,
    }
}

/// Publish `keys`' DM key record from `node`, awaited.
///
/// The front end's job, not the driver's — `dm::seam::DmDht` omits this write on
/// purpose. Awaited rather than spawned so the knock below cannot race a record
/// that has not been written yet; a `NoKeyRecord` refusal caused by the test's
/// own ordering would be indistinguishable from the transport losing the write.
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

/// Stop one driver and wait until its event stream closes.
///
/// The closed stream is the front end's only signal that the driver is gone, and
/// waiting for it is what separates a restart from two drivers over one profile.
async fn stop(handle: &DmDriverHandle, side: &mut Side) {
    handle
        .send(DmCommand::Shutdown)
        .await
        .expect("the driver takes the shutdown");
    let asked = Instant::now();
    loop {
        let left = STOP.saturating_sub(asked.elapsed());
        assert!(
            !left.is_zero(),
            "{}: the driver did not stop within {}s",
            side.who,
            STOP.as_secs()
        );
        match tokio::time::timeout(left, side.rx.recv()).await {
            Ok(Some(event)) => side.seen.push(event),
            Ok(None) => break,
            Err(_) => panic!(
                "{}: the driver did not stop within {}s",
                side.who,
                STOP.as_secs()
            ),
        }
    }
    eprintln!("[{:>7.1}s] {}: stopped", side.at(), side.who);
    tokio::time::sleep(HANDOVER).await;
}

/// The label the profile holds for `peer`, or fail.
///
/// A contact record is written by both roles — the initiator's at first contact,
/// the acceptor's when it establishes — so this resolves on either side once the
/// knock has been composed.
fn label_for(store: &DmPersist, peer: &PkLt) -> CorrespondenceLabel {
    store
        .correspondence_for_pk_lt(peer)
        .expect("the correspondence lookup reads")
        .expect("the profile holds a correspondence with this identity")
}

/// The resume record the profile holds for `label`, or fail.
fn resume_of(store: &DmPersist, label: &CorrespondenceLabel) -> ResumeRecord {
    store
        .read_resume(label)
        .expect("the resume record reads")
        .expect("the correspondence has a resume record")
}

/// What the outbox has spent on this correspondence: the next sequence number a
/// channel write would take.
///
/// Read from disk rather than from an event, because a refusal that spent a
/// sequence number and one that did not emit the same event.
fn next_send_seq(store: &DmPersist, label: &CorrespondenceLabel) -> u64 {
    store
        .read_outbox(label, WallClock::system().now_ms())
        .expect("the outbox reads")
        .expect("the correspondence has an outbox")
        .next_send_seq()
}

/// Re-read both resume records until each records a completed
/// re-establishment, draining both event streams while it waits.
///
/// **The drain is what keeps the drivers running.** A driver's event sender is
/// a bounded channel and its emit awaits a free slot, so a front end that stops
/// reading stops the driver's loop at whatever it was doing. Nothing here waits
/// on an event — the records are the evidence — but a wait this long with no
/// reader would suspend the cadence the exchange itself runs on, and the
/// failure would read as a network that never delivered.
///
/// `reconnect_gen` advances only on a completed handshake, from either end, so
/// reaching one is the record's own statement that three legs crossed the
/// network. **Exactly one**, because exactly one restart happened: a record past
/// it has run an exchange nothing here asked for.
async fn wait_for_reestablishment(
    a: (&mut Side, &DmPersist, &CorrespondenceLabel),
    b: (&mut Side, &DmPersist, &CorrespondenceLabel),
    budget: Duration,
) -> (ResumeRecord, ResumeRecord) {
    let (side_a, store_a, label_a) = a;
    let (side_b, store_b, label_b) = b;
    let waited = Instant::now();
    loop {
        let a_record = resume_of(store_a, label_a);
        let b_record = resume_of(store_b, label_b);
        for (who, record) in [(side_a.who, &a_record), (side_b.who, &b_record)] {
            assert!(
                record.reconnect_gen() <= 1,
                "{who}: the record reads generation {}, and one restart happened",
                record.reconnect_gen()
            );
        }
        if a_record.reconnect_gen() == 1 && b_record.reconnect_gen() == 1 {
            eprintln!(
                "[{:>7.1}s] both sides re-established at generation 1",
                waited.elapsed().as_secs_f64()
            );
            return (a_record, b_record);
        }
        assert!(
            waited.elapsed() < budget,
            "no re-establishment completed within {}s; {} reads generation {}, own slot {}, \
             acceptance {}; {} reads generation {}, own slot {}, acceptance {}",
            budget.as_secs(),
            side_a.who,
            a_record.reconnect_gen(),
            a_record.own_slot().is_some(),
            a_record.acceptance().is_some(),
            side_b.who,
            b_record.reconnect_gen(),
            b_record.own_slot().is_some(),
            b_record.acceptance().is_some()
        );
        eprintln!(
            "[{:>7.1}s] {}: generation {}, own slot {}, acceptance {} | {}: generation {}, \
             own slot {}, acceptance {}",
            waited.elapsed().as_secs_f64(),
            side_a.who,
            a_record.reconnect_gen(),
            a_record.own_slot().is_some(),
            a_record.acceptance().is_some(),
            side_b.who,
            b_record.reconnect_gen(),
            b_record.own_slot().is_some(),
            b_record.acceptance().is_some()
        );
        drop(a_record);
        drop(b_record);
        // Both sides drain concurrently. Sequentially, whichever went second
        // would be the one left unread — which is the condition this exists to
        // avoid, moved rather than removed.
        tokio::join!(side_a.drain_for(POLL), side_b.drain_for(POLL));
    }
}

/// A knock, an acceptance, and the acceptance collected — the sequence every
/// correspondence starts with, and the state both restarts below begin from.
///
/// The knock reaches the acceptor by derivation alone: it sweeps the doorbell
/// its own slot secret addresses, and the knocker wrote into the slot it derived
/// from the acceptor's public key. Nothing about that slot was exchanged.
async fn first_contact(
    knocker: (&DmDriverHandle, &mut Side),
    acceptor: (&DmDriverHandle, &mut Side),
    knocker_pk: &PkLt,
    acceptor_pk: &PkLt,
) {
    let (handle_a, side_a) = knocker;
    let (handle_b, side_b) = acceptor;

    handle_a
        .send(DmCommand::FirstContact {
            recipient: acceptor_pk.clone(),
            body: KNOCK_BODY.into(),
        })
        .await
        .expect("the first contact queues");
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

    let (request, from, body): (RequestId, PkLt, String) = side_b
        .wait_for("the knock arrives at the doorbell", HOP, |e| match e {
            DmEvent::ContactRequest {
                request,
                from,
                body,
                ..
            } => Some((request.clone(), from.clone(), body.clone())),
            _ => None,
        })
        .await;
    assert_eq!(body, KNOCK_BODY, "the body the knocker sent must arrive");
    assert_eq!(&from, knocker_pk, "the knocker must be named as the sender");

    handle_b
        .send(DmCommand::Accept { request })
        .await
        .expect("the accept queues");
    side_b
        .wait_for("the acceptance is composed", HOP, |e| {
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

    // **Nothing here was sent by a command.** The acceptance was composed by the
    // accept above, published by the acceptor's own cadence and swept by the
    // knocker's, so what is opened is the frame the acceptor sealed, under a key
    // the knocker's ratchet derived. It surfaces as a message at sequence zero
    // with an empty body, which is the acceptance's shape — and until it lands
    // the knocker can verify nothing the acceptor writes.
    let accepted = side_a
        .wait_for("the acceptance is collected", HOP, |e| match e {
            DmEvent::Message { seq: 0, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(
        accepted, "",
        "the acceptance carries no body; a non-empty one is a different frame"
    );
}

/// Both sides restart, each composes a message while it holds no key schedule,
/// and those two waiting messages open the re-establishment that carries them —
/// each at the sequence it reserved, with a further message each way after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "attaches to the public Veilid network and waits out the reconnect band; opt-in, run with --ignored"]
async fn a_re_established_correspondence_carries_a_message_each_way_over_the_real_network() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-restart-resumed-it");
    let _ = std::fs::remove_dir_all(&base);
    let profile_a = tempfile::tempdir().expect("profile A");
    let profile_b = tempfile::tempdir().expect("profile B");

    let a_seed = Mnemonic::generate().expect("A's mnemonic");
    let b_seed = Mnemonic::generate().expect("B's mnemonic");
    let a_keys = identity(&a_seed);
    let b_keys = identity(&b_seed);
    let a_pk: PkLt = Box::new(*a_keys.signing.public_key());
    let b_pk: PkLt = Box::new(*b_keys.signing.public_key());

    // ── the nodes ────────────────────────────────────────────────────────────
    //
    // The nodes stay up across the restart. What restarts is the process that
    // owns the conversation's records, which is where every key under test
    // lives; a node key is not one of them.
    let (node_a, _rx_a) = VeilidNet::start(node_config("a", ":5184", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config("b", ":5185", &base.join("B")))
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
    publish_key_record(&node_a, &a_keys).await;
    publish_key_record(&node_b, &b_keys).await;
    let node_a = Arc::new(node_a);
    let node_b = Arc::new(node_b);

    // Opened before either driver, so the store's own start-up sweep runs while
    // nothing else is writing. These read what the drivers persist; they never
    // drive the conversation.
    let store_a = DmPersist::open(profile_a.path().join("dm"), &AT_REST).expect("A's store");
    let store_b = DmPersist::open(profile_b.path().join("dm"), &AT_REST).expect("B's store");

    // ── the conversation, before any restart ─────────────────────────────────
    let (handle_a, evt_a) = DmDriver::spawn(parts(
        identity(&a_seed),
        Arc::clone(&node_a),
        profile_a.path(),
    ));
    let (handle_b, evt_b) = DmDriver::spawn(parts(
        identity(&b_seed),
        Arc::clone(&node_b),
        profile_b.path(),
    ));
    let mut side_a = Side::new("A", evt_a);
    let mut side_b = Side::new("B", evt_b);

    first_contact(
        (&handle_a, &mut side_a),
        (&handle_b, &mut side_b),
        &a_pk,
        &b_pk,
    )
    .await;

    // The positive control for everything below: this channel carried a message
    // before the restart, so a refusal afterwards is about the restart and not
    // about a conversation that never worked.
    handle_a
        .send(DmCommand::Send {
            to: b_pk.clone(),
            body: A_BODY.into(),
        })
        .await
        .expect("A queues the send");
    let a_to_b = side_b
        .wait_for("B collects A's message", HOP, |e| match e {
            DmEvent::Message { seq: 1, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(a_to_b, A_BODY, "B must recover the exact body A sent");

    let label_a = label_for(&store_a, &b_pk);
    let label_b = label_for(&store_b, &a_pk);
    let root_before_a = resume_of(&store_a, &label_a);
    let root_before_b = resume_of(&store_b, &label_b);
    assert_eq!(
        root_before_a.reconnect_gen(),
        0,
        "A's correspondence has re-established before it restarted"
    );
    assert_eq!(
        root_before_b.reconnect_gen(),
        0,
        "B's correspondence has re-established before it restarted"
    );

    // ── both stores restart ──────────────────────────────────────────────────
    stop(&handle_a, &mut side_a).await;
    stop(&handle_b, &mut side_b).await;
    drop(handle_a);
    drop(handle_b);

    let a_again = identity(&a_seed);
    let b_again = identity(&b_seed);
    // **What this shows is that the derivation repeats, and no more than
    // that.** Both sides of the comparison are computed here from the same
    // mnemonic, so it cannot catch a restarted driver diverging from what the
    // profile holds — a profile keeps no copy of its own identity to check
    // against. The check stays because a derivation that did not repeat
    // would restart as a stranger, and every wait after it would expire with
    // the transport working perfectly. Compared without printing, because the
    // message would otherwise carry two whole public keys.
    assert!(
        a_again.signing.public_key() == a_pk.as_ref(),
        "A's restarted identity is not the one that established the correspondence"
    );
    assert!(
        b_again.signing.public_key() == b_pk.as_ref(),
        "B's restarted identity is not the one that established the correspondence"
    );

    let (handle_a, evt_a) = DmDriver::spawn(parts(a_again, Arc::clone(&node_a), profile_a.path()));
    let (handle_b, evt_b) = DmDriver::spawn(parts(b_again, Arc::clone(&node_b), profile_b.path()));
    let mut sides = [Side::new("A", evt_a), Side::new("B", evt_b)];
    let handles = [&handle_a, &handle_b];
    let stores = [&store_a, &store_b];
    let labels = [&label_a, &label_b];
    // Whom each side addresses, and the two bodies it mints.
    let peers = [&b_pk, &a_pk];
    let waiting_bodies = [A_WAITING_BODY, B_WAITING_BODY];
    let resumed_bodies = [A_RESUMED_BODY, B_RESUMED_BODY];
    eprintln!("both stores restarted");

    // ── each side composes, and the two waiting messages open the exchange ───
    //
    // **This is what causes the re-establishment.** A restart is not an emission
    // event: the survey that decides whether to open an attempt opens one only
    // where the outbox holds a message awaiting a key, and at load there is
    // none. A send on a correspondence that holds a resume record and no key
    // schedule reserves the outbox's next sequence, holds its body in the
    // sending process, reports itself composed at that sequence, and arms the
    // exchange — so the sends come first and the wait follows them.
    let spent_before = [
        next_send_seq(stores[0], labels[0]),
        next_send_seq(stores[1], labels[1]),
    ];
    for i in [0, 1] {
        handles[i]
            .send(DmCommand::Send {
                to: peers[i].clone(),
                body: waiting_bodies[i].into(),
            })
            .await
            .expect("the send queues");
    }

    // A command is answered off the driver's own queue rather than over the
    // network, so both answers are in hand in well under a hop.
    //
    // **The composition is recognised by its sequence, not merely by its
    // state.** Every outbox entry reports its own state changes, so a match on
    // the state alone would take some other entry for the message commanded here
    // and carry its sequence into every assertion below.
    let mut waiting_seq = [0u64; 2];
    for i in [0, 1] {
        let ours = spent_before[i];
        let answered = sides[i]
            .wait_for(
                "the message composed with no key schedule is reported",
                HOP,
                |e| match e {
                    DmEvent::Delivery {
                        state: DeliveryState::Composed,
                        seq,
                        ..
                    } if *seq == ours => Some(Ok(*seq)),
                    DmEvent::Refused { reason, .. } => Some(Err(*reason)),
                    _ => None,
                },
            )
            .await;
        waiting_seq[i] = answered.unwrap_or_else(|reason| {
            panic!(
                "{}: a message composed on a restarted correspondence was refused {reason:?}",
                sides[i].who
            )
        });
    }

    // **One sequence spent, and only the one.** A reservation takes its number
    // at compose and keeps it, so the number that answered the command is the
    // number the frame is eventually sealed at. Read from disk rather than from
    // the event, because the report names a sequence and says nothing about how
    // far the counter moved to give it one.
    for i in [0, 1] {
        assert_eq!(
            next_send_seq(stores[i], labels[i]),
            waiting_seq[i].saturating_add(1),
            "{}: composing the waiting message did not spend exactly its own sequence",
            sides[i].who
        );
    }
    eprintln!("both sides hold a message awaiting a key; waiting out the reconnect band");

    // ── the re-establishment ─────────────────────────────────────────────────
    //
    // Neither side is told to do this. Each defers its first dispatch into the
    // band on its waiting message's own schedule, and the exchange runs on
    // whichever draw came up first. Both records are waited on, because a
    // generation that advanced at one end says only that that end folded
    // something.
    let budget = reestablishment_budget();
    let (after_a, after_b) = {
        let [side_one, side_two] = &mut sides;
        wait_for_reestablishment(
            (side_one, &store_a, &label_a),
            (side_two, &store_b, &label_b),
            budget,
        )
        .await
    };

    // Compared without printing on either side of the comparison: a committed
    // root is the secret a resumed channel's keys descend from, and a failure
    // message is a log line.
    assert!(
        after_a.committed_root().as_bytes() != root_before_a.committed_root().as_bytes(),
        "A's committed root did not move, so nothing was re-rooted"
    );
    assert!(
        after_b.committed_root().as_bytes() != root_before_b.committed_root().as_bytes(),
        "B's committed root did not move, so nothing was re-rooted"
    );
    assert!(
        after_a.committed_root().as_bytes() == after_b.committed_root().as_bytes(),
        "the two sides committed different roots, so they are not on one channel"
    );

    // ── each waiting message is opened at the sequence it reserved ───────────
    //
    // **The budget covers two hops, and the asymmetry is why.** The party that
    // asked for the re-establishment owns the only chain under the re-rooted
    // root, so its waiting message is sealed as the exchange settles. The
    // answering party's sending chain is cut by that first frame, so its own
    // waiting message is sealed a hop later. Which party is which was settled by
    // the two independent dispatch draws hours ago and is not asserted: the
    // budget admits either order, and both messages have to arrive.
    for i in [0, 1] {
        let peer = 1 - i;
        let ours = waiting_seq[i];
        let opened = sides[peer]
            .wait_for(
                "the correspondent opens the waiting message",
                HOP * 2,
                |e| match e {
                    DmEvent::Message { seq, body, .. } if *seq == ours => Some(body.clone()),
                    _ => None,
                },
            )
            .await;
        assert_eq!(
            opened, waiting_bodies[i],
            "{}: the body recovered at sequence {ours} is not the one that was sealed",
            sides[peer].who
        );
    }

    // ── and a further send on each side seals above the exchange's own legs ──
    //
    // The waiting message sat below the positions the legs took, so a chain that
    // simply continued from it would ask the record for a number it already
    // holds. The outbox is the authority on what is spent: the next send takes
    // its next sequence, above every leg this side rode, and the chain steps
    // over the positions in between.
    //
    // **A floor rather than an exact number, because both sides arm.** Each side
    // may open its own attempt before either has answered the other's, so a side
    // that ends up answering can have spent a position on an abandoned
    // initiation as well as on the leg it sent. What holds whatever the draws
    // did is that at least one leg sits between the waiting message and this
    // send. The outbox counter is read rather than the key schedule's because
    // the outbox is what decides where a resumed chain continues: the sealing
    // pass carries the chain over the positions the legs took, so by the time
    // the waiting message has been opened the two counters agree, and the
    // outbox is the one that is authoritative.
    let mut resumed_seq = [0u64; 2];
    for i in [0, 1] {
        resumed_seq[i] = next_send_seq(stores[i], labels[i]);
        assert!(
            resumed_seq[i] >= waiting_seq[i].saturating_add(2),
            "{}: the exchange rode this outbox, so the next send sits above its legs; \
             the waiting message took {} and the next sequence is {}",
            sides[i].who,
            waiting_seq[i],
            resumed_seq[i]
        );
        handles[i]
            .send(DmCommand::Send {
                to: peers[i].clone(),
                body: resumed_bodies[i].into(),
            })
            .await
            .expect("the further send queues");
    }
    for i in [0, 1] {
        let ours = resumed_seq[i];
        let answered = sides[i]
            .wait_for("the further send is composed", HOP, |e| match e {
                DmEvent::Delivery {
                    seq,
                    state: DeliveryState::Composed,
                    ..
                } if *seq == ours => Some(Ok(())),
                DmEvent::Refused { reason, .. } => Some(Err(*reason)),
                _ => None,
            })
            .await;
        answered.unwrap_or_else(|reason| {
            panic!(
                "{}: a send on the resumed channel was refused {reason:?}",
                sides[i].who
            )
        });
        assert_eq!(
            next_send_seq(stores[i], labels[i]),
            ours.saturating_add(1),
            "{}: the further send did not spend exactly its own sequence",
            sides[i].who
        );
    }
    for i in [0, 1] {
        let peer = 1 - i;
        let ours = resumed_seq[i];
        let opened = sides[peer]
            .wait_for(
                "the correspondent opens the further message",
                HOP,
                |e| match e {
                    DmEvent::Message { seq, body, .. } if *seq == ours => Some(body.clone()),
                    _ => None,
                },
            )
            .await;
        assert_eq!(
            opened, resumed_bodies[i],
            "{}: the body recovered at sequence {ours} is not the one that was sealed",
            sides[peer].who
        );
    }

    // ── every outbox settles on the correspondent's acknowledgement ──────────
    //
    // Either path is a pass and both are real: an ordinary frame carries its
    // sender's whole collection state inside its own signature, and a standalone
    // cadence writes the same statement to a record derived from the address
    // root alone. Which arrives first is a race between two live cadences, and
    // the property is that the sender's outbox settles.
    for (i, seq) in [
        (0, waiting_seq[0]),
        (1, waiting_seq[1]),
        (0, resumed_seq[0]),
        (1, resumed_seq[1]),
    ] {
        sides[i]
            .wait_for("the frame is confirmed collected", ACK_HOP, |e| {
                matches!(
                    e,
                    DmEvent::Delivery { seq: s, state: DeliveryState::ConfirmedCollected, .. }
                        if *s == seq
                )
                .then_some(())
            })
            .await;
    }

    // ── exactly once, not merely once ────────────────────────────────────────
    //
    // Both sides drain concurrently, so the window is paid once rather than
    // twice — see [`SETTLE`] for what it has to cover.
    let [side_one, side_two] = &mut sides;
    tokio::join!(side_one.drain_for(SETTLE), side_two.drain_for(SETTLE));

    for i in [0, 1] {
        let peer = 1 - i;
        assert_eq!(
            sides[peer].messages(),
            vec![
                (waiting_seq[i], waiting_bodies[i].to_string()),
                (resumed_seq[i], resumed_bodies[i].to_string()),
            ],
            "{}: the two frames were not shown exactly once each, in order, and alone: {:?}",
            sides[peer].who,
            sides[peer].seen
        );
    }
    for (i, seq) in [
        (0, waiting_seq[0]),
        (1, waiting_seq[1]),
        (0, resumed_seq[0]),
        (1, resumed_seq[1]),
    ] {
        assert_eq!(
            sides[i].delivery_count(seq, DeliveryState::ConfirmedCollected),
            1,
            "{}: sequence {seq} was not reported collected exactly once: {:?}",
            sides[i].who,
            sides[i].seen
        );
    }
    for i in [0, 1] {
        assert_eq!(
            sides[i].refusals(),
            Vec::new(),
            "{}: a send on the resumed channel was refused: {:?}",
            sides[i].who,
            sides[i].seen
        );
    }

    eprintln!(
        "live DM restart oracle: knock -> accept -> message -> both stores restart -> \
         a message composed on each side with no key schedule -> re-establishment on one \
         committed root -> both waiting messages opened at the sequences they reserved and \
         a further message each way, every outbox confirmed collected, in {:.1}s",
        sides[0].at()
    );

    handle_a.send(DmCommand::Shutdown).await.expect("stop A");
    handle_b.send(DmCommand::Shutdown).await.expect("stop B");
}

/// A sender restarts between its knock and the acceptance, and carries on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "attaches to the public Veilid network; opt-in, run with --ignored"]
async fn a_sender_that_restarted_before_its_acceptance_sends_over_the_real_network() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-restart-pending-it");
    let _ = std::fs::remove_dir_all(&base);
    let profile_a = tempfile::tempdir().expect("profile A");
    let profile_b = tempfile::tempdir().expect("profile B");

    let a_seed = Mnemonic::generate().expect("A's mnemonic");
    let b_seed = Mnemonic::generate().expect("B's mnemonic");
    let a_keys = identity(&a_seed);
    let b_keys = identity(&b_seed);
    let a_pk: PkLt = Box::new(*a_keys.signing.public_key());
    let b_pk: PkLt = Box::new(*b_keys.signing.public_key());

    let (node_a, _rx_a) = VeilidNet::start(node_config("a", ":5186", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config("b", ":5187", &base.join("B")))
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
    publish_key_record(&node_a, &a_keys).await;
    publish_key_record(&node_b, &b_keys).await;
    let node_a = Arc::new(node_a);
    let node_b = Arc::new(node_b);

    let (handle_a, evt_a) = DmDriver::spawn(parts(
        identity(&a_seed),
        Arc::clone(&node_a),
        profile_a.path(),
    ));
    let (handle_b, evt_b) = DmDriver::spawn(parts(
        identity(&b_seed),
        Arc::clone(&node_b),
        profile_b.path(),
    ));
    let mut side_a = Side::new("A", evt_a);
    let mut side_b = Side::new("B", evt_b);

    // ── A knocks, and the knock reaches B ────────────────────────────────────
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

    // ── A restarts, with its request unanswered ──────────────────────────────
    //
    // The keypair A's knock published is minted from the random generator and is
    // not derivable from anything else, so the provisional record beside the
    // handshake is the only place it survives this. What A comes back holding
    // decides whether the rest of the conversation is reachable at all.
    stop(&handle_a, &mut side_a).await;
    drop(handle_a);
    let a_again = identity(&a_seed);
    assert_eq!(
        a_again.signing.public_key(),
        a_pk.as_ref(),
        "the restarted identity is not the one that knocked"
    );
    let (handle_a, evt_a) = DmDriver::spawn(parts(a_again, Arc::clone(&node_a), profile_a.path()));
    let mut side_a = Side::new("A", evt_a);
    eprintln!("A restarted with its first-contact request unanswered");

    // ── B accepts, and the restarted A collects the acceptance ───────────────
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
    let accepted = side_a
        .wait_for(
            "the restarted A collects B's acceptance",
            HOP,
            |e| match e {
                DmEvent::Message { seq: 0, body, .. } => Some(body.clone()),
                _ => None,
            },
        )
        .await;
    assert_eq!(
        accepted, "",
        "the acceptance carries no body; a non-empty one is a different frame"
    );

    // ── and sends an ordinary frame B can open ───────────────────────────────
    //
    // **This is the whole claim.** B verifies every channel frame against the
    // pseudonym public key A's knock published, and nothing re-publishes it. A
    // restarted sender signing under a freshly minted keypair would compose,
    // publish and re-seed a frame B discards without a word, and the wait below
    // would expire with the transport working perfectly.
    handle_a
        .send(DmCommand::Send {
            to: b_pk.clone(),
            body: A_BODY.into(),
        })
        .await
        .expect("A queues the send");
    side_a
        .wait_for("the restarted A's message is composed", HOP, |e| {
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
        .wait_for("B collects the restarted A's message", HOP, |e| match e {
            DmEvent::Message { seq: 1, body, .. } => Some(body.clone()),
            _ => None,
        })
        .await;
    assert_eq!(a_to_b, A_BODY, "B must recover the exact body A sent");
    assert_eq!(
        side_a.refusals(),
        Vec::<RefusalReason>::new(),
        "the restarted sender was refused: {:?}",
        side_a.seen
    );

    eprintln!(
        "live DM restart oracle: knock -> A restarts -> accept -> acceptance collected -> \
         a frame signed under the restored keypair opened by B, in {:.1}s",
        side_a.at()
    );

    handle_a.send(DmCommand::Shutdown).await.expect("stop A");
    handle_b.send(DmCommand::Shutdown).await.expect("stop B");
}
