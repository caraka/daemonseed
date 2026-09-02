//! The [`VeilidNet`] actor — a spawned task owning the `VeilidAPI` +
//! `RoutingContext`, driven through a command channel via [`VeilidNetHandle`].
//! Inbound `VeilidUpdate`s are mapped to typed [`VeilidNetEvent`]s on a
//! separate stream the app/UI consumes.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use veilid_core::{
    api_startup, KeyPair, OperationId, PublicKey, RecordKey, RouteBlob, RouteId, RoutingContext,
    Target, VeilidAPI, VeilidConfig, VeilidUpdate,
};

use daemonseed_core::dm::ack_record::DmAckAddress;
use daemonseed_core::dm::paging::{DmPageAddress, PagePosition, Receiving, Sending};
use daemonseed_core::public_room::PublicRoomKey;
use daemonseed_core::share_envelope::ManifestEntry;
use daemonseed_core::share_serve::ChunkSource;
use daemonseed_core::storage::cas::ChunkAddr;

use crate::config::VeilidNetConfig;
use crate::dht_gate::DhtGate;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;
use crate::identity::{OwnerSeed, RendezvousOwner};
use crate::schedule::{
    DispatchFuture, DispatchLane, DispatchOutcome, SchedulerConfig, WriteClass, WriteKind,
    WriteRequest, WriteScheduler, WriteSchedulerHandle, WriteSink,
};
use crate::{discovery, identity, rendezvous, share};

/// RAII guard clearing a record's repair-in-flight marker on Drop (#180 CRSH-ISC-22).
/// Held by the spawned `RepairRendezvous` task; its Drop runs on BOTH normal
/// completion AND panic-unwind, so a panic inside `repair_rendezvous` (or the veilid
/// code it awaits) cannot leave the record stuck in the in-flight set — which would
/// make every future `RepairRendezvous` for that record hit `!set.insert(..)` and be
/// skipped, permanently disabling that record's self-heal until app restart.
struct RepairInFlightGuard {
    set: Arc<Mutex<HashSet<[u8; 32]>>>,
    key: [u8; 32],
}

impl Drop for RepairInFlightGuard {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

/// How a presence current-state write is classified in the WB-3 funnel (WB-1).
/// The write itself is always a last-writer-wins current-state beacon at the
/// member's slot; the boundary decides its priority class and whether it dominates
/// (a leave tombstone), so the funnel protects join/leave with I3 dominance and
/// paces keepalives under the non-chat cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceBoundary {
    /// A periodic keepalive (WB-1.2) — class-4, last-writer-wins current-state.
    Keepalive,
    /// A session-boundary JOIN beacon (WB-1.1) published on subscribe — class-2,
    /// current-state, so it rides the funnel's session-boundary priority.
    Join,
    /// A session-boundary LEAVE tombstone (WB-1.3) published on graceful close —
    /// class-2 and non-coalescible-dominant (I3), so a queued keepalive can never
    /// supersede it and resurrect a departed member.
    Leave,
}

impl PresenceBoundary {
    /// The funnel priority class + coalescing kind for this boundary, given the
    /// member's stable slot `logical_id`.
    fn classify(self, logical_id: String) -> (WriteClass, WriteKind) {
        match self {
            PresenceBoundary::Keepalive => (
                WriteClass::Keepalive,
                WriteKind::CurrentState { logical_id },
            ),
            PresenceBoundary::Join => (
                WriteClass::SessionBoundary,
                WriteKind::CurrentState { logical_id },
            ),
            PresenceBoundary::Leave => (
                WriteClass::SessionBoundary,
                WriteKind::Tombstone { logical_id },
            ),
        }
    }
}

/// Total a frontend waits on a graceful close (#161) — the whole user-visible quit.
/// Value carried over from the gui close path (2s→8s at #121, 8s→12s at the #161 gui
/// half); the work below is carved OUT of it rather than added to it, so a quit never
/// takes longer than it did before.
///
/// The carve-up, which must stay consistent:
/// `CLOSE_PREFLUSH_BUDGET` (6s, withdraws + leaves) + `CLOSE_FLUSH_FLOOR` (2s, the I7
/// flush) = 8s of actor work, leaving 4s for the transport teardown (itself capped at
/// `TEARDOWN_CAP`) and the command/reply hops. A close that spends its whole budget
/// therefore acks at ~11s, inside the 12s the frontend waits — so the frontend's wait
/// stays a backstop against an ack that never comes and cannot pre-empt a close that is
/// still within its budget.
pub const GRACEFUL_CLOSE_BUDGET: Duration = Duration::from_secs(12);

/// What a close arm may spend on its pre-flush steps — share withdraws and LEAVE
/// tombstones — before the I7 flush must get its turn.
///
/// A step cut off here is NOT lost: the write is already enqueued on the scheduler, so
/// abandoning the await hands it to the flush rather than cancelling it. That is what
/// makes a hard bound here safe.
pub const CLOSE_PREFLUSH_BUDGET: Duration = Duration::from_secs(6);

/// The floor the WB-3.I7 flush always gets, however long the pre-flush steps took. It
/// also receives whatever `CLOSE_PREFLUSH_BUDGET` went unspent, so a fast close spends
/// its slack on flushing rather than idling.
pub const CLOSE_FLUSH_FLOOR: Duration = Duration::from_secs(2);

/// The slice of `CLOSE_PREFLUSH_BUDGET` the withdraws may not take, so the LEAVE
/// tombstone always has a budget to run in. Without it step 1 takes the whole remaining
/// preflush on every iteration, so one slow withdraw leaves step 2 running under a zero
/// timeout — which happens to work only because tokio polls the inner future once and the
/// enqueue completes on that poll. That is correctness by luck; this makes it structural.
pub const CLOSE_LEAVE_RESERVE: Duration = Duration::from_secs(2);

/// Cap on veilid's own teardown. `flush_budget` bounds the scheduler flush only;
/// `api.shutdown()` is a separate unbounded await on the same path, so without this the
/// close has no bound at all past the flush. An overrun is abandoned — the process is
/// exiting and the OS reclaims the node either way.
///
/// Public because it is half of the caller's bound, not an actor-private detail:
/// `flush_budget` starts counting when the actor *dequeues* `Command::Shutdown`, and
/// `actor_loop` is serial, so a caller that awaits `shutdown` without a timeout is
/// unbounded no matter what budget it passed. `flush_budget + TEARDOWN_CAP` is the
/// actor's own ceiling once dequeued and is therefore what a caller caps at.
pub const TEARDOWN_CAP: Duration = Duration::from_secs(3);

/// Veilid's `app_message` / `app_call` payload cap (bytes). Sealed envelopes
/// must fit; file-share chunks re-chunk to this in Phase 3.
pub const APP_MESSAGE_CAP: usize = 32768;

/// Bound on the inbound serve queue (#125): a full queue sheds the incoming fetch
/// request on the producer rather than growing without limit under a serve-latency
/// spike. Sized well above a single fetch's fragment fan-out so a normal burst never
/// sheds; a shed request is one fetcher retry.
const SERVE_QUEUE_CAP: usize = 256;

/// Max concurrent `app_call_reply` tasks (#125): caps the network work — and the
/// sealed responses held in memory — in flight at once, applying backpressure to the
/// serve intake when replies are slow. MUST exceed one fetcher's peak concurrent
/// fragment demand (gui `CHUNK_FETCH_CONCURRENCY` 8 × `share::FRAGMENT_FETCH_CONCURRENCY`
/// 8 = 64), or a single legitimate large download self-throttles: fragments beyond the
/// cap wait for a permit, age past the 5s answer window, and the download fails on an
/// otherwise-idle sharer (xhigh review). 128 clears one full download with margin while
/// still bounding a pathological multi-fetcher burst.
const MAX_CONCURRENT_SERVE_REPLIES: usize = 128;

/// One page sweep's full result: the populated slots as checked
/// [`PagePosition`]s, and the health of the sweep that produced them.
///
/// **A position, not a subkey index.** A frame declares its own sequence number,
/// and the slot it was found in implies one; the collector must check that the two
/// agree. Handing back a bare `u32` leaves that comparison to arithmetic at the
/// call site, which is what `PagePosition`'s private fields exist to prevent — so
/// the sweep runs each subkey through `PagePosition::new` against its own page and
/// returns what a collector can use directly.
///
/// The [`rendezvous::SweepOutcome`] is not decoration. Without it an empty `Vec`
/// means both "nobody has written to this page" and "all sixteen GETs errored",
/// and those demand opposite responses — the first is the ordinary state of a page
/// the probe frontier has run ahead to, the second is a record session that needs
/// healing. `rendezvous.rs` names surfacing `failed` separately as the enabling
/// signal for consumer-side session-health tracking (CRSH-ISC-1); a DM page that
/// swallowed it would be the one record family invisible to that tracker.
///
/// **One exception, and it is deliberate.** Failed GETs never cost the outcome: they
/// are counted into `failed` inside the sweep and the partial result comes back
/// `Ok`. A record whose subkey count is not the page slot count is the other way,
/// and fails the whole sweep with no outcome to report. That is the lesser evil, and
/// it is now decided at the FRONT of the sweep rather than at the back: the count is
/// compared before any GET is issued, so the disagreement is loud in **both**
/// directions — a record with more subkeys than a page holds would yield an
/// unplaceable slot, but a record with fewer yields none, and would otherwise come
/// back `Ok` and silently short, which is a lost message dressed as an empty slot.
/// Checking first also means no partial outcome is discarded: at that point there is
/// nothing yet to discard. The residual placement failure
/// (`dm_page_position_of_slot`) is kept behind it as a backstop, reported rather than
/// skipped for the same reason — a skipped slot is a message missing from an `Ok`
/// page. Neither can happen for a record this code created; both are defensive.
///
/// (This deliberately does not name the shape constant: a test counts its textual
/// occurrences to catch a second open site, and prose naming it would read as one.)
/// One page's sweep, tagged with the conversation it came from (#270).
///
/// A named struct rather than a wider tuple, and the reason is the tag. A caller
/// fanning out over several correspondents — a join set, a `FuturesUnordered`,
/// any concurrent dispatch — used to distinguish results only by what it
/// remembered about the order it sent them in. Attributing B's frames to A's
/// ratchet was then an ordinary bookkeeping slip with no type to object: frames
/// are individually authenticated, so nothing is forged and nothing errors, but
/// the ratchet fails to open them and that conversation stops progressing while
/// every layer reports success.
///
/// Adding a third anonymous member to a two-wide tuple destructured at five call
/// sites is how a caller comes to bind the tag to the wrong name, which would be
/// the same class of slip one layer up. Named fields cannot be positionally
/// mismatched.
pub struct DmPageSweep {
    /// Which conversation these frames belong to — the `AR` fingerprint carried
    /// by the address that was swept. A hash, not a capability, and never
    /// serialized.
    pub conversation: [u8; daemonseed_core::dm::firstcontact::AR_FINGERPRINT_LEN],
    /// The populated slots, as `(position, bytes)`.
    pub slots: Vec<(PagePosition, Vec<u8>)>,
    /// Whether the sweep saw the whole page.
    pub outcome: rendezvous::SweepOutcome,
}

impl DmPageSweep {
    /// Build a result tagged with the address that was swept.
    ///
    /// **A function rather than a struct literal at the call site, because the
    /// call site is untestable.** `sweep_dm_page` needs a live DHT, so a tag
    /// written there is a line no runnable test reaches — and a mutation proving
    /// exactly that survived the whole suite: replacing the tag with a constant
    /// left everything green. Taking the address here puts the tagging inside a
    /// function a unit test can call, which is the cheapest way to turn an
    /// untested argument into an oracle.
    fn for_address(
        address: &DmPageAddress<Receiving>,
        slots: Vec<(PagePosition, Vec<u8>)>,
        outcome: rendezvous::SweepOutcome,
    ) -> Self {
        Self {
            conversation: *address.conversation(),
            slots,
            outcome,
        }
    }
}

/// Which dispatch of a doorbell knock this is — the field that decides its funnel
/// class (`docs/design/direct-messaging.md:127-128`).
///
/// An explicit two-variant enum rather than a `bool` or an `Option`: the caller is
/// the only layer that knows which dispatch it is holding, the two map to different
/// priority lanes, and a defaulted or positionally-passed flag is exactly the kind of
/// argument that gets the wrong value silently. There is no `Default` for the same
/// reason `PresenceBoundary` has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorbellDispatch {
    /// The first dispatch of a user's first-contact send — the doorbell write that
    /// rides along with the user action that caused it. `Chat` (rank 1): a user
    /// action wanting user-action latency, and **one write per action, not a burst**
    /// (two at first contact, counting the outbox write) — which is what the 2-permit
    /// chat lane is for.
    FirstSend,
    /// A scheduler-driven re-dispatch — the doorbell keep-alive the outbox re-seeds
    /// on its backoff. `Keepalive` (rank 4), competing in the non-chat window against
    /// presence and advert refreshes, exactly as the key-record keep-alive does.
    Reseed,
}

impl DoorbellDispatch {
    /// The funnel priority class for this dispatch.
    ///
    /// Only the class varies. The coalescing *kind* is `CurrentState` on the slot for
    /// both, because `:128` fixes the logical id as the message (the slot) so that a
    /// superseded re-seed of one knock coalesces while distinct knocks never do — and
    /// that rule is indifferent to which dispatch produced the write.
    pub fn classify(self) -> WriteClass {
        match self {
            DoorbellDispatch::FirstSend => WriteClass::Chat,
            DoorbellDispatch::Reseed => WriteClass::Keepalive,
        }
    }
}

/// One doorbell sweep's result: the populated slots, and whether the sweep saw
/// the whole record.
///
/// Modelled on [`DmPageSweep`] and deliberately WITHOUT its conversation tag.
/// A page sweep names one correspondence, so a caller fanning several of them out
/// concurrently needs the result to say which it belongs to. A doorbell is the
/// opposite shape of problem: there is exactly one per identity, a caller sweeps
/// its own and no other, and every populated slot is a knock from a DIFFERENT and
/// as-yet-unknown sender. There is nothing to tag the result with that this layer
/// could compute — the slot is derived from a secret only the sender holds, which
/// is what sender-blindness means — and nothing the caller does not already know.
pub struct DoorbellSweep {
    /// The populated slots, as `(slot, bytes)`.
    ///
    /// The bytes are UNVERIFIED and still sealed. Only
    /// `daemonseed_core::dm::firstcontact::open` may decide an entry is genuine,
    /// and it needs the recipient's ML-KEM decapsulation key, which this layer
    /// does not hold. The doorbell is world-writable, so garbage in a slot is an
    /// ordinary input rather than an error condition.
    ///
    /// The slot travels back with the bytes because a recipient that accepts a
    /// knock has to be able to name the slot it came from — a later retry from the
    /// same sender lands in that same slot and overwrites it, and a block drops it
    /// there.
    pub slots: Vec<(u16, Vec<u8>)>,
    /// Whether the sweep saw the whole record.
    ///
    /// Required, not decoration, for the reason [`DmPageSweep::outcome`] is: an
    /// empty slot list alone means both "nobody has knocked" and "all 32 GETs
    /// errored", and those demand opposite responses.
    pub outcome: rendezvous::SweepOutcome,
}

/// Commands the [`VeilidNetHandle`] sends to the actor task. Each carries a
/// `oneshot` reply so the caller awaits the result.
enum Command {
    Attach {
        timeout_secs: u64,
        reply: oneshot::Sender<Result<()>>,
    },
    NewInboundRoute {
        reply: oneshot::Sender<Result<RouteBlob>>,
    },
    ImportRoute {
        blob: Vec<u8>,
        reply: oneshot::Sender<Result<RouteId>>,
    },
    SendSealed {
        route: RouteId,
        sealed: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    // One generic command pair drives every shared-owner rendezvous — circles
    // (Phase 2) and the lobby / public rooms + share discovery (Phase 3/4). The
    // ONLY difference is which `owner_seed` the caller derives; the engine treats
    // the payload as opaque sealed bytes regardless of feature.
    PublishRendezvous {
        owner_seed: [u8; 32],
        sealed: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    SubscribeRendezvous {
        owner: RendezvousOwner,
        /// `true` when a record was opened and watched, `false` on the read-only arm
        /// when the record does not exist yet — see [`subscribe_rendezvous`].
        reply: oneshot::Sender<Result<bool>>,
    },
    /// Write a SEALED payload to a stable-identity slot on a rendezvous record —
    /// the current-state (last-writer-wins) counterpart to [`Command::PublishRendezvous`]'s
    /// append-ring write. Presence beacons use it: one fixed slot per member
    /// (keyed by `stable_id` via `rendezvous::current_state_subkey`), so a
    /// re-beacon overwrites in place instead of filling the ring (P1). `owner_seed`
    /// is the presence sibling record's owner seed; the engine treats `sealed` as
    /// opaque.
    PublishCurrentState {
        owner_seed: [u8; 32],
        stable_id: String,
        sealed: Vec<u8>,
        /// WB-1 presence classification (Keepalive / Join / Leave). The operator
        /// MOTD path uses [`PresenceBoundary::Keepalive`] (a class-4 current-state
        /// write, its previous behaviour).
        boundary: PresenceBoundary,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Re-run the one-shot backlog sweep on an already-subscribed rendezvous
    /// record WITHOUT registering another watch — the recovery primitive for an
    /// item published during the post-(re)connect watch-warmup window (#132/#133).
    ResweepRendezvous {
        owner: RendezvousOwner,
        reply: oneshot::Sender<Result<()>>,
    },
    /// **Repair** a dead rendezvous record session (consumer-route self-heal §RS-1.2,
    /// step 3b). Re-establishes the record — invalidate the open-cache entry, (optionally
    /// close), re-open, re-watch, full 0..64 re-sweep — **holding the record's
    /// `record_lock` across the whole sequence** (CRSH-ISC-3/18), so a concurrent
    /// same-record write can never target a torn-down handle. `owner` is the same
    /// rendezvous owner as [`Command::SubscribeRendezvous`] /
    /// [`Command::ResweepRendezvous`]. Re-swept backlog arrives as
    /// [`VeilidNetEvent::Inbound`]; the frontend dispatches this only for a repair-due
    /// record and resets its session-health tracker at dispatch.
    RepairRendezvous {
        owner: RendezvousOwner,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Resolve a rendezvous record's deterministic [`RecordKey`] from its `owner` —
    /// local crypto only, no network round-trip. Feeds the frontend's map from
    /// `RecordKey` to the record's owner (§RS-1.2) so a repair-due signal (which the
    /// tracker keys by `RecordKey`) can be dispatched as a
    /// [`Command::RepairRendezvous`] on that owner.
    RendezvousKey {
        owner: RendezvousOwner,
        reply: oneshot::Sender<Result<RecordKey>>,
    },
    // ── Direct messaging (#232) ──
    /// Publish this identity's DM key record — its static ML-KEM-1024 encapsulation
    /// key — to subkey 0 of the `dflt(1)` record at `owner_seed`
    /// (`daemonseed_core::dm::keyrec::derive_owner_seed`). `record` is the already
    /// signed, prost-encoded `DmKeyRecord`; this layer moves opaque bytes and never
    /// inspects them. Rides the WB-3 funnel as a coalescible `Keepalive`
    /// current-state write: the publish is presence-independent, and a re-seed
    /// against eviction supersedes any queued earlier one for the same record.
    PublishDmKeyRecord {
        owner_seed: [u8; 32],
        record: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Fetch a correspondent's DM key record from subkey 0 of the `dflt(1)` record
    /// at `owner_seed`. `Ok(None)` means the slot is empty — evicted, wiped, or
    /// never published — which the caller surfaces as *awaiting-key* and retries;
    /// it is deliberately distinct from a transport error. The bytes are returned
    /// unverified: `daemonseed_core::dm::keyrec::verify` is the only thing that may
    /// decide a record is genuine, and it needs the identity pubkey this layer does
    /// not hold.
    FetchDmKeyRecord {
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    // ── Direct messaging (#234) ──
    /// Publish one channel frame into `at`'s slot of the `dflt(16)` page record
    /// `address` names. `frame` is the already-sealed, already-signed channel frame;
    /// this layer moves opaque bytes and never inspects them.
    ///
    /// Rides the WB-3 funnel as a **`Chat`-class, `Ring`-kind** write. A DM is chat,
    /// so it draws the chat lane and never queues behind a keepalive; and the page
    /// slot is *intended* to be written exactly once, so the write must never be
    /// coalesced — which is what `Ring` means to the scheduler, whatever its name
    /// suggests about append-rings. Dispatch is its own [`ProdWrite`] variant, so no
    /// ring-sequence cursor is touched.
    ///
    /// **Write-once is a caller obligation, not an enforced property.** This is an
    /// unconditional last-writer-wins `set_dht_value` with no read-before-write: a
    /// caller that reissues a sequence number overwrites the peer's copy of an
    /// already-delivered message and gets `Ok(())`. Re-deriving a ratchet from
    /// generation zero after a restart is exactly how that happens (#243), which is
    /// part of why #243 is alpha-blocking.
    ///
    /// The address is the typed [`DmPageAddress`], not a seed beside a slot, and
    /// this is the one command in this enum where the distinction matters. Every
    /// other `owner_seed` here is world-derivable by design; a page's derives from
    /// the conversation secret, and under Veilid a derivable owner seed IS write
    /// access to the conversation. `[u8; 32]` is `Copy`, so a bare array would be
    /// duplicated into the command channel, the actor stack, the scheduler's pending
    /// queue and the dispatch frame, none of which zeroize (#244). The address
    /// carries one boxed, redacted, zeroize-on-drop seed the whole way, and it
    /// carries its page and its stream with it, so the seed cannot come apart from
    /// the page whose slots `at` indexes (#254).
    ///
    /// The position is **not** a field: the address carries it (#269). Keeping a
    /// second copy beside the address is the very thing that could disagree with
    /// it, which is what this change removed at the public surface — carrying one
    /// across an internal seam would put it straight back. Dispatch reads the
    /// subkey through `address.at()`, so no layer is ever handed a naked subkey
    /// either.
    PublishDmPage {
        address: DmPageAddress<Sending>,
        frame: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Sweep every slot of one channel page, returning a [`DmPageSweep`] — the
    /// populated `(position, bytes)` pairs, the outcome, and the conversation the
    /// swept address named (#270).
    ///
    /// The position travels back with the bytes because the collector must check the
    /// frame's declared sequence number against where it was found; it is built
    /// through `PagePosition::new` against the address's own page at the sweep
    /// boundary. An empty result is the ordinary state of a page nobody has written
    /// to yet, distinct from a transport error.
    ///
    /// Carries the typed [`DmPageAddress`] for the reason
    /// [`Command::PublishDmPage`] gives — and typed to `Receiving`, so a sweep of
    /// our OWN stream (a valid address for the wrong record, which would read our
    /// own writes back forever) does not compile.
    SweepDmPage {
        address: DmPageAddress<Receiving>,
        reply: oneshot::Sender<Result<DmPageSweep>>,
    },
    // ── Direct messaging (#233) ──
    /// Write one first-contact entry into `slot` of the `dflt(32)` doorbell record
    /// at `owner_seed` (`daemonseed_core::dm::doorbell::derive_owner_seed` over the
    /// RECIPIENT's ML-DSA-87 public key). `entry` is the already-sealed,
    /// already-signed first-contact entry; this layer moves opaque bytes and never
    /// inspects them.
    ///
    /// **The one record a party writes that it does not own, and the only
    /// unauthenticated write surface in DM.** Nothing new is needed to express
    /// that: a world-derivable address implies a world-derivable owner under
    /// Veilid's DFLT schema, so the sender derives the *recipient's* owner keypair
    /// from the recipient's public identity key and signs the write with it,
    /// exactly as [`Command::PublishDmKeyRecord`] does for a key record. The
    /// difference is whose record it is, and that difference is a fact about the
    /// design, not about the mechanism — see [`publish_doorbell_entry`].
    ///
    /// `slot` comes from `doorbell::slot_for`, which is keyed on a secret only the
    /// sender holds, so this layer cannot check it against anything: it can only
    /// check that the record can hold it. Both that and the entry's size are
    /// refused at [`VeilidNetHandle::publish_doorbell_entry`], before this command
    /// is built.
    ///
    /// Rides the WB-3 funnel as a `CurrentState`-kind write coalescing on the SLOT,
    /// at the class [`DoorbellDispatch::classify`] gives — see
    /// [`doorbell_entry_write_request`] for why each of those is what it is.
    PublishDoorbellEntry {
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Sweep all `DOORBELL_SLOTS` slots of OUR OWN doorbell, returning a
    /// [`DoorbellSweep`] — the populated `(slot, bytes)` pairs and the outcome.
    ///
    /// `owner_seed` is derived from OUR public identity key, which is what makes
    /// this a sweep of our own doorbell rather than someone else's. There is no
    /// type-level direction to lean on the way [`Command::SweepDmPage`] has one:
    /// a doorbell owner seed is a plain world-derivable `[u8; 32]`, and sweeping
    /// another identity's doorbell is a perfectly well-formed operation that
    /// simply returns entries nothing local can open. The check that it is ours
    /// lives with the caller, which is the layer that holds the decapsulation key.
    ///
    /// An empty result is the ordinary state of a doorbell nobody has knocked on,
    /// and is distinct from a transport error.
    SweepDoorbell {
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<DoorbellSweep>>,
    },
    // ── Direct messaging (#235) ──
    /// Publish one direction's acknowledgement record to subkey 0 of the `dflt(1)`
    /// record `address` names
    /// (`daemonseed_core::dm::ack_record::DmAckAddress::for_direction` over the
    /// conversation's address root and the direction). `record` is the
    /// already-sealed, already-signed acknowledgement; this layer moves opaque
    /// bytes and never inspects them.
    ///
    /// Rides the WB-3 funnel as a coalescible `Keepalive` **current-state** write,
    /// exactly as [`Command::PublishDmKeyRecord`] does and for the same reason: an
    /// acknowledgement is current state rewritten in place, so a newer one always
    /// supersedes a queued older one for the same record. That is not merely
    /// permitted here, it is the point — the statement is monotonic, so coalescing
    /// can only ever drop a write whose content the surviving one already
    /// contains. The logical id is a constant, because one address names exactly
    /// one acknowledgement record.
    ///
    /// **The address is the typed [`DmAckAddress`], not a bare owner seed, for the
    /// reason [`Command::PublishDmPage`] gives (#244).** Every `owner_seed: [u8;
    /// 32]` elsewhere in this enum is world-derivable by design; an
    /// acknowledgement record's derives from the conversation's retained address
    /// root `AR`, and under Veilid a derivable owner seed IS write access to that
    /// record. A `Copy` array would be duplicated into the command channel, the
    /// actor stack, the scheduler's pending queue and the dispatch frame, none of
    /// which zeroize; the address carries one boxed, redacted, zeroize-on-drop
    /// seed the whole way, and it carries the direction it was derived for beside
    /// it, so the seed cannot come apart from the half of the conversation it
    /// addresses.
    PublishDmAck {
        address: DmAckAddress,
        record: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Fetch a correspondent's acknowledgement record from subkey 0 of the
    /// `dflt(1)` record `address` names. `Ok(None)` means the slot is empty —
    /// evicted, or never written because the peer has settled nothing — which the
    /// caller treats as "no acknowledgement yet" and retries; it is deliberately
    /// distinct from a transport error, because a fail-safe delivery state must
    /// never read a network fault as an absence of confirmation.
    ///
    /// **The address is the typed [`DmAckAddress`] on the read side too**, for the
    /// reason [`Self::PublishDmAck`] gives: an acknowledgement record's owner seed
    /// derives from `AR` whichever direction it is read or written in, so it is the
    /// same conversation secret and gets the same zeroizing carrier. The plain type
    /// covers both directions — unlike `DmPageAddress<D>`, there is nothing here a
    /// stream marker would prevent, because both parties write their own record and
    /// read the other's.
    ///
    /// The bytes are returned UNVERIFIED, and unverified here means more than it
    /// does for a key record: `daemonseed_core::dm::ack_record::decode_and_verify`
    /// is the only thing that may open and authenticate them, and even its result
    /// is a `PeerAck` that answers no question until it has been merged under the
    /// caller's own ceiling.
    FetchDmAck {
        address: DmAckAddress,
        reply: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    // ── Public-share content (Phase 3) ──
    /// Register a share to serve owner-on-demand (`share_id` → content source
    /// + the `PublicRoomKey` bytes responses seal under).
    ServeShare {
        share_id: String,
        content: Arc<dyn ChunkSource + Send + Sync>,
        room_key: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
    },
    /// Make one outbound `app_call` over a peer's private route (the fetch
    /// side's per-fragment round-trip). Spawned so a long fetch never blocks the
    /// actor loop.
    AppCall {
        route: RouteId,
        request: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    /// Announce a public share to the lobby with an anti-swap SIGNED route advert
    /// (D-3.5). The actor allocates a private inbound route, asks `signer` to sign
    /// `share_id ‖ route_blob`, wraps it with the sealed announcement into a
    /// `DiscoveryEnvelope`, and publishes it on the lobby rendezvous. When `persist`
    /// is true it remembers the advert so a `RouteChanged` can re-allocate, re-sign,
    /// and re-publish. When `persist` is false (a withdraw) the advert is written
    /// ONCE and NOT remembered: a RouteChanged/watchdog never re-publishes it, so a
    /// withdraw cannot re-linger and re-race a later reshare on the same
    /// (#156-deterministic) id (#163); its transient route is released once the
    /// single write completes.
    PublishShare {
        owner_seed: [u8; 32],
        share_id: String,
        sealed_announcement: Vec<u8>,
        signer: Arc<dyn discovery::RouteAdvertSigner>,
        /// Remember the advert for `RouteChanged`/watchdog re-publish (a live share)
        /// vs. a one-shot withdraw that must never re-linger (#163).
        persist: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Stop serving a share and drop its advert (the teeth of unpublish): removes
    /// it from the serve registry so inbound fetch `app_call`s for it are no longer
    /// answered, and from the advert set so a `RouteChanged` never re-publishes it.
    StopServe {
        share_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// A private route died/rotated (from the update pump). Carries veilid's dead
    /// allocated-route list so the actor refreshes ONLY when a route it currently
    /// advertises died — veilid reports routes we ourselves released (each advert
    /// re-publish releases its previous route) in the same update, and reacting to
    /// those re-armed an endless refresh→release→RouteChange→refresh storm.
    /// Coalesced against bursts; fire-and-forget.
    RouteMaintenance { dead_routes: Vec<RouteId> },
    /// Release a private route this node imported for a discovered share (the
    /// consumer-side counterpart to the sharer's advert-route release — §RS-3,
    /// CRSH-ISC-10). Fire-and-forget: the actor releases through `release_tolerant`,
    /// so an id veilid already evicted is a benign no-op, no reply is awaited.
    ReleaseRoute { route_id: RouteId },
    /// Periodic slow-cadence advert refresh (the #124 watchdog). Unlike
    /// [`Command::RouteMaintenance`], which fires only on an OBSERVED route death,
    /// this fires on a timer and refreshes every advert unconditionally — the sole
    /// recovery path for a route that died SILENTLY (veilid never surfaced it in a
    /// `RouteChange.dead_routes`). Bounded by a minutes-scale interval well above the
    /// coalesce window so it cannot recreate the refresh storm. Fire-and-forget.
    AdvertWatchdog,
    Shutdown {
        /// Budget for the WB-3.I7 scheduler flush before the node is torn down.
        flush_budget: Duration,
        reply: oneshot::Sender<()>,
    },
}

/// A cloneable handle to the running actor. Every transport operation goes
/// through here; the actor task serializes access to the single `VeilidAPI`.
/// This is the shape the app/UI drives (the `AppSession` replacement).
#[derive(Clone)]
pub struct VeilidNetHandle {
    cmd_tx: mpsc::Sender<Command>,
    /// The scheduler's most-recent non-chat enqueue-to-ack latency in millis — the
    /// WB-1.10 / WB-ISC-5 congestion signal, read by the presence reaper to suspend
    /// reaping while the local write funnel is backed up. `0` until the first
    /// non-chat write completes.
    write_latency: Arc<AtomicU64>,
}

impl VeilidNetHandle {
    /// Send a command and await its `oneshot` reply, surfacing a clean error if
    /// the actor task is gone.
    async fn send<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(make(tx))
            .await
            .map_err(|_| VeilidNetError::Actor("actor task is gone".into()))?;
        rx.await
            .map_err(|_| VeilidNetError::Actor("actor dropped the reply".into()))
    }

    /// Attach and wait until the node is public-internet-ready (D4).
    pub async fn attach_and_wait(&self, timeout_secs: u64) -> Result<()> {
        self.send(|reply| Command::Attach {
            timeout_secs,
            reply,
        })
        .await?
    }

    /// Allocate a private inbound route. The returned blob is what a peer
    /// addresses — it never exposes our node id or IP (anti-dox receiver side).
    pub async fn new_inbound_route(&self) -> Result<RouteBlob> {
        self.send(|reply| Command::NewInboundRoute { reply })
            .await?
    }

    /// Import a peer's private-route blob, returning the route id to send to.
    pub async fn import_route(&self, blob: Vec<u8>) -> Result<RouteId> {
        self.send(|reply| Command::ImportRoute { blob, reply })
            .await?
    }

    /// Release a private route previously imported via [`Self::import_route`] (§RS-3,
    /// CRSH-ISC-10). Fire-and-forget — the actor releases tolerantly, treating an
    /// already-evicted route as a benign no-op (design Evidence 3), so no reply is
    /// awaited. A closed command channel just means the actor is gone.
    pub async fn release_route(&self, route_id: RouteId) {
        let _ = self.cmd_tx.send(Command::ReleaseRoute { route_id }).await;
    }

    /// Send a SEALED message over a private route (the proven 1:1 path).
    /// `sealed` is daemonseed's opaque AES-256-GCM envelope; this layer never
    /// holds the plaintext or the content key.
    pub async fn send_sealed(&self, route: RouteId, sealed: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::SendSealed {
            route,
            sealed,
            reply,
        })
        .await?
    }

    /// Shut the node down cleanly: run the WB-3.I7 scheduler flush within
    /// `flush_budget`, then tear the transport down. `flush_budget` is the caller's
    /// REMAINING graceful-close budget (see [`GRACEFUL_CLOSE_BUDGET`]) — a caller that
    /// has already spent part of its close on withdraws and leaves passes what is left,
    /// so the whole close stays inside one bound. Terminal: the actor task returns, so
    /// every later command on this handle fails.
    pub async fn shutdown(&self, flush_budget: Duration) {
        let _ = self
            .send(|reply| Command::Shutdown {
                flush_budget,
                reply,
            })
            .await;
    }

    /// The scheduler's most-recent non-chat enqueue-to-ack latency in millis (WB-1.10
    /// congestion signal). The presence reaper compares it against
    /// `daemonseed_core::presence::REAP_CONGESTION_THRESHOLD` and suspends reaping
    /// while elevated (WB-ISC-5). A synchronous relaxed read — no command round-trip
    /// — so the reap timer can consult it cheaply. `0` before the first non-chat
    /// write completes (treated as calm).
    pub fn last_write_latency_ms(&self) -> u64 {
        self.write_latency.load(Ordering::Relaxed)
    }

    // ── Circles (Phase 2): shared-owner DFLT rendezvous + append-ring fan-out ──

    /// Publish a SEALED message to a circle (Phase 2). `owner_seed` is the
    /// circle's deterministic Veilid rendezvous-owner seed
    /// (`daemonseed_core::circle::key::derive_circle_veilid_owner_seed`); the
    /// actor opens/creates the shared-owner DFLT record at the derived
    /// rendezvous address and writes `sealed` into this member's append-ring.
    /// `sealed` is the opaque circle envelope — this layer never holds the key
    /// or plaintext.
    pub async fn publish_circle(&self, owner_seed: [u8; 32], sealed: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::PublishRendezvous {
            owner_seed,
            sealed,
            reply,
        })
        .await?
    }

    /// Subscribe to a circle (Phase 2): open the same rendezvous record, watch
    /// it for member writes, and sweep it once for the bounded login backlog.
    /// Inbound circle messages arrive as [`VeilidNetEvent::Inbound`] on the
    /// event stream (eventual — watch latency is tens of seconds). `owner_seed`
    /// is the circle's rendezvous-owner seed, as for [`Self::publish_circle`].
    ///
    /// The seed alone, not a [`RendezvousOwner`]: every member of a circle derives
    /// the owner seed because every member writes, so there is no reader-only way
    /// to hold a circle.
    pub async fn subscribe_circle(&self, owner_seed: OwnerSeed) -> Result<()> {
        // A held owner opens-or-creates, so the record is always open on success and
        // the "was a record opened?" answer carries no information here.
        self.send(|reply| Command::SubscribeRendezvous {
            owner: RendezvousOwner::Held(owner_seed),
            reply,
        })
        .await?
        .map(|_opened| ())
    }

    // ── Lobby / public rooms + share discovery (Phase 3/4) ──────────────────
    // The SAME shared-owner DFLT rendezvous engine as a circle — only the owner
    // derivation differs. `owner_seed` is the public-room rendezvous-owner seed
    // (`daemonseed_core::public_room::derive_room_veilid_owner_seed`), which is
    // WORLD-derivable, so the room is an open rendezvous. A public-share
    // announcement is just a `ShareAnnouncement` sealed under the room's
    // `PublicRoomKey` and published here — discovery rides the lobby record.

    /// Publish a SEALED payload to a public room / lobby (Phase 3/4). Mechanics
    /// are identical to [`Self::publish_circle`]; the difference is only that
    /// `owner_seed` is a public-room rendezvous-owner seed and `sealed` is sealed
    /// under the room's `PublicRoomKey` (a room message, or a `ShareAnnouncement`
    /// for share discovery). This layer never holds the key or plaintext.
    pub async fn publish_room(&self, owner_seed: [u8; 32], sealed: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::PublishRendezvous {
            owner_seed,
            sealed,
            reply,
        })
        .await?
    }

    /// Subscribe to a public room / lobby (Phase 3/4): open the room's
    /// rendezvous record, watch it, and sweep it for the bounded backlog —
    /// identical to [`Self::subscribe_circle`] but for a public-room owner.
    /// Inbound sealed room messages / share announcements arrive as
    /// [`VeilidNetEvent::Inbound`]; the app opens them under the `PublicRoomKey`.
    ///
    /// A [`RendezvousOwner`] rather than a bare seed because this method also
    /// carries the project-announce/MOTD record, which one instance writes and
    /// every other reads.
    ///
    /// A [`RendezvousOwner::PublicOnly`] owner opens the record read-only — no
    /// create, no writer — and a record that is absent is a clean `Ok` with no watch
    /// registered. Call this again (the frontend already does, on every refresh) to
    /// pick the record up once it exists.
    ///
    /// Returns whether a record was actually opened and watched: `true` on success,
    /// `false` on that read-only absent path. A caller that remembers "this record is
    /// subscribed" must remember it only on `true`, or one absent first pass costs it
    /// push updates for as long as it holds that memory. A [`RendezvousOwner::Held`]
    /// owner opens-or-creates, so it answers `true` whenever it answers `Ok`.
    pub async fn subscribe_room(&self, owner: RendezvousOwner) -> Result<bool> {
        self.send(|reply| Command::SubscribeRendezvous { owner, reply })
            .await?
    }

    /// Re-sweep an already-subscribed rendezvous record for backlog missed during
    /// the watch-warmup window, WITHOUT registering another watch — the recovery
    /// primitive for #132/#133. `owner` is the record's rendezvous owner (the same
    /// one passed to [`Self::subscribe_circle`] / [`Self::subscribe_room`]).
    /// Re-swept items arrive as [`VeilidNetEvent::Inbound`] and are deduped
    /// downstream.
    ///
    /// A [`RendezvousOwner::PublicOnly`] owner opens the record read-only; an absent
    /// record is a clean `Ok` with nothing swept.
    pub async fn resweep_rendezvous(&self, owner: RendezvousOwner) -> Result<()> {
        self.send(|reply| Command::ResweepRendezvous { owner, reply })
            .await?
    }

    /// Repair a dead rendezvous record session (consumer-route self-heal §RS-1.2, step
    /// 3b): re-establish the record under its `record_lock` — invalidate the open-cache
    /// entry, (optionally) close, re-open, re-watch, and full 0..64 re-sweep (CRSH-ISC-3).
    /// `owner` is the record's rendezvous owner (the same one passed to
    /// [`Self::subscribe_room`] / [`Self::resweep_rendezvous`]). The frontend dispatches
    /// this ONLY for a repair-due record, one at a time (serialized with the steady
    /// resweep). Re-swept backlog arrives as [`VeilidNetEvent::Inbound`].
    ///
    /// A [`RendezvousOwner::PublicOnly`] owner re-opens the record read-only. Unlike
    /// the two methods above, a record that cannot be found is an error here: a
    /// repair re-establishes a session that was working, so its absence is a failure
    /// to report rather than a state to wait out.
    pub async fn repair_rendezvous(&self, owner: RendezvousOwner) -> Result<()> {
        self.send(|reply| Command::RepairRendezvous { owner, reply })
            .await?
    }

    /// Resolve a rendezvous record's deterministic [`RecordKey`] from its `owner` —
    /// local crypto only (no network round-trip). The frontend feeds this into its map
    /// from `RecordKey` to the record's owner, so a repair-due signal (keyed by
    /// `RecordKey`) resolves to the owner [`Self::repair_rendezvous`] needs (§RS-1.2).
    ///
    /// Both owner variants resolve to the same [`RecordKey`] for one record: the
    /// address is a function of the owner's public half alone, which a seed and a
    /// public key reach by the same derivation.
    pub async fn rendezvous_record_key(&self, owner: RendezvousOwner) -> Result<RecordKey> {
        self.send(|reply| Command::RendezvousKey { owner, reply })
            .await?
    }

    // ── Direct messaging (#232) ──

    /// Publish this identity's signed DM key record (ISC-C40). `record` is the
    /// prost-encoded `DmKeyRecord`; the caller signs it with
    /// `daemonseed_core::dm::keyrec::build` and derives `owner_seed` with
    /// `derive_owner_seed`. Enqueued as a coalescible `Keepalive` write, so
    /// re-seeding on the slow anti-eviction schedule costs at most one queued
    /// write per record no matter how often it is called.
    pub async fn publish_dm_key_record(&self, owner_seed: [u8; 32], record: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::PublishDmKeyRecord {
            owner_seed,
            record,
            reply,
        })
        .await?
    }

    /// Fetch a correspondent's DM key record. `Ok(None)` is an empty slot —
    /// evicted, wiped by anyone (the record is world-writable), or never
    /// published — and is the caller's *awaiting-key* state, distinct from a
    /// transport failure. The bytes are UNVERIFIED; pass them to
    /// `daemonseed_core::dm::keyrec::verify` with the identity pubkey the address
    /// was derived from before trusting anything in them.
    pub async fn fetch_dm_key_record(&self, owner_seed: [u8; 32]) -> Result<Option<Vec<u8>>> {
        self.send(|reply| Command::FetchDmKeyRecord { owner_seed, reply })
            .await?
    }

    // ── Direct messaging (#234) ──

    /// Publish one sealed channel frame into the slot `address` names — the
    /// transport half of ISC-C42, which also needs collection (#236) before it can
    /// close.
    ///
    /// Build `address` with
    /// `DmPageAddress::sending(&address_root, &ratchet, paging::position_of(seq))`.
    /// The page and the slot then come from one sequence number **by
    /// construction** (#269): the address is a placed slot, so there is no second
    /// position to supply and nothing for this call to compare. A page derived for
    /// sequence *a* paired with a slot belonging to sequence *b* used to be a
    /// runtime refusal; it is now a pair that cannot be built.
    ///
    /// The *direction* needs no check: `address` is typed `DmPageAddress<Sending>`,
    /// so an address for the stream we receive on will not compile.
    ///
    /// Enqueued as a non-coalescible chat-lane write: every call reaches the
    /// network, because every slot holds a different message.
    ///
    /// **Takes the address BY VALUE, and the alternative is not available.** A
    /// page's owner seed is the conversation's write capability (#244), so it
    /// travels as a boxed, redacted, zeroize-on-drop secret rather than a `Copy`
    /// array — and that value must be *moved* into the command that crosses the
    /// channel. It is deliberately neither `Clone` nor constructible from bytes
    /// outside `daemonseed_core::dm::paging`, so a `&DmPageAddress` parameter could
    /// only be honoured by copying the secret into a fresh non-zeroizing buffer,
    /// which is precisely the copy this signature exists to remove. The address
    /// therefore inherits the seed's move discipline wholesale: derive one per call;
    /// derivation is pure.
    pub async fn publish_dm_page(
        &self,
        address: DmPageAddress<Sending>,
        frame: Vec<u8>,
    ) -> Result<()> {
        // No position argument and nothing to check: a sending address carries
        // the slot it writes (#269), so the pair cannot disagree. The comparison
        // that used to stand here, and the error it raised, are gone because the
        // state they guarded is no longer constructible.
        self.send(|reply| Command::PublishDmPage {
            address,
            frame,
            reply,
        })
        .await?
    }

    /// Sweep one channel page, returning `(position, bytes)` per populated slot.
    ///
    /// An empty `Vec` is the ordinary state of an unwritten page — the probe
    /// frontier is meant to run ahead of what exists — and is deliberately distinct
    /// from `Err`, a transport failure. The bytes are UNVERIFIED: only
    /// `daemonseed_core::dm::frame::parse` followed by the ratchet's own checks may
    /// decide a frame is genuine, and the collector must confirm the frame's
    /// declared sequence number agrees with the position it came back in.
    ///
    /// `address` is typed `DmPageAddress<Receiving>`, so sweeping the stream we
    /// *send* on will not compile. That address would be perfectly valid — both
    /// parties derive both streams — and the sweep would read our own writes back
    /// forever while the correspondent's messages sat untouched, with no error on
    /// any surface.
    ///
    /// Takes the address by value for the same reason [`Self::publish_dm_page`]
    /// does: the seed inside must be moved into the command, and cannot be cloned or
    /// rebuilt from borrowed bytes without reintroducing the copy (#244).
    pub async fn sweep_dm_page(&self, address: DmPageAddress<Receiving>) -> Result<DmPageSweep> {
        self.send(|reply| Command::SweepDmPage { address, reply })
            .await?
    }

    // ── Direct messaging (#233) ──

    /// Knock on a recipient's doorbell: write one sealed first-contact entry into
    /// one slot of the recipient's `dflt(32)` doorbell record (ISC-C41).
    ///
    /// Derive `owner_seed` with `daemonseed_core::dm::doorbell::derive_owner_seed`
    /// over the RECIPIENT's ML-DSA-87 public key, and `slot` with
    /// `doorbell::slot_for` over this sender's own doorbell slot secret and that
    /// same recipient key. Both are pure; derive them per call.
    ///
    /// **This writes a record this node does not own, and that needs no new
    /// authority model.** The address is world-derivable from a public key, and
    /// under Veilid's DFLT schema a world-derivable address implies a
    /// world-derivable *owner* — so the sender derives the recipient's owner
    /// keypair and signs the `set` with it, through the same
    /// `rendezvous::open_or_create` / `publish_at_subkey` pair every other record
    /// uses. The safety of the doorbell rests entirely on the entry being sealed to
    /// the recipient and verified by them, never on who could write the slot: any
    /// third party can overwrite or erase any slot, and that DoS residual is
    /// accepted and priced by the design rather than mitigated here.
    ///
    /// Two things are refused BEFORE the command crosses the channel, so neither
    /// can reach the network: a `slot` the record cannot hold, and an `entry` above
    /// the `dflt(32)` per-subkey cap. Both would otherwise fail after an
    /// `open_or_create` had already created or opened the record on the network.
    ///
    /// `entry` is opaque here: this layer neither parses, seals, nor verifies it,
    /// and a successful write proves nothing about the sender — the doorbell is
    /// world-writable, so reaching this function is not evidence of anything.
    ///
    /// Enqueued as a current-state write coalescing on the slot, at the class
    /// `dispatch` names. The full classification is stated on
    /// `doorbell_entry_write_request` (de-linked: it is private, and widening it to
    /// satisfy a doc link would be the wrong direction).
    pub async fn publish_doorbell_entry(
        &self,
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
    ) -> Result<()> {
        // Refused HERE, at the public boundary, and therefore before the command is
        // even built — the earliest point at which the two facts are both known.
        // Putting it further in would mean the record had been opened (or CREATED,
        // on this path) before anything was validated, which is the same
        // move `rendezvous::check_subkey_range` exists to make for the slot bound.
        doorbell_write_must_be_addressable(slot, entry.len())?;
        self.send(|reply| Command::PublishDoorbellEntry {
            owner_seed,
            slot,
            entry,
            dispatch,
            reply,
        })
        .await?
    }

    /// Sweep our own doorbell, returning `(slot, bytes)` per populated slot
    /// together with the sweep's outcome (ISC-C41).
    ///
    /// `owner_seed` is `daemonseed_core::dm::doorbell::derive_owner_seed` over
    /// **our** public identity key. Nothing here checks that: a doorbell owner seed
    /// is a world-derivable `[u8; 32]`, so sweeping someone else's doorbell is
    /// well-formed and simply returns entries no local key can open. The caller
    /// holds the decapsulation key and is the layer that knows whose doorbell this
    /// is.
    ///
    /// An empty `Vec` is the ordinary state of a doorbell nobody has knocked on,
    /// and is deliberately distinct from `Err`. The bytes are UNVERIFIED and still
    /// sealed — pass each to `daemonseed_core::dm::firstcontact::open`, which fails
    /// closed and uniformly, because a world-writable record makes garbage an
    /// ordinary input rather than an incident.
    ///
    /// A partial sweep returns what it read; `outcome.failed > 0` is a
    /// record-health signal, not an empty doorbell, and conflating the two would
    /// turn a network fault into "nobody wants to talk to you".
    pub async fn sweep_doorbell(&self, owner_seed: [u8; 32]) -> Result<DoorbellSweep> {
        self.send(|reply| Command::SweepDoorbell { owner_seed, reply })
            .await?
    }

    // ── Direct messaging (#235) ──

    /// Publish one direction's sealed acknowledgement record (ISC-C39). `record`
    /// is the prost-encoded `DmAck`; the caller builds it with
    /// `daemonseed_core::dm::ack_record::build_encoded` and builds `address` with
    /// `DmAckAddress::for_direction` over the same address root and direction.
    /// Enqueued as a coalescible `Keepalive` current-state write, so re-writing an
    /// acknowledgement costs at most one queued write per record however often it
    /// is called.
    ///
    /// Takes the address by value for the same reason [`Self::publish_dm_page`]
    /// does: an acknowledgement record's owner seed is the conversation's write
    /// capability, so it must be moved into the command rather than copied out of
    /// a borrow (#244). Derive one per call.
    pub async fn publish_dm_ack(&self, address: DmAckAddress, record: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::PublishDmAck {
            address,
            record,
            reply,
        })
        .await?
    }

    /// Fetch a correspondent's acknowledgement record. `Ok(None)` is an empty
    /// slot — evicted, or never written because the peer has settled nothing — and
    /// is the caller's *no confirmation yet* state, distinct from a transport
    /// failure. Conflating the two would let a network fault read as an absence of
    /// confirmation, which is the direction a fail-safe delivery state must never
    /// blur.
    ///
    /// Build `address` with `DmAckAddress::for_direction` over this conversation's
    /// address root and the direction whose messages the correspondent is
    /// acknowledging — for a sender reading its peer's acknowledgement, that is
    /// `Ratchet::send_direction`. Taken by value for the same reason
    /// [`Self::publish_dm_ack`] does: the seed is the conversation's capability for
    /// that record and must be moved, not copied out of a borrow (#244).
    ///
    /// The bytes are UNVERIFIED. Pass them to
    /// `daemonseed_core::dm::ack_record::decode_and_verify` with this
    /// conversation's `chan_id`, address root and the correspondent's pseudonym
    /// public key, then merge the resulting `PeerAck` under the highest sequence
    /// number this end has actually sent, before trusting anything in them.
    pub async fn fetch_dm_ack(&self, address: DmAckAddress) -> Result<Option<Vec<u8>>> {
        self.send(|reply| Command::FetchDmAck { address, reply })
            .await?
    }

    // ── Public-share CONTENT transfer (Phase 3): owner-on-demand over app_call ──

    /// Register a share to serve owner-on-demand. The actor answers inbound
    /// fragment `app_call`s for `share_id` from `content`, sealing each response
    /// under `room_key` (the share's `PublicRoomKey` bytes). The sharer must stay
    /// online to serve (ISC-A-S21); discovery (`publish_room`) is what advertises
    /// it.
    ///
    /// `content` is any [`ChunkSource`]: pass a `DiskShareContent` to serve a
    /// published share at O(CHUNK_SIZE) memory per request (#246), or a
    /// `ShareContent` to hold it in RAM.
    pub async fn serve_share(
        &self,
        share_id: String,
        content: Arc<dyn ChunkSource + Send + Sync>,
        room_key: [u8; 32],
    ) -> Result<()> {
        self.send(|reply| Command::ServeShare {
            share_id,
            content,
            room_key,
            reply,
        })
        .await?
    }

    /// Fetch + reassemble + open a share's manifest from the sharer reachable at
    /// private-route `route`. `room_key` is the share's `PublicRoomKey` bytes.
    pub async fn fetch_manifest(
        &self,
        route: RouteId,
        share_id: &str,
        room_key: [u8; 32],
    ) -> Result<Vec<ManifestEntry>> {
        let rk = PublicRoomKey::from_bytes(room_key);
        let this = self.clone();
        share::fetch_manifest(share_id, &rk, move |req| {
            let this = this.clone();
            let route = route.clone();
            async move { this.app_call(route, req).await }
        })
        .await
    }

    /// Budget-admitted manifest fetch (download-subsystem redesign, step 5). Same
    /// as [`fetch_manifest`](Self::fetch_manifest) but every fragment `app_call`
    /// is admitted through the shared per-route [`crate::RouteBudget`] via `lease`,
    /// so a folder's parallel fetches never exceed the sharer's route ceiling
    /// (#204). The scheduler leases once per download and shares the lease across
    /// the manifest + every chunk.
    pub async fn fetch_manifest_budgeted(
        &self,
        route: RouteId,
        share_id: &str,
        room_key: [u8; 32],
        lease: &crate::RouteLease<RouteId>,
    ) -> Result<Vec<ManifestEntry>> {
        let rk = PublicRoomKey::from_bytes(room_key);
        let this = self.clone();
        share::fetch_manifest_budgeted(share_id, &rk, lease, move |req| {
            let this = this.clone();
            let route = route.clone();
            async move { this.app_call(route, req).await }
        })
        .await
    }

    /// Budget-admitted chunk fetch (download-subsystem redesign, step 5). Reassembles,
    /// opens, and SHA-384-VERIFIES one chunk (ISC-S28 / ISC-A-S20) — but every fragment
    /// `app_call` is admitted
    /// through the shared per-route budget via `lease`, and the controller's
    /// `Failed`/`Completed` observations are fed INTERNALLY (the caller never calls
    /// `observe`). Returns the verified bytes + the max per-fragment latency.
    pub async fn fetch_chunk_budgeted(
        &self,
        route: RouteId,
        share_id: &str,
        chunk_addr: ChunkAddr,
        room_key: [u8; 32],
        lease: &crate::RouteLease<RouteId>,
    ) -> Result<(Vec<u8>, Duration)> {
        let rk = PublicRoomKey::from_bytes(room_key);
        let this = self.clone();
        share::fetch_chunk_budgeted(share_id, &chunk_addr, &rk, lease, move |req| {
            let this = this.clone();
            let route = route.clone();
            async move { this.app_call(route, req).await }
        })
        .await
    }

    /// One outbound `app_call` over a peer's private route (a fetch fragment
    /// round-trip).
    async fn app_call(&self, route: RouteId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.send(|reply| Command::AppCall {
            route,
            request,
            reply,
        })
        .await?
    }

    /// Announce a public share to the lobby with a SIGNED route advert (D-3.5 /
    /// [`crate::discovery`]). Allocates a private inbound route, has `signer` sign
    /// the route advert (`share_id ‖ route_blob`), wraps it with `sealed_announcement`
    /// (the core sealed `ShareAnnouncement`) into a [`crate::DiscoveryEnvelope`], and
    /// publishes it on the lobby rendezvous identified by `owner_seed`
    /// (`daemonseed_core::public_room::derive_room_veilid_owner_seed`). The advert is
    /// remembered and re-published on `RouteChanged`. Pair with [`Self::serve_share`],
    /// which registers the content this route serves.
    ///
    /// `persist` = true for a live share (remembered + re-published); false for a
    /// one-shot withdraw, which is written exactly once and never re-lingered (#163).
    pub async fn publish_share(
        &self,
        owner_seed: [u8; 32],
        share_id: String,
        sealed_announcement: Vec<u8>,
        signer: Arc<dyn discovery::RouteAdvertSigner>,
        persist: bool,
    ) -> Result<()> {
        self.send(|reply| Command::PublishShare {
            owner_seed,
            share_id,
            sealed_announcement,
            signer,
            persist,
            reply,
        })
        .await?
    }

    /// Stop serving a previously [`Self::serve_share`]d share and drop its advert.
    /// The teeth of unpublish: after this the owner no longer answers fetch
    /// `app_call`s for `share_id` (a holder of a stale route gets nothing), and a
    /// `RouteChanged` will not re-publish its advert. Pair with a withdraw
    /// announcement, which removes the share from listeners' discovery catalogs.
    pub async fn stop_serve(&self, share_id: String) -> Result<()> {
        self.send(|reply| Command::StopServe { share_id, reply })
            .await?
    }

    /// Publish a SEALED member-presence beacon to a presence rendezvous record
    /// (Phase 4). `owner_seed` is the **presence sibling** record's owner seed
    /// (`daemonseed_core::public_room::derive_room_presence_veilid_owner_seed` for
    /// the lobby/public room, `…::circle::key::derive_circle_presence_veilid_owner_seed`
    /// for a circle) — a record DISTINCT from the chat rendezvous, so a heartbeat
    /// can never evict the chat append-ring (P1). `member_pubkey` is the beacon's
    /// stable identity key; this owns the stable-id encoding
    /// ([`member_slot_id`], hex) so both the gui and tui callers derive the SAME
    /// slot, and the write lands in that member's `rendezvous::current_state_subkey`
    /// slot — last-writer-wins.
    ///
    /// **Slot-collision ceiling (bounded, degrades not-crashes).** The current-state
    /// scheme has only `rendezvous::SUBKEY_COUNT` slots (sized for a handful of
    /// shares). Presence membership is UNBOUNDED, so two members whose ids collide to
    /// one slot slot-share (last-writer-wins) — the loser is transiently missing from
    /// rosters. Bounded, self-healing (the next beacon may win the race back), but a
    /// real ceiling at lobby scale; the remedy is a larger dedicated presence schema —
    /// a record-key boundary change, deferred (#134).
    ///
    /// `sealed` is the opaque sealed `MemberHeartbeat`; this layer never holds the
    /// room key or the member's signing key. The emit/ingest/reap loop and all
    /// sealing/opening live in the app net actor (which holds the keys); a receiver
    /// SUBSCRIBES to the presence record via [`Self::subscribe_room`] on the same
    /// presence `owner_seed`.
    pub async fn publish_presence(
        &self,
        owner_seed: [u8; 32],
        member_pubkey: &[u8],
        sealed: Vec<u8>,
        boundary: PresenceBoundary,
    ) -> Result<()> {
        let stable_id = member_slot_id(member_pubkey);
        self.send(|reply| Command::PublishCurrentState {
            owner_seed,
            stable_id,
            sealed,
            boundary,
            reply,
        })
        .await?
    }

    /// Publish opaque bytes to a NAMED current-state slot on an owner-gated
    /// rendezvous record (Phase 4 A-b — the operator announcements/MOTD record).
    /// Last-writer-wins per slot; the write is owner-signed, so **only a holder of
    /// `owner_seed`** (the non-derivable project-announce owner —
    /// `daemonseed_core::public_space::derive_project_announce_veilid_owner_seed`)
    /// can place a value: it IS the DHT write-gate (A1). Clients holding only the
    /// owner PUBKEY [`Self::subscribe_room`] the record and read/verify but cannot
    /// write. `slot_id` is the stable slot key — a fixed `"motd"` for the MOTD, or an
    /// announcement item's content address. `bytes` is the caller's payload — a
    /// signed `SignedArtifact` (public + ML-DSA-87-provenance-signed, verified
    /// client-side by `daemonseed_core::public_space::verify_artifact`; NOT
    /// AEAD-sealed, since operator announcements are public). Spawned off-loop +
    /// per-record serialized, exactly like [`Self::publish_presence`].
    pub async fn publish_current_state(
        &self,
        owner_seed: [u8; 32],
        slot_id: &str,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.send(|reply| Command::PublishCurrentState {
            owner_seed,
            stable_id: slot_id.to_owned(),
            sealed: bytes,
            boundary: PresenceBoundary::Keepalive,
            reply,
        })
        .await?
    }
}

/// A stable presence-slot id for a member — its identity pubkey, hex-encoded. A
/// pure function of the member's stable identity, so a re-beacon overwrites the
/// SAME `rendezvous::current_state_subkey` slot (last-writer-wins) and the gui +
/// tui callers agree byte-for-byte. Owned here (not duplicated per caller) so the
/// slot encoding has one home.
pub fn member_slot_id(member_pubkey: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(member_pubkey.len() * 2);
    for b in member_pubkey {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Brings up the daemonseed Veilid transport node.
///
/// Phase 1 implements the PROVEN 1:1 path: identity-bound node, private routes,
/// sealed `app_message`. Phase 2 adds circles (shared-owner DFLT rendezvous +
/// append-ring fan-out). Shares, presence, and announcements are Phase 3+
/// ([`VeilidNetHandle`] signposts them).
pub struct VeilidNet;

impl VeilidNet {
    /// Bring up the node with a daemonseed-derived identity (D3), spawn the
    /// actor task, and return a [`VeilidNetHandle`] plus a stream of typed
    /// events. Does NOT attach — call [`VeilidNetHandle::attach_and_wait`].
    pub async fn start(
        cfg: VeilidNetConfig,
    ) -> Result<(VeilidNetHandle, mpsc::UnboundedReceiver<VeilidNetEvent>)> {
        // The storage dir is a hard prerequisite: veilid's protected store + insecure
        // keyring are created INSIDE it. Swallowing a create failure here (`.ok()`)
        // let a missing/unwritable dir surface downstream as the misleading
        // "internal failed to create insecure keyring" (#188) — a silent-looking
        // launch failure. Propagate the real cause + path instead so the GUI's
        // `ConnectFailed` shows what actually went wrong. An existing dir returns
        // `Ok`, so the working (id-already-exists) path is unaffected.
        std::fs::create_dir_all(&cfg.storage_dir).map_err(|e| {
            VeilidNetError::Startup(format!(
                "could not create veilid storage dir {:?}: {e}",
                cfg.storage_dir
            ))
        })?;

        let (ev_tx, ev_rx) = mpsc::unbounded_channel::<VeilidNetEvent>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
        // Inbound app_calls (the share-serve request path) get a DEDICATED lane,
        // never the command channel: veilid answers an inbound call for only
        // `rpc.timeout_ms` (5s default), and a shared FIFO parks serve requests
        // behind multi-second inline DHT commands (a chat publish is an
        // open_or_create + set), so every reply landed late → "Unmatched
        // operation id" on the sharer, timeout wave + prune on the fetcher.
        // BOUNDED + shed (#125): the producer (the update callback) must never
        // block, so on a full queue it `try_send`-sheds the incoming request — a
        // shed serve is one fetcher retry, which the fetch side already does — rather
        // than growing without limit under a serve-latency spike.
        let (serve_tx, serve_rx) =
            mpsc::channel::<(OperationId, Vec<u8>, std::time::Instant)>(SERVE_QUEUE_CAP);
        let ev_tx_cb = ev_tx.clone();
        let cmd_tx_cb = cmd_tx.clone();
        let update_callback: Arc<dyn Fn(VeilidUpdate) + Send + Sync> = Arc::new(
            move |u: VeilidUpdate| match u {
                VeilidUpdate::AppCall(call) => {
                    let entry = (
                        call.id(),
                        call.message().to_vec(),
                        std::time::Instant::now(),
                    );
                    match serve_tx.try_send(entry) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => crate::vtrace!(
                            "serve: inbound queue full ({SERVE_QUEUE_CAP} cap), shedding a fetch request (fetcher retries)"
                        ),
                        Err(mpsc::error::TrySendError::Closed(_)) => {} // actor gone
                    }
                }
                // A private route died/rotated: hand the dead-route list to the
                // actor (which knows which routes it currently advertises) AND
                // surface the event. Under the relevance filter a genuine death
                // is a ONE-SHOT event, so a full FIFO must not eat it — on Full,
                // deliver on a spawned awaited send once a slot frees.
                VeilidUpdate::RouteChange(chg) => {
                    let cmd = Command::RouteMaintenance {
                        dead_routes: chg.dead_routes.clone(),
                    };
                    if let Err(mpsc::error::TrySendError::Full(cmd)) = cmd_tx_cb.try_send(cmd) {
                        let tx = cmd_tx_cb.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(cmd).await;
                        });
                    }
                    let _ = ev_tx_cb.send(VeilidNetEvent::RouteChanged);
                }
                other => {
                    if let Some(ev) = map_update(other) {
                        let _ = ev_tx_cb.send(ev);
                    }
                }
            },
        );

        let mut vcfg = VeilidConfig::new(
            "daemonseed_veilid_net",
            "daemonseed",
            "net",
            Some(&cfg.storage_dir),
            None,
        );
        vcfg.namespace = cfg.namespace.clone();
        vcfg.protected_store.always_use_insecure_storage = true;
        vcfg.protected_store.allow_insecure_fallback = true;
        // Veilid timeouts stay at defaults (rpc 5s, dht value ops 10s).
        // `rpc.timeout_ms` is not an app_call-only knob: it prices every RPC
        // probe, the fanout slow-node throttle is pegged to 33% of it, and the
        // config validator forces the DHT value budgets to >= 2x it — so
        // raising it reprices every chat publish, sweep, and watch. veilid-core
        // exposes no per-call app_call timeout ("governed by
        // network.rpc.timeout_ms"); a longer fragment-fetch deadline needs an
        // app-level mechanism, not this knob.
        // Distinct listen ports let several nodes coexist on one host (tests).
        if let Some(addr) = &cfg.listen_address {
            vcfg.network.protocol.udp.listen_address = addr.clone();
            vcfg.network.protocol.tcp.listen_address = addr.clone();
            vcfg.network.protocol.ws.listen_address = addr.clone();
        }
        // D4: public network — no network_key_password. Override bootstrap only
        // if the caller baked one in (the fra1 seed).
        if !cfg.bootstrap.is_empty() {
            vcfg.network.routing_table.bootstrap = cfg.bootstrap.clone();
        }
        // D3: pin the daemonseed-derived node identity.
        let (pks, sks) = identity::identity_groups(&cfg.identity_seed)?;
        vcfg.network.routing_table.public_keys = pks;
        vcfg.network.routing_table.secret_keys = sks;

        crate::vtrace!(
            "start: namespace={:?} listen={:?} store={} bootstrap_overrides={}",
            vcfg.namespace,
            cfg.listen_address,
            cfg.storage_dir,
            cfg.bootstrap.len()
        );
        let api = api_startup(update_callback, vcfg)
            .await
            .map_err(|e| VeilidNetError::Startup(e.to_string()))?;
        crate::vtrace!("start: api_startup ok; node identity assigned");
        // Phase 1 uses Veilid's DEFAULT routing context, which already carries a
        // 1-hop safety route. Sends ride the receiver's private route
        // (Target::RouteId), so no safety override is needed. D5 — raising the
        // hop count via with_safety(Safe { hop_count: cfg.hop_count }) — is the
        // planned dial-up; cfg.hop_count is carried for it. (An explicit Unsafe
        // context would need veilid-core's footgun-nodeid-target feature — the
        // anti-dox NodeId path we deliberately avoid.)
        let rc = api
            .routing_context()
            .map_err(|e| VeilidNetError::Routing(e.to_string()))?;

        // This node's pubkey spreads it across the circle record's subkey
        // regions (Phase 2 fan-out).
        let node_pub = identity::node_public_bytes(&cfg.identity_seed);

        // Served-share registry, shared between the actor loop (ServeShare /
        // StopServe register + withdraw) and the dedicated serve task (answers
        // inbound fetch app_calls). Locked only for synchronous map ops and the
        // in-memory seal — never across an await.
        let shares: Arc<Mutex<HashMap<String, share::ServedShare>>> =
            Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(serve_loop(api.clone(), shares.clone(), serve_rx));
        // Weak so the actor's own re-arm tasks never hold the command channel
        // open: it still closes (and the loop still cleans up) when the last
        // real handle drops.
        let cmd_weak = cmd_tx.downgrade();
        // #124 watchdog ticker: a slow heartbeat that nudges the actor to re-publish
        // its adverts, recovering a route that died without an observed RouteChange.
        // Weak sender so the ticker dies with the last real handle (never keeps the
        // actor alive); a send failure means the actor is gone → stop ticking.
        let watchdog_weak = cmd_tx.downgrade();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(ADVERT_WATCHDOG_INTERVAL);
            tick.tick().await; // consume the immediate first tick — first refresh at +interval
            loop {
                tick.tick().await;
                match watchdog_weak.upgrade() {
                    Some(tx) => {
                        if tx.send(Command::AdvertWatchdog).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });
        // Shared congestion probe (WB-1.10): the scheduler publishes each non-chat
        // write's enqueue-to-ack latency here; the handle exposes it to the presence
        // reaper. Created before the actor loop so both sides share the one Arc.
        let write_latency = Arc::new(AtomicU64::new(0));
        tokio::spawn(actor_loop(
            api,
            rc,
            cmd_rx,
            ev_tx,
            node_pub,
            shares,
            cmd_weak,
            write_latency.clone(),
        ));
        Ok((
            VeilidNetHandle {
                cmd_tx,
                write_latency,
            },
            ev_rx,
        ))
    }
}

/// The actor task: owns the `VeilidAPI` + `RoutingContext` and processes
/// commands until `Shutdown` or the command channel closes. Holds an event
/// sender (for background rendezvous sweeps), this node's pubkey (region
/// assignment), and a per-rendezvous append-ring write cursor.
#[allow(clippy::too_many_arguments)]
async fn actor_loop(
    api: VeilidAPI,
    rc: RoutingContext,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev_tx: mpsc::UnboundedSender<VeilidNetEvent>,
    node_pub: [u8; 32],
    shares: Arc<Mutex<HashMap<String, share::ServedShare>>>,
    cmd_weak: mpsc::WeakSender<Command>,
    write_latency: Arc<AtomicU64>,
) {
    // Cache of opened rendezvous records (owner seed → post-reopen key):
    // open_or_create costs a fresh ~6–10 s open per publish/subscribe, so once a
    // record is open its key is reused. Shared (Arc) so a spawned advert refresh
    // reuses the SAME opened handles as the main loop. There is deliberately NO
    // error-path invalidation — a cached key is held for the whole session (see
    // rendezvous::open_cached); a transient set/get failure is surfaced to the
    // caller, not treated as a dead local handle.
    let opened: Arc<rendezvous::OpenCache> = Arc::new(Mutex::new(HashMap::new()));
    // LRU recency over the DM channel-page subset of `opened` (#252). Pages are the
    // one record family whose count grows with traffic rather than with peers — a new
    // owner seed every PAGE_SLOTS messages, per direction, per conversation — so the
    // open-once contract above would hold DHT records open for the life of the
    // process. Only the page opener records into this ring, so only pages are ever
    // evicted and the shared entries keep the open-once behaviour exactly.
    let page_recency: Arc<rendezvous::DmPageRecency> =
        Arc::new(Mutex::new(rendezvous::BoundedRing::new()));
    // Per-rendezvous-record serialization lock (owner seed → async mutex). Two ops
    // on the SAME record must not race: spawned append-ring publishes would clobber
    // each other in the 2-slot ring (an older seq landing after a newer one loses
    // the newer message), and two cold-cache callers would both open_or_create. One
    // async mutex per record serializes both; DISTINCT records stay fully concurrent,
    // so a slow write to one record never blocks another's traffic or the actor loop.
    // Shared so the spawned publish + advert refresh contend on the same locks as the
    // main loop. See rendezvous::record_lock + ISA (2026-07-07, #128 xhigh review).
    let record_locks: Arc<rendezvous::RecordLocks> = Arc::new(Mutex::new(HashMap::new()));
    // Active share adverts (Phase 3 discovery), keyed by share_id, so a
    // RouteChanged can re-allocate + re-sign + re-publish each one.
    let mut share_adverts: HashMap<String, AdvertState> = HashMap::new();
    // The CURRENT private RouteId per advertised share, so a re-publish releases
    // the previous route instead of leaking it under route churn. Shared so the
    // spawned refresh releases through the same map as the main loop.
    let advert_routes: Arc<Mutex<HashMap<String, RouteId>>> = Arc::new(Mutex::new(HashMap::new()));
    // Coalesce RouteChanged bursts: at most one refresh in flight at a time, and
    // the next no sooner than ADVERT_REFRESH_MIN_INTERVAL after the last one
    // COMPLETED. Both are shared with the spawned refresh, which stamps the
    // completion time and clears the in-flight flag when it finishes.
    let refresh_in_flight = Arc::new(AtomicBool::new(false));
    let last_advert_refresh: Arc<Mutex<Option<tokio::time::Instant>>> = Arc::new(Mutex::new(None));
    // Per-record repair-in-flight guard (F1 / CRSH-ISC-22). A `RepairRendezvous` is
    // dispatched OFF this loop (spawned), so the loop can receive a second repair for the
    // SAME record — from a re-dispatch the frontend dedup can't reach — while the first is
    // still running. This set holds the records with a repair in flight; a re-dispatch for
    // a record already present is skipped rather than double-run. The `std::sync::Mutex` is
    // only ever held briefly (insert on dispatch, remove on completion), never across an
    // await. Shared with each spawned repair task, which clears its marker when it finishes.
    let repair_in_flight: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));

    // The WB-3 write funnel (I1): every `set_dht_value` in this actor is dispatched
    // through this one prioritized, rate-limited scheduler. The production sink holds
    // the SAME shared caches (opened / record_locks) the read paths use, so a
    // scheduled write and a concurrent same-record subscribe/resweep still serialize
    // on the record's `record_lock`. The append-ring cursor lives in the sink because
    // only the write path touches it. The write commands below enqueue and return, so
    // a slow DHT set never parks this loop (#154 retired).
    // The shared DHT permit accountant (WB-5 / I5′.1): the write lane (via the sink)
    // and the read lane (sweeps/resweeps) both draw permits here, so daemonseed's own
    // combined in-flight DHT ops stay provably under veilid's 16-permit gate, and chat
    // keeps a reserved permit it never has to queue behind a non-chat backlog for.
    let dht_gate = DhtGate::new();
    let sched: WriteSchedulerHandle<ProdWrite> = WriteScheduler::spawn_with_probe(
        Arc::new(ProductionSink {
            api: api.clone(),
            rc: rc.clone(),
            node_pub,
            ring_seq: Arc::new(Mutex::new(HashMap::new())),
            opened: opened.clone(),
            page_recency: page_recency.clone(),
            record_locks: record_locks.clone(),
            gate: dht_gate.clone(),
        }),
        SchedulerConfig::default(),
        write_latency,
    );

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Command::Attach {
                timeout_secs,
                reply,
            } => {
                let _ = reply.send(attach_and_wait(&api, timeout_secs).await);
            }
            Command::NewInboundRoute { reply } => {
                let res = api
                    .new_private_route()
                    .await
                    .map_err(|e| VeilidNetError::Routing(e.to_string()));
                let _ = reply.send(res);
            }
            Command::ImportRoute { blob, reply } => {
                let res = api
                    .import_remote_private_route(blob)
                    .map_err(|e| VeilidNetError::Routing(e.to_string()));
                let _ = reply.send(res);
            }
            Command::SendSealed {
                route,
                sealed,
                reply,
            } => {
                let _ = reply.send(send_sealed(&rc, route, sealed).await);
            }
            Command::PublishRendezvous {
                owner_seed,
                sealed,
                reply,
            } => {
                // Chat / room / circle append-ring write — the highest priority class
                // (I1) and never coalesced (I3). Enqueue and return: the scheduler
                // dispatches (record_lock + ring-seq bump inside it, #131/I2 intact)
                // and fires the reply, so a slow DHT set never parks this loop (#154).
                // Per-record FIFO in the funnel + the receiver's sent_unix_ms sort
                // (#105/#126) preserve ordering.
                sched.enqueue(WriteRequest {
                    record: funnel_record_key(&owner_seed),
                    class: WriteClass::Chat,
                    kind: WriteKind::Ring,
                    deadline: None,
                    item: ProdWrite::Rendezvous { owner_seed, sealed },
                    reply: Some(reply),
                });
            }
            Command::PublishDmKeyRecord {
                owner_seed,
                record,
                reply,
            } => {
                // Class-4 Keepalive, coalescible last-writer-wins (WB-3 I1/I3,
                // `docs/design/direct-messaging.md` § Fork 4 — "key-record keep-alive"
                // is named there as a Keepalive-class writer). Coalescing is the point:
                // the record is re-seeded against eviction on a slow schedule, and a
                // newer re-seed always supersedes a queued older one for the same
                // record. The logical id is a constant because there is exactly one
                // key record per owner seed, so the coalescing key `(record, id)`
                // collapses to the record — which is the intended behaviour.
                sched.enqueue(WriteRequest {
                    record: funnel_record_key(&owner_seed),
                    class: WriteClass::Keepalive,
                    kind: WriteKind::CurrentState {
                        logical_id: "dm-keyrec".to_string(),
                    },
                    deadline: None,
                    item: ProdWrite::DmKeyRecord { owner_seed, record },
                    reply: Some(reply),
                });
            }
            Command::FetchDmKeyRecord { owner_seed, reply } => {
                // A read, so it never touches the write funnel (I9: no read-triggered
                // writes).
                //
                // SPAWNED, never awaited inline (D-0b / #128, CRSH-ISC-22). The GET
                // itself is one subkey, but it is preceded by an `open_or_create` that
                // costs ~6-10 s live-measured on a cold cache — and the caller fetches
                // one key record PER correspondent, so a cold start walks C serial
                // opens (`docs/design/direct-messaging.md` § Decision #4 prices C=20 at
                // ~2-3 minutes). Awaiting that on the command loop would park every
                // other command behind it for minutes: the exact #154 failure mode the
                // off-loop dispatch rule exists to prevent. The `oneshot` reply is
                // moved into the task, so the caller still gets exactly one answer.
                let gate = dht_gate.clone();
                let api = api.clone();
                let rc = rc.clone();
                let opened = opened.clone();
                let record_locks = record_locks.clone();
                tokio::spawn(async move {
                    let r =
                        fetch_dm_key_record(&gate, &api, &rc, &opened, &record_locks, owner_seed)
                            .await;
                    // A dropped receiver (caller gave up / shutting down) is benign.
                    let _ = reply.send(r);
                });
            }
            Command::PublishDmPage {
                address,
                frame,
                reply,
            } => {
                // The classification is built by `dm_page_write_request` rather than
                // inline, because every field of it fails SILENTLY and a funnel
                // request constructed on the command loop is reachable from no test.
                // See that function for why each field is what it is.
                //
                // WARM THE RECORD OPEN FIRST, off the chat lane. A chat-class dispatch
                // holds one of only CHAT_PERMITS (2) permits across the WHOLE write,
                // and for a page nobody has opened yet that write begins with a cold
                // `open_or_create` — measured ~6-10 s, and worst case open→create→open.
                // A conversation crosses into a new page every PAGE_SLOTS messages,
                // forever, so without this the chat lane eats that stall on a recurring
                // schedule; two conversations rolling over together would hold both
                // permits and stall every circle and lobby message in the app behind
                // them.
                //
                // **This is a latency argument, not a rule violation.** Opening a record
                // while holding a pool permit is explicitly sanctioned — `dht_gate`'s
                // margin doc names the publish path opening under its write permit as
                // the normal case — and WB-ISC-24 is about permit ACQUISITION (a chat
                // acquire never waits on a non-chat pool), not about what work runs
                // under a held one. The old arrangement broke no contract; it was just
                // a recurring multi-second occupancy of a 2-permit lane.
                //
                // Nor is the open made cheaper: it still costs an un-gated-limiter
                // permit, exactly as it did before, and that limiter is the margin(2)
                // shared with watches, consumer-route repair and Refresh. What changes
                // is only that it no longer ALSO holds a chat permit for its duration.
                //
                // Pre-opening populates the shared open cache, so the dispatch's own
                // `dm_page_open` is a map hit and the chat permit covers only the
                // `set_dht_value`. A pre-open FAILURE is not fatal and not swallowed:
                // it is traced, and the write is enqueued regardless, so the dispatch
                // retries the open under the permit exactly as it would have anyway.
                // Spawned so the command loop never waits on the open (D-0b / #128).
                let sched = sched.clone();
                let gate = dht_gate.clone();
                let api = api.clone();
                let rc = rc.clone();
                let opened = opened.clone();
                let page_recency = page_recency.clone();
                let record_locks = record_locks.clone();
                tokio::spawn(async move {
                    // Borrowed for the pre-open; ownership passes to the request
                    // below, so exactly one zeroizing copy of the conversation
                    // secret exists on this path (#244).
                    match address.with_owner_seed(identity::rendezvous_owner_keypair) {
                        Ok(owner) => {
                            // Single-flight against a concurrent op on this record, as
                            // the dispatch itself does. The guard is dropped before the
                            // enqueue so the write never queues holding a record lock.
                            let record_lock = rendezvous::record_lock(&record_locks, &owner.key());
                            let _open_guard = record_lock.lock().await;
                            if let Err(e) = dm_page_open(
                                &gate,
                                &api,
                                &rc,
                                &opened,
                                &page_recency,
                                &record_locks,
                                &owner,
                                IfAbsent::Create,
                            )
                            .await
                            {
                                crate::vtrace!(
                                    "publish_dm_page: pre-open failed ({e}); enqueuing anyway, \
                                     the dispatch will retry the open under the chat permit"
                                );
                            }
                        }
                        Err(e) => {
                            // The dispatch derives the same keypair and will fail the
                            // same way, reporting it through the caller's `reply`.
                            crate::vtrace!("publish_dm_page: owner keypair failed ({e})");
                        }
                    }
                    sched.enqueue(dm_page_write_request(address, frame, reply));
                });
            }
            Command::SweepDmPage { address, reply } => {
                // A read, so it never touches the write funnel (I9: no read-triggered
                // writes). SPAWNED, never awaited inline (D-0b / #128, CRSH-ISC-22):
                // the sweep is PAGE_SLOTS gated GETs behind an `open_or_create` that
                // costs ~6-10 s on a cold cache, and collection probes the frontier
                // page ahead of the one being filled — so a live conversation issues
                // these continuously. Awaiting one on the command loop would park every
                // other command behind it, the #154 failure mode exactly.
                let gate = dht_gate.clone();
                let api = api.clone();
                let rc = rc.clone();
                let opened = opened.clone();
                let page_recency = page_recency.clone();
                let record_locks = record_locks.clone();
                tokio::spawn(async move {
                    let r = sweep_dm_page(
                        &gate,
                        &api,
                        &rc,
                        &opened,
                        &page_recency,
                        &record_locks,
                        &address,
                    )
                    .await;
                    // A dropped receiver (caller gave up / shutting down) is benign.
                    let _ = reply.send(r);
                });
            }
            Command::PublishDoorbellEntry {
                owner_seed,
                slot,
                entry,
                dispatch,
                reply,
            } => {
                // The classification is built by `doorbell_entry_write_request` rather
                // than inline, for the reason `dm_page_write_request` gives: every field
                // of it fails SILENTLY, and a funnel request constructed on the command
                // loop is reachable from no test.
                //
                // **The two dispatches take different paths here, because they are
                // different writes.** `enqueue` is a synchronous send on an unbounded
                // channel and can neither block nor yield, so nothing in this arm needs
                // spawning for the D-0b / #128 / CRSH-ISC-22 reason — that rule is about
                // not AWAITING the DHT on the loop.
                match dispatch {
                    // A re-seed is class-4. Enqueue and return, exactly as
                    // `PublishDmKeyRecord` does for the sibling keep-alive. A pre-open
                    // would be actively wrong: the funnel may pace this write minutes
                    // later, so opening the record NOW moves network work out from under
                    // the budget the funnel exists to enforce, and decouples the open
                    // from the write it is meant to be warming.
                    DoorbellDispatch::Reseed => {
                        sched.enqueue(doorbell_entry_write_request(
                            owner_seed, slot, entry, dispatch, reply,
                        ));
                    }
                    // A first send is `Chat`, and that changes the argument completely.
                    // WARM THE RECORD OPEN FIRST, off the chat lane — the same trade
                    // `PublishDmPage` makes, and for a sharper reason. A chat-class
                    // dispatch holds one of only CHAT_PERMITS (2) across the WHOLE write,
                    // and a first contact's target is a STRANGER's doorbell this node has
                    // never opened, so that write begins with a cold `open_or_create`
                    // (~6-10 s live-measured, worst case open->create->open). This is now
                    // the only Chat-class write in the crate whose record can be cold at
                    // dispatch: the subscribe-time rendezvous record is already open and
                    // the page is pre-warmed by the arm above. Two concurrent first
                    // contacts would otherwise hold both permits for seconds and queue
                    // every chat message in the app behind them.
                    //
                    // A latency argument, not a rule violation: opening under a pool
                    // permit is sanctioned, and WB-ISC-24 governs permit ACQUISITION, not
                    // what runs under a held one. Nor is the open made cheaper — it still
                    // costs an un-gated margin permit. What changes is that it no longer
                    // ALSO holds a chat permit for its duration.
                    //
                    // A pre-open FAILURE is not fatal and not swallowed: it is traced and
                    // the write enqueued regardless, so the dispatch retries the open
                    // under the chat permit exactly as it would have anyway. Spawned so
                    // the command loop never waits on the open (D-0b / #128).
                    DoorbellDispatch::FirstSend => {
                        let sched = sched.clone();
                        let gate = dht_gate.clone();
                        let api = api.clone();
                        let rc = rc.clone();
                        let opened = opened.clone();
                        let record_locks = record_locks.clone();
                        tokio::spawn(async move {
                            match identity::rendezvous_owner_keypair(&owner_seed) {
                                Ok(owner) => {
                                    // Single-flight against a concurrent op on this
                                    // record, as the dispatch itself does. The guard is
                                    // dropped before the enqueue so the write never
                                    // queues holding a record lock.
                                    let record_lock =
                                        rendezvous::record_lock(&record_locks, &owner.key());
                                    let _open_guard = record_lock.lock().await;
                                    if let Err(e) = doorbell_open(
                                        &gate,
                                        &api,
                                        &rc,
                                        &opened,
                                        &owner,
                                        IfAbsent::Create,
                                    )
                                    .await
                                    {
                                        crate::vtrace!(
                                            "publish_doorbell_entry: pre-open failed ({e}); \
                                             enqueuing anyway, the dispatch will retry the \
                                             open under the chat permit"
                                        );
                                    }
                                }
                                Err(e) => {
                                    // The dispatch derives the same keypair and will fail
                                    // the same way, reporting it through the caller's
                                    // `reply`.
                                    crate::vtrace!(
                                        "publish_doorbell_entry: owner keypair failed ({e})"
                                    );
                                }
                            }
                            sched.enqueue(doorbell_entry_write_request(
                                owner_seed, slot, entry, dispatch, reply,
                            ));
                        });
                    }
                }
            }
            Command::SweepDoorbell { owner_seed, reply } => {
                // A read, so it never touches the write funnel (I9: no read-triggered
                // writes). SPAWNED, never awaited inline (D-0b / #128, CRSH-ISC-22):
                // the sweep is DOORBELL_SLOTS (32) gated GETs behind an open that costs
                // ~6-10 s on a cold cache, and a client re-sweeps its doorbell on a
                // recurring schedule for as long as it is running. Awaiting one on the
                // command loop would park every other command behind it for tens of
                // seconds, the #154 failure mode exactly.
                let gate = dht_gate.clone();
                let api = api.clone();
                let rc = rc.clone();
                let opened = opened.clone();
                let record_locks = record_locks.clone();
                tokio::spawn(async move {
                    let r =
                        sweep_doorbell(&gate, &api, &rc, &opened, &record_locks, owner_seed).await;
                    // A dropped receiver (caller gave up / shutting down) is benign.
                    let _ = reply.send(r);
                });
            }
            Command::PublishDmAck {
                address,
                record,
                reply,
            } => {
                // Class-4 Keepalive, coalescible last-writer-wins, exactly as
                // `PublishDmKeyRecord` is and for a stronger reason: the statement is
                // MONOTONIC, so a newer acknowledgement contains everything a queued
                // older one carried and coalescing can drop nothing. The logical id is
                // a constant because one address names exactly one acknowledgement
                // record — the coalescing key `(record, id)` collapses to the record,
                // which is the intended behaviour.
                //
                // The funnel key is derived from the address's own seed and the
                // address is then MOVED into the item, so the conversation secret is
                // never copied into a second binding on this loop (#244). Struct
                // fields initialise in source order, so `record:` reads the seed
                // before `item:` takes the address.
                sched.enqueue(WriteRequest {
                    record: funnel_record_key(address.owner_seed().as_bytes()),
                    class: WriteClass::Keepalive,
                    kind: WriteKind::CurrentState {
                        logical_id: "dm-ack".to_string(),
                    },
                    deadline: None,
                    item: ProdWrite::DmAck { address, record },
                    reply: Some(reply),
                });
            }
            Command::FetchDmAck { address, reply } => {
                // A read, so it never touches the write funnel (I9: no read-triggered
                // writes). SPAWNED, never awaited inline (D-0b / #128, CRSH-ISC-22) for
                // the reason `FetchDmKeyRecord` gives: the GET is one subkey, but the
                // `open_or_create` in front of it costs ~6-10 s on a cold cache, and a
                // sender polls one acknowledgement record PER conversation.
                //
                // The address is MOVED into the task and borrowed from there, so the
                // conversation secret lives exactly as long as the read it authorises
                // and zeroizes when the task ends (#244).
                let gate = dht_gate.clone();
                let api = api.clone();
                let rc = rc.clone();
                let opened = opened.clone();
                let record_locks = record_locks.clone();
                tokio::spawn(async move {
                    let r = fetch_dm_ack(&gate, &api, &rc, &opened, &record_locks, &address).await;
                    // A dropped receiver (caller gave up / shutting down) is benign.
                    let _ = reply.send(r);
                });
            }
            Command::SubscribeRendezvous { owner, reply } => {
                let _ = reply.send(
                    subscribe_rendezvous(
                        &api,
                        &rc,
                        &ev_tx,
                        &opened,
                        &record_locks,
                        &dht_gate,
                        &owner,
                    )
                    .await,
                );
            }
            Command::PublishCurrentState {
                owner_seed,
                stable_id,
                sealed,
                boundary,
                reply,
            } => {
                // Current-state presence / MOTD write. The WB-1 boundary sets the
                // funnel class + coalescing kind (Slice B live callers): a keepalive
                // is class-4 last-writer-wins; a join is class-2 session-boundary
                // current-state; a leave is a class-2 non-coalescible tombstone that
                // dominates any queued same-member keepalive (I3, no resurrection).
                // Enqueue and return; the scheduler paces it under the non-chat cap so
                // it never blocks chat, and dispatches through the record's `record_lock`.
                let (class, kind) = boundary.classify(stable_id.clone());
                sched.enqueue(WriteRequest {
                    record: funnel_record_key(&owner_seed),
                    class,
                    kind,
                    deadline: None,
                    item: ProdWrite::CurrentState {
                        owner_seed,
                        stable_id,
                        sealed,
                    },
                    reply: Some(reply),
                });
            }
            Command::ResweepRendezvous { owner, reply } => {
                let _ = reply.send(
                    resweep_rendezvous(
                        &api,
                        &rc,
                        &ev_tx,
                        &opened,
                        &record_locks,
                        &dht_gate,
                        &owner,
                    )
                    .await,
                );
            }
            Command::RepairRendezvous { owner, reply } => {
                // The owner's public key is taken once, up front: it keys the in-flight
                // guard below as well as the record's open cache and lock, and all three
                // must name the same thing. Both owner arms yield it.
                let owner_id = owner.public_bytes();
                // F1 (#180): dispatch the repair OFF the actor loop. `repair_rendezvous`
                // awaits a close/open/watch + full 0..64 re-sweep; on a DEAD record each
                // GET hits the veilid timeout, so awaiting it INLINE (as this arm once did)
                // parks the single-tasked loop for seconds→tens of seconds and starves every
                // other inline command (SendSealed 1:1 sends, SubscribeRendezvous joins) —
                // the exact chat-starvation class #180 exists to kill. Spawning it returns
                // the loop to `recv()` immediately. Atomicity vs a concurrent same-record
                // write is provided by the `record_lock` (acquired inside `repair_gated` and
                // held across the WHOLE re-establishment, CRSH-ISC-3/18), NOT by the inline
                // await — so moving the await into a spawned task preserves atomicity while
                // freeing the loop.
                //
                // Per-record in-flight guard (CRSH-ISC-22): the transport can legitimately
                // receive two RepairRendezvous for the same record (a re-dispatch the
                // frontend dedup can't reach), so a repair already in flight for this record
                // is skipped — dedup — rather than double-run. The std::sync::Mutex is only
                // held briefly (insert here, remove in the spawned task), never across an await.
                {
                    let mut set = repair_in_flight.lock().unwrap_or_else(|e| e.into_inner());
                    if !set.insert(owner_id) {
                        // A repair for this record is already in flight — skip, don't spawn.
                        let _ = reply.send(Ok(()));
                        continue;
                    }
                }
                let api = api.clone();
                let rc = rc.clone();
                let ev_tx = ev_tx.clone();
                let opened = opened.clone();
                let record_locks = record_locks.clone();
                let dht_gate = dht_gate.clone();
                let repair_in_flight = repair_in_flight.clone();
                tokio::spawn(async move {
                    // RAII: the guard clears the in-flight marker on Drop, which runs on
                    // BOTH normal completion AND panic-unwind (CRSH-ISC-22) — so a panic in
                    // `repair_rendezvous` cannot leave a stale marker that permanently skips
                    // (disables) this record's future self-heal.
                    let _guard = RepairInFlightGuard {
                        set: repair_in_flight,
                        key: owner_id,
                    };
                    let res = repair_rendezvous(
                        &api,
                        &rc,
                        &ev_tx,
                        &opened,
                        &record_locks,
                        &dht_gate,
                        &owner,
                    )
                    .await;
                    let _ = reply.send(res);
                    // `_guard` drops here on normal return, or on panic-unwind — the marker
                    // is cleared either way.
                });
            }
            Command::RendezvousKey { owner, reply } => {
                // Local crypto only (no network): resolve the owner, compute the
                // deterministic record key. Feeds the frontend's RecordKey→owner map.
                // Both arms address the same record — `rendezvous_key_for` is one body
                // behind both entry points — so a reader and a writer of one record
                // resolve to one `RecordKey`.
                let res = match owner.resolve() {
                    Ok(identity::ResolvedOwner::Writer(keypair)) => rendezvous::rendezvous_key(
                        &api,
                        &keypair,
                        rendezvous::RecordShape::RENDEZVOUS,
                    )
                    .await
                    .map(rendezvous::RendezvousHandle::into_key),
                    Ok(identity::ResolvedOwner::ReadOnly(public)) => {
                        rendezvous::rendezvous_key_from_owner_public(
                            &api,
                            public.as_bytes(),
                            rendezvous::RecordShape::RENDEZVOUS,
                        )
                        .await
                        .map(rendezvous::RendezvousHandle::into_key)
                    }
                    Err(e) => Err(e),
                };
                let _ = reply.send(res);
            }
            Command::ServeShare {
                share_id,
                content,
                room_key,
                reply,
            } => {
                shares
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(
                        share_id,
                        share::ServedShare::new(content, PublicRoomKey::from_bytes(room_key)),
                    );
                let _ = reply.send(Ok(()));
            }
            Command::AppCall {
                route,
                request,
                reply,
            } => {
                // Spawn so a multi-fragment fetch never blocks the actor loop.
                let rc2 = rc.clone();
                tokio::spawn(async move {
                    let r = rc2
                        .app_call(Target::RouteId(route), request)
                        .await
                        .map_err(|e| VeilidNetError::Send(e.to_string()));
                    let _ = reply.send(r);
                });
            }
            Command::PublishShare {
                owner_seed,
                share_id,
                sealed_announcement,
                signer,
                persist,
                reply,
            } => {
                let advert = AdvertState {
                    owner_seed,
                    sealed_announcement,
                    signer,
                };
                // A live share (`persist`) is remembered so a RouteChanged / watchdog
                // can refresh it, and a first-publish write failure self-heals on the
                // next watchdog tick rather than being lost. A withdraw (`!persist`) is
                // a ONE-SHOT write: it is NOT remembered, so a RouteChanged/watchdog
                // never re-publishes it — the withdraw cannot re-linger and re-race a
                // later reshare on the same (#156-deterministic) id (#163). Either way
                // the route alloc + funnel write runs OFF the command loop so it never
                // parks (#154); the scheduler classes it class-3 and coalesces
                // same-share refreshes (I1/I3).
                if persist {
                    share_adverts.insert(share_id.clone(), advert.clone());
                }
                let api = api.clone();
                let sched = sched.clone();
                let advert_routes = advert_routes.clone();
                tokio::spawn(async move {
                    // `persist` threads into publish_one_advert: a withdraw (false) is a
                    // one-shot write that releases its OWN route (guarded against a
                    // concurrent same-id reshare), so it is never remembered for a
                    // RouteChanged/watchdog re-publish (#163).
                    let res = publish_one_advert(
                        &api,
                        &sched,
                        &advert_routes,
                        &share_id,
                        &advert,
                        persist,
                    )
                    .await;
                    let _ = reply.send(res);
                });
            }
            Command::StopServe { share_id, reply } => {
                // De-register from BOTH the serve registry (inbound fetch
                // app_calls for it are no longer answered) and the advert set (a
                // RouteChanged will not re-publish a dead advert). The route blob
                // still routes to this node until released, but the share is
                // unserved — a holder of a stale route gets a not-found, never bytes.
                shares
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&share_id);
                share_adverts.remove(&share_id);
                // Release this share's current private route (route-leak fix): once
                // unpublished it serves nothing, so the route is dead weight.
                release_any_advert_route(
                    &api,
                    &advert_routes,
                    &share_id,
                    &format!("stop_serve {share_id}"),
                );
                let _ = reply.send(Ok(()));
            }
            Command::RouteMaintenance { dead_routes } => {
                // Refresh ONLY if a route we currently advertise is in the dead
                // set. Veilid reports a route in `dead_routes` when it dies OR
                // when we release it — and every advert re-publish releases its
                // previous route AFTER swapping the map to the new one, so a
                // self-inflicted release never matches here. Without this filter
                // the actor's own releases re-armed refresh forever: an endless
                // refresh→release→RouteChange→refresh storm re-publishing a 12KB
                // envelope every coalesce window (2026-07-02 felt-test log).
                let relevant = {
                    let routes = advert_routes.lock().unwrap();
                    dead_routes.iter().any(|d| routes.values().any(|r| r == d))
                };
                // Always trace: correlating route churn against a fetch wave's
                // serve/reply timing is the latency-kill vs rotation-kill
                // discriminator a felt-test log needs.
                crate::vtrace!(
                    "route_maintenance: {} dead route(s), relevant={relevant}",
                    dead_routes.len()
                );
                if !relevant {
                    continue;
                }
                // Coalesce + spawn the refresh (shared with the #124 watchdog). Skips
                // if a refresh is in flight or one completed within the interval; the
                // refresh is SPAWNED so re-allocating a route per advert never blocks
                // the loop for the whole wave (head-of-line).
                if spawn_refresh_if_due(
                    &api,
                    &sched,
                    &advert_routes,
                    &share_adverts,
                    &refresh_in_flight,
                    &last_advert_refresh,
                ) {
                    // (#180 §RS-3, CRSH-ISC-10d) A refresh is scheduled: drop the now-dead
                    // entries by value so the spawned re-publish inserts a fresh route with
                    // no stale prev to release — removing the most common source of the
                    // benign `InvalidArgument` rather than merely silencing it. Compare-by-
                    // value leaves a concurrent reshare's own live route untouched. Deferred
                    // to the scheduled branch: dropping when the gate is busy would blind the
                    // redelivery's relevance re-check and strand a genuinely dead advert.
                    let dropped = drop_dead_advert_routes(&advert_routes, &dead_routes);
                    if dropped > 0 {
                        crate::vtrace!(
                            "route_maintenance: dropped {dropped} dead advert-route entry(ies)"
                        );
                    }
                } else {
                    // A relevant death is ONE-SHOT under the filter, so a busy
                    // gate (refresh in flight, or inside the coalesce window)
                    // must not consume it silently: re-deliver the same command
                    // after the window. Relevance is re-checked on arrival, so
                    // once a refresh has replaced the dead route the redelivery
                    // is a quiet no-op and the cycle stops.
                    crate::vtrace!("route_maintenance: gate busy, re-arming redelivery");
                    let cmd_weak = cmd_weak.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(ADVERT_REFRESH_MIN_INTERVAL).await;
                        if let Some(tx) = cmd_weak.upgrade() {
                            let _ = tx.send(Command::RouteMaintenance { dead_routes }).await;
                        }
                    });
                }
            }
            Command::ReleaseRoute { route_id } => {
                // (#180 §RS-3, CRSH-ISC-10) Consumer-side release of an imported route the
                // frontend's in-use guard cleared (superseded advert + no in-flight fetch).
                release_tolerant(&api, route_id, "consumer release");
            }
            Command::AdvertWatchdog => {
                // The silently-dead-route recovery path (#124): re-publish IDLE adverts
                // on a slow timer to recover a route that died without an observed
                // `dead_routes`. Rotating a route (`publish_one_advert` allocates a new
                // one + releases the old) would kill an active download's imported
                // route mid-transfer, so a share that served a fetch within
                // SERVE_RECENCY_WINDOW is skipped — a live download keeps its route
                // stamped fresh and is never disturbed (xhigh review). No busy-gate
                // re-delivery (the next tick is the retry); the shared coalesce gate
                // makes a tick just after a real refresh a quiet no-op, so the cadence
                // never approaches the refresh storm the RouteMaintenance filter closed.
                let now = std::time::Instant::now();
                let idle: HashMap<String, AdvertState> = {
                    let served = shares
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    share_adverts
                        .iter()
                        .filter(|(id, _)| {
                            served.get(*id).is_none_or(|s| {
                                now.duration_since(s.last_served()) >= SERVE_RECENCY_WINDOW
                            })
                        })
                        .map(|(id, st)| (id.clone(), st.clone()))
                        .collect()
                };
                if !idle.is_empty()
                    && spawn_refresh_if_due(
                        &api,
                        &sched,
                        &advert_routes,
                        &idle,
                        &refresh_in_flight,
                        &last_advert_refresh,
                    )
                {
                    crate::vtrace!("advert_watchdog: refreshing {} idle advert(s)", idle.len());
                }
            }
            Command::Shutdown {
                flush_budget,
                reply,
            } => {
                // I7: flush pending chat writes + leave tombstones + share withdraws
                // within the caller's remaining close budget, shed class-3/4/5
                // current-state writes, THEN tear the node down — a locally-echoed chat
                // silently dropped at close is data loss the sender already saw as sent.
                sched.shutdown(flush_budget).await;
                // Capped: the caller is blocking a UI thread on the reply below, and
                // veilid's teardown is otherwise an unbounded await past every budget.
                let _ = tokio::time::timeout(TEARDOWN_CAP, api.shutdown()).await;
                let _ = reply.send(());
                return;
            }
        }
    }
    // Channel closed without an explicit Shutdown — clean up the node.
    api.shutdown().await;
}

/// The dedicated serve task: answers inbound fetch `app_call`s against the
/// served-share registry, on its OWN lane — never the actor command channel.
/// veilid holds an inbound call's answer window open for only `rpc.timeout_ms`
/// (5s default) from the moment it fires the update callback; a reply after
/// that is dropped as "Unmatched operation id" and the fetcher times out. The
/// command FIFO cannot guarantee that budget — one inline chat publish
/// (open_or_create + DHT set) parks everything behind it for seconds — so
/// serve requests bypass it entirely (2026-07-02 root cause; the earlier
/// reply-spawn fix moved latency off the reply await but not off the queue).
/// The serve step itself runs on a blocking thread, never on this task: since
/// #246 a served share reads its chunk from disk at answer time
/// (`DiskShareContent`), so the map lookup + read + seal is real blocking I/O
/// plus CPU, and ISC-A-C35 requires every per-chunk disk read to run on a
/// blocking thread. The registry lock is taken and released inside that blocking
/// step — never held across the reply await, and never held on a runtime worker
/// during the disk read (which would also stall the actor's own
/// `ServeShare`/`StopServe` locks and the advert watchdog's `last_served` read).
/// The bytes to reply with once the blocking serve step has completed or failed.
///
/// A [`tokio::task::JoinError`] means the step itself panicked, and the answer is
/// `NOT_FOUND` — the offline-equivalent (ISC-A-S21) — rather than leaving the
/// fetcher to burn its five-second answer window on a reply that will never come.
///
/// **Factored out of [`serve_loop`] so the panic arm is reachable (#248).** In the
/// loop it sits behind a live `VeilidAPI`, so nothing could drive it; as a
/// function taking the join result, a test hands it a real `JoinError` from a
/// genuinely panicking task. That arm is the actor's only defence against a
/// panicking serve step, and a regression in it strands fetchers rather than
/// failing anything loudly.
fn serve_response_or_not_found(
    outcome: std::result::Result<Vec<u8>, tokio::task::JoinError>,
) -> Vec<u8> {
    match outcome {
        Ok(response) => response,
        Err(e) => {
            crate::vtrace!("serve: blocking serve step failed ({e}); replying NOT_FOUND");
            share::encode_response_not_found()
        }
    }
}

async fn serve_loop(
    api: VeilidAPI,
    shares: Arc<Mutex<HashMap<String, share::ServedShare>>>,
    mut serve_rx: mpsc::Receiver<(OperationId, Vec<u8>, std::time::Instant)>,
) {
    // veilid's default answer window (`rpc.timeout_ms`): a reply after this is
    // rejected as "Unmatched operation id", so serving an older entry is pure
    // wasted seal + network work that only deepens a backlog.
    const SERVE_ANSWER_WINDOW: Duration = Duration::from_secs(5);
    // Cap concurrent app_call_reply tasks (#125): a fetch burst must not spawn
    // unbounded reply tasks, each holding a sealed response across a slow network
    // send. Acquiring the permit BEFORE sealing means we never seal work we can't yet
    // send, and a permit-starved reply awaits — deliberate backpressure that pairs
    // with the bounded+shed intake channel to bound the whole serve lane.
    let reply_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SERVE_REPLIES));
    while let Some((call_id, message, received)) = serve_rx.recv().await {
        let queued_ms = received.elapsed().as_millis();
        if received.elapsed() > SERVE_ANSWER_WINDOW {
            crate::vtrace!("serve: EXPIRED after {queued_ms}ms in queue, dropped");
            continue;
        }
        // Reserve a reply slot before doing any seal work; held on the spawned task
        // across app_call_reply. `acquire_owned` errors only on a closed semaphore,
        // which never happens here (it lives for the loop).
        let permit = reply_sem
            .clone()
            .acquire_owned()
            .await
            .expect("serve reply semaphore is never closed");
        // Re-check expiry AFTER the permit wait: acquiring can block seconds when all
        // permits are held (the exact latency spike #125 targets), so an entry that
        // passed the dequeue check may have aged past the window while waiting. Sealing
        // + sending it would be pure wasted work the reply lands too late for (xhigh
        // review). The permit drops here on `continue`.
        if received.elapsed() > SERVE_ANSWER_WINDOW {
            crate::vtrace!(
                "serve: EXPIRED after {}ms (post-permit), dropped",
                received.elapsed().as_millis()
            );
            continue;
        }
        // Serve on a blocking thread (ISC-A-C35): a disk-backed share reads its
        // chunk from the filesystem here, and that must not run on a runtime
        // worker. Recover the guard if another holder panicked: a poisoned
        // registry must not cascade into the actor's later ServeShare/StopServe
        // locks. A JoinError means the blocking step itself panicked — reply
        // NOT_FOUND (the offline-equivalent, ISC-A-S21) rather than leaving the
        // fetcher to burn its answer window on a reply that will never come.
        let seal_started = std::time::Instant::now();
        let serve_shares = shares.clone();
        let response = serve_response_or_not_found(
            tokio::task::spawn_blocking(move || {
                let mut s = serve_shares
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                share::serve(&mut s, &message)
            })
            .await,
        );
        let seal_ms = seal_started.elapsed().as_millis();
        // Reply on a spawned task: awaiting `app_call_reply` inline serializes
        // the lane at whatever per-reply latency the network imposes (observed
        // ~4.6s per call, cause not yet pinned). queued / seal / reply are
        // timed separately so a slow felt-test log names the stage to blame.
        let api = api.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this reply task ends
            let started = std::time::Instant::now();
            let result = api.app_call_reply(call_id, response).await;
            let reply_ms = started.elapsed().as_millis();
            match result {
                Err(e) => crate::vtrace!(
                    "serve: reply failed (queued {queued_ms}ms, seal {seal_ms}ms, reply {reply_ms}ms) ({e})"
                ),
                Ok(()) if queued_ms + seal_ms + reply_ms > 1_000 => crate::vtrace!(
                    "serve: SLOW reply delivered (queued {queued_ms}ms, seal {seal_ms}ms, reply {reply_ms}ms)"
                ),
                Ok(()) => {}
            }
        });
    }
}

/// Open/create the rendezvous record (a circle's, or a public room's / lobby's)
/// and write `sealed` into this node's append-ring slot, advancing the local
/// cursor. Identical for every consumer — only the caller's `owner_seed` differs.
// All nine parameters are distinct threaded actor state (the gate, three shared caches,
// the node id, the owner seed, and the payload); bundling them into a struct would only
// move the coupling, not remove it, on a single private helper.
#[allow(clippy::too_many_arguments)]
async fn publish_rendezvous(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    node_pub: &[u8; 32],
    ring_seq: &Mutex<HashMap<RecordKey, u32>>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
    sealed: Vec<u8>,
) -> Result<()> {
    crate::vtrace!("publish_rendezvous: open (cached) rendezvous");
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Serialize the whole open + seq-bump + write for THIS record: a spawned publish
    // for a later ring seq must not race an earlier one into the shared 2-slot ring
    // and lose the newer message (#128 xhigh review). Distinct records take distinct
    // locks and stay concurrent, so this never blocks another record or the loop.
    let record_lock = rendezvous::record_lock(record_locks, &owner.key());
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner.key(), rendezvous::RecordShape::RENDEZVOUS),
        rendezvous::open_or_create(gate, api, rc, &owner, rendezvous::RecordShape::RENDEZVOUS),
    )
    .await?;
    let key = handle.key().clone();
    let base = rendezvous::member_base_subkey(node_pub);
    // Lock only for the synchronous cursor bump — never across an await — so the
    // main loop and a spawned refresh can interleave ring writes safely.
    let seq = {
        // Side-step std-Mutex poisoning: a panic in another dispatch task must not
        // wedge every subsequent ring write (#168 — the panic-wedge cascade). The
        // cursor map is plain data; recover the guard and carry on.
        let mut seqs = ring_seq.lock().unwrap_or_else(|e| e.into_inner());
        let cur = seqs.entry(key.clone()).or_insert(0);
        let s = *cur;
        *cur = cur.wrapping_add(1);
        s
    };
    crate::vtrace!("publish_rendezvous: key={key:?} ring base={base} seq={seq}");
    let started = std::time::Instant::now();
    let r = rendezvous::publish(rc, &handle, &owner, base, seq, sealed).await;
    // Runs on a spawned task off the actor command loop (D-0b, #128), so a slow
    // write never becomes queue latency for the commands behind it.
    crate::vtrace!(
        "publish_rendezvous: write {} in {}ms",
        if r.is_ok() { "ok" } else { "ERR" },
        started.elapsed().as_millis()
    );
    r
}

/// Open/create the rendezvous record and write `sealed` to the stable-identity slot
/// for `stable_id` — the **current-state** (Shape B) publish. Re-publishing the same
/// `stable_id` overwrites in place (last-writer-wins), so a share's dead-route advert
/// never orphans across a restart (#118) and a withdraw cancels it in the same slot.
/// The public-share advert path uses this; circles / lobby-chat keep the append-ring.
// Distinct threaded actor state (the gate, two shared caches, the owner seed, the
// stable id, and the payload); bundling them would move the coupling, not remove it.
#[allow(clippy::too_many_arguments)]
async fn publish_current_state(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
    stable_id: &str,
    sealed: Vec<u8>,
) -> Result<()> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Single-flight the record open and serialize the write against concurrent
    // same-record ops (chat publishes, other adverts) — see rendezvous::record_lock.
    let record_lock = rendezvous::record_lock(record_locks, &owner.key());
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner.key(), rendezvous::RecordShape::RENDEZVOUS),
        rendezvous::open_or_create(gate, api, rc, &owner, rendezvous::RecordShape::RENDEZVOUS),
    )
    .await?;
    let subkey = rendezvous::current_state_subkey(stable_id);
    crate::vtrace!(
        "publish_current_state: stable_id={stable_id} key={:?} subkey={subkey}",
        handle.key()
    );
    rendezvous::publish_at_subkey(rc, &handle, &owner, subkey, sealed).await
}

/// The dispatch token the write scheduler carries per queued write, matched by the
/// [`ProductionSink`] onto the existing per-record write function. The scheduler
/// treats it opaquely; only the sink interprets it, so #131 / ring-seq-inside-
/// `record_lock` stay where they are (inside these two functions, at dispatch time).
enum ProdWrite {
    /// An append-ring (chat / room / circle) write → [`publish_rendezvous`].
    Rendezvous {
        owner_seed: [u8; 32],
        sealed: Vec<u8>,
    },
    /// A current-state (presence beacon / MOTD / share advert) write →
    /// [`publish_current_state`].
    CurrentState {
        owner_seed: [u8; 32],
        stable_id: String,
        sealed: Vec<u8>,
    },
    /// A DM key-record write → [`publish_dm_key_record`]. Its own variant rather
    /// than a `CurrentState` because the record has a different SHAPE (`dflt(1)`,
    /// not `dflt(64)`) and a fixed slot, and shape is part of the record address —
    /// routing it through the `dflt(64)` path would address a different record.
    DmKeyRecord {
        owner_seed: [u8; 32],
        record: Vec<u8>,
    },
    /// A DM channel-page write → [`publish_dm_page`]. Its own variant for the same
    /// reason as [`ProdWrite::DmKeyRecord`] — the page is `dflt(16)`, a third shape
    /// again, and shape is part of the record address — plus a second one: the slot
    /// is derived from the message's sequence number, so unlike a current-state
    /// write it is neither a fixed slot nor a hashed one.
    ///
    /// The only variant carrying a typed address: a page's owner seed is the
    /// conversation secret, so it rides inside the zeroizing [`DmPageAddress`] and
    /// not as a `Copy` array duplicated through the pending queue (#244). The
    /// address also keeps the seed bound to its page, its slot and its stream for
    /// the length of the queue, so nothing in flight can drift onto another page's
    /// record (#254, #269). The scheduler's `D: Send + 'static` bound is satisfied structurally —
    /// the address is a `Box<[u8; 32]>`, a `u64`, a `Direction` and a zero-sized
    /// marker, all of which are both — and is enforced by the compiler at
    /// `WriteScheduler::spawn_with_probe::<ProdWrite>`.
    DmPage {
        address: DmPageAddress<Sending>,
        frame: Vec<u8>,
    },
    /// A DM doorbell first-contact write -> [`publish_doorbell_entry`]. Its own
    /// variant for the reason [`ProdWrite::DmKeyRecord`] gives: the doorbell is
    /// `dflt(32)`, a fourth shape again, and shape is part of the record address,
    /// so routing it down any of the other three paths would address a different
    /// record. Plus a second reason, shared with [`ProdWrite::DmPage`]: the slot is
    /// supplied by the caller (`doorbell::slot_for`), so it is neither a fixed slot
    /// like the key record's nor a hashed one like a current-state beacon's.
    ///
    /// The seed rides as a plain `[u8; 32]` rather than inside a zeroizing type,
    /// unlike [`ProdWrite::DmPage`]'s address, and that is correct rather than an
    /// omission. A doorbell owner seed is derived from the recipient's PUBLIC
    /// identity key: everyone who can address the doorbell can already compute it,
    /// so it is not a secret and there is nothing for zeroize-on-drop to protect.
    /// This is exactly the reasoning [`ProdWrite::DmKeyRecord`] rests on, and the
    /// distinction #244 draws — a page's owner seed IS the conversation's write
    /// capability, a doorbell's confers only what the world already has.
    DoorbellEntry {
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
    },
    /// A DM acknowledgement write → [`publish_dm_ack`]. Its own variant for the
    /// reason [`ProdWrite::DmKeyRecord`] gives: shape is part of the record
    /// address, so routing it down another surface's path would address a
    /// different record. It shares the key record's `dflt(1)` today, which is
    /// exactly why the two must not share a path — the coincidence is in the slot
    /// count, not in the address.
    ///
    /// The second variant carrying a typed address, and for the same reason
    /// [`ProdWrite::DmPage`] does: an acknowledgement record's owner seed derives
    /// from `AR`, so under Veilid holding it is write access to the conversation's
    /// acknowledgement record. It rides inside the zeroizing [`DmAckAddress`]
    /// rather than as a `Copy` array duplicated through the pending queue (#244),
    /// and the address keeps the seed bound to the direction it was derived for
    /// for the length of the queue. The scheduler's `D: Send + 'static` bound is
    /// satisfied structurally — the address is a `Box<[u8; 32]>` and a
    /// `Direction`, both of which are — and is enforced by the compiler at
    /// `WriteScheduler::spawn_with_probe::<ProdWrite>`.
    DmAck {
        address: DmAckAddress,
        record: Vec<u8>,
    },
}

/// The production [`WriteSink`] (WB-3.I1): the funnel's dispatch end. Holds the same
/// shared caches the actor loop and the read paths share (`ring_seq`, `opened`,
/// `record_locks`), so a scheduled write serializes against a concurrent same-record
/// subscribe/resweep exactly as before. Every `set_dht_value` in the crate reaches
/// the network only through here, called by the scheduler task.
struct ProductionSink {
    api: VeilidAPI,
    rc: RoutingContext,
    node_pub: [u8; 32],
    // Per-record append-ring cursor — the seq bump happens INSIDE `record_lock` at
    // dispatch (`publish_rendezvous`), never at enqueue (#131 / I2 / I13 untouched).
    ring_seq: Arc<Mutex<HashMap<RecordKey, u32>>>,
    opened: Arc<rendezvous::OpenCache>,
    // LRU recency over the DM-page subset of `opened` (#252). Shared with the read
    // paths for the same reason `opened` is: the page a sweep opened and the page a
    // write reuses must be one entry in one ring, or the bound counts each path's
    // opens separately and neither closes the other's.
    page_recency: Arc<rendezvous::DmPageRecency>,
    record_locks: Arc<rendezvous::RecordLocks>,
    // The shared four-pool DHT permit accountant (WB-5.1 / I5″.1). Every write acquires
    // a permit from its lane's pool here before touching the DHT; the read lane draws
    // its own pool, so daemonseed's combined in-flight DHT ops are provably ≤ the
    // budget. The measured acquire-wait is trace-only telemetry (WB-ISC-27) — the
    // §I5′.2 window controller that consumed it is retired.
    gate: Arc<DhtGate>,
}

impl WriteSink for ProductionSink {
    type Item = ProdWrite;

    fn dispatch(&self, item: ProdWrite, lane: DispatchLane) -> DispatchFuture {
        let api = self.api.clone();
        let rc = self.rc.clone();
        let node_pub = self.node_pub;
        let ring_seq = self.ring_seq.clone();
        let opened = self.opened.clone();
        let page_recency = self.page_recency.clone();
        let record_locks = self.record_locks.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            // WB-5.1 / I5″.1: acquire the matching DHT-gate pool before touching the
            // network — chat draws the chat pool (never waits on non-chat), floor the
            // 1-permit floor pool, window the W_max pool. No cross-pool fallback. The
            // permit is an RAII guard held across the whole write, so it releases even on
            // a panic-unwind (#168). This write path issues NO gated GET (single-permit
            // rule, WB-ISC-28): it only opens (un-gated/margin) + sets.
            let permit = match lane {
                DispatchLane::Chat => gate.acquire_chat().await,
                DispatchLane::Floor => gate.acquire_floor().await,
                DispatchLane::Window => gate.acquire_write().await,
            };
            let acquire_wait = Some(permit.acquire_wait);
            let result = match item {
                ProdWrite::Rendezvous { owner_seed, sealed } => {
                    publish_rendezvous(
                        &gate,
                        &api,
                        &rc,
                        &node_pub,
                        &ring_seq,
                        &opened,
                        &record_locks,
                        owner_seed,
                        sealed,
                    )
                    .await
                }
                ProdWrite::CurrentState {
                    owner_seed,
                    stable_id,
                    sealed,
                } => {
                    publish_current_state(
                        &gate,
                        &api,
                        &rc,
                        &opened,
                        &record_locks,
                        owner_seed,
                        &stable_id,
                        sealed,
                    )
                    .await
                }
                ProdWrite::DmKeyRecord { owner_seed, record } => {
                    publish_dm_key_record(
                        &gate,
                        &api,
                        &rc,
                        &opened,
                        &record_locks,
                        owner_seed,
                        record,
                    )
                    .await
                }
                ProdWrite::DmPage { address, frame } => {
                    // Borrowed, not moved: the binding is dropped — and therefore
                    // zeroized — at the end of this arm, so the conversation secret
                    // lives no longer than the write it authorises (#244).
                    publish_dm_page(
                        &gate,
                        &api,
                        &rc,
                        &opened,
                        &page_recency,
                        &record_locks,
                        &address,
                        frame,
                    )
                    .await
                }
                ProdWrite::DoorbellEntry {
                    owner_seed,
                    slot,
                    entry,
                } => {
                    publish_doorbell_entry(
                        &gate,
                        &api,
                        &rc,
                        &opened,
                        &record_locks,
                        owner_seed,
                        slot,
                        entry,
                    )
                    .await
                }
                ProdWrite::DmAck { address, record } => {
                    // Borrowed, not moved, exactly as `DmPage` is: the binding is
                    // dropped — and therefore zeroized — at the end of this arm, so
                    // the conversation secret lives no longer than the write it
                    // authorises (#244).
                    publish_dm_ack(&gate, &api, &rc, &opened, &record_locks, &address, record).await
                }
            };
            drop(permit);
            DispatchOutcome {
                result,
                acquire_wait,
            }
        })
    }
}

/// The DM key record's schema: `dflt(1)`, one slot, the full 32 KiB per-subkey cap.
/// Part of the record ADDRESS — every participant must derive with this shape or
/// they compute a different record (`docs/design/direct-messaging.md` DRAFT v6).
const DM_KEY_RECORD_SHAPE: rendezvous::RecordShape = rendezvous::RecordShape::DM_KEY_RECORD;

/// The only slot in the key record.
const DM_KEY_RECORD_SUBKEY: u32 = 0;

/// Publish a signed DM key record to subkey 0 of its `dflt(1)` record (ISC-C40).
///
/// `record` is opaque here: this layer never parses or verifies it. Verification
/// needs the identity public key the address was derived from, which only the
/// caller holds, and putting a second verification point here would create a
/// second place for the rule to drift.
///
/// The record is world-writable by construction (a world-derivable address implies
/// a world-derivable owner), so this write can be overwritten or erased by anyone.
/// That is the accepted, DoS-only residual — forgery is impossible because the
/// signature inside is checked against the address's own identity key — and it is
/// why the caller re-seeds on a slow schedule.
async fn publish_dm_key_record(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
    record: Vec<u8>,
) -> Result<()> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Single-flight the open and serialize against any concurrent op on this record,
    // exactly as the rendezvous write paths do (CRSH-ISC-3).
    let record_lock = rendezvous::record_lock(record_locks, &owner.key());
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner.key(), DM_KEY_RECORD_SHAPE),
        rendezvous::open_or_create(gate, api, rc, &owner, DM_KEY_RECORD_SHAPE),
    )
    .await?;
    crate::vtrace!(
        "publish_dm_key_record: key={:?} bytes={}",
        handle.key(),
        record.len()
    );
    rendezvous::publish_at_subkey(rc, &handle, &owner, DM_KEY_RECORD_SUBKEY, record).await
}

/// Fetch a correspondent's DM key record from subkey 0 of its `dflt(1)` record.
///
/// Returns `Ok(None)` for an empty slot — evicted, wiped, or never published —
/// which is a real and expected state for a world-writable record, and which the
/// caller surfaces as *awaiting-key* and retries. It is deliberately distinct from
/// `Err`, a transport failure: conflating them would make an attacker's wipe look
/// like a network problem and vice versa.
///
/// The bytes come back UNVERIFIED. Only `daemonseed_core::dm::keyrec::verify` may
/// decide a record is genuine, and it needs the identity pubkey this layer does
/// not have.
async fn fetch_dm_key_record(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
) -> Result<Option<Vec<u8>>> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // The open is serialized under the record lock; the GET is NOT, so a slow read
    // never blocks a concurrent write to the same record. The lock guard is dropped
    // before the read permit is acquired, which also keeps the single-permit rule
    // (CRSH-ISC-17): no un-gated-op permit is held while acquiring a read permit.
    let handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner.key());
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &rendezvous::cached_record_id(&owner.key(), DM_KEY_RECORD_SHAPE),
            rendezvous::open_or_create(gate, api, rc, &owner, DM_KEY_RECORD_SHAPE),
        )
        .await?
    };
    // Read lane (WB-5.1 / I5″.2): one read permit around the one GET.
    let got = {
        let _read_permit = gate.acquire_read().await;
        rc.get_dht_value(handle.key().clone(), DM_KEY_RECORD_SUBKEY, true)
            .await
    };
    match got {
        Ok(Some(v)) => Ok(Some(v.data().to_vec())),
        Ok(None) => {
            crate::vtrace!("fetch_dm_key_record: slot empty (evicted, wiped, or never published)");
            Ok(None)
        }
        Err(e) => Err(VeilidNetError::Routing(e.to_string())),
    }
}

/// The DM acknowledgement record's schema: `dflt(1)`, one current-state slot.
/// Part of the record ADDRESS — every participant must derive with this shape or
/// they compute a different record (`docs/design/direct-messaging.md` DRAFT v6).
const DM_ACK_SHAPE: rendezvous::RecordShape = rendezvous::RecordShape::DM_ACK;

/// The only slot in an acknowledgement record.
const DM_ACK_SUBKEY: u32 = 0;

/// Publish a sealed acknowledgement to subkey 0 of its `dflt(1)` record
/// (ISC-C39).
///
/// `record` is opaque here: this layer never opens or verifies it. Opening needs
/// the conversation's address root and verification the correspondent's pseudonym
/// key, neither of which this layer holds, and a second verification point would
/// be a second place for the rule to drift.
///
/// Unlike the key record and the doorbell, this record is **owner-write-gated**:
/// the owner seed derives from the conversation's secret address root, so only the
/// two parties can write here and neither erasure nor forgery by a third party is
/// available. The residual is the peer itself, and a peer's claim is bounded where
/// it is merged, not here.
async fn publish_dm_ack(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    address: &DmAckAddress,
    record: Vec<u8>,
) -> Result<()> {
    let owner = identity::rendezvous_owner_keypair(address.owner_seed().as_bytes())?;
    // Single-flight the open and serialize against any concurrent op on this record,
    // exactly as the key-record and rendezvous write paths do (CRSH-ISC-3).
    let record_lock = rendezvous::record_lock(record_locks, &owner.key());
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner.key(), DM_ACK_SHAPE),
        rendezvous::open_or_create(gate, api, rc, &owner, DM_ACK_SHAPE),
    )
    .await?;
    crate::vtrace!(
        "publish_dm_ack: key={:?} bytes={}",
        handle.key(),
        record.len()
    );
    rendezvous::publish_at_subkey(rc, &handle, &owner, DM_ACK_SUBKEY, record).await
}

/// Fetch a correspondent's acknowledgement from subkey 0 of its `dflt(1)` record.
///
/// Returns `Ok(None)` for an empty slot — evicted, or never written because the
/// peer has settled nothing — which is a real and expected state and which the
/// caller treats as *no confirmation yet*. It is deliberately distinct from `Err`,
/// a transport failure: under a fail-safe delivery posture, conflating the two
/// would let a network fault be read as an absence of confirmation and vice versa.
///
/// The bytes come back UNVERIFIED. Only
/// `daemonseed_core::dm::ack_record::decode_and_verify` may open them, and even
/// its result answers nothing until it has been merged under the caller's own
/// ceiling.
async fn fetch_dm_ack(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    address: &DmAckAddress,
) -> Result<Option<Vec<u8>>> {
    let owner = identity::rendezvous_owner_keypair(address.owner_seed().as_bytes())?;
    // The open is serialized under the record lock; the GET is NOT, so a slow read
    // never blocks a concurrent write to the same record. The lock guard is dropped
    // before the read permit is acquired, which also keeps the single-permit rule
    // (CRSH-ISC-17): no un-gated-op permit is held while acquiring a read permit.
    let handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner.key());
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &rendezvous::cached_record_id(&owner.key(), DM_ACK_SHAPE),
            rendezvous::open_or_create(gate, api, rc, &owner, DM_ACK_SHAPE),
        )
        .await?
    };
    // Read lane (WB-5.1 / I5″.2): one read permit around the one GET.
    let got = {
        let _read_permit = gate.acquire_read().await;
        rc.get_dht_value(handle.key().clone(), DM_ACK_SUBKEY, true)
            .await
    };
    match got {
        Ok(Some(v)) => Ok(Some(v.data().to_vec())),
        Ok(None) => {
            crate::vtrace!("fetch_dm_ack: slot empty (evicted or never written)");
            Ok(None)
        }
        Err(e) => Err(VeilidNetError::Routing(e.to_string())),
    }
}

/// The DM channel page's schema: `dflt(16)`, one subkey per message slot.
/// Part of the record ADDRESS, and simultaneously the modulus of the slot
/// arithmetic — hence derived from `paging::PAGE_SLOTS` rather than typed here
/// (`ISA.md` ISC-C100; sizing in `docs/design/direct-messaging.md` DRAFT v6).
const DM_PAGE_SHAPE: rendezvous::RecordShape = rendezvous::RecordShape::DM_PAGE;

/// Refuse a page record whose subkey count is not the page slot count, **in both
/// directions** (#254).
///
/// Checked before a single slot is read, because only one of the two directions is
/// visible afterwards. A record with MORE subkeys than a page holds yields slot
/// indices that will not place, and `dm_page_position_of_slot` reports them. A
/// record with FEWER yields no unplaceable slot at all — the sweep is bounded by the
/// record's own `o_cnt`, so every position places, the missing slots are simply
/// never attempted, and the caller gets `Ok` with a silently truncated page. That is
/// the lost-message-under-an-`Ok` outcome the whole placement check exists to
/// prevent, reached from the side nothing downstream can see.
fn dm_page_shape_must_match(page: u64, o_cnt: u16) -> Result<()> {
    if o_cnt != daemonseed_core::dm::paging::PAGE_SLOTS {
        return Err(VeilidNetError::DmPageShapeMismatch { page, o_cnt });
    }
    Ok(())
}

/// Turn one swept subkey into the [`PagePosition`] it holds on `page`.
///
/// The checked slot-to-sequence direction, applied at the transport boundary so no
/// caller does the arithmetic. `page` comes from the swept address, which refused
/// anything above `MAX_PAGE` at construction, so the only way this fails is a slot
/// the record cannot hold — a shape whose `o_cnt` disagrees with `PAGE_SLOTS`
/// (ISC-C100), reported rather than skipped because a skipped slot is a message
/// silently missing from an `Ok` page.
fn dm_page_position_of_slot(page: u64, slot: u32) -> Result<PagePosition> {
    u16::try_from(slot)
        .ok()
        .and_then(|slot| PagePosition::new(page, slot))
        .ok_or(VeilidNetError::DmPageSlotOutsideRecord { page, slot })
}

/// Place every swept subkey on the page **the address names**, so a collector
/// receives positions rather than indices.
///
/// **It takes the address, not a page number, and that is the whole reason it
/// exists.** The placement used to happen inline in [`sweep_dm_page`], which cannot
/// run without a live DHT — so the page argument at that call site was reachable by
/// no test, and replacing it with a literal `0` left every runnable test AND both
/// `#[ignore]`d two-node tests green while giving every frame on every page a page-0
/// sequence number. `ParsedFrame::open`'s found-at check would then have rejected
/// every message on page 1 and above as tampered. Reading the page off the address
/// inside a function a unit test can call is what makes that mutation visible.
fn dm_page_place_swept(
    address: &DmPageAddress<Receiving>,
    raw: Vec<(u32, Vec<u8>)>,
) -> Result<Vec<(PagePosition, Vec<u8>)>> {
    raw.into_iter()
        .map(|(subkey, bytes)| {
            dm_page_position_of_slot(address.page(), subkey).map(|at| (at, bytes))
        })
        .collect()
}

/// The funnel's FIFO and coalescing scope for a record: the owner's **public
/// key**, never the seed (#244, #256).
///
/// **One function so the keyspace cannot go heterogeneous by copy-paste.** The
/// scope needs *injectivity*, not the secret. The public key supplies it at least
/// as precisely — it is what the record's DHT address derives from, so two seeds
/// sharing a public key would be one record and belong in one queue anyway — and
/// it is a total 32-byte function of the seed (VLD0 is Ed25519), so it fits
/// `schedule::RecordId` with no fallible step on the enqueue path.
///
/// The mapping is **injective** — not bijective, since Ed25519 derivation clamps
/// and the image is not all of `[u8; 32]`, but surjectivity is never what the
/// argument uses — so re-keying an existing class changes no coalescing group:
/// every request that shared a key still shares one, and every request that did
/// not still does not. That is what makes this safe to apply to the live chat,
/// presence and advert paths rather than only to new ones.
///
/// **Injectivity alone is not the whole safety argument, and the missing premise
/// is the one a future enqueue site could break.** It preserves partitions
/// *within* a set that moves together, which is why all four seed-keyed sites had
/// to move in one change rather than one at a time. It says nothing about whether
/// the moved set now collides with the site that was already keyed on a public
/// key. It does not: DM page owner seeds derive under their own HKDF domain, so a
/// merge would require a page seed's public key to equal another class's raw
/// seed — a preimage coincidence, strictly harder than the seed equality the
/// pre-change keyspace needed. The change therefore cannot create a merge. A new
/// site keyed on a seed would reopen exactly that gap, which is what the
/// source-level probe in this module's tests is for.
///
/// The hazard it removes is specific. `WriteRequest.record` is both the FIFO
/// ordering scope and the coalescing scope, so a new enqueue site keyed on the
/// seed while its neighbour keys on the public key would **split one record's
/// FIFO into two queues** — per-record single-flight and write ordering both
/// lost, with `Ok(())` on every surface.
fn funnel_record_key(owner_seed: &[u8; 32]) -> [u8; 32] {
    identity::rendezvous_owner_public_bytes(owner_seed)
}

/// Build the funnel request for one channel-frame publish.
///
/// Class-1 `Chat`, `Ring` kind — never coalesced, never dropped (WB-ISC-11). A DM
/// is a circle with one other person, so its writes belong in the same lane as any
/// other typed message rather than behind the keepalives. `Ring` is the funnel's
/// name for "never coalesce", which is what a write-once page slot needs; the
/// dispatch token is its own [`ProdWrite`] variant, so nothing touches a
/// ring-sequence cursor despite the kind's name.
///
/// Coalescing would be actively wrong here, not merely wasteful: two queued writes
/// to the same page are two *different messages* in two different slots, and a
/// last-writer-wins collapse would silently drop one of them off the wire with its
/// `reply` reporting success.
///
/// Constructed here rather than inline in the [`Command::PublishDmPage`] arm so
/// that classification is reachable from a unit test. That is not tidiness: a
/// request built on the command loop can only be observed by a live two-node round
/// trip, and every mistake available here — a coalescible kind, the wrong lane, a
/// position mutated on the way to dispatch, a `record` set from the SEED rather
/// than the owner's public key — reports `Ok(())` on every local surface. The record
/// id is derived *inside* this function for exactly that reason: passing it in would
/// move the one decision worth pinning back out to the untestable call site.
fn dm_page_write_request(
    address: DmPageAddress<Sending>,
    frame: Vec<u8>,
    reply: oneshot::Sender<Result<()>>,
) -> WriteRequest<ProdWrite> {
    // Scope rationale lives on `funnel_record_key`; `RecordId` is opaque to the
    // scheduler, which only ever compares and hashes it.
    let record = address.with_owner_seed(funnel_record_key);
    WriteRequest {
        record,
        class: WriteClass::Chat,
        kind: WriteKind::Ring,
        deadline: None,
        item: ProdWrite::DmPage { address, frame },
        reply: Some(reply),
    }
}

/// An open page record and the lease that keeps it open. **The lease is not
/// optional bookkeeping:** it is what stops a concurrent page open evicting and
/// closing this record while the handle is still in use, so every caller binds it
/// for at least as long as it touches the handle. Dropping it says "done".
type OpenPage<'r> = (
    rendezvous::RendezvousHandle,
    rendezvous::PageLease<'r, rendezvous::CachedRecordId>,
);

/// What [`dm_page_open`] does when the page record is not on the network.
///
/// The distinction is the whole of #253: a publish is about to write the page, so
/// bringing it into being is the point; a sweep is a **read**, and the probe
/// frontier deliberately runs ahead of what exists, so creating there manufactures
/// empty records at the frontier and destroys the difference between "no such page"
/// and "page with nothing in it".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IfAbsent {
    /// Create the record and return it. The publish path, and the pre-open that
    /// warms the cache for it.
    Create,
    /// Leave the network alone and answer `Ok(None)`. The sweep path.
    ReportAbsent,
}

/// Open (or create) one channel page's record — the single opener both page
/// operations go through.
///
/// **One call site for the shape, and that is the whole point.** `o_cnt` is part of
/// the record ADDRESS, so a publish and a sweep naming different shapes would run
/// against two different records: the write succeeds, the sweep comes back empty,
/// and no surface anywhere reports an error (the ISC-C100 failure mode, reached by
/// a different door than a mistyped constant). Two independent opens is all it
/// takes for one bad edit to reintroduce that; with one, the disagreement is
/// unrepresentable rather than merely tested-against.
///
/// Locking is deliberately NOT folded in. [`publish_dm_page`] holds the record lock
/// across the open *and* the write, while [`sweep_dm_page`] drops it the moment the
/// open returns so its GETs never block a concurrent write to the same page
/// (CRSH-ISC-17). Only the open itself is common, so only the open is shared.
///
/// Whether an absent page record may be brought into being is the caller's to say,
/// and is the ONE thing that differs between the two paths (#253). It is a parameter
/// rather than a second function precisely so the shape argument above stays true:
/// splitting this into an open-for-publish and an open-for-sweep would give the page
/// shape constant two independent uses again, which is the arrangement the paragraph
/// above exists to rule out. (Named in prose rather than in code deliberately — the
/// guard test counts textual occurrences and cannot tell a mention from a use, and
/// that conservatism is worth keeping.)
///
/// **The page family is the one this engine bounds (#252).** Every other record it
/// serves has cardinality per circle or per correspondent; a page owner seed is new
/// every `PAGE_SLOTS` messages, per direction, per conversation, so an open-once
/// cache over pages grows with message count and never gives a record back. Because
/// this is the only path that opens one, recording the page id in `page_recency`
/// here bounds exactly the page subset and nothing else — the cache's shared entries
/// are never offered to the LRU, so their open-once behaviour is unchanged. See
/// `rendezvous::open_page_bounded`.
#[allow(clippy::too_many_arguments)]
async fn dm_page_open<'r>(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    page_recency: &'r rendezvous::DmPageRecency,
    record_locks: &rendezvous::RecordLocks,
    owner: &KeyPair,
    if_absent: IfAbsent,
) -> Result<Option<OpenPage<'r>>> {
    // Bound ONCE, and every use below goes through this binding. The two modes must
    // address the same record or they are two open sites wearing one name, and a
    // local makes that unrepresentable rather than merely reviewed — the cache id and
    // both opens cannot drift apart without editing this line.
    let shape = DM_PAGE_SHAPE;
    let id = rendezvous::cached_record_id(&owner.key(), shape);
    rendezvous::open_page_bounded(
        opened,
        page_recency,
        &id,
        rendezvous::DM_PAGE_CACHE_CAPACITY,
        // One future, both modes: an `async` block rather than two calls, so the
        // single-open-site property above survives the mode split.
        async {
            match if_absent {
                // `open_or_create` cannot answer "absent" — it opens, or creates and
                // reopens, or fails — so this is a widening to the common type, not a
                // fallback with a behaviour.
                IfAbsent::Create => rendezvous::open_or_create(gate, api, rc, owner, shape)
                    .await
                    .map(Some),
                IfAbsent::ReportAbsent => rendezvous::open_only(gate, api, rc, owner, shape).await,
            }
        },
        // The victim's own serialization lock. Every page open holds this same lock
        // across its open — all three callers take it before reaching here — so
        // holding it across the close is what stops an eviction killing a session a
        // concurrent opener has just established for the same record. `.0` is the
        // owner public key, which is what `record_lock` keys on.
        |evicted: rendezvous::CachedRecordId| rendezvous::record_lock(record_locks, &evicted.0),
        // Best-effort, exactly as the repair arm's close is: releasing a session
        // veilid has already GC'd is a benign race, and the eviction has dropped the
        // local entry either way. The key comes off the evicted handle itself, which
        // is what binds the close to the record that was actually removed.
        |evicted: rendezvous::RendezvousHandle| async move {
            if let Err(e) = rc.close_dht_record(evicted.into_key()).await {
                crate::vtrace!("dm page eviction: close_dht_record failed ({e})");
            }
        },
    )
    .await
}

/// Publish one sealed channel frame into one slot of one page (part of ISC-C42).
///
/// `frame` is opaque here, exactly as the key record is: this layer neither parses
/// nor verifies it. Authorship inside the pair comes from the frame's own
/// signature, checked by the collector — never from the fact that a write
/// succeeded. Both parties can derive the owner seed for *both* directions, so
/// reaching this function proves nothing about who wrote the bytes.
///
/// Unlike the key record, the page record is **not** world-writable: its owner seed
/// derives from the conversation's address root, which comes from the secret
/// encapsulated at first contact. A third party cannot compute the address at all,
/// which is why the ongoing channel needs no admission control.
#[allow(clippy::too_many_arguments)]
async fn publish_dm_page(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    page_recency: &rendezvous::DmPageRecency,
    record_locks: &rendezvous::RecordLocks,
    address: &DmPageAddress<Sending>,
    frame: Vec<u8>,
) -> Result<()> {
    // Borrowed: this needs to READ the seed once, to derive the signing keypair, and
    // has no reason to take ownership of a conversation secret (#244). The keypair
    // it produces DOES contain the seed — that is what a VLD0 secret is — and this
    // binding drops with the call. That does NOT bound the secret's lifetime:
    // handing the keypair to the open below makes veilid retain a clone in
    // `OpenedRecord.writer` for as long as the record stays open — which for a page
    // is until the open cache's page LRU evicts and closes it (#252). See
    // `identity::vld0_keypair`'s residual note.
    let owner = address.with_owner_seed(identity::rendezvous_owner_keypair)?;
    // Single-flight the open and serialize against any concurrent op on this record,
    // exactly as the rendezvous and key-record write paths do (CRSH-ISC-3). Two
    // messages landing in two slots of the same page is the ordinary case, so this
    // lock is contended by design and must not be skipped.
    let record_lock = rendezvous::record_lock(record_locks, &owner.key());
    let _write_guard = record_lock.lock().await;
    // `IfAbsent::Create` cannot answer `None` — it either opens, creates and
    // reopens, or fails — so the `ok_or_else` is unreachable rather than a fallback
    // with a behaviour. It is written as a hard error instead of an `expect` so a
    // future change to `dm_page_open` surfaces here as a reported failure on the
    // publish path rather than as a panic inside the actor loop.
    // `_lease` is held to the end of this function, which is what keeps a concurrent
    // page open from closing this record between here and the write below — the
    // record lock cannot do it, because it is taken on THIS page's owner key while an
    // eviction is triggered by a different page's.
    let (handle, _lease) = dm_page_open(
        gate,
        api,
        rc,
        opened,
        page_recency,
        record_locks,
        &owner,
        IfAbsent::Create,
    )
    .await?
    .ok_or_else(|| {
        VeilidNetError::Actor(
            "the page opener, in IfAbsent::Create mode, reported the page absent \
                 instead of creating it"
                .to_string(),
        )
    })?;
    // The subkey is read off the address's own position at the very last step, so
    // the page it belongs to travels bound to the slot for the whole path from the
    // public handle to here — and, since #269, in one value rather than two that
    // could drift apart.
    let at = address.at();
    let slot = u32::from(at.slot());
    crate::vtrace!(
        "publish_dm_page: key={:?} page={} slot={} bytes={}",
        handle.key(),
        at.page(),
        slot,
        frame.len()
    );
    rendezvous::publish_at_subkey(rc, &handle, &owner, slot, frame).await
}

/// Sweep one channel page, returning `(position, bytes)` per populated slot
/// together with the sweep's [`rendezvous::SweepOutcome`].
///
/// A **partial** sweep — some slots read, some GETs failed — returns the slots it
/// did read rather than an error, which makes the outcome a **caller obligation**
/// rather than a property this function provides. Two rules the collector must
/// satisfy, neither of which exists in the tree yet (collection is #236):
///
/// 1. Hold the probe frontier and the contiguous cursor as separate pointers, per
///    `daemonseed_core::dm::paging`'s module docs. The cursor may only advance
///    across an unbroken prefix, so a slot missed by a failed GET holds it in place
///    and is re-probed rather than skipped.
/// 2. Treat `outcome.failed > 0` as a record-health signal, not as an empty page.
///
/// Until a collector honouring both exists, an `Ok` carrying an empty `Vec` and a
/// non-zero `failed` is unguarded — which is precisely why the outcome is returned
/// instead of being traced and dropped.
#[allow(clippy::too_many_arguments)]
async fn sweep_dm_page(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    page_recency: &rendezvous::DmPageRecency,
    record_locks: &rendezvous::RecordLocks,
    address: &DmPageAddress<Receiving>,
) -> Result<DmPageSweep> {
    // Borrowed, for the reason `publish_dm_page` gives (#244).
    let owner = address.with_owner_seed(identity::rendezvous_owner_keypair)?;
    // The open is serialized under the record lock; the GETs are NOT, so a slow
    // page read never blocks a concurrent write to the same page. The guard drops
    // before any read permit is acquired, keeping the single-permit rule
    // (CRSH-ISC-17).
    let opened_handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner.key());
        let _open_guard = record_lock.lock().await;
        dm_page_open(
            gate,
            api,
            rc,
            opened,
            page_recency,
            record_locks,
            &owner,
            IfAbsent::ReportAbsent,
        )
        .await?
    };
    // An unwritten page is the probe frontier's ordinary state. Nothing was created,
    // so nothing was read, and the outcome reports `attempted: 0` rather than the
    // full slot count with nothing found — the two are different facts and the
    // collector's `outcome.failed > 0` health rule depends on being able to tell
    // them apart. Before #253 the only way to reach the empty case at all was to
    // have just created the record, which is what made "no such page" and "empty
    // page" the same answer.
    //
    // Destructured, and `_lease` deliberately outlives the GETs below: the record
    // lock was dropped above so the reads never block a writer, which leaves the
    // sweeper holding a live handle and — between two subkey GETs — zero permits. The
    // lease is the only thing standing between that window and an eviction closing
    // the record mid-sweep, which would surface as a partial sweep and be read as
    // record ill-health.
    let Some((handle, _lease)) = opened_handle else {
        crate::vtrace!(
            "sweep_dm_page: page={} absent, not created -> empty sweep",
            address.page()
        );
        return Ok(DmPageSweep::for_address(
            address,
            Vec::new(),
            rendezvous::SweepOutcome {
                attempted: 0,
                failed: 0,
                found: 0,
            },
        ));
    };
    // Before a single GET: the record we opened must have exactly as many subkeys as
    // a page has slots. The sweep below is bounded by this same number, so a record
    // carrying fewer would come back Ok and short — every position placing cleanly,
    // the missing messages simply absent — which is the one shape disagreement no
    // later check can see.
    dm_page_shape_must_match(address.page(), handle.shape().o_cnt())?;
    let key = handle.key().clone();
    // Subkeys are collected raw and placed on the page afterwards, because placing
    // is fallible and `sweep_gated`'s callback answers only "keep sweeping". A
    // partial sweep must still report what it read, so the failure cannot be
    // swallowed inside the loop.
    let mut raw: Vec<(u32, Vec<u8>)> = Vec::new();
    // The slot bound comes off the handle's own shape, never from a constant at
    // this call site: a sweep wider than the record the address was derived under
    // is the mistake `RendezvousHandle` binds key and shape together to prevent.
    let outcome = rendezvous::sweep_gated(
        gate,
        handle.shape().o_cnt(),
        |subkey, bytes| {
            raw.push((subkey, bytes));
            true
        },
        |subkey| {
            let rc = rc.clone();
            let key = key.clone();
            async move {
                match rc.get_dht_value(key, subkey, true).await {
                    Ok(Some(v)) => Ok(Some(v.data().to_vec())),
                    Ok(None) => Ok(None),
                    Err(e) => {
                        crate::vtrace!("sweep_dm_page: get error on slot {subkey}: {e}");
                        Err(())
                    }
                }
            }
        },
    )
    .await;
    crate::vtrace!(
        "sweep_dm_page: key={:?} page={} attempted={} found={} failed={}",
        handle.key(),
        address.page(),
        outcome.attempted,
        outcome.found,
        outcome.failed
    );
    // Each subkey becomes a checked position on the address's OWN page, so a
    // collector never re-does the arithmetic and never has to be told which page the
    // slots came from. The address goes in whole rather than its page number, so the
    // placement is unit-testable — see `dm_page_place_swept`.
    let found = dm_page_place_swept(address, raw)?;
    Ok(DmPageSweep::for_address(address, found, outcome))
}

/// The DM doorbell's schema: `dflt(32)`, one subkey per knock slot.
///
/// Part of the record ADDRESS, and simultaneously the modulus of
/// `daemonseed_core::dm::doorbell::slot_for` — hence derived from
/// `doorbell::DOORBELL_SLOTS` rather than typed here (ISC-C41), for the reason the
/// page shape is derived from `paging::PAGE_SLOTS`. It carries a third fact the
/// page's does not: 32 slots is what makes the per-subkey cap exactly
/// `firstcontact::MAX_ENTRY_LEN`, so this shape and the entry ceiling are one
/// number wearing two names.
const DM_DOORBELL_SHAPE: rendezvous::RecordShape = rendezvous::RecordShape::DM_DOORBELL;

/// Refuse a slot the doorbell record cannot hold.
///
/// The slot comes from `doorbell::slot_for`, which reduces mod `DOORBELL_SLOTS` and
/// therefore cannot produce one — so this guards a caller that computed the slot
/// some other way, which is the only way a knock can be aimed outside the record.
/// Veilid would refuse the subkey itself, but only after an `open_or_create` had
/// already brought the recipient's record into being on the network, and only as a
/// generic schema-validation failure.
fn doorbell_slot_must_be_in_record(slot: u16) -> Result<()> {
    if slot >= daemonseed_core::dm::doorbell::DOORBELL_SLOTS {
        return Err(VeilidNetError::DmDoorbellSlotOutsideRecord {
            slot: u32::from(slot),
        });
    }
    Ok(())
}

/// Refuse a first-contact entry above the doorbell subkey's cap.
///
/// The bound is `firstcontact::MAX_ENTRY_LEN`, which is the ceiling the entry's own
/// padding ladder is built against AND — because the slot count was chosen to make
/// it so — exactly this shape's [`rendezvous::RecordShape::max_value_len`]. The two
/// being equal is pinned by a test rather than assumed here; if they ever diverged,
/// `rendezvous::check_write_cap` is the network-truth backstop underneath, and it
/// would refuse the write after the open rather than before it.
///
/// An entry built by `firstcontact::build` cannot trip this — it is padded into a
/// bucket that fits. Reaching it means the entry came from somewhere else, or the
/// ladder and the schema have drifted apart, and both are worth a loud local
/// failure naming the cap.
fn doorbell_entry_must_fit(entry_len: usize) -> Result<()> {
    let max = daemonseed_core::dm::firstcontact::MAX_ENTRY_LEN;
    if entry_len > max {
        return Err(VeilidNetError::DmDoorbellEntryTooLarge {
            len: entry_len,
            max,
        });
    }
    Ok(())
}

/// Both write-side doorbell guards, applied together at the public handle before
/// anything crosses the command channel.
///
/// One function so the two cannot come apart: a caller that checked the size and
/// forgot the slot reaches the network with a subkey the record cannot hold, and a
/// caller that checked the slot and forgot the size reaches it with a value veilid
/// will refuse — both after `open_or_create` has already created the recipient's
/// record. Pairing them also makes the pair unit-testable in one call, which the
/// command loop's own arm is not.
fn doorbell_write_must_be_addressable(slot: u16, entry_len: usize) -> Result<()> {
    doorbell_slot_must_be_in_record(slot)?;
    doorbell_entry_must_fit(entry_len)
}

/// Turn one swept subkey into the doorbell slot it holds.
///
/// The checked subkey-to-slot direction, applied at the transport boundary so no
/// caller does the narrowing. A sweep is bounded by the opened record's own `o_cnt`,
/// and `doorbell_open` binds one shape, so this cannot fail on any path that exists
/// today — it is the narrowing's total-function form, kept because the alternative
/// to reporting an unplaceable subkey is skipping it, and a skipped slot is a knock
/// the recipient never sees under an `Ok`.
fn doorbell_slot_of_subkey(subkey: u32) -> Result<u16> {
    u16::try_from(subkey)
        .ok()
        .filter(|slot| *slot < daemonseed_core::dm::doorbell::DOORBELL_SLOTS)
        .ok_or(VeilidNetError::DmDoorbellSlotOutsideRecord { slot: subkey })
}

/// Place every swept subkey in its slot, so a caller receives slots rather than
/// raw subkey indices.
///
/// A free function rather than an inline `map` inside [`sweep_doorbell`] for the
/// reason `dm_page_place_swept` is one: the sweep cannot run without a live DHT, so
/// anything written inline there is a line no runnable test reaches.
fn doorbell_place_swept(raw: Vec<(u32, Vec<u8>)>) -> Result<Vec<(u16, Vec<u8>)>> {
    raw.into_iter()
        .map(|(subkey, bytes)| doorbell_slot_of_subkey(subkey).map(|slot| (slot, bytes)))
        .collect()
}

/// Build the funnel request for one doorbell knock.
///
/// **`CurrentState` kind coalescing on the SLOT, at the class `dispatch` names.**
/// Each of the three is a decision that fails silently if it is wrong, so each is
/// stated. The authority for all of it is
/// `docs/design/direct-messaging.md:127-128` (§ Fork 4, write classification).
///
/// *Class.* Not one class but two, because the design splits the doorbell in two.
/// `:127`: the FIRST dispatch of a user send is `Chat` (rank 1) — "the outbox
/// write, plus the doorbell write when the send is a first contact… a user action
/// wanting user-action latency… **one write (two at first contact) per user
/// action**". `:128`: every scheduler-driven re-dispatch — "outbox re-seeds,
/// doorbell keep-alive, key-record keep-alive" — is `Keepalive` (rank 4). The
/// caller states which through [`DoorbellDispatch`], the way
/// [`Command::PublishCurrentState`] takes a [`PresenceBoundary`], because the
/// transport cannot tell them apart and a default would silently pick one.
///
/// Neither carries a deadline: there is no hard DHT expiry anywhere in the DM path,
/// only eviction pressure (`:129`).
///
/// **The chat lane does NOT confer never-coalesce, and that is worth stating
/// because `:127` calls it "never coalesced".** The funnel keys coalescing on the
/// `kind` alone — `WriteScheduler::enqueue` matches on `req.kind` and never reads
/// `req.class` — so a `Chat`-class `CurrentState` write is coalescible like any
/// other. `:127`'s phrase is true of the writes it has in mind (the outbox and page
/// writes, which are `Ring`), not of the lane itself. The consequence here is
/// narrow and accepted: if a `Reseed` for the same slot is enqueued while a
/// `FirstSend` for it is still queued, the elder is dropped and the survivor
/// carries the *newer* request's class, so the knock lands at rank 4 rather than
/// rank 1. Nothing is lost — same slot, same entry, and the elder's reply resolves
/// `Ok` — and it is only reachable when a first send has already sat queued long
/// enough for its own backoff to fire. Pinned by a test so a change to `schedule.rs`
/// surfaces here.
///
/// *Kind.* `CurrentState`, i.e. coalescible — the opposite of the page write's
/// `Ring`, and correct for the opposite reason. Two queued writes to one page are
/// two different messages in two different slots, so collapsing them drops one. Two
/// queued writes to one doorbell SLOT are the same sender knocking twice at the same
/// recipient, because the slot is a pure function of `(sender secret, recipient
/// key)` — a retry is *defined* to overwrite the sender's own previous entry, so a
/// newer knock superseding a queued older one is exactly the intended behaviour.
///
/// *Coalescing key.* The `logical_id` is the SLOT — `:128`, "the logical id is the
/// *message* (slot), so a superseded re-seed of the same message coalesces and
/// distinct messages never do". This is the field with the least margin for error. The funnel coalesces on `(record, logical_id)`, and the
/// record here is one doorbell shared by every sender who ever knocks on it. A
/// constant id — the shape [`Command::PublishDmKeyRecord`] can afford, because there
/// is exactly one key record per owner seed — would make two knocks from two local
/// identities to one recipient collapse into one, and the loser's first contact
/// would never reach the wire while its `reply` reported `Ok(())`. The slot is what
/// separates them, and it is the finest scope that is still correct: it is precisely
/// the granularity at which "the same sender knocking again" is defined.
///
/// Constructed out of line, not inline in the [`Command::PublishDoorbellEntry`] arm,
/// for the reason `dm_page_write_request` gives: a request built on the command loop
/// can only be observed by a live two-node round trip, and every mistake available
/// here reports `Ok(())` on every local surface. The record id is derived *inside*
/// this function for the same reason — passing it in would move the one decision
/// worth pinning back out to the untestable call site.
fn doorbell_entry_write_request(
    owner_seed: [u8; 32],
    slot: u16,
    entry: Vec<u8>,
    dispatch: DoorbellDispatch,
    reply: oneshot::Sender<Result<()>>,
) -> WriteRequest<ProdWrite> {
    WriteRequest {
        // Scope rationale lives on `funnel_record_key`.
        record: funnel_record_key(&owner_seed),
        class: dispatch.classify(),
        kind: WriteKind::CurrentState {
            logical_id: doorbell_coalescing_id(slot),
        },
        deadline: None,
        item: ProdWrite::DoorbellEntry {
            owner_seed,
            slot,
            entry,
        },
        reply: Some(reply),
    }
}

/// The funnel's coalescing id for one doorbell slot.
///
/// One function so two enqueue paths cannot spell it differently: the id is a
/// coalescing scope, so two spellings for one slot silently stop coalescing and two
/// slots sharing a spelling silently start.
fn doorbell_coalescing_id(slot: u16) -> String {
    format!("dm-doorbell-{slot}")
}

/// Open (or create) one doorbell's record — the single opener both doorbell
/// operations go through.
///
/// **One call site for the shape, and that is the whole point** — the argument
/// `dm_page_open` makes, verbatim in force here: `o_cnt` is part of the record
/// ADDRESS, so a knock and a sweep naming different shapes would run against two
/// different records, the write would succeed, the sweep would come back empty, and
/// no surface anywhere would report an error.
///
/// Whether an absent record may be brought into being is the caller's to say, and
/// is the one thing that differs between the two paths. A knock uses
/// [`IfAbsent::Create`], and on this record that means a SENDER creating a record it
/// does not own — which is not an anomaly but the mechanism of cold first contact:
/// until somebody knocks, a recipient's doorbell does not exist on the network at
/// all. A sweep uses [`IfAbsent::ReportAbsent`], for the reason #253 gives on the
/// page: creating on a read path manufactures an empty record and destroys the
/// difference between "nobody has knocked" and "the record was not found on this
/// pass".
///
/// Locking is deliberately NOT folded in, exactly as it is not for the page:
/// [`publish_doorbell_entry`] holds the record lock across the open *and* the write,
/// while [`sweep_doorbell`] drops it the moment the open returns so its GETs never
/// block a concurrent write to the same doorbell (CRSH-ISC-17).
async fn doorbell_open(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    owner: &KeyPair,
    if_absent: IfAbsent,
) -> Result<Option<rendezvous::RendezvousHandle>> {
    // Bound ONCE, and every use below goes through this binding, for the reason
    // `dm_page_open` binds its own: the cache id and both open modes cannot drift
    // apart without editing this line.
    let shape = DM_DOORBELL_SHAPE;
    let id = rendezvous::cached_record_id(&owner.key(), shape);
    match if_absent {
        IfAbsent::Create => rendezvous::open_cached(
            opened,
            &id,
            rendezvous::open_or_create(gate, api, rc, owner, shape),
        )
        .await
        .map(Some),
        IfAbsent::ReportAbsent => {
            rendezvous::open_cached_optional(
                opened,
                &id,
                rendezvous::open_only(gate, api, rc, owner, shape),
            )
            .await
        }
    }
}

/// Write one sealed first-contact entry into one slot of one doorbell (ISC-C41).
///
/// `entry` is opaque here, exactly as the key record and the channel frame are: this
/// layer neither parses, seals, nor verifies it. Authorship is proved by the
/// signature sealed inside — checked by the recipient's
/// `firstcontact::open` — never by the fact that a write succeeded.
///
/// **This is the one record daemonseed writes that the writer does not own, and it
/// needs nothing new to express.** The owner keypair is derived from a
/// world-derivable seed, so the sender holds full write authority over the
/// recipient's doorbell and signs the `set` with it, through the identical
/// `open_or_create` / `publish_at_subkey` pair every owned record uses. What differs
/// from every other write in this crate is not the mechanism but the consequence:
/// any third party holds that same authority, so any slot can be overwritten or
/// erased by anyone. That is the accepted, DoS-only residual the design prices —
/// forgery is impossible, because an entry that does not verify under the
/// recipient's own decapsulation key simply does not open — and it is why the
/// sender's outbox re-seeds on a backoff rather than treating one successful write
/// as delivery.
///
/// `IfAbsent::Create` is therefore load-bearing rather than incidental: a recipient
/// who has never been knocked on has no doorbell record on the network, and the
/// first sender brings it into being.
#[allow(clippy::too_many_arguments)]
async fn publish_doorbell_entry(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
    slot: u16,
    entry: Vec<u8>,
) -> Result<()> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Single-flight the open and serialize against any concurrent op on this record,
    // exactly as the rendezvous, key-record and page write paths do (CRSH-ISC-3).
    // Contended by design here in a way the others are not: one doorbell is shared by
    // every sender in the world, so two knocks from this node to one recipient — and
    // this node's own sweep of its own doorbell — take the same lock.
    let record_lock = rendezvous::record_lock(record_locks, &owner.key());
    let _write_guard = record_lock.lock().await;
    // `IfAbsent::Create` cannot answer `None` — it either opens, creates and reopens,
    // or fails — so this is unreachable rather than a fallback with a behaviour. It is
    // written as a hard error instead of an `expect` so a future change to
    // `doorbell_open` surfaces as a reported failure rather than a panic inside a
    // scheduler dispatch task.
    let handle = doorbell_open(gate, api, rc, opened, &owner, IfAbsent::Create)
        .await?
        .ok_or_else(|| {
            VeilidNetError::Actor(
                "the doorbell opener, in IfAbsent::Create mode, reported the record absent \
                 instead of creating it"
                    .to_string(),
            )
        })?;
    crate::vtrace!(
        "publish_doorbell_entry: key={:?} slot={} bytes={}",
        handle.key(),
        slot,
        entry.len()
    );
    rendezvous::publish_at_subkey(rc, &handle, &owner, u32::from(slot), entry).await
}

/// Sweep every slot of one doorbell, returning `(slot, bytes)` per populated slot
/// together with the sweep's [`rendezvous::SweepOutcome`].
///
/// A **partial** sweep — some slots read, some GETs failed — returns the slots it
/// did read rather than an error, which makes the outcome a **caller obligation**:
/// `outcome.failed > 0` is a record-health signal and must not be read as an empty
/// doorbell, or a network fault becomes "nobody has knocked". Unlike the page sweep
/// there is no cursor to hold in place — every slot is independently meaningful and
/// a missed one is simply re-read on the next pass — so the obligation is the one
/// rule rather than two.
///
/// The record's shape is an invariant here rather than something checked: the opener
/// binds one shape and `RendezvousHandle` carries the shape it was derived under, so a
/// record with a different `o_cnt` is a different address this code never opens.
///
/// Opens with [`IfAbsent::ReportAbsent`], so sweeping a doorbell nobody has knocked
/// on does not create it: an absent record answers `attempted: 0`, which is
/// deliberately distinct from a present record whose every slot was read and empty
/// (`attempted: DOORBELL_SLOTS, found: 0`). As on the page path, `attempted: 0` means
/// the record was not found by this node on this pass, NOT that it cannot exist.
async fn sweep_doorbell(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
) -> Result<DoorbellSweep> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // The open is serialized under the record lock; the GETs are NOT, so a slow sweep
    // never blocks a concurrent knock on the same doorbell. The guard drops before any
    // read permit is acquired, keeping the single-permit rule (CRSH-ISC-17).
    let opened_handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner.key());
        let _open_guard = record_lock.lock().await;
        doorbell_open(gate, api, rc, opened, &owner, IfAbsent::ReportAbsent).await?
    };
    let Some(handle) = opened_handle else {
        crate::vtrace!("sweep_doorbell: record absent, not created -> empty sweep");
        return Ok(DoorbellSweep {
            slots: Vec::new(),
            outcome: rendezvous::SweepOutcome {
                attempted: 0,
                failed: 0,
                found: 0,
            },
        });
    };
    // **An invariant, not a guard, and the distinction is the point.** `RendezvousHandle`
    // stamps the shape it was DERIVED under, never a schema observed on the network, and
    // `doorbell_open` binds one shape constant — so this equality holds by construction.
    // A record with a different `o_cnt` is a different ADDRESS, one this code never opens
    // and never sweeps. There is therefore no such thing here as a short doorbell that
    // silently truncates a sweep; that failure mode belongs to code that derives a shape
    // and a key independently, which `RendezvousHandle` exists to make unrepresentable.
    // A `debug_assert!` records the invariant for free in release, where a runtime
    // refusal (and the error variant, tests and source probe it needed) was pure cost
    // defending a state that cannot occur.
    debug_assert_eq!(
        handle.shape().o_cnt(),
        daemonseed_core::dm::doorbell::DOORBELL_SLOTS,
        "the doorbell opener binds one shape, so the handle can carry no other"
    );
    let bound = handle.shape().o_cnt();
    let key = handle.key().clone();
    // Subkeys are collected raw and placed afterwards, because placing is fallible and
    // `sweep_gated`'s callback answers only "keep sweeping". A partial sweep must still
    // report what it read, so the failure cannot be swallowed inside the loop.
    let mut raw: Vec<(u32, Vec<u8>)> = Vec::new();
    // The slot bound comes off the handle's own shape, never from a constant at this
    // call site: a sweep wider than the record the seed was derived under is the mistake
    // `RendezvousHandle` binds key and shape together to prevent.
    let outcome = rendezvous::sweep_gated(
        gate,
        bound,
        |subkey, bytes| {
            raw.push((subkey, bytes));
            true
        },
        |subkey| {
            let rc = rc.clone();
            let key = key.clone();
            async move {
                match rc.get_dht_value(key, subkey, true).await {
                    Ok(Some(v)) => Ok(Some(v.data().to_vec())),
                    Ok(None) => Ok(None),
                    Err(e) => {
                        crate::vtrace!("sweep_doorbell: get error on slot {subkey}: {e}");
                        Err(())
                    }
                }
            }
        },
    )
    .await;
    crate::vtrace!(
        "sweep_doorbell: key={:?} attempted={} found={} failed={}",
        handle.key(),
        outcome.attempted,
        outcome.found,
        outcome.failed
    );
    let slots = doorbell_place_swept(raw)?;
    Ok(DoorbellSweep { slots, outcome })
}

/// Open the rendezvous record, register a watch, and kick off a one-shot background
/// sweep for the bounded login backlog. Inbound items flow out as
/// [`VeilidNetEvent::Inbound`]. Used for circles and public rooms / lobby alike.
///
/// **The two owner arms differ in what an absent record means.** A
/// [`RendezvousOwner::Held`] owner opens-or-creates: every party that holds the seed
/// writes the record, so a record nobody has created yet is created here,
/// deterministically at the same address every other member derives. A
/// [`RendezvousOwner::PublicOnly`] owner cannot create it and must not pretend to —
/// it opens read-only, and an absent record is a clean `Ok` with no watch and no
/// sweep. That is not a silent failure: the record's absence is a provisioning state
/// of the party that writes it, which this one can do nothing about, and the caller
/// re-subscribes on its own cadence, so the watch registers on the first pass that
/// finds the record present.
///
/// The `Ok` value distinguishes those two outcomes: `true` when a record was opened
/// and a watch registered, `false` on the read-only absent path. The caller needs it
/// to tell "subscribed" from "nothing there yet", which are the same `Ok` otherwise.
async fn subscribe_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    gate: &Arc<DhtGate>,
    owner: &RendezvousOwner,
) -> Result<bool> {
    crate::vtrace!("subscribe_rendezvous: open (cached) rendezvous");
    let resolved = owner.resolve()?;
    let owner_key = resolved.public_key();
    // Single-flight the open against a concurrent same-record publish; the guard is
    // dropped before the watch registers (only the open needs serialization).
    let opened_handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner_key);
        let _open_guard = record_lock.lock().await;
        open_subscribed_record(gate, api, rc, opened, &resolved, &owner_key).await?
    };
    let Some(handle) = opened_handle else {
        crate::vtrace!(
            "subscribe_rendezvous: read-only record absent -> Ok(false) (no watch, no sweep, not cached)"
        );
        return Ok(false);
    };
    crate::vtrace!(
        "subscribe_rendezvous: record open key={:?}; registering watch",
        handle.key()
    );
    // §RS-2 margin limiter: `watch_dht_values` is an un-gated DHT op, so hold an
    // un-gated-op permit across the raw watch — peak open+watch concurrency ≤ margin(2)
    // by construction (CRSH-ISC-14). CRSH-ISC-17: no read-pool permit is held across
    // this acquire; the backlog sweep's per-GET read permits are taken later, inside
    // the spawned `sweep`, strictly outside the limiter's span. The `record_lock` open
    // guard above is already dropped, so only the watch RPC sits under the limiter.
    {
        let _ungated = gate.acquire_ungated().await;
        rc.watch_dht_values(handle.key().clone(), None, None, None)
            .await
            .map_err(|e| VeilidNetError::Routing(e.to_string()))?;
    }
    crate::vtrace!("subscribe_rendezvous: watch ok; spawning backlog sweep -> Ok(true)");
    // Read lane (WB-5 / I5′.1): the backlog sweep is a burst of DHT GETs; hold a
    // read permit from the shared accountant for its duration so reads and writes
    // draw on one budget.
    spawn_gated_sweep(gate, rc, handle, ev_tx);
    Ok(true)
}

/// The record open shared by [`subscribe_rendezvous`] and [`resweep_rendezvous`] —
/// one arm per way of holding the owner, both onto the SAME open-cache entry, since
/// [`identity::ResolvedOwner::public_key`] is one value per record.
///
/// `Ok(None)` is reachable only from the read-only arm and says the record was not
/// found on this pass. It is deliberately not cached
/// ([`rendezvous::open_cached_optional`]), so the next pass sees the record the
/// moment the party that writes it has created it, rather than answering "absent"
/// for the rest of the session.
async fn open_subscribed_record(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    resolved: &identity::ResolvedOwner,
    owner_key: &PublicKey,
) -> Result<Option<rendezvous::RendezvousHandle>> {
    let shape = rendezvous::RecordShape::RENDEZVOUS;
    let id = rendezvous::cached_record_id(owner_key, shape);
    match resolved {
        identity::ResolvedOwner::Writer(keypair) => rendezvous::open_cached(
            opened,
            &id,
            rendezvous::open_or_create(gate, api, rc, keypair, shape),
        )
        .await
        .map(Some),
        identity::ResolvedOwner::ReadOnly(public) => {
            rendezvous::open_cached_optional(
                opened,
                &id,
                rendezvous::open_read_only(gate, api, rc, public.as_bytes(), shape),
            )
            .await
        }
    }
}

/// Spawn a backlog sweep. The read permits are acquired PER-GET inside
/// [`rendezvous::sweep`] (WB-5.1 / I5″.2) — the spawn no longer holds one whole-sweep
/// permit (the first WB-5 build's defect: ≥13 cold-start sweeps each pinned a permit
/// for its full multi-minute run and drained the pool, starving writes). Read
/// occupancy is now bounded by the read partition regardless of live sweep count.
fn spawn_gated_sweep(
    gate: &Arc<DhtGate>,
    rc: &RoutingContext,
    handle: rendezvous::RendezvousHandle,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
) {
    let gate = gate.clone();
    let rc = rc.clone();
    let ev_tx = ev_tx.clone();
    tokio::spawn(async move {
        rendezvous::sweep(gate, rc, handle, ev_tx).await;
    });
}

/// Re-open an already-known rendezvous record and kick off a fresh one-shot sweep,
/// WITHOUT registering a watch — the recovery primitive for a backlog item published
/// during the post-(re)connect watch-warmup window (#132/#133). The open block is
/// identical to [`subscribe_rendezvous`], including its two owner arms and its
/// clean `Ok` on a read-only record that is absent; found items flow out as
/// [`VeilidNetEvent::Inbound`] and are deduped downstream.
async fn resweep_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    gate: &Arc<DhtGate>,
    owner: &RendezvousOwner,
) -> Result<()> {
    crate::vtrace!("resweep_rendezvous: open (cached) rendezvous");
    let resolved = owner.resolve()?;
    let owner_key = resolved.public_key();
    // Single-flight the open against a concurrent same-record publish (mirrors
    // subscribe_rendezvous); no watch is registered here.
    let opened_handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner_key);
        let _open_guard = record_lock.lock().await;
        open_subscribed_record(gate, api, rc, opened, &resolved, &owner_key).await?
    };
    let Some(handle) = opened_handle else {
        crate::vtrace!("resweep_rendezvous: read-only record absent -> Ok (nothing to sweep)");
        return Ok(());
    };
    crate::vtrace!(
        "resweep_rendezvous: record open key={:?}; spawning backlog sweep -> Ok",
        handle.key()
    );
    // Read lane (WB-5 / I5′.1): hold a shared-accountant read permit for the sweep.
    spawn_gated_sweep(gate, rc, handle, ev_tx);
    Ok(())
}

/// **Repair** a dead rendezvous record session (consumer-route self-heal §RS-1.2, step
/// 3b). Re-establishes the record under its `record_lock` held across the WHOLE sequence
/// (CRSH-ISC-3/18): invalidate the open-cache entry, optionally
/// [`rendezvous::REPAIR_CLOSE_FIRST`]-close the old handle, re-open, re-watch, and full
/// 0..64 re-sweep. The open/watch acquire the §RS-2 un-gated limiter; the re-sweep GETs
/// take per-GET read permits — never nested (CRSH-ISC-17), since open/watch complete
/// before the sweep starts. Unlike [`subscribe_rendezvous`], the re-sweep is **awaited
/// under the lock** (via [`rendezvous::sweep_collect`]) rather than spawned, so the whole
/// re-establishment is atomic against a concurrent same-record write; it emits backlog
/// [`VeilidNetEvent::Inbound`]s but NOT a [`VeilidNetEvent::SweepHealth`] (the frontend
/// resets the tracker at dispatch, so a repair-sweep health event would muddy detection).
///
/// **A read-only owner repairs too, and an absent record is an error here.** The
/// re-open goes through `open_read_only` — no create, no writer — but where
/// [`subscribe_rendezvous`] treats absence as a clean `Ok`, a repair is
/// re-establishing a session that was working, so a record that is now unreachable
/// is a failure to report. It classifies transient, which is right: the frontend
/// clears the record's tracker at dispatch and re-detects on the next cycle.
async fn repair_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    gate: &Arc<DhtGate>,
    owner: &RendezvousOwner,
) -> Result<()> {
    crate::vtrace!("repair_rendezvous: re-establishing dead record session");
    let resolved = owner.resolve()?;
    let owner_key = resolved.public_key();
    let record_lock = rendezvous::record_lock(record_locks, &owner_key);
    let outcome = rendezvous::repair_gated(
        &record_lock,
        opened,
        &rendezvous::cached_record_id(&owner_key, rendezvous::RecordShape::RENDEZVOUS),
        rendezvous::REPAIR_CLOSE_FIRST,
        // close (repro-gated): best-effort — a close on a session veilid already GC'd is a
        // benign race (Evidence 3 sibling), so the error is swallowed.
        |handle: rendezvous::RendezvousHandle| async move {
            if let Err(e) = rc.close_dht_record(handle.into_key()).await {
                crate::vtrace!("repair_rendezvous: close_dht_record (pre-reopen) failed ({e})");
            }
        },
        // open: both arms acquire the un-gated limiter around each raw open
        // (CRSH-ISC-14/17); no read permit is held across it. The read-only arm's
        // `Ok(None)` becomes an error because `repair_gated` re-caches what it opens and
        // there is nothing to cache — see the fn doc.
        || async {
            match &resolved {
                identity::ResolvedOwner::Writer(keypair) => {
                    rendezvous::open_or_create(
                        gate,
                        api,
                        rc,
                        keypair,
                        rendezvous::RecordShape::RENDEZVOUS,
                    )
                    .await
                }
                identity::ResolvedOwner::ReadOnly(public) => rendezvous::open_read_only(
                    gate,
                    api,
                    rc,
                    public.as_bytes(),
                    rendezvous::RecordShape::RENDEZVOUS,
                )
                .await?
                .ok_or_else(|| {
                    // Traced here because the caller is fire-and-forget: nothing
                    // downstream reads this error, so without a trace a repair that
                    // cannot find the record leaves no evidence anywhere.
                    crate::vtrace!(
                        "repair_rendezvous: read-only re-open found no record -> Err (transient)"
                    );
                    VeilidNetError::Routing(
                        "the rendezvous record was not found on repair re-open".to_owned(),
                    )
                }),
            }
        },
        // watch: un-gated limiter around the raw watch; no read permit held (CRSH-ISC-17).
        |handle: rendezvous::RendezvousHandle| async move {
            let _ungated = gate.acquire_ungated().await;
            rc.watch_dht_values(handle.into_key(), None, None, None)
                .await
                .map(|_| ())
                .map_err(|e| VeilidNetError::Routing(e.to_string()))
        },
        // sweep: full 0..o_cnt re-sweep, per-GET read permits (WB-5.1 / I5″.2), awaited under
        // the lock. No SweepHealth emission (the frontend owns the tracker reset).
        |handle| rendezvous::sweep_collect(gate, rc, handle, ev_tx),
    )
    .await?;
    crate::vtrace!(
        "repair_rendezvous: re-established ({} slot(s) re-swept, {} attempted, {} failed) -> Ok",
        outcome.found,
        outcome.attempted,
        outcome.failed
    );
    Ok(())
}

/// Min interval between RouteChanged-triggered advert refreshes — coalesces route
/// churn bursts (NAT flaps cluster) into at most one re-publish wave, breaking the
/// churn → republish → load → churn reinforcing loop.
const ADVERT_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// Cadence of the #124 advert watchdog: a slow advert re-publish that recovers a
/// route which died without veilid ever reporting it in `dead_routes`. Deliberately
/// minutes-scale — 30× [`ADVERT_REFRESH_MIN_INTERVAL`], so even back-to-back with an
/// observed refresh it cannot reconstruct the tight refresh→release→RouteChange storm
/// the relevance filter closed. A tick that lands inside a recent refresh's coalesce
/// window is a no-op, and a share actively serving a download (served within
/// [`SERVE_RECENCY_WINDOW`]) is skipped so its in-use route is never rotated.
const ADVERT_WATCHDOG_INTERVAL: Duration = Duration::from_secs(150);

/// A share that answered a fetch request within this window is treated as actively
/// serving, so the #124 watchdog skips rotating its route — a route rotation
/// (`publish_one_advert` allocates a new route and releases the old) would kill the
/// recipient's single imported route mid-download. A download continuously serves
/// fragments, so it keeps refreshing the stamp and is never disturbed; only a genuinely
/// idle share (no serve for this long) has its route re-allocated to recover a silent
/// death. Set to the watchdog cadence so one idle tick makes a share eligible.
const SERVE_RECENCY_WINDOW: Duration = ADVERT_WATCHDOG_INTERVAL;

/// A remembered public-share advert: enough to re-allocate a route, re-sign, and
/// re-publish it on RouteChanged. Holds the signing CAPABILITY, never key material.
/// `Clone` so a `RouteMaintenance` refresh can take a snapshot of the advert set to
/// re-publish off-loop (the `Arc<dyn …>` signer clones cheaply).
#[derive(Clone)]
struct AdvertState {
    owner_seed: [u8; 32],
    sealed_announcement: Vec<u8>,
    signer: Arc<dyn discovery::RouteAdvertSigner>,
}

/// Allocate a fresh private inbound route, sign the route advert with the sharer's
/// capability, wrap it with the sealed announcement into a `DiscoveryEnvelope`, and
/// publish it on the lobby rendezvous THROUGH the write funnel (WB-3.I1, class-3
/// advert-refresh, coalescing key = `share_id`). The signed `share_id ‖ route_blob`
/// is the anti-swap binding (D-3.5); this layer never holds the announcer's key. The
/// route alloc/sign/release happen off the command loop (this fn is only ever spawned)
/// and the DHT set itself is enqueued, so nothing here parks the actor loop.
async fn publish_one_advert(
    api: &VeilidAPI,
    sched: &WriteSchedulerHandle<ProdWrite>,
    advert_routes: &Mutex<HashMap<String, RouteId>>,
    share_id: &str,
    advert: &AdvertState,
    // `false` for a one-shot withdraw: after the single write lands, release the route
    // this call allocated (guarded so a concurrent reshare's live route is never freed)
    // instead of leaving it remembered for a RouteChanged/watchdog re-publish (#163).
    persist: bool,
) -> Result<()> {
    let route = api
        .new_private_route()
        .await
        .map_err(|e| VeilidNetError::Routing(e.to_string()))?;
    // Record this share's new route and release the PREVIOUS one (route-leak fix):
    // each refresh allocates a fresh route, so the old one must be freed or routes
    // accumulate under churn.
    let prev = advert_routes
        .lock()
        .unwrap()
        .insert(share_id.to_owned(), route.route_id.clone());
    if let Some(prev) = prev {
        release_tolerant(api, prev, &format!("publish_one_advert prev {share_id}"));
    }
    let route_sig = match advert.signer.sign_route_advert(share_id, &route.blob) {
        Ok(sig) => sig,
        Err(e) => {
            rollback_advert_route(api, advert_routes, share_id, route.route_id);
            return Err(e);
        }
    };
    let route_id = route.route_id.clone();
    let envelope = discovery::DiscoveryEnvelope {
        sealed_announcement: advert.sealed_announcement.clone(),
        route_blob: route.blob,
        route_sig,
    }
    .encode();
    crate::vtrace!(
        "publish_one_advert: share_id={share_id} envelope={} bytes",
        envelope.len()
    );
    // Funnel the DHT write (I1): class-3 advert refresh, coalescing key = share_id, so
    // a RouteChanged burst or a watchdog tick racing a route-change refresh collapses
    // to one write per share (I3). Await the scheduler's completion so route rollback
    // still runs on failure.
    let (reply_tx, reply_rx) = oneshot::channel();
    sched.enqueue(WriteRequest {
        record: funnel_record_key(&advert.owner_seed),
        class: WriteClass::AdvertRefresh,
        kind: WriteKind::CurrentState {
            logical_id: share_id.to_owned(),
        },
        deadline: None,
        item: ProdWrite::CurrentState {
            owner_seed: advert.owner_seed,
            stable_id: share_id.to_owned(),
            sealed: envelope,
        },
        reply: Some(reply_tx),
    });
    let res = reply_rx.await.unwrap_or_else(|_| {
        Err(VeilidNetError::Actor(
            "write scheduler dropped advert reply".into(),
        ))
    });
    if res.is_err() {
        rollback_advert_route(api, advert_routes, share_id, route_id);
    } else if !persist {
        // One-shot withdraw: this write backs no remembered advert, so release the
        // route we just allocated — but ONLY if it is still the entry we installed. A
        // concurrent reshare (persist=true) on the same #156-deterministic share_id may
        // have overwritten advert_routes[share_id] with its OWN live route (releasing
        // ours as its `prev` already); a bare remove-by-key would tear down the
        // reshare's LIVE route and silently break it (#163 review [0]). Compare-and-
        // remove under the lock so we only ever free the route this call owns.
        release_own_advert_route(
            api,
            advert_routes,
            share_id,
            route_id,
            &format!("publish_one_advert withdraw {share_id}"),
        );
    }
    res
}

/// Undo the `advert_routes` insert for a publish that never landed. The
/// RouteMaintenance relevance filter reads that map, so an entry must only ever
/// name a route backing a PUBLISHED advert — and the never-published route is
/// released rather than leaked.
///
/// Compare-and-remove under the lock, exactly like the one-shot withdraw path:
/// both `PublishShare` handlers run `publish_one_advert` in a spawned task, so a
/// concurrent reshare (persist=true) on the same #156-deterministic `share_id`
/// may already have overwritten `advert_routes[share_id]` with its OWN live route
/// (releasing ours as its `prev` in the process). A bare remove-by-key would then
/// wipe the reshare's live entry — leaking its route and blinding RouteMaintenance
/// to that route's death — and double-free our already-freed route (#163 review).
/// Only ever free the route this call still owns.
fn rollback_advert_route(
    api: &VeilidAPI,
    advert_routes: &Mutex<HashMap<String, RouteId>>,
    share_id: &str,
    route_id: RouteId,
) {
    release_own_advert_route(
        api,
        advert_routes,
        share_id,
        route_id,
        &format!("publish_one_advert rollback {share_id}"),
    );
}

/// Drop a share's advert route: take it out of `advert_routes` and release it,
/// as one operation under one lock acquisition (#175).
///
/// **`expected` is the guard, and it is a parameter rather than an internal
/// decision so that each call site states which one it is.** With `Some(id)` the
/// release happens only if the map still holds exactly that route — a
/// compare-and-remove. With `None` whatever route is registered for `share_id` is
/// removed and released.
///
/// **Why the guard is load-bearing where it is used.** Both `PublishShare`
/// handlers run `publish_one_advert` in a spawned task, so a concurrent reshare
/// (`persist=true`) on the same #156-deterministic `share_id` may already have
/// overwritten `advert_routes[share_id]` with its OWN live route, releasing ours
/// as its `prev` in the process. A bare remove-by-key would then wipe the
/// reshare's live entry — leaking its route and blinding RouteMaintenance to that
/// route's death — and double-free our already-freed route (#163 review). A path
/// that owns a specific route only ever frees that one.
///
/// `StopServe` is the `None` case and is correct as such: the share is being
/// unpublished outright, so whatever route currently advertises it is dead weight
/// regardless of which call installed it.
///
/// The lock is dropped before the release, which crosses into the Veilid API —
/// holding an actor-wide mutex across that call is what the explicit `drop` is
/// avoiding, and [`release_advert_route_with`] is where a test can see it.
/// Release the advert route **this call owns**, and only that one.
///
/// The guarded entry point. Use it wherever the caller allocated a specific route
/// and is undoing its own work.
fn release_own_advert_route(
    api: &VeilidAPI,
    advert_routes: &Mutex<HashMap<String, RouteId>>,
    share_id: &str,
    route_id: RouteId,
    context: &str,
) {
    release_advert_route_with(advert_routes, share_id, Some(&route_id), |id| {
        release_tolerant(api, id, context)
    });
}

/// Release whatever advert route is registered for `share_id`, whoever installed
/// it.
///
/// The unguarded entry point, and correct only where the share is being
/// unpublished outright — `StopServe` — so that any route advertising it is dead
/// weight regardless of provenance.
fn release_any_advert_route(
    api: &VeilidAPI,
    advert_routes: &Mutex<HashMap<String, RouteId>>,
    share_id: &str,
    context: &str,
) {
    release_advert_route_with(advert_routes, share_id, None, |id| {
        release_tolerant(api, id, context)
    });
}

/// [`release_advert_route`] with the release itself as a closure — the shape that
/// makes the lock ordering testable.
///
/// `release_tolerant` needs a live `VeilidAPI` and no test in this crate can build
/// one, so with the call inlined the ordering would be verifiable only by reading
/// it. Here a fixture passes a closure that asserts the map is *unlocked* when it
/// runs: `std::sync::Mutex` is not reentrant, so a `try_lock` from inside the
/// closure returns `Err(WouldBlock)` if the guard is still held.
///
/// Generic over the value type so a fixture can use a plain `u32`, matching the
/// shape `drop_dead_advert_routes_removes_only_dead_by_value` already uses.
fn release_advert_route_with<R: PartialEq>(
    advert_routes: &Mutex<HashMap<String, R>>,
    share_id: &str,
    expected: Option<&R>,
    release: impl FnOnce(R),
) {
    let mut routes = advert_routes.lock().unwrap();
    let taken = take_advert_route(&mut routes, share_id, expected);
    drop(routes);
    if let Some(route_id) = taken {
        release(route_id);
    }
}

/// The map half of [`release_advert_route`]: decide what, if anything, to release.
///
/// Pure and generic over the value type, so a fixture can use a plain `u32` — the
/// shape `drop_dead_advert_routes_removes_only_dead_by_value` already uses for the
/// same reason.
///
/// Returns the route to release, or `None` when there is nothing to release:
/// either no entry for `share_id`, or `expected` was given and the entry is a
/// different route.
fn take_advert_route<R: PartialEq>(
    routes: &mut HashMap<String, R>,
    share_id: &str,
    expected: Option<&R>,
) -> Option<R> {
    match expected {
        Some(want) if routes.get(share_id) != Some(want) => None,
        _ => routes.remove(share_id),
    }
}

/// (#180 §RS-3, CRSH-ISC-10b/10c) The single private-route release path for this actor.
/// Veilid returns `InvalidArgument` for a route id that is "unknown, already released, or
/// malformed" and evicts dead routes itself (`take_dead_routes`), so releasing a route the
/// transport already GC'd is a benign race (design Evidence 3) — traced, not surfaced as an
/// error. Every allocation/import release routes through here; a raw `release_private_route`
/// call outside this helper fails CRSH-ISC-10c's grep probe.
fn release_tolerant(api: &VeilidAPI, route_id: RouteId, ctx: &str) {
    match api.release_private_route(route_id) {
        Ok(()) => {}
        Err(veilid_core::VeilidAPIError::InvalidArgument { .. }) => {
            crate::vtrace!("{ctx}: route already evicted (InvalidArgument) — benign");
        }
        Err(e) => crate::vtrace!("{ctx}: release route failed ({e})"),
    }
}

/// (#180 §RS-3, CRSH-ISC-10d) Drop every `advert_routes` entry whose route is in `dead`, so a
/// later re-publish never attempts to release an id veilid already evicted. Compare-by-value
/// (not by share id): a concurrent reshare that swapped in its OWN live route is left intact,
/// exactly as the withdraw/rollback compare-and-remove guards require. Returns the count
/// dropped.
fn drop_dead_advert_routes<R: PartialEq>(
    advert_routes: &Mutex<HashMap<String, R>>,
    dead: &[R],
) -> usize {
    let mut routes = advert_routes.lock().unwrap();
    let before = routes.len();
    routes.retain(|_share, route| !dead.contains(route));
    before - routes.len()
}

/// Re-publish every active share advert with a fresh route + signature (called on
/// RouteChanged). A failure on one advert is logged and skipped — the others still
/// refresh.
async fn refresh_share_adverts(
    api: &VeilidAPI,
    sched: &WriteSchedulerHandle<ProdWrite>,
    advert_routes: &Mutex<HashMap<String, RouteId>>,
    adverts: &HashMap<String, AdvertState>,
) {
    crate::vtrace!("refresh_share_adverts: {} advert(s)", adverts.len());
    let started = std::time::Instant::now();
    for (share_id, st) in adverts {
        if let Err(e) = publish_one_advert(api, sched, advert_routes, share_id, st, true).await {
            crate::vtrace!("refresh_share_adverts: {share_id} ERR ({e})");
        }
    }
    crate::vtrace!(
        "refresh_share_adverts: done in {}ms",
        started.elapsed().as_millis()
    );
}

/// Spawn an advert refresh if the coalesce gate allows it, returning whether one was
/// spawned. Shared by `RouteMaintenance` (an OBSERVED route death) and the #124
/// watchdog (a SILENT death): routing both through the SAME in-flight guard + interval
/// is what lets the watchdog fire on a slow timer without ever doubling a just-fired
/// route-change refresh — so the combined cadence stays far below the storm the
/// relevance filter closed. Clones the shared caches into the spawned task and stamps
/// completion + clears the in-flight guard when it finishes.
fn spawn_refresh_if_due(
    api: &VeilidAPI,
    sched: &WriteSchedulerHandle<ProdWrite>,
    advert_routes: &Arc<Mutex<HashMap<String, RouteId>>>,
    share_adverts: &HashMap<String, AdvertState>,
    refresh_in_flight: &Arc<AtomicBool>,
    last_advert_refresh: &Arc<Mutex<Option<tokio::time::Instant>>>,
) -> bool {
    let last = *last_advert_refresh.lock().unwrap();
    if !refresh_due(last, !share_adverts.is_empty(), ADVERT_REFRESH_MIN_INTERVAL) {
        return false;
    }
    // Claim the in-flight guard; a `true` return means another refresh already holds
    // it. Swapped only after the due-check so we never set it when nothing is due.
    if refresh_in_flight.swap(true, Ordering::SeqCst) {
        return false;
    }
    let api = api.clone();
    let sched = sched.clone();
    let advert_routes = advert_routes.clone();
    let adverts = share_adverts.clone();
    let in_flight = refresh_in_flight.clone();
    let last_refresh = last_advert_refresh.clone();
    tokio::spawn(async move {
        // The outer #124 coalesce gate (in-flight guard + min interval) still bounds
        // the refresh CADENCE; the per-write funnel adds cross-record priority + the
        // I5 cap + I3 same-share coalescing on top.
        refresh_share_adverts(&api, &sched, &advert_routes, &adverts).await;
        // Stamp the coalesce window from COMPLETION, then release the in-flight guard
        // so the next RouteChange or watchdog tick can schedule again.
        *last_refresh.lock().unwrap() = Some(tokio::time::Instant::now());
        in_flight.store(false, Ordering::SeqCst);
    });
    true
}

/// Whether a `RouteMaintenance` refresh should be scheduled now: there are adverts
/// to refresh, and either none has run yet or the last completed at least
/// `min_interval` ago. Pure so the coalesce gate is unit-testable (the in-flight
/// guard is an atomic side effect checked separately at the call site).
fn refresh_due(
    last_completed: Option<tokio::time::Instant>,
    have_adverts: bool,
    min_interval: Duration,
) -> bool {
    have_adverts && last_completed.is_none_or(|t| t.elapsed() >= min_interval)
}

/// Attach and poll until public-internet-ready or the deadline elapses.
async fn attach_and_wait(api: &VeilidAPI, timeout_secs: u64) -> Result<()> {
    crate::vtrace!("attach: calling api.attach()");
    api.attach()
        .await
        .map_err(|e| VeilidNetError::Startup(e.to_string()))?;
    crate::vtrace!(
        "attach: api.attach() ok; waiting up to {timeout_secs}s for public_internet_ready"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    // Log only when the snapshot changes — the peer counts distinguish a
    // bootstrap/NAT-discovery stall (peers stay 0) from a DHT-cold-but-reachable
    // node, the two competing Branch-1 causes.
    let mut last = String::new();
    loop {
        let attachment = api
            .get_state()
            .await
            .map_err(|e| VeilidNetError::Startup(e.to_string()))?
            .attachment;
        let snap = format!(
            "state={:?} public={} local={} peers(reliable={:?} live={:?})",
            attachment.state,
            attachment.public_internet_ready,
            attachment.local_network_ready,
            attachment.reliable_peer_count,
            attachment.live_peer_count
        );
        if snap != last {
            crate::vtrace!("attach: {snap}");
            last = snap;
        }
        if attachment.public_internet_ready {
            crate::vtrace!("attach: public_internet_ready -> Ok");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            crate::vtrace!("attach: deadline elapsed -> NotReady (last {last})");
            return Err(VeilidNetError::NotReady);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Send a sealed envelope over a private route, enforcing the `app_message` cap.
async fn send_sealed(rc: &RoutingContext, route: RouteId, sealed: Vec<u8>) -> Result<()> {
    if sealed.len() > APP_MESSAGE_CAP {
        return Err(VeilidNetError::Send(format!(
            "sealed {} bytes exceeds the {APP_MESSAGE_CAP}-byte app_message cap (re-chunk)",
            sealed.len()
        )));
    }
    rc.app_message(Target::RouteId(route), sealed)
        .await
        .map_err(|e| VeilidNetError::Send(e.to_string()))
}

/// Map a raw `VeilidUpdate` to a typed event (`None` = ignored).
fn map_update(u: VeilidUpdate) -> Option<VeilidNetEvent> {
    match u {
        VeilidUpdate::AppMessage(m) => Some(VeilidNetEvent::Inbound {
            bytes: m.message().to_vec(),
        }),
        VeilidUpdate::Attachment(a) => Some(VeilidNetEvent::Attachment {
            public_internet_ready: a.public_internet_ready,
            // NodeCount is a u64 newtype; peer counts are small, so the cast is safe.
            reliable_peers: a.reliable_peer_count.as_u64() as u32,
            live_peers: a.live_peer_count.as_u64() as u32,
        }),
        // `RouteChange` is intercepted in the update callback (it drives advert
        // refresh + emits `RouteChanged` directly), so it never reaches here.
        // A watched rendezvous record changed. We only watch rendezvous records
        // (circles + public rooms / lobby), so a value-bearing change is an
        // inbound sealed item — surface its bytes (the app opens it with the
        // circle key or `PublicRoomKey`). An empty change (no value) means the
        // watch died; report it as ValueChanged.
        VeilidUpdate::ValueChange(vc) => match vc.value {
            Some(v) => Some(VeilidNetEvent::Inbound {
                bytes: v.data().to_vec(),
            }),
            None => Some(VeilidNetEvent::ValueChanged),
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use daemonseed_core::dm::paging;

    // #161: the graceful-close budgets must compose. The whole no-hang argument is
    // arithmetic — a front-end blocks a UI thread for GRACEFUL_CLOSE_BUDGET, and the
    // actor's own steps must finish inside it with room for the transport teardown, or
    // the front-end's wait stops being a backstop and starts truncating closes that were
    // still within budget (which is how the flush silently stops running). Nothing else
    // checks these four numbers against each other, and each is edited independently.
    #[test]
    fn graceful_close_budgets_compose_inside_the_frontend_wait() {
        let actor_work = CLOSE_PREFLUSH_BUDGET + CLOSE_FLUSH_FLOOR;
        assert!(
            actor_work + TEARDOWN_CAP < GRACEFUL_CLOSE_BUDGET,
            "pre-flush ({CLOSE_PREFLUSH_BUDGET:?}) + flush floor ({CLOSE_FLUSH_FLOOR:?}) \
             + teardown ({TEARDOWN_CAP:?}) must leave headroom inside the front-end's \
             {GRACEFUL_CLOSE_BUDGET:?} wait, or a close still within budget is cut off"
        );
        assert!(
            !CLOSE_FLUSH_FLOOR.is_zero(),
            "the I7 flush must always get a non-zero floor — a zero-budget flush \
             dispatches writes and then tears the transport down under them"
        );
        // The LEAVE's guaranteed slice must be a real slice OF the preflush, not equal to
        // it and not zero: at zero one slow withdraw leaves the leave running under a
        // zero timeout (the defect this reserve exists to remove), and at the full
        // preflush the withdraws get nothing and a stale advert outlives the sharer.
        assert!(
            !CLOSE_LEAVE_RESERVE.is_zero() && CLOSE_LEAVE_RESERVE < CLOSE_PREFLUSH_BUDGET,
            "the leave reserve ({CLOSE_LEAVE_RESERVE:?}) must be a non-zero proper slice \
             of the pre-flush budget ({CLOSE_PREFLUSH_BUDGET:?}) — both ends starve a step"
        );
        // A caller caps its `shutdown` await at `flush_budget + TEARDOWN_CAP`, and
        // `flush_budget` is at most `CLOSE_FLUSH_FLOOR + CLOSE_PREFLUSH_BUDGET` (the
        // whole preflush unspent). That worst case still has to fit the front-end wait,
        // or the cap that exists to bound a head-of-line Shutdown would itself be the
        // thing that truncates a flush already running.
        let widest_caller_cap = CLOSE_FLUSH_FLOOR + CLOSE_PREFLUSH_BUDGET + TEARDOWN_CAP;
        assert!(
            widest_caller_cap < GRACEFUL_CLOSE_BUDGET,
            "the widest caller cap ({widest_caller_cap:?}) must fit inside the front-end's \
             {GRACEFUL_CLOSE_BUDGET:?} wait — an unspent pre-flush is the widest case"
        );
    }

    // #161: a graceful-close LEAVE must reach the funnel as a TOMBSTONE, which is what
    // buys it I3/WB-ISC-12 dominance over a queued or in-flight same-member keepalive and
    // what keeps it in the I7 close flush instead of being shed with the class-4 writes.
    // Classified as a plain current-state write it would be silently coalescible and
    // silently shed at close — the member would resurrect or never depart, with nothing
    // failing anywhere.
    #[test]
    fn presence_leave_classifies_as_a_session_boundary_tombstone() {
        let id = "member-slot".to_owned();
        assert_eq!(
            PresenceBoundary::Leave.classify(id.clone()),
            (
                WriteClass::SessionBoundary,
                WriteKind::Tombstone {
                    logical_id: id.clone()
                }
            ),
            "a leave must be a session-boundary TOMBSTONE"
        );
        assert_eq!(
            PresenceBoundary::Join.classify(id.clone()),
            (
                WriteClass::SessionBoundary,
                WriteKind::CurrentState {
                    logical_id: id.clone()
                }
            ),
            "a join must stay a session-boundary current-state write"
        );
        assert_eq!(
            PresenceBoundary::Keepalive.classify(id.clone()),
            (
                WriteClass::Keepalive,
                WriteKind::CurrentState { logical_id: id }
            ),
            "a keepalive must stay a class-4 current-state write"
        );
    }

    // CRSH-ISC-10c: every private-route release routes through `release_tolerant`. Build
    // the needle from fragments so this assertion's own source text does not self-match.
    #[test]
    fn release_private_route_only_called_through_release_tolerant() {
        let needle: String = [".release", "_private_route("].concat();
        let src = include_str!("actor.rs");
        let count = src.matches(needle.as_str()).count();
        assert_eq!(
            count, 1,
            "exactly one raw release_private_route call must remain — inside release_tolerant"
        );
    }

    /// #175: the lock is released before the release call runs.
    ///
    /// `release_tolerant` crosses into the Veilid API, and holding an actor-wide
    /// mutex across an FFI call is a deadlock waiting for a re-entrant path. The
    /// closure seam is what makes this observable without a `VeilidAPI`:
    /// `std::sync::Mutex` is not reentrant, so a `try_lock` from inside the release
    /// closure fails if the guard is still held.
    ///
    /// **This was not previously true at every site.** `StopServe` used
    /// `if let Some(id) = map.lock().unwrap().remove(&id)`, whose guard temporary
    /// lives to the end of the `if let` body — so it held the lock across the
    /// release. Routing it through here changed that, and this test is what states
    /// the property now holds everywhere.
    #[test]
    fn release_advert_route_with_drops_the_lock_before_releasing() {
        let routes: Mutex<HashMap<String, u32>> =
            Mutex::new(HashMap::from([("s".to_owned(), 1u32)]));
        let mut ran = false;

        release_advert_route_with(&routes, "s", None, |id| {
            ran = true;
            assert_eq!(id, 1u32);
            assert!(
                routes.try_lock().is_ok(),
                "the advert_routes lock is still held while releasing — an \
                 actor-wide mutex must not span the Veilid API call"
            );
        });

        assert!(
            ran,
            "the release closure never ran, so this test asserted nothing"
        );
        assert!(routes.lock().unwrap().is_empty());
    }

    /// #175: a refused take runs no release at all.
    ///
    /// The guard's whole point is that a concurrent reshare's live route is left
    /// alone — which means not merely leaving the map entry, but never handing that
    /// route to `release_tolerant`. A version that took nothing and released
    /// anyway would double-free.
    #[test]
    fn release_advert_route_with_runs_no_release_when_the_guard_refuses() {
        let routes: Mutex<HashMap<String, u32>> =
            Mutex::new(HashMap::from([("s".to_owned(), 1u32)]));
        let mut ran = false;

        // A different route is registered — the reshare case.
        release_advert_route_with(&routes, "s", Some(&2u32), |_| ran = true);
        assert!(!ran, "released a route this call does not own");
        assert_eq!(routes.lock().unwrap().get("s"), Some(&1u32));

        // Positive control: the owning call DOES release, so the assertion above is
        // not passing because the closure never runs for any input.
        release_advert_route_with(&routes, "s", Some(&1u32), |_| ran = true);
        assert!(ran, "the owning call must release");
    }

    /// #175: with `expected`, only the route the caller owns is taken.
    ///
    /// This is the guard the three call sites used to each carry a copy of, and it
    /// is load-bearing rather than defensive: both `PublishShare` handlers run
    /// `publish_one_advert` in a spawned task, so a concurrent reshare on the same
    /// `share_id` may have replaced the entry with its OWN live route. Taking that
    /// one would leak the reshare's route, blind RouteMaintenance to its death, and
    /// double-free the route this call already lost.
    #[test]
    fn take_advert_route_guarded_takes_only_its_own_route() {
        // A SECOND share is registered throughout: a one-entry fixture makes
        // `routes.is_empty()` a strong claim about the target and a vacuous one
        // about everything else, so a mutation that cleared the whole map would
        // pass. Measured, not assumed — that mutant went green on the old fixture.
        let mut routes: HashMap<String, u32> =
            HashMap::from([("s".to_owned(), 1u32), ("other".to_owned(), 9u32)]);

        // A different route is registered — the reshare case. Take nothing, and
        // leave the entry alone.
        assert_eq!(take_advert_route(&mut routes, "s", Some(&2u32)), None);
        assert_eq!(routes.get("s"), Some(&1u32), "the live entry must survive");

        // No entry at all.
        assert_eq!(take_advert_route(&mut routes, "absent", Some(&1u32)), None);

        // Our own route is still registered — take it, and the entry goes.
        assert_eq!(take_advert_route(&mut routes, "s", Some(&1u32)), Some(1u32));
        assert_eq!(routes.get("s"), None);
        assert_eq!(
            routes.get("other"),
            Some(&9u32),
            "another share's route registration must survive untouched"
        );
    }

    /// #175: without `expected`, whatever is registered is taken.
    ///
    /// `StopServe` is this case and is correct as such — the share is being
    /// unpublished outright, so any route advertising it is dead weight regardless
    /// of which call installed it.
    #[test]
    fn take_advert_route_unguarded_takes_whatever_is_registered() {
        let mut routes: HashMap<String, u32> =
            HashMap::from([("s".to_owned(), 7u32), ("other".to_owned(), 9u32)]);

        assert_eq!(take_advert_route(&mut routes, "s", None), Some(7u32));
        assert_eq!(routes.get("s"), None);
        assert_eq!(
            routes.get("other"),
            Some(&9u32),
            "another share's route registration must survive untouched"
        );

        // And an absent share is not an error, just nothing to release.
        assert_eq!(take_advert_route(&mut routes, "s", None), None);
    }

    // CRSH-ISC-10d: a dead-route sweep drops only the entries whose route is dead, by value,
    // leaving a share whose route was replaced (concurrent reshare) untouched.
    #[test]
    fn drop_dead_advert_routes_removes_only_dead_by_value() {
        let map: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::from([
            ("live".to_owned(), 1u32),
            ("dead".to_owned(), 2u32),
        ]));
        let dropped = drop_dead_advert_routes(&map, &[2, 99]);
        assert_eq!(
            dropped, 1,
            "only the one matching-by-value entry is dropped"
        );
        let routes = map.lock().unwrap();
        assert!(routes.contains_key("live"), "a live route survives");
        assert!(!routes.contains_key("dead"), "the dead route is gone");
    }

    #[tokio::test]
    async fn refresh_due_gates_on_adverts_and_interval() {
        // No prior refresh + adverts present → schedule.
        assert!(refresh_due(None, true, Duration::from_secs(5)));
        // No adverts → never schedule, regardless of timing.
        assert!(!refresh_due(None, false, Duration::from_secs(5)));
        // A refresh just completed → wait out the interval before the next.
        let now = tokio::time::Instant::now();
        assert!(!refresh_due(Some(now), true, Duration::from_secs(3600)));
        // Zero interval → eligible again immediately (only the in-flight guard,
        // checked separately, prevents overlap).
        assert!(refresh_due(Some(now), true, Duration::ZERO));
    }

    #[test]
    fn watchdog_cadence_is_storm_safe() {
        // The #124 watchdog fires unconditionally on its own timer, so its cadence
        // MUST stay far above the coalesce window — otherwise a periodic refresh could
        // approach the tight refresh→release→RouteChange loop the relevance filter
        // closed. Require at least a 10× margin.
        assert!(
            ADVERT_WATCHDOG_INTERVAL >= ADVERT_REFRESH_MIN_INTERVAL * 10,
            "watchdog interval must dwarf the coalesce window"
        );
    }

    // CRSH-ISC-22: the per-record repair-in-flight guard dedups a re-dispatched repair.
    // Pure test on the guard semantics the RepairRendezvous arm relies on — same
    // `Arc<Mutex<HashSet<[u8; 32]>>>` type and insert/remove operations the arm uses.
    #[test]
    fn repair_in_flight_guard_dedups_same_record_until_cleared() {
        let guard: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
        let seed = [7u8; 32];
        let other = [8u8; 32];

        // First dispatch for a record proceeds (marker inserted → spawn).
        assert!(
            guard.lock().unwrap().insert(seed),
            "first repair for a record proceeds"
        );
        // A second dispatch for the SAME record while the first is in flight is skipped.
        assert!(
            !guard.lock().unwrap().insert(seed),
            "a repair already in flight for this record is skipped (dedup)"
        );
        // A DISTINCT record is unaffected — its repair proceeds concurrently.
        assert!(
            guard.lock().unwrap().insert(other),
            "a distinct record's repair is not blocked by another record's in-flight repair"
        );
        // The in-flight repair completes and clears its marker.
        assert!(
            guard.lock().unwrap().remove(&seed),
            "completing the repair clears the record's in-flight marker"
        );
        // A later repair for that record proceeds again.
        assert!(
            guard.lock().unwrap().insert(seed),
            "after the marker clears, a later repair for the record proceeds again"
        );
    }

    // CRSH-ISC-22 (R2 re-review): the RAII guard clears the record's marker on Drop —
    // the mechanism that survives a panic in the spawned repair.
    #[test]
    fn repair_in_flight_guard_clears_marker_on_drop() {
        let set: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
        let key = [9u8; 32];
        set.lock().unwrap().insert(key);
        {
            let _guard = RepairInFlightGuard {
                set: set.clone(),
                key,
            };
            assert!(
                set.lock().unwrap().contains(&key),
                "marker present while guard lives"
            );
        } // guard drops here
        assert!(
            !set.lock().unwrap().contains(&key),
            "Drop must clear the record's in-flight marker"
        );
    }

    // CRSH-ISC-22 (R2 re-review): a PANIC in the spawned closure still clears the
    // marker, because Rust runs Drop on unwind — so a panicking repair cannot
    // permanently disable a record's self-heal. The `JoinHandle` returns `Err`
    // (panic isolated to the task), yet the marker is gone.
    #[tokio::test]
    async fn repair_in_flight_guard_clears_marker_on_panic() {
        let set: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
        let key = [11u8; 32];
        set.lock().unwrap().insert(key);
        let set2 = set.clone();
        let handle = tokio::spawn(async move {
            let _guard = RepairInFlightGuard { set: set2, key };
            panic!("simulated repair_rendezvous panic");
        });
        let joined = handle.await;
        assert!(joined.is_err(), "the spawned task panicked");
        assert!(
            !set.lock().unwrap().contains(&key),
            "Drop-on-unwind must clear the marker despite the panic"
        );
    }

    #[test]
    fn serve_lane_bounds_are_sane() {
        // #125 hardening invariants (compile-time): the reply cap MUST exceed one
        // fetcher's peak concurrent fragment fan-out (gui CHUNK_FETCH_CONCURRENCY 8 ×
        // share::FRAGMENT_FETCH_CONCURRENCY 8 = 64) or a single legitimate download
        // self-throttles past the answer window (xhigh review); it stays below the
        // intake cap so replies remain the tighter bound (the network work).
        const SINGLE_FETCHER_PEAK_FRAGMENTS: usize = 8 * 8;
        const {
            assert!(
                SERVE_QUEUE_CAP >= 64,
                "queue must hold a normal fetch burst"
            );
            assert!(
                MAX_CONCURRENT_SERVE_REPLIES > SINGLE_FETCHER_PEAK_FRAGMENTS,
                "one download's 64-fragment peak must not self-throttle"
            );
            assert!(
                MAX_CONCURRENT_SERVE_REPLIES < SERVE_QUEUE_CAP,
                "concurrent replies are the tighter bound"
            );
        }
    }

    /// **Record kind → shape.** Now that more than one shape is live, a write site
    /// that picked the wrong constant would address a *different record* and fail
    /// silently, so the mapping is pinned rather than left to review. This is the
    /// table the #232 review asked for once heterogeneous shapes existed.
    #[test]
    fn each_record_kind_uses_its_designed_shape() {
        // Chat / lobby / rooms / share discovery — unchanged by the DM work.
        assert_eq!(rendezvous::RecordShape::RENDEZVOUS.o_cnt(), 64);
        assert_eq!(rendezvous::RecordShape::RENDEZVOUS.max_value_len(), 16384);

        // The DM key record: one slot, full 32 KiB cap. A ~6.2 KiB signed record
        // fits with ample headroom (`docs/design/direct-messaging.md` DRAFT v6).
        assert_eq!(DM_KEY_RECORD_SHAPE.o_cnt(), 1);
        assert_eq!(DM_KEY_RECORD_SHAPE.max_value_len(), 32768);
        assert_eq!(DM_KEY_RECORD_SUBKEY, 0);
        assert!(DM_KEY_RECORD_SUBKEY < u32::from(DM_KEY_RECORD_SHAPE.o_cnt()));

        // The DM channel page: sixteen slots, 32 KiB each (1 MiB / 16 = 64 KiB is
        // above the per-subkey ceiling, so the full 32 KiB survives).
        assert_eq!(DM_PAGE_SHAPE.o_cnt(), 16);
        assert_eq!(DM_PAGE_SHAPE.max_value_len(), 32768);

        // The DM doorbell: thirty-two slots, 32 KiB each (1 MiB / 32 = 32 KiB is
        // exactly the per-subkey ceiling, which is WHY the slot count is 32 — the
        // top padding bucket of a first-contact entry must fit one subkey).
        assert_eq!(
            DM_DOORBELL_SHAPE.o_cnt(),
            daemonseed_core::dm::doorbell::DOORBELL_SLOTS
        );
        assert_eq!(DM_DOORBELL_SHAPE.o_cnt(), 32);
        assert_eq!(
            DM_DOORBELL_SHAPE.max_value_len(),
            daemonseed_core::dm::firstcontact::MAX_ENTRY_LEN,
            "the doorbell subkey cap and the first-contact entry ceiling are one \
             number: `doorbell_entry_must_fit` guards on the entry constant while \
             the network enforces the shape's, so a divergence would admit locally \
             and be refused on the wire (or the reverse)"
        );
        assert_eq!(DM_DOORBELL_SHAPE.max_value_len(), 32768);

        // The DM acknowledgement record: one current-state slot, full 32 KiB cap.
        // A maximal sealed acknowledgement is ~6.2 KiB, so the headroom is ample —
        // and `ack_record::a_maximal_record_fits_one_subkey` is what pins that from
        // the producing side.
        assert_eq!(
            DM_ACK_SHAPE.o_cnt(),
            daemonseed_core::dm::ack_record::ACK_RECORD_SLOTS
        );
        assert_eq!(DM_ACK_SHAPE.o_cnt(), 1);
        assert_eq!(DM_ACK_SHAPE.max_value_len(), 32768);
        assert_eq!(DM_ACK_SUBKEY, 0);
        assert!(DM_ACK_SUBKEY < u32::from(DM_ACK_SHAPE.o_cnt()));

        // The five kinds must stay distinct under one owner seed, or they would
        // collapse in the open-cache. **The key record and the acknowledgement
        // record share a shape**, so this pair is the one the set below cannot
        // separate — they are distinct records because their owner seeds derive
        // differently, never because their shapes do, and nothing here or in
        // `RecordShape` can enforce that. Asserted explicitly so a reader is not
        // left thinking the shape table separates them.
        assert_eq!(
            DM_ACK_SHAPE.o_cnt(),
            DM_KEY_RECORD_SHAPE.o_cnt(),
            "these two shapes are equal by design; separation is the owner seed's job"
        );
        let owner = crate::identity::rendezvous_owner_keypair(&[3u8; 32]).unwrap();
        let ids = [
            rendezvous::cached_record_id(&owner.key(), rendezvous::RecordShape::RENDEZVOUS),
            rendezvous::cached_record_id(&owner.key(), DM_KEY_RECORD_SHAPE),
            rendezvous::cached_record_id(&owner.key(), DM_PAGE_SHAPE),
            rendezvous::cached_record_id(&owner.key(), DM_DOORBELL_SHAPE),
        ];
        let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(
            distinct.len(),
            ids.len(),
            "two record kinds share a cached-record id under one owner"
        );
    }

    /// **The page shape and the page arithmetic are the same number.** `o_cnt` is
    /// part of the record address AND the modulus of `position_of`, so a shape
    /// typed independently of `PAGE_SLOTS` would keep every test in `paging` green
    /// while addressing a record the other party never sweeps — silently, with no
    /// error on any surface (ISC-C100). Pinned here because this crate is where the
    /// two facts finally meet.
    #[test]
    fn the_page_record_shape_is_the_page_slot_count() {
        // The ONE load-bearing assertion. A "does every `position_of` slot fit
        // inside the record" loop was deliberately REMOVED from here: after this
        // equality it reduces to `seq % PAGE_SLOTS < PAGE_SLOTS`, total by
        // construction and already covered verbatim by
        // `paging::a_slot_is_always_within_the_record`. It read as a second oracle
        // without being one, and a test that cannot fail is worse than no test —
        // it buys false confidence in review.
        assert_eq!(
            DM_PAGE_SHAPE.o_cnt(),
            daemonseed_core::dm::paging::PAGE_SLOTS,
            "the page record's subkey count must BE the slot arithmetic's modulus"
        );
    }

    /// A ratchet to derive page addresses from, built the cheap way: the RECIPIENT
    /// constructor takes only the PUBLIC half of the opening ephemeral and never
    /// inspects it, so no ephemeral keygen is needed. Its role fixes both
    /// directions, which is all an address needs — the absolute direction is
    /// irrelevant to the transport, and `daemonseed_core::dm::paging`'s own tests
    /// are where the role-to-direction mapping is pinned.
    ///
    /// The `daemonseed_core::kats::initialize_module_unsigned_test_binary()` is required because the derivations below
    /// are HKDF: the crypto module must be past its power-up self-tests. Idempotent
    /// and race-safe by design — a loser of the `PowerOff → SelfTest` CAS gets
    /// `AlreadyInitialized`, which is why the result is discarded here exactly as
    /// `daemonseed-core`'s tests discard it.
    fn page_ratchet() -> daemonseed_core::dm::ratchet::Ratchet {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let eph = daemonseed_core::identity::keys::derive_identity_keys(
            &daemonseed_core::identity::mnemonic::Mnemonic::generate().expect("mnemonic"),
            daemonseed_core::identity::keys::Identity::Primary,
        )
        .expect("derive identity keys");
        daemonseed_core::dm::ratchet::Ratchet::recipient(
            &PAGE_FIXTURE_SS0,
            Box::new(*eph.kem.encapsulation_key()),
        )
        .expect("open a recipient ratchet")
    }

    /// The `ss0` the page fixtures share — the ratchet and the address root must
    /// come from the same one, or the derivation refuses them (#270).
    const PAGE_FIXTURE_SS0: [u8; 32] = [0x5c; 32];

    /// A non-zero page for the address fixtures: on page 0 a position is
    /// numerically indistinguishable from its own slot, which is the degeneracy
    /// this file's other page tests were deliberately moved off.
    const PAGE_FIXTURE_PAGE: u64 = 3;

    /// A byte-distinct address root, so a derivation that mis-sliced its input
    /// would not pass.
    fn page_address_root() -> [u8; paging::ADDRESS_ROOT_LEN] {
        // **Derived from the same `ss0` as `page_ratchet`, not invented (#270).**
        // An address derivation refuses a root whose conversation is not the
        // ratchet's, so a hand-made root beside a real ratchet is precisely the
        // crossed pair that check exists to catch — it would fail here as a test
        // failure rather than in production as a silent stall. `AR` is not
        // invertible from a chosen value, so the fixture derives it.
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        daemonseed_core::dm::firstcontact::derive_channel_roots(&PAGE_FIXTURE_SS0)
            .expect("derive the fixture conversation's roots")
            .ar
    }

    /// A real derived sending address for `page`. Never hand-made: the seed inside
    /// has no constructor outside `daemonseed_core::dm::paging` (#244), and the
    /// address's TYPE is what #254 is about.
    fn sending_address(at: PagePosition) -> DmPageAddress<Sending> {
        DmPageAddress::sending(&page_address_root(), &page_ratchet(), at)
            .expect("derive a sending page address")
    }

    /// The sweep's counterpart of [`sending_address`] — a real derived address for
    /// the stream this end receives on, which is the only kind a sweep takes.
    fn receiving_address(page: u64) -> DmPageAddress<Receiving> {
        DmPageAddress::receiving(&page_address_root(), &page_ratchet(), page)
            .expect("derive a receiving page address")
    }

    /// A handle whose command channel is serviced by `service`, with no actor, no
    /// DHT and no attach. The channel is the observable: a command that reaches it
    /// was enqueued, and a call rejected before `send` leaves it empty.
    ///
    /// The channel is always SERVICED rather than left dangling, because
    /// `VeilidNetHandle::send` awaits a `oneshot` reply — an unserviced channel
    /// turns "the guard failed to fire" into a test that HANGS instead of one that
    /// fails, and a hanging test proves nothing to whoever removed the guard.
    fn detached_handle() -> (VeilidNetHandle, mpsc::Receiver<Command>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        (
            VeilidNetHandle {
                cmd_tx,
                write_latency: Arc::new(AtomicU64::new(0)),
            },
            cmd_rx,
        )
    }

    /// **A sweep result is tagged from the address that was swept, and two
    /// conversations do not share a tag.**
    ///
    /// `sweep_dm_page` needs a live DHT, so its tagging line is unreachable from
    /// any runnable test — and a mutation replacing it with a constant survived
    /// the whole suite. `DmPageSweep::for_address` exists so the tagging happens
    /// somewhere a unit test can call, and this is that test.
    ///
    /// The second assertion is what makes the first mean anything: comparing a
    /// result's tag against the address it came from passes for any value, a
    /// constant included, since both sides move together.
    #[test]
    fn a_sweep_result_carries_the_conversation_of_the_address_it_swept() {
        let outcome = rendezvous::SweepOutcome::default();
        let addr = receiving_address(PAGE_FIXTURE_PAGE);
        let swept = DmPageSweep::for_address(&addr, Vec::new(), outcome);
        assert_eq!(
            swept.conversation,
            *addr.conversation(),
            "the tag must come from the swept address"
        );

        // A different conversation, so a constant cannot satisfy this.
        let other_ss0 = [0xa7u8; 32];
        assert_ne!(
            other_ss0, PAGE_FIXTURE_SS0,
            "the two conversations must differ"
        );
        let other_roots = daemonseed_core::dm::firstcontact::derive_channel_roots(&other_ss0)
            .expect("the second conversation's roots");
        // Built the way `page_ratchet` builds its own, since this crate does not
        // depend on the ML-KEM crate directly and has no business naming its
        // key length.
        let eph = daemonseed_core::identity::keys::derive_identity_keys(
            &daemonseed_core::identity::mnemonic::Mnemonic::generate().expect("mnemonic"),
            daemonseed_core::identity::keys::Identity::Primary,
        )
        .expect("derive identity keys");
        let other_ratchet = daemonseed_core::dm::ratchet::Ratchet::recipient(
            &other_ss0,
            Box::new(*eph.kem.encapsulation_key()),
        )
        .expect("the second conversation's ratchet");
        let other_addr =
            DmPageAddress::receiving(&other_roots.ar, &other_ratchet, PAGE_FIXTURE_PAGE)
                .expect("the second conversation's address");
        let other_swept = DmPageSweep::for_address(&other_addr, Vec::new(), outcome);
        assert_ne!(
            other_swept.conversation, swept.conversation,
            "two conversations must not produce the same tag, or the tag \
             distinguishes nothing and a fan-out can still misattribute"
        );
    }

    /// **The refusal this replaces is now a thing that cannot be said.**
    ///
    /// A test used to stand here publishing to an address for one page while
    /// handing `publish_dm_page` a position from another, and asserting the
    /// mismatch came back as `DmPageWrongPage`. That call no longer type-checks:
    /// a sending address carries the position it writes (#269), so there is no
    /// second position to disagree with it and no error variant left to name.
    ///
    /// Recorded rather than silently dropped, because a deleted negative test
    /// reads the same whether its subject was fixed or forgotten. The state it
    /// guarded is refused by the type; the state `PagePosition::new` guards —
    /// a page above `MAX_PAGE`, or a slot outside the record — is asserted in
    /// `daemonseed_core::dm::paging`'s own tests, which is where the bound now
    /// lives.
    #[test]
    fn a_publish_address_carries_its_own_position_so_a_mismatch_is_unconstructible() {
        let at = paging::position_of(57);
        let address = sending_address(at);
        assert_eq!(
            address.at(),
            at,
            "the address must write the position it was derived for"
        );
        assert_eq!(
            address.page(),
            at.page(),
            "and its page must be that position's page, with nothing to compare at publish time"
        );
    }

    /// The positive control for the guard above: a position that DOES belong to its
    /// address reaches the actor, with the position intact.
    ///
    /// Without this, a guard that rejected every publish would pass the refusal test
    /// and break the transport outright.
    ///
    /// On a NON-ZERO page, for the reason the refusal test above gives: on page 0 the
    /// address's page, the position's page and the literal zero are all the same
    /// value, so nothing here would notice a comparison against a constant.
    #[tokio::test]
    async fn a_dm_page_publish_whose_position_matches_its_address_reaches_the_actor() {
        let (handle, mut cmd_rx) = detached_handle();
        let at = paging::position_of(57);
        assert_eq!((at.page(), at.slot(), at.seq()), (3, 9, 57));
        let frame = vec![0xde, 0xad];

        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::PublishDmPage {
                    address,
                    frame,
                    reply,
                } => {
                    let _ = reply.send(Ok(()));
                    // The position rides inside the address now, so what crosses
                    // the channel is read back off it rather than beside it.
                    (address.page(), address.at(), frame)
                }
                _ => panic!("expected a PublishDmPage command"),
            }
        });

        handle
            .publish_dm_page(sending_address(at), frame.clone())
            .await
            .expect("a matching position must publish");

        let (address_page, got_at, got_frame) = observed.await.expect("the observing task");
        assert_eq!(address_page, at.page());
        assert_eq!(got_at, at, "the position must cross the channel unchanged");
        assert_eq!(got_frame, frame);
    }

    /// **A swept subkey is placed on the ADDRESSED page, through the checked
    /// constructor.** The sweep's callers never see a bare subkey, so the
    /// slot-to-sequence arithmetic happens once, here.
    ///
    /// The out-of-record case is reported rather than skipped: dropping the slot
    /// would hand a collector a silently short page under an `Ok`, which is a lost
    /// message. It is reachable only if the record's `o_cnt` stops agreeing with
    /// `PAGE_SLOTS` (ISC-C100) — the page cannot be at fault, because
    /// `DmPageAddress` refuses one above `MAX_PAGE` at construction.
    #[test]
    fn a_swept_subkey_is_placed_on_the_addressed_page() {
        let at = dm_page_position_of_slot(3, 9).expect("slot 9 is inside the record");
        assert_eq!((at.page(), at.slot()), (3, 9));
        assert_eq!(
            at.seq(),
            3 * u64::from(paging::PAGE_SLOTS) + 9,
            "the sequence number must be the ADDRESSED page's, not the slot's — \
             placing a slot on page 0 regardless is how a page's frames get read \
             as another page's"
        );

        for slot in [u32::from(paging::PAGE_SLOTS), 31, u32::MAX] {
            let err = dm_page_position_of_slot(3, slot)
                .expect_err("a slot the record cannot hold must be reported");
            assert!(
                matches!(
                    err,
                    VeilidNetError::DmPageSlotOutsideRecord { page: 3, slot: s } if s == slot
                ),
                "unexpected error for slot {slot}: {err:?}"
            );
        }
    }

    /// **The sweep places its slots on the page the ADDRESS names, and that argument
    /// is now under test.** It was not: the placement lived inline in
    /// `sweep_dm_page`, which cannot run without a live DHT, so replacing its page
    /// argument with a literal `0` left every runnable test green — and both
    /// `#[ignore]`d two-node tests as well, since each of them sweeps page 0 only.
    ///
    /// The consequence of that mutation is not a wrong number in a log. Every frame
    /// on every page would come back carrying a page-0 sequence number, so
    /// `ParsedFrame::open`'s found-at check would reject every message from page 1
    /// onward as tampered — a conversation that dies silently at its seventeenth
    /// message.
    ///
    /// So the page here is 3 and the slots are chosen to make page, slot and sequence
    /// three different values.
    #[test]
    fn swept_slots_are_placed_on_the_page_the_address_names() {
        const PAGE: u64 = 3;
        let address = receiving_address(PAGE);
        let raw = vec![
            (9u32, b"nine".to_vec()),
            (0u32, b"zero".to_vec()),
            (u32::from(paging::PAGE_SLOTS) - 1, b"last".to_vec()),
        ];

        let placed = dm_page_place_swept(&address, raw).expect("every slot is inside the record");

        assert_eq!(placed.len(), 3, "no slot may be dropped");
        for (at, bytes) in &placed {
            assert_eq!(
                at.page(),
                PAGE,
                "a swept slot must be placed on the ADDRESSED page, not on page 0 — \
                 {bytes:?} landed on page {}",
                at.page()
            );
            assert_eq!(
                at.seq(),
                PAGE * u64::from(paging::PAGE_SLOTS) + u64::from(at.slot()),
                "the sequence number must be the addressed page's"
            );
            assert_ne!(
                at.seq(),
                u64::from(at.slot()),
                "on page 0 a sequence number equals its slot and this test is blind"
            );
        }
        // The exact sequence numbers, pinned: 48, 57 and 63 on page 3. A page dropped
        // anywhere in the placement yields 0, 9 and 15 instead.
        let seqs: Vec<u64> = placed.iter().map(|(at, _)| at.seq()).collect();
        assert_eq!(seqs, [57, 48, 63], "slot order is preserved, page applied");
        // The bytes stay with their own slot.
        assert_eq!(placed[0].1, b"nine".to_vec());
        assert_eq!(placed[0].0.slot(), 9);

        // And a slot the page cannot hold fails the whole placement rather than being
        // skipped: a skipped slot is a message missing from an `Ok` page.
        let err = dm_page_place_swept(
            &receiving_address(PAGE),
            vec![(u32::from(paging::PAGE_SLOTS), b"past the end".to_vec())],
        )
        .expect_err("a slot outside the record must fail the sweep");
        assert!(
            matches!(
                err,
                VeilidNetError::DmPageSlotOutsideRecord { page: PAGE, .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    /// **A page record whose subkey count is not the page slot count is refused
    /// before any slot is read, in BOTH directions (#254).**
    ///
    /// The too-many direction was already visible: those slots will not place. The
    /// too-few direction was invisible, and is the reason this check exists. The sweep
    /// is bounded by the record's own `o_cnt`, so a short record yields no unplaceable
    /// slot at all — every position places, the missing slots are never attempted, and
    /// the caller gets `Ok` with a page that is silently truncated. That is the lost
    /// message under an `Ok` that `DmPageSlotOutsideRecord`'s own docs say cannot
    /// happen, arriving from the side nothing downstream can see.
    #[test]
    fn a_page_record_whose_shape_is_not_the_page_shape_is_refused() {
        let slots = paging::PAGE_SLOTS;

        dm_page_shape_must_match(3, slots).expect("the page shape itself must pass");

        for o_cnt in [1, slots - 1, slots + 1, 32, 64, 1024] {
            let err = dm_page_shape_must_match(3, o_cnt)
                .expect_err("a shape that is not the page shape must be refused");
            assert!(
                matches!(
                    err,
                    VeilidNetError::DmPageShapeMismatch { page: 3, o_cnt: c } if c == o_cnt
                ),
                "unexpected error for o_cnt {o_cnt}: {err:?}"
            );
        }
        // Named separately because it is the direction with no downstream symptom: a
        // 15-slot record loses the sixteenth message of every page under an `Ok`.
        assert!(
            dm_page_shape_must_match(3, slots - 1).is_err(),
            "a record SHORTER than a page must be refused — nothing later can see it"
        );
    }

    /// **The sweep handle passes the address through untouched.** The publish path had
    /// this coverage and the sweep path did not, so nothing observed that the page and
    /// stream a caller asked for are the page and stream the actor is told to sweep.
    ///
    /// A non-zero page, so an address rebuilt on page 0 anywhere between the handle
    /// and the command is visible.
    #[tokio::test]
    async fn a_dm_page_sweep_passes_its_address_to_the_actor_unchanged() {
        let (handle, mut cmd_rx) = detached_handle();
        const PAGE: u64 = 3;
        let expected_seed = receiving_address(PAGE).with_owner_seed(|b| *b);
        let expected_direction = receiving_address(PAGE).direction();

        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::SweepDmPage { address, reply } => {
                    let seen = (
                        address.page(),
                        address.direction(),
                        address.with_owner_seed(|b| *b),
                    );
                    let _ = reply.send(Ok(DmPageSweep {
                        conversation: *address.conversation(),
                        slots: Vec::new(),
                        outcome: rendezvous::SweepOutcome::default(),
                    }));
                    seen
                }
                _ => panic!("expected a SweepDmPage command"),
            }
        });

        let swept = handle
            .sweep_dm_page(receiving_address(PAGE))
            .await
            .expect("the sweep reaches the actor");
        assert!(swept.slots.is_empty(), "the stub actor returns no slots");
        // The tag rides back with the frames (#270): a caller fanning out over
        // several conversations reads it off the result rather than matching on
        // the order it dispatched in.
        assert_eq!(
            swept.conversation,
            *receiving_address(PAGE).conversation(),
            "the sweep must name the conversation it was asked for"
        );

        let (page, direction, seed) = observed.await.expect("the observing task");
        assert_eq!(page, PAGE, "the actor must sweep the page the caller named");
        assert_eq!(
            direction, expected_direction,
            "the stream must cross the channel unchanged — the other one is a valid \
             address for this end's own writes"
        );
        assert_eq!(
            seed, expected_seed,
            "the record the actor opens must be the record the address named"
        );
    }

    /// A panicking blocking serve step answers NOT_FOUND rather than nothing.
    ///
    /// The `JoinError` is a real one — produced by actually panicking a
    /// `spawn_blocking` task — not a constructed stand-in, because the point of the
    /// arm is what happens when tokio reports a panic and a hand-rolled error would
    /// only prove the `match` compiles.
    ///
    /// Both controls matter. The Ok path must pass its payload through unchanged,
    /// or an implementation that answered NOT_FOUND unconditionally would satisfy
    /// the panic assertion. And NOT_FOUND must differ from that payload, or the two
    /// assertions could both hold on a function that returned one constant.
    #[tokio::test]
    async fn a_panicking_serve_step_answers_not_found() {
        let served = b"a served response".to_vec();
        assert_eq!(
            super::serve_response_or_not_found(Ok(served.clone())),
            served,
            "the Ok path must pass its payload through, or the assertion below is \
             satisfied by a function that always answers NOT_FOUND"
        );

        let join_err = tokio::task::spawn_blocking(|| panic!("serve step panicked"))
            .await
            .expect_err("the task panicked, so joining it must fail");
        assert!(join_err.is_panic(), "expected a panic, not a cancellation");

        let not_found = share::encode_response_not_found();
        assert_ne!(
            not_found, served,
            "NOT_FOUND is indistinguishable from the served payload, so neither \
             assertion here proves anything"
        );
        assert_eq!(super::serve_response_or_not_found(Err(join_err)), not_found);
    }

    /// Every funnel enqueue keys on the helper, and none on a raw seed (#256).
    ///
    /// **A source-level probe, because the behavioural one cannot reach here.**
    /// The four re-keyed enqueue sites are inside `actor_loop`, so no unit test
    /// constructs them; the sibling test below pins the helper's contract and is
    /// blind to a single site reverted to `record: owner_seed`. That reversion is
    /// the exact failure this change exists to prevent — it splits one record's
    /// FIFO into two queues, with `Ok(())` on every surface — so it needs a probe
    /// that can see it.
    ///
    /// The instrument is the one this file already uses for
    /// `both_page_paths_open_the_record_through_one_shape`: read the production
    /// half of the source and count. Brittle on purpose — a new enqueue site is
    /// supposed to make someone look at this number and decide, which is the
    /// review moment the copy-paste hazard needs.
    #[test]
    fn every_funnel_enqueue_keys_on_the_helper() {
        let src = include_str!("actor.rs");
        let (prod, _) = src
            .split_once("#[cfg(test)]")
            .expect("the tests-module marker moved");

        // Assembled from fragments so this test's own source does not count as a
        // match — the same trick the shape probe uses.
        let keyed: String = ["record: funnel_record", "_key("].concat();
        assert_eq!(
            prod.matches(keyed.as_str()).count(),
            6,
            "exactly six enqueue sites set `record:` through the helper. A different \
             count means an enqueue site was added, removed, or keyed another way — \
             decide which, then update this number"
        );

        // The negative half: no raw-seed key survives anywhere in production.
        for raw in [
            ["record: owner", "_seed"].concat(),
            ["record: advert.owner", "_seed"].concat(),
        ] {
            assert_eq!(
                prod.matches(raw.as_str()).count(),
                0,
                "a funnel enqueue keys on the raw seed again ({raw}) — that splits one \
                 record's FIFO into two queues and reports Ok() on every surface"
            );
        }

        // Positive control: the needles are real. If the fragments ever stop
        // matching anything at all, the assertions above pass vacuously.
        assert!(
            prod.contains(["funnel_record", "_key"].concat().as_str()),
            "the helper's name is not in the production source — this probe is \
             matching nothing and its zero-counts prove nothing"
        );
    }

    /// The funnel key is the public key, and the mapping is injective (#256).
    ///
    /// **Honest scope: this pins the helper, not the call sites.** The four
    /// re-keyed enqueue sites live inside the actor loop and no unit test reaches
    /// them; what makes them consistent is that they all call `funnel_record_key`,
    /// which is a structural property a reader checks, not one this test proves.
    /// What it does prove is the contract every one of them depends on — that the
    /// key is not the seed, and that distinct seeds stay distinct, which is what
    /// keeps each record's FIFO a single queue.
    #[test]
    fn the_funnel_key_is_the_public_key_and_stays_injective() {
        let a = [0x11u8; 32];
        let b = [0x12u8; 32];

        assert_ne!(
            funnel_record_key(&a),
            a,
            "the funnel key must not be the seed — keying on the secret is what #244 removed"
        );
        assert_eq!(
            funnel_record_key(&a),
            identity::rendezvous_owner_public_bytes(&a),
            "the funnel key must be exactly the record's own owner public key"
        );
        // Injective on distinct seeds: two records must not collapse into one
        // FIFO, and one record must not split into two.
        assert_ne!(funnel_record_key(&a), funnel_record_key(&b));
    }

    /// **How a DM page write is classified in the funnel.** Every field asserted
    /// here fails silently if it is wrong, and the kind fails worst: `Ring` is the
    /// funnel's name for "never coalesce", and a `CurrentState` kind in its place
    /// would let two queued writes to one page — two DIFFERENT messages, in two
    /// different slots — collapse last-writer-wins, dropping one off the wire while
    /// its `reply` still reports `Ok(())`. Nothing downstream can see that, so it is
    /// pinned at the point of construction rather than left to the live oracle.
    #[test]
    fn a_dm_page_write_is_a_chat_lane_write_that_never_coalesces() {
        let frame = vec![0xde, 0xad, 0xbe, 0xef];
        let (reply, _rx) = oneshot::channel();

        // Sequence 57 is chosen, not arbitrary. Its slot is 9: non-zero (so a
        // request that hard-wired subkey 0 differs), not 8 or 16 (so a second
        // modulus applied on the way to dispatch differs), and 9+1 is still inside
        // the record (so an off-by-one shows up as a wrong slot rather than as an
        // out-of-range error some other check would catch first).
        //
        // And its page is 3, which is the part that took a mutation run to get
        // right: on page ZERO a position is indistinguishable from its own slot, so
        // `position_of(at.slot())` inserted anywhere between here and dispatch is a
        // no-op and every assertion below still passes. A non-zero page makes the
        // slot, the sequence number and the page three different values.
        let at = paging::position_of(3 * u64::from(paging::PAGE_SLOTS) + 9);
        assert_eq!((at.page(), at.slot(), at.seq()), (3, 9, 57));
        let address = sending_address(at);
        // A plain copy, deliberately: `address` is MOVED into the request below, and
        // the assertions afterwards are about what the request did with it. Test-only
        // — this is the one place a non-zeroizing copy is the point, not the bug.
        let seed_bytes = address.with_owner_seed(|b| *b);

        let req = dm_page_write_request(address, frame.clone(), reply);

        assert_eq!(
            req.class,
            WriteClass::Chat,
            "a DM is chat: its writes take the chat lane, never the keepalive one"
        );
        assert_eq!(
            req.kind,
            WriteKind::Ring,
            "a page slot is written once and must never be coalesced away"
        );
        // **The record id is the owner's PUBLIC key, and is NOT the seed (#244).**
        // Both are `[u8; 32]`, so putting the secret back where the identity belongs
        // type-checks everywhere and shows up on no surface — which is why both
        // halves are asserted. The positive pins WHICH value it is (a hash, or the
        // wrong key, fails it); the negative is the direct regression guard.
        assert_eq!(
            req.record,
            identity::rendezvous_owner_public_bytes(&seed_bytes),
            "the funnel's FIFO + coalescing scope is the page record's PUBLIC \
             identity — what the DHT address derives from"
        );
        assert_ne!(
            req.record, seed_bytes,
            "the record id must never carry the owner SEED: it is the conversation's \
             write capability, and the scheduler holds this value in a pending-queue \
             key that does not zeroize"
        );
        assert!(
            req.deadline.is_none(),
            "a chat-class write is already the highest class; a deadline would only \
             reorder it against its own lane"
        );
        assert!(
            req.reply.is_some(),
            "the caller awaits this write — a dropped reply hangs `publish_dm_page`"
        );

        match req.item {
            ProdWrite::DmPage {
                address,
                frame: dispatched,
            } => {
                let dispatched_at = address.at();
                assert_eq!(
                    address.with_owner_seed(|b| *b),
                    seed_bytes,
                    "the dispatch token carries the seed itself — the write cannot \
                     be signed without it — and must reach dispatch unchanged"
                );
                // Weaker than it was, and honestly so. There is no longer a
                // separate position for the request to mangle — this reads the
                // one the address carries — so what it still catches is the
                // address itself being swapped or re-derived on the way to
                // dispatch, not arithmetic applied to a loose value. The
                // arithmetic it used to guard cannot be performed any more.
                assert_eq!(
                    dispatched_at, at,
                    "the address that reaches dispatch must be the one the caller \
                     derived, still naming the position it was built for"
                );
                assert_eq!(
                    dispatched_at.page(),
                    address.page(),
                    "the position and the address must still name one page at \
                     dispatch: they are checked against each other once, at the \
                     public handle, and nothing between may pull them apart"
                );
                assert_eq!(
                    dispatched, frame,
                    "the frame is opaque at this layer and must arrive byte-identical"
                );
            }
            _ => panic!("a DM page write must dispatch as its own ProdWrite variant"),
        }
    }

    /// **Publish and sweep cannot disagree about the page record's shape.** `o_cnt`
    /// is part of the record address, so two shapes means two records: the write
    /// succeeds, the sweep returns empty, and nothing errors anywhere. The
    /// structural guard is that both paths open through one function; what this
    /// test pins is the two facts that guard rests on, neither of which is
    /// observable without a live DHT — the single opener names the page shape, and
    /// both transport fns route through it.
    ///
    /// Needles are assembled from fragments so this test's own source text does not
    /// self-match, as `release_private_route_only_called_through_release_tolerant`
    /// does above.
    #[test]
    fn both_page_paths_open_the_record_through_one_shape() {
        let src = include_str!("actor.rs");
        // Production half only — this module names both symbols freely.
        let (prod, _) = src
            .split_once("#[cfg(test)]")
            .expect("the tests-module marker moved");

        let shape: String = ["DM_PAGE", "_SHAPE"].concat();
        assert_eq!(
            prod.matches(shape.as_str()).count(),
            2,
            "the page shape must be named exactly twice outside the tests: its own \
             definition, and the single binding inside the one opener that the cache \
             id and both open modes are all built from. A third naming is a second \
             open site, which is how publish and sweep come to address different \
             records"
        );

        // The count was 3 until #253 gave the opener a second mode (create for the
        // publish path, report-absent for the sweep), and dropping it to 2 by binding
        // the shape to a local was NOT sufficient on its own — it removed the very
        // check it appeared to strengthen. Under the old arrangement the single
        // open's shape argument was one of the three counted namings, so retargeting
        // it at another record's shape dropped the count to 2 and failed this test.
        // With both modes reading a local, retargeting ONE of them names a different
        // constant and leaves this count at 2 untouched: publish and sweep address
        // different records, the write succeeds, the sweep is permanently empty, and
        // nothing errors — precisely the ISC-C100 failure this guard exists for. The
        // count above therefore no longer stands alone; the assertion below is what
        // actually closes that hole, by pinning that the opener's body names a shape
        // constant exactly once.
        //
        // (Found by an independent review lens, which ran the mutation — retargeting
        // the report-absent mode at the key-record shape — and got a clean 123-pass
        // run. Recorded because the reasoning that produced the weaker guard was
        // confident and wrong.)
        let opener_start = prod
            .find("async fn dm_page_open")
            .expect("the opener's definition moved");
        let opener_body = &prod[opener_start..];
        let opener_body = &opener_body[..opener_body
            .find("\n}\n")
            .expect("the opener's closing brace moved")];
        let shape_suffix: String = ["_", "SHAPE"].concat();
        assert_eq!(
            opener_body.matches(shape_suffix.as_str()).count(),
            1,
            "the opener's body must name a shape constant exactly ONCE — the single \
             binding both open modes and the cache id are built from. A second naming \
             is one mode addressing a different record from the other, which is the \
             shape disagreement this test exists to make unrepresentable"
        );
        //
        // The shape count above is the load-bearing guard: an inline open must name a
        // shape, so an extra naming IS a second open site. This is the positive half —
        // the opener is defined once and reached from the three places that open a
        // page: `publish_dm_page`, `sweep_dm_page`, and the pre-warm in the
        // `PublishDmPage` arm that keeps the cold open off the chat lane.
        //
        // An exact count is deliberate, and so is its brittleness: a fourth caller has
        // to come and edit this number, which is the moment to ask whether it should
        // be going through the opener at all. Bump it only after answering that.
        // The opener is DEFINED once (the definition is generic over the lease
        // lifetime, so the needle stops before the parameter list) and CALLED exactly
        // three times: `publish_dm_page`, `sweep_dm_page`, and the publish pre-warm.
        //
        // An exact count is deliberate, and so is its brittleness: a fourth caller has
        // to come and edit this number, which is the moment to ask whether it should
        // be going through the opener at all. Bump it only after answering that.
        let opener: String = ["dm_page", "_open"].concat();
        let defined: String = ["async fn ", opener.as_str()].concat();
        assert_eq!(
            prod.matches(defined.as_str()).count(),
            1,
            "the opener is defined exactly once"
        );
        assert_eq!(
            prod.matches([opener.as_str(), "("].concat().as_str())
                .count(),
            3,
            "the opener must be called exactly three times — from `publish_dm_page`, \
             `sweep_dm_page`, and the publish pre-warm. A page path that opened its \
             own record would be free to open a different one"
        );
    }

    /// **Only the page opener may bound the open cache (#252), and only one ring
    /// may exist — together those are the safety property of the whole bound.**
    ///
    /// `rendezvous::open_page_bounded` evicts from the ring, never from the cache, so
    /// an entry that never enters a ring cannot be chosen — which is what lets the
    /// shared entries keep the open-once contract #128 D-0a settled. The lobby record
    /// is the one that matters: every share advert and the lobby subscription derive
    /// the SAME owner seed, so closing it takes a live handle from callers still using
    /// it. `BoundedRing`'s fields are private and this crate exposes no way to write
    /// one except through the opener, so a second *writer* is unrepresentable; what is
    /// still representable, and what this test pins, is a second call site, a second
    /// ring, or an opener that stopped closing what it evicts.
    ///
    /// The ring count is the sharpest of the three. Replacing any `page_recency`
    /// clone with a fresh `Arc` gives each spawned publish and sweep a private ring,
    /// nothing ever reaches the bound, and the leak is total and silent — every other
    /// test in this crate still passes.
    ///
    /// Needles assembled from fragments so this test's own source does not
    /// self-match, as the tests above do.
    #[test]
    fn only_the_page_opener_bounds_the_open_cache() {
        let src = include_str!("actor.rs");
        let (prod, _) = src
            .split_once("#[cfg(test)]")
            .expect("the tests-module marker moved");

        let ring: String = ["Bounded", "Ring::new("].concat();
        assert_eq!(
            prod.matches(ring.as_str()).count(),
            1,
            "exactly ONE page ring exists, built once in the actor and shared by \
             clone with every spawned publish and sweep. A second construction is a \
             per-task private ring: each bounds only its own opens, the shared cache \
             is never held at the bound, and nothing is ever closed"
        );

        let bound: String = ["open_page", "_bounded("].concat();
        assert_eq!(
            prod.matches(bound.as_str()).count(),
            1,
            "the open cache is bounded from exactly ONE place. A second call site \
             puts ids from another record family into a ring, and those ids then \
             become evictable — including the shared lobby record, which several \
             callers hold open at once"
        );

        // And that call belongs to the page opener rather than merely to this file —
        // a call in a sibling function would satisfy the count above while bounding a
        // family that has no business being bounded. Checked together with the two
        // things the opener supplies that no unit test can reach: the capacity, and a
        // close that actually releases the evicted record on the network.
        let opener_start = prod
            .find("async fn dm_page_open")
            .expect("the opener's definition moved");
        let opener_body = &prod[opener_start..];
        let opener_body = &opener_body[..opener_body
            .find("\n}\n")
            .expect("the opener's closing brace moved")];
        for (needle, why) in [
            (
                bound.clone(),
                "the single bounding call belongs to the page opener, the only path \
                 that opens a page record",
            ),
            (
                ["DM_PAGE_CACHE", "_CAPACITY"].concat(),
                "and it passes the shared capacity constant, not a number typed here \
                 — a local literal drifts from the constant the doc reasons about",
            ),
            (
                ["cached_record", "_id("].concat(),
                "the cache id is derived ONCE and that one binding is what both the \
                 cache and the ring are keyed on. A second derivation is free to name \
                 another shape — the ISC-C100 failure by a third door, and one the \
                 shape count cannot see because a different family's constant does \
                 not carry this one's suffix",
            ),
            (
                ["record", "_lock("].concat(),
                "and the close runs under the EVICTED record's own serialization \
                 lock, which every page open already holds across its open. Without \
                 it the close can kill a session a concurrent opener of that same \
                 record has just established — the lease cannot cover this, because \
                 the victim is by definition unleased",
            ),
            (
                ["close_dht", "_record("].concat(),
                "and its eviction closes the record. Dropping the map entry alone \
                 leaves the record open on the network, which is the cardinality the \
                 bound exists to reclaim — a stand-in closure in a unit test proves \
                 only that SOME closure ran",
            ),
            (
                ["evicted.into", "_key()"].concat(),
                "closing the key of the handle that was actually evicted, not one \
                 computed at the call site, is what binds the close to the removal",
            ),
        ] {
            assert_eq!(opener_body.matches(needle.as_str()).count(), 1, "{why}");
        }
    }

    // ── Direct messaging (#233): the doorbell transport ───────────────────

    /// **The doorbell shape and the doorbell slot arithmetic are the same
    /// number.** `o_cnt` is part of the record address AND the modulus of
    /// `doorbell::slot_for`, so a shape typed independently of `DOORBELL_SLOTS`
    /// would keep every test in `doorbell` green while addressing a record no
    /// sender writes to — silently, with no error on any surface. Pinned here
    /// because this crate is where the two facts meet.
    #[test]
    fn the_doorbell_record_shape_is_the_doorbell_slot_count() {
        assert_eq!(
            DM_DOORBELL_SHAPE.o_cnt(),
            daemonseed_core::dm::doorbell::DOORBELL_SLOTS,
            "the doorbell record's subkey count must BE the slot arithmetic's modulus"
        );
    }

    /// **An entry at the subkey cap is accepted and one byte more is refused.**
    ///
    /// The exact-cap case is the load-bearing one, and it is why this is not
    /// written as a bare "big entries are refused". `firstcontact`'s top padding
    /// bucket is sized so a token-bearing entry fills the subkey, so an off-by-one
    /// in the wrong direction here refuses the very entries the padding ladder was
    /// built to allow — and it would do so only for the largest ones, which is
    /// precisely the case a hand test is least likely to construct.
    #[test]
    fn a_doorbell_entry_at_the_cap_is_accepted_and_one_byte_more_is_refused() {
        let max = daemonseed_core::dm::firstcontact::MAX_ENTRY_LEN;
        assert_eq!(max, 32768, "the frozen per-subkey ceiling");

        for len in [0, 1, 18 * 1024, 25600, max - 1, max] {
            doorbell_entry_must_fit(len).unwrap_or_else(|e| {
                panic!("{len} bytes is inside the {max}-byte cap and must be admitted: {e:?}")
            });
        }

        let err = doorbell_entry_must_fit(max + 1)
            .expect_err("one byte above the cap must be refused locally");
        assert!(
            matches!(
                err,
                VeilidNetError::DmDoorbellEntryTooLarge { len, max: m } if len == max + 1 && m == max
            ),
            "the refusal must name the length and the true cap: {err:?}"
        );
    }

    /// **A slot outside the record is refused, and every slot inside it is not.**
    ///
    /// The whole in-range set is checked rather than a sample, because the interesting
    /// boundary is `DOORBELL_SLOTS - 1` — a `>` written for a `>=` admits exactly one
    /// value, the last slot, and `doorbell::slot_for` reaches it 1/32 of the time.
    #[test]
    fn a_doorbell_slot_outside_the_record_is_refused() {
        let slots = daemonseed_core::dm::doorbell::DOORBELL_SLOTS;

        for slot in 0..slots {
            doorbell_slot_must_be_in_record(slot)
                .unwrap_or_else(|e| panic!("slot {slot} is inside the record: {e:?}"));
        }

        for slot in [slots, slots + 1, 64, 256, u16::MAX] {
            let err = doorbell_slot_must_be_in_record(slot)
                .expect_err("a slot the record cannot hold must be refused");
            assert!(
                matches!(
                    err,
                    VeilidNetError::DmDoorbellSlotOutsideRecord { slot: s } if s == u32::from(slot)
                ),
                "unexpected error for slot {slot}: {err:?}"
            );
        }
    }

    /// **A swept subkey is placed in its slot, and one the record cannot hold is
    /// reported rather than skipped.** A skipped slot is a knock the recipient
    /// never sees under an `Ok` — the same reasoning as
    /// `a_swept_subkey_is_placed_on_the_addressed_page`.
    #[test]
    fn a_swept_doorbell_subkey_is_placed_in_its_slot() {
        let slots = daemonseed_core::dm::doorbell::DOORBELL_SLOTS;

        let placed = doorbell_place_swept(vec![
            (0, vec![0xa0]),
            (6, vec![0xa6]),
            (u32::from(slots) - 1, vec![0xff]),
        ])
        .expect("every subkey is inside the record");
        assert_eq!(
            placed,
            vec![(0u16, vec![0xa0]), (6, vec![0xa6]), (slots - 1, vec![0xff])],
            "the slot must be the subkey it came back in, and the bytes must be untouched"
        );

        // Reachable only if the record's o_cnt exceeds DOORBELL_SLOTS, which the
        // shape guard refuses before any GET — so this is the second line, kept
        // because the alternative to reporting is dropping a knock.
        let err = doorbell_place_swept(vec![(0, vec![0xa0]), (u32::from(slots), vec![0xbb])])
            .expect_err("a subkey the doorbell cannot hold must be reported");
        assert!(
            matches!(
                err,
                VeilidNetError::DmDoorbellSlotOutsideRecord { slot } if slot == u32::from(slots)
            ),
            "unexpected error: {err:?}"
        );
    }

    /// **How a doorbell knock is classified in the funnel.** Every field asserted
    /// here fails silently if it is wrong, and the coalescing id fails worst: one
    /// doorbell record is shared by every sender in the world, so a CONSTANT
    /// logical id — the shape the key record can afford, having exactly one record
    /// per owner seed — would collapse two knocks from two local identities to one
    /// recipient into a single write, and the loser's first contact would never
    /// reach the wire while its `reply` reported `Ok(())`.
    #[test]
    fn a_doorbell_write_takes_its_dispatchs_class_and_coalesces_per_slot() {
        let owner_seed = [0x5au8; 32];
        let entry = vec![0xde, 0xad, 0xbe, 0xef];
        let (reply, _rx) = oneshot::channel();

        // Slot 6 is chosen, not arbitrary: it is the KAT slot `doorbell.rs` pins for
        // alice→bob, it is non-zero (so a request that hard-wired slot 0 differs) and
        // it is not a power of two (so a stray second modulus on the way to dispatch
        // differs).
        let req = doorbell_entry_write_request(
            owner_seed,
            6,
            entry.clone(),
            DoorbellDispatch::Reseed,
            reply,
        );

        // **Both mappings, and both directions.** `direct-messaging.md:127-128` puts
        // the first dispatch of a user send in the chat lane and every
        // scheduler-driven re-dispatch at rank 4. Asserting only one of them would
        // pass on a `classify` that returned a constant.
        assert_eq!(
            req.class,
            WriteClass::Keepalive,
            "a scheduler-driven re-seed competes in the non-chat window, exactly as \
             the key-record keep-alive does (:128)"
        );
        let (first_reply, _first_rx) = oneshot::channel();
        let first = doorbell_entry_write_request(
            owner_seed,
            6,
            entry.clone(),
            DoorbellDispatch::FirstSend,
            first_reply,
        );
        assert_eq!(
            first.class,
            WriteClass::Chat,
            "the first dispatch of a user's first-contact send is a user action \
             wanting user-action latency — one write per action, not a burst (:127)"
        );
        assert_ne!(
            first.class, req.class,
            "the two dispatches must not collapse to one class, or the split :127-128 \
             draws is not being made at all"
        );
        assert_eq!(DoorbellDispatch::FirstSend.classify(), WriteClass::Chat);
        assert_eq!(DoorbellDispatch::Reseed.classify(), WriteClass::Keepalive);

        // The kind does NOT vary with the dispatch: `:128` fixes the logical id as
        // the slot for both, so a re-seed supersedes the send it repeats.
        assert_eq!(
            first.kind, req.kind,
            "both dispatches must coalesce on the same key, or a re-seed would not \
             supersede the send it repeats"
        );
        assert_eq!(
            req.kind,
            WriteKind::CurrentState {
                logical_id: doorbell_coalescing_id(6)
            },
            "a retry re-lands in the sender's own slot and is DEFINED to overwrite its \
             previous entry, so a queued older knock must be superseded — the opposite \
             of the page write's Ring"
        );

        // The load-bearing half: two slots must not share a coalescing id. Comparing
        // a request's id against `doorbell_coalescing_id(6)` alone passes for a
        // constant, since both sides move together.
        assert_ne!(
            doorbell_coalescing_id(6),
            doorbell_coalescing_id(7),
            "two slots sharing a coalescing id silently drops one sender's knock"
        );
        let (other_reply, _other_rx) = oneshot::channel();
        let other = doorbell_entry_write_request(
            owner_seed,
            7,
            entry.clone(),
            DoorbellDispatch::Reseed,
            other_reply,
        );
        assert_ne!(
            req.kind, other.kind,
            "two knocks in two slots of ONE doorbell must not coalesce — same record, \
             so the logical id is the only thing separating them"
        );
        assert_eq!(
            req.record, other.record,
            "and they must still share a record, or the coalescing scope is not the \
             thing this test claims it is"
        );

        // The record id is the owner's PUBLIC key, not the seed. Both are `[u8; 32]`,
        // so the substitution type-checks everywhere and shows on no surface. The
        // doorbell seed is world-derivable and therefore not a secret, so the #244
        // capability argument does not apply here — but the FIFO-splitting argument
        // does, and it is what this pins.
        assert_eq!(
            req.record,
            identity::rendezvous_owner_public_bytes(&owner_seed),
            "the funnel's FIFO + coalescing scope is the doorbell record's PUBLIC \
             identity — what the DHT address derives from"
        );
        assert_ne!(
            req.record, owner_seed,
            "keying on the raw seed splits one record's FIFO into two queues"
        );
        assert!(
            req.deadline.is_none(),
            "there is no hard DHT expiry anywhere in the DM path, only eviction \
             pressure, so no DM write carries a deadline"
        );
        assert!(
            req.reply.is_some(),
            "the caller awaits this write — a dropped reply hangs `publish_doorbell_entry`"
        );

        match req.item {
            ProdWrite::DoorbellEntry {
                owner_seed: dispatched_seed,
                slot: dispatched_slot,
                entry: dispatched_entry,
            } => {
                assert_eq!(
                    dispatched_seed, owner_seed,
                    "the dispatch token carries the seed the write is signed with"
                );
                assert_eq!(
                    dispatched_slot, 6,
                    "the slot must reach dispatch unchanged — it is the subkey written"
                );
                assert_eq!(
                    dispatched_entry, entry,
                    "the entry is opaque at this layer and must arrive byte-identical"
                );
            }
            _ => panic!("a doorbell write must dispatch as its own ProdWrite variant"),
        }
    }

    /// The publish handle passes the seed, slot and entry to the actor untouched.
    #[tokio::test]
    async fn a_doorbell_publish_reaches_the_actor_unchanged() {
        let (handle, mut cmd_rx) = detached_handle();
        let owner_seed = [0x5au8; 32];
        let entry = vec![0xde, 0xad, 0xbe, 0xef];

        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::PublishDoorbellEntry {
                    owner_seed,
                    slot,
                    entry,
                    dispatch,
                    reply,
                } => {
                    let _ = reply.send(Ok(()));
                    (owner_seed, slot, entry, dispatch)
                }
                _ => panic!("expected a PublishDoorbellEntry command"),
            }
        });

        handle
            .publish_doorbell_entry(owner_seed, 6, entry.clone(), DoorbellDispatch::FirstSend)
            .await
            .expect("an addressable knock must publish");

        let (seen_seed, seen_slot, seen_entry, seen_dispatch) =
            observed.await.expect("the observing task");
        assert_eq!(
            seen_seed, owner_seed,
            "the record the actor opens must be the one named"
        );
        assert_eq!(seen_slot, 6, "the slot must cross the channel unchanged");
        assert_eq!(seen_entry, entry);
        assert_eq!(
            seen_dispatch,
            DoorbellDispatch::FirstSend,
            "the dispatch decides the funnel lane and must cross the channel \
             unchanged — the transport cannot re-derive it"
        );

        // **The OTHER dispatch, and it is not symmetry for its own sake.** Asserting
        // only `FirstSend` passes on a handle that discards the argument and writes a
        // literal, which is a real mistake shape here — the field was added to a
        // struct-literal call that already compiled without it. A mutation run
        // confirmed exactly that: hard-wiring `FirstSend` in the handle survived the
        // whole suite until this leg existed.
        let (handle, mut cmd_rx) = detached_handle();
        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::PublishDoorbellEntry {
                    dispatch, reply, ..
                } => {
                    let _ = reply.send(Ok(()));
                    dispatch
                }
                _ => panic!("expected a PublishDoorbellEntry command"),
            }
        });
        handle
            .publish_doorbell_entry(owner_seed, 6, entry, DoorbellDispatch::Reseed)
            .await
            .expect("a re-seed must publish too");
        assert_eq!(
            observed.await.expect("the observing task"),
            DoorbellDispatch::Reseed,
            "a re-seed must not arrive at the actor as a first send — it would take \
             the chat lane on every backoff rung, which is the one thing \
             `direct-messaging.md:128` puts in the non-chat window"
        );
    }

    /// **An unaddressable knock is refused before the command channel, so it can
    /// reach no network call.** The channel is the observable: a command that
    /// reached it was enqueued, and a call rejected before `send` leaves it empty.
    ///
    /// The channel is deliberately NOT serviced here, and that is safe only because
    /// the guard fires before `send` — which is exactly what is being asserted. If a
    /// guard ever stopped firing, `VeilidNetHandle::send` would await a `oneshot`
    /// nobody answers and this test would HANG rather than fail; the `timeout` turns
    /// that back into a failure, since a hanging test proves nothing to whoever
    /// removed the guard.
    #[tokio::test]
    async fn an_unaddressable_doorbell_knock_never_reaches_the_actor() {
        let slots = daemonseed_core::dm::doorbell::DOORBELL_SLOTS;
        let max = daemonseed_core::dm::firstcontact::MAX_ENTRY_LEN;

        for (slot, len, what) in [
            (slots, 16, "a slot outside the record"),
            (slots + 1, 16, "a slot well outside the record"),
            (0, max + 1, "an entry one byte above the cap"),
            (slots, max + 1, "both at once"),
        ] {
            let (handle, mut cmd_rx) = detached_handle();
            let refused = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                handle.publish_doorbell_entry(
                    [0x5au8; 32],
                    slot,
                    vec![0u8; len],
                    DoorbellDispatch::FirstSend,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                panic!("{what}: the guard did not fire and `send` is awaiting a reply")
            });
            assert!(refused.is_err(), "{what} must be refused");
            assert!(
                cmd_rx.try_recv().is_err(),
                "{what} must not reach the command channel — past it the write is \
                 enqueued and the recipient's record is opened or CREATED before \
                 anything is validated"
            );
        }

        // The positive control, and it is what makes the four refusals mean
        // something: an addressable knock at the same boundaries DOES reach the
        // channel. Without it a guard that refused everything would pass above.
        let (handle, mut cmd_rx) = detached_handle();
        let serviced = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::PublishDoorbellEntry {
                    slot, entry, reply, ..
                } => {
                    let _ = reply.send(Ok(()));
                    (slot, entry.len())
                }
                _ => panic!("expected a PublishDoorbellEntry command"),
            }
        });
        handle
            .publish_doorbell_entry(
                [0x5au8; 32],
                slots - 1,
                vec![0u8; max],
                DoorbellDispatch::FirstSend,
            )
            .await
            .expect("the last slot at the exact cap is addressable and must publish");
        assert_eq!(
            serviced.await.expect("the observing task"),
            (slots - 1, max),
            "the boundary values must arrive unchanged"
        );
    }

    /// The sweep handle passes the owner seed to the actor untouched — the record
    /// swept must be the record named, since nothing downstream can tell one
    /// doorbell from another.
    #[tokio::test]
    async fn a_doorbell_sweep_passes_its_owner_seed_to_the_actor_unchanged() {
        let (handle, mut cmd_rx) = detached_handle();
        let owner_seed = [0x5au8; 32];

        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::SweepDoorbell { owner_seed, reply } => {
                    let _ = reply.send(Ok(DoorbellSweep {
                        slots: vec![(6, vec![0xa6])],
                        outcome: rendezvous::SweepOutcome {
                            attempted: 32,
                            failed: 0,
                            found: 1,
                        },
                    }));
                    owner_seed
                }
                _ => panic!("expected a SweepDoorbell command"),
            }
        });

        let swept = handle
            .sweep_doorbell(owner_seed)
            .await
            .expect("the sweep reaches the actor");
        assert_eq!(swept.slots, vec![(6u16, vec![0xa6])]);
        assert_eq!(
            swept.outcome.attempted, 32,
            "the outcome must ride back with the slots: an empty list alone cannot \
             distinguish an unknocked doorbell from one whose every GET errored"
        );

        assert_eq!(
            observed.await.expect("the observing task"),
            owner_seed,
            "the actor must sweep the doorbell the caller named"
        );
    }

    /// The acknowledgement handle passes the address and the record bytes to the
    /// actor untouched. Nothing downstream can tell one ack record from another —
    /// the bytes are opaque and the address is the only thing naming a record — so
    /// a handle that altered either would write a well-formed acknowledgement
    /// somewhere the correspondent never reads, with no error on any surface. The
    /// direction is asserted alongside the seed because the address exists to keep
    /// the two together.
    #[tokio::test]
    async fn publishing_an_acknowledgement_passes_the_address_and_bytes_through_unchanged() {
        use daemonseed_core::dm::ack_record;
        use daemonseed_core::dm::ratchet::Direction;

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let ar = [0x71u8; 32];
        let dir = Direction::BToA;
        let record = vec![0xacu8; 96];
        let (handle, mut cmd_rx) = detached_handle();

        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::PublishDmAck {
                    address,
                    record,
                    reply,
                } => {
                    let _ = reply.send(Ok(()));
                    (
                        *address.owner_seed().as_bytes(),
                        address.direction(),
                        record,
                    )
                }
                _ => panic!("expected a PublishDmAck command"),
            }
        });

        handle
            .publish_dm_ack(
                ack_record::DmAckAddress::for_direction(&ar, dir).unwrap(),
                record.clone(),
            )
            .await
            .expect("the publish reaches the actor");
        assert_eq!(
            observed.await.expect("the observing task"),
            (
                *ack_record::derive_owner_seed(&ar, dir).unwrap().as_bytes(),
                dir,
                record
            )
        );
    }

    /// An empty slot comes back as `Ok(None)`, not as an error. The distinction is
    /// load-bearing under a fail-safe delivery posture: a transport fault read as
    /// "no acknowledgement" and an absent acknowledgement read as a fault are the
    /// two ways a sender's delivery state goes wrong, and only the handle's own
    /// contract keeps them apart.
    /// The address is asserted through as well, seed and direction both: the read
    /// side names a record exactly as the write side does, and reading the wrong
    /// direction's returns a valid acknowledgement about the wrong half of the
    /// conversation rather than an error.
    #[tokio::test]
    async fn fetching_an_absent_acknowledgement_is_ok_none_not_an_error() {
        use daemonseed_core::dm::ack_record;
        use daemonseed_core::dm::ratchet::Direction;

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let ar = [0x72u8; 32];
        let dir = Direction::AToB;
        let (handle, mut cmd_rx) = detached_handle();

        let observed = tokio::spawn(async move {
            match cmd_rx.recv().await.expect("a command reached the actor") {
                Command::FetchDmAck { address, reply } => {
                    let _ = reply.send(Ok(None));
                    (*address.owner_seed().as_bytes(), address.direction())
                }
                _ => panic!("expected a FetchDmAck command"),
            }
        });

        assert_eq!(
            handle
                .fetch_dm_ack(ack_record::DmAckAddress::for_direction(&ar, dir).unwrap())
                .await
                .expect("an empty slot is not a transport error"),
            None
        );
        assert_eq!(
            observed.await.expect("the observing task"),
            (
                *ack_record::derive_owner_seed(&ar, dir).unwrap().as_bytes(),
                dir
            )
        );
    }

    /// **Knock and sweep cannot disagree about the doorbell record's shape.**
    /// `o_cnt` is part of the record address, so two shapes means two records: the
    /// knock succeeds, the recipient's sweep returns empty, and nothing errors
    /// anywhere. The structural guard is that both paths open through one function;
    /// what this pins is the two facts that guard rests on, neither observable
    /// without a live DHT.
    ///
    /// Needles are assembled from fragments so this test's own source text does not
    /// self-match, as `both_page_paths_open_the_record_through_one_shape` does.
    #[test]
    fn both_doorbell_paths_open_the_record_through_one_shape() {
        let src = include_str!("actor.rs");
        let (prod, _) = src
            .split_once("#[cfg(test)]")
            .expect("the tests-module marker moved");

        let shape: String = ["DM_DOORBELL", "_SHAPE"].concat();
        assert_eq!(
            prod.matches(shape.as_str()).count(),
            2,
            "the doorbell shape must be named exactly twice outside the tests: its own \
             definition, and the single binding inside the one opener that the cache id \
             and both open modes are built from. A third naming is a second open site"
        );

        // The count above is not sufficient on its own, for the reason the page
        // guard records: with both modes reading a local, retargeting ONE of them at
        // another record's shape names a different constant and leaves this count at
        // 2 untouched. Pinning that the opener's body names a shape constant exactly
        // once is what closes that.
        let opener_start = prod
            .find("async fn doorbell_open(")
            .expect("the opener's definition moved");
        let opener_body = &prod[opener_start..];
        let opener_body = &opener_body[..opener_body
            .find("\n}\n")
            .expect("the opener's closing brace moved")];
        let shape_suffix: String = ["_", "SHAPE"].concat();
        assert_eq!(
            opener_body.matches(shape_suffix.as_str()).count(),
            1,
            "the opener's body must name a shape constant exactly ONCE — the single \
             binding both open modes and the cache id are built from"
        );

        let opener: String = ["doorbell", "_open("].concat();
        assert_eq!(
            prod.matches(opener.as_str()).count(),
            4,
            "the opener must be defined once and called exactly three times — from \
             `publish_doorbell_entry`, `sweep_doorbell`, and the FirstSend pre-warm \
             that keeps a cold stranger's-doorbell open off the 2-permit chat lane. A \
             doorbell path that opened its own record would be free to open a \
             different one. An exact count is deliberately brittle: a fourth caller \
             has to come and edit this number, which is the moment to ask whether it \
             should be going through the opener at all"
        );

        // Positive control: the needles are real. If the fragments ever stop matching
        // anything at all, the counts above are asserting over nothing.
        assert!(
            prod.contains("async fn sweep_doorbell(") && prod.contains(shape.as_str()),
            "the doorbell transport's own symbols are not in the production source — \
             this probe is matching nothing"
        );
    }
}
