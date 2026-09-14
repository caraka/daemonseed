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
    api_startup, OperationId, PublicKey, RecordKey, RouteBlob, RouteId, RoutingContext, Target,
    VeilidAPI, VeilidConfig, VeilidUpdate,
};

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
/// otherwise-idle sharer (review). 128 clears one full download with margin while
/// still bounding a pathological multi-fetcher burst.
const MAX_CONCURRENT_SERVE_REPLIES: usize = 128;

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
    /// Hand out the transport state a [`crate::dm::records::VeilidRecords`] is built
    /// over: the routing context and API this loop holds, the caches and locks
    /// its own read and write paths use, and the write funnel.
    ///
    /// A read of this loop's state rather than an operation on it, which is why
    /// it is one command and not seven. The alternative — a command per record
    /// read and write — would put every one of them behind this single FIFO,
    /// where a drop sweep is 256 reads and a slow one would park the whole node.
    /// The values handed out are clones the sink already holds off this loop, so
    /// the concurrency bound stays the shared gate rather than the queue.
    DmRecordsParts {
        reply: oneshot::Sender<crate::dm::records::VeilidRecordsParts>,
    },
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

    /// The transport state a [`crate::dm::records::VeilidRecords`] is built over.
    ///
    /// Every value in it is a clone of one the actor holds, so a record store
    /// built here shares the node's open-record cache, its per-record locks and
    /// its write funnel rather than keeping a second set beside them.
    pub async fn dm_records_parts(&self) -> Result<crate::dm::records::VeilidRecordsParts> {
        self.send(|reply| Command::DmRecordsParts { reply }).await
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
    // Per-rendezvous-record serialization lock (owner seed → async mutex). Two ops
    // on the SAME record must not race: spawned append-ring publishes would clobber
    // each other in the 2-slot ring (an older seq landing after a newer one loses
    // the newer message), and two cold-cache callers would both open_or_create. One
    // async mutex per record serializes both; DISTINCT records stay fully concurrent,
    // so a slow write to one record never blocks another's traffic or the actor loop.
    // Shared so the spawned publish + advert refresh contend on the same locks as the
    // main loop. See rendezvous::record_lock + ISA (2026-07-07, #128 review).
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
                // envelope every coalesce window (2026-07-02 manual test log).
                let relevant = {
                    let routes = advert_routes.lock().unwrap();
                    dead_routes.iter().any(|d| routes.values().any(|r| r == d))
                };
                // Always trace: correlating route churn against a fetch wave's
                // serve/reply timing is the latency-kill vs rotation-kill
                // discriminator a manual test log needs.
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
                // stamped fresh and is never disturbed (review). No busy-gate
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
            Command::DmRecordsParts { reply } => {
                let _ = reply.send(crate::dm::records::VeilidRecordsParts {
                    transport: crate::dm::records::Transport {
                        gate: dht_gate.clone(),
                        api: api.clone(),
                        rc: rc.clone(),
                        opened: opened.clone(),
                        record_locks: record_locks.clone(),
                    },
                    sched: sched.clone(),
                });
            }
            Command::Shutdown {
                flush_budget,
                reply,
            } => {
                // Traced at the dequeue, not at the send: `flush_budget` starts counting
                // here, so the gap between this line and the caller's own entry line is
                // the head-of-line wait the caller's cap exists to bound.
                let dequeued = std::time::Instant::now();
                crate::vtrace!("close: Shutdown dequeued, flush_budget={flush_budget:?}");
                // I7: flush pending chat writes + leave tombstones + share withdraws
                // within the caller's remaining close budget, shed class-3/4/5
                // current-state writes, THEN tear the node down — a locally-echoed chat
                // silently dropped at close is data loss the sender already saw as sent.
                sched.shutdown(flush_budget).await;
                crate::vtrace!(
                    "close: sched.shutdown returned after {:?}",
                    dequeued.elapsed()
                );
                // Capped: the caller is blocking a UI thread on the reply below, and
                // veilid's teardown is otherwise an unbounded await past every budget.
                let teardown_started = std::time::Instant::now();
                match tokio::time::timeout(TEARDOWN_CAP, api.shutdown()).await {
                    Ok(()) => crate::vtrace!(
                        "close: teardown returned after {:?}",
                        teardown_started.elapsed()
                    ),
                    Err(_) => {
                        crate::vtrace!("close: teardown hit TEARDOWN_CAP {TEARDOWN_CAP:?}")
                    }
                }
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
        // + sending it would be pure wasted work the reply lands too late for (review
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
        // timed separately so a slow manual test log names the stage to blame.
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
    // and lose the newer message (#128 review). Distinct records take distinct
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
pub(crate) enum ProdWrite {
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
    /// A direct-messaging record write — one subkey of an advert, a drop or a
    /// channel record, or the deletion of a channel record — dispatched by
    /// [`crate::dm::records::RecordWrite`].
    ///
    /// One variant for the three record kinds. A record is addressed under a
    /// subkey count the flows supply — it is part of the address, and the flows are
    /// what hold the three counts — so the shape travels in the token and the
    /// dispatch end has nothing left to choose.
    DmRecord(crate::dm::records::RecordWrite),
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
                ProdWrite::DmRecord(write) => {
                    write
                        .dispatch(&gate, &api, &rc, &opened, &record_locks)
                        .await
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

/// The error of a read the bounded read lane wraps, which that lane can tell
/// apart as running out of time.
pub(crate) trait ReadError: std::fmt::Display {
    /// How this error failed the read.
    fn failure(&self) -> crate::error::VeilidFailure;
}

impl ReadError for veilid_core::VeilidAPIError {
    /// As [`crate::error::veilid_failure`] classes Veilid's variants.
    fn failure(&self) -> crate::error::VeilidFailure {
        crate::error::veilid_failure(self)
    }
}

impl ReadError for VeilidNetError {
    fn failure(&self) -> crate::error::VeilidFailure {
        match self {
            VeilidNetError::TimedOut(_) => crate::error::VeilidFailure::TimedOut,
            VeilidNetError::Local(_) => crate::error::VeilidFailure::Local,
            _ => crate::error::VeilidFailure::Refused,
        }
    }
}

impl ReadError for String {
    /// A message carries no kind, so it is a refusal.
    fn failure(&self) -> crate::error::VeilidFailure {
        crate::error::VeilidFailure::Refused
    }
}

/// Run one read-lane GET under a read permit, bounded by
/// [`rendezvous::SWEEP_GET_TIMEOUT`] (#411).
///
/// The permit is acquired first and `get` is polled only inside the bound, so the
/// bound covers the read itself and never the wait for a permit — the same split a
/// sweep's per-GET reads use. A read that has not answered when the bound expires is
/// abandoned: the future is dropped and the permit released with it, so an unanswered
/// read cannot hold a read-pool slot past the bound and later readers are not queued
/// behind it for ever.
///
/// A read cut off at the bound, and a read Veilid itself answers with `Timeout`,
/// is [`VeilidNetError::TimedOut`]; a read refused before it left this node is
/// [`VeilidNetError::Local`]; any other erroring GET is
/// [`VeilidNetError::Routing`]. Both say the read did not deliver an answer and
/// the record's state is unknown, and both stay distinct from `Ok(None)`, which
/// is the authoritative *empty slot*. They are told apart here, where the typed
/// error is still in hand, so a caller counting failures can count a timeout as
/// one.
pub(crate) async fn gated_bounded_get<T, E: ReadError>(
    gate: &Arc<DhtGate>,
    what: &str,
    get: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    let got = {
        let _read_permit = gate.acquire_read().await;
        tokio::time::timeout(rendezvous::SWEEP_GET_TIMEOUT, get).await
    };
    match got {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(match e.failure() {
            crate::error::VeilidFailure::TimedOut => {
                VeilidNetError::TimedOut(format!("{what}: {e}"))
            }
            crate::error::VeilidFailure::Local => VeilidNetError::Local(format!("{what}: {e}")),
            crate::error::VeilidFailure::Refused => VeilidNetError::Routing(e.to_string()),
        }),
        Err(_elapsed) => Err(VeilidNetError::TimedOut(format!(
            "{what}: GET exceeded {}s, abandoned",
            rendezvous::SWEEP_GET_TIMEOUT.as_secs()
        ))),
    }
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
/// *within* a set that moves together, which is why all three seed-keyed sites had
/// to move in one change rather than one at a time. A new site keyed on a seed
/// rather than through this function would break that premise, which is what the
/// source-level probe in this module's tests is for.
///
/// The hazard it removes is specific. `WriteRequest.record` is both the FIFO
/// ordering scope and the coalescing scope, so a new enqueue site keyed on the
/// seed while its neighbour keys on the public key would **split one record's
/// FIFO into two queues** — per-record single-flight and write ordering both
/// lost, with `Ok(())` on every surface.
pub(crate) fn funnel_record_key(owner_seed: &[u8; 32]) -> [u8; 32] {
    identity::rendezvous_owner_public_bytes(owner_seed)
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
        // self-throttles past the answer window (review); it stays below the
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
            3,
            "exactly three enqueue sites set `record:` through the helper. A different \
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

    // ── an unanswered read must not hold its read permit for ever ─────────────
    /// A read-lane GET that never answers is abandoned at
    /// [`rendezvous::SWEEP_GET_TIMEOUT`], which releases the read permit it holds, so a
    /// later reader acquires one and completes instead of queueing behind the wedged
    /// read for the process's lifetime. The read pool is sized to ONE permit, so the
    /// later acquire can only succeed by the wedged read having given its permit back.
    ///
    /// The abandoned read surfaces as [`VeilidNetError::TimedOut`] and never as
    /// `Ok(None)`, which would report an unread slot as an authoritative empty one.
    ///
    /// This exercises [`gated_bounded_get`], the bounded read the direct-messaging
    /// record reads go through; those reads need a live `RoutingContext` to reach
    /// `get_dht_value` and so cannot be driven from a unit test. Runs on tokio's paused
    /// clock, so the asserted wait is virtual time advanced by the bound's own timer.
    /// The outer timeout is what turns a permit that is never released into a failed
    /// assertion instead of a test that hangs.
    #[tokio::test(start_paused = true)]
    async fn a_dm_fetch_releases_its_read_permit_when_the_get_never_answers() {
        // Only the READ pool is sized to one, so a later read that acquires can only
        // have drawn the read pool — an acquire that reached another pool would find
        // spare permits there and pass for the wrong reason.
        let gate = DhtGate::with_pools(2, 1, 2, 1);

        let wedged_gate = gate.clone();
        let wedged = tokio::spawn(async move {
            let never =
                std::future::pending::<std::result::Result<Option<Vec<u8>>, VeilidNetError>>();
            gated_bounded_get(&wedged_gate, "dm records", never).await
        });
        // Let the wedged read take the only read permit before anything else asks for
        // one — the assertion below is what proves it did, rather than assuming it.
        tokio::task::yield_now().await;
        assert_eq!(
            gate.available_read(),
            0,
            "the unanswered read holds the pool's only read permit"
        );

        let started = tokio::time::Instant::now();
        let later_read = tokio::time::timeout(
            rendezvous::SWEEP_GET_TIMEOUT + Duration::from_secs(30),
            gate.acquire_read(),
        )
        .await
        .expect(
            "a later read acquires a permit — the unanswered read released its own at \
             the bound instead of holding it",
        );
        let waited = started.elapsed();
        assert!(
            waited >= rendezvous::SWEEP_GET_TIMEOUT,
            "the unanswered read was given its full bound before being abandoned: {waited:?}"
        );
        assert!(
            waited < rendezvous::SWEEP_GET_TIMEOUT + Duration::from_secs(1),
            "the permit came back at the bound, not later: {waited:?}"
        );

        // Bounded: an abandoned read must RETURN, not merely release its permit. Without
        // the outer bound, a read that gave the permit back and then hung would park
        // here for ever rather than failing.
        let err = tokio::time::timeout(Duration::from_secs(1), wedged)
            .await
            .expect("the abandoned read returns")
            .expect("the wedged read's task finished")
            .expect_err("an abandoned read is a failure, never an empty slot");
        assert!(
            matches!(err, VeilidNetError::TimedOut(ref text) if text.contains("abandoned")),
            "an abandoned read is reported as running out of time: {err:?}"
        );
        drop(later_read);
    }

    /// The bound must not disturb the two outcomes it is wrapped around: an answering
    /// read is passed through unchanged, and an erroring one becomes
    /// [`VeilidNetError::Routing`] carrying the read's own message. Both give the read
    /// permit back, so a read that answers or errors costs the pool nothing beyond its
    /// own duration.
    #[tokio::test]
    async fn a_bounded_read_passes_an_answer_through_and_reports_an_error() {
        let gate = DhtGate::with_pools(2, 1, 2, 1);

        let answered = gated_bounded_get(&gate, "dm records", async {
            Ok::<_, String>(Some(vec![1u8]))
        })
        .await
        .expect("an answering read reaches the caller as an answer");
        assert_eq!(
            answered,
            Some(vec![1u8]),
            "the read's own bytes reach the caller unchanged"
        );
        assert_eq!(
            gate.available_read(),
            1,
            "an answering read gives its permit back"
        );

        let err = gated_bounded_get(&gate, "dm records", async {
            Err::<Option<Vec<u8>>, _>("boom".to_string())
        })
        .await
        .expect_err("an erroring read is a failure, never an empty slot");
        match err {
            VeilidNetError::Routing(ref reported) => assert!(
                reported.contains("boom"),
                "the read's own error text reaches the caller: {reported}"
            ),
            other => panic!("an erroring read is the existing transport failure: {other:?}"),
        }
        assert_eq!(
            gate.available_read(),
            1,
            "an erroring read gives its permit back"
        );

        let err = gated_bounded_get(&gate, "dm records", async {
            Err::<Option<Vec<u8>>, _>(veilid_core::VeilidAPIError::Timeout)
        })
        .await
        .expect_err("a read Veilid answers with Timeout is a failure");
        assert!(
            matches!(err, VeilidNetError::TimedOut(ref text) if text.contains("dm records")),
            "a read Veilid answers with Timeout is reported as running out of time: {err:?}"
        );
        let err = gated_bounded_get(&gate, "dm records", async {
            Err::<Option<Vec<u8>>, _>(veilid_core::VeilidAPIError::TryAgain {
                message: "offline".to_owned(),
            })
        })
        .await
        .expect_err("a read Veilid refuses is a failure");
        assert!(
            matches!(err, VeilidNetError::Routing(_)),
            "a read Veilid refuses for any other reason is not a timeout: {err:?}"
        );
        let err = gated_bounded_get(&gate, "dm records", async {
            Err::<Option<Vec<u8>>, _>(veilid_core::VeilidAPIError::Shutdown)
        })
        .await
        .expect_err("a read Veilid refuses while shutting down is a failure");
        assert!(
            matches!(err, VeilidNetError::Local(ref text) if text.contains("dm records")),
            "a read Veilid refuses before sending it is a local refusal: {err:?}"
        );
    }

    /// **The bound covers the read, never the wait for a permit.** The only read permit
    /// is held elsewhere for `HOLD` before it is released, and the read that then
    /// acquires it never answers, so the call must last the whole wait PLUS its full
    /// bound. A bound taken around the acquire as well would spend itself waiting and
    /// abandon the read the moment it began, finishing at `HOLD` — which is what makes
    /// the lower assertion the one with teeth.
    #[tokio::test(start_paused = true)]
    async fn a_bounded_read_is_bounded_from_its_permit_not_from_the_call() {
        const HOLD: Duration = Duration::from_secs(20);
        let gate = DhtGate::with_pools(2, 1, 2, 1);

        let held = gate.acquire_read().await;
        let holder = tokio::spawn(async move {
            tokio::time::sleep(HOLD).await;
            drop(held);
        });

        let started = tokio::time::Instant::now();
        let never = std::future::pending::<std::result::Result<Option<Vec<u8>>, VeilidNetError>>();
        let got = tokio::time::timeout(
            HOLD + rendezvous::SWEEP_GET_TIMEOUT + Duration::from_secs(30),
            gated_bounded_get(&gate, "dm records", never),
        )
        .await
        .expect("the read is abandoned at its bound and returns");
        let elapsed = started.elapsed();

        assert!(
            got.is_err(),
            "a read that never answers is abandoned, whatever it waited for its permit"
        );
        assert!(
            elapsed >= HOLD + rendezvous::SWEEP_GET_TIMEOUT,
            "the read got its full bound AFTER the permit wait, not inside it: {elapsed:?}"
        );
        assert!(
            elapsed < HOLD + rendezvous::SWEEP_GET_TIMEOUT + Duration::from_secs(1),
            "the read ended one bound past the permit, not later: {elapsed:?}"
        );
        holder.await.expect("the permit holder's task finished");
    }
}
