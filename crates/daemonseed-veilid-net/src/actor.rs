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
    api_startup, KeyPair, OperationId, RecordKey, RouteBlob, RouteId, RoutingContext, Target,
    VeilidAPI, VeilidConfig, VeilidUpdate,
};

use daemonseed_core::public_room::PublicRoomKey;
use daemonseed_core::share_envelope::ManifestEntry;
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::ChunkAddr;

use crate::config::VeilidNetConfig;
use crate::dht_gate::DhtGate;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;
use crate::schedule::{
    DispatchFuture, DispatchLane, DispatchOutcome, SchedulerConfig, WriteClass, WriteKind,
    WriteRequest, WriteScheduler, WriteSchedulerHandle, WriteSink,
};
use crate::{discovery, identity, rendezvous, share};

/// RAII guard clearing a record's repair-in-flight marker on Drop (#180 CRSH-ISC-22).
/// Held by the spawned `RepairRendezvous` task; its Drop runs on BOTH normal
/// completion AND panic-unwind, so a panic inside `repair_rendezvous` (or the veilid
/// code it awaits) cannot leave `owner_seed` stuck in the in-flight set — which would
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

/// Close-flush budget handed to the write scheduler on graceful shutdown (WB-3.I7):
/// pending chat writes + leave tombstones + share withdraws flush within this,
/// class-3/4/5 current-state writes are shed. Same close-budget class as the share
/// `WithdrawAllOwned` flush; an overrun abandons to the TTL backstop.
const SHUTDOWN_FLUSH_BUDGET: Duration = Duration::from_secs(8);

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

/// What one sweep of a DM channel page yields: the populated slots, each paired
/// with the subkey index it came back in.
///
/// The pairing is the point, not a convenience. A frame declares its own sequence
/// number, and the slot it was found in implies one; the collector must check that
/// the two agree, via `daemonseed_core::dm::paging::PagePosition::new`. Returning
/// bare bytes would unbind a frame from its position and leave the write-once
/// property this scheme rests on checked by nothing.
pub type DmPageSlots = Vec<(u32, Vec<u8>)>;

/// One page sweep's full result: the populated slots, and the health of the sweep
/// that produced them.
///
/// The [`rendezvous::SweepOutcome`] is not decoration. Without it an empty `Vec`
/// means both "nobody has written to this page" and "all sixteen GETs errored",
/// and those demand opposite responses — the first is the ordinary state of a page
/// the probe frontier has run ahead to, the second is a record session that needs
/// healing. `rendezvous.rs` names surfacing `failed` separately as the enabling
/// signal for consumer-side session-health tracking (CRSH-ISC-1); a DM page that
/// swallowed it would be the one record family invisible to that tracker.
pub type DmPageSweep = (DmPageSlots, rendezvous::SweepOutcome);

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
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
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
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
    },
    /// **Repair** a dead rendezvous record session (consumer-route self-heal §RS-1.2,
    /// step 3b). Re-establishes the record — invalidate the open-cache entry, (optionally
    /// close), re-open, re-watch, full 0..64 re-sweep — **holding the record's
    /// `record_lock` across the whole sequence** (CRSH-ISC-3/18), so a concurrent
    /// same-record write can never target a torn-down handle. `owner_seed` is the same
    /// rendezvous-owner seed as [`Command::SubscribeRendezvous`] /
    /// [`Command::ResweepRendezvous`]. Re-swept backlog arrives as
    /// [`VeilidNetEvent::Inbound`]; the frontend dispatches this only for a repair-due
    /// record and resets its session-health tracker at dispatch.
    RepairRendezvous {
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
    },
    /// Resolve a rendezvous record's deterministic [`RecordKey`] from its `owner_seed` —
    /// local crypto only, no network round-trip. Feeds the frontend's
    /// `RecordKey → owner_seed` map (§RS-1.2) so a repair-due signal (which the tracker
    /// keys by `RecordKey`) can be dispatched as a [`Command::RepairRendezvous`] on the
    /// record's owner seed.
    RendezvousKey {
        owner_seed: [u8; 32],
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
    /// Publish one channel frame into `slot` of the `dflt(16)` page record at
    /// `owner_seed` (`daemonseed_core::dm::paging::derive_owner_seed`). `frame` is
    /// the already-sealed, already-signed channel frame; this layer moves opaque
    /// bytes and never inspects them.
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
    PublishDmPage {
        owner_seed: [u8; 32],
        slot: u32,
        frame: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Sweep every slot of one channel page, returning `(slot, bytes)` for each
    /// populated one.
    ///
    /// The slot index travels back with the bytes because the collector must check
    /// the frame's declared sequence number against the position it was found in —
    /// `daemonseed_core::dm::paging::PagePosition::new` is the checked way to make
    /// that comparison, and it needs the slot. An empty result is the ordinary state
    /// of a page nobody has written to yet, distinct from a transport error.
    SweepDmPage {
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<DmPageSweep>>,
    },
    // ── Public-share content (Phase 3) ──
    /// Register an indexed share to serve owner-on-demand (`share_id` → content
    /// + the `PublicRoomKey` bytes responses seal under).
    ServeShare {
        share_id: String,
        content: Arc<ShareContent>,
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
    RouteMaintenance {
        dead_routes: Vec<RouteId>,
    },
    /// Release a private route this node imported for a discovered share (the
    /// consumer-side counterpart to the sharer's advert-route release — §RS-3,
    /// CRSH-ISC-10). Fire-and-forget: the actor releases through `release_tolerant`,
    /// so an id veilid already evicted is a benign no-op, no reply is awaited.
    ReleaseRoute {
        route_id: RouteId,
    },
    /// Periodic slow-cadence advert refresh (the #124 watchdog). Unlike
    /// [`Command::RouteMaintenance`], which fires only on an OBSERVED route death,
    /// this fires on a timer and refreshes every advert unconditionally — the sole
    /// recovery path for a route that died SILENTLY (veilid never surfaced it in a
    /// `RouteChange.dead_routes`). Bounded by a minutes-scale interval well above the
    /// coalesce window so it cannot recreate the refresh storm. Fire-and-forget.
    AdvertWatchdog,
    Shutdown {
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

    /// Shut the node down cleanly.
    pub async fn shutdown(&self) {
        let _ = self.send(|reply| Command::Shutdown { reply }).await;
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
    pub async fn subscribe_circle(&self, owner_seed: [u8; 32]) -> Result<()> {
        self.send(|reply| Command::SubscribeRendezvous { owner_seed, reply })
            .await?
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
    /// identical to [`Self::subscribe_circle`] but for a public-room
    /// `owner_seed`. Inbound sealed room messages / share announcements arrive as
    /// [`VeilidNetEvent::Inbound`]; the app opens them under the `PublicRoomKey`.
    pub async fn subscribe_room(&self, owner_seed: [u8; 32]) -> Result<()> {
        self.send(|reply| Command::SubscribeRendezvous { owner_seed, reply })
            .await?
    }

    /// Re-sweep an already-subscribed rendezvous record for backlog missed during
    /// the watch-warmup window, WITHOUT registering another watch — the recovery
    /// primitive for #132/#133. `owner_seed` is the circle or public-room
    /// rendezvous-owner seed (same as [`Self::subscribe_circle`] /
    /// [`Self::subscribe_room`]). Re-swept items arrive as
    /// [`VeilidNetEvent::Inbound`] and are deduped downstream.
    pub async fn resweep_rendezvous(&self, owner_seed: [u8; 32]) -> Result<()> {
        self.send(|reply| Command::ResweepRendezvous { owner_seed, reply })
            .await?
    }

    /// Repair a dead rendezvous record session (consumer-route self-heal §RS-1.2, step
    /// 3b): re-establish the record under its `record_lock` — invalidate the open-cache
    /// entry, (optionally) close, re-open, re-watch, and full 0..64 re-sweep (CRSH-ISC-3).
    /// `owner_seed` is the circle or public-room rendezvous-owner seed (same as
    /// [`Self::subscribe_room`] / [`Self::resweep_rendezvous`]). The frontend dispatches
    /// this ONLY for a repair-due record, one at a time (serialized with the steady
    /// resweep). Re-swept backlog arrives as [`VeilidNetEvent::Inbound`].
    pub async fn repair_rendezvous(&self, owner_seed: [u8; 32]) -> Result<()> {
        self.send(|reply| Command::RepairRendezvous { owner_seed, reply })
            .await?
    }

    /// Resolve a rendezvous record's deterministic [`RecordKey`] from its `owner_seed` —
    /// local crypto only (no network round-trip). The frontend feeds this into its
    /// `RecordKey → owner_seed` map so a repair-due signal (keyed by `RecordKey`) resolves
    /// to the seed [`Self::repair_rendezvous`] needs (§RS-1.2).
    pub async fn rendezvous_record_key(&self, owner_seed: [u8; 32]) -> Result<RecordKey> {
        self.send(|reply| Command::RendezvousKey { owner_seed, reply })
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

    /// Publish one sealed channel frame into `slot` of its page — the transport
    /// half of ISC-C42, which also needs collection (#236) before it can close.
    ///
    /// Derive `owner_seed` with `daemonseed_core::dm::paging::derive_owner_seed`
    /// from the conversation's address root, the *sending* direction, and
    /// `position_of(seq).page()`; take `slot` from the same
    /// `position_of(seq).slot()`. Deriving the two from one `PagePosition` is what
    /// keeps them consistent — a page from one sequence number and a slot from
    /// another writes a frame nobody will find at the sequence it claims.
    ///
    /// Enqueued as a non-coalescible chat-lane write: every call reaches the
    /// network, because every slot holds a different message.
    pub async fn publish_dm_page(
        &self,
        owner_seed: [u8; 32],
        slot: u32,
        frame: Vec<u8>,
    ) -> Result<()> {
        self.send(|reply| Command::PublishDmPage {
            owner_seed,
            slot,
            frame,
            reply,
        })
        .await?
    }

    /// Sweep one channel page, returning `(slot, bytes)` per populated slot.
    ///
    /// An empty `Vec` is the ordinary state of an unwritten page — the probe
    /// frontier is meant to run ahead of what exists — and is deliberately distinct
    /// from `Err`, a transport failure. The bytes are UNVERIFIED: only
    /// `daemonseed_core::dm::frame::parse` followed by the ratchet's own checks may
    /// decide a frame is genuine, and the collector must confirm the frame's
    /// sequence number agrees with the slot it came back in.
    pub async fn sweep_dm_page(&self, owner_seed: [u8; 32]) -> Result<DmPageSweep> {
        self.send(|reply| Command::SweepDmPage { owner_seed, reply })
            .await?
    }

    // ── Public-share CONTENT transfer (Phase 3): owner-on-demand over app_call ──

    /// Register an indexed share to serve owner-on-demand. The actor answers
    /// inbound fragment `app_call`s for `share_id` from `content`, sealing each
    /// response under `room_key` (the share's `PublicRoomKey` bytes). The sharer
    /// must stay online to serve (ISC-A-S21); discovery (`publish_room`) is what
    /// advertises it.
    pub async fn serve_share(
        &self,
        share_id: String,
        content: Arc<ShareContent>,
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
                    record: owner_seed,
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
                    record: owner_seed,
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
                owner_seed,
                slot,
                frame,
                reply,
            } => {
                // The classification is built by `dm_page_write_request` rather than
                // inline, because every field of it fails SILENTLY and a funnel
                // request constructed on the command loop is reachable from no test.
                // See that function for why each field is what it is.
                sched.enqueue(dm_page_write_request(owner_seed, slot, frame, reply));
            }
            Command::SweepDmPage { owner_seed, reply } => {
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
                let record_locks = record_locks.clone();
                tokio::spawn(async move {
                    let r =
                        sweep_dm_page(&gate, &api, &rc, &opened, &record_locks, owner_seed).await;
                    // A dropped receiver (caller gave up / shutting down) is benign.
                    let _ = reply.send(r);
                });
            }
            Command::SubscribeRendezvous { owner_seed, reply } => {
                let _ = reply.send(
                    subscribe_rendezvous(
                        &api,
                        &rc,
                        &ev_tx,
                        &opened,
                        &record_locks,
                        &dht_gate,
                        owner_seed,
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
                    record: owner_seed,
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
            Command::ResweepRendezvous { owner_seed, reply } => {
                let _ = reply.send(
                    resweep_rendezvous(
                        &api,
                        &rc,
                        &ev_tx,
                        &opened,
                        &record_locks,
                        &dht_gate,
                        owner_seed,
                    )
                    .await,
                );
            }
            Command::RepairRendezvous { owner_seed, reply } => {
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
                    if !set.insert(owner_seed) {
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
                        key: owner_seed,
                    };
                    let res = repair_rendezvous(
                        &api,
                        &rc,
                        &ev_tx,
                        &opened,
                        &record_locks,
                        &dht_gate,
                        owner_seed,
                    )
                    .await;
                    let _ = reply.send(res);
                    // `_guard` drops here on normal return, or on panic-unwind — the marker
                    // is cleared either way.
                });
            }
            Command::RendezvousKey { owner_seed, reply } => {
                // Local crypto only (no network): derive the owner keypair, compute the
                // deterministic record key. Feeds the frontend's RecordKey→owner_seed map.
                let res = match identity::rendezvous_owner_keypair(&owner_seed) {
                    Ok(owner) => rendezvous::rendezvous_key(
                        &api,
                        &owner,
                        rendezvous::RecordShape::RENDEZVOUS,
                    )
                    .await
                    .map(rendezvous::RendezvousHandle::into_key),
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
                if let Some(route_id) = advert_routes.lock().unwrap().remove(&share_id) {
                    release_tolerant(&api, route_id, &format!("stop_serve {share_id}"));
                }
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
            Command::Shutdown { reply } => {
                // I7: flush pending chat writes + leave tombstones + share withdraws
                // within the close budget, shed class-3/4/5 current-state writes, THEN
                // tear the node down — a locally-echoed chat silently dropped at close
                // is data loss the sender already saw as sent.
                sched.shutdown(SHUTDOWN_FLUSH_BUDGET).await;
                api.shutdown().await;
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
/// The registry lock is held only for the synchronous serve (map lookup +
/// in-memory seal), never across the reply await.
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
        // Recover the guard if another holder panicked: a poisoned registry
        // must not cascade into the actor's later ServeShare/StopServe locks.
        let seal_started = std::time::Instant::now();
        let response = {
            let mut s = shares
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            share::serve(&mut s, &message)
        };
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
    let record_lock = rendezvous::record_lock(record_locks, &owner);
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner, rendezvous::RecordShape::RENDEZVOUS),
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
    let record_lock = rendezvous::record_lock(record_locks, &owner);
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner, rendezvous::RecordShape::RENDEZVOUS),
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
    DmPage {
        owner_seed: [u8; 32],
        slot: u32,
        frame: Vec<u8>,
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
                ProdWrite::DmPage {
                    owner_seed,
                    slot,
                    frame,
                } => {
                    publish_dm_page(
                        &gate,
                        &api,
                        &rc,
                        &opened,
                        &record_locks,
                        owner_seed,
                        slot,
                        frame,
                    )
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
    let record_lock = rendezvous::record_lock(record_locks, &owner);
    let _write_guard = record_lock.lock().await;
    let handle = rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(&owner, DM_KEY_RECORD_SHAPE),
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
        let record_lock = rendezvous::record_lock(record_locks, &owner);
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &rendezvous::cached_record_id(&owner, DM_KEY_RECORD_SHAPE),
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

/// The DM channel page's schema: `dflt(16)`, one subkey per message slot.
/// Part of the record ADDRESS, and simultaneously the modulus of the slot
/// arithmetic — hence derived from `paging::PAGE_SLOTS` rather than typed here
/// (`ISA.md` ISC-C100; sizing in `docs/design/direct-messaging.md` DRAFT v6).
const DM_PAGE_SHAPE: rendezvous::RecordShape = rendezvous::RecordShape::DM_PAGE;

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
/// slot mutated on the way to dispatch — reports `Ok(())` on every local surface.
fn dm_page_write_request(
    owner_seed: [u8; 32],
    slot: u32,
    frame: Vec<u8>,
    reply: oneshot::Sender<Result<()>>,
) -> WriteRequest<ProdWrite> {
    WriteRequest {
        record: owner_seed,
        class: WriteClass::Chat,
        kind: WriteKind::Ring,
        deadline: None,
        item: ProdWrite::DmPage {
            owner_seed,
            slot,
            frame,
        },
        reply: Some(reply),
    }
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
async fn dm_page_open(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    owner: &KeyPair,
) -> Result<rendezvous::RendezvousHandle> {
    rendezvous::open_cached(
        opened,
        &rendezvous::cached_record_id(owner, DM_PAGE_SHAPE),
        rendezvous::open_or_create(gate, api, rc, owner, DM_PAGE_SHAPE),
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
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
    slot: u32,
    frame: Vec<u8>,
) -> Result<()> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Single-flight the open and serialize against any concurrent op on this record,
    // exactly as the rendezvous and key-record write paths do (CRSH-ISC-3). Two
    // messages landing in two slots of the same page is the ordinary case, so this
    // lock is contended by design and must not be skipped.
    let record_lock = rendezvous::record_lock(record_locks, &owner);
    let _write_guard = record_lock.lock().await;
    let handle = dm_page_open(gate, api, rc, opened, &owner).await?;
    crate::vtrace!(
        "publish_dm_page: key={:?} slot={} bytes={}",
        handle.key(),
        slot,
        frame.len()
    );
    rendezvous::publish_at_subkey(rc, &handle, &owner, slot, frame).await
}

/// Sweep one channel page, returning `(slot, bytes)` per populated slot together
/// with the sweep's [`rendezvous::SweepOutcome`].
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
async fn sweep_dm_page(
    gate: &Arc<DhtGate>,
    api: &VeilidAPI,
    rc: &RoutingContext,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    owner_seed: [u8; 32],
) -> Result<DmPageSweep> {
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // The open is serialized under the record lock; the GETs are NOT, so a slow
    // page read never blocks a concurrent write to the same page. The guard drops
    // before any read permit is acquired, keeping the single-permit rule
    // (CRSH-ISC-17).
    let handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner);
        let _open_guard = record_lock.lock().await;
        dm_page_open(gate, api, rc, opened, &owner).await?
    };
    let key = handle.key().clone();
    let mut found: DmPageSlots = Vec::new();
    // The slot bound comes off the handle's own shape, never from a constant at
    // this call site: a sweep wider than the record the address was derived under
    // is the mistake `RendezvousHandle` binds key and shape together to prevent.
    let outcome = rendezvous::sweep_gated(
        gate,
        handle.shape().o_cnt(),
        |subkey, bytes| {
            found.push((subkey, bytes));
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
        "sweep_dm_page: key={:?} attempted={} found={} failed={}",
        handle.key(),
        outcome.attempted,
        outcome.found,
        outcome.failed
    );
    Ok((found, outcome))
}

/// Open/create the rendezvous record, register a watch, and kick off a one-shot
/// background sweep for the bounded login backlog. Inbound items flow out as
/// [`VeilidNetEvent::Inbound`]. Used for circles and public rooms / lobby alike.
async fn subscribe_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    gate: &Arc<DhtGate>,
    owner_seed: [u8; 32],
) -> Result<()> {
    crate::vtrace!("subscribe_rendezvous: open (cached) rendezvous");
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Single-flight the open against a concurrent same-record publish; the guard is
    // dropped before the watch registers (only the open needs serialization).
    let handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner);
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &rendezvous::cached_record_id(&owner, rendezvous::RecordShape::RENDEZVOUS),
            rendezvous::open_or_create(gate, api, rc, &owner, rendezvous::RecordShape::RENDEZVOUS),
        )
        .await?
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
    crate::vtrace!("subscribe_rendezvous: watch ok; spawning backlog sweep -> Ok");
    // Read lane (WB-5 / I5′.1): the backlog sweep is a burst of DHT GETs; hold a
    // read permit from the shared accountant for its duration so reads and writes
    // draw on one budget.
    spawn_gated_sweep(gate, rc, handle, ev_tx);
    Ok(())
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
/// identical to [`subscribe_rendezvous`]; found items flow out as
/// [`VeilidNetEvent::Inbound`] and are deduped downstream.
async fn resweep_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    gate: &Arc<DhtGate>,
    owner_seed: [u8; 32],
) -> Result<()> {
    crate::vtrace!("resweep_rendezvous: open (cached) rendezvous");
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    // Single-flight the open against a concurrent same-record publish (mirrors
    // subscribe_rendezvous); no watch is registered here.
    let handle = {
        let record_lock = rendezvous::record_lock(record_locks, &owner);
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &rendezvous::cached_record_id(&owner, rendezvous::RecordShape::RENDEZVOUS),
            rendezvous::open_or_create(gate, api, rc, &owner, rendezvous::RecordShape::RENDEZVOUS),
        )
        .await?
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
async fn repair_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    opened: &rendezvous::OpenCache,
    record_locks: &rendezvous::RecordLocks,
    gate: &Arc<DhtGate>,
    owner_seed: [u8; 32],
) -> Result<()> {
    crate::vtrace!("repair_rendezvous: re-establishing dead record session");
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    let record_lock = rendezvous::record_lock(record_locks, &owner);
    let outcome = rendezvous::repair_gated(
        &record_lock,
        opened,
        &rendezvous::cached_record_id(&owner, rendezvous::RecordShape::RENDEZVOUS),
        rendezvous::REPAIR_CLOSE_FIRST,
        // close (repro-gated): best-effort — a close on a session veilid already GC'd is a
        // benign race (Evidence 3 sibling), so the error is swallowed.
        |handle: rendezvous::RendezvousHandle| async move {
            if let Err(e) = rc.close_dht_record(handle.into_key()).await {
                crate::vtrace!("repair_rendezvous: close_dht_record (pre-reopen) failed ({e})");
            }
        },
        // open: `open_or_create` acquires the un-gated limiter around each raw open
        // (CRSH-ISC-14/17); no read permit is held across it.
        || rendezvous::open_or_create(gate, api, rc, &owner, rendezvous::RecordShape::RENDEZVOUS),
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
        record: advert.owner_seed,
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
        let mut routes = advert_routes.lock().unwrap();
        if routes.get(share_id) == Some(&route_id) {
            routes.remove(share_id);
            drop(routes);
            release_tolerant(
                api,
                route_id,
                &format!("publish_one_advert withdraw {share_id}"),
            );
        }
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
    let mut routes = advert_routes.lock().unwrap();
    if routes.get(share_id) == Some(&route_id) {
        routes.remove(share_id);
        drop(routes);
        release_tolerant(
            api,
            route_id,
            &format!("publish_one_advert rollback {share_id}"),
        );
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

        // The three shapes must stay distinct: sharing an owner seed across them
        // would otherwise collapse in the open-cache.
        let owner = crate::identity::rendezvous_owner_keypair(&[3u8; 32]).unwrap();
        let ids = [
            rendezvous::cached_record_id(&owner, rendezvous::RecordShape::RENDEZVOUS),
            rendezvous::cached_record_id(&owner, DM_KEY_RECORD_SHAPE),
            rendezvous::cached_record_id(&owner, DM_PAGE_SHAPE),
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

    /// **How a DM page write is classified in the funnel.** Every field asserted
    /// here fails silently if it is wrong, and the kind fails worst: `Ring` is the
    /// funnel's name for "never coalesce", and a `CurrentState` kind in its place
    /// would let two queued writes to one page — two DIFFERENT messages, in two
    /// different slots — collapse last-writer-wins, dropping one off the wire while
    /// its `reply` still reports `Ok(())`. Nothing downstream can see that, so it is
    /// pinned at the point of construction rather than left to the live oracle.
    #[test]
    fn a_dm_page_write_is_a_chat_lane_write_that_never_coalesces() {
        let seed = [0xa7u8; 32];
        let frame = vec![0xde, 0xad, 0xbe, 0xef];
        let (reply, _rx) = oneshot::channel();

        // Slot 9 is chosen, not arbitrary: it is non-zero (so a request that
        // hard-wired subkey 0 differs), it is not 8 or 16 (so a second modulus
        // applied on the way to dispatch differs), and 9+1 is still inside the
        // record (so an off-by-one shows up as a wrong slot rather than as an
        // out-of-range error some other check would catch first).
        let req = dm_page_write_request(seed, 9, frame.clone(), reply);

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
        assert_eq!(
            req.record, seed,
            "the funnel's FIFO + coalescing scope is the page record itself"
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
                owner_seed,
                slot,
                frame: dispatched,
            } => {
                assert_eq!(owner_seed, seed);
                assert_eq!(
                    slot, 9,
                    "the slot must reach dispatch UNCHANGED — the caller derived it \
                     from a sequence number, so any arithmetic here writes the frame \
                     where the other party never looks for it"
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
            3,
            "the page shape must be named exactly three times outside the tests: its \
             own definition, and the two references inside the one opener. A fourth \
             naming is a second open site, which is how publish and sweep come to \
             address different records"
        );

        let opener: String = ["dm_page", "_open("].concat();
        assert_eq!(
            prod.matches(opener.as_str()).count(),
            3,
            "the opener must be defined once and called exactly twice — from \
             `publish_dm_page` and from `sweep_dm_page`. A page path that opened its \
             own record would be free to open a different one"
        );
    }
}
