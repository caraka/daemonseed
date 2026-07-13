//! The [`VeilidNet`] actor — a spawned task owning the `VeilidAPI` +
//! `RoutingContext`, driven through a command channel via [`VeilidNetHandle`].
//! Inbound `VeilidUpdate`s are mapped to typed [`VeilidNetEvent`]s on a
//! separate stream the app/UI consumes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use veilid_core::{
    api_startup, OperationId, RecordKey, RouteBlob, RouteId, RoutingContext, Target, VeilidAPI,
    VeilidConfig, VeilidUpdate,
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
    /// (keyed by `stable_id` via [`rendezvous::current_state_subkey`]), so a
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

    /// Fetch + reassemble + open + SHA-384-VERIFY one content chunk (ISC-S28 /
    /// ISC-A-S20) from the sharer at private-route `route`. `window` caps how many
    /// fragment `app_call`s run in flight (the caller's AIMD window, #128 D-1);
    /// returns the chunk bytes plus the MAX per-fragment latency observed — the
    /// congestion signal the caller feeds back to size the next chunk's window.
    pub async fn fetch_chunk(
        &self,
        route: RouteId,
        share_id: &str,
        chunk_addr: ChunkAddr,
        room_key: [u8; 32],
        window: usize,
    ) -> Result<(Vec<u8>, Duration)> {
        let rk = PublicRoomKey::from_bytes(room_key);
        let this = self.clone();
        share::fetch_chunk(share_id, &chunk_addr, &rk, window, move |req| {
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
    /// slot, and the write lands in that member's [`rendezvous::current_state_subkey`]
    /// slot — last-writer-wins.
    ///
    /// **Slot-collision ceiling (bounded, degrades not-crashes).** The current-state
    /// scheme has only [`rendezvous::SUBKEY_COUNT`] slots (sized for a handful of
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
/// SAME [`rendezvous::current_state_subkey`] slot (last-writer-wins) and the gui +
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
        std::fs::create_dir_all(&cfg.storage_dir).ok();

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
                    if let Err(e) = api.release_private_route(route_id) {
                        crate::vtrace!("stop_serve: release route for {share_id} failed ({e})");
                    }
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
                if !spawn_refresh_if_due(
                    &api,
                    &sched,
                    &advert_routes,
                    &share_adverts,
                    &refresh_in_flight,
                    &last_advert_refresh,
                ) {
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
// All eight parameters are distinct threaded actor state (three shared caches, the
// node id, the owner seed, and the payload); bundling them into a struct would only
// move the coupling, not remove it, on a single private helper.
#[allow(clippy::too_many_arguments)]
async fn publish_rendezvous(
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
    let record_lock = rendezvous::record_lock(record_locks, &owner_seed);
    let _write_guard = record_lock.lock().await;
    let key = rendezvous::open_cached(
        opened,
        &owner_seed,
        rendezvous::open_or_create(api, rc, &owner),
    )
    .await?;
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
    let r = rendezvous::publish(rc, &key, &owner, base, seq, sealed).await;
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
async fn publish_current_state(
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
    let record_lock = rendezvous::record_lock(record_locks, &owner_seed);
    let _write_guard = record_lock.lock().await;
    let key = rendezvous::open_cached(
        opened,
        &owner_seed,
        rendezvous::open_or_create(api, rc, &owner),
    )
    .await?;
    let subkey = rendezvous::current_state_subkey(stable_id);
    crate::vtrace!("publish_current_state: stable_id={stable_id} key={key:?} subkey={subkey}");
    rendezvous::publish_at_subkey(rc, &key, &owner, subkey, sealed).await
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
            };
            drop(permit);
            DispatchOutcome {
                result,
                acquire_wait,
            }
        })
    }
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
    let key = {
        let record_lock = rendezvous::record_lock(record_locks, &owner_seed);
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &owner_seed,
            rendezvous::open_or_create(api, rc, &owner),
        )
        .await?
    };
    crate::vtrace!("subscribe_rendezvous: record open key={key:?}; registering watch");
    rc.watch_dht_values(key.clone(), None, None, None)
        .await
        .map_err(|e| VeilidNetError::Routing(e.to_string()))?;
    crate::vtrace!("subscribe_rendezvous: watch ok; spawning backlog sweep -> Ok");
    // Read lane (WB-5 / I5′.1): the backlog sweep is a burst of DHT GETs; hold a
    // read permit from the shared accountant for its duration so reads and writes
    // draw on one budget.
    spawn_gated_sweep(gate, rc, key, ev_tx);
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
    key: RecordKey,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
) {
    let gate = gate.clone();
    let rc = rc.clone();
    let ev_tx = ev_tx.clone();
    tokio::spawn(async move {
        rendezvous::sweep(gate, rc, key, ev_tx).await;
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
    let key = {
        let record_lock = rendezvous::record_lock(record_locks, &owner_seed);
        let _open_guard = record_lock.lock().await;
        rendezvous::open_cached(
            opened,
            &owner_seed,
            rendezvous::open_or_create(api, rc, &owner),
        )
        .await?
    };
    crate::vtrace!("resweep_rendezvous: record open key={key:?}; spawning backlog sweep -> Ok");
    // Read lane (WB-5 / I5′.1): hold a shared-accountant read permit for the sweep.
    spawn_gated_sweep(gate, rc, key, ev_tx);
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
        if let Err(e) = api.release_private_route(prev) {
            crate::vtrace!("publish_one_advert: release prev route for {share_id} failed ({e})");
        }
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
            if let Err(e) = api.release_private_route(route_id) {
                crate::vtrace!(
                    "publish_one_advert withdraw: release route for {share_id} failed ({e})"
                );
            }
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
        if let Err(e) = api.release_private_route(route_id) {
            crate::vtrace!("publish_one_advert: rollback release for {share_id} failed ({e})");
        }
    }
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
}
