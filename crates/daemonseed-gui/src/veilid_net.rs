//! Veilid-backed net actor (#98 S2 + Phase 3 Slice 2b) — the only transport.
//!
//! It implements the `NetCommand` / `NetEvent` contract defined in [`crate::net`],
//! which [`crate::net::NetHandle::new`] spawns unconditionally.
//! Backed by [`daemonseed_veilid_net::VeilidNetHandle`].
//!
//! **Circles, public shares, lobby chat, lobby presence + operator
//! announcements/MOTD today.** `Connect` (attach + lobby + operator-record
//! subscribe), `JoinCircle`, `SendCircle`, the inbound circle path, the
//! public-share publish / discover / fetch path (Phase 3 Slice 2b), public-room
//! (Lobby) chat (`JoinRoom` / `SendRoom`), lobby member presence (#74), and the
//! operator announcements/MOTD composer (Phase 4 A-c — `RefreshPublicSpace`,
//! `SetMotd`, `UploadAnnouncement`) are live. This is a degraded-but-honest
//! dev/test mode, NOT a dual transport — it honors the no-relay↔Veilid-interop
//! clean cut (one transport at a time).
//!
//! **Single encryption layer.** Content is sealed under the circle `cot_key` /
//! the public-room `PublicRoomKey` exactly as on the relay; the Veilid DHT stores
//! those opaque bytes verbatim. This actor never touches Veilid's transport
//! crypto.
//!
//! **Public-share discovery + anti-swap (Phase 3 Slice 2b).** A share is
//! announced by publishing a [`daemonseed_veilid_net::DiscoveryEnvelope`] onto the
//! world-derivable lobby rendezvous: a sealed `ShareAnnouncement` (signed by the
//! sharer's stable identity), the sharer's Veilid private-route blob, and an
//! ML-DSA-87 signature binding `share_id ‖ route_blob`. A fetcher
//! `open_announcement`s the item (provenance → announcer pubkey + share_id), THEN
//! [`verify_route_advert`]s the route
//! against that pubkey before importing it — a man-in-the-middle on the
//! world-writable lobby record cannot redirect a fetch onto a rogue route. Content
//! chunks are SHA-384-verified inside `fetch_chunk` (ISC-S28).
//!
//! **Least-authority signing.** veilid-net never holds the identity key. The actor
//! keeps the stable [`SignKeypair`] behind an `Arc` (it is `!Clone`) to seal
//! announcements, and hands veilid-net only an
//! `Arc<dyn RouteAdvertSigner>` ([`IdentityRouteAdvertSigner`]) scoped to route
//! adverts.
//!
//! **Inbound demux.** `VeilidNetEvent::Inbound` carries only sealed bytes (no
//! record tag), so a received blob is tried against each joined circle's `cot_key`
//! (the AEAD seal authenticates the match), then as a lobby chat message
//! (`open_room_message` under the lobby `PublicRoomKey`), then as a lobby
//! `DiscoveryEnvelope` (share discovery). The distinct per-kind AAD means only the
//! matching open succeeds. Own circle/lobby messages are emitted `mine:true` and
//! deduped against the optimistic local echo in `push_message` (#143).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_cli::public_space::{
    post_render_fields, render_motd, sign_motd, sign_post, verify_served_motd, verify_served_post,
};
use daemonseed_cli::route_signer::IdentityRouteAdvertSigner;
use daemonseed_core::browse_retry::{ParkedBrowseRetry, ParkedRetryAction, parked_retry_action};
use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::{
    CircleKey, derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
    derive_cot_key,
};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::heartbeat::{
    HeartbeatFields, open_heartbeat, seal_circle_heartbeat, seal_public_heartbeat,
};
use daemonseed_core::identity::keys::{Identity, ShareRootIkm, SignKeypair, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::presence::{
    PRESENCE_TTL, PresenceChange, PresenceTracker, ReapGate, beacon_is_fresh,
    next_keepalive_interval,
};
use daemonseed_core::public_room::{
    DEFAULT_ROOM, PublicRoomKey, derive_room_key, derive_room_presence_veilid_owner_seed,
    derive_room_share_veilid_owner_seed, derive_room_veilid_owner_seed, open_room_message,
    seal_room_message,
};
use daemonseed_core::public_space::{
    Whitelist, content_address, dev_project_announce_veilid_owner_seed, dev_project_release_keypair,
};
use daemonseed_core::route_guard::ImportedRouteGuard;
use daemonseed_core::session_health::{
    RepairDecision, SessionHealthTracker, SweepHealthInput, WatchState, Weather,
};
use daemonseed_core::share_announce::{
    AnnouncementFields, derive_root_commitment, derive_share_id_v2, derive_share_root_nonce,
    open_announcement, seal_public_announcement, share_binding_is_valid,
};
use daemonseed_core::share_catalog::{CatalogChange, ShareCatalog, ShareListing};
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::ChunkAddr;
use daemonseed_core::storage::fetched::rebase_to_selection_root;
use daemonseed_proto::v1 as wire;
use daemonseed_veilid_net::{
    AimdWindow, DiscoveryEnvelope, PresenceBoundary, RecordKey, RouteId, VeilidNet,
    VeilidNetConfig, VeilidNetError, VeilidNetEvent, VeilidNetHandle, next_resweep_seed,
    verify_route_advert,
};
use prost::Message as _;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::net::{
    NetCommand, NetEvent, ShareManifestEntry, beacon_is_own, is_unsafe_publish_root,
    roster_from_members, roster_render_changed, safe_folder_name, sanitize_rel_path,
};
use crate::state::{AnnouncementRow, AnnouncementsView};

/// How long a discovered share lives in the catalog without a fresh announce —
/// Generous TTL — a backstop for a sharer that vanished WITHOUT a withdraw (a hard
/// crash, or — until withdraw-on-close lands — a graceful quit). A live share is kept
/// fresh by natural route-rotation re-announce well within it, so the generous window
/// avoids ever aging out a live share. Tunable; diverges from the relay's faster
/// roll-call cadence.
const SHARE_CATALOG_TTL: Duration = Duration::from_secs(600);

/// How often the recipient ages out shares it has not reheard within the TTL.
const SHARE_CATALOG_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Ceiling for chunk fetches in flight at once during a download (#113). Bounds the
/// parallelism so a many-chunk file saturates the link without an unbounded fan-out
/// of `app_call`s; mirrors the veilid-net fragment pipeline window (#109). Chunks
/// still reassemble in manifest order (`buffered` preserves order). This is the
/// MAXIMUM the adaptive chunk window ([`CHUNK_SLOW_START`], #128 D-2) climbs to.
const CHUNK_FETCH_CONCURRENCY: usize = 8;

/// The chunk window a download OPENS at before climbing (#128 D-2 / #204). A cold
/// open at the full [`CHUNK_FETCH_CONCURRENCY`] ceiling drives a sustained
/// chunk×fragment fanout (up to 8×2) that killed the fetch route mid-folder on
/// Windows before the adaptive controller ever saw a healthy sample. Slow-starting
/// gentle and climbing by one per healthy chunk keeps the route alive; a folder
/// with many chunks still reaches the ceiling within a few files.
const CHUNK_SLOW_START: usize = 2;

// ── Operator announce-record item envelope (Phase 4 A-c) ─────────────────────
//
// Inbound `VeilidNetEvent::Inbound { bytes }` carries NO slot id, and a
// `MotdPayload` vs a `PostPayload` are prost-ambiguous, so the reader cannot tell a
// MOTD from an announcement by content. Each value published to the operator record
// is therefore prefixed with a 1-byte KIND tag: `[kind] ++ prost(artifact)`.

/// #140 stepped warmup re-sweep schedule: absolute deadlines from connect at which a
/// force-refresh re-sweep round runs (dispatched via `sleep_until`, so a round's own
/// re-sweep await time never pushes later rounds later — no accumulated drift). The
/// passive DHT watch's first fold lands tens of seconds in (measured ~68 s for lobby
/// chat on a warm restart), so a few front-loaded rounds catch converged content sooner
/// and give each surface an earlier "discovering → content" reveal. Each re-sweep is
/// `SUBKEY_COUNT` (64) force-refresh gets/record, so rounds are few + widening, not a
/// tight loop; re-swept already-seen items are deduped downstream (`apply_discovery`
/// self-filter, `push_message` exact-match). **#140 dial-down (felt-test 2026-07-08):**
/// the original 4-round 12/25/45/75 s schedule spun the host fans up (~900 gets/client)
/// for marginal benefit — operator content converged (~120 s) past the window, and #142
/// removed the #93 landing this schedule used to feed — so it is dialled to a LIGHT
/// 2-round best-effort early-catch that helps only fast-converging content; slower
/// content rides the passive watch. The proper load fix (stop-on-content backoff) is
/// deferred; whether to keep / revert this at all is caraka's call after felt-test.
/// Felt-tunable.
const WARMUP_RESWEEP_SCHEDULE: [Duration; 2] = [Duration::from_secs(20), Duration::from_secs(60)];

/// Rounds (from the front of [`WARMUP_RESWEEP_SCHEDULE`]) in which the circle records
/// are ALSO re-swept. Operator + lobby — the top priority and the #93 landing feed —
/// are re-swept every round; circles (which can be many) only in the early rounds, so a
/// heavily-joined user's warmup doesn't fan out to `rounds × circles` concurrent
/// backlog sweeps competing with initial chat/downloads (#140 review). Felt-tunable.
const WARMUP_CIRCLE_RESWEEP_ROUNDS: usize = 1;

/// #157 (generalized, felt-test 2026-07-10): the steady-state resweep tick. The
/// warmup schedule above stops at +60s, but the passive DHT watch is lossy — a chat
/// message or share advert *written after* warmup gets no reliable ValueChange, so it
/// never re-surfaces at a peer that has already settled (the felt-test symptom: matching
/// record keys, writes 36–246s, lobby chat that echoes locally but never arrives). WB-4
/// sanctions a reader-side resweep as the fix. On each tick ONE record from the current
/// subscribed chat/discovery set is re-swept, round-robin, so the instantaneous read
/// burst stays one `SUBKEY_COUNT` (64) force-refresh sweep (WB-2 read lane) and the
/// per-record cadence = tick × record-count (scales with room count instead of fanning
/// out). Presence records are excluded — they self-heal via keepalive re-writes (WB-4
/// table). Known limitations (both felt-tunable, each with a follow-up lever): (1)
/// per-record latency grows linearly with room count — the fix is a tail-sweep (resweep
/// only beyond each record's high-water) so more records fit per tick; (2) the sweep is a
/// continuous background read load (one 64-GET sweep per tick, indefinitely) — the fix is
/// a stop-on-quiet backoff that widens the tick when no new content arrives. The tick is
/// set conservatively for the alpha to bound (2) against the #140 fan-spin ceiling.
const STEADY_RESWEEP_TICK: Duration = Duration::from_secs(15);

/// Hand-off point from [`WARMUP_RESWEEP_SCHEDULE`]: the steady resweep begins only once
/// the warmup window (last round at +60s) has elapsed, so the two resweep sources never
/// double the read burst against the same DHT nodes (WB-2). A small margin past the last
/// warmup round.
const STEADY_RESWEEP_WARMUP_HANDOFF: Duration = Duration::from_secs(70);

/// Build the #140 warmup PRIORITY re-sweep records: operator MOTD/announce first (its
/// content feeds the #93 landing), then lobby chat. These are re-swept every round;
/// circle records are handled separately (early rounds only — see
/// [`WARMUP_CIRCLE_RESWEEP_ROUNDS`]). Presence records are excluded (they self-heal via
/// the heartbeat emit/reap cycle). Order is issue-order and load-bearing: within a round
/// each `resweep_rendezvous` awaits its record open before the next is issued, so the
/// operator sweep is dispatched first (the spawned backlog reads then overlap).
fn warmup_priority_records(
    operator: Option<[u8; 32]>,
    lobby: Option<[u8; 32]>,
    share: Option<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut seeds = Vec::with_capacity(3);
    seeds.extend(operator);
    seeds.extend(lobby);
    // #153: the share record is a separate rendezvous, so a cold-joiner must
    // re-sweep it too to discover shares announced before it subscribed.
    seeds.extend(share);
    seeds
}

/// KIND tag for a MOTD value: the payload is a [`wire::SignedArtifact`].
const OPERATOR_ITEM_MOTD: u8 = 0x00;
/// KIND tag for an announcement value: the payload is a [`wire::Post`].
const OPERATOR_ITEM_ANNOUNCEMENT: u8 = 0x01;

/// #141: how often a writer re-publishes its known operator MOTD + announcements so
/// their DHT subkey values do not expire. Operator content is otherwise written only
/// on post, and Veilid DHT values age out without owner refresh — so an announcement
/// silently vanished across sessions (felt-test 2026-07-08). Gated on holding the
/// announce owner seed, so only a writer (dev: any client; prod: the operator) keeps
/// content alive; the record is low-volume, so re-publishing a handful of already-signed
/// items on this cadence is cheap. Felt-tunable; set safely under Veilid's default DHT
/// value TTL (to confirm).
const OPERATOR_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);

/// Prepend the 1-byte KIND tag to a prost-encoded operator artifact.
fn encode_operator_item(kind: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(kind);
    out.extend_from_slice(bytes);
    out
}

/// Split an operator-record value into `(kind, payload)`. `None` for an empty
/// buffer (no tag byte) — the read side treats that as "not an operator item".
fn decode_operator_item(buf: &[u8]) -> Option<(u8, &[u8])> {
    buf.split_first().map(|(kind, rest)| (*kind, rest))
}

/// A joined circle's local state: the GUI routing tag, the content key (for
/// seal/open), and the shared rendezvous-owner seed (for publish/subscribe).
struct VeilidCircle {
    circle_id: u64,
    cot_key: CircleKey,
    owner_seed: [u8; 32],
    /// The circle's **presence** sibling record owner seed (#77, P1: presence rides
    /// its OWN record, never the chat rendezvous). Publishes/subscribes circle beacons.
    presence_owner_seed: [u8; 32],
    /// Receiver-side liveness view for THIS circle's roster (#77): verified, fresh,
    /// non-own circle beacons fold in via [`PresenceTracker::apply`]; the heartbeat
    /// timer reaps it. Live-only — dropped with the circle on teardown.
    presence: PresenceTracker,
}

/// The subscribed lobby / public-room rendezvous: the world-derivable
/// `PublicRoomKey` (seals/opens announcements) and the rendezvous-owner seed
/// (publishes onto + subscribes to the lobby record). Both derive from the public
/// room name + suite, so every node computes the same lobby (an open rendezvous).
struct LobbyRendezvous {
    room_key: PublicRoomKey,
    owner_seed: [u8; 32],
    /// The **share-discovery** sibling record's owner seed (#153: share
    /// announcements ride their OWN world-derivable record, never the chat
    /// rendezvous, so a share advert can never silently overwrite the chat
    /// append-ring — and vice versa). Publishes/subscribes public-share adverts.
    share_owner_seed: [u8; 32],
    /// The **presence** sibling record's owner seed (P1: presence rides its OWN
    /// world-derivable record, never the chat rendezvous, so a ~15–20s beacon can
    /// never evict chat backlog). Publishes/subscribes lobby member beacons.
    presence_owner_seed: [u8; 32],
    /// Receiver-side liveness view for the lobby roster (#74/#75): verified,
    /// fresh, non-own member beacons fold in via [`PresenceTracker::apply`]; the
    /// heartbeat timer `reap`s it. Live-only — a fresh actor starts empty.
    presence: PresenceTracker,
}

/// A discovered share's anti-swap-verified route: the sharer's opaque Veilid
/// private-route blob, kept so a fetch can `import_route` it. The announcer pubkey
/// the route was verified against lives in the catalog entry (`sender_pubkey`).
struct DiscoveredRoute {
    route_blob: Vec<u8>,
    /// (#180 §RS-1.4) A strictly-increasing generation stamped on every accepted advert
    /// fold for this share (from [`ShareState::next_generation`]). A parked browse retry
    /// captures this at fetch-fail time; a later fold bumps it strictly above the parked
    /// value, which is the retry's fire signal (CRSH-ISC-6/19).
    generation: u64,
    /// (#180 §RS-1.4) `true` once a fetch of this share failed and it is **re-resolving**:
    /// the share stays listed (never pruned on a fetch failure, CRSH-ISC-5) with a parked
    /// one-shot retry. Cleared by a successful fetch; preserved across a fresh advert fold
    /// (still re-resolving until the retry actually succeeds).
    unresolved: bool,
}

/// A share this node published this session — enough to post a
/// provenance-matching withdraw on unpublish and to show in the publisher's own
/// list (the lobby never reflects our own announcement back).
#[derive(Clone)]
struct OwnShare {
    share_id: String,
    /// (#156) The receiver-verifiable root commitment for this share, so a
    /// re-announce / roll-call answer / withdraw carries the SAME commitment the
    /// id derives from (else a receiver's binding check drops it).
    root_commitment: Vec<u8>,
    name: String,
    rating: String,
    sharer_handle: String,
}

/// The subscribed operator announce/MOTD record (Phase 4 A-c): the write-gate owner
/// seed (dev-only — the in-source project seed) plus the accumulated, verified
/// operator content. A0: ONE project-owned channel; the composer signs with the F17
/// project-release key, so an empty [`Whitelist`] authorizes it and NO signer
/// whitelist distribution is needed. `motd` holds the current verified MOTD;
/// `posts` maps a content-address hex slot → its verified announcement (dedup +
/// stable order).
///
/// **Slot ceiling (#134, deferred).** The MOTD (fixed `"motd"` slot) and every
/// announcement (content-address slot) key into the SAME `current_state_subkey`
/// 64-slot space on the operator record, so past a handful of items two can collide
/// (last-writer-wins) on-wire — and an announcement colliding with `"motd"` evicts
/// the MOTD for peers. Low-volume here (a project posts few live items), so it bites
/// far later than lobby presence; the fix is the same #134 dedicated-schema call.
struct OperatorSpace {
    /// The project-announce Veilid rendezvous-owner seed — the DHT write-gate. In the
    /// dev phase this is derivable by everyone from the in-source project seed, so any
    /// client can compose (A0/A1 dev-possession gate); in production only the offline
    /// seed-holder can write.
    announce_owner_seed: [u8; 32],
    /// The current verified MOTD (F17-signed), or `None` if none verifies yet.
    motd: Option<wire::SignedArtifact>,
    /// Verified announcement posts, keyed by their content-address hex slot.
    posts: BTreeMap<String, wire::Post>,
}

/// The actor's public-share state (Phase 3 Slice 2b): the held signing key, the
/// subscribed lobby, the discovered-share catalog + their routes, and our own
/// published shares. Bundled into one struct so the share wiring adds a single
/// parameter to the command/inbound handlers rather than many.
struct ShareState {
    /// The stable identity key, behind an `Arc` because [`SignKeypair`] is
    /// `!Clone` yet is needed in two roles at once: sealing announcements
    /// (`&SignKeypair`) and the [`IdentityRouteAdvertSigner`] capability.
    signing: Option<Arc<SignKeypair>>,
    /// (#156) The stable identity's share-root IKM, behind an `Arc` (it holds
    /// secret bytes), so a publish derives a receiver-verifiable `share_id` from
    /// the same identity that seals the announcement. `None` until Connect.
    share_root_ikm: Option<Arc<ShareRootIkm>>,
    lobby: Option<LobbyRendezvous>,
    catalog: ShareCatalog,
    discovered: HashMap<String, DiscoveredRoute>,
    /// (#180 §RS-1.4) Monotonic generation counter: bumped and stamped onto a
    /// [`DiscoveredRoute`] on every accepted advert fold, so a parked browse retry can
    /// detect a fresh advert (generation strictly advanced) and a withdraw/re-add never
    /// reuses a stale generation (CRSH-ISC-6/19).
    next_generation: u64,
    /// (#180 §RS-1.4) Parked one-shot browse retries, keyed by `share_id`. A fetch failure
    /// marks the share `Unresolved` and parks a retry here (local only, no network); it
    /// fires at the next cursor tick after a fresh advert folds (CRSH-ISC-6/15), or clears
    /// on window expiry / withdraw (CRSH-ISC-19) — never a prune.
    parked_retries: HashMap<String, ParkedBrowseRetry>,
    own: Vec<OwnShare>,
    /// The subscribed operator announce/MOTD record (Phase 4 A-c), set on Connect
    /// after the owner seed derives + the record subscribes. `None` until connected.
    operator: Option<OperatorSpace>,
    /// The reap-suspension gate (WB-5.1 / I5″.6/.7): folds the scheduler's published
    /// median DHT-weather (hysteresis band + resume grace) into "suspend reaping now",
    /// so the reaper does not false-reap members whose keepalives are merely queued in
    /// an elevated regime. Persists across reap ticks.
    reap_gate: ReapGate,
    /// Last-emitted "presence may be stale" signal (WB-5.1 / I5″.7, WB-ISC-20), so a
    /// `NetEvent::PresenceStale` is emitted only on a change.
    prev_presence_stale: bool,
    /// (#180 §RS-3, CRSH-ISC-10) The in-use guard over each discovered share's last-imported
    /// private route: defers a superseded route's release until no in-flight fetch is still
    /// streaming over it. Fed by fetch spawn/finish (`spawn_fetch_share`/`fold_fetch_outcome`)
    /// and advert-replacement folds (`apply_discovery`); the actor loop drains
    /// `pending_route_releases` through the net handle. The on-loop map is authoritative — a
    /// spawned fetch never releases anything itself.
    route_guard: ImportedRouteGuard<String, RouteId>,
    /// (#180 §RS-3) Imported routes the guard has cleared for release, drained and released
    /// (spawned) by the actor loop each iteration. Buffered here because release rides the
    /// async net handle while the guard's decisions are synchronous.
    pending_route_releases: Vec<RouteId>,
}

impl ShareState {
    fn new() -> Self {
        Self {
            signing: None,
            share_root_ikm: None,
            lobby: None,
            catalog: ShareCatalog::new(SHARE_CATALOG_TTL),
            discovered: HashMap::new(),
            next_generation: 0,
            parked_retries: HashMap::new(),
            own: Vec::new(),
            operator: None,
            reap_gate: ReapGate::new(),
            prev_presence_stale: false,
            route_guard: ImportedRouteGuard::new(),
            pending_route_releases: Vec::new(),
        }
    }

    /// The public-share rows: our own published shares first (the lobby never
    /// echoes them back), then the discovered catalog, deduped by `share_id` —
    /// mirrors the relay actor's `catalog_listings`.
    fn listings(&self) -> Vec<ShareListing> {
        let mut seen = HashSet::new();
        let mut out: Vec<ShareListing> = Vec::new();
        for own in &self.own {
            if seen.insert(own.share_id.clone()) {
                out.push(ShareListing {
                    share_id: own.share_id.clone(),
                    name: own.name.clone(),
                    rating: own.rating.clone(),
                    sharer_handle: own.sharer_handle.clone(),
                    sharer_fingerprint: String::new(), // own shares render "you" (#114)
                    mine: true, // our own published share → rendered as "you" (#114)
                    unresolved: false, // own shares are never re-resolving (#180)
                });
            }
        }
        for s in self.catalog.entries() {
            if seen.insert(s.share_id.clone()) {
                let mut listing = ShareListing::from(&s);
                // (#180 §RS-1.4) Overlay the frontend-local re-resolve state: a share whose
                // fetch failed stays listed, marked `unresolved`, until a parked retry
                // resolves it (CRSH-ISC-5).
                listing.unresolved = self
                    .discovered
                    .get(&s.share_id)
                    .is_some_and(|d| d.unresolved);
                out.push(listing);
            }
        }
        out
    }
}

/// Best-effort wall-clock for the outgoing `CircleMessage` / announcement timestamp.
fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The Veilid net actor. Same channel shape as [`crate::net`]'s `net_actor`
/// (`cmd_rx` in, `evt_tx` out; `_cmd_tx` is the self-send handle the relay actor
/// uses for timers — unused here, kept for a uniform spawn signature).
pub async fn veilid_net_actor(
    mut cmd_rx: UnboundedReceiver<NetCommand>,
    cmd_tx: UnboundedSender<NetCommand>,
    evt_tx: UnboundedSender<NetEvent>,
) {
    let mut net: Option<VeilidNetHandle> = None;
    let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
    let mut circles: Vec<VeilidCircle> = Vec::new();
    let mut shares = ShareState::new();
    // The presented display name. Set from a profile's persisted handle on
    // Connect/SetMyHandle; the fallback only matters on the ephemeral path, and
    // the S4 felt-test uses named profiles.
    let mut my_handle = "guest".to_owned();
    let mut prune_timer = tokio::time::interval(SHARE_CATALOG_PRUNE_INTERVAL);
    // #141: re-publish operator MOTD/announcements on a slow cadence so their DHT
    // values do not expire (operator content is otherwise written only on post).
    let mut operator_keepalive = tokio::time::interval(OPERATOR_KEEPALIVE_INTERVAL);
    // Presence keepalive + reap clock (WB-1.2): a jittered [180,220]s keepalive into
    // each joined room's presence record that also reaps the roster on each fire. A
    // self-rescheduling `Sleep` (not a fixed `interval`) so each tick draws a fresh
    // jittered deadline — no fixed-period signature, no cross-record phase-lock
    // (WB-3.I6), and the cadence takes NO input from user activity (WB-0).
    let heartbeat = tokio::time::sleep(next_keepalive_interval());
    tokio::pin!(heartbeat);
    // #157 (generalized): steady-state resweep clock. Round-robins ONE subscribed
    // chat/discovery record per tick once the warmup window closes (see
    // STEADY_RESWEEP_TICK / STEADY_RESWEEP_WARMUP_HANDOFF). `connected_at` is the
    // warmup hand-off reference (set on Connect); `resweep_cursor` is the key-based
    // round-robin position.
    let mut steady_resweep = tokio::time::interval(STEADY_RESWEEP_TICK);
    steady_resweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut connected_at: Option<Instant> = None;
    let mut resweep_cursor: Option<[u8; 32]> = None;
    // In-flight guard: skip a tick while a prior resweep is still running, so a sweep
    // that outlasts the tick on a slow DHT can't overlap the next one — keeps the WB-2
    // read burst at one 64-GET sweep at a time (review finding).
    let resweep_busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Consumer-route self-heal detection (§RS-1.2, CRSH-ISC-2): per-record session-health
    // tracker keyed by the swept record's key. Each `VeilidNetEvent::SweepHealth` folds in
    // one sweep pass; K consecutive all-failed passes in calm weather flag the record
    // repair-due. Detection only — step 3b attaches repair execution at the repair-due arm.
    let mut session_health: SessionHealthTracker<RecordKey> = SessionHealthTracker::new();
    // §RS-1.2 repair resolution: the tracker keys by `RecordKey`, but the repair works in
    // `owner_seed`. This map (fed at resweep dispatch — the key is deterministic per seed)
    // resolves a repair-due `RecordKey` back to its owner seed. `resolved_seeds` avoids a
    // redundant resolve round-trip once a seed's key is known.
    let mut record_key_owners: HashMap<RecordKey, [u8; 32]> = HashMap::new();
    let mut resolved_seeds: HashSet<[u8; 32]> = HashSet::new();
    // Records detected repair-due while a repair/resweep is already in flight or during
    // warmup: enqueued here (dedup by the tracker's latch) and drained one-at-a-time at
    // the cadence tick. One repair in flight at a time via `resweep_busy` (§RS-1.2).
    let mut pending_repairs: VecDeque<RecordKey> = VecDeque::new();
    // (#180 §RS-4, CRSH-ISC-13/16) Records armed by the last manual Refresh for
    // evidence-gated re-establishment: the SweepHealth fold arm consumes an arm on the
    // record's next swept pass and re-establishes on a SINGLE failed pass in calm weather
    // (lowering K to 1 for the arm only). A healthy armed record clears its arm and
    // re-establishes nothing (CRSH-ISC-16). Filled only by `handle_refresh_shares`.
    let mut refresh_armed: HashSet<RecordKey> = HashSet::new();
    // (#180 §RS-2, CRSH-ISC-8) Spawned share fetches report their generation-tagged outcome
    // here; the loop folds them on-loop (`fold_fetch_outcome`) so a slow/failing fetch never
    // parks the command loop and starves chat (#180 item 3). The actor holds a sender for
    // the whole loop, so the receiver never closes while the actor lives.
    let (fetch_outcome_tx, mut fetch_outcome_rx) =
        tokio::sync::mpsc::unbounded_channel::<FetchOutcome>();
    // (#197, mirroring #180 §RS-2 / CRSH-ISC-29) Spawned chunk DOWNLOADS (`ConfirmFetch`)
    // report their terminal outcome here; the loop folds them on-loop (`fold_confirm_outcome`)
    // so a slow/large download never parks the command loop and starves chat. Separate from
    // the browse `fetch_outcome` channel because the download fold (Complete / route-death /
    // local-disk) is disjoint from the browse fold's staleness dance.
    let (confirm_outcome_tx, mut confirm_outcome_rx) =
        tokio::sync::mpsc::unbounded_channel::<ConfirmOutcome>();
    // (#180 §RS-3, CRSH-ISC-10) The in-use guard over discovered shares' imported routes
    // lives on `shares.route_guard`; the loop drains `shares.pending_route_releases` below.

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // UI side dropped — shut down
                // #157: anchor the steady-resweep warmup hand-off to each Connect, and
                // reset the round-robin cursor so a reconnect re-sweeps from the top.
                if matches!(cmd, NetCommand::Connect { .. }) {
                    connected_at = Some(Instant::now());
                    resweep_cursor = None;
                }
                // (#180 §RS-4, CRSH-ISC-13) The manual Refresh button drives loop-local
                // state (resweep_busy, the record-key maps, refresh_armed) that the stateless
                // command dispatcher cannot reach, so its §RS-4 contract runs here — the only
                // path into the Refresh contract (CRSH-ISC-20).
                if matches!(cmd, NetCommand::ResweepShares) {
                    handle_refresh_shares(
                        &evt_tx, &net, &shares, &circles, &resweep_busy,
                        &mut record_key_owners, &mut resolved_seeds, &mut refresh_armed,
                    ).await;
                } else {
                    handle_command(
                        cmd, &evt_tx, &cmd_tx, &mut net, &mut ev_rx, &mut circles, &mut my_handle,
                        &mut shares, &fetch_outcome_tx, &confirm_outcome_tx,
                    ).await;
                }
            }
            // (#180 §RS-2, CRSH-ISC-8/19) Fold a spawned fetch's generation-tagged outcome
            // on-loop: render the manifest / mark Unresolved / record the imported route. A
            // stale-generation outcome no-ops. Cheap and synchronous — no fetch is awaited
            // here (the await already happened in the spawned task).
            Some(outcome) = fetch_outcome_rx.recv() => {
                fold_fetch_outcome(&mut shares, &evt_tx, outcome);
            }
            // (#197, CRSH-ISC-29) Fold a spawned download's terminal outcome on-loop: clear
            // Unresolved on success / mark Unresolved on route-death / neither on a local-disk
            // failure, and emit the terminal FetchComplete/FetchError. Cheap and synchronous —
            // the download itself already ran in the spawned task, never awaited here.
            Some(outcome) = confirm_outcome_rx.recv() => {
                fold_confirm_outcome(&mut shares, &evt_tx, outcome);
            }
            // Only poll the Veilid event stream once connected.
            Some(ev) = recv_opt(&mut ev_rx), if ev_rx.is_some() => {
                match ev {
                    // #144: surface the attach peer counts to the startup mask as they
                    // climb during the cold-start warmup.
                    VeilidNetEvent::Attachment {
                        reliable_peers,
                        live_peers,
                        ..
                    } => {
                        let _ = evt_tx.send(NetEvent::PeerCount {
                            reliable: reliable_peers,
                            live: live_peers,
                        });
                    }
                    // CRSH-ISC-1/2: fold one completed sweep's per-record outcome into the
                    // session-health tracker. Weather is the WB-5.1 estimator, consumed via
                    // the shared ReapGate (`suspend_reaping` == elevated) — no new estimator
                    // (§RS-1.2). L2 watch state is not yet surfaced by the transport, so the
                    // L1-only path supplies `Unknown` (§RS-1.3 open question).
                    VeilidNetEvent::SweepHealth { key, outcome } => {
                        let weather = if shares.reap_gate.suspend_reaping(Instant::now()) {
                            Weather::Elevated
                        } else {
                            Weather::Calm
                        };
                        let input = SweepHealthInput {
                            attempted: outcome.attempted,
                            failed: outcome.failed,
                            found: outcome.found,
                            watch: WatchState::Unknown,
                            weather,
                        };
                        let decision = session_health.observe(key.clone(), input);
                        // (#180 §RS-4, CRSH-ISC-13/16) PEEK this record's Refresh arm — do NOT
                        // consume it here. The arm's lifecycle is decided by the branch taken
                        // (R1): consumed on immediate dispatch or on a not-due pass, but LEFT
                        // IN PLACE when the repair is enqueued busy/warming so the drain can
                        // honor it. An armed record re-establishes on a SINGLE failed pass in
                        // calm weather (evidence-gated, K lowered to 1 for the arm only); an
                        // armed HEALTHY record clears the arm and re-establishes nothing
                        // (anti-criterion CRSH-ISC-16). Un-armed cadence is unchanged.
                        let armed = refresh_armed.contains(&key);
                        if refresh_or_cadence_due(decision, armed, &input) {
                            // Step 3b re-establishment (§RS-1.2), shared verbatim by the
                            // cadence repair-due path and the §RS-4 single-failure override.
                            // The SweepHealth carrying the triggering failed pass IS a cadence
                            // (resweep-completion) tick, so an immediate dispatch here is still
                            // cadence-timed (CRSH-ISC-2). Warmup guard (§RS-1.3): no repair
                            // before the resweep warmup hand-off. One repair in flight at a
                            // time via `resweep_busy`; if busy or still warming, queue for the
                            // next cadence drain.
                            let warmed = connected_at.is_some_and(|t| {
                                t.elapsed() >= STEADY_RESWEEP_WARMUP_HANDOFF
                            });
                            match record_key_owners.get(&key).copied() {
                                Some(owner_seed) => {
                                    let free = !resweep_busy
                                        .load(std::sync::atomic::Ordering::Acquire);
                                    if let (true, true, Some(handle)) =
                                        (warmed, free, net.as_ref())
                                    {
                                        // Immediate dispatch: consume the arm now.
                                        refresh_armed.remove(&key);
                                        session_health.note_repair_dispatched(&key);
                                        // (#180 F5, CRSH-ISC-24) If this key was already
                                        // enqueued on a prior busy tick, drop the stale copy
                                        // so the next drain cannot pop and dispatch it a
                                        // second time. Defense-in-depth with the drain
                                        // re-check (note_repair_dispatched cleared the latch,
                                        // so the drain would also skip it) — both are cheap;
                                        // keep the queue clean.
                                        pending_repairs.retain(|k| k != &key);
                                        spawn_repair(handle, &resweep_busy, owner_seed);
                                        daemonseed_veilid_net::vtrace!(
                                            "gui session-health: repairing dead record \
                                             ({} failed) — re-establishing session",
                                            input.failed
                                        );
                                    } else if !pending_repairs.contains(&key) {
                                        // (#180 R1) Busy/warming: queue the repair and LEAVE
                                        // the arm in place — a §RS-4 armed record is not
                                        // latched repair-due, so the drain must honor the
                                        // surviving arm (else the queued repair is dropped as
                                        // "recovered" and the dead record never heals).
                                        pending_repairs.push_back(key);
                                        daemonseed_veilid_net::vtrace!(
                                            "gui session-health: record repair-due — \
                                             queued (busy or warming)"
                                        );
                                    }
                                    // else: already queued — the surviving arm (if any) stays
                                    // in place for the existing entry's drain.
                                }
                                None => {
                                    // Unmapped owner: cannot dispatch or enqueue, so the arm
                                    // (if any) is consumed rather than left dangling.
                                    refresh_armed.remove(&key);
                                    daemonseed_veilid_net::vtrace!(
                                        "gui session-health: repair-due for an unmapped \
                                         record key — cannot resolve owner seed"
                                    );
                                }
                            }
                        } else {
                            // (#180 R1) Not due (healthy pass, or elevated/Suppressed): consume
                            // the arm. A healthy armed record clears its arm and re-establishes
                            // nothing (CRSH-ISC-16); a weather-suppressed armed record likewise
                            // clears and re-arms nothing.
                            refresh_armed.remove(&key);
                            if matches!(decision, RepairDecision::Suppressed) {
                                daemonseed_veilid_net::vtrace!(
                                    "gui session-health: repair-due suppressed (elevated \
                                     weather) — will resume in calm"
                                );
                            }
                        }
                    }
                    // Everything else demuxes in handle_inbound (which only acts on Inbound).
                    other => handle_inbound(other, &evt_tx, &mut circles, &mut shares),
                }
            }
            // Age out discovered shares not reheard within the TTL (Shape B liveness):
            // a sharer that vanished without a withdraw self-clears from the list.
            // Own shares live in `shares.own`, never in the catalog, so they are safe.
            _ = prune_timer.tick() => {
                if shares.catalog.prune(Instant::now()) > 0 {
                    let _ = evt_tx.send(NetEvent::SharesSnapshot { shares: shares.listings() });
                }
            }
            // #141: keep operator content alive in the DHT — re-publish the known MOTD +
            // announcements OFF the actor loop (their DHT values age out without owner
            // refresh, else they silently expire). Collect synchronously, spawn the
            // writes so a many-item record never stalls chat/commands (#128 class).
            _ = operator_keepalive.tick() => {
                if let (Some(handle), Some((owner_seed, items))) =
                    (net.as_ref(), collect_operator_keepalive_items(&shares))
                {
                    let handle = handle.clone();
                    tokio::spawn(async move {
                        let mut n = 0usize;
                        for (slot, value) in items {
                            if handle
                                .publish_current_state(owner_seed, &slot, value)
                                .await
                                .is_ok()
                            {
                                n += 1;
                            }
                        }
                        if n > 0 {
                            daemonseed_veilid_net::vtrace!(
                                "gui operator: keep-alive re-published {n} item(s)"
                            );
                        }
                    });
                }
            }
            // Emit one presence keepalive per joined room + reap the rosters, then
            // re-arm the timer with a fresh jittered deadline (WB-1.2).
            () = heartbeat.as_mut() => {
                emit_and_reap_presence(&evt_tx, &net, &my_handle, &mut shares, &mut circles);
                heartbeat
                    .as_mut()
                    .reset(tokio::time::Instant::now() + next_keepalive_interval());
            }
            // #157 (generalized): once the warmup window has closed, re-sweep ONE
            // subscribed chat/discovery record per tick (round-robin) so a message or
            // advert written after warmup can no longer be stranded by the lossy DHT
            // watch. Presence records are excluded — they self-heal via keepalive
            // re-writes (WB-4). The sweep is spawned off the loop (its record-open await
            // must not stall commands/chat, #128 class); the cursor advance is
            // synchronous so the round-robin stays deterministic.
            _ = steady_resweep.tick() => {
                // (#180 §RS-1.4, CRSH-ISC-6/15) Dispatch parked browse retries on the
                // consumer's own cursor tick (decorrelated from the sharer's re-announce).
                // Independent of the resweep `ready` gate below: it only marks route-refreshed
                // shares fetchable-again (reframe #180) — no sweep, no network op.
                process_parked_browse_retries(&mut shares, &evt_tx);
                // Ready once the warmup hand-off window has elapsed, we are attached, and
                // no prior resweep is still in flight (the WB-2 one-sweep-at-a-time bound
                // — a resweep can outlast the tick on a slow DHT).
                let ready = connected_at
                    .is_some_and(|t| t.elapsed() >= STEADY_RESWEEP_WARMUP_HANDOFF)
                    && !resweep_busy.load(std::sync::atomic::Ordering::Acquire);
                if let Some(handle) = net.as_ref().filter(|_| ready) {
                    // Repairs take priority over resweeps (§RS-1.2): heal a dead record
                    // before spending cadence ticks resweeping healthy ones. Drained one at
                    // a time, serialized with the resweep via `resweep_busy`.
                    if let Some(key) = pending_repairs.pop_front() {
                        // (#180 F4/F5/R1, CRSH-ISC-13/24) Re-check at drain. A record queued
                        // while busy/warming may have RECOVERED before the queue drained (a
                        // successful sweep cleared its streak + latch), or already been
                        // dispatched by the immediate fold arm (which cleared its latch).
                        // Either way, dispatching a recovered record would needlessly tear it
                        // down and re-establish (with REPAIR_CLOSE_FIRST this closes a live
                        // record and can drop a message in the re-watch gap). BUT a §RS-4
                        // manual-Refresh arm is NOT latched repair-due (it lowers K to 1 for a
                        // single failed pass), so a queued armed repair must also be honored
                        // via its surviving arm — else the manual Refresh silently fails to
                        // heal a dead record during busy/warmup (R1). Consume the arm here and
                        // dispatch iff STILL latched cadence-repair-due OR armed; otherwise the
                        // popped entry is stale — drop it (pop_front already removed it).
                        let armed = refresh_armed.remove(&key);
                        if drain_should_dispatch(session_health.is_repair_due(&key), armed) {
                            if let Some(&owner_seed) = record_key_owners.get(&key) {
                                session_health.note_repair_dispatched(&key);
                                spawn_repair(handle, &resweep_busy, owner_seed);
                                daemonseed_veilid_net::vtrace!(
                                    "gui steady-resweep: draining a queued repair"
                                );
                            }
                        } else {
                            daemonseed_veilid_net::vtrace!(
                                "gui steady-resweep: dropping a stale queued repair \
                                 (record recovered or already dispatched)"
                            );
                        }
                    } else {
                        let mut seeds: Vec<[u8; 32]> = Vec::new();
                        seeds.extend(shares.operator.as_ref().map(|op| op.announce_owner_seed));
                        if let Some(lobby) = shares.lobby.as_ref() {
                            seeds.push(lobby.owner_seed);
                            seeds.push(lobby.share_owner_seed);
                        }
                        seeds.extend(circles.iter().map(|c| c.owner_seed));
                        if let Some(seed) = next_resweep_seed(&mut seeds, resweep_cursor) {
                            resweep_cursor = Some(seed);
                            // Feed the RecordKey→owner_seed map once per seed (§RS-1.2): the
                            // key is deterministic per seed (local crypto), so resolve it the
                            // first time this seed is swept and cache it for repair resolution.
                            if resolved_seeds.insert(seed) {
                                if let Ok(rk) = handle.rendezvous_record_key(seed).await {
                                    record_key_owners.insert(rk, seed);
                                } else {
                                    resolved_seeds.remove(&seed); // retry next round
                                }
                            }
                            resweep_busy.store(true, std::sync::atomic::Ordering::Release);
                            daemonseed_veilid_net::vtrace!(
                                "gui steady-resweep: re-sweeping 1 of {} record(s)",
                                seeds.len()
                            );
                            let handle = handle.clone();
                            let busy = resweep_busy.clone();
                            tokio::spawn(async move {
                                let _ = handle.resweep_rendezvous(seed).await;
                                busy.store(false, std::sync::atomic::Ordering::Release);
                            });
                        }
                    }
                }
            }
        }
        // (#180 §RS-3, CRSH-ISC-10) Release any imported route the in-use guard cleared this
        // iteration (superseded advert + no in-flight fetch), off the loop.
        drain_route_releases(&mut shares, &net);
    }
}

/// (#180 §RS-3, CRSH-ISC-10) Release, off the loop, every imported route the in-use guard
/// cleared this iteration. Each release is spawned (fire-and-forget) through the net handle,
/// which routes it via `release_tolerant` — so an already-evicted id is a benign no-op. When
/// disconnected there is no handle to release through; the drained ids fall to the transport
/// LRU/expiry backstop (design Evidence 2).
fn drain_route_releases(shares: &mut ShareState, net: &Option<VeilidNetHandle>) {
    if shares.pending_route_releases.is_empty() {
        return;
    }
    let routes = std::mem::take(&mut shares.pending_route_releases);
    let Some(handle) = net.as_ref() else {
        return;
    };
    for route in routes {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle.release_route(route).await;
        });
    }
}

/// (#180 §RS-4, CRSH-ISC-13/16) The SweepHealth fold-arm re-establishment gate: whether a
/// swept record should be re-established now. `true` iff the tracker flagged it repair-due
/// (the K-consecutive cadence path, [`RepairDecision::RepairDue`]) **or** it was manually
/// Refresh-`armed` AND this pass just failed ([`SweepHealthInput::is_failed_pass`]) in calm
/// weather — the §RS-4 single-failure override, which lowers the K threshold to 1 for an
/// armed record only. An armed **healthy** record (a non-failed pass) returns `false`, so a
/// Refresh over a healthy record re-establishes nothing and emits only sweep-shaped GETs
/// (anti-criterion CRSH-ISC-16). Un-armed records keep the cadence path unchanged.
fn refresh_or_cadence_due(decision: RepairDecision, armed: bool, input: &SweepHealthInput) -> bool {
    matches!(decision, RepairDecision::RepairDue)
        || (armed && input.is_failed_pass() && matches!(input.weather, Weather::Calm))
}

/// (#180 R1, CRSH-ISC-13/24) The `pending_repairs` drain dispatch gate: a queued repair is
/// dispatched iff the record is STILL latched cadence-repair-due (the K-consecutive path
/// survived the queue wait) **or** it carried a surviving §RS-4 Refresh `armed` flag. The arm
/// is the second disjunct because a manual-Refresh-armed record is never latched repair-due
/// (the arm lowers K to 1 for a single failed pass); without honoring it the drain drops an
/// armed queued repair as "recovered" and the dead record never heals during a busy/warmup
/// window — the R1 regression. `false` drops the popped entry (recovered AND un-armed).
fn drain_should_dispatch(is_repair_due: bool, armed: bool) -> bool {
    is_repair_due || armed
}

/// (#180 §RS-4, CRSH-ISC-13/16/20) The manual Refresh contract — the user-consented
/// accelerant, sent only by the UI Refresh button (`NetCommand::ResweepShares`). Steps:
///
/// 1. **Immediate re-render** from the current catalog (`SharesSnapshot`) — instant
///    feedback; the swept adverts fold in later via `apply_discovery`.
/// 2. **Arm** every share-bearing subscribed record (operator announce + lobby chat/share
///    records + every circle) in `refresh_armed`, resolving each seed to its deterministic
///    `RecordKey` (reusing the cadence-populated reverse map, else a one-shot local-crypto
///    resolve). The SweepHealth fold arm then re-establishes an armed record on a single
///    failed pass in calm weather ([`refresh_or_cadence_due`]).
/// 3. **Sweep-first wave** over the same records — traffic-shaped identically to the steady
///    resweep (GETs on existing sessions via `resweep_rendezvous`; NO open, NO watch, so a
///    healthy record is indistinguishable from a coincident cadence resweep — CRSH-ISC-16),
///    spawned off the actor loop so a multi-record wave never starves chat, and serialized
///    behind `resweep_busy` so it never overlaps a cadence sweep (WB-2 one-sweep-at-a-time).
///
/// If a cadence sweep/repair is already in flight, the wave is skipped this Refresh — the
/// arms persist and the following cadence resweeps sweep each armed record, so the fold arm
/// still applies the single-failure override (CRSH-ISC-13: "one action, no restart").
#[allow(clippy::too_many_arguments)]
async fn handle_refresh_shares(
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    shares: &ShareState,
    circles: &[VeilidCircle],
    resweep_busy: &Arc<std::sync::atomic::AtomicBool>,
    record_key_owners: &mut HashMap<RecordKey, [u8; 32]>,
    resolved_seeds: &mut HashSet<[u8; 32]>,
    refresh_armed: &mut HashSet<RecordKey>,
) {
    // 1. Immediate local re-render (§RS-4.4).
    let _ = evt_tx.send(NetEvent::SharesSnapshot {
        shares: shares.listings(),
    });
    let Some(handle) = net.as_ref() else {
        return;
    };
    // Build the same share-bearing subscribed record set the steady resweep round-robins.
    let mut seeds: Vec<[u8; 32]> = Vec::new();
    seeds.extend(shares.operator.as_ref().map(|op| op.announce_owner_seed));
    if let Some(lobby) = shares.lobby.as_ref() {
        seeds.push(lobby.owner_seed);
        seeds.push(lobby.share_owner_seed);
    }
    seeds.extend(circles.iter().map(|c| c.owner_seed));
    if seeds.is_empty() {
        return;
    }
    // 2. Arm every record (§RS-4.2). Resolve each seed → RecordKey via the cadence-populated
    //    reverse map first (no round-trip); else resolve once (local crypto, no network — the
    //    same call the tick uses) and cache it so the fold arm can map a failed pass back to
    //    its owner seed.
    for &seed in &seeds {
        let key = match record_key_owners
            .iter()
            .find(|(_, s)| **s == seed)
            .map(|(k, _)| k.clone())
        {
            Some(k) => Some(k),
            None => match handle.rendezvous_record_key(seed).await {
                Ok(rk) => {
                    record_key_owners.insert(rk.clone(), seed);
                    resolved_seeds.insert(seed);
                    Some(rk)
                }
                Err(_) => None,
            },
        };
        if let Some(k) = key {
            refresh_armed.insert(k);
        }
    }
    // 3. Sweep-first wave (§RS-4.1), off-loop and serialized behind `resweep_busy`. Acquire
    //    the guard by CAS so the wave never overlaps a cadence sweep/repair; if it is already
    //    held, skip the wave (the arms above still drive the single-failure override on the
    //    following cadence resweeps).
    if resweep_busy
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }
    daemonseed_veilid_net::vtrace!(
        "gui refresh: sweep-first wave over {} record(s)",
        seeds.len()
    );
    let handle = handle.clone();
    let busy = resweep_busy.clone();
    tokio::spawn(async move {
        for seed in seeds {
            let _ = handle.resweep_rendezvous(seed).await;
        }
        busy.store(false, std::sync::atomic::Ordering::Release);
    });
}

/// Spawn a one-shot **repair** of a dead rendezvous record session (§RS-1.2 step 3b),
/// serialized with the steady resweep via `resweep_busy` (one repair/resweep in flight at
/// a time). Fire-and-forget: the re-established backlog arrives as inbound events, and a
/// transport error self-heals on the next detection cycle. The caller resets the
/// session-health tracker (`note_repair_dispatched`) before this so the record re-detects
/// on a fresh streak if the repair does not restore service.
fn spawn_repair(
    handle: &VeilidNetHandle,
    resweep_busy: &Arc<std::sync::atomic::AtomicBool>,
    owner_seed: [u8; 32],
) {
    resweep_busy.store(true, std::sync::atomic::Ordering::Release);
    let handle = handle.clone();
    let busy = resweep_busy.clone();
    tokio::spawn(async move {
        let _ = handle.repair_rendezvous(owner_seed).await;
        busy.store(false, std::sync::atomic::Ordering::Release);
    });
}

/// Seal and publish ONE presence beacon for a PUBLIC room (lobby) — a WB-1 join,
/// keepalive, or leave, per `boundary` — spawning the DHT write off the actor loop
/// (the #128 D-0b pattern: `publish_presence` awaits an ack that can take seconds).
/// Fixed-length (WB-ISC-6) with an EMPTY digest: share liveness rides the share
/// record post-#153, so the veilid presence beacon carries no `live_share_ids` (its
/// removal also keeps the padded payload well inside the constant length). A seal /
/// transport failure is non-fatal — presence self-heals on the next cadence.
fn spawn_public_beacon(
    handle: &VeilidNetHandle,
    signing: &SignKeypair,
    room_key: &PublicRoomKey,
    presence_seed: [u8; 32],
    my_handle: &str,
    boundary: PresenceBoundary,
) {
    let fields = HeartbeatFields {
        room: DEFAULT_ROOM,
        sender_handle: my_handle,
        sent_unix_ms: now_unix_ms(),
        live_share_ids: &[],
        is_leave: matches!(boundary, PresenceBoundary::Leave),
    };
    if let Ok(sealed) = seal_public_heartbeat(room_key, signing, &fields) {
        let handle = handle.clone();
        let pubkey = signing.public_key().to_vec();
        tokio::spawn(async move {
            if let Err(e) = handle
                .publish_presence(presence_seed, &pubkey, sealed, boundary)
                .await
            {
                daemonseed_veilid_net::vtrace!("gui presence: {boundary:?} emit failed: {e}");
            }
        });
    }
}

/// Seal and publish ONE presence beacon for a CIRCLE (WB-1) — as
/// [`spawn_public_beacon`] but sealed under the circle `cot_key` and posted to the
/// circle's presence sibling record.
fn spawn_circle_beacon(
    handle: &VeilidNetHandle,
    signing: &SignKeypair,
    circle: &VeilidCircle,
    my_handle: &str,
    boundary: PresenceBoundary,
) {
    let label = default_circle_label(&circle_fingerprint(&circle.cot_key));
    let fields = HeartbeatFields {
        room: &label,
        sender_handle: my_handle,
        sent_unix_ms: now_unix_ms(),
        live_share_ids: &[],
        is_leave: matches!(boundary, PresenceBoundary::Leave),
    };
    if let Ok(sealed) = seal_circle_heartbeat(&circle.cot_key, signing, &fields) {
        let handle = handle.clone();
        let seed = circle.presence_owner_seed;
        let pubkey = signing.public_key().to_vec();
        tokio::spawn(async move {
            if let Err(e) = handle
                .publish_presence(seed, &pubkey, sealed, boundary)
                .await
            {
                daemonseed_veilid_net::vtrace!(
                    "gui circle presence: {boundary:?} emit failed: {e}"
                );
            }
        });
    }
}

/// Seal and AWAIT one LEAVE tombstone for a PUBLIC room (lobby) — the close-path
/// counterpart of [`spawn_public_beacon`]. On graceful close the write is *awaited*,
/// not spawned fire-and-forget, so the leave reaches the DHT within the close budget
/// before the process exits (#161) — a spawned task is aborted at exit, leaving the
/// member to age out at the ~600s TTL. `publish_presence` resolves after the
/// scheduler's `set_dht_value` returns, so the await bounds delivery. Non-fatal on
/// seal/transport failure (the TTL backstops it).
async fn publish_public_leave(
    handle: &VeilidNetHandle,
    signing: &SignKeypair,
    room_key: &PublicRoomKey,
    presence_seed: [u8; 32],
    my_handle: &str,
) {
    let fields = HeartbeatFields {
        room: DEFAULT_ROOM,
        sender_handle: my_handle,
        sent_unix_ms: now_unix_ms(),
        live_share_ids: &[],
        is_leave: true,
    };
    if let Ok(sealed) = seal_public_heartbeat(room_key, signing, &fields) {
        let pubkey = signing.public_key().to_vec();
        if let Err(e) = handle
            .publish_presence(presence_seed, &pubkey, sealed, PresenceBoundary::Leave)
            .await
        {
            daemonseed_veilid_net::vtrace!("gui presence: Leave emit failed: {e}");
        }
    }
}

/// Seal and AWAIT one LEAVE tombstone for a CIRCLE — the close-path counterpart of
/// [`spawn_circle_beacon`] (see [`publish_public_leave`] for why the leave is awaited).
async fn publish_circle_leave(
    handle: &VeilidNetHandle,
    signing: &SignKeypair,
    circle: &VeilidCircle,
    my_handle: &str,
) {
    let label = default_circle_label(&circle_fingerprint(&circle.cot_key));
    let fields = HeartbeatFields {
        room: &label,
        sender_handle: my_handle,
        sent_unix_ms: now_unix_ms(),
        live_share_ids: &[],
        is_leave: true,
    };
    if let Ok(sealed) = seal_circle_heartbeat(&circle.cot_key, signing, &fields) {
        let pubkey = signing.public_key().to_vec();
        if let Err(e) = handle
            .publish_presence(
                circle.presence_owner_seed,
                &pubkey,
                sealed,
                PresenceBoundary::Leave,
            )
            .await
        {
            daemonseed_veilid_net::vtrace!("gui circle presence: Leave emit failed: {e}");
        }
    }
}

/// Emit one sealed presence KEEPALIVE (WB-1.2) per joined room to its presence
/// record, then `reap` each roster so members past their TTL age out — but only in
/// calm (WB-1.10): while the DHT regime is elevated, reaping is suspended via the
/// [`ReapGate`]. A missing identity/lobby, a seal failure, or a closed transport is
/// non-fatal — presence self-heals on the next tick. A reap that changed a set pushes a
/// fresh (possibly empty) Roster; a change in the aggregate "presence may be stale"
/// signal pushes a `NetEvent::PresenceStale` (WB-ISC-20).
fn emit_and_reap_presence(
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    my_handle: &str,
    shares: &mut ShareState,
    circles: &mut [VeilidCircle],
) {
    // WB-5.1 / I5″.6/.7: fold the scheduler's published median DHT-weather through the
    // ReapGate (hysteresis band 8s/4s + 220s resume grace) into "suspend reaping now".
    // Sampled once per tick for the whole reap pass; while suspended a keepalive merely
    // queued in an elevated regime does not false-reap its member.
    let now = Instant::now();
    let weather_ms = net.as_ref().map(|h| h.last_write_latency_ms()).unwrap_or(0);
    shares.reap_gate.observe(weather_ms, now);
    let suspend = shares.reap_gate.suspend_reaping(now);
    // EMIT the lobby keepalive — needs an identity to self-sign with (ISC-C57), a
    // live transport, and a subscribed lobby.
    if let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone())
        && let Some(lobby) = shares.lobby.as_ref()
    {
        spawn_public_beacon(
            handle,
            &signing,
            &lobby.room_key,
            lobby.presence_owner_seed,
            my_handle,
            PresenceBoundary::Keepalive,
        );
    }
    // REAP the lobby on the same tick — the timer is the reap clock. Push a fresh
    // roster only when a reap actually removed someone (a reap-to-empty still pushes
    // an empty roster so the UI clears).
    if let Some(lobby) = shares.lobby.as_mut()
        && !lobby.presence.reap(now, suspend).is_empty()
    {
        let entries = roster_from_members(&lobby.presence.members());
        let _ = evt_tx.send(NetEvent::Roster {
            circle_id: None,
            entries,
        });
    }

    // ── Per-circle presence (#77) — one keepalive per joined circle. ──
    if !circles.is_empty()
        && let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone())
    {
        for circle in circles.iter() {
            spawn_circle_beacon(
                handle,
                &signing,
                circle,
                my_handle,
                PresenceBoundary::Keepalive,
            );
        }
    }
    // Reap each circle's tracker on the same tick (in calm); push a fresh (possibly
    // empty) roster tagged with that circle for any tracker a reap changed.
    for circle in circles.iter_mut() {
        if !circle.presence.reap(now, suspend).is_empty() {
            let entries = roster_from_members(&circle.presence.members());
            let _ = evt_tx.send(NetEvent::Roster {
                circle_id: Some(circle.circle_id),
                entries,
            });
        }
    }

    // WB-5.1 / I5″.7 (WB-ISC-20): "presence may be stale" — computed AFTER the reaps
    // (in calm the reaper removed overdue members, so nothing reads stale). True while
    // the suspension holds a past-TTL member visible on ANY roster; emitted only on a
    // change so the UI toggles the indicator without per-tick churn.
    let stale = shares
        .lobby
        .as_ref()
        .is_some_and(|l| l.presence.stale_suspected(now, suspend))
        || circles
            .iter()
            .any(|c| c.presence.stale_suspected(now, suspend));
    if stale != shares.prev_presence_stale {
        shares.prev_presence_stale = stale;
        let _ = evt_tx.send(NetEvent::PresenceStale { stale });
    }
}

/// Await the optional Veilid event receiver. The `if ev_rx.is_some()` guard on
/// the select arm ensures this is only polled when `Some`, so the `unwrap` holds.
async fn recv_opt(ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>) -> Option<VeilidNetEvent> {
    ev_rx.as_mut().unwrap().recv().await
}

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    cmd: NetCommand,
    evt_tx: &UnboundedSender<NetEvent>,
    // Kept for a uniform spawn signature with the relay actor; the veilid actor no
    // longer self-sends (the #93 connect-landing refresh that used it was removed in
    // #142 in favour of the #142 unread dot).
    _cmd_tx: &UnboundedSender<NetCommand>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    circles: &mut Vec<VeilidCircle>,
    my_handle: &mut String,
    shares: &mut ShareState,
    // (#180 §RS-2) Where a spawned `FetchShare` reports its generation-tagged outcome for
    // on-loop folding — the fetch never blocks this command loop (CRSH-ISC-8).
    fetch_outcome_tx: &UnboundedSender<FetchOutcome>,
    // (#197, CRSH-ISC-29) Where a spawned `ConfirmFetch` download reports its terminal
    // outcome for on-loop folding — the download never blocks this command loop either.
    confirm_outcome_tx: &UnboundedSender<ConfirmOutcome>,
) {
    match cmd {
        NetCommand::Connect {
            display_handle,
            rejoin_circles,
            republish_roots,
            stable_signing_key,
            stable_share_root_ikm,
            ..
        } => {
            if let Some(h) = display_handle {
                *my_handle = h;
            }
            // Capture the stable identity key (least-authority: kept behind an Arc
            // for sealing announcements + minting the route-advert capability; the
            // raw key never enters veilid-net).
            shares.signing = stable_signing_key.map(Arc::new);
            // (#156) Capture the share-root IKM (Arc — it holds secret bytes) so a
            // publish derives a receiver-verifiable share_id from the same identity.
            shares.share_root_ikm = stable_share_root_ikm.map(Arc::new);
            // #188: a STABLE per-profile veilid namespace discriminator from the
            // unlocked identity pubkey — distinct across profiles (co-resident store
            // isolation), stable across a profile's launches (store reuse). `None` on
            // the ephemeral no-profile path.
            let ns_key = shares.signing.as_ref().map(|k| {
                let pk = k.public_key().to_vec();
                hex::encode(&pk[..pk.len().min(8)])
            });
            connect(evt_tx, net, ev_rx, ns_key).await;
            if net.is_some() {
                // Subscribe the world-derivable lobby so share announcements fold
                // into the catalog as they arrive (Phase 3 discovery).
                subscribe_lobby(shares, net, evt_tx, my_handle).await;
                // Subscribe the operator announce/MOTD record (Phase 4 A-c) so MOTD +
                // announcement items fold in as they arrive.
                subscribe_operator_space(shares, net).await;
                // Operator content (MOTD/announcements) folds in ASYNC via the
                // post-connect sweep + watch; each verified fold emits a
                // `PublicSpaceSnapshot` that drives the #142 unread dot, and the warmup
                // re-sweep below force-refreshes the operator record early. (The #93
                // connect-time auto-landing was removed in #142 in favour of the dot, so
                // there is no self-sent settle-refresh here any more.)
                // #102: relay-parity — silently re-subscribe persisted circles after
                // attach, so a circle restored into the UI is actually joined on the
                // transport (else SendCircle finds known=[] → "join before sending").
                for (circle_id, phrase) in rejoin_circles {
                    join_circle(
                        circle_id,
                        &phrase,
                        evt_tx,
                        net,
                        circles,
                        my_handle,
                        shares.signing.clone(),
                    )
                    .await;
                }
                // #108: relay-parity — re-publish persisted shares on connect, exactly
                // like the circle re-join above (the relay path does this; the Veilid
                // path was dropping `republish_roots`). The node identity is ephemeral
                // per launch, so each re-serves under a fresh private route and
                // discovery re-announces it. A per-share failure surfaces as a publish
                // error and never aborts the others.
                let sharer = my_handle.clone();
                // #122: lead the restore with a single reassurance banner before any
                // share is re-served, instead of a per-share toast coincident with the
                // share going live.
                if !republish_roots.is_empty() {
                    let _ = evt_tx.send(NetEvent::RestoreStarted {
                        count: republish_roots.len(),
                    });
                }
                for (root, persisted_name) in republish_roots {
                    let name = crate::net::republish_name(&root, persisted_name.as_deref());
                    publish_share(shares, evt_tx, net, root, name, sharer.clone(), true).await;
                }
                // #132 / #140: the passive watch's first fold lands tens of seconds in,
                // so a message/announcement published during the post-connect warmup
                // window is missed by the join-time one-shot sweep and only surfaces
                // late. Replace the single delayed re-sweep with a STEPPED, priority-
                // ordered schedule ([`WARMUP_RESWEEP_SCHEDULE`]): force-refresh the
                // operator record first (its MOTD/announce feeds the #142 unread dot),
                // then the lobby, then circles, at widening delays. Re-swept already-seen
                // items are deduped downstream (`apply_discovery` self-filter,
                // `push_message` exact-match). Presence records self-heal via the
                // heartbeat cycle and are excluded.
                if let Some(handle) = net.as_ref() {
                    let handle = handle.clone();
                    let priority = warmup_priority_records(
                        shares.operator.as_ref().map(|op| op.announce_owner_seed),
                        shares.lobby.as_ref().map(|l| l.owner_seed),
                        shares.lobby.as_ref().map(|l| l.share_owner_seed),
                    );
                    let circle_seeds: Vec<[u8; 32]> =
                        circles.iter().map(|c| c.owner_seed).collect();
                    daemonseed_veilid_net::vtrace!(
                        "gui connect: scheduling {}-round stepped warmup re-sweep ({} priority + {} circles)",
                        WARMUP_RESWEEP_SCHEDULE.len(),
                        priority.len(),
                        circle_seeds.len()
                    );
                    tokio::spawn(async move {
                        // Absolute deadlines from connect: `sleep_until` means a round's own
                        // re-sweep await time never pushes later rounds later (#140 review —
                        // no accumulated drift between rounds).
                        let start = tokio::time::Instant::now();
                        for (round, &at) in WARMUP_RESWEEP_SCHEDULE.iter().enumerate() {
                            tokio::time::sleep_until(start + at).await;
                            // Operator + lobby every round (top priority + #93 landing feed).
                            for seed in &priority {
                                let _ = handle.resweep_rendezvous(*seed).await;
                            }
                            // Circles only in the early rounds — bounds the fan-out for a
                            // heavily-joined user (#140 review).
                            if round < WARMUP_CIRCLE_RESWEEP_ROUNDS {
                                for seed in &circle_seeds {
                                    let _ = handle.resweep_rendezvous(*seed).await;
                                }
                            }
                        }
                    });
                }
            }
        }
        NetCommand::SetMyHandle { handle } => {
            *my_handle = handle;
        }
        NetCommand::JoinCircle { circle_id, phrase } => {
            join_circle(
                circle_id,
                &phrase,
                evt_tx,
                net,
                circles,
                my_handle,
                shares.signing.clone(),
            )
            .await;
        }
        NetCommand::SendCircle { circle_id, text } => {
            send_circle(
                circle_id,
                &text,
                evt_tx,
                net,
                circles,
                my_handle,
                shares.signing.clone(),
            )
            .await;
        }

        // ── Public shares (Phase 3 Slice 2b) ──
        NetCommand::PublishShare {
            root,
            name,
            sharer_handle,
        } => {
            // A fresh user-driven publish (restored: false → "Published …" status).
            publish_share(shares, evt_tx, net, root, name, sharer_handle, false).await;
        }
        NetCommand::UnpublishShare { share_id } => {
            unpublish_share(shares, evt_tx, net, &share_id).await;
        }
        NetCommand::WithdrawAllOwned { ack } => {
            // Business-as-usual on a graceful quit: withdraw every owned share so it
            // drops from peers' lists at once (not via the TTL backstop), then ack so
            // the close path can briefly wait for these to reach the network.
            for s in shares.own.clone() {
                unpublish_share(shares, evt_tx, net, &s.share_id).await;
            }
            // WB-1.3: publish one LEAVE tombstone per joined room inside the same
            // close budget (the #121 pattern). AWAIT each (not fire-and-forget spawn,
            // #161) so the leave actually reaches the DHT before the process exits —
            // a spawned task is aborted at exit and the member ages out at the ~600s
            // TTL instead of departing immediately. The funnel's I3 dominance keeps a
            // queued keepalive from superseding it (now closed on the in-flight window
            // too, #164). The tombstone is byte-identical to a keepalive on the wire
            // (WB-ISC-6); only in-room members decrypt the leave marker.
            if let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone()) {
                if let Some(lobby) = shares.lobby.as_ref() {
                    publish_public_leave(
                        handle,
                        &signing,
                        &lobby.room_key,
                        lobby.presence_owner_seed,
                        my_handle,
                    )
                    .await;
                }
                for circle in circles.iter() {
                    publish_circle_leave(handle, &signing, circle, my_handle).await;
                }
            }
            let _ = ack.send(());
        }
        NetCommand::RefreshShares => {
            // Local re-render of the current catalog ONLY. This rides the ~3 s
            // liveness auto-poll (main.rs poll_tick), so it MUST stay cheap: putting a
            // DHT re-sweep here re-swept the lobby every 3 s (#133 regression) — a CPU
            // storm plus re-delivery of the whole un-deduped lobby backlog. The
            // re-sweep now lives on the user-initiated ResweepShares (below) and the
            // one-shot delayed post-connect re-sweep (#132).
            let _ = evt_tx.send(NetEvent::SharesSnapshot {
                shares: shares.listings(),
            });
        }
        NetCommand::ResweepShares => {
            // (#180 §RS-4) The manual Refresh contract runs in the actor loop
            // (`handle_refresh_shares`), which owns the loop-local state it needs
            // (resweep_busy, the record-key maps, refresh_armed). ResweepShares is
            // intercepted before this dispatcher, so this arm is never reached.
            unreachable!("ResweepShares is handled in the actor loop (§RS-4)");
        }
        NetCommand::FetchShare { share_id, name } => {
            // (#180 §RS-2, CRSH-ISC-8) Spawn the fetch off-loop and return immediately — a
            // slow/failing fetch can never park this loop and starve chat (#180 item 3).
            spawn_fetch_share(shares, evt_tx, net, fetch_outcome_tx, &share_id, &name);
        }
        NetCommand::ConfirmFetch {
            share_id,
            name,
            fetched_root,
            selected,
            flat_dest,
        } => {
            // (#197, CRSH-ISC-29) Spawn the download off-loop and return immediately — a
            // slow/large download can never park this loop and starve chat (mirrors the #180
            // §RS-2 FetchShare restructure). The terminal outcome folds on-loop.
            spawn_confirm_fetch(
                shares,
                evt_tx,
                net,
                confirm_outcome_tx,
                &share_id,
                &name,
                fetched_root,
                selected,
                flat_dest,
            );
        }

        // ── Public-room (Lobby) chat ──
        NetCommand::SendRoom { text } => {
            send_room(&text, evt_tx, net, my_handle, shares).await;
        }

        // ── Operator announcements / MOTD (Phase 4 A-c) ──
        NetCommand::RefreshPublicSpace => refresh_public_space(shares, evt_tx, net).await,
        NetCommand::SetMotd { text } => set_motd(shares, evt_tx, net, &text).await,
        NetCommand::UploadAnnouncement { topic, body } => {
            upload_announcement(shares, evt_tx, net, &topic, &body).await;
        }
    }
}

/// Start a Veilid node bound to a fresh daemonseed-derived identity (D3) and
/// #188: reserve an OS-assigned free port, then release it, so the Veilid node can
/// bind udp/tcp/ws there without clashing with a co-resident instance. Binding
/// `0.0.0.0:0` lets the kernel pick a free port; we read it back and drop the probe
/// socket. Reusing a concrete `:{port}` (rather than literal `:0`) keeps us on the
/// proven explicit-port path. The probe→veilid-bind gap is a negligible race on the
/// dev multi-instance path this serves; a residual clash still surfaces as the
/// (now port-clash-aware) start error.
fn pick_free_port() -> Option<u16> {
    std::net::TcpListener::bind("0.0.0.0:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

/// attach to the public network. No relay address / handshake (D1/D4): the
/// bootstrap is baked into the node config.
async fn connect(
    evt_tx: &UnboundedSender<NetEvent>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    // #188: stable per-profile veilid namespace discriminator (hex of the unlocked
    // identity pubkey prefix); `None` on the ephemeral no-profile path.
    ns_key: Option<String>,
) {
    if net.is_some() {
        let _ = evt_tx.send(NetEvent::Connected);
        return;
    }
    // The node identity is per-launch; circle membership derives from the phrase,
    // not the node key, so a fresh identity is fine (proven by #99's two
    // independent nodes sharing a rendezvous).
    let id = match derive_identity_keys(
        &match Mnemonic::generate() {
            Ok(m) => m,
            Err(e) => return fail(evt_tx, format!("identity seed: {e}")),
        },
        Identity::Primary,
    ) {
        Ok(k) => k,
        Err(e) => return fail(evt_tx, format!("identity keys: {e}")),
    };
    // Per-instance overrides so several clients can run on ONE host (the
    // single-machine felt-test): `DAEMONSEED_VEILID_DIR` gives each instance its
    // own Veilid protected-store, `DAEMONSEED_VEILID_PORT` its own listen port.
    let dir = std::env::var("DAEMONSEED_VEILID_DIR").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join("daemonseed-gui-veilid")
            .to_string_lossy()
            .into_owned()
    });
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir);
    if let Ok(port) = std::env::var("DAEMONSEED_VEILID_PORT") {
        cfg.listen_address = Some(format!(":{port}"));
        // Distinct program namespace per instance too; veilid keys process/host
        // coexistence state on it (#99's two_node_circle does the same).
        cfg.namespace = format!("daemonseed-{port}");
    } else if let Some(port) = pick_free_port() {
        // #188: with no explicit port, DON'T leave listen_address None — that binds
        // veilid's FIXED default port, so a second co-resident client (a `--portable`
        // instance beside the desktop one) clashes on the bind and aborts startup with
        // the misleading "failed to create insecure keyring". Bind an OS-assigned free
        // port instead. A GUI client is relay-reached (not a public node), so a
        // non-default listen port does not affect reachability; an ephemeral port also
        // removes a static listen-port fingerprint. A concrete `:{port}` (not literal
        // `:0`) reuses the proven explicit-port path and avoids depending on veilid's
        // port-0 handling.
        cfg.listen_address = Some(format!(":{port}"));
        // #188: a distinct-per-PROFILE, stable-across-launches namespace so two
        // co-resident no-env instances (distinct profiles) get isolated veilid
        // protected stores in the shared dir. Keyed on the unlocked identity — NOT the
        // ephemeral port (a port-keyed namespace churned every launch, cold-
        // bootstrapping and stranding a store partition per run). Same profile → same
        // namespace (store reuse); different profiles → different namespaces (co-
        // resident isolation). `None` (ephemeral / no-profile reader) keeps the default.
        if let Some(k) = &ns_key {
            cfg.namespace = format!("daemonseed-{k}");
        }
    }

    daemonseed_veilid_net::vtrace!(
        "gui connect: namespace={} listen={:?} dir-env={:?}",
        cfg.namespace,
        cfg.listen_address,
        std::env::var("DAEMONSEED_VEILID_DIR").ok()
    );
    let listen = cfg.listen_address.clone();
    match VeilidNet::start(cfg).await {
        Ok((handle, rx)) => match handle.attach_and_wait(180).await {
            Ok(()) => {
                *net = Some(handle);
                *ev_rx = Some(rx);
                let _ = evt_tx.send(NetEvent::Connected);
            }
            Err(e) => fail(evt_tx, format!("veilid attach: {e}")),
        },
        // #188 guardrail: a listen-bind clash aborts veilid startup and surfaces as
        // the misleading keyring error. When a listen address was in play, name the
        // likely cause + the escape hatch instead of the raw internal string.
        Err(e) => fail(
            evt_tx,
            match &listen {
                Some(a) => format!(
                    "veilid start: {e} — listen {a} may already be in use by another \
                     instance; set DAEMONSEED_VEILID_PORT to a free port"
                ),
                None => format!("veilid start: {e}"),
            },
        ),
    }
}

fn fail(evt_tx: &UnboundedSender<NetEvent>, reason: String) {
    let _ = evt_tx.send(NetEvent::ConnectFailed { reason });
}

/// Subscribe the world-derivable lobby / public-room rendezvous (Phase 3/4):
/// derive the `PublicRoomKey` + the rendezvous-owner seed from the public room
/// name + suite, subscribe the rendezvous record, and remember it so discovery
/// items fold into the catalog. Best-effort: a derivation/subscribe failure is
/// traced and leaves the lobby unset (publish/fetch then surface a clean error).
async fn subscribe_lobby(
    shares: &mut ShareState,
    net: &Option<VeilidNetHandle>,
    evt_tx: &UnboundedSender<NetEvent>,
    my_handle: &str,
) {
    if shares.lobby.is_some() {
        return;
    }
    let Some(handle) = net.as_ref() else {
        return;
    };
    let room_key = match derive_room_key(DEFAULT_ROOM, &CNSA_2_0) {
        Ok(k) => k,
        Err(e) => {
            daemonseed_veilid_net::vtrace!("gui lobby: room-key derivation failed: {e}");
            return;
        }
    };
    let owner_seed = match derive_room_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0) {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            daemonseed_veilid_net::vtrace!("gui lobby: owner-seed derivation failed: {e}");
            return;
        }
    };
    // The SHARE-discovery sibling record (#153) — a distinct, world-derivable
    // rendezvous so public-share adverts never share the chat append-ring's record
    // (co-located, the two subkey schemes overlapped and silently overwrote each
    // other). Unlike presence (read-only, benign on failure), this is a WRITE record —
    // publish_share advertises on it — so a [0u8;32] fallback would put the advert on a
    // predictable, world-writable all-zeros-owned record. It is the same KDF primitive
    // as the chat owner seed above, so a failure means the whole lobby is broken: bail
    // (return) rather than write to a zeros record.
    let share_owner_seed = match derive_room_share_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0) {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            daemonseed_veilid_net::vtrace!("gui lobby: share owner-seed derivation failed: {e}");
            return;
        }
    };
    // The PRESENCE sibling record (P1) — a distinct, world-derivable rendezvous so
    // member beacons never share the chat append-ring. A derivation failure is
    // non-fatal: chat still works; the roster just stays empty.
    let presence_owner_seed = derive_room_presence_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0)
        .map(|s| *s.as_bytes())
        .unwrap_or([0u8; 32]);
    if let Err(e) = handle.subscribe_room(owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui lobby: subscribe failed: {e}");
        return;
    }
    // Subscribe the share record too so inbound share adverts fold into the catalog
    // (#153). Non-fatal on failure — discovery stays empty but chat is unaffected.
    if let Err(e) = handle.subscribe_room(share_owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui lobby: share-record subscribe failed: {e}");
    }
    // Subscribe the presence record too so inbound beacons fold into the roster.
    // Non-fatal on failure — the roster stays empty but chat is unaffected.
    if let Err(e) = handle.subscribe_room(presence_owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui lobby: presence subscribe failed: {e}");
    }
    daemonseed_veilid_net::vtrace!("gui lobby: subscribed (chat + shares + presence)");
    shares.lobby = Some(LobbyRendezvous {
        room_key,
        owner_seed,
        share_owner_seed,
        presence_owner_seed,
        // WB-1.9: TTL 600s + read-side fold; the crash/network-loss backstop only —
        // a graceful close disappears immediately via the leave tombstone.
        presence: PresenceTracker::for_room(DEFAULT_ROOM, PRESENCE_TTL),
    });
    // WB-1.1: publish one JOIN beacon (a session-boundary current-state write) so
    // the roster shows this member within the connect window, not a keepalive
    // interval later.
    if let (Some(signing), Some(lobby)) = (shares.signing.clone(), shares.lobby.as_ref()) {
        spawn_public_beacon(
            handle,
            &signing,
            &lobby.room_key,
            lobby.presence_owner_seed,
            my_handle,
            PresenceBoundary::Join,
        );
    }
    // The lobby rendezvous is live: tell the UI the public room is joined so its
    // Lobby chat box is enabled (relay-path parity — the relay emits RoomJoined on
    // its connect-time auto-join).
    let _ = evt_tx.send(NetEvent::RoomJoined);
}

/// Join a circle: derive the content key + the shared rendezvous-owner seed from
/// the phrase, subscribe the rendezvous record, and record local state.
async fn join_circle(
    circle_id: u64,
    phrase: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &mut Vec<VeilidCircle>,
    my_handle: &str,
    signing: Option<Arc<SignKeypair>>,
) {
    daemonseed_veilid_net::vtrace!("gui join_circle: requested id={circle_id}");
    let err = |reason: String| {
        daemonseed_veilid_net::vtrace!("gui join_circle: CircleError id={circle_id}: {reason}");
        let _ = evt_tx.send(NetEvent::CircleError { circle_id, reason });
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let cot_key = match derive_cot_key(phrase, &CNSA_2_0) {
        Ok(k) => k,
        Err(e) => return err(format!("circle-key derivation failed: {e}")),
    };
    let owner_seed = match derive_circle_veilid_owner_seed(phrase, &CNSA_2_0) {
        Ok(s) => *s.as_bytes(),
        Err(e) => return err(format!("rendezvous-owner derivation failed: {e}")),
    };
    // A circle already joined (same phrase → same owner_seed) re-emits CircleJoined
    // so the UI re-selects it, rather than re-subscribing.
    if let Some(existing) = circles.iter().find(|c| c.owner_seed == owner_seed) {
        daemonseed_veilid_net::vtrace!(
            "gui join_circle: already joined -> re-emit CircleJoined id={}",
            existing.circle_id
        );
        let _ = evt_tx.send(NetEvent::CircleJoined {
            circle_id: existing.circle_id,
            asset_addr: circle_fingerprint(&existing.cot_key),
        });
        return;
    }
    if let Err(e) = handle.subscribe_circle(owner_seed).await {
        return err(format!("subscribe failed: {e}"));
    }
    // #77: the circle PRESENCE sibling record (P1) — a distinct rendezvous so circle
    // beacons never share the chat append-ring. Non-fatal on failure (chat still
    // works; the roster just stays empty).
    let presence_owner_seed = derive_circle_presence_veilid_owner_seed(phrase, &CNSA_2_0)
        .map(|s| *s.as_bytes())
        .unwrap_or([0u8; 32]);
    if let Err(e) = handle.subscribe_room(presence_owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui join_circle: presence subscribe failed: {e}");
    }
    daemonseed_veilid_net::vtrace!("gui join_circle: subscribed ok -> CircleJoined id={circle_id}");
    let fingerprint = circle_fingerprint(&cot_key);
    let label = default_circle_label(&fingerprint);
    circles.push(VeilidCircle {
        circle_id,
        cot_key,
        owner_seed,
        presence_owner_seed,
        // WB-1.9: TTL 600s + read-side fold; scoped to this circle's label so
        // cross-room activity can never refresh it (WB-1.6).
        presence: PresenceTracker::for_room(label, PRESENCE_TTL),
    });
    // WB-1.1: one JOIN beacon on subscribe so the circle roster shows this member
    // within the connect window.
    if let (Some(signing), Some(circle)) = (signing, circles.last()) {
        spawn_circle_beacon(handle, &signing, circle, my_handle, PresenceBoundary::Join);
    }
    let _ = evt_tx.send(NetEvent::CircleJoined {
        circle_id,
        asset_addr: fingerprint,
    });
}

/// A stable per-circle fingerprint for the UI's `asset_addr` slot. The Veilid
/// rendezvous is a DHT record key, not an `AssetAddr`, so we synthesize a
/// deterministic `AssetAddr` from the content key (same value every join) purely
/// for the UI's existing dedup/fingerprint display.
fn circle_fingerprint(cot_key: &CircleKey) -> AssetAddr {
    asset_address(cot_key, b"veilid-circle").expect("asset_address is infallible for a fixed salt")
}

/// Seal a message under the circle key, publish it to the rendezvous record, and
/// local-echo it (the DHT sweep would also re-surface our own write after watch
/// latency; the inbound path emits it `mine:true` and `push_message` dedups it against
/// this echo by `sent_unix_ms`, so there is no double render — #143).
async fn send_circle(
    circle_id: u64,
    text: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &[VeilidCircle],
    my_handle: &str,
    signing: Option<Arc<SignKeypair>>,
) {
    let err = |reason: String| {
        let _ = evt_tx.send(NetEvent::CircleError { circle_id, reason });
    };
    daemonseed_veilid_net::vtrace!(
        "gui send_circle: requested id={circle_id} known={:?}",
        circles.iter().map(|c| c.circle_id).collect::<Vec<_>>()
    );
    let Some(circle) = circles.iter().find(|c| c.circle_id == circle_id) else {
        return err("join the circle before sending".to_owned());
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let Some(signing) = signing else {
        return err("no identity to sign the message".to_owned());
    };
    let sent_unix_ms = now_unix_ms();
    // Circle messages are now SIGNED (room↔circle convergence): the poster's
    // identity signs the RoomMessage so authorship is verifiable. Transmit the
    // CANONICAL `name#<12hex>` handle so a receiver's display_bound honors the name.
    let wire_handle = crate::net::canonical_wire_handle(my_handle, signing.public_key());
    let sealed = match seal_message(
        &circle.cot_key,
        signing.as_ref(),
        &wire_handle,
        text,
        sent_unix_ms,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("seal failed: {e}")),
    };
    // #101: optimistic local echo FIRST — the sender sees their own message
    // immediately, not after the DHT publish round-trip (seconds on Veilid). The
    // delayed DHT re-surface of this same write is emitted `mine:true`; its `who` is
    // `display_bound(...).format(Default)` = our display name, so the echo emits the
    // SAME display name (not the raw handle) and `push_message` dedups them (#143).
    // #155: compute the echo `who` via the SAME display_bound(wire_handle,
    // pubkey).format(Default) path as the DHT re-surface, so a nameless/floor
    // identity floors to `#<hex>` identically on both sides and push_message
    // dedups the own echo (was: `"#hex".split('#').next()` = "" → double-render).
    let display_name = Handle::display_bound(&wire_handle, signing.public_key().as_slice())
        .map(|b| b.format(DisplayMode::Default))
        .unwrap_or_else(|_| my_handle.to_owned());
    let _ = evt_tx.send(NetEvent::CircleMessage {
        circle_id,
        who: display_name,
        text: text.to_owned(),
        mine: true,
        sent_unix_ms,
    });
    // Publish off-task so a slow DHT write does not stall the actor's select loop
    // (which would also delay inbound delivery). A failure surfaces as a
    // CircleError; the already-echoed line stays (optimistic UI).
    let owner_seed = circle.owner_seed;
    let handle = handle.clone();
    let evt_tx_pub = evt_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = handle.publish_circle(owner_seed, sealed).await {
            let _ = evt_tx_pub.send(NetEvent::CircleError {
                circle_id,
                reason: format!("publish failed: {e}"),
            });
        }
    });
}

/// Seal a public-room (Lobby) message under the lobby `PublicRoomKey`, publish it
/// onto the lobby rendezvous, and optimistically local-echo it. The public-tier
/// counterpart of [`send_circle`]: the DHT sweep re-surfaces our own write after
/// watch latency, so `handle_inbound` emits own room messages `mine:true` and
/// `push_message` dedups them against this echo (#143). Mirrors the relay actor's
/// `handle_send_room`.
async fn send_room(
    text: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    my_handle: &str,
    shares: &ShareState,
) {
    let err = |reason: String| {
        let _ = evt_tx.send(NetEvent::Error { reason });
    };
    let Some(lobby) = shares.lobby.as_ref() else {
        return err("no public room joined".to_owned());
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let Some(signing) = shares.signing.clone() else {
        return err("no identity to sign the post".to_owned());
    };
    let sent_unix_ms = now_unix_ms();
    // Transmit the CANONICAL `name#<12hex>` handle so a receiver's display_bound
    // honors the name (a bare handle would floor to `#<hex>` for every peer).
    let wire_handle = crate::net::canonical_wire_handle(my_handle, signing.public_key());
    let sealed = match seal_room_message(
        &lobby.room_key,
        signing.as_ref(),
        DEFAULT_ROOM,
        &wire_handle,
        text,
        sent_unix_ms,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("public-room seal/sign failed: {e}")),
    };
    // Optimistic local echo FIRST — the sender sees their own message immediately,
    // not after the Veilid publish round-trip; the delayed DHT re-surface emits
    // `mine:true` with `who = display_bound(...).format(Default)` = our display name,
    // so the echo emits the SAME display name and `push_message` dedups them (#143).
    // #155: compute the echo `who` via the SAME display_bound(wire_handle,
    // pubkey).format(Default) path as the DHT re-surface, so a nameless/floor
    // identity floors to `#<hex>` identically on both sides and push_message
    // dedups the own echo (was: `"#hex".split('#').next()` = "" → double-render).
    let display_name = Handle::display_bound(&wire_handle, signing.public_key().as_slice())
        .map(|b| b.format(DisplayMode::Default))
        .unwrap_or_else(|_| my_handle.to_owned());
    let _ = evt_tx.send(NetEvent::Message {
        who: display_name,
        text: text.to_owned(),
        mine: true,
        sent_unix_ms,
    });
    // Publish off-task so a slow DHT write does not stall the actor's select loop.
    let owner_seed = lobby.owner_seed;
    let handle = handle.clone();
    let evt_tx_pub = evt_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = handle.publish_room(owner_seed, sealed).await {
            let _ = evt_tx_pub.send(NetEvent::Error {
                reason: format!("public-room publish failed: {e}"),
            });
        }
    });
}

// ── Operator announcements / MOTD (Phase 4 A-c) ─────────────────────────────

/// Subscribe the operator announce/MOTD record (A-c): derive the dev project-announce
/// owner seed (the DHT write-gate), subscribe the record so MOTD + announcement items
/// fold in as they arrive, and remember it. Best-effort — a derivation/subscribe
/// failure is traced and leaves `operator` unset (compose/refresh then surface a clean
/// not-connected error). Mirrors [`subscribe_lobby`].
async fn subscribe_operator_space(shares: &mut ShareState, net: &Option<VeilidNetHandle>) {
    if shares.operator.is_some() {
        return;
    }
    let Some(handle) = net.as_ref() else {
        return;
    };
    let announce_owner_seed = match dev_project_announce_veilid_owner_seed() {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            daemonseed_veilid_net::vtrace!("gui operator: owner-seed derivation failed: {e}");
            return;
        }
    };
    if let Err(e) = handle.subscribe_room(announce_owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui operator: subscribe failed: {e}");
        return;
    }
    daemonseed_veilid_net::vtrace!("gui operator: announce/MOTD record subscribed");
    shares.operator = Some(OperatorSpace {
        announce_owner_seed,
        motd: None,
        posts: BTreeMap::new(),
    });
}

/// Project the current verified operator content as a [`NetEvent::PublicSpaceSnapshot`]
/// (A-c). Everything in `OperatorSpace` was ALREADY verified before it was folded in
/// (`apply_operator_item` runs `verify_served_*` before insert; our own publishes are
/// self-authored), so the view is built **directly** from the stored artifacts —
/// `render_motd` / `post_render_fields` are the same inert decodes
/// `build_announcements_view` uses, minus the re-verification. Building the view
/// through `build_announcements_view` here would re-run the ML-DSA-87 signature check
/// on every stored post on every inbound item — O(N²) post-quantum work on the event
/// path during a backlog sweep (review finding). `can_compose` follows
/// [`operator_write_enabled`] — the interim write-gate (dev possession in debug;
/// operator-only in release).
fn public_space_snapshot_event(op: &OperatorSpace) -> NetEvent {
    let motd = op.motd.as_ref().map(render_motd);
    let posts = op
        .posts
        .values()
        .map(|p| {
            let (topic, body, sent_unix_ms) = post_render_fields(p);
            AnnouncementRow {
                topic,
                body,
                sent_unix_ms,
            }
        })
        .collect();
    NetEvent::PublicSpaceSnapshot {
        view: AnnouncementsView { motd, posts },
        // Interim write-gate (ISC-15 precursor): the composer shows in debug (dev
        // possession) and, in release, ONLY for an operator instance
        // (`DAEMONSEED_OPERATOR=1`). Non-operator release clients get a read-only pane.
        can_compose: operator_write_enabled(),
    }
}

/// The error surfaced when the operator record isn't available: honest about WHY —
/// truly not connected vs connected-but-the-subscribe-hasn't-landed (a transient
/// failure the lazy re-subscribe retries), rather than always claiming "not connected".
fn operator_unavailable_message(net: &Option<VeilidNetHandle>) -> String {
    if net.is_none() {
        "not connected to Veilid yet".to_owned()
    } else {
        "the announce/MOTD record isn't available yet — try again in a moment".to_owned()
    }
}

/// Re-render the current operator view (A-c) — the Veilid counterpart of the relay
/// `handle_refresh_public_space`, but local (verified content already lives in
/// `OperatorSpace`, no fetch). Lazily (re-)subscribes first so a transient subscribe
/// failure at Connect doesn't disable announcements for the whole session. Still
/// unavailable → a clean [`NetEvent::PublicSpaceError`], leaving the pane unchanged.
async fn refresh_public_space(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
) {
    subscribe_operator_space(shares, net).await;
    match shares.operator.as_mut() {
        Some(op) => {
            let _ = evt_tx.send(public_space_snapshot_event(op));
        }
        None => {
            let _ = evt_tx.send(NetEvent::PublicSpaceError {
                message: operator_unavailable_message(net),
            });
        }
    }
}

/// Interim MOTD/announce write-gate (ISC-15 precursor). Debug builds stay
/// world-writable (felt-test convenience). Release builds are **read-only for
/// everyone** except an operator instance launched with `DAEMONSEED_OPERATOR=1`, so a
/// tester on a release bundle can no longer overwrite the operator record. This is an
/// app-level capability gate, NOT the crypto write-gate: the dev owner seed is still
/// baked, so it does not yet satisfy ISC-15 (retire the dev seed, clients hold only
/// the pubkey, real operator key stays offline). It stops the casual write path today;
/// ISC-15 makes it cryptographic.
fn operator_write_enabled() -> bool {
    cfg!(debug_assertions) || operator_flag_enables(std::env::var_os("DAEMONSEED_OPERATOR"))
}

/// Whether a `DAEMONSEED_OPERATOR` value ENABLES operator writes. Presence alone is
/// not enough — a stray `DAEMONSEED_OPERATOR=0` (or empty) must keep the pane
/// read-only — so the value must be explicitly truthy. Pure over its input so the
/// release branch (which `cfg!(debug_assertions)` masks in tests) is unit-testable.
fn operator_flag_enables(var: Option<std::ffi::OsString>) -> bool {
    match var.as_deref().and_then(|v| v.to_str()) {
        Some(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        None => false,
    }
}

/// (#92 / A-c) Sign a MOTD with the F17 project-release key ([`sign_motd`] enforces the
/// ISC-S9 single-line-plaintext rule BEFORE signing), publish it to the operator
/// record's fixed `"motd"` slot, then fold it in locally + refresh. Guards mirror the
/// relay path (not connected → a clean [`NetEvent::PublicSpaceError`], nothing
/// published). The dev composer signs with F17 (A0), NOT the local stable identity —
/// so an empty whitelist authorizes it and non-signer distribution is unnecessary.
async fn set_motd(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    text: &str,
) {
    // Lazily (re-)subscribe first so a transient Connect-time subscribe failure doesn't
    // wedge the composer for the session (review finding); a no-op once subscribed.
    subscribe_operator_space(shares, net).await;
    let err = |message: String| {
        let _ = evt_tx.send(NetEvent::PublicSpaceError { message });
    };
    // Interim write-gate: read-only in release except an operator instance.
    if !operator_write_enabled() {
        return err("the MOTD is read-only in this build".to_owned());
    }
    let Some(owner_seed) = shares.operator.as_ref().map(|o| o.announce_owner_seed) else {
        return err(operator_unavailable_message(net));
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let kp = match dev_project_release_keypair() {
        Ok(k) => k,
        Err(e) => return err(format!("could not load the project-release key: {e}")),
    };
    let artifact = match sign_motd(&kp, text, now_unix_ms()) {
        Ok(a) => a,
        // Includes the ISC-S9 plaintext rejection (single line, no markup/links) —
        // surfaced, not silently dropped.
        Err(e) => return err(format!("could not set MOTD: {e}")),
    };
    let value = encode_operator_item(OPERATOR_ITEM_MOTD, &artifact.encode_to_vec());
    if let Err(e) = handle
        .publish_current_state(owner_seed, "motd", value)
        .await
    {
        return err(format!("could not publish MOTD: {e}"));
    }
    // Fold our own MOTD in immediately (the record sweep also re-surfaces it).
    if let Some(op) = shares.operator.as_mut() {
        op.motd = Some(artifact);
    }
    if let Some(op) = shares.operator.as_ref() {
        let _ = evt_tx.send(public_space_snapshot_event(op));
    }
}

/// (#92 / A-c) Sign an announcement post with the F17 project-release key, publish it
/// to the operator record at its content-address slot, then fold it in locally +
/// refresh. Same guards + F17 signing rationale as [`set_motd`].
async fn upload_announcement(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    topic: &str,
    body: &str,
) {
    subscribe_operator_space(shares, net).await;
    let err = |message: String| {
        let _ = evt_tx.send(NetEvent::PublicSpaceError { message });
    };
    // Interim write-gate: read-only in release except an operator instance.
    if !operator_write_enabled() {
        return err("announcements are read-only in this build".to_owned());
    }
    let Some(owner_seed) = shares.operator.as_ref().map(|o| o.announce_owner_seed) else {
        return err(operator_unavailable_message(net));
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let kp = match dev_project_release_keypair() {
        Ok(k) => k,
        Err(e) => return err(format!("could not load the project-release key: {e}")),
    };
    let artifact = match sign_post(&kp, topic, body, now_unix_ms()) {
        Ok(a) => a,
        Err(e) => return err(format!("could not sign announcement: {e}")),
    };
    let addr = match content_address(&artifact.signed_payload) {
        Ok(a) => a,
        Err(e) => return err(format!("could not derive the announcement address: {e}")),
    };
    let content_address_bytes = addr.as_bytes().to_vec();
    let slot = hex::encode(&content_address_bytes);
    let post = wire::Post {
        artifact: Some(artifact),
        content_address: content_address_bytes,
    };
    let value = encode_operator_item(OPERATOR_ITEM_ANNOUNCEMENT, &post.encode_to_vec());
    if let Err(e) = handle.publish_current_state(owner_seed, &slot, value).await {
        return err(format!("could not publish announcement: {e}"));
    }
    if let Some(op) = shares.operator.as_mut() {
        op.posts.insert(slot, post);
    }
    if let Some(op) = shares.operator.as_ref() {
        let _ = evt_tx.send(public_space_snapshot_event(op));
    }
}

/// (owner seed, `[(slot_id, encoded-value)]`) — one #141 keep-alive re-publish batch.
type OperatorKeepaliveBatch = ([u8; 32], Vec<(String, Vec<u8>)>);

/// #141: collect the operator record's re-publishable items as `(slot_id,
/// encoded-value)` pairs for a keep-alive, with the owner seed to write them. `None`
/// when there is no operator record or nothing to re-publish. Pure (no I/O) so the
/// caller can spawn the DHT writes off the actor loop.
///
/// ONLY the announcements are kept alive, NOT the MOTD. Announcements live in
/// content-addressed slots (`hex(content_address)`), so re-publishing their exact
/// F17-signed bytes to the same key is idempotent under last-writer-wins — it can never
/// revert anything a peer already holds. The MOTD lives in the single MUTABLE `"motd"`
/// slot and the fold ([`apply_operator_item`]) has no newer-wins, so re-publishing a
/// stale MOTD would let peers adopt + rebroadcast it and revert a newer/cleared MOTD
/// network-wide. MOTD keep-alive waits for the #136 monotonic version that makes the
/// mutable slot safe to refresh.
fn collect_operator_keepalive_items(shares: &ShareState) -> Option<OperatorKeepaliveBatch> {
    let op = shares.operator.as_ref()?;
    let mut items: Vec<(String, Vec<u8>)> = Vec::new();
    // Announcements only — content-addressed slots are idempotent under re-publish. The
    // mutable MOTD slot is deliberately excluded (see the fn doc: reverts without #136).
    for (slot, post) in op.posts.iter() {
        items.push((
            slot.clone(),
            encode_operator_item(OPERATOR_ITEM_ANNOUNCEMENT, &post.encode_to_vec()),
        ));
    }
    if items.is_empty() {
        None
    } else {
        Some((op.announce_owner_seed, items))
    }
}

/// Try inbound bytes as an operator announce-record item (A-c). Returns `true` only
/// when the bytes were a VERIFIED operator item (folded into `OperatorSpace` + a fresh
/// [`NetEvent::PublicSpaceSnapshot`] pushed) — so the caller stops interpreting them.
/// Returns `false` when they are not an operator item, or fail to decode/verify
/// (dropped; the caller logs them as unrecognized).
///
/// A0 verification: an empty [`Whitelist`] authorizes the F17 project-release key the
/// item is signed with, so no signer-whitelist distribution is needed. A MOTD uses
/// [`verify_served_motd`]; an announcement uses [`verify_served_post`] (signature AND
/// content-address). This runs AFTER the circle / lobby-chat / presence / discovery
/// attempts, so a legitimate blob of those kinds has already been consumed — the tag +
/// prost-decode + verify is a tight filter a foreign/unknown blob fails.
fn apply_operator_item(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    bytes: &[u8],
) -> bool {
    // Only fold when the operator record is subscribed (else these bytes aren't ours).
    if shares.operator.is_none() {
        return false;
    }
    let Some((kind, payload)) = decode_operator_item(bytes) else {
        return false;
    };
    // A0: an empty whitelist authorizes the F17 project-release signer.
    let whitelist = Whitelist::default();
    match kind {
        OPERATOR_ITEM_MOTD => {
            let Ok(artifact) = wire::SignedArtifact::decode(payload) else {
                return false;
            };
            if verify_served_motd(&artifact, &whitelist).is_err() {
                return false; // not F17-authorized / bad signature → dropped
            }
            if let Some(op) = shares.operator.as_mut() {
                op.motd = Some(artifact);
            }
        }
        OPERATOR_ITEM_ANNOUNCEMENT => {
            let Ok(post) = wire::Post::decode(payload) else {
                return false;
            };
            if verify_served_post(&post, &whitelist).is_err() {
                return false; // bad signature / content-address mismatch → dropped
            }
            let slot = hex::encode(&post.content_address);
            if let Some(op) = shares.operator.as_mut() {
                op.posts.insert(slot, post);
            }
        }
        _ => return false, // unknown tag → not an operator item
    }
    if let Some(op) = shares.operator.as_ref() {
        let _ = evt_tx.send(public_space_snapshot_event(op));
    }
    true
}

// ── Public shares (Phase 3 Slice 2b) ────────────────────────────────────────

/// Publish a local directory as a public share: index it (RAM path), mint a
/// client-side `share_id`, seal a self-signed `ShareAnnouncement` under the lobby
/// `PublicRoomKey`, register the content to serve owner-on-demand, and announce it
/// onto the lobby rendezvous with a SIGNED route advert (anti-swap, D-3.5).
/// Mirrors the relay actor's `handle_publish_share` (minus the redb chunk-addr
/// cache — the RAM index is the no-cache path).
/// Insert or replace an own-share entry, keyed by its deterministic `share_id`
/// (#156, #195). A mid-session re-index (manual Refresh) republishes the same root
/// under the same id, so this upserts rather than appends — `own` never carries a
/// duplicate entry for one root.
fn upsert_own_share(own: &mut Vec<OwnShare>, entry: OwnShare) {
    own.retain(|s| s.share_id != entry.share_id);
    own.push(entry);
}

async fn publish_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    root: PathBuf,
    name: String,
    sharer_handle: String,
    // #117: true on the connect-time auto-republish (the M16 restore path) so the
    // live emit drives the always-visible "Restored N shares from last session"
    // banner — a sharer sees their shares come back without opening Manage shares.
    restored: bool,
) {
    let err = |message: String| {
        let _ = evt_tx.send(NetEvent::PublishError { message });
    };
    // Fail-safe: never recursively hash the home tree / a system dir.
    if is_unsafe_publish_root(&root) {
        return err(format!(
            "refusing to publish {} — pick a specific folder, not your home or a system directory",
            root.display()
        ));
    }
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let Some(signing) = shares.signing.clone() else {
        return err("no identity to sign the announcement".to_owned());
    };
    let Some(share_root_ikm) = shares.share_root_ikm.clone() else {
        return err("no identity to derive the share id".to_owned());
    };
    // Copy the lobby's address material out so no borrow of `shares` is held
    // across an `.await` (and so the later `shares.own.push` is unobstructed). The
    // advert publishes on the SHARE record (#153), disjoint from the chat record.
    let (room_key_bytes, owner_seed) = match shares.lobby.as_ref() {
        Some(l) => (*l.room_key.as_bytes(), l.share_owner_seed),
        None => return err("lobby not subscribed yet".to_owned()),
    };

    let root_str = root.to_string_lossy().into_owned();
    // Index off the actor loop (the in-RAM `ShareContent`; no redb cache on the
    // Veilid path). The hashing stays off the async select loop.
    let content = match tokio::task::spawn_blocking(move || ShareContent::index_dir(&root)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return err(format!("could not index {root_str}: {e}")),
        Err(_) => return err("share-index task failed".to_owned()),
    };
    let file_count = content.file_count();
    let content = Arc::new(content);

    // Receiver-verifiable deterministic id (#156, not a fresh mint): share_id =
    // derive_share_id_v2(own_pubkey, root_commitment), where the commitment hides
    // the root under a secret per-share nonce. The same (identity, root) always
    // yields the same id, so a republish on reconnect re-asserts the SAME id and a
    // fetcher folds it onto the existing catalog entry — no duplicate / dead-route
    // second copy (#112). A v2 receiver recomputes and rejects any non-derivable id.
    let nonce = derive_share_root_nonce(share_root_ikm.as_bytes(), &root_str);
    let root_commitment = derive_root_commitment(&root_str, &nonce);
    let share_id = derive_share_id_v2(signing.public_key(), &root_commitment);
    let rating = String::new();
    let room_key = PublicRoomKey::from_bytes(room_key_bytes);
    let fields = AnnouncementFields {
        room: DEFAULT_ROOM,
        sender_handle: &sharer_handle,
        share_id: &share_id,
        root_commitment: &root_commitment,
        name: &name,
        rating: &rating,
        withdraw: false,
        sent_unix_ms: now_unix_ms(),
    };
    let sealed = match seal_public_announcement(&room_key, signing.as_ref(), &fields) {
        Ok(s) => s,
        Err(e) => return err(format!("could not seal share announcement: {e}")),
    };

    // #117: show the share as "republishing…" for the slow serve+advert window below
    // (route allocation + DHT write over Veilid). On a reconnect this window is what
    // made a sharer think their share had died — the in-flight tag says it is being
    // re-established, not gone. Cleared to live by the final `PublishStarted` once the
    // advert lands; the entry is removed (`PublishStopped`) if the publish fails.
    let _ = evt_tx.send(NetEvent::PublishStarted {
        share_id: share_id.clone(),
        name: name.clone(),
        file_count,
        root: root_str.clone(),
        restored,
        republishing: true,
    });

    // Register the content to serve owner-on-demand (chunks sealed under the room
    // key), then announce it with a signed route advert. veilid-net allocates the
    // private route + signs via the capability internally.
    if let Err(e) = handle
        .serve_share(share_id.clone(), content, room_key_bytes)
        .await
    {
        let _ = evt_tx.send(NetEvent::PublishStopped {
            share_id: share_id.clone(),
        });
        return err(format!("could not register share to serve: {e}"));
    }
    let signer = IdentityRouteAdvertSigner::from_arc(signing).into_arc();
    if let Err(e) = handle
        .publish_share(
            owner_seed,
            share_id.clone(),
            sealed,
            signer,
            /* persist */ true,
        )
        .await
    {
        let _ = evt_tx.send(NetEvent::PublishStopped {
            share_id: share_id.clone(),
        });
        return err(format!("could not announce share: {e}"));
    }

    // #195: a mid-session re-index (manual Refresh) republishes under the SAME
    // deterministic share_id, so upsert (replace) any existing own-entry rather
    // than appending a duplicate. At connect-time restore `own` is empty, so this
    // is a plain push there; the upsert is the mid-session idempotency guard.
    upsert_own_share(
        &mut shares.own,
        OwnShare {
            share_id: share_id.clone(),
            root_commitment: root_commitment.to_vec(),
            name: name.clone(),
            rating,
            sharer_handle,
        },
    );
    // Reflect the new own-share immediately (the lobby never echoes it back).
    let _ = evt_tx.send(NetEvent::SharesSnapshot {
        shares: shares.listings(),
    });
    // The advert is live: flip the in-flight tag off (republishing: false).
    let _ = evt_tx.send(NetEvent::PublishStarted {
        share_id,
        name,
        file_count,
        root: root_str,
        restored,
        republishing: false,
    });
}

/// Unpublish a share published this session: post a withdraw `ShareAnnouncement`
/// onto the lobby (wrapped in a `DiscoveryEnvelope` via `publish_share` so
/// listeners decode + open it and drop it from their catalog) and clear our own
/// record. Mirrors the relay actor's `handle_unpublish_share`. The withdraw reuses
/// the original metadata so its provenance input matches the announce's.
async fn unpublish_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    share_id: &str,
) {
    let own = shares.own.iter().find(|s| s.share_id == share_id).cloned();
    shares.own.retain(|s| s.share_id != share_id);
    // Always clear it locally + tell the UI, even if we cannot post a withdraw.
    let _ = evt_tx.send(NetEvent::SharesSnapshot {
        shares: shares.listings(),
    });
    let _ = evt_tx.send(NetEvent::PublishStopped {
        share_id: share_id.to_owned(),
    });

    // Teeth of unpublish: stop SERVING the bytes. Fires whenever connected,
    // independent of whether the withdraw below can be signed — the withdraw only
    // removes the share from listeners' discovery catalogs, while this de-registers
    // it from the serve registry so the owner no longer answers fetch app_calls
    // (a holder of a stale route gets a not-found, never bytes).
    if let Some(handle) = net.as_ref() {
        let _ = handle.stop_serve(share_id.to_owned()).await;
    }

    // Best-effort withdraw so listeners drop it (discovery self-heals via TTL even
    // if this fails).
    let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone()) else {
        return;
    };
    let (room_key_bytes, owner_seed) = match shares.lobby.as_ref() {
        Some(l) => (*l.room_key.as_bytes(), l.share_owner_seed),
        None => return,
    };
    let own = own.unwrap_or(OwnShare {
        share_id: share_id.to_owned(),
        // #156: without the recorded commitment a withdraw cannot validate at
        // receivers; this only happens if the own-record was already lost, and
        // discovery self-heals via the prune TTL regardless.
        root_commitment: Vec::new(),
        name: String::new(),
        rating: String::new(),
        sharer_handle: String::new(),
    });
    let room_key = PublicRoomKey::from_bytes(room_key_bytes);
    let fields = AnnouncementFields {
        room: DEFAULT_ROOM,
        sender_handle: &own.sharer_handle,
        share_id: &own.share_id,
        root_commitment: &own.root_commitment,
        name: &own.name,
        rating: &own.rating,
        withdraw: true,
        sent_unix_ms: now_unix_ms(),
    };
    let Ok(sealed) = seal_public_announcement(&room_key, signing.as_ref(), &fields) else {
        return;
    };
    let signer = IdentityRouteAdvertSigner::from_arc(signing).into_arc();
    let _ = handle
        .publish_share(
            owner_seed,
            share_id.to_owned(),
            sealed,
            signer,
            /* persist */ false,
        )
        .await;
}

/// Map a fetch [`VeilidNetError`] to a user-facing message, distinguishing the
/// sharer's authoritative withdraw ([`VeilidNetError::NotServed`] — the owner
/// answered "no longer served") from a transport failure (offline / slow / dead
/// route). The client-side helper notification that resolves the Demonsaw
/// ambiguity: a deliberate unpublish reads plainly instead of an indefinite timeout.
fn fetch_error_message(context: &str, e: VeilidNetError) -> String {
    match e {
        VeilidNetError::NotServed => "sharer withdrew this share".to_owned(),
        // Log the FULL error to the trace — the GUI status line truncates it to an
        // ellipsis, hiding the diagnostic for a transport/reassembly/verify failure.
        other => {
            daemonseed_veilid_net::vtrace!("fetch error — {context}: {other}");
            format!("{context}: {other}")
        }
    }
}

/// (#180 §RS-2, CRSH-ISC-7/8/19) The generation-tagged outcome of a share fetch that ran
/// in a spawned task **off** the net-actor loop. Folded back on-loop by
/// [`fold_fetch_outcome`], which is where the `&mut ShareState` mutations (mark/clear
/// Unresolved) and the UI emissions happen — never inside the spawned task. Every variant
/// carries the `generation` captured at spawn time so a stale outcome (the share was
/// withdrawn / re-added while the fetch was in flight) no-ops on fold (CRSH-ISC-19). The
/// imported `RouteId` rides the `route`-bearing variants back on-loop so step 6's release
/// map can attach (§RS-3) — the spawned task never releases a route itself.
enum FetchOutcome {
    /// Import + manifest fetch both succeeded: render the preview and clear any Unresolved
    /// mark. `route` is the imported private route (release-tracked on-loop).
    Manifest {
        share_id: String,
        name: String,
        generation: u64,
        route: RouteId,
        entries: Vec<ShareManifestEntry>,
    },
    /// `import_route` failed — the sharer's route is dead, NOT a malformed blob (the advert
    /// was binding + signature verified at discovery). No route was imported. Mark the share
    /// Unresolved (local only) and park a one-shot retry; never prune (§RS-1.4/§RS-1.5).
    ImportFailed {
        share_id: String,
        name: String,
        generation: u64,
        message: String,
    },
    /// The route imported but the manifest fetch failed (dead route / withdraw / transport).
    /// Same local-only reactive handling as [`Self::ImportFailed`]; `route` was imported and
    /// rides back on-loop for release tracking.
    ManifestFailed {
        share_id: String,
        name: String,
        generation: u64,
        route: RouteId,
        message: String,
    },
}

/// (#180 §RS-2, CRSH-ISC-8) The network half of a share fetch — import the route, fetch +
/// reassemble + open the manifest — run **inside a spawned task**, never on the actor loop.
/// Returns a generation-tagged [`FetchOutcome`]; all state mutation and UI emission is
/// deferred to [`fold_fetch_outcome`] on-loop. No bytes are fetched (preview only).
async fn run_fetch(
    handle: &VeilidNetHandle,
    share_id: String,
    name: String,
    generation: u64,
    route_blob: Vec<u8>,
    room_key_bytes: [u8; 32],
) -> FetchOutcome {
    let route = match handle.import_route(route_blob).await {
        Ok(r) => r,
        Err(e) => {
            return FetchOutcome::ImportFailed {
                share_id,
                name,
                generation,
                message: format!(
                    "could not import the sharer's route: {e} — re-resolving; the share stays listed"
                ),
            };
        }
    };
    // Keep a copy of the imported route for the outcome — `fetch_manifest` consumes it and
    // the on-loop release map (step 6) needs the id (RouteId is Clone, not Copy).
    let route_for_outcome = route.clone();
    match handle
        .fetch_manifest(route, &share_id, room_key_bytes)
        .await
    {
        Ok(manifest) => {
            let entries = manifest
                .iter()
                .map(|e| ShareManifestEntry {
                    rel_path: e.rel_path.clone(),
                    size: e.size,
                })
                .collect();
            FetchOutcome::Manifest {
                share_id,
                name,
                generation,
                route: route_for_outcome,
                entries,
            }
        }
        Err(e) => FetchOutcome::ManifestFailed {
            share_id,
            name,
            generation,
            route: route_for_outcome,
            message: fetch_error_message("could not fetch the share manifest — re-resolving", e),
        },
    }
}

/// (#180 §RS-2, CRSH-ISC-7/8) Dispatch an A1 fetch-preview **off** the net-actor loop: copy
/// the route blob + room key + current discovered-generation out of share state, spawn
/// [`run_fetch`] as a task, and return immediately so the actor loop returns to its
/// `select!` without ever awaiting the fetch (the #180 item-3 chat-starvation fix). The
/// outcome returns via `outcome_tx` and is folded on-loop by [`fold_fetch_outcome`].
/// Immediate local failures (not connected, lobby not subscribed, share not discovered)
/// still fail inline — they touch no network and need no spawn.
fn spawn_fetch_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    outcome_tx: &UnboundedSender<FetchOutcome>,
    share_id: &str,
    name: &str,
) {
    let fail = |message: String| {
        let _ = evt_tx.send(NetEvent::FetchError { message });
    };
    let Some(handle) = net.as_ref() else {
        return fail("not connected to Veilid yet".to_owned());
    };
    let Some(lobby) = shares.lobby.as_ref() else {
        return fail("lobby not subscribed yet".to_owned());
    };
    let Some(disc) = shares.discovered.get(share_id) else {
        return fail("share not discovered yet — refresh the list".to_owned());
    };
    let route_blob = disc.route_blob.clone();
    let generation = disc.generation;
    let room_key_bytes = *lobby.room_key.as_bytes();
    let handle = handle.clone();
    let share_id = share_id.to_owned();
    let name = name.to_owned();
    // (#180 §RS-3, CRSH-ISC-10) This fetch is in flight over the imported route until its
    // outcome folds — so a concurrent advert-replacement defers the old route's release
    // until this fetch finishes (the guard's in-use guard).
    shares.route_guard.note_fetch_started(share_id.clone());
    spawn_fetch_task(outcome_tx.clone(), async move {
        run_fetch(
            &handle,
            share_id,
            name,
            generation,
            route_blob,
            room_key_bytes,
        )
        .await
    });
}

/// (#180 §RS-2, CRSH-ISC-7/8) The spawn seam shared by [`spawn_fetch_share`] and the actor
/// tests: run `fetch` as a detached task and report its [`FetchOutcome`] to `outcome_tx`,
/// returning immediately. This is the single point guaranteeing no fetch is ever awaited on
/// the caller (the actor loop) — testable without a live veilid attach (§RS-1.3).
fn spawn_fetch_task<F>(outcome_tx: UnboundedSender<FetchOutcome>, fetch: F)
where
    F: std::future::Future<Output = FetchOutcome> + Send + 'static,
{
    tokio::spawn(async move {
        // A closed channel just means the actor shut down mid-fetch — the outcome is moot.
        let _ = outcome_tx.send(fetch.await);
    });
}

/// (#180 §RS-2, CRSH-ISC-8/19/23, §RS-3) Fold a spawned fetch's outcome back on the actor
/// loop. A **stale-generation** outcome drops its manifest/route (a dead manifest never
/// renders and a route fetched over a superseded advert never drives UI), but the two
/// staleness causes diverge on the parked retry (CRSH-ISC-23, #180 F2): a WITHDRAWN entry
/// (gone from `discovered`) drops outright, while a fresh advert advancing the generation
/// mid-fetch re-parks a one-shot retry at the outcome's generation so a cursor tick fires it
/// against the newer advert — the share is never stranded Unresolved-without-a-retry. On a
/// live outcome:
/// success clears the Unresolved mark + emits `FetchManifest`; either failure marks the
/// share Unresolved (local only, never a prune). Every folded outcome closes out the fetch
/// on the in-use guard (`note_fetch_finished`, CRSH-ISC-10): the imported route is recorded
/// so a later advert-replacement can release it, and any route a prior advert-replacement
/// left pending is released once this share goes idle (buffered into
/// `pending_route_releases` for the loop's off-loop release).
fn fold_fetch_outcome(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    outcome: FetchOutcome,
) {
    let (share_id, generation, name) = match &outcome {
        FetchOutcome::Manifest {
            share_id,
            generation,
            name,
            ..
        }
        | FetchOutcome::ImportFailed {
            share_id,
            generation,
            name,
            ..
        }
        | FetchOutcome::ManifestFailed {
            share_id,
            generation,
            name,
            ..
        } => (share_id.clone(), *generation, name.clone()),
    };
    // CRSH-ISC-19/23 (#180 F2): the outcome is valid only against the exact discovered-entry
    // generation it was fetched over. A withdraw (entry gone) or a fresh advert fold
    // (generation advanced) mid-fetch makes the outcome stale → drop the outcome + any
    // imported route (the LRU/expiry is the backstop). The fetch still closes on the guard so
    // its in-flight count is released (else a deferred route would never flush).
    if shares.discovered.get(&share_id).map(|d| d.generation) != Some(generation) {
        let released = shares.route_guard.note_fetch_finished(&share_id, None);
        shares.pending_route_releases.extend(released);
        // CRSH-ISC-23 (#180 F2): staleness has two causes and they diverge. If the entry is
        // GONE (withdrawn) the drop is correct — the share is removed (CRSH-ISC-19). But if
        // the entry is STILL discovered and only its generation advanced (a FRESH ADVERT
        // folded mid-fetch), the share is genuinely still Unresolved: re-park a one-shot retry
        // at the OUTCOME's `generation` (strictly below the current generation) so
        // `parked_retry_action` Fires on the next cursor tick against the newer advert's route
        // (current > parked). Without this the share strands Unresolved with an empty
        // `parked_retries` and never re-resolves — the F2 defect.
        // (#180 R4, CRSH-ISC-23) Re-park ONLY a share that is still Unresolved. A share a
        // newer fetch already RESOLVED (unresolved == false) must be left resolved — a late
        // stale outcome from an earlier-generation overlapping fetch must not revert it (the R4
        // regression). A withdrawn share (absent) drops outright (CRSH-ISC-19). Do NOT set
        // `unresolved = true` here: it is already true in the re-park case, and setting it is
        // exactly what reverted an already-resolved share.
        let re_parked = matches!(
            shares.discovered.get(&share_id),
            Some(disc) if disc.unresolved
        );
        if re_parked {
            shares.parked_retries.insert(
                share_id.clone(),
                ParkedBrowseRetry::park(name, generation, Instant::now()),
            );
            let _ = evt_tx.send(NetEvent::SharesSnapshot {
                shares: shares.listings(),
            });
            daemonseed_veilid_net::vtrace!(
                "gui fetch outcome for {share_id} stale via fresh advert (gen {generation}) \
                 — re-parked one-shot retry (still Unresolved)"
            );
        } else {
            daemonseed_veilid_net::vtrace!(
                "gui fetch outcome for {share_id} stale (gen {generation}) — dropped \
                 (share already resolved by a newer fetch, or withdrawn)"
            );
        }
        return;
    }
    match outcome {
        FetchOutcome::Manifest {
            share_id,
            name,
            route,
            entries,
            ..
        } => {
            // Record the imported route on the guard (§RS-3); flush any route a prior
            // advert-replacement deferred now that this fetch is done.
            let released = shares
                .route_guard
                .note_fetch_finished(&share_id, Some(route));
            shares.pending_route_releases.extend(released);
            // A successful re-resolve: clear any Unresolved mark + drop a parked retry.
            clear_share_unresolved(shares, evt_tx, &share_id);
            let _ = evt_tx.send(NetEvent::FetchManifest {
                share_id,
                name,
                entries,
            });
        }
        FetchOutcome::ManifestFailed {
            share_id,
            name,
            route,
            message,
            ..
        } => {
            // The route imported but the manifest fetch failed — record it on the guard,
            // then the local-only reactive path (§RS-1.4/§RS-1.5).
            let released = shares
                .route_guard
                .note_fetch_finished(&share_id, Some(route));
            shares.pending_route_releases.extend(released);
            mark_share_unresolved(shares, evt_tx, &share_id, &name);
            let _ = evt_tx.send(NetEvent::FetchError { message });
        }
        FetchOutcome::ImportFailed {
            share_id,
            name,
            message,
            ..
        } => {
            // No route imported — close the fetch on the guard, mark Unresolved + park a
            // one-shot retry, never prune.
            let released = shares.route_guard.note_fetch_finished(&share_id, None);
            shares.pending_route_releases.extend(released);
            mark_share_unresolved(shares, evt_tx, &share_id, &name);
            let _ = evt_tx.send(NetEvent::FetchError { message });
        }
    }
}

/// (#180 §RS-1.4, CRSH-ISC-4/5) Mark a share's route **Unresolved** after a fetch failure
/// and park a one-shot, generation-tagged browse retry — **local computation only, ZERO
/// network** (§RS-0). The share stays in `discovered` and the catalog (never pruned on a
/// fetch failure); the parked retry fires at the next cursor tick after a fresh advert
/// folds (CRSH-ISC-6), or clears on window expiry / withdraw. Takes no network handle by
/// construction, so it cannot issue a DHT op. No-op if the route is already gone.
fn mark_share_unresolved(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    share_id: &str,
    name: &str,
) {
    let generation = match shares.discovered.get_mut(share_id) {
        Some(disc) => {
            disc.unresolved = true;
            disc.generation
        }
        // No route to re-resolve (already withdrawn/gone): nothing to mark or park.
        None => return,
    };
    shares.parked_retries.insert(
        share_id.to_owned(),
        ParkedBrowseRetry::park(name.to_owned(), generation, Instant::now()),
    );
    daemonseed_veilid_net::vtrace!(
        "gui reactive: marked {share_id} Unresolved + parked one-shot retry (no network)"
    );
    let _ = evt_tx.send(NetEvent::SharesSnapshot {
        shares: shares.listings(),
    });
}

/// (#180 §RS-1.4) A successful fetch resolves the share: clear the Unresolved mark and drop
/// any parked retry, snapshotting only if something changed.
fn clear_share_unresolved(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    share_id: &str,
) {
    let mut changed = shares.parked_retries.remove(share_id).is_some();
    if let Some(disc) = shares.discovered.get_mut(share_id)
        && disc.unresolved
    {
        disc.unresolved = false;
        changed = true;
    }
    if changed {
        let _ = evt_tx.send(NetEvent::SharesSnapshot {
            shares: shares.listings(),
        });
    }
}

/// (#180 §RS-1.4/§RS-2, CRSH-ISC-6/15) House-keep the parked browse retries **at the consumer's
/// own cursor tick** — never at the advert-fold event. Under the reframe (#180, 2026-07-17) the
/// actual mark-fetchable happens at the route-rotation fold (`apply_discovery`, a local
/// no-network op), so this tick no longer re-fetches or clears `Unresolved`: it only expires
/// stale parks. A park whose share saw a fresh advert fold since the park (its discovered
/// generation advanced) but no route rotation (a content-only re-advert — `apply_discovery`
/// left it parked) is dropped, since the route is not refreshed and a real rotation will mark it
/// fetchable at the fold; an expired-window retry surfaces failure WITHOUT pruning (the share
/// stays listed and still recovers on a later rotation); a withdrawn share's retry drops
/// silently. Synchronous, no network op.
fn process_parked_browse_retries(shares: &mut ShareState, evt_tx: &UnboundedSender<NetEvent>) {
    if shares.parked_retries.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut fire: Vec<String> = Vec::new();
    let mut expire: Vec<String> = Vec::new();
    let mut drop_ids: Vec<String> = Vec::new();
    for (share_id, parked) in &shares.parked_retries {
        let current = shares.discovered.get(share_id).map(|d| d.generation);
        match parked_retry_action(parked, current, now) {
            ParkedRetryAction::Fire => fire.push(share_id.clone()),
            ParkedRetryAction::Expire => expire.push(share_id.clone()),
            ParkedRetryAction::Drop => drop_ids.push(share_id.clone()),
            ParkedRetryAction::Wait => {}
        }
    }
    for id in &drop_ids {
        shares.parked_retries.remove(id);
    }
    for id in &expire {
        // Name the share in the give-up toast so the user knows which browse to re-initiate;
        // the share stays listed and still recovers automatically on a later route rotation.
        let name = shares
            .parked_retries
            .remove(id)
            .map(|p| p.name)
            .unwrap_or_default();
        let _ = evt_tx.send(NetEvent::FetchError {
            message: format!(
                "re-resolve window elapsed for '{name}' — the share stays listed; \
                 browse it again to retry"
            ),
        });
    }
    for id in &fire {
        // Reframe (#180, 2026-07-17): the mark-fetchable lives at the route-rotation fold
        // (`apply_discovery`), which also drops the park. A park reaching Fire here saw a
        // generation bump WITHOUT a route rotation (a content-only re-advert), so the route is
        // NOT refreshed — drop the stale park without clearing; a real rotation marks it
        // fetchable at the fold.
        shares.parked_retries.remove(id);
    }
}

/// Fetch every chunk in `addrs` with bounded concurrency `cap`, returning the chunk
/// bytes in the SAME order as `addrs` so a file reassembles byte-for-byte (#113).
/// `buffered` runs up to `cap` `fetch` futures at once but yields them in input
/// order, so reassembly is correct while the link stays busy; `on_chunk` fires per
/// chunk as it arrives (download progress). The first error short-circuits — the
/// remaining in-flight fetches are cancelled when the stream drops. `fetch` is a
/// closure so the real path closes over `handle.fetch_chunk` while a test injects a
/// concurrency-counting fake (no network).
async fn fetch_chunks_ordered<F, Fut, P>(
    addrs: &[ChunkAddr],
    cap: usize,
    fetch: F,
    mut on_chunk: P,
) -> Result<Vec<Vec<u8>>, VeilidNetError>
where
    F: Fn(ChunkAddr) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, VeilidNetError>>,
    P: FnMut(&[u8]),
{
    use futures_util::stream::{self, StreamExt};
    let mut stream = stream::iter(addrs.iter().copied().map(fetch)).buffered(cap.max(1));
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(addrs.len());
    while let Some(res) = stream.next().await {
        let data = res?;
        on_chunk(&data);
        out.push(data);
    }
    Ok(out)
}

/// A2 download: import the route, fetch the selected files' chunks (each
/// SHA-384-verified inside `fetch_chunk`, ISC-S28), and write them under
/// `fetched_root`. On any failure the partial files are deleted (ISC-A-C31).
/// (#197, CRSH-ISC-29) The terminal outcome of a chunk download that ran in a spawned task
/// **off** the net-actor loop. Folded back on-loop by [`fold_confirm_outcome`], which is
/// where the `&mut ShareState` mark/clear-Unresolved mutation and the terminal
/// `FetchComplete`/`FetchError` emission happen — never inside the spawned task.
/// `FetchProgress` events still stream from the worker via the cloned `evt_tx`.
enum ConfirmOutcome {
    /// Every selected file was fetched, verified, and written. Fold: clear any Unresolved
    /// mark + drop the parked retry (CRSH-ISC-25 F6), then emit `FetchComplete`.
    Complete {
        share_id: String,
        files_written: u32,
        bytes_written: u64,
    },
    /// A route-death failure (import / manifest / chunk fetch). Fold: mark the share
    /// Unresolved + park a one-shot retry (#180 §RS-1.4/§RS-1.5, CRSH-ISC-5) — never a prune —
    /// then emit `FetchError`. Any partial bytes were already cleaned in the worker (ISC-A-C31).
    RouteFailed {
        share_id: String,
        name: String,
        message: String,
    },
    /// A local failure (path sanitize / disk write) that must NOT mark the share Unresolved —
    /// the sharer's route is fine. Fold: emit `FetchError` only. Partials already cleaned.
    LocalFailed { message: String },
}

/// Internal: which fold action a download-worker failure implies. Keeps the failure sites in
/// the worker terse (`.map_err`) while carrying the route-death-vs-local distinction that the
/// prior inline code expressed by calling (or not calling) `mark_share_unresolved`.
enum ConfirmFail {
    /// Import / manifest / chunk-fetch failure — the sharer's route is dead: mark Unresolved.
    RouteDeath(String),
    /// Path-sanitize / local-disk failure — the route is fine: do not mark Unresolved.
    Local(String),
}

/// (#197, CRSH-ISC-29) Dispatch an A1/A2 chunk download **off** the net-actor loop: copy the
/// route blob + room key out of share state, spawn [`run_confirm_download`], and return
/// immediately so the actor loop returns to its `select!` without ever awaiting the download
/// (the chat-starvation fix, mirroring the #180 §RS-2 `spawn_fetch_share` restructure). The
/// terminal outcome returns via `outcome_tx` and is folded on-loop by [`fold_confirm_outcome`].
/// Immediate local failures (not connected, lobby not subscribed, share not discovered) still
/// fail inline — they touch no network, need no spawn, and (matching the prior inline behavior)
/// never mark the share Unresolved.
#[allow(clippy::too_many_arguments)]
fn spawn_confirm_fetch(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    outcome_tx: &UnboundedSender<ConfirmOutcome>,
    share_id: &str,
    name: &str,
    fetched_root: PathBuf,
    selected: Option<Vec<usize>>,
    flat_dest: bool,
) {
    let fail = |message: String| {
        let _ = evt_tx.send(NetEvent::FetchError { message });
    };
    let Some(handle) = net.as_ref() else {
        return fail("not connected to Veilid yet".to_owned());
    };
    // Copy the route + room key out under an immutable borrow, dropping it before the spawn.
    let (route_blob, room_key_bytes) = {
        let Some(lobby) = shares.lobby.as_ref() else {
            return fail("lobby not subscribed yet".to_owned());
        };
        let Some(disc) = shares.discovered.get(share_id) else {
            return fail("share not discovered yet — refresh the list".to_owned());
        };
        (disc.route_blob.clone(), *lobby.room_key.as_bytes())
    };
    let handle = handle.clone();
    let evt_tx = evt_tx.clone();
    let share_id = share_id.to_owned();
    let name = name.to_owned();
    spawn_confirm_task(outcome_tx.clone(), async move {
        run_confirm_download(
            &handle,
            &evt_tx,
            share_id,
            name,
            route_blob,
            room_key_bytes,
            fetched_root,
            selected,
            flat_dest,
        )
        .await
    });
}

/// (#197, CRSH-ISC-29) The spawn seam shared by [`spawn_confirm_fetch`] and the actor tests:
/// run `download` as a detached task and report its [`ConfirmOutcome`] to `outcome_tx`,
/// returning immediately. This is the single point guaranteeing no download is ever awaited on
/// the caller (the actor loop) — testable without a live veilid attach.
fn spawn_confirm_task<F>(outcome_tx: UnboundedSender<ConfirmOutcome>, download: F)
where
    F: std::future::Future<Output = ConfirmOutcome> + Send + 'static,
{
    tokio::spawn(async move {
        // A closed channel just means the actor shut down mid-download — the outcome is moot.
        let _ = outcome_tx.send(download.await);
    });
}

/// (#197, CRSH-ISC-29) The network+disk half of a download — import the route, then fetch,
/// verify, and reassemble each selected file's chunks and write them to disk — run **inside a
/// spawned task**, never on the actor loop. Streams `FetchProgress` via the cloned `evt_tx`; all
/// `&mut ShareState` mutation and the terminal event are deferred to [`fold_confirm_outcome`]
/// via the returned [`ConfirmOutcome`]. On any failure the partial bytes this download wrote
/// are removed here (clean-partial, ISC-A-C31) before the outcome returns.
#[allow(clippy::too_many_arguments)]
async fn run_confirm_download(
    handle: &VeilidNetHandle,
    evt_tx: &UnboundedSender<NetEvent>,
    share_id: String,
    name: String,
    route_blob: Vec<u8>,
    room_key_bytes: [u8; 32],
    fetched_root: PathBuf,
    selected: Option<Vec<usize>>,
    flat_dest: bool,
) -> ConfirmOutcome {
    let mut written: Vec<PathBuf> = Vec::new();
    let mut chunks_received: u32 = 0;
    let mut bytes_received: u64 = 0;
    let mut files_written: u32 = 0;

    // The whole download funnels through ONE async block returning `Result` so every failure
    // site routes to the single clean-partial + outcome-mapping tail below.
    let result: Result<(), ConfirmFail> = async {
        let sid: &str = &share_id;
        let name_ref: &str = &name;
        let route = handle.import_route(route_blob).await.map_err(|e| {
            ConfirmFail::RouteDeath(format!("could not import the sharer's route: {e}"))
        })?;
        let manifest = handle
            .fetch_manifest(route.clone(), sid, room_key_bytes)
            .await
            .map_err(|e| {
                ConfirmFail::RouteDeath(fetch_error_message(
                    "could not fetch the share manifest",
                    e,
                ))
            })?;

        // Resolve the selected file set (None → all; out-of-range indices ignored).
        let indices: Vec<usize> = match &selected {
            None => (0..manifest.len()).collect(),
            Some(sel) => sel
                .iter()
                .copied()
                .filter(|&i| i < manifest.len())
                .collect(),
        };
        // `flat_dest` (choose-download-dir): rebase the selection to the dest root.
        let rel_paths: Vec<&str> = indices
            .iter()
            .map(|&i| manifest[i].rel_path.as_str())
            .collect();
        let rebased: Option<Vec<String>> = flat_dest.then(|| rebase_to_selection_root(&rel_paths));

        let total_chunks: u32 = indices
            .iter()
            .map(|&i| manifest[i].chunks.len() as u32)
            .sum();
        let _ = evt_tx.send(NetEvent::FetchProgress {
            total_chunks: Some(total_chunks),
            chunks_received: 0,
            bytes_received: 0,
        });

        // TWO adaptive concurrency windows for the whole download, each shared across every
        // chunk fetch, both fed the per-chunk max-fragment latency against
        // FRAGMENT_LATENCY_THRESHOLD. `Arc<Mutex>` because concurrent chunk fetches read and
        // update them (the guard is never held across an await).
        //
        // #128 D-1: the FRAGMENT window — opens fully at FRAGMENT_FETCH_CONCURRENCY
        // (safe-by-default: a healthy download is unchanged), narrows floored at 1 on a latency
        // breach, yielding bandwidth back to interactive chat under fat-link congestion and
        // climbing back as latency recovers.
        let aimd = std::sync::Arc::new(std::sync::Mutex::new(AimdWindow::new(
            1,
            daemonseed_veilid_net::share::FRAGMENT_FETCH_CONCURRENCY,
        )));
        // #128 D-2 / #204: the CHUNK window — the dominant folder fanout (chunks per file). It
        // SLOW-STARTS at CHUNK_SLOW_START and climbs by one per healthy chunk up to the
        // CHUNK_FETCH_CONCURRENCY ceiling, so the fetch route is never hit with the cold
        // sustained wide fanout that killed Windows folder downloads. It carries its learned
        // window across files (read once per file, below), so backoff learned early persists.
        let chunk_aimd = std::sync::Arc::new(std::sync::Mutex::new(AimdWindow::slow_start(
            CHUNK_SLOW_START,
            1,
            CHUNK_FETCH_CONCURRENCY,
        )));

        for (pos, &i) in indices.iter().enumerate() {
            let entry = &manifest[i];
            let rel = match &rebased {
                Some(r) => r[pos].as_str(),
                None => entry.rel_path.as_str(),
            };
            let safe = sanitize_rel_path(rel)
                .ok_or_else(|| ConfirmFail::Local(format!("unsafe path in manifest: {rel:?}")))?;
            let dest = if flat_dest {
                fetched_root.join(&safe)
            } else {
                fetched_root.join(safe_folder_name(name_ref)).join(&safe)
            };
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ConfirmFail::Local(format!("could not create {}: {e}", parent.display()))
                })?;
            }
            // Fetch this file's chunks with bounded concurrency (#113), preserving manifest
            // order for byte-for-byte reassembly. Each `fetch_chunk` reassembles its transport
            // fragments and SHA-384-verifies the chunk against its address (ISC-S28 /
            // ISC-A-S20). Open this file at the chunk window learned so far (slow-start on the
            // first file, then whatever the running download has climbed/backed off to — #128
            // D-2). The window is read once per file; the per-chunk `observe` adapts the window
            // the NEXT file opens at.
            let cap = chunk_aimd.lock().expect("chunk aimd mutex").window();
            let chunks = fetch_chunks_ordered(
                &entry.chunks,
                cap,
                |addr| {
                    // Fetch this chunk's fragments at the current adaptive fragment window, then
                    // feed the max observed fragment latency back to BOTH controllers — the
                    // fragment window for the next chunk (#128 D-1) and the chunk window for the
                    // next file (#128 D-2).
                    let aimd = aimd.clone();
                    let chunk_aimd = chunk_aimd.clone();
                    let route = route.clone();
                    let window = aimd.lock().expect("aimd mutex").window();
                    async move {
                        let (data, latency) = handle
                            .fetch_chunk(route, sid, addr, room_key_bytes, window)
                            .await?;
                        let threshold = daemonseed_veilid_net::share::FRAGMENT_LATENCY_THRESHOLD;
                        aimd.lock().expect("aimd mutex").observe(latency, threshold);
                        chunk_aimd
                            .lock()
                            .expect("chunk aimd mutex")
                            .observe(latency, threshold);
                        Ok::<Vec<u8>, VeilidNetError>(data)
                    }
                },
                |data| {
                    chunks_received += 1;
                    bytes_received += data.len() as u64;
                    let _ = evt_tx.send(NetEvent::FetchProgress {
                        total_chunks: Some(total_chunks),
                        chunks_received,
                        bytes_received,
                    });
                },
            )
            .await
            .map_err(|e| ConfirmFail::RouteDeath(fetch_error_message("chunk fetch failed", e)))?;
            let mut file_bytes: Vec<u8> = Vec::with_capacity(entry.size as usize);
            for data in &chunks {
                file_bytes.extend_from_slice(data);
            }
            std::fs::write(&dest, &file_bytes).map_err(|e| {
                ConfirmFail::Local(format!("could not write {}: {e}", dest.display()))
            })?;
            written.push(dest);
            files_written += 1;
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => ConfirmOutcome::Complete {
            share_id,
            files_written,
            bytes_written: bytes_received,
        },
        Err(fail) => {
            // Clean-partial (ISC-A-C31): a failed download persists nothing.
            for p in &written {
                let _ = std::fs::remove_file(p);
            }
            match fail {
                ConfirmFail::RouteDeath(message) => ConfirmOutcome::RouteFailed {
                    share_id,
                    name,
                    message,
                },
                ConfirmFail::Local(message) => ConfirmOutcome::LocalFailed { message },
            }
        }
    }
}

/// (#197, CRSH-ISC-29) Fold a spawned download's terminal outcome on the actor loop — the only
/// place the download's `&mut ShareState` mutation happens. Success clears the Unresolved mark
/// and drops the parked retry (CRSH-ISC-25 F6) and emits `FetchComplete`; a route-death failure
/// marks the share Unresolved and parks a one-shot retry (never a prune) and emits `FetchError`;
/// a local-disk failure emits `FetchError` only (the sharer's route is fine, so no mark).
fn fold_confirm_outcome(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    outcome: ConfirmOutcome,
) {
    match outcome {
        ConfirmOutcome::Complete {
            share_id,
            files_written,
            bytes_written,
        } => {
            clear_share_unresolved(shares, evt_tx, &share_id);
            let _ = evt_tx.send(NetEvent::FetchComplete {
                share_id,
                files_written,
                bytes_written,
            });
        }
        ConfirmOutcome::RouteFailed {
            share_id,
            name,
            message,
        } => {
            mark_share_unresolved(shares, evt_tx, &share_id, &name);
            let _ = evt_tx.send(NetEvent::FetchError { message });
        }
        ConfirmOutcome::LocalFailed { message } => {
            let _ = evt_tx.send(NetEvent::FetchError { message });
        }
    }
}

/// Translate a `VeilidNetEvent` into the `NetEvent` contract. Inbound sealed bytes
/// are tried against each joined circle's key (the AEAD seal authenticates the
/// match); own messages are emitted `mine:true` and deduped in `push_message` (#143). Bytes that
/// open under no circle are tried as a lobby `DiscoveryEnvelope` (share discovery).
/// Fold a verified member heartbeat into a room's presence tracker and push a
/// `Roster` on a render-visible change (#74 lobby / #77 circles). ONE home for the
/// receive-side apply so the own-filter, #78 replay-freshness, and roster-emit logic
/// can't diverge between the lobby and circle paths. `own_pubkey` is our signing
/// pubkey (own beacons are never roster rows); `circle_id` tags the roster (`None` =
/// lobby). The caller has already `open_heartbeat`'d the beacon (provenance verified)
/// and scoped it to this room (the seal/key), so this only decides liveness + render.
fn apply_inbound_beacon(
    tracker: &mut PresenceTracker,
    own_pubkey: Option<&[u8]>,
    circle_id: Option<u64>,
    hb: &wire::MemberHeartbeat,
    evt_tx: &UnboundedSender<NetEvent>,
) {
    // Own beacon → presence is implicit for us, never a roster row.
    if own_pubkey.is_some_and(|pk| beacon_is_own(pk, &hb.sender_pubkey)) {
        return;
    }
    // #78 replay-freshness: drop a captured/replayed or future-dated beacon so it
    // cannot pin a departed member present past the TTL.
    if !beacon_is_fresh(hb.sent_unix_ms, now_unix_ms()) {
        return;
    }
    let prior_handle = tracker
        .members()
        .into_iter()
        .find(|m| m.pubkey == hb.sender_pubkey)
        .map(|m| m.handle);
    let change = tracker.apply(hb, Instant::now());
    if roster_render_changed(change, prior_handle.as_deref(), &hb.sender_handle) {
        let entries = roster_from_members(&tracker.members());
        let _ = evt_tx.send(NetEvent::Roster { circle_id, entries });
    }
}

fn handle_inbound(
    ev: VeilidNetEvent,
    evt_tx: &UnboundedSender<NetEvent>,
    circles: &mut [VeilidCircle],
    shares: &mut ShareState,
) {
    let VeilidNetEvent::Inbound { bytes } = ev else {
        // Attachment / RouteChanged / ValueChanged carry no chat/discovery payload.
        return;
    };
    daemonseed_veilid_net::vtrace!(
        "gui inbound: {} bytes; trying {} joined circle(s)",
        bytes.len(),
        circles.len()
    );
    // `mine` keys on the STABLE identity pubkey, not the mutable display handle —
    // the room↔circle convergence's #143 fix (a mid-session rename no longer makes
    // an own DHT-loopback fail the own-message check and duplicate).
    let my_pubkey = shares
        .signing
        .as_ref()
        .map(|s| s.public_key().to_vec())
        .unwrap_or_default();
    for circle in circles.iter_mut() {
        if let Ok(msg) = open_message(&circle.cot_key, &bytes) {
            // #143: emit own messages too (mine == our pubkey) instead of suppressing.
            // A LIVE own message dedups against its optimistic local echo in
            // `push_message` (same `sent_unix_ms`); a COLD-START backlog own message has
            // no prior echo and renders once — so the reconstructed transcript shows
            // BOTH halves of the conversation, not just the other party's.
            let mine = msg.sender_pubkey == my_pubkey;
            // `who` binds to SHA-384(sender_pubkey)[:12] (ISC-C4/C57): a spoofed
            // handle shows at its `#<prefix>` floor, never under the stolen name.
            let Ok(bound) = Handle::display_bound(&msg.sender_handle, &msg.sender_pubkey) else {
                return; // unbindable pubkey (unreachable post-verify) — drop
            };
            daemonseed_veilid_net::vtrace!(
                "gui inbound: opened circle {} (mine={mine}) -> deliver",
                circle.circle_id
            );
            let _ = evt_tx.send(NetEvent::CircleMessage {
                circle_id: circle.circle_id,
                who: bound.format(DisplayMode::Default),
                text: msg.body,
                mine,
                sent_unix_ms: msg.sent_unix_ms,
            });
            // WB-ISC-4: a verified same-room chat write advances the sender's roster
            // freshness (read-side fold — emits nothing to the network), so a chatty
            // member never false-reaps without needing a keepalive. Delivered AFTER
            // the message so chat is the primary event; own messages are implicit
            // presence, never rostered.
            // #165: gate the presence fold on beacon freshness (±window), exactly as
            // the beacon fold does — an untrusted relay replaying one captured,
            // provenance-valid OLD chat write must not indefinitely re-freshen a
            // departed member's roster liveness. Message delivery/dedup is unaffected.
            if !mine && beacon_is_fresh(msg.sent_unix_ms, now_unix_ms()) {
                let label = default_circle_label(&circle_fingerprint(&circle.cot_key));
                if circle.presence.apply_member_write(
                    &label,
                    &msg.sender_pubkey,
                    &msg.sender_handle,
                    msg.sent_unix_ms,
                    Instant::now(),
                ) == PresenceChange::Appeared
                {
                    let entries = roster_from_members(&circle.presence.members());
                    let _ = evt_tx.send(NetEvent::Roster {
                        circle_id: Some(circle.circle_id),
                        entries,
                    });
                }
            }
            return; // opened under exactly one circle
        }
    }
    // Not a circle message — try it as a public-room (Lobby) chat message before
    // share discovery. Chat and share adverts now ride SEPARATE records (#153), but
    // inbound carries no record tag, so every blob is tried against each opener; the
    // distinct per-kind AAD means only the matching open succeeds (a DiscoveryEnvelope
    // fails `open_room_message`'s AEAD and a chat blob fails `apply_discovery`). #143:
    // own messages are emitted
    // `mine:true` (not suppressed) — they dedup against the optimistic local echo live
    // (same `sent_unix_ms`) and render once from the cold-start backlog.
    // Open under an immutable borrow, then fold under a mutable one (WB-ISC-4).
    let lobby_msg = shares
        .lobby
        .as_ref()
        .and_then(|lobby| open_room_message(&lobby.room_key, DEFAULT_ROOM, &bytes).ok());
    if let Some(msg) = lobby_msg {
        // Pubkey-keyed `mine` + pubkey-bound `who` (ISC-C4/C57), same as circles.
        let mine = msg.sender_pubkey == my_pubkey;
        let Ok(bound) = Handle::display_bound(&msg.sender_handle, &msg.sender_pubkey) else {
            return; // unbindable pubkey (unreachable post-verify) — drop
        };
        daemonseed_veilid_net::vtrace!("gui inbound: opened lobby chat (mine={mine}) -> deliver");
        let _ = evt_tx.send(NetEvent::Message {
            who: bound.format(DisplayMode::Default),
            text: msg.body,
            mine,
            sent_unix_ms: msg.sent_unix_ms,
        });
        // WB-ISC-4 read-side fold (after the message, chat is primary): a same-room
        // lobby chat write advances the sender's roster freshness (emits nothing to
        // the network). Own messages are implicit presence.
        // #165: gate the presence fold on beacon freshness (see the circle fold above).
        if !mine
            && beacon_is_fresh(msg.sent_unix_ms, now_unix_ms())
            && let Some(lobby) = shares.lobby.as_mut()
            && lobby.presence.apply_member_write(
                DEFAULT_ROOM,
                &msg.sender_pubkey,
                &msg.sender_handle,
                msg.sent_unix_ms,
                Instant::now(),
            ) == PresenceChange::Appeared
        {
            let entries = roster_from_members(&lobby.presence.members());
            let _ = evt_tx.send(NetEvent::Roster {
                circle_id: None,
                entries,
            });
        }
        return;
    }
    // Not a chat message — try it as a lobby member-presence heartbeat (#74). A
    // beacon rides the SEPARATE presence record but arrives as the same Inbound
    // (no record tag); the distinct heartbeat AAD means only a real beacon opens
    // here (a chat/announcement blob fails). Fold a verified, fresh, non-own beacon
    // into the lobby roster and push a Roster event on a render-visible change —
    // mirrors the relay `Actor::handle_apply_heartbeat` (lobby route). Read our own
    // pubkey before the `&mut lobby` borrow to avoid aliasing `shares`.
    let own_pubkey = shares.signing.as_ref().map(|s| s.public_key().to_vec());
    if let Some(lobby) = shares.lobby.as_mut()
        && let Ok(hb) = open_heartbeat(&lobby.room_key, &bytes)
    {
        apply_inbound_beacon(
            &mut lobby.presence,
            own_pubkey.as_deref(),
            None,
            &hb,
            evt_tx,
        );
        return;
    }
    // Not a lobby heartbeat — try it as a CIRCLE member-presence heartbeat (#77).
    // Each circle's beacon rides its OWN presence record but arrives as the same
    // Inbound (no record tag); try opening under each joined circle's `cot_key` (the
    // seal scopes it to that circle), then fold it into THAT circle's roster via the
    // shared apply path. Mirrors the relay `Actor::handle_apply_heartbeat` circle route.
    for circle in circles.iter_mut() {
        if let Ok(hb) = open_heartbeat(&circle.cot_key, &bytes) {
            apply_inbound_beacon(
                &mut circle.presence,
                own_pubkey.as_deref(),
                Some(circle.circle_id),
                &hb,
                evt_tx,
            );
            return; // opened under exactly one circle
        }
    }
    // Not a heartbeat — try it as a lobby share-discovery item.
    if apply_discovery(shares, evt_tx, &bytes) {
        return;
    }
    // Not a discovery item — try it as an operator announce/MOTD record item (A-c). A
    // verified item folds into OperatorSpace and pushes a fresh PublicSpaceSnapshot.
    if apply_operator_item(shares, evt_tx, &bytes) {
        return;
    }
    daemonseed_veilid_net::vtrace!(
        "gui inbound: {} bytes opened under no joined circle / lobby",
        bytes.len()
    );
}

/// Try inbound bytes as a lobby `DiscoveryEnvelope` (share discovery). Returns
/// `true` when the bytes were a valid, lobby-openable discovery item (folded in,
/// or dropped on a failed anti-swap check) — so the caller stops trying other
/// interpretations. Returns `false` when they are not a lobby item at all.
///
/// Anti-swap (D-3.5): `open_announcement` provenance-verifies the announcement
/// (yielding the announcer pubkey + share_id); the route advert is then verified
/// against that pubkey before the route is trusted for a fetch. A failed verify
/// drops the item — a MITM on the world-writable lobby record cannot redirect a
/// fetch onto a rogue route.
fn apply_discovery(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    bytes: &[u8],
) -> bool {
    // Reconstruct the lobby room key (no borrow of `shares` held across the
    // mutations below).
    let room_key = match shares.lobby.as_ref() {
        Some(l) => PublicRoomKey::from_bytes(*l.room_key.as_bytes()),
        None => return false,
    };
    let Ok(env) = DiscoveryEnvelope::decode(bytes) else {
        return false; // not a discovery envelope (likely a foreign/own blob)
    };
    let Ok(ann) = open_announcement(&room_key, &env.sealed_announcement) else {
        // Parsed as an envelope but not openable under the lobby key — foreign.
        return false;
    };
    // #116 self-filter: our own announcements (republish AND withdraw) loop back
    // through the same lobby record we sweep. Our shares live in `shares.own`,
    // never the discovered catalog — folding one in creates an un-manageable
    // self-ghost: visible in Public shares yet absent from the unpublish dialog.
    // Drop anything signed by our own identity key before it touches the catalog.
    if let Some(signing) = shares.signing.as_ref()
        && ann.sender_pubkey.as_slice() == signing.public_key().as_slice()
    {
        daemonseed_veilid_net::vtrace!(
            "gui lobby: dropping own announcement for {} (self-filter, #116)",
            ann.share_id
        );
        return true; // consumed: our own announcement is never a discovered share
    }
    // #156 route-import gate (STANDALONE — not a reliance on the catalog wiring):
    // never touch the route map for a share whose announcement fails the
    // receiver-verifiable binding check. #152 shipped route-theater once because
    // the fetch path reads `discovered`, not the catalog; this drops a non-derivable
    // announcement before it can reach either.
    if !share_binding_is_valid(&ann) {
        daemonseed_veilid_net::vtrace!(
            "gui lobby: dropping discovery for {} — v2 share_id binding failed (#156)",
            ann.share_id
        );
        return true; // consumed-and-dropped; no route, no catalog fold
    }
    let now = Instant::now();
    if ann.withdraw {
        let change = shares.catalog.apply_verified(&ann, now);
        // #152: gate the ROUTE map on the catalog decision. The fetch path resolves
        // routes from `discovered`, not the catalog, so an unconditional remove would
        // let a forged withdraw (foreign key → owner-mismatch → `Unchanged`) evict the
        // owner's route and leave the share visible-but-unfetchable. Only drop the
        // route when the catalog actually removed the share.
        if change == CatalogChange::Removed {
            shares.discovered.remove(&ann.share_id);
            // (#180 §RS-1.4, CRSH-ISC-19) A verified withdraw drops any parked browse
            // retry for this share: the discovery episode is over, so a later re-add is a
            // fresh episode and the stale-generation retry never fires against a new route.
            shares.parked_retries.remove(&ann.share_id);
            // (#180 §RS-3, CRSH-ISC-26) Release the withdrawn share's imported route and
            // drop its guard entry — immediately when idle, or deferred to any in-flight
            // fetch's completion. Without this the route leaks until the veilid LRU evicts
            // it and `route_guard` grows unbounded across discovery churn. The loop drains
            // `pending_route_releases` via `release_tolerant`, exactly like the
            // advert-replacement path.
            if let Some(route) = shares.route_guard.note_share_withdrawn(&ann.share_id) {
                shares.pending_route_releases.push(route);
            }
            let _ = evt_tx.send(NetEvent::SharesSnapshot {
                shares: shares.listings(),
            });
        }
        return true;
    }
    // Anti-swap: bind the advertised route to the provenance-verified announcer.
    if !verify_route_advert(
        &ann.sender_pubkey,
        &ann.share_id,
        &env.route_blob,
        &env.route_sig,
    ) {
        daemonseed_veilid_net::vtrace!(
            "gui lobby: dropping discovery for {} — route advert failed verify",
            ann.share_id
        );
        return true; // consumed-and-dropped; do not fall through
    }
    let change = shares.catalog.apply_verified(&ann, now);
    // (#180 route-rotation self-heal, CRSH-ISC-12) A route rotation must re-import even
    // when the catalog folds `Unchanged`. After a sharer restart / route-death its
    // watchdog re-advertises the SAME sealed advert — same `sent_unix_ms` + metadata,
    // only the `route_blob` rotated. The F3 Unchanged arm (`share_catalog.rs`) excludes
    // `route_blob` (it lives in `discovered`, not the catalog), so without an
    // independent blob check a rotated route folds `Unchanged` and the re-import below
    // is skipped — leaving the consumer wedged on the dead route until it restarts.
    // Detect the blob change independently of the catalog metadata verdict.
    //
    // Security (#152/#156): honoring a route change on `Unchanged` does NOT reopen the
    // hijack/redirect path — that protection is UPSTREAM, not this catalog verdict. An
    // announce only reaches here after `share_binding_is_valid` (#156:
    // `share_id == derive_share_id_v2(sender_pubkey, root_commitment)`, so a foreign key
    // derives a different id and is dropped at ingest, line ~3396) AND
    // `verify_route_advert` (the `route_blob`/`route_sig` are cryptographically bound to
    // the id's verified owner, line ~3433). So `env.route_blob` is provably the
    // legitimate owner's rotated route; a non-owner can neither reach this line for this
    // id nor forge a route advert for it.
    let route_changed = shares
        .discovered
        .get(&ann.share_id)
        .is_some_and(|d| d.route_blob != env.route_blob);
    if change != CatalogChange::Unchanged || route_changed {
        // (#180 §RS-3, CRSH-ISC-10) Read the prior entry BEFORE mutating: whether the share is
        // still re-resolving, and whether this advert CHANGES the route blob — an identical
        // re-advert re-imports to the same route id (Evidence 2), so only a real blob change
        // supersedes the imported route.
        let (was_unresolved, route_replaced) = match shares.discovered.get(&ann.share_id) {
            Some(d) => (d.unresolved, d.route_blob != env.route_blob),
            None => (false, false),
        };
        // Reframe (#180, 2026-07-17, CRSH-ISC-6): a ROUTE ROTATION *is* the route refresh, so it
        // marks the share fetchable-again (clears the re-resolve flag). Clearing is a purely
        // local no-network op, so it happens right here at the fold — no cursor-tick
        // decorrelation is owed (CRSH-ISC-15 preserved: nothing is emitted to the network) — and
        // it is keyed on the route blob rotating, NOT the parked-retry window, so a share
        // recovers however long the sharer is away. A content-only re-advert (route blob
        // unchanged) is NOT a refresh: the share stays "re-resolving" until its route rotates.
        let unresolved = if route_replaced {
            false
        } else {
            was_unresolved
        };
        shares.next_generation += 1;
        let generation = shares.next_generation;
        shares.discovered.insert(
            ann.share_id.clone(),
            DiscoveredRoute {
                route_blob: env.route_blob.clone(),
                generation,
                unresolved,
            },
        );
        if route_replaced {
            // The route refreshed: drop the fetch-failure park (its recovery job is now done —
            // the share is fetchable-again) and release the superseded route on the later of now
            // or the completion of any in-flight fetch still streaming over it — the guard
            // decides; the loop releases.
            shares.parked_retries.remove(&ann.share_id);
            if let Some(route) = shares.route_guard.note_advert_replaced(&ann.share_id) {
                shares.pending_route_releases.push(route);
            }
        }
        let _ = evt_tx.send(NetEvent::SharesSnapshot {
            shares: shares.listings(),
        });
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_veilid_net::route_provenance_input;
    use tokio::sync::mpsc::unbounded_channel;

    /// The interim MOTD write-gate keys on the operator flag's VALUE, not its mere
    /// presence — `DAEMONSEED_OPERATOR=0`/empty must keep a release build read-only.
    /// Exercises the release branch that `cfg!(debug_assertions)` masks in-process.
    #[test]
    fn operator_flag_requires_a_truthy_value() {
        use std::ffi::OsString;
        for on in ["1", "true", "TRUE", "yes", " 1 "] {
            assert!(
                operator_flag_enables(Some(OsString::from(on))),
                "{on:?} should enable"
            );
        }
        for off in ["0", "", "false", "no", "off", "2"] {
            assert!(
                !operator_flag_enables(Some(OsString::from(off))),
                "{off:?} must NOT enable"
            );
        }
        assert!(!operator_flag_enables(None), "unset must NOT enable");
    }

    /// Derive a v2-valid `(share_id, root_commitment)` pair for `signer` publishing
    /// `root` (#156), so an announcement built from them passes the ingest binding
    /// check. A fixed test IKM stands in for the identity's `ShareRootIkm`.
    fn v2_ids(signer: &SignKeypair, root: &str) -> (String, Vec<u8>) {
        let ikm = [0x5au8; 32];
        let nonce = derive_share_root_nonce(&ikm, root);
        let rc = derive_root_commitment(root, &nonce);
        let share_id = derive_share_id_v2(signer.public_key(), &rc);
        (share_id, rc.to_vec())
    }

    #[test]
    fn fetch_error_message_flags_withdrawn_distinctly() {
        // The sharer's authoritative withdraw reads plainly — no context prefix,
        // no "offline" guess — so the UI can tell the user it was unpublished.
        let withdrawn = fetch_error_message(
            "could not fetch the share manifest",
            VeilidNetError::NotServed,
        );
        assert!(withdrawn.contains("withdrew"));
        assert!(!withdrawn.contains("could not fetch"));
        // A transport error keeps its context (the offline / slow / dead-route path).
        let transport = fetch_error_message(
            "chunk fetch failed",
            VeilidNetError::Send("route dead".to_owned()),
        );
        assert!(transport.contains("chunk fetch failed"));
        assert!(transport.contains("route dead"));
    }

    #[test]
    fn warmup_priority_records_order_operator_then_lobby_then_share() {
        let op = [1u8; 32];
        let lobby = [2u8; 32];
        let share = [3u8; 32];
        // #140 priority: operator MOTD/announce before lobby chat; #153: the share
        // record re-sweeps too so a cold-joiner discovers pre-existing shares.
        assert_eq!(
            warmup_priority_records(Some(op), Some(lobby), Some(share)),
            vec![op, lobby, share]
        );
        // Operator alone.
        assert_eq!(warmup_priority_records(Some(op), None, None), vec![op]);
        // Lobby + share, no operator.
        assert_eq!(
            warmup_priority_records(None, Some(lobby), Some(share)),
            vec![lobby, share]
        );
        // Neither joined → empty (the scheduler re-sweeps nothing that round).
        assert!(warmup_priority_records(None, None, None).is_empty());
    }

    #[test]
    fn steady_resweep_hands_off_after_the_warmup_window() {
        // The steady resweep must not overlap the warmup schedule (advisor trap #3):
        // its hand-off point is strictly past the last warmup round.
        let last_warmup = *WARMUP_RESWEEP_SCHEDULE.last().unwrap();
        assert!(STEADY_RESWEEP_WARMUP_HANDOFF > last_warmup);
    }

    #[test]
    fn warmup_resweep_schedule_is_strictly_increasing_and_nonempty() {
        assert!(!WARMUP_RESWEEP_SCHEDULE.is_empty());
        for w in WARMUP_RESWEEP_SCHEDULE.windows(2) {
            assert!(w[0] < w[1], "re-sweep schedule must be strictly increasing");
        }
        // The circle-taper round count can't exceed the schedule length.
        assert!(WARMUP_CIRCLE_RESWEEP_ROUNDS <= WARMUP_RESWEEP_SCHEDULE.len());
    }

    fn announcer(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn lobby() -> LobbyRendezvous {
        LobbyRendezvous {
            room_key: derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap(),
            owner_seed: *derive_room_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            share_owner_seed: *derive_room_share_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            presence_owner_seed: *derive_room_presence_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            presence: PresenceTracker::for_room(DEFAULT_ROOM, PRESENCE_TTL),
        }
    }

    /// Build a lobby `DiscoveryEnvelope`: a sealed self-signed announcement plus a
    /// route advert signed over `share_id ‖ route_blob`. `blob_to_advertise` is
    /// what the envelope carries; `blob_to_sign` is what the signature commits to
    /// (equal for an honest item, differing to model a MITM route swap).
    fn discovery_bytes(
        room_key: &PublicRoomKey,
        signer: &SignKeypair,
        share_id: &str,
        root_commitment: &[u8],
        blob_to_advertise: &[u8],
        blob_to_sign: &[u8],
    ) -> Vec<u8> {
        let fields = AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "tester",
            share_id,
            root_commitment,
            name: "demo-share",
            rating: "",
            withdraw: false,
            sent_unix_ms: 1_000,
        };
        let sealed_announcement = seal_public_announcement(room_key, signer, &fields).unwrap();
        let route_sig = signer
            .sign(&route_provenance_input(share_id, blob_to_sign))
            .unwrap()
            .to_vec();
        DiscoveryEnvelope {
            sealed_announcement,
            route_blob: blob_to_advertise.to_vec(),
            route_sig,
        }
        .encode()
    }

    /// A self-signed WITHDRAW envelope for `share_id` (the withdraw path never checks
    /// the route advert, so the route fields are inert). `sent_unix_ms` is fresh so a
    /// rejection can only come from the binding / owner-check, not staleness.
    fn withdraw_bytes(
        room_key: &PublicRoomKey,
        signer: &SignKeypair,
        share_id: &str,
        root_commitment: &[u8],
    ) -> Vec<u8> {
        let fields = AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "tester",
            share_id,
            root_commitment,
            name: "demo-share",
            rating: "",
            withdraw: true,
            sent_unix_ms: 2_000,
        };
        let sealed_announcement = seal_public_announcement(room_key, signer, &fields).unwrap();
        let route_sig = signer
            .sign(&route_provenance_input(share_id, &[]))
            .unwrap()
            .to_vec();
        DiscoveryEnvelope {
            sealed_announcement,
            route_blob: Vec::new(),
            route_sig,
        }
        .encode()
    }

    /// #152 (finding 3): a foreign peer's forged withdraw for the victim's `share_id`
    /// must NOT evict the owner's route from `discovered` — the fetch path reads that
    /// map, so an unconditional remove would leave the share visible-but-unfetchable.
    #[test]
    fn a_forged_withdraw_cannot_evict_the_owners_route() {
        let victim = announcer(21);
        let attacker = announcer(22);
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());

        let (share_id, rc) = v2_ids(&victim, "/victim/root");
        let vblob = vec![0x11; 96];
        let (evt_tx, mut evt_rx) = unbounded_channel();
        // Victim announces first → catalog entry + route.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &victim, &share_id, &rc, &vblob, &vblob)
        ));
        let _ = evt_rx.try_recv(); // drain the fold snapshot

        // Attacker forges a withdraw pairing the victim's (share_id, rc) with the
        // ATTACKER's key: the #156 binding check fails (share_id ≠
        // derive_share_id_v2(attacker_pk, rc)) → dropped before the withdraw branch,
        // so the owner's route is never evicted.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &attacker, &share_id, &rc)
        ));
        assert_eq!(
            shares.catalog.len(),
            1,
            "the victim's share survives the forged withdraw"
        );
        assert_eq!(
            shares
                .discovered
                .get(&share_id)
                .map(|d| d.route_blob.clone()),
            Some(vblob),
            "the owner's route is NOT evicted → the share stays fetchable"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "the forged withdraw is a no-op — no snapshot"
        );
    }

    /// #152 (finding 1): a foreign peer re-announcing the victim's `share_id` under
    /// its OWN key + route (validly self-signed) must NOT replace the owner's route in
    /// `discovered` — otherwise a click on the victim-attributed row fetches attacker
    /// content. The catalog keeps the owner (first-writer-wins) AND the route map does.
    #[test]
    fn a_hijack_reannounce_cannot_replace_the_owners_route() {
        let victim = announcer(23);
        let attacker = announcer(24);
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());

        let (share_id, rc) = v2_ids(&victim, "/victim/root");
        let vblob = vec![0x33; 96];
        let ablob = vec![0x44; 96];
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &victim, &share_id, &rc, &vblob, &vblob)
        ));
        let _ = evt_rx.try_recv();

        // Attacker re-announces the victim's (share_id, rc) with its own key + route:
        // the #156 binding check fails, so it never reaches the catalog or route map.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &attacker, &share_id, &rc, &ablob, &ablob)
        ));
        assert_eq!(
            shares
                .discovered
                .get(&share_id)
                .map(|d| d.route_blob.clone()),
            Some(vblob),
            "the fetch route stays the owner's — no redirect"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "the hijack refresh is rejected — no snapshot"
        );
    }

    #[test]
    fn apply_discovery_folds_in_an_honest_signed_item_and_keeps_its_route() {
        let signer = announcer(11);
        let mut shares = ShareState::new();
        let lob = lobby();
        // Re-derive the room key for the envelope (the one in `lob` is moved in).
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lob);

        let (share_id, rc) = v2_ids(&signer, "/root");
        let blob = vec![0xAB; 96];
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &rc, &blob, &blob);

        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes));
        assert_eq!(shares.catalog.len(), 1, "the share entered the catalog");
        assert_eq!(
            shares
                .discovered
                .get(&share_id)
                .map(|d| d.route_blob.clone()),
            Some(blob),
            "the verified route is retained for the fetch"
        );
        assert!(
            matches!(evt_rx.try_recv(), Ok(NetEvent::SharesSnapshot { shares }) if shares.len() == 1),
            "a SharesSnapshot listing the share is emitted"
        );
    }

    /// Fold one honest share and return `(shares, share_id, room_key, signer, rc)` ready
    /// for the reactive-path tests — the share is in the catalog + discovered map.
    fn folded_share(seed: u8) -> (ShareState, String, PublicRoomKey, SignKeypair, Vec<u8>) {
        let signer = announcer(seed);
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());
        let (share_id, rc) = v2_ids(&signer, "/root");
        let blob = vec![0xAB; 96];
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &rc, &blob, &blob);
        let (evt_tx, _rx) = unbounded_channel();
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes));
        (shares, share_id, room_key, signer, rc)
    }

    // ── CRSH-ISC-4: the reactive path mutates LOCAL state only — zero network ops ──────
    /// A fetch failure's local effect (`mark_share_unresolved`) marks the route Unresolved,
    /// parks a one-shot retry, keeps the share listed, and emits only a `SharesSnapshot`.
    /// The function takes NO network handle by construction, so it structurally cannot
    /// enqueue a DHT write/GET/open/watch — the design keystone (§RS-0).
    #[test]
    fn crsh_isc_4_reactive_path_marks_unresolved_without_network() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(31);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");

        // Local state: route marked Unresolved, one-shot retry parked, share still present.
        assert!(shares.discovered.get(&share_id).unwrap().unresolved);
        assert!(shares.parked_retries.contains_key(&share_id));
        assert_eq!(shares.catalog.len(), 1, "the share is NOT pruned");
        // The ONLY event is a local SharesSnapshot that lists the share as unresolved — no
        // network event of any kind (there is no network handle in scope to produce one).
        match evt_rx.try_recv() {
            Ok(NetEvent::SharesSnapshot { shares }) => {
                let row = shares.iter().find(|s| s.share_id == share_id).unwrap();
                assert!(row.unresolved, "the share is listed, marked re-resolving");
            }
            other => panic!("expected a SharesSnapshot, got {other:?}"),
        }
        assert!(evt_rx.try_recv().is_err(), "no further events");
    }

    // ── CRSH-ISC-27 (#180 route-rotation self-heal): a rotated route re-imports on catalog Unchanged ──
    /// The headline CRSH-ISC-12 wedge: after a sharer restart / route-death its watchdog
    /// re-advertises the SAME sealed advert (same `sent_unix_ms` + metadata) with only the
    /// `route_blob` rotated. The F3 Unchanged arm excludes `route_blob` (it lives in
    /// `discovered`, not the catalog), so the fold returns `Unchanged`. This proves the
    /// consumer STILL re-imports the rotated route (un-wedging without restart), stamps a
    /// fresh generation, and — per the reframe (CRSH-ISC-6) — marks the share fetchable-again
    /// (clears Unresolved, drops the park) since a route rotation IS the route refresh; an
    /// identical re-read (no rotation) still folds with no generation churn (F3 preserved).
    #[test]
    fn crsh_isc_27_route_rotation_reimports_on_catalog_unchanged() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(43);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // The consumer's fetch died on the old route → Unresolved + a parked browse retry.
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        let _ = evt_rx.try_recv(); // drain the mark's snapshot
        let gen_before = shares.discovered.get(&share_id).unwrap().generation;
        let old_blob = shares.discovered.get(&share_id).unwrap().route_blob.clone();

        // The sharer re-advertises the SAME advert (sent_unix_ms=1000 + metadata) with a
        // ROTATED route blob — the exact restart-republish shape that folds Unchanged.
        let new_blob = vec![0xCD; 96];
        assert_ne!(
            new_blob, old_blob,
            "the rotated blob differs from the dead one"
        );
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &rc, &new_blob, &new_blob);
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes));

        // The catalog folded Unchanged (same metadata + timestamp) — one entry, not two.
        assert_eq!(
            shares.catalog.len(),
            1,
            "the catalog folds Unchanged, no new entry"
        );
        let d = shares.discovered.get(&share_id).unwrap();
        // THE FIX: the rotated route is re-imported despite the Unchanged catalog verdict.
        assert_eq!(
            d.route_blob, new_blob,
            "the rotated route is re-imported on Unchanged"
        );
        // A fresh generation is stamped, superseding the dead route.
        assert!(
            d.generation > gen_before,
            "a fresh generation supersedes the dead route"
        );
        // Reframe (CRSH-ISC-6): a route rotation IS the route refresh, so the share is marked
        // fetchable-again — Unresolved cleared, the fetch-failure park dropped.
        assert!(
            !d.unresolved,
            "the route rotation marks the share fetchable-again (Unresolved cleared)"
        );
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "the route rotation drops the fetch-failure park"
        );
        assert!(
            matches!(evt_rx.try_recv(), Ok(NetEvent::SharesSnapshot { .. })),
            "a SharesSnapshot is emitted on the re-import"
        );

        // F3 no-churn preserved: re-reading the SAME (now-current) blob folds with no
        // generation bump and no snapshot — only a genuine rotation re-imports.
        let gen_after = shares.discovered.get(&share_id).unwrap().generation;
        let bytes_same = discovery_bytes(&room_key, &signer, &share_id, &rc, &new_blob, &new_blob);
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes_same));
        assert_eq!(
            shares.discovered.get(&share_id).unwrap().generation,
            gen_after,
            "an identical re-read (no rotation) does not bump the generation (F3 preserved)"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "an identical re-read emits no snapshot (no churn)"
        );
    }

    // ── CRSH-ISC-25 (#180 F6): a completed download clears the Unresolved mark + parked retry ──
    /// A failed-then-retried download that SUCCEEDS must resolve the share — symmetric with the
    /// download-failure `mark_share_unresolved` and the browse-preview-success clear in
    /// `fold_fetch_outcome`. `confirm_fetch_inner`'s success tail calls `clear_share_unresolved`
    /// right before it emits `FetchComplete`; that clear seam is exercised here directly (the
    /// full `confirm_fetch_inner` needs a live veilid handle + real chunk I/O to reach the tail,
    /// so the byte-transfer portion is live-only). Without the clear the share strands
    /// "re-resolving" and its stale parked retry fires a redundant browse fetch.
    #[test]
    fn crsh_isc_25_download_success_clears_unresolved_and_parked_retry() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(37);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // Precondition: a prior download failed → Unresolved + a parked browse retry (the exact
        // state a mid-download route-death leaves behind).
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        assert!(shares.discovered.get(&share_id).unwrap().unresolved);
        assert!(shares.parked_retries.contains_key(&share_id));
        let _ = evt_rx.try_recv(); // drain the mark's SharesSnapshot

        // The retried download completes: the success tail clears the mark + drops the retry.
        clear_share_unresolved(&mut shares, &evt_tx, &share_id);

        assert!(
            !shares.discovered.get(&share_id).unwrap().unresolved,
            "a completed download clears the Unresolved mark"
        );
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "a completed download drops the parked browse retry"
        );
        assert_eq!(
            shares.catalog.len(),
            1,
            "the share stays listed, now resolved"
        );
        // The clear snapshots the resolved listing.
        match evt_rx.try_recv() {
            Ok(NetEvent::SharesSnapshot { shares }) => {
                let row = shares.iter().find(|s| s.share_id == share_id).unwrap();
                assert!(
                    !row.unresolved,
                    "the listed share is no longer re-resolving"
                );
            }
            other => panic!("expected a SharesSnapshot, got {other:?}"),
        }
    }

    // ── CRSH-ISC-5: a fetch-fail share stays listed Unresolved; removed only on verified
    //    withdraw or catalog TTL ─────────────────────────────────────────────────────
    /// Both browse fetch-fail variants (import-fail and manifest-fail) AND the download path
    /// (`confirm_fetch_inner` import/manifest/chunk-fetch fail) route through
    /// `mark_share_unresolved`, so its effect is the variant-independent contract: the share
    /// stays listed, and a verified withdraw is what removes it.
    #[test]
    fn crsh_isc_5_fetch_fail_stays_listed_until_verified_withdraw() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(32);
        let (evt_tx, _rx) = unbounded_channel();

        // Fetch failed (either variant) → Unresolved, still listed.
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        assert!(
            shares.listings().iter().any(|s| s.share_id == share_id),
            "an Unresolved share stays listed (never pruned on fetch failure)"
        );

        // The owner's verified withdraw is the authoritative removal signal.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &signer, &share_id, &rc)
        ));
        assert!(
            !shares.listings().iter().any(|s| s.share_id == share_id),
            "a verified withdraw removes the share"
        );
    }

    /// The other authoritative removal: catalog receive-time TTL expiry drops the share
    /// from the listing even while Unresolved.
    #[test]
    fn crsh_isc_5_catalog_ttl_removes_an_unresolved_share() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(33);
        let (evt_tx, _rx) = unbounded_channel();
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");

        // Advance past the catalog TTL: the receive-time prune removes it from the listing.
        shares
            .catalog
            .prune(Instant::now() + SHARE_CATALOG_TTL + Duration::from_secs(1));
        assert!(
            !shares.listings().iter().any(|s| s.share_id == share_id),
            "catalog TTL expiry removes the share"
        );
    }

    // ── CRSH-ISC-19: a withdraw/re-add while parked drops the stale retry ──────────────
    /// A verified withdraw removes the discovered entry AND its parked retry, so a later
    /// re-add is a fresh discovery episode that never fires the old (stale-generation)
    /// retry against the new advert's route.
    #[test]
    fn crsh_isc_19_verified_withdraw_drops_the_parked_retry() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(34);
        let (evt_tx, _rx) = unbounded_channel();
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        assert!(shares.parked_retries.contains_key(&share_id));

        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &signer, &share_id, &rc)
        ));
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "the withdraw dropped the parked retry (CRSH-ISC-19)"
        );
    }

    /// The parked-retry tick processor surfaces failure (no prune) on window expiry and
    /// clears the entry — the local, no-network half of CRSH-ISC-6.
    #[test]
    fn crsh_isc_6_window_expiry_surfaces_error_without_pruning() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(35);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        // Park a retry whose window is already elapsed (deadline in the past).
        shares.discovered.get_mut(&share_id).unwrap().unresolved = true;
        shares.parked_retries.insert(
            share_id.clone(),
            ParkedBrowseRetry {
                name: "demo-share".to_owned(),
                parked_generation: shares.discovered.get(&share_id).unwrap().generation,
                deadline: Instant::now() - Duration::from_secs(1),
            },
        );

        process_parked_browse_retries(&mut shares, &evt_tx);

        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "the expired retry is cleared"
        );
        assert_eq!(shares.catalog.len(), 1, "expiry NEVER prunes the share");
        assert!(
            matches!(evt_rx.try_recv(), Ok(NetEvent::FetchError { .. })),
            "expiry surfaces a failure to the UI"
        );
    }

    /// Reframe (#180, 2026-07-17) finding-1 guard: a content-only re-advert (fresher timestamp,
    /// SAME route blob) folds `Updated` and bumps the discovered generation, but it is NOT a
    /// route refresh — so the share must STAY `Unresolved` (re-resolving), not flip to
    /// fetchable-looking against a route that never changed. Only an actual route rotation
    /// (`route_replaced`, `crsh_isc_27_*`) clears `Unresolved`.
    #[test]
    fn crsh_isc_6_content_readvert_does_not_mark_fetchable() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(36);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // The consumer's fetch died → Unresolved + a parked browse retry (same route blob 0xAB).
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        let _ = evt_rx.try_recv(); // drain the mark's snapshot
        let same_blob = shares.discovered.get(&share_id).unwrap().route_blob.clone();
        let gen_before = shares.discovered.get(&share_id).unwrap().generation;

        // A content-only re-advert: a FRESHER timestamp (folds Updated) over the SAME route blob.
        let fields = AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "tester",
            share_id: &share_id,
            root_commitment: &rc,
            name: "demo-share",
            rating: "",
            withdraw: false,
            sent_unix_ms: 9_000, // fresher than folded_share's 1_000 → catalog Updated
        };
        let sealed = seal_public_announcement(&room_key, &signer, &fields).unwrap();
        let route_sig = signer
            .sign(&route_provenance_input(&share_id, &same_blob))
            .unwrap()
            .to_vec();
        let bytes = DiscoveryEnvelope {
            sealed_announcement: sealed,
            route_blob: same_blob.clone(),
            route_sig,
        }
        .encode();
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes));

        let d = shares.discovered.get(&share_id).unwrap();
        assert!(
            d.generation > gen_before,
            "the fresher-timestamp re-advert bumps the generation (folds Updated)"
        );
        assert_eq!(d.route_blob, same_blob, "the route blob did NOT rotate");
        assert!(
            d.unresolved,
            "a content-only re-advert is NOT a route refresh — the share stays re-resolving"
        );
        assert!(
            shares.parked_retries.contains_key(&share_id),
            "the park survives a non-rotating re-advert"
        );
    }

    /// Reframe (#180, 2026-07-17): with the mark-fetchable now owned by the route-rotation fold
    /// (`apply_discovery`), a park reaching `Fire` at a cursor tick saw a generation bump WITHOUT
    /// a route rotation (a content-only re-advert) — so the tick drops the stale park and does
    /// NOT clear `Unresolved` (a real rotation would already have cleared it at the fold).
    #[test]
    fn crsh_isc_6_fire_drops_stale_park_without_clearing() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(46);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        // Park a live-window retry, then advance the generation past it (a content re-advert
        // folded) so the tick classifies Fire — but the route was never refreshed.
        let g = shares.discovered.get(&share_id).unwrap().generation;
        shares.discovered.get_mut(&share_id).unwrap().unresolved = true;
        shares.parked_retries.insert(
            share_id.clone(),
            ParkedBrowseRetry {
                name: "demo-share".to_owned(),
                parked_generation: g,
                deadline: Instant::now() + Duration::from_secs(60),
            },
        );
        shares.discovered.get_mut(&share_id).unwrap().generation = g + 1;
        assert_eq!(
            parked_retry_action(
                shares.parked_retries.get(&share_id).unwrap(),
                Some(g + 1),
                Instant::now()
            ),
            ParkedRetryAction::Fire,
            "precondition: the advanced generation classifies as Fire"
        );

        process_parked_browse_retries(&mut shares, &evt_tx);

        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "the Fire tick drops the stale park"
        );
        assert!(
            shares.discovered.get(&share_id).unwrap().unresolved,
            "the tick does NOT clear Unresolved — clearing is the route-rotation fold's job"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "dropping a stale park emits no event"
        );
    }

    // ── CRSH-ISC-8: the actor loop never awaits a fetch inline ─────────────────────────
    /// A chat command enqueued while a fetch is in flight is processed BEFORE the fetch
    /// resolves. Modelled on the spawn seam (`spawn_fetch_task`) that the actor's
    /// `FetchShare` dispatch uses: a fetch that blocks on a gate is spawned, then the
    /// "chat" work runs synchronously to completion while the fetch outcome has NOT yet
    /// arrived — proving the dispatch returned immediately rather than awaiting the fetch.
    /// No live veilid attach is required.
    #[tokio::test]
    async fn crsh_isc_8_actor_never_awaits_a_fetch_inline() {
        let (outcome_tx, mut outcome_rx) = unbounded_channel::<FetchOutcome>();
        let gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let gate_fetch = gate.clone();

        // Dispatch a "FetchShare" whose fetch blocks until the gate is released.
        spawn_fetch_task(outcome_tx, async move {
            gate_fetch.notified().await;
            FetchOutcome::ImportFailed {
                share_id: "s".to_owned(),
                name: "demo".to_owned(),
                generation: 1,
                message: "blocked fetch released".to_owned(),
            }
        });

        // The actor loop is free to process a chat command right away: the fetch is still
        // parked on the gate, so its outcome must not be available yet.
        let mut order: Vec<&str> = vec!["dispatched-fetch"];
        order.push("chat"); // stands in for handle_command(SendLobby/SendCircle)
        assert_eq!(
            order,
            ["dispatched-fetch", "chat"],
            "chat is processed inline while the fetch is still in flight"
        );
        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the fetch has NOT resolved — the loop did not await it inline"
        );

        // Releasing the gate lets the spawned fetch complete and its outcome arrive on-loop.
        gate.notify_one();
        let outcome = outcome_rx.recv().await.expect("the fetch outcome arrives");
        assert!(
            matches!(outcome, FetchOutcome::ImportFailed { .. }),
            "the spawned fetch reports its outcome back for on-loop folding"
        );
    }

    // ── CRSH-ISC-29 (#197): the actor loop never awaits a DOWNLOAD inline ──────────────
    /// A chat command enqueued while a download is in flight is processed BEFORE the download
    /// resolves. Modelled on the spawn seam (`spawn_confirm_task`) that the actor's
    /// `ConfirmFetch` dispatch uses: a download that blocks on a gate is spawned, then its
    /// outcome has NOT yet arrived when the loop is free to process chat — proving the dispatch
    /// returned immediately rather than awaiting the download. No live veilid attach required.
    #[tokio::test]
    async fn crsh_isc_29_actor_never_awaits_a_download_inline() {
        let (outcome_tx, mut outcome_rx) = unbounded_channel::<ConfirmOutcome>();
        let gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let gate_dl = gate.clone();

        // Dispatch a "ConfirmFetch" whose download blocks until the gate is released.
        spawn_confirm_task(outcome_tx, async move {
            gate_dl.notified().await;
            ConfirmOutcome::Complete {
                share_id: "s".to_owned(),
                files_written: 1,
                bytes_written: 42,
            }
        });

        // The actor loop is free to process a chat command right away: the download is still
        // parked on the gate, so its outcome must not be available yet.
        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the download has NOT resolved — the loop did not await it inline"
        );

        // Releasing the gate lets the spawned download complete and its outcome arrive on-loop.
        gate.notify_one();
        let outcome = outcome_rx
            .recv()
            .await
            .expect("the download outcome arrives");
        assert!(
            matches!(outcome, ConfirmOutcome::Complete { .. }),
            "the spawned download reports its outcome back for on-loop folding"
        );
    }

    // ── CRSH-ISC-29 fold: mark/clear-Unresolved is applied on-loop, per outcome kind ───
    /// `Complete` clears any Unresolved mark + emits FetchComplete; `RouteFailed` marks the
    /// share Unresolved + parks a retry + emits FetchError; `LocalFailed` touches ShareState
    /// not at all + emits FetchError only. This is the semantic-parity guard for the off-loop
    /// move: the fold applies exactly the mutation the prior inline code applied at each site.
    #[test]
    fn crsh_isc_29_fold_applies_mark_clear_per_outcome() {
        // Complete → clears a prior Unresolved mark + drops the parked retry + FetchComplete.
        let (mut shares, share_id, _rk, _s, _rc) = folded_share(29);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo");
        while evt_rx.try_recv().is_ok() {}
        assert!(shares.discovered.get(&share_id).unwrap().unresolved);
        fold_confirm_outcome(
            &mut shares,
            &evt_tx,
            ConfirmOutcome::Complete {
                share_id: share_id.clone(),
                files_written: 2,
                bytes_written: 100,
            },
        );
        assert!(
            !shares.discovered.get(&share_id).unwrap().unresolved,
            "Complete clears the Unresolved mark"
        );
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "Complete drops the parked retry"
        );
        assert!(
            std::iter::from_fn(|| evt_rx.try_recv().ok())
                .any(|e| matches!(e, NetEvent::FetchComplete { .. })),
            "Complete emits FetchComplete"
        );

        // RouteFailed → marks Unresolved + parks a one-shot retry + FetchError.
        let (mut shares, share_id, _rk, _s, _rc) = folded_share(30);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(!shares.discovered.get(&share_id).unwrap().unresolved);
        fold_confirm_outcome(
            &mut shares,
            &evt_tx,
            ConfirmOutcome::RouteFailed {
                share_id: share_id.clone(),
                name: "demo".to_owned(),
                message: "route dead".to_owned(),
            },
        );
        assert!(
            shares.discovered.get(&share_id).unwrap().unresolved,
            "RouteFailed marks the share Unresolved"
        );
        assert!(
            shares.parked_retries.contains_key(&share_id),
            "RouteFailed parks a one-shot retry"
        );
        assert!(
            std::iter::from_fn(|| evt_rx.try_recv().ok())
                .any(|e| matches!(e, NetEvent::FetchError { .. })),
            "RouteFailed emits FetchError"
        );

        // LocalFailed → no ShareState mutation, FetchError only.
        let (mut shares, share_id, _rk, _s, _rc) = folded_share(28);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        fold_confirm_outcome(
            &mut shares,
            &evt_tx,
            ConfirmOutcome::LocalFailed {
                message: "disk full".to_owned(),
            },
        );
        assert!(
            !shares.discovered.get(&share_id).unwrap().unresolved,
            "LocalFailed does NOT mark the share Unresolved"
        );
        assert!(
            shares.parked_retries.is_empty(),
            "LocalFailed parks nothing"
        );
        let evts: Vec<_> = std::iter::from_fn(|| evt_rx.try_recv().ok()).collect();
        assert!(
            evts.iter()
                .any(|e| matches!(e, NetEvent::FetchError { .. })),
            "LocalFailed emits FetchError"
        );
        assert!(
            !evts
                .iter()
                .any(|e| matches!(e, NetEvent::SharesSnapshot { .. })),
            "LocalFailed emits no SharesSnapshot (no state change)"
        );
    }

    // ── CRSH-ISC-7: a failing-fetch storm never delays chat past the I4 bound ──────────
    /// Anti (paused-time): a storm of slow failing fetches is dispatched, then a chat
    /// dispatch runs — and completes within the WB-3 I4 chat bound (≤ 2s), because every
    /// fetch is spawned off-loop and none is awaited on the dispatch path. The storm's
    /// outcomes are still pending when chat dispatches (they resolve only after their long
    /// simulated latency elapses).
    #[tokio::test(start_paused = true)]
    async fn crsh_isc_7_failing_fetch_storm_never_delays_chat() {
        const I4_BOUND: Duration = Duration::from_secs(2);
        let (outcome_tx, mut outcome_rx) = unbounded_channel::<FetchOutcome>();

        // A ~60s failing-fetch storm (the felt-test's retry window), all spawned off-loop.
        let start = Instant::now();
        for i in 0..16 {
            let tx = outcome_tx.clone();
            spawn_fetch_task(tx, async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                FetchOutcome::ImportFailed {
                    share_id: format!("s{i}"),
                    name: "demo".to_owned(),
                    generation: 1,
                    message: "storm".to_owned(),
                }
            });
        }
        // The chat dispatch happens on-loop immediately after the storm is spawned.
        let chat_dispatch_elapsed = start.elapsed();
        assert!(
            chat_dispatch_elapsed <= I4_BOUND,
            "chat dispatched within the I4 bound ({chat_dispatch_elapsed:?} ≤ {I4_BOUND:?})"
        );
        // None of the storm's outcomes has resolved yet — chat did not wait on them.
        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the storm is still in flight when chat dispatches"
        );

        // Advancing past the simulated latency lets the storm drain — bounded, not leaked.
        tokio::time::advance(Duration::from_secs(61)).await;
        for _ in 0..16 {
            assert!(
                matches!(
                    outcome_rx.recv().await,
                    Some(FetchOutcome::ImportFailed { .. })
                ),
                "every spawned fetch eventually reports its outcome"
            );
        }
    }

    // ── CRSH-ISC-19: a WITHDRAW-stale fetch outcome drops, never re-parks ──────────────
    /// Two folds. First a LIVE-generation failure takes effect (marks Unresolved + parks a
    /// retry). Then the share is WITHDRAWN (removed from `discovered`) and a stale outcome
    /// folds: it MUST drop — no re-park against a gone share, no resurrection, no event. This
    /// is the withdraw-staleness half; the fresh-advert half (which now re-parks) is
    /// CRSH-ISC-23 below. Exercised via the route-free `ImportFailed` variant.
    #[test]
    fn crsh_isc_19_withdraw_staleness_drops_without_re_parking() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(36);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        let live_gen = shares.discovered.get(&share_id).unwrap().generation;

        // A live-generation outcome takes effect: mark Unresolved + park a one-shot retry.
        fold_fetch_outcome(
            &mut shares,
            &evt_tx,
            FetchOutcome::ImportFailed {
                share_id: share_id.clone(),
                name: "demo".to_owned(),
                generation: live_gen,
                message: "route dead".to_owned(),
            },
        );
        assert!(
            shares.discovered.get(&share_id).unwrap().unresolved,
            "a live outcome marks the share Unresolved"
        );
        assert!(
            shares.parked_retries.contains_key(&share_id),
            "a live failure outcome parks a one-shot retry"
        );
        while evt_rx.try_recv().is_ok() {} // drain the live-path events (SharesSnapshot + FetchError)

        // Now the share is WITHDRAWN mid-flight and a stale outcome folds. The entry is gone,
        // so the drop is correct: NO re-park, no resurrection, no event.
        shares.parked_retries.remove(&share_id);
        shares.discovered.remove(&share_id);
        fold_fetch_outcome(
            &mut shares,
            &evt_tx,
            FetchOutcome::ImportFailed {
                share_id: share_id.clone(),
                name: "demo".to_owned(),
                generation: live_gen,
                message: "stale-withdrawn".to_owned(),
            },
        );
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "a withdrawn share's stale outcome re-parks NOTHING (CRSH-ISC-19)"
        );
        assert!(
            !shares.discovered.contains_key(&share_id),
            "the stale fold does not resurrect the withdrawn entry"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "a withdrawn-stale outcome emits no snapshot"
        );
    }

    // ── CRSH-ISC-23 (#180 F2): fresh-advert staleness re-parks the browse retry ────────
    /// The headline self-heal case. A parked retry FIRED at generation G (removing itself)
    /// and re-fetched; while that fetch was in flight a FRESH ADVERT folded, advancing the
    /// discovered generation to G+1. The in-flight outcome folds stale (tagged G, entry now
    /// G+1). Pre-fix it was dropped, stranding the share Unresolved-with-no-retry forever.
    /// Post-fix it re-parks at the OUTCOME's generation G so `parked_retry_action` Fires on
    /// the next cursor tick against the newer advert (current G+1 > parked G).
    #[test]
    fn crsh_isc_23_fresh_advert_staleness_re_parks_the_browse_retry() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(37);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // Set up the F2 precondition: unresolved at G+1 (a fresh advert advanced it) with an
        // EMPTY parked_retries (the earlier retry already fired and removed itself).
        let g = shares.discovered.get(&share_id).unwrap().generation;
        {
            let disc = shares.discovered.get_mut(&share_id).unwrap();
            disc.unresolved = true;
            disc.generation = g + 1;
        }
        assert!(
            shares.parked_retries.is_empty(),
            "precondition: the fired retry left parked_retries empty"
        );

        // The in-flight fetch (tagged the OLD generation g) folds stale.
        fold_fetch_outcome(
            &mut shares,
            &evt_tx,
            FetchOutcome::ImportFailed {
                share_id: share_id.clone(),
                name: "demo-share".to_owned(),
                generation: g, // stale: discovered is now g+1
                message: "route dead".to_owned(),
            },
        );

        // The share is NOT stranded: still listed, still Unresolved, and re-parked such that a
        // cursor tick will Fire it against the newer advert.
        let disc = shares.discovered.get(&share_id).unwrap();
        assert!(
            disc.unresolved,
            "the share stays Unresolved after the stale fold"
        );
        let parked = shares
            .parked_retries
            .get(&share_id)
            .expect("a browse retry was re-parked (dropped pre-fix, stranding the share)");
        assert_eq!(
            parked.parked_generation, g,
            "re-parked at the OUTCOME's generation, not the current"
        );
        assert_eq!(
            parked_retry_action(parked, Some(disc.generation), Instant::now()),
            ParkedRetryAction::Fire,
            "process_parked_browse_retries Fires it next tick against the newer advert (g+1 > g)"
        );
        assert!(
            matches!(evt_rx.try_recv(), Ok(NetEvent::SharesSnapshot { .. })),
            "the re-park snapshots the still-Unresolved share to the UI"
        );
    }

    // ── CRSH-ISC-23 (#180 R4): a resolved share is NOT reverted by a late stale outcome ──
    /// R4 regression. Two overlapping different-generation browse fetches: a fetch at G+1 has
    /// already SUCCEEDED, cleared Unresolved, and rendered the manifest; a slower earlier fetch
    /// tagged G then folds stale. Pre-fix the stale branch unconditionally set `unresolved =
    /// true` and re-parked, flipping the resolved share back to Unresolved and firing a
    /// redundant fetch. Post-fix a stale outcome re-parks ONLY a still-unresolved share — a
    /// resolved one is left resolved and the stale outcome is dropped.
    #[test]
    fn crsh_isc_23_resolved_share_is_not_reverted_by_a_late_stale_outcome() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(38);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // A newer fetch at G+1 already resolved the share: unresolved == false, generation G+1,
        // no parked retry outstanding.
        let g = shares.discovered.get(&share_id).unwrap().generation;
        {
            let disc = shares.discovered.get_mut(&share_id).unwrap();
            disc.unresolved = false;
            disc.generation = g + 1;
        }
        shares.parked_retries.remove(&share_id);

        // The slower earlier fetch (tagged the OLD generation G) folds stale.
        fold_fetch_outcome(
            &mut shares,
            &evt_tx,
            FetchOutcome::ImportFailed {
                share_id: share_id.clone(),
                name: "demo-share".to_owned(),
                generation: g, // stale: discovered is now g+1
                message: "route dead".to_owned(),
            },
        );

        // The resolved share is left resolved: NOT reverted, NO parked retry, NO snapshot.
        assert!(
            !shares.discovered.get(&share_id).unwrap().unresolved,
            "a late stale outcome does not revert a share a newer fetch already resolved (R4)"
        );
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "no browse retry is re-parked for an already-resolved share"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "a resolved-stale outcome emits no snapshot"
        );
    }

    // ── CRSH-ISC-13/16: the §RS-4 Refresh re-establishment gate ───────────────────────
    /// [`refresh_or_cadence_due`] is the fold-arm core of the manual-Refresh contract and
    /// the CRSH-ISC-16 anti-criterion: an armed record re-establishes on a SINGLE failed
    /// pass in calm weather; an armed HEALTHY record re-establishes nothing (only sweep
    /// GETs); RepairDue (the cadence K-consecutive path) always re-establishes; and an
    /// un-armed sub-K failure keeps the cadence path unchanged.
    #[test]
    fn crsh_isc_16_refresh_gate_reestablishes_only_on_failure_evidence() {
        let failed_calm = SweepHealthInput {
            attempted: 64,
            failed: 64,
            found: 0,
            watch: WatchState::Unknown,
            weather: Weather::Calm,
        };
        let failed_elevated = SweepHealthInput {
            weather: Weather::Elevated,
            ..failed_calm
        };
        let healthy_calm = SweepHealthInput {
            attempted: 64,
            failed: 0,
            found: 1,
            watch: WatchState::Unknown,
            weather: Weather::Calm,
        };

        // (a) healthy + armed → NO re-establish (CRSH-ISC-16): a Refresh over a healthy
        //     record emits only sweep-shaped GETs, never an open/watch.
        assert!(!refresh_or_cadence_due(
            RepairDecision::NotDue,
            true,
            &healthy_calm
        ));
        // (b) failed + armed + calm → re-establish on a single failure (§RS-4 override).
        assert!(refresh_or_cadence_due(
            RepairDecision::NotDue,
            true,
            &failed_calm
        ));
        // (c) failed + armed + elevated → weather gate suppresses; no re-establish.
        assert!(!refresh_or_cadence_due(
            RepairDecision::NotDue,
            true,
            &failed_elevated
        ));
        // (d) failed + UN-armed below K → cadence K-consecutive path unchanged.
        assert!(!refresh_or_cadence_due(
            RepairDecision::NotDue,
            false,
            &failed_calm
        ));
        // (e) RepairDue (cadence K reached) → always re-establish, armed or not, and
        //     regardless of this single pass's shape.
        assert!(refresh_or_cadence_due(
            RepairDecision::RepairDue,
            false,
            &healthy_calm
        ));
        assert!(refresh_or_cadence_due(
            RepairDecision::RepairDue,
            true,
            &failed_calm
        ));
        // A Suppressed decision on its own (un-armed) never re-establishes — the streak is
        // retained for a later calm pass, not acted on now.
        assert!(!refresh_or_cadence_due(
            RepairDecision::Suppressed,
            false,
            &failed_calm
        ));
    }

    // ── CRSH-ISC-13 (#180 R1): an armed Refresh survives a busy enqueue; the drain honors it ──
    /// R1 regression. A §RS-4 manual Refresh arms a record that is NOT latched repair-due (the
    /// arm lowers K to 1 for a single failed pass). If the fold enqueues the repair because a
    /// sweep is busy/warming, the arm must SURVIVE into `pending_repairs` so the drain
    /// dispatches it — else `is_repair_due` (false) drops it as "recovered" and the dead record
    /// never heals ("one action, no restart"). The fold/drain are inline in the actor loop; this
    /// exercises the pure seams they compose — `refresh_or_cadence_due`, the
    /// `SessionHealthTracker` latch, `drain_should_dispatch` — plus the `refresh_armed`
    /// lifecycle (peek-on-fold, keep-on-enqueue, consume-on-dispatch/not-due, consume-at-drain).
    /// Live end-to-end coverage is CRSH-ISC-12/13.
    #[test]
    fn crsh_isc_13_armed_refresh_survives_a_busy_enqueue_and_the_drain_honors_it() {
        let failed_calm = SweepHealthInput {
            attempted: 64,
            failed: 64,
            found: 0,
            watch: WatchState::Unknown,
            weather: Weather::Calm,
        };
        let healthy_calm = SweepHealthInput {
            attempted: 64,
            failed: 0,
            found: 1,
            watch: WatchState::Unknown,
            weather: Weather::Calm,
        };
        let key = 0xD00Du64;

        // (1) Armed dead record, sweep BUSY → fold enqueues, arm SURVIVES, drain dispatches.
        {
            let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
            let mut refresh_armed: HashSet<u64> = HashSet::new();
            let mut pending_repairs: VecDeque<u64> = VecDeque::new();
            refresh_armed.insert(key);
            let decision = tracker.observe(key, failed_calm); // one failed pass < K
            assert_eq!(
                decision,
                RepairDecision::NotDue,
                "a single failed pass is below K — the record is never latched repair-due"
            );
            // Fold arm PEEKs the arm and finds the record due via the single-failure override.
            let armed = refresh_armed.contains(&key);
            assert!(refresh_or_cadence_due(decision, armed, &failed_calm));
            // Busy/warming enqueue: push and LEAVE the arm in place (the R1 fix).
            pending_repairs.push_back(key);
            assert!(
                refresh_armed.contains(&key),
                "the arm SURVIVES the busy enqueue (R1) — not consumed at fold"
            );
            // Drain: consume the arm, dispatch iff still-due OR armed.
            let popped = pending_repairs.pop_front().unwrap();
            let armed_at_drain = refresh_armed.remove(&popped);
            assert!(armed_at_drain, "the drain sees the surviving arm");
            assert!(
                !tracker.is_repair_due(&popped),
                "the armed record was never latched cadence-repair-due"
            );
            assert!(
                drain_should_dispatch(tracker.is_repair_due(&popped), armed_at_drain),
                "the drain dispatches the armed repair (R1 restored)"
            );
        }

        // (2) A recovered armed record (a successful sweep consumed the arm at the not-due
        //     fold) is NOT dispatched at drain — Q4/F4 preserved.
        {
            let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
            let mut refresh_armed: HashSet<u64> = HashSet::new();
            let mut pending_repairs: VecDeque<u64> = VecDeque::new();
            refresh_armed.insert(key);
            // A failed pass enqueues it, arm surviving.
            let d1 = tracker.observe(key, failed_calm);
            assert!(refresh_or_cadence_due(
                d1,
                refresh_armed.contains(&key),
                &failed_calm
            ));
            pending_repairs.push_back(key); // arm left in place
            // Then a SUCCESSFUL sweep folds not-due: the not-due fold arm consumes the arm.
            let d2 = tracker.observe(key, healthy_calm);
            assert!(!refresh_or_cadence_due(
                d2,
                refresh_armed.contains(&key),
                &healthy_calm
            ));
            refresh_armed.remove(&key); // not-due branch consumes the arm
            // Drain pops the stale queued entry: latch clear AND arm consumed → dropped.
            let popped = pending_repairs.pop_front().unwrap();
            let armed_at_drain = refresh_armed.remove(&popped);
            assert!(
                !armed_at_drain,
                "a recovered record's arm was consumed by the not-due fold"
            );
            assert!(!tracker.is_repair_due(&popped));
            assert!(
                !drain_should_dispatch(tracker.is_repair_due(&popped), armed_at_drain),
                "the drain drops the recovered queued repair (Q4/F4 preserved)"
            );
        }

        // (3) A healthy armed record → arm consumed at the not-due fold, nothing enqueued
        //     (CRSH-ISC-16: a Refresh over a healthy record emits no open/watch).
        {
            let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
            let mut refresh_armed: HashSet<u64> = HashSet::new();
            let pending_repairs: VecDeque<u64> = VecDeque::new();
            refresh_armed.insert(key);
            let d = tracker.observe(key, healthy_calm);
            assert_eq!(d, RepairDecision::NotDue);
            assert!(
                !refresh_or_cadence_due(d, refresh_armed.contains(&key), &healthy_calm),
                "a healthy armed record is NOT due"
            );
            refresh_armed.remove(&key); // not-due branch consumes
            assert!(
                refresh_armed.is_empty(),
                "a healthy Refresh consumes the arm (no re-establishment)"
            );
            assert!(
                pending_repairs.is_empty(),
                "and enqueues no repair (CRSH-ISC-16)"
            );
        }
    }

    // ── CRSH-ISC-5 (download-fail variant): a failed DOWNLOAD keeps the share listed ──────
    /// The download path (`confirm_fetch_inner`) retired its three prune sites (import-fail,
    /// manifest-fail, chunk-fetch-fail) for the SAME `mark_share_unresolved` reactive path as
    /// the browse path — a download-fail is route-death, not an authoritative removal. So a
    /// download failure keeps the share listed AND keeps its discovered route intact (the
    /// parked retry re-resolves it); only a verified withdraw / catalog TTL removes it.
    #[test]
    fn crsh_isc_5_download_fail_keeps_share_listed_with_route() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(13);
        let (evt_tx, _rx) = unbounded_channel();

        // The download path's failure effect (import / manifest / chunk-fetch fail all funnel
        // through `mark_share_unresolved` now that the prunes are retired).
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        assert!(
            shares.listings().iter().any(|s| s.share_id == share_id),
            "a failed download keeps the share listed (never pruned)"
        );
        assert!(
            shares.discovered.contains_key(&share_id),
            "the discovered route is retained so the parked retry can re-resolve"
        );
        assert!(shares.parked_retries.contains_key(&share_id));

        // Removed only on an authoritative signal — a verified withdraw.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &signer, &share_id, &rc)
        ));
        assert!(
            !shares.listings().iter().any(|s| s.share_id == share_id),
            "a verified withdraw removes it"
        );
    }

    #[test]
    fn apply_discovery_drops_our_own_looped_back_announcement() {
        // #116: we publish our own share to the same lobby record we sweep, so the
        // announcement returns to us. It must NOT land in the discovered catalog —
        // own shares live in `shares.own`. Otherwise it appears in Public shares yet
        // is absent from the unpublish dialog: an un-deletable self-ghost.
        let me = Arc::new(announcer(14));
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());
        shares.signing = Some(me.clone());

        let (share_id, rc) = v2_ids(me.as_ref(), "/root");
        let blob = vec![0xEF; 96];
        // An honest, well-formed announcement signed by our OWN identity key.
        let bytes = discovery_bytes(&room_key, me.as_ref(), &share_id, &rc, &blob, &blob);

        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(
            apply_discovery(&mut shares, &evt_tx, &bytes),
            "our own bytes are a lobby item (consumed)"
        );
        assert_eq!(
            shares.catalog.len(),
            0,
            "our own share never enters the discovered catalog"
        );
        assert!(shares.discovered.is_empty(), "no self-route is retained");
        assert!(
            evt_rx.try_recv().is_err(),
            "no SharesSnapshot is emitted for our own looped-back announcement"
        );
    }

    #[test]
    fn apply_discovery_drops_an_item_whose_route_was_swapped() {
        let signer = announcer(12);
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());

        let (share_id, rc) = v2_ids(&signer, "/root");
        let honest = vec![0x11; 96];
        let rogue = vec![0x22; 96];
        // A MITM keeps the signed announcement + the signature over `honest`, but
        // swaps in `rogue` as the advertised route blob. The binding check passes
        // (genuine id), then the route-advert verify fails on the swap.
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &rc, &rogue, &honest);

        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(
            apply_discovery(&mut shares, &evt_tx, &bytes),
            "the bytes were a lobby item (consumed)"
        );
        assert_eq!(
            shares.catalog.len(),
            0,
            "the swapped item never enters the catalog"
        );
        assert!(shares.discovered.is_empty(), "no rogue route is retained");
        assert!(
            evt_rx.try_recv().is_err(),
            "no SharesSnapshot is emitted for a dropped item"
        );
    }

    #[test]
    fn apply_discovery_ignores_bytes_when_no_lobby_is_subscribed() {
        let mut shares = ShareState::new(); // lobby = None
        let (evt_tx, _evt_rx) = unbounded_channel();
        assert!(!apply_discovery(&mut shares, &evt_tx, b"not-an-envelope"));
    }

    #[tokio::test]
    async fn publish_share_without_a_connection_reports_a_clean_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut net: Option<VeilidNetHandle> = None;
        let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
        let mut circles: Vec<VeilidCircle> = Vec::new();
        let mut my_handle = "guest".to_owned();
        let mut shares = ShareState::new();
        let (evt_tx, mut evt_rx) = unbounded_channel();
        let (cmd_tx, _cmd_rx) = unbounded_channel::<NetCommand>();
        let (fetch_outcome_tx, _fetch_rx) = unbounded_channel();
        let (confirm_outcome_tx, _confirm_rx) = unbounded_channel::<ConfirmOutcome>();

        handle_command(
            NetCommand::PublishShare {
                root: dir.path().to_path_buf(),
                name: "demo".to_owned(),
                sharer_handle: "tester".to_owned(),
            },
            &evt_tx,
            &cmd_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
            &fetch_outcome_tx,
            &confirm_outcome_tx,
        )
        .await;

        match evt_rx.try_recv() {
            Ok(NetEvent::PublishError { message }) => {
                assert!(
                    message.contains("not connected"),
                    "expected a not-connected publish error, got: {message}"
                );
            }
            other => panic!("expected PublishError, got {other:?}"),
        }
    }

    /// #195 (CRSH-ISC-28): a mid-session re-index republishes a root under its SAME
    /// deterministic `share_id`, so the own-share list upserts in place — one entry
    /// per root, never a growing pile of duplicates on repeated Refresh.
    #[test]
    fn upsert_own_share_replaces_same_id_without_duplicating() {
        let mk = |sid: &str, name: &str| OwnShare {
            share_id: sid.to_owned(),
            root_commitment: vec![1, 2, 3],
            name: name.to_owned(),
            rating: String::new(),
            sharer_handle: "tester".to_owned(),
        };
        let mut own: Vec<OwnShare> = Vec::new();

        upsert_own_share(&mut own, mk("sid-1", "v1"));
        assert_eq!(own.len(), 1);

        // Re-index of the SAME root (same share_id) with a refreshed manifest/name.
        upsert_own_share(&mut own, mk("sid-1", "v2"));
        assert_eq!(own.len(), 1, "same share_id must not duplicate");
        assert_eq!(own[0].name, "v2", "the re-index replaces in place");

        // A genuinely different share keeps its own slot.
        upsert_own_share(&mut own, mk("sid-2", "other"));
        assert_eq!(own.len(), 2);
    }

    /// A-c: `RefreshPublicSpace` with no operator record subscribed (not connected)
    /// reports a clean `PublicSpaceError` rather than panicking or silently dropping.
    #[tokio::test]
    async fn refresh_public_space_without_a_connection_reports_a_clean_error() {
        let mut net: Option<VeilidNetHandle> = None;
        let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
        let mut circles: Vec<VeilidCircle> = Vec::new();
        let mut my_handle = "guest".to_owned();
        let mut shares = ShareState::new(); // operator = None
        let (evt_tx, mut evt_rx) = unbounded_channel();
        let (cmd_tx, _cmd_rx) = unbounded_channel::<NetCommand>();
        let (fetch_outcome_tx, _fetch_rx) = unbounded_channel();
        let (confirm_outcome_tx, _confirm_rx) = unbounded_channel::<ConfirmOutcome>();

        handle_command(
            NetCommand::RefreshPublicSpace,
            &evt_tx,
            &cmd_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
            &fetch_outcome_tx,
            &confirm_outcome_tx,
        )
        .await;

        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::PublicSpaceError { message }) if message.contains("not connected")
        ));
    }

    /// A-c: `SetMotd` dispatched with no operator record subscribed (not connected)
    /// reports a clean `PublicSpaceError` — guards the command dispatch + the
    /// not-subscribed guard so a click before subscribe can never `unwrap`-panic the
    /// actor task (which would tear down all Veilid connectivity).
    #[tokio::test]
    async fn set_motd_without_a_connection_reports_a_clean_error() {
        let mut net: Option<VeilidNetHandle> = None;
        let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
        let mut circles: Vec<VeilidCircle> = Vec::new();
        let mut my_handle = "guest".to_owned();
        let mut shares = ShareState::new();
        let (evt_tx, mut evt_rx) = unbounded_channel();
        let (cmd_tx, _cmd_rx) = unbounded_channel::<NetCommand>();
        let (fetch_outcome_tx, _fetch_rx) = unbounded_channel();
        let (confirm_outcome_tx, _confirm_rx) = unbounded_channel::<ConfirmOutcome>();
        handle_command(
            NetCommand::SetMotd {
                text: "hello".to_owned(),
            },
            &evt_tx,
            &cmd_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
            &fetch_outcome_tx,
            &confirm_outcome_tx,
        )
        .await;
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::PublicSpaceError { message }) if message.contains("not connected")
        ));
    }

    /// A-c: `UploadAnnouncement` dispatched with no operator record subscribed reports
    /// a clean `PublicSpaceError` rather than panicking.
    #[tokio::test]
    async fn upload_announcement_without_a_connection_reports_a_clean_error() {
        let mut net: Option<VeilidNetHandle> = None;
        let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
        let mut circles: Vec<VeilidCircle> = Vec::new();
        let mut my_handle = "guest".to_owned();
        let mut shares = ShareState::new();
        let (evt_tx, mut evt_rx) = unbounded_channel();
        let (cmd_tx, _cmd_rx) = unbounded_channel::<NetCommand>();
        let (fetch_outcome_tx, _fetch_rx) = unbounded_channel();
        let (confirm_outcome_tx, _confirm_rx) = unbounded_channel::<ConfirmOutcome>();
        handle_command(
            NetCommand::UploadAnnouncement {
                topic: "t".to_owned(),
                body: "b".to_owned(),
            },
            &evt_tx,
            &cmd_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
            &fetch_outcome_tx,
            &confirm_outcome_tx,
        )
        .await;
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::PublicSpaceError { message }) if message.contains("not connected")
        ));
    }

    // ── Operator announcements / MOTD (Phase 4 A-c) ──────────────────────

    fn operator_space() -> OperatorSpace {
        OperatorSpace {
            announce_owner_seed: [0u8; 32],
            motd: None,
            posts: BTreeMap::new(),
        }
    }

    #[test]
    fn collect_operator_keepalive_items_excludes_the_mutable_motd() {
        let _ = oxicrypt_module::initialize();
        // No operator record → nothing to re-publish.
        assert!(collect_operator_keepalive_items(&ShareState::new()).is_none());
        // Operator subscribed but empty → still None.
        let mut shares = ShareState::new();
        shares.operator = Some(operator_space());
        assert!(collect_operator_keepalive_items(&shares).is_none());
        let kp = dev_project_release_keypair().unwrap();
        let (evt_tx, _rx) = unbounded_channel();
        // #141: a MOTD alone is NOT kept alive — the mutable "motd" slot has no
        // newer-wins, so re-publishing a stale one could revert a newer MOTD
        // network-wide. A MOTD-only operator therefore has nothing safe to refresh.
        let motd = sign_motd(&kp, "hello", 100).unwrap();
        let motd_bytes = encode_operator_item(OPERATOR_ITEM_MOTD, &motd.encode_to_vec());
        assert!(apply_operator_item(&mut shares, &evt_tx, &motd_bytes));
        assert!(
            collect_operator_keepalive_items(&shares).is_none(),
            "a MOTD-only operator has nothing safe to keep alive"
        );
        // An announcement (content-addressed → idempotent under re-publish) IS kept alive.
        let post_artifact = sign_post(&kp, "release", "v0.33.0 is out", 200).unwrap();
        let addr = content_address(&post_artifact.signed_payload).unwrap();
        let post = wire::Post {
            artifact: Some(post_artifact),
            content_address: addr.as_bytes().to_vec(),
        };
        let post_bytes = encode_operator_item(OPERATOR_ITEM_ANNOUNCEMENT, &post.encode_to_vec());
        assert!(apply_operator_item(&mut shares, &evt_tx, &post_bytes));
        let (seed, items) = collect_operator_keepalive_items(&shares)
            .expect("the announcement should be collected");
        assert_eq!(seed, shares.operator.as_ref().unwrap().announce_owner_seed);
        assert_eq!(items.len(), 1, "only the announcement, never the MOTD");
        assert_eq!(items[0].0, hex::encode(&post.content_address));
        assert_eq!(
            decode_operator_item(&items[0].1).unwrap().0,
            OPERATOR_ITEM_ANNOUNCEMENT
        );
    }

    /// `refresh_public_space` re-renders the current operator content as a plain
    /// `PublicSpaceSnapshot`. (The #93 connect-time landing signal was removed in #142 in
    /// favour of the #142 unread dot, so every refresh is an equal re-render — there is
    /// no longer a one-shot "landing" snapshot.)
    #[tokio::test]
    async fn refresh_public_space_emits_a_snapshot() {
        let mut shares = ShareState::new();
        shares.operator = Some(operator_space());
        let net: Option<VeilidNetHandle> = None; // already subscribed → no re-subscribe
        let (evt_tx, mut evt_rx) = unbounded_channel();

        refresh_public_space(&mut shares, &evt_tx, &net).await;
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::PublicSpaceSnapshot { .. })
        ));
    }

    /// #77: a verified, fresh, non-own circle beacon (sealed under the circle's
    /// `cot_key`) folds into THAT circle's roster and pushes a `Roster` tagged with
    /// its `circle_id` — the per-circle mirror of the lobby presence path.
    #[test]
    fn circle_heartbeat_folds_into_the_owning_circles_roster() {
        let _ = oxicrypt_module::initialize();
        let phrase = "a shared circle passphrase for presence #77";
        let cot_key = derive_cot_key(phrase, &CNSA_2_0).unwrap();
        // A DISTINCT member (not us): shares.signing is None below, so the own-filter
        // is a no-op and this beacon is a genuine "other member" row.
        let member = announcer(77);
        let label = default_circle_label(&circle_fingerprint(&cot_key));
        let fields = HeartbeatFields {
            room: &label,
            sender_handle: "otter#aabbccddeeff",
            sent_unix_ms: now_unix_ms(),
            live_share_ids: &[],
            is_leave: false,
        };
        let sealed = seal_circle_heartbeat(&cot_key, &member, &fields).unwrap();

        let mut circles = vec![VeilidCircle {
            circle_id: 42,
            cot_key: derive_cot_key(phrase, &CNSA_2_0).unwrap(),
            owner_seed: [0u8; 32],
            presence_owner_seed: [0u8; 32],
            presence: PresenceTracker::for_room(DEFAULT_ROOM, PRESENCE_TTL),
        }];
        let mut shares = ShareState::new(); // signing None → own-filter no-op
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &mut circles,
            &mut shares,
        );
        assert_eq!(
            circles[0].presence.len(),
            1,
            "the beacon folded into the circle"
        );
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::Roster { circle_id: Some(42), entries }) if entries.len() == 1
        ));
    }

    /// The operator-item envelope round-trips through the 1-byte KIND tag, and a
    /// buffer with no tag byte is rejected (not an operator item).
    #[test]
    fn operator_item_envelope_round_trips_and_rejects_empty() {
        let payload: &[u8] = b"prost-bytes-here";
        let framed = encode_operator_item(OPERATOR_ITEM_ANNOUNCEMENT, payload);
        assert_eq!(
            decode_operator_item(&framed),
            Some((OPERATOR_ITEM_ANNOUNCEMENT, payload))
        );
        // A zero-length payload still carries its tag byte.
        let motd = encode_operator_item(OPERATOR_ITEM_MOTD, b"");
        assert_eq!(
            decode_operator_item(&motd),
            Some((OPERATOR_ITEM_MOTD, b"".as_slice()))
        );
        // An empty buffer has no tag byte → not an operator item.
        assert_eq!(decode_operator_item(&[]), None);
    }

    /// A verified F17-signed MOTD folds into `OperatorSpace` and pushes a
    /// `PublicSpaceSnapshot`; an EMPTY whitelist authorizes the F17 signer (A0), so no
    /// whitelist distribution is needed, and `can_compose` is the dev possession gate.
    #[test]
    fn apply_operator_item_folds_a_verified_f17_motd() {
        let _ = oxicrypt_module::initialize();
        let kp = dev_project_release_keypair().unwrap();
        let artifact = sign_motd(&kp, "Welcome to daemonseed", 100).unwrap();
        let bytes = encode_operator_item(OPERATOR_ITEM_MOTD, &artifact.encode_to_vec());

        let mut shares = ShareState::new();
        shares.operator = Some(operator_space());
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_operator_item(&mut shares, &evt_tx, &bytes));
        assert!(shares.operator.as_ref().unwrap().motd.is_some());
        match evt_rx.try_recv() {
            Ok(NetEvent::PublicSpaceSnapshot { view, can_compose }) => {
                assert_eq!(view.motd.as_deref(), Some("Welcome to daemonseed"));
                assert!(can_compose, "dev-possession gate is open");
            }
            other => panic!("expected a PublicSpaceSnapshot, got {other:?}"),
        }
    }

    /// A verified F17-signed announcement folds in, keyed by its content-address slot,
    /// and appears in the projected view's posts.
    #[test]
    fn apply_operator_item_folds_a_verified_f17_announcement() {
        let _ = oxicrypt_module::initialize();
        let kp = dev_project_release_keypair().unwrap();
        let artifact = sign_post(&kp, "release", "v0.33.0 is out", 200).unwrap();
        let addr = content_address(&artifact.signed_payload).unwrap();
        let post = wire::Post {
            artifact: Some(artifact),
            content_address: addr.as_bytes().to_vec(),
        };
        let bytes = encode_operator_item(OPERATOR_ITEM_ANNOUNCEMENT, &post.encode_to_vec());

        let mut shares = ShareState::new();
        shares.operator = Some(operator_space());
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_operator_item(&mut shares, &evt_tx, &bytes));
        assert_eq!(shares.operator.as_ref().unwrap().posts.len(), 1);
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::PublicSpaceSnapshot { view, .. }) if view.posts.len() == 1
        ));
    }

    /// Bytes arriving with no operator record subscribed are not consumed (they fall
    /// through to the caller's other interpretations / the unrecognized trace).
    #[test]
    fn apply_operator_item_ignores_bytes_when_operator_unsubscribed() {
        let mut shares = ShareState::new(); // operator = None
        let (evt_tx, _rx) = unbounded_channel();
        assert!(!apply_operator_item(&mut shares, &evt_tx, b"\x00garbage"));
    }

    /// A verified inbound lobby chat message (sealed under the public room key by a
    /// peer) surfaces as a `NetEvent::Message` — the Veilid lobby-chat ingest path.
    #[test]
    fn handle_inbound_surfaces_a_verified_lobby_chat_message() {
        let signer = announcer(31);
        let mut shares = ShareState::new();
        shares.lobby = Some(lobby());
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sealed = seal_room_message(
            &room_key,
            &signer,
            DEFAULT_ROOM,
            "river-otter#aabbccddeeff",
            "hello lobby",
            42,
        )
        .unwrap();
        // No signing key in `shares` → own_pubkey is None → nothing is `mine`.
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &mut [],
            &mut shares,
        );
        // `who` is now bound to the signer's pubkey (ISC-C4/C57): the self-asserted
        // "river-otter#aabbccddeeff" whose hash disagrees is shown at its `#<prefix>`
        // floor, never under the spoofed name.
        let expected_who =
            Handle::display_bound("river-otter#aabbccddeeff", signer.public_key().as_slice())
                .unwrap()
                .format(DisplayMode::Default);
        match evt_rx.try_recv() {
            Ok(NetEvent::Message {
                who,
                text,
                mine,
                sent_unix_ms,
            }) => {
                assert_eq!(who, expected_who);
                assert_eq!(text, "hello lobby");
                assert!(!mine, "a peer's message is not ours");
                assert_eq!(sent_unix_ms, 42, "#126: the wire timestamp is plumbed");
            }
            other => panic!("expected a lobby Message, got {other:?}"),
        }
    }

    /// #165: a replayed OLD chat write must not fold into presence (it would let an
    /// untrusted relay indefinitely re-freshen a departed member's roster liveness).
    /// A fresh chat write folds; a stale one (outside the beacon-freshness window) is
    /// still delivered as a message but leaves the roster untouched.
    #[test]
    fn issue_165_stale_chat_write_does_not_refresh_presence() {
        let signer = announcer(31);
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let now = now_unix_ms();

        // A fresh same-room chat write folds the sender into presence (WB-ISC-4).
        let mut shares = ShareState::new();
        shares.lobby = Some(lobby());
        let fresh = seal_room_message(
            &room_key,
            &signer,
            DEFAULT_ROOM,
            "otter#aabbccddeeff",
            "hi",
            now,
        )
        .unwrap();
        let (evt_tx, _rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: fresh },
            &evt_tx,
            &mut [],
            &mut shares,
        );
        assert_eq!(
            shares.lobby.as_ref().unwrap().presence.members().len(),
            1,
            "a fresh chat write folds the sender into presence"
        );

        // A stale/replayed chat write (600s old, outside the freshness window) is still
        // delivered as a message but must NOT fold into presence.
        let mut shares2 = ShareState::new();
        shares2.lobby = Some(lobby());
        let stale_ts = now.saturating_sub(600_000);
        let stale = seal_room_message(
            &room_key,
            &signer,
            DEFAULT_ROOM,
            "otter#aabbccddeeff",
            "replayed",
            stale_ts,
        )
        .unwrap();
        let (evt_tx2, mut rx2) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: stale },
            &evt_tx2,
            &mut [],
            &mut shares2,
        );
        assert!(
            matches!(rx2.try_recv(), Ok(NetEvent::Message { .. })),
            "the stale message is still delivered"
        );
        assert_eq!(
            shares2.lobby.as_ref().unwrap().presence.members().len(),
            0,
            "a stale/replayed chat write must not fold into presence (#165)"
        );
    }

    /// Our own lobby message re-surfaces via the DHT sweep; it is emitted `mine:true`
    /// (dedup against the echo lives in `push_message`), and on a cold-start backlog
    /// with no echo it renders once (#143).
    #[test]
    fn handle_inbound_emits_our_own_looped_back_lobby_message_as_mine() {
        let me = Arc::new(announcer(32));
        let my_handle = "me#aabbccddeeff";
        let mut shares = ShareState::new();
        shares.lobby = Some(lobby());
        // #143: `mine` keys on the STABLE pubkey — set our signing key so the
        // looped-back own message is recognised regardless of the display handle.
        shares.signing = Some(Arc::clone(&me));
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sealed = seal_room_message(
            &room_key,
            me.as_ref(),
            DEFAULT_ROOM,
            my_handle,
            "my own line",
            7,
        )
        .unwrap();
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &mut [],
            &mut shares,
        );
        // #143: an own looped-back message is now EMITTED as `mine:true` (not
        // suppressed) — dedup against the optimistic local echo happens in
        // `push_message`; the cold-start backlog (no echo) renders it once.
        let ev = evt_rx
            .try_recv()
            .expect("own looped-back lobby message must now be emitted");
        let NetEvent::Message {
            who, text, mine, ..
        } = ev
        else {
            panic!("expected a lobby Message event for the own looped-back line");
        };
        let expected_who = Handle::display_bound(my_handle, me.public_key().as_slice())
            .unwrap()
            .format(DisplayMode::Default);
        assert_eq!(who, expected_who);
        assert_eq!(text, "my own line");
        assert!(
            mine,
            "own message must be flagged mine:true (keyed on pubkey)"
        );
    }

    /// #155: for a nameless/floor identity the sender's own-echo `who` must equal
    /// the DHT re-surface `who` so `push_message` dedups it. The re-surface floors
    /// to `#<hex>` via `display_bound(...).format(Default)`; the pre-fix echo used
    /// `my_handle.split('#').next()`, which yields `""` for a `#<hex>` handle — so
    /// the echo (`""`) and re-surface (`#<hex>`) `who` mismatched and the own
    /// message rendered twice. After the fix both floor identically.
    #[test]
    fn floor_identity_own_echo_who_matches_resurface() {
        let me = announcer(41);
        let pubkey = me.public_key().as_slice();
        // A nameless identity transmits the canonical floor handle `#<hex>`.
        let wire = crate::net::canonical_wire_handle("", pubkey);
        assert!(
            wire.starts_with('#'),
            "a nameless identity floors on the wire: {wire:?}"
        );
        // The re-surface `who` (veilid_net inbound path, 2186/2237).
        let resurface_who = Handle::display_bound(&wire, pubkey)
            .unwrap()
            .format(DisplayMode::Default);
        // The FIXED echo `who` — same wire handle + pubkey, so identical.
        let echo_who = Handle::display_bound(&wire, pubkey)
            .map(|b| b.format(DisplayMode::Default))
            .unwrap_or_else(|_| wire.clone());
        assert_eq!(
            echo_who, resurface_who,
            "#155: the echo `who` must equal the re-surface `who`"
        );
        assert!(
            !echo_who.is_empty() && echo_who.starts_with('#'),
            "a floor identity's `who` is `#<hex>`, never empty: {echo_who:?}"
        );
        // Regression witness: the pre-fix computation collapsed a `#<hex>` handle to "".
        let pre_fix = wire.split('#').next().unwrap_or(&wire).to_owned();
        assert_eq!(
            pre_fix, "",
            "pre-#155: split('#').next() on a floor handle gave \"\""
        );
        assert_ne!(
            pre_fix, resurface_who,
            "pre-#155: echo \"\" != re-surface `#<hex>` → the double-render"
        );
    }

    /// `SendRoom` with no lobby subscribed reports a clean error rather than
    /// panicking or silently dropping.
    #[tokio::test]
    async fn send_room_without_a_lobby_reports_a_clean_error() {
        let mut net: Option<VeilidNetHandle> = None;
        let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
        let mut circles: Vec<VeilidCircle> = Vec::new();
        let mut my_handle = "guest".to_owned();
        let mut shares = ShareState::new(); // lobby = None
        let (evt_tx, mut evt_rx) = unbounded_channel();
        let (cmd_tx, _cmd_rx) = unbounded_channel::<NetCommand>();
        let (fetch_outcome_tx, _fetch_rx) = unbounded_channel();
        let (confirm_outcome_tx, _confirm_rx) = unbounded_channel::<ConfirmOutcome>();
        handle_command(
            NetCommand::SendRoom {
                text: "hi".to_owned(),
            },
            &evt_tx,
            &cmd_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
            &fetch_outcome_tx,
            &confirm_outcome_tx,
        )
        .await;
        match evt_rx.try_recv() {
            Ok(NetEvent::Error { reason }) => {
                assert!(reason.contains("no public room"), "got: {reason}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// #113 oracle: chunk fetches run with bounded concurrency and reassemble in
    /// manifest order. A counting fake fetcher records the peak in-flight count; the
    /// helper must run more than one at once, never exceed the cap, and return the
    /// chunks in addr order (byte-for-byte reassembly).
    #[tokio::test]
    async fn fetch_chunks_ordered_runs_bounded_concurrent_and_reassembles_in_order() {
        use daemonseed_core::storage::cas::CHUNK_ADDR_LEN;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let addrs: Vec<ChunkAddr> = (0..20u8)
            .map(|i| ChunkAddr::from_bytes([i; CHUNK_ADDR_LEN]))
            .collect();
        let cap = CHUNK_FETCH_CONCURRENCY;
        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let chunks = fetch_chunks_ordered(
            &addrs,
            cap,
            |addr| {
                let inflight = inflight.clone();
                let peak = peak.clone();
                async move {
                    let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    // Park so other fetches enter before this one resolves — makes
                    // genuine concurrency (not mere interleaving) observable.
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    inflight.fetch_sub(1, Ordering::SeqCst);
                    // The chunk "content" encodes its addr's first byte so the
                    // returned order is checkable.
                    Ok(vec![addr.as_bytes()[0]])
                }
            },
            |_data| {},
        )
        .await
        .expect("all fake fetches succeed");

        let order: Vec<u8> = chunks.iter().map(|c| c[0]).collect();
        assert_eq!(
            order,
            (0..20u8).collect::<Vec<_>>(),
            "chunks reassemble in manifest (addr) order"
        );
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak > 1, "fetches ran concurrently (peak {peak})");
        assert!(
            peak <= cap,
            "concurrency stayed bounded (peak {peak} <= cap {cap})"
        );
    }
}
