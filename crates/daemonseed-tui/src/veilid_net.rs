//! Veilid-backed net actor (#98 S2 + Phase 3 Slice 2b) — the only transport.
//!
//! It implements the `NetCommand` / `NetEvent` contract defined in [`crate::net`],
//! which [`crate::net::NetHandle::new`] spawns unconditionally.
//! Backed by [`daemonseed_veilid_net::VeilidNetHandle`]. This is the TUI mirror
//! of `daemonseed-gui`'s `veilid_net` module, adapted to the TUI's command
//! surface (the GUI and TUI `NetCommand`/`NetEvent` enums diverge — see below).
//!
//! **Circles, public shares + lobby chat today.** `Connect` (attach + lobby
//! subscribe), `JoinCircle`, `SendChat`, the inbound circle path, the public-share
//! publish / discover / fetch path (Phase 3 Slice 2b), and public-room (Lobby) chat
//! (`SendPublicRoom`) are live; presence, MOTD and announcements return the
//! matching per-surface error event carrying `"not yet on Veilid"` until Phase 4.
//! This is a degraded-but-honest dev/test mode, NOT a dual transport — it honors the
//! no-relay↔Veilid-interop clean cut (one transport at a time).
//!
//! **TUI surface differences from the GUI mirror.** The TUI `NetCommand` carries
//! the sender's display handle *per message* (`SendChat { sender_handle, .. }`)
//! rather than once at `Connect`, and the TUI `NetEvent::ChatMessage` has no
//! `mine` flag (the relay path renders own messages by comparing `sender` to the
//! user's handle at the UI layer). The TUI also assigns the per-session
//! `circle_id` at join and returns it on `CircleJoined { circle_id, label,
//! entropy }`, so this actor owns the id counter and derives the client-local
//! label ([`daemonseed_core::circle::default_circle_label`]).
//!
//! On the share surface the TUI contract is RICHER than the GUI's: there is no
//! single `Error`/`SharesSnapshot { shares }` — instead per-surface error events
//! (`PublishError { root }`, `FetchError`, `SharesError`), a three-field
//! `SharesSnapshot { local, remote, indexer_status }`, and a separate browse
//! pane fed by `ListFetched` → `FetchedShares` persisted in a `downloads.idx`
//! ([`daemonseed_core::storage::fetched::FetchedStore`]). So while the GUI veilid
//! actor writes fetched bytes straight to disk and emits only `FetchComplete`,
//! this actor mirrors the RELAY's share handlers — `FetchedStore` persistence,
//! `downloads.idx`, the `remote`-only `SharesSnapshot` (own shares ride
//! `PublishStarted`, never the snapshot) — while sourcing every byte over the
//! same Veilid transport calls the GUI mirror proved.
//!
//! **No actor echo; suppress the DHT re-surface.** The TUI app layer already
//! local-echoes a composed line on Enter (its `App` Enter handler) — unlike the
//! GUI, whose actor's `mine:true` echo is the *only* render path. So this actor
//! must NOT echo (that would double-render every own message). What it must do is
//! drop the member's OWN write when Veilid's circle watch re-surfaces it tens of
//! seconds later: the inbound path suppresses it by sender-handle match (the
//! handle is learned from each `SendChat`, `None` until then).
//!
//! **Single encryption layer.** Content is sealed under the circle `cot_key` /
//! the public-room `PublicRoomKey` exactly as on the relay (`seal_message` /
//! `seal_public_announcement`); the Veilid DHT stores those opaque bytes
//! verbatim. This actor never touches Veilid's transport crypto.
//!
//! **Public-share discovery + anti-swap (Phase 3 Slice 2b).** A share is
//! announced by publishing a [`daemonseed_veilid_net::DiscoveryEnvelope`] onto the
//! world-derivable lobby rendezvous: a sealed `ShareAnnouncement` (signed by the
//! sharer's stable identity), the sharer's Veilid private-route blob, and an
//! ML-DSA-87 signature binding `share_id ‖ route_blob`. A fetcher
//! `open_announcement`s the item (provenance → announcer pubkey + share_id), THEN
//! [`verify_route_advert`](daemonseed_veilid_net::verify_route_advert)s the route
//! against that pubkey before importing it — a man-in-the-middle on the
//! world-writable lobby record cannot redirect a fetch onto a rogue route. Content
//! chunks are SHA-384-verified inside `fetch_chunk` (ISC-S28).
//!
//! **Least-authority signing.** veilid-net never holds the identity key. The actor
//! keeps the stable [`SignKeypair`] behind an `Arc` (it is `!Clone`) to seal
//! announcements, and hands veilid-net only an `Arc<dyn RouteAdvertSigner>`
//! ([`IdentityRouteAdvertSigner`]) scoped to route adverts.
//!
//! **Inbound demux.** `VeilidNetEvent::Inbound` carries only sealed bytes (no
//! record tag), so a received blob is tried against each joined circle's `cot_key`
//! (the AEAD seal authenticates the match), then as a lobby chat message
//! (`open_room_message` under the lobby `PublicRoomKey`), then as a lobby
//! `DiscoveryEnvelope` (share discovery). The distinct per-kind AAD means only the
//! matching open succeeds; own lobby messages are suppressed by handle (the app
//! already echoed them on Enter).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_cli::route_signer::IdentityRouteAdvertSigner;
use daemonseed_core::browse_retry::{ParkedBrowseRetry, ParkedRetryAction, parked_retry_action};
use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::{CircleKey, derive_circle_veilid_owner_seed, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::heartbeat::{HeartbeatFields, open_heartbeat, seal_public_heartbeat};
use daemonseed_core::identity::keys::{Identity, ShareRootIkm, SignKeypair, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::presence::{
    PRESENCE_TTL, PresenceTracker, ReapGate, beacon_is_fresh, next_keepalive_interval,
};
use daemonseed_core::public_room::{
    DEFAULT_ROOM, PublicRoomKey, derive_room_key, derive_room_presence_veilid_owner_seed,
    derive_room_share_veilid_owner_seed, derive_room_veilid_owner_seed, open_room_message,
    seal_room_message,
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
use daemonseed_core::share_envelope::ManifestEntry;
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::ChunkAddr;
use daemonseed_core::storage::fetched::{
    FetchedFile, FetchedStore, LiveFetchRegistry, SelectionRoot, StagingArea, derive_resume_state,
    manifest_digest, place_at_dest, sweep_staging, verify_stored_manifest,
};
use daemonseed_core::storage::manifest_digest::ManifestDigestStore;
use daemonseed_veilid_net::download::{DownloadOutcome, PlannedFile, run_download};
use daemonseed_veilid_net::{
    DiscoveryEnvelope, FetchErrorClass, PresenceBoundary, RecordKey, RouteBudget, RouteId,
    SharerKey, VeilidNet, VeilidNetConfig, VeilidNetError, VeilidNetEvent, VeilidNetHandle,
    next_resweep_seed, verify_route_advert,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::app::IndexerStatus;
use crate::net::{NetCommand, NetEvent, RootKind, ShareManifestEntry, resolve_share_folder};

/// Reported for [`NetEvent::Connected::version`]: the Veilid transport carries
/// no negotiated wire version (unlike the relay's APP_HELLO handshake), so we
/// report the Veilid-era major.minor for the UI's status line.
const VEILID_WIRE_VERSION: &str = "2.0";

/// The honest answer for every user-facing surface not yet on Veilid (Phase 4).
const NOT_YET: &str = "not yet on Veilid";

/// How long a discovered share lives in the catalog without a fresh announce —
/// mirrors the relay actor's `SHARE_CATALOG_TTL`.
const SHARE_CATALOG_TTL: Duration = Duration::from_secs(600);

/// How often the recipient ages out shares it has not reheard within the TTL
/// (mirrors the GUI Veilid actor's prune tick).
const SHARE_CATALOG_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// A joined circle's local state: the per-session routing id, the content key
/// (for seal/open), the shared rendezvous-owner seed (for publish/subscribe),
/// and the client-local display label.
struct VeilidCircle {
    circle_id: u64,
    cot_key: CircleKey,
    owner_seed: [u8; 32],
    label: String,
}

/// The subscribed lobby / public-room rendezvous: the world-derivable
/// `PublicRoomKey` (seals/opens announcements) and the rendezvous-owner seed
/// (publishes onto + subscribes to the lobby record). Both derive from the public
/// room name + suite, so every node computes the same lobby (an open rendezvous).
struct LobbyRendezvous {
    room_key: PublicRoomKey,
    owner_seed: [u8; 32],
    /// The **share-discovery** sibling record's owner seed (#153: share adverts ride
    /// their OWN world-derivable record, never the chat rendezvous, so a share advert
    /// can never silently overwrite the chat append-ring — and vice versa).
    /// Publishes/subscribes public-share adverts.
    share_owner_seed: [u8; 32],
    /// The **presence** sibling record's owner seed (P1: presence rides its OWN
    /// world-derivable record, never the chat rendezvous). Publishes/subscribes
    /// lobby member beacons.
    presence_owner_seed: [u8; 32],
    /// Receiver-side liveness view for the lobby (#74). Verified, fresh, non-own
    /// beacons fold in via [`PresenceTracker::apply`]; the heartbeat timer reaps it.
    /// Maintained for symmetry with the GUI + #77/roster; the TUI does not yet
    /// render a roster (it applies/reaps like the relay TUI). Live-only.
    presence: PresenceTracker,
}

/// A discovered share's anti-swap-verified route: the sharer's opaque Veilid
/// private-route blob, kept so a fetch can `import_route` it.
struct DiscoveredRoute {
    route_blob: Vec<u8>,
    /// (#156 / download-subsystem redesign, step 6) The verified announcer pubkey
    /// this share's route was authenticated against (the accepted announcement's
    /// `sender_pubkey`), copied out at fetch time as the [`SharerKey`] the per-route
    /// budget keys its learned ceiling by — so a route rotation (fresh `RouteId`,
    /// same sharer) does not discard the protective backoff memory (DL-ISC-2).
    sender_pubkey: Vec<u8>,
    /// (#180 §RS-1.4) A strictly-increasing generation stamped on every accepted advert
    /// fold for this share (from [`ShareState::next_generation`]). A parked browse retry
    /// captures this at fetch-fail time; a later fold bumps it strictly above the parked
    /// value, the retry's fire signal (CRSH-ISC-6/19).
    generation: u64,
    /// (#180 §RS-1.4) `true` once a fetch of this share failed and it is **re-resolving**:
    /// the share stays listed (never pruned on a fetch failure, CRSH-ISC-5) with a parked
    /// one-shot retry. Cleared by a successful fetch; preserved across a fresh advert fold.
    unresolved: bool,
}

/// A share this node published this session — enough to post a
/// provenance-matching withdraw on unpublish (the in-band replacement for the
/// relay registry's owner-scoped record).
#[derive(Clone)]
struct OwnShare {
    share_id: String,
    /// (#156) The receiver-verifiable root commitment, so a withdraw carries the
    /// SAME commitment the id derives from (else a receiver's binding check drops it).
    root_commitment: Vec<u8>,
    name: String,
    rating: String,
    sharer_handle: String,
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
    /// (#156) The stable identity's share-root IKM, behind an `Arc` (secret bytes),
    /// so a publish derives a receiver-verifiable `share_id`. `None` until Connect.
    share_root_ikm: Option<Arc<ShareRootIkm>>,
    lobby: Option<LobbyRendezvous>,
    catalog: ShareCatalog,
    discovered: HashMap<String, DiscoveredRoute>,
    /// (#180 §RS-1.4) Monotonic generation counter, stamped onto a [`DiscoveredRoute`] on
    /// every accepted advert fold, so a parked browse retry can detect a fresh advert and
    /// a withdraw/re-add never reuses a stale generation (CRSH-ISC-6/19).
    next_generation: u64,
    /// (#180 §RS-1.4) Parked one-shot browse retries, keyed by `share_id`. A fetch failure
    /// marks the share `Unresolved` and parks a retry here (local only, no network); it
    /// fires at the next cursor tick after a fresh advert folds (CRSH-ISC-6/15), or clears
    /// on window expiry / withdraw (CRSH-ISC-19) — never a prune.
    parked_retries: HashMap<String, ParkedBrowseRetry>,
    /// Shares published this session — held ONLY to post a matching withdraw on
    /// unpublish. Unlike the GUI mirror, own shares are NOT folded into the
    /// `SharesSnapshot` (the relay's `remote` rows are the discovered catalog
    /// alone; the publisher's own list rides `PublishStarted`/`PublishStopped`).
    own: Vec<OwnShare>,
    /// The reap-suspension gate (WB-5.1 / I5″.6/.7): folds the scheduler's published
    /// median DHT-weather (hysteresis band + resume grace) into "suspend reaping now".
    /// Persists across reap ticks.
    reap_gate: ReapGate,
    /// Last-emitted "presence may be stale" signal (WB-ISC-20), so a
    /// `NetEvent::PresenceStale` is emitted only on a change.
    prev_presence_stale: bool,
    /// (#180 §RS-3, CRSH-ISC-10) The in-use guard over each discovered share's last-imported
    /// private route: defers a superseded route's release until no in-flight fetch is still
    /// streaming over it. Fed by fetch spawn/finish and advert-replacement folds; the actor
    /// loop drains `pending_route_releases` through the net handle.
    route_guard: ImportedRouteGuard<String, RouteId>,
    /// (#180 §RS-3) Imported routes the guard has cleared for release, drained and released
    /// (spawned) by the actor loop each iteration.
    pending_route_releases: Vec<RouteId>,
    /// (download-subsystem redesign, step 6, Part 1) The ONE session-lifetime per-route
    /// concurrency budget every download leases from — the learned-ceiling map is
    /// session-scoped by design, so this is held here (not per-download) and shared with
    /// each spawned worker via a cheap `Arc` clone.
    budget: Arc<RouteBudget<RouteId>>,
    /// (download-subsystem redesign, step 6, Part 3) In-flight/resuming fetches, so a future
    /// startup/idle staging sweep never reclaims a live download's staging. Cheap to clone;
    /// each worker holds a registration guard for its lifetime.
    live_fetches: LiveFetchRegistry,
    /// (download-subsystem redesign, step 6 / DL-ISC-13) Shares flagged after an integrity
    /// failure (`share_id`). Durable within the session, independent of the discovery
    /// lifecycle — set by the `IntegrityFailed` fold. Per-chunk SHA-384 verification
    /// (ISC-A-S20) is the always-on enforcement; this flag is the UX guard that a user
    /// re-download of a poisoned share is warned about.
    poisoned_shares: HashSet<String>,
    /// (download-subsystem redesign, step 8b-2 / DL-ISC-20) The unlocked profile's
    /// on-disk root — the client's own trusted state dir, set at `Connect`. A
    /// verified resume anchors each fetch's confirmed-manifest digest in a
    /// [`ManifestDigestStore`] under this dir (NOT the co-resident-writable downloads
    /// root). `None` on the no-profile path — that session persists no resume anchor,
    /// so a download simply re-fetches fresh on a later attempt.
    profile_root: Option<PathBuf>,
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
            reap_gate: ReapGate::new(),
            prev_presence_stale: false,
            route_guard: ImportedRouteGuard::new(),
            pending_route_releases: Vec::new(),
            budget: Arc::new(RouteBudget::new()),
            live_fetches: LiveFetchRegistry::new(),
            poisoned_shares: HashSet::new(),
            profile_root: None,
        }
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
/// #157 (generalized, felt-test 2026-07-10): the steady-state resweep tick. The passive
/// DHT watch is lossy — a chat message or share advert written after the login sweep gets
/// no reliable ValueChange, so it never re-surfaces at a peer that has already settled.
/// WB-4 sanctions a reader-side resweep as the fix. On each tick ONE record from the
/// current subscribed chat/discovery set is re-swept, round-robin, so the instantaneous
/// read burst stays one `SUBKEY_COUNT` (64) force-refresh sweep (WB-2 read lane) and the
/// per-record cadence = tick × record-count (scales with room count). Presence records
/// are excluded — they self-heal via keepalive re-writes (WB-4 table). Mirrors the GUI
/// actor; same known limitations (per-record latency vs room count → tail-sweep;
/// continuous read load → stop-on-quiet backoff). Felt-tunable.
const STEADY_RESWEEP_TICK: Duration = Duration::from_secs(15);

/// Hand-off delay past Connect before the steady resweep begins. Unlike the GUI, the TUI
/// has NO stepped warmup re-sweep schedule — only the single connect-time login sweep in
/// `subscribe_lobby` — so this is kept SHORT: just long enough to clear the connect-time
/// subscribe/login-sweep read burst (WB-2), never a 70s dead window in which nothing
/// re-surfaces (review finding). Felt-tunable.
const STEADY_RESWEEP_WARMUP_HANDOFF: Duration = Duration::from_secs(20);

pub async fn veilid_net_actor(
    mut cmd_rx: UnboundedReceiver<NetCommand>,
    _cmd_tx: UnboundedSender<NetCommand>,
    evt_tx: UnboundedSender<NetEvent>,
) {
    let mut net: Option<VeilidNetHandle> = None;
    let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
    let mut circles: Vec<VeilidCircle> = Vec::new();
    let mut shares = ShareState::new();
    // Monotonic id handed out at join — mirrors the relay actor's `next_circle_id`.
    let mut next_circle_id: u64 = 0;
    // Our own display handle, learned from each `SendChat` (the TUI carries the
    // handle per-message). `None` until the first send: used ONLY to suppress the
    // DHT re-surface of our own circle write. Staying `None` pre-send means a
    // genuine inbound from another member is never mistaken for our own, even if
    // they share a default name (the over-suppression hazard); after a real
    // `name#hash` is learned, a collision is identity-derived and astronomically
    // unlikely.
    let mut my_handle: Option<String> = None;
    let mut prune_timer = tokio::time::interval(SHARE_CATALOG_PRUNE_INTERVAL);
    // Presence keepalive + reap clock (WB-1.2): a jittered [180,220]s keepalive into
    // the lobby presence record (when joined) that also reaps the tracker each fire,
    // only in calm (WB-1.10). Self-rescheduling `Sleep` so each tick draws a fresh
    // jittered deadline — no fixed period, no activity coupling (WB-0).
    let heartbeat = tokio::time::sleep(veilid_keepalive_interval());
    tokio::pin!(heartbeat);
    // #157 (generalized): steady-state resweep clock — round-robins ONE subscribed
    // chat/discovery record per tick once the Connect hand-off window closes.
    let mut steady_resweep = tokio::time::interval(STEADY_RESWEEP_TICK);
    steady_resweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut connected_at: Option<Instant> = None;
    let mut resweep_cursor: Option<[u8; 32]> = None;
    // In-flight guard: skip a tick while a prior resweep is still running, so a slow
    // resweep can't overlap the next one (keeps the WB-2 read burst at one sweep).
    let resweep_busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Consumer-route self-heal detection (§RS-1.2, CRSH-ISC-2): per-record session-health
    // tracker keyed by the swept record's key. Each `VeilidNetEvent::SweepHealth` folds in
    // one sweep pass; K consecutive all-failed passes in calm weather flag a record
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
                // #157: anchor the steady-resweep hand-off to each Connect, and reset
                // the round-robin cursor so a reconnect re-sweeps from the top.
                if matches!(cmd, NetCommand::Connect { .. }) {
                    connected_at = Some(Instant::now());
                    resweep_cursor = None;
                }
                handle_command(
                    cmd, &evt_tx, &mut net, &mut ev_rx, &mut circles,
                    &mut next_circle_id, &mut my_handle, &mut shares, &fetch_outcome_tx,
                    &confirm_outcome_tx,
                ).await;
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
                // CRSH-ISC-1/2: fold one completed sweep's per-record outcome into the
                // session-health tracker. Weather is the WB-5.1 estimator, consumed via the
                // shared ReapGate (`suspend_reaping` == elevated) — no new estimator
                // (§RS-1.2). L2 watch state is not yet transport-surfaced, so the L1-only
                // path supplies `Unknown` (§RS-1.3 open question). Everything else demuxes
                // in handle_inbound (which only acts on Inbound).
                if let VeilidNetEvent::SweepHealth { key, outcome } = ev {
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
                    match session_health.observe(key.clone(), input) {
                        RepairDecision::RepairDue => {
                            // Step 3b: re-establish the record's session (§RS-1.2). The
                            // SweepHealth carrying the K-th failed pass IS a cadence
                            // (resweep-completion) tick, so an immediate dispatch here is
                            // still cadence-timed (CRSH-ISC-2). Warmup guard (§RS-1.3): no
                            // repair before the resweep warmup hand-off. One repair in flight
                            // at a time via `resweep_busy`; if busy or still warming, queue
                            // for the next cadence drain (the tracker's latch de-dupes it).
                            let warmed = connected_at
                                .is_some_and(|t| t.elapsed() >= STEADY_RESWEEP_WARMUP_HANDOFF);
                            match record_key_owners.get(&key).copied() {
                                Some(owner_seed) => {
                                    let free = !resweep_busy
                                        .load(std::sync::atomic::Ordering::Acquire);
                                    if let (true, true, Some(handle)) =
                                        (warmed, free, net.as_ref())
                                    {
                                        session_health.note_repair_dispatched(&key);
                                        // (#180 F5, CRSH-ISC-24) Drop any stale enqueued copy
                                        // so the next drain cannot double-dispatch this key.
                                        // Defense-in-depth with the drain re-check.
                                        pending_repairs.retain(|k| k != &key);
                                        spawn_repair(handle, &resweep_busy, owner_seed);
                                        daemonseed_veilid_net::vtrace!(
                                            "tui session-health: repairing dead record \
                                             ({} failed) — re-establishing session",
                                            input.failed
                                        );
                                    } else if !pending_repairs.contains(&key) {
                                        pending_repairs.push_back(key);
                                        daemonseed_veilid_net::vtrace!(
                                            "tui session-health: record repair-due — \
                                             queued (busy or warming)"
                                        );
                                    }
                                }
                                None => daemonseed_veilid_net::vtrace!(
                                    "tui session-health: repair-due for an unmapped record \
                                     key — cannot resolve owner seed"
                                ),
                            }
                        }
                        RepairDecision::Suppressed => {
                            daemonseed_veilid_net::vtrace!(
                                "tui session-health: repair-due suppressed (elevated \
                                 weather) — will resume in calm"
                            );
                        }
                        RepairDecision::NotDue => {}
                    }
                } else {
                    handle_inbound(ev, &evt_tx, &circles, &mut shares);
                }
            }
            // Age out discovered shares not reheard within the TTL (Shape B liveness),
            // mirroring the GUI Veilid actor. Own shares ride PublishStarted/Stopped,
            // never the catalog, so they are unaffected.
            _ = prune_timer.tick() => {
                if shares.catalog.prune(Instant::now()) > 0 {
                    emit_shares_snapshot(&shares, &evt_tx);
                }
            }
            // Emit one lobby presence beacon + reap the tracker, then re-arm with a
            // fresh jittered deadline.
            () = heartbeat.as_mut() => {
                emit_and_reap_lobby_presence(&evt_tx, &net, &my_handle, &mut shares);
                heartbeat
                    .as_mut()
                    .reset(tokio::time::Instant::now() + veilid_keepalive_interval());
            }
            // #157 (generalized): once the Connect hand-off window has closed, re-sweep
            // ONE subscribed chat/discovery record per tick (round-robin) so a message
            // or advert written after the login sweep can no longer be stranded by the
            // lossy DHT watch. Presence records are excluded (self-heal via keepalive
            // re-writes, WB-4). Spawned off the loop so its record-open await never
            // stalls commands/chat; the cursor advance is synchronous.
            _ = steady_resweep.tick() => {
                // (#180 §RS-1.4, CRSH-ISC-6/15) Dispatch parked browse retries on the
                // consumer's own cursor tick (decorrelated from the sharer's re-announce),
                // independent of the resweep `ready` gate — it only marks route-refreshed
                // shares fetchable-again (reframe #180), no sweep, no network op.
                process_parked_browse_retries(&mut shares, &evt_tx);
                // Ready once the hand-off window has elapsed, we are attached, and no
                // prior resweep is still in flight (the WB-2 one-sweep-at-a-time bound).
                let ready = connected_at
                    .is_some_and(|t| t.elapsed() >= STEADY_RESWEEP_WARMUP_HANDOFF)
                    && !resweep_busy.load(std::sync::atomic::Ordering::Acquire);
                if let Some(handle) = net.as_ref().filter(|_| ready) {
                    // Repairs take priority over resweeps (§RS-1.2): heal a dead record
                    // before spending cadence ticks resweeping healthy ones. Drained one at
                    // a time, serialized with the resweep via `resweep_busy`.
                    if let Some(key) = pending_repairs.pop_front() {
                        // (#180 F4/F5, CRSH-ISC-24) Re-check at drain: a record queued while
                        // busy/warming may have RECOVERED before the queue drained (a
                        // successful sweep cleared its streak + latch), or already been
                        // dispatched by the immediate fold arm (which cleared its latch).
                        // Dispatch only if it is STILL repair-due; otherwise the popped entry
                        // is stale — drop it (pop_front already removed it) rather than
                        // re-establish a healthy record.
                        if session_health.is_repair_due(&key) {
                            if let Some(&owner_seed) = record_key_owners.get(&key) {
                                session_health.note_repair_dispatched(&key);
                                spawn_repair(handle, &resweep_busy, owner_seed);
                                daemonseed_veilid_net::vtrace!(
                                    "tui steady-resweep: draining a queued repair"
                                );
                            }
                        } else {
                            daemonseed_veilid_net::vtrace!(
                                "tui steady-resweep: dropping a stale queued repair \
                                 (record recovered or already dispatched)"
                            );
                        }
                    } else {
                        let mut seeds: Vec<[u8; 32]> = Vec::new();
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
                                "tui steady-resweep: re-sweeping 1 of {} record(s)",
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
/// disconnected there is no handle; the drained ids fall to the transport LRU/expiry backstop
/// (design Evidence 2).
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

/// Await the optional Veilid event receiver. The `if ev_rx.is_some()` guard on
/// the select arm ensures this is only polled when `Some`, so the `unwrap` holds.
async fn recv_opt(ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>) -> Option<VeilidNetEvent> {
    ev_rx.as_mut().unwrap().recv().await
}

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    cmd: NetCommand,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    circles: &mut Vec<VeilidCircle>,
    next_circle_id: &mut u64,
    my_handle: &mut Option<String>,
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
            stable_signing_key,
            stable_share_root_ikm,
            profile_root,
            ..
        } => {
            // Capture the stable identity key (least-authority: kept behind an Arc
            // for sealing announcements + minting the route-advert capability; the
            // raw key never enters veilid-net). `StableSigningKey` already wraps an
            // `Arc<SignKeypair>`.
            shares.signing = stable_signing_key.map(|k| k.0);
            // (#156) Capture the share-root IKM (Arc — it holds secret bytes) so a
            // publish derives a receiver-verifiable share_id from the same identity.
            shares.share_root_ikm = stable_share_root_ikm.map(Arc::new);
            // (step 8b-2 / DL-ISC-20) Hold the profile root for the session so a
            // verified resume anchors each fetch's manifest digest in the client's
            // own trusted state (a `ManifestDigestStore` under this dir).
            shares.profile_root = profile_root;
            connect(evt_tx, net, ev_rx).await;
            if net.is_some() {
                // Subscribe the world-derivable lobby so share announcements fold
                // into the catalog as they arrive (Phase 3 discovery) and so lobby
                // chat can flow (emits PublicRoomJoined).
                subscribe_lobby(shares, net, evt_tx, my_handle.as_deref().unwrap_or("guest")).await;
            }
        }
        NetCommand::JoinCircle { phrase } => {
            join_circle(&phrase, evt_tx, net, circles, next_circle_id).await;
        }
        NetCommand::SendChat {
            circle_id,
            body,
            sender_handle,
        } => {
            *my_handle = Some(sender_handle.clone());
            send_chat(
                circle_id,
                &body,
                &sender_handle,
                evt_tx,
                net,
                circles,
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
            publish_share(shares, evt_tx, net, root, name, sharer_handle).await;
        }
        NetCommand::UnpublishShare { share_id } => {
            unpublish_share(shares, evt_tx, net, &share_id).await;
        }
        NetCommand::RefreshShares => {
            emit_shares_snapshot(shares, evt_tx);
        }
        NetCommand::FetchShare { share_id, name, .. } => {
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
            root_kind,
            ..
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
                root_kind,
            );
        }
        NetCommand::ListFetched { fetched_root } => {
            emit_fetched_snapshot(evt_tx, &fetched_root);
        }

        // ── Public-room (Lobby) chat ──
        NetCommand::SendPublicRoom {
            body,
            sender_handle,
        } => {
            // Learn our handle so the inbound demux suppresses our own DHT
            // re-surface (parity with SendChat; the app already echoed on Enter).
            *my_handle = Some(sender_handle.clone());
            send_public_room(&body, &sender_handle, evt_tx, net, shares).await;
        }

        // User-facing surfaces not yet on Veilid (Phase 4): answer honestly on the
        // matching per-surface error event (the TUI has no single generic `Error`
        // variant — the GUI's contract does — so each maps to the event its UI
        // status line already renders) rather than silently swallow.
        // The redb "My shares" index is a relay-path concept (it backs the
        // serve-from-disk publish cache). The Veilid publish path indexes its
        // root fresh on each `PublishShare`, so there is nothing for `DefineShare`
        // to do here — answer honestly.
        NetCommand::DefineShare { .. } => {
            let _ = evt_tx.send(NetEvent::ShareDefineFailed {
                message: NOT_YET.to_owned(),
            });
        }
        NetCommand::RefreshPublicSpace
        | NetCommand::UploadAnnouncement { .. }
        | NetCommand::SetMotd { .. } => {
            let _ = evt_tx.send(NetEvent::PublicSpaceError {
                message: NOT_YET.to_owned(),
            });
        }
        NetCommand::RefreshDeprecation => {
            let _ = evt_tx.send(NetEvent::DeprecationError {
                message: NOT_YET.to_owned(),
            });
        }
        NetCommand::RefreshIntroducer => {
            let _ = evt_tx.send(NetEvent::IntroducerError {
                message: NOT_YET.to_owned(),
            });
        }

        // No-op commands: the relay actor's internal/timer-driven self-sends
        // (`ApplyAnnouncement`, `AnswerRollCall`, `ReconcileShares`,
        // `EmitHeartbeat`, `ApplyHeartbeat`) — none are generated in Veilid mode
        // (no relay machinery runs) — plus `CancelPublish` (the Veilid publish
        // indexes synchronously off the actor loop, so there is no in-flight hash
        // to cancel).
        _ => {}
    }
}

/// Start a Veilid node bound to a fresh daemonseed-derived identity (D3) and
/// attach to the public network. No relay address / handshake (D1/D4): the
/// bootstrap is baked into the node config.
async fn connect(
    evt_tx: &UnboundedSender<NetEvent>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
) {
    if net.is_some() {
        let _ = evt_tx.send(NetEvent::Connected {
            server: "veilid".to_owned(),
            version: VEILID_WIRE_VERSION.to_owned(),
            rotation_notice: None,
        });
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
    // Without them two nodes on one host collide on the default store dir + port.
    let dir = std::env::var("DAEMONSEED_VEILID_DIR").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join("daemonseed-tui-veilid")
            .to_string_lossy()
            .into_owned()
    });
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir);
    if let Ok(port) = std::env::var("DAEMONSEED_VEILID_PORT") {
        cfg.listen_address = Some(format!(":{port}"));
        // Distinct program namespace per instance too. veilid keys some
        // process/host-global coexistence state on the namespace, so two nodes
        // sharing the default "daemonseed" evict each other even with distinct
        // stores + ports (the #99 `two_node_circle` test gives each node its own
        // namespace for exactly this reason). Derive it from the distinct port so
        // it tracks automatically.
        cfg.namespace = format!("daemonseed-{port}");
    }

    match VeilidNet::start(cfg).await {
        Ok((handle, rx)) => match handle.attach_and_wait(180).await {
            Ok(()) => {
                *net = Some(handle);
                *ev_rx = Some(rx);
                let _ = evt_tx.send(NetEvent::Connected {
                    server: "veilid".to_owned(),
                    version: VEILID_WIRE_VERSION.to_owned(),
                    rotation_notice: None,
                });
            }
            Err(e) => fail(evt_tx, format!("veilid attach: {e}")),
        },
        Err(e) => fail(evt_tx, format!("veilid start: {e}")),
    }
}

fn fail(evt_tx: &UnboundedSender<NetEvent>, message: String) {
    let _ = evt_tx.send(NetEvent::ConnectFailed { message });
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
            daemonseed_veilid_net::vtrace!("tui lobby: room-key derivation failed: {e}");
            return;
        }
    };
    let owner_seed = match derive_room_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0) {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            daemonseed_veilid_net::vtrace!("tui lobby: owner-seed derivation failed: {e}");
            return;
        }
    };
    // The SHARE-discovery sibling record (#153) — a distinct, world-derivable
    // rendezvous so share adverts never share the chat append-ring's record (the two
    // subkey schemes overlapped and silently overwrote each other). Unlike presence
    // (read-only), this is a WRITE record — publish_share advertises on it — so a
    // [0u8;32] fallback would advertise on a predictable, world-writable record. Same
    // KDF primitive as the chat owner seed, so a failure means the lobby is broken:
    // bail rather than write to a zeros record.
    let share_owner_seed = match derive_room_share_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0) {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            daemonseed_veilid_net::vtrace!("tui lobby: share owner-seed derivation failed: {e}");
            return;
        }
    };
    // The PRESENCE sibling record (P1) — a distinct, world-derivable rendezvous so
    // beacons never share the chat append-ring. Non-fatal on failure.
    let presence_owner_seed = derive_room_presence_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0)
        .map(|s| *s.as_bytes())
        .unwrap_or([0u8; 32]);
    if let Err(e) = handle.subscribe_room(owner_seed).await {
        daemonseed_veilid_net::vtrace!("tui lobby: subscribe failed: {e}");
        return;
    }
    // Subscribe the share record too so inbound share adverts fold into the catalog
    // (#153). Non-fatal — chat is unaffected if it fails.
    if let Err(e) = handle.subscribe_room(share_owner_seed).await {
        daemonseed_veilid_net::vtrace!("tui lobby: share-record subscribe failed: {e}");
    }
    // Subscribe the presence record too so inbound beacons fold into the tracker.
    // Non-fatal — chat is unaffected if it fails.
    if let Err(e) = handle.subscribe_room(presence_owner_seed).await {
        daemonseed_veilid_net::vtrace!("tui lobby: presence subscribe failed: {e}");
    }
    daemonseed_veilid_net::vtrace!("tui lobby: subscribed (chat + shares + presence)");
    shares.lobby = Some(LobbyRendezvous {
        room_key,
        owner_seed,
        share_owner_seed,
        presence_owner_seed,
        // WB-1.9: TTL 600s + read-side fold; the crash/network-loss backstop only.
        presence: PresenceTracker::for_room(DEFAULT_ROOM, PRESENCE_TTL),
    });
    // WB-1.1: publish one JOIN beacon on subscribe so the member shows on rosters
    // within the connect window (not a keepalive interval later).
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
    // The lobby rendezvous is live: tell the app the public room is joined so its
    // Lobby chat input is enabled (relay-path parity — the relay emits
    // PublicRoomJoined on its connect-time auto-join).
    let _ = evt_tx.send(NetEvent::PublicRoomJoined {
        room: DEFAULT_ROOM.to_owned(),
    });
}

/// Join a circle: derive the content key + the shared rendezvous-owner seed from
/// the phrase, subscribe the rendezvous record, assign a stable id + client-local
/// label, and record local state.
async fn join_circle(
    phrase: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &mut Vec<VeilidCircle>,
    next_circle_id: &mut u64,
) {
    let err = |message: String| {
        let _ = evt_tx.send(NetEvent::CircleJoinFailed { message });
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
    // Idempotent join (ISC-C59): a circle already in the set (same phrase → same
    // owner_seed) re-emits its existing id + label so the app re-selects it,
    // rather than re-subscribing or duplicating membership.
    if let Some(existing) = circles.iter().find(|c| c.owner_seed == owner_seed) {
        let _ = evt_tx.send(NetEvent::CircleJoined {
            circle_id: existing.circle_id,
            label: existing.label.clone(),
            entropy: phrase.to_owned(),
        });
        return;
    }
    if let Err(e) = handle.subscribe_circle(owner_seed).await {
        return err(format!("subscribe failed: {e}"));
    }
    let circle_id = *next_circle_id;
    *next_circle_id += 1;
    // Deterministic client-local label (ISC-C62): derived from the per-circle
    // content-key fingerprint so the same circle gets the same default label,
    // never from other members and never transmitted.
    let label = default_circle_label(&circle_fingerprint(&cot_key));
    circles.push(VeilidCircle {
        circle_id,
        cot_key,
        owner_seed,
        label: label.clone(),
    });
    let _ = evt_tx.send(NetEvent::CircleJoined {
        circle_id,
        label,
        entropy: phrase.to_owned(),
    });
}

/// A stable per-circle fingerprint, used only to seed the deterministic
/// client-local label. The Veilid rendezvous is a DHT record key, not an
/// `AssetAddr`, so we synthesize a deterministic `AssetAddr` from the content key
/// (same value every join) purely for [`default_circle_label`].
fn circle_fingerprint(cot_key: &CircleKey) -> AssetAddr {
    asset_address(cot_key, b"veilid-circle").expect("asset_address is infallible for a fixed salt")
}

/// Seal a message under the circle key and publish it to the rendezvous record.
/// NO local echo (unlike the GUI, whose actor is the only render path): the TUI
/// app layer already echoes the composed line on Enter (`app::App` Enter handler,
/// ISC-A-C29). The actor's only job is to drop the DELAYED DHT re-surface of this
/// same write (see `handle_inbound`), so the line stays single.
async fn send_chat(
    circle_id: u64,
    body: &str,
    sender_handle: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &[VeilidCircle],
    signing: Option<Arc<SignKeypair>>,
) {
    let err = |message: String| {
        let _ = evt_tx.send(NetEvent::ChatError { message });
    };
    let Some(circle) = circles.iter().find(|c| c.circle_id == circle_id) else {
        return err("join a circle before sending".to_owned());
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let Some(signing) = signing else {
        return err("no identity to sign the message".to_owned());
    };
    let sent_unix_ms = now_unix_ms();
    // Circle messages are now SIGNED (room↔circle convergence): the poster's
    // identity signs the RoomMessage so authorship is verifiable.
    let sealed = match seal_message(
        &circle.cot_key,
        signing.as_ref(),
        sender_handle,
        body,
        sent_unix_ms,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("seal failed: {e}")),
    };
    if let Err(e) = handle.publish_circle(circle.owner_seed, sealed).await {
        err(format!("publish failed: {e}"));
    }
}

/// Seal a public-room (Lobby) message under the lobby `PublicRoomKey` and publish
/// it onto the lobby rendezvous. The public-tier counterpart of [`send_chat`]: NO
/// local echo (the TUI app already echoed the composed line on Enter), so the
/// actor's only job is the seal+publish; the DELAYED DHT re-surface of this same
/// write is suppressed by handle in [`handle_inbound`]. Mirrors the relay actor's
/// `handle_send_public_room`.
async fn send_public_room(
    body: &str,
    sender_handle: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    shares: &ShareState,
) {
    let err = |message: String| {
        let _ = evt_tx.send(NetEvent::PublicRoomJoinFailed { message });
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
    let sealed = match seal_room_message(
        &lobby.room_key,
        signing.as_ref(),
        DEFAULT_ROOM,
        sender_handle,
        body,
        now_unix_ms(),
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("public-room seal/sign failed: {e}")),
    };
    if let Err(e) = handle.publish_room(lobby.owner_seed, sealed).await {
        err(format!("public-room publish failed: {e}"));
    }
}

// ── Public shares (Phase 3 Slice 2b) ────────────────────────────────────────

/// Emit a [`NetEvent::PublishError`]. `root` is `Some` once the failure concerns
/// a specific publish (the index step), `None` for the pre-flight checks — the
/// app keys its hashing/published state by root, mirroring the relay.
fn publish_fail(evt_tx: &UnboundedSender<NetEvent>, message: String, root: Option<PathBuf>) {
    let _ = evt_tx.send(NetEvent::PublishError { message, root });
}

fn fetch_fail(evt_tx: &UnboundedSender<NetEvent>, message: String) {
    let _ = evt_tx.send(NetEvent::FetchError { message });
}

/// Build + emit a [`NetEvent::SharesSnapshot`] from the in-band discovery catalog.
/// `local` is empty + `indexer_status` is `Idle` (the Veilid path has no redb
/// "My shares" index); `remote` is the discovered catalog. Own published shares
/// are NOT folded in — they ride `PublishStarted`/`PublishStopped`, exactly as on
/// the relay (the lobby never echoes our own announcement back).
fn emit_shares_snapshot(shares: &ShareState, evt_tx: &UnboundedSender<NetEvent>) {
    let remote = shares
        .catalog
        .entries()
        .iter()
        .map(|s| {
            let mut listing = ShareListing::from(s);
            // (#180 §RS-1.4) Overlay the frontend-local re-resolve state: a share whose
            // fetch failed stays listed, marked `unresolved`, until a parked retry
            // resolves it (CRSH-ISC-5).
            listing.unresolved = shares
                .discovered
                .get(&s.share_id)
                .is_some_and(|d| d.unresolved);
            listing
        })
        .collect();
    let _ = evt_tx.send(NetEvent::SharesSnapshot {
        local: Vec::new(),
        remote,
        indexer_status: IndexerStatus::Idle,
    });
}

/// Read the fetched-shares browse manifest and emit a [`NetEvent::FetchedShares`]
/// snapshot (M15 C; ISC-C64). Mirrors the relay's `handle_list_fetched`: a
/// transient/corrupt read leaves the pane's last-known list in place (no event).
fn emit_fetched_snapshot(evt_tx: &UnboundedSender<NetEvent>, fetched_root: &Path) {
    if let Ok(shares) = FetchedStore::open(fetched_root).and_then(|s| s.list_shares()) {
        let _ = evt_tx.send(NetEvent::FetchedShares { shares });
    }
}

/// Publish a local directory as a public share: index it (RAM path), mint a
/// client-side `share_id`, seal a self-signed `ShareAnnouncement` under the lobby
/// `PublicRoomKey`, register the content to serve owner-on-demand, and announce it
/// onto the lobby rendezvous with a SIGNED route advert (anti-swap, D-3.5).
/// Mirrors the relay actor's `handle_publish_share` (minus the redb chunk-addr
/// cache — the RAM index is the no-cache path) on the TUI's `PublishError { root }`
/// / `PublishStarted` contract.
async fn publish_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    root: PathBuf,
    name: String,
    sharer_handle: String,
) {
    let Some(handle) = net.as_ref() else {
        return publish_fail(evt_tx, "not connected to Veilid yet".to_owned(), None);
    };
    let Some(signing) = shares.signing.clone() else {
        return publish_fail(
            evt_tx,
            "no identity to sign the announcement".to_owned(),
            None,
        );
    };
    let Some(share_root_ikm) = shares.share_root_ikm.clone() else {
        return publish_fail(
            evt_tx,
            "no identity to derive the share id".to_owned(),
            None,
        );
    };
    // Copy the lobby's address material out so no borrow of `shares` is held
    // across an `.await` (and so the later `shares.own.push` is unobstructed). The
    // advert publishes on the SHARE record (#153), disjoint from the chat record.
    let (room_key_bytes, owner_seed) = match shares.lobby.as_ref() {
        Some(l) => (*l.room_key.as_bytes(), l.share_owner_seed),
        None => return publish_fail(evt_tx, "lobby not subscribed yet".to_owned(), None),
    };

    // Index off the actor loop (the in-RAM `ShareContent`; no redb cache on the
    // Veilid path). Clone the root for the blocking task so the original survives
    // for the event + error reporting.
    let index_root = root.clone();
    let content = match tokio::task::spawn_blocking(move || ShareContent::index_dir(&index_root))
        .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            return publish_fail(
                evt_tx,
                format!("could not index {}: {e}", root.display()),
                Some(root),
            );
        }
        Err(_) => return publish_fail(evt_tx, "share-index task failed".to_owned(), Some(root)),
    };
    let file_count = content.file_count();
    let content = Arc::new(content);

    // Receiver-verifiable deterministic id (#156): share_id =
    // derive_share_id_v2(own_pubkey, root_commitment). The commitment hides the
    // root under a secret per-share nonce; a republish re-asserts the SAME id and
    // a v2 receiver rejects any non-derivable id.
    let root_str = root.to_string_lossy();
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
        Err(e) => {
            return publish_fail(
                evt_tx,
                format!("could not seal share announcement: {e}"),
                Some(root),
            );
        }
    };

    // Register the content to serve owner-on-demand (chunks sealed under the room
    // key), then announce it with a signed route advert. veilid-net allocates the
    // private route + signs via the capability internally.
    if let Err(e) = handle
        .serve_share(share_id.clone(), content, room_key_bytes)
        .await
    {
        return publish_fail(
            evt_tx,
            format!("could not register share to serve: {e}"),
            Some(root),
        );
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
        return publish_fail(evt_tx, format!("could not announce share: {e}"), Some(root));
    }

    shares.own.push(OwnShare {
        share_id: share_id.clone(),
        root_commitment: root_commitment.to_vec(),
        name: name.clone(),
        rating,
        sharer_handle,
    });
    let _ = evt_tx.send(NetEvent::PublishStarted {
        share_id,
        root,
        name,
        file_count,
    });
}

/// Unpublish a share published this session: stop serving its bytes (the teeth of
/// unpublish), post a withdraw `ShareAnnouncement` onto the lobby so listeners
/// drop it from their catalog, and clear our own record. Mirrors the relay actor's
/// `handle_unpublish_share`. The withdraw reuses the original metadata so its
/// provenance input matches the announce's.
async fn unpublish_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    share_id: &str,
) {
    let own = shares.own.iter().find(|s| s.share_id == share_id).cloned();
    shares.own.retain(|s| s.share_id != share_id);
    let _ = evt_tx.send(NetEvent::PublishStopped {
        share_id: share_id.to_owned(),
    });

    // Teeth of unpublish: stop SERVING the bytes. Fires whenever connected,
    // independent of whether the withdraw below can be signed — the withdraw only
    // removes the share from listeners' discovery catalogs, while this
    // de-registers it from the serve registry so the owner no longer answers fetch
    // app_calls (a holder of a stale route gets a not-found, never bytes).
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
        // receivers; only reached if the own-record was already lost, and
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
/// route). The helper that resolves the Demonsaw ambiguity: a deliberate unpublish
/// reads plainly instead of an indefinite timeout.
fn fetch_error_message(context: &str, e: VeilidNetError) -> String {
    match e {
        VeilidNetError::NotServed => "sharer withdrew this share".to_owned(),
        other => format!("{context}: {other}"),
    }
}

/// (#180 §RS-2, CRSH-ISC-7/8/19) The generation-tagged outcome of a share fetch that ran in
/// a spawned task **off** the net-actor loop. Folded back on-loop by [`fold_fetch_outcome`],
/// which is where the `&mut ShareState` mutations (mark/clear Unresolved) and UI emissions
/// happen — never inside the spawned task. Every variant carries the `generation` captured
/// at spawn time so a stale outcome (the share was withdrawn / re-added while the fetch was
/// in flight) no-ops on fold (CRSH-ISC-19). The imported `RouteId` rides the `route`-bearing
/// variants back on-loop so step 6's release map can attach (§RS-3) — the spawned task never
/// releases a route itself.
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
                    "could not import the sharer's route: {e} — re-resolving; the share \
                     stays listed"
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
                    chunk_count: e.chunks.len() as u32,
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
    let Some(handle) = net.as_ref() else {
        return fetch_fail(evt_tx, "not connected to Veilid yet".to_owned());
    };
    let Some(lobby) = shares.lobby.as_ref() else {
        return fetch_fail(evt_tx, "lobby not subscribed yet".to_owned());
    };
    let Some(disc) = shares.discovered.get(share_id) else {
        return fetch_fail(
            evt_tx,
            "share not discovered yet — refresh the list".to_owned(),
        );
    };
    let route_blob = disc.route_blob.clone();
    let generation = disc.generation;
    let room_key_bytes = *lobby.room_key.as_bytes();
    let handle = handle.clone();
    let share_id = share_id.to_owned();
    let name = name.to_owned();
    // (#180 §RS-3, CRSH-ISC-10) In flight over the imported route until its outcome folds —
    // a concurrent advert-replacement defers the old route's release until this completes.
    shares.route_guard.note_fetch_started(share_id.clone());
    // (#207 / DL-ISC-14) On a worker panic, emit a terminal outcome so the fetch still folds —
    // closing the route guard's in-use count (else a superseded route would never release). No
    // route was imported by a panicking preview, so ImportFailed (no route, marks Unresolved +
    // parks) is the terminal fold that closes the guard.
    let on_panic = FetchOutcome::ImportFailed {
        share_id: share_id.clone(),
        name: name.clone(),
        generation,
        message: "the share-preview fetch task panicked".to_owned(),
    };
    spawn_fetch_task(outcome_tx.clone(), on_panic, async move {
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
///
/// (#207 / DL-ISC-14) The browse fetch future IS `Send` (unlike the download engine), so it rides
/// `tokio::spawn`; its `JoinHandle` is awaited on an outer detached task so a `JoinError` (the
/// worker panicked) maps to `on_panic` — a terminal outcome — rather than stranding the share.
/// Mirrors the GUI's browse seam.
fn spawn_fetch_task<F>(outcome_tx: UnboundedSender<FetchOutcome>, on_panic: FetchOutcome, fetch: F)
where
    F: std::future::Future<Output = FetchOutcome> + Send + 'static,
{
    let worker = tokio::spawn(fetch);
    tokio::spawn(async move {
        let outcome = match worker.await {
            Ok(outcome) => outcome,
            Err(_join_err) => on_panic,
        };
        // A closed channel just means the actor shut down mid-fetch — the outcome is moot.
        let _ = outcome_tx.send(outcome);
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
            emit_shares_snapshot(shares, evt_tx);
            daemonseed_veilid_net::vtrace!(
                "tui fetch outcome for {share_id} stale via fresh advert (gen {generation}) \
                 — re-parked one-shot retry (still Unresolved)"
            );
        } else {
            daemonseed_veilid_net::vtrace!(
                "tui fetch outcome for {share_id} stale (gen {generation}) — dropped \
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
            fetch_fail(evt_tx, message);
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
            fetch_fail(evt_tx, message);
        }
    }
}

/// (#180 §RS-1.4, CRSH-ISC-4/5) Mark a share's route **Unresolved** after a fetch failure
/// and park a one-shot, generation-tagged browse retry — **local computation only, ZERO
/// network** (§RS-0). The share stays listed (never pruned on a fetch failure); the parked
/// retry fires at the next cursor tick after a fresh advert folds (CRSH-ISC-6), or clears
/// on window expiry / withdraw. Takes no network handle by construction. No-op if the route
/// is already gone.
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
        None => return,
    };
    shares.parked_retries.insert(
        share_id.to_owned(),
        ParkedBrowseRetry::park(name.to_owned(), generation, Instant::now()),
    );
    emit_shares_snapshot(shares, evt_tx);
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
        emit_shares_snapshot(shares, evt_tx);
    }
}

/// (#180 §RS-1.4/§RS-2, CRSH-ISC-6/15) House-keep the parked browse retries **at the consumer's
/// own cursor tick** — never at the advert-fold event. Under the reframe (#180, 2026-07-17) the
/// actual mark-fetchable happens at the route-rotation fold (`apply_discovery`, a local
/// no-network op), so this tick no longer re-fetches or clears `Unresolved`: it only expires
/// stale parks. A park whose share saw a fresh advert fold since the park (its discovered
/// generation advanced) but no route rotation (a content-only re-advert — `apply_discovery` left
/// it parked) is dropped, since the route is not refreshed and a real rotation will mark it
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
        fetch_fail(
            evt_tx,
            format!(
                "re-resolve window elapsed for '{name}' — the share stays listed; \
                 browse it again to retry"
            ),
        );
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

/// (#197, CRSH-ISC-29) The terminal outcome of a chunk download that ran in a spawned task
/// **off** the net-actor loop. Folded back on-loop by [`fold_confirm_outcome`], which is where
/// the `&mut ShareState` mark/clear-Unresolved mutation and the terminal
/// `FetchComplete`/`FetchError` emission happen — never inside the spawned task.
/// `FetchProgress` events still stream from the worker via the cloned `evt_tx`.
#[derive(Debug)]
enum ConfirmOutcome {
    /// Every selected file was fetched, verified, and written (and, in managed mode, recorded
    /// in `downloads.idx` by the worker). Fold: clear any Unresolved mark + drop the parked
    /// retry (CRSH-ISC-25 F6), then emit `FetchComplete`.
    Complete {
        share_id: String,
        files_written: u32,
        bytes_written: u64,
    },
    /// A route-death failure (import / manifest / any streaming-loop failure). Fold: mark the
    /// share Unresolved + park a one-shot retry (#180 §RS-1.4/§RS-1.5, CRSH-ISC-5) — never a
    /// prune — then emit `FetchError`. Partial bytes + a stale idx entry were already cleaned
    /// in the worker (ISC-A-C31).
    RouteFailed {
        share_id: String,
        name: String,
        message: String,
    },
    /// (download-subsystem redesign, step 6 / DL-ISC-13) The sharer served content that failed
    /// verification. The engine has ALREADY destroyed the fetch's staged partials (poison
    /// boundary = the whole fetch); already-promoted files stay (self-authenticating). Fold:
    /// set the durable poison flag + emit `FetchError` — NO Unresolved mark, NO parked retry
    /// (the route is fine, the content is hostile). The message names no chunk index.
    IntegrityFailed { share_id: String, message: String },
    /// A local failure (staging disk/path fault / post-verify idx write) that must NOT mark the
    /// share Unresolved — the sharer's route is fine. Fold: emit `FetchError` only. Verified
    /// units are retained (they verified — a disk blip must not wipe them).
    LocalFailed { message: String },
}

/// (#197, CRSH-ISC-29) Dispatch an A1/A2 chunk download **off** the net-actor loop: copy the
/// route blob + room key + verified announcer pubkey out of share state, spawn
/// [`run_confirm_download`], and return immediately so the actor loop returns to its `select!`
/// without ever awaiting the download (the chat-starvation fix, mirroring the #180 §RS-2
/// `spawn_fetch_share` restructure). The terminal outcome returns via `outcome_tx` and is folded
/// on-loop by [`fold_confirm_outcome`]. Immediate local failures (not connected, lobby not
/// subscribed, share not discovered) still fail inline — they touch no network, need no spawn,
/// and (matching the prior inline behavior) never mark the share Unresolved.
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
    root_kind: RootKind,
) {
    let Some(handle) = net.as_ref() else {
        return fetch_fail(evt_tx, "not connected to Veilid yet".to_owned());
    };
    // Copy the route blob + room key + verified announcer pubkey out under an immutable borrow,
    // dropping it before the spawn. `handle` rides `net`, disjoint from `shares`. The pubkey is
    // the budget's sharer key (DL-ISC-2).
    let (route_blob, room_key_bytes, sender_pubkey) = {
        let Some(lobby) = shares.lobby.as_ref() else {
            return fetch_fail(evt_tx, "lobby not subscribed yet".to_owned());
        };
        let Some(disc) = shares.discovered.get(share_id) else {
            return fetch_fail(
                evt_tx,
                "share not discovered yet — refresh the list".to_owned(),
            );
        };
        (
            disc.route_blob.clone(),
            *lobby.room_key.as_bytes(),
            disc.sender_pubkey.clone(),
        )
    };
    // (DL-ISC-13) A user-initiated re-download of a share previously flagged for an integrity
    // failure is ALLOWED (per-chunk verification, ISC-A-S20, is the always-on enforcement), but
    // it is warned about — the poison flag is a UX guard, not a block.
    if shares.poisoned_shares.contains(share_id) {
        daemonseed_veilid_net::vtrace!(
            "tui: re-downloading share {share_id} previously flagged for an integrity failure \
             — per-chunk verification remains fail-closed"
        );
    }
    let budget = shares.budget.clone();
    let live_fetches = shares.live_fetches.clone();
    // (step 8b-2 / DL-ISC-20) The profile root anchors this fetch's resume digest in
    // the client's trusted state; `None` on the no-profile path (no resume anchor).
    let profile_root = shares.profile_root.clone();
    let handle = handle.clone();
    let evt_tx = evt_tx.clone();
    let share_id = share_id.to_owned();
    let name = name.to_owned();
    // (#207 / DL-ISC-14) A panic in the worker still yields a terminal outcome so the share is
    // never stranded; staging-by-construction means a panic strands only quarantined state.
    let on_panic = ConfirmOutcome::LocalFailed {
        message: "the download task ended abnormally (panic or runtime failure)".to_owned(),
    };
    // A `FnOnce` that BUILDS the (non-`Send`) engine future on the download's own runtime — the
    // seam runs it off the actor loop without ever needing it to be `Send` (see
    // `spawn_confirm_task`).
    spawn_confirm_task(outcome_tx.clone(), on_panic, move || {
        run_confirm_download(
            handle,
            evt_tx,
            budget,
            live_fetches,
            share_id,
            name,
            route_blob,
            room_key_bytes,
            sender_pubkey,
            fetched_root,
            profile_root,
            selected,
            flat_dest,
            root_kind,
        )
    });
}

/// (#197, CRSH-ISC-29) The spawn seam shared by [`spawn_confirm_fetch`] and the actor tests: run
/// the download to completion **off** the actor loop and report its [`ConfirmOutcome`] to
/// `outcome_tx`, returning immediately. This is the single point guaranteeing no download is ever
/// awaited on the caller (the actor loop) — testable without a live veilid attach.
///
/// `make_download` is a `FnOnce` that BUILDS the download future (rather than the future itself),
/// because the shared engine ([`run_download`]) future is **not `Send`** — its internal
/// `files.iter().map(|f| fetch_one_file(f, …))` trips the well-known rustc higher-ranked `Send`
/// inference limitation (#99492), so it cannot ride `tokio::spawn` on the multi-thread net
/// runtime. Instead a blocking thread builds a dedicated current-thread runtime and drives the
/// future there: the actor's own worker threads keep serving the download's chunk `app_call`s
/// concurrently, so the download is genuinely off-loop while never needing to be `Send`.
///
/// (#207 / DL-ISC-14) A panic while driving the download is caught and mapped to `on_panic` — a
/// terminal outcome — so a panicking worker never strands the share. Staging-by-construction means
/// the panic leaves only quarantined `.dspart` state, reclaimed by the sweep.
fn spawn_confirm_task<F, Fut>(
    outcome_tx: UnboundedSender<ConfirmOutcome>,
    on_panic: ConfirmOutcome,
    make_download: F,
) where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ConfirmOutcome>,
{
    tokio::task::spawn_blocking(move || {
        // Build a current-thread runtime on this blocking thread and drive the (non-`Send`)
        // download future to completion; `enable_all` gives the fetch path its timers (retry
        // backoff sleeps). A runtime-build failure or a worker panic yields the terminal outcome.
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
            .and_then(|rt| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rt.block_on(make_download())
                }))
                .ok()
            })
            .unwrap_or(on_panic);
        // A closed channel just means the actor shut down mid-download — the outcome is moot.
        let _ = outcome_tx.send(outcome);
    });
}

/// (#197 / download-subsystem redesign step 6) The network+disk half of a download — run
/// **inside a spawned task**, never on the actor loop. It leases the per-route budget once,
/// imports the route, fetches the manifest (budget-admitted), computes each selected file's
/// destination-relative placement (selection roots for a chosen dir, DL-ISC-8; `<share-folder>/
/// <rel>` for the managed dir), then drives the shared [`run_download`] engine, which stages
/// every VERIFIED chunk at its offset and promotes each completed file (RAM buffering + the
/// per-chunk `sanitize`/`fetch_chunk`/`cleanup_written` loop retired, #207). Streams
/// `FetchProgress` via the cloned `evt_tx`; all `&mut ShareState` mutation + the terminal event
/// are deferred to [`fold_confirm_outcome`] via the returned [`ConfirmOutcome`]. Disposition on
/// failure is the ENGINE's (integrity destroys staging; transient/local retain verified units,
/// ISC-A-C31 reword) — no clean-partial wipe loop here.
#[allow(clippy::too_many_arguments)]
async fn run_confirm_download(
    handle: VeilidNetHandle,
    evt_tx: UnboundedSender<NetEvent>,
    budget: Arc<RouteBudget<RouteId>>,
    live_fetches: LiveFetchRegistry,
    share_id: String,
    name: String,
    route_blob: Vec<u8>,
    room_key_bytes: [u8; 32],
    sender_pubkey: Vec<u8>,
    fetched_root: PathBuf,
    profile_root: Option<PathBuf>,
    selected: Option<Vec<usize>>,
    flat_dest: bool,
    root_kind: RootKind,
) -> ConfirmOutcome {
    // Hold the live-fetch registration for the whole download so a future startup/idle staging
    // sweep never reclaims this fetch's staging (DL-ISC-22 caller-ordering contract).
    let _live = live_fetches.register(&share_id);

    // Import the route, then lease the per-route budget ONCE — shared across the manifest fetch
    // and every chunk fetch (Part 1). The sharer pubkey keys the learned ceiling (DL-ISC-2).
    let route = match handle.import_route(route_blob).await {
        Ok(r) => r,
        Err(e) => {
            // (#180 §RS-1.4/§RS-1.5, CRSH-ISC-5) A download import-fail is route-death — the
            // fold keeps the share listed Unresolved + parks a one-shot retry; never prune.
            return ConfirmOutcome::RouteFailed {
                share_id,
                name,
                message: format!("could not import the sharer's route: {e}"),
            };
        }
    };
    // The lease is `Arc`-wrapped so each per-chunk future can hold an OWNED clone (a `RouteLease`
    // is `!Clone` — it refcounts the route account), keeping the engine's `fetch_chunk` closure
    // fully self-contained (it borrows nothing external).
    let lease = Arc::new(budget.lease(route.clone(), SharerKey(sender_pubkey)));

    let manifest = match handle
        .fetch_manifest_budgeted(route.clone(), &share_id, room_key_bytes, &lease)
        .await
    {
        Ok(m) => m,
        Err(e) => {
            // (F1 / DL-ISC-13) Classify like the chunk path: a hostile / malformed /
            // oversized manifest frame is `Integrity` → poison the share (no Unresolved
            // mark, no parked retry), not a transient route-death that parks a retry
            // re-fetching the same hostile manifest forever. No staging exists yet —
            // nothing to destroy. Transport / not-served stays route-death (#180 §RS-1.4).
            let class = e.fetch_class();
            let message = fetch_error_message("could not fetch the share manifest", e);
            return match class {
                FetchErrorClass::Integrity => ConfirmOutcome::IntegrityFailed { share_id, message },
                _ => ConfirmOutcome::RouteFailed {
                    share_id,
                    name,
                    message,
                },
            };
        }
    };

    // Resolve the selected file set (None → all; out-of-range indices ignored).
    let indices: Vec<usize> = match &selected {
        None => (0..manifest.len()).collect(),
        Some(sel) => sel
            .iter()
            .copied()
            .filter(|&i| i < manifest.len())
            .collect(),
    };
    if indices.is_empty() {
        // Nothing valid selected — a no-op success (no bytes to fetch, nothing to persist).
        return ConfirmOutcome::Complete {
            share_id,
            files_written: 0,
            bytes_written: 0,
        };
    }
    // Compute the staging destination root + managed-folder identity (independent of
    // the per-file placement — resolved once, shared by fresh and resume).
    //   flat_dest (user-chosen dir): the dest root IS the chosen dir; no downloads.idx.
    //   managed dir: <fetched_root>/<share-folder>; the idx is registered on Complete.
    let (dest_root, managed_folder): (PathBuf, Option<String>) = if flat_dest {
        (fetched_root.clone(), None)
    } else {
        // Fix #1 (step 6): a store open/list failure while resolving the managed folder
        // is a LocalFailed — never silently treat `existing` as empty (which would
        // mis-resolve/orphan a re-fetch's folder).
        let existing = match FetchedStore::open(&fetched_root).and_then(|s| s.list_shares()) {
            Ok(e) => e,
            Err(e) => {
                return ConfirmOutcome::LocalFailed {
                    message: format!("could not read the downloads manifest: {e}"),
                };
            }
        };
        let folder = resolve_share_folder(&existing, &share_id, &name);
        (fetched_root.join(&folder), Some(folder))
    };

    let staging = match StagingArea::open(&dest_root, &share_id) {
        Ok(s) => s,
        Err(e) => {
            return ConfirmOutcome::LocalFailed {
                message: format!("could not open the download staging area: {e}"),
            };
        }
    };

    // (F7 / DL-ISC-22) Reclaim any UNRESUMABLE staging debris under this dest root
    // before fetching — a crash before the confirmed manifest persisted leaves a
    // `.dspart/<share_id>` tree that is neither registered nor resumable, and nothing
    // else ever deletes it. Best-effort: the current fetch is registered (`_live`), so
    // its own staging is kept, and a resumable sibling (its stored confirmed manifest
    // is present) is kept; sweep_staging never deletes on a name pattern alone, so a
    // foreign `.dspart`-adjacent dir under a chosen dest is left untouched.
    let _ = sweep_staging(&dest_root, &live_fetches, |sid| {
        StagingArea::open(&dest_root, sid)
            .and_then(|s| s.read_stored_manifest())
            .is_ok()
    });

    // Place the SELECTED files at their destination-relative paths from a source
    // manifest — identical placement for a fresh confirm and a resume (DL-ISC-8 /
    // precondition D): `flat_dest` uses the selection roots; the managed dir keeps
    // the full share rel_path. `already_verified` is filled later (resume only).
    let build_planned = |source: &[ManifestEntry]| -> Result<Vec<PlannedFile>, ConfirmOutcome> {
        let sel_rels: Vec<&str> = indices
            .iter()
            .map(|&i| source[i].rel_path.as_str())
            .collect();
        if flat_dest {
            let roots = selection_roots(root_kind, &sel_rels);
            let placed =
                place_at_dest(&roots, &sel_rels).map_err(|e| ConfirmOutcome::LocalFailed {
                    message: format!("could not place the download under the chosen folder: {e}"),
                })?;
            // `place_at_dest` returns one PlacedFile per selected file, in indices order.
            Ok(indices
                .iter()
                .zip(placed.iter())
                .map(|(&i, pf)| PlannedFile {
                    dest_rel: pf.dest_rel.clone(),
                    size: source[i].size,
                    chunks: source[i].chunks.clone(),
                    already_verified: Vec::new(),
                })
                .collect())
        } else {
            Ok(indices
                .iter()
                .map(|&i| PlannedFile {
                    dest_rel: source[i].rel_path.clone(),
                    size: source[i].size,
                    chunks: source[i].chunks.clone(),
                    already_verified: Vec::new(),
                })
                .collect())
        }
    };

    // ── Resume detection (fail-closed, DL-ISC-20) ──
    // A resume is a re-initiated ConfirmFetch for a share whose staging already
    // carries a stored confirmed manifest. It proceeds ONLY through the full
    // fail-closed chain and HALTS on any break — never resuming without the
    // profile-anchored digest, never reinterpreting retained bytes under a
    // different manifest. A fresh download has no stored manifest and skips this.
    let stored_manifest_present = staging.read_stored_manifest().is_ok();
    let resume: Option<Vec<ManifestEntry>> = if stored_manifest_present {
        // Staging carries a persisted manifest → a resume. Without the profile store
        // there is no trusted anchor to verify it against → HALT (precondition A).
        let Some(profile_root) = profile_root.as_ref() else {
            return ConfirmOutcome::LocalFailed {
                message: "an incomplete download exists but no unlocked profile is available to \
                          verify its integrity anchor — reconnect with your profile, or delete the \
                          incomplete download and start over"
                    .to_owned(),
            };
        };
        // Read the profile-anchored digest, then DROP the store before the long
        // download: redb::Database::create takes an EXCLUSIVE lock, so a long-lived
        // handle would block the other frontend (precondition B).
        let digest = {
            let store = match ManifestDigestStore::open(profile_root.join(DIGEST_STORE_FILE)) {
                Ok(s) => s,
                Err(e) => {
                    return ConfirmOutcome::LocalFailed {
                        message: format!("could not open the resume integrity-anchor store: {e}"),
                    };
                }
            };
            match store.get_digest(&share_id) {
                // [precondition A] Staging exists but no anchor → HALT. Never fall
                // through to a fresh download that reuses/ignores staging unanchored.
                Ok(None) => {
                    return ConfirmOutcome::LocalFailed {
                        message:
                            "the incomplete download is missing its integrity anchor — delete \
                                  it and start the download over"
                                .to_owned(),
                    };
                }
                Ok(Some(d)) => d,
                Err(e) => {
                    return ConfirmOutcome::LocalFailed {
                        message: format!("could not read the resume integrity anchor: {e}"),
                    };
                }
            }
        };
        // Verify the stored staging manifest against the anchor (DL-ISC-20). A
        // tampered / swapped / missing manifest → HALT (re-gate).
        let stored = match verify_stored_manifest(&staging, &digest) {
            Ok(m) => m,
            Err(e) => {
                return ConfirmOutcome::LocalFailed {
                    message: format!(
                        "the incomplete download failed its integrity check — delete it and start \
                         over: {e}"
                    ),
                };
            }
        };
        // Compare the re-fetched LIVE manifest to the digest-verified STORED one
        // (precondition C). If the sharer changed the content set, HALT + re-gate on
        // preview/confirm — retained bytes are never reinterpreted under a different
        // manifest, and the resume fetches ONLY against the stored chunk addresses.
        // Surfaced as LocalFailed (a plain FetchError, NO Unresolved mark + NO parked
        // retry): a content-set change is neither a route death (RouteFailed would
        // park a doomed auto-retry) nor poison — the user re-opens the share to
        // preview and re-confirm the new contents.
        if manifest != stored {
            // The sharer changed the content set. The stale partial cannot be reused
            // under a different manifest (retained bytes are never reinterpreted), so
            // DISCARD it + its anchor — a re-open then previews and downloads the NEW
            // contents fresh (design §Part 3 re-gate). Without this, the stale stored
            // manifest would re-trigger this same halt forever. Best-effort cleanup;
            // the download halts regardless.
            let _ = staging.destroy();
            if let Ok(store) = ManifestDigestStore::open(profile_root.join(DIGEST_STORE_FILE)) {
                let _ = store.remove(&share_id);
            }
            return ConfirmOutcome::LocalFailed {
                message: "the share's contents changed since this download was confirmed — the \
                          incomplete download was discarded; open the share again to download the \
                          new contents"
                    .to_owned(),
            };
        }
        Some(stored)
    } else {
        None
    };

    // The placement source: the digest-verified STORED manifest on a resume (fetch
    // only against stored chunk addresses), else the live manifest.
    let source_manifest: &[ManifestEntry] = resume.as_deref().unwrap_or(&manifest);
    let planned_all = match build_planned(source_manifest) {
        Ok(p) => p,
        Err(o) => return o,
    };
    // The managed-dir idx records EVERY selected file (done + to-run) on completion.
    let idx_recs: Vec<FetchedFile> = planned_all
        .iter()
        .map(|p| FetchedFile {
            rel_path: p.dest_rel.clone(),
            size: p.size,
        })
        .collect();

    // On a resume, re-derive per-file verified state from BYTES ON DISK (DL-ISC-12)
    // and split: a file already promoted at the dest (complete + present at its
    // confirmed size) is DONE; every other file runs (missing chunks, or complete
    // only in staging — which the engine promotes). `already_verified` marks the
    // chunks the engine SKIPS fetching.
    let (to_run, done_files, done_bytes, resumed_verified_chunks) = if resume.is_some() {
        let placement_manifest: Vec<ManifestEntry> = planned_all
            .iter()
            .map(|p| ManifestEntry {
                rel_path: p.dest_rel.clone(),
                size: p.size,
                chunks: p.chunks.clone(),
            })
            .collect();
        let plan = derive_resume_state(&placement_manifest, &dest_root, &staging);
        let mut to_run: Vec<PlannedFile> = Vec::new();
        let mut done_files: u32 = 0;
        let mut done_bytes: u64 = 0;
        let mut resumed_verified: usize = 0;
        for (pf, fr) in planned_all.into_iter().zip(plan.files.iter()) {
            // A file already complete + verified at its dest (content-checked in
            // `derive_resume_state::promoted_complete`, not length-only) is kept as-is;
            // everything else runs, skipping only its STAGING-verified chunks (never a
            // promoted-only chunk — that would promote a sparse zero-hole).
            let done_at_dest = fr.promoted_complete;
            if done_at_dest {
                done_files += 1;
                done_bytes += pf.size;
            } else {
                resumed_verified += fr.verified.len();
                to_run.push(PlannedFile {
                    already_verified: fr.verified.clone(),
                    ..pf
                });
            }
        }
        (to_run, done_files, done_bytes, resumed_verified)
    } else {
        (planned_all, 0u32, 0u64, 0usize)
    };

    // Fresh download: anchor the digest FIRST (then drop the store before the long
    // download — precondition B), then persist the FULL confirmed manifest with
    // SHARE rel_paths into staging (Part A) — so a failure never leaves a stored
    // manifest without its anchor. Skipped on the no-profile path (no profile store →
    // no resume anchor; fail-closed — a later resume finds no anchor and re-downloads).
    let fresh = resume.is_none();
    if let Some(profile_root) = profile_root.as_ref().filter(|_| fresh) {
        let digest = match manifest_digest(&manifest) {
            Ok(d) => d,
            Err(e) => {
                return ConfirmOutcome::LocalFailed {
                    message: format!("could not digest the confirmed manifest for resume: {e}"),
                };
            }
        };
        if let Err(e) = ManifestDigestStore::open(profile_root.join(DIGEST_STORE_FILE))
            .and_then(|store| store.record_digest(&share_id, &digest))
        {
            return ConfirmOutcome::LocalFailed {
                message: format!("could not record the resume integrity anchor: {e}"),
            };
        }
        if let Err(e) = staging.persist_manifest(&manifest) {
            return ConfirmOutcome::LocalFailed {
                message: format!("could not persist the confirmed manifest for resume: {e}"),
            };
        }
    }

    let total_chunks: u32 = to_run.iter().map(|p| p.chunks.len() as u32).sum();
    // Seed the bar with the chunks already re-verified this resume so it resumes
    // ahead of zero; the engine then reports cumulative totals over `to_run`.
    let _ = evt_tx.send(NetEvent::FetchProgress {
        total_chunks: Some(total_chunks),
        chunks_received: resumed_verified_chunks as u32,
        bytes_received: 0,
    });

    // The engine's chunk closure: one budget-admitted, SHA-384-verified chunk fetch, discarding
    // the latency Duration (the controller is fed INTERNALLY by `fetch_chunk_budgeted`). The one
    // shared `lease` (Arc) funnels every fetch through the per-route budget (Part 1). Each future
    // owns its captures (handle + share_id + route + the lease Arc), so it borrows nothing
    // external.
    let handle_dl = handle.clone();
    let share_id_dl = share_id.clone();
    let lease_dl = Arc::clone(&lease);
    // Return a `'static + Send` boxed future (owns every capture — handle, share_id, route, and
    // the lease Arc): a concrete, lifetime-free `Fut` type keeps the engine's `run_download`
    // future provably `Send` across the crate boundary. An inline `async move` would give `Fut`
    // a per-call lifetime the cross-crate HRTB `Send` check cannot generalize.
    type ChunkFut = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, VeilidNetError>> + Send>,
    >;
    let fetch_chunk = move |addr: ChunkAddr| -> ChunkFut {
        let handle = handle_dl.clone();
        let share_id = share_id_dl.clone();
        let lease = Arc::clone(&lease_dl);
        let route = route.clone();
        Box::pin(async move {
            handle
                .fetch_chunk_budgeted(route, &share_id, addr, room_key_bytes, &lease)
                .await
                .map(|(bytes, _latency)| bytes)
        })
    };
    let progress_tx = evt_tx.clone();
    let progress = move |chunks_done: u32, bytes_done: u64| {
        let _ = progress_tx.send(NetEvent::FetchProgress {
            total_chunks: Some(total_chunks),
            chunks_received: chunks_done,
            bytes_received: bytes_done,
        });
    };

    // Every selected file was already complete at the dest (a resume with nothing to
    // do): finish without touching the network and clean up the spent staging. Else
    // run the engine over the runnable files and fold in the already-complete count.
    let outcome = if to_run.is_empty() {
        let _ = staging.destroy();
        DownloadOutcome::Complete {
            files: done_files,
            bytes: done_bytes,
        }
    } else {
        match run_download(&to_run, &staging, &fetch_chunk, &progress).await {
            DownloadOutcome::Complete { files, bytes } => DownloadOutcome::Complete {
                files: files + done_files,
                bytes: bytes + done_bytes,
            },
            other => other,
        }
    };

    // Managed dir: on a completed download, register the downloads.idx entry for the
    // already-promoted files — idx-only, no byte re-buffering (#207). Done off-loop here (a
    // quick locked fs op), not in the fold, which has neither the promoted-file list nor a store
    // handle. An idx-registration FAILURE downgrades the outcome to `LocalFailed`: the files are
    // promoted on disk (retained) but not discoverable in the downloads list, so reporting
    // `Complete` would be a silent success — surface the error instead. On success, refresh the
    // browse pane (fs read → evt; no `&mut ShareState`, so it stays in the worker).
    let outcome = match (outcome, &managed_folder) {
        (DownloadOutcome::Complete { files, bytes }, Some(folder)) => {
            match FetchedStore::open(&fetched_root)
                .and_then(|mut store| store.register_share(&share_id, &name, folder, &idx_recs))
            {
                Ok(_) => {
                    emit_fetched_snapshot(&evt_tx, &fetched_root);
                    DownloadOutcome::Complete { files, bytes }
                }
                Err(e) => DownloadOutcome::LocalFailed {
                    message: format!(
                        "download of {share_id} completed on disk but could not be recorded in \
                         the downloads index: {e}"
                    ),
                },
            }
        }
        (outcome, _) => outcome,
    };

    confirm_outcome_from(outcome, share_id, name)
}

/// (download-subsystem redesign, step 8b-2 / DL-ISC-20) The profile-local redb file
/// anchoring each fetch's confirmed-manifest digest for a verified resume. Lives
/// under the private profile root (the client's own trusted state), NOT the
/// co-resident-writable downloads root.
const DIGEST_STORE_FILE: &str = "download-manifest-digests.redb";

/// (download-subsystem redesign, step 6 / DL-ISC-8) Map the engine's [`DownloadOutcome`] onto the
/// frontend's [`ConfirmOutcome`] — the dictated 1:1 mapping (design §"Outcome + fold semantics"):
/// `Complete` → `Complete`; `TransientFailed` → `RouteFailed` (mark Unresolved + park);
/// `IntegrityFailed` → `IntegrityFailed` (poison, no mark/park); `LocalFailed` → `LocalFailed`.
/// Disposition (staging destroy vs retain) already happened inside the engine.
fn confirm_outcome_from(
    outcome: DownloadOutcome,
    share_id: String,
    name: String,
) -> ConfirmOutcome {
    match outcome {
        DownloadOutcome::Complete { files, bytes } => ConfirmOutcome::Complete {
            share_id,
            files_written: files,
            bytes_written: bytes,
        },
        // Transport / route-death / withdrawn: retained verified units, mark Unresolved + park.
        DownloadOutcome::TransientFailed { message } => ConfirmOutcome::RouteFailed {
            share_id,
            name,
            message,
        },
        // Hostile content: the engine already destroyed the staged partials — poison the share.
        DownloadOutcome::IntegrityFailed { message } => {
            ConfirmOutcome::IntegrityFailed { share_id, message }
        }
        // Local disk/path fault: verified units retained; surface the error, no Unresolved mark.
        DownloadOutcome::LocalFailed { message } => ConfirmOutcome::LocalFailed { message },
    }
}

/// (download-subsystem redesign, step 6 / DL-ISC-8) Compute the placement selection roots from the
/// selection kind + the selected files' share `rel_path`s. `Share` → the whole-share root; `File`
/// → the single selected file; `Dir` → the selected files' common parent-directory prefix (so a
/// scattered selection collapses to its shared ancestor). `place_at_dest` then lands each root per
/// the ratified placement table. The GUI's `selection_roots` instead carries the toggled folder's
/// path (F5); the TUI's cardinality-derived selection has no toggled node, so the common prefix is
/// its best available root.
fn selection_roots(root_kind: RootKind, selected_rels: &[&str]) -> Vec<SelectionRoot> {
    match root_kind {
        RootKind::Share => vec![SelectionRoot::Dir(String::new())],
        RootKind::File => match selected_rels.first() {
            Some(rel) => vec![SelectionRoot::File((*rel).to_owned())],
            // Defensive: a File selection with no concrete file falls back to the whole share.
            None => vec![SelectionRoot::Dir(String::new())],
        },
        RootKind::Dir => vec![SelectionRoot::Dir(common_prefix_dir(selected_rels))],
    }
}

/// The common parent-directory prefix of a set of share `rel_path`s (`/`-separated), used as the
/// `Dir` selection root for a folder/scattered selection (DL-ISC-8). Each path's parent
/// (everything before its last `/`) is taken, then their longest common leading component run — so
/// a one-file folder keeps its folder (`a/b/only.mp3` → `a/b`), and scattered files under a shared
/// ancestor collapse to it (`a/b/1`, `a/c/2` → `a`). An empty result is the share root. Mirrors
/// the GUI's `common_prefix_dir`.
fn common_prefix_dir(rels: &[&str]) -> String {
    let dirs: Vec<Vec<&str>> = rels
        .iter()
        .map(|p| {
            let mut comps: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
            comps.pop(); // drop the filename component; keep only the directory path
            comps
        })
        .collect();
    let Some((first, rest)) = dirs.split_first() else {
        return String::new();
    };
    let mut common = first.clone();
    for d in rest {
        let n = common
            .iter()
            .zip(d.iter())
            .take_while(|(a, b)| a == b)
            .count();
        common.truncate(n);
    }
    common.join("/")
}

/// (#197, CRSH-ISC-29) Fold a spawned download's terminal outcome on the actor loop — the only
/// place the download's `&mut ShareState` mutation happens. Success clears the Unresolved mark
/// and drops the parked retry (CRSH-ISC-25 F6) and emits `FetchComplete`; a route-death failure
/// marks the share Unresolved and parks a one-shot retry (never a prune) and emits `FetchError`;
/// an INTEGRITY failure (DL-ISC-13) sets the durable poison flag and emits `FetchError` with NO
/// Unresolved mark and NO parked retry (the route is fine, the content is hostile — the engine
/// already destroyed the staged partials); a local-disk failure emits `FetchError` only (the
/// sharer's route is fine, so no mark).
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
            fetch_fail(evt_tx, message);
        }
        ConfirmOutcome::IntegrityFailed { share_id, message } => {
            // (DL-ISC-13) Poison the share against automatic re-fetch — durable within the
            // session, independent of the discovery lifecycle. NO Unresolved mark, NO parked
            // retry: the route is healthy, the content is hostile, and the engine already
            // destroyed the fetch's staged partials. Per-chunk verification (ISC-A-S20) is the
            // always-on enforcement; this flag is the UX guard.
            shares.poisoned_shares.insert(share_id);
            fetch_fail(evt_tx, message);
        }
        ConfirmOutcome::LocalFailed { message } => {
            fetch_fail(evt_tx, message);
        }
    }
}

/// Translate a `VeilidNetEvent` into the `NetEvent` contract. Inbound sealed bytes
/// are tried against each joined circle's key (the AEAD seal authenticates the
/// match and attributes the frame to that one circle, ISC-A-C30). Our OWN write
/// re-surfaces here via the DHT watch tens of seconds after `send_chat` published
/// it; it is suppressed by sender-handle match so it never renders a delayed
/// duplicate of the app-layer Enter echo. Bytes that open under no circle are
/// tried as a lobby `DiscoveryEnvelope` (share discovery).
fn handle_inbound(
    ev: VeilidNetEvent,
    evt_tx: &UnboundedSender<NetEvent>,
    circles: &[VeilidCircle],
    shares: &mut ShareState,
) {
    let VeilidNetEvent::Inbound { bytes } = ev else {
        // Attachment / RouteChanged / ValueChanged carry no chat/discovery payload.
        return;
    };
    // Own-message suppression keys on the STABLE identity pubkey, not the mutable
    // display handle — the room↔circle convergence's #143 fix (a mid-session
    // rename no longer makes an own DHT-loopback fail the own check and duplicate).
    let own_pubkey = shares.signing.as_ref().map(|s| s.public_key().to_vec());
    let is_own = |pubkey: &[u8]| own_pubkey.as_deref() == Some(pubkey);
    for circle in circles {
        if let Ok(msg) = open_message(&circle.cot_key, &bytes) {
            if !is_own(&msg.sender_pubkey) {
                // ISC-C4/C57: bind the displayed author to the verified pubkey.
                if let Ok(bound) = Handle::display_bound(&msg.sender_handle, &msg.sender_pubkey) {
                    let _ = evt_tx.send(NetEvent::ChatMessage {
                        circle_id: circle.circle_id,
                        sender: bound.format(DisplayMode::Default),
                        body: msg.body,
                        sent_unix_ms: msg.sent_unix_ms,
                    });
                }
            }
            return; // opened under exactly one circle
        }
    }
    // Not a circle message — try it as a public-room (Lobby) chat message before
    // share discovery. Both ride the lobby record; the distinct per-kind AEAD AAD
    // means only the matching open succeeds. Own messages are suppressed by pubkey
    // (the app already echoed on Enter), mirroring the circle path above.
    // Open under an immutable borrow, then fold under a mutable one (WB-ISC-4).
    let lobby_msg = shares
        .lobby
        .as_ref()
        .and_then(|lobby| open_room_message(&lobby.room_key, DEFAULT_ROOM, &bytes).ok());
    if let Some(msg) = lobby_msg {
        if !is_own(&msg.sender_pubkey)
            && let Ok(bound) = Handle::display_bound(&msg.sender_handle, &msg.sender_pubkey)
        {
            let _ = evt_tx.send(NetEvent::PublicRoomMessage {
                // The lobby we opened under — never the untrusted carried `room_id`
                // (LOW-1: the carried field is never trusted; don't leak it here).
                room: DEFAULT_ROOM.to_owned(),
                sender: bound.format(DisplayMode::Default),
                body: msg.body,
                sent_unix_ms: msg.sent_unix_ms,
            });
            // WB-ISC-4 (after the message, chat is primary): a verified same-room
            // chat write advances the sender's roster freshness — read-side fold,
            // emits nothing.
            // #165: gate the presence fold on beacon freshness, as the beacon fold
            // does below — a replayed old chat write must not re-freshen a departed
            // member. Message delivery is unaffected.
            if beacon_is_fresh(msg.sent_unix_ms, now_unix_ms())
                && let Some(lobby) = shares.lobby.as_mut()
            {
                let _ = lobby.presence.apply_member_write(
                    DEFAULT_ROOM,
                    &msg.sender_pubkey,
                    &msg.sender_handle,
                    msg.sent_unix_ms,
                    Instant::now(),
                );
            }
        }
        return;
    }
    // Not a chat message — try it as a lobby member-presence heartbeat (#74). A
    // beacon rides the SEPARATE presence record but arrives as the same Inbound
    // (no record tag); the distinct heartbeat AAD means only a real beacon opens.
    // Fold a verified, fresh, non-own beacon into the tracker (no roster render in
    // the TUI — it maintains the tracker like the relay TUI). Read our own pubkey
    // before the `&mut lobby` borrow to avoid aliasing `shares`.
    let own_pubkey = shares.signing.as_ref().map(|s| s.public_key().to_vec());
    if let Some(lobby) = shares.lobby.as_mut()
        && let Ok(hb) = open_heartbeat(&lobby.room_key, &bytes)
    {
        let is_own = own_pubkey
            .as_deref()
            .is_some_and(|pk| pk == hb.sender_pubkey.as_slice());
        // #78 replay-freshness drops a captured/replayed or future-dated beacon.
        if !is_own && beacon_is_fresh(hb.sent_unix_ms, now_unix_ms()) {
            let _ = lobby.presence.apply(&hb, Instant::now());
        }
        return;
    }
    // Not a heartbeat — try it as a lobby share-discovery item.
    let _ = apply_discovery(shares, evt_tx, &bytes);
}

/// The jittered lobby presence-KEEPALIVE interval — [180, 220]s (WB-1.2), well
/// above the ~14.7s DHT watch floor and under the WB-2 write ceiling. Presence is a
/// read question moved to the read side; the write cadence takes NO input from user
/// activity (WB-0) and re-draws fresh per emission (no fixed period / phase-lock).
fn veilid_keepalive_interval() -> Duration {
    next_keepalive_interval()
}

/// Emit one sealed lobby presence beacon (#74) to the presence record, then reap
/// the lobby tracker (the timer is the reap clock). A missing identity/lobby, a
/// seal failure, or a closed transport is non-fatal — presence self-heals on the
/// next tick. Lobby-only; circle presence is #77. The TUI does not push a roster
/// event (it has none — it applies/reaps like the relay TUI); emitting is what
/// makes this node visible on other clients' rosters.
///
/// The DHT publish is **spawned off the actor loop** (like `send_chat`, the #128
/// D-0b pattern): awaiting the write's ack inline in the select arm would stall the
/// loop for seconds every ~15–20 s. The reap is a fast in-memory op and stays inline.
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

/// Seal and publish ONE lobby presence beacon (WB-1 join / keepalive / leave, per
/// `boundary`), spawning the DHT write off the actor loop. Fixed-length (WB-ISC-6)
/// with an EMPTY digest — share liveness rides the share record post-#153.
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
                daemonseed_veilid_net::vtrace!("tui presence: {boundary:?} emit failed: {e}");
            }
        });
    }
}

fn emit_and_reap_lobby_presence(
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    my_handle: &Option<String>,
    shares: &mut ShareState,
) {
    // WB-5.1 / I5″.6/.7: fold the scheduler's published median DHT-weather through the
    // ReapGate (hysteresis band 8s/4s + 220s resume grace) into "suspend reaping now",
    // so a keepalive merely queued in an elevated regime does not false-reap its member.
    let now = Instant::now();
    let weather_ms = net.as_ref().map(|h| h.last_write_latency_ms()).unwrap_or(0);
    shares.reap_gate.observe(weather_ms, now);
    let suspend = shares.reap_gate.suspend_reaping(now);
    if let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone())
        && let Some(lobby) = shares.lobby.as_ref()
    {
        spawn_public_beacon(
            handle,
            &signing,
            &lobby.room_key,
            lobby.presence_owner_seed,
            my_handle.as_deref().unwrap_or("guest"),
            PresenceBoundary::Keepalive,
        );
    }
    // Reap only in calm (the timer is the reap clock).
    if let Some(lobby) = shares.lobby.as_mut() {
        let _ = lobby.presence.reap(now, suspend);
    }
    // WB-ISC-20: "presence may be stale" — computed after the reap, emitted on change.
    let stale = shares
        .lobby
        .as_ref()
        .is_some_and(|l| l.presence.stale_suspected(now, suspend));
    if stale != shares.prev_presence_stale {
        shares.prev_presence_stale = stale;
        let _ = evt_tx.send(NetEvent::PresenceStale { stale });
    }
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
            "tui lobby: dropping own announcement for {} (self-filter, #116)",
            ann.share_id
        );
        return true; // consumed: our own announcement is never a discovered share
    }
    // #156 route-import gate (STANDALONE — not a reliance on the catalog wiring):
    // never touch the route map for a share whose announcement fails the
    // receiver-verifiable binding check. Drops a non-derivable announcement before
    // it can reach either the route map or the catalog.
    if !share_binding_is_valid(&ann) {
        daemonseed_veilid_net::vtrace!(
            "tui lobby: dropping discovery for {} — v2 share_id binding failed (#156)",
            ann.share_id
        );
        return true; // consumed-and-dropped; no route, no catalog fold
    }
    let now = Instant::now();
    if ann.withdraw {
        let change = shares.catalog.apply_verified(&ann, now);
        // #152: gate the ROUTE map on the catalog decision — a forged withdraw
        // (foreign key → owner-mismatch → `Unchanged`) must not evict the owner's
        // route (the fetch path reads `discovered`, not the catalog).
        if change == CatalogChange::Removed {
            shares.discovered.remove(&ann.share_id);
            // (#180 §RS-1.4, CRSH-ISC-19) A verified withdraw drops any parked browse
            // retry: the episode is over, so a later re-add never fires a stale retry.
            shares.parked_retries.remove(&ann.share_id);
            // (#180 §RS-3, CRSH-ISC-26) Release the withdrawn share's imported route and
            // drop its guard entry — immediately when idle, or deferred to any in-flight
            // fetch's completion. Without this the route leaks until the veilid LRU evicts
            // it and `route_guard` grows unbounded across discovery churn. The loop drains
            // `pending_route_releases` via `release_tolerant`, like the advert-replace path.
            if let Some(route) = shares.route_guard.note_share_withdrawn(&ann.share_id) {
                shares.pending_route_releases.push(route);
            }
            emit_shares_snapshot(shares, evt_tx);
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
            "tui lobby: dropping discovery for {} — route advert failed verify",
            ann.share_id
        );
        return true; // consumed-and-dropped; do not fall through
    }
    let change = shares.catalog.apply_verified(&ann, now);
    // (#180 route-rotation self-heal, CRSH-ISC-12) A route rotation must re-import even
    // when the catalog folds `Unchanged`. After a sharer restart / route-death its
    // watchdog re-advertises the SAME sealed advert — same `sent_unix_ms` + metadata,
    // only the `route_blob` rotated — which the F3 Unchanged arm folds `Unchanged`
    // (`route_blob` lives in `discovered`, not the catalog). Without an independent blob
    // check the rotated route is dropped and the consumer stays wedged on the dead route
    // until it restarts. Security (#152/#156): honoring this does NOT reopen the hijack
    // path — an announce only reaches here after `share_binding_is_valid` (#156:
    // `share_id == derive_share_id_v2(sender_pubkey, ...)`) AND `verify_route_advert`, so
    // `env.route_blob` is provably the id's verified owner's rotated route.
    let route_changed = shares
        .discovered
        .get(&ann.share_id)
        .is_some_and(|d| d.route_blob != env.route_blob);
    if change != CatalogChange::Unchanged || route_changed {
        // (#180 §RS-3, CRSH-ISC-10) Read the prior entry BEFORE mutating: the re-resolve flag,
        // and whether this advert CHANGES the route blob — only a real blob change supersedes
        // the imported route (an identical re-advert re-imports to the same id, Evidence 2).
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
                sender_pubkey: ann.sender_pubkey.clone(),
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
        emit_shares_snapshot(shares, evt_tx);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_veilid_net::route_provenance_input;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn steady_resweep_hands_off_within_a_short_connect_window() {
        // The TUI has no stepped warmup schedule, so the hand-off must clear the
        // connect-time subscribe/login-sweep burst yet stay short enough that it is not a
        // dead window with no re-surfacing (review finding) — a sensible band, not >0.
        assert!(STEADY_RESWEEP_WARMUP_HANDOFF >= Duration::from_secs(10));
        assert!(STEADY_RESWEEP_WARMUP_HANDOFF <= Duration::from_secs(45));
    }

    /// Drive the actor with one command and return its first emitted event,
    /// WITHOUT a live Veilid node. Every arm exercised here emits synchronously
    /// (no `attach`/`subscribe`/`publish` await), so this never touches the
    /// network. The actor is never awaited to completion — it holds a self-send
    /// handle so its command channel never closes; the runtime aborts the spawned
    /// task at test end.
    async fn first_event(cmd: NetCommand) -> NetEvent {
        let (cmd_tx, cmd_rx) = unbounded_channel();
        // The actor's `_cmd_tx` is a distinct, unused channel here.
        let (self_tx, _self_rx) = unbounded_channel();
        let (evt_tx, mut evt_rx) = unbounded_channel();
        tokio::spawn(veilid_net_actor(cmd_rx, self_tx, evt_tx));
        cmd_tx.send(cmd).expect("actor is alive");
        let ev = tokio::time::timeout(Duration::from_secs(2), evt_rx.recv())
            .await
            .expect("actor emitted no event in time")
            .expect("event channel closed");
        drop(cmd_tx);
        ev
    }

    #[tokio::test]
    async fn join_circle_before_connect_fails() {
        let ev = first_event(NetCommand::JoinCircle {
            phrase: "correct horse battery staple".to_owned(),
        })
        .await;
        match ev {
            NetEvent::CircleJoinFailed { message } => {
                assert!(message.contains("not connected"), "got: {message}");
            }
            other => panic!("expected CircleJoinFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_chat_before_join_errors() {
        let ev = first_event(NetCommand::SendChat {
            circle_id: 0,
            body: "hi".to_owned(),
            sender_handle: "alice#abcd".to_owned(),
        })
        .await;
        match ev {
            NetEvent::ChatError { message } => {
                assert!(message.contains("join a circle"), "got: {message}");
            }
            other => panic!("expected ChatError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn refresh_shares_emits_an_empty_snapshot() {
        // With no lobby/discovery yet, RefreshShares answers with an empty
        // three-field snapshot (the TUI contract), NOT a "not yet" error.
        let ev = first_event(NetCommand::RefreshShares).await;
        match ev {
            NetEvent::SharesSnapshot {
                local,
                remote,
                indexer_status,
            } => {
                assert!(local.is_empty());
                assert!(remote.is_empty());
                assert_eq!(indexer_status, IndexerStatus::Idle);
            }
            other => panic!("expected SharesSnapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn refresh_public_space_is_not_yet_on_veilid() {
        let ev = first_event(NetCommand::RefreshPublicSpace).await;
        match ev {
            NetEvent::PublicSpaceError { message } => assert_eq!(message, NOT_YET),
            other => panic!("expected PublicSpaceError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_share_without_a_connection_reports_a_clean_error() {
        // The first check is the connection — with no Veilid node, PublishShare
        // surfaces a clean PublishError carrying root=None (a pre-flight failure
        // that never started an index), NOT the generic "not yet" stub.
        let root = std::path::PathBuf::from("/tmp/share");
        let ev = first_event(NetCommand::PublishShare {
            root: root.clone(),
            name: "docs".to_owned(),
            sharer_handle: "alice#abcd".to_owned(),
        })
        .await;
        match ev {
            NetEvent::PublishError { message, root: r } => {
                assert!(
                    message.contains("not connected"),
                    "expected a not-connected publish error, got: {message}"
                );
                assert_eq!(r, None, "a pre-flight failure carries no root");
            }
            other => panic!("expected PublishError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_fetched_yields_empty_snapshot_for_an_empty_root() {
        let dir = tempfile::tempdir().unwrap();
        let ev = first_event(NetCommand::ListFetched {
            fetched_root: dir.path().to_path_buf(),
        })
        .await;
        match ev {
            NetEvent::FetchedShares { shares } => assert!(shares.is_empty()),
            other => panic!("expected empty FetchedShares, got {other:?}"),
        }
    }

    // ── Public-share discovery + anti-swap (Phase 3 Slice 2b) ──

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

    /// A verified inbound lobby chat message (sealed under the public room key by a
    /// peer) surfaces as a `PublicRoomMessage` — the Veilid lobby-chat ingest path.
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
        // No signing key in `shares` → nothing is `own` → the peer message surfaces.
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &[],
            &mut shares,
        );
        // `sender` is bound to the signer's pubkey (ISC-C4/C57): a self-asserted
        // handle whose hash disagrees is shown at its `#<prefix>` floor.
        let expected_sender =
            Handle::display_bound("river-otter#aabbccddeeff", signer.public_key().as_slice())
                .unwrap()
                .format(DisplayMode::Default);
        match evt_rx.try_recv() {
            Ok(NetEvent::PublicRoomMessage {
                room, sender, body, ..
            }) => {
                assert_eq!(room, DEFAULT_ROOM);
                assert_eq!(sender, expected_sender);
                assert_eq!(body, "hello lobby");
            }
            other => panic!("expected a PublicRoomMessage, got {other:?}"),
        }
    }

    /// Our own lobby message re-surfaces via the DHT sweep; the app already echoed
    /// it on Enter, so the inbound copy is suppressed — no double render. #143:
    /// suppression keys on the STABLE pubkey, not the mutable handle.
    #[test]
    fn handle_inbound_suppresses_our_own_looped_back_lobby_message() {
        let me = std::sync::Arc::new(announcer(32));
        let my_handle = "me#aabbccddeeff";
        let mut shares = ShareState::new();
        shares.lobby = Some(lobby());
        shares.signing = Some(std::sync::Arc::clone(&me));
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
            &[],
            &mut shares,
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "our own looped-back lobby message must be suppressed (keyed on pubkey)"
        );
    }

    /// `SendPublicRoom` with no lobby subscribed reports a clean error rather than
    /// panicking or silently dropping.
    #[tokio::test]
    async fn send_public_room_without_a_lobby_reports_a_clean_error() {
        let ev = first_event(NetCommand::SendPublicRoom {
            body: "hi".to_owned(),
            sender_handle: "alice#abcd".to_owned(),
        })
        .await;
        match ev {
            NetEvent::PublicRoomJoinFailed { message } => {
                assert!(message.contains("no public room"), "got: {message}");
            }
            other => panic!("expected PublicRoomJoinFailed, got {other:?}"),
        }
    }

    /// Build a lobby `DiscoveryEnvelope`: a sealed self-signed announcement plus a
    /// route advert signed over `share_id ‖ route_blob`. `blob_to_advertise` is
    /// what the envelope carries; `blob_to_sign` is what the signature commits to
    /// (equal for an honest item, differing to model a MITM route swap).
    /// Derive a v2-valid `(share_id, root_commitment)` pair for `signer` publishing
    /// `root` (#156), so an announcement built from them passes the ingest binding.
    fn v2_ids(signer: &SignKeypair, root: &str) -> (String, Vec<u8>) {
        let ikm = [0x5au8; 32];
        let nonce = derive_share_root_nonce(&ikm, root);
        let rc = derive_root_commitment(root, &nonce);
        let share_id = derive_share_id_v2(signer.public_key(), &rc);
        (share_id, rc.to_vec())
    }

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

    /// A self-signed WITHDRAW envelope (the withdraw path never checks the route
    /// advert, so the route fields are inert); `sent_unix_ms` is fresh so a rejection
    /// can only come from the binding / owner-check.
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

    /// #152 (finding 3): a foreign forged withdraw must NOT evict the owner's route.
    #[test]
    fn a_forged_withdraw_cannot_evict_the_owners_route() {
        let victim = announcer(41);
        let attacker = announcer(42);
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());

        let (share_id, rc) = v2_ids(&victim, "/victim/root");
        let vblob = vec![0x11; 96];
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &victim, &share_id, &rc, &vblob, &vblob)
        ));
        let _ = evt_rx.try_recv();

        // Attacker pairs the victim's (share_id, rc) with its own key: the #156
        // binding check fails → dropped before the withdraw branch, route survives.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &attacker, &share_id, &rc)
        ));
        assert_eq!(shares.catalog.len(), 1, "the victim's share survives");
        assert_eq!(
            shares
                .discovered
                .get(&share_id)
                .map(|d| d.route_blob.clone()),
            Some(vblob),
            "the owner's route is NOT evicted"
        );
        assert!(evt_rx.try_recv().is_err(), "no-op → no snapshot");
    }

    /// #152 (finding 1): a hijack re-announce must NOT replace the owner's route.
    #[test]
    fn a_hijack_reannounce_cannot_replace_the_owners_route() {
        let victim = announcer(43);
        let attacker = announcer(44);
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

        // Attacker re-announces the victim's (share_id, rc) under its own key: the
        // #156 binding check fails, so the route map is never touched.
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
        assert!(evt_rx.try_recv().is_err(), "hijack rejected → no snapshot");
    }

    #[test]
    fn apply_discovery_folds_in_an_honest_signed_item_and_keeps_its_route() {
        let signer = announcer(11);
        let mut shares = ShareState::new();
        // Re-derive the room key for the envelope (the one in `lobby()` is moved in).
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());

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
            matches!(
                evt_rx.try_recv(),
                Ok(NetEvent::SharesSnapshot { remote, .. }) if remote.len() == 1
            ),
            "a SharesSnapshot listing the share is emitted"
        );
    }

    /// Fold one honest share ready for the reactive-path tests.
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

    // ── CRSH-ISC-4/5: a fetch failure marks the share Unresolved (local only), keeps it
    //    listed, and never prunes; a verified withdraw is what removes it ───────────────
    #[test]
    fn crsh_isc_5_fetch_fail_stays_listed_until_verified_withdraw() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(32);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // Fetch failed → Unresolved, still listed, parked retry, NOT pruned. The reactive
        // helper takes no network handle, so it cannot emit a DHT op (CRSH-ISC-4).
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        assert!(shares.discovered.get(&share_id).unwrap().unresolved);
        assert!(shares.parked_retries.contains_key(&share_id));
        assert_eq!(shares.catalog.len(), 1, "the share is NOT pruned");
        match evt_rx.try_recv() {
            Ok(NetEvent::SharesSnapshot { remote, .. }) => {
                let row = remote.iter().find(|s| s.share_id == share_id).unwrap();
                assert!(row.unresolved, "listed, marked re-resolving");
            }
            other => panic!("expected a SharesSnapshot, got {other:?}"),
        }

        // The owner's verified withdraw removes it.
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &signer, &share_id, &rc)
        ));
        assert_eq!(
            shares.catalog.len(),
            0,
            "a verified withdraw removes the share"
        );
    }

    // ── CRSH-ISC-5 (download-fail variant): a failed DOWNLOAD keeps the share listed ──────
    /// `confirm_fetch`'s import-fail, manifest-fail, and download-stage (chunk-fetch)
    /// failures all mark the share Unresolved instead of pruning — a download-fail is
    /// route-death, not an authoritative removal. The share stays listed with its route
    /// intact (the parked retry re-resolves it); only a verified withdraw / catalog TTL
    /// removes it.
    #[test]
    fn crsh_isc_5_download_fail_keeps_share_listed_with_route() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(13);
        let (evt_tx, _rx) = unbounded_channel();

        // The download path's failure effect (import / manifest / chunk-fetch fail all funnel
        // through `mark_share_unresolved` now that the prunes are retired).
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        assert_eq!(
            shares.catalog.len(),
            1,
            "a failed download keeps the share listed"
        );
        assert!(
            shares.discovered.contains_key(&share_id),
            "the discovered route is retained so the parked retry can re-resolve"
        );
        assert!(shares.parked_retries.contains_key(&share_id));

        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &signer, &share_id, &rc)
        ));
        assert_eq!(shares.catalog.len(), 0, "a verified withdraw removes it");
    }

    // ── CRSH-ISC-27 (#180 route-rotation self-heal): a rotated route re-imports on catalog Unchanged ──
    /// Mirror of the GUI probe: after a sharer restart / route-death the watchdog re-advertises
    /// the SAME sealed advert (same `sent_unix_ms` + metadata) with only the `route_blob` rotated,
    /// which folds `Unchanged`. The consumer STILL re-imports the rotated route (un-wedging without
    /// restart), stamps a fresh generation, and — per the reframe (CRSH-ISC-6) — marks the share
    /// fetchable-again (clears Unresolved, drops the park) since a route rotation IS the refresh;
    /// an identical re-read (no rotation) still folds with no generation churn (F3 preserved).
    #[test]
    fn crsh_isc_27_route_rotation_reimports_on_catalog_unchanged() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(43);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // The consumer's fetch died on the old route → Unresolved + a parked browse retry.
        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        while evt_rx.try_recv().is_ok() {} // drain the mark's snapshot(s)
        let gen_before = shares.discovered.get(&share_id).unwrap().generation;
        let old_blob = shares.discovered.get(&share_id).unwrap().route_blob.clone();

        // Same advert (sent_unix_ms=1000 + metadata), ROTATED route blob — the restart shape.
        let new_blob = vec![0xCD; 96];
        assert_ne!(
            new_blob, old_blob,
            "the rotated blob differs from the dead one"
        );
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &rc, &new_blob, &new_blob);
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes));

        assert_eq!(
            shares.catalog.len(),
            1,
            "the catalog folds Unchanged, no new entry"
        );
        let d = shares.discovered.get(&share_id).unwrap();
        assert_eq!(
            d.route_blob, new_blob,
            "the rotated route is re-imported on Unchanged"
        );
        assert!(
            d.generation > gen_before,
            "a fresh generation supersedes the dead route"
        );
        // Reframe (CRSH-ISC-6): a route rotation IS the route refresh → fetchable-again.
        assert!(
            !d.unresolved,
            "the route rotation marks the share fetchable-again (Unresolved cleared)"
        );
        assert!(
            !shares.parked_retries.contains_key(&share_id),
            "the route rotation drops the fetch-failure park"
        );
        assert!(
            evt_rx.try_recv().is_ok(),
            "a shares snapshot is emitted on the re-import"
        );
        while evt_rx.try_recv().is_ok() {}

        // F3 no-churn preserved: an identical re-read (same blob) bumps nothing, emits nothing.
        let gen_after = shares.discovered.get(&share_id).unwrap().generation;
        let bytes_same = discovery_bytes(&room_key, &signer, &share_id, &rc, &new_blob, &new_blob);
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes_same));
        assert_eq!(
            shares.discovered.get(&share_id).unwrap().generation,
            gen_after,
            "an identical re-read does not bump the generation (F3 preserved)"
        );
        assert!(
            evt_rx.try_recv().is_err(),
            "an identical re-read emits no snapshot"
        );
    }

    // ── CRSH-ISC-25 (#180 F6): a completed download clears the Unresolved mark + parked retry ──
    /// A failed-then-retried download that SUCCEEDS must resolve the share — symmetric with the
    /// download-failure `mark_share_unresolved` and the browse-preview-success clear in
    /// `fold_fetch_outcome`. `confirm_fetch`'s success tail calls `clear_share_unresolved` before
    /// BOTH `FetchComplete` emissions (flat-dest and managed-dir); that clear seam is exercised
    /// here directly (the full `confirm_fetch` needs a live veilid handle + real chunk I/O to
    /// reach the tail, so the byte-transfer portion is live-only). Without the clear the share
    /// strands "re-resolving" and its stale parked retry fires a redundant browse fetch.
    #[test]
    fn crsh_isc_25_download_success_clears_unresolved_and_parked_retry() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(37);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        // Precondition: a prior download failed → Unresolved + a parked browse retry.
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
        match evt_rx.try_recv() {
            Ok(NetEvent::SharesSnapshot { remote, .. }) => {
                let row = remote.iter().find(|s| s.share_id == share_id).unwrap();
                assert!(
                    !row.unresolved,
                    "the listed share is no longer re-resolving"
                );
            }
            other => panic!("expected a SharesSnapshot, got {other:?}"),
        }
    }

    // ── CRSH-ISC-19: a verified withdraw drops the parked retry ────────────────────────
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

    // ── CRSH-ISC-6: window expiry surfaces failure without pruning ─────────────────────
    #[test]
    fn crsh_isc_6_window_expiry_surfaces_error_without_pruning() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(35);
        let (evt_tx, mut evt_rx) = unbounded_channel();
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

    // ── CRSH-ISC-6 (reframe #180) finding-1 guard: a content re-advert does NOT mark fetchable ──
    /// A content-only re-advert (fresher timestamp, SAME route blob) folds `Updated` and bumps
    /// the generation, but it is NOT a route refresh — so the share must STAY `Unresolved`. Only
    /// an actual route rotation (`crsh_isc_27_*`) clears it.
    #[test]
    fn crsh_isc_6_content_readvert_does_not_mark_fetchable() {
        let (mut shares, share_id, room_key, signer, rc) = folded_share(36);
        let (evt_tx, mut evt_rx) = unbounded_channel();

        mark_share_unresolved(&mut shares, &evt_tx, &share_id, "demo-share");
        while evt_rx.try_recv().is_ok() {} // drain the mark's snapshot(s)
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

    // ── CRSH-ISC-6 (reframe #180): a Fire tick drops a stale park without clearing ─────
    /// With the mark-fetchable owned by the route-rotation fold (`apply_discovery`), a park
    /// reaching `Fire` saw a generation bump WITHOUT a route rotation (a content-only re-advert)
    /// — so the tick drops the stale park and does NOT clear `Unresolved`.
    #[test]
    fn crsh_isc_6_fire_drops_stale_park_without_clearing() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(46);
        let (evt_tx, mut evt_rx) = unbounded_channel();
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
    #[tokio::test]
    async fn crsh_isc_8_actor_never_awaits_a_fetch_inline() {
        let (outcome_tx, mut outcome_rx) = unbounded_channel::<FetchOutcome>();
        let gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let gate_fetch = gate.clone();

        let on_panic = FetchOutcome::ImportFailed {
            share_id: "s".to_owned(),
            name: "demo".to_owned(),
            generation: 1,
            message: "panic".to_owned(),
        };
        spawn_fetch_task(outcome_tx, on_panic, async move {
            gate_fetch.notified().await;
            FetchOutcome::ImportFailed {
                share_id: "s".to_owned(),
                name: "demo".to_owned(),
                generation: 1,
                message: "blocked fetch released".to_owned(),
            }
        });

        let mut order: Vec<&str> = vec!["dispatched-fetch"];
        order.push("chat"); // stands in for handle_command(SendChat)
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

        let on_panic = ConfirmOutcome::LocalFailed {
            message: "panic".to_owned(),
        };
        spawn_confirm_task(outcome_tx, on_panic, move || async move {
            gate_dl.notified().await;
            ConfirmOutcome::Complete {
                share_id: "s".to_owned(),
                files_written: 1,
                bytes_written: 42,
            }
        });

        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the download has NOT resolved — the loop did not await it inline"
        );

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
    /// not at all + emits FetchError only. The semantic-parity guard for the off-loop move.
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

    // ── download-subsystem redesign, step 6: engine adoption (parity with the GUI) ──────
    /// (DL-ISC-8) `selection_roots` maps the confirmed selection kind to placement roots: a share
    /// → the whole-share root; a file → that one file; a folder/scattered selection → the selected
    /// files' common parent-directory prefix (a one-file folder keeps its folder).
    #[test]
    fn selection_roots_map_node_kind_to_placement_roots() {
        // Share → whole-share root, regardless of the selected rels.
        assert_eq!(
            selection_roots(RootKind::Share, &["a/1.txt", "b/2.txt"]),
            vec![SelectionRoot::Dir(String::new())]
        );
        // File → the single selected file.
        assert_eq!(
            selection_roots(RootKind::File, &["Artist/Album/song.mp3"]),
            vec![SelectionRoot::File("Artist/Album/song.mp3".to_owned())]
        );
        // Dir, one-file folder → keeps the folder (the reproduced defect the design fixes).
        assert_eq!(
            selection_roots(RootKind::Dir, &["Artist/Album/only.mp3"]),
            vec![SelectionRoot::Dir("Artist/Album".to_owned())]
        );
        // Dir, scattered files under a shared ancestor → collapse to it.
        assert_eq!(
            selection_roots(RootKind::Dir, &["Artist/A/1.mp3", "Artist/B/2.mp3"]),
            vec![SelectionRoot::Dir("Artist".to_owned())]
        );
    }

    /// `common_prefix_dir` takes the longest common PARENT-dir component run (never the filename),
    /// so a lone file keeps its directory and unrelated tops collapse to the share root.
    #[test]
    fn common_prefix_dir_is_the_parent_directory_prefix() {
        assert_eq!(common_prefix_dir(&["a/b/c.txt"]), "a/b");
        assert_eq!(common_prefix_dir(&["a/b/1", "a/b/2"]), "a/b");
        assert_eq!(common_prefix_dir(&["a/b/1", "a/c/2"]), "a");
        assert_eq!(common_prefix_dir(&["top.txt"]), "");
        assert_eq!(common_prefix_dir(&["x/1", "y/2"]), "");
        assert_eq!(common_prefix_dir(&[]), "");
    }

    /// (DL-ISC-8) `confirm_outcome_from` maps the four engine `DownloadOutcome` classes onto the
    /// four `ConfirmOutcome` variants exactly, threading share id + name where each needs them —
    /// `IntegrityFailed` carries the share id the poison fold keys on, `RouteFailed` carries both.
    #[test]
    fn download_outcome_maps_to_confirm_outcome() {
        let complete = confirm_outcome_from(
            DownloadOutcome::Complete {
                files: 3,
                bytes: 300,
            },
            "sid".to_owned(),
            "Album".to_owned(),
        );
        assert!(matches!(
            complete,
            ConfirmOutcome::Complete {
                files_written: 3,
                bytes_written: 300,
                ..
            }
        ));

        let transient = confirm_outcome_from(
            DownloadOutcome::TransientFailed {
                message: "route died".to_owned(),
            },
            "sid".to_owned(),
            "Album".to_owned(),
        );
        assert!(
            matches!(transient, ConfirmOutcome::RouteFailed { ref share_id, ref name, .. } if share_id == "sid" && name == "Album")
        );

        let integrity = confirm_outcome_from(
            DownloadOutcome::IntegrityFailed {
                message: "sha-384 mismatch".to_owned(),
            },
            "sid".to_owned(),
            "Album".to_owned(),
        );
        assert!(
            matches!(integrity, ConfirmOutcome::IntegrityFailed { ref share_id, .. } if share_id == "sid")
        );

        let local = confirm_outcome_from(
            DownloadOutcome::LocalFailed {
                message: "disk full".to_owned(),
            },
            "sid".to_owned(),
            "Album".to_owned(),
        );
        assert!(matches!(local, ConfirmOutcome::LocalFailed { .. }));
    }

    /// (DL-ISC-13) The fold of an `IntegrityFailed` outcome sets the durable poison flag and emits
    /// `FetchError`, but does NOT mark the share Unresolved and does NOT park a one-shot retry —
    /// the route is fine, the content is hostile (the engine already destroyed the staged
    /// partials). Distinct from `RouteFailed` (which marks + parks) and `LocalFailed`.
    #[test]
    fn fold_integrity_failed_poisons_without_mark_or_park() {
        let (mut shares, share_id, _rk, _s, _rc) = folded_share(31);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(!shares.discovered.get(&share_id).unwrap().unresolved);
        fold_confirm_outcome(
            &mut shares,
            &evt_tx,
            ConfirmOutcome::IntegrityFailed {
                share_id: share_id.clone(),
                message: "the sharer served content that failed verification".to_owned(),
            },
        );
        assert!(
            shares.poisoned_shares.contains(&share_id),
            "IntegrityFailed sets the durable poison flag"
        );
        assert!(
            !shares.discovered.get(&share_id).unwrap().unresolved,
            "IntegrityFailed does NOT mark the share Unresolved (the route is fine)"
        );
        assert!(
            shares.parked_retries.is_empty(),
            "IntegrityFailed parks no retry (the content is hostile, not the route)"
        );
        assert!(
            std::iter::from_fn(|| evt_rx.try_recv().ok())
                .any(|e| matches!(e, NetEvent::FetchError { .. })),
            "IntegrityFailed emits FetchError"
        );
    }

    /// (#207 / DL-ISC-14) A panicking download worker still yields a terminal outcome: the
    /// `spawn_confirm_task` seam drives the (non-`Send`) future on a current-thread runtime under
    /// `catch_unwind`, mapping a panic to the caller-supplied terminal `on_panic` outcome, so a
    /// panicking worker never strands the share awaiting an outcome that never arrives.
    #[tokio::test]
    async fn a_panicking_download_worker_yields_a_terminal_outcome() {
        let (outcome_tx, mut outcome_rx) = unbounded_channel::<ConfirmOutcome>();
        let on_panic = ConfirmOutcome::LocalFailed {
            message: "the download task panicked".to_owned(),
        };
        spawn_confirm_task(outcome_tx, on_panic, move || async move {
            panic!("worker blew up mid-download");
        });
        let outcome = outcome_rx
            .recv()
            .await
            .expect("a terminal outcome arrives despite the panic");
        assert!(
            matches!(outcome, ConfirmOutcome::LocalFailed { .. }),
            "a JoinError folds to the terminal on_panic outcome (got {outcome:?})"
        );
    }

    // ── CRSH-ISC-7: a failing-fetch storm never delays chat past the I4 bound ──────────
    /// Anti (paused-time): a storm of slow failing fetches is dispatched, then a chat
    /// dispatch runs — and completes within the WB-3 I4 chat bound (≤ 2s), because every
    /// fetch is spawned off-loop and none is awaited on the dispatch path.
    #[tokio::test(start_paused = true)]
    async fn crsh_isc_7_failing_fetch_storm_never_delays_chat() {
        const I4_BOUND: Duration = Duration::from_secs(2);
        let (outcome_tx, mut outcome_rx) = unbounded_channel::<FetchOutcome>();

        let start = Instant::now();
        for i in 0..16 {
            let tx = outcome_tx.clone();
            let on_panic = FetchOutcome::ImportFailed {
                share_id: format!("s{i}"),
                name: "demo".to_owned(),
                generation: 1,
                message: "panic".to_owned(),
            };
            spawn_fetch_task(tx, on_panic, async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                FetchOutcome::ImportFailed {
                    share_id: format!("s{i}"),
                    name: "demo".to_owned(),
                    generation: 1,
                    message: "storm".to_owned(),
                }
            });
        }
        let chat_dispatch_elapsed = start.elapsed();
        assert!(
            chat_dispatch_elapsed <= I4_BOUND,
            "chat dispatched within the I4 bound ({chat_dispatch_elapsed:?} ≤ {I4_BOUND:?})"
        );
        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the storm is still in flight when chat dispatches"
        );

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
    /// A live-generation failure takes effect (Unresolved + parked retry); then the share is
    /// WITHDRAWN and a stale outcome folds — it MUST drop: no re-park against a gone share, no
    /// resurrection, no event. The fresh-advert half (which now re-parks) is CRSH-ISC-23.
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

        // The share is WITHDRAWN mid-flight; a stale outcome folds. The entry is gone, so the
        // drop is correct: NO re-park, no resurrection, no event.
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
    /// A parked retry FIRED at generation G (removing itself) and re-fetched; while that fetch
    /// was in flight a FRESH ADVERT folded, advancing the discovered generation to G+1. The
    /// in-flight outcome folds stale (tagged G, entry now G+1). Pre-fix it was dropped,
    /// stranding the share Unresolved-with-no-retry forever. Post-fix it re-parks at the
    /// OUTCOME's generation G so a cursor tick Fires it against the newer advert (G+1 > G).
    #[test]
    fn crsh_isc_23_fresh_advert_staleness_re_parks_the_browse_retry() {
        let (mut shares, share_id, _rk, _signer, _rc) = folded_share(37);
        let (evt_tx, mut evt_rx) = unbounded_channel();

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
        // swaps in `rogue` as the advertised route blob. Binding passes (genuine id),
        // then the route-advert verify fails on the swap.
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
}
