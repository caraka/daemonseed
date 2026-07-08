//! Parallel Veilid-backed net actor (#98 S2 + Phase 3 Slice 2b), compiled only
//! under the `veilid` feature.
//!
//! It implements the SAME `NetCommand` / `NetEvent` contract the relay actor in
//! [`crate::net`] does, so the UI is unchanged — the only switch is which actor
//! [`crate::net::NetHandle::new`] spawns (a `#[cfg(feature = "veilid")]` branch).
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
//! [`verify_route_advert`](daemonseed_veilid_net::verify_route_advert)s the route
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_cli::public_space::{
    post_render_fields, render_motd, sign_motd, sign_post, verify_served_motd, verify_served_post,
};
use daemonseed_cli::route_signer::IdentityRouteAdvertSigner;
use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::{
    CircleKey, derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
    derive_cot_key,
};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::heartbeat::{
    HeartbeatFields, open_heartbeat, seal_circle_heartbeat, seal_public_heartbeat,
};
use daemonseed_core::identity::keys::{Identity, SignKeypair, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::presence::{
    HEARTBEAT_MISS_COUNT, PresenceTracker, beacon_is_fresh, next_heartbeat_interval,
};
use daemonseed_core::public_room::{
    DEFAULT_ROOM, PublicRoomKey, derive_room_key, derive_room_presence_veilid_owner_seed,
    derive_room_veilid_owner_seed, open_room_message, seal_room_message,
};
use daemonseed_core::public_space::{
    Whitelist, content_address, dev_project_announce_veilid_owner_seed, dev_project_release_keypair,
};
use daemonseed_core::share_announce::{
    AnnouncementFields, derive_share_id, open_announcement, seal_public_announcement,
};
use daemonseed_core::share_catalog::{CatalogChange, ShareCatalog, ShareListing};
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::ChunkAddr;
use daemonseed_core::storage::fetched::rebase_to_selection_root;
use daemonseed_proto::v1 as wire;
use daemonseed_veilid_net::{
    AimdWindow, DiscoveryEnvelope, VeilidNet, VeilidNetConfig, VeilidNetError, VeilidNetEvent,
    VeilidNetHandle, verify_route_advert,
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

/// Max chunk fetches in flight at once during a download (#113). Bounds the
/// parallelism so a many-chunk file saturates the link without an unbounded fan-out
/// of `app_call`s; mirrors the veilid-net fragment pipeline window (#109). Chunks
/// still reassemble in manifest order (`buffered` preserves order).
const CHUNK_FETCH_CONCURRENCY: usize = 8;

// ── Operator announce-record item envelope (Phase 4 A-c) ─────────────────────
//
// Inbound `VeilidNetEvent::Inbound { bytes }` carries NO slot id, and a
// `MotdPayload` vs a `PostPayload` are prost-ambiguous, so the reader cannot tell a
// MOTD from an announcement by content. Each value published to the operator record
// is therefore prefixed with a 1-byte KIND tag: `[kind] ++ prost(artifact)`.

/// Delay after Connect before the #93 unread-gated landing fires its one-shot
/// self-refresh — set past the first two [`WARMUP_RESWEEP_SCHEDULE`] rounds (12 s /
/// 25 s) PLUS DHT fold latency so the re-swept operator items have arrived, and the
/// landing decision runs over as
/// settled a view as the async transport allows. **Best-effort, not a settle
/// confirmation:** on a slow/congested DHT the backlog may still be folding at this
/// deadline, so the landing can run over a partial view (land early / spuriously, or
/// miss a late item — the pane, content, and marker are all still correct, only the
/// auto-open TIMING is heuristic). Robust settle-detection (hash-stable window) is a
/// follow-up (#137). A felt-test tunable.
const OPERATOR_CONNECT_LANDING_DELAY: Duration = Duration::from_secs(35);

/// #140 stepped warmup re-sweep schedule: absolute deadlines from connect at which a
/// force-refresh re-sweep round runs (dispatched via `sleep_until`, so a round's own
/// re-sweep await time never pushes later rounds later — no accumulated drift). The
/// passive DHT watch's first fold lands tens of seconds in (measured ~68 s for lobby
/// chat on a warm restart), so a few front-loaded rounds catch converged content sooner
/// and give each surface an earlier "discovering → content" reveal. Each re-sweep is
/// `SUBKEY_COUNT` (64) force-refresh gets/record, so rounds are few + widening, not a
/// tight loop; re-swept already-seen items are deduped downstream (`apply_discovery`
/// self-filter, `push_message` exact-match). The first two rounds land at/under
/// [`OPERATOR_CONNECT_LANDING_DELAY`] (35 s) so operator MOTD/announcement content is
/// refreshed before the #93 connect-landing decision. Felt-tunable.
const WARMUP_RESWEEP_SCHEDULE: [Duration; 4] = [
    Duration::from_secs(12),
    Duration::from_secs(25),
    Duration::from_secs(45),
    Duration::from_secs(75),
];

/// Rounds (from the front of [`WARMUP_RESWEEP_SCHEDULE`]) in which the circle records
/// are ALSO re-swept. Operator + lobby — the top priority and the #93 landing feed —
/// are re-swept every round; circles (which can be many) only in the early rounds, so a
/// heavily-joined user's warmup doesn't fan out to `rounds × circles` concurrent
/// backlog sweeps competing with initial chat/downloads (#140 review). Felt-tunable.
const WARMUP_CIRCLE_RESWEEP_ROUNDS: usize = 2;

/// Build the #140 warmup PRIORITY re-sweep records: operator MOTD/announce first (its
/// content feeds the #93 landing), then lobby chat. These are re-swept every round;
/// circle records are handled separately (early rounds only — see
/// [`WARMUP_CIRCLE_RESWEEP_ROUNDS`]). Presence records are excluded (they self-heal via
/// the heartbeat emit/reap cycle). Order is issue-order and load-bearing: within a round
/// each `resweep_rendezvous` awaits its record open before the next is issued, so the
/// operator sweep is dispatched first (the spawned backlog reads then overlap).
fn warmup_priority_records(operator: Option<[u8; 32]>, lobby: Option<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut seeds = Vec::with_capacity(2);
    seeds.extend(operator);
    seeds.extend(lobby);
    seeds
}

/// KIND tag for a MOTD value: the payload is a [`wire::SignedArtifact`].
const OPERATOR_ITEM_MOTD: u8 = 0x00;
/// KIND tag for an announcement value: the payload is a [`wire::Post`].
const OPERATOR_ITEM_ANNOUNCEMENT: u8 = 0x01;

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
}

/// A share this node published this session — enough to post a
/// provenance-matching withdraw on unpublish and to show in the publisher's own
/// list (the lobby never reflects our own announcement back).
#[derive(Clone)]
struct OwnShare {
    share_id: String,
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
    /// #93 unread-gated landing: `true` from subscribe until the ONE connect-time
    /// snapshot has been emitted (by the delayed self-refresh, or a manual open first).
    /// The next refresh with this set emits `connect_time: true` so `main.rs` runs the
    /// landing decision (land on the pane iff the content changed since last seen),
    /// then clears it — a manual refresh / poll / post-publish refresh never re-lands.
    landing_pending: bool,
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
    lobby: Option<LobbyRendezvous>,
    catalog: ShareCatalog,
    discovered: HashMap<String, DiscoveredRoute>,
    own: Vec<OwnShare>,
    /// The subscribed operator announce/MOTD record (Phase 4 A-c), set on Connect
    /// after the owner seed derives + the record subscribes. `None` until connected.
    operator: Option<OperatorSpace>,
}

impl ShareState {
    fn new() -> Self {
        Self {
            signing: None,
            lobby: None,
            catalog: ShareCatalog::new(SHARE_CATALOG_TTL),
            discovered: HashMap::new(),
            own: Vec::new(),
            operator: None,
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
                });
            }
        }
        for s in self.catalog.entries() {
            if seen.insert(s.share_id.clone()) {
                out.push(ShareListing::from(&s));
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
    // Presence emit + reap clock (#74): a jittered [15,20]s beacon into the lobby
    // presence record (when joined) that also reaps the roster on each fire. A
    // self-rescheduling `Sleep` (not a fixed `interval`) so each tick draws a fresh
    // jittered deadline — de-syncing daemons and keeping the cadence off a fixed
    // period (ISC-A-S2 traffic shape).
    let heartbeat = tokio::time::sleep(veilid_presence_interval());
    tokio::pin!(heartbeat);

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // UI side dropped — shut down
                handle_command(
                    cmd, &evt_tx, &cmd_tx, &mut net, &mut ev_rx, &mut circles, &mut my_handle,
                    &mut shares,
                ).await;
            }
            // Only poll the Veilid event stream once connected.
            Some(ev) = recv_opt(&mut ev_rx), if ev_rx.is_some() => {
                handle_inbound(ev, &evt_tx, &mut circles, &my_handle, &mut shares);
            }
            // Age out discovered shares not reheard within the TTL (Shape B liveness):
            // a sharer that vanished without a withdraw self-clears from the list.
            // Own shares live in `shares.own`, never in the catalog, so they are safe.
            _ = prune_timer.tick() => {
                if shares.catalog.prune(Instant::now()) > 0 {
                    let _ = evt_tx.send(NetEvent::SharesSnapshot { shares: shares.listings() });
                }
            }
            // Emit one lobby presence beacon + reap the roster, then re-arm the timer
            // with a fresh jittered deadline.
            () = heartbeat.as_mut() => {
                emit_and_reap_presence(&evt_tx, &net, &my_handle, &mut shares, &mut circles);
                heartbeat
                    .as_mut()
                    .reset(tokio::time::Instant::now() + veilid_presence_interval());
            }
        }
    }
}

/// The jittered lobby presence-beacon interval — [15, 20]s (P2), which sits at or
/// above the ~14.7s cross-node DHT watch floor so beaconing never outruns
/// propagation (a faster beacon only adds redundant DHT writes). Reuses the core
/// [10, 15]s jittered draw plus a 5s floor, so the CSPRNG jitter (de-sync + no
/// fixed period, ISC-A-S2) is shared with the relay path. The band is a felt-test
/// tunable (design open question).
fn veilid_presence_interval() -> Duration {
    next_heartbeat_interval() + Duration::from_secs(5)
}

/// Emit one sealed lobby presence beacon (#74) to the presence record, then `reap`
/// the lobby roster so members past their TTL age out (the timer is the reap clock
/// too). A missing identity/lobby, a seal failure, or a closed transport is
/// non-fatal — presence self-heals on the next tick. A reap that changed the set
/// pushes a fresh (possibly empty) Roster. Lobby-only; circle presence is #77.
/// Mirrors the relay `Actor::handle_emit_heartbeat`.
///
/// The DHT publish is **spawned off the actor loop** (like `send_room` / `send_circle`,
/// the #128 D-0b pattern): `handle.publish_presence` awaits the write's ack, which
/// can take seconds, so awaiting it inline in the select arm would stall the loop —
/// no inbound chat rendered, no commands serviced — every ~15–20 s. The reap is a
/// fast in-memory op and stays inline.
fn emit_and_reap_presence(
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    my_handle: &str,
    shares: &mut ShareState,
    circles: &mut [VeilidCircle],
) {
    // EMIT — needs an identity to self-sign with (ISC-C57), a live transport, and a
    // subscribed lobby. The beacon carries this node's served-share digest (#76).
    // Seal on the loop (fast, in-memory), then spawn the DHT write.
    if let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone())
        && let Some(lobby) = shares.lobby.as_ref()
    {
        let own_share_ids: Vec<String> = shares.own.iter().map(|s| s.share_id.clone()).collect();
        let fields = HeartbeatFields {
            room: DEFAULT_ROOM,
            sender_handle: my_handle,
            sent_unix_ms: now_unix_ms(),
            live_share_ids: &own_share_ids,
        };
        if let Ok(sealed) = seal_public_heartbeat(&lobby.room_key, &signing, &fields) {
            let handle = handle.clone();
            let seed = lobby.presence_owner_seed;
            let pubkey = signing.public_key().to_vec();
            tokio::spawn(async move {
                if let Err(e) = handle.publish_presence(seed, &pubkey, sealed).await {
                    daemonseed_veilid_net::vtrace!("gui presence: beacon emit failed: {e}");
                }
            });
        }
    }
    // REAP on the same tick — the timer is the reap clock. Push a fresh roster only
    // when a reap actually removed someone (a reap-to-empty still pushes an empty
    // roster so the UI clears).
    if let Some(lobby) = shares.lobby.as_mut()
        && !lobby.presence.reap(Instant::now()).is_empty()
    {
        let entries = roster_from_members(&lobby.presence.members());
        let _ = evt_tx.send(NetEvent::Roster {
            circle_id: None,
            entries,
        });
    }

    // ── Per-circle presence (#77) ──
    // One beacon per joined circle, sealed under that circle's `cot_key` and
    // published to that circle's presence sibling record. Mirrors the lobby emit
    // above + the relay `Actor::handle_emit_heartbeat` circle loop. `room` is the
    // circle's deterministic client-local label (provenance-only — the beacon is
    // self-verifying; routing is by which circle's key opened it, not the label).
    // No circle-share digest yet (#76): an empty `live_share_ids`. Skip entirely
    // (no keypair clone) when no circles are joined.
    if !circles.is_empty()
        && let (Some(handle), Some(signing)) = (net.as_ref(), shares.signing.clone())
    {
        let sent_unix_ms = now_unix_ms();
        for circle in circles.iter() {
            let label = default_circle_label(&circle_fingerprint(&circle.cot_key));
            let fields = HeartbeatFields {
                room: &label,
                sender_handle: my_handle,
                sent_unix_ms,
                live_share_ids: &[],
            };
            if let Ok(sealed) = seal_circle_heartbeat(&circle.cot_key, &signing, &fields) {
                let handle = handle.clone();
                let seed = circle.presence_owner_seed;
                let pubkey = signing.public_key().to_vec();
                tokio::spawn(async move {
                    if let Err(e) = handle.publish_presence(seed, &pubkey, sealed).await {
                        daemonseed_veilid_net::vtrace!("gui circle presence: emit failed: {e}");
                    }
                });
            }
        }
    }
    // Reap each circle's tracker on the same tick; push a fresh (possibly empty)
    // roster tagged with that circle for any tracker a reap changed.
    let now = Instant::now();
    for circle in circles.iter_mut() {
        if !circle.presence.reap(now).is_empty() {
            let entries = roster_from_members(&circle.presence.members());
            let _ = evt_tx.send(NetEvent::Roster {
                circle_id: Some(circle.circle_id),
                entries,
            });
        }
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
    cmd_tx: &UnboundedSender<NetCommand>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    circles: &mut Vec<VeilidCircle>,
    my_handle: &mut String,
    shares: &mut ShareState,
) {
    match cmd {
        NetCommand::Connect {
            display_handle,
            rejoin_circles,
            republish_roots,
            stable_signing_key,
            ..
        } => {
            if let Some(h) = display_handle {
                *my_handle = h;
            }
            // Capture the stable identity key (least-authority: kept behind an Arc
            // for sealing announcements + minting the route-advert capability; the
            // raw key never enters veilid-net).
            shares.signing = stable_signing_key.map(Arc::new);
            connect(evt_tx, net, ev_rx).await;
            if net.is_some() {
                // Subscribe the world-derivable lobby so share announcements fold
                // into the catalog as they arrive (Phase 3 discovery).
                subscribe_lobby(shares, net, evt_tx).await;
                // Subscribe the operator announce/MOTD record (Phase 4 A-c) so MOTD +
                // announcement items fold in as they arrive.
                subscribe_operator_space(shares, net).await;
                // #93 connect-landing: re-arm for THIS connect (relay parity — the
                // landing fires on every connect if the content changed since last seen,
                // not only the first), then fire a delayed settle-then-refresh. The
                // operator backlog arrives ASYNC via the post-connect sweep, so a delayed
                // one-shot self-refresh runs the landing decision over the SETTLED view —
                // an eager connect_time snapshot would land on an empty/partial view and
                // false-positive-land on every reconnect. The self-sent RefreshPublicSpace
                // consumes `landing_pending` and emits the single connect_time:true
                // snapshot; the delay sits just past the first warmup re-sweep rounds
                // (#140) so re-swept operator items have folded. A felt-test tunable.
                if let Some(op) = shares.operator.as_mut() {
                    op.landing_pending = true;
                    let cmd_tx = cmd_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(OPERATOR_CONNECT_LANDING_DELAY).await;
                        let _ = cmd_tx.send(NetCommand::RefreshPublicSpace);
                    });
                }
                // #102: relay-parity — silently re-subscribe persisted circles after
                // attach, so a circle restored into the UI is actually joined on the
                // transport (else SendCircle finds known=[] → "join before sending").
                for (circle_id, phrase) in rejoin_circles {
                    join_circle(circle_id, &phrase, evt_tx, net, circles).await;
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
                // operator record first (its MOTD/announce feeds the #93 landing), then
                // the lobby, then circles, at widening delays. Re-swept already-seen
                // items are deduped downstream (`apply_discovery` self-filter,
                // `push_message` exact-match). Presence records self-heal via the
                // heartbeat cycle and are excluded.
                if let Some(handle) = net.as_ref() {
                    let handle = handle.clone();
                    let priority = warmup_priority_records(
                        shares.operator.as_ref().map(|op| op.announce_owner_seed),
                        shares.lobby.as_ref().map(|l| l.owner_seed),
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
                        // no accumulated drift, so round 2 stays at/under the 35 s #93 landing).
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
            join_circle(circle_id, &phrase, evt_tx, net, circles).await;
        }
        NetCommand::SendCircle { circle_id, text } => {
            send_circle(circle_id, &text, evt_tx, net, circles, my_handle).await;
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
            // User-initiated (the Refresh button): re-render locally AND re-sweep the
            // lobby rendezvous to surface an announcement the watch missed during the
            // warmup window (#133). Swept ShareAnnouncements arrive as inbound events →
            // apply_discovery folds them → a fresh SharesSnapshot. NOT on the auto-poll
            // cadence — a manual click is rare, so the re-sweep cost is acceptable.
            let _ = evt_tx.send(NetEvent::SharesSnapshot {
                shares: shares.listings(),
            });
            if let (Some(lobby), Some(handle)) = (shares.lobby.as_ref(), net.as_ref()) {
                let owner_seed = lobby.owner_seed;
                daemonseed_veilid_net::vtrace!("gui resweep: re-sweeping lobby");
                if let Err(e) = handle.resweep_rendezvous(owner_seed).await {
                    daemonseed_veilid_net::vtrace!("gui resweep: lobby re-sweep failed: {e}");
                }
            }
        }
        NetCommand::FetchShare { share_id, name } => {
            fetch_share(shares, evt_tx, net, &share_id, &name).await;
        }
        NetCommand::ConfirmFetch {
            share_id,
            name,
            fetched_root,
            selected,
            flat_dest,
        } => {
            confirm_fetch(
                shares,
                evt_tx,
                net,
                &share_id,
                &name,
                fetched_root,
                selected,
                flat_dest,
            )
            .await;
        }

        // ── Public-room (Lobby) chat ──
        NetCommand::JoinRoom { room } => {
            // The lobby is world-derivable and already subscribed on Connect; a
            // JoinRoom just re-affirms it so the UI marks the room ready. Only the
            // default lobby is wired (named public rooms are Phase 4).
            if shares.lobby.is_some() {
                let _ = evt_tx.send(NetEvent::RoomJoined { room });
            } else {
                let _ = evt_tx.send(NetEvent::Error {
                    reason: "lobby not subscribed yet".to_owned(),
                });
            }
        }
        NetCommand::SendRoom { text } => {
            send_room(&text, evt_tx, net, my_handle, shares).await;
        }

        // ── Operator announcements / MOTD (Phase 4 A-c) ──
        NetCommand::RefreshPublicSpace => refresh_public_space(shares, evt_tx, net).await,
        NetCommand::SetMotd { text } => set_motd(shares, evt_tx, net, &text).await,
        NetCommand::UploadAnnouncement { topic, body } => {
            upload_announcement(shares, evt_tx, net, &topic, &body).await;
        }

        // Internal / timer-driven commands the relay actor self-sends. None are
        // generated in Veilid mode (no relay heartbeat/reconnect machinery runs),
        // so they are silent no-ops; the catch-all also covers `#[cfg(test)]`
        // seam variants that do not exist in this build.
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
            server_handle: "veilid".to_owned(),
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
    }

    daemonseed_veilid_net::vtrace!(
        "gui connect: namespace={} listen={:?} dir-env={:?}",
        cfg.namespace,
        cfg.listen_address,
        std::env::var("DAEMONSEED_VEILID_DIR").ok()
    );
    match VeilidNet::start(cfg).await {
        Ok((handle, rx)) => match handle.attach_and_wait(180).await {
            Ok(()) => {
                *net = Some(handle);
                *ev_rx = Some(rx);
                let _ = evt_tx.send(NetEvent::Connected {
                    server_handle: "veilid".to_owned(),
                });
            }
            Err(e) => fail(evt_tx, format!("veilid attach: {e}")),
        },
        Err(e) => fail(evt_tx, format!("veilid start: {e}")),
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
    // Subscribe the presence record too so inbound beacons fold into the roster.
    // Non-fatal on failure — the roster stays empty but chat is unaffected.
    if let Err(e) = handle.subscribe_room(presence_owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui lobby: presence subscribe failed: {e}");
    }
    daemonseed_veilid_net::vtrace!("gui lobby: subscribed (chat + presence)");
    shares.lobby = Some(LobbyRendezvous {
        room_key,
        owner_seed,
        presence_owner_seed,
        // TTL = 20s × 3 misses = 60s, sized to the 15–20s emit band (P2 ~45–60s
        // bias-to-forgiveness window). A brief wobble never reaps a live member.
        presence: PresenceTracker::with_cadence(Duration::from_secs(20), HEARTBEAT_MISS_COUNT),
    });
    // The lobby rendezvous is live: tell the UI the public room is joined so its
    // Lobby chat box is enabled (relay-path parity — the relay emits RoomJoined on
    // its connect-time auto-join).
    let _ = evt_tx.send(NetEvent::RoomJoined {
        room: DEFAULT_ROOM.to_owned(),
    });
}

/// Join a circle: derive the content key + the shared rendezvous-owner seed from
/// the phrase, subscribe the rendezvous record, and record local state.
async fn join_circle(
    circle_id: u64,
    phrase: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &mut Vec<VeilidCircle>,
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
    circles.push(VeilidCircle {
        circle_id,
        cot_key,
        owner_seed,
        presence_owner_seed,
        // TTL = 20s × 3 = 60s, matching the lobby presence cadence (P2).
        presence: PresenceTracker::with_cadence(Duration::from_secs(20), HEARTBEAT_MISS_COUNT),
    });
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
    let sent_unix_ms = now_unix_ms();
    let message = wire::CircleMessage {
        sender_handle: my_handle.to_owned(),
        body: text.to_owned(),
        sent_unix_ms,
    };
    let sealed = match seal_message(&circle.cot_key, &message) {
        Ok(s) => s,
        Err(e) => return err(format!("seal failed: {e}")),
    };
    // #101: optimistic local echo FIRST — the sender sees their own message
    // immediately, not after the DHT publish round-trip (seconds on Veilid). The
    // delayed DHT re-surface of this same write is emitted `mine:true` and deduped
    // against this echo by `sent_unix_ms` in `push_message` (#143), so no double-render.
    let _ = evt_tx.send(NetEvent::CircleMessage {
        circle_id,
        who: my_handle.to_owned(),
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
    let sealed = match seal_room_message(
        &lobby.room_key,
        signing.as_ref(),
        DEFAULT_ROOM,
        my_handle,
        text,
        sent_unix_ms,
    ) {
        Ok(s) => s,
        Err(e) => return err(format!("public-room seal/sign failed: {e}")),
    };
    // Optimistic local echo FIRST — the sender sees their own message immediately,
    // not after the Veilid publish round-trip; the delayed DHT re-surface of this
    // same write is emitted `mine:true` and deduped against this echo (#143).
    let _ = evt_tx.send(NetEvent::Message {
        who: my_handle.to_owned(),
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
        landing_pending: true,
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
/// path during a backlog sweep (review finding). `can_compose = true` is the dev
/// possession gate. `connect_time` drives the #93 unread-gated landing in `main.rs`:
/// `true` ONLY for the single post-connect settle snapshot (so it can auto-land on
/// the pane when the content changed) — every other snapshot (a manual refresh, an
/// inbound fold, a post-publish refresh) passes `false` so it never yanks the user.
fn public_space_snapshot_event(op: &OperatorSpace, connect_time: bool) -> NetEvent {
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
        can_compose: true,
        connect_time,
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
            // Consume the one-shot connect-landing flag: this snapshot may auto-land
            // (#93); every subsequent refresh is a plain re-render that never re-lands.
            let connect_time = std::mem::replace(&mut op.landing_pending, false);
            let _ = evt_tx.send(public_space_snapshot_event(op, connect_time));
        }
        None => {
            let _ = evt_tx.send(NetEvent::PublicSpaceError {
                message: operator_unavailable_message(net),
            });
        }
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
        let _ = evt_tx.send(public_space_snapshot_event(op, false));
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
        let _ = evt_tx.send(public_space_snapshot_event(op, false));
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
        let _ = evt_tx.send(public_space_snapshot_event(op, false));
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
    // Copy the lobby's address material out so no borrow of `shares` is held
    // across an `.await` (and so the later `shares.own.push` is unobstructed).
    let (room_key_bytes, owner_seed) = match shares.lobby.as_ref() {
        Some(l) => (*l.room_key.as_bytes(), l.owner_seed),
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

    // Deterministic id (not a fresh mint): the same (identity, root) always yields
    // the same share_id, so a republish on reconnect re-asserts the SAME id and a
    // fetcher folds it onto the existing catalog entry — no duplicate / dead-route
    // second copy (#112). The pubkey is already the announcement's provenance
    // anchor, so this adds no linkability.
    let share_id = derive_share_id(signing.public_key(), &root_str);
    let rating = String::new();
    let room_key = PublicRoomKey::from_bytes(room_key_bytes);
    let fields = AnnouncementFields {
        room: DEFAULT_ROOM,
        sender_handle: &sharer_handle,
        share_id: &share_id,
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
        .publish_share(owner_seed, share_id.clone(), sealed, signer)
        .await
    {
        let _ = evt_tx.send(NetEvent::PublishStopped {
            share_id: share_id.clone(),
        });
        return err(format!("could not announce share: {e}"));
    }

    shares.own.push(OwnShare {
        share_id: share_id.clone(),
        name: name.clone(),
        rating,
        sharer_handle,
    });
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
        Some(l) => (*l.room_key.as_bytes(), l.owner_seed),
        None => return,
    };
    let own = own.unwrap_or(OwnShare {
        share_id: share_id.to_owned(),
        name: String::new(),
        rating: String::new(),
        sharer_handle: String::new(),
    });
    let room_key = PublicRoomKey::from_bytes(room_key_bytes);
    let fields = AnnouncementFields {
        room: DEFAULT_ROOM,
        sender_handle: &own.sharer_handle,
        share_id: &own.share_id,
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
        .publish_share(owner_seed, share_id.to_owned(), sealed, signer)
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

/// A1 fetch-preview: import the discovered share's private route, fetch +
/// reassemble + open its manifest, and emit `FetchManifest` (file names + sizes).
/// No bytes are fetched. The route is anti-swap-verified at discovery time, before
/// it ever enters `shares.discovered`.
async fn fetch_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    share_id: &str,
    name: &str,
) {
    let fail = |message: String| {
        let _ = evt_tx.send(NetEvent::FetchError { message });
    };
    let Some(handle) = net.as_ref() else {
        return fail("not connected to Veilid yet".to_owned());
    };
    // Copy the route + room key out, dropping the immutable borrow so a fetch
    // failure can prune (&mut) below.
    let (route_blob, room_key_bytes) = {
        let Some(lobby) = shares.lobby.as_ref() else {
            return fail("lobby not subscribed yet".to_owned());
        };
        let Some(disc) = shares.discovered.get(share_id) else {
            return fail("share not discovered yet — refresh the list".to_owned());
        };
        (disc.route_blob.clone(), *lobby.room_key.as_bytes())
    };
    let route = match handle.import_route(route_blob).await {
        Ok(r) => r,
        Err(e) => {
            // The advertised route won't import (the sharer/route is gone): prune
            // the stale entry so the dead copy disappears (ISC-S30, #112).
            prune_unreachable_share(shares, evt_tx, share_id);
            return fail(format!("could not import the sharer's route: {e}"));
        }
    };
    match handle.fetch_manifest(route, share_id, room_key_bytes).await {
        Ok(manifest) => {
            let entries = manifest
                .iter()
                .map(|e| ShareManifestEntry {
                    rel_path: e.rel_path.clone(),
                    size: e.size,
                    chunk_count: e.chunks.len() as u32,
                })
                .collect();
            let _ = evt_tx.send(NetEvent::FetchManifest {
                share_id: share_id.to_owned(),
                name: name.to_owned(),
                entries,
            });
        }
        Err(e) => {
            prune_unreachable_share(shares, evt_tx, share_id);
            fail(fetch_error_message("could not fetch the share manifest", e));
        }
    }
}

/// Prune a share that failed to fetch — a dead/un-importable route or an
/// authoritative withdraw means the catalog entry is stale (ISC-S30
/// prune-on-fetch-fail). Drops it from the discovered-route map + the catalog and
/// refreshes the listing; a still-live share re-announces and reappears. This
/// self-heals the stale duplicate (#112): a copy whose route points at a gone node
/// disappears when its fetch fails, instead of lingering until its TTL.
fn prune_unreachable_share(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    share_id: &str,
) {
    let removed_route = shares.discovered.remove(share_id).is_some();
    let removed_cat = shares.catalog.remove(share_id);
    if removed_route || removed_cat {
        daemonseed_veilid_net::vtrace!(
            "pruned unreachable share {share_id} after fetch fail (prune-on-fetch-fail)"
        );
        let _ = evt_tx.send(NetEvent::SharesSnapshot {
            shares: shares.listings(),
        });
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
/// Mirrors the relay actor's `handle_confirm_fetch`.
#[allow(clippy::too_many_arguments)]
async fn confirm_fetch(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    share_id: &str,
    name: &str,
    fetched_root: PathBuf,
    selected: Option<Vec<usize>>,
    flat_dest: bool,
) {
    let mut written: Vec<PathBuf> = Vec::new();
    if let Err(message) = confirm_fetch_inner(
        shares,
        evt_tx,
        net,
        share_id,
        name,
        fetched_root,
        selected,
        flat_dest,
        &mut written,
    )
    .await
    {
        for p in &written {
            let _ = std::fs::remove_file(p);
        }
        let _ = evt_tx.send(NetEvent::FetchError { message });
    }
}

#[allow(clippy::too_many_arguments)]
async fn confirm_fetch_inner(
    shares: &mut ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    share_id: &str,
    name: &str,
    fetched_root: PathBuf,
    selected: Option<Vec<usize>>,
    flat_dest: bool,
    written: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let handle = net
        .as_ref()
        .ok_or_else(|| "not connected to Veilid yet".to_owned())?;
    // Copy the route + room key out, dropping the immutable borrow so a fetch-stage
    // failure can prune the stale entry (&mut) below (ISC-S30 prune-on-fetch-fail).
    let (route_blob, room_key_bytes) = {
        let lobby = shares
            .lobby
            .as_ref()
            .ok_or_else(|| "lobby not subscribed yet".to_owned())?;
        let disc = shares
            .discovered
            .get(share_id)
            .ok_or_else(|| "share not discovered yet — refresh the list".to_owned())?;
        (disc.route_blob.clone(), *lobby.room_key.as_bytes())
    };
    let route = match handle.import_route(route_blob).await {
        Ok(r) => r,
        Err(e) => {
            prune_unreachable_share(shares, evt_tx, share_id);
            return Err(format!("could not import the sharer's route: {e}"));
        }
    };
    let manifest = match handle
        .fetch_manifest(route.clone(), share_id, room_key_bytes)
        .await
    {
        Ok(m) => m,
        Err(e) => {
            prune_unreachable_share(shares, evt_tx, share_id);
            return Err(fetch_error_message("could not fetch the share manifest", e));
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

    let mut chunks_received: u32 = 0;
    let mut bytes_received: u64 = 0;
    let mut files_written: u32 = 0;

    // #128 D-1: ONE adaptive fragment-concurrency window for the whole download,
    // shared across every chunk fetch (chunks still run concurrently — #113).
    // It starts fully open at FRAGMENT_FETCH_CONCURRENCY (safe-by-default: a
    // healthy download is unchanged) and only narrows, floored at 1, when a
    // chunk's fragment `app_call`s breach FRAGMENT_LATENCY_THRESHOLD — yielding
    // bandwidth back to interactive chat under fat-link congestion, then climbing
    // back as latency recovers. `Arc<Mutex>` because concurrent chunk fetches read
    // and update it (the guard is never held across an await).
    let aimd = std::sync::Arc::new(std::sync::Mutex::new(AimdWindow::new(
        1,
        daemonseed_veilid_net::share::FRAGMENT_FETCH_CONCURRENCY,
    )));

    for (pos, &i) in indices.iter().enumerate() {
        let entry = &manifest[i];
        let rel = match &rebased {
            Some(r) => r[pos].as_str(),
            None => entry.rel_path.as_str(),
        };
        let safe =
            sanitize_rel_path(rel).ok_or_else(|| format!("unsafe path in manifest: {rel:?}"))?;
        let dest = if flat_dest {
            fetched_root.join(&safe)
        } else {
            fetched_root.join(safe_folder_name(name)).join(&safe)
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
        // Fetch this file's chunks with bounded concurrency (#113), preserving
        // manifest order for byte-for-byte reassembly. Each `fetch_chunk` reassembles
        // its transport fragments and SHA-384-verifies the chunk against its address
        // (ISC-S28 / ISC-A-S20); the first failure prunes the stale share and aborts.
        let chunks = match fetch_chunks_ordered(
            &entry.chunks,
            CHUNK_FETCH_CONCURRENCY,
            |addr| {
                // Fetch this chunk's fragments at the current adaptive window, then
                // feed the max observed fragment latency back so the NEXT chunk's
                // window backs off (or recovers) — #128 D-1.
                let aimd = aimd.clone();
                let route = route.clone();
                let window = aimd.lock().expect("aimd mutex").window();
                async move {
                    let (data, latency) = handle
                        .fetch_chunk(route, share_id, addr, room_key_bytes, window)
                        .await?;
                    aimd.lock().expect("aimd mutex").observe(
                        latency,
                        daemonseed_veilid_net::share::FRAGMENT_LATENCY_THRESHOLD,
                    );
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
        {
            Ok(c) => c,
            Err(e) => {
                prune_unreachable_share(shares, evt_tx, share_id);
                return Err(fetch_error_message("chunk fetch failed", e));
            }
        };
        let mut file_bytes: Vec<u8> = Vec::with_capacity(entry.size as usize);
        for data in &chunks {
            file_bytes.extend_from_slice(data);
        }
        std::fs::write(&dest, &file_bytes)
            .map_err(|e| format!("could not write {}: {e}", dest.display()))?;
        written.push(dest);
        files_written += 1;
    }

    let _ = evt_tx.send(NetEvent::FetchComplete {
        share_id: share_id.to_owned(),
        files_written,
        bytes_written: bytes_received,
    });
    Ok(())
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
    my_handle: &str,
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
    for circle in circles.iter() {
        if let Ok(msg) = open_message(&circle.cot_key, &bytes) {
            // #143: emit own messages too (mine == our handle) instead of suppressing.
            // A LIVE own message dedups against its optimistic local echo in
            // `push_message` (same `sent_unix_ms`); a COLD-START backlog own message has
            // no prior echo and renders once — so the reconstructed transcript shows
            // BOTH halves of the conversation, not just the other party's.
            let mine = msg.sender_handle == my_handle;
            daemonseed_veilid_net::vtrace!(
                "gui inbound: opened circle {} from '{}' (mine={mine}) -> deliver",
                circle.circle_id,
                msg.sender_handle
            );
            let _ = evt_tx.send(NetEvent::CircleMessage {
                circle_id: circle.circle_id,
                who: msg.sender_handle,
                text: msg.body,
                mine,
                sent_unix_ms: msg.sent_unix_ms,
            });
            return; // opened under exactly one circle
        }
    }
    // Not a circle message — try it as a public-room (Lobby) chat message before
    // share discovery. Both ride the lobby record; the distinct per-kind AAD means
    // only the matching open succeeds (a DiscoveryEnvelope fails `open_room_message`'s
    // AEAD and a chat blob fails `apply_discovery`). #143: own messages are emitted
    // `mine:true` (not suppressed) — they dedup against the optimistic local echo live
    // (same `sent_unix_ms`) and render once from the cold-start backlog.
    if let Some(lobby) = shares.lobby.as_ref()
        && let Ok(msg) = open_room_message(&lobby.room_key, &bytes)
    {
        let mine = msg.sender_handle == my_handle;
        daemonseed_veilid_net::vtrace!(
            "gui inbound: opened lobby chat from '{}' (mine={mine}) -> deliver",
            msg.sender_handle
        );
        let _ = evt_tx.send(NetEvent::Message {
            who: msg.sender_handle,
            text: msg.body,
            mine,
            sent_unix_ms: msg.sent_unix_ms,
        });
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
    let now = Instant::now();
    if ann.withdraw {
        let change = shares.catalog.apply(&ann, now);
        shares.discovered.remove(&ann.share_id);
        if change != CatalogChange::Unchanged {
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
    let change = shares.catalog.apply(&ann, now);
    shares.discovered.insert(
        ann.share_id.clone(),
        DiscoveredRoute {
            route_blob: env.route_blob.clone(),
        },
    );
    if change != CatalogChange::Unchanged {
        let _ = evt_tx.send(NetEvent::SharesSnapshot {
            shares: shares.listings(),
        });
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::share_announce::mint_share_id;
    use daemonseed_veilid_net::route_provenance_input;
    use tokio::sync::mpsc::unbounded_channel;

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
    fn warmup_priority_records_order_operator_then_lobby() {
        let op = [1u8; 32];
        let lobby = [2u8; 32];
        // #140 priority: operator MOTD/announce before lobby chat.
        assert_eq!(
            warmup_priority_records(Some(op), Some(lobby)),
            vec![op, lobby]
        );
        // Operator alone.
        assert_eq!(warmup_priority_records(Some(op), None), vec![op]);
        // Lobby alone.
        assert_eq!(warmup_priority_records(None, Some(lobby)), vec![lobby]);
        // Neither joined → empty (the scheduler re-sweeps nothing that round).
        assert!(warmup_priority_records(None, None).is_empty());
    }

    #[test]
    fn warmup_resweep_schedule_is_strictly_increasing_and_nonempty() {
        assert!(!WARMUP_RESWEEP_SCHEDULE.is_empty());
        for w in WARMUP_RESWEEP_SCHEDULE.windows(2) {
            assert!(w[0] < w[1], "re-sweep schedule must be strictly increasing");
        }
        // The first two rounds precede the #93 landing so operator content is
        // refreshed before the landing decision runs.
        assert!(WARMUP_RESWEEP_SCHEDULE[1] <= OPERATOR_CONNECT_LANDING_DELAY);
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
            presence_owner_seed: *derive_room_presence_veilid_owner_seed(DEFAULT_ROOM, &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            presence: PresenceTracker::with_cadence(Duration::from_secs(20), HEARTBEAT_MISS_COUNT),
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
        blob_to_advertise: &[u8],
        blob_to_sign: &[u8],
    ) -> Vec<u8> {
        let fields = AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "tester",
            share_id,
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

    #[test]
    fn apply_discovery_folds_in_an_honest_signed_item_and_keeps_its_route() {
        let signer = announcer(11);
        let mut shares = ShareState::new();
        let lob = lobby();
        // Re-derive the room key for the envelope (the one in `lob` is moved in).
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lob);

        let share_id = mint_share_id();
        let blob = vec![0xAB; 96];
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &blob, &blob);

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

    #[test]
    fn prune_unreachable_share_drops_a_folded_item_and_snapshots() {
        let signer = announcer(13);
        let mut shares = ShareState::new();
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        shares.lobby = Some(lobby());

        let share_id = mint_share_id();
        let blob = vec![0xCD; 96];
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &blob, &blob);
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_discovery(&mut shares, &evt_tx, &bytes));
        assert_eq!(shares.catalog.len(), 1);
        let _ = evt_rx.try_recv(); // drain the fold snapshot

        // A failed fetch prunes the share from BOTH the catalog and the
        // discovered-route map, and snapshots the now-shorter listing.
        prune_unreachable_share(&mut shares, &evt_tx, &share_id);
        assert_eq!(shares.catalog.len(), 0, "pruned from the catalog");
        assert!(
            !shares.discovered.contains_key(&share_id),
            "pruned from the discovered-route map"
        );
        assert!(
            matches!(evt_rx.try_recv(), Ok(NetEvent::SharesSnapshot { shares }) if shares.is_empty()),
            "an empty SharesSnapshot is emitted after the prune"
        );

        // Pruning an unknown id is a no-op — no snapshot.
        prune_unreachable_share(&mut shares, &evt_tx, "deadbeef");
        assert!(
            evt_rx.try_recv().is_err(),
            "a no-op prune emits no snapshot"
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

        let share_id = mint_share_id();
        let blob = vec![0xEF; 96];
        // An honest, well-formed announcement signed by our OWN identity key.
        let bytes = discovery_bytes(&room_key, me.as_ref(), &share_id, &blob, &blob);

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

        let share_id = mint_share_id();
        let honest = vec![0x11; 96];
        let rogue = vec![0x22; 96];
        // A MITM keeps the signed announcement + the signature over `honest`, but
        // swaps in `rogue` as the advertised route blob.
        let bytes = discovery_bytes(&room_key, &signer, &share_id, &rogue, &honest);

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

        handle_command(
            NetCommand::RefreshPublicSpace,
            &evt_tx,
            &cmd_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
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
            landing_pending: false,
        }
    }

    /// A-d (#93): the FIRST refresh after subscribe consumes `landing_pending` and
    /// emits `connect_time: true` (so `main.rs` runs the unread-gated landing); the
    /// next refresh is `connect_time: false` — a manual refresh / poll / post-publish
    /// refresh never re-lands.
    #[tokio::test]
    async fn refresh_fires_the_connect_landing_once_then_clears() {
        let mut shares = ShareState::new();
        let mut op = operator_space();
        op.landing_pending = true;
        shares.operator = Some(op);
        let net: Option<VeilidNetHandle> = None; // already subscribed → no re-subscribe
        let (evt_tx, mut evt_rx) = unbounded_channel();

        refresh_public_space(&mut shares, &evt_tx, &net).await;
        assert!(
            matches!(
                evt_rx.try_recv(),
                Ok(NetEvent::PublicSpaceSnapshot {
                    connect_time: true,
                    ..
                })
            ),
            "first post-connect refresh lands"
        );
        // Consumed → subsequent refreshes never re-land.
        refresh_public_space(&mut shares, &evt_tx, &net).await;
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::PublicSpaceSnapshot {
                connect_time: false,
                ..
            })
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
        };
        let sealed = seal_circle_heartbeat(&cot_key, &member, &fields).unwrap();

        let mut circles = vec![VeilidCircle {
            circle_id: 42,
            cot_key: derive_cot_key(phrase, &CNSA_2_0).unwrap(),
            owner_seed: [0u8; 32],
            presence_owner_seed: [0u8; 32],
            presence: PresenceTracker::with_cadence(Duration::from_secs(20), HEARTBEAT_MISS_COUNT),
        }];
        let mut shares = ShareState::new(); // signing None → own-filter no-op
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &mut circles,
            "guest",
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
            Ok(NetEvent::PublicSpaceSnapshot {
                view,
                can_compose,
                connect_time,
            }) => {
                assert_eq!(view.motd.as_deref(), Some("Welcome to daemonseed"));
                assert!(can_compose, "dev-possession gate is open");
                assert!(
                    !connect_time,
                    "an inbound fold is never the connect-time land"
                );
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
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &mut [],
            "me#000000000000",
            &mut shares,
        );
        match evt_rx.try_recv() {
            Ok(NetEvent::Message {
                who,
                text,
                mine,
                sent_unix_ms,
            }) => {
                assert_eq!(who, "river-otter#aabbccddeeff");
                assert_eq!(text, "hello lobby");
                assert!(!mine, "a peer's message is not ours");
                assert_eq!(sent_unix_ms, 42, "#126: the wire timestamp is plumbed");
            }
            other => panic!("expected a lobby Message, got {other:?}"),
        }
    }

    /// Our own lobby message re-surfaces via the DHT sweep; it is emitted `mine:true`
    /// (dedup against the echo lives in `push_message`), and on a cold-start backlog
    /// with no echo it renders once (#143).
    #[test]
    fn handle_inbound_emits_our_own_looped_back_lobby_message_as_mine() {
        let me = announcer(32);
        let my_handle = "me#aabbccddeeff";
        let mut shares = ShareState::new();
        shares.lobby = Some(lobby());
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let sealed =
            seal_room_message(&room_key, &me, DEFAULT_ROOM, my_handle, "my own line", 7).unwrap();
        let (evt_tx, mut evt_rx) = unbounded_channel();
        handle_inbound(
            VeilidNetEvent::Inbound { bytes: sealed },
            &evt_tx,
            &mut [],
            my_handle,
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
        assert_eq!(who, my_handle);
        assert_eq!(text, "my own line");
        assert!(mine, "own message must be flagged mine:true");
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
