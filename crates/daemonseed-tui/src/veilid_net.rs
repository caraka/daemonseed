//! Parallel Veilid-backed net actor (#98 S2 + Phase 3 Slice 2b), compiled only
//! under the `veilid` feature.
//!
//! It implements the SAME `NetCommand` / `NetEvent` contract the relay actor in
//! [`crate::net`] does, so the UI is unchanged — the only switch is which actor
//! [`crate::net::NetHandle::new`] spawns (a `#[cfg(feature = "veilid")]` branch).
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

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_cli::route_signer::IdentityRouteAdvertSigner;
use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::{CircleKey, derive_circle_veilid_owner_seed, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::heartbeat::{HeartbeatFields, open_heartbeat, seal_public_heartbeat};
use daemonseed_core::identity::keys::{Identity, SignKeypair, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::presence::{
    PRESENCE_TTL, PresenceTracker, REAP_CONGESTION_THRESHOLD, beacon_is_fresh,
    next_keepalive_interval,
};
use daemonseed_core::public_room::{
    DEFAULT_ROOM, PublicRoomKey, derive_room_key, derive_room_presence_veilid_owner_seed,
    derive_room_share_veilid_owner_seed, derive_room_veilid_owner_seed, open_room_message,
    seal_room_message,
};
use daemonseed_core::share_announce::{
    AnnouncementFields, mint_share_id, open_announcement, seal_public_announcement,
};
use daemonseed_core::share_catalog::{CatalogChange, ShareCatalog, ShareListing};
use daemonseed_core::share_envelope::ManifestEntry;
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::fetched::{
    FetchedFile, FetchedShare, FetchedStore, rebase_to_selection_root,
};
use daemonseed_veilid_net::{
    DiscoveryEnvelope, PresenceBoundary, VeilidNet, VeilidNetConfig, VeilidNetError,
    VeilidNetEvent, VeilidNetHandle, verify_route_advert,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::app::IndexerStatus;
use crate::net::{
    NetCommand, NetEvent, ShareManifestEntry, cleanup_written, render_downloads_idx,
    resolve_share_folder, sanitize_rel_path,
};

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
/// private-route blob, kept so a fetch can `import_route` it. The announcer pubkey
/// the route was verified against lives in the catalog entry.
struct DiscoveredRoute {
    route_blob: Vec<u8>,
}

/// A share this node published this session — enough to post a
/// provenance-matching withdraw on unpublish (the in-band replacement for the
/// relay registry's owner-scoped record).
#[derive(Clone)]
struct OwnShare {
    share_id: String,
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
    lobby: Option<LobbyRendezvous>,
    catalog: ShareCatalog,
    discovered: HashMap<String, DiscoveredRoute>,
    /// Shares published this session — held ONLY to post a matching withdraw on
    /// unpublish. Unlike the GUI mirror, own shares are NOT folded into the
    /// `SharesSnapshot` (the relay's `remote` rows are the discovered catalog
    /// alone; the publisher's own list rides `PublishStarted`/`PublishStopped`).
    own: Vec<OwnShare>,
}

impl ShareState {
    fn new() -> Self {
        Self {
            signing: None,
            lobby: None,
            catalog: ShareCatalog::new(SHARE_CATALOG_TTL),
            discovered: HashMap::new(),
            own: Vec::new(),
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

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // UI side dropped — shut down
                handle_command(
                    cmd, &evt_tx, &mut net, &mut ev_rx, &mut circles,
                    &mut next_circle_id, &mut my_handle, &mut shares,
                ).await;
            }
            // Only poll the Veilid event stream once connected.
            Some(ev) = recv_opt(&mut ev_rx), if ev_rx.is_some() => {
                handle_inbound(ev, &evt_tx, &circles, &mut shares);
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
                emit_and_reap_lobby_presence(&net, &my_handle, &mut shares);
                heartbeat
                    .as_mut()
                    .reset(tokio::time::Instant::now() + veilid_keepalive_interval());
            }
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
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    circles: &mut Vec<VeilidCircle>,
    next_circle_id: &mut u64,
    my_handle: &mut Option<String>,
    shares: &mut ShareState,
) {
    match cmd {
        NetCommand::Connect {
            stable_signing_key, ..
        } => {
            // Capture the stable identity key (least-authority: kept behind an Arc
            // for sealing announcements + minting the route-advert capability; the
            // raw key never enters veilid-net). `StableSigningKey` already wraps an
            // `Arc<SignKeypair>`.
            shares.signing = stable_signing_key.map(|k| k.0);
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
            fetch_share(shares, evt_tx, net, &share_id, &name).await;
        }
        NetCommand::ConfirmFetch {
            share_id,
            name,
            fetched_root,
            selected,
            flat_dest,
            ..
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
        .map(ShareListing::from)
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

    let share_id = mint_share_id();
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
        .publish_share(owner_seed, share_id.clone(), sealed, signer)
        .await
    {
        return publish_fail(evt_tx, format!("could not announce share: {e}"), Some(root));
    }

    shares.own.push(OwnShare {
        share_id: share_id.clone(),
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
/// route). The helper that resolves the Demonsaw ambiguity: a deliberate unpublish
/// reads plainly instead of an indefinite timeout.
fn fetch_error_message(context: &str, e: VeilidNetError) -> String {
    match e {
        VeilidNetError::NotServed => "sharer withdrew this share".to_owned(),
        other => format!("{context}: {other}"),
    }
}

/// A1 fetch-preview: import the discovered share's private route, fetch +
/// reassemble + open its manifest, and emit `FetchManifest` (file names + sizes).
/// No bytes are fetched. The route is anti-swap-verified at discovery time, before
/// it ever enters `shares.discovered`.
async fn fetch_share(
    shares: &ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
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
    let room_key_bytes = *lobby.room_key.as_bytes();
    let route = match handle.import_route(disc.route_blob.clone()).await {
        Ok(r) => r,
        Err(e) => return fetch_fail(evt_tx, format!("could not import the sharer's route: {e}")),
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
        Err(e) => fetch_fail(
            evt_tx,
            fetch_error_message("could not fetch the share manifest", e),
        ),
    }
}

/// A1 confirm: import the route, fetch the selected files' chunks (each
/// SHA-384-verified inside `fetch_chunk`, ISC-S28), stream them to disk, and
/// persist the download into `downloads.idx` for the browse pane. Mirrors the
/// relay actor's `handle_confirm_fetch` (FetchedStore policy, flat-dest rebasing,
/// clean-partial cleanup on failure, ISC-A-C31) while sourcing bytes over Veilid.
#[allow(clippy::too_many_arguments)]
async fn confirm_fetch(
    shares: &ShareState,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    share_id: &str,
    name: &str,
    fetched_root: PathBuf,
    selected: Option<Vec<usize>>,
    flat_dest: bool,
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
    let room_key_bytes = *lobby.room_key.as_bytes();
    let route = match handle.import_route(disc.route_blob.clone()).await {
        Ok(r) => r,
        Err(e) => return fetch_fail(evt_tx, format!("could not import the sharer's route: {e}")),
    };
    let manifest = match handle
        .fetch_manifest(route.clone(), share_id, room_key_bytes)
        .await
    {
        Ok(m) => m,
        Err(e) => {
            return fetch_fail(
                evt_tx,
                fetch_error_message("could not fetch the share manifest", e),
            );
        }
    };

    // Resolve the file set: an explicit selection (A2) or the whole manifest (A1
    // confirm-all). Indices map onto the manifest's order; an out-of-range index
    // is dropped (filter_map) rather than aborting.
    let wanted: Vec<&ManifestEntry> = match &selected {
        Some(idxs) => idxs.iter().filter_map(|&i| manifest.get(i)).collect(),
        None => manifest.iter().collect(),
    };

    // Chunk-granular progress over the SELECTED set.
    let total_chunks: u32 = wanted.iter().map(|e| e.chunks.len() as u32).sum();
    let _ = evt_tx.send(NetEvent::FetchProgress {
        total_chunks: Some(total_chunks),
        chunks_received: 0,
        bytes_received: 0,
    });

    // Resolve the destination folder under the downloads root, mirroring core's
    // `FetchedStore` policy (reuse this share's folder on a re-fetch; otherwise a
    // safe name, collision-suffixed by share_id). The store open also creates root.
    let store = match FetchedStore::open(&fetched_root) {
        Ok(s) => s,
        Err(e) => return fetch_fail(evt_tx, format!("could not open the downloads folder: {e}")),
    };
    let mut recorded_shares = match store.list_shares() {
        Ok(s) => s,
        Err(e) => {
            return fetch_fail(
                evt_tx,
                format!("could not read the downloads manifest: {e}"),
            );
        }
    };
    let folder = resolve_share_folder(&recorded_shares, share_id, name);
    let share_dir = fetched_root.join(&folder);

    // Destination layout (ISC-C68). For a user-chosen dest, files land directly
    // under it, rebased so the selected item is the top-level entry (no per-share
    // folder). For the managed downloads dir, keep the namespaced
    // `<share>/<rel_path>` layout. `rebased` is index-aligned with `wanted` and
    // only populated in flat mode.
    let base_dir = if flat_dest {
        fetched_root.clone()
    } else {
        share_dir.clone()
    };
    let rebased: Vec<String> = if flat_dest {
        rebase_to_selection_root(
            &wanted
                .iter()
                .map(|e| e.rel_path.as_str())
                .collect::<Vec<_>>(),
        )
    } else {
        Vec::new()
    };

    let mut written_paths: Vec<PathBuf> = Vec::new();
    let mut chunks_received: u32 = 0;
    let mut bytes_received: u64 = 0;

    // The streaming download loop. Factored as an async block returning `Result`
    // so every failure site funnels through ONE cleanup path below.
    let fetch_result: Result<Vec<FetchedFile>, String> = async {
        let mut recorded: Vec<FetchedFile> = Vec::with_capacity(wanted.len());
        for (i, entry) in wanted.iter().enumerate() {
            // The on-disk relative path: the rebased selection-root path for a
            // user-chosen dest (ISC-C68), else the share-relative path.
            let write_rel = if flat_dest {
                rebased[i].as_str()
            } else {
                entry.rel_path.as_str()
            };
            // Path-traversal guard (ISC-A-C32): a hostile manifest must never write
            // outside the destination folder. Fail closed.
            let Some(safe_rel) = sanitize_rel_path(write_rel) else {
                return Err(format!(
                    "refusing a download path escaping its folder: {}",
                    entry.rel_path
                ));
            };
            let dest = base_dir.join(&safe_rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("could not create download folder: {e}"))?;
            }
            // Create (truncating any previous copy — a re-fetch refreshes the
            // download); chunks append through this held handle. An empty file
            // (`chunks: []`) is complete as-is.
            let mut file = std::fs::File::create(&dest)
                .map_err(|e| format!("could not create {}: {e}", entry.rel_path))?;
            written_paths.push(dest.clone());

            let mut file_bytes: u64 = 0;
            for addr in &entry.chunks {
                // `fetch_chunk` reassembles fragments and SHA-384-verifies the
                // chunk against its address before returning (ISC-S28 / ISC-A-S20),
                // so no manual re-verify is needed here (unlike the relay's stream).
                // TUI keeps the static fragment window for now (adaptive parity is
                // a follow-up, #128 D-1); the latency signal is unused here.
                let (data, _lat) = handle
                    .fetch_chunk(
                        route.clone(),
                        share_id,
                        *addr,
                        room_key_bytes,
                        daemonseed_veilid_net::share::FRAGMENT_FETCH_CONCURRENCY,
                    )
                    .await
                    .map_err(|e| fetch_error_message("chunk fetch failed", e))?;
                file.write_all(&data)
                    .map_err(|e| format!("could not write {}: {e}", entry.rel_path))?;
                file_bytes += data.len() as u64;
                chunks_received += 1;
                bytes_received += data.len() as u64;
                let _ = evt_tx.send(NetEvent::FetchProgress {
                    total_chunks: Some(total_chunks),
                    chunks_received,
                    bytes_received,
                });
            }

            // Size on record is the verified bytes actually on disk.
            recorded.push(FetchedFile {
                rel_path: entry.rel_path.clone(),
                size: file_bytes,
            });
        }
        Ok(recorded)
    }
    .await;

    let recorded = match fetch_result {
        Ok(recorded) => recorded,
        Err(message) => {
            // Clean partial handling: delete everything this fetch wrote and prune
            // the directories that emptied — a failed fetch persists nothing
            // (ISC-A-C31).
            cleanup_written(&fetched_root, &base_dir, &written_paths);
            // A failed RE-fetch already truncated the previous download's copies,
            // so its idx entry now describes deleted files — prune it (best-effort)
            // so the browse pane does not lie. Only the managed downloads dir
            // carries a browse manifest; a user-chosen dest (flat) has none.
            if !flat_dest && recorded_shares.iter().any(|s| s.share_id == share_id) {
                recorded_shares.retain(|s| s.share_id != share_id);
                let _ = std::fs::write(
                    fetched_root.join("downloads.idx"),
                    render_downloads_idx(&recorded_shares),
                );
            }
            return fetch_fail(evt_tx, message);
        }
    };

    // A user-chosen dest (ISC-C68): the files were placed directly under the
    // user's directory. Do not write a `downloads.idx` into it and do not touch
    // the managed browse manifest — the browse pane tracks only the managed dir.
    if flat_dest {
        let _ = evt_tx.send(NetEvent::FetchComplete {
            share_id: share_id.to_owned(),
            files_written: recorded.len() as u32,
            bytes_written: bytes_received,
        });
        return;
    }

    // Record the fully-verified download in `downloads.idx` (M15 C; ISC-C63 /
    // C64). Only a fetch that verified every chunk reaches here (ISC-A-C31). A
    // bookkeeping failure surfaces as a fetch error — the user must not believe a
    // download landed when the browse pane will not show it.
    let files_written = recorded.len() as u32;
    recorded_shares.retain(|s| s.share_id != share_id);
    recorded_shares.push(FetchedShare {
        share_id: share_id.to_owned(),
        name: name.to_owned(),
        folder,
        files: recorded,
    });
    if let Err(e) = std::fs::write(
        fetched_root.join("downloads.idx"),
        render_downloads_idx(&recorded_shares),
    ) {
        return fetch_fail(evt_tx, format!("verified but could not save download: {e}"));
    }

    let _ = evt_tx.send(NetEvent::FetchComplete {
        share_id: share_id.to_owned(),
        files_written,
        bytes_written: bytes_received,
    });
    // Refresh the browse pane with the newly-persisted download.
    emit_fetched_snapshot(evt_tx, &fetched_root);
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
            if let Some(lobby) = shares.lobby.as_mut() {
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

/// Whether the local write funnel is congested (WB-1.10 / WB-ISC-5): the
/// scheduler's most-recent non-chat enqueue-to-ack latency is at/above
/// [`REAP_CONGESTION_THRESHOLD`]. While congested, presence reaping is suspended.
fn write_congested(net: &Option<VeilidNetHandle>) -> bool {
    net.as_ref()
        .map(|h| h.last_write_latency_ms() >= REAP_CONGESTION_THRESHOLD.as_millis() as u64)
        .unwrap_or(false)
}

fn emit_and_reap_lobby_presence(
    net: &Option<VeilidNetHandle>,
    my_handle: &Option<String>,
    shares: &mut ShareState,
) {
    let congested = write_congested(net);
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
    // WB-1.10: reap only in calm (the timer is the reap clock).
    if let Some(lobby) = shares.lobby.as_mut() {
        let _ = lobby.presence.reap(Instant::now(), congested);
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
    let now = Instant::now();
    if ann.withdraw {
        let change = shares.catalog.apply(&ann, now);
        // #152: gate the ROUTE map on the catalog decision — a forged withdraw
        // (foreign key → owner-mismatch → `Unchanged`) must not evict the owner's
        // route (the fetch path reads `discovered`, not the catalog).
        if change == CatalogChange::Removed {
            shares.discovered.remove(&ann.share_id);
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
    let change = shares.catalog.apply(&ann, now);
    // #152: only trust the advertised route when the catalog ACCEPTED the announce.
    // An owner-mismatch hijack refresh returns `Unchanged` (first-writer-wins) —
    // skipping the insert prevents the fetch redirect.
    if change != CatalogChange::Unchanged {
        shares.discovered.insert(
            ann.share_id.clone(),
            DiscoveredRoute {
                route_blob: env.route_blob.clone(),
            },
        );
        emit_shares_snapshot(shares, evt_tx);
    }
    true
}

#[cfg(all(test, feature = "veilid"))]
mod tests {
    use super::*;
    use daemonseed_veilid_net::route_provenance_input;
    use tokio::sync::mpsc::unbounded_channel;

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

    /// A self-signed WITHDRAW envelope (the withdraw path never checks the route
    /// advert, so the route fields are inert); `sent_unix_ms` is fresh so a rejection
    /// can only come from the owner-check.
    fn withdraw_bytes(room_key: &PublicRoomKey, signer: &SignKeypair, share_id: &str) -> Vec<u8> {
        let fields = AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "tester",
            share_id,
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

        let share_id = mint_share_id();
        let vblob = vec![0x11; 96];
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &victim, &share_id, &vblob, &vblob)
        ));
        let _ = evt_rx.try_recv();

        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &withdraw_bytes(&room_key, &attacker, &share_id)
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

        let share_id = mint_share_id();
        let vblob = vec![0x33; 96];
        let ablob = vec![0x44; 96];
        let (evt_tx, mut evt_rx) = unbounded_channel();
        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &victim, &share_id, &vblob, &vblob)
        ));
        let _ = evt_rx.try_recv();

        assert!(apply_discovery(
            &mut shares,
            &evt_tx,
            &discovery_bytes(&room_key, &attacker, &share_id, &ablob, &ablob)
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
            matches!(
                evt_rx.try_recv(),
                Ok(NetEvent::SharesSnapshot { remote, .. }) if remote.len() == 1
            ),
            "a SharesSnapshot listing the share is emitted"
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
}
