//! Parallel Veilid-backed net actor (#98 S2 + Phase 3 Slice 2b), compiled only
//! under the `veilid` feature.
//!
//! It implements the SAME `NetCommand` / `NetEvent` contract the relay actor in
//! [`crate::net`] does, so the UI is unchanged — the only switch is which actor
//! [`crate::net::NetHandle::new`] spawns (a `#[cfg(feature = "veilid")]` branch).
//! Backed by [`daemonseed_veilid_net::VeilidNetHandle`].
//!
//! **Circles + public shares today.** `Connect` (attach + lobby subscribe),
//! `JoinCircle`, `SendCircle`, the inbound circle path, and the public-share
//! publish / discover / fetch path (Phase 3 Slice 2b) are live; lobby chat,
//! presence and MOTD/announcements return `NetEvent::Error("not yet on Veilid")`
//! until Phase 4. This is a degraded-but-honest dev/test mode, NOT a dual
//! transport — it honors the no-relay↔Veilid-interop clean cut (one transport at
//! a time).
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
//! (the AEAD seal authenticates the match) and, failing that, parsed as a lobby
//! `DiscoveryEnvelope` and opened under the lobby `PublicRoomKey`. Own circle
//! messages (already local-echoed on send) are suppressed by sender-handle match.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_cli::route_signer::IdentityRouteAdvertSigner;
use daemonseed_core::circle::key::{CircleKey, derive_circle_veilid_owner_seed, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{Identity, SignKeypair, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::{
    DEFAULT_ROOM, PublicRoomKey, derive_room_key, derive_room_veilid_owner_seed,
};
use daemonseed_core::share_announce::{
    AnnouncementFields, mint_share_id, open_announcement, seal_public_announcement,
};
use daemonseed_core::share_catalog::{CatalogChange, ShareCatalog, ShareListing};
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::fetched::rebase_to_selection_root;
use daemonseed_proto::v1 as wire;
use daemonseed_veilid_net::{
    DiscoveryEnvelope, VeilidNet, VeilidNetConfig, VeilidNetError, VeilidNetEvent, VeilidNetHandle,
    verify_route_advert,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::net::{
    NetCommand, NetEvent, ShareManifestEntry, is_unsafe_publish_root, safe_folder_name,
    sanitize_rel_path,
};

/// How long a discovered share lives in the catalog without a fresh announce —
/// mirrors the relay actor's `SHARE_CATALOG_TTL`.
const SHARE_CATALOG_TTL: Duration = Duration::from_secs(90);

/// A joined circle's local state: the GUI routing tag, the content key (for
/// seal/open), and the shared rendezvous-owner seed (for publish/subscribe).
struct VeilidCircle {
    circle_id: u64,
    cot_key: CircleKey,
    owner_seed: [u8; 32],
}

/// The subscribed lobby / public-room rendezvous: the world-derivable
/// `PublicRoomKey` (seals/opens announcements) and the rendezvous-owner seed
/// (publishes onto + subscribes to the lobby record). Both derive from the public
/// room name + suite, so every node computes the same lobby (an open rendezvous).
struct LobbyRendezvous {
    room_key: PublicRoomKey,
    owner_seed: [u8; 32],
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
    _cmd_tx: UnboundedSender<NetCommand>,
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

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // UI side dropped — shut down
                handle_command(
                    cmd, &evt_tx, &mut net, &mut ev_rx, &mut circles, &mut my_handle, &mut shares,
                ).await;
            }
            // Only poll the Veilid event stream once connected.
            Some(ev) = recv_opt(&mut ev_rx), if ev_rx.is_some() => {
                handle_inbound(ev, &evt_tx, &circles, &my_handle, &mut shares);
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
    my_handle: &mut String,
    shares: &mut ShareState,
) {
    match cmd {
        NetCommand::Connect {
            display_handle,
            rejoin_circles,
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
                // #102: relay-parity — silently re-subscribe persisted circles after
                // attach, so a circle restored into the UI is actually joined on the
                // transport (else SendCircle finds known=[] → "join before sending").
                for (circle_id, phrase) in rejoin_circles {
                    join_circle(circle_id, &phrase, evt_tx, net, circles).await;
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
            publish_share(shares, evt_tx, net, root, name, sharer_handle).await;
        }
        NetCommand::UnpublishShare { share_id } => {
            unpublish_share(shares, evt_tx, net, &share_id).await;
        }
        NetCommand::RefreshShares => {
            let _ = evt_tx.send(NetEvent::SharesSnapshot {
                shares: shares.listings(),
            });
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

        // User-facing surfaces not yet on Veilid (Phase 4): answer honestly rather
        // than silently swallow.
        NetCommand::SendRoom { .. }
        | NetCommand::JoinRoom { .. }
        | NetCommand::RefreshPublicSpace
        | NetCommand::UploadAnnouncement { .. }
        | NetCommand::SetMotd { .. } => {
            let _ = evt_tx.send(NetEvent::Error {
                reason: "not yet on Veilid".to_owned(),
            });
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
    _evt_tx: &UnboundedSender<NetEvent>,
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
    if let Err(e) = handle.subscribe_room(owner_seed).await {
        daemonseed_veilid_net::vtrace!("gui lobby: subscribe failed: {e}");
        return;
    }
    daemonseed_veilid_net::vtrace!("gui lobby: subscribed");
    shares.lobby = Some(LobbyRendezvous {
        room_key,
        owner_seed,
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
    daemonseed_veilid_net::vtrace!("gui join_circle: subscribed ok -> CircleJoined id={circle_id}");
    let fingerprint = circle_fingerprint(&cot_key);
    circles.push(VeilidCircle {
        circle_id,
        cot_key,
        owner_seed,
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
/// latency; the inbound path suppresses own messages by handle to avoid a double
/// render).
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
    // delayed DHT re-surface of this same write is suppressed by sender-handle in
    // `handle_inbound`, so there is no double-render.
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
        Err(e) => return err(format!("could not seal share announcement: {e}")),
    };

    // Register the content to serve owner-on-demand (chunks sealed under the room
    // key), then announce it with a signed route advert. veilid-net allocates the
    // private route + signs via the capability internally.
    if let Err(e) = handle
        .serve_share(share_id.clone(), content, room_key_bytes)
        .await
    {
        return err(format!("could not register share to serve: {e}"));
    }
    let signer = IdentityRouteAdvertSigner::from_arc(signing).into_arc();
    if let Err(e) = handle
        .publish_share(owner_seed, share_id.clone(), sealed, signer)
        .await
    {
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
    let _ = evt_tx.send(NetEvent::PublishStarted {
        share_id,
        name,
        file_count,
        root: root_str,
        restored: false,
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
        VeilidNetError::NotServed => {
            "the sharer withdrew this share — it is no longer served".to_owned()
        }
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
    shares: &ShareState,
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
    let Some(lobby) = shares.lobby.as_ref() else {
        return fail("lobby not subscribed yet".to_owned());
    };
    let Some(disc) = shares.discovered.get(share_id) else {
        return fail("share not discovered yet — refresh the list".to_owned());
    };
    let room_key_bytes = *lobby.room_key.as_bytes();
    let route = match handle.import_route(disc.route_blob.clone()).await {
        Ok(r) => r,
        Err(e) => return fail(format!("could not import the sharer's route: {e}")),
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
        Err(e) => fail(fetch_error_message("could not fetch the share manifest", e)),
    }
}

/// A2 download: import the route, fetch the selected files' chunks (each
/// SHA-384-verified inside `fetch_chunk`, ISC-S28), and write them under
/// `fetched_root`. On any failure the partial files are deleted (ISC-A-C31).
/// Mirrors the relay actor's `handle_confirm_fetch`.
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
    shares: &ShareState,
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
    let lobby = shares
        .lobby
        .as_ref()
        .ok_or_else(|| "lobby not subscribed yet".to_owned())?;
    let disc = shares
        .discovered
        .get(share_id)
        .ok_or_else(|| "share not discovered yet — refresh the list".to_owned())?;
    let room_key_bytes = *lobby.room_key.as_bytes();
    let route = handle
        .import_route(disc.route_blob.clone())
        .await
        .map_err(|e| format!("could not import the sharer's route: {e}"))?;
    let manifest = handle
        .fetch_manifest(route.clone(), share_id, room_key_bytes)
        .await
        .map_err(|e| fetch_error_message("could not fetch the share manifest", e))?;

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
        let mut file_bytes: Vec<u8> = Vec::with_capacity(entry.size as usize);
        for addr in &entry.chunks {
            // `fetch_chunk` reassembles fragments and SHA-384-verifies the chunk
            // against its address before returning (ISC-S28 / ISC-A-S20).
            let data = handle
                .fetch_chunk(route.clone(), share_id, *addr, room_key_bytes)
                .await
                .map_err(|e| fetch_error_message("chunk fetch failed", e))?;
            chunks_received += 1;
            bytes_received += data.len() as u64;
            file_bytes.extend_from_slice(&data);
            let _ = evt_tx.send(NetEvent::FetchProgress {
                total_chunks: Some(total_chunks),
                chunks_received,
                bytes_received,
            });
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
/// match); own circle messages are suppressed (already local-echoed). Bytes that
/// open under no circle are tried as a lobby `DiscoveryEnvelope` (share discovery).
fn handle_inbound(
    ev: VeilidNetEvent,
    evt_tx: &UnboundedSender<NetEvent>,
    circles: &[VeilidCircle],
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
    for circle in circles {
        if let Ok(msg) = open_message(&circle.cot_key, &bytes) {
            if msg.sender_handle != my_handle {
                daemonseed_veilid_net::vtrace!(
                    "gui inbound: opened circle {} from '{}' -> deliver",
                    circle.circle_id,
                    msg.sender_handle
                );
                let _ = evt_tx.send(NetEvent::CircleMessage {
                    circle_id: circle.circle_id,
                    who: msg.sender_handle,
                    text: msg.body,
                    mine: false,
                    sent_unix_ms: msg.sent_unix_ms,
                });
            } else {
                daemonseed_veilid_net::vtrace!(
                    "gui inbound: opened circle {} but SUPPRESSED (own handle '{}')",
                    circle.circle_id,
                    my_handle
                );
            }
            return; // opened under exactly one circle
        }
    }
    // Not a circle message — try it as a lobby share-discovery item.
    if apply_discovery(shares, evt_tx, &bytes) {
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

        handle_command(
            NetCommand::PublishShare {
                root: dir.path().to_path_buf(),
                name: "demo".to_owned(),
                sharer_handle: "tester".to_owned(),
            },
            &evt_tx,
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

    #[tokio::test]
    async fn lobby_only_surfaces_are_still_honestly_unimplemented() {
        let mut net: Option<VeilidNetHandle> = None;
        let mut ev_rx: Option<UnboundedReceiver<VeilidNetEvent>> = None;
        let mut circles: Vec<VeilidCircle> = Vec::new();
        let mut my_handle = "guest".to_owned();
        let mut shares = ShareState::new();
        let (evt_tx, mut evt_rx) = unbounded_channel();

        handle_command(
            NetCommand::SendRoom {
                text: "hi".to_owned(),
            },
            &evt_tx,
            &mut net,
            &mut ev_rx,
            &mut circles,
            &mut my_handle,
            &mut shares,
        )
        .await;

        assert!(matches!(
            evt_rx.try_recv(),
            Ok(NetEvent::Error { reason }) if reason == "not yet on Veilid"
        ));
    }
}
