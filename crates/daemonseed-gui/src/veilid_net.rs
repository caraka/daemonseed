//! Parallel Veilid-backed net actor (#98 S2), compiled only under the `veilid`
//! feature.
//!
//! It implements the SAME `NetCommand` / `NetEvent` contract the relay actor in
//! [`crate::net`] does, so the UI is unchanged — the only switch is which actor
//! [`crate::net::NetHandle::new`] spawns (a `#[cfg(feature = "veilid")]` branch).
//! Backed by [`daemonseed_veilid_net::VeilidNetHandle`].
//!
//! **Circles-only today.** `Connect` (attach), `JoinCircle`, `SendCircle` and the
//! inbound circle path are live; lobby, shares, presence and MOTD return
//! `NetEvent::Error("not yet on Veilid")` until Phases 3/4. This is a
//! degraded-but-honest dev/test mode, NOT a dual transport — it honors the
//! no-relay↔Veilid-interop clean cut (one transport at a time).
//!
//! **Single encryption layer.** Content is sealed under the circle `cot_key`
//! exactly as on the relay (`seal_message` / `open_message`); the Veilid DHT
//! stores those opaque bytes verbatim (see `daemonseed-veilid-net`'s `circle`
//! module). This actor never touches Veilid's transport crypto.
//!
//! **Inbound demux.** A circle's rendezvous record is its own DHT address, but
//! `VeilidNetEvent::Inbound` carries only the sealed bytes (no record tag), so a
//! received blob is tried against each joined circle's `cot_key` — the AEAD seal
//! is authenticated, so the wrong key simply fails to open. Own messages
//! (already local-echoed on send) are suppressed by sender-handle match, matching
//! the relay actor's `mine` de-dup.

use daemonseed_core::circle::key::{CircleKey, derive_circle_veilid_owner_seed, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{Identity, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_proto::v1 as wire;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidNetEvent, VeilidNetHandle};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::net::{NetCommand, NetEvent};

/// A joined circle's local state: the GUI routing tag, the content key (for
/// seal/open), and the shared rendezvous-owner seed (for publish/subscribe).
struct VeilidCircle {
    circle_id: u64,
    cot_key: CircleKey,
    owner_seed: [u8; 32],
}

/// Best-effort wall-clock for the outgoing `CircleMessage` timestamp.
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
    // The presented display name. Set from a profile's persisted handle on
    // Connect/SetMyHandle; the fallback only matters on the ephemeral path, and
    // the S4 felt-test uses named profiles.
    let mut my_handle = "guest".to_owned();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // UI side dropped — shut down
                handle_command(
                    cmd, &evt_tx, &mut net, &mut ev_rx, &mut circles, &mut my_handle,
                ).await;
            }
            // Only poll the Veilid event stream once connected.
            Some(ev) = recv_opt(&mut ev_rx), if ev_rx.is_some() => {
                handle_inbound(ev, &evt_tx, &circles, &my_handle);
            }
        }
    }
}

/// Await the optional Veilid event receiver. The `if ev_rx.is_some()` guard on
/// the select arm ensures this is only polled when `Some`, so the `unwrap` holds.
async fn recv_opt(ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>) -> Option<VeilidNetEvent> {
    ev_rx.as_mut().unwrap().recv().await
}

async fn handle_command(
    cmd: NetCommand,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    circles: &mut Vec<VeilidCircle>,
    my_handle: &mut String,
) {
    match cmd {
        NetCommand::Connect { display_handle, .. } => {
            if let Some(h) = display_handle {
                *my_handle = h;
            }
            connect(evt_tx, net, ev_rx).await;
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

        // User-facing surfaces not yet on Veilid (Phases 3/4): answer honestly
        // rather than silently swallow.
        NetCommand::SendRoom { .. }
        | NetCommand::JoinRoom { .. }
        | NetCommand::PublishShare { .. }
        | NetCommand::UnpublishShare { .. }
        | NetCommand::RefreshShares
        | NetCommand::RefreshPublicSpace
        | NetCommand::UploadAnnouncement { .. }
        | NetCommand::SetMotd { .. }
        | NetCommand::FetchShare { .. }
        | NetCommand::ConfirmFetch { .. } => {
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
    let dir = std::env::temp_dir().join("daemonseed-gui-veilid");
    let cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());

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

/// Join a circle: derive the content key + the shared rendezvous-owner seed from
/// the phrase, subscribe the rendezvous record, and record local state.
async fn join_circle(
    circle_id: u64,
    phrase: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &mut Vec<VeilidCircle>,
) {
    let err = |reason: String| {
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
        let _ = evt_tx.send(NetEvent::CircleJoined {
            circle_id: existing.circle_id,
            asset_addr: circle_fingerprint(&existing.cot_key),
        });
        return;
    }
    if let Err(e) = handle.subscribe_circle(owner_seed).await {
        return err(format!("subscribe failed: {e}"));
    }
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
    let Some(circle) = circles.iter().find(|c| c.circle_id == circle_id) else {
        return err("join the circle before sending".to_owned());
    };
    let Some(handle) = net.as_ref() else {
        return err("not connected to Veilid yet".to_owned());
    };
    let message = wire::CircleMessage {
        sender_handle: my_handle.to_owned(),
        body: text.to_owned(),
        sent_unix_ms: now_unix_ms(),
    };
    let sealed = match seal_message(&circle.cot_key, &message) {
        Ok(s) => s,
        Err(e) => return err(format!("seal failed: {e}")),
    };
    if let Err(e) = handle.publish_circle(circle.owner_seed, sealed).await {
        return err(format!("publish failed: {e}"));
    }
    // LOCAL ECHO (mirrors the relay actor): show the sender's own message now.
    let _ = evt_tx.send(NetEvent::CircleMessage {
        circle_id,
        who: my_handle.to_owned(),
        text: text.to_owned(),
        mine: true,
    });
}

/// Translate a `VeilidNetEvent` into the `NetEvent` contract. Inbound sealed
/// bytes are tried against each joined circle's key (the AEAD seal authenticates
/// the match); own messages are suppressed (already local-echoed).
fn handle_inbound(
    ev: VeilidNetEvent,
    evt_tx: &UnboundedSender<NetEvent>,
    circles: &[VeilidCircle],
    my_handle: &str,
) {
    let VeilidNetEvent::Inbound { bytes } = ev else {
        // Attachment / RouteChanged / ValueChanged carry no chat payload for S2.
        return;
    };
    for circle in circles {
        if let Ok(msg) = open_message(&circle.cot_key, &bytes) {
            if msg.sender_handle != my_handle {
                let _ = evt_tx.send(NetEvent::CircleMessage {
                    circle_id: circle.circle_id,
                    who: msg.sender_handle,
                    text: msg.body,
                    mine: false,
                });
            }
            return; // opened under exactly one circle
        }
    }
}
