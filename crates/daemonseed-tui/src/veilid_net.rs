//! Parallel Veilid-backed net actor (#98 S2), compiled only under the `veilid`
//! feature.
//!
//! It implements the SAME `NetCommand` / `NetEvent` contract the relay actor in
//! [`crate::net`] does, so the UI is unchanged — the only switch is which actor
//! [`crate::net::NetHandle::new`] spawns (a `#[cfg(feature = "veilid")]` branch).
//! Backed by [`daemonseed_veilid_net::VeilidNetHandle`]. This is the TUI mirror
//! of `daemonseed-gui`'s `veilid_net` module, adapted to the TUI's command
//! surface (the GUI and TUI `NetCommand`/`NetEvent` enums diverge — see below).
//!
//! **Circles-only today.** `Connect` (attach), `JoinCircle`, `SendChat` and the
//! inbound circle path are live; the lobby (public room), shares, presence and
//! MOTD return the matching per-surface error event carrying `"not yet on
//! Veilid"` until Phases 3/4. This is a degraded-but-honest dev/test mode, NOT a
//! dual transport — it honors the no-relay↔Veilid-interop clean cut (one
//! transport at a time).
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
//! **No actor echo; suppress the DHT re-surface.** The TUI app layer already
//! local-echoes a composed line on Enter (its `App` Enter handler) — unlike the
//! GUI, whose actor's `mine:true` echo is the *only* render path. So this actor
//! must NOT echo (that would double-render every own message). What it must do is
//! drop the member's OWN write when Veilid's circle watch re-surfaces it tens of
//! seconds later: the inbound path suppresses it by sender-handle match (the
//! handle is learned from each `SendChat`, `None` until then). End state: an own
//! message renders exactly once (the app's Enter echo), a foreign message once
//! (the inbound path), matching the relay TUI's single-render behavior.
//!
//! **Single encryption layer.** Content is sealed under the circle `cot_key`
//! exactly as on the relay (`seal_message` / `open_message`); the Veilid DHT
//! stores those opaque bytes verbatim. This actor never touches Veilid's
//! transport crypto.
//!
//! **Inbound demux.** A received blob is tried against each joined circle's
//! `cot_key` — the AEAD seal is authenticated, so the wrong key simply fails to
//! open; the frame is attributed to the single circle whose key opened it
//! (ISC-A-C30).

use daemonseed_core::circle::default_circle_label;
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

/// Reported for [`NetEvent::Connected::version`]: the Veilid transport carries
/// no negotiated wire version (unlike the relay's APP_HELLO handshake), so we
/// report the Veilid-era major.minor for the UI's status line.
const VEILID_WIRE_VERSION: &str = "2.0";

/// The honest answer for every user-facing surface not yet on Veilid (Phases 3/4).
const NOT_YET: &str = "not yet on Veilid";

/// A joined circle's local state: the per-session routing id, the content key
/// (for seal/open), the shared rendezvous-owner seed (for publish/subscribe),
/// and the client-local display label.
struct VeilidCircle {
    circle_id: u64,
    cot_key: CircleKey,
    owner_seed: [u8; 32],
    label: String,
}

/// Best-effort wall-clock for the outgoing/echoed `CircleMessage` timestamp.
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

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break }; // UI side dropped — shut down
                handle_command(
                    cmd, &evt_tx, &mut net, &mut ev_rx, &mut circles,
                    &mut next_circle_id, &mut my_handle,
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

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    cmd: NetCommand,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &mut Option<VeilidNetHandle>,
    ev_rx: &mut Option<UnboundedReceiver<VeilidNetEvent>>,
    circles: &mut Vec<VeilidCircle>,
    next_circle_id: &mut u64,
    my_handle: &mut Option<String>,
) {
    match cmd {
        NetCommand::Connect { .. } => {
            connect(evt_tx, net, ev_rx).await;
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
            send_chat(circle_id, &body, &sender_handle, evt_tx, net, circles).await;
        }

        // User-facing surfaces not yet on Veilid (Phases 3/4): answer honestly on
        // the matching per-surface error event (the TUI has no single generic
        // `Error` variant — the GUI's contract does — so each maps to the event
        // its UI status line already renders) rather than silently swallow.
        NetCommand::SendPublicRoom { .. } => {
            let _ = evt_tx.send(NetEvent::PublicRoomJoinFailed {
                message: NOT_YET.to_owned(),
            });
        }
        NetCommand::DefineShare { .. } => {
            let _ = evt_tx.send(NetEvent::ShareDefineFailed {
                message: NOT_YET.to_owned(),
            });
        }
        NetCommand::RefreshShares => {
            let _ = evt_tx.send(NetEvent::SharesError {
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
        NetCommand::FetchShare { .. } | NetCommand::ConfirmFetch { .. } => {
            let _ = evt_tx.send(NetEvent::FetchError {
                message: NOT_YET.to_owned(),
            });
        }
        NetCommand::PublishShare { root, .. } => {
            let _ = evt_tx.send(NetEvent::PublishError {
                message: NOT_YET.to_owned(),
                root: Some(root),
            });
        }
        // An honest empty snapshot — nothing has been fetched in Veilid mode —
        // matches the relay's "no fetched shares" response, not an error.
        NetCommand::ListFetched { .. } => {
            let _ = evt_tx.send(NetEvent::FetchedShares { shares: Vec::new() });
        }

        // No-op commands: the relay actor's internal/timer-driven self-sends
        // (`ApplyAnnouncement`, `AnswerRollCall`, `ReconcileShares`,
        // `EmitHeartbeat`, `ApplyHeartbeat`) — none are generated in Veilid mode
        // (no relay machinery runs) — plus the control commands that are
        // documented no-ops for unknown work (`CancelPublish` with nothing
        // hashing, `UnpublishShare` for an id never published).
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
    let dir = std::env::temp_dir().join("daemonseed-tui-veilid");
    let cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());

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

/// Seal a message under the circle key, publish it to the rendezvous record, and
/// local-echo it (the DHT sweep would also re-surface our own write after watch
/// latency; the inbound path suppresses own messages by handle to avoid a double
/// render).
async fn send_chat(
    circle_id: u64,
    body: &str,
    sender_handle: &str,
    evt_tx: &UnboundedSender<NetEvent>,
    net: &Option<VeilidNetHandle>,
    circles: &[VeilidCircle],
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
    let sent_unix_ms = now_unix_ms();
    let message = wire::CircleMessage {
        sender_handle: sender_handle.to_owned(),
        body: body.to_owned(),
        sent_unix_ms,
    };
    let sealed = match seal_message(&circle.cot_key, &message) {
        Ok(s) => s,
        Err(e) => return err(format!("seal failed: {e}")),
    };
    if let Err(e) = handle.publish_circle(circle.owner_seed, sealed).await {
        err(format!("publish failed: {e}"));
    }
    // NO local echo here: unlike the GUI (whose actor is the only render path),
    // the TUI app layer already echoes the composed line on Enter
    // (`app::App` Enter handler, ISC-A-C29). Echoing again would render the own
    // message twice. The actor's only job is to drop the DELAYED DHT re-surface
    // of this same write (see `handle_inbound`), so the line stays single.
}

/// Translate a `VeilidNetEvent` into the `NetEvent` contract. Inbound sealed
/// bytes are tried against each joined circle's key (the AEAD seal authenticates
/// the match and attributes the frame to that one circle, ISC-A-C30). Our OWN
/// write re-surfaces here via the DHT watch tens of seconds after `send_chat`
/// published it; it is suppressed by sender-handle match so it never renders a
/// delayed duplicate of the app-layer Enter echo. `my_handle` is `None` until the
/// first send — so before we have sent, nothing is suppressed and a real inbound
/// from another member always renders.
fn handle_inbound(
    ev: VeilidNetEvent,
    evt_tx: &UnboundedSender<NetEvent>,
    circles: &[VeilidCircle],
    my_handle: &Option<String>,
) {
    let VeilidNetEvent::Inbound { bytes } = ev else {
        // Attachment / RouteChanged / ValueChanged carry no chat payload for S2.
        return;
    };
    for circle in circles {
        if let Ok(msg) = open_message(&circle.cot_key, &bytes) {
            let is_own = my_handle.as_deref() == Some(msg.sender_handle.as_str());
            if !is_own {
                let _ = evt_tx.send(NetEvent::ChatMessage {
                    circle_id: circle.circle_id,
                    sender: msg.sender_handle,
                    body: msg.body,
                    sent_unix_ms: msg.sent_unix_ms,
                });
            }
            return; // opened under exactly one circle
        }
    }
}

#[cfg(all(test, feature = "veilid"))]
mod tests {
    use super::*;
    use std::time::Duration;
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
    async fn refresh_shares_is_not_yet_on_veilid() {
        let ev = first_event(NetCommand::RefreshShares).await;
        match ev {
            NetEvent::SharesError { message } => assert_eq!(message, NOT_YET),
            other => panic!("expected SharesError, got {other:?}"),
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
    async fn publish_share_is_not_yet_and_keeps_root() {
        let root = std::path::PathBuf::from("/tmp/share");
        let ev = first_event(NetCommand::PublishShare {
            root: root.clone(),
            name: "docs".to_owned(),
            sharer_handle: "alice#abcd".to_owned(),
        })
        .await;
        match ev {
            NetEvent::PublishError { message, root: r } => {
                assert_eq!(message, NOT_YET);
                assert_eq!(r, Some(root));
            }
            other => panic!("expected PublishError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_fetched_yields_empty_snapshot() {
        let ev = first_event(NetCommand::ListFetched {
            fetched_root: std::path::PathBuf::from("/tmp/fetched"),
        })
        .await;
        match ev {
            NetEvent::FetchedShares { shares } => assert!(shares.is_empty()),
            other => panic!("expected empty FetchedShares, got {other:?}"),
        }
    }
}
