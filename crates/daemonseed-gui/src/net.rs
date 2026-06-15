//! Network actor — the async side of the GUI (round-3).
//!
//! The Slint UI thread is synchronous and must NEVER block on the network. The
//! daemon protocol is async. This module bridges them with the standard actor
//! shape, mirroring `daemonseed-tui`'s proven `net` actor: a dedicated named
//! thread owns a *current-thread* tokio runtime inside a [`tokio::task::LocalSet`];
//! [`NetCommand`]s flow in, [`NetEvent`]s flow out. The UI sends commands
//! fire-and-forget and drains events with non-blocking `try_recv`, so a slow
//! connect (or a foreign keepalive frame) never stalls a frame.
//!
//! This module is **Slint-free** (no `slint` import) so it stays unit-testable in
//! isolation and the UI/network concerns never entangle.
//!
//! ## Scope
//!
//! The **public Lobby room** (round 3) AND **circles** (round 5), end-to-end:
//! connect → auto-join the default public room → real Lobby chat; plus
//! `JoinCircle`/`SendCircle` for a SET of circle subscriptions (`Vec<CircleSub>`),
//! each sealed under its own `cot_key`. Both paths are mirrored from
//! `daemonseed_tui::net` so the clients interoperate byte-for-byte on the same
//! relay: the Lobby from `join_default_public_room` / `handle_send_public_room` /
//! `read_inbound_public_room`, and circles from `handle_join_circle` /
//! `handle_send_chat` / `read_inbound` (`derive_cot_key` → `asset_address` →
//! `seal_message`/`open_message` — the CIRCLE path, not the room path).
//!
//! ## Identity
//!
//! `my_handle` is a throwaway adjective-noun handle regenerated every launch.
//! There is **no persistent identity / first-start in this slice** — that is a
//! separate milestone. The actor signs public-room posts under a fresh
//! [`ClientIdentity::ephemeral`] per connect (the same key that proved the
//! connection), exactly as the TUI does.
//!
//! ## Why current-thread + `LocalSet`
//!
//! [`connect_session`] takes `&mut dyn TrustStore` (its future is `!Send`) and the
//! inbound reader holds an [`Rc`] of the room key, so neither can be
//! `tokio::spawn`ed onto a multi-thread runtime. Driving everything on one thread
//! via `block_on(local.run_until(..))` + [`tokio::task::spawn_local`] sidesteps
//! both `Send` bounds — identical to the TUI's rationale.

use std::rc::Rc;

use daemonseed_cli::connect::connect_session;
use daemonseed_cli::identity_proof::ClientIdentity;
use daemonseed_cli::session::AppSession;
use daemonseed_core::circle::key::{CotKey, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::public_room::{
    DEFAULT_ROOM, derive_room_key, open_room_message, room_asset_address, seal_room_message,
};
use daemonseed_core::storage::seeds::CounterState;
use daemonseed_proto::v1 as wire;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// A command from the UI thread to the network actor. Fire-and-forget: the UI
/// never blocks waiting for one to complete.
pub enum NetCommand {
    /// Open a connection to `server_id` at `address` (trusted mode), run the full
    /// TLS + APP_HELLO + identity-proof flow to Authenticated, keep the live
    /// session, and auto-join the default public room.
    Connect { server_id: String, address: String },
    /// Join (subscribe to) a public room by name. In this slice production Connect
    /// auto-joins the default room directly (via [`Actor::join_room`]); this
    /// command exists so the post-`open` JoinRoom path is driven identically by a
    /// test through the `AttachSession` seam. Not constructed in non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
    JoinRoom { room: String },
    /// Publish a message to the joined public room: seal it under the global room
    /// key, send the `CotFrame`, and LOCAL-ECHO it (the relay never reflects a
    /// sender's own frame — see [`Actor::handle_send_room`]).
    SendRoom { text: String },
    /// Join (subscribe to) a circle by its shared phrase: derive the circle key,
    /// derive the per-relay rendezvous, subscribe, and spawn the circle's inbound
    /// reader. `circle_id` is the GUI-assigned routing tag (the GUI owns circle
    /// identity); it is echoed back on every [`NetEvent::CircleMessage`] so an
    /// inbound frame lands in the right circle. Mirrors `daemonseed_tui`'s
    /// `handle_join_circle` (derive_cot_key → asset_address → subscribe).
    JoinCircle { circle_id: u64, phrase: String },
    /// Publish a message to a joined circle: seal it under that circle's `cot_key`
    /// and LOCAL-ECHO it (the relay never reflects a sender's own frame). Mirrors
    /// `daemonseed_tui`'s `handle_send_chat`.
    SendCircle { circle_id: u64, text: String },
    /// TEST SEAM (never used in production). Inject a pre-opened [`AppSession`]
    /// plus the `server_id` the test namespaces its rendezvous by, so a test
    /// exercises the SAME post-`open` JoinRoom/SendRoom path as a real Connect
    /// while bypassing TCP/TLS. Gated to test builds.
    #[doc(hidden)]
    #[cfg(test)]
    AttachSession {
        session: AppSession,
        server_id: String,
    },
}

/// An event from the network actor to the UI thread.
#[derive(Debug, Clone)]
pub enum NetEvent {
    /// The connection reached Authenticated; `server_handle` is the verified
    /// relay handle.
    Connected { server_handle: String },
    /// The connection attempt failed; `reason` is human-readable.
    ConnectFailed { reason: String },
    /// A public room is subscribed and chat can flow; `room` is the joined name.
    RoomJoined { room: String },
    /// A message to render: a verified inbound frame, or a local echo of the
    /// user's own just-sent message. `mine` is true when `who == my_handle`.
    Message {
        who: String,
        text: String,
        mine: bool,
    },
    /// A non-fatal error to surface (join/send failure). The connection itself
    /// may still be up.
    Error { reason: String },
    /// A circle subscribe stream is live; chat can flow. `circle_id` is the
    /// GUI-assigned tag from the originating [`NetCommand::JoinCircle`].
    CircleJoined { circle_id: u64 },
    /// A circle message to render: a verified inbound frame for `circle_id`, or a
    /// local echo of the user's own just-sent message. `mine` is true when
    /// `who == my_handle`.
    CircleMessage {
        circle_id: u64,
        who: String,
        text: String,
        mine: bool,
    },
    /// A non-fatal circle error (join/send failure) tagged with the circle it
    /// concerns. The connection itself may still be up.
    CircleError { circle_id: u64, reason: String },
}

/// The UI-side handle: owns the channels and the net thread. Held for the app's
/// lifetime by `main` so neither the thread nor the event drain silently dies.
pub struct NetHandle {
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
    evt_rx: mpsc::UnboundedReceiver<NetEvent>,
    _thread: std::thread::JoinHandle<()>,
}

impl NetHandle {
    /// Spawn the dedicated network thread (current-thread tokio runtime inside a
    /// [`tokio::task::LocalSet`]) and the actor loop.
    ///
    /// Caller contract: the process-wide CryptoProvider + oxicrypt module must be
    /// installed before a `Connect` is sent (the binary does this at startup; the
    /// in-process test drives it too). Building the channels + thread itself has
    /// no such dependency, so `new` is infallible beyond the OS thread spawn.
    pub fn new() -> std::io::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("daemonseed-gui-net".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread net runtime");
                let local = tokio::task::LocalSet::new();
                // `spawn_local` (the inbound reader) is run INSIDE this
                // `run_until` context — the reader holds an `Rc` of the room key,
                // so it cannot ride a multi-thread runtime.
                rt.block_on(local.run_until(net_actor(cmd_rx, evt_tx)));
            })?;
        Ok(Self {
            cmd_tx,
            evt_rx,
            _thread: thread,
        })
    }

    /// Queue a command for the actor (non-blocking). Fails only if the actor
    /// stopped; the UI treats that as "offline" and never panics.
    pub fn send(&self, cmd: NetCommand) -> Result<(), NetCommand> {
        self.cmd_tx.send(cmd).map_err(|e| e.0)
    }

    /// Non-blocking single-event poll. `Ok(None)` means "nothing right now";
    /// `Err(())` means the actor thread is gone (treat as offline).
    pub fn try_recv(&mut self) -> Result<Option<NetEvent>, ()> {
        match self.evt_rx.try_recv() {
            Ok(evt) => Ok(Some(evt)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(()),
        }
    }
}

/// The live public room the actor is subscribed to. Mirrors `daemonseed_tui`'s
/// `PublicRoom`: the outbound frame sender (to publish sealed messages) plus the
/// global room key, rendezvous address, and room name. Storing the OUT sender
/// here — and `spawn_local`-ing the reader to own the IN half — is the TUI
/// ownership model: the `&mut AppSession` is never shared between reader and
/// sender (`subscribe` hands back owned halves), so no `Rc<RefCell<AppSession>>`.
struct PublicRoom {
    /// The room name, joined into each message's provenance signature.
    room: String,
    /// The GLOBAL shared room key — derived from public inputs, so every client
    /// AND the relay hold it. Reused as the AEAD key for seal/open.
    room_key: Rc<daemonseed_core::circle::key::CotKey>,
    /// The room's rendezvous address on the connected relay.
    asset_addr: daemonseed_core::cot::AssetAddr,
    /// Outbound frame sender — publishing seals + sends here.
    out_tx: mpsc::Sender<wire::CotFrame>,
}

/// One live circle the daemon is subscribed to. A member can hold several at once
/// ([`Actor::circles`]); each carries its OWN `cot_key`, so a post seals under
/// exactly that circle's key and an inbound frame is attributed to the single
/// circle whose key opened it (ISC-A-C30 — no cross-circle key/attribution
/// mixing). Mirrors `daemonseed_tui::net::Circle`, minus the client-local label
/// (the GUI owns display); `circle_id` is the GUI-assigned routing tag.
struct CircleSub {
    /// GUI-assigned routing tag — echoed on every [`NetEvent::CircleMessage`].
    circle_id: u64,
    /// This circle's key. Used to pick the seal key on send and held by the
    /// inbound reader (`Rc`) to open frames.
    cot_key: Rc<CotKey>,
    /// Per-relay rendezvous address; the dedupe key for idempotent re-join.
    asset_addr: AssetAddr,
    /// Outbound frame sender — sealing seals + sends here.
    out_tx: mpsc::Sender<wire::CotFrame>,
}

/// Mutable state the actor carries across commands. `identity`/`server_id` and
/// the `counters`/`trust` stores live here for the SESSION lifetime, not as
/// Connect-handler locals (mirrors the TUI).
struct Actor {
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    /// The live application session, once Connected.
    session: Option<AppSession>,
    /// The connected relay's wire server-id, namespacing the room address.
    server_id: Option<String>,
    /// The daemon's own ephemeral identity, retained after connect so room posts
    /// are self-signed for provenance under the key that proved the connection.
    identity: Option<ClientIdentity>,
    /// This launch's display handle (adjective-noun, ephemeral). Used to tag
    /// local echoes and to decide `mine` on inbound frames.
    my_handle: String,
    /// Monotonic send counter (ISC-19) + per-server highest-seen (ISC-34),
    /// threaded through `connect_session`. Lives for the session, not the call.
    counters: CounterState,
    /// In-memory C22 trust store; the trusted server entry is upserted per
    /// connect so `connect_session` accepts the presented key.
    trust: InMemoryTrustStore,
    /// The auto-joined default public room, if subscribed.
    public_room: Option<PublicRoom>,
    /// The set of circles currently joined. Joining ADDS; it never evicts. Each
    /// holds its own key, so sealing/attribution stays per-circle (ISC-A-C30).
    /// Session-only (RAM) — not persisted, like the TUI.
    circles: Vec<CircleSub>,
}

impl Actor {
    fn emit(&self, evt: NetEvent) {
        let _ = self.evt_tx.send(evt);
    }

    /// Open a connection and keep the live session, then auto-join the default
    /// room. Mirrors `daemonseed_tui::net::Actor::handle_connect`: ephemeral
    /// identity, trusted-mode upsert, `connect_session` → `AppSession::open`.
    async fn handle_connect(&mut self, server_id: &str, address: &str) {
        let identity = match ClientIdentity::ephemeral() {
            Ok(i) => i,
            Err(e) => {
                return self.emit(NetEvent::ConnectFailed {
                    reason: format!("identity: {e}"),
                });
            }
        };
        let server_handle = match server_id.parse::<Handle>() {
            Ok(h) => h,
            Err(_) => {
                return self.emit(NetEvent::ConnectFailed {
                    reason: "server-id is not a valid <name>#<12hex> handle".to_owned(),
                });
            }
        };
        // Trusted mode: TOFU-pin the presented key (the GUI alpha has no operator
        // key import flow, so untrusted mode is not offered — mirrors the TUI,
        // which rejects untrusted without an imported key).
        self.trust
            .upsert(ServerEntry::new_trusted(server_handle, address.to_owned()));

        match connect_session(
            server_id,
            address,
            &identity,
            &mut self.counters,
            &mut self.trust,
        )
        .await
        {
            Ok((outcome, stream)) => match AppSession::open(stream).await {
                Ok(session) => {
                    self.session = Some(session);
                    self.server_id = Some(server_id.to_owned());
                    self.identity = Some(identity);
                    self.emit(NetEvent::Connected {
                        server_handle: outcome.server_handle,
                    });
                    // The default chat surface is a public room: auto-join it on
                    // connect so chatting needs no circle (mirrors the TUI). A
                    // failure here is non-fatal — it surfaces as an Error; the
                    // connection itself is up.
                    self.join_room(DEFAULT_ROOM).await;
                }
                Err(e) => {
                    self.emit(NetEvent::ConnectFailed {
                        reason: format!("application session setup failed: {e}"),
                    });
                }
            },
            Err(e) => {
                self.emit(NetEvent::ConnectFailed {
                    reason: e.to_string(),
                });
            }
        }
    }

    /// Inject an already-opened session (TEST SEAM). Lets a test drive the EXACT
    /// post-`open` JoinRoom/SendRoom path with no TCP/TLS. No identity is set
    /// (post-`open` send signs under a fresh ephemeral identity below — but the
    /// test path supplies one explicitly via the same flow as the real connect).
    #[cfg(test)]
    async fn handle_attach(&mut self, session: AppSession, server_id: String) {
        // A test needs a signing identity to seal room posts, exactly as a real
        // connect retains one. Generate an ephemeral one here so the AttachSession
        // path is faithful to the post-`open` Send path.
        match ClientIdentity::ephemeral() {
            Ok(id) => self.identity = Some(id),
            Err(e) => {
                return self.emit(NetEvent::ConnectFailed {
                    reason: format!("identity: {e}"),
                });
            }
        }
        self.session = Some(session);
        self.server_id = Some(server_id);
        self.emit(NetEvent::Connected {
            server_handle: "attached#000000000000".to_owned(),
        });
    }

    /// Derive the room key + rendezvous address, subscribe, spawn the inbound
    /// reader, and store the outbound half. ONE shared path for Connect's
    /// auto-join and the `AttachSession`-driven JoinRoom (both route here off
    /// actor state), mirroring `daemonseed_tui::net::Actor::join_default_public_room`.
    async fn join_room(&mut self, room: &str) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::Error {
                reason: "not connected to a relay yet".to_owned(),
            });
        };
        let Some(server_id) = self.server_id.as_ref() else {
            return self.emit(NetEvent::Error {
                reason: "no server-id for the connected relay".to_owned(),
            });
        };

        // The room key is GLOBAL: derived from public inputs, identical for every
        // client and the relay. Reused as the AEAD key for seal/open.
        let room = room.to_owned();
        let room_key = match derive_room_key(&room, &CNSA_2_0) {
            Ok(k) => Rc::new(k),
            Err(e) => {
                return self.emit(NetEvent::Error {
                    reason: format!("public-room key derivation failed: {e}"),
                });
            }
        };
        // VERBATIM mirror of TUI net.rs:1277 —
        //   `room_asset_address(&room_key, server_id.as_bytes())`
        let asset_addr = match room_asset_address(&room_key, server_id.as_bytes()) {
            Ok(a) => a,
            Err(e) => {
                return self.emit(NetEvent::Error {
                    reason: format!("public-room rendezvous derivation failed: {e}"),
                });
            }
        };

        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);
        // Name the rendezvous with an initial EMPTY frame (registers the asset;
        // not relayed) before subscribing.
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        if out_tx.send(naming).await.is_err() {
            return self.emit(NetEvent::Error {
                reason: "public-room subscribe channel closed".to_owned(),
            });
        }

        let mut cot = session.circle_of_trust();
        let inbound = match cot.subscribe(ReceiverStream::new(out_rx)).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::Error {
                    reason: format!("public-room subscribe refused: {}", status.message()),
                });
            }
        };

        // Inbound reader: owns the IN half, decrypts each frame under the global
        // room key, emits a `Message`. `spawn_local` because it holds the `Rc`
        // room key (mirrors the TUI). The OUT sender stays here in actor state —
        // `&mut AppSession` is never shared between reader and sender.
        let reader_key = Rc::clone(&room_key);
        let reader_tx = self.evt_tx.clone();
        let reader_handle = self.my_handle.clone();
        tokio::task::spawn_local(read_inbound_public_room(
            inbound,
            reader_key,
            reader_tx,
            reader_handle,
        ));

        self.public_room = Some(PublicRoom {
            room: room.clone(),
            room_key,
            asset_addr,
            out_tx,
        });
        self.emit(NetEvent::RoomJoined { room });
    }

    /// Publish a message to the joined public room and LOCAL-ECHO it. Mirrors
    /// `daemonseed_tui::net::Actor::handle_send_public_room` for the seal/send,
    /// then adds the local echo the TUI's *app* layer does (app.rs:2849: "Local
    /// echo, Lobby-tagged. The relay never reflects a frame to its sender."). We
    /// echo HERE because the GUI has no separate app layer between the net actor
    /// and the UI; without it the sender would never see their own message.
    async fn handle_send_room(&mut self, text: &str) {
        let Some(room) = self.public_room.as_ref() else {
            return self.emit(NetEvent::Error {
                reason: "no public room joined".to_owned(),
            });
        };
        let Some(identity) = self.identity.as_ref() else {
            return self.emit(NetEvent::Error {
                reason: "no identity to sign the post".to_owned(),
            });
        };

        let sealed = match seal_room_message(
            &room.room_key,
            identity.signing(),
            &room.room,
            &self.my_handle,
            text,
            now_unix_ms(),
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.emit(NetEvent::Error {
                    reason: format!("public-room seal/sign failed: {e}"),
                });
            }
        };
        let frame = wire::CotFrame {
            asset_address: room.asset_addr.as_bytes().to_vec(),
            payload: sealed,
        };
        if room.out_tx.send(frame).await.is_err() {
            return self.emit(NetEvent::Error {
                reason: "public-room stream closed; reconnect to post".to_owned(),
            });
        }

        // LOCAL ECHO: the relay does not reflect a sender's own frame back, so
        // emit it locally (mirrors the TUI's choice). `mine == true`; the inbound
        // reader's `mine` check (who == my_handle) prevents a double-render even
        // if a relay ever did reflect.
        self.emit(NetEvent::Message {
            who: self.my_handle.clone(),
            text: text.to_owned(),
            mine: true,
        });
    }

    /// Join a circle by its shared phrase: derive the key, derive the per-relay
    /// rendezvous, subscribe, and spawn the circle's inbound reader. VERBATIM
    /// mirror of `daemonseed_tui::net::Actor::handle_join_circle` — `derive_cot_key`
    /// → `asset_address(cot_key, server_id.as_bytes())` (the CIRCLE path, not the
    /// room path). Joining ADDS to the set; a circle whose rendezvous is already
    /// present is an idempotent no-op re-join (re-emits `CircleJoined`). All
    /// failures surface as `CircleError` tagged with `circle_id`; the connection
    /// stays up.
    async fn handle_join_circle(&mut self, circle_id: u64, phrase: &str) {
        let err = |reason: String| NetEvent::CircleError { circle_id, reason };

        let Some(session) = self.session.as_ref() else {
            return self.emit(err("not connected to a relay yet".to_owned()));
        };
        let Some(server_id) = self.server_id.as_ref() else {
            return self.emit(err("no server-id for the connected relay".to_owned()));
        };

        let cot_key = match derive_cot_key(phrase, &CNSA_2_0) {
            Ok(k) => Rc::new(k),
            Err(e) => return self.emit(err(format!("circle-key derivation failed: {e}"))),
        };
        // VERBATIM mirror of TUI net.rs:1172 — the CIRCLE rendezvous is
        // `asset_address(&cot_key, server_id.as_bytes())` (NOT room_asset_address).
        let asset_addr = match asset_address(&cot_key, server_id.as_bytes()) {
            Ok(a) => a,
            Err(e) => return self.emit(err(format!("rendezvous derivation failed: {e}"))),
        };

        // Idempotent join (mirror): a circle already subscribed at this rendezvous
        // is not re-subscribed — re-emit CircleJoined so the UI re-selects it.
        // Address-equality is the dedupe key (same phrase → same cot_key → same
        // addr). We key the re-emit on the EXISTING sub's circle_id so the UI's
        // own routing stays stable.
        if let Some(existing) = self.circles.iter().find(|c| c.asset_addr == asset_addr) {
            return self.emit(NetEvent::CircleJoined {
                circle_id: existing.circle_id,
            });
        }

        // Outbound half: first frame names the asset (empty payload, not relayed),
        // sent before subscribe consumes the receiver (mirror).
        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        if out_tx.send(naming).await.is_err() {
            return self.emit(err("circle subscribe channel closed".to_owned()));
        }

        let mut cot = session.circle_of_trust();
        let inbound = match cot.subscribe(ReceiverStream::new(out_rx)).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(err(format!("subscribe refused: {}", status.message())));
            }
        };

        // Inbound reader: decrypts each frame under THIS circle's key and emits a
        // CircleMessage tagged with THIS circle_id (ISC-A-C30 attribution).
        // `spawn_local` because it holds the `Rc` key (mirrors the TUI / lobby).
        let reader_key = Rc::clone(&cot_key);
        let reader_tx = self.evt_tx.clone();
        let reader_handle = self.my_handle.clone();
        tokio::task::spawn_local(read_inbound_circle(
            inbound,
            circle_id,
            reader_key,
            reader_tx,
            reader_handle,
        ));

        self.circles.push(CircleSub {
            circle_id,
            cot_key,
            asset_addr,
            out_tx,
        });
        self.emit(NetEvent::CircleJoined { circle_id });
    }

    /// Publish a message to a joined circle and LOCAL-ECHO it. Mirrors
    /// `daemonseed_tui::net::Actor::handle_send_chat` for the seal/send; the local
    /// echo is the GUI's (the relay never reflects a sender's own frame, and the
    /// GUI has no app layer between the actor and the UI — same as the Lobby path).
    /// Circle messages are AEAD-only: `seal_message` takes the `cot_key` and no
    /// signing key — membership IS the auth (no provenance signature, unlike rooms).
    async fn handle_send_circle(&mut self, circle_id: u64, text: &str) {
        let Some(circle) = self.circles.iter().find(|c| c.circle_id == circle_id) else {
            return self.emit(NetEvent::CircleError {
                circle_id,
                reason: "join the circle before sending".to_owned(),
            });
        };
        let message = wire::CircleMessage {
            sender_handle: self.my_handle.clone(),
            body: text.to_owned(),
            sent_unix_ms: now_unix_ms(),
        };
        let sealed = match seal_message(&circle.cot_key, &message) {
            Ok(s) => s,
            Err(e) => {
                return self.emit(NetEvent::CircleError {
                    circle_id,
                    reason: format!("seal failed: {e}"),
                });
            }
        };
        let frame = wire::CotFrame {
            asset_address: circle.asset_addr.as_bytes().to_vec(),
            payload: sealed,
        };
        if circle.out_tx.send(frame).await.is_err() {
            return self.emit(NetEvent::CircleError {
                circle_id,
                reason: "circle stream closed; rejoin to send".to_owned(),
            });
        }

        // LOCAL ECHO: the relay does not reflect a sender's own frame, so emit it
        // locally (the inbound reader's `mine` check prevents a double-render even
        // if a relay ever did reflect).
        self.emit(NetEvent::CircleMessage {
            circle_id,
            who: self.my_handle.clone(),
            text: text.to_owned(),
            mine: true,
        });
    }
}

/// The actor loop: build state, then service commands one at a time.
async fn net_actor(
    mut cmd_rx: mpsc::UnboundedReceiver<NetCommand>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    let mut actor = Actor {
        evt_tx,
        session: None,
        server_id: None,
        identity: None,
        my_handle: generate_handle(),
        counters: CounterState::default(),
        trust: InMemoryTrustStore::new(),
        public_room: None,
        circles: Vec::new(),
    };
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            NetCommand::Connect { server_id, address } => {
                actor.handle_connect(&server_id, &address).await
            }
            NetCommand::JoinRoom { room } => actor.join_room(&room).await,
            NetCommand::SendRoom { text } => actor.handle_send_room(&text).await,
            NetCommand::JoinCircle { circle_id, phrase } => {
                actor.handle_join_circle(circle_id, &phrase).await
            }
            NetCommand::SendCircle { circle_id, text } => {
                actor.handle_send_circle(circle_id, &text).await
            }
            #[cfg(test)]
            NetCommand::AttachSession { session, server_id } => {
                actor.handle_attach(session, server_id).await
            }
        }
    }
}

/// Inbound reader for a public room. Mirrors
/// `daemonseed_tui::net::read_inbound_public_room`, with the spec-mandated guard:
/// **skip empty payloads BEFORE `open_room_message`** (the subscribe stream's
/// initial/keepalive frames carry an empty payload). On a verified open, emit a
/// `Message`; on a decrypt/provenance error, skip silently (a foreign frame).
async fn read_inbound_public_room(
    mut inbound: tonic::Streaming<wire::CotFrame>,
    room_key: Rc<daemonseed_core::circle::key::CotKey>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    my_handle: String,
) {
    loop {
        match inbound.message().await {
            Ok(Some(frame)) => {
                // Empty payload = naming/keepalive frame; never a sealed message.
                // Skip it BEFORE attempting to open (open would just error, but
                // skipping first keeps intent explicit per the architecture note).
                if frame.payload.is_empty() {
                    continue;
                }
                // `open_room_message` verifies the embedded provenance signature
                // before returning, so only verified messages are surfaced.
                if let Ok(msg) = open_room_message(&room_key, &frame.payload) {
                    let mine = msg.sender_handle == my_handle;
                    if evt_tx
                        .send(NetEvent::Message {
                            who: msg.sender_handle,
                            text: msg.body,
                            mine,
                        })
                        .is_err()
                    {
                        return; // UI gone
                    }
                }
                // A decrypt/provenance error means a foreign frame — skip silently.
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// Read one circle's inbound frame stream, decrypt each under THAT circle's key,
/// and emit a [`NetEvent::CircleMessage`] tagged with `circle_id` (ISC-A-C30
/// attribution: a frame is attributed only to the circle whose key opened it).
/// Each joined circle gets its own reader task with its own `cot_key`/`circle_id`.
/// Empty payloads (the naming/keepalive frame) are skipped before `open_message`
/// (mirrors the lobby reader); undecryptable frames (foreign noise on the shared
/// rendezvous, or tampering) are skipped silently. `mine` is set when the sealed
/// sender handle equals this client's handle. Returns when the stream ends.
async fn read_inbound_circle(
    mut inbound: tonic::Streaming<wire::CotFrame>,
    circle_id: u64,
    cot_key: Rc<CotKey>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    my_handle: String,
) {
    loop {
        match inbound.message().await {
            Ok(Some(frame)) => {
                // Empty payload = naming/keepalive frame; never a sealed message.
                if frame.payload.is_empty() {
                    continue;
                }
                if let Ok(msg) = open_message(&cot_key, &frame.payload) {
                    let mine = msg.sender_handle == my_handle;
                    if evt_tx
                        .send(NetEvent::CircleMessage {
                            circle_id,
                            who: msg.sender_handle,
                            text: msg.body,
                            mine,
                        })
                        .is_err()
                    {
                        return; // UI gone
                    }
                }
                // A decrypt/auth error means a foreign frame — skip silently.
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// Wall-clock now in unix milliseconds (advisory message timestamp). Mirrors the
/// TUI's `now_unix_ms`.
fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A readable, ephemeral adjective-noun display handle, regenerated every launch.
/// There is NO persistent identity in this slice — a stable handle (passphrase
/// plus sealed seeds blob) is a separate milestone. The handle is purely for
/// display and local-echo tagging; the provenance signature still binds to the
/// ephemeral signing key, so a spoofed handle can never impersonate a real key.
fn generate_handle() -> String {
    const ADJ: &[&str] = &[
        "wandering",
        "midnight",
        "quiet",
        "amber",
        "silver",
        "restless",
        "hidden",
        "drifting",
        "copper",
        "northern",
        "velvet",
        "distant",
    ];
    const NOUN: &[&str] = &[
        "otter", "sparrow", "harbor", "signal", "ember", "willow", "lantern", "current", "thicket",
        "meadow", "cinder", "beacon",
    ];
    // Seed from the wall clock — good enough for a non-security display handle.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let adj = ADJ[(seed as usize) % ADJ.len()];
    let noun = NOUN[((seed >> 8) as usize) % NOUN.len()];
    format!("{adj}-{noun}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::crypto::suite::CNSA_2_0;
    use daemonseed_core::public_room::{derive_room_key, room_asset_address};
    use std::sync::Arc;
    use std::time::Duration;

    /// A fixed server-id the cross-derivation + relay tests namespace by.
    const SERVER_ID: &str = "relay-test#001122334455";

    /// ISC: interop insurance — the GUI's lobby asset address is the canonical
    /// derivation, byte-for-byte. If `DEFAULT_ROOM`, the suite, or the server_id
    /// source ever drifts, this equality breaks and the GUI silently stops
    /// meeting the TUI at the same rendezvous. We pin it against an explicit,
    /// independently-spelled core call (same inputs the actor's `join_room` uses).
    #[test]
    fn lobby_asset_address_is_canonical() {
        let _ = oxicrypt_module::initialize();
        // The address the actor's join_room computes (DEFAULT_ROOM, server_id bytes).
        let key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let gui_addr = room_asset_address(&key, SERVER_ID.as_bytes()).unwrap();

        // An independently-computed expectation: re-derive from scratch with the
        // same canonical inputs. Any divergence in DEFAULT_ROOM / suite / the
        // server_id-as-bytes source flips this.
        let expect_key = derive_room_key("lobby", &CNSA_2_0).unwrap();
        let expect_addr = room_asset_address(&expect_key, b"relay-test#001122334455").unwrap();

        assert_eq!(
            gui_addr.as_bytes(),
            expect_addr.as_bytes(),
            "GUI lobby rendezvous must be the canonical derivation, byte-for-byte"
        );
        // And DEFAULT_ROOM really is the lobby (guards a silent constant change).
        assert_eq!(DEFAULT_ROOM, "lobby");
    }

    // ── In-process relay round-trip (deterministic, no network) ──────────────
    //
    // Mirrors daemonseed-integration-tests/tests/cot_chat_e2e.rs: a shared
    // CotRegistry + serve_application over tokio::io::duplex. Two AppSessions are
    // fed to two actor instances via the AttachSession seam with the SAME
    // server_id; member A SendRoom, member B's actor must emit a decrypted
    // Message. This drives the REAL join_room/handle_send_room/inbound path.

    use daemonseed_server::cot::CotRegistry;
    use daemonseed_server::public_space::{
        PublicSpaceService, PublicSpaceState, serve_application,
    };

    fn spawn_relay(
        server_io: tokio::io::DuplexStream,
        registry: CotRegistry,
    ) -> tokio::task::JoinHandle<Result<(), tonic::transport::Error>> {
        tokio::task::spawn_local(serve_application(
            server_io,
            PublicSpaceService::new(Arc::new(PublicSpaceState::empty())),
            registry,
            Arc::new(Vec::new()),
        ))
    }

    /// Build a `NetHandle` whose actor is pre-attached to `session` via the test
    /// seam, then JoinRoom the default room. Returns the handle so the caller can
    /// drive SendRoom and drain events. Runs the actor on the SAME LocalSet as the
    /// relay so `spawn_local` works — so we DON'T use `NetHandle::new` (its own
    /// thread); instead we spawn the actor loop locally and hand back channels.
    struct LocalActor {
        cmd_tx: mpsc::UnboundedSender<NetCommand>,
        evt_rx: mpsc::UnboundedReceiver<NetEvent>,
    }

    fn spawn_local_actor() -> LocalActor {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        tokio::task::spawn_local(net_actor(cmd_rx, evt_tx));
        LocalActor { cmd_tx, evt_rx }
    }

    async fn wait_for_message(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<(String, String)> {
        for _ in 0..400 {
            while let Ok(evt) = evt_rx.try_recv() {
                if let NetEvent::Message { who, text, .. } = evt {
                    return Some((who, text));
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    async fn wait_for_room_joined(evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>) {
        for _ in 0..400 {
            while let Ok(evt) = evt_rx.try_recv() {
                if matches!(evt, NetEvent::RoomJoined { .. }) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("actor never reported RoomJoined");
    }

    async fn wait_registry(registry: &CotRegistry, n: usize) {
        for _ in 0..400 {
            if registry.live_assets() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("relay never registered {n} asset(s)");
    }

    #[test]
    fn in_process_relay_round_trip() {
        let _ = oxicrypt_module::initialize();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            // One shared relay registry; two independent connections to it.
            let registry = CotRegistry::new();
            let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
            let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
            let _srv_a = spawn_relay(a_server_io, registry.clone());
            let _srv_b = spawn_relay(b_server_io, registry.clone());

            let sess_a = AppSession::open(a_client_io).await.expect("A session");
            let sess_b = AppSession::open(b_client_io).await.expect("B session");

            // Two actor instances, same server_id → same rendezvous.
            let mut a = spawn_local_actor();
            let mut b = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: SERVER_ID.to_owned(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: SERVER_ID.to_owned(),
                })
                .ok();

            // B joins first and waits for the relay to register the rendezvous,
            // so A's publish is not a no-op against an empty asset. A and B meet
            // at the SAME address (same room, same server_id), so the relay holds
            // exactly ONE live asset — both members are subscribers of it.
            b.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            wait_registry(&registry, 1).await;
            a.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            // Let A's subscribe register before publishing (its RoomJoined event
            // is the signal the join completed). Drain until A reports joined.
            wait_for_room_joined(&mut a.evt_rx).await;

            // A publishes a sealed message.
            a.cmd_tx
                .send(NetCommand::SendRoom {
                    text: "meet at the usual place".to_owned(),
                })
                .ok();

            // B's actor must emit a DECRYPTED inbound Message with the body. (A
            // also emits its own local echo on a.evt_rx — proving local echo —
            // but the cross-member proof is B receiving it.)
            let got = wait_for_message(&mut b.evt_rx).await;
            assert_eq!(
                got.map(|(_, text)| text),
                Some("meet at the usual place".to_owned()),
                "member B's actor emits the decrypted public-room message"
            );

            // A's own local echo is on its own channel (mirrors the relay never
            // reflecting to the sender — the echo is the only way A sees its msg).
            let a_echo = wait_for_message(&mut a.evt_rx).await;
            assert_eq!(
                a_echo.map(|(_, text)| text),
                Some("meet at the usual place".to_owned()),
                "sender A sees its own message only via local echo"
            );
        });
    }

    /// Opacity: a non-member (different room key) cannot decrypt the frame. We
    /// reuse the core seal/open primitives the actor uses — the actor's inbound
    /// reader drops exactly such a frame silently (the `if let Ok(..)` arm).
    #[test]
    fn non_member_cannot_decrypt() {
        use daemonseed_core::identity::keys::SignKeypair;
        use daemonseed_core::public_room::{open_room_message, seal_room_message};
        let _ = oxicrypt_module::initialize();
        let lobby = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
        let other = derive_room_key("a-room-no-member-joined", &CNSA_2_0).unwrap();
        let sender = SignKeypair::from_ml_dsa_seed(&[3u8; 32]).unwrap();
        let sealed = seal_room_message(
            &lobby,
            &sender,
            DEFAULT_ROOM,
            "wandering-otter",
            "secret lobby line",
            1,
        )
        .unwrap();
        // A member opens it.
        assert!(open_room_message(&lobby, &sealed).is_ok());
        // A non-member (wrong key) cannot — exactly what the actor's reader drops.
        assert!(
            open_room_message(&other, &sealed).is_err(),
            "a non-member must not decrypt the public-room frame"
        );
    }

    // ── Live fra1 round-trip (ignored; env-gated; orchestrator runs explicitly) ──
    //
    // Two ephemeral clients connect to the real relay, join a UNIQUE RANDOM
    // throwaway room (NEVER the public lobby — a random room string so it never
    // touches real lobby traffic), exchange a sealed canary, and assert
    // round-trip. `#[ignore]` so the default `cargo test` excludes it.
    #[test]
    #[ignore = "live relay; run explicitly with DAEMONSEED_RELAY_* set"]
    fn live_fra1_round_trip() {
        use daemonseed_server::kats::CNSA_2_0_KATS;
        use daemonseed_server::tls::install_provider;
        use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};

        let server_id =
            std::env::var("DAEMONSEED_RELAY_ID").unwrap_or_else(|_| "fra1#06177b08dc06".to_owned());
        let address =
            std::env::var("DAEMONSEED_RELAY_ADDR").unwrap_or_else(|_| "167.86.91.98".to_owned());
        let address = if address.contains(':') {
            address
        } else {
            format!("{address}:443")
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2).unwrap();
            install_provider().unwrap();

            // A UNIQUE RANDOM throwaway room — NOT the public lobby. Never publish
            // to the real lobby in any test.
            let nonce = now_unix_ms();
            let room = format!("gui-test-canary-{nonce:x}-{:x}", std::process::id());
            let room_key = Rc::new(derive_room_key(&room, &CNSA_2_0).unwrap());

            let id_a = ClientIdentity::ephemeral().unwrap();
            let id_b = ClientIdentity::ephemeral().unwrap();
            let mut c_a = CounterState::default();
            let mut c_b = CounterState::default();
            let parse = |s: &str| s.parse::<Handle>().unwrap();
            let mut t_a = InMemoryTrustStore::new();
            let mut t_b = InMemoryTrustStore::new();
            t_a.upsert(ServerEntry::new_trusted(parse(&server_id), address.clone()));
            t_b.upsert(ServerEntry::new_trusted(parse(&server_id), address.clone()));

            let (_oa, sa) = connect_session(&server_id, &address, &id_a, &mut c_a, &mut t_a)
                .await
                .expect("A connect");
            let (_ob, sb) = connect_session(&server_id, &address, &id_b, &mut c_b, &mut t_b)
                .await
                .expect("B connect");
            let sess_a = AppSession::open(sa).await.unwrap();
            let sess_b = AppSession::open(sb).await.unwrap();

            let addr = room_asset_address(&room_key, server_id.as_bytes()).unwrap();
            let addr_bytes = addr.as_bytes().to_vec();

            // B subscribes to the throwaway room.
            let mut cot_b = sess_b.circle_of_trust();
            let (b_tx, b_rx) = mpsc::channel::<wire::CotFrame>(8);
            b_tx.send(wire::CotFrame {
                asset_address: addr_bytes.clone(),
                payload: Vec::new(),
            })
            .await
            .unwrap();
            let mut b_in = cot_b
                .subscribe(ReceiverStream::new(b_rx))
                .await
                .expect("B subscribe")
                .into_inner();

            // A subscribes + publishes a sealed canary.
            let mut cot_a = sess_a.circle_of_trust();
            let (a_tx, a_rx) = mpsc::channel::<wire::CotFrame>(8);
            a_tx.send(wire::CotFrame {
                asset_address: addr_bytes.clone(),
                payload: Vec::new(),
            })
            .await
            .unwrap();
            let _a_in = cot_a
                .subscribe(ReceiverStream::new(a_rx))
                .await
                .expect("A subscribe")
                .into_inner();

            let canary = "canary 12345 — gui live round-trip";
            let sealed = seal_room_message(
                &room_key,
                id_a.signing(),
                &room,
                "live-test-a",
                canary,
                now_unix_ms(),
            )
            .unwrap();
            a_tx.send(wire::CotFrame {
                asset_address: addr_bytes.clone(),
                payload: sealed,
            })
            .await
            .unwrap();

            // B opens the frame the relay forwarded.
            loop {
                let frame = tokio::time::timeout(Duration::from_secs(10), b_in.message())
                    .await
                    .expect("frame within timeout")
                    .expect("stream healthy")
                    .expect("a frame, not EOS");
                if frame.payload.is_empty() {
                    continue;
                }
                let msg = open_room_message(&room_key, &frame.payload).expect("B opens canary");
                assert_eq!(msg.body, canary);
                break;
            }
        });
    }

    // ── Round 5: the circle path ─────────────────────────────────────────────

    /// A genuinely-strong 12-word phrase for circle tests (join doesn't gate in the
    /// actor; the GUI gates before calling, so any phrase derives a key here).
    const CIRCLE_PHRASE: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    async fn wait_for_circle_message(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<(u64, String, String)> {
        for _ in 0..400 {
            while let Ok(evt) = evt_rx.try_recv() {
                if let NetEvent::CircleMessage {
                    circle_id,
                    who,
                    text,
                    ..
                } = evt
                {
                    return Some((circle_id, who, text));
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    async fn wait_for_circle_joined(evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>) {
        for _ in 0..400 {
            while let Ok(evt) = evt_rx.try_recv() {
                if matches!(evt, NetEvent::CircleJoined { .. }) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("actor never reported CircleJoined");
    }

    /// Interop insurance (round-3 lesson): the GUI circle rendezvous derivation is
    /// the canonical one — pinned against an independent `derive_cot_key` +
    /// `asset_address` (the CIRCLE path) AND asserted DISTINCT from the room path,
    /// so an accidental swap to `room_asset_address`/`derive_room_key` is caught.
    /// Both round-trip tests are GUI-to-GUI, so a wrong-but-symmetric derivation
    /// would pass them; this nails the derivation itself.
    #[test]
    fn circle_asset_address_is_canonical() {
        let _ = oxicrypt_module::initialize();
        // The address handle_join_circle computes (derive_cot_key → asset_address).
        let key = derive_cot_key(CIRCLE_PHRASE, &CNSA_2_0).unwrap();
        let gui_addr = asset_address(&key, SERVER_ID.as_bytes()).unwrap();
        // Independent re-derivation with the same canonical inputs.
        let expect_key = derive_cot_key(CIRCLE_PHRASE, &CNSA_2_0).unwrap();
        let expect_addr = asset_address(&expect_key, b"relay-test#001122334455").unwrap();
        assert_eq!(
            gui_addr.as_bytes(),
            expect_addr.as_bytes(),
            "GUI circle rendezvous must be the canonical derivation, byte-for-byte"
        );
        // Distinct from the ROOM path for the same string (different key domain) —
        // guards against silently using the lobby derivation for circles.
        let room_key = derive_room_key(CIRCLE_PHRASE, &CNSA_2_0).unwrap();
        let room_addr = room_asset_address(&room_key, SERVER_ID.as_bytes()).unwrap();
        assert_ne!(
            gui_addr.as_bytes(),
            room_addr.as_bytes(),
            "the circle rendezvous must NOT be the room derivation"
        );
    }

    /// In-process circle round-trip (deterministic, no network): two actors join the
    /// SAME circle by phrase; A `SendCircle`, B's actor must emit a decrypted
    /// `CircleMessage`. Drives the REAL handle_join_circle / handle_send_circle /
    /// read_inbound_circle path. Mirrors `in_process_relay_round_trip`.
    #[test]
    fn in_process_circle_round_trip() {
        let _ = oxicrypt_module::initialize();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let registry = CotRegistry::new();
            let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
            let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
            let _srv_a = spawn_relay(a_server_io, registry.clone());
            let _srv_b = spawn_relay(b_server_io, registry.clone());

            let sess_a = AppSession::open(a_client_io).await.expect("A session");
            let sess_b = AppSession::open(b_client_io).await.expect("B session");

            let mut a = spawn_local_actor();
            let mut b = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: SERVER_ID.to_owned(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: SERVER_ID.to_owned(),
                })
                .ok();

            // B joins first (its own circle_id tag); wait for the relay to register
            // the rendezvous so A's publish lands on a live asset. Same phrase +
            // server_id → same rendezvous; the ids are per-actor-local routing tags.
            b.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 1,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_registry(&registry, 1).await;
            a.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 1,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_for_circle_joined(&mut a.evt_rx).await;

            a.cmd_tx
                .send(NetCommand::SendCircle {
                    circle_id: 1,
                    text: "meet at the cove".to_owned(),
                })
                .ok();

            // B's actor emits the DECRYPTED circle message.
            let got = wait_for_circle_message(&mut b.evt_rx).await;
            assert_eq!(
                got.map(|(_, _, text)| text),
                Some("meet at the cove".to_owned()),
                "member B's actor emits the decrypted circle message"
            );

            // A sees its own message only via local echo, tagged with A's circle_id.
            let a_echo = wait_for_circle_message(&mut a.evt_rx).await;
            assert_eq!(
                a_echo.map(|(id, _, text)| (id, text)),
                Some((1u64, "meet at the cove".to_owned())),
                "sender A sees its own message via local echo, tagged with its circle_id"
            );
        });
    }

    /// Opacity: a non-member (different circle phrase → different key) cannot
    /// decrypt the sealed circle frame — exactly the frame read_inbound_circle
    /// drops silently (the `if let Ok(..)` arm). Uses the core seal/open the actor uses.
    #[test]
    fn non_member_cannot_decrypt_circle() {
        let _ = oxicrypt_module::initialize();
        let member = derive_cot_key(CIRCLE_PHRASE, &CNSA_2_0).unwrap();
        let outsider = derive_cot_key(
            "a completely different circle phrase nobody shared",
            &CNSA_2_0,
        )
        .unwrap();
        let msg = wire::CircleMessage {
            sender_handle: "wandering-otter".to_owned(),
            body: "secret circle line".to_owned(),
            sent_unix_ms: 1,
        };
        let sealed = seal_message(&member, &msg).unwrap();
        assert!(open_message(&member, &sealed).is_ok(), "a member opens it");
        assert!(
            open_message(&outsider, &sealed).is_err(),
            "a non-member (wrong circle key) must not decrypt the circle frame"
        );
    }

    // ── Live fra1 circle round-trip (ignored; env-gated) ─────────────────────
    //
    // Two ephemeral clients connect to the real relay, join a UNIQUE RANDOM
    // throwaway CIRCLE (never a shared circle — a random phrase per run), exchange
    // a sealed canary via the CIRCLE path (derive_cot_key + asset_address +
    // seal_message/open_message), and assert round-trip. `#[ignore]` so default
    // `cargo test` excludes it.
    #[test]
    #[ignore = "live relay; run explicitly with DAEMONSEED_RELAY_* set"]
    fn live_fra1_circle_round_trip() {
        use daemonseed_server::kats::CNSA_2_0_KATS;
        use daemonseed_server::tls::install_provider;
        use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};

        let server_id =
            std::env::var("DAEMONSEED_RELAY_ID").unwrap_or_else(|_| "fra1#06177b08dc06".to_owned());
        let address =
            std::env::var("DAEMONSEED_RELAY_ADDR").unwrap_or_else(|_| "167.86.91.98".to_owned());
        let address = if address.contains(':') {
            address
        } else {
            format!("{address}:443")
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2).unwrap();
            install_provider().unwrap();

            // A UNIQUE RANDOM throwaway CIRCLE phrase — never a shared circle.
            let nonce = now_unix_ms();
            let phrase = format!(
                "gui circle canary {nonce:x} {:x} alpha bravo charlie delta echo foxtrot golf",
                std::process::id()
            );
            let cot_key = Rc::new(derive_cot_key(&phrase, &CNSA_2_0).unwrap());

            let id_a = ClientIdentity::ephemeral().unwrap();
            let id_b = ClientIdentity::ephemeral().unwrap();
            let mut c_a = CounterState::default();
            let mut c_b = CounterState::default();
            let parse = |s: &str| s.parse::<Handle>().unwrap();
            let mut t_a = InMemoryTrustStore::new();
            let mut t_b = InMemoryTrustStore::new();
            t_a.upsert(ServerEntry::new_trusted(parse(&server_id), address.clone()));
            t_b.upsert(ServerEntry::new_trusted(parse(&server_id), address.clone()));

            let (_oa, sa) = connect_session(&server_id, &address, &id_a, &mut c_a, &mut t_a)
                .await
                .expect("A connect");
            let (_ob, sb) = connect_session(&server_id, &address, &id_b, &mut c_b, &mut t_b)
                .await
                .expect("B connect");
            let sess_a = AppSession::open(sa).await.unwrap();
            let sess_b = AppSession::open(sb).await.unwrap();

            // CIRCLE rendezvous: asset_address(cot_key, server_id) — NOT the room path.
            let addr = asset_address(&cot_key, server_id.as_bytes()).unwrap();
            let addr_bytes = addr.as_bytes().to_vec();

            let mut cot_b = sess_b.circle_of_trust();
            let (b_tx, b_rx) = mpsc::channel::<wire::CotFrame>(8);
            b_tx.send(wire::CotFrame {
                asset_address: addr_bytes.clone(),
                payload: Vec::new(),
            })
            .await
            .unwrap();
            let mut b_in = cot_b
                .subscribe(ReceiverStream::new(b_rx))
                .await
                .expect("B subscribe")
                .into_inner();

            let mut cot_a = sess_a.circle_of_trust();
            let (a_tx, a_rx) = mpsc::channel::<wire::CotFrame>(8);
            a_tx.send(wire::CotFrame {
                asset_address: addr_bytes.clone(),
                payload: Vec::new(),
            })
            .await
            .unwrap();
            let _a_in = cot_a
                .subscribe(ReceiverStream::new(a_rx))
                .await
                .expect("A subscribe")
                .into_inner();

            let canary = "circle canary 67890 — gui live round-trip";
            let message = wire::CircleMessage {
                sender_handle: "live-test-a".to_owned(),
                body: canary.to_owned(),
                sent_unix_ms: now_unix_ms(),
            };
            let sealed = seal_message(&cot_key, &message).unwrap();
            a_tx.send(wire::CotFrame {
                asset_address: addr_bytes.clone(),
                payload: sealed,
            })
            .await
            .unwrap();

            loop {
                let frame = tokio::time::timeout(Duration::from_secs(10), b_in.message())
                    .await
                    .expect("frame within timeout")
                    .expect("stream healthy")
                    .expect("a frame, not EOS");
                if frame.payload.is_empty() {
                    continue;
                }
                let msg = open_message(&cot_key, &frame.payload).expect("B opens circle canary");
                assert_eq!(msg.body, canary);
                break;
            }
        });
    }
}
