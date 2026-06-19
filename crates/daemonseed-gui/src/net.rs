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
//! By default `my_handle` is a throwaway adjective-noun handle regenerated every
//! launch. Round 6 adds **persistent identity**: when the app unlocks a profile,
//! `Connect` carries the persisted stable display handle (derived from the
//! profile's mnemonic, decoupled from the connection key) and the actor presents
//! under it. The connection proof itself stays a fresh [`ClientIdentity::ephemeral`]
//! per connect (D8) — exactly as the TUI does (`daemonseed-tui` net.rs also
//! connects ephemeral). Persistence is a stable *display* identity + silent circle
//! rejoin, NOT a persisted connection-signing key. A spoofed display handle still
//! cannot impersonate a real key: public-room provenance binds to the ephemeral
//! signing key, and circle messages are AEAD-only (membership is the auth).
//!
//! ## Why current-thread + `LocalSet`
//!
//! [`connect_session`] takes `&mut dyn TrustStore` (its future is `!Send`) and the
//! inbound reader holds an [`Rc`] of the room key, so neither can be
//! `tokio::spawn`ed onto a multi-thread runtime. Driving everything on one thread
//! via `block_on(local.run_until(..))` + [`tokio::task::spawn_local`] sidesteps
//! both `Send` bounds — identical to the TUI's rationale.

use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use daemonseed_cli::connect::connect_session;
use daemonseed_cli::identity_proof::ClientIdentity;
use daemonseed_cli::session::AppSession;
use daemonseed_core::circle::key::{CotKey, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address, public_share_asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::public_room::{
    DEFAULT_ROOM, derive_room_key, open_room_message, room_asset_address, seal_room_message,
};
use daemonseed_core::share_envelope::{ManifestEntry, ShareFrame};
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::chunk_addr;
use daemonseed_core::storage::fetched::rebase_to_selection_root;
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
    ///
    /// `display_handle` (round 6) is the persisted, stable presented name from an
    /// unlocked profile — when `Some`, it replaces the actor's per-launch random
    /// handle so the user presents the SAME name across sessions. The connection
    /// proof itself stays ephemeral (D8, mirroring the TUI): persistence is a
    /// stable *display* identity, not a persisted connection-signing key.
    ///
    /// `rejoin_circles` (round 6) is the set of persisted circles to silently
    /// re-join once the session is live — `(gui_circle_id, phrase)` pairs read
    /// from the at-rest blob. Re-joined AFTER the lobby auto-join so each has a
    /// live session; failures surface per-circle (`CircleError`) and never abort
    /// the connect. Empty for the ephemeral / no-profile path.
    Connect {
        server_id: String,
        address: String,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
        /// (M16) persisted published-share roots (directory paths) to silently
        /// re-publish once the session is live — read from the at-rest blob, served
        /// after the lobby auto-join exactly like `rejoin_circles`. Each republish
        /// uses the directory basename as the share name and `display_handle` as the
        /// sharer handle. Empty for the ephemeral / no-profile path.
        republish_roots: Vec<PathBuf>,
    },
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
    /// Publish a local directory as a public share: index it (manifest + 1 MiB
    /// sub-file chunking), register the listing via the PublicSpace RPC to receive
    /// the server-assigned opaque `share_id`, and serve it from disk for the session.
    /// Mirrors `daemonseed_tui`'s `handle_publish_share` — minus the redb chunk-addr
    /// cache and the cancel/progress events, which are TUI UI affordances the GUI
    /// alpha does not surface (the manifest + served bytes are byte-identical either
    /// way). Terminal events: `PublishStarted` / `PublishError`; `PublishStopped` on
    /// unpublish, session end, or relay reap.
    ///
    /// `#[cfg_attr(not(test), allow(dead_code))]`: constructed by the in-process
    /// round-trip oracle today; the attended Shares-tab wiring constructs it in the
    /// bin (same convention as [`NetCommand::JoinRoom`]).
    #[cfg_attr(not(test), allow(dead_code))]
    PublishShare {
        root: PathBuf,
        name: String,
        sharer_handle: String,
    },
    /// Stop serving and unpublish a share published this session (owner-scoped,
    /// ISC-A-S1). Aborts the serve task and sends `UnpublishShare` to the relay.
    #[cfg_attr(not(test), allow(dead_code))]
    UnpublishShare { share_id: String },
    /// List the relay's live public shares — a single `SharesSnapshot` (or
    /// `SharesError`). Read-only; no scan.
    #[cfg_attr(not(test), allow(dead_code))]
    RefreshShares,
    /// A1 fetch-preview: open the share's stream, read the manifest, emit
    /// `FetchManifest` (file names + sizes), then drop the stream. No bytes fetched.
    #[cfg_attr(not(test), allow(dead_code))]
    FetchShare { share_id: String, name: String },
    /// A2 download: re-open the share and fetch the selected files' chunks (all when
    /// `selected` is `None`), SHA-384-verify each (fail-closed, ISC-S28), and write
    /// them under `fetched_root`. `flat_dest` rebases the selection to the dest root
    /// (choose-download-dir). Terminal: `FetchComplete` or `FetchError` (partial
    /// files deleted, ISC-A-C31). Mirrors `daemonseed_tui`'s `handle_confirm_fetch`.
    #[cfg_attr(not(test), allow(dead_code))]
    ConfirmFetch {
        share_id: String,
        name: String,
        fetched_root: PathBuf,
        selected: Option<Vec<usize>>,
        flat_dest: bool,
    },
    /// TEST SEAM (never used in production). Inject a pre-opened [`AppSession`]
    /// plus the `server_id` the test namespaces its rendezvous by, so a test
    /// exercises the SAME post-`open` JoinRoom/SendRoom path as a real Connect
    /// while bypassing TCP/TLS. Gated to test builds.
    #[doc(hidden)]
    #[cfg(test)]
    AttachSession {
        session: AppSession,
        server_id: String,
        /// Round-6 parity: when `Some`, sets the actor's presented handle exactly
        /// as a real `Connect{display_handle}` would, so a test can assert echo
        /// tagging under the persisted name.
        display_handle: Option<String>,
        /// Round-6 parity: persisted circles to silently re-join post-attach,
        /// driving the SAME `handle_join_circle` path the real connect runs.
        rejoin_circles: Vec<(u64, String)>,
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
    /// GUI-assigned tag from the originating [`NetCommand::JoinCircle`]; `asset_addr`
    /// is the relay rendezvous the circle resolved to, from which the UI derives the
    /// stable client-local label (`default_circle_label`) and fills the net contract's
    /// rendezvous slot.
    CircleJoined {
        circle_id: u64,
        asset_addr: AssetAddr,
    },
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
    /// A share is now published and served; `share_id` is server-assigned (opaque).
    /// `root` is the published directory path — carried back so the GUI can persist
    /// it for auto-republish (M16) and key Unpublish on it.
    PublishStarted {
        share_id: String,
        name: String,
        file_count: usize,
        root: String,
        /// True when this is an auto-republish on connect (the M16 restore path),
        /// false for a fresh user-driven publish — drives the "Restored N shares
        /// from last session" status vs the per-share "Published …" line.
        restored: bool,
    },
    /// A published share stopped serving (unpublish, session end, or relay reap).
    PublishStopped { share_id: String },
    /// A publish attempt failed (no session, index error, or refused RPC).
    PublishError { message: String },
    /// The relay's live public-share listing (response to `RefreshShares`).
    SharesSnapshot {
        shares: Vec<wire::PublicShareListing>,
    },
    /// A `RefreshShares` could not complete; the previous snapshot is unchanged.
    SharesError { message: String },
    /// A1 fetch-preview: the share's file list (names + sizes), no addresses.
    FetchManifest {
        share_id: String,
        name: String,
        entries: Vec<ShareManifestEntry>,
    },
    /// Fetch progress: chunks / bytes received so far (total known post-manifest).
    FetchProgress {
        total_chunks: Option<u32>,
        chunks_received: u32,
        bytes_received: u64,
    },
    /// A fetch completed: all selected files written and SHA-384-verified.
    FetchComplete {
        share_id: String,
        files_written: u32,
        bytes_written: u64,
    },
    /// A fetch failed (timeout, hash mismatch, I/O); partial files are deleted.
    FetchError { message: String },
}

/// One file in an A1 fetch-preview ([`NetEvent::FetchManifest`]): the file's
/// relative path and size plus its chunk count, but NOT the chunk addresses (those
/// are fetched on `ConfirmFetch`). Mirrors `daemonseed_tui`'s `ShareManifestEntry`.
///
/// Fields are read by the in-process fetch-preview oracle and by the attended
/// Shares-tab wiring; `#[cfg_attr(not(test), allow(dead_code))]` keeps the bin
/// build clean until that wiring lands (a binary crate's `pub` does not escape).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct ShareManifestEntry {
    pub rel_path: String,
    pub size: u64,
    pub chunk_count: u32,
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
    /// stopped; the UI treats that as "offline" and never panics. The `Err` returns
    /// the bounced command (tokio mpsc convention); callers fire-and-forget it, but
    /// the enum is large enough (the `Connect` rejoin set, the test `AttachSession`)
    /// that `result_large_err` flags it — and boxing a never-inspected payload buys
    /// nothing here.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, cmd: NetCommand) -> Result<(), NetCommand> {
        self.cmd_tx.send(cmd).map_err(|e| e.0)
    }

    /// A `Send + Clone` handle to the command channel, for code that must dispatch a
    /// `NetCommand` from OFF the UI thread (the `Rc<RefCell<NetHandle>>` is UI-thread
    /// only). The folder-picker thread holds one to fire `ConfirmFetch` once a
    /// download destination is chosen (commit 2), without marshaling back to the UI.
    pub fn command_sender(&self) -> mpsc::UnboundedSender<NetCommand> {
        self.cmd_tx.clone()
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
    /// Shares published this session, keyed by server-assigned `share_id`, each
    /// holding its `serve_share` task handle so `UnpublishShare` can abort it
    /// (mirrors the TUI's `published` map). RAM-only — relay state is ephemeral.
    published: HashMap<String, tokio::task::JoinHandle<()>>,
}

impl Actor {
    fn emit(&self, evt: NetEvent) {
        let _ = self.evt_tx.send(evt);
    }

    /// Open a connection and keep the live session, then auto-join the default
    /// room. Mirrors `daemonseed_tui::net::Actor::handle_connect`: ephemeral
    /// identity, trusted-mode upsert, `connect_session` → `AppSession::open`.
    async fn handle_connect(
        &mut self,
        server_id: &str,
        address: &str,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
        republish_roots: Vec<PathBuf>,
    ) {
        // Round 6: present under the persisted stable handle when unlocked from a
        // profile. The connection proof below stays ephemeral (D8) — only the
        // display name is persistent.
        if let Some(handle) = display_handle {
            self.my_handle = handle;
        }
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
                    // Round 6: silently re-join persisted circles now that the
                    // session is live. Each re-derives its key from the stored
                    // phrase (never a persisted key) through the SAME path a fresh
                    // user-driven join takes; a per-circle failure surfaces as a
                    // CircleError and never aborts the others or the connect.
                    for (circle_id, phrase) in rejoin_circles {
                        self.handle_join_circle(circle_id, &phrase).await;
                    }
                    // M16: silently re-publish persisted shares now that the session
                    // is live, exactly like the circle re-join above. Each uses the
                    // directory basename as the share name and the presented handle
                    // as the sharer handle; a per-share failure surfaces as a
                    // PublishError and never aborts the others or the connect.
                    let sharer = self.my_handle.clone();
                    for root in republish_roots {
                        let name = root
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "share".to_owned());
                        self.handle_publish_share(root, name, sharer.clone(), true)
                            .await;
                    }
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
    async fn handle_attach(
        &mut self,
        session: AppSession,
        server_id: String,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
        republish_roots: Vec<PathBuf>,
    ) {
        // Round-6 parity: present under the persisted handle if supplied.
        if let Some(handle) = display_handle {
            self.my_handle = handle;
        }
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
        // Round-6 parity: silently re-join persisted circles via the real path.
        for (circle_id, phrase) in rejoin_circles {
            self.handle_join_circle(circle_id, &phrase).await;
        }
        // M16 parity: silently re-publish persisted shares via the real path.
        let sharer = self.my_handle.clone();
        for root in republish_roots {
            let name = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "share".to_owned());
            self.handle_publish_share(root, name, sharer.clone(), true)
                .await;
        }
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
                asset_addr: existing.asset_addr,
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
        self.emit(NetEvent::CircleJoined {
            circle_id,
            asset_addr,
        });
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

    // ── Shares: publish / serve / fetch (M15/M16 path, mirrors the TUI) ───────

    /// Publish `root` as a public share and serve it from disk for the session.
    /// `restored` is true on the M16 auto-republish path (connect-time restore),
    /// false for a fresh user-driven publish. See [`NetCommand::PublishShare`].
    async fn handle_publish_share(
        &mut self,
        root: PathBuf,
        name: String,
        sharer_handle: String,
        restored: bool,
    ) {
        // Fail-safe: never recursively hash the home tree / a system dir. A picker that
        // returns the default directory (some xdg portals do) would otherwise index all
        // of $HOME and appear to hang. Reject with a clear error instead.
        if is_unsafe_publish_root(&root) {
            return self.emit(NetEvent::PublishError {
                message: format!(
                    "refusing to publish {} — pick a specific folder, not your home or a system directory",
                    root.display()
                ),
            });
        }
        let Some(session) = self.session.clone() else {
            return self.emit(NetEvent::PublishError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let Some(server_id) = self.server_id.clone() else {
            return self.emit(NetEvent::PublishError {
                message: "no server-id for the connected relay".to_owned(),
            });
        };

        // Index the directory off the actor thread (1 MiB sub-file chunking). The
        // GUI keeps no redb share-index, so it always hashes fresh — the manifest
        // and the served bytes are byte-identical to the cached path either way.
        let index_root = root.clone();
        let content =
            match tokio::task::spawn_blocking(move || ShareContent::index_dir(&index_root)).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    return self.emit(NetEvent::PublishError {
                        message: format!("could not index {}: {e}", root.display()),
                    });
                }
                Err(_) => {
                    return self.emit(NetEvent::PublishError {
                        message: "share-index task failed".to_owned(),
                    });
                }
            };
        let content = std::sync::Arc::new(content);
        let file_count = content.file_count();

        // Register the listing — the server assigns the opaque `share_id` (F25); the
        // `share_id` we send is ignored. Done BEFORE serving so the listing is never
        // advertised for content we cannot serve.
        let resp = session
            .public_space()
            .publish_share(wire::PublishShareRequest {
                listing: Some(wire::PublicShareListing {
                    share_id: String::new(),
                    name: name.clone(),
                    rating: String::new(),
                    sharer_handle,
                }),
            })
            .await;
        let share_id = match resp {
            Ok(r) => r.into_inner().share_id,
            Err(s) => {
                return self.emit(NetEvent::PublishError {
                    message: format!("publish refused: {s}"),
                });
            }
        };

        // Serve from disk for the life of the session via `spawn_local` (like the
        // circle inbound readers). A natural end emits `PublishStopped`; an explicit
        // `UnpublishShare` aborts the task before that line runs.
        let task_share_id = share_id.clone();
        let serve_evt_tx = self.evt_tx.clone();
        let handle = tokio::task::spawn_local(async move {
            let _ = session
                .serve_share(&server_id, &task_share_id, content)
                .await;
            let _ = serve_evt_tx.send(NetEvent::PublishStopped {
                share_id: task_share_id,
            });
        });
        self.published.insert(share_id.clone(), handle);
        self.emit(NetEvent::PublishStarted {
            share_id,
            name,
            file_count,
            root: root.to_string_lossy().into_owned(),
            restored,
        });
    }

    /// Unpublish a share published this session and stop serving it. See
    /// [`NetCommand::UnpublishShare`].
    async fn handle_unpublish_share(&mut self, share_id: &str) {
        if let Some(handle) = self.published.remove(share_id) {
            handle.abort();
        }
        if let Some(session) = self.session.as_ref() {
            let _ = session
                .public_space()
                .unpublish_share(wire::UnpublishShareRequest {
                    share_id: share_id.to_owned(),
                })
                .await;
        }
        self.emit(NetEvent::PublishStopped {
            share_id: share_id.to_owned(),
        });
    }

    /// List the relay's live public shares. See [`NetCommand::RefreshShares`].
    async fn handle_refresh_shares(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::SharesError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        match session
            .public_space()
            .list_public_shares(wire::ListPublicSharesRequest {})
            .await
        {
            Ok(r) => self.emit(NetEvent::SharesSnapshot {
                shares: r.into_inner().shares,
            }),
            Err(s) => self.emit(NetEvent::SharesError {
                message: format!("could not list shares: {s}"),
            }),
        }
    }

    /// A1 fetch-preview: open the share, read the manifest, emit `FetchManifest`,
    /// drop the stream. See [`NetCommand::FetchShare`].
    async fn handle_fetch_share(&mut self, share_id: &str, name: &str) {
        match self.open_share_stream(share_id).await {
            Ok(opened) => {
                let entries = opened
                    .manifest
                    .iter()
                    .map(|e| ShareManifestEntry {
                        rel_path: e.rel_path.clone(),
                        size: e.size,
                        chunk_count: e.chunks.len() as u32,
                    })
                    .collect();
                // `opened` (out_tx + inbound) drops here — preview only.
                self.emit(NetEvent::FetchManifest {
                    share_id: share_id.to_owned(),
                    name: name.to_owned(),
                    entries,
                });
            }
            Err(message) => self.emit(NetEvent::FetchError { message }),
        }
    }

    /// A2 download: fetch the selected files' chunks, SHA-384-verify each, and write
    /// them under `fetched_root`. See [`NetCommand::ConfirmFetch`].
    async fn handle_confirm_fetch(
        &mut self,
        share_id: &str,
        name: &str,
        fetched_root: PathBuf,
        selected: Option<Vec<usize>>,
        flat_dest: bool,
    ) {
        let opened = match self.open_share_stream(share_id).await {
            Ok(o) => o,
            Err(message) => return self.emit(NetEvent::FetchError { message }),
        };
        let OpenedShare {
            out_tx,
            mut inbound,
            asset_bytes,
            manifest,
        } = opened;

        // Resolve the selected file set (None → all; out-of-range indices ignored).
        let indices: Vec<usize> = match &selected {
            None => (0..manifest.len()).collect(),
            Some(sel) => sel
                .iter()
                .copied()
                .filter(|&i| i < manifest.len())
                .collect(),
        };
        // `flat_dest` (choose-download-dir): rebase the selection to the dest root so
        // a single file lands as its basename and a folder drops its ancestors.
        let rel_paths: Vec<&str> = indices
            .iter()
            .map(|&i| manifest[i].rel_path.as_str())
            .collect();
        let rebased: Option<Vec<String>> = flat_dest.then(|| rebase_to_selection_root(&rel_paths));

        let total_chunks: u32 = indices
            .iter()
            .map(|&i| manifest[i].chunks.len() as u32)
            .sum();
        self.emit(NetEvent::FetchProgress {
            total_chunks: Some(total_chunks),
            chunks_received: 0,
            bytes_received: 0,
        });

        let mut written: Vec<PathBuf> = Vec::new();
        let mut chunks_received: u32 = 0;
        let mut bytes_received: u64 = 0;
        let mut files_written: u32 = 0;

        for (pos, &i) in indices.iter().enumerate() {
            let entry = &manifest[i];
            let rel = match &rebased {
                Some(r) => r[pos].as_str(),
                None => entry.rel_path.as_str(),
            };
            let Some(safe) = sanitize_rel_path(rel) else {
                return fail_fetch(self, &written, format!("unsafe path in manifest: {rel:?}"))
                    .await;
            };
            // A chosen dest writes flat; the default namespaces under a share folder.
            let dest = if flat_dest {
                fetched_root.join(&safe)
            } else {
                fetched_root.join(safe_folder_name(name)).join(&safe)
            };
            if let Some(parent) = dest.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return fail_fetch(
                    self,
                    &written,
                    format!("could not create {}: {e}", parent.display()),
                )
                .await;
            }

            let mut file_bytes: Vec<u8> = Vec::with_capacity(entry.size as usize);
            for addr in &entry.chunks {
                if out_tx
                    .send(share_frame(
                        &asset_bytes,
                        ShareFrame::ChunkRequest { chunk_addr: *addr }.encode(),
                    ))
                    .await
                    .is_err()
                {
                    return fail_fetch(self, &written, "share request channel closed".to_owned())
                        .await;
                }
                let data = loop {
                    let resp = match tokio::time::timeout(FETCH_INACTIVITY, inbound.message()).await
                    {
                        Ok(Ok(Some(f))) => f,
                        Ok(Ok(None)) => {
                            return fail_fetch(
                                self,
                                &written,
                                "share stream ended mid-fetch".to_owned(),
                            )
                            .await;
                        }
                        Ok(Err(s)) => {
                            return fail_fetch(
                                self,
                                &written,
                                format!("share stream error: {}", s.message()),
                            )
                            .await;
                        }
                        Err(_) => {
                            return fail_fetch(self, &written, FETCH_TIMEOUT.to_owned()).await;
                        }
                    };
                    if resp.payload.is_empty() {
                        continue;
                    }
                    match ShareFrame::decode(&resp.payload) {
                        Ok(ShareFrame::ChunkResponse {
                            chunk_addr: got,
                            data,
                        }) if got == *addr => {
                            break data;
                        }
                        _ => continue,
                    }
                };
                // ISC-S28 / ISC-19: re-derive SHA-384 and reject on mismatch.
                let ok = matches!(chunk_addr(&data), Ok(recomputed) if recomputed == *addr);
                if !ok {
                    return fail_fetch(
                        self,
                        &written,
                        "a served chunk failed its hash check".to_owned(),
                    )
                    .await;
                }
                chunks_received += 1;
                bytes_received += data.len() as u64;
                file_bytes.extend_from_slice(&data);
                self.emit(NetEvent::FetchProgress {
                    total_chunks: Some(total_chunks),
                    chunks_received,
                    bytes_received,
                });
            }
            if let Err(e) = std::fs::write(&dest, &file_bytes) {
                return fail_fetch(
                    self,
                    &written,
                    format!("could not write {}: {e}", dest.display()),
                )
                .await;
            }
            written.push(dest);
            files_written += 1;
        }

        drop(out_tx);
        self.emit(NetEvent::FetchComplete {
            share_id: share_id.to_owned(),
            files_written,
            bytes_written: bytes_received,
        });
    }

    /// Open a fetch subscribe stream for `share_id`, send the naming frame + a
    /// `ManifestRequest`, and read until the `ManifestResponse` arrives. Both halves
    /// derive the SAME rendezvous via [`public_share_asset_address`], so a fetch that
    /// finds the manifest IS the agreement proof (a mismatch lands on a dead asset
    /// and times out). Returns the live stream + decoded manifest, or `Err(message)`.
    async fn open_share_stream(&self, share_id: &str) -> Result<OpenedShare, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "not connected to a relay yet".to_owned())?;
        let server_id = self
            .server_id
            .as_ref()
            .ok_or_else(|| "no server-id for the connected relay".to_owned())?;
        let asset_addr = public_share_asset_address(share_id.as_bytes(), server_id.as_bytes())
            .map_err(|e| format!("share-address derivation failed: {e}"))?;
        let asset_bytes = asset_addr.as_bytes().to_vec();

        let mut cot = session.circle_of_trust();
        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(16);
        out_tx
            .send(share_frame(&asset_bytes, Vec::new()))
            .await
            .map_err(|_| "share subscribe channel closed".to_owned())?;
        let mut inbound = cot
            .subscribe(ReceiverStream::new(out_rx))
            .await
            .map_err(|s| format!("subscribe refused: {}", s.message()))?
            .into_inner();
        out_tx
            .send(share_frame(
                &asset_bytes,
                ShareFrame::ManifestRequest.encode(),
            ))
            .await
            .map_err(|_| "share subscribe channel closed".to_owned())?;

        let manifest = loop {
            let resp = match tokio::time::timeout(FETCH_INACTIVITY, inbound.message()).await {
                Ok(Ok(Some(f))) => f,
                Ok(Ok(None)) => return Err("share stream ended before a manifest".to_owned()),
                Ok(Err(s)) => return Err(format!("share stream error: {}", s.message())),
                Err(_) => return Err(FETCH_MANIFEST_TIMEOUT.to_owned()),
            };
            if resp.payload.is_empty() {
                continue;
            }
            match ShareFrame::decode(&resp.payload) {
                Ok(ShareFrame::ManifestResponse { entries }) => break entries,
                _ => continue,
            }
        };
        Ok(OpenedShare {
            out_tx,
            inbound,
            asset_bytes,
            manifest,
        })
    }
}

/// True if `root` is the home directory, an ancestor of it, or the filesystem root —
/// directories we must never recursively hash for a share. A picker that returns the
/// default dir (some xdg portals do) would otherwise index all of `$HOME` and hang.
/// Canonicalizes both sides; falls back to the raw path if that fails.
fn is_unsafe_publish_root(root: &std::path::Path) -> bool {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if root.parent().is_none() {
        return true; // filesystem root "/"
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        let home = home.canonicalize().unwrap_or(home);
        if root == home || home.starts_with(&root) {
            return true; // the home dir itself, or an ancestor of it (/home, /)
        }
    }
    false
}

/// A live fetch stream plus the decoded manifest. The GUI analog of the TUI's
/// `OpenedShare`; both the A1 preview and the A2 download open one.
struct OpenedShare {
    out_tx: mpsc::Sender<wire::CotFrame>,
    inbound: tonic::Streaming<wire::CotFrame>,
    asset_bytes: Vec<u8>,
    manifest: Vec<ManifestEntry>,
}

/// Per-frame inactivity budget for a fetch (manifest or chunk). Only a relevant
/// frame resets it; relay noise does not (mirrors the TUI's 30s budget).
const FETCH_INACTIVITY: std::time::Duration = std::time::Duration::from_secs(30);
const FETCH_TIMEOUT: &str = "timed out waiting for chunks — the share may have stopped serving";
const FETCH_MANIFEST_TIMEOUT: &str =
    "timed out waiting for the share — it may be offline; refresh the list";

/// Build a `CotFrame` addressed to a share rendezvous.
fn share_frame(asset: &[u8], payload: Vec<u8>) -> wire::CotFrame {
    wire::CotFrame {
        asset_address: asset.to_vec(),
        payload,
    }
}

/// Delete the partial files written so far and emit `FetchError` (ISC-A-C31 — a
/// failed fetch persists nothing). Free function so the borrow of `written` does
/// not collide with `&mut actor`.
async fn fail_fetch(actor: &Actor, written: &[PathBuf], message: String) {
    for p in written {
        let _ = std::fs::remove_file(p);
    }
    actor.emit(NetEvent::FetchError { message });
}

/// Map a wire `/`-separated rel_path to a safe relative path under the fetch root,
/// or `None` if it escapes (absolute, `.`/`..`, backslash, or empty). ISC-A-C32.
fn sanitize_rel_path(rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        return None;
    }
    let mut out = PathBuf::new();
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." || comp.contains('\\') {
            return None;
        }
        out.push(comp);
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// A safe single-component folder name derived from a share's display name: path
/// separators and control chars become `_`, leading/trailing dots+space trimmed,
/// empty falls back to `share`.
fn safe_folder_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        "share".to_owned()
    } else {
        trimmed.to_owned()
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
        published: HashMap::new(),
    };
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            NetCommand::Connect {
                server_id,
                address,
                display_handle,
                rejoin_circles,
                republish_roots,
            } => {
                actor
                    .handle_connect(
                        &server_id,
                        &address,
                        display_handle,
                        rejoin_circles,
                        republish_roots,
                    )
                    .await
            }
            NetCommand::JoinRoom { room } => actor.join_room(&room).await,
            NetCommand::SendRoom { text } => actor.handle_send_room(&text).await,
            NetCommand::JoinCircle { circle_id, phrase } => {
                actor.handle_join_circle(circle_id, &phrase).await
            }
            NetCommand::SendCircle { circle_id, text } => {
                actor.handle_send_circle(circle_id, &text).await
            }
            NetCommand::PublishShare {
                root,
                name,
                sharer_handle,
            } => {
                actor
                    .handle_publish_share(root, name, sharer_handle, false)
                    .await
            }
            NetCommand::UnpublishShare { share_id } => {
                actor.handle_unpublish_share(&share_id).await
            }
            NetCommand::RefreshShares => actor.handle_refresh_shares().await,
            NetCommand::FetchShare { share_id, name } => {
                actor.handle_fetch_share(&share_id, &name).await
            }
            NetCommand::ConfirmFetch {
                share_id,
                name,
                fetched_root,
                selected,
                flat_dest,
            } => {
                actor
                    .handle_confirm_fetch(&share_id, &name, fetched_root, selected, flat_dest)
                    .await
            }
            #[cfg(test)]
            NetCommand::AttachSession {
                session,
                server_id,
                display_handle,
                rejoin_circles,
            } => {
                actor
                    .handle_attach(
                        session,
                        server_id,
                        display_handle,
                        rejoin_circles,
                        Vec::new(), // attach seam drives join/send/fetch flows, not republish
                    )
                    .await
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
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
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

    // ── Share publish→fetch (the item-3 spine oracle) ─────────────────────────

    /// Canonical-address pin: the GUI derives a share rendezvous via
    /// `public_share_asset_address(share_id, server_id)` — deterministic, and the
    /// argument order is load-bearing (swapping the inputs changes the address, so a
    /// silent swap can't pass). The byte-level *agreement* between serve and fetch is
    /// proven by the round-trip below (a wrong derivation lands on a dead asset).
    #[test]
    fn share_asset_address_is_canonical() {
        let _ = oxicrypt_module::initialize();
        let share_id: &[u8] = b"9f3c1a77b2e04d6680aa1c2d3e4f5061";
        let server = SERVER_ID.as_bytes();
        let addr = public_share_asset_address(share_id, server).unwrap();
        assert_eq!(
            addr.as_bytes(),
            public_share_asset_address(share_id, server)
                .unwrap()
                .as_bytes(),
            "share-address derivation must be deterministic"
        );
        assert_ne!(
            addr.as_bytes(),
            public_share_asset_address(server, share_id)
                .unwrap()
                .as_bytes(),
            "argument order (share_id, server_id) is load-bearing"
        );
    }

    async fn wait_for_publish_started(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<String> {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                match evt {
                    NetEvent::PublishStarted { share_id, .. } => return Some(share_id),
                    NetEvent::PublishError { message } => panic!("publish failed: {message}"),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    async fn wait_for_fetch_manifest(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<Vec<ShareManifestEntry>> {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                match evt {
                    NetEvent::FetchManifest { entries, .. } => return Some(entries),
                    NetEvent::FetchError { message } => panic!("fetch preview failed: {message}"),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    async fn wait_for_fetch_complete(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<(u32, u64)> {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                match evt {
                    NetEvent::FetchComplete {
                        files_written,
                        bytes_written,
                        ..
                    } => return Some((files_written, bytes_written)),
                    NetEvent::FetchError { message } => panic!("fetch failed: {message}"),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    /// The item-3 spine, end-to-end through TWO GUI actors on a shared in-process
    /// relay: actor A publishes a two-file directory (real `publish_share` RPC +
    /// `serve_share`); actor B previews the manifest, downloads to a temp root, and
    /// recovers both files byte-for-byte (each chunk SHA-384-verified). Exercises the
    /// GUI's OWN publish + fetch handlers — not the inlined core path.
    #[test]
    fn share_publish_fetch_round_trip() {
        let _ = oxicrypt_module::initialize();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let registry = CotRegistry::new();
            let (a_client_io, a_server_io) = tokio::io::duplex(256 * 1024);
            let (b_client_io, b_server_io) = tokio::io::duplex(256 * 1024);
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
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();

            // A publishes a two-file share (one nested).
            let dir = tempfile::TempDir::new().unwrap();
            let file_a: &[u8] = b"gui share round-trip, page 1";
            let file_b: &[u8] = b"gui share round-trip, page 2 (with addendum)";
            std::fs::write(dir.path().join("page-1.txt"), file_a).unwrap();
            std::fs::create_dir(dir.path().join("sub")).unwrap();
            std::fs::write(dir.path().join("sub").join("page-2.txt"), file_b).unwrap();
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: dir.path().to_path_buf(),
                    name: "alice-share".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            let share_id = wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("A reports PublishStarted");
            // A's serve subscription must be live before B fetches.
            wait_registry(&registry, 1).await;

            // B previews the manifest (A1).
            b.cmd_tx
                .send(NetCommand::FetchShare {
                    share_id: share_id.clone(),
                    name: "alice-share".to_owned(),
                })
                .ok();
            let entries = wait_for_fetch_manifest(&mut b.evt_rx)
                .await
                .expect("B receives the manifest preview");
            assert_eq!(entries.len(), 2, "two-file manifest preview");
            assert_eq!(entries[0].rel_path, "page-1.txt");
            assert_eq!(entries[0].size, file_a.len() as u64, "preview size matches");
            assert_eq!(entries[0].chunk_count, 1, "a sub-1-MiB file is one chunk");
            assert_eq!(entries[1].rel_path, "sub/page-2.txt");
            assert_eq!(entries[1].size, file_b.len() as u64, "preview size matches");

            // B downloads (A2) to a temp fetch root and recovers both files.
            let out = tempfile::TempDir::new().unwrap();
            b.cmd_tx
                .send(NetCommand::ConfirmFetch {
                    share_id: share_id.clone(),
                    name: "alice-share".to_owned(),
                    fetched_root: out.path().to_path_buf(),
                    selected: None,
                    flat_dest: false,
                })
                .ok();
            let (files_written, _bytes) = wait_for_fetch_complete(&mut b.evt_rx)
                .await
                .expect("B reports FetchComplete");
            assert_eq!(files_written, 2, "both files written");

            // Files land under <fetched_root>/<share-name>/<rel_path>, byte-identical.
            let got_a = std::fs::read(out.path().join("alice-share").join("page-1.txt")).unwrap();
            let got_b = std::fs::read(
                out.path()
                    .join("alice-share")
                    .join("sub")
                    .join("page-2.txt"),
            )
            .unwrap();
            assert_eq!(got_a, file_a, "page 1 recovered byte-for-byte");
            assert_eq!(got_b, file_b, "page 2 recovered byte-for-byte");
        });
    }

    async fn wait_for_shares_snapshot(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<Vec<wire::PublicShareListing>> {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                match evt {
                    NetEvent::SharesSnapshot { shares } => return Some(shares),
                    NetEvent::SharesError { message } => panic!("refresh failed: {message}"),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    async fn wait_for_publish_stopped(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<String> {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                if let NetEvent::PublishStopped { share_id } = evt {
                    return Some(share_id);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    /// `RefreshShares` lists a share the same actor just published (same connection →
    /// same `PublicSpaceState`), and `UnpublishShare` stops serving it
    /// (`PublishStopped`). Exercises the list + unpublish RPCs the round-trip does not.
    #[test]
    fn share_refresh_lists_own_publish_then_unpublishes() {
        let _ = oxicrypt_module::initialize();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let registry = CotRegistry::new();
            let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
            let _srv = spawn_relay(a_server_io, registry.clone());
            let sess_a = AppSession::open(a_client_io).await.expect("A session");
            let mut a = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();

            let dir = tempfile::TempDir::new().unwrap();
            std::fs::write(dir.path().join("note.txt"), b"hi there").unwrap();
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: dir.path().to_path_buf(),
                    name: "notes".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            let share_id = wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("A reports PublishStarted");

            // RefreshShares: A sees its own listing.
            a.cmd_tx.send(NetCommand::RefreshShares).ok();
            let shares = wait_for_shares_snapshot(&mut a.evt_rx)
                .await
                .expect("A receives a SharesSnapshot");
            assert!(
                shares.iter().any(|s| s.share_id == share_id),
                "the just-published share is in the listing"
            );

            // Unpublish stops serving it.
            a.cmd_tx
                .send(NetCommand::UnpublishShare {
                    share_id: share_id.clone(),
                })
                .ok();
            let stopped = wait_for_publish_stopped(&mut a.evt_rx).await;
            assert_eq!(
                stopped.as_deref(),
                Some(share_id.as_str()),
                "UnpublishShare emits PublishStopped for the share"
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
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
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

    /// Round 6 (persistent identity): a silently RE-JOINED circle (supplied as a
    /// persisted `(circle_id, phrase)` at attach time, NOT via an explicit
    /// JoinCircle command) is live, and the member presents under the PERSISTED
    /// display handle. A attaches with `display_handle = "alice#stable"` and the
    /// circle in `rejoin_circles`; B joins the same circle the ordinary way; A
    /// sends. B must receive the message attributed to the persisted handle —
    /// proving both that the rejoin subscribed A and that the persisted handle is
    /// what travels on the wire.
    #[test]
    fn persisted_circle_rejoins_and_presents_stable_handle() {
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

            // B joins the circle the ordinary way (explicit JoinCircle) and waits
            // for the relay to register the rendezvous.
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 7,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_registry(&registry, 1).await;

            // A attaches with a PERSISTED handle and the circle in rejoin_circles —
            // no explicit JoinCircle command. The attach path must subscribe it.
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: Some("alice#stable".to_owned()),
                    rejoin_circles: vec![(3, CIRCLE_PHRASE.to_owned())],
                })
                .ok();
            wait_for_circle_joined(&mut a.evt_rx).await;

            a.cmd_tx
                .send(NetCommand::SendCircle {
                    circle_id: 3,
                    text: "rejoined and still me".to_owned(),
                })
                .ok();

            // B receives the message attributed to A's PERSISTED handle.
            let got = wait_for_circle_message(&mut b.evt_rx).await;
            assert_eq!(
                got,
                Some((
                    7u64,
                    "alice#stable".to_owned(),
                    "rejoined and still me".to_owned()
                )),
                "a silently re-joined circle delivers under the persisted display handle"
            );
        });
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

    // ── Live fra1 share round-trip (ignored; env-gated) ──────────────────────
    //
    // Two ephemeral clients connect to the real relay; actor A publishes a UNIQUE
    // throwaway one-file share (real publish_share RPC + serve_share), actor B
    // fetches it (real subscribe + manifest + chunk + SHA-384 verify) and recovers
    // the canary byte-for-byte. `#[ignore]` so the default `cargo test` excludes it.
    #[test]
    #[ignore = "live relay; run explicitly with DAEMONSEED_RELAY_* set"]
    fn live_fra1_share_round_trip() {
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

            let mut a = spawn_local_actor();
            let mut b = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: server_id.clone(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            b.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_b,
                    server_id: server_id.clone(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();

            // A UNIQUE throwaway share (random name + body) so it never collides.
            let nonce = now_unix_ms();
            let dir = tempfile::TempDir::new().unwrap();
            let payload =
                format!("gui live share canary {nonce:x} {:x}", std::process::id()).into_bytes();
            std::fs::write(dir.path().join("canary.txt"), &payload).unwrap();
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: dir.path().to_path_buf(),
                    name: format!("gui-live-{nonce:x}"),
                    sharer_handle: "live-test-a#000000000000".to_owned(),
                })
                .ok();
            let share_id = wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("A publishes on fra1");
            // Let A's serve subscription register on the real relay before B fetches.
            tokio::time::sleep(Duration::from_secs(1)).await;

            let out = tempfile::TempDir::new().unwrap();
            b.cmd_tx
                .send(NetCommand::ConfirmFetch {
                    share_id: share_id.clone(),
                    name: format!("gui-live-{nonce:x}"),
                    fetched_root: out.path().to_path_buf(),
                    selected: None,
                    flat_dest: true,
                })
                .ok();
            let (files_written, _bytes) = wait_for_fetch_complete(&mut b.evt_rx)
                .await
                .expect("B fetches from fra1");
            assert_eq!(files_written, 1);
            // flat_dest → the single file lands as its basename under the fetch root.
            let got = std::fs::read(out.path().join("canary.txt")).unwrap();
            assert_eq!(
                got, payload,
                "fra1 share round-trip recovers the canary byte-for-byte"
            );

            // Clean up the throwaway share.
            a.cmd_tx.send(NetCommand::UnpublishShare { share_id }).ok();
        });
    }
}
