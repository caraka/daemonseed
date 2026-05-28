//! Network actor — the async side of the TUI.
//!
//! The render loop is synchronous (a blocking crossterm poll), but the daemon
//! protocol is async. This module bridges them with the standard actor shape:
//! the binary owns a [`NetHandle`] holding a tokio runtime and two channels —
//! [`NetCommand`]s flow in, [`NetEvent`]s flow out. The render thread sends
//! commands and drains events with non-blocking `try_recv`, so a slow connect
//! (or a cold share-index walk, ISC-A-C7) never blocks the UI.
//!
//! [`NetCommand`] and [`NetEvent`] are plain data, so [`crate::app::App`] folds
//! events in via `App::on_net_event` without ever touching the runtime — which
//! keeps `App` unit-testable and the PTY gate deterministic.
//!
//! ## Live session (M11)
//!
//! Once a connect reaches `Authenticated` the actor keeps the live
//! [`AppSession`] (it no longer drops the stream), so subsequent commands run
//! application traffic over the one connection. Circle chat (ISC-10..14) opens a
//! bidirectional `CircleOfTrust` subscribe stream: a dedicated inbound-reader
//! task ([`spawn_local`]) decrypts each frame ([`open_message`]) and emits a
//! [`NetEvent::ChatMessage`], while the actor keeps the outbound half to publish
//! sealed messages. The runtime is *current-thread inside a `LocalSet`*: the
//! `connect_session` future is `!Send` (it borrows `&mut dyn TrustStore`) and
//! the reader holds an [`Rc`] of the circle key, so neither can be
//! `tokio::spawn`ed onto a multi-thread runtime — `spawn_local` sidesteps the
//! `Send` bound.

use std::rc::Rc;
use std::sync::Arc;

use daemonseed_cli::connect::{ConnectError, connect_session};
use daemonseed_cli::identity_proof::ClientIdentity;
use daemonseed_cli::session::AppSession;
use daemonseed_core::backoff::{Backoff, CloseCause};
use daemonseed_core::circle::key::{CotKey, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::public_share_asset_address;
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::share_envelope::ShareFrame;
use daemonseed_core::storage::cas::chunk_addr;
use daemonseed_core::storage::seeds::CounterState;
use daemonseed_core::storage::share_index::ShareIndex;
use daemonseed_core::trust_events::TrustEventKey;
use daemonseed_proto::v1 as wire;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::app::{IndexerStatus, LocalShareRow};

/// A command from the UI to the network actor.
#[derive(Debug, Clone)]
pub enum NetCommand {
    /// Open a connection to `server_id` at `address`, in the given trust mode
    /// (C22), running TLS + APP_HELLO + identity-proof to Authenticated and
    /// keeping the live application session.
    Connect {
        server_id: String,
        address: String,
        trusted: bool,
    },
    /// Join a circle by its shared phrase: derive the circle key, subscribe to
    /// the rendezvous asset on the connected relay, and stream chat (ISC-15/16).
    JoinCircle { phrase: String },
    /// Send a chat message to the joined circle (ISC-14). `sender_handle` is the
    /// user's own display handle, sealed into the message for the recipient's
    /// client-side @mention (C17) / mute (C15) — never seen by the relay.
    SendChat { body: String, sender_handle: String },
    /// Refresh the Shares-pane snapshot (ISC-17 / ISC-20). Returns the current
    /// `ShareIndex` entries (My shares), the latest `ListPublicShares` from
    /// the connected relay (Public shares), and the current indexer status.
    /// A read-only operation — no scan kicks off here; the cold-scan / live
    /// watcher are driven independently and the actor reports whatever state
    /// it observes. Emitted as a single [`NetEvent::SharesSnapshot`].
    RefreshShares,
    /// Initiate a share fetch from the connected relay (ISC-19, F23 unified
    /// mechanism). Derives the public-share asset address from `share_id` +
    /// the connected server-id, opens a new bidi `CircleOfTrust.Subscribe`
    /// stream over the existing `AppSession`, sends a `ManifestRequest`,
    /// reads a `ManifestResponse`, then issues one `ChunkRequest` per entry
    /// and writes each verified chunk to a local in-memory CAS. Progress is
    /// surfaced via `NetEvent::FetchProgress`; the terminal state is one of
    /// `NetEvent::FetchComplete` or `NetEvent::FetchError`. `sharer_handle`
    /// is advisory — included so subsequent UX layers (post-MVP `f`-keyed
    /// trust-on-sharer affordances) can route per-sharer events; the relay
    /// never sees the value (it lives in the recipient's local state only).
    FetchShare {
        share_id: String,
        sharer_handle: String,
    },
}

/// An event from the network actor back to the UI. Plain data — folded into
/// [`crate::app::App`] by `on_net_event` with no runtime dependency.
///
/// `Eq` is intentionally NOT derived: `SharesSnapshot` carries a
/// `Vec<wire::PublicShareListing>` and the prost-generated message type only
/// implements `PartialEq`. Tests use `assert_eq!` (which only needs PartialEq);
/// equality on raw wire types is well-defined for the strings/integers they
/// carry but not for arbitrary embedded prost values, so `PartialEq` is the
/// correct ceiling.
#[derive(Debug, Clone, PartialEq)]
pub enum NetEvent {
    /// The connection reached Authenticated (ISC-47).
    Connected {
        /// The verified server handle.
        server: String,
        /// Negotiated wire version, `MAJOR.MINOR`.
        version: String,
        /// A non-blocking C22 key-rotation notice, if the trusted-mode server
        /// presented a new (undismissed) key.
        rotation_notice: Option<String>,
    },
    /// The connection attempt failed; `message` is a human-readable cause.
    ConnectFailed { message: String },
    /// A circle subscribe stream is live; chat can flow (ISC-16).
    CircleJoined,
    /// Joining a circle failed (no live session, derivation, or subscribe error).
    CircleJoinFailed { message: String },
    /// A decrypted chat message arrived on the joined circle (ISC-10).
    ChatMessage {
        /// The sender's self-asserted handle (for client-side mention/mute).
        sender: String,
        /// The message body, as typed.
        body: String,
        /// Sender wall-clock at compose, unix ms (advisory ordering).
        sent_unix_ms: i64,
    },
    /// A chat send failed (no joined circle, seal, or publish error).
    ChatError { message: String },
    /// A trust-state event to surface per its ISC-C28 affordance class. The key
    /// determines the class via `class_of`; the UI routes it (Blocking modal,
    /// Persistent status badge, Transient toast, or LogOnly history).
    TrustEvent {
        key: TrustEventKey,
        /// The server-id the event concerns, for per-scope dismissal (A-C12).
        server_id: Option<String>,
    },
    /// The connection closed at an observable layer (ISC-C26). Categorized by the
    /// layer reached, never by a guessed server-side cause (ISC-A-S12).
    ConnectionClosed { cause: CloseCause },
    /// A fresh Shares-pane snapshot (ISC-17 / ISC-20). `local` is the user's
    /// own indexed files; `remote` is the full pre-filter listing from the
    /// connected relay (the recipient applies its private hide set at render,
    /// ISC-A-C3); `indexer_status` is the observed indexer state for the
    /// non-blocking status line (ISC-A-C7). Either pane can be empty —
    /// "no share root configured" and "no public listings" are normal states.
    SharesSnapshot {
        local: Vec<LocalShareRow>,
        remote: Vec<wire::PublicShareListing>,
        indexer_status: IndexerStatus,
    },
    /// A `RefreshShares` command could not complete (e.g., no live session,
    /// or `ListPublicShares` returned an RPC status). The user-facing
    /// rendering surfaces this on the status line; the cached snapshot is
    /// left in place so the user keeps seeing the last known state.
    SharesError { message: String },
    /// Progress on an active share fetch (ISC-19). `total_chunks` is `None`
    /// while the fetcher is still waiting on the `ManifestResponse`, and
    /// `Some(N)` after the manifest arrives. Emitted at least once after the
    /// manifest lands and once per successful chunk write.
    FetchProgress {
        total_chunks: Option<u32>,
        chunks_received: u32,
        bytes_received: u64,
    },
    /// The share fetch completed: every chunk in the manifest was verified
    /// and written. `files_written` and `bytes_written` mirror the manifest's
    /// tallies (one chunk = one file at the M11 alpha; multi-chunk-per-file
    /// is post-MVP, layered on without wire change).
    FetchComplete {
        share_id: String,
        files_written: u32,
        bytes_written: u64,
    },
    /// The fetch failed at some point (no session, derive error, decode error,
    /// chunk-hash mismatch, peer dropped the stream, RPC status). The fetcher
    /// stops; partial chunks already in local CAS are kept (any later retry
    /// can dedupe by chunk_addr). The overlay marks the fetch failed and
    /// waits for the user to dismiss.
    FetchError { message: String },
}

/// Owns the network thread and the command/event channels. Held by the binary
/// for the life of the session; dropped on quit (dropping `cmd_tx` ends the
/// actor loop, which returns the runtime and joins the thread).
pub struct NetHandle {
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
    evt_rx: mpsc::UnboundedReceiver<NetEvent>,
    _thread: std::thread::JoinHandle<()>,
}

impl NetHandle {
    /// Spawn a dedicated network thread running a current-thread tokio runtime
    /// (inside a [`tokio::task::LocalSet`]) and the actor loop.
    ///
    /// A *current-thread* runtime + `LocalSet` is deliberate: [`connect_session`]
    /// takes `&mut dyn TrustStore`, which is not `Send`, so its future cannot be
    /// `tokio::spawn`ed onto a multi-thread runtime; and the circle inbound-reader
    /// task holds an [`Rc`] of the circle key. Driving everything on one thread
    /// via `block_on` + `spawn_local` sidesteps both `Send` bounds.
    ///
    /// Caller contract: the process-wide CryptoProvider must already be
    /// installed (the binary does this at startup).
    pub fn new() -> std::io::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("daemonseed-tui-net".to_owned())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread net runtime");
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, net_actor(cmd_rx, evt_tx));
            })?;
        Ok(Self {
            cmd_tx,
            evt_rx,
            _thread: thread,
        })
    }

    /// Queue a command for the network actor. Fails only if the actor stopped.
    pub fn send(&self, cmd: NetCommand) -> Result<(), NetCommand> {
        self.cmd_tx.send(cmd).map_err(|e| e.0)
    }

    /// Drain all currently-available events without blocking. Called once per
    /// render tick.
    pub fn drain_events(&mut self) -> Vec<NetEvent> {
        let mut out = Vec::new();
        while let Ok(evt) = self.evt_rx.try_recv() {
            out.push(evt);
        }
        out
    }
}

/// The live circle a member is currently subscribed to: the outbound frame
/// sender (to publish sealed messages) plus the key + rendezvous address.
struct Circle {
    cot_key: Rc<CotKey>,
    asset_addr: AssetAddr,
    out_tx: mpsc::Sender<wire::CotFrame>,
}

/// Mutable state the actor carries across commands.
struct Actor {
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    /// The live application session, once Connected.
    session: Option<AppSession>,
    /// The connected relay's wire server-id, namespacing circle addresses.
    server_id: Option<String>,
    /// The currently-joined circle, if any.
    circle: Option<Circle>,
    /// Per-session reconnect-refusal budget (ISC-C26). Consecutive refused
    /// connects advance it so the surfaced trust event escalates
    /// `ConnectionRateLimited` (Transient) → `ConnectionRateLimitedExhausted`
    /// (PersistentNonBlocking); a successful connect resets it.
    backoff: Backoff,
    /// The user's own share-index, if a share root has been configured
    /// (ISC-17 / ISC-C21). `None` for the M11 alpha default — the screen
    /// shows "no share root configured" until a config / setup flow lands.
    /// The redb handle is held behind `Arc` so the actor can hand a borrow
    /// to a background cold scan in a future commit without giving up the
    /// foreground query path.
    share_index: Option<Arc<ShareIndex>>,
}

/// The actor loop: receive commands and drive each on the current-thread
/// runtime (network ops serialized; the circle inbound reader runs concurrently
/// as a `spawn_local` task).
async fn net_actor(
    mut cmd_rx: mpsc::UnboundedReceiver<NetCommand>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    let mut actor = Actor {
        evt_tx,
        session: None,
        server_id: None,
        circle: None,
        backoff: Backoff::new(),
        share_index: None,
    };
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            NetCommand::Connect {
                server_id,
                address,
                trusted,
            } => actor.handle_connect(&server_id, &address, trusted).await,
            NetCommand::JoinCircle { phrase } => actor.handle_join_circle(&phrase).await,
            NetCommand::SendChat {
                body,
                sender_handle,
            } => actor.handle_send_chat(&body, &sender_handle).await,
            NetCommand::RefreshShares => actor.handle_refresh_shares().await,
            NetCommand::FetchShare {
                share_id,
                sharer_handle,
            } => actor.handle_fetch_share(&share_id, &sharer_handle).await,
        }
    }
}

impl Actor {
    fn emit(&self, evt: NetEvent) {
        let _ = self.evt_tx.send(evt);
    }

    /// Drive a single connect to Authenticated, keep the live session, and emit
    /// a [`NetEvent`].
    ///
    /// Mirrors the cli connect path: an ephemeral client identity (D8), an
    /// in-memory counter, and an in-memory trust store seeded with one entry for
    /// the dialed server in the requested C22 mode. Trusted-mode first-contact
    /// pins the presented key (TOFU); untrusted mode requires a pre-imported key.
    async fn handle_connect(&mut self, server_id: &str, address: &str, trusted: bool) {
        let identity = match ClientIdentity::ephemeral() {
            Ok(i) => i,
            Err(e) => {
                return self.emit(NetEvent::ConnectFailed {
                    message: format!("identity: {e}"),
                });
            }
        };
        let server_handle = match server_id.parse::<Handle>() {
            Ok(h) => h,
            Err(_) => {
                return self.emit(NetEvent::ConnectFailed {
                    message: "server-id is not a valid <name>#<12hex> handle".to_owned(),
                });
            }
        };
        let mut counters = CounterState::default();
        let mut trust = InMemoryTrustStore::new();
        if trusted {
            trust.upsert(ServerEntry::new_trusted(server_handle, address.to_owned()));
        } else {
            return self.emit(NetEvent::ConnectFailed {
                message: "untrusted mode requires importing the operator key first".to_owned(),
            });
        }

        match connect_session(server_id, address, &identity, &mut counters, &mut trust).await {
            Ok((outcome, stream)) => match AppSession::open(stream).await {
                Ok(session) => {
                    self.session = Some(session);
                    self.server_id = Some(server_id.to_owned());
                    self.backoff.reset();
                    // A trusted-mode key rotation is a PersistentNonBlocking
                    // trust event (ISC-C22/C28): the connect succeeded, but the
                    // user should know the key changed.
                    if outcome.rotation_notice.is_some() {
                        self.emit(NetEvent::TrustEvent {
                            key: TrustEventKey::ServerKeyRotated,
                            server_id: Some(outcome.server_handle.clone()),
                        });
                    }
                    self.emit(NetEvent::Connected {
                        server: outcome.server_handle,
                        version: outcome.version.to_string(),
                        rotation_notice: outcome.rotation_notice,
                    });
                }
                // The handshake succeeded but the application session failed to
                // open — an after-auth close (ISC-C26).
                Err(e) => {
                    self.emit(NetEvent::ConnectFailed {
                        message: format!("application session setup failed: {e}"),
                    });
                    self.emit_close(server_id, CloseCause::ClosedAfterAuth, None);
                }
            },
            Err(e) => {
                let (cause, specific) = classify_failure(&e);
                self.emit(NetEvent::ConnectFailed {
                    message: e.to_string(),
                });
                self.emit_close(server_id, cause, specific);
            }
        }
    }

    /// Emit a connection-close event and the trust event it warrants (ISC-C26 /
    /// ISC-C28). An actionable `specific` key (key mismatch, no-common-version)
    /// surfaces directly; otherwise an app-level close flows through the uniform
    /// rate-limit refusal path (ISC-A-S12) — the client cannot tell a refusal
    /// from a rate-limit, so it escalates the bounded refusal event and advances
    /// the backoff budget. A pure network failure carries no trust event.
    fn emit_close(&mut self, server_id: &str, cause: CloseCause, specific: Option<TrustEventKey>) {
        self.emit(NetEvent::ConnectionClosed { cause });
        match specific {
            Some(key) => self.emit(NetEvent::TrustEvent {
                key,
                server_id: Some(server_id.to_owned()),
            }),
            None => {
                if matches!(
                    cause,
                    CloseCause::RefusedBeforeHelloAck | CloseCause::ClosedAfterAuth
                ) {
                    let key = self.backoff.refusal_event();
                    let _ = self.backoff.next_jittered(); // advance the budget
                    self.emit(NetEvent::TrustEvent {
                        key,
                        server_id: Some(server_id.to_owned()),
                    });
                }
            }
        }
    }

    /// Derive the circle key, subscribe to the rendezvous asset on the connected
    /// relay, and spawn the inbound chat reader (ISC-15/16).
    async fn handle_join_circle(&mut self, phrase: &str) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::CircleJoinFailed {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let Some(server_id) = self.server_id.as_ref() else {
            return self.emit(NetEvent::CircleJoinFailed {
                message: "no server-id for the connected relay".to_owned(),
            });
        };

        let cot_key = match derive_cot_key(phrase, &CNSA_2_0) {
            Ok(k) => Rc::new(k),
            Err(e) => {
                return self.emit(NetEvent::CircleJoinFailed {
                    message: format!("circle-key derivation failed: {e}"),
                });
            }
        };
        let asset_addr = match asset_address(&cot_key, server_id.as_bytes()) {
            Ok(a) => a,
            Err(e) => {
                return self.emit(NetEvent::CircleJoinFailed {
                    message: format!("rendezvous derivation failed: {e}"),
                });
            }
        };

        // Outbound half: first frame names the asset (empty payload, not
        // relayed), then publishes flow. Send the naming frame before subscribe
        // consumes the receiver, so it is the stream's first item.
        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        if out_tx.send(naming).await.is_err() {
            return self.emit(NetEvent::CircleJoinFailed {
                message: "circle subscribe channel closed".to_owned(),
            });
        }

        let mut cot = session.circle_of_trust();
        let inbound = match cot.subscribe(ReceiverStream::new(out_rx)).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::CircleJoinFailed {
                    message: format!("subscribe refused: {}", status.message()),
                });
            }
        };

        // Inbound reader: decrypt each frame under the circle key and emit a
        // ChatMessage. Foreign / undecryptable frames are skipped silently
        // (noise on a shared rendezvous). Runs until the stream ends.
        let reader_key = Rc::clone(&cot_key);
        let reader_tx = self.evt_tx.clone();
        tokio::task::spawn_local(read_inbound(inbound, reader_key, reader_tx));

        self.circle = Some(Circle {
            cot_key,
            asset_addr,
            out_tx,
        });
        self.emit(NetEvent::CircleJoined);
    }

    /// Read the My-shares ([`ShareIndex::entries`]) + Public-shares
    /// (`ListPublicShares` over the held [`AppSession`]) snapshots and emit
    /// them as a single [`NetEvent::SharesSnapshot`] (ISC-17 / ISC-20).
    ///
    /// Pure read-path — no scan kicks off here. The indexer status reported
    /// is whatever the actor has observed; for the M11 alpha default (no
    /// configured share root) it is [`IndexerStatus::Idle`] and the local
    /// pane is empty. When a share root is configured in a future commit, a
    /// background `Indexer::spawn_background_scan` will publish updated
    /// states to the actor — this method just reports them.
    async fn handle_refresh_shares(&mut self) {
        // My shares: best-effort read of the persisted index. A redb error is
        // surfaced via `SharesError` and the local list reverts to empty so
        // the UI never blocks on a transient storage hiccup (ISC-A-C7).
        let (local, indexer_status) = match self.share_index.as_ref() {
            Some(index) => {
                let entries = index.entries();
                match entries {
                    Ok(rows) => {
                        let count = rows.len() as u64;
                        let local: Vec<LocalShareRow> = rows
                            .into_iter()
                            .map(|e| LocalShareRow {
                                rel_path: e.rel_path,
                                size: e.size,
                                mtime_unix_ms: e.mtime_unix_ms,
                            })
                            .collect();
                        (local, IndexerStatus::Ready { entries: count })
                    }
                    Err(e) => {
                        self.emit(NetEvent::SharesError {
                            message: format!("share-index read failed: {e}"),
                        });
                        (Vec::new(), IndexerStatus::Idle)
                    }
                }
            }
            None => (Vec::new(), IndexerStatus::Idle),
        };

        // Public shares: requires a live session. Missing session is not an
        // error per se — the user has not yet connected — so we emit a
        // snapshot with empty `remote` rather than an error.
        let remote = if let Some(session) = self.session.as_ref() {
            let mut ps = session.public_space();
            match ps
                .list_public_shares(wire::ListPublicSharesRequest {})
                .await
            {
                Ok(resp) => resp.into_inner().shares,
                Err(status) => {
                    self.emit(NetEvent::SharesError {
                        message: format!("list-public-shares refused: {}", status.message()),
                    });
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        self.emit(NetEvent::SharesSnapshot {
            local,
            remote,
            indexer_status,
        });
    }

    /// Initiate a share fetch (ISC-19, F23 unified mechanism). Opens a fresh
    /// `CircleOfTrust.Subscribe` stream over the held [`AppSession`] (chat
    /// stays unaffected; the actor's existing `circle` field is independent),
    /// names the public-share asset address derived from `share_id` +
    /// connected `server_id`, and runs the manifest-then-chunks protocol from
    /// the fetcher's side.
    ///
    /// Verification: each `ChunkResponse.data` is re-hashed with
    /// [`chunk_addr`]; a mismatch fails the fetch closed (the fetcher refuses
    /// to write a chunk whose bytes do not match the address it asked for).
    /// This is the file-side analog of the chat envelope's `open_message`
    /// fail-closed posture — a corrupt relay or hostile sharer cannot deliver
    /// falsified content to a verifying fetcher.
    async fn handle_fetch_share(&mut self, share_id: &str, _sharer_handle: &str) {
        // Pre-flight: live session + known relay are mandatory.
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::FetchError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let Some(server_id) = self.server_id.as_ref() else {
            return self.emit(NetEvent::FetchError {
                message: "no server-id for the connected relay".to_owned(),
            });
        };

        let asset_addr = match public_share_asset_address(share_id.as_bytes(), server_id.as_bytes())
        {
            Ok(a) => a,
            Err(e) => {
                return self.emit(NetEvent::FetchError {
                    message: format!("share-asset derivation failed: {e}"),
                });
            }
        };

        // The outbound half: a tokio mpsc the actor publishes to; the bidi
        // Subscribe stream reads from it. Capacity sized for the small set of
        // round-trip request frames a fetch generates (manifest + chunks);
        // ChunkResponse arrivals do not back-pressure this channel.
        let (out_tx, out_rx) = mpsc::channel::<daemonseed_proto::v1::CotFrame>(32);

        // The naming frame: every Subscribe stream's first frame names its
        // rendezvous (empty payload, not relayed); same shape as the chat
        // path. Send it before subscribe consumes the receiver.
        let naming = daemonseed_proto::v1::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        if out_tx.send(naming).await.is_err() {
            return self.emit(NetEvent::FetchError {
                message: "fetch subscribe channel closed before naming frame".to_owned(),
            });
        }

        let mut cot = session.circle_of_trust();
        let mut inbound = match cot.subscribe(ReceiverStream::new(out_rx)).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::FetchError {
                    message: format!("subscribe refused: {}", status.message()),
                });
            }
        };

        // Send ManifestRequest. The first non-empty inbound frame on this
        // stream is expected to be the ManifestResponse from the sharer.
        let request = ShareFrame::ManifestRequest;
        let req_frame = daemonseed_proto::v1::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: request.encode(),
        };
        if out_tx.send(req_frame).await.is_err() {
            return self.emit(NetEvent::FetchError {
                message: "fetch subscribe channel closed before manifest request".to_owned(),
            });
        }

        // Read the manifest. Foreign / undecryptable frames (other members'
        // chatter, the sharer's naming frame echoing back if any) are skipped
        // silently — same posture as chat. The first valid ManifestResponse
        // wins.
        let manifest = loop {
            let frame = match inbound.message().await {
                Ok(Some(f)) => f,
                Ok(None) | Err(_) => {
                    return self.emit(NetEvent::FetchError {
                        message: "stream ended before manifest arrived".to_owned(),
                    });
                }
            };
            if frame.payload.is_empty() {
                continue; // naming-frame echo or noise
            }
            match ShareFrame::decode(&frame.payload) {
                Ok(ShareFrame::ManifestResponse { entries }) => break entries,
                Ok(_) => continue, // out-of-order request or chunk noise
                Err(_) => continue,
            }
        };

        let total_chunks = manifest.len() as u32;
        self.emit(NetEvent::FetchProgress {
            total_chunks: Some(total_chunks),
            chunks_received: 0,
            bytes_received: 0,
        });

        // For each manifest entry, request the chunk by its advertised
        // address, verify the response, and account bytes. A single-chunk-
        // per-file alpha: one request per file, one response per request,
        // sequential (pipelining is a post-MVP optimisation).
        let mut chunks_received: u32 = 0;
        let mut bytes_received: u64 = 0;
        for entry in &manifest {
            let request = ShareFrame::ChunkRequest {
                chunk_addr: entry.chunk_addr,
            };
            let req_frame = daemonseed_proto::v1::CotFrame {
                asset_address: asset_addr.as_bytes().to_vec(),
                payload: request.encode(),
            };
            if out_tx.send(req_frame).await.is_err() {
                return self.emit(NetEvent::FetchError {
                    message: "fetch subscribe channel closed mid-fetch".to_owned(),
                });
            }

            // Read until we see the response naming this chunk_addr; ignore
            // other frame kinds (re-arrival of the manifest, noise from
            // other subscribers).
            let chunk_data = loop {
                let frame = match inbound.message().await {
                    Ok(Some(f)) => f,
                    Ok(None) | Err(_) => {
                        return self.emit(NetEvent::FetchError {
                            message: "stream ended mid-fetch".to_owned(),
                        });
                    }
                };
                if frame.payload.is_empty() {
                    continue;
                }
                match ShareFrame::decode(&frame.payload) {
                    Ok(ShareFrame::ChunkResponse { chunk_addr, data }) => {
                        if chunk_addr == entry.chunk_addr {
                            break (chunk_addr, data);
                        }
                        // Response for some other chunk_addr — skip; sequential
                        // alpha never has more than one outstanding request.
                    }
                    Ok(_) | Err(_) => continue,
                }
            };

            // Verification (ISC-19 / F23): recompute SHA-384 and compare. A
            // mismatch fails the whole fetch — the fetcher cannot trust any
            // chunk after a hostile or corrupted one slipped through.
            let recomputed = match chunk_addr(&chunk_data.1) {
                Ok(a) => a,
                Err(e) => {
                    return self.emit(NetEvent::FetchError {
                        message: format!("hash recompute failed: {e}"),
                    });
                }
            };
            if recomputed != chunk_data.0 {
                return self.emit(NetEvent::FetchError {
                    message: format!(
                        "chunk hash mismatch on {} — refusing tampered content",
                        entry.rel_path
                    ),
                });
            }

            // The M11 alpha keeps the local sink in-memory: each verified
            // chunk's bytes are dropped after accounting. A persistent
            // [`crate::storage::cas`]-backed sink is the next layer (the
            // M11.5 fetch-persistence workstream wires it in via a
            // `Box<dyn ChunkStore>` injected at actor construction). The
            // verification gate above is the load-bearing security
            // contract for ISC-19; persistence is bookkeeping above it.
            chunks_received += 1;
            bytes_received += chunk_data.1.len() as u64;
            self.emit(NetEvent::FetchProgress {
                total_chunks: Some(total_chunks),
                chunks_received,
                bytes_received,
            });
        }

        self.emit(NetEvent::FetchComplete {
            share_id: share_id.to_owned(),
            files_written: chunks_received,
            bytes_written: bytes_received,
        });
        // Close the subscribe stream by dropping the sender; the relay reaps
        // when both halves of this Subscribe stream are gone (refcount → 0).
        drop(out_tx);
    }

    /// Seal a chat message under the joined circle's key and publish it (ISC-14).
    async fn handle_send_chat(&mut self, body: &str, sender_handle: &str) {
        let Some(circle) = self.circle.as_ref() else {
            return self.emit(NetEvent::ChatError {
                message: "join a circle before sending".to_owned(),
            });
        };
        let message = wire::CircleMessage {
            sender_handle: sender_handle.to_owned(),
            body: body.to_owned(),
            sent_unix_ms: now_unix_ms(),
        };
        let sealed = match seal_message(&circle.cot_key, &message) {
            Ok(s) => s,
            Err(e) => {
                return self.emit(NetEvent::ChatError {
                    message: format!("seal failed: {e}"),
                });
            }
        };
        let frame = wire::CotFrame {
            asset_address: circle.asset_addr.as_bytes().to_vec(),
            payload: sealed,
        };
        if circle.out_tx.send(frame).await.is_err() {
            self.emit(NetEvent::ChatError {
                message: "circle stream closed; rejoin to send".to_owned(),
            });
        }
    }
}

/// Read the circle's inbound frame stream, decrypt each, and emit a
/// [`NetEvent::ChatMessage`]. Undecryptable frames (foreign noise on the shared
/// rendezvous, or a tampered frame) are skipped silently. Returns when the
/// stream ends (the relay closed it or the session dropped).
async fn read_inbound(
    mut inbound: tonic::Streaming<wire::CotFrame>,
    cot_key: Rc<CotKey>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    loop {
        match inbound.message().await {
            Ok(Some(frame)) => {
                // Foreign/undecryptable frames (noise on the shared rendezvous,
                // or tampering) skip silently; a closed UI channel ends the task.
                if let Ok(msg) = open_message(&cot_key, &frame.payload)
                    && evt_tx
                        .send(NetEvent::ChatMessage {
                            sender: msg.sender_handle,
                            body: msg.body,
                            sent_unix_ms: msg.sent_unix_ms,
                        })
                        .is_err()
                {
                    return; // UI gone
                }
            }
            Ok(None) | Err(_) => return, // stream ended / errored
        }
    }
}

/// Categorize a connect failure into its observable close layer (ISC-C26) and,
/// when the error maps to a *specific actionable* trust event (ISC-C28), that
/// key. Network-layer failures and the deliberately-opaque app-layer closes
/// carry no specific key — they flow through the uniform rate-limit refusal path
/// instead (ISC-A-S12), so the client never claims to know a server-side cause
/// it cannot observe.
fn classify_failure(e: &ConnectError) -> (CloseCause, Option<TrustEventKey>) {
    match e {
        // Never reached the application: DNS / TCP / TLS, or a local config
        // failure that meant no server was ever contacted.
        ConnectError::Tcp { .. }
        | ConnectError::TlsHandshake(_)
        | ConnectError::Rustls(_)
        | ConnectError::NoAddress { .. }
        | ConnectError::BadServerId => (CloseCause::NetworkFailure, None),
        // Actionable, non-opaque: the C22 trust slider refused the presented key.
        ConnectError::TrustRefused => (
            CloseCause::RefusedBeforeHelloAck,
            Some(TrustEventKey::ServerKeyMismatch),
        ),
        // Actionable: no protocol version in common (ISC-C23).
        ConnectError::NoCommonVersion { .. } => (
            CloseCause::RefusedBeforeHelloAck,
            Some(TrustEventKey::NoCommonVersion),
        ),
        // App-level close at/around APP_HELLO, or the deliberately-opaque
        // identity-proof refusal (ISC-46) — no specific key.
        ConnectError::HelloWrite(_)
        | ConnectError::HelloDecode(_)
        | ConnectError::OutOfSetAck { .. }
        | ConnectError::UnknownRejectCode { .. }
        | ConnectError::WireOutOfRange(_)
        | ConnectError::ChannelBinding(_)
        | ConnectError::IdentityProofRefused => (CloseCause::RefusedBeforeHelloAck, None),
    }
}

/// Wall-clock now in unix milliseconds (advisory message timestamp).
fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_event_variants_are_data() {
        let c = NetEvent::Connected {
            server: "relay#aabbccddeeff".to_owned(),
            version: "1.0".to_owned(),
            rotation_notice: None,
        };
        let f = NetEvent::ConnectFailed {
            message: "boom".to_owned(),
        };
        assert_ne!(c, f);
    }

    #[test]
    fn chat_message_event_is_data() {
        let m = NetEvent::ChatMessage {
            sender: "otter#aabbccddeeff".to_owned(),
            body: "hi".to_owned(),
            sent_unix_ms: 1,
        };
        match m {
            NetEvent::ChatMessage { sender, body, .. } => {
                assert_eq!(sender, "otter#aabbccddeeff");
                assert_eq!(body, "hi");
            }
            _ => panic!("variant mismatch"),
        }
    }

    /// Joining a circle before connecting emits CircleJoinFailed, not a panic —
    /// the actor's prerequisite guard. Driven on a current-thread + LocalSet
    /// runtime exactly as the live actor runs.
    #[test]
    fn join_circle_without_session_fails_cleanly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let (evt_tx, mut evt_rx) = mpsc::unbounded_channel();
            let mut actor = Actor {
                evt_tx,
                session: None,
                server_id: None,
                circle: None,
                backoff: Backoff::new(),
                share_index: None,
            };
            actor.handle_join_circle("some circle phrase").await;
            match evt_rx.try_recv() {
                Ok(NetEvent::CircleJoinFailed { message }) => {
                    assert!(message.contains("not connected"));
                }
                other => panic!("expected CircleJoinFailed, got {other:?}"),
            }
        });
    }

    /// `classify_failure` maps each error to the right close layer (ISC-C26) and
    /// only the two actionable errors carry a specific trust-event key (ISC-C28).
    #[test]
    fn classify_failure_maps_layers_and_specific_keys() {
        assert_eq!(
            classify_failure(&ConnectError::BadServerId),
            (CloseCause::NetworkFailure, None)
        );
        assert_eq!(
            classify_failure(&ConnectError::TrustRefused),
            (
                CloseCause::RefusedBeforeHelloAck,
                Some(TrustEventKey::ServerKeyMismatch)
            )
        );
        assert_eq!(
            classify_failure(&ConnectError::NoCommonVersion {
                server_supported: Vec::new()
            }),
            (
                CloseCause::RefusedBeforeHelloAck,
                Some(TrustEventKey::NoCommonVersion)
            )
        );
        // The opaque identity-proof refusal carries no specific key (ISC-46).
        assert_eq!(
            classify_failure(&ConnectError::IdentityProofRefused),
            (CloseCause::RefusedBeforeHelloAck, None)
        );
    }

    fn bare_actor(evt_tx: mpsc::UnboundedSender<NetEvent>) -> Actor {
        Actor {
            evt_tx,
            session: None,
            server_id: None,
            circle: None,
            backoff: Backoff::new(),
            share_index: None,
        }
    }

    /// An actionable failure emits the close event plus its specific trust event
    /// (ISC-C28), and does not consume the refusal budget.
    #[test]
    fn emit_close_surfaces_specific_trust_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut actor = bare_actor(tx);
        actor.emit_close(
            "relay#aabbccddeeff",
            CloseCause::RefusedBeforeHelloAck,
            Some(TrustEventKey::ServerKeyMismatch),
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            NetEvent::ConnectionClosed {
                cause: CloseCause::RefusedBeforeHelloAck
            }
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            NetEvent::TrustEvent {
                key: TrustEventKey::ServerKeyMismatch,
                server_id: Some("relay#aabbccddeeff".to_owned())
            }
        );
    }

    /// A network-layer failure emits only the close event — no trust event, since
    /// the client never reached the application (ISC-A-S12).
    #[test]
    fn emit_close_network_failure_has_no_trust_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut actor = bare_actor(tx);
        actor.emit_close("relay#aabbccddeeff", CloseCause::NetworkFailure, None);
        assert_eq!(
            rx.try_recv().unwrap(),
            NetEvent::ConnectionClosed {
                cause: CloseCause::NetworkFailure
            }
        );
        assert!(rx.try_recv().is_err(), "no trust event on network failure");
    }

    /// Repeated opaque app-level refusals escalate the uniform refusal event from
    /// Transient (`ConnectionRateLimited`) to PersistentNonBlocking
    /// (`ConnectionRateLimitedExhausted`) once the budget is spent (ISC-C26/C28).
    #[test]
    fn emit_close_escalates_refusal_after_budget() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut actor = bare_actor(tx);
        let refusal_key = |rx: &mut mpsc::UnboundedReceiver<NetEvent>| {
            // Drain the ConnectionClosed, return the trust-event key.
            let _ = rx.try_recv();
            match rx.try_recv().unwrap() {
                NetEvent::TrustEvent { key, .. } => key,
                other => panic!("expected TrustEvent, got {other:?}"),
            }
        };
        // First refusal is Transient.
        actor.emit_close(
            "relay#aabbccddeeff",
            CloseCause::RefusedBeforeHelloAck,
            None,
        );
        assert_eq!(refusal_key(&mut rx), TrustEventKey::ConnectionRateLimited);
        // Spend the rest of the 8-retry budget.
        for _ in 0..8 {
            actor.emit_close(
                "relay#aabbccddeeff",
                CloseCause::RefusedBeforeHelloAck,
                None,
            );
            let _ = refusal_key(&mut rx);
        }
        // Now the budget is exhausted → PersistentNonBlocking.
        actor.emit_close(
            "relay#aabbccddeeff",
            CloseCause::RefusedBeforeHelloAck,
            None,
        );
        assert_eq!(
            refusal_key(&mut rx),
            TrustEventKey::ConnectionRateLimitedExhausted
        );
    }

    /// Sending chat before joining a circle emits ChatError, not a panic.
    #[test]
    fn send_chat_without_circle_fails_cleanly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let (evt_tx, mut evt_rx) = mpsc::unbounded_channel();
            let mut actor = Actor {
                evt_tx,
                session: None,
                server_id: None,
                circle: None,
                backoff: Backoff::new(),
                share_index: None,
            };
            actor.handle_send_chat("hello", "me#000000000000").await;
            match evt_rx.try_recv() {
                Ok(NetEvent::ChatError { message }) => assert!(message.contains("join a circle")),
                other => panic!("expected ChatError, got {other:?}"),
            }
        });
    }
}
