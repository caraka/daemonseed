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

use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use daemonseed_cli::connect::{ConnectError, connect_session};
use daemonseed_cli::identity_proof::ClientIdentity;
use daemonseed_cli::public_space::{
    post_render_fields, render_motd, verify_served_post, whitelist_from_wire,
};
use daemonseed_cli::session::AppSession;
use daemonseed_core::backoff::{Backoff, CloseCause};
use daemonseed_core::circle::key::{CotKey, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::public_share_asset_address;
use daemonseed_core::cot::{AssetAddr, asset_address};
use daemonseed_core::crypto::deprecation::{PolicyCache, PolicyError, verify_policy};
use daemonseed_core::crypto::suite::{CNSA_2_0, SuiteId};
use daemonseed_core::federation::discovered::DiscoveredPeers;
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::indexer::scan_into;
use daemonseed_core::public_room::{
    DEFAULT_ROOM, derive_room_key, open_room_message, room_asset_address, seal_room_message,
};
use daemonseed_core::share_envelope::{ManifestEntry, ShareFrame};
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::chunk_addr;
use daemonseed_core::storage::fetched::{FetchedShare, FetchedStore, VerifiedFile};
use daemonseed_core::storage::seeds::{CounterState, IndexKey};
use daemonseed_core::storage::share_index::ShareIndex;
use daemonseed_core::trust_events::{TrustEventKey, assess_deprecation, unreadable_policy_event};
use daemonseed_proto::v1 as wire;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::app::{DeprecationWarningRow, IndexerStatus, LocalShareRow, PublicPostRow};

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
    /// Send a chat message to one joined circle (ISC-14 / ISC-C60 / ISC-A-C30).
    /// `circle_id` names the *active* circle the post must seal under; the actor
    /// looks it up in its membership set and seals under exactly that circle's
    /// `cot_key` — never another circle's, never broadcast. `sender_handle` is
    /// the user's own display handle, sealed into the message for the recipient's
    /// client-side @mention (C17) / mute (C15) — never seen by the relay.
    SendChat {
        circle_id: u64,
        body: String,
        sender_handle: String,
    },
    /// Post a message to the joined default public room (ISC-S22 / ISC-S24).
    /// Self-signed for provenance under the daemon's own identity, then sealed
    /// under the global room key. Any daemon may post; the relay can read it
    /// (it holds the global key) but it is never wire-cleartext (ISC-A-S16).
    /// `sender_handle` is the poster's own display handle (name#hash) — sealed
    /// into the message so peers render the display name, not the floor (parity
    /// with `SendChat`). The relay never sees it in cleartext (ISC-A-S16).
    SendPublicRoom { body: String, sender_handle: String },
    /// Define (activate) a local share root (M14, ISC-C21 / ISC-A-C7). Opens
    /// the redb [`ShareIndex`] at `index_path` under `index_key` (the
    /// share-index key derived as a sibling of the at-rest key — the actor never
    /// re-derives it), retains it for foreground queries, and runs a cold scan
    /// of `root` on a dedicated blocking thread so the net task is never blocked.
    /// Progress is surfaced via [`NetEvent::IndexerStatus`]; an open failure via
    /// [`NetEvent::ShareDefineFailed`]. `index_key` is carried in the redacted
    /// [`IndexKey`] newtype so it never lands in a `Debug` log.
    DefineShare {
        root: PathBuf,
        label: Option<String>,
        index_path: PathBuf,
        index_key: IndexKey,
    },
    /// Refresh the Shares-pane snapshot (ISC-17 / ISC-20). Returns the current
    /// `ShareIndex` entries (My shares), the latest `ListPublicShares` from
    /// the connected relay (Public shares), and the current indexer status.
    /// A read-only operation — no scan kicks off here; the cold-scan / live
    /// watcher are driven independently and the actor reports whatever state
    /// it observes. Emitted as a single [`NetEvent::SharesSnapshot`].
    RefreshShares,
    /// Refresh the public-space snapshot (ISC-25 / ISC-S7 / ISC-A-S3): fetch the
    /// connected relay's MOTD, announcement posts, and published signer
    /// whitelist over the live [`AppSession`], render the MOTD as inert text,
    /// and re-verify each post against the whitelist client-side. A read-only
    /// operation emitted as a single [`NetEvent::PublicSpaceSnapshot`].
    RefreshPublicSpace,
    /// Refresh the suite-deprecation policy (ISC-C25 / ISC-A-S11 / ISC-C28):
    /// fetch the connected relay's signed policy over the live [`AppSession`],
    /// verify its ML-DSA-87 signature against the pinned server-wide key,
    /// anti-rollback-check it against the cached version, and surface a warning
    /// row for each in-use suite the policy schedules for retirement. A
    /// read-only operation; a verified policy emits a
    /// [`NetEvent::DeprecationSnapshot`] (and one [`NetEvent::TrustEvent`] per
    /// newly-surfaced affected suite), while a rollback / unverifiable /
    /// withdrawn policy emits a [`NetEvent::DeprecationError`] plus the matching
    /// trust event and leaves the cached warnings in place.
    RefreshDeprecation,
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
    /// `name` is the sharer-advertised listing name, recorded in the fetched
    /// manifest. `fetched_root` is the on-disk landing zone (the binary supplies
    /// `<profile-root>/fetched`); on a fully-verified fetch the actor persists
    /// every file there via [`FetchedStore`] and emits a fresh
    /// [`NetEvent::FetchedShares`] (M15 C; ISC-C63 / C64). A fetch that fails
    /// verification never persists (ISC-A-C31).
    FetchShare {
        share_id: String,
        sharer_handle: String,
        name: String,
        fetched_root: PathBuf,
    },
    /// Confirm an A1-previewed fetch and download it (ISC-19). Issued after the
    /// user accepts the `NetEvent::FetchManifest` preview. Re-opens the share
    /// stream, requests the chunks (`selected = None` downloads every file;
    /// `Some(indices)` downloads only those manifest rows — the A2 selective
    /// path), verifies each against its content address, and persists the
    /// fully-verified download (ISC-C63 / A-C31). Terminal state is
    /// `NetEvent::FetchComplete` or `NetEvent::FetchError`.
    ConfirmFetch {
        share_id: String,
        sharer_handle: String,
        name: String,
        fetched_root: PathBuf,
        selected: Option<Vec<usize>>,
    },
    /// List the fetched shares recorded under `fetched_root` for the browse
    /// pane (M15 C; ISC-C64). Emits a [`NetEvent::FetchedShares`] snapshot
    /// (empty if nothing has been fetched).
    ListFetched { fetched_root: PathBuf },
    /// Refresh the introducer-discovered candidate peers for the Servers pane
    /// (M12 gate step 6, ISC-C22 / ISC-S6 / ISC-A-C19). Ask the connected
    /// relay's `FederationIntroducer` for its peer list over the live
    /// [`AppSession`] and merge the result into the actor's [`DiscoveredPeers`]
    /// cache as candidates, then emit the candidate `(server_id, address)`
    /// pairs as a single [`NetEvent::IntroducerSnapshot`].
    ///
    /// Precautionary by construction: discovery records *candidates only* and
    /// NEVER writes the trust set (ISC-A-C19) — promotion to a trusted/untrusted
    /// server stays the explicit user action ([`DiscoveredPeers::promote_trusted`]
    /// / [`DiscoveredPeers::promote_untrusted`]). The introducer response carries
    /// no key material (ISC-S6), so the snapshot it produces is server-id +
    /// address only. A read-only operation against an already-shipped gRPC
    /// service — no new wire protocol.
    RefreshIntroducer,
    /// Publish a defined share to the connected relay and serve its content
    /// (D, M15; ISC-S27 / ISC-S29 / F25). Indexes `root` into a [`ShareContent`]
    /// (fails fast on a bad path), publishes the listing via `PublishShare` to
    /// learn the server-assigned `share_id`, then spawns a `serve_share` task
    /// answering fetchers' manifest/chunk requests over the share's CoT
    /// fetch-asset for as long as the session is up ("you must be online to
    /// share" — the relay reaps the share when this connection drops, ISC-S20).
    /// Lifecycle arrives as `NetEvent::PublishStarted` / `PublishError` /
    /// `PublishStopped`.
    PublishShare {
        root: PathBuf,
        name: String,
        /// The publisher's display handle, advertised in the listing so peers
        /// see the sharer's name, not "(operator)".
        sharer_handle: String,
    },
    /// Unpublish a share published this session and stop serving it (D, M15;
    /// owner-scoped, ISC-A-S1). Sends `UnpublishShare` to the relay and aborts
    /// the local serve task, emitting `NetEvent::PublishStopped`. No-op for an
    /// unknown id.
    UnpublishShare { share_id: String },
}

/// One file in an A1 fetch-preview ([`NetEvent::FetchManifest`]): the
/// sharer-advertised relative path and its byte size. Carries no `chunk_addr`
/// — the content address stays in the net actor; the UI shows names + sizes
/// only and confirms by manifest-row index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareManifestEntry {
    pub rel_path: String,
    pub size: u64,
}

/// An opened share-fetch stream plus its manifest — the shared front half of
/// the A1 preview and the confirmed download (see `Actor::open_share_stream`).
/// Owned values only: `inbound`/`out_tx` come from `into_inner()` / the mpsc
/// channel and do not borrow the actor, so this is freely movable out of the
/// helper and dropped (preview) or consumed (confirm) by the caller.
struct OpenedShare {
    out_tx: mpsc::Sender<wire::CotFrame>,
    inbound: tonic::Streaming<wire::CotFrame>,
    asset_addr: AssetAddr,
    manifest: Vec<ManifestEntry>,
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
    /// A circle subscribe stream is live; chat can flow (ISC-16 / ISC-C59). The
    /// circle is ADDED to the membership set (it never evicts an existing one);
    /// `circle_id` is the stable per-session id the app keys its membership and
    /// active-surface selection on, and `label` is the client-local display label
    /// assigned at join (ISC-C62) — never transmitted.
    ///
    /// `entropy` is the exact phrase string the actor derived this circle's
    /// `cot_key` from (M13 persistence keystone, ISC-C59): re-sending it as a
    /// future [`NetCommand::JoinCircle`] re-derives the same key deterministically,
    /// so it is the sufficient persisted seed. It travels only on this in-process
    /// actor→UI channel, never on the wire.
    CircleJoined {
        circle_id: u64,
        label: String,
        entropy: String,
    },
    /// Joining a circle failed (no live session, derivation, or subscribe error).
    CircleJoinFailed { message: String },
    /// A decrypted chat message arrived on a joined circle (ISC-10 / ISC-A-C30).
    /// `circle_id` is the id of the single circle whose `cot_key` opened this
    /// frame — the app renders it only in that circle's pane (ISC-A-C29); it is
    /// never guessed nor broadcast to other panes.
    ChatMessage {
        /// The circle whose key decrypted this frame (attribution, ISC-A-C30).
        circle_id: u64,
        /// The sender's self-asserted handle (for client-side mention/mute).
        sender: String,
        /// The message body, as typed.
        body: String,
        /// Sender wall-clock at compose, unix ms (advisory ordering).
        sent_unix_ms: i64,
    },
    /// A chat send failed (no joined circle, seal, or publish error).
    ChatError { message: String },
    /// The default public room is subscribed; everyone-reads chat can flow
    /// (ISC-S22 / ISC-C56). `room` is the joined room name.
    PublicRoomJoined { room: String },
    /// Joining the default public room failed (no live session or subscribe
    /// error). Non-fatal: the connection itself is up.
    PublicRoomJoinFailed { message: String },
    /// A verified public-room message arrived (ISC-S25 / ISC-C57). Only messages
    /// whose provenance signature verified are emitted (ISC-A-S17).
    PublicRoomMessage {
        /// The room the message belongs to.
        room: String,
        /// The sender's self-asserted handle (cross-checked against the verified
        /// pubkey at the UI layer per ISC-C57).
        sender: String,
        /// The message body, as posted.
        body: String,
        /// Sender wall-clock at compose, unix ms (advisory ordering).
        sent_unix_ms: i64,
    },
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
    /// A standalone indexer-status transition (M14, ISC-20 / ISC-A-C7): emitted
    /// when a share is defined (`Indexing`) and when its background cold scan
    /// finishes (`Ready`), without a full `SharesSnapshot`. The app folds it
    /// straight into its indexer-status line; the My-shares rows refresh via the
    /// `SharesSnapshot` the actor emits once the scan completes.
    IndexerStatus(IndexerStatus),
    /// A `DefineShare` command could not open the share index (bad path,
    /// permissions, redb error). Surfaced on the status line; the previously
    /// active index, if any, is left in place.
    ShareDefineFailed { message: String },
    /// A fresh public-space snapshot (ISC-25 / ISC-S7 / ISC-A-S3). `motd` is the
    /// rendered, terminal-sanitized message of the day (`None` when the relay
    /// publishes none); `posts` are the announcement posts, each carrying its
    /// client-side whitelist-verification verdict. MOTD *signature*
    /// re-verification is not done here — it requires the server's full pubkey,
    /// which `ConnectOutcome` does not yet thread through (tracked follow-up);
    /// the MOTD text is rendered inert (ANSI stripped) regardless.
    PublicSpaceSnapshot {
        motd: Option<String>,
        posts: Vec<PublicPostRow>,
    },
    /// A `RefreshPublicSpace` command could not complete (no live session, a
    /// refused RPC, or a malformed signer whitelist). Surfaced on the status
    /// line; any previously-shown snapshot is left in place.
    PublicSpaceError { message: String },
    /// A fresh deprecation-policy snapshot (ISC-C25). `warnings` carries one row
    /// per in-use suite the verified policy schedules for retirement (empty when
    /// no in-use suite is affected); `policy_version` is the accepted monotonic
    /// version (`None` when the relay serves no policy); `had_policy` is `true`
    /// only when a verified policy was actually served, distinguishing
    /// "no policy configured" from "policy served but nothing in use affected".
    DeprecationSnapshot {
        policy_version: Option<u64>,
        warnings: Vec<DeprecationWarningRow>,
        had_policy: bool,
    },
    /// A `RefreshDeprecation` command could not complete (no live session, a
    /// refused RPC, a rollback/withdrawal, a signature/verification failure, or
    /// a missing/short pinned key). Surfaced on the status line; the cached
    /// warning rows are deliberately left in place (a rollback must not blank
    /// the state the anti-rollback check protects). The matching trust event
    /// (`ServerDeprecationPolicyRollback` / `ServerDeprecationPolicyUnreadable`)
    /// arrives separately as a [`NetEvent::TrustEvent`].
    DeprecationError { message: String },
    /// A1 fetch preview: the share's manifest arrived. Carries the file list
    /// (names + sizes) for the user to review before any chunk is downloaded.
    /// The stream is already closed; the user confirms via `NetCommand::
    /// ConfirmFetch`, which re-opens it. `name` is the listing name (echoed so
    /// the confirm round-trip can label the persisted download).
    FetchManifest {
        share_id: String,
        name: String,
        entries: Vec<ShareManifestEntry>,
    },
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
    /// A fresh snapshot of the fetched shares recorded on disk (M15 C;
    /// ISC-C64). Emitted after a successful fetch persists, and in response to
    /// `NetCommand::ListFetched`. Replaces the browse pane's list wholesale.
    FetchedShares { shares: Vec<FetchedShare> },
    /// A fresh introducer-discovery snapshot for the Servers pane (M12 gate
    /// step 6, ISC-C22 / ISC-S6 / ISC-A-C19). `candidates` is the full current
    /// set of introducer-learned peers that are NOT already in the active trust
    /// set, each as a `(server_id, address)` pair. Server-id + address ONLY —
    /// the introducer response carries no key material (ISC-S6), so neither
    /// does this event. Folded into App state wholesale (it replaces the cached
    /// list, mirroring the idempotent merge); the render surfaces it read-only,
    /// and promotion to the trust set stays an explicit user action (ISC-A-C19).
    /// An empty `candidates` is a normal state (nothing new discovered).
    IntroducerSnapshot {
        /// Discovered candidate peers as `(server_id, address)` pairs. No keys.
        candidates: Vec<(String, String)>,
    },
    /// A `RefreshIntroducer` command could not complete (no live session, or a
    /// refused `Introduce` RPC). Surfaced on the status line; the cached
    /// candidate list is left in place so a transient failure never blanks the
    /// last-known discovery state (mirrors the deprecation-error precedent).
    IntroducerError { message: String },
    /// A share began publishing and is now being served (D, M15). `share_id` is
    /// the server-assigned id; `file_count` mirrors the indexed manifest. The
    /// share stays served until `UnpublishShare`, the session drops, or the relay
    /// reaps the asset — then `PublishStopped` arrives.
    PublishStarted {
        share_id: String,
        name: String,
        file_count: usize,
    },
    /// Publishing a share failed (no session, no server-id, an unreadable path,
    /// or a refused `PublishShare` RPC). Surfaced on the status line.
    PublishError { message: String },
    /// A published share stopped being served (D, M15): the user unpublished it,
    /// the serve stream ended (peer/relay closed), or the session dropped.
    PublishStopped { share_id: String },
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

/// One live circle a member is subscribed to (ISC-C59): the outbound frame
/// sender (to publish sealed messages) plus the key + rendezvous address, the
/// stable per-session id the app keys membership/attribution on, and the
/// client-local display label (ISC-C62, never transmitted).
///
/// A member can hold several of these at once ([`Actor::circles`]); each carries
/// its own `cot_key`, so a post seals under exactly the active circle's key and
/// an inbound frame is attributed to the single circle whose key opened it
/// (ISC-A-C30 — no cross-circle key or attribution mixing).
struct Circle {
    /// Stable per-session id, assigned monotonically at join. Threaded into the
    /// inbound reader so every emitted [`NetEvent::ChatMessage`] names its source
    /// circle, and used by [`NetCommand::SendChat`] to pick the seal key.
    id: u64,
    /// Client-local display label (ISC-C62). Generated at join (adj-noun default,
    /// `#<hex>` floor); never transmitted, never derived from other members.
    label: String,
    cot_key: Rc<CotKey>,
    asset_addr: AssetAddr,
    out_tx: mpsc::Sender<wire::CotFrame>,
}

/// The live public room a daemon is subscribed to (ISC-S22..S26 / ISC-C56).
/// Mirrors [`Circle`] but keyed by the *global* room key (server-readable) and
/// posting is self-signed for provenance under the daemon's own identity.
struct PublicRoom {
    /// The room name (e.g. "lobby"), bound into each message's provenance
    /// signature so it cannot be replayed into another room (ISC-S24).
    room: String,
    /// The global shared room key — derived from public inputs, so every
    /// client and the relay hold it (ISC-S22). Reused for AEAD seal/open.
    room_key: Rc<CotKey>,
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
    /// The set of circles the member is currently joined to (ISC-C59). Joining
    /// ADDS a circle; it never evicts an existing one. Each holds its own key, so
    /// sealing/attribution stays per-circle (ISC-A-C30). Held as a `Vec` — a
    /// serialization-shaped list so circle-membership persistence is a later
    /// additive change to the at-rest blob, not a refactor (ISC-C59) — though it
    /// is NOT persisted now (session-only).
    circles: Vec<Circle>,
    /// Monotonic counter handing out the next circle id at join. Never reused
    /// within a session, so an id always names the same circle.
    next_circle_id: u64,
    /// The daemon's own client identity, retained after connect so public-room
    /// posts can be self-signed for provenance (ISC-S24) under the same key that
    /// proved the connection. `None` until a connect succeeds.
    identity: Option<ClientIdentity>,
    /// The auto-joined default public room, if subscribed (ISC-S22 / ISC-C56).
    /// The default chat surface needs no circle; circles are the private opt-in.
    public_room: Option<PublicRoom>,
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
    /// The connected relay's pinned server-wide public key (ISC-A-S11),
    /// captured from [`daemonseed_cli::connect::ConnectOutcome`] at connect.
    /// This is the TOFU-pinned key `apply_trust` already accepted, so verifying
    /// the deprecation policy against it trusts nothing the relay newly asserts.
    /// `None` until a connect succeeds; a deprecation refresh without it fails
    /// closed (an unverifiable policy is never accepted, ISC-C25).
    server_pubkey: Option<Vec<u8>>,
    /// Per-server deprecation-policy cache (ISC-C25 / ISC-A-S11): tracks the
    /// highest accepted `policy_version` for anti-rollback and the fetch time
    /// for the one-hour TTL. Anti-rollback "just works" by feeding
    /// [`PolicyCache::cached_version`] into [`verify_policy`].
    policy_cache: PolicyCache,
    /// RAM-only cache of introducer-discovered candidate peers (M12 gate step 6,
    /// ISC-C22 / ISC-S6 / ISC-A-C19). Refreshed by [`Actor::handle_refresh_introducer`]
    /// and surfaced read-only in the Servers pane. Deliberately distinct from the
    /// active trust set: nothing here is trusted or connectable until the user
    /// promotes it — discovery NEVER writes the trust set.
    discovered: DiscoveredPeers,
    /// Active publish serve-tasks keyed by the server-assigned `share_id` (D,
    /// M15). Each value is the `spawn_local` handle for that share's
    /// `serve_share` loop; `UnpublishShare` aborts it. Empty until the user
    /// publishes; a task that ends on its own leaves a harmless completed entry.
    published: HashMap<String, tokio::task::JoinHandle<()>>,
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
        circles: Vec::new(),
        next_circle_id: 0,
        identity: None,
        public_room: None,
        backoff: Backoff::new(),
        share_index: None,
        server_pubkey: None,
        policy_cache: PolicyCache::new(),
        discovered: DiscoveredPeers::new(),
        published: HashMap::new(),
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
                circle_id,
                body,
                sender_handle,
            } => {
                actor
                    .handle_send_chat(circle_id, &body, &sender_handle)
                    .await
            }
            NetCommand::SendPublicRoom {
                body,
                sender_handle,
            } => actor.handle_send_public_room(&body, &sender_handle).await,
            NetCommand::DefineShare {
                root,
                label,
                index_path,
                index_key,
            } => {
                actor
                    .handle_define_share(root, label, index_path, index_key)
                    .await
            }
            NetCommand::RefreshShares => actor.handle_refresh_shares().await,
            NetCommand::RefreshPublicSpace => actor.handle_refresh_public_space().await,
            NetCommand::RefreshDeprecation => actor.handle_refresh_deprecation().await,
            NetCommand::FetchShare {
                share_id,
                sharer_handle,
                name,
                fetched_root,
            } => {
                actor
                    .handle_fetch_share(&share_id, &sharer_handle, &name, fetched_root)
                    .await
            }
            NetCommand::ConfirmFetch {
                share_id,
                sharer_handle,
                name,
                fetched_root,
                selected,
            } => {
                actor
                    .handle_confirm_fetch(&share_id, &sharer_handle, &name, fetched_root, selected)
                    .await
            }
            NetCommand::ListFetched { fetched_root } => actor.handle_list_fetched(fetched_root),
            NetCommand::RefreshIntroducer => actor.handle_refresh_introducer().await,
            NetCommand::PublishShare {
                root,
                name,
                sharer_handle,
            } => actor.handle_publish_share(root, name, sharer_handle).await,
            NetCommand::UnpublishShare { share_id } => {
                actor.handle_unpublish_share(&share_id).await
            }
        }
    }
}

impl Actor {
    fn emit(&self, evt: NetEvent) {
        let _ = self.evt_tx.send(evt);
    }

    /// Publish a defined share and serve its content for the life of the session
    /// (D, M15). See [`NetCommand::PublishShare`]. The session is cloned up front
    /// (cheap — the tonic channel is `Arc`-backed) so no borrow of `self` is held
    /// across the `&mut self` bookkeeping at the end.
    async fn handle_publish_share(&mut self, root: PathBuf, name: String, sharer_handle: String) {
        let session = match self.session.as_ref() {
            Some(s) => s.clone(),
            None => {
                return self.emit(NetEvent::PublishError {
                    message: "not connected to a relay yet".to_owned(),
                });
            }
        };
        let Some(server_id) = self.server_id.clone() else {
            return self.emit(NetEvent::PublishError {
                message: "no server-id for the connected relay".to_owned(),
            });
        };
        // Index BEFORE publishing so a bad path fails fast and the listing is
        // never advertised for content we cannot serve (mirrors the CLI).
        let content = match ShareContent::index_dir(&root) {
            Ok(c) => c,
            Err(e) => {
                return self.emit(NetEvent::PublishError {
                    message: format!("could not index {}: {e}", root.display()),
                });
            }
        };
        let file_count = content.file_count();
        // listing.share_id is ignored — the server assigns it (F25).
        let resp = session
            .public_space()
            .publish_share(wire::PublishShareRequest {
                listing: Some(wire::PublicShareListing {
                    share_id: String::new(),
                    name: name.clone(),
                    rating: String::new(),
                    // The publisher's display handle so peers see who shared it
                    // instead of "(operator)" (M15 — completes the #6 handle
                    // passthrough on the publish side).
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
        // Serve concurrently for the life of the session via `spawn_local` (like
        // the circle inbound readers). `serve_share` ends (Ok) when the relay
        // reaps the asset or the peer leaves; an explicit `UnpublishShare` aborts
        // the task before then. On a natural end we emit `PublishStopped`; on an
        // abort the future is dropped before that line runs, so unpublish's own
        // `PublishStopped` is the single notification.
        let evt_tx = self.evt_tx.clone();
        let task_share_id = share_id.clone();
        let handle = tokio::task::spawn_local(async move {
            let _ = session
                .serve_share(&server_id, &task_share_id, &content)
                .await;
            let _ = evt_tx.send(NetEvent::PublishStopped {
                share_id: task_share_id,
            });
        });
        self.published.insert(share_id.clone(), handle);
        self.emit(NetEvent::PublishStarted {
            share_id,
            name,
            file_count,
        });
    }

    /// Unpublish a share published this session and stop serving it (D, M15).
    /// See [`NetCommand::UnpublishShare`]. Owner-scoped server-side (ISC-A-S1):
    /// the relay honours it only on the publishing connection, which is this
    /// long-lived actor.
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
                    // Capture the TOFU-pinned server-wide key for client-side
                    // deprecation-policy verification (ISC-C25 / ISC-A-S11).
                    self.server_pubkey = Some(outcome.server_pubkey.clone());
                    // Retain the identity for public-room provenance signing
                    // (ISC-S24): the same key that proved this connection signs
                    // its public-room posts.
                    self.identity = Some(identity);
                    self.backoff.reset();
                    // The default chat surface is a public room (ISC-S22 /
                    // ISC-C56): auto-join it on connect so chatting needs no
                    // circle. A failure here is non-fatal — it surfaces as a
                    // room-join failure; the connection itself is up.
                    self.join_default_public_room().await;
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
    /// relay, and spawn the inbound chat reader (ISC-15/16 / ISC-C59).
    ///
    /// Joining ADDS to the membership set; it never evicts a currently-joined
    /// circle (ISC-C59). A circle whose rendezvous address is already present is
    /// a no-op idempotent re-join (re-emitting `CircleJoined` for the existing id
    /// so the app can re-select it active) — the same shared phrase derives the
    /// same `cot_key` and therefore the same `asset_addr`, so address-equality is
    /// the dedupe key.
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

        // Idempotent join (ISC-C59): a circle already in the set is not
        // re-subscribed — re-emit its existing id + label so the app re-selects
        // it active. This never evicts or duplicates the existing membership.
        if let Some(existing) = self.circles.iter().find(|c| c.asset_addr == asset_addr) {
            return self.emit(NetEvent::CircleJoined {
                circle_id: existing.id,
                label: existing.label.clone(),
                // The phrase the actor processed is the persisted seed (M13):
                // re-sending it re-derives the same `cot_key` (ISC-C59).
                entropy: phrase.to_owned(),
            });
        }

        // Assign a stable id and a deterministic client-local label (ISC-C62):
        // derived from the rendezvous address so the same circle gets the same
        // default label, never from other members and never transmitted.
        let circle_id = self.next_circle_id;
        self.next_circle_id += 1;
        let label = default_circle_label(&asset_addr);

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

        // Inbound reader: decrypt each frame under THIS circle's key and emit a
        // ChatMessage tagged with this circle's id (ISC-A-C30 attribution — a
        // frame is attributed to the single circle whose key opened it). Foreign
        // / undecryptable frames are skipped silently (noise on a shared
        // rendezvous). Runs until the stream ends.
        let reader_key = Rc::clone(&cot_key);
        let reader_tx = self.evt_tx.clone();
        tokio::task::spawn_local(read_inbound(inbound, circle_id, reader_key, reader_tx));

        self.circles.push(Circle {
            id: circle_id,
            label: label.clone(),
            cot_key,
            asset_addr,
            out_tx,
        });
        self.emit(NetEvent::CircleJoined {
            circle_id,
            label,
            // The phrase the actor processed is the persisted seed (M13):
            // re-sending it re-derives the same `cot_key` (ISC-C59).
            entropy: phrase.to_owned(),
        });
    }

    /// Subscribe to the well-known default public room (ISC-S22 / ISC-C56) so the
    /// default chat surface flows without any circle. Reuses the SAME
    /// `CircleOfTrust.Subscribe` relay (ISC-S23) — only the key (global,
    /// server-readable) and posting auth (self-signed, ISC-S24) differ.
    async fn join_default_public_room(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::PublicRoomJoinFailed {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let Some(server_id) = self.server_id.as_ref() else {
            return self.emit(NetEvent::PublicRoomJoinFailed {
                message: "no server-id for the connected relay".to_owned(),
            });
        };

        // The room key is GLOBAL: derived from public inputs, identical for every
        // client and the relay (ISC-S22). Reused as the AEAD key for seal/open.
        let room = DEFAULT_ROOM.to_owned();
        let room_key = match derive_room_key(&room, &CNSA_2_0) {
            Ok(k) => Rc::new(k),
            Err(e) => {
                return self.emit(NetEvent::PublicRoomJoinFailed {
                    message: format!("public-room key derivation failed: {e}"),
                });
            }
        };
        let asset_addr = match room_asset_address(&room_key, server_id.as_bytes()) {
            Ok(a) => a,
            Err(e) => {
                return self.emit(NetEvent::PublicRoomJoinFailed {
                    message: format!("public-room rendezvous derivation failed: {e}"),
                });
            }
        };

        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        if out_tx.send(naming).await.is_err() {
            return self.emit(NetEvent::PublicRoomJoinFailed {
                message: "public-room subscribe channel closed".to_owned(),
            });
        }

        let mut cot = session.circle_of_trust();
        let inbound = match cot.subscribe(ReceiverStream::new(out_rx)).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::PublicRoomJoinFailed {
                    message: format!("public-room subscribe refused: {}", status.message()),
                });
            }
        };

        // Inbound reader: open + VERIFY each frame under the global room key
        // (ISC-S25 / ISC-C57). Unverifiable / forged-provenance frames are
        // dropped silently (ISC-A-S17). Runs until the stream ends.
        let reader_key = Rc::clone(&room_key);
        let reader_tx = self.evt_tx.clone();
        tokio::task::spawn_local(read_inbound_public_room(inbound, reader_key, reader_tx));

        self.public_room = Some(PublicRoom {
            room,
            room_key,
            asset_addr,
            out_tx,
        });
        self.emit(NetEvent::PublicRoomJoined {
            room: DEFAULT_ROOM.to_owned(),
        });
    }

    /// Post a message to the joined public room (ISC-S22 / ISC-S24). The message
    /// is self-signed for provenance under the daemon's own identity, then sealed
    /// under the global room key. Any daemon may post — the signature establishes
    /// authorship, not authorization.
    async fn handle_send_public_room(&mut self, body: &str, sender_handle: &str) {
        let Some(room) = self.public_room.as_ref() else {
            return self.emit(NetEvent::ChatError {
                message: "no public room joined".to_owned(),
            });
        };
        let Some(identity) = self.identity.as_ref() else {
            return self.emit(NetEvent::ChatError {
                message: "no identity to sign the post".to_owned(),
            });
        };

        // Seal under the poster's display handle (name#hash) so peers render the
        // name, not the floor — `identity.handle()` is the bare floor handle
        // (built `from_pubkey(None, ..)`); the app supplies the name-bearing one.
        let sealed = match seal_room_message(
            &room.room_key,
            identity.signing(),
            &room.room,
            sender_handle,
            body,
            now_unix_ms(),
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.emit(NetEvent::ChatError {
                    message: format!("public-room seal/sign failed: {e}"),
                });
            }
        };
        let frame = wire::CotFrame {
            asset_address: room.asset_addr.as_bytes().to_vec(),
            payload: sealed,
        };
        if room.out_tx.send(frame).await.is_err() {
            self.emit(NetEvent::ChatError {
                message: "public-room stream closed; reconnect to post".to_owned(),
            });
        }
    }

    /// Define (activate) a local share root (M14, ISC-C21 / ISC-A-C7).
    ///
    /// Opens (create-if-absent) the redb [`ShareIndex`] at `index_path` under
    /// `index_key` — the share-index key derived once as a sibling of the
    /// at-rest key, never re-derived here — retains it for foreground queries,
    /// then runs the cold scan of `root` on a dedicated blocking thread. The
    /// actor returns to its command loop immediately (the walk never parks it),
    /// and the same index stays fully queryable from the foreground during the
    /// scan (redb MVCC — ISC-A-C7 no-startup-blockade / no-fate-sharing). The
    /// scan thread emits the terminal [`NetEvent::IndexerStatus`]; the app pulls
    /// the freshly-indexed rows via a follow-up `RefreshShares`.
    ///
    /// MVP scope: a single active share index — the latest `DefineShare` wins.
    /// Multi-root concurrent indexing (one index per root) is a documented
    /// follow-up; `_label` is reserved for that surface and the at-rest
    /// `share` directive (D3) rather than consumed here.
    async fn handle_define_share(
        &mut self,
        root: PathBuf,
        _label: Option<String>,
        index_path: PathBuf,
        index_key: IndexKey,
    ) {
        // Open off the actor thread — redb's file-create + table-materialize is
        // blocking I/O. Quick, but offloaded so the async loop does no sync disk.
        let key_bytes = index_key.to_bytes();
        let opened = tokio::task::spawn_blocking(move || ShareIndex::open(&index_path, key_bytes))
            .await
            .expect("share-index open task panicked");
        let index = match opened {
            Ok(index) => Arc::new(index),
            Err(e) => {
                self.emit(NetEvent::ShareDefineFailed {
                    message: format!("could not open share index: {e}"),
                });
                return;
            }
        };
        // Retain for foreground queries immediately — queryable during the scan
        // via redb MVCC (ISC-A-C7).
        self.share_index = Some(Arc::clone(&index));
        self.emit(NetEvent::IndexerStatus(IndexerStatus::Indexing {
            seen: 0,
            total: None,
        }));

        // Cold scan on a dedicated blocking thread, writing to the same index
        // the foreground reads (redb MVCC). Detached: the actor resumes its
        // command loop at once; the thread reports the terminal status itself.
        let evt_tx = self.evt_tx.clone();
        tokio::task::spawn_blocking(move || {
            let status = match scan_into(&index, &root) {
                Ok(count) => IndexerStatus::Ready {
                    entries: count as u64,
                },
                // A scan error leaves the retained index in place; report Idle so
                // the status line stops showing an indefinite "indexing".
                Err(_) => IndexerStatus::Idle,
            };
            let _ = evt_tx.send(NetEvent::IndexerStatus(status));
        });
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

    /// Fetch the connected relay's public space — MOTD, announcement posts, and
    /// the published signer whitelist — and emit a single
    /// [`NetEvent::PublicSpaceSnapshot`] (ISC-25 / ISC-S7 / ISC-A-S3).
    ///
    /// Provenance is established client-side, trusting nothing the relay
    /// asserts: the signer whitelist is fetched first, then each post is
    /// re-verified against it with [`verify_served_post`] (signature + content
    /// address). The verdict travels in [`PublicPostRow::verified`] so the
    /// render layer can flag an unverifiable post rather than present it as
    /// authentic. The MOTD is rendered inert ([`render_motd`] strips terminal
    /// control sequences, ISC-25); its *signature* is not re-checked here
    /// because that needs the server's full pubkey, which the connect outcome
    /// does not yet carry (tracked follow-up).
    async fn handle_refresh_public_space(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::PublicSpaceError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let mut ps = session.public_space();

        // Whitelist first — post provenance verification depends on it.
        let whitelist = match ps
            .get_signer_whitelist(wire::GetSignerWhitelistRequest {})
            .await
        {
            Ok(resp) => match whitelist_from_wire(&resp.into_inner().entries, None) {
                Ok(wl) => wl,
                Err(e) => {
                    return self.emit(NetEvent::PublicSpaceError {
                        message: format!("malformed signer whitelist: {e:?}"),
                    });
                }
            },
            Err(status) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("signer-whitelist fetch refused: {}", status.message()),
                });
            }
        };

        // MOTD — rendered inert (ANSI stripped); absent is a normal state.
        let motd = match ps.get_motd(wire::GetMotdRequest {}).await {
            Ok(resp) => resp.into_inner().motd.as_ref().map(render_motd),
            Err(status) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("MOTD fetch refused: {}", status.message()),
                });
            }
        };

        // Posts — each re-verified against the whitelist (ISC-A-S3 client half).
        let posts = match ps.list_posts(wire::ListPostsRequest { topic: None }).await {
            Ok(resp) => resp
                .into_inner()
                .posts
                .iter()
                .map(|p| {
                    let verified = verify_served_post(p, &whitelist).is_ok();
                    let (topic, body, sent_unix_ms) = post_render_fields(p);
                    PublicPostRow {
                        topic,
                        body,
                        verified,
                        sent_unix_ms,
                    }
                })
                .collect(),
            Err(status) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("posts fetch refused: {}", status.message()),
                });
            }
        };

        self.emit(NetEvent::PublicSpaceSnapshot { motd, posts });
    }

    /// Fetch, verify, and surface the connected relay's signed suite-deprecation
    /// policy (ISC-C25 / ISC-A-S11 / ISC-C28).
    ///
    /// The decision logic — `None`-handling, signature + rollback verification,
    /// and version-gated trust-event emission — lives in the pure
    /// [`decide_deprecation`] so every branch is unit-testable without a live
    /// session. This method does only the I/O: read the cached version, fetch
    /// the RPC, then apply the decision's cache write and emits. The policy is
    /// verified against [`Self::server_pubkey`] — the TOFU-pinned key the connect
    /// path already accepted — so verification trusts nothing the relay newly
    /// asserts.
    async fn handle_refresh_deprecation(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::DeprecationError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let Some(server_id) = self.server_id.clone() else {
            return self.emit(NetEvent::DeprecationError {
                message: "no server-id for the connected relay".to_owned(),
            });
        };
        let server_pubkey = self.server_pubkey.clone();
        let now = now_unix_ms();
        let prev_version = self.policy_cache.cached_version(&server_id);

        let mut ps = session.public_space();
        let artifact = match ps
            .get_deprecation_policy(wire::GetDeprecationPolicyRequest {})
            .await
        {
            Ok(resp) => resp.into_inner().policy,
            Err(status) => {
                return self.emit(NetEvent::DeprecationError {
                    message: format!("deprecation-policy fetch refused: {}", status.message()),
                });
            }
        };

        let decision = decide_deprecation(
            prev_version,
            artifact.as_ref(),
            server_pubkey.as_deref(),
            &[CNSA_2_0.id],
            now,
        );

        // Persist the accepted policy so the next fetch's anti-rollback baseline
        // and TTL are correct (ISC-C25). Done before emitting so an observer
        // draining events sees a consistent cache.
        if let Some(policy) = decision.cache_policy {
            self.policy_cache.insert(&server_id, policy, now);
        }
        // Trust events first (ISC-C28 taxonomy routing), each scoped to this
        // server for per-(key, server) dismissal (ISC-A-C12).
        for key in decision.trust_keys {
            self.emit(NetEvent::TrustEvent {
                key,
                server_id: Some(server_id.clone()),
            });
        }
        if let Some(snapshot) = decision.snapshot {
            self.emit(NetEvent::DeprecationSnapshot {
                policy_version: snapshot.policy_version,
                warnings: snapshot.warnings,
                had_policy: snapshot.had_policy,
            });
        }
        if let Some(message) = decision.error {
            self.emit(NetEvent::DeprecationError { message });
        }
    }

    /// Refresh the introducer-discovered candidate peers and emit a single
    /// [`NetEvent::IntroducerSnapshot`] (M12 gate step 6, ISC-C22 / ISC-S6 /
    /// ISC-A-C19).
    ///
    /// Requires a live session — without one there is no relay to ask, so this
    /// emits [`NetEvent::IntroducerError`] (mirroring the deprecation / public-
    /// space "not connected yet" path). With a session, it asks the connected
    /// relay's `FederationIntroducer` over [`AppSession::refresh_introducer`]
    /// and merges the answer into [`Self::discovered`], then reads the resulting
    /// candidates back out for the render.
    ///
    /// Precautionary by construction (ISC-A-C19): the `known` trust store handed
    /// to the merge is an empty [`InMemoryTrustStore`] — it is only *read* to
    /// skip already-configured servers, never written, and the merge itself
    /// never touches the trust set (it records candidates only). An empty
    /// `known` simply means no candidate is suppressed as "already trusted"; it
    /// cannot cause discovery to trust anything. The snapshot carries the
    /// server-id and address ONLY: the introducer response has no key field
    /// (ISC-S6), so no key material can ever flow through this path.
    async fn handle_refresh_introducer(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::IntroducerError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        // `known` is read-only here (skip already-configured servers) and is
        // never written; an empty store is correct — discovery trusts nothing.
        let known = InMemoryTrustStore::new();
        match session
            .refresh_introducer(&mut self.discovered, &known)
            .await
        {
            Ok(_outcome) => {
                // Read the full candidate set back out as (server_id, address)
                // pairs — no keys (ISC-S6). The per-merge tally is intentionally
                // dropped: the snapshot is the converged candidate list, not the
                // delta, so a repeated refresh renders the same stable view.
                let candidates = self
                    .discovered
                    .iter()
                    .map(|peer| (peer.server_id.to_string(), peer.address.clone()))
                    .collect();
                self.emit(NetEvent::IntroducerSnapshot { candidates });
            }
            Err(status) => self.emit(NetEvent::IntroducerError {
                message: format!("introducer refresh refused: {}", status.message()),
            }),
        }
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
    /// Open a share-fetch stream and read its manifest — the shared front half
    /// of the A1 preview ([`Self::handle_fetch_share`]) and the confirmed
    /// download ([`Self::handle_confirm_fetch`]). Does the pre-flight (live
    /// session + known relay), opens a fresh `CircleOfTrust.Subscribe` stream,
    /// sends a `ManifestRequest`, and reads the `ManifestResponse`. On any
    /// failure it emits `NetEvent::FetchError` and returns `None`; the caller
    /// then simply returns.
    async fn open_share_stream(&mut self, share_id: &str) -> Option<OpenedShare> {
        // Pre-flight: live session + known relay are mandatory.
        let Some(session) = self.session.as_ref() else {
            self.emit(NetEvent::FetchError {
                message: "not connected to a relay yet".to_owned(),
            });
            return None;
        };
        let Some(server_id) = self.server_id.as_ref() else {
            self.emit(NetEvent::FetchError {
                message: "no server-id for the connected relay".to_owned(),
            });
            return None;
        };

        let asset_addr = match public_share_asset_address(share_id.as_bytes(), server_id.as_bytes())
        {
            Ok(a) => a,
            Err(e) => {
                self.emit(NetEvent::FetchError {
                    message: format!("share-asset derivation failed: {e}"),
                });
                return None;
            }
        };

        // The outbound half: a tokio mpsc the actor publishes to; the bidi
        // Subscribe stream reads from it. Capacity sized for the small set of
        // round-trip request frames a fetch generates (manifest + chunks);
        // ChunkResponse arrivals do not back-pressure this channel.
        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);

        // The naming frame: every Subscribe stream's first frame names its
        // rendezvous (empty payload, not relayed); same shape as the chat
        // path. Send it before subscribe consumes the receiver.
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        if out_tx.send(naming).await.is_err() {
            self.emit(NetEvent::FetchError {
                message: "fetch subscribe channel closed before naming frame".to_owned(),
            });
            return None;
        }

        let mut cot = session.circle_of_trust();
        let mut inbound = match cot.subscribe(ReceiverStream::new(out_rx)).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                self.emit(NetEvent::FetchError {
                    message: format!("subscribe refused: {}", status.message()),
                });
                return None;
            }
        };

        // Send ManifestRequest. The first non-empty inbound frame on this
        // stream is expected to be the ManifestResponse from the sharer.
        let request = ShareFrame::ManifestRequest;
        let req_frame = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: request.encode(),
        };
        if out_tx.send(req_frame).await.is_err() {
            self.emit(NetEvent::FetchError {
                message: "fetch subscribe channel closed before manifest request".to_owned(),
            });
            return None;
        }

        // Read the manifest. Foreign / undecryptable frames (other members'
        // chatter, the sharer's naming frame echoing back if any) are skipped
        // silently — same posture as chat. The first valid ManifestResponse
        // wins.
        let manifest = loop {
            let frame = match inbound.message().await {
                Ok(Some(f)) => f,
                Ok(None) | Err(_) => {
                    self.emit(NetEvent::FetchError {
                        message: "stream ended before manifest arrived".to_owned(),
                    });
                    return None;
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

        Some(OpenedShare {
            out_tx,
            inbound,
            asset_addr,
            manifest,
        })
    }

    /// A1 fetch preview: open the share, read its manifest, surface it as
    /// `NetEvent::FetchManifest` (file names + sizes), then CLOSE the stream.
    /// Nothing is pulled or written here — the user reviews the contents and
    /// confirms, and the download is a separate `NetCommand::ConfirmFetch` that
    /// re-opens the stream. Dropping the stream keeps the actor stateless (no
    /// parked fetch) and never pins a relay subscription during think-time.
    async fn handle_fetch_share(
        &mut self,
        share_id: &str,
        _sharer_handle: &str,
        name: &str,
        _fetched_root: PathBuf,
    ) {
        let Some(opened) = self.open_share_stream(share_id).await else {
            return;
        };
        let entries = opened
            .manifest
            .iter()
            .map(|e| ShareManifestEntry {
                rel_path: e.rel_path.clone(),
                size: e.size,
            })
            .collect();
        drop(opened); // close the stream; confirm re-opens
        self.emit(NetEvent::FetchManifest {
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            entries,
        });
    }

    /// A1 confirm: the user accepted the preview. Re-open the share, request the
    /// selected chunks (`selected = None` downloads every file; `Some(indices)`
    /// the A2 selective subset), verify each against its content address
    /// (ISC-S28 / ISC-A-S20), and persist the fully-verified download (ISC-C63
    /// / A-C31). `selected` indices are into the manifest's natural order, which
    /// a sharer serves deterministically; an out-of-range index is skipped
    /// defensively rather than failing the whole fetch.
    async fn handle_confirm_fetch(
        &mut self,
        share_id: &str,
        _sharer_handle: &str,
        name: &str,
        fetched_root: PathBuf,
        selected: Option<Vec<usize>>,
    ) {
        let Some(opened) = self.open_share_stream(share_id).await else {
            return;
        };
        let OpenedShare {
            out_tx,
            mut inbound,
            asset_addr,
            manifest,
        } = opened;

        // Resolve the chunk set: an explicit selection (A2) or the whole
        // manifest (A1 confirm-all). Indices map onto the manifest's order;
        // an out-of-range index is dropped (filter_map) rather than aborting.
        let wanted: Vec<&ManifestEntry> = match &selected {
            Some(idxs) => idxs.iter().filter_map(|&i| manifest.get(i)).collect(),
            None => manifest.iter().collect(),
        };

        let total_chunks = wanted.len() as u32;
        self.emit(NetEvent::FetchProgress {
            total_chunks: Some(total_chunks),
            chunks_received: 0,
            bytes_received: 0,
        });

        // For each wanted entry, request the chunk by its advertised address,
        // verify the response, and account bytes. A single-chunk-per-file
        // alpha: one request per file, one response per request, sequential
        // (pipelining is a post-MVP optimisation).
        let mut chunks_received: u32 = 0;
        let mut bytes_received: u64 = 0;
        // Accumulate each file's verified plaintext bytes; persisted to the
        // on-disk fetched store only after the whole fetch verifies (ISC-A-C31
        // — a fetch that fails mid-stream returns early and persists nothing).
        let mut fetched_files: Vec<VerifiedFile> = Vec::with_capacity(wanted.len());
        for entry in &wanted {
            let request = ShareFrame::ChunkRequest {
                chunk_addr: entry.chunk_addr,
            };
            let req_frame = wire::CotFrame {
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

            // The verified bytes are accumulated for persistence below; the
            // verification gate above (ISC-S28 / ISC-A-S20) is the load-bearing
            // security contract, persistence is bookkeeping above it. Bytes
            // are kept in RAM until the whole fetch verifies, then written
            // once as an explicit download (M15 C; ISC-C63).
            chunks_received += 1;
            bytes_received += chunk_data.1.len() as u64;
            fetched_files.push(VerifiedFile {
                rel_path: entry.rel_path.clone(),
                bytes: chunk_data.1,
            });
            self.emit(NetEvent::FetchProgress {
                total_chunks: Some(total_chunks),
                chunks_received,
                bytes_received,
            });
        }

        // Close the subscribe stream first — the network half of the fetch is
        // done and the relay can reap once both stream halves are gone
        // (refcount → 0); persistence is a local-disk step that needs no
        // connection.
        drop(out_tx);

        // Persist the fully-verified download (M15 C; ISC-C63 / C64). Only a
        // fetch that verified every chunk reaches here, so a poisoned or
        // truncated download is never recorded (ISC-A-C31). A persistence
        // failure surfaces as a fetch error — the user must not believe a
        // download landed when it did not.
        match FetchedStore::open(&fetched_root)
            .and_then(|mut store| store.record_share(share_id, name, &fetched_files))
        {
            Ok(_) => {}
            Err(e) => {
                return self.emit(NetEvent::FetchError {
                    message: format!("verified but could not save download: {e}"),
                });
            }
        }

        self.emit(NetEvent::FetchComplete {
            share_id: share_id.to_owned(),
            files_written: chunks_received,
            bytes_written: bytes_received,
        });
        // Refresh the browse pane with the newly-persisted download.
        self.handle_list_fetched(fetched_root);
    }

    /// List the fetched shares recorded under `fetched_root` and emit them as a
    /// [`NetEvent::FetchedShares`] snapshot for the browse pane (M15 C;
    /// ISC-C64). A transient/corrupt read leaves the pane's last-known list in
    /// place (no event), mirroring the introducer-refresh precedent.
    fn handle_list_fetched(&self, fetched_root: PathBuf) {
        match FetchedStore::open(&fetched_root).and_then(|s| s.list_shares()) {
            Ok(shares) => self.emit(NetEvent::FetchedShares { shares }),
            Err(_e) => {}
        }
    }

    /// Seal a chat message under the *active* circle's key and publish it
    /// (ISC-14 / ISC-C60 / ISC-A-C30). The post is sealed under exactly the
    /// circle named by `circle_id` — the app's active circle — never another's,
    /// so cycling the carousel changes the seal key and never the wrong-circle
    /// post that ISC-A-C30 forbids. An unknown id (the circle was dropped, or the
    /// app's active selection went stale) is a clean ChatError, not a panic.
    async fn handle_send_chat(&mut self, circle_id: u64, body: &str, sender_handle: &str) {
        let Some(circle) = self.circles.iter().find(|c| c.id == circle_id) else {
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

/// Read one circle's inbound frame stream, decrypt each under THAT circle's key,
/// and emit a [`NetEvent::ChatMessage`] tagged with `circle_id` (ISC-A-C30
/// attribution: a frame is attributed to the single circle whose key opened it,
/// never guessed nor broadcast). Each joined circle (ISC-C59) gets its own reader
/// task with its own `cot_key` and `circle_id`, so a frame that only this key can
/// open can only ever be emitted under this circle's id. Undecryptable frames
/// (foreign noise on the shared rendezvous, or a tampered frame) are skipped
/// silently. Returns when the stream ends (the relay closed it or the session
/// dropped).
async fn read_inbound(
    mut inbound: tonic::Streaming<wire::CotFrame>,
    circle_id: u64,
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
                            circle_id,
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

/// Build the default client-local label for a newly-joined circle (ISC-C62),
/// deterministically from its rendezvous address. The address is itself a
/// `SHA-384(cot_key ‖ server_id)` (ISC-S20), so a given circle on a given relay
/// always yields the same default label — convenient for recognising a re-join —
/// while the label never leaves the client and is never derived from members.
///
/// An `adj-noun` pair indexed by the address bytes is the default; the `#<hex>`
/// floor is the fallback if the wordlists are somehow empty (they are not, per
/// the ISC-C4b sizing invariants), keeping this total without an `unwrap`.
fn default_circle_label(asset_addr: &AssetAddr) -> String {
    use daemonseed_core::handle::display_name::{DisplayNameRng, generate_display_name};

    /// Deterministic index source: consumes the address bytes (wrapping) so the
    /// chosen `(adjective, noun)` pair is a pure function of the rendezvous.
    struct AddrRng<'a> {
        bytes: &'a [u8],
        cursor: usize,
    }
    impl DisplayNameRng for AddrRng<'_> {
        fn random_index(&mut self, len: usize) -> usize {
            // Fold 8 address bytes into a u64, advancing the cursor; modulo the
            // wordlist length. Deterministic and stable for a given address.
            let mut acc = 0u64;
            for _ in 0..8 {
                let b = self.bytes[self.cursor % self.bytes.len()];
                self.cursor += 1;
                acc = (acc << 8) | b as u64;
            }
            (acc % len as u64) as usize
        }
    }

    let bytes = asset_addr.as_bytes();
    if bytes.is_empty() {
        return "#circle".to_owned();
    }
    let mut rng = AddrRng { bytes, cursor: 0 };
    generate_display_name(&mut rng)
}

/// Read the public room's inbound frames, open + VERIFY each under the global
/// room key (ISC-S25 / ISC-C57), and emit a [`NetEvent::PublicRoomMessage`].
/// A frame whose seal or provenance signature does not verify is dropped
/// silently (forged-provenance or foreign noise, ISC-A-S17) — it is never
/// surfaced. Returns when the stream ends.
async fn read_inbound_public_room(
    mut inbound: tonic::Streaming<wire::CotFrame>,
    room_key: Rc<CotKey>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    loop {
        match inbound.message().await {
            Ok(Some(frame)) => {
                // open_room_message verifies the embedded provenance signature
                // before returning, so only verified messages are surfaced.
                if let Ok(msg) = open_room_message(&room_key, &frame.payload) {
                    // ISC-C57: bind the displayed author to SHA-384(sender_pubkey)[:12].
                    // A self-asserted `sender_handle` whose hash disagrees with the
                    // verified provenance pubkey is shown at its `#<prefix>` floor,
                    // never under the spoofed name. A bind error (oxicrypt self-test)
                    // is effectively unreachable here — `open_room_message` already
                    // exercised the same key material — so drop the frame rather than
                    // surface it unbound.
                    let Ok(bound) = Handle::display_bound(&msg.sender_handle, &msg.sender_pubkey)
                    else {
                        continue;
                    };
                    if evt_tx
                        .send(NetEvent::PublicRoomMessage {
                            room: msg.room,
                            sender: bound.format(DisplayMode::Default),
                            body: msg.body,
                            sent_unix_ms: msg.sent_unix_ms,
                        })
                        .is_err()
                    {
                        return; // UI gone
                    }
                }
            }
            Ok(None) | Err(_) => return,
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

/// The cacheable + renderable result of evaluating a fetched deprecation policy
/// (ISC-C25). Produced by the pure [`decide_deprecation`] so the verification,
/// rollback, and version-gating logic is unit-testable without a live session.
struct DeprecationDecision {
    /// The snapshot to emit, or `None` on an error path — an error deliberately
    /// leaves the cached warning rows in place rather than blanking them.
    snapshot: Option<DeprecationSnapshotData>,
    /// A human-readable cause to emit as [`NetEvent::DeprecationError`], or
    /// `None` on success.
    error: Option<String>,
    /// Trust-event keys to emit (each scoped to the server by the caller).
    trust_keys: Vec<TrustEventKey>,
    /// The verified policy to insert into the cache, or `None` when nothing
    /// valid was accepted (every error path leaves the cache untouched).
    cache_policy: Option<daemonseed_core::crypto::deprecation::DeprecationPolicy>,
}

/// The payload of a [`NetEvent::DeprecationSnapshot`], split out so
/// [`decide_deprecation`] stays independent of the event enum.
#[cfg_attr(test, derive(Debug, PartialEq))]
struct DeprecationSnapshotData {
    policy_version: Option<u64>,
    warnings: Vec<DeprecationWarningRow>,
    had_policy: bool,
}

impl DeprecationDecision {
    /// An unreadable / unverifiable policy (ISC-A-C9): surface the persistent
    /// non-blocking `ServerDeprecationPolicyUnreadable` warning and an error;
    /// never accept or cache the policy.
    fn unreadable(message: impl Into<String>) -> Self {
        Self {
            snapshot: None,
            error: Some(message.into()),
            trust_keys: vec![unreadable_policy_event()],
            cache_policy: None,
        }
    }

    /// A rollback or withdrawal of a previously-held policy (ISC-A-S11): surface
    /// the blocking `ServerDeprecationPolicyRollback` event and an error; keep
    /// the cached policy (do not accept the offered version).
    fn rollback(message: impl Into<String>) -> Self {
        Self {
            snapshot: None,
            error: Some(message.into()),
            trust_keys: vec![TrustEventKey::ServerDeprecationPolicyRollback],
            cache_policy: None,
        }
    }
}

/// Decide what to surface for a fetched deprecation policy (ISC-C25 /
/// ISC-A-S11 / ISC-C28), purely from inputs — no I/O, no actor state — so every
/// branch is unit-testable.
///
/// Fail-closed throughout: a missing key, a wrong-length key, a bad signature,
/// or a rollback never yields an accepted policy. A withdrawn policy (the relay
/// served `None` after we held a version) is treated as a rollback, not a
/// benign empty state — otherwise an attacker stripping the policy would look
/// identical to a fresh server with none configured. Affected-suite trust
/// events are emitted only when the policy version increased *or* a suite is
/// already past its cutoff (blocking), so a passive re-fetch never resurrects a
/// dismissed warning while a genuine escalation always breaks through.
fn decide_deprecation(
    prev_version: Option<u64>,
    artifact: Option<&wire::SignedArtifact>,
    server_pubkey: Option<&[u8]>,
    in_use: &[SuiteId],
    now_ms: i64,
) -> DeprecationDecision {
    let Some(artifact) = artifact else {
        return if prev_version.is_some() {
            DeprecationDecision::rollback("relay withdrew a previously-served deprecation policy")
        } else {
            DeprecationDecision {
                snapshot: Some(DeprecationSnapshotData {
                    policy_version: None,
                    warnings: Vec::new(),
                    had_policy: false,
                }),
                error: None,
                trust_keys: Vec::new(),
                cache_policy: None,
            }
        };
    };

    let Some(pubkey) = server_pubkey else {
        return DeprecationDecision::unreadable(
            "no pinned server key to verify the deprecation policy",
        );
    };

    // The `try_into` target (`&[u8; ml_dsa::PK_LEN]`) is inferred from the
    // `verify_policy` parameter, so the length constant never has to be named.
    let policy = match pubkey.try_into() {
        Ok(key) => match verify_policy(artifact, key, prev_version) {
            Ok(policy) => policy,
            Err(PolicyError::VersionRollback { cached, offered }) => {
                return DeprecationDecision::rollback(format!(
                    "deprecation policy rollback rejected (offered {offered} < cached {cached})"
                ));
            }
            Err(e) => {
                return DeprecationDecision::unreadable(format!(
                    "deprecation policy verification failed: {e}"
                ));
            }
        },
        Err(_) => {
            return DeprecationDecision::unreadable("pinned server key has unexpected length");
        }
    };

    let is_new = match prev_version {
        Some(p) => policy.policy_version() > p,
        None => true,
    };
    let signals = assess_deprecation(&policy, in_use, now_ms);
    let mut warnings = Vec::with_capacity(signals.len());
    let mut trust_keys = Vec::new();
    for sig in &signals {
        let past_cutoff = sig.key == TrustEventKey::SuiteDeprecationCutoffHit;
        warnings.push(DeprecationWarningRow {
            suite_id: sig.suite_id.get(),
            cutoff_unix_ms: sig.cutoff_unix_ms,
            recommended_suite_id: sig.recommended_suite_id.get(),
            past_cutoff,
        });
        // Re-surface a warning only on a version bump (a policy the user has not
        // seen) or a blocking cutoff-hit (which must never be masked by a prior
        // non-blocking dismissal); a passive same-version re-fetch stays quiet.
        if is_new || past_cutoff {
            trust_keys.push(sig.key);
        }
    }

    DeprecationDecision {
        snapshot: Some(DeprecationSnapshotData {
            policy_version: Some(policy.policy_version()),
            warnings,
            had_policy: true,
        }),
        error: None,
        trust_keys,
        cache_policy: Some(policy),
    }
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
            circle_id: 3,
            sender: "otter#aabbccddeeff".to_owned(),
            body: "hi".to_owned(),
            sent_unix_ms: 1,
        };
        match m {
            NetEvent::ChatMessage {
                circle_id,
                sender,
                body,
                ..
            } => {
                assert_eq!(circle_id, 3);
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
            let mut actor = bare_actor(evt_tx);
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
            circles: Vec::new(),
            next_circle_id: 0,
            identity: None,
            public_room: None,
            backoff: Backoff::new(),
            share_index: None,
            server_pubkey: None,
            policy_cache: PolicyCache::new(),
            discovered: DiscoveredPeers::new(),
            published: HashMap::new(),
        }
    }

    /// Publishing with no live session fails fast with a `PublishError` and
    /// spawns no serve task (D, M15).
    #[test]
    fn publish_without_session_errors() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut actor = bare_actor(tx);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(actor.handle_publish_share(
            std::path::PathBuf::from("/tmp"),
            "x".to_owned(),
            "x#000000000000".to_owned(),
        ));
        match rx.try_recv().unwrap() {
            NetEvent::PublishError { message } => assert!(message.contains("not connected")),
            other => panic!("expected PublishError, got {other:?}"),
        }
        assert!(actor.published.is_empty(), "no serve task tracked");
    }

    /// Unpublishing an unknown id with no session still emits `PublishStopped`
    /// (idempotent stop) and tracks nothing (D, M15).
    #[test]
    fn unpublish_unknown_id_emits_stopped() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut actor = bare_actor(tx);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(actor.handle_unpublish_share("deadbeef"));
        match rx.try_recv().unwrap() {
            NetEvent::PublishStopped { share_id } => assert_eq!(share_id, "deadbeef"),
            other => panic!("expected PublishStopped, got {other:?}"),
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
            let mut actor = bare_actor(evt_tx);
            actor.handle_send_chat(0, "hello", "me#000000000000").await;
            match evt_rx.try_recv() {
                Ok(NetEvent::ChatError { message }) => assert!(message.contains("join a circle")),
                other => panic!("expected ChatError, got {other:?}"),
            }
        });
    }

    /// Sending to a circle id that is not in the membership set emits ChatError,
    /// not a panic (ISC-A-C30 stale-selection guard) — a post is sealed under an
    /// existing active circle's key or not at all, never the wrong one.
    #[test]
    fn send_chat_unknown_circle_id_fails_cleanly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let (evt_tx, mut evt_rx) = mpsc::unbounded_channel();
            let mut actor = bare_actor(evt_tx);
            // No circles joined, so id 42 cannot resolve.
            actor.handle_send_chat(42, "hello", "me#000000000000").await;
            match evt_rx.try_recv() {
                Ok(NetEvent::ChatError { message }) => assert!(message.contains("join a circle")),
                other => panic!("expected ChatError, got {other:?}"),
            }
        });
    }

    /// The client-local circle label (ISC-C62) is a deterministic function of the
    /// rendezvous address: the same address yields the same default label, and
    /// distinct addresses (overwhelmingly) yield distinct labels. The label is
    /// generated locally — it is never derived from members or transmitted.
    #[test]
    fn default_circle_label_is_deterministic_per_address() {
        let a = AssetAddr::from_bytes([7u8; 48]);
        let b = AssetAddr::from_bytes([7u8; 48]);
        let c = AssetAddr::from_bytes([9u8; 48]);
        assert_eq!(
            default_circle_label(&a),
            default_circle_label(&b),
            "same address → same label"
        );
        assert_ne!(
            default_circle_label(&a),
            default_circle_label(&c),
            "different address → different label"
        );
        // Adj-noun shape (the default, not the floor).
        assert!(default_circle_label(&a).contains('-'));
    }

    /// Refreshing the public space before connecting emits PublicSpaceError, not
    /// a panic — the actor's prerequisite guard mirrors the shares/chat paths.
    #[test]
    fn refresh_public_space_without_session_fails_cleanly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let (evt_tx, mut evt_rx) = mpsc::unbounded_channel();
            let mut actor = bare_actor(evt_tx);
            actor.handle_refresh_public_space().await;
            match evt_rx.try_recv() {
                Ok(NetEvent::PublicSpaceError { message }) => {
                    assert!(message.contains("not connected"));
                }
                other => panic!("expected PublicSpaceError, got {other:?}"),
            }
        });
    }

    // ── Deprecation policy (ISC-C25 / ISC-A-S11 / ISC-C28) ─────────────────

    /// Refreshing deprecation before connecting emits DeprecationError, not a
    /// panic — the actor's prerequisite guard mirrors the public-space path.
    #[test]
    fn refresh_deprecation_without_session_fails_cleanly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let (evt_tx, mut evt_rx) = mpsc::unbounded_channel();
            let mut actor = bare_actor(evt_tx);
            actor.handle_refresh_deprecation().await;
            match evt_rx.try_recv() {
                Ok(NetEvent::DeprecationError { message }) => {
                    assert!(message.contains("not connected"));
                }
                other => panic!("expected DeprecationError, got {other:?}"),
            }
        });
    }

    const HOUR_MS: i64 = 3_600_000;

    /// Sign a one-entry deprecation policy under a fixed key and return the
    /// artifact + its signer pubkey, for the pure `decide_deprecation` tests.
    fn signed_policy(
        version: u64,
        deprecated: SuiteId,
        cutoff_ms: i64,
        signed_now: i64,
    ) -> (wire::SignedArtifact, Vec<u8>) {
        use daemonseed_core::crypto::deprecation::{
            DeprecationEntry, DeprecationPolicy, sign_policy,
        };
        use daemonseed_core::identity::keys::SignKeypair;
        let _ = oxicrypt_module::initialize();
        let kp = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).unwrap();
        let entry = DeprecationEntry {
            suite_id: deprecated,
            cutoff_unix_ms: cutoff_ms,
            recommended_suite_id: SuiteId::try_new(0x0002).unwrap(),
        };
        let policy =
            DeprecationPolicy::build(version, signed_now, vec![entry], signed_now).unwrap();
        let artifact = sign_policy(&policy, &kp).unwrap();
        (artifact, kp.public_key().to_vec())
    }

    /// No policy served and nothing cached: a benign empty snapshot, no trust
    /// events, nothing cached.
    #[test]
    fn decide_no_policy_no_cache_is_empty_snapshot() {
        let d = decide_deprecation(None, None, Some(&[0u8; 4]), &[CNSA_2_0.id], 1_000);
        let snap = d.snapshot.expect("empty snapshot");
        assert!(!snap.had_policy);
        assert!(snap.warnings.is_empty());
        assert_eq!(snap.policy_version, None);
        assert!(d.trust_keys.is_empty());
        assert!(d.error.is_none());
        assert!(d.cache_policy.is_none());
    }

    /// Policy withdrawn after we held a version is a rollback, not a benign
    /// empty state (advisor finding) — blocking trust event, cache untouched.
    #[test]
    fn decide_withdrawn_policy_with_cache_is_rollback() {
        let d = decide_deprecation(Some(3), None, Some(&[0u8; 4]), &[CNSA_2_0.id], 1_000);
        assert!(d.snapshot.is_none(), "no snapshot — cached panel kept");
        assert!(d.error.is_some());
        assert_eq!(
            d.trust_keys,
            vec![TrustEventKey::ServerDeprecationPolicyRollback]
        );
        assert!(d.cache_policy.is_none());
    }

    /// A valid, newer policy whose deprecated suite is in use surfaces a pending
    /// warning row and one pending trust event, and is cached.
    #[test]
    fn decide_valid_new_pending_emits_warning_and_trust() {
        let now = 1_000_000_000_000;
        let (artifact, pubkey) = signed_policy(1, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(None, Some(&artifact), Some(&pubkey), &[CNSA_2_0.id], now);
        let snap = d.snapshot.expect("snapshot");
        assert!(snap.had_policy);
        assert_eq!(snap.policy_version, Some(1));
        assert_eq!(snap.warnings.len(), 1);
        assert!(!snap.warnings[0].past_cutoff);
        assert_eq!(snap.warnings[0].suite_id, CNSA_2_0.id.get());
        assert_eq!(d.trust_keys, vec![TrustEventKey::SuiteDeprecationPending]);
        assert!(d.cache_policy.is_some());
        assert!(d.error.is_none());
    }

    /// A passive re-fetch of the same version keeps the warning row but emits NO
    /// trust event — a dismissed warning must not resurrect (advisor finding).
    #[test]
    fn decide_same_version_suppresses_trust_keeps_warning() {
        let now = 1_000_000_000_000;
        let (artifact, pubkey) = signed_policy(1, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(Some(1), Some(&artifact), Some(&pubkey), &[CNSA_2_0.id], now);
        let snap = d.snapshot.expect("snapshot");
        assert_eq!(snap.warnings.len(), 1, "warning row still rendered");
        assert!(
            d.trust_keys.is_empty(),
            "same-version re-fetch resurrects nothing"
        );
    }

    /// A higher policy version re-emits the warning trust event.
    #[test]
    fn decide_higher_version_re_emits_trust() {
        let now = 1_000_000_000_000;
        let (artifact, pubkey) = signed_policy(2, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(Some(1), Some(&artifact), Some(&pubkey), &[CNSA_2_0.id], now);
        assert_eq!(d.trust_keys, vec![TrustEventKey::SuiteDeprecationPending]);
    }

    /// A suite already past its cutoff emits the blocking cutoff-hit event even
    /// on a same-version re-fetch — a blocking gate is never masked by a prior
    /// non-blocking dismissal (advisor finding).
    #[test]
    fn decide_cutoff_hit_emits_even_same_version() {
        let signed_now = 1_000_000_000_000;
        let cutoff = signed_now + 3 * HOUR_MS;
        let (artifact, pubkey) = signed_policy(1, CNSA_2_0.id, cutoff, signed_now);
        // Evaluate well past the cutoff, same cached version.
        let eval_now = cutoff + HOUR_MS;
        let d = decide_deprecation(
            Some(1),
            Some(&artifact),
            Some(&pubkey),
            &[CNSA_2_0.id],
            eval_now,
        );
        let snap = d.snapshot.expect("snapshot");
        assert!(snap.warnings[0].past_cutoff);
        assert_eq!(d.trust_keys, vec![TrustEventKey::SuiteDeprecationCutoffHit]);
    }

    /// A version-rollback artifact is rejected: rollback trust event, no cache.
    #[test]
    fn decide_version_rollback_is_rejected() {
        let now = 1_000_000_000_000;
        let (artifact, pubkey) = signed_policy(3, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(Some(7), Some(&artifact), Some(&pubkey), &[CNSA_2_0.id], now);
        assert!(d.snapshot.is_none());
        assert_eq!(
            d.trust_keys,
            vec![TrustEventKey::ServerDeprecationPolicyRollback]
        );
        assert!(d.cache_policy.is_none());
    }

    /// A tampered payload fails verification → unreadable (never accepted).
    #[test]
    fn decide_bad_signature_is_unreadable() {
        let now = 1_000_000_000_000;
        let (mut artifact, pubkey) = signed_policy(1, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        artifact.signed_payload.push(0xFF);
        let d = decide_deprecation(None, Some(&artifact), Some(&pubkey), &[CNSA_2_0.id], now);
        assert!(d.snapshot.is_none());
        assert_eq!(
            d.trust_keys,
            vec![TrustEventKey::ServerDeprecationPolicyUnreadable]
        );
        assert!(d.cache_policy.is_none());
    }

    /// A missing pinned key fails closed — an unverifiable policy is never
    /// accepted (advisor finding: the one failure mode that defeats the feature).
    #[test]
    fn decide_missing_pubkey_is_unreadable() {
        let now = 1_000_000_000_000;
        let (artifact, _pubkey) = signed_policy(1, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(None, Some(&artifact), None, &[CNSA_2_0.id], now);
        assert!(d.snapshot.is_none());
        assert_eq!(
            d.trust_keys,
            vec![TrustEventKey::ServerDeprecationPolicyUnreadable]
        );
        assert!(d.cache_policy.is_none());
    }

    /// A wrong-length pinned key fails closed before verification.
    #[test]
    fn decide_short_pubkey_is_unreadable() {
        let now = 1_000_000_000_000;
        let (artifact, _pubkey) = signed_policy(1, CNSA_2_0.id, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(
            None,
            Some(&artifact),
            Some(&[1u8, 2, 3]),
            &[CNSA_2_0.id],
            now,
        );
        assert!(d.snapshot.is_none());
        assert_eq!(
            d.trust_keys,
            vec![TrustEventKey::ServerDeprecationPolicyUnreadable]
        );
        assert!(d.cache_policy.is_none());
    }

    /// A valid policy deprecating a suite the client does not use: accepted and
    /// cached, but no warning row and no trust event (distinct from "no policy").
    #[test]
    fn decide_unaffected_suite_has_no_warning() {
        let now = 1_000_000_000_000;
        let other = SuiteId::try_new(0x0002).unwrap();
        let (artifact, pubkey) = signed_policy(1, other, now + 3 * HOUR_MS, now);
        let d = decide_deprecation(None, Some(&artifact), Some(&pubkey), &[CNSA_2_0.id], now);
        let snap = d.snapshot.expect("snapshot");
        assert!(snap.had_policy);
        assert!(snap.warnings.is_empty());
        assert!(d.trust_keys.is_empty());
        assert!(
            d.cache_policy.is_some(),
            "still cached for rollback baseline"
        );
    }
}
