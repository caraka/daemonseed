//! Network contract + shared helpers — the async side of the TUI.
//!
//! The render loop is synchronous (a blocking crossterm poll), but the daemon
//! protocol is async. This module defines the transport contract the binary
//! drives: the binary owns a [`NetHandle`] holding a tokio runtime and two
//! channels — [`NetCommand`]s flow in, [`NetEvent`]s flow out. The render thread
//! sends commands and drains events with non-blocking `try_recv`, so a slow
//! operation never blocks the UI.
//!
//! [`NetCommand`] and [`NetEvent`] are plain data, so [`crate::app::App`] folds
//! events in via `App::on_net_event` without ever touching the runtime — which
//! keeps `App` unit-testable and the PTY gate deterministic.
//!
//! ## What lives here
//!
//! - The transport contract: [`StableSigningKey`], [`NetCommand`], [`NetEvent`],
//!   [`ShareManifestEntry`], and [`NetHandle`] — shared by the binary, [`crate::app`],
//!   and the Veilid actor (`crate::veilid_net`).
//! - The transport-agnostic helpers the Veilid actor and the app reuse:
//!   `now_unix_ms`, and the managed-download folder resolver
//!   `resolve_share_folder` (the download write/placement path now lives in the
//!   shared `daemonseed_veilid_net::download` engine + core `StagingArea`).
//!
//! ## Transport
//!
//! Veilid is the only transport. [`NetHandle::new`] spawns
//! `crate::veilid_net::veilid_net_actor`; the UI drives the same
//! `NetCommand`/`NetEvent` contract over Veilid.

use std::path::PathBuf;
use std::sync::Arc;

use daemonseed_core::backoff::CloseCause;
use daemonseed_core::identity::keys::{ShareRootIkm, SignKeypair};
use daemonseed_core::share_catalog::ShareListing;
use daemonseed_core::storage::fetched::FetchedShare;
use daemonseed_core::storage::seeds::IndexKey;
use daemonseed_core::trust_events::TrustEventKey;
use daemonseed_proto::v1 as wire;
use tokio::sync::mpsc;

use crate::app::{DeprecationWarningRow, IndexerStatus, LocalShareRow, PublicPostRow};

/// (#92) `Clone + Debug` wrapper around the stable identity signing key so it can
/// ride the `Clone + Debug` [`NetCommand`] enum. The inner [`SignKeypair`] is
/// `!Clone` (`ZeroizeOnDrop`) and `!Debug` (it holds secret bytes); the [`Arc`]
/// makes the wrapper cheaply clonable (shared, never copied) and the redacted
/// `Debug` keeps the secret out of any log (mirrors [`IndexKey`]'s redaction).
#[derive(Clone)]
pub struct StableSigningKey(pub Arc<SignKeypair>);

impl std::fmt::Debug for StableSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StableSigningKey(<redacted>)")
    }
}

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
        /// (#92) the unlocked profile's STABLE persistent identity signing key
        /// (derived from the mnemonic via `derive_identity_keys(.., Primary)` —
        /// the key behind the whitelisted `name#hash` handle). Held by the actor
        /// for the session so the public-space composer is gated (`composer_visible`)
        /// and MOTD/announcements are signed under the persistent identity, NOT the
        /// ephemeral connection key. `None` on the ephemeral / no-profile path
        /// (read-only public space, no composer).
        stable_signing_key: Option<StableSigningKey>,
        /// (#156) the unlocked profile's share-root IKM (the fourth expansion of
        /// the identity PRK, same `derive_identity_keys` as `stable_signing_key`).
        /// The veilid actor holds it so a publish derives a receiver-verifiable
        /// `share_id`. `None` on the ephemeral / no-profile path. (`ShareRootIkm`
        /// is `Clone` + redacted `Debug`, so it rides the enum directly — no
        /// wrapper needed.)
        stable_share_root_ikm: Option<ShareRootIkm>,
        /// (download-subsystem redesign, step 8b-2 / DL-ISC-20) the unlocked
        /// profile's on-disk ROOT — the client's own trusted state dir (where
        /// `seeds.blob` / `share-index.redb` live). The actor holds it so a verified
        /// resume can anchor each fetch's confirmed-manifest digest in
        /// `storage::manifest_digest::ManifestDigestStore` under this dir (NOT the
        /// co-resident-writable downloads root). `None` on the no-profile path — that
        /// session persists no resume anchor, so a later resume finds no digest and
        /// re-downloads fresh (fail-closed).
        profile_root: Option<PathBuf>,
        /// Our own `name#<12hex>` display handle, captured at connect so the lobby
        /// presence beacon carries the real name from its FIRST emit. Previously
        /// `my_handle` was learned only from the first `SendChat`/`SendPublicRoom`,
        /// so a publish-only or lurking session (e.g. a seed node that never chats)
        /// stayed nameless and broadcast the `"guest"` fallback. In practice this is
        /// always the session's real handle — every Connect dispatch runs under an
        /// unlocked profile; the actor still guards `""`/`"anon"` (the no-session
        /// `own_handle()` sentinel) and falls back to "guest" defensively.
        self_handle: String,
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
    /// the redb `ShareIndex` at `index_path` under `index_key` (the
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
    ///
    /// In the unified share model this also posts a sealed [`wire::ShareRollCall`]
    /// to the lobby (the single late-join hook — startup, the Refresh action, and
    /// the reconcile timer all route through here) so live sharers re-announce,
    /// then snapshots the in-band `ShareCatalog` as the `remote` rows.
    RefreshShares,
    /// Internal: a verified lobby [`wire::ShareAnnouncement`] the inbound reader
    /// opened, to fold into the actor's `ShareCatalog` (all catalog mutation
    /// stays on `&mut self`). Posted by the inbound reader; never sent
    /// by the binary. Emits a fresh [`NetEvent::SharesSnapshot`] on a real change.
    ApplyAnnouncement(Box<wire::ShareAnnouncement>),
    /// Internal: a verified lobby [`wire::ShareRollCall`] the inbound reader
    /// opened — re-announce every own share so the requester discovers them.
    /// Posted by the inbound reader; never sent by the binary.
    AnswerRollCall,
    /// Internal: the slow-reconcile tick — prune aged-out catalog entries and
    /// post a roll-call. Self-scheduled on the reconcile tick; never sent by
    /// the binary.
    ReconcileShares,
    /// Internal: the presence-heartbeat tick (#74) — emit one sealed member
    /// beacon into the lobby and each joined circle, then `reap` every tracker so
    /// members past their TTL age out (the timer is the reap clock too).
    /// Self-scheduled on `next_heartbeat_interval`; never sent by the binary.
    EmitHeartbeat,
    /// Internal: a verified member heartbeat the inbound reader opened, to fold
    /// into the matching room/circle's `PresenceTracker` (all tracker mutation
    /// stays on `&mut self`). `room` is the session-local routing key — the lobby
    /// room name for a lobby beacon, the circle's label for a circle beacon.
    /// Boxed because [`wire::MemberHeartbeat`] is large (mirrors
    /// [`Self::ApplyAnnouncement`]). Posted by the inbound readers; never sent by
    /// the binary.
    ApplyHeartbeat {
        room: String,
        heartbeat: Box<wire::MemberHeartbeat>,
    },
    /// Refresh the public-space snapshot (ISC-25 / ISC-S7 / ISC-A-S3): fetch the
    /// connected relay's MOTD, announcement posts, and published signer
    /// whitelist over the live `AppSession`, render the MOTD as inert text,
    /// and re-verify each post against the whitelist client-side. A read-only
    /// operation emitted as a single [`NetEvent::PublicSpaceSnapshot`].
    RefreshPublicSpace,
    /// (#92) Signer authoring: sign an announcement post with the held stable
    /// identity key (`sign_post`) and upload it via `UploadPost`, then refresh.
    /// A no-op surfaced as [`NetEvent::PublicSpaceError`] when no stable key is held
    /// (non-signer / ephemeral) or no session is live; the relay independently
    /// re-verifies the signature against the published whitelist (ISC-S8).
    UploadAnnouncement { topic: String, body: String },
    /// (#92) Signer authoring: sign a MOTD with the held stable identity key
    /// (`sign_motd`, which enforces the ISC-S9 single-line-plaintext rule) and
    /// upload it via `UploadMotd` (#89), then refresh. Non-plaintext text is
    /// rejected BEFORE upload and surfaced as [`NetEvent::PublicSpaceError`].
    SetMotd { text: String },
    /// Refresh the suite-deprecation policy (ISC-C25 / ISC-A-S11 / ISC-C28):
    /// fetch the connected relay's signed policy over the live `AppSession`,
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
    /// stream over the existing `AppSession`, sends a `ManifestRequest`, and
    /// reads a `ManifestResponse` for the A1 preview (the download itself is
    /// the separate `ConfirmFetch`). Progress is surfaced via
    /// `NetEvent::FetchProgress`; the terminal state is one of
    /// `NetEvent::FetchComplete` or `NetEvent::FetchError`. `sharer_handle`
    /// is advisory — included so subsequent UX layers (post-MVP `f`-keyed
    /// trust-on-sharer affordances) can route per-sharer events; the relay
    /// never sees the value (it lives in the recipient's local state only).
    /// `name` is the sharer-advertised listing name, recorded in the fetched
    /// manifest. `fetched_root` is the on-disk landing zone (the binary supplies
    /// `<profile-root>/fetched`); on a fully-verified fetch the actor persists
    /// every file there via `FetchedStore` and emits a fresh
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
    /// stream and requests every chunk of the selected files (`selected = None`
    /// downloads every file; `Some(indices)` downloads only those manifest
    /// rows — the A2 selective path), verifying each chunk against its content
    /// address and streaming it to the destination file as it arrives (M16,
    /// ISC-C73 / ISC-A-C35 — never a whole file in RAM). A 30s inactivity
    /// timeout aborts a silent hang; an abort deletes the fetch's partial
    /// files (ISC-A-C31). Terminal state is `NetEvent::FetchComplete` or
    /// `NetEvent::FetchError`.
    ConfirmFetch {
        share_id: String,
        sharer_handle: String,
        name: String,
        fetched_root: PathBuf,
        selected: Option<Vec<usize>>,
        /// True when `fetched_root` is an explicit user-chosen destination
        /// (ISC-C68): files land directly under it via the selection-root
        /// placement resolver (`root_kind` → `SelectionRoot` → `place_at_dest`),
        /// with no per-share folder and no `downloads.idx` written into the
        /// user's directory. False for the managed downloads dir, which keeps
        /// the namespaced `<share>/<rel_path>` layout and the browse manifest.
        flat_dest: bool,
        /// (download-subsystem redesign, step 6 / DL-ISC-8) The kind of selection
        /// the user confirmed — the placement selection root the net side maps to
        /// a `SelectionRoot` (mirrors the GUI's `RootKind` on `ConfirmFetch`). The
        /// TUI's preview is a FLAT manifest-row list (no folder tree), so the node
        /// kind is a function of the selection cardinality, resolved by the binary:
        /// `selected: None` → `Share`, one checked row → `File`, several → `Dir`.
        /// Only consulted in the `flat_dest` branch; an in-process `NetCommand`
        /// field (UI ↔ actor mpsc), never on the wire.
        root_kind: RootKind,
    },
    /// List the fetched shares recorded under `fetched_root` for the browse
    /// pane (M15 C; ISC-C64). Emits a [`NetEvent::FetchedShares`] snapshot
    /// (empty if nothing has been fetched).
    ListFetched { fetched_root: PathBuf },
    /// Refresh the introducer-discovered candidate peers for the Servers pane
    /// (M12 gate step 6, ISC-C22 / ISC-S6 / ISC-A-C19). Ask the connected
    /// relay's `FederationIntroducer` for its peer list over the live
    /// `AppSession` and merge the result into the actor's `DiscoveredPeers`
    /// cache as candidates, then emit the candidate `(server_id, address)`
    /// pairs as a single [`NetEvent::IntroducerSnapshot`].
    ///
    /// Precautionary by construction: discovery records *candidates only* and
    /// NEVER writes the trust set (ISC-A-C19) — promotion to a trusted/untrusted
    /// server stays the explicit user action (`DiscoveredPeers::promote_trusted`
    /// / `DiscoveredPeers::promote_untrusted`). The introducer response carries
    /// no key material (ISC-S6), so the snapshot it produces is server-id +
    /// address only. A read-only operation against an already-shipped gRPC
    /// service — no new wire protocol.
    RefreshIntroducer,
    /// Publish a defined share to the connected relay and serve its content
    /// from disk (D, M15 → serve-from-disk, M16; ISC-S27 / ISC-S29 / F25).
    /// Hashes `root` into a manifest on a dedicated blocking thread —
    /// `cached_or_hash` reuses redb-cached chunk addresses when the actor's
    /// single-active `ShareIndex` is for this root, hashing only the misses —
    /// so the actor keeps draining commands while a large share hashes.
    /// Per-file progress arrives as `NetEvent::PublishProgress`; the hash is
    /// cancellable via [`NetCommand::CancelPublish`]. On success the listing is
    /// published via `PublishShare` to learn the server-assigned `share_id`,
    /// then a `serve_share` task holding a `DiskShareContent` (manifest in
    /// RAM, file bytes read from disk per request) answers fetchers'
    /// manifest/chunk requests over the share's CoT fetch-asset for as long as
    /// the session is up ("you must be online to share" — the relay reaps the
    /// share when this connection drops, ISC-S20). Lifecycle arrives as
    /// `NetEvent::PublishStarted` / `PublishError` / `PublishCancelled` /
    /// `PublishStopped`.
    PublishShare {
        root: PathBuf,
        name: String,
        /// The publisher's display handle, advertised in the listing so peers
        /// see the sharer's name, not "(operator)".
        sharer_handle: String,
    },
    /// Cancel an in-flight publish hash for `root` (M16 serve-from-disk).
    /// Sets that publish's cancel flag so the blocking `cached_or_hash`
    /// returns `ServeError::Cancelled` at its next per-file check and the
    /// publish flow emits `NetEvent::PublishCancelled` instead of proceeding
    /// to the RPC. A no-op when no hash for `root` is in flight (the cancel
    /// raced a completion, or the share is already serving — stopping a
    /// *served* share is [`NetCommand::UnpublishShare`]'s job).
    CancelPublish { root: PathBuf },
    /// Unpublish a share published this session and stop serving it (D, M15;
    /// owner-scoped, ISC-A-S1). Sends `UnpublishShare` to the relay and aborts
    /// the local serve task, emitting `NetEvent::PublishStopped`. No-op for an
    /// unknown id.
    UnpublishShare { share_id: String },
}

/// (download-subsystem redesign, step 6 / DL-ISC-8) The kind of selection root a
/// `ConfirmFetch` targets — carried so a user-chosen-dest placement is a function
/// of the selection, not guessed from path shapes. Analogous to the GUI's
/// `net::RootKind` (which carries the toggled folder's path); the TUI preview
/// is a flat manifest-row list, so the binary derives the kind from the confirmed
/// selection: none selected → `Share`, one row → `File`, several → `Dir`. Drives
/// `veilid_net::selection_roots`. An in-process `NetCommand` field only, never on
/// the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKind {
    /// The whole share — every file (`selected: None`).
    Share,
    /// A single selected file (`selected: Some([one index])`).
    File,
    /// A scattered multi-file selection (`selected: Some([several indices])`) —
    /// placed under the selected files' common parent-directory prefix.
    Dir,
}

/// One file in an A1 fetch-preview ([`NetEvent::FetchManifest`]): the
/// sharer-advertised relative path, its byte size, and its chunk count.
/// Carries no chunk *addresses* — those stay in the net actor; the UI shows
/// names + sizes only and confirms by manifest-row index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareManifestEntry {
    pub rel_path: String,
    pub size: u64,
    /// How many [`daemonseed_core::share_serve::CHUNK_SIZE`] chunks the file's
    /// bytes span (M16, ISC-C73 / ISC-A-C35) — `manifest.chunks.len()`, so an
    /// empty file is `0`. The app sums this over the selected files to seed
    /// the chunk-granular progress gauge before the net actor's authoritative
    /// first `FetchProgress` arrives.
    pub chunk_count: u32,
}

/// An event from the network actor back to the UI. Plain data — folded into
/// [`crate::app::App`] by `on_net_event` with no runtime dependency.
///
/// `Eq` is intentionally NOT derived: `SharesSnapshot` carries a
/// `Vec<ShareListing>` and the prost-generated message type only
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
    /// (WB-5.1 / I5″.7, WB-ISC-20) The aggregate "presence may be stale" signal
    /// toggled: an elevated DHT regime has the reaper suspended, holding a past-TTL
    /// member visible on the roster. The status line surfaces the caveat while `stale`
    /// is true. Emitted only on a change.
    PresenceStale { stale: bool },
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
        remote: Vec<ShareListing>,
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
        /// (#92) signer-gating verdict (`composer_visible`): true iff the held
        /// stable identity key is on the relay's published whitelist, gating the
        /// composer affordance. False for a non-signer or the ephemeral path.
        can_compose: bool,
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
    /// Progress on an active share fetch (ISC-19). Chunk-granular over the
    /// SELECTED set (M16, ISC-C73 / ISC-A-C35): `total_chunks` counts every
    /// 1 MiB chunk of every selected file, not the file count. `None` only
    /// while the fetcher is still waiting on the `ManifestResponse`; `Some(N)`
    /// from the first confirm-side emit on. Emitted once when the download
    /// starts and once per verified chunk streamed to disk.
    FetchProgress {
        total_chunks: Option<u32>,
        chunks_received: u32,
        bytes_received: u64,
    },
    /// The share fetch completed: every chunk of every selected file was
    /// verified and streamed to its named destination file. `files_written`
    /// counts FILES (M16 — no longer == chunks); `bytes_written` is the total
    /// verified bytes on disk.
    FetchComplete {
        share_id: String,
        files_written: u32,
        bytes_written: u64,
    },
    /// The fetch failed at some point (no session, derive error, decode error,
    /// chunk-hash mismatch, peer dropped the stream, RPC status, or the M16
    /// 30s inactivity timeout). The fetcher stops and DELETES every file this
    /// fetch wrote — the in-progress partial and any already-completed
    /// siblings — so a failed fetch never leaves a silently-truncated file on
    /// disk (ISC-A-C31 posture, now applied to streamed writes). The overlay
    /// marks the fetch failed and waits for the user to dismiss.
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
    /// reaps the asset — then `PublishStopped` arrives. `root` is echoed
    /// client-side from the publish request so the app can key its published
    /// list by the defined root (ISC-A-C34 idempotency guard) — it is local-only
    /// plumbing and never rides the wire (the relay sees only the listing).
    PublishStarted {
        share_id: String,
        root: PathBuf,
        name: String,
        file_count: usize,
    },
    /// Per-file progress on an in-flight publish hash (M16 serve-from-disk).
    /// Emitted from the blocking `cached_or_hash` thread once per file
    /// (`done` strictly advances — the throttle), so the app can render a
    /// "hashing N/M" status and offer `[u]` as the cancel affordance while the
    /// actor stays responsive. `root` is the defined-root key (client-local
    /// plumbing, mirroring `PublishStarted` — display-name string joins
    /// conflate distinct shares per ISC-A-C34); `name` is for the status line.
    PublishProgress {
        root: PathBuf,
        name: String,
        done: usize,
        total: usize,
    },
    /// An in-flight publish hash was cancelled (`NetCommand::CancelPublish`,
    /// M16 serve-from-disk). Distinct from `PublishError` so the app can word
    /// it neutrally — a cancel is the user's own action, not a failure.
    /// Nothing was published or served; `[p]` re-publishes from scratch.
    /// `root` keys the app's hashing-state set (ISC-A-C34 root-keying).
    PublishCancelled { root: PathBuf, name: String },
    /// Publishing a share failed (no session, no server-id, an unreadable path,
    /// or a refused `PublishShare` RPC). Surfaced on the status line. `root` is
    /// the defined-root key when the failure concerns a specific publish (the
    /// hash or RPC step) so the app can clear that root's hashing state;
    /// `None` for the pre-flight failures (no session / no server-id) that
    /// never started a hash.
    PublishError {
        message: String,
        root: Option<PathBuf>,
    },
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
    /// A *current-thread* runtime + `LocalSet` is deliberate: `connect_session`
    /// takes `&mut dyn TrustStore`, which is not `Send`, so its future cannot be
    /// `tokio::spawn`ed onto a multi-thread runtime; and the circle inbound-reader
    /// task holds an `Rc` of the circle key. Driving everything on one thread
    /// via `block_on` + `spawn_local` sidesteps both `Send` bounds.
    ///
    /// Caller contract: the oxicrypt module must already be `Operational`
    /// (the binary drives `initialize_with_profile` at startup).
    pub fn new() -> std::io::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        // A self-command sender the actor clones so detached tasks (the lobby
        // inbound reader, the reconcile timer) can post discovery commands back
        // into the one command loop, keeping all catalog mutation on `&mut self`.
        let cmd_tx_actor = cmd_tx.clone();
        let thread = std::thread::Builder::new()
            .name("daemonseed-tui-net".to_owned())
            .spawn(move || {
                // Veilid is the only transport. veilid-core spawns its own tasks
                // and needs a multi-thread runtime.
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("build veilid net runtime");
                rt.block_on(crate::veilid_net::veilid_net_actor(
                    cmd_rx,
                    cmd_tx_actor,
                    evt_tx,
                ));
            })?;
        Ok(Self {
            cmd_tx,
            evt_rx,
            _thread: thread,
        })
    }

    /// Queue a command for the network actor. Fails only if the actor stopped;
    /// the rejected command is returned (boxed — `NetCommand` is large, so an
    /// unboxed error would trip `clippy::result_large_err`) for the caller to
    /// inspect or drop.
    pub fn send(&self, cmd: NetCommand) -> Result<(), Box<NetCommand>> {
        self.cmd_tx.send(cmd).map_err(|e| Box::new(e.0))
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

/// Wall-clock now in unix milliseconds (advisory message timestamp). `pub(crate)` so
/// the app layer stamps a local echo with a real time for chronological ordered-insert
/// (#130), matching the wire timestamp the actor stamps on the sent frame.
pub(crate) fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Resolve the per-share folder for a download, mirroring core
/// `FetchedStore::record_share`: reuse the share's existing folder on a
/// re-fetch; otherwise derive a safe name from the listing name,
/// collision-suffixed by share_id if another share already claimed it.
///
/// KNOWN RACE (download-subsystem redesign, step 6 follow-up, tracked): two
/// DISTINCT shares with IDENTICAL display names downloading concurrently both
/// read `existing` before either has registered its `downloads.idx` entry, so
/// each sees the base name un-taken and both pick the same unsuffixed folder —
/// the collision suffix never fires. The window is the gap between this
/// resolution and `register_share`. It is NOT silent data loss: `StagingArea`
/// promotion is no-clobber (DL-ISC-21), so colliding files inside the shared
/// folder collision-suffix rather than overwrite; only the folder *identity* is
/// shared. A correct fix needs atomic folder reservation UNDER the idx lock
/// (`register_share` reserving the folder as part of the same locked RMW that
/// writes the entry), a non-trivial addition deliberately deferred — a
/// half-baked reservation scheme is worse than the narrow, non-destructive race.
pub(crate) fn resolve_share_folder(
    existing: &[FetchedShare],
    share_id: &str,
    name: &str,
) -> String {
    if let Some(s) = existing.iter().find(|s| s.share_id == share_id) {
        return s.folder.clone();
    }
    let base = safe_folder_name(name);
    let taken = existing.iter().any(|s| s.folder == base);
    if taken {
        let suffix: String = share_id.chars().take(6).collect();
        format!("{base}-{suffix}")
    } else {
        base
    }
}

/// Derive a safe single-component folder name from an untrusted share name
/// (mirror of core's `fetched::safe_folder_name`, ISC-A-C32): separators and
/// control chars become `_`, leading/trailing dots and whitespace trimmed,
/// empty falls back to `"share"`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::cot::AssetAddr;

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

    /// The TUI labels a joined circle via the canonical core derivation
    /// (`daemonseed_core::circle::default_circle_label`, ISC-C62): a deterministic
    /// function of the rendezvous address — the same address yields the same default
    /// label, distinct addresses (overwhelmingly) distinct labels — generated locally,
    /// never derived from members or transmitted.
    #[test]
    fn default_circle_label_is_deterministic_per_address() {
        use daemonseed_core::circle::default_circle_label;
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

    /// The safe-folder-name mirror (ISC-A-C32) reduces a hostile share name to a
    /// single safe component exactly like core's. (Wire `rel_path` hygiene now
    /// lives in the shared engine's core `sanitize_rel_path`/`place_at_dest`; the
    /// TUI no longer carries its own copy.)
    #[test]
    fn fetch_path_hygiene_mirrors_fail_closed() {
        assert_eq!(safe_folder_name(""), "share");
        assert_eq!(safe_folder_name("a/b\\c"), "a_b_c");
        for n in ["..", "../../etc", "/", ".", ""] {
            let f = safe_folder_name(n);
            assert!(!f.contains('/') && !f.contains('\\') && f != "." && f != "..");
        }
    }

    /// Folder resolution mirrors core's `record_share` policy: a re-fetch
    /// reuses the share's existing folder; a name collision with a DIFFERENT
    /// share is suffixed by share_id.
    #[test]
    fn resolve_share_folder_reuses_and_collision_suffixes() {
        let existing = vec![FetchedShare {
            share_id: "aaaaaa11".to_owned(),
            name: "Vacation".to_owned(),
            folder: "Vacation".to_owned(),
            files: Vec::new(),
        }];
        // Re-fetch of the same share_id → same folder.
        assert_eq!(
            resolve_share_folder(&existing, "aaaaaa11", "Vacation"),
            "Vacation"
        );
        // A different share with the same name → suffixed.
        assert_eq!(
            resolve_share_folder(&existing, "bbbbbb22", "Vacation"),
            "Vacation-bbbbbb"
        );
        // No collision → the safe base name.
        assert_eq!(resolve_share_folder(&existing, "cccccc33", "docs"), "docs");
    }
}
