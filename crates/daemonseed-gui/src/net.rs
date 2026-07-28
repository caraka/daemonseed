//! Network contract + shared helpers — the async side of the GUI.
//!
//! The Slint UI thread is synchronous and must NEVER block on the network. This
//! module defines the transport contract the UI drives: [`NetCommand`]s flow in,
//! [`NetEvent`]s flow out over a [`NetHandle`] that owns a dedicated named thread.
//! The UI sends commands fire-and-forget and drains events with non-blocking
//! `try_recv`, so a slow operation never stalls a frame.
//!
//! This module is **Slint-free** (no `slint` import) so it stays unit-testable in
//! isolation and the UI/network concerns never entangle.
//!
//! ## What lives here
//!
//! - The transport contract: [`NetCommand`], [`NetEvent`], [`RosterEntry`],
//!   [`ShareManifestEntry`], and [`NetHandle`] — the UI-facing types that both the
//!   UI and the Veilid actor ([`crate::veilid_net`]) share.
//! - The transport-agnostic helpers the Veilid actor and the UI reuse: roster
//!   building ([`roster_from_members`], [`roster_render_changed`],
//!   [`member_fingerprint`], [`beacon_is_own`]), handle canonicalization
//!   ([`canonical_wire_handle`], [`republish_name`]), and share-path path hygiene
//!   ([`safe_folder_name`], [`is_unsafe_publish_root`]).
//!
//! ## Transport
//!
//! Veilid is the only transport. [`NetHandle::new`] spawns
//! [`crate::veilid_net::veilid_net_actor`]; the UI drives the same
//! `NetCommand`/`NetEvent` contract over Veilid. veilid-core spawns its own tasks
//! and needs a multi-thread runtime.

use std::path::{Path, PathBuf};

use crate::state::AnnouncementsView;
use daemonseed_core::cot::AssetAddr;
use daemonseed_core::dm::keyrec::KemEncapsulationKey;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::identity::keys::{ShareRootIkm, SignKeypair};
use daemonseed_core::presence::{LiveMember, PresenceChange};
use daemonseed_core::share_catalog::ShareListing;
use tokio::sync::mpsc;

/// The wire-facing name for an auto-republished share (M16 restore path, #41):
/// the persisted [`daemonseed_core::storage::seeds::PublishedShare`] `name` when
/// one was stored, else the root directory's basename, else `"share"`. Centralizes
/// the choice both republish loops make so the persisted name is consumed
/// consistently. The publish overlay's name field sets the persisted name, so a
/// custom name returns verbatim here and an un-named share (`None`) falls back to
/// the folder basename.
///
/// `pub(crate)` so the Veilid net actor's connect-time republish (#108) names
/// shares identically to the relay path — one source for the choice, no drift.
pub(crate) fn republish_name(root: &Path, persisted: Option<&str>) -> String {
    if let Some(name) = persisted.filter(|n| !n.is_empty()) {
        return name.to_owned();
    }
    root.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "share".to_owned())
}

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
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
        /// (M16) persisted published-share roots (directory paths) to silently
        /// re-publish once the session is live — read from the at-rest blob, served
        /// after the lobby auto-join exactly like `rejoin_circles`. Each republish
        /// uses the directory basename as the share name and `display_handle` as the
        /// sharer handle. Empty for the ephemeral / no-profile path.
        republish_roots: Vec<(PathBuf, Option<String>)>,
        /// (#92) the unlocked profile's STABLE persistent identity signing key
        /// (`Profile::stable_signing_key` — `derive_identity_keys(.., Primary)`),
        /// the key behind the `name#hash` handle an operator whitelists. Derived
        /// ONCE on the UI thread and handed over so the actor can gate the composer
        /// (`composer_visible` against the published whitelist) and SIGN
        /// MOTD/announcements — NOT the ephemeral connection-proof key. `None` on
        /// the ephemeral / no-profile path (read-only public space, no composer).
        stable_signing_key: Option<SignKeypair>,
        /// (#156) the unlocked profile's share-root IKM
        /// (`Profile::stable_share_root_ikm` — the fourth expansion of the identity
        /// PRK), derived from the SAME `derive_identity_keys` as
        /// `stable_signing_key`. The veilid actor holds it so a publish derives a
        /// receiver-verifiable `share_id`. `None` on the ephemeral / no-profile
        /// path (no publish under a stable identity).
        stable_share_root_ikm: Option<ShareRootIkm>,
        /// (#232) the unlocked profile's STABLE ML-KEM-1024 **encapsulation** key
        /// (`Profile::stable_kem_encapsulation_key`) — the public half of the
        /// identity KEM keypair, derived from the SAME `derive_identity_keys` as
        /// `stable_signing_key`. The veilid actor holds it so it can publish the DM
        /// key record (ISC-C40) that makes this identity reachable for direct
        /// messages. Public material only: the decapsulation key never leaves the
        /// profile. `None` on the ephemeral / no-profile path — that session is not
        /// DM-reachable, which is the honest state for an identity with no
        /// persistent key.
        stable_kem_encapsulation_key: Option<KemEncapsulationKey>,
        /// (download-subsystem redesign, step 8b / DL-ISC-20) the unlocked profile's
        /// on-disk ROOT — the client's own trusted state dir. The actor holds it so a
        /// verified resume can anchor each fetch's confirmed-manifest digest in
        /// `storage::manifest_digest::ManifestDigestStore` under this dir (NOT the
        /// co-resident-writable downloads root). `None` on the ephemeral / no-profile
        /// path — that session persists nothing, so a download simply gets no resume
        /// anchor (fail-closed: a later resume finds no digest and re-downloads fresh).
        profile_root: Option<PathBuf>,
    },
    /// (#66) Update the presented display handle in place after a rename, without a
    /// reconnect. Sets the actor's `my_handle` exactly as a `Connect{display_handle}`
    /// would, so subsequent local echoes, heartbeats, and `mine` detection present the
    /// new name. The connection proof stays the ephemeral one already established —
    /// only the *display* identity changes (D8). A no-op effect when not connected (the
    /// next Connect carries the persisted handle anyway).
    SetMyHandle { handle: String },
    /// Publish a message to the joined public room: seal it under the global room
    /// key, publish it, and LOCAL-ECHO it (the transport never reflects a
    /// sender's own frame, so the actor echoes locally).
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
    /// sub-file chunking), mint a client-side opaque `share_id`, announce the share
    /// in-band by posting a sealed `wire::ShareAnnouncement` into the lobby, and
    /// serve it from disk for the session. Mirrors `daemonseed_tui`'s
    /// `handle_publish_share` — minus the redb chunk-addr cache and the
    /// cancel/progress events, which are TUI UI affordances the GUI alpha does not
    /// surface (the manifest + served bytes are byte-identical either way).
    /// Terminal events: `PublishStarted` / `PublishError`; `PublishStopped` on
    /// unpublish, session end, or relay reap.
    ///
    /// `#[cfg_attr(not(test), allow(dead_code))]`: constructed by the in-process
    /// round-trip oracle today; the attended Shares-tab wiring constructs it in the
    /// bin (same convention as [`NetCommand::JoinCircle`]).
    #[cfg_attr(not(test), allow(dead_code))]
    PublishShare {
        root: PathBuf,
        name: String,
        sharer_handle: String,
    },
    /// Stop serving and unpublish a share published this session. Aborts the serve
    /// task and posts a withdraw `wire::ShareAnnouncement` to the lobby so
    /// listeners drop the share from their [`daemonseed_core::share_catalog::ShareCatalog`] (unified share model).
    #[cfg_attr(not(test), allow(dead_code))]
    UnpublishShare { share_id: String },
    /// Graceful-close (business-as-usual on quit): withdraw EVERY owned share, then
    /// signal `ack` once the withdraws are posted, so the UI can briefly block the
    /// close until they reach the network. The TTL backstop covers any miss. Unlike
    /// the others, this is NOT fire-and-forget — the close path waits on `ack` with a
    /// short timeout.
    // Constructed only by the windowed close handler (`desktop`); the base
    // offscreen build never builds that path, so the variant reads as dead there.
    #[cfg_attr(not(feature = "desktop"), allow(dead_code))]
    WithdrawAllOwned {
        ack: tokio::sync::oneshot::Sender<()>,
    },
    /// The single late-join hook (unified share model): post a sealed
    /// `wire::ShareRollCall` to the lobby (startup, the Refresh action, and the
    /// reconcile timer all route through here) so live sharers re-announce, then
    /// snapshot the in-band [`daemonseed_core::share_catalog::ShareCatalog`] as the `remote` rows of a single
    /// [`NetEvent::SharesSnapshot`]. Read-only; no scan. Rides the ~3 s liveness
    /// auto-poll, so it stays a cheap local re-render (no DHT work).
    #[cfg_attr(not(test), allow(dead_code))]
    RefreshShares,
    /// User-initiated re-discovery (the Refresh button): like [`NetCommand::RefreshShares`]
    /// but on Veilid it ALSO re-sweeps the lobby rendezvous to recover an announcement
    /// missed during the watch-warmup window (#133). NOT for the liveness auto-poll —
    /// the re-sweep is a DHT op, far too costly at the ~3 s poll cadence. On the relay
    /// path it maps to the ordinary roll-call refresh.
    #[cfg_attr(not(test), allow(dead_code))]
    ResweepShares,
    /// (#91) Fetch the connected relay's public space — MOTD, announcement posts,
    /// and the published signer whitelist — re-verify it client-side (trusting
    /// nothing the relay asserts), and deliver a single
    /// [`NetEvent::PublicSpaceSnapshot`]. Read-only display path; mirrors the TUI's
    /// `handle_refresh_public_space`. Constructed by the binary (the announcements
    /// pane open + the on-tab poll), like [`NetCommand::RefreshShares`].
    #[cfg_attr(not(test), allow(dead_code))]
    RefreshPublicSpace,
    /// (#92) Signer authoring: sign an announcement post with the held stable
    /// identity key ([`daemonseed_cli::public_space::sign_post`]) and upload it via `UploadPost`, then refresh
    /// the public space so the new post appears. A no-op (surfaced as
    /// [`NetEvent::PublicSpaceError`]) when no stable key is held (non-signer /
    /// ephemeral) or no session is live. The relay re-verifies the signature
    /// against the published whitelist before storing (ISC-S8). Constructed by the
    /// binary from the composer affordance (gated on `can_compose`).
    #[cfg_attr(not(test), allow(dead_code))]
    UploadAnnouncement { topic: String, body: String },
    /// (#92) Signer authoring: sign a MOTD with the held stable identity key
    /// ([`daemonseed_cli::public_space::sign_motd`], which enforces the ISC-S9 single-line-plaintext rule) and
    /// upload it via `UploadMotd` (#89), then refresh. Non-plaintext text is
    /// rejected BEFORE upload and surfaced as [`NetEvent::PublicSpaceError`]. Same
    /// no-stable-key / no-session guard as [`NetCommand::UploadAnnouncement`].
    #[cfg_attr(not(test), allow(dead_code))]
    SetMotd { text: String },
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
        /// (download-subsystem redesign, step 5) The kind of tree node the user
        /// toggled — the selection root the placement resolver maps to (ISC-C72 /
        /// DL-ISC-8). `Share` = the whole share; `File` = one file; `Dir` = a
        /// folder subtree. Drives `veilid_net::selection_roots`.
        root_kind: RootKind,
    },
}

/// (download-subsystem redesign, step 5 / DL-ISC-8) The kind of selection root a
/// `ConfirmFetch` targets — which tree node the user actually toggled, carried so
/// placement is a function of the selection (not guessed from path shapes). An
/// in-process `NetCommand` field only (main ↔ actor mpsc); never on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootKind {
    /// The share root — the whole share (every file), `selected: None`.
    Share,
    /// A single selected file (`selected: Some([one index])`).
    File,
    /// A selected directory subtree — carries the toggled folder's own
    /// manifest-relative path, so placement keeps that folder even when its
    /// contents nest deeper (a folder must NOT collapse to the common descendant
    /// prefix — F5 / DL-ISC-8). `selected: Some([its descendant indices])`.
    Dir(String),
}

/// An event from the network actor to the UI thread.
#[derive(Debug, Clone)]
pub enum NetEvent {
    /// The connection reached Authenticated — the client is attached to the Veilid
    /// network (there is no relay handle post-cutover).
    Connected,
    /// (#144) The Veilid attach peer counts, emitted as they climb during the
    /// cold-start DHT warmup — drives the startup mask's counting-up progress.
    PeerCount { reliable: u32, live: u32 },
    /// (WB-5.1 / I5″.7, WB-ISC-20) The aggregate "presence may be stale" signal
    /// toggled: the DHT regime is elevated and the reaper is suspended, holding a
    /// past-TTL member visible on some roster. The UI surfaces a "presence may be
    /// stale" indicator while `stale` is true. Emitted only on a change.
    PresenceStale { stale: bool },
    /// The connection attempt failed; `reason` is human-readable.
    ConnectFailed { reason: String },
    /// A public room is subscribed and chat can flow.
    RoomJoined,
    /// A message to render: a verified inbound frame, or a local echo of the
    /// user's own just-sent message. `mine` is true when `who == my_handle`.
    Message {
        who: String,
        text: String,
        mine: bool,
        /// Best-effort sender wall-clock (ms since epoch). The Lobby transcript is
        /// ordered + deduped by this (#126), mirroring `CircleMessage`; the age
        /// caption (#100) renders against it. Inbound uses the wire timestamp;
        /// a local echo uses `now_unix_ms()`.
        sent_unix_ms: i64,
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
        /// Best-effort sender wall-clock (ms since epoch) — the transcript is
        /// ordered by this (#105).
        sent_unix_ms: i64,
    },
    /// A non-fatal circle error (join/send failure) tagged with the circle it
    /// concerns. The connection itself may still be up.
    CircleError { circle_id: u64, reason: String },
    /// A share is now published and served; `share_id` is client-minted (opaque).
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
        /// #117: true while a (re)publish is in flight — the slow serve+advert window
        /// over Veilid, which on a reconnect made a sharer think their share had died
        /// (and re-publish it). The own-share row shows "republishing…" until a second
        /// `PublishStarted` with `republishing: false` confirms it is live.
        republishing: bool,
    },
    /// Emitted once at the start of a connect-time auto-republish, before any share is
    /// re-served, so the UI can lead with a "Restoring N shares from last session…"
    /// reassurance during the slow republish window — instead of a toast that arrives
    /// coincident with the share going live, which reads as redundant (#122).
    RestoreStarted { count: usize },
    /// A published share stopped serving (unpublish, session end, or relay reap).
    PublishStopped { share_id: String },
    /// A publish attempt failed (no session, index error, or refused RPC).
    PublishError { message: String },
    /// The in-band discovery catalog rendered as public-share rows (response to
    /// `RefreshShares` and emitted on every catalog change).
    SharesSnapshot { shares: Vec<ShareListing> },
    /// A share-listing read could not complete; the previous snapshot is unchanged.
    /// Retained as a render target (`main.rs`, matching the TUI) for a future
    /// in-band error producer; the discovery refresh is best-effort and has no
    /// producer today, so nothing constructs it yet.
    #[allow(dead_code)]
    SharesError { message: String },
    /// (#91/#92) The connected relay's verified public space — the inert verbatim
    /// MOTD (if present and verified) and the verified announcement rows — assembled
    /// client-side from verified artifacts (ISC-A-S3: nothing the relay
    /// asserts is trusted). `can_compose` (#92) is the signer-gating verdict
    /// ([`daemonseed_cli::public_space::composer_visible`]): true iff the held stable identity key is on the
    /// relay's published whitelist, gating the composer affordance — false for a
    /// non-signer or the ephemeral / no-profile path. The `main.rs` arm renders the
    /// `view` into the announcements pane and shows/hides the composer. The client
    /// never force-opens the pane; a per-relay content-hash unread dot (#142) marks
    /// changed content on every snapshot (connect + mid-session alike).
    PublicSpaceSnapshot {
        view: AnnouncementsView,
        can_compose: bool,
    },
    /// (#91) A public-space fetch could not complete (not connected, a refused RPC,
    /// or a malformed whitelist). The previous pane content is left unchanged.
    PublicSpaceError { message: String },
    /// A live room roster (#74/#75 lobby; #77 circles): the set of currently-present
    /// members, keyed internally by pubkey (so two members with identical display
    /// names are two distinct rows). `circle_id` names the room the roster is for —
    /// `None` is the lobby, `Some(id)` is that joined circle — so the UI updates only
    /// the active room's people column (a background room's roster updates its
    /// tracker net-side without changing the visible column). Pushed on a
    /// roster-changing `ApplyHeartbeat` (a member appeared, or a refresh changed a
    /// displayed handle) and whenever a heartbeat tick reaped ≥ 1 member from that
    /// room — so a reap-to-empty pushes an empty roster. The Slint roster UI that
    /// renders this is the right-hand roster column (#75); the `main.rs` arm replaces
    /// the Slint `roster` model from `entries` when `circle_id` is the active room.
    Roster {
        circle_id: Option<u64>,
        entries: Vec<RosterEntry>,
    },
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
}

/// One row of the live Lobby roster ([`NetEvent::Roster`], #74/#75). Built from a
/// verified [`daemonseed_core::presence::LiveMember`]: `handle` is the member's
/// advisory display handle (`name#12hex`), while `fingerprint` is the canonical
/// `#12hex` derived from the VERIFIED `sender_pubkey` (ISC-C4 / ISC-C57 binding,
/// via [`member_fingerprint`]) — the UI shows `fingerprint` as the trust anchor,
/// not the self-asserted handle. Two members with identical display names produce
/// two distinct entries because the tracker keys by pubkey.
///
/// `#[cfg_attr(not(test), allow(dead_code))]`: the producer is wired in this half;
/// the Slint roster pane that consumes the fields is #75 half two, so the bin build
/// would otherwise warn the fields unread (a binary crate's `pub` does not escape).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub handle: String,
    pub fingerprint: String,
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
        // A self-command sender the actor clones so detached tasks (the lobby
        // inbound reader, the reconcile timer) can post discovery commands back
        // into the one command loop, keeping all catalog mutation on `&mut self`.
        let cmd_tx_actor = cmd_tx.clone();
        let thread = std::thread::Builder::new()
            .name("daemonseed-gui-net".to_owned())
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

/// True if `root` is the home directory, an ancestor of it, or the filesystem root —
/// directories we must never recursively hash for a share. A picker that returns the
/// default dir (some xdg portals do) would otherwise index all of `$HOME` and hang.
/// Canonicalizes both sides; falls back to the raw path if that fails.
pub(crate) fn is_unsafe_publish_root(root: &std::path::Path) -> bool {
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

/// A safe single-component folder name derived from a share's display name: path
/// separators and control chars become `_`, leading/trailing dots+space trimmed,
/// empty falls back to `share`.
pub(crate) fn safe_folder_name(name: &str) -> String {
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

/// Wall-clock now in unix milliseconds (advisory message timestamp). Mirrors the
/// TUI's `now_unix_ms`. Test-only: the transport paths carry their own clock; this
/// remains as a fixture for the roster/presence unit tests.
#[cfg(test)]
fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The canonical `#12hex` member fingerprint bound to a VERIFIED pubkey — the
/// ISC-C4 / ISC-C57 trust anchor the roster shows instead of the self-asserted
/// handle. Reuses [`Handle::from_pubkey`] (which computes `SHA-384(pubkey)[:12]`
/// and renders the floor `#<12hex>` form) so the GUI never rolls its own hash and
/// the fingerprint matches every other surface. A pubkey that cannot be hashed
/// (an entropy/length failure inside `from_pubkey`) yields a bare `#` sentinel —
/// degenerate but never a panic; the member still appears, just without a usable
/// fingerprint, which is strictly safer than dropping a live roster row.
fn member_fingerprint(pubkey: &[u8]) -> String {
    Handle::from_pubkey(None, pubkey)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| "#".to_owned())
}

/// Build our own canonical `name#<12hex>` wire handle from a display name and our
/// identity pubkey. Receivers bind the shown author with [`Handle::display_bound`],
/// which honors the name ONLY when the transmitted handle carries the matching
/// `#<hash>` — a BARE name is unparseable and floors to `#<hex>`. So the sender
/// must transmit the canonical form (matching what the TUI's `own_handle()` sends).
/// Any `#`-suffix on `display` is stripped first (the name is the pre-`#` segment);
/// falls back to `display` verbatim only if the pubkey can't be hashed.
pub(crate) fn canonical_wire_handle(display: &str, pubkey: &[u8]) -> String {
    let name = display.split('#').next().unwrap_or(display);
    Handle::from_pubkey((!name.is_empty()).then(|| name.to_owned()), pubkey)
        .map(|h| h.format(DisplayMode::Verify))
        .unwrap_or_else(|_| display.to_owned())
}

/// The self-filter predicate (#74/#77): true when a beacon's signer pubkey is our
/// OWN identity key, so a daemon never lists itself as a live OTHER member. The
/// relay should never fan a sender's own beacon back, but this filters it
/// defensively at ingest, for the lobby and every circle alike. Extracted so the
/// per-room self-filter is unit-testable independently of the actor.
pub(crate) fn beacon_is_own(own_pubkey: &[u8], beacon_pubkey: &[u8]) -> bool {
    own_pubkey == beacon_pubkey
}

/// Whether a [`PresenceChange`] from `apply` changes what the roster renders: a
/// member appearing always does; a refresh only when it changed the displayed
/// handle (a same-handle refresh is invisible to the UI); an unchanged apply never
/// does. Shared by the lobby and per-circle ingest so both push a fresh roster on
/// exactly the same condition.
pub(crate) fn roster_render_changed(
    change: PresenceChange,
    prior_handle: Option<&str>,
    new_handle: &str,
) -> bool {
    match change {
        // Appeared/Departed both change the roster membership; a leave tombstone
        // (WB-1.3) removes a row, so it must re-render.
        PresenceChange::Appeared | PresenceChange::Departed => true,
        PresenceChange::Refreshed => prior_handle != Some(new_handle),
        PresenceChange::Unchanged => false,
    }
}

/// Build the roster rows from a presence tracker's current members. Mirrors
/// [`daemonseed_core::presence::PresenceTracker::members`] ordering (handle, then pubkey) for a stable view,
/// and binds each row's `fingerprint` to the verified pubkey via
/// [`member_fingerprint`]. Keying lives in the tracker (by pubkey), so two members
/// sharing a display name yield two distinct rows here.
pub(crate) fn roster_from_members(members: &[LiveMember]) -> Vec<RosterEntry> {
    members
        .iter()
        .map(|m| RosterEntry {
            handle: m.handle.clone(),
            fingerprint: member_fingerprint(&m.pubkey),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::circle::key::derive_cot_key;
    use daemonseed_core::circle::message::{open_message, seal_message};
    use daemonseed_core::cot::{asset_address, public_share_asset_address};
    use daemonseed_core::crypto::suite::CNSA_2_0;
    use daemonseed_core::heartbeat::{
        HeartbeatFields, open_heartbeat, seal_circle_heartbeat, seal_public_heartbeat,
    };
    use daemonseed_core::presence::{
        HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT, PresenceTracker,
    };
    use daemonseed_core::public_room::{DEFAULT_ROOM, derive_room_key, room_asset_address};
    use daemonseed_proto::v1 as wire;
    use std::time::{Duration, Instant};

    #[test]
    fn republish_name_prefers_persisted_else_basename() {
        // #41 wiring: a persisted wire-facing name wins over the root basename.
        assert_eq!(
            republish_name(Path::new("/home/alice/2026-trip"), Some("trip-photos")),
            "trip-photos"
        );
        // No persisted name → the directory basename (the legacy fallback).
        assert_eq!(
            republish_name(Path::new("/home/alice/trip-photos"), None),
            "trip-photos"
        );
        // An empty persisted name is treated as absent → basename.
        assert_eq!(republish_name(Path::new("/srv/docs"), Some("")), "docs");
        // Degenerate root with no basename → "share".
        assert_eq!(republish_name(Path::new("/"), None), "share");
    }

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
        assert!(open_room_message(&lobby, DEFAULT_ROOM, &sealed).is_ok());
        // A non-member (wrong key) cannot — exactly what the actor's reader drops.
        assert!(
            open_room_message(&other, DEFAULT_ROOM, &sealed).is_err(),
            "a non-member must not decrypt the public-room frame"
        );
    }

    /// A genuinely-strong 12-word phrase for circle tests (join doesn't gate in the
    /// actor; the GUI gates before calling, so any phrase derives a key here).
    const CIRCLE_PHRASE: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

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
        let signer = SignKeypair::from_ml_dsa_seed(&[0x33; 32]).unwrap();
        let sealed =
            seal_message(&member, &signer, "wandering-otter", "secret circle line", 1).unwrap();
        assert!(open_message(&member, &sealed).is_ok(), "a member opens it");
        assert!(
            open_message(&outsider, &sealed).is_err(),
            "a non-member (wrong circle key) must not decrypt the circle frame"
        );
    }

    // ── Presence / Lobby roster (#74/#75 half one) ───────────────────────────
    //
    // These exercise the roster-building + push-decision logic the GUI net actor
    // adds on top of `daemonseed_core::presence` (which is itself unit-tested in
    // core). They use the core seal/open primitives the actor's inbound reader
    // uses, so the "sealed beacon → roster" path is real, not faked.
    mod presence_roster {
        use super::*;
        use daemonseed_core::identity::keys::SignKeypair;

        /// A wire heartbeat as `seal_public_heartbeat`/`open_heartbeat` would yield
        /// (provenance fields populated by the seal path). Built directly here to
        /// drive the tracker/roster logic without a relay.
        fn heartbeat(pubkey: &[u8], handle: &str, sent_unix_ms: i64) -> wire::MemberHeartbeat {
            wire::MemberHeartbeat {
                room: DEFAULT_ROOM.to_owned(),
                sender_pubkey: pubkey.to_vec(),
                sender_handle: handle.to_owned(),
                sent_unix_ms,
                signature: vec![9, 9, 9],
                live_share_ids: vec![],
                is_leave: false,
            }
        }

        /// Guardrail 1: the roster keys by pubkey, never handle — two members with
        /// IDENTICAL display names produce two DISTINCT rows.
        #[test]
        fn identical_display_names_are_two_rows() {
            let _ = oxicrypt_module::initialize(); // SHA-384 self-test must pass for fingerprints
            let mut t = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
            let now = Instant::now();
            t.apply(&heartbeat(b"pubkey-a", "twin#aaaa", 100), now);
            t.apply(&heartbeat(b"pubkey-b", "twin#bbbb", 100), now);
            let rows = roster_from_members(&t.members());
            assert_eq!(
                rows.len(),
                2,
                "two distinct pubkeys must be two roster rows"
            );
            // Same advisory handle, but distinct pubkey-bound fingerprints.
            assert_eq!(rows[0].handle, "twin#aaaa");
            assert_eq!(rows[1].handle, "twin#bbbb");
            assert_ne!(
                rows[0].fingerprint, rows[1].fingerprint,
                "fingerprint must be bound to the pubkey, so identical handles differ"
            );
        }

        /// The fingerprint is the canonical `#12hex` derived from the VERIFIED
        /// pubkey (ISC-C4), reusing `Handle::from_pubkey` — not a GUI-local hash.
        #[test]
        fn fingerprint_matches_handle_from_pubkey() {
            let _ = oxicrypt_module::initialize(); // SHA-384 self-test must pass for fingerprints
            let pubkey = b"some-verified-ml-dsa-pubkey-bytes";
            let fp = member_fingerprint(pubkey);
            let expected = Handle::from_pubkey(None, pubkey).unwrap().to_string();
            assert_eq!(fp, expected);
            assert!(fp.starts_with('#'), "floor form is #<12hex>: {fp}");
            assert_eq!(fp.len(), 1 + 12, "12 hex chars after the #: {fp}");
        }

        /// A sealed beacon, opened under the lobby key and applied, appears in the
        /// roster; after the TTL elapses a `reap` ages it out. Uses the REAL
        /// seal/open primitives (the actor's path), so this is the sealed-beacon →
        /// roster end-to-end (sans relay).
        #[test]
        fn sealed_beacon_appears_then_reaps() {
            let _ = oxicrypt_module::initialize();
            let lobby = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
            let member = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).unwrap();
            let fields = HeartbeatFields {
                room: DEFAULT_ROOM,
                sender_handle: "wandering-otter#abc",
                sent_unix_ms: now_unix_ms(),
                live_share_ids: &[],
                is_leave: false,
            };
            let sealed = seal_public_heartbeat(&lobby, &member, &fields).unwrap();
            // The actor's inbound reader opens it under the lobby key.
            let hb = open_heartbeat(&lobby, &sealed).expect("verified beacon opens");
            assert_eq!(hb.sender_pubkey, member.public_key().to_vec());

            let mut t = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
            let t0 = Instant::now();
            assert_eq!(t.apply(&hb, t0), PresenceChange::Appeared);
            let rows = roster_from_members(&t.members());
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].handle, "wandering-otter#abc");
            // The fingerprint is bound to the VERIFIED pubkey, not the advisory handle.
            assert_eq!(rows[0].fingerprint, member_fingerprint(member.public_key()));

            // Past the TTL → reaped → empty roster.
            let past_ttl = t0 + t.ttl() + Duration::from_secs(1);
            assert_eq!(t.reap(past_ttl, false).len(), 1, "the lone member ages out");
            assert!(roster_from_members(&t.members()).is_empty());
        }

        /// Guardrail 2 (the push predicate): the actor pushes a roster on a reap that
        /// removed ≥ 1 member, predicated on the REMOVED set — so a reap-to-empty
        /// still pushes (an empty roster). Models the `handle_emit_heartbeat` reap
        /// branch: `reaped_any = !reap().is_empty()` gates the push. A member appears
        /// (one push), then reaps to empty (a second push, empty).
        #[test]
        fn reap_to_empty_still_pushes_empty_roster() {
            let mut t = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
            let t0 = Instant::now();

            // Push 1: a member appears (the apply path pushes on Appeared).
            let mut pushes: Vec<Vec<RosterEntry>> = Vec::new();
            assert_eq!(
                t.apply(&heartbeat(b"pk", "lone#dddd", 100), t0),
                PresenceChange::Appeared
            );
            pushes.push(roster_from_members(&t.members()));

            // Push 2: a later tick reaps the now-stale member. The emit handler's
            // predicate is "did reap remove anything?" — true here, so it pushes the
            // resulting (empty) roster.
            let past_ttl = t0 + t.ttl() + Duration::from_secs(1);
            let reaped_any = !t.reap(past_ttl, false).is_empty();
            assert!(reaped_any, "the member must have been reaped");
            pushes.push(roster_from_members(&t.members()));

            assert_eq!(pushes.len(), 2, "appear then reap-to-empty = two pushes");
            assert_eq!(pushes[0].len(), 1, "first push has the member");
            assert!(pushes[1].is_empty(), "second push is the empty roster");
        }

        /// A no-op reap (nothing aged out) does NOT push — the predicate is on the
        /// removed set, not on calling reap.
        #[test]
        fn reap_that_removes_nothing_does_not_push() {
            let mut t = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
            let t0 = Instant::now();
            t.apply(&heartbeat(b"pk", "fresh#eeee", 100), t0);
            // Well within the TTL → nothing reaped → no push.
            let reaped_any = !t.reap(t0 + Duration::from_secs(1), false).is_empty();
            assert!(
                !reaped_any,
                "a fresh member is not reaped, so no roster push"
            );
        }

        /// A same-handle refresh is invisible to the rendered roster, so the apply
        /// path does NOT push for it; only an Appeared or a handle-changing Refresh
        /// pushes. Models the `roster_changed` predicate in `handle_apply_heartbeat`.
        #[test]
        fn same_handle_refresh_does_not_push() {
            let mut t = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
            let t0 = Instant::now();
            t.apply(&heartbeat(b"pk", "otter#ffff", 100), t0);

            // A newer beacon, SAME handle → Refreshed but the roster render is
            // unchanged, so the predicate must be false.
            let prior = t
                .members()
                .into_iter()
                .find(|m| m.pubkey == b"pk".to_vec())
                .map(|m| m.handle);
            let hb = heartbeat(b"pk", "otter#ffff", 200);
            assert_eq!(
                t.apply(&hb, t0 + Duration::from_secs(1)),
                PresenceChange::Refreshed
            );
            let roster_changed = prior.as_deref() != Some(hb.sender_handle.as_str());
            assert!(
                !roster_changed,
                "a same-handle refresh must not push a roster"
            );

            // A handle-CHANGING refresh → push.
            let prior2 = t
                .members()
                .into_iter()
                .find(|m| m.pubkey == b"pk".to_vec())
                .map(|m| m.handle);
            let hb2 = heartbeat(b"pk", "otter-renamed#ffff", 300);
            assert_eq!(
                t.apply(&hb2, t0 + Duration::from_secs(2)),
                PresenceChange::Refreshed
            );
            let roster_changed2 = prior2.as_deref() != Some(hb2.sender_handle.as_str());
            assert!(
                roster_changed2,
                "a handle-changing refresh must push a roster"
            );
        }

        // ── Circle presence (#77) ────────────────────────────────────────────
        //
        // The same roster-building logic over a CIRCLE-keyed beacon: sealed under a
        // circle key, it opens only under that circle's key (relay-blind /
        // wrong-circle isolation), surfaces the member, then reaps live-only.

        /// #77 circle presence: a beacon sealed under a circle's key opens ONLY under
        /// that same circle key (relay-blind, ISC-A-S2; wrong-circle isolation), and
        /// the opened beacon surfaces the member in that circle's tracker, then ages
        /// out on reap. Uses the REAL `seal_circle_heartbeat` / `open_heartbeat`
        /// primitives the actor's circle reader uses — the sealed-circle-beacon →
        /// roster path end-to-end (sans relay).
        #[test]
        fn circle_beacon_opens_under_its_key_only_then_rosters() {
            let _ = oxicrypt_module::initialize();
            let circle_a = derive_cot_key("alpha circle phrase one", &CNSA_2_0).unwrap();
            let circle_b = derive_cot_key("beta circle phrase two", &CNSA_2_0).unwrap();
            let member = SignKeypair::from_ml_dsa_seed(&[5u8; 32]).unwrap();
            let fields = HeartbeatFields {
                // The circle beacon seals the deterministic client-local label as its
                // room (mirrors the actor's `default_circle_label`); the value only
                // binds provenance — it is never matched on the receive side.
                room: "jolly-otter",
                sender_handle: "wandering-otter#abc",
                sent_unix_ms: now_unix_ms(),
                live_share_ids: &[],
                is_leave: false,
            };
            let sealed = seal_circle_heartbeat(&circle_a, &member, &fields).unwrap();

            // Wrong circle key cannot open it — a different circle's members never
            // see it, and neither does the relay (it holds no circle key at all).
            assert!(
                open_heartbeat(&circle_b, &sealed).is_err(),
                "a beacon sealed under circle A must not open under circle B"
            );

            // The actor's circle reader opens it under THIS circle's key, then applies.
            let hb = open_heartbeat(&circle_a, &sealed).expect("verified circle beacon opens");
            assert_eq!(hb.sender_pubkey, member.public_key().to_vec());
            let mut t = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
            let t0 = Instant::now();
            assert_eq!(t.apply(&hb, t0), PresenceChange::Appeared);
            let rows = roster_from_members(&t.members());
            assert_eq!(rows.len(), 1, "the circle member appears in the roster");
            assert_eq!(rows[0].handle, "wandering-otter#abc");
            assert_eq!(rows[0].fingerprint, member_fingerprint(member.public_key()));

            // Past the TTL → reaped → the circle roster empties (live-only).
            let past_ttl = t0 + t.ttl() + Duration::from_secs(1);
            assert_eq!(
                t.reap(past_ttl, false).len(),
                1,
                "the circle member ages out"
            );
            assert!(roster_from_members(&t.members()).is_empty());
        }

        /// The self-filter predicate drops a daemon's OWN beacon (so it never lists
        /// itself) while admitting every other member — the per-room filter
        /// `handle_apply_heartbeat` runs before routing to the lobby or any circle.
        #[test]
        fn self_filter_drops_own_beacon_only() {
            let _ = oxicrypt_module::initialize();
            let me = SignKeypair::from_ml_dsa_seed(&[1u8; 32]).unwrap();
            let other = SignKeypair::from_ml_dsa_seed(&[2u8; 32]).unwrap();
            assert!(
                beacon_is_own(me.public_key(), me.public_key()),
                "our own beacon is filtered"
            );
            assert!(
                !beacon_is_own(me.public_key(), other.public_key()),
                "another member's beacon is admitted"
            );
        }

        /// The shared roster-push predicate: a new member always pushes; a refresh
        /// pushes only when the displayed handle changed; an unchanged apply never
        /// does. The single source the lobby and per-circle ingest both gate on.
        #[test]
        fn roster_render_changed_matrix() {
            assert!(roster_render_changed(PresenceChange::Appeared, None, "a#1"));
            assert!(roster_render_changed(
                PresenceChange::Refreshed,
                Some("a#1"),
                "a-renamed#1"
            ));
            assert!(!roster_render_changed(
                PresenceChange::Refreshed,
                Some("a#1"),
                "a#1"
            ));
            assert!(!roster_render_changed(
                PresenceChange::Unchanged,
                Some("a#1"),
                "a#1"
            ));
        }
    }
}
