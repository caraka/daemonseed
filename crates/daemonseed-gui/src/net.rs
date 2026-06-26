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

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use crate::state::{AnnouncementsView, build_announcements_view};
use daemonseed_cli::connect::connect_session;
use daemonseed_cli::identity_proof::ClientIdentity;
use daemonseed_cli::public_space::{composer_visible, sign_motd, sign_post};
use daemonseed_cli::session::AppSession;
use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::{CircleKey, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::{AssetAddr, asset_address, public_share_asset_address};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::heartbeat::{
    HeartbeatFields, open_heartbeat, seal_circle_heartbeat, seal_public_heartbeat,
};
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::indexer::{CachedHashError, cached_or_hash};
use daemonseed_core::presence::{
    HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT, LiveMember, PresenceChange, PresenceTracker,
    beacon_is_fresh, next_heartbeat_interval,
};
use daemonseed_core::public_room::{
    DEFAULT_ROOM, PublicRoomKey, derive_room_key, open_room_message, room_asset_address,
    seal_room_message,
};
use daemonseed_core::share_announce::{
    AnnouncementFields, mint_share_id, open_announcement, seal_public_announcement,
};
use daemonseed_core::share_catalog::{CatalogChange, ShareCatalog, ShareListing};
use daemonseed_core::share_envelope::{ManifestEntry, ShareFrame};
use daemonseed_core::share_rollcall::{RollCallFields, open_rollcall, seal_public_rollcall};
use daemonseed_core::share_seal::{open_share_frame, seal_public_share_frame};
use daemonseed_core::share_serve::{DiskShareContent, ServeError};
use daemonseed_core::storage::cas::chunk_addr;
use daemonseed_core::storage::fetched::rebase_to_selection_root;
use daemonseed_core::storage::seeds::{CounterState, IndexKey};
use daemonseed_core::storage::share_index::{ShareIndex, per_share_index_filename};
use daemonseed_proto::v1 as wire;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// The wire-facing name for an auto-republished share (M16 restore path, #41):
/// the persisted [`daemonseed_core::storage::seeds::PublishedShare`] `name` when
/// one was stored, else the root directory's basename, else `"share"`. Centralizes
/// the choice both republish loops make so the persisted name is consumed
/// consistently. (The name-a-share UI that would set a non-`None` persisted name is
/// a separate follow-up; today the persisted slot is `None` and this falls back to
/// the basename — unchanged behavior — but the wiring now carries a name end to end.)
fn republish_name(root: &Path, persisted: Option<&str>) -> String {
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
        server_id: String,
        address: String,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
        /// (M16) persisted published-share roots (directory paths) to silently
        /// re-publish once the session is live — read from the at-rest blob, served
        /// after the lobby auto-join exactly like `rejoin_circles`. Each republish
        /// uses the directory basename as the share name and `display_handle` as the
        /// sharer handle. Empty for the ephemeral / no-profile path.
        republish_roots: Vec<(PathBuf, Option<String>)>,
        /// (#81) the persisted share-index location + key for the unlocked profile:
        /// `(index_path, index_key)`, where `index_path` is
        /// `profile_root/share-index.redb` (mirroring the TUI) and `index_key` is
        /// the share-index key from [`SessionMaterials`]
        /// (`daemonseed_core::first_start::SessionMaterials::index_key`). Opened ONCE
        /// (create-if-absent) here, BEFORE the connect-time republish loop, so an
        /// unchanged share's republish reuses the persisted chunk-address cache
        /// (cache hits only — no from-scratch re-hash). `None` on the ephemeral /
        /// no-profile path: with no profile root there is nowhere to persist the
        /// cache, so a publish falls back to hashing fresh (no index). The key is
        /// carried in the redacted [`IndexKey`] newtype so it never lands in a
        /// `Debug` log.
        index_params: Option<(PathBuf, IndexKey)>,
        /// (#92) the unlocked profile's STABLE persistent identity signing key
        /// (`Profile::stable_signing_key` — `derive_identity_keys(.., Primary)`),
        /// the key behind the `name#hash` handle an operator whitelists. Derived
        /// ONCE on the UI thread and handed over so the actor can gate the composer
        /// (`composer_visible` against the published whitelist) and SIGN
        /// MOTD/announcements — NOT the ephemeral connection-proof key. `None` on
        /// the ephemeral / no-profile path (read-only public space, no composer).
        stable_signing_key: Option<SignKeypair>,
    },
    /// (#66) Update the presented display handle in place after a rename, without a
    /// reconnect. Sets the actor's `my_handle` exactly as a `Connect{display_handle}`
    /// would, so subsequent local echoes, heartbeats, and `mine` detection present the
    /// new name. The connection proof stays the ephemeral one already established —
    /// only the *display* identity changes (D8). A no-op effect when not connected (the
    /// next Connect carries the persisted handle anyway).
    SetMyHandle { handle: String },
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
    /// sub-file chunking), mint a client-side opaque `share_id`, announce the share
    /// in-band by posting a sealed [`wire::ShareAnnouncement`] into the lobby, and
    /// serve it from disk for the session. Mirrors `daemonseed_tui`'s
    /// `handle_publish_share` — minus the redb chunk-addr cache and the
    /// cancel/progress events, which are TUI UI affordances the GUI alpha does not
    /// surface (the manifest + served bytes are byte-identical either way).
    /// Terminal events: `PublishStarted` / `PublishError`; `PublishStopped` on
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
    /// Stop serving and unpublish a share published this session. Aborts the serve
    /// task and posts a withdraw [`wire::ShareAnnouncement`] to the lobby so
    /// listeners drop the share from their [`ShareCatalog`] (unified share model).
    #[cfg_attr(not(test), allow(dead_code))]
    UnpublishShare { share_id: String },
    /// The single late-join hook (unified share model): post a sealed
    /// [`wire::ShareRollCall`] to the lobby (startup, the Refresh action, and the
    /// reconcile timer all route through here) so live sharers re-announce, then
    /// snapshot the in-band [`ShareCatalog`] as the `remote` rows of a single
    /// [`NetEvent::SharesSnapshot`]. Read-only; no scan.
    #[cfg_attr(not(test), allow(dead_code))]
    RefreshShares,
    /// (#91) Fetch the connected relay's public space — MOTD, announcement posts,
    /// and the published signer whitelist — re-verify it client-side (trusting
    /// nothing the relay asserts), and deliver a single
    /// [`NetEvent::PublicSpaceSnapshot`]. Read-only display path; mirrors the TUI's
    /// `handle_refresh_public_space`. Constructed by the binary (the announcements
    /// pane open + the on-tab poll), like [`NetCommand::RefreshShares`].
    #[cfg_attr(not(test), allow(dead_code))]
    RefreshPublicSpace,
    /// (#92) Signer authoring: sign an announcement post with the held stable
    /// identity key ([`sign_post`]) and upload it via `UploadPost`, then refresh
    /// the public space so the new post appears. A no-op (surfaced as
    /// [`NetEvent::PublicSpaceError`]) when no stable key is held (non-signer /
    /// ephemeral) or no session is live. The relay re-verifies the signature
    /// against the published whitelist before storing (ISC-S8). Constructed by the
    /// binary from the composer affordance (gated on `can_compose`).
    #[cfg_attr(not(test), allow(dead_code))]
    UploadAnnouncement { topic: String, body: String },
    /// (#92) Signer authoring: sign a MOTD with the held stable identity key
    /// ([`sign_motd`], which enforces the ISC-S9 single-line-plaintext rule) and
    /// upload it via `UploadMotd` (#89), then refresh. Non-plaintext text is
    /// rejected BEFORE upload and surfaced as [`NetEvent::PublicSpaceError`]. Same
    /// no-stable-key / no-session guard as [`NetCommand::UploadAnnouncement`].
    #[cfg_attr(not(test), allow(dead_code))]
    SetMotd { text: String },
    /// Internal: a verified lobby [`wire::ShareAnnouncement`] the inbound reader
    /// opened, to fold into the actor's [`ShareCatalog`] (all catalog mutation
    /// stays on `&mut self`). Posted by [`read_inbound_public_room`]; never sent
    /// by the binary. Emits a fresh [`NetEvent::SharesSnapshot`] on a real change.
    ApplyAnnouncement(Box<wire::ShareAnnouncement>),
    /// Internal: a verified lobby [`wire::ShareRollCall`] the inbound reader
    /// opened — re-announce every own share so the requester discovers them.
    /// Posted by [`read_inbound_public_room`]; never sent by the binary.
    AnswerRollCall,
    /// Internal: the presence-heartbeat tick (#74) — emit one sealed member beacon
    /// into the lobby (if joined), then `reap` the lobby tracker so members past
    /// their TTL age out (the timer is the reap clock too). Self-scheduled on
    /// [`next_heartbeat_interval`]; spawned ONCE for the actor's life so a
    /// reconnect/rejoin never double-emits. A no-op when no lobby is joined or no
    /// identity is held. Never sent by the binary.
    EmitHeartbeat,
    /// Internal: a verified member heartbeat the inbound reader opened, to fold into
    /// the lobby's [`PresenceTracker`] (all tracker mutation stays on `&mut self`).
    /// `room` is the session-local routing key (the lobby room name). Boxed because
    /// [`wire::MemberHeartbeat`] is large (mirrors [`Self::ApplyAnnouncement`]).
    /// Posted by [`read_inbound_public_room`]; never sent by the binary.
    ApplyHeartbeat {
        room: String,
        heartbeat: Box<wire::MemberHeartbeat>,
    },
    /// Internal: the slow-reconcile tick — prune aged-out catalog entries and
    /// post a roll-call. Self-scheduled on [`RECONCILE_INTERVAL`]; never sent by
    /// the binary.
    ReconcileShares,
    /// Internal (#71): a backoff-timer tick — re-issue the stored [`ConnectPlan`]
    /// to re-establish the connection (and silently re-join circles / re-publish
    /// shares like a fresh launch). Self-scheduled by [`Actor::arm_reconnect`] on
    /// capped exponential backoff while disconnected. Never sent by the binary.
    Reconnect,
    /// Internal (#80): the lobby subscribe stream ended (`Ok(None)` end-of-stream
    /// OR `Err`). Because a half-open connection ALSO surfaces as end-of-stream
    /// (the relay's GOAWAY), the reader can't tell a graceful per-stream EOS from a
    /// dead connection by the result code alone — so it asks the actor to RE-SUBSCRIBE
    /// the lobby on the live session. A successful re-subscribe proves the
    /// authenticated connection is still up (the channel rides one already-opened
    /// stream, [`AppSession::open`] — there is no transparent re-dial), so circles
    /// and serve tasks are left intact; a failed one means the connection is dead,
    /// and the handler tears down + reconnects via [`Actor::handle_disconnected`]
    /// (#72/#71). Posted by [`read_inbound_public_room`]; never sent by the binary.
    ResubscribeRoom,
    /// Internal (#80): one circle's subscribe stream ended (`Ok(None)` or `Err`) —
    /// re-subscribe just THAT circle on the live session (same active-probe rationale
    /// as [`NetCommand::ResubscribeRoom`]). Posted by [`read_inbound_circle`]; never
    /// sent by the binary. A `circle_id` no longer in the joined set (already torn
    /// down) is a no-op (never resurrected).
    ResubscribeCircle { circle_id: u64 },
    /// TEST SEAM (never used in production): drive the post-reconnect re-establish
    /// path with a fresh in-memory [`AppSession`] instead of a real TCP `Connect`,
    /// so the in-process oracle exercises the SAME re-subscribe logic the backoff
    /// timer triggers. Carries the same `rejoin_circles` the stored plan would.
    #[doc(hidden)]
    #[cfg(test)]
    ReattachSession {
        session: AppSession,
        server_id: String,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
    },
    /// TEST SEAM (never used in production): ask the actor to emit its current
    /// `connected` flag as a [`NetEvent::ConnectedProbe`], so the oracle can assert
    /// the post-drop teardown (#72) without a side channel into actor state.
    #[doc(hidden)]
    #[cfg(test)]
    ProbeConnected,
    /// TEST SEAM (#81, never used in production): set the persisted-index home
    /// (`index_dir` + `index_key`) the SAME way a real `Connect{index_params}` does,
    /// so a publish opens its per-share index file under it — letting a test prove the
    /// publish path reuses the persisted chunk-address cache without a real Connect.
    #[doc(hidden)]
    #[cfg(test)]
    SetIndexHome {
        index_dir: PathBuf,
        index_key: IndexKey,
    },
    /// TEST SEAM (#81, never used in production): emit the first cached chunk address
    /// the per-share index for `root` holds for `rel_path` as a
    /// [`NetEvent::CachedAddrProbe`] — `None` if no index for `root`, no entry, or no
    /// cached blob. Lets the oracle assert a republish was a cache HIT (the address is
    /// unchanged even after the file's bytes are rewritten at the same size+mtime)
    /// rather than a re-hash.
    #[doc(hidden)]
    #[cfg(test)]
    ProbeCachedAddr { root: PathBuf, rel_path: String },
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
    /// A live connection dropped — a subscribe stream ended (`Ok(None)`) or
    /// errored (`Err`, e.g. an h2 keepalive PING went unanswered on a half-open
    /// socket). The actor has cleared its stale session/server-id so no half-open
    /// state is reused (#72); the UI shows offline. Auto-reconnect (#71) is armed
    /// when a prior successful connect plan exists; `reason` is human-readable.
    Disconnected { reason: String },
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
    },
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
    /// client-side by [`build_announcements_view`] (ISC-A-S3: nothing the relay
    /// asserts is trusted). `can_compose` (#92) is the signer-gating verdict
    /// ([`composer_visible`]): true iff the held stable identity key is on the
    /// relay's published whitelist, gating the composer affordance — false for a
    /// non-signer or the ephemeral / no-profile path. The `main.rs` arm renders the
    /// `view` into the announcements pane and shows/hides the composer.
    ///
    /// `connect_time` (#93) marks the snapshot produced by the automatic
    /// connect-time fetch (vs a manual Refresh / on-tab poll / post-upload
    /// refresh). The unread gate auto-opens the announcements pane ONLY on a
    /// connect-time snapshot, so a manual refresh never yanks the user away.
    PublicSpaceSnapshot {
        view: AnnouncementsView,
        can_compose: bool,
        connect_time: bool,
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
    /// TEST SEAM (never produced in production): the actor's current `connected`
    /// flag, emitted in response to [`NetCommand::ProbeConnected`] so the in-process
    /// oracle can assert the actor cleared its live state after a drop (#72) and
    /// restored it after reconnect (#71).
    #[doc(hidden)]
    #[cfg(test)]
    ConnectedProbe { connected: bool },
    /// TEST SEAM (#81): the first cached chunk address the open share index holds for
    /// the probed `rel_path` (48-byte [`daemonseed_core::storage::cas::ChunkAddr`]
    /// bytes), or `None` if there is no entry / no cached blob. Reply to
    /// [`NetCommand::ProbeCachedAddr`].
    #[doc(hidden)]
    #[cfg(test)]
    CachedAddrProbe { addr: Option<Vec<u8>> },
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
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread net runtime");
                let local = tokio::task::LocalSet::new();
                // `spawn_local` (the inbound reader) is run INSIDE this
                // `run_until` context — the reader holds an `Rc` of the room key,
                // so it cannot ride a multi-thread runtime.
                rt.block_on(local.run_until(net_actor(cmd_rx, cmd_tx_actor, evt_tx)));
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
    room_key: Rc<daemonseed_core::public_room::PublicRoomKey>,
    /// The room's rendezvous address on the connected relay.
    asset_addr: daemonseed_core::cot::AssetAddr,
    /// Outbound frame sender — publishing seals + sends here.
    out_tx: mpsc::Sender<wire::CotFrame>,
    /// Member-presence roster for this lobby (#74/#75): verified member beacons
    /// fold in via [`PresenceTracker::apply`]; the heartbeat timer `reap`s it. A
    /// FRESH tracker is built per [`PublicRoom`] construction (so a leave/rejoin
    /// never shows stale members). Cadence-matched to the emit interval.
    presence: PresenceTracker,
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
    cot_key: Rc<CircleKey>,
    /// Per-relay rendezvous address; the dedupe key for idempotent re-join.
    asset_addr: AssetAddr,
    /// Outbound frame sender — sealing seals + sends here. Replaced (not the whole
    /// entry) when this circle's stream is re-subscribed after an EOS (#80).
    out_tx: mpsc::Sender<wire::CotFrame>,
    /// #80 flap detector for THIS circle's re-subscribe path.
    resub: BurstGuard,
    /// Member-presence roster for THIS circle (#77): verified circle beacons fold
    /// in via [`PresenceTracker::apply`]; the heartbeat timer `reap`s it. A FRESH
    /// tracker is built when the circle is joined (so a leave/rejoin never shows
    /// stale members), cadence-matched to the emit interval. Mirrors
    /// `daemonseed_tui::net::Circle::presence`; dropped with the circle, so circle
    /// presence is inherently live-only (no stale roster survives a teardown).
    presence: PresenceTracker,
}

/// A share this daemon is publishing this session — the in-band-discovery
/// replacement for the relay registry's owner-scoped record. Held so a roll-call
/// can re-announce every live share (the slow-reconcile / late-join response) and
/// an unpublish can post a matching withdraw. The serve task itself lives in
/// [`Actor::published`], keyed by the same `share_id`. Mirrors the TUI's `OwnShare`.
#[derive(Clone)]
struct OwnShare {
    share_id: String,
    name: String,
    rating: String,
    sharer_handle: String,
}

/// The parameters of the last successful [`NetCommand::Connect`] (#71). Retained
/// so the auto-reconnect timer can re-establish the connection exactly like the
/// original launch — same relay, same persisted display handle, and the same
/// `rejoin_circles` / `republish_roots` so a recovered connection restores circles
/// and shares without any UI involvement. `None` until a first successful connect;
/// cleared only by an explicit re-`Connect` replacing it (never by a drop, so a
/// drop can reconnect using the same plan).
#[derive(Clone)]
struct ConnectPlan {
    server_id: String,
    address: String,
    display_handle: Option<String>,
    rejoin_circles: Vec<(u64, String)>,
    republish_roots: Vec<(PathBuf, Option<String>)>,
    /// (#81) the share-index location + key, so a reconnect re-opens the SAME
    /// persisted index and a reconnect-time republish reuses the cache instead of
    /// re-hashing from scratch. Carried verbatim from the original `Connect`.
    index_params: Option<(PathBuf, IndexKey)>,
}

/// First auto-reconnect backoff delay (#71). The actor waits this long after a
/// drop before the first reconnect attempt, doubling each failed attempt up to
/// [`RECONNECT_BACKOFF_MAX`]. Never a busy-loop.
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_secs(2);

/// Cap on the auto-reconnect backoff delay (#71): exponential growth from
/// [`RECONNECT_BACKOFF_BASE`] saturates here so a long outage retries steadily
/// (once per cap) rather than backing off unboundedly.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Prune-TTL for a discovered share's in-band liveness ([`ShareCatalog`]). Must
/// exceed ~2 re-announce intervals so one missed reconcile cycle never drops a
/// still-live share; [`RECONCILE_INTERVAL`] is the re-announce cadence.
const SHARE_CATALOG_TTL: Duration = Duration::from_secs(90);

/// Cadence of the slow-reconcile roll-call ([`Actor::handle_reconcile_shares`]):
/// prune aged-out entries and post a roll-call so live sharers re-announce. Fixed
/// (not jittered) — a deterministic interval keeps the loop test-friendly, and
/// `SHARE_CATALOG_TTL` is set to > ~2× this so a single miss is absorbed.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// #80 storm guard: a re-subscribe of a stream landing within this window of the
/// previous one counts as a "rapid" burst; a stream that lived longer than this
/// before ending resets the burst (it was healthy).
const RESUB_BURST_WINDOW: Duration = Duration::from_secs(3);

/// #80 storm guard: after this many consecutive rapid re-subscribes of one stream
/// the link is treated as flapping and escalated to a full teardown + reconnect
/// (which retries on capped backoff) instead of hot-looping re-subscribes.
const RESUB_BURST_MAX: u32 = 5;

/// Per-stream flap detector for the #80 re-subscribe path. Records each
/// re-subscribe; once too many land in rapid succession (each within
/// [`RESUB_BURST_WINDOW`] of the last) it reports the stream as flapping so the
/// caller escalates to teardown + reconnect rather than re-subscribing forever.
#[derive(Default)]
struct BurstGuard {
    last: Option<Instant>,
    burst: u32,
}

impl BurstGuard {
    /// Record a re-subscribe at `now`; return `true` if the stream is now flapping
    /// (≥ [`RESUB_BURST_MAX`] consecutive rapid re-subscribes) and should escalate.
    fn record_and_is_flapping(&mut self, now: Instant) -> bool {
        let rapid = self
            .last
            .is_some_and(|t| now.duration_since(t) < RESUB_BURST_WINDOW);
        self.burst = if rapid {
            self.burst.saturating_add(1)
        } else {
            0
        };
        self.last = Some(now);
        self.burst >= RESUB_BURST_MAX
    }
}

/// Mutable state the actor carries across commands. `identity`/`server_id` and
/// the `counters`/`trust` stores live here for the SESSION lifetime, not as
/// Connect-handler locals (mirrors the TUI).
struct Actor {
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    /// A self-command sender so detached tasks (the lobby inbound reader, the
    /// reconcile timer) can post discovery commands back into the one command
    /// loop. All [`ShareCatalog`] mutation stays on the actor's `&mut self`.
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
    /// In-band discovery catalog for the lobby (unified share model): verified
    /// [`wire::ShareAnnouncement`]s fold in here, replacing the relay's
    /// `ListPublicShares` registry. Rendered into the Shares pane as
    /// [`ShareListing`] rows so the UI is unchanged.
    share_catalog: ShareCatalog,
    /// Shares this daemon is publishing this session, so a roll-call can
    /// re-announce them and an unpublish can post a matching withdraw. Behind
    /// `Rc<RefCell<..>>` so the detached publish flow (a `spawn_local`) records its
    /// own entry once the index phase succeeds.
    own_shares: Rc<RefCell<Vec<OwnShare>>>,
    /// The live application session, once Connected.
    session: Option<AppSession>,
    /// The connected relay's wire server-id, namespacing the room address.
    server_id: Option<String>,
    /// (#91) The connected relay's TOFU-pinned public key, captured from the
    /// connect [`daemonseed_cli::connect::ConnectOutcome`]. Needed to build the
    /// MOTD verification whitelist (a MOTD may be server-signed, ISC-26). `None`
    /// before a successful connect / on the test-attach path (no public-space fetch).
    server_pubkey: Option<Vec<u8>>,
    /// The daemon's own ephemeral identity, retained after connect so room posts
    /// are self-signed for provenance under the key that proved the connection.
    identity: Option<ClientIdentity>,
    /// (#92) The unlocked profile's STABLE persistent identity signing key — the
    /// key behind the `name#hash` handle an operator whitelists (derived from the
    /// mnemonic, NOT the ephemeral `identity` above). Held for the actor's life so
    /// the composer-gating (`composer_visible`) and MOTD/announcement signing
    /// (`sign_motd` / `sign_post`) use the persistent identity. `None` on the
    /// ephemeral / no-profile path: the public space stays read-only (no composer).
    stable_signing_key: Option<SignKeypair>,
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
    /// `true` once a session is live (Authenticated), `false` after a drop (#72)
    /// or before the first connect. Gates [`Actor::handle_disconnected`] so the
    /// FIRST failed re-subscribe per drop tears down and arms reconnect, while later
    /// ones from sibling readers of the same dead connection are no-ops (one drop,
    /// one teardown).
    connected: bool,
    /// The last successful connect's parameters (#71), so the auto-reconnect timer
    /// re-establishes exactly like the original launch. `None` until a first
    /// successful connect.
    last_connect: Option<ConnectPlan>,
    /// The current auto-reconnect attempt counter (#71), driving the exponential
    /// backoff delay. Reset to 0 on a successful (re)connect; incremented per
    /// scheduled attempt.
    reconnect_attempt: u32,
    /// #80 flap detector for the lobby re-subscribe path. Each circle carries its
    /// own in [`CircleSub::resub`].
    room_resub: BurstGuard,
    /// (#81) the persisted-index home: the profile root dir + share-index key,
    /// captured from the first `Connect` carrying `index_params`. A publish opens a
    /// PER-SHARE redb file under this dir (one per share root — see
    /// [`Self::share_indexes`]). `None` on the ephemeral / no-profile path, where a
    /// publish hashes fresh with no cache.
    index_home: Option<(PathBuf, IndexKey)>,
    /// (#81) open per-share redb indexes, keyed by share root. ONE redb FILE per
    /// share (`share-index-<12hex(root)>.redb` under [`Self::index_home`]'s dir), so
    /// a share's cache pass can never evict another share's cached chunk addresses —
    /// the multi-share startup re-hash bug (#81), where a single shared index
    /// cross-pruned every other share on each publish. Opened create-if-absent on the
    /// first publish of a root and retained for the actor's life (redb holds an
    /// exclusive file lock; each `Arc` clone goes to a blocking hash pass while the
    /// foreground keeps querying via redb MVCC). Empty on the ephemeral / no-profile
    /// path.
    share_indexes: HashMap<PathBuf, Arc<ShareIndex>>,
}

impl Actor {
    /// Build a fresh actor with a throwaway per-launch `my_handle` and no live
    /// session. The presence-heartbeat timer is armed separately by [`net_actor`]
    /// (once per actor life); tests that don't need the timer call this directly.
    fn new(
        evt_tx: mpsc::UnboundedSender<NetEvent>,
        cmd_tx: mpsc::UnboundedSender<NetCommand>,
    ) -> Self {
        Actor {
            evt_tx,
            cmd_tx,
            share_catalog: ShareCatalog::new(SHARE_CATALOG_TTL),
            own_shares: Rc::new(RefCell::new(Vec::new())),
            session: None,
            server_id: None,
            server_pubkey: None,
            identity: None,
            stable_signing_key: None,
            my_handle: generate_handle(),
            counters: CounterState::default(),
            trust: InMemoryTrustStore::new(),
            public_room: None,
            circles: Vec::new(),
            published: HashMap::new(),
            connected: false,
            last_connect: None,
            reconnect_attempt: 0,
            room_resub: BurstGuard::default(),
            index_home: None,
            share_indexes: HashMap::new(),
        }
    }

    fn emit(&self, evt: NetEvent) {
        let _ = self.evt_tx.send(evt);
    }

    /// (#81) The persisted redb share index for `root`, opened create-if-absent under
    /// [`Self::index_home`] as a PER-SHARE file (`share-index-<12hex(root)>.redb`) and
    /// cached in [`Self::share_indexes`] for the actor's life. Returns `None` on the
    /// ephemeral / no-profile path (no `index_home`), where a publish hashes fresh.
    ///
    /// A per-share file holds only this root's files, so cache-hitting (or otherwise
    /// touching) it can never affect another share's cache — that is the whole point
    /// of the per-share split (#81). The open is blocking redb I/O (file-create +
    /// table-materialize), so it runs on a blocking thread off the actor's async loop.
    /// A failed open is non-fatal: it surfaces an Error and returns `None`, degrading
    /// that one publish to a from-scratch hash (correct, just uncached).
    async fn index_for_root(&mut self, root: &Path) -> Option<Arc<ShareIndex>> {
        if let Some(existing) = self.share_indexes.get(root) {
            return Some(existing.clone());
        }
        let (index_dir, index_key) = self.index_home.as_ref()?;
        let index_path = index_dir.join(per_share_index_filename(root));
        let key_bytes = index_key.to_bytes();
        let opened =
            tokio::task::spawn_blocking(move || ShareIndex::open(&index_path, key_bytes)).await;
        match opened {
            Ok(Ok(index)) => {
                let index = Arc::new(index);
                self.share_indexes.insert(root.to_path_buf(), index.clone());
                Some(index)
            }
            // A failed open is non-fatal: surface it and return `None` so this publish
            // degrades to a from-scratch hash (correct, just not cached).
            Ok(Err(e)) => {
                self.emit(NetEvent::Error {
                    reason: format!("could not open share index: {e}"),
                });
                None
            }
            Err(_) => {
                self.emit(NetEvent::Error {
                    reason: "share-index open task failed".to_owned(),
                });
                None
            }
        }
    }

    /// TEST SEAM (#81): the first cached chunk address the per-share index for `root`
    /// holds for `rel_path`, or `None` if no index is open for `root`, no entry, or no
    /// cached blob. Reads only the first 48 bytes of the cached blob (one
    /// [`daemonseed_core::storage::cas::ChunkAddr`]), all the cache-hit-vs-rehash
    /// assertion needs.
    #[cfg(test)]
    fn probe_cached_addr(&self, root: &Path, rel_path: &str) -> Option<Vec<u8>> {
        use daemonseed_core::storage::cas::CHUNK_ADDR_LEN;
        let index = self.share_indexes.get(root)?;
        let entry = index.get(rel_path).ok().flatten()?;
        let blob = entry.chunk_addrs?;
        (blob.len() >= CHUNK_ADDR_LEN).then(|| blob[..CHUNK_ADDR_LEN].to_vec())
    }

    /// Open a connection and keep the live session, then auto-join the default
    /// room. Mirrors `daemonseed_tui::net::Actor::handle_connect`: ephemeral
    /// identity, trusted-mode upsert, `connect_session` → `AppSession::open`.
    // The connect path threads the full per-launch profile context (handle,
    // rejoins, republishes, index params, stable signing key); bundling it into a
    // one-use struct would add indirection without clarity.
    #[allow(clippy::too_many_arguments)]
    async fn handle_connect(
        &mut self,
        server_id: &str,
        address: &str,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
        republish_roots: Vec<(PathBuf, Option<String>)>,
        index_params: Option<(PathBuf, IndexKey)>,
        stable_signing_key: Option<SignKeypair>,
    ) {
        // Round 6: present under the persisted stable handle when unlocked from a
        // profile. The connection proof below stays ephemeral (D8) — only the
        // display name is persistent.
        if let Some(handle) = display_handle {
            self.my_handle = handle;
        }
        // (#92) Hold the unlocked profile's stable identity signing key for the
        // actor's life — it gates the composer and signs MOTD/announcements. Set
        // once; idempotent across reconnects (the key never changes for a session).
        if stable_signing_key.is_some() {
            self.stable_signing_key = stable_signing_key;
        }
        // (#81) Capture the persisted-index home (profile dir + key) BEFORE the
        // republish loop, so a connect-time republish of an unchanged share opens its
        // per-share index file under it and reuses the cache instead of re-hashing
        // from scratch. Set once; idempotent across reconnects.
        if self.index_home.is_none() {
            self.index_home = index_params.clone();
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
                    // (#91) Pin the relay's verified key for MOTD re-verification.
                    self.server_pubkey = Some(outcome.server_pubkey);
                    self.identity = Some(identity);
                    self.connected = true;
                    // #71: remember this connect so a later drop reconnects with the
                    // SAME relay + persisted handle + rejoin/republish sets. Reset the
                    // backoff counter — a fresh success clears any prior failure run.
                    self.last_connect = Some(ConnectPlan {
                        server_id: server_id.to_owned(),
                        address: address.to_owned(),
                        display_handle: Some(self.my_handle.clone()),
                        rejoin_circles: rejoin_circles.clone(),
                        republish_roots: republish_roots.clone(),
                        index_params: index_params.clone(),
                    });
                    self.reconnect_attempt = 0;
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
                    for (root, persisted_name) in republish_roots {
                        let name = republish_name(&root, persisted_name.as_deref());
                        self.handle_publish_share(root, name, sharer.clone(), true)
                            .await;
                    }
                    // #93: fetch + re-verify the relay's public space once the session
                    // is live and emit a connect-time snapshot, so the binary can run
                    // the unread gate (auto-open the announcements pane iff the MOTD /
                    // announcements changed since last seen, else stay on the Lobby).
                    // A relay without a public space (empty MOTD / no posts / no
                    // whitelist) yields an empty view — the gate then compares an
                    // empty-content hash and behaves sanely. Best-effort: a refused
                    // fetch surfaces as a PublicSpaceError and never aborts the connect.
                    self.handle_refresh_public_space(true).await;
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
        republish_roots: Vec<(PathBuf, Option<String>)>,
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
        self.connected = true;
        self.reconnect_attempt = 0;
        self.emit(NetEvent::Connected {
            server_handle: "attached#000000000000".to_owned(),
        });
        // Round-6 parity: silently re-join persisted circles via the real path.
        for (circle_id, phrase) in rejoin_circles {
            self.handle_join_circle(circle_id, &phrase).await;
        }
        // M16 parity: silently re-publish persisted shares via the real path.
        let sharer = self.my_handle.clone();
        for (root, persisted_name) in republish_roots {
            let name = republish_name(&root, persisted_name.as_deref());
            self.handle_publish_share(root, name, sharer.clone(), true)
                .await;
        }
    }

    /// Re-establish over a fresh in-memory session (TEST SEAM, #71/#72). Mirrors
    /// what [`Actor::handle_reconnect`]'s `Connect` does — clears the prior
    /// reconnect counter, re-attaches the (test-supplied) session, and re-joins the
    /// circles — so the in-process oracle drives the SAME re-subscribe path the
    /// backoff timer triggers in production, without a real TCP dial.
    #[cfg(test)]
    async fn handle_reattach(
        &mut self,
        session: AppSession,
        server_id: String,
        display_handle: Option<String>,
        rejoin_circles: Vec<(u64, String)>,
    ) {
        self.handle_attach(
            session,
            server_id,
            display_handle,
            rejoin_circles,
            Vec::new(),
        )
        .await;
    }

    /// Handle a live-connection drop (#72/#80): tear down stale session state so a
    /// half-open session is never reused, surface [`NetEvent::Disconnected`], and
    /// arm auto-reconnect (#71). Reached when a re-subscribe fails (the connection
    /// is dead) or a stream is flapping. Idempotent — only the FIRST such signal per
    /// session does work; later ones (sibling readers' failed re-subscribes of the
    /// same dead connection) short-circuit because `connected` is already `false`.
    fn handle_disconnected(&mut self, reason: String) {
        if !self.connected {
            return; // already torn down for this drop
        }
        self.connected = false;
        // Drop every live handle to the dead connection. The detached reader tasks
        // observe their streams ending and exit on their own; clearing the OUT
        // halves here makes any in-flight send fail fast rather than block.
        self.session = None;
        self.server_id = None;
        self.server_pubkey = None;
        self.identity = None;
        self.public_room = None;
        self.circles.clear();
        // Abort each serve task — its subscribe stream is dead; a republish on
        // reconnect re-establishes it from the stored plan.
        for (_id, task) in self.published.drain() {
            task.abort();
        }
        self.own_shares.borrow_mut().clear();
        self.emit(NetEvent::Disconnected { reason });
        // #71: schedule a reconnect if we have a plan to reconnect WITH. Without a
        // prior successful connect there is nothing to retry (e.g. a drop during
        // the very first handshake surfaces as ConnectFailed, not here).
        if self.last_connect.is_some() {
            self.arm_reconnect();
        }
    }

    /// Schedule one auto-reconnect attempt (#71) on capped exponential backoff: a
    /// detached timer sleeps `min(BASE · 2^attempt, MAX)` then posts a
    /// [`NetCommand::Reconnect`] back into the command loop. Self-terminating — the
    /// send fails (and the loop ends) once the actor is gone. Never busy-loops.
    fn arm_reconnect(&mut self) {
        let attempt = self.reconnect_attempt;
        self.reconnect_attempt = attempt.saturating_add(1);
        let delay = reconnect_backoff(attempt);
        let cmd_tx = self.cmd_tx.clone();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(delay).await;
            let _ = cmd_tx.send(NetCommand::Reconnect);
        });
    }

    /// Run one auto-reconnect attempt (#71): if still disconnected and a stored
    /// [`ConnectPlan`] exists, re-issue the full `Connect` (which restores circles
    /// and shares from the plan). A successful connect resets the backoff and stops
    /// the retry chain (`handle_connect` sets `connected = true`); a failed one
    /// arms the next attempt with a longer delay. A reconnect that finds the
    /// session already live (a racing manual reconnect) is a no-op.
    async fn handle_reconnect(&mut self) {
        if self.connected {
            return; // already back up — nothing to retry
        }
        let Some(plan) = self.last_connect.clone() else {
            return; // no plan to reconnect with
        };
        self.handle_connect(
            &plan.server_id,
            &plan.address,
            plan.display_handle.clone(),
            plan.rejoin_circles.clone(),
            plan.republish_roots.clone(),
            plan.index_params.clone(),
            // (#92) The stable signing key is held on the actor across reconnects
            // (set once on the first Connect, never cleared); a reconnect re-supplies
            // None and handle_connect leaves the held key untouched.
            None,
        )
        .await;
        // If the attempt failed (`handle_connect` emitted ConnectFailed and left
        // `connected == false`), schedule the next backoff tick.
        if !self.connected && self.last_connect.is_some() {
            self.arm_reconnect();
        }
    }

    /// Re-subscribe the lobby after its inbound stream ended (#80). The re-subscribe
    /// attempt is the active probe that tells a graceful per-stream EOS on a LIVE
    /// connection apart from a dead one: success ⇒ the authenticated connection is
    /// still up (circles + serve tasks left intact); failure ⇒ the connection is
    /// gone, so post `Disconnected` to tear down + reconnect (#72/#71). No-op if
    /// already torn down (`!connected`) or there is no lobby — never resurrects state.
    async fn handle_resubscribe_room(&mut self) {
        if !self.connected {
            return;
        }
        let Some(room) = self.public_room.as_ref().map(|r| r.room.clone()) else {
            return;
        };
        // Flap guard: too many rapid lobby re-subscribes ⇒ stop hot-looping and
        // escalate to a full teardown + reconnect (which retries on backoff).
        if self.room_resub.record_and_is_flapping(Instant::now()) {
            return self.handle_disconnected("lobby stream flapping".to_owned());
        }
        match self.establish_room(&room).await {
            // Re-discover shares missed during the blip; do NOT re-emit RoomJoined
            // or start a second reconcile timer (the original join already did).
            Ok(()) => self.post_rollcall().await,
            Err(_) => self.handle_disconnected("lobby connection lost".to_owned()),
        }
    }

    /// Re-subscribe ONE circle after its inbound stream ended (#80) — same
    /// active-probe rationale as [`Actor::handle_resubscribe_room`]. Replaces just
    /// that circle's outbound half + reader; every other circle and the lobby are
    /// left untouched (ISC-10). No-op if already torn down or the `circle_id` is no
    /// longer joined (never resurrects a circle).
    async fn handle_resubscribe_circle(&mut self, circle_id: u64) {
        if !self.connected {
            return;
        }
        let Some(idx) = self.circles.iter().position(|c| c.circle_id == circle_id) else {
            return;
        };
        if self.circles[idx]
            .resub
            .record_and_is_flapping(Instant::now())
        {
            return self.handle_disconnected("circle stream flapping".to_owned());
        }
        let cot_key = Rc::clone(&self.circles[idx].cot_key);
        let asset_addr = self.circles[idx].asset_addr;
        match self.subscribe_circle(circle_id, cot_key, asset_addr).await {
            Ok(out_tx) => {
                // Re-find by id (the single-threaded actor keeps the set stable
                // across this await, but re-finding keeps the swap robust): swap in
                // the live sender, leaving the rest of the entry (key, guard) intact.
                if let Some(sub) = self.circles.iter_mut().find(|c| c.circle_id == circle_id) {
                    sub.out_tx = out_tx;
                }
            }
            Err(_) => self.handle_disconnected("circle connection lost".to_owned()),
        }
    }

    /// Subscribe one circle's rendezvous on the live session and spawn its inbound
    /// reader, returning the outbound half. Shared by [`Actor::handle_join_circle`]
    /// (initial join) and [`Actor::handle_resubscribe_circle`] (#80). Does NOT touch
    /// the joined-circle set — the caller adds (join) or replaces (re-subscribe).
    async fn subscribe_circle(
        &self,
        circle_id: u64,
        cot_key: Rc<CircleKey>,
        asset_addr: AssetAddr,
    ) -> Result<mpsc::Sender<wire::CotFrame>, String> {
        let Some(session) = self.session.as_ref() else {
            return Err("not connected to a relay yet".to_owned());
        };
        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);
        // Name the rendezvous (empty payload, not relayed) before subscribing.
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        out_tx
            .send(naming)
            .await
            .map_err(|_| "circle subscribe channel closed".to_owned())?;
        let mut cot = session.circle_of_trust();
        let inbound = cot
            .subscribe(ReceiverStream::new(out_rx))
            .await
            .map_err(|status| format!("subscribe refused: {}", status.message()))?
            .into_inner();
        // Inbound reader: decrypts each frame under THIS circle's key and emits a
        // CircleMessage tagged with THIS circle_id (ISC-A-C30 attribution).
        let reader_key = Rc::clone(&cot_key);
        let reader_tx = self.evt_tx.clone();
        let reader_handle = self.my_handle.clone();
        let reader_cmd = self.cmd_tx.clone();
        tokio::task::spawn_local(read_inbound_circle(
            inbound,
            circle_id,
            reader_key,
            reader_tx,
            reader_handle,
            reader_cmd,
        ));
        Ok(out_tx)
    }

    /// Auto-join / re-join the default public room: establish the inbound stream
    /// (see [`Actor::establish_room`]) then bootstrap share discovery. ONE shared
    /// path for Connect's auto-join and the `AttachSession`-driven JoinRoom (both
    /// route here off actor state), mirroring
    /// `daemonseed_tui::net::Actor::join_default_public_room`.
    async fn join_room(&mut self, room: &str) {
        let room = room.to_owned();
        if let Err(reason) = self.establish_room(&room).await {
            return self.emit(NetEvent::Error { reason });
        }
        self.emit(NetEvent::RoomJoined { room });

        // Discovery bootstrap (unified share model): post an initial roll-call so
        // already-live sharers re-announce into our fresh catalog, and start the
        // slow-reconcile timer that re-polls + prunes on `RECONCILE_INTERVAL`.
        self.post_rollcall().await;
        self.start_reconcile_timer();
    }

    /// Derive the room key + rendezvous, subscribe, spawn the inbound reader, and
    /// store the live [`PublicRoom`] (replacing any prior one). Shared by
    /// [`Actor::join_room`] (initial / auto-join) and [`Actor::handle_resubscribe_room`]
    /// (#80 re-subscribe after an EOS). Returns `Err(reason)` if any derivation or
    /// the subscribe fails; the caller decides whether that surfaces as an Error
    /// event (join) or a dead-connection teardown (#80 re-subscribe).
    async fn establish_room(&mut self, room: &str) -> Result<(), String> {
        let Some(session) = self.session.as_ref() else {
            return Err("not connected to a relay yet".to_owned());
        };
        let Some(server_id) = self.server_id.as_ref() else {
            return Err("no server-id for the connected relay".to_owned());
        };

        // The room key is GLOBAL: derived from public inputs, identical for every
        // client and the relay. Reused as the AEAD key for seal/open.
        let room = room.to_owned();
        let room_key = Rc::new(
            derive_room_key(&room, &CNSA_2_0)
                .map_err(|e| format!("public-room key derivation failed: {e}"))?,
        );
        // VERBATIM mirror of TUI net.rs:1277 —
        //   `room_asset_address(&room_key, server_id.as_bytes())`
        let asset_addr = room_asset_address(&room_key, server_id.as_bytes())
            .map_err(|e| format!("public-room rendezvous derivation failed: {e}"))?;

        let (out_tx, out_rx) = mpsc::channel::<wire::CotFrame>(32);
        // Name the rendezvous with an initial EMPTY frame (registers the asset;
        // not relayed) before subscribing.
        let naming = wire::CotFrame {
            asset_address: asset_addr.as_bytes().to_vec(),
            payload: Vec::new(),
        };
        out_tx
            .send(naming)
            .await
            .map_err(|_| "public-room subscribe channel closed".to_owned())?;

        let mut cot = session.circle_of_trust();
        let inbound = cot
            .subscribe(ReceiverStream::new(out_rx))
            .await
            .map_err(|status| format!("public-room subscribe refused: {}", status.message()))?
            .into_inner();

        // Inbound reader: owns the IN half, decrypts each frame under the global
        // room key (mirrors the TUI). The OUT sender stays here in actor state.
        let reader_key = Rc::clone(&room_key);
        let reader_tx = self.evt_tx.clone();
        let reader_handle = self.my_handle.clone();
        let reader_cmd = self.cmd_tx.clone();
        let reader_room = room.clone();
        tokio::task::spawn_local(read_inbound_public_room(
            inbound,
            reader_room,
            reader_key,
            reader_tx,
            reader_handle,
            reader_cmd,
        ));

        self.public_room = Some(PublicRoom {
            room,
            room_key,
            asset_addr,
            out_tx,
            // A fresh tracker per construction: a leave/rejoin (or #80 re-subscribe)
            // starts from an empty roster rather than carrying stale members.
            presence: PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT),
        });
        Ok(())
    }

    /// Start the slow-reconcile loop (unified share model): a detached `spawn_local`
    /// that, every [`RECONCILE_INTERVAL`], posts a [`NetCommand::ReconcileShares`]
    /// back into the command loop (which prunes the catalog + posts a roll-call).
    /// Self-terminating: the send fails once the actor loop ends, breaking the loop.
    /// Started once per public-room join.
    fn start_reconcile_timer(&self) {
        let cmd_tx = self.cmd_tx.clone();
        tokio::task::spawn_local(async move {
            loop {
                tokio::time::sleep(RECONCILE_INTERVAL).await;
                if cmd_tx.send(NetCommand::ReconcileShares).is_err() {
                    break;
                }
            }
        });
    }

    /// Start the presence-heartbeat loop (#74): a detached `spawn_local` that posts
    /// a [`NetCommand::EmitHeartbeat`] back into the command loop on a freshly
    /// jittered [`next_heartbeat_interval`] each pass (~10–15s) so beacons never
    /// lock-step across daemons. Self-terminating — the send fails once the actor
    /// loop ends, breaking the loop. Spawned EXACTLY ONCE at actor start (NOT per
    /// join, unlike the reconcile timer), so a reconnect/rejoin can never
    /// double-emit; the emit handler is a no-op until a lobby is joined.
    fn start_heartbeat_timer(&self) {
        let cmd_tx = self.cmd_tx.clone();
        tokio::task::spawn_local(async move {
            loop {
                tokio::time::sleep(next_heartbeat_interval()).await;
                if cmd_tx.send(NetCommand::EmitHeartbeat).is_err() {
                    break;
                }
            }
        });
    }

    /// Emit one sealed member beacon (#74/#77) into the lobby (if joined) AND each
    /// joined circle, then `reap` every presence tracker so members past their TTL
    /// age out (the heartbeat timer is the reap clock too). See
    /// [`NetCommand::EmitHeartbeat`]. A missing identity, a missing room, a seal
    /// failure, or a closed stream is non-fatal — presence self-heals on the next
    /// tick, exactly like the reconcile/announce handlers. Mirrors
    /// `daemonseed_tui::net::Actor::handle_emit_heartbeat` (lobby + per-circle): each
    /// beacon is self-signed under the daemon's own identity (provenance, ISC-C57)
    /// and sealed under the tier-correct key — the global room key for the lobby, the
    /// circle key for a circle. A reap that removed ≥ 1 member from a room pushes a
    /// fresh (possibly empty) roster tagged with that room.
    async fn handle_emit_heartbeat(&mut self) {
        // EMIT — needs an identity to self-sign with; the reap below runs regardless
        // so the trackers stay honest even with no identity.
        if let Some(identity) = self.identity.as_ref() {
            let signing = identity.signing();
            let sent_unix_ms = now_unix_ms();

            // Lobby beacon (carries the served-share digest, #76). The RefCell
            // borrow ends before the await: seal first, send via the room's sender.
            if let Some(room) = self.public_room.as_ref() {
                let lobby_share_ids: Vec<String> = self
                    .own_shares
                    .borrow()
                    .iter()
                    .map(|s| s.share_id.clone())
                    .collect();
                let fields = HeartbeatFields {
                    room: &room.room,
                    sender_handle: &self.my_handle,
                    sent_unix_ms,
                    live_share_ids: &lobby_share_ids,
                };
                if let Ok(sealed) = seal_public_heartbeat(&room.room_key, signing, &fields) {
                    let frame = wire::CotFrame {
                        asset_address: room.asset_addr.as_bytes().to_vec(),
                        payload: sealed,
                    };
                    // A closed lobby stream is non-fatal: the next reconnect
                    // re-subscribes and resumes beaconing.
                    let _ = room.out_tx.send(frame).await;
                }
            }

            // One beacon per joined circle, sealed under that circle's key (#77).
            // The sealed `room` is the circle's deterministic client-local label
            // (`default_circle_label`) — the SAME value the TUI seals and every
            // member derives from the rendezvous, so provenance binds consistently.
            // No circle-share concept yet (#76): an empty `live_share_ids` digest.
            for circle in &self.circles {
                let label = default_circle_label(&circle.asset_addr);
                let fields = HeartbeatFields {
                    room: &label,
                    sender_handle: &self.my_handle,
                    sent_unix_ms,
                    live_share_ids: &[],
                };
                if let Ok(sealed) = seal_circle_heartbeat(&circle.cot_key, signing, &fields) {
                    let frame = wire::CotFrame {
                        asset_address: circle.asset_addr.as_bytes().to_vec(),
                        payload: sealed,
                    };
                    let _ = circle.out_tx.send(frame).await;
                }
            }
        }

        // REAP every tracker on the same tick — the timer is the reap clock. Push a
        // fresh roster for each tracker a reap changed, predicated on the removed set
        // (so a reap-to-empty still pushes an empty roster), tagged with its room so
        // the UI updates only the active room's column.
        let now = Instant::now();
        let mut lobby_reaped = false;
        let mut lobby_rows: Vec<RosterEntry> = Vec::new();
        if let Some(room) = self.public_room.as_mut() {
            lobby_reaped = !room.presence.reap(now).is_empty();
            if lobby_reaped {
                lobby_rows = roster_from_members(&room.presence.members());
            }
        }
        if lobby_reaped {
            self.emit(NetEvent::Roster {
                circle_id: None,
                entries: lobby_rows,
            });
        }
        // Collect the circle rosters that changed first, so the `&mut self.circles`
        // borrow ends before each `self.emit` (which borrows `&self`).
        let mut circle_rosters: Vec<(u64, Vec<RosterEntry>)> = Vec::new();
        for circle in &mut self.circles {
            if !circle.presence.reap(now).is_empty() {
                circle_rosters.push((
                    circle.circle_id,
                    roster_from_members(&circle.presence.members()),
                ));
            }
        }
        for (circle_id, entries) in circle_rosters {
            self.emit(NetEvent::Roster {
                circle_id: Some(circle_id),
                entries,
            });
        }
    }

    /// Fold a verified member heartbeat into the matching room's
    /// [`PresenceTracker`] (#74 lobby; #77 circles). See [`NetCommand::ApplyHeartbeat`].
    /// The inbound reader verifies provenance before posting; this self-filters our
    /// own beacon (per-circle too), drops a replayed/stale beacon ([`beacon_is_fresh`],
    /// #78), routes by the session-local `room` key (the lobby room name, or a
    /// circle's GUI id as a decimal string), and applies to exactly that tracker.
    /// Pushes a fresh roster — tagged with the room it concerns — on a real change (a
    /// member appeared, or a refresh that changed the displayed handle; a same-handle
    /// refresh leaves the rendered roster identical and is not pushed). Mirrors
    /// `daemonseed_tui::net::Actor::handle_apply_heartbeat`.
    fn handle_apply_heartbeat(&mut self, room: &str, heartbeat: &wire::MemberHeartbeat) {
        // Self-filter: never count our own beacon as a live OTHER member (relay
        // should never fan it back, but filter defensively — and for every room).
        if let Some(identity) = self.identity.as_ref()
            && beacon_is_own(
                identity.signing().public_key().as_slice(),
                heartbeat.sender_pubkey.as_slice(),
            )
        {
            return;
        }
        // #78 replay-freshness: drop a beacon outside the freshness window so a
        // captured-and-replayed beacon cannot pin a departed member present.
        if !beacon_is_fresh(heartbeat.sent_unix_ms, now_unix_ms()) {
            return;
        }
        let now = Instant::now();

        // Lobby route: the routing key is the lobby room name. A non-lobby key (or no
        // lobby) skips this block and falls through to the circle route below.
        if let Some(lobby) = self.public_room.as_mut()
            && lobby.room == room
        {
            // Capture the handle a refresh might replace, to decide if the rendered
            // roster actually changed (a same-handle refresh is invisible to the UI).
            let prior_handle = lobby
                .presence
                .members()
                .into_iter()
                .find(|m| m.pubkey == heartbeat.sender_pubkey)
                .map(|m| m.handle);
            let change = lobby.presence.apply(heartbeat, now);
            if roster_render_changed(change, prior_handle.as_deref(), &heartbeat.sender_handle) {
                let entries = roster_from_members(&lobby.presence.members());
                self.emit(NetEvent::Roster {
                    circle_id: None,
                    entries,
                });
            }
            return;
        }

        // Circle route (#77): the routing key is the circle's GUI id as a decimal
        // string (the circle inbound reader posts `circle_id.to_string()`). Apply to
        // exactly that circle's tracker; an unknown/unparsable id drops (raced a
        // leave/teardown) and never resurrects a circle.
        let Ok(circle_id) = room.parse::<u64>() else {
            return;
        };
        // Build the roster inside a block so the `&mut self.circles` borrow ends
        // before `self.emit` (which borrows `&self`); the block early-returns when
        // the circle is gone or the apply did not change the rendered roster.
        let entries = {
            let Some(circle) = self.circles.iter_mut().find(|c| c.circle_id == circle_id) else {
                return;
            };
            let prior_handle = circle
                .presence
                .members()
                .into_iter()
                .find(|m| m.pubkey == heartbeat.sender_pubkey)
                .map(|m| m.handle);
            let change = circle.presence.apply(heartbeat, now);
            if !roster_render_changed(change, prior_handle.as_deref(), &heartbeat.sender_handle) {
                return;
            }
            roster_from_members(&circle.presence.members())
        };
        self.emit(NetEvent::Roster {
            circle_id: Some(circle_id),
            entries,
        });
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

        if self.session.is_none() {
            return self.emit(err("not connected to a relay yet".to_owned()));
        }
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

        // Subscribe the rendezvous + spawn the reader (shared with the #80
        // re-subscribe path); ADD the new circle to the joined set.
        let out_tx = match self
            .subscribe_circle(circle_id, Rc::clone(&cot_key), asset_addr)
            .await
        {
            Ok(tx) => tx,
            Err(reason) => return self.emit(err(reason)),
        };

        self.circles.push(CircleSub {
            circle_id,
            cot_key,
            asset_addr,
            out_tx,
            resub: BurstGuard::default(),
            // #77: a fresh per-circle tracker — a leave/rejoin (or #80 re-subscribe)
            // starts from an empty roster rather than carrying stale members.
            presence: PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT),
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

        // (#81) Index the directory off the actor thread (1 MiB sub-file chunking),
        // reusing the PER-SHARE persisted redb chunk-address cache so an unchanged
        // share — the common case, especially the connect-time auto-republish of a
        // large share — is cache-hits-only (near-instant) instead of a full
        // from-scratch re-hash (the Demonsaw-style CPU thrash ISC-C21 / ISC-A-C7 exist
        // to prevent). The hashing stays inside `spawn_blocking` (off the async loop,
        // ISC-A-C7); `cached_or_hash` reads no file whose size+mtime still match a
        // cached entry, and writes fresh addresses back for misses so the next publish
        // of an unchanged share reads no file at all.
        //
        // The index is a per-share redb file dedicated to THIS root, so its cache pass
        // can never evict another share's cache — every published share keeps its own
        // cache across launches (the #81 multi-share re-hash bug). With no index_home
        // (the ephemeral / no-profile path) the pass degrades to a from-scratch hash.
        let index = self.index_for_root(&root).await;

        let hash_root = root.clone();
        let manifest = match tokio::task::spawn_blocking(move || {
            cached_or_hash(
                index.as_deref(),
                &hash_root,
                &AtomicBool::new(false),
                &mut |_, _| {},
            )
        })
        .await
        {
            Ok(Ok(m)) => m,
            Ok(Err(CachedHashError::Serve(ServeError::Cancelled))) => {
                // The GUI alpha never cancels a publish hash; treat a Cancelled as a
                // benign no-op rather than a hard error.
                return self.emit(NetEvent::PublishError {
                    message: format!("indexing {} was cancelled", root.display()),
                });
            }
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
        // Disk-backed serve content (mirrors the TUI): the manifest stays in RAM, the
        // file bytes are read from disk per chunk request, so a share is never copied
        // whole into RAM. `Arc`-shared because `serve_share` answers each request on
        // the blocking pool.
        let content = std::sync::Arc::new(DiskShareContent::new(root.clone(), manifest));
        let file_count = content.file_count();

        // The lobby subscription is the in-band discovery transport (unified share
        // model): the share is announced by posting a sealed `ShareAnnouncement` on
        // the SAME stream chat uses, not via a relay RPC. The lobby auto-joins on
        // connect, so it is present whenever a session is. Borrowed AFTER indexing
        // (the `.await` above) so the borrows do not cross it.
        let Some(room) = self.public_room.as_ref() else {
            return self.emit(NetEvent::PublishError {
                message: "public room not joined yet".to_owned(),
            });
        };
        let Some(identity) = self.identity.as_ref() else {
            return self.emit(NetEvent::PublishError {
                message: "no identity to sign the announcement".to_owned(),
            });
        };

        // Mint the share id CLIENT-side (unified share model): the relay no longer
        // assigns it, which makes it relay-portable (a future cross-relay path) and
        // removes the last relay-held share state. Empty rating (advisory).
        let share_id = mint_share_id();
        let rating = String::new();
        let announce_fields = AnnouncementFields {
            room: &room.room,
            sender_handle: &sharer_handle,
            share_id: &share_id,
            name: &name,
            rating: &rating,
            withdraw: false,
            sent_unix_ms: now_unix_ms(),
        };
        let sealed_announcement =
            match seal_public_announcement(&room.room_key, identity.signing(), &announce_fields) {
                Ok(s) => s,
                Err(e) => {
                    return self.emit(NetEvent::PublishError {
                        message: format!("could not seal share announcement: {e}"),
                    });
                }
            };
        let announce_frame = wire::CotFrame {
            asset_address: room.asset_addr.as_bytes().to_vec(),
            payload: sealed_announcement,
        };
        // In-band publish: announce the share by posting the sealed, self-signed
        // `ShareAnnouncement` into the lobby — the same stream chat uses — instead
        // of a relay `PublishShare` RPC. Listeners fold it into their `ShareCatalog`;
        // the relay holds no share directory (ISC-A-S2).
        if room.out_tx.send(announce_frame).await.is_err() {
            return self.emit(NetEvent::PublishError {
                message: "lobby stream closed; reconnect to publish".to_owned(),
            });
        }
        // Record the own-share so a roll-call can re-announce it and an unpublish
        // can post a matching withdraw (the in-band replacement for the relay's
        // owner-scoped registry record).
        self.own_shares.borrow_mut().push(OwnShare {
            share_id: share_id.clone(),
            name: name.clone(),
            rating,
            sharer_handle,
        });
        // Reflect the new own-share in our own Shares list immediately — the relay
        // never echoes our own announcement back, so the local catalog never sees it.
        self.emit_shares_snapshot();

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

    /// Unpublish a share published this session and stop serving it. In the unified
    /// share model the "unpublish" signal is a withdraw [`wire::ShareAnnouncement`]
    /// posted to the lobby — listeners drop the share from their [`ShareCatalog`] —
    /// not a relay RPC. The local serve task is aborted and the own-share record
    /// removed. See [`NetCommand::UnpublishShare`].
    async fn handle_unpublish_share(&mut self, share_id: &str) {
        if let Some(handle) = self.published.remove(share_id) {
            handle.abort();
        }
        // Post a matching withdraw announcement so listeners remove it (the in-band
        // replacement for the relay's `UnpublishShare`). Re-use the own-share's
        // advertised metadata so the withdraw's provenance input matches the
        // announce's (same share, same name/rating).
        let own = self
            .own_shares
            .borrow()
            .iter()
            .find(|s| s.share_id == share_id)
            .cloned();
        if let Some(own) = own {
            self.announce_own_share(&own, true).await;
        }
        self.own_shares
            .borrow_mut()
            .retain(|s| s.share_id != share_id);
        // Drop it from our own Shares list immediately too.
        self.emit_shares_snapshot();
        self.emit(NetEvent::PublishStopped {
            share_id: share_id.to_owned(),
        });
    }

    /// Post a sealed, self-signed [`wire::ShareAnnouncement`] for one own-share into
    /// the lobby — the in-band publish/withdraw/re-announce primitive (unified share
    /// model). `withdraw = false` announces or re-announces (a publish, a roll-call
    /// answer); `withdraw = true` retracts (an unpublish). A missing lobby/identity,
    /// a seal failure, or a closed stream is logged via [`NetEvent::PublishError`]
    /// and otherwise non-fatal — discovery self-heals on the next roll-call.
    async fn announce_own_share(&self, own: &OwnShare, withdraw: bool) {
        let Some(room) = self.public_room.as_ref() else {
            return;
        };
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let fields = AnnouncementFields {
            room: &room.room,
            sender_handle: &own.sharer_handle,
            share_id: &own.share_id,
            name: &own.name,
            rating: &own.rating,
            withdraw,
            sent_unix_ms: now_unix_ms(),
        };
        let sealed = match seal_public_announcement(&room.room_key, identity.signing(), &fields) {
            Ok(s) => s,
            Err(e) => {
                return self.emit(NetEvent::PublishError {
                    message: format!("could not seal share announcement: {e}"),
                });
            }
        };
        let frame = wire::CotFrame {
            asset_address: room.asset_addr.as_bytes().to_vec(),
            payload: sealed,
        };
        if room.out_tx.send(frame).await.is_err() {
            self.emit(NetEvent::PublishError {
                message: "lobby stream closed; reconnect to (re)announce".to_owned(),
            });
        }
    }

    /// Fold a verified lobby [`wire::ShareAnnouncement`] into the in-band discovery
    /// catalog and emit a fresh [`NetEvent::SharesSnapshot`] on a real change
    /// (unified share model). See [`NetCommand::ApplyAnnouncement`]. All catalog
    /// mutation runs here on `&mut self`; the inbound reader only opens the frame
    /// and posts the command.
    fn handle_apply_announcement(&mut self, ann: &wire::ShareAnnouncement) {
        let change = self.share_catalog.apply(ann, Instant::now());
        if change != CatalogChange::Unchanged {
            self.emit_shares_snapshot();
        }
    }

    /// Answer a verified lobby [`wire::ShareRollCall`] by re-announcing every
    /// own-share so the requester discovers them (unified share model). See
    /// [`NetCommand::AnswerRollCall`]. A no-op when nothing is published or the
    /// lobby is not joined.
    async fn handle_answer_rollcall(&mut self) {
        let owned: Vec<OwnShare> = self.own_shares.borrow().clone();
        for own in &owned {
            self.announce_own_share(own, false).await;
        }
    }

    /// The slow-reconcile tick (unified share model): prune aged-out catalog
    /// entries, then post a [`wire::ShareRollCall`] so live sharers re-announce. See
    /// [`NetCommand::ReconcileShares`]. Self-scheduled on [`RECONCILE_INTERVAL`]. A
    /// prune that removed entries refreshes the snapshot; the roll-call is
    /// best-effort.
    async fn handle_reconcile_shares(&mut self) {
        let pruned = self.share_catalog.prune(Instant::now());
        if pruned > 0 {
            self.emit_shares_snapshot();
        }
        self.post_rollcall().await;
    }

    /// Post a sealed, self-signed [`wire::ShareRollCall`] into the lobby — the
    /// single late-join hook (startup / Refresh / reconcile all route here). A
    /// missing lobby/identity or a seal failure is non-fatal (discovery self-heals
    /// on the next tick); a closed stream is silently dropped.
    async fn post_rollcall(&self) {
        let Some(room) = self.public_room.as_ref() else {
            return;
        };
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        let fields = RollCallFields {
            room: &room.room,
            requester_handle: &self.my_handle,
            sent_unix_ms: now_unix_ms(),
        };
        let Ok(sealed) = seal_public_rollcall(&room.room_key, identity.signing(), &fields) else {
            return;
        };
        let frame = wire::CotFrame {
            asset_address: room.asset_addr.as_bytes().to_vec(),
            payload: sealed,
        };
        let _ = room.out_tx.send(frame).await;
    }

    /// Build and emit a [`NetEvent::SharesSnapshot`] from the in-band
    /// [`ShareCatalog`]. The single snapshot builder shared by
    /// [`Self::handle_refresh_shares`] and the catalog-mutating discovery handlers,
    /// so every surface renders the same rows. The recipient applies its private
    /// hide set at render (ISC-A-C3); the catalog carries every discovered share.
    fn emit_shares_snapshot(&self) {
        self.emit(NetEvent::SharesSnapshot {
            shares: self.catalog_listings(),
        });
    }

    /// Render the in-band [`ShareCatalog`] as the public-share rows
    /// ([`ShareListing`]) so the UI surface is unchanged from the
    /// retired `ListPublicShares` path.
    fn catalog_listings(&self) -> Vec<ShareListing> {
        // Own shares are never reflected back by the relay, so they never enter the
        // received-announcement catalog — merge them in first (deduped by share_id)
        // so a publisher sees their own shares in their own Shares list, not only on
        // other clients.
        let mut seen = std::collections::HashSet::new();
        let mut out: Vec<ShareListing> = Vec::new();
        for own in self.own_shares.borrow().iter() {
            if seen.insert(own.share_id.clone()) {
                out.push(ShareListing {
                    share_id: own.share_id.clone(),
                    name: own.name.clone(),
                    rating: own.rating.clone(),
                    sharer_handle: own.sharer_handle.clone(),
                });
            }
        }
        for s in self.share_catalog.entries() {
            if seen.insert(s.share_id.clone()) {
                out.push(ShareListing::from(&s));
            }
        }
        out
    }

    /// The single late-join hook (unified share model): post a roll-call so every
    /// live sharer re-announces, then snapshot. The catalog filled by those answers
    /// (and by ongoing live announces) IS the public-shares pane — the relay holds
    /// no share directory (ISC-A-S2). Best-effort: a missing lobby is a no-op and
    /// the snapshot still renders what is known. See [`NetCommand::RefreshShares`].
    async fn handle_refresh_shares(&mut self) {
        self.post_rollcall().await;
        self.emit_shares_snapshot();
    }

    /// (#91) Fetch the connected relay's public space — signer whitelist, MOTD, and
    /// announcement posts — re-verify it client-side via
    /// [`build_announcements_view`] (trusting nothing the relay asserts, ISC-A-S3),
    /// and emit a single [`NetEvent::PublicSpaceSnapshot`]. Mirrors the TUI's
    /// `handle_refresh_public_space`. Any missing session / pinned key, or a refused
    /// RPC, surfaces as [`NetEvent::PublicSpaceError`] and leaves the pane unchanged.
    ///
    /// `connect_time` (#93) is threaded onto the emitted
    /// [`NetEvent::PublicSpaceSnapshot`] so the binary auto-lands on the pane only
    /// for the connect-time fetch — `true` from the post-connect fetch, `false` from
    /// the manual Refresh / on-tab poll / post-upload refresh.
    async fn handle_refresh_public_space(&mut self, connect_time: bool) {
        let (Some(session), Some(server_pubkey)) =
            (self.session.as_ref(), self.server_pubkey.as_ref())
        else {
            return self.emit(NetEvent::PublicSpaceError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let server_pubkey = server_pubkey.clone();
        let mut ps = session.public_space();

        let whitelist = match ps
            .get_signer_whitelist(wire::GetSignerWhitelistRequest {})
            .await
        {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("signer-whitelist fetch refused: {}", status.message()),
                });
            }
        };
        let motd = match ps.get_motd(wire::GetMotdRequest {}).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("MOTD fetch refused: {}", status.message()),
                });
            }
        };
        let posts = match ps.list_posts(wire::ListPostsRequest { topic: None }).await {
            Ok(resp) => resp.into_inner(),
            Err(status) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("posts fetch refused: {}", status.message()),
                });
            }
        };

        let view = build_announcements_view(&motd, &posts, &whitelist, &server_pubkey);
        // (#92) Self-determine signer status against the SAME published whitelist
        // (`composer_visible`, fail-closed): true only when a stable identity key is
        // held AND it is on the relay's published whitelist. A non-signer or the
        // ephemeral / no-profile path yields false → the pane stays read-only.
        let can_compose = self
            .stable_signing_key
            .as_ref()
            .is_some_and(|kp| composer_visible(kp.public_key(), &whitelist.entries));
        self.emit(NetEvent::PublicSpaceSnapshot {
            view,
            can_compose,
            connect_time,
        });
    }

    /// (#92) Sign an announcement post with the held stable identity key and
    /// upload it via `UploadPost`, then refresh so it appears. Mirrors the TUI
    /// authoring path. Guards: a missing stable key (non-signer / ephemeral) or no
    /// live session surfaces a [`NetEvent::PublicSpaceError`] and uploads nothing;
    /// the relay independently re-verifies the signature against the published
    /// whitelist before storing (ISC-S8), so a non-signer can never write.
    async fn handle_upload_announcement(&mut self, topic: &str, body: &str) {
        let Some(kp) = self.stable_signing_key.as_ref() else {
            return self.emit(NetEvent::PublicSpaceError {
                message: "not a signer on this relay — cannot post announcements".to_owned(),
            });
        };
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::PublicSpaceError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let ts = now_unix_ms();
        let artifact = match sign_post(kp, topic, body, ts) {
            Ok(a) => a,
            Err(e) => {
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("could not sign announcement: {e}"),
                });
            }
        };
        let mut ps = session.public_space();
        match ps
            .upload_post(wire::UploadPostRequest {
                artifact: Some(artifact),
            })
            .await
        {
            Ok(_) => self.handle_refresh_public_space(false).await,
            Err(status) => self.emit(NetEvent::PublicSpaceError {
                message: format!("announcement upload refused: {}", status.message()),
            }),
        }
    }

    /// (#92) Sign a MOTD with the held stable identity key ([`sign_motd`] enforces
    /// the ISC-S9 single-line-plaintext rule BEFORE signing) and upload it via
    /// `UploadMotd` (#89), then refresh. Non-plaintext text is rejected before any
    /// upload and surfaced as a [`NetEvent::PublicSpaceError`] — the composer shows
    /// (#66) Adopt a renamed display handle for the rest of this session — the live
    /// counterpart of the `Connect{display_handle}` assignment, applied without a
    /// reconnect. Only the presented name changes; the ephemeral connection proof is
    /// untouched (D8).
    fn handle_set_my_handle(&mut self, handle: String) {
        self.my_handle = handle;
    }

    /// the message rather than silently dropping. Same no-stable-key / no-session
    /// guards as [`Self::handle_upload_announcement`].
    async fn handle_set_motd(&mut self, text: &str) {
        let Some(kp) = self.stable_signing_key.as_ref() else {
            return self.emit(NetEvent::PublicSpaceError {
                message: "not a signer on this relay — cannot set the MOTD".to_owned(),
            });
        };
        let Some(session) = self.session.as_ref() else {
            return self.emit(NetEvent::PublicSpaceError {
                message: "not connected to a relay yet".to_owned(),
            });
        };
        let ts = now_unix_ms();
        let artifact = match sign_motd(kp, text, ts) {
            Ok(a) => a,
            Err(e) => {
                // Includes the ISC-S9 plaintext rejection (single line, no
                // markup/links) — surfaced, not silently dropped.
                return self.emit(NetEvent::PublicSpaceError {
                    message: format!("could not set MOTD: {e}"),
                });
            }
        };
        let mut ps = session.public_space();
        match ps
            .upload_motd(wire::UploadMotdRequest {
                artifact: Some(artifact),
            })
            .await
        {
            Ok(_) => self.handle_refresh_public_space(false).await,
            Err(status) => self.emit(NetEvent::PublicSpaceError {
                message: format!("MOTD upload refused: {}", status.message()),
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
            room_key,
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
                let chunk_req = match seal_public_share_frame(
                    &room_key,
                    &ShareFrame::ChunkRequest { chunk_addr: *addr },
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        return fail_fetch(
                            self,
                            &written,
                            format!("could not seal chunk request: {e}"),
                        )
                        .await;
                    }
                };
                if out_tx
                    .send(share_frame(&asset_bytes, chunk_req))
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
                    match open_share_frame(&room_key, &resp.payload) {
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

        // Content-frame seal key for a PUBLIC share: the public room key, from
        // public inputs (lobby room name + suite), derived independently of the
        // serve side — never from `share_id`. Requests ride sealed under it and
        // responses are opened with it, so share traffic is structurally
        // indistinguishable from chat on the wire (was cleartext); see
        // `docs/design/unified-share-model.md` workstream A.
        let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0)
            .map_err(|e| format!("share seal-key derivation failed: {e}"))?;

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
        let manifest_req = seal_public_share_frame(&room_key, &ShareFrame::ManifestRequest)
            .map_err(|e| format!("could not seal manifest request: {e}"))?;
        out_tx
            .send(share_frame(&asset_bytes, manifest_req))
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
            // Open the sealed response under the public room key; a wrong-key /
            // tampered / foreign payload fails closed and is skipped.
            match open_share_frame(&room_key, &resp.payload) {
                Ok(ShareFrame::ManifestResponse { entries }) => break entries,
                _ => continue,
            }
        };
        Ok(OpenedShare {
            out_tx,
            inbound,
            asset_bytes,
            manifest,
            room_key,
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
    /// The public room key the content frames are sealed/opened under. Derived
    /// once when the stream opens and reused for the manifest + every chunk.
    /// Public-share-only (this fetch path serves the public tier); see
    /// `docs/design/unified-share-model.md` workstream A.
    room_key: PublicRoomKey,
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
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
) {
    let mut actor = Actor::new(evt_tx, cmd_tx);
    // Start the presence-heartbeat timer ONCE for the actor's life (#74/#75) — not
    // per join, so a reconnect/rejoin can never double-emit. The emit handler is a
    // no-op until a lobby is joined and an identity is held.
    actor.start_heartbeat_timer();
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            NetCommand::Connect {
                server_id,
                address,
                display_handle,
                rejoin_circles,
                republish_roots,
                index_params,
                stable_signing_key,
            } => {
                actor
                    .handle_connect(
                        &server_id,
                        &address,
                        display_handle,
                        rejoin_circles,
                        republish_roots,
                        index_params,
                        stable_signing_key,
                    )
                    .await
            }
            NetCommand::SetMyHandle { handle } => actor.handle_set_my_handle(handle),
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
            NetCommand::RefreshPublicSpace => actor.handle_refresh_public_space(false).await,
            NetCommand::UploadAnnouncement { topic, body } => {
                actor.handle_upload_announcement(&topic, &body).await
            }
            NetCommand::SetMotd { text } => actor.handle_set_motd(&text).await,
            NetCommand::ApplyAnnouncement(ann) => actor.handle_apply_announcement(&ann),
            NetCommand::AnswerRollCall => actor.handle_answer_rollcall().await,
            NetCommand::EmitHeartbeat => actor.handle_emit_heartbeat().await,
            NetCommand::ApplyHeartbeat { room, heartbeat } => {
                actor.handle_apply_heartbeat(&room, &heartbeat)
            }
            NetCommand::ReconcileShares => actor.handle_reconcile_shares().await,
            NetCommand::Reconnect => actor.handle_reconnect().await,
            NetCommand::ResubscribeRoom => actor.handle_resubscribe_room().await,
            NetCommand::ResubscribeCircle { circle_id } => {
                actor.handle_resubscribe_circle(circle_id).await
            }
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
            #[cfg(test)]
            NetCommand::ReattachSession {
                session,
                server_id,
                display_handle,
                rejoin_circles,
            } => {
                actor
                    .handle_reattach(session, server_id, display_handle, rejoin_circles)
                    .await
            }
            #[cfg(test)]
            NetCommand::ProbeConnected => actor.emit(NetEvent::ConnectedProbe {
                connected: actor.connected,
            }),
            #[cfg(test)]
            NetCommand::SetIndexHome {
                index_dir,
                index_key,
            } => {
                actor.index_home = Some((index_dir, index_key));
            }
            #[cfg(test)]
            NetCommand::ProbeCachedAddr { root, rel_path } => {
                let addr = actor.probe_cached_addr(&root, &rel_path);
                actor.emit(NetEvent::CachedAddrProbe { addr });
            }
        }
    }
}

/// Inbound reader for a public room. Mirrors
/// `daemonseed_tui::net::read_inbound_public_room`. Three kinds share the lobby
/// stream, each with a distinct AAD so only the matching open succeeds (the rest
/// fail closed and are skipped), each under the global room key:
///
///   1. a chat [`open_room_message`] → [`NetEvent::Message`];
///   2. a share [`open_announcement`] (unified share model) →
///      [`NetCommand::ApplyAnnouncement`] folded into the actor's catalog;
///   3. a [`open_rollcall`] → [`NetCommand::AnswerRollCall`] (re-announce our own
///      shares);
///   4. a member [`open_heartbeat`] (#74) → [`NetCommand::ApplyHeartbeat`] folded
///      into the lobby's presence tracker.
///
/// The discovery and presence kinds go back through `cmd_tx` so every catalog and
/// tracker mutation stays on the actor's `&mut self`. Empty payloads (the subscribe stream's
/// initial/keepalive frames) are skipped BEFORE any open. A frame whose seal or
/// provenance signature does not verify under any kind is dropped silently (a
/// foreign frame). Returns when the stream ends or either channel closes.
async fn read_inbound_public_room(
    mut inbound: tonic::Streaming<wire::CotFrame>,
    room: String,
    room_key: Rc<daemonseed_core::public_room::PublicRoomKey>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    my_handle: String,
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
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
                } else if let Ok(ann) = open_announcement(room_key.as_ref(), &frame.payload) {
                    // A verified share announcement — fold into the actor's catalog
                    // on its command loop (unified share model).
                    if cmd_tx
                        .send(NetCommand::ApplyAnnouncement(Box::new(ann)))
                        .is_err()
                    {
                        return; // actor gone
                    }
                } else if open_rollcall(room_key.as_ref(), &frame.payload).is_ok() {
                    // A verified roll-call — answer by re-announcing our shares. The
                    // verified fields beyond "it opened" are unused (we re-announce
                    // everything regardless of who asked).
                    if cmd_tx.send(NetCommand::AnswerRollCall).is_err() {
                        return; // actor gone
                    }
                } else if let Ok(hb) = open_heartbeat(room_key.as_ref(), &frame.payload) {
                    // A verified member beacon (#74) — fold into the lobby's presence
                    // tracker on the actor's command loop (all tracker mutation stays
                    // on `&mut self`).
                    if cmd_tx
                        .send(NetCommand::ApplyHeartbeat {
                            room: room.clone(),
                            heartbeat: Box::new(hb),
                        })
                        .is_err()
                    {
                        return; // actor gone
                    }
                }
                // A frame that opened under none of the four kinds is a foreign
                // frame — skip silently.
            }
            // #80: the subscribe stream ended (`Ok(None)`) or errored (`Err`). Both
            // a graceful per-stream EOS on a LIVE connection and a dead half-open
            // socket surface here (the relay's GOAWAY arrives as end-of-stream), so
            // the result code can't tell them apart. Ask the actor to RE-SUBSCRIBE
            // the lobby; the re-subscribe attempt is the active probe — success means
            // the connection is alive (don't tear down circles), failure means it is
            // dead (the handler then posts Disconnected → teardown + reconnect, #72/#71).
            // Best-effort: if the actor is already gone the send fails and we return.
            Ok(None) | Err(_) => {
                let _ = cmd_tx.send(NetCommand::ResubscribeRoom);
                return;
            }
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
    cot_key: Rc<CircleKey>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    my_handle: String,
    cmd_tx: mpsc::UnboundedSender<NetCommand>,
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
                } else if let Ok(hb) = open_heartbeat(cot_key.as_ref(), &frame.payload) {
                    // A verified member beacon (#77) sealed under THIS circle's key —
                    // fold into this circle's presence tracker on the actor's command
                    // loop (all tracker mutation stays on `&mut self`). The routing
                    // key is this circle's GUI id; `handle_apply_heartbeat` parses it
                    // back to find the matching circle (the lobby is the room name).
                    if cmd_tx
                        .send(NetCommand::ApplyHeartbeat {
                            room: circle_id.to_string(),
                            heartbeat: Box::new(hb),
                        })
                        .is_err()
                    {
                        return; // actor gone
                    }
                }
                // A frame that opened under neither kind is foreign — skip silently.
            }
            // #80: a circle subscribe stream ended/errored. Re-subscribe just THIS
            // circle on the live session (same active-probe rationale as the lobby
            // reader). If the connection is actually dead the handler's re-subscribe
            // fails and it posts Disconnected (idempotent teardown collapses the
            // duplicates from sibling readers of the same dead connection).
            Ok(None) | Err(_) => {
                let _ = cmd_tx.send(NetCommand::ResubscribeCircle { circle_id });
                return;
            }
        }
    }
}

/// The auto-reconnect backoff delay for a given attempt index (#71): capped
/// exponential — `min(RECONNECT_BACKOFF_BASE · 2^attempt, RECONNECT_BACKOFF_MAX)`.
/// Attempt 0 is the first retry after a drop; the delay doubles each failed
/// attempt and saturates at the cap so a long outage retries steadily, never in a
/// busy-loop and never backing off unboundedly.
fn reconnect_backoff(attempt: u32) -> Duration {
    let base = RECONNECT_BACKOFF_BASE.as_secs();
    // 2^attempt with overflow saturating straight to the cap.
    let secs = base.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
    Duration::from_secs(secs.min(RECONNECT_BACKOFF_MAX.as_secs()))
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

/// The self-filter predicate (#74/#77): true when a beacon's signer pubkey is our
/// OWN identity key, so a daemon never lists itself as a live OTHER member. The
/// relay should never fan a sender's own beacon back, but this filters it
/// defensively at ingest, for the lobby and every circle alike. Extracted so the
/// per-room self-filter is unit-testable independently of the actor.
fn beacon_is_own(own_pubkey: &[u8], beacon_pubkey: &[u8]) -> bool {
    own_pubkey == beacon_pubkey
}

/// Whether a [`PresenceChange`] from `apply` changes what the roster renders: a
/// member appearing always does; a refresh only when it changed the displayed
/// handle (a same-handle refresh is invisible to the UI); an unchanged apply never
/// does. Shared by the lobby and per-circle ingest so both push a fresh roster on
/// exactly the same condition.
fn roster_render_changed(
    change: PresenceChange,
    prior_handle: Option<&str>,
    new_handle: &str,
) -> bool {
    match change {
        PresenceChange::Appeared => true,
        PresenceChange::Refreshed => prior_handle != Some(new_handle),
        PresenceChange::Unchanged => false,
    }
}

/// Build the roster rows from a presence tracker's current members. Mirrors
/// [`PresenceTracker::members`] ordering (handle, then pubkey) for a stable view,
/// and binds each row's `fingerprint` to the verified pubkey via
/// [`member_fingerprint`]. Keying lives in the tracker (by pubkey), so two members
/// sharing a display name yield two distinct rows here.
fn roster_from_members(members: &[LiveMember]) -> Vec<RosterEntry> {
    members
        .iter()
        .map(|m| RosterEntry {
            handle: m.handle.clone(),
            fingerprint: member_fingerprint(&m.pubkey),
        })
        .collect()
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
    use std::time::Duration;

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

    /// #66: `SetMyHandle` updates the presented handle in place — the same
    /// `my_handle` field a `Connect{display_handle}` sets, which drives local echoes,
    /// heartbeats, and `mine` detection. A rename therefore presents the new name
    /// without a reconnect.
    #[test]
    fn set_my_handle_updates_presented_handle() {
        let (evt_tx, _evt_rx) = mpsc::unbounded_channel();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let mut actor = Actor::new(evt_tx, cmd_tx);
        let original = actor.my_handle.clone();
        actor.handle_set_my_handle("battle-otter#abc123def456".to_owned());
        assert_eq!(actor.my_handle, "battle-otter#abc123def456");
        assert_ne!(actor.my_handle, original, "the presented handle changed");
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

    /// A transport wrapper whose I/O can be force-killed (#72 oracle): once
    /// `kill()` fires, every read returns EOF and every write/flush errors, exactly
    /// as a dead socket (a VPN namespace swap black-holing the TCP connection)
    /// behaves to the h2 layer. Aborting the relay *task* alone does NOT close the
    /// connection — tonic keeps the live h2 connection on internal runtime tasks the
    /// outer abort never touches — so the test needs a transport it can actually
    /// sever. Wrapping the relay's SERVER-side IO and killing it propagates EOF to
    /// the CLIENT's subscribe stream, the same end-of-stream the reader exits on.
    /// Shared kill switch for [`KillableIo`]: a flag plus the parked read [`Waker`]
    /// so flipping the flag also WAKES the server's parked read. Without the wake, a
    /// kill on an idle connection (no frames flowing) would never be observed —
    /// `poll_read` is parked and only re-polls when the underlying duplex signals,
    /// which a mere flag flip does not do. Modelling the dead socket faithfully
    /// requires actively waking the reader.
    #[derive(Default)]
    struct KillSwitch {
        killed: std::sync::atomic::AtomicBool,
        read_waker: std::sync::Mutex<Option<std::task::Waker>>,
    }

    impl KillSwitch {
        fn kill(&self) {
            self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(w) = self.read_waker.lock().unwrap().take() {
                w.wake();
            }
        }
        fn dead(&self) -> bool {
            self.killed.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    struct KillableIo {
        inner: tokio::io::DuplexStream,
        kill: Arc<KillSwitch>,
    }

    impl tokio::io::AsyncRead for KillableIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.kill.dead() {
                // EOF — the peer is gone. The server's h2 layer sees the read close
                // and writes a GOAWAY, ending the CLIENT's subscribe stream.
                return std::task::Poll::Ready(Ok(()));
            }
            // Park our waker so a later `kill()` wakes this read even while idle.
            *self.kill.read_waker.lock().unwrap() = Some(cx.waker().clone());
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for KillableIo {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            // Writes pass through even after kill so the server can still write its
            // GOAWAY to terminate the client's stream promptly; a write-error would
            // strand the client. The kill models the read direction dying.
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A relay whose server-side transport can be force-killed mid-session (#72
    /// oracle). Returns a [`KillSwitch`]: calling `kill()` severs the connection
    /// (read-EOF + wake) so the client's subscribe stream ends. The relay still
    /// uses a real `serve_application`; only the transport under it is killable.
    fn spawn_killable_relay(
        server_io: tokio::io::DuplexStream,
        registry: CotRegistry,
    ) -> (
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
        Arc<KillSwitch>,
    ) {
        let kill = Arc::new(KillSwitch::default());
        let io = KillableIo {
            inner: server_io,
            kill: Arc::clone(&kill),
        };
        let task = tokio::task::spawn_local(serve_application(
            io,
            PublicSpaceService::new(Arc::new(PublicSpaceState::empty())),
            registry,
            Arc::new(Vec::new()),
        ));
        (task, kill)
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
        // The actor clones this self-sender for its detached discovery tasks (the
        // lobby inbound reader, the reconcile timer), mirroring `NetHandle::new`.
        let cmd_tx_actor = cmd_tx.clone();
        tokio::task::spawn_local(net_actor(cmd_rx, cmd_tx_actor, evt_tx));
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
    /// relay: actor A joins the lobby and publishes a two-file directory (in-band
    /// announce + `serve_share`); actor B previews the manifest, downloads to a temp
    /// root, and recovers both files byte-for-byte (each chunk SHA-384-verified).
    /// Exercises the GUI's OWN publish + fetch handlers — not the inlined core path.
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

            // A joins the lobby first: in-band publish posts a `ShareAnnouncement`
            // onto the lobby stream, so a publish needs a joined room (unified share
            // model). This registers the lobby asset.
            a.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            wait_for_room_joined(&mut a.evt_rx).await;

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
            // A's serve subscription must be live before B fetches: the lobby asset
            // plus the share's serve asset = 2 live assets.
            wait_registry(&registry, 2).await;

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

    /// Drain events until a [`NetEvent::CachedAddrProbe`] arrives; the outer `Option`
    /// is `Some` once the probe replied, the inner is the probed address (the first
    /// cached chunk address, or `None` if the index has no cached blob for it).
    async fn wait_for_cached_addr(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<Option<Vec<u8>>> {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                if let NetEvent::CachedAddrProbe { addr } = evt {
                    return Some(addr);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    /// (#81) The publish path reuses the persisted chunk-address cache instead of
    /// re-hashing from scratch. After a first publish caches a file's chunk address,
    /// the file's BYTES are rewritten at the SAME size + mtime (so the cache's
    /// size+mtime stat triplet still matches) and the share is published AGAIN: a
    /// cache HIT leaves the cached address unchanged (the rewritten bytes were never
    /// read, let alone re-hashed), whereas a from-scratch re-hash would replace it
    /// with the new bytes' address. Mirrors the core
    /// `cached_or_hash_writes_back_multi_addr_then_hits_without_reading` test,
    /// observed end-to-end through the GUI net actor.
    #[test]
    fn publish_reuses_persisted_cache_not_rehash() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;

        let _ = oxicrypt_module::initialize();

        // A real share-index key, derived the production way (the sibling of the
        // at-rest key from one Argon2id run) — no synthetic key, no new core API.
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";
        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let index_key = verified
            .finalize(
                Some("alice".to_string()),
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials()
            .index_key;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let registry = CotRegistry::new();
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let _srv = spawn_relay(server_io, registry.clone());
            let sess = AppSession::open(client_io).await.expect("session");

            let mut a = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            a.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            wait_for_room_joined(&mut a.evt_rx).await;

            // Set the persisted-index home (a temp dir) the SAME way a real
            // Connect{index_params} does; the publish opens its per-share file under it.
            let index_dir = tempfile::TempDir::new().unwrap();
            a.cmd_tx
                .send(NetCommand::SetIndexHome {
                    index_dir: index_dir.path().to_path_buf(),
                    index_key,
                })
                .ok();

            // A single-file share. The bytes hash to address X.
            let share_dir = tempfile::TempDir::new().unwrap();
            let file_path = share_dir.path().join("doc.bin");
            let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
            std::fs::write(&file_path, &original).unwrap();

            // First publish: a MISS → hash → write-back of the address.
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: share_dir.path().to_path_buf(),
                    name: "doc-share".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("first publish started");
            a.cmd_tx
                .send(NetCommand::ProbeCachedAddr {
                    root: share_dir.path().to_path_buf(),
                    rel_path: "doc.bin".to_owned(),
                })
                .ok();
            let first_addr = wait_for_cached_addr(&mut a.evt_rx)
                .await
                .expect("probe replied")
                .expect("first publish wrote a cached chunk address (the cache path ran)");

            // Rewrite the file with DIFFERENT bytes of the SAME length, then restore
            // the original mtime so the cache's (size, mtime) stat triplet still
            // matches — the only way a re-hash vs cache-hit is observable.
            let mtime = std::fs::metadata(&file_path).unwrap().modified().unwrap();
            let mut rewritten = original.clone();
            rewritten[0] ^= 0xff;
            std::fs::write(&file_path, &rewritten).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&file_path)
                .unwrap()
                .set_modified(mtime)
                .unwrap();

            // Second publish of the unchanged-by-stat file: a cache HIT — the file is
            // never read or re-hashed, so the index still holds the ORIGINAL address.
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: share_dir.path().to_path_buf(),
                    name: "doc-share-2".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("second publish started");
            a.cmd_tx
                .send(NetCommand::ProbeCachedAddr {
                    root: share_dir.path().to_path_buf(),
                    rel_path: "doc.bin".to_owned(),
                })
                .ok();
            let second_addr = wait_for_cached_addr(&mut a.evt_rx)
                .await
                .expect("probe replied")
                .expect("the cached address survives the second publish");

            assert_eq!(
                first_addr, second_addr,
                "the republish was a cache HIT — the rewritten bytes were never \
                 re-hashed, so the cached chunk address is unchanged (a from-scratch \
                 re-hash would have produced the new bytes' address)"
            );
        });
    }

    /// (#81) The multi-share regression: each published share keeps its OWN cache, so
    /// publishing a SECOND share never evicts the FIRST share's cache. This is the
    /// exact bug a multi-share user hit — a single shared index re-pointed (and
    /// cross-pruned) on every publish, so every share re-hashed on every launch.
    ///
    /// Reproduction: publish share A (caches A's address), publish share B in between,
    /// then corrupt A's file at the SAME size+mtime and publish A again. With per-share
    /// index files A's republish is a cache HIT (address unchanged). With the old
    /// single-active index, B's publish would have evicted A's entry, so A's republish
    /// would MISS and re-hash → a DIFFERENT (corrupted-bytes) address — the assertion
    /// below would fail.
    #[test]
    fn second_share_publish_does_not_evict_first_share_cache() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;

        let _ = oxicrypt_module::initialize();

        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            // A real share-index key, derived the production way.
            let sealed = FirstStart::new().initialize(pass, fast).unwrap();
            let phrase = sealed.display_phrase();
            let index_key = sealed
                .verify_round_trip(&phrase)
                .unwrap()
                .finalize(
                    Some("alice".to_string()),
                    BootstrapAnchor {
                        server_id: "relay#aabbccddeeff".to_string(),
                        address: "127.0.0.1:443".to_string(),
                    },
                )
                .unwrap()
                .into_session_materials()
                .index_key;

            let registry = CotRegistry::new();
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let _srv = spawn_relay(server_io, registry.clone());
            let sess = AppSession::open(client_io).await.expect("session");

            let mut a = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: None,
                    rejoin_circles: Vec::new(),
                })
                .ok();
            a.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            wait_for_room_joined(&mut a.evt_rx).await;

            // One shared index home; TWO distinct share roots under it.
            let index_dir = tempfile::TempDir::new().unwrap();
            a.cmd_tx
                .send(NetCommand::SetIndexHome {
                    index_dir: index_dir.path().to_path_buf(),
                    index_key,
                })
                .ok();

            let share_a = tempfile::TempDir::new().unwrap();
            let file_a = share_a.path().join("a.bin");
            let bytes_a: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
            std::fs::write(&file_a, &bytes_a).unwrap();
            let mtime_a = std::fs::metadata(&file_a).unwrap().modified().unwrap();

            let share_b = tempfile::TempDir::new().unwrap();
            let file_b = share_b.path().join("b.bin");
            let bytes_b: Vec<u8> = (0..4096u32).map(|i| ((i + 7) % 251) as u8).collect();
            std::fs::write(&file_b, &bytes_b).unwrap();

            // Publish A → MISS → hash → write-back A's address.
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: share_a.path().to_path_buf(),
                    name: "share-a".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("share A published");
            a.cmd_tx
                .send(NetCommand::ProbeCachedAddr {
                    root: share_a.path().to_path_buf(),
                    rel_path: "a.bin".to_owned(),
                })
                .ok();
            let a_addr_before = wait_for_cached_addr(&mut a.evt_rx)
                .await
                .expect("probe replied")
                .expect("share A cached its address");

            // Publish B in between — under the old single-active index this re-points
            // and cross-prunes A's entry from the shared db.
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: share_b.path().to_path_buf(),
                    name: "share-b".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("share B published");

            // Corrupt A's file at the SAME size+mtime so a re-hash is observable as a
            // changed address, while a cache hit leaves the original address.
            let mut rewritten = bytes_a.clone();
            rewritten[0] ^= 0xff;
            std::fs::write(&file_a, &rewritten).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&file_a)
                .unwrap()
                .set_modified(mtime_a)
                .unwrap();

            // Republish A: with per-share files this is a cache HIT despite B's publish.
            a.cmd_tx
                .send(NetCommand::PublishShare {
                    root: share_a.path().to_path_buf(),
                    name: "share-a-again".to_owned(),
                    sharer_handle: "alice#aabbccddeeff".to_owned(),
                })
                .ok();
            wait_for_publish_started(&mut a.evt_rx)
                .await
                .expect("share A republished");
            a.cmd_tx
                .send(NetCommand::ProbeCachedAddr {
                    root: share_a.path().to_path_buf(),
                    rel_path: "a.bin".to_owned(),
                })
                .ok();
            let a_addr_after = wait_for_cached_addr(&mut a.evt_rx)
                .await
                .expect("probe replied")
                .expect("share A still has its cached address after B's publish");

            assert_eq!(
                a_addr_before, a_addr_after,
                "share A's cache survived an intervening publish of share B — per-share \
                 index files never cross-evict (a single shared index would have pruned \
                 A on B's publish, forcing a re-hash to the corrupted bytes' address)"
            );
        });
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

    /// Drain `SharesSnapshot`s until one whose membership of `share_id` matches
    /// `present`. Multiple snapshots arrive (a roll-call answer folds in an
    /// announcement, then a withdraw removes it), so a discovery test waits for the
    /// snapshot in the desired state rather than the first one.
    async fn wait_for_snapshot_contains(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
        share_id: &str,
        present: bool,
    ) -> bool {
        for _ in 0..600 {
            while let Ok(evt) = evt_rx.try_recv() {
                match evt {
                    NetEvent::SharesSnapshot { shares } => {
                        if shares.iter().any(|s| s.share_id == share_id) == present {
                            return true;
                        }
                    }
                    NetEvent::SharesError { message } => panic!("refresh failed: {message}"),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    /// In-band discovery, end-to-end through TWO GUI actors on a shared in-process
    /// relay (unified share model): A joins the lobby and publishes; B joins the
    /// lobby and `RefreshShares` (posts a roll-call); A answers by re-announcing, so
    /// B's catalog gains the share and B's `SharesSnapshot` lists it. A then
    /// `UnpublishShare`s — a withdraw announcement — and B's catalog drops it (a
    /// later snapshot omits it). Exercises the GUI's roll-call / announce / withdraw
    /// path the publish→fetch round-trip does not.
    #[test]
    fn share_discovery_lists_peer_publish_then_withdraws() {
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

            // Both join the SAME lobby (same room + server_id → same rendezvous):
            // the relay holds one lobby asset both subscribe to. B joins first and
            // waits for the asset so A's announce is not a no-op against an empty one.
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
            wait_for_room_joined(&mut a.evt_rx).await;

            // A publishes (posts a `ShareAnnouncement` to the lobby + serves).
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

            // B refreshes: posts a roll-call → A re-announces → B's catalog folds it
            // in → B emits a SharesSnapshot that lists A's share.
            b.cmd_tx.send(NetCommand::RefreshShares).ok();
            assert!(
                wait_for_snapshot_contains(&mut b.evt_rx, &share_id, true).await,
                "B discovers A's just-published share in-band"
            );

            // A unpublishes → a withdraw announcement → B's catalog drops it.
            a.cmd_tx
                .send(NetCommand::UnpublishShare {
                    share_id: share_id.clone(),
                })
                .ok();
            assert_eq!(
                wait_for_publish_stopped(&mut a.evt_rx).await.as_deref(),
                Some(share_id.as_str()),
                "UnpublishShare emits PublishStopped for the share"
            );
            assert!(
                wait_for_snapshot_contains(&mut b.evt_rx, &share_id, false).await,
                "B drops A's share after the withdraw announcement"
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

    /// Wait for the actor to surface a drop (#72): returns the `Disconnected`
    /// event's reason, or `None` if none arrived within the budget.
    async fn wait_for_disconnected(
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> Option<String> {
        for _ in 0..400 {
            while let Ok(evt) = evt_rx.try_recv() {
                if let NetEvent::Disconnected { reason } = evt {
                    return Some(reason);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }

    /// Probe the actor's `connected` flag via the test seam and return it. Drains
    /// any interleaved events until the [`NetEvent::ConnectedProbe`] reply arrives.
    async fn probe_connected(
        cmd_tx: &mpsc::UnboundedSender<NetCommand>,
        evt_rx: &mut mpsc::UnboundedReceiver<NetEvent>,
    ) -> bool {
        cmd_tx.send(NetCommand::ProbeConnected).ok();
        for _ in 0..400 {
            while let Ok(evt) = evt_rx.try_recv() {
                if let NetEvent::ConnectedProbe { connected } = evt {
                    return connected;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("actor never answered ProbeConnected");
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

    /// #72 + #71 ORACLE: a dropped inbound stream surfaces a [`NetEvent::Disconnected`]
    /// and tears the actor's live state down (`connected == false`), then the
    /// re-establish path re-subscribes the persisted circle and a post-reconnect
    /// send/receive round-trips. Mirrors `in_process_circle_round_trip`, adding the
    /// drop + reconnect legs.
    ///
    /// The drop is staged the in-process way a half-open socket dies: A's relay
    /// server task is aborted, so A's `Subscribe` inbound stream ends (`Ok(None)`)
    /// — the SAME exit arm a keepalive-detected `Err` takes. The reconnect is driven
    /// through the [`NetCommand::ReattachSession`] seam (a fresh in-memory session on
    /// the same relay) so the test exercises the actor's real re-subscribe logic
    /// without a TCP dial — carrying the persisted circle exactly as the stored
    /// [`ConnectPlan`]'s `rejoin_circles` would on a production backoff reconnect.
    #[test]
    fn disconnect_detected_then_reconnect_restores_circle() {
        let _ = oxicrypt_module::initialize();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            // One shared relay registry: B stays put across A's reconnect, and A's
            // FRESH post-reconnect session lands on the same relay so the round-trip
            // meets at the same circle rendezvous.
            let registry = CotRegistry::new();
            let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
            let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
            // A's relay rides a KILLABLE transport so the test can sever the
            // connection out from under A (an aborted relay task alone does not
            // close tonic's live h2 connection — see `spawn_killable_relay`).
            let (_srv_a, kill_a) = spawn_killable_relay(a_server_io, registry.clone());
            let _srv_b = spawn_relay(b_server_io, registry.clone());

            let sess_a = AppSession::open(a_client_io).await.expect("A session");
            let sess_b = AppSession::open(b_client_io).await.expect("B session");

            let mut a = spawn_local_actor();
            let mut b = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: Some("alice#stable".to_owned()),
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

            // B joins the circle and waits for the relay to register the rendezvous;
            // A joins the SAME circle. Baseline: A → B round-trips while live.
            b.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 1,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_registry(&registry, 1).await;
            a.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 9,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_for_circle_joined(&mut a.evt_rx).await;
            assert!(
                probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "A is connected after the initial attach + join"
            );
            a.cmd_tx
                .send(NetCommand::SendCircle {
                    circle_id: 9,
                    text: "before the drop".to_owned(),
                })
                .ok();
            assert_eq!(
                wait_for_circle_message(&mut b.evt_rx)
                    .await
                    .map(|(_, who, text)| (who, text)),
                Some(("alice#stable".to_owned(), "before the drop".to_owned())),
                "baseline: A → B round-trips on the live connection"
            );

            // ── DROP: sever A's transport. A's subscribe stream ends (`Ok(None)`)
            // → the inbound reader's exit arm posts Disconnected → the actor tears
            // down + emits. Yield so the runtime polls the EOF propagation on this
            // single thread. ──
            kill_a.kill();
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }

            let reason = wait_for_disconnected(&mut a.evt_rx)
                .await
                .expect("A surfaces a Disconnected event when its stream dies (#72)");
            assert!(
                !reason.is_empty(),
                "the Disconnected event carries a human-readable reason"
            );
            assert!(
                !probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "after the drop the actor cleared its live state (connected == false, #72)"
            );

            // ── RECONNECT: a fresh session on the same relay, carrying the persisted
            // circle — the SAME re-subscribe path a production backoff reconnect runs. ──
            let (a2_client_io, a2_server_io) = tokio::io::duplex(64 * 1024);
            let _srv_a2 = spawn_relay(a2_server_io, registry.clone());
            let sess_a2 = AppSession::open(a2_client_io).await.expect("A re-session");
            a.cmd_tx
                .send(NetCommand::ReattachSession {
                    session: sess_a2,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: Some("alice#stable".to_owned()),
                    rejoin_circles: vec![(9, CIRCLE_PHRASE.to_owned())],
                })
                .ok();
            wait_for_circle_joined(&mut a.evt_rx).await;
            assert!(
                probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "the reconnect restored the connection (connected == true, #71)"
            );

            // Post-reconnect round-trip: A sends on the re-subscribed circle, B
            // receives — the recovered connection restores the circle like a launch.
            a.cmd_tx
                .send(NetCommand::SendCircle {
                    circle_id: 9,
                    text: "after the reconnect".to_owned(),
                })
                .ok();
            assert_eq!(
                wait_for_circle_message(&mut b.evt_rx)
                    .await
                    .map(|(_, who, text)| (who, text)),
                Some(("alice#stable".to_owned(), "after the reconnect".to_owned())),
                "the re-subscribed circle round-trips after reconnect (#71)"
            );
        });
    }

    /// #80 ORACLE: a graceful per-stream EOS on a LIVE connection re-subscribes that
    /// one stream and leaves the rest of the session intact — it does NOT tear the
    /// whole session down (the v0.30.0 regression). Drives the real
    /// `handle_resubscribe_room` / `handle_resubscribe_circle` against a live
    /// in-process relay: after each re-subscribe the actor stays `connected` and the
    /// joined circle still round-trips A → B. (The graceful per-stream EOS is staged
    /// by posting the Resubscribe command the reader's exit arm posts on `Ok(None)`;
    /// the relay can't close one stream while keeping the connection up, so the
    /// command is the faithful stand-in for the handler under test. The pre-existing
    /// reader left running is a harmless test artifact — the A → B assertion reads
    /// A's fresh out half.)
    #[test]
    fn graceful_eos_resubscribes_without_tearing_down_session() {
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

            // B subscribes the circle rendezvous; A joins the lobby AND the same
            // circle. Baseline: A → B circle round-trips on the live connection.
            b.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 1,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_registry(&registry, 1).await;
            a.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            wait_for_room_joined(&mut a.evt_rx).await;
            a.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 9,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_for_circle_joined(&mut a.evt_rx).await;
            a.cmd_tx
                .send(NetCommand::SendCircle {
                    circle_id: 9,
                    text: "before the EOS".to_owned(),
                })
                .ok();
            assert_eq!(
                wait_for_circle_message(&mut b.evt_rx)
                    .await
                    .map(|(_, _, text)| text),
                Some("before the EOS".to_owned()),
                "baseline: A → B round-trips on the live connection"
            );

            // ── Graceful LOBBY EOS: re-subscribe the lobby. The session must stay up
            // and the joined circle must survive (the #80 anti-criterion: a lobby EOS
            // must NOT clear circles). ──
            a.cmd_tx.send(NetCommand::ResubscribeRoom).ok();
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "a graceful lobby EOS re-subscribes on the live connection; session stays up"
            );

            // ── Graceful CIRCLE EOS: re-subscribe just that circle. ──
            a.cmd_tx
                .send(NetCommand::ResubscribeCircle { circle_id: 9 })
                .ok();
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "a graceful circle EOS re-subscribes on the live connection; session stays up"
            );

            // The circle still round-trips after BOTH re-subscribes — proof the
            // session + circle survived and the re-subscribed stream is live.
            a.cmd_tx
                .send(NetCommand::SendCircle {
                    circle_id: 9,
                    text: "after the resubscribe".to_owned(),
                })
                .ok();
            assert_eq!(
                wait_for_circle_message(&mut b.evt_rx)
                    .await
                    .map(|(_, _, text)| text),
                Some("after the resubscribe".to_owned()),
                "the circle still round-trips after a lobby + circle re-subscribe (#80)"
            );
        });
    }

    /// #80 ORACLE (Advisor-required fall-through): when the connection is genuinely
    /// dead, the re-subscribe ATTEMPT fails, and the handler escalates to a full
    /// teardown — `Disconnected` fires and `connected` flips false. This is the path
    /// the brief's naive `Ok(None)`-vs-`Err` split would have broken; here the dead
    /// connection still tears down because the active-probe re-subscribe can't
    /// succeed on a severed transport (no transparent re-dial — [`AppSession::open`]).
    #[test]
    fn resubscribe_on_dead_connection_tears_down() {
        let _ = oxicrypt_module::initialize();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let registry = CotRegistry::new();
            let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
            let (_srv_a, kill_a) = spawn_killable_relay(a_server_io, registry.clone());
            let sess_a = AppSession::open(a_client_io).await.expect("A session");

            let mut a = spawn_local_actor();
            a.cmd_tx
                .send(NetCommand::AttachSession {
                    session: sess_a,
                    server_id: SERVER_ID.to_owned(),
                    display_handle: Some("alice#stable".to_owned()),
                    rejoin_circles: Vec::new(),
                })
                .ok();
            a.cmd_tx
                .send(NetCommand::JoinCircle {
                    circle_id: 9,
                    phrase: CIRCLE_PHRASE.to_owned(),
                })
                .ok();
            wait_for_circle_joined(&mut a.evt_rx).await;
            assert!(
                probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "A is connected after attach + join"
            );

            // Sever the transport. The circle reader hits EOF → posts ResubscribeCircle
            // → the handler's re-subscribe attempt fails on the dead connection →
            // escalates to handle_disconnected.
            kill_a.kill();
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                wait_for_disconnected(&mut a.evt_rx).await.is_some(),
                "a failed re-subscribe on a dead connection surfaces Disconnected (#80 fall-through)"
            );
            assert!(
                !probe_connected(&a.cmd_tx, &mut a.evt_rx).await,
                "the dead-connection teardown cleared live state (connected == false)"
            );
        });
    }

    /// #71: the auto-reconnect backoff is capped exponential and never zero — so the
    /// timer can't busy-loop and a long outage retries steadily rather than backing
    /// off forever.
    #[test]
    fn reconnect_backoff_is_capped_exponential() {
        assert_eq!(reconnect_backoff(0), RECONNECT_BACKOFF_BASE);
        assert_eq!(
            reconnect_backoff(1),
            Duration::from_secs(RECONNECT_BACKOFF_BASE.as_secs() * 2)
        );
        // Saturates at the cap and stays there for large / overflowing attempts.
        assert_eq!(reconnect_backoff(20), RECONNECT_BACKOFF_MAX);
        assert_eq!(reconnect_backoff(u32::MAX), RECONNECT_BACKOFF_MAX);
        // Never a busy-loop.
        assert!(reconnect_backoff(0) > Duration::ZERO);
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

            // In-band publish posts a `ShareAnnouncement` to the lobby, so A joins
            // it first (unified share model). The share + its announcement are a
            // UNIQUE throwaway and are withdrawn (UnpublishShare) at the end.
            a.cmd_tx
                .send(NetCommand::JoinRoom {
                    room: DEFAULT_ROOM.to_owned(),
                })
                .ok();
            wait_for_room_joined(&mut a.evt_rx).await;

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
            }
        }

        /// Guardrail 1: the roster keys by pubkey, never handle — two members with
        /// IDENTICAL display names produce two DISTINCT rows.
        #[test]
        fn identical_display_names_are_two_rows() {
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
            assert_eq!(t.reap(past_ttl).len(), 1, "the lone member ages out");
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
            let reaped_any = !t.reap(past_ttl).is_empty();
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
            let reaped_any = !t.reap(t0 + Duration::from_secs(1)).is_empty();
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
            assert_eq!(t.reap(past_ttl).len(), 1, "the circle member ages out");
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
