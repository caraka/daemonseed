//! The TUI screen state machine.
//!
//! [`App`] holds all interactive state and advances only through
//! [`App::on_key`]. It performs no terminal I/O, so it is fully unit-testable
//! and deterministically driveable by the PTY gate harness.

use daemonseed_core::backoff::CloseCause;
use daemonseed_core::first_start::SessionMaterials;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::passphrase::strength::{self, CircleStrength};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::share_catalog::ShareListing;
use daemonseed_core::storage::seeds::{SealingKey, Seeds};
use daemonseed_core::trust_events::{
    DismissalScope, TrustEvent, TrustEventClass, TrustEventKey, TrustEventLog, class_of,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use zeroize::Zeroizing;

use crate::net::{NetEvent, ShareManifestEntry};
use crate::screens::first_start::{FirstStartOutcome, FirstStartUi};

/// Live connection state shown in the main view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// No connection attempted yet.
    Disconnected,
    /// A connect is in flight (the net actor is working).
    Connecting,
    /// Reached Authenticated (ISC-47).
    Connected {
        server: String,
        version: String,
        rotation_notice: Option<String>,
    },
    /// The connect attempt failed; carries a human-readable cause.
    Failed(String),
}

/// A queued request for the binary to hand to the network actor. Returned by
/// [`App::take_pending_connect`] so `App` itself never touches the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub server_id: String,
    pub address: String,
    pub trusted: bool,
}

/// The top-level screen the TUI is currently showing.
///
/// Sub-screens (first-start steps, main-view tabs) are modelled by the later
/// M11 workstreams; this scaffold establishes the outer navigation skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// Landing screen shown on launch (no existing profile).
    Welcome,
    /// Daily-login passphrase unlock (ISC-C3 / Item E). Shown at startup when a
    /// profile blob already exists at the resolved profile root — the binary
    /// decrypts the blob and routes to [`Screen::Main`], never the enrollment
    /// wizard.
    Unlock,
    /// Cold first-start flow (passphrase → mnemonic → recovery → name →
    /// bootstrap). Expanded by the M11 first-start workstream.
    FirstStart,
    /// Post-first-start main view (chat / circles / shares / trust / servers).
    /// Expanded by the later M11 workstreams.
    Main,
    /// The logged-in "back" menu (Item E). Reached by Esc on [`Screen::Main`];
    /// offers disconnect/quit without ever dropping the user back into the
    /// enrollment wizard (ISC-A-C27). Esc here returns to Main.
    LoggedInMenu,
}

/// Which surface a stored chat line belongs to (ISC-C61 / ISC-A-C29).
///
/// Every [`ChatLine`] carries one of these, set at the point it enters the
/// transcript — `Lobby` for a public-room message (ISC-C56) and `Circle(id)` for
/// a circle message attributed to the single circle whose key opened it
/// (ISC-A-C30). The split chat view filters strictly on this tag: the lobby pane
/// renders only `Lobby` lines, the active-circle pane renders only its own
/// `Circle(id)` lines, so a line received on one surface can never bleed into
/// another pane (ISC-A-C29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The auto-joined default public room (ISC-C56). Always present, always
    /// rendered in the top lobby pane.
    Lobby,
    /// A specific joined circle, keyed by its stable per-session id (ISC-C59).
    Circle(u64),
}

/// One rendered chat line (ISC-10). `sent_unix_ms` is the sender's advisory
/// timestamp; a local echo of a just-sent message (which the relay never reflects
/// back to its sender) carries a real `now_unix_ms()` so it sorts as the newest line
/// under the #130 chronological ordered-insert. `surface` tags which pane the line
/// renders in (ISC-C61 / ISC-A-C29) — set at every push site and never changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLine {
    pub sender: String,
    pub body: String,
    pub sent_unix_ms: i64,
    /// The surface this line belongs to (ISC-C61). Drives the per-pane filter.
    pub surface: Surface,
}

/// Which input on the [`Screen::Main`] view has keyboard focus. `Tab` cycles
/// Chat → JoinCircle → Mute → Shares → DefineShare → Hide → Servers →
/// TrustHistory → PublicSpace → Deprecation → Fetched → Chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainFocus {
    /// The chat compose box (default): typing composes, Enter sends (ISC-14).
    Chat,
    /// The circle-join phrase box: typing builds the phrase, Enter joins
    /// (ISC-15/16).
    JoinCircle,
    /// The mute box: type a full `name#hash` handle, Enter toggles it in the
    /// client-local mute set (ISC-13 / C15). The set never leaves this client
    /// (ISC-A-C3).
    Mute,
    /// The Shares view (ISC-17 / ISC-20): two panes — local files indexed by
    /// the user's own [`daemonseed_core::indexer::Indexer`] (My shares), and
    /// the remote [`ShareListing`] snapshot fetched from the
    /// connected relay (Public shares). Up/Down navigates the public-shares
    /// rows, `r` requests a fresh snapshot, `f` (later) initiates a fetch
    /// (ISC-19). The indexer status line at the top of My-shares stays
    /// non-blocking during a cold scan (ISC-A-C7).
    Shares,
    /// The Define-Share input box (M14, ISC-C21): type a directory path
    /// (optionally `path|label`), Enter validates the directory exists and
    /// queues a [`ShareDefineRequest`] the binary turns into a
    /// `NetCommand::DefineShare` — opening the redb share index and activating
    /// the M8 indexer against that root. An input box modelled on
    /// [`MainFocus::JoinCircle`]; on success focus returns to the Shares view so
    /// the My-shares pane shows the new root indexing. Publishing the defined
    /// share to the relay is the Shares pane's `[p]` action (M15 cleanup —
    /// define once, then `[p]` to publish, `[u]` to unpublish); there is no
    /// separate Publish input pane.
    DefineShare,
    /// The Hide box: type a full `name#hash` handle, Enter toggles it in the
    /// client-local hidden-shares set (ISC-18 / C16). The set never leaves
    /// this client (ISC-A-C3) — there is no wire field carrying it — and is
    /// applied as a render-time filter to the Public shares pane. Main area
    /// stays on the Shares view.
    Hide,
    /// The server-management screen (F22): add servers, set per-server trust
    /// mode with the trusted/untrusted slider (C22), and connect to a selected
    /// one (ISC-21/26/27). The main area shows the server list instead of chat,
    /// plus a read-only "Discovered (introducer)" sub-section listing candidate
    /// peers the connected relay's introducer reported (M12 gate step 6, ISC-S6 /
    /// ISC-A-C19). Opening the pane auto-dispatches a `RefreshIntroducer`;
    /// candidates are surfaced but never auto-trusted — promotion stays explicit.
    Servers,
    /// The Trust History view (ISC-C28 LogOnly surface, ISC-25): a scrollable
    /// list of every recorded trust event. Up/Down select, Enter dismisses the
    /// selected event's affordance per `(key, scope)` (ISC-A-C12 — no global
    /// dismissal). The main area shows the history instead of chat.
    TrustHistory,
    /// The Public Space view (ISC-25 / ISC-S7 / ISC-A-S3): the connected relay's
    /// MOTD (rendered inert) plus its announcement posts, each carrying a
    /// client-side whitelist-verification verdict. Up/Down navigate the posts,
    /// `r` requests a fresh snapshot. A read-only surface over already-shipped
    /// server APIs (no new wire protocol). The main area shows the public space
    /// instead of chat.
    PublicSpace,
    /// The Deprecation view (ISC-C25 / ISC-A-S11 / ISC-C28): the connected
    /// relay's signed suite-deprecation policy, fetched, ML-DSA-verified against
    /// the pinned server key, anti-rollback-checked, and surfaced as
    /// persistent non-blocking warning rows for any in-use suite the operator
    /// has scheduled for retirement. Up/Down navigate the warning rows, `r`
    /// requests a fresh fetch. A read-only surface over the already-shipped
    /// `PublicSpace.GetDeprecationPolicy` RPC (no new wire protocol). The main
    /// area shows the deprecation policy instead of chat.
    Deprecation,
    /// The Fetched-downloads browse pane (M15 C; ISC-C64 / C65). Lists the
    /// shares fetched this profile (persisted on disk as explicit downloads,
    /// ISC-C63); ↑/↓ selects a download, typing builds a destination directory
    /// path, Enter extracts the selected download's files there (path-traversal
    /// safe, ISC-A-C32). Opening the pane requests a fresh list (`ListFetched`).
    Fetched,
}

/// (#92) Public-space composer sub-mode, active only for a whitelisted signer
/// (`can_compose`). `None` is the read-only display state (Up/Down navigate posts,
/// `r` refreshes, `m`/`a` open a composer). The other variants capture keystrokes
/// into the matching buffer; `Esc` cancels back to `None`. Non-signers never leave
/// `None` (the open keys are ignored), keeping the pane read-only (D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicComposeMode {
    /// Read-only display (no composer open).
    None,
    /// Typing the single-line MOTD (ISC-S9); Enter signs+uploads via `UploadMotd`.
    Motd,
    /// Typing the announcement topic; Enter advances to [`PublicComposeMode::Body`].
    Topic,
    /// Typing the announcement body; Enter signs+uploads via `UploadPost`.
    Body,
}

/// One indexed file in the user's own share, as rendered in the My-shares
/// pane (ISC-17 / ISC-C21). A render-only projection of
/// [`daemonseed_core::storage::share_index::ShareEntry`] kept local to the
/// TUI so [`App`] does not depend on the redb-backed concrete type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalShareRow {
    /// Path relative to the share root.
    pub rel_path: String,
    /// File size in bytes.
    pub size: u64,
    /// Last-modified time, milliseconds since the Unix epoch.
    pub mtime_unix_ms: u64,
}

/// One announcement post in the public-space view (ISC-S7), as a render-only
/// projection kept local to the TUI so [`App`] does not depend on the wire
/// `Post` type. `verified` is the client-side provenance verdict: the net actor
/// re-ran `verify_served_post` against the relay's published signer whitelist
/// (ISC-A-S3). A `false` verdict means the post failed signature /
/// content-address verification and the render layer flags it rather than
/// presenting it as authentic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPostRow {
    /// The post's topic (operator-defined channel).
    pub topic: String,
    /// The post body, as inert text.
    pub body: String,
    /// Whether the post passed client-side whitelist verification (ISC-A-S3).
    pub verified: bool,
    /// Signer's wall-clock at signing, unix ms (advisory ordering, ISC-S7).
    pub sent_unix_ms: i64,
}

/// One affected-suite warning in the deprecation view (ISC-C25), a render-only
/// projection kept local to the TUI so [`App`] does not depend on core's
/// `DeprecationEntry`. Built by the net actor from
/// [`daemonseed_core::trust_events::assess_deprecation`] for each in-use suite
/// the verified policy schedules for retirement. `past_cutoff` distinguishes a
/// blocking cutoff-hit (the suite is already refused) from a still-advisory
/// pending deprecation, so the render layer can flag it accordingly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationWarningRow {
    /// The in-use suite the operator has scheduled for retirement.
    pub suite_id: u16,
    /// UTC wall-clock milliseconds at/after which the suite is refused.
    pub cutoff_unix_ms: i64,
    /// Operator-recommended successor suite to migrate to.
    pub recommended_suite_id: u16,
    /// Whether the suite is already at/past its cutoff (blocking) versus a
    /// still-advisory pending deprecation.
    pub past_cutoff: bool,
}

/// Indexer state as seen by the TUI (ISC-20 / ISC-A-C7). The line at the top
/// of the My-shares pane reflects whichever state the net actor last emitted;
/// transitions never gate user input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexerStatus {
    /// No share root configured, or the indexer has not started yet.
    Idle,
    /// A cold or incremental scan is in flight. `seen` is the running file
    /// count; `total` is `None` while the walk has not finished — the cold
    /// scan does not know the total ahead of time, by design (single-pass).
    Indexing { seen: u64, total: Option<u64> },
    /// The indexer is up-to-date with the last scan; `entries` is the size
    /// of the persisted index (ISC-C21 cross-launch persistence).
    Ready { entries: u64 },
}

/// A user request to define (add) a local share root (M14, ISC-C21).
///
/// Produced by `App::on_key_define_share` when the user enters a valid
/// directory path in the Define-Share box, drained by the binary via
/// [`App::take_pending_share_define`]. The binary derives the redb index-file
/// path and the share-index key (the [`daemonseed_core::storage::seeds::IndexKey`]
/// from the active session) and turns this into a `NetCommand::DefineShare` — the
/// App layer deliberately holds no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareDefineRequest {
    /// The directory the user chose to share. Validated to exist at capture
    /// time; the indexer walks it on the net task.
    pub root: std::path::PathBuf,
    /// Optional human label for the share root; `None` falls back to the path.
    pub label: Option<String>,
}

/// A queued publish request the binary turns into a `NetCommand::PublishShare`
/// (D, M15). Like [`ShareDefineRequest`] the App holds no key material — publish
/// + serve run entirely on the net task off the directory `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequest {
    /// The directory to publish + serve. Validated to exist at capture time.
    pub root: std::path::PathBuf,
    /// The share's advertised display name (defaults to the directory name).
    pub name: String,
    /// The publisher's own display handle (name#hash), advertised in the
    /// listing so peers see who shared it instead of "(operator)".
    pub sharer_handle: String,
}

/// A share currently published + served this session (M16 smoke fix,
/// ISC-A-C34). Keyed by the client-local defined `root` so `[p]` can be
/// idempotent and the Shares pane's `●` marker binds to the exact defined row
/// — display-name string joins conflate distinct shares that happen to share
/// a name. `share_id` is the relay-minted listing id (the unpublish handle);
/// `name` is the advertised display name. `root` is client-local only and
/// never rides the wire.
#[derive(Debug, Clone)]
pub struct PublishedShare {
    /// Server-assigned opaque listing id (F25); the `[u]` unpublish handle.
    pub share_id: String,
    /// The defined share root this listing serves — the idempotency key.
    pub root: std::path::PathBuf,
    /// The advertised display name (defaults to the directory name).
    pub name: String,
}

/// One node in the fetch preview's collapsible folder tree (ISC-C72). The tree
/// is a *view* over the flat manifest — selection still lives per-file in
/// [`FetchUi::preview_checked`]; a node merely names a row and (for a `Dir`)
/// the contiguous span of descendants it controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewNode {
    /// Nesting depth (0 = top level). Drives the render indent.
    pub depth: usize,
    /// The path segment displayed on this row (the last `/`-component).
    pub name: String,
    /// Whether this node is a directory or a file.
    pub kind: PreviewKind,
}

/// The two node flavours in the preview tree (ISC-C72).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewKind {
    /// A directory. `subtree_end` is the exclusive end of this dir's
    /// pre-order-contiguous descendant span: `nodes[i+1..subtree_end]` are all
    /// of node `i`'s descendants. Lets a collapsed dir skip its descendants and
    /// a folder-select aggregate every file beneath it.
    Dir { subtree_end: usize },
    /// A file. `manifest_idx` indexes the flat manifest (and
    /// [`FetchUi::preview_checked`]); `size` is the per-file byte count.
    File { manifest_idx: usize, size: u64 },
}

/// Aggregate selection state of a directory's files (ISC-C72), for the dir
/// row's checkbox glyph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirSelection {
    /// Every file under the dir is selected.
    All,
    /// No file under the dir is selected.
    None,
    /// Some but not all files under the dir are selected.
    Partial,
}

/// Active share-fetch state (ISC-19, F23 unified mechanism).
///
/// Constructed when the user presses `f` on a selected Public-shares row;
/// folded by [`App::on_net_event`] as `NetEvent::FetchProgress` /
/// `FetchComplete` / `FetchError` arrive. Surfaced as a centered overlay by
/// [`crate::ui`]; key handling routes through [`App::on_key`] while the
/// overlay is up (Esc cancels; Enter on a completed/failed overlay
/// dismisses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchUi {
    /// The share being fetched (from `PublicShareListing.share_id`).
    pub share_id: String,
    /// The sharer's wire handle, for user-facing display.
    pub sharer_handle: String,
    /// The sharer-advertised listing name, recorded as the download label on
    /// the confirmed fetch (carried into `NetCommand::ConfirmFetch`).
    pub name: String,
    /// Phase of the fetch.
    pub status: FetchStatus,
    /// Total chunks over the SELECTED set (M16, ISC-C73 / ISC-A-C35 —
    /// chunk-granular, NOT a file count: every selected file contributes its
    /// `chunk_count`). `Some` from confirm on (seeded from the preview's
    /// per-entry chunk counts, then confirmed by the net actor's first
    /// `FetchProgress`); `None` while the fetcher is waiting on the manifest.
    pub total_chunks: Option<u32>,
    /// Chunks verified and streamed to disk so far (drives the gauge).
    pub chunks_received: u32,
    /// Bytes verified and streamed to disk so far (advisory progress).
    pub bytes_received: u64,
    /// A2 selective fetch: per-manifest-entry selection, parallel to the
    /// `Preview(entries)` list. Defaulted all-`true` when the manifest arrives
    /// (Enter-without-toggling downloads everything = the A1 behavior). Only
    /// meaningful while `status` is `Preview`.
    pub preview_checked: Vec<bool>,
    /// A2/ISC-C72: the highlighted row in the preview tree (`↑`/`↓`); index
    /// into the **currently-visible rows** (see [`FetchUi::visible_rows`]), NOT
    /// the flat manifest. Only meaningful in `Preview`.
    pub preview_cursor: usize,
    /// ISC-C72: the collapsible folder tree, a pre-order node list built once
    /// from the flat manifest when it arrives (see
    /// [`FetchUi::build_preview_tree`]). Empty until the manifest lands and for
    /// an empty share. Selection still lives in `preview_checked`.
    pub preview_tree: Vec<PreviewNode>,
    /// ISC-C72: collapse state parallel to `preview_tree` (`true` = collapsed).
    /// Every `Dir` defaults collapsed so a dense share opens to a short
    /// top-level list; `File` entries are always `false` (ignored).
    pub preview_collapsed: Vec<bool>,
    /// ISC-C72: the first visible row drawn — the render adjusts it each frame
    /// so the cursor row stays within `[scroll, scroll + pane_rows)`. Index into
    /// the currently-visible rows.
    pub preview_scroll: usize,
    /// A3 (ISC-C68): the user-chosen download destination. **Empty means "use
    /// the default downloads dir"** — the binary resolves the empty case to
    /// `main::os_downloads_dir` (or `<profile>/downloads` under `--portable`),
    /// so the App layer never threads the resolved path through `App::new`. A
    /// non-empty value is taken verbatim as the fetch's `fetched_root`. Edited
    /// in `Preview` via the `d` key; carried into `NetCommand::ConfirmFetch`.
    pub dest: String,
    /// A3: whether the destination field is being edited (entered with `d` in
    /// `Preview`). While `true`, `Char`/`Backspace` edit `dest` and the A2 nav
    /// keys + download-`Enter` are suppressed so typing a path cannot toggle a
    /// file's checkbox or start the download. `Enter`/`Esc` exit edit mode back
    /// to the preview without downloading. Only meaningful in `Preview`.
    pub editing_dest: bool,
}

impl FetchUi {
    /// ISC-C72: build the pre-order folder tree from the flat manifest.
    ///
    /// Each `rel_path` is split on `/`; intermediate segments become `Dir`
    /// nodes (deduped per parent), the final segment a `File` carrying its index
    /// into the *received* manifest order (so `preview_checked` /
    /// `ConfirmFetch.selected` indices stay valid). Entries are visited in
    /// `rel_path`-sorted order so siblings group and the tree is stable, but the
    /// stored `manifest_idx` is the original received index. Each `Dir`'s
    /// `subtree_end` is back-patched to the exclusive end of its descendant
    /// span. A flat share (no `/`) yields all-`File` nodes at depth 0 — exactly
    /// the pre-C72 list.
    pub fn build_preview_tree(entries: &[ShareManifestEntry]) -> Vec<PreviewNode> {
        // Sort by path for stable grouping; keep the received index alongside.
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by(|&a, &b| entries[a].rel_path.cmp(&entries[b].rel_path));

        let mut nodes: Vec<PreviewNode> = Vec::new();
        // The Dir node index for each currently-open path prefix, depth-indexed:
        // `open[d]` is `(segment, node_idx)` of the dir open at depth `d`.
        let mut open: Vec<(String, usize)> = Vec::new();

        for &idx in &order {
            let path = &entries[idx].rel_path;
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segments.is_empty() {
                continue;
            }
            let dir_count = segments.len() - 1;

            // Truncate the open-dir stack back to the longest shared prefix with
            // this path's directory segments.
            let mut shared = 0usize;
            while shared < open.len() && shared < dir_count && open[shared].0 == segments[shared] {
                shared += 1;
            }
            open.truncate(shared);

            // Open any new directory segments.
            for seg in segments.iter().take(dir_count).skip(shared) {
                let depth = open.len();
                let node_idx = nodes.len();
                nodes.push(PreviewNode {
                    depth,
                    name: (*seg).to_owned(),
                    // subtree_end back-patched once the subtree is complete.
                    kind: PreviewKind::Dir {
                        subtree_end: node_idx + 1,
                    },
                });
                open.push(((*seg).to_owned(), node_idx));
            }

            // The file leaf.
            let depth = open.len();
            nodes.push(PreviewNode {
                depth,
                name: segments[dir_count].to_owned(),
                kind: PreviewKind::File {
                    manifest_idx: idx,
                    size: entries[idx].size,
                },
            });
        }

        // Back-patch every Dir's subtree_end: it spans all later nodes whose
        // depth is greater than the dir's (pre-order makes that span
        // contiguous).
        for i in 0..nodes.len() {
            if let PreviewKind::Dir { .. } = nodes[i].kind {
                let dir_depth = nodes[i].depth;
                let mut end = i + 1;
                while end < nodes.len() && nodes[end].depth > dir_depth {
                    end += 1;
                }
                if let PreviewKind::Dir { subtree_end } = &mut nodes[i].kind {
                    *subtree_end = end;
                }
            }
        }
        nodes
    }

    /// ISC-C72: the tree-node indices currently visible, in draw order — walk
    /// the pre-order tree skipping the descendants of any collapsed `Dir`. The
    /// `preview_cursor` and `preview_scroll` index INTO this list.
    pub fn visible_rows(&self) -> Vec<usize> {
        let mut rows = Vec::new();
        let mut i = 0usize;
        while i < self.preview_tree.len() {
            rows.push(i);
            match self.preview_tree[i].kind {
                PreviewKind::Dir { subtree_end }
                    if self.preview_collapsed.get(i).copied().unwrap_or(false) =>
                {
                    // Collapsed: jump past the whole subtree.
                    i = subtree_end;
                }
                _ => i += 1,
            }
        }
        rows
    }

    /// ISC-C72: aggregate selection state of a `Dir` node's files (the files in
    /// `tree[node_idx+1..subtree_end]`), for the dir-row checkbox glyph.
    pub fn dir_selection(&self, node_idx: usize) -> DirSelection {
        let PreviewKind::Dir { subtree_end } = self.preview_tree[node_idx].kind else {
            return DirSelection::None;
        };
        let (mut any, mut all, mut saw_file) = (false, true, false);
        for n in &self.preview_tree[node_idx + 1..subtree_end] {
            if let PreviewKind::File { manifest_idx, .. } = n.kind {
                saw_file = true;
                if self
                    .preview_checked
                    .get(manifest_idx)
                    .copied()
                    .unwrap_or(false)
                {
                    any = true;
                } else {
                    all = false;
                }
            }
        }
        if !saw_file {
            DirSelection::None
        } else if all {
            DirSelection::All
        } else if any {
            DirSelection::Partial
        } else {
            DirSelection::None
        }
    }
}

/// A queued fetch-confirm the binary drains into `NetCommand::ConfirmFetch`:
/// `(share_id, sharer_handle, name, selected, dest)`. `selected` is `None` for
/// confirm-all (A1) / the chosen manifest-row indices (A2); `dest` (A3, ISC-C68)
/// is the user-chosen download destination, empty for the default downloads dir.
type PendingFetchConfirm = (String, String, String, Option<Vec<usize>>, String);

/// Phase of an active [`FetchUi`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchStatus {
    /// `ManifestRequest` is out; the fetcher is waiting on the manifest.
    RequestingManifest,
    /// A1: the manifest arrived and is shown for review (file names + sizes)
    /// before any chunk is downloaded. `Enter` confirms (queues the download),
    /// `Esc` cancels. Nothing has been written; no stream is held open.
    Preview(Vec<ShareManifestEntry>),
    /// The manifest has arrived; chunks are flowing.
    Receiving,
    /// All chunks verified and written; user dismisses on Enter.
    Complete,
    /// Aborted (Esc) or failed (`message` carries the cause).
    Failed(String),
}

/// A surfaced trust event awaiting user attention (ISC-C28). The `key` selects
/// the affordance class via [`class_of`]; `server_id` scopes dismissal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustItem {
    pub key: TrustEventKey,
    pub server_id: Option<String>,
}

/// One managed federation server in the server-management screen (F22 / C22).
/// `trusted` is the slider position: trusted = TOFU-pin on first contact,
/// untrusted = require a pre-imported operator key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedServer {
    pub server_id: String,
    pub address: String,
    pub trusted: bool,
}

/// State of the most-recent circle-join attempt, shown on the status bar.
///
/// With multiple simultaneous circles (ISC-C59) the durable membership lives in
/// [`App::circles`]; this enum tracks only the *latest* join attempt so the
/// status bar can show "joining…" / a failure cause. A successful join leaves it
/// `Joined`; the actual joined set is the membership list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircleStatus {
    /// No circle joined yet (membership set empty).
    NotJoined,
    /// A join is in flight (the net actor is subscribing).
    Joining,
    /// The most recent join succeeded; chat can flow (ISC-16).
    Joined,
    /// The most recent join failed; carries a human-readable cause.
    Failed(String),
}

/// One circle in the client's session-scoped membership set (ISC-C59 / ISC-C62).
///
/// The struct is intentionally serialization-shaped: id + client-local label are
/// exactly what a later additive persistence into the at-rest [`Seeds`] blob
/// would store, so adding circle-membership persistence (ISC-C59) is an additive
/// change, not a refactor. It is NOT persisted now — the set is rebuilt each
/// session (circle entropy is re-entered, ISC-A-C2).
///
/// [`Seeds`]: daemonseed_core::storage::seeds::Seeds
/// `entropy` is secret material — it is the `cot_key` IKM (ISC-C8) — so it is
/// **private** and held in a [`Zeroizing`] `String`, exactly as its at-rest
/// counterpart [`PersistedCircle`] is. The wipe is carried by the field type, so
/// it happens on every path out of every scope the value reaches including an
/// unwind, and no caller can lift the raw phrase into a container with no `Drop`
/// of its own. Read it through [`Self::entropy`], build one with [`Self::new`].
/// `Debug` is hand-written so the phrase never reaches a log surface (ISC-A-C1).
/// `PartialEq` / `Eq` are not implemented: nothing compares whole
/// `JoinedCircle`s, and deriving equality onto a secret-bearing type invites
/// copies of the secret into comparison sites for no benefit.
///
/// #259 made all of this true of the core and the GUI and named only those two
/// sites, so this one kept the defect it fixed: the session-long copy of the
/// phrase sat here in a bare `String` with no wipe and a derived `Debug` that
/// would print it (#268).
///
/// [`PersistedCircle`]: daemonseed_core::storage::seeds::PersistedCircle
#[derive(Clone)]
pub struct JoinedCircle {
    /// Stable per-session id assigned by the net actor at join. Keys the
    /// active-surface selection, the [`Surface::Circle`] tag on inbound lines,
    /// and the `SendChat` seal target (ISC-A-C30).
    pub id: u64,
    /// Client-local display label (ISC-C62), shown in the carousel and compose
    /// indicator. Never transmitted, never derived from members.
    pub label: String,
    /// The phrase this circle's `cot_key` derives from — the in-memory session
    /// copy of the persisted seed (M13, ISC-C59). The at-rest form is
    /// [`daemonseed_core::storage::seeds::PersistedCircle`]; this lets the
    /// `CircleJoined` handler map a runtime circle back to its persisted entry.
    entropy: Zeroizing<String>,
}

impl core::fmt::Debug for JoinedCircle {
    /// Hand-written, never derived: `entropy` is the `cot_key` IKM (ISC-C8) and
    /// [`Zeroizing`]'s own `Debug` forwards to the value it wraps, so a derived
    /// one would print the circle secret verbatim. The id and the client-local
    /// label are what a reader actually wants (#268).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinedCircle")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("entropy", &"<redacted>")
            .finish()
    }
}

impl JoinedCircle {
    /// Remember a circle for this session. `entropy` MUST already be canonicalized
    /// (ISC-C9) — this only stores what the join path normalized.
    pub fn new(id: u64, label: impl Into<String>, entropy: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            entropy: Zeroizing::new(entropy.into()),
        }
    }

    /// Borrow the canonicalized circle phrase — the `cot_key` IKM (ISC-C8). A
    /// borrow, never a copy: an owned `String` taken from here has escaped the
    /// zeroizing wrapper and will release its buffer with the phrase still in it.
    pub fn entropy(&self) -> &str {
        &self.entropy
    }

    /// The relay-independent `#<hash-of-entropy>` fingerprint (ISC-C62), a pure
    /// function of this circle's entropy.
    ///
    /// **Coded but unsurfaced in the TUI** (caraka, 2026-06-05): while terminal
    /// space is limited, the human-readable adj-noun [`Self::label`] carries
    /// cross-daemon same-circle verification. This precise check is reserved for
    /// the GUI era — where the user names the circle and the fingerprint backs
    /// verification — so the renderer never shows it today; it is exposed here so
    /// that surface can light it up without a core change.
    pub fn fingerprint(&self) -> String {
        daemonseed_core::circle::key::circle_fingerprint(&self.entropy)
    }
}

/// A queued chat send for the binary to forward to the network actor. `body` is
/// the typed text; `sender_handle` is the user's own display handle, sealed into
/// the message for the recipient's client-side mention/mute (never seen by the
/// relay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatSend {
    /// The active circle to seal under (ISC-C60 / ISC-A-C30). The net actor looks
    /// this id up in its membership set and seals under exactly that key.
    pub circle_id: u64,
    pub body: String,
    pub sender_handle: String,
}

/// Which surface a Chat-pane post will land on, resolved by a fixed precedence.
///
/// A joined circle (the private opt-in, ISC-14) wins over a joined public room
/// (the default surface, ISC-S22 / ISC-C56). [`App::active_chat_surface`] is the
/// single source of truth for this precedence: both the Enter handler
/// (`App::on_key_chat`) and the compose-box indicator
/// (`crate::ui::render_main_input`) resolve the target through it, so the
/// indicator can never claim a different surface than the one a post lands on.
/// That divergence — the handler posting to the auto-joined lobby while the user
/// believed they were posting to their joined circle — was the v0.15.1
/// chat-surface bug (the handler checked `public_room` first, contradicting its
/// own doc comment). Routing both through one resolver makes the bug
/// unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatSurface {
    /// The private opt-in surface — the *active* joined circle (ISC-14 / ISC-C60).
    /// Carries the circle's id (the `SendChat` seal target, ISC-A-C30) and its
    /// client-local label (the compose-indicator name, ISC-C62). Takes precedence
    /// over the lobby when a circle is active.
    Circle { id: u64, label: String },
    /// The default surface — the auto-joined public room (lobby), carrying its
    /// name (ISC-S22 / ISC-C56). The active surface when no circle is selected.
    PublicRoom(String),
}

/// Interactive application state.
///
/// Construct with [`App::new`], feed key events with [`App::on_key`], render
/// from [`crate::ui`]. The event loop stops when [`App::should_quit`] is true.
pub struct App {
    screen: Screen,
    should_quit: bool,
    /// Argon2 params used when the user starts first-start. Production uses
    /// [`ArgonParams::desktop_default`]; tests inject fast params.
    argon: ArgonParams,
    /// Active first-start flow, present while on [`Screen::FirstStart`].
    first_start: Option<FirstStartUi>,
    /// Materials produced by a completed first-start, awaiting the connect path.
    session: Option<SessionMaterials>,
    /// Live connection state shown on the main view.
    connection: ConnectionStatus,
    /// A connect the binary should hand to the network actor (drained once).
    pending_connect: Option<ConnectRequest>,
    /// Which main-view input has focus (Tab toggles).
    main_focus: MainFocus,
    /// The chat compose buffer (ISC-14).
    compose: String,
    /// The circle-join phrase buffer (ISC-15).
    circle_phrase: String,
    /// The Define-Share input buffer (M14). Typing in [`MainFocus::DefineShare`]
    /// builds it; Enter parses `path` (optional `path|label`) into a
    /// [`ShareDefineRequest`]. Kept on validation failure so the user can fix a
    /// typo'd path in place (mirrors `circle_phrase`).
    share_input: String,
    /// Received + locally-echoed chat lines, oldest first (ISC-10). Each line
    /// carries a [`Surface`] tag; the split view filters strictly on it
    /// (ISC-C61 / ISC-A-C29).
    messages: Vec<ChatLine>,
    /// Status of the most-recent circle-join attempt, for the status bar.
    circle_status: CircleStatus,
    /// The session-scoped circle membership set (ISC-C59). Joining ADDS to it;
    /// it is never evicted by another join. Order is join order; the carousel
    /// cycles through it with ←/→. Serialization-shaped (see [`JoinedCircle`])
    /// but session-only — not persisted.
    circles: Vec<JoinedCircle>,
    /// Index into [`Self::circles`] of the active circle, or `None` when no
    /// circle is selected (the lobby is then the active surface). Bounded to a
    /// valid index whenever `circles` is non-empty; cleared to `None` only when
    /// the set is empty (ISC-C60).
    active_circle: Option<usize>,
    /// The auto-joined default public room (ISC-S22 / ISC-C56), if subscribed.
    /// The default chat surface is this room — no circle required. `None` until
    /// the net actor reports a successful join after connect.
    public_room: Option<String>,
    /// A transient status/error line (e.g. a failed send).
    status: Option<String>,
    /// The mute-box input buffer (ISC-13).
    mute_input: String,
    /// Client-local muted full wire handles (ISC-13 / C15). Never leaves the
    /// client (ISC-A-C3); applied as a render-time suppression filter.
    muted: std::collections::BTreeSet<String>,
    /// Managed federation servers shown on the server-management screen (F22).
    servers: Vec<ManagedServer>,
    /// The add-server input buffer (`server-id@host:port`) (ISC-26).
    server_input: String,
    /// Index of the selected server in [`Self::servers`] (Up/Down moves it).
    server_sel: usize,
    /// A circle-join the binary should forward to the net actor (drained once).
    /// The single-shot slot for an interactive join; [`Self::take_pending_join`]
    /// drains it first, then [`Self::pending_joins`].
    pending_join: Option<String>,
    /// Single-shot slot for an interactive Define-Share request (M14); the
    /// binary drains it via [`Self::take_pending_share_define`], derives the
    /// index path + key from the session, and sends `NetCommand::DefineShare`.
    pending_share_define: Option<ShareDefineRequest>,
    /// Queued share re-definitions to replay on Unlock (M14, ISC-C21): one per
    /// persisted share root, drained after the single-shot slot so a returning
    /// daemon re-indexes its remembered roots without re-typing. FIFO preserves
    /// definition order. Mirrors [`Self::pending_joins`] for circles.
    pending_share_defines: std::collections::VecDeque<ShareDefineRequest>,
    /// The defined share roots + their display names (M16 C1, ISC-C69). One
    /// entry per share the user has defined this session (interactively or
    /// restored on Unlock, in full); appended on define (dedup by root) and
    /// restored entirely across Unlock. The Shares pane lists these with a
    /// selection cursor ([`Self::defined_sel`]); `[p]` publishes the selected
    /// root, `[u]` unpublishes the selected one if it is currently served.
    /// Empty until a share is defined. Each published root is served by its own
    /// session-scoped serve task on the net actor (the redb browse-index stays
    /// single-active per the M14 deferral — only the latest-defined root is
    /// reflected in the "my shares" indexed file-count view).
    defined_shares: Vec<(std::path::PathBuf, String)>,
    /// Selection cursor into [`Self::defined_shares`] for the Shares pane's
    /// My-defined list (M16 C1). `↑`/`↓` move it (clamped); `[p]`/`[u]` act on
    /// the selected entry. Clamped on restore/append so it never dangles.
    defined_sel: usize,
    /// Single-shot slot for a publish request (M15); the binary drains it via
    /// [`Self::take_pending_publish`] into `NetCommand::PublishShare`.
    pending_publish: Option<PublishRequest>,
    /// Queue of `(root, name)` auto-republishes restored from the at-rest blob
    /// on Unlock (publish-intent persistence): each remembered-published root is
    /// re-asserted once reconnected. Drained via [`Self::take_pending_autopublish`]
    /// (gated on a live connection — publish needs a session).
    pending_publishes: std::collections::VecDeque<(std::path::PathBuf, String)>,
    /// Single-shot slot for an unpublish (D, M15): the server-assigned share_id
    /// to stop serving; drained into `NetCommand::UnpublishShare`.
    pending_unpublish: Option<String>,
    /// Single-shot slot for a publish-hash cancel (M16 serve-from-disk): the
    /// defined root whose in-flight hash `[u]` asked to stop; drained into
    /// `NetCommand::CancelPublish`. Root-keyed like [`Self::hashing`]
    /// (ISC-A-C34 — never a display-name join).
    pending_cancel_publish: Option<std::path::PathBuf>,
    /// Defined roots whose publish hash is currently in flight (M16
    /// serve-from-disk). Inserted on `PublishProgress`; removed on
    /// `PublishStarted` / `PublishCancelled` / a root-carrying `PublishError`.
    /// Drives the `[u]`-cancels affordance and extends the `[p]` idempotency
    /// guard (ISC-A-C34) to the hashing window — without it a second `[p]`
    /// mid-hash would queue a duplicate publish.
    hashing: std::collections::BTreeSet<std::path::PathBuf>,
    /// Shares currently published+served this session, keyed by defined root
    /// ([`PublishedShare`], M16 ISC-A-C34). Appended on `PublishStarted`,
    /// pruned on `PublishStopped`; drives the `[p]` idempotency guard and the
    /// Shares-pane `[u]` unpublish affordance. Serving is session-scoped — the
    /// relay reaps these when the connection drops.
    published: Vec<PublishedShare>,
    /// Queued circle-rejoins to forward to the net actor, one per launch-time
    /// remembered circle (M13 persistence, ISC-C59). Filled on Unlock from
    /// `seeds.circles()` and drained one-per-tick by the same binary loop that
    /// drains [`Self::pending_join`]; FIFO preserves join order. Distinct slot so
    /// existing single-join callers/tests are unaffected.
    pending_joins: std::collections::VecDeque<String>,
    /// A chat send the binary should forward to the net actor (drained once).
    pending_chat: Option<ChatSend>,
    /// A public-room post the binary should forward to the net actor (drained
    /// once). The post is self-signed for provenance by the net actor under the
    /// daemon's own identity (ISC-S24), so only the body is queued here.
    pending_public_room: Option<(String, String)>,
    /// The bounded, per-session trust-event audit log (ISC-C28). Every recorded
    /// event surfaces in the Trust History view; Transient events are dropped by
    /// [`TrustEventLog::append`] (the ISC-A-C12 asymmetry).
    trust_log: TrustEventLog,
    /// The active Blocking trust event, shown as a modal that captures input
    /// until acknowledged (ISC-22 / C28 Blocking class).
    blocking: Option<TrustItem>,
    /// Undismissed PersistentNonBlocking trust events, shown as status-bar badges
    /// (ISC-23 / C28 Persistent class).
    persistent: Vec<TrustItem>,
    /// The most recent Transient trust event, shown as a toast until the next key
    /// press (ISC-24 / C28 Transient class).
    transient: Option<TrustItem>,
    /// The last observed connection close layer (ISC-28 / C26), for the distinct
    /// close-cause status rendering.
    close_cause: Option<CloseCause>,
    /// Selected row in the Trust History view (Up/Down moves it).
    history_sel: usize,
    /// Latest My-shares snapshot from the net actor (ISC-17).
    local_shares: Vec<LocalShareRow>,
    /// Latest Public-shares snapshot from the net actor (ISC-17 / ISC-18).
    /// Pre-filter; the hide set is applied at render time (ISC-A-C3 keeps the
    /// hide set off the wire — there is nothing for the relay to know).
    public_shares: Vec<ShareListing>,
    /// Current indexer status, surfaced non-blocking at the top of the
    /// My-shares pane (ISC-20 / ISC-A-C7).
    indexer_status: IndexerStatus,
    /// Client-local hidden-share full wire handles (ISC-18 / C16). Applied as
    /// a render-time filter on [`Self::public_shares`] via
    /// [`daemonseed_cli::public_space::filter_shares_excluding_hidden`]. Never
    /// leaves the client (ISC-A-C3): no wire field carries it. This set is the UI
    /// source of truth; it is kept in lock-step with the persisted home
    /// [`daemonseed_core::storage::seeds::Seeds::hidden_shares`] (M13
    /// write-through) — every toggle mirrors onto [`Self::seeds`] and re-seals, and
    /// it is restored from there on Unlock (ISC-C16).
    hidden_shares: std::collections::BTreeSet<String>,
    /// The hide-box input buffer (ISC-18).
    hide_input: String,
    /// Selected row index in the Public-shares pane (Up/Down moves it). Will
    /// be the fetch target once ISC-19 lands.
    share_sel: usize,
    /// A queued shares-refresh the binary should forward to the net actor
    /// (drained once). `true` means "the user pressed R" or "the screen just
    /// opened"; the binary translates this into a `NetCommand::RefreshShares`.
    pending_share_refresh: bool,
    /// An active share-fetch (ISC-19), if any. While `Some`, the centered
    /// fetch overlay is up and captures input until the user dismisses it.
    fetch: Option<FetchUi>,
    /// A queued share-fetch request the binary should forward to the net
    /// actor (drained once). The `(share_id, sharer_handle, name)` triple
    /// identifies the share and carries the listing name for the fetched
    /// manifest; the binary translates this into a `NetCommand::FetchShare`.
    pending_share_fetch: Option<(String, String, String)>,
    /// A queued fetch-confirm the binary forwards as `NetCommand::ConfirmFetch`
    /// (drained once). `(share_id, sharer_handle, name, selected, dest)` —
    /// `selected` is `None` for the A1 confirm-all path or the A2 chosen
    /// manifest-row indices; `dest` (A3, ISC-C68) is the user-chosen download
    /// destination, empty for the default downloads dir.
    pending_fetch_confirm: Option<PendingFetchConfirm>,
    /// Fetched-downloads list for the browse pane (M15 C; ISC-C64). Replaced
    /// wholesale by `NetEvent::FetchedShares`.
    fetched_shares: Vec<daemonseed_core::storage::fetched::FetchedShare>,
    /// Selected row in the Fetched pane (↑/↓ moves it).
    fetched_sel: usize,
    /// A queued fetched-list refresh the binary forwards as `ListFetched`
    /// (drained once). Set when the Fetched pane opens and after a fetch lands.
    pending_fetched_refresh: bool,
    /// The connected relay's rendered (inert) MOTD (ISC-25), `None` when the
    /// relay publishes none.
    public_motd: Option<String>,
    /// Latest announcement-posts snapshot from the net actor (ISC-S7), each row
    /// carrying its client-side whitelist-verification verdict (ISC-A-S3).
    public_posts: Vec<PublicPostRow>,
    /// Selected row index in the announcements pane (Up/Down moves it).
    post_sel: usize,
    /// A queued public-space refresh the binary should forward to the net actor
    /// (drained once). Set when the user opens the Public Space pane or presses
    /// `r`; the binary translates it into a `NetCommand::RefreshPublicSpace`.
    pending_public_space_refresh: bool,
    /// (#92) Signer self-determination verdict from the latest `PublicSpaceSnapshot`
    /// (`composer_visible`): `true` iff the held stable identity key is on the
    /// relay's published whitelist. Gates the composer affordance — `false` keeps
    /// the pane read-only (non-signer / ephemeral path).
    can_compose: bool,
    /// (#92) The active public-space composer sub-mode (`None` = read-only).
    compose_mode: PublicComposeMode,
    /// (#92) The composer buffers: the single-line MOTD draft, and the
    /// announcement topic + body drafts. Cleared after a submit or `Esc`.
    compose_motd: String,
    compose_topic: String,
    compose_body: String,
    /// (#92) A queued signed-MOTD upload the binary forwards as `NetCommand::SetMotd`
    /// (drained once). The net actor signs with the stable key and uploads.
    pending_set_motd: Option<String>,
    /// (#92) A queued signed-announcement upload `(topic, body)` the binary forwards
    /// as `NetCommand::UploadAnnouncement` (drained once).
    pending_upload_announcement: Option<(String, String)>,
    /// Latest deprecation-warning snapshot from the net actor (ISC-C25), one row
    /// per in-use suite the verified policy schedules for retirement. Replaced
    /// wholesale on each `DeprecationSnapshot` (idempotent — never appended), so
    /// a refresh can never duplicate or resurrect a row. Left intact on a
    /// `DeprecationError` so a rollback / fetch failure never blanks the cached
    /// warnings the user is relying on.
    deprecation_warnings: Vec<DeprecationWarningRow>,
    /// Version of the last accepted deprecation policy (ISC-A-S11), `None`
    /// before any policy has been fetched or when the relay serves none.
    deprecation_policy_version: Option<u64>,
    /// Whether the relay served a (verified) policy on the last successful
    /// fetch. `false` distinguishes "relay has no policy configured" from
    /// "policy fetched but no in-use suite is affected" — both yield zero
    /// warning rows but mean different things to the user.
    deprecation_had_policy: bool,
    /// Selected row index in the deprecation-warnings pane (Up/Down moves it).
    dep_sel: usize,
    /// A queued deprecation refresh the binary should forward to the net actor
    /// (drained once). Set when the user opens the Deprecation pane or presses
    /// `r`; the binary translates it into a `NetCommand::RefreshDeprecation`.
    pending_deprecation_refresh: bool,
    /// Latest introducer-discovered candidate peers (M12 gate step 6, ISC-C22 /
    /// ISC-S6 / ISC-A-C19), each as a `(server_id, address)` pair. Replaced
    /// wholesale on each `IntroducerSnapshot` (idempotent — never appended), and
    /// left intact on an `IntroducerError` so a transient refresh failure never
    /// blanks the last-known discovery view. Server-id + address ONLY — no key
    /// material reaches this field (ISC-S6). Surfaced read-only in the Servers
    /// pane; these are *candidates*, never trusted or connectable until the user
    /// explicitly promotes one (ISC-A-C19 — discovery never auto-trusts).
    discovered_peers: Vec<(String, String)>,
    /// A queued introducer refresh the binary should forward to the net actor
    /// (drained once). Set when the user opens the Servers pane; the binary
    /// translates it into a `NetCommand::RefreshIntroducer`.
    pending_introducer_refresh: bool,
    /// Set true on first-start completion (Item D / ISC-C49/C50) so the binary
    /// persists the at-rest blob + `.dseed` to the profile root. Drained once
    /// by [`Self::take_pending_persist`]; the binary then reads [`Self::session`].
    pending_persist: bool,
    /// The daily-login Unlock passphrase buffer (ISC-C3 / Item E).
    unlock_input: String,
    /// The last Unlock error to surface (wrong passphrase, etc.).
    unlock_error: Option<String>,
    /// A queued Unlock attempt the binary should service (drained once): the
    /// typed passphrase. The binary decrypts the on-disk blob and feeds the
    /// result back via [`Self::on_unlock_success`] / [`Self::on_unlock_failure`].
    pending_unlock: Option<String>,
    /// The live at-rest payload the running client mutates and re-seals for the
    /// M13 write-through (display name / mute / hide / circles). Populated from
    /// [`SessionMaterials::seeds`] at first-start completion and on Unlock; `None`
    /// before either. Mutations on this drive [`Self::persist_seeds`].
    seeds: Option<Seeds>,
    /// The cached at-rest AEAD key matching [`Self::seeds`], from
    /// [`SessionMaterials::seal_key`]. Lets [`Self::persist_seeds`] re-seal on
    /// every mutation without re-running Argon2id. `None` until a session lands;
    /// zeroizes on drop.
    seal_key: Option<SealingKey>,
    /// A re-sealed at-rest blob the binary should write over `seeds.blob` (M13
    /// write-through). Set by [`Self::persist_seeds`], drained once by
    /// [`Self::take_pending_blob_update`]. Distinct from [`Self::pending_persist`],
    /// which is the first-start config+blob+`.dseed` write.
    pending_blob_update: Option<Vec<u8>>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// A freshly-launched app sitting on the [`Screen::Welcome`] landing screen,
    /// using production-strength Argon2 params for first-start sealing.
    pub fn new() -> Self {
        Self::with_argon(ArgonParams::desktop_default())
    }

    /// Construct with explicit Argon2 params — the test/gate entry point that
    /// keeps first-start sealing fast.
    pub fn with_argon(argon: ArgonParams) -> Self {
        Self {
            screen: Screen::Welcome,
            should_quit: false,
            argon,
            first_start: None,
            session: None,
            connection: ConnectionStatus::Disconnected,
            pending_connect: None,
            main_focus: MainFocus::Chat,
            compose: String::new(),
            circle_phrase: String::new(),
            share_input: String::new(),
            messages: Vec::new(),
            circle_status: CircleStatus::NotJoined,
            circles: Vec::new(),
            active_circle: None,
            public_room: None,
            status: None,
            mute_input: String::new(),
            muted: std::collections::BTreeSet::new(),
            servers: Vec::new(),
            server_input: String::new(),
            server_sel: 0,
            pending_join: None,
            pending_share_define: None,
            pending_share_defines: std::collections::VecDeque::new(),
            defined_shares: Vec::new(),
            defined_sel: 0,
            pending_publish: None,
            pending_publishes: std::collections::VecDeque::new(),
            pending_unpublish: None,
            pending_cancel_publish: None,
            hashing: std::collections::BTreeSet::new(),
            published: Vec::new(),
            pending_joins: std::collections::VecDeque::new(),
            pending_chat: None,
            pending_public_room: None,
            trust_log: TrustEventLog::default(),
            blocking: None,
            persistent: Vec::new(),
            transient: None,
            close_cause: None,
            history_sel: 0,
            local_shares: Vec::new(),
            public_shares: Vec::new(),
            indexer_status: IndexerStatus::Idle,
            hidden_shares: std::collections::BTreeSet::new(),
            hide_input: String::new(),
            share_sel: 0,
            pending_share_refresh: false,
            fetch: None,
            pending_share_fetch: None,
            pending_fetch_confirm: None,
            fetched_shares: Vec::new(),
            fetched_sel: 0,
            pending_fetched_refresh: false,
            public_motd: None,
            public_posts: Vec::new(),
            post_sel: 0,
            can_compose: false,
            compose_mode: PublicComposeMode::None,
            compose_motd: String::new(),
            compose_topic: String::new(),
            compose_body: String::new(),
            pending_set_motd: None,
            pending_upload_announcement: None,
            pending_public_space_refresh: false,
            deprecation_warnings: Vec::new(),
            deprecation_policy_version: None,
            deprecation_had_policy: false,
            dep_sel: 0,
            pending_deprecation_refresh: false,
            discovered_peers: Vec::new(),
            pending_introducer_refresh: false,
            pending_persist: false,
            unlock_input: String::new(),
            unlock_error: None,
            pending_unlock: None,
            seeds: None,
            seal_key: None,
            pending_blob_update: None,
        }
    }

    /// Construct an app that starts on the daily-login [`Screen::Unlock`] (Item
    /// E): used when the binary detected an existing profile blob at startup.
    /// Production uses [`ArgonParams::desktop_default`]; tests inject fast params.
    pub fn for_existing_profile() -> Self {
        Self::for_existing_profile_with_argon(ArgonParams::desktop_default())
    }

    /// [`Self::for_existing_profile`] with explicit Argon2 params.
    pub fn for_existing_profile_with_argon(argon: ArgonParams) -> Self {
        let mut app = Self::with_argon(argon);
        app.screen = Screen::Unlock;
        app
    }

    /// The screen currently being displayed.
    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    /// Whether the event loop should stop and the terminal be restored.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// The active first-start flow, for rendering. `Some` only on
    /// [`Screen::FirstStart`].
    pub fn first_start(&self) -> Option<&FirstStartUi> {
        self.first_start.as_ref()
    }

    /// Whether a completed first-start has produced session materials (the
    /// connect path consumes these in a later workstream).
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// The live connection status, for rendering the main view.
    pub fn connection(&self) -> &ConnectionStatus {
        &self.connection
    }

    /// Take a queued connect request, if any — the binary forwards it to the
    /// network actor. Clears the slot so it is handed off exactly once.
    pub fn take_pending_connect(&mut self) -> Option<ConnectRequest> {
        self.pending_connect.take()
    }

    /// Take a queued circle-join phrase (drained once by the binary). The
    /// interactive single-shot slot wins; with it empty, the next queued rejoin
    /// (M13 persistence, ISC-C59) is popped FIFO. So the binary's once-per-tick
    /// drain dispatches all remembered circles over successive ticks without any
    /// dispatch-loop change.
    pub fn take_pending_join(&mut self) -> Option<String> {
        self.pending_join
            .take()
            .or_else(|| self.pending_joins.pop_front())
    }

    /// Take a queued chat send (drained once by the binary).
    pub fn take_pending_chat(&mut self) -> Option<ChatSend> {
        self.pending_chat.take()
    }

    /// Take a queued Define-Share request (M14, drained once by the binary,
    /// which derives the index path + key from the session and sends
    /// `NetCommand::DefineShare`). The interactive single-shot slot wins; with it
    /// empty, the next queued Unlock re-definition (ISC-C21) is popped FIFO — so
    /// the binary's once-per-tick drain replays all remembered roots over
    /// successive ticks without any dispatch-loop change (mirrors
    /// [`Self::take_pending_join`]).
    pub fn take_pending_share_define(&mut self) -> Option<ShareDefineRequest> {
        self.pending_share_define
            .take()
            .or_else(|| self.pending_share_defines.pop_front())
    }

    /// All defined share roots + names, in definition order (M16 C1, ISC-C69) —
    /// the My-defined list rendered in the Shares pane.
    pub fn defined_shares(&self) -> &[(std::path::PathBuf, String)] {
        &self.defined_shares
    }

    /// The selection cursor into [`Self::defined_shares`] (M16 C1).
    pub fn defined_sel(&self) -> usize {
        self.defined_sel
    }

    /// The currently-selected defined share (M16 C1) — what the Shares pane's
    /// `[p]`/`[u]` act on. `None` when nothing is defined.
    pub fn selected_defined_share(&self) -> Option<&(std::path::PathBuf, String)> {
        self.defined_shares.get(self.defined_sel)
    }

    /// Append a defined share root, deduplicating by root (M16 C1). Defining the
    /// same root twice does not duplicate it; the display name is refreshed to
    /// the latest. Used by both the interactive define and the Unlock restore.
    fn push_defined_share(&mut self, root: std::path::PathBuf, name: String) {
        if let Some(existing) = self.defined_shares.iter_mut().find(|(r, _)| r == &root) {
            existing.1 = name;
        } else {
            self.defined_shares.push((root, name));
        }
        self.clamp_defined_sel();
    }

    /// Echo the My-defined selection on the status line after a `[`/`]` move
    /// (M16 smoke fix). The split-cursor scheme (arrows = public row, `[`/`]`
    /// = defined row) proved invisible in live smoke — the echo confirms the
    /// keys did something and names what `[p]`/`[u]` will act on. One-shot:
    /// cleared on focus change like any status (ISC-C70).
    fn echo_defined_selection(&mut self) {
        let (sel, len) = (self.defined_sel, self.defined_shares.len());
        if let Some(name) = self.defined_shares.get(sel).map(|(_, n)| n.clone()) {
            self.status = Some(format!("selected {}/{len}: {name}", sel + 1));
        }
    }

    /// Keep [`Self::defined_sel`] within bounds of [`Self::defined_shares`].
    fn clamp_defined_sel(&mut self) {
        let max = self.defined_shares.len().saturating_sub(1);
        if self.defined_sel > max {
            self.defined_sel = max;
        }
    }

    /// Shares currently published+served this session (M16, [`PublishedShare`]).
    pub fn published(&self) -> &[PublishedShare] {
        &self.published
    }

    /// Drain a queued publish request (D, M15) — the binary turns it into a
    /// `NetCommand::PublishShare`.
    pub fn take_pending_publish(&mut self) -> Option<PublishRequest> {
        self.pending_publish.take()
    }

    /// Drain one queued auto-republish (publish-intent persistence), but ONLY
    /// once connected+authed — publish needs a live session, so before that this
    /// returns `None` and the queue waits. Skips a root already published,
    /// mid-publish, or queued for a manual publish (the ISC-A-C34 guard). The
    /// binary drains it into `NetCommand::PublishShare`.
    pub fn take_pending_autopublish(&mut self) -> Option<PublishRequest> {
        if !matches!(self.connection, ConnectionStatus::Connected { .. }) {
            return None;
        }
        while let Some((root, name)) = self.pending_publishes.pop_front() {
            let already = self.published.iter().any(|p| p.root == root)
                || self
                    .pending_publish
                    .as_ref()
                    .is_some_and(|r| r.root == root)
                || self.hashing.contains(&root);
            if already {
                continue;
            }
            let sharer_handle = self.own_handle();
            return Some(PublishRequest {
                root,
                name,
                sharer_handle,
            });
        }
        None
    }

    /// Drain a queued unpublish (D, M15) — the binary turns it into a
    /// `NetCommand::UnpublishShare`.
    pub fn take_pending_unpublish(&mut self) -> Option<String> {
        self.pending_unpublish.take()
    }

    /// Drain a queued publish-hash cancel (M16 serve-from-disk) — the binary
    /// turns it into a `NetCommand::CancelPublish` for that defined root.
    pub fn take_pending_cancel_publish(&mut self) -> Option<std::path::PathBuf> {
        self.pending_cancel_publish.take()
    }

    /// The current Define-Share input buffer, for rendering the box (M14).
    pub fn share_input(&self) -> &str {
        &self.share_input
    }

    /// Take a queued public-room post as `(body, sender_handle)` — drained once
    /// by the binary (ISC-S22). The handle carries the display name so peers see
    /// the name, not the floor (parity with the circle path).
    pub fn take_pending_public_room(&mut self) -> Option<(String, String)> {
        self.pending_public_room.take()
    }

    /// The joined default public room name, if subscribed (ISC-S22 / ISC-C56),
    /// for rendering the chat-surface header.
    pub fn public_room(&self) -> Option<&str> {
        self.public_room.as_deref()
    }

    /// The completed/active session materials, for the binary to persist (Item
    /// D) and for tests. `Some` once first-start completes or an Unlock succeeds.
    pub fn session(&self) -> Option<&SessionMaterials> {
        self.session.as_ref()
    }

    /// Drain the persist flag (Item D / ISC-C49/C50). When `true`, the binary
    /// writes [`Self::session`]'s blob + `.dseed` to the resolved profile root.
    pub fn take_pending_persist(&mut self) -> bool {
        std::mem::replace(&mut self.pending_persist, false)
    }

    /// Re-seal the live [`Seeds`] under the cached [`SealingKey`] and queue the
    /// refreshed blob for the binary to write over `seeds.blob` (M13
    /// write-through). A no-op (with no error) before a session lands — both the
    /// seeds and the key are `None` until first-start completes or an Unlock
    /// succeeds. A seal failure surfaces on the status line rather than panicking,
    /// so a persist hiccup never takes the session down; the in-memory mutation is
    /// kept regardless (the next mutation re-attempts the write).
    fn persist_seeds(&mut self) {
        let (Some(seeds), Some(key)) = (self.seeds.as_ref(), self.seal_key.as_ref()) else {
            return;
        };
        match key.seal(seeds) {
            Ok(bytes) => self.pending_blob_update = Some(bytes),
            Err(e) => self.status = Some(format!("could not save: {e}")),
        }
    }

    /// Drain the queued M13 write-through blob, if any — the binary overwrites
    /// `seeds.blob` with it (settings payload only; the `.dseed` and config are
    /// untouched). Distinct from [`Self::take_pending_persist`], the first-start
    /// config+blob+`.dseed` write.
    pub fn take_pending_blob_update(&mut self) -> Option<Vec<u8>> {
        self.pending_blob_update.take()
    }

    /// Test-only: take the session materials out (to feed an Unlock-success
    /// test without re-implementing the core enrollment dance).
    #[cfg(test)]
    pub(crate) fn session_take_for_test(&mut self) -> SessionMaterials {
        self.session.take().expect("session present")
    }

    /// The Unlock passphrase buffer, for rendering the masked field (Item E).
    pub fn unlock_input(&self) -> &str {
        &self.unlock_input
    }

    /// The last Unlock error to surface, if any.
    pub fn unlock_error(&self) -> Option<&str> {
        self.unlock_error.as_deref()
    }

    /// Take a queued Unlock attempt — the typed passphrase (drained once). The
    /// binary decrypts the on-disk blob and reports back via
    /// [`Self::on_unlock_success`] / [`Self::on_unlock_failure`].
    pub fn take_pending_unlock(&mut self) -> Option<String> {
        self.pending_unlock.take()
    }

    /// Fold a successful Unlock (ISC-C3 / Item E): stash the reconstructed
    /// session, queue a trusted-mode connect to the persisted bootstrap relay,
    /// and route to [`Screen::Main`] — never the enrollment wizard.
    pub fn on_unlock_success(&mut self, session: SessionMaterials) {
        self.pending_connect = Some(ConnectRequest {
            server_id: session.bootstrap.server_id.clone(),
            address: session.bootstrap.address.clone(),
            trusted: true,
        });
        self.connection = ConnectionStatus::Connecting;
        // M13 write-through: hold the live payload + cached key for in-place
        // re-seals, and restore the persisted UI state (mute / hide sets) from it
        // so the session reflects what was saved instead of starting empty
        // (ISC-C15 / C16 / C4b). The display name rides in `session.display_name`
        // / `session.handle` (restored in `session_materials_from_unlock`).
        self.seeds = Some(session.seeds.clone());
        self.seal_key = Some(session.seal_key.clone());
        self.muted = session.seeds.muted.clone();
        self.hidden_shares = session.seeds.hidden_shares.clone();
        // M13 persistence (ISC-C59): every remembered circle is silently rejoined
        // next launch — no re-typing the phrase. Queue one rejoin per persisted
        // entry (FIFO preserves join order); the binary drains `take_pending_join`
        // once per tick and reconnects on unlock, so these dispatch naturally.
        // The runtime set is NOT pre-populated — the `CircleJoined` events restore
        // `self.circles` with the persisted labels (the rejoin branch above).
        for entry in session.seeds.circles() {
            self.pending_joins.push_back(entry.entropy().to_owned());
        }
        if !self.pending_joins.is_empty() {
            self.circle_status = CircleStatus::Joining;
        }
        // M14 persistence (ISC-C21): re-index every remembered share root next
        // launch. Queue one re-definition per persisted entry (FIFO); the binary
        // drains `take_pending_share_define` once per tick, so these dispatch as
        // `NetCommand::DefineShare` naturally — and because they ride the queue
        // (not `on_key_define_share`), they re-index without re-persisting.
        for sh in session.seeds.shares() {
            let root = std::path::PathBuf::from(&sh.root);
            // Restore EVERY persisted root into the My-defined list so `[p]`/`[u]`
            // can publish/unpublish each independently (M16 C1, ISC-C69) — not
            // just the last-defined one.
            let name = Self::share_display_name(&root, &sh.label);
            self.push_defined_share(root.clone(), name.clone());
            // Publish-intent persistence: a remembered-published root
            // auto-republishes once reconnected. Queued here, drained after auth
            // (publish needs a live session); the relay stays RAM-only and the
            // client simply re-asserts, so ISC-S20 ephemerality is unchanged.
            if session.seeds.published().iter().any(|p| p.root == sh.root) {
                self.pending_publishes.push_back((root.clone(), name));
            }
            self.pending_share_defines.push_back(ShareDefineRequest {
                root,
                label: sh.label.clone(),
            });
        }
        self.session = Some(session);
        self.unlock_input.clear();
        self.unlock_error = None;
        self.screen = Screen::Main;
    }

    /// Fold a failed Unlock: surface the error and stay on [`Screen::Unlock`].
    /// The passphrase buffer is cleared so a retry starts fresh.
    pub fn on_unlock_failure(&mut self, message: impl Into<String>) {
        self.unlock_error = Some(message.into());
        self.unlock_input.clear();
    }

    /// Which main-view input has focus, for rendering.
    pub fn main_focus(&self) -> MainFocus {
        self.main_focus
    }

    /// The current chat compose buffer, for rendering.
    pub fn compose(&self) -> &str {
        &self.compose
    }

    /// The current circle-join phrase buffer, for rendering.
    pub fn circle_phrase(&self) -> &str {
        &self.circle_phrase
    }

    /// Estimated key-space strength of the current circle-join phrase (ISC-C9),
    /// for the red→green meter in the join box. Mirrors the first-start
    /// session-passphrase meter (ISC-C12); the circle floor is higher (≥128 bits,
    /// [`strength::CIRCLE_ENTROPY_MIN_BITS`]) and uses the M15 word+charset
    /// estimator that can actually reach it. An empty phrase estimates `0.0`
    /// bits, so the meter reads empty until the user types.
    pub fn circle_phrase_strength(&self) -> CircleStrength {
        strength::estimate_circle(&self.circle_phrase)
    }

    /// The chat lines, oldest first, for rendering (ISC-10). The split view
    /// filters these per pane via [`Self::messages_on`]; this accessor returns the
    /// whole transcript (used by mention-autocomplete and tests).
    pub fn messages(&self) -> &[ChatLine] {
        &self.messages
    }

    /// Chat lines whose [`Surface`] tag matches `surface`, oldest first
    /// (ISC-C61 / ISC-A-C29). The split chat view calls this once per pane —
    /// `Surface::Lobby` for the top pane and `Surface::Circle(active_id)` for the
    /// bottom carousel pane — so a line received on one surface can never render
    /// in another's pane (no cross-surface bleed).
    pub fn messages_on(&self, surface: Surface) -> impl Iterator<Item = &ChatLine> {
        self.messages.iter().filter(move |m| m.surface == surface)
    }

    /// Fold a chat line into the transcript with de-dup + chronological ordered-insert
    /// (#130 — TUI parity with the GUI's `push_message`). The DHT re-sweep and the live
    /// watch can both deliver the SAME message, and DHT propagation can deliver messages
    /// out of send order, so a plain append duplicated a re-swept line and rendered
    /// out-of-order arrivals out of order. Returns `true` if the line was inserted.
    ///
    /// - **De-dup:** an exact `(surface, sender, body, sent_unix_ms)` match already
    ///   present is skipped, so a re-swept already-seen line renders once.
    /// - **Ordered-insert:** the line lands at its `sent_unix_ms` position — a no-op
    ///   append for the common in-order case, a chronological slot for a late arrival.
    ///
    /// The flat transcript is kept globally sorted by `sent_unix_ms`; `messages_on`
    /// filters by surface, so each pane stays chronological (a local echo carries a real
    /// `now_unix_ms()` so it sorts as the newest line, not to the epoch-0 front). The
    /// GUI's per-room read high-water / unread half of #126 has no TUI counterpart —
    /// the TUI has no unread indicator.
    fn push_message(
        &mut self,
        sender: String,
        body: String,
        sent_unix_ms: i64,
        surface: Surface,
    ) -> bool {
        if self.messages.iter().any(|m| {
            m.sent_unix_ms == sent_unix_ms
                && m.surface == surface
                && m.sender == sender
                && m.body == body
        }) {
            return false;
        }
        // Ordered-insert by sent_unix_ms (#130). The #131 forged-timestamp clamp is
        // GUI-only for now: the TUI is a post-cutover surface (does not gate), and the
        // sound clamp needs a stored per-line order key (a moving-`now` re-clamp in the
        // comparator would break the sorted invariant — xhigh review); TUI-#131 rides
        // the TUI parity work (#111). Raw ordering here is stable.
        let pos = self
            .messages
            .partition_point(|m| m.sent_unix_ms <= sent_unix_ms);
        self.messages.insert(
            pos,
            ChatLine {
                sender,
                body,
                sent_unix_ms,
                surface,
            },
        );
        true
    }

    /// The circle subscription status, for rendering.
    pub fn circle_status(&self) -> &CircleStatus {
        &self.circle_status
    }

    /// A transient status/error line, for rendering.
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Set the transient status/error line from the binary (e.g. a profile
    /// persist failure surfaced after first-start, Item D).
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status = Some(message.into());
    }

    /// Fold a network-actor event into UI state.
    pub fn on_net_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::Connected {
                server,
                version,
                rotation_notice,
            } => {
                self.connection = ConnectionStatus::Connected {
                    server,
                    version,
                    rotation_notice,
                };
            }
            NetEvent::ConnectFailed { message } => {
                self.connection = ConnectionStatus::Failed(message);
            }
            // (WB-5.1 / I5″.7, WB-ISC-20) The reaper is suspended under an elevated DHT
            // regime, so the roster may show a departed member — surface it on the
            // status line so a sharing decision that trusts roster-as-presence sees the
            // caveat. Cleared once the regime calms and the resume grace elapses.
            NetEvent::PresenceStale { stale } => {
                // The status line is SHARED (ChatError, SharesError, …), so this is
                // lowest-priority: set the caveat only when the line is free, clear only
                // our own message — never clobbering an unrelated status.
                const STALE_MSG: &str = "presence may be stale — network congested";
                if stale {
                    if self.status.is_none() {
                        self.set_status(STALE_MSG);
                    }
                } else if self.status.as_deref() == Some(STALE_MSG) {
                    self.status = None;
                }
            }
            // A circle joined (ISC-C59): ADD it to the membership set (never evict
            // an existing one) and select it active (ISC-C60). An idempotent
            // re-join — the actor re-emits an id already in the set — only
            // re-selects it active; the label is refreshed in case it changed.
            NetEvent::CircleJoined {
                circle_id,
                label,
                entropy,
            } => {
                self.circle_status = CircleStatus::Joined;
                if let Some(pos) = self.circles.iter().position(|c| c.id == circle_id) {
                    // Idempotent re-emit: refresh the label, keep the existing
                    // entropy, and re-select active. Never re-persist.
                    self.circles[pos].label = label;
                    self.active_circle = Some(pos);
                } else if let Some(persisted) = self
                    .seeds
                    .as_ref()
                    .and_then(|s| s.circles().iter().find(|c| c.entropy() == entropy))
                {
                    // A rejoin (M13, ISC-C59): this circle is already remembered.
                    // The user's persisted label (ISC-C62) wins over the
                    // actor-supplied one, and we must NOT persist again.
                    self.circles.push(JoinedCircle::new(
                        circle_id,
                        persisted.label.clone(),
                        entropy,
                    ));
                    self.active_circle = Some(self.circles.len() - 1);
                } else {
                    // A fresh join: remember it (M13 write-through, ISC-C59) so
                    // it is silently rejoined next launch.
                    self.circles
                        .push(JoinedCircle::new(circle_id, label.clone(), entropy.clone()));
                    self.active_circle = Some(self.circles.len() - 1);
                    if let Some(seeds) = self.seeds.as_mut() {
                        seeds.add_circle(entropy, label);
                        self.persist_seeds();
                    }
                }
            }
            NetEvent::CircleJoinFailed { message } => {
                self.circle_status = CircleStatus::Failed(message);
            }
            // A circle message (ISC-A-C30): tag it with the single circle whose
            // key opened it (the actor's attribution). The split view renders it
            // only in that circle's pane (ISC-A-C29). A frame for a circle no
            // longer in the set is dropped — never re-attributed to another pane.
            NetEvent::ChatMessage {
                circle_id,
                sender,
                body,
                sent_unix_ms,
            } => {
                if self.circles.iter().any(|c| c.id == circle_id) {
                    // De-dup + ordered-insert (#130): a DHT re-sweep can re-deliver an
                    // already-seen circle message, and propagation can deliver out of
                    // send order. (#151 stale-backlog prune is GUI-only for now — the
                    // TUI is a post-cutover surface; it rides the TUI parity work #111,
                    // like the #131 clamp.)
                    self.push_message(sender, body, sent_unix_ms, Surface::Circle(circle_id));
                }
            }
            NetEvent::ChatError { message } => self.status = Some(message),
            // Public-room lifecycle (ISC-S22 / ISC-C56): the default chat surface
            // is a public room, so a verified public-room message folds into the
            // same transcript as circle chat. The default surface needs no
            // circle — joining/failing only updates the status line.
            NetEvent::PublicRoomJoined { room } => {
                self.public_room = Some(room);
            }
            NetEvent::PublicRoomJoinFailed { message } => {
                self.status = Some(format!("public room: {message}"));
            }
            NetEvent::PublicRoomMessage {
                room: _,
                sender,
                body,
                sent_unix_ms,
            } => {
                // De-dup + ordered-insert (#130), Lobby-tagged so it renders only in
                // the top lobby pane (ISC-C61 / ISC-A-C29). (#151 stale-backlog prune
                // is GUI-only for now; the TUI rides #111, like the #131 clamp.)
                self.push_message(sender, body, sent_unix_ms, Surface::Lobby);
            }
            NetEvent::TrustEvent { key, server_id } => self.fold_trust_event(key, server_id),
            NetEvent::ConnectionClosed { cause } => self.close_cause = Some(cause),
            NetEvent::SharesSnapshot {
                local,
                remote,
                indexer_status,
            } => {
                self.local_shares = local;
                self.public_shares = remote;
                self.indexer_status = indexer_status;
                // Clamp the selection so it never points past the new list.
                let max_idx = self.public_shares.len().saturating_sub(1);
                if self.share_sel > max_idx {
                    self.share_sel = max_idx;
                }
            }
            NetEvent::SharesError { message } => self.status = Some(message),
            NetEvent::IndexerStatus(status) => {
                // M14: a standalone indexer transition (define → Indexing →
                // Ready). On Ready, pull the freshly-indexed rows into the
                // My-shares pane with a follow-up RefreshShares.
                let ready = matches!(status, IndexerStatus::Ready { .. });
                self.indexer_status = status;
                if ready {
                    self.pending_share_refresh = true;
                }
            }
            NetEvent::ShareDefineFailed { message } => self.status = Some(message),
            NetEvent::PublicSpaceSnapshot {
                motd,
                posts,
                can_compose,
            } => {
                self.public_motd = motd;
                self.public_posts = posts;
                // (#92) Signer-gating verdict for the composer affordance.
                self.can_compose = can_compose;
                // Clamp the selection so it never points past the new list.
                let max_idx = self.public_posts.len().saturating_sub(1);
                if self.post_sel > max_idx {
                    self.post_sel = max_idx;
                }
            }
            NetEvent::PublicSpaceError { message } => self.status = Some(message),
            NetEvent::DeprecationSnapshot {
                policy_version,
                warnings,
                had_policy,
            } => {
                self.deprecation_warnings = warnings;
                self.deprecation_policy_version = policy_version;
                self.deprecation_had_policy = had_policy;
                // Clamp the selection so it never points past the new list.
                let max_idx = self.deprecation_warnings.len().saturating_sub(1);
                if self.dep_sel > max_idx {
                    self.dep_sel = max_idx;
                }
            }
            // A fetch / verification / rollback failure surfaces on the status
            // line only — the cached warning rows are deliberately left intact
            // (ISC-C25): going blank on rollback would hide the very state the
            // anti-rollback check exists to protect. The rollback / unreadable
            // trust event arrives separately as a `TrustEvent`.
            NetEvent::DeprecationError { message } => self.status = Some(message),
            // A1: the manifest arrived. Move the overlay into Preview so the
            // user can review the file list before any chunk downloads. Guard
            // on share_id so a stale manifest for a since-replaced fetch is
            // ignored.
            NetEvent::FetchManifest {
                share_id,
                name: _,
                entries,
            } => {
                if let Some(f) = self.fetch.as_mut()
                    && f.share_id == share_id
                {
                    // A2: default every file selected (Enter without toggling
                    // downloads all = the A1 behavior); cursor at the top.
                    f.preview_checked = vec![true; entries.len()];
                    f.preview_cursor = 0;
                    f.preview_scroll = 0;
                    // ISC-C72: build the collapsible folder tree once from the
                    // flat manifest; every Dir starts collapsed.
                    f.preview_tree = FetchUi::build_preview_tree(&entries);
                    f.preview_collapsed = f
                        .preview_tree
                        .iter()
                        .map(|n| matches!(n.kind, PreviewKind::Dir { .. }))
                        .collect();
                    f.status = FetchStatus::Preview(entries);
                }
            }
            NetEvent::FetchProgress {
                total_chunks,
                chunks_received,
                bytes_received,
            } => {
                if let Some(f) = self.fetch.as_mut() {
                    if total_chunks.is_some() && f.total_chunks.is_none() {
                        // First progress event carrying a total: the manifest
                        // just arrived and chunks are now flowing.
                        f.status = FetchStatus::Receiving;
                    }
                    f.total_chunks = total_chunks.or(f.total_chunks);
                    f.chunks_received = chunks_received;
                    f.bytes_received = bytes_received;
                }
            }
            NetEvent::FetchComplete {
                share_id: _,
                files_written,
                bytes_written,
            } => {
                if let Some(f) = self.fetch.as_mut() {
                    f.status = FetchStatus::Complete;
                    // Complete means every selected chunk landed: clamp the
                    // counter to the known chunk total (M16 — `files_written`
                    // counts FILES, no longer == chunks; it is only the
                    // fallback when no total was ever learned).
                    f.chunks_received = f.total_chunks.unwrap_or(files_written);
                    f.bytes_received = bytes_written;
                }
            }
            NetEvent::FetchError { message } => {
                if let Some(f) = self.fetch.as_mut() {
                    f.status = FetchStatus::Failed(message);
                } else {
                    self.status = Some(message);
                }
            }
            // M15 C: the fetched-downloads list (browse pane), replaced wholesale.
            NetEvent::FetchedShares { shares } => {
                self.fetched_shares = shares;
                if self.fetched_sel >= self.fetched_shares.len() {
                    self.fetched_sel = self.fetched_shares.len().saturating_sub(1);
                }
            }
            // The discovered-candidate list replaces wholesale (the introducer
            // merge is idempotent, so the snapshot is the converged set, never a
            // delta). Server-id + address only — no key material (ISC-S6).
            NetEvent::IntroducerSnapshot { candidates } => {
                self.discovered_peers = candidates;
            }
            // A refresh failure surfaces on the status line only — the cached
            // candidate list is left intact so a transient failure never blanks
            // the last-known discovery view (mirrors the deprecation precedent).
            NetEvent::IntroducerError { message } => self.status = Some(message),
            // A share is now publishing + being served (D, M15). Track it for the
            // unpublish affordance and confirm what's serving on the status line.
            NetEvent::PublishStarted {
                share_id,
                root,
                name,
                file_count,
            } => {
                // The hash phase is over — clear the hashing marker so `[u]`
                // routes to unpublish, not cancel (M16 serve-from-disk).
                self.hashing.remove(&root);
                // Publish-intent persistence: remember this root as published so
                // it auto-republishes next launch. Idempotent — an auto-republish
                // re-firing PublishStarted is a no-op write (add returns false).
                let root_str = root.to_string_lossy().into_owned();
                if self
                    .seeds
                    .as_mut()
                    .is_some_and(|s| s.add_published(root_str, None))
                {
                    self.persist_seeds();
                }
                self.published.push(PublishedShare {
                    share_id: share_id.clone(),
                    root,
                    name: name.clone(),
                });
                self.status = Some(format!(
                    "sharing {name:?} as {share_id} ({file_count} file(s)) — [u] in Shares to stop"
                ));
            }
            // A publish hash is in flight (M16 serve-from-disk): mark the root
            // hashing — which extends the `[p]` guard (ISC-A-C34) and routes
            // `[u]` to CancelPublish — and surface the per-file progress with
            // the cancel affordance spelled out.
            NetEvent::PublishProgress {
                root,
                name,
                done,
                total,
            } => {
                self.hashing.insert(root);
                self.status = Some(format!(
                    "hashing {name}: {done}/{total} files — [u] cancels"
                ));
            }
            // The user's own cancel landed — neutral wording, not a failure
            // (M16). The root leaves the hashing set so `[p]` can retry.
            NetEvent::PublishCancelled { root, name } => {
                self.hashing.remove(&root);
                self.status = Some(format!("publish of {name:?} cancelled"));
            }
            NetEvent::PublishError { message, root } => {
                // A root-carrying failure (hash / RPC step) clears that root's
                // hashing marker so the ISC-A-C34 guard stays open and `[p]`
                // is retryable; a pre-flight failure (`None`) never set one.
                if let Some(root) = root {
                    self.hashing.remove(&root);
                }
                self.status = Some(message);
            }
            NetEvent::PublishStopped { share_id } => {
                // Drop the publish-intent persistence for this share (keyed via
                // its root) so an explicit unpublish does NOT auto-republish next
                // launch.
                let root_str = self
                    .published
                    .iter()
                    .find(|p| p.share_id == share_id)
                    .map(|p| p.root.to_string_lossy().into_owned());
                self.published.retain(|p| p.share_id != share_id);
                if let Some(root_str) = root_str
                    && self
                        .seeds
                        .as_mut()
                        .is_some_and(|s| s.remove_published(&root_str))
                {
                    self.persist_seeds();
                }
                self.status = Some(format!("stopped sharing {share_id}"));
            }
        }
    }

    /// Route a trust event to its ISC-C28 affordance class and record it
    /// (Transient events are dropped from the log by [`TrustEventLog::append`] —
    /// the intentional A-C12 asymmetry — but still drive the toast slot).
    fn fold_trust_event(&mut self, key: TrustEventKey, server_id: Option<String>) {
        self.trust_log.append(TrustEvent::observed(
            now_unix_ms(),
            key,
            server_id.clone(),
            None,
        ));
        let item = TrustItem { key, server_id };
        match class_of(key) {
            TrustEventClass::Blocking => self.blocking = Some(item),
            TrustEventClass::PersistentNonBlocking => {
                if !self.persistent.contains(&item) {
                    self.persistent.push(item);
                }
            }
            TrustEventClass::Transient => self.transient = Some(item),
            // LogOnly surfaces only in the Trust History view (already logged).
            TrustEventClass::LogOnly => {}
        }
    }

    /// The user's own full wire handle (`name#<12hex>`): the value sealed into
    /// outgoing chat / share announcements as the sender so recipients can
    /// @mention / mute / attribute it (ISC-C17/C15/C4), and — since the presence
    /// fix — the name the net actor seeds into the lobby beacon at connect. Falls
    /// back to `"anon"` only if there is no session (pre-first-start). `pub` so the
    /// binary can pass it as `NetCommand::Connect.self_handle`.
    pub fn own_handle(&self) -> String {
        self.session
            .as_ref()
            .map(|s| s.handle.to_string())
            .unwrap_or_else(|| "anon".to_owned())
    }

    /// The user's own handle as a typed [`Handle`], for self-@mention detection
    /// at render (ISC-C17). `None` before first-start completes.
    pub fn own_chat_handle(&self) -> Option<Handle> {
        self.session.as_ref().map(|s| s.handle.clone())
    }

    /// Whether `sender` (a full wire handle) is in the client-local mute set
    /// (ISC-13). The render layer suppresses muted senders.
    pub fn is_muted(&self, sender: &str) -> bool {
        self.muted.contains(sender)
    }

    /// The current mute-box input buffer, for rendering.
    pub fn mute_input(&self) -> &str {
        &self.mute_input
    }

    /// The muted handles, for rendering the mute-box list.
    pub fn muted(&self) -> impl Iterator<Item = &str> {
        self.muted.iter().map(String::as_str)
    }

    /// The managed servers, for rendering the server-management screen (F22).
    pub fn servers(&self) -> &[ManagedServer] {
        &self.servers
    }

    /// The add-server input buffer, for rendering.
    pub fn server_input(&self) -> &str {
        &self.server_input
    }

    /// The selected server index, for highlighting in the server list.
    pub fn server_sel(&self) -> usize {
        self.server_sel
    }

    /// The active Blocking trust event, for rendering the modal (ISC-22).
    pub fn blocking_trust(&self) -> Option<&TrustItem> {
        self.blocking.as_ref()
    }

    /// Undismissed PersistentNonBlocking trust events, for the status-bar badges
    /// (ISC-23).
    pub fn persistent_trust(&self) -> &[TrustItem] {
        &self.persistent
    }

    /// The current Transient trust toast, if any (ISC-24).
    pub fn transient_trust(&self) -> Option<&TrustItem> {
        self.transient.as_ref()
    }

    /// The trust-event audit log, for the Trust History view (ISC-25).
    pub fn trust_log(&self) -> &TrustEventLog {
        &self.trust_log
    }

    /// The last observed connection-close layer, for the distinct close-cause
    /// status rendering (ISC-28).
    pub fn close_cause(&self) -> Option<CloseCause> {
        self.close_cause
    }

    /// The selected row in the Trust History view (newest-first index).
    pub fn history_sel(&self) -> usize {
        self.history_sel
    }

    /// Latest My-shares snapshot (ISC-17), oldest first.
    pub fn local_shares(&self) -> &[LocalShareRow] {
        &self.local_shares
    }

    /// Public-share rows after the hidden-shares filter (ISC-17 / ISC-18).
    /// Mirrors [`daemonseed_cli::public_space::filter_shares_excluding_hidden`]
    /// in the cli crate; duplicated here as a thin borrow-respecting helper so
    /// `App` does not depend on cli's public surface from its own renderer.
    /// Listings with an empty `sharer_handle` (legacy / operator-pinned) are
    /// always kept (no handle to filter against).
    pub fn visible_public_shares(&self) -> Vec<&ShareListing> {
        self.public_shares
            .iter()
            .filter(|s| {
                s.sharer_handle.is_empty() || !self.hidden_shares.contains(&s.sharer_handle)
            })
            .collect()
    }

    /// Size of [`Self::visible_public_shares`] without materialising the Vec.
    fn visible_public_shares_count(&self) -> usize {
        self.public_shares
            .iter()
            .filter(|s| {
                s.sharer_handle.is_empty() || !self.hidden_shares.contains(&s.sharer_handle)
            })
            .count()
    }

    /// Raw public-share snapshot, pre-filter, for tests that need to assert on
    /// what arrived from the relay vs what renders.
    pub fn public_shares_raw(&self) -> &[ShareListing] {
        &self.public_shares
    }

    /// Current indexer status (ISC-20), for the My-shares pane's status line.
    pub fn indexer_status(&self) -> &IndexerStatus {
        &self.indexer_status
    }

    /// Whether `sharer` (a full wire handle) is on the client-local hide set
    /// (ISC-18 / C16).
    pub fn is_share_hidden(&self, sharer: &str) -> bool {
        self.hidden_shares.contains(sharer)
    }

    /// The hide-box input buffer, for rendering.
    pub fn hide_input(&self) -> &str {
        &self.hide_input
    }

    /// The hidden-share handles, for rendering the hide-box list.
    pub fn hidden_shares(&self) -> impl Iterator<Item = &str> {
        self.hidden_shares.iter().map(String::as_str)
    }

    /// The selected public-share row index, for highlighting.
    pub fn share_sel(&self) -> usize {
        self.share_sel
    }

    /// Take a queued shares-refresh request (drained once by the binary, which
    /// translates it into a `NetCommand::RefreshShares`).
    pub fn take_pending_share_refresh(&mut self) -> bool {
        std::mem::replace(&mut self.pending_share_refresh, false)
    }

    /// The currently-active share fetch, if any (ISC-19), for rendering the
    /// fetch overlay.
    pub fn fetch(&self) -> Option<&FetchUi> {
        self.fetch.as_ref()
    }

    /// Take a queued share-fetch request — `(share_id, sharer_handle)` —
    /// drained once by the binary, which translates it into a
    /// `NetCommand::FetchShare`.
    pub fn take_pending_share_fetch(&mut self) -> Option<(String, String, String)> {
        self.pending_share_fetch.take()
    }

    /// Take a queued fetch-confirm —
    /// `(share_id, sharer_handle, name, selected, dest)` — drained once by the
    /// binary into a `NetCommand::ConfirmFetch` (A1/A2/A3). `dest` (ISC-C68) is
    /// the user-chosen download destination, empty for the default downloads dir.
    pub fn take_pending_fetch_confirm(&mut self) -> Option<PendingFetchConfirm> {
        self.pending_fetch_confirm.take()
    }

    /// Accessors + drains for the Fetched browse pane (M15 C).
    pub fn fetched_shares(&self) -> &[daemonseed_core::storage::fetched::FetchedShare] {
        &self.fetched_shares
    }

    /// The selected row index in the Fetched pane.
    pub fn fetched_sel(&self) -> usize {
        self.fetched_sel
    }

    /// Drain a queued fetched-list refresh (binary → `NetCommand::ListFetched`).
    pub fn take_pending_fetched_refresh(&mut self) -> bool {
        std::mem::take(&mut self.pending_fetched_refresh)
    }

    /// The connected relay's rendered (inert) MOTD (ISC-25), for the Public
    /// Space view's MOTD pane. `None` when the relay publishes no MOTD.
    pub fn public_motd(&self) -> Option<&str> {
        self.public_motd.as_deref()
    }

    /// Latest announcement posts (ISC-S7), for the Public Space view's
    /// announcements pane. Each row carries its client-side verification verdict.
    pub fn public_posts(&self) -> &[PublicPostRow] {
        &self.public_posts
    }

    /// The selected announcement-post row index, for highlighting.
    pub fn post_sel(&self) -> usize {
        self.post_sel
    }

    /// Take a queued public-space refresh request (drained once by the binary,
    /// which translates it into a `NetCommand::RefreshPublicSpace`).
    pub fn take_pending_public_space_refresh(&mut self) -> bool {
        std::mem::replace(&mut self.pending_public_space_refresh, false)
    }

    /// (#92) Signer self-determination verdict for the latest snapshot: `true` iff
    /// the local stable identity key is on the relay's published whitelist
    /// (`composer_visible`). Gates the composer affordance in the Public Space view.
    pub fn can_compose(&self) -> bool {
        self.can_compose
    }

    /// (#92) The active public-space composer sub-mode (`None` = read-only display),
    /// for the Public Space view's composer rendering.
    pub fn compose_mode(&self) -> PublicComposeMode {
        self.compose_mode
    }

    /// (#92) The current composer buffers — the MOTD draft, the announcement topic
    /// draft, and the announcement body draft — for echoing the active field.
    pub fn compose_motd(&self) -> &str {
        &self.compose_motd
    }
    pub fn compose_topic(&self) -> &str {
        &self.compose_topic
    }
    pub fn compose_body(&self) -> &str {
        &self.compose_body
    }

    /// (#92) Take a queued signed-MOTD upload (drained once by the binary into a
    /// `NetCommand::SetMotd`). The net actor signs with the held stable key.
    pub fn take_pending_set_motd(&mut self) -> Option<String> {
        self.pending_set_motd.take()
    }

    /// (#92) Take a queued signed-announcement upload `(topic, body)` (drained once
    /// by the binary into a `NetCommand::UploadAnnouncement`).
    pub fn take_pending_upload_announcement(&mut self) -> Option<(String, String)> {
        self.pending_upload_announcement.take()
    }

    /// (#92) Derive the STABLE persistent identity signing key from the unlocked
    /// profile's mnemonic — `derive_identity_keys(.., Identity::Primary)`, the key
    /// behind the whitelisted `name#hash` handle — for the binary to hand to the net
    /// actor on Connect (composer gating + MOTD/announcement signing). `None` on the
    /// ephemeral / no-profile path (no seeds) or if derivation fails.
    pub fn stable_signing_key(&self) -> Option<SignKeypair> {
        let seeds = self.seeds.as_ref()?;
        daemonseed_core::identity::keys::derive_identity_keys(
            &seeds.mnemonic,
            daemonseed_core::identity::keys::Identity::Primary,
        )
        .ok()
        .map(|k| k.signing)
    }

    /// (#156) Derive the STABLE share-root IKM from the unlocked profile's
    /// mnemonic — the fourth expansion of the same identity PRK as
    /// `stable_signing_key` — for the binary to hand to the veilid actor on
    /// Connect, so a published share derives a receiver-verifiable `share_id`.
    /// `None` on the ephemeral / no-profile path or if derivation fails.
    pub fn stable_share_root_ikm(&self) -> Option<daemonseed_core::identity::keys::ShareRootIkm> {
        let seeds = self.seeds.as_ref()?;
        daemonseed_core::identity::keys::derive_identity_keys(
            &seeds.mnemonic,
            daemonseed_core::identity::keys::Identity::Primary,
        )
        .ok()
        .map(|k| k.share_root_ikm)
    }

    /// (#232) The unlocked profile's STABLE ML-KEM-1024 **encapsulation** key — the
    /// public half of the identity KEM keypair, the same `derive_identity_keys`
    /// expansion behind [`Self::stable_signing_key`]. The net actor holds it so it
    /// can publish the DM key record (ISC-C40) that makes this identity reachable
    /// for direct messages. Only the public half is returned; the decapsulation key
    /// is dropped here, because nothing in the publish path needs it.
    pub fn stable_kem_encapsulation_key(
        &self,
    ) -> Option<daemonseed_core::dm::keyrec::KemEncapsulationKey> {
        let seeds = self.seeds.as_ref()?;
        daemonseed_core::identity::keys::derive_identity_keys(
            &seeds.mnemonic,
            daemonseed_core::identity::keys::Identity::Primary,
        )
        .ok()
        .map(|k| Box::new(*k.kem.encapsulation_key()))
    }

    /// Latest deprecation-warning rows (ISC-C25), for the Deprecation view. One
    /// row per in-use suite the verified policy schedules for retirement.
    pub fn deprecation_warnings(&self) -> &[DeprecationWarningRow] {
        &self.deprecation_warnings
    }

    /// Version of the last accepted deprecation policy (ISC-A-S11), for the
    /// Deprecation view header. `None` before any policy has been fetched.
    pub fn deprecation_policy_version(&self) -> Option<u64> {
        self.deprecation_policy_version
    }

    /// Whether the relay served a verified policy on the last successful fetch,
    /// for distinguishing "no policy configured" from "no in-use suite affected"
    /// in the Deprecation view's empty state.
    pub fn deprecation_had_policy(&self) -> bool {
        self.deprecation_had_policy
    }

    /// The selected deprecation-warning row index, for highlighting.
    pub fn dep_sel(&self) -> usize {
        self.dep_sel
    }

    /// Take a queued deprecation refresh request (drained once by the binary,
    /// which translates it into a `NetCommand::RefreshDeprecation`).
    pub fn take_pending_deprecation_refresh(&mut self) -> bool {
        std::mem::replace(&mut self.pending_deprecation_refresh, false)
    }

    /// Introducer-discovered candidate peers (M12 gate step 6, ISC-C22 /
    /// ISC-S6 / ISC-A-C19), each as a `(server_id, address)` pair, for the
    /// Servers pane's "Discovered (introducer)" sub-section. These are
    /// *candidates* only — known-of but never trusted or connectable until the
    /// user explicitly promotes one. Server-id + address only; no key material.
    pub fn discovered_peers(&self) -> &[(String, String)] {
        &self.discovered_peers
    }

    /// Take a queued introducer refresh request (drained once by the binary,
    /// which translates it into a `NetCommand::RefreshIntroducer`).
    pub fn take_pending_introducer_refresh(&mut self) -> bool {
        std::mem::replace(&mut self.pending_introducer_refresh, false)
    }

    /// @-mention autocomplete candidates for the current compose buffer
    /// (ISC-12 / C18). When composing and the buffer ends with a partial
    /// `@token` (no whitespace after the last `@`), returns the full wire
    /// handles of in-scope members whose friendly form prefix-matches the
    /// token — a bare `@` lists everyone in scope. Scope is the set of handles
    /// seen as chat senders (the relay never exposes a roster — ISC-A-S2), so
    /// autocomplete only knows who has spoken. Excludes the user's own handle
    /// and muted handles. Empty unless focus is Chat with a live `@token`.
    pub fn mention_autocomplete(&self) -> Vec<String> {
        if self.main_focus != MainFocus::Chat {
            return Vec::new();
        }
        let Some(at) = self.compose.rfind('@') else {
            return Vec::new();
        };
        let token = &self.compose[at + 1..];
        if token.contains(char::is_whitespace) {
            return Vec::new();
        }
        let own = self.own_handle();
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for m in &self.messages {
            if m.sender == own || self.muted.contains(&m.sender) || !seen.insert(&m.sender) {
                continue;
            }
            let Ok(handle) = m.sender.parse::<Handle>() else {
                continue;
            };
            let friendly = handle.format(DisplayMode::Default);
            if token.is_empty() || friendly.starts_with(token) {
                out.push(handle.to_string());
            }
        }
        out
    }

    /// Advance state in response to a key press.
    ///
    /// Only [`KeyEventKind::Press`] events drive state — `crossterm` on Windows
    /// also emits `Release` and `Repeat` events, which must not double-fire a
    /// transition.
    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        // A Transient trust toast auto-dismisses on the next interaction
        // (ISC-24 / C28 Transient class).
        self.transient = None;
        // A Blocking trust event captures all input on the main view until the
        // user acknowledges it (ISC-22 / C28 Blocking class — "prevents the
        // affected functional path until the user acts"). Acknowledgement
        // records a per-`(key, scope)` dismissal (ISC-A-C12).
        if self.screen == Screen::Main && self.blocking.is_some() {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                let item = self.blocking.take().expect("checked is_some");
                self.trust_log.dismiss(
                    item.key,
                    &DismissalScope {
                        server_id: item.server_id,
                        suite_id: None,
                    },
                    now_unix_ms(),
                );
            }
            return;
        }
        // The fetch overlay captures input next (ISC-19). It sits below the
        // Blocking modal in z-order — a security event always wins. Esc
        // cancels in flight, Enter dismisses a terminal state, other keys are
        // absorbed.
        if self.screen == Screen::Main && self.fetch.is_some() {
            self.on_key_fetch_overlay(key);
            return;
        }
        match self.screen {
            Screen::Welcome => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                KeyCode::Enter => {
                    self.first_start = Some(FirstStartUi::new(self.argon));
                    self.screen = Screen::FirstStart;
                }
                // Clean-device recovery (gate step 8): same FirstStart screen,
                // started on its recover branch. The completion path is shared.
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.first_start = Some(FirstStartUi::new_recovery(self.argon));
                    self.screen = Screen::FirstStart;
                }
                _ => {}
            },
            Screen::Unlock => self.on_key_unlock(key),
            Screen::LoggedInMenu => self.on_key_logged_in_menu(key),
            Screen::FirstStart => {
                if let Some(fs) = self.first_start.as_mut() {
                    match fs.on_key(key) {
                        Some(FirstStartOutcome::Completed) => {
                            let session = fs.take_completed();
                            // Queue a trusted-mode connect to the chosen bootstrap
                            // relay (C37 + C22 default-trusted for the canonical
                            // anchor). The binary drains this and drives the net actor.
                            if let Some(s) = session.as_ref() {
                                self.pending_connect = Some(ConnectRequest {
                                    server_id: s.bootstrap.server_id.clone(),
                                    address: s.bootstrap.address.clone(),
                                    trusted: true,
                                });
                                self.connection = ConnectionStatus::Connecting;
                                // Item D / ISC-C49/C50: ask the binary to persist
                                // the at-rest blob + `.dseed` to the profile root.
                                self.pending_persist = true;
                                // M13 write-through: hold the live payload + cached
                                // key so later mute/hide/name changes re-seal in
                                // place. The first-start blob was sealed before the
                                // display name was chosen; the binary persists the
                                // refreshed blob via the write-through below.
                                self.seeds = Some(s.seeds.clone());
                                self.seal_key = Some(s.seal_key.clone());
                                self.persist_seeds();
                            }
                            self.session = session;
                            self.first_start = None;
                            self.screen = Screen::Main;
                        }
                        Some(FirstStartOutcome::Cancelled) => {
                            self.first_start = None;
                            self.screen = Screen::Welcome;
                        }
                        None => {}
                    }
                }
            }
            Screen::Main => self.on_key_main(key),
        }
    }

    /// Key handling for the post-first-start main view: `Tab` toggles focus
    /// between the chat compose box and the circle-join box, `Esc` leaves to
    /// Welcome, and printable keys / Enter drive whichever input has focus.
    fn on_key_main(&mut self, key: KeyEvent) {
        // (#92) While the public-space composer is open, every key (incl. Esc/Tab)
        // belongs to it: Esc cancels the compose rather than opening the menu, and
        // chars/Enter drive the active field. Route before the global Esc/Tab so the
        // composer owns the keystream until it submits or cancels.
        if matches!(self.main_focus, MainFocus::PublicSpace)
            && self.compose_mode != PublicComposeMode::None
        {
            self.on_key_public_space(key);
            return;
        }
        match key.code {
            // Item E / ISC-A-C27: "back" never strands the user at the
            // enrollment wizard. Esc opens the logged-in menu (confirm
            // disconnect / quit), not Welcome → FirstStart.
            KeyCode::Esc => self.screen = Screen::LoggedInMenu,
            KeyCode::Tab => {
                self.main_focus = match self.main_focus {
                    MainFocus::Chat => MainFocus::JoinCircle,
                    MainFocus::JoinCircle => MainFocus::Mute,
                    MainFocus::Mute => MainFocus::Shares,
                    MainFocus::Shares => MainFocus::DefineShare,
                    MainFocus::DefineShare => MainFocus::Hide,
                    MainFocus::Hide => MainFocus::Servers,
                    MainFocus::Servers => MainFocus::TrustHistory,
                    MainFocus::TrustHistory => MainFocus::PublicSpace,
                    MainFocus::PublicSpace => MainFocus::Deprecation,
                    MainFocus::Deprecation => MainFocus::Fetched,
                    MainFocus::Fetched => MainFocus::Chat,
                };
                // ISC-C70: clear the one-shot status line on every focus change.
                // A transient status (e.g. "share added — indexing…") is tied to
                // the pane that produced it; once the user navigates away it is
                // stale, so it must not linger across the rest of the session.
                // Deterministic (focus-change, not a timer) so it never makes the
                // TUI tests flaky.
                self.status = None;
                // Opening the Shares pane requests a fresh snapshot — the
                // alpha gate harness drives this through `RefreshShares` so
                // the screen is never accidentally empty on first view.
                if matches!(self.main_focus, MainFocus::Shares | MainFocus::Hide) {
                    self.pending_share_refresh = true;
                }
                // Opening the Public Space pane likewise requests a fresh
                // snapshot, so the MOTD / announcements are never silently
                // empty on first view (`RefreshPublicSpace`).
                if matches!(self.main_focus, MainFocus::PublicSpace) {
                    self.pending_public_space_refresh = true;
                }
                // Opening the Deprecation pane requests a fresh policy fetch so
                // the warning rows reflect the live policy on first view
                // (`RefreshDeprecation`), never a stale or empty pane.
                if matches!(self.main_focus, MainFocus::Deprecation) {
                    self.pending_deprecation_refresh = true;
                }
                // Opening the Servers pane requests a fresh introducer-discovery
                // refresh so the "Discovered (introducer)" candidates reflect the
                // connected relay's current peer list on first view
                // (`RefreshIntroducer`, M12 gate step 6). Read-only: discovery
                // surfaces candidates, it never writes the trust set (ISC-A-C19).
                if matches!(self.main_focus, MainFocus::Servers) {
                    self.pending_introducer_refresh = true;
                }
                // Opening the Fetched pane requests a fresh downloads list so
                // the browse view reflects what is on disk (`ListFetched`,
                // M15 C; ISC-C64).
                if matches!(self.main_focus, MainFocus::Fetched) {
                    self.pending_fetched_refresh = true;
                }
            }
            _ => match self.main_focus {
                MainFocus::Chat => self.on_key_chat(key),
                MainFocus::JoinCircle => self.on_key_join(key),
                MainFocus::Mute => self.on_key_mute(key),
                MainFocus::Shares => self.on_key_shares(key),
                MainFocus::DefineShare => self.on_key_define_share(key),
                MainFocus::Hide => self.on_key_hide(key),
                MainFocus::Servers => self.on_key_servers(key),
                MainFocus::TrustHistory => self.on_key_history(key),
                MainFocus::PublicSpace => self.on_key_public_space(key),
                MainFocus::Deprecation => self.on_key_deprecation(key),
                MainFocus::Fetched => self.on_key_fetched(key),
            },
        }
    }

    /// Daily-login Unlock key handling (ISC-C3 / Item E). Printable chars build
    /// the passphrase, Backspace deletes, Enter queues a decrypt attempt for the
    /// binary, Esc quits (there is no enrollment wizard to fall back to — an
    /// existing profile means the only paths are unlock or quit; recovery is a
    /// separate, explicit launch). `[r]` jumps to clean-device recovery.
    fn on_key_unlock(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.should_quit = true,
            KeyCode::Char(c) => {
                self.unlock_input.push(c);
                self.unlock_error = None;
            }
            KeyCode::Backspace => {
                self.unlock_input.pop();
                self.unlock_error = None;
            }
            KeyCode::Enter if !self.unlock_input.is_empty() => {
                // Queue the passphrase for the binary to decrypt the on-disk
                // blob. App never touches the filesystem or runs Argon2.
                self.pending_unlock = Some(self.unlock_input.clone());
            }
            _ => {}
        }
    }

    /// Logged-in "back" menu key handling (Item E / ISC-A-C27). `Esc` returns to
    /// Main (a stray back never strands the user); `q` quits; `d` disconnects
    /// (drops to the Unlock screen for re-login, NOT the enrollment wizard).
    fn on_key_logged_in_menu(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Main,
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Char('d') | KeyCode::Char('D') => {
                // Disconnect → back to Unlock (re-login), never Welcome. The
                // session-scoped circle membership (ISC-C59) is dropped — circles
                // are re-entered each session (ISC-A-C2).
                self.connection = ConnectionStatus::Disconnected;
                self.circle_status = CircleStatus::NotJoined;
                self.circles.clear();
                self.active_circle = None;
                self.unlock_input.clear();
                self.unlock_error = None;
                self.screen = Screen::Unlock;
            }
            _ => {}
        }
    }

    /// Public-space pane key handling (read-only display, ISC-25 / ISC-S7).
    /// `Up` / `Down` move the announcement-post selection (clamped to the post
    /// list); `r` requests a fresh snapshot. No write affordances: the public
    /// space is a read surface for this client (publishing is operator-side).
    fn on_key_public_space(&mut self, key: KeyEvent) {
        match self.compose_mode {
            // Read-only display: Up/Down navigate posts, `r` refreshes, and (for a
            // signer only, ISC-S8 / D3) `m` / `a` open the composer.
            PublicComposeMode::None => match key.code {
                KeyCode::Up => self.post_sel = self.post_sel.saturating_sub(1),
                KeyCode::Down => {
                    let max = self.public_posts.len().saturating_sub(1);
                    if self.post_sel < max {
                        self.post_sel += 1;
                    }
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.pending_public_space_refresh = true;
                }
                // (#92) composer entry — gated on the signer verdict; ignored for a
                // non-signer so the pane stays read-only.
                KeyCode::Char('m') | KeyCode::Char('M') if self.can_compose => {
                    self.compose_motd.clear();
                    self.compose_mode = PublicComposeMode::Motd;
                }
                KeyCode::Char('a') | KeyCode::Char('A') if self.can_compose => {
                    self.compose_topic.clear();
                    self.compose_body.clear();
                    self.compose_mode = PublicComposeMode::Topic;
                }
                _ => {}
            },
            // MOTD entry — single line, plaintext (ISC-S9). The net actor / relay
            // enforce the plaintext rule; a rejection returns on the status line.
            PublicComposeMode::Motd => match key.code {
                KeyCode::Esc => {
                    self.compose_motd.clear();
                    self.compose_mode = PublicComposeMode::None;
                }
                KeyCode::Char(c) => self.compose_motd.push(c),
                KeyCode::Backspace => {
                    self.compose_motd.pop();
                }
                KeyCode::Enter if !self.compose_motd.is_empty() => {
                    self.pending_set_motd = Some(std::mem::take(&mut self.compose_motd));
                    self.compose_mode = PublicComposeMode::None;
                }
                _ => {}
            },
            // Announcement topic — Enter advances to the body field.
            PublicComposeMode::Topic => match key.code {
                KeyCode::Esc => {
                    self.compose_topic.clear();
                    self.compose_body.clear();
                    self.compose_mode = PublicComposeMode::None;
                }
                KeyCode::Char(c) => self.compose_topic.push(c),
                KeyCode::Backspace => {
                    self.compose_topic.pop();
                }
                KeyCode::Enter if !self.compose_topic.is_empty() => {
                    self.compose_mode = PublicComposeMode::Body;
                }
                _ => {}
            },
            // Announcement body — Enter signs+uploads the post (topic + body).
            PublicComposeMode::Body => match key.code {
                KeyCode::Esc => {
                    self.compose_topic.clear();
                    self.compose_body.clear();
                    self.compose_mode = PublicComposeMode::None;
                }
                KeyCode::Char(c) => self.compose_body.push(c),
                KeyCode::Backspace => {
                    self.compose_body.pop();
                }
                KeyCode::Enter if !self.compose_body.is_empty() => {
                    let topic = std::mem::take(&mut self.compose_topic);
                    let body = std::mem::take(&mut self.compose_body);
                    self.pending_upload_announcement = Some((topic, body));
                    self.compose_mode = PublicComposeMode::None;
                }
                _ => {}
            },
        }
    }

    /// Deprecation-pane key handling (read-only display, ISC-C25). `Up` / `Down`
    /// move the warning-row selection (clamped to the warning list); `r`
    /// requests a fresh policy fetch. No write affordances: the deprecation
    /// policy is operator-signed and the client only verifies and surfaces it —
    /// it never mutates suite state from here (ISC-A-C9 / ISC-A3).
    fn on_key_deprecation(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.dep_sel = self.dep_sel.saturating_sub(1),
            KeyCode::Down => {
                let max = self.deprecation_warnings.len().saturating_sub(1);
                if self.dep_sel < max {
                    self.dep_sel += 1;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.pending_deprecation_refresh = true;
            }
            _ => {}
        }
    }

    /// Shares-pane key handling (ISC-17 / ISC-20 / ISC-C69).
    ///
    /// `Up` / `Down` move the public-shares selection (clamped to the visible,
    /// hide-filtered subset so a hidden row can never be highlighted);
    /// `[` / `]` move the My-defined selection (M16 C1, ISC-C69, same
    /// saturating idiom as the other single-list panes); `r` requests a fresh
    /// snapshot; `f` initiates a fetch of the currently-selected public-share
    /// row (ISC-19, F23 unified mechanism); `p` / `u` publish /
    /// unpublish-or-cancel the selected defined share; `x` removes it
    /// (unpublishing/cancelling first and forgetting the persisted root, M16
    /// serve-from-disk). (`Up`/`Down` stay on public shares to keep the fetch
    /// flow's selector untouched; the defined-list cursor rides `[`/`]`.)
    fn on_key_shares(&mut self, key: KeyEvent) {
        let visible = self.visible_public_shares_count();
        match key.code {
            KeyCode::Up => {
                self.share_sel = self.share_sel.saturating_sub(1);
            }
            KeyCode::Down => {
                let max = visible.saturating_sub(1);
                if self.share_sel < max {
                    self.share_sel += 1;
                }
            }
            KeyCode::Char('[') => {
                self.defined_sel = self.defined_sel.saturating_sub(1);
                self.echo_defined_selection();
            }
            KeyCode::Char(']') => {
                let max = self.defined_shares.len().saturating_sub(1);
                if self.defined_sel < max {
                    self.defined_sel += 1;
                }
                self.echo_defined_selection();
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.pending_share_refresh = true;
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                // Publish the SELECTED defined share to the relay (M16 C1,
                // ISC-C69 — define several via DefineShare, select with `[`/`]`,
                // then `[p]`). Each published share serves on its own task.
                self.publish_selected_share();
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                // Unpublish the SELECTED defined share if it is currently served
                // (M16 C1, ISC-C69) — or cancel its in-flight publish hash (M16
                // serve-from-disk). Serving is session-scoped, so this is the
                // in-session "stop sharing"; quit / disconnect reaps everything
                // anyway. The binary forwards it as NetCommand::UnpublishShare /
                // NetCommand::CancelPublish; PublishStopped prunes `published`.
                self.unpublish_selected_share();
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                // Remove the SELECTED defined share entirely (M16
                // serve-from-disk): stop any publish stage in flight, drop it
                // from the My-defined list, and forget the persisted root so
                // it is not re-defined next launch.
                self.remove_selected_defined_share();
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                // Snapshot the selected visible row and start a fetch. A
                // hidden row cannot be selected (share_sel clamps to
                // visible_public_shares_count), so this never accidentally
                // initiates against something the user has hidden. Clone
                // the row's identifying fields out before mutating
                // `self.fetch` / `self.pending_share_fetch` so the borrow
                // from `visible_public_shares()` is dropped before either
                // write.
                let row = self
                    .visible_public_shares()
                    .get(self.share_sel)
                    .map(|r| (r.share_id.clone(), r.sharer_handle.clone(), r.name.clone()));
                if let Some((share_id, sharer_handle, name)) = row {
                    self.fetch = Some(FetchUi {
                        share_id: share_id.clone(),
                        sharer_handle: sharer_handle.clone(),
                        name: name.clone(),
                        status: FetchStatus::RequestingManifest,
                        total_chunks: None,
                        chunks_received: 0,
                        bytes_received: 0,
                        preview_checked: Vec::new(),
                        preview_cursor: 0,
                        preview_tree: Vec::new(),
                        preview_collapsed: Vec::new(),
                        preview_scroll: 0,
                        // A3: empty = the default downloads dir until the user
                        // sets one via `d` in the preview (ISC-C68).
                        dest: String::new(),
                        editing_dest: false,
                    });
                    self.pending_share_fetch = Some((share_id, sharer_handle, name));
                }
            }
            _ => {}
        }
    }

    /// Fetch-overlay key handling (ISC-19 / C66 / C67 / C68 / C72). The overlay
    /// captures input while the fetch is active. In `Preview` (now a collapsible
    /// folder tree, ISC-C72): `↑`/`↓` move the cursor over the *visible* rows,
    /// `→` expands a collapsed dir, `←` collapses an expanded dir (or jumps to
    /// the parent of a file / already-collapsed dir), `space` toggles selection
    /// of the cursor node (a file toggles itself, a dir toggles all files in its
    /// subtree), `a` toggles all (A2 selective fetch), `d` enters
    /// destination-edit mode (A3), `Enter` downloads the selected files, `Esc`
    /// cancels without downloading. While editing the destination (A3, ISC-C68),
    /// `Char`/`Backspace` edit the path and `Enter` or `Esc` exit edit mode back
    /// to the preview (no download); the A2 nav keys and the download-`Enter` are
    /// suppressed so typing a path can neither toggle a checkbox nor start the
    /// download. On a terminal state (Complete/Failed): either key dismisses.
    /// While chunks flow: `Esc` aborts (marks Failed). Other keys are absorbed so
    /// they cannot accidentally drive the background view.
    fn on_key_fetch_overlay(&mut self, key: KeyEvent) {
        let Some(f) = self.fetch.as_ref() else { return };
        let in_preview = matches!(f.status, FetchStatus::Preview(_));
        // A3: while editing the destination, all input routes to the `dest` field
        // and nothing toggles selection or starts a download (ISC-C68).
        let editing_dest = in_preview && f.editing_dest;
        if editing_dest {
            match key.code {
                KeyCode::Char(c) => {
                    if let Some(f) = self.fetch.as_mut() {
                        f.dest.push(c);
                    }
                }
                KeyCode::Backspace => {
                    if let Some(f) = self.fetch.as_mut() {
                        f.dest.pop();
                    }
                }
                // Leave edit mode (commit the typed path into `dest`); does NOT
                // trigger the download — that is a deliberate second `Enter`.
                KeyCode::Enter | KeyCode::Esc => {
                    if let Some(f) = self.fetch.as_mut() {
                        f.editing_dest = false;
                    }
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc => {
                // Preview-cancel and terminal-dismiss both just close the
                // overlay (no stream is held in Preview; the transfer is done
                // in a terminal state). An in-flight transfer is marked Failed
                // so the gauge shows the abort.
                let close = matches!(
                    f.status,
                    FetchStatus::Complete | FetchStatus::Failed(_) | FetchStatus::Preview(_)
                );
                if close {
                    self.fetch = None;
                } else if let Some(f) = self.fetch.as_mut() {
                    f.status = FetchStatus::Failed("cancelled by user".to_owned());
                }
            }
            // A2/C72 navigation over the *visible* tree rows (Preview only).
            KeyCode::Up | KeyCode::Down if in_preview => {
                if let Some(f) = self.fetch.as_mut() {
                    let visible_len = f.visible_rows().len();
                    match key.code {
                        KeyCode::Up => f.preview_cursor = f.preview_cursor.saturating_sub(1),
                        KeyCode::Down if f.preview_cursor + 1 < visible_len => {
                            f.preview_cursor += 1
                        }
                        _ => {}
                    }
                }
            }
            // C72: `→` expands a collapsed dir under the cursor (no-op otherwise).
            KeyCode::Right if in_preview => {
                if let Some(f) = self.fetch.as_mut() {
                    let visible = f.visible_rows();
                    if let Some(&node) = visible.get(f.preview_cursor)
                        && matches!(f.preview_tree[node].kind, PreviewKind::Dir { .. })
                        && f.preview_collapsed.get(node).copied().unwrap_or(false)
                    {
                        f.preview_collapsed[node] = false;
                    }
                }
            }
            // C72: `←` collapses an expanded dir under the cursor; on a file or
            // already-collapsed dir, move the cursor to the parent dir row.
            KeyCode::Left if in_preview => {
                if let Some(f) = self.fetch.as_mut() {
                    let visible = f.visible_rows();
                    if let Some(&node) = visible.get(f.preview_cursor) {
                        let is_expanded_dir =
                            matches!(f.preview_tree[node].kind, PreviewKind::Dir { .. })
                                && !f.preview_collapsed.get(node).copied().unwrap_or(false);
                        if is_expanded_dir {
                            f.preview_collapsed[node] = true;
                        } else {
                            // Move to the nearest visible ancestor (shallower
                            // depth above the cursor in the visible list).
                            let depth = f.preview_tree[node].depth;
                            if depth > 0
                                && let Some(parent_vis) = visible[..f.preview_cursor]
                                    .iter()
                                    .rposition(|&n| f.preview_tree[n].depth < depth)
                            {
                                f.preview_cursor = parent_vis;
                            }
                        }
                    }
                }
            }
            // C72: `space` toggles selection of the cursor NODE. A file toggles
            // its own checkbox; a dir toggles every file in its subtree — check
            // all if any are unchecked, else uncheck all.
            KeyCode::Char(' ') if in_preview => {
                if let Some(f) = self.fetch.as_mut() {
                    let visible = f.visible_rows();
                    if let Some(&node) = visible.get(f.preview_cursor) {
                        match f.preview_tree[node].kind {
                            PreviewKind::File { manifest_idx, .. } => {
                                if let Some(c) = f.preview_checked.get_mut(manifest_idx) {
                                    *c = !*c;
                                }
                            }
                            PreviewKind::Dir { subtree_end } => {
                                // Target: if any file under the dir is currently
                                // unchecked, set ALL on; else set all off.
                                let want = matches!(
                                    f.dir_selection(node),
                                    DirSelection::None | DirSelection::Partial
                                );
                                for n in node + 1..subtree_end {
                                    if let PreviewKind::File { manifest_idx, .. } =
                                        f.preview_tree[n].kind
                                        && let Some(c) = f.preview_checked.get_mut(manifest_idx)
                                    {
                                        *c = want;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') if in_preview => {
                if let Some(f) = self.fetch.as_mut() {
                    // Toggle all: if everything is currently selected, clear;
                    // otherwise select everything.
                    let all = !f.preview_checked.is_empty() && f.preview_checked.iter().all(|&c| c);
                    for c in f.preview_checked.iter_mut() {
                        *c = !all;
                    }
                }
            }
            // A3 (ISC-C68): enter destination-edit mode. The `editing_dest`
            // branch at the top of this fn then routes typed input into `dest`.
            KeyCode::Char('d') | KeyCode::Char('D') if in_preview => {
                if let Some(f) = self.fetch.as_mut() {
                    f.editing_dest = true;
                }
            }
            KeyCode::Enter => {
                // Decide with an immutable read, then apply. `Enter` in Preview
                // confirms the selected files (an all-selected set passes `None`
                // = confirm-all; a subset passes `Some(indices)`; an empty set
                // is ignored). On a terminal overlay it dismisses.
                let confirm = match &f.status {
                    FetchStatus::Preview(entries) => {
                        let selected: Vec<usize> = f
                            .preview_checked
                            .iter()
                            .enumerate()
                            .filter_map(|(i, &c)| c.then_some(i))
                            .collect();
                        if selected.is_empty() {
                            None
                        } else {
                            let all = selected.len() == entries.len();
                            // M16: the gauge total is CHUNKS over the selected
                            // set, not the file count — each entry contributes
                            // its chunk_count (0 for an empty file).
                            let total: u32 = selected
                                .iter()
                                .map(|&i| entries.get(i).map_or(0, |e| e.chunk_count))
                                .sum();
                            Some((
                                f.share_id.clone(),
                                f.sharer_handle.clone(),
                                f.name.clone(),
                                total,
                                if all { None } else { Some(selected) },
                                // A3 (ISC-C68): the chosen destination (empty =
                                // default downloads dir, resolved by the binary).
                                f.dest.clone(),
                            ))
                        }
                    }
                    _ => None,
                };
                let dismiss = matches!(f.status, FetchStatus::Complete | FetchStatus::Failed(_));
                if let Some((share_id, sharer_handle, name, total, selection, dest)) = confirm {
                    if let Some(f) = self.fetch.as_mut() {
                        f.total_chunks = Some(total);
                        f.chunks_received = 0;
                        f.bytes_received = 0;
                        f.status = FetchStatus::Receiving;
                    }
                    self.pending_fetch_confirm =
                        Some((share_id, sharer_handle, name, selection, dest));
                } else if dismiss {
                    self.fetch = None;
                }
            }
            _ => {}
        }
    }

    /// Hide-box key handling (ISC-18 / C16). Typing edits [`Self::hide_input`];
    /// Enter on a non-empty buffer toggles the handle in
    /// [`Self::hidden_shares`] (set membership), mirrors the change onto
    /// [`Self::seeds`], re-seals for the M13 write-through, then clears the input.
    /// On toggle, render-time filtering picks the change up immediately because
    /// [`Self::visible_public_shares`] reads [`Self::hidden_shares`] each time.
    fn on_key_hide(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.hide_input.push(c),
            KeyCode::Backspace => {
                self.hide_input.pop();
            }
            KeyCode::Enter if !self.hide_input.is_empty() => {
                let handle = std::mem::take(&mut self.hide_input);
                // Reject line-breaks for parity with `Seeds::add_hidden_share`
                // (blob-integrity guard); a well-formed wire handle never has
                // one, but a paste of "garbage\nmore" must not corrupt the
                // future seeds-blob round-trip.
                if handle.contains(['\n', '\r']) {
                    self.status = Some("hide handle rejected: line break".to_owned());
                    return;
                }
                // Toggle, keeping the live `Seeds` in lock-step (ISC-C16) so the
                // M13 write-through persists the change, then re-seal.
                if self.hidden_shares.remove(&handle) {
                    if let Some(seeds) = self.seeds.as_mut() {
                        seeds.remove_hidden_share(&handle);
                    }
                } else {
                    self.hidden_shares.insert(handle.clone());
                    if let Some(seeds) = self.seeds.as_mut() {
                        seeds.add_hidden_share(handle);
                    }
                }
                self.persist_seeds();
                // Re-clamp selection — the visible subset may have shrunk.
                let max = self.visible_public_shares_count().saturating_sub(1);
                if self.share_sel > max {
                    self.share_sel = max;
                }
            }
            _ => {}
        }
    }

    /// Whether a chat surface is joined, so chat can actually transmit. True when
    /// a public room (the default surface, ISC-S22 / ISC-C56) OR a circle (the
    /// private opt-in, ISC-14) is joined. Used to gate the compose box: with
    /// NEITHER joined, Enter is a no-op (Item F / ISC-C48 / A-C26) — no local
    /// echo, nothing transmitted.
    pub fn can_chat(&self) -> bool {
        self.public_room.is_some() || !self.circles.is_empty()
    }

    /// The surface a Chat-pane post will land on, or `None` when nothing is
    /// joined (Enter is then a no-op — Item F / A-C26).
    ///
    /// Precedence (ISC-C60): the *active* circle (the private opt-in, ISC-14)
    /// wins over the auto-joined lobby (the default, ISC-S22 / ISC-C56). The
    /// active circle is the `active_circle` index into [`Self::circles`]; with
    /// no circle selected the lobby is the active surface. This is the single
    /// source of truth for chat-surface routing — see [`ChatSurface`]. Both the
    /// Enter handler and the compose-box indicator resolve through it so they
    /// cannot disagree about where a message goes, nor which circle's key seals it
    /// (ISC-A-C30).
    pub fn active_chat_surface(&self) -> Option<ChatSurface> {
        if let Some(c) = self.active_circle_ref() {
            Some(ChatSurface::Circle {
                id: c.id,
                label: c.label.clone(),
            })
        } else {
            self.public_room
                .as_deref()
                .map(|room| ChatSurface::PublicRoom(room.to_owned()))
        }
    }

    /// The active circle (ISC-C60), if one is selected. `None` when the
    /// membership set is empty or the active surface is the lobby.
    fn active_circle_ref(&self) -> Option<&JoinedCircle> {
        self.active_circle.and_then(|i| self.circles.get(i))
    }

    /// The session-scoped circle membership set (ISC-C59), in join order, for
    /// the carousel render.
    pub fn circles(&self) -> &[JoinedCircle] {
        &self.circles
    }

    /// Test-only: the queued circle-rejoins not yet drained (M13, ISC-C59).
    #[cfg(test)]
    pub(crate) fn pending_joins_for_test(&self) -> &std::collections::VecDeque<String> {
        &self.pending_joins
    }

    /// Test-only: queue an auto-republish directly (publish-intent persistence).
    #[cfg(test)]
    pub(crate) fn push_pending_autopublish_for_test(
        &mut self,
        root: std::path::PathBuf,
        name: String,
    ) {
        self.pending_publishes.push_back((root, name));
    }

    /// The active-circle index into [`Self::circles`] (ISC-C60), or `None` when
    /// the lobby is active / the set is empty. For the carousel header
    /// ("circle N/M").
    pub fn active_circle_index(&self) -> Option<usize> {
        self.active_circle
    }

    /// The active circle's id + label (ISC-C60 / ISC-C62), for the circle-pane
    /// header and the compose indicator. `None` when the lobby is active.
    pub fn active_circle_label(&self) -> Option<(u64, &str)> {
        self.active_circle_ref().map(|c| (c.id, c.label.as_str()))
    }

    /// Cycle the active surface one step (ISC-C60: ←/→ in the circle pane).
    /// `forward` advances; `false` goes back. The carousel is
    /// `[lobby, circle₀, …, circleₙ₋₁]` — **position 0 is the lobby**
    /// (`active_circle == None`) and positions `1..=n` are the joined circles —
    /// so cycling always wraps back through the lobby (ISC-C56: the lobby is
    /// always reachable and postable), not just rotating among circles. A no-op
    /// when no circle is joined (the lobby is then the only surface). Cycling
    /// changes only the active selection — never the membership set — so it can
    /// never evict a circle (ISC-C59) and the next post seals under exactly the
    /// newly-active surface's key (ISC-A-C30).
    pub fn cycle_active_circle(&mut self, forward: bool) {
        let n = self.circles.len();
        if n == 0 {
            return;
        }
        // Map current selection → carousel position (0 = lobby), step with
        // wraparound over the n+1 positions, then map back (position 0 → lobby).
        let total = n + 1;
        let cur = self.active_circle.map_or(0, |i| i + 1);
        let next = if forward {
            (cur + 1) % total
        } else {
            (cur + total - 1) % total
        };
        self.active_circle = (next != 0).then(|| next - 1);
    }

    /// Chat compose: printable chars append, Backspace deletes, Enter sends a
    /// non-empty message (ISC-14 / ISC-S22 / Item F / ISC-C48 / A-C26).
    ///
    /// The target surface is resolved by [`App::active_chat_surface`]: a joined
    /// circle (the private opt-in, ISC-14) takes precedence over a joined public
    /// room (the default surface, ISC-S22 / ISC-C56, self-signed for provenance
    /// by the net actor, ISC-S24). Routing through that one resolver — rather
    /// than re-deciding precedence inline — is what keeps the compose-box
    /// indicator and this handler in agreement (the v0.15.1 fix: the inline
    /// check tested `public_room` first, so a post always went to the
    /// auto-joined lobby and a joined circle never received it).
    ///
    /// The author's own post is locally echoed because the relay never reflects
    /// a frame to its sender. With NEITHER a public room nor a circle joined,
    /// Enter is a strict no-op with a status hint — nothing is appended to the
    /// transcript and nothing is transmitted, so a draft can never masquerade as
    /// a sent message (no false "it sent", Item F). The compose buffer is left
    /// intact so the user's draft survives until they join a surface.
    fn on_key_chat(&mut self, key: KeyEvent) {
        match key.code {
            // ←/→ cycle the active circle (ISC-C60). Cycling changes only the
            // active selection (and thus the compose target + seal key), never
            // the membership set — a no-op when no circle is joined.
            KeyCode::Left => self.cycle_active_circle(false),
            KeyCode::Right => self.cycle_active_circle(true),
            KeyCode::Char(c) => self.compose.push(c),
            KeyCode::Backspace => {
                self.compose.pop();
            }
            KeyCode::Enter if !self.compose.is_empty() => {
                match self.active_chat_surface() {
                    Some(ChatSurface::Circle { id, .. }) => {
                        let body = std::mem::take(&mut self.compose);
                        let sender = self.own_handle();
                        // Local echo, tagged with the active circle's surface so
                        // it renders only in that circle's pane (ISC-A-C29). The
                        // relay never reflects a frame to its sender. A real
                        // `now_unix_ms()` (not the old 0) sorts it as the newest line
                        // under the #130 ordered-insert instead of the epoch-0 front.
                        self.push_message(
                            sender.clone(),
                            body.clone(),
                            crate::net::now_unix_ms(),
                            Surface::Circle(id),
                        );
                        // Seal under exactly the active circle's key (ISC-A-C30).
                        self.pending_chat = Some(ChatSend {
                            circle_id: id,
                            body,
                            sender_handle: sender,
                        });
                    }
                    Some(ChatSurface::PublicRoom(_)) => {
                        let body = std::mem::take(&mut self.compose);
                        let sender = self.own_handle();
                        // Local echo, Lobby-tagged (ISC-A-C29). The relay never
                        // reflects a frame to its sender. A real `now_unix_ms()` (not
                        // the old 0) sorts it as the newest line under the #130
                        // ordered-insert instead of the epoch-0 front.
                        self.push_message(
                            sender.clone(),
                            body.clone(),
                            crate::net::now_unix_ms(),
                            Surface::Lobby,
                        );
                        // Carry the name-bearing handle so the post reaches peers
                        // under the display name, not the floor (parity with the
                        // circle path's `sender_handle`).
                        self.pending_public_room = Some((body, sender));
                    }
                    None => {
                        // No surface to post to (Item F / A-C26): do not echo, do
                        // not transmit; leave the draft intact and surface the hint.
                        self.status = Some("join a public room or circle to chat".to_owned());
                    }
                }
            }
            _ => {}
        }
    }

    /// Circle-join input: printable chars append, Backspace deletes, Enter
    /// queues a join for a non-empty phrase and returns focus to chat
    /// (ISC-15/16).
    fn on_key_join(&mut self, key: KeyEvent) {
        // ISC-C71: Ctrl-G generates a strong circle phrase into the input. The
        // ≥128-bit circle-entropy floor (ISC-C9) is demanding to invent by hand,
        // so offer a diceware generator the user can accept; circle phrases are
        // shared out-of-band, so a generated one is fine. A 12-word BIP-39 diceware
        // phrase is ~132 bits, but a bare `generate_diceware(12)` draws WITH
        // replacement, so ~3% repeat a word and score below the 128-bit floor on the
        // distinct-word estimator — the join gate would then reject our own
        // "generated" phrase. `generate_circle_phrase` (the canonical core home,
        // shared with the GUI) rejection-samples until `is_circle_green`, so the
        // generated phrase always clears the same gate. Ctrl-G (not a bare letter —
        // those are typed into the phrase) so it does not collide with phrase entry.
        if key.code == KeyCode::Char('g')
            && key
                .modifiers
                .contains(ratatui::crossterm::event::KeyModifiers::CONTROL)
        {
            match strength::generate_circle_phrase() {
                Ok(phrase) => {
                    self.circle_phrase = phrase;
                    self.status = Some(
                        "generated a strong circle phrase — [Enter] to join, or edit it; share it \
                         with members out-of-band"
                            .to_owned(),
                    );
                }
                Err(e) => self.status = Some(format!("could not generate a phrase: {e}")),
            }
            return;
        }
        match key.code {
            KeyCode::Char(c) => self.circle_phrase.push(c),
            KeyCode::Backspace => {
                self.circle_phrase.pop();
            }
            KeyCode::Enter if !self.circle_phrase.is_empty() => {
                // ISC-C9: gate the join on circle-entropy strength. A weak shared
                // phrase is the circle's whole vulnerability, so a below-≥128-bit
                // estimate BLOCKS the join (caraka 2026-06-05, precautionary
                // default — Fork 4) rather than merely warning. The phrase is
                // deliberately kept (not drained) so the user can strengthen it in
                // place; the meter already shows them the gap.
                //
                // M15 (caraka 2026-06-05): the REAL ≥128-bit key-space gate, now
                // that `estimate_circle` (words + charset) can certify it —
                // replacing the M14 interim zxcvbn score-4 proxy that wrongly
                // accepted the public xkcd phrase.
                let est = strength::estimate_circle(&self.circle_phrase);
                if !est.is_circle_green() {
                    self.status = Some(
                        "circle phrase too weak — keep adding words or characters until the \
                         border turns green (need ≥128 bits, ISC-C9)"
                            .to_owned(),
                    );
                    return;
                }
                let phrase = std::mem::take(&mut self.circle_phrase);
                self.pending_join = Some(phrase);
                self.circle_status = CircleStatus::Joining;
                self.main_focus = MainFocus::Chat;
            }
            _ => {}
        }
    }

    /// Handle a key in the Define-Share box (M14, ISC-C21). Typing builds the
    /// buffer; Enter parses `path` (or `path|label`), validates the directory
    /// exists, and queues a [`ShareDefineRequest`] for the binary to turn into a
    /// `NetCommand::DefineShare`. A non-existent path keeps the buffer and shows
    /// a status so the user can correct the typo in place rather than silently
    /// indexing nothing.
    fn on_key_define_share(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.share_input.push(c),
            KeyCode::Backspace => {
                self.share_input.pop();
            }
            KeyCode::Enter if !self.share_input.trim().is_empty() => {
                let (path_part, label) = match self.share_input.split_once('|') {
                    Some((p, l)) => {
                        let l = l.trim();
                        (p.trim().to_owned(), (!l.is_empty()).then(|| l.to_owned()))
                    }
                    None => (self.share_input.trim().to_owned(), None),
                };
                let root = std::path::PathBuf::from(&path_part);
                if !root.is_dir() {
                    // Keep the buffer so the user can fix the path in place.
                    self.status = Some(format!("no such directory: {path_part}"));
                    return;
                }
                self.share_input.clear();
                // D3 write-through (ISC-C21): remember the root in the at-rest
                // blob so it re-indexes next launch — persistence of config, not
                // of shared content (no-client-history invariant holds). The
                // re-emit on Unlock goes through pending_share_defines, which
                // does NOT re-persist, so this is the only persist site.
                let root_str = root.to_string_lossy().into_owned();
                if let Some(seeds) = self.seeds.as_mut() {
                    seeds.add_share(root_str, label.clone());
                    self.persist_seeds();
                }
                // Append the defined root to the My-defined list (dedup by root)
                // so the Shares pane's `[p]`/`[u]` can publish/unpublish it
                // independently (M16 C1, ISC-C69 — define several, act per-share).
                let name = Self::share_display_name(&root, &label);
                self.push_defined_share(root.clone(), name);
                self.pending_share_define = Some(ShareDefineRequest { root, label });
                self.status = Some("share added — indexing… ([p] in Shares to publish)".to_owned());
                // Return to the My-shares view so the new root's indexer status
                // is visible immediately, and request a snapshot so the pane is
                // not stale on entry (the actor emits Indexing now, Ready after
                // the background scan).
                self.main_focus = MainFocus::Shares;
                self.pending_share_refresh = true;
            }
            _ => {}
        }
    }

    /// A share's display name: its label if set, else the directory's own name,
    /// else the path string (M15 cleanup — used for `[p]` publish + downloads).
    fn share_display_name(root: &std::path::Path, label: &Option<String>) -> String {
        label.clone().unwrap_or_else(|| {
            root.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.to_string_lossy().into_owned())
        })
    }

    /// Publish the **selected** defined share root to the relay (M16 C1,
    /// ISC-C69 — the Shares pane's `[p]` action). Define several, select with
    /// `[`/`]`, then `[p]`; each is served by its own session-scoped serve task.
    /// A no-op with a hint if nothing is defined yet. Idempotent per root
    /// (ISC-A-C34): a root that is already published — or already queued and
    /// not yet drained, or mid-hash on the net actor (M16 serve-from-disk) —
    /// is never re-queued; `[u]` first to re-publish. A failed publish never
    /// reaches `published` (and a root-carrying `PublishError` clears the
    /// hashing marker), so the guard stays open and `[p]` is retryable after
    /// a `PublishError`.
    fn publish_selected_share(&mut self) {
        let sharer_handle = self.own_handle();
        match self.selected_defined_share().cloned() {
            Some((root, name)) => {
                let already = self.published.iter().any(|p| p.root == root)
                    || self
                        .pending_publish
                        .as_ref()
                        .is_some_and(|r| r.root == root)
                    || self.hashing.contains(&root);
                if already {
                    self.status =
                        Some(format!("{name:?} is already published — [u] to stop first"));
                    return;
                }
                self.pending_publish = Some(PublishRequest {
                    root,
                    name,
                    sharer_handle,
                });
                self.status = Some("publishing…".to_owned());
            }
            None => {
                self.status = Some("define a share first (Tab → DefineShare), then [p]".to_owned());
            }
        }
    }

    /// Unpublish — or cancel the in-flight publish of — the selected defined
    /// share (M16 C1 / serve-from-disk, ISC-C69 — the Shares pane's `[u]`
    /// action). The selected defined share is matched by its root (the
    /// [`PublishedShare`] key, ISC-A-C34) — never by display-name string join,
    /// which would conflate distinct shares sharing a name.
    ///
    /// `[u]` resolves the publish lifecycle stage in priority order, earliest
    /// stage first (each stage is exclusive of the later ones):
    /// (a) queued but not yet drained by the binary → drop the request
    /// locally, nothing ever reached the net actor; (b) hashing in flight on
    /// the actor → queue a `CancelPublish` for the root; (c) published +
    /// served → the existing unpublish; (d) none of those → the existing
    /// hints.
    fn unpublish_selected_share(&mut self) {
        let Some((root, name)) = self.selected_defined_share().cloned() else {
            self.status = Some("nothing to unpublish".to_owned());
            return;
        };
        // (a) Still queued locally: dropping the request IS the cancel — the
        // binary never sees it, so no actor round-trip is needed.
        if self
            .pending_publish
            .as_ref()
            .is_some_and(|r| r.root == root)
        {
            self.pending_publish = None;
            self.status = Some("publish cancelled".to_owned());
            return;
        }
        // (b) Hashing on the net actor: ask it to stop (the PublishCancelled
        // event clears the hashing marker and words the outcome).
        if self.hashing.contains(&root) {
            self.pending_cancel_publish = Some(root);
            self.status = Some(format!("cancelling publish of {name:?}…"));
            return;
        }
        // (c) Published + served: the existing unpublish path.
        if let Some(id) = self
            .published
            .iter()
            .find(|p| p.root == root)
            .map(|p| p.share_id.clone())
        {
            self.pending_unpublish = Some(id);
            return;
        }
        // (d) Nothing in flight for this share.
        self.status = Some("selected share is not currently published".to_owned());
    }

    /// Remove the selected defined share (M16 serve-from-disk — the Shares
    /// pane's `[x]` action). Stops whatever publish stage is in flight for it
    /// first — drops an undrained [`PublishRequest`], queues a `CancelPublish`
    /// for an in-flight hash, queues the unpublish if it is served — then
    /// drops it from the My-defined list and forgets the persisted root
    /// ([`Seeds::remove_share`] + the M13 write-through), so it neither
    /// re-indexes nor reappears next launch. Removing config, not content:
    /// the directory on disk is untouched (and the no-client-history
    /// invariant is moot — a share root was never history). A no-op with a
    /// hint when nothing is defined.
    ///
    /// [`Seeds::remove_share`]: daemonseed_core::storage::seeds::Seeds::remove_share
    fn remove_selected_defined_share(&mut self) {
        let Some((root, name)) = self.selected_defined_share().cloned() else {
            self.status = Some("nothing to remove".to_owned());
            return;
        };
        // Stop any in-flight publish stage, mirroring the `[u]` priority
        // order — but fall through rather than return: the removal proceeds
        // regardless of which stage (if any) was live.
        if self
            .pending_publish
            .as_ref()
            .is_some_and(|r| r.root == root)
        {
            self.pending_publish = None;
        }
        if self.hashing.remove(&root) {
            self.pending_cancel_publish = Some(root.clone());
        }
        if let Some(id) = self
            .published
            .iter()
            .find(|p| p.root == root)
            .map(|p| p.share_id.clone())
        {
            self.pending_unpublish = Some(id);
        }
        self.defined_shares.retain(|(r, _)| r != &root);
        self.clamp_defined_sel();
        // Forget the persisted root (the inverse of the on_key_define_share
        // write-through, ISC-C21): keyed by the same string form `add_share`
        // stored, then re-sealed so the removal survives the session.
        if let Some(seeds) = self.seeds.as_mut() {
            seeds.remove_share(&root.to_string_lossy());
            self.persist_seeds();
        }
        self.status = Some(format!("removed {name:?}"));
    }

    /// Fetched-downloads pane key handling (M15 C; ISC-C64). A read-only browse
    /// pane — ↑/↓ scrolls the downloaded shares. The files already live on disk
    /// under their real names in each share's download folder (M15 cleanup: no
    /// extract step), so there is no input here. Refreshed when the pane opens
    /// (`ListFetched`).
    fn on_key_fetched(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => {
                self.fetched_sel = self.fetched_sel.saturating_sub(1);
            }
            KeyCode::Down if self.fetched_sel + 1 < self.fetched_shares.len() => {
                self.fetched_sel += 1;
            }
            _ => {}
        }
    }

    /// Mute input: printable chars append, Backspace deletes, Enter toggles the
    /// typed full wire handle in the client-local mute set (ISC-13). Muting is
    /// unilateral and silent — nothing is sent to the peer or relay (A-C3).
    fn on_key_mute(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.mute_input.push(c),
            KeyCode::Backspace => {
                self.mute_input.pop();
            }
            KeyCode::Enter if !self.mute_input.is_empty() => {
                let handle = std::mem::take(&mut self.mute_input);
                // Toggle: a second Enter on the same handle unmutes it. Keep the
                // live `Seeds` in lock-step (ISC-C15) so the M13 write-through
                // persists the change, then re-seal.
                if self.muted.remove(&handle) {
                    if let Some(seeds) = self.seeds.as_mut() {
                        seeds.remove_mute(&handle);
                    }
                } else {
                    self.muted.insert(handle.clone());
                    if let Some(seeds) = self.seeds.as_mut() {
                        seeds.add_mute(handle);
                    }
                }
                self.persist_seeds();
            }
            _ => {}
        }
    }

    /// Server-management screen (F22 / C22): printable chars build the
    /// add-server input; Enter either adds a server (when the input is
    /// non-empty, ISC-26) or connects to the selected one (when the input is
    /// empty); Up/Down moves the selection; Left/Right slides the selected
    /// server's trust mode (ISC-21/27). The trusted/untrusted slider and the
    /// connect both reuse the existing trust + connect plumbing.
    fn on_key_servers(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.server_input.push(c),
            KeyCode::Backspace => {
                self.server_input.pop();
            }
            KeyCode::Up => self.server_sel = self.server_sel.saturating_sub(1),
            KeyCode::Down if !self.servers.is_empty() => {
                self.server_sel = (self.server_sel + 1).min(self.servers.len() - 1);
            }
            // The trust slider (ISC-21/27): Left = untrusted, Right = trusted.
            KeyCode::Left => {
                if let Some(s) = self.servers.get_mut(self.server_sel) {
                    s.trusted = false;
                }
            }
            KeyCode::Right => {
                if let Some(s) = self.servers.get_mut(self.server_sel) {
                    s.trusted = true;
                }
            }
            KeyCode::Enter if !self.server_input.is_empty() => {
                // Add a server (ISC-26): `server-id@host:port`.
                let raw = std::mem::take(&mut self.server_input);
                match raw.split_once('@') {
                    Some((id, addr)) if !id.is_empty() && !addr.is_empty() => {
                        self.servers.push(ManagedServer {
                            server_id: id.to_owned(),
                            address: addr.to_owned(),
                            trusted: true, // default to trusted (TOFU); slider adjusts
                        });
                        self.server_sel = self.servers.len() - 1;
                    }
                    _ => {
                        self.status = Some("server format: <server-id>@<host:port>".to_owned());
                        self.server_input = raw; // keep what they typed to fix
                    }
                }
            }
            KeyCode::Enter => {
                // Empty input + a selected server → connect to it, reusing the
                // existing pending-connect path with the slider's trust mode.
                if let Some(s) = self.servers.get(self.server_sel) {
                    self.pending_connect = Some(ConnectRequest {
                        server_id: s.server_id.clone(),
                        address: s.address.clone(),
                        trusted: s.trusted,
                    });
                    self.connection = ConnectionStatus::Connecting;
                }
            }
            _ => {}
        }
    }

    /// Trust History view (ISC-25 / C28): Up/Down move the selection (rows render
    /// newest-first), Enter dismisses the selected event's affordance per
    /// `(key, scope)` (ISC-A-C12 — dismissal is scoped, never global, and never
    /// removes the log entry).
    fn on_key_history(&mut self, key: KeyEvent) {
        let rows = self.trust_log.len();
        match key.code {
            KeyCode::Up => self.history_sel = self.history_sel.saturating_sub(1),
            KeyCode::Down if rows > 0 => {
                self.history_sel = (self.history_sel + 1).min(rows - 1);
            }
            KeyCode::Enter if rows > 0 => {
                // Map the newest-first selection back to the log entry, then
                // release the immutable borrow before the mutable dismiss.
                let (dkey, scope) = {
                    let entries = self.trust_log.entries();
                    let idx = rows - 1 - self.history_sel.min(rows - 1);
                    let e = &entries[idx];
                    (
                        e.key,
                        DismissalScope {
                            server_id: e.server_id.clone(),
                            suite_id: e.suite_id,
                        },
                    )
                };
                self.trust_log.dismiss(dkey, &scope, now_unix_ms());
                self.persistent
                    .retain(|it| !(it.key == dkey && it.server_id == scope.server_id));
            }
            _ => {}
        }
    }
}

/// Wall-clock now in unix milliseconds, for trust-event log timestamps. The
/// Trust History view renders stable key strings, not raw timestamps, so this
/// does not affect render determinism.
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
    use ratatui::crossterm::event::{KeyCode, KeyEvent};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, ratatui::crossterm::event::KeyModifiers::NONE)
    }

    #[test]
    fn new_app_starts_on_welcome_and_running() {
        let app = App::new();
        assert_eq!(app.screen(), &Screen::Welcome);
        assert!(!app.should_quit());
    }

    #[test]
    fn q_on_welcome_quits() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Char('q')));
        assert!(app.should_quit(), "pressing q should request quit");
    }

    #[test]
    fn esc_on_welcome_quits() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Esc));
        assert!(app.should_quit(), "Esc on the landing screen should quit");
    }

    #[test]
    fn enter_on_welcome_advances_to_first_start() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.screen(), &Screen::FirstStart);
        assert!(!app.should_quit());
    }

    #[test]
    fn r_on_welcome_starts_recovery_branch() {
        let _ = oxicrypt_module::initialize();
        let mut app = App::new();
        app.on_key(press(KeyCode::Char('r')));
        assert_eq!(app.screen(), &Screen::FirstStart);
        assert_eq!(
            app.first_start().map(|f| f.step()),
            Some(crate::screens::first_start::FsStep::RecoverChoose),
            "r enters the recover branch, not cold enrollment"
        );
    }

    #[test]
    fn autopublish_is_gated_on_connection() {
        // Publish-intent persistence: an auto-republish queued on Unlock must NOT
        // drain while disconnected — publish needs a live session, and draining
        // early would storm PublishError. A fresh App starts Disconnected.
        let mut app = App::new();
        app.push_pending_autopublish_for_test(
            std::path::PathBuf::from("/srv/music"),
            "music".into(),
        );
        assert!(
            app.take_pending_autopublish().is_none(),
            "auto-republish must wait until connected+authed"
        );
        // (The connected-path drain calls own_handle(), which needs a wired
        // session, so the live republish is covered by smoke, not this unit.)
    }

    #[test]
    fn release_events_do_not_drive_state() {
        let mut app = App::new();
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            ratatui::crossterm::event::KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        app.on_key(release);
        assert!(!app.should_quit(), "key Release must not trigger quit");
    }

    #[test]
    fn full_first_start_flow_reaches_main_with_session() {
        let _ = oxicrypt_module::initialize();
        let fast = daemonseed_core::profile::config::ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let mut app = App::with_argon(fast);
        app.on_key(press(KeyCode::Enter)); // Welcome → FirstStart
        assert_eq!(app.screen(), &Screen::FirstStart);

        // Type a strong passphrase and seal.
        for ch in "correct horse battery staple table mountain".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = app
            .first_start()
            .and_then(|fs| fs.mnemonic())
            .expect("mnemonic shown")
            .to_string();
        app.on_key(press(KeyCode::Char('f'))); // [f] full re-type → VerifyRoundTrip
        for ch in phrase.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → DisplayName (default prefilled)
        app.on_key(press(KeyCode::Enter)); // accept name → Bootstrap
        for ch in "relay#aabbccddeeff@127.0.0.1:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // finalize → Main

        assert_eq!(app.screen(), &Screen::Main);
        assert!(
            app.has_session(),
            "completed first-start should stash session materials"
        );
        assert!(
            app.first_start().is_none(),
            "first-start component cleared on completion"
        );

        // Completing first-start queues a trusted-mode connect to the bootstrap
        // relay and shows Connecting until the net actor reports back.
        assert_eq!(app.connection(), &ConnectionStatus::Connecting);
        let req = app
            .take_pending_connect()
            .expect("connect queued on completion");
        assert_eq!(req.server_id, "relay#aabbccddeeff");
        assert_eq!(req.address, "127.0.0.1:443");
        assert!(req.trusted);
        assert!(
            app.take_pending_connect().is_none(),
            "connect handed off exactly once"
        );
    }

    #[test]
    fn net_event_connected_sets_connected_status() {
        let mut app = App::new();
        app.on_net_event(NetEvent::Connected {
            server: "relay#aabbccddeeff".to_owned(),
            version: "1.0".to_owned(),
            rotation_notice: None,
        });
        assert_eq!(
            app.connection(),
            &ConnectionStatus::Connected {
                server: "relay#aabbccddeeff".to_owned(),
                version: "1.0".to_owned(),
                rotation_notice: None,
            }
        );
    }

    #[test]
    fn net_event_failed_sets_failed_status() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ConnectFailed {
            message: "tcp connect refused".to_owned(),
        });
        assert_eq!(
            app.connection(),
            &ConnectionStatus::Failed("tcp connect refused".to_owned())
        );
    }

    #[test]
    fn cancelling_first_start_returns_to_welcome() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Enter)); // → FirstStart
        app.on_key(press(KeyCode::Esc)); // cancel
        assert_eq!(app.screen(), &Screen::Welcome);
        assert!(app.first_start().is_none());
    }

    // ── Main view: circle chat (ISC-10 / 14 / 15 / 16) ───────────────────

    /// Drive the full fast-Argon first-start flow to land on the Main view with
    /// session materials, so chat-behaviour tests start from a connected-style
    /// state. Mirrors `full_first_start_flow_reaches_main_with_session`.
    fn drive_to_main() -> App {
        let _ = oxicrypt_module::initialize();
        let fast = daemonseed_core::profile::config::ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let mut app = App::with_argon(fast);
        app.on_key(press(KeyCode::Enter)); // Welcome → FirstStart
        for ch in "correct horse battery staple table mountain".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = app
            .first_start()
            .and_then(|fs| fs.mnemonic())
            .expect("mnemonic shown")
            .to_string();
        app.on_key(press(KeyCode::Char('f'))); // [f] full re-type → VerifyRoundTrip
        for ch in phrase.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → DisplayName (default prefilled)
        app.on_key(press(KeyCode::Enter)); // accept → Bootstrap
        for ch in "relay#aabbccddeeff@127.0.0.1:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // finalize → Main
        // Drain the auto-queued bootstrap connect so it doesn't confuse tests.
        let _ = app.take_pending_connect();
        assert_eq!(app.screen(), &Screen::Main);
        app
    }

    /// Test helper: simulate the net actor confirming a circle join with a given
    /// id + a derived label, mirroring `NetEvent::CircleJoined`.
    fn join_circle(app: &mut App, id: u64) {
        app.on_net_event(NetEvent::CircleJoined {
            circle_id: id,
            label: format!("circle-{id}"),
            entropy: format!("entropy-{id}"),
        });
    }

    /// ISC-C56 regression: once circles are joined, the carousel must still be
    /// able to return to the lobby (`active_circle == None`) so the lobby stays
    /// the postable surface. Before the fix, `cycle_active_circle` rotated among
    /// circles only and the lobby became unreachable until disconnect — the
    /// compose box was locked onto circles.
    #[test]
    fn lobby_is_reachable_via_carousel_when_circles_joined() {
        let mut app = App::new();
        join_circle(&mut app, 1);
        join_circle(&mut app, 2);
        // The carousel is [lobby, circle₀, circle₁]; the last join is active.
        assert_eq!(app.active_circle_index(), Some(1));
        // Forward from the last circle wraps to the lobby (position 0).
        app.cycle_active_circle(true);
        assert_eq!(
            app.active_circle_index(),
            None,
            "cycling forward must reach the lobby, not skip it"
        );
        // Continue forward → first circle.
        app.cycle_active_circle(true);
        assert_eq!(app.active_circle_index(), Some(0));
        // Backward from the first circle also lands on the lobby.
        app.cycle_active_circle(false);
        assert_eq!(
            app.active_circle_index(),
            None,
            "cycling backward must also reach the lobby"
        );
        // Membership is never touched by cycling (ISC-C59).
        assert_eq!(app.circles().len(), 2);
    }

    #[test]
    fn chat_message_event_appends_to_transcript() {
        let mut app = App::new();
        join_circle(&mut app, 1);
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "otter#aabbccddeeff".to_owned(),
            body: "hello circle".to_owned(),
            sent_unix_ms: 7,
        });
        assert_eq!(app.messages().len(), 1);
        assert_eq!(app.messages()[0].sender, "otter#aabbccddeeff");
        assert_eq!(app.messages()[0].body, "hello circle");
    }

    #[test]
    fn circle_join_events_update_status() {
        let mut app = App::new();
        assert_eq!(app.circle_status(), &CircleStatus::NotJoined);
        join_circle(&mut app, 1);
        assert_eq!(app.circle_status(), &CircleStatus::Joined);
        app.on_net_event(NetEvent::CircleJoinFailed {
            message: "subscribe refused".to_owned(),
        });
        assert_eq!(
            app.circle_status(),
            &CircleStatus::Failed("subscribe refused".to_owned())
        );
    }

    #[test]
    fn tab_cycles_main_focus() {
        let mut app = drive_to_main();
        assert_eq!(app.main_focus(), MainFocus::Chat);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::JoinCircle);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Mute);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Shares);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Hide);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Servers);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::TrustHistory);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::PublicSpace);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Deprecation);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Fetched);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Chat);
    }

    /// ISC-C70 — a one-shot status line is cleared when the focus changes, so a
    /// transient message tied to one pane (e.g. "share added — indexing…") does
    /// not persist across navigation. Deterministic: keyed on the focus change,
    /// not a timer.
    #[test]
    fn focus_change_clears_one_shot_status() {
        let mut app = drive_to_main();
        app.set_status("share added — indexing…");
        assert!(app.status().is_some(), "status set");
        app.on_key(press(KeyCode::Tab)); // focus change
        assert!(
            app.status().is_none(),
            "a focus change must clear the one-shot status line"
        );
    }

    /// M15 C — opening the Fetched pane queues a downloads-list refresh so the
    /// browse view is never accidentally empty on first view (ISC-C64).
    #[test]
    fn fetched_pane_open_requests_refresh() {
        let mut app = drive_to_main();
        for _ in 0..10 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::Fetched);
        assert!(
            app.take_pending_fetched_refresh(),
            "opening Fetched should queue a ListFetched refresh"
        );
    }

    /// M15 C — a `FetchedShares` event populates the browse list (ISC-C64).
    #[test]
    fn fetched_shares_event_populates_list() {
        use daemonseed_core::storage::fetched::{FetchedFile, FetchedShare};
        let mut app = drive_to_main();
        let share = FetchedShare {
            share_id: "abc123".to_owned(),
            name: "docs".to_owned(),
            folder: "docs".to_owned(),
            files: vec![FetchedFile {
                rel_path: "a.txt".to_owned(),
                size: 5,
            }],
        };
        app.on_net_event(NetEvent::FetchedShares {
            shares: vec![share],
        });
        assert_eq!(app.fetched_shares().len(), 1);
        assert_eq!(app.fetched_shares()[0].name, "docs");
        assert_eq!(app.fetched_shares()[0].folder, "docs");
    }

    // ── M14 D1: Define-Share input box (ISC-C21) ─────────────────────────

    /// Tabbing to DefineShare, typing a valid directory (`path|label`) and
    /// pressing Enter queues a [`ShareDefineRequest`] and returns focus to the
    /// Shares view so the My-shares pane is visible.
    #[test]
    fn define_share_valid_dir_queues_request_and_returns_to_shares() {
        let mut app = drive_to_main();
        // Chat → JoinCircle → Mute → Shares → DefineShare
        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::DefineShare);

        let dir = std::env::temp_dir();
        let input = format!("{}|My Docs", dir.display());
        for ch in input.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        assert_eq!(app.main_focus(), MainFocus::Shares, "returns to My-shares");
        let req = app
            .take_pending_share_define()
            .expect("a valid dir queues a define request");
        assert!(req.root.is_dir());
        assert_eq!(req.label.as_deref(), Some("My Docs"));
        assert!(app.share_input().is_empty(), "buffer cleared on success");
        assert!(
            app.take_pending_share_define().is_none(),
            "request drained exactly once"
        );
    }

    /// A non-existent directory is rejected: no request is queued, the buffer is
    /// kept so the user can correct the typo in place, focus stays on the box,
    /// and a status explains the refusal (no silent empty index).
    #[test]
    fn define_share_rejects_nonexistent_dir_and_keeps_buffer() {
        let mut app = drive_to_main();
        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        let bogus = "/nonexistent/xyzzy-daemonseed-m14";
        for ch in bogus.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        assert!(
            app.take_pending_share_define().is_none(),
            "a bad path queues nothing"
        );
        assert_eq!(app.share_input(), bogus, "buffer kept to fix in place");
        assert_eq!(app.main_focus(), MainFocus::DefineShare, "stays on the box");
        assert!(app.status().is_some(), "a status explains the refusal");
    }

    // ── D (M15): TUI publish + serve + unpublish ─────────────────────────

    /// M15 cleanup: define a share, then `[p]` in the Shares pane publishes that
    /// defined root — no separate Publish pane, no re-typing the path.
    #[test]
    fn publish_p_publishes_the_defined_share() {
        let mut app = drive_to_main();
        // Define a share: Chat → JoinCircle → Mute → Shares → DefineShare.
        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        let dir = std::env::temp_dir();
        let input = format!("{}|My Share", dir.display());
        for ch in input.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        // Define returns to Shares and remembers the root.
        assert_eq!(app.main_focus(), MainFocus::Shares);
        let _ = app.take_pending_share_define();
        assert!(
            app.selected_defined_share().is_some(),
            "root remembered for [p]"
        );

        // [p] publishes the defined share.
        app.on_key(press(KeyCode::Char('p')));
        let req = app
            .take_pending_publish()
            .expect("[p] queues a publish of the defined share");
        assert!(req.root.is_dir());
        assert_eq!(req.name, "My Share");
        // The listing carries the publisher's handle so peers see the sharer's
        // name, not "(operator)" (M15 — completes the #6 passthrough).
        assert!(
            !req.sharer_handle.is_empty(),
            "publish carries the sharer handle"
        );
        assert!(
            app.take_pending_publish().is_none(),
            "request drained exactly once"
        );
    }

    /// `[p]` with nothing defined is a no-op that hints to define first.
    #[test]
    fn publish_p_without_a_defined_share_is_a_hint() {
        let mut app = drive_to_main();
        for _ in 0..3 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::Shares);
        app.on_key(press(KeyCode::Char('p')));
        assert!(
            app.take_pending_publish().is_none(),
            "nothing defined → nothing queued"
        );
        assert!(app.status().is_some(), "a hint explains define-first");
    }

    /// `PublishStarted` tracks the share; `[u]` on the matching selected defined
    /// share queues the unpublish; `PublishStopped` prunes it (M16 C1, ISC-C69).
    #[test]
    fn publish_lifecycle_tracks_and_unpublish_queues() {
        let mut app = drive_to_main();
        // Define a share so `[u]` has a selected defined share to act on. The
        // PublishStarted name must match the defined share's display name.
        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        let dir = std::env::temp_dir();
        let input = format!("{}|My Share", dir.display());
        for ch in input.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();
        assert_eq!(app.main_focus(), MainFocus::Shares);

        app.on_net_event(NetEvent::PublishStarted {
            share_id: "deadbeef".to_owned(),
            root: dir.clone(),
            name: "My Share".to_owned(),
            file_count: 3,
        });
        assert_eq!(app.published().len(), 1);
        assert_eq!(app.published()[0].share_id, "deadbeef");

        app.on_key(press(KeyCode::Char('u')));
        assert_eq!(
            app.take_pending_unpublish().as_deref(),
            Some("deadbeef"),
            "[u] queues an unpublish for the selected published share"
        );

        app.on_net_event(NetEvent::PublishStopped {
            share_id: "deadbeef".to_owned(),
        });
        assert!(
            app.published().is_empty(),
            "PublishStopped prunes the share"
        );
    }

    /// `[u]` with nothing defined is a no-op that sets an explanatory status.
    #[test]
    fn unpublish_with_nothing_published_is_a_noop() {
        let mut app = drive_to_main();
        for _ in 0..3 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::Shares);
        app.on_key(press(KeyCode::Char('u')));
        assert!(
            app.take_pending_unpublish().is_none(),
            "nothing to unpublish"
        );
        assert!(app.status().is_some());
    }

    // ── M16 C1: multi-share publish (ISC-C69) ────────────────────────────

    /// Define two distinct roots → both land in `defined_shares` (dedup by root);
    /// publishing each (simulated PublishStarted) → both tracked in `published`;
    /// `[u]` on the selected one removes only it.
    #[test]
    fn multi_share_define_publish_and_independent_unpublish() {
        let mut app = drive_to_main();

        // Two distinct real directories to define.
        let base = std::env::temp_dir();
        let dir_a = base.join("ds-m16-c1-share-a");
        let dir_b = base.join("ds-m16-c1-share-b");
        std::fs::create_dir_all(&dir_a).expect("mk dir a");
        std::fs::create_dir_all(&dir_b).expect("mk dir b");

        // Define share A.
        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        for ch in format!("{}|Share A", dir_a.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();

        // Define share B (Shares → DefineShare is one Tab).
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        for ch in format!("{}|Share B", dir_b.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();

        // Both defined; defining A again does not duplicate it.
        assert_eq!(app.defined_shares().len(), 2, "two distinct roots defined");
        app.on_key(press(KeyCode::Tab));
        for ch in format!("{}|Share A again", dir_a.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();
        assert_eq!(
            app.defined_shares().len(),
            2,
            "re-defining the same root does not duplicate"
        );

        // Publish both (simulate the relay's PublishStarted for each root).
        app.on_net_event(NetEvent::PublishStarted {
            share_id: "idA".to_owned(),
            root: dir_a.clone(),
            name: "Share A again".to_owned(),
            file_count: 1,
        });
        app.on_net_event(NetEvent::PublishStarted {
            share_id: "idB".to_owned(),
            root: dir_b.clone(),
            name: "Share B".to_owned(),
            file_count: 1,
        });
        assert_eq!(app.published().len(), 2, "both shares tracked as served");

        // Select B (`]`) and `[u]` it — only B's id is queued.
        app.on_key(press(KeyCode::Char(']')));
        assert_eq!(app.defined_sel(), 1, "`]` moves selection to B");
        app.on_key(press(KeyCode::Char('u')));
        assert_eq!(
            app.take_pending_unpublish().as_deref(),
            Some("idB"),
            "[u] on the selected share queues only that share's id"
        );
        app.on_net_event(NetEvent::PublishStopped {
            share_id: "idB".to_owned(),
        });
        assert_eq!(app.published().len(), 1, "only B unpublished");
        assert_eq!(app.published()[0].share_id, "idA", "A is still served");

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// `[p]` publishes the SELECTED defined share, not always the first (M16 C1).
    #[test]
    fn publish_p_acts_on_the_selected_defined_share() {
        let mut app = drive_to_main();
        let base = std::env::temp_dir();
        let dir_a = base.join("ds-m16-c1-sel-a");
        let dir_b = base.join("ds-m16-c1-sel-b");
        std::fs::create_dir_all(&dir_a).expect("mk dir a");
        std::fs::create_dir_all(&dir_b).expect("mk dir b");

        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        for ch in format!("{}|Alpha", dir_a.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();
        app.on_key(press(KeyCode::Tab));
        for ch in format!("{}|Beta", dir_b.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();

        // Select Beta and publish — the queued root is Beta's.
        app.on_key(press(KeyCode::Char(']')));
        app.on_key(press(KeyCode::Char('p')));
        let req = app
            .take_pending_publish()
            .expect("[p] queues a publish of the selected share");
        assert_eq!(req.name, "Beta", "publishes the selected, not the first");
        assert_eq!(req.root, dir_b);

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    // ── M16 smoke fixes: publish idempotency (ISC-A-C34) + `[`/`]` echo ──

    /// A second `[p]` on an already-published share is a status-hint no-op —
    /// both against a live `published` entry and against a still-queued
    /// in-flight request (ISC-A-C34).
    #[test]
    fn second_p_on_a_published_share_is_a_guarded_noop() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-ac34-guard");
        std::fs::create_dir_all(&dir).expect("mk dir");

        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        for ch in format!("{}|Guarded", dir.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();
        assert_eq!(app.main_focus(), MainFocus::Shares);

        // In-flight guard: a second [p] before the binary drains the first
        // request queues nothing new (the pending root matches).
        app.on_key(press(KeyCode::Char('p')));
        app.on_key(press(KeyCode::Char('p')));
        assert!(
            app.take_pending_publish().is_some(),
            "first [p] queued the publish"
        );
        assert!(
            app.take_pending_publish().is_none(),
            "second [p] while in-flight queued nothing"
        );

        // Published guard: once PublishStarted lands for the root, [p] is a
        // hint no-op until [u].
        app.on_net_event(NetEvent::PublishStarted {
            share_id: "id1".to_owned(),
            root: dir.clone(),
            name: "Guarded".to_owned(),
            file_count: 1,
        });
        app.on_key(press(KeyCode::Char('p')));
        assert!(
            app.take_pending_publish().is_none(),
            "[p] on a published share queues nothing (ISC-A-C34)"
        );
        assert!(
            app.status()
                .is_some_and(|s| s.contains("already published")),
            "the no-op explains itself"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed publish never reaches `published`, so the ISC-A-C34 guard
    /// stays open and `[p]` is retryable after a `PublishError`.
    #[test]
    fn p_is_retryable_after_a_publish_error() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-ac34-retry");
        std::fs::create_dir_all(&dir).expect("mk dir");

        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        for ch in format!("{}|Retry", dir.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();

        app.on_key(press(KeyCode::Char('p')));
        assert!(app.take_pending_publish().is_some(), "first attempt queued");
        app.on_net_event(NetEvent::PublishError {
            message: "publish refused: relay unreachable".to_owned(),
            root: Some(dir.clone()),
        });
        app.on_key(press(KeyCode::Char('p')));
        assert!(
            app.take_pending_publish().is_some(),
            "a failed publish leaves the guard open — [p] retryable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── M16 serve-from-disk: async publish hash + cancel + [x] remove ────

    /// Test helper: define a share named `label` rooted at a fresh temp dir
    /// and land back on the Shares pane. Returns the root. Mirrors the manual
    /// Tab-and-type dance the earlier publish tests spell out inline.
    fn define_share(app: &mut App, dir: &std::path::Path, label: &str) {
        std::fs::create_dir_all(dir).expect("mk share dir");
        while app.main_focus() != MainFocus::DefineShare {
            app.on_key(press(KeyCode::Tab));
        }
        for ch in format!("{}|{label}", dir.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();
        assert_eq!(app.main_focus(), MainFocus::Shares);
    }

    /// `PublishProgress` folds into a "hashing N/M — [u] cancels" status, and
    /// `[u]` during the hash queues a `CancelPublish` for that root (M16
    /// serve-from-disk) — never an unpublish (nothing is published yet).
    #[test]
    fn publish_progress_sets_status_and_u_queues_cancel() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-m16-hash-cancel");
        define_share(&mut app, &dir, "Hashing");

        // [p], drained by the binary — the hash is now the actor's.
        app.on_key(press(KeyCode::Char('p')));
        assert!(app.take_pending_publish().is_some(), "publish queued");
        app.on_net_event(NetEvent::PublishProgress {
            root: dir.clone(),
            name: "Hashing".to_owned(),
            done: 3,
            total: 10,
        });
        assert!(
            app.status()
                .is_some_and(|s| s.contains("hashing Hashing: 3/10 files") && s.contains("[u]")),
            "progress surfaces with the cancel affordance, got {:?}",
            app.status()
        );

        app.on_key(press(KeyCode::Char('u')));
        assert_eq!(
            app.take_pending_cancel_publish().as_deref(),
            Some(dir.as_path()),
            "[u] mid-hash queues a CancelPublish for the root"
        );
        assert!(
            app.take_pending_unpublish().is_none(),
            "nothing is published yet — no unpublish"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[u]` on a publish still queued locally (not yet drained by the binary)
    /// drops the request in place — no actor round-trip (M16, `[u]` priority
    /// stage (a)).
    #[test]
    fn u_drops_an_undrained_publish_request() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-m16-undrained-cancel");
        define_share(&mut app, &dir, "Queued");

        app.on_key(press(KeyCode::Char('p')));
        app.on_key(press(KeyCode::Char('u')));
        assert!(
            app.take_pending_publish().is_none(),
            "[u] dropped the undrained request"
        );
        assert!(
            app.take_pending_cancel_publish().is_none(),
            "nothing reached the actor — no CancelPublish needed"
        );
        assert!(
            app.status()
                .is_some_and(|s| s.contains("publish cancelled")),
            "the drop explains itself, got {:?}",
            app.status()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ISC-A-C34 `[p]` guard covers the hashing window: a second `[p]`
    /// while the hash runs queues nothing, and a `PublishCancelled` re-opens
    /// the guard so `[p]` retries (M16 serve-from-disk).
    #[test]
    fn p_guard_covers_the_hashing_window() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-m16-hash-guard");
        define_share(&mut app, &dir, "Guarded");

        app.on_key(press(KeyCode::Char('p')));
        assert!(app.take_pending_publish().is_some(), "first [p] queued");
        app.on_net_event(NetEvent::PublishProgress {
            root: dir.clone(),
            name: "Guarded".to_owned(),
            done: 1,
            total: 4,
        });
        app.on_key(press(KeyCode::Char('p')));
        assert!(
            app.take_pending_publish().is_none(),
            "[p] mid-hash queues nothing (ISC-A-C34 extended)"
        );
        assert!(
            app.status()
                .is_some_and(|s| s.contains("already published")),
            "the no-op explains itself"
        );

        // The cancel lands → the guard re-opens.
        app.on_net_event(NetEvent::PublishCancelled {
            root: dir.clone(),
            name: "Guarded".to_owned(),
        });
        assert!(
            app.status().is_some_and(|s| s.contains("cancelled")),
            "a cancel is worded neutrally, got {:?}",
            app.status()
        );
        app.on_key(press(KeyCode::Char('p')));
        assert!(
            app.take_pending_publish().is_some(),
            "after a cancel, [p] re-publishes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[x]` removes the selected defined share: queues the unpublish for a
    /// served share, drops the defined row, and persists the removal via the
    /// M13 write-through so the root is not re-defined next launch (M16
    /// serve-from-disk).
    #[test]
    fn x_removes_unpublishes_and_persists_the_removal() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-m16-x-remove");
        define_share(&mut app, &dir, "Removable");
        // Drain the define's own write-through so the next blob update is
        // unambiguously the removal's.
        assert!(
            app.take_pending_blob_update().is_some(),
            "define persisted the root"
        );

        app.on_net_event(NetEvent::PublishStarted {
            share_id: "idX".to_owned(),
            root: dir.clone(),
            name: "Removable".to_owned(),
            file_count: 2,
        });

        app.on_key(press(KeyCode::Char('x')));
        assert_eq!(
            app.take_pending_unpublish().as_deref(),
            Some("idX"),
            "[x] on a served share queues the unpublish first"
        );
        assert!(
            app.defined_shares().is_empty(),
            "the defined row is dropped"
        );
        assert!(
            app.take_pending_blob_update().is_some(),
            "the removal is persisted (write-through re-seal queued)"
        );
        assert!(
            app.status().is_some_and(|s| s.contains("removed")),
            "[x] confirms the removal, got {:?}",
            app.status()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[x]` mid-hash cancels the in-flight publish too: the CancelPublish is
    /// queued alongside the removal (M16 serve-from-disk).
    #[test]
    fn x_mid_hash_cancels_the_publish_too() {
        let mut app = drive_to_main();
        let dir = std::env::temp_dir().join("ds-m16-x-mid-hash");
        define_share(&mut app, &dir, "MidHash");

        app.on_key(press(KeyCode::Char('p')));
        assert!(app.take_pending_publish().is_some(), "publish drained");
        app.on_net_event(NetEvent::PublishProgress {
            root: dir.clone(),
            name: "MidHash".to_owned(),
            done: 1,
            total: 9,
        });

        app.on_key(press(KeyCode::Char('x')));
        assert_eq!(
            app.take_pending_cancel_publish().as_deref(),
            Some(dir.as_path()),
            "[x] mid-hash queues the CancelPublish"
        );
        assert!(app.defined_shares().is_empty(), "row dropped regardless");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `[x]` with nothing defined is a no-op that explains itself.
    #[test]
    fn x_with_nothing_defined_is_a_hint() {
        let mut app = drive_to_main();
        for _ in 0..3 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::Shares);
        app.on_key(press(KeyCode::Char('x')));
        assert!(app.take_pending_unpublish().is_none());
        assert!(app.take_pending_cancel_publish().is_none());
        assert!(
            app.status()
                .is_some_and(|s| s.contains("nothing to remove")),
            "the no-op explains itself"
        );
    }

    /// `[`/`]` echo the My-defined selection on the status line (M16 smoke
    /// fix) — live smoke showed the split-cursor scheme gave no feedback at
    /// all when the user reached for the wrong keys.
    #[test]
    fn bracket_keys_echo_the_defined_selection() {
        let mut app = drive_to_main();
        let base = std::env::temp_dir();
        let dir_a = base.join("ds-echo-a");
        let dir_b = base.join("ds-echo-b");
        std::fs::create_dir_all(&dir_a).expect("mk dir a");
        std::fs::create_dir_all(&dir_b).expect("mk dir b");

        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        for ch in format!("{}|First", dir_a.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();
        app.on_key(press(KeyCode::Tab));
        for ch in format!("{}|Second", dir_b.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let _ = app.take_pending_share_define();

        app.on_key(press(KeyCode::Char(']')));
        assert!(
            app.status()
                .is_some_and(|s| s.contains("2/2") && s.contains("Second")),
            "`]` echoes the new selection, got {:?}",
            app.status()
        );
        app.on_key(press(KeyCode::Char('[')));
        assert!(
            app.status()
                .is_some_and(|s| s.contains("1/2") && s.contains("First")),
            "`[` echoes the new selection, got {:?}",
            app.status()
        );

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// On Unlock, ALL persisted roots are restored into `defined_shares` (M16 C1,
    /// ISC-C69) — not just the last — each re-emitted for re-indexing.
    #[test]
    fn unlock_restores_all_persisted_roots_into_defined_shares() {
        let _ = oxicrypt_module::initialize();
        let mut materials = drive_to_main().session_take_for_test();
        materials
            .seeds
            .add_share("/data/alpha", Some("Alpha".to_owned()));
        materials
            .seeds
            .add_share("/data/beta", Some("Beta".to_owned()));

        let mut app = App::new();
        app.on_unlock_success(materials);

        // Both restored into the My-defined list, in order.
        assert_eq!(
            app.defined_shares().len(),
            2,
            "every persisted root restored, not just the last"
        );
        assert_eq!(app.defined_shares()[0].1, "Alpha");
        assert_eq!(app.defined_shares()[1].1, "Beta");

        // And both re-emitted as DefineShare for re-indexing.
        let first = app.take_pending_share_define().expect("first re-emitted");
        assert_eq!(first.root, std::path::PathBuf::from("/data/alpha"));
        let second = app.take_pending_share_define().expect("second re-emitted");
        assert_eq!(second.root, std::path::PathBuf::from("/data/beta"));
        assert!(
            app.take_pending_share_define().is_none(),
            "exactly the two persisted roots replayed"
        );
    }

    // ── C28 trust-event affordance routing (ISC-22..25 / 28) ─────────────

    /// A Blocking trust event populates the modal slot, captures input until
    /// acknowledged, and Enter records a dismissal without removing the log
    /// entry (ISC-22 / A-C12).
    #[test]
    fn blocking_trust_event_modal_captures_then_dismisses() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyMismatch,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert!(
            app.blocking_trust().is_some(),
            "blocking modal set (ISC-22)"
        );
        // While the modal is up, a chat keystroke must NOT compose.
        app.on_key(press(KeyCode::Char('x')));
        assert_eq!(app.compose(), "", "modal captures input until acknowledged");
        assert!(app.blocking_trust().is_some(), "non-ack key keeps modal up");
        // Enter acknowledges and clears the modal; the log entry survives.
        app.on_key(press(KeyCode::Enter));
        assert!(app.blocking_trust().is_none(), "Enter dismisses the modal");
        assert_eq!(app.trust_log().len(), 1, "dismissal keeps the log entry");
        assert!(
            app.trust_log().entries()[0].dismissed_at_unix_ms.is_some(),
            "entry marked dismissed"
        );
    }

    /// A PersistentNonBlocking event appears as a status badge and is logged
    /// (ISC-23).
    #[test]
    fn persistent_trust_event_badges_and_logs() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert_eq!(app.persistent_trust().len(), 1, "badge surfaced (ISC-23)");
        assert_eq!(app.trust_log().len(), 1, "persistent event is logged");
        // The same event again does not duplicate the badge.
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert_eq!(app.persistent_trust().len(), 1, "no duplicate badge");
    }

    /// A Transient event is a toast that is NOT logged (the A-C12 asymmetry) and
    /// auto-dismisses on the next key press (ISC-24).
    #[test]
    fn transient_trust_event_toasts_then_clears_and_is_not_logged() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ConnectionRateLimited,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert!(app.transient_trust().is_some(), "toast surfaced (ISC-24)");
        assert_eq!(app.trust_log().len(), 0, "transient is not logged (A-C12)");
        app.on_key(press(KeyCode::Char('a')));
        assert!(
            app.transient_trust().is_none(),
            "toast auto-dismisses on key"
        );
    }

    /// A LogOnly event surfaces only in the audit log — no modal, badge, or toast
    /// (ISC-25, the Trust History surface).
    #[test]
    fn logonly_trust_event_only_in_history() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerSourceUnverified,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert!(app.blocking_trust().is_none());
        assert!(app.persistent_trust().is_empty());
        assert!(app.transient_trust().is_none());
        assert_eq!(
            app.trust_log().len(),
            1,
            "recorded in Trust History (ISC-25)"
        );
    }

    /// A ConnectionClosed event records its observable close layer (ISC-28).
    #[test]
    fn connection_closed_sets_close_cause() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ConnectionClosed {
            cause: CloseCause::RefusedBeforeHelloAck,
        });
        assert_eq!(app.close_cause(), Some(CloseCause::RefusedBeforeHelloAck));
    }

    /// Trust History selection moves with Up/Down and Enter dismisses the
    /// selected event's persistent badge per scope (ISC-25 / A-C12).
    #[test]
    fn trust_history_enter_dismisses_selected_persistent_badge() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert_eq!(app.persistent_trust().len(), 1);
        // Tab to the Trust History view and dismiss the selected (only) row.
        app.on_key(press(KeyCode::Tab)); // → JoinCircle
        app.on_key(press(KeyCode::Tab)); // → Mute
        app.on_key(press(KeyCode::Tab)); // → Shares
        app.on_key(press(KeyCode::Tab)); // → DefineShare
        app.on_key(press(KeyCode::Tab)); // → Hide
        app.on_key(press(KeyCode::Tab)); // → Servers
        app.on_key(press(KeyCode::Tab)); // → TrustHistory
        assert_eq!(app.main_focus(), MainFocus::TrustHistory);
        app.on_key(press(KeyCode::Enter));
        assert!(
            app.persistent_trust().is_empty(),
            "dismissing clears the badge"
        );
        assert_eq!(app.trust_log().len(), 1, "log entry survives dismissal");
    }

    // ── C28 render paths (ISC-22..25 / 28), real ui::render via TestBackend ──

    fn render_text(app: &App, w: u16, h: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::render(app, f)).unwrap();
        buffer_text(&term)
    }

    /// ISC-22: a Blocking trust event renders as a modal overlay.
    #[test]
    fn blocking_trust_renders_modal() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyMismatch,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        let text = render_text(&app, 80, 24);
        assert!(text.contains("security warning"), "modal title rendered");
        assert!(
            text.contains("Server key does not match"),
            "modal body rendered"
        );
    }

    /// ISC-23: a PersistentNonBlocking event renders as a status-bar badge.
    #[test]
    fn persistent_trust_renders_status_badge() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        let text = render_text(&app, 120, 24);
        assert!(
            text.contains("server-key-rotated"),
            "badge rendered in status"
        );
    }

    /// ISC-24: a Transient event renders as a toast.
    #[test]
    fn transient_trust_renders_toast() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ConnectionRateLimited,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        let text = render_text(&app, 80, 24);
        assert!(text.contains("backing off"), "toast rendered");
    }

    /// ISC-25: a LogOnly event renders in the scrollable Trust History view.
    #[test]
    fn logonly_trust_renders_in_history_view() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerSourceUnverified,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        // Tab to the Trust History view (7 hops past Chat → … → TrustHistory).
        for _ in 0..7 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::TrustHistory);
        let text = render_text(&app, 80, 24);
        assert!(text.contains("trust history"), "history view titled");
        assert!(
            text.contains("server-source-unverified"),
            "LogOnly event listed (ISC-25)"
        );
    }

    /// ISC-28: each of the three close-cause layers renders a distinct message.
    #[test]
    fn close_cause_renders_three_distinct_states() {
        let causes = [
            (CloseCause::NetworkFailure, "Unable to reach server"),
            (
                CloseCause::RefusedBeforeHelloAck,
                "Server refused the connection",
            ),
            (
                CloseCause::ClosedAfterAuth,
                "Server closed the connection unexpectedly",
            ),
        ];
        for (cause, msg) in causes {
            let mut app = drive_to_main();
            app.on_net_event(NetEvent::ConnectionClosed { cause });
            let text = render_text(&app, 120, 24);
            assert!(text.contains(msg), "{cause:?} renders its distinct message");
        }
    }

    #[test]
    fn composing_and_sending_queues_chat_and_local_echoes() {
        let mut app = drive_to_main();
        // A joined circle is the private opt-in; with one joined (and no public
        // room), Enter posts to the circle.
        join_circle(&mut app, 1);
        for ch in "hi there".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        assert_eq!(app.compose(), "hi there");
        app.on_key(press(KeyCode::Enter));
        // Compose cleared, message locally echoed, send queued exactly once.
        assert_eq!(app.compose(), "");
        assert_eq!(app.messages().len(), 1, "sender sees their own message");
        assert_eq!(app.messages()[0].body, "hi there");
        let send = app.take_pending_chat().expect("chat queued on Enter");
        assert_eq!(send.body, "hi there");
        assert!(!send.sender_handle.is_empty());
        assert!(app.take_pending_chat().is_none(), "queued exactly once");
    }

    /// ISC-S22 / ISC-C56: the DEFAULT chat surface is a public room. With a
    /// public room joined and NO circle, Enter posts to the public room (queued
    /// for self-signing by the net actor) and locally echoes.
    #[test]
    fn composing_posts_to_public_room_by_default() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        assert_eq!(app.public_room(), Some("lobby"));
        for ch in "hello lobby".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.compose(), "");
        assert_eq!(app.messages().len(), 1, "sender sees their own post");
        assert_eq!(app.messages()[0].body, "hello lobby");
        // The body is queued for the public-room send path; no circle chat queued.
        assert!(app.take_pending_chat().is_none(), "not a circle send");
        let (body, sender_handle) = app
            .take_pending_public_room()
            .expect("public-room post queued on Enter");
        assert_eq!(body, "hello lobby");
        // The post carries the poster's own (name-bearing) handle so peers see
        // the display name, not the floor (parity with the circle path).
        assert!(!sender_handle.is_empty(), "post carries the sender handle");
        assert!(
            app.take_pending_public_room().is_none(),
            "queued exactly once"
        );
    }

    /// Regression (v0.15.1): with BOTH a public room AND a circle joined, a post
    /// lands in the joined circle (the private opt-in), NOT the auto-joined
    /// lobby. The shipped bug checked `public_room` first, so once the net actor
    /// auto-joined the lobby on connect, every post went to the lobby and a
    /// joined circle was unpostable. The prior circle test never set a public
    /// room, so it could not catch this — this is the both-surfaces-joined case.
    #[test]
    fn circle_takes_precedence_over_public_room_when_both_joined() {
        let mut app = drive_to_main();
        // The net actor auto-joins the lobby on connect …
        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        // … then the user opts into a circle.
        join_circle(&mut app, 1);
        assert_eq!(app.public_room(), Some("lobby"));
        assert_eq!(app.circle_status(), &CircleStatus::Joined);
        assert_eq!(
            app.active_chat_surface(),
            Some(ChatSurface::Circle {
                id: 1,
                label: "circle-1".to_owned()
            }),
            "a joined circle takes precedence over the auto-joined lobby"
        );

        for ch in "circle only".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        assert_eq!(app.compose(), "");
        assert_eq!(app.messages().len(), 1, "echoed once");
        assert_eq!(app.messages()[0].body, "circle only");
        // Routed to the circle send path …
        let send = app.take_pending_chat().expect("post routed to the circle");
        assert_eq!(send.body, "circle only");
        // … and NOT to the public room (the v0.15.1 bug).
        assert!(
            app.take_pending_public_room().is_none(),
            "must NOT post to the auto-joined lobby when a circle is joined"
        );
    }

    /// The surface resolver reflects the documented precedence at every state:
    /// none joined → `None`; only a public room → that room; a joined circle
    /// always wins. This pins the single source of truth the indicator and the
    /// Enter handler both consume.
    #[test]
    fn active_chat_surface_resolves_by_precedence() {
        let mut app = drive_to_main();
        assert_eq!(app.active_chat_surface(), None, "nothing joined");

        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        assert_eq!(
            app.active_chat_surface(),
            Some(ChatSurface::PublicRoom("lobby".to_owned())),
            "only a public room joined"
        );

        join_circle(&mut app, 1);
        assert_eq!(
            app.active_chat_surface(),
            Some(ChatSurface::Circle {
                id: 1,
                label: "circle-1".to_owned()
            }),
            "circle wins once joined"
        );
    }

    // ── Multi-circle carousel (ISC-C59..C62 / A-C29 / A-C30) ─────────────────

    /// ISC-C59: joining a second circle ADDS to the membership set; it never
    /// evicts the first. Both remain joined, in join order, and the newest is
    /// selected active.
    #[test]
    fn joining_second_circle_does_not_evict_first() {
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        assert_eq!(app.circles().len(), 1);
        assert_eq!(app.active_circle_index(), Some(0));

        join_circle(&mut app, 2);
        assert_eq!(app.circles().len(), 2, "second join ADDS, never evicts");
        assert_eq!(app.circles()[0].id, 1, "first circle still present");
        assert_eq!(app.circles()[1].id, 2, "second circle appended");
        assert_eq!(
            app.active_circle_index(),
            Some(1),
            "the newly-joined circle is selected active (ISC-C60)"
        );
    }

    /// ISC-C59: an idempotent re-join (the net actor re-emits an id already in
    /// the set) does not duplicate the membership; it only re-selects it active.
    #[test]
    fn rejoining_existing_circle_is_idempotent() {
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        join_circle(&mut app, 2);
        assert_eq!(app.active_circle_index(), Some(1));
        // Re-emit circle 1 (a re-join of an already-joined circle).
        join_circle(&mut app, 1);
        assert_eq!(app.circles().len(), 2, "no duplicate membership");
        assert_eq!(
            app.active_circle_index(),
            Some(0),
            "re-join re-selects the existing circle active"
        );
    }

    /// ISC-C60 / ISC-C56: cycling the active surface follows the carousel
    /// `[lobby, circle₀, …]` — the compose target (and thus the `SendChat` seal
    /// id) tracks it, and the lobby is ALWAYS a carousel position so it stays
    /// reachable and postable, never skipped in favour of circles-only rotation.
    #[test]
    fn cycling_active_circle_changes_compose_target() {
        let mut app = drive_to_main();
        // Join the lobby (the default public room) so it is a real postable
        // surface, then three circles. Carousel becomes [lobby, c10, c20, c30].
        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        join_circle(&mut app, 10);
        join_circle(&mut app, 20);
        join_circle(&mut app, 30);
        // Active is the last-joined (id 30).
        assert_eq!(
            app.active_chat_surface(),
            Some(ChatSurface::Circle {
                id: 30,
                label: "circle-30".to_owned()
            })
        );
        // → from the last circle wraps to the LOBBY (carousel position 0) —
        // always reachable (ISC-C56) — not straight to the first circle.
        app.on_key(press(KeyCode::Right));
        assert!(
            matches!(app.active_chat_surface(), Some(ChatSurface::PublicRoom(_))),
            "→ from the last circle lands on the lobby"
        );
        assert_eq!(app.active_circle_index(), None);
        // → again advances to the first circle.
        app.on_key(press(KeyCode::Right));
        assert!(matches!(
            app.active_chat_surface(),
            Some(ChatSurface::Circle { id: 10, .. })
        ));
        // ← from the first circle returns to the lobby.
        app.on_key(press(KeyCode::Left));
        assert!(
            matches!(app.active_chat_surface(), Some(ChatSurface::PublicRoom(_))),
            "← from the first circle returns to the lobby"
        );
        // ← from the lobby wraps to the last circle (id 30).
        app.on_key(press(KeyCode::Left));
        assert!(matches!(
            app.active_chat_surface(),
            Some(ChatSurface::Circle { id: 30, .. })
        ));
    }

    /// ISC-A-C30: a composed post seals under EXACTLY the active circle's id —
    /// never another circle's. Cycling the carousel then composing changes the
    /// `SendChat` target id accordingly.
    #[test]
    fn post_seals_under_active_circle_id_only() {
        let mut app = drive_to_main();
        join_circle(&mut app, 7);
        join_circle(&mut app, 8); // active = 8
        for ch in "to eight".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let send = app.take_pending_chat().expect("queued");
        assert_eq!(send.circle_id, 8, "sealed under the active circle only");
        assert_eq!(send.body, "to eight");

        // Cycle to circle 7 and post again — the seal id follows the carousel.
        app.on_key(press(KeyCode::Left)); // 8 → 7
        for ch in "to seven".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        let send = app.take_pending_chat().expect("queued");
        assert_eq!(
            send.circle_id, 7,
            "now sealed under the newly-active circle"
        );
        assert_eq!(send.body, "to seven");
    }

    /// ISC-A-C29: a message received on circle A renders ONLY in circle A's pane.
    /// The per-surface filter keys strictly on the line's `surface` tag, so a
    /// circle-A line never appears under circle B or the lobby.
    #[test]
    fn inbound_message_renders_only_in_its_own_surface() {
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        join_circle(&mut app, 2);
        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        // A message on circle 1, a message on circle 2, and a lobby message.
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "a#aabbccddeeff".to_owned(),
            body: "only-in-one".to_owned(),
            sent_unix_ms: 1,
        });
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 2,
            sender: "b#ccddeeff0011".to_owned(),
            body: "only-in-two".to_owned(),
            sent_unix_ms: 2,
        });
        app.on_net_event(NetEvent::PublicRoomMessage {
            room: "lobby".to_owned(),
            sender: "c#eeff00112233".to_owned(),
            body: "only-in-lobby".to_owned(),
            sent_unix_ms: 3,
        });

        let circle1: Vec<&str> = app
            .messages_on(Surface::Circle(1))
            .map(|m| m.body.as_str())
            .collect();
        let circle2: Vec<&str> = app
            .messages_on(Surface::Circle(2))
            .map(|m| m.body.as_str())
            .collect();
        let lobby: Vec<&str> = app
            .messages_on(Surface::Lobby)
            .map(|m| m.body.as_str())
            .collect();

        assert_eq!(
            circle1,
            vec!["only-in-one"],
            "circle 1 pane is exactly its line"
        );
        assert_eq!(
            circle2,
            vec!["only-in-two"],
            "circle 2 pane is exactly its line"
        );
        assert_eq!(
            lobby,
            vec!["only-in-lobby"],
            "lobby pane is exactly its line"
        );
        // No cross-surface bleed.
        assert!(!circle1.contains(&"only-in-two"));
        assert!(!circle1.contains(&"only-in-lobby"));
        assert!(!lobby.contains(&"only-in-one"));
    }

    /// ISC-A-C30: an inbound frame attributed to a circle NOT in the membership
    /// set is dropped — never re-attributed to another pane or the lobby.
    #[test]
    fn inbound_for_unknown_circle_is_dropped() {
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 99, // not joined
            sender: "ghost#aabbccddeeff".to_owned(),
            body: "from nowhere".to_owned(),
            sent_unix_ms: 1,
        });
        assert!(app.messages().is_empty(), "unknown-circle frame dropped");
    }

    /// #130: the transcript de-dups an exactly-repeated swept line and inserts
    /// out-of-order arrivals chronologically (TUI parity with the GUI `push_message`).
    #[test]
    fn transcript_dedups_and_orders_by_sent_unix_ms() {
        // #131: now-relative timestamps so they're INSIDE the ordering window
        // (unclamped) and exercise real chronological ordering.
        let now = crate::net::now_unix_ms();
        let mut app = drive_to_main();
        // Arrive out of send order on the lobby surface.
        app.on_net_event(NetEvent::PublicRoomMessage {
            room: "lobby".to_owned(),
            sender: "a#aabbccddeeff".to_owned(),
            body: "second".to_owned(),
            sent_unix_ms: now - 1000,
        });
        app.on_net_event(NetEvent::PublicRoomMessage {
            room: "lobby".to_owned(),
            sender: "a#aabbccddeeff".to_owned(),
            body: "first".to_owned(),
            sent_unix_ms: now - 2000,
        });
        // A DHT re-sweep re-delivers an already-seen line verbatim.
        app.on_net_event(NetEvent::PublicRoomMessage {
            room: "lobby".to_owned(),
            sender: "a#aabbccddeeff".to_owned(),
            body: "second".to_owned(),
            sent_unix_ms: now - 1000,
        });
        let lobby: Vec<&str> = app
            .messages_on(Surface::Lobby)
            .map(|m| m.body.as_str())
            .collect();
        assert_eq!(
            lobby,
            vec!["first", "second"],
            "ordered by sent_unix_ms with the re-swept duplicate coalesced"
        );
    }

    /// ISC-C61: the split chat view renders both panes with correct per-surface
    /// filtering — the lobby pane shows the lobby line, the active-circle pane
    /// shows the active circle's line and its carousel header, and neither bleeds
    /// into the other.
    #[test]
    fn split_view_renders_both_panes_with_correct_filtering() {
        let mut app = drive_to_main();
        let _ = app.take_pending_persist();
        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        join_circle(&mut app, 1);
        join_circle(&mut app, 2); // active = circle 2 (index 1 → "2/2")
        app.on_net_event(NetEvent::PublicRoomMessage {
            room: "lobby".to_owned(),
            sender: "c#eeff00112233".to_owned(),
            body: "LOBBYLINE".to_owned(),
            sent_unix_ms: 1,
        });
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 2,
            sender: "b#ccddeeff0011".to_owned(),
            body: "CIRCLELINE".to_owned(),
            sent_unix_ms: 2,
        });
        // A line on the NON-active circle 1 must not show in the circle pane.
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "a#aabbccddeeff".to_owned(),
            body: "HIDDENLINE".to_owned(),
            sent_unix_ms: 3,
        });

        let text = render_text(&app, 100, 30);
        assert!(text.contains("LOBBYLINE"), "lobby pane renders its line");
        assert!(
            text.contains("CIRCLELINE"),
            "active-circle pane renders its line"
        );
        assert!(
            !text.contains("HIDDENLINE"),
            "non-active circle's line is not rendered in the circle pane (ISC-A-C29)"
        );
        // Carousel header names label + position (ISC-C60 / ISC-C62).
        assert!(
            text.contains("circle 2/2: circle-2"),
            "circle pane header names the active label + carousel position"
        );
    }

    /// PRD item F position: with NEITHER a public room nor a circle joined, Enter
    /// is a no-op — nothing echoed, nothing transmitted (no false "it sent").
    #[test]
    fn enter_with_no_surface_does_not_echo_or_transmit() {
        let mut app = drive_to_main();
        for ch in "into the void".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.messages().is_empty(), "no local echo without a surface");
        assert!(app.take_pending_chat().is_none(), "no circle send");
        assert!(app.take_pending_public_room().is_none(), "no room post");
    }

    #[test]
    fn empty_compose_enter_is_a_noop() {
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        app.on_key(press(KeyCode::Enter));
        assert!(app.messages().is_empty(), "no empty message echoed");
        assert!(app.take_pending_chat().is_none(), "no empty send queued");
    }

    // ── Item F / ISC-C48 / A-C26: no false local echo with no circle ─────

    /// With no circle joined, pressing Enter on a non-empty compose buffer is a
    /// strict no-op: nothing is appended to the transcript and nothing is
    /// queued for transmission (ISC-A-C26). The draft is preserved.
    #[test]
    fn enter_with_no_circle_does_not_echo_or_transmit() {
        let mut app = drive_to_main();
        assert_eq!(app.circle_status(), &CircleStatus::NotJoined);
        for ch in "did this send?".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(
            app.messages().is_empty(),
            "no false local echo with no circle joined (ISC-A-C26)"
        );
        assert!(
            app.take_pending_chat().is_none(),
            "nothing transmitted with no circle joined (ISC-A-C26)"
        );
        assert_eq!(
            app.compose(),
            "did this send?",
            "draft preserved — Enter was a no-op, not a clear"
        );
        assert_eq!(app.status(), Some("join a public room or circle to chat"));
    }

    /// After joining a circle, the same Enter now echoes and transmits — the
    /// gate is the circle membership, not the keystroke (ISC-C48).
    #[test]
    fn enter_after_joining_circle_echoes_and_transmits() {
        let mut app = drive_to_main();
        for ch in "hello".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // no circle → no-op
        assert!(app.messages().is_empty());
        join_circle(&mut app, 1);
        assert!(app.can_chat());
        app.on_key(press(KeyCode::Enter)); // now sends the preserved draft
        assert_eq!(app.messages().len(), 1, "echoed after joining");
        assert_eq!(app.messages()[0].body, "hello");
        assert!(
            app.take_pending_chat().is_some(),
            "transmitted after joining"
        );
    }

    /// A strong circle phrase — 34 distinct characters, ≈173 key-space bits —
    /// used by join tests that must clear the ISC-C9 ≥128-bit floor
    /// (`App::on_key_join`). The public xkcd 4-word phrase is blocked, by design.
    const STRONG_CIRCLE_PHRASE: &str = "x7Qk!9zR2m@Lp4wV6sT1bN8dF3hJ5cG0aY";

    #[test]
    fn joining_a_circle_queues_phrase_and_marks_joining() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Tab)); // focus → JoinCircle
        for ch in STRONG_CIRCLE_PHRASE.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        assert_eq!(app.circle_phrase(), STRONG_CIRCLE_PHRASE);
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.circle_status(), &CircleStatus::Joining);
        assert_eq!(app.main_focus(), MainFocus::Chat, "focus returns to chat");
        let phrase = app.take_pending_join().expect("join queued");
        assert_eq!(phrase, STRONG_CIRCLE_PHRASE);
        assert_eq!(app.circle_phrase(), "", "phrase buffer cleared");
        assert!(app.take_pending_join().is_none(), "queued exactly once");
    }

    /// ISC-C9 / Fork 4 — a weak circle phrase is BLOCKED at Enter: no join is
    /// queued, the status explains, and the phrase is kept (not drained) so the
    /// user can strengthen it in place. M15: the gate is the real ≥128-bit
    /// key-space floor (`estimate_circle`); `password123` is ≈36 bits.
    #[test]
    fn weak_circle_phrase_is_blocked_at_join() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Tab)); // focus → JoinCircle
        for ch in "password123".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(
            app.take_pending_join().is_none(),
            "weak phrase must not queue a join"
        );
        assert_eq!(
            app.circle_status(),
            &CircleStatus::NotJoined,
            "no join attempt is marked"
        );
        assert_eq!(
            app.circle_phrase(),
            "password123",
            "phrase kept so the user can strengthen it"
        );
        assert!(app.status().is_some_and(|s| s.contains("too weak")));
    }

    /// ISC-C71 — Ctrl-G in the circle-join box fills the input with a generated
    /// phrase that clears the ISC-C9 circle-entropy floor (`is_circle_green`), so
    /// the user can accept a strong phrase instead of inventing ≥128-bit entropy.
    #[test]
    fn ctrl_g_generates_a_phrase_that_clears_the_circle_floor() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Tab)); // focus → JoinCircle
        assert!(app.circle_phrase().is_empty(), "buffer starts empty");
        let ctrl_g = KeyEvent::new(
            KeyCode::Char('g'),
            ratatui::crossterm::event::KeyModifiers::CONTROL,
        );
        // Batch the floor check: a bare `generate_diceware(12)` is ~3% flaky (a
        // duplicate word drops the distinct-word estimate below 128 bits), which a
        // single draw can hide. 64 samples make a regression to the bare generator
        // practically certain to surface. The fix routes Ctrl-G through the
        // rejection-sampling `strength::generate_circle_phrase`.
        let mut phrase = String::new();
        for _ in 0..64 {
            app.on_key(ctrl_g);
            phrase = app.circle_phrase().to_owned();
            assert!(!phrase.is_empty(), "Ctrl-G fills the join buffer");
            assert!(
                daemonseed_core::passphrase::strength::estimate_circle(&phrase).is_circle_green(),
                "the generated phrase {phrase:?} must clear the ISC-C9 ≥128-bit circle floor"
            );
        }
        // And it must actually join: a generated phrase passes the on-Enter gate.
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.circle_status(), &CircleStatus::Joining);
        assert_eq!(
            app.take_pending_join().as_deref(),
            Some(phrase.as_str()),
            "the generated phrase is what gets queued for join"
        );
    }

    /// The circle-phrase strength accessor (ISC-C9 meter) reflects the live buffer:
    /// the strong phrase clears the ≥128-bit floor, an empty/weak one does not.
    #[test]
    fn circle_phrase_strength_tracks_the_buffer() {
        let mut app = drive_to_main();
        assert!(
            !app.circle_phrase_strength().is_circle_green(),
            "empty phrase is not strong"
        );
        app.on_key(press(KeyCode::Tab)); // focus → JoinCircle
        for ch in STRONG_CIRCLE_PHRASE.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        assert!(app.circle_phrase_strength().is_circle_green());
    }

    /// ISC-C62 — a joined circle exposes a relay-independent `#<hash-of-entropy>`
    /// fingerprint for future GUI verification, while its visible `label` stays the
    /// human-readable seed name (caraka 2026-06-05: hash coded but unsurfaced).
    #[test]
    fn joined_circle_exposes_hidden_fingerprint() {
        let mut app = drive_to_main(); // initializes the crypto backend
        join_circle(&mut app, 1);
        let c = &app.circles()[0];
        let fp = c.fingerprint();
        assert!(fp.starts_with('#'), "fingerprint is #-prefixed: {fp}");
        assert!(fp.len() > 1, "fingerprint has a hash body: {fp}");
        assert_ne!(
            c.label, fp,
            "the visible label is the seed name, not the hash"
        );
        // Deterministic: same entropy → same fingerprint (the verification check).
        assert_eq!(fp, c.fingerprint());
    }

    #[test]
    fn chat_error_event_sets_status_line() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ChatError {
            message: "join a circle before sending".to_owned(),
        });
        assert_eq!(app.status(), Some("join a circle before sending"));
    }

    /// Flatten a TestBackend buffer to a string for `.contains` assertions.
    fn buffer_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    /// The Main view actually renders (real render path via TestBackend): a
    /// folded chat message appears in the transcript, and the compose footer is
    /// shown. Catches layout panics on a realistic terminal size too.
    #[test]
    fn main_view_renders_chat_transcript_and_compose() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = drive_to_main();
        app.on_net_event(NetEvent::Connected {
            server: "relay#aabbccddeeff".to_owned(),
            version: "1.0".to_owned(),
            rotation_notice: None,
        });
        join_circle(&mut app, 1);
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "otter".to_owned(),
            body: "ping".to_owned(),
            sent_unix_ms: 1,
        });

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);

        assert!(text.contains("otter: ping"), "transcript line rendered");
        assert!(text.contains("circle joined"), "circle status shown");
        assert!(text.contains("compose"), "compose footer shown");
    }

    /// v0.15.1 surface indicator: the compose footer names where Enter posts,
    /// and it tracks the same precedence as the handler — a joined circle shows
    /// the circle, the lobby-only case shows the public room. Rendered through
    /// the real `ui::render` path so the indicator is verified end-to-end.
    #[test]
    fn compose_indicator_names_the_active_surface() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        // Only the lobby joined → indicator names the public room.
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::PublicRoomJoined {
            room: "lobby".to_owned(),
        });
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        assert!(
            buffer_text(&term).contains("# lobby (public)"),
            "lobby-only compose footer names the public room"
        );

        // Joining a circle flips the indicator to the circle (it takes precedence).
        join_circle(&mut app, 1);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);
        // The footer names the circle. (A wide emoji's trailing skip-cell flattens
        // to an extra space in TestBackend, so match up to the glyph, not past it —
        // a real terminal renders `compose → 🔒 circle`.)
        assert!(
            text.contains("compose → 🔒"),
            "circle-joined compose footer names the circle"
        );
        assert!(
            !text.contains("# lobby (public)"),
            "indicator must not still claim the lobby once a circle is joined"
        );
    }

    // ── @mention (ISC-11/12) + mute (ISC-13) ─────────────────────────────

    #[test]
    fn muting_a_handle_toggles() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // JoinCircle → Mute
        assert_eq!(app.main_focus(), MainFocus::Mute);
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.is_muted("spammer#aabbccddeeff"), "muted after toggle");
        // Re-typing the same handle and Enter unmutes (toggle).
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(
            !app.is_muted("spammer#aabbccddeeff"),
            "unmuted on re-toggle"
        );
    }

    // ── M13 write-through (ISC-C15 / C16 / C4b persistence) ──────────────

    /// The fast-Argon params + passphrase `drive_to_main` enrolls under, so a
    /// test can open the re-sealed blob the write-through queues.
    const WT_PASSPHRASE: &str = "correct horse battery staple table mountain";
    fn wt_params() -> daemonseed_core::profile::config::ArgonParams {
        daemonseed_core::profile::config::ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Muting a handle in a running app re-seals the at-rest blob: the queued
    /// `pending_blob_update` bytes open under the enrollment passphrase + params
    /// and carry the mute (ISC-C15 persistence via the M13 write-through).
    #[test]
    fn muting_queues_a_blob_update_that_persists_the_mute() {
        use daemonseed_core::storage::seeds;

        let mut app = drive_to_main();
        let pid = app
            .session()
            .expect("session present")
            .profile_config
            .profile_id;

        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // JoinCircle → Mute
        assert_eq!(app.main_focus(), MainFocus::Mute);
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        // The live Seeds reflects the mutation immediately.
        assert!(
            app.seeds
                .as_ref()
                .expect("seeds present")
                .is_muted("spammer#aabbccddeeff"),
            "live seeds carries the mute"
        );

        // The binary would write these bytes over seeds.blob; opening them under
        // the same passphrase/params recovers the mute.
        let bytes = app
            .take_pending_blob_update()
            .expect("a mute queues a blob re-seal");
        let recovered = seeds::open(&bytes, WT_PASSPHRASE, pid, wt_params())
            .expect("re-sealed blob opens")
            .seeds;
        assert!(
            recovered.is_muted("spammer#aabbccddeeff"),
            "persisted blob carries the mute"
        );
        // Drained exactly once.
        assert!(app.take_pending_blob_update().is_none());
    }

    /// Hiding a sharer's shares re-seals the blob and the queued bytes carry the
    /// hide on re-open (ISC-C16 persistence via the M13 write-through).
    #[test]
    fn hiding_queues_a_blob_update_that_persists_the_hide() {
        use daemonseed_core::storage::seeds;

        let mut app = drive_to_main();
        let pid = app
            .session()
            .expect("session present")
            .profile_config
            .profile_id;

        // Tab Chat → JoinCircle → Mute → Shares → DefineShare → Hide.
        for _ in 0..5 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::Hide);
        for ch in "noisy#0a0b0c0d0e0f".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        assert!(
            app.seeds
                .as_ref()
                .expect("seeds present")
                .is_share_hidden("noisy#0a0b0c0d0e0f"),
            "live seeds carries the hide"
        );
        let bytes = app
            .take_pending_blob_update()
            .expect("a hide queues a blob re-seal");
        let recovered = seeds::open(&bytes, WT_PASSPHRASE, pid, wt_params())
            .expect("re-sealed blob opens")
            .seeds;
        assert!(
            recovered.is_share_hidden("noisy#0a0b0c0d0e0f"),
            "persisted blob carries the hide"
        );
    }

    /// First-start completion seeds the live payload with the chosen display name
    /// and queues a write-through, so the persisted blob carries it (ISC-C4b).
    #[test]
    fn first_start_persists_chosen_display_name() {
        use daemonseed_core::storage::seeds;

        let mut app = drive_to_main();
        let pid = app
            .session()
            .expect("session present")
            .profile_config
            .profile_id;
        // The live payload carries the default display name picked in the flow.
        let name = app
            .seeds
            .as_ref()
            .expect("seeds present")
            .display_name()
            .map(str::to_owned);
        assert!(name.is_some(), "first-start chose a display name");

        let bytes = app
            .take_pending_blob_update()
            .expect("first-start queues a write-through with the name");
        let recovered = seeds::open(&bytes, WT_PASSPHRASE, pid, wt_params())
            .expect("re-sealed blob opens")
            .seeds;
        assert_eq!(
            recovered.display_name().map(str::to_owned),
            name,
            "persisted blob carries the chosen display name"
        );
    }

    /// M14 (ISC-C21): defining a share persists its root in the at-rest blob
    /// (write-through) AND queues a DefineShare command for the actor.
    #[test]
    fn defining_a_share_persists_root_and_queues_the_command() {
        use daemonseed_core::storage::seeds;

        let mut app = drive_to_main();
        let pid = app
            .session()
            .expect("session present")
            .profile_config
            .profile_id;
        let _ = app.take_pending_blob_update(); // drain first-start's write-through

        // Tab Chat → JoinCircle → Mute → Shares → DefineShare, then define a dir.
        for _ in 0..4 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::DefineShare);
        let dir = std::env::temp_dir();
        for ch in format!("{}|My Docs", dir.display()).chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        let root_str = dir.to_string_lossy().into_owned();
        // Live seeds carry the share.
        assert!(
            app.seeds
                .as_ref()
                .expect("seeds present")
                .shares()
                .iter()
                .any(|s| s.root == root_str),
            "live seeds carries the share root"
        );
        // The persisted blob carries it too.
        let bytes = app
            .take_pending_blob_update()
            .expect("defining a share queues a blob re-seal");
        let recovered = seeds::open(&bytes, WT_PASSPHRASE, pid, wt_params())
            .expect("re-sealed blob opens")
            .seeds;
        assert_eq!(recovered.shares().len(), 1);
        assert_eq!(recovered.shares()[0].root, root_str);
        assert_eq!(recovered.shares()[0].label.as_deref(), Some("My Docs"));
        // And a DefineShare command is queued for the actor.
        assert!(
            app.take_pending_share_define().is_some(),
            "DefineShare queued for the actor"
        );
    }

    /// M14 (ISC-C21): on Unlock every persisted share root is replayed as a
    /// DefineShare (FIFO), so a returning daemon re-indexes without re-typing —
    /// and the replay rides the queue, so it does NOT re-persist.
    #[test]
    fn unlock_reemits_define_share_per_persisted_root() {
        let _ = oxicrypt_module::initialize();
        let mut materials = drive_to_main().session_take_for_test();
        materials
            .seeds
            .add_share("/data/alpha", Some("Alpha".to_owned()));
        materials.seeds.add_share("/data/beta", None);

        let mut app = App::new();
        app.on_unlock_success(materials);

        let first = app
            .take_pending_share_define()
            .expect("first persisted share re-emitted");
        assert_eq!(first.root, std::path::PathBuf::from("/data/alpha"));
        assert_eq!(first.label.as_deref(), Some("Alpha"));
        let second = app
            .take_pending_share_define()
            .expect("second persisted share re-emitted");
        assert_eq!(second.root, std::path::PathBuf::from("/data/beta"));
        assert_eq!(second.label, None);
        assert!(
            app.take_pending_share_define().is_none(),
            "exactly the two persisted roots replayed"
        );
        // The replay did not re-persist (no blob update queued by the restore).
        assert!(
            app.take_pending_blob_update().is_none(),
            "Unlock replay re-indexes without re-persisting"
        );
    }

    /// On Unlock the mute/hide sets and live payload are restored from the
    /// decrypted blob, not started empty (ISC-C15 / C16 restore).
    #[test]
    fn unlock_restores_mute_and_hide_from_seeds() {
        let _ = oxicrypt_module::initialize();
        // Build a SessionMaterials carrying a mute + hide, as Unlock would yield.
        let mut materials = {
            let mut app = drive_to_main();
            // Mute + hide so the live seeds carry them.
            app.on_key(press(KeyCode::Tab));
            app.on_key(press(KeyCode::Tab));
            for ch in "muted#aabbccddeeff".chars() {
                app.on_key(press(KeyCode::Char(ch)));
            }
            app.on_key(press(KeyCode::Enter));
            app.session_take_for_test()
        };
        // Replace the materials' seeds with one carrying a known mute + hide, so
        // the assertion is independent of the flow's defaults.
        materials.seeds.add_mute("muted#aabbccddeeff");
        materials.seeds.add_hidden_share("hidden#0a0b0c0d0e0f");

        let mut app = App::for_existing_profile_with_argon(wt_params());
        app.on_unlock_success(materials);
        assert!(
            app.is_muted("muted#aabbccddeeff"),
            "mute restored on unlock"
        );
        assert!(
            app.is_share_hidden("hidden#0a0b0c0d0e0f"),
            "hide restored on unlock"
        );
    }

    /// A fresh circle join (entropy not yet in `seeds.circles()`) remembers the
    /// circle in the live payload AND queues a write-through (M13, ISC-C59).
    #[test]
    fn fresh_join_persists_circle_and_queues_blob() {
        use daemonseed_core::storage::seeds;

        let mut app = drive_to_main();
        let pid = app
            .session()
            .expect("session present")
            .profile_config
            .profile_id;
        // Drain any first-start write-through so we observe the join's own.
        let _ = app.take_pending_blob_update();

        app.on_net_event(NetEvent::CircleJoined {
            circle_id: 7,
            label: "Book Club".to_owned(),
            entropy: "shared phrase one".to_owned(),
        });

        // Live seeds carries the remembered circle.
        let live = app.seeds.as_ref().expect("seeds present");
        assert_eq!(live.circles().len(), 1);
        assert_eq!(live.circles()[0].entropy(), "shared phrase one");
        assert_eq!(live.circles()[0].label, "Book Club");

        // And the join queued a write-through that persists it.
        let bytes = app
            .take_pending_blob_update()
            .expect("a fresh join queues a blob re-seal");
        let recovered = seeds::open(&bytes, WT_PASSPHRASE, pid, wt_params())
            .expect("re-sealed blob opens")
            .seeds;
        assert_eq!(recovered.circles().len(), 1);
        assert_eq!(recovered.circles()[0].entropy(), "shared phrase one");
    }

    /// On Unlock, every remembered circle is queued for rejoin; the resulting
    /// `CircleJoined` restores the runtime circle with the PERSISTED label (it
    /// wins over the actor-supplied one) and does NOT re-persist (M13, ISC-C59).
    #[test]
    fn unlock_queues_rejoins_and_persisted_label_wins() {
        let _ = oxicrypt_module::initialize();
        let mut materials = {
            let mut app = drive_to_main();
            app.session_take_for_test()
        };
        // The persisted blob remembers a circle with the user's label.
        materials.seeds.add_circle("phrase x", "My Label");

        let mut app = App::for_existing_profile_with_argon(wt_params());
        app.on_unlock_success(materials);

        // The remembered circle is queued for rejoin (not yet in the runtime set).
        assert!(
            app.pending_joins_for_test()
                .contains(&"phrase x".to_owned()),
            "unlock queues the remembered circle for rejoin"
        );
        assert!(app.circles().is_empty(), "runtime set waits for the event");
        assert_eq!(app.circle_status(), &CircleStatus::Joining);
        // The unlock-success connect write-through must not be mistaken for a
        // circle re-persist; drain it before the rejoin event.
        let _ = app.take_pending_blob_update();

        // The rejoin event arrives with an actor-generated label.
        app.on_net_event(NetEvent::CircleJoined {
            circle_id: 3,
            label: "actor-generated".to_owned(),
            entropy: "phrase x".to_owned(),
        });

        // Persisted label wins, the set did not grow, no new blob was queued.
        assert_eq!(app.circles().len(), 1);
        assert_eq!(app.circles()[0].label, "My Label");
        assert_eq!(
            app.seeds.as_ref().expect("seeds present").circles().len(),
            1,
            "a rejoin does not duplicate the persisted entry"
        );
        assert!(
            app.take_pending_blob_update().is_none(),
            "a rejoin does not re-persist"
        );
    }

    /// A disconnect clears the RUNTIME circle set but leaves the persisted
    /// circles in the live payload intact (M13, ISC-C59).
    #[test]
    fn disconnect_keeps_persisted_circles() {
        let mut app = drive_to_main();
        let _ = app.take_pending_blob_update();

        app.on_net_event(NetEvent::CircleJoined {
            circle_id: 1,
            label: "Ops".to_owned(),
            entropy: "ops phrase".to_owned(),
        });
        assert_eq!(app.circles().len(), 1);
        assert_eq!(
            app.seeds.as_ref().expect("seeds present").circles().len(),
            1
        );

        // Disconnect via the logged-in back menu (Esc → Main → Esc → menu, d).
        app.on_key(press(KeyCode::Esc)); // Main → LoggedInMenu
        app.on_key(press(KeyCode::Char('d'))); // disconnect

        assert!(
            app.circles().is_empty(),
            "runtime set cleared on disconnect"
        );
        assert_eq!(
            app.seeds.as_ref().expect("seeds present").circles().len(),
            1,
            "persisted circles survive a disconnect"
        );
    }

    #[test]
    fn muted_sender_suppressed_in_transcript() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "spammer#aabbccddeeff".to_owned(),
            body: "BUYNOW spam".to_owned(),
            sent_unix_ms: 1,
        });
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "friend#ccddeeff0011".to_owned(),
            body: "genuine hello".to_owned(),
            sent_unix_ms: 2,
        });
        // Mute the spammer.
        app.on_key(press(KeyCode::Tab));
        app.on_key(press(KeyCode::Tab)); // → Mute focus
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);
        assert!(
            !text.contains("BUYNOW spam"),
            "muted sender suppressed (ISC-13)"
        );
        assert!(text.contains("genuine hello"), "non-muted message kept");
    }

    #[test]
    fn self_mention_is_highlighted() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use ratatui::style::Color;

        // One app / one identity throughout (separate drive_to_main calls each
        // generate a different mnemonic → different handle, which would not
        // match the mention).
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        let own = app.own_chat_handle().expect("session handle").to_string();

        let yellow_cells = |app: &App| -> usize {
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| crate::ui::render(app, f)).unwrap();
            term.backend()
                .buffer()
                .content()
                .iter()
                .filter(|c| c.fg == Color::Yellow)
                .count()
        };

        // Baseline: a message that does NOT mention us (the connecting-status
        // line may already be yellow — we measure the delta, not absolute).
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "friend#ccddeeff0011".to_owned(),
            body: "nothing to see".to_owned(),
            sent_unix_ms: 1,
        });
        let baseline = yellow_cells(&app);

        // Now a message that mentions our own full handle.
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "friend#ccddeeff0011".to_owned(),
            body: format!("hey @{own} look here"),
            sent_unix_ms: 2,
        });
        assert!(
            yellow_cells(&app) > baseline,
            "a self-mention highlights its span yellow (ISC-11)"
        );
    }

    // ── server management + trust slider (ISC-21/26/27) ─────────────────

    /// Navigate to the Servers screen via the Tab cycle.
    fn to_servers(app: &mut App) {
        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // → Mute
        app.on_key(press(KeyCode::Tab)); // → Shares
        app.on_key(press(KeyCode::Tab)); // → DefineShare
        app.on_key(press(KeyCode::Tab)); // → Hide
        app.on_key(press(KeyCode::Tab)); // → Servers
        assert_eq!(app.main_focus(), MainFocus::Servers);
    }

    #[test]
    fn adding_a_server_appends_trusted_by_default() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@10.0.0.5:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // add (ISC-26)
        assert_eq!(app.servers().len(), 1);
        assert_eq!(app.servers()[0].server_id, "relay#aabbccddeeff");
        assert_eq!(app.servers()[0].address, "10.0.0.5:443");
        assert!(app.servers()[0].trusted, "new server defaults to trusted");
        assert_eq!(app.server_input(), "", "input cleared after add");
    }

    #[test]
    fn malformed_server_input_is_rejected_with_status() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "no-at-sign".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.servers().is_empty(), "malformed entry not added");
        assert!(app.status().is_some(), "error surfaced");
        assert_eq!(app.server_input(), "no-at-sign", "input kept to fix");
    }

    #[test]
    fn left_right_slider_sets_per_server_trust_mode() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@host:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // add (trusted by default)
        assert!(app.servers()[0].trusted);
        app.on_key(press(KeyCode::Left)); // slide → untrusted (ISC-21/27)
        assert!(!app.servers()[0].trusted);
        app.on_key(press(KeyCode::Right)); // slide → trusted
        assert!(app.servers()[0].trusted);
    }

    #[test]
    fn up_down_moves_server_selection() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for id in ["a#aabbccddeeff@h:1", "b#ccddeeff0011@h:2"] {
            for ch in id.chars() {
                app.on_key(press(KeyCode::Char(ch)));
            }
            app.on_key(press(KeyCode::Enter));
        }
        assert_eq!(app.server_sel(), 1, "selection follows the last-added");
        app.on_key(press(KeyCode::Up));
        assert_eq!(app.server_sel(), 0);
        app.on_key(press(KeyCode::Up)); // saturates
        assert_eq!(app.server_sel(), 0);
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.server_sel(), 1);
    }

    #[test]
    fn enter_on_selected_server_with_empty_input_connects() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@10.0.0.5:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // add (input now empty)
        let _ = app.take_pending_connect(); // ignore any prior
        app.on_key(press(KeyCode::Enter)); // empty input + selected → connect
        assert_eq!(app.connection(), &ConnectionStatus::Connecting);
        let req = app.take_pending_connect().expect("connect queued");
        assert_eq!(req.server_id, "relay#aabbccddeeff");
        assert_eq!(req.address, "10.0.0.5:443");
        assert!(req.trusted);
    }

    #[test]
    fn server_list_renders_with_slider_and_selection() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@10.0.0.5:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("relay#aabbccddeeff"), "server id rendered");
        assert!(text.contains("TRUSTED"), "trust slider rendered");
    }

    /// M12 gate step 6 (ISC-C22 / ISC-S6 / ISC-A-C19): an `IntroducerSnapshot`
    /// folds into App state and the Servers pane renders each candidate's
    /// server-id and address — and NEVER any key-like bytes (the introducer path
    /// carries no key material, ISC-S6). The address (`host:port`) and server-id
    /// (`name#hex`) are single tokens, so each renders contiguously.
    #[test]
    fn introducer_snapshot_folds_and_renders_candidate_without_keys() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        let _ = app.take_pending_introducer_refresh(); // drain the open-pane queue
        app.on_net_event(NetEvent::IntroducerSnapshot {
            candidates: vec![(
                "peer#0011aabbccdd".to_owned(),
                "peer.example.net:443".to_owned(),
            )],
        });
        assert_eq!(
            app.discovered_peers().len(),
            1,
            "candidate folded into state"
        );

        let text = render_text(&app, 120, 28);
        assert!(
            text.contains("Discovered (introducer)"),
            "discovered sub-section heading rendered"
        );
        assert!(
            text.contains("peer#0011aabbccdd"),
            "candidate server-id rendered contiguously"
        );
        assert!(
            text.contains("peer.example.net:443"),
            "candidate address rendered contiguously"
        );
        // No key material can ever reach this render (ISC-S6). The introducer
        // event has no key field; assert the render carries no PEM/base64-ish
        // key markers as a belt-and-braces guard against a future regression
        // that tried to thread one through.
        for marker in ["BEGIN", "PUBLIC KEY", "ml-dsa", "ML-DSA", "pubkey", "0x"] {
            assert!(
                !text.contains(marker),
                "render must contain no key-like bytes (found {marker:?})"
            );
        }
    }

    /// Opening the Servers pane auto-dispatches an introducer refresh so the
    /// "Discovered (introducer)" candidates are never silently empty on first
    /// view (drained as `NetCommand::RefreshIntroducer`).
    #[test]
    fn tab_to_servers_queues_an_introducer_refresh() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        assert!(
            app.take_pending_introducer_refresh(),
            "tabbing into Servers queues an introducer refresh"
        );
    }

    /// An empty `IntroducerSnapshot` is a normal state and renders a calm
    /// empty-state line, not an error.
    #[test]
    fn empty_introducer_snapshot_renders_calm_empty_state() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        app.on_net_event(NetEvent::IntroducerSnapshot {
            candidates: Vec::new(),
        });
        let text = render_text(&app, 120, 28);
        assert!(
            text.contains("no peers discovered"),
            "empty discovery shows a calm empty-state line"
        );
    }

    /// An `IntroducerError` surfaces on the status line and leaves any prior
    /// candidate list intact (mirrors the deprecation-error precedent).
    #[test]
    fn introducer_error_sets_status_and_keeps_candidates() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::IntroducerSnapshot {
            candidates: vec![("p#0011aabbccdd".to_owned(), "p:443".to_owned())],
        });
        app.on_net_event(NetEvent::IntroducerError {
            message: "introducer refresh refused: boom".to_owned(),
        });
        assert_eq!(
            app.discovered_peers().len(),
            1,
            "a refresh failure must not blank the cached candidates"
        );
        assert_eq!(
            app.status(),
            Some("introducer refresh refused: boom"),
            "error surfaced on the status line"
        );
    }

    #[test]
    fn mention_autocomplete_prefix_matches_seen_senders() {
        let mut app = drive_to_main();
        join_circle(&mut app, 1);
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "alice#aabbccddeeff".to_owned(),
            body: "hi".to_owned(),
            sent_unix_ms: 1,
        });
        app.on_net_event(NetEvent::ChatMessage {
            circle_id: 1,
            sender: "bob#ccddeeff0011".to_owned(),
            body: "yo".to_owned(),
            sent_unix_ms: 2,
        });
        // Compose a partial mention "@al".
        for ch in "@al".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        let suggestions = app.mention_autocomplete();
        assert!(
            suggestions.contains(&"alice#aabbccddeeff".to_owned()),
            "alice prefix-matches @al; got {suggestions:?}"
        );
        assert!(
            !suggestions.contains(&"bob#ccddeeff0011".to_owned()),
            "bob does not prefix-match @al"
        );
    }

    // ── Shares pane (ISC-17 / ISC-18 / ISC-20) ─────────────────────────────

    fn listing(share_id: &str, name: &str, rating: &str, sharer: &str) -> ShareListing {
        ShareListing {
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            rating: rating.to_owned(),
            sharer_handle: sharer.to_owned(),
            sharer_fingerprint: String::new(),
            mine: false,
            unresolved: false,
        }
    }

    fn to_shares(app: &mut App) {
        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // → Mute
        app.on_key(press(KeyCode::Tab)); // → Shares
        assert_eq!(app.main_focus(), MainFocus::Shares);
    }

    /// ISC-17: a `SharesSnapshot` lands in App state, both panes are queryable,
    /// and the render shows the local entry + the indexer status line.
    #[test]
    fn shares_snapshot_lands_and_renders_both_panes() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: vec![LocalShareRow {
                rel_path: "notes/recipe.md".to_owned(),
                size: 4096,
                mtime_unix_ms: 1,
            }],
            remote: vec![listing("s1", "Alice's notes", "PG13", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Ready { entries: 1 },
        });
        assert_eq!(app.local_shares().len(), 1);
        assert_eq!(app.public_shares_raw().len(), 1);
        assert_eq!(app.visible_public_shares().len(), 1);
        let text = render_text(&app, 120, 28);
        assert!(text.contains("my shares"), "My shares pane titled");
        assert!(text.contains("public shares"), "Public shares pane titled");
        assert!(text.contains("notes/recipe.md"), "local entry rendered");
        assert!(text.contains("Alice's notes"), "remote listing rendered");
        assert!(text.contains("indexer: ready"), "indexer status line shown");
    }

    /// ISC-20: indexer status surfaces in distinct strings per state (Idle /
    /// Indexing / Ready). The line is purely informational — no state machinery
    /// gates user input on it (ISC-A-C7).
    #[test]
    fn indexer_status_renders_three_distinct_states() {
        let mut app = drive_to_main();
        to_shares(&mut app);

        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Idle,
        });
        assert!(render_text(&app, 100, 24).contains("indexer: idle"));

        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Indexing {
                seen: 17,
                total: None,
            },
        });
        assert!(render_text(&app, 100, 24).contains("indexer: indexing 17"));

        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Ready { entries: 42 },
        });
        assert!(render_text(&app, 100, 24).contains("indexer: ready (42 entries)"));
    }

    /// ISC-18 / C16: a `SharesSnapshot` carrying a `sharer_handle` matching an
    /// entry in `hidden_shares` does NOT render that row. The raw snapshot still
    /// holds the row (the relay sent it); only the visible projection drops it.
    #[test]
    fn hide_toggle_filters_public_shares_render() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![
                listing("s1", "Alice notes", "", "alice#aabbccddeeff"),
                listing("s2", "Bob notes", "", "bob#001122334455"),
            ],
            indexer_status: IndexerStatus::Idle,
        });
        assert!(render_text(&app, 120, 24).contains("Alice notes"));

        // Move to the Hide box and toggle alice's handle into the hide set.
        app.on_key(press(KeyCode::Tab)); // → DefineShare
        app.on_key(press(KeyCode::Tab)); // → Hide
        assert_eq!(app.main_focus(), MainFocus::Hide);
        for ch in "alice#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.is_share_hidden("alice#aabbccddeeff"));

        let after = render_text(&app, 120, 24);
        assert!(
            !after.contains("Alice notes"),
            "alice's listing suppressed (ISC-18)"
        );
        assert!(after.contains("Bob notes"), "bob's listing still shown");
        // The raw snapshot is unchanged: the filter is purely render-time.
        assert_eq!(app.public_shares_raw().len(), 2);
    }

    /// ISC-18: the Enter-on-input toggle is idempotent (Enter again on the same
    /// handle removes it) — same shape as the chat-mute toggle. Mirrors the
    /// semantics of `Seeds::add_hidden_share` / `remove_hidden_share`.
    #[test]
    fn hide_toggle_is_idempotent() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_key(press(KeyCode::Tab)); // → DefineShare
        app.on_key(press(KeyCode::Tab)); // → Hide
        for ch in "alice#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.is_share_hidden("alice#aabbccddeeff"));
        // Re-type the same handle and toggle off.
        for ch in "alice#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(!app.is_share_hidden("alice#aabbccddeeff"));
    }

    /// Blob-integrity parity with `Seeds::add_hidden_share`: a paste containing
    /// `\n` or `\r` is refused so the future at-rest blob stays line-safe.
    #[test]
    fn hide_toggle_refuses_line_break_handle() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_key(press(KeyCode::Tab)); // → DefineShare
        app.on_key(press(KeyCode::Tab)); // → Hide
        for ch in "garbage\nmore".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(!app.is_share_hidden("garbage\nmore"), "rejected");
        assert!(
            app.status().is_some(),
            "status surfaces the rejection cause"
        );
    }

    /// Tabbing into the Shares (or Hide) focus drains a pending share refresh
    /// so the screen is never silently empty on first view. The binary turns
    /// this into a `NetCommand::RefreshShares`.
    #[test]
    fn tab_to_shares_or_hide_queues_a_refresh() {
        let mut app = drive_to_main();
        // Pre-condition: nothing queued from a fresh drive_to_main.
        let _ = app.take_pending_share_refresh();
        to_shares(&mut app); // Tab → … → Shares
        assert!(
            app.take_pending_share_refresh(),
            "tabbing into Shares queues a refresh"
        );
        app.on_key(press(KeyCode::Tab)); // → DefineShare (no refresh queued)
        assert!(
            !app.take_pending_share_refresh(),
            "DefineShare is an input box, not a shares view — no refresh"
        );
        app.on_key(press(KeyCode::Tab)); // → Hide
        assert!(
            app.take_pending_share_refresh(),
            "tabbing into Hide queues a refresh"
        );
    }

    /// `r` on the Shares pane queues a fresh refresh (the user-facing
    /// counterpart to the auto-queue on entry).
    #[test]
    fn r_key_on_shares_queues_a_refresh() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        let _ = app.take_pending_share_refresh();
        app.on_key(press(KeyCode::Char('r')));
        assert!(app.take_pending_share_refresh());
    }

    // ── Fetch overlay (ISC-19) ────────────────────────────────────────────

    /// Pressing `f` on a selected public-share row opens the fetch overlay,
    /// queues a NetCommand::FetchShare for the binary to drain, and starts
    /// in the RequestingManifest phase.
    #[test]
    fn f_key_on_shares_starts_fetch() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "Alice's notes", "PG13", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        let queued = app.take_pending_share_fetch().expect("fetch queued");
        assert_eq!(queued.0, "s1");
        assert_eq!(queued.1, "alice#aabbccddeeff");
        let f = app.fetch().expect("overlay up");
        assert_eq!(f.share_id, "s1");
        assert_eq!(f.status, FetchStatus::RequestingManifest);
        assert_eq!(f.total_chunks, None);
        assert_eq!(f.chunks_received, 0);
    }

    /// `f` with no visible rows is a no-op (no overlay, no queued command,
    /// no panic on an empty selection).
    #[test]
    fn f_key_on_empty_shares_is_a_no_op() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        assert!(app.fetch().is_none());
        assert!(app.take_pending_share_fetch().is_none());
    }

    /// A1: when the manifest arrives the overlay enters Preview carrying the
    /// file list, and nothing is queued for download yet (the user must
    /// confirm first).
    #[test]
    fn fetch_manifest_enters_preview() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![
                ShareManifestEntry {
                    rel_path: "a.txt".to_owned(),
                    size: 10,
                    chunk_count: 1,
                },
                ShareManifestEntry {
                    rel_path: "b.txt".to_owned(),
                    size: 20,
                    chunk_count: 1,
                },
            ],
        });
        let f = app.fetch().expect("overlay up");
        match &f.status {
            FetchStatus::Preview(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].rel_path, "a.txt");
                assert_eq!(entries[1].size, 20);
            }
            other => panic!("expected Preview, got {other:?}"),
        }
        // No download queued — the user has not confirmed.
        assert!(app.take_pending_fetch_confirm().is_none());
    }

    /// A1: a manifest for a different share_id than the active fetch is ignored
    /// (stale-fetch guard) — the overlay stays in RequestingManifest.
    #[test]
    fn fetch_manifest_for_other_share_is_ignored() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "OTHER".to_owned(),
            name: "x".to_owned(),
            entries: vec![ShareManifestEntry {
                rel_path: "z".to_owned(),
                size: 1,
                chunk_count: 1,
            }],
        });
        assert_eq!(app.fetch().unwrap().status, FetchStatus::RequestingManifest);
    }

    /// A1: Enter on the preview queues ConfirmFetch with a `None` selection
    /// (confirm-all) and moves the overlay to Receiving with the known total —
    /// the CHUNK sum over the selection (M16), not the file count.
    #[test]
    fn preview_enter_queues_confirm_all() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![
                ShareManifestEntry {
                    rel_path: "a.txt".to_owned(),
                    size: 10,
                    chunk_count: 1,
                },
                // A multi-chunk file (M16): e.g. a 2.1 MB file spans 3 chunks.
                ShareManifestEntry {
                    rel_path: "b.txt".to_owned(),
                    size: 20,
                    chunk_count: 3,
                },
            ],
        });
        app.on_key(press(KeyCode::Enter));
        let queued = app.take_pending_fetch_confirm().expect("confirm queued");
        assert_eq!(queued.0, "s1");
        assert_eq!(queued.1, "alice#aabbccddeeff");
        assert_eq!(queued.2, "notes");
        assert_eq!(queued.3, None); // confirm-all
        let f = app.fetch().unwrap();
        assert_eq!(f.status, FetchStatus::Receiving);
        // 1 chunk (a.txt) + 3 chunks (b.txt) — chunk-granular, not 2 files.
        assert_eq!(f.total_chunks, Some(4));
    }

    /// A1: Esc on the preview cancels — the overlay closes and nothing is
    /// queued (no stream is held during preview, so cancel is pure-UI).
    #[test]
    fn preview_esc_cancels_without_download() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![ShareManifestEntry {
                rel_path: "a.txt".to_owned(),
                size: 10,
                chunk_count: 1,
            }],
        });
        app.on_key(press(KeyCode::Esc));
        assert!(app.fetch().is_none());
        assert!(app.take_pending_fetch_confirm().is_none());
    }

    /// A2: space deselects the cursor file; Enter then downloads only the
    /// remaining selection (`Some(indices)`, not confirm-all).
    #[test]
    fn preview_space_deselects_and_enter_queues_subset() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![
                ShareManifestEntry {
                    rel_path: "a".to_owned(),
                    size: 1,
                    chunk_count: 1,
                },
                ShareManifestEntry {
                    rel_path: "b".to_owned(),
                    size: 2,
                    chunk_count: 2,
                },
                // An empty file contributes 0 chunks (M16) but still selects.
                ShareManifestEntry {
                    rel_path: "c".to_owned(),
                    size: 0,
                    chunk_count: 0,
                },
            ],
        });
        app.on_key(press(KeyCode::Char(' '))); // deselect file 0 (cursor at top)
        app.on_key(press(KeyCode::Enter));
        let queued = app.take_pending_fetch_confirm().expect("confirm queued");
        assert_eq!(queued.3, Some(vec![1, 2]));
        // Chunk sum over the SELECTED set only: b (2) + c (0).
        assert_eq!(app.fetch().unwrap().total_chunks, Some(2));
    }

    /// A2: `a` toggles all — from the all-selected default that clears the set,
    /// and Enter on an empty selection is ignored (overlay stays in Preview).
    #[test]
    fn preview_select_none_then_enter_is_ignored() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![ShareManifestEntry {
                rel_path: "a".to_owned(),
                size: 1,
                chunk_count: 1,
            }],
        });
        app.on_key(press(KeyCode::Char('a'))); // all -> none
        app.on_key(press(KeyCode::Enter));
        assert!(app.take_pending_fetch_confirm().is_none());
        assert!(matches!(
            app.fetch().unwrap().status,
            FetchStatus::Preview(_)
        ));
    }

    /// A2: ↓ moves the preview cursor and clamps at the last row.
    #[test]
    fn preview_down_moves_and_clamps_cursor() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![
                ShareManifestEntry {
                    rel_path: "a".to_owned(),
                    size: 1,
                    chunk_count: 1,
                },
                ShareManifestEntry {
                    rel_path: "b".to_owned(),
                    size: 2,
                    chunk_count: 1,
                },
            ],
        });
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.fetch().unwrap().preview_cursor, 1);
        app.on_key(press(KeyCode::Down)); // clamp at last row
        assert_eq!(app.fetch().unwrap().preview_cursor, 1);
    }

    /// A1/A2 regression: the preview's whole purpose is to SHOW the share's
    /// contents before downloading — so the file list must actually be visible
    /// on a standard 80×24 terminal, not pushed below the overlay's info pane by
    /// the header. (Found in smoke test: the file list rendered off-screen.)
    #[test]
    fn fetch_preview_shows_file_list_on_a_standard_terminal() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "docs", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "docs".to_owned(),
            entries: vec![
                ShareManifestEntry {
                    rel_path: "report.pdf".to_owned(),
                    size: 1234,
                    chunk_count: 1,
                },
                ShareManifestEntry {
                    rel_path: "notes.md".to_owned(),
                    size: 56,
                    chunk_count: 1,
                },
            ],
        });
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|frame| crate::ui::render(&app, frame)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("report.pdf") && text.contains("notes.md"),
            "the preview must show the share's file list on a standard 80×24 terminal; got:\n{text}"
        );
        // M16: the key hint renders inside the preview box (dim line under the
        // header). Assert the leading portion — the overlay is ~57 cols wide
        // at 80×24, so the line's tail may truncate on narrow terminals.
        assert!(
            text.contains("space toggle · a all/none · →/← fold · d dest"),
            "the preview must show the key-hint line; got:\n{text}"
        );
    }

    /// A3 (ISC-C68): editing the destination then confirming queues a confirm
    /// whose `dest` element is the typed path.
    #[test]
    fn preview_edit_dest_then_enter_queues_typed_path() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![ShareManifestEntry {
                rel_path: "a.txt".to_owned(),
                size: 10,
                chunk_count: 1,
            }],
        });
        // Enter dest-edit mode, type a path, leave edit mode, then download.
        app.on_key(press(KeyCode::Char('d')));
        assert!(app.fetch().unwrap().editing_dest);
        for c in "/tmp/dl".chars() {
            app.on_key(press(KeyCode::Char(c)));
        }
        app.on_key(press(KeyCode::Enter)); // exit edit mode — no download yet
        assert!(!app.fetch().unwrap().editing_dest);
        assert!(app.take_pending_fetch_confirm().is_none());
        app.on_key(press(KeyCode::Enter)); // now download
        let queued = app.take_pending_fetch_confirm().expect("confirm queued");
        assert_eq!(queued.4, "/tmp/dl");
    }

    /// A3 (ISC-C68): `d` enters dest-edit mode and a typed char lands in `dest`
    /// — and does NOT toggle a file's checkbox (the routing guard holds).
    #[test]
    fn preview_d_enters_edit_and_typing_does_not_toggle_selection() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![
                ShareManifestEntry {
                    rel_path: "a".to_owned(),
                    size: 1,
                    chunk_count: 1,
                },
                ShareManifestEntry {
                    rel_path: "b".to_owned(),
                    size: 2,
                    chunk_count: 1,
                },
            ],
        });
        app.on_key(press(KeyCode::Char('d'))); // enter dest-edit mode
        // 'a' would normally toggle-all; while editing it must land in `dest`.
        app.on_key(press(KeyCode::Char('a')));
        let f = app.fetch().unwrap();
        assert!(f.editing_dest);
        assert_eq!(f.dest, "a");
        // Selection is untouched — both files still selected (the default).
        assert_eq!(f.preview_checked, vec![true, true]);
        // Backspace edits the field.
        app.on_key(press(KeyCode::Backspace));
        assert_eq!(app.fetch().unwrap().dest, "");
    }

    /// A3 (ISC-C68): an empty `dest` still confirms — the binary resolves the
    /// empty case to the default downloads dir, so the queued confirm carries an
    /// empty destination element.
    #[test]
    fn preview_empty_dest_confirms_with_empty_element() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "notes".to_owned(),
            entries: vec![ShareManifestEntry {
                rel_path: "a.txt".to_owned(),
                size: 10,
                chunk_count: 1,
            }],
        });
        app.on_key(press(KeyCode::Enter)); // confirm without setting a dest
        let queued = app.take_pending_fetch_confirm().expect("confirm queued");
        assert_eq!(queued.4, ""); // empty → binary uses the default downloads dir
    }

    // ── ISC-C72: collapsible folder tree + scroll in the fetch preview ──────

    /// Drive an app into the share-fetch Preview state carrying `paths`
    /// (rel_path → size 1 each), for the C72 tree tests.
    fn drive_to_preview(paths: &[&str]) -> App {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "share", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchManifest {
            share_id: "s1".to_owned(),
            name: "share".to_owned(),
            entries: paths
                .iter()
                .map(|p| ShareManifestEntry {
                    rel_path: (*p).to_owned(),
                    size: 1,
                    chunk_count: 1,
                })
                .collect(),
        });
        app
    }

    /// C72: a nested manifest builds the expected pre-order node list with the
    /// right depths and `subtree_end` spans.
    #[test]
    fn c72_tree_build_has_correct_depths_and_subtree_ends() {
        let entries: Vec<ShareManifestEntry> = [
            "TV/BB/S1/e1.mkv",
            "TV/BB/S1/e2.mkv",
            "TV/BB/S2/e1.mkv",
            "readme.txt",
        ]
        .iter()
        .map(|p| ShareManifestEntry {
            rel_path: (*p).to_owned(),
            size: 1,
            chunk_count: 1,
        })
        .collect();
        let tree = FetchUi::build_preview_tree(&entries);
        // Pre-order: TV(0) BB(1) S1(2) e1(3) e2(4) S2(5) e1(6) readme(7)
        assert_eq!(tree.len(), 8);
        let names: Vec<&str> = tree.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "TV",
                "BB",
                "S1",
                "e1.mkv",
                "e2.mkv",
                "S2",
                "e1.mkv",
                "readme.txt"
            ]
        );
        let depths: Vec<usize> = tree.iter().map(|n| n.depth).collect();
        assert_eq!(depths, vec![0, 1, 2, 3, 3, 2, 3, 0]);
        // Dir spans: TV covers nodes 1..7, BB 2..7, S1 3..5, S2 6..7.
        assert!(matches!(tree[0].kind, PreviewKind::Dir { subtree_end: 7 }));
        assert!(matches!(tree[1].kind, PreviewKind::Dir { subtree_end: 7 }));
        assert!(matches!(tree[2].kind, PreviewKind::Dir { subtree_end: 5 }));
        assert!(matches!(tree[5].kind, PreviewKind::Dir { subtree_end: 7 }));
        // The S1 episodes carry the right manifest indices (received order).
        assert!(matches!(
            tree[3].kind,
            PreviewKind::File {
                manifest_idx: 0,
                ..
            }
        ));
        assert!(matches!(
            tree[4].kind,
            PreviewKind::File {
                manifest_idx: 1,
                ..
            }
        ));
        assert!(matches!(
            tree[7].kind,
            PreviewKind::File {
                manifest_idx: 3,
                ..
            }
        ));
    }

    /// C72: every Dir starts collapsed, so a dense share opens to just its
    /// top-level rows; expanding (→) reveals descendants.
    #[test]
    fn c72_dirs_default_collapsed_and_arrow_expands() {
        let mut app = drive_to_preview(&["TV/BB/S1/e1.mkv", "TV/BB/S1/e2.mkv", "readme.txt"]);
        // Top level: TV (collapsed) + readme.txt = 2 visible rows.
        assert_eq!(app.fetch().unwrap().visible_rows().len(), 2);
        // Cursor on TV; → expands it, revealing BB.
        app.on_key(press(KeyCode::Right));
        assert_eq!(app.fetch().unwrap().visible_rows().len(), 3); // TV, BB, readme
    }

    /// C72: collapsing a dir (←) hides its descendants — the visible-row count
    /// drops and the cursor stays put.
    #[test]
    fn c72_collapse_hides_descendants() {
        let mut app = drive_to_preview(&["TV/BB/e1.mkv", "TV/BB/e2.mkv", "readme.txt"]);
        // Fully expand: → on TV, → on BB.
        app.on_key(press(KeyCode::Right)); // expand TV
        app.on_key(press(KeyCode::Right)); // cursor still on TV → no-op (TV already expanded)
        // Move to BB and expand it.
        app.on_key(press(KeyCode::Down)); // cursor → BB
        app.on_key(press(KeyCode::Right)); // expand BB
        let full = app.fetch().unwrap().visible_rows().len();
        assert_eq!(full, 5); // TV, BB, e1, e2, readme
        // Collapse BB (cursor is on BB) → its two episodes vanish.
        app.on_key(press(KeyCode::Left));
        assert_eq!(app.fetch().unwrap().visible_rows().len(), 3); // TV, BB, readme
    }

    /// C72: `space` on a Dir selects exactly the files in its subtree; a second
    /// `space` clears them; the resulting confirm carries that subset.
    #[test]
    fn c72_folder_select_toggles_subtree_and_confirm_carries_subset() {
        // S1 has two episodes (manifest 0,1); a third file sits elsewhere (idx 2).
        let mut app = drive_to_preview(&["TV/S1/e1.mkv", "TV/S1/e2.mkv", "other.txt"]);
        // Start clean: deselect everything via `a` (default is all-selected).
        app.on_key(press(KeyCode::Char('a')));
        assert!(app.fetch().unwrap().preview_checked.iter().all(|&c| !c));
        // Navigate to the S1 dir: TV(0) is cursor; expand it, move to S1.
        app.on_key(press(KeyCode::Right)); // expand TV
        app.on_key(press(KeyCode::Down)); // cursor → S1
        // `space` on S1 checks exactly its two episodes (manifest 0,1), not idx 2.
        app.on_key(press(KeyCode::Char(' ')));
        assert_eq!(
            app.fetch().unwrap().preview_checked,
            vec![true, true, false]
        );
        // `space` again clears them.
        app.on_key(press(KeyCode::Char(' ')));
        assert_eq!(
            app.fetch().unwrap().preview_checked,
            vec![false, false, false]
        );
        // Re-select the subtree and confirm: the queued selection is Some([0,1]).
        app.on_key(press(KeyCode::Char(' ')));
        app.on_key(press(KeyCode::Enter));
        let queued = app.take_pending_fetch_confirm().expect("confirm queued");
        assert_eq!(queued.3, Some(vec![0, 1]));
    }

    /// C72: with one of a dir's two files checked, the dir renders `[~]`
    /// (partial); all-checked renders `[x]`, none renders `[ ]`.
    #[test]
    fn c72_partial_dir_aggregate_renders_tilde() {
        let app = drive_to_preview(&["TV/S1/e1.mkv", "TV/S1/e2.mkv"]);
        // Tree: TV(0) S1(1) e1(2,manifest 0) e2(3,manifest 1).
        let f = app.fetch().unwrap();
        // Default all-selected → S1 is All.
        assert_eq!(f.dir_selection(1), DirSelection::All);
        assert_eq!(f.dir_selection(0), DirSelection::All);
        // Build a custom FetchUi with exactly one episode checked.
        let mut f2 = f.clone();
        f2.preview_checked = vec![true, false];
        assert_eq!(f2.dir_selection(1), DirSelection::Partial);
        assert_eq!(f2.dir_selection(0), DirSelection::Partial);
        f2.preview_checked = vec![false, false];
        assert_eq!(f2.dir_selection(1), DirSelection::None);
    }

    /// C72 scroll: with more expanded files than the pane can hold, moving the
    /// cursor to the last row keeps that row on-screen (the render windows the
    /// list to the cursor).
    #[test]
    fn c72_scroll_keeps_cursor_visible_on_standard_terminal() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        // A single dir with many files — more than the ~70-wide × 24-tall
        // overlay's tree pane can show at once.
        let mut paths: Vec<String> = Vec::new();
        for i in 0..40 {
            paths.push(format!("flat/file{i:02}.bin"));
        }
        let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
        let mut app = drive_to_preview(&path_refs);
        // Expand the single top-level dir so all 40 files are in the visible list.
        app.on_key(press(KeyCode::Right));
        let visible = app.fetch().unwrap().visible_rows().len();
        assert_eq!(visible, 41); // the dir + 40 files
        // Drive the cursor to the very last row.
        for _ in 0..visible {
            app.on_key(press(KeyCode::Down));
        }
        assert_eq!(app.fetch().unwrap().preview_cursor, visible - 1);
        // Render at a standard terminal; the last file must be on-screen.
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|frame| crate::ui::render(&app, frame)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("file39.bin"),
            "the cursor row (last file) must stay visible after scrolling; got:\n{text}"
        );
        // And an early file should have scrolled OFF (proving it's a window).
        assert!(
            !text.contains("file00.bin"),
            "early rows should scroll off when the cursor is at the bottom; got:\n{text}"
        );
    }

    /// FetchProgress carrying Some(total) transitions the overlay from
    /// RequestingManifest to Receiving and accumulates chunk + byte counts.
    #[test]
    fn fetch_progress_transitions_and_accumulates() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "x", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        // Manifest arrives.
        app.on_net_event(NetEvent::FetchProgress {
            total_chunks: Some(3),
            chunks_received: 0,
            bytes_received: 0,
        });
        let f = app.fetch().unwrap();
        assert_eq!(f.status, FetchStatus::Receiving);
        assert_eq!(f.total_chunks, Some(3));
        // First chunk lands.
        app.on_net_event(NetEvent::FetchProgress {
            total_chunks: Some(3),
            chunks_received: 1,
            bytes_received: 42,
        });
        let f = app.fetch().unwrap();
        assert_eq!(f.chunks_received, 1);
        assert_eq!(f.bytes_received, 42);
    }

    /// FetchComplete sets the overlay's status to Complete; Enter then
    /// dismisses it (the fetch slot becomes None).
    #[test]
    fn fetch_complete_then_enter_dismisses_overlay() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "x", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchComplete {
            share_id: "s1".to_owned(),
            files_written: 3,
            bytes_written: 1024,
        });
        let f = app.fetch().unwrap();
        assert_eq!(f.status, FetchStatus::Complete);
        // No chunk total was ever learned → files_written is the fallback.
        assert_eq!(f.chunks_received, 3);
        // Enter on Complete dismisses.
        app.on_key(press(KeyCode::Enter));
        assert!(app.fetch().is_none());
    }

    /// M16: with a known chunk total, FetchComplete clamps the counter to the
    /// TOTAL CHUNKS, not `files_written` (which now counts files) — the done
    /// gauge must read N/N chunks, not files/N.
    #[test]
    fn fetch_complete_clamps_chunks_to_known_total() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "x", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        // The download started with a chunk-granular total: 2 files, 9 chunks.
        app.on_net_event(NetEvent::FetchProgress {
            total_chunks: Some(9),
            chunks_received: 7,
            bytes_received: 7 << 20,
        });
        app.on_net_event(NetEvent::FetchComplete {
            share_id: "s1".to_owned(),
            files_written: 2,
            bytes_written: 9 << 20,
        });
        let f = app.fetch().unwrap();
        assert_eq!(f.status, FetchStatus::Complete);
        assert_eq!(f.chunks_received, 9, "clamped to the chunk total");
        assert_eq!(f.bytes_received, 9 << 20);
    }

    /// FetchError with an active fetch puts the overlay into Failed; Enter
    /// or Esc dismisses.
    #[test]
    fn fetch_error_renders_failed_state_then_enter_dismisses() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "x", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_net_event(NetEvent::FetchError {
            message: "stream ended mid-fetch".to_owned(),
        });
        let f = app.fetch().unwrap();
        assert_eq!(
            f.status,
            FetchStatus::Failed("stream ended mid-fetch".to_owned())
        );
        app.on_key(press(KeyCode::Esc));
        assert!(app.fetch().is_none());
    }

    /// Esc while a fetch is in flight (not yet Complete/Failed) marks it
    /// Failed("cancelled by user") rather than dismissing — the user sees
    /// the cancellation reason before pressing Enter to acknowledge.
    #[test]
    fn esc_during_fetch_marks_cancelled_then_dismisses_on_second_esc() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "x", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        app.on_key(press(KeyCode::Esc));
        let f = app.fetch().unwrap();
        match &f.status {
            FetchStatus::Failed(msg) => assert!(msg.contains("cancelled by user")),
            other => panic!("expected Failed(cancelled), got {other:?}"),
        }
        // A second Esc dismisses the (terminal) overlay.
        app.on_key(press(KeyCode::Esc));
        assert!(app.fetch().is_none());
    }

    /// The overlay captures input while up: other keys are absorbed and do
    /// NOT drive the background view.
    #[test]
    fn fetch_overlay_captures_input_until_dismissed() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "x", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        // While the overlay is up and the fetch is in flight, hitting any
        // chat-like key MUST NOT compose anything.
        app.on_key(press(KeyCode::Char('q')));
        assert_eq!(app.compose(), "");
        assert!(app.fetch().is_some(), "overlay still up");
        // 'r' (refresh on Shares) is similarly absorbed.
        let _ = app.take_pending_share_refresh();
        app.on_key(press(KeyCode::Char('r')));
        assert!(
            !app.take_pending_share_refresh(),
            "r is absorbed by the overlay"
        );
    }

    /// The fetch overlay renders the phase + N/M progress strings.
    #[test]
    fn fetch_overlay_renders_phase_and_progress() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![listing("s1", "Alice notes", "", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Idle,
        });
        let _ = app.take_pending_share_fetch();
        app.on_key(press(KeyCode::Char('f')));
        // RequestingManifest phase.
        let text = render_text(&app, 100, 30);
        assert!(text.contains("share fetch"), "overlay titled");
        assert!(text.contains("requesting manifest"), "phase text rendered");
        // Manifest + first chunk.
        app.on_net_event(NetEvent::FetchProgress {
            total_chunks: Some(2),
            chunks_received: 1,
            bytes_received: 256,
        });
        let text = render_text(&app, 100, 30);
        assert!(text.contains("receiving chunks"), "phase advanced");
        assert!(text.contains("1/2"), "N/M progress visible");
    }

    /// Selection in the public-shares pane clamps to the *visible* subset, so a
    /// hidden row can never be silently highlighted.
    #[test]
    fn share_selection_clamps_to_visible_subset_after_hide() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![
                listing("s1", "Alice notes", "", "alice#aabbccddeeff"),
                listing("s2", "Bob notes", "", "bob#001122334455"),
            ],
            indexer_status: IndexerStatus::Idle,
        });
        // Move selection to the second row.
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.share_sel(), 1);
        // Hide bob — the visible subset shrinks to 1, so the sel must clamp.
        app.on_key(press(KeyCode::Tab)); // → DefineShare
        app.on_key(press(KeyCode::Tab)); // → Hide
        for ch in "bob#001122334455".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.share_sel(), 0, "clamped after hide");
    }

    // ── Public Space pane (ISC-25 / ISC-S7 / ISC-A-S3) ─────────────────────

    /// Navigate to the Public Space view via the Tab cycle (8 hops from Chat).
    fn to_public_space(app: &mut App) {
        for _ in 0..8 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::PublicSpace);
    }

    fn post_row(topic: &str, body: &str, verified: bool) -> PublicPostRow {
        PublicPostRow {
            topic: topic.to_owned(),
            body: body.to_owned(),
            verified,
            sent_unix_ms: 1,
        }
    }

    /// ISC-25 / ISC-S7: a `PublicSpaceSnapshot` lands in App state and the view
    /// renders the MOTD plus each announcement post.
    #[test]
    fn public_space_snapshot_lands_and_renders_motd_and_posts() {
        let mut app = drive_to_main();
        to_public_space(&mut app);
        app.on_net_event(NetEvent::PublicSpaceSnapshot {
            motd: Some("welcome to the relay".to_owned()),
            posts: vec![post_row("announcements", "maintenance at 0200 UTC", true)],
            can_compose: false,
        });
        assert_eq!(app.public_motd(), Some("welcome to the relay"));
        assert_eq!(app.public_posts().len(), 1);
        let text = render_text(&app, 120, 28);
        assert!(text.contains("message of the day"), "MOTD pane titled");
        assert!(text.contains("welcome to the relay"), "MOTD body rendered");
        assert!(text.contains("announcements"), "post topic rendered");
        assert!(
            text.contains("maintenance at 0200 UTC"),
            "post body rendered"
        );
    }

    /// ISC-A-S3: a post that failed client-side whitelist verification is
    /// flagged in the render, never presented as authentic.
    #[test]
    fn unverified_post_is_flagged() {
        let mut app = drive_to_main();
        to_public_space(&mut app);
        app.on_net_event(NetEvent::PublicSpaceSnapshot {
            motd: None,
            posts: vec![post_row("announcements", "forged-by-relay", false)],
            can_compose: false,
        });
        let text = render_text(&app, 120, 28);
        assert!(
            text.contains("unverified"),
            "an unverifiable post is flagged (ISC-A-S3)"
        );
        // The "no MOTD" state renders its own distinct line.
        assert!(
            text.contains("no message of the day"),
            "empty MOTD state shown"
        );
    }

    /// Tabbing into the Public Space view queues a refresh so the pane is never
    /// silently empty on first view (drained as `NetCommand::RefreshPublicSpace`).
    #[test]
    fn tab_to_public_space_queues_a_refresh() {
        let mut app = drive_to_main();
        to_public_space(&mut app);
        assert!(
            app.take_pending_public_space_refresh(),
            "tabbing into Public Space queues a refresh"
        );
    }

    /// `r` on the Public Space pane queues a fresh refresh.
    #[test]
    fn r_key_on_public_space_queues_a_refresh() {
        let mut app = drive_to_main();
        to_public_space(&mut app);
        let _ = app.take_pending_public_space_refresh();
        app.on_key(press(KeyCode::Char('r')));
        assert!(app.take_pending_public_space_refresh());
    }

    /// Up/Down move the announcement-post selection, clamped to the list.
    #[test]
    fn up_down_moves_post_selection() {
        let mut app = drive_to_main();
        to_public_space(&mut app);
        app.on_net_event(NetEvent::PublicSpaceSnapshot {
            motd: None,
            posts: vec![post_row("a", "first", true), post_row("a", "second", true)],
            can_compose: false,
        });
        assert_eq!(app.post_sel(), 0);
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.post_sel(), 1);
        app.on_key(press(KeyCode::Down)); // saturates at last row
        assert_eq!(app.post_sel(), 1);
        app.on_key(press(KeyCode::Up));
        assert_eq!(app.post_sel(), 0);
    }

    /// A `PublicSpaceError` surfaces on the status line and leaves any prior
    /// snapshot in place.
    #[test]
    fn public_space_error_sets_status_line() {
        let mut app = App::new();
        app.on_net_event(NetEvent::PublicSpaceError {
            message: "not connected to a relay yet".to_owned(),
        });
        assert_eq!(app.status(), Some("not connected to a relay yet"));
    }

    // ── Deprecation pane (ISC-C25 / ISC-A-S11 / ISC-C28) ───────────────────

    /// Navigate to the Deprecation view via the Tab cycle (9 hops from Chat).
    fn to_deprecation(app: &mut App) {
        for _ in 0..9 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::Deprecation);
    }

    fn dep_row(suite_id: u16, past_cutoff: bool) -> DeprecationWarningRow {
        DeprecationWarningRow {
            suite_id,
            cutoff_unix_ms: 1_000_000_000_000,
            recommended_suite_id: 2,
            past_cutoff,
        }
    }

    /// ISC-C25: a `DeprecationSnapshot` lands in App state and the view renders
    /// a hyphenated warning token (PTY-matchable) plus the policy version.
    #[test]
    fn deprecation_snapshot_lands_and_renders_warning() {
        let mut app = drive_to_main();
        to_deprecation(&mut app);
        app.on_net_event(NetEvent::DeprecationSnapshot {
            policy_version: Some(3),
            warnings: vec![dep_row(1, false)],
            had_policy: true,
        });
        assert_eq!(app.deprecation_warnings().len(), 1);
        assert_eq!(app.deprecation_policy_version(), Some(3));
        let text = render_text(&app, 120, 28);
        assert!(
            text.contains("suite-deprecation-pending"),
            "a still-advisory deprecation renders the pending token"
        );
        assert!(text.contains("recommended"), "recommended-suite surfaced");
    }

    /// ISC-C25: a still-future cutoff renders the pending token; a past cutoff
    /// renders the blocking cutoff-hit token instead.
    #[test]
    fn deprecation_cutoff_hit_renders_blocking_token() {
        let mut app = drive_to_main();
        to_deprecation(&mut app);
        app.on_net_event(NetEvent::DeprecationSnapshot {
            policy_version: Some(1),
            warnings: vec![dep_row(1, true)],
            had_policy: true,
        });
        let text = render_text(&app, 120, 28);
        assert!(
            text.contains("suite-deprecation-cutoff-hit"),
            "a past-cutoff suite renders the blocking token"
        );
    }

    /// ISC-C25: a `DeprecationError` (rollback / fetch failure) surfaces on the
    /// status line but leaves the cached warning rows intact — going blank on
    /// rollback would hide the very state the anti-rollback check protects.
    #[test]
    fn deprecation_error_keeps_cached_warnings() {
        let mut app = drive_to_main();
        to_deprecation(&mut app);
        app.on_net_event(NetEvent::DeprecationSnapshot {
            policy_version: Some(5),
            warnings: vec![dep_row(1, false)],
            had_policy: true,
        });
        app.on_net_event(NetEvent::DeprecationError {
            message: "deprecation policy rollback rejected".to_owned(),
        });
        assert_eq!(app.status(), Some("deprecation policy rollback rejected"));
        assert_eq!(
            app.deprecation_warnings().len(),
            1,
            "cached warnings survive a rollback error (ISC-C25)"
        );
        assert_eq!(app.deprecation_policy_version(), Some(5));
    }

    /// Tabbing into the Deprecation view queues a fetch so the pane is never
    /// silently empty on first view (drained as `NetCommand::RefreshDeprecation`).
    #[test]
    fn tab_to_deprecation_queues_a_refresh() {
        let mut app = drive_to_main();
        to_deprecation(&mut app);
        assert!(
            app.take_pending_deprecation_refresh(),
            "tabbing into Deprecation queues a refresh"
        );
    }

    /// `r` on the Deprecation pane queues a fresh fetch.
    #[test]
    fn r_key_on_deprecation_queues_a_refresh() {
        let mut app = drive_to_main();
        to_deprecation(&mut app);
        let _ = app.take_pending_deprecation_refresh();
        app.on_key(press(KeyCode::Char('r')));
        assert!(app.take_pending_deprecation_refresh());
    }

    /// Up/Down move the warning-row selection, clamped to the list.
    #[test]
    fn up_down_moves_dep_selection() {
        let mut app = drive_to_main();
        to_deprecation(&mut app);
        app.on_net_event(NetEvent::DeprecationSnapshot {
            policy_version: Some(1),
            warnings: vec![dep_row(1, false), dep_row(3, false)],
            had_policy: true,
        });
        assert_eq!(app.dep_sel(), 0);
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.dep_sel(), 1);
        app.on_key(press(KeyCode::Down)); // saturates at last row
        assert_eq!(app.dep_sel(), 1);
        app.on_key(press(KeyCode::Up));
        assert_eq!(app.dep_sel(), 0);
    }

    /// A `DeprecationError` before any snapshot surfaces on the status line and
    /// leaves the (empty) warning list untouched.
    #[test]
    fn deprecation_error_sets_status_line() {
        let mut app = App::new();
        app.on_net_event(NetEvent::DeprecationError {
            message: "not connected to a relay yet".to_owned(),
        });
        assert_eq!(app.status(), Some("not connected to a relay yet"));
        assert!(app.deprecation_warnings().is_empty());
    }

    // ── Item D: first-start sets the persist flag (ISC-C49/C50) ──────────

    /// Completing first-start raises the persist flag exactly once so the binary
    /// writes the at-rest blob + `.dseed` (ISC-C49 / ISC-C50). The session
    /// materials carry the bytes the binary persists.
    #[test]
    fn first_start_completion_queues_persist_once() {
        let mut app = drive_to_main();
        assert!(app.has_session());
        assert!(
            app.session()
                .is_some_and(|s| !s.at_rest_blob_bytes.is_empty()),
            "session carries the at-rest blob bytes to persist (ISC-C49)"
        );
        assert!(
            app.session()
                .is_some_and(|s| !s.recovery_file_bytes.is_empty()),
            "session carries the .dseed bytes to persist (ISC-C50)"
        );
        assert!(app.take_pending_persist(), "persist queued on completion");
        assert!(
            !app.take_pending_persist(),
            "persist flag drained exactly once"
        );
    }

    // ── Item E: Unlock daily-login + sane back (ISC-C3 / A-C27) ──────────

    /// An existing-profile launch starts on the Unlock screen, not enrollment
    /// (ISC-C51 routing). Enter queues a decrypt attempt; the binary services it.
    #[test]
    fn existing_profile_starts_on_unlock_and_queues_attempt() {
        let mut app = App::for_existing_profile();
        assert_eq!(app.screen(), &Screen::Unlock);
        for ch in "my passphrase".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        assert_eq!(app.unlock_input(), "my passphrase");
        app.on_key(press(KeyCode::Enter));
        let pp = app.take_pending_unlock().expect("unlock attempt queued");
        assert_eq!(pp, "my passphrase");
        assert!(app.take_pending_unlock().is_none(), "queued exactly once");
    }

    /// A failed unlock stays on Unlock with an error and a cleared buffer; a
    /// successful unlock reaches Main and queues a connect to the bootstrap.
    #[test]
    fn unlock_failure_then_success_routes_correctly() {
        let _ = oxicrypt_module::initialize();
        let mut app = App::for_existing_profile();
        app.on_unlock_failure("wrong passphrase");
        assert_eq!(app.screen(), &Screen::Unlock, "failure stays on Unlock");
        assert_eq!(app.unlock_error(), Some("wrong passphrase"));
        assert_eq!(app.unlock_input(), "", "buffer cleared for retry");

        // Build a real SessionMaterials via a cold first-start to feed success.
        let session = {
            let mut fs = drive_to_main();
            fs.session_take_for_test()
        };
        app.on_unlock_success(session);
        assert_eq!(app.screen(), &Screen::Main, "success reaches Main (ISC-C3)");
        assert_eq!(app.connection(), &ConnectionStatus::Connecting);
        assert!(
            app.take_pending_connect().is_some(),
            "unlock queues a connect to the persisted bootstrap"
        );
    }

    /// The Unlock screen renders its masked passphrase field + hint (Item E).
    #[test]
    fn unlock_screen_renders() {
        let mut app = App::for_existing_profile();
        for ch in "secret".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        let text = render_text(&app, 80, 12);
        assert!(
            text.contains("unlock your identity"),
            "unlock title rendered"
        );
        assert!(text.contains("******"), "passphrase masked");
        assert!(text.contains("[Enter] unlock"), "unlock hint rendered");
    }

    /// The split chat view's circle pane states the join requirement when the
    /// membership set is empty (ISC-C61 narrows ISC-C48 to the circle pane), and
    /// switches once a circle is joined. The lobby pane is always present
    /// regardless (ISC-C56).
    #[test]
    fn chat_empty_state_states_circle_requirement() {
        let mut app = drive_to_main();
        let _ = app.take_pending_persist();
        let text = render_text(&app, 100, 24);
        assert!(
            text.contains("join a circle to chat"),
            "circle pane states the join requirement when the set is empty (ISC-C61)"
        );
        assert!(
            text.contains("lobby"),
            "lobby pane is always present (ISC-C56)"
        );
        join_circle(&mut app, 1);
        let text = render_text(&app, 100, 24);
        assert!(
            !text.contains("join a circle to chat"),
            "requirement message gone once a circle is joined"
        );
    }

    /// ISC-A-C27: Esc in Main opens the logged-in menu, never the enrollment
    /// wizard; Esc in the menu returns to Main; `d` drops to Unlock for re-login.
    #[test]
    fn esc_in_main_opens_menu_never_enrollment() {
        let mut app = drive_to_main();
        let _ = app.take_pending_persist();
        app.on_key(press(KeyCode::Esc));
        assert_eq!(
            app.screen(),
            &Screen::LoggedInMenu,
            "Esc opens the logged-in menu, not Welcome/FirstStart"
        );
        // Esc again returns to Main (a stray back never strands the user).
        app.on_key(press(KeyCode::Esc));
        assert_eq!(app.screen(), &Screen::Main);
        // `d` disconnects → Unlock (re-login), never the enrollment wizard.
        app.on_key(press(KeyCode::Esc));
        app.on_key(press(KeyCode::Char('d')));
        assert_eq!(app.screen(), &Screen::Unlock);
        assert_ne!(app.screen(), &Screen::Welcome);
        assert_ne!(app.screen(), &Screen::FirstStart);
    }
}
