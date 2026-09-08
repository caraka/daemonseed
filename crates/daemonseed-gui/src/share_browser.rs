//! Slint-free, RAM-only model of the public-share **browse tree** (GUI alpha,
//! Shares tab — commit 1 of the public-share UI).
//!
//! No `slint` import: like [`crate::state`], this is the in-memory model the GUI
//! renders, kept Slint-free so the tree logic — parsing a flat manifest into a
//! folder hierarchy, lazy per-share expansion, flatten-with-depth for rendering —
//! is unit-testable in isolation. `main.rs` binds it to a Slint `[ShareRow]` model
//! and drives it from the [`crate::net::NetEvent`] drain (`SharesSnapshot` →
//! [`ShareBrowser::set_shares`], `FetchManifest` → [`ShareBrowser::load_manifest`]).
//!
//! The pane is one unified tree (demonsaw-4.20 reference): each
//! live relay share is a **root node**; expanding it lazily previews its files
//! (`FetchShare` → `FetchManifest`), parsed from the manifest's `/`-separated
//! `rel_path`s into real folders. Everyone's shares — including your own — appear in
//! the same tree, since the relay's `SharesSnapshot` lists them all.
//!
//! **Scope (commit 1): browse only.** Refresh → root nodes → lazy expand → render.
//! Right-click *Download to…* + the native dir picker + the progress meter are
//! commit 2; the publish overlay is commit 3. The `manifest_index` carried on each
//! file node is the seam commit 2's `ConfirmFetch` selection consumes — populated
//! here during the same parse so commit 2 needs no tree rebuild.

/// What kind of row a flattened tree row is (drives the Slint glyph + styling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A live relay share (tree root, depth 0).
    Share,
    /// A folder inside a previewed share's manifest.
    Folder,
    /// A file inside a previewed share's manifest.
    File,
}

/// One flattened, render-ready row of the visible tree. `id` is stable for the
/// node's lifetime (assigned at build) so a toggle/right-click dispatched from the
/// UI names the same node across re-renders.
#[derive(Debug, Clone)]
pub struct Row {
    pub id: u64,
    pub depth: u32,
    /// The node's own path segment (share name / folder name / file name) — never
    /// the full path; indentation conveys the hierarchy.
    pub label: String,
    /// Human-readable size for a file row; empty for shares and folders.
    pub size: String,
    pub kind: NodeKind,
    /// True if the row has a disclosure control (a share, or a non-empty folder).
    pub expandable: bool,
    pub expanded: bool,
    /// True for a share you published yourself (sharer handle == your handle).
    pub mine: bool,
    /// True for a share that is expanded but whose manifest has not arrived yet
    /// (the FetchShare preview is in flight) — the UI shows a quiet "loading…".
    pub loading: bool,
    /// #114: the sharer's display handle (name part of the advisory `name#12hex`),
    /// shown on a foreign share's depth-0 row so it is not anonymous. Empty for
    /// own shares (the UI tags those "you") and for non-share rows.
    pub sharer: String,
    /// #114: the sharer's `#12hex` fingerprint (the `#…` tail of the advisory
    /// handle), revealed only on hover per the "no hash unless hover" design. Empty
    /// when the handle carries no fingerprint, for own shares, and non-share rows.
    pub sharer_fingerprint: String,
}

/// The outcome of a [`ShareBrowser::toggle`]: if `needs_fetch` is `Some`, the caller
/// must send `NetCommand::FetchShare { share_id, name }` to load the manifest; on the
/// matching `FetchManifest` it calls [`ShareBrowser::load_manifest`]. `None` means the
/// model already changed (collapse, or a folder toggle) and only a re-render is owed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Toggle {
    pub needs_fetch: Option<FetchRequest>,
}

/// The (share_id, name) pair a lazy expand must fetch a preview for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub share_id: String,
    pub name: String,
}

/// The target of a download action on a tree node (commit 2): which share, and which
/// files within it. `selected: None` = the whole share (all files); `Some(indices)`
/// is a subset keyed by manifest position — the `NetCommand::ConfirmFetch { selected }`
/// contract. A right-click on a file yields its single index; on a folder, all its
/// descendant files; on a share root, `None` (everything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchTarget {
    pub share_id: String,
    pub name: String,
    pub selected: Option<Vec<usize>>,
    /// (download-subsystem redesign, step 5 / DL-ISC-8) Which kind of node the user
    /// toggled — the placement selection root. A share root → `RootKind::Share`, a
    /// file → `RootKind::File`, a folder → `RootKind::Dir`. `main.rs` passes it into
    /// `NetCommand::ConfirmFetch`.
    pub root_kind: crate::net::RootKind,
}

/// One manifest row as handed in by `main.rs` from a `NetEvent::FetchManifest`
/// (decoupled from `net::ShareManifestEntry` so this module never imports the net
/// layer). `index` is the file's position in the share manifest — the selection key
/// `ConfirmFetch` will consume in commit 2.
#[derive(Debug, Clone)]
pub struct ManifestRow {
    pub rel_path: String,
    pub size: u64,
    pub index: usize,
}

#[derive(Debug)]
enum Node {
    Dir(Dir),
    File(File),
}

#[derive(Debug)]
struct Dir {
    id: u64,
    name: String,
    expanded: bool,
    children: Vec<Node>,
}

#[derive(Debug)]
struct File {
    id: u64,
    name: String,
    size: u64,
    /// Position in the share manifest — the `ConfirmFetch` selection key (used by
    /// [`ShareBrowser::fetch_target`]).
    manifest_index: usize,
}

#[derive(Debug)]
struct ShareNode {
    id: u64,
    share_id: String,
    name: String,
    mine: bool,
    /// #114: the sharer's **self-asserted** advisory display handle, shown on the
    /// depth-0 row so a foreign share is not anonymous. It MAY carry a `#<12hex>`
    /// (a TUI publisher sends its whole wire handle; a display-named GUI publisher
    /// sends the bare name) — so it is stripped to name-only for the row via
    /// [`daemonseed_core::handle::strip_handle_hash`]. It is a display label, not
    /// identity: the verified attribution is `sharer_fingerprint` (from the signed
    /// pubkey), revealed on hover.
    sharer_handle: String,
    /// #114: the sharer's `#12hex` fingerprint, derived from the VERIFIED announcer
    /// pubkey (not the spoofable handle) and revealed only on hover. Empty for own
    /// shares.
    sharer_fingerprint: String,
    expanded: bool,
    /// True once the manifest preview has been folded in via [`ShareBrowser::load_manifest`].
    loaded: bool,
    children: Vec<Node>,
}

/// The browse-tree model: the live relay shares as tree roots, each with a lazily
/// loaded file subtree. RAM-only; a refresh replaces the whole set.
#[derive(Debug, Default)]
pub struct ShareBrowser {
    /// Monotonic id source, never reset — so an id handed to the UI never aliases a
    /// node from a previous refresh that a late event might still reference.
    next_id: u64,
    shares: Vec<ShareNode>,
}

impl ShareBrowser {
    pub fn new() -> ShareBrowser {
        ShareBrowser::default()
    }

    fn fresh_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Reconcile the listing against a relay `SharesSnapshot` (refresh). Each tuple
    /// is `(share_id, name, sharer_handle, sharer_fingerprint)` — the fingerprint is
    /// the announcer's verified `#12hex` (#114), empty for own shares. `my_handle`
    /// (the unlocked wire handle, or `None` on the ephemeral path) tags a share as
    /// `mine` when it matches the sharer handle exactly.
    ///
    /// **Reconcile, not replace** — keyed on the stable opaque `share_id`: a share
    /// still listed keeps its node identity (id, expansion, loaded manifest, open
    /// folders), a newly-appeared share is added collapsed + unloaded, and a share no
    /// longer listed is dropped. Order follows the relay's listing. This is what lets
    /// a refresh — manual now, or a future auto-poll — update the catalog live as
    /// other daemons publish/unpublish WITHOUT collapsing the tree the user is reading
    /// (the protocol has no push for the share catalog: `ListPublicShares` is unary,
    /// so the only way to track other daemons' shares is to re-list and reconcile).
    pub fn set_shares<'a, I>(&mut self, listings: I, my_handle: Option<&str>)
    where
        I: IntoIterator<Item = (&'a str, &'a str, &'a str, &'a str)>,
    {
        // Drain the prior shares into a by-share_id map so a persisting share's node
        // (with its expansion + loaded subtree) is reused rather than rebuilt.
        let mut prior: std::collections::HashMap<String, ShareNode> = self
            .shares
            .drain(..)
            .map(|s| (s.share_id.clone(), s))
            .collect();
        let mut next: Vec<ShareNode> = Vec::new();
        for (share_id, name, sharer_handle, sharer_fingerprint) in listings {
            let mine = my_handle.is_some_and(|h| !h.is_empty() && h == sharer_handle);
            if let Some(mut existing) = prior.remove(share_id) {
                // Persisting share: keep id/expansion/loaded/children; refresh display.
                existing.name = name.to_owned();
                existing.mine = mine;
                existing.sharer_handle = sharer_handle.to_owned();
                existing.sharer_fingerprint = sharer_fingerprint.to_owned();
                next.push(existing);
            } else {
                let id = self.fresh_id();
                next.push(ShareNode {
                    id,
                    share_id: share_id.to_owned(),
                    name: name.to_owned(),
                    mine,
                    sharer_handle: sharer_handle.to_owned(),
                    sharer_fingerprint: sharer_fingerprint.to_owned(),
                    expanded: false,
                    loaded: false,
                    children: Vec::new(),
                });
            }
        }
        // `prior`'s leftovers are shares no longer listed — dropped by going out of scope.
        self.shares = next;
    }

    /// Fold a fetched manifest preview into the named share's subtree, parsing the
    /// flat `rel_path` list into a real folder hierarchy (dirs first, then files,
    /// each level alphabetical — OS-browser order). No-op if the share is no longer
    /// listed (e.g. refreshed away before the preview arrived). Leaves the share's
    /// `expanded` flag as the toggle set it, so the children appear immediately.
    pub fn load_manifest(&mut self, share_id: &str, entries: &[ManifestRow]) {
        // Resolve the share index without holding a borrow across the id allocations.
        let Some(pos) = self.shares.iter().position(|s| s.share_id == share_id) else {
            return;
        };
        let mut root: Vec<Node> = Vec::new();
        for entry in entries {
            self.insert_path(&mut root, entry);
        }
        // One recursive pass once the whole tree is built — a per-insert sort misses
        // a folder created AFTER a sibling file at the same level (it never re-sorts
        // that level), leaving files ahead of dirs.
        sort_tree(&mut root);
        let share = &mut self.shares[pos];
        share.children = root;
        share.loaded = true;
    }

    /// Insert one manifest entry into the tree under `root`, creating folder nodes
    /// for each intermediate path segment as needed.
    fn insert_path(&mut self, root: &mut Vec<Node>, entry: &ManifestRow) {
        let segments: Vec<&str> = entry
            .rel_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let Some((file_name, dirs)) = segments.split_last() else {
            return; // empty / all-separators path — skip rather than panic
        };

        // Descend/create the folder chain. `cursor` walks the children vec at each level.
        let mut level = root;
        for dir_name in dirs {
            // Find an existing dir child by name (linear — manifests are small).
            let existing = level
                .iter()
                .position(|n| matches!(n, Node::Dir(d) if d.name == *dir_name));
            let idx = match existing {
                Some(i) => i,
                None => {
                    let id = self.fresh_id();
                    level.push(Node::Dir(Dir {
                        id,
                        name: (*dir_name).to_owned(),
                        expanded: false,
                        children: Vec::new(),
                    }));
                    level.len() - 1
                }
            };
            let Node::Dir(dir) = &mut level[idx] else {
                unreachable!("matched/created a Dir at idx");
            };
            level = &mut dir.children;
        }

        let id = self.fresh_id();
        level.push(Node::File(File {
            id,
            name: (*file_name).to_owned(),
            size: entry.size,
            manifest_index: entry.index,
        }));
    }

    /// Toggle the node with `id` open/closed. A share that has never been previewed
    /// returns `needs_fetch` so the caller loads its manifest; collapsing it, or
    /// toggling any folder, just mutates the model and owes a re-render.
    pub fn toggle(&mut self, id: u64) -> Toggle {
        for share in &mut self.shares {
            if share.id == id {
                share.expanded = !share.expanded;
                if share.expanded && !share.loaded {
                    return Toggle {
                        needs_fetch: Some(FetchRequest {
                            share_id: share.share_id.clone(),
                            name: share.name.clone(),
                        }),
                    };
                }
                return Toggle::default();
            }
            if toggle_in(&mut share.children, id) {
                return Toggle::default();
            }
        }
        Toggle::default()
    }

    /// Flatten the visible tree (respecting expansion) into render rows, in display
    /// order: each share root, then — if expanded + loaded — its folders (dirs first)
    /// and files, recursively.
    pub fn rows(&self) -> Vec<Row> {
        let mut out = Vec::new();
        for share in &self.shares {
            // #114/#173: own shares are tagged "you" by the UI, so leave their sharer
            // fields empty; a foreign share shows its handle NAME-ONLY (the `#12hex`
            // stripped, mirroring the Lobby roster) and reveals the VERIFIED-pubkey
            // fingerprint only on hover. The strip is required, not cosmetic: a
            // `sharer_handle` MAY be a full `name#hash` (a publisher whose display
            // name is set to that whole wire handle — the TUI seed node) or a bare
            // name; without stripping the former shows `name#hash` in the row.
            let (sharer, sharer_fingerprint) = if share.mine {
                (String::new(), String::new())
            } else {
                (
                    daemonseed_core::handle::strip_handle_hash(&share.sharer_handle).to_owned(),
                    share.sharer_fingerprint.clone(),
                )
            };
            out.push(Row {
                id: share.id,
                depth: 0,
                label: share.name.clone(),
                size: String::new(),
                kind: NodeKind::Share,
                expandable: true,
                expanded: share.expanded,
                mine: share.mine,
                loading: share.expanded && !share.loaded,
                sharer,
                sharer_fingerprint,
            });
            if share.expanded && share.loaded {
                push_rows(&share.children, 1, &mut out);
            }
        }
        out
    }

    /// Resolve a node id to a download target (commit 2): a share root → the whole
    /// share (`selected: None`); a folder → its descendant files; a file → just
    /// itself. `None` if the id is unknown. A share root resolves even when unloaded
    /// (`ConfirmFetch { selected: None }` re-opens and fetches every file); a folder /
    /// file id only exists once the manifest is loaded, so its selection is concrete.
    pub fn fetch_target(&self, id: u64) -> Option<FetchTarget> {
        for share in &self.shares {
            if share.id == id {
                return Some(FetchTarget {
                    share_id: share.share_id.clone(),
                    name: share.name.clone(),
                    selected: None,
                    root_kind: crate::net::RootKind::Share,
                });
            }
            if let Some((dir_path, indices)) = indices_under(&share.children, id, "") {
                return Some(FetchTarget {
                    share_id: share.share_id.clone(),
                    name: share.name.clone(),
                    selected: Some(indices),
                    // A folder subtree → Dir carrying the toggled folder's OWN path;
                    // a single file → File (DL-ISC-8). The placement resolver treats a
                    // one-file folder (Dir) differently from that same file selected
                    // alone (File), and the carried path keeps the toggled folder even
                    // when its files nest deeper (F5) — the node, not a derived prefix,
                    // is authoritative.
                    root_kind: match dir_path {
                        Some(path) => crate::net::RootKind::Dir(path),
                        None => crate::net::RootKind::File,
                    },
                });
            }
        }
        None
    }
}

/// If `id` names a node within `level`, return `(dir_path, manifest indices)`: a
/// file → `(None, [its index])`; a folder → `(Some(<its full manifest-relative
/// path>), all descendant file indices in tree order)`. `None` if the id is not in
/// this subtree. `prefix` is the accumulated ancestor-directory path (`""` at the
/// share root). The returned dir path lets `fetch_target` carry the toggled folder
/// itself into `RootKind::Dir` — a one-file folder keeps its folder, and a folder
/// whose files nest deeper keeps its own name rather than collapsing to the deeper
/// common prefix (F5 / DL-ISC-8).
fn indices_under(level: &[Node], id: u64, prefix: &str) -> Option<(Option<String>, Vec<usize>)> {
    for node in level {
        match node {
            Node::File(file) if file.id == id => return Some((None, vec![file.manifest_index])),
            Node::File(_) => {}
            Node::Dir(dir) => {
                let dir_path = if prefix.is_empty() {
                    dir.name.clone()
                } else {
                    format!("{prefix}/{}", dir.name)
                };
                if dir.id == id {
                    let mut acc = Vec::new();
                    collect_file_indices(&dir.children, &mut acc);
                    return Some((Some(dir_path), acc));
                }
                if let Some(found) = indices_under(&dir.children, id, &dir_path) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Append every descendant file's manifest index under `level`, in tree order.
fn collect_file_indices(level: &[Node], acc: &mut Vec<usize>) {
    for node in level {
        match node {
            Node::File(file) => acc.push(file.manifest_index),
            Node::Dir(dir) => collect_file_indices(&dir.children, acc),
        }
    }
}

/// Recursively toggle a folder by id within a child level; returns true if found.
fn toggle_in(level: &mut [Node], id: u64) -> bool {
    for node in level {
        if let Node::Dir(dir) = node {
            if dir.id == id {
                dir.expanded = !dir.expanded;
                return true;
            }
            if toggle_in(&mut dir.children, id) {
                return true;
            }
        }
    }
    false
}

/// Append render rows for a child level at `depth`, recursing into expanded folders.
fn push_rows(level: &[Node], depth: u32, out: &mut Vec<Row>) {
    for node in level {
        match node {
            Node::Dir(dir) => {
                out.push(Row {
                    id: dir.id,
                    depth,
                    label: dir.name.clone(),
                    size: String::new(),
                    kind: NodeKind::Folder,
                    expandable: !dir.children.is_empty(),
                    expanded: dir.expanded,
                    mine: false,
                    loading: false,
                    sharer: String::new(),
                    sharer_fingerprint: String::new(),
                });
                if dir.expanded {
                    push_rows(&dir.children, depth + 1, out);
                }
            }
            Node::File(file) => out.push(Row {
                id: file.id,
                depth,
                label: file.name.clone(),
                size: daemonseed_core::format::human_bytes(file.size),
                kind: NodeKind::File,
                expandable: false,
                expanded: false,
                mine: false,
                loading: false,
                sharer: String::new(),
                sharer_fingerprint: String::new(),
            }),
        }
    }
}

/// Recursively sort every level of a subtree into OS-browser order.
fn sort_tree(level: &mut [Node]) {
    sort_level(level);
    for node in level.iter_mut() {
        if let Node::Dir(dir) = node {
            sort_tree(&mut dir.children);
        }
    }
}

/// Sort one child level into OS-browser order: directories first, then files, each
/// group case-insensitively alphabetical (stable for equal keys).
fn sort_level(level: &mut [Node]) {
    level.sort_by(|a, b| {
        let rank = |n: &Node| match n {
            Node::Dir(_) => 0u8,
            Node::File(_) => 1u8,
        };
        let name = |n: &Node| match n {
            Node::Dir(d) => d.name.to_lowercase(),
            Node::File(f) => f.name.to_lowercase(),
        };
        rank(a).cmp(&rank(b)).then_with(|| name(a).cmp(&name(b)))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(rel: &str, size: u64, index: usize) -> ManifestRow {
        ManifestRow {
            rel_path: rel.to_owned(),
            size,
            index,
        }
    }

    #[test]
    fn empty_browser_has_no_rows() {
        let b = ShareBrowser::new();
        assert!(b.rows().is_empty());
    }

    #[test]
    fn set_shares_lists_collapsed_roots() {
        let mut b = ShareBrowser::new();
        b.set_shares(
            [
                ("id-a", "quiet-harbor", "alice", "#aa"),
                ("id-b", "amber-lantern", "bob", "#bb"),
            ],
            None,
        );
        let rows = b.rows();
        assert_eq!(
            rows.len(),
            2,
            "two collapsed share roots, no children shown"
        );
        assert!(
            rows.iter()
                .all(|r| r.depth == 0 && r.kind == NodeKind::Share)
        );
        assert!(rows.iter().all(|r| r.expandable && !r.expanded));
        assert_eq!(rows[0].label, "quiet-harbor");
        assert!(
            rows.iter().all(|r| !r.mine),
            "no my_handle → nothing is mine"
        );
    }

    #[test]
    fn my_handle_tags_only_the_exact_sharer() {
        let mut b = ShareBrowser::new();
        b.set_shares(
            [
                ("id-a", "mine", "me#11", ""),
                ("id-b", "theirs", "you#22", ""),
            ],
            Some("me#11"),
        );
        let rows = b.rows();
        assert!(rows[0].mine, "exact sharer-handle match → mine");
        assert!(!rows[1].mine);
    }

    #[test]
    fn foreign_share_surfaces_name_and_verified_fingerprint_own_share_neither() {
        // #114: a foreign row shows the (hash-less) handle as `sharer` and the
        // verified `#12hex` in `sharer_fingerprint` (revealed on hover); an own
        // share is tagged "you" by the UI, so both fields are empty.
        let mut b = ShareBrowser::new();
        b.set_shares(
            [
                ("id-them", "vacation", "river-otter", "#aabbccddeeff"),
                ("id-mine", "backups", "me", ""),
            ],
            Some("me"),
        );
        let rows = b.rows();
        assert_eq!(rows[0].sharer, "river-otter", "foreign handle, no hash");
        assert_eq!(
            rows[0].sharer_fingerprint, "#aabbccddeeff",
            "verified fingerprint revealed on hover"
        );
        assert!(rows[1].mine, "our own share");
        assert!(
            rows[1].sharer.is_empty() && rows[1].sharer_fingerprint.is_empty(),
            "own shares render \"you\" — no attribution fields"
        );
    }

    #[test]
    fn foreign_tui_sharer_handle_is_stripped_to_name_only() {
        // #173: a TUI client publishes its full `name#hash` as the share's
        // `sharer_handle` (a GUI client publishes the bare name). The browse row
        // must show name-only either way; the verified fingerprint rides on hover.
        let mut b = ShareBrowser::new();
        b.set_shares(
            [(
                "id-frank",
                "frank_music",
                "frank#a1b2c3d4e5f6",
                "#a1b2c3d4e5f6",
            )],
            Some("me"),
        );
        let rows = b.rows();
        assert_eq!(
            rows[0].sharer, "frank",
            "the #<12hex> is stripped from a name#hash sharer handle"
        );
        assert_eq!(
            rows[0].sharer_fingerprint, "#a1b2c3d4e5f6",
            "verified fingerprint still revealed on hover"
        );
    }

    #[test]
    fn foreign_floor_form_sharer_handle_renders_verbatim() {
        // A floor-form handle (`#<12hex>`, no display name) has no name to show —
        // the strip must leave it verbatim, not blank the row.
        let mut b = ShareBrowser::new();
        b.set_shares(
            [("id-anon", "mixtape", "#a1b2c3d4e5f6", "#a1b2c3d4e5f6")],
            Some("me"),
        );
        let rows = b.rows();
        assert_eq!(
            rows[0].sharer, "#a1b2c3d4e5f6",
            "a nameless floor handle renders unchanged, never empty"
        );
    }

    #[test]
    fn empty_my_handle_never_tags_mine() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "s", "", "")], Some(""));
        assert!(
            !b.rows()[0].mine,
            "empty handle must not match an empty sharer"
        );
    }

    #[test]
    fn expanding_an_unloaded_share_requests_a_fetch_and_shows_loading() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "quiet-harbor", "alice", "#aa")], None);
        let share_id = b.rows()[0].id;
        let t = b.toggle(share_id);
        assert_eq!(
            t.needs_fetch,
            Some(FetchRequest {
                share_id: "id-a".to_owned(),
                name: "quiet-harbor".to_owned(),
            }),
            "first expand of an unloaded share asks for its manifest"
        );
        let rows = b.rows();
        assert!(
            rows[0].expanded && rows[0].loading,
            "expanded, awaiting preview"
        );
        assert_eq!(rows.len(), 1, "no children until the manifest loads");
    }

    #[test]
    fn load_manifest_builds_a_dirs_first_alphabetical_tree() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        let share_id = b.rows()[0].id;
        b.toggle(share_id); // expand + request fetch
        b.load_manifest(
            "id-a",
            &[
                m("zeta.txt", 10, 0),
                m("reports/q3.pdf", 2048, 1),
                m("reports/img/chart.png", 4096, 2),
                m("alpha.md", 20, 3),
            ],
        );
        let rows = b.rows();
        // share + (reports folder) + zeta.txt? No — dirs first, then files alpha.
        // depth-0 share, depth-1: reports(dir), alpha.md(file), zeta.txt(file).
        assert_eq!(rows[0].kind, NodeKind::Share);
        assert_eq!(
            (rows[1].kind, rows[1].label.as_str()),
            (NodeKind::Folder, "reports")
        );
        assert!(
            rows[1].expandable && !rows[1].expanded,
            "folder collapsed by default"
        );
        assert_eq!(
            (rows[2].kind, rows[2].label.as_str()),
            (NodeKind::File, "alpha.md")
        );
        assert_eq!(rows[3].label, "zeta.txt");
        assert_eq!(rows.len(), 4, "collapsed folder hides its children");
        assert_eq!(rows[2].size, "20 B");
    }

    #[test]
    fn expanding_a_folder_reveals_its_children_at_increasing_depth() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        let share_id = b.rows()[0].id;
        b.toggle(share_id);
        b.load_manifest(
            "id-a",
            &[
                m("reports/q3.pdf", 2048, 0),
                m("reports/img/chart.png", 4096, 1),
            ],
        );
        let reports = b.rows()[1].id;
        b.toggle(reports);
        let rows = b.rows();
        // share / reports(dir,d1) / img(dir,d2) / q3.pdf(file,d2)
        assert_eq!(rows[1].label, "reports");
        assert!(rows[1].expanded);
        assert_eq!((rows[2].depth, rows[2].label.as_str()), (2, "img"));
        assert_eq!((rows[3].depth, rows[3].label.as_str()), (2, "q3.pdf"));
        assert_eq!(rows[3].size, "2.0 KB");
    }

    #[test]
    fn collapsing_a_loaded_share_hides_children_without_refetch() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        let share_id = b.rows()[0].id;
        b.toggle(share_id);
        b.load_manifest("id-a", &[m("a.txt", 1, 0)]);
        assert_eq!(b.rows().len(), 2, "share + one file");
        let t = b.toggle(share_id); // collapse
        assert_eq!(t.needs_fetch, None, "collapse never refetches");
        assert_eq!(b.rows().len(), 1, "children hidden");
        let t2 = b.toggle(share_id); // re-expand — already loaded
        assert_eq!(
            t2.needs_fetch, None,
            "re-expand of a loaded share never refetches"
        );
        assert_eq!(b.rows().len(), 2);
    }

    #[test]
    fn load_manifest_for_unknown_share_is_a_noop() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        b.load_manifest("id-gone", &[m("x", 1, 0)]); // refreshed away
        assert_eq!(b.rows().len(), 1, "no crash, no spurious rows");
    }

    #[test]
    fn toggle_unknown_id_is_a_quiet_noop() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        assert_eq!(b.toggle(99_999), Toggle::default());
    }

    #[test]
    fn refresh_reconciles_keeping_persisting_shares_and_dropping_vanished_ones() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "first", "a#a", "")], None);
        let first_id = b.rows()[0].id;
        // A refresh that adds id-b and keeps id-a: id-a's node identity is preserved.
        b.set_shares(
            [("id-a", "first", "a#a", ""), ("id-b", "second", "b#b", "")],
            None,
        );
        let rows = b.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, first_id, "a persisting share keeps its node id");
        assert!(
            rows[1].id != first_id,
            "a new share gets a fresh, never-reused id"
        );
        // A refresh where id-a vanished: it is dropped, id-b remains.
        b.set_shares([("id-b", "second", "b#b", "")], None);
        let rows = b.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "second");
    }

    #[test]
    fn refresh_preserves_expansion_and_loaded_subtree_of_a_persisting_share() {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        let share_id = b.rows()[0].id;
        b.toggle(share_id);
        b.load_manifest("id-a", &[m("docs/a.txt", 1, 0)]);
        let reports = b.rows()[1].id; // the "docs" folder
        b.toggle(reports); // open the folder
        let before = b.rows().len();
        assert_eq!(before, 3, "share / docs(open) / a.txt");
        // A poll/refresh that still lists id-a (a sibling appears too) must NOT
        // collapse the open tree — comparative-real-time without losing the user's view.
        b.set_shares(
            [("id-a", "share", "a#a", ""), ("id-z", "new", "z#z", "")],
            None,
        );
        let rows = b.rows();
        assert_eq!(rows[0].id, share_id, "id-a node preserved across refresh");
        assert!(rows[1].expanded, "the open folder stays open");
        assert!(
            rows.iter().any(|r| r.label == "a.txt"),
            "the loaded subtree survives the refresh (no refetch, no collapse)"
        );
        assert!(
            rows.iter().any(|r| r.label == "new"),
            "the new sibling appears"
        );
    }

    /// Build a loaded, fully-expanded share for fetch_target tests.
    fn loaded_share() -> (ShareBrowser, u64) {
        let mut b = ShareBrowser::new();
        b.set_shares([("id-a", "share", "a#a", "")], None);
        let share_id = b.rows()[0].id;
        b.toggle(share_id);
        b.load_manifest(
            "id-a",
            &[
                m("reports/q3.pdf", 2048, 0),
                m("reports/img/chart.png", 4096, 1),
                m("README.md", 64, 2),
            ],
        );
        (b, share_id)
    }

    #[test]
    fn fetch_target_for_a_share_root_is_the_whole_share() {
        let (b, share_id) = loaded_share();
        let t = b.fetch_target(share_id).expect("share resolves");
        assert_eq!(t.share_id, "id-a");
        assert_eq!(t.selected, None, "a share root downloads everything");
        assert_eq!(t.root_kind, crate::net::RootKind::Share);
    }

    #[test]
    fn fetch_target_for_a_file_is_its_single_manifest_index() {
        let (b, _) = loaded_share();
        let readme = b.rows().iter().find(|r| r.label == "README.md").unwrap().id;
        let t = b.fetch_target(readme).expect("file resolves");
        assert_eq!(t.selected, Some(vec![2]), "README.md is manifest index 2");
        assert_eq!(t.root_kind, crate::net::RootKind::File);
    }

    #[test]
    fn fetch_target_for_a_folder_is_all_its_descendant_files() {
        let (mut b, _) = loaded_share();
        let reports = b.rows().iter().find(|r| r.label == "reports").unwrap().id;
        let t = b.fetch_target(reports).expect("folder resolves");
        // reports/ holds q3.pdf (idx 0) and img/chart.png (idx 1) — both descendants.
        let mut got = t.selected.expect("folder selects a subset");
        got.sort_unstable();
        assert_eq!(got, vec![0, 1], "folder pulls every descendant file");
        assert_eq!(t.share_id, "id-a");
        // (F5) The toggled folder carries its OWN manifest-relative path.
        assert_eq!(t.root_kind, crate::net::RootKind::Dir("reports".to_owned()));

        // Expand `reports` so the nested `img` folder is a reachable row, then target
        // it: its FULL path accumulates to `reports/img` (not the bare leaf `img`) —
        // path accumulation is what keeps a nested folder's own place (F5).
        b.toggle(reports);
        let img = b.rows().iter().find(|r| r.label == "img").unwrap().id;
        let ti = b.fetch_target(img).expect("nested folder resolves");
        assert_eq!(ti.selected, Some(vec![1]), "img holds chart.png (idx 1)");
        assert_eq!(
            ti.root_kind,
            crate::net::RootKind::Dir("reports/img".to_owned())
        );
    }

    #[test]
    fn fetch_target_for_unknown_id_is_none() {
        let (b, _) = loaded_share();
        assert_eq!(b.fetch_target(987_654), None);
    }
}
