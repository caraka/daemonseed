//! Persistent landing zone for *fetched* share content — explicit downloads
//! (M15 C; ISC-C63 / ISC-C64 / ISC-C65, ISC-A-C31 / ISC-A-C32).
//!
//! The share-fetch path ([`crate::share_envelope`], the TUI `FetchShare` net
//! actor) verifies every chunk against its content address (ISC-S28 /
//! ISC-A-S20). This module persists a fully-verified fetch to disk as an
//! *explicit download*: the files land **directly, under their real names**, in
//! a per-share folder the user can open — no content-addressed store, no manual
//! extract step.
//!
//! ## At-rest posture — plaintext named downloads (M15 cleanup, 2026-06-06)
//!
//! A fetched chunk is a **plaintext byte run of a shared file** as the sharer
//! indexed it (since M16 a file is split into fixed
//! [`crate::share_serve::CHUNK_SIZE`] chunks of its raw bytes — ISC-C73 /
//! ISC-A-C35). The fetcher verifies each chunk, concatenates them in manifest
//! order, and writes the file back out under its original `rel_path`, so a
//! download is just *the files the user fetched, named the way they were
//! shared*. This is a deliberately larger at-rest surface than
//! the rest of the client (ISC-A-C1) — downloaded files are user-chosen
//! artifacts, not message/post/session history, so the no-client-history
//! invariant holds; the surface is the R-PANIC erasure target.
//!
//! **Why not a content-addressed store?** The original M15 C design persisted
//! chunks into a hex-named [`crate::storage::cas::FileChunkStore`] and required a
//! separate "extract" step. The pre-merge smoke test (2026-06-06) showed that
//! leaks implementation to the user — a `cas/` folder, hex filenames, stripped
//! extensions, `.rc` refcount sidecars, all shares mingled by dedup. A CAS earns
//! its keep on the *serve* side; for a fetcher's explicit downloads it is
//! over-engineering. So the fetcher writes named files directly instead. (A
//! future at-rest folder-encryption feature would wrap the whole `downloads/`
//! tree, additive and post-MVP.)
//!
//! ## Layout
//!
//! ```text
//! <root>/                      (e.g. <profile-root>/downloads)
//!   <share-name>/              one folder per fetched share, named by the share
//!     readme.txt               the files, real names, mirroring the rel_path tree
//!     sub/notes.md
//!   downloads.idx              a small manifest, for the browse pane
//! ```
//!
//! ## Manifest format (`downloads.idx`)
//!
//! A line-based text file (the same hand-rolled, dependency-free style as the
//! seeds directives — the workspace carries no `serde_json`). Variable fields
//! are hex-encoded so a name or path can never collide with the space delimiter:
//!
//! ```text
//! # daemonseed downloads manifest v2
//! S <share_id_hex> <name_hex> <folder_hex> <file_count>
//! F <rel_path_hex> <size_dec>
//! F ...
//! S ...
//! ```

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use oxicrypt_sha::sha384;

use crate::share_envelope::ManifestEntry;
use crate::share_serve::CHUNK_SIZE;
use crate::storage::cas::{CHUNK_ADDR_LEN, ChunkAddr, chunk_addr};

/// Manifest header — bumped if the on-disk format changes incompatibly.
const MANIFEST_HEADER: &str = "# daemonseed downloads manifest v2";

/// The reserved staging directory component under a downloads/destination root
/// (`<root>/.dspart/<share_id>/…`). No manifest `rel_path` may name it —
/// [`sanitize_rel_path`] refuses it — so a hostile sharer can neither collide
/// with an in-progress partial nor plant a file the sweep would delete
/// (download-subsystem redesign §Part 3; DL-ISC-18).
pub const STAGING_DIR: &str = ".dspart";

/// One downloaded file inside a [`FetchedShare`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedFile {
    /// The file's path relative to the share's download folder (the sharer's
    /// `rel_path`, `/`-separated). On disk it is written under its real name.
    pub rel_path: String,
    /// The file's size in bytes.
    pub size: u64,
}

/// A fetched share's record: what was downloaded under one `share_id`, and the
/// folder it landed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedShare {
    /// The server-assigned share id this content was fetched under (ISC-S21).
    pub share_id: String,
    /// The sharer-advertised display name (from the `PublicShareListing`).
    pub name: String,
    /// The folder under the downloads root the files landed in (a single safe
    /// path component, derived from `name`, collision-suffixed if needed).
    pub folder: String,
    /// One entry per downloaded file.
    pub files: Vec<FetchedFile>,
}

impl FetchedShare {
    /// Total bytes across all files in this fetched share.
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// Why a [`FetchedStore`] operation failed.
#[derive(Debug)]
pub enum FetchedError {
    /// Filesystem I/O failed.
    Io(std::io::Error),
    /// The manifest on disk was unparseable.
    Corrupt(String),
    /// A download was asked to write a file whose `rel_path` escapes its folder
    /// (`..`, an absolute path, or a root/prefix component). A hostile sharer's
    /// manifest must never write outside the share folder (ISC-A-C32).
    UnsafePath(String),
}

impl core::fmt::Display for FetchedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FetchedError::Io(e) => write!(f, "downloads-store I/O failed: {e}"),
            FetchedError::Corrupt(m) => write!(f, "downloads manifest corrupt: {m}"),
            FetchedError::UnsafePath(p) => {
                write!(
                    f,
                    "refusing to write a download path escaping its folder: {p}"
                )
            }
        }
    }
}

impl core::error::Error for FetchedError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FetchedError::Io(e) => Some(e),
            FetchedError::Corrupt(_) | FetchedError::UnsafePath(_) => None,
        }
    }
}

impl From<std::io::Error> for FetchedError {
    fn from(e: std::io::Error) -> Self {
        FetchedError::Io(e)
    }
}

/// One file's verified bytes, ready to persist: the sharer's `rel_path` and the
/// plaintext bytes the fetch verified against the content address.
pub struct VerifiedFile {
    /// The file's wire `rel_path` (untrusted; sanitised before it is written).
    pub rel_path: String,
    /// The verified plaintext file bytes.
    pub bytes: Vec<u8>,
}

/// The on-disk store of fetched share content — named files under a per-share
/// folder.
///
/// Open once with [`FetchedStore::open`]; [`record_share`](Self::record_share)
/// persists a completed fetch (writing named files), and
/// [`list_shares`](Self::list_shares) enumerates downloads for the browse view.
/// The files are already on disk under their real names, so there is no extract
/// step — the browse pane shows each share's folder.
pub struct FetchedStore {
    root: PathBuf,
}

/// An exclusive OS advisory lock over a downloads root's `downloads.idx`
/// read-modify-write. The GUI and TUI are separate binaries that can share one
/// non-portable downloads root, so an in-process mutex would not serialize them
/// (#208 / DL-ISC-9) — a `flock`/`LockFileEx` on a `.idx.lock` sibling does, and
/// the OS releases it if the holder dies (a crash mid-write cannot wedge it).
/// Held for the whole `record_share` RMW; released on drop.
struct IdxLock {
    _file: std::fs::File,
}

impl IdxLock {
    /// Block until the exclusive advisory lock on `<root>/.idx.lock` is held.
    fn acquire(root: &Path) -> Result<Self, FetchedError> {
        use fs4::fs_std::FileExt;
        let path = root.join(".idx.lock");
        // Refuse a symlink at the lock path: a co-resident attacker could point
        // it at a different inode so the GUI and TUI end up locking different
        // files, defeating the cross-process serialization. (An atomic
        // `O_NOFOLLOW` open would close the residual check-then-open window
        // without a platform-specific dependency; that hardening is tracked.)
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(FetchedError::UnsafePath(format!(
                "{} is a symlink; refusing to take the idx lock through it",
                path.display()
            )));
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        file.lock_exclusive()?;
        Ok(Self { _file: file })
    }
}

impl FetchedStore {
    /// Open (creating if absent) the downloads store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, FetchedError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The absolute path of the folder a recorded share's files live in.
    pub fn share_dir(&self, share: &FetchedShare) -> PathBuf {
        self.root.join(&share.folder)
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("downloads.idx")
    }

    /// Persist a fully-verified fetched share by writing its files, under their
    /// real names, into a per-share folder beneath the downloads root.
    ///
    /// **No-partial invariant (ISC-A-C31):** the caller invokes this only after
    /// the fetch has verified *every* chunk, so a poisoned or truncated download
    /// is never written. Re-recording the same `share_id` reuses its folder and
    /// overwrites the files (a re-fetch refreshes the download).
    ///
    /// **Path-traversal safe (ISC-A-C32):** the share folder is a single safe
    /// component derived from `name`, and every file's `rel_path` is validated
    /// to be strictly relative with only normal components before it is written.
    pub fn record_share(
        &mut self,
        share_id: &str,
        name: &str,
        files: &[VerifiedFile],
    ) -> Result<FetchedShare, FetchedError> {
        // Serialize the whole idx read-modify-write across processes (#208):
        // re-read UNDER the lock so a concurrent record_share cannot lose an
        // entry via a stale snapshot. Released when this guard drops.
        let _idx_lock = IdxLock::acquire(&self.root)?;
        let mut shares = self.list_shares()?;

        // Reuse this share's existing folder on a re-fetch; otherwise derive a
        // unique folder name from the share name (collision-suffixed by share_id).
        let folder = match shares.iter().find(|s| s.share_id == share_id) {
            Some(existing) => existing.folder.clone(),
            None => {
                let base = safe_folder_name(name);
                let taken: std::collections::BTreeSet<&str> =
                    shares.iter().map(|s| s.folder.as_str()).collect();
                if taken.contains(base.as_str()) {
                    let suffix: String = share_id.chars().take(6).collect();
                    format!("{base}-{suffix}")
                } else {
                    base
                }
            }
        };

        let share_dir = self.root.join(&folder);
        let mut recs = Vec::with_capacity(files.len());
        for vf in files {
            let safe = sanitize_rel_path(&vf.rel_path)?;
            let out = share_dir.join(&safe);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out, &vf.bytes)?;
            recs.push(FetchedFile {
                rel_path: vf.rel_path.clone(),
                size: vf.bytes.len() as u64,
            });
        }

        shares.retain(|s| s.share_id != share_id);
        let share = FetchedShare {
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            folder,
            files: recs,
        };
        shares.push(share.clone());
        self.write_manifest(&shares)?;
        Ok(share)
    }

    /// Register an ALREADY-PROMOTED managed download in `downloads.idx` without
    /// writing any file bytes (download-subsystem redesign, step 5). The shared
    /// engine ([`daemonseed_veilid_net::download::run_download`]) has already
    /// staged + promoted every file to `<root>/<folder>/<rel_path>`, so this only
    /// records the idx entry — unlike [`record_share`](Self::record_share), which
    /// writes bytes from an in-RAM [`VerifiedFile`] buffer (the pattern #207
    /// retired). `folder` is the caller's pre-resolved share folder (the
    /// `resolve_share_folder` policy: reuse the share's existing folder on a
    /// re-fetch, else collision-suffix), passed in so the on-disk promote target
    /// and the idx entry never disagree. The idx read-modify-write is serialized by
    /// the same cross-process advisory lock `record_share` uses (#208 / DL-ISC-9):
    /// re-read under the lock, replace this share's entry, write.
    pub fn register_share(
        &mut self,
        share_id: &str,
        name: &str,
        folder: &str,
        files: &[FetchedFile],
    ) -> Result<FetchedShare, FetchedError> {
        let _idx_lock = IdxLock::acquire(&self.root)?;
        let mut shares = self.list_shares()?;
        shares.retain(|s| s.share_id != share_id);
        let share = FetchedShare {
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            folder: folder.to_owned(),
            files: files.to_vec(),
        };
        shares.push(share.clone());
        self.write_manifest(&shares)?;
        Ok(share)
    }

    /// Enumerate every fetched share, in manifest order. `Ok(vec![])` when
    /// nothing has been fetched.
    pub fn list_shares(&self) -> Result<Vec<FetchedShare>, FetchedError> {
        let raw = match std::fs::read_to_string(self.manifest_path()) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(FetchedError::Io(e)),
        };
        parse_manifest(&raw)
    }

    fn write_manifest(&self, shares: &[FetchedShare]) -> Result<(), FetchedError> {
        let mut out = String::new();
        out.push_str(MANIFEST_HEADER);
        out.push('\n');
        for s in shares {
            out.push_str(&format!(
                "S {} {} {} {}\n",
                hex::encode(s.share_id.as_bytes()),
                hex::encode(s.name.as_bytes()),
                hex::encode(s.folder.as_bytes()),
                s.files.len(),
            ));
            for f in &s.files {
                out.push_str(&format!(
                    "F {} {}\n",
                    hex::encode(f.rel_path.as_bytes()),
                    f.size
                ));
            }
        }
        std::fs::write(self.manifest_path(), out)?;
        Ok(())
    }
}

/// Derive a safe single-component folder name from an untrusted share name.
/// Path separators and control chars become `_`; leading/trailing dots and
/// whitespace are trimmed; an empty or all-trimmed result falls back to
/// `"share"`. The result is always a single safe path component (ISC-A-C32).
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

/// Validate an untrusted wire `rel_path` and return the safe relative
/// [`PathBuf`] to join under the share folder. Rejects absolute paths, `..`,
/// `.`, and any root/prefix component — only `Component::Normal` survives
/// (ISC-A-C32).
fn sanitize_rel_path(rel: &str) -> Result<PathBuf, FetchedError> {
    if rel.is_empty() {
        return Err(FetchedError::UnsafePath(rel.to_owned()));
    }
    // A leading `/` is an absolute path. Reject it outright rather than silently
    // relativise it.
    if rel.starts_with('/') {
        return Err(FetchedError::UnsafePath(rel.to_owned()));
    }
    // The wire form is always `/`-separated; interpret it as such on every
    // platform rather than trusting the host separator.
    let mut safe = PathBuf::new();
    for seg in rel.split('/') {
        if seg.is_empty() {
            continue;
        }
        // The staging namespace is reserved — no manifest path may name it, so a
        // hostile `rel_path` can neither reach into the quarantine nor collide
        // with an in-progress partial (DL-ISC-18). Case-fold and strip trailing
        // dots/spaces first: Windows/macOS lookups are case-insensitive and Win32
        // strips trailing dots/spaces, so `.DSPART`, `.dspart.`, and `.dspart `
        // all alias the reserved dir on the target platforms.
        if seg
            .trim_end_matches(['.', ' '])
            .eq_ignore_ascii_case(STAGING_DIR)
        {
            return Err(FetchedError::UnsafePath(rel.to_owned()));
        }
        let p = Path::new(seg);
        let mut comps = p.components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(c)), None) => safe.push(c),
            _ => return Err(FetchedError::UnsafePath(rel.to_owned())),
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(FetchedError::UnsafePath(rel.to_owned()));
    }
    Ok(safe)
}

/// Rebase a fetch's selected share-relative paths so the *thing the user
/// selected* becomes the top-level entry under their chosen destination
/// (ISC-C68 layout). Used only for an explicit user-chosen dest — the managed
/// downloads dir keeps its namespaced `<share>/<rel_path>` layout.
///
/// The rule, derived from two pinned expectations:
///  - **Exactly one file** → its basename. Picking a single file drops it
///    directly in the dest, never recreating its share-internal folders.
///  - **Many files** → drop the longest common leading path prefix *minus its
///    last component*, i.e. keep the deepest directory common to the whole
///    selection as the top entry and preserve everything below it. Selecting an
///    `Artist/Album` folder lands `Album/<tracks…>`, not `Artist/Album/<tracks…>`.
///
/// Inputs are `/`-separated wire paths; outputs are `/`-separated and still
/// strictly relative (only leading components are dropped), so the per-file
/// `sanitize_rel_path` guard at write time remains the traversal authority.
pub fn rebase_to_selection_root(rel_paths: &[&str]) -> Vec<String> {
    match rel_paths {
        [] => Vec::new(),
        [only] => vec![only.rsplit('/').next().unwrap_or(only).to_owned()],
        _ => {
            let split: Vec<Vec<&str>> = rel_paths.iter().map(|p| p.split('/').collect()).collect();
            let min_len = split.iter().map(Vec::len).min().unwrap_or(0);
            // Longest run of leading components shared by every path.
            let mut common: usize = 0;
            'outer: for i in 0..min_len {
                let head = split[0][i];
                for s in &split[1..] {
                    if s[i] != head {
                        break 'outer;
                    }
                }
                common += 1;
            }
            // Keep the deepest shared directory: drop all but its last component.
            let drop = common.saturating_sub(1);
            split.iter().map(|c| c[drop..].join("/")).collect()
        }
    }
}

// ── Placement as a stated total function (download-subsystem redesign, step 4a) ──
//
// The old `rebase_to_selection_root` GUESSES the user's intent from path shapes
// (longest common prefix), which discards the actual selection: a folder holding
// exactly one file collapses to the bare filename, and a scattered selection
// recreates the full share-internal ancestry. The fix is at ingestion — carry the
// user's *selection roots* (the tree nodes actually toggled, ISC-C72) and make
// placement a total function of them (design `docs/design/download-subsystem.md`
// §Part 2). This is the user-chosen-dest layout; the managed downloads dir keeps
// the full `<share-folder>/<rel_path>` layout (`record_share`).

/// A node the user toggled in the fetch-preview tree — the unit "placement is a
/// function of" (ISC-C72). Share-relative, `/`-separated wire paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionRoot {
    /// A single selected file (its share `rel_path`).
    File(String),
    /// A selected directory subtree (its share `rel_path`). The empty string is
    /// the share root — "the whole share is selected".
    Dir(String),
}

impl SelectionRoot {
    fn path(&self) -> &str {
        match self {
            SelectionRoot::File(p) | SelectionRoot::Dir(p) => p,
        }
    }
}

/// Where one selected file lands: its share `rel_path` (what to fetch) and its
/// path relative to the user's chosen destination (`/`-separated, guard-checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedFile {
    /// The file's share-relative `rel_path`.
    pub share_rel: String,
    /// Where it lands, relative to the chosen destination.
    pub dest_rel: String,
}

/// `true` iff directory `d` is a strict ancestor of path `p` (component-wise).
/// The empty `d` (share root) is an ancestor of every non-empty path.
fn is_strict_ancestor(d: &str, p: &str) -> bool {
    if d == p {
        return false;
    }
    if d.is_empty() {
        return !p.is_empty();
    }
    p.strip_prefix(d).is_some_and(|rest| rest.starts_with('/'))
}

/// Everything up to and including a path's last `/` (its parent prefix), or ""
/// when the path has no `/` (a top-level name) or is the share root.
fn parent_prefix(dir: &str) -> &str {
    match dir.rfind('/') {
        Some(i) => &dir[..=i],
        None => "",
    }
}

fn basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_owned()
}

/// Drop any root nested inside another selected `Dir` root, and drop exact
/// duplicates — so overlapping selections (a dir plus a file within it, nested
/// dirs) are well-defined. Input order of the survivors is preserved (collision
/// suffixing depends on it).
fn normalize_roots(roots: &[SelectionRoot]) -> Vec<SelectionRoot> {
    let mut seen: std::collections::BTreeSet<(&str, &str)> = std::collections::BTreeSet::new();
    roots
        .iter()
        .filter(|r| {
            // strict-ancestor subsumption
            if roots.iter().any(|other| match other {
                SelectionRoot::Dir(d) => is_strict_ancestor(d, r.path()),
                SelectionRoot::File(_) => false,
            }) {
                return false;
            }
            // exact-duplicate dedup (keep first)
            let tag = match r {
                SelectionRoot::File(p) => ("F", p.as_str()),
                SelectionRoot::Dir(p) => ("D", p.as_str()),
            };
            seen.insert(tag)
        })
        .cloned()
        .collect()
}

/// The destination-relative path a file lands at under its governing root: a
/// `File` root drops to its basename; a `Dir` root keeps the root's own name and
/// everything below it (i.e. strips the root's parent prefix), so a selected
/// folder arrives whole (ratified item 2).
fn dest_rel_for(file_rel: &str, root: &SelectionRoot) -> String {
    match root {
        SelectionRoot::File(_) => basename(file_rel),
        SelectionRoot::Dir(d) => file_rel
            .strip_prefix(parent_prefix(d))
            .unwrap_or(file_rel)
            .to_owned(),
    }
}

/// The single top-level output name a root contributes under the dest, or `None`
/// for the whole-share root (which spreads to many top-level entries).
fn top_name_of(root: &SelectionRoot) -> Option<String> {
    match root {
        SelectionRoot::File(f) => Some(basename(f)),
        SelectionRoot::Dir(d) if d.is_empty() => None,
        SelectionRoot::Dir(d) => Some(basename(d)),
    }
}

fn governs(root: &SelectionRoot, file: &str) -> bool {
    match root {
        SelectionRoot::File(f) => f == file,
        SelectionRoot::Dir(d) => d.is_empty() || is_strict_ancestor(d, file),
    }
}

/// Reserve `base` in `taken`, or the first free `base-N` (N ≥ 2) — the between-
/// roots collision suffix (design table: `name-2`).
fn uniquify(base: &str, taken: &mut std::collections::BTreeSet<String>) -> String {
    if taken.insert(base.to_owned()) {
        return base.to_owned();
    }
    let mut n = 2usize;
    loop {
        let cand = format!("{base}-{n}");
        if taken.insert(cand.clone()) {
            return cand;
        }
        n += 1;
    }
}

fn replace_top(dest_rel: &str, new_top: &str) -> String {
    match dest_rel.split_once('/') {
        Some((_, rest)) => format!("{new_top}/{rest}"),
        None => new_top.to_owned(),
    }
}

/// Place each selected file under the user's chosen destination as a total
/// function of the selection roots (design §Part 2). Roots are normalized first
/// (nested subsumed, duplicates dropped); each file maps to its deepest governing
/// root; between-roots top-level name collisions suffix the later root (`name-2`).
/// Every computed destination-relative path passes the traversal guard as ONE
/// unit before it is returned (DL-ISC-18), so no root basename + subpath can
/// combine into an escape.
///
/// `selected_files` are the concrete share `rel_path`s being fetched (a `Dir`
/// root's subtree already expanded by the caller). Returns one [`PlacedFile`] per
/// selected file, in input order.
pub fn place_at_dest(
    roots: &[SelectionRoot],
    selected_files: &[&str],
) -> Result<Vec<PlacedFile>, FetchedError> {
    let roots = normalize_roots(roots);
    // Assign each root its unique top-level output name (whole-share root → None).
    let mut taken: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let assigned: Vec<Option<String>> = roots
        .iter()
        .map(|r| top_name_of(r).map(|base| uniquify(&base, &mut taken)))
        .collect();

    let mut out = Vec::with_capacity(selected_files.len());
    for &file in selected_files {
        let (idx, root) = roots
            .iter()
            .enumerate()
            .filter(|(_, r)| governs(r, file))
            .max_by_key(|(_, r)| r.path().len())
            .ok_or_else(|| {
                FetchedError::UnsafePath(format!("selected file {file} is under no selected root"))
            })?;
        let raw = dest_rel_for(file, root);
        let dest_rel = match &assigned[idx] {
            Some(top) => replace_top(&raw, top),
            None => raw, // whole-share: full rel_path, many top-level entries
        };
        // DL-ISC-18: the whole computed destination-relative path is guard-checked
        // as one unit before it can be joined under the dest.
        sanitize_rel_path(&dest_rel)?;
        out.push(PlacedFile {
            share_rel: file.to_owned(),
            dest_rel,
        });
    }
    Ok(out)
}

// ── Stage-then-promote staging writer (download-subsystem redesign, step 4b) ──
//
// A download writes each verified chunk into a reserved staging file at its
// manifest-derived byte OFFSET (files are pre-sized sparse; partial state is a
// SET of verified chunks, never a prefix), then PROMOTES the file to its final
// name only once every chunk has verified and the size matches. Unverified bytes
// never touch a final filename, even mid-download (design §Part 3). Promotion
// targets a no-clobber path (an existing unrelated file is never overwritten —
// DL-ISC-21), so a plain cross-platform `rename` to a fresh target suffices here;
// the overwrite-if-ours replace path (Windows `ReplaceFileW`) lands with resume
// (step 8), where a promote may legitimately replace its own prior partial.

/// Positional write of `bytes` at `offset` into `f` — a `pwrite`, so concurrent
/// writes of a file's chunks at distinct offsets are race-free (they do not share
/// a seek position).
fn pwrite_all(f: &std::fs::File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_all_at(bytes, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut rest, mut pos) = (bytes, offset);
        while !rest.is_empty() {
            let n = f.seek_write(rest, pos)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "seek_write wrote 0 bytes",
                ));
            }
            rest = &rest[n..];
            pos += n as u64;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut fc = f.try_clone()?;
        fc.seek(SeekFrom::Start(offset))?;
        fc.write_all(bytes)
    }
}

/// The injective, always-safe staging directory component for a `share_id`: hex
/// of its bytes. Two distinct share_ids can never collide onto one staging area
/// (the lossy [`safe_folder_name`] is many-to-one — `a/b` and `a_b` both fold to
/// `a_b`, all-dots to `share` — which would let two fetches share one quarantine
/// and cross-contaminate their partials).
fn staging_component(share_id: &str) -> String {
    hex::encode(share_id.as_bytes())
}

/// Atomically reserve the first free `name`/`name-N.ext` slot at `intended` by an
/// `O_EXCL` create, and return it — never overwriting a pre-existing file
/// (DL-ISC-21). Reserving with `create_new` closes the check-then-rename TOCTOU:
/// the caller renames the staged file ONTO this reservation (which it now
/// exclusively owns), so a concurrent promote that picks the same name loses the
/// `create_new` race and advances to the next suffix instead of clobbering. The
/// suffix goes before the extension so the file keeps its type.
fn reserve_no_clobber_target(intended: &Path) -> Result<PathBuf, FetchedError> {
    let parent = intended.parent().unwrap_or_else(|| Path::new("."));
    let stem = intended
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = intended.extension().and_then(|s| s.to_str());
    let mut n = 1usize;
    loop {
        let candidate = if n == 1 {
            intended.to_path_buf()
        } else {
            let name = match ext {
                Some(e) => format!("{stem}-{n}.{e}"),
                None => format!("{stem}-{n}"),
            };
            parent.join(name)
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                n = if n == 1 { 2 } else { n + 1 };
            }
            Err(e) => return Err(FetchedError::Io(e)),
        }
    }
}

/// A fetch's reserved staging area under a destination root:
/// `<root>/.dspart/<share_id>/<final-rel>`. Chunks are written verified at their
/// offsets ([`write_verified_chunk`](Self::write_verified_chunk)); a completed
/// file is [`promote`](Self::promote)d to `<root>/<final-rel>` (no-clobber); the
/// whole area is [`destroy`](Self::destroy)ed on an integrity abort or after
/// every file promotes. `<final-rel>` is what the caller computed for the
/// destination — the managed dir's `<share-folder>/<rel>` or a chosen dest's
/// [`PlacedFile::dest_rel`].
pub struct StagingArea {
    /// The destination root a completed file promotes under.
    root: PathBuf,
    /// `<root>/.dspart/<share_id>` — the quarantine for this fetch's partials.
    dir: PathBuf,
}

impl StagingArea {
    /// Open (creating) the staging area for `share_id` under `root`.
    pub fn open(root: impl Into<PathBuf>, share_id: &str) -> Result<Self, FetchedError> {
        let root = root.into();
        let dir = root.join(STAGING_DIR).join(staging_component(share_id));
        std::fs::create_dir_all(&dir)?;
        Ok(Self { root, dir })
    }

    /// This fetch's staging directory (`<root>/.dspart/<share_id>`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn staging_path(&self, final_rel: &str) -> Result<PathBuf, FetchedError> {
        Ok(self.dir.join(sanitize_rel_path(final_rel)?))
    }

    /// Pre-size a sparse staging file for `final_rel` at `size` bytes, so verified
    /// chunks can be written at their offsets in any order. Idempotent.
    pub fn preallocate(&self, final_rel: &str, size: u64) -> Result<(), FetchedError> {
        let path = self.staging_path(final_rel)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        f.set_len(size)?;
        Ok(())
    }

    /// Write one VERIFIED chunk's bytes into the staging file at its
    /// manifest-derived `offset`. The caller invokes this only after the chunk
    /// has passed its SHA-384 content-address check, so no unverified byte ever
    /// reaches disk (ISC-A-C31 intent). The file must have been
    /// [`preallocate`](Self::preallocate)d.
    pub fn write_verified_chunk(
        &self,
        final_rel: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), FetchedError> {
        let path = self.staging_path(final_rel)?;
        let f = std::fs::OpenOptions::new().write(true).open(&path)?;
        // Defence-in-depth: a chunk must land within the pre-sized file — never
        // extend it past the confirmed manifest's size (a hostile/mis-derived
        // offset must not silently grow the staged file). The caller supplies a
        // manifest-derived offset; verification is content-only, not positional.
        let allocated = f.metadata()?.len();
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > allocated)
        {
            return Err(FetchedError::Corrupt(format!(
                "chunk at offset {offset} (+{} bytes) exceeds the {allocated}-byte staged file",
                bytes.len()
            )));
        }
        pwrite_all(&f, offset, bytes)?;
        Ok(())
    }

    /// Promote a completed staging file to its final path under the destination
    /// root, never overwriting a pre-existing unrelated file (DL-ISC-21): the
    /// target is the first free `name`/`name-N` slot. Returns the final path.
    /// The caller promotes only once every chunk of the file has verified and the
    /// size matches the confirmed manifest.
    pub fn promote(&self, final_rel: &str) -> Result<PathBuf, FetchedError> {
        let staging = self.staging_path(final_rel)?;
        let intended = self.root.join(sanitize_rel_path(final_rel)?);
        if let Some(parent) = intended.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let target = reserve_no_clobber_target(&intended)?;
        std::fs::rename(&staging, &target)?;
        Ok(target)
    }

    /// Destroy this fetch's entire staging area — the integrity-abort disposition
    /// (every unpromoted partial of the fetch is erased) and the post-completion
    /// cleanup. Idempotent (a missing area is success).
    pub fn destroy(&self) -> Result<(), FetchedError> {
        match std::fs::remove_dir_all(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(FetchedError::Io(e)),
        }
    }

    /// The stored-confirmed-manifest path for this fetch. It lives INSIDE the
    /// staging dir under the reserved [`STAGING_DIR`] component
    /// (`<root>/.dspart/<share_id>/.dspart/manifest`) — a path no staged file can
    /// ever occupy, since [`sanitize_rel_path`] refuses a `.dspart` segment in any
    /// `final_rel` (DL-ISC-18). So a hostile manifest `rel_path` (even one named
    /// to alias the manifest) can neither collide with nor overwrite the stored
    /// manifest, and [`destroy`](Self::destroy) / the sweep clean it with the area.
    fn stored_manifest_path(&self) -> PathBuf {
        self.dir.join(STAGING_DIR).join("manifest")
    }

    /// Persist the user-confirmed manifest into this fetch's staging area (the
    /// deterministic canonical serialization — [`serialize_stored_manifest`]). A
    /// resume binds to this stored copy (DL-ISC-20): its digest is anchored in the
    /// profile's [`super::manifest_digest::ManifestDigestStore`] and re-verified
    /// before any reuse. Written via a temp sibling + rename so a crash mid-write
    /// cannot leave a half-written manifest.
    pub fn persist_manifest(&self, manifest: &[ManifestEntry]) -> Result<(), FetchedError> {
        let path = self.stored_manifest_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serialize_stored_manifest(manifest);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Read + deserialize the stored confirmed manifest. A missing file (no
    /// manifest was ever persisted) surfaces as [`FetchedError::Io`]
    /// (`NotFound`) and an unparseable one as [`FetchedError::Corrupt`] — never a
    /// silent empty manifest (fail-closed). Callers that must additionally prove
    /// the copy is untampered use [`verify_stored_manifest`], which chains this to
    /// the profile-anchored digest.
    pub fn read_stored_manifest(&self) -> Result<Vec<ManifestEntry>, FetchedError> {
        let bytes = std::fs::read(self.stored_manifest_path())?;
        deserialize_stored_manifest(&bytes)
    }
}

// ── Verified resume — fail-closed (download-subsystem redesign, step 8a) ──
//
// A resume is RE-DERIVATION, never trust (design §Part 3). The confirmed manifest
// is persisted into the fetch's staging area and its digest anchored in the
// profile's own trusted state (`super::manifest_digest`). Before any reuse the
// staging copy is re-verified against that digest (DL-ISC-20), and every retained
// byte on disk is re-hashed against its content address before it counts as
// present (DL-ISC-12). No sidecar/journal is trusted for content — only bytes that
// re-verify are kept; everything else is re-fetched.

/// The 48-byte SHA-384 that anchors a stored confirmed manifest's integrity.
pub const MANIFEST_DIGEST_LEN: usize = 48;

/// Magic + one-byte version prefix on the stored-manifest serialization. Bump the
/// trailing version byte on any incompatible format change so an old file fails
/// [`deserialize_stored_manifest`] closed rather than mis-parsing.
const STORED_MANIFEST_MAGIC: &[u8] = b"dsmanifest\x01";

/// Serialize a confirmed manifest to its DETERMINISTIC canonical bytes — the exact
/// byte string the [`manifest_digest`] covers. Deterministic because the field
/// order is fixed, every integer is big-endian and length-prefixed, and entries
/// (and each entry's chunk list) are emitted in slice order with no map iteration,
/// so an identical `&[ManifestEntry]` always serializes byte-identically.
///
/// Layout: `MAGIC | count(u32 BE) | entry×count`, where
/// `entry := rel_path_len(u32 BE) | rel_path_utf8 | size(u64 BE) |
/// chunk_count(u32 BE) | chunk_addr(48)×chunk_count`.
pub(crate) fn serialize_stored_manifest(manifest: &[ManifestEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(STORED_MANIFEST_MAGIC);
    out.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    for e in manifest {
        let path = e.rel_path.as_bytes();
        out.extend_from_slice(&(path.len() as u32).to_be_bytes());
        out.extend_from_slice(path);
        out.extend_from_slice(&e.size.to_be_bytes());
        out.extend_from_slice(&(e.chunks.len() as u32).to_be_bytes());
        for addr in &e.chunks {
            out.extend_from_slice(addr.as_bytes());
        }
    }
    out
}

/// Deserialize a stored manifest — fail-closed: a bad magic/version, a truncated
/// buffer, a length prefix past the buffer, a non-UTF-8 `rel_path`, or trailing
/// bytes all return [`FetchedError::Corrupt`], never a partial or empty parse.
pub(crate) fn deserialize_stored_manifest(
    bytes: &[u8],
) -> Result<Vec<ManifestEntry>, FetchedError> {
    fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], FetchedError> {
        if cur.len() < n {
            return Err(FetchedError::Corrupt(
                "stored manifest truncated".to_owned(),
            ));
        }
        let (head, tail) = cur.split_at(n);
        *cur = tail;
        Ok(head)
    }
    fn be_u32(cur: &mut &[u8]) -> Result<u32, FetchedError> {
        Ok(u32::from_be_bytes(take(cur, 4)?.try_into().unwrap()))
    }

    let mut cur = bytes;
    if take(&mut cur, STORED_MANIFEST_MAGIC.len())? != STORED_MANIFEST_MAGIC {
        return Err(FetchedError::Corrupt(
            "stored manifest bad magic/version".to_owned(),
        ));
    }
    let count = be_u32(&mut cur)? as usize;
    // Pre-alloc is capped so a hostile count field cannot force a giant Vec before
    // the (fail-fast) `take` calls run out of bytes; the loop still parses exactly
    // `count` entries or errors.
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let plen = be_u32(&mut cur)? as usize;
        let rel_path = String::from_utf8(take(&mut cur, plen)?.to_vec())
            .map_err(|_| FetchedError::Corrupt("stored manifest rel_path not UTF-8".to_owned()))?;
        let size = u64::from_be_bytes(take(&mut cur, 8)?.try_into().unwrap());
        let chunk_count = be_u32(&mut cur)? as usize;
        let mut chunks = Vec::with_capacity(chunk_count.min(4096));
        for _ in 0..chunk_count {
            let mut arr = [0u8; CHUNK_ADDR_LEN];
            arr.copy_from_slice(take(&mut cur, CHUNK_ADDR_LEN)?);
            chunks.push(ChunkAddr::from_bytes(arr));
        }
        out.push(ManifestEntry {
            rel_path,
            size,
            chunks,
        });
    }
    if !cur.is_empty() {
        return Err(FetchedError::Corrupt(
            "stored manifest has trailing bytes".to_owned(),
        ));
    }
    Ok(out)
}

/// SHA-384 over the [`serialize_stored_manifest`] bytes — the digest a resume
/// re-derives and compares against the profile-anchored copy (DL-ISC-20). The
/// only failure is SHA-384's power-up self-test not having passed (never on a real
/// download path).
pub fn manifest_digest(
    manifest: &[ManifestEntry],
) -> Result<[u8; MANIFEST_DIGEST_LEN], FetchedError> {
    let bytes = serialize_stored_manifest(manifest);
    let digest = sha384(&bytes)
        .map_err(|_| FetchedError::Corrupt("SHA-384 unavailable (self-test)".to_owned()))?;
    let mut out = [0u8; MANIFEST_DIGEST_LEN];
    out.copy_from_slice(&digest[..MANIFEST_DIGEST_LEN]);
    Ok(out)
}

/// Constant-time equality over two manifest digests — no data-dependent early
/// return (every byte folds into one accumulator).
fn digest_ct_eq(a: &[u8; MANIFEST_DIGEST_LEN], b: &[u8; MANIFEST_DIGEST_LEN]) -> bool {
    let mut acc = 0u8;
    for i in 0..MANIFEST_DIGEST_LEN {
        acc |= a[i] ^ b[i];
    }
    core::hint::black_box(acc) == 0
}

/// Verify a fetch's stored staging manifest against the profile-anchored digest,
/// FAIL-CLOSED (DL-ISC-20). Reads the staging copy, re-serializes + re-digests it,
/// and constant-time-compares to `expected_digest`. Any mismatch — a tampered or
/// swapped staging manifest, a missing staging manifest, or an unparseable one —
/// returns [`Err`]; a resume MUST halt on `Err` (re-gate on a fresh preview/
/// confirm) and never proceed on an unverified stored manifest. Returns the parsed
/// confirmed manifest only on a digest match.
pub fn verify_stored_manifest(
    staging: &StagingArea,
    expected_digest: &[u8; MANIFEST_DIGEST_LEN],
) -> Result<Vec<ManifestEntry>, FetchedError> {
    let manifest = staging.read_stored_manifest()?;
    let actual = manifest_digest(&manifest)?;
    if !digest_ct_eq(&actual, expected_digest) {
        return Err(FetchedError::Corrupt(
            "stored manifest digest does not match the profile-anchored digest".to_owned(),
        ));
    }
    Ok(manifest)
}

/// The byte region chunk `index` covers for a file of `size` bytes:
/// `[index*CHUNK_SIZE, min((index+1)*CHUNK_SIZE, size))`. Returns `(offset, len)`;
/// `len` is 0 for an out-of-range index (offset ≥ size).
fn chunk_region(index: usize, size: u64) -> (u64, u64) {
    let cs = CHUNK_SIZE as u64;
    let offset = (index as u64).saturating_mul(cs);
    if offset >= size {
        return (offset, 0);
    }
    (offset, offset.saturating_add(cs).min(size) - offset)
}

/// Positional read of exactly `buf.len()` bytes at `offset` — a `pread`, so it
/// shares no seek position with concurrent writers.
fn pread_exact(f: &std::fs::File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut rest, mut pos) = (buf, offset);
        while !rest.is_empty() {
            match f.seek_read(rest, pos)? {
                0 => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "seek_read returned 0 before filling the buffer",
                    ));
                }
                n => {
                    rest = &mut rest[n..];
                    pos += n as u64;
                }
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut fc = f.try_clone()?;
        fc.seek(SeekFrom::Start(offset))?;
        fc.read_exact(buf)
    }
}

/// Read the exact `[offset, offset+len)` region from `path`, or `Err` if the file
/// is shorter than the region (a sparse/truncated tail) or unreadable.
fn read_region(path: &Path, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let file_len = f.metadata()?.len();
    if offset.checked_add(len).is_none_or(|end| end > file_len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "chunk region past end of file",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    pread_exact(&f, offset, &mut buf)?;
    Ok(buf)
}

/// Whether the bytes of chunk `(offset, len)` at `path` re-hash to `addr`. A
/// missing path, a short/sparse region, an unreadable file, or a hash mismatch
/// all read as "does not verify" — never as verified.
fn chunk_verifies(path: Option<&Path>, offset: u64, len: u64, addr: &ChunkAddr) -> bool {
    let Some(path) = path else {
        return false;
    };
    let Ok(bytes) = read_region(path, offset, len) else {
        return false;
    };
    chunk_addr(&bytes).is_ok_and(|a| &a == addr)
}

/// One file's resume state, RE-DERIVED from bytes on disk (never from
/// bookkeeping). `verified` and `missing` partition `0..total_chunks` as a SET —
/// there is NO prefix assumption, so a later chunk can be present while an earlier
/// one is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResume {
    /// The file's placement-resolved on-disk path (relative to the dest root for a
    /// promoted file, and to the staging dir for a partial).
    pub rel_path: String,
    /// The file's confirmed size in bytes.
    pub size: u64,
    /// The file's total chunk count (the stored manifest's chunk-list length).
    pub total_chunks: usize,
    /// Chunk indices whose bytes re-verify IN STAGING against their content address
    /// — the chunks a resume can SKIP fetching. Staging-authoritative: the engine
    /// promotes the staging file, so a skippable chunk MUST be present in staging,
    /// NOT merely at the promoted dest (a promoted-only chunk would become a sparse
    /// zero-hole on promote). Sorted ascending.
    pub verified: Vec<usize>,
    /// Chunk indices to (re-)fetch — not present+verified in staging (mismatched,
    /// short, sparse/unwritten, unreadable, or present only at the promoted dest).
    /// Sorted ascending.
    pub missing: Vec<usize>,
    /// The file is ALREADY fully present + verified at its promoted dest path
    /// (`dest_root/<rel_path>`) at the exact confirmed size — content-checked chunk
    /// by chunk, not length-only. When true the resume keeps the dest file as-is (no
    /// fetch, no re-promote). DISTINCT from `verified` (staging): the engine can only
    /// skip chunks that live in staging, so a partially-good promoted file is not
    /// trusted here — its chunks are re-fetched into staging.
    pub promoted_complete: bool,
}

impl FileResume {
    /// Whether the resume needs to fetch nothing for this file — it is already fully
    /// present + verified, either at its promoted dest (`promoted_complete`) or as a
    /// complete staging file (`missing.is_empty()`).
    pub fn is_complete(&self) -> bool {
        self.promoted_complete || self.missing.is_empty()
    }
}

/// A resume's per-file plan: which chunks verify on disk and which must be
/// (re-)fetched, for every file in the confirmed manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumePlan {
    /// One entry per manifest file, in manifest order.
    pub files: Vec<FileResume>,
}

impl ResumePlan {
    /// Whether every file is already complete (a resume would fetch nothing).
    pub fn is_complete(&self) -> bool {
        self.files.iter().all(FileResume::is_complete)
    }

    /// Total chunks that re-verified on disk across all files (feeds resumed
    /// progress — the bar resumes ahead rather than restarting).
    pub fn verified_chunk_count(&self) -> usize {
        self.files.iter().map(|f| f.verified.len()).sum()
    }

    /// Total chunks that must be (re-)fetched across all files.
    pub fn missing_chunk_count(&self) -> usize {
        self.files.iter().map(|f| f.missing.len()).sum()
    }
}

/// Re-derive a resume plan for `manifest` from bytes on disk (DL-ISC-12). Each chunk
/// region (`[i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size))`, boundaries from
/// `CHUNK_SIZE` + the stored `size`, never from the file self-describing) is
/// re-hashed against the stored content address. Two locations, two DISTINCT roles:
///
/// - `verified`/`missing` partition the chunks by their presence IN STAGING
///   (`staging/<rel_path>`) — the chunks the engine can SKIP, because it promotes the
///   staging file. A chunk verified only at the promoted dest is NOT skippable
///   (skipping it would promote a sparse zero-hole), so it is `missing` and re-fetched.
/// - `promoted_complete` is the fast-path: the file is ALREADY fully present +
///   verified at `dest_root/<rel_path>` (every chunk content-checked, exact size), so
///   the resume keeps it as-is.
///
/// A chunk that mismatches, is short/sparse, or is unreadable is MISSING. No on-disk
/// byte is ever reused without re-verifying its content address AT USE — the engine
/// skips only staging-present chunks, and `promoted_complete` re-hashes every chunk.
///
/// `manifest`'s entries must carry the file's placement-resolved on-disk `rel_path`
/// (what the download staged/promoted under); the caller re-paths the digest-verified
/// confirmed manifest into placement space before calling.
pub fn derive_resume_state(
    manifest: &[ManifestEntry],
    dest_root: &Path,
    staging: &StagingArea,
) -> ResumePlan {
    let file_len = |p: &Path| std::fs::metadata(p).ok().map(|m| m.len());
    let files = manifest
        .iter()
        .map(|entry| {
            // Coverage guard (mirrors the engine's DL-ISC-11 fresh-download check): the
            // chunk list MUST exactly tile `[0, size)` — `chunks.len() ==
            // ceil(size / CHUNK_SIZE)`. A malformed entry (a hostile `{size: 2*CS,
            // chunks: [one]}` leaves `[CS, 2*CS)` uncovered) is NEVER resumed-as-complete:
            // every chunk is marked missing so the re-fetch path re-derives it and the
            // engine's coverage guard rejects a hostile manifest. Without this, a
            // "fully verified" file could carry an unverified sparse tail (xhigh review F1).
            let expected_chunks = entry.size.div_ceil(CHUNK_SIZE as u64) as usize;
            if entry.chunks.len() != expected_chunks {
                return FileResume {
                    rel_path: entry.rel_path.clone(),
                    size: entry.size,
                    total_chunks: entry.chunks.len(),
                    verified: Vec::new(),
                    missing: (0..entry.chunks.len()).collect(),
                    promoted_complete: false,
                };
            }
            // Exact-length gate: a candidate file is trusted only if it is EXACTLY
            // `size` bytes. A co-resident append past `size` would otherwise ride along
            // as unverified content beyond the last chunk's region; a short file fails
            // the last chunk's read anyway (xhigh review F1).
            //
            // STAGING-authoritative `verified`: the engine promotes the STAGING file,
            // so a chunk is skippable (already_verified) ONLY if it re-verifies in
            // staging. A chunk present only at the promoted dest is `missing` and
            // re-fetched — skipping it would promote a sparse zero-hole (xhigh review,
            // 8b-1 location-mismatch finding).
            let staged = staging
                .staging_path(&entry.rel_path)
                .ok()
                .filter(|p| file_len(p) == Some(entry.size));
            let mut verified = Vec::new();
            let mut missing = Vec::new();
            for (i, addr) in entry.chunks.iter().enumerate() {
                let (offset, len) = chunk_region(i, entry.size);
                if chunk_verifies(staged.as_deref(), offset, len, addr) {
                    verified.push(i);
                } else {
                    missing.push(i);
                }
            }
            // Promoted fast-path (CONTENT-checked, not length-only): the file is
            // already complete at its dest path iff it exists at exact size AND every
            // chunk re-verifies there. Separate from staging — a partially-good promoted
            // file is not trusted here (its chunks re-fetch into staging).
            let promoted_complete = sanitize_rel_path(&entry.rel_path)
                .ok()
                .map(|rel| dest_root.join(rel))
                .filter(|p| file_len(p) == Some(entry.size))
                .is_some_and(|p| {
                    entry.chunks.iter().enumerate().all(|(i, addr)| {
                        let (offset, len) = chunk_region(i, entry.size);
                        chunk_verifies(Some(&p), offset, len, addr)
                    })
                });
            FileResume {
                rel_path: entry.rel_path.clone(),
                size: entry.size,
                total_chunks: entry.chunks.len(),
                verified,
                missing,
                promoted_complete,
            }
        })
        .collect();
    ResumePlan { files }
}

// ── Live-fetch registry + staging sweep (download-subsystem redesign, step 4c) ──
//
// A startup/idle sweep reclaims UNRESUMABLE staging debris (e.g. a crash before
// the confirmed manifest persisted) but must never delete state belonging to a
// registered in-flight or resuming fetch. The sweep skips any share_id in the
// registry or that the caller's resumable predicate keeps — never deletes on a
// name pattern alone (design §Part 3; DL-ISC-22).
//
// CALLER CONTRACT (not enforced here): the registry check and the delete are not
// one atomic step, so a `register()` that races an in-flight sweep is not ordered
// by this code. The caller must ensure a resume registers BEFORE a sweep can see
// its staging — run the sweep at startup / idle when no fetch is registering, or
// coordinate them externally. The step-5/6 wiring owns that ordering.

/// The `share_id`s whose fetches are in-flight or resuming in THIS process,
/// REFERENCE-COUNTED so overlapping registrations of one id (a re-fetch that
/// starts before the prior fetch's guard drops) each hold it active until the
/// LAST guard drops. Cheap to clone (shared inner map); the staging sweep
/// consults it.
#[derive(Clone, Default)]
pub struct LiveFetchRegistry {
    active: Arc<Mutex<HashMap<String, usize>>>,
}

impl LiveFetchRegistry {
    /// A new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `share_id` as an active fetch; the returned guard drops its
    /// reference on drop (the id stays active while any guard for it lives).
    pub fn register(&self, share_id: &str) -> LiveFetchGuard {
        *self
            .active
            .lock()
            .unwrap()
            .entry(share_id.to_owned())
            .or_insert(0) += 1;
        LiveFetchGuard {
            registry: self.clone(),
            share_id: share_id.to_owned(),
        }
    }

    /// Whether `share_id` has any active registration.
    pub fn is_active(&self, share_id: &str) -> bool {
        self.active
            .lock()
            .unwrap()
            .get(share_id)
            .is_some_and(|&c| c > 0)
    }
}

/// Keeps one reference to a `share_id`'s active registration for its lifetime;
/// drops that reference (freeing the id for the sweep only once the last guard
/// drops) on drop.
pub struct LiveFetchGuard {
    registry: LiveFetchRegistry,
    share_id: String,
}

impl Drop for LiveFetchGuard {
    fn drop(&mut self) {
        let mut active = self.registry.active.lock().unwrap();
        if let Some(count) = active.get_mut(&self.share_id) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.share_id);
            }
        }
    }
}

/// Decode a staging directory component (`hex(share_id)`) back to its raw
/// `share_id`, or `None` if the component is not one of our staging dirs.
fn decode_staging_component(component: &str) -> Option<String> {
    let bytes = hex::decode(component).ok()?;
    String::from_utf8(bytes).ok()
}

/// Reclaim UNRESUMABLE staging debris under `<root>/.dspart/`: delete every
/// `<share_id>` staging dir that is NEITHER registered as an active fetch
/// (`registry`) NOR resumable (`is_resumable(share_id)` — the caller's check
/// that a stored confirmed manifest exists for it). A directory whose name is
/// not a valid staging component is foreign and left untouched. Returns the
/// deleted staging dirs (DL-ISC-22).
pub fn sweep_staging(
    root: &Path,
    registry: &LiveFetchRegistry,
    is_resumable: impl Fn(&str) -> bool,
) -> Result<Vec<PathBuf>, FetchedError> {
    let staging_root = root.join(STAGING_DIR);
    let entries = match std::fs::read_dir(&staging_root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(FetchedError::Io(e)),
    };
    let mut deleted = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(share_id) = decode_staging_component(&name.to_string_lossy()) else {
            // Not one of our staging dirs (foreign / not hex) — never delete on a
            // name pattern alone.
            continue;
        };
        if registry.is_active(&share_id) || is_resumable(&share_id) {
            continue;
        }
        std::fs::remove_dir_all(entry.path())?;
        deleted.push(entry.path());
    }
    Ok(deleted)
}

fn parse_manifest(raw: &str) -> Result<Vec<FetchedShare>, FetchedError> {
    let mut shares = Vec::new();
    let mut lines = raw.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(' ');
        match parts.next() {
            Some("S") => {
                let share_id = next_hex_str(&mut parts, "share_id")?;
                let name = next_hex_str(&mut parts, "name")?;
                let folder = next_hex_str(&mut parts, "folder")?;
                let count: usize = parts
                    .next()
                    .ok_or_else(|| FetchedError::Corrupt("S line missing file count".to_owned()))?
                    .parse()
                    .map_err(|_| {
                        FetchedError::Corrupt("S line file count not a number".to_owned())
                    })?;
                let mut files = Vec::with_capacity(count);
                for _ in 0..count {
                    let fline = lines.next().ok_or_else(|| {
                        FetchedError::Corrupt("manifest ended mid-share".to_owned())
                    })?;
                    files.push(parse_file_line(fline.trim())?);
                }
                shares.push(FetchedShare {
                    share_id,
                    name,
                    folder,
                    files,
                });
            }
            Some(other) => {
                return Err(FetchedError::Corrupt(format!(
                    "unexpected manifest record `{other}`"
                )));
            }
            None => continue,
        }
    }
    Ok(shares)
}

fn parse_file_line(line: &str) -> Result<FetchedFile, FetchedError> {
    let mut parts = line.split(' ');
    match parts.next() {
        Some("F") => {}
        _ => {
            return Err(FetchedError::Corrupt(format!(
                "expected F line, got `{line}`"
            )));
        }
    }
    let rel_path = next_hex_str(&mut parts, "rel_path")?;
    let size: u64 = parts
        .next()
        .ok_or_else(|| FetchedError::Corrupt("F line missing size".to_owned()))?
        .parse()
        .map_err(|_| FetchedError::Corrupt("F line size not a number".to_owned()))?;
    Ok(FetchedFile { rel_path, size })
}

fn next_hex_str<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    field: &str,
) -> Result<String, FetchedError> {
    let token = parts
        .next()
        .ok_or_else(|| FetchedError::Corrupt(format!("missing {field}")))?;
    let bytes =
        hex::decode(token).map_err(|_| FetchedError::Corrupt(format!("{field} not hex")))?;
    String::from_utf8(bytes).map_err(|_| FetchedError::Corrupt(format!("{field} not UTF-8")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vf(rel: &str, bytes: &[u8]) -> VerifiedFile {
        VerifiedFile {
            rel_path: rel.to_owned(),
            bytes: bytes.to_vec(),
        }
    }

    /// ISC-C68 layout — a single selected file lands as its bare basename, no
    /// matter how deep it sat in the share.
    #[test]
    fn rebase_single_file_is_basename() {
        assert_eq!(
            rebase_to_selection_root(&["Music/Artist/Album/track.mp3"]),
            vec!["track.mp3".to_owned()]
        );
        // A file already at the share root is unchanged.
        assert_eq!(
            rebase_to_selection_root(&["song.flac"]),
            vec!["song.flac".to_owned()]
        );
    }

    /// ISC-C68 layout — selecting a folder keeps the deepest folder common to
    /// the selection as the top entry (`Album/…`), dropping its ancestors and
    /// preserving structure below it.
    #[test]
    fn rebase_folder_keeps_deepest_common_dir() {
        let out = rebase_to_selection_root(&[
            "Music/Artist/Album/01.mp3",
            "Music/Artist/Album/02.mp3",
            "Music/Artist/Album/disc2/03.mp3",
        ]);
        assert_eq!(
            out,
            vec![
                "Album/01.mp3".to_owned(),
                "Album/02.mp3".to_owned(),
                "Album/disc2/03.mp3".to_owned(),
            ]
        );
    }

    /// A messy multi-album selection keeps their shared parent (`Artist/…`) so
    /// the two albums stay disambiguated under the dest.
    #[test]
    fn rebase_disjoint_selection_keeps_shared_parent() {
        let out =
            rebase_to_selection_root(&["Music/Artist/AlbumA/01.mp3", "Music/Artist/AlbumB/01.mp3"]);
        assert_eq!(
            out,
            vec![
                "Artist/AlbumA/01.mp3".to_owned(),
                "Artist/AlbumB/01.mp3".to_owned(),
            ]
        );
    }

    /// Files sharing no leading directory land directly under the dest, each
    /// keeping its own top folder (nothing to strip).
    #[test]
    fn rebase_no_common_prefix_is_untouched() {
        let out = rebase_to_selection_root(&["a/x.txt", "b/y.txt"]);
        assert_eq!(out, vec!["a/x.txt".to_owned(), "b/y.txt".to_owned()]);
    }

    #[test]
    fn rebase_empty_selection_is_empty() {
        assert!(rebase_to_selection_root(&[]).is_empty());
    }

    // ── place_at_dest — the selection-root total function (step 4a, DL-ISC-7/18) ──

    fn dests(placed: &[PlacedFile]) -> Vec<String> {
        placed.iter().map(|p| p.dest_rel.clone()).collect()
    }

    /// DL-ISC-7: a single selected file lands as its bare basename.
    #[test]
    fn place_single_file_is_basename() {
        let placed = place_at_dest(
            &[SelectionRoot::File(
                "Music/Artist/Album/track.mp3".to_owned(),
            )],
            &["Music/Artist/Album/track.mp3"],
        )
        .unwrap();
        assert_eq!(dests(&placed), vec!["track.mp3".to_owned()]);
    }

    /// DL-ISC-7: a folder holding exactly ONE file keeps its folder (the reproduced
    /// case the old shape-guessing `rebase_to_selection_root` collapsed to a bare
    /// filename).
    #[test]
    fn place_one_file_folder_keeps_its_folder() {
        let placed = place_at_dest(
            &[SelectionRoot::Dir("Music/Artist/Album".to_owned())],
            &["Music/Artist/Album/only.mp3"],
        )
        .unwrap();
        assert_eq!(dests(&placed), vec!["Album/only.mp3".to_owned()]);
        // Contrast: the legacy shape-guesser collapsed this to the bare basename.
        assert_eq!(
            rebase_to_selection_root(&["Music/Artist/Album/only.mp3"]),
            vec!["only.mp3".to_owned()]
        );
    }

    /// DL-ISC-7: a scattered selection (two folders from different parents) lands
    /// each selected folder as a top-level entry — NOT recreating the full
    /// share-internal ancestry (the reproduced scattered-selection defect).
    #[test]
    fn place_scattered_folders_each_top_level() {
        let placed = place_at_dest(
            &[
                SelectionRoot::Dir("Music/RockBand".to_owned()),
                SelectionRoot::Dir("Podcasts/SciShow".to_owned()),
            ],
            &["Music/RockBand/01.mp3", "Podcasts/SciShow/ep1.mp3"],
        )
        .unwrap();
        assert_eq!(
            dests(&placed),
            vec!["RockBand/01.mp3".to_owned(), "SciShow/ep1.mp3".to_owned()]
        );
    }

    /// DL-ISC-7: the whole-share root keeps every file's full rel_path (top-level
    /// entries of the share land directly under the dest).
    #[test]
    fn place_whole_share_keeps_full_paths() {
        let placed = place_at_dest(
            &[SelectionRoot::Dir(String::new())],
            &["a/x.txt", "b/y.txt", "top.md"],
        )
        .unwrap();
        assert_eq!(
            dests(&placed),
            vec![
                "a/x.txt".to_owned(),
                "b/y.txt".to_owned(),
                "top.md".to_owned()
            ]
        );
    }

    /// DL-ISC-7: overlapping roots are normalized — a file root nested inside a
    /// selected dir root is subsumed, so the dir governs all its files (the folder
    /// arrives whole).
    #[test]
    fn place_normalizes_nested_roots() {
        let placed = place_at_dest(
            &[
                SelectionRoot::Dir("Music".to_owned()),
                SelectionRoot::File("Music/Artist/track.mp3".to_owned()),
            ],
            &["Music/Artist/track.mp3", "Music/other.mp3"],
        )
        .unwrap();
        assert_eq!(
            dests(&placed),
            vec![
                "Music/Artist/track.mp3".to_owned(),
                "Music/other.mp3".to_owned()
            ]
        );
    }

    /// DL-ISC-7: two roots whose basenames collide suffix the LATER root (`name-2`),
    /// so they stay disambiguated under the dest.
    #[test]
    fn place_suffixes_between_root_collisions() {
        let placed = place_at_dest(
            &[
                SelectionRoot::Dir("A/Live".to_owned()),
                SelectionRoot::Dir("B/Live".to_owned()),
            ],
            &["A/Live/1.mp3", "B/Live/2.mp3"],
        )
        .unwrap();
        assert_eq!(
            dests(&placed),
            vec!["Live/1.mp3".to_owned(), "Live-2/2.mp3".to_owned()]
        );
    }

    /// DL-ISC-18: the WHOLE computed destination-relative path is guard-checked as
    /// one unit — a hostile file `rel_path` under a selected dir that would combine
    /// into an escape is refused, not written.
    #[test]
    fn place_guards_the_full_computed_path() {
        let err = place_at_dest(
            &[SelectionRoot::Dir("Music".to_owned())],
            &["Music/../../etc/passwd"],
        )
        .unwrap_err();
        assert!(matches!(err, FetchedError::UnsafePath(_)));
    }

    // ── StagingArea — stage-then-promote (step 4b, DL-ISC-11/18/21) ──

    /// DL-ISC-11: chunks are written at their offsets into the reserved staging
    /// namespace (in ANY order — a set, not a prefix); the final name appears only
    /// on promote, after the file is complete. Mid-download nothing sits under a
    /// final name.
    #[test]
    fn staging_writes_at_offsets_then_promotes() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let staging = StagingArea::open(root, "abc123share").unwrap();
        staging.preallocate("sub/f.bin", 10).unwrap();
        // Write the two halves out of order — offsets, not a prefix.
        staging
            .write_verified_chunk("sub/f.bin", 5, b"BBBBB")
            .unwrap();
        staging
            .write_verified_chunk("sub/f.bin", 0, b"AAAAA")
            .unwrap();

        // Mid-download: bytes live ONLY in the staging namespace, never under the
        // final name.
        assert!(
            !root.join("sub/f.bin").exists(),
            "no final name mid-download"
        );
        assert!(
            staging.dir().join("sub/f.bin").exists(),
            "staged under .dspart"
        );
        assert!(root.join(STAGING_DIR).is_dir());

        let final_path = staging.promote("sub/f.bin").unwrap();
        assert_eq!(final_path, root.join("sub/f.bin"));
        assert_eq!(std::fs::read(&final_path).unwrap(), b"AAAAABBBBB");
        // The staging copy is gone after promotion (renamed, not copied).
        assert!(!staging.dir().join("sub/f.bin").exists());
    }

    /// DL-ISC-18 (full): the reserved `.dspart` staging component is refused in any
    /// manifest `rel_path` — via `sanitize_rel_path`, `record_share`, and
    /// `place_at_dest` — so no manifest can reach into the quarantine.
    #[test]
    fn staging_namespace_is_refused_in_manifest_paths() {
        assert!(sanitize_rel_path(".dspart").is_err());
        assert!(sanitize_rel_path(".dspart/evil.txt").is_err());
        assert!(sanitize_rel_path("sub/.dspart/evil.txt").is_err());
        // A normal dotfile that merely CONTAINS the string is fine.
        assert!(sanitize_rel_path("my.dspartner/notes.txt").is_ok());

        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        let err = store
            .record_share("s", "s", &[vf(".dspart/x", b"pwn")])
            .unwrap_err();
        assert!(matches!(err, FetchedError::UnsafePath(_)));

        let err =
            place_at_dest(&[SelectionRoot::Dir(String::new())], &[".dspart/planted"]).unwrap_err();
        assert!(matches!(err, FetchedError::UnsafePath(_)));
    }

    /// DL-ISC-21: promotion never overwrites a pre-existing unrelated file — it
    /// lands at the first free `name-N` slot (suffix before the extension), and the
    /// pre-existing file is untouched.
    #[test]
    fn promote_never_clobbers_a_preexisting_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        std::fs::write(root.join("track.mp3"), b"ORIGINAL").unwrap();

        let staging = StagingArea::open(root, "share1").unwrap();
        staging.preallocate("track.mp3", 3).unwrap();
        staging
            .write_verified_chunk("track.mp3", 0, b"NEW")
            .unwrap();
        let final_path = staging.promote("track.mp3").unwrap();

        assert_eq!(
            final_path,
            root.join("track-2.mp3"),
            "suffix before the extension"
        );
        assert_eq!(
            std::fs::read(root.join("track.mp3")).unwrap(),
            b"ORIGINAL",
            "untouched"
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), b"NEW");
    }

    /// The integrity-abort disposition: `destroy` erases the whole staging area
    /// (every unpromoted partial), and is idempotent.
    #[test]
    fn destroy_erases_the_staging_area() {
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "share2").unwrap();
        staging.preallocate("a.bin", 4).unwrap();
        staging.write_verified_chunk("a.bin", 0, b"data").unwrap();
        assert!(staging.dir().exists());
        staging.destroy().unwrap();
        assert!(!staging.dir().exists(), "staging erased");
        staging.destroy().unwrap(); // idempotent
    }

    /// DL-ISC-18 (review): the `.dspart` refusal is case-insensitive and strips
    /// trailing dots/spaces, so a hostile manifest cannot alias the reserved
    /// quarantine on Windows/macOS (`.DSPART`, `.dspart.`, `.dspart `).
    #[test]
    fn staging_guard_rejects_case_and_trailing_dot_variants() {
        for hostile in [
            ".DSPART/evil.txt",
            ".DsPart/evil.txt",
            ".dspart./evil.txt",
            ".dspart /evil.txt",
            "sub/.DSPART/evil.txt",
            ".dspart",
        ] {
            assert!(
                sanitize_rel_path(hostile).is_err(),
                "must refuse {hostile:?}"
            );
        }
        // A name that merely resembles it (different component) is still fine.
        assert!(sanitize_rel_path(".dspartx/notes.txt").is_ok());
        assert!(sanitize_rel_path("my.dspart.backup/notes.txt").is_ok());
    }

    /// Review finding: two distinct share_ids that the lossy `safe_folder_name`
    /// would fold together get DISTINCT staging areas (injective hex component),
    /// so their partials can never cross-contaminate.
    #[test]
    fn distinct_share_ids_get_distinct_staging() {
        // `a/b` and `a_b` both fold to `a_b` under safe_folder_name.
        assert_eq!(safe_folder_name("a/b"), safe_folder_name("a_b"));
        assert_ne!(
            staging_component("a/b"),
            staging_component("a_b"),
            "hex component is injective"
        );
        let dir = tempfile::TempDir::new().unwrap();
        let a = StagingArea::open(dir.path(), "a/b").unwrap();
        let b = StagingArea::open(dir.path(), "a_b").unwrap();
        assert_ne!(a.dir(), b.dir(), "distinct staging dirs");
    }

    /// Review finding: a chunk write is refused if its offset+len would extend the
    /// staged file past the preallocated (confirmed-manifest) size.
    #[test]
    fn write_rejects_out_of_range_offset() {
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "share3").unwrap();
        staging.preallocate("f.bin", 10).unwrap();
        assert!(
            staging
                .write_verified_chunk("f.bin", 0, b"0123456789")
                .is_ok()
        );
        assert!(staging.write_verified_chunk("f.bin", 6, b"6789").is_ok());
        // offset+len past the end is refused.
        assert!(matches!(
            staging.write_verified_chunk("f.bin", 8, b"88888"),
            Err(FetchedError::Corrupt(_))
        ));
        assert!(matches!(
            staging.write_verified_chunk("f.bin", 10, b"x"),
            Err(FetchedError::Corrupt(_))
        ));
    }

    /// A promote onto a FRESH name lands directly (the `create_new` reservation at
    /// n=1 succeeds and the staged file renames onto it).
    #[test]
    fn promote_to_a_fresh_name_lands_directly() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let staging = StagingArea::open(root, "share4").unwrap();
        staging.preallocate("out.bin", 3).unwrap();
        staging.write_verified_chunk("out.bin", 0, b"abc").unwrap();
        let final_path = staging.promote("out.bin").unwrap();
        assert_eq!(final_path, root.join("out.bin"));
        assert_eq!(std::fs::read(&final_path).unwrap(), b"abc");
    }

    // ── Live-fetch registry + sweep (step 4c, DL-ISC-22) ──

    /// DL-ISC-22: the sweep reclaims only staging that is NEITHER registered as an
    /// active fetch NOR resumable — a registered fetch and a resumable one are both
    /// kept; only unregistered, unresumable debris is deleted.
    #[test]
    fn sweep_reclaims_only_unregistered_unresumable_debris() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let stage_path = |sid: &str| root.join(STAGING_DIR).join(staging_component(sid));

        StagingArea::open(root, "shareA").unwrap(); // registered (active)
        StagingArea::open(root, "shareB").unwrap(); // unregistered, unresumable → debris
        StagingArea::open(root, "shareC").unwrap(); // resumable (has stored manifest)

        let registry = LiveFetchRegistry::new();
        let _guard = registry.register("shareA");

        let deleted = sweep_staging(root, &registry, |sid| sid == "shareC").unwrap();

        assert_eq!(deleted, vec![stage_path("shareB")], "only debris reclaimed");
        assert!(stage_path("shareA").exists(), "registered kept");
        assert!(!stage_path("shareB").exists(), "debris reclaimed");
        assert!(stage_path("shareC").exists(), "resumable kept");
    }

    /// DL-ISC-22 (TOCTOU close): a registered resume's staging is never swept, even
    /// when the resumable predicate says false — registration is the guard.
    #[test]
    fn sweep_keeps_a_registered_resume() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        StagingArea::open(root, "resuming").unwrap();
        let registry = LiveFetchRegistry::new();
        let _guard = registry.register("resuming");
        let deleted = sweep_staging(root, &registry, |_| false).unwrap();
        assert!(deleted.is_empty(), "a registered fetch is never swept");
        assert!(
            root.join(STAGING_DIR)
                .join(staging_component("resuming"))
                .exists()
        );
    }

    /// A foreign directory under `.dspart/` (not a valid staging component) is left
    /// untouched — the sweep never deletes on a name pattern alone.
    #[test]
    fn sweep_leaves_foreign_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let foreign = root.join(STAGING_DIR).join("not-a-hex-component");
        std::fs::create_dir_all(&foreign).unwrap();
        let deleted = sweep_staging(root, &LiveFetchRegistry::new(), |_| false).unwrap();
        assert!(deleted.is_empty());
        assert!(foreign.exists(), "foreign dir untouched");
    }

    /// Sweeping a root with no `.dspart` is a no-op.
    #[test]
    fn sweep_empty_root_is_noop() {
        let dir = tempfile::TempDir::new().unwrap();
        let deleted = sweep_staging(dir.path(), &LiveFetchRegistry::new(), |_| false).unwrap();
        assert!(deleted.is_empty());
    }

    /// The registry guard unregisters on drop.
    #[test]
    fn registry_guard_unregisters_on_drop() {
        let registry = LiveFetchRegistry::new();
        {
            let _g = registry.register("s");
            assert!(registry.is_active("s"));
        }
        assert!(!registry.is_active("s"), "unregistered on drop");
    }

    /// Review fix: overlapping registrations of one share_id are reference-counted
    /// — dropping one guard while another lives keeps the id active, so a sweep
    /// can't delete a still-in-flight re-fetch's staging.
    #[test]
    fn registry_refcounts_overlapping_registrations() {
        let registry = LiveFetchRegistry::new();
        let g1 = registry.register("shareA");
        let g2 = registry.register("shareA");
        assert!(registry.is_active("shareA"));
        drop(g1);
        assert!(
            registry.is_active("shareA"),
            "still active while a second guard lives"
        );
        drop(g2);
        assert!(
            !registry.is_active("shareA"),
            "inactive once the last guard drops"
        );
    }

    /// Review fix: the idx lock refuses to open through a symlink at `.idx.lock`,
    /// so a co-resident attacker cannot redirect it to a different inode and
    /// defeat the cross-process serialization.
    #[cfg(unix)]
    #[test]
    fn idx_lock_refuses_a_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        std::os::unix::fs::symlink(root.join("elsewhere"), root.join(".idx.lock")).unwrap();
        let mut store = FetchedStore::open(root).unwrap();
        let err = store.record_share("s", "n", &[vf("f", b"x")]).unwrap_err();
        assert!(matches!(err, FetchedError::UnsafePath(_)));
    }

    /// DL-ISC-9: concurrent `record_share` on one downloads root — separate
    /// stores/handles, as the GUI and TUI would be — never loses a `downloads.idx`
    /// entry, because the idx read-modify-write is serialized by the OS advisory
    /// file lock. Without the lock, interleaved read-mutate-write would drop
    /// entries via a stale snapshot.
    #[test]
    fn concurrent_record_share_never_loses_an_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let n = 8usize;
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let mut store = FetchedStore::open(&root).unwrap();
                    store
                        .record_share(
                            &format!("share{i:02}"),
                            &format!("name{i}"),
                            &[vf("f", b"x")],
                        )
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let shares = FetchedStore::open(&root).unwrap().list_shares().unwrap();
        assert_eq!(
            shares.len(),
            n,
            "no idx entry lost under concurrent record_share"
        );
    }

    /// ISC-C63 / ISC-C65 — a recorded fetch writes named files (real names,
    /// real rel_path tree) directly under a per-share folder; no CAS, no hex,
    /// no `.rc`.
    #[test]
    fn record_writes_named_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        let share = store
            .record_share(
                "abc123",
                "My Photos",
                &[vf("readme.txt", b"hello"), vf("sub/pic.png", b"PNGDATA")],
            )
            .unwrap();

        let folder = dir.path().join("My Photos");
        assert!(folder.is_dir());
        assert_eq!(std::fs::read(folder.join("readme.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(folder.join("sub/pic.png")).unwrap(),
            b"PNGDATA"
        );
        // No CAS internals leaked.
        assert!(!dir.path().join("cas").exists());
        assert_eq!(share.folder, "My Photos");
        // No `.rc` sidecars anywhere under the share folder.
        for entry in walkdir::WalkDir::new(&folder) {
            let e = entry.unwrap();
            assert!(
                !e.path().to_string_lossy().ends_with(".rc"),
                "no refcount sidecars"
            );
        }
    }

    /// ISC-C64 — a recorded fetch lists back with the same files, names, sizes,
    /// and folder across a reopen (process restart).
    #[test]
    fn record_then_list_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        store
            .record_share(
                "abc123",
                "docs",
                &[vf("a.txt", b"hello"), vf("b.md", b"notes!")],
            )
            .unwrap();

        let reopened = FetchedStore::open(dir.path()).unwrap();
        let shares = reopened.list_shares().unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share_id, "abc123");
        assert_eq!(shares[0].name, "docs");
        assert_eq!(shares[0].folder, "docs");
        assert_eq!(shares[0].files.len(), 2);
        assert_eq!(shares[0].total_bytes(), 11);
        assert_eq!(reopened.share_dir(&shares[0]), dir.path().join("docs"));
    }

    /// `register_share` records the idx entry for an already-promoted managed
    /// download WITHOUT writing bytes (the #207 RAM-buffer retirement): the entry
    /// lists back with the caller-supplied folder + files, and no file bytes were
    /// written by the call itself.
    #[test]
    fn register_records_idx_without_writing_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        let files = vec![
            FetchedFile {
                rel_path: "song.mp3".into(),
                size: 4096,
            },
            FetchedFile {
                rel_path: "art/cover.png".into(),
                size: 128,
            },
        ];
        let share = store
            .register_share("sid42", "Album", "Album", &files)
            .unwrap();
        assert_eq!(share.folder, "Album");

        let reopened = FetchedStore::open(dir.path()).unwrap();
        let shares = reopened.list_shares().unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share_id, "sid42");
        assert_eq!(shares[0].files.len(), 2);
        assert_eq!(shares[0].total_bytes(), 4096 + 128);
        // register_share never wrote file bytes (the engine promotes them; this
        // call only touched the idx).
        assert!(!dir.path().join("Album/song.mp3").exists());
    }

    /// ISC-A-C32 — a manifest entry whose rel_path escapes the folder is
    /// refused; nothing is written outside the share folder.
    #[test]
    fn record_rejects_path_traversal() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        let err = store
            .record_share("evil", "evil", &[vf("../escape.txt", b"pwn")])
            .unwrap_err();
        assert!(matches!(err, FetchedError::UnsafePath(_)));
        assert!(!dir.path().join("escape.txt").exists());
    }

    /// ISC-A-C32 — absolute and `..` paths are refused; a normal nested path is
    /// accepted.
    #[test]
    fn sanitize_rejects_absolute_and_dotdot() {
        assert!(sanitize_rel_path("/etc/passwd").is_err());
        assert!(sanitize_rel_path("..").is_err());
        assert!(sanitize_rel_path("a/../../b").is_err());
        assert!(sanitize_rel_path("").is_err());
        assert_eq!(
            sanitize_rel_path("sub/dir/file.txt").unwrap(),
            PathBuf::from("sub").join("dir").join("file.txt")
        );
    }

    /// Two shares with the same name land in distinct folders (no mingling) —
    /// the second is collision-suffixed by share_id.
    #[test]
    fn same_name_shares_get_distinct_folders() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        let a = store
            .record_share("aaaaaa11", "Vacation", &[vf("x", b"1")])
            .unwrap();
        let b = store
            .record_share("bbbbbb22", "Vacation", &[vf("y", b"2")])
            .unwrap();
        assert_eq!(a.folder, "Vacation");
        assert_eq!(b.folder, "Vacation-bbbbbb");
        assert_ne!(a.folder, b.folder);
        assert!(dir.path().join("Vacation").join("x").exists());
        assert!(dir.path().join("Vacation-bbbbbb").join("y").exists());
    }

    /// A hostile share name can't escape the downloads root — it's reduced to a
    /// single safe component.
    #[test]
    fn hostile_share_name_is_contained() {
        assert_eq!(safe_folder_name(""), "share");
        assert_eq!(safe_folder_name("..."), "share");
        assert_eq!(safe_folder_name("a/b\\c"), "a_b_c");
        // Any name reduces to a single safe component — never `.`/`..`, never a
        // path separator, so it can't escape the downloads root (ISC-A-C32).
        for n in ["..", "../../etc", "/", "//", ".", "normal name", ""] {
            let f = safe_folder_name(n);
            assert!(!f.contains('/') && !f.contains('\\'));
            assert!(f != "." && f != "..");
            assert!(!f.is_empty());
        }
    }

    /// Re-recording the same share_id reuses its folder and refreshes files.
    #[test]
    fn re_record_reuses_folder() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        store.record_share("s1", "v", &[vf("a", b"1")]).unwrap();
        let b = store
            .record_share("s1", "v", &[vf("a", b"12"), vf("b", b"3")])
            .unwrap();
        assert_eq!(b.folder, "v");
        let shares = store.list_shares().unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].files.len(), 2);
    }

    /// An empty store lists nothing; a corrupt manifest errors rather than
    /// silently returning empty.
    #[test]
    fn empty_and_corrupt() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FetchedStore::open(dir.path()).unwrap();
        assert!(store.list_shares().unwrap().is_empty());
        std::fs::write(store.manifest_path(), "S nothex nothex nothex 1\n").unwrap();
        assert!(matches!(store.list_shares(), Err(FetchedError::Corrupt(_))));
    }

    // ── Verified resume — stored manifest, digest, re-derivation (step 8a) ──

    /// A [`ManifestEntry`] with `n` deterministic fake chunk addresses — enough to
    /// exercise serialization / digest / persist without materializing bytes.
    fn fake_entry(rel: &str, size: u64, seed: u8, n: usize) -> ManifestEntry {
        let chunks = (0..n)
            .map(|i| ChunkAddr::from_bytes([seed ^ (i as u8); CHUNK_ADDR_LEN]))
            .collect();
        ManifestEntry {
            rel_path: rel.to_owned(),
            size,
            chunks,
        }
    }

    /// `size` deterministic content bytes plus the REAL per-chunk addresses over
    /// [`CHUNK_SIZE`] windows — the fixtures the re-derivation oracles hash against.
    fn real_content(size: u64) -> (Vec<u8>, Vec<ChunkAddr>) {
        let _ = oxicrypt_module::initialize();
        let mut bytes = vec![0u8; size as usize];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let mut addrs = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            let end = (off + CHUNK_SIZE).min(bytes.len());
            addrs.push(chunk_addr(&bytes[off..end]).unwrap());
            off = end;
        }
        (bytes, addrs)
    }

    /// Round-trip determinism: persist→read is byte-identical, serialization is
    /// stable, and the digest is reproducible (the DL-ISC-20 anchor).
    #[test]
    fn stored_manifest_serialization_is_deterministic_and_round_trips() {
        let _ = oxicrypt_module::initialize();
        let manifest = vec![
            fake_entry("a/b.txt", 3, 0x11, 2),
            fake_entry("c.bin", 1_048_577, 0x22, 3),
            fake_entry("empty", 0, 0x00, 0),
        ];
        let s1 = serialize_stored_manifest(&manifest);
        let s2 = serialize_stored_manifest(&manifest);
        assert_eq!(
            s1, s2,
            "serialization must be byte-identical for equal input"
        );
        assert_eq!(deserialize_stored_manifest(&s1).unwrap(), manifest);
        assert_eq!(
            manifest_digest(&manifest).unwrap(),
            manifest_digest(&manifest).unwrap(),
            "digest is stable"
        );
    }

    /// Deserialization is fail-closed: bad magic, truncation, and trailing bytes
    /// each error rather than yield a partial/empty manifest.
    #[test]
    fn stored_manifest_deserialize_is_fail_closed() {
        assert!(matches!(
            deserialize_stored_manifest(b"not-a-manifest"),
            Err(FetchedError::Corrupt(_))
        ));
        let good = serialize_stored_manifest(&[fake_entry("x", 1, 9, 1)]);
        assert!(matches!(
            deserialize_stored_manifest(&good[..good.len() - 3]),
            Err(FetchedError::Corrupt(_))
        ));
        let mut trailing = good.clone();
        trailing.push(0xFF);
        assert!(matches!(
            deserialize_stored_manifest(&trailing),
            Err(FetchedError::Corrupt(_))
        ));
    }

    /// `persist_manifest` → `read_stored_manifest` recovers the exact manifest, and
    /// the stored copy lives under the reserved `.dspart` component (collision-proof
    /// against any staged file).
    #[test]
    fn persist_and_read_stored_manifest_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "share-x").unwrap();
        let manifest = vec![fake_entry("a.txt", 5, 1, 1), fake_entry("b/c.bin", 9, 2, 2)];
        staging.persist_manifest(&manifest).unwrap();
        assert_eq!(staging.read_stored_manifest().unwrap(), manifest);
        // The stored manifest is under `<dir>/.dspart/manifest` — a path no staged
        // final_rel can name (`sanitize_rel_path` refuses a `.dspart` segment).
        assert!(staging.dir().join(STAGING_DIR).join("manifest").is_file());
    }

    /// A missing stored manifest is a typed error, never a silent empty manifest.
    #[test]
    fn read_stored_manifest_missing_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "share-x").unwrap();
        assert!(staging.read_stored_manifest().is_err());
    }

    /// DL-ISC-20: `verify_stored_manifest` returns the manifest only when the
    /// staging copy's digest matches the profile-anchored digest.
    #[test]
    fn verify_stored_manifest_accepts_the_matching_digest() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let manifest = vec![fake_entry("a.txt", 5, 1, 2)];
        staging.persist_manifest(&manifest).unwrap();
        let digest = manifest_digest(&manifest).unwrap();
        assert_eq!(verify_stored_manifest(&staging, &digest).unwrap(), manifest);
    }

    /// DL-ISC-20 (tampered staging manifest): tampering the on-disk staging
    /// manifest bytes makes `verify_stored_manifest` halt — the resume must not
    /// proceed on an unverified stored manifest.
    #[test]
    fn verify_stored_manifest_rejects_a_tampered_staging_manifest() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let manifest = vec![fake_entry("a.txt", 5, 1, 2)];
        staging.persist_manifest(&manifest).unwrap();
        let digest = manifest_digest(&manifest).unwrap();
        // Flip a byte in the persisted manifest (keep it parseable so the failure
        // is the DIGEST check, not a parse error).
        let path = staging.dir().join(STAGING_DIR).join("manifest");
        let mut raw = std::fs::read(&path).unwrap();
        *raw.last_mut().unwrap() ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();
        assert!(verify_stored_manifest(&staging, &digest).is_err());
    }

    /// DL-ISC-20 (swapped manifest): a DIFFERENT manifest in staging fails the
    /// digest compare against the original's anchored digest.
    #[test]
    fn verify_stored_manifest_rejects_a_swapped_manifest() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let original = vec![fake_entry("a.txt", 5, 1, 2)];
        let digest = manifest_digest(&original).unwrap();
        // Persist a different manifest (a colluding sharer's swap).
        let swapped = vec![fake_entry("a.txt", 5, 2, 2)];
        staging.persist_manifest(&swapped).unwrap();
        assert!(verify_stored_manifest(&staging, &digest).is_err());
    }

    /// DL-ISC-20 (missing staging manifest): no persisted manifest → halt, never a
    /// silent proceed.
    #[test]
    fn verify_stored_manifest_rejects_a_missing_staging_manifest() {
        let dir = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        assert!(verify_stored_manifest(&staging, &[0u8; MANIFEST_DIGEST_LEN]).is_err());
    }

    /// Stage a subset of `present` chunk indices of a multi-chunk file into
    /// `staging`, pre-sized to `size`. The rest stay sparse/unwritten.
    fn stage_chunks(staging: &StagingArea, rel: &str, content: &[u8], present: &[usize]) {
        staging.preallocate(rel, content.len() as u64).unwrap();
        for &i in present {
            let (off, len) = chunk_region(i, content.len() as u64);
            let (off, len) = (off as usize, len as usize);
            staging
                .write_verified_chunk(rel, off as u64, &content[off..off + len])
                .unwrap();
        }
    }

    /// DL-ISC-12 (kill-mid-download, set semantics): a non-prefix subset of a
    /// 4-chunk file's chunks staged ({0,2}) re-derives as exactly verified {0,2},
    /// missing {1,3} — no prefix assumption.
    #[test]
    fn derive_resume_returns_verified_and_missing_as_a_set() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (3 * CHUNK_SIZE + 1000) as u64; // 4 chunks, short last
        let (content, addrs) = real_content(size);
        assert_eq!(addrs.len(), 4);
        stage_chunks(&staging, "f.bin", &content, &[0, 2]);
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].verified, vec![0, 2]);
        assert_eq!(plan.files[0].missing, vec![1, 3]);
        assert!(!plan.files[0].is_complete());
        assert!(!plan.is_complete());
        assert_eq!(plan.verified_chunk_count(), 2);
        assert_eq!(plan.missing_chunk_count(), 2);
    }

    /// DL-ISC-12 (tamper-a-partial): a staged chunk whose bytes are corrupted
    /// re-hashes to a mismatch and is classified MISSING, not verified.
    #[test]
    fn derive_resume_classifies_a_tampered_partial_as_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (CHUNK_SIZE + 500) as u64; // 2 chunks
        let (content, addrs) = real_content(size);
        assert_eq!(addrs.len(), 2);
        stage_chunks(&staging, "f.bin", &content, &[0, 1]);
        // Corrupt one byte of chunk 0 on disk, bypassing the verify path.
        let staged_path = staging.staging_path("f.bin").unwrap();
        let mut raw = std::fs::read(&staged_path).unwrap();
        raw[10] ^= 0xFF;
        std::fs::write(&staged_path, &raw).unwrap();
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert_eq!(plan.files[0].verified, vec![1]);
        assert_eq!(plan.files[0].missing, vec![0]);
    }

    /// DL-ISC-12 (fully-verified file): every chunk staged → zero missing, complete.
    #[test]
    fn derive_resume_on_a_fully_staged_file_is_complete() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (CHUNK_SIZE + 500) as u64;
        let (content, addrs) = real_content(size);
        stage_chunks(&staging, "f.bin", &content, &[0, 1]);
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(plan.files[0].is_complete());
        assert!(plan.is_complete());
        assert!(plan.files[0].missing.is_empty());
    }

    /// xhigh review F1 (coverage guard): a manifest entry whose chunk list does NOT
    /// tile `[0, size)` (a hostile `{size: 2*CHUNK_SIZE, chunks: [one]}`) is NEVER
    /// resumed-as-complete even though the one listed chunk verifies — the uncovered
    /// `[CHUNK_SIZE, 2*CHUNK_SIZE)` tail would otherwise ride along as unverified
    /// sparse zeros.
    #[test]
    fn derive_resume_rejects_an_undersized_chunk_list() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (2 * CHUNK_SIZE) as u64; // the size implies 2 chunks
        let (content, addrs) = real_content(size);
        assert_eq!(addrs.len(), 2);
        stage_chunks(&staging, "f.bin", &content, &[0]); // chunk 0 verifies on disk
        // The hostile manifest lists ONLY chunk 0 but claims the 2-chunk size.
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: vec![addrs[0]],
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(
            !plan.files[0].is_complete(),
            "an undersized chunk list must never be Complete"
        );
        assert!(plan.files[0].verified.is_empty());
        assert_eq!(plan.files[0].missing, vec![0]);
    }

    /// xhigh review F1 (exact-length gate): a promoted file APPENDED past `size` by a
    /// co-resident (every in-bounds chunk still re-hashes correctly) is NOT trusted —
    /// the unverified trailing bytes must not ride along as content; the file is
    /// treated as absent and its chunks re-fetch.
    #[test]
    fn derive_resume_rejects_an_appended_promoted_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = 5_000u64; // one chunk (< CHUNK_SIZE)
        let (content, addrs) = real_content(size);
        assert_eq!(addrs.len(), 1);
        // Promote the correct content, then a co-resident appends extra bytes.
        let mut tampered = content.clone();
        tampered.extend_from_slice(b"evil trailing payload");
        std::fs::write(dest_root.path().join("f.bin"), &tampered).unwrap();
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(
            !plan.files[0].is_complete(),
            "an appended promoted file must not be Complete"
        );
        assert_eq!(plan.files[0].missing, vec![0]);
    }

    /// DL-ISC-12 (promoted fast-path): a completed file at `dest_root/<rel>` re-derives
    /// as `promoted_complete` (content-checked) with nothing in staging — its
    /// STAGING `verified` (skippable) set is empty (the engine keeps the dest file).
    #[test]
    fn derive_resume_reads_a_promoted_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (CHUNK_SIZE + 500) as u64;
        let (content, addrs) = real_content(size);
        std::fs::write(dest_root.path().join("f.bin"), &content).unwrap();
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(
            plan.files[0].promoted_complete,
            "a full dest file is promoted_complete"
        );
        assert!(plan.files[0].is_complete());
        assert!(plan.is_complete());
        // STAGING-authoritative: nothing is in staging, so the skippable set is empty.
        assert!(plan.files[0].verified.is_empty());
    }

    /// xhigh review (8b-1 location-mismatch): chunks good at the PROMOTED dest but
    /// absent from staging are NOT `verified`/skippable — the engine promotes staging,
    /// so skipping them would promote a sparse zero-hole. A partially-corrupt promoted
    /// file with no staging yields an EMPTY skippable set (every chunk re-fetched) and
    /// `promoted_complete == false`.
    #[test]
    fn derive_resume_does_not_skip_promoted_only_chunks() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (CHUNK_SIZE + 500) as u64; // 2 chunks
        let (mut content, addrs) = real_content(size);
        assert_eq!(addrs.len(), 2);
        content[CHUNK_SIZE + 10] ^= 0xFF; // corrupt chunk 1's region; chunk 0 stays good
        std::fs::write(dest_root.path().join("f.bin"), &content).unwrap(); // no staging exists
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(
            !plan.files[0].promoted_complete,
            "a partially-corrupt dest file is not complete"
        );
        // Nothing skippable (staging empty); every chunk re-fetches — no sparse hole.
        assert!(plan.files[0].verified.is_empty());
        assert_eq!(plan.files[0].missing, vec![0, 1]);
        assert!(!plan.files[0].is_complete());
    }

    /// xhigh review (8b-1): a length-matched but content-GARBAGE promoted dest file is
    /// NOT `promoted_complete`, even when staging holds the complete verified copy — so
    /// the resume promotes the good STAGING bytes, never the garbage dest file.
    #[test]
    fn derive_resume_does_not_trust_a_garbage_dest_by_length() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let size = (CHUNK_SIZE + 500) as u64;
        let (content, addrs) = real_content(size);
        stage_chunks(&staging, "f.bin", &content, &[0, 1]); // staging complete + verified
        std::fs::write(dest_root.path().join("f.bin"), vec![0x00u8; size as usize]).unwrap(); // exact-size garbage
        let manifest = vec![ManifestEntry {
            rel_path: "f.bin".to_owned(),
            size,
            chunks: addrs,
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(
            !plan.files[0].promoted_complete,
            "a length-matched garbage dest is not complete"
        );
        assert_eq!(plan.files[0].verified, vec![0, 1]); // staging authoritative + complete
        assert!(plan.files[0].missing.is_empty());
        assert!(plan.files[0].is_complete()); // via staging (the engine promotes it), not the dest garbage
    }

    /// An empty file (size 0, no chunks) is trivially complete.
    #[test]
    fn derive_resume_empty_file_is_complete() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest_root = tempfile::TempDir::new().unwrap();
        let staging = StagingArea::open(dir.path(), "s").unwrap();
        let manifest = vec![ManifestEntry {
            rel_path: "empty".to_owned(),
            size: 0,
            chunks: vec![],
        }];
        let plan = derive_resume_state(&manifest, dest_root.path(), &staging);
        assert!(plan.files[0].is_complete());
    }
}
