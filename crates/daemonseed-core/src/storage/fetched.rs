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

use std::path::{Component, Path, PathBuf};

/// Manifest header — bumped if the on-disk format changes incompatibly.
const MANIFEST_HEADER: &str = "# daemonseed downloads manifest v2";

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
}
