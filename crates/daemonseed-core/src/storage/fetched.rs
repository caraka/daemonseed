//! Persistent landing zone for *fetched* share content — explicit downloads
//! (M15 C; ISC-C63 / ISC-C64 / ISC-C65, ISC-A-C31 / ISC-A-C32).
//!
//! The share-fetch path ([`crate::share_envelope`], the TUI `FetchShare` net
//! actor) verifies every chunk against its content address (ISC-S28 /
//! ISC-A-S20) and, until M15, dropped the verified bytes after accounting them
//! — a fetch proved the content was *fetchable* but left nothing on disk. This
//! module is the persistence layer above that verification: a fetched share's
//! files land in an on-disk content-addressed store and a small manifest
//! records what was downloaded, so the user can browse fetched shares and
//! extract their files after the fetch overlay closes.
//!
//! ## At-rest posture — plaintext explicit downloads (decided 2026-06-05)
//!
//! A fetched chunk is the **plaintext file bytes** the sharer indexed
//! ([`crate::share_serve::ShareContent::index_dir`] reads each file and stores
//! its raw bytes; the chunk address is `SHA-384(file-bytes)`). So this store
//! holds plaintext content by design — that is the whole point of an *explicit
//! download*: the user fetched these files to open them. This is a deliberately
//! larger at-rest surface than the rest of the client (which persists only the
//! encrypted blob + config, ISC-A-C1) and is the seized-blob footprint the
//! R-PANIC erasure reservation targets. It does **not** breach the
//! no-client-history invariant: downloaded files are user-chosen artifacts, not
//! message/post/session history.
//!
//! The manifest is likewise plaintext: encrypting metadata that names files
//! whose bytes sit beside it in plaintext would be theatre — an attacker with
//! the seized download directory reads the files directly. A future at-rest
//! folder-encryption feature (the same one [`crate::storage::share_index`]
//! anticipates) would wrap the whole `fetched/` tree, content and manifest
//! together; that is post-MVP and additive.
//!
//! ## Layout
//!
//! ```text
//! <root>/                     (e.g. <profile-root>/fetched)
//!   cas/                      a FileChunkStore — one file per chunk, hex(addr)
//!   shares.idx                the manifest (see below)
//! ```
//!
//! ## Manifest format (`shares.idx`)
//!
//! A line-based text file (the same hand-rolled, dependency-free style as the
//! seeds directives — the workspace carries no `serde_json`). Variable fields
//! are hex-encoded so a path, name, or address can never collide with the
//! space delimiter or the newline framing:
//!
//! ```text
//! # daemonseed fetched-share manifest v1
//! S <share_id_hex> <name_hex> <file_count>
//! F <rel_path_hex> <chunk_addr_hex> <size_dec>
//! F ...
//! S ...
//! ```

use std::path::{Component, Path, PathBuf};

use crate::storage::cas::{CHUNK_ADDR_LEN, CasError, ChunkAddr, ChunkStore, FileChunkStore};

/// Manifest header — bumped if the on-disk format changes incompatibly.
const MANIFEST_HEADER: &str = "# daemonseed fetched-share manifest v1";

/// One downloaded file inside a [`FetchedShare`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedFile {
    /// The file's path relative to the share root (the sharer's `rel_path`;
    /// `/`-separated, as it arrived on the wire). Untrusted — sanitised at
    /// extraction time (ISC-A-C32).
    pub rel_path: String,
    /// The content address its bytes live under in the CAS.
    pub chunk_addr: ChunkAddr,
    /// The file's size in bytes.
    pub size: u64,
}

/// A fetched share's manifest record: what was downloaded under one `share_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedShare {
    /// The server-assigned share id this content was fetched under (ISC-S21).
    pub share_id: String,
    /// The sharer-advertised display name (from the `PublicShareListing`).
    pub name: String,
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
    /// The underlying content-addressed store failed.
    Cas(CasError),
    /// The manifest on disk was unparseable, or a manifest entry named a chunk
    /// the CAS does not hold (a corrupt or partially-deleted download dir).
    Corrupt(String),
    /// An extraction was asked to write a file whose `rel_path` escapes the
    /// destination directory (`..`, an absolute path, or a root/prefix
    /// component). A hostile sharer's manifest must never write outside the
    /// chosen dir (ISC-A-C32).
    UnsafePath(String),
}

impl core::fmt::Display for FetchedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FetchedError::Io(e) => write!(f, "fetched-store I/O failed: {e}"),
            FetchedError::Cas(e) => write!(f, "fetched-store chunk store failed: {e}"),
            FetchedError::Corrupt(m) => write!(f, "fetched-store manifest corrupt: {m}"),
            FetchedError::UnsafePath(p) => {
                write!(f, "refusing to extract path escaping the destination: {p}")
            }
        }
    }
}

impl core::error::Error for FetchedError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FetchedError::Io(e) => Some(e),
            FetchedError::Cas(e) => Some(e),
            FetchedError::Corrupt(_) | FetchedError::UnsafePath(_) => None,
        }
    }
}

impl From<CasError> for FetchedError {
    fn from(e: CasError) -> Self {
        FetchedError::Cas(e)
    }
}

impl From<std::io::Error> for FetchedError {
    fn from(e: std::io::Error) -> Self {
        FetchedError::Io(e)
    }
}

/// One file's verified bytes, ready to persist: the sharer's `rel_path` and the
/// plaintext bytes the fetch verified against the content address. The address
/// is *re-derived* by the CAS on `put`, never trusted from the caller.
pub struct VerifiedFile {
    /// The file's wire `rel_path` (untrusted; sanitised only at extraction).
    pub rel_path: String,
    /// The verified plaintext file bytes.
    pub bytes: Vec<u8>,
}

/// The on-disk store of fetched share content.
///
/// Open once with [`FetchedStore::open`]; [`record_share`](Self::record_share)
/// persists a completed fetch, [`list_shares`](Self::list_shares) enumerates
/// downloads for the browse view, and [`extract_share`](Self::extract_share)
/// reconstructs a download's files into a chosen directory.
pub struct FetchedStore {
    root: PathBuf,
}

impl FetchedStore {
    /// Open (creating if absent) the fetched-content store rooted at `root`.
    /// Reopening an existing root recovers every prior download.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, FetchedError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn cas_root(&self) -> PathBuf {
        self.root.join("cas")
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join("shares.idx")
    }

    /// Persist a fully-verified fetched share. Every file's bytes are stored in
    /// the content-addressed store and a manifest record is written.
    ///
    /// **No-partial invariant (ISC-A-C31):** the caller invokes this only after
    /// the fetch has verified *every* chunk; a fetch that fails verification
    /// mid-stream never reaches here, so a poisoned or truncated download is
    /// never recorded. Re-recording the same `share_id` replaces its manifest
    /// record (a re-fetch overwrites the listing); the prior chunks remain in
    /// the CAS — refcount-correct eviction on replace is a documented post-MVP
    /// follow-up, harmless because the bytes are content-addressed and shared.
    pub fn record_share(
        &mut self,
        share_id: &str,
        name: &str,
        files: &[VerifiedFile],
    ) -> Result<FetchedShare, FetchedError> {
        let mut store = FileChunkStore::open(self.cas_root())?;
        let mut recs = Vec::with_capacity(files.len());
        for vf in files {
            // `put` re-derives SHA-384(bytes); the address recorded is the
            // store's, never a wire-asserted value.
            let addr = store.put(&vf.bytes)?;
            recs.push(FetchedFile {
                rel_path: vf.rel_path.clone(),
                chunk_addr: addr,
                size: vf.bytes.len() as u64,
            });
        }

        let mut shares = self.list_shares()?;
        shares.retain(|s| s.share_id != share_id);
        let share = FetchedShare {
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            files: recs,
        };
        shares.push(share.clone());
        self.write_manifest(&shares)?;
        Ok(share)
    }

    /// Enumerate every fetched share, newest-recorded last (the order they sit
    /// in the manifest). `Ok(vec![])` when nothing has been fetched.
    pub fn list_shares(&self) -> Result<Vec<FetchedShare>, FetchedError> {
        let raw = match std::fs::read_to_string(self.manifest_path()) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(FetchedError::Io(e)),
        };
        parse_manifest(&raw)
    }

    /// Reconstruct a fetched share's files into `dest`, returning how many files
    /// were written. Each file's bytes come from the CAS by content address;
    /// the directory tree under `dest` mirrors the share's `rel_path`s.
    ///
    /// **Path-traversal safe (ISC-A-C32):** every `rel_path` is validated to be
    /// strictly relative with only normal components — a manifest entry naming
    /// `..`, an absolute path, or a drive/root prefix is refused with
    /// [`FetchedError::UnsafePath`] and nothing is written for it, so a hostile
    /// sharer's manifest can never escape `dest`.
    pub fn extract_share(&self, share_id: &str, dest: &Path) -> Result<u32, FetchedError> {
        let share = self
            .list_shares()?
            .into_iter()
            .find(|s| s.share_id == share_id)
            .ok_or_else(|| FetchedError::Corrupt(format!("no fetched share with id {share_id}")))?;

        let store = FileChunkStore::open(self.cas_root())?;
        std::fs::create_dir_all(dest)?;

        let mut written = 0u32;
        for file in &share.files {
            // Validate BEFORE touching the chunk store so a hostile path is
            // rejected even if its chunk is present.
            let safe = sanitize_rel_path(&file.rel_path)?;
            let bytes = store.get(&file.chunk_addr)?.ok_or_else(|| {
                FetchedError::Corrupt(format!(
                    "fetched share {share_id} references a chunk missing from the store ({})",
                    file.rel_path
                ))
            })?;
            let out = dest.join(&safe);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out, &bytes)?;
            written += 1;
        }
        Ok(written)
    }

    fn write_manifest(&self, shares: &[FetchedShare]) -> Result<(), FetchedError> {
        let mut out = String::new();
        out.push_str(MANIFEST_HEADER);
        out.push('\n');
        for s in shares {
            out.push_str(&format!(
                "S {} {} {}\n",
                hex::encode(s.share_id.as_bytes()),
                hex::encode(s.name.as_bytes()),
                s.files.len(),
            ));
            for f in &s.files {
                out.push_str(&format!(
                    "F {} {} {}\n",
                    hex::encode(f.rel_path.as_bytes()),
                    hex::encode(f.chunk_addr.as_bytes()),
                    f.size,
                ));
            }
        }
        std::fs::write(self.manifest_path(), out)?;
        Ok(())
    }
}

/// Validate an untrusted wire `rel_path` and return the safe relative
/// [`PathBuf`] to join under the destination. Rejects absolute paths, `..`,
/// `.`, and any root/prefix component — only `Component::Normal` survives
/// (ISC-A-C32).
fn sanitize_rel_path(rel: &str) -> Result<PathBuf, FetchedError> {
    if rel.is_empty() {
        return Err(FetchedError::UnsafePath(rel.to_owned()));
    }
    // A leading `/` is an absolute path. Joining it under `dest` would silently
    // relativise it (safe but surprising); reject it outright instead so a
    // weird/hostile manifest path surfaces rather than being rewritten.
    if rel.starts_with('/') {
        return Err(FetchedError::UnsafePath(rel.to_owned()));
    }
    // The wire form is always `/`-separated; interpret it as such on every
    // platform rather than trusting the host separator.
    let mut safe = PathBuf::new();
    for seg in rel.split('/') {
        if seg.is_empty() {
            // Leading, trailing, or doubled `/` — collapse, but a lone `/`
            // (absolute) yields an empty first segment and nothing else, which
            // we reject below via the empty-result guard.
            continue;
        }
        let p = Path::new(seg);
        let mut comps = p.components();
        match (comps.next(), comps.next()) {
            // Exactly one Normal component and nothing else is the only safe
            // shape. A `..`, `.`, root, or prefix component is rejected.
            (Some(Component::Normal(c)), None) => safe.push(c),
            _ => return Err(FetchedError::UnsafePath(rel.to_owned())),
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(FetchedError::UnsafePath(rel.to_owned()));
    }
    Ok(safe)
}

fn parse_manifest(raw: &str) -> Result<Vec<FetchedShare>, FetchedError> {
    let mut shares = Vec::new();
    let mut lines = raw.lines().peekable();
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
    let addr_hex = parts
        .next()
        .ok_or_else(|| FetchedError::Corrupt("F line missing chunk_addr".to_owned()))?;
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|_| FetchedError::Corrupt("F line chunk_addr not hex".to_owned()))?;
    let addr_arr: [u8; CHUNK_ADDR_LEN] = addr_bytes
        .try_into()
        .map_err(|_| FetchedError::Corrupt("F line chunk_addr wrong length".to_owned()))?;
    let size: u64 = parts
        .next()
        .ok_or_else(|| FetchedError::Corrupt("F line missing size".to_owned()))?
        .parse()
        .map_err(|_| FetchedError::Corrupt("F line size not a number".to_owned()))?;
    Ok(FetchedFile {
        rel_path,
        chunk_addr: ChunkAddr::from_bytes(addr_arr),
        size,
    })
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

    /// ISC-C63 / ISC-C64 — a recorded fetch persists to disk and lists back
    /// with the same files, names, sizes, and addresses.
    #[test]
    fn record_then_list_roundtrip() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        store
            .record_share(
                "abc123",
                "My Share",
                &[vf("readme.txt", b"hello"), vf("sub/notes.md", b"notes!")],
            )
            .unwrap();

        // A fresh handle over the same root == a process restart.
        let reopened = FetchedStore::open(dir.path()).unwrap();
        let shares = reopened.list_shares().unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share_id, "abc123");
        assert_eq!(shares[0].name, "My Share");
        assert_eq!(shares[0].files.len(), 2);
        assert_eq!(shares[0].files[0].rel_path, "readme.txt");
        assert_eq!(shares[0].files[0].size, 5);
        assert_eq!(shares[0].files[1].rel_path, "sub/notes.md");
        assert_eq!(shares[0].total_bytes(), 11);
    }

    /// ISC-C65 — extraction reconstructs the share's files byte-for-byte under
    /// the chosen directory, mirroring the rel_path tree.
    #[test]
    fn extract_reconstructs_bytes() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        store
            .record_share(
                "deadbeef",
                "docs",
                &[vf("a.txt", b"alpha"), vf("d/b.txt", b"bravo")],
            )
            .unwrap();

        let out = tempfile::TempDir::new().unwrap();
        let n = store.extract_share("deadbeef", out.path()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(out.path().join("d/b.txt")).unwrap(), b"bravo");
    }

    /// ISC-A-C32 — a manifest entry whose rel_path escapes the destination is
    /// refused; nothing is written outside the chosen dir.
    #[test]
    fn extract_rejects_path_traversal() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        store
            .record_share("evil", "evil", &[vf("../escape.txt", b"pwn")])
            .unwrap();

        let out = tempfile::TempDir::new().unwrap();
        let err = store.extract_share("evil", out.path()).unwrap_err();
        assert!(matches!(err, FetchedError::UnsafePath(_)));
        // The sibling-escape target was never written.
        assert!(!out.path().parent().unwrap().join("escape.txt").exists());
    }

    /// ISC-A-C32 — absolute paths are refused too.
    #[test]
    fn sanitize_rejects_absolute_and_dotdot() {
        assert!(sanitize_rel_path("/etc/passwd").is_err());
        assert!(sanitize_rel_path("..").is_err());
        assert!(sanitize_rel_path("a/../../b").is_err());
        assert!(sanitize_rel_path("").is_err());
        // A normal nested path is accepted and normalised to a relative path.
        assert_eq!(
            sanitize_rel_path("sub/dir/file.txt").unwrap(),
            PathBuf::from("sub").join("dir").join("file.txt")
        );
    }

    /// Re-recording the same share_id replaces its manifest record rather than
    /// duplicating it (a re-fetch overwrites the listing).
    #[test]
    fn re_record_replaces_listing() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FetchedStore::open(dir.path()).unwrap();
        store.record_share("s1", "v1", &[vf("a", b"1")]).unwrap();
        store
            .record_share("s1", "v2", &[vf("a", b"1"), vf("b", b"2")])
            .unwrap();
        let shares = store.list_shares().unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "v2");
        assert_eq!(shares[0].files.len(), 2);
    }

    /// An empty store lists nothing (no manifest file yet).
    #[test]
    fn empty_store_lists_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FetchedStore::open(dir.path()).unwrap();
        assert!(store.list_shares().unwrap().is_empty());
    }

    /// A corrupt manifest surfaces as an error rather than a silent empty list.
    #[test]
    fn corrupt_manifest_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FetchedStore::open(dir.path()).unwrap();
        std::fs::write(store.manifest_path(), "S nothex nothex 1\n").unwrap();
        assert!(matches!(store.list_shares(), Err(FetchedError::Corrupt(_))));
    }
}
