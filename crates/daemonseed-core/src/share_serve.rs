//! Share **serve** side — the sharer's half of the share-fetch protocol
//! (alpha2 item B; ISC-S27 / ISC-S28 / ISC-S29 / ISC-A-S20 / ISC-A-S21).
//!
//! The [`share_envelope`](crate::share_envelope) module defines the
//! `ShareFrame` manifest/chunk protocol; [`storage::cas`](crate::storage::cas)
//! the content-addressed chunk store; and [`cot`](crate::cot) the
//! `(share_id, server_id)` → asset-address derivation. The **consumer** (the
//! TUI `FetchShare` net actor, and the in-process integration tests) already
//! runs the fetcher half. What was missing — until this module — was a
//! **reusable serve side**: nothing answered a `ManifestRequest` /
//! `ChunkRequest` except the inline logic baked into the
//! `share_fetch_e2e` integration test.
//!
//! [`ShareContent`] is that reusable serve side, factored out of the test:
//!
//! 1. [`ShareContent::index_dir`] walks a directory, reads each regular file,
//!    chunks it into a [`crate::storage::cas::MemoryChunkStore`]
//!    (one chunk per file for the alpha — multi-chunk-per-file is post-MVP,
//!    layered on without wire change), and records a [`ManifestEntry`] per file.
//!    The chunk's address is `SHA-384(file-bytes)` — the same content address
//!    the fetcher re-derives and verifies (ISC-S28).
//! 2. [`ShareContent::answer`] is the **pure** request → response step: given a
//!    decoded inbound `ShareFrame`, it returns the `ShareFrame` to relay back
//!    (a `ManifestResponse` for a `ManifestRequest`, a `ChunkResponse` for a
//!    `ChunkRequest` naming a chunk this content holds, or `None` for a request
//!    this serve side does not answer — a response frame, an unknown chunk).
//!    A transport driver (the CLI's `publish --path` serve loop, the
//!    integration test) wraps a subscribe stream around it.
//!
//! ## Why the serve loop is a transport-agnostic driver, not part of this module
//!
//! The fan-out subscribe stream is a `tonic` / `daemonseed-proto` surface;
//! `daemonseed-core` deliberately carries no tonic dependency (it is the
//! protocol library both client and server build on). So this module keeps the
//! transport-free pieces — directory indexing, the chunk store, and the pure
//! `answer` step — and the caller supplies the stream loop. That keeps the
//! security-load-bearing logic (content addressing, self-consistency) in one
//! tested place and lets the CLI and the tests share it byte-for-byte.
//!
//! ## Self-consistency check (ISC-A-S21 — offline sharer ⇒ unfetchable)
//!
//! The serve side answers a `ChunkRequest` only for a chunk it actually holds
//! in its [`MemoryChunkStore`]; an unknown address yields `None` (no frame is
//! relayed). Combined with the live-only relay (ISC-S20: a fan-out asset exists
//! only while a subscriber holds it open), this is what makes an **offline
//! sharer's content unfetchable** — when the sharer's `publish --path` process
//! exits, its subscribe stream closes, the relay reaps the asset, and no party
//! is left to answer `ManifestRequest` / `ChunkRequest`. The fetcher's request
//! lands on a dead (or never-live) asset and times out / sees end-of-stream;
//! the content is *temporarily unavailable*, never served stale by the relay.
//!
//! Every chunk the serve side returns is, by construction, addressed by its own
//! `SHA-384` (it was stored under `chunk_addr(file-bytes)`), so a faithful relay
//! forward passes the fetcher's re-derived-hash verification; a relay that
//! tampers with the bytes in flight fails it (ISC-A-S20, proved fetcher-side).
//!
//! ## Disk-backed serving (M16)
//!
//! [`ShareContent::index_dir`] reads every file into RAM, which caps a share
//! at available memory. The disk-backed path replaces that for the publish
//! flow while keeping the wire and the fetcher untouched:
//!
//! 1. [`hash_share`] walks the same deterministic file order as `index_dir`
//!    but only *hashes* each file — streaming through a fixed buffer, never a
//!    whole-file read — producing a [`ShareManifest`] whose per-file
//!    `chunk_addr` is byte-identical to what `MemoryChunkStore::put` derives
//!    for the same bytes (one SHA-384 over the file's full content), so the
//!    fetch-side verification is unchanged. It is cancellable between files
//!    and reports per-file progress.
//! 2. [`DiskShareContent`] pairs that manifest with the share root and reads
//!    a requested chunk's one file from disk at answer time, with **cheap**
//!    fail-closed checks only (a read error, or a byte length that no longer
//!    matches the manifest entry — [`ServeError::ChunkModified`]). There is
//!    deliberately no serve-time re-hash: the fetcher re-derives SHA-384 over
//!    every `ChunkResponse` and fails closed on mismatch (ISC-S28), so
//!    receiver-side verification is the integrity guarantee — see
//!    [`DiskShareContent::get_chunk`].
//!
//! The serve loop's needs are factored into the [`ChunkSource`] trait
//! (manifest + chunk lookup, with the pure `answer` step provided), which
//! both [`ShareContent`] (kept — the CLI and tests use it) and
//! [`DiskShareContent`] implement, so a transport driver serves either.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use oxicrypt_sha::Sha384;
use walkdir::WalkDir;

use crate::share_envelope::{ManifestEntry, ShareFrame};
use crate::storage::cas::{CHUNK_ADDR_LEN, CasError, ChunkAddr, ChunkStore, MemoryChunkStore};

/// Fixed buffer length for the streaming per-file hash pass (1 MiB). Files
/// are fed through this buffer in [`hash_file`] — never read whole into
/// memory — so the hash pass's footprint is independent of file size.
const HASH_BUF_LEN: usize = 1024 * 1024;

/// An indexed, in-memory view of a shared directory ready to answer
/// share-fetch requests. Holds the manifest (one [`ManifestEntry`] per file)
/// and the file bytes in a content-addressed [`MemoryChunkStore`].
///
/// Built once by [`ShareContent::index_dir`]; queried repeatedly (one query per
/// fetcher request) by [`ShareContent::answer`]. Cheap to share read-only across
/// many concurrent fetchers — the only mutation is at construction.
pub struct ShareContent {
    manifest: Vec<ManifestEntry>,
    store: MemoryChunkStore,
}

/// Why building serve-side content (an index, a hash pass, or a disk-backed
/// chunk read) failed.
#[derive(Debug)]
pub enum ServeError {
    /// Reading a file under the share root failed.
    Io(std::io::Error),
    /// Hashing a chunk failed — oxicrypt's SHA-384 power-up self-test has not
    /// passed in this process (initialize the module first).
    Cas(CasError),
    /// The hash pass was cancelled via its cancel flag before completing
    /// (checked between files — no partial manifest is returned).
    Cancelled,
    /// A chunk was requested whose address is not in this content's manifest.
    UnknownChunk,
    /// A share file's on-disk byte length no longer matches the size its
    /// manifest entry advertises — it was truncated or grew since the hash
    /// pass. Failing closed here (rather than serving bytes that provably
    /// cannot hash to the old address) is the cheap half of the
    /// content-addressing invariant; the fetcher's re-derived-hash check
    /// (ISC-S28) is the full one and would reject the chunk anyway. We never
    /// put a *knowingly* mismatched frame on the wire.
    ChunkModified {
        /// The share-root-relative path of the file that changed.
        rel_path: String,
    },
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Io(e) => write!(f, "share index I/O failed: {e}"),
            ServeError::Cas(e) => write!(f, "share chunk store failed: {e}"),
            ServeError::Cancelled => f.write_str("share hash pass cancelled"),
            ServeError::UnknownChunk => {
                f.write_str("requested chunk is not in this share's manifest")
            }
            ServeError::ChunkModified { rel_path } => write!(
                f,
                "share file '{rel_path}' changed since hashing — refusing to serve \
                 bytes that no longer match their advertised address"
            ),
        }
    }
}

impl core::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ServeError::Io(e) => Some(e),
            ServeError::Cas(e) => Some(e),
            ServeError::Cancelled | ServeError::UnknownChunk | ServeError::ChunkModified { .. } => {
                None
            }
        }
    }
}

impl ShareContent {
    /// Walk `root`, chunk every regular file beneath it into the content store,
    /// and build the manifest. One file = one chunk (the alpha; multi-chunk is
    /// post-MVP). The manifest's `rel_path` is the file's path relative to
    /// `root`, using `/` separators on every platform so the wire form is
    /// stable; an unreadable file aborts the index (a sharer must know its own
    /// content is complete before advertising it — unlike the relay-side
    /// indexer's skip-and-continue posture).
    pub fn index_dir(root: impl AsRef<Path>) -> Result<Self, ServeError> {
        let root = root.as_ref();
        let mut store = MemoryChunkStore::new();
        let mut manifest = Vec::new();

        for entry in share_files(root) {
            let bytes = std::fs::read(entry.path()).map_err(ServeError::Io)?;
            let addr = store.put(&bytes).map_err(ServeError::Cas)?;
            manifest.push(ManifestEntry {
                rel_path: share_rel_path(root, &entry),
                chunk_addr: addr,
                size: bytes.len() as u64,
            });
        }

        Ok(Self { manifest, store })
    }

    /// The number of files in the share (one chunk per file, alpha).
    pub fn file_count(&self) -> usize {
        self.manifest.len()
    }

    /// Borrow the manifest entries (for the listing / progress UX).
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest
    }

    /// Pure request → response: given a decoded inbound [`ShareFrame`], return
    /// the frame to relay back, or `None` when this serve side does not answer
    /// (a response-kind frame echoing back, or a `ChunkRequest` for a chunk we
    /// do not hold). Holding no answer for an unknown chunk is the
    /// self-consistency property behind ISC-A-S21 — the serve side never
    /// fabricates content.
    ///
    /// `ChunkResponse.data` is sourced straight from the content-addressed
    /// store, so its bytes hash to the `chunk_addr` the response advertises by
    /// construction (ISC-S28); a faithful relay forward passes the fetcher's
    /// verification, a tampering relay fails it (ISC-A-S20).
    ///
    /// Delegates to the [`ChunkSource`] provided method so the in-RAM and
    /// disk-backed answer paths are one implementation; kept inherent so
    /// existing callers need no trait import.
    pub fn answer(&self, req: &ShareFrame) -> Option<ShareFrame> {
        ChunkSource::answer(self, req)
    }
}

impl ChunkSource for ShareContent {
    fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest
    }

    fn chunk(&self, addr: &ChunkAddr) -> Option<Vec<u8>> {
        // `get` is the authorized-participant O(1) lookup; the constant-time
        // `has` path is the relay's adversary-probe surface, not the sharer's
        // own serve loop.
        self.store.get(addr).ok().flatten()
    }
}

/// The minimal content surface a serve loop needs to answer fetcher requests:
/// the manifest (for `ManifestRequest`) and a per-address chunk lookup (for
/// `ChunkRequest`), with the pure `answer` step provided on top. Implemented
/// by both the in-RAM [`ShareContent`] and the disk-backed
/// [`DiskShareContent`], so a transport driver (the CLI's `publish --path`
/// serve loop, the TUI net actor) serves either through one code path.
pub trait ChunkSource {
    /// Borrow the manifest entries (the `ManifestResponse` body, and the
    /// listing / progress UX).
    fn manifest(&self) -> &[ManifestEntry];

    /// The bytes of one chunk this source holds, or `None` when it does not —
    /// or can no longer faithfully — serve that address (an unknown chunk, or
    /// a disk-backed file that changed since hashing). The serve loop relays
    /// no frame in that case: the source never fabricates content
    /// (ISC-A-S21).
    fn chunk(&self, addr: &ChunkAddr) -> Option<Vec<u8>>;

    /// Pure request → response: given a decoded inbound [`ShareFrame`], return
    /// the frame to relay back, or `None` when this serve side does not answer
    /// (a response-kind frame echoing back, or a `ChunkRequest` this source
    /// cannot faithfully serve). See [`ShareContent::answer`] for the ISC
    /// provenance — this is that logic, factored over the trait.
    fn answer(&self, req: &ShareFrame) -> Option<ShareFrame> {
        match req {
            ShareFrame::ManifestRequest => Some(ShareFrame::ManifestResponse {
                entries: self.manifest().to_vec(),
            }),
            ShareFrame::ChunkRequest { chunk_addr } => {
                let data = self.chunk(chunk_addr)?;
                Some(ShareFrame::ChunkResponse {
                    chunk_addr: *chunk_addr,
                    data,
                })
            }
            // A response frame (manifest/chunk) arriving inbound is another
            // party's traffic or an echo — the serve side never answers it.
            ShareFrame::ManifestResponse { .. } | ShareFrame::ChunkResponse { .. } => None,
        }
    }
}

// ── Streaming hash pass + disk-backed content (M16) ───────────────────────

/// The manifest a hash pass produces over a share root — one [`ManifestEntry`]
/// per file, in the same deterministic order as [`ShareContent::index_dir`]
/// (sorted walk + full-path sort), so the wire form is stable across runs and
/// platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareManifest {
    /// One entry per file under the share root.
    pub entries: Vec<ManifestEntry>,
}

/// Walk `root`, hashing every regular file beneath it into a [`ShareManifest`]
/// **without ever holding a whole file in memory** — each file streams through
/// a fixed [`HASH_BUF_LEN`] buffer into SHA-384. The resulting `chunk_addr`
/// per file is byte-identical to what [`ShareContent::index_dir`] (via
/// `MemoryChunkStore::put`) derives for the same bytes — one SHA-384 over the
/// file's full content — so fetch-side verification is unchanged (ISC-S28).
///
/// Two passes: the file list is collected first so `progress(done, total)`
/// reports a stable total from the first callback; then each file is hashed,
/// with `progress` invoked after every file. `cancel` is checked between
/// files — a set flag aborts with [`ServeError::Cancelled`] (no partial
/// manifest). An unreadable file aborts the pass, same posture as
/// `index_dir`: a sharer must know its own content is complete before
/// advertising it.
pub fn hash_share(
    root: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<ShareManifest, ServeError> {
    // Pass 1: count (and order) the files so the progress total is stable.
    let files = share_files(root);
    let total = files.len();
    let mut entries = Vec::with_capacity(total);

    // Pass 2: stream-hash each file.
    for (done, entry) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(ServeError::Cancelled);
        }
        let size = entry
            .metadata()
            .map_err(|e| ServeError::Io(e.into()))?
            .len();
        entries.push(ManifestEntry {
            rel_path: share_rel_path(root, entry),
            chunk_addr: hash_file(entry.path())?,
            size,
        });
        progress(done + 1, total);
    }

    Ok(ShareManifest { entries })
}

/// Disk-backed serve content: the share root plus a hashed [`ShareManifest`]
/// (from [`hash_share`] or `indexer::cached_or_hash`). Where [`ShareContent`]
/// holds every file's bytes in RAM, this reads a requested chunk's **one**
/// file from disk at answer time, so serving a share costs memory proportional
/// to one file, not the whole share.
///
/// Each read applies cheap fail-closed checks only — a read error, or a byte
/// length that no longer matches the manifest entry
/// ([`ServeError::ChunkModified`]). Content integrity is verified by the
/// **receiver**, not re-proved here per request — see [`Self::get_chunk`].
pub struct DiskShareContent {
    root: PathBuf,
    manifest: ShareManifest,
    /// `chunk_addr` → index into `manifest.entries`, built once so the
    /// per-request lookup is O(1) rather than a manifest scan. Duplicate
    /// content (two identical files) collapses to one slot — either file
    /// serves the same bytes.
    by_addr: HashMap<[u8; CHUNK_ADDR_LEN], usize>,
}

impl DiskShareContent {
    /// Pair a share `root` with the `manifest` a hash pass produced over it.
    pub fn new(root: PathBuf, manifest: ShareManifest) -> Self {
        let by_addr = manifest
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (*e.chunk_addr.as_bytes(), i))
            .collect();
        Self {
            root,
            manifest,
            by_addr,
        }
    }

    /// The number of files in the share (one chunk per file, alpha).
    pub fn file_count(&self) -> usize {
        self.manifest.entries.len()
    }

    /// Borrow the manifest entries (for the listing / progress UX).
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest.entries
    }

    /// Read one chunk's file from disk, with cheap fail-closed checks only.
    ///
    /// Locates the manifest entry by address ([`ServeError::UnknownChunk`] if
    /// absent) and reads that one file. A read failure — the file moved or
    /// was deleted since the hash pass, the publish-time TOCTOU — is a clean
    /// [`ServeError::Io`], never a panic; a byte length that no longer
    /// matches the manifest entry's size (truncation or growth) fails closed
    /// with [`ServeError::ChunkModified`].
    ///
    /// Deliberately **no serve-time re-hash**: the fetcher already
    /// re-derives SHA-384 over every `ChunkResponse` and fails closed on a
    /// mismatch (M11, the file-side analog of `open_message` — ISC-S28), so
    /// receiver-side verification is the integrity guarantee. Re-hashing
    /// here would cost a full pass over the file before the first byte goes
    /// out on EVERY request — a multi-GB hash per fetch — and catch nothing
    /// the receiver won't. The consequence, stated plainly: a **same-size**
    /// content change on the sharer's own disk passes this server and is
    /// rejected by the receiver's hash check. Re-run the hash pass and
    /// re-publish to serve intentionally changed content.
    pub fn get_chunk(&self, addr: &ChunkAddr) -> Result<Vec<u8>, ServeError> {
        let &i = self
            .by_addr
            .get(addr.as_bytes())
            .ok_or(ServeError::UnknownChunk)?;
        let entry = &self.manifest.entries[i];
        let bytes = std::fs::read(join_rel(&self.root, &entry.rel_path)).map_err(ServeError::Io)?;
        if bytes.len() as u64 != entry.size {
            return Err(ServeError::ChunkModified {
                rel_path: entry.rel_path.clone(),
            });
        }
        Ok(bytes)
    }
}

impl ChunkSource for DiskShareContent {
    fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest.entries
    }

    /// Any failure (unknown address, I/O, a file changed since hashing)
    /// collapses to `None` — the serve loop relays no frame rather than a
    /// knowingly bad one (ISC-A-S21 / ISC-S28 fail-closed posture).
    fn chunk(&self, addr: &ChunkAddr) -> Option<Vec<u8>> {
        self.get_chunk(addr).ok()
    }
}

/// Collect the regular files under `root` in the deterministic share order
/// shared by [`ShareContent::index_dir`], [`hash_share`], and the indexer's
/// cached pass: a name-sorted walk, then a full-path sort (WalkDir's native
/// order is filesystem-dependent). This single function is what guarantees
/// the RAM-backed and disk-backed manifests agree entry-for-entry.
pub(crate) fn share_files(root: &Path) -> Vec<walkdir::DirEntry> {
    let mut files: Vec<_> = WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    files.sort_by(|a, b| a.path().cmp(b.path()));
    files
}

/// The manifest `rel_path` for a walked entry: the path relative to `root`,
/// using `/` separators on every platform so the wire form is stable.
pub(crate) fn share_rel_path(root: &Path, entry: &walkdir::DirEntry) -> String {
    match entry.path().strip_prefix(root) {
        Ok(rel) => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        // Should not happen (WalkDir yields paths under root); fall
        // back to the file name so the entry is still usable.
        Err(_) => entry.file_name().to_string_lossy().into_owned(),
    }
}

/// Stream-hash one file's full contents to its chunk address through a fixed
/// [`HASH_BUF_LEN`] buffer — the digest is the same SHA-384 over the same
/// bytes as [`crate::storage::cas::chunk_addr`], just fed incrementally, so
/// the address is byte-identical to the whole-file path's.
pub(crate) fn hash_file(path: &Path) -> Result<ChunkAddr, ServeError> {
    let mut file = std::fs::File::open(path).map_err(ServeError::Io)?;
    let mut hasher = Sha384::new().map_err(|e| ServeError::Cas(CasError::Hash(e)))?;
    let mut buf = vec![0u8; HASH_BUF_LEN];
    loop {
        let n = file.read(&mut buf).map_err(ServeError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(ChunkAddr::from_bytes(hasher.finalize()))
}

/// Join a `/`-separated manifest `rel_path` back onto the share root using
/// native components (the inverse of [`share_rel_path`] on every platform).
fn join_rel(root: &Path, rel_path: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in rel_path.split('/') {
        path.push(component);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cas::chunk_addr;

    fn write(root: &Path, rel: &str, contents: &[u8]) {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, contents).unwrap();
    }

    /// ISC-S27 — indexing a directory builds one manifest entry per file, with
    /// the content address and size of each, recovering the bytes from the
    /// store under that address.
    #[test]
    fn index_dir_builds_manifest_and_stores_chunks() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.txt", b"alpha");
        write(dir.path(), "sub/b.txt", b"bravo bravo");

        let content = ShareContent::index_dir(dir.path()).unwrap();
        assert_eq!(content.file_count(), 2);

        // Manifest is sorted deterministically (a.txt before sub/b.txt).
        let m = content.manifest();
        assert_eq!(m[0].rel_path, "a.txt");
        assert_eq!(m[0].size, 5);
        assert_eq!(m[1].rel_path, "sub/b.txt");
        assert_eq!(m[1].size, 11);

        // The address is SHA-384 of the file bytes.
        assert_eq!(m[0].chunk_addr, chunk_addr(b"alpha").unwrap());
    }

    /// ISC-S27 — `answer(ManifestRequest)` returns the full manifest.
    #[test]
    fn answer_manifest_request_returns_manifest() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "only.txt", b"the only file");
        let content = ShareContent::index_dir(dir.path()).unwrap();

        match content.answer(&ShareFrame::ManifestRequest) {
            Some(ShareFrame::ManifestResponse { entries }) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].rel_path, "only.txt");
            }
            other => panic!("expected ManifestResponse, got {other:?}"),
        }
    }

    /// ISC-S28 — a served `ChunkResponse`'s bytes hash to the address it
    /// advertises (content-addressed by construction): the fetcher's
    /// re-derived-hash verification passes on a faithful serve.
    #[test]
    fn answer_chunk_request_is_content_addressed() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "f.bin", b"some bytes to address");
        let content = ShareContent::index_dir(dir.path()).unwrap();
        let addr = content.manifest()[0].chunk_addr;

        match content.answer(&ShareFrame::ChunkRequest { chunk_addr: addr }) {
            Some(ShareFrame::ChunkResponse {
                chunk_addr: a,
                data,
            }) => {
                assert_eq!(a, addr, "echoes the requested address");
                // The load-bearing check: recompute SHA-384(data) == addr.
                assert_eq!(
                    chunk_addr(&data).unwrap(),
                    addr,
                    "served chunk bytes hash to the advertised address (ISC-S28)"
                );
                assert_eq!(data, b"some bytes to address");
            }
            other => panic!("expected ChunkResponse, got {other:?}"),
        }
    }

    /// ISC-A-S21 (self-consistency half) — the serve side never fabricates a
    /// chunk it does not hold: a request for an unknown address yields no
    /// answer, so an offline / never-indexed file is unfetchable from this
    /// serve side (the live-only relay supplies the other half).
    #[test]
    fn answer_unknown_chunk_yields_no_frame() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "present.txt", b"i exist");
        let content = ShareContent::index_dir(dir.path()).unwrap();

        let absent = chunk_addr(b"this content was never shared").unwrap();
        assert!(
            content
                .answer(&ShareFrame::ChunkRequest { chunk_addr: absent })
                .is_none(),
            "no answer for a chunk the serve side does not hold (ISC-A-S21)"
        );
    }

    /// A response-kind frame arriving inbound is never answered (it is another
    /// party's traffic or an echo of our own response).
    #[test]
    fn answer_ignores_response_frames() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "x", b"x");
        let content = ShareContent::index_dir(dir.path()).unwrap();
        assert!(
            content
                .answer(&ShareFrame::ManifestResponse {
                    entries: Vec::new()
                })
                .is_none()
        );
        let addr = content.manifest()[0].chunk_addr;
        assert!(
            content
                .answer(&ShareFrame::ChunkResponse {
                    chunk_addr: addr,
                    data: b"x".to_vec()
                })
                .is_none()
        );
    }

    /// An empty share root indexes to an empty manifest (a valid state — a
    /// sharer can offer an empty folder), and answers the manifest request
    /// with zero entries rather than failing.
    #[test]
    fn index_empty_dir_is_empty_manifest() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let content = ShareContent::index_dir(dir.path()).unwrap();
        assert_eq!(content.file_count(), 0);
        match content.answer(&ShareFrame::ManifestRequest) {
            Some(ShareFrame::ManifestResponse { entries }) => assert!(entries.is_empty()),
            other => panic!("expected empty ManifestResponse, got {other:?}"),
        }
    }

    // ── streaming hash pass (M16) ──────────────────────────────────────────

    /// A no-op cancel flag for passes that should run to completion.
    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// The streaming hash pass produces a manifest **byte-identical** to
    /// `index_dir`'s on the same fixture tree — same order, same `rel_path`s,
    /// same sizes, and the same SHA-384 chunk addresses `MemoryChunkStore::put`
    /// derived — so existing fetch-side verification is unchanged (ISC-S28).
    /// The fixture includes a file larger than the streaming buffer so the
    /// multi-read path is exercised, not just the single-read one.
    #[test]
    fn hash_share_matches_index_dir() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.txt", b"alpha");
        write(dir.path(), "sub/b.txt", b"bravo bravo");
        // > HASH_BUF_LEN, with non-uniform content spanning the buffer seam.
        let big: Vec<u8> = (0..HASH_BUF_LEN + 4096).map(|i| (i % 251) as u8).collect();
        write(dir.path(), "big.bin", &big);

        let indexed = ShareContent::index_dir(dir.path()).unwrap();
        let hashed = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();

        assert_eq!(hashed.entries, indexed.manifest());
    }

    /// The hash pass reports `(done, total)` after every file, with the total
    /// fixed from the first callback (the count pass ran first).
    #[test]
    fn hash_share_reports_progress_per_file() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.txt", b"a");
        write(dir.path(), "b.txt", b"b");
        write(dir.path(), "c.txt", b"c");

        let mut seen = Vec::new();
        hash_share(dir.path(), &no_cancel(), &mut |done, total| {
            seen.push((done, total));
        })
        .unwrap();
        assert_eq!(seen, vec![(1, 3), (2, 3), (3, 3)]);
    }

    /// A set cancel flag aborts the pass with `Cancelled` before any file is
    /// hashed — no partial manifest escapes.
    #[test]
    fn hash_share_cancel_aborts() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.txt", b"a");

        let cancel = AtomicBool::new(true);
        let mut calls = 0usize;
        let result = hash_share(dir.path(), &cancel, &mut |_, _| calls += 1);
        assert!(matches!(result, Err(ServeError::Cancelled)));
        assert_eq!(calls, 0, "cancelled before the first file");
    }

    // ── disk-backed content (M16) ──────────────────────────────────────────

    /// Build a `DiskShareContent` over a fresh fixture tree.
    fn disk_fixture() -> (tempfile::TempDir, DiskShareContent) {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.txt", b"alpha");
        write(dir.path(), "sub/b.txt", b"bravo bravo");
        let manifest = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();
        let content = DiskShareContent::new(dir.path().to_path_buf(), manifest);
        (dir, content)
    }

    /// ISC-S27 / ISC-S28 — the disk-backed source answers a manifest request
    /// with the full manifest and a chunk request with bytes read from disk
    /// that hash to the advertised address, through the same `ChunkSource`
    /// answer path the serve loop drives.
    #[test]
    fn disk_content_serves_manifest_and_chunks_from_disk() {
        let (_dir, content) = disk_fixture();
        assert_eq!(content.file_count(), 2);

        match content.answer(&ShareFrame::ManifestRequest) {
            Some(ShareFrame::ManifestResponse { entries }) => {
                assert_eq!(entries, content.manifest());
            }
            other => panic!("expected ManifestResponse, got {other:?}"),
        }

        let addr = content.manifest()[0].chunk_addr;
        match content.answer(&ShareFrame::ChunkRequest { chunk_addr: addr }) {
            Some(ShareFrame::ChunkResponse {
                chunk_addr: a,
                data,
            }) => {
                assert_eq!(a, addr);
                assert_eq!(chunk_addr(&data).unwrap(), addr, "ISC-S28 on disk");
                assert_eq!(data, b"alpha");
            }
            other => panic!("expected ChunkResponse, got {other:?}"),
        }
    }

    /// A file whose **size** changed since the hash pass (truncation/growth —
    /// the cheap check `get_chunk` keeps) fails closed: `ChunkModified`, and
    /// the serve answer relays no frame. Content integrity beyond the length
    /// check is the receiver's job — see the same-size-tamper test below.
    #[test]
    fn disk_content_fails_closed_on_modified_file() {
        let (dir, content) = disk_fixture();
        let addr = content.manifest()[0].chunk_addr; // a.txt, 5 bytes
        write(dir.path(), "a.txt", b"ALPHA REWRITTEN LONGER"); // size 5 → 22

        assert!(matches!(
            content.get_chunk(&addr),
            Err(ServeError::ChunkModified { ref rel_path }) if rel_path == "a.txt"
        ));
        assert!(
            content
                .answer(&ShareFrame::ChunkRequest { chunk_addr: addr })
                .is_none(),
            "the serve loop relays no frame for a size-changed file"
        );
    }

    /// The receiver-verification contract, pinned: a **same-size** content
    /// change passes the serve side (no serve-time re-hash — the bytes are
    /// returned, no panic, no error) and the served bytes provably fail the
    /// fetcher's re-derived SHA-384 check (ISC-S28, M11) — rejecting tampered
    /// content is the receiver's job, not a per-request full hash here.
    #[test]
    fn disk_content_same_size_tamper_is_rejected_by_receiver_not_server() {
        let (dir, content) = disk_fixture();
        let addr = content.manifest()[0].chunk_addr; // a.txt = b"alpha"
        write(dir.path(), "a.txt", b"tlpha"); // same 5-byte length

        let bytes = content
            .get_chunk(&addr)
            .expect("same-size tamper passes the server's cheap checks");
        assert_eq!(bytes, b"tlpha");
        match content.answer(&ShareFrame::ChunkRequest { chunk_addr: addr }) {
            Some(ShareFrame::ChunkResponse { data, .. }) => assert_ne!(
                chunk_addr(&data).unwrap(),
                addr,
                "the fetcher's re-derived hash rejects exactly this frame"
            ),
            other => panic!("expected ChunkResponse, got {other:?}"),
        }
    }

    /// TOCTOU on the publish-time snapshot: a file moved or deleted since the
    /// hash pass yields a clean `ServeError::Io` from `get_chunk` (never a
    /// panic) and no frame from the answer path — the fetcher just sees the
    /// chunk go unanswered.
    #[test]
    fn disk_content_deleted_file_yields_clean_error() {
        let (dir, content) = disk_fixture();
        let addr = content.manifest()[0].chunk_addr; // a.txt
        std::fs::remove_file(dir.path().join("a.txt")).unwrap();

        assert!(matches!(content.get_chunk(&addr), Err(ServeError::Io(_))));
        assert!(
            content
                .answer(&ShareFrame::ChunkRequest { chunk_addr: addr })
                .is_none(),
            "no frame for a file that vanished since hashing"
        );
    }

    /// ISC-A-S21 — an address not in the manifest is `UnknownChunk` from
    /// `get_chunk` and no frame from the answer path: the disk-backed source
    /// never fabricates content either.
    #[test]
    fn disk_content_unknown_chunk_yields_no_frame() {
        let (_dir, content) = disk_fixture();
        let absent = chunk_addr(b"never shared").unwrap();
        assert!(matches!(
            content.get_chunk(&absent),
            Err(ServeError::UnknownChunk)
        ));
        assert!(
            content
                .answer(&ShareFrame::ChunkRequest { chunk_addr: absent })
                .is_none()
        );
    }

    /// The trait-provided answer and `ShareContent`'s inherent answer are the
    /// same logic: both serve sides agree frame-for-frame on the same tree.
    #[test]
    fn ram_and_disk_sources_answer_identically() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "x.txt", b"same bytes either way");

        let ram = ShareContent::index_dir(dir.path()).unwrap();
        let manifest = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();
        let disk = DiskShareContent::new(dir.path().to_path_buf(), manifest);

        let addr = ram.manifest()[0].chunk_addr;
        for req in [
            ShareFrame::ManifestRequest,
            ShareFrame::ChunkRequest { chunk_addr: addr },
        ] {
            assert_eq!(ram.answer(&req), ChunkSource::answer(&disk, &req));
        }
    }
}
