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
//!    splits it into fixed [`CHUNK_SIZE`] chunks (M16 — see below), stores
//!    each chunk in a [`crate::storage::cas::MemoryChunkStore`], and records
//!    a [`ManifestEntry`] per file carrying the **ordered** per-chunk address
//!    list. Each address is `SHA-384(chunk-bytes)` — the same content address
//!    the fetcher re-derives and verifies per chunk (ISC-S28).
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
//! `SHA-384` (it was stored under `chunk_addr(chunk-bytes)`), so a faithful relay
//! forward passes the fetcher's re-derived-hash verification; a relay that
//! tampers with the bytes in flight fails it (ISC-A-S20, proved fetcher-side).
//!
//! ## Sub-file fixed-size chunking (M16 — ISC-C73 / ISC-A-C35)
//!
//! The alpha's chunk == whole file put an entire file's bytes into ONE
//! `ChunkResponse`, hence one gRPC frame: an 8.9 MB file exceeded tonic's
//! default 4 MB per-message decode cap at the relay and the fetch hung — the
//! live gap this module closes. Every file is now split into fixed
//! [`CHUNK_SIZE`] (1 MiB) chunks: chunk `i` covers
//! `[i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size))`, so only the last chunk may
//! be short, and an empty file has no chunks at all. That keeps every frame
//! relay-safe regardless of file size, makes serve and fetch O(CHUNK_SIZE)
//! in memory, and makes the fetcher's per-chunk SHA-384 verification cheap.
//! The relay never decodes `CotFrame.payload` (ISC-A-S2), so deployed relays
//! keep working unchanged; the manifest encoding changed in place — see the
//! [`crate::share_envelope`] module docs for the alpha-compat waiver.
//!
//! ## Disk-backed serving
//!
//! [`ShareContent::index_dir`] reads every file into RAM, which caps a share
//! at available memory. The disk-backed path replaces that for the publish
//! flow while keeping the fetcher's verification untouched:
//!
//! 1. [`hash_share`] walks the same deterministic file order as `index_dir`
//!    but only *hashes* each file — one [`CHUNK_SIZE`] buffer at a time,
//!    never a whole-file read — producing a [`ShareManifest`] whose per-chunk
//!    addresses are byte-identical to what `MemoryChunkStore::put` derives
//!    for the same chunk bytes, so the fetch-side verification is unchanged
//!    (ISC-S28). It is cancellable between files **and between chunks** of a
//!    large file, and reports per-file progress.
//! 2. [`DiskShareContent`] pairs that manifest with the share root and reads
//!    a requested chunk's [`CHUNK_SIZE`]-bounded byte range from disk at
//!    answer time (seek + exact-length read), with **cheap** fail-closed
//!    checks only (a read error, or a length that no longer matches the
//!    manifest entry — [`ServeError::ChunkModified`]). There is
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
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use crate::share_envelope::{ManifestEntry, ShareFrame};
use crate::storage::cas::{
    CHUNK_ADDR_LEN, CasError, ChunkAddr, ChunkStore, MemoryChunkStore, chunk_addr,
};

/// Fixed share-chunk size: 1 MiB (M16 — ISC-C73 / ISC-A-C35). Every file is
/// split into chunks of exactly this many bytes (only the last chunk of a
/// file may be short), and one chunk rides in one `ChunkResponse`, hence one
/// gRPC frame. This MUST stay well under tonic's default 4 MB per-message
/// decode cap — including the `CotFrame` envelope overhead (asset address,
/// `ShareFrame` header, protobuf framing) — because the relay decodes the
/// *outer* `CotFrame` even though it never looks inside the payload: a chunk
/// that pushes the outer message past the cap stalls the fetch at the relay
/// (the exact 8.9 MB-file failure that motivated M16 chunking).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// The largest encoded `ManifestResponse` a publisher may put on the wire
/// (M16 design review). [`CHUNK_SIZE`] keeps every *content* frame under
/// tonic's default 4 MiB (4_194_304 bytes) per-message decode cap at the
/// relay — but the MANIFEST frame itself grows with file count (~62 bytes +
/// path per entry), so a file-count-dense share (a music library is exactly
/// this shape) would reproduce the same silent publish-stall for the
/// manifest that chunking fixed for content. 3_500_000 leaves ~694 KB of
/// headroom under the cap for the `CotFrame` envelope around the
/// `ShareFrame` (asset address, protobuf field/length framing) plus margin
/// against a relay configured tighter. The publish flow checks
/// [`manifest_frame_len`] against this BEFORE advertising the listing and
/// refuses loudly — never a silent stall.
pub const MANIFEST_FRAME_BUDGET: usize = 3_500_000;

/// The exact byte length of the encoded `ShareFrame::ManifestResponse`
/// carrying `manifest`'s entries — what the manifest's wire frame will
/// weigh, computed WITHOUT building the (potentially multi-megabyte)
/// buffer.
///
/// Mirrors the [`crate::share_envelope`] entry encoding exactly:
/// `[1 kind][u32 count]` + per entry `[u16 path-len][path bytes][u64 size]
/// [u32 chunk_count][48-byte addr × chunk_count]`. The unit test
/// `manifest_frame_len_matches_real_encoding` pins this arithmetic to
/// `ShareFrame::encode`'s actual output length, so the two cannot drift
/// silently.
pub fn manifest_frame_len(manifest: &ShareManifest) -> usize {
    1 + 4
        + manifest
            .entries
            .iter()
            .map(|e| 2 + e.rel_path.len() + 8 + 4 + e.chunks.len() * CHUNK_ADDR_LEN)
            .sum::<usize>()
}

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
    /// Walk `root`, chunk every regular file beneath it into the content store
    /// in fixed [`CHUNK_SIZE`] pieces (M16 — ISC-C73 / ISC-A-C35), and build
    /// the manifest (one entry per file, ordered per-chunk addresses; an
    /// empty file gets `chunks: []`). The manifest's `rel_path` is the file's
    /// path relative to `root`, using `/` separators on every platform so the
    /// wire form is stable; an unreadable file aborts the index (a sharer
    /// must know its own content is complete before advertising it — unlike
    /// the relay-side indexer's skip-and-continue posture).
    ///
    /// This RAM path is kept for tests and the CLI's small shares — it still
    /// holds every chunk's bytes in memory. The disk-backed
    /// [`DiskShareContent`] is the O(CHUNK_SIZE)-memory publish path. The
    /// parity test `hash_share_matches_index_dir` pins both paths to
    /// byte-identical manifests.
    pub fn index_dir(root: impl AsRef<Path>) -> Result<Self, ServeError> {
        let root = root.as_ref();
        let mut store = MemoryChunkStore::new();
        let mut manifest = Vec::new();

        for entry in share_files(root) {
            let bytes = std::fs::read(entry.path()).map_err(ServeError::Io)?;
            // Same boundaries as the streaming hash pass: chunk i covers
            // [i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size)); empty file → no
            // chunks. `MemoryChunkStore::put` derives SHA-384 over exactly
            // the chunk slice, so both paths agree address-for-address.
            let mut chunks = Vec::with_capacity(bytes.len().div_ceil(CHUNK_SIZE));
            for chunk in bytes.chunks(CHUNK_SIZE) {
                chunks.push(store.put(chunk).map_err(ServeError::Cas)?);
            }
            manifest.push(ManifestEntry {
                rel_path: share_rel_path(root, &entry),
                size: bytes.len() as u64,
                chunks,
            });
        }

        Ok(Self { manifest, store })
    }

    /// The number of files in the share (manifest entries, not chunks).
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
    ///
    /// A conforming implementation must never let [`Self::manifest`] advertise
    /// an address this method would answer with bytes that are not that
    /// address's content. Answering `None` is always allowed — it degrades to
    /// the offline-equivalent NOT_FOUND — but answering *wrong* bytes is the
    /// one thing a source may not do. The bound is stated here because the
    /// serve registry holds `dyn ChunkSource`, so this contract is no longer
    /// local to the two implementations in this module.
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

// ── Streaming hash pass + disk-backed content ───────────────────────

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
/// **without ever holding a whole file in memory** — each file is read one
/// [`CHUNK_SIZE`] buffer at a time, and each buffer-load IS one chunk, hashed
/// to its own SHA-384 address (M16 — ISC-C73 / ISC-A-C35). The resulting
/// per-chunk addresses are byte-identical to what [`ShareContent::index_dir`]
/// (via `MemoryChunkStore::put`) derives for the same chunk bytes, so
/// fetch-side verification is unchanged (ISC-S28).
///
/// Two passes: the file list is collected first so `progress(done, total)`
/// reports a stable total from the first callback; then each file is hashed,
/// with `progress` invoked after every file — progress stays **per-file**
/// (a chunk is an internal unit, not a UX one). `cancel` is checked between
/// files and **between chunks** of a large file — a multi-GB file must not
/// pin the pass against a cancel request — and a set flag aborts with
/// [`ServeError::Cancelled`] (no partial manifest). An unreadable file aborts
/// the pass, same posture as `index_dir`: a sharer must know its own content
/// is complete before advertising it.
pub fn hash_share(
    root: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<ShareManifest, ServeError> {
    // Pass 1: count (and order) the files so the progress total is stable.
    let files = share_files(root);
    let total = files.len();
    let mut entries = Vec::with_capacity(total);

    // Pass 2: stream-hash each file, chunk by chunk.
    for (done, entry) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(ServeError::Cancelled);
        }
        let (chunks, size) = hash_file_chunks(entry.path(), cancel)?;
        entries.push(ManifestEntry {
            rel_path: share_rel_path(root, entry),
            size,
            chunks,
        });
        progress(done + 1, total);
    }

    Ok(ShareManifest { entries })
}

/// Disk-backed serve content: the share root plus a hashed [`ShareManifest`]
/// (from [`hash_share`] or `indexer::cached_or_hash`). Where [`ShareContent`]
/// holds every file's bytes in RAM, this reads a requested chunk's
/// [`CHUNK_SIZE`]-bounded byte range from its one file at answer time, so
/// serving a share costs O(CHUNK_SIZE) memory per request — never a whole
/// file, never the whole share (M16, ISC-C73 / ISC-A-C35).
///
/// Each read applies cheap fail-closed checks only — a read error, or a
/// length that no longer matches what the manifest entry implies for that
/// chunk ([`ServeError::ChunkModified`]). Content integrity is verified by
/// the **receiver**, not re-proved here per request — see [`Self::get_chunk`].
pub struct DiskShareContent {
    root: PathBuf,
    manifest: ShareManifest,
    /// `chunk_addr` → `(entry index, chunk index within that entry)`, built
    /// once so the per-request lookup is O(1) rather than a manifest scan.
    /// Duplicate addresses across (or within) files keep the FIRST mapping —
    /// CAS semantics: the same address names the same bytes, so any holder
    /// serves identical content and one slot suffices.
    by_addr: HashMap<[u8; CHUNK_ADDR_LEN], (usize, usize)>,
}

impl DiskShareContent {
    /// Pair a share `root` with the `manifest` a hash pass produced over it.
    pub fn new(root: PathBuf, manifest: ShareManifest) -> Self {
        let mut by_addr = HashMap::new();
        for (i, entry) in manifest.entries.iter().enumerate() {
            for (c, addr) in entry.chunks.iter().enumerate() {
                // First wins (CAS: same addr ⇒ same bytes — see field docs).
                by_addr.entry(*addr.as_bytes()).or_insert((i, c));
            }
        }
        Self {
            root,
            manifest,
            by_addr,
        }
    }

    /// The number of files in the share (manifest entries, not chunks).
    pub fn file_count(&self) -> usize {
        self.manifest.entries.len()
    }

    /// Borrow the manifest entries (for the listing / progress UX).
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest.entries
    }

    /// Read one chunk's byte range from its file on disk, with cheap
    /// fail-closed checks only.
    ///
    /// Locates `(file, chunk index)` by address via the prebuilt map
    /// ([`ServeError::UnknownChunk`] if absent), opens that one file, seeks
    /// to `chunk_index * CHUNK_SIZE`, and reads **exactly** the chunk's
    /// manifest-implied length into a right-sized buffer — O(CHUNK_SIZE)
    /// memory however large the file is. Failure posture:
    ///
    /// - A read/open failure — the file moved or was deleted since the hash
    ///   pass, the publish-time TOCTOU — is a clean [`ServeError::Io`],
    ///   never a panic.
    /// - A length mismatch — the file's on-disk size no longer matches the
    ///   manifest entry, or the exact-length read comes up short — fails
    ///   closed with [`ServeError::ChunkModified`]: we never put a
    ///   *knowingly* wrong-length frame on the wire.
    ///
    /// Deliberately **no serve-time re-hash**: the fetcher already
    /// re-derives SHA-384 over every `ChunkResponse` and fails closed on a
    /// mismatch (M11, the file-side analog of `open_message` — ISC-S28), so
    /// receiver-side verification is the integrity guarantee. Re-hashing
    /// here would cost a hash pass before every frame and catch nothing the
    /// receiver won't. The consequence, stated plainly: a **same-size**
    /// content change on the sharer's own disk passes this server and is
    /// rejected by the receiver's per-chunk hash check. Re-run the hash pass
    /// and re-publish to serve intentionally changed content.
    pub fn get_chunk(&self, addr: &ChunkAddr) -> Result<Vec<u8>, ServeError> {
        let &(i, c) = self
            .by_addr
            .get(addr.as_bytes())
            .ok_or(ServeError::UnknownChunk)?;
        let entry = &self.manifest.entries[i];
        let modified = || ServeError::ChunkModified {
            rel_path: entry.rel_path.clone(),
        };

        let mut file =
            std::fs::File::open(join_rel(&self.root, &entry.rel_path)).map_err(ServeError::Io)?;
        // Cheap whole-file length check first: truncation or growth since
        // the hash pass invalidates every chunk boundary, not just this one.
        let on_disk = file.metadata().map_err(ServeError::Io)?.len();
        if on_disk != entry.size {
            return Err(modified());
        }

        // Chunk i covers [i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size)) — the
        // invariant pinned on `ManifestEntry::chunks`.
        let offset = (c as u64) * (CHUNK_SIZE as u64);
        let expected = (entry.size - offset).min(CHUNK_SIZE as u64) as usize;
        file.seek(SeekFrom::Start(offset)).map_err(ServeError::Io)?;
        let mut buf = vec![0u8; expected];
        file.read_exact(&mut buf).map_err(|e| {
            // A short read despite the length check (a race with truncation)
            // is a modification, not an I/O fault; everything else is Io.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                modified()
            } else {
                ServeError::Io(e)
            }
        })?;
        Ok(buf)
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

/// Stream one file into its ordered per-chunk addresses plus the total byte
/// count actually read (M16 — ISC-C73 / ISC-A-C35). The file is read one
/// [`CHUNK_SIZE`] buffer at a time, and each **full** buffer-load is hashed
/// as one chunk via [`crate::storage::cas::chunk_addr`] — exactly the digest
/// `MemoryChunkStore::put` derives for the same chunk slice — so memory stays
/// O(CHUNK_SIZE) regardless of file size and the addresses are byte-identical
/// to [`ShareContent::index_dir`]'s. An empty file yields `([], 0)`.
///
/// The returned size is the bytes *streamed*, not a `stat`, so
/// `chunks.len() == size.div_ceil(CHUNK_SIZE)` holds by construction — the
/// manifest can never advertise a chunk list inconsistent with its own size
/// field even if the file changes mid-pass (the per-chunk fetch verification
/// then rejects stale chunks, ISC-S28).
///
/// `cancel` is checked between chunks: a multi-GB file must not pin the hash
/// pass against a cancel request (the between-files check alone would).
pub(crate) fn hash_file_chunks(
    path: &Path,
    cancel: &AtomicBool,
) -> Result<(Vec<ChunkAddr>, u64), ServeError> {
    let mut file = std::fs::File::open(path).map_err(ServeError::Io)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunks = Vec::new();
    let mut size: u64 = 0;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(ServeError::Cancelled);
        }
        // Fill the buffer completely before hashing: `read` may return short
        // reads mid-file (pipes, network filesystems), and a chunk boundary
        // moved by a short read would silently change every following
        // address. Only EOF may leave a chunk short.
        let n = read_to_fill(&mut file, &mut buf).map_err(ServeError::Io)?;
        if n == 0 {
            break;
        }
        chunks.push(chunk_addr(&buf[..n]).map_err(|e| ServeError::Cas(CasError::Hash(e)))?);
        size += n as u64;
        if n < CHUNK_SIZE {
            break; // EOF inside this chunk — it is the (short) last one.
        }
    }
    Ok((chunks, size))
}

/// Read from `r` until `buf` is full or EOF; returns how many bytes were
/// read. (Like `read_exact` but EOF-tolerant — the short final chunk of a
/// file is expected, not an error.)
fn read_to_fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
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
    /// the per-chunk content addresses and size of each, recovering the bytes
    /// from the store under those addresses.
    #[test]
    fn index_dir_builds_manifest_and_stores_chunks() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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

        // A sub-CHUNK_SIZE file is one chunk whose address is SHA-384 of the
        // file bytes (the whole file IS the chunk).
        assert_eq!(m[0].chunks, vec![chunk_addr(b"alpha").unwrap()]);
    }

    /// M16 (ISC-C73 / ISC-A-C35) — a file larger than CHUNK_SIZE indexes to
    /// multiple ordered chunks, each addressed by SHA-384 of THAT chunk's
    /// slice, with boundaries at exact CHUNK_SIZE multiples and only the last
    /// chunk short; an empty file indexes to zero chunks.
    #[test]
    fn index_dir_chunks_large_files_at_fixed_boundaries() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let big: Vec<u8> = (0..CHUNK_SIZE + 4096).map(|i| (i % 251) as u8).collect();
        write(dir.path(), "big.bin", &big);
        write(dir.path(), "empty.bin", b"");

        let content = ShareContent::index_dir(dir.path()).unwrap();
        let m = content.manifest();
        assert_eq!(m[0].rel_path, "big.bin");
        assert_eq!(
            m[0].chunks,
            vec![
                chunk_addr(&big[..CHUNK_SIZE]).unwrap(),
                chunk_addr(&big[CHUNK_SIZE..]).unwrap(),
            ],
            "chunk i is SHA-384 over [i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size))"
        );
        assert_eq!(m[1].rel_path, "empty.bin");
        assert_eq!(m[1].size, 0);
        assert!(m[1].chunks.is_empty(), "empty file → no chunks");
    }

    /// ISC-S27 — `answer(ManifestRequest)` returns the full manifest.
    #[test]
    fn answer_manifest_request_returns_manifest() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "f.bin", b"some bytes to address");
        let content = ShareContent::index_dir(dir.path()).unwrap();
        let addr = content.manifest()[0].chunks[0];

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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        let addr = content.manifest()[0].chunks[0];
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let content = ShareContent::index_dir(dir.path()).unwrap();
        assert_eq!(content.file_count(), 0);
        match content.answer(&ShareFrame::ManifestRequest) {
            Some(ShareFrame::ManifestResponse { entries }) => assert!(entries.is_empty()),
            other => panic!("expected empty ManifestResponse, got {other:?}"),
        }
    }

    // ── manifest frame budget (M16 design review) ──────────────────────────

    /// `manifest_frame_len`'s arithmetic equals the REAL encoder's output
    /// length, byte for byte, on a manifest exercising every entry shape:
    /// an empty file (zero chunks), a one-chunk file, a multi-chunk file,
    /// and a multi-byte-UTF-8 path (`rel_path.len()` must count BYTES, not
    /// chars — the encoder writes bytes). This pin is what lets the publish
    /// guard trust the arithmetic instead of building a probe buffer.
    #[test]
    fn manifest_frame_len_matches_real_encoding() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let a = |b: &[u8]| chunk_addr(b).unwrap();
        let manifest = ShareManifest {
            entries: vec![
                ManifestEntry {
                    rel_path: "empty.bin".to_owned(),
                    size: 0,
                    chunks: Vec::new(),
                },
                ManifestEntry {
                    rel_path: "söngvar/álbum.flac".to_owned(), // multi-byte UTF-8
                    size: 7,
                    chunks: vec![a(b"one")],
                },
                ManifestEntry {
                    rel_path: "big.bin".to_owned(),
                    size: 3 * CHUNK_SIZE as u64 + 99,
                    chunks: vec![a(b"c0"), a(b"c1"), a(b"c2"), a(b"c3")],
                },
            ],
        };
        let encoded = ShareFrame::ManifestResponse {
            entries: manifest.entries.clone(),
        }
        .encode();
        assert_eq!(
            manifest_frame_len(&manifest),
            encoded.len(),
            "arithmetic must equal the real encoder's length exactly"
        );
    }

    /// The threshold logic the publish guard runs: a file-count-dense
    /// synthetic manifest (built arithmetically — no real files, no encode)
    /// exceeds [`MANIFEST_FRAME_BUDGET`], while a normal-sized one stays
    /// under, and the budget itself sits under tonic's 4 MiB decode cap.
    #[test]
    fn manifest_frame_budget_threshold_logic() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let addr = chunk_addr(b"x").unwrap();
        let entry = |i: usize| ManifestEntry {
            rel_path: format!("library/track-{i:06}.mp3"),
            size: 1,
            chunks: vec![addr],
        };

        // ~84 bytes/entry → 60_000 entries ≈ 5.0 MB: over budget.
        let dense = ShareManifest {
            entries: (0..60_000).map(entry).collect(),
        };
        assert!(
            manifest_frame_len(&dense) > MANIFEST_FRAME_BUDGET,
            "a many-small-files share must trip the publish guard"
        );

        // A 1_000-file share is nowhere near the budget.
        let normal = ShareManifest {
            entries: (0..1_000).map(entry).collect(),
        };
        assert!(manifest_frame_len(&normal) <= MANIFEST_FRAME_BUDGET);

        // The budget leaves real headroom under tonic's default cap
        // (compile-time: both sides are consts).
        const { assert!(MANIFEST_FRAME_BUDGET < 4 * 1024 * 1024) };
    }

    // ── streaming hash pass ──────────────────────────────────────────

    /// A no-op cancel flag for passes that should run to completion.
    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// The streaming hash pass produces a manifest **byte-identical** to
    /// `index_dir`'s on the same fixture tree — same order, same `rel_path`s,
    /// same sizes, and the same per-chunk SHA-384 addresses
    /// `MemoryChunkStore::put` derived — so existing fetch-side verification
    /// is unchanged (ISC-S28). The fixture spans every chunk-boundary seam:
    /// an empty file (zero chunks), a sub-1MiB file (one short chunk),
    /// an exactly-1MiB file (one full chunk, no phantom empty second chunk),
    /// and a >2MiB file (two full chunks + a short last, non-uniform content
    /// across the seams).
    #[test]
    fn hash_share_matches_index_dir() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "empty.bin", b"");
        write(dir.path(), "a.txt", b"alpha"); // sub-1MiB
        let exact: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 253) as u8).collect();
        write(dir.path(), "exact.bin", &exact); // exactly 1 MiB
        let big: Vec<u8> = (0..2 * CHUNK_SIZE + 4096)
            .map(|i| (i % 251) as u8)
            .collect();
        write(dir.path(), "big.bin", &big); // > 2 MiB

        let indexed = ShareContent::index_dir(dir.path()).unwrap();
        let hashed = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();

        assert_eq!(hashed.entries, indexed.manifest());

        // Pin the seam shapes themselves (not just parity between paths).
        let by_path = |p: &str| {
            hashed
                .entries
                .iter()
                .find(|e| e.rel_path == p)
                .unwrap()
                .clone()
        };
        assert_eq!(by_path("empty.bin").chunks.len(), 0);
        assert_eq!(by_path("a.txt").chunks.len(), 1);
        assert_eq!(
            by_path("exact.bin").chunks.len(),
            1,
            "an exactly-CHUNK_SIZE file is ONE chunk — no phantom empty tail"
        );
        assert_eq!(by_path("big.bin").chunks.len(), 3);
    }

    /// The hash pass reports `(done, total)` after every file, with the total
    /// fixed from the first callback (the count pass ran first).
    #[test]
    fn hash_share_reports_progress_per_file() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.txt", b"a");

        let cancel = AtomicBool::new(true);
        let mut calls = 0usize;
        let result = hash_share(dir.path(), &cancel, &mut |_, _| calls += 1);
        assert!(matches!(result, Err(ServeError::Cancelled)));
        assert_eq!(calls, 0, "cancelled before the first file");
    }

    // ── disk-backed content ──────────────────────────────────────────

    /// Build a `DiskShareContent` over a fresh fixture tree.
    fn disk_fixture() -> (tempfile::TempDir, DiskShareContent) {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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

        let addr = content.manifest()[0].chunks[0];
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

    /// M16 (ISC-C73 / ISC-A-C35) — the disk-backed source serves every chunk
    /// of a >2MiB file correctly: first, middle, and the short last chunk
    /// each come back as exactly their `[i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE,
    /// size))` slice of the source bytes, hashing to the advertised address.
    #[test]
    fn disk_content_serves_first_middle_and_short_last_chunks() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let big: Vec<u8> = (0..2 * CHUNK_SIZE + 12345)
            .map(|i| (i % 251) as u8)
            .collect();
        write(dir.path(), "big.bin", &big);
        let manifest = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();
        let content = DiskShareContent::new(dir.path().to_path_buf(), manifest);

        let entry = &content.manifest()[0];
        assert_eq!(entry.chunks.len(), 3);
        for (i, addr) in entry.chunks.iter().enumerate() {
            let start = i * CHUNK_SIZE;
            let end = (start + CHUNK_SIZE).min(big.len());
            let bytes = content.get_chunk(addr).unwrap();
            assert_eq!(bytes, &big[start..end], "chunk {i} is its exact slice");
            assert_eq!(
                chunk_addr(&bytes).unwrap(),
                *addr,
                "chunk {i} hashes to its advertised address (ISC-S28)"
            );
        }
        // The short last chunk really is short.
        assert_eq!(
            content.get_chunk(&entry.chunks[2]).unwrap().len(),
            12345,
            "last chunk length = size mod CHUNK_SIZE"
        );
    }

    /// The receiver-verification contract per chunk, pinned: a
    /// size-preserving tamper of ONE chunk's bytes (at the chunk-boundary
    /// region) passes the server's cheap checks — the bytes are served, no
    /// error — and the served bytes' re-derived SHA-384 differs from that
    /// chunk's advertised address (the fetcher rejects exactly this chunk,
    /// ISC-S28), while untampered chunks still verify.
    #[test]
    fn disk_content_single_tampered_chunk_fails_only_its_own_addr() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let big: Vec<u8> = (0..2 * CHUNK_SIZE + 999).map(|i| (i % 251) as u8).collect();
        write(dir.path(), "big.bin", &big);
        let path = dir.path().join("big.bin");
        let manifest = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();
        let content = DiskShareContent::new(dir.path().to_path_buf(), manifest);
        let chunks = content.manifest()[0].chunks.clone();

        // Flip one byte at the very start of chunk 1 (offset CHUNK_SIZE —
        // the boundary region), preserving the file size.
        let mut tampered = big.clone();
        tampered[CHUNK_SIZE] ^= 0x01;
        std::fs::write(&path, &tampered).unwrap();

        // The server still serves (no serve-time re-hash) …
        let served = content.get_chunk(&chunks[1]).unwrap();
        assert_ne!(
            chunk_addr(&served).unwrap(),
            chunks[1],
            "tampered chunk's digest mismatches its advertised address — \
             the fetcher's per-chunk verify rejects exactly this chunk"
        );
        // … and the neighbours still verify (the tamper is contained).
        for i in [0usize, 2] {
            let ok = content.get_chunk(&chunks[i]).unwrap();
            assert_eq!(chunk_addr(&ok).unwrap(), chunks[i], "chunk {i} intact");
        }
    }

    /// A file whose **size** changed since the hash pass (truncation/growth —
    /// the cheap check `get_chunk` keeps) fails closed: `ChunkModified`, and
    /// the serve answer relays no frame. Content integrity beyond the length
    /// check is the receiver's job — see the same-size-tamper test below.
    #[test]
    fn disk_content_fails_closed_on_modified_file() {
        let (dir, content) = disk_fixture();
        let addr = content.manifest()[0].chunks[0]; // a.txt, 5 bytes
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
        let addr = content.manifest()[0].chunks[0]; // a.txt = b"alpha"
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
        let addr = content.manifest()[0].chunks[0]; // a.txt
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "x.txt", b"same bytes either way");

        let ram = ShareContent::index_dir(dir.path()).unwrap();
        let manifest = hash_share(dir.path(), &no_cancel(), &mut |_, _| {}).unwrap();
        let disk = DiskShareContent::new(dir.path().to_path_buf(), manifest);

        let addr = ram.manifest()[0].chunks[0];
        for req in [
            ShareFrame::ManifestRequest,
            ShareFrame::ChunkRequest { chunk_addr: addr },
        ] {
            assert_eq!(ram.answer(&req), ChunkSource::answer(&disk, &req));
        }
    }
}
