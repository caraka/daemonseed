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

use std::path::Path;

use walkdir::WalkDir;

use crate::share_envelope::{ManifestEntry, ShareFrame};
use crate::storage::cas::{CasError, ChunkStore, MemoryChunkStore};

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

/// Why building a [`ShareContent`] from a directory failed.
#[derive(Debug)]
pub enum ServeError {
    /// Reading a file under the share root failed.
    Io(std::io::Error),
    /// Hashing a chunk failed — oxicrypt's SHA-384 power-up self-test has not
    /// passed in this process (initialize the module first).
    Cas(CasError),
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Io(e) => write!(f, "share index I/O failed: {e}"),
            ServeError::Cas(e) => write!(f, "share chunk store failed: {e}"),
        }
    }
}

impl core::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ServeError::Io(e) => Some(e),
            ServeError::Cas(e) => Some(e),
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

        // Deterministic order: sort entries so the manifest is stable across
        // runs and platforms (WalkDir's order is filesystem-dependent).
        let mut files: Vec<_> = WalkDir::new(root)
            .sort_by_file_name()
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();
        files.sort_by(|a, b| a.path().cmp(b.path()));

        for entry in files {
            let bytes = std::fs::read(entry.path()).map_err(ServeError::Io)?;
            let addr = store.put(&bytes).map_err(ServeError::Cas)?;
            let rel_path = match entry.path().strip_prefix(root) {
                Ok(rel) => rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
                // Should not happen (WalkDir yields paths under root); fall
                // back to the file name so the entry is still usable.
                Err(_) => entry.file_name().to_string_lossy().into_owned(),
            };
            manifest.push(ManifestEntry {
                rel_path,
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
    pub fn answer(&self, req: &ShareFrame) -> Option<ShareFrame> {
        match req {
            ShareFrame::ManifestRequest => Some(ShareFrame::ManifestResponse {
                entries: self.manifest.clone(),
            }),
            ShareFrame::ChunkRequest { chunk_addr } => {
                // `get` is the authorized-participant O(1) lookup; the
                // constant-time `has` path is the relay's adversary-probe
                // surface, not the sharer's own serve loop.
                let data = self.store.get(chunk_addr).ok().flatten()?;
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
}
