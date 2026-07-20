//! The shared download engine (download-subsystem redesign, step 5).
//!
//! One scheduler both frontends drive: given a set of files already *placed* at
//! their destination-relative paths (by [`daemonseed_core::storage::fetched::place_at_dest`])
//! and a [`StagingArea`], it fetches every file's chunks in parallel under the
//! caller's per-route budget (the `fetch_chunk` closure is a
//! [`crate::share::fetch_chunk_budgeted`] bound to one [`crate::RouteLease`]),
//! writes each **verified** chunk into staging at its manifest-derived offset,
//! and promotes each file only once all of its chunks have verified. It NEVER
//! touches the network or the budget itself — that lives behind the closure — so
//! it is unit-testable with a fake fetcher and reused verbatim by the GUI (step 5)
//! and TUI (step 6).
//!
//! Disposition on failure is the ISC-A-C31 reword made mechanical:
//! - **Integrity** ([`FetchErrorClass::Integrity`]) — the sharer served hostile
//!   content: destroy every staged partial of the fetch (the poison boundary is
//!   the whole fetch), keep already-promoted files (self-authenticating), abort;
//!   the caller flags the share poisoned and never resumes past it.
//! - **Transient** / **NotServed** — keep verified units (promoted files AND
//!   staged verified chunks) for a later user-initiated resume; nothing is wiped.
//! - **Local** (staging disk/path fault) — keep verified units (they verified);
//!   surface the error.
//!
//! `chunk i` covers `[i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size))` (last chunk may
//! be short), so its staging offset is `i * CHUNK_SIZE` — the file is
//! pre-sized sparse and chunks land in any order under the budget.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use daemonseed_core::share_serve::CHUNK_SIZE;
use daemonseed_core::storage::cas::ChunkAddr;
use daemonseed_core::storage::fetched::{FetchedError, StagingArea};
use futures_util::stream::{self, StreamExt};

use crate::error::{FetchErrorClass, VeilidNetError};
use crate::route_budget::F_FILES;

/// One file to fetch, already placed at its destination-relative path by the
/// placement resolver. `size` and `chunks` come from the user-confirmed manifest
/// entry; `dest_rel` is where the completed file promotes to under the staging
/// area's destination root.
#[derive(Debug, Clone)]
pub struct PlannedFile {
    /// Destination-relative path (from `PlacedFile::dest_rel`) — the promote target.
    pub dest_rel: String,
    /// The confirmed manifest size in bytes (the staging file is pre-sized to it).
    pub size: u64,
    /// The file's ordered chunk addresses; chunk `i` writes at offset `i*CHUNK_SIZE`.
    pub chunks: Vec<ChunkAddr>,
}

/// The terminal outcome of a [`run_download`] — the class distinction the GUI/TUI
/// fold on-loop (design §"Outcome + fold semantics"). Frontend-agnostic: the
/// frontend maps this onto its own `ConfirmOutcome` and event surface.
#[derive(Debug)]
pub enum DownloadOutcome {
    /// Every planned file was fetched, verified, and promoted.
    Complete {
        /// Files promoted.
        files: u32,
        /// Total verified bytes written.
        bytes: u64,
    },
    /// A transport / route-death (or authoritative not-served) failure. Fold as
    /// today's `RouteFailed`: mark the share Unresolved + park the one-shot retry
    /// (#180) — but NO wipe; verified units are retained for resume.
    TransientFailed {
        /// Human-readable cause.
        message: String,
    },
    /// The sharer served content that failed verification. Fold: surface a fetch
    /// error + set the durable poison flag; NO Unresolved mark, NO parked retry.
    /// The engine has already destroyed the fetch's staged partials.
    IntegrityFailed {
        /// Human-readable cause (names no chunk index on a non-local surface).
        message: String,
    },
    /// A local fetcher fault (staging disk/path). Fold: surface a fetch error only
    /// (the route is fine, so no mark); verified units are retained.
    LocalFailed {
        /// Human-readable cause.
        message: String,
    },
}

/// Internal abort carrier: the first failure that stops the download, tagged with
/// the disposition class so the tail can wipe-or-retain correctly.
struct Stop {
    class: FetchErrorClass,
    message: String,
}

impl Stop {
    fn from_fetch(context: &str, e: VeilidNetError) -> Self {
        Stop {
            class: e.fetch_class(),
            message: format!("{context}: {e}"),
        }
    }
    fn local(message: String) -> Self {
        Stop {
            class: FetchErrorClass::Local,
            message,
        }
    }
}

/// Poll at most this many chunk fetches per file concurrently. The per-route
/// budget behind the `fetch_chunk` closure is the REAL admission cap — this only
/// bounds how many not-yet-admitted chunk futures we hold polled at once, so a
/// file with thousands of chunks does not build a giant future set. Sized to the
/// route ceiling: never a throughput bottleneck under the budget.
const CHUNK_POLL_CAP: usize = crate::route_budget::W_CEIL;

/// Fetch, verify, stage, and promote every file in `files` in parallel under the
/// budget behind `fetch_chunk`. `progress(chunks_done, bytes_done)` is called with
/// the running cumulative totals after each verified chunk lands (shared across
/// concurrent fetches; must be cheap + `Sync`). Returns the terminal
/// [`DownloadOutcome`]; on any failure the staged partials are disposed per the
/// failure class BEFORE returning (integrity → destroyed; otherwise retained).
///
/// `fetch_chunk(addr)` must return the chunk's **already-verified** bytes (it is
/// [`crate::share::fetch_chunk_budgeted`], which SHA-384-checks inside), or a
/// [`VeilidNetError`] whose [`VeilidNetError::fetch_class`] drives disposition.
pub async fn run_download<FetchChunk, Fut, Prog>(
    files: &[PlannedFile],
    staging: &StagingArea,
    fetch_chunk: &FetchChunk,
    progress: &Prog,
) -> DownloadOutcome
where
    FetchChunk: Fn(ChunkAddr) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, VeilidNetError>>,
    Prog: Fn(u32, u64) + Sync,
{
    let chunks_done = AtomicU32::new(0);
    let bytes_done = AtomicU64::new(0);
    let files_done = AtomicU32::new(0);

    // Files run F_FILES-concurrent; each file's chunks run CHUNK_POLL_CAP-polled.
    // The budget behind `fetch_chunk` caps the true per-route in-flight total
    // across ALL of them, so this nested concurrency is safe (DL-ISC-1).
    let mut file_stream = stream::iter(
        files
            .iter()
            .map(|f| fetch_one_file(f, staging, fetch_chunk, progress, &chunks_done, &bytes_done)),
    )
    .buffer_unordered(F_FILES.max(1));

    let mut stop: Option<Stop> = None;
    while let Some(res) = file_stream.next().await {
        match res {
            Ok(()) => {
                files_done.fetch_add(1, Ordering::Relaxed);
            }
            Err(s) => {
                // First failure aborts: drop the remaining file futures (cancels
                // their in-flight chunk fetches, releasing budget permits on drop)
                // and stop consuming the stream.
                stop = Some(s);
                break;
            }
        }
    }
    // Ensure the in-flight futures are dropped (permits released) before disposition.
    drop(file_stream);

    match stop {
        None => {
            // Success: promotions moved every completed file out of staging; sweep
            // away the now-empty staging tree (best-effort — a stray staging dir is
            // reclaimed by the sweep, never surfaced).
            let _ = staging.destroy();
            DownloadOutcome::Complete {
                files: files_done.load(Ordering::Relaxed),
                bytes: bytes_done.load(Ordering::Relaxed),
            }
        }
        Some(s) => match s.class {
            FetchErrorClass::Integrity => {
                // The poison boundary is the WHOLE fetch's unpromoted state.
                // Already-promoted files stay (self-authenticating). A destroy
                // failure does not un-poison the outcome.
                let _ = staging.destroy();
                DownloadOutcome::IntegrityFailed { message: s.message }
            }
            // Transport, not-served: keep verified units (promoted + staged) for a
            // later user-initiated resume. NotServed rides the transient fold — it
            // is not poison and not a local fault; marking the share Unresolved so
            // it re-resolves is benign, the one-shot park harmless, verified units
            // retained. (Decision: NotServed → transient disposition.)
            FetchErrorClass::Transient | FetchErrorClass::NotServed => {
                DownloadOutcome::TransientFailed { message: s.message }
            }
            // Local disk/path fault: the bytes that verified stay staged (a
            // disk-full blip must not wipe verified work); surface the error.
            FetchErrorClass::Local => DownloadOutcome::LocalFailed { message: s.message },
        },
    }
}

/// Fetch every chunk of ONE file (bounded-concurrent), writing each verified chunk
/// into staging at its offset, then promote the completed file. Returns the first
/// failure as a classified [`Stop`].
async fn fetch_one_file<FetchChunk, Fut, Prog>(
    file: &PlannedFile,
    staging: &StagingArea,
    fetch_chunk: &FetchChunk,
    progress: &Prog,
    chunks_done: &AtomicU32,
    bytes_done: &AtomicU64,
) -> Result<(), Stop>
where
    FetchChunk: Fn(ChunkAddr) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, VeilidNetError>>,
    Prog: Fn(u32, u64) + Sync,
{
    // Pre-size the sparse staging file so verified chunks can land at their
    // offsets in any order (set-not-prefix partial state).
    staging
        .preallocate(&file.dest_rel, file.size)
        .map_err(|e| Stop::local(staging_error("could not stage", &file.dest_rel, e)))?;

    let mut chunk_stream = stream::iter(file.chunks.iter().enumerate().map(|(i, addr)| {
        let offset = i as u64 * CHUNK_SIZE as u64;
        let addr = *addr;
        async move {
            // The bytes come back already SHA-384-verified (fetch_chunk_budgeted);
            // a verification failure surfaces as VeilidNetError::Integrity.
            let bytes = fetch_chunk(addr)
                .await
                .map_err(|e| Stop::from_fetch("chunk fetch failed", e))?;
            staging
                .write_verified_chunk(&file.dest_rel, offset, &bytes)
                .map_err(|e| Stop::local(staging_error("could not write", &file.dest_rel, e)))?;
            let c = chunks_done.fetch_add(1, Ordering::Relaxed) + 1;
            let b =
                bytes_done.fetch_add(bytes.len() as u64, Ordering::Relaxed) + bytes.len() as u64;
            progress(c, b);
            Ok::<(), Stop>(())
        }
    }))
    .buffer_unordered(CHUNK_POLL_CAP.max(1));

    while let Some(res) = chunk_stream.next().await {
        res?;
    }
    drop(chunk_stream);

    // Every chunk verified and landed: promote (no-clobber) to the final path.
    staging
        .promote(&file.dest_rel)
        .map_err(|e| Stop::local(staging_error("could not finalize", &file.dest_rel, e)))?;
    Ok(())
}

fn staging_error(context: &str, dest_rel: &str, e: FetchedError) -> String {
    format!("{context} {dest_rel}: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::storage::cas::chunk_addr;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// Build a `PlannedFile` + the (addr → bytes) map a fake fetcher serves, from
    /// raw file bytes split into CHUNK_SIZE chunks.
    fn plan_file(dest_rel: &str, bytes: &[u8]) -> (PlannedFile, HashMap<ChunkAddr, Vec<u8>>) {
        let mut chunks = Vec::new();
        let mut map = HashMap::new();
        let _ = oxicrypt_module::initialize();
        for chunk in bytes.chunks(CHUNK_SIZE) {
            let addr = chunk_addr(chunk).unwrap();
            chunks.push(addr);
            map.insert(addr, chunk.to_vec());
        }
        (
            PlannedFile {
                dest_rel: dest_rel.to_owned(),
                size: bytes.len() as u64,
                chunks,
            },
            map,
        )
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ds-dl-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A healthy multi-file download promotes every file byte-for-byte and reports
    /// cumulative progress + the Complete counts; staging is cleaned up.
    #[tokio::test]
    async fn healthy_download_promotes_every_file_and_cleans_staging() {
        let root = tmp("ok");
        let staging = StagingArea::open(&root, "abcd").unwrap();
        // One small file + one multi-chunk file (>1 MiB) exercising offset writes.
        let big = vec![0x5Au8; CHUNK_SIZE + 4096];
        let (f1, m1) = plan_file("a.txt", b"hello world");
        let (f2, m2) = plan_file("sub/big.bin", &big);
        let mut map = m1;
        map.extend(m2);

        let seen = AtomicUsize::new(0);
        let fetch = |addr: ChunkAddr| {
            let bytes = map.get(&addr).cloned();
            seen.fetch_add(1, Ordering::Relaxed);
            async move { bytes.ok_or(VeilidNetError::NotServed) }
        };
        let last = Arc::new(std::sync::Mutex::new((0u32, 0u64)));
        let last2 = last.clone();
        let progress = move |c: u32, b: u64| *last2.lock().unwrap() = (c, b);

        let outcome = run_download(&[f1, f2], &staging, &fetch, &progress).await;
        match outcome {
            DownloadOutcome::Complete { files, bytes } => {
                assert_eq!(files, 2);
                assert_eq!(bytes, 11 + big.len() as u64);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        // Files promoted to their dest_rel; staging removed.
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"hello world");
        assert_eq!(std::fs::read(root.join("sub/big.bin")).unwrap(), big);
        assert!(!staging.dir().exists(), "staging should be cleaned up");
        let (c, _) = *last.lock().unwrap();
        assert_eq!(c as usize, seen.load(Ordering::Relaxed));
    }

    /// DL-ISC-13: an integrity failure destroys ALL of the fetch's staged partials,
    /// keeps already-promoted files, and returns IntegrityFailed.
    #[tokio::test]
    async fn integrity_failure_destroys_staging_keeps_promoted() {
        let root = tmp("poison");
        let staging = StagingArea::open(&root, "dead").unwrap();
        // f_good is tiny (single chunk) and will likely promote; f_bad's chunk is
        // served as an Integrity error. Run them; the abort must destroy staging.
        let (f_good, m_good) = plan_file("good.txt", b"trustworthy");
        let (f_bad, _m_bad) = plan_file("bad.txt", b"poisoned-content-xyz");
        let good_addr = f_good.chunks[0];
        let fetch = move |addr: ChunkAddr| {
            let is_good = addr == good_addr;
            let bytes = m_good.get(&addr).cloned();
            async move {
                if is_good {
                    Ok(bytes.unwrap())
                } else {
                    Err(VeilidNetError::Integrity("sha-384 mismatch".into()))
                }
            }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f_good, f_bad], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::IntegrityFailed { .. }),
            "got {outcome:?}"
        );
        // The whole staging tree is gone (poison boundary = the fetch).
        assert!(
            !staging.dir().exists(),
            "staging must be destroyed on poison"
        );
        // The staging namespace held bad.txt's partial; it is not under the dest.
        assert!(!root.join("bad.txt").exists());
    }

    /// A transient failure retains staged verified chunks (no wipe) for resume.
    #[tokio::test]
    async fn transient_failure_retains_staging() {
        let root = tmp("transient");
        let staging = StagingArea::open(&root, "flaky").unwrap();
        let big = vec![0x11u8; CHUNK_SIZE * 2 + 7]; // 3 chunks
        let (f, map) = plan_file("movie.bin", &big);
        let chunk0 = f.chunks[0];
        let fetch = move |addr: ChunkAddr| {
            let is_first = addr == chunk0;
            let bytes = map.get(&addr).cloned();
            async move {
                if is_first {
                    Ok(bytes.unwrap()) // first chunk verifies + stages
                } else {
                    Err(VeilidNetError::Send("route died".into())) // transient
                }
            }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::TransientFailed { .. }),
            "got {outcome:?}"
        );
        // Staging survives with the pre-sized (partially written) file — resume
        // material. The file was never promoted.
        assert!(
            staging.dir().exists(),
            "staging must survive a transient blip"
        );
        assert!(!root.join("movie.bin").exists(), "no promote on failure");
    }

    /// NotServed rides the transient disposition (retained, not poison, not local).
    #[tokio::test]
    async fn not_served_maps_to_transient_and_retains() {
        let root = tmp("withdrawn");
        let staging = StagingArea::open(&root, "gone").unwrap();
        let (f, _m) = plan_file("x.txt", b"anything at all");
        let fetch = |_addr: ChunkAddr| async { Err(VeilidNetError::NotServed) };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::TransientFailed { .. }),
            "got {outcome:?}"
        );
        assert!(staging.dir().exists());
    }

    /// An empty-file (size 0, no chunks) plan promotes an empty file.
    #[tokio::test]
    async fn empty_file_promotes() {
        let root = tmp("empty");
        let staging = StagingArea::open(&root, "e").unwrap();
        let f = PlannedFile {
            dest_rel: "empty.dat".into(),
            size: 0,
            chunks: vec![],
        };
        let fetch = |_addr: ChunkAddr| async { Ok::<Vec<u8>, VeilidNetError>(vec![]) };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(matches!(
            outcome,
            DownloadOutcome::Complete { files: 1, bytes: 0 }
        ));
        assert_eq!(
            std::fs::read(root.join("empty.dat")).unwrap(),
            Vec::<u8>::new()
        );
    }
}
