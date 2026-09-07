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
use futures_util::stream::StreamExt;

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
    /// (download-subsystem redesign, step 8b / DL-ISC-12) Chunk indices already
    /// verified on disk from a PRIOR attempt (a resume): their bytes are already
    /// staged at their offsets, re-derived by
    /// [`daemonseed_core::storage::fetched::derive_resume_state`]. The engine SKIPS
    /// fetching and writing these — but still counts them toward progress and toward
    /// the file's completeness (its promote requires every chunk present, skipped or
    /// freshly fetched). A FRESH download leaves this EMPTY (every chunk is fetched),
    /// preserving the pre-resume behaviour and every existing engine test.
    pub already_verified: Vec<usize>,
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

/// Internal abort carrier: the failure that stops the download (the worst class
/// among concurrently in-flight failures — see [`merge_stop`]), tagged with its
/// disposition class so the tail can wipe-or-retain correctly.
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
    fn integrity(message: String) -> Self {
        Stop {
            class: FetchErrorClass::Integrity,
            message,
        }
    }
    /// Map a staging *write* failure. A [`FetchedError::Corrupt`] means the served
    /// bytes do not fit the confirmed manifest's byte layout (the presized-file
    /// bounds check) — malformed content, classed `Integrity`, not a local disk
    /// fault. Any other staging fault (disk/path) is `Local`. Defensive: the
    /// coverage + exact-length guards below make the bounds path unreachable for a
    /// well-formed manifest.
    fn from_staging_write(context: &str, dest_rel: &str, e: FetchedError) -> Self {
        let class = match &e {
            FetchedError::Corrupt(_) => FetchErrorClass::Integrity,
            _ => FetchErrorClass::Local,
        };
        Stop {
            class,
            message: staging_error(context, dest_rel, e),
        }
    }
}

/// Keep an `Integrity` stop over any other class; otherwise keep the FIRST recorded
/// failure. An integrity failure must quarantine the share even when a transient
/// route-death races ahead of it (DL-ISC-13 / ISC-A-C31) — the poison-flag +
/// no-auto-resume guarantee must not be defeatable by completion timing.
fn merge_stop(current: Option<Stop>, incoming: Stop) -> Stop {
    match current {
        Some(c) if c.class == FetchErrorClass::Integrity => c,
        Some(_) if incoming.class == FetchErrorClass::Integrity => incoming,
        Some(c) => c,
        None => incoming,
    }
}

/// Drive `futures` at most `concurrency` at a time, returning the WORST failure
/// class among them rather than the first to complete. A non-`Integrity` failure
/// (transient / not-served / local) does NOT stop the driver: every remaining
/// future is still driven to a terminal result, so an `Integrity` anywhere in the
/// set — even on a unit that had not begun polling when an earlier transient
/// completed — still surfaces and dominates. This is load-bearing: with more files
/// than the in-flight window (`F_FILES`), gating refill on "no failure yet" would
/// leave a poisoned late file unpolled, and the fetch would mis-report transient
/// (retain + park) instead of integrity (destroy + poison) — DL-ISC-13's poison-flag
/// guarantee must not be defeatable by completion timing OR set size. Only an
/// `Integrity` short-circuits: once one is held we return immediately, dropping the
/// rest. The budget behind the fetch closure is the true admission cap — `concurrency`
/// only bounds the polled future set; dropping the remaining futures on return cancels
/// their in-flight fetches, releasing budget permits via RAII.
async fn drive_bounded<I, Fut>(futures: I, concurrency: usize) -> Result<(), Stop>
where
    I: IntoIterator<Item = Fut>,
    Fut: std::future::Future<Output = Result<(), Stop>>,
{
    let mut pending = futures.into_iter();
    let mut inflight = futures_util::stream::FuturesUnordered::new();
    for f in pending.by_ref().take(concurrency.max(1)) {
        inflight.push(f);
    }
    let mut worst: Option<Stop> = None;
    while let Some(res) = inflight.next().await {
        if let Err(s) = res {
            let dominant = s.class == FetchErrorClass::Integrity;
            worst = Some(merge_stop(worst.take(), s));
            // An Integrity failure quarantines the whole fetch — return at once,
            // dropping the remaining futures (RAII releases their permits). Any
            // other class keeps draining so a later Integrity can still dominate.
            if dominant {
                break;
            }
        }
        // Refill on EVERY completion (success OR non-Integrity failure) until the
        // set is exhausted, so every unit is driven to a terminal result and a
        // poisoned unit beyond the initial window is never left unpolled.
        if let Some(f) = pending.next() {
            inflight.push(f);
        }
    }
    match worst {
        Some(s) => Err(s),
        None => Ok(()),
    }
}

/// The verified byte length chunk `index` must have, given the confirmed manifest
/// tiles `[0, size)` at `CHUNK_SIZE`: every non-last chunk is exactly `CHUNK_SIZE`;
/// the last chunk is the remainder. `last` is `chunk_count - 1` and the caller has
/// already checked the count matches `size.div_ceil(CHUNK_SIZE)`, so the remainder
/// is in `(0, CHUNK_SIZE]` and never underflows.
fn expected_chunk_len(index: usize, last: usize, size: u64) -> u64 {
    if index < last {
        CHUNK_SIZE as u64
    } else {
        size - (last as u64 * CHUNK_SIZE as u64)
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
    // across ALL of them, so this nested concurrency is safe (DL-ISC-1). The driver
    // selects the WORST failure class (Integrity dominant), so a poisoned file is
    // never masked by a transient sibling that completes first.
    let file_futures = files.iter().map(|f| {
        fetch_one_file(
            f,
            staging,
            fetch_chunk,
            progress,
            &chunks_done,
            &bytes_done,
            &files_done,
        )
    });
    let result = drive_bounded(file_futures, F_FILES).await;

    match result {
        Ok(()) => {
            // Success: promotions moved every completed file out of staging; sweep
            // away the now-empty staging tree (best-effort — a stray staging dir is
            // reclaimed by the sweep, never surfaced).
            let _ = staging.destroy();
            DownloadOutcome::Complete {
                files: files_done.load(Ordering::Relaxed),
                bytes: bytes_done.load(Ordering::Relaxed),
            }
        }
        Err(s) => match s.class {
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
/// into staging at its offset, then promote the completed file (incrementing
/// `files_done` on success). Returns the worst failure as a classified [`Stop`].
#[allow(clippy::too_many_arguments)]
async fn fetch_one_file<FetchChunk, Fut, Prog>(
    file: &PlannedFile,
    staging: &StagingArea,
    fetch_chunk: &FetchChunk,
    progress: &Prog,
    chunks_done: &AtomicU32,
    bytes_done: &AtomicU64,
    files_done: &AtomicU32,
) -> Result<(), Stop>
where
    FetchChunk: Fn(ChunkAddr) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, VeilidNetError>>,
    Prog: Fn(u32, u64) + Sync,
{
    // Coverage guard (full-file verification, DL-ISC-11): the confirmed manifest's
    // chunk list must EXACTLY tile `[0, size)` at CHUNK_SIZE. Without this, a
    // hostile manifest that lists fewer chunks than its advisory `size` implies
    // (e.g. `size: 10 MiB, chunks: [one 1 MiB chunk]`) would preallocate a 10 MiB
    // sparse file, write the one verified chunk, and promote 9 MiB of UNVERIFIED
    // zero-fill as a completed download. Reject the mismatch as `Integrity`
    // (malformed content) BEFORE any allocation or fetch — this also refuses a
    // `size: u64::MAX` `set_len` DoS (no real manifest carries 2^44 chunk addrs).
    let expected_chunks = file.size.div_ceil(CHUNK_SIZE as u64);
    if file.chunks.len() as u64 != expected_chunks {
        return Err(Stop::integrity(format!(
            "manifest for {} lists {} chunk(s) but its {}-byte size requires {}",
            file.dest_rel,
            file.chunks.len(),
            file.size,
            expected_chunks
        )));
    }

    // (step 8b / DL-ISC-12) Resume: chunk indices already verified on disk from a
    // prior attempt are staged at their offsets — SKIP fetching+writing them, but
    // still count them toward progress + completeness. Clamped to the valid index
    // range (the plan is engine-internal, from `derive_resume_state`, but a
    // defensive clamp keeps a stray index from mis-seeding the byte total). Empty
    // on a fresh download → no skips, no seeding, identical behaviour.
    let already: std::collections::HashSet<usize> = file
        .already_verified
        .iter()
        .copied()
        .filter(|&i| i < file.chunks.len())
        .collect();

    // Pre-size the sparse staging file so verified chunks can land at their
    // offsets in any order (set-not-prefix partial state). On RESUME this opens the
    // existing partial WITHOUT discarding its staged bytes (`preallocate` is
    // create-or-open + `set_len`, never a truncate), so the already-verified chunks
    // survive into the promote.
    staging
        .preallocate(&file.dest_rel, file.size)
        .map_err(|e| Stop::local(staging_error("could not stage", &file.dest_rel, e)))?;

    let last = file.chunks.len().saturating_sub(1);

    // Seed the already-verified chunks into the running totals BEFORE fetching, so
    // the progress bar resumes ahead and the `Complete` byte count reflects the
    // whole file (not just the freshly-fetched tail). The engine owns this seeding
    // — the frontend forwards the cumulative totals verbatim (no separate seed), so
    // a resumed chunk is counted exactly once.
    if !already.is_empty() {
        let seeded_bytes: u64 = already
            .iter()
            .map(|&i| expected_chunk_len(i, last, file.size))
            .sum();
        let c =
            chunks_done.fetch_add(already.len() as u32, Ordering::Relaxed) + already.len() as u32;
        let b = bytes_done.fetch_add(seeded_bytes, Ordering::Relaxed) + seeded_bytes;
        progress(c, b);
    }

    let chunk_futures = file
        .chunks
        .iter()
        .enumerate()
        .filter(|(i, _)| !already.contains(i))
        .map(|(i, addr)| {
            let offset = i as u64 * CHUNK_SIZE as u64;
            let expected_len = expected_chunk_len(i, last, file.size);
            let addr = *addr;
            async move {
                // The bytes come back already SHA-384-verified (fetch_chunk_budgeted);
                // a verification failure surfaces as VeilidNetError::Integrity.
                let bytes = fetch_chunk(addr)
                    .await
                    .map_err(|e| Stop::from_fetch("chunk fetch failed", e))?;
                // Exact-length guard (DL-ISC-11): a verified chunk whose length does not
                // fill its manifest slot would leave an unverified zero gap in the
                // promoted file. The bytes are authentic to their content-address, but a
                // short/long chunk means the manifest's byte layout is malformed →
                // `Integrity`, not a resumable transient.
                if bytes.len() as u64 != expected_len {
                    return Err(Stop::integrity(format!(
                    "chunk {i} of {} verified but is {} bytes, not the manifest's {expected_len}",
                    file.dest_rel,
                    bytes.len()
                )));
                }
                staging
                    .write_verified_chunk(&file.dest_rel, offset, &bytes)
                    .map_err(|e| Stop::from_staging_write("could not write", &file.dest_rel, e))?;
                let c = chunks_done.fetch_add(1, Ordering::Relaxed) + 1;
                let b = bytes_done.fetch_add(bytes.len() as u64, Ordering::Relaxed)
                    + bytes.len() as u64;
                progress(c, b);
                Ok::<(), Stop>(())
            }
        });
    drive_bounded(chunk_futures, CHUNK_POLL_CAP).await?;

    // Every chunk verified, exactly tiled, and landed: promote (no-clobber).
    staging
        .promote(&file.dest_rel)
        .map_err(|e| Stop::local(staging_error("could not finalize", &file.dest_rel, e)))?;
    files_done.fetch_add(1, Ordering::Relaxed);
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
                already_verified: Vec::new(),
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
            already_verified: vec![],
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

    /// DL-ISC-11 coverage guard: a manifest whose chunk list does not tile its
    /// advisory `size` is rejected as `Integrity` (never promotes zero-fill), and
    /// nothing is fetched. Models the hostile `size: N, chunks: [one small chunk]`.
    #[tokio::test]
    async fn undersized_chunk_list_is_integrity_not_zero_fill() {
        let root = tmp("undersized");
        let staging = StagingArea::open(&root, "liar").unwrap();
        // Claim 10 MiB but list a single 11-byte chunk.
        let (mut f, map) = plan_file("archive.bin", b"hello world");
        f.size = 10 * 1024 * 1024;
        let seen = AtomicUsize::new(0);
        let fetch = |addr: ChunkAddr| {
            seen.fetch_add(1, Ordering::Relaxed);
            let bytes = map.get(&addr).cloned();
            async move { bytes.ok_or(VeilidNetError::NotServed) }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::IntegrityFailed { .. }),
            "got {outcome:?}"
        );
        assert_eq!(
            seen.load(Ordering::Relaxed),
            0,
            "must reject before fetching"
        );
        assert!(!root.join("archive.bin").exists(), "no zero-fill promotion");
    }

    /// DL-ISC-11 exact-length guard: a verified chunk that is SHORTER than its
    /// manifest slot (a gap that would zero-fill) is rejected as `Integrity`.
    #[tokio::test]
    async fn a_short_verified_chunk_is_integrity() {
        let root = tmp("shortchunk");
        let staging = StagingArea::open(&root, "gap").unwrap();
        // A 2-chunk file (size = CHUNK_SIZE + 10); serve chunk 0 SHORT (10 bytes,
        // not the full CHUNK_SIZE slot). The count matches, so only the per-chunk
        // length guard can catch it.
        let big = vec![0x22u8; CHUNK_SIZE + 10];
        let (f, mut map) = plan_file("clip.bin", &big);
        assert_eq!(f.chunks.len(), 2);
        let chunk0 = f.chunks[0];
        map.insert(chunk0, vec![0x22u8; 10]); // serve a short (but "verified") chunk 0
        let fetch = move |addr: ChunkAddr| {
            let bytes = map.get(&addr).cloned();
            async move { bytes.ok_or(VeilidNetError::NotServed) }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::IntegrityFailed { .. }),
            "got {outcome:?}"
        );
        assert!(!root.join("clip.bin").exists());
    }

    /// Integrity dominates a racing transient (review finding): a fetch where one
    /// file route-deaths (transient) and another serves poison (integrity) always
    /// resolves to IntegrityFailed + destroyed staging, regardless of which failure
    /// completes first — the poison-quarantine guarantee is not timing-defeatable.
    #[tokio::test]
    async fn integrity_dominates_a_racing_transient() {
        let root = tmp("race");
        let staging = StagingArea::open(&root, "mix").unwrap();
        let (f_transient, _mt) = plan_file("a.bin", b"eleven byte"); // 11 bytes, 1 chunk
        let (f_poison, _mp) = plan_file("b.bin", b"twelve bytes"); // 12 bytes, 1 chunk
        let t_addr = f_transient.chunks[0];
        let p_addr = f_poison.chunks[0];
        let fetch = move |addr: ChunkAddr| {
            let is_transient = addr == t_addr;
            let is_poison = addr == p_addr;
            async move {
                if is_transient {
                    Err(VeilidNetError::Send("route died".into()))
                } else if is_poison {
                    Err(VeilidNetError::Integrity("sha-384 mismatch".into()))
                } else {
                    Err(VeilidNetError::NotServed)
                }
            }
        };
        let progress = |_c: u32, _b: u64| {};
        // Run both orderings (file order does not change the dominance outcome).
        for files in [
            vec![f_transient.clone(), f_poison.clone()],
            vec![f_poison.clone(), f_transient.clone()],
        ] {
            let st = StagingArea::open(&root, "mix").unwrap();
            let outcome = run_download(&files, &st, &fetch, &progress).await;
            assert!(
                matches!(outcome, DownloadOutcome::IntegrityFailed { .. }),
                "integrity must dominate; got {outcome:?}"
            );
            assert!(!st.dir().exists(), "poison destroys staging");
        }
        let _ = staging;
    }

    /// (F2 / DL-ISC-13) Integrity must dominate a transient even when the poisoned
    /// file sits BEYOND the initial in-flight window (`F_FILES`). The 2-file test
    /// above only covers the in-window race; with more files than the window, an
    /// early transient must NOT stop the driver from reaching a later poison — else
    /// the fetch mis-reports TransientFailed (retain + park) instead of IntegrityFailed
    /// (destroy + poison). The pre-fix refill gate ("stop pulling new futures on the
    /// first failure") left the late poison unpolled; this pins that it no longer can.
    #[tokio::test]
    async fn integrity_dominates_a_transient_beyond_the_inflight_window() {
        let root = tmp("race-window");
        let staging = StagingArea::open(&root, "win").unwrap();

        // F_FILES + 4 files, each with unique bytes (so chunk addresses never
        // collide). The LAST file (index F_FILES + 3, well beyond the initial
        // window) serves poison; every other file route-deaths (transient). Under the
        // fixed driver all files are driven to a terminal result, so the single poison
        // surfaces and dominates the sea of transients regardless of completion order.
        let total = F_FILES + 4;
        let mut files = Vec::new();
        for i in 0..total {
            let body = format!("file-{i:02}-unique-body");
            let (f, _m) = plan_file(&format!("f{i:02}.bin"), body.as_bytes());
            files.push(f);
        }
        let poison_addr = files[total - 1].chunks[0];
        let fetch = move |addr: ChunkAddr| {
            let out: std::result::Result<Vec<u8>, VeilidNetError> = if addr == poison_addr {
                Err(VeilidNetError::Integrity("sha-384 mismatch".into()))
            } else {
                Err(VeilidNetError::Send("route died".into()))
            };
            async move { out }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&files, &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::IntegrityFailed { .. }),
            "poison beyond the in-flight window must still dominate; got {outcome:?}"
        );
        assert!(
            !staging.dir().exists(),
            "poison destroys the whole fetch's staging"
        );
    }

    /// (F2 / DL-ISC-13) The same dominance must hold at the CHUNK level within one
    /// file: a poisoned chunk BEYOND the chunk poll window (`CHUNK_POLL_CAP` = 8) must
    /// still dominate a transient chunk that completed first. This proves the uniform
    /// driver fix reaches chunk-level dominance, not just file-level — the pre-fix
    /// refill gate left a late chunk unpolled once an early chunk failed transient.
    #[tokio::test]
    async fn integrity_dominates_a_transient_chunk_beyond_the_poll_window() {
        let root = tmp("race-chunks");
        let staging = StagingArea::open(&root, "cwin").unwrap();
        // A 12-chunk file (> CHUNK_POLL_CAP = 8), each chunk a DISTINCT fill so the
        // content-addresses differ. Chunk 0 route-deaths (transient, in the poll
        // window); chunk 10 (beyond the window) serves poison. The fixed chunk driver
        // drives every chunk to terminal, so the poison surfaces and dominates.
        let n_chunks = 12usize;
        let mut body = Vec::new();
        for i in 0..n_chunks {
            body.extend(std::iter::repeat_n(0xB0u8 + i as u8, CHUNK_SIZE));
        }
        let (f, map) = plan_file("reel.bin", &body);
        assert_eq!(f.chunks.len(), n_chunks);
        let transient_addr = f.chunks[0];
        let poison_addr = f.chunks[10];
        let fetch = move |addr: ChunkAddr| {
            let out: std::result::Result<Vec<u8>, VeilidNetError> = if addr == transient_addr {
                Err(VeilidNetError::Send("route died".into()))
            } else if addr == poison_addr {
                Err(VeilidNetError::Integrity("sha-384 mismatch".into()))
            } else {
                map.get(&addr).cloned().ok_or(VeilidNetError::NotServed)
            };
            async move { out }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::IntegrityFailed { .. }),
            "a poisoned chunk beyond the poll window must dominate; got {outcome:?}"
        );
        assert!(!staging.dir().exists(), "poison destroys staging");
    }

    /// (step 8b / DL-ISC-12) A resume plan with `already_verified = [0, 2]` on a
    /// 4-chunk file fetches ONLY the missing {1, 3} (the verified chunks are never
    /// requested) and promotes a byte-correct file from the staged + fetched bytes.
    #[tokio::test]
    async fn resume_fetches_only_missing_chunks_and_promotes() {
        let root = tmp("resume-partial");
        let staging = StagingArea::open(&root, "rsm").unwrap();
        // A 4-chunk file (3 full chunks + a 100-byte tail), each chunk filled with a
        // DISTINCT byte so the four content-addresses differ (a uniform fill would
        // collapse identical chunks to one address and defeat the per-address assert).
        let mut big = Vec::new();
        big.extend(std::iter::repeat_n(0xA0u8, CHUNK_SIZE));
        big.extend(std::iter::repeat_n(0xA1u8, CHUNK_SIZE));
        big.extend(std::iter::repeat_n(0xA2u8, CHUNK_SIZE));
        big.extend(std::iter::repeat_n(0xA3u8, 100));
        let (mut f, map) = plan_file("vid.bin", &big);
        assert_eq!(f.chunks.len(), 4);
        // Simulate a prior attempt's staged partial: pre-size + write chunks 0 and 2.
        staging.preallocate("vid.bin", f.size).unwrap();
        let parts: Vec<&[u8]> = big.chunks(CHUNK_SIZE).collect();
        for i in [0usize, 2] {
            staging
                .write_verified_chunk("vid.bin", i as u64 * CHUNK_SIZE as u64, parts[i])
                .unwrap();
        }
        f.already_verified = vec![0, 2];

        let addr0 = f.chunks[0];
        let addr2 = f.chunks[2];
        let requested = Arc::new(std::sync::Mutex::new(Vec::<ChunkAddr>::new()));
        let requested2 = requested.clone();
        let fetch = move |addr: ChunkAddr| {
            requested2.lock().unwrap().push(addr);
            let bytes = map.get(&addr).cloned();
            async move { bytes.ok_or(VeilidNetError::NotServed) }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        match outcome {
            DownloadOutcome::Complete { files, bytes } => {
                assert_eq!(files, 1);
                // Skipped bytes (0,2) + fetched bytes (1,3) = the whole file.
                assert_eq!(bytes, big.len() as u64);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        // Only the missing chunks {1, 3} were fetched — {0, 2} were never requested.
        let req = requested.lock().unwrap();
        assert!(
            !req.contains(&addr0) && !req.contains(&addr2),
            "must not re-fetch already-verified chunks"
        );
        assert_eq!(req.len(), 2, "exactly the two missing chunks were fetched");
        // The promoted file is byte-correct (staged + fetched bytes).
        assert_eq!(std::fs::read(root.join("vid.bin")).unwrap(), big);
    }

    /// (step 8b / DL-ISC-12) A resume plan whose `already_verified` covers every
    /// chunk promotes the staged file WITHOUT any fetch.
    #[tokio::test]
    async fn resume_with_all_chunks_verified_promotes_without_fetching() {
        let root = tmp("resume-complete");
        let staging = StagingArea::open(&root, "rsc").unwrap();
        let data = vec![0x7Eu8; CHUNK_SIZE + 5]; // 2 chunks
        let (mut f, _map) = plan_file("done.bin", &data);
        assert_eq!(f.chunks.len(), 2);
        // Stage every chunk (a fully-staged-but-unpromoted file — the aborted-just-
        // before-promote case).
        staging.preallocate("done.bin", f.size).unwrap();
        for (i, p) in data.chunks(CHUNK_SIZE).enumerate() {
            staging
                .write_verified_chunk("done.bin", i as u64 * CHUNK_SIZE as u64, p)
                .unwrap();
        }
        f.already_verified = (0..f.chunks.len()).collect();

        let seen = AtomicUsize::new(0);
        let fetch = |_addr: ChunkAddr| {
            seen.fetch_add(1, Ordering::Relaxed);
            async move { Ok::<Vec<u8>, VeilidNetError>(vec![]) }
        };
        let progress = |_c: u32, _b: u64| {};
        let outcome = run_download(&[f], &staging, &fetch, &progress).await;
        assert!(
            matches!(outcome, DownloadOutcome::Complete { files: 1, .. }),
            "got {outcome:?}"
        );
        assert_eq!(
            seen.load(Ordering::Relaxed),
            0,
            "no chunk is fetched when every chunk is already verified"
        );
        assert_eq!(std::fs::read(root.join("done.bin")).unwrap(), data);
    }
}
