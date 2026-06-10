//! Share-folder indexer engine (M8 — ISC-C21 / ISC-A-C7).
//!
//! Drives a [`ShareIndex`] from the filesystem in the two modes ISC-C21
//! requires — both designed against the
//! specific failure that drove Demonsaw users off Pi-class hosts: a cold
//! rescan that pinned CPU and disk for hours, re-triggered by any single file
//! change.
//!
//! - **Cold scan** ([`Indexer::cold_scan`]) — a one-time walk of the share root
//!   that upserts every regular file. It is plain synchronous work by design:
//!   the caller runs it on a **low-priority background thread** (`nice` /
//!   `ionice idle` on Linux) so it never wins CPU/IO contention against a
//!   foreground task (ISC-A-C7 no-fate-sharing), while the index stays queryable
//!   from the persisted redb the whole time, so startup is never blocked
//!   (ISC-A-C7 no-startup-blockade). Keeping the engine free of the async
//!   runtime is what lets that isolation be the caller's choice.
//! - **Incremental update** ([`Indexer::apply_event`]) — one filesystem change
//!   maps to exactly one index write. A single file changing never triggers a
//!   share-wide rewalk (ISC-A-C7 / ISC-C21) — that share-wide rewalk on a
//!   single change is precisely the thrash Demonsaw suffered.
//!
//! M16 adds the **cached hash pass** ([`cached_or_hash`]): the index doubles
//! as a chunk-addr cache for the disk-backed publish path, so re-publishing
//! an unchanged share reads no file contents at all (the same anti-thrash
//! posture, applied to hashing instead of stat walks).
//!
//! The live filesystem-event source (inotify / FSEvents / ReadDirectoryChangesW
//! via the `notify` crate) and its watch-limit fallback feed [`FsEvent`]s into
//! [`Indexer::apply_event`]; that wiring layers on top of this engine.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::UNIX_EPOCH;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use walkdir::WalkDir;

use crate::share_envelope::ManifestEntry;
use crate::share_serve::{
    CHUNK_SIZE, ServeError, ShareManifest, hash_file_chunks, hash_share, share_files,
    share_rel_path,
};
use crate::storage::cas::{CHUNK_ADDR_LEN, ChunkAddr};
use crate::storage::share_index::{IndexError, ShareEntry, ShareIndex};

/// A single filesystem change to fold into the index — the unit of incremental
/// update. Whatever produces these (a live watcher, a fallback mtime-walk)
/// hands them one at a time to [`Indexer::apply_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    /// A file was created or its contents/metadata changed → upsert one entry.
    /// (If the path has since vanished, it is treated as a removal — watcher
    /// event ordering is not guaranteed.)
    Upserted(PathBuf),
    /// A file was removed → drop one entry.
    Removed(PathBuf),
}

/// The indexer engine: a [`ShareIndex`] plus the share root it mirrors.
pub struct Indexer {
    index: ShareIndex,
    root: PathBuf,
}

impl Indexer {
    /// Build an indexer over `index`, mirroring the files under `root`.
    pub fn new(index: ShareIndex, root: impl Into<PathBuf>) -> Self {
        Self {
            index,
            root: root.into(),
        }
    }

    /// Borrow the underlying index for queries (`get` / `entries` / `len`).
    pub fn index(&self) -> &ShareIndex {
        &self.index
    }

    /// Cold-scan the share root: upsert every regular file beneath it, and
    /// return how many were indexed. Unreadable entries are skipped, not fatal
    /// — one bad file must not abort the whole walk (ISC-A-C7 robustness).
    ///
    /// Synchronous by design — see the module docs. Run it on a niced
    /// background thread so it cannot starve a foreground task. Delegates to the
    /// free [`scan_into`] (with a never-set cancel flag — an owned cold scan
    /// runs to completion) so a caller holding only an `Arc<ShareIndex>` (M14
    /// net-actor activation) can run the identical walk against a borrowed index.
    pub fn cold_scan(&self) -> Result<usize, IndexError> {
        scan_into(&self.index, &self.root, &AtomicBool::new(false))
    }

    /// Apply one filesystem event as a **single-entry** index write — never a
    /// share-wide rewalk (ISC-C21 / ISC-A-C7). An `Upserted` event for a path
    /// that has since vanished is folded to a removal; a transient stat error
    /// (not "missing") leaves the entry as-is rather than wrongly dropping it.
    pub fn apply_event(&self, event: &FsEvent) -> Result<(), IndexError> {
        match event {
            FsEvent::Upserted(path) => {
                let Some(rel_path) = self.rel_path(path) else {
                    return Ok(()); // outside the share root — ignore
                };
                match std::fs::metadata(path) {
                    // A change event means the bytes may differ — never carry
                    // a cached chunk_addrs blob forward; the next hash pass
                    // ([`cached_or_hash`]) recomputes and re-caches it.
                    Ok(meta) if meta.is_file() => self.index.put(&ShareEntry {
                        rel_path,
                        size: meta.len(),
                        mtime_unix_ms: mtime_ms(&meta),
                        chunk_addrs: None,
                    }),
                    // A directory (its files arrive as their own events) — ignore.
                    Ok(_) => Ok(()),
                    // Gone since the event fired → it's really a removal.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        self.index.remove(&rel_path)
                    }
                    // Transient error (permissions, races) → leave the index
                    // untouched rather than drop a possibly-still-present file.
                    Err(_) => Ok(()),
                }
            }
            FsEvent::Removed(path) => match self.rel_path(path) {
                Some(rel_path) => self.index.remove(&rel_path),
                None => Ok(()),
            },
        }
    }

    /// Run the cold scan on a dedicated background thread (ISC-19 / ISC-A-C7).
    /// Returns immediately with a [`ScanHandle`]; the index stays fully
    /// queryable from the persisted redb while the scan runs (ISC-A-C7
    /// no-startup-blockade), and the scan runs on its own thread so it never
    /// shares scheduling fate with the foreground / network surface (ISC-A-C7
    /// no-fate-sharing) — the structural fix Demonsaw lacked. Lowering OS
    /// priority (`nice` / `ionice idle`) on top is a best-effort platform
    /// refinement the binary applies; the thread isolation is the load-bearing
    /// guarantee. `redb`'s MVCC lets the scan's writes and concurrent foreground
    /// reads proceed without blocking each other.
    pub fn spawn_background_scan(self: Arc<Self>) -> ScanHandle {
        let join = thread::Builder::new()
            .name("daemonseed-cold-scan".to_owned())
            .spawn(move || self.cold_scan())
            .expect("spawn cold-scan thread");
        ScanHandle { join }
    }

    /// Fallback rescan when live watching is unavailable (ISC-21): walk the
    /// root and upsert only files whose mtime is newer than `since_unix_ms`,
    /// returning how many were updated. It still visits every path, but it
    /// *writes* only changed files — the bounded-work fallback for when the
    /// inotify watch limit is exceeded and we can't get per-file events. The
    /// caller drives it periodically with the timestamp of the last pass.
    pub fn mtime_rescan(&self, since_unix_ms: u64) -> Result<usize, IndexError> {
        let mut updated = 0usize;
        for entry in WalkDir::new(&self.root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let mtime = mtime_ms(&meta);
            if mtime <= since_unix_ms {
                continue;
            }
            let Some(rel_path) = self.rel_path(entry.path()) else {
                continue;
            };
            self.index.put(&ShareEntry {
                rel_path,
                size: meta.len(),
                mtime_unix_ms: mtime,
                chunk_addrs: None, // changed file — a stale address must not survive
            })?;
            updated += 1;
        }
        Ok(updated)
    }

    /// The share-root-relative path string used as the index identity for an
    /// absolute path. `None` if the path is not under the root.
    fn rel_path(&self, abs: &Path) -> Option<String> {
        abs.strip_prefix(&self.root)
            .ok()?
            .to_str()
            .map(|s| s.to_owned())
    }
}

/// Cold-scan `root` into a borrowed [`ShareIndex`]: upsert every regular file
/// beneath it and return how many were indexed. Unreadable entries are skipped,
/// not fatal — one bad file must not abort the whole walk (ISC-A-C7 robustness).
/// A metadata-only scan writes `chunk_addrs: None` — content addresses come from
/// the hash pass ([`cached_or_hash`]), never from a stat walk.
///
/// `cancel` is checked per entry; a set flag **early-returns `Ok(count)`**
/// with however many files were upserted so far. Cancellation is deliberately
/// not an error: the scan is idempotent metadata work and every entry already
/// written is valid (this matches the walk's own skip-and-continue posture —
/// [`IndexError`]'s variants are storage failures, which this is not). A
/// caller that must distinguish "complete" from "cut short" checks its own
/// flag after the call.
///
/// Operates on `&ShareIndex` rather than owning it so a caller holding an
/// `Arc<ShareIndex>` can run the scan on a dedicated background thread while the
/// *same* index stays fully queryable from the foreground (redb MVCC) — the M14
/// net-actor share-activation path. [`Indexer::cold_scan`] delegates here.
pub fn scan_into(
    index: &ShareIndex,
    root: &Path,
    cancel: &AtomicBool,
) -> Result<usize, IndexError> {
    let mut count = 0usize;
    for entry in WalkDir::new(root).into_iter().flatten() {
        if cancel.load(Ordering::Relaxed) {
            return Ok(count);
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Some(rel_path) = entry
            .path()
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        index.put(&ShareEntry {
            rel_path,
            size: meta.len(),
            mtime_unix_ms: mtime_ms(&meta),
            chunk_addrs: None,
        })?;
        count += 1;
    }
    Ok(count)
}

/// Why a cached-or-hash pass ([`cached_or_hash`]) failed — it spans two
/// domains, so it wraps both error types.
#[derive(Debug)]
pub enum CachedHashError {
    /// Reading or writing the share index (the chunk-addr cache) failed.
    Index(IndexError),
    /// The hash pass failed: I/O, hashing, or cancellation —
    /// [`ServeError::Cancelled`] arrives wrapped here.
    Serve(ServeError),
}

impl core::fmt::Display for CachedHashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CachedHashError::Index(e) => write!(f, "chunk-addr cache failed: {e}"),
            CachedHashError::Serve(e) => write!(f, "share hash pass failed: {e}"),
        }
    }
}

impl core::error::Error for CachedHashError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            CachedHashError::Index(e) => Some(e),
            CachedHashError::Serve(e) => Some(e),
        }
    }
}

/// Build a share's [`ShareManifest`] using the index as a **chunk-addr cache**:
/// a file whose indexed `size` + `mtime` still match and whose entry carries a
/// well-formed cached `chunk_addrs` blob is reused *without reading the file*;
/// only misses (new, changed, or never-hashed files) are streamed through
/// per-chunk SHA-384 (as in [`hash_share`] — fixed
/// [`CHUNK_SIZE`] chunks, M16, ISC-C73 / ISC-A-C35), and the freshly computed
/// addresses are written back into the index entry (all of them, ordered,
/// concatenated) so the next publish of an unchanged share reads no file at
/// all.
///
/// A cached blob is reused only when it **parses** for the statted size:
/// `len % 48 == 0` and `len/48 == ceil(size/CHUNK_SIZE)` (0 for an empty
/// file). A malformed or wrong-count blob — e.g. a row written by the
/// abandoned single-addr v2 shape, or a stat/blob race — is treated as a
/// miss and re-hashed, never served: a cache must degrade to correctness,
/// not propagate its own corruption into the manifest.
///
/// With `index: None` this is exactly [`hash_share`] — the cache is an
/// optimization, never a requirement. The walk order, `rel_path` form,
/// `progress(done, total)` cadence (after every file, hit or miss), and
/// cancellation between files *and between chunks*
/// ([`ServeError::Cancelled`], wrapped in [`CachedHashError::Serve`]) all
/// match `hash_share`, so the two paths produce identical manifests for the
/// same tree.
///
/// A cached blob is trusted only as far as its `stat` match — mtime
/// granularity is the usual caveat. The serve side
/// ([`crate::share_serve::DiskShareContent`]) does NOT re-hash at answer time
/// (only cheap IO/length fail-closed checks); a stale cached address is caught
/// by the fetcher's per-`ChunkResponse` SHA-384 re-derivation, which is the
/// integrity guarantee end to end (ISC-A-C35).
pub fn cached_or_hash(
    index: Option<&ShareIndex>,
    root: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<ShareManifest, CachedHashError> {
    let Some(index) = index else {
        return hash_share(root, cancel, progress).map_err(CachedHashError::Serve);
    };

    let files = share_files(root);
    let total = files.len();
    let mut entries = Vec::with_capacity(total);

    for (done, entry) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(CachedHashError::Serve(ServeError::Cancelled));
        }
        let meta = entry
            .metadata()
            .map_err(|e| CachedHashError::Serve(ServeError::Io(e.into())))?;
        let size = meta.len();
        let mtime_unix_ms = mtime_ms(&meta);
        let rel_path = share_rel_path(root, entry);

        // Cache hit: same rel_path + size + mtime with a cached blob that
        // parses for that size → reuse it without reading the file.
        let cached = index
            .get(&rel_path)
            .map_err(CachedHashError::Index)?
            .filter(|e| e.size == size && e.mtime_unix_ms == mtime_unix_ms)
            .and_then(|e| e.chunk_addrs)
            .and_then(|blob| parse_addr_blob(&blob, size));

        let (chunks, size) = match cached {
            Some(chunks) => (chunks, size),
            None => {
                // Miss → stream-hash per chunk (cancel honoured between
                // chunks too — a multi-GB file must not pin the pass). The
                // streamed byte count, not the stat, becomes the entry size
                // so chunks/size stay mutually consistent even if the file
                // changed between stat and read (the next pass's stat
                // mismatch then invalidates this cache row, self-correcting).
                let (chunks, streamed) =
                    hash_file_chunks(entry.path(), cancel).map_err(CachedHashError::Serve)?;
                // Write-back ALL chunk addrs, ordered & concatenated: the
                // next pass over this unchanged file is a read-free hit.
                let blob = chunks
                    .iter()
                    .flat_map(|a| a.as_bytes().iter().copied())
                    .collect();
                index
                    .put(&ShareEntry {
                        rel_path: rel_path.clone(),
                        size: streamed,
                        mtime_unix_ms,
                        chunk_addrs: Some(blob),
                    })
                    .map_err(CachedHashError::Index)?;
                (chunks, streamed)
            }
        };

        entries.push(ManifestEntry {
            rel_path,
            size,
            chunks,
        });
        progress(done + 1, total);
    }

    Ok(ShareManifest { entries })
}

/// Parse a cached `chunk_addrs` blob into ordered [`ChunkAddr`]s, validating
/// it against the file size it claims to describe: the blob must split into
/// whole 48-byte addresses and yield exactly `ceil(size/CHUNK_SIZE)` of them
/// (0 for an empty file — `Some(empty)` is a valid hashed state). `None`
/// means "do not trust this blob, re-hash" (see [`cached_or_hash`]).
fn parse_addr_blob(blob: &[u8], size: u64) -> Option<Vec<ChunkAddr>> {
    if !blob.len().is_multiple_of(CHUNK_ADDR_LEN) {
        return None;
    }
    let count = blob.len() / CHUNK_ADDR_LEN;
    if count as u64 != size.div_ceil(CHUNK_SIZE as u64) {
        return None;
    }
    Some(
        blob.chunks_exact(CHUNK_ADDR_LEN)
            .map(|c| ChunkAddr::from_bytes(c.try_into().expect("exact 48-byte chunk")))
            .collect(),
    )
}

/// A running background cold-scan ([`Indexer::spawn_background_scan`]). Join to
/// wait for completion and get the file count; drop it to detach (the scan
/// finishes on its own).
pub struct ScanHandle {
    join: thread::JoinHandle<Result<usize, IndexError>>,
}

impl ScanHandle {
    /// Wait for the background scan to finish and return how many files it
    /// indexed. Propagates a scan error; panics only if the scan thread itself
    /// panicked.
    pub fn join(self) -> Result<usize, IndexError> {
        self.join.join().expect("cold-scan thread panicked")
    }
}

/// Last-modified time as milliseconds since the Unix epoch, or 0 if the
/// platform/file doesn't report one.
fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why a live watch could not be established (ISC-21).
#[derive(Debug)]
pub enum WatchError {
    /// The OS watch limit was exceeded (on Linux, `fs.inotify.max_user_watches`).
    /// This is the **surfaced** signal ISC-21 requires: the caller falls back to
    /// periodic [`Indexer::mtime_rescan`] rather than silently missing changes.
    Limit,
    /// Any other watcher-setup failure.
    Io(notify::Error),
}

impl core::fmt::Display for WatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WatchError::Limit => {
                f.write_str("filesystem watch limit exceeded — fall back to periodic mtime rescan")
            }
            WatchError::Io(e) => write!(f, "filesystem watch setup failed: {e}"),
        }
    }
}

impl core::error::Error for WatchError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            WatchError::Io(e) => Some(e),
            WatchError::Limit => None,
        }
    }
}

/// A live filesystem watch over a share root. Holds the platform watcher alive
/// for its lifetime — dropping it stops the watch. Mapped [`FsEvent`]s arrive on
/// the paired [`Receiver`]; the consumer feeds each to [`Indexer::apply_event`],
/// so a watched change becomes a single-entry index write (ISC-20).
pub struct ShareWatcher {
    _watcher: RecommendedWatcher,
}

impl ShareWatcher {
    /// Begin recursively watching `root`. Returns the watch handle (keep it
    /// alive) and the receiver of mapped events. A [`WatchError::Limit`] means
    /// the caller must drop to [`Indexer::mtime_rescan`] (ISC-21).
    pub fn watch(root: impl AsRef<Path>) -> Result<(Self, Receiver<FsEvent>), WatchError> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                for fs_event in map_notify_event(&event) {
                    // A closed receiver just means the consumer stopped.
                    let _ = tx.send(fs_event);
                }
            }
        })
        .map_err(classify_watch_error)?;
        watcher
            .watch(root.as_ref(), RecursiveMode::Recursive)
            .map_err(classify_watch_error)?;
        Ok((Self { _watcher: watcher }, rx))
    }
}

/// Distinguish the watch-limit case (ISC-21) from other notify errors.
fn classify_watch_error(e: notify::Error) -> WatchError {
    match e.kind {
        notify::ErrorKind::MaxFilesWatch => WatchError::Limit,
        _ => WatchError::Io(e),
    }
}

/// Map a raw notify event to the index updates it implies. Create and Modify
/// (including the two halves of a rename) upsert each affected path; Remove
/// drops each; access/metadata-only/other events produce nothing.
fn map_notify_event(event: &Event) -> Vec<FsEvent> {
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            event.paths.iter().cloned().map(FsEvent::Upserted).collect()
        }
        EventKind::Remove(_) => event.paths.iter().cloned().map(FsEvent::Removed).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use notify::event::{AccessKind, CreateKind, RemoveKind};

    use super::*;
    use crate::storage::share_index::ShareIndex;

    const KEY: [u8; 32] = [0x55; 32];

    /// Build an indexer over a fresh temp share root + temp index file.
    fn fixture() -> (tempfile::TempDir, Indexer) {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(&root).unwrap();
        let index = ShareIndex::open(dir.path().join("index.redb"), KEY).unwrap();
        (dir, Indexer::new(index, root))
    }

    fn write(root: &Path, rel: &str, contents: &[u8]) -> PathBuf {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, contents).unwrap();
        abs
    }

    /// ISC-C21 — a cold scan indexes every file under the root.
    #[test]
    fn cold_scan_indexes_every_file() {
        let (_dir, idx) = fixture();
        write(&idx.root, "a.txt", b"aaa");
        write(&idx.root, "sub/b.txt", b"bbbb");
        write(&idx.root, "sub/deep/c.txt", b"c");

        assert_eq!(idx.cold_scan().unwrap(), 3);
        assert_eq!(idx.index().len().unwrap(), 3);
        assert_eq!(idx.index().get("a.txt").unwrap().unwrap().size, 3);
        assert_eq!(idx.index().get("sub/b.txt").unwrap().unwrap().size, 4);
    }

    /// M14: the free `scan_into` indexes a borrowed `Arc<ShareIndex>` so the
    /// net-actor can run the walk on a background thread while the same index
    /// stays queryable from the foreground (redb MVCC). Same result as the
    /// owning `Indexer::cold_scan`.
    #[test]
    fn scan_into_indexes_a_shared_arc_index() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a.txt", b"aaa");
        write(&root, "sub/b.txt", b"bbbb");

        let index = Arc::new(ShareIndex::open(dir.path().join("index.redb"), KEY).unwrap());
        // The actor pattern: scan a borrowed Arc while holding another clone.
        let foreground = Arc::clone(&index);
        assert_eq!(
            scan_into(&index, &root, &AtomicBool::new(false)).unwrap(),
            2
        );
        // The foreground clone observes the scan's writes (shared redb).
        assert_eq!(foreground.len().unwrap(), 2);
        assert_eq!(foreground.get("a.txt").unwrap().unwrap().size, 3);
    }

    /// A set cancel flag early-returns `Ok(count)` — cancellation is not an
    /// error, and a pre-set flag indexes nothing.
    #[test]
    fn scan_into_cancel_early_returns_ok() {
        let (_dir, idx) = fixture();
        write(&idx.root, "a.txt", b"a");
        write(&idx.root, "b.txt", b"b");

        let cancelled = AtomicBool::new(true);
        assert_eq!(scan_into(idx.index(), &idx.root, &cancelled).unwrap(), 0);
        assert_eq!(idx.index().len().unwrap(), 0);
    }

    /// A metadata scan writes `chunk_addrs: None` — content addresses come
    /// only from the hash pass.
    #[test]
    fn scan_into_writes_no_chunk_addrs() {
        let (_dir, idx) = fixture();
        write(&idx.root, "a.txt", b"aaa");
        idx.cold_scan().unwrap();
        assert_eq!(idx.index().get("a.txt").unwrap().unwrap().chunk_addrs, None);
    }

    /// Directories themselves are not indexed — only the files in them.
    #[test]
    fn cold_scan_indexes_files_not_dirs() {
        let (_dir, idx) = fixture();
        std::fs::create_dir_all(idx.root.join("empty_dir")).unwrap();
        write(&idx.root, "only.txt", b"x");
        assert_eq!(idx.cold_scan().unwrap(), 1);
    }

    /// ISC-C21 / ISC-A-C7 — applying one upsert event is a single-entry write
    /// that updates only that file; the rest of the index is untouched (no
    /// share-wide rewalk).
    #[test]
    fn apply_upsert_is_single_entry() {
        let (_dir, idx) = fixture();
        write(&idx.root, "a.txt", b"aaa");
        let b = write(&idx.root, "b.txt", b"bb");
        idx.cold_scan().unwrap();
        let a_before = idx.index().get("a.txt").unwrap().unwrap();

        // Grow b.txt, then apply ONE event for it.
        std::fs::write(&b, b"bbbbbbbb").unwrap();
        idx.apply_event(&FsEvent::Upserted(b)).unwrap();

        assert_eq!(
            idx.index().get("b.txt").unwrap().unwrap().size,
            8,
            "b updated"
        );
        assert_eq!(
            idx.index().get("a.txt").unwrap().unwrap(),
            a_before,
            "a untouched — no share-wide rewalk"
        );
        assert_eq!(idx.index().len().unwrap(), 2);
    }

    /// A `Removed` event drops exactly that entry.
    #[test]
    fn apply_removed_drops_entry() {
        let (_dir, idx) = fixture();
        let a = write(&idx.root, "a.txt", b"a");
        write(&idx.root, "b.txt", b"b");
        idx.cold_scan().unwrap();

        std::fs::remove_file(&a).unwrap();
        idx.apply_event(&FsEvent::Removed(a)).unwrap();
        assert_eq!(idx.index().get("a.txt").unwrap(), None);
        assert!(idx.index().get("b.txt").unwrap().is_some());
    }

    /// An `Upserted` event for a path that has vanished folds to a removal
    /// (watchers don't guarantee event ordering).
    #[test]
    fn apply_upsert_of_vanished_path_removes_it() {
        let (_dir, idx) = fixture();
        let a = write(&idx.root, "a.txt", b"a");
        idx.cold_scan().unwrap();
        std::fs::remove_file(&a).unwrap();

        idx.apply_event(&FsEvent::Upserted(a)).unwrap();
        assert_eq!(idx.index().get("a.txt").unwrap(), None);
    }

    /// Events for paths outside the share root are ignored, not errors.
    #[test]
    fn apply_event_outside_root_is_ignored() {
        let (_dir, idx) = fixture();
        idx.apply_event(&FsEvent::Upserted(PathBuf::from("/etc/hostname")))
            .unwrap();
        idx.apply_event(&FsEvent::Removed(PathBuf::from("/tmp/elsewhere")))
            .unwrap();
        assert_eq!(idx.index().len().unwrap(), 0);
    }

    // ── notify-event mapping (ISC-20) ──────────────────────────────────────

    /// Create and Modify events map to upserts of each affected path.
    #[test]
    fn map_create_and_modify_upsert() {
        let p = PathBuf::from("/share/x.txt");
        let create = Event::new(EventKind::Create(CreateKind::Any)).add_path(p.clone());
        assert_eq!(
            map_notify_event(&create),
            vec![FsEvent::Upserted(p.clone())]
        );
        let modify =
            Event::new(EventKind::Modify(notify::event::ModifyKind::Any)).add_path(p.clone());
        assert_eq!(map_notify_event(&modify), vec![FsEvent::Upserted(p)]);
    }

    /// Remove events map to removals.
    #[test]
    fn map_remove_event_removes() {
        let p = PathBuf::from("/share/x.txt");
        let rm = Event::new(EventKind::Remove(RemoveKind::Any)).add_path(p.clone());
        assert_eq!(map_notify_event(&rm), vec![FsEvent::Removed(p)]);
    }

    /// Access (and other non-mutating) events produce nothing.
    #[test]
    fn map_access_event_ignored() {
        let ev = Event::new(EventKind::Access(AccessKind::Any)).add_path(PathBuf::from("/x"));
        assert!(map_notify_event(&ev).is_empty());
    }

    // ── mtime fallback (ISC-21) ────────────────────────────────────────────

    /// `mtime_rescan` upserts only files newer than the cutoff: nothing is
    /// newer than u64::MAX; everything is newer than the epoch.
    #[test]
    fn mtime_rescan_filters_by_cutoff() {
        let (_dir, idx) = fixture();
        write(&idx.root, "a.txt", b"a");
        write(&idx.root, "b.txt", b"b");
        idx.cold_scan().unwrap();
        assert_eq!(
            idx.mtime_rescan(u64::MAX).unwrap(),
            0,
            "none newer than max"
        );
        assert_eq!(idx.mtime_rescan(0).unwrap(), 2, "all newer than epoch");
    }

    // ── live watch (ISC-20) ────────────────────────────────────────────────

    /// A live watch delivers an upsert event for a newly created file, and
    /// feeding it to the indexer is a single-entry write.
    #[test]
    fn live_watch_delivers_create_event() {
        let (_dir, idx) = fixture();
        let (_watch, rx) = ShareWatcher::watch(&idx.root).expect("watch starts");
        // Let the watcher arm before mutating the tree.
        std::thread::sleep(Duration::from_millis(150));
        write(&idx.root, "live.txt", b"hello");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut saw = false;
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(FsEvent::Upserted(p)) if p.ends_with("live.txt") => {
                    saw = true;
                    break;
                }
                _ => continue,
            }
        }
        assert!(saw, "watcher delivered an Upserted for the new file");

        idx.apply_event(&FsEvent::Upserted(idx.root.join("live.txt")))
            .unwrap();
        assert!(idx.index().get("live.txt").unwrap().is_some());
    }

    // ── background isolation (ISC-19 / ISC-23) ─────────────────────────────

    /// The cold scan runs on its own thread: spawn returns immediately, the
    /// index is queryable concurrently (never blocked by the scan — redb MVCC),
    /// and joining yields the full count.
    #[test]
    fn background_scan_is_isolated_and_non_blocking() {
        let (_dir, idx) = fixture();
        for i in 0..200 {
            write(&idx.root, &format!("f{i}.txt"), b"x");
        }
        let idx = Arc::new(idx);
        let handle = Arc::clone(&idx).spawn_background_scan();

        // A concurrent query returns without waiting on the scan to finish.
        let _ = idx.index().len().unwrap();

        assert_eq!(handle.join().unwrap(), 200);
        assert_eq!(idx.index().len().unwrap(), 200);
    }

    // ── cached hash pass (M16) ─────────────────────────────────────────────

    /// A no-op cancel flag for passes that should run to completion.
    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// With no index, `cached_or_hash` is exactly `hash_share`: identical
    /// manifest on the same tree.
    #[test]
    fn cached_or_hash_without_index_equals_hash_share() {
        let _ = oxicrypt_module::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(&root).unwrap();
        write(&root, "a.txt", b"alpha");
        write(&root, "sub/b.txt", b"bravo");

        let direct = hash_share(&root, &no_cancel(), &mut |_, _| {}).unwrap();
        let cached = cached_or_hash(None, &root, &no_cancel(), &mut |_, _| {}).unwrap();
        assert_eq!(cached, direct);
    }

    /// Concatenate a manifest entry's chunk addresses into the blob shape the
    /// index caches (ordered, 48 bytes each).
    fn addr_blob(chunks: &[ChunkAddr]) -> Vec<u8> {
        chunks
            .iter()
            .flat_map(|a| a.as_bytes().iter().copied())
            .collect()
    }

    /// The full cache cycle (M16 multi-addr): a metadata-only entry (no
    /// cached blob) is hashed and **all** its per-chunk addresses written
    /// back, ordered and concatenated; a second pass over the unchanged file
    /// reuses the cached addresses *without reading the file* — proved by
    /// rewriting the bytes with the same size and restoring the mtime, then
    /// observing the second pass still return the ORIGINAL addresses (a
    /// re-hash would have produced the new bytes' addresses). Uses a
    /// >CHUNK_SIZE file so the blob really is multi-addr.
    #[test]
    fn cached_or_hash_writes_back_multi_addr_then_hits_without_reading() {
        let (_dir, idx) = fixture();
        let original: Vec<u8> = (0..CHUNK_SIZE + 4096).map(|i| (i % 251) as u8).collect();
        let path = write(&idx.root, "big.bin", &original);
        idx.cold_scan().unwrap(); // metadata only — chunk_addrs: None

        // First pass: miss → hash → write-back of ALL chunk addrs.
        let first =
            cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |_, _| {}).unwrap();
        let original_chunks = first.entries[0].chunks.clone();
        assert_eq!(original_chunks.len(), 2, "fixture spans two chunks");
        assert_eq!(
            idx.index().get("big.bin").unwrap().unwrap().chunk_addrs,
            Some(addr_blob(&original_chunks)),
            "every chunk address was written back, ordered and concatenated"
        );

        // Rewrite with different bytes of the SAME length, then restore the
        // mtime, so the stat triplet matches the cached entry exactly.
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut rewrite = original.clone();
        rewrite[0] ^= 0xff;
        rewrite[CHUNK_SIZE] ^= 0xff; // touch both chunks
        std::fs::write(&path, &rewrite).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();

        // Second pass: a hit. Returning the ORIGINAL addresses (not the new
        // bytes') proves the file was never read, let alone re-hashed; the
        // per-file progress cadence is unchanged by hits.
        let mut seen = Vec::new();
        let second = cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |d, t| {
            seen.push((d, t));
        })
        .unwrap();
        assert_eq!(second.entries[0].chunks, original_chunks);
        assert_eq!(seen, vec![(1, 1)]);
    }

    /// Stale mtime → the cached addresses are NOT reused: the file is
    /// re-hashed and the fresh addresses written back.
    #[test]
    fn cached_or_hash_stale_mtime_rehashes() {
        let (_dir, idx) = fixture();
        let path = write(&idx.root, "a.txt", b"version one");
        let first =
            cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |_, _| {}).unwrap();

        // New content (and a naturally newer — or at worst equal — mtime;
        // bump it explicitly so coarse filesystem clocks can't alias).
        std::fs::write(&path, b"version TWO").unwrap();
        let later = std::time::SystemTime::now() + Duration::from_secs(10);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(later)
            .unwrap();

        let second =
            cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |_, _| {}).unwrap();
        assert_ne!(
            second.entries[0].chunks, first.entries[0].chunks,
            "a stat mismatch forces a re-hash"
        );
        assert_eq!(
            idx.index().get("a.txt").unwrap().unwrap().chunk_addrs,
            Some(addr_blob(&second.entries[0].chunks)),
            "the fresh addresses replaced the stale ones"
        );
    }

    /// Stale SIZE (mtime restored, size changed) → invalidation: the cached
    /// blob is not reused even though the mtime matches, because the stat
    /// filter checks both — and the blob's chunk count would no longer match
    /// `ceil(size/CHUNK_SIZE)` anyway (the parse-validation backstop).
    #[test]
    fn cached_or_hash_stale_size_invalidates() {
        let (_dir, idx) = fixture();
        let path = write(&idx.root, "a.txt", b"four");
        let first =
            cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |_, _| {}).unwrap();
        assert_eq!(first.entries[0].size, 4);

        // Grow the file but restore the original mtime: only the size differs.
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, b"four and then some").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();

        let second =
            cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |_, _| {}).unwrap();
        assert_eq!(second.entries[0].size, 18, "the new size is manifested");
        assert_ne!(
            second.entries[0].chunks, first.entries[0].chunks,
            "a size change forces a re-hash even under a matching mtime"
        );
    }

    /// A cached blob that does not parse for the statted size — here a
    /// single-addr-shaped row as the abandoned v2 format would have written
    /// for a 2-chunk file — is a miss, not a hit: re-hash and write back the
    /// well-formed multi-addr blob. The cache degrades to correctness.
    #[test]
    fn cached_or_hash_malformed_blob_rehashes() {
        let (_dir, idx) = fixture();
        let big: Vec<u8> = (0..CHUNK_SIZE + 1).map(|i| (i % 251) as u8).collect();
        let path = write(&idx.root, "big.bin", &big);

        // Plant a stat-matching entry whose blob has the WRONG chunk count
        // (one addr for a two-chunk file).
        let meta = std::fs::metadata(&path).unwrap();
        idx.index()
            .put(&ShareEntry {
                rel_path: "big.bin".to_owned(),
                size: meta.len(),
                mtime_unix_ms: super::mtime_ms(&meta),
                chunk_addrs: Some(vec![0xaa; CHUNK_ADDR_LEN]),
            })
            .unwrap();

        let manifest =
            cached_or_hash(Some(idx.index()), &idx.root, &no_cancel(), &mut |_, _| {}).unwrap();
        let direct = hash_share(&idx.root, &no_cancel(), &mut |_, _| {}).unwrap();
        assert_eq!(
            manifest, direct,
            "the planted bad blob was ignored and the file re-hashed"
        );
        assert_eq!(
            idx.index().get("big.bin").unwrap().unwrap().chunk_addrs,
            Some(addr_blob(&direct.entries[0].chunks)),
            "the well-formed blob replaced the malformed one"
        );
    }

    /// A set cancel flag aborts the cached pass with `Cancelled` (wrapped in
    /// `CachedHashError::Serve`) — symmetric with `hash_share`.
    #[test]
    fn cached_or_hash_cancel_aborts() {
        let (_dir, idx) = fixture();
        write(&idx.root, "a.txt", b"a");
        let cancelled = AtomicBool::new(true);
        let result = cached_or_hash(Some(idx.index()), &idx.root, &cancelled, &mut |_, _| {});
        assert!(matches!(
            result,
            Err(CachedHashError::Serve(ServeError::Cancelled))
        ));
    }
}
