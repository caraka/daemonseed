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
//! The live filesystem-event source (inotify / FSEvents / ReadDirectoryChangesW
//! via the `notify` crate) and its watch-limit fallback feed [`FsEvent`]s into
//! [`Indexer::apply_event`]; that wiring layers on top of this engine.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::UNIX_EPOCH;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use walkdir::WalkDir;

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
    /// free [`scan_into`] so a caller holding only an `Arc<ShareIndex>` (M14
    /// net-actor activation) can run the identical walk against a borrowed index.
    pub fn cold_scan(&self) -> Result<usize, IndexError> {
        scan_into(&self.index, &self.root)
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
                    Ok(meta) if meta.is_file() => self.index.put(&ShareEntry {
                        rel_path,
                        size: meta.len(),
                        mtime_unix_ms: mtime_ms(&meta),
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
///
/// Operates on `&ShareIndex` rather than owning it so a caller holding an
/// `Arc<ShareIndex>` can run the scan on a dedicated background thread while the
/// *same* index stays fully queryable from the foreground (redb MVCC) — the M14
/// net-actor share-activation path. [`Indexer::cold_scan`] delegates here.
pub fn scan_into(index: &ShareIndex, root: &Path) -> Result<usize, IndexError> {
    let mut count = 0usize;
    for entry in WalkDir::new(root).into_iter().flatten() {
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
        })?;
        count += 1;
    }
    Ok(count)
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
        assert_eq!(scan_into(&index, &root).unwrap(), 2);
        // The foreground clone observes the scan's writes (shared redb).
        assert_eq!(foreground.len().unwrap(), 2);
        assert_eq!(foreground.get("a.txt").unwrap().unwrap().size, 3);
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
}
