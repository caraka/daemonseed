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
use std::time::UNIX_EPOCH;

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
    /// background thread so it cannot starve a foreground task.
    pub fn cold_scan(&self) -> Result<usize, IndexError> {
        let mut count = 0usize;
        for entry in WalkDir::new(&self.root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let Some(rel_path) = self.rel_path(entry.path()) else {
                continue;
            };
            self.index.put(&ShareEntry {
                rel_path,
                size: meta.len(),
                mtime_unix_ms: mtime_ms(&meta),
            })?;
            count += 1;
        }
        Ok(count)
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

    /// The share-root-relative path string used as the index identity for an
    /// absolute path. `None` if the path is not under the root.
    fn rel_path(&self, abs: &Path) -> Option<String> {
        abs.strip_prefix(&self.root)
            .ok()?
            .to_str()
            .map(|s| s.to_owned())
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

#[cfg(test)]
mod tests {
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
}
