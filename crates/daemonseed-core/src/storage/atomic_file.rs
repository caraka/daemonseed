//! Durable atomic file replacement — the primitive every DM record write goes
//! through (Amendment A9's build-obligation list, `docs/design/direct-messaging.md`).
//!
//! ## Why this is not `write` + `rename`
//!
//! The tmp-sibling-plus-rename idiom already in this tree — see
//! [`super::fetched::FetchedStore::persist_manifest`] — is **crash-atomic but not
//! power-loss-durable**. `rename(2)` is atomic with respect to a concurrent
//! reader, so a crash can never expose a half-written file; but neither the
//! file's data nor the directory entry that names it is guaranteed to have
//! reached stable storage. After a power cut the rename can be lost wholesale,
//! or — worse — the directory entry can land while the data behind it has not,
//! yielding a file of the right name full of zeroes.
//!
//! That distinction does not matter for a manifest that can be re-fetched. It
//! matters a great deal for the DM resume record, whose entire purpose is to
//! make *commit-then-emit* a single provable act: A9.2 requires the committed
//! re-establishment root, the `attempt` counter and the sealed `RE-EST` frame
//! bytes to land together, so that a crash can never pair a committed root with
//! a stale attempt. A lost or zero-filled record breaks exactly that pairing.
//!
//! So [`replace_atomically`] adds the two missing barriers:
//!
//! ```text
//!   create tmp sibling (O_CREAT|O_EXCL)
//!   write bytes
//!   fsync(tmp)            <- the data is durable
//!   close tmp
//!   rename(tmp -> path)   <- atomic for any concurrent reader
//!   fsync(parent dir)     <- the *name* is durable
//! ```
//!
//! Both barriers are load-bearing and neither implies the other. Omit the file
//! fsync and the rename can expose a name with unwritten data behind it; omit
//! the directory fsync and the rename itself can vanish.
//!
//! ## Cross-process exclusion
//!
//! `rename` serializes readers, not writers: two processes replacing the same
//! path race, and last-writer-wins silently discards the other's committed
//! state. A9 names `flock` as the cross-process exclusion, and [`FileLock`]
//! provides it. The lock is advisory and separate from the replacement itself —
//! a caller performing a read-modify-write critical section must hold it across
//! *both* halves, which is why it is not taken inside [`replace_atomically`]:
//! taking it there would serialize the write while leaving the far more
//! dangerous read-then-write window wide open, and would read as safe.
//!
//! ## Windows
//!
//! `rename` is not atomic-over-an-existing-file on Windows, and a directory
//! cannot be opened as a file to be fsynced. [`replace_atomically`] therefore
//! removes the destination before renaming there, and skips the directory
//! barrier. The Windows build is consequently *crash-atomic with durable file
//! data* but without the durable-directory-entry guarantee; this is recorded
//! rather than silently papered over, because the DM store's atomicity contract
//! is weaker on that platform.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Failure modes of a durable replacement.
#[derive(Debug)]
pub enum AtomicReplaceError {
    /// An underlying filesystem operation failed. The destination is unchanged
    /// unless the failure was the `rename` itself, which is atomic — so the
    /// destination holds either its previous contents or the new ones, never a
    /// mixture.
    Io(std::io::Error),

    /// The target has no parent directory, so no sibling temp file can be
    /// placed on the same filesystem — and a cross-filesystem `rename` is not
    /// atomic.
    NoParent(PathBuf),

    /// A path that must be a regular file (or absent) is a symlink. Following
    /// it would let a co-resident attacker redirect the write, or — at the lock
    /// path — point two processes at different inodes so they lock different
    /// files and the exclusion silently does nothing.
    UnsafePath(PathBuf),
}

impl core::fmt::Display for AtomicReplaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AtomicReplaceError::Io(e) => write!(f, "durable replace I/O failed: {e}"),
            AtomicReplaceError::NoParent(p) => write!(
                f,
                "{} has no parent directory to place a sibling temp file in",
                p.display()
            ),
            AtomicReplaceError::UnsafePath(p) => {
                write!(
                    f,
                    "{} is a symlink; refusing to write through it",
                    p.display()
                )
            }
        }
    }
}

impl core::error::Error for AtomicReplaceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            AtomicReplaceError::Io(e) => Some(e),
            AtomicReplaceError::NoParent(_) | AtomicReplaceError::UnsafePath(_) => None,
        }
    }
}

impl From<std::io::Error> for AtomicReplaceError {
    fn from(e: std::io::Error) -> Self {
        AtomicReplaceError::Io(e)
    }
}

/// The two durability barriers, behind a seam.
///
/// An fsync has no observable effect that a test can detect from the
/// filesystem — a missing one is invisible until a power cut. Routing both
/// barriers through this trait means the tests can assert they were performed,
/// in the right order, against the right paths, rather than asserting nothing
/// and reading as if they had proved something.
pub(crate) trait Durability {
    fn sync_file(&self, file: &File) -> std::io::Result<()>;
    fn sync_dir(&self, dir: &Path) -> std::io::Result<()>;
}

/// The real barriers.
pub(crate) struct RealDurability;

impl Durability for RealDurability {
    fn sync_file(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    #[cfg(unix)]
    fn sync_dir(&self, dir: &Path) -> std::io::Result<()> {
        // Opening a directory read-only and fsyncing it is the portable-POSIX
        // way to make a rename durable.
        File::open(dir)?.sync_all()
    }

    #[cfg(not(unix))]
    fn sync_dir(&self, _dir: &Path) -> std::io::Result<()> {
        // Windows cannot open a directory as a file. See the module docs: the
        // durable-directory-entry guarantee does not hold on this platform.
        Ok(())
    }
}

/// Replace `path`'s contents with `bytes` atomically **and durably**.
///
/// On return, `path` names a file whose contents are exactly `bytes` and whose
/// data and directory entry have both reached stable storage. A crash or power
/// loss at any point leaves `path` holding either its previous contents or
/// `bytes` — never a mixture, never a truncation, and (on Unix) never a name
/// whose data was lost.
///
/// The temp sibling is created with `O_CREAT|O_EXCL` under a random suffix, so
/// an existing symlink at the temp path cannot be followed and two concurrent
/// callers cannot collide on it. It is removed on every failure path.
///
/// This does **not** take the [`FileLock`] — see the module docs for why a
/// read-modify-write caller must hold it across both halves itself.
pub fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<(), AtomicReplaceError> {
    replace_atomically_with(path, bytes, &RealDurability)
}

pub(crate) fn replace_atomically_with<D: Durability>(
    path: &Path,
    bytes: &[u8],
    durability: &D,
) -> Result<(), AtomicReplaceError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AtomicReplaceError::NoParent(path.to_path_buf()))?;
    std::fs::create_dir_all(parent)?;

    let tmp = unique_tmp_sibling(path)?;

    // Everything from here on must clean up `tmp` before returning an error,
    // or a crash-looping caller litters the directory — which for the DM store
    // is not merely untidy: the record directory's fixed-size, fixed-count
    // shape is the privacy argument that stops it leaking pending volume.
    let result = write_and_commit(&tmp, path, bytes, durability);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn write_and_commit<D: Durability>(
    tmp: &Path,
    path: &Path,
    bytes: &[u8],
    durability: &D,
) -> Result<(), AtomicReplaceError> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(tmp)?;
    file.write_all(bytes)?;

    // Barrier 1: the data is durable before any name points at it.
    durability.sync_file(&file)?;
    drop(file);

    // Windows cannot rename onto an existing file. This opens a window in
    // which `path` does not exist — the reason the module docs record the
    // Windows guarantee as weaker.
    #[cfg(not(unix))]
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    std::fs::rename(tmp, path)?;

    // Barrier 2: the *name* is durable. Only reachable on Unix in any
    // meaningful sense; see `RealDurability::sync_dir`.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AtomicReplaceError::NoParent(path.to_path_buf()))?;
    durability.sync_dir(parent)?;

    Ok(())
}

/// A temp sibling name that no existing entry can already hold.
///
/// The suffix is drawn from the CSPRNG rather than a counter or a pid so that
/// two processes — or one process crash-looping — cannot collide, and so an
/// attacker cannot pre-create the path to make `O_EXCL` fail in a loop.
fn unique_tmp_sibling(path: &Path) -> Result<PathBuf, AtomicReplaceError> {
    let mut suffix = [0u8; 12];
    getrandom::fill(&mut suffix).map_err(|e| {
        AtomicReplaceError::Io(std::io::Error::other(format!(
            "csprng unavailable for temp-file suffix: {e}"
        )))
    })?;

    let mut name = path
        .file_name()
        .ok_or_else(|| AtomicReplaceError::NoParent(path.to_path_buf()))?
        .to_os_string();
    name.push(format!(".tmp.{}", hex::encode(suffix)));

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AtomicReplaceError::NoParent(path.to_path_buf()))?;
    Ok(parent.join(name))
}

/// A held exclusive advisory lock, released when dropped.
///
/// `flock` is released on close, so dropping the handle is the unlock. Held
/// across a whole read-modify-write critical section, this is what stops two
/// processes' committed state from silently overwriting each other — the
/// cardinal silent-send-loss the DM store's single-writer discipline exists to
/// prevent.
#[derive(Debug)]
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Block until the exclusive advisory lock at `lock_path` is held.
    ///
    /// Refuses a symlink at the lock path: a co-resident attacker could point
    /// it at a different inode so two processes lock different files and the
    /// exclusion silently does nothing. (An atomic `O_NOFOLLOW` open would
    /// close the residual check-then-open window without a platform-specific
    /// dependency; that hardening is tracked alongside the same check in
    /// [`super::fetched`].)
    pub fn acquire(lock_path: &Path) -> Result<Self, AtomicReplaceError> {
        use fs4::fs_std::FileExt;

        if std::fs::symlink_metadata(lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(AtomicReplaceError::UnsafePath(lock_path.to_path_buf()));
        }
        if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_path)?;
        file.lock_exclusive()?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// What a durability barrier was asked to do, in the order it was asked.
    #[derive(Debug, PartialEq, Eq)]
    enum Barrier {
        File,
        Dir(PathBuf),
    }

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Barrier>>,
    }

    impl Durability for Recorder {
        fn sync_file(&self, _file: &File) -> std::io::Result<()> {
            self.seen.lock().unwrap().push(Barrier::File);
            Ok(())
        }
        fn sync_dir(&self, dir: &Path) -> std::io::Result<()> {
            self.seen
                .lock()
                .unwrap()
                .push(Barrier::Dir(dir.to_path_buf()));
            Ok(())
        }
    }

    /// The positive control for the whole module: both barriers are performed,
    /// in the order file-then-directory, against the target's own parent.
    ///
    /// An fsync leaves no filesystem trace, so without this assertion every
    /// other test here would pass just as happily with both `sync_all` calls
    /// deleted — a broken probe that reads exactly like a passing one. Deleting
    /// either barrier from `RealDurability` is invisible; deleting either call
    /// site fails *this* test.
    #[test]
    fn both_durability_barriers_are_performed_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        let recorder = Recorder::default();

        replace_atomically_with(&path, b"committed", &recorder).unwrap();

        let seen = recorder.seen.lock().unwrap();
        assert_eq!(
            *seen,
            vec![Barrier::File, Barrier::Dir(dir.path().to_path_buf())],
            "the data barrier must precede the name barrier, and the name \
             barrier must target the destination's own parent directory"
        );
    }

    #[test]
    fn writes_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");

        replace_atomically(&path, b"first").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn replaces_an_existing_file_wholesale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        std::fs::write(&path, b"a much longer previous value").unwrap();

        replace_atomically(&path, b"short").unwrap();

        // Not a prefix-overwrite: the old tail must be gone, which is exactly
        // what an in-place write would have left behind.
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dm").join("corr-01").join("resume.bin");

        replace_atomically(&path, b"resume").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"resume");
    }

    /// The record directory's shape is a privacy argument — a directory whose
    /// entry count tracks pending volume leaks it. Temp siblings must never
    /// survive a successful write.
    #[test]
    fn leaves_no_temp_sibling_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");

        replace_atomically(&path, b"one").unwrap();
        replace_atomically(&path, b"two").unwrap();
        replace_atomically(&path, b"three").unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("record.bin")]);
    }

    /// A failure after the temp file exists must not litter, and must leave the
    /// destination exactly as it was.
    #[test]
    fn a_failed_commit_cleans_up_and_leaves_the_destination_untouched() {
        struct FailingFileBarrier;
        impl Durability for FailingFileBarrier {
            fn sync_file(&self, _file: &File) -> std::io::Result<()> {
                Err(std::io::Error::other("simulated fsync failure"))
            }
            fn sync_dir(&self, _dir: &Path) -> std::io::Result<()> {
                unreachable!("the file barrier fails first")
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        std::fs::write(&path, b"previous").unwrap();

        let err = replace_atomically_with(&path, b"never lands", &FailingFileBarrier).unwrap_err();
        assert!(matches!(err, AtomicReplaceError::Io(_)));

        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"previous",
            "a failed replacement must not disturb the committed value"
        );
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("record.bin")],
            "the temp sibling must be removed on the failure path"
        );
    }

    #[test]
    fn a_path_without_a_parent_is_rejected_rather_than_written_somewhere() {
        let err = replace_atomically(Path::new("bare-name"), b"x").unwrap_err();
        assert!(matches!(err, AtomicReplaceError::NoParent(_)));
    }

    #[test]
    fn temp_siblings_are_unique_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");

        let a = unique_tmp_sibling(&path).unwrap();
        let b = unique_tmp_sibling(&path).unwrap();

        assert_ne!(a, b, "a collision would make O_EXCL fail spuriously");
        assert_eq!(
            a.parent(),
            path.parent(),
            "the temp file must be a sibling — a cross-filesystem rename is not atomic"
        );
    }

    #[test]
    fn a_lock_is_exclusive_and_released_on_drop() {
        use fs4::fs_std::FileExt;

        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(".dm.lock");

        let held = FileLock::acquire(&lock_path).unwrap();

        // Positive control: prove the lock is actually held, by showing a
        // second handle to the same inode cannot take it. Without this, a
        // no-op `acquire` would pass every other assertion here.
        let contender = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        assert!(
            !contender.try_lock_exclusive().unwrap(),
            "the lock must exclude a second holder while it is held"
        );
        drop(contender);

        drop(held);

        let after = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        assert!(
            after.try_lock_exclusive().unwrap(),
            "dropping the handle must release the lock"
        );
    }

    #[test]
    fn a_symlinked_lock_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("elsewhere.lock");
        std::fs::write(&real, b"").unwrap();
        let link = dir.path().join(".dm.lock");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(not(unix))]
        {
            let _ = &real;
            return;
        }

        let err = FileLock::acquire(&link).unwrap_err();
        assert!(matches!(err, AtomicReplaceError::UnsafePath(_)));
    }
}
