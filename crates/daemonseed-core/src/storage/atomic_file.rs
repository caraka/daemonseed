//! Durable atomic file replacement — the primitive every DM record write goes
//! through (Amendment A9's build-obligation list, `docs/design/direct-messaging.md`).
//!
//! ## Why this is not `write` + `rename`
//!
//! The tmp-sibling-plus-rename idiom already in this tree — see
//! [`super::fetched::StagingArea::persist_manifest`] — is **crash-atomic but not
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
//! So `replace_atomically` adds the two missing barriers:
//!
//! ```text
//!   create each missing ancestor, fsync(its parent)  <- the directory is durable
//!   create tmp sibling (O_CREAT|O_EXCL, mode 0600)
//!   write bytes
//!   fsync(tmp)            <- the data is durable
//!   close tmp
//!   rename(tmp -> path)   <- atomic for any concurrent reader
//!   fsync(parent dir)     <- the *name* is durable
//! ```
//!
//! Both barriers are load-bearing and neither implies the other. Omit the file
//! fsync and the rename can expose a name with unwritten data behind it; omit
//! the directory fsync and the rename itself can vanish. The same argument
//! applies one level up: a freshly created *directory* is an entry in its own
//! parent, buffered like any other, so the first write into a new
//! correspondence directory must make those entries durable too — otherwise
//! `dm/corr-01/` itself is what the power cut takes.
//!
//! A crash or power loss at any point therefore leaves `path` holding either
//! its previous contents or `bytes` — never a mixture, never a truncation, and
//! never a name whose data was lost. That holds on every supported platform.
//! What differs is only *how* the name is made durable: Unix fsyncs the parent
//! directory as barrier 2, Windows requests it as part of the replacement. See
//! the Windows section below.
//!
//! ## Cross-process exclusion
//!
//! `rename` serializes readers, not writers: two processes replacing the same
//! path race, and last-writer-wins silently discards the other's committed
//! state. A9 names `flock` as the cross-process exclusion, and [`FileLock`]
//! provides it. The lock is advisory and separate from the replacement itself —
//! a caller performing a read-modify-write critical section must hold it across
//! *both* halves, which is why it is not taken inside `replace_atomically`:
//! taking it there would serialize the write while leaving the far more
//! dangerous read-then-write window wide open, and would read as safe.
//!
//! ## Orphaned temp siblings
//!
//! The temp sibling is removed on every path that *returns* an error from a
//! live process. It is **not** removed when the process does not live to return
//! one: a SIGKILL, an OOM kill or a power cut between the `create_new` and the
//! `rename` leaves the sibling on disk permanently, and nothing in this tree
//! sweeps it. A startup sweep of `*.tmp.*` is an obligation on the store built
//! over this module, not a service this module provides.
//!
//! That bounds what the record directory's shape can be claimed to prove. Its
//! fixed-size, fixed-count shape — the privacy argument that stops it leaking
//! pending volume — holds across *clean* runs only. Orphan count grows
//! monotonically with abnormal terminations, so until the store sweeps them the
//! entry count is itself a coarse signal of how often the writer died mid-write.
//! Recording that is better than pretending the shape is invariant.
//!
//! ## Windows
//!
//! The guarantee is the same as on Unix, reached by a different route. A
//! directory cannot be opened as a file there, so barrier 2 has nothing to
//! `fsync` and `RealDurability::sync_dir` is a no-op. The durability is
//! instead requested as part of the replacement itself:
//! [`daemonseed_sys::replace_durably`] passes `MOVEFILE_WRITE_THROUGH`
//! alongside `MOVEFILE_REPLACE_EXISTING`, so the directory entry has reached
//! stable storage by the time the call returns.
//!
//! That call is the workspace's only `unsafe`, quarantined in its own crate so
//! this one keeps `#![forbid(unsafe_code)]`.
//!
//! A replacement that fails — an antivirus scanner or search indexer holding
//! the temp file open yields `ERROR_SHARING_VIOLATION` in ordinary operation —
//! surfaces as [`AtomicReplaceError::Indeterminate`]; the caller must re-read
//! the destination rather than assume a generation.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The infix every temp sibling's name carries, between the target's name and
/// the random suffix.
///
/// Shared with the store that sweeps them ([`super::dm_store::DmStore::open`]),
/// so the writer and the sweeper cannot disagree about the name — a sweeper
/// keyed on a string this module later changed would silently stop finding
/// anything, and would read exactly like a directory with no orphans in it.
pub(crate) const TMP_INFIX: &str = ".tmp.";

/// Failure modes of a durable replacement.
///
/// The variants discriminate on the one thing a *commit-then-emit* caller can
/// act on: **what state the destination is in**. A single `Io` variant collapses
/// exactly that distinction — most sharply for a durability barrier that runs
/// *after* the rename, whose failure would otherwise report "the write failed"
/// for a write that landed.
#[derive(Debug)]
pub enum AtomicReplaceError {
    /// The failure happened **before** the rename: creating a missing ancestor
    /// directory, opening the temp sibling, writing it, or its data barrier.
    ///
    /// The destination is untouched — it holds its previous contents, or is
    /// still absent if it never existed. Nothing was committed, so the caller
    /// must not emit, and retrying is safe.
    NotLanded(std::io::Error),

    /// The rename itself failed.
    ///
    /// The destination state is unknown to this function: a failed `rename`
    /// ordinarily leaves the previous contents in place, but this function does
    /// not re-read to confirm it, so the caller must. Re-read the destination
    /// before emitting anything and do not assume either generation.
    Indeterminate(std::io::Error),

    /// The rename succeeded but a durability barrier after it failed.
    ///
    /// The new bytes **are readable now** — any concurrent reader already sees
    /// them — but the directory entry naming them has not reached stable
    /// storage and can revert on power loss. Emitting is not safe: the emission
    /// would outlive a record that can still disappear. A caller that
    /// re-attempts the same write and succeeds has re-established durability.
    LandedNotDurable(std::io::Error),

    /// The target has no parent directory, so no sibling temp file can be
    /// placed on the same filesystem — and a cross-filesystem `rename` is not
    /// atomic. Nothing was written; the destination is untouched.
    NoParent(PathBuf),

    /// The CSPRNG that names the temp sibling was unavailable.
    ///
    /// Nothing was written; the destination is untouched. This is kept distinct
    /// from an I/O failure because in a crypto application an unavailable
    /// CSPRNG is an alarm in its own right, and must never be indistinguishable
    /// from a transient disk error.
    Entropy(getrandom::Error),
}

impl core::fmt::Display for AtomicReplaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AtomicReplaceError::NotLanded(e) => {
                write!(
                    f,
                    "durable replace failed before the rename, destination unchanged: {e}"
                )
            }
            AtomicReplaceError::Indeterminate(e) => write!(
                f,
                "durable replace failed at the rename, destination state unknown — re-read before emitting: {e}"
            ),
            AtomicReplaceError::LandedNotDurable(e) => write!(
                f,
                "durable replace landed but its name barrier failed — the new bytes are readable and may revert on power loss: {e}"
            ),
            AtomicReplaceError::NoParent(p) => write!(
                f,
                "{} has no parent directory to place a sibling temp file in",
                p.display()
            ),
            AtomicReplaceError::Entropy(e) => {
                write!(f, "csprng unavailable for the temp-file suffix: {e}")
            }
        }
    }
}

impl core::error::Error for AtomicReplaceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            AtomicReplaceError::NotLanded(e)
            | AtomicReplaceError::Indeterminate(e)
            | AtomicReplaceError::LandedNotDurable(e) => Some(e),
            // `getrandom::Error` only implements `Error` under getrandom's
            // `std` feature, which this build does not enable, so the cause is
            // carried in `Display` rather than dropped.
            AtomicReplaceError::NoParent(_) | AtomicReplaceError::Entropy(_) => None,
        }
    }
}

// Deliberately no `impl From<std::io::Error> for AtomicReplaceError`: the whole
// point of the variants above is which side of the rename the failure fell on,
// and a blanket conversion cannot know that. Every I/O failure is mapped at its
// call site instead.

/// Why acquiring a [`FileLock`] failed.
///
/// Kept separate from [`AtomicReplaceError`] because the two entry points have
/// genuinely different ranges: acquiring a lock can never fail the way a rename
/// can, and a replacement can never hit the symlink refusal. A shared type
/// would make each signature claim failures it cannot produce.
#[derive(Debug)]
pub enum LockError {
    /// Creating the lock file's directory, opening the lock file, or blocking
    /// for the lock failed.
    Io(std::io::Error),

    /// The lock path is a symlink. Following it would let a co-resident
    /// attacker point two processes at different inodes, so they lock different
    /// files and the exclusion silently does nothing.
    UnsafePath(PathBuf),
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LockError::Io(e) => write!(f, "acquiring the store lock failed: {e}"),
            LockError::UnsafePath(p) => {
                write!(
                    f,
                    "{} is a symlink; refusing to lock through it",
                    p.display()
                )
            }
        }
    }
}

impl core::error::Error for LockError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            LockError::Io(e) => Some(e),
            LockError::UnsafePath(_) => None,
        }
    }
}

impl From<std::io::Error> for LockError {
    fn from(e: std::io::Error) -> Self {
        LockError::Io(e)
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

/// Test-only proof that the public entry point drives the *real* barriers.
///
/// The seam above is only as good as the argument the public function passes
/// through it: swapping [`RealDurability`] for a no-op implementation would
/// leave no filesystem trace and pass every other test in this module. These
/// counters are the positive control for that substitution.
///
/// **Per thread, not per process, and that is the whole point.** `cargo test`
/// runs the ~1160 tests in this binary on parallel threads and many of them
/// drive real barriers through `replace_atomically` or `DmStore::open`. Against
/// a process-global counter every exact-count assertion is a latent flake, and
/// every *strict-increase* assertion is worse — a neighbour's fsync satisfies it
/// even when the function under test drove none, so it passes for the wrong
/// reason. A mutex over the readers cannot fix either: the polluters are the
/// tests that never take it. libtest gives each test its own thread and every
/// barrier on these paths is driven synchronously on the caller's, so a
/// thread-local counter observes exactly the work the test itself caused.
#[cfg(test)]
mod barriers {
    use std::cell::Cell;

    thread_local! {
        static FILE_SYNCS: Cell<usize> = const { Cell::new(0) };
        static DIR_SYNCS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn note_file_sync() {
        FILE_SYNCS.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn note_dir_sync() {
        DIR_SYNCS.with(|c| c.set(c.get() + 1));
    }

    /// Barriers driven on **this thread** so far.
    pub(crate) fn file_syncs() -> usize {
        FILE_SYNCS.with(Cell::get)
    }

    /// Directory barriers driven on **this thread** so far.
    pub(crate) fn dir_syncs() -> usize {
        DIR_SYNCS.with(Cell::get)
    }
}

#[cfg(test)]
pub(crate) use barriers::{dir_syncs, file_syncs};

impl Durability for RealDurability {
    fn sync_file(&self, file: &File) -> std::io::Result<()> {
        #[cfg(test)]
        barriers::note_file_sync();
        file.sync_all()
    }

    #[cfg(unix)]
    fn sync_dir(&self, dir: &Path) -> std::io::Result<()> {
        #[cfg(test)]
        barriers::note_dir_sync();
        // Opening a directory read-only and fsyncing it is the portable-POSIX
        // way to make a rename durable.
        File::open(dir)?.sync_all()
    }

    #[cfg(not(unix))]
    fn sync_dir(&self, _dir: &Path) -> std::io::Result<()> {
        // Windows cannot open a directory as a file. See the module docs: the
        // durable-directory-entry guarantee does not hold on this platform.
        //
        // Deliberately does NOT call `barriers::note_dir_sync`. That counter is
        // the positive control for a no-op substitution, so a no-op incrementing
        // it would defeat the one test written to catch exactly that. The test
        // asserts `barriers::dir_syncs()` stays put on non-Unix, pinning the
        // weaker guarantee rather than concealing it.
        Ok(())
    }
}

/// Replace `path`'s contents with `bytes` atomically **and durably**.
///
/// On return, `path` names a file whose contents are exactly `bytes` and whose
/// data and directory entry have both reached stable storage — as have the
/// entries naming any ancestor directories this call had to create. On Unix a
/// crash or power loss at any point leaves `path` holding either its previous
/// contents or `bytes`, never a mixture and never a truncation; on non-Unix
/// there is additionally a window in which `path` is absent (module docs).
///
/// The temp sibling is created with `O_CREAT|O_EXCL` under a random suffix, so
/// an existing symlink at the temp path cannot be followed and two concurrent
/// callers cannot collide on it. It is removed on every path that returns an
/// `Err`, but a process killed mid-write orphans it permanently — sweeping
/// `*.tmp.*` is the store's obligation, not this module's.
///
/// The **destination** is not checked for being a symlink, and does not need to
/// be: POSIX `rename(2)` does not dereference the final path component, so a
/// symlinked destination is *replaced* by the renamed temp file rather than
/// written through. The symlink refusal in [`FileLock::acquire`] exists because
/// the lock path is `open`ed, which does follow. There is no such check here.
///
/// This does **not** take the [`FileLock`] — see the module docs for why a
/// read-modify-write caller must hold it across both halves itself.
///
/// **`pub(crate)`, deliberately.** It takes a path, and the DM record store's
/// first invariant is that a record's path is *derived* from its kind and its
/// correspondence rather than passed — so a write to the wrong record is
/// unrepresentable. Left public with this signature it is a second door into the
/// same directory with none of that on it, and none of the store's lock,
/// fixed-size or sealing discipline either. In-crate callers outside the store
/// still reach it; [`FileLock`] stays public because holding a lock is the
/// caller's business wherever it happens.
pub(crate) fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<(), AtomicReplaceError> {
    replace_atomically_with(path, bytes, &RealDurability)
}

pub(crate) fn replace_atomically_with<D: Durability>(
    path: &Path,
    bytes: &[u8],
    durability: &D,
) -> Result<(), AtomicReplaceError> {
    let parent = parent_dir(path)?;
    create_dir_all_durable(parent, durability).map_err(AtomicReplaceError::NotLanded)?;

    let tmp = unique_tmp_sibling(path, parent)?;

    // Everything from here on must clean up `tmp` before returning an error,
    // or a crash-looping caller litters the directory — which for the DM store
    // is not merely untidy: the record directory's shape is the privacy
    // argument that stops it leaking pending volume (bounded as the module docs
    // record — this covers returned errors, not killed processes).
    //
    // On a `LandedNotDurable` the sibling has already been renamed away, so the
    // removal is a harmless no-op; it never touches the destination.
    let result = write_and_commit(&tmp, path, parent, bytes, durability);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The directory a sibling temp file can be placed in, or [`AtomicReplaceError::NoParent`].
fn parent_dir(path: &Path) -> Result<&Path, AtomicReplaceError> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AtomicReplaceError::NoParent(path.to_path_buf()))
}

/// `create_dir_all`, but with the directory entries it creates made durable.
///
/// [`std::fs::create_dir_all`] returns as soon as the directories are visible
/// to this process. The entry naming a newly created directory inside *its own*
/// parent is buffered like any other write, so a power cut can lose the whole
/// directory — and with it a record whose write already returned `Ok` and whose
/// emission the caller therefore treated as proven. That is exactly the first
/// write into a new correspondence directory (`dm/corr-01/resume.bin`), where
/// commit-then-emit is at its most load-bearing.
///
/// So each missing ancestor is created on its own and its parent fsynced before
/// descending. The walk runs shallowest-first, so more than one missing level
/// (`dm/` and `dm/corr-01/` both absent) is covered, not just the last one.
fn create_dir_all_durable<D: Durability>(dir: &Path, durability: &D) -> std::io::Result<()> {
    // Walk up from the target to the deepest ancestor that already exists,
    // collecting what is missing (deepest-first).
    let mut missing: Vec<&Path> = Vec::new();
    let mut cursor = dir;
    while !cursor.exists() {
        missing.push(cursor);
        match cursor.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => cursor = parent,
            None => break,
        }
    }

    for created in missing.iter().rev() {
        match std::fs::create_dir(created) {
            Ok(()) => {}
            // A concurrent writer won the race. The entry is that writer's to
            // make durable, not ours — fsyncing here would be harmless but the
            // barrier belongs with the create that actually happened.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        // A relative first component has no named parent; the working directory
        // is the one that gained the entry.
        let entry_holder = created
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        durability.sync_dir(entry_holder)?;
    }
    Ok(())
}

fn write_and_commit<D: Durability>(
    tmp: &Path,
    path: &Path,
    parent: &Path,
    bytes: &[u8],
    durability: &D,
) -> Result<(), AtomicReplaceError> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    // `create_new` alone yields 0666 & ~umask — typically 0644 — and the rename
    // carries the TEMP file's mode onto the destination, discarding the old
    // inode's entirely. Without this line the first replacement of a record
    // hardened to 0600 would silently widen it back to world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(tmp).map_err(AtomicReplaceError::NotLanded)?;
    file.write_all(bytes)
        .map_err(AtomicReplaceError::NotLanded)?;

    // Barrier 1: the data is durable before any name points at it.
    durability
        .sync_file(&file)
        .map_err(AtomicReplaceError::NotLanded)?;
    drop(file);

    // Past this point the destination may already hold the new bytes, so no
    // later failure may be reported as "nothing happened".
    //
    // Nothing may be inserted between the temp file's data barrier and this
    // call. The replacement is atomic on every supported platform, and removing
    // the destination first is never required — doing so would open a window in
    // which the file is absent outright rather than holding one generation or
    // the other.
    //
    // On Windows this also carries `MOVEFILE_WRITE_THROUGH`, which is the only
    // way to make the resulting directory entry durable on that platform; see
    // [`daemonseed_sys`]. On Unix it is a plain `rename(2)` and barrier 2
    // below supplies the durability.
    daemonseed_sys::replace_durably(tmp, path).map_err(AtomicReplaceError::Indeterminate)?;

    // Barrier 2: the *name* is durable. Only reachable on Unix in any
    // meaningful sense; see `RealDurability::sync_dir`.
    durability
        .sync_dir(parent)
        .map_err(AtomicReplaceError::LandedNotDurable)?;

    Ok(())
}

/// A temp sibling name that no existing entry can already hold.
///
/// The suffix is drawn from the CSPRNG rather than a counter or a pid so that
/// two processes — or one process crash-looping — cannot collide, and so an
/// attacker cannot pre-create the path to make `O_EXCL` fail in a loop.
fn unique_tmp_sibling(path: &Path, parent: &Path) -> Result<PathBuf, AtomicReplaceError> {
    let mut suffix = [0u8; 12];
    getrandom::fill(&mut suffix).map_err(AtomicReplaceError::Entropy)?;

    let mut name = path
        .file_name()
        .ok_or_else(|| AtomicReplaceError::NoParent(path.to_path_buf()))?
        .to_os_string();
    name.push(format!("{TMP_INFIX}{}", hex::encode(suffix)));

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
    pub fn acquire(lock_path: &Path) -> Result<Self, LockError> {
        use fs4::fs_std::FileExt;

        if std::fs::symlink_metadata(lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(LockError::UnsafePath(lock_path.to_path_buf()));
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
        /// The data barrier, carrying the length the synced handle held — proof
        /// the barrier saw the *new* bytes and not an empty file.
        File {
            synced_len: u64,
        },
        Dir(PathBuf),
    }

    /// What the destination must look like when each barrier runs.
    struct Witness {
        dest: PathBuf,
        /// The destination's contents before the replacement, or `None` if it
        /// did not exist.
        before: Option<Vec<u8>>,
        after: Vec<u8>,
    }

    /// Records the barriers *and observes the filesystem at each one*.
    ///
    /// Recording the order alone proves nothing about the ordering that matters:
    /// the two barriers must straddle the rename, and a recorder that sees only
    /// its own calls is satisfied identically if `sync_file` moves after the
    /// rename or `sync_dir` moves before it — the exact two defects the module
    /// docs call load-bearing. So the recorder asserts the destination state it
    /// must be able to see from each side of the rename.
    struct Recorder {
        seen: Mutex<Vec<Barrier>>,
        witness: Witness,
    }

    impl Recorder {
        fn new(dest: &Path, before: Option<&[u8]>, after: &[u8]) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                witness: Witness {
                    dest: dest.to_path_buf(),
                    before: before.map(<[u8]>::to_vec),
                    after: after.to_vec(),
                },
            }
        }

        fn barriers(&self) -> Vec<Barrier> {
            std::mem::take(&mut *self.seen.lock().unwrap())
        }
    }

    impl Durability for Recorder {
        fn sync_file(&self, file: &File) -> std::io::Result<()> {
            let synced_len = file.metadata()?.len();
            self.seen.lock().unwrap().push(Barrier::File { synced_len });

            // Pre-rename: the destination must still be exactly as it was.
            match &self.witness.before {
                Some(previous) => assert_eq!(
                    &std::fs::read(&self.witness.dest).unwrap(),
                    previous,
                    "the data barrier must run BEFORE the rename — the destination \
                     already holds the new bytes here"
                ),
                None => assert!(
                    !self.witness.dest.exists(),
                    "the data barrier must run BEFORE the rename — the destination \
                     already exists here"
                ),
            }
            Ok(())
        }

        fn sync_dir(&self, dir: &Path) -> std::io::Result<()> {
            self.seen
                .lock()
                .unwrap()
                .push(Barrier::Dir(dir.to_path_buf()));

            // Only the destination's own parent is fsynced after the rename;
            // barriers for freshly created ancestors run before anything is
            // written, so they are not evidence either way.
            if Some(dir) == self.witness.dest.parent() {
                assert_eq!(
                    std::fs::read(&self.witness.dest).unwrap(),
                    self.witness.after,
                    "the name barrier must run AFTER the rename — the destination \
                     does not hold the new bytes yet"
                );
            }
            Ok(())
        }
    }

    /// The positive control for the whole module: both barriers are performed,
    /// in the order file-then-directory, against the target's own parent, and —
    /// the part that actually matters — one on each side of the rename.
    ///
    /// An fsync leaves no filesystem trace, so without this assertion every
    /// other test here would pass just as happily with both `sync_all` calls
    /// deleted, or with either call site moved across the rename — a broken
    /// probe that reads exactly like a passing one.
    #[test]
    fn both_durability_barriers_are_performed_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        std::fs::write(&path, b"a much longer previous value").unwrap();
        let recorder = Recorder::new(&path, Some(b"a much longer previous value"), b"committed");

        replace_atomically_with(&path, b"committed", &recorder).unwrap();

        assert_eq!(
            recorder.barriers(),
            vec![
                Barrier::File {
                    synced_len: b"committed".len() as u64
                },
                Barrier::Dir(dir.path().to_path_buf()),
            ],
            "the data barrier must precede the name barrier, and the name \
             barrier must target the destination's own parent directory"
        );
    }

    /// The seam is only as honest as the argument the public entry point passes
    /// through it. Swapping `RealDurability` for a no-op leaves no filesystem
    /// trace, so nothing else in this module would notice.
    #[test]
    fn the_public_entry_point_drives_the_real_barriers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");

        let files_before = file_syncs();
        let dirs_before = dir_syncs();

        replace_atomically(&path, b"real").unwrap();

        // Other tests in this binary run concurrently and can only inflate the
        // counters, never hold them back — so a strict increase is the whole
        // claim: the public path performed real barriers.
        assert!(
            file_syncs() > files_before,
            "replace_atomically must drive RealDurability's data barrier"
        );

        // The name barrier is real only on Unix, so each platform asserts what
        // is true there. A single claim across both would pass on non-Unix
        // without the barrier having run, which is the failure this split
        // exists to prevent.
        #[cfg(unix)]
        assert!(
            dir_syncs() > dirs_before,
            "replace_atomically must drive RealDurability's name barrier"
        );

        // Non-Unix reaches name durability through the replacement itself
        // (`MOVEFILE_WRITE_THROUGH`), not through this barrier, so `sync_dir`
        // is a no-op there and must not appear to have run. Equality is exact
        // rather than best-effort: no arm of `sync_dir` compiled on this
        // platform touches the counter, and the counter is per-thread besides,
        // so nothing can inflate it. Should a real barrier ever be added here,
        // this fails and says so. Do not delete it to make that green.
        #[cfg(not(unix))]
        assert_eq!(
            dir_syncs(),
            dirs_before,
            "non-Unix has no durable-name barrier; if one is added, assert it \
             here rather than removing this check"
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

    /// A directory is an entry in its own parent. Creating `dm/corr-01/` and
    /// fsyncing only `corr-01` leaves the entries naming `dm` and `corr-01`
    /// buffered, so a power cut takes the whole correspondence directory while
    /// the write has already returned `Ok` and the caller has emitted.
    #[test]
    fn each_newly_created_ancestor_directory_is_made_durable() {
        let dir = tempfile::tempdir().unwrap();
        let dm = dir.path().join("dm");
        let corr = dm.join("corr-01");
        let path = corr.join("resume.bin");
        let recorder = Recorder::new(&path, None, b"resume");

        replace_atomically_with(&path, b"resume", &recorder).unwrap();

        assert_eq!(
            recorder.barriers(),
            vec![
                // the entry naming `dm`, in the tempdir
                Barrier::Dir(dir.path().to_path_buf()),
                // the entry naming `corr-01`, in `dm`
                Barrier::Dir(dm.clone()),
                Barrier::File {
                    synced_len: b"resume".len() as u64
                },
                // the entry naming the record itself
                Barrier::Dir(corr.clone()),
            ],
            "every ancestor this call created must have its own parent fsynced, \
             shallowest first, before the record is written"
        );
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
    /// destination exactly as it was — which is what `NotLanded` promises.
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
        assert!(matches!(err, AtomicReplaceError::NotLanded(_)));

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

    /// The case a single `Io` variant got exactly backwards: the rename has
    /// already succeeded, so the new bytes are readable by every concurrent
    /// reader. Reporting this as a plain failure would leave the caller holding
    /// generation n and emitting nothing while the disk holds n+1.
    #[test]
    fn a_failed_name_barrier_reports_that_the_bytes_already_landed() {
        struct FailingDirBarrier;
        impl Durability for FailingDirBarrier {
            fn sync_file(&self, _file: &File) -> std::io::Result<()> {
                Ok(())
            }
            fn sync_dir(&self, _dir: &Path) -> std::io::Result<()> {
                Err(std::io::Error::other("simulated directory fsync failure"))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        std::fs::write(&path, b"previous").unwrap();

        let err = replace_atomically_with(&path, b"landed", &FailingDirBarrier).unwrap_err();
        assert!(
            matches!(err, AtomicReplaceError::LandedNotDurable(_)),
            "a barrier that runs after the rename cannot report the write as not landed"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"landed",
            "the rename succeeded before the barrier failed, so the new bytes are readable"
        );

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("record.bin")],
            "the sibling was renamed away; the cleanup must not litter or delete the destination"
        );
    }

    /// `Indeterminate` is the variant whose whole purpose is telling the caller
    /// to re-read before emitting, and it is the one the `Durability` seam
    /// cannot reach — the seam wraps the two barriers, not `rename(2)`. A real
    /// rename failure is inducible without it: `rename` refuses to replace a
    /// directory with a file, so a destination that is a non-empty directory
    /// drives the genuine syscall error rather than a simulated one.
    #[test]
    fn a_rename_that_cannot_complete_is_reported_as_indeterminate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("occupant"), b"in the way").unwrap();

        let err = replace_atomically(&path, b"never lands").unwrap_err();
        assert!(
            matches!(err, AtomicReplaceError::Indeterminate(_)),
            "a failed rename must tell the caller the destination state is unknown, got {err:?}"
        );

        assert!(
            path.join("occupant").exists(),
            "the failed rename must not have disturbed the destination"
        );
        let siblings: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            siblings,
            vec![std::ffi::OsString::from("record.bin")],
            "the temp sibling must still be cleaned up on the indeterminate path"
        );
    }

    /// The rename carries the TEMP file's mode onto the destination, discarding
    /// the old inode's. A default-mode temp file therefore *widens* a hardened
    /// record on its next replacement — silently, and only once someone bothers
    /// to harden it.
    #[cfg(unix)]
    #[test]
    fn a_replacement_does_not_widen_the_destinations_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.bin");
        std::fs::write(&path, b"previous").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        replace_atomically(&path, b"next").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the replacement must not hand the destination a wider mode than it had"
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
        let parent = path.parent().unwrap();

        let a = unique_tmp_sibling(&path, parent).unwrap();
        let b = unique_tmp_sibling(&path, parent).unwrap();

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
        assert!(matches!(err, LockError::UnsafePath(_)));
    }
}
