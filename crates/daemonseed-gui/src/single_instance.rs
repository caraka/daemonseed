//! Single-instance guard (#60): an advisory PID lockfile in the *resolved* profile
//! root, so a second client on the SAME root refuses to start, while a
//! `--portable` instance resolving a DIFFERENT root is still allowed. Guarding the
//! resolved root (not the binary) preserves the portable multi-instance story
//! (`cd alice && … ; cd bob && …`) and prevents same-root double-open of the
//! single-writer storage layer (redb + seeds + CAS).
//!
//! Dep-free (std only). **Refuse-to-start only** — focusing the existing window
//! needs cross-process IPC and is the harder half (deferred). A clean exit drops
//! the [`InstanceLock`] and removes the lockfile; a crash skips the drop, leaving a
//! stale lockfile that the next launch reclaims by a PID-liveness check.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Lockfile name inside the resolved profile root.
const LOCK_FILE: &str = "daemonseed.lock";

/// Held for the process lifetime; removes the lockfile on drop (clean exit).
#[derive(Debug)]
pub struct InstanceLock {
    path: PathBuf,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Best-effort: a failure here only leaves a stale lock the next launch reclaims.
        let _ = fs::remove_file(&self.path);
    }
}

/// Why a single-instance lock acquisition failed.
#[derive(Debug)]
pub enum LockError {
    /// Another live process already holds this profile root.
    AlreadyRunning,
    /// An I/O error creating, reading, or reclaiming the lockfile.
    Io(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::AlreadyRunning => {
                write!(
                    f,
                    "another daemonseed instance is already running for this profile"
                )
            }
            LockError::Io(e) => write!(f, "single-instance lockfile error: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

/// Acquire the single-instance lock on `root`. Creates the lockfile atomically
/// (`create_new` = `O_EXCL`); if it already exists, the holder's PID is checked for
/// liveness — a dead holder's lock is reclaimed and the acquisition retried, a live
/// holder yields [`LockError::AlreadyRunning`].
pub fn acquire(root: &Path) -> Result<InstanceLock, LockError> {
    fs::create_dir_all(root).map_err(LockError::Io)?;
    let path = root.join(LOCK_FILE);
    loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                // Best-effort PID stamp — only ever read by a later launch's liveness
                // check; an empty/short write just makes the lock look reclaimable.
                let _ = write!(f, "{}", std::process::id());
                return Ok(InstanceLock { path });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if holder_is_alive(&path) {
                    return Err(LockError::AlreadyRunning);
                }
                // Stale holder: remove and retry. A NotFound means another launch
                // already reclaimed it — re-loop and re-contend cleanly.
                match fs::remove_file(&path) {
                    Ok(()) => continue,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(LockError::Io(e)),
                }
            }
            Err(e) => return Err(LockError::Io(e)),
        }
    }
}

/// Whether the process named in the lockfile at `path` is alive. A
/// missing/empty/unparseable lockfile is treated as NOT alive (reclaimable).
fn holder_is_alive(path: &Path) -> bool {
    match read_pid(path) {
        Some(pid) if pid == std::process::id() => true, // our own (shouldn't happen)
        Some(pid) => pid_alive(pid),
        None => false,
    }
}

fn read_pid(path: &Path) -> Option<u32> {
    let mut s = String::new();
    OpenOptions::new()
        .read(true)
        .open(path)
        .ok()?
        .read_to_string(&mut s)
        .ok()?;
    s.trim().parse().ok()
}

/// On Linux, liveness = `/proc/<pid>` exists. On other platforms, conservatively
/// assume the holder is alive (never auto-reclaim — a stale lock there is cleared
/// by removing the file manually); refusing a false-positive is the safe failure.
#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(target_os = "linux"))]
fn pid_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique temp root per test (pid + nanos + tag — no uuid dep, mirrors the
    /// state.rs profile tests).
    fn temp_root(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ds-single-instance-{}-{tag}-{nanos}",
            std::process::id()
        ));
        p
    }

    #[test]
    fn second_acquire_on_the_same_root_is_refused() {
        let root = temp_root("same-root");
        let _held = acquire(&root).expect("first acquire succeeds");
        match acquire(&root) {
            Err(LockError::AlreadyRunning) => {}
            other => panic!("a second acquire on the same root must be refused, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    // A guaranteed-dead PID (well above Linux's pid_max) → `/proc/<pid>` is absent,
    // so the stale lock is reclaimable. Gated to Linux because the reclaim path keys
    // on `/proc`; the non-Linux conservative branch never reclaims.
    #[cfg(target_os = "linux")]
    #[test]
    fn stale_lock_from_a_dead_pid_is_reclaimed() {
        let root = temp_root("stale");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(LOCK_FILE), format!("{}", u32::MAX)).unwrap();
        let _held = acquire(&root).expect("a stale (dead-pid) lock must be reclaimable");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn drop_releases_the_lock_so_a_relaunch_succeeds() {
        let root = temp_root("drop");
        {
            let _held = acquire(&root).expect("acquire");
        } // drop here removes the lockfile
        let _held2 = acquire(&root).expect("re-acquire after the prior lock dropped");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_different_root_is_allowed_concurrently() {
        // The portable multi-instance story: distinct roots never contend.
        let a = temp_root("multi-a");
        let b = temp_root("multi-b");
        let _held_a = acquire(&a).expect("root a");
        let _held_b = acquire(&b).expect("root b — a different root must be allowed");
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }
}
