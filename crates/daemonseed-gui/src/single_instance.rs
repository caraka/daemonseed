//! Single-instance guard (#60): an advisory PID lockfile in the *resolved* profile
//! root, so a second client on the SAME root refuses to start, while a
//! `--portable` instance resolving a DIFFERENT root is still allowed. Guarding the
//! resolved root (not the binary) preserves the portable multi-instance story
//! (`cd alice && … ; cd bob && …`) and prevents same-root double-open of the
//! single-writer storage layer (redb + seeds + CAS).
//!
//! Std-only on Linux/macOS. **Refuse-to-start only** — focusing the existing window
//! needs cross-process IPC and is the harder half (deferred). A clean exit drops
//! the [`InstanceLock`] and removes the lockfile; a crash skips the drop, leaving a
//! stale lockfile that the next launch reclaims by a PID-liveness check.
//!
//! On Windows (#196) the lockfile is *not* the liveness authority: `pid_alive` had no
//! Windows implementation (`-> true`), so a lockfile left by a crash/ungraceful-close
//! was never reclaimed and every later launch on that root refused to start —
//! invisibly on the no-console build. Windows instead keys liveness on a `Global`
//! named mutex, which the OS releases on process death; if we acquire it cleanly, any
//! leftover lockfile on that root is definitionally stale and is reclaimed.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
// `Read` is only used by the non-Windows PID-liveness path (`read_pid`); on Windows
// the named mutex is the liveness authority, so the import would be dead there.
#[cfg(not(windows))]
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CreateMutexW;

/// Lockfile name inside the resolved profile root.
const LOCK_FILE: &str = "daemonseed.lock";

/// Held for the process lifetime; removes the lockfile on drop (clean exit).
#[derive(Debug)]
pub struct InstanceLock {
    path: PathBuf,
    /// Windows named-mutex handle (#196) — the authoritative liveness token. The OS
    /// auto-releases the mutex on process death; closing the handle on drop is the
    /// clean path. Kept on the main (UI) thread for the whole session.
    #[cfg(windows)]
    mutex: HANDLE,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Best-effort: a failure here only leaves a stale lock the next launch reclaims.
        let _ = fs::remove_file(&self.path);
        // Release the named mutex (#196). The OS would also drop it on process exit,
        // but closing the handle is the clean path for a graceful shutdown.
        #[cfg(windows)]
        // SAFETY: `mutex` is a live handle from `CreateMutexW`, closed exactly once here.
        unsafe {
            CloseHandle(self.mutex);
        }
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

    // Windows (#196): the named mutex — not the lockfile — is the liveness authority.
    // A clean acquisition proves no live process holds this root, so any leftover
    // lockfile is stale by definition: reclaim it (remove + rewrite our PID) instead
    // of consulting `pid_alive`. The lockfile is kept only as a human-visible marker.
    #[cfg(windows)]
    {
        let mutex = acquire_root_mutex(root)?;
        let _ = fs::remove_file(&path);
        let mut f = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                // SAFETY: `mutex` is the live handle we just acquired; close it once.
                unsafe { CloseHandle(mutex) };
                return Err(LockError::Io(e));
            }
        };
        let _ = write!(f, "{}", std::process::id());
        return Ok(InstanceLock { path, mutex });
    }

    #[cfg(not(windows))]
    {
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    // Best-effort PID stamp — only ever read by a later launch's
                    // liveness check; an empty/short write just makes the lock look
                    // reclaimable.
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
}

/// The single-instance lockfile path for `root` — for user-facing diagnostics: naming
/// the file to delete in the Windows stale-lock recovery dialog (#196). Windows-only,
/// as that is its only consumer; the `desktop` gate mirrors its call site.
#[cfg(windows)]
#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
pub fn lock_path(root: &Path) -> PathBuf {
    root.join(LOCK_FILE)
}

/// Create/acquire the `Global` named mutex keyed on `root` (#196). Returns the owned
/// handle on a clean acquisition; [`LockError::AlreadyRunning`] when a live process
/// already holds it (`ERROR_ALREADY_EXISTS`); [`LockError::Io`] if the OS call fails.
#[cfg(windows)]
fn acquire_root_mutex(root: &Path) -> Result<HANDLE, LockError> {
    let name = root_mutex_name(root);
    // SAFETY: `name` is a valid NUL-terminated UTF-16 buffer that outlives the call;
    // a null security-attributes pointer and `0` (not initial owner) are the documented
    // defaults for a plain named mutex.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(LockError::Io(io::Error::last_os_error()));
    }
    // CreateMutexW returns a handle to the *existing* mutex (and sets last-error to
    // ERROR_ALREADY_EXISTS) when another live process holds it — the OS having not yet
    // released it proves that process is alive. Close our extra handle and refuse.
    // SAFETY: called immediately after CreateMutexW with no intervening Win32 calls.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // SAFETY: `handle` is the live handle just returned; close it once.
        unsafe { CloseHandle(handle) };
        return Err(LockError::AlreadyRunning);
    }
    Ok(handle)
}

/// A per-root `Global` mutex name: `Global\daemonseed-<fnv1a64(path)>`. Distinct roots
/// hash to distinct names, so the portable multi-instance story (different roots may
/// run concurrently) is preserved. Canonicalize best-effort; fall back to the raw path.
/// Returns a NUL-terminated UTF-16 buffer ready for `CreateMutexW`.
#[cfg(windows)]
fn root_mutex_name(root: &Path) -> Vec<u16> {
    let canonical = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let h = fnv1a64(canonical.as_os_str().as_encoded_bytes());
    let name = format!("Global\\daemonseed-{h:016x}");
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// FNV-1a 64-bit hash (std-only). Used solely to derive a stable, collision-resistant
/// mutex name from a canonicalized path — not a security primitive.
#[cfg(windows)]
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Whether the process named in the lockfile at `path` is alive. A
/// missing/empty/unparseable lockfile is treated as NOT alive (reclaimable).
///
/// Non-Windows only: Windows keys liveness on the named mutex (#196), not the PID in
/// the lockfile, and short-circuits before reaching this path.
#[cfg(not(windows))]
fn holder_is_alive(path: &Path) -> bool {
    match read_pid(path) {
        Some(pid) if pid == std::process::id() => true, // our own (shouldn't happen)
        Some(pid) => pid_alive(pid),
        None => false,
    }
}

#[cfg(not(windows))]
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

// macOS and other non-Linux, non-Windows targets. Windows uses the named mutex
// (#196) and never reaches this; Linux uses `/proc` above.
#[cfg(all(not(target_os = "linux"), not(windows)))]
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
