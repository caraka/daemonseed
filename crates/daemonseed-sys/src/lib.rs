//! OS-level calls that have no safe equivalent in `std`.
//!
//! This is the **only** crate in the daemonseed workspace that uses `unsafe`.
//! Every other crate remains `#![forbid(unsafe_code)]`, including
//! `daemonseed-core`, which holds the storage and key-handling paths and calls
//! into this one.
//!
//! Today it provides a single mechanism, [`replace_durably`].
//!
//! ## What belongs here, and what does not
//!
//! A crate named for its *permission* rather than its *purpose* will become
//! the place unsafe goes to stop being read, unless the bar is written down.
//! The bar is:
//!
//! - **Admit** a call into the operating system that `std` does not wrap, where
//!   the only unsafety is discharging an FFI pointer or lifetime contract, and
//!   the safety argument fits in the comment above it.
//! - **Refuse** anything whose unsafety is a *Rust* invariant rather than an OS
//!   boundary — transmutes, aliasing tricks, hand-rolled `Send`/`Sync`, raw
//!   allocator hooks, SIMD intrinsics. Those are their own mechanisms and each
//!   earns its own crate and its own audit, the way `oxicrypt-zeroize` and
//!   `oxicrypt-aes-accel` do.
//!
//! Every function here carries a `SAFETY:` comment that discharges its
//! contract explicitly. A function that cannot be given one does not belong.
//!
//! ## Why a crate boundary rather than an exception
//!
//! On Unix the durability of a rename is obtained after the fact, by opening
//! the parent directory and `fsync`ing it. That is ordinary safe code and lives
//! in `daemonseed-core` alongside the rest of the write path.
//!
//! Windows has no equivalent: a directory cannot be opened as a file, so there
//! is nothing to `fsync`. The durability must instead be requested *as part of*
//! the rename, via `MoveFileExW`'s `MOVEFILE_WRITE_THROUGH` flag — and
//! `std::fs::rename` does not pass it. There is no safe wrapper for that call
//! in std or in this workspace's dependency graph.
//!
//! So the choice was to relax `#![forbid(unsafe_code)]` on the crate where it
//! is worth the most, or to quarantine one `unsafe` block behind a boundary.
//! This crate is that boundary. It is small enough to audit in one sitting and
//! has no dependencies beyond the raw bindings themselves.
//!
//! ## What is and is not guaranteed
//!
//! **Atomicity of the replacement is not this crate's contribution** — it is
//! `std::fs::rename`'s, on every supported platform, by documented contract.
//! On Windows that is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`.
//!
//! What this crate adds is *durability of the resulting name*:
//!
//! | platform | replacement | name durable after return |
//! |----------|-------------|---------------------------|
//! | Unix     | `rename(2)` | no — caller must `fsync` the parent |
//! | Windows  | `MoveFileExW` + `MOVEFILE_WRITE_THROUGH` | yes |
//!
//! The asymmetry is deliberate. On Unix the parent `fsync` is a separate,
//! observable barrier that `daemonseed-core` already performs and tests; adding
//! a second mechanism here would give two places to get it wrong. On Windows no
//! such barrier is expressible, so the flag is the only way to obtain the
//! guarantee at all.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::io;
use std::path::Path;

/// Rename `from` onto `to`, replacing `to` if it exists.
///
/// Returns once the rename has been performed. On Windows the directory entry
/// is durable when this returns; on Unix the caller must still make the parent
/// directory durable itself — see the table in the crate documentation.
///
/// # Errors
///
/// Returns the underlying OS error if the rename fails. A failure leaves the
/// destination in an indeterminate state as far as this function is concerned:
/// it does not re-read to confirm, so a caller that must know should.
pub fn replace_durably(from: &Path, to: &Path) -> io::Result<()> {
    replace_durably_inner(from, to)
}

#[cfg(not(windows))]
fn replace_durably_inner(from: &Path, to: &Path) -> io::Result<()> {
    // `rename(2)` replaces atomically. Durability of the directory entry is the
    // caller's parent-`fsync`, which is safe code and lives in the caller.
    std::fs::rename(from, to)
}

#[cfg(windows)]
fn replace_durably_inner(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    /// A NUL-terminated UTF-16 copy of `p`, as every Win32 `*W` entry point
    /// requires. The `Vec` must outlive the call that borrows its pointer.
    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let from_w = wide(from);
    let to_w = wide(to);

    // SAFETY: `MoveFileExW` requires two NUL-terminated wide strings that
    // remain valid for the duration of the call, and a flag word. `from_w` and
    // `to_w` are owned `Vec<u16>`s built by `wide`, which appends the
    // terminator, and both are still in scope here, so neither pointer can
    // dangle and neither buffer can be reallocated during the call. The
    // function has no other preconditions: it validates the paths itself and
    // reports every failure through `GetLastError`, which is read below. No
    // Rust invariant is being asserted — this is a plain FFI call whose only
    // unsafety is the pointer contract just discharged.
    let ok = unsafe {
        MoveFileExW(
            from_w.as_ptr(),
            to_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if ok == 0 {
        // Win32 signals failure by returning zero and setting the thread's last
        // error. `last_os_error` reads exactly that, so the returned error is
        // the OS's own rather than a synthesised approximation.
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_an_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("new");
        let to = dir.path().join("old");
        std::fs::write(&from, b"new bytes").expect("write from");
        std::fs::write(&to, b"old bytes").expect("write to");

        replace_durably(&from, &to).expect("replace over an existing file");

        assert_eq!(
            std::fs::read(&to).expect("read destination"),
            b"new bytes",
            "the destination must hold the source's bytes after replacement"
        );
        assert!(
            !from.exists(),
            "the source must no longer exist under its old name"
        );
    }

    #[test]
    fn creates_a_destination_that_did_not_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("new");
        let to = dir.path().join("absent");
        std::fs::write(&from, b"bytes").expect("write from");

        replace_durably(&from, &to).expect("replace where no destination exists");

        assert_eq!(std::fs::read(&to).expect("read destination"), b"bytes");
    }

    #[test]
    fn a_missing_source_is_an_error_not_a_silent_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("does-not-exist");
        let to = dir.path().join("dest");

        let err = replace_durably(&from, &to)
            .expect_err("renaming a source that does not exist must fail");

        // The destination must not have been created as a side effect. This is
        // the positive control for the two tests above: without it, an
        // implementation that silently created empty files would satisfy them.
        assert!(
            !to.exists(),
            "a failed replace must not create the destination"
        );
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
