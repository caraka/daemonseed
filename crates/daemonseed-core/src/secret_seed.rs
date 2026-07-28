//! Shared hygiene for redacted-zeroizing secret-material newtypes (#135).
//!
//! Several distinct secrets in this crate share one hygiene contract: a 32-byte
//! newtype that (a) zeroizes its bytes on drop, (b) renders `Debug` as
//! `"<Name>(<redacted>)"` so raw bytes never reach a log surface (ISC-A-C1), and
//! (c) exposes exactly one `as_bytes()` accessor. Two families use it:
//!
//! - **World-/maintainer-derivable Veilid rendezvous-owner seeds** — the six
//!   `*VeilidOwnerSeed` newtypes across [`crate::circle::key`],
//!   [`crate::public_room`], and [`crate::public_space`]. Each holds its seed in
//!   a `Box<[u8; 32]>` and is built by [`derive_boxed_seed`] from a per-context
//!   HKDF PRK (the `boxed` macro arm).
//! - **Identity-rooted secrets** — [`crate::identity::keys::VeilidNodeSeed`],
//!   [`crate::identity::keys::ShareRootIkm`] and
//!   [`crate::identity::keys::DmDoorbellSlotSecret`], held inline as `[u8; 32]` and
//!   additionally `Clone` + `Zeroize` (the `inline` macro arm). Their derivation
//!   is NOT shared — each is a distinct expansion of the identity PRK — only the
//!   newtype hygiene is.
//!
//! Consolidating the newtype boilerplate and the boxed-seed derivation into one
//! place means the zeroize-on-drop / redacted-`Debug` / both-path stack-zeroize
//! invariants are carried exactly once: a future hardening change lands for every
//! secret at once, and no site can silently regress a property the others keep.
//! The distinct newtypes are retained for key-class safety (a compile error
//! prevents substituting one secret for another at a use site); only the shape is
//! shared. The per-context HKDF-**extract** deliberately stays at each call site —
//! the salt, IKM, and canonicalization differ per secret and must not be unified.

use oxicrypt_kdf::{HkdfSha384, KdfError};
use zeroize::Zeroize;

/// Define a redacted-zeroizing 32-(or N-)byte secret newtype with the shared
/// hygiene contract: zeroize-on-drop, a `Debug` that renders
/// `"<Name>(<redacted>)"`, and a single `as_bytes()` accessor. Outer attributes
/// (including `///` docs) written before the `boxed`/`inline` keyword are applied
/// to the generated struct.
///
/// Two storage shapes:
///
/// - `boxed` — `Box<[u8; N]>`, `ZeroizeOnDrop`. The rendezvous-owner seeds, built
///   by [`derive_boxed_seed`].
/// - `inline` — `[u8; N]`, `Clone + Zeroize + ZeroizeOnDrop`. The identity-rooted
///   secrets, copied out of a transient buffer at their (distinct) derivation
///   sites.
macro_rules! redacted_secret_newtype {
    (
        $(#[$meta:meta])*
        boxed $vis:vis struct $name:ident([u8; $len:expr]);
    ) => {
        $(#[$meta])*
        #[derive(::zeroize::ZeroizeOnDrop)]
        $vis struct $name(::std::boxed::Box<[u8; $len]>);

        impl $name {
            /// Borrow the raw seed bytes. Callers must not copy these into a
            /// non-zeroizing buffer.
            $vis fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
    (
        $(#[$meta:meta])*
        inline $vis:vis struct $name:ident([u8; $len:expr]);
    ) => {
        $(#[$meta])*
        #[derive(::core::clone::Clone, ::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]
        $vis struct $name([u8; $len]);

        impl $name {
            /// Borrow the raw secret bytes. Callers must not copy these into a
            /// non-zeroizing buffer.
            $vis fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

pub(crate) use redacted_secret_newtype;

/// Expand an already-extracted HKDF PRK into a freshly-boxed `N`-byte seed,
/// zeroizing the transient stack buffer on **both** the success and error paths
/// (#135). This is the shared body of the six boxed rendezvous-owner-seed
/// derivations: the caller performs the per-context HKDF-**extract** (its salt,
/// IKM, and any canonicalization differ per secret) and passes the resulting
/// `hkdf` PRK plus its distinct `info` label; the boxed output is wrapped in the
/// caller's key-class newtype.
///
/// The stack `seed` is zeroized before returning on the expand-error path and
/// before returning `Ok` (its bytes now live only in the boxed allocation, which
/// zeroizes on drop) — so the secret never lingers in a stack frame past its use.
pub(crate) fn derive_boxed_seed<const N: usize>(
    hkdf: &HkdfSha384,
    info: &[u8],
) -> Result<Box<[u8; N]>, KdfError> {
    let mut seed = [0u8; N];
    if let Err(e) = hkdf.expand(info, &mut seed) {
        seed.zeroize();
        return Err(e);
    }
    let boxed = Box::new(seed);
    seed.zeroize();
    Ok(boxed)
}
