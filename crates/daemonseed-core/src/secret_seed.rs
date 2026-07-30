//! Shared hygiene for redacted-zeroizing secret-material newtypes (#135).
//!
//! Several distinct secrets in this crate share one hygiene contract: a 32-byte
//! newtype that (a) zeroizes its bytes on drop, (b) renders `Debug` as
//! `"<Name>(<redacted>)"` so raw bytes never reach a log surface (ISC-A-C1), and
//! (c) exposes exactly one `as_bytes()` accessor. Three families use it:
//!
//! - **AEAD content keys** — [`crate::circle::key::CircleKey`] and
//!   [`crate::public_room::PublicRoomKey`], held in a `Box<[u8; 32]>` (the `boxed`
//!   macro arm) and constructed in their own modules, each additionally exposing a
//!   `from_bytes` in a separate `impl` block.
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
/// - `boxed` — `Box<[u8; N]>`, `ZeroizeOnDrop`. Two families: the AEAD content
///   keys, constructed in their own modules, and the rendezvous-owner seeds, built
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

/// Tests for the shared hygiene contract (#242).
///
/// The contract has two halves and they are tested in two places, because this
/// crate is `#![forbid(unsafe_code)]` and one of them cannot be observed without
/// raw pointers. Here: the trait bound on every generated type, and the redacted
/// `Debug` — both reachable in safe code. In `tests/secret_zeroize_on_drop.rs`:
/// the behavioural half, that the bytes actually reach zero before their storage
/// is released, observed from inside a witness allocator in a separate crate
/// where `unsafe` is permitted.
#[cfg(test)]
mod tests {
    use zeroize::ZeroizeOnDrop;

    // Two secrets of the macro's own making, one per storage shape. They exist so
    // the macro can be exercised directly rather than through whichever caller
    // happens to be cheapest to construct, and so the field is reachable — every
    // real user declares its newtype in its own module, where the tuple field is
    // private to that module.
    redacted_secret_newtype! {
        /// Inline-arm probe: a 32-byte secret held as `[u8; 32]`.
        inline struct TestInlineSecret([u8; 32]);
    }

    redacted_secret_newtype! {
        /// Boxed-arm probe: a 32-byte secret held as `Box<[u8; 32]>`.
        boxed struct TestBoxedSecret([u8; 32]);
    }

    /// The byte every probe secret is filled with. Distinctive in both hex and
    /// decimal so a leaked rendering is recognisable either way.
    const FILL: u8 = 0xA5;

    /// Every secret newtype the macro generates carries `ZeroizeOnDrop`.
    ///
    /// This is a compile-time bound, so it proves the trait is implemented on all
    /// nineteen key classes — and nothing more. A hand-written `impl
    /// ZeroizeOnDrop for T {}` with no `Drop` would satisfy it while wiping
    /// nothing; closing that gap is what `tests/secret_zeroize_on_drop.rs` is
    /// for. The value here is breadth: it fails on the arm-level derive AND on
    /// any single type that later drifts to a hand-rolled shape without the
    /// property, including the ones with no public constructor to build a
    /// behavioural test around.
    #[test]
    #[allow(clippy::extra_unused_type_parameters)]
    fn every_macro_generated_secret_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        // The macro's own probes.
        assert_zeroize_on_drop::<TestInlineSecret>();
        assert_zeroize_on_drop::<TestBoxedSecret>();

        // inline arm — identity-rooted secrets.
        assert_zeroize_on_drop::<crate::identity::keys::ShareRootIkm>();
        assert_zeroize_on_drop::<crate::identity::keys::VeilidNodeSeed>();
        assert_zeroize_on_drop::<crate::identity::keys::DmDoorbellSlotSecret>();

        // inline arm — the DM ratchet key schedule.
        assert_zeroize_on_drop::<crate::dm::ratchet::RootKey>();
        assert_zeroize_on_drop::<crate::dm::ratchet::ChainKey>();
        assert_zeroize_on_drop::<crate::dm::ratchet::MessageKey>();

        // boxed arm — AEAD content keys.
        assert_zeroize_on_drop::<crate::circle::key::CircleKey>();
        assert_zeroize_on_drop::<crate::public_room::PublicRoomKey>();

        // boxed arm — rendezvous-owner seeds.
        assert_zeroize_on_drop::<crate::circle::key::CircleVeilidOwnerSeed>();
        assert_zeroize_on_drop::<crate::circle::key::CirclePresenceVeilidOwnerSeed>();
        assert_zeroize_on_drop::<crate::public_room::RoomVeilidOwnerSeed>();
        assert_zeroize_on_drop::<crate::public_room::RoomPresenceVeilidOwnerSeed>();
        assert_zeroize_on_drop::<crate::public_room::RoomShareVeilidOwnerSeed>();
        assert_zeroize_on_drop::<crate::public_space::ProjectAnnounceVeilidOwnerSeed>();

        // boxed arm — DM.
        assert_zeroize_on_drop::<crate::dm::ack::DmAckSealKey>();
        assert_zeroize_on_drop::<crate::dm::doorbell::DmDoorbellOwnerSeed>();
        assert_zeroize_on_drop::<crate::dm::keyrec::DmKeyRecordOwnerSeed>();
        assert_zeroize_on_drop::<crate::dm::paging::DmPageOwnerSeed>();
        assert_zeroize_on_drop::<crate::dm::ratchet::EphemeralDecapKey>();
    }

    /// Both arms render a redacted `Debug`.
    ///
    /// Exact-string equality, not a `contains("<redacted>")` check: a `Debug` that
    /// printed `Name { inner: <redacted>, bytes: [..] }` would pass a substring
    /// test. The second half then pins the failure mode a derived `Debug` would
    /// actually produce — a tuple struct over `[u8; 32]` renders its bytes in
    /// decimal — so the assertion is tied to the leak, not only to the wording.
    #[test]
    fn both_arms_render_a_redacted_debug() {
        let inline = TestInlineSecret([FILL; 32]);
        let boxed = TestBoxedSecret(Box::new([FILL; 32]));

        let inline_dbg = format!("{inline:?}");
        let boxed_dbg = format!("{boxed:?}");

        assert_eq!(inline_dbg, "TestInlineSecret(<redacted>)");
        assert_eq!(boxed_dbg, "TestBoxedSecret(<redacted>)");

        for rendered in [&inline_dbg, &boxed_dbg] {
            assert!(
                !rendered.contains("165"),
                "decimal byte rendering leaked: {rendered}"
            );
            assert!(
                !rendered.contains("a5"),
                "hex byte rendering leaked: {rendered}"
            );
        }
    }

    /// `as_bytes` is the single accessor, and it hands back the stored secret
    /// unchanged on both arms — the property the zeroize tests above depend on to
    /// locate the bytes at all.
    #[test]
    fn both_arms_expose_their_bytes_through_as_bytes() {
        assert_eq!(TestInlineSecret([FILL; 32]).as_bytes(), &[FILL; 32]);
        assert_eq!(
            TestBoxedSecret(Box::new([FILL; 32])).as_bytes(),
            &[FILL; 32]
        );
    }

    /// The shared boxed-seed derivation returns the expansion it was asked for and
    /// is deterministic for a given PRK and label — the input side of the boxed
    /// arm, whose output hygiene the allocator-witness test in
    /// `tests/secret_zeroize_on_drop.rs` covers.
    #[test]
    fn derive_boxed_seed_is_deterministic_per_label() {
        let _ = oxicrypt_module::initialize();
        let hkdf = super::HkdfSha384::extract(Some(b"salt"), b"ikm").unwrap();

        let a = super::derive_boxed_seed::<32>(&hkdf, b"label-one").unwrap();
        let b = super::derive_boxed_seed::<32>(&hkdf, b"label-one").unwrap();
        let c = super::derive_boxed_seed::<32>(&hkdf, b"label-two").unwrap();

        assert_eq!(a, b, "same PRK and label expand to the same seed");
        assert_ne!(a, c, "a distinct label is a distinct seed");
        assert_ne!(*a, [0u8; 32], "the expansion is not all-zero");
    }
}
