//! Shared hygiene for redacted-zeroizing secret-material newtypes (#135).
//!
//! Several distinct secrets in this crate share one hygiene contract: a 32-byte
//! newtype that (a) zeroizes its bytes on drop, (b) renders `Debug` as
//! `"<Name>(<redacted>)"` so raw bytes never reach a log surface (ISC-A-C1), and
//! (c) exposes exactly one accessor — `as_bytes()`, or `with_bytes()` on the
//! scoped arm (#271). Three families use it:
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
//! - **Identity-rooted secrets** — [`crate::identity::keys::ShareRootIkm`] and
//!   [`crate::identity::keys::DmDoorbellSlotSecret`], held inline as `[u8; 32]` and
//!   additionally `Clone` + `Zeroize` (the `inline` macro arm). Their derivation
//!   is NOT shared — each is a distinct expansion of the identity PRK — only the
//!   newtype hygiene is.
//! - **Identity-rooted capabilities** — [`crate::identity::keys::VeilidNodeSeed`]
//!   alone, on the `inline_scoped` arm: same storage, but reached through
//!   `with_bytes` and not `Clone` (#271). It is the node identity, so a copy of it
//!   is a copy of the whole process's standing on the network — unlike its two
//!   siblings above, which root content keys and a slot index.
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
/// `"<Name>(<redacted>)"`, and a single accessor. Outer attributes (including
/// `///` docs) written before the `boxed`/`inline`/`inline_scoped` keyword are
/// applied to the generated struct.
///
/// Three storage shapes:
///
/// - `boxed` — `Box<[u8; N]>`, `ZeroizeOnDrop`. Two families: the AEAD content
///   keys, constructed in their own modules, and the rendezvous-owner seeds, built
///   by [`derive_boxed_seed`].
/// - `inline` — `[u8; N]`, `Clone + Zeroize + ZeroizeOnDrop`, reached by
///   `as_bytes`. The identity-rooted secrets, copied out of a transient buffer at
///   their (distinct) derivation sites.
/// - `inline_scoped` — the same storage, reached by `with_bytes` instead, and
///   **not** `Clone`. For a secret that is a *capability* rather than a content
///   key, where a borrowing accessor plus `Clone` are two cheap paths to a plain
///   non-zeroizing copy (#271). The choice is per-secret and deliberately not a
///   sweep: the DM siblings are world-derivable by design and the circle seeds
///   derive from material their trust set already holds, so a copy of any of them
///   opens no boundary.
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
        inline_scoped $vis:vis struct $name:ident([u8; $len:expr]);
    ) => {
        $(#[$meta])*
        #[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]
        $vis struct $name([u8; $len]);

        impl $name {
            /// Run `f` over the raw secret bytes, and return what it returns.
            ///
            /// The scoped counterpart to the `inline` arm's `as_bytes`. It does not
            /// make copying impossible and is not claimed to — `f` may return the
            /// array. It requires the copy to be written as a closure whose return
            /// type is the secret, visible in review, rather than taken invisibly in
            /// a deref, and it bounds the borrow to the call.
            ///
            /// `T` cannot borrow from the argument, so a caller needing to hold the
            /// bytes across an `.await` cannot express it and is pushed to `|b| *b`
            /// — which is the point: that copy is then legible.
            $vis fn with_bytes<T>(&self, f: impl ::core::ops::FnOnce(&[u8; $len]) -> T) -> T {
                f(&self.0)
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

    redacted_secret_newtype! {
        /// Scoped-arm probe: `[u8; 32]` reached through `with_bytes`, not `Clone`.
        ///
        /// Exists so the arm's expansion is exercised here rather than only through
        /// the one real type on it. Without it, a change to the arm would be caught
        /// only by `VeilidNodeSeed`'s own tests, and an arm added for a future
        /// capability would ship unexercised.
        inline_scoped struct TestScopedSecret([u8; 32]);
    }

    /// The byte every probe secret is filled with. Distinctive in both hex and
    /// decimal so a leaked rendering is recognisable either way.
    const FILL: u8 = 0xA5;

    /// What is wrong with an `inline_scoped` arm expansion, if anything.
    ///
    /// **Factored out of the assertion on purpose.** A check that reads its own
    /// source through `include_str!` has no seam a fixture can reach, so it can
    /// never be shown to fire and reads as a passing guard for ever. Taking the
    /// predicate as a `&str -> Vec<_>` makes it drivable: the test below pins each
    /// shape it must catch AND one it must not, and only then points it at the
    /// real file.
    ///
    /// Needles are assembled from fragments so this function's own source cannot
    /// satisfy them — the same trick the actor's enqueue probe uses.
    ///
    /// **This is the secondary net, not the guarantee.** It sees only the macro
    /// arm's text, so it cannot see a derive written at a declaration or an `impl`
    /// added to a concrete type elsewhere. Those are pinned at the type by the
    /// `compile_fail` doctests on `identity::keys::VeilidNodeSeed`, where a compile
    /// is the oracle. What this catches is a change made to the arm itself, which
    /// would silently weaken every future user of it.
    fn scoped_arm_defects(src: &str) -> Vec<&'static str> {
        // Production half only. Without this, deleting the arm outright makes
        // `find` land on this module's own fixture strings and the check passes on
        // borrowed text — it went red by luck rather than by the "arm not found"
        // path it advertises.
        let prod = src.split_once("#[cfg(test)]").map_or(src, |(p, _)| p);

        let marker: String = ["inline_scoped $vis:vis ", "struct"].concat();
        let Some(start) = prod.find(marker.as_str()) else {
            return vec!["arm not found"];
        };
        let rest = &prod[start..];
        let body = &rest[..rest.find("\n    };").unwrap_or(rest.len())];

        let mut out = Vec::new();
        // Any signature handing back a borrow of the bytes, under ANY name —
        // pinning the literal `as_bytes` would miss `fn raw`, and missing it is
        // the whole defect.
        if body.contains(["-> &[", "u8"].concat().as_str()) {
            out.push("borrowing accessor");
        }
        // The same borrow by a trait door.
        if body.contains("Deref") || body.contains(["AsRef", "<"].concat().as_str()) {
            out.push("borrowing trait impl");
        }
        // `Clone` inside a derive list, not anywhere in the prose — the arm's own
        // doc comment is free to say the word, and saying it must not fail a test.
        let cloned = body
            .match_indices(["#[der", "ive("].concat().as_str())
            .any(|(i, _)| {
                let tail = &body[i..];
                tail[..tail.find(')').unwrap_or(tail.len())].contains("Clone")
            });
        if cloned {
            out.push("Clone");
        }
        if !body.contains(["fn with", "_bytes"].concat().as_str()) {
            out.push("no scoped accessor");
        }
        out
    }

    /// The `inline_scoped` arm keeps its shape: a scoped accessor, no borrow out,
    /// no `Clone` (#271).
    ///
    /// The arm exists so a secret that is a *capability* — `VeilidNodeSeed`, whose
    /// blast radius is the whole process — cannot have its bytes copied out in a
    /// deref or a clone. Weakening the arm is a one-line change here that nothing
    /// else would notice: every type on it would still compile, still zeroize, and
    /// still pass every behavioural test, while the property the arm exists for
    /// would be gone. `8566ab9` recorded exactly this gap against the page-seed
    /// accessor — "no test covers the shape, and the guarantee rests on review".
    ///
    /// **Scope, stated so this is not read wider than it is.** This test covers the
    /// arm. It does *not* cover a given type: a declaration-site `#[derive(Clone)]`
    /// rides in through `$(#[$meta])*`, and an inherent `impl` can be written
    /// wherever the field is reachable — neither appears in this file. Those are
    /// pinned by the `compile_fail` doctests on `identity::keys::VeilidNodeSeed`.
    /// Both halves are needed and neither subsumes the other.
    #[test]
    fn the_scoped_arm_does_not_hand_back_a_borrow_or_a_clone() {
        // `}}` escapes the arm terminator's brace: a bare `}` in a format string is
        // a compile error, not a literal.
        let arm = |inner: &str| format!("inline_scoped $vis:vis struct X;\n{inner}\n    }};");

        // Each shape the predicate MUST catch. The accessor cases use real return
        // types, because a signature with no return type is not the defect.
        assert_eq!(
            scoped_arm_defects(&arm("        $vis fn as_bytes(&self) -> &[u8; $len] {}")),
            vec!["borrowing accessor", "no scoped accessor"],
        );
        // The same defect under a different name — pinning the literal `as_bytes`
        // would have missed this, which is what the review caught.
        assert_eq!(
            scoped_arm_defects(&arm("        $vis fn raw(&self) -> &[u8; $len] {}")),
            vec!["borrowing accessor", "no scoped accessor"],
        );
        // And through a trait door.
        assert_eq!(
            scoped_arm_defects(&arm(
                "        impl Deref for $name {}\n        $vis fn with_bytes<T>() {}"
            )),
            vec!["borrowing trait impl"],
        );
        assert_eq!(
            scoped_arm_defects(&arm(
                "        #[derive(Clone)]\n        $vis fn with_bytes<T>() {}"
            )),
            vec!["Clone"],
        );
        assert_eq!(scoped_arm_defects(&arm("")), vec!["no scoped accessor"],);

        // Mirror controls: well-formed input is NOT flagged, so the check cannot
        // pass by firing on everything.
        assert!(scoped_arm_defects(&arm("        $vis fn with_bytes<T>() {}")).is_empty(),);
        // Specifically, prose may say "Clone" and "as_bytes" without failing — the
        // arm's own doc comment does both, and a check that forbade the words would
        // train someone to weaken it.
        assert!(
            scoped_arm_defects(&arm(
                "        /// Unlike as_bytes on the inline arm, this is not Clone.\n        $vis fn with_bytes<T>() {}"
            ))
            .is_empty(),
        );

        // A missing arm is a defect, not a silent pass — and it must reach this
        // verdict from the production half alone, not by finding these fixtures.
        assert_eq!(scoped_arm_defects("nothing here"), vec!["arm not found"]);
        assert_eq!(
            scoped_arm_defects("nothing here\n#[cfg(test)]\ninline_scoped $vis:vis struct X;"),
            vec!["arm not found"],
        );

        // Only now, the real file.
        assert!(
            scoped_arm_defects(include_str!("secret_seed.rs")).is_empty(),
            "the inline_scoped arm lost its shape: {:?}",
            scoped_arm_defects(include_str!("secret_seed.rs")),
        );
    }

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
        assert_zeroize_on_drop::<TestScopedSecret>();

        // inline arm — identity-rooted secrets.
        assert_zeroize_on_drop::<crate::identity::keys::ShareRootIkm>();
        assert_zeroize_on_drop::<crate::identity::keys::DmDoorbellSlotSecret>();

        // inline_scoped arm — the one identity-rooted capability.
        assert_zeroize_on_drop::<crate::identity::keys::VeilidNodeSeed>();

        // inline arm — the DM ratchet key schedule.
        assert_zeroize_on_drop::<crate::dm::ratchet::RootKey>();
        assert_zeroize_on_drop::<crate::dm::ratchet::ChainKey>();
        assert_zeroize_on_drop::<crate::dm::ratchet::MessageKey>();

        // inline arm — the re-establishment root. Added with #314: it was the ONE
        // macro-generated newtype of twenty missing from this sweep, and its absence
        // was load-bearing rather than cosmetic. `CommittedRoot::from_bytes` is
        // `pub` and the type is dropped STANDALONE on `ResumeRecord::decode`'s error
        // paths and at `dm/persist.rs`'s construction site — so on those paths
        // nothing else wipes it. A hand-rolled replacement deriving only `Zeroize`
        // passed every test in the tree, including the behavioural witness, because
        // that witness only ever observes the root inside a `ResumeRecord` whose own
        // derive wipes it in place.
        assert_zeroize_on_drop::<crate::dm::resume::CommittedRoot>();

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

    /// The two secret-bearing structs the macro does not generate also carry
    /// `ZeroizeOnDrop` — now by derive rather than by a hand-written `Drop`
    /// (#267).
    ///
    /// Kept separate from the sweep above because it asserts a different thing.
    /// That one says every macro expansion still has the property. This one says
    /// two multi-field structs, which the macro cannot reach, are on the derive at
    /// all — and the derive is what makes a *newly added* secret field wiped by
    /// default instead of silently unwiped. Losing the derive would leave both
    /// types compiling and their existing secrets partly covered (`entropy` by
    /// `Zeroizing`, `ss0` and `body` by nothing), which is why the loss needs
    /// stating somewhere that fails.
    ///
    /// The bound is breadth only, exactly as above: it says the trait is there,
    /// not that any byte reaches zero. `tests/secret_zeroize_on_drop.rs` is the
    /// depth half for both types.
    #[test]
    #[allow(clippy::extra_unused_type_parameters)]
    fn the_multi_field_secret_structs_are_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<crate::storage::seeds::PersistedCircle>();
        assert_zeroize_on_drop::<crate::dm::firstcontact::VerifiedFirstContact>();
    }

    /// Every arm renders a redacted `Debug`.
    ///
    /// Exact-string equality, not a `contains("<redacted>")` check: a `Debug` that
    /// printed `Name { inner: <redacted>, bytes: [..] }` would pass a substring
    /// test. The second half then pins the failure mode a derived `Debug` would
    /// actually produce — a tuple struct over `[u8; 32]` renders its bytes in
    /// decimal — so the assertion is tied to the leak, not only to the wording.
    #[test]
    fn every_arm_renders_a_redacted_debug() {
        let inline = TestInlineSecret([FILL; 32]);
        let boxed = TestBoxedSecret(Box::new([FILL; 32]));
        let scoped = TestScopedSecret([FILL; 32]);

        let inline_dbg = format!("{inline:?}");
        let boxed_dbg = format!("{boxed:?}");
        let scoped_dbg = format!("{scoped:?}");

        assert_eq!(inline_dbg, "TestInlineSecret(<redacted>)");
        assert_eq!(boxed_dbg, "TestBoxedSecret(<redacted>)");
        assert_eq!(scoped_dbg, "TestScopedSecret(<redacted>)");

        for rendered in [&inline_dbg, &boxed_dbg, &scoped_dbg] {
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

    /// Each arm has exactly one accessor and it hands back the stored secret
    /// unchanged — the property the zeroize tests above depend on to locate the
    /// bytes at all. `boxed` and `inline` expose `as_bytes`; `inline_scoped`
    /// exposes `with_bytes` and nothing else.
    #[test]
    fn every_arm_exposes_its_bytes_through_its_one_accessor() {
        assert_eq!(TestInlineSecret([FILL; 32]).as_bytes(), &[FILL; 32]);
        assert_eq!(
            TestBoxedSecret(Box::new([FILL; 32])).as_bytes(),
            &[FILL; 32]
        );
        assert_eq!(TestScopedSecret([FILL; 32]).with_bytes(|b| *b), [FILL; 32]);
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
