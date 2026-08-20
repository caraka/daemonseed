//! CNSA 2.0 KATS slice for production module initialization.
//!
//! Every module-gated oxicrypt primitive requires `oxicrypt-module` to be
//! in the `Operational` state before it can be called. Each front-end
//! drives that at startup through [`initialize_module`], which pairs the
//! pre-operational integrity inventory with a slice that union-covers
//! every gated primitive daemonseed touches.
//!
//! The gated primitives are:
//!
//! - **SHA** — SHA-384 for content addressing, transcript hashing, HMAC
//!   and KDF.
//! - **HMAC** — the HKDF salt path inside oxicrypt-kdf.
//! - **AES** — AES-256-GCM AEAD sealing for shares, envelopes and DMs.
//! - **KDF** — HKDF-SHA-384 expand/extract for the derivation root.
//! - **DRBG** — random source for ML-KEM keygen and the ML-DSA nonce path.
//! - **ECDH** — SecP384r1. **No longer reached by any daemonseed call
//!   path**: it was the classical half of the TLS 1.3 hybrid key
//!   exchange, retired with the TLS stack. Its KATs stay in the slice
//!   because dropping a primitive from module init changes what the
//!   power-up self-test covers, which is a crypto-boundary decision that
//!   belongs in its own reviewed change rather than riding along with a
//!   dependency removal.
//! - **ML-KEM** — ML-KEM-1024 for DM key establishment.
//! - **ML-DSA** — ML-DSA-87 identity and provenance signatures.
//!
//! Listing the union here (rather than pulling each crate's KATS at the
//! call site in `main()`) keeps the production init shape in one place
//! and makes the "did we forget a primitive" check a single-file
//! review. The slice is `pub const` so callers consume it without an
//! extra allocation.
//!
//! Module init is one-shot per process, so production must use this
//! full slice rather than a narrower per-test one.

use oxicrypt_module::KatEntry;

/// Concatenated KATs for every primitive the CNSA 2.0 transitional
/// provider exercises. Reached through [`initialize_module`], which is
/// what callers use; this constant is the approved-algorithm half of the
/// pair that function passes.
///
/// **Order is not significant within this slice** — each KAT runs in
/// turn and any failure latches the module into the error state. We list
/// the primitives in roughly call-order for human readability. Order
/// *between* the two inventories is significant, and
/// [`initialize_module`] is where it is fixed.
pub const CNSA_2_0_KATS: &[KatEntry] = &concat_kats();

/// Bring the oxicrypt module to `Operational` under the CNSA 2.0 profile.
///
/// **The one place daemonseed initializes the module**, called by every front
/// end at boot and by every test that touches a module-gated primitive.
///
/// **Idempotent, and it has to be made so rather than being so.** Module init is
/// one-shot per process: the second caller loses the compare-and-swap and gets
/// `Error::AlreadyInitialized` back, never `Ok`. That is the right contract
/// upstream — it distinguishes "you initialized" from "someone else did" — but it
/// is the wrong one here, where the call is spread across front-end startup paths
/// and hundreds of tests that each have to work whether or not they ran first.
/// So the already-initialized case is mapped to `Ok` at this seam, exactly as
/// oxicrypt's own integration guidance does, and a caller may invoke this
/// unconditionally. Every other error is passed through untouched.
///
/// Both inventories are required and they are not interchangeable.
/// [`oxicrypt_integrity::KATS`] is the **pre-operational software integrity
/// test** — the technique's own CAST followed by the HMAC-SHA-256 check over
/// the module image, run in that order (ISO/IEC 19790:2012 §7.10.2.2). A module
/// initialized with an empty integrity group latches `IntegrityUnverified` and
/// never becomes `Operational`, so passing it is what makes every later call
/// work, not a formality. [`CNSA_2_0_KATS`] is the approved-algorithm inventory
/// that runs after the image is verified.
///
/// Callers do not assemble that pair themselves — one function is one place to
/// be right about which inventories go in and in which order.
///
/// **The artifact calling this must be signed** — `oxicrypt-integrity-sign
/// --sign <artifact>`, as the last step of the build, after anything that
/// rewrites the file. An unsigned binary fails the image check and never
/// reaches `Operational`. Test binaries are never signed and use
/// `initialize_module_unsigned_test_binary` instead. That name is plain text
/// rather than a link on purpose: the item is behind the `testing` feature, so
/// the default `cargo doc` cannot resolve a link to it, and making it reachable
/// to satisfy one would undo the gating.
pub fn initialize_module() -> Result<(), oxicrypt_module::Error> {
    already_initialized_is_ok(oxicrypt_module::initialize_with_profile(
        oxicrypt_integrity::KATS,
        CNSA_2_0_KATS,
        oxicrypt_module::AlgorithmProfile::Cnsa2,
    ))
}

/// Map `AlreadyInitialized` to success, and nothing else.
///
/// One home for the mapping so the two entry points cannot drift into treating a
/// second call differently, and so the set of swallowed errors is a single line a
/// reviewer can check. It is deliberately not `is_err()`-shaped: a
/// `SelfTestFailed` or an `IntegrityUnverified` must still reach the caller,
/// because those mean the module is in a terminal state and no cryptographic
/// call will work.
fn already_initialized_is_ok(
    result: Result<(), oxicrypt_module::Error>,
) -> Result<(), oxicrypt_module::Error> {
    match result {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Bring the module `Operational` inside a `cargo test` binary, which cannot
/// satisfy the real image check.
///
/// A test binary is never signed, so [`oxicrypt_integrity::KATS`]'s image test
/// cannot pass inside one — and the module offers no skip flag, deliberately,
/// because a skip flag is the thing that eventually ships enabled. The
/// documented pattern is to hand it a stub group that stands in the integrity
/// slot's place, which is what this function's `UNSIGNED_TEST_BINARY` is.
///
/// **Gated behind the `testing` feature rather than kept out by convention.**
/// oxicrypt's own guidance is to write the stub inline at each call site, on the
/// grounds that the verbosity is what keeps it out of production. Across a
/// corpus this size that trade inverts: the copies drift, and one of them
/// eventually reads as production code. A feature gate makes naming this from a
/// library or binary path a compile error instead of a review question.
///
/// **The precise guarantee, because the loose version is false.** The feature is
/// switched on only through a dev-dependency edge, and the release command —
/// `cargo zigbuild --release --locked -p <crate>` — carries none, so no shipped
/// artifact links a `testing`-enabled core. It is *not* true that the feature is
/// off in every build: `--all-targets` enables it for a crate's bin target as
/// well, which is why the claim is scoped to the build that ships rather than
/// stated as an absolute.
///
/// The algorithm inventory is the full production [`CNSA_2_0_KATS`]: module
/// init is one-shot per process, so a narrower per-test slice would leave
/// whichever primitive a later test in the same binary reaches ungated.
#[cfg(feature = "testing")]
pub fn initialize_module_unsigned_test_binary() -> Result<(), oxicrypt_module::Error> {
    /// Stands where the pre-operational image test would be in a signed
    /// artifact. Returns `Ok` because there is nothing here it could truthfully
    /// check — the name is what carries the meaning to a reader of the failure
    /// output.
    const UNSIGNED_TEST_BINARY: &[KatEntry] = &[KatEntry {
        name: "integrity not verifiable in an unsigned test binary",
        run: || Ok(()),
    }];

    already_initialized_is_ok(oxicrypt_module::initialize_with_profile(
        UNSIGNED_TEST_BINARY,
        CNSA_2_0_KATS,
        oxicrypt_module::AlgorithmProfile::Cnsa2,
    ))
}

const fn concat_kats() -> [KatEntry; LEN] {
    // Placeholder entry — overwritten in the loops below. `run` returns
    // `Ok` and `name` is empty so even if the slice were used unmodified
    // (it isn't — the loop fully populates) the module-init step would
    // pass without latching the error state. The real entries come from
    // each primitive crate's `KATS` constant.
    let mut out: [KatEntry; LEN] = [KatEntry {
        name: "",
        run: || Ok(()),
    }; LEN];
    let mut i = 0;

    let mut j = 0;
    while j < oxicrypt_sha::KATS.len() {
        out[i] = oxicrypt_sha::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_hmac::KATS.len() {
        out[i] = oxicrypt_hmac::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_aes::KATS.len() {
        out[i] = oxicrypt_aes::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_kdf::KATS.len() {
        out[i] = oxicrypt_kdf::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_drbg::KATS.len() {
        out[i] = oxicrypt_drbg::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_ecdh::KATS.len() {
        out[i] = oxicrypt_ecdh::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_ml_kem::KATS.len() {
        out[i] = oxicrypt_ml_kem::KATS[j];
        i += 1;
        j += 1;
    }
    let mut j = 0;
    while j < oxicrypt_ml_dsa::KATS.len() {
        out[i] = oxicrypt_ml_dsa::KATS[j];
        i += 1;
        j += 1;
    }

    // Every slot was written. This is a `const fn`, so a deleted or short-bounded
    // copy-loop is a build failure — on every build including release, with no
    // test run — rather than a slice with placeholder tails that
    // `initialize_with_profile` counts as passing self-tests (#305). The overrun
    // direction is already a const-eval bounds error, so the two together make the
    // whole under/over-fill class unrepresentable rather than merely tested.
    assert!(i == LEN);

    out
}

const LEN: usize = oxicrypt_sha::KATS.len()
    + oxicrypt_hmac::KATS.len()
    + oxicrypt_aes::KATS.len()
    + oxicrypt_kdf::KATS.len()
    + oxicrypt_drbg::KATS.len()
    + oxicrypt_ecdh::KATS.len()
    + oxicrypt_ml_kem::KATS.len()
    + oxicrypt_ml_dsa::KATS.len();

#[cfg(test)]
mod tests {
    use super::*;

    /// Calling an entry point twice succeeds twice.
    ///
    /// The mapping in `already_initialized_is_ok` is the whole subject: without
    /// it the second call returns `Error::AlreadyInitialized`, because module
    /// init is one-shot per process and the compare-and-swap loser is told so.
    /// Delete that arm and this test fails on its second assertion, which is
    /// what makes it a probe rather than a restatement.
    ///
    /// Order-independent by construction, which matters because this binary
    /// runs hundreds of tests that each initialize: whether this test is the
    /// one that actually performed the initialization or the thousandth to ask
    /// for it, both calls below must read `Ok`.
    #[test]
    fn initializing_twice_is_ok() {
        assert!(
            initialize_module_unsigned_test_binary().is_ok(),
            "first initialization failed"
        );
        assert!(
            initialize_module_unsigned_test_binary().is_ok(),
            "second initialization returned an error — the AlreadyInitialized \
             arm is missing, and every unconditional caller is now a panic"
        );
    }

    #[test]
    fn cnsa_2_0_kats_is_non_empty() {
        assert!(
            !CNSA_2_0_KATS.is_empty(),
            "production KATS slice must cover at least one primitive"
        );
    }

    /// The published slice covers the whole array.
    ///
    /// **Not the tautology this replaced, and the difference is the `&`.** The
    /// removed `cnsa_2_0_kats_length_matches_constituents` compared
    /// `CNSA_2_0_KATS.len()` against a re-derivation of `LEN`, which is the array's
    /// own length — the same expression twice, w.r.t. [`concat_kats`]. But
    /// `CNSA_2_0_KATS` is a `&[KatEntry]` *view*, and a view can be narrower than
    /// what it views. Publish `FULL.split_last().unwrap().1` and the slice silently
    /// loses its last entry — ML-DSA-87, the identity and provenance signature —
    /// while every population check below still passes. That class is real and this
    /// is the only test that sees it.
    #[test]
    fn the_published_slice_covers_the_whole_array() {
        assert_eq!(
            CNSA_2_0_KATS.len(),
            LEN,
            "the published view is narrower than the array it views, so {} \
             self-test(s) never run at power-up",
            LEN - CNSA_2_0_KATS.len()
        );
    }

    /// Every upstream KAT reaches the slice — all of them, not one per crate.
    ///
    /// Checking a single entry per source leaves a loop that reads a fixed index
    /// invisible: `out[i] = oxicrypt_aes::KATS[0]` copies entry zero twenty-three
    /// times, so the count is `LEN`, no placeholder survives, the crate is
    /// "represented" — and twenty-two AES KATs including AES-256-GCM, the AEAD used
    /// for share, envelope and DM sealing, never run. Requiring every name closes
    /// that, and subsumes the placeholder scan and the one-per-crate check it
    /// replaces: a missing loop, an off-by-one bound, a stalled index and a
    /// wrong-crate copy all drop at least one name.
    ///
    /// [`concat_kats`]'s `assert!(i == LEN)` makes the under-fill class a build
    /// failure, so this test's remaining job is the shapes that fill every slot
    /// with the wrong thing.
    #[test]
    fn every_upstream_kat_reaches_the_slice() {
        let sources: [(&str, &[KatEntry]); 8] = [
            ("sha", oxicrypt_sha::KATS),
            ("hmac", oxicrypt_hmac::KATS),
            ("aes", oxicrypt_aes::KATS),
            ("kdf", oxicrypt_kdf::KATS),
            ("drbg", oxicrypt_drbg::KATS),
            ("ecdh", oxicrypt_ecdh::KATS),
            ("ml-kem", oxicrypt_ml_kem::KATS),
            ("ml-dsa", oxicrypt_ml_dsa::KATS),
        ];

        // The list above duplicates knowledge `concat_kats` and `LEN` already hold,
        // and nothing links the three. Tying its total to `LEN` is that link: add a
        // ninth crate to the loops and to `LEN` but not here, and this fails rather
        // than silently leaving the new primitive unverified.
        let counted: usize = sources.iter().map(|(_, k)| k.len()).sum();
        assert_eq!(
            counted, LEN,
            "the sources list totals {counted} against LEN {LEN}, so it has drifted \
             from concat_kats and the coverage check below is incomplete"
        );

        for (crate_name, kats) in sources {
            assert!(
                !kats.is_empty(),
                "{crate_name} publishes no KATs at all, so its coverage check is \
                 unreachable rather than satisfied"
            );
            for want in kats {
                assert!(
                    CNSA_2_0_KATS.iter().any(|e| e.name == want.name),
                    "{crate_name}'s KAT {:?} never reached CNSA_2_0_KATS, so that \
                     primitive is not fully covered by the power-up self-test",
                    want.name
                );
            }
        }
    }
}
