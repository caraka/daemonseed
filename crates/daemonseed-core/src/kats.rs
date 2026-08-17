//! CNSA 2.0 KATS slice for production module initialization.
//!
//! Every module-gated oxicrypt primitive requires `oxicrypt-module` to be
//! in the `Operational` state before it can be called. Each front-end
//! drives that at startup with
//! `oxicrypt_module::initialize_with_profile(&kats,
//! AlgorithmProfile::Cnsa2)`, passing a slice that union-covers every
//! gated primitive daemonseed touches.
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
/// provider exercises. Pass to
/// `oxicrypt_module::initialize_with_profile(&kats,
/// AlgorithmProfile::Cnsa2)` exactly once per process at boot.
///
/// **Order is not significant** — `initialize_with_profile` runs each
/// KAT in turn; any failure latches the module into the error state.
/// We list the primitives in roughly call-order for human readability.
pub const CNSA_2_0_KATS: &[KatEntry] = &concat_kats();

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
