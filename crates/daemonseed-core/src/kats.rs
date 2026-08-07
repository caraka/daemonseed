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

    #[test]
    fn cnsa_2_0_kats_length_matches_constituents() {
        let expected = oxicrypt_sha::KATS.len()
            + oxicrypt_hmac::KATS.len()
            + oxicrypt_aes::KATS.len()
            + oxicrypt_kdf::KATS.len()
            + oxicrypt_drbg::KATS.len()
            + oxicrypt_ecdh::KATS.len()
            + oxicrypt_ml_kem::KATS.len()
            + oxicrypt_ml_dsa::KATS.len();
        assert_eq!(CNSA_2_0_KATS.len(), expected);
    }
}
