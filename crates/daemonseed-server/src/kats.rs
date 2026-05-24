//! CNSA 2.0 KATS slice for production module initialization.
//!
//! `oxitls_rustls_provider::cnsa_2_0_hybrid_provider` requires
//! `oxicrypt-module` to be in the `Operational` state. The caller drives
//! that with `oxicrypt_module::initialize_with_profile(&kats,
//! AlgorithmProfile::Cnsa2)`, passing a slice that union-covers every
//! module-gated primitive the provider touches.
//!
//! For the CNSA 2.0 transitional provider, the gated primitives are:
//!
//! - **SHA** — used by HMAC, KDF, transcript hashing, and the
//!   server-id derivation in [`crate::identity::derive_server_id`].
//! - **HMAC** — record-protection KDF salt path (HKDF inside oxicrypt-kdf).
//! - **AES** — `TLS_AES_256_GCM_SHA384` record protection.
//! - **KDF** — HKDF-SHA-384 expand/extract for TLS 1.3 key schedule.
//! - **DRBG** — random source for ECDH/ML-KEM keygen + ML-DSA nonce path.
//! - **ECDH** — SecP384r1 half of the hybrid key exchange.
//! - **ML-KEM** — ML-KEM-1024 post-quantum half of the hybrid kx.
//! - **ML-DSA** — ML-DSA-87 server identity + handshake signature.
//!
//! Listing the union here (rather than pulling each crate's KATS at the
//! call site in `main()`) keeps the production init shape in one place
//! and makes the "did we forget a primitive" check a single-file
//! review. The slice is `pub const` so callers consume it without an
//! extra allocation.
//!
//! Tests use the lighter-weight `oxitls_rustls_provider::testing::
//! ensure_module_operational()` shim (DRBG-only KATs) — production
//! must use this full slice because the module init is one-shot per
//! process.

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
