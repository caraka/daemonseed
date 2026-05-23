//! Encrypted at-rest seeds blob (ISC-C3).
//!
//! Layout:
//! ```text
//!   [MAGIC (19 bytes: b"daemonseed/blob/v1\0")]
//!   [NONCE (12 bytes — CSPRNG-generated)]
//!   [CIPHERTEXT (plaintext_len bytes)]
//!   [TAG (16 bytes — AES-GCM authenticator)]
//! ```
//!
//! KDF chain per ISC-C3 (the "daemonseed two-stage passphrase KDF"):
//! ```text
//!   intermediate = Argon2id(
//!       passphrase = utf8(passphrase),
//!       salt       = profile_id (16-byte UUID),
//!       params     = persisted [argon2] table (ISC-C14),
//!       length     = 32,
//!   )
//!   aead_key     = HKDF-SHA256-Expand(
//!       prk  = intermediate,
//!       info = "daemonseed/at-rest/<profile-id>",
//!       length = 32,
//!   )
//!   ciphertext, tag = AES-256-GCM-seal(aead_key, nonce, plaintext, aad="")
//! ```
//!
//! The plaintext at M1 is the BIP-39 phrase UTF-8 bytes; M2+ extends the
//! [`Seeds`] type with additional fields and the plaintext gains a
//! length-prefixed structure. The MAGIC's `/v1\0` tag is the migration
//! anchor — bumping it allows incompatible format changes without
//! silently corrupting decryption.

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha256;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::identity::mnemonic::{Mnemonic, MnemonicError};
use crate::kdf::info;
use crate::profile::config::ArgonParams;

/// Magic prefix for the v1 blob format. Bump the `v1` tag on any
/// incompatible layout change.
pub const MAGIC: &[u8; 19] = b"daemonseed/blob/v1\0";

/// AES-256-GCM nonce length (per NIST SP 800-38D §8.2.1).
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM tag length (per NIST SP 800-38D §5.2.1.2).
pub const TAG_LEN: usize = 16;

/// Argon2id intermediate output length (= AEAD key length = HKDF PRK len).
pub const ARGON2_OUTPUT_LEN: usize = 32;

/// AEAD key length (AES-256 → 32 bytes).
pub const AEAD_KEY_LEN: usize = 32;

/// Plaintext payload of the at-rest blob. M1 carries only the mnemonic;
/// M2+ extends this struct with circle-of-trust seed material, mute/hide
/// lists, and settings.
pub struct Seeds {
    pub mnemonic: Mnemonic,
}

impl core::fmt::Debug for Seeds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Seeds")
            .field("mnemonic", &"<redacted>")
            .finish()
    }
}

impl Seeds {
    fn to_plaintext(&self) -> String {
        self.mnemonic.to_phrase()
    }

    fn from_plaintext(s: &str) -> Result<Self, BlobError> {
        Mnemonic::from_phrase(s)
            .map(|mnemonic| Self { mnemonic })
            .map_err(BlobError::Mnemonic)
    }
}

/// Errors from [`seal`] / [`open`].
#[derive(Debug)]
pub enum BlobError {
    /// Argon2 KDF returned an error (bad params, etc.).
    Argon2(argon2::Error),
    /// HKDF expand or the underlying oxicrypt module gate failed.
    Hkdf(oxicrypt_kdf::KdfError),
    /// `oxicrypt-module`-gated AES key construction failed.
    AesKeyInit(oxicrypt_module::Error),
    /// AES-GCM encrypt / decrypt failed.
    AesMode(oxicrypt_aes::ModeError),
    /// Failed to fill nonce from OS CSPRNG.
    EntropySource(getrandom::Error),
    /// Blob is too short / missing magic / truncated layout.
    Malformed(&'static str),
    /// AEAD authenticator did not verify — wrong passphrase, tampered blob,
    /// or wrong KDF inputs (profile_id / argon2 params).
    AuthenticationFailed,
    /// Plaintext was decrypted but isn't a valid mnemonic (different blob
    /// version, corrupt content despite valid AEAD — should be impossible
    /// if MAGIC matches and AEAD passed; surfaced here for safety).
    InvalidPlaintext,
    /// Plaintext bytes weren't valid UTF-8 (paired with `InvalidPlaintext`
    /// in practice; kept distinct for diagnostics).
    Utf8(core::str::Utf8Error),
    /// Inner mnemonic-parse failure (unreachable in steady state but
    /// surfaced for diagnostics).
    Mnemonic(MnemonicError),
}

impl core::fmt::Display for BlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlobError::Argon2(e) => write!(f, "argon2: {e}"),
            BlobError::Hkdf(e) => write!(f, "HKDF: {e:?}"),
            BlobError::AesKeyInit(e) => write!(f, "AES-256 key init: {e:?}"),
            BlobError::AesMode(e) => write!(f, "AES-GCM mode error: {e:?}"),
            BlobError::EntropySource(e) => write!(f, "OS CSPRNG: {e}"),
            BlobError::Malformed(s) => write!(f, "malformed at-rest blob: {s}"),
            BlobError::AuthenticationFailed => {
                write!(
                    f,
                    "at-rest blob: authentication failed (wrong passphrase or tampered blob)"
                )
            }
            BlobError::InvalidPlaintext => write!(f, "at-rest blob: plaintext failed schema check"),
            BlobError::Utf8(e) => write!(f, "at-rest blob plaintext is not UTF-8: {e}"),
            BlobError::Mnemonic(e) => write!(f, "mnemonic in at-rest blob: {e}"),
        }
    }
}

impl std::error::Error for BlobError {}

/// Encrypt a [`Seeds`] payload into the canonical v1 blob layout.
pub fn seal(
    seeds: &Seeds,
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Vec<u8>, BlobError> {
    let mut key = derive_aead_key(passphrase, profile_id, params)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(BlobError::EntropySource)?;

    let aes = Aes256Key::new(&key).map_err(BlobError::AesKeyInit)?;
    key.zeroize();

    let plaintext_str = seeds.to_plaintext();
    let plaintext = plaintext_str.as_bytes();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(&aes, &nonce, b"", plaintext, &mut ciphertext, &mut tag)
        .map_err(BlobError::AesMode)?;

    let mut blob = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len() + TAG_LEN);
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&tag);
    Ok(blob)
}

/// Decrypt a v1 blob. Fails closed on wrong passphrase / tampered blob /
/// schema mismatch — no information leaks about which check failed.
pub fn open(
    blob: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Seeds, BlobError> {
    if blob.len() < MAGIC.len() + NONCE_LEN + TAG_LEN {
        return Err(BlobError::Malformed("blob shorter than minimum header+tag"));
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(BlobError::Malformed("magic prefix mismatch"));
    }

    let rest = &blob[MAGIC.len()..];
    let nonce: &[u8; NONCE_LEN] = rest[..NONCE_LEN].try_into().unwrap();
    let after_nonce = &rest[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();

    let mut key = derive_aead_key(passphrase, profile_id, params)?;
    let aes = Aes256Key::new(&key).map_err(BlobError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext).map_err(|e| match e {
        // Treat authentication failures as a single uniform error so the
        // caller can't distinguish "wrong passphrase" from "tampered blob".
        oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
        other => BlobError::AesMode(other),
    })?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let result = Seeds::from_plaintext(plaintext_str);
    plaintext.zeroize();
    result
}

/// Run the two-stage Argon2id + HKDF KDF and produce the 32-byte AEAD key.
fn derive_aead_key(
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<[u8; AEAD_KEY_LEN], BlobError> {
    // Stage 1: Argon2id (passphrase, salt=profile_id) → 32-byte intermediate.
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::default(),
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(BlobError::Argon2)?,
    );
    let mut intermediate = [0u8; ARGON2_OUTPUT_LEN];
    let salt: [u8; 16] = *profile_id.as_bytes();
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut intermediate)
        .map_err(BlobError::Argon2)?;

    // Stage 2: HKDF-Expand only (intermediate is already a high-entropy
    // 32-byte secret — no extract needed; that's what `from_prk` is for).
    let info_str = info::at_rest(&profile_id.to_string());
    let hkdf = HkdfSha256::from_prk(&intermediate).map_err(BlobError::Hkdf)?;
    intermediate.zeroize();

    let mut key = [0u8; AEAD_KEY_LEN];
    hkdf.expand(info_str.as_bytes(), &mut key)
        .map_err(BlobError::Hkdf)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_oxicrypt_initialized() {
        let _ = oxicrypt_module::initialize();
    }

    fn test_params() -> ArgonParams {
        // 8 KiB memory, t=1, p=1 — completes in single-digit ms so the test
        // suite doesn't bog. NEVER suitable for production deployment.
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn fresh_seeds() -> Seeds {
        Seeds {
            mnemonic: Mnemonic::generate().unwrap(),
        }
    }

    #[test]
    fn round_trip() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let original_phrase = seeds.mnemonic.to_phrase();

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap();
        assert_eq!(recovered.mnemonic.to_phrase(), original_phrase);
    }

    #[test]
    fn open_with_wrong_passphrase_fails_closed() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let blob = seal(
            &fresh_seeds(),
            "correct horse battery staple table mountain",
            pid,
            test_params(),
        )
        .unwrap();
        match open(
            &blob,
            "wrong horse battery staple table mountain",
            pid,
            test_params(),
        ) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_with_wrong_profile_id_fails_closed() {
        ensure_oxicrypt_initialized();
        let pid_a = Uuid::new_v4();
        let pid_b = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let blob = seal(&fresh_seeds(), pp, pid_a, test_params()).unwrap();
        match open(&blob, pp, pid_b, test_params()) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_with_wrong_argon_params_fails_closed() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        let different = ArgonParams {
            memory_kib: 16,
            iterations: 1,
            parallelism: 1,
        };
        match open(&blob, pp, pid, different) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_truncated_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let blob = seal(&fresh_seeds(), "passphrase x", pid, test_params()).unwrap();
        let truncated = &blob[..MAGIC.len() + NONCE_LEN + 1];
        match open(truncated, "passphrase x", pid, test_params()) {
            Err(BlobError::Malformed(_)) | Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected Malformed or AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_bad_magic() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        blob[0] = b'X'; // flip magic
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::Malformed(_)) => {}
            other => panic!("expected Malformed (magic), got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        // Flip a byte in the ciphertext (middle of the blob).
        let mid = blob.len() / 2;
        blob[mid] ^= 0x01;
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed on tamper, got {other:?}"),
        }
    }

    #[test]
    fn blob_magic_v1_is_pinned() {
        // Spec contract — bumping this is a format-incompatible change.
        assert_eq!(MAGIC, b"daemonseed/blob/v1\0");
    }

    #[test]
    fn debug_redacts_seeds() {
        let s = fresh_seeds();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn two_seals_of_same_seeds_produce_different_blobs() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let seeds = fresh_seeds();
        let a = seal(&seeds, pp, pid, test_params()).unwrap();
        let b = seal(&seeds, pp, pid, test_params()).unwrap();
        // Distinct nonces → distinct ciphertexts despite identical inputs.
        assert_ne!(a, b);
    }
}
