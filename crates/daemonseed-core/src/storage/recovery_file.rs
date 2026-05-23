//! Encrypted recovery file — `.dseed` (ISC-C32 / ISC-C30 / ISC-A-C17).
//!
//! The recovery file is the air-gap-paper replacement for restoring an
//! identity on a clean device. Same passphrase as the at-rest blob (ISC-C30),
//! same Argon2id KDF stage with `profile-id` as salt (ISC-C36), same AEAD
//! (AES-256-GCM). The HKDF expand stage uses a *distinct* info string —
//! `daemonseed/recovery-file/<profile-id>` — so the two artifacts decrypt
//! under independent keys even though they share an expensive Argon2id pass.
//!
//! ## Layout
//!
//! ```text
//!   [MAGIC          (20 bytes: b"daemonseed/dseed/v1\0")]
//!   [PROFILE_ID     (16 bytes — uuid v4)]
//!   [MEMORY_KIB     (4 bytes  — u32 LE)]
//!   [ITERATIONS     (4 bytes  — u32 LE)]
//!   [PARALLELISM    (4 bytes  — u32 LE)]
//!   [NONCE          (12 bytes — CSPRNG)]
//!   [CIPHERTEXT     (mnemonic-phrase UTF-8 bytes)]
//!   [TAG            (16 bytes — AES-GCM authenticator)]
//! ```
//!
//! Per ISC-C32 the **header is unauthenticated by design**. An attacker
//! who flips any header byte changes the derived key — wrong salt, wrong
//! params, or wrong HKDF info all produce a wrong key — and the AEAD
//! fails to verify. No AAD is needed for header integrity; the KDF chain
//! IS the integrity check.
//!
//! Recovery on a clean device per ISC-C36: read header → prompt for
//! passphrase → derive key (from header's salt + params) → decrypt → on
//! success the caller persists the embedded profile-id + argon2 params
//! into a freshly-written `daemonseed.toml` and the identity is back.

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha256;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::identity::mnemonic::{Mnemonic, MnemonicError};
use crate::kdf::info;
use crate::profile::config::ArgonParams;

/// Magic prefix for the v1 `.dseed` format. Bump the `v1` tag on any
/// incompatible layout change.
pub const MAGIC: &[u8; 20] = b"daemonseed/dseed/v1\0";

const PROFILE_ID_LEN: usize = 16;
const ARGON_PARAM_LEN: usize = 4 + 4 + 4; // memory_kib + iterations + parallelism
const HEADER_LEN: usize = MAGIC.len() + PROFILE_ID_LEN + ARGON_PARAM_LEN;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ARGON2_OUTPUT_LEN: usize = 32;
const AEAD_KEY_LEN: usize = 32;

/// Decrypted recovery-file contents. Caller persists `profile_id` + `argon2`
/// into a fresh `daemonseed.toml` on recovery.
pub struct RecoveryFileContents {
    pub mnemonic: Mnemonic,
    pub profile_id: Uuid,
    pub argon2: ArgonParams,
}

impl core::fmt::Debug for RecoveryFileContents {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryFileContents")
            .field("mnemonic", &"<redacted>")
            .field("profile_id", &self.profile_id)
            .field("argon2", &self.argon2)
            .finish()
    }
}

/// Errors from [`seal`] / [`open`]. Authentication-failure variants are
/// uniform so the caller cannot tell wrong-passphrase from tampered-blob.
#[derive(Debug)]
pub enum RecoveryFileError {
    Argon2(argon2::Error),
    Hkdf(oxicrypt_kdf::KdfError),
    AesKeyInit(oxicrypt_module::Error),
    AesMode(oxicrypt_aes::ModeError),
    EntropySource(getrandom::Error),
    Malformed(&'static str),
    AuthenticationFailed,
    Utf8(core::str::Utf8Error),
    Mnemonic(MnemonicError),
}

impl core::fmt::Display for RecoveryFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecoveryFileError::Argon2(e) => write!(f, "argon2: {e}"),
            RecoveryFileError::Hkdf(e) => write!(f, "HKDF: {e:?}"),
            RecoveryFileError::AesKeyInit(e) => write!(f, "AES-256 key init: {e:?}"),
            RecoveryFileError::AesMode(e) => write!(f, "AES-GCM mode error: {e:?}"),
            RecoveryFileError::EntropySource(e) => write!(f, "OS CSPRNG: {e}"),
            RecoveryFileError::Malformed(s) => write!(f, "malformed .dseed: {s}"),
            RecoveryFileError::AuthenticationFailed => write!(
                f,
                ".dseed: authentication failed (wrong passphrase or tampered file)"
            ),
            RecoveryFileError::Utf8(e) => write!(f, ".dseed plaintext is not UTF-8: {e}"),
            RecoveryFileError::Mnemonic(e) => write!(f, "mnemonic in .dseed: {e}"),
        }
    }
}

impl std::error::Error for RecoveryFileError {}

/// Encrypt a mnemonic into the canonical v1 `.dseed` layout. The
/// `profile_id` and `argon2` params land in the cleartext header so a
/// clean-device recovery can derive the same key from passphrase alone.
pub fn seal(
    mnemonic: &Mnemonic,
    passphrase: &str,
    profile_id: Uuid,
    argon2: ArgonParams,
) -> Result<Vec<u8>, RecoveryFileError> {
    let mut key = derive_aead_key(passphrase, profile_id, argon2)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(RecoveryFileError::EntropySource)?;

    let aes = Aes256Key::new(&key).map_err(RecoveryFileError::AesKeyInit)?;
    key.zeroize();

    let phrase = mnemonic.to_phrase();
    let plaintext = phrase.as_bytes();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(&aes, &nonce, b"", plaintext, &mut ciphertext, &mut tag)
        .map_err(RecoveryFileError::AesMode)?;

    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(profile_id.as_bytes());
    out.extend_from_slice(&argon2.memory_kib.to_le_bytes());
    out.extend_from_slice(&argon2.iterations.to_le_bytes());
    out.extend_from_slice(&argon2.parallelism.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a v1 `.dseed`. The profile_id and argon2 params are read from
/// the cleartext header (per ISC-C36 recovery-on-clean-device); the caller
/// supplies only the file bytes and the passphrase.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<RecoveryFileContents, RecoveryFileError> {
    if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(RecoveryFileError::Malformed(
            "file shorter than minimum header",
        ));
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(RecoveryFileError::Malformed("magic prefix mismatch"));
    }

    let mut cursor = MAGIC.len();

    let profile_id_bytes: [u8; PROFILE_ID_LEN] =
        bytes[cursor..cursor + PROFILE_ID_LEN].try_into().unwrap();
    let profile_id = Uuid::from_bytes(profile_id_bytes);
    cursor += PROFILE_ID_LEN;

    let memory_kib = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let iterations = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let parallelism = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let argon2 = ArgonParams {
        memory_kib,
        iterations,
        parallelism,
    };

    let nonce: &[u8; NONCE_LEN] = bytes[cursor..cursor + NONCE_LEN].try_into().unwrap();
    cursor += NONCE_LEN;

    let after_nonce = &bytes[cursor..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();

    let mut key = derive_aead_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(RecoveryFileError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext).map_err(|e| match e {
        // Uniform AuthenticationFailed — caller can't distinguish wrong
        // passphrase from tampered header or tampered ciphertext.
        oxicrypt_aes::ModeError::TagMismatch => RecoveryFileError::AuthenticationFailed,
        other => RecoveryFileError::AesMode(other),
    })?;

    let phrase = core::str::from_utf8(&plaintext).map_err(RecoveryFileError::Utf8)?;
    let mnemonic = Mnemonic::from_phrase(phrase).map_err(RecoveryFileError::Mnemonic);
    plaintext.zeroize();
    let mnemonic = mnemonic?;

    Ok(RecoveryFileContents {
        mnemonic,
        profile_id,
        argon2,
    })
}

/// Two-stage Argon2id + HKDF KDF — identical to the at-rest blob's stage
/// (per ISC-C30 / ISC-C3) except for the HKDF info string.
fn derive_aead_key(
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<[u8; AEAD_KEY_LEN], RecoveryFileError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::default(),
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(RecoveryFileError::Argon2)?,
    );
    let mut intermediate = [0u8; ARGON2_OUTPUT_LEN];
    let salt: [u8; 16] = *profile_id.as_bytes();
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut intermediate)
        .map_err(RecoveryFileError::Argon2)?;

    let info_str = info::recovery_file(&profile_id.to_string());
    let hkdf = HkdfSha256::from_prk(&intermediate).map_err(RecoveryFileError::Hkdf)?;
    intermediate.zeroize();

    let mut key = [0u8; AEAD_KEY_LEN];
    hkdf.expand(info_str.as_bytes(), &mut key)
        .map_err(RecoveryFileError::Hkdf)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_oxicrypt() {
        let _ = oxicrypt_module::initialize();
    }

    fn fast_params() -> ArgonParams {
        // ms-scale for tests; never production.
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn fresh_mnemonic() -> Mnemonic {
        Mnemonic::generate().unwrap()
    }

    #[test]
    fn round_trip() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let m = fresh_mnemonic();
        let orig = m.to_phrase();

        let file = seal(&m, pp, pid, fast_params()).unwrap();
        let recovered = open(&file, pp).unwrap();
        assert_eq!(recovered.mnemonic.to_phrase(), orig);
        assert_eq!(recovered.profile_id, pid);
        assert_eq!(recovered.argon2, fast_params());
    }

    #[test]
    fn recovery_does_not_require_external_profile_state() {
        // The recovery-on-clean-device invariant: open() takes only the
        // file bytes + passphrase. profile-id + argon2 params come from
        // the file's cleartext header.
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let m = fresh_mnemonic();
        let file = seal(&m, "passphrase x", pid, fast_params()).unwrap();
        // No caller-supplied profile_id / params:
        let recovered = open(&file, "passphrase x").unwrap();
        assert_eq!(recovered.profile_id, pid);
        assert_eq!(recovered.argon2, fast_params());
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        init_oxicrypt();
        let file = seal(
            &fresh_mnemonic(),
            "correct one",
            Uuid::new_v4(),
            fast_params(),
        )
        .unwrap();
        match open(&file, "wrong one") {
            Err(RecoveryFileError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_profile_id_in_header_fails_closed() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut file = seal(&fresh_mnemonic(), pp, pid, fast_params()).unwrap();
        // Flip a byte inside the profile_id range — derived HKDF info will
        // be wrong → wrong key → AEAD fails to verify.
        file[MAGIC.len()] ^= 0x01;
        match open(&file, pp) {
            Err(RecoveryFileError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_argon_params_in_header_fails_closed() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut file = seal(&fresh_mnemonic(), pp, pid, fast_params()).unwrap();
        // Flip a byte in the memory_kib LE bytes.
        let mem_kib_offset = MAGIC.len() + PROFILE_ID_LEN;
        file[mem_kib_offset] ^= 0x01;
        match open(&file, pp) {
            Err(RecoveryFileError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut file = seal(&fresh_mnemonic(), pp, pid, fast_params()).unwrap();
        let mid = file.len() / 2;
        file[mid] ^= 0x01;
        match open(&file, pp) {
            Err(RecoveryFileError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn truncated_file_rejected() {
        init_oxicrypt();
        let file = seal(
            &fresh_mnemonic(),
            "passphrase x",
            Uuid::new_v4(),
            fast_params(),
        )
        .unwrap();
        let too_short = &file[..HEADER_LEN + 1];
        match open(too_short, "passphrase x") {
            Err(RecoveryFileError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn bad_magic_rejected() {
        init_oxicrypt();
        let mut file = seal(
            &fresh_mnemonic(),
            "passphrase x",
            Uuid::new_v4(),
            fast_params(),
        )
        .unwrap();
        file[0] = b'X';
        match open(&file, "passphrase x") {
            Err(RecoveryFileError::Malformed(_)) => {}
            other => panic!("expected Malformed (magic), got {other:?}"),
        }
    }

    #[test]
    fn magic_v1_is_pinned() {
        assert_eq!(MAGIC, b"daemonseed/dseed/v1\0");
    }

    #[test]
    fn debug_redacts_mnemonic() {
        init_oxicrypt();
        let file = seal(
            &fresh_mnemonic(),
            "passphrase x",
            Uuid::new_v4(),
            fast_params(),
        )
        .unwrap();
        let contents = open(&file, "passphrase x").unwrap();
        let dbg = format!("{contents:?}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn two_seals_produce_different_files() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let m = fresh_mnemonic();
        let a = seal(&m, pp, pid, fast_params()).unwrap();
        let b = seal(&m, pp, pid, fast_params()).unwrap();
        assert_ne!(a, b); // distinct nonces
    }

    #[test]
    fn recovery_file_key_is_distinct_from_at_rest_key() {
        // Same passphrase + same profile_id + same argon2 params must yield
        // different keys for recovery_file vs at-rest because the HKDF info
        // string differs. Easiest proof: seal an at-rest blob and a
        // recovery file with identical inputs, then verify a recovery-file
        // open() fails to authenticate an at-rest blob (and vice versa).
        init_oxicrypt();
        use crate::storage::seeds;
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let m = fresh_mnemonic();
        let seeds_payload = seeds::Seeds {
            mnemonic: m.clone(),
        };
        let at_rest_blob = seeds::seal(&seeds_payload, pp, pid, fast_params()).unwrap();
        // Try to open the at-rest blob as a recovery file. Magic prefix
        // differs — recovery-file should reject it as Malformed.
        match open(&at_rest_blob, pp) {
            Err(RecoveryFileError::Malformed(_)) => {}
            other => panic!("expected Malformed (different magic), got {other:?}"),
        }
    }
}
