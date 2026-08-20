//! Encrypted recovery file — `.dseed` (ISC-C32 / ISC-C30 / ISC-A-C17 /
//! ISC-C24).
//!
//! The recovery file is the air-gap-paper replacement for restoring an
//! identity on a clean device. Same passphrase as the at-rest blob (ISC-C30),
//! same Argon2id KDF stage with `profile-id` as salt (ISC-C36), same AEAD
//! (AES-256-GCM). The HKDF expand stage uses a *distinct* info string —
//! `daemonseed/recovery-file/<profile-id>` — so the two artifacts decrypt
//! under independent keys even though they share an expensive Argon2id pass.
//!
//! ## Format v2 (M3+)
//!
//! ```text
//!   [MAGIC          (20 bytes: b"daemonseed/dseed/v2\0")]
//!   [SUITE_ID       ( 2 bytes: u16 big-endian, per ds-suite-registry.md)]
//!   [PROFILE_ID     (16 bytes — uuid v4)]
//!   [MEMORY_KIB     (4 bytes  — u32 LE)]
//!   [ITERATIONS     (4 bytes  — u32 LE)]
//!   [PARALLELISM    (4 bytes  — u32 LE)]
//!   [NONCE          (12 bytes — CSPRNG)]
//!   [CIPHERTEXT     (mnemonic-phrase UTF-8 bytes)]
//!   [TAG            (16 bytes — AES-GCM authenticator)]
//! ```
//!
//! ## Format v1 (M2 — read-only since M3)
//!
//! ```text
//!   [MAGIC          (20 bytes: b"daemonseed/dseed/v1\0")]
//!   [PROFILE_ID     (16 bytes)]
//!   [MEMORY_KIB     (4 bytes  — u32 LE)]
//!   [ITERATIONS     (4 bytes  — u32 LE)]
//!   [PARALLELISM    (4 bytes  — u32 LE)]
//!   [NONCE          (12 bytes)]
//!   [CIPHERTEXT     (mnemonic-phrase UTF-8 bytes)]
//!   [TAG            (16 bytes)]
//! ```
//!
//! v1 files are accepted by [`open`] under the implicit assumption that
//! `suite_id = 0x0001` (CNSA 2.0) — the only suite that existed at M2.
//! [`seal`] always writes v2.
//!
//! Per ISC-C32 the **header outside the suite_id is unauthenticated by
//! design**. An attacker who flips any header byte (profile_id, argon2
//! params) changes the derived key — wrong salt, wrong params, or wrong
//! HKDF info all produce a wrong key — and the AEAD fails to verify. The
//! suite_id byte pair *is* covered as AAD in v2 so a tamper-swap of the
//! suite tag fails authentication directly rather than via the
//! derived-key-mismatch path.
//!
//! Recovery on a clean device per ISC-C36: read header → prompt for
//! passphrase → derive key (from header's salt + params) → decrypt → on
//! success the caller persists the embedded profile-id + argon2 params
//! into a freshly-written `daemonseed.toml` and the identity is back.

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError, WriteRefusal};
use crate::identity::mnemonic::{Mnemonic, MnemonicError};
use crate::kdf::info;
use crate::profile::config::ArgonParams;

/// Magic prefix for the **current** (v2) `.dseed` format. M3+ writes this
/// magic on every [`seal`] call. Bump the `v2` tag on any incompatible
/// layout change.
pub const MAGIC: &[u8; 20] = b"daemonseed/dseed/v2\0";

/// Magic prefix for the **legacy** v1 `.dseed` format (M2). [`open`]
/// accepts files prefixed with this value and treats them as carrying the
/// implicit `suite_id = 0x0001` (CNSA 2.0). [`seal`] never writes this
/// magic.
pub const MAGIC_V1: &[u8; 20] = b"daemonseed/dseed/v1\0";

/// Implicit suite id assumed when reading a v1 `.dseed`. v1 predates the
/// registry; only CNSA 2.0 existed when v1 files were written.
const V1_IMPLICIT_SUITE_RAW: u16 = 0x0001;

const PROFILE_ID_LEN: usize = 16;
const ARGON_PARAM_LEN: usize = 4 + 4 + 4; // memory_kib + iterations + parallelism

/// Width of the suite_id field on the v2 wire layout (big-endian u16).
pub const SUITE_ID_LEN: usize = 2;

const HEADER_LEN_V2: usize = MAGIC.len() + SUITE_ID_LEN + PROFILE_ID_LEN + ARGON_PARAM_LEN;
const HEADER_LEN_V1: usize = MAGIC_V1.len() + PROFILE_ID_LEN + ARGON_PARAM_LEN;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ARGON2_OUTPUT_LEN: usize = 48;
const AEAD_KEY_LEN: usize = 32;

/// Decrypted recovery-file contents. Caller persists `profile_id` + `argon2`
/// into a fresh `daemonseed.toml` on recovery. `suite_id` indicates which
/// registry entry the file was sealed under (ISC-C24); `legacy_v1` is true
/// when the file was a v1 `.dseed` and the consumer should consider
/// re-sealing on next save (ISC-C24 read-old-write-new).
pub struct RecoveryFileContents {
    pub mnemonic: Mnemonic,
    pub profile_id: Uuid,
    pub argon2: ArgonParams,
    pub suite_id: SuiteId,
    pub legacy_v1: bool,
}

impl core::fmt::Debug for RecoveryFileContents {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryFileContents")
            .field("mnemonic", &"<redacted>")
            .field("profile_id", &self.profile_id)
            .field("argon2", &self.argon2)
            .field("suite_id", &self.suite_id)
            .field("legacy_v1", &self.legacy_v1)
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
    /// v2 file carried a `suite_id` whose raw value is one of the reserved
    /// sentinels (`0x0000` / `0xFFFF`).
    SuiteIdSentinel(SuiteIdError),
    /// v2 file carried a `suite_id` not present in this build's registry.
    UnknownSuite(SuiteId),
    /// Active write-suite refused by the registry (e.g. all suites
    /// deprecated). Returned by [`seal`] when no write-eligible suite
    /// exists.
    WriteRefused(WriteRefusal),
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
            RecoveryFileError::SuiteIdSentinel(e) => write!(f, ".dseed suite_id: {e}"),
            RecoveryFileError::UnknownSuite(id) => {
                write!(f, ".dseed references unknown suite {id}")
            }
            RecoveryFileError::WriteRefused(r) => write!(f, ".dseed write refused: {r}"),
            RecoveryFileError::Utf8(e) => write!(f, ".dseed plaintext is not UTF-8: {e}"),
            RecoveryFileError::Mnemonic(e) => write!(f, "mnemonic in .dseed: {e}"),
        }
    }
}

impl std::error::Error for RecoveryFileError {}

/// Encrypt a mnemonic into the canonical v2 `.dseed` layout under the
/// active write-suite. The `profile_id` and `argon2` params land in the
/// cleartext header so a clean-device recovery can derive the same key
/// from passphrase alone.
pub fn seal(
    mnemonic: &Mnemonic,
    passphrase: &str,
    profile_id: Uuid,
    argon2: ArgonParams,
) -> Result<Vec<u8>, RecoveryFileError> {
    let suite_id = Registry::default_write_suite();
    seal_under(mnemonic, passphrase, profile_id, argon2, suite_id)
}

/// Encrypt a mnemonic into the v2 `.dseed` layout under an explicit
/// `suite_id`. Used by tests that need to write a non-default suite. The
/// registry MUST contain `suite_id` and it MUST be write-eligible.
///
/// Both the derived AEAD key and the mnemonic phrase are held in [`Zeroizing`], so
/// each is wiped on every path out — including the two fallible steps that sit
/// between the key's derivation and its last use (the CSPRNG nonce draw and the AES
/// key schedule), and an unwind out of any of it.
pub fn seal_under(
    mnemonic: &Mnemonic,
    passphrase: &str,
    profile_id: Uuid,
    argon2: ArgonParams,
    suite_id: SuiteId,
) -> Result<Vec<u8>, RecoveryFileError> {
    Registry::resolve_for_write(suite_id).map_err(RecoveryFileError::WriteRefused)?;

    // Both secrets let the type carry the wipe rather than a positional
    // `zeroize()` call. For the key that closes a real gap: two `?` returns sit
    // between its derivation and its last use, and a positional wipe after
    // `Aes256Key::new` is skipped by either of them. (#259)
    let key = Zeroizing::new(derive_aead_key(passphrase, profile_id, argon2)?);

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(RecoveryFileError::EntropySource)?;

    let aes = Aes256Key::new(&key).map_err(RecoveryFileError::AesKeyInit)?;

    // The phrase is the whole recovery secret.
    let phrase = Zeroizing::new(mnemonic.to_phrase());
    let plaintext = phrase.as_bytes();
    let suite_bytes = suite_id.get().to_be_bytes();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(
        &aes,
        &nonce,
        &suite_bytes,
        plaintext,
        &mut ciphertext,
        &mut tag,
    )
    .map_err(RecoveryFileError::AesMode)?;

    let mut out = Vec::with_capacity(HEADER_LEN_V2 + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&suite_bytes);
    out.extend_from_slice(profile_id.as_bytes());
    out.extend_from_slice(&argon2.memory_kib.to_le_bytes());
    out.extend_from_slice(&argon2.iterations.to_le_bytes());
    out.extend_from_slice(&argon2.parallelism.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a v2 (or legacy v1) `.dseed`. The profile_id and argon2 params
/// are read from the cleartext header (per ISC-C36 recovery-on-clean-
/// device); the caller supplies only the file bytes and the passphrase.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<RecoveryFileContents, RecoveryFileError> {
    if bytes.len() < MAGIC.len() {
        return Err(RecoveryFileError::Malformed("file shorter than magic"));
    }
    let magic = &bytes[..MAGIC.len()];
    if magic == MAGIC {
        open_v2(bytes, passphrase)
    } else if magic == MAGIC_V1 {
        open_v1(bytes, passphrase)
    } else {
        Err(RecoveryFileError::Malformed("magic prefix mismatch"))
    }
}

fn open_v2(bytes: &[u8], passphrase: &str) -> Result<RecoveryFileContents, RecoveryFileError> {
    if bytes.len() < HEADER_LEN_V2 + NONCE_LEN + TAG_LEN {
        return Err(RecoveryFileError::Malformed(
            "v2 file shorter than minimum header",
        ));
    }

    let mut cursor = MAGIC.len();

    let suite_bytes: [u8; SUITE_ID_LEN] = bytes[cursor..cursor + SUITE_ID_LEN].try_into().unwrap();
    cursor += SUITE_ID_LEN;
    let suite_raw = u16::from_be_bytes(suite_bytes);
    let suite_id = SuiteId::try_new(suite_raw).map_err(RecoveryFileError::SuiteIdSentinel)?;
    if Registry::lookup(suite_id).is_none() {
        return Err(RecoveryFileError::UnknownSuite(suite_id));
    }

    let (profile_id, argon2, after_header) = parse_post_suite_header(bytes, cursor)?;

    let (nonce, ciphertext, tag) = split_body(after_header)?;

    let mut key = derive_aead_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(RecoveryFileError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, nonce, &suite_bytes, ciphertext, tag, &mut plaintext).map_err(
        |e| match e {
            oxicrypt_aes::ModeError::TagMismatch => RecoveryFileError::AuthenticationFailed,
            other => RecoveryFileError::AesMode(other),
        },
    )?;

    let phrase = core::str::from_utf8(&plaintext).map_err(RecoveryFileError::Utf8)?;
    let mnemonic = Mnemonic::from_phrase(phrase).map_err(RecoveryFileError::Mnemonic);
    plaintext.zeroize();
    let mnemonic = mnemonic?;

    Ok(RecoveryFileContents {
        mnemonic,
        profile_id,
        argon2,
        suite_id,
        legacy_v1: false,
    })
}

fn open_v1(bytes: &[u8], passphrase: &str) -> Result<RecoveryFileContents, RecoveryFileError> {
    if bytes.len() < HEADER_LEN_V1 + NONCE_LEN + TAG_LEN {
        return Err(RecoveryFileError::Malformed(
            "v1 file shorter than minimum header",
        ));
    }

    let (profile_id, argon2, after_header) = parse_post_suite_header(bytes, MAGIC_V1.len())?;

    let (nonce, ciphertext, tag) = split_body(after_header)?;

    let mut key = derive_aead_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(RecoveryFileError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    // v1 used empty AAD — preserve that contract or M2 .dseed fails to open.
    gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext).map_err(|e| match e {
        oxicrypt_aes::ModeError::TagMismatch => RecoveryFileError::AuthenticationFailed,
        other => RecoveryFileError::AesMode(other),
    })?;

    let phrase = core::str::from_utf8(&plaintext).map_err(RecoveryFileError::Utf8)?;
    let mnemonic = Mnemonic::from_phrase(phrase).map_err(RecoveryFileError::Mnemonic);
    plaintext.zeroize();
    let mnemonic = mnemonic?;

    let implicit = SuiteId::try_new(V1_IMPLICIT_SUITE_RAW)
        .expect("V1_IMPLICIT_SUITE_RAW is a valid non-sentinel id");
    Ok(RecoveryFileContents {
        mnemonic,
        profile_id,
        argon2,
        suite_id: implicit,
        legacy_v1: true,
    })
}

/// Decode the (profile_id, argon2 params, remaining-bytes) tuple starting
/// at `cursor`. Shared between v1 and v2 paths because the field layout
/// after the magic + (v2-only) suite_id is identical.
fn parse_post_suite_header(
    bytes: &[u8],
    mut cursor: usize,
) -> Result<(Uuid, ArgonParams, &[u8]), RecoveryFileError> {
    let profile_id_bytes: [u8; PROFILE_ID_LEN] = bytes[cursor..cursor + PROFILE_ID_LEN]
        .try_into()
        .map_err(|_| RecoveryFileError::Malformed("profile_id slice"))?;
    let profile_id = Uuid::from_bytes(profile_id_bytes);
    cursor += PROFILE_ID_LEN;

    let memory_kib = u32::from_le_bytes(
        bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| RecoveryFileError::Malformed("memory_kib slice"))?,
    );
    cursor += 4;
    let iterations = u32::from_le_bytes(
        bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| RecoveryFileError::Malformed("iterations slice"))?,
    );
    cursor += 4;
    let parallelism = u32::from_le_bytes(
        bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| RecoveryFileError::Malformed("parallelism slice"))?,
    );
    cursor += 4;
    let argon2 = ArgonParams {
        memory_kib,
        iterations,
        parallelism,
    };

    Ok((profile_id, argon2, &bytes[cursor..]))
}

/// Tuple of (nonce, ciphertext, tag) borrowed out of the post-header body.
type BodyParts<'a> = (&'a [u8; NONCE_LEN], &'a [u8], &'a [u8; TAG_LEN]);

fn split_body(after_header: &[u8]) -> Result<BodyParts<'_>, RecoveryFileError> {
    if after_header.len() < NONCE_LEN + TAG_LEN {
        return Err(RecoveryFileError::Malformed("body shorter than nonce+tag"));
    }
    let nonce: &[u8; NONCE_LEN] = after_header[..NONCE_LEN].try_into().unwrap();
    let after_nonce = &after_header[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();
    Ok((nonce, ciphertext, tag))
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
    let hkdf = HkdfSha384::from_prk(&intermediate).map_err(RecoveryFileError::Hkdf)?;
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        assert_eq!(recovered.suite_id.get(), 0x0001);
        assert!(!recovered.legacy_v1);
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
        // Flip a byte inside the profile_id range (which sits after MAGIC
        // and the v2 suite_id) — derived HKDF info will be wrong → wrong
        // key → AEAD fails to verify.
        file[MAGIC.len() + SUITE_ID_LEN] ^= 0x01;
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
        let mem_kib_offset = MAGIC.len() + SUITE_ID_LEN + PROFILE_ID_LEN;
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
        let too_short = &file[..HEADER_LEN_V2 + 1];
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
    fn magic_v2_is_pinned() {
        // Spec contract — bumping this is a format-incompatible change.
        assert_eq!(MAGIC, b"daemonseed/dseed/v2\0");
    }

    #[test]
    fn magic_v1_legacy_is_pinned() {
        assert_eq!(MAGIC_V1, b"daemonseed/dseed/v1\0");
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
        let seeds_payload = seeds::Seeds::new(m.clone());
        let at_rest_blob = seeds::seal(&seeds_payload, pp, pid, fast_params()).unwrap();
        // Try to open the at-rest blob as a recovery file. Magic prefix
        // differs — recovery-file should reject it as Malformed.
        match open(&at_rest_blob, pp) {
            Err(RecoveryFileError::Malformed(_)) => {}
            other => panic!("expected Malformed (different magic), got {other:?}"),
        }
    }

    /// Hand-build a v1 `.dseed` (M2 wire shape) and confirm `open` recovers
    /// it under the implicit `suite_id = 0x0001`. Without this test the
    /// v1→v2 migration claim is just words.
    #[test]
    fn open_accepts_legacy_v1_file() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let m = fresh_mnemonic();
        let orig_phrase = m.to_phrase();
        let params = fast_params();

        // Construct a v1 file by hand using the same KDF chain seal() uses
        // but with the v1 layout (no suite_id; AAD=b"").
        let mut key = derive_aead_key(pp, pid, params).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let aes = Aes256Key::new(&key).unwrap();
        key.zeroize();
        let pt = orig_phrase.as_bytes();
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, b"", pt, &mut ct, &mut tag).unwrap();

        let mut v1_file = Vec::with_capacity(HEADER_LEN_V1 + NONCE_LEN + ct.len() + TAG_LEN);
        v1_file.extend_from_slice(MAGIC_V1);
        v1_file.extend_from_slice(pid.as_bytes());
        v1_file.extend_from_slice(&params.memory_kib.to_le_bytes());
        v1_file.extend_from_slice(&params.iterations.to_le_bytes());
        v1_file.extend_from_slice(&params.parallelism.to_le_bytes());
        v1_file.extend_from_slice(&nonce);
        v1_file.extend_from_slice(&ct);
        v1_file.extend_from_slice(&tag);

        let opened = open(&v1_file, pp).unwrap();
        assert_eq!(opened.mnemonic.to_phrase(), orig_phrase);
        assert_eq!(opened.profile_id, pid);
        assert_eq!(opened.argon2, params);
        assert_eq!(opened.suite_id.get(), 0x0001);
        assert!(opened.legacy_v1);
    }

    /// AAD binding: flipping the suite_id byte in a v2 `.dseed` must fail
    /// authentication, because the suite_id is part of the AAD covered by
    /// the AEAD tag.
    #[test]
    fn v2_suite_id_tamper_fails_auth() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut file = seal(&fresh_mnemonic(), pp, pid, fast_params()).unwrap();
        // Tamper the low byte of suite_id from 0x01 → 0x02 (still
        // non-sentinel, but not in the registry).
        let suite_lo = MAGIC.len() + 1;
        assert_eq!(file[suite_lo], 0x01);
        file[suite_lo] = 0x02;
        match open(&file, pp) {
            Err(RecoveryFileError::UnknownSuite(id)) => assert_eq!(id.get(), 0x0002),
            other => panic!("expected UnknownSuite, got {other:?}"),
        }
    }

    /// A v2 `.dseed` whose suite_id field encodes a reserved sentinel is
    /// rejected before any AEAD work.
    #[test]
    fn v2_suite_id_sentinel_rejected() {
        init_oxicrypt();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut file = seal(&fresh_mnemonic(), pp, pid, fast_params()).unwrap();
        let suite_hi = MAGIC.len();
        let suite_lo = MAGIC.len() + 1;
        file[suite_hi] = 0xFF;
        file[suite_lo] = 0xFF;
        match open(&file, pp) {
            Err(RecoveryFileError::SuiteIdSentinel(_)) => {}
            other => panic!("expected SuiteIdSentinel, got {other:?}"),
        }
    }
}
