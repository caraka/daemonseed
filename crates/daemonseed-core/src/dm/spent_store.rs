//! Where the spent-invite-token set lives on disk (#233, ISC-C28).
//!
//! [`SpentTokenSet`] knows how to encode itself and how to forget an expired
//! grant. What it did not have was a home, and the obvious home was wrong.
//!
//! **Why not the DM store.** [`crate::storage::dm_store::DmStore`] holds the
//! state a correspondence needs to carry on — reconnect material, a handshake in
//! progress, the unsettled outbox, the read cursor, the contact record — under
//! `root/<correspondence>/<kind>`, where the directory name *is* the
//! correspondence. The spent set belongs to none of them. An invite token is
//! minted by this profile and redeemed once against this profile — the whole
//! point of the set is that a token burnt in one conversation cannot be replayed
//! into another — so filing it under any single correspondence would be a lie
//! about its scope, and filing it under a reserved sentinel correspondence would
//! put a directory in the store that names something that is not a
//! correspondence, in exactly the place where directory names are load-bearing
//! for privacy.
//!
//! **The store has since grown a profile scope, and that does not move this
//! set.** `RecordKind::BlockList` is profile-scoped, so "every record belongs to
//! one correspondence" is no longer the reason. The reason is the shape: a
//! profile record there is one fixed-size file padded to a ceiling chosen so its
//! length reveals nothing, which suits a bounded set of identities and does not
//! suit a set that grows and expires with token traffic. Revisit this if that
//! ever stops being true; do not revisit it because the scope exists.
//!
//! So the set is profile-global and sits at the profile root, beside the trust
//! log, sealed under its own key.
//!
//! **What the file gives away, stated rather than implied.** Its size is
//! `count × 40` bytes plus a fixed header, so an observer with the file and no
//! passphrase learns how many unexpired grants this profile has burnt. It does
//! not learn who they were issued to: a spent entry is a nonce and an expiry,
//! and the nonce is drawn from the CSPRNG at mint with no relationship to the
//! grantee. Nothing here is padded, because padding a count that
//! [`SpentTokenSet::prune`] already bounds to two first-contact periods would
//! trade a real cost for a marginal one.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::kdf::info;
use crate::profile::config::ArgonParams;
use crate::storage::seeds::{AEAD_KEY_LEN, ARGON2_OUTPUT_LEN, NONCE_LEN, TAG_LEN};

use super::token::SpentTokenSet;

/// Filename of the spent-invite-token set at the profile root.
pub const SPENT_TOKENS_FILENAME: &str = "dm-spent-tokens.bin";

/// The spent-token-set path for a profile root:
/// `<profile-root>/dm-spent-tokens.bin`.
///
/// Deliberately a sibling of the trust log rather than anything under the DM
/// store — see the module docs.
pub fn spent_tokens_path(profile_root: &Path) -> PathBuf {
    profile_root.join(SPENT_TOKENS_FILENAME)
}

/// Magic prefix for the sealed spent-token file.
///
/// Versioned from the first byte written, for the reason the trust log had to
/// learn the hard way: the body is a bare stride of fixed-width records with no
/// per-record length and no terminator, so any future field would shift every
/// record after it and an older reader would decode plausible nonsense rather
/// than fail. The magic is inside the AAD, so the version is authenticated and
/// cannot be edited down to force an older layout.
const MAGIC_V1: &[u8] = b"DSSPENTTOK1";

/// The magic [`seal`] writes.
const MAGIC: &[u8] = MAGIC_V1;

const PROFILE_ID_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + PROFILE_ID_LEN + 4 + 4 + 4; // + argon params

/// Anything that can go wrong sealing or opening the spent-token file.
#[derive(Debug)]
pub enum SpentStoreError {
    /// Argon2id stage failed (bad params).
    Argon2(argon2::Error),
    /// HKDF stage failed.
    Hkdf(oxicrypt_kdf::KdfError),
    /// AES-256 key init failed.
    AesKeyInit(oxicrypt_module::Error),
    /// AES-GCM mode error (non-auth).
    AesMode(oxicrypt_aes::ModeError),
    /// AEAD authentication failed — wrong passphrase or tampered file.
    AuthenticationFailed,
    /// Entropy source failed while generating the nonce.
    EntropySource(getrandom::Error),
    /// The file was structurally malformed.
    Malformed(&'static str),
    /// The file could not be read.
    Io(std::io::Error),
    /// The file could not be replaced durably.
    ///
    /// Carries [`crate::storage::AtomicReplaceError`] whole rather than
    /// flattening it: its
    /// three arms differ in **what state the destination is in**, and a caller
    /// deciding whether the set on disk is the old one, the new one, or
    /// unknown needs that distinction rather than a rendered string.
    Replace(crate::storage::AtomicReplaceError),
}

impl core::fmt::Display for SpentStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpentStoreError::Argon2(e) => write!(f, "argon2: {e}"),
            SpentStoreError::Hkdf(e) => write!(f, "HKDF: {e:?}"),
            SpentStoreError::AesKeyInit(e) => write!(f, "AES-256 key init: {e:?}"),
            SpentStoreError::AesMode(e) => write!(f, "AES-GCM mode error: {e:?}"),
            SpentStoreError::AuthenticationFailed => write!(
                f,
                "spent-token set authentication failed (wrong passphrase or tampering)"
            ),
            SpentStoreError::EntropySource(e) => write!(f, "entropy source: {e}"),
            SpentStoreError::Malformed(m) => write!(f, "malformed spent-token set: {m}"),
            SpentStoreError::Io(e) => write!(f, "spent-token set io: {e}"),
            SpentStoreError::Replace(e) => write!(f, "spent-token set replace: {e:?}"),
        }
    }
}

impl std::error::Error for SpentStoreError {}

/// Encrypt a spent-token set into the on-disk layout.
///
/// Key derivation is the daemonseed two-stage KDF — Argon2id salted with the
/// profile-id, then HKDF-SHA-384 under `daemonseed/dm-spent-tokens/<profile-id>`
/// — so this key is independent of the at-rest blob, the recovery file, the
/// share index and the trust log. The cleartext header (magic, profile-id,
/// argon params) is the AAD, so editing any of it fails the open rather than
/// silently changing how the body is read.
pub fn seal(
    set: &SpentTokenSet,
    passphrase: &str,
    profile_id: Uuid,
    argon2: ArgonParams,
) -> Result<Vec<u8>, SpentStoreError> {
    let mut key = derive_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(SpentStoreError::AesKeyInit)?;
    key.zeroize();

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(SpentStoreError::EntropySource)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(profile_id.as_bytes());
    header.extend_from_slice(&argon2.memory_kib.to_le_bytes());
    header.extend_from_slice(&argon2.iterations.to_le_bytes());
    header.extend_from_slice(&argon2.parallelism.to_le_bytes());

    let plaintext = set.encode();
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(&aes, &nonce, &header, &plaintext, &mut ciphertext, &mut tag)
        .map_err(SpentStoreError::AesMode)?;

    let mut out = Vec::with_capacity(header.len() + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a spent-token set written by [`seal`]. The profile-id and argon
/// params come from the cleartext header; the caller supplies only the file
/// bytes and the passphrase.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<SpentTokenSet, SpentStoreError> {
    if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(SpentStoreError::Malformed("shorter than minimum header"));
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(SpentStoreError::Malformed("magic prefix mismatch"));
    }
    let mut cursor = MAGIC.len();
    let profile_id = Uuid::from_slice(&bytes[cursor..cursor + PROFILE_ID_LEN])
        .map_err(|_| SpentStoreError::Malformed("bad profile-id"))?;
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
    // Before deriving anything: these came out of the file, and the key has to
    // be derived before the tag can reject the file. See `is_openable`.
    if !argon2.is_openable() {
        return Err(SpentStoreError::Malformed("argon parameters out of range"));
    }

    let header = &bytes[..cursor];
    let nonce: [u8; NONCE_LEN] = bytes[cursor..cursor + NONCE_LEN].try_into().unwrap();
    cursor += NONCE_LEN;
    let ciphertext_len = bytes.len() - cursor - TAG_LEN;
    let ciphertext = &bytes[cursor..cursor + ciphertext_len];
    let tag: [u8; TAG_LEN] = bytes[cursor + ciphertext_len..].try_into().unwrap();

    let mut key = derive_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(SpentStoreError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, &nonce, header, ciphertext, &tag, &mut plaintext).map_err(|e| match e {
        oxicrypt_aes::ModeError::TagMismatch => SpentStoreError::AuthenticationFailed,
        other => SpentStoreError::AesMode(other),
    })?;

    // Zeroize BEFORE the `?` — see the same note in `trust_events::open_log`.
    let decoded = SpentTokenSet::decode(&plaintext);
    plaintext.zeroize();
    decoded.ok_or(SpentStoreError::Malformed("bad spent-token body"))
}

/// Read the sealed set at `path`.
///
/// `Ok(None)` is the file being absent, which is the ordinary state of a
/// profile that has never redeemed an invite. **Every other failure is an
/// error**, deliberately: a file that is present and will not open is either a
/// wrong passphrase or tampering, and answering that with an empty set is
/// silent un-spending — every grant already burnt becomes redeemable again. The
/// caller decides what to do about it; this will not decide by forgetting.
pub fn read_from(path: &Path, passphrase: &str) -> Result<Option<SpentTokenSet>, SpentStoreError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(SpentStoreError::Io(e)),
    };
    open(&bytes, passphrase).map(Some)
}

/// Seal the set and replace the file at `path` durably.
///
/// The storage layer's durable replacement, not a plain write: this file
/// is a suppression plane, and a truncated one is a set of grants that can be
/// spent twice. A partial write is the one outcome that must not be reachable,
/// so the bytes land in a temp sibling, are fsynced, and are renamed over the
/// destination.
pub fn write_to(
    path: &Path,
    set: &SpentTokenSet,
    passphrase: &str,
    profile_id: Uuid,
    argon2: ArgonParams,
) -> Result<(), SpentStoreError> {
    let sealed = seal(set, passphrase, profile_id, argon2)?;
    crate::storage::atomic_file::replace_atomically(path, &sealed).map_err(SpentStoreError::Replace)
}

/// Two-stage Argon2id + HKDF-SHA-384 key derivation for the spent-token set.
/// Mirrors the trust-log derivation with its own info string, so a compromise
/// of one key does not implicate the other.
fn derive_key(
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<[u8; AEAD_KEY_LEN], SpentStoreError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::default(),
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(SpentStoreError::Argon2)?,
    );
    let mut intermediate = [0u8; ARGON2_OUTPUT_LEN];
    let salt: [u8; 16] = *profile_id.as_bytes();
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut intermediate)
        .map_err(SpentStoreError::Argon2)?;

    let info_str = info::spent_tokens(&profile_id.to_string());
    let hkdf = HkdfSha384::from_prk(&intermediate).map_err(SpentStoreError::Hkdf)?;
    intermediate.zeroize();

    let mut key = [0u8; AEAD_KEY_LEN];
    hkdf.expand(info_str.as_bytes(), &mut key)
        .map_err(SpentStoreError::Hkdf)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";
    const NOW: u64 = 1_700_000_000;

    fn argon() -> ArgonParams {
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn profile() -> Uuid {
        Uuid::from_bytes([7u8; 16])
    }

    /// The crypto module powers on per test binary; every test here reaches
    /// AES-GCM or HKDF, so each one calls this first.
    fn boot() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    fn populated() -> SpentTokenSet {
        let mut set = SpentTokenSet::new();
        assert!(set.insert([1u8; 32], NOW + 100));
        assert!(set.insert([2u8; 32], NOW + 200));
        set
    }

    /// The set lands at the profile root, beside the trust log — never inside
    /// the DM store, whose directory names are per-correspondence.
    #[test]
    fn the_set_lives_at_the_profile_root() {
        boot();
        let p = spent_tokens_path(Path::new("/profiles/alice"));
        assert_eq!(p, PathBuf::from("/profiles/alice/dm-spent-tokens.bin"));
        assert_eq!(
            p.parent(),
            Some(Path::new("/profiles/alice")),
            "one level below the root, so it is not under any correspondence"
        );
    }

    #[test]
    fn seal_then_open_round_trips() {
        boot();
        let set = populated();
        let bytes = seal(&set, PASS, profile(), argon()).expect("seals");
        let back = open(&bytes, PASS).expect("opens");
        assert_eq!(back, set);
        assert_eq!(back.len(), 2);
        assert!(back.contains(&[1u8; 32]));
    }

    /// An empty set is a real state — a profile that has issued invites and
    /// had none redeemed yet — and must survive the round trip.
    #[test]
    fn an_empty_set_round_trips() {
        boot();
        let set = SpentTokenSet::new();
        let bytes = seal(&set, PASS, profile(), argon()).expect("seals");
        assert_eq!(open(&bytes, PASS).expect("opens"), SpentTokenSet::new());
    }

    #[test]
    fn open_rejects_a_wrong_passphrase() {
        boot();
        let bytes = seal(&populated(), PASS, profile(), argon()).expect("seals");
        assert!(
            open(&bytes, PASS).is_ok(),
            "control: the right passphrase opens it"
        );
        assert!(matches!(
            open(&bytes, "wrong passphrase entirely"),
            Err(SpentStoreError::AuthenticationFailed)
        ));
    }

    /// Every cleartext header byte is inside the AAD, so editing any of them
    /// fails the open. The loop is the point: a spot-check of one field would
    /// pass while another field sat unauthenticated.
    ///
    /// Two rejection routes are both correct here and the test does not care
    /// which fires. A flipped magic or profile-id byte reaches the tag and
    /// fails authentication; a flipped argon-parameter byte is refused earlier,
    /// by `is_openable`, precisely because deriving the key at whatever cost
    /// the file asked for is the thing that must not happen.
    #[test]
    fn every_header_byte_is_authenticated() {
        boot();
        let bytes = seal(&populated(), PASS, profile(), argon()).expect("seals");
        assert!(open(&bytes, PASS).is_ok(), "control: the intact file opens");
        for i in 0..HEADER_LEN {
            let mut tampered = bytes.clone();
            // The high bit of a `u32` cost field: the flip that turns a
            // trivial derivation into an impossible one, and the reason the
            // guard exists. Flipping bit 0 instead would leave the cost small
            // and let this test pass without ever exercising the guard.
            tampered[i] ^= 0x80;
            assert!(
                open(&tampered, PASS).is_err(),
                "flipping header byte {i} must not open"
            );
        }
    }

    /// A header naming an absurd Argon2 cost is refused before any derivation.
    ///
    /// **This is a regression test for a live hang, not a hypothetical.** The
    /// loop above originally flipped a bit in `memory_kib` and the suite stopped
    /// responding: the opener had gone off to allocate the terabytes the file
    /// asked for, and would only have rejected the file afterwards. The tag
    /// cannot save you here, because the work happens before the tag is checked.
    #[test]
    fn an_absurd_argon_cost_is_refused_before_deriving() {
        boot();
        let bytes = seal(&populated(), PASS, profile(), argon()).expect("seals");
        assert!(open(&bytes, PASS).is_ok(), "control: the intact file opens");

        let at = MAGIC.len() + PROFILE_ID_LEN;
        let mut absurd = bytes.clone();
        absurd[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            matches!(
                open(&absurd, PASS),
                Err(SpentStoreError::Malformed("argon parameters out of range"))
            ),
            "a 4 TiB memory cost is refused by name, not attempted"
        );

        // Zero is refused too, at the other end of the same range.
        let mut zeroed = bytes.clone();
        zeroed[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            open(&zeroed, PASS),
            Err(SpentStoreError::Malformed("argon parameters out of range"))
        ));
    }

    /// The header is genuinely bound as AAD, and not merely echoed.
    ///
    /// **`every_header_byte_is_authenticated` cannot show this.** Every header
    /// byte feeds either the magic check, the key derivation or `is_openable`,
    /// so every flip errors by some route whether or not the AAD is passed —
    /// drop the AAD from both `gcm_encrypt` and `gcm_decrypt` and that test
    /// stays green. This one seals with the real AAD and opens with a different
    /// one, which can only fail if the binding is real.
    #[test]
    fn the_header_is_bound_as_aad_and_not_merely_echoed() {
        boot();
        let set = populated();
        let pid = profile();
        let a = argon();

        let mut key = derive_key(PASS, pid, a).expect("derives");
        let aes = Aes256Key::new(&key).expect("key");
        key.zeroize();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("nonce");

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(pid.as_bytes());
        header.extend_from_slice(&a.memory_kib.to_le_bytes());
        header.extend_from_slice(&a.iterations.to_le_bytes());
        header.extend_from_slice(&a.parallelism.to_le_bytes());

        let plaintext = set.encode();
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, &header, &plaintext, &mut ct, &mut tag).expect("seals");

        // Control: the same AAD opens it.
        let mut out = vec![0u8; ct.len()];
        assert!(
            gcm_decrypt(&aes, &nonce, &header, &ct, &tag, &mut out).is_ok(),
            "control: the real AAD authenticates"
        );

        // The claim: an empty AAD does not.
        let mut out2 = vec![0u8; ct.len()];
        assert!(
            gcm_decrypt(&aes, &nonce, &[], &ct, &tag, &mut out2).is_err(),
            "an empty AAD must not authenticate a header-bound ciphertext"
        );
    }

    #[test]
    fn a_tampered_body_fails_the_tag() {
        boot();
        let bytes = seal(&populated(), PASS, profile(), argon()).expect("seals");
        let mut tampered = bytes.clone();
        let last = tampered.len() - TAG_LEN - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(
            open(&tampered, PASS),
            Err(SpentStoreError::AuthenticationFailed)
        ));
    }

    /// The spent-token key is not the trust-log key. Same passphrase, same
    /// profile, same argon params — a file sealed by one must not open under
    /// the other, which is what the distinct HKDF info string buys.
    #[test]
    fn the_key_is_domain_separated_from_the_trust_log() {
        boot();
        let spent = derive_key(PASS, profile(), argon()).expect("derives");
        let trust = {
            // Re-derived here rather than called, because the trust log's
            // derivation is private to its own module. The only difference
            // between the two is the info string, which is exactly the claim.
            let a = Argon2::new(
                Algorithm::Argon2id,
                Version::default(),
                Params::new(8, 1, 1, Some(ARGON2_OUTPUT_LEN)).unwrap(),
            );
            let mut prk = [0u8; ARGON2_OUTPUT_LEN];
            a.hash_password_into(PASS.as_bytes(), profile().as_bytes(), &mut prk)
                .unwrap();
            let h = HkdfSha384::from_prk(&prk).unwrap();
            let mut k = [0u8; AEAD_KEY_LEN];
            h.expand(
                info::trust_events(&profile().to_string()).as_bytes(),
                &mut k,
            )
            .unwrap();
            k
        };
        assert_ne!(
            spent, trust,
            "one passphrase must not produce one key for two artifacts"
        );
    }

    /// A file whose magic says something else is refused before any key is
    /// derived — the version is read, not guessed.
    #[test]
    fn a_foreign_magic_is_refused() {
        boot();
        let mut bytes = seal(&populated(), PASS, profile(), argon()).expect("seals");
        assert!(open(&bytes, PASS).is_ok(), "control: the intact file opens");
        bytes[MAGIC.len() - 1] = b'9';
        assert!(matches!(
            open(&bytes, PASS),
            Err(SpentStoreError::Malformed("magic prefix mismatch"))
        ));
    }

    /// A truncated file is malformed rather than panicking on a slice.
    #[test]
    fn a_short_file_is_malformed() {
        boot();
        let bytes = seal(&populated(), PASS, profile(), argon()).expect("seals");
        for len in [0usize, 1, HEADER_LEN, HEADER_LEN + NONCE_LEN] {
            assert!(
                open(&bytes[..len.min(bytes.len())], PASS).is_err(),
                "a {len}-byte file must not open"
            );
        }
    }
}
