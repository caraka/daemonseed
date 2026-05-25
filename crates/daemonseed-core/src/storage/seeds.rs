//! Encrypted at-rest seeds blob (ISC-C3, ISC-C24).
//!
//! ## Format v2 (M3+)
//!
//! ```text
//!   [MAGIC      (19 bytes: b"daemonseed/blob/v2\0")]
//!   [SUITE_ID   ( 2 bytes: u16 big-endian, per ds-suite-registry.md)]
//!   [NONCE      (12 bytes: CSPRNG-generated)]
//!   [CIPHERTEXT (plaintext_len bytes)]
//!   [TAG        (16 bytes: AES-GCM authenticator)]
//! ```
//!
//! The `suite_id` resolves through [`crate::crypto::suite::Registry`] to the
//! concrete AEAD / KDF used for this blob. Per ISC-C24 every cryptographic
//! artifact the client authors carries a `suite_id`; the at-rest blob is the
//! first such artifact in M3.
//!
//! ## Format v1 (M1 / M2 — read-only since M3)
//!
//! ```text
//!   [MAGIC      (19 bytes: b"daemonseed/blob/v1\0")]
//!   [NONCE      (12 bytes)]
//!   [CIPHERTEXT (plaintext_len bytes)]
//!   [TAG        (16 bytes)]
//! ```
//!
//! v1 blobs are accepted by [`open`] under the implicit assumption that
//! `suite_id = 0x0001` (CNSA 2.0) — the only suite that existed at M1/M2.
//! [`seal`] always writes v2. [`touch_reseal`] is the on-touch migration
//! path per ISC-C24: decrypt under the stored suite, re-encrypt as v2
//! under the active write-suite. Read-old / write-new without a flag-day.
//!
//! ## KDF chain (unchanged from M1)
//!
//! ```text
//!   intermediate = Argon2id(
//!       passphrase = utf8(passphrase),
//!       salt       = profile_id (16-byte UUID),
//!       params     = persisted [argon2] table (ISC-C14),
//!       length     = 32,
//!   )
//!   aead_key     = HKDF-SHA384-Expand(
//!       prk  = intermediate,
//!       info = "daemonseed/at-rest/<profile-id>",
//!       length = 32,
//!   )
//!   ciphertext, tag = AES-256-GCM-seal(aead_key, nonce, plaintext, aad)
//! ```
//!
//! ## AAD binding
//!
//! v1 blobs use empty AAD (M1 / M2 contract). v2 blobs bind the `suite_id`
//! bytes into the AAD so a tamper-swap of the suite tag fails AEAD auth —
//! the receiver cannot be tricked into running a v2 blob under the wrong
//! suite's primitives without the AEAD detecting it.

use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError, WriteRefusal};
use crate::identity::mnemonic::{Mnemonic, MnemonicError};
use crate::kdf::info;
use crate::profile::config::ArgonParams;

/// Magic prefix for the **current** (v2) blob format. M3+ writes this magic
/// on every [`seal`] call. Bump the `v2` tag on any incompatible layout
/// change.
pub const MAGIC: &[u8; 19] = b"daemonseed/blob/v2\0";

/// Magic prefix for the **legacy** v1 blob format (M1 / M2). [`open`]
/// accepts blobs prefixed with this value and treats them as carrying the
/// implicit `suite_id = 0x0001` (CNSA 2.0). [`seal`] never writes this
/// magic.
pub const MAGIC_V1: &[u8; 19] = b"daemonseed/blob/v1\0";

/// Implicit suite id assumed when reading a v1 blob. v1 predates the
/// registry; only CNSA 2.0 existed when v1 blobs were written.
const V1_IMPLICIT_SUITE_RAW: u16 = 0x0001;

/// Width of the suite_id field on the v2 wire layout (big-endian u16).
pub const SUITE_ID_LEN: usize = 2;

/// AES-256-GCM nonce length (per NIST SP 800-38D §8.2.1).
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM tag length (per NIST SP 800-38D §5.2.1.2).
pub const TAG_LEN: usize = 16;

/// Argon2id intermediate output length (= AEAD key length = HKDF PRK len).
pub const ARGON2_OUTPUT_LEN: usize = 48;

/// AEAD key length (AES-256 → 32 bytes).
pub const AEAD_KEY_LEN: usize = 32;

/// Replay-protection counter state persisted alongside the mnemonic
/// (`project_clocks_freshness`).
///
/// - `send_counter` is this identity's own monotonic counter. The
///   orchestration layer calls [`next_send`](CounterState::next_send) for each
///   identity-proof envelope it builds; persisting it is what stops a restarted
///   client from re-emitting a counter value a peer has already recorded
///   (which the peer would reject as a replay). **This is the load-bearing
///   field** — ISC-33.
/// - `seen` is the highest counter accepted per target `(signer-key /
///   server-id)` — ISC-34. The verifier ([`crate::identity_proof::verify_envelope`])
///   consumes this via its `highest_seen_counter` argument. Persisting it is
///   defense-in-depth: channel binding already defeats cross-session replay,
///   so a forgotten `seen` map across restart is not a vulnerability. **A
///   *server* MUST NOT persist its per-client `seen` map** (ISC-A-S1 / A-S12,
///   RAM-only) — that is the server orchestration's responsibility; this type
///   merely makes persistence *possible* for the client's per-server map.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CounterState {
    send_counter: u64,
    seen: BTreeMap<String, u64>,
}

impl CounterState {
    /// Increment and return the next send counter (first call returns 1).
    pub fn next_send(&mut self) -> u64 {
        self.send_counter += 1;
        self.send_counter
    }

    /// The current send counter without advancing it (0 if nothing sent).
    pub fn current_send(&self) -> u64 {
        self.send_counter
    }

    /// Highest counter accepted from `target`, or `None` if never seen.
    pub fn highest_seen(&self, target: &str) -> Option<u64> {
        self.seen.get(target).copied()
    }

    /// Record `counter` as seen from `target`, keeping the maximum. Call after
    /// a successful [`verify_envelope`](crate::identity_proof::verify_envelope).
    pub fn record_seen(&mut self, target: &str, counter: u64) {
        let entry = self.seen.entry(target.to_string()).or_insert(0);
        if counter > *entry {
            *entry = counter;
        }
    }
}

/// Plaintext payload of the at-rest blob. M1 carried only the mnemonic; M4b
/// adds replay-protection [`CounterState`]. M5+ extends it further with
/// circle-of-trust seed material, mute/hide lists, and settings.
///
/// ## Plaintext schema (directive lines)
///
/// The decrypted payload is line-based and **backward-compatible**: line 0 is
/// always the 24-word mnemonic phrase (the entire M1/M2/M3 payload), and any
/// following lines are `directive` entries — `send-counter <n>` and
/// `seen <target> <n>`. A bare-phrase payload (no extra lines, the legacy
/// form) parses with default counters, so existing blobs open without
/// re-enrollment. Default-counter seeds serialize back to the bare phrase, so
/// nothing changes on the wire until a counter is actually used. The
/// directive scheme is additive — future fields append new directive kinds
/// without a blob-format (magic) bump.
pub struct Seeds {
    pub mnemonic: Mnemonic,
    pub counters: CounterState,
}

impl core::fmt::Debug for Seeds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Seeds")
            .field("mnemonic", &"<redacted>")
            .field("counters", &self.counters)
            .finish()
    }
}

impl Seeds {
    /// A fresh payload wrapping `mnemonic` with empty counter state.
    pub fn new(mnemonic: Mnemonic) -> Self {
        Self {
            mnemonic,
            counters: CounterState::default(),
        }
    }

    fn to_plaintext(&self) -> String {
        let mut s = self.mnemonic.to_phrase();
        if self.counters.send_counter != 0 {
            s.push_str(&format!("\nsend-counter {}", self.counters.send_counter));
        }
        for (target, counter) in &self.counters.seen {
            s.push_str(&format!("\nseen {target} {counter}"));
        }
        s
    }

    fn from_plaintext(s: &str) -> Result<Self, BlobError> {
        let mut lines = s.lines();
        let phrase = lines.next().ok_or(BlobError::InvalidPlaintext)?;
        let mnemonic = Mnemonic::from_phrase(phrase).map_err(BlobError::Mnemonic)?;
        let mut counters = CounterState::default();
        for line in lines {
            let mut parts = line.splitn(3, ' ');
            match parts.next() {
                Some("send-counter") => {
                    let n = parts.next().ok_or(BlobError::InvalidPlaintext)?;
                    counters.send_counter = n.parse().map_err(|_| BlobError::InvalidPlaintext)?;
                }
                Some("seen") => {
                    let target = parts.next().ok_or(BlobError::InvalidPlaintext)?;
                    let n = parts.next().ok_or(BlobError::InvalidPlaintext)?;
                    let counter = n.parse().map_err(|_| BlobError::InvalidPlaintext)?;
                    counters.seen.insert(target.to_string(), counter);
                }
                _ => return Err(BlobError::InvalidPlaintext),
            }
        }
        Ok(Self { mnemonic, counters })
    }
}

/// Outcome of [`open`] — carries the recovered seeds plus the suite_id the
/// blob was sealed under. Callers (e.g. the orchestrator) use the
/// `suite_id` to decide whether [`touch_reseal`] is needed on the next save.
#[derive(Debug)]
pub struct Opened {
    pub seeds: Seeds,
    pub suite_id: SuiteId,
    /// `true` iff the blob was the legacy v1 format; consumers should
    /// schedule a [`touch_reseal`] on the next write to migrate the blob
    /// to v2 (ISC-C24 read-old-write-new).
    pub legacy_v1: bool,
}

/// Errors from [`seal`] / [`open`] / [`touch_reseal`].
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
    /// v2 blob carried a `suite_id` whose raw value is one of the reserved
    /// sentinels (`0x0000` / `0xFFFF`).
    SuiteIdSentinel(SuiteIdError),
    /// v2 blob carried a `suite_id` not present in this build's registry.
    UnknownSuite(SuiteId),
    /// Active write-suite refused by the registry (e.g. all suites
    /// deprecated). Returned by [`seal`] and [`touch_reseal`] when no
    /// write-eligible suite exists.
    WriteRefused(WriteRefusal),
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
            BlobError::SuiteIdSentinel(e) => write!(f, "at-rest blob suite_id: {e}"),
            BlobError::UnknownSuite(id) => {
                write!(f, "at-rest blob references unknown suite {id}")
            }
            BlobError::WriteRefused(r) => write!(f, "at-rest blob write refused: {r}"),
            BlobError::InvalidPlaintext => write!(f, "at-rest blob: plaintext failed schema check"),
            BlobError::Utf8(e) => write!(f, "at-rest blob plaintext is not UTF-8: {e}"),
            BlobError::Mnemonic(e) => write!(f, "mnemonic in at-rest blob: {e}"),
        }
    }
}

impl std::error::Error for BlobError {}

/// Encrypt a [`Seeds`] payload into the canonical v2 blob layout under the
/// active write-suite resolved from [`Registry::default_write_suite`].
///
/// The suite_id is embedded in the v2 header **and** bound into the AEAD
/// AAD so a tamper-swap of the suite tag fails authentication.
pub fn seal(
    seeds: &Seeds,
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Vec<u8>, BlobError> {
    let suite_id = Registry::default_write_suite();
    seal_under(seeds, passphrase, profile_id, params, suite_id)
}

/// Encrypt a [`Seeds`] payload under an explicit `suite_id`. Used by
/// [`touch_reseal`] and by tests that need to write a non-default suite.
/// The registry MUST contain `suite_id` and it MUST be write-eligible.
pub fn seal_under(
    seeds: &Seeds,
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
    suite_id: SuiteId,
) -> Result<Vec<u8>, BlobError> {
    Registry::resolve_for_write(suite_id).map_err(BlobError::WriteRefused)?;

    let mut key = derive_aead_key(passphrase, profile_id, params)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(BlobError::EntropySource)?;

    let aes = Aes256Key::new(&key).map_err(BlobError::AesKeyInit)?;
    key.zeroize();

    let plaintext_str = seeds.to_plaintext();
    let plaintext = plaintext_str.as_bytes();

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
    .map_err(BlobError::AesMode)?;

    let mut blob =
        Vec::with_capacity(MAGIC.len() + SUITE_ID_LEN + NONCE_LEN + ciphertext.len() + TAG_LEN);
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&suite_bytes);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&tag);
    Ok(blob)
}

/// Decrypt a v2 (or legacy v1) blob. Fails closed on wrong passphrase /
/// tampered blob / schema mismatch / unknown suite — no information leaks
/// about which check failed beyond the variant boundary.
///
/// Returns an [`Opened`] carrying both the recovered [`Seeds`] and the
/// `suite_id` the blob was sealed under, plus a `legacy_v1` flag so the
/// caller can schedule a [`touch_reseal`] on the next write.
pub fn open(
    blob: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Opened, BlobError> {
    if blob.len() < MAGIC.len() {
        return Err(BlobError::Malformed("blob shorter than magic prefix"));
    }
    let magic = &blob[..MAGIC.len()];
    if magic == MAGIC {
        open_v2(&blob[MAGIC.len()..], passphrase, profile_id, params)
    } else if magic == MAGIC_V1 {
        open_v1(&blob[MAGIC_V1.len()..], passphrase, profile_id, params)
    } else {
        Err(BlobError::Malformed("magic prefix mismatch"))
    }
}

fn open_v2(
    rest: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Opened, BlobError> {
    if rest.len() < SUITE_ID_LEN + NONCE_LEN + TAG_LEN {
        return Err(BlobError::Malformed(
            "v2 blob shorter than minimum header+tag",
        ));
    }
    let suite_bytes: [u8; SUITE_ID_LEN] = rest[..SUITE_ID_LEN].try_into().unwrap();
    let suite_raw = u16::from_be_bytes(suite_bytes);
    let suite_id = SuiteId::try_new(suite_raw).map_err(BlobError::SuiteIdSentinel)?;
    if Registry::lookup(suite_id).is_none() {
        return Err(BlobError::UnknownSuite(suite_id));
    }

    let after_suite = &rest[SUITE_ID_LEN..];
    let nonce: &[u8; NONCE_LEN] = after_suite[..NONCE_LEN].try_into().unwrap();
    let after_nonce = &after_suite[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();

    let mut key = derive_aead_key(passphrase, profile_id, params)?;
    let aes = Aes256Key::new(&key).map_err(BlobError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, nonce, &suite_bytes, ciphertext, tag, &mut plaintext).map_err(
        |e| match e {
            oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
            other => BlobError::AesMode(other),
        },
    )?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let seeds = Seeds::from_plaintext(plaintext_str)?;
    plaintext.zeroize();
    Ok(Opened {
        seeds,
        suite_id,
        legacy_v1: false,
    })
}

fn open_v1(
    rest: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Opened, BlobError> {
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(BlobError::Malformed(
            "v1 blob shorter than minimum header+tag",
        ));
    }
    let nonce: &[u8; NONCE_LEN] = rest[..NONCE_LEN].try_into().unwrap();
    let after_nonce = &rest[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();

    let mut key = derive_aead_key(passphrase, profile_id, params)?;
    let aes = Aes256Key::new(&key).map_err(BlobError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    // v1 used empty AAD — preserve that contract or M2 blobs fail to open.
    gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext).map_err(|e| match e {
        oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
        other => BlobError::AesMode(other),
    })?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let seeds = Seeds::from_plaintext(plaintext_str)?;
    plaintext.zeroize();
    // V1 predates the registry; the only suite that existed is 0x0001.
    let implicit = SuiteId::try_new(V1_IMPLICIT_SUITE_RAW)
        .expect("V1_IMPLICIT_SUITE_RAW is a valid non-sentinel id");
    Ok(Opened {
        seeds,
        suite_id: implicit,
        legacy_v1: true,
    })
}

/// Decrypt under the stored suite, re-encrypt as v2 under the active
/// write-suite. ISC-C24 "read-old, write-new on touch" — every save migrates
/// the blob to the current write-suite without flag-day coordination.
///
/// If the blob is already at the active write-suite, the function still
/// returns a re-sealed v2 blob (new nonce, same payload); callers may
/// short-circuit if `Opened::legacy_v1 == false` and `Opened::suite_id ==
/// Registry::default_write_suite()`. The function intentionally does no
/// short-circuit itself so the caller decides the policy.
pub fn touch_reseal(
    blob: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Vec<u8>, BlobError> {
    let opened = open(blob, passphrase, profile_id, params)?;
    let write_suite = Registry::default_write_suite();
    seal_under(&opened.seeds, passphrase, profile_id, params, write_suite)
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
    let hkdf = HkdfSha384::from_prk(&intermediate).map_err(BlobError::Hkdf)?;
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
        Seeds::new(Mnemonic::generate().unwrap())
    }

    #[test]
    fn fresh_seeds_have_default_counters() {
        let seeds = Seeds::new(Mnemonic::generate().unwrap());
        assert_eq!(seeds.counters.current_send(), 0);
        assert_eq!(seeds.counters.highest_seen("anything"), None);
    }

    #[test]
    fn counter_state_round_trips_through_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = Seeds::new(Mnemonic::generate().unwrap());
        assert_eq!(seeds.counters.next_send(), 1);
        assert_eq!(seeds.counters.next_send(), 2);
        seeds.counters.record_seen("srv#aabbccddeeff", 7);
        seeds.counters.record_seen("peer#001122334455", 3);

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.counters.current_send(), 2);
        assert_eq!(recovered.counters.highest_seen("srv#aabbccddeeff"), Some(7));
        assert_eq!(
            recovered.counters.highest_seen("peer#001122334455"),
            Some(3)
        );
        assert_eq!(recovered.counters.highest_seen("unknown"), None);
    }

    #[test]
    fn legacy_bare_phrase_blob_opens_with_default_counters() {
        // Default-counter seeds serialize to the bare-phrase plaintext (the
        // M1/M2/M3 form), so this exercises the backward-compatible read path:
        // an existing test-group blob must still open with no re-enrollment.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = Seeds::new(Mnemonic::generate().unwrap());
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.counters.current_send(), 0);
    }

    #[test]
    fn record_seen_keeps_the_highest() {
        let mut cs = CounterState::default();
        cs.record_seen("t", 5);
        cs.record_seen("t", 3); // lower — must be ignored
        assert_eq!(cs.highest_seen("t"), Some(5));
        cs.record_seen("t", 8);
        assert_eq!(cs.highest_seen("t"), Some(8));
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
        assert_eq!(recovered.seeds.mnemonic.to_phrase(), original_phrase);
        assert_eq!(recovered.suite_id.get(), 0x0001);
        assert!(!recovered.legacy_v1);
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
        let truncated = &blob[..MAGIC.len() + SUITE_ID_LEN + NONCE_LEN + 1];
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
    fn blob_magic_v2_is_pinned() {
        // Spec contract — bumping this is a format-incompatible change.
        assert_eq!(MAGIC, b"daemonseed/blob/v2\0");
    }

    #[test]
    fn blob_magic_v1_legacy_is_pinned() {
        // The v1 magic is the read-fallback anchor and must stay byte-stable
        // for as long as we ship code that accepts M1/M2 enrollments.
        assert_eq!(MAGIC_V1, b"daemonseed/blob/v1\0");
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

    /// Hand-build a v1 blob (M2 wire shape) and confirm `open` recovers
    /// it under the implicit `suite_id = 0x0001`. Without this test the
    /// v1→v2 migration claim is just words.
    #[test]
    fn open_accepts_legacy_v1_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let phrase = seeds.mnemonic.to_phrase();

        // Construct a v1 blob by hand using the same KDF chain seal() uses
        // but with the v1 layout: magic | nonce | ct | tag, AAD=b"".
        let mut key = derive_aead_key(pp, pid, test_params()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let aes = Aes256Key::new(&key).unwrap();
        key.zeroize();
        let pt = phrase.as_bytes();
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, b"", pt, &mut ct, &mut tag).unwrap();
        let mut v1_blob = Vec::with_capacity(MAGIC_V1.len() + NONCE_LEN + ct.len() + TAG_LEN);
        v1_blob.extend_from_slice(MAGIC_V1);
        v1_blob.extend_from_slice(&nonce);
        v1_blob.extend_from_slice(&ct);
        v1_blob.extend_from_slice(&tag);

        let opened = open(&v1_blob, pp, pid, test_params()).unwrap();
        assert_eq!(opened.seeds.mnemonic.to_phrase(), phrase);
        assert_eq!(opened.suite_id.get(), 0x0001);
        assert!(opened.legacy_v1);
    }

    /// touch_reseal migrates a v1 blob to v2 preserving payload — the
    /// ISC-C24 read-old / write-new property end-to-end.
    #[test]
    fn touch_reseal_migrates_v1_to_v2() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let phrase = seeds.mnemonic.to_phrase();

        // Forge a v1 blob the same way as the prior test.
        let mut key = derive_aead_key(pp, pid, test_params()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let aes = Aes256Key::new(&key).unwrap();
        key.zeroize();
        let pt = phrase.as_bytes();
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, b"", pt, &mut ct, &mut tag).unwrap();
        let mut v1_blob = Vec::with_capacity(MAGIC_V1.len() + NONCE_LEN + ct.len() + TAG_LEN);
        v1_blob.extend_from_slice(MAGIC_V1);
        v1_blob.extend_from_slice(&nonce);
        v1_blob.extend_from_slice(&ct);
        v1_blob.extend_from_slice(&tag);

        // Migrate.
        let v2_blob = touch_reseal(&v1_blob, pp, pid, test_params()).unwrap();
        assert_eq!(&v2_blob[..MAGIC.len()], MAGIC);
        assert_eq!(
            &v2_blob[MAGIC.len()..MAGIC.len() + SUITE_ID_LEN],
            &0x0001u16.to_be_bytes()
        );

        // Round-trip the migrated blob.
        let recovered = open(&v2_blob, pp, pid, test_params()).unwrap();
        assert_eq!(recovered.seeds.mnemonic.to_phrase(), phrase);
        assert_eq!(recovered.suite_id.get(), 0x0001);
        assert!(!recovered.legacy_v1);
    }

    /// AAD binding: flipping the suite_id byte in a v2 blob must fail
    /// authentication, because the suite_id is part of the AAD covered by
    /// the AEAD tag.
    #[test]
    fn v2_suite_id_tamper_fails_auth() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        // Tamper a suite_id byte while keeping the value within the
        // non-sentinel range — flip the low byte from 0x01 → 0x02.
        let suite_lo = MAGIC.len() + 1;
        assert_eq!(blob[suite_lo], 0x01);
        blob[suite_lo] = 0x02;
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::UnknownSuite(id)) => assert_eq!(id.get(), 0x0002),
            other => panic!("expected UnknownSuite, got {other:?}"),
        }
    }

    /// A v2 blob whose suite_id field encodes a reserved sentinel
    /// (`0x0000` / `0xFFFF`) is rejected as malformed before any AEAD work.
    #[test]
    fn v2_suite_id_sentinel_rejected() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        let suite_hi = MAGIC.len();
        let suite_lo = MAGIC.len() + 1;
        // Force the suite bytes to 0x0000 (invalid sentinel).
        blob[suite_hi] = 0x00;
        blob[suite_lo] = 0x00;
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::SuiteIdSentinel(_)) => {}
            other => panic!("expected SuiteIdSentinel, got {other:?}"),
        }
    }
}
