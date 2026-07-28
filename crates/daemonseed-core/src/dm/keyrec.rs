//! The DM **key record** — an identity's published static ML-KEM-1024
//! encapsulation key (ISC-C40).
//!
//! This is the whole of DM discovery. An identity's ML-DSA-87 public key already
//! rides on every provenance-signed artifact — chat and room messages, share
//! announcements, presence beacons — so anyone visible on a roster or in a
//! transcript can compute this record's address and encapsulate to its owner. No
//! new discovery surface, no roster, no handshake.
//!
//! Three properties do the work, and each is load-bearing
//! (`docs/design/direct-messaging.md` DRAFT v6):
//!
//! 1. **World-derivable address.** The Veilid owner seed is
//!    `HKDF(salt = DM_KEYREC_SALT, ikm = PK_lt, info = DM_KEYREC_OWNER)`. Anyone
//!    holding the identity pubkey derives it — that is the point, not a leak.
//! 2. **Forgery-proof, erasure-vulnerable.** A world-derivable address under DFLT
//!    means a world-derivable *owner*, so the record is world-writable. Accepted:
//!    the inner signature is verified against the pubkey the reader already used
//!    to derive the address, so nobody can forge a record for someone else's
//!    identity. Only erasure and rollback remain, and both are denial-of-service.
//! 3. **Presence-independent.** The record is written once and re-seeded against
//!    eviction on a fixed slow schedule that takes no input from user activity,
//!    so polling it reveals at most "this identity is DM-able" — never an
//!    online/offline rhythm. (The re-seed still tracks the owner's online windows
//!    at coarse eviction granularity; that residual is subsumed by the accepted,
//!    finer lobby-presence signal — ISC-A-C23.)
//!
//! **The record carries no identity pubkey.** It does not need one: the reader
//! derived the address from the pubkey, so that is what it verifies against.
//! Omitting it removes any field an attacker could substitute, and saves 2592
//! bytes on a record that must also hold a 4627-byte signature.

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;

use daemonseed_proto::v1 as wire;

use crate::dm::domain;
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Slots in a key record — the `o_cnt` of its `dflt(o_cnt)` schema, and part of
/// the record's address.
///
/// One: the record holds a single signed value and nothing else. A writer MUST
/// build its `RecordShape` from this constant rather than a literal (ISC-C100).
pub const KEY_RECORD_SLOTS: u16 = 1;

/// Byte length of the Veilid owner seed this module derives.
pub const DM_KEYREC_OWNER_SEED_LEN: usize = 32;

/// The first-contact anti-replay period, in seconds (one week).
///
/// `fc_epoch = floor(now / FC_PERIOD_SECS)` is derived from the wall clock by
/// **both** parties and is deliberately NOT published anywhere — see
/// [`fc_epoch`]. Slow on purpose: the window must be wide enough that a
/// first-contact entry composed while the recipient is offline is still current
/// when they collect it. FROZEN.
pub const FC_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

/// Byte length of an ML-KEM-1024 encapsulation key.
///
/// Re-exported so a frontend can name the type without taking a direct
/// dependency on `oxicrypt-ml-kem`. The crypto crates are `daemonseed-core`'s
/// concern; a UI crate should be able to carry the key without linking them.
pub const KEM_EK_LEN: usize = ml_kem::EK_LEN;

/// An identity's public ML-KEM-1024 encapsulation key — the half that is
/// published. Boxed because it is 1568 bytes and gets moved through command
/// channels; never the decapsulation key, which stays in `IdentityKeys`.
pub type KemEncapsulationKey = Box<[u8; KEM_EK_LEN]>;

/// The `version` every alpha client publishes.
///
/// The identity's KEM keypair is derived deterministically from the recovery
/// phrase and never rotates in alpha, so there is exactly one key to publish and
/// one version to publish it at. The monotonic field exists for the rotation this
/// build does not yet do — a future rotation bumps it, and
/// [`KeyRecordCache`]'s highest-verified-wins rule is what stops the pre-rotation
/// record being replayed over it. Publishing a constant is therefore correct
/// today and forward-compatible, not a placeholder.
pub const DM_KEY_RECORD_VERSION: u64 = 1;

/// Whether an alpha client advertises an invite-only first-contact policy.
///
/// `false`: there is no UI to set the policy and no invite-token issuance yet, so
/// advertising `true` would promise an admission gate nothing can satisfy. The
/// recipient enforces its real policy at admission regardless of what the record
/// advertises, so this is an advert, never the enforcement point (ISC-C41).
pub const DM_KEY_RECORD_INVITE_ONLY: bool = false;

/// Lower bound of the jittered key-record re-seed interval.
///
/// Veilid has no TTL — retention is capacity-eviction only — so a published record
/// survives exactly as long as its owner re-seeds it. The cadence is deliberately
/// slow: the frozen design budgets the key-record keep-alive at ~0.02 writes/min
/// against the WB-2 ceiling of 4/min, and this band's ~50-minute mean lands there.
pub const RESEED_INTERVAL_MIN: std::time::Duration = std::time::Duration::from_secs(40 * 60);

/// Upper bound of the jittered key-record re-seed interval.
pub const RESEED_INTERVAL_MAX: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// A fresh re-seed delay drawn uniformly from
/// `[RESEED_INTERVAL_MIN, RESEED_INTERVAL_MAX]`.
///
/// Jitter is drawn **per emission**, never once per session, and takes no input
/// from user activity — the WB-1.2 pattern, and the fix the design's M7 finding
/// asks for. A fixed period would give the record a recognisable cadence
/// signature and, across records, a stable phase relationship that is itself a
/// linkage channel (WB-3 I6). An entropy failure falls back to the midpoint: a
/// re-seed is liveness, not a key, and the next draw recovers.
pub fn next_reseed_interval() -> std::time::Duration {
    let min_ms = RESEED_INTERVAL_MIN.as_millis() as u64;
    let max_ms = RESEED_INTERVAL_MAX.as_millis() as u64;
    let span = max_ms - min_ms;
    let mut buf = [0u8; 8];
    let offset = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf) % (span + 1),
        Err(_) => span / 2,
    };
    std::time::Duration::from_millis(min_ms + offset)
}

redacted_secret_newtype! {
    /// The Veilid record-owner seed for an identity's key record.
    ///
    /// Named a "secret" seed for consistency with its siblings and to get the
    /// zeroize-on-drop and redacted-`Debug` hygiene, but it is deliberately
    /// **world-derivable** — anyone with the identity's public key computes the
    /// same value. Holding it confers write access to the record, which is why
    /// the record's integrity rests on the inner signature and not on ownership.
    boxed pub struct DmKeyRecordOwnerSeed([u8; DM_KEYREC_OWNER_SEED_LEN]);
}

/// Why a key record was rejected.
///
/// `PartialEq` is implemented by hand rather than derived because
/// [`SignatureError`] is not comparable; two [`Self::Signing`] values compare
/// equal on the variant alone, which is all any caller needs (the wrapped cause
/// is for humans and logs, not for control flow).
#[derive(Debug)]
pub enum DmKeyRecordError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// A signature did not verify against the identity key.
    ///
    /// **Verify-path only, and deliberately uniform.** It does not distinguish
    /// tampered-message from wrong-key from forged-signature, matching the
    /// existing `SignatureError::BadSignature` convention (ISC-A-S12 /
    /// ISC-A-C18): a verifier must not become an oracle. Nothing is lost by
    /// collapsing here, because `verify_signature` has already flattened every
    /// underlying cause before this module sees it. A LOCAL signing failure is
    /// [`Self::Signing`], never this.
    Signature,
    /// The fetched bytes are not a decodable `DmKeyRecord`. The record is
    /// world-writable, so arbitrary bytes in the slot are an expected input, not
    /// an exceptional one — rejected exactly as a bad signature is.
    Malformed,
    /// A local signing operation failed while BUILDING a record — the crypto
    /// module is not operational, or the active profile disallows ML-DSA
    /// signing. Carries the cause: there is no adversary on this path and no
    /// anti-oracle reason to hide why, and a FIPS-mode policy refusal reported
    /// as "signature did not verify" would send a reader hunting for tampering
    /// that never happened.
    Signing(SignatureError),
    /// A length-gated field was absent or the wrong size. Carries what was
    /// expected and what arrived, so a truncation is diagnosable.
    FieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The record's `version` is older than the highest already verified for this
    /// identity — a replayed pre-rotation blob. Denial-of-service only, but never
    /// accepted.
    VersionRegression { cached: u64, offered: u64 },
}

impl PartialEq for DmKeyRecordError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Kdf(a), Self::Kdf(b)) => a == b,
            (Self::Signature, Self::Signature) => true,
            (Self::Malformed, Self::Malformed) => true,
            // Compared on the variant: the wrapped cause is diagnostic, and
            // `SignatureError` is not itself comparable.
            (Self::Signing(_), Self::Signing(_)) => true,
            (
                Self::FieldLength {
                    field: fa,
                    expected: ea,
                    actual: aa,
                },
                Self::FieldLength {
                    field: fb,
                    expected: eb,
                    actual: ab,
                },
            ) => fa == fb && ea == eb && aa == ab,
            (
                Self::VersionRegression {
                    cached: ca,
                    offered: oa,
                },
                Self::VersionRegression {
                    cached: cb,
                    offered: ob,
                },
            ) => ca == cb && oa == ob,
            _ => false,
        }
    }
}

impl Eq for DmKeyRecordError {}

impl std::fmt::Display for DmKeyRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "key-record HKDF failed: {e:?}"),
            Self::Signature => write!(f, "key-record signature did not verify"),
            Self::Malformed => write!(f, "key-record bytes are not a decodable DmKeyRecord"),
            Self::Signing(e) => write!(f, "key-record could not be signed locally: {e:?}"),
            Self::FieldLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "key-record {field}: expected {expected} bytes, got {actual}"
            ),
            Self::VersionRegression { cached, offered } => write!(
                f,
                "key-record version regression: cached {cached}, offered {offered}"
            ),
        }
    }
}

impl std::error::Error for DmKeyRecordError {}

/// The first-contact anti-replay epoch for a wall-clock instant.
///
/// Both parties derive this from the clock alone. That is the whole design:
/// an earlier draft had the recipient publish a nonce it rotated on restart,
/// which made the key record a **restart oracle** (an observer watching the
/// nonce change learned when the identity restarted) and coupled first-contact
/// availability to recipient-side state. Deriving from the clock removes the
/// oracle, the state, and the coupling at once.
///
/// A recipient accepts the current epoch and the previous one, so a sender whose
/// entry was composed just before a boundary is not spuriously rejected; older
/// epochs are stale replays. No seen-set has to be persisted.
pub fn fc_epoch(now_unix_secs: u64) -> u64 {
    now_unix_secs / FC_PERIOD_SECS
}

/// Whether `offered` is within the accept window for `current` — the current
/// epoch or the one immediately before it.
///
/// Expressed as a range against `current` rather than as `offered + 1 == current`
/// because `offered` arrives **on the wire** (a first-contact entry binds it, per
/// ISC-C41) and is therefore attacker-controlled: an `offered` of `u64::MAX` would
/// overflow that addition — panicking in a debug build, and in a release build
/// wrapping to `0 == 0` so that `u64::MAX` was accepted as the epoch "before" 0.
/// `saturating_sub` also gives the right answer at `current == 0`, where there is
/// no previous epoch to accept.
pub fn fc_epoch_is_current(offered: u64, current: u64) -> bool {
    offered <= current && offered >= current.saturating_sub(1)
}

/// Derive the world-derivable Veilid owner seed for `identity_pubkey`'s key
/// record: `HKDF-SHA-384(salt = DM_KEYREC_SALT, ikm = PK_lt, info = DM_KEYREC_OWNER)`.
///
/// Deterministic and pure — no clock, no randomness, no network. Every reader
/// and the owner itself compute the same value, which is what makes the record
/// findable from a pubkey alone.
pub fn derive_owner_seed(
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<DmKeyRecordOwnerSeed, DmKeyRecordError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_KEYREC_SALT), identity_pubkey)
        .map_err(DmKeyRecordError::Kdf)?;
    let seed = derive_boxed_seed::<DM_KEYREC_OWNER_SEED_LEN>(&hkdf, domain::DM_KEYREC_OWNER)
        .map_err(DmKeyRecordError::Kdf)?;
    Ok(DmKeyRecordOwnerSeed(seed))
}

/// Build the domain-separated signing preimage.
///
/// Every variable-length field is length-prefixed (`u64` big-endian length ‖
/// bytes), matching [`crate::room_message::provenance_input`] and
/// `share_announce::push_lp`, so the concatenation is unambiguous and no pair of
/// adjacent fields can be re-split to forge a different tuple. Integers are
/// big-endian for the same consistency.
///
/// Binding `identity_pubkey` inside the preimage is what ties a record to exactly
/// one identity: the same `(version, kem_ek, invite_only)` signed for identity A
/// will not verify at identity B's address, because B's reader feeds B's pubkey
/// into this function.
pub fn signing_input(
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
    version: u64,
    kem_ek: &[u8; ml_kem::EK_LEN],
    invite_only: bool,
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(domain::DM_KEYREC_SIG.len() + ml_dsa::PK_LEN + ml_kem::EK_LEN + 64);
    buf.extend_from_slice(domain::DM_KEYREC_SIG);
    let mut push_lp = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    push_lp(identity_pubkey);
    push_lp(&version.to_be_bytes());
    push_lp(kem_ek);
    push_lp(&[u8::from(invite_only)]);
    buf
}

/// A key record whose signature verified against the identity that owns its
/// address. Only constructible via [`verify`], so holding one IS the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKeyRecord {
    /// The monotonic version this record asserts.
    pub version: u64,
    /// The identity's static ML-KEM-1024 encapsulation key.
    pub kem_ek: Box<[u8; ml_kem::EK_LEN]>,
    /// Whether first contact requires a grantee-bound one-time invite token.
    pub invite_only: bool,
}

/// Sign and assemble a key record for publication.
pub fn build(
    signing: &SignKeypair,
    kem_ek: &[u8; ml_kem::EK_LEN],
    version: u64,
    invite_only: bool,
) -> Result<wire::DmKeyRecord, DmKeyRecordError> {
    let preimage = signing_input(signing.public_key(), version, kem_ek, invite_only);
    let sig = signing.sign(&preimage).map_err(DmKeyRecordError::Signing)?;
    Ok(wire::DmKeyRecord {
        version,
        kem_ek: kem_ek.to_vec(),
        invite_only,
        signature: sig.to_vec(),
    })
}

/// Sign, assemble, and **encode** a key record ready for publication.
///
/// The wire-encoding wrapper over [`build`]. Frontends publish opaque bytes and
/// should not have to know — or depend on a protobuf crate to express — how a
/// record is serialised; that is this crate's business. `daemonseed-tui` has no
/// `prost` dependency at all, and adding one so a UI crate could call
/// `encode_to_vec` would be the wrong direction.
pub fn build_encoded(
    signing: &SignKeypair,
    kem_ek: &[u8; ml_kem::EK_LEN],
    version: u64,
    invite_only: bool,
) -> Result<Vec<u8>, DmKeyRecordError> {
    use prost::Message as _;
    Ok(build(signing, kem_ek, version, invite_only)?.encode_to_vec())
}

/// Decode a fetched key record and verify it against `identity_pubkey` in one
/// step — the read counterpart of [`build_encoded`], so a caller handling raw DHT
/// bytes never needs prost either. A record that does not decode is rejected the
/// same way a record that does not verify is: fail closed.
pub fn decode_and_verify(
    bytes: &[u8],
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<VerifiedKeyRecord, DmKeyRecordError> {
    use prost::Message as _;
    let record = wire::DmKeyRecord::decode(bytes).map_err(|_| DmKeyRecordError::Malformed)?;
    verify(&record, identity_pubkey)
}

/// Verify a fetched key record against `identity_pubkey` — the SAME pubkey the
/// reader derived the record's address from, never anything carried in the
/// record (which carries no pubkey precisely so there is nothing to substitute).
///
/// Fails closed on a wrong-length `kem_ek` or `signature`: both are exact-length
/// gated with `try_into` *before* any ML-DSA call, mirroring
/// `room_message`'s rule that an empty pubkey is not "anyone".
pub fn verify(
    record: &wire::DmKeyRecord,
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<VerifiedKeyRecord, DmKeyRecordError> {
    let kem_ek: Box<[u8; ml_kem::EK_LEN]> = record
        .kem_ek
        .as_slice()
        .try_into()
        .map(Box::new)
        .map_err(|_| DmKeyRecordError::FieldLength {
            field: "kem_ek",
            expected: ml_kem::EK_LEN,
            actual: record.kem_ek.len(),
        })?;
    let sig: [u8; ml_dsa::SIG_LEN] =
        record
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| DmKeyRecordError::FieldLength {
                field: "signature",
                expected: ml_dsa::SIG_LEN,
                actual: record.signature.len(),
            })?;

    let preimage = signing_input(identity_pubkey, record.version, &kem_ek, record.invite_only);
    verify_signature(identity_pubkey, &preimage, &sig).map_err(|_| DmKeyRecordError::Signature)?;

    Ok(VerifiedKeyRecord {
        version: record.version,
        kem_ek,
        invite_only: record.invite_only,
    })
}

/// Highest-verified-version-wins cache for one correspondent's key record.
///
/// The record is world-writable, so an attacker can plant an *authentic* older
/// record (they cannot forge one, but they can replay a real one the owner
/// signed before a key rotation). This cache is the defence: a reader keeps the
/// highest version it has verified and refuses to regress, so a rotation cannot
/// be reverted. The residual is a genuinely cold reader — one with no cached
/// version at all — which will accept whatever authentic record it is served;
/// that is the accepted M1 rollback residual (ISC-A-C23), bounded to
/// denial-of-service because the attacker still cannot produce a key the
/// identity never published.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyRecordCache {
    current: Option<VerifiedKeyRecord>,
}

impl KeyRecordCache {
    /// An empty cache — a reader that has never verified a record for this
    /// identity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a cache from an already-verified record (e.g. restored from the
    /// at-rest contact cache across a restart).
    pub fn from_verified(record: VerifiedKeyRecord) -> Self {
        Self {
            current: Some(record),
        }
    }

    /// The highest verified record, if any.
    pub fn current(&self) -> Option<&VerifiedKeyRecord> {
        self.current.as_ref()
    }

    /// The highest verified version, if any.
    pub fn version(&self) -> Option<u64> {
        self.current.as_ref().map(|r| r.version)
    }

    /// Verify `record` against `identity_pubkey` and, if it is at least as new as
    /// what is cached, adopt it.
    ///
    /// A record equal to the cached version is accepted and replaces it — the
    /// signature verified, so it is the same authentic content, and accepting it
    /// keeps a re-seed idempotent. A strictly older one is rejected with
    /// [`DmKeyRecordError::VersionRegression`] and the cache is left untouched.
    pub fn accept(
        &mut self,
        record: &wire::DmKeyRecord,
        identity_pubkey: &[u8; ml_dsa::PK_LEN],
    ) -> Result<&VerifiedKeyRecord, DmKeyRecordError> {
        let verified = verify(record, identity_pubkey)?;
        if let Some(cached) = &self.current
            && verified.version < cached.version
        {
            return Err(DmKeyRecordError::VersionRegression {
                cached: cached.version,
                offered: verified.version,
            });
        }
        // `Option::insert` hands back the reference it just stored, so the
        // "assigned Some, therefore Some" invariant is structural rather than
        // asserted — a later edit cannot open a gap between the two.
        Ok(&*self.current.insert(verified))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";

    const PHRASE_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                            zoo zoo zoo zoo zoo zoo zoo vote";

    fn keys(phrase: &str) -> IdentityKeys {
        let _ = oxicrypt_module::initialize();
        derive_identity_keys(&Mnemonic::from_phrase(phrase).unwrap(), Identity::Primary).unwrap()
    }

    fn alice() -> IdentityKeys {
        keys(PHRASE_A)
    }

    /// A fixed second identity, never `Mnemonic::generate()`. Every assertion
    /// against Bob is an inequality or a must-fail, so a random identity could
    /// not make a test spuriously pass — but it would make an intermittent
    /// failure unreplayable from the source, which is the whole reason the
    /// first identity is a fixed vector too.
    fn bob() -> IdentityKeys {
        keys(PHRASE_B)
    }

    /// The address must be a pure function of the identity's public key —
    /// that is what lets any holder of a signed artifact find the record.
    #[test]
    fn owner_seed_is_deterministic_from_the_identity_pubkey() {
        let a = alice();
        let first = derive_owner_seed(a.signing.public_key()).unwrap();
        let second = derive_owner_seed(a.signing.public_key()).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    /// Distinct identities must never collide onto one key record.
    #[test]
    fn owner_seed_separates_distinct_identities() {
        let a = alice();
        let b = bob();
        let sa = derive_owner_seed(a.signing.public_key()).unwrap();
        let sb = derive_owner_seed(b.signing.public_key()).unwrap();
        assert_ne!(sa.as_bytes(), sb.as_bytes());
    }

    /// The seed must not be the pubkey (or a prefix of it) — it is an HKDF
    /// output, and a reader must not be able to invert it.
    #[test]
    fn owner_seed_is_not_the_pubkey_material() {
        let a = alice();
        let seed = derive_owner_seed(a.signing.public_key()).unwrap();
        assert_ne!(&seed.as_bytes()[..], &a.signing.public_key()[..32]);
    }

    #[test]
    fn build_then_verify_round_trips() {
        let a = alice();
        let rec = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        let v = verify(&rec, a.signing.public_key()).unwrap();
        assert_eq!(v.version, 1);
        assert_eq!(&v.kem_ek[..], &a.kem.encapsulation_key()[..]);
        assert!(!v.invite_only);
    }

    #[test]
    fn invite_only_flag_round_trips_and_is_signed() {
        let a = alice();
        let mut rec = build(&a.signing, a.kem.encapsulation_key(), 4, true).unwrap();
        assert!(verify(&rec, a.signing.public_key()).unwrap().invite_only);
        // Flipping the advertised policy must break the signature — the flag is
        // inside the preimage, not decoration.
        rec.invite_only = false;
        assert_eq!(
            verify(&rec, a.signing.public_key()),
            Err(DmKeyRecordError::Signature)
        );
    }

    /// The core anti-forgery property: a record signed by one identity must not
    /// verify at another identity's address, because the reader feeds its OWN
    /// pubkey into the preimage.
    #[test]
    fn a_record_does_not_verify_against_another_identity() {
        let a = alice();
        let b = bob();
        let rec = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        assert_eq!(
            verify(&rec, b.signing.public_key()),
            Err(DmKeyRecordError::Signature)
        );
    }

    /// Substituting the KEM key — the entire point of the record — must break the
    /// signature. Otherwise an attacker could redirect encapsulation to a key
    /// they hold.
    #[test]
    fn a_substituted_kem_key_is_rejected() {
        let a = alice();
        let b = bob();
        let mut rec = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        rec.kem_ek = b.kem.encapsulation_key().to_vec();
        assert_eq!(
            verify(&rec, a.signing.public_key()),
            Err(DmKeyRecordError::Signature)
        );
    }

    #[test]
    fn a_bumped_version_is_rejected_without_a_fresh_signature() {
        let a = alice();
        let mut rec = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        rec.version = 99;
        assert_eq!(
            verify(&rec, a.signing.public_key()),
            Err(DmKeyRecordError::Signature)
        );
    }

    /// Fail closed on malformed lengths BEFORE any ML-DSA call — an absent or
    /// truncated field is never "anyone" (the `room_message` rule).
    #[test]
    fn wrong_length_fields_fail_closed_with_a_diagnosable_error() {
        let a = alice();
        let good = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();

        let mut short_ek = good.clone();
        short_ek.kem_ek.truncate(1567);
        assert_eq!(
            verify(&short_ek, a.signing.public_key()),
            Err(DmKeyRecordError::FieldLength {
                field: "kem_ek",
                expected: ml_kem::EK_LEN,
                actual: 1567
            })
        );

        let mut empty_ek = good.clone();
        empty_ek.kem_ek.clear();
        assert!(matches!(
            verify(&empty_ek, a.signing.public_key()),
            Err(DmKeyRecordError::FieldLength {
                field: "kem_ek",
                ..
            })
        ));

        let mut short_sig = good.clone();
        short_sig.signature.truncate(10);
        assert!(matches!(
            verify(&short_sig, a.signing.public_key()),
            Err(DmKeyRecordError::FieldLength {
                field: "signature",
                ..
            })
        ));

        let mut empty_sig = good;
        empty_sig.signature.clear();
        assert!(matches!(
            verify(&empty_sig, a.signing.public_key()),
            Err(DmKeyRecordError::FieldLength {
                field: "signature",
                ..
            })
        ));
    }

    /// Length-prefixing must make the preimage unambiguous: no two distinct
    /// field tuples may produce the same bytes.
    #[test]
    fn signing_input_is_unambiguous_across_fields() {
        let a = alice();
        let pk = a.signing.public_key();
        let ek = a.kem.encapsulation_key();
        let base = signing_input(pk, 1, ek, false);
        assert_ne!(base, signing_input(pk, 2, ek, false));
        assert_ne!(base, signing_input(pk, 1, ek, true));
        assert_ne!(
            base,
            signing_input(bob().signing.public_key(), 1, ek, false)
        );
        assert!(base.starts_with(domain::DM_KEYREC_SIG));
    }

    // ── rollback: highest-verified-version-wins ──────────────────────────────

    #[test]
    fn cache_adopts_a_newer_version_and_refuses_an_older_one() {
        let a = alice();
        let pk = a.signing.public_key();
        let v1 = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        let v5 = build(&a.signing, a.kem.encapsulation_key(), 5, false).unwrap();

        let mut cache = KeyRecordCache::new();
        assert_eq!(cache.version(), None);
        cache.accept(&v1, pk).unwrap();
        assert_eq!(cache.version(), Some(1));
        cache.accept(&v5, pk).unwrap();
        assert_eq!(cache.version(), Some(5));

        // The rollback attack: replay the older AUTHENTIC record.
        assert_eq!(
            cache.accept(&v1, pk),
            Err(DmKeyRecordError::VersionRegression {
                cached: 5,
                offered: 1
            })
        );
        assert_eq!(
            cache.version(),
            Some(5),
            "a refused record must not regress"
        );
    }

    /// A re-seed of the same version is idempotent, not a regression — the owner
    /// re-publishes the identical record against eviction constantly.
    #[test]
    fn cache_accepts_an_equal_version_idempotently() {
        let a = alice();
        let pk = a.signing.public_key();
        let v3 = build(&a.signing, a.kem.encapsulation_key(), 3, false).unwrap();
        let mut cache = KeyRecordCache::new();
        cache.accept(&v3, pk).unwrap();
        cache.accept(&v3, pk).unwrap();
        assert_eq!(cache.version(), Some(3));
    }

    /// A forged record must never disturb a good cached one.
    #[test]
    fn cache_rejects_an_unverifiable_record_without_disturbing_the_cache() {
        let a = alice();
        let b = bob();
        let pk = a.signing.public_key();
        let v2 = build(&a.signing, a.kem.encapsulation_key(), 2, false).unwrap();
        let forged = build(&b.signing, b.kem.encapsulation_key(), 9, false).unwrap();

        let mut cache = KeyRecordCache::new();
        cache.accept(&v2, pk).unwrap();
        assert_eq!(cache.accept(&forged, pk), Err(DmKeyRecordError::Signature));
        assert_eq!(cache.version(), Some(2));
    }

    /// The accepted M1 residual, pinned so it stays a known limit rather than a
    /// surprise: a genuinely cold reader has no floor to enforce and will accept
    /// whatever authentic record it is served.
    #[test]
    fn a_cold_cache_accepts_any_authentic_version_the_m1_residual() {
        let a = alice();
        let old = build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        let mut cache = KeyRecordCache::new();
        cache.accept(&old, a.signing.public_key()).unwrap();
        assert_eq!(cache.version(), Some(1));
    }

    // ── fc_epoch ─────────────────────────────────────────────────────────────

    #[test]
    fn fc_epoch_is_a_pure_function_of_the_clock() {
        assert_eq!(fc_epoch(0), 0);
        assert_eq!(fc_epoch(FC_PERIOD_SECS - 1), 0);
        assert_eq!(fc_epoch(FC_PERIOD_SECS), 1);
        assert_eq!(fc_epoch(FC_PERIOD_SECS * 3 + 5), 3);
    }

    /// The window is current-or-previous: wide enough that an entry composed just
    /// before a boundary still lands, narrow enough that older epochs are stale.
    #[test]
    fn fc_epoch_window_accepts_current_and_previous_only() {
        assert!(fc_epoch_is_current(7, 7));
        assert!(fc_epoch_is_current(6, 7), "previous epoch is in-window");
        assert!(!fc_epoch_is_current(5, 7), "two epochs back is stale");
        assert!(
            !fc_epoch_is_current(8, 7),
            "a future epoch is not accepted either"
        );
    }

    /// One week, pinned. The period is a wire-visible constant: both parties
    /// derive the epoch from it, so changing it desynchronises first contact.
    #[test]
    fn fc_period_is_one_week() {
        assert_eq!(FC_PERIOD_SECS, 604_800);
    }

    /// `offered` arrives on the wire, so the window arithmetic must survive a
    /// hostile value. `u64::MAX` must be rejected, not panic (debug) and not wrap
    /// into "the epoch before 0" (release).
    #[test]
    fn fc_epoch_window_is_overflow_safe_against_a_hostile_offered() {
        assert!(!fc_epoch_is_current(u64::MAX, 0));
        assert!(!fc_epoch_is_current(u64::MAX, 7));
        assert!(fc_epoch_is_current(u64::MAX, u64::MAX));
        assert!(fc_epoch_is_current(u64::MAX - 1, u64::MAX));
        // At epoch 0 there is no previous epoch to accept.
        assert!(fc_epoch_is_current(0, 0));
        assert!(!fc_epoch_is_current(1, 0));
    }

    /// Version bounds round-trip, so the big-endian encoding in the preimage and
    /// the comparison in the cache both behave at the extremes.
    #[test]
    fn version_bounds_round_trip_and_order_correctly() {
        let a = alice();
        let pk = a.signing.public_key();
        let v0 = build(&a.signing, a.kem.encapsulation_key(), 0, false).unwrap();
        let vmax = build(&a.signing, a.kem.encapsulation_key(), u64::MAX, false).unwrap();
        assert_eq!(verify(&v0, pk).unwrap().version, 0);
        assert_eq!(verify(&vmax, pk).unwrap().version, u64::MAX);

        let mut cache = KeyRecordCache::new();
        cache.accept(&v0, pk).unwrap();
        assert_eq!(cache.version(), Some(0));
        cache.accept(&vmax, pk).unwrap();
        assert_eq!(cache.version(), Some(u64::MAX));
        assert_eq!(
            cache.accept(&v0, pk),
            Err(DmKeyRecordError::VersionRegression {
                cached: u64::MAX,
                offered: 0
            })
        );
    }

    /// "Never verified" and "verified version 0" must stay distinguishable, or a
    /// caller doing `version().unwrap_or(0)` would treat a cold cache as having a
    /// floor it does not have.
    #[test]
    fn a_cold_cache_is_distinguishable_from_one_holding_version_zero() {
        let a = alice();
        let cold = KeyRecordCache::new();
        assert_eq!(cold.version(), None);
        assert!(cold.current().is_none());

        let mut warm = KeyRecordCache::new();
        warm.accept(
            &build(&a.signing, a.kem.encapsulation_key(), 0, false).unwrap(),
            a.signing.public_key(),
        )
        .unwrap();
        assert_eq!(warm.version(), Some(0));
    }

    /// A well-formed signature with a flipped bit must fail — the length gates
    /// pass, so this exercises ML-DSA's own rejection at this call site rather
    /// than the pre-checks.
    #[test]
    fn a_bit_flipped_signature_of_correct_length_is_rejected() {
        let a = alice();
        let mut rec = build(&a.signing, a.kem.encapsulation_key(), 2, false).unwrap();
        let len = rec.signature.len();
        assert_eq!(len, ml_dsa::SIG_LEN, "precondition: length gate would pass");
        rec.signature[len / 2] ^= 0x01;
        assert_eq!(
            verify(&rec, a.signing.public_key()),
            Err(DmKeyRecordError::Signature)
        );
    }

    /// **Documented behaviour, not an endorsement.** The version guard compares
    /// versions only, never content, so two authentically-signed records at the
    /// SAME version but with different payloads both verify and the later one
    /// wins. Only the identity's own key can produce them (an attacker cannot
    /// forge either), so the reachable causes are a multi-device owner or two
    /// racing re-seeds — but a reader cannot detect the equivocation. Pinned so
    /// the behaviour is a deliberate, reviewed choice; tightening it would mean
    /// treating equal-version-different-content as an error.
    #[test]
    fn equal_version_with_different_content_is_accepted_last_writer_wins() {
        let a = alice();
        let pk = a.signing.public_key();
        let permissive = build(&a.signing, a.kem.encapsulation_key(), 3, false).unwrap();
        let invite_only = build(&a.signing, a.kem.encapsulation_key(), 3, true).unwrap();

        let mut cache = KeyRecordCache::new();
        cache.accept(&permissive, pk).unwrap();
        assert!(!cache.current().unwrap().invite_only);
        cache.accept(&invite_only, pk).unwrap();
        assert!(
            cache.current().unwrap().invite_only,
            "equal version, different content: last verified write wins"
        );
        assert_eq!(cache.version(), Some(3));
    }

    /// **Caller responsibility, pinned.** A `KeyRecordCache` holds no identity
    /// binding — it is whatever the caller verified against. Handing it a record
    /// for a different correspondent, with that correspondent's pubkey, verifies
    /// and is adopted. Correct at the crypto layer (nothing is forged) but an
    /// API footgun, so the contract is stated here: one cache per correspondent,
    /// and the caller supplies the matching pubkey.
    #[test]
    fn cache_has_no_identity_binding_and_adopts_any_correctly_verified_record() {
        let a = alice();
        let b = bob();
        let mut cache = KeyRecordCache::new();
        cache
            .accept(
                &build(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap(),
                a.signing.public_key(),
            )
            .unwrap();
        // A different correspondent entirely, verified against ITS own pubkey.
        cache
            .accept(
                &build(&b.signing, b.kem.encapsulation_key(), 2, false).unwrap(),
                b.signing.public_key(),
            )
            .unwrap();
        assert_eq!(
            &cache.current().unwrap().kem_ek[..],
            &b.kem.encapsulation_key()[..],
            "the cache tracks versions, not identities — one cache per correspondent"
        );
    }

    /// The re-seed cadence must sit in its band and must actually vary — a fixed
    /// period would give the record a recognisable signature (WB-1.2 / M7).
    #[test]
    fn reseed_interval_is_in_band_and_jittered() {
        let draws: Vec<_> = (0..64).map(|_| next_reseed_interval()).collect();
        for d in &draws {
            assert!(
                *d >= RESEED_INTERVAL_MIN && *d <= RESEED_INTERVAL_MAX,
                "{d:?} outside [{RESEED_INTERVAL_MIN:?}, {RESEED_INTERVAL_MAX:?}]"
            );
        }
        let distinct: std::collections::BTreeSet<_> = draws.iter().collect();
        assert!(
            distinct.len() > 1,
            "64 draws collapsed to one value — the cadence is not jittered"
        );
    }

    /// The budgeted rate the frozen design assumes: ~0.02 writes/min against the
    /// WB-2 ceiling of 4/min. Pinned so widening the band silently is caught.
    #[test]
    fn reseed_cadence_matches_the_budgeted_rate() {
        let mean_secs =
            (RESEED_INTERVAL_MIN.as_secs() + RESEED_INTERVAL_MAX.as_secs()) as f64 / 2.0;
        let writes_per_min = 60.0 / mean_secs;
        assert!(
            (writes_per_min - 0.02).abs() < 0.005,
            "key-record keep-alive is {writes_per_min:.4}/min, design budgets ~0.02/min"
        );
    }

    /// The alpha publish constants, pinned. Not tautologies: they assert the
    /// values a running client actually puts on the wire, so changing either
    /// becomes a deliberate, reviewed act rather than an edit nobody notices.
    #[test]
    fn alpha_publishes_version_one_and_no_invite_policy() {
        const _: () = assert!(DM_KEY_RECORD_VERSION == 1);
        const _: () = assert!(!DM_KEY_RECORD_INVITE_ONLY);
        // Also exercise them through the real build path, so the constants are
        // pinned where they are USED, not only where they are declared.
        let a = alice();
        let rec = build(
            &a.signing,
            a.kem.encapsulation_key(),
            DM_KEY_RECORD_VERSION,
            DM_KEY_RECORD_INVITE_ONLY,
        )
        .unwrap();
        let v = verify(&rec, a.signing.public_key()).unwrap();
        assert_eq!(v.version, 1);
        assert!(!v.invite_only);
    }

    /// The encode/decode pair frontends actually use, so neither needs prost.
    #[test]
    fn build_encoded_and_decode_and_verify_round_trip() {
        let a = alice();
        let bytes = build_encoded(&a.signing, a.kem.encapsulation_key(), 5, true).unwrap();
        let v = decode_and_verify(&bytes, a.signing.public_key()).unwrap();
        assert_eq!(v.version, 5);
        assert!(v.invite_only);
        assert_eq!(&v.kem_ek[..], &a.kem.encapsulation_key()[..]);
    }

    /// The wrapper must not weaken the checks it wraps: a record decoded from
    /// bytes still has to verify against the right identity.
    #[test]
    fn decode_and_verify_still_rejects_another_identity() {
        let a = alice();
        let b = bob();
        let bytes = build_encoded(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        assert_eq!(
            decode_and_verify(&bytes, b.signing.public_key()),
            Err(DmKeyRecordError::Signature)
        );
    }

    /// The record slot is world-writable, so arbitrary bytes are an EXPECTED
    /// input. Garbage must fail closed as `Malformed`, and — the case that
    /// matters — must never panic, whatever an attacker writes there.
    #[test]
    fn decode_and_verify_fails_closed_on_arbitrary_bytes() {
        let a = alice();
        let pk = a.signing.public_key();
        for junk in [
            b"".as_slice(),
            b"\x00".as_slice(),
            b"not a protobuf at all".as_slice(),
            &[0xffu8; 64],
        ] {
            let got = decode_and_verify(junk, pk);
            assert!(
                got.is_err(),
                "arbitrary bytes must never verify: {junk:?} -> {got:?}"
            );
        }
        // Truncating a VALID encoding is the realistic corruption, and must also
        // fail closed rather than half-decode into something trusted.
        let good = build_encoded(&a.signing, a.kem.encapsulation_key(), 1, false).unwrap();
        assert!(decode_and_verify(&good[..good.len() / 2], pk).is_err());
    }
}
