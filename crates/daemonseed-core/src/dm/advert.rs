//! The **advert** — the signed record holding an identity's current
//! ML-KEM-1024 public key, and the state that rotates it.
//!
//! `docs/design/direct-messaging.md` § Records gives the record and its
//! address. Subkey 0 of a [`ADVERT_SUBKEYS`]-subkey record holds
//! `serial ‖ not_before ‖ kem_pk ‖ signature`, signed under the identity's
//! ML-DSA-87 key. The owner keypair is derived by HKDF from the identity
//! public key, so anyone who holds that key computes the address and may
//! write; a reader accepts only content whose signature verifies under the
//! same public key it derived the address from.
//!
//! Four rules govern the state:
//!
//! - **Rotation.** The KEM keypair rotates every [`ROTATION_PERIOD_SECS`].
//!   A rotation raises the serial by one and sets `not_before` to the moment
//!   it happened.
//! - **Retention.** The key that stopped being current is kept for one
//!   further [`ROTATION_PERIOD_SECS`] and then dropped, so a hello
//!   encapsulated just before a rotation still opens.
//! - **Monotonic serial.** A reader keeps the highest serial it has verified
//!   and refuses a lower one ([`AdvertReader`]). The record is world-writable,
//!   so an authentic older advert can be replayed over a newer one; every
//!   sender-side decision below reads the serial, and none of them may be
//!   driven backwards.
//! - **Poll.** A poll rewrites subkey 0 when an [`InspectReport`] shows the
//!   network's sequence number differing from the local one, or when the
//!   bytes fetched back differ from the canonical encoding of the current
//!   key. Otherwise it writes nothing.
//!
//! **The usability window is this module's reading of a point the design
//! leaves open.** The design fixes when an advert key is *published* and when
//! its secret is dropped, and says nothing about which adverts a sender may
//! encapsulate to. [`VerifiedAdvert::usable_at`] takes the narrowest reading
//! the two facts support: not before `not_before`, less [`CLOCK_SKEW_SECS`]
//! for unsynchronised clocks, and not at or after
//! `not_before + 2 × ROTATION_PERIOD_SECS`, by which time the owner has
//! rotated once and pruned once and holds no secret that could open the
//! result. Widening it needs the design to say so.
//!
//! Everything here is pure: no I/O, no clock, no ambient randomness. Wall
//! time arrives as a `u64` of Unix seconds from the caller and entropy as a
//! fill function, and the poll returns [`AdvertAction`] values the caller
//! performs.
//!
//! Serves FC4, FC5.

use std::time::Duration;

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroize;

use crate::dm::{domain, push_lp};
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Subkeys in an advert record — the `o_cnt` of its `dflt(o_cnt)` schema, and
/// part of the record's address.
///
/// Subkey 0 holds the advert. Subkeys 1 to 63 are reserved for per-device
/// keys and are never written: the count is fixed now so that adding a second
/// device later changes no address. A writer MUST build its `RecordShape`
/// from this constant rather than a literal.
pub const ADVERT_SUBKEYS: u16 = 64;

/// The subkey the advert itself occupies.
pub const ADVERT_SUBKEY: u32 = 0;

/// Byte length of the Veilid owner seed this module derives.
pub const ADVERT_OWNER_SEED_LEN: usize = 32;

/// How long one advert KEM keypair stays current, in seconds (one week).
///
/// It is also the retention period: a key is kept for this long again after
/// it stops being current, which is the window inside which a hello
/// encapsulated to it still opens.
pub const ROTATION_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

/// How far a sender's clock may sit behind an advert's `not_before` and still
/// encapsulate to it (one hour).
///
/// daemonseed assumes no shared time source, so two honest parties disagree
/// about the current instant. Without the allowance a sender whose clock runs
/// slow refuses a freshly rotated advert it has correctly read and verified.
pub const CLOCK_SKEW_SECS: u64 = 60 * 60;

/// Lower bound of the jittered poll interval.
///
/// The design budgets the advert at one write a week plus a rewrite only when
/// the poll finds the record missing or wrong (`docs/design/direct-messaging.md`
/// § Write budget). This band, [`POLL_INTERVAL_MIN`] to
/// [`POLL_INTERVAL_MAX`], is what that poll runs on; the jitter is drawn per
/// poll rather than fixed so the record carries no recognisable cadence.
pub const POLL_INTERVAL_MIN: Duration = Duration::from_secs(40 * 60);

/// Upper bound of the jittered poll interval.
pub const POLL_INTERVAL_MAX: Duration = Duration::from_secs(60 * 60);

/// Byte length of the encoded advert: two big-endian `u64` fields, the
/// ML-KEM-1024 public key, and the ML-DSA-87 signature.
pub const ADVERT_LEN: usize = 8 + 8 + ml_kem::EK_LEN + ml_dsa::SIG_LEN;

/// Byte offset of `not_before` within the encoded advert.
const NOT_BEFORE_AT: usize = 8;

/// Byte offset of `kem_pk` within the encoded advert.
const KEM_PK_AT: usize = 16;

/// Where an ML-KEM-1024 decapsulation key carries its own encapsulation key.
///
/// FIPS 203 lays a decapsulation key out as `dk_PKE ‖ ek ‖ H(ek) ‖ z`, so the
/// public half is recoverable from the secret one and need not be stored
/// beside it. [`AdvertSnapshot`] relies on this: the design's on-disk record
/// holds the advert secret keys and the serial, and nothing public
/// (`docs/design/direct-messaging.md` § On-disk records).
const EK_IN_DK_AT: usize = ml_kem::DK_LEN - ml_kem::EK_LEN - 64;

/// A fresh poll delay drawn uniformly from
/// `[POLL_INTERVAL_MIN, POLL_INTERVAL_MAX]`.
///
/// A source failure degrades to the midpoint: a poll is liveness, not a key,
/// and the next draw recovers.
pub fn next_poll_interval(mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>) -> Duration {
    crate::presence::interval_in_band(POLL_INTERVAL_MIN, POLL_INTERVAL_MAX, move |buf| {
        fill(buf.as_mut_slice())
    })
}

/// [`next_poll_interval`] over the OS CSPRNG — the production draw.
pub fn next_poll_interval_os() -> Duration {
    next_poll_interval(crate::jitter::os_fill_bytes)
}

redacted_secret_newtype! {
    /// The Veilid record-owner seed for an identity's advert.
    ///
    /// A secret newtype for the zeroize-on-drop and redacted-`Debug` hygiene,
    /// but deliberately world-derivable: anyone holding the identity's public
    /// key computes the same value, which is what makes the record findable.
    /// Holding it confers write access, which is why the record's integrity
    /// rests on the inner signature rather than on ownership.
    boxed pub struct AdvertOwnerSeed([u8; ADVERT_OWNER_SEED_LEN]);
}

redacted_secret_newtype! {
    /// The secret half of one advert KEM keypair.
    boxed pub struct AdvertDecapKey([u8; ml_kem::DK_LEN]);
}

impl AdvertDecapKey {
    /// A key over bytes read back from the profile's at-rest store.
    ///
    /// The counterpart of [`Self::as_bytes`], for the one caller that writes
    /// an [`AdvertSnapshot`] down and reads it again
    /// ([`crate::dm::store`]). Nothing derives a decapsulation key, so a
    /// restored one has to come from the bytes a snapshot was written from.
    pub(crate) fn from_bytes(bytes: &[u8; ml_kem::DK_LEN]) -> Self {
        Self(Box::new(*bytes))
    }
}

redacted_secret_newtype! {
    /// The secret an encapsulation to an advert key yields on both sides.
    boxed pub struct AdvertSharedSecret([u8; ml_kem::SHARED_SECRET_LEN]);
}

/// Why an advert operation failed.
///
/// `PartialEq` is implemented by hand rather than derived because neither
/// [`SignatureError`] nor `oxicrypt_module::Error` is comparable; those two
/// variants compare equal on the variant alone, which is all a caller needs.
#[derive(Debug)]
pub enum AdvertError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// The bytes are not [`ADVERT_LEN`] long, so no field can be read from
    /// them. Carries both figures, so a truncation is diagnosable.
    Length {
        /// What an advert measures.
        expected: usize,
        /// What arrived.
        actual: usize,
    },
    /// The signature did not verify under the identity public key the reader
    /// derived the address from.
    ///
    /// **Verify-path only, and deliberately uniform.** It does not separate a
    /// tampered record from one signed under a different identity: the
    /// preimage binds the signer's public key, so a record built for someone
    /// else fails here exactly as a flipped byte does, and a verifier that
    /// told the two apart would be an oracle (ISC-A-S12 / ISC-A-C18). A LOCAL
    /// signing failure is [`Self::Signing`], never this.
    Signature,
    /// An authentic advert whose serial is below the highest already verified
    /// for this identity — a replayed pre-rotation record. Denial of service
    /// only, since the attacker cannot produce a key the identity never
    /// published, but never accepted.
    Regressed {
        /// The serial the offered advert asserts.
        seen: u64,
        /// The highest serial already verified for this identity.
        highest: u64,
    },
    /// The advert is outside its usability window at the instant supplied:
    /// not yet in force even allowing [`CLOCK_SKEW_SECS`], or old enough that
    /// its owner has pruned the secret.
    Unusable {
        /// The instant the caller supplied, in Unix seconds.
        now: u64,
        /// The advert's own validity start, in Unix seconds.
        not_before: u64,
    },
    /// A local signing operation failed while building an advert — the crypto
    /// module is not operational, or the active profile disallows ML-DSA
    /// signing. Carries the cause: there is no adversary on this path, and a
    /// policy refusal reported as "did not verify" would send a reader
    /// hunting for tampering that never happened.
    Signing(SignatureError),
    /// The entropy source failed, so no key could be generated and no secret
    /// encapsulated.
    Entropy,
    /// The crypto module refused a key-generation, encapsulation or
    /// decapsulation call.
    Module(oxicrypt_module::Error),
}

impl PartialEq for AdvertError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Kdf(a), Self::Kdf(b)) => a == b,
            (
                Self::Length {
                    expected: ea,
                    actual: aa,
                },
                Self::Length {
                    expected: eb,
                    actual: ab,
                },
            ) => ea == eb && aa == ab,
            (Self::Signature, Self::Signature) => true,
            (
                Self::Regressed {
                    seen: sa,
                    highest: ha,
                },
                Self::Regressed {
                    seen: sb,
                    highest: hb,
                },
            ) => sa == sb && ha == hb,
            (
                Self::Unusable {
                    now: na,
                    not_before: ba,
                },
                Self::Unusable {
                    now: nb,
                    not_before: bb,
                },
            ) => na == nb && ba == bb,
            (Self::Entropy, Self::Entropy) => true,
            // Compared on the variant: the wrapped cause is diagnostic and is
            // not itself comparable.
            (Self::Signing(_), Self::Signing(_)) => true,
            (Self::Module(_), Self::Module(_)) => true,
            _ => false,
        }
    }
}

impl Eq for AdvertError {}

impl std::fmt::Display for AdvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "advert HKDF failed: {e:?}"),
            Self::Length { expected, actual } => {
                write!(f, "advert: expected {expected} bytes, got {actual}")
            }
            Self::Signature => write!(f, "advert signature did not verify"),
            Self::Regressed { seen, highest } => {
                write!(
                    f,
                    "advert serial regression: seen {seen}, highest {highest}"
                )
            }
            Self::Unusable { now, not_before } => write!(
                f,
                "advert is unusable at {now}: it is in force from {not_before}"
            ),
            Self::Signing(e) => write!(f, "advert could not be signed locally: {e:?}"),
            Self::Entropy => write!(f, "advert: the entropy source failed"),
            Self::Module(e) => write!(f, "advert: the crypto module refused: {e:?}"),
        }
    }
}

impl std::error::Error for AdvertError {}

/// Derive the world-derivable Veilid owner seed for `identity_pubkey`'s
/// advert: `HKDF-SHA-384(salt = DM_ADVERT_SALT, ikm = PK_lt, info =
/// DM_ADVERT_OWNER)`.
///
/// Deterministic and pure. Every reader and the owner compute the same value,
/// which is what makes the record findable from a public key alone. The
/// labels are the advert's own, so this address never coincides with that of
/// another record derived from the same public key.
pub fn derive_owner_seed(
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<AdvertOwnerSeed, AdvertError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_ADVERT_SALT), identity_pubkey)
        .map_err(AdvertError::Kdf)?;
    let seed = derive_boxed_seed::<ADVERT_OWNER_SEED_LEN>(&hkdf, domain::DM_ADVERT_OWNER)
        .map_err(AdvertError::Kdf)?;
    Ok(AdvertOwnerSeed(seed))
}

/// Build the domain-separated signing preimage.
///
/// Every field is length-prefixed (`u64` big-endian length ‖ bytes), the
/// repository's one preimage convention, so the concatenation is unambiguous
/// and no pair of adjacent fields can be re-split to forge a different tuple.
///
/// Binding `identity_pubkey` inside the preimage is what ties an advert to
/// exactly one identity: the same `(serial, not_before, kem_pk)` signed for
/// identity A does not verify at B's address, because B's reader feeds B's
/// public key into this function.
pub fn signing_input(
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
    serial: u64,
    not_before: u64,
    kem_pk: &[u8; ml_kem::EK_LEN],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(domain::DM_ADVERT_SIG.len() + ml_dsa::PK_LEN + ml_kem::EK_LEN + 64);
    buf.extend_from_slice(domain::DM_ADVERT_SIG);
    push_lp(&mut buf, identity_pubkey);
    push_lp(&mut buf, &serial.to_be_bytes());
    push_lp(&mut buf, &not_before.to_be_bytes());
    push_lp(&mut buf, kem_pk);
    buf
}

/// An advert whose signature verified against the identity that owns its
/// address. Only constructible via [`verify`], so holding one is the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdvert {
    /// The serial this advert asserts. It rises by one per rotation.
    pub serial: u64,
    /// Unix seconds at which the key became current.
    pub not_before: u64,
    /// The identity's current ML-KEM-1024 public key.
    pub kem_pk: Box<[u8; ml_kem::EK_LEN]>,
}

impl VerifiedAdvert {
    /// Whether a sender may encapsulate to this advert at `now`.
    ///
    /// True from `not_before − CLOCK_SKEW_SECS`, so an honest sender whose
    /// clock runs slow still accepts a freshly rotated advert, and false from
    /// `not_before + 2 × ROTATION_PERIOD_SECS`, by which time the owner has
    /// rotated once and pruned once and holds nothing that could open the
    /// result. See the module header: the window is this module's reading of
    /// a point the design leaves open, not a figure the design states.
    pub fn usable_at(&self, now: u64) -> bool {
        let opens = self.not_before.saturating_sub(CLOCK_SKEW_SECS);
        let closes = self
            .not_before
            .saturating_add(2u64.saturating_mul(ROTATION_PERIOD_SECS));
        now >= opens && now < closes
    }
}

/// Highest-verified-serial-wins gate for one correspondent's advert.
///
/// The record is world-writable, so an attacker cannot forge an advert but
/// can replay an authentic one the owner signed before a rotation. This is
/// the defence: a reader keeps the highest serial it has verified and refuses
/// to regress, so a rotation cannot be reverted. The residual is a genuinely
/// cold reader — one with no serial at all — which accepts whatever authentic
/// advert it is served; that is bounded to denial of service, because the
/// attacker still cannot produce a key the identity never published.
///
/// One reader per correspondent: it carries no identity binding of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvertReader {
    highest: Option<u64>,
}

impl AdvertReader {
    /// A reader that has never verified an advert for this identity.
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest serial verified so far, if any.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Take an already-verified advert if it is at least as new as what this
    /// reader has seen, and hand it back.
    ///
    /// An advert equal to the highest serial is accepted: the signature
    /// verified, so it is the same authentic content, and accepting it keeps
    /// a rewrite idempotent. A strictly older one is refused with
    /// [`AdvertError::Regressed`] and the reader is left untouched.
    pub fn accept(&mut self, advert: VerifiedAdvert) -> Result<VerifiedAdvert, AdvertError> {
        if let Some(highest) = self.highest
            && advert.serial < highest
        {
            return Err(AdvertError::Regressed {
                seen: advert.serial,
                highest,
            });
        }
        self.highest = Some(advert.serial);
        Ok(advert)
    }
}

/// Sign and encode an advert for publication:
/// `serial ‖ not_before ‖ kem_pk ‖ signature`, each integer big-endian.
pub fn build(
    signer: &SignKeypair,
    serial: u64,
    not_before: u64,
    kem_pk: &[u8; ml_kem::EK_LEN],
) -> Result<Vec<u8>, AdvertError> {
    let preimage = signing_input(signer.public_key(), serial, not_before, kem_pk);
    let sig = signer.sign(&preimage).map_err(AdvertError::Signing)?;
    let mut out = Vec::with_capacity(ADVERT_LEN);
    out.extend_from_slice(&serial.to_be_bytes());
    out.extend_from_slice(&not_before.to_be_bytes());
    out.extend_from_slice(kem_pk);
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Verify fetched advert bytes against `identity_pubkey` — the SAME public
/// key the reader derived the record's address from, never anything carried
/// in the record, which carries no public key precisely so there is nothing
/// to substitute.
///
/// Fails closed on a length that is not [`ADVERT_LEN`], before any ML-DSA
/// call: the record is world-writable, so arbitrary bytes in the subkey are
/// an expected input rather than an exceptional one.
pub fn verify(
    identity_pubkey: &[u8; ml_dsa::PK_LEN],
    bytes: &[u8],
) -> Result<VerifiedAdvert, AdvertError> {
    let wrong_length = || AdvertError::Length {
        expected: ADVERT_LEN,
        actual: bytes.len(),
    };
    if bytes.len() != ADVERT_LEN {
        return Err(wrong_length());
    }
    let serial = u64::from_be_bytes(
        bytes[..NOT_BEFORE_AT]
            .try_into()
            .map_err(|_| wrong_length())?,
    );
    let not_before = u64::from_be_bytes(
        bytes[NOT_BEFORE_AT..KEM_PK_AT]
            .try_into()
            .map_err(|_| wrong_length())?,
    );
    let (pk_bytes, sig_bytes) = bytes[KEM_PK_AT..].split_at(ml_kem::EK_LEN);
    let kem_pk: Box<[u8; ml_kem::EK_LEN]> = pk_bytes
        .try_into()
        .map(Box::new)
        .map_err(|_| wrong_length())?;
    let sig: [u8; ml_dsa::SIG_LEN] = sig_bytes.try_into().map_err(|_| wrong_length())?;

    let preimage = signing_input(identity_pubkey, serial, not_before, &kem_pk);
    verify_signature(identity_pubkey, &preimage, &sig).map_err(|_| AdvertError::Signature)?;

    Ok(VerifiedAdvert {
        serial,
        not_before,
        kem_pk,
    })
}

/// One advert KEM keypair, with the serial and `not_before` the advert
/// publishes for it.
struct AdvertKey {
    serial: u64,
    not_before: u64,
    ek: Box<[u8; ml_kem::EK_LEN]>,
    dk: AdvertDecapKey,
}

/// The key that stopped being current, and the moment it did.
struct RetiredKey {
    key: AdvertKey,
    retired_at: u64,
}

/// Recover the encapsulation key an ML-KEM-1024 decapsulation key carries.
///
/// See `EK_IN_DK_AT` for the layout this reads.
fn ek_from_dk(dk: &AdvertDecapKey) -> Box<[u8; ml_kem::EK_LEN]> {
    let mut ek = Box::new([0u8; ml_kem::EK_LEN]);
    ek.copy_from_slice(&dk.as_bytes()[EK_IN_DK_AT..EK_IN_DK_AT + ml_kem::EK_LEN]);
    ek
}

/// Generate a fresh advert KEM keypair at `serial` and `not_before`.
///
/// **What the zeroize here does and does not reach.** `keygen` hands the
/// secret half back inside a `Result`, and moving a `Copy` array out of one
/// copies rather than takes — so `let (ek, dk) = generated?` would leave the
/// `Result`'s own copy of the key on this frame with nothing able to reach
/// it. Binding by reference keeps it reachable and the zeroize below clears
/// it. It does NOT clear the argument temporary `Box::new(*dk)` materialises
/// on the way into the allocation: the crate's API offers no way to construct
/// the box without that copy, so one copy of the key is left for the frame to
/// overwrite. The same is true of [`AdvertKeys::decapsulate`]'s `Box::new`.
fn generate(
    serial: u64,
    not_before: u64,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<AdvertKey, AdvertError> {
    let mut d = [0u8; ml_kem::SEED_LEN];
    let mut z = [0u8; ml_kem::SEED_LEN];
    let drawn = fill(&mut d).and_then(|()| fill(&mut z));
    if drawn.is_err() {
        d.zeroize();
        z.zeroize();
        return Err(AdvertError::Entropy);
    }
    let mut generated = ml_kem::keygen(&d, &z);
    d.zeroize();
    z.zeroize();
    match generated {
        Ok((ref ek, ref mut dk)) => {
            let key = AdvertKey {
                serial,
                not_before,
                ek: Box::new(*ek),
                dk: AdvertDecapKey(Box::new(*dk)),
            };
            dk.zeroize();
            Ok(key)
        }
        Err(e) => Err(AdvertError::Module(e)),
    }
}

/// Whether [`AdvertKeys::rotate_if_due`] rotated.
///
/// An enum rather than a `bool` so the caller cannot drop the answer: a
/// rotation that is not republished leaves correspondents encapsulating to a
/// key that is on its way out of retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a rotation must be republished to subkey 0 before correspondents can reach the new key"]
pub enum Rotation {
    /// A fresh key is current. Write [`AdvertKeys::advert_bytes`] to the
    /// record.
    Rotated,
    /// The current key is unchanged. Nothing to publish.
    Unchanged,
}

impl Rotation {
    /// Whether a rotation happened.
    pub fn happened(self) -> bool {
        matches!(self, Self::Rotated)
    }
}

/// Everything an advert's key state needs to survive a restart, matching the
/// design's on-disk record (`docs/design/direct-messaging.md` § On-disk
/// records): the current and retained advert secret keys and the serial.
///
/// Public halves are absent because they are recoverable from the secret
/// ones: FIPS 203 lays a decapsulation key out as `dk_PKE ‖ ek ‖ H(ek) ‖ z`,
/// so the public half sits inside the secret one.
#[derive(Debug)]
pub struct AdvertSnapshot {
    /// The current key's serial.
    pub serial: u64,
    /// The current key's validity start, in Unix seconds.
    pub not_before: u64,
    /// The current key's secret half.
    pub decapsulation_key: AdvertDecapKey,
    /// The retained key, if one is still held: its serial, the moment it
    /// stopped being current, and its secret half.
    pub previous: Option<RetiredSnapshot>,
}

/// The retained half of an [`AdvertSnapshot`].
#[derive(Debug)]
pub struct RetiredSnapshot {
    /// The retained key's serial.
    pub serial: u64,
    /// The moment the key stopped being current, in Unix seconds.
    pub retired_at: u64,
    /// The retained key's secret half.
    pub decapsulation_key: AdvertDecapKey,
}

/// The rotation state behind an identity's advert: the current KEM keypair,
/// and the one before it while it is still retained.
///
/// The secret halves zeroize on drop, so dropping the retained key is what
/// makes a hello encapsulated to it permanently unopenable.
pub struct AdvertKeys {
    current: AdvertKey,
    previous: Option<RetiredKey>,
}

impl std::fmt::Debug for AdvertKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdvertKeys")
            .field("serial", &self.current.serial)
            .field("not_before", &self.current.not_before)
            .field("previous_serial", &self.previous_serial())
            .field("previous_retired_at", &self.previous_retired_at())
            .finish()
    }
}

impl AdvertKeys {
    /// A first advert keypair at serial 0, current from `now`.
    pub fn new(
        now: u64,
        fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<Self, AdvertError> {
        Ok(Self {
            current: generate(0, now, fill)?,
            previous: None,
        })
    }

    /// The serial of the current key.
    pub fn serial(&self) -> u64 {
        self.current.serial
    }

    /// Unix seconds at which the current key became current.
    pub fn not_before(&self) -> u64 {
        self.current.not_before
    }

    /// The current public key, the half an advert publishes.
    pub fn encapsulation_key(&self) -> &[u8; ml_kem::EK_LEN] {
        &self.current.ek
    }

    /// The serial of the retained key, if one is still held.
    pub fn previous_serial(&self) -> Option<u64> {
        self.previous.as_ref().map(|p| p.key.serial)
    }

    /// When the retained key stopped being current, if one is still held.
    pub fn previous_retired_at(&self) -> Option<u64> {
        self.previous.as_ref().map(|p| p.retired_at)
    }

    /// Everything needed to rebuild this state after a restart.
    pub fn snapshot(&self) -> AdvertSnapshot {
        AdvertSnapshot {
            serial: self.current.serial,
            not_before: self.current.not_before,
            decapsulation_key: AdvertDecapKey(Box::new(*self.current.dk.as_bytes())),
            previous: self.previous.as_ref().map(|p| RetiredSnapshot {
                serial: p.key.serial,
                retired_at: p.retired_at,
                decapsulation_key: AdvertDecapKey(Box::new(*p.key.dk.as_bytes())),
            }),
        }
    }

    /// Rebuild the state from a snapshot. The public halves are recovered
    /// from the secret ones, so a restored state republishes the same advert
    /// bytes the snapshot was taken from.
    pub fn restore(snapshot: AdvertSnapshot) -> Self {
        Self {
            current: AdvertKey {
                serial: snapshot.serial,
                not_before: snapshot.not_before,
                ek: ek_from_dk(&snapshot.decapsulation_key),
                dk: snapshot.decapsulation_key,
            },
            previous: snapshot.previous.map(|p| RetiredKey {
                key: AdvertKey {
                    serial: p.serial,
                    // A retained key is never published again, so the moment
                    // it became current is not restored; nothing below reads
                    // it, and `retired_at` is what bounds its retention.
                    not_before: p.retired_at,
                    ek: ek_from_dk(&p.decapsulation_key),
                    dk: p.decapsulation_key,
                },
                retired_at: p.retired_at,
            }),
        }
    }

    /// Drop the retained key once a full [`ROTATION_PERIOD_SECS`] has passed
    /// since it stopped being current.
    ///
    /// This is what bounds the exposure of a device copied at some moment: a
    /// hello still on the network encapsulated to a key older than the
    /// retained one opens for nobody, including its owner.
    pub fn prune(&mut self, now: u64) {
        let expired = self
            .previous
            .as_ref()
            .is_some_and(|p| now >= p.retired_at.saturating_add(ROTATION_PERIOD_SECS));
        if expired {
            self.previous = None;
        }
    }

    /// Rotate when a full [`ROTATION_PERIOD_SECS`] has passed since the
    /// current key became current, and say whether it did. On
    /// [`Rotation::Rotated`] the caller writes [`Self::advert_bytes`] to
    /// subkey 0; on [`Rotation::Unchanged`] there is nothing to publish.
    ///
    /// A rotation moves the current key into the retained slot and makes a
    /// fresh keypair current at the next serial with `not_before = now`.
    ///
    /// **The retired key's retention is anchored to the moment it was DUE to
    /// stop being current, not to `now`.** A poll that runs late — the
    /// process was off, the schedule slipped — would otherwise extend the old
    /// key's life by exactly the lateness, which is the one direction the
    /// retention bound must not move.
    ///
    /// [`Self::prune`] runs first, so a retained key that has outlived its
    /// window is dropped whether or not this call rotates.
    pub fn rotate_if_due(
        &mut self,
        now: u64,
        fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<Rotation, AdvertError> {
        self.prune(now);
        let due_at = self.current.not_before.saturating_add(ROTATION_PERIOD_SECS);
        if now < due_at {
            return Ok(Rotation::Unchanged);
        }
        self.rotate(now, due_at, fill)?;
        Ok(Rotation::Rotated)
    }

    /// Rotate whether or not a rotation is due: the current key retires at
    /// `now` and a fresh keypair becomes current at the next serial with
    /// `not_before = now`.
    ///
    /// This is the reset path (`docs/design/direct-messaging.md` § Keys and
    /// forward secrecy, *Reset*), which rotates the advert immediately rather
    /// than waiting for the schedule. The retention anchor is `now` here and
    /// not a due moment, because there is none: the key is being retired early
    /// on purpose, so its window runs from when that happened.
    pub fn rotate_now(
        &mut self,
        now: u64,
        fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<(), AdvertError> {
        self.prune(now);
        self.rotate(now, now, fill)
    }

    /// The rotation body both paths share: mint at the next serial, move the
    /// current key into the retained slot, and anchor its retention at
    /// `retired_at`.
    ///
    /// Shared so the two entry points cannot disagree about what a rotation
    /// does — only about when it happens and what the retention runs from.
    fn rotate(
        &mut self,
        now: u64,
        retired_at: u64,
        fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<(), AdvertError> {
        let next_serial = self.current.serial.saturating_add(1);
        let fresh = generate(next_serial, now, fill)?;
        let retired = std::mem::replace(&mut self.current, fresh);
        self.previous = Some(RetiredKey {
            key: retired,
            retired_at,
        });
        Ok(())
    }

    /// Recover the secret a sender encapsulated to the advert key at
    /// `serial`, from the current key or the retained one.
    ///
    /// `Ok(None)` means no key this state still holds published that serial.
    /// An `Err` is a crypto-module refusal, which is a different condition
    /// and must not read as a hello that failed to open.
    ///
    /// **The serial selects the key, and that is not a convenience.**
    /// ML-KEM decapsulation uses implicit rejection: handed a ciphertext
    /// meant for a different key it returns a pseudorandom secret rather than
    /// an error, so trying both secrets in turn has no failure signal to stop
    /// on. The serial is on the wire — a sender carries it from
    /// [`HelloEncapsulation`] and an opening binds it — so it is the
    /// selector.
    pub fn decapsulate(
        &self,
        serial: u64,
        ciphertext: &[u8; ml_kem::CT_LEN],
    ) -> Result<Option<AdvertSharedSecret>, AdvertError> {
        let key = if self.current.serial == serial {
            &self.current
        } else {
            match self.previous.as_ref() {
                Some(retained) if retained.key.serial == serial => &retained.key,
                _ => return Ok(None),
            }
        };
        let mut ss =
            ml_kem::decapsulate(key.dk.as_bytes(), ciphertext).map_err(AdvertError::Module)?;
        let secret = AdvertSharedSecret(Box::new(ss));
        ss.zeroize();
        Ok(Some(secret))
    }

    /// The canonical encoding of the current key — the exact bytes subkey 0
    /// must hold.
    pub fn advert_bytes(&self, signer: &SignKeypair) -> Result<Vec<u8>, AdvertError> {
        build(
            signer,
            self.current.serial,
            self.current.not_before,
            &self.current.ek,
        )
    }

    /// Decide what one poll must do.
    ///
    /// Returns exactly one [`AdvertAction::Rewrite`] when the report shows
    /// the record needs repair, or when `fetched` is present and differs from
    /// the canonical encoding; otherwise nothing. `fetched` is `None` when
    /// the poll read no bytes back, which the report alone then settles.
    ///
    /// The decision is taken before anything is signed: a poll that finds the
    /// record intact and read nothing back performs no ML-DSA operation at
    /// all, which is most polls.
    pub fn on_poll(
        &self,
        signer: &SignKeypair,
        report: &InspectReport,
        fetched: Option<&[u8]>,
    ) -> Result<Vec<AdvertAction>, AdvertError> {
        let repair = repair_needed(report);
        if !repair && fetched.is_none() {
            return Ok(Vec::new());
        }
        let canonical = self.advert_bytes(signer)?;
        if repair || fetched.is_some_and(|bytes| bytes != canonical.as_slice()) {
            return Ok(vec![AdvertAction::Rewrite(canonical)]);
        }
        Ok(Vec::new())
    }
}

/// What one subkey's `inspect_dht_record` under `DHTReportScope::SyncSet`
/// reported: the local sequence number, and the network's as if the local
/// copy did not exist.
///
/// A plain read cannot stand in for this. It returns the same absent result
/// for a never-written and an evicted subkey, and a writer reading its own
/// record is served the local copy without the network being asked, even on
/// a forced refresh. Either is `None` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InspectReport {
    /// The sequence number of the local copy.
    pub local_seq: Option<u64>,
    /// The sequence number the network holds.
    pub network_seq: Option<u64>,
}

/// Whether the report calls for a rewrite: the network holds no sequence
/// number, or one that differs from the local copy's in either direction.
///
/// **A network sequence number ABOVE the local one is repair too.** The
/// record is world-writable, so anyone can write it, and a higher sequence
/// number means another writer reached it. The owner cannot inspect what they
/// wrote — a self-read is served the local copy — so the sequence number is
/// the only signal there is, and the only safe response to a difference is to
/// put the canonical bytes back.
pub fn repair_needed(report: &InspectReport) -> bool {
    report.network_seq.is_none() || report.network_seq != report.local_seq
}

/// Something a poll asks its caller to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertAction {
    /// Write these bytes to subkey [`ADVERT_SUBKEY`].
    Rewrite(Vec<u8>),
}

/// What a sender holds after encapsulating to a correspondent's advert key.
#[derive(Debug)]
pub struct HelloEncapsulation {
    /// The advert serial this was encapsulated to. The sender keeps it and
    /// compares it against every later advert it reads.
    pub serial: u64,
    /// The secret both sides now hold.
    pub shared_secret: AdvertSharedSecret,
    /// The ciphertext the hello carries.
    pub ciphertext: Box<[u8; ml_kem::CT_LEN]>,
}

/// Encapsulate to a verified advert's key at `now`.
///
/// Refuses with [`AdvertError::Unusable`] outside
/// [`VerifiedAdvert::usable_at`]: encapsulating to a key whose owner has
/// already pruned the secret produces a hello nobody can ever open, and the
/// sender would wait for a reply that cannot come.
pub fn encapsulate_to(
    advert: &VerifiedAdvert,
    now: u64,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<HelloEncapsulation, AdvertError> {
    if !advert.usable_at(now) {
        return Err(AdvertError::Unusable {
            now,
            not_before: advert.not_before,
        });
    }
    let mut m = [0u8; ml_kem::SEED_LEN];
    if fill(&mut m).is_err() {
        m.zeroize();
        return Err(AdvertError::Entropy);
    }
    let encapsulated = ml_kem::encapsulate(&advert.kem_pk, &m);
    m.zeroize();
    let (mut ss, ct) = encapsulated.map_err(AdvertError::Module)?;
    let shared_secret = AdvertSharedSecret(Box::new(ss));
    ss.zeroize();
    Ok(HelloEncapsulation {
        serial: advert.serial,
        shared_secret,
        ciphertext: Box::new(ct),
    })
}

/// Whether a sender whose hello has not yet been collected must re-encapsulate
/// and rewrite it: the correspondent has rotated PAST the serial the
/// outstanding hello was encapsulated to.
///
/// Strictly greater, never merely different. An authentic older advert can be
/// replayed over the record by anyone, and a sender that treated a lower
/// serial as a change would re-encapsulate to a key its owner has already
/// retired — turning a replay into a hello that can never be opened.
pub fn hello_needs_rewrite(outstanding_serial: u64, observed: &VerifiedAdvert) -> bool {
    observed.serial > outstanding_serial
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

    /// A fixed wall-clock origin, so every `now` in these tests is a literal
    /// the source can be read against.
    const ORIGIN: u64 = 1_700_000_000;

    const DAY: u64 = 24 * 60 * 60;

    /// Unix seconds `n` days after [`ORIGIN`].
    fn day(n: u64) -> u64 {
        ORIGIN + n * DAY
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Bring the crypto module up.
    ///
    /// Every test here needs it, and a test that mints no identity must call
    /// it directly: depending on another test having run first makes the
    /// suite order-sensitive, and the failure it produces —
    /// `NotOperational` out of a keygen — reads like a broken keygen.
    fn module() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    fn keys(phrase: &str) -> IdentityKeys {
        module();
        derive_identity_keys(&Mnemonic::from_phrase(phrase).unwrap(), Identity::Primary).unwrap()
    }

    fn alice() -> IdentityKeys {
        keys(PHRASE_A)
    }

    /// A fixed second identity, never `Mnemonic::generate()`. Every assertion
    /// against Bob is an inequality or a must-fail, so a random identity
    /// could not make a test spuriously pass — but it would make an
    /// intermittent failure unreplayable from the source.
    fn bob() -> IdentityKeys {
        keys(PHRASE_B)
    }

    /// A seeded entropy source. Deterministic, so a failing run replays from
    /// the source alone, and never constant, so two keypairs drawn from one
    /// instance differ.
    #[derive(Default)]
    struct SeededEntropy(u64);

    impl SeededEntropy {
        fn at(seed: u64) -> Self {
            Self(seed)
        }

        fn fill(&mut self, buf: &mut [u8]) -> Result<(), ()> {
            for b in buf.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    /// An instant comfortably inside every advert's usability window, for the
    /// tests whose subject is not the window.
    fn usable_now(advert: &VerifiedAdvert) -> u64 {
        advert.not_before
    }

    #[test]
    fn build_then_verify_round_trips() {
        let a = alice();
        let mut ent = SeededEntropy::at(1);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let bytes = k.advert_bytes(&a.signing).unwrap();

        // The encoded field offsets, not the total length — the total is
        // ADVERT_LEN by construction and asserting it proves nothing.
        assert_eq!(&bytes[..NOT_BEFORE_AT], &0u64.to_be_bytes());
        assert_eq!(&bytes[NOT_BEFORE_AT..KEM_PK_AT], &day(0).to_be_bytes());
        assert_eq!(
            &bytes[KEM_PK_AT..KEM_PK_AT + ml_kem::EK_LEN],
            &k.encapsulation_key()[..]
        );
        assert_eq!(
            bytes.len() - (KEM_PK_AT + ml_kem::EK_LEN),
            ml_dsa::SIG_LEN,
            "the signature must occupy the rest of the record"
        );

        let v = verify(a.signing.public_key(), &bytes).unwrap();
        assert_eq!(v.serial, 0);
        assert_eq!(v.not_before, day(0));
        assert_eq!(&v.kem_pk[..], &k.encapsulation_key()[..]);
    }

    /// Control: a single flipped byte of the signature must be refused.
    #[test]
    fn verify_refuses_a_flipped_signature_byte() {
        let a = alice();
        let mut ent = SeededEntropy::at(2);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let mut bytes = k.advert_bytes(&a.signing).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(
            verify(a.signing.public_key(), &bytes),
            Err(AdvertError::Signature)
        );
    }

    /// Control: a record short of [`ADVERT_LEN`] must be refused on length,
    /// before any ML-DSA call.
    #[test]
    fn verify_refuses_a_truncated_record() {
        let a = alice();
        let mut ent = SeededEntropy::at(3);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let bytes = k.advert_bytes(&a.signing).unwrap();
        let short = &bytes[..bytes.len() - 1];
        assert_eq!(
            verify(a.signing.public_key(), short),
            Err(AdvertError::Length {
                expected: ADVERT_LEN,
                actual: ADVERT_LEN - 1,
            })
        );
    }

    /// Control: an advert signed by one identity must not verify under
    /// another's public key. The preimage binds the signer's public key, so
    /// this is the same uniform refusal a tampered record gets.
    #[test]
    fn verify_refuses_a_record_signed_for_another_identity() {
        let a = alice();
        let b = bob();
        let mut ent = SeededEntropy::at(4);
        let k = AdvertKeys::new(day(0), |x| ent.fill(x)).unwrap();
        let bytes = k.advert_bytes(&a.signing).unwrap();
        assert!(verify(a.signing.public_key(), &bytes).is_ok());
        assert_eq!(
            verify(b.signing.public_key(), &bytes),
            Err(AdvertError::Signature)
        );
    }

    /// Every signed field is bound: flipping one byte of each, in the encoded
    /// record, must break the signature. Without this a field could be moved
    /// out of the preimage and nothing else here would notice.
    #[test]
    fn every_encoded_field_is_inside_the_signature() {
        let a = alice();
        let mut ent = SeededEntropy::at(5);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let bytes = k.advert_bytes(&a.signing).unwrap();
        assert!(
            verify(a.signing.public_key(), &bytes).is_ok(),
            "the unflipped record must verify, or the flips below prove nothing"
        );
        for (field, at) in [
            ("serial", NOT_BEFORE_AT - 1),
            ("not_before", KEM_PK_AT - 1),
            ("kem_pk", KEM_PK_AT),
        ] {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0x01;
            assert_eq!(
                verify(a.signing.public_key(), &flipped),
                Err(AdvertError::Signature),
                "a flipped {field} byte was accepted"
            );
        }
    }

    /// The preimage binds the signing identity, so the same fields signed by
    /// two identities are two different messages.
    #[test]
    fn the_preimage_binds_the_identity() {
        let a = alice();
        let b = bob();
        let pk = [0x5au8; ml_kem::EK_LEN];
        let for_a = signing_input(a.signing.public_key(), 7, day(0), &pk);
        let for_b = signing_input(b.signing.public_key(), 7, day(0), &pk);
        assert_ne!(for_a, for_b);
        // Control: the same identity twice is the same preimage, so the
        // inequality above is the identity and not nondeterminism.
        assert_eq!(for_a, signing_input(a.signing.public_key(), 7, day(0), &pk));
    }

    #[test]
    fn owner_seed_is_deterministic_and_separates_identities() {
        let a = alice();
        let b = bob();
        let first = derive_owner_seed(a.signing.public_key()).unwrap();
        let second = derive_owner_seed(a.signing.public_key()).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
        let other = derive_owner_seed(b.signing.public_key()).unwrap();
        assert_ne!(first.as_bytes(), other.as_bytes());
    }

    /// **Golden vectors: these values are the wire.**
    ///
    /// The address an identity's advert sits at, the bytes its signature is
    /// taken over, and the record's shape are all things a peer computes
    /// independently. A change to any of them is a protocol change that makes
    /// two clients unable to find or verify each other, and every other test
    /// in this module would stay green through it, because each derives its
    /// expectation from the same code it is checking. These do not: they were
    /// captured once and are pinned.
    ///
    /// The inputs are fixed and named: the owner seed is over the `PHRASE_A`
    /// identity's ML-DSA-87 public key; the preimage is over that same public
    /// key with `serial = 7`, `not_before = 1_700_000_000` and a `kem_pk` of
    /// 1568 bytes of `0x5a`. The preimage is pinned by its length and its
    /// SHA-384 digest rather than in full, since it is 4 235 bytes; the
    /// digest covers every byte and every field ordering.
    #[test]
    fn the_wire_is_pinned() {
        let a = alice();
        assert_eq!(ADVERT_SUBKEYS, 64);
        assert_eq!(
            ADVERT_LEN, 6211,
            "the record layout of docs/design/direct-messaging.md § Records"
        );

        let seed = derive_owner_seed(a.signing.public_key()).unwrap();
        assert_eq!(
            hex(seed.as_bytes()),
            "f7a96220acf173e29c795baed1bc58ea19e4e7167270e05e44d3f914a0991e58"
        );

        let pk = [0x5au8; ml_kem::EK_LEN];
        let preimage = signing_input(a.signing.public_key(), 7, ORIGIN, &pk);
        assert_eq!(preimage.len(), 4235);
        assert_eq!(
            hex(&oxicrypt_sha::sha384(&preimage).unwrap()),
            "8b6a0f413ad2e0121c52567ff69d3d1302a73d4fa43c2985ec99ef531017e5b0\
             78fda5ed817b23b8607460e9b33cc514"
        );
    }

    /// The public half really is recoverable from the secret half, which is
    /// what lets a snapshot hold only secrets.
    #[test]
    fn the_encapsulation_key_is_recoverable_from_the_decapsulation_key() {
        module();
        let mut ent = SeededEntropy::at(6);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let recovered = ek_from_dk(&k.current.dk);
        assert_eq!(&recovered[..], &k.encapsulation_key()[..]);
    }

    /// Rotation, retention and expiry, walked over explicit days.
    #[test]
    fn the_key_rotates_weekly_and_the_retained_one_expires_a_week_later() {
        let a = alice();
        let mut ent = SeededEntropy::at(10);
        let mut k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        assert_eq!(k.serial(), 0);
        assert_eq!(k.previous_serial(), None);

        // A sender encapsulates to the serial-0 key on day 6.
        let advert_0 =
            verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        let hello_0 = encapsulate_to(&advert_0, day(6), |b| ent.fill(b)).unwrap();
        assert_eq!(hello_0.serial, 0);

        assert_eq!(
            k.rotate_if_due(day(6), |b| ent.fill(b)).unwrap(),
            Rotation::Unchanged,
            "a rotation before the period has elapsed"
        );
        assert_eq!(k.serial(), 0);

        assert_eq!(
            k.rotate_if_due(day(7), |b| ent.fill(b)).unwrap(),
            Rotation::Rotated,
            "no rotation once the period has elapsed"
        );
        assert_eq!(k.serial(), 1);
        assert_eq!(k.not_before(), day(7));
        assert_eq!(k.previous_serial(), Some(0));
        assert_eq!(k.previous_retired_at(), Some(day(7)));

        // Retention: the day-6 ciphertext still opens six days into the
        // retention window, and yields the sender's own secret.
        let opened = k
            .decapsulate(hello_0.serial, &hello_0.ciphertext)
            .unwrap()
            .expect("the retained key must still open a hello encapsulated to it");
        assert_eq!(opened.as_bytes(), hello_0.shared_secret.as_bytes());

        // Day 14 rotates again, which retires serial 1 and drops serial 0.
        assert_eq!(
            k.rotate_if_due(day(14), |b| ent.fill(b)).unwrap(),
            Rotation::Rotated
        );
        assert_eq!(k.serial(), 2);
        assert_eq!(k.previous_serial(), Some(1));

        assert_eq!(
            k.rotate_if_due(day(15), |b| ent.fill(b)).unwrap(),
            Rotation::Unchanged
        );
        assert!(
            k.decapsulate(hello_0.serial, &hello_0.ciphertext)
                .unwrap()
                .is_none(),
            "a key past its retention window must open nothing"
        );

        // Control: the state still opens a hello encapsulated to what is
        // current, so the `None` above is expiry and not a broken decapsulate.
        let advert_2 =
            verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        assert_eq!(advert_2.serial, 2);
        let hello_2 = encapsulate_to(&advert_2, day(15), |b| ent.fill(b)).unwrap();
        let opened_2 = k
            .decapsulate(hello_2.serial, &hello_2.ciphertext)
            .unwrap()
            .expect("the current key must open a hello encapsulated to it");
        assert_eq!(opened_2.as_bytes(), hello_2.shared_secret.as_bytes());
    }

    /// A late rotation must not extend the old key's life by its own
    /// lateness: retention is anchored to the moment the key was DUE to stop
    /// being current.
    #[test]
    fn retention_is_anchored_to_the_due_moment_not_to_the_late_poll() {
        let a = alice();
        let mut ent = SeededEntropy::at(11);
        let mut k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let advert_0 =
            verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        let hello_0 = encapsulate_to(&advert_0, day(0), |b| ent.fill(b)).unwrap();

        // The poll runs a week late. The key was due to retire on day 7.
        assert_eq!(
            k.rotate_if_due(day(14), |b| ent.fill(b)).unwrap(),
            Rotation::Rotated
        );
        assert_eq!(k.previous_serial(), Some(0));
        assert_eq!(
            k.previous_retired_at(),
            Some(day(7)),
            "retention was anchored to the late poll rather than to the due moment"
        );

        k.prune(day(14));
        assert_eq!(k.previous_serial(), None);
        assert!(
            k.decapsulate(hello_0.serial, &hello_0.ciphertext)
                .unwrap()
                .is_none()
        );
    }

    /// Control for the clause above: an on-time rotation retains the key for
    /// the full period, so the anchoring change does not shorten retention
    /// for a poller that is not late.
    #[test]
    fn an_on_time_rotation_retains_the_key_for_the_full_period() {
        let a = alice();
        let mut ent = SeededEntropy::at(12);
        let mut k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let advert_0 =
            verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        let hello_0 = encapsulate_to(&advert_0, day(0), |b| ent.fill(b)).unwrap();
        assert_eq!(
            k.rotate_if_due(day(7), |b| ent.fill(b)).unwrap(),
            Rotation::Rotated
        );

        k.prune(day(10));
        let opened = k
            .decapsulate(hello_0.serial, &hello_0.ciphertext)
            .unwrap()
            .expect("a prune mid-window must not drop the retained key");
        assert_eq!(opened.as_bytes(), hello_0.shared_secret.as_bytes());

        k.prune(day(14));
        assert!(
            k.decapsulate(hello_0.serial, &hello_0.ciphertext)
                .unwrap()
                .is_none(),
            "a prune at the end of the window must drop the retained key"
        );
    }

    /// `rotate_if_due` prunes whether or not it rotates.
    #[test]
    fn a_call_that_does_not_rotate_still_prunes() {
        module();
        let mut ent = SeededEntropy::at(13);
        let mut k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        assert_eq!(
            k.rotate_if_due(day(14), |b| ent.fill(b)).unwrap(),
            Rotation::Rotated
        );
        // The retained key was due to retire on day 7 and is already past its
        // window; the next call is well before the next rotation.
        assert_eq!(k.previous_serial(), Some(0));
        assert_eq!(
            k.rotate_if_due(day(15), |b| ent.fill(b)).unwrap(),
            Rotation::Unchanged
        );
        assert_eq!(k.serial(), 1, "a call that reported Unchanged rotated");
        assert_eq!(k.previous_serial(), None, "the expired key was not pruned");
    }

    /// The reset path rotates off the schedule, and the key it retires stays
    /// usable for one retention period measured from that moment.
    ///
    /// Control: the same instant through `rotate_if_due` reports `Unchanged`,
    /// so the rotation below is `rotate_now` and not a rotation that was due
    /// anyway.
    #[test]
    fn a_reset_rotates_off_schedule_and_retains_for_a_full_period() {
        let a = alice();
        let mut ent = SeededEntropy::at(21);
        let mut k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let bytes = k.advert_bytes(&a.signing).unwrap();
        let advert = verify(a.signing.public_key(), &bytes).unwrap();
        let hello = encapsulate_to(&advert, day(0), |b| ent.fill(b)).unwrap();

        assert_eq!(
            k.rotate_if_due(day(3), |b| ent.fill(b)).unwrap(),
            Rotation::Unchanged,
            "the control: nothing is due on day 3"
        );
        k.rotate_now(day(3), |b| ent.fill(b)).unwrap();
        assert_eq!(k.serial(), 1);
        assert_eq!(k.previous_serial(), Some(0));
        assert_eq!(k.previous_retired_at(), Some(day(3)));

        // The retired key still opens the hello encapsulated to it, up to one
        // retention period after the reset.
        k.prune(day(9));
        assert!(
            k.decapsulate(hello.serial, &hello.ciphertext)
                .unwrap()
                .is_some(),
            "the retired key is still held on day 9"
        );
        k.prune(day(10));
        assert_eq!(k.previous_serial(), None);
        assert!(
            k.decapsulate(hello.serial, &hello.ciphertext)
                .unwrap()
                .is_none(),
            "the retired key is gone a full period after the reset"
        );
    }

    /// A restart rebuilds the same keys, current and retained.
    #[test]
    fn a_snapshot_restores_both_keys() {
        let a = alice();
        let mut ent = SeededEntropy::at(14);
        let mut k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let advert_0 =
            verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        let hello_0 = encapsulate_to(&advert_0, day(0), |b| ent.fill(b)).unwrap();
        assert_eq!(
            k.rotate_if_due(day(7), |b| ent.fill(b)).unwrap(),
            Rotation::Rotated
        );
        let advert_1 =
            verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        let hello_1 = encapsulate_to(&advert_1, day(8), |b| ent.fill(b)).unwrap();

        let restored = AdvertKeys::restore(k.snapshot());
        assert_eq!(restored.serial(), 1);
        assert_eq!(restored.not_before(), day(7));
        assert_eq!(restored.previous_serial(), Some(0));
        assert_eq!(restored.previous_retired_at(), Some(day(7)));
        assert_eq!(
            restored.advert_bytes(&a.signing).unwrap(),
            k.advert_bytes(&a.signing).unwrap(),
            "a restored state must republish the same advert"
        );
        let opened_1 = restored
            .decapsulate(hello_1.serial, &hello_1.ciphertext)
            .unwrap()
            .expect("the restored current key must open its hello");
        assert_eq!(opened_1.as_bytes(), hello_1.shared_secret.as_bytes());
        let opened_0 = restored
            .decapsulate(hello_0.serial, &hello_0.ciphertext)
            .unwrap()
            .expect("the restored retained key must open its hello");
        assert_eq!(opened_0.as_bytes(), hello_0.shared_secret.as_bytes());

        // Control: a snapshot taken with no retained key restores without one,
        // so the serial-0 open above is the retained key and not a decapsulate
        // that opens anything handed to it.
        let mut bare = k.snapshot();
        bare.previous = None;
        let restored_bare = AdvertKeys::restore(bare);
        assert!(
            restored_bare
                .decapsulate(hello_0.serial, &hello_0.ciphertext)
                .unwrap()
                .is_none()
        );
    }

    /// A reader keeps the highest serial it has verified.
    #[test]
    fn a_reader_refuses_a_replayed_older_advert() {
        module();
        let mut ent = SeededEntropy::at(15);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let at = |serial: u64| VerifiedAdvert {
            serial,
            not_before: day(0),
            kem_pk: Box::new(*k.encapsulation_key()),
        };
        let mut reader = AdvertReader::new();
        assert_eq!(reader.highest(), None);
        assert_eq!(reader.accept(at(3)).unwrap().serial, 3);
        assert_eq!(reader.accept(at(5)).unwrap().serial, 5);
        assert_eq!(
            reader.accept(at(4)),
            Err(AdvertError::Regressed {
                seen: 4,
                highest: 5
            })
        );
        assert_eq!(reader.highest(), Some(5), "a refusal moved the reader");
        // Control: the same serial again is accepted, so the refusal above is
        // the regression and not a reader that refuses everything.
        assert_eq!(reader.accept(at(5)).unwrap().serial, 5);
    }

    /// The usability window's three boundaries.
    #[test]
    fn an_advert_is_usable_only_inside_its_window() {
        let a = alice();
        let mut ent = SeededEntropy::at(16);
        let k = AdvertKeys::new(day(7), |b| ent.fill(b)).unwrap();
        let advert = verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        let not_before = advert.not_before;

        let too_early = not_before - CLOCK_SKEW_SECS - 1;
        assert!(!advert.usable_at(too_early));
        assert_eq!(
            encapsulate_to(&advert, too_early, |b| ent.fill(b)).err(),
            Some(AdvertError::Unusable {
                now: too_early,
                not_before
            })
        );

        // Control: one second later, inside the skew allowance, it is usable.
        assert!(advert.usable_at(not_before - CLOCK_SKEW_SECS));
        assert!(encapsulate_to(&advert, not_before, |b| ent.fill(b)).is_ok());

        let closed = not_before + 2 * ROTATION_PERIOD_SECS;
        assert!(!advert.usable_at(closed), "the window is closed at its end");
        assert!(
            advert.usable_at(closed - 1),
            "the instant before the end must still be usable"
        );
        assert_eq!(
            encapsulate_to(&advert, closed, |b| ent.fill(b)).err(),
            Some(AdvertError::Unusable {
                now: closed,
                not_before
            })
        );
    }

    /// Counts the rewrites one poll asked for, and asserts the running total
    /// moved by exactly that much.
    #[derive(Default)]
    struct ActionCounter {
        rewrites: usize,
    }

    impl ActionCounter {
        /// Applies one poll's actions and returns how many rewrites THIS call
        /// carried — never the running total, so a case cannot pass on a
        /// count another case produced.
        fn apply(&mut self, actions: &[AdvertAction]) -> usize {
            let before = self.rewrites;
            for action in actions {
                match action {
                    AdvertAction::Rewrite(bytes) => {
                        assert_eq!(bytes.len(), ADVERT_LEN);
                        self.rewrites += 1;
                    }
                }
            }
            let this_call = self.rewrites - before;
            assert_eq!(
                this_call,
                actions.len(),
                "the harness and the returned vector disagree"
            );
            this_call
        }
    }

    #[test]
    fn a_poll_rewrites_only_on_a_missing_differing_or_wrong_record() {
        let a = alice();
        let mut ent = SeededEntropy::at(20);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let canonical = k.advert_bytes(&a.signing).unwrap();
        let intact = InspectReport {
            local_seq: Some(4),
            network_seq: Some(4),
        };
        let mut counter = ActionCounter::default();

        // Asserted first: an intact record asks for nothing. Every case below
        // is compared against its own call's count, so none of them can pass
        // on a rewrite another case produced.
        let actions = k.on_poll(&a.signing, &intact, Some(&canonical)).unwrap();
        assert_eq!(
            counter.apply(&actions),
            0,
            "an intact record asked for a rewrite"
        );

        for (name, report) in [
            (
                "missing",
                InspectReport {
                    local_seq: Some(4),
                    network_seq: None,
                },
            ),
            (
                "behind",
                InspectReport {
                    local_seq: Some(4),
                    network_seq: Some(3),
                },
            ),
            (
                "ahead",
                InspectReport {
                    local_seq: Some(4),
                    network_seq: Some(5),
                },
            ),
            (
                "no local copy",
                InspectReport {
                    local_seq: None,
                    network_seq: Some(3),
                },
            ),
            (
                "neither side",
                InspectReport {
                    local_seq: None,
                    network_seq: None,
                },
            ),
        ] {
            assert!(repair_needed(&report), "{name} was not read as repair");
            let actions = k.on_poll(&a.signing, &report, Some(&canonical)).unwrap();
            assert_eq!(counter.apply(&actions), 1, "{name} asked for no rewrite");
        }
        assert!(!repair_needed(&intact), "an intact report asked for repair");

        let mut wrong = canonical.clone();
        wrong[0] ^= 0x01;
        let actions = k.on_poll(&a.signing, &intact, Some(&wrong)).unwrap();
        assert_eq!(
            counter.apply(&actions),
            1,
            "a record differing by one byte asked for no rewrite"
        );
        assert!(matches!(
            actions.first(),
            Some(AdvertAction::Rewrite(bytes)) if *bytes == canonical
        ));
    }

    /// A poll that read nothing back is settled by the report alone.
    #[test]
    fn a_poll_with_nothing_fetched_follows_the_report() {
        let a = alice();
        let mut ent = SeededEntropy::at(21);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let intact = InspectReport {
            local_seq: Some(4),
            network_seq: Some(4),
        };
        assert!(k.on_poll(&a.signing, &intact, None).unwrap().is_empty());

        let missing = InspectReport {
            local_seq: Some(4),
            network_seq: None,
        };
        let actions = k.on_poll(&a.signing, &missing, None).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            AdvertAction::Rewrite(k.advert_bytes(&a.signing).unwrap())
        );
    }

    /// A sender's outstanding hello across the recipient's rotation.
    #[test]
    fn a_sender_re_encapsulates_once_the_recipient_rotates_past_retention() {
        let a = alice();
        let b = bob();
        let mut ent_a = SeededEntropy::at(30);
        let mut ent_b = SeededEntropy::at(31);
        let sender = AdvertKeys::new(day(0), |x| ent_a.fill(x)).unwrap();
        let mut recipient = AdvertKeys::new(day(0), |x| ent_b.fill(x)).unwrap();
        // The sender publishes an advert of its own, and the two states are
        // independent: nothing below can pass by the two sides sharing a key.
        let sender_advert = verify(
            a.signing.public_key(),
            &sender.advert_bytes(&a.signing).unwrap(),
        )
        .unwrap();
        assert_ne!(
            &sender_advert.kem_pk[..],
            &recipient.encapsulation_key()[..],
            "the two parties must hold independent advert keys"
        );

        let advert_0 = verify(
            b.signing.public_key(),
            &recipient.advert_bytes(&b.signing).unwrap(),
        )
        .unwrap();
        let hello = encapsulate_to(&advert_0, usable_now(&advert_0), |x| ent_a.fill(x)).unwrap();

        assert_eq!(
            recipient.rotate_if_due(day(7), |x| ent_b.fill(x)).unwrap(),
            Rotation::Rotated
        );

        // Control, both halves inside the retention window: the old hello
        // still opens, and an unchanged serial asks for no rewrite.
        let opened = recipient
            .decapsulate(hello.serial, &hello.ciphertext)
            .unwrap()
            .expect("a hello inside the retention window must still open");
        assert_eq!(opened.as_bytes(), hello.shared_secret.as_bytes());
        assert!(!hello_needs_rewrite(hello.serial, &advert_0));
        assert!(
            day(13) < day(7).saturating_add(ROTATION_PERIOD_SECS),
            "day 13 must lie inside the retention window this test walks"
        );

        recipient.prune(day(14));

        let advert_1 = verify(
            b.signing.public_key(),
            &recipient.advert_bytes(&b.signing).unwrap(),
        )
        .unwrap();
        assert_eq!(advert_1.serial, 1);
        assert!(
            recipient
                .decapsulate(hello.serial, &hello.ciphertext)
                .unwrap()
                .is_none(),
            "the key the hello was encapsulated to is past retention"
        );
        assert!(hello_needs_rewrite(hello.serial, &advert_1));

        let rewritten = encapsulate_to(&advert_1, day(15), |x| ent_a.fill(x)).unwrap();
        assert_eq!(rewritten.serial, 1);
        let opened = recipient
            .decapsulate(rewritten.serial, &rewritten.ciphertext)
            .unwrap()
            .expect("a hello re-encapsulated to the current key must open");
        assert_eq!(opened.as_bytes(), rewritten.shared_secret.as_bytes());
        assert!(!hello_needs_rewrite(rewritten.serial, &advert_1));
    }

    /// A replayed older advert must not send a sender back to a retired key.
    #[test]
    fn a_lower_observed_serial_never_asks_for_a_rewrite() {
        module();
        let mut ent = SeededEntropy::at(32);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let at = |serial: u64| VerifiedAdvert {
            serial,
            not_before: day(0),
            kem_pk: Box::new(*k.encapsulation_key()),
        };
        assert!(
            !hello_needs_rewrite(5, &at(3)),
            "a replayed older advert asked for a re-encapsulation to a retired key"
        );
        assert!(!hello_needs_rewrite(5, &at(5)));
        // Control: a genuinely newer advert does ask for one.
        assert!(hello_needs_rewrite(5, &at(6)));
    }

    #[test]
    fn poll_interval_is_in_band_and_jittered() {
        module();
        let mut ent = SeededEntropy::at(40);
        let draws: Vec<_> = (0..64)
            .map(|_| next_poll_interval(|b| ent.fill(b)))
            .collect();
        for d in &draws {
            assert!(
                *d >= POLL_INTERVAL_MIN && *d <= POLL_INTERVAL_MAX,
                "{d:?} outside [{POLL_INTERVAL_MIN:?}, {POLL_INTERVAL_MAX:?}]"
            );
        }
        let distinct: std::collections::BTreeSet<_> = draws.iter().collect();
        assert!(
            distinct.len() > 1,
            "64 draws collapsed to one value — the cadence is not jittered"
        );
        // The production draw goes through the same band.
        let os = next_poll_interval_os();
        assert!(os >= POLL_INTERVAL_MIN && os <= POLL_INTERVAL_MAX);
    }

    /// The band ends are exactly reachable, so a draw narrowed to some
    /// fraction of the span could not pass the test above unnoticed.
    #[test]
    fn poll_band_ends_are_exactly_reachable() {
        module();
        let span = (POLL_INTERVAL_MAX.as_millis() - POLL_INTERVAL_MIN.as_millis()) as u64;
        let at = |v: u64| {
            next_poll_interval(move |buf: &mut [u8]| {
                buf.fill(0);
                let bytes = v.to_le_bytes();
                let n = buf.len().min(bytes.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(())
            })
        };
        assert_eq!(
            at(0),
            POLL_INTERVAL_MIN,
            "a zero draw must land on the floor"
        );
        assert_eq!(
            at(span),
            POLL_INTERVAL_MAX,
            "a full draw must land on the ceiling"
        );
    }

    /// An entropy failure is reported, never papered over with a weak key.
    #[test]
    fn an_entropy_failure_refuses_to_generate_or_encapsulate() {
        let a = alice();
        let mut ent = SeededEntropy::at(50);
        let k = AdvertKeys::new(day(0), |b| ent.fill(b)).unwrap();
        let advert = verify(a.signing.public_key(), &k.advert_bytes(&a.signing).unwrap()).unwrap();
        assert_eq!(
            AdvertKeys::new(day(0), |_| Err(())).err(),
            Some(AdvertError::Entropy)
        );
        assert_eq!(
            encapsulate_to(&advert, usable_now(&advert), |_| Err(())).err(),
            Some(AdvertError::Entropy)
        );
    }
}
