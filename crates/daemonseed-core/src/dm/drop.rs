//! The **drop** — the record anyone may write into, used only for first
//! contact.
//!
//! `docs/design/direct-messaging.md` § Records gives the record and its
//! address. A drop is [`DROP_SUBKEYS`] subkeys of [`DROP_SLOT_LEN`] bytes, one
//! hello per slot, and a hello is
//!
//! ```text
//!   kem_ct ‖ AEAD_{k_hello}(lookup_key ‖ r) ‖ pow_tag
//! ```
//!
//! where `ss0` is the secret a sender gets from encapsulating to the
//! recipient's advert key, `k_hello = HKDF(ss0, DM_DROP_HELLO)`, `lookup_key`
//! addresses the sender's own channel record and `r` is 32 fresh bytes that
//! pick the slot.
//!
//! Four rules govern it:
//!
//! - **World-writable by design.** The owner seed is
//!   `HKDF-SHA-384(salt = DM_DROP_SALT, ikm = PK_lt of the RECIPIENT, info =
//!   DM_DROP_OWNER)`, so a stranger holding nothing but the recipient's
//!   published identity computes the address — which is the whole of first
//!   contact — and therefore may also write and erase. Nothing here rests on
//!   ownership: a hello is sealed, and a slot holding anything else is
//!   discarded.
//! - **The slot is a function of `r` alone.** [`slot_for`] is
//!   `SHA-384(DM_DROP_SLOT ‖ lp(r)) mod DROP_SUBKEYS`, read off the digest's
//!   last byte. `r` is secret until the AEAD opens, so a storage node cannot
//!   predict which slot a given sender will take, and a fresh `r` moves the
//!   hello somewhere else.
//! - **The tag is checked on every hello.** `pow_tag` is
//!   [`DROP_POW_TAG_LEN`] bytes of `SHA-384(DM_DROP_POW ‖ lp(kem_ct) ‖ lp(r) ‖
//!   lp(recipient identity))` at [`DROP_POW_BITS`] difficulty. At zero bits it
//!   costs one hash to produce and binds nothing the fixed slot count and the
//!   write ceiling do not already bind (§ Abuse). It is present and it is
//!   checked, so raising the difficulty changes a constant rather than the
//!   record.
//! - **One read-back, then a re-pick.** After writing, a sender reads the slot
//!   once. [`after_read_back`] answers [`ReadBack::Landed`] only when the bytes
//!   found are the bytes written; anything else is [`ReadBack::Clobbered`] and
//!   the sender draws a fresh `r` and rewrites, which is what
//!   [`HelloAttempt`] carries.
//!
//! **The slot label is this module's reading of a point the design leaves
//! open.** The design fixes the slot as `H(r) mod 256` and does not say
//! whether `H` is domain-separated. It is separated here under
//! [`domain::DM_DROP_SLOT`], with `r` length-prefixed, so the digest that
//! picks a slot can never coincide with a digest computed over the same bytes
//! for another purpose. Two implementations must agree on this to find each
//! other's hellos.
//!
//! Everything here is pure: no I/O, no clock, no ambient randomness except
//! the AEAD nonce the shared envelope primitive draws. `r` arrives from the
//! caller, or from a fill function the caller supplies, and a read-back is a
//! value the caller obtained and passes in.
//!
//! Serves FC4, FC5.

use oxicrypt_aes::Aes256Key;
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use oxicrypt_sha::sha384;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::dm::pow::has_leading_zero_bits;
use crate::dm::{advert, domain, push_lp};
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Subkeys in a drop record — the `o_cnt` of its `dflt(o_cnt)` schema, and
/// part of the record's address.
///
/// One hello per slot. A writer MUST build its `RecordShape` from this
/// constant rather than a literal: `o_cnt` is part of the deterministic
/// address, so a shape that disagrees addresses a record nobody reads.
pub const DROP_SUBKEYS: u16 = 256;

/// Bytes one drop slot holds: `min(32 KiB, 1 MiB / DROP_SUBKEYS)`.
///
/// Derived from [`DROP_SUBKEYS`] by the substrate's own rule, so the figure
/// moves with the subkey count. A hello is [`HELLO_LEN`] bytes and must fit
/// inside this, which is asserted in the tests rather than left to arithmetic
/// in a comment.
pub const DROP_SLOT_LEN: usize = {
    let per_subkey = (1024 * 1024) / DROP_SUBKEYS as usize;
    if per_subkey < 32 * 1024 {
        per_subkey
    } else {
        32 * 1024
    }
};

/// Pins the derivation above to the figure
/// `docs/design/direct-messaging.md` § Substrate facts states for a
/// 256-subkey record.
const _: () = assert!(
    DROP_SLOT_LEN == 4096,
    "a 256-subkey record holds 4 KiB per subkey"
);

/// Byte length of the Veilid owner seed this module derives.
pub const DROP_OWNER_SEED_LEN: usize = 32;

/// Leading zero bits a hello's `pow_tag` must show.
///
/// Zero, and the zero is the design's (§ Abuse): the rate at which one node
/// can fill a drop is already bounded by the write ceiling and by
/// [`DROP_SUBKEYS`], so below about fifteen seconds of work a proof binds
/// nothing new. The tag is still carried and still checked, so raising this
/// constant is the whole of raising the difficulty.
pub const DROP_POW_BITS: u32 = 0;

/// Byte length of a hello's `pow_tag`.
pub const DROP_POW_TAG_LEN: usize = 8;

/// Byte length of the channel lookup key a hello discloses.
pub const HELLO_LOOKUP_KEY_LEN: usize = 32;

/// Byte length of `r`, the value that picks the slot.
pub const HELLO_R_LEN: usize = 32;

/// Byte length of a hello's sealed plaintext: `lookup_key ‖ r`.
const HELLO_PLAINTEXT_LEN: usize = HELLO_LOOKUP_KEY_LEN + HELLO_R_LEN;

/// Byte length of an encoded hello:
/// `kem_ct ‖ nonce ‖ ciphertext ‖ tag ‖ pow_tag`.
pub const HELLO_LEN: usize =
    ml_kem::CT_LEN + NONCE_LEN + HELLO_PLAINTEXT_LEN + TAG_LEN + DROP_POW_TAG_LEN;

/// Byte offset at which the sealed region starts.
const SEALED_AT: usize = ml_kem::CT_LEN;

/// Byte offset at which the `pow_tag` starts.
const POW_TAG_AT: usize = HELLO_LEN - DROP_POW_TAG_LEN;

redacted_secret_newtype! {
    /// The Veilid record-owner seed for an identity's drop.
    ///
    /// A secret newtype for the zeroize-on-drop and redacted-`Debug` hygiene,
    /// but deliberately world-derivable: every sender computes the same value
    /// from the recipient's published identity key, which is what makes first
    /// contact possible at all. Holding it confers write access — and so does
    /// holding the public key — which is why a hello is sealed and a slot's
    /// contents are never trusted for being where they are.
    boxed pub struct DropOwnerSeed([u8; DROP_OWNER_SEED_LEN]);
}

redacted_secret_newtype! {
    /// The AEAD key a hello is sealed under: `HKDF(ss0, DM_DROP_HELLO)`.
    boxed pub struct HelloKey([u8; 32]);
}

/// Why a drop operation failed.
///
/// `PartialEq` is implemented by hand rather than derived because
/// `oxicrypt_module::Error` and `oxicrypt_aes::ModeError` are not comparable;
/// those variants compare equal on the variant alone, which is all a caller
/// needs.
#[derive(Debug)]
pub enum DropError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// The bytes are not [`HELLO_LEN`] long, so no field can be read from
    /// them. Carries both figures, so a truncation is diagnosable.
    Length {
        /// What a hello measures.
        expected: usize,
        /// What arrived.
        actual: usize,
    },
    /// The `pow_tag` is not a valid tag for this hello: it fails the
    /// [`DROP_POW_BITS`] shape check, or it is not the tag over the
    /// ciphertext, the `r` the seal carried and the recipient identity.
    BadTag,
    /// The AEAD did not open: a wrong `ss0`, a tampered ciphertext, or an
    /// associated-data mismatch. Deliberately uniform — a reader that told
    /// those apart would be an oracle for a world-writable record.
    Aead,
    /// The hello opened, but the `r` it carries picks a slot other than the
    /// one these bytes were read from — a valid hello copied out of its own
    /// slot, which is junk wherever else it lands.
    SlotMismatch {
        /// The slot the hello's `r` picks.
        expected: u16,
        /// The slot the bytes were read from.
        found: u16,
    },
    /// The entropy source failed, so no `r` could be drawn and no hello
    /// sealed.
    Entropy,
    /// The crypto module refused an AES or SHA call.
    Module(oxicrypt_module::Error),
}

impl PartialEq for DropError {
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
            (Self::BadTag, Self::BadTag) => true,
            (Self::Aead, Self::Aead) => true,
            (
                Self::SlotMismatch {
                    expected: ea,
                    found: fa,
                },
                Self::SlotMismatch {
                    expected: eb,
                    found: fb,
                },
            ) => ea == eb && fa == fb,
            (Self::Entropy, Self::Entropy) => true,
            // Compared on the variant: the wrapped cause is diagnostic and is
            // not itself comparable.
            (Self::Module(_), Self::Module(_)) => true,
            _ => false,
        }
    }
}

impl Eq for DropError {}

impl std::fmt::Display for DropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "drop HKDF failed: {e:?}"),
            Self::Length { expected, actual } => {
                write!(f, "hello: expected {expected} bytes, got {actual}")
            }
            Self::BadTag => write!(f, "hello: the proof-of-work tag is not valid"),
            Self::Aead => write!(f, "hello: the seal did not open"),
            Self::SlotMismatch { expected, found } => write!(
                f,
                "hello: its r picks slot {expected}, but it was read from slot {found}"
            ),
            Self::Entropy => write!(f, "drop: the entropy source failed"),
            Self::Module(e) => write!(f, "drop: the crypto module refused: {e:?}"),
        }
    }
}

impl std::error::Error for DropError {}

impl From<EnvelopeError> for DropError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_) => Self::Entropy,
            // A too-short buffer cannot reach here — the length gate runs
            // first — and a decrypt failure is uniform by design.
            EnvelopeError::TooShort | EnvelopeError::Decrypt(_) | EnvelopeError::Encrypt(_) => {
                Self::Aead
            }
        }
    }
}

/// Derive the world-derivable Veilid owner seed for `recipient_pubkey`'s drop:
/// `HKDF-SHA-384(salt = DM_DROP_SALT, ikm = PK_lt, info = DM_DROP_OWNER)`.
///
/// Deterministic and pure. The recipient derives it to sweep its own drop and
/// every sender derives the same value to write into it. It takes the same
/// `ikm` as [`advert::derive_owner_seed`] and yields a different address
/// purely because the labels differ, which is why those labels are distinct
/// and prefix-free.
pub fn derive_owner_seed(
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<DropOwnerSeed, DropError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_DROP_SALT), recipient_pubkey)
        .map_err(DropError::Kdf)?;
    let seed = derive_boxed_seed::<DROP_OWNER_SEED_LEN>(&hkdf, domain::DM_DROP_OWNER)
        .map_err(DropError::Kdf)?;
    Ok(DropOwnerSeed(seed))
}

/// Derive the key a hello is sealed under: `HKDF(ss0, DM_DROP_HELLO)`.
///
/// `ss0` is the secret both sides hold after the sender encapsulated to the
/// recipient's advert key, so the recipient recomputes this key from its own
/// decapsulation and nothing else travels.
pub fn hello_key(ss0: &advert::AdvertSharedSecret) -> Result<HelloKey, DropError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_DROP_HELLO_SALT), ss0.as_bytes())
        .map_err(DropError::Kdf)?;
    let key = derive_boxed_seed::<32>(&hkdf, domain::DM_DROP_HELLO).map_err(DropError::Kdf)?;
    Ok(HelloKey(key))
}

/// The associated data a hello's seal binds: `DM_DROP_AAD ‖ lp(kem_ct) ‖
/// lp(recipient identity)`.
///
/// Binding `kem_ct` is what stops a ciphertext being lifted out of one hello
/// and pasted in front of another's seal; binding the recipient's identity
/// public key is what stops a hello written at one identity's drop opening at
/// another's. Neither value is carried in the sealed region, so neither
/// widens what the record discloses.
pub fn hello_aad(
    kem_ct: &[u8; ml_kem::CT_LEN],
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(domain::DM_DROP_AAD.len() + 16 + ml_kem::CT_LEN + ml_dsa::PK_LEN);
    buf.extend_from_slice(domain::DM_DROP_AAD);
    push_lp(&mut buf, kem_ct);
    push_lp(&mut buf, recipient_pubkey);
    buf
}

/// The proof-of-work preimage: `DM_DROP_POW ‖ lp(kem_ct) ‖ lp(r) ‖
/// lp(recipient identity)`.
///
/// Every field is length-prefixed with a big-endian `u64` length, the one
/// convention this build uses everywhere, so no pair of adjacent fields can be
/// re-split into a different tuple. A uniformly wrong encoding — a dropped
/// prefix, two fields transposed — is invisible to a round trip, because the
/// minter and the verifier here are the same function; the known-answer test
/// is what catches that class.
pub fn pow_input(
    kem_ct: &[u8; ml_kem::CT_LEN],
    r: &[u8; HELLO_R_LEN],
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        domain::DM_DROP_POW.len() + 24 + ml_kem::CT_LEN + HELLO_R_LEN + ml_dsa::PK_LEN,
    );
    buf.extend_from_slice(domain::DM_DROP_POW);
    push_lp(&mut buf, kem_ct);
    push_lp(&mut buf, r);
    push_lp(&mut buf, recipient_pubkey);
    buf
}

/// Mint the `pow_tag` for one hello: the first [`DROP_POW_TAG_LEN`] bytes of
/// the SHA-384 digest over [`pow_input`].
///
/// At [`DROP_POW_BITS`] zero this is one hash and no search, which is what the
/// design means by free to produce.
pub fn pow_tag(
    kem_ct: &[u8; ml_kem::CT_LEN],
    r: &[u8; HELLO_R_LEN],
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<[u8; DROP_POW_TAG_LEN], DropError> {
    let digest = sha384(&pow_input(kem_ct, r, recipient_pubkey)).map_err(DropError::Module)?;
    let mut tag = [0u8; DROP_POW_TAG_LEN];
    tag.copy_from_slice(&digest[..DROP_POW_TAG_LEN]);
    Ok(tag)
}

/// Which slot of a drop a hello with this `r` occupies:
/// `SHA-384(DM_DROP_SLOT ‖ lp(r)) mod DROP_SUBKEYS`, taken from the digest's
/// last byte.
///
/// **No modulo bias:** [`DROP_SUBKEYS`] is 256 and divides 2^8 exactly, so the
/// last byte of a digest is already uniform over the slots and no reduction is
/// needed at all. A slot count that was not a power of two would need
/// rejection sampling; the tests assert the power-of-two property so a change
/// to [`DROP_SUBKEYS`] cannot silently skew it.
pub fn slot_for(r: &[u8; HELLO_R_LEN]) -> Result<u16, DropError> {
    let mut input = Vec::with_capacity(domain::DM_DROP_SLOT.len() + 8 + HELLO_R_LEN);
    input.extend_from_slice(domain::DM_DROP_SLOT);
    push_lp(&mut input, r);
    let digest = sha384(&input).map_err(DropError::Module)?;
    let last = *digest.last().expect("SHA-384 produces 48 bytes");
    Ok(u16::from(last) % DROP_SUBKEYS)
}

/// Draw a fresh `r`.
///
/// The only randomness this module asks for, and it is the caller's: a sender
/// uses it once to open a first contact and again on every clobbered
/// read-back.
pub fn repick(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<[u8; HELLO_R_LEN], DropError> {
    let mut r = [0u8; HELLO_R_LEN];
    if fill(&mut r).is_err() {
        r.zeroize();
        return Err(DropError::Entropy);
    }
    Ok(r)
}

/// What a hello discloses once it opens: the lookup key of the sender's own
/// channel record, and the `r` that placed the hello.
///
/// Only constructible via [`open_hello`], so holding one is the proof the seal
/// opened and the tag verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The lookup key of `CHAN(sender → recipient)`, which the recipient now
    /// reads.
    pub lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The value that picked this hello's slot. The recipient needs it to
    /// erase the slot the hello actually occupies.
    pub r: [u8; HELLO_R_LEN],
}

/// Seal a hello for publication:
/// `kem_ct ‖ AEAD_{k_hello}(lookup_key ‖ r) ‖ pow_tag`.
///
/// `encap` is what [`advert::encapsulate_to`] produced against the
/// recipient's verified advert, so it carries both the ciphertext the hello
/// publishes and the `ss0` the key comes from.
pub fn seal_hello(
    encap: &advert::HelloEncapsulation,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    r: &[u8; HELLO_R_LEN],
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<Vec<u8>, DropError> {
    let key = hello_key(&encap.shared_secret)?;
    let aes = Aes256Key::new(key.as_bytes()).map_err(DropError::Module)?;

    let mut plaintext = Vec::with_capacity(HELLO_PLAINTEXT_LEN);
    plaintext.extend_from_slice(lookup_key);
    plaintext.extend_from_slice(r);
    let sealed = seal_envelope(
        &aes,
        &hello_aad(&encap.ciphertext, recipient_pubkey),
        &plaintext,
    );
    plaintext.zeroize();
    let sealed = sealed?;

    let tag = pow_tag(&encap.ciphertext, r, recipient_pubkey)?;

    let mut out = Vec::with_capacity(HELLO_LEN);
    out.extend_from_slice(encap.ciphertext.as_slice());
    out.extend_from_slice(&sealed);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Open a hello read out of a drop slot, under the `ss0` a decapsulation
/// recovered.
///
/// `slot` is the subkey these bytes were read from. A hello whose `r` picks a
/// different slot is refused with [`DropError::SlotMismatch`], so a valid
/// hello copied out of its own slot does not open where it was pasted.
///
/// Fails closed in order, and each step has its own error so a sweep can tell
/// junk from a hello meant for someone else: the length must be exactly
/// [`HELLO_LEN`] ([`DropError::Length`]), the `pow_tag` must clear
/// [`DROP_POW_BITS`] ([`DropError::BadTag`]), the seal must open
/// ([`DropError::Aead`]), the tag must be the tag over the `r` the seal
/// carried ([`DropError::BadTag`]), and `r` must pick `slot`
/// ([`DropError::SlotMismatch`]).
///
/// **At [`DROP_POW_BITS`] zero the tag's value check binds nothing the AEAD
/// does not already bind.** Anything that opens the seal was produced by a
/// party holding `ss0`, and that party could equally mint the tag; and the
/// caller has already paid an ML-KEM decapsulation to reach this call, so the
/// shape check saves no work on a sweep either. The tag is checked because the
/// design requires it present and checked, which is what makes raising
/// [`DROP_POW_BITS`] a change to a constant rather than to the record.
pub fn open_hello(
    ss0: &advert::AdvertSharedSecret,
    bytes: &[u8],
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
    slot: u16,
) -> Result<Hello, DropError> {
    if bytes.len() != HELLO_LEN {
        return Err(DropError::Length {
            expected: HELLO_LEN,
            actual: bytes.len(),
        });
    }
    let kem_ct: &[u8; ml_kem::CT_LEN] = bytes[..SEALED_AT].try_into().expect("checked length");
    let sealed = &bytes[SEALED_AT..POW_TAG_AT];
    let tag = &bytes[POW_TAG_AT..];

    if !has_leading_zero_bits(tag, DROP_POW_BITS) {
        return Err(DropError::BadTag);
    }

    let key = hello_key(ss0)?;
    let aes = Aes256Key::new(key.as_bytes()).map_err(DropError::Module)?;
    let mut plaintext = open_envelope(&aes, &hello_aad(kem_ct, recipient_pubkey), sealed)?;
    if plaintext.len() != HELLO_PLAINTEXT_LEN {
        plaintext.zeroize();
        return Err(DropError::Aead);
    }
    let mut hello = Hello {
        lookup_key: [0u8; HELLO_LOOKUP_KEY_LEN],
        r: [0u8; HELLO_R_LEN],
    };
    hello
        .lookup_key
        .copy_from_slice(&plaintext[..HELLO_LOOKUP_KEY_LEN]);
    hello.r.copy_from_slice(&plaintext[HELLO_LOOKUP_KEY_LEN..]);
    plaintext.zeroize();

    if pow_tag(kem_ct, &hello.r, recipient_pubkey)? != tag {
        return Err(DropError::BadTag);
    }
    let picked = slot_for(&hello.r)?;
    if picked != slot {
        return Err(DropError::SlotMismatch {
            expected: picked,
            found: slot,
        });
    }
    Ok(hello)
}

/// What one read-back of a written slot settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a clobbered slot is only repaired by re-picking r and rewriting"]
pub enum ReadBack {
    /// The slot holds the bytes that were written. Nothing more to do.
    Landed,
    /// The slot holds something else, or nothing. Another writer reached it —
    /// the record is world-writable — so the sender picks a fresh `r` and
    /// writes again.
    Clobbered,
}

/// Settle one read-back: [`ReadBack::Landed`] only when the slot holds exactly
/// the bytes written, [`ReadBack::Clobbered`] otherwise.
///
/// An absent value is clobbered rather than a separate answer. A plain read
/// returns the same absent result for a never-written and an evicted subkey
/// (§ Substrate facts), so a sender cannot tell those apart and the response
/// to both is the same: write again.
pub fn after_read_back(written: &[u8], found: Option<&[u8]>) -> ReadBack {
    match found {
        Some(bytes) if bytes == written => ReadBack::Landed,
        _ => ReadBack::Clobbered,
    }
}

/// A hello in flight: the `r` it was sealed with, the slot that `r` picks, and
/// how many times the sender has re-picked.
///
/// The re-pick count is carried so a caller can see the retry behaviour it is
/// getting rather than infer it: one clobber is one re-pick, and a sender that
/// found itself re-picking without bound would be contending with an attacker
/// keeping the drop full (§ Abuse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAttempt {
    r: [u8; HELLO_R_LEN],
    slot: u16,
    repicks: u32,
}

impl HelloAttempt {
    /// An attempt at the slot `r` picks.
    pub fn new(r: [u8; HELLO_R_LEN]) -> Result<Self, DropError> {
        Ok(Self {
            slot: slot_for(&r)?,
            r,
            repicks: 0,
        })
    }

    /// The `r` this attempt is sealed with.
    pub fn r(&self) -> &[u8; HELLO_R_LEN] {
        &self.r
    }

    /// The slot this attempt occupies.
    pub fn slot(&self) -> u16 {
        self.slot
    }

    /// How many times this attempt has re-picked `r`.
    pub fn repicks(&self) -> u32 {
        self.repicks
    }

    /// Settle one read-back and, on [`ReadBack::Clobbered`], move to a fresh
    /// `r` and its slot.
    ///
    /// Exactly one re-pick per clobber: the caller re-seals with
    /// [`Self::r`] and writes at [`Self::slot`], then reads back again.
    pub fn read_back(
        &mut self,
        written: &[u8],
        found: Option<&[u8]>,
        fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<ReadBack, DropError> {
        let outcome = after_read_back(written, found);
        if outcome == ReadBack::Clobbered {
            let r = repick(fill)?;
            self.slot = slot_for(&r)?;
            self.r = r;
            self.repicks = self.repicks.saturating_add(1);
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::SignKeypair;

    /// A moment inside every advert's usability window.
    const NOW: u64 = 1_700_000_000;

    /// The `r` every hello fixture is sealed with.
    const FIXTURE_R: [u8; HELLO_R_LEN] = [0x44u8; HELLO_R_LEN];

    /// The slot [`FIXTURE_R`] picks — the slot a fixture hello is read from.
    fn fixture_slot() -> u16 {
        module();
        slot_for(&FIXTURE_R).expect("pick the slot")
    }

    /// A fill that succeeds, seeded so a run is replayable from the source.
    fn fill_with(byte: u8) -> impl FnMut(&mut [u8]) -> Result<(), ()> {
        let mut counter = byte;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// A fill that fails, for the entropy path.
    fn fill_fails(_: &mut [u8]) -> Result<(), ()> {
        Err(())
    }

    /// The crypto module has to be operational before any SHA or AES call, so
    /// every test that reaches one starts here.
    fn module() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    fn signer(seed: u8) -> SignKeypair {
        module();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).expect("derive a signer")
    }

    /// A recipient's advert key state and one sender's encapsulation to it —
    /// the real path, since `AdvertSharedSecret` is only constructible by
    /// encapsulating or decapsulating.
    fn encapsulation(seed: u8) -> (advert::AdvertKeys, advert::HelloEncapsulation) {
        let signer = signer(seed);
        let keys = advert::AdvertKeys::new(NOW, fill_with(seed)).expect("advert keys");
        let bytes = keys.advert_bytes(&signer).expect("advert bytes");
        let verified = advert::verify(signer.public_key(), &bytes).expect("verify the advert");
        let encap =
            advert::encapsulate_to(&verified, NOW, fill_with(seed ^ 0x5a)).expect("encapsulate");
        (keys, encap)
    }

    fn recipient_pk(seed: u8) -> [u8; ml_dsa::PK_LEN] {
        *signer(seed).public_key()
    }

    /// A sealed hello and everything needed to open it.
    fn sealed_hello() -> (
        advert::AdvertSharedSecret,
        [u8; ml_dsa::PK_LEN],
        Vec<u8>,
        [u8; HELLO_R_LEN],
    ) {
        let (keys, encap) = encapsulation(0x11);
        let pk = recipient_pk(0x11);
        let lookup_key = [0x33u8; HELLO_LOOKUP_KEY_LEN];
        let r = FIXTURE_R;
        let bytes = seal_hello(&encap, &lookup_key, &r, &pk).expect("seal the hello");
        let ss0 = keys
            .decapsulate(encap.serial, &encap.ciphertext)
            .expect("decapsulate")
            .expect("the serial is current");
        (ss0, pk, bytes, r)
    }

    #[test]
    fn a_hello_round_trips() {
        let (ss0, pk, bytes, r) = sealed_hello();
        let opened = open_hello(&ss0, &bytes, &pk, fixture_slot()).expect("open the hello");
        assert_eq!(opened.lookup_key, [0x33u8; HELLO_LOOKUP_KEY_LEN]);
        assert_eq!(opened.r, r);
    }

    /// **Control for every length figure in the module header.** A hello must
    /// fit one slot, and the constant must be what `seal_hello` emits — a
    /// `HELLO_LEN` computed from the wrong pieces would leave `open_hello`
    /// rejecting every real hello as the wrong length.
    #[test]
    fn a_hello_is_one_slot_long_and_measures_hello_len() {
        let (_, _, bytes, _) = sealed_hello();
        assert_eq!(bytes.len(), HELLO_LEN);
        const { assert!(HELLO_LEN <= DROP_SLOT_LEN, "a hello must fit one drop slot") };
    }

    #[test]
    fn a_short_record_fails_on_length() {
        let (ss0, pk, bytes, _) = sealed_hello();
        let err = open_hello(&ss0, &bytes[..HELLO_LEN - 1], &pk, fixture_slot()).unwrap_err();
        assert_eq!(
            err,
            DropError::Length {
                expected: HELLO_LEN,
                actual: HELLO_LEN - 1,
            }
        );
    }

    #[test]
    fn a_flipped_tag_byte_is_a_bad_tag() {
        let (ss0, pk, mut bytes, _) = sealed_hello();
        bytes[POW_TAG_AT] ^= 0x01;
        assert_eq!(
            open_hello(&ss0, &bytes, &pk, fixture_slot()).unwrap_err(),
            DropError::BadTag
        );
    }

    /// A tag minted over a different `r` than the seal carries is rejected,
    /// which is the binding the tag exists for: the tag names the hello it
    /// belongs to, not merely some hello.
    #[test]
    fn a_tag_over_another_r_is_a_bad_tag() {
        let (keys, encap) = encapsulation(0x11);
        let pk = recipient_pk(0x11);
        let r = FIXTURE_R;
        let mut bytes = seal_hello(&encap, &[0x33u8; HELLO_LOOKUP_KEY_LEN], &r, &pk).unwrap();
        let other = pow_tag(&encap.ciphertext, &[0x45u8; HELLO_R_LEN], &pk).unwrap();
        bytes[POW_TAG_AT..].copy_from_slice(&other);
        let ss0 = keys
            .decapsulate(encap.serial, &encap.ciphertext)
            .unwrap()
            .unwrap();
        assert_eq!(
            open_hello(&ss0, &bytes, &pk, fixture_slot()).unwrap_err(),
            DropError::BadTag
        );
    }

    /// **The mirror control for the two tests above:** the unmodified hello
    /// they mutate opens. Without it a `BadTag` on every input — a tag
    /// function that never matches — would read as both tests passing.
    #[test]
    fn the_unmodified_hello_those_tests_mutate_opens() {
        let (ss0, pk, bytes, _) = sealed_hello();
        assert!(open_hello(&ss0, &bytes, &pk, fixture_slot()).is_ok());
    }

    #[test]
    fn a_tampered_ciphertext_fails_the_aead() {
        let (ss0, pk, mut bytes, _) = sealed_hello();
        bytes[SEALED_AT + NONCE_LEN] ^= 0x01;
        assert_eq!(
            open_hello(&ss0, &bytes, &pk, fixture_slot()).unwrap_err(),
            DropError::Aead
        );
    }

    /// A hello written at one identity's drop does not open at another's: the
    /// recipient's identity key is in the associated data.
    #[test]
    fn another_recipient_identity_fails_the_aead() {
        let (ss0, _, bytes, _) = sealed_hello();
        let other = recipient_pk(0x77);
        assert_eq!(
            open_hello(&ss0, &bytes, &other, fixture_slot()).unwrap_err(),
            DropError::Aead
        );
    }

    /// A hello is junk in any slot but its own: `r` picks the slot, so the
    /// bytes and their position are bound to each other and a hello copied
    /// elsewhere in the record does not open where it was pasted.
    #[test]
    fn a_hello_copied_into_another_slot_is_refused() {
        let (ss0, pk, bytes, r) = sealed_hello();
        let slot = slot_for(&r).unwrap();
        // The control: at its own slot the same bytes open.
        assert!(open_hello(&ss0, &bytes, &pk, slot).is_ok());
        assert_eq!(
            open_hello(&ss0, &bytes, &pk, slot + 1).unwrap_err(),
            DropError::SlotMismatch {
                expected: slot,
                found: slot + 1,
            }
        );
    }

    /// FC5, as far as a drop can carry it — **the sender is hidden, the
    /// recipient is not.** The record's address derives from the recipient's
    /// identity key, so a node holding the drop knows whose drop it holds;
    /// § Abuse, *Linkability* states that, and no test changes it. What a
    /// hello must not disclose is who wrote it: the sender's identity is not
    /// an input to a hello's construction at all, and this is the tripwire
    /// against it becoming one.
    #[test]
    fn the_sender_identity_appears_in_no_byte_of_a_hello() {
        let (_, _, bytes, _) = sealed_hello();
        let sender = recipient_pk(0x77);
        // A whole-key search over a hello could not match whatever the record
        // held, since a hello is shorter than an identity key — so the prefix
        // is the search with teeth here, and the whole key is searched in the
        // control below, on a buffer long enough to hold one.
        const { assert!(HELLO_LEN < ml_dsa::PK_LEN) };
        assert!(
            !bytes.windows(32).any(|w| w == &sender[..32]),
            "the first 32 bytes of a sender identity key appear in a sealed hello"
        );
    }

    /// The control for the search above: it finds a key that IS present.
    #[test]
    fn the_identity_key_search_finds_a_key_that_is_there() {
        let pk = recipient_pk(0x11);
        let mut haystack = vec![0u8; 64];
        haystack.extend_from_slice(&pk);
        assert!(haystack.windows(pk.len()).any(|w| w == pk.as_slice()));
        assert!(haystack.windows(32).any(|w| w == &pk[..32]));
    }

    /// Seeded draws the addressability check takes. The draws are
    /// deterministic, so the coverage below either holds at this number or
    /// does not.
    const ADDRESSABILITY_DRAWS: u16 = 2048;

    /// Every slot of the record is reachable, and each is the digest's last
    /// byte.
    ///
    /// Reachability is the property, and `slot < DROP_SUBKEYS` does not test
    /// it: the slot is a `u16` built from one byte, so that comparison holds
    /// for any implementation at all. Reaching all [`DROP_SUBKEYS`] slots does
    /// not.
    #[test]
    fn every_slot_is_reachable_and_is_the_last_digest_byte() {
        module();
        let mut reached = std::collections::BTreeSet::new();
        for i in 0..ADDRESSABILITY_DRAWS {
            let mut r = [0u8; HELLO_R_LEN];
            r[..2].copy_from_slice(&i.to_le_bytes());
            let slot = slot_for(&r).unwrap();
            let mut input = Vec::new();
            input.extend_from_slice(domain::DM_DROP_SLOT);
            push_lp(&mut input, &r);
            assert_eq!(slot, u16::from(sha384(&input).unwrap()[47]));
            reached.insert(slot);
        }
        assert_eq!(
            reached.len(),
            usize::from(DROP_SUBKEYS),
            "{ADDRESSABILITY_DRAWS} draws reached {} slots",
            reached.len()
        );
    }

    /// 256 draws over 256 slots reach many of them. A derivation collapsed to
    /// a handful of slots — a stray `% 4`, a digest byte that is always zero —
    /// passes every range assertion and fails this.
    #[test]
    fn slots_spread_across_the_record() {
        module();
        let slots: std::collections::BTreeSet<u16> = (0u8..=255)
            .map(|seed| slot_for(&[seed; HELLO_R_LEN]).unwrap())
            .collect();
        assert!(
            slots.len() >= 64,
            "256 values of r reached only {} distinct slots",
            slots.len()
        );
    }

    /// The uniformity argument in [`slot_for`]'s docs holds only where the
    /// digest's last byte addresses every slot and no more. This trips on any
    /// change to `DROP_SUBKEYS`: a count that is not a power of two, or is one
    /// but is no longer 256, biases the derivation toward the low slots or
    /// leaves slots unreachable.
    #[test]
    fn the_slot_count_is_pinned_at_256_so_the_last_byte_is_unbiased() {
        assert!(DROP_SUBKEYS.is_power_of_two());
        assert_eq!(
            DROP_SUBKEYS, 256,
            "the slot derivation reads one byte, which addresses exactly 256 slots"
        );
    }

    /// **Known-answer vectors, computed outside this crate from the preimages
    /// the functions above document.** A structural test cannot see a change
    /// that is uniformly wrong — a dropped length prefix, an edited label, a
    /// bare hash of `r` — because minting and checking would then agree with
    /// each other while agreeing with nobody else.
    #[test]
    fn known_answer_slot_and_tag() {
        module();
        let r = [0x44u8; HELLO_R_LEN];
        let ct = [0x22u8; ml_kem::CT_LEN];
        let pk = [0x66u8; ml_dsa::PK_LEN];
        assert_eq!(hex::encode(pow_tag(&ct, &r, &pk).unwrap()), KAT_TAG);
        assert_eq!(slot_for(&r).unwrap(), KAT_SLOT);
        assert_eq!(
            hex::encode(derive_owner_seed(&pk).unwrap().as_bytes()),
            KAT_OWNER_SEED
        );
    }

    /// The tag `known_answer_slot_and_tag` pins. Computed outside this crate
    /// from the preimage `pow_input` documents, so it is an independent
    /// oracle rather than a recording of whatever this code currently emits.
    const KAT_TAG: &str = "4ca164eb405242e2";

    /// The slot `known_answer_slot_and_tag` pins, computed the same way.
    const KAT_SLOT: u16 = 105;

    /// The owner seed of the drop of an identity whose public key is 2592
    /// bytes of `0x66`: `HKDF-SHA-384(salt = DM_DROP_SALT, ikm = that key,
    /// info = DM_DROP_OWNER)`, 32 bytes.
    ///
    /// A synthetic public key rather than a real one, because an ML-DSA-87
    /// public key cannot be computed outside this crate and the vector has to
    /// come from an independent oracle. What it pins is the wiring — salt,
    /// ikm, info and output length — against a relabel, which moves every
    /// drop address and is invisible to every other test here.
    const KAT_OWNER_SEED: &str = "145b776cb01cbc8966eebdc9f8b56ca8e9218f9a4aa59030538532d9d2a16366";

    #[test]
    fn a_matching_read_back_landed_and_anything_else_clobbered() {
        let written = b"the bytes written".as_slice();
        assert_eq!(after_read_back(written, Some(written)), ReadBack::Landed);
        assert_eq!(
            after_read_back(written, Some(b"something else")),
            ReadBack::Clobbered
        );
        assert_eq!(after_read_back(written, None), ReadBack::Clobbered);
    }

    /// One clobbered read-back costs exactly one re-pick, and the attempt
    /// moves: a re-pick that left `r` where it was would rewrite into the
    /// slot that was just taken, for ever.
    #[test]
    fn one_clobber_is_one_repick_and_the_attempt_moves() {
        module();
        let mut attempt = HelloAttempt::new([0x44u8; HELLO_R_LEN]).unwrap();
        let before_r = *attempt.r();
        let before_slot = attempt.slot();
        assert_eq!(attempt.repicks(), 0);

        let outcome = attempt
            .read_back(b"written", Some(b"somebody else's"), fill_with(0x90))
            .unwrap();
        assert_eq!(outcome, ReadBack::Clobbered);
        assert_eq!(attempt.repicks(), 1);
        assert_ne!(*attempt.r(), before_r);
        assert!(
            attempt.slot() != before_slot || *attempt.r() != before_r,
            "the attempt did not move"
        );

        // The control: a landed read-back re-picks nothing.
        let r_after = *attempt.r();
        let outcome = attempt
            .read_back(b"written", Some(b"written"), fill_with(0x91))
            .unwrap();
        assert_eq!(outcome, ReadBack::Landed);
        assert_eq!(attempt.repicks(), 1);
        assert_eq!(*attempt.r(), r_after);
    }

    #[test]
    fn a_failed_draw_is_an_entropy_error() {
        module();
        assert_eq!(repick(fill_fails).unwrap_err(), DropError::Entropy);
    }

    /// Two identities have two drops, and one identity's drop is one address
    /// however often it is derived.
    #[test]
    fn the_owner_seed_is_deterministic_and_identity_scoped() {
        let a = recipient_pk(0x11);
        let b = recipient_pk(0x77);
        let seed_a = derive_owner_seed(&a).unwrap();
        assert_eq!(seed_a.as_bytes(), derive_owner_seed(&a).unwrap().as_bytes());
        assert_ne!(seed_a.as_bytes(), derive_owner_seed(&b).unwrap().as_bytes());
        // The control: the drop's address is not the advert's, though both
        // derive from the same public key.
        assert_ne!(
            seed_a.as_bytes().as_slice(),
            advert::derive_owner_seed(&a).unwrap().as_bytes().as_slice()
        );
    }
}
