//! The DM **acknowledgement record** — where a direction's settled state is
//! published (ISC-C39 / ISC-A-C21).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § v3 "Ack: per-party record `ack_addr(dir)`", § v3 crypto F-3/F-6.
//!
//! [`ack`] is the pure half — the key, the preimage, and the
//! state machine that decides what "settled up to here" means. This module is the
//! record that state travels in: the address it is published at, the seal around
//! it, and the signature over it. It still publishes nothing itself; the jittered
//! standalone cadence and the piggyback path are separate again, and the
//! client-global allowance governing how often a standalone acknowledgement may
//! be written at all is [`ack_budget`](crate::dm::ack_budget).
//!
//! ## One record per direction, and no page number
//!
//! An acknowledgement is a *current-state* value, not a log: each write
//! supersedes the last, and a reader unions whatever it finds into what it holds.
//! There is nothing to page. So the address binds the conversation and the
//! direction and stops — `dflt(1)`, one slot, rewritten for the life of the
//! conversation. That is the whole difference from
//! [`paging`](crate::dm::paging), which binds a page number for the same reason
//! this does not: a channel page is written once and never rewritten, so it needs
//! a fresh address per page.
//!
//! **Per-direction (F-6) rather than one record for both halves.** The two
//! parties write independently; a single record would put two writers on one
//! slot, so each would erase the other's statement on every write, and the seal
//! key covering both halves would be one key whose compromise covers both.
//!
//! ## The address is a conversation secret, unlike the key record's
//!
//! The owner seed derives from `AR` — the retained address root — so only the two
//! parties can compute it. Under Veilid a derivable owner seed **is** write
//! access, so the record is owner-write-gated: no third party can forge an
//! acknowledgement or erase one, which is the property the key record and the
//! doorbell deliberately do not have. What that leaves is the peer itself, and a
//! peer's statement is bounded on arrival by
//! [`AckState::merge_peer_ack`](crate::dm::ack::AckState::merge_peer_ack) rather
//! than by the address.
//!
//! It descends from the same secret as the seal key and under its own salt
//! ([`domain::DM_ACK_ADDR_SALT`] against [`domain::DM_ACK_SALT`]). Sharing one
//! extraction would mean a party that learned the address was one HKDF-Expand
//! from the key its contents are sealed under.
//!
//! ## Everything is inside the seal
//!
//! A reader derives `K_ack(dir)` from `AR` and the direction, both of which it
//! holds before it fetches anything, so there is no header it needs in the clear
//! to reach the key — and the whole content of an acknowledgement is collection
//! metadata, which is exactly what a page co-host must not read. So the record is
//! an AEAD envelope and nothing else, unlike
//! [`frame`](crate::dm::frame), whose ratchet header must be legible before its
//! key can be derived.
//!
//! The signature goes inside the seal for the same reason it does on a channel
//! frame: it is authorship, and authorship in the clear is a provenance marker on
//! an otherwise opaque record.
//!
//! ## Constant size
//!
//! [`MAX_ACK_RUNS`](crate::dm::ack::MAX_ACK_RUNS) fixes the encoded run set at no
//! more than 1026 bytes, so an acknowledgement has a bounded maximum — and a
//! variable length would publish the one thing the seal exists to hide, since the
//! encoded length tracks the number of *gaps* a conversation has accumulated. The
//! plaintext therefore pads to the single bucket [`ACK_PAD_BUCKETS`] before
//! sealing, so every acknowledgement this client ever writes is the same number of
//! bytes and the length says nothing.
//!
//! ## Decode, verify, then merge — the record does not change the order
//!
//! [`decode_and_verify`] returns a [`PeerAck`], never an
//! [`AckState`], which is [`ack`]'s rule and not a fresh one: a verifier rebuilds the
//! signature preimage from the decoded statement, so nothing may alter it before
//! the signature is checked, and the ceiling that bounds it is a required argument
//! on `merge_peer_ack`. There is deliberately no function here that reads
//! settlement off an unmerged decode.

use oxicrypt_aes::Aes256Key;
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use prost::Message as _;
use zeroize::Zeroize;

use daemonseed_proto::v1 as wire;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::dm::ack::{self, AckError, AckState, PeerAck};
use crate::dm::domain;
use crate::dm::firstcontact::ROOT_LEN;
use crate::dm::paging::ADDRESS_ROOT_LEN;
use crate::dm::push_lp;
use crate::dm::ratchet::Direction;
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Slots in an acknowledgement record — the `o_cnt` of its `dflt(o_cnt)` schema,
/// and part of the record's address.
///
/// One: the record holds a single current-state value and nothing else. A writer
/// MUST build its `RecordShape` from this constant rather than a literal
/// (ISC-C100) — `o_cnt` is part of the deterministic address, so a shape that
/// disagreed with it would address a record the other party never reads, silently
/// and with no error on any surface.
pub const ACK_RECORD_SLOTS: u16 = 1;

/// Byte length of the Veilid owner seed this module derives.
pub const DM_ACK_OWNER_SEED_LEN: usize = 32;

/// The one padding bucket every acknowledgement is padded to before sealing.
///
/// A single rung, not a ladder, and that is the point: a ladder would still leak
/// a size class, and here a size class is a count of accumulated gaps. The value
/// clears the largest body the module can produce — an absent-or-present `u64`
/// prefix, a 1026-byte run set at [`ack::MAX_ACK_RUNS`], and a 4627-byte ML-DSA-87
/// signature, plus protobuf and length-prefix overhead — with margin, and
/// `the_pad_bucket_holds_a_maximal_body` pins that it does.
///
/// Shared with the other DM frame kinds through the crate-private
/// `dm::pad_to_bucket`, so the padding scheme cannot drift into two
/// incompatible spellings.
pub const ACK_PAD_BUCKETS: &[usize] = &[6144];

/// The sealed size of every acknowledgement record's `sealed` field: the one
/// padding bucket plus the envelope's nonce and tag.
///
/// A constant because the padding makes it one, and stated so a reader can see
/// that the record's length carries no signal.
pub const ACK_SEALED_LEN: usize = ACK_PAD_BUCKETS[0] + 12 + 16;

redacted_secret_newtype! {
    /// The Veilid record-owner seed for one direction's acknowledgement record.
    ///
    /// **Genuinely secret**, like [`crate::dm::paging::DmPageOwnerSeed`] and
    /// unlike the world-derivable key-record and doorbell seeds: it descends from
    /// `AR`, which descends from the first-contact encapsulation, so holding it
    /// means being one of the two parties. Under Veilid a derivable owner seed is
    /// write access, which is what makes the record owner-write-gated.
    boxed pub struct DmAckOwnerSeed([u8; DM_ACK_OWNER_SEED_LEN]);
}

/// Anything that can go wrong addressing, building, or reading an acknowledgement
/// record.
///
/// The statement's own faults are not restated here: they arrive as
/// [`Self::Ack`], carrying the [`AckError`] [`ack`] produced, so
/// there is one home for what a malformed run set means.
///
/// `PartialEq` is implemented by hand rather than derived, exactly as
/// [`crate::dm::keyrec::DmKeyRecordError`]'s is: [`SignatureError`] and the two
/// oxicrypt error types are not comparable, and two values of those variants
/// compare equal on the variant alone — which is all any caller needs, since the
/// wrapped cause is for humans and logs, not for control flow.
#[derive(Debug)]
pub enum AckRecordError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// The AES key could not be initialised from the ack seal key — a
    /// crypto-module condition, never an adversary.
    Module(oxicrypt_module::Error),
    /// A local signing operation failed while BUILDING a record. Carries the
    /// cause: there is no adversary on this path, and a FIPS-mode policy refusal
    /// reported as "signature did not verify" would send a reader hunting for
    /// tampering that never happened.
    Signing(SignatureError),
    /// The AEAD seal failed while composing — a local crypto-module condition,
    /// kept distinct from [`Self::Aead`] for the reason
    /// [`crate::dm::frame::DmFrameError::Sealing`] gives.
    Sealing(oxicrypt_aes::ModeError),
    /// The OS entropy source failed while drawing a nonce.
    EntropySource,
    /// The AEAD open failed. The uniform authentication failure — wrong key, wrong
    /// direction, wrong conversation, a tampered ciphertext or a truncated
    /// envelope are indistinguishable, deliberately (ISC-A-C18).
    Aead,
    /// The bytes are not a decodable record, or the plaintext under the seal is
    /// not a decodable body. The record is owner-write-gated, so this means the
    /// peer wrote something malformed rather than a stranger writing anything —
    /// still rejected here rather than surfacing later as a wrong statement.
    Malformed,
    /// A length-gated field was absent or the wrong size, so a truncation is
    /// diagnosable rather than surfacing as a signature failure.
    FieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The signature did not verify against the correspondent's pseudonym key.
    /// Uniform for the same anti-oracle reason as its siblings (ISC-A-C18).
    Signature,
    /// The statement itself is not well-formed — see the carried [`AckError`].
    Ack(AckError),
    /// The encoded body does not fit [`ACK_PAD_BUCKETS`].
    ///
    /// Unreachable from a well-formed [`AckState`], whose run count is capped at
    /// [`ack::MAX_ACK_RUNS`] — the bucket is sized against exactly that maximum.
    /// It is a returned error rather than a `debug_assert!` because the size that
    /// would trip it is a function of the signature length and the cap, and a
    /// future change to either should fail loudly at the write rather than
    /// silently in a release build.
    TooLarge { got: usize, max: usize },
}

impl PartialEq for AckRecordError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Kdf(a), Self::Kdf(b)) => a == b,
            // Compared on the variant: the wrapped causes are diagnostic and are
            // not themselves comparable.
            (Self::Module(_), Self::Module(_)) => true,
            (Self::Signing(_), Self::Signing(_)) => true,
            (Self::Sealing(_), Self::Sealing(_)) => true,
            (Self::EntropySource, Self::EntropySource) => true,
            (Self::Aead, Self::Aead) => true,
            (Self::Malformed, Self::Malformed) => true,
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
            (Self::Signature, Self::Signature) => true,
            (Self::Ack(a), Self::Ack(b)) => a == b,
            (Self::TooLarge { got: ga, max: ma }, Self::TooLarge { got: gb, max: mb }) => {
                ga == gb && ma == mb
            }
            _ => false,
        }
    }
}

impl Eq for AckRecordError {}

impl std::fmt::Display for AckRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "ack-record key derivation failed: {e}"),
            Self::Module(e) => write!(f, "crypto module unavailable: {e:?}"),
            Self::Signing(e) => write!(f, "could not sign the acknowledgement: {e:?}"),
            Self::Sealing(e) => write!(f, "could not seal the acknowledgement: {e:?}"),
            Self::EntropySource => write!(f, "the entropy source failed"),
            Self::Aead => write!(f, "the acknowledgement did not open"),
            Self::Malformed => write!(f, "not a decodable acknowledgement record"),
            Self::FieldLength {
                field,
                expected,
                actual,
            } => write!(f, "{field} must be {expected} bytes, got {actual}"),
            Self::Signature => write!(f, "acknowledgement signature did not verify"),
            Self::Ack(e) => write!(f, "the acknowledgement statement is malformed: {e}"),
            Self::TooLarge { got, max } => {
                write!(f, "acknowledgement body is {got} bytes, bucket is {max}")
            }
        }
    }
}

impl std::error::Error for AckRecordError {}

/// Open-path mapping only: every non-entropy envelope failure collapses to the
/// uniform authentication error, matching
/// [`crate::dm::frame`]'s split. The seal path maps its own errors explicitly, so
/// a local encrypt fault is never reported as "did not open".
impl From<EnvelopeError> for AckRecordError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_) => Self::EntropySource,
            _ => Self::Aead,
        }
    }
}

/// Derive the Veilid owner seed for one direction's acknowledgement record:
/// `HKDF-SHA-384(salt = DM_ACK_ADDR_SALT, ikm = AR, info = DM_ACK_ADDR ‖ lp(dir))`.
///
/// Deterministic and pure — no clock, no randomness, no network — so both parties
/// reach the same record from the same conversation whatever generation their
/// ratchets are at, and a party returning after a month recomputes an address it
/// never stored. That independence from the ratchet is the same property
/// [`ack::derive_seal_key`] rests on (crypto F-3), and for the same reason: `AR`
/// is stable for the life of the conversation.
///
/// **There is no page argument.** An acknowledgement is current state, rewritten
/// in place, so one direction has exactly one record — see the module docs.
///
/// `direction` is the direction of the **messages being acknowledged**, not of the
/// acknowledgement itself, matching [`ack::derive_seal_key`]. The party collecting
/// `a2b` writes the `a2b` record. Take the value from
/// [`Ratchet::recv_direction`](crate::dm::ratchet::Ratchet::recv_direction) when
/// publishing an acknowledgement and from
/// [`send_direction`](crate::dm::ratchet::Ratchet::send_direction) when fetching
/// the peer's, rather than mapping a role by hand: the two readings differ by one
/// label, and choosing the other one addresses a record the peer never writes,
/// with no error to say why.
pub fn derive_owner_seed(
    address_root: &[u8; ADDRESS_ROOT_LEN],
    direction: Direction,
) -> Result<DmAckOwnerSeed, AckRecordError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_ACK_ADDR_SALT), address_root)
        .map_err(AckRecordError::Kdf)?;

    let dir = direction.label();
    let mut info = Vec::with_capacity(domain::DM_ACK_ADDR.len() + dir.len() + 8);
    info.extend_from_slice(domain::DM_ACK_ADDR);
    push_lp(&mut info, dir);

    let seed =
        derive_boxed_seed::<DM_ACK_OWNER_SEED_LEN>(&hkdf, &info).map_err(AckRecordError::Kdf)?;
    Ok(DmAckOwnerSeed(seed))
}

/// Where one direction's acknowledgement record lives: the owner seed and the
/// direction it was derived for, together.
///
/// A seed on its own says nothing about which half of the conversation it
/// addresses, and the two halves are the same type at the same length — so a
/// publish handed the wrong one writes a perfectly valid record that the peer
/// never reads. Keeping the direction beside the seed means the value a transport
/// is handed carries the answer with it.
///
/// **Deliberately plain, with no phantom-typed stream marker.**
/// [`crate::dm::paging::DmPageAddress`] earns that machinery from paging: a page
/// address must also carry a page and, when sending, a slot, and it must refuse a
/// receiving address to a publish because sweeping one's own stream reads one's
/// own writes back forever. None of that exists here — there is one record per
/// direction, both parties write theirs and read the other's, and the direction is
/// a value the caller takes from the ratchet's own accessor. A type parameter
/// would buy nothing and cost a second way to spell an address.
#[derive(Debug)]
pub struct DmAckAddress {
    owner_seed: DmAckOwnerSeed,
    direction: Direction,
}

impl DmAckAddress {
    /// Derive the address of the record acknowledging `direction`'s messages.
    pub fn for_direction(
        address_root: &[u8; ADDRESS_ROOT_LEN],
        direction: Direction,
    ) -> Result<Self, AckRecordError> {
        Ok(Self {
            owner_seed: derive_owner_seed(address_root, direction)?,
            direction,
        })
    }

    /// The record's Veilid owner seed.
    ///
    /// It is the conversation's write capability for this record, so a caller that
    /// copies the bytes out takes on the hygiene the newtype was providing.
    pub fn owner_seed(&self) -> &DmAckOwnerSeed {
        &self.owner_seed
    }

    /// The direction of the messages this record acknowledges.
    pub fn direction(&self) -> Direction {
        self.direction
    }
}

/// The AAD binding a sealed acknowledgement to one conversation and one
/// direction.
///
/// The same two fields [`ack::ack_sig_input`] binds first, so a record moved onto
/// the other direction's address — or another conversation's — fails to open
/// before any signature is examined. It is not redundant with the key: the key
/// already separates both, and this makes the separation fail *at the AEAD*,
/// which is the layer a reader reaches first and the layer that costs an attacker
/// nothing to probe.
fn seal_aad(chan_id: &[u8; ROOT_LEN], direction: Direction) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain::DM_ACK_AAD.len() + ROOT_LEN + 32);
    aad.extend_from_slice(domain::DM_ACK_AAD);
    push_lp(&mut aad, chan_id);
    push_lp(&mut aad, direction.label());
    aad
}

/// The AES-256-GCM key one direction's acknowledgements are sealed under.
fn aes_key(
    address_root: &[u8; ADDRESS_ROOT_LEN],
    direction: Direction,
) -> Result<Aes256Key, AckRecordError> {
    let key = ack::derive_seal_key(address_root, direction).map_err(ack_kdf)?;
    Aes256Key::new(key.as_bytes()).map_err(AckRecordError::Module)
}

/// An ack-module failure on a LOCAL derivation is a crypto-module condition, not
/// a malformed statement — reporting it as the latter would send a reader hunting
/// for a peer bug that does not exist.
fn ack_kdf(e: AckError) -> AckRecordError {
    match e {
        AckError::Kdf(k) => AckRecordError::Kdf(k),
        other => AckRecordError::Ack(other),
    }
}

fn exact<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], AckRecordError> {
    bytes.try_into().map_err(|_| AckRecordError::FieldLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

/// Sign, seal, and assemble one direction's acknowledgement for publication.
///
/// `state` is what THIS party has settled on `direction`; `chan_id` and
/// `address_root` are the conversation's, and `signing_pc` is this party's
/// per-contact pseudonym keypair — the same key that signs every message of the
/// conversation, never the long-term identity key.
///
/// `chan_id` is bound in the signature preimage and in the AAD and appears on the
/// wire in neither, which is [`ack`]'s rule: a receiver
/// recomputes it from the record it derived, and serializing it would collapse the
/// address scatter the channel rests on.
pub fn build(
    state: &AckState,
    chan_id: &[u8; ROOT_LEN],
    direction: Direction,
    address_root: &[u8; ADDRESS_ROOT_LEN],
    signing_pc: &SignKeypair,
) -> Result<wire::DmAck, AckRecordError> {
    let preimage = ack::ack_sig_input(chan_id, direction, state);
    let msg_sig = signing_pc
        .sign(&preimage)
        .map_err(AckRecordError::Signing)?;

    let body = wire::DmAckBody {
        high_water: state.high_water(),
        beyond: state.encode_beyond(),
        msg_sig: msg_sig.to_vec(),
    };

    let mut encoded = body.encode_to_vec();
    let padded = crate::dm::pad_to_bucket(&encoded, ACK_PAD_BUCKETS);
    // The error needs the length, so it is taken BEFORE the zeroize that would
    // truncate nothing but is easy to reorder into reporting zero.
    let needed = crate::dm::LEN_PREFIX.saturating_add(encoded.len());
    encoded.zeroize();
    let mut padded = padded.ok_or(AckRecordError::TooLarge {
        got: needed,
        max: *ACK_PAD_BUCKETS.last().expect("the ladder is never empty"),
    })?;

    let sealed = seal_envelope(
        &aes_key(address_root, direction)?,
        &seal_aad(chan_id, direction),
        &padded,
    );
    padded.zeroize();
    // Mapped explicitly rather than through the blanket `From`: on this path there
    // is no adversary, so an encrypt fault is a module condition, not tampering.
    let sealed = sealed.map_err(|e| match e {
        EnvelopeError::EntropySource(_) => AckRecordError::EntropySource,
        EnvelopeError::Encrypt(m) | EnvelopeError::Decrypt(m) => AckRecordError::Sealing(m),
        EnvelopeError::TooShort => AckRecordError::Sealing(oxicrypt_aes::ModeError::TagMismatch),
    })?;

    Ok(wire::DmAck { sealed })
}

/// Sign, seal, assemble, and **encode** an acknowledgement ready for publication.
///
/// The wire-encoding wrapper over [`build`], for the reason
/// [`crate::dm::keyrec::build_encoded`] gives: a frontend publishes opaque bytes
/// and should not have to know — or take a protobuf dependency to express — how a
/// record is serialised. `daemonseed-tui` has no `prost` dependency at all.
pub fn build_encoded(
    state: &AckState,
    chan_id: &[u8; ROOT_LEN],
    direction: Direction,
    address_root: &[u8; ADDRESS_ROOT_LEN],
    signing_pc: &SignKeypair,
) -> Result<Vec<u8>, AckRecordError> {
    Ok(build(state, chan_id, direction, address_root, signing_pc)?.encode_to_vec())
}

/// Decode a fetched acknowledgement record, open it, and verify its signature —
/// the read counterpart of [`build_encoded`], so a caller handling raw DHT bytes
/// never needs prost either.
///
/// `peer_pk_pc` is the correspondent's per-contact pseudonym public key, held in
/// the contact cache since first contact. `direction` is the direction of the
/// messages being acknowledged, and must be the one the record was fetched from —
/// it is bound in the key, the AAD and the preimage, so naming the other one
/// fails at the AEAD rather than yielding a wrong answer.
///
/// **The result is a [`PeerAck`], and that is the whole discipline.** It answers
/// no question about settlement; the only thing that can be done with it is
/// [`AckState::merge_peer_ack`], where the ceiling — the highest sequence number
/// this party has actually sent on `direction` — is a required argument. The
/// sequence is decode → verify → merge, and this function is the first two steps.
pub fn decode_and_verify(
    encoded: &[u8],
    chan_id: &[u8; ROOT_LEN],
    direction: Direction,
    address_root: &[u8; ADDRESS_ROOT_LEN],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
) -> Result<PeerAck, AckRecordError> {
    let record = wire::DmAck::decode(encoded).map_err(|_| AckRecordError::Malformed)?;
    verify(&record, chan_id, direction, address_root, peer_pk_pc)
}

/// Open and verify an already-decoded acknowledgement record.
///
/// Fails closed at every step, in order: the seal must open under the key and AAD
/// this conversation and direction derive, the plaintext must unpad and decode,
/// `msg_sig` must be exactly [`ml_dsa::SIG_LEN`] bytes, the statement must be
/// canonical, and only then is the signature checked against `peer_pk_pc`.
pub fn verify(
    record: &wire::DmAck,
    chan_id: &[u8; ROOT_LEN],
    direction: Direction,
    address_root: &[u8; ADDRESS_ROOT_LEN],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
) -> Result<PeerAck, AckRecordError> {
    let mut padded = open_envelope(
        &aes_key(address_root, direction)?,
        &seal_aad(chan_id, direction),
        &record.sealed,
    )?;
    let decoded = crate::dm::unpad(&padded)
        .ok_or(AckRecordError::Malformed)
        .and_then(|body| wire::DmAckBody::decode(body).map_err(|_| AckRecordError::Malformed));
    padded.zeroize();
    let body = decoded?;

    let msg_sig: [u8; ml_dsa::SIG_LEN] = exact("msg_sig", &body.msg_sig)?;

    // Decoded, not validated: `high_water` and every run are the peer's own
    // claim, bounded by nothing we know until `merge_peer_ack` applies the
    // ceiling. The signature is checked over the statement AS DECODED, because a
    // step that altered it would rebuild a preimage the peer's signature cannot
    // match.
    let peer =
        AckState::decode_unvalidated(body.high_water, &body.beyond).map_err(AckRecordError::Ack)?;

    let preimage = peer.sig_input(chan_id, direction);
    verify_signature(peer_pk_pc, &preimage, &msg_sig).map_err(|_| AckRecordError::Signature)?;
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::ack::MAX_ACK_RUNS;
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";
    const PHRASE_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                            zoo zoo zoo zoo zoo zoo zoo vote";

    fn keys(phrase: &str) -> IdentityKeys {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(&Mnemonic::from_phrase(phrase).unwrap(), Identity::Primary).unwrap()
    }

    fn alice() -> IdentityKeys {
        keys(PHRASE_A)
    }

    fn bob() -> IdentityKeys {
        keys(PHRASE_B)
    }

    /// A byte-distinct address root: a run of equal bytes would pass under a
    /// derivation that mis-sliced its input, and this does not.
    fn ar(tag: u8) -> [u8; ADDRESS_ROOT_LEN] {
        let mut out = [0u8; ADDRESS_ROOT_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = tag ^ (i as u8).wrapping_mul(11).wrapping_add(0x3d);
        }
        out
    }

    fn chan(tag: u8) -> [u8; ROOT_LEN] {
        let mut out = [0u8; ROOT_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = tag ^ (i as u8).wrapping_mul(7).wrapping_add(0x91);
        }
        out
    }

    /// Settle a list of positions, expecting every one to be accepted.
    fn settled(seqs: &[u64]) -> AckState {
        let mut state = AckState::new();
        for &seq in seqs {
            state.collect(seq).expect("within the cap");
        }
        state
    }

    /// A state holding the maximum number of runs the cap allows — alternating
    /// loss, so run *n* sits at `2n + 1`.
    fn maximal_state() -> AckState {
        let mut state = AckState::new();
        state.collect(0).unwrap();
        for n in 0..MAX_ACK_RUNS as u64 {
            state.collect(2 * n + 2).unwrap();
        }
        assert_eq!(state.runs(), MAX_ACK_RUNS, "fixture must be at the cap");
        state
    }

    fn seed(tag: u8, dir: Direction) -> String {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        hex::encode(derive_owner_seed(&ar(tag), dir).unwrap().as_bytes())
    }

    // ---- the address -------------------------------------------------------
    //
    // Known-answer vectors, captured from this implementation, exactly as in
    // `paging`, `doorbell` and `ack`. They guard against DRIFT: a uniform change
    // to the label, the salt, or the length-prefixing would keep every structural
    // test below green while moving every address — two clients that never see
    // each other's acknowledgements, on a conversation that otherwise looks
    // healthy. They cannot say the derivation was right to begin with; the design
    // doc and review do that.

    #[test]
    fn ack_record_owner_seeds_are_pinned() {
        assert_eq!(
            seed(0x41, Direction::AToB),
            "9d4ab26c62942812bd9d2933f8dbd72daf5dc84eb368deeb7c63114ef10d1d98"
        );
        assert_eq!(
            seed(0x41, Direction::BToA),
            "8dd3c2c647155670e51e33837c7b82d0919204c89544634fa51166e624fabd42"
        );
    }

    /// Per-direction (F-6): one record for both halves would put two writers on
    /// one slot, each erasing the other's statement.
    #[test]
    fn the_two_directions_address_different_records() {
        assert_ne!(seed(0x41, Direction::AToB), seed(0x41, Direction::BToA));
    }

    /// Two conversations must never share an acknowledgement record.
    #[test]
    fn distinct_conversations_address_distinct_records() {
        assert_ne!(seed(0x41, Direction::AToB), seed(0x42, Direction::AToB));
    }

    /// The address root and the SEAL KEY derive from the same secret and must not
    /// collide: only the salt and the info label separate them, so this is the
    /// test that catches a label edit publishing the key as the address.
    #[test]
    fn the_address_is_not_the_seal_key() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let addr = derive_owner_seed(&ar(0x41), Direction::AToB).unwrap();
        let key = ack::derive_seal_key(&ar(0x41), Direction::AToB).unwrap();
        assert_ne!(addr.as_bytes(), key.as_bytes());
    }

    /// The acknowledgement and the channel page derive from the SAME `AR` under
    /// the same kind of info construction, and must still land on different
    /// records. Page 0 is the collision candidate, since it is where a
    /// conversation starts.
    #[test]
    fn the_ack_record_does_not_collide_with_a_channel_page() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let ack_addr = derive_owner_seed(&ar(0x41), Direction::AToB).unwrap();
        for page in [0u64, 1, 3] {
            let page_addr =
                crate::dm::paging::derive_owner_seed(&ar(0x41), Direction::AToB, page).unwrap();
            assert_ne!(
                ack_addr.as_bytes(),
                page_addr.as_bytes(),
                "the ack record collides with page {page}"
            );
        }
    }

    /// The owner seed is a conversation secret, so it must not render its bytes.
    #[test]
    fn the_owner_seed_does_not_render_its_bytes() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let s = derive_owner_seed(&ar(0x41), Direction::AToB).unwrap();
        assert_eq!(format!("{s:?}"), "DmAckOwnerSeed(<redacted>)");
    }

    /// The address type must carry the direction it was derived for, or the seed
    /// it holds says nothing about which half it addresses.
    #[test]
    fn the_address_carries_its_direction_and_its_seed() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let addr = DmAckAddress::for_direction(&ar(0x41), Direction::BToA).unwrap();
        assert_eq!(addr.direction(), Direction::BToA);
        assert_eq!(
            addr.owner_seed().as_bytes(),
            derive_owner_seed(&ar(0x41), Direction::BToA)
                .unwrap()
                .as_bytes()
        );
    }

    // ---- the record --------------------------------------------------------

    #[test]
    fn build_encoded_and_decode_and_verify_round_trip() {
        let a = alice();
        let state = settled(&[0, 1, 2, 5, 9]);
        let bytes =
            build_encoded(&state, &chan(0x51), Direction::AToB, &ar(0x41), &a.signing).unwrap();
        let peer = decode_and_verify(
            &bytes,
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            a.signing.public_key(),
        )
        .unwrap();

        // A `PeerAck` answers nothing on its own; merging under a ceiling that
        // clips nothing is the only way to read what it carried.
        let mut ours = AckState::new();
        let _ = ours.merge_peer_ack(peer, Some(u64::MAX)).unwrap();
        assert_eq!(ours.high_water(), Some(2));
        assert!(ours.is_settled(5));
        assert!(ours.is_settled(9));
        assert!(!ours.is_settled(4));
    }

    /// The core anti-forgery property: an acknowledgement signed by one identity
    /// must not verify as another's, because the reader feeds the correspondent's
    /// own pseudonym key into the preimage.
    #[test]
    fn a_record_does_not_verify_against_another_identity() {
        let a = alice();
        let b = bob();
        let bytes = build_encoded(
            &settled(&[0, 1]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            &a.signing,
        )
        .unwrap();
        assert_eq!(
            decode_and_verify(
                &bytes,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                b.signing.public_key(),
            )
            .unwrap_err(),
            AckRecordError::Signature
        );
    }

    /// The direction is bound in the key and in the AAD, so an acknowledgement
    /// replayed onto the other half's record fails at the AEAD — before any
    /// signature is examined.
    #[test]
    fn a_record_does_not_open_on_the_other_direction() {
        let a = alice();
        let bytes = build_encoded(
            &settled(&[0, 1]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            &a.signing,
        )
        .unwrap();
        assert_eq!(
            decode_and_verify(
                &bytes,
                &chan(0x51),
                Direction::BToA,
                &ar(0x41),
                a.signing.public_key(),
            )
            .unwrap_err(),
            AckRecordError::Aead
        );
    }

    /// And onto another conversation's record, for the same reason.
    #[test]
    fn a_record_does_not_open_in_another_conversation() {
        let a = alice();
        let bytes = build_encoded(
            &settled(&[0, 1]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            &a.signing,
        )
        .unwrap();
        assert_eq!(
            decode_and_verify(
                &bytes,
                &chan(0x51),
                Direction::AToB,
                &ar(0x42),
                a.signing.public_key(),
            )
            .unwrap_err(),
            AckRecordError::Aead
        );
    }

    /// `chan_id` reaches only the AAD and the preimage, never the wire — but it
    /// must still be *bound*, or an acknowledgement could be replayed into a
    /// conversation sharing an `AR` by accident.
    #[test]
    fn the_chan_id_is_bound_even_though_it_is_never_serialized() {
        let a = alice();
        let bytes = build_encoded(
            &settled(&[0, 1]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            &a.signing,
        )
        .unwrap();
        assert_eq!(
            decode_and_verify(
                &bytes,
                &chan(0x52),
                Direction::AToB,
                &ar(0x41),
                a.signing.public_key(),
            )
            .unwrap_err(),
            AckRecordError::Aead
        );
    }

    /// **The AAD's direction component, isolated from the key's.**
    ///
    /// The direction is bound twice and this module's docs claim the two are
    /// non-redundant. `a_record_does_not_open_on_the_other_direction` cannot show
    /// that: it moves BOTH bindings at once, so it stays green if either one is
    /// deleted — dropping `dir` from [`seal_aad`] and hardcoding the direction
    /// inside [`aes_key`] each leave it passing. As far as that test can tell, the
    /// AAD's direction is dead weight.
    ///
    /// So this one **holds the key fixed** and moves only the AAD: the record is
    /// sealed under the `a2b` key with an AAD that says `b2a`, and read back as
    /// `a2b`. Both sides derive the identical key, so the open can fail for
    /// exactly one reason. The mirror control below — the same seal with the
    /// matching AAD — must open, or this would pass against any AEAD failure at
    /// all rather than against the one it names.
    #[test]
    fn the_aad_binds_the_direction_independently_of_the_key() {
        let a = alice();
        let key = aes_key(&ar(0x41), Direction::AToB).unwrap();
        // Every field taken from ONE state, so the body and the signature cannot
        // disagree and the control below can only fail on the AAD.
        let state = settled(&[0, 1]);
        let body = wire::DmAckBody {
            high_water: state.high_water(),
            beyond: state.encode_beyond(),
            msg_sig: a
                .signing
                .sign(&ack::ack_sig_input(&chan(0x51), Direction::AToB, &state))
                .unwrap()
                .to_vec(),
        };
        let padded =
            crate::dm::pad_to_bucket(&body.encode_to_vec(), ACK_PAD_BUCKETS).expect("fits");

        // One key, two AADs differing ONLY in their direction component.
        let mismatched = wire::DmAck {
            sealed: seal_envelope(&key, &seal_aad(&chan(0x51), Direction::BToA), &padded).unwrap(),
        };
        let matched = wire::DmAck {
            sealed: seal_envelope(&key, &seal_aad(&chan(0x51), Direction::AToB), &padded).unwrap(),
        };

        assert_eq!(
            verify(
                &matched,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                a.signing.public_key()
            )
            .err(),
            None,
            "control: the same key and the matching AAD must open, or the refusal \
             below says nothing about the direction"
        );
        assert_eq!(
            verify(
                &mismatched,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                a.signing.public_key()
            )
            .unwrap_err(),
            AckRecordError::Aead,
            "the key is identical on both sides, so only the AAD's direction \
             component can refuse this — remove it from `seal_aad` and this opens"
        );
    }

    /// **A peer's claim, off the wire, actually clipped.**
    ///
    /// The whole decode → verify → merge discipline exists for the case where a
    /// peer claims more than it could possibly have collected, and every other
    /// merge in this module passes a ceiling generous enough never to fire — which
    /// exercises the union algebra and says nothing about the bound. This one
    /// builds a real record claiming a prefix of 9, carries it through
    /// [`build_encoded`] and [`decode_and_verify`], and merges it under a ceiling
    /// of 3.
    ///
    /// The claim is not refused: a peer's high-water is itself monotonic, so a
    /// refusal would be permanent rather than a retry and would discard the
    /// truthful low half with the impossible high half. It is clipped, and the
    /// result is a strict subset of what was claimed — the fail-safe direction.
    #[test]
    fn a_peer_claim_above_the_ceiling_is_clipped_not_accepted() {
        let a = alice();
        let bytes = build_encoded(
            &settled(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            &a.signing,
        )
        .unwrap();
        let peer = decode_and_verify(
            &bytes,
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            a.signing.public_key(),
        )
        .expect("a well-formed record still verifies — the lie is in what it claims");

        // We have sent up to 3 on this direction, so nothing above it is a claim
        // any honest peer could make.
        let mut ours = AckState::new();
        assert_eq!(
            ours.merge_peer_ack(peer, Some(3)).unwrap(),
            ack::PeerAckOutcome::ClippedToCeiling {
                claimed: 9,
                ceiling: Some(3),
            }
        );
        assert_eq!(ours.high_water(), Some(3));
        assert!(ours.is_settled(3));
        assert!(
            !ours.is_settled(4),
            "a position we never sent must not read as settled — this is the \
             false-delivered failure the ceiling exists to prevent"
        );
        assert!(!ours.is_settled(9));
    }

    /// An absent prefix is a real state — sequence zero is a live position — and
    /// must survive the round trip as `None` rather than collapsing to `Some(0)`.
    /// `optional uint64` on the wire is what carries the distinction.
    #[test]
    fn an_absent_prefix_round_trips_as_absent() {
        let a = alice();
        let mut state = AckState::new();
        state.collect(4).unwrap();
        assert_eq!(state.high_water(), None, "precondition: nothing contiguous");

        let bytes =
            build_encoded(&state, &chan(0x51), Direction::AToB, &ar(0x41), &a.signing).unwrap();
        let peer = decode_and_verify(
            &bytes,
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            a.signing.public_key(),
        )
        .unwrap();

        // A prefix that had collapsed to `Some(0)` would make position 0 settled.
        let mut ours = AckState::new();
        let _ = ours.merge_peer_ack(peer, Some(u64::MAX)).unwrap();
        assert_eq!(ours.high_water(), None);
        assert!(!ours.is_settled(0));
        assert!(ours.is_settled(4));
    }

    /// The runs decide confirmation just as the prefix does, so the signature must
    /// cover them: a record whose run set is swapped for another authentic one at
    /// the same prefix must not verify. Rebuilt through the real seal so the test
    /// exercises the shipped path rather than the preimage builder alone.
    #[test]
    fn a_substituted_run_set_is_rejected() {
        let a = alice();
        let pc = &a.signing;
        let five = build(
            &settled(&[0, 5]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            pc,
        )
        .unwrap();

        // Splice the SIGNATURE from a record over a different run set at the same
        // prefix into a body carrying the other run set, and re-seal.
        let sig = {
            let opened = open_envelope(
                &aes_key(&ar(0x41), Direction::AToB).unwrap(),
                &seal_aad(&chan(0x51), Direction::AToB),
                &five.sealed,
            )
            .unwrap();
            wire::DmAckBody::decode(crate::dm::unpad(&opened).unwrap())
                .unwrap()
                .msg_sig
        };
        let forged_body = wire::DmAckBody {
            high_water: Some(0),
            beyond: settled(&[0, 6]).encode_beyond(),
            msg_sig: sig,
        };
        let padded = crate::dm::pad_to_bucket(&forged_body.encode_to_vec(), ACK_PAD_BUCKETS)
            .expect("fits the bucket");
        let forged = wire::DmAck {
            sealed: seal_envelope(
                &aes_key(&ar(0x41), Direction::AToB).unwrap(),
                &seal_aad(&chan(0x51), Direction::AToB),
                &padded,
            )
            .unwrap(),
        };

        assert_eq!(
            verify(
                &forged,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                pc.public_key(),
            )
            .unwrap_err(),
            AckRecordError::Signature,
            "the signature must cover the runs, not only the prefix"
        );
    }

    /// The record is owner-write-gated rather than world-writable, so garbage in
    /// the slot means a peer wrote something malformed — still rejected, and above
    /// all never a panic, whatever bytes arrive.
    #[test]
    fn decode_and_verify_fails_closed_on_arbitrary_bytes() {
        let a = alice();
        let pc = &a.signing;
        for junk in [
            b"".as_slice(),
            b"\x00".as_slice(),
            b"not a protobuf at all".as_slice(),
            &[0xffu8; 64],
        ] {
            assert!(
                decode_and_verify(
                    junk,
                    &chan(0x51),
                    Direction::AToB,
                    &ar(0x41),
                    pc.public_key()
                )
                .is_err(),
                "arbitrary bytes must never verify: {junk:?}"
            );
        }
        let good = build_encoded(
            &settled(&[0, 1]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            pc,
        )
        .unwrap();
        assert!(
            decode_and_verify(
                &good[..good.len() / 2],
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                pc.public_key()
            )
            .is_err()
        );
    }

    /// A well-formed signature with a flipped bit must be rejected. It has to be
    /// flipped INSIDE the seal and re-sealed, because a flip in the sealed bytes
    /// fails the AEAD first and would exercise nothing about the signature.
    #[test]
    fn a_bit_flipped_signature_of_correct_length_is_rejected() {
        let a = alice();
        let pc = &a.signing;
        let key = aes_key(&ar(0x41), Direction::AToB).unwrap();
        let aad = seal_aad(&chan(0x51), Direction::AToB);

        let good = build(
            &settled(&[0, 1]),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            pc,
        )
        .unwrap();
        let opened = open_envelope(&key, &aad, &good.sealed).unwrap();
        let mut body = wire::DmAckBody::decode(crate::dm::unpad(&opened).unwrap()).unwrap();
        assert_eq!(
            body.msg_sig.len(),
            ml_dsa::SIG_LEN,
            "precondition: the length gate would pass"
        );
        body.msg_sig[ml_dsa::SIG_LEN / 2] ^= 0x01;

        let padded =
            crate::dm::pad_to_bucket(&body.encode_to_vec(), ACK_PAD_BUCKETS).expect("fits");
        let tampered = wire::DmAck {
            sealed: seal_envelope(&key, &aad, &padded).unwrap(),
        };
        assert_eq!(
            verify(
                &tampered,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                pc.public_key()
            )
            .unwrap_err(),
            AckRecordError::Signature
        );
    }

    /// A truncated signature must be diagnosable as a length fault rather than
    /// surfacing as "the signature did not verify", which would send a reader
    /// hunting for tampering.
    #[test]
    fn a_wrong_length_signature_fails_closed_with_a_diagnosable_error() {
        let a = alice();
        let pc = &a.signing;
        let key = aes_key(&ar(0x41), Direction::AToB).unwrap();
        let aad = seal_aad(&chan(0x51), Direction::AToB);

        let body = wire::DmAckBody {
            high_water: Some(1),
            beyond: Vec::new(),
            msg_sig: vec![0u8; 10],
        };
        let padded =
            crate::dm::pad_to_bucket(&body.encode_to_vec(), ACK_PAD_BUCKETS).expect("fits");
        let short = wire::DmAck {
            sealed: seal_envelope(&key, &aad, &padded).unwrap(),
        };
        assert_eq!(
            verify(
                &short,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                pc.public_key()
            )
            .unwrap_err(),
            AckRecordError::FieldLength {
                field: "msg_sig",
                expected: ml_dsa::SIG_LEN,
                actual: 10,
            }
        );
    }

    /// A non-canonical run set must be refused by the decoder before the signature
    /// is checked — a second spelling of one set is a set a signature cannot pin.
    #[test]
    fn a_non_canonical_run_set_is_refused() {
        let a = alice();
        let pc = &a.signing;
        let key = aes_key(&ar(0x41), Direction::AToB).unwrap();
        let aad = seal_aad(&chan(0x51), Direction::AToB);

        // A run declaring a count of one with no run bytes behind it.
        let body = wire::DmAckBody {
            high_water: Some(1),
            beyond: vec![0x00, 0x01],
            msg_sig: vec![0u8; ml_dsa::SIG_LEN],
        };
        let padded =
            crate::dm::pad_to_bucket(&body.encode_to_vec(), ACK_PAD_BUCKETS).expect("fits");
        let bad = wire::DmAck {
            sealed: seal_envelope(&key, &aad, &padded).unwrap(),
        };
        assert_eq!(
            verify(
                &bad,
                &chan(0x51),
                Direction::AToB,
                &ar(0x41),
                pc.public_key()
            )
            .unwrap_err(),
            AckRecordError::Ack(AckError::Malformed)
        );
    }

    // ---- size --------------------------------------------------------------

    /// The bucket must hold the largest body this module can produce, or a
    /// conversation that accumulated the maximum number of gaps could not
    /// acknowledge at all — the failure would appear only under sustained loss,
    /// which is exactly when acknowledgement matters most.
    #[test]
    fn the_pad_bucket_holds_a_maximal_body() {
        let a = alice();
        let state = maximal_state();
        let record = build(&state, &chan(0x51), Direction::AToB, &ar(0x41), &a.signing)
            .expect("a maximal statement must still fit its bucket");
        assert_eq!(record.sealed.len(), ACK_SEALED_LEN);
    }

    /// **The property the padding exists for.** Two acknowledgements with wildly
    /// different gap counts must be byte-identical in length, or the record's
    /// size publishes the loss pattern the seal is hiding.
    #[test]
    fn every_record_is_the_same_length_whatever_it_carries() {
        let a = alice();
        let pc = &a.signing;
        let empty = build_encoded(
            &AckState::new(),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            pc,
        )
        .unwrap();
        let full = build_encoded(
            &maximal_state(),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            pc,
        )
        .unwrap();
        assert_eq!(
            empty.len(),
            full.len(),
            "an empty ack and a 64-gap ack must be indistinguishable by length"
        );
    }

    /// The record must fit the single subkey of its `dflt(1)` schema, whose cap is
    /// the full 32 KiB. Asserted here rather than trusted, because the bound is a
    /// function of the signature length and the run cap and both could move.
    #[test]
    fn a_maximal_record_fits_one_subkey() {
        let a = alice();
        let bytes = build_encoded(
            &maximal_state(),
            &chan(0x51),
            Direction::AToB,
            &ar(0x41),
            &a.signing,
        )
        .unwrap();
        assert!(
            bytes.len() <= 32768,
            "a maximal ack record is {} bytes, past the dflt(1) subkey cap",
            bytes.len()
        );
    }

    /// One slot, pinned. `o_cnt` is part of the record address, so this constant
    /// and every `RecordShape` built from it move together or not at all.
    #[test]
    fn the_record_holds_exactly_one_slot() {
        const _: () = assert!(ACK_RECORD_SLOTS == 1);
    }
}
