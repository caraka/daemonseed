//! The **channel** — one direction of a conversation, written only by its
//! owner and read by the other party.
//!
//! `docs/design/direct-messaging.md` § Records gives the record and its
//! address. A channel is [`CHANNEL_SUBKEYS`] subkeys: subkey
//! [`CONTROL_SUBKEY`] is the control subkey, and the remaining
//! [`RING_SLOTS`] are the message ring, where message `seq` lives at
//! [`slot_for`]`(seq)`.
//!
//! Four rules govern it:
//!
//! - **The owner keypair is derived, never random.** [`derive_owner_seed`]
//!   is `HKDF-SHA-384` over the writer's identity secret, the peer's identity
//!   public key and the conversation generation, each length-prefixed. The
//!   seed is the VLD0 secret key, and Veilid's lookup key is a hash of the
//!   owner PUBLIC key — itself a pure function of the seed — so any store that
//!   derives this seed addresses the same record. That is what lets a second
//!   device recompute its own channels from the recovery phrase without any
//!   record changing.
//! - **No uncollected slot is ever overwritten, given a truthful cursor.**
//!   [`Ring::reserve`] refuses with [`ChannelError::RingFull`] once
//!   `send_seq − peer_collected` reaches [`RING_SLOTS`], which is exactly the
//!   point at which the next sequence would map onto the slot of the oldest
//!   uncollected one. The precondition is the cursor: it is the peer's own
//!   sealed statement of what it has collected, read from the reverse
//!   channel, and a peer that inflates it only licenses the overwrite of
//!   messages addressed to itself. No third party can move it, because it
//!   arrives under the reverse channel's own seal.
//! - **The turn fields travel together.** A turn's first message carries both
//!   `kem_ct` and `kem_pk`; every later message in the turn carries neither.
//!   [`MessageHeader::decode`] refuses one without the other
//!   ([`ChannelError::TurnFieldsIncomplete`]), because a header with only the
//!   ciphertext names a ratchet key the reader has no way to obtain.
//! - **The opening binds the advert it encapsulated to.** A
//!   [`ChannelOpening`] is signed over the writer's identity public key, its
//!   first ratchet key and the advert serial, so a hello relayed to a third
//!   party lands in a channel whose opening names an advert that party never
//!   published — [`ChannelError::AdvertSerial`], distinct from a signature
//!   failure (§ Abuse, *Redirect and impersonation*).
//!
//! **Two points the design leaves open are read here, and the readings are
//! what the code implements.**
//!
//! - *Which key seals the control subkey.* It is
//!   `k_control = HKDF(ss_hello, DM_CHANNEL_CONTROL)`, where `ss_hello` is the
//!   shared secret of the hello that named the channel: for `CHAN(A→B)` that
//!   is A's `ss0`, and for `CHAN(B→A)` it is the secret of B's hello written
//!   back. It does not step per turn — the control subkey is rewritten in
//!   place with a cursor, and a key that stepped would leave a reader that
//!   missed a turn unable to read the cursor it needs to catch up.
//! - *How wide the device identifier is.* [`MessageHeader::device_id`] is a
//!   `u32`, and a single-device installation writes
//!   [`DEVICE_ID_SINGLE_DEVICE`]. The field is reserved: nothing in this
//!   release reads it, and it is carried so that adding a second device later
//!   changes no record.
//!
//! Everything here is pure: no I/O, no clock, no ambient randomness except
//! the AEAD nonce the shared envelope primitive draws. The identity secret is
//! a parameter, never read from a store.
//!
//! Serves FC1, FC5.

use oxicrypt_aes::Aes256Key;
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::dm::{advert, domain, push_lp};
use crate::identity::keys::{ML_DSA_SEED_LEN, SignKeypair, SignatureError, verify_signature};
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Subkeys in a channel record — the `o_cnt` of its `dflt(o_cnt)` schema, and
/// part of the record's address.
///
/// One control subkey plus [`RING_SLOTS`] message slots. A writer MUST build
/// its `RecordShape` from this constant rather than a literal: `o_cnt` is part
/// of the deterministic address, so a shape that disagrees addresses a record
/// the peer is not reading.
pub const CHANNEL_SUBKEYS: u16 = 64;

/// The subkey holding the control record: the channel opening and the
/// writer's collection cursor.
pub const CONTROL_SUBKEY: u16 = 0;

/// Message slots in the ring — every subkey but [`CONTROL_SUBKEY`].
///
/// Also the backpressure bound: [`Ring::reserve`] refuses once this many
/// messages are uncollected.
pub const RING_SLOTS: u64 = 63;

/// Byte length of the Veilid owner seed this module derives. VLD0 is Ed25519,
/// so these bytes ARE the owner's secret key.
pub const CHANNEL_OWNER_SEED_LEN: usize = 32;

/// The device identifier a single-device installation writes.
///
/// The field is reserved (see the module header): a single-device
/// installation writes this value and reads nothing from it.
pub const DEVICE_ID_SINGLE_DEVICE: u32 = 0;

/// Bytes one channel subkey holds: `min(32 KiB, 1 MiB / CHANNEL_SUBKEYS)`.
///
/// Derived from [`CHANNEL_SUBKEYS`] by the substrate's own rule, so every fit
/// assertion below is against a figure that moves with the subkey count and a
/// change to [`CHANNEL_SUBKEYS`] that shrinks the subkey is caught at compile
/// time rather than by a write the network refuses.
pub const CHANNEL_SUBKEY_LEN: usize = {
    let per_subkey = (1024 * 1024) / CHANNEL_SUBKEYS as usize;
    if per_subkey < 32 * 1024 {
        per_subkey
    } else {
        32 * 1024
    }
};

/// Pins the derivation above to the figure
/// `docs/design/direct-messaging.md` § Substrate facts states for a 64-subkey
/// record.
const _: () = assert!(
    CHANNEL_SUBKEY_LEN == 16 * 1024,
    "a 64-subkey record holds 16 KiB per subkey"
);

/// Bytes an encoded [`MessageHeader`] takes at its largest — a turn's first
/// message, carrying both turn fields.
pub const MESSAGE_HEADER_MAX_LEN: usize =
    4 + 8 + 8 + 8 + 8 + (8 + ml_kem::CT_LEN) + (8 + ml_kem::EK_LEN);

/// Bytes the AEAD envelope adds to any sealed payload: the nonce it prepends
/// and the tag it appends.
const ENVELOPE_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Bytes a message body may occupy, derived rather than chosen: one subkey
/// less the largest header that can head it and the envelope's own overhead.
///
/// A sender that exceeds this writes a slot the network refuses, so the figure
/// belongs to whoever seals the body; it is exported here because only this
/// module knows the header's maximum.
pub const MESSAGE_BODY_MAX_LEN: usize =
    CHANNEL_SUBKEY_LEN - MESSAGE_HEADER_MAX_LEN - ENVELOPE_OVERHEAD;

const _: () = assert!(
    MESSAGE_BODY_MAX_LEN > 0,
    "a header plus the envelope overhead fills a whole subkey, leaving no body"
);

/// Byte length of an encoded [`ChannelOpening`]: `writer_identity_pk ‖
/// recipient_identity_pk ‖ first_ratchet_pk ‖ advert_serial ‖ signature`.
pub const OPENING_LEN: usize =
    ml_dsa::PK_LEN + ml_dsa::PK_LEN + ml_kem::EK_LEN + 8 + ml_dsa::SIG_LEN;

/// Byte offset of `recipient_identity_pk` within an encoded opening.
const RECIPIENT_PK_AT: usize = ml_dsa::PK_LEN;

/// Byte offset of `first_ratchet_pk` within an encoded opening.
const RATCHET_PK_AT: usize = RECIPIENT_PK_AT + ml_dsa::PK_LEN;

/// Byte offset of `advert_serial` within an encoded opening.
const SERIAL_AT: usize = RATCHET_PK_AT + ml_kem::EK_LEN;

/// Byte offset of the signature within an encoded opening.
const SIGNATURE_AT: usize = SERIAL_AT + 8;

/// Bytes a sealed control subkey takes at its largest: an opening, a cursor
/// and the closed flag, under the AEAD envelope.
pub const SEALED_CONTROL_MAX_LEN: usize = ENVELOPE_OVERHEAD + 8 + OPENING_LEN + 8 + 1;

const _: () = assert!(
    SEALED_CONTROL_MAX_LEN <= CHANNEL_SUBKEY_LEN,
    "a sealed control record does not fit one channel subkey"
);

redacted_secret_newtype! {
    /// The Veilid record-owner seed for one direction of one conversation —
    /// the VLD0 secret key of the record the holder writes.
    ///
    /// Unlike the advert's and the drop's owner seeds this one is NOT
    /// world-derivable: it is rooted in the writer's identity secret, so only
    /// the writer (or another device holding the same recovery phrase) can
    /// compute it, and only the writer can write the record.
    boxed pub struct ChannelOwnerSeed([u8; CHANNEL_OWNER_SEED_LEN]);
}

redacted_secret_newtype! {
    /// The AEAD key the control subkey is sealed under:
    /// `HKDF(ss_hello, DM_CHANNEL_CONTROL)`.
    boxed pub struct ControlKey([u8; 32]);
}

/// Why a channel operation failed.
///
/// `PartialEq` is implemented by hand rather than derived because neither
/// [`SignatureError`] nor `oxicrypt_module::Error` is comparable; those
/// variants compare equal on the variant alone, which is all a caller needs.
#[derive(Debug)]
pub enum ChannelError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// An encoded opening is not [`OPENING_LEN`] long, so no field can be
    /// read from it. Carries both figures, so a truncation is diagnosable.
    Length {
        /// What an opening measures.
        expected: usize,
        /// What arrived.
        actual: usize,
    },
    /// An encoded header or control record ran out of bytes, or carried a
    /// flag byte that is neither zero nor one.
    Malformed,
    /// A header carried `kem_ct` without `kem_pk`, or the reverse. A turn's
    /// first message carries both and every later message neither, so one
    /// alone names a ratchet key the reader cannot obtain.
    TurnFieldsIncomplete,
    /// A header's `kem_ct` or `kem_pk` is present at the wrong length.
    FieldLength {
        /// What the field measures.
        expected: usize,
        /// What arrived.
        actual: usize,
    },
    /// A restored ring claims the peer collected more than was ever sent.
    /// Nothing legitimate produces that, so it is refused rather than
    /// repaired: a clamp would let a corrupt cursor read as a full ring and
    /// the next `reserve` would overwrite an uncollected slot.
    CorruptState {
        /// The next sequence the restored state claims.
        send_seq: u64,
        /// The peer cursor the restored state claims.
        peer_collected: u64,
    },
    /// The ring is full: [`RING_SLOTS`] messages are uncollected, so the next
    /// sequence would overwrite the oldest of them. Backpressure, not a
    /// failure — the caller retries once the peer's cursor advances.
    RingFull {
        /// The next sequence that would have been handed out.
        send_seq: u64,
        /// The peer's cursor over this direction.
        peer_collected: u64,
    },
    /// An authentic opening naming a recipient other than the reader — a
    /// hello relayed to somebody the writer never addressed.
    Recipient,
    /// The opening's signature did not verify under the identity public key
    /// the opening itself carries.
    ///
    /// Deliberately uniform: the preimage binds that public key, so an
    /// opening assembled from someone else's fields fails here exactly as a
    /// flipped byte does, and a verifier that told the two apart would be an
    /// oracle.
    Signature,
    /// An authentic opening naming an advert serial other than the one the
    /// reader expects — a hello relayed to a party whose advert it was never
    /// encapsulated to.
    AdvertSerial {
        /// The serial the reader encapsulated to, or published.
        expected: u64,
        /// The serial the opening names.
        found: u64,
    },
    /// The control subkey did not open: a wrong `ss_hello`, a tampered
    /// ciphertext, or an associated-data mismatch. Uniform by design.
    Aead,
    /// A local signing operation failed while building an opening — the
    /// crypto module is not operational, or the active profile disallows
    /// ML-DSA signing. Carries the cause: there is no adversary on this path.
    Signing(SignatureError),
    /// The crypto module refused an AES or key-generation call.
    Module(oxicrypt_module::Error),
}

impl PartialEq for ChannelError {
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
            )
            | (
                Self::FieldLength {
                    expected: ea,
                    actual: aa,
                },
                Self::FieldLength {
                    expected: eb,
                    actual: ab,
                },
            ) => ea == eb && aa == ab,
            (Self::Malformed, Self::Malformed) => true,
            (Self::TurnFieldsIncomplete, Self::TurnFieldsIncomplete) => true,
            (
                Self::RingFull {
                    send_seq: sa,
                    peer_collected: ca,
                },
                Self::RingFull {
                    send_seq: sb,
                    peer_collected: cb,
                },
            )
            | (
                Self::CorruptState {
                    send_seq: sa,
                    peer_collected: ca,
                },
                Self::CorruptState {
                    send_seq: sb,
                    peer_collected: cb,
                },
            ) => sa == sb && ca == cb,
            (Self::Signature, Self::Signature) => true,
            (Self::Recipient, Self::Recipient) => true,
            (
                Self::AdvertSerial {
                    expected: ea,
                    found: fa,
                },
                Self::AdvertSerial {
                    expected: eb,
                    found: fb,
                },
            ) => ea == eb && fa == fb,
            (Self::Aead, Self::Aead) => true,
            // Compared on the variant: the wrapped cause is diagnostic and is
            // not itself comparable.
            (Self::Signing(_), Self::Signing(_)) => true,
            (Self::Module(_), Self::Module(_)) => true,
            _ => false,
        }
    }
}

impl Eq for ChannelError {}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "channel HKDF failed: {e:?}"),
            Self::Length { expected, actual } => {
                write!(
                    f,
                    "channel opening: expected {expected} bytes, got {actual}"
                )
            }
            Self::Malformed => write!(f, "channel: the encoding is malformed"),
            Self::TurnFieldsIncomplete => {
                write!(
                    f,
                    "channel header: one turn field is present without the other"
                )
            }
            Self::FieldLength { expected, actual } => {
                write!(
                    f,
                    "channel header: a turn field measures {actual} bytes, not {expected}"
                )
            }
            Self::RingFull {
                send_seq,
                peer_collected,
            } => write!(
                f,
                "channel ring is full at seq {send_seq} with the peer collected to {peer_collected}"
            ),
            Self::CorruptState {
                send_seq,
                peer_collected,
            } => write!(
                f,
                "channel ring state is impossible: sent {send_seq}, peer collected {peer_collected}"
            ),
            Self::Signature => write!(f, "channel opening signature did not verify"),
            Self::Recipient => write!(f, "channel opening names another recipient"),
            Self::AdvertSerial { expected, found } => write!(
                f,
                "channel opening names advert serial {found}, not {expected}"
            ),
            Self::Aead => write!(f, "channel control subkey did not open"),
            Self::Signing(e) => write!(f, "channel opening could not be signed locally: {e:?}"),
            Self::Module(e) => write!(f, "channel: the crypto module refused: {e:?}"),
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<EnvelopeError> for ChannelError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_)
            | EnvelopeError::TooShort
            | EnvelopeError::Decrypt(_)
            | EnvelopeError::Encrypt(_) => Self::Aead,
        }
    }
}

/// Which subkey message `seq` occupies: `1 + (seq mod RING_SLOTS)`.
///
/// Subkey [`CONTROL_SUBKEY`] is skipped, so the ring is the
/// [`RING_SLOTS`] subkeys above it. Total within a direction, so a reader
/// walks the ring in sequence order and there is no out-of-order delivery to
/// reconcile.
pub fn slot_for(seq: u64) -> u16 {
    // The remainder is below RING_SLOTS, which is below u16::MAX, so the cast
    // cannot truncate.
    1 + (seq % RING_SLOTS) as u16
}

/// Derive the owner seed for one direction of one conversation:
/// `HKDF-SHA-384(salt = DM_CHANNEL_SALT, ikm = identity_seed, info =
/// DM_CHANNEL_OWNER ‖ lp(peer identity pk) ‖ lp(BE64(generation)))`.
///
/// Deterministic and pure in its three inputs, which is the whole point: any
/// store holding the same recovery phrase re-derives the same seed, hence the
/// same VLD0 keypair and the same record address, and the conversation
/// generation is what makes a re-established conversation a different record
/// rather than a reuse of the old one.
///
/// `identity_seed` is a parameter and is never read from a store here. The
/// public half — and so the record's lookup key — is computed from this seed
/// by the transport layer, which is where VLD0's Ed25519 lives; it is a pure
/// function of the seed, so equal seeds address equal records.
pub fn derive_owner_seed(
    identity_seed: &[u8; ML_DSA_SEED_LEN],
    peer_identity_pk: &[u8; ml_dsa::PK_LEN],
    generation: u64,
) -> Result<ChannelOwnerSeed, ChannelError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_CHANNEL_SALT), identity_seed)
        .map_err(ChannelError::Kdf)?;
    let mut info = Vec::with_capacity(domain::DM_CHANNEL_OWNER.len() + 16 + ml_dsa::PK_LEN + 8);
    info.extend_from_slice(domain::DM_CHANNEL_OWNER);
    push_lp(&mut info, peer_identity_pk);
    push_lp(&mut info, &generation.to_be_bytes());
    let seed =
        derive_boxed_seed::<CHANNEL_OWNER_SEED_LEN>(&hkdf, &info).map_err(ChannelError::Kdf)?;
    Ok(ChannelOwnerSeed(seed))
}

/// Derive the key the control subkey is sealed under:
/// `HKDF(ss_hello, DM_CHANNEL_CONTROL)`.
///
/// `ss_hello` is the shared secret of the hello that named this channel. It
/// does not step per turn — see the module header.
pub fn control_key(ss_hello: &advert::AdvertSharedSecret) -> Result<ControlKey, ChannelError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_CHANNEL_CONTROL_SALT), ss_hello.as_bytes())
        .map_err(ChannelError::Kdf)?;
    let key =
        derive_boxed_seed::<32>(&hkdf, domain::DM_CHANNEL_CONTROL).map_err(ChannelError::Kdf)?;
    Ok(ControlKey(key))
}

/// The associated data the control subkey's seal binds:
/// `DM_CHANNEL_CONTROL_AAD ‖ lp(BE32(CONTROL_SUBKEY))`.
///
/// Domain separation is what this carries: the key already binds the
/// conversation and the direction, since it comes from that hello's shared
/// secret alone, so the subkey number is what stops a control record opening
/// as any other sealed payload under a coincidentally equal key.
pub fn control_aad() -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain::DM_CHANNEL_CONTROL_AAD.len() + 12);
    buf.extend_from_slice(domain::DM_CHANNEL_CONTROL_AAD);
    push_lp(&mut buf, &u32::from(CONTROL_SUBKEY).to_be_bytes());
    buf
}

/// The send side of the ring: the next sequence to hand out, and the peer's
/// cursor over this direction.
///
/// The cursor is the count of messages the peer has collected contiguously
/// from sequence 0 (§ Delivery), so `send_seq − peer_collected` is what is
/// outstanding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ring {
    send_seq: u64,
    peer_collected: u64,
}

impl Ring {
    /// A ring at the start of a conversation.
    pub fn new() -> Self {
        Self::default()
    }

    /// A ring restored from the conversation's on-disk state.
    ///
    /// Refuses [`ChannelError::CorruptState`] on a cursor above `send_seq`
    /// rather than clamping it. A clamp would turn an impossible state into a
    /// plausible one and carry the corruption forward silently; the caller
    /// that reads a restored conversation is the one that can act on it.
    pub fn restore(send_seq: u64, peer_collected: u64) -> Result<Self, ChannelError> {
        if peer_collected > send_seq {
            return Err(ChannelError::CorruptState {
                send_seq,
                peer_collected,
            });
        }
        Ok(Self {
            send_seq,
            peer_collected,
        })
    }

    /// The next sequence that will be handed out.
    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    /// The peer's cursor over this direction.
    pub fn peer_collected(&self) -> u64 {
        self.peer_collected
    }

    /// How many sent messages the peer has not collected.
    pub fn uncollected(&self) -> u64 {
        self.send_seq.saturating_sub(self.peer_collected)
    }

    /// Take the next sequence, or refuse with [`ChannelError::RingFull`].
    ///
    /// The refusal is what keeps the design's promise that no uncollected
    /// slot is overwritten: at [`RING_SLOTS`] uncollected messages the next
    /// sequence maps onto the slot of the oldest of them. On a refusal
    /// [`Self::send_seq`] is unchanged, so a caller that retries after the
    /// peer's cursor advances gets the sequence it would have had.
    pub fn reserve(&mut self) -> Result<u64, ChannelError> {
        if self.uncollected() >= RING_SLOTS {
            return Err(ChannelError::RingFull {
                send_seq: self.send_seq,
                peer_collected: self.peer_collected,
            });
        }
        let seq = self.send_seq;
        self.send_seq = self.send_seq.saturating_add(1);
        Ok(seq)
    }

    /// Take the peer's cursor, which never moves backwards.
    ///
    /// A lower cursor than the one already held is ignored: the peer's
    /// records are world-readable and an old value can be re-read, and a
    /// cursor that regressed would license overwriting a slot already
    /// counted as collected. A cursor ABOVE [`Self::send_seq`] is taken as
    /// `send_seq`, since the peer cannot have collected a message this
    /// direction has not written.
    pub fn advance_peer_collected(&mut self, cursor: u64) {
        let bounded = cursor.min(self.send_seq);
        if bounded > self.peer_collected {
            self.peer_collected = bounded;
        }
    }
}

/// The clear header of one message slot: `header ‖ AEAD_{mk}(body)`.
///
/// `n` and `m` are the turn numbers the message's key was derived from, and
/// pinning both in the header is what lets a reader recompute the chain it
/// belongs to (§ Keys and forward secrecy). `device_id` is reserved.
///
/// **The header is the body's associated data** — [`message_aad`] is a domain
/// label and these bytes — so every clear field here is bound to the body it
/// heads, and a field rewritten on an otherwise genuine slot leaves a body
/// that does not open.
///
/// `cursor` rides here because § Delivery has it ride here: a reader publishes
/// its collection cursor inside its reply, and the control subkey is written
/// only when there is no reply to carry it, which is what keeps a collection
/// batch at zero writes in the common case.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// Which device of the writer's wrote this. Reserved: a single-device
    /// installation writes [`DEVICE_ID_SINGLE_DEVICE`] and reads nothing from
    /// it.
    pub device_id: u32,
    /// The writer's turn number this message's key came from.
    pub n: u64,
    /// The peer turn number the writer had read when it started turn `n`.
    pub m: u64,
    /// The message's sequence within this direction.
    pub seq: u64,
    /// How many of the peer's messages the writer has collected contiguously
    /// from sequence 0 — the cursor § Delivery has a reply carry.
    pub cursor: u64,
    /// The turn's ML-KEM ciphertext, on a turn's first message only.
    pub kem_ct: Option<Box<[u8; ml_kem::CT_LEN]>>,
    /// The writer's fresh ratchet public key, on a turn's first message only.
    pub kem_pk: Option<Box<[u8; ml_kem::EK_LEN]>>,
}

impl std::fmt::Debug for MessageHeader {
    /// Renders the turn fields as present or absent rather than as three
    /// kilobytes of key material on a log surface.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageHeader")
            .field("device_id", &self.device_id)
            .field("n", &self.n)
            .field("m", &self.m)
            .field("seq", &self.seq)
            .field("cursor", &self.cursor)
            .field("kem_ct", &self.kem_ct.is_some())
            .field("kem_pk", &self.kem_pk.is_some())
            .finish()
    }
}

impl MessageHeader {
    /// A header for a message that is not a turn's first.
    pub fn continuing(device_id: u32, n: u64, m: u64, seq: u64, cursor: u64) -> Self {
        Self {
            device_id,
            n,
            m,
            seq,
            cursor,
            kem_ct: None,
            kem_pk: None,
        }
    }

    /// Whether this header starts a turn, which is exactly when it carries
    /// the turn fields.
    pub fn starts_turn(&self) -> bool {
        self.kem_ct.is_some() && self.kem_pk.is_some()
    }

    /// Encode the header: `BE32(device_id) ‖ BE64(n) ‖ BE64(m) ‖ BE64(seq) ‖
    /// BE64(cursor) ‖ lp(kem_ct) ‖ lp(kem_pk)`, each optional field
    /// length-prefixed and empty when absent.
    ///
    /// Self-describing: the two length prefixes are always present, so a
    /// reader knows where the header ends without knowing whether this is a
    /// turn's first message, and an encoding carrying one field without the
    /// other is representable and therefore rejectable rather than
    /// unnoticed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MESSAGE_HEADER_MAX_LEN);
        out.extend_from_slice(&self.device_id.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&self.m.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.cursor.to_be_bytes());
        push_lp(
            &mut out,
            self.kem_ct.as_ref().map(|ct| ct.as_slice()).unwrap_or(&[]),
        );
        push_lp(
            &mut out,
            self.kem_pk.as_ref().map(|pk| pk.as_slice()).unwrap_or(&[]),
        );
        out
    }

    /// Decode a header from the start of a slot, returning it and the bytes
    /// after it — the sealed body.
    ///
    /// Fails closed: [`ChannelError::Malformed`] when the bytes run out,
    /// [`ChannelError::FieldLength`] on a turn field of the wrong width, and
    /// [`ChannelError::TurnFieldsIncomplete`] on one turn field without the
    /// other.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), ChannelError> {
        let mut reader = Reader::new(bytes);
        let device_id = u32::from_be_bytes(reader.take_array::<4>()?);
        let n = u64::from_be_bytes(reader.take_array::<8>()?);
        let m = u64::from_be_bytes(reader.take_array::<8>()?);
        let seq = u64::from_be_bytes(reader.take_array::<8>()?);
        let cursor = u64::from_be_bytes(reader.take_array::<8>()?);
        let ct_field = reader.take_lp()?;
        let pk_field = reader.take_lp()?;

        let kem_ct = optional_field::<{ ml_kem::CT_LEN }>(ct_field)?;
        let kem_pk = optional_field::<{ ml_kem::EK_LEN }>(pk_field)?;
        if kem_ct.is_some() != kem_pk.is_some() {
            return Err(ChannelError::TurnFieldsIncomplete);
        }

        Ok((
            Self {
                device_id,
                n,
                m,
                seq,
                cursor,
                kem_ct,
                kem_pk,
            },
            reader.rest(),
        ))
    }
}

/// The associated data a message body is sealed under: `DM_CHANNEL_MSG_AAD ‖
/// header`, the header exactly as [`MessageHeader::encode`] wrote it.
///
/// Every clear field the slot carries is therefore bound to the body it heads.
/// A storage node holding the record can rewrite a header field — it holds the
/// bytes — but the body then fails to open, so the sequence number, the turn
/// numbers, the cursor and the device identifier are as authentic as the body
/// itself rather than merely present.
pub fn message_aad(header: &MessageHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain::DM_CHANNEL_MSG_AAD.len() + MESSAGE_HEADER_MAX_LEN);
    buf.extend_from_slice(domain::DM_CHANNEL_MSG_AAD);
    buf.extend_from_slice(&header.encode());
    buf
}

/// An absent-or-exact-width optional field: empty is absent, the exact width
/// is present, anything else is [`ChannelError::FieldLength`].
fn optional_field<const N: usize>(field: &[u8]) -> Result<Option<Box<[u8; N]>>, ChannelError> {
    if field.is_empty() {
        return Ok(None);
    }
    let exact: &[u8; N] = field.try_into().map_err(|_| ChannelError::FieldLength {
        expected: N,
        actual: field.len(),
    })?;
    Ok(Some(Box::new(*exact)))
}

/// A cursor over an encoded record that runs out rather than panicking.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ChannelError> {
        if self.bytes.len() < n {
            return Err(ChannelError::Malformed);
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ChannelError> {
        let head = self.take(N)?;
        Ok(*<&[u8; N]>::try_from(head).expect("checked length"))
    }

    /// Take one length-prefixed field written by
    /// [`crate::dm::push_lp`].
    fn take_lp(&mut self) -> Result<&'a [u8], ChannelError> {
        let len = u64::from_be_bytes(self.take_array::<8>()?);
        let len = usize::try_from(len).map_err(|_| ChannelError::Malformed)?;
        self.take(len)
    }

    fn rest(self) -> &'a [u8] {
        self.bytes
    }
}

/// The channel opening, written once into the control subkey: who writes this
/// channel, the first ratchet key they will step from, and the advert serial
/// they encapsulated to.
///
/// **Decoding an opening is not verifying it.** [`Self::decode`] reads the
/// fields as they stand, including the identity public key, which is the
/// reader's first sight of who is calling. [`Self::verify`] is what makes it
/// evidence, and a reader applies its known-identity rules (§ Flows, *A hello
/// from a known identity*) only after that returns `Ok`.
///
/// This is the one DM record that CARRIES the public key it is verified
/// under, and deliberately: an advert is verified under the key its address
/// was derived from, because a reader already knows whose advert it sought,
/// whereas a channel opening is how a reader learns who wrote to it. The
/// signature therefore proves only that the holder of that key signed these
/// fields; whether that key is one the reader will talk to is a separate
/// decision the reader takes afterwards.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelOpening {
    /// The writer's long-term ML-DSA-87 identity public key.
    pub writer_identity_pk: Box<[u8; ml_dsa::PK_LEN]>,
    /// The identity the writer addressed this channel to.
    pub recipient_identity_pk: Box<[u8; ml_dsa::PK_LEN]>,
    /// The writer's first ratchet ML-KEM-1024 public key.
    pub first_ratchet_pk: Box<[u8; ml_kem::EK_LEN]>,
    /// The serial of the advert the writer encapsulated to.
    pub advert_serial: u64,
    /// The ML-DSA-87 signature over all of the above.
    pub signature: Box<[u8; ml_dsa::SIG_LEN]>,
}

impl std::fmt::Debug for ChannelOpening {
    /// Renders the three key-sized fields by name rather than as nine
    /// kilobytes on a log surface.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelOpening")
            .field("writer_identity_pk", &"<ML-DSA-87 pubkey>")
            .field("recipient_identity_pk", &"<ML-DSA-87 pubkey>")
            .field("first_ratchet_pk", &"<ML-KEM-1024 pubkey>")
            .field("advert_serial", &self.advert_serial)
            .field("signature", &"<ML-DSA-87 signature>")
            .finish()
    }
}

/// Build the domain-separated signing preimage for an opening:
/// `DM_CHANNEL_OPENING_SIG ‖ lp(writer pk) ‖ lp(recipient pk) ‖ lp(first
/// ratchet pk) ‖ lp(BE64(advert_serial))`.
///
/// Every field is length-prefixed, the repository's one preimage convention,
/// so no pair of adjacent fields can be re-split into a different tuple.
///
/// Two of the four fields are what stop a relayed hello, and they stop
/// different relays: `advert_serial` names the advert the writer encapsulated
/// to, which a reader who never published that serial refuses, and the
/// recipient key names the identity the writer addressed, which a reader who
/// is not that identity refuses even when the serial happens to match.
pub fn opening_signing_input(
    writer_identity_pk: &[u8; ml_dsa::PK_LEN],
    recipient_identity_pk: &[u8; ml_dsa::PK_LEN],
    first_ratchet_pk: &[u8; ml_kem::EK_LEN],
    advert_serial: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        domain::DM_CHANNEL_OPENING_SIG.len() + 32 + 2 * ml_dsa::PK_LEN + ml_kem::EK_LEN + 8,
    );
    buf.extend_from_slice(domain::DM_CHANNEL_OPENING_SIG);
    push_lp(&mut buf, writer_identity_pk);
    push_lp(&mut buf, recipient_identity_pk);
    push_lp(&mut buf, first_ratchet_pk);
    push_lp(&mut buf, &advert_serial.to_be_bytes());
    buf
}

impl ChannelOpening {
    /// Sign and assemble an opening for the control subkey.
    pub fn build(
        signer: &SignKeypair,
        recipient_identity_pk: &[u8; ml_dsa::PK_LEN],
        first_ratchet_pk: &[u8; ml_kem::EK_LEN],
        advert_serial: u64,
    ) -> Result<Self, ChannelError> {
        let preimage = opening_signing_input(
            signer.public_key(),
            recipient_identity_pk,
            first_ratchet_pk,
            advert_serial,
        );
        let signature = signer.sign(&preimage).map_err(ChannelError::Signing)?;
        Ok(Self {
            writer_identity_pk: Box::new(*signer.public_key()),
            recipient_identity_pk: Box::new(*recipient_identity_pk),
            first_ratchet_pk: Box::new(*first_ratchet_pk),
            advert_serial,
            signature: Box::new(signature),
        })
    }

    /// Encode the opening: `writer_identity_pk ‖ recipient_identity_pk ‖
    /// first_ratchet_pk ‖ BE64(advert_serial) ‖ signature`, exactly
    /// [`OPENING_LEN`] bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OPENING_LEN);
        out.extend_from_slice(self.writer_identity_pk.as_slice());
        out.extend_from_slice(self.recipient_identity_pk.as_slice());
        out.extend_from_slice(self.first_ratchet_pk.as_slice());
        out.extend_from_slice(&self.advert_serial.to_be_bytes());
        out.extend_from_slice(self.signature.as_slice());
        out
    }

    /// Read an opening's fields. Fails closed on any length but
    /// [`OPENING_LEN`], before any ML-DSA call.
    ///
    /// Reading is not verifying — see the type's own documentation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChannelError> {
        if bytes.len() != OPENING_LEN {
            return Err(ChannelError::Length {
                expected: OPENING_LEN,
                actual: bytes.len(),
            });
        }
        let writer_identity_pk: Box<[u8; ml_dsa::PK_LEN]> = Box::new(
            *<&[u8; ml_dsa::PK_LEN]>::try_from(&bytes[..RECIPIENT_PK_AT]).expect("checked length"),
        );
        let recipient_identity_pk: Box<[u8; ml_dsa::PK_LEN]> = Box::new(
            *<&[u8; ml_dsa::PK_LEN]>::try_from(&bytes[RECIPIENT_PK_AT..RATCHET_PK_AT])
                .expect("checked length"),
        );
        let first_ratchet_pk: Box<[u8; ml_kem::EK_LEN]> = Box::new(
            *<&[u8; ml_kem::EK_LEN]>::try_from(&bytes[RATCHET_PK_AT..SERIAL_AT])
                .expect("checked length"),
        );
        let advert_serial = u64::from_be_bytes(
            *<&[u8; 8]>::try_from(&bytes[SERIAL_AT..SIGNATURE_AT]).expect("checked length"),
        );
        let signature: Box<[u8; ml_dsa::SIG_LEN]> = Box::new(
            *<&[u8; ml_dsa::SIG_LEN]>::try_from(&bytes[SIGNATURE_AT..]).expect("checked length"),
        );
        Ok(Self {
            writer_identity_pk,
            recipient_identity_pk,
            first_ratchet_pk,
            advert_serial,
            signature,
        })
    }

    /// Verify the opening: the signature under the identity public key the
    /// opening carries, then that it names the reader as its recipient, then
    /// that it names the advert serial the reader expects.
    ///
    /// The signature is checked first, so [`ChannelError::Recipient`] and
    /// [`ChannelError::AdvertSerial`] are only ever reported for an opening
    /// that is genuinely someone's — a relayed hello, not a random subkey.
    pub fn verify(
        &self,
        expected_recipient_pk: &[u8; ml_dsa::PK_LEN],
        expected_advert_serial: u64,
    ) -> Result<(), ChannelError> {
        let preimage = opening_signing_input(
            &self.writer_identity_pk,
            &self.recipient_identity_pk,
            &self.first_ratchet_pk,
            self.advert_serial,
        );
        verify_signature(&self.writer_identity_pk, &preimage, &self.signature)
            .map_err(|_| ChannelError::Signature)?;
        if self.recipient_identity_pk.as_slice() != expected_recipient_pk.as_slice() {
            return Err(ChannelError::Recipient);
        }
        if self.advert_serial != expected_advert_serial {
            return Err(ChannelError::AdvertSerial {
                expected: expected_advert_serial,
                found: self.advert_serial,
            });
        }
        Ok(())
    }
}

/// The control subkey's plaintext: the opening, the writer's collection
/// cursor over the reverse direction, and whether the writer has closed the
/// conversation.
///
/// The opening is written once and then carried unchanged; the cursor is
/// rewritten in place, which is why the sealing key does not step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// The channel opening, absent only before it has been written.
    pub opening: Option<ChannelOpening>,
    /// How many of the peer's messages the writer has collected contiguously
    /// from sequence 0.
    pub collected_cursor: u64,
    /// Whether the writer has torn this conversation down (§ Delivery).
    pub closed: bool,
}

impl Control {
    /// Encode the control record: `lp(opening) ‖ BE64(collected_cursor) ‖
    /// closed`, the opening field empty when absent and the flag one byte.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OPENING_LEN + 24);
        let encoded = self.opening.as_ref().map(ChannelOpening::encode);
        push_lp(&mut out, encoded.as_deref().unwrap_or(&[]));
        out.extend_from_slice(&self.collected_cursor.to_be_bytes());
        out.push(u8::from(self.closed));
        out
    }

    /// Decode a control record. Reading an opening is not verifying it — the
    /// caller calls [`ChannelOpening::verify`].
    ///
    /// Fails closed with [`ChannelError::Malformed`] on bytes that run out, a
    /// flag byte that is neither zero nor one, or trailing bytes past the
    /// flag.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChannelError> {
        let mut reader = Reader::new(bytes);
        let opening_field = reader.take_lp()?;
        let collected_cursor = u64::from_be_bytes(reader.take_array::<8>()?);
        let closed = match reader.take_array::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err(ChannelError::Malformed),
        };
        if !reader.rest().is_empty() {
            return Err(ChannelError::Malformed);
        }
        let opening = if opening_field.is_empty() {
            None
        } else {
            Some(ChannelOpening::decode(opening_field)?)
        };
        Ok(Self {
            opening,
            collected_cursor,
            closed,
        })
    }
}

/// Seal the control subkey under `k_control = HKDF(ss_hello,
/// DM_CHANNEL_CONTROL)`.
pub fn seal_control(
    ss_hello: &advert::AdvertSharedSecret,
    control: &Control,
) -> Result<Vec<u8>, ChannelError> {
    let key = control_key(ss_hello)?;
    let aes = Aes256Key::new(key.as_bytes()).map_err(ChannelError::Module)?;
    let mut plaintext = control.encode();
    let sealed = seal_envelope(&aes, &control_aad(), &plaintext);
    plaintext.zeroize();
    Ok(sealed?)
}

/// Open the control subkey read out of a channel record.
///
/// A wrong `ss_hello` fails as [`ChannelError::Aead`], uniformly with a
/// tampered ciphertext.
pub fn open_control(
    ss_hello: &advert::AdvertSharedSecret,
    bytes: &[u8],
) -> Result<Control, ChannelError> {
    let key = control_key(ss_hello)?;
    let aes = Aes256Key::new(key.as_bytes()).map_err(ChannelError::Module)?;
    let mut plaintext = open_envelope(&aes, &control_aad(), bytes)?;
    let decoded = Control::decode(&plaintext);
    plaintext.zeroize();
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A moment inside every advert's usability window.
    const NOW: u64 = 1_700_000_000;

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

    fn signer(seed: u8) -> SignKeypair {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).expect("derive a signer")
    }

    /// One party's advert key state and a shared secret against it — the real
    /// path, since `AdvertSharedSecret` is only constructible by
    /// encapsulating or decapsulating.
    fn shared_secret(seed: u8) -> advert::AdvertSharedSecret {
        let signer = signer(seed);
        let keys = advert::AdvertKeys::new(NOW, fill_with(seed)).expect("advert keys");
        let bytes = keys.advert_bytes(&signer).expect("advert bytes");
        let verified = advert::verify(signer.public_key(), &bytes).expect("verify the advert");
        let encap =
            advert::encapsulate_to(&verified, NOW, fill_with(seed ^ 0x5a)).expect("encapsulate");
        encap.shared_secret
    }

    fn ratchet_pk(byte: u8) -> [u8; ml_kem::EK_LEN] {
        [byte; ml_kem::EK_LEN]
    }

    /// The identity every fixture opening is addressed to.
    fn recipient_pk() -> [u8; ml_dsa::PK_LEN] {
        *signer(0x77).public_key()
    }

    /// An opening from the writer at seed `0x11` to [`recipient_pk`].
    fn opening(serial: u64) -> ChannelOpening {
        ChannelOpening::build(&signer(0x11), &recipient_pk(), &ratchet_pk(0x22), serial)
            .expect("build the opening")
    }

    // ── slot_for ────────────────────────────────────────────────────────────

    /// Every slot a sequence maps to is a ring slot, never the control
    /// subkey, and the mapping repeats with period `RING_SLOTS`.
    #[test]
    fn slots_stay_in_the_ring_and_repeat_every_ring_slots() {
        for seq in 0u64..=200 {
            let slot = slot_for(seq);
            assert!(
                (1..=RING_SLOTS as u16).contains(&slot),
                "seq {seq} mapped to slot {slot}, outside the ring"
            );
            assert_ne!(
                slot, CONTROL_SUBKEY,
                "seq {seq} mapped to the control subkey"
            );
            assert_eq!(
                slot,
                slot_for(seq + RING_SLOTS),
                "the period is not {RING_SLOTS}"
            );
        }
    }

    /// One window of `RING_SLOTS` consecutive sequences occupies
    /// `RING_SLOTS` distinct slots — the property the backpressure bound
    /// exists to preserve, checked by exhaustion over a window.
    #[test]
    fn a_full_window_of_sequences_occupies_distinct_slots() {
        for base in [0u64, 1, 62, 63, 1_000_000] {
            let slots: std::collections::BTreeSet<u16> =
                (base..base + RING_SLOTS).map(slot_for).collect();
            assert_eq!(
                slots.len(),
                RING_SLOTS as usize,
                "a window at {base} reused a slot"
            );
        }
    }

    /// **The control for the backpressure bound, as a mutation-shaped
    /// assertion on `slot_for` rather than an edit to the ring.** Were
    /// `reserve` to drop its `>= RING_SLOTS` check, a ring with sequence 0
    /// still uncollected would hand out sequence `RING_SLOTS`, and this is
    /// the collision that would follow: the 64th sequence in the window maps
    /// onto the slot of the oldest uncollected one.
    #[test]
    fn the_sequence_past_a_full_window_collides_with_an_uncollected_slot() {
        let mut ring = Ring::new();
        let reserved: Vec<u64> = (0..RING_SLOTS).map(|_| ring.reserve().unwrap()).collect();
        let past_the_window = ring.send_seq();
        assert_eq!(past_the_window, RING_SLOTS);
        assert_eq!(
            slot_for(past_the_window),
            slot_for(reserved[0]),
            "the 64th sequence must be the collision the refusal prevents"
        );
        // And the refusal is what stops it being written.
        assert_eq!(
            ring.reserve().unwrap_err(),
            ChannelError::RingFull {
                send_seq: RING_SLOTS,
                peer_collected: 0,
            }
        );
    }

    // ── owner seed ──────────────────────────────────────────────────────────

    /// Two stores holding the same identity secret, peer and generation
    /// derive byte-equal owner seeds, and so the same VLD0 keypair and the
    /// same record. A different generation is a different record.
    #[test]
    fn the_owner_seed_is_deterministic_and_generation_scoped() {
        let secret = [0x31u8; ML_DSA_SEED_LEN];
        let peer = *signer(0x77).public_key();
        let first = derive_owner_seed(&secret, &peer, 0).unwrap();
        let again = derive_owner_seed(&secret, &peer, 0).unwrap();
        assert_eq!(first.as_bytes(), again.as_bytes());

        let next_generation = derive_owner_seed(&secret, &peer, 1).unwrap();
        assert_ne!(first.as_bytes(), next_generation.as_bytes());

        // The controls: a different identity secret and a different peer each
        // move the record too, so the equality above is not one the
        // derivation gives to everything.
        let other_secret = derive_owner_seed(&[0x32u8; ML_DSA_SEED_LEN], &peer, 0).unwrap();
        assert_ne!(first.as_bytes(), other_secret.as_bytes());
        let other_peer = derive_owner_seed(&secret, signer(0x78).public_key(), 0).unwrap();
        assert_ne!(first.as_bytes(), other_peer.as_bytes());
    }

    // ── the ring ────────────────────────────────────────────────────────────

    #[test]
    fn the_ring_hands_out_a_full_window_then_refuses() {
        let mut ring = Ring::new();
        for expected in 0..RING_SLOTS {
            assert_eq!(ring.reserve().unwrap(), expected);
        }
        assert_eq!(ring.uncollected(), RING_SLOTS);

        let before = ring.send_seq();
        let err = ring.reserve().unwrap_err();
        assert_eq!(
            err,
            ChannelError::RingFull {
                send_seq: RING_SLOTS,
                peer_collected: 0,
            }
        );
        assert_eq!(ring.send_seq(), before, "a refusal moved send_seq");

        // One collection admits exactly one more message, and then it is
        // full again.
        ring.advance_peer_collected(1);
        assert_eq!(ring.reserve().unwrap(), RING_SLOTS);
        assert!(matches!(ring.reserve(), Err(ChannelError::RingFull { .. })));
    }

    #[test]
    fn the_peer_cursor_never_moves_backwards_or_past_what_was_sent() {
        let mut ring = Ring::new();
        for _ in 0..10 {
            ring.reserve().unwrap();
        }
        ring.advance_peer_collected(6);
        assert_eq!(ring.peer_collected(), 6);
        ring.advance_peer_collected(3);
        assert_eq!(ring.peer_collected(), 6, "the cursor regressed");
        ring.advance_peer_collected(u64::MAX);
        assert_eq!(
            ring.peer_collected(),
            10,
            "the cursor passed what this direction has written"
        );
        assert_eq!(ring.uncollected(), 0);
    }

    /// A restored state whose cursor exceeds what was sent is impossible, so
    /// it is refused rather than clamped into something plausible.
    #[test]
    fn a_restored_ring_refuses_a_cursor_above_what_was_sent() {
        assert_eq!(
            Ring::restore(10, 11).unwrap_err(),
            ChannelError::CorruptState {
                send_seq: 10,
                peer_collected: 11,
            }
        );
    }

    /// The control, and the property a clamp would have hidden: a legitimate
    /// restore keeps both figures and reserves from where it left off.
    #[test]
    fn a_restored_ring_reserves_from_where_it_left_off() {
        let mut ring = Ring::restore(10, 4).expect("a legitimate state");
        assert_eq!(ring.send_seq(), 10);
        assert_eq!(ring.peer_collected(), 4);
        assert_eq!(ring.uncollected(), 6);
        assert_eq!(ring.reserve().unwrap(), 10);
        assert_eq!(Ring::restore(10, 10).unwrap().uncollected(), 0);
    }

    // ── the message header ──────────────────────────────────────────────────

    #[test]
    fn a_turn_header_round_trips() {
        let header = MessageHeader {
            device_id: DEVICE_ID_SINGLE_DEVICE,
            n: 4,
            m: 3,
            seq: 17,
            cursor: 9,
            kem_ct: Some(Box::new([0x51u8; ml_kem::CT_LEN])),
            kem_pk: Some(Box::new([0x52u8; ml_kem::EK_LEN])),
        };
        let encoded = header.encode();
        let (decoded, rest) = MessageHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert!(decoded.starts_turn());
        assert!(rest.is_empty());
    }

    #[test]
    fn a_continuing_header_round_trips_and_keeps_the_body() {
        let header = MessageHeader::continuing(DEVICE_ID_SINGLE_DEVICE, 4, 3, 18, 9);
        let mut slot = header.encode();
        slot.extend_from_slice(b"the sealed body");
        let (decoded, rest) = MessageHeader::decode(&slot).unwrap();
        assert_eq!(decoded, header);
        assert!(!decoded.starts_turn());
        assert_eq!(rest, b"the sealed body");
    }

    /// One turn field without the other is refused, in both directions.
    #[test]
    fn one_turn_field_without_the_other_is_refused() {
        let only_ct = MessageHeader {
            device_id: 0,
            n: 1,
            m: 0,
            seq: 0,
            cursor: 0,
            kem_ct: Some(Box::new([0x51u8; ml_kem::CT_LEN])),
            kem_pk: None,
        };
        assert_eq!(
            MessageHeader::decode(&only_ct.encode()).unwrap_err(),
            ChannelError::TurnFieldsIncomplete
        );

        let only_pk = MessageHeader {
            device_id: 0,
            n: 1,
            m: 0,
            seq: 0,
            cursor: 0,
            kem_ct: None,
            kem_pk: Some(Box::new([0x52u8; ml_kem::EK_LEN])),
        };
        assert_eq!(
            MessageHeader::decode(&only_pk.encode()).unwrap_err(),
            ChannelError::TurnFieldsIncomplete
        );
    }

    /// **The control for the test above:** a header carrying both fields
    /// decodes, so the refusal is of the incomplete pair and not of the turn
    /// fields as such.
    #[test]
    fn both_turn_fields_together_are_accepted() {
        let both = MessageHeader {
            device_id: 0,
            n: 1,
            m: 0,
            seq: 0,
            cursor: 0,
            kem_ct: Some(Box::new([0x51u8; ml_kem::CT_LEN])),
            kem_pk: Some(Box::new([0x52u8; ml_kem::EK_LEN])),
        };
        assert!(MessageHeader::decode(&both.encode()).is_ok());
    }

    #[test]
    fn a_truncated_header_and_a_wrong_width_field_are_distinct_failures() {
        let header = MessageHeader::continuing(0, 1, 0, 0, 0);
        let encoded = header.encode();
        assert_eq!(
            MessageHeader::decode(&encoded[..encoded.len() - 1]).unwrap_err(),
            ChannelError::Malformed
        );

        // A turn field present at one byte short of its width.
        let mut wrong = Vec::new();
        wrong.extend_from_slice(&0u32.to_be_bytes());
        wrong.extend_from_slice(&1u64.to_be_bytes());
        wrong.extend_from_slice(&0u64.to_be_bytes());
        wrong.extend_from_slice(&0u64.to_be_bytes());
        wrong.extend_from_slice(&0u64.to_be_bytes());
        push_lp(&mut wrong, &[0x51u8; ml_kem::CT_LEN - 1]);
        push_lp(&mut wrong, &[0x52u8; ml_kem::EK_LEN]);
        assert_eq!(
            MessageHeader::decode(&wrong).unwrap_err(),
            ChannelError::FieldLength {
                expected: ml_kem::CT_LEN,
                actual: ml_kem::CT_LEN - 1,
            }
        );
    }

    /// Every clear header field is bound to the body, so changing any one of
    /// them changes the associated data and the body stops opening.
    #[test]
    fn the_message_aad_changes_with_every_header_field() {
        let base = MessageHeader::continuing(1, 2, 3, 4, 5);
        let aad = message_aad(&base);
        assert_eq!(aad, message_aad(&MessageHeader::continuing(1, 2, 3, 4, 5)));

        let mut changed = base.clone();
        changed.device_id = 2;
        assert_ne!(aad, message_aad(&changed), "device_id is not bound");
        let mut changed = base.clone();
        changed.n = 3;
        assert_ne!(aad, message_aad(&changed), "n is not bound");
        let mut changed = base.clone();
        changed.m = 4;
        assert_ne!(aad, message_aad(&changed), "m is not bound");
        let mut changed = base.clone();
        changed.seq = 5;
        assert_ne!(aad, message_aad(&changed), "seq is not bound");
        let mut changed = base.clone();
        changed.cursor = 6;
        assert_ne!(aad, message_aad(&changed), "cursor is not bound");
    }

    /// A header at its largest fits the subkey with room for a body, which is
    /// what [`MESSAGE_BODY_MAX_LEN`] is derived from.
    #[test]
    fn a_full_header_measures_its_stated_maximum() {
        let full = MessageHeader {
            device_id: u32::MAX,
            n: u64::MAX,
            m: u64::MAX,
            seq: u64::MAX,
            cursor: u64::MAX,
            kem_ct: Some(Box::new([0x51u8; ml_kem::CT_LEN])),
            kem_pk: Some(Box::new([0x52u8; ml_kem::EK_LEN])),
        };
        assert_eq!(full.encode().len(), MESSAGE_HEADER_MAX_LEN);
        assert_eq!(
            MESSAGE_BODY_MAX_LEN,
            CHANNEL_SUBKEY_LEN - MESSAGE_HEADER_MAX_LEN - NONCE_LEN - TAG_LEN
        );
    }

    // ── the opening ─────────────────────────────────────────────────────────

    #[test]
    fn an_opening_round_trips_and_verifies() {
        let built = opening(7);
        let decoded = ChannelOpening::decode(&built.encode()).unwrap();
        assert_eq!(decoded, built);
        assert_eq!(decoded.encode().len(), OPENING_LEN);
        assert_eq!(
            decoded.writer_identity_pk.as_slice(),
            signer(0x11).public_key()
        );
        assert_eq!(decoded.recipient_identity_pk.as_slice(), recipient_pk());
        decoded
            .verify(&recipient_pk(), 7)
            .expect("the opening verifies");
    }

    #[test]
    fn a_flipped_signature_byte_fails_verification() {
        let built = opening(7);
        let mut bytes = built.encode();
        bytes[SIGNATURE_AT] ^= 0x01;
        let decoded = ChannelOpening::decode(&bytes).unwrap();
        assert_eq!(
            decoded.verify(&recipient_pk(), 7).unwrap_err(),
            ChannelError::Signature
        );
    }

    /// A relayed hello lands in a channel whose opening names the wrong
    /// advert, and that is its own error — not a signature failure, because
    /// the opening is authentically someone's.
    #[test]
    fn an_opening_naming_another_advert_serial_is_its_own_failure() {
        let built = opening(7);
        assert_eq!(
            built.verify(&recipient_pk(), 8).unwrap_err(),
            ChannelError::AdvertSerial {
                expected: 8,
                found: 7,
            }
        );
    }

    /// An opening addressed to one identity is refused by another, even when
    /// the advert serial matches — a hello relayed to a third party lands in a
    /// channel that names somebody else.
    #[test]
    fn an_opening_addressed_elsewhere_is_refused_by_the_wrong_reader() {
        let built = opening(7);
        let elsewhere = *signer(0x78).public_key();
        assert_eq!(
            built.verify(&elsewhere, 7).unwrap_err(),
            ChannelError::Recipient
        );
        // The control: the identity it IS addressed to accepts it.
        built.verify(&recipient_pk(), 7).expect("its recipient");
    }

    #[test]
    fn a_short_opening_fails_on_length() {
        let bytes = opening(7).encode();
        assert_eq!(
            ChannelOpening::decode(&bytes[..OPENING_LEN - 1]).unwrap_err(),
            ChannelError::Length {
                expected: OPENING_LEN,
                actual: OPENING_LEN - 1,
            }
        );
    }

    // ── the control subkey ──────────────────────────────────────────────────

    #[test]
    fn the_control_subkey_round_trips() {
        let ss = shared_secret(0x11);
        let control = Control {
            opening: Some(opening(7)),
            collected_cursor: 12,
            closed: false,
        };
        let sealed = seal_control(&ss, &control).unwrap();
        let opened = open_control(&ss, &sealed).unwrap();
        assert_eq!(opened, control);
        opened
            .opening
            .unwrap()
            .verify(&recipient_pk(), 7)
            .expect("it verifies");
    }

    #[test]
    fn a_control_subkey_without_an_opening_round_trips() {
        let ss = shared_secret(0x11);
        let control = Control {
            opening: None,
            collected_cursor: 0,
            closed: true,
        };
        let sealed = seal_control(&ss, &control).unwrap();
        assert_eq!(open_control(&ss, &sealed).unwrap(), control);
    }

    #[test]
    fn another_shared_secret_does_not_open_the_control_subkey() {
        let sealed = seal_control(
            &shared_secret(0x11),
            &Control {
                opening: Some(opening(7)),
                collected_cursor: 12,
                closed: false,
            },
        )
        .unwrap();
        assert_eq!(
            open_control(&shared_secret(0x77), &sealed).unwrap_err(),
            ChannelError::Aead
        );
    }

    /// FC5 — a storage node holding the record cannot tell which two
    /// identities are talking. The writer's identity public key is inside the
    /// opening, and the opening is inside the seal.
    #[test]
    fn the_writer_identity_key_appears_in_no_byte_of_the_sealed_control_subkey() {
        let ss = shared_secret(0x11);
        let built = opening(7);
        let key = built.writer_identity_pk.clone();
        let sealed = seal_control(
            &ss,
            &Control {
                opening: Some(built.clone()),
                collected_cursor: 12,
                closed: false,
            },
        )
        .unwrap();
        assert!(
            !sealed.windows(key.len()).any(|w| w == key.as_slice()),
            "the writer's identity key appears in the sealed control subkey"
        );
        assert!(
            !sealed.windows(32).any(|w| w == &key[..32]),
            "the first 32 bytes of the writer's identity key appear in the sealed control subkey"
        );

        // The control: it DOES appear in the opening's plaintext, so the
        // search above is a search that can find this key.
        let plaintext = built.encode();
        assert!(plaintext.windows(key.len()).any(|w| w == key.as_slice()));
        assert!(plaintext.windows(32).any(|w| w == &key[..32]));
    }

    #[test]
    fn a_malformed_control_record_is_refused() {
        // A flag byte that is neither zero nor one.
        let mut bytes = Control {
            opening: None,
            collected_cursor: 3,
            closed: false,
        }
        .encode();
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert_eq!(
            Control::decode(&bytes).unwrap_err(),
            ChannelError::Malformed
        );

        // Trailing bytes past the flag.
        let mut trailing = Control {
            opening: None,
            collected_cursor: 3,
            closed: false,
        }
        .encode();
        trailing.push(0);
        assert_eq!(
            Control::decode(&trailing).unwrap_err(),
            ChannelError::Malformed
        );

        // The control: the unmodified encoding decodes.
        assert!(
            Control::decode(
                &Control {
                    opening: None,
                    collected_cursor: 3,
                    closed: false,
                }
                .encode()
            )
            .is_ok()
        );
    }

    /// **Known-answer vectors, computed outside this crate from the preimages
    /// the functions above document.** Structural tests cannot see a change
    /// that is uniformly wrong — an edited label, a dropped length prefix, a
    /// transposed field — because both sides of a round trip move together;
    /// two implementations that disagree here address different records and
    /// cannot read each other's control subkeys.
    ///
    /// The synthetic public keys are deliberate: an ML-DSA-87 public key
    /// cannot be computed outside this crate, so a vector built from a real
    /// one could not come from an independent oracle.
    #[test]
    fn known_answer_owner_seed_aad_and_opening_preimage() {
        module();
        let seed = [0x31u8; ML_DSA_SEED_LEN];
        let peer = [0x67u8; ml_dsa::PK_LEN];
        assert_eq!(
            hex::encode(derive_owner_seed(&seed, &peer, 7).unwrap().as_bytes()),
            KAT_OWNER_SEED
        );
        assert_eq!(hex::encode(control_aad()), KAT_CONTROL_AAD);
        let preimage = opening_signing_input(
            &[0x66u8; ml_dsa::PK_LEN],
            &peer,
            &[0x22u8; ml_kem::EK_LEN],
            7,
        );
        assert_eq!(preimage.len(), KAT_OPENING_PREIMAGE_LEN);
        assert_eq!(
            hex::encode(oxicrypt_sha::sha384(&preimage).unwrap()),
            KAT_OPENING_PREIMAGE_SHA384
        );
    }

    /// `derive_owner_seed` over an identity seed of 32 `0x31` bytes, a peer
    /// public key of 2592 `0x67` bytes and generation 7.
    const KAT_OWNER_SEED: &str = "298b040277b2d86e07e952111f5cf70639cd9cc74a523c7eeb0da67c064017bf";

    /// `control_aad()`, which takes no inputs: the label and the
    /// length-prefixed control subkey number.
    const KAT_CONTROL_AAD: &str = "6461656d6f6e736565642f646d2f6368616e6e656c2f636f6e74726f6c2d6161642f7631000000000000000400000000";

    /// Bytes `opening_signing_input` produces for the vector below. Pinned
    /// alongside the digest because a preimage of the wrong length is the one
    /// corruption a digest comparison cannot describe.
    const KAT_OPENING_PREIMAGE_LEN: usize = 6828;

    /// SHA-384 of `opening_signing_input` over a writer key of 2592 `0x66`
    /// bytes, a recipient key of 2592 `0x67` bytes, a ratchet key of 1568
    /// `0x22` bytes and advert serial 7 — the digest rather than the preimage,
    /// which is 6828 bytes of mostly repeated input.
    const KAT_OPENING_PREIMAGE_SHA384: &str = "052afcb47cee443eb7952cbf8e27d6256b321fcda52846e2a608928d0aeee41d11e68590e19e434fd53176adb6e35ef2";

    /// The crypto module has to be operational before any SHA or ML-DSA call.
    fn module() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }
}
