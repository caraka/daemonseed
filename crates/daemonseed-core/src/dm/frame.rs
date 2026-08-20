//! The ongoing-channel wire frame — one message on an established conversation
//! (ISC-C42 / ISC-A-C20 / ISC-A-C21 / ISC-A-C22).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § The ongoing channel & ratchet, § v4 (crypto V8), § v6 minor invariant (a).
//!
//! This module is the seam between the ratchet ([`crate::dm::ratchet`], which
//! decides *which key*) and the page record ([`crate::dm::paging`], which decides
//! *which slot*). It owns exactly what goes on the wire between them: the clear
//! ratchet header, the sealed body, and the two deterministic preimages that bind
//! one to the other.
//!
//! ## What is in the clear, and why that is the whole list
//!
//! A receiver cannot derive a message key until it knows which chain position the
//! frame occupies and — across a generation boundary — which ciphertext re-rooted
//! the ratchet. Those, and the sender's current ephemeral, are therefore clear.
//! Everything else is sealed. In particular a channel frame carries **no identity,
//! no pseudonym key and no signature in the clear**: both parties learned each
//! other's keys at first contact and hold them in the contact cache.
//!
//! What a page co-host does still learn, stated honestly rather than waved at:
//! `eph_ek` and `eph_ct` are byte-identical across every frame of a generation, so
//! the frames group into exact generation boundaries — i.e. conversational turns —
//! with no key at all; and `eph_ct` being absent makes the opening burst about
//! 1571 bytes shorter than every later frame, so it is distinguishable regardless
//! of padding bucket. Neither leaks content or identity, and both fold into the
//! accepted F1 rhythm-linkage residual — but "opaque bytes and nothing more" would
//! be an overclaim.
//!
//! The clear fields are not therefore unprotected. Every one is bound in the
//! seal's AAD, so a header edited in flight fails the AEAD open *before* the
//! ratchet is asked to move; and every one is bound again in `msg_sig` inside the
//! seal, so a party that opens a frame can prove who wrote it.
//!
//! ## `msg_sig` is mandatory here, and the reason is easy to get wrong
//!
//! Page owner-write authority is **symmetric** — both parties derive the owner
//! seed for both directions — so finding a frame in the `a2b` pages establishes
//! that *one of the two parties* wrote it, never which. Only `msg_sig` under the
//! sender's pseudonym key establishes authorship, and after the `bind_pop` fold it
//! is the sole proof-of-possession path in the whole feature. [`ParsedFrame::open`]
//! verifies it unconditionally; there is no variant that skips it.
//!
//! ## Sealing and opening are deliberately two steps
//!
//! [`ParsedFrame::open`] takes a message key rather than a ratchet, because the
//! ratchet must not commit any state for a frame that fails to authenticate. The
//! caller wires the two together by handing this module's open to
//! [`crate::dm::ratchet::Ratchet::receive`] as its closure:
//!
//! ```ignore
//! let parsed = frame::parse(&bytes)?;
//! let verified = ratchet.receive(
//!     parsed.header(),
//!     parsed.eph_ct(),
//!     parsed.eph_ek(),
//!     |mk| parsed.open(mk, &chan_id, dir, found_at, &rcpt_hash, author),
//! )??;
//! ```
//!
//! `found_at` is the [`crate::dm::paging::PagePosition`] the bytes were read from
//! — the collector's own knowledge, not the frame's claim about itself. The outer
//! `Result` is the ratchet's (it refused the position); the inner one is this
//! module's (the frame did not authenticate). They are different failures and a
//! caller should not flatten them.

use oxicrypt_aes::Aes256Key;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use prost::Message;
use zeroize::Zeroize;

use daemonseed_proto::v1 as wire;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::dm::firstcontact::{DM_BODY_CAP, RECIPIENT_HASH_LEN, ROOT_LEN, msg_sig_input};
use crate::dm::paging::PagePosition;
use crate::dm::ratchet::{Direction, FrameHeader, MessageKey, Outbound};
use crate::dm::{LEN_PREFIX, domain, push_lp};
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};

/// The frame-kind label bound into an ongoing-channel authorship signature.
///
/// Distinct from [`crate::dm::firstcontact::FRAME_KIND_FIRST_CONTACT`] because the
/// two shapes sign different things over the same conversation: without the
/// discriminator a first-contact signature would be a byte-valid channel signature
/// for the same `(chan_id, dir, seq)` tuple.
pub const FRAME_KIND_CHANNEL: &[u8] = b"msg";

/// The plaintext padding ladder for a channel frame.
///
/// Sized so the smaller rung holds a typical short message with its 4627-byte
/// signature, and the larger holds a [`DM_BODY_CAP`] body — see
/// `worst_case_frame_fits_a_page_subkey`, which pins the whole chain of arithmetic
/// against the record shape rather than leaving it to comment.
pub const PAD_BUCKETS: &[usize] = &[8192, 16384];

/// Largest encoded frame a channel page slot accepts.
///
/// This is the `dflt(16)` subkey cap — `min(MAX_SUBKEY_SIZE, MAX_RECORD_DATA_SIZE
/// / 16) = min(32768, 65536) = 32768` — the same schema-derived bound ISC-C100
/// makes every write guard use.
///
/// **It is an invariant here, not a runtime check.** [`DM_BODY_CAP`] and the top
/// rung of [`PAD_BUCKETS`] together bound a sealed frame well below it, so a
/// compose-time rejection is unreachable by construction: a `if len >
/// MAX_FRAME_LEN` branch in [`seal`] could never be taken, and a guard that cannot
/// fire is worse than none — it reads as protection that is not there. The
/// invariant is enforced instead by `worst_case_frame_fits_a_page_subkey`, which
/// drives the real [`seal`] with a maximal body and measures the result, so
/// raising either constant without re-checking the fit fails the build.
pub const MAX_FRAME_LEN: usize = 32768;

/// The largest frame [`seal`] can actually produce, measured rather than derived.
///
/// **[`MAX_FRAME_LEN`] is the wrong number to size storage against**, and that is
/// not a subtlety — it is the schema's subkey cap, which the doc above says
/// `seal` can never reach. Sizing a bucket against it undercounts how many real
/// frames fit by a third, and sizing against a guessed "typical" frame overcounts
/// wildly in the other direction, because [`PAD_BUCKETS`] means **no frame is
/// ever small**: the floor is the lower rung plus overhead, not a few hundred
/// bytes.
///
/// `worst_case_frame_fits_a_page_subkey` pins this exactly, so a change to
/// [`PAD_BUCKETS`], [`DM_BODY_CAP`], the signature suite or the header fails that
/// test rather than silently shifting every capacity derived from it —
/// [`crate::storage::dm_store::OUTBOX_CAPACITY`] being the one that matters.
pub const WORST_CASE_SEALED_FRAME_LEN: usize = 19_560;

/// Anything that can go wrong sealing or opening a channel frame.
#[derive(Debug)]
pub enum DmFrameError {
    /// The AES key could not be initialised from the ratchet message key — a
    /// crypto-module condition, never an adversary.
    Module(oxicrypt_module::Error),
    /// A local signing operation failed while SEALING. Carries the cause: there is
    /// no adversary on this path, and a policy refusal reported as "signature did
    /// not verify" would send a reader hunting for tampering that never happened.
    Signing(SignatureError),
    /// AEAD open failed. This is the uniform authentication failure — wrong key,
    /// wrong AAD, a tampered header, a tampered ciphertext or a truncated envelope
    /// are indistinguishable, deliberately (ISC-A-C18).
    ///
    /// Reserved for the OPEN path. A seal-side AEAD fault is [`Self::Sealing`],
    /// because there is no adversary while composing and reporting a local
    /// crypto-module fault as an authentication failure would send a reader
    /// hunting for tampering that never happened.
    Aead,
    /// The AEAD seal failed while composing — a local crypto-module condition.
    Sealing(oxicrypt_aes::ModeError),
    /// The frame declares a sequence number other than the one belonging to the
    /// slot it was read from. Only the collector holds both facts, so only the
    /// collector can catch it.
    Misplaced { declared: u64, found_at: u64 },
    /// The authorship signature did not verify. Uniform for the same reason.
    Signature,
    /// The bytes are not a decodable frame or body.
    Malformed,
    /// A length-gated field was absent or the wrong size, so a truncation is
    /// diagnosable rather than surfacing later as a wrong key.
    FieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// A body exceeds [`DM_BODY_CAP`], on either side, or an encoded body exceeds
    /// the top rung of [`PAD_BUCKETS`]. `max` names which bound was hit.
    ///
    /// Deliberately NOT the [`MAX_FRAME_LEN`] bound: that one is an invariant with
    /// no runtime check, so naming it here would describe a rejection that never
    /// happens — see [`MAX_FRAME_LEN`].
    TooLarge { got: usize, max: usize },
    /// The OS entropy source failed while drawing a nonce.
    EntropySource,
}

impl std::fmt::Display for DmFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module(e) => write!(f, "crypto module unavailable: {e:?}"),
            Self::Signing(e) => write!(f, "could not sign the channel frame: {e}"),
            Self::Aead => write!(f, "the channel frame did not open"),
            Self::Sealing(e) => write!(f, "could not seal the channel frame: {e:?}"),
            Self::Misplaced { declared, found_at } => write!(
                f,
                "the frame declares sequence {declared} but sits at {found_at}"
            ),
            Self::Signature => write!(f, "signature verification failed"),
            Self::Malformed => write!(f, "not a decodable channel frame"),
            Self::FieldLength {
                field,
                expected,
                actual,
            } => write!(f, "{field} must be {expected} bytes, got {actual}"),
            Self::TooLarge { got, max } => write!(f, "frame is {got} bytes, cap is {max}"),
            Self::EntropySource => write!(f, "the entropy source failed"),
        }
    }
}

impl std::error::Error for DmFrameError {}

/// Open-path mapping only: every non-entropy failure collapses to the uniform
/// authentication error. The seal path maps its own errors explicitly (see
/// [`DmFrameError::Aead`]), which is a deliberate divergence from
/// `firstcontact`'s single blanket `From` — the sibling folds a local encrypt
/// fault into "did not open" too, which is worth fixing there separately rather
/// than copying here.
impl From<EnvelopeError> for DmFrameError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_) => Self::EntropySource,
            _ => Self::Aead,
        }
    }
}

/// The sender's two public keys, as the signature preimage binds them.
///
/// A struct rather than two adjacent `&[u8; PK_LEN]` parameters, because
/// transposing them compiles: the pseudonym and the long-term key are the same
/// type and the same length. A collector that swapped them would derive a
/// different preimage and reject every message of a conversation forever with
/// [`DmFrameError::Signature`] — the error this module's docs reserve for
/// tampering, which is precisely the wrong place to send someone debugging their
/// own wiring. Same reasoning as `ratchet::DeliveryLosses`, which exists because
/// three bare counts would be transposable at the call site.
#[derive(Clone, Copy)]
pub struct AuthorKeys<'a> {
    /// The per-contact pseudonym key that signs this conversation.
    pub pc: &'a [u8; ml_dsa::PK_LEN],
    /// The long-term identity key the pseudonym is bound to.
    pub lt: &'a [u8; ml_dsa::PK_LEN],
}

/// The preimage for a channel frame's authorship signature, signed under the
/// PSEUDONYM key.
///
/// The first ten components are [`msg_sig_input`]'s, under this module's frame
/// kind, so the two frame types share one definition of what an authorship
/// signature covers. Three more follow, each length-prefixed: the generation, the
/// chain base, and the generation ciphertext.
///
/// Those three are the frozen design's `(ratchet_gen, PN)` header plus § v6 minor
/// invariant (a). They are already bound in the AAD, so binding them again is
/// belt-and-braces — but the two bindings answer different questions. The AAD
/// proves the header was not edited between sealing and opening; the signature
/// proves the *sender* chose it, which is what stops a party who holds the message
/// key (there are only two, but a compromised one is the threat) from re-filing an
/// authentic body at a different ratchet position.
///
/// An absent `eph_ct` is bound as a zero-length component rather than skipped, so
/// "no ciphertext" and "empty ciphertext" cannot produce the same preimage.
#[allow(clippy::too_many_arguments)]
pub fn frame_sig_input(
    chan_id: &[u8; ROOT_LEN],
    dir: Direction,
    header: &FrameHeader,
    eph_ek: &[u8; ml_kem::EK_LEN],
    eph_ct: Option<&[u8; ml_kem::CT_LEN]>,
    recipient_hash: &[u8; RECIPIENT_HASH_LEN],
    author: AuthorKeys<'_>,
    sent_unix_ms: i64,
    body: &str,
) -> Vec<u8> {
    let mut buf = msg_sig_input(
        FRAME_KIND_CHANNEL,
        chan_id,
        dir.label(),
        header.seq,
        eph_ek,
        recipient_hash,
        author.pc,
        author.lt,
        sent_unix_ms,
        body,
    );
    push_lp(&mut buf, &u64::from(header.generation).to_be_bytes());
    push_lp(&mut buf, &header.chain_base.to_be_bytes());
    push_lp(&mut buf, eph_ct.map_or(&[][..], |ct| &ct[..]));
    buf
}

/// The AAD binding a sealed body to every clear field of its frame.
///
/// `chan_id` leads it and is **never serialized** — a receiver recomputes it from
/// the record it derived — so the AAD also binds the frame to the one conversation
/// whose address root produced the page it sits in.
fn frame_aad(
    chan_id: &[u8; ROOT_LEN],
    dir: Direction,
    header: &FrameHeader,
    eph_ek: &[u8; ml_kem::EK_LEN],
    eph_ct: Option<&[u8; ml_kem::CT_LEN]>,
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(domain::DM_MSG_AAD.len() + ml_kem::EK_LEN + ml_kem::CT_LEN + 96);
    aad.extend_from_slice(domain::DM_MSG_AAD);
    push_lp(&mut aad, chan_id);
    push_lp(&mut aad, dir.label());
    push_lp(&mut aad, &u64::from(header.generation).to_be_bytes());
    push_lp(&mut aad, &header.chain_base.to_be_bytes());
    push_lp(&mut aad, &header.seq.to_be_bytes());
    push_lp(&mut aad, eph_ek);
    push_lp(&mut aad, eph_ct.map_or(&[][..], |ct| &ct[..]));
    aad
}

fn aes_key(key: &MessageKey) -> Result<Aes256Key, DmFrameError> {
    Aes256Key::new(key.as_bytes()).map_err(DmFrameError::Module)
}

fn exact<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], DmFrameError> {
    bytes.try_into().map_err(|_| DmFrameError::FieldLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

/// Seal one outbound message into the bytes a page slot carries.
///
/// The ratchet has already chosen the key and the position; everything this
/// function adds is the wire shape around them. `pk_lt` is the sender's own
/// long-term public key — carried in the signature preimage but never on the wire,
/// because the recipient already holds it from first contact and re-stating it
/// would re-identify the sender to a page co-host.
///
/// **`outbound` is taken BY VALUE, and that is load-bearing.** A ratchet message
/// key is single-use: `send_next` has already advanced the sending sequence when
/// it handed this one over, so the natural way to retry a failed page write is to
/// re-seal the `Outbound` still in hand — which would mint a second, independently
/// authentic frame at the same `(generation, chain_base, seq)` with a different
/// body. The receiver opens whichever arrives first, destroys the key, and reports
/// the other as [`DmFrameError::Aead`], i.e. as tampering. Consuming the value
/// makes that a compile error, the same way `ratchet::chain_step` consumes the
/// chain key it steps. **To retry a write, keep the sealed BYTES and re-emit them
/// unchanged** — which is what the frozen design's re-seed rule requires anyway.
pub fn seal(
    outbound: Outbound,
    chan_id: &[u8; ROOT_LEN],
    signing_pc: &SignKeypair,
    pk_lt: &[u8; ml_dsa::PK_LEN],
    recipient_hash: &[u8; RECIPIENT_HASH_LEN],
    sent_unix_ms: i64,
    body: &str,
) -> Result<Vec<u8>, DmFrameError> {
    if body.len() > DM_BODY_CAP {
        return Err(DmFrameError::TooLarge {
            got: body.len(),
            max: DM_BODY_CAP,
        });
    }

    let eph_ct = outbound.eph_ct.as_deref();
    // The preimage embeds the plaintext body verbatim, so it is cleared rather
    // than dropped intact (#135).
    let mut preimage = frame_sig_input(
        chan_id,
        outbound.direction,
        &outbound.header,
        &outbound.eph_ek,
        eph_ct,
        recipient_hash,
        AuthorKeys {
            pc: signing_pc.public_key(),
            lt: pk_lt,
        },
        sent_unix_ms,
        body,
    );
    let signed = signing_pc.sign(&preimage);
    preimage.zeroize();
    let msg_sig = signed.map_err(DmFrameError::Signing)?;

    // Bound to a name rather than encoded from a temporary: the struct owns a
    // second heap copy of the plaintext, and a temporary would be dropped — and
    // its buffer freed — without ever being zeroized, defeating the two
    // `zeroize()` calls below (#135).
    let mut plain = wire::DmChannelBody {
        sent_unix_ms,
        body: body.to_owned(),
        msg_sig: msg_sig.to_vec(),
    };
    let mut encoded = plain.encode_to_vec();
    plain.body.zeroize();
    let mut padded =
        crate::dm::pad_to_bucket(&encoded, PAD_BUCKETS).ok_or(DmFrameError::TooLarge {
            got: LEN_PREFIX.saturating_add(encoded.len()),
            max: *PAD_BUCKETS.last().expect("ladder is never empty"),
        })?;
    encoded.zeroize();

    let sealed = seal_envelope(
        &aes_key(&outbound.key)?,
        &frame_aad(
            chan_id,
            outbound.direction,
            &outbound.header,
            &outbound.eph_ek,
            eph_ct,
        ),
        &padded,
    );
    padded.zeroize();
    // Mapped explicitly rather than through the blanket `From`: on this path there
    // is no adversary, so an encrypt fault is a module condition, not tampering.
    let sealed = sealed.map_err(|e| match e {
        EnvelopeError::EntropySource(_) => DmFrameError::EntropySource,
        EnvelopeError::Encrypt(m) | EnvelopeError::Decrypt(m) => DmFrameError::Sealing(m),
        _ => DmFrameError::Sealing(oxicrypt_aes::ModeError::TagMismatch),
    })?;

    let frame = wire::DmChannelFrame {
        ratchet_gen: outbound.header.generation,
        chain_base: outbound.header.chain_base,
        seq: outbound.header.seq,
        eph_ek: outbound.eph_ek.to_vec(),
        eph_ct: eph_ct.map(|ct| ct.to_vec()).unwrap_or_default(),
        sealed,
    }
    .encode_to_vec();

    // An invariant, not a check — see [`MAX_FRAME_LEN`]. The body cap and the
    // padding ladder bound this by construction, so a runtime rejection here could
    // never fire; the debug assertion states the invariant without pretending to
    // enforce a condition that cannot occur.
    debug_assert!(
        frame.len() <= MAX_FRAME_LEN,
        "the padding ladder must keep every frame inside the page subkey cap"
    );
    Ok(frame)
}

/// A decoded frame whose clear header is well-formed. **Nothing here is
/// authenticated yet** — the type exists so a caller can reach the ratchet, which
/// is the only thing that can produce the key that authenticates it.
pub struct ParsedFrame {
    header: FrameHeader,
    eph_ek: Box<[u8; ml_kem::EK_LEN]>,
    eph_ct: Option<Box<[u8; ml_kem::CT_LEN]>>,
    sealed: Vec<u8>,
}

impl std::fmt::Debug for ParsedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedFrame")
            .field("header", &self.header)
            .field("has_eph_ct", &self.eph_ct.is_some())
            .field("sealed_len", &self.sealed.len())
            .finish()
    }
}

impl ParsedFrame {
    /// The ratchet position this frame CLAIMS.
    ///
    /// Claimed, never proven. [`Self::open`] proves that the sender chose these
    /// values — it cannot prove the frame was found where they say it should be.
    /// That is [`Self::open`]'s `found_at` argument, and it is a separate fact.
    pub fn header(&self) -> &FrameHeader {
        &self.header
    }

    /// The sender's current ephemeral, for the receiver's next generation step.
    pub fn eph_ek(&self) -> &[u8; ml_kem::EK_LEN] {
        &self.eph_ek
    }

    /// The ciphertext that created this generation, absent in the opening burst.
    pub fn eph_ct(&self) -> Option<&[u8; ml_kem::CT_LEN]> {
        self.eph_ct.as_deref()
    }

    /// Open and verify under a ratchet message key.
    ///
    /// Three independent checks, all mandatory. The AEAD open binds every clear
    /// field via the AAD, so a tampered header cannot reach the ratchet as an
    /// authenticated position. The authorship signature under `author.pc` is the
    /// only thing that establishes *who* wrote it — page owner-write authority is
    /// symmetric, so the address never does. And `found_at` binds the frame to the
    /// slot it was actually read from.
    ///
    /// ## Why `found_at` is a parameter and not a caller's good intention
    ///
    /// `seq` addresses the page and slot a message occupies, and the write-once
    /// mapping between the two is what makes the ack's contiguous prefix and the
    /// page-probe frontier mean anything. But `seq` arrives *inside the frame*,
    /// chosen by the peer. A peer that signs `seq = 5` and writes the bytes into
    /// the slot for `seq = 100` produces a frame that opens, verifies, and is filed
    /// at a position it does not occupy — so the two pointers disagree with the
    /// record and nothing anywhere says so. Only the collector holds both facts, so
    /// only the collector can check, and the frozen build contract's own rule is
    /// that an obligation like this must be structural rather than documentary.
    /// Requiring the position here is what makes skipping it impossible.
    pub fn open(
        &self,
        key: &MessageKey,
        chan_id: &[u8; ROOT_LEN],
        dir: Direction,
        found_at: PagePosition,
        recipient_hash: &[u8; RECIPIENT_HASH_LEN],
        author: AuthorKeys<'_>,
    ) -> Result<VerifiedFrame, DmFrameError> {
        if found_at.seq() != self.header.seq {
            return Err(DmFrameError::Misplaced {
                declared: self.header.seq,
                found_at: found_at.seq(),
            });
        }

        let mut plaintext = open_envelope(
            &aes_key(key)?,
            &frame_aad(chan_id, dir, &self.header, &self.eph_ek, self.eph_ct()),
            &self.sealed,
        )?;

        let decoded = crate::dm::unpad(&plaintext)
            .ok_or(DmFrameError::Malformed)
            .and_then(|encoded| {
                wire::DmChannelBody::decode(encoded).map_err(|_| DmFrameError::Malformed)
            });
        plaintext.zeroize();
        let mut body = decoded?;

        // Every path below this point holds the peer's cleartext, so each one
        // clears it before returning rather than dropping the `String` intact
        // (#135) — including the two error returns, which are reachable by a
        // non-conforming peer that already holds the message key.
        let verdict = self.verify(&body, chan_id, dir, recipient_hash, author);
        if verdict.is_err() {
            body.body.zeroize();
            verdict?;
        }

        Ok(VerifiedFrame {
            seq: self.header.seq,
            sent_unix_ms: body.sent_unix_ms,
            body: body.body,
        })
    }

    /// The post-decryption half of [`Self::open`]: the body cap a non-conforming
    /// peer can exceed, and the authorship signature.
    fn verify(
        &self,
        body: &wire::DmChannelBody,
        chan_id: &[u8; ROOT_LEN],
        dir: Direction,
        recipient_hash: &[u8; RECIPIENT_HASH_LEN],
        author: AuthorKeys<'_>,
    ) -> Result<(), DmFrameError> {
        // The sender's own cap is enforced in `seal`; a peer is under no obligation
        // to respect it, so it is re-checked here or an over-cap body reaches the UI.
        if body.body.len() > DM_BODY_CAP {
            return Err(DmFrameError::TooLarge {
                got: body.body.len(),
                max: DM_BODY_CAP,
            });
        }
        let msg_sig: [u8; ml_dsa::SIG_LEN] = exact("msg_sig", &body.msg_sig)?;

        let mut preimage = frame_sig_input(
            chan_id,
            dir,
            &self.header,
            &self.eph_ek,
            self.eph_ct(),
            recipient_hash,
            author,
            body.sent_unix_ms,
            &body.body,
        );
        let verified = verify_signature(author.pc, &preimage, &msg_sig);
        preimage.zeroize();
        verified.map_err(|_| DmFrameError::Signature)
    }
}

/// Decode the clear half of a frame, gating every length-fixed field.
///
/// A page is owner-write-gated, so arbitrary bytes in a slot mean a peer wrote
/// something malformed rather than a stranger writing anything at all — but it is
/// still rejected here rather than surfacing later as a wrong key.
pub fn parse(encoded: &[u8]) -> Result<ParsedFrame, DmFrameError> {
    let frame = wire::DmChannelFrame::decode(encoded).map_err(|_| DmFrameError::Malformed)?;
    let eph_ek: [u8; ml_kem::EK_LEN] = exact("eph_ek", &frame.eph_ek)?;
    let eph_ct = if frame.eph_ct.is_empty() {
        None
    } else {
        Some(Box::new(exact::<{ ml_kem::CT_LEN }>(
            "eph_ct",
            &frame.eph_ct,
        )?))
    };

    Ok(ParsedFrame {
        header: FrameHeader {
            generation: frame.ratchet_gen,
            chain_base: frame.chain_base,
            seq: frame.seq,
        },
        eph_ek: Box::new(eph_ek),
        eph_ct,
        sealed: frame.sealed,
    })
}

/// A frame whose seal opened and whose authorship signature verified. Only
/// constructible via [`ParsedFrame::open`], so holding one IS the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFrame {
    /// The position it occupies. Taken from the header rather than the body, and
    /// checked against the slot the frame was read from — both facts, not one.
    pub seq: u64,
    /// Sender-asserted and signed. Display only.
    pub sent_unix_ms: i64,
    /// The message.
    pub body: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::firstcontact::{FRAME_KIND_FIRST_CONTACT, recipient_hash};
    use crate::dm::paging::{PAGE_SLOTS, position_of};
    use crate::dm::ratchet::{EphemeralDecapKey, Ratchet, Role};
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;
    use oxicrypt_sha::sha384;

    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";
    const PHRASE_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                            zoo zoo zoo zoo zoo zoo zoo vote";
    const SENT: i64 = 1_700_000_000_000;
    const SS0: [u8; 32] = [7u8; 32];

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

    /// An edit applied to an encoded frame before it is re-parsed and attacked.
    type Mutation = Box<dyn Fn(&mut wire::DmChannelFrame)>;

    fn header() -> FrameHeader {
        FrameHeader {
            generation: 0x0102_0304,
            chain_base: 0x1112_1314_1516_1718,
            seq: 0x2122_2324_2526_2728,
        }
    }

    fn eph_keypair(d: u8, z: u8) -> (Box<[u8; ml_kem::EK_LEN]>, EphemeralDecapKey) {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let (ek, dk) = ml_kem::keygen(&[d; 32], &[z; 32]).unwrap();
        (Box::new(ek), EphemeralDecapKey::new(Box::new(dk)))
    }

    /// A live conversation: the initiator's ratchet, the recipient's ratchet, and
    /// the identity keys of both ends.
    struct Pair {
        a: IdentityKeys,
        b: IdentityKeys,
        a_pc: IdentityKeys,
        init: Ratchet,
        recip: Ratchet,
    }

    fn pair() -> Pair {
        let (ek, dk) = eph_keypair(5, 6);
        let init = Ratchet::initiator(&SS0, ek.clone(), dk).unwrap();
        let recip = Ratchet::recipient(&SS0, ek).unwrap();
        assert_eq!(init.role(), Role::Initiator);
        Pair {
            a: alice(),
            b: bob(),
            // The per-contact pseudonym is a random key in production; a second
            // derived identity stands in for it here.
            a_pc: keys(PHRASE_B),
            init,
            recip,
        }
    }

    /// A sequence number whose page, slot and sequence are three DIFFERENT
    /// numbers: page 3, slot 9, sequence 57.
    ///
    /// On page 0 a slot index *is* its own sequence number, so a page-0 fixture
    /// cannot tell the two apart: a mutant that reads `found_at.slot()` where
    /// [`ParsedFrame::open`] reads `found_at.seq()` passes it, and since the
    /// misfiling check below is the only coverage of that binding anywhere, such a
    /// mutant would have nothing standing in its way (#272). Every fixture here
    /// that exercises the slot-to-sequence binding uses this sequence instead, so
    /// substituting any one of the three numbers for another is caught.
    const DISTINCT_SEQ: u64 = 3 * PAGE_SLOTS as u64 + 9;

    /// Burn frames from `r` until the next one it seals will carry `seq`.
    ///
    /// A ratchet has no "what sequence number comes next" accessor, so the frames
    /// in between are produced and dropped rather than inspected. That is only
    /// sound for a receiver that tolerates the resulting gap: the skip stays under
    /// [`crate::dm::ratchet::MAX_SKIP`], which is what lets the far end catch up in
    /// one `receive`.
    fn advance_send_to(r: &mut Ratchet, seq: u64) {
        loop {
            let out = r.send_next().expect("the chain advances");
            assert!(
                out.header.seq < seq,
                "the ratchet is already at or past sequence {seq}, so this fixture \
                 cannot reach it"
            );
            if out.header.seq + 1 == seq {
                return;
            }
        }
    }

    impl Pair {
        /// Seal one message from the initiator, addressed to the recipient.
        fn send(&mut self, body: &str) -> Vec<u8> {
            self.send_keyed(body).0
        }

        /// As [`Self::send`], but also hands back the message key the sender used.
        /// Attacks on the seal want the honest key in hand, so that "the AAD
        /// rejected it" is not conflated with "the ratchet refused the position".
        fn send_keyed(&mut self, body: &str) -> (Vec<u8>, MessageKey) {
            let out = self.init.send_next().unwrap();
            let key = out.key.clone();
            let bytes = seal(
                out,
                &[1u8; ROOT_LEN],
                &self.a_pc.signing,
                self.a.signing.public_key(),
                &recipient_hash(self.b.signing.public_key()).unwrap(),
                SENT,
                body,
            )
            .unwrap();
            (bytes, key)
        }

        /// Drive the recipient's ratchet over a frame, exactly as the collector
        /// will — including the outer `RatchetError`, which a caller sees whenever
        /// the ratchet refuses a position before `open` is ever reached.
        fn recv_raw(
            &mut self,
            bytes: &[u8],
        ) -> Result<Result<VerifiedFrame, DmFrameError>, crate::dm::ratchet::RatchetError> {
            let parsed = parse(bytes).unwrap();
            let dir = self.recip.recv_direction();
            let author = AuthorKeys {
                pc: self.a_pc.signing.public_key(),
                lt: self.a.signing.public_key(),
            };
            let rcpt = recipient_hash(self.b.signing.public_key()).unwrap();
            let at = position_of(parsed.header().seq);
            self.recip
                .receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |mk| {
                    parsed.open(mk, &[1u8; ROOT_LEN], dir, at, &rcpt, author)
                })
        }

        fn recv(&mut self, bytes: &[u8]) -> Result<VerifiedFrame, DmFrameError> {
            self.recv_raw(bytes).unwrap()
        }
    }

    /// The two deterministic preimages are an INTEROP CONTRACT: a second
    /// implementation that orders a field differently, or writes an integer
    /// little-endian, produces signatures and AADs this one rejects — while every
    /// round-trip test here stays green, because both halves would drift together.
    ///
    /// Every integer below has distinct bytes in each position, so an endianness
    /// flip cannot survive. Captured from this implementation once reviewed; they
    /// guard drift, not first correctness.
    #[test]
    fn deterministic_preimages_match_their_known_answer_vectors() {
        let a = alice();
        let b = bob();
        let (eph_ek, _) = eph_keypair(5, 6);
        let ct = Box::new([9u8; ml_kem::CT_LEN]);

        let sig_input = sha384(&frame_sig_input(
            &[1u8; ROOT_LEN],
            Direction::AToB,
            &header(),
            &eph_ek,
            Some(&ct),
            &[2u8; RECIPIENT_HASH_LEN],
            AuthorKeys {
                pc: a.signing.public_key(),
                lt: b.signing.public_key(),
            },
            0x0a0b_0c0d_0e0f_1011,
            "ab",
        ))
        .unwrap();
        assert_eq!(hex::encode(sig_input), SIG_INPUT_KAT);

        let aad = sha384(&frame_aad(
            &[1u8; ROOT_LEN],
            Direction::AToB,
            &header(),
            &eph_ek,
            Some(&ct),
        ))
        .unwrap();
        assert_eq!(hex::encode(aad), AAD_KAT);

        // The opening burst has no generation ciphertext, and its absence is bound
        // as a zero-length component rather than skipped.
        let no_ct = sha384(&frame_aad(
            &[1u8; ROOT_LEN],
            Direction::AToB,
            &header(),
            &eph_ek,
            None,
        ))
        .unwrap();
        assert_eq!(hex::encode(no_ct), AAD_NO_CT_KAT);

        // Pinned structurally as well as by hash: an absent ciphertext is a
        // zero-LENGTH component, not an omitted one. Skipping it entirely would
        // leave both KATs above unchanged (they cover the present case), so
        // without this the documented rule is asserted in prose and nowhere else.
        let absent = frame_sig_input(
            &[1u8; ROOT_LEN],
            Direction::AToB,
            &header(),
            &eph_ek,
            None,
            &[2u8; RECIPIENT_HASH_LEN],
            AuthorKeys {
                pc: a.signing.public_key(),
                lt: b.signing.public_key(),
            },
            0x0a0b_0c0d_0e0f_1011,
            "ab",
        );
        assert!(
            absent.ends_with(&0u64.to_be_bytes()),
            "an absent generation ciphertext must be bound as lp(&[])"
        );
        let present = frame_sig_input(
            &[1u8; ROOT_LEN],
            Direction::AToB,
            &header(),
            &eph_ek,
            Some(&ct),
            &[2u8; RECIPIENT_HASH_LEN],
            AuthorKeys {
                pc: a.signing.public_key(),
                lt: b.signing.public_key(),
            },
            0x0a0b_0c0d_0e0f_1011,
            "ab",
        );
        assert_eq!(
            present.len(),
            absent.len() + ml_kem::CT_LEN,
            "the two cases must differ by exactly the ciphertext, so the length \
             prefix is present in both"
        );
    }

    const SIG_INPUT_KAT: &str = concat!(
        "21cbde75de754e9805d2f1d2b344f620ace1269d8d29cc706cb2e439",
        "9dd3d6d36b7c2bd0d2765eff1a9b9695498a48d3"
    );
    const AAD_KAT: &str = concat!(
        "f91604db3477d2929f2e3107db4a5b65297ff2eb035cd8912a806dfe",
        "9f9948dd3af087605e737a63053748aa53925e4c"
    );
    const AAD_NO_CT_KAT: &str = concat!(
        "e4f1c7d1ccba0ecb422a1b4d0de4a34793fa5dabbd379c07a2345041",
        "a8b3aae546f3921ed64ac75c33f31a6d98f81258"
    );

    /// No two distinct field tuples may produce the same signed or bound bytes.
    /// Length prefixes are what guarantee it; this notices if one is dropped.
    #[test]
    fn preimages_are_unambiguous_across_every_field() {
        let a = alice();
        let b = bob();
        let (ek1, _) = eph_keypair(5, 6);
        let (ek2, _) = eph_keypair(7, 8);
        let ct = Box::new([9u8; ml_kem::CT_LEN]);
        let h = header();

        // Keeps `pc` and `lt` as separate parameters here deliberately: this test
        // exists to prove they are NOT interchangeable in the preimage, which
        // `AuthorKeys` would hide behind a field name.
        let sig =
            |dir, hdr: &FrameHeader, ek: &[u8; ml_kem::EK_LEN], ct, rcpt, pc, lt, ms, body| {
                frame_sig_input(
                    &[1u8; ROOT_LEN],
                    dir,
                    hdr,
                    ek,
                    ct,
                    rcpt,
                    AuthorKeys { pc, lt },
                    ms,
                    body,
                )
            };
        let base = sig(
            Direction::AToB,
            &h,
            &ek1,
            Some(&ct),
            &[2u8; RECIPIENT_HASH_LEN],
            a.signing.public_key(),
            b.signing.public_key(),
            SENT,
            "hello",
        );

        // Direction — otherwise a frame replays into the reverse stream.
        assert_ne!(
            base,
            sig(
                Direction::BToA,
                &h,
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hello"
            )
        );
        // Generation, chain base and sequence are three distinct positions; a
        // preimage that folded any two together would let one be traded for another.
        for shifted in [
            FrameHeader {
                generation: h.generation + 1,
                ..h
            },
            FrameHeader {
                chain_base: h.chain_base + 1,
                ..h
            },
            FrameHeader {
                seq: h.seq + 1,
                ..h
            },
        ] {
            assert_ne!(
                base,
                sig(
                    Direction::AToB,
                    &shifted,
                    &ek1,
                    Some(&ct),
                    &[2u8; RECIPIENT_HASH_LEN],
                    a.signing.public_key(),
                    b.signing.public_key(),
                    SENT,
                    "hello"
                ),
                "every header field must be bound independently"
            );
        }
        // Swapping generation and chain_base must not produce the same bytes —
        // the length prefixes are what stop two integers concatenating alike.
        assert_ne!(
            sig(
                Direction::AToB,
                &FrameHeader {
                    generation: 1,
                    chain_base: 2,
                    seq: 3
                },
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hello"
            ),
            sig(
                Direction::AToB,
                &FrameHeader {
                    generation: 2,
                    chain_base: 1,
                    seq: 3
                },
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hello"
            )
        );
        // The ephemeral — an unauthenticated one lets an attacker substitute their
        // own and defeat the post-compromise heal.
        assert_ne!(
            base,
            sig(
                Direction::AToB,
                &h,
                &ek2,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hello"
            )
        );
        // Present-but-empty and absent must differ.
        assert_ne!(
            base,
            sig(
                Direction::AToB,
                &h,
                &ek1,
                None,
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hello"
            )
        );
        // Recipient, both keys, timestamp, body.
        assert_ne!(
            base,
            sig(
                Direction::AToB,
                &h,
                &ek1,
                Some(&ct),
                &[3u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hello"
            )
        );
        assert_ne!(
            base,
            sig(
                Direction::AToB,
                &h,
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                b.signing.public_key(),
                a.signing.public_key(),
                SENT,
                "hello"
            ),
            "the two public keys must not be interchangeable"
        );
        assert_ne!(
            base,
            sig(
                Direction::AToB,
                &h,
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT + 1,
                "hello"
            )
        );
        assert_ne!(
            base,
            sig(
                Direction::AToB,
                &h,
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                a.signing.public_key(),
                b.signing.public_key(),
                SENT,
                "hellp"
            )
        );

        // The AAD must separate the same way.
        let aad = frame_aad(&[1u8; ROOT_LEN], Direction::AToB, &h, &ek1, Some(&ct));
        assert_ne!(
            aad,
            frame_aad(&[4u8; ROOT_LEN], Direction::AToB, &h, &ek1, Some(&ct)),
            "the conversation must be bound"
        );
        assert_ne!(
            aad,
            frame_aad(&[1u8; ROOT_LEN], Direction::BToA, &h, &ek1, Some(&ct))
        );
        assert_ne!(
            aad,
            frame_aad(&[1u8; ROOT_LEN], Direction::AToB, &h, &ek1, None)
        );
    }

    /// A first-contact signature must not be a valid channel signature over the
    /// same tuple. The frame-kind label is the only thing standing between them.
    #[test]
    fn the_frame_kind_separates_the_two_signature_shapes() {
        let a = alice();
        let b = bob();
        let (ek, _) = eph_keypair(5, 6);
        let h = FrameHeader {
            generation: 0,
            chain_base: 0,
            seq: 0,
        };

        let fc = msg_sig_input(
            FRAME_KIND_FIRST_CONTACT,
            &[1u8; ROOT_LEN],
            Direction::AToB.label(),
            0,
            &ek,
            &[2u8; RECIPIENT_HASH_LEN],
            a.signing.public_key(),
            b.signing.public_key(),
            SENT,
            "hi",
        );
        let channel = frame_sig_input(
            &[1u8; ROOT_LEN],
            Direction::AToB,
            &h,
            &ek,
            None,
            &[2u8; RECIPIENT_HASH_LEN],
            AuthorKeys {
                pc: a.signing.public_key(),
                lt: b.signing.public_key(),
            },
            SENT,
            "hi",
        );
        assert_ne!(fc, channel);
        assert!(
            !channel.starts_with(&fc),
            "a channel preimage must not merely EXTEND a first-contact one — a \
             signature over a prefix must never be reusable"
        );
    }

    #[test]
    fn a_sealed_frame_round_trips_through_the_ratchet() {
        let mut p = pair();
        let bytes = p.send("the quick brown fox");
        let got = p.recv(&bytes).unwrap();
        assert_eq!(got.body, "the quick brown fox");
        assert_eq!(got.sent_unix_ms, SENT);
        // The initiator's channel sequence starts at 1: sequence 0 was the knock,
        // which travelled via the doorbell rather than the channel.
        assert_eq!(got.seq, 1);

        let second = p.send("and again");
        assert_eq!(p.recv(&second).unwrap().seq, 2);
    }

    /// Both directions, over a real generation step: the recipient's reply
    /// re-roots the ratchet, and the initiator opens it.
    #[test]
    fn the_reply_direction_round_trips_after_a_generation_step() {
        let mut p = pair();
        let first = p.send("hello");
        p.recv(&first).unwrap();

        let out = p.recip.send_next().unwrap();
        assert_eq!(out.header.generation, 1, "the reply takes the first step");
        assert!(out.eph_ct.is_some(), "a step publishes its ciphertext");
        let rcpt_a = recipient_hash(p.a.signing.public_key()).unwrap();
        let reply_seq = out.header.seq;
        let bytes = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.b.signing,
            p.b.signing.public_key(),
            &rcpt_a,
            SENT,
            "hi back",
        )
        .unwrap();

        let parsed = parse(&bytes).unwrap();
        let dir = p.init.recv_direction();
        let pk_b = *p.b.signing.public_key();
        let opened = p
            .init
            .receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |mk| {
                parsed.open(
                    mk,
                    &[1u8; ROOT_LEN],
                    dir,
                    position_of(reply_seq),
                    &rcpt_a,
                    AuthorKeys {
                        pc: &pk_b,
                        lt: &pk_b,
                    },
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(opened.body, "hi back");
        assert_eq!(
            opened.seq, 0,
            "the recipient's channel sequence starts at 0"
        );
    }

    /// The reply direction again, at a position where page, slot and sequence are
    /// three different numbers.
    ///
    /// Its sibling above stays at sequence zero on purpose — that the recipient's
    /// channel starts there is the property it exists to pin, so moving it would
    /// lose that. But `(page 0, slot 0, sequence 0)` is triply degenerate: the
    /// three numbers and the asserted literal are all the same integer, so nothing
    /// in it can witness `open` binding a frame to its SEQUENCE rather than to its
    /// slot or its page (#272). This one is the same round trip at page 3, slot 9,
    /// sequence 57, where those three answers differ and a substitution shows.
    #[test]
    fn the_reply_direction_round_trips_at_a_position_that_is_not_page_zero() {
        let mut p = pair();
        let first = p.send("hello");
        p.recv(&first).unwrap();

        // The step happens on the recipient's first send, so the burn covers it and
        // the frame that comes back is well inside the generation.
        advance_send_to(&mut p.recip, DISTINCT_SEQ);
        let out = p.recip.send_next().unwrap();
        assert_eq!(out.header.generation, 1, "the reply took the first step");
        assert!(
            out.eph_ct.is_some(),
            "the generation carries its ciphertext"
        );

        let rcpt_a = recipient_hash(p.a.signing.public_key()).unwrap();
        let at = position_of(out.header.seq);
        assert_eq!(
            (at.page(), at.slot(), at.seq()),
            (3, 9, DISTINCT_SEQ),
            "this fixture must sit where page, slot and sequence are three different \
             numbers, or it adds nothing its sibling does not already cover"
        );

        let bytes = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.b.signing,
            p.b.signing.public_key(),
            &rcpt_a,
            SENT,
            "hi back",
        )
        .unwrap();

        let parsed = parse(&bytes).unwrap();
        let dir = p.init.recv_direction();
        let pk_b = *p.b.signing.public_key();
        // The initiator never saw sequences 0..57, so this also exercises the
        // catch-up path — the skip stays under `MAX_SKIP`.
        let opened = p
            .init
            .receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |mk| {
                parsed.open(
                    mk,
                    &[1u8; ROOT_LEN],
                    dir,
                    at,
                    &rcpt_a,
                    AuthorKeys {
                        pc: &pk_b,
                        lt: &pk_b,
                    },
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(opened.body, "hi back");
        assert_eq!(opened.seq, DISTINCT_SEQ);
    }

    /// Every clear field is bound in the AAD, so an edited header fails the AEAD
    /// open rather than reaching the ratchet as an authenticated position. Each
    /// mutation below is applied to the encoded frame and must fail.
    #[test]
    fn every_clear_field_is_bound_in_the_aad() {
        let mut p = pair();
        let (bytes, key) = p.send_keyed("bound");
        let good = parse(&bytes).unwrap();

        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let dir = p.recip.recv_direction();
        let at = position_of(good.header().seq);

        // Attack the frame under the sender's OWN key, so a failure can only be
        // the AAD binding — using a ratchet here would conflate that with "the
        // ratchet refused the position", which is a different defence entirely.
        assert!(
            good.open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, author)
                .is_ok(),
            "the honest frame opens under the honest key"
        );

        let mutations: Vec<(&str, Mutation)> = vec![
            (
                "ratchet_gen",
                Box::new(|f: &mut wire::DmChannelFrame| f.ratchet_gen += 1),
            ),
            (
                "chain_base",
                Box::new(|f: &mut wire::DmChannelFrame| f.chain_base += 1),
            ),
            ("seq", Box::new(|f: &mut wire::DmChannelFrame| f.seq += 1)),
            (
                "eph_ek",
                Box::new(|f: &mut wire::DmChannelFrame| f.eph_ek[0] ^= 0xff),
            ),
            (
                "sealed",
                Box::new(|f: &mut wire::DmChannelFrame| {
                    let last = f.sealed.len() - 1;
                    f.sealed[last] ^= 0xff;
                }),
            ),
        ];

        for (field, mutate) in mutations {
            let mut decoded = wire::DmChannelFrame::decode(&bytes[..]).unwrap();
            mutate(&mut decoded);
            let tampered = parse(&decoded.encode_to_vec()).unwrap();
            // The position is taken from the TAMPERED header on purpose: it
            // isolates the AAD binding from the separate seq-vs-slot check, which
            // would otherwise reject the `seq` mutation before the open is
            // attempted and leave the AAD's coverage of `seq` untested.
            let at = position_of(tampered.header().seq);
            assert!(
                matches!(
                    tampered.open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, author),
                    Err(DmFrameError::Aead)
                ),
                "mutating {field} must fail the AEAD open"
            );
        }
    }

    #[test]
    fn a_frame_does_not_open_in_another_conversation_or_the_reverse_direction() {
        let mut p = pair();
        let (bytes, key) = p.send_keyed("scoped");
        let parsed = parse(&bytes).unwrap();
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let at = position_of(parsed.header().seq);

        assert!(matches!(
            parsed.open(&key, &[9u8; ROOT_LEN], Direction::AToB, at, &rcpt, author),
            Err(DmFrameError::Aead)
        ));
        assert!(matches!(
            parsed.open(&key, &[1u8; ROOT_LEN], Direction::BToA, at, &rcpt, author),
            Err(DmFrameError::Aead)
        ));
    }

    /// The authorship signature is verified, and it is verified against the right
    /// key. Deleting the `verify_signature` call must fail this test — owner-write
    /// authority on a page is symmetric, so nothing else establishes authorship.
    #[test]
    fn the_authorship_signature_is_mandatory_and_key_bound() {
        let mut p = pair();
        let (bytes, key) = p.send_keyed("signed");
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };

        // Verified against the wrong pseudonym key: the signature is genuine, the
        // key is not the one the contact cache holds.
        let parsed = parse(&bytes).unwrap();
        let dir = p.recip.recv_direction();
        let at = position_of(parsed.header().seq);
        let wrong = AuthorKeys {
            pc: p.a.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        assert!(matches!(
            parsed.open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, wrong),
            Err(DmFrameError::Signature)
        ));

        // A frame addressed to somebody else: the signature covers the recipient,
        // so redirecting it is caught even though the AAD does not carry it.
        assert!(matches!(
            parsed.open(
                &key,
                &[1u8; ROOT_LEN],
                dir,
                at,
                &[0u8; RECIPIENT_HASH_LEN],
                author
            ),
            Err(DmFrameError::Signature)
        ));

        // And a corrupted signature.
        let mut decoded = wire::DmChannelFrame::decode(&bytes[..]).unwrap();
        let last = decoded.sealed.len() - 1;
        decoded.sealed[last] ^= 0x01;
        assert!(
            parse(&decoded.encode_to_vec())
                .unwrap()
                .open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, author)
                .is_err()
        );
    }

    /// Padding hides the message length: two different bodies in the same bucket
    /// produce byte-identical frame lengths, so a page co-host learns a coarse
    /// size class and nothing finer.
    #[test]
    fn padding_reduces_the_length_to_a_size_class() {
        let mut p = pair();
        let short = p.send("a");
        let longer = p.send("a considerably longer message, but still a short one");
        assert_eq!(short.len(), longer.len());

        let big = p.send(&"x".repeat(DM_BODY_CAP));
        assert!(
            big.len() > short.len(),
            "a body that does not fit the small bucket must use the larger one"
        );
        assert!(big.len() <= MAX_FRAME_LEN);
    }

    /// The whole chain of arithmetic — body cap, signature size, padding ladder,
    /// ML-KEM material, protobuf overhead — against the record shape it must fit.
    /// `PAGE_SLOTS = 16` gives `min(32768, 1MiB/16) = 32768` bytes per subkey.
    #[test]
    fn worst_case_frame_fits_a_page_subkey() {
        assert_eq!(
            MAX_FRAME_LEN,
            std::cmp::min(
                32768,
                (1024 * 1024) / crate::dm::paging::PAGE_SLOTS as usize
            ),
            "the cap must be the schema-derived subkey bound, not a constant"
        );
        // The worst case carries a generation ciphertext, so it must be measured
        // on a frame that HAS one. The initiator's opening burst does not — its
        // chain hangs off the first-contact secret — so measuring there would
        // under-count by the full 1571-byte `eph_ct` field and check a raised
        // constant against the wrong number.
        let mut p = pair();
        let first = p.send("open the conversation");
        p.recv(&first).unwrap();

        let out = p.recip.send_next().unwrap();
        assert!(
            out.eph_ct.is_some(),
            "the worst case must include a generation ciphertext"
        );
        let worst = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.b.signing,
            p.b.signing.public_key(),
            &recipient_hash(p.a.signing.public_key()).unwrap(),
            SENT,
            &"x".repeat(DM_BODY_CAP),
        )
        .unwrap();
        assert!(
            worst.len() > first.len() + ml_kem::CT_LEN,
            "the measured frame must be the larger, ciphertext-bearing shape"
        );
        assert!(
            worst.len() <= MAX_FRAME_LEN,
            "worst case is {} bytes against a {MAX_FRAME_LEN}-byte cap",
            worst.len()
        );
        // Storage capacities are sized against this, not against MAX_FRAME_LEN,
        // which `seal` cannot reach. Pinned exactly so a change to PAD_BUCKETS,
        // DM_BODY_CAP, the signature suite or the header lands here rather than
        // silently moving how many frames an outbox record holds.
        assert_eq!(
            worst.len(),
            WORST_CASE_SEALED_FRAME_LEN,
            "the measured worst-case frame moved; re-check OUTBOX_CAPACITY's headroom"
        );
    }

    /// A peer is not obliged to respect our compose-time body cap — it is the
    /// SENDER's own limit, enforced in `seal`, and a non-conforming client can
    /// seal anything the padding bucket holds. `open` must therefore re-check it
    /// on the receiving side, or an over-cap body reaches the UI.
    ///
    /// The frame below is built by hand for exactly that reason: `seal` refuses to
    /// produce one, so nothing that goes through the public API can reach this
    /// path, and the check would otherwise be untested by construction.
    #[test]
    fn an_over_cap_body_from_a_non_conforming_peer_is_rejected_on_open() {
        let mut p = pair();
        let out = p.init.send_next().unwrap();
        let key = out.key.clone();
        let out_direction = out.direction;
        let out_seq = out.header.seq;
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let body = "x".repeat(DM_BODY_CAP + 1);

        let msg_sig = p
            .a_pc
            .signing
            .sign(&frame_sig_input(
                &[1u8; ROOT_LEN],
                out.direction,
                &out.header,
                &out.eph_ek,
                out.eph_ct.as_deref(),
                &rcpt,
                AuthorKeys {
                    pc: p.a_pc.signing.public_key(),
                    lt: p.a.signing.public_key(),
                },
                SENT,
                &body,
            ))
            .unwrap();
        let encoded = wire::DmChannelBody {
            sent_unix_ms: SENT,
            body: body.clone(),
            msg_sig: msg_sig.to_vec(),
        }
        .encode_to_vec();
        let padded = crate::dm::pad_to_bucket(&encoded, PAD_BUCKETS).unwrap();
        let sealed = seal_envelope(
            &aes_key(&key).unwrap(),
            &frame_aad(
                &[1u8; ROOT_LEN],
                out.direction,
                &out.header,
                &out.eph_ek,
                out.eph_ct.as_deref(),
            ),
            &padded,
        )
        .unwrap();
        let bytes = wire::DmChannelFrame {
            ratchet_gen: out.header.generation,
            chain_base: out.header.chain_base,
            seq: out.header.seq,
            eph_ek: out.eph_ek.to_vec(),
            eph_ct: Vec::new(),
            sealed,
        }
        .encode_to_vec();

        // Everything about this frame is authentic — it opens, and its signature
        // verifies. Only the body cap rejects it.
        let parsed = parse(&bytes).unwrap();
        assert!(matches!(
            parsed.open(
                &key,
                &[1u8; ROOT_LEN],
                out_direction,
                position_of(out_seq),
                &rcpt,
                AuthorKeys {
                    pc: p.a_pc.signing.public_key(),
                    lt: p.a.signing.public_key(),
                },
            ),
            Err(DmFrameError::TooLarge { .. })
        ));
    }

    /// The composition this module exists for, on its FAILURE path: a frame that
    /// does not authenticate must leave the ratchet byte-for-byte where it was,
    /// and the honest frame at that position must still open afterwards.
    ///
    /// Every other test here either opens honestly or attacks `open` in isolation
    /// with the sender's own key. This one goes through the real seam, which is
    /// the only place the authenticate-before-commit discipline actually lives.
    #[test]
    fn a_frame_that_fails_to_open_moves_no_ratchet_state() {
        let mut p = pair();
        let (bytes, _) = p.send_keyed("honest");

        let mut decoded = wire::DmChannelFrame::decode(&bytes[..]).unwrap();
        let last = decoded.sealed.len() - 1;
        decoded.sealed[last] ^= 0xff;
        let tampered = decoded.encode_to_vec();

        let before = (p.recip.generation(), p.recip.losses());
        let outcome = p
            .recv_raw(&tampered)
            .expect("the ratchet accepts the position");
        assert!(
            matches!(outcome, Err(DmFrameError::Aead)),
            "a tampered frame must fail inside the closure, not outside it"
        );
        assert_eq!(
            (p.recip.generation(), p.recip.losses()),
            before,
            "a frame that did not authenticate must not move the ratchet"
        );

        // The position was not consumed, so the honest frame still arrives.
        assert_eq!(p.recv(&bytes).unwrap().body, "honest");
    }

    /// A peer that signs one sequence number and writes the bytes into another
    /// slot is caught, and caught BEFORE the seal is opened — only the collector
    /// holds both facts, so nothing else in the system could notice.
    ///
    /// Deliberately sealed at [`DISTINCT_SEQ`] rather than at the conversation's
    /// first sequence number. This is the *only* test of slot misfiling in the
    /// crate, and on page 0 it could not do its job: slot and sequence are the same
    /// integer there, so `open` reading the slot where it should read the sequence
    /// would satisfy both halves below (#272). At page 3, slot 9, sequence 57 the
    /// honest half fails under that mutant, because slot 9 is not sequence 57.
    #[test]
    fn a_frame_written_to_the_wrong_slot_is_rejected() {
        let mut p = pair();
        advance_send_to(&mut p.init, DISTINCT_SEQ);
        let (bytes, key) = p.send_keyed("misfiled");
        let parsed = parse(&bytes).unwrap();
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let dir = p.recip.recv_direction();

        // The control on the fixture itself. Everything below is only a test of the
        // slot-to-sequence binding while these three numbers differ; if this
        // position ever drifts back onto page 0 the assertions keep passing while
        // proving strictly less, which is the exact failure #272 records.
        let honest = position_of(parsed.header().seq);
        assert_eq!(
            (honest.page(), honest.slot(), honest.seq()),
            (3, 9, DISTINCT_SEQ),
            "this fixture must sit where page, slot and sequence are three different \
             numbers, or it cannot tell a slot from a sequence"
        );

        let elsewhere = position_of(parsed.header().seq + 100);
        assert!(matches!(
            parsed.open(&key, &[1u8; ROOT_LEN], dir, elsewhere, &rcpt, author),
            Err(DmFrameError::Misplaced { .. })
        ));
        // And the honest position still opens, so the check is not simply refusing
        // everything. This is the half that the page-0 fixture used to let a
        // slot-for-sequence mutant through: at page 3 slot 9, reading the slot
        // yields 9 against a declared sequence of 57, so the mutant fails here.
        assert!(
            parsed
                .open(&key, &[1u8; ROOT_LEN], dir, honest, &rcpt, author)
                .is_ok()
        );
    }

    /// The two things a peer holding the message key still controls, inside the
    /// seal: the padding length prefix and the inner protobuf. Both reach `open`
    /// only after the AEAD has authenticated, so only the peer can produce them —
    /// and both must fail closed rather than slicing past a buffer.
    #[test]
    fn a_hostile_padded_plaintext_from_a_key_holding_peer_is_rejected() {
        let mut p = pair();
        let out = p.init.send_next().unwrap();
        let key = out.key.clone();
        let direction = out.direction;
        let seq = out.header.seq;
        let header = out.header;
        let eph_ek = out.eph_ek.clone();
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };

        // A length prefix claiming far more than the buffer holds, and a
        // well-formed prefix over bytes that are not a `DmChannelBody`.
        let mut hostile = vec![0u8; PAD_BUCKETS[0]];
        hostile[..LEN_PREFIX].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut garbage = vec![0xffu8; PAD_BUCKETS[0]];
        garbage[..LEN_PREFIX].copy_from_slice(&64u32.to_le_bytes());

        for (name, plaintext) in [
            ("oversized length prefix", hostile),
            ("not a body", garbage),
        ] {
            let sealed = seal_envelope(
                &aes_key(&key).unwrap(),
                &frame_aad(&[1u8; ROOT_LEN], direction, &header, &eph_ek, None),
                &plaintext,
            )
            .unwrap();
            let bytes = wire::DmChannelFrame {
                ratchet_gen: header.generation,
                chain_base: header.chain_base,
                seq: header.seq,
                eph_ek: eph_ek.to_vec(),
                eph_ct: Vec::new(),
                sealed,
            }
            .encode_to_vec();

            let parsed = parse(&bytes).unwrap();
            assert!(
                matches!(
                    parsed.open(
                        &key,
                        &[1u8; ROOT_LEN],
                        direction,
                        position_of(seq),
                        &rcpt,
                        author
                    ),
                    Err(DmFrameError::Malformed)
                ),
                "{name} must be rejected as malformed"
            );
        }
    }

    #[test]
    fn an_oversized_body_is_refused_locally() {
        let mut p = pair();
        let out = p.init.send_next().unwrap();
        let err = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.a_pc.signing,
            p.a.signing.public_key(),
            &recipient_hash(p.b.signing.public_key()).unwrap(),
            SENT,
            &"x".repeat(DM_BODY_CAP + 1),
        );
        assert!(matches!(err, Err(DmFrameError::TooLarge { .. })));
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        assert!(matches!(parse(&[0xff; 32]), Err(DmFrameError::Malformed)));

        let mut p = pair();
        let bytes = p.send("ok");

        for (field, mutate) in [
            (
                "eph_ek",
                Box::new(|f: &mut wire::DmChannelFrame| f.eph_ek.truncate(10))
                    as Box<dyn Fn(&mut wire::DmChannelFrame)>,
            ),
            (
                "eph_ct",
                Box::new(|f: &mut wire::DmChannelFrame| f.eph_ct = vec![0u8; 3]),
            ),
        ] {
            let mut decoded = wire::DmChannelFrame::decode(&bytes[..]).unwrap();
            mutate(&mut decoded);
            assert!(
                matches!(
                    parse(&decoded.encode_to_vec()),
                    Err(DmFrameError::FieldLength { .. })
                ),
                "a wrong-length {field} must be rejected at parse"
            );
        }
    }

    /// The opening burst hangs off the first-contact secret, so it carries no
    /// generation ciphertext — and the absent field must survive the round trip
    /// as absent rather than as an empty one.
    #[test]
    fn the_opening_burst_carries_no_generation_ciphertext() {
        let mut p = pair();
        let bytes = p.send("first");
        let parsed = parse(&bytes).unwrap();
        assert!(parsed.eph_ct().is_none());
        assert_eq!(parsed.header().generation, 0);
        assert!(p.recv(&bytes).is_ok());
    }
}
