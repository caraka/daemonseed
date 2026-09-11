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
use crate::dm::ack::{AckError, AckState, PeerAck};
use crate::dm::firstcontact::{
    DM_BODY_CAP, RECIPIENT_HASH_LEN, ROOT_LEN, bind_lt_input, msg_sig_input,
};
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
///
/// **Which rung a frame lands on is computed as though it carried a saturated
/// piggybacked acknowledgement, whether or not it carries one** — see
/// [`WORST_CASE_ACK_FIELDS_LEN`]. Selecting on the real encoded length instead
/// would make the rung a function of the acknowledgement, and a ladder is a
/// leak the moment anything a co-host cannot otherwise see can move a frame
/// between its rungs.
pub const PAD_BUCKETS: &[usize] = &[8192, 16384];

/// The longest [`AckState::encode_beyond`] output that can exist: the two-byte
/// run count plus [`crate::dm::ack::MAX_ACK_RUNS`] sixteen-byte runs.
///
/// Stated here rather than imported because `ack.rs` keeps its run and count
/// widths private; `the_worst_case_acknowledgement_overhead_is_pinned` measures a
/// saturated [`AckState`] against it, so a change to either width fails the build
/// rather than silently shrinking the constant-overhead reservation below.
pub const MAX_ACK_BEYOND_LEN: usize = 2 + crate::dm::ack::MAX_ACK_RUNS * 16;

/// Bytes the two acknowledgement fields add to an encoded [`wire::DmChannelBody`]
/// at their largest: an eleven-byte `ack_high_water` (tag plus a ten-byte varint)
/// and a 1029-byte `ack_beyond` (tag, two-byte length, [`MAX_ACK_BEYOND_LEN`]).
///
/// **Every frame reserves this much regardless of what it actually carries**, and
/// that reservation is the whole mechanism. `ack_record.rs` pads a standalone
/// acknowledgement to a single fixed rung for the same reason — a ladder still
/// leaks a size class — and a piggybacked acknowledgement rides a ladder that
/// already exists, so the equivalent defence has to be to make the *choice of
/// rung* independent of the acknowledgement rather than to flatten the ladder.
///
/// Without it, a body between roughly 2.5 KB and 3.5 KB lands on the 8192 rung
/// bare and the 16384 rung with a saturated acknowledgement — an 8 KB difference
/// on the wire that says whether this reply acknowledged anything and roughly how
/// many gap-runs it carried. **The cost is honest and is paid by every frame:**
/// bodies in that band always take the larger rung now, acknowledgement or not.
pub const WORST_CASE_ACK_FIELDS_LEN: usize = 1040;

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
    /// The piggybacked acknowledgement did not decode. Carries the cause, the
    /// same way [`Self::Signing`] does, because there is a real diagnosis here
    /// rather than a uniform authentication verdict: the seal has already opened
    /// and `msg_sig` has already verified by the time this can fire, so the
    /// acknowledgement was written by the peer that holds the message key —
    /// the same non-conforming-peer class as [`Self::TooLarge`].
    PiggybackedAck(AckError),
    /// The pseudonym binding carried in the body did not verify under the
    /// long-term key this conversation was opened against.
    ///
    /// Uniform in exactly the way [`Self::Signature`] is: a forged signature, a
    /// binding over some other pseudonym and a binding by some other identity
    /// are one verdict, because distinguishing them would say which half of the
    /// forgery was closest.
    Binding,
    /// [`ParsedFrame::open_accept`] was given a frame carrying no binding at
    /// all — the ordinary-frame shape, at the position an ACCEPT occupies.
    ///
    /// Distinct from [`Self::Binding`] on purpose. An absent binding is a peer
    /// that replied without accepting, which is a protocol state; a binding
    /// that does not verify is an attack. Collapsing them would report the
    /// first as tampering.
    MissingBinding,
    /// A frame carries a pseudonym key other than the one already installed for
    /// this conversation.
    ///
    /// Checked BEFORE the authorship signature, so a second pseudonym is
    /// refused as a pinning violation rather than as a signature that happens
    /// not to verify under the installed key.
    PseudonymMismatch,
    /// [`ParsedFrame::open_accept`] was asked to open a position an ACCEPT
    /// cannot occupy: any sequence but the acceptor's zero, or the initiator's
    /// own direction.
    NotAccept { seq: u64 },
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
            Self::PiggybackedAck(e) => {
                write!(f, "the piggybacked acknowledgement did not decode: {e}")
            }
            Self::Binding => write!(f, "the pseudonym binding did not verify"),
            Self::MissingBinding => write!(f, "the frame carries no pseudonym binding"),
            Self::PseudonymMismatch => {
                write!(f, "the frame carries a different pseudonym key")
            }
            Self::NotAccept { seq } => {
                write!(f, "sequence {seq} is not where an acceptance can sit")
            }
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
/// signature covers. Five more follow, each length-prefixed: the generation, the
/// chain base, the generation ciphertext, and the two halves of the piggybacked
/// acknowledgement.
///
/// The first three are the frozen design's `(ratchet_gen, PN)` header plus § v6
/// minor invariant (a). They are already bound in the AAD, so binding them again
/// is belt-and-braces — but the two bindings answer different questions. The AAD
/// proves the header was not edited between sealing and opening; the signature
/// proves the *sender* chose it, which is what stops a party who holds the message
/// key (there are only two, but a compromised one is the threat) from re-filing an
/// authentic body at a different ratchet position.
///
/// An absent `eph_ct` is bound as a zero-length component rather than skipped, so
/// "no ciphertext" and "empty ciphertext" cannot produce the same preimage.
///
/// ## The acknowledgement's two components, and why they need no signature of
/// their own
///
/// `ack_high_water` and `ack_beyond` are the sender's own collection state riding
/// out on this message rather than on a standalone acknowledgement record
/// (`docs/design/direct-messaging.md` § v3 *Ack*: "piggybacks on outbound
/// messages"). A standalone acknowledgement carries its own ML-DSA signature over
/// [`crate::dm::ack::ack_sig_input`]; a piggybacked one is inside a body `msg_sig`
/// already covers end to end, so binding it here **is** its authentication step.
/// There is deliberately no second signature: one would be a distinct preimage
/// over the same claim, and two authenticating paths for one statement is exactly
/// how a claim gets read off the path that was not checked.
///
/// An absent `ack_high_water` is bound as a zero-length component rather than
/// skipped, identically to an absent `eph_ct` — `Some(0)` says sequence zero was
/// collected and `None` says nothing was, and a preimage that could not tell them
/// apart would let one be replayed as the other. This mirrors
/// [`crate::dm::ack::ack_sig_input`], which binds the same distinction the same
/// way one level down. `ack_beyond` is never absent, only possibly empty, and
/// [`crate::dm::ack::AckState::encode_beyond`] gives one set exactly one
/// spelling, so it binds directly.
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
    ack_high_water: Option<u64>,
    ack_beyond: &[u8],
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
    match ack_high_water {
        Some(h) => push_lp(&mut buf, &h.to_be_bytes()),
        None => push_lp(&mut buf, &[]),
    }
    push_lp(&mut buf, ack_beyond);
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

/// Bytes the two acknowledgement fields contribute to an encoded body.
///
/// Measured by encoding a probe whose every other field is at its protobuf
/// default — prost omits those entirely, so what is left is exactly the two
/// fields in question. Deliberately measured with prost's own encoder rather
/// than computed from tag and varint widths by hand: a hand-rolled size that
/// disagreed with the encoder would move the padding rung by a byte or two and
/// reintroduce the very leak the reservation exists to close, silently.
///
/// The probe never holds plaintext — `body` and `msg_sig` are empty — so this
/// costs one small allocation and no second copy of the message (#135).
fn ack_fields_encoded_len(high_water: Option<u64>, beyond: &[u8]) -> usize {
    wire::DmChannelBody {
        sent_unix_ms: 0,
        body: String::new(),
        msg_sig: Vec::new(),
        ack_high_water: high_water,
        ack_beyond: beyond.to_vec(),
        pk_pc: Vec::new(),
        bind_lt: Vec::new(),
    }
    .encoded_len()
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
///
/// ## `ack`, and the staleness it accepts
///
/// `ack` is the sender's own collection state, riding out with this message
/// instead of costing a standalone acknowledgement record — the frozen design's
/// "the high-water rides on any outbound message". `None` composes a frame that
/// acknowledges nothing, which is what the reconnect legs produce: `RE-EST`,
/// `RE-ACK` and `RE-CONFIRM` carry no content, so they have nothing to piggyback
/// on and pay the standalone ack instead.
///
/// ## ⚠ Which `AckState` — the directions here are OPPOSITE, and nothing checks
///
/// **Pass the state tracking what we have COLLECTED from the peer** — the one
/// [`crate::dm::collect::Collection`] advances, keyed on the *receiving*
/// direction ([`crate::dm::ratchet::Ratchet::recv_direction`]). Never the state
/// tracking which of our own sends the peer has confirmed; that one is the
/// peer's statement about us, and re-emitting it here would claim to have
/// collected our own messages.
///
/// The trap is that this frame is bound under `outbound.direction`, which is the
/// direction the *frame* travels — the opposite of the direction the messages it
/// acknowledges travelled. Every other ack surface in this feature takes `dir`
/// to mean "the direction of the messages being acknowledged"
/// ([`crate::dm::ack::ack_sig_input`], [`crate::dm::ack::derive_seal_key`]),
/// so the meaning inverts exactly once, here, and it inverts silently:
/// [`AckState`] carries no direction, so **the type system cannot tell the two
/// apart and neither can a signature**. Passing the wrong one produces a
/// perfectly valid, correctly signed frame carrying a claim about the wrong half
/// of the conversation, which the peer would merge against its own outbox and
/// use to mark messages delivered that were never collected.
///
/// This is not a live defect — nothing calls `seal` with a real acknowledgement
/// yet — but it is unguarded, and the guard belongs on whatever wires the two
/// together, not here.
///
/// **A piggybacked acknowledgement is fixed at compose time and a re-seed does
/// not refresh it.** The two facts above compose: a re-seed re-emits the sealed
/// bytes unchanged, so a message still pending a week later carries the
/// high-water its sender held when it was first composed, not the one it holds
/// now. That is an accepted residual, not a defect. It is fail-safe in the only
/// direction that matters — a stale high-water is always *lower* than the
/// current one, because [`crate::dm::ack::AckState`] never regresses, so it
/// under-claims and the peer keeps re-seeding a message it has in fact
/// collected. The cost is a delayed confirmation, paid for by the standalone
/// ack's own cadence; the alternative — re-sealing to refresh it — would mint a
/// second authentic frame at one ratchet position, which is exactly what taking
/// `outbound` by value exists to forbid.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    outbound: Outbound,
    chan_id: &[u8; ROOT_LEN],
    signing_pc: &SignKeypair,
    pk_lt: &[u8; ml_dsa::PK_LEN],
    recipient_hash: &[u8; RECIPIENT_HASH_LEN],
    sent_unix_ms: i64,
    body: &str,
    ack: Option<&AckState>,
) -> Result<Vec<u8>, DmFrameError> {
    seal_bound(
        outbound,
        chan_id,
        signing_pc,
        pk_lt,
        recipient_hash,
        sent_unix_ms,
        body,
        ack,
        None,
    )
}

/// The acceptor's ACCEPT: an ordinary channel frame at the acceptor's sequence
/// zero, carrying its pseudonym key and that key's long-term binding inside the
/// seal.
///
/// **Not a new wire message and not a new frame kind.** It is
/// [`seal`]'s output with two more sealed fields, signed under the identical
/// [`frame_sig_input`] preimage under [`FRAME_KIND_CHANNEL`], so a receiver that
/// never looks at the two fields opens it as any other frame. What it adds is
/// the one thing a channel frame otherwise cannot carry: page owner-write
/// authority is symmetric and the ratchet is keyed off a secret both ends hold,
/// so an initiator that has never seen the acceptor's pseudonym has nothing to
/// verify authorship against. This frame is where it arrives.
///
/// **The body is empty, and that is the design's shape rather than a
/// simplification.** The acceptance fires the instant the user accepts, whether
/// or not they have composed anything, so it takes no body parameter — a reply
/// with content is an ordinary [`seal`] at the next sequence number.
///
/// `signing_lt` is the acceptor's own long-term identity keypair, used here and
/// only here: `bind_lt` is signed under it, exactly as a first-contact entry's
/// is in the other direction, under the same
/// [`crate::dm::domain::DM_BIND_LT`] domain. The public half never goes on the
/// wire — the initiator already holds it, because it is the key it knocked at.
pub fn seal_accept(
    outbound: Outbound,
    chan_id: &[u8; ROOT_LEN],
    signing_pc: &SignKeypair,
    signing_lt: &SignKeypair,
    recipient_hash: &[u8; RECIPIENT_HASH_LEN],
    sent_unix_ms: i64,
    ack: Option<&AckState>,
) -> Result<Vec<u8>, DmFrameError> {
    debug_assert_eq!(
        outbound.direction,
        Direction::BToA,
        "an acceptance travels on the acceptor's own sending direction"
    );
    debug_assert_eq!(
        outbound.header.seq,
        crate::dm::ratchet::FIRST_RECIPIENT_CHANNEL_SEQ,
        "an acceptance is the first thing the acceptor writes to the channel"
    );
    let pk_pc = *signing_pc.public_key();
    let pk_lt = *signing_lt.public_key();
    let bind_lt = signing_lt
        .sign(&bind_lt_input(&pk_lt, &pk_pc))
        .map_err(DmFrameError::Signing)?;
    seal_bound(
        outbound,
        chan_id,
        signing_pc,
        &pk_lt,
        recipient_hash,
        sent_unix_ms,
        "",
        ack,
        Some(PseudonymBinding {
            pk_pc: &pk_pc,
            bind_lt: &bind_lt,
        }),
    )
}

/// The two sealed fields an ACCEPT adds, kept together so neither can be
/// written without the other.
struct PseudonymBinding<'a> {
    pk_pc: &'a [u8; ml_dsa::PK_LEN],
    bind_lt: &'a [u8; ml_dsa::SIG_LEN],
}

#[allow(clippy::too_many_arguments)]
fn seal_bound(
    outbound: Outbound,
    chan_id: &[u8; ROOT_LEN],
    signing_pc: &SignKeypair,
    pk_lt: &[u8; ml_dsa::PK_LEN],
    recipient_hash: &[u8; RECIPIENT_HASH_LEN],
    sent_unix_ms: i64,
    body: &str,
    ack: Option<&AckState>,
    binding: Option<PseudonymBinding<'_>>,
) -> Result<Vec<u8>, DmFrameError> {
    if body.len() > DM_BODY_CAP {
        return Err(DmFrameError::TooLarge {
            got: body.len(),
            max: DM_BODY_CAP,
        });
    }

    // Read once, here, so the bytes signed and the bytes carried are the same
    // bytes rather than two encodings of one state taken a few lines apart.
    let (ack_high_water, ack_beyond) = match ack {
        Some(state) => (state.high_water(), state.encode_beyond()),
        None => (None, Vec::new()),
    };

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
        ack_high_water,
        &ack_beyond,
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
        ack_high_water,
        ack_beyond,
        // Empty on every ordinary frame, so prost omits both fields and an
        // ordinary body's encoding is byte-identical to what it was before
        // they existed.
        pk_pc: binding
            .as_ref()
            .map(|b| b.pk_pc.to_vec())
            .unwrap_or_default(),
        bind_lt: binding
            .as_ref()
            .map(|b| b.bind_lt.to_vec())
            .unwrap_or_default(),
    };
    let mut encoded = plain.encode_to_vec();
    plain.body.zeroize();

    // The rung is chosen for the frame this WOULD be if it carried a saturated
    // acknowledgement, then the real bytes are padded out to it. Selecting on
    // `encoded.len()` instead would let the acknowledgement decide the rung, and
    // the ladder would then publish whether one rode along — see
    // [`WORST_CASE_ACK_FIELDS_LEN`]. The notional length is never below the real
    // one, because the reservation is the maximum of what the two fields can
    // occupy, so the chosen rung always holds the actual bytes.
    let notional = encoded
        .len()
        .saturating_sub(ack_fields_encoded_len(ack_high_water, &plain.ack_beyond))
        .saturating_add(WORST_CASE_ACK_FIELDS_LEN);
    let too_large = DmFrameError::TooLarge {
        got: LEN_PREFIX.saturating_add(notional),
        max: *PAD_BUCKETS.last().expect("ladder is never empty"),
    };
    let rung = PAD_BUCKETS
        .iter()
        .copied()
        .find(|b| LEN_PREFIX.saturating_add(notional) <= *b)
        .ok_or(too_large)?;
    let mut padded = crate::dm::pad_to_bucket(&encoded, &[rung])
        .expect("the notional length is never below the real one, so the rung holds it");
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

        // Decoded only AFTER the signature verified, deliberately: the ack fields
        // are inside `msg_sig`'s preimage, so until it verifies they are a claim
        // by nobody. Decoding first would build a `PeerAck` — the type whose whole
        // job is to be an unmerged claim — out of unauthenticated bytes.
        let peer_ack = match piggybacked_ack(&body) {
            Ok(ack) => ack,
            Err(e) => {
                body.body.zeroize();
                return Err(e);
            }
        };

        Ok(VerifiedFrame {
            seq: self.header.seq,
            sent_unix_ms: body.sent_unix_ms,
            body: body.body,
            peer_ack,
        })
    }

    /// Open and verify an ACCEPT: the acceptor's first frame, whose sealed body
    /// carries the pseudonym key every later frame of this conversation is
    /// verified against.
    ///
    /// **This is the only entry point that does not already know
    /// `author.pc`.** Every other open takes the pseudonym as a parameter,
    /// because both ends learned it at first contact — except the initiator,
    /// which never sees the acceptor's. So the key arrives here, inside the
    /// seal, and the two questions that make trusting it sound are asked in
    /// order:
    ///
    /// 1. **Is this the position an acceptance can occupy?** The acceptor's
    ///    sequence zero on the acceptor's own direction, and nothing else —
    ///    [`DmFrameError::NotAccept`] otherwise. The position is `found_at`'s,
    ///    i.e. the collector's own knowledge, never the frame's claim, so a
    ///    frame cannot nominate itself as an acceptance.
    /// 2. **Did the identity we knocked at vouch for this pseudonym?**
    ///    `bind_lt` is verified under `peer_pk_lt` — a key this side already
    ///    holds and did not learn from the frame — over the same
    ///    [`bind_lt_input`] preimage a first-contact entry carries in the other
    ///    direction. Without that step the sealed pseudonym would be
    ///    self-asserted by whoever holds the message key.
    ///
    /// Only then is the frame verified as an ordinary frame, under the carried
    /// pseudonym, so `msg_sig` proves possession of the key just installed.
    ///
    /// A failure here commits nothing: the caller runs this as
    /// [`crate::dm::ratchet::Ratchet::receive`]'s closure, which restores the
    /// ratchet when the closure returns `Err`, so a forged acceptance costs one
    /// refused open and no key.
    pub fn open_accept(
        &self,
        key: &MessageKey,
        chan_id: &[u8; ROOT_LEN],
        dir: Direction,
        found_at: PagePosition,
        recipient_hash: &[u8; RECIPIENT_HASH_LEN],
        peer_pk_lt: &[u8; ml_dsa::PK_LEN],
    ) -> Result<VerifiedAccept, DmFrameError> {
        if dir != Direction::BToA
            || found_at.seq() != crate::dm::ratchet::FIRST_RECIPIENT_CHANNEL_SEQ
        {
            return Err(DmFrameError::NotAccept {
                seq: found_at.seq(),
            });
        }
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

        // Every path below holds the peer's cleartext, so each one clears it
        // before returning — the same discipline [`Self::open`] keeps, and for
        // the same reason: a key-holding peer can reach all of them.
        let outcome = self.verified_binding(&body, chan_id, dir, recipient_hash, peer_pk_lt);
        let pk_pc = match outcome {
            Ok(pk_pc) => pk_pc,
            Err(e) => {
                body.body.zeroize();
                return Err(e);
            }
        };
        let peer_ack = match piggybacked_ack(&body) {
            Ok(ack) => ack,
            Err(e) => {
                body.body.zeroize();
                return Err(e);
            }
        };

        Ok(VerifiedAccept {
            frame: VerifiedFrame {
                seq: self.header.seq,
                sent_unix_ms: body.sent_unix_ms,
                body: body.body,
                peer_ack,
            },
            peer_pk_pc: pk_pc,
        })
    }

    /// The binding half of [`Self::open_accept`], split out so every error path
    /// above it clears the plaintext in one place.
    fn verified_binding(
        &self,
        body: &wire::DmChannelBody,
        chan_id: &[u8; ROOT_LEN],
        dir: Direction,
        recipient_hash: &[u8; RECIPIENT_HASH_LEN],
        peer_pk_lt: &[u8; ml_dsa::PK_LEN],
    ) -> Result<Box<[u8; ml_dsa::PK_LEN]>, DmFrameError> {
        if body.pk_pc.is_empty() && body.bind_lt.is_empty() {
            return Err(DmFrameError::MissingBinding);
        }
        let pk_pc: Box<[u8; ml_dsa::PK_LEN]> = Box::new(exact("pk_pc", &body.pk_pc)?);
        // **The binding signature is NOT checked here.** [`Self::verify`] below
        // checks it, under an author whose `pc` is the key just read out and
        // whose `lt` is `peer_pk_lt` — the same signature over the same
        // preimage under the same key. Doing it twice would be two
        // authenticating paths for one statement, which is how a claim gets
        // read off the path that was not checked. This function's job is to say
        // *which key* the frame is claiming; whether the claim holds is one
        // check, in one place, on every frame that carries the fields.
        self.verify(
            body,
            chan_id,
            dir,
            recipient_hash,
            AuthorKeys {
                pc: &pk_pc,
                lt: peer_pk_lt,
            },
        )?;
        Ok(pk_pc)
    }

    /// The post-decryption half of [`Self::open`]: the body cap a non-conforming
    /// peer can exceed, the pseudonym pinning, and the authorship signature.
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
        // **Pinning, and it runs before the signature.** A body that carries a
        // pseudonym key at all must carry the one already in hand: a peer that
        // rotated its pseudonym mid-conversation would otherwise present a
        // frame that verifies perfectly under a key nobody vouched for. Refused
        // here as a pinning violation rather than left to fail as a signature,
        // because the two say different things. A body carrying no key — every
        // ordinary frame — takes the path it always took, byte for byte.
        if !body.pk_pc.is_empty() || !body.bind_lt.is_empty() {
            let pk_pc: [u8; ml_dsa::PK_LEN] = exact("pk_pc", &body.pk_pc)?;
            if pk_pc.as_slice() != author.pc.as_slice() {
                return Err(DmFrameError::PseudonymMismatch);
            }
            let bind_lt: [u8; ml_dsa::SIG_LEN] = exact("bind_lt", &body.bind_lt)?;
            verify_signature(author.lt, &bind_lt_input(author.lt, &pk_pc), &bind_lt)
                .map_err(|_| DmFrameError::Binding)?;
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
            body.ack_high_water,
            &body.ack_beyond,
        );
        let verified = verify_signature(author.pc, &preimage, &msg_sig);
        preimage.zeroize();
        verified.map_err(|_| DmFrameError::Signature)
    }
}

/// Read the acknowledgement a verified body piggybacked, if it carried one.
///
/// **"Carried one" is `ack_high_water.is_some() || !ack_beyond.is_empty()`**, and
/// the asymmetry between the two is the encoding's, not a choice made here.
/// [`AckState::encode_beyond`] always emits at least its two-byte run count, so a
/// piggybacked acknowledgement of zero runs is `[0, 0]` and only a frame that
/// piggybacked *nothing* leaves `ack_beyond` empty. An absent prefix, by
/// contrast, is a real state that a real acknowledgement carries — so both fields
/// have to be consulted, and the all-default pair is the one shape that means "no
/// acknowledgement here".
///
/// A present prefix with empty run bytes therefore reaches
/// [`AckState::decode_unvalidated`] and is refused there as malformed, which is
/// correct: it is a spelling [`AckState::encode_beyond`] cannot produce, and this
/// module does not invent a second one.
///
/// What comes back is a [`PeerAck`] — the peer's claim, checked against nothing
/// we know. Merging it is [`AckState::merge_peer_ack`]'s job and happens
/// elsewhere; nothing here can read a settlement verdict off it.
fn piggybacked_ack(body: &wire::DmChannelBody) -> Result<Option<PeerAck>, DmFrameError> {
    if body.ack_high_water.is_none() && body.ack_beyond.is_empty() {
        return Ok(None);
    }
    AckState::decode_unvalidated(body.ack_high_water, &body.ack_beyond)
        .map(Some)
        .map_err(DmFrameError::PiggybackedAck)
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
///
/// **Not `Clone`, `PartialEq` or `Eq`, and that follows from [`Self::peer_ack`]
/// rather than from a decision taken here.** [`PeerAck`] deliberately carries
/// none of the three: it is moved into [`AckState::merge_peer_ack`] exactly once,
/// and equality would let an unmerged claim be read out by bisection against
/// states the caller builds itself. A frame that owns one cannot hand those back
/// by derive without reopening the surface `ack.rs` closed.
#[derive(Debug)]
pub struct VerifiedFrame {
    /// The position it occupies. Taken from the header rather than the body, and
    /// checked against the slot the frame was read from — both facts, not one.
    pub seq: u64,
    /// Sender-asserted and signed. Display only.
    pub sent_unix_ms: i64,
    /// The message.
    pub body: String,
    /// The sender's own collection state, if this message piggybacked it —
    /// `None` when the frame acknowledged nothing.
    ///
    /// **A claim, not a verdict.** It is authenticated: the two fields it was
    /// decoded from are inside `msg_sig`'s preimage, so holding this frame proves
    /// the sender wrote this acknowledgement, exactly as it proves the sender
    /// wrote the body. What it is *not* is checked against what we have actually
    /// sent — [`PeerAck`] has no settlement query surface for precisely that
    /// reason, and the ceiling lives on [`AckState::merge_peer_ack`], which
    /// consumes this by value. A piggybacked acknowledgement therefore takes the
    /// identical decode → verify → merge path a standalone
    /// [`crate::dm::ack_record`] one takes; only the *verify* step differs, and
    /// only in what authenticates it — this frame's `msg_sig` rather than a
    /// second signature of the acknowledgement's own.
    pub peer_ack: Option<PeerAck>,
}

/// A verified ACCEPT: the frame, plus the pseudonym key it installed.
///
/// Only constructible via [`ParsedFrame::open_accept`], so holding one is the
/// proof that the identity this conversation was opened against vouched for
/// that key — not merely that some key arrived.
///
/// Not `Clone`, `PartialEq` or `Eq`, inherited from [`VerifiedFrame`] and for
/// that type's stated reason.
pub struct VerifiedAccept {
    /// The frame itself, verified under the pseudonym below.
    pub frame: VerifiedFrame,
    /// The acceptor's per-contact pseudonym key, bound to the long-term
    /// identity the initiator knocked at.
    pub peer_pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
}

/// Hand-written: the pseudonym is a public key rather than a secret, but the
/// frame it arrives with carries the peer's cleartext, and a derived `Debug`
/// would print it.
impl std::fmt::Debug for VerifiedAccept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedAccept")
            .field("seq", &self.frame.seq)
            .field("sent_unix_ms", &self.frame.sent_unix_ms)
            .field("body_len", &self.frame.body.len())
            .field("has_peer_ack", &self.frame.peer_ack.is_some())
            .field("peer_pk_pc", &"<installed>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::firstcontact::{FRAME_KIND_FIRST_CONTACT, recipient_hash};
    use crate::dm::paging::{PAGE_SLOTS, position_of};
    use crate::dm::ratchet::{
        EphemeralDecapKey, FIRST_RECIPIENT_CHANNEL_SEQ, Ratchet, ReconnectSide, Role,
    };
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

    /// The same, one layer in: an edit applied to a decoded body before it is
    /// re-sealed under the honest key, which is the only way to reach a field
    /// that lives inside the seal.
    type BodyMutation = Box<dyn Fn(&mut wire::DmChannelBody)>;

    /// An acknowledgement of two collected positions, ten apart, so the encoded
    /// run set is short but neither half of it is a default value.
    fn small_ack() -> AckState {
        let mut ack = AckState::new();
        ack.collect(0).unwrap();
        ack.collect(10).unwrap();
        ack
    }

    /// An acknowledgement with settled positions but NO contiguous prefix:
    /// `high_water() == None`, two runs beyond it.
    ///
    /// The shape a receiver reaches when the head of the conversation is lost —
    /// sequences 0..=3 never arrived, 4, 5 and 9 did — which is the case the runs
    /// encoding exists for. Every other fixture here collects zero first, so
    /// without this one nothing on the real `seal → parse → open` path ever
    /// carries an absent prefix, and the `is_some() || !is_empty()` presence test
    /// is exercised only through the private helper.
    fn headless_ack() -> AckState {
        let mut ack = AckState::new();
        ack.collect(4).unwrap();
        ack.collect(5).unwrap();
        ack.collect(9).unwrap();
        assert_eq!(ack.high_water(), None, "the fixture must have no prefix");
        assert_eq!(ack.runs(), 2, "4..=5 and 9..=9");
        ack
    }

    /// The largest acknowledgement [`AckState`] will carry: a prefix, plus
    /// [`crate::dm::ack::MAX_ACK_RUNS`] runs beyond it.
    ///
    /// Even sequences from 2 upwards, so every run is a single position with one
    /// unsettled position between it and its neighbour — the shape that packs the
    /// most runs into the fewest sequence numbers. Sequence 0 is collected first
    /// so the prefix is `Some(0)` rather than absent, and 1 is left out so the
    /// prefix cannot swallow the rest.
    fn maximal_ack() -> AckState {
        let mut ack = AckState::new();
        ack.collect(0).unwrap();
        for i in 0..crate::dm::ack::MAX_ACK_RUNS as u64 {
            ack.collect(2 + i * 2).unwrap();
        }
        assert_eq!(
            ack.runs(),
            crate::dm::ack::MAX_ACK_RUNS,
            "the fixture must be saturated, or it measures a smaller worst case \
             than the one that can actually be sealed"
        );
        ack
    }

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
        /// The acceptor's per-contact pseudonym — what its ACCEPT carries and
        /// every later frame of its direction is verified against.
        ///
        /// **Distinct from `b.signing`, and that is load-bearing.** `bind_lt`
        /// is a signature by the long-term key over the pseudonym; if the two
        /// were one key the preimage would be `lp(k) || lp(k)` and a mutant
        /// that verified the binding against the wrong one of them would pass.
        b_pc: SignKeypair,
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
            b_pc: pseudonym(0xB1),
            init,
            recip,
        }
    }

    /// A standalone signing key, for the per-contact pseudonyms and for the
    /// third-party keys the forgery tests sign under.
    fn pseudonym(tag: u8) -> SignKeypair {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[tag; crate::identity::keys::ML_DSA_SEED_LEN])
            .expect("pseudonym keygen")
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
            self.send_acked(body, None)
        }

        /// As [`Self::send_keyed`], with an acknowledgement piggybacked on the
        /// message.
        fn send_acked(&mut self, body: &str, ack: Option<&AckState>) -> (Vec<u8>, MessageKey) {
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
                ack,
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

        /// The acceptor's ACCEPT: its first channel write, at sequence zero,
        /// carrying `b_pc` and that key's binding under `b.signing`.
        fn accept(&mut self, ack: Option<&AckState>) -> (Vec<u8>, MessageKey) {
            let out = self.recip.send_next().expect("the acceptor's chain steps");
            assert_eq!(out.header.seq, FIRST_RECIPIENT_CHANNEL_SEQ);
            let key = out.key.clone();
            let bytes = seal_accept(
                out,
                &[1u8; ROOT_LEN],
                &self.b_pc,
                &self.b.signing,
                &recipient_hash(self.a.signing.public_key()).unwrap(),
                SENT,
                ack,
            )
            .expect("the acceptance seals");
            (bytes, key)
        }

        /// An ORDINARY frame from the acceptor, at whatever sequence its chain
        /// is up to — the shape every reply after the acceptance takes.
        fn b_send(&mut self, body: &str) -> (Vec<u8>, MessageKey, u64) {
            let out = self.recip.send_next().expect("the acceptor's chain steps");
            let key = out.key.clone();
            let seq = out.header.seq;
            let bytes = seal(
                out,
                &[1u8; ROOT_LEN],
                &self.b_pc,
                self.b.signing.public_key(),
                &recipient_hash(self.a.signing.public_key()).unwrap(),
                SENT,
                body,
                None,
            )
            .expect("the reply seals");
            (bytes, key, seq)
        }

        /// The hash the acceptor addresses its frames to — the initiator's.
        fn to_a(&self) -> [u8; RECIPIENT_HASH_LEN] {
            recipient_hash(self.a.signing.public_key()).unwrap()
        }

        /// Re-seal one of the acceptor's frames under the same honest key with
        /// its decoded body edited.
        ///
        /// The only way to reach a field that lives inside the seal: a body a
        /// key-holding peer composes is exactly what an attack on the binding
        /// has to produce, and no public API will compose one.
        fn reseal(&self, bytes: &[u8], key: &MessageKey, edit: BodyMutation) -> Vec<u8> {
            let parsed = parse(bytes).expect("the honest frame parses");
            let mut plaintext = open_envelope(
                &aes_key(key).unwrap(),
                &frame_aad(
                    &[1u8; ROOT_LEN],
                    Direction::BToA,
                    &parsed.header,
                    &parsed.eph_ek,
                    parsed.eph_ct(),
                ),
                &parsed.sealed,
            )
            .expect("the honest frame opens");
            let encoded = crate::dm::unpad(&plaintext).expect("padded").to_vec();
            plaintext.zeroize();
            let mut body = wire::DmChannelBody::decode(&encoded[..]).expect("decodes");
            edit(&mut body);
            let padded =
                crate::dm::pad_to_bucket(&body.encode_to_vec(), PAD_BUCKETS).expect("fits");
            let sealed = seal_envelope(
                &aes_key(key).unwrap(),
                &frame_aad(
                    &[1u8; ROOT_LEN],
                    Direction::BToA,
                    &parsed.header,
                    &parsed.eph_ek,
                    parsed.eph_ct(),
                ),
                &padded,
            )
            .expect("re-seals");
            wire::DmChannelFrame {
                ratchet_gen: parsed.header.generation,
                chain_base: parsed.header.chain_base,
                seq: parsed.header.seq,
                eph_ek: parsed.eph_ek.to_vec(),
                eph_ct: parsed.eph_ct().map(|c| c.to_vec()).unwrap_or_default(),
                sealed,
            }
            .encode_to_vec()
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
            Some(KAT_ACK_HIGH_WATER),
            KAT_ACK_BEYOND,
        ))
        .unwrap();
        assert_eq!(hex::encode(sig_input), SIG_INPUT_KAT);

        // The same preimage with NO acknowledgement piggybacked. Pinned
        // separately because the vector above cannot witness it: a build that
        // dropped the two ack components entirely would move that hash, but so
        // would any other change to them, and the no-ack shape is the one every
        // frame composed before this field existed produced.
        let no_ack = sha384(&frame_sig_input(
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
            None,
            &[],
        ))
        .unwrap();
        assert_eq!(hex::encode(no_ack), SIG_INPUT_NO_ACK_KAT);

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
        //
        // The ack components deliberately ride along here and are non-empty, so
        // the ciphertext's own component is no longer the last thing in the
        // buffer and the tail has to be stripped before it can be examined. That
        // is the point: an `ends_with` on the whole preimage would now be
        // satisfied by the acknowledgement's bytes and would pin nothing.
        let sig_with_ack = |eph_ct| {
            frame_sig_input(
                &[1u8; ROOT_LEN],
                Direction::AToB,
                &header(),
                &eph_ek,
                eph_ct,
                &[2u8; RECIPIENT_HASH_LEN],
                AuthorKeys {
                    pc: a.signing.public_key(),
                    lt: b.signing.public_key(),
                },
                0x0a0b_0c0d_0e0f_1011,
                "ab",
                Some(KAT_ACK_HIGH_WATER),
                KAT_ACK_BEYOND,
            )
        };
        let mut ack_tail = Vec::new();
        push_lp(&mut ack_tail, &KAT_ACK_HIGH_WATER.to_be_bytes());
        push_lp(&mut ack_tail, KAT_ACK_BEYOND);

        let absent = sig_with_ack(None);
        assert!(
            absent.ends_with(&ack_tail),
            "the acknowledgement must be the last two components"
        );
        assert!(
            absent[..absent.len() - ack_tail.len()].ends_with(&0u64.to_be_bytes()),
            "an absent generation ciphertext must be bound as lp(&[])"
        );
        let present = sig_with_ack(Some(&ct));
        assert_eq!(
            present.len(),
            absent.len() + ml_kem::CT_LEN,
            "the two cases must differ by exactly the ciphertext, so the length \
             prefix is present in both"
        );
    }

    /// A high-water and a run encoding with distinct bytes in every position, so
    /// the known-answer vector above cannot survive an endianness flip in either.
    const KAT_ACK_HIGH_WATER: u64 = 0x3132_3334_3536_3738;
    const KAT_ACK_BEYOND: &[u8] = &[0x41, 0x42, 0x43, 0x44];

    const SIG_INPUT_KAT: &str = concat!(
        "49d4909b3af9bdf995742112636baa7cf92956aee7e894e3e2fb0c4f",
        "0808f3fc9ec9f30e4f9a6e9323580b72facdb2f5"
    );
    const SIG_INPUT_NO_ACK_KAT: &str = concat!(
        "1e2adf8c2d46ebcd63ce48c6e8b8dac21f0ca2988952eec702fef077",
        "2fe04a78978d130b5f5684bc38143f00e5eddaaf"
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
        //
        // The piggybacked acknowledgement is held FIXED here and varied by
        // `sig_ack` below instead: every assertion in this block is about some
        // other field being bound independently, and a fixed non-empty ack is
        // what keeps each of them honest about the components that follow it.
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
                    Some(KAT_ACK_HIGH_WATER),
                    KAT_ACK_BEYOND,
                )
            };
        let sig_ack = |hw, beyond: &[u8]| {
            frame_sig_input(
                &[1u8; ROOT_LEN],
                Direction::AToB,
                &h,
                &ek1,
                Some(&ct),
                &[2u8; RECIPIENT_HASH_LEN],
                AuthorKeys {
                    pc: a.signing.public_key(),
                    lt: b.signing.public_key(),
                },
                SENT,
                "hello",
                hw,
                beyond,
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

        // The piggybacked acknowledgement, both halves. `base` carries
        // `(Some(KAT_ACK_HIGH_WATER), KAT_ACK_BEYOND)`, so each of these is one
        // component moved and nothing else.
        assert_eq!(
            base,
            sig_ack(Some(KAT_ACK_HIGH_WATER), KAT_ACK_BEYOND),
            "the control: `sig_ack`'s fixed arguments must reproduce `base`, or \
             every assertion below it is comparing two unrelated preimages"
        );
        assert_ne!(
            base,
            sig_ack(Some(KAT_ACK_HIGH_WATER + 1), KAT_ACK_BEYOND),
            "the acknowledged prefix must be bound"
        );
        assert_ne!(
            base,
            sig_ack(Some(KAT_ACK_HIGH_WATER), &[0x41, 0x42, 0x43, 0x45]),
            "the acknowledged runs must be bound"
        );
        assert_ne!(
            base,
            sig_ack(None, KAT_ACK_BEYOND),
            "an absent prefix must not bind as the prefix it happened to follow"
        );
        assert_ne!(
            sig_ack(None, KAT_ACK_BEYOND),
            sig_ack(Some(0), KAT_ACK_BEYOND),
            "`None` says nothing was collected and `Some(0)` says sequence zero \
             was — a preimage that could not tell them apart would let one be \
             replayed as the other"
        );
        // The two halves must not be able to trade bytes with each other: a
        // preimage that concatenated them without length prefixes would let a
        // prefix's trailing byte be read as the run set's leading one.
        assert_ne!(
            sig_ack(Some(0x0000_0000_0000_0041), &[0x42, 0x43, 0x44]),
            sig_ack(Some(0), &[0x41, 0x42, 0x43, 0x44]),
        );

        // The AAD must separate the same way. The acknowledgement is NOT in it —
        // it rides inside the sealed body, which the AAD covers wholesale — so
        // there is deliberately no ack case here.
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
            None,
            &[],
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

    /// A receiving chain that has opened nothing takes its base from the frame's
    /// clear header, and here it does so on the production path: a real seal, a
    /// real parse, and the ratchet driving [`ParsedFrame::open`].
    ///
    /// **The control is the point.** `chain_base` is bound in the AAD, so the
    /// base the chain re-bases to and the base the sender sealed under must be
    /// the same number or the frame cannot open. A passthrough closure derives a
    /// key and asks nothing of it; only a real open puts the two in contact.
    #[test]
    fn a_re_based_receive_chain_opens_a_sealed_frame_and_refuses_an_edited_base() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let a = alice();
        let b = bob();
        let a_pc = keys(PHRASE_B);

        // The initiating side opened at the lowest sequence still awaiting a key;
        // the answering side at the number it was told its correspondent would
        // write next, which is higher.
        let rerooted = crate::dm::resume::reroot(
            &crate::dm::resume::CommittedRoot::from_bytes(
                &[0x5c; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            &[0x09; 32],
        )
        .expect("the module is operational");
        let ar = [0x71u8; ROOT_LEN];
        let mut writer = Ratchet::reestablished(
            &rerooted,
            Role::Initiator,
            ReconnectSide::Initiated {
                last_persisted_generation: 6,
            },
            7,
            37,
            &ar,
        )
        .expect("the initiating side opens");
        let mut answering = Ratchet::reestablished(
            &rerooted,
            Role::Recipient,
            ReconnectSide::Answered {
                last_persisted_generation: 6,
                peer_next_send_seq: 40,
            },
            7,
            900,
            &ar,
        )
        .expect("the answering side opens");

        let out = writer.send_next().expect("the reserved position mints");
        assert_eq!(out.header.chain_base, 37);
        assert_eq!(out.header.seq, 37);
        let rcpt = recipient_hash(b.signing.public_key()).unwrap();
        let bytes = seal(
            out,
            &[1u8; ROOT_LEN],
            &a_pc.signing,
            a.signing.public_key(),
            &rcpt,
            SENT,
            "waiting since before the exchange",
            None,
        )
        .expect("the frame seals");

        let dir = answering.recv_direction();
        let author = AuthorKeys {
            pc: a_pc.signing.public_key(),
            lt: a.signing.public_key(),
        };
        let open_with = |r: &mut Ratchet, frame: &[u8]| {
            let parsed = parse(frame).unwrap();
            let at = position_of(parsed.header().seq);
            r.receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |mk| {
                parsed.open(mk, &[1u8; ROOT_LEN], dir, at, &rcpt, author)
            })
        };

        // The control runs FIRST, so the honest open cannot be what left the
        // chain unable to take it: the same frame with the AAD-bound base edited
        // to the number the chain started on. The chain's fields are private to
        // the ratchet, so what is asserted here is what a caller can observe —
        // the refusal, the unchanged loss counts, and, below, that the honest
        // frame still opens afterwards. That last one is the state assertion: a
        // chain that had committed a base of 40 on this failed frame could never
        // derive the key the honest frame at base 37 was sealed under.
        let losses = answering.losses();
        let edit_base_to = |to: u64| {
            let mut decoded = wire::DmChannelFrame::decode(&bytes[..]).unwrap();
            decoded.chain_base = to;
            decoded.encode_to_vec()
        };

        // A base ABOVE the frame's own sequence never reaches the AEAD: the
        // receive path refuses that shape outright, before any key is derived.
        assert!(
            matches!(
                open_with(&mut answering, &edit_base_to(40)),
                Err(crate::dm::ratchet::RatchetError::SeqBeforeChainBase {
                    chain_base: 40,
                    seq: 37
                })
            ),
            "a base above the frame's own sequence must be refused outright"
        );

        // A base BELOW it is a shape the chain would re-base to, so this one does
        // reach the open — and fails there, because the AAD binds the base the
        // sender actually sealed under.
        assert!(
            matches!(
                open_with(&mut answering, &edit_base_to(36)).expect("no key-schedule failure"),
                Err(DmFrameError::Aead)
            ),
            "an edited base must fail the AEAD open"
        );
        assert_eq!(
            answering.losses(),
            losses,
            "a frame that did not open moved the loss counts"
        );

        // The open is itself the proof of the re-base: a chain still positioned
        // at 40 would derive a different key for sequence 37, and `chain_base` is
        // bound in the AAD, so the frame would not open at all.
        let opened = open_with(&mut answering, &bytes)
            .expect("no key-schedule failure")
            .expect("the frame opened");
        assert_eq!(opened.body, "waiting since before the exchange");
        assert_eq!(opened.seq, 37);

        // And the cursor landed one past it rather than anywhere else.
        let next_out = writer.send_next().expect("the next position mints");
        assert_eq!(next_out.header.seq, 38);
        let next_bytes = seal(
            next_out,
            &[1u8; ROOT_LEN],
            &a_pc.signing,
            a.signing.public_key(),
            &rcpt,
            SENT,
            "the one after",
            None,
        )
        .expect("the frame seals");
        let second = open_with(&mut answering, &next_bytes)
            .expect("no key-schedule failure")
            .expect("the frame opened");
        assert_eq!(second.seq, 38);
        assert_eq!(
            answering.losses().pending,
            0,
            "the two frames were contiguous, so nothing was stepped over"
        );
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
            None,
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
            None,
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

        // **`msg_sig` is mandatory on the ACCEPTANCE too, and it is bound to
        // the key the acceptance CARRIES.** This is the one frame whose author
        // key is not known in advance, so the binding could be satisfied while
        // the authorship signature was somebody else's: a genuine binding over
        // a pseudonym, spliced onto a frame signed by a different one, would
        // install a key its holder never proved possession of. The signature is
        // what refuses it, and it refuses it as a signature failure — the
        // binding above verified.
        let mut q = pair();
        let (accept, accept_key) = q.accept(None);
        let other_pc = pseudonym(0xD7);
        let other_pk = *other_pc.public_key();
        let genuine_bind =
            q.b.signing
                .sign(&bind_lt_input(q.b.signing.public_key(), &other_pk))
                .unwrap();
        let swapped = q.reseal(
            &accept,
            &accept_key,
            Box::new(move |b: &mut wire::DmChannelBody| {
                b.pk_pc = other_pk.to_vec();
                b.bind_lt = genuine_bind.to_vec();
            }),
        );
        let verdict = parse(&swapped).unwrap().open_accept(
            &accept_key,
            &[1u8; ROOT_LEN],
            Direction::BToA,
            position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
            &q.to_a(),
            q.b.signing.public_key(),
        );
        assert!(
            matches!(verdict, Err(DmFrameError::Signature)),
            "an acceptance signed under a key other than the one it carries must \
             fail the authorship signature, got {verdict:?}"
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
        // ...and a MAXIMAL piggybacked acknowledgement, for the same reason: a
        // frame that carried none would under-count by the full 1026-byte run
        // set plus its prefix, and the constant below is what storage capacities
        // are sized against.
        let worst = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.b.signing,
            p.b.signing.public_key(),
            &recipient_hash(p.a.signing.public_key()).unwrap(),
            SENT,
            &"x".repeat(DM_BODY_CAP),
            Some(&maximal_ack()),
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

        // The ACCEPT is measured here too, because it is the one frame shape
        // whose size is not a function of its body: an empty body plus a
        // 2592-byte pseudonym and a 4627-byte binding lands it on the TOP rung
        // regardless. That is what would silently move if either field grew, so
        // it is pinned against the ladder rather than left to the body cap.
        let mut q = pair();
        let (accept, accept_key) = q.accept(None);
        assert!(
            accept.len() <= WORST_CASE_SEALED_FRAME_LEN,
            "an acceptance is {} bytes against the measured worst case of \
             {WORST_CASE_SEALED_FRAME_LEN}",
            accept.len()
        );

        // Which rung, measured rather than inferred from the frame's length —
        // a frame carries protobuf and ephemeral overhead the rung does not.
        // An empty ORDINARY frame from the same chain is the control: it holds
        // the same overhead and lands on the SMALLER rung, so the difference
        // between the two sealed fields is exactly one step of the ladder.
        let (plain, _, _) = q.b_send("");
        let accept_sealed = parse(&accept).unwrap().sealed.len();
        let plain_sealed = parse(&plain).unwrap().sealed.len();
        assert_eq!(
            accept_sealed - plain_sealed,
            PAD_BUCKETS[1] - PAD_BUCKETS[0],
            "an acceptance must sit one rung above an empty ordinary frame — \
             {accept_sealed} against {plain_sealed}"
        );
        // ...and the control that the smaller of the two really is the smaller
        // rung, without which the difference above is satisfied by both frames
        // moving together.
        assert!(
            plain_sealed > PAD_BUCKETS[0] && plain_sealed < PAD_BUCKETS[1],
            "an empty ordinary frame must sit on the 8192 rung, got {plain_sealed}"
        );
        let _ = accept_key;
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
                None,
                &[],
            ))
            .unwrap();
        let encoded = wire::DmChannelBody {
            sent_unix_ms: SENT,
            body: body.clone(),
            msg_sig: msg_sig.to_vec(),
            ack_high_water: None,
            ack_beyond: Vec::new(),
            pk_pc: Vec::new(),
            bind_lt: Vec::new(),
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

        // **The same discipline on the ACCEPTANCE path**, which is a separate
        // seam: `open_accept` runs as the closure of the INITIATOR's ratchet,
        // and a forged acceptance must cost one refused open rather than the
        // key that opens the real one. Without this, a forgery would consume
        // sequence zero and the genuine acceptance behind it would come back as
        // `AlreadyConsumed` — a conversation permanently unable to verify its
        // correspondent, from one frame anybody able to write the page can
        // plant.
        let mut q = pair();
        let (accept, key) = q.accept(None);
        let stranger = pseudonym(0xC3);
        let forged_sig = stranger
            .sign(&bind_lt_input(stranger.public_key(), q.b_pc.public_key()))
            .unwrap();
        let forged = q.reseal(
            &accept,
            &key,
            Box::new(move |b: &mut wire::DmChannelBody| b.bind_lt = forged_sig.to_vec()),
        );
        let rcpt = q.to_a();
        let pk_lt_b = *q.b.signing.public_key();
        let dir = q.init.recv_direction();
        let at = position_of(FIRST_RECIPIENT_CHANNEL_SEQ);
        let before = (q.init.generation(), q.init.losses());

        let parsed = parse(&forged).unwrap();
        let outcome = q
            .init
            .receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |k| {
                parsed.open_accept(k, &[1u8; ROOT_LEN], dir, at, &rcpt, &pk_lt_b)
            })
            .expect("the ratchet accepts the position");
        assert!(
            matches!(outcome, Err(DmFrameError::Binding)),
            "a forged acceptance must fail inside the closure, got {outcome:?}"
        );
        assert_eq!(
            (q.init.generation(), q.init.losses()),
            before,
            "a forged acceptance must not move the initiator's ratchet"
        );

        // And the genuine acceptance, through the same seam, still installs.
        let honest = parse(&accept).unwrap();
        let installed = q
            .init
            .receive(honest.header(), honest.eph_ct(), honest.eph_ek(), |k| {
                honest.open_accept(k, &[1u8; ROOT_LEN], dir, at, &rcpt, &pk_lt_b)
            })
            .expect("the ratchet accepts the position")
            .expect("the honest acceptance opens");
        assert_eq!(
            installed.peer_pk_pc.as_slice(),
            q.b_pc.public_key().as_slice(),
            "the key sequence zero was holding must still be reachable"
        );
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

    /// A sealed frame republished into a DIFFERENT CARRIER RECORD is refused, and
    /// refused where the slot index alone cannot tell the two records apart
    /// (ISC-A-C21).
    ///
    /// **The neighbouring misfiling test moves both the page and the slot; this one
    /// moves only the page.** A channel page is one DHT record, so a frame taken
    /// from the record at page 3 and written into the record at page 5 is the same
    /// bytes carried by a different record — which is what replay across carrier
    /// records means here. Choosing the SAME slot in that record is what makes the
    /// probe sharp: a check comparing slot indices sees two nines and admits the
    /// frame, while `open` compares the sequence number the position resolves to and
    /// refuses it.
    ///
    /// Nothing else in the system holds both facts. The record and the slot say
    /// where the bytes were found; the header says where their author put them; and
    /// `msg_sig` binds the sequence number but not the record it arrived in, so a
    /// signature check alone passes a frame that has been moved wholesale.
    #[test]
    fn a_frame_replayed_into_another_carrier_record_is_refused() {
        let mut p = pair();
        advance_send_to(&mut p.init, DISTINCT_SEQ);
        let (bytes, key) = p.send_keyed("replayed");
        let parsed = parse(&bytes).unwrap();
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let dir = p.recip.recv_direction();

        let honest = position_of(parsed.header().seq);
        // The same slot of a different page, which is a different record. Asserted
        // rather than assumed: the whole probe rests on these two positions sharing
        // a slot and differing in page, and an arithmetic slip either way would
        // leave it testing what the neighbouring misfiling test already tests.
        let elsewhere = position_of(5 * PAGE_SLOTS as u64 + 9);
        assert_eq!(
            (honest.page(), honest.slot()),
            (3, 9),
            "the honest position must be page 3, slot 9"
        );
        assert_eq!(
            (elsewhere.page(), elsewhere.slot()),
            (5, 9),
            "the replay target must be another page at the SAME slot, or this probe              is the misfiling test again"
        );

        assert!(matches!(
            parsed.open(&key, &[1u8; ROOT_LEN], dir, elsewhere, &rcpt, author),
            Err(DmFrameError::Misplaced { .. })
        ));
        // The control: the frame is a good frame in its own record, so the refusal
        // above is about where it was found and not about the frame.
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
            None,
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

    /// The piggyback path end to end: an acknowledgement composed into an
    /// outbound message comes back out of the opened frame as the same claim,
    /// and the frame's own signature is what authenticated it.
    ///
    /// The round trip is asserted through `sig_input` rather than through a
    /// merge, because a merge would answer from *our* state and could pass on a
    /// `PeerAck` carrying something else entirely. `sig_input` is a pure function
    /// of what the peer actually stated, so comparing it against the preimage the
    /// sender's own state produces pins the statement itself.
    #[test]
    fn an_acknowledgement_piggybacked_on_a_message_round_trips() {
        let mut p = pair();
        let sent = small_ack();
        let (bytes, _) = p.send_acked("with an ack", Some(&sent));

        let got = p.recv(&bytes).unwrap();
        assert_eq!(got.body, "with an ack");
        let peer = got.peer_ack.expect("the frame carried an acknowledgement");
        assert_eq!(
            peer.sig_input(&[1u8; ROOT_LEN], Direction::AToB),
            crate::dm::ack::ack_sig_input(&[1u8; ROOT_LEN], Direction::AToB, &sent),
            "the decoded claim must be the state the sender composed"
        );

        // And it is still only a claim: merging is what bounds it, and that
        // happens here rather than anywhere inside this module.
        let mut ours = AckState::new();
        assert_eq!(
            ours.merge_peer_ack(peer, Some(10)).unwrap(),
            crate::dm::ack::PeerAckOutcome::WithinCeiling
        );
        assert!(ours.is_settled(0));
        assert!(ours.is_settled(10));
        assert!(!ours.is_settled(5));
    }

    /// A message that piggybacks nothing round-trips with the field absent, and
    /// the two wire fields stay at their defaults — so a frame composed before
    /// this feature existed parses identically to one composed after it.
    #[test]
    fn a_message_without_an_acknowledgement_round_trips_with_the_field_absent() {
        let mut p = pair();
        let (bytes, key) = p.send_keyed("no ack");

        let parsed = parse(&bytes).unwrap();
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let dir = p.recip.recv_direction();
        let at = position_of(parsed.header().seq);
        let got = parsed
            .open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, author)
            .unwrap();
        assert_eq!(got.body, "no ack");
        assert!(
            got.peer_ack.is_none(),
            "a frame that acknowledged nothing must not manufacture a claim"
        );

        // The wire fields themselves, read out of the opened body: both at their
        // protobuf defaults, which is what makes the pair unambiguous as "no
        // acknowledgement here".
        let plaintext = open_envelope(
            &aes_key(&key).unwrap(),
            &frame_aad(
                &[1u8; ROOT_LEN],
                dir,
                parsed.header(),
                parsed.eph_ek(),
                parsed.eph_ct(),
            ),
            &parsed.sealed,
        )
        .unwrap();
        let body = wire::DmChannelBody::decode(crate::dm::unpad(&plaintext).unwrap()).unwrap();
        assert_eq!(body.ack_high_water, None);
        assert!(body.ack_beyond.is_empty());
    }

    /// Both acknowledgement fields are inside `msg_sig`'s preimage, so editing
    /// either one after sealing invalidates the signature.
    ///
    /// Attacked from INSIDE the seal, the way `the_authorship_signature_is_...`
    /// does not need to: these fields live in the sealed body, so an attacker
    /// without the message key cannot reach them at all. The mutation therefore
    /// has to be performed by a party that holds the key — which is exactly the
    /// threat `msg_sig` exists for, a compromised peer re-filing an authentic
    /// body with a claim it did not sign.
    #[test]
    fn editing_a_piggybacked_acknowledgement_breaks_the_signature() {
        let mut p = pair();
        let out = p.init.send_next().unwrap();
        let key = out.key.clone();
        let dir = out.direction;
        let header = out.header;
        let eph_ek = out.eph_ek.clone();
        let seq = out.header.seq;
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let sent = small_ack();

        let bytes = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.a_pc.signing,
            p.a.signing.public_key(),
            &rcpt,
            SENT,
            "signed ack",
            Some(&sent),
        )
        .unwrap();

        // The control: untouched, it opens and verifies.
        let honest = parse(&bytes).unwrap();
        assert!(
            honest
                .open(&key, &[1u8; ROOT_LEN], dir, position_of(seq), &rcpt, author)
                .is_ok(),
            "the honest frame must open, or every mutation below proves nothing"
        );

        // Re-seal the SAME body with one acknowledgement field edited and the
        // original signature kept. Everything else — key, AAD, header, padding —
        // is identical, so only the signature can reject it.
        //
        // The first row changes NOTHING and expects `Ok`. It is not decoration:
        // the two real mutations run through
        // `open_envelope → decode → mutate → encode → pad_to_bucket →
        // seal_envelope → parse`, and if that pipeline ever stopped reproducing a
        // valid frame — a padding change, a re-encode that dropped a field — both
        // of them would still report `Signature` and this test would pass while
        // proving nothing. The identity row fails in exactly that case, and only
        // in that case. The `honest.open` control above cannot do this job: it
        // reads the ORIGINAL bytes and never enters the pipeline at all.
        let mutations: Vec<(&str, BodyMutation, bool)> = vec![
            (
                "IDENTITY-CONTROL (nothing edited)",
                Box::new(|_: &mut wire::DmChannelBody| {}),
                true,
            ),
            (
                "ack_high_water",
                Box::new(|b: &mut wire::DmChannelBody| {
                    b.ack_high_water = Some(b.ack_high_water.unwrap() + 1)
                }),
                false,
            ),
            (
                "ack_beyond",
                Box::new(|b: &mut wire::DmChannelBody| {
                    let last = b.ack_beyond.len() - 1;
                    b.ack_beyond[last] ^= 0x01;
                }),
                false,
            ),
        ];

        for (field, mutate, must_open) in mutations {
            let plaintext = open_envelope(
                &aes_key(&key).unwrap(),
                &frame_aad(&[1u8; ROOT_LEN], dir, &header, &eph_ek, None),
                &honest.sealed,
            )
            .unwrap();
            let mut body =
                wire::DmChannelBody::decode(crate::dm::unpad(&plaintext).unwrap()).unwrap();
            mutate(&mut body);
            let padded = crate::dm::pad_to_bucket(&body.encode_to_vec(), PAD_BUCKETS).unwrap();
            let sealed = seal_envelope(
                &aes_key(&key).unwrap(),
                &frame_aad(&[1u8; ROOT_LEN], dir, &header, &eph_ek, None),
                &padded,
            )
            .unwrap();
            let tampered = parse(
                &wire::DmChannelFrame {
                    ratchet_gen: header.generation,
                    chain_base: header.chain_base,
                    seq: header.seq,
                    eph_ek: eph_ek.to_vec(),
                    eph_ct: Vec::new(),
                    sealed,
                }
                .encode_to_vec(),
            )
            .unwrap();

            let outcome =
                tampered.open(&key, &[1u8; ROOT_LEN], dir, position_of(seq), &rcpt, author);
            if must_open {
                assert!(
                    outcome.is_ok(),
                    "{field}: the re-seal pipeline must itself reproduce a VALID \
                     frame, or the mutations below reject for the wrong reason \
                     and this test goes vacuous — got {:?}",
                    outcome.err()
                );
            } else {
                assert!(
                    matches!(outcome, Err(DmFrameError::Signature)),
                    "editing {field} must break the authorship signature"
                );
            }
        }
    }

    /// One level up from `ack.rs`'s own
    /// `an_absent_prefix_is_distinguishable_from_a_prefix_of_zero`: the frame
    /// preimage must carry the same distinction, or a message acknowledging
    /// nothing and a message acknowledging sequence zero sign the same bytes.
    #[test]
    fn an_absent_ack_high_water_is_distinguishable_from_a_prefix_of_zero() {
        let a = alice();
        let b = bob();
        let (ek, _) = eph_keypair(5, 6);

        let sig = |hw| {
            frame_sig_input(
                &[1u8; ROOT_LEN],
                Direction::AToB,
                &header(),
                &ek,
                None,
                &[2u8; RECIPIENT_HASH_LEN],
                AuthorKeys {
                    pc: a.signing.public_key(),
                    lt: b.signing.public_key(),
                },
                SENT,
                "hi",
                hw,
                // A real encoding of zero runs, so the two cases differ only in
                // the prefix — `encode_beyond` never yields empty bytes.
                &[0, 0],
            )
        };
        assert_ne!(sig(None), sig(Some(0)));
        // Structurally too: `None` is a zero-LENGTH component, so it is eight
        // bytes shorter than any present prefix rather than an omitted one.
        assert_eq!(sig(Some(0)).len(), sig(None).len() + 8);
    }

    /// The wire pair that means "no acknowledgement" is `(None, empty)` and
    /// nothing else — and a present prefix with no run bytes is refused rather
    /// than read as a prefix-only acknowledgement.
    ///
    /// This is the one asymmetry in the encoding worth pinning: an absent prefix
    /// is a real state a real acknowledgement carries, but empty run bytes are
    /// not — [`AckState::encode_beyond`] always emits its two-byte count. So the
    /// "is there an ack here" test cannot be either field alone.
    #[test]
    fn the_absence_of_a_piggybacked_acknowledgement_is_the_default_pair_only() {
        let body = |ack_high_water, ack_beyond: &[u8]| wire::DmChannelBody {
            sent_unix_ms: SENT,
            body: String::new(),
            msg_sig: Vec::new(),
            ack_high_water,
            ack_beyond: ack_beyond.to_vec(),
            pk_pc: Vec::new(),
            bind_lt: Vec::new(),
        };

        assert!(piggybacked_ack(&body(None, &[])).unwrap().is_none());
        // Zero runs and no prefix is a real acknowledgement — it says "nothing
        // collected yet" — and it is NOT the absent pair.
        assert!(piggybacked_ack(&body(None, &[0, 0])).unwrap().is_some());
        assert!(piggybacked_ack(&body(Some(4), &[0, 0])).unwrap().is_some());
        // A prefix with no run bytes is a spelling `encode_beyond` cannot
        // produce, so it is refused rather than silently completed.
        assert!(matches!(
            piggybacked_ack(&body(Some(4), &[])),
            Err(DmFrameError::PiggybackedAck(
                crate::dm::ack::AckError::Malformed
            ))
        ));
    }

    /// [`WORST_CASE_ACK_FIELDS_LEN`] and [`MAX_ACK_BEYOND_LEN`] are measured, not
    /// asserted: a saturated [`AckState`] is encoded and its two wire fields are
    /// sized with prost's own encoder.
    ///
    /// Both constants size the padding reservation, so a change to `ack.rs`'s run
    /// width, run count or encoding that shrank either one would silently narrow
    /// the reservation and reopen the size-class leak. It fails here instead.
    #[test]
    fn the_worst_case_acknowledgement_overhead_is_pinned() {
        assert_eq!(
            maximal_ack().encode_beyond().len(),
            MAX_ACK_BEYOND_LEN,
            "a saturated run set must be exactly the reserved length"
        );
        assert_eq!(
            ack_fields_encoded_len(Some(u64::MAX), &vec![0xff; MAX_ACK_BEYOND_LEN]),
            WORST_CASE_ACK_FIELDS_LEN,
            "the reservation must be the largest the two fields can encode to"
        );
        // No acknowledgement contributes nothing, which is what makes the probe a
        // measurement of the two fields rather than of a body.
        assert_eq!(ack_fields_encoded_len(None, &[]), 0);
        // And nothing real can exceed the reservation — the property the
        // `saturating_sub`/`saturating_add` in `seal` relies on.
        for ack in [small_ack(), headless_ack(), maximal_ack()] {
            assert!(
                ack_fields_encoded_len(ack.high_water(), &ack.encode_beyond())
                    <= WORST_CASE_ACK_FIELDS_LEN
            );
        }
    }

    /// **The padding rung must not depend on the acknowledgement**, swept across
    /// both bucket boundaries rather than sampled at one convenient length.
    ///
    /// A single short body cannot witness this: it sits far below the 8192 rung's
    /// edge, so a saturated acknowledgement does not push it over and the test
    /// passes against a build that selects the rung from the real encoded length.
    /// The band that matters is where the reservation straddles a boundary —
    /// around 2.5–3.5 KB for the 8192 rung — and the sweep below covers it a byte
    /// at a time at the crossover, plus the approach to the top rung.
    ///
    /// What this defends is the same thing `ack_record.rs`'s single fixed rung
    /// defends: a ladder publishes a size class, and if an acknowledgement can
    /// move a frame between rungs then the ladder publishes whether a reply
    /// acknowledged anything and roughly how many gaps it carried.
    #[test]
    fn the_padding_rung_never_depends_on_the_piggybacked_acknowledgement() {
        let saturated = maximal_ack();
        // The rungs are classified by the frame lengths actually observed, never
        // by comparing a FRAME length against a PAD_BUCKETS value: those are
        // different quantities. A frame carries the padded plaintext plus a
        // nonce, a tag, a 1568-byte `eph_ek` and the clear header, so every frame
        // on the lower rung is already longer than `PAD_BUCKETS[0]` and a
        // threshold test against it silently classifies all of them as upper.
        let mut observed = std::collections::BTreeSet::new();

        // The band where the reservation straddles the 8192 rung's edge: a bare
        // body of ~2400 still fits it, one of ~3700 does not once the 1040-byte
        // reservation is added. That is the whole crossover — a 4627-byte
        // signature plus [`DM_BODY_CAP`] cannot reach the 16384 rung's own edge,
        // so there is no second boundary to sweep.
        //
        // Every length is sealed from a FRESH pair, so both frames sit at the
        // same low sequence numbers. Reusing one pair would walk `seq` across a
        // varint width boundary mid-sweep and change the CLEAR frame's length for
        // reasons that have nothing to do with padding.
        let lengths = (2400..=3700)
            .step_by(16)
            .chain([1, 2, DM_BODY_CAP - 1, DM_BODY_CAP]);

        for len in lengths {
            let body = "x".repeat(len);
            let mut p = pair();
            let bare = p.send(&body);
            let (acked, _) = p.send_acked(&body, Some(&saturated));
            assert_eq!(
                bare.len(),
                acked.len(),
                "a {len}-byte body took a different padding rung depending on \
                 whether it piggybacked an acknowledgement — the ladder is \
                 leaking the acknowledgement"
            );
            observed.insert(bare.len());
        }

        // The control on the sweep itself. Inside a single rung the assertion
        // above holds however the rung is chosen, so a sweep that never crossed a
        // boundary would pass against the very defect it exists to catch. Two
        // distinct frame lengths IS the crossing, and there are exactly two
        // because `PAD_BUCKETS` has two rungs.
        assert_eq!(
            observed.len(),
            2,
            "the sweep must span a rung boundary — it saw frame lengths {observed:?}, \
             so it never crossed and proves nothing"
        );
    }

    /// The piggyback path with an ABSENT contiguous prefix, over the real
    /// `seal → parse → open` seam.
    ///
    /// `(None, non-empty runs)` is the shape a receiver produces when the head of
    /// a conversation is lost, and it is the case that separates the presence
    /// test's `||` from an `&&`: with `&&`, a frame carrying runs but no prefix
    /// would silently come back as "no acknowledgement" on the public path.
    #[test]
    fn an_acknowledgement_with_no_contiguous_prefix_round_trips() {
        let mut p = pair();
        let sent = headless_ack();
        let (bytes, _) = p.send_acked("head of the conversation was lost", Some(&sent));

        let got = p.recv(&bytes).unwrap();
        let peer = got
            .peer_ack
            .expect("runs without a prefix are still an acknowledgement");
        assert_eq!(
            peer.sig_input(&[1u8; ROOT_LEN], Direction::AToB),
            crate::dm::ack::ack_sig_input(&[1u8; ROOT_LEN], Direction::AToB, &sent),
        );

        let mut ours = AckState::new();
        assert_eq!(
            ours.merge_peer_ack(peer, Some(9)).unwrap(),
            crate::dm::ack::PeerAckOutcome::WithinCeiling
        );
        assert_eq!(
            ours.high_water(),
            None,
            "an absent prefix must survive the round trip as absent, not as zero"
        );
        for settled in [4, 5, 9] {
            assert!(ours.is_settled(settled));
        }
        for unsettled in [0, 3, 6, 8, 10] {
            assert!(!ours.is_settled(unsettled));
        }
    }

    /// The adversarial outcome the decode → verify → merge sequence exists for,
    /// driven from real wire bytes rather than a hand-built [`AckState`].
    ///
    /// A peer that claims to have collected sequence numbers we never sent is
    /// either broken or trying to make us report messages delivered before they
    /// were composed. Nothing in this module can catch it — the decoder must hand
    /// back the claim intact or the signature would not verify against it — so
    /// the whole defence is that the claim reaches
    /// [`AckState::merge_peer_ack`] as a [`PeerAck`] and is clipped there.
    /// This test drives that path end to end and asserts the clip actually fired.
    #[test]
    fn a_piggybacked_claim_above_what_we_sent_is_clipped_on_merge() {
        let mut p = pair();
        // The peer claims a prefix of 4 and a run at 9 — we will have sent 6.
        let sent = headless_ack();
        let (bytes, _) = p.send_acked("I collected more than you sent", Some(&sent));

        let peer = p
            .recv(&bytes)
            .unwrap()
            .peer_ack
            .expect("the frame carried an acknowledgement");

        let mut ours = AckState::new();
        assert_eq!(
            ours.merge_peer_ack(peer, Some(6)).unwrap(),
            crate::dm::ack::PeerAckOutcome::ClippedToCeiling {
                claimed: 9,
                ceiling: Some(6),
            },
            "a claim above the highest sequence we sent must be clipped, and the \
             clip must be reported rather than absorbed"
        );
        // The possible part of the claim still merged...
        assert!(ours.is_settled(4));
        assert!(ours.is_settled(5));
        // ...and the impossible part did not.
        assert!(
            !ours.is_settled(9),
            "a position we never sent must not become settled because a peer said so"
        );
    }

    // ---- the ACCEPT frame -------------------------------------------------
    //
    // The acceptor's first channel write. Every test below drives the real
    // `seal_accept` → `parse` → `open_accept` path; nothing hands the initiator
    // a pseudonym it did not read out of a frame.

    /// T1. An initiator that holds only the long-term key it knocked at opens
    /// the acceptance, gets the pseudonym, and can then open the acceptor's
    /// ordinary frames with it.
    ///
    /// **The second half is what makes the first mean anything.** Installing a
    /// key that nothing later verifies against would be satisfied by returning
    /// any 2592 bytes. The reply at the next sequence is opened through the
    /// ordinary `open`, under the installed key, with no binding fields in
    /// sight — which is the steady state the acceptance exists to reach.
    #[test]
    fn an_accept_opens_with_no_prior_pseudonym_and_installs_it() {
        let mut p = pair();
        let (bytes, key) = p.accept(None);
        let rcpt = p.to_a();
        let parsed = parse(&bytes).unwrap();

        let accepted = parsed
            .open_accept(
                &key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                &rcpt,
                p.b.signing.public_key(),
            )
            .expect("the acceptance opens under the long-term key alone");
        assert_eq!(
            accepted.peer_pk_pc.as_slice(),
            p.b_pc.public_key().as_slice(),
            "the installed key must be the acceptor's pseudonym"
        );
        assert_eq!(accepted.frame.seq, FIRST_RECIPIENT_CHANNEL_SEQ);
        assert_eq!(accepted.frame.body, "", "an acceptance carries no body");

        // And the steady state: the acceptor's next frame is an ordinary one,
        // opened under the key just installed.
        let installed = accepted.peer_pk_pc;
        let (reply, reply_key, seq) = p.b_send("and a reply");
        assert_eq!(seq, FIRST_RECIPIENT_CHANNEL_SEQ + 1);
        let verified = parse(&reply)
            .unwrap()
            .open(
                &reply_key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(seq),
                &rcpt,
                AuthorKeys {
                    pc: &installed,
                    lt: p.b.signing.public_key(),
                },
            )
            .expect("the reply opens under the installed pseudonym");
        assert_eq!(verified.body, "and a reply");
    }

    /// T2. A forged binding is refused, in both directions a forgery can point,
    /// and the ratchet is left where it was.
    ///
    /// Two distinct forgeries, because they fail for different reasons and a
    /// check that caught only one would look identical here:
    ///
    /// 1. A binding signed by some OTHER long-term key over the honest
    ///    pseudonym — the attacker vouching for a key nobody asked them about.
    /// 2. A genuine binding by the honest long-term key over a DIFFERENT
    ///    pseudonym, spliced onto this frame. The signature is real; it just
    ///    does not say what this frame claims it says.
    ///
    /// The second is the one a check that verified `bind_lt` without binding it
    /// to the carried `pk_pc` would let through.
    #[test]
    fn a_forged_accept_binding_is_refused() {
        let mut p = pair();
        let (bytes, key) = p.accept(None);
        let rcpt = p.to_a();
        let before = (p.init.generation(), p.init.losses());

        let stranger = pseudonym(0xC3);
        let other_pc = pseudonym(0xD7);
        let honest_pc = *p.b_pc.public_key();
        let stranger_over_honest = stranger
            .sign(&bind_lt_input(stranger.public_key(), &honest_pc))
            .unwrap();
        let honest_over_other =
            p.b.signing
                .sign(&bind_lt_input(
                    p.b.signing.public_key(),
                    other_pc.public_key(),
                ))
                .unwrap();

        for (name, forged) in [
            ("a binding by a third identity", stranger_over_honest),
            ("a genuine binding over another key", honest_over_other),
        ] {
            let sig = forged;
            let tampered = p.reseal(
                &bytes,
                &key,
                Box::new(move |b: &mut wire::DmChannelBody| b.bind_lt = sig.to_vec()),
            );
            let verdict = parse(&tampered).unwrap().open_accept(
                &key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                &rcpt,
                p.b.signing.public_key(),
            );
            assert!(
                matches!(verdict, Err(DmFrameError::Binding)),
                "{name} must be refused as a binding failure, got {verdict:?}"
            );
        }
        assert_eq!(
            (p.init.generation(), p.init.losses()),
            before,
            "a refused acceptance must not move the initiator's ratchet"
        );

        // The control on the whole fixture: the UNforged acceptance still
        // opens. Without it every assertion above is satisfied by an
        // `open_accept` that refuses everything.
        assert!(
            parse(&bytes)
                .unwrap()
                .open_accept(
                    &key,
                    &[1u8; ROOT_LEN],
                    Direction::BToA,
                    position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                    &rcpt,
                    p.b.signing.public_key(),
                )
                .is_ok(),
            "the honest acceptance must still open, or the refusals prove nothing"
        );
    }

    /// T3. Once a pseudonym is installed, a frame carrying a DIFFERENT one is
    /// refused — and refused as a pinning violation, before any signature is
    /// looked at.
    ///
    /// The rotation an attacker wants is not a forged signature: it is a second
    /// key, correctly signed under itself, presented as though the conversation
    /// had moved on. `msg_sig` cannot catch that on its own, because a frame
    /// signed under the new key verifies perfectly against the new key.
    #[test]
    fn a_second_accept_with_a_different_pseudonym_is_refused() {
        let mut p = pair();
        let (accept_bytes, accept_key) = p.accept(None);
        let rcpt = p.to_a();
        let installed = parse(&accept_bytes)
            .unwrap()
            .open_accept(
                &accept_key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                &rcpt,
                p.b.signing.public_key(),
            )
            .expect("the first acceptance opens")
            .peer_pk_pc;

        // A second frame carrying a second pseudonym, bound genuinely by the
        // same long-term identity — so nothing about it is forged.
        let rotated = pseudonym(0xE9);
        let rotated_pk = *rotated.public_key();
        let rotated_bind =
            p.b.signing
                .sign(&bind_lt_input(p.b.signing.public_key(), &rotated_pk))
                .unwrap();
        let (reply, reply_key, seq) = p.b_send("rotated under you");
        let tampered = p.reseal(
            &reply,
            &reply_key,
            Box::new(move |b: &mut wire::DmChannelBody| {
                b.pk_pc = rotated_pk.to_vec();
                b.bind_lt = rotated_bind.to_vec();
            }),
        );

        let verdict = parse(&tampered).unwrap().open(
            &reply_key,
            &[1u8; ROOT_LEN],
            Direction::BToA,
            position_of(seq),
            &rcpt,
            AuthorKeys {
                pc: &installed,
                lt: p.b.signing.public_key(),
            },
        );
        assert!(
            matches!(verdict, Err(DmFrameError::PseudonymMismatch)),
            "a rotated pseudonym must be refused as a pinning violation, got {verdict:?}"
        );
    }

    /// T4. A reply that is not an acceptance is refused as unverifiable, never
    /// quietly accepted.
    ///
    /// Three shapes, one for each way a frame can fail to be an acceptance, and
    /// the errors are deliberately different: an ordinary body at the right
    /// position carries no binding at all (a peer that replied without
    /// accepting), while the wrong sequence and the wrong direction are not
    /// positions an acceptance can occupy at all.
    #[test]
    fn a_reply_before_any_accept_is_refused_not_accepted() {
        let mut p = pair();
        // An ordinary frame at the acceptor's sequence zero: the acceptor
        // composed a message instead of accepting.
        let out = p.recip.send_next().unwrap();
        assert_eq!(out.header.seq, FIRST_RECIPIENT_CHANNEL_SEQ);
        let key = out.key.clone();
        let rcpt = p.to_a();
        let plain = seal(
            out,
            &[1u8; ROOT_LEN],
            &p.b_pc,
            p.b.signing.public_key(),
            &rcpt,
            SENT,
            "no acceptance here",
            None,
        )
        .unwrap();
        let parsed = parse(&plain).unwrap();
        assert!(
            matches!(
                parsed.open_accept(
                    &key,
                    &[1u8; ROOT_LEN],
                    Direction::BToA,
                    position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                    &rcpt,
                    p.b.signing.public_key(),
                ),
                Err(DmFrameError::MissingBinding)
            ),
            "an ordinary body at sequence zero must be refused as unverifiable"
        );
        // ...and the wrong direction, on the same bytes.
        assert!(matches!(
            parsed.open_accept(
                &key,
                &[1u8; ROOT_LEN],
                Direction::AToB,
                position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                &rcpt,
                p.b.signing.public_key(),
            ),
            Err(DmFrameError::NotAccept { seq: 0 })
        ));

        // A genuine acceptance body, presented at sequence one.
        let (later, later_key, seq) = p.b_send("later");
        assert_eq!(seq, FIRST_RECIPIENT_CHANNEL_SEQ + 1);
        assert!(matches!(
            parse(&later).unwrap().open_accept(
                &later_key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(seq),
                &rcpt,
                p.b.signing.public_key(),
            ),
            Err(DmFrameError::NotAccept { seq: 1 })
        ));

        // **HALF a binding is not a binding, and neither half alone may be
        // skipped.** The presence test is `pk_pc` non-empty OR `bind_lt`
        // non-empty, and the reason it is `||` rather than `&&` is exactly
        // these two shapes: under `&&` a body carrying a pseudonym with NO
        // binding takes the never-carried-one path, the check that would
        // demand the binding never runs, and `msg_sig` — which the sender
        // signs under whatever key it also wrote into `pk_pc` — then verifies
        // against it. That installs a pseudonym nobody vouched for. Both
        // one-sided shapes are refused, through BOTH doors, because `open` and
        // `open_accept` reach the check by different routes.
        let mut q = pair();
        let (accept, accept_key) = q.accept(None);
        let honest_pc = *q.b_pc.public_key();
        let to_a = q.to_a();
        for (name, edit) in [
            (
                "a pseudonym with no binding",
                Box::new(|b: &mut wire::DmChannelBody| b.bind_lt = Vec::new()) as BodyMutation,
            ),
            (
                "a binding over no pseudonym",
                Box::new(|b: &mut wire::DmChannelBody| b.pk_pc = Vec::new()) as BodyMutation,
            ),
        ] {
            let half = q.reseal(&accept, &accept_key, edit);
            let parsed = parse(&half).expect("a half-bound body still parses");

            let by_accept = parsed.open_accept(
                &accept_key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                &to_a,
                q.b.signing.public_key(),
            );
            assert!(
                matches!(
                    by_accept,
                    Err(DmFrameError::FieldLength { actual: 0, .. })
                        | Err(DmFrameError::MissingBinding)
                ),
                "{name} must be refused by open_accept, got {by_accept:?}"
            );

            let by_open = parsed.open(
                &accept_key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                &to_a,
                AuthorKeys {
                    pc: &honest_pc,
                    lt: q.b.signing.public_key(),
                },
            );
            assert!(
                matches!(by_open, Err(DmFrameError::FieldLength { actual: 0, .. })),
                "{name} must be refused by open, got {by_open:?}"
            );
        }

        // The control on both loops: the UNedited acceptance still opens
        // through both doors, so the refusals above are about the missing half
        // and not about the fixture.
        let parsed = parse(&accept).unwrap();
        assert!(
            parsed
                .open_accept(
                    &accept_key,
                    &[1u8; ROOT_LEN],
                    Direction::BToA,
                    position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                    &to_a,
                    q.b.signing.public_key(),
                )
                .is_ok(),
            "the whole acceptance must still open"
        );
        assert!(
            parsed
                .open(
                    &accept_key,
                    &[1u8; ROOT_LEN],
                    Direction::BToA,
                    position_of(FIRST_RECIPIENT_CHANNEL_SEQ),
                    &to_a,
                    AuthorKeys {
                        pc: &honest_pc,
                        lt: q.b.signing.public_key(),
                    },
                )
                .is_ok(),
            "the whole acceptance must also open through the ordinary door"
        );
    }

    /// T5. An ordinary frame carries neither binding field, and the check that
    /// reads them fires only when they are there.
    ///
    /// The mutation is the half that matters. "Both fields are empty" alone is
    /// satisfied by an `open` that never looks at them — so the same frame is
    /// re-sealed with a garbage `bind_lt` and must now be refused, which is
    /// only possible if the presence test is what gates the check.
    #[test]
    fn the_binding_fields_are_absent_on_an_ordinary_frame() {
        let mut p = pair();
        let (bytes, key) = p.send_keyed("an ordinary message");
        let parsed = parse(&bytes).unwrap();
        let dir = p.recip.recv_direction();
        let rcpt = recipient_hash(p.b.signing.public_key()).unwrap();
        let author = AuthorKeys {
            pc: p.a_pc.signing.public_key(),
            lt: p.a.signing.public_key(),
        };
        let at = position_of(parsed.header().seq);

        // The body an ordinary `seal` produced carries neither field.
        let verified = parsed
            .open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, author)
            .expect("an ordinary frame opens");
        assert_eq!(verified.body, "an ordinary message");
        let mut plaintext = open_envelope(
            &aes_key(&key).unwrap(),
            &frame_aad(
                &[1u8; ROOT_LEN],
                dir,
                parsed.header(),
                parsed.eph_ek(),
                parsed.eph_ct(),
            ),
            &parsed.sealed,
        )
        .unwrap();
        let encoded = crate::dm::unpad(&plaintext).unwrap().to_vec();
        plaintext.zeroize();
        let mut decoded = wire::DmChannelBody::decode(&encoded[..]).unwrap();
        assert!(decoded.pk_pc.is_empty(), "pk_pc must be absent");
        assert!(decoded.bind_lt.is_empty(), "bind_lt must be absent");

        // The mutation: a garbage binding on the same ordinary frame. The check
        // must now fire, which proves the emptiness above is what skipped it.
        decoded.pk_pc = p.a_pc.signing.public_key().to_vec();
        decoded.bind_lt = vec![0xAA; ml_dsa::SIG_LEN];
        let padded = crate::dm::pad_to_bucket(&decoded.encode_to_vec(), PAD_BUCKETS).unwrap();
        let sealed = seal_envelope(
            &aes_key(&key).unwrap(),
            &frame_aad(
                &[1u8; ROOT_LEN],
                dir,
                parsed.header(),
                parsed.eph_ek(),
                parsed.eph_ct(),
            ),
            &padded,
        )
        .unwrap();
        let tampered = wire::DmChannelFrame {
            ratchet_gen: parsed.header().generation,
            chain_base: parsed.header().chain_base,
            seq: parsed.header().seq,
            eph_ek: parsed.eph_ek().to_vec(),
            eph_ct: parsed.eph_ct().map(|c| c.to_vec()).unwrap_or_default(),
            sealed,
        }
        .encode_to_vec();
        let verdict =
            parse(&tampered)
                .unwrap()
                .open(&key, &[1u8; ROOT_LEN], dir, at, &rcpt, author);
        assert!(
            matches!(verdict, Err(DmFrameError::Binding)),
            "a non-empty binding on an ordinary frame must be checked, got {verdict:?}"
        );
    }

    /// T6. A frame that re-states the binding already installed opens.
    ///
    /// The pinning check refuses a DIFFERENT key, not a repeated one. A peer
    /// that carried its binding on more than the acceptance would otherwise be
    /// cut off after its first frame — and this is the assertion that would
    /// fail if the check were written as "any binding after the first is a
    /// violation".
    #[test]
    fn a_reused_binding_is_idempotent_under_open() {
        let mut p = pair();
        let honest_pc = *p.b_pc.public_key();
        let honest_bind =
            p.b.signing
                .sign(&bind_lt_input(p.b.signing.public_key(), &honest_pc))
                .unwrap();
        let rcpt = p.to_a();
        let (reply, reply_key, seq) = p.b_send("stated again");
        let restated = p.reseal(
            &reply,
            &reply_key,
            Box::new(move |b: &mut wire::DmChannelBody| {
                b.pk_pc = honest_pc.to_vec();
                b.bind_lt = honest_bind.to_vec();
            }),
        );

        let verified = parse(&restated)
            .unwrap()
            .open(
                &reply_key,
                &[1u8; ROOT_LEN],
                Direction::BToA,
                position_of(seq),
                &rcpt,
                AuthorKeys {
                    pc: &honest_pc,
                    lt: p.b.signing.public_key(),
                },
            )
            .expect("a frame restating the installed binding must open");
        assert_eq!(verified.body, "stated again");
    }
}
