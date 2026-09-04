//! The three re-establishment legs — `RE-EST`, `RE-ACK`, `RE-CONFIRM` — with the
//! key derivation that separates them, the authorship signature every leg
//! carries, the bounded trial-decryption scan that conveys `attempt`, the
//! tiebreak coin that resolves a simultaneous re-establishment, and the
//! admission rule that runs duplicate detection ahead of any response budget.
//!
//! Design of record: `docs/design/direct-messaging.md`, **Amendment A9**
//! (RATIFIED 2026-07-30), with the leg key from § A4.6, the trial scan from
//! § A5.2, the wire shape from § A3.9, the signature obligation from § A3.1, the
//! coin from § A3.7 and the dedup ordering from § A9.4(ii).
//!
//! ## The leg has no clear fields, and that is the whole shape decision
//!
//! A leg on the wire is one AES-256-GCM envelope over a fixed-size padded
//! plaintext, and nothing else. No kind label, no generation, no attempt, no
//! direction. A3.9: *"A re-establish frame is shaped exactly like an ordinary
//! frame and identified by trial decryption — one bounded AEAD attempt per
//! otherwise-unopenable frame with the expected generation's key"*. The receiver
//! supplies every discriminator from its own state:
//!
//! - **kind** — the caller names the leg it is looking for; a leg sealed as one
//!   kind cannot open as another because the kind is an HKDF `info` input.
//! - **direction** — implied by which of the two direction records the bytes were
//!   read from, never carried in them.
//! - **generation** — *the expected generation's key*, from the reader's own
//!   resume record. It is not read off the frame.
//! - **seq** — the sequence position the leg was fetched from. A leg rides the
//!   ordinary outbox *"at its own sequence position"* (A3.2) and the design's
//!   per-message address is `msg_addr(dir, seq)`, so the position is the address
//!   the reader used, never a field inside the bytes.
//! - **attempt** — trial-decrypted over the bounded window A5.2 specifies
//!   (see [`scan_re_est`] and [`MAX_GAP`]).
//!
//! A5.2 rejects the alternative in terms: *"A clear `attempt` field was the other
//! option and is rejected: it would be a new reconnect-count discriminator"*.
//! The same argument retires the clear kind label, which A3.9 had already
//! replaced with trial decryption.
//!
//! ## Every leg carries `msg_sig`
//!
//! A3.1: *"A frame kind without `msg_sig` cannot exist in this feature"*, and the
//! signature *"binds a per-leg frame-kind label … and the `reconnect_gen` the
//! frame acts at, so a tiebreak or a retirement is only ever decided by a frame
//! bound to that contest"*. `leg_sig_input` binds the kind, the direction, the
//! generation, the attempt and the leg's payload, under the per-correspondent
//! pseudonym key. A4.8 homes both halves of that material — the party's own
//! `S_pc` and the peer's `PK_pc` — in the resume record for exactly these legs,
//! so it survives the restart this feature exists to survive.
//!
//! The signature is sealed *inside* the envelope, matching
//! [`crate::dm::frame`]'s layout, so it is not a clear discriminator either.
//!
//! ## There is no AAD, and the reason is a list, not a slogan
//!
//! An AAD's job is to bind a frame's **clear** fields to its seal. This leg has
//! no clear fields. The claim that therefore "an AAD would bind nothing the key
//! does not" is only true of the values actually enumerated, so they are
//! enumerated: the leg binds **`kind`, `dir`, `generation`, `seq` and
//! `attempt`**, each of them in the HKDF `info` and again in the signature
//! preimage, and there is no sixth value an AAD could reach. Adding one later —
//! a suite tag, a chain base — reopens the question and this paragraph with it.
//!
//! For the five that exist, binding in the key is the stronger of the two: two
//! values derive two *keys*, where an AAD gives one key that refuses a second
//! AAD. Each is therefore bound exactly twice, and this module's tests exercise
//! the two bindings at their own layers, because a binding tested only through
//! the other layer is not tested at all.
//!
//! `seq` is here because A5.3 keys its dedup memory on
//! `(gen, attempt, leg, dir, seq)` and the ordinary frame binds `seq` in both
//! `msg_sig` and its AAD. Binding it costs nothing — the reader already knows
//! the position it fetched from — and without it a captured leg could be
//! re-filed at another position on the same plane.
//!
//! ## The KEM seam, and where the shared secret is allowed to exist
//!
//! [`mint_ephemeral`], [`answer`] and [`complete`] are the three ML-KEM
//! operations a re-establishment performs: the returning party mints a keypair
//! and publishes the encapsulation key in its `RE-EST`; the peer encapsulates to
//! it and re-roots; the returning party decapsulates the `RE-ACK`'s ciphertext
//! and reaches the same pair.
//!
//! **`ss_new` never crosses the crate boundary.** Each of the two folding calls
//! encapsulates or decapsulates and hands the secret straight to
//! [`crate::dm::resume::reroot`] inside one function, zeroizing it before
//! returning. A caller receives a [`Rerooted`] and, on the answering side, a
//! ciphertext — neither of which yields the secret. A seam that returned
//! `ss_new` for the caller to fold later would make it possible to commit a root
//! whose ciphertext was never sent, or to send a ciphertext whose secret was
//! dropped, and both leave the two parties on roots that will never agree.
//!
//! ## What this module does not do
//!
//! It holds no state across a restart. The sealed leg bytes and the ephemeral's
//! secret half are persisted by [`crate::dm::resume`], and nothing here writes a
//! record. Deriving the resumed channel's chains from the re-rooted root is
//! [`crate::dm::ratchet`]'s.

use std::num::NonZeroU32;

use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_kdf::{HkdfSha384, KdfError};
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::dm::ratchet::{Direction, EphemeralDecapKey};
use crate::dm::resume::{Attempt, CommittedRoot, FreshAttempt, Rerooted, ResumeRecord, reroot};
use crate::dm::{LEN_PREFIX, domain, pad_to_bucket, push_lp, unpad};
use crate::identity::keys::verify_signature;

/// The returning side's ask: "this conversation was interrupted; here is a fresh
/// ephemeral to re-root it".
///
/// **Not a wire field.** It is an HKDF `info` input and a signature-preimage
/// component, length-prefixed in both, so two kinds cannot be confused however
/// their bytes relate. FROZEN — changing one changes the key schedule.
pub const FRAME_KIND_RE_EST: &[u8] = b"re-est";

/// The other side's answer, carrying the ciphertext that co-determines the new
/// root. Not a wire field; see [`FRAME_KIND_RE_EST`]. FROZEN.
pub const FRAME_KIND_RE_ACK: &[u8] = b"re-ack";

/// The returning side settling the exchange — A9's retirement mechanism. Its
/// payload is the signature and nothing else: the whole content of the leg is
/// the authenticated fact that it arrived. Not a wire field. FROZEN.
pub const FRAME_KIND_RE_CONFIRM: &[u8] = b"re-confirm";

/// The one padded plaintext size every leg seals, so all three are the same
/// length on the wire and length is not a kind discriminator.
///
/// A3.2 requires `RE-CONFIRM` be *"empty-bodied and padded like any frame"*;
/// padding all three to one bucket is that requirement applied uniformly. The
/// value matches the outbox's lower `PAD_BUCKETS` rung (A4.8), so a leg is the
/// size of an ordinary padded frame body rather than a size of its own. FROZEN.
const LEG_PLAINTEXT_LEN: usize = 8192;

/// The single-rung padding ladder [`pad_to_bucket`] is driven with.
const LEG_BUCKETS: [usize; 1] = [LEG_PLAINTEXT_LEN];

/// Bytes of AES-256-GCM overhead on a sealed leg: a 12-byte nonce ahead of the
/// ciphertext and a 16-byte tag behind it.
const SEAL_OVERHEAD: usize = 28;

/// The length of every leg on the wire. One constant, because all three legs are
/// one length.
pub const LEG_LEN: usize = LEG_PLAINTEXT_LEN + SEAL_OVERHEAD;

/// Bytes of `RE-EST` payload inside the seal: the ephemeral and the signature.
const RE_EST_PAYLOAD_LEN: usize = ml_kem::EK_LEN + ml_dsa::SIG_LEN;

/// Bytes of `RE-ACK` payload inside the seal: the ciphertext and the signature.
const RE_ACK_PAYLOAD_LEN: usize = ml_kem::CT_LEN + ml_dsa::SIG_LEN;

/// Bytes of `RE-CONFIRM` payload inside the seal: the signature alone.
const RE_CONFIRM_PAYLOAD_LEN: usize = ml_dsa::SIG_LEN;

const _: () = assert!(LEN_PREFIX + RE_EST_PAYLOAD_LEN <= LEG_PLAINTEXT_LEN);
const _: () = assert!(LEN_PREFIX + RE_ACK_PAYLOAD_LEN <= LEG_PLAINTEXT_LEN);
const _: () = assert!(LEN_PREFIX + RE_CONFIRM_PAYLOAD_LEN <= LEG_PLAINTEXT_LEN);

/// How many re-establishment attempts a window admits before the party gives up
/// — the design's `C`.
///
/// **This number is a PLACEHOLDER, not a ratified value.** A9 ratifies `C` as a
/// tunable dial *"at a middle default"* and defers the number: *"the absolute
/// leaked-integer numbers to be closed at the byte pass"*. Eight is this build's
/// stand-in for that middle setting. Nothing in this module is frozen against
/// it: the count it bounds is already a `u32` field of the resume record, so
/// moving it changes no encoding and no size class — only the receiver's scan
/// width ([`MAX_GAP`]) and the number of legible re-attempts per window.
///
/// A7.3 also pins what kind of knob it is: `C` is *"a protocol-global constant,
/// identical across all clients and deployments — never a per-deployment
/// setting"*, because a per-client ceiling is a fingerprint. Moving it is a
/// release-wide change, never a configuration.
pub const ATTEMPT_CEILING: u32 = 8;

/// How far past `last_seen` the receiver's trial-decryption scan reaches.
///
/// A8.1's one-knob identity: *"A crash before emit therefore causes zero
/// inflation, so A7.3's decoupling is deleted and `MAX_GAP = C` is restored"*.
/// It is written as an alias of [`ATTEMPT_CEILING`] rather than as a second
/// number so the identity cannot drift; a test pins that it is one.
///
/// # Why a sender's attempt cannot outrun the window
///
/// `MAX_GAP = C` is sound only while a sender's `attempt` stays within `C` of
/// the receiver's `last_seen`, and `attempt` is monotone for the channel's whole
/// lifetime (A7.3) while `C` bounds attempts *per window*. Two things close the
/// gap between those facts, and both are durable state in [`ResumeRecord`].
///
/// A7.3's anchor: the count `C` bounds is
/// *"`attempt − attempt_at_window_start`"*, against a window-start anchor
/// persisted in the resume record. [`AttemptBudget`] is that subtraction, so
/// [`AttemptBudget::charge`] refuses at `anchor + C` however high the monotone
/// counter has climbed.
///
/// A8.2's rollover rule: window membership and anchor reset are *"an idempotent
/// derivation from durable `last_seen`"*, recomputed at load — and `last_seen`
/// is the highest attempt the peer has opened
/// ([`ResumeRecord::last_seen_re_est`](crate::dm::resume::ResumeRecord::last_seen_re_est)
/// and [`ResumeRecord::last_seen_re_ack`](crate::dm::resume::ResumeRecord::last_seen_re_ack),
/// derived from the acceptance slot). [`AttemptBudget::observe_peer_opened`] is
/// the only reset, and it takes the attempt an opened `RE-ACK` names.
///
/// Together they bound the gap: a sender reaches `anchor + C` and stops, and the
/// anchor advances only to an attempt the peer has opened — which is an attempt
/// the receiver's own `last_seen` has therefore reached. So
/// `attempt − last_seen ≤ C` holds at every point, and the legitimate current
/// attempt is always inside `[last_seen, last_seen + MAX_GAP]`.
/// `the_anchor_keeps_a_multi_window_sender_inside_the_receivers_window` in this
/// module's tests drives two full windows and shows the leg opening.
pub const MAX_GAP: u32 = ATTEMPT_CEILING;

/// [`crate::dm::resume`] bounds a stored `RE-ACK` without being able to name
/// this constant — it cannot read this module, because this module reads it.
/// The bound holds or the build fails.
const _: () = assert!(LEG_LEN <= crate::dm::resume::MAX_SEALED_LEG_LEN);

/// What survives the eviction `ResumeRecord::observe_accepted` performs is one
/// scan window's worth per leg, on the one plane a party receives on: three
/// legs, `MAX_GAP + 1` attempts inclusive. The same cross-module pin as the one
/// above, for the same reason — and it is the scan window rather than `C`
/// because the anchor rolls over inside one retention (A6.1), so a bound sized
/// at one re-initiation window would be reachable by an ordinary sequence of
/// answered attempts.
const _: () = assert!(3 * (MAX_GAP as usize + 1) == crate::dm::resume::DEDUP_CAPACITY);

/// Anything that can go wrong sealing, opening or scanning a leg.
#[derive(Debug)]
pub enum ReEstError {
    /// The bytes are not a leg's length. Every leg is [`LEG_LEN`].
    Truncated,
    /// The seal opened but the recovered payload is not the length this leg
    /// carries — a peer running a different build, not a reachable local
    /// mistake. Reported for a payload too long as well as too short.
    PayloadLen {
        /// What the leg's payload must measure.
        expected: usize,
        /// What was actually inside the seal.
        got: usize,
    },
    /// A payload handed to the sealer does not fit the padded plaintext. A
    /// LOCAL caller error, structurally unreachable from the three public
    /// sealers (their payload lengths are compile-time constants and a
    /// `const` assertion pins each below the bucket) — kept as an error rather
    /// than a panic because the bucket is a constant a future edit could
    /// shrink.
    PayloadTooLong {
        /// The most a leg's payload can measure.
        max: usize,
        /// What the caller offered.
        got: usize,
    },
    /// No key in the scanned window opened the seal: a different root, a
    /// different direction, a different leg, a different generation, or an
    /// attempt outside the window. The sub-cause is deliberately not
    /// distinguished (ISC-A-S12 / ISC-A-C18 uniform close-shape).
    DidNotOpen,
    /// The seal opened and the authorship signature did not verify under the
    /// peer's `PK_pc`. Distinct from [`Self::DidNotOpen`] because only a party
    /// holding the committed root can reach it, so it is an anomaly to surface
    /// rather than an attacker-reachable oracle.
    Signature,
    /// Key derivation failed inside the module.
    Kdf(KdfError),
    /// The crypto module refused to build the key schedule, or to sign.
    Module(oxicrypt_module::Error),
    /// The AEAD reported a fault while sealing.
    Sealing(ModeError),
    /// The system entropy source failed while sealing.
    EntropySource,
    /// Folding an encapsulated secret into a re-rooted pair failed.
    ///
    /// Carries the cause verbatim rather than flattening it into
    /// [`Self::Kdf`]: [`crate::dm::resume::reroot`] performs two separate
    /// derivations and a fault in either is a sick crypto module, which a
    /// reader has to be able to tell from a leg that merely did not open.
    /// Boxed to keep this enum small, the way `dm::ratchet` boxes the
    /// first-contact error it carries.
    Reroot(Box<crate::dm::ratchet::RatchetError>),
}

impl std::fmt::Display for ReEstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "the bytes are not a re-establishment leg's length"),
            Self::PayloadLen { expected, got } => {
                write!(f, "the leg's payload is {got} bytes, not {expected}")
            }
            Self::PayloadTooLong { max, got } => {
                write!(f, "a {got}-byte leg payload exceeds the {max}-byte bucket")
            }
            Self::DidNotOpen => write!(f, "the re-establishment leg did not open"),
            Self::Signature => write!(f, "the re-establishment leg's signature did not verify"),
            Self::Kdf(e) => write!(f, "re-establishment key derivation failed: {e}"),
            Self::Module(e) => write!(f, "crypto module unavailable: {e:?}"),
            Self::Sealing(e) => write!(f, "the re-establishment seal reported a fault: {e}"),
            Self::EntropySource => write!(f, "the entropy source failed while sealing a leg"),
            Self::Reroot(e) => write!(f, "re-rooting the channel failed: {e}"),
        }
    }
}

impl std::error::Error for ReEstError {}

impl From<EnvelopeError> for ReEstError {
    /// Every decrypt fault collapses to [`ReEstError::DidNotOpen`]. A leg's
    /// bytes come from a page a correspondent writes, so the difference between
    /// a bad tag and a short buffer is a distinction about the attacker's
    /// spelling, not about what happened here.
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_) => Self::EntropySource,
            EnvelopeError::Encrypt(m) => Self::Sealing(m),
            _ => Self::DidNotOpen,
        }
    }
}

/// The HKDF `info` for one leg of one attempt in one direction, per A4.6's
/// `K(RS_n, gen, attempt, leg, dir)`.
///
/// Every input past the domain prefix is length-prefixed, so no two field
/// values can be concatenated into one another's encoding — a leg of kind `re`
/// in a direction spelled `esta2b` must not derive the key of `re-est` in
/// `a2b`. Factored out of `leg_key` so that injectivity can be driven over
/// fixtures directly rather than inferred from the key it happens to produce.
fn leg_info(kind: &[u8], dir: Direction, generation: u32, seq: u64, attempt: Attempt) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain::DM_REEST_LEG.len() + 72);
    info.extend_from_slice(domain::DM_REEST_LEG);
    push_lp(&mut info, kind);
    push_lp(&mut info, dir.label());
    push_lp(&mut info, &generation.to_be_bytes());
    push_lp(&mut info, &seq.to_be_bytes());
    push_lp(&mut info, &attempt.get().to_be_bytes());
    info
}

/// The seal key for one leg of one attempt in one direction.
fn leg_key_bytes(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
) -> Result<[u8; 32], ReEstError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_REEST_SALT), root.as_bytes())
        .map_err(ReEstError::Kdf)?;
    let info = leg_info(kind, dir, generation, seq, attempt);
    let mut key = [0u8; 32];
    let derived = hkdf.expand(&info, &mut key);
    if let Err(e) = derived {
        key.zeroize();
        return Err(ReEstError::Kdf(e));
    }
    Ok(key)
}

/// The seal key for one leg of one attempt at one sequence position in one
/// direction.
///
/// Split from `leg_key_bytes` so a known-answer vector can pin the derived
/// bytes. Pinning the `info` alone proves nothing about the salt, the extract
/// step, the hash or the output length — both parties derive through this same
/// code in every test, so agreement is structural and would survive replacing
/// the salt outright.
fn leg_key(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
) -> Result<Aes256Key, ReEstError> {
    let mut key = leg_key_bytes(root, kind, dir, generation, seq, attempt)?;
    let aes = Aes256Key::new(&key).map_err(ReEstError::Module);
    key.zeroize();
    aes
}

/// The preimage for a leg's authorship signature, signed under the sender's
/// per-correspondent pseudonym key `S_pc` and verified under the peer's
/// `PK_pc`.
///
/// A3.1 requires the frame-kind label and the `reconnect_gen` the frame acts at;
/// this preimage also binds the direction, the attempt and the leg's payload.
/// The payload is here for [`crate::dm::firstcontact::msg_sig_input`]'s reason:
/// an unauthenticated ephemeral would let an active attacker substitute their
/// own and defeat the post-compromise heal the ratchet exists to provide.
///
/// **Neither public key is bound**, which is a deviation from
/// [`crate::dm::firstcontact::msg_sig_input`] and is deliberate. That preimage
/// absorbed a pseudonym proof-of-possession because a first-contact frame
/// *carries* the keys it is verified under. A leg carries neither: both parties
/// installed `PK_pc` at establishment and the verifier uses exactly the one key
/// its resume record holds, so there is no key for a signature to substitute.
fn leg_sig_input(
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain::DM_REEST_SIG.len() + payload.len() + 72);
    buf.extend_from_slice(domain::DM_REEST_SIG);
    push_lp(&mut buf, kind);
    push_lp(&mut buf, dir.label());
    push_lp(&mut buf, &generation.to_be_bytes());
    push_lp(&mut buf, &seq.to_be_bytes());
    push_lp(&mut buf, &attempt.get().to_be_bytes());
    push_lp(&mut buf, payload);
    buf
}

/// Seal one leg's plaintext payload. The AEAD layer alone — it signs nothing, so
/// each of the four key bindings can be exercised here without the signature
/// standing in for them.
fn seal_leg(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
    payload: &[u8],
) -> Result<Vec<u8>, ReEstError> {
    let key = leg_key(root, kind, dir, generation, seq, attempt)?;
    let padded = pad_to_bucket(payload, &LEG_BUCKETS).ok_or(ReEstError::PayloadTooLong {
        max: LEG_PLAINTEXT_LEN - LEN_PREFIX,
        got: payload.len(),
    })?;
    Ok(seal_envelope(&key, &[], &padded)?)
}

/// Open one leg's plaintext payload under one candidate key. The AEAD layer
/// alone; the signature is the caller's.
fn open_leg(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
    encoded: &[u8],
) -> Result<Vec<u8>, ReEstError> {
    // The single length guard for both entry points. `open_envelope` would
    // report a wrong-length buffer as an authentication failure, which is the
    // wrong diagnosis for bytes that were never a leg — and the scan relies on
    // this returning `Truncated` rather than `DidNotOpen`, because only the
    // latter makes it try the next candidate.
    if encoded.len() != LEG_LEN {
        return Err(ReEstError::Truncated);
    }
    let key = leg_key(root, kind, dir, generation, seq, attempt)?;
    let padded = open_envelope(&key, &[], encoded)?;
    let payload = unpad(&padded).ok_or(ReEstError::DidNotOpen)?;
    Ok(payload.to_vec())
}

/// Seal a leg: build the signature over `payload`, append it, and seal the pair.
// 8 parameters against clippy's threshold of 7. Splitting them into a
// struct would move the same values behind a name that adds nothing: every
// one is a distinct binding the design enumerates.
#[allow(clippy::too_many_arguments)]
fn seal_signed_leg(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
    payload: &[u8],
    s_pc: &[u8; ml_dsa::SK_LEN],
) -> Result<Vec<u8>, ReEstError> {
    let mut preimage = leg_sig_input(kind, dir, generation, seq, attempt, payload);
    let signed = ml_dsa::sign(s_pc, &preimage, &[]);
    preimage.zeroize();
    let sig = signed.map_err(ReEstError::Module)?;
    let mut body = Vec::with_capacity(payload.len() + ml_dsa::SIG_LEN);
    body.extend_from_slice(payload);
    body.extend_from_slice(&sig);
    seal_leg(root, kind, dir, generation, seq, attempt, &body)
}

/// Open a leg under one candidate attempt and verify its signature.
///
/// Returns the payload with the signature stripped.
// 9 parameters against clippy's threshold of 7. Splitting them into a
// struct would move the same values behind a name that adds nothing: every
// one is a distinct binding the design enumerates.
#[allow(clippy::too_many_arguments)]
fn open_signed_leg(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
    encoded: &[u8],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
    payload_len: usize,
) -> Result<Vec<u8>, ReEstError> {
    let body = open_leg(root, kind, dir, generation, seq, attempt, encoded)?;
    let expected = payload_len + ml_dsa::SIG_LEN;
    if body.len() != expected {
        return Err(ReEstError::PayloadLen {
            expected,
            got: body.len(),
        });
    }
    let (payload, sig) = body.split_at(payload_len);
    let sig: [u8; ml_dsa::SIG_LEN] = sig.try_into().expect("checked length");
    let mut preimage = leg_sig_input(kind, dir, generation, seq, attempt, payload);
    let verified = verify_signature(peer_pk_pc, &preimage, &sig);
    preimage.zeroize();
    verified.map_err(|_| ReEstError::Signature)?;
    Ok(payload.to_vec())
}

/// A5.2's bounded trial-decryption scan: the one place `attempt` is recovered.
///
/// *"the receiver holds `RS_n` … and trial-decrypts over a bounded `attempt`
/// window `[last_seen, last_seen + MAX_GAP]`, rejecting anything beyond — the
/// cap is required because A3.13's backoff bounds the re-initiation rate but not
/// the cumulative count over a long absence, so an uncapped window would let a
/// junk frame force a full-window scan (a DoS amplifier, not a crypto break)."*
///
/// `last_seen` is the highest attempt this direction has opened, or `0` for a
/// correspondence that has opened none — attempt `0` is the resume record's
/// spelling for an empty slot and is never a real attempt, so the window starts
/// at `1` in that case. The window's lower end is *inclusive* because A9.1(a)
/// re-emits a persisted attempt byte-identically and the receiver must be able
/// to open it in order to dedup it.
///
/// **A signature failure ends the scan** rather than continuing to the next
/// candidate. Only a party holding the committed root can produce a leg that
/// opens at all, so an opened-but-unsigned leg is an anomaly to surface — and
/// continuing past it would let the key's `attempt` binding be silently dropped
/// while the scan still found the right attempt a candidate later.
// 9 parameters against clippy's threshold of 7. Splitting them into a
// struct would move the same values behind a name that adds nothing: every
// one is a distinct binding the design enumerates.
#[allow(clippy::too_many_arguments)]
fn scan_signed_leg(
    root: &CommittedRoot,
    kind: &[u8],
    dir: Direction,
    generation: u32,
    seq: u64,
    last_seen: u32,
    encoded: &[u8],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
    payload_len: usize,
) -> Result<(Attempt, Vec<u8>), ReEstError> {
    // No length guard here. `open_leg` has one and it is the only one needed:
    // the window below always yields at least one candidate, and a non-
    // `DidNotOpen` error returns immediately, so a wrong-length buffer is
    // refused as `Truncated` on the first call. A second copy here would be a
    // guard whose removal changes nothing observable — measured, not assumed:
    // deleting it left the whole suite green while deleting `open_leg`'s did
    // not.
    // The window's base is a `NonZeroU32`, so every candidate below is a real
    // attempt by construction and there is no zero case to skip. `last_seen`
    // of 0 is the empty-slot spelling and starts the window at attempt 1.
    let first = NonZeroU32::new(last_seen).unwrap_or(NonZeroU32::MIN);
    for offset in 0..=MAX_GAP {
        // Reachable at the top of the counter's range, where the window is
        // short rather than wrapped.
        let Some(candidate) = first.checked_add(offset) else {
            break;
        };
        let attempt = Attempt::from_nonzero(candidate);
        match open_signed_leg(
            root,
            kind,
            dir,
            generation,
            seq,
            attempt,
            encoded,
            peer_pk_pc,
            payload_len,
        ) {
            Ok(payload) => return Ok((attempt, payload)),
            Err(ReEstError::DidNotOpen) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(ReEstError::DidNotOpen)
}

/// Seal a `RE-EST` carrying a fresh ratchet ephemeral.
///
/// Takes a [`FreshAttempt`] rather than an [`Attempt`], which is A9.1 at the type
/// level: a fresh encapsulation is permitted only under a new attempt, and the
/// token is the only way to name one. A re-emit of an attempt already persisted
/// is not this call — it is the stored bytes, handed back by
/// [`crate::dm::resume::SealedReEst::bytes`].
pub fn seal_re_est(
    root: &CommittedRoot,
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: &FreshAttempt,
    eph_ek: &[u8; ml_kem::EK_LEN],
    s_pc: &[u8; ml_dsa::SK_LEN],
) -> Result<Vec<u8>, ReEstError> {
    seal_signed_leg(
        root,
        FRAME_KIND_RE_EST,
        dir,
        generation,
        seq,
        attempt.attempt(),
        eph_ek,
        s_pc,
    )
}

/// Seal a `RE-ACK` answering an opened `RE-EST`.
///
/// **Takes a [`ReAckAuthority`], not a bare [`Attempt`].** A9.1 names the case
/// this closes and names the reasoning that does not close it: the amendment it
/// supersedes justified re-encapsulating under a held attempt by *"`attempt` is
/// a distinct key namespace"* and A9.1 calls that **"the wrong invariant"**,
/// because *"the one thing forbidden is a fresh `eph_ct` under an unchanged
/// key"*. A `RE-ACK` carries an ML-KEM ciphertext as fresh as a `RE-EST`'s
/// encapsulation key, so a bare `Attempt` — which is `Copy` and always in hand
/// on the answering side — is exactly the spelling of that forbidden act.
/// [`OpenedReEst::answer`] is the only mint, so the authority to seal one
/// `RE-ACK` comes from having opened the `RE-EST` it answers, once.
///
/// The generation and the attempt travel inside the authority rather than as
/// arguments, so they cannot disagree with the leg being answered. `dir` and
/// `seq` stay arguments: they are the *answerer's* own direction and its own
/// next send position, neither of which the incoming leg names.
pub fn seal_re_ack(
    root: &CommittedRoot,
    dir: Direction,
    seq: u64,
    authority: ReAckAuthority,
    eph_ct: &[u8; ml_kem::CT_LEN],
    s_pc: &[u8; ml_dsa::SK_LEN],
) -> Result<Vec<u8>, ReEstError> {
    seal_signed_leg(
        root,
        FRAME_KIND_RE_ACK,
        dir,
        authority.generation,
        seq,
        authority.attempt,
        eph_ct,
        s_pc,
    )
}

/// Seal a `RE-CONFIRM`, settling the exchange of `attempt`.
///
/// A bare [`Attempt`] and no token, unlike its two siblings, because A9.1's
/// forbidden act cannot be spelled with this leg: it encapsulates nothing, so
/// there is no *"fresh `eph_ct` under an unchanged key"* available to it. Two
/// calls at one attempt produce two ciphertexts under one key, which is a
/// re-emit discipline question — A9.1(a) answers it, the stored bytes — and not
/// the root-divergence class the tokens exist to remove.
pub fn seal_re_confirm(
    root: &CommittedRoot,
    dir: Direction,
    generation: u32,
    seq: u64,
    attempt: Attempt,
    s_pc: &[u8; ml_dsa::SK_LEN],
) -> Result<Vec<u8>, ReEstError> {
    seal_signed_leg(
        root,
        FRAME_KIND_RE_CONFIRM,
        dir,
        generation,
        seq,
        attempt,
        &[],
        s_pc,
    )
}

/// Mint the fresh ML-KEM keypair a `RE-EST` carries.
///
/// The returning party generates this, publishes the encapsulation key in its
/// `RE-EST`, and keeps the decapsulation key to open the `RE-ACK` that answers
/// it. Both halves come back from one call for the reason
/// [`crate::dm::firstcontact::build`] gives about the opening ratchet
/// ephemeral: a caller that could keep the public half and drop the secret one
/// would lose the ability to re-root at all, and nothing on the wire would show
/// it.
///
/// The secret half must reach disk with the sealed `RE-EST` it belongs to —
/// [`crate::dm::resume::OwnSlot`] is where it goes — because a crash after the
/// commit re-emits the stored leg and must still be able to open the answer
/// (`docs/design/direct-messaging.md:1351`, A9.1(a)).
pub fn mint_ephemeral() -> Result<(Box<[u8; ml_kem::EK_LEN]>, EphemeralDecapKey), ReEstError> {
    let mut d = [0u8; ml_kem::SEED_LEN];
    let mut z = [0u8; ml_kem::SEED_LEN];
    getrandom::fill(&mut d).map_err(|_| ReEstError::EntropySource)?;
    getrandom::fill(&mut z).map_err(|_| ReEstError::EntropySource)?;
    let mut generated = ml_kem::keygen(&d, &z);
    d.zeroize();
    z.zeroize();
    // **The `Result` is wiped where it lies, not destructured.** `keygen`
    // returns the secret half inside a `Result`, and moving a `Copy` array out
    // of one copies rather than takes — so `let (ek, dk) = generated?` leaves
    // the `Result`'s own copy of the decapsulation key on this frame with
    // nothing able to reach it. Binding by reference keeps it reachable, and
    // `zeroize` runs before the `Result` goes out of scope.
    //
    // Nothing tests this shape, here or at the sibling sites in `answer`,
    // `complete` and `Ratchet::reestablished`. `tests/secret_zeroize_on_drop.rs`
    // hooks the global allocator and reads heap blocks as they are freed; a
    // `Copy` secret on a stack frame is never allocated, so no case there can go
    // red on it. Review is the guard for this class.
    match generated {
        Ok((ref ek, ref mut dk)) => {
            let out = (Box::new(*ek), EphemeralDecapKey::new(Box::new(*dk)));
            dk.zeroize();
            Ok(out)
        }
        Err(e) => Err(ReEstError::Module(e)),
    }
}

/// Answer a `RE-EST`: encapsulate to the ephemeral it carried, and re-root.
///
/// This is the **responder's** half. It produces the ciphertext the `RE-ACK`
/// carries and the re-rooted pair the responder commits, in one call, because
/// the shared secret must not outlive the call that folds it — a caller handed
/// `ss_new` to fold later could commit a root without its ciphertext, or a
/// ciphertext whose secret it no longer holds.
///
/// `ss_new` never leaves this function. That is what keeps the KEM secret inside
/// the crate: a caller receives a [`Rerooted`] and a ciphertext, neither of which
/// yields it.
pub fn answer(
    root: &CommittedRoot,
    peer_eph_ek: &[u8; ml_kem::EK_LEN],
) -> Result<(Rerooted, Box<[u8; ml_kem::CT_LEN]>), ReEstError> {
    let mut m = [0u8; ml_kem::SEED_LEN];
    getrandom::fill(&mut m).map_err(|_| ReEstError::EntropySource)?;
    let mut encapsulated = ml_kem::encapsulate(peer_eph_ek, &m);
    m.zeroize();
    // **The `Result` is wiped where it lies, not destructured.** `encapsulate`
    // returns the shared secret inside a `Result`, and moving a `Copy` array out
    // of one copies rather than takes — so the `Result`'s own copy of `ss_new`
    // would stay on this frame with nothing able to reach it. Binding by
    // reference folds the secret in place and wipes it before the `Result` goes
    // out of scope.
    match encapsulated {
        Ok((ref mut ss, ref ct)) => {
            let folded = reroot(root, ss).map_err(|e| ReEstError::Reroot(Box::new(e)));
            let ct = Box::new(*ct);
            ss.zeroize();
            folded.map(|rerooted| (rerooted, ct))
        }
        Err(e) => Err(ReEstError::Module(e)),
    }
}

/// Complete a re-establishment: decapsulate the `RE-ACK`'s ciphertext under the
/// ephemeral this party published, and re-root.
///
/// This is the **initiator's** half, and it reaches the same [`Rerooted`] the
/// responder's [`answer`] produced, because both derive from the same
/// `(RS_n, ss_new)` pair.
///
/// **The decapsulation key is consumed**, so the ephemeral cannot be used twice
/// and the secret half is zeroized when this call returns
/// ([`EphemeralDecapKey`] wipes on drop). An ephemeral answers exactly one
/// `RE-ACK`; a later attempt carries a new one.
///
/// **A wrong key does not fail here.** ML-KEM decapsulation uses implicit
/// rejection: a ciphertext that does not belong to this key yields a
/// pseudorandom secret rather than an error, so this call succeeds and produces
/// a root that simply differs from the responder's. The divergence surfaces when
/// the first frame under the re-rooted chain does not open, which is where a
/// receiver can attribute it.
pub fn complete(
    root: &CommittedRoot,
    eph_dk: EphemeralDecapKey,
    eph_ct: &[u8; ml_kem::CT_LEN],
) -> Result<Rerooted, ReEstError> {
    let mut decapsulated = ml_kem::decapsulate(eph_dk.as_bytes(), eph_ct);
    // Wiped where it lies rather than moved out, for the reason [`answer`]
    // records: a `Copy` array taken out of a `Result` leaves the `Result`'s copy
    // behind, and this one is the fresh shared secret.
    match decapsulated {
        Ok(ref mut ss) => {
            let folded = reroot(root, ss).map_err(|e| ReEstError::Reroot(Box::new(e)));
            ss.zeroize();
            folded
        }
        Err(e) => Err(ReEstError::Module(e)),
    }
}

/// A `RE-EST` that opened and verified. Only constructible by [`scan_re_est`],
/// so holding one is the proof.
#[derive(Debug)]
pub struct OpenedReEst {
    generation: u32,
    attempt: Attempt,
    eph_ek: Box<[u8; ml_kem::EK_LEN]>,
}

impl OpenedReEst {
    /// The re-establishment generation this leg was opened at.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The attempt the scan recovered — the value dedup keys on.
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }

    /// The sender's fresh ratchet ephemeral, to encapsulate to in the `RE-ACK`.
    pub fn eph_ek(&self) -> &[u8; ml_kem::EK_LEN] {
        &self.eph_ek
    }

    /// Consume this opened `RE-EST` for the authority to seal one `RE-ACK`
    /// answering it.
    ///
    /// Consuming rather than borrowing is the whole mechanism: the opened leg
    /// is neither `Clone` nor `Copy`, so one opened `RE-EST` yields one
    /// authority, and there is no way to name an authority for an attempt you
    /// merely hold the number of.
    pub fn answer(self) -> ReAckAuthority {
        ReAckAuthority {
            generation: self.generation,
            attempt: self.attempt,
        }
    }
}

/// Authority to seal a `RE-ACK` carrying a **fresh** ML-KEM ciphertext.
///
/// A9.1: *"The one thing forbidden is a fresh `eph_ct` under an unchanged
/// key."* On the answering side the attempt is always in hand — it came off the
/// peer's leg — so a bare [`Attempt`] parameter is precisely the shape that lets
/// a build re-encapsulate under a key that has already sealed a ciphertext, and
/// the peer then confirms one secret while this party holds another: root
/// divergence to a permanent unknown ephemeral. Minted only by
/// [`OpenedReEst::answer`], and deliberately **not `Clone` and not `Copy`**.
///
/// **The same three limits [`FreshAttempt`] documents apply here**, for the same
/// reasons, and are not restated as a claim this type closes more than it does:
/// re-running the scan over the same stored bytes mints a second authority; the
/// type knows nothing of what another process or a previous boot persisted; and
/// a re-emit is [`crate::dm::resume::SealedReEst`]'s stored bytes, not a second
/// call here. The store's commit guards remain the enforcement point; this
/// removes the caller's mistake at compile time.
#[derive(Debug)]
pub struct ReAckAuthority {
    generation: u32,
    attempt: Attempt,
}

#[cfg(test)]
impl ReAckAuthority {
    /// Mint an authority without opening a `RE-EST`, so a test can seal a
    /// `RE-ACK` at a chosen generation and attempt.
    ///
    /// `#[cfg(test)]` and crate-private: shipping it would reopen the exact hole
    /// [`OpenedReEst::answer`] exists to close, which is why it is a
    /// compile-time-absent constructor rather than a documented caveat.
    pub(crate) fn for_test(generation: u32, attempt: Attempt) -> Self {
        Self {
            generation,
            attempt,
        }
    }
}

impl ReAckAuthority {
    /// The generation of the `RE-EST` this answers.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The attempt this answers.
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }
}

/// A `RE-ACK` that opened and verified.
#[derive(Debug)]
pub struct OpenedReAck {
    generation: u32,
    attempt: Attempt,
    eph_ct: Box<[u8; ml_kem::CT_LEN]>,
}

impl OpenedReAck {
    /// The re-establishment generation this leg was opened at.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The attempt this leg answers.
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }

    /// The ciphertext that created the new generation.
    pub fn eph_ct(&self) -> &[u8; ml_kem::CT_LEN] {
        &self.eph_ct
    }
}

/// A `RE-CONFIRM` that opened and verified. It carries no payload past its
/// signature, so it carries no accessor past the exchange it settles.
#[derive(Debug)]
pub struct OpenedReConfirm {
    generation: u32,
    attempt: Attempt,
}

impl OpenedReConfirm {
    /// The re-establishment generation this leg settles.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The attempt this leg settles.
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }
}

/// Scan a leg read from `dir`'s pages as a `RE-EST` at the expected
/// `generation`, over the attempt window rooted at `last_seen`.
///
/// The window is `[last_seen, last_seen + MAX_GAP]`, inclusive at both ends and
/// skipping attempt `0`; `last_seen` is `0` for a correspondence that has opened
/// none. `generation`, `dir` and the leg kind come from the reader's own state,
/// never from the bytes. A leg that opens but whose signature does not verify
/// ends the scan with [`ReEstError::Signature`] rather than continuing.
pub fn scan_re_est(
    root: &CommittedRoot,
    dir: Direction,
    generation: u32,
    seq: u64,
    last_seen: u32,
    encoded: &[u8],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
) -> Result<OpenedReEst, ReEstError> {
    let (attempt, payload) = scan_signed_leg(
        root,
        FRAME_KIND_RE_EST,
        dir,
        generation,
        seq,
        last_seen,
        encoded,
        peer_pk_pc,
        ml_kem::EK_LEN,
    )?;
    let eph_ek: Box<[u8; ml_kem::EK_LEN]> = payload
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ReEstError::DidNotOpen)?;
    Ok(OpenedReEst {
        generation,
        attempt,
        eph_ek,
    })
}

/// Scan a leg read from `dir`'s pages as a `RE-ACK`.
pub fn scan_re_ack(
    root: &CommittedRoot,
    dir: Direction,
    generation: u32,
    seq: u64,
    last_seen: u32,
    encoded: &[u8],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
) -> Result<OpenedReAck, ReEstError> {
    let (attempt, payload) = scan_signed_leg(
        root,
        FRAME_KIND_RE_ACK,
        dir,
        generation,
        seq,
        last_seen,
        encoded,
        peer_pk_pc,
        ml_kem::CT_LEN,
    )?;
    let eph_ct: Box<[u8; ml_kem::CT_LEN]> = payload
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ReEstError::DidNotOpen)?;
    Ok(OpenedReAck {
        generation,
        attempt,
        eph_ct,
    })
}

/// Scan a leg read from `dir`'s pages as a `RE-CONFIRM`.
pub fn scan_re_confirm(
    root: &CommittedRoot,
    dir: Direction,
    generation: u32,
    seq: u64,
    last_seen: u32,
    encoded: &[u8],
    peer_pk_pc: &[u8; ml_dsa::PK_LEN],
) -> Result<OpenedReConfirm, ReEstError> {
    let (attempt, _) = scan_signed_leg(
        root,
        FRAME_KIND_RE_CONFIRM,
        dir,
        generation,
        seq,
        last_seen,
        encoded,
        peer_pk_pc,
        0,
    )?;
    Ok(OpenedReConfirm {
        generation,
        attempt,
    })
}

/// The raw coin byte A3.7 expands from the superseded root:
/// `HKDF(RS_n, <tiebreak label> ‖ reconnect_gen)`.
///
/// Factored out of [`tiebreak_winner`] so the expansion and the bit selection
/// can be pinned separately. A known-answer vector over both is the only thing
/// that stops two implementations picking different bits, agreeing internally,
/// and disagreeing on the wire.
fn tiebreak_bytes(root: &CommittedRoot, generation: u32) -> Result<[u8; 1], ReEstError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_REEST_SALT), root.as_bytes())
        .map_err(ReEstError::Kdf)?;
    let mut info = Vec::with_capacity(domain::DM_REEST_TIEBREAK.len() + 16);
    info.extend_from_slice(domain::DM_REEST_TIEBREAK);
    push_lp(&mut info, &generation.to_be_bytes());
    let mut coin = [0u8; 1];
    hkdf.expand(&info, &mut coin).map_err(ReEstError::Kdf)?;
    Ok(coin)
}

/// Which direction's handshake survives a simultaneous re-establishment, per
/// A3.7: the coin's **first bit** names the direction.
///
/// "First bit" is the **least-significant bit of the first expanded byte**, and
/// that spelling is wire, not taste: an implementation reading the
/// most-significant bit instead would agree with itself on both sides and
/// disagree with this one, which no property test over agreement or variation
/// can see. A known-answer vector in this module's tests pins it.
///
/// Ungrindable and unobservable for the reasons A3.7 gives: no frame material
/// enters the selector, so no keygen spend biases it, and a third party holds
/// neither the root nor the outcome.
pub fn tiebreak_winner(root: &CommittedRoot, generation: u32) -> Result<Direction, ReEstError> {
    let mut coin = tiebreak_bytes(root, generation)?;
    let winner = if coin[0] & 1 == 0 {
        Direction::AToB
    } else {
        Direction::BToA
    };
    coin.zeroize();
    Ok(winner)
}

/// What A3.7's local check says about an incoming `RE-EST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContestOutcome {
    /// No initiation of our own at this generation, so this is an ordinary
    /// response: answer as a plain responder.
    NoContest,
    /// The coin names us. Do nothing with the peer's frame and keep waiting for
    /// the `RE-ACK` to our own.
    WeSurvive,
    /// The coin names the peer. Abandon our own handshake and answer theirs as
    /// an ordinary responder.
    WeAbandon,
}

/// Resolve a contest between our own pending initiation and an incoming
/// `RE-EST`, per A3.7's rule that detection is a local check rather than a race.
///
/// `our_pending_initiation_at` is the generation of our own un-answered
/// initiation, if we hold one. A contest fires only when it is this generation:
/// a pending initiation at another generation is not the same exchange, so it
/// does not make us anything but an ordinary responder here.
///
/// Both sides compute the same coin from the same root and generation, which is
/// why asymmetric observation converges — the loser answers whichever moment it
/// observes and the winner waits, whatever order the two sweeps ran in.
pub fn contest_outcome(
    root: &CommittedRoot,
    generation: u32,
    our_direction: Direction,
    our_pending_initiation_at: Option<u32>,
) -> Result<ContestOutcome, ReEstError> {
    if our_pending_initiation_at != Some(generation) {
        return Ok(ContestOutcome::NoContest);
    }
    let winner = tiebreak_winner(root, generation)?;
    Ok(if winner == our_direction {
        ContestOutcome::WeSurvive
    } else {
        ContestOutcome::WeAbandon
    })
}

/// What to do with an opened `RE-EST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReEstAdmission {
    /// A pair beyond the accepted one — a new generation, or A5.1's superseding
    /// higher attempt at an unconfirmed candidate — and the response budget
    /// admitted it: compose and emit a `RE-ACK`.
    Emit,
    /// A differing attempt at a **confirmed** generation. Nothing changed and no
    /// budget was charged.
    ///
    /// **This is wider than the text it enforces, deliberately.** A5.1(ii) says
    /// a confirmed candidate *"is locked, and a later-arriving **lower-or-stale**
    /// attempt's `RE-EST` never supersedes it"*, naming only the lower case; a
    /// *higher* attempt is refused here too, because confirmation means a frame
    /// has already opened under the re-rooted chain (A6.1) and re-rooting again
    /// would fork the root the peer is already using — the permanent
    /// `UnknownEphemeral` divergence ([`crate::dm::ratchet`]) A9.1 forbids,
    /// reached from the answering side.
    ///
    /// Distinct from [`Self::Dropped`] because the two say different things
    /// about the peer: a drop is an ordinary stale frame, and this is a peer
    /// re-attempting an exchange this side has already settled — which is a
    /// state worth surfacing rather than a routine replay.
    Locked,
    /// The attempt already accepted, arriving again. Re-serve the stored
    /// `RE-ACK`, byte-identical. **No budget was charged.**
    ReServe,
    /// A new attempt the response budget refused. Nothing was accepted, so the
    /// same attempt may be admitted later.
    Withheld,
    /// A pair ordering below the accepted one — a lower attempt at the accepted
    /// generation, or any lower generation. A3.4's differing frame at an
    /// already-accepted generation: dropped with no state change and no budget
    /// charged.
    Dropped,
}

/// The duplicate check A9.4(ii) requires ahead of the response-emission budget.
///
/// **This is A3.4's acceptance slot, and it is NOT A5.3's dedup memory.** The
/// two are easy to conflate and the design keeps them apart. A3.4 accepts one
/// `RE-EST` per generation and A9.4(ii) requires that check to run before the
/// budget is charged; this type answers that question, from the durable slot it
/// is built out of. A5.3's byte-novelty memory is a different object with
/// different obligations: keyed `(gen, attempt, leg, dir, seq)` rather than
/// `(gen, attempt)`, covering all three legs rather than the accepted `RE-EST`,
/// and evicted on `RS_n` retirement rather than replaced by the next
/// acceptance. It lives in
/// [`ResumeRecord::dedup`](crate::dm::resume::ResumeRecord::dedup), and what it
/// defends against is a co-host re-serving captured bytes to re-fire the
/// peer-state-regressed alarm — a question this gate does not ask.
///
/// **The ordering is the whole point, and it is structural rather than
/// documented.** A9.4(ii): "header/`attempt` dedup is evaluated **before** the
/// response-emission budget is charged, so a crash-loop re-emitting the same
/// attempt is deduped and never drains the peer's `RE-ACK` budget — the property
/// that makes A8.4's DoS-resistance hold." [`Self::admit`] takes the charge as a
/// closure and calls it on exactly one path, so a build cannot charge first
/// without moving the call.
///
/// **The rule it applies, stated from A3.4 and A5.1 rather than paraphrased.**
/// A3.4: *"One `RE-EST` is accepted per generation — the first the receiver
/// commits … a differing frame at an already-accepted generation is dropped
/// without any state change"*, and *"a byte-identical replay of an accepted
/// generation's `RE-EST` is answered idempotently: the stored `RE-ACK` is
/// re-served"*. A5.1 then carves out the one differing frame that is **not**
/// dropped: a returning initiator *"re-initiates — a fresh attempt … which
/// supersedes the responder's prior unconfirmed candidate"*. So, against the
/// one accepted `(generation, attempt)`:
///
/// - the same pair → [`ReEstAdmission::ReServe`], no budget charged;
/// - a **lower** attempt at that generation, or **any lower generation** →
///   [`ReEstAdmission::Dropped`], no state change and no charge — A3.4's
///   differing frame, and the ordering that makes generations monotonic;
/// - a **higher** attempt at that generation while the candidate is
///   **unconfirmed**, or a **higher generation** → admitted subject to the
///   budget, replacing the slot. The higher-attempt case is A5.1's supersede and
///   the reason this is not the flat "first commit wins" that A3.4 alone reads
///   as;
/// - **any** differing attempt at a **confirmed** generation →
///   [`ReEstAdmission::Locked`], ahead of the ordering comparison and ahead of
///   the budget — wider than A5.1(ii)'s *"lower-or-stale"*, for the reason
///   [`ReEstAdmission::Locked`] gives;
/// - anything at or below the record's committed `reconnect_gen` →
///   [`ReEstAdmission::Dropped`], also ahead of the budget.
///
/// **A5.1(ii)'s confirmation lock is the durable half of this gate.** A5.1(ii):
/// a confirmed candidate *"is locked, and a later-arriving lower-or-stale
/// attempt's `RE-EST` never supersedes it"*, and A6.1 says what confirms one —
/// *"the first frame that opens under the re-rooted chain — content *or*
/// RE-CONFIRM, whichever arrives"*. The flag is persisted in the resume
/// record's acceptance slot, so it survives the restart that this whole feature
/// exists to survive, and [`Self::from_record`] is how it comes back. A gate
/// built empty after a restart would answer *unconfirmed* to a generation the
/// two parties had already settled, and a returning peer's stale attempt would
/// supersede it — the split-brain A5.1 opens with.
///
/// **One slot, not a set**, which is what the rule above allows: only the
/// accepted pair has to be remembered, so the memory is bounded by
/// construction, with no eviction policy to size and none to get wrong.
///
/// **Neither `Clone`, `Copy` nor `Default`**, which is the same reason
/// [`ReEstGate::admit`] takes `&mut self`: a copy would accept an attempt its
/// original never learned about, and a default would answer *nothing accepted,
/// nothing confirmed* for a correspondence whose record says otherwise. The
/// state comes from the record, or from [`Self::new`] naming the empty case
/// deliberately.
#[derive(Debug)]
pub struct ReEstGate {
    accepted: Option<(u32, Attempt)>,
    confirmed: bool,
    /// The record's committed `reconnect_gen`. Anything at or below it names an
    /// exchange A3.4 has already closed.
    floor: u32,
}

impl ReEstGate {
    /// A gate that has accepted nothing — what a correspondence with an empty
    /// acceptance slot loads as.
    #[expect(
        clippy::new_without_default,
        reason = "a Default would answer 'nothing accepted, nothing confirmed' for a \
                  correspondence whose record says otherwise, which is A5.1's split-brain \
                  arriving through a trait nobody called on purpose; the state comes from \
                  ReEstGate::from_record, or from this constructor naming the empty case"
    )]
    pub const fn new() -> Self {
        Self {
            accepted: None,
            confirmed: false,
            floor: 0,
        }
    }

    /// Build the gate from the durable acceptance slot, at load.
    ///
    /// **This is the constructor production uses**, and the reason the type has
    /// no `Default`: the accepted pair and A5.1(ii)'s confirmation lock are
    /// durable state (A5.4), so a gate that did not read them would answer
    /// questions about this correspondence from an empty memory after every
    /// restart.
    pub fn from_record(record: &ResumeRecord) -> Self {
        // **The floor is carried even when the slot is empty, and that is the
        // half a slot-only reading loses.** A3.14 zeroes the acceptance slot on
        // completion, so after every completed handshake the slot says nothing
        // — and a gate seeded from it alone would admit any generation at all,
        // including ones already committed. A3.4 requires the opposite: *"a
        // differing frame at an already-accepted generation is dropped without
        // any state change"*, and a committed generation is the strongest case
        // of one. The committed number survives the zeroing, so it is what
        // bounds the gate from below.
        let floor = record.reconnect_gen();
        match record.acceptance() {
            Some(slot) => Self {
                accepted: Some((slot.generation(), slot.attempt())),
                confirmed: slot.confirmed(),
                floor,
            },
            None => Self {
                floor,
                ..Self::new()
            },
        }
    }

    /// The committed generation below which nothing is admitted.
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// The accepted pair, if one has been.
    ///
    /// Stored as an [`Attempt`] rather than a bare `u32`, so the empty-slot
    /// spelling is unrepresentable here instead of being an impossible state
    /// this accessor would have to decide how to report.
    pub fn accepted(&self) -> Option<(u32, Attempt)> {
        self.accepted
    }

    /// Whether a frame has opened under the accepted candidate's re-rooted
    /// chain (A6.1), locking it against supersede (A5.1(ii)).
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Admit an opened `RE-EST`, charging `budget` only if the frame is new.
    ///
    /// `budget` returns whether the response-emission budget admits one more
    /// `RE-ACK`. It is called on exactly one path — a `(generation, attempt)`
    /// strictly beyond what has been accepted, at a generation that is not
    /// locked — so a replay, a stale frame and a supersede of a confirmed
    /// candidate all cost nothing, however many times they arrive.
    ///
    /// **The confirmation check runs before the budget closure**, which is
    /// A9.4(ii)'s ordering applied to the case A5.1(ii) adds: a peer looping on
    /// an exchange this side has settled must not drain the response budget any
    /// more than a peer replaying one frame may.
    pub fn admit(
        &mut self,
        generation: u32,
        attempt: Attempt,
        budget: impl FnOnce() -> bool,
    ) -> ReEstAdmission {
        let incoming = (generation, attempt);
        // Ahead of everything but the re-serve: a generation the record has
        // already committed is closed whatever the acceptance slot holds, and a
        // replay of the accepted pair still costs nothing.
        if self.accepted != Some(incoming) && generation <= self.floor {
            return ReEstAdmission::Dropped;
        }
        match self.accepted {
            Some(seen) if incoming == seen => return ReEstAdmission::ReServe,
            Some(seen) if self.confirmed && generation == seen.0 => {
                return ReEstAdmission::Locked;
            }
            Some(seen) if incoming < seen => return ReEstAdmission::Dropped,
            _ => {}
        }
        if !budget() {
            return ReEstAdmission::Withheld;
        }
        self.accepted = Some(incoming);
        // A supersede replaces the candidate, so whatever confirmed the previous
        // one says nothing about this one. The lock is scoped to the generation
        // that earned it: an admission at a new generation starts unlocked, and
        // an admission at the accepted generation is only reachable while that
        // generation is still unconfirmed.
        self.confirmed = false;
        ReEstAdmission::Emit
    }
}

/// How far a correspondence has gone toward `C` in its current re-initiation
/// window — the toward-`C` count A9.2 puts in the resume record.
///
/// **Two numbers, not one, and the count is the difference between them.** A7.3
/// puts a window-start anchor (`attempt_at_window_start`) in the durable resume
/// record and derives *"attempts this window"* as
/// `attempt − attempt_at_window_start`, rather than persisting a second counter:
/// *"Both are in the atomically-replaced resume blob, so a crash cannot reset
/// the toward-`C` count and let a crash-loop mint `>C` attempts"*. A separately
/// stored count would be free to disagree with the monotone attempt counter it
/// is supposed to describe; a subtraction cannot.
///
/// **The anchor moves only on observed peer progress.** A8.2 makes window
/// membership and rollover *"an idempotent derivation from durable `last_seen`
/// … recomputed at load"*, so there is no time-based rollover to tear at a
/// boundary and no way for a window to turn over while the peer has opened
/// nothing. [`Self::observe_peer_opened`] is the only reset, and what it takes
/// is the attempt an opened `RE-ACK` names — see [`MAX_GAP`] for why that is
/// what keeps a sender inside the receiver's scan window.
///
/// Every value here is a projection of [`ResumeRecord`]; nothing is stored twice
/// and [`Self::from_record`] is the load-time derivation A8.2 asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptBudget {
    anchor: u32,
    attempt: u32,
}

impl AttemptBudget {
    /// A correspondence that has attempted nothing: the anchor and the attempt
    /// counter both before [`Attempt::FIRST`].
    pub const fn empty() -> Self {
        Self {
            anchor: 0,
            attempt: 0,
        }
    }

    /// The anchor and the attempt a resume record carries — A8.2's load-time
    /// derivation.
    ///
    /// The attempt comes from the own-initiation slot, which is where the
    /// monotone counter lives; a record whose slot stands empty has attempted
    /// nothing since its last completion and reads as `0`.
    pub fn from_record(record: &ResumeRecord) -> Self {
        Self {
            anchor: record.attempt_at_window_start(),
            attempt: record.attempt().map_or(0, Attempt::get),
        }
    }

    /// The window anchor and the counter, without a record — for a caller that
    /// holds both numbers already.
    pub fn at(anchor: u32, attempt: u32) -> Self {
        Self { anchor, attempt }
    }

    /// The window anchor, for writing back into a record.
    pub fn anchor(self) -> u32 {
        self.anchor
    }

    /// The monotone attempt counter this budget is measured against.
    pub fn attempt(self) -> u32 {
        self.attempt
    }

    /// Attempts spent this window: `attempt − attempt_at_window_start`.
    ///
    /// Saturating, so a record whose anchor somehow sits above its attempt reads
    /// as a fresh window rather than wrapping to four billion — a wrap would
    /// report a window with more headroom than any real one has.
    pub fn count(self) -> u32 {
        self.attempt.saturating_sub(self.anchor)
    }

    /// Whether the ceiling is reached and the party gives up rather than
    /// re-initiating again in this window.
    pub fn exhausted(self) -> bool {
        self.count() >= ATTEMPT_CEILING
    }

    /// Spend one attempt. `None` at the ceiling, which is the give-up A9 makes
    /// loud rather than a silent stall.
    pub fn charge(self) -> Option<Self> {
        if self.exhausted() {
            return None;
        }
        Some(Self {
            anchor: self.anchor,
            attempt: self.attempt + 1,
        })
    }

    /// Reset the window anchor to an attempt the peer has opened.
    ///
    /// **The only reset, and it takes an observation rather than a clock.** A8.2
    /// derives the rollover from durable `last_seen`, and the observation that
    /// advances `last_seen` is a `RE-ACK` answering one of our own attempts —
    /// [`OpenedReAck::attempt`] is where the number comes from. An ordinary
    /// frame carries no attempt at all (a leg has no clear fields), so there is
    /// nothing an ordinary frame could pass here.
    ///
    /// **Inert outside the current window.** An attempt at or below the anchor
    /// is a window this side has already left, and one above the counter names
    /// an attempt this side never sealed; neither is progress, and either
    /// moving the anchor would hand a sender a window's worth of fresh attempts
    /// the peer never asked for — which is the `>C` mint A7.3's persistence
    /// exists to prevent.
    pub fn observe_peer_opened(self, attempt: Attempt) -> Self {
        let observed = attempt.get();
        if observed > self.anchor && observed <= self.attempt {
            return Self {
                anchor: observed,
                attempt: self.attempt,
            };
        }
        self
    }
}

#[cfg(test)]
mod tests {

    /// **The two sides of one handshake reach the same re-rooted pair.**
    ///
    /// The returning party mints an ephemeral and publishes the encapsulation
    /// key; the peer encapsulates to it and re-roots; the returning party
    /// decapsulates and re-roots. Both outputs must agree, or the resumed channel
    /// derives its message keys from two different roots and every frame fails to
    /// open with no way back.
    #[test]
    fn a_kem_round_trip_reaches_one_rerooted_pair_on_both_sides() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let root = CommittedRoot::from_bytes(&[0x5c; 32]);

        let (ek, dk) = mint_ephemeral().expect("the module is operational");
        let (answered, ct) = answer(&root, &ek).expect("the responder encapsulates");
        let completed = complete(&root, dk, &ct).expect("the initiator decapsulates");

        assert_eq!(
            completed.next().as_bytes(),
            answered.next().as_bytes(),
            "the two sides committed different retained roots"
        );
        assert_eq!(
            completed.ratchet_root().as_bytes(),
            answered.ratchet_root().as_bytes(),
            "the two sides opened the resumed channel on different ratchet roots"
        );
    }

    /// **A wrong decapsulation key yields a different root rather than an
    /// error**, and the test says so rather than expecting a refusal.
    ///
    /// ML-KEM uses implicit rejection: a ciphertext that does not belong to the
    /// key produces a pseudorandom secret, constant-time, with nothing to
    /// observe. So `complete` succeeds and the divergence is only visible at the
    /// first frame under the re-rooted chain. Asserting a refusal here would pin
    /// behaviour the primitive does not have.
    #[test]
    fn a_wrong_decapsulation_key_diverges_silently_rather_than_failing() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let root = CommittedRoot::from_bytes(&[0x5c; 32]);

        // The matching key is dropped unused on purpose: this case is about the
        // one that does not match.
        let (ek, _dk) = mint_ephemeral().expect("operational");
        let (_other_ek, wrong_dk) = mint_ephemeral().expect("operational");
        let (answered, ct) = answer(&root, &ek).expect("operational");

        let diverged = complete(&root, wrong_dk, &ct).expect("implicit rejection does not error");
        assert_ne!(
            diverged.ratchet_root().as_bytes(),
            answered.ratchet_root().as_bytes(),
            "a wrong key reached the right root, so the secret is not reaching the derivation"
        );

        // Positive control: the right key does agree, so the assertion above is
        // about the key rather than about `complete` being broken for everyone.
        let (ek, dk) = mint_ephemeral().expect("operational");
        let (answered, ct) = answer(&root, &ek).expect("operational");
        assert_eq!(
            complete(&root, dk, &ct)
                .expect("operational")
                .ratchet_root()
                .as_bytes(),
            answered.ratchet_root().as_bytes()
        );
    }

    /// **A different committed root reaches a different resumed channel**, which
    /// is what makes `RS_n` load-bearing rather than decorative: a party that
    /// holds the fresh KEM secret but not the retained root cannot re-root.
    #[test]
    fn the_committed_root_is_an_input_to_the_resumed_channel() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let (ek, dk) = mint_ephemeral().expect("operational");
        let (answered, ct) = answer(&CommittedRoot::from_bytes(&[0x5c; 32]), &ek).expect("ok");
        let under_other_root = complete(&CommittedRoot::from_bytes(&[0x5d; 32]), dk, &ct)
            .expect("implicit rejection does not error");
        assert_ne!(
            under_other_root.ratchet_root().as_bytes(),
            answered.ratchet_root().as_bytes(),
            "the retained root is not reaching the derivation"
        );
    }

    use super::*;
    use crate::dm::eph_dk_fixture;
    use crate::identity::keys::{ML_DSA_SEED_LEN, SignKeypair};

    /// Power the crypto module on. Every derivation here refuses at
    /// `PowerOff`, and a test binary reaches the module in whatever state its
    /// predecessors left it, so each crypto test asks rather than assumes.
    fn ready() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    /// The sequence position every fixture leg is filed at, unless it is the
    /// value under test. Deliberately neither 0 nor 1: a `seq` dropped from a
    /// derivation would still collide with a zero default.
    const SEQ: u64 = 42;

    fn root() -> CommittedRoot {
        CommittedRoot::from_bytes(&[3u8; 32])
    }

    fn other_root() -> CommittedRoot {
        CommittedRoot::from_bytes(&[4u8; 32])
    }

    fn keypair(tag: u8) -> SignKeypair {
        ready();
        SignKeypair::from_ml_dsa_seed(&[tag; ML_DSA_SEED_LEN]).expect("a keypair from a fixed seed")
    }

    fn eph_ek() -> [u8; ml_kem::EK_LEN] {
        [9u8; ml_kem::EK_LEN]
    }

    fn eph_ct() -> [u8; ml_kem::CT_LEN] {
        [11u8; ml_kem::CT_LEN]
    }

    /// A sealed `RE-EST` comes back with the ephemeral it went in with, and the
    /// scan recovers the attempt nothing on the wire names.
    ///
    /// Kills a `seal_signed_leg` that seals the payload without the signature,
    /// or an ordering swap between them: the length assertion and the ephemeral
    /// comparison both move.
    #[test]
    fn a_re_est_round_trips() {
        let ours = keypair(1);
        let fresh = FreshAttempt::first();
        let bytes = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(bytes.len(), LEG_LEN);
        let opened = scan_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            0,
            &bytes,
            ours.public_key(),
        )
        .unwrap();
        assert_eq!(opened.generation(), 7);
        assert_eq!(opened.attempt(), Attempt::FIRST);
        assert_eq!(opened.eph_ek(), &eph_ek());
    }

    /// A sealed `RE-ACK` comes back with the ciphertext it went in with.
    ///
    /// Kills an `open_signed_leg` that splits the payload at the wrong offset:
    /// the ciphertext comparison fails rather than the length check.
    #[test]
    fn a_re_ack_round_trips() {
        let ours = keypair(2);
        let bytes = seal_re_ack(
            &root(),
            Direction::BToA,
            SEQ,
            ReAckAuthority::for_test(7, Attempt::FIRST),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(bytes.len(), LEG_LEN);
        let opened = scan_re_ack(
            &root(),
            Direction::BToA,
            7,
            SEQ,
            0,
            &bytes,
            ours.public_key(),
        )
        .unwrap();
        assert_eq!(opened.attempt(), Attempt::FIRST);
        assert_eq!(opened.eph_ct(), &eph_ct());
    }

    /// A sealed `RE-CONFIRM` carries only its signature and still authenticates
    /// the exchange it settles.
    #[test]
    fn a_re_confirm_round_trips() {
        let ours = keypair(3);
        let bytes = seal_re_confirm(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(bytes.len(), LEG_LEN);
        let opened = scan_re_confirm(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            0,
            &bytes,
            ours.public_key(),
        )
        .unwrap();
        assert_eq!(opened.generation(), 7);
        assert_eq!(opened.attempt(), Attempt::FIRST);
    }

    /// **The wire carries no discriminator.** All three legs are one length, so
    /// a reader who cannot open them cannot tell them apart by size — A3.9's
    /// "shaped exactly like an ordinary frame", and the replacement for the
    /// per-kind body length a clear-labelled build could rely on.
    ///
    /// Kills padding a leg to its own payload's bucket instead of the shared
    /// one: `RE-CONFIRM` is ~1568 bytes shorter than the other two and the
    /// equality fails.
    #[test]
    fn every_leg_is_one_length_on_the_wire() {
        let ours = keypair(4);
        let fresh = FreshAttempt::first();
        let est = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        let ack = seal_re_ack(
            &root(),
            Direction::AToB,
            SEQ,
            ReAckAuthority::for_test(7, Attempt::FIRST),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        let confirm = seal_re_confirm(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(est.len(), ack.len());
        assert_eq!(ack.len(), confirm.len());
        assert_eq!(est.len(), LEG_LEN);
    }

    /// The three kinds are pairwise distinct.
    ///
    /// Every use of a kind is length-prefixed, so prefix-freeness is not
    /// required; what matters is that two kinds sharing a spelling would
    /// collapse two key namespaces into one, which is what this pins. Kills a rename that
    /// duplicates an existing kind.
    #[test]
    fn frame_kinds_are_distinct() {
        let kinds = [FRAME_KIND_RE_EST, FRAME_KIND_RE_ACK, FRAME_KIND_RE_CONFIRM];
        for (i, a) in kinds.iter().enumerate() {
            for (j, b) in kinds.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "two frame kinds share a spelling: {a:?}");
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // The key layer. These drive `seal_leg` / `open_leg` directly, with no
    // signature anywhere, so each of the four key inputs is exercised on its
    // own. Through the public API the signature binds the same four values and
    // would catch a dropped key binding by itself — which is exactly how a key
    // binding goes untested while looking covered.
    // ---------------------------------------------------------------------

    /// A leg sealed as one kind does not open as another **at the key layer**.
    ///
    /// Kills dropping `kind` from `leg_info`. `RE-EST` and `RE-ACK` payloads
    /// are both `ml_kem::EK_LEN == ml_kem::CT_LEN == 1568` bytes and every leg
    /// pads to one bucket, so nothing about the length would notice.
    #[test]
    fn a_leg_does_not_open_as_another_kind_at_the_key_layer() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        assert!(matches!(
            open_leg(
                &root(),
                FRAME_KIND_RE_ACK,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST,
                &bytes
            ),
            Err(ReEstError::DidNotOpen)
        ));
        // Control: the kind it was sealed as does open.
        assert!(
            open_leg(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST,
                &bytes
            )
            .is_ok()
        );
    }

    /// A leg sealed in one direction does not open in the other.
    ///
    /// Kills dropping `dir` from `leg_info` — A4.6's fix for two parties
    /// sealing their own `RE-EST` under one key in a contest.
    #[test]
    fn a_leg_does_not_open_in_the_other_direction_at_the_key_layer() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        assert!(matches!(
            open_leg(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::BToA,
                7,
                SEQ,
                Attempt::FIRST,
                &bytes
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// A leg sealed at one generation does not open at another.
    ///
    /// Kills dropping `generation` from `leg_info`. There is no clear
    /// generation field and no AAD, so the key is the only place it is bound at
    /// this layer.
    #[test]
    fn a_leg_does_not_open_at_another_generation_at_the_key_layer() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        assert!(matches!(
            open_leg(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                8,
                SEQ,
                Attempt::FIRST,
                &bytes
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// A leg sealed at one attempt does not open at another.
    ///
    /// Kills dropping `attempt` from `leg_info`, which would let two attempts
    /// at one generation share a key — B-CRYPTO-2, the collision A4.6 added the
    /// input to close.
    #[test]
    fn a_leg_does_not_open_at_another_attempt_at_the_key_layer() {
        ready();
        let second = Attempt::FIRST.advance().unwrap().attempt();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        assert!(matches!(
            open_leg(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                second,
                &bytes
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// A leg does not open under a different committed root.
    ///
    /// Kills a `leg_key` that ignores the root — the derivation would then be
    /// public and any observer could forge a leg.
    #[test]
    fn a_leg_does_not_open_under_another_root_at_the_key_layer() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        assert!(matches!(
            open_leg(
                &other_root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST,
                &bytes
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// The key's `info` is pinned byte for byte, length prefixes included.
    ///
    /// **Why a known-answer test and not a collision fixture.** The honest
    /// probe for a length prefix is two field tuples that concatenate to one
    /// byte string, and this encoder admits none: `kind` is the only
    /// variable-length field and every field after it is fixed width
    /// (`dir.label()` is always 3 bytes, `generation` and `attempt` 4 each), so
    /// the unprefixed concatenation is still uniquely decodable from the end. A
    /// collision fixture would therefore have to be a lie. What is real is that
    /// the prefixes are **wire**: the `info` is an input to a key two
    /// implementations must derive identically, and adding one variable-length
    /// field later — a suite tag, a longer kind — reopens the ambiguity with
    /// nothing to notice. So the encoding is pinned as a contract.
    ///
    /// Kills stripping the length prefixes, reordering the fields, changing the
    /// prefix width or endianness, switching the generation or attempt to
    /// little-endian, and changing [`domain::DM_REEST_LEG`].
    #[test]
    fn the_key_info_is_pinned_byte_for_byte() {
        let mut expected = Vec::new();
        expected.extend_from_slice(b"daemonseed/dm/reest/leg/v1");
        expected.extend_from_slice(&6u64.to_be_bytes());
        expected.extend_from_slice(b"re-est");
        expected.extend_from_slice(&3u64.to_be_bytes());
        expected.extend_from_slice(b"a2b");
        expected.extend_from_slice(&4u64.to_be_bytes());
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&SEQ.to_be_bytes());
        expected.extend_from_slice(&4u64.to_be_bytes());
        expected.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            leg_info(FRAME_KIND_RE_EST, Direction::AToB, 7, SEQ, Attempt::FIRST),
            expected
        );
        // Control: the assertion above is over a value that varies with its
        // inputs, not a constant. Every field moves it.
        for other in [
            leg_info(FRAME_KIND_RE_ACK, Direction::AToB, 7, SEQ, Attempt::FIRST),
            leg_info(FRAME_KIND_RE_EST, Direction::BToA, 7, SEQ, Attempt::FIRST),
            leg_info(FRAME_KIND_RE_EST, Direction::AToB, 8, SEQ, Attempt::FIRST),
            leg_info(
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ + 1,
                Attempt::FIRST,
            ),
            leg_info(
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST.advance().unwrap().attempt(),
            ),
        ] {
            assert_ne!(other, expected, "a field did not move the encoding");
        }
    }

    /// The signature preimage is pinned byte for byte for the same reason, and
    /// with one more thing at stake: `payload` IS variable-length and it is
    /// last, so the prefixes are what stop a kind's tail being read as the head
    /// of a payload once a second variable field joins it.
    ///
    /// Kills stripping the prefixes, reordering, and changing
    /// [`domain::DM_REEST_SIG`].
    #[test]
    fn the_signature_preimage_is_pinned_byte_for_byte() {
        let mut expected = Vec::new();
        expected.extend_from_slice(b"daemonseed/dm/reest/sig/v1");
        expected.extend_from_slice(&10u64.to_be_bytes());
        expected.extend_from_slice(b"re-confirm");
        expected.extend_from_slice(&3u64.to_be_bytes());
        expected.extend_from_slice(b"b2a");
        expected.extend_from_slice(&4u64.to_be_bytes());
        expected.extend_from_slice(&9u32.to_be_bytes());
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&SEQ.to_be_bytes());
        expected.extend_from_slice(&4u64.to_be_bytes());
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(b"hi");
        assert_eq!(
            leg_sig_input(
                FRAME_KIND_RE_CONFIRM,
                Direction::BToA,
                9,
                SEQ,
                Attempt::FIRST,
                b"hi"
            ),
            expected
        );
        // Control: every field moves it, so the pin is not over a constant.
        for other in [
            leg_sig_input(
                FRAME_KIND_RE_EST,
                Direction::BToA,
                9,
                SEQ,
                Attempt::FIRST,
                b"hi",
            ),
            leg_sig_input(
                FRAME_KIND_RE_CONFIRM,
                Direction::AToB,
                9,
                SEQ,
                Attempt::FIRST,
                b"hi",
            ),
            leg_sig_input(
                FRAME_KIND_RE_CONFIRM,
                Direction::BToA,
                10,
                SEQ,
                Attempt::FIRST,
                b"hi",
            ),
            leg_sig_input(
                FRAME_KIND_RE_CONFIRM,
                Direction::BToA,
                9,
                SEQ + 1,
                Attempt::FIRST,
                b"hi",
            ),
            leg_sig_input(
                FRAME_KIND_RE_CONFIRM,
                Direction::BToA,
                9,
                SEQ,
                Attempt::FIRST.advance().unwrap().attempt(),
                b"hi",
            ),
            leg_sig_input(
                FRAME_KIND_RE_CONFIRM,
                Direction::BToA,
                9,
                SEQ,
                Attempt::FIRST,
                b"ho",
            ),
        ] {
            assert_ne!(other, expected, "a field did not move the encoding");
        }
    }

    /// A leg sealed at one sequence position does not open at another.
    ///
    /// Kills dropping `seq` from `leg_info`. A5.3 keys its dedup memory on
    /// `(gen, attempt, leg, dir, seq)` and the ordinary frame binds `seq` in
    /// both its AAD and `msg_sig`; without it here, a captured leg could be
    /// re-filed at another position on the same plane and still open.
    #[test]
    fn a_leg_does_not_open_at_another_seq_at_the_key_layer() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        assert!(matches!(
            open_leg(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ + 1,
                Attempt::FIRST,
                &bytes
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// **The leg key's known-answer vector.** Pins the 32 derived bytes, not the
    /// `info` that goes into them.
    ///
    /// The `info` KAT above pins what is fed to HKDF and says nothing about what
    /// is done with it — the extract salt, the hash, the output length. Both
    /// parties derive through this same function in every other test, so
    /// agreement there is structural: replacing `DM_REEST_SALT` with another
    /// label, or passing `None`, changes every byte on the wire and breaks
    /// nothing. This is the same failure the coin vector exists to prevent,
    /// applied to the key.
    ///
    /// Regenerating these bytes is a wire change and needs the same
    /// deliberation as changing a frozen domain label.
    #[test]
    fn the_leg_key_is_a_known_answer_vector() {
        ready();
        const KEY: [u8; 32] = [
            0x96, 0xAF, 0xB0, 0x6F, 0xCB, 0xFA, 0x00, 0x70, 0x14, 0x2A, 0x81, 0x0E, 0xC0, 0x74,
            0x14, 0x06, 0x29, 0x57, 0x1A, 0x7F, 0xE2, 0x46, 0xB6, 0x14, 0xA5, 0xDC, 0x2A, 0xEB,
            0x42, 0x5F, 0x27, 0x77,
        ];
        assert_eq!(
            leg_key_bytes(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST
            )
            .unwrap(),
            KEY
        );
        // Control: the pin is over a value that moves with its inputs and with
        // the root, not a constant the derivation happens to return.
        assert_ne!(
            leg_key_bytes(
                &other_root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST
            )
            .unwrap(),
            KEY
        );
        assert_ne!(
            leg_key_bytes(
                &root(),
                FRAME_KIND_RE_ACK,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST
            )
            .unwrap(),
            KEY
        );
    }

    // ---------------------------------------------------------------------
    // The signature layer. Each of the four values is bound a second time in
    // the preimage; these craft a leg whose key says one thing and whose
    // signature says another, which the key layer cannot produce.
    // ---------------------------------------------------------------------

    /// Seal a leg whose AEAD key names one tuple and whose signature names
    /// another. No public sealer can produce this — that is the point.
    #[allow(clippy::too_many_arguments)]
    fn seal_with_mismatched_signature(
        s_pc: &[u8; ml_dsa::SK_LEN],
        key_kind: &[u8],
        key_dir: Direction,
        key_gen: u32,
        key_seq: u64,
        key_attempt: Attempt,
        sig_kind: &[u8],
        sig_dir: Direction,
        sig_gen: u32,
        sig_seq: u64,
        sig_attempt: Attempt,
        payload: &[u8],
    ) -> Vec<u8> {
        let preimage = leg_sig_input(sig_kind, sig_dir, sig_gen, sig_seq, sig_attempt, payload);
        let sig = ml_dsa::sign(s_pc, &preimage, &[]).unwrap();
        let mut body = Vec::from(payload);
        body.extend_from_slice(&sig);
        seal_leg(
            &root(),
            key_kind,
            key_dir,
            key_gen,
            key_seq,
            key_attempt,
            &body,
        )
        .unwrap()
    }

    /// The signature binds the generation, not only the key.
    ///
    /// Kills dropping `generation` from `leg_sig_input` — A3.1's requirement
    /// that *"a tiebreak or a retirement is only ever decided by a frame bound
    /// to that contest"*. The control below is the same construction with the
    /// generations agreeing, which opens.
    #[test]
    fn the_signature_binds_the_generation() {
        let ours = keypair(5);
        let mismatched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_EST,
            Direction::AToB,
            8,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        );
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &mismatched,
                ours.public_key()
            ),
            Err(ReEstError::Signature)
        ));
        let matched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        );
        assert!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &matched,
                ours.public_key()
            )
            .is_ok(),
            "the control did not open, so the probe above proves nothing"
        );
    }

    /// The signature binds the attempt, not only the key.
    ///
    /// Kills dropping `attempt` from `leg_sig_input`.
    #[test]
    fn the_signature_binds_the_attempt() {
        let ours = keypair(6);
        let second = Attempt::FIRST.advance().unwrap().attempt();
        let mismatched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            second,
            &eph_ek(),
        );
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &mismatched,
                ours.public_key()
            ),
            Err(ReEstError::Signature)
        ));
    }

    /// The signature binds the frame kind, not only the key.
    ///
    /// Kills dropping `kind` from `leg_sig_input` — the *"per-leg frame-kind
    /// label"* A3.1 names explicitly.
    #[test]
    fn the_signature_binds_the_frame_kind() {
        let ours = keypair(7);
        let mismatched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_ACK,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        );
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &mismatched,
                ours.public_key()
            ),
            Err(ReEstError::Signature)
        ));
    }

    /// The signature binds the sequence position, not only the key.
    ///
    /// Kills dropping `seq` from `leg_sig_input`.
    #[test]
    fn the_signature_binds_the_seq() {
        let ours = keypair(20);
        let mismatched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ + 1,
            Attempt::FIRST,
            &eph_ek(),
        );
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &mismatched,
                ours.public_key()
            ),
            Err(ReEstError::Signature)
        ));
    }

    /// The signature binds the direction, not only the key.
    #[test]
    fn the_signature_binds_the_direction() {
        let ours = keypair(8);
        let mismatched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_EST,
            Direction::BToA,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        );
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &mismatched,
                ours.public_key()
            ),
            Err(ReEstError::Signature)
        ));
    }

    /// The signature binds the payload, so an ephemeral cannot be substituted
    /// inside an otherwise-authentic leg.
    #[test]
    fn the_signature_binds_the_payload() {
        let ours = keypair(9);
        let mismatched = seal_with_mismatched_signature(
            ours.secret_key(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &[0xAAu8; ml_kem::EK_LEN],
        );
        // Re-seal the *other* ephemeral under the same key with that signature.
        let preimage = leg_sig_input(
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &[0xAAu8; ml_kem::EK_LEN],
        );
        let sig = ml_dsa::sign(ours.secret_key(), &preimage, &[]).unwrap();
        let mut body = Vec::from(eph_ek());
        body.extend_from_slice(&sig);
        let swapped = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &body,
        )
        .unwrap();
        assert_ne!(mismatched, swapped);
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &swapped,
                ours.public_key()
            ),
            Err(ReEstError::Signature)
        ));
    }

    /// A leg signed by one pseudonym does not verify under another's.
    ///
    /// Kills verifying under a key the frame supplies rather than the one the
    /// resume record holds.
    #[test]
    fn a_leg_does_not_verify_under_another_pseudonym() {
        let ours = keypair(10);
        let stranger = keypair(11);
        let fresh = FreshAttempt::first();
        let bytes = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &bytes,
                stranger.public_key()
            ),
            Err(ReEstError::Signature)
        ));
    }

    // ---------------------------------------------------------------------
    // The trial-decryption scan (A5.2).
    // ---------------------------------------------------------------------

    /// The scan recovers the exact attempt the leg was sealed under, from bytes
    /// that name no attempt at all.
    ///
    /// **This is the probe for the conveyance decision.** Kills dropping
    /// `attempt` from `leg_info`: every candidate key would then be one key,
    /// the first candidate would open, and the recovered attempt would be
    /// `last_seen` rather than the sealed value. Kills a scan that returns the
    /// window's base regardless of which candidate opened.
    #[test]
    fn the_scan_recovers_the_sealed_attempt() {
        let ours = keypair(12);
        let mut attempt = Attempt::FIRST;
        for _ in 0..4 {
            attempt = attempt.advance().unwrap().attempt();
        }
        assert_eq!(attempt.get(), 5);
        let bytes = seal_re_ack(
            &root(),
            Direction::AToB,
            SEQ,
            ReAckAuthority::for_test(7, attempt),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        let opened = scan_re_ack(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            1,
            &bytes,
            ours.public_key(),
        )
        .unwrap();
        assert_eq!(opened.attempt(), attempt);
    }

    /// The window's far edge is `last_seen + MAX_GAP`, inclusive, and one past
    /// it is refused.
    ///
    /// Kills widening or narrowing the window by one, and kills a scan whose
    /// width is not [`MAX_GAP`].
    #[test]
    fn the_scan_window_ends_at_max_gap() {
        let ours = keypair(13);
        let last_seen = 3u32;
        let edge = Attempt::from_nonzero(NonZeroU32::new(last_seen + MAX_GAP).unwrap());
        let beyond = Attempt::from_nonzero(NonZeroU32::new(last_seen + MAX_GAP + 1).unwrap());
        let at_edge = seal_re_ack(
            &root(),
            Direction::AToB,
            SEQ,
            ReAckAuthority::for_test(7, edge),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(
            scan_re_ack(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                last_seen,
                &at_edge,
                ours.public_key()
            )
            .unwrap()
            .attempt(),
            edge
        );
        let past_edge = seal_re_ack(
            &root(),
            Direction::AToB,
            SEQ,
            ReAckAuthority::for_test(7, beyond),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        assert!(matches!(
            scan_re_ack(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                last_seen,
                &past_edge,
                ours.public_key()
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// The window's near edge is `last_seen` itself, inclusive, so a
    /// byte-identical re-emit of the accepted attempt still opens and can be
    /// deduped (A9.1(a)). An attempt below it does not.
    #[test]
    fn the_scan_window_includes_last_seen_and_nothing_below_it() {
        let ours = keypair(14);
        let last_seen = 4u32;
        let at_base = Attempt::from_nonzero(NonZeroU32::new(last_seen).unwrap());
        let below = Attempt::from_nonzero(NonZeroU32::new(last_seen - 1).unwrap());
        let base_leg = seal_re_ack(
            &root(),
            Direction::AToB,
            SEQ,
            ReAckAuthority::for_test(7, at_base),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(
            scan_re_ack(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                last_seen,
                &base_leg,
                ours.public_key()
            )
            .unwrap()
            .attempt(),
            at_base
        );
        let below_leg = seal_re_ack(
            &root(),
            Direction::AToB,
            SEQ,
            ReAckAuthority::for_test(7, below),
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        assert!(matches!(
            scan_re_ack(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                last_seen,
                &below_leg,
                ours.public_key()
            ),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// A `last_seen` of zero — the empty-slot spelling — starts the window at
    /// [`Attempt::FIRST`] rather than at zero.
    ///
    /// Attempt `0` is not skipped by a branch; it is unrepresentable, because
    /// the window's base is a `NonZeroU32`. What this pins is the base: a window
    /// that started literally at `last_seen` would spend a trial on a value no
    /// seal can ever have used, and would shift every candidate by one.
    #[test]
    fn the_scan_never_tries_attempt_zero() {
        let ours = keypair(15);
        let fresh = FreshAttempt::first();
        let bytes = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        assert_eq!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &bytes,
                ours.public_key()
            )
            .unwrap()
            .attempt(),
            Attempt::FIRST
        );
    }

    /// Bytes that are not a leg's length are refused before any key is derived.
    #[test]
    fn a_short_leg_is_refused() {
        let ours = keypair(16);
        let fresh = FreshAttempt::first();
        let bytes = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &bytes[..LEG_LEN - 1],
                ours.public_key()
            ),
            Err(ReEstError::Truncated)
        ));
    }

    /// A leg whose seal opens but whose payload is the wrong length is refused.
    ///
    /// Sealed through the private `seal_leg` because no public sealer can
    /// produce this spelling — which is the point of the check: it catches a
    /// peer running a different build.
    #[test]
    fn a_payload_of_the_wrong_length_is_refused() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &[0u8; 8],
        )
        .unwrap();
        let ours = keypair(17);
        assert!(matches!(
            scan_re_est(
                &root(),
                Direction::AToB,
                7,
                SEQ,
                0,
                &bytes,
                ours.public_key()
            ),
            Err(ReEstError::PayloadLen { .. })
        ));
    }

    /// A payload LONGER than the leg carries is refused, not split past its
    /// signature.
    ///
    /// The short side alone is not enough: `open_signed_leg`'s length check is
    /// the only thing standing between an over-length body and the
    /// `sig.try_into().expect(..)` below it, so relaxing `!=` to `<` turns a
    /// peer running a different build into a panic rather than an error. Sealed
    /// through the private `seal_leg`, because no public sealer can spell it.
    #[test]
    fn an_over_length_payload_is_refused() {
        ready();
        let ours = keypair(21);
        let mut body = Vec::from(eph_ek());
        body.push(0);
        let preimage = leg_sig_input(
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &body,
        );
        let sig = ml_dsa::sign(ours.secret_key(), &preimage, &[]).unwrap();
        body.extend_from_slice(&sig);
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &body,
        )
        .unwrap();
        assert!(matches!(
            scan_re_est(&root(), Direction::AToB, 7, SEQ, 0, &bytes, ours.public_key()),
            Err(ReEstError::PayloadLen {
                expected,
                got
            }) if expected == ml_kem::EK_LEN + ml_dsa::SIG_LEN && got == expected + 1
        ));
    }

    /// `open_leg` refuses a wrong-length buffer on its OWN guard, at both edges.
    ///
    /// The scan has an identical guard, so through the public API the two mask
    /// each other and removing either alone changes nothing. Driving `open_leg`
    /// directly is what separates them. Asserting `Truncated` rather than any
    /// error is load-bearing: without the guard `open_envelope` reports a
    /// wrong-length buffer as an authentication failure, which passes an
    /// `is_err()` check and reads as the right verdict for the wrong reason.
    #[test]
    fn open_leg_refuses_a_wrong_length_buffer_on_its_own_guard() {
        ready();
        let bytes = seal_leg(
            &root(),
            FRAME_KIND_RE_EST,
            Direction::AToB,
            7,
            SEQ,
            Attempt::FIRST,
            &eph_ek(),
        )
        .unwrap();
        let mut over = bytes.clone();
        over.push(0);
        for buf in [&bytes[..LEG_LEN - 1], over.as_slice()] {
            assert!(
                matches!(
                    open_leg(
                        &root(),
                        FRAME_KIND_RE_EST,
                        Direction::AToB,
                        7,
                        SEQ,
                        Attempt::FIRST,
                        buf
                    ),
                    Err(ReEstError::Truncated)
                ),
                "a {}-byte buffer was not refused as truncated",
                buf.len()
            );
        }
        // Control: the exact length still opens.
        assert!(
            open_leg(
                &root(),
                FRAME_KIND_RE_EST,
                Direction::AToB,
                7,
                SEQ,
                Attempt::FIRST,
                &bytes
            )
            .is_ok()
        );
    }

    /// The scan refuses a wrong-length buffer on its own guard, at both edges,
    /// before spending a single key derivation on it.
    #[test]
    fn the_scan_refuses_a_wrong_length_buffer_at_both_edges() {
        let ours = keypair(22);
        let bytes = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &FreshAttempt::first(),
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        let mut over = bytes.clone();
        over.push(0);
        for buf in [&bytes[..LEG_LEN - 1], over.as_slice()] {
            assert!(matches!(
                scan_re_est(&root(), Direction::AToB, 7, SEQ, 0, buf, ours.public_key()),
                Err(ReEstError::Truncated)
            ));
        }
    }

    /// One opened `RE-EST` yields exactly one `RE-ACK` authority, carrying the
    /// generation and attempt of the leg it answers.
    ///
    /// The compile-time half of A9.1 cannot be asserted from inside the crate:
    /// a `seal_re_ack` call taking a bare `Attempt` does not compile, and a test
    /// cannot assert that. What is testable is the mint path: [`OpenedReEst::answer`] consumes
    /// the opened leg (it is neither `Clone` nor `Copy`), and the authority it
    /// yields cannot name a different exchange.
    #[test]
    fn an_opened_re_est_yields_one_authority_for_its_own_exchange() {
        let ours = keypair(23);
        let mut attempt = Attempt::FIRST;
        let mut fresh = FreshAttempt::first();
        for _ in 0..2 {
            fresh = attempt.advance().unwrap();
            attempt = fresh.attempt();
        }
        let est = seal_re_est(
            &root(),
            Direction::AToB,
            11,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        let authority = scan_re_est(
            &root(),
            Direction::AToB,
            11,
            SEQ,
            0,
            &est,
            ours.public_key(),
        )
        .unwrap()
        .answer();
        assert_eq!(authority.generation(), 11);
        assert_eq!(authority.attempt(), attempt);
        let ack = seal_re_ack(
            &root(),
            Direction::BToA,
            SEQ + 1,
            authority,
            &eph_ct(),
            ours.secret_key(),
        )
        .unwrap();
        let opened = scan_re_ack(
            &root(),
            Direction::BToA,
            11,
            SEQ + 1,
            0,
            &ack,
            ours.public_key(),
        )
        .unwrap();
        assert_eq!(opened.attempt(), attempt);
    }

    // ---------------------------------------------------------------------
    // The tiebreak coin (A3.7).
    // ---------------------------------------------------------------------

    /// **The coin's known-answer vector.** Pins the expanded byte AND the bit
    /// the winner is read from, for a fixed root over sixteen generations.
    ///
    /// Agreement and variation tests are satisfied by *any* unbiased bit, so
    /// two implementations reading different bits both pass and then disagree
    /// on the wire — with no local symptom on either side. This repo ships LAMA
    /// manifests for cross-implementation readers, so that failure is reachable.
    /// Kills changing which bit is selected (`& 1` to `& 2`, `>> 7`, the first
    /// byte to another), and kills any change to the salt, the label, the
    /// generation encoding or the length prefix in `tiebreak_bytes`.
    ///
    /// Regenerating these numbers is a wire change and needs the same
    /// deliberation as changing a frozen domain label.
    #[test]
    fn the_coin_is_a_known_answer_vector() {
        ready();
        // (generation, first expanded byte, winner is a2b)
        const KAT: [(u32, u8, bool); 16] = [
            (0, 0xC0, true),
            (1, 0x55, false),
            (2, 0x5F, false),
            (3, 0xE8, true),
            (4, 0x65, false),
            (5, 0xDC, true),
            (6, 0xD4, true),
            (7, 0x75, false),
            (8, 0x21, false),
            (9, 0xFD, false),
            (10, 0x9B, false),
            (11, 0x7A, true),
            (12, 0x74, true),
            (13, 0x1F, false),
            (14, 0x05, false),
            (15, 0xAB, false),
        ];
        let root = CommittedRoot::from_bytes(&[3u8; 32]);
        for (generation, byte, a_to_b) in KAT {
            assert_eq!(
                tiebreak_bytes(&root, generation).unwrap(),
                [byte],
                "the coin expansion changed at generation {generation}"
            );
            let expected = if a_to_b {
                Direction::AToB
            } else {
                Direction::BToA
            };
            assert_eq!(
                tiebreak_winner(&root, generation).unwrap(),
                expected,
                "the bit selection changed at generation {generation}"
            );
            // The vector is only a vector if the two halves are independently
            // stated: assert the documented rule ties them together.
            assert_eq!(byte & 1 == 0, a_to_b, "the vector contradicts itself");
        }
        // Control: the vector must exercise both outcomes, or a constant-return
        // coin would pass it.
        assert!(KAT.iter().any(|(_, _, a)| *a));
        assert!(KAT.iter().any(|(_, _, a)| !*a));
    }

    /// Both parties compute one coin, so a contest resolves to exactly one
    /// survivor however the two observations are ordered.
    ///
    /// Kills mixing the caller's own direction into the selector — the two sides
    /// would then disagree and both abandon, or both wait.
    #[test]
    fn the_coin_names_one_survivor_on_both_sides() {
        ready();
        for generation in 0..64u32 {
            let a =
                contest_outcome(&root(), generation, Direction::AToB, Some(generation)).unwrap();
            let b =
                contest_outcome(&root(), generation, Direction::BToA, Some(generation)).unwrap();
            assert_ne!(a, b, "both sides reached {a:?} at generation {generation}");
            assert!(matches!(
                (a, b),
                (ContestOutcome::WeSurvive, ContestOutcome::WeAbandon)
                    | (ContestOutcome::WeAbandon, ContestOutcome::WeSurvive)
            ));
        }
    }

    /// The coin moves with the generation rather than standing still.
    ///
    /// Kills dropping the generation from the tiebreak `info`, after which one
    /// direction would win every contest of a correspondence for ever.
    #[test]
    fn the_coin_moves_with_the_generation() {
        ready();
        let mut a_to_b = 0u32;
        for generation in 0..64u32 {
            if tiebreak_winner(&root(), generation).unwrap() == Direction::AToB {
                a_to_b += 1;
            }
        }
        assert!(
            a_to_b > 0 && a_to_b < 64,
            "the coin returned one direction for all 64 generations ({a_to_b} were a2b)"
        );
    }

    /// Without a pending initiation at the same generation there is no contest,
    /// whatever the coin says.
    #[test]
    fn no_contest_without_a_pending_initiation_at_that_generation() {
        ready();
        for pending in [None, Some(6u32), Some(8u32)] {
            assert_eq!(
                contest_outcome(&root(), 7, Direction::AToB, pending).unwrap(),
                ContestOutcome::NoContest
            );
        }
    }

    // ---------------------------------------------------------------------
    // The admission gate (A9.4(ii)) and the toward-`C` budget.
    // ---------------------------------------------------------------------

    /// A replayed attempt is deduped and the response budget is never consulted.
    ///
    /// Kills moving the `budget()` call above the dedup arms in
    /// [`ReEstGate::admit`]: the charge count would then climb with the replays.
    #[test]
    fn dedup_is_evaluated_before_the_budget_is_charged() {
        let mut gate = ReEstGate::new();
        let mut charges = 0u32;
        assert_eq!(
            gate.admit(7, Attempt::FIRST, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Emit
        );
        for _ in 0..16 {
            assert_eq!(
                gate.admit(7, Attempt::FIRST, || {
                    charges += 1;
                    true
                }),
                ReEstAdmission::ReServe
            );
        }
        assert_eq!(charges, 1, "a replay charged the response budget");
    }

    /// A differing frame at an already-accepted generation is dropped with no
    /// state change and no charge, per A3.4.
    #[test]
    fn an_older_attempt_at_an_accepted_generation_is_dropped() {
        let mut gate = ReEstGate::new();
        let second = Attempt::FIRST.advance().unwrap().attempt();
        let mut charges = 0u32;
        gate.admit(7, second, || {
            charges += 1;
            true
        });
        assert_eq!(
            gate.admit(7, Attempt::FIRST, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Dropped
        );
        assert_eq!(gate.accepted(), Some((7, second)));
        assert_eq!(charges, 1);
    }

    /// A HIGHER attempt at an already-accepted generation is admitted and
    /// replaces the slot — A5.1's supersede, and the case A3.4 read alone would
    /// wrongly drop.
    ///
    /// Kills narrowing the ordering arm to drop everything at an accepted
    /// generation, which would strand a returning initiator's re-initiation for
    /// the whole retention window.
    #[test]
    fn a_higher_attempt_at_an_accepted_generation_supersedes() {
        let mut gate = ReEstGate::new();
        let second = Attempt::FIRST.advance().unwrap().attempt();
        let mut charges = 0u32;
        assert_eq!(
            gate.admit(7, Attempt::FIRST, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Emit
        );
        assert_eq!(
            gate.admit(7, second, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Emit
        );
        assert_eq!(gate.accepted(), Some((7, second)));
        assert_eq!(charges, 2, "the supersede was not charged");
    }

    /// A LOWER generation is dropped whatever its attempt, and a HIGHER
    /// generation is a fresh acceptance.
    ///
    /// This is the only gate test that varies the generation, so it is the
    /// only one a comparison on the attempt alone would fail.
    #[test]
    fn the_gate_orders_on_the_generation_before_the_attempt() {
        let mut gate = ReEstGate::new();
        let high = Attempt::FIRST.advance().unwrap().attempt();
        let mut charges = 0u32;
        gate.admit(7, high, || {
            charges += 1;
            true
        });
        // A lower generation is dropped even carrying an attempt that would
        // supersede at generation 7 — which is what an attempt-only comparison
        // would get wrong.
        assert_eq!(
            gate.admit(6, high, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Dropped
        );
        assert_eq!(
            gate.admit(6, Attempt::FIRST, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Dropped
        );
        assert_eq!(gate.accepted(), Some((7, high)));
        // A higher generation is admitted even carrying the lowest attempt.
        assert_eq!(
            gate.admit(8, Attempt::FIRST, || {
                charges += 1;
                true
            }),
            ReEstAdmission::Emit
        );
        assert_eq!(gate.accepted(), Some((8, Attempt::FIRST)));
        assert_eq!(charges, 2, "a dropped frame charged the budget");
    }

    /// A refused budget accepts nothing, so the same attempt may be admitted
    /// when the budget next allows it.
    #[test]
    fn a_withheld_attempt_is_not_accepted() {
        let mut gate = ReEstGate::new();
        assert_eq!(
            gate.admit(7, Attempt::FIRST, || false),
            ReEstAdmission::Withheld
        );
        assert_eq!(gate.accepted(), None);
        assert_eq!(gate.admit(7, Attempt::FIRST, || true), ReEstAdmission::Emit);
    }

    /// The ceiling's VALUE is pinned, not only its relation to the loop that
    /// spends it.
    ///
    /// A loop written `0..ATTEMPT_CEILING` moves with the constant and can never
    /// notice it changing, so raising the ceiling passes silently. This asserts
    /// the number, and asserts A8.1's `MAX_GAP = C` identity beside it. Both are
    /// placeholders per A9 — changing either is a deliberate act that edits this
    /// test, which is exactly the point.
    #[test]
    fn the_attempt_ceiling_and_scan_width_are_the_documented_placeholders() {
        assert_eq!(ATTEMPT_CEILING, 8, "the placeholder for C moved");
        assert_eq!(
            MAX_GAP, ATTEMPT_CEILING,
            "A8.1's MAX_GAP = C identity broke"
        );
        // Spelled as a literal so a redefinition of the constant cannot make the
        // boundary assertions below move with it.
        let mut budget = AttemptBudget::empty();
        for _ in 0..8 {
            budget = budget.charge().expect("below the ceiling");
        }
        assert_eq!(budget.count(), 8);
        assert!(budget.exhausted());
        assert!(budget.charge().is_none());
    }

    /// The toward-`C` count spends up to the ceiling and then gives up, on a
    /// `>=` boundary.
    ///
    /// Kills an off-by-one in [`AttemptBudget::charge`] — a `>` ceiling test
    /// admits one attempt past `C`.
    #[test]
    fn the_attempt_budget_stops_at_the_ceiling() {
        let mut budget = AttemptBudget::empty();
        for spent in 0..ATTEMPT_CEILING {
            assert_eq!(budget.count(), spent);
            assert!(!budget.exhausted());
            budget = budget.charge().expect("below the ceiling");
        }
        assert_eq!(budget.count(), ATTEMPT_CEILING);
        assert!(budget.exhausted());
        assert!(budget.charge().is_none());
    }

    // ---------------------------------------------------------------------
    // A5.1(ii)'s confirmation lock, and A7.3's window anchor.
    // ---------------------------------------------------------------------

    /// A record whose acceptance slot holds `(generation, attempt)`, confirmed
    /// or not, and whose own slot names `own_attempt` against `anchor`.
    fn record_for_gate(
        generation: u32,
        attempt: u32,
        confirmed: bool,
        anchor: u32,
        own_attempt: u32,
    ) -> ResumeRecord {
        use crate::dm::resume::{AcceptanceSlot, OwnSlot, ReEstState, Retention, SendFloor};
        let slot = AcceptanceSlot::accept(
            generation,
            Attempt::from_nonzero(NonZeroU32::new(attempt).expect("a real attempt")),
            vec![0xC3; 64].into_boxed_slice(),
        )
        .expect("inside MAX_SEALED_LEG_LEN");
        let slot = if confirmed { slot.confirm() } else { slot };
        let own = (own_attempt > 0).then(|| {
            let mut fresh = FreshAttempt::first();
            while fresh.attempt().get() < own_attempt {
                fresh = fresh.attempt().advance().expect("far below u32::MAX");
            }
            OwnSlot::new(generation, 77, seal_stub(fresh), eph_dk_fixture())
        });
        ResumeRecord::new(
            Box::new([0x11; ml_dsa::SK_LEN]),
            Box::new([0x22; ml_dsa::PK_LEN]),
            root(),
            ReEstState {
                // A3.4 advances `reconnect_gen` only by a COMPLETED handshake,
                // so a pending acceptance at `generation` sits one above the
                // committed number rather than at it.
                reconnect_gen: generation.saturating_sub(1),
                attempt: own_attempt,
                last_seen_re_est: 0,
                own,
                acceptance: Some(slot),
                attempt_at_window_start: anchor,
                reroot_ratchet_gen: 0,
            },
            Retention::none(),
            SendFloor::new(0, 0),
        )
    }

    /// A sealed frame's worth of bytes bound to `fresh`. The gate and the budget
    /// read numbers off the record, never the frame, so the bytes only have to
    /// be a legal length.
    fn seal_stub(fresh: FreshAttempt) -> crate::dm::resume::SealedReEst {
        crate::dm::resume::SealedReEst::seal(fresh, vec![0xA5; 64].into_boxed_slice())
            .expect("inside MAX_FRAME_LEN")
    }

    /// **The confirmation lock comes back off the record, and it refuses a
    /// differing attempt without consulting the budget.**
    ///
    /// A5.1(ii): a confirmed candidate *"is locked, and a later-arriving
    /// lower-or-stale attempt's `RE-EST` never supersedes it"*. A9.4(ii) puts
    /// dedup ahead of the budget, and this applies the same ordering to the
    /// lock: a peer looping on a settled exchange must not drain the response
    /// budget.
    ///
    /// Kills a `from_record` that ignores `AcceptanceSlot::confirmed` — the
    /// higher attempt would then supersede — and a lock checked *after* the
    /// budget closure, which the panicking closure catches.
    #[test]
    fn a_confirmed_generation_refuses_a_differing_attempt_before_the_budget() {
        let record = record_for_gate(7, 5, true, 0, 0);
        let mut gate = ReEstGate::from_record(&record);
        assert_eq!(gate.accepted().map(|(g, a)| (g, a.get())), Some((7, 5)));
        assert!(gate.is_confirmed(), "the lock did not survive the record");

        let higher = Attempt::from_nonzero(NonZeroU32::new(6).expect("non-zero"));
        let lower = Attempt::from_nonzero(NonZeroU32::new(4).expect("non-zero"));
        for attempt in [higher, lower] {
            assert_eq!(
                gate.admit(7, attempt, || panic!("the budget was consulted")),
                ReEstAdmission::Locked
            );
        }
        assert_eq!(
            gate.accepted().map(|(g, a)| (g, a.get())),
            Some((7, 5)),
            "a locked generation may not move"
        );

        // The lock is scoped to its generation: A3.4's monotone generations
        // still advance, and the accepted attempt is re-served as ever.
        assert_eq!(
            gate.admit(
                7,
                Attempt::from_nonzero(NonZeroU32::new(5).expect("non-zero")),
                || { panic!("a re-serve charges nothing") }
            ),
            ReEstAdmission::ReServe
        );
        assert_eq!(gate.admit(8, Attempt::FIRST, || true), ReEstAdmission::Emit);
        assert!(!gate.is_confirmed(), "a new candidate inherits no lock");
    }

    /// **An UNconfirmed candidate is superseded by a higher attempt, and a lower
    /// one is still dropped.**
    ///
    /// A5.1(i): *"an unconfirmed `RS_{n+1}` may be superseded by a newer
    /// attempt's"*, which is the returning initiator's re-initiation. A3.4 drops
    /// the differing frame that is not that.
    ///
    /// The control for the test above: without it, a `from_record` that reported
    /// *everything* confirmed would pass there and be caught only here.
    ///
    /// Kills an `admit` that refuses every differing attempt at the accepted
    /// generation regardless of the flag.
    #[test]
    fn an_unconfirmed_candidate_is_superseded_by_a_higher_attempt() {
        let record = record_for_gate(7, 5, false, 0, 0);
        let mut gate = ReEstGate::from_record(&record);
        assert!(!gate.is_confirmed());

        let lower = Attempt::from_nonzero(NonZeroU32::new(4).expect("non-zero"));
        assert_eq!(
            gate.admit(7, lower, || panic!("a dropped frame charges nothing")),
            ReEstAdmission::Dropped
        );
        let higher = Attempt::from_nonzero(NonZeroU32::new(6).expect("non-zero"));
        assert_eq!(gate.admit(7, higher, || true), ReEstAdmission::Emit);
        assert_eq!(gate.accepted().map(|(g, a)| (g, a.get())), Some((7, 6)));
    }

    /// **A gate built from a record with no acceptance has accepted nothing.**
    ///
    /// The type has no `Default` precisely so that this state is named rather
    /// than assumed, and this is the one input that legitimately produces it.
    #[test]
    fn a_gate_built_from_an_unaccepted_record_is_empty() {
        use crate::dm::resume::{ReEstState, Retention, SendFloor};
        let record = ResumeRecord::new(
            Box::new([0x11; ml_dsa::SK_LEN]),
            Box::new([0x22; ml_dsa::PK_LEN]),
            root(),
            ReEstState::first_establishment(),
            Retention::none(),
            SendFloor::new(0, 0),
        );
        let gate = ReEstGate::from_record(&record);
        assert_eq!(gate.accepted(), None);
        assert!(!gate.is_confirmed());
    }

    /// **A gate reloaded after a completed handshake still refuses the
    /// generations that handshake closed.**
    ///
    /// A3.14 zeroes the acceptance slot on completion, so a gate seeded from the
    /// slot alone comes back having accepted nothing and admits any generation
    /// at all — including ones already committed. A3.4 requires the opposite:
    /// *"a differing frame at an already-accepted generation is dropped without
    /// any state change"*, and a committed generation is the strongest case of
    /// one. The committed number survives the zeroing, so it is the floor.
    ///
    /// Kills `from_record` reading only the acceptance slot: with an empty slot
    /// the gate would admit generations 2 and 3 and charge the budget for them.
    #[test]
    fn a_gate_reloaded_after_a_completion_drops_the_generations_it_closed() {
        use crate::dm::resume::{ReEstState, Retention, SendFloor};
        let record = ResumeRecord::new(
            Box::new([0x11; ml_dsa::SK_LEN]),
            Box::new([0x22; ml_dsa::PK_LEN]),
            root(),
            ReEstState {
                reconnect_gen: 3,
                attempt: 4,
                last_seen_re_est: 0,
                own: None,
                acceptance: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            Retention::none(),
            SendFloor::new(0, 0),
        );
        let mut gate = ReEstGate::from_record(&record);
        assert!(gate.accepted().is_none(), "the slot is empty");
        assert_eq!(gate.floor(), 3);
        for generation in [2, 3] {
            assert_eq!(
                gate.admit(generation, Attempt::FIRST, || panic!(
                    "a closed generation charges nothing"
                )),
                ReEstAdmission::Dropped
            );
        }
        // The control: the next generation is genuinely open, so the floor is
        // not simply refusing everything.
        assert_eq!(gate.admit(4, Attempt::FIRST, || true), ReEstAdmission::Emit);
        assert_eq!(gate.accepted().map(|(g, a)| (g, a.get())), Some((4, 1)));
    }

    /// **A replay of the accepted pair is still re-served even when the floor
    /// would otherwise drop it.**
    ///
    /// A3.4 answers a byte-identical replay idempotently *"the stored `RE-ACK`
    /// is re-served"*, and that must not depend on where the floor happens to
    /// sit — a re-serve costs nothing and losing it would leave a peer
    /// re-attempting an exchange this side has already answered.
    ///
    /// Kills the floor check being placed ahead of the re-serve arm: with the
    /// floor at the accepted generation, the replay would read as Dropped.
    #[test]
    fn the_floor_does_not_swallow_a_re_serve() {
        use crate::dm::resume::{AcceptanceSlot, ReEstState, Retention, SendFloor};
        let slot = AcceptanceSlot::accept(5, Attempt::FIRST, vec![0xC3; 64].into_boxed_slice())
            .expect("inside MAX_SEALED_LEG_LEN");
        let record = ResumeRecord::new(
            Box::new([0x11; ml_dsa::SK_LEN]),
            Box::new([0x22; ml_dsa::PK_LEN]),
            root(),
            ReEstState {
                reconnect_gen: 5,
                attempt: 0,
                last_seen_re_est: 0,
                own: None,
                acceptance: Some(slot),
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            Retention::none(),
            SendFloor::new(0, 0),
        );
        let mut gate = ReEstGate::from_record(&record);
        assert_eq!(gate.floor(), 5, "the floor sits at the accepted generation");
        assert_eq!(
            gate.admit(5, Attempt::FIRST, || panic!("a re-serve charges nothing")),
            ReEstAdmission::ReServe
        );
        // A DIFFERING attempt at that generation is still dropped by the floor.
        let two = Attempt::from_nonzero(NonZeroU32::new(2).expect("non-zero"));
        assert_eq!(
            gate.admit(5, two, || panic!("a closed generation charges nothing")),
            ReEstAdmission::Dropped
        );
    }

    /// **The toward-`C` count is a subtraction, not a stored number.**
    ///
    /// A7.3 derives *"attempts this window"* as
    /// `attempt − attempt_at_window_start`. A separately stored count could
    /// disagree with the monotone counter it describes; a subtraction cannot.
    ///
    /// Kills a `from_record` that reads the anchor and reports it as the count,
    /// and one that reports the raw attempt: the fixture's anchor and attempt
    /// are distinct and neither equals their difference.
    #[test]
    fn the_toward_c_count_is_the_attempt_less_the_anchor() {
        let record = record_for_gate(7, 1, false, 4, 6);
        let budget = AttemptBudget::from_record(&record);
        assert_eq!(budget.anchor(), 4);
        assert_eq!(budget.attempt(), 6);
        assert_eq!(budget.count(), 2, "6 − 4, and not 4, 6 or 0");
        assert!(!budget.exhausted());
    }

    /// **A crash between commit and emit mints no new attempt.**
    ///
    /// A8.1: *"commit-then-emit persists both the re-establishment generation's
    /// root and the `attempt` counter before any emission, and recovery re-emits
    /// the committed values, advancing neither"*. The record is the only source
    /// of both numbers, so reloading it after a crash reproduces the budget
    /// exactly — there is no in-memory counter that could have moved.
    ///
    /// Kills a `from_record` that adds one to the stored attempt, or that resets
    /// the anchor at load: either would make the reloaded budget differ from the
    /// one that was persisted.
    #[test]
    fn a_reload_reproduces_the_budget_without_advancing_it() {
        let record = record_for_gate(7, 1, false, 4, 6);
        let before = AttemptBudget::from_record(&record);
        // The crash: nothing was emitted, and the record is read again.
        let reloaded =
            ResumeRecord::decode(&record.encode()).expect("a fresh encoding must decode");
        let after = AttemptBudget::from_record(&reloaded);
        assert_eq!(after, before, "the reload moved the budget");
        assert_eq!(after.attempt(), 6);
        assert_eq!(after.count(), 2);
        // The re-emit sends the persisted bytes, so the attempt they are bound
        // to is unchanged too.
        assert_eq!(reloaded.attempt().map(Attempt::get), Some(6));
        assert_eq!(reloaded.sealed_re_est(), record.sealed_re_est());
    }

    /// **The window anchor resets only on an observed `RE-ACK`, and only for one
    /// of this window's attempts.**
    ///
    /// A8.2 makes the rollover *"an idempotent derivation from durable
    /// `last_seen`"*, and `last_seen` advances on an opened `RE-ACK` — the
    /// attempt comes from [`OpenedReAck::attempt`]. An ordinary frame carries no
    /// attempt at all (a leg has no clear fields), so there is nothing an
    /// ordinary frame could offer here; what this pins is that an observation
    /// *outside* the window is inert, which is the stale-frame case.
    ///
    /// Kills an `observe_peer_opened` with the window check removed: the stale
    /// observation at 2 and the never-sealed one at 9 would each move the anchor
    /// and hand the sender a fresh window's worth of attempts.
    #[test]
    fn the_anchor_resets_only_on_an_observation_inside_the_window() {
        let attempt = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let budget = AttemptBudget::from_record(&record_for_gate(7, 1, false, 4, 6));
        assert_eq!((budget.anchor(), budget.attempt()), (4, 6));

        // At or below the anchor: a window this side has already left.
        assert_eq!(budget.observe_peer_opened(attempt(4)).anchor(), 4);
        assert_eq!(budget.observe_peer_opened(attempt(2)).anchor(), 4);
        // Above the counter: an attempt this side never sealed.
        assert_eq!(budget.observe_peer_opened(attempt(9)).anchor(), 4);
        // Inside the window: the peer opened one of ours.
        let rolled = budget.observe_peer_opened(attempt(5));
        assert_eq!(rolled.anchor(), 5);
        assert_eq!(rolled.attempt(), 6, "the monotone counter does not move");
        assert_eq!(rolled.count(), 1, "the window rolled over");
    }

    /// **A sender at `anchor + C` is refused.**
    ///
    /// A6.3 caps attempts per window at `C`, and A9 makes the give-up loud
    /// rather than a silent stall.
    ///
    /// Kills a `charge` that compares the raw attempt against the ceiling
    /// instead of the count: the anchor here is far above zero, so the raw
    /// attempt passes `< C` at no point while the count is legal at every one.
    #[test]
    fn a_sender_at_the_anchor_plus_c_is_refused() {
        let mut budget = AttemptBudget {
            anchor: 100,
            attempt: 100,
        };
        for spent in 0..ATTEMPT_CEILING {
            assert_eq!(budget.count(), spent);
            assert!(!budget.exhausted());
            budget = budget.charge().expect("below the ceiling");
        }
        assert_eq!(budget.attempt(), 100 + ATTEMPT_CEILING);
        assert_eq!(budget.count(), ATTEMPT_CEILING);
        assert!(budget.exhausted());
        assert!(budget.charge().is_none(), "the ceiling did not hold");
    }

    /// **The anchor keeps a two-window sender inside the receiver's scan
    /// window.**
    ///
    /// `attempt` is monotone for the channel's whole life while `C` bounds the
    /// attempts in one window, so a sender that reaches `2C` while the
    /// receiver's `last_seen` is still 0 would fall outside
    /// `[last_seen, last_seen + MAX_GAP]` and every leg it sealed would be
    /// unopenable until `RS_n` retired. The two halves that rule this out are
    /// coupled. [`AttemptBudget::charge`] stops the sender at `anchor + C`, and
    /// [`AttemptBudget::observe_peer_opened`] is the only thing that moves the
    /// anchor — so reaching `2C` at all requires the peer to have opened an
    /// attempt, and that same observation is what advanced the receiver's
    /// `last_seen`. The sender therefore arrives inside the window it is scanned
    /// against, and `MAX_GAP = C` is sufficient (A7.3).
    ///
    /// Kills the removal of either half: without the ceiling the sender walks
    /// past `2C` and the final scan fails, and without the anchor reset the
    /// sender cannot reach `2C` at all and the loop's `expect` fails.
    #[test]
    fn the_anchor_keeps_a_multi_window_sender_inside_the_receivers_window() {
        let ours = keypair(24);

        // Window one: C attempts, and the ceiling stops there.
        let mut budget = AttemptBudget::empty();
        let mut fresh = FreshAttempt::first();
        let mut attempt = fresh.attempt();
        for _ in 0..ATTEMPT_CEILING {
            budget = budget.charge().expect("inside the first window");
            fresh = FreshAttempt::first();
            while fresh.attempt().get() < budget.attempt() {
                fresh = fresh.attempt().advance().expect("far below u32::MAX");
            }
            attempt = fresh.attempt();
        }
        assert_eq!(attempt.get(), ATTEMPT_CEILING);
        assert!(budget.exhausted(), "the first window did not close");
        assert!(budget.charge().is_none());

        // The peer answers attempt C. That is the observation that rolls the
        // window, and it is the same event that advances the receiver's
        // `last_seen` to C.
        budget = budget.observe_peer_opened(attempt);
        assert_eq!(budget.anchor(), ATTEMPT_CEILING);
        assert_eq!(budget.count(), 0, "a fresh window");
        let last_seen = ATTEMPT_CEILING;

        // Window two: C more attempts, reaching 2C.
        for _ in 0..ATTEMPT_CEILING {
            budget = budget.charge().expect("inside the second window");
            fresh = FreshAttempt::first();
            while fresh.attempt().get() < budget.attempt() {
                fresh = fresh.attempt().advance().expect("far below u32::MAX");
            }
        }
        assert_eq!(budget.attempt(), 2 * ATTEMPT_CEILING);
        assert!(budget.exhausted());

        // The leg sealed at 2C opens against a receiver whose `last_seen` is C.
        let leg = seal_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            &fresh,
            &eph_ek(),
            ours.secret_key(),
        )
        .unwrap();
        let opened = scan_re_est(
            &root(),
            Direction::AToB,
            7,
            SEQ,
            last_seen,
            &leg,
            ours.public_key(),
        )
        .expect("the sender is inside [last_seen, last_seen + MAX_GAP]");
        assert_eq!(opened.attempt().get(), 2 * ATTEMPT_CEILING);

        // The control that makes the pass mean something: a receiver whose
        // `last_seen` never moved is exactly the lockout, and it still refuses.
        assert!(matches!(
            scan_re_est(&root(), Direction::AToB, 7, SEQ, 0, &leg, ours.public_key()),
            Err(ReEstError::DidNotOpen)
        ));
    }

    /// **The dedup key's leg tags name the three frame kinds, one each.**
    ///
    /// [`crate::dm::resume::Leg`] lives in the record's module because the key is
    /// durable state there, so the two spellings of "which leg" sit in different
    /// files and could drift. This is the mapping written down where both are
    /// visible.
    ///
    /// Kills a `Leg` variant repurposed to a different kind: the constants are
    /// distinct byte strings and the variants are distinct values, and the
    /// pairing below is the only thing asserting which goes with which.
    #[test]
    fn the_dedup_legs_name_the_three_frame_kinds() {
        use crate::dm::resume::Leg;
        let pairs: [(Leg, &[u8]); 3] = [
            (Leg::ReEst, FRAME_KIND_RE_EST),
            (Leg::ReAck, FRAME_KIND_RE_ACK),
            (Leg::ReConfirm, FRAME_KIND_RE_CONFIRM),
        ];
        assert_eq!(pairs.len(), 3, "three legs, three kinds");
        for (i, (leg_a, kind_a)) in pairs.iter().enumerate() {
            for (leg_b, kind_b) in &pairs[i + 1..] {
                assert_ne!(leg_a, leg_b, "two kinds share one Leg");
                assert_ne!(kind_a, kind_b, "two legs share one kind");
            }
        }
    }
}
