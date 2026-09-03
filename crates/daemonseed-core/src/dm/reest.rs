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
//! ## What this module does not do
//!
//! It encapsulates nothing and holds no state across a restart. The ML-KEM
//! material travels through it as bytes: `RE-EST` carries an encapsulation key,
//! `RE-ACK` carries the ciphertext that answers it, and folding either into a
//! root is [`crate::dm::ratchet`]'s. Persisting the sealed bytes is
//! [`crate::dm::resume`]'s, and nothing here writes a record.

use std::num::NonZeroU32;

use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_kdf::{HkdfSha384, KdfError};
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::dm::ratchet::Direction;
use crate::dm::resume::{Attempt, CommittedRoot, FreshAttempt, ResumeRecord};
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
/// # The identity rests on a precondition this build does not yet meet
///
/// `MAX_GAP = C` is sound only while a sender's `attempt` stays within `C` of
/// the receiver's `last_seen`. A8.1 restored the identity by closing **one** way
/// they diverge — crash inflation — and says nothing about the other. A7.3 names
/// that other one: *"`attempt` (A5.2) is monotone for the channel's whole
/// lifetime, not per-window"*, so the count that `C` bounds is
/// *"`attempt − attempt_at_window_start`"*, against **a window-start anchor A7.3
/// persists in the durable resume record**. Two windows of `C` attempts each
/// against a receiver that opened none of them puts the sender's `attempt` at
/// `2C`, outside `[last_seen, last_seen + C]`, and every leg it seals is
/// unopenable until `RS_n` retires — the lockout A7.3 named and A8.1 did not
/// re-examine.
///
/// **Neither half of the guard exists here.** [`ResumeRecord`] carries
/// `toward_c` and a *time* anchor (`window_anchor_ms`) but no
/// `attempt_at_window_start`; [`AttemptBudget`] is the count alone, with no
/// anchor and no rollover; and A8.2's rule that a window rolls over only by an
/// *"idempotent derivation from durable `last_seen`"* — the rule that would make
/// a rollover impossible without receiver progress, and so make the lockout
/// unreachable — is the store's and is unbuilt. Until both land, the lockout is
/// reachable rather than merely theoretical, and widening `MAX_GAP` is the wrong
/// repair: it would trade the lockout for the DoS amplifier A5.2 capped the scan
/// to prevent. `a_multi_window_attempt_locks_the_receiver_out` in this module's
/// tests is the standing demonstration.
pub const MAX_GAP: u32 = ATTEMPT_CEILING;

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
    /// higher attempt at the accepted generation — and the response budget
    /// admitted it: compose and emit a `RE-ACK`. The caller owes A5.1(ii)'s
    /// confirmation check before treating a supersede as legitimate.
    Emit,
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
/// budget is charged; both are in-session decisions about what to answer, which
/// is what this type holds. A5.3's byte-novelty memory is a different object
/// with different obligations: **durable** (*"a lost entry is a torn security
/// invariant"*), homed in the resume record, keyed
/// `(gen, attempt, leg, dir, seq)` rather than `(gen, attempt)`, and evicted on
/// *actual* `RS_n` retirement rather than on process exit. [`ResumeRecord`] has
/// no field for it and nothing here writes one, so **A5.3 is unbuilt** and this
/// type must not be read as covering it. What A5.3 defends against and this does
/// not: a co-host re-serving captured `RE-EST` bytes into a restarted party's
/// empty memory to re-fire the peer-state-regressed alarm.
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
/// - a **higher** attempt at that generation, or a **higher generation** →
///   admitted subject to the budget, replacing the slot. The higher-attempt
///   case is A5.1's supersede and the reason this is not the flat "first
///   commit wins" that A3.4 alone reads as.
///
/// **A5.1's confirmation lock is NOT here.** A5.1(ii): a *confirmed* candidate
/// *"is locked, and a later-arriving lower-or-stale attempt's `RE-EST` never
/// supersedes it"*. This gate holds no confirmation state and cannot, so the
/// caller must refuse a supersede of a confirmed generation before consulting
/// it. Like A5.3's memory, that obligation is named here because it is real and
/// unbuilt, not because this type covers it.
///
/// **One slot, not a set**, which is what the rule above allows: only the
/// accepted pair has to be remembered, so the memory is bounded by
/// construction, with no eviction policy to size and none to get wrong.
///
/// **Neither `Clone` nor `Copy`**, which is the same reason [`ReEstGate::admit`]
/// takes `&mut self`: a copy would accept an attempt its original never learned
/// about, and the two would then disagree about what has been answered with no
/// oracle to say which is right.
#[derive(Debug, Default)]
pub struct ReEstGate {
    accepted: Option<(u32, Attempt)>,
}

impl ReEstGate {
    /// A gate that has accepted nothing.
    pub const fn new() -> Self {
        Self { accepted: None }
    }

    /// The accepted pair, if one has been.
    ///
    /// Stored as an [`Attempt`] rather than a bare `u32`, so the empty-slot
    /// spelling is unrepresentable here instead of being an impossible state
    /// this accessor would have to decide how to report.
    pub fn accepted(&self) -> Option<(u32, Attempt)> {
        self.accepted
    }

    /// Admit an opened `RE-EST`, charging `budget` only if the frame is new.
    ///
    /// `budget` returns whether the response-emission budget admits one more
    /// `RE-ACK`. It is called on exactly one path — a `(generation, attempt)`
    /// strictly beyond what has been accepted — so a replay, however many times
    /// it arrives, costs nothing.
    pub fn admit(
        &mut self,
        generation: u32,
        attempt: Attempt,
        budget: impl FnOnce() -> bool,
    ) -> ReEstAdmission {
        let incoming = (generation, attempt);
        match self.accepted {
            Some(seen) if incoming == seen => return ReEstAdmission::ReServe,
            Some(seen) if incoming < seen => return ReEstAdmission::Dropped,
            _ => {}
        }
        if !budget() {
            return ReEstAdmission::Withheld;
        }
        self.accepted = Some(incoming);
        ReEstAdmission::Emit
    }
}

/// How far a correspondence has gone toward `C` in its current re-initiation
/// window — the toward-`C` count A9.2 puts in the resume record.
///
/// A newtype rather than a bare `u32` because the ceiling is the whole meaning of
/// the number: past it the party gives up and the exchange is surfaced, and a
/// bare counter carries no way to say so.
///
/// **It is the count and nothing else.** A7.3's window-start anchor
/// (`attempt_at_window_start`) and A8.2's `last_seen`-derived rollover are not
/// here and are not in [`ResumeRecord`] — see [`MAX_GAP`] for what that leaves
/// open. Charging this budget therefore bounds attempts *within* a window and
/// says nothing about the monotone `attempt` counter across windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptBudget(u32);

impl AttemptBudget {
    /// A window with no attempts spent.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// The count a resume record carries.
    pub fn from_record(record: &ResumeRecord) -> Self {
        Self(record.toward_c())
    }

    /// The count, for encoding back into a record.
    pub fn count(self) -> u32 {
        self.0
    }

    /// Whether the ceiling is reached and the party gives up rather than
    /// re-initiating again in this window.
    pub fn exhausted(self) -> bool {
        self.0 >= ATTEMPT_CEILING
    }

    /// Spend one attempt. `None` at the ceiling, which is the give-up A9 makes
    /// loud rather than a silent stall.
    pub fn charge(self) -> Option<Self> {
        if self.exhausted() {
            return None;
        }
        Some(Self(self.0 + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        CommittedRoot::from_bytes([3u8; 32])
    }

    fn other_root() -> CommittedRoot {
        CommittedRoot::from_bytes([4u8; 32])
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

    /// **A worked demonstration of an OPEN defect. It is NOT a tripwire, and
    /// this doc says so because the obvious reading is that it is one.**
    ///
    /// What it shows: `attempt` is monotone for the channel's whole life (A7.3)
    /// while `C` bounds attempts *per window*, so an `attempt` of `2C` against a
    /// receiver whose `last_seen` is still 0 falls outside
    /// `[last_seen, last_seen + MAX_GAP]` and every leg sealed under it is
    /// unopenable until `RS_n` retires. See [`MAX_GAP`].
    ///
    /// **What it does NOT do, precisely.** It reaches `2C` by calling
    /// `Attempt::advance` directly, which is not a path either half of the
    /// missing guard touches: neither an `attempt_at_window_start` anchor nor
    /// A8.2's `last_seen`-derived rollover would change one line of it, so both
    /// could land with this test still green. The only mutation it kills is a
    /// change to [`MAX_GAP`] or the scan width, and
    /// `the_scan_window_ends_at_max_gap` already kills that. **A real tripwire
    /// for the anchor landing cannot be written until the anchor exists** —
    /// there is nothing to observe — so this is a documented reproduction of
    /// the failure, kept because a reader who doubts the [`MAX_GAP`] doc can run
    /// it, and nothing more.
    #[test]
    fn a_multi_window_attempt_locks_the_receiver_out() {
        let ours = keypair(24);
        // Two windows of C attempts each. Nothing here resets the monotone
        // counter, because there is nothing in this crate that could.
        let mut attempt = Attempt::FIRST;
        let mut fresh = FreshAttempt::first();
        for _ in 0..(2 * ATTEMPT_CEILING - 1) {
            fresh = attempt.advance().unwrap();
            attempt = fresh.attempt();
        }
        assert_eq!(attempt.get(), 2 * ATTEMPT_CEILING);
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
        // The receiver opened nothing, so its window is [1, C].
        assert!(matches!(
            scan_re_est(&root(), Direction::AToB, 7, SEQ, 0, &leg, ours.public_key()),
            Err(ReEstError::DidNotOpen)
        ));
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
        let root = CommittedRoot::from_bytes([3u8; 32]);
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
}
