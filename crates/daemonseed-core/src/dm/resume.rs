//! The re-establishment resume record: everything a reconnect needs that a
//! restart would otherwise destroy (A9.2, part of ISC-C39 / ISC-A-C21).
//!
//! Design of record: `docs/design/direct-messaging.md`, **Amendment A9**
//! (RATIFIED 2026-07-30), § A9.2 in particular, plus § A4's enumeration at
//! `:1061` and the store's atomicity contract in A8.2.
//!
//! A channel that goes down mid-re-establishment has to come back holding
//! *exactly* what it held before, and A9.1 makes that literal: a re-emit of an
//! already-persisted attempt is the **byte-identical persisted seal**. ML-KEM
//! encapsulation is randomized and `ss → eph_ct` is not invertible, so that
//! seal cannot be reproduced from its key inputs — it has to have been written
//! down. That single fact is why this record exists and why it is one blob
//! rather than several.
//!
//! ## One write, not seven
//!
//! A9.2's field list is not a bag of related values; it is the **set that must
//! agree with itself**. A crash that paired a committed root with a stale
//! attempt would re-emit under a key the peer will never confirm, and the
//! divergence is permanent — `RatchetError::UnknownEphemeral`
//! ([`crate::dm::ratchet`]) with no path back. So every field travels in one
//! [`ResumeRecord`], written by one `replace_atomically` through
//! [`crate::storage::dm_store`], and there is no API here that writes a part of
//! it. "Commit-then-emit is provably a single atomic act" is a property of
//! there being nothing else to call.
//!
//! ## The two high-waters are not both here, and that is the point
//!
//! A9.2 names them apart because A8.2 had collided them, and they have
//! **opposite durability**:
//!
//! | | lives | scope | here? |
//! |---|---|---|---|
//! | **send-side floor** ([`SendFloor`]) | durable, in this record | the conversation | **yes** |
//! | receive-side peer high-water | the ratchet, in RAM | one session, reset per `chan_id` | **no** |
//!
//! The receive side is discharged by loud teardown and bounded by eviction; a
//! copy of it here would be a second answer to a question the ratchet already
//! answers, free to disagree with it and with no oracle to say which was right
//! — the objection `dm::collect` raises against keeping a second cursor. There
//! is deliberately **no field** for it, so a future edit that wants one has to
//! add it on purpose rather than fill one in.
//!
//! ## What this module does not do
//!
//! It holds bytes and orders two integers. It seals nothing, derives nothing,
//! reads no clock and encapsulates nothing: [`ResumeRecord::encode`] is
//! plaintext, and `dm_store` seals it, pads it to the kind's fixed bucket and
//! refuses an oversized payload — the same split [`crate::dm::outbox`] uses.

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError};
use crate::dm::frame::MAX_FRAME_LEN;
use crate::dm::ratchet::ROOT_KEY_LEN;
use crate::secret_seed::redacted_secret_newtype;
use oxicrypt_ml_dsa as ml_dsa;

/// At-rest magic. The version is **inside** it, so a decoder compares one thing
/// and cannot read an older body under a newer header — the shape
/// [`crate::dm::outbox`] and [`crate::dm::provisional`] both use.
pub const RESUME_MAGIC: &[u8] = b"daemonseed/dm/resume/v1\0";

/// Width of the suite-id field, big-endian, immediately after the magic.
pub const SUITE_ID_LEN: usize = 2;

/// Every fixed-width field of the encoding, in order, so the worst case below
/// is arithmetic rather than a guess.
const FIXED_LEN: usize = RESUME_MAGIC.len()
    + SUITE_ID_LEN
    + ml_dsa::SK_LEN /* s_pc */
    + ml_dsa::PK_LEN /* pk_pc */
    + ROOT_KEY_LEN /* committed_root */
    + 4 /* attempt */
    + 4 /* send_floor.generation */
    + 8 /* send_floor.seq */
    + 8 /* window_anchor_ms */
    + 4 /* toward_c */
    + 8 /* sealed RE-EST length prefix */;

/// The largest [`ResumeRecord::encode`] output this build can produce.
///
/// **Computed, not estimated.** Every field but one is fixed-width, and the one
/// that is not is bounded by [`MAX_FRAME_LEN`] — which [`SealedReEst::seal`]
/// refuses to exceed and [`ResumeRecord::decode`] re-checks before allocating,
/// so this is a real ceiling rather than a typical case.
/// [`crate::storage::dm_store::RESUME_CAPACITY`] is sized
/// against it, and `the_capacity_holds_the_worst_case` pins the relationship in
/// the direction that matters: if a field is added here and the constant is not
/// revisited, that test fails rather than a write failing on a user's disk.
pub const MAX_ENCODED_LEN: usize = FIXED_LEN + MAX_FRAME_LEN;

/// What can go wrong building or decoding a resume record.
#[derive(Debug, PartialEq, Eq)]
pub enum ResumeError {
    /// A sealed RE-EST frame longer than [`MAX_FRAME_LEN`]. Refused at
    /// construction as well as at decode, so an oversized record has no
    /// spelling rather than being caught one layer later by the store.
    FrameTooLong { len: usize },
    /// The at-rest bytes started with no magic this build recognises.
    BadMagic,
    /// The at-rest bytes ended inside a field.
    Truncated,
    /// Trailing bytes after the record.
    TrailingBytes(usize),
    /// The suite id in the header is one of the registry's reserved sentinels.
    SuiteIdSentinel(SuiteIdError),
    /// The suite id names no entry in this build's registry, so the record was
    /// written by a build whose primitives this one does not implement.
    UnknownSuite(SuiteId),
    /// A [`SendFloor`] that does not advance on the one it replaces. The stored
    /// floor is returned alongside so a caller can report both.
    FloorWouldRollBack {
        stored: SendFloor,
        offered: SendFloor,
    },
    /// A record offered under an earlier `attempt` than the stored one.
    AttemptWouldRollBack { stored: u32, offered: u32 },
    /// A record offered under an `attempt` that is already persisted, carrying
    /// **different** sealed RE-EST bytes.
    ///
    /// A9.1: a re-emit of an already-persisted attempt is always the
    /// byte-identical persisted seal, and a fresh secret is permitted only under
    /// a **new** attempt. The peer dedups on `attempt` (A9.4), so it has already
    /// seen the first seal and will drop the second as a duplicate — leaving the
    /// recovering party holding a secret the peer will never confirm, which is
    /// the permanent `UnknownEphemeral` divergence
    /// ([`crate::dm::ratchet`]) A9.1 exists to forbid.
    AttemptResealed { attempt: u32 },
    /// A record whose handshake slot is **empty** offered against a stored one
    /// carrying a real attempt.
    ///
    /// The empty slot is what first establishment writes, so this is a first
    /// establishment arriving after a re-establishment has been persisted. It is
    /// [`Self::AttemptWouldRollBack`]'s case for the slot that has no number —
    /// separate rather than reported as `offered: 0`, because no [`Attempt`] is
    /// ever `0` and a log line saying so names a value that cannot exist.
    EmptySlotWouldReplaceAttempt { stored: u32 },
    /// A record offering a different `s_pc` or `pk_pc` than the stored one.
    ///
    /// **The pseudonym pair is fixed for the life of a correspondence.** It is
    /// at-rest-only and not mnemonic-derivable (§ Keys), so the stored copy is
    /// the only one there is: replacing it discards the key every frame already
    /// sent was signed under and the key every frame received is verified
    /// against, leaving a correspondence that is on disk and cannot speak. A
    /// different pair means a different correspondence, which needs a different
    /// label rather than this record.
    ///
    /// Neither key is reported. `s_pc` is a signing key, and `pk_pc` would name
    /// the correspondent in a log line.
    PseudonymPairChanged,
    /// At-rest bytes spelling attempt `0` — the empty handshake slot — beside a
    /// non-empty sealed frame.
    ///
    /// The two halves contradict each other: [`Attempt::FIRST`] is `1`, so `0`
    /// is reachable at rest only as the empty slot, and an empty slot has no
    /// frame. Refused rather than repaired, because either half could be the
    /// true one and nothing here can say which.
    ///
    /// **[`ResumeRecord::encode`] cannot produce these bytes** — it derives both
    /// halves from one `Option` — so no round-trip test reaches this arm, and
    /// neither does a tampered file, which fails the store's seal before any of
    /// it arrives here. The path that does reach it is a caller handing
    /// [`ResumeRecord::decode`] a hand-written buffer, which is what a record
    /// from another encoder is, and
    /// `the_decoder_refuses_a_slot_that_contradicts_itself` takes it.
    EmptySlotHasFrame { len: usize },
    /// The mirror: at-rest bytes spelling a real attempt beside a **zero-length**
    /// frame.
    ///
    /// A [`SealedReEst`] is a sealed frame bound to its attempt, so an attempt
    /// with no frame is the same contradiction the other way round, and letting
    /// it through would build the one value
    /// [`ResumeRecord::sealed_re_est`] says cannot exist — a `Some` carrying
    /// nothing, which a re-emit would send as an empty frame. Reached the same
    /// way, by the same test.
    OccupiedSlotHasNoFrame { attempt: u32 },
}

impl std::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLong { len } => {
                write!(
                    f,
                    "a sealed RE-EST frame of {len} bytes exceeds {MAX_FRAME_LEN}"
                )
            }
            Self::BadMagic => write!(f, "not a resume record"),
            Self::Truncated => write!(f, "the resume record ends inside a field"),
            Self::TrailingBytes(n) => write!(f, "{n} bytes after the record"),
            Self::SuiteIdSentinel(e) => write!(f, "resume suite_id: {e}"),
            Self::UnknownSuite(id) => {
                write!(f, "resume suite {id} is not in this build's registry")
            }
            Self::AttemptWouldRollBack { stored, offered } => {
                write!(f, "attempt {offered} is behind the stored attempt {stored}")
            }
            Self::AttemptResealed { attempt } => write!(
                f,
                "attempt {attempt} is already persisted under different sealed bytes"
            ),
            Self::EmptySlotHasFrame { len } => write!(
                f,
                "an empty handshake slot carries {len} bytes of sealed frame"
            ),
            Self::OccupiedSlotHasNoFrame { attempt } => {
                write!(f, "attempt {attempt} carries no sealed frame")
            }
            Self::EmptySlotWouldReplaceAttempt { stored } => write!(
                f,
                "a record with no re-establishment is behind the stored attempt {stored}"
            ),
            Self::PseudonymPairChanged => write!(
                f,
                "the correspondence's pseudonym keypair may not change once stored"
            ),
            Self::FloorWouldRollBack { stored, offered } => write!(
                f,
                "send floor {}:{} does not advance on the stored {}:{}",
                offered.generation(),
                offered.seq(),
                stored.generation(),
                stored.seq()
            ),
        }
    }
}

impl std::error::Error for ResumeError {}

redacted_secret_newtype! {
    /// The committed re-establishment root.
    ///
    /// Distinct from [`RootKey`](crate::dm::ratchet::RootKey) on purpose: that
    /// is the running ratchet's root, advanced and destroyed as its successor
    /// appears, and this is the one a re-establishment **committed** — the value
    /// a resuming party must fold from, not the value it is currently using.
    /// Giving them one type would let a caller persist a live ratchet root here,
    /// which is the forward secrecy `dm::ratchet` deletes chains to protect.
    inline pub struct CommittedRoot([u8; ROOT_KEY_LEN]);
}

impl CommittedRoot {
    /// Wrap raw bytes. The caller is handing over a secret; nothing here copies
    /// it anywhere that does not zeroize.
    pub fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// The send-side floor: how far this party's own sequence numbers have gone,
/// qualified by the generation they went there under.
///
/// **The field order IS the comparison.** `derive(Ord)` on a struct compares
/// fields in declaration order, so `generation` first and `seq` second gives
/// exactly A9.2's lexicographic rule with no hand-written comparison to get
/// wrong — and no way to write a comparison that disagrees with the encoding,
/// since the encoder walks the same order.
///
/// **Why the generation is carried at all — settled by caraka 2026-08-14,
/// closing #313.** Send `seq` does **not** restart at a new generation:
/// `Ratchet::step_send` starts a new chain at the current `next_send_seq` and
/// never resets it, so `seq` is monotone per direction for the life of the
/// conversation. Three surfaces make that continuity load-bearing — `seq` is
/// the DHT page address, the outbox's only key, and the acknowledgement's
/// position, none of them namespaced by generation.
///
/// So the generation is **not** here to absorb a sequence restart. It is here
/// because with a bare counter, *"re-established and nothing sent yet"* and
/// *"a replayed stale resume blob"* are the same value; the pair tells them
/// apart.
///
/// **A9.2 originally justified the qualification by a restart at 0. That
/// premise was false, and the design text is amended** (§ build note
/// 2026-08-14). It is recorded here because a false *reason* is more dangerous
/// than a missing one: a reader who checks it, finds it untrue, and concludes
/// the field is unnecessary would delete a guard that is doing real work.
///
/// **Lexicographic ordering is not by itself a safe write guard.** `(5, 0)`
/// outranks `(4, u64::MAX)`, so a bare `>=` admits a sequence rollback riding on
/// a generation bump — which is why [`Self::admits`] requires both components to
/// be non-decreasing rather than deferring to [`Ord`]. An earlier draft of this
/// comment claimed lexicographic ordering "contains plain `seq` ordering"; that
/// is false and was caught in review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SendFloor {
    generation: u32,
    seq: u64,
}

impl SendFloor {
    /// The floor at a generation and sequence.
    pub fn new(generation: u32, seq: u64) -> Self {
        Self { generation, seq }
    }

    /// The generation this floor was reached under.
    pub fn generation(self) -> u32 {
        self.generation
    }

    /// How far this party's own sequence numbers have gone.
    pub fn seq(self) -> u64 {
        self.seq
    }

    /// The later of two floors, or [`ResumeError::FloorWouldRollBack`] if the
    /// offered one is not later.
    ///
    /// **Equal is refused, not accepted.** A floor that has not moved is not
    /// evidence of progress, and accepting it would let a caller persist a write
    /// that reports success while advancing nothing — the shape #278 records one
    /// module over. A caller with genuinely nothing to advance has no reason to
    /// write.
    pub fn advance_to(self, offered: Self) -> Result<Self, ResumeError> {
        if offered > self {
            Ok(offered)
        } else {
            Err(ResumeError::FloorWouldRollBack {
                stored: self,
                offered,
            })
        }
    }

    /// Whether a record carrying `offered` may replace one carrying `self`.
    ///
    /// **Deliberately weaker than [`Self::advance_to`], and the difference is
    /// not an oversight.** That call advances the floor and refuses a value
    /// that stands still, because standing still is not progress. This one
    /// guards a *record write*, and a resume record is rewritten for reasons
    /// that have nothing to do with the send side — a new `attempt`, a new
    /// window anchor, a fresh toward-`C` count. Refusing an unmoved floor here
    /// would refuse those writes, so the invariant this enforces is the only one
    /// that is actually true of the send side: **it never goes backwards.**
    ///
    /// **Both components must be non-decreasing, and that is deliberately
    /// stricter than [`Ord`].** Lexicographically `(5, 0)` outranks
    /// `(4, u64::MAX)`, so an `offered >= self` guard would admit a floor whose
    /// sequence dropped by up to 2⁶⁴ as long as the generation went up — and
    /// against the ratchet as built, where send `seq` never restarts, that is a
    /// real rollback of spent sequences rather than the false alarm A9.2's
    /// qualification exists to avoid. Writing the floor as `(G+1, 0)` is exactly
    /// what A9.2's own restart-at-0 prose invites, which is what makes this the
    /// dangerous spelling rather than a theoretical one.
    ///
    /// So the ordering stays lexicographic as A9.2 ratifies — that is what
    /// [`Ord`] and [`Self::advance_to`] use — and only this **write guard** is
    /// conservative. If the unbuilt re-establishment path does restart `seq`,
    /// relaxing this to the plain comparison is then a deliberate, reviewed
    /// change rather than a hole nobody notices. The question is filed.
    pub fn admits(self, offered: Self) -> bool {
        offered.generation >= self.generation && offered.seq >= self.seq
    }
}

/// Which re-establishment attempt a record describes.
///
/// A newtype rather than a bare `u32` because A9.1 attaches an invariant to this
/// number that arithmetic does not carry: **a fresh encapsulation is permitted
/// only under a new attempt.** Authority to seal one comes only from
/// [`Self::advance`], which yields a [`FreshAttempt`] for the *successor*, and
/// from [`FreshAttempt::first`] — so [`SealedReEst::seal`] cannot be called with
/// an attempt already in hand. See [`FreshAttempt`] for what that does and does
/// not close.
///
/// Ordering is the ordinary numeric one, which is what
/// [`crate::dm::persist::DmPersist::commit_resume`] compares to refuse a
/// regression.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Attempt(u32);

impl std::fmt::Debug for Attempt {
    /// The bare number, not `Attempt(7)`. This value is read in log lines beside
    /// a correspondence label, where the wrapper name is noise and the reader
    /// wants the counter the peer dedups on.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Attempt {
    /// The first attempt of a correspondence.
    pub const FIRST: Self = Self(1);

    /// The number, for encoding and for error reporting.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Advance to the next attempt, yielding the one token that authorises a
    /// **fresh** encapsulation under it (A9.1(b)).
    ///
    /// `None` at `u32::MAX` rather than wrapping: a wrapped attempt would
    /// re-enter numbers the peer has already deduped, which is the divergence
    /// A9.1 forbids arriving by arithmetic instead of by a bad call.
    pub fn advance(self) -> Option<FreshAttempt> {
        self.0.checked_add(1).map(|n| FreshAttempt(Self(n)))
    }
}

/// Authority to seal a **fresh** RE-EST under an attempt other than one already
/// in hand.
///
/// A9.1's forbidden act — a fresh `eph_ct` under an unchanged key — is spelled by
/// sealing fresh bytes under an attempt that is already persisted, and requiring
/// a capability that only [`Attempt::advance`] and [`FreshAttempt::first`] can
/// mint is what removes that spelling: there is no token for an attempt you are
/// holding, so [`SealedReEst::seal`] cannot be called with one.
///
/// **Three limits, stated because the tempting reading is that this closes more
/// than it does.**
///
/// 1. **It bounds seals per token, not per attempt.** [`Attempt`] is `Copy`, so
///    `advance()` may be called repeatedly on one value and hand back several
///    independent tokens for the *same* successor. Each seals once; nothing here
///    stops two of them sealing different frames under one attempt. Whichever
///    commits second is refused by `AttemptResealed`, on disk, not here.
/// 2. **It does not constrain [`ResumeRecord::decode`].** That path rebuilds a
///    [`SealedReEst`] from at-rest bytes, pairing an attempt and a frame read
///    from two independent byte ranges with no token involved — necessarily, as
///    the bytes come from a file rather than from a caller. So a
///    [`SealedReEst`] in hand is **not** proof a token authorised it.
/// 3. **It is blind across processes and restarts.** The token proves an attempt
///    is the successor of one held *in this process*; it cannot know what
///    another process, or this one before a restart, already persisted.
///
/// All three land in the same place: `commit_resume`'s `AttemptResealed` and
/// `AttemptWouldRollBack` guards are what stop a wrong pairing reaching the
/// wire, and they are **not** superseded by this type. The type removes the
/// caller's mistake at compile time; the store remains the enforcement point.
/// Deliberately **not `Clone` and not `Copy`**, which is what makes limit 1 a
/// bound at all rather than no bound.
pub struct FreshAttempt(Attempt);

impl FreshAttempt {
    /// Authority to seal the **first** attempt of a correspondence.
    ///
    /// Necessary rather than convenient: [`Attempt::advance`] is the only other
    /// mint and it yields a successor, so without this there is no way to seal
    /// [`Attempt::FIRST`] at all and a correspondence could never emit its first
    /// RE-EST. It is safe for the same reason `advance` is — a first attempt has
    /// no predecessor to re-seal — and `commit_resume` still refuses it against
    /// anything already on disk.
    pub fn first() -> Self {
        Self(Attempt::FIRST)
    }

    /// The attempt this token authorises.
    pub fn attempt(&self) -> Attempt {
        self.0
    }
}

/// A sealed RE-EST frame, bound to the attempt it was sealed under.
///
/// The binding is the point: the pairing is fixed at the moment of sealing and
/// no later call can restate it. Carried as two independent values, a caller
/// could pair a fresh encapsulation with any attempt number it liked, and the
/// mistake would surface — if at all — one layer down at the store.
///
/// A9.1(a)'s byte-identical re-emit falls out of the same shape: a record read
/// back from disk yields this type with the stored bytes already inside it, and
/// there is no constructor that re-seals it.
///
/// # The correct call
///
/// ```
/// use daemonseed_core::dm::resume::{Attempt, SealedReEst};
///
/// // A fresh secret under a NEW attempt — A9.1(b), permitted.
/// let fresh = Attempt::FIRST.advance().expect("attempt space remains");
/// let sealed = SealedReEst::seal(fresh, vec![0u8; 32].into_boxed_slice())
///     .expect("32 bytes is within MAX_FRAME_LEN");
/// assert_eq!(sealed.attempt().get(), 2);
/// ```
///
/// # The forbidden call does not compile
///
/// A fresh seal under an attempt already in hand — the act A9.1 forbids, and the
/// one that reaches AEAD nonce-reuse forgery or permanent `UnknownEphemeral`
/// divergence. There is no `FreshAttempt` for it, so it is a type error:
///
/// ```compile_fail,E0308
/// use daemonseed_core::dm::resume::{Attempt, SealedReEst};
///
/// let persisted = Attempt::FIRST;
/// // error[E0308]: expected `FreshAttempt`, found `Attempt`
/// let sealed = SealedReEst::seal(persisted, vec![0u8; 32].into_boxed_slice());
/// ```
///
/// **The `E0308` annotation records the expected error but does NOT enforce it
/// on this toolchain** — measured, not assumed: replacing it with an unrelated
/// code (`E0369`) leaves the doctest passing. Treat it as documentation of
/// intent. What actually protects this probe is the paired control above: a
/// `compile_fail` block passes on *any* compilation failure, including a typo or
/// a renamed import, and the control shares its imports and call so that failure
/// mode surfaces there instead of being scored as a success here.
///
/// **The two blocks above are a probe and its control, and the pairing is
/// load-bearing rather than decorative.** A `compile_fail` block passes for *any*
/// compilation failure, including a typo or a stale import path — so on its own
/// it cannot distinguish "the wrong call is rejected" from "this doctest is
/// broken". The first block carries the same imports and the corrected call, so
/// a path that stopped resolving fails there, loudly, instead of being scored as
/// a success here.
///
/// # One token, one seal
///
/// ```compile_fail,E0382
/// use daemonseed_core::dm::resume::{Attempt, SealedReEst};
///
/// let fresh = Attempt::FIRST.advance().expect("attempt space remains");
/// let first = SealedReEst::seal(fresh, vec![0u8; 32].into_boxed_slice());
/// // error[E0382]: use of moved value — `FreshAttempt` is not `Clone`.
/// let second = SealedReEst::seal(fresh, vec![1u8; 32].into_boxed_slice());
/// ```
pub struct SealedReEst {
    attempt: Attempt,
    bytes: Box<[u8]>,
}

impl SealedReEst {
    /// Seal a fresh RE-EST under a newly advanced attempt.
    ///
    /// Refuses a frame past [`MAX_FRAME_LEN`], which is where that ceiling now
    /// lives: it is a property of a sealed frame, so holding one of these is
    /// proof the length was checked and [`ResumeRecord::new`] no longer has to
    /// be fallible to say so.
    pub fn seal(fresh: FreshAttempt, bytes: Box<[u8]>) -> Result<Self, ResumeError> {
        Self::bind(fresh.attempt(), bytes)
    }

    /// Rebuild from the at-rest form. **Crate-private, and only
    /// [`ResumeRecord::decode`] calls it** — a public version would be a
    /// re-seal by another name, since it takes an arbitrary attempt beside
    /// arbitrary bytes.
    fn from_stored(attempt: Attempt, bytes: Box<[u8]>) -> Result<Self, ResumeError> {
        Self::bind(attempt, bytes)
    }

    fn bind(attempt: Attempt, bytes: Box<[u8]>) -> Result<Self, ResumeError> {
        if bytes.len() > MAX_FRAME_LEN {
            return Err(ResumeError::FrameTooLong { len: bytes.len() });
        }
        Ok(Self { attempt, bytes })
    }

    /// The attempt these bytes were sealed under.
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }

    /// The sealed frame, borrowed — the same bytes every call, which is A9.1(a)'s
    /// byte-identical re-emit at this layer.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for SealedReEst {
    /// The frame is ciphertext rather than a secret, but its length is the only
    /// part worth reading and printing it whole would bury every log line it
    /// appears in — the same judgement [`ResumeRecord`]'s own `Debug` makes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedReEst")
            .field("attempt", &self.attempt)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

/// Everything a re-establishment needs to survive a restart, in one blob.
///
/// **Every field here is one A9.2 enumerates**, and the list is closed: the
/// module docs give the argument for what is deliberately absent.
///
/// The secret halves zero on drop. `s_pc` is a per-correspondent ML-DSA-87
/// signing key that is **at-rest only and not mnemonic-derivable** (§ Keys), so
/// unlike the long-term identity there is no re-derivation path — losing this
/// record loses the ability to sign as that pseudonym at all, which is why the
/// key is in it rather than being fetched from somewhere on resume.
#[derive(ZeroizeOnDrop)]
pub struct ResumeRecord {
    /// **Ours**, and secret: the per-correspondent signing key `msg_sig` is
    /// produced under. Without it every leg we send after the restart is
    /// unsignable.
    s_pc: Box<[u8; ml_dsa::SK_LEN]>,
    /// **The peer's**, and public: the verifying key every inbound leg's
    /// `msg_sig` is checked against. Without it an inbound leg fails signature
    /// check and is indistinguishable from filler (A4, `:1061`).
    #[zeroize(skip)]
    pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
    /// The re-establishment root this party has committed to.
    committed_root: CommittedRoot,
    /// **The sealed RE-EST frame and the attempt it was sealed under, as one
    /// value.** The peer dedups a re-emit on the attempt (A9.4), and A9.1 permits
    /// a fresh secret only under a **new** one — so the two facts are carried
    /// bound together rather than as fields a caller could pair wrongly. See
    /// [`SealedReEst`] for the construction rule that enforces it.
    ///
    /// **`None` is the handshake slot standing empty** rather than a missing
    /// field: a correspondence that has established and not yet
    /// re-established has a resume record and no re-establishment frame, and
    /// [`SealedReEst::seal`] cannot mint a stand-in for one because it consumes
    /// a [`FreshAttempt`] — spending attempt 1 on a frame that was never
    /// emitted, which `AttemptResealed` then refuses when the real first
    /// re-establishment arrives. At rest the slot is attempt `0` and a
    /// zero-length frame; [`Attempt::FIRST`] is `1`, so the spelling is free.
    ///
    /// The bytes are load-bearing in this blob (A9.2): ML-KEM encapsulation is
    /// randomized and `ss → eph_ct` is not invertible, so A9.1(a)'s
    /// byte-identical re-emit cannot be rebuilt from the key inputs. Recovery
    /// re-emits *these*, not a fresh encapsulation.
    ///
    /// `zeroize(skip)` matches what the two fields it replaces both carried: an
    /// attempt counter and a sealed frame are neither of them secrets.
    #[zeroize(skip)]
    sealed: Option<SealedReEst>,
    /// The durable send-side floor. See [`SendFloor`].
    #[zeroize(skip)]
    send_floor: SendFloor,
    /// The re-establishment window's anchor, in the caller's clock.
    #[zeroize(skip)]
    window_anchor_ms: i64,
    /// How far this correspondence has progressed toward `C`.
    #[zeroize(skip)]
    toward_c: u32,
}

impl std::fmt::Debug for ResumeRecord {
    /// Redacted by hand rather than derived: `s_pc` is a signing key and
    /// `committed_root` is a root, so one `debug!(?record)` would put both in a
    /// log — the defect `dm::firstcontact` records for a decrypted body.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumeRecord")
            .field("s_pc", &"<redacted>")
            .field("pk_pc", &"<peer verifying key>")
            .field("committed_root", &self.committed_root)
            .field("send_floor", &self.send_floor)
            .field("window_anchor_ms", &self.window_anchor_ms)
            .field("toward_c", &self.toward_c)
            // Renders the attempt and the frame's length; `SealedReEst`'s own
            // `Debug` makes the same redaction decision this impl does.
            .field("sealed", &self.sealed)
            .finish()
    }
}

impl ResumeRecord {
    /// Build a record.
    ///
    /// **All of it or none of it.** There is no builder and no field setter:
    /// the fields have to agree with each other, so the only way to have a
    /// record is to have supplied every part of one at the same moment.
    ///
    /// **Infallible, where it used to return a `Result`.** Its one failure mode
    /// was a sealed frame past [`MAX_FRAME_LEN`], and that ceiling now belongs to
    /// [`SealedReEst`] — holding one is already proof the length was checked, so
    /// there is nothing left here to refuse. The attempt arrives inside the same
    /// value for the reason [`SealedReEst`] gives: the pairing is fixed at
    /// sealing time and this call cannot restate it.
    ///
    /// **`sealed` is `None` at first establishment.** The keys, the committed
    /// root and the floor are known the moment a correspondence exists; a sealed
    /// re-establishment frame is not, and there is nothing legitimate to put in
    /// its place. See the field's own note.
    pub fn new(
        s_pc: Box<[u8; ml_dsa::SK_LEN]>,
        pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
        committed_root: CommittedRoot,
        sealed: Option<SealedReEst>,
        send_floor: SendFloor,
        window_anchor_ms: i64,
        toward_c: u32,
    ) -> Self {
        Self {
            s_pc,
            pk_pc,
            committed_root,
            sealed,
            send_floor,
            window_anchor_ms,
            toward_c,
        }
    }

    /// Our per-correspondent signing key.
    pub fn s_pc(&self) -> &[u8; ml_dsa::SK_LEN] {
        &self.s_pc
    }

    /// Where `committed_root` sits inside the struct (#314).
    ///
    /// The out-of-crate zeroize witness pins this as its structural control, and
    /// `offset_of!` cannot see a private field from out there — the same reason
    /// `VerifiedFirstContact::ss0_offset_for_test` exists. Without it the witness's
    /// containment match would accept the secret being freed at *any* offset in the
    /// record, which is precisely the drift the control is for: an accessor
    /// silently pointing at a neighbouring field would still pass.
    ///
    /// `s_pc` needs no equivalent because it is `Box`ed and therefore owns its
    /// allocation outright, so its offset is zero by construction.
    #[cfg(any(test, feature = "testing"))]
    pub const fn committed_root_offset_for_test() -> usize {
        core::mem::offset_of!(Self, committed_root)
    }

    /// The peer's per-correspondent verifying key.
    pub fn pk_pc(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.pk_pc
    }

    /// The committed re-establishment root.
    pub fn committed_root(&self) -> &CommittedRoot {
        &self.committed_root
    }

    /// Which attempt this record describes, or `None` while the handshake slot
    /// stands empty.
    ///
    /// **`None` orders below every [`Attempt`]**, which is what the anti-rollback
    /// comparison in
    /// [`commit_resume`](crate::dm::persist::DmPersist::commit_resume) needs and
    /// gets for free from `Option`'s derived ordering: a record with no
    /// re-establishment yet may be replaced by one carrying
    /// [`Attempt::FIRST`], and never the other way round.
    pub fn attempt(&self) -> Option<Attempt> {
        self.sealed.as_ref().map(SealedReEst::attempt)
    }

    /// The sealed frame bound to its attempt — what a re-emit sends.
    ///
    /// A re-emit path wants *this*, not the loose bytes: it carries the attempt
    /// the peer will dedup on (A9.4) alongside the frame, and there is no
    /// constructor on it that would re-seal either.
    pub fn sealed(&self) -> Option<&SealedReEst> {
        self.sealed.as_ref()
    }

    /// The durable send-side floor.
    pub fn send_floor(&self) -> SendFloor {
        self.send_floor
    }

    /// The re-establishment window's anchor.
    pub fn window_anchor_ms(&self) -> i64 {
        self.window_anchor_ms
    }

    /// Progress toward `C`.
    pub fn toward_c(&self) -> u32 {
        self.toward_c
    }

    /// The sealed RE-EST frame, borrowed — the same bytes every call, which is
    /// A9.1(a)'s byte-identical re-emit at this layer.
    ///
    /// Retained beside [`Self::sealed`] for the callers that genuinely want only
    /// the bytes — the store's encode path and the persist layer's
    /// byte-comparison guard.
    ///
    /// `None` while the handshake slot stands empty, and deliberately not an
    /// empty slice: a caller that emits what this returns must have nothing to
    /// emit in that state, and an empty slice is a frame of length zero.
    pub fn sealed_re_est(&self) -> Option<&[u8]> {
        self.sealed.as_ref().map(SealedReEst::bytes)
    }

    /// The at-rest form, plaintext. `dm_store` seals it.
    ///
    /// Field order matches [`Self::decode`] byte for byte, and the one
    /// variable-length field is last so nothing after it depends on its length.
    ///
    /// **`Zeroizing`, because this buffer holds a signing key.** `dm_store`
    /// zeroizes the padded copy it seals from and not the caller's bytes, so a
    /// plain `Vec` here would leave `s_pc` and the committed root in freed heap
    /// on every commit. [`crate::dm::provisional`] wraps its plaintext the same
    /// way on both seal and open, for the same reason.
    ///
    /// **The suite id is stamped at the current default write suite**, so a
    /// record read under an older still-registered suite is re-encoded under
    /// the current one — ISC-C24's read-old-write-new, exactly as
    /// [`crate::dm::outbox`] does it, and it loses nothing because the field
    /// describes the writer rather than the payload.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        // The empty slot: attempt `0`, which `Attempt::FIRST` leaves free, and a
        // zero-length frame. Both halves come from one `Option`, so the two
        // spellings that disagree — an attempt with no frame, a frame with no
        // attempt — have no expression here; `decode` refuses them on the way
        // back in, for bytes this encoder did not write.
        let attempt = self.attempt().map_or(0, Attempt::get);
        let frame = self.sealed_re_est().unwrap_or(&[]);
        let mut out = Zeroizing::new(Vec::with_capacity(FIXED_LEN + frame.len()));
        out.extend_from_slice(RESUME_MAGIC);
        out.extend_from_slice(&Registry::default_write_suite().get().to_be_bytes());
        out.extend_from_slice(self.s_pc.as_ref());
        out.extend_from_slice(self.pk_pc.as_ref());
        out.extend_from_slice(self.committed_root.as_bytes());
        out.extend_from_slice(&attempt.to_be_bytes());
        out.extend_from_slice(&self.send_floor.generation.to_be_bytes());
        out.extend_from_slice(&self.send_floor.seq.to_be_bytes());
        out.extend_from_slice(&self.window_anchor_ms.to_be_bytes());
        out.extend_from_slice(&self.toward_c.to_be_bytes());
        out.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        out.extend_from_slice(frame);
        out
    }

    /// Read the at-rest form back.
    ///
    /// **No clock argument.** `window_anchor_ms` is taken verbatim: nothing in
    /// this build computes a terminal transition from it, so a corrupt value
    /// costs re-establishment timing rather than switching a guarantee off —
    /// the distinction `dm::outbox::Outbox::decode` draws between the give-up
    /// clock and `next_due_ms`.
    ///
    /// **That is a statement about consumers that do not exist yet, so it is a
    /// re-check rather than a settled property.** When the re-establishment
    /// window logic lands, a future-dated anchor is the same clock-rollback
    /// class `Outbox::decode` refuses, and this decision has to be made again
    /// against what actually reads the field.
    ///
    /// The frame length is checked against what remains **before** anything is
    /// reserved, so a corrupt length cannot drive an allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResumeError> {
        let mut r = Reader::new(bytes);
        if r.take(RESUME_MAGIC.len())? != RESUME_MAGIC {
            return Err(ResumeError::BadMagic);
        }
        let suite_raw = u16::from_be_bytes(r.array()?);
        let suite_id = SuiteId::try_new(suite_raw).map_err(ResumeError::SuiteIdSentinel)?;
        if Registry::lookup(suite_id).is_none() {
            return Err(ResumeError::UnknownSuite(suite_id));
        }
        // **Boxed straight from the borrowed input, never through a stack
        // array.** `r.array()` would return `[u8; SK_LEN]` by value — a 4,896-byte
        // copy of a signing key left on the stack after the `Box::new` that
        // follows it. `to_vec()` allocates at exact capacity, so
        // `into_boxed_slice` reuses that allocation rather than copying again,
        // and the conversion to a fixed-size box reuses it a second time.
        let s_pc: Box<[u8; ml_dsa::SK_LEN]> = r
            .take(ml_dsa::SK_LEN)?
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| ResumeError::Truncated)?;
        let pk_pc: Box<[u8; ml_dsa::PK_LEN]> = Box::new(r.array()?);
        let committed_root = CommittedRoot::from_bytes(r.array()?);
        let attempt = u32::from_be_bytes(r.array()?);
        let generation = u32::from_be_bytes(r.array()?);
        let seq = u64::from_be_bytes(r.array()?);
        let window_anchor_ms = i64::from_be_bytes(r.array()?);
        let toward_c = u32::from_be_bytes(r.array()?);
        let len = u64::from_be_bytes(r.array()?);
        let len = usize::try_from(len).map_err(|_| ResumeError::Truncated)?;
        if len > MAX_FRAME_LEN {
            return Err(ResumeError::FrameTooLong { len });
        }
        let sealed_re_est: Box<[u8]> = r.take(len)?.to_vec().into_boxed_slice();
        let rest = r.remaining();
        if rest != 0 {
            return Err(ResumeError::TrailingBytes(rest));
        }
        // The at-rest form is the one place an attempt and a frame are paired
        // from separate bytes rather than at sealing time — which is why
        // `from_stored` is private to this module and this is its only caller.
        //
        // Attempt `0` is the empty slot, and `Attempt(0)` is therefore never
        // constructed: below `Attempt::FIRST`, it would order beneath a real
        // attempt while claiming to be one.
        let sealed = match attempt {
            0 if !sealed_re_est.is_empty() => {
                return Err(ResumeError::EmptySlotHasFrame {
                    len: sealed_re_est.len(),
                });
            }
            0 => None,
            n if sealed_re_est.is_empty() => {
                return Err(ResumeError::OccupiedSlotHasNoFrame { attempt: n });
            }
            n => Some(SealedReEst::from_stored(Attempt(n), sealed_re_est)?),
        };
        Ok(Self {
            s_pc,
            pk_pc,
            committed_root,
            sealed,
            send_floor: SendFloor { generation, seq },
            window_anchor_ms,
            toward_c,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ResumeError> {
        let end = self.at.checked_add(n).ok_or(ResumeError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(ResumeError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResumeError> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("take returned exactly N bytes"))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: i64 = 1_700_000_000_000;

    /// Byte-distinct and position-dependent, so a comparison that sliced,
    /// transposed or truncated could not pass by coincidence.
    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                seed.wrapping_add((i as u8).wrapping_mul(31))
                    .wrapping_add((i >> 8) as u8)
            })
            .collect()
    }

    fn s_pc(seed: u8) -> Box<[u8; ml_dsa::SK_LEN]> {
        Box::new(pattern(seed, ml_dsa::SK_LEN).try_into().unwrap())
    }

    fn pk_pc(seed: u8) -> Box<[u8; ml_dsa::PK_LEN]> {
        Box::new(pattern(seed, ml_dsa::PK_LEN).try_into().unwrap())
    }

    fn root(seed: u8) -> CommittedRoot {
        CommittedRoot::from_bytes(pattern(seed, ROOT_KEY_LEN).try_into().unwrap())
    }

    /// Every field set to a value distinct from every other field's, so a
    /// decoder that crossed two of them fails rather than passing.
    /// Walk to `attempt` the way a real caller must — there is no back door, by
    /// design. See the twin in [`crate::dm::persist`]'s tests.
    fn fresh(attempt: u32) -> FreshAttempt {
        let mut token = FreshAttempt::first();
        while token.attempt().get() < attempt {
            token = token
                .attempt()
                .advance()
                .expect("the fixture stays far below u32::MAX");
        }
        assert_eq!(token.attempt().get(), attempt, "the walk overshot");
        token
    }

    /// The fixture's occupied handshake slot, so a test asserting on the frame
    /// says which state it assumes rather than unwrapping in the assertion.
    fn frame_of(record: &ResumeRecord) -> &[u8] {
        record
            .sealed_re_est()
            .expect("the fixture's handshake slot is occupied")
    }

    /// As [`frame_of`], for the attempt.
    fn attempt_of(record: &ResumeRecord) -> Attempt {
        record
            .attempt()
            .expect("the fixture's handshake slot is occupied")
    }

    fn populated() -> ResumeRecord {
        ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            Some(
                SealedReEst::seal(fresh(7), pattern(0x44, 512).into_boxed_slice())
                    .expect("the fixture is within MAX_FRAME_LEN"),
            ),
            SendFloor::new(4, 100),
            ANCHOR,
            3,
        )
    }

    #[test]
    fn every_field_survives_the_round_trip() {
        let before = populated();
        let after = ResumeRecord::decode(&before.encode()).expect("a fresh encoding must decode");

        assert_eq!(after.s_pc(), before.s_pc());
        assert_eq!(after.pk_pc(), before.pk_pc());
        assert_eq!(
            after.committed_root().as_bytes(),
            before.committed_root().as_bytes()
        );
        assert_eq!(after.attempt(), before.attempt());
        assert_eq!(after.send_floor(), before.send_floor());
        assert_eq!(after.window_anchor_ms(), before.window_anchor_ms());
        assert_eq!(after.toward_c(), before.toward_c());
        assert_eq!(after.sealed_re_est(), before.sealed_re_est());

        // The fixture has to be non-degenerate for any of the above to mean
        // something: two fields holding the same bytes would let a crossed
        // decoder pass.
        assert_ne!(&before.s_pc()[..32], &before.pk_pc()[..32]);
        assert_ne!(&before.pk_pc()[..32], before.committed_root().as_bytes());
        // Every scalar against every other, so a later fixture edit cannot
        // hollow this test by making two of them equal. The earlier guard
        // covered three pairs and left the rest distinct only by accident.
        let scalars: [(&str, u64); 5] = [
            ("attempt", u64::from(attempt_of(&before).get())),
            ("generation", u64::from(before.send_floor().generation())),
            ("seq", before.send_floor().seq()),
            ("toward_c", u64::from(before.toward_c())),
            ("frame_len", frame_of(&before).len() as u64),
        ];
        for (i, (na, a)) in scalars.iter().enumerate() {
            for (nb, b) in &scalars[i + 1..] {
                assert_ne!(a, b, "fixture is degenerate: {na} and {nb} are both {a}");
            }
        }
    }

    /// Every byte accounted for and named — so there is nowhere in this record
    /// a receive-side peer high-water could be hiding, which is the property
    /// A9.2 asks for and the module docs argue for.
    #[test]
    fn the_encoding_has_room_for_nothing_else() {
        let record = populated();
        let encoded = record.encode();
        let named = RESUME_MAGIC.len()
            + SUITE_ID_LEN
            + ml_dsa::SK_LEN
            + ml_dsa::PK_LEN
            + ROOT_KEY_LEN
            + 4 /* attempt */
            + 4 /* generation */
            + 8 /* seq */
            + 8 /* window_anchor_ms */
            + 4 /* toward_c */
            + 8 /* frame length prefix */
            + frame_of(&record).len();
        assert_eq!(
            encoded.len(),
            named,
            "a field is present that nothing names"
        );
        assert_eq!(encoded.len(), FIXED_LEN + frame_of(&record).len());
    }

    /// A record's plaintext, assembled by hand so the two contradictory slot
    /// spellings can be written down at all.
    ///
    /// [`ResumeRecord::encode`] reads both halves from one `Option`, so neither
    /// spelling has an expression there; this is the second opinion the layout
    /// test uses, reused to reach the decoder's own guards.
    fn assembled(attempt: u32, frame: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(RESUME_MAGIC);
        out.extend_from_slice(&crate::crypto::suite::CNSA_2_0.id.get().to_be_bytes());
        out.extend_from_slice(&pattern(0x11, ml_dsa::SK_LEN));
        out.extend_from_slice(&pattern(0x22, ml_dsa::PK_LEN));
        out.extend_from_slice(&pattern(0x33, ROOT_KEY_LEN));
        out.extend_from_slice(&attempt.to_be_bytes());
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&100u64.to_be_bytes());
        out.extend_from_slice(&ANCHOR.to_be_bytes());
        out.extend_from_slice(&3u32.to_be_bytes());
        out.extend_from_slice(&(frame.len() as u64).to_be_bytes());
        out.extend_from_slice(frame);
        out
    }

    /// **Both spellings in which the attempt and the frame contradict each other
    /// are refused**, and the two that agree still decode.
    ///
    /// The pair that agrees is the positive control: without it a decoder that
    /// refused every record would pass this test. Neither refusal is reachable
    /// from this build's encoder — it derives both halves from one `Option`, and
    /// the store seals the record so an altered file fails to open first — so
    /// handing `decode` a buffer is the only path to them, and it is the path
    /// a record written by some other encoder would take.
    #[test]
    fn the_decoder_refuses_a_slot_that_contradicts_itself() {
        assert_eq!(
            ResumeRecord::decode(&assembled(0, &pattern(0x44, 64))).err(),
            Some(ResumeError::EmptySlotHasFrame { len: 64 }),
            "an empty slot carrying a frame decoded"
        );
        assert_eq!(
            ResumeRecord::decode(&assembled(7, &[])).err(),
            Some(ResumeError::OccupiedSlotHasNoFrame { attempt: 7 }),
            "an attempt carrying no frame decoded"
        );

        let empty = ResumeRecord::decode(&assembled(0, &[])).expect("the empty slot is legal");
        assert!(empty.attempt().is_none());
        let occupied =
            ResumeRecord::decode(&assembled(7, &pattern(0x44, 64))).expect("an attempt is legal");
        assert_eq!(occupied.attempt().map(Attempt::get), Some(7));
    }
    /// **The at-rest layout is pinned against an independently assembled
    /// buffer**, so a record written by an older build still decodes here.
    ///
    /// This exists because binding the attempt to the sealed frame changed which
    /// expressions `encode` reads those two fields from. Nothing else in this
    /// module could have caught a reordering: the round-trip test encodes and
    /// decodes with the *same* field order, so it passes just as happily if two
    /// fields swap, and the length test only counts bytes. Both compare the code
    /// to itself. The expected buffer below is built from the fixture's own
    /// values in the order the module docs specify, which is a second opinion
    /// rather than an echo.
    #[test]
    fn the_at_rest_layout_is_byte_for_byte_what_it_was() {
        let record = populated();

        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(RESUME_MAGIC);
        // **Named constant, NOT `Registry::default_write_suite()`** — that is the
        // expression `encode` itself calls, so using it here would move both
        // sides together and pass through exactly the cross-build event this
        // test's failure message claims to catch. Which suite is `ActiveWrite`
        // is pinned separately by `default_write_suite_is_cnsa_2_0`; if that
        // moves, the at-rest bytes really have changed and this test should say
        // so rather than follow along.
        expected.extend_from_slice(&crate::crypto::suite::CNSA_2_0.id.get().to_be_bytes());
        expected.extend_from_slice(&pattern(0x11, ml_dsa::SK_LEN));
        expected.extend_from_slice(&pattern(0x22, ml_dsa::PK_LEN));
        expected.extend_from_slice(&pattern(0x33, ROOT_KEY_LEN));
        expected.extend_from_slice(&7u32.to_be_bytes()); // attempt
        expected.extend_from_slice(&4u32.to_be_bytes()); // floor generation
        expected.extend_from_slice(&100u64.to_be_bytes()); // floor seq
        expected.extend_from_slice(&ANCHOR.to_be_bytes()); // window anchor
        expected.extend_from_slice(&3u32.to_be_bytes()); // toward_c
        expected.extend_from_slice(&512u64.to_be_bytes()); // frame length prefix
        expected.extend_from_slice(&pattern(0x44, 512)); // the sealed frame

        assert_eq!(
            &record.encode()[..],
            &expected[..],
            "the at-rest layout moved — a record written by an earlier build no longer decodes"
        );
    }

    /// The overflow branch, which nothing else reaches.
    ///
    /// `advance`'s own docs make this the security-relevant half — a wrapped
    /// attempt re-enters numbers the peer has already deduped — and the `fresh`
    /// helpers only ever exercise the `Some` arm. Reachable here because the
    /// test module is a child of the one that owns the private field; a caller
    /// outside the module cannot build this value, which is the point.
    #[test]
    fn an_attempt_at_the_ceiling_refuses_to_advance() {
        assert!(
            Attempt(u32::MAX).advance().is_none(),
            "a wrapped attempt would re-enter numbers the peer has already deduped"
        );
        // Positive control: one below the ceiling still advances, so the
        // assertion above is not passing because `advance` refuses everything.
        let below = Attempt(u32::MAX - 1).advance().expect("must still advance");
        assert_eq!(below.attempt().get(), u32::MAX);
    }

    /// `FreshAttempt::first()` must mint authority for `Attempt::FIRST` and not
    /// for some other number.
    ///
    /// Nothing else pins this: the `fresh` helpers walk `while get() < n`, so
    /// they arrive at `n` whether `first()` starts at 0 or 1, and the error-path
    /// tests assert only variants. Mutating `first()` to `Attempt(0)` passed the
    /// whole suite before this test existed.
    #[test]
    fn the_first_attempt_is_the_first_attempt() {
        assert_eq!(FreshAttempt::first().attempt(), Attempt::FIRST);
        assert_eq!(Attempt::FIRST.get(), 1, "FIRST is 1, not 0");
    }

    /// The two frame accessors describe one value and may not drift apart.
    ///
    /// `sealed()` is new public API with no production caller yet — the re-emit
    /// path it exists for is unbuilt — so without this it is untested surface,
    /// the same complaint #280 records against an unreferenced function.
    #[test]
    fn the_bound_frame_and_the_loose_bytes_agree() {
        let record = populated();
        let sealed = record
            .sealed()
            .expect("the fixture's handshake slot is occupied");
        assert_eq!(Some(sealed.attempt()), record.attempt());
        assert_eq!(Some(sealed.bytes()), record.sealed_re_est());
        // Non-degenerate: the fixture's frame is neither empty nor uniform with
        // anything else asserted here.
        assert_eq!(sealed.bytes().len(), 512);
    }

    /// A9.2's lexicographic rule, in the direction that matters: a generation
    /// bump outranks any sequence under the previous generation.
    #[test]
    fn the_floor_orders_by_generation_before_sequence() {
        let old = SendFloor::new(4, 100);
        let new_generation = SendFloor::new(5, 0);
        assert!(
            new_generation > old,
            "a generation bump read as a rollback — the exact false alarm the qualification exists to prevent"
        );
        assert_eq!(old.advance_to(new_generation), Ok(new_generation));

        // And within one generation it is an ordinary anti-rollback bound.
        assert!(SendFloor::new(4, 101) > old);
        assert_eq!(
            old.advance_to(SendFloor::new(4, 99)),
            Err(ResumeError::FloorWouldRollBack {
                stored: old,
                offered: SendFloor::new(4, 99)
            })
        );
    }

    /// The two guards differ on the one case that separates them, and each is
    /// used where its rule is the true one.
    #[test]
    fn admits_accepts_the_standstill_that_advance_to_refuses() {
        let floor = SendFloor::new(4, 100);

        // The case they disagree on.
        assert!(
            floor.admits(floor),
            "a record rewrite with an unmoved floor was refused"
        );
        assert!(
            floor.advance_to(floor).is_err(),
            "standing still counted as progress"
        );

        // And they agree everywhere else, in both directions — so the
        // difference is exactly the standstill and not a second divergence.
        let later = SendFloor::new(4, 101);
        assert!(floor.admits(later) && floor.advance_to(later).is_ok());
        let earlier = SendFloor::new(4, 99);
        assert!(!floor.admits(earlier) && floor.advance_to(earlier).is_err());
    }

    /// Standing still is not progress, and is refused rather than silently
    /// accepted.
    #[test]
    fn an_unmoved_floor_is_refused() {
        let stored = SendFloor::new(4, 100);
        assert_eq!(
            stored.advance_to(stored),
            Err(ResumeError::FloorWouldRollBack {
                stored,
                offered: stored
            })
        );
    }

    /// An earlier generation never outranks a later one however far its
    /// sequence ran — the half a bare sequence counter gets wrong.
    #[test]
    fn a_high_sequence_under_an_old_generation_does_not_outrank_a_new_one() {
        let new_generation = SendFloor::new(5, 0);
        let old_but_far = SendFloor::new(4, u64::MAX);
        assert!(old_but_far < new_generation);
        assert!(new_generation.advance_to(old_but_far).is_err());
    }

    /// **The write guard does NOT defer to that ordering.** A generation bump
    /// carrying a lower sequence is lexicographically "later" and is still a
    /// rollback of spent sequences against the ratchet as built, so `admits`
    /// refuses it while `Ord` ranks it higher. The two disagreeing here is the
    /// design, not an inconsistency — see `SendFloor::admits`.
    #[test]
    fn a_generation_bump_may_not_smuggle_a_sequence_rollback() {
        let stored = SendFloor::new(4, 100);
        let bumped_but_lower = SendFloor::new(5, 0);

        assert!(
            bumped_but_lower > stored,
            "the ordering is no longer lexicographic, so this pins nothing"
        );
        assert!(
            !stored.admits(bumped_but_lower),
            "a generation bump smuggled a sequence rollback past the write guard"
        );
        // A bump that also carries the sequence forward is fine — the guard
        // refuses the rollback, not the bump.
        assert!(stored.admits(SendFloor::new(5, 100)));
        assert!(stored.admits(SendFloor::new(5, 101)));
    }

    /// The store's bucket holds the worst case this module can produce. Sized
    /// against `MAX_ENCODED_LEN` rather than against a typical record, so a
    /// field added here fails this test instead of failing a write on a disk.
    #[test]
    fn the_capacity_holds_the_worst_case() {
        // The bucket relationship itself is a `const` assertion in `dm_store`,
        // where both constants live and where the build can enforce it. What is
        // genuinely a runtime fact, and all this test asserts, is that the bound
        // is REAL rather than generous: a record actually built at the frame
        // ceiling encodes to exactly it.
        let at_ceiling = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            Some(
                SealedReEst::seal(
                    FreshAttempt::first(),
                    pattern(0x44, MAX_FRAME_LEN).into_boxed_slice(),
                )
                .expect("a frame of exactly MAX_FRAME_LEN is allowed"),
            ),
            SendFloor::new(0, 0),
            ANCHOR,
            0,
        );
        assert_eq!(at_ceiling.encode().len(), MAX_ENCODED_LEN);
    }

    /// The ceiling moved from `ResumeRecord::new` to `SealedReEst::seal` when the
    /// frame and its attempt became one value — so a sealed frame is now proof
    /// the length was checked, and the record constructor has nothing left to
    /// refuse. Same invariant, enforced one layer earlier.
    #[test]
    fn an_oversized_frame_is_refused_at_sealing_and_at_decode() {
        let too_long = MAX_FRAME_LEN + 1;
        assert_eq!(
            SealedReEst::seal(
                FreshAttempt::first(),
                pattern(0x44, too_long).into_boxed_slice(),
            )
            .err(),
            Some(ResumeError::FrameTooLong { len: too_long })
        );

        // And a frame of exactly the ceiling still seals — without this the
        // assertion above would pass just as well against an off-by-one that
        // refused everything.
        assert!(
            SealedReEst::seal(
                FreshAttempt::first(),
                pattern(0x44, MAX_FRAME_LEN).into_boxed_slice(),
            )
            .is_ok(),
            "positive control: the ceiling itself must still be sealable"
        );

        // The decoder cannot lean on the constructor, because the bytes it reads
        // did not come through it. A corrupt length is refused BEFORE anything
        // is reserved, so it cannot drive an allocation.
        let mut bytes = populated().encode();
        let len_at = FIXED_LEN - 8;
        bytes[len_at..len_at + 8].copy_from_slice(&(too_long as u64).to_be_bytes());
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::FrameTooLong { len: too_long })
        );
    }

    #[test]
    fn the_decoder_refuses_malformed_records() {
        let good = populated().encode();
        assert!(ResumeRecord::decode(&good).is_ok(), "positive control");

        let mut alien = good.clone();
        alien[0] ^= 1;
        assert_eq!(
            ResumeRecord::decode(&alien).err(),
            Some(ResumeError::BadMagic)
        );

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            ResumeRecord::decode(&trailing).err(),
            Some(ResumeError::TrailingBytes(1))
        );

        // Every prefix ends inside a field. Truncation is the one failure a
        // reader cannot detect by looking at a single field, so it is checked
        // exhaustively rather than at a sampled offset.
        for cut in 0..good.len() {
            assert!(
                ResumeRecord::decode(&good[..cut]).is_err(),
                "a record truncated at {cut} decoded"
            );
        }
    }

    /// One `debug!(?record)` must not put a signing key or a root in a log.
    #[test]
    fn debug_redacts_both_secret_halves() {
        let record = populated();
        let shown = format!("{record:?}");
        // **Named per field, not a bare substring search.** An earlier version
        // asserted only that the output contained `<redacted>` somewhere — which
        // `CommittedRoot(<redacted>)` satisfies on its own, so it said nothing
        // whatever about `s_pc`. A review mutation printing the signing key
        // verbatim passed the whole test.
        assert!(
            shown.contains(r#"s_pc: "<redacted>""#),
            "the signing key field is not redacted: {shown}"
        );
        assert!(
            shown.contains("committed_root: CommittedRoot(<redacted>)"),
            "the committed root field is not redacted: {shown}"
        );
        // Positive control: the non-secret fields ARE shown, so the assertions
        // above are not passing because `Debug` prints nothing useful.
        assert!(shown.contains("attempt: 7"), "Debug shows nothing at all");
        // `sealed_re_est_len` became `bytes_len` when the frame and its attempt
        // became one value — the field this names moved, the control it provides
        // did not. It still fails if `Debug` stops rendering the frame's length.
        assert!(
            shown.contains("bytes_len: 512"),
            "the sealed frame's length is not shown: {shown}"
        );
        // **The two assertions above now render out of ONE nested field**, where
        // they used to be two independent ones — so on their own they no longer
        // notice `ResumeRecord::Debug` dropping the rest of the record. The
        // remaining non-secret fields are named explicitly to restore that span.
        for field in ["toward_c: 3", "window_anchor_ms:", "send_floor:"] {
            assert!(
                shown.contains(field),
                "Debug stopped rendering {field}: {shown}"
            );
        }

        // **The byte backstop is format-agnostic, because the previous one was
        // not.** It matched lowercase hex only, while Rust's derived `Debug` for
        // `[u8; N]` prints DECIMAL — so it missed exactly the rendering the
        // compiler emits by default, which is the one a mistake would produce.
        let head = &record.s_pc()[..8];
        for rendering in [
            head.iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            head.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            head.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        ] {
            assert!(
                !shown.contains(&rendering),
                "the signing key's bytes reached the Debug output as {rendering}"
            );
        }
    }

    /// The suite id is validated, not merely read past. Deleting the check
    /// outright was invisible to the suite until these two cases existed.
    #[test]
    fn a_record_naming_an_unusable_suite_is_refused() {
        let at = RESUME_MAGIC.len();

        let mut sentinel = populated().encode().to_vec();
        sentinel[at..at + SUITE_ID_LEN].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            matches!(
                ResumeRecord::decode(&sentinel),
                Err(ResumeError::SuiteIdSentinel(_))
            ),
            "a reserved sentinel suite id was accepted"
        );

        // A well-formed id this build's registry does not know — a record from a
        // build whose primitives we do not implement.
        let mut unknown = populated().encode().to_vec();
        // NOT `u16::MAX`: that is the reserved SENTINEL_MAX and would take the
        // branch above instead, which is how the first draft of this test passed
        // its sentinel case and failed its unknown one.
        unknown[at..at + SUITE_ID_LEN].copy_from_slice(&0xFFFEu16.to_be_bytes());
        assert!(
            matches!(
                ResumeRecord::decode(&unknown),
                Err(ResumeError::UnknownSuite(_))
            ),
            "an unregistered suite id was accepted"
        );

        // Positive control: the same bytes with the suite untouched decode.
        assert!(ResumeRecord::decode(&populated().encode()).is_ok());
    }
}
