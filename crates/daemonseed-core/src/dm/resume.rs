//! The re-establishment resume record: everything a reconnect needs that a
//! restart would otherwise destroy (A9.2, part of ISC-C39 / ISC-A-C21).
//!
//! Design of record: `docs/design/direct-messaging.md`, **Amendment A9**
//! (RATIFIED 2026-07-30), § A9.2 in particular, plus § A4.8's enumeration of
//! what the record carries and the store's atomicity contract in § A8.2.
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
//! ## Two handshake slots, not one
//!
//! A3.14 gives the record *"two handshake slots, own-initiation and
//! peer-acceptance, always present and fixed-size"*, and A3.4 gives the reason:
//! *"a party's own initiation does not consume the generation for
//! acceptance"*. A party holding an initiation at the same generation as an
//! incoming `RE-EST` is in a contest, and A3.7's coin decides which of the two
//! frames survives — a decision one slot could not hold, because it would have
//! had to overwrite one of them to store the other.
//!
//! Each slot stores the sealed leg it holds, and for the same reason: the
//! `RE-EST` because A9.1(a) re-emits the persisted bytes, the `RE-ACK` because
//! A3.4 re-serves the stored answer *"byte-identical"*. Neither is
//! reconstructible — both legs carry randomized ML-KEM material.
//!
//! The acceptance slot also carries A5.1(ii)'s confirmation lock. Held in
//! memory it would reset on the restart this record exists to survive, and a
//! returning peer's stale attempt would then supersede a candidate both sides
//! had already agreed on. [`crate::dm::reest::ReEstGate::from_record`] builds
//! its in-session gate from this slot rather than from nothing.
//!
//! ## The window is anchored on an attempt number, never on a clock
//!
//! A7.3 persists `attempt_at_window_start` and derives *"attempts this window"*
//! as `attempt − attempt_at_window_start`, so the toward-`C` count is arithmetic
//! over two durable numbers rather than a third number a crash could leave
//! disagreeing with them. A8.2 then makes the window's rollover *"an idempotent
//! derivation from durable `last_seen` … recomputed at load"*, and `last_seen`
//! is itself derived — the acceptance slot's attempt is the highest this
//! direction has opened.
//!
//! What that buys is the one thing a time anchor could not: a window rolls over
//! only when the peer has actually opened one of this window's attempts, so a
//! sender's `attempt` can never run more than `C` ahead of the receiver's
//! `last_seen`, and A8.1's `MAX_GAP = C` scan window is wide enough by
//! construction. [`crate::dm::reest::AttemptBudget`] is that arithmetic.
//!
//! ## The dedup memory lives exactly as long as the retained root
//!
//! A5.3's processed-frame memory is durable — *"a lost entry is a torn security
//! invariant"* — and retention-scoped, *"gated on **actual** `RS_n` retirement,
//! not a fixed 14-day duration"*. So the retained `RS_n`, its write-once
//! `superseded_at_ms` and the memory travel as one group, and
//! [`ResumeRecord::retire_retained`] ends all of it in one act. There is no call
//! that empties the memory while the root that makes its frames openable is
//! still held.
//!
//! ## Four things A5.4 names that are deliberately not here
//!
//! A5.4's paragraph on the resume record is a list of what the *design* homes
//! in one durable place, and four of its entries have a different home in this
//! build. Each is recorded because a reader checking the list against the
//! struct will find them missing and needs the reason rather than a gap.
//!
//! | absent | where it lives, and why |
//! |---|---|
//! | `previously_established` | Nowhere. Its only reader (A3.8) asks *"is `RS` absent or unreadable **while `previously_established` is set**"*, which is a question about a correspondence whose resume record it cannot read — so a flag inside that record could never answer it. The presence of the record is the fact, and `dm::persist`'s restart path reads it that way. |
//! | the peer's `PK_lt` and cached EK | The contact record ([`crate::dm::contact_cache`]), which is the same blob discipline in the same store. Both are properties of the correspondent rather than of a re-establishment attempt, so they outlive every attempt and are read without one (A3.14). |
//! | the clear ratchet-generation continuity counter | The outbox. A4.8 moved it there explicitly and gives the reason: it is *"a per-turn counter and persisting it only at a reconnect boundary produces the backwards jump"*, so it rides the same per-send write as `next_send_seq`. |
//! | the receive-side peer high-water | The ratchet, in RAM — see the table below, which is A9.2's own separation. |
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
//! [`ResumeRecord`] holds bytes and orders integers. It seals nothing, reads no
//! clock and encapsulates nothing: [`ResumeRecord::encode`] is plaintext, and
//! `dm_store` seals it, pads it to the kind's fixed bucket and refuses an
//! oversized payload — the same split [`crate::dm::outbox`] uses.
//!
//! [`reroot`] is the one derivation here, and it sits beside the record rather
//! than in [`crate::dm::ratchet`] because its subject is the **retained** root:
//! it consumes the value this record stores and produces the value that
//! replaces it, so putting it with the running ratchet's roots would invite a
//! caller to advance the wrong one. It still encapsulates nothing — the fresh
//! secret arrives as an argument, from [`crate::dm::reest`].

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use oxicrypt_kdf::HkdfSha384;

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError};
use crate::dm::domain;
use crate::dm::frame::MAX_FRAME_LEN;
use crate::dm::ratchet::{Direction, ROOT_KEY_LEN};
use crate::secret_seed::redacted_secret_newtype;
use std::num::NonZeroU32;

use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;

/// At-rest magic. The version is **inside** it, so a decoder compares one thing
/// and cannot read an older body under a newer header — the shape
/// [`crate::dm::outbox`] and [`crate::dm::provisional`] both use.
///
/// **The v2 body was extended in place by the own slot's `seq`, rather than by
/// a v3.** v2 has never been written by a released build, so no record of that
/// layout exists to be read: a version bump would add a decoder arm for a
/// population of zero, and `RESUME_MAGIC_V1`'s note gives the argument for why
/// this module refuses predecessors rather than migrating them. The field order
/// is `… own slot attempt · own slot seq · ephemeral key present …`, pinned by
/// `the_at_rest_layout_is_byte_for_byte_what_it_was`.
pub const RESUME_MAGIC: &[u8] = b"daemonseed/dm/resume/v2\0";

/// The v1 magic, which [`ResumeRecord::decode`] recognises **only in order to
/// refuse it by name**, with [`ResumeError::ObsoleteV1Layout`].
///
/// v2 widened the body by the own slot's ephemeral decapsulation key, its
/// presence flag, and the re-rooted ratchet generation. A v1 body read under
/// this layout runs out of bytes and reports [`ResumeError::Truncated`], which
/// names the wrong fault and hides that the record is simply older — and the
/// two fields it lacks are not defaultable in the direction that matters: an
/// occupied own slot with no ephemeral key is precisely the state
/// [`ResumeError::OccupiedSlotHasNoEphemeralKey`] exists to refuse, because such
/// an initiation re-emits for ever and can never be completed.
///
/// [`crate::dm::outbox`] reads its own predecessors instead of refusing them.
/// The difference is what the missing field is: an outbox's new fields have a
/// truthful zero (nothing sent, the first chain), and this one's does not.
pub const RESUME_MAGIC_V1: &[u8] = b"daemonseed/dm/resume/v1\0";

/// Width of the suite-id field, big-endian, immediately after the magic.
pub const SUITE_ID_LEN: usize = 2;

/// The most a stored `RE-ACK` may measure.
///
/// A `RE-ACK` is a re-establishment leg, and every leg is one fixed length —
/// `daemonseed_core::dm::reest::LEG_LEN`. That constant cannot be named here,
/// because `reest` reads this module and a dependency the other way would be a
/// cycle; `reest` asserts at compile time that `LEG_LEN` fits inside this
/// number, so the two cannot drift apart without failing the build.
///
/// [`MAX_FRAME_LEN`] would be the wrong bound: it is four times a leg, and two
/// slots sized against it do not fit
/// [`crate::storage::dm_store::RESUME_CAPACITY`].
pub const MAX_SEALED_LEG_LEN: usize = 8_320;

/// How many processed-handshake-frame keys the A5.3 dedup memory holds.
///
/// **Sized against the scan window, not against a re-initiation window**, and
/// the difference is what makes the bound reachable. A5.3 scopes the memory to
/// `RS_n`'s whole retention, and the window anchor rolls over *inside* that
/// retention (A6.1), so the number of attempts a retained root sees is not `C`
/// — it is `C` per window for as many windows as the peer keeps answering. A
/// set sized at one window's worth fills, and refusing a legitimate handshake
/// frame is an outcome the design does not have (A3.15: every row recovering or
/// loud).
///
/// What bounds it instead is the eviction [`ResumeRecord::observe_accepted`]
/// performs when A6.1's window base moves, whose derivation is A5.3's own
/// applied to the other thing that makes a frame unopenable. A5.3 evicts at retirement because *"once retired, a
/// superseded-root frame cannot open and cannot alarm regardless"*; A5.2 says
/// the receiver *"trial-decrypts over a bounded `attempt` window
/// `[last_seen, last_seen + MAX_GAP]`, **rejecting anything beyond**"*, and
/// A6.1 slides `last_seen` forward on observed attempts. So an entry whose
/// attempt has fallen below its leg's window base names a frame the scan now
/// rejects before any novelty question arises: it cannot open, so it cannot
/// alarm, so it needs no memory.
///
/// What survives eviction is therefore one window per leg, on one plane:
/// `3 × (MAX_GAP + 1)`. `reest` asserts that product against this constant at
/// compile time, the same way it does for [`MAX_SEALED_LEG_LEN`], so widening
/// the scan window cannot silently outgrow the set.
///
/// **One plane, not two, and [`DedupMemory`] enforces it.** This memory records
/// frames that were *processed* — A5.3 calls it a *"receive-side memory"* of
/// *"processed-handshake-frame"* positions, and A4.5's predicate governs whether
/// an opened frame *"causes a state transition"*. A party opens only what
/// arrives, and everything that arrives is read from the one plane the
/// correspondent writes; a party never processes a frame it sealed itself. So
/// the direction in the key identifies the plane rather than selecting between
/// two populations, and [`DedupMemory::insert`] refuses a second one.
pub const DEDUP_CAPACITY: usize = 27;

/// Bytes one [`DedupKey`] occupies at rest: generation, attempt, leg,
/// direction, sequence.
const DEDUP_ENTRY_LEN: usize = 4 + 4 + 1 + 1 + 8;

/// Every fixed-width field of the encoding, in order, so the worst case below
/// is arithmetic rather than a guess.
const FIXED_LEN: usize = RESUME_MAGIC.len()
    + SUITE_ID_LEN
    + ml_dsa::SK_LEN /* s_pc */
    + ml_dsa::PK_LEN /* pk_pc */
    + ROOT_KEY_LEN /* committed_root */
    + 4 /* reconnect_gen */
    + 4 /* attempt */
    + 4 /* own slot generation */
    + 4 /* own slot attempt */
    + 8 /* own slot seq */
    + 1 /* own slot ephemeral decapsulation key present */
    + ml_kem::DK_LEN /* own slot ephemeral decapsulation key */
    + 4 /* acceptance slot generation */
    + 4 /* acceptance slot attempt */
    + 1 /* acceptance slot confirmed */
    + 1 /* retained RS_n present */
    + ROOT_KEY_LEN /* retained RS_n */
    + 8 /* superseded_at_ms */
    + 4 /* send_floor.generation */
    + 8 /* send_floor.seq */
    + 4 /* attempt_at_window_start */
    + 4 /* reroot_ratchet_gen */
    + 4 /* last_seen_re_est */
    + 1 /* retained_but_stopped */
    + 2 /* dedup entry count */
    + 8 /* sealed RE-EST length prefix */
    + 8 /* sealed RE-ACK length prefix */;

/// The largest [`ResumeRecord::encode`] output this build can produce.
///
/// **Computed, not estimated.** Three fields are variable-width and each has a
/// ceiling the encoder cannot exceed and the decoder re-checks before it
/// allocates: the own slot's sealed `RE-EST` at [`MAX_FRAME_LEN`]
/// ([`SealedReEst::seal`] refuses more), the acceptance slot's sealed `RE-ACK`
/// at [`MAX_SEALED_LEG_LEN`] ([`AcceptanceSlot::accept`] refuses more), and the
/// dedup memory at [`DEDUP_CAPACITY`] entries ([`DedupMemory::insert`] refuses
/// more). [`crate::storage::dm_store::RESUME_CAPACITY`] is sized against the
/// sum, and `the_capacity_holds_the_worst_case` pins the relationship in the
/// direction that matters: if a field is added here and the constant is not
/// revisited, that test fails rather than a write failing on a user's disk.
pub const MAX_ENCODED_LEN: usize =
    FIXED_LEN + MAX_FRAME_LEN + MAX_SEALED_LEG_LEN + DEDUP_CAPACITY * DEDUP_ENTRY_LEN;

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
    /// An empty own-initiation slot carrying a non-zero sequence position.
    ///
    /// Sequence 0 is a real outbox position, so the field cannot spell its own
    /// absence; [`ResumeRecord::encode`] writes zero beside an empty slot and a
    /// record carrying anything else was written by something else.
    EmptySlotHasSequence { seq: u64 },
    /// [`ResumeRecord::open_attempt`] on a record whose own-initiation slot is
    /// already occupied.
    ///
    /// A9.1(a) makes a re-emit of a persisted attempt the byte-identical stored
    /// seal, so a party holding an initiation has nothing to seal: the bytes it
    /// owes the wire are in the slot. Overwriting the slot would publish a
    /// second encapsulation key for one logical attempt while the peer, which
    /// dedups on `attempt` (A9.4), answers the first — and the two sides then
    /// hold roots that never agree.
    AttemptAlreadyOpen { attempt: u32 },
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
    /// An occupied own-initiation slot replaced by an empty one with neither of
    /// the two acts that legitimately empty it.
    ///
    /// A3.7's abandonment is *"abandonment and acceptance committed together,
    /// intra-record"* at an unchanged generation — recognised by an acceptance
    /// slot newly occupying the generation the abandoned initiation was
    /// contesting. A3.14's completion advances `reconnect_gen` in the same
    /// write. Anything else is an initiation that simply disappeared, leaving
    /// this side believing it has a handshake in flight that no record holds.
    OwnSlotAbandonedWithoutAcceptance { attempt: u32 },
    /// A record whose `attempt` counter is **zero** offered against a stored one
    /// carrying a real attempt.
    ///
    /// The empty slot is what first establishment writes, so this is a first
    /// establishment arriving after a re-establishment has been persisted. It is
    /// [`Self::AttemptWouldRollBack`]'s case for the slot that has no number —
    /// separate rather than reported as `offered: 0`, because no [`Attempt`] is
    /// ever `0` and a log line saying so names a value that cannot exist.
    ///
    /// **The generation qualifier is the whole guard.** A3.14 zeroes the own
    /// slot on completion — a folded `RE-ACK`, or the abandonment a lost coin
    /// forces (A3.7) — and a completed handshake is exactly what advances
    /// `reconnect_gen` (A3.4). So an empty slot replacing an occupied one is the
    /// *normal* end of a re-establishment when the generation moved with it, and
    /// refusing that write would make completion unpersistable. Only an empty
    /// slot at an unchanged generation is a regression, and that is what this
    /// names.
    EmptySlotWouldReplaceAttempt { stored: u32 },
    /// A `reconnect_gen` behind the stored one. A3.4: generations advance only
    /// by a completed handshake and are strictly monotonic, so a record offering
    /// an earlier one describes a state this correspondence has already left.
    ReconnectGenWouldRollBack { stored: u32, offered: u32 },
    /// A peer-acceptance slot offered at a generation behind the stored one, or
    /// at the same generation under an earlier attempt.
    ///
    /// A5.1(i) admits a *higher* attempt superseding an unconfirmed candidate
    /// and A3.4 drops a lower one, so a stored acceptance never moves backwards.
    AcceptanceWouldRollBack {
        stored_generation: u32,
        stored_attempt: u32,
        offered_generation: u32,
        offered_attempt: u32,
    },
    /// A peer-acceptance slot at the stored `(generation, attempt)` carrying
    /// **different** sealed `RE-ACK` bytes.
    ///
    /// A3.4 answers a byte-identical replay by re-serving *the stored*
    /// `RE-ACK` — *"the stored `RE-ACK` is re-served, byte-identical — safe
    /// because it is the same frame"*. Those bytes are the only copy there is:
    /// ML-KEM encapsulation is randomized, so a re-serve cannot re-derive them.
    /// Replacing them under one accepted pair would send the peer a second,
    /// different answer to one question, and the peer dedups on the attempt
    /// (A9.4) and so confirms the first — the divergence to permanent
    /// `UnknownEphemeral` ([`crate::dm::ratchet`]) that A9.1 forbids, reached
    /// from the answering side.
    AcceptanceResealed { generation: u32, attempt: u32 },
    /// A record clearing or moving a **confirmed** peer-acceptance slot without
    /// advancing `reconnect_gen`.
    ///
    /// A5.1(ii): a confirmed candidate *"is locked, and a later-arriving
    /// lower-or-stale attempt's `RE-EST` never supersedes it"*. The lock is
    /// durable, so it survives the restart that would otherwise reset it, and
    /// the one write that legitimately ends it is the generation advance that
    /// retires the whole exchange.
    ConfirmedAcceptanceCleared { generation: u32, attempt: u32 },
    /// A record offering an earlier `RE-EST` window base than the stored one.
    ///
    /// A6.1 has the window *"slide with observed traffic"*, forward only. The
    /// base is what both the record's eviction and the store's no-shrink rule
    /// read to decide which dedup positions still matter, so a base that could
    /// regress would let a later write re-admit frames an earlier one had put
    /// out of reach.
    ReEstBaseWouldRegress { stored: u32, offered: u32 },
    /// A second `superseded_at_ms` offered for a retained `RS_n` already
    /// carrying one.
    ///
    /// A5.4 stamps it *"write-once at the first supersede so `T_RETIRE` cannot
    /// slide forward per re-attempt"*. Re-stamping would extend the window a
    /// stale copy of the superseded root enjoys, one re-attempt at a time, with
    /// nothing reporting that the ceiling had moved.
    SupersededStampMoved { stored: i64, offered: i64 },
    /// A dedup position offered on a different plane from the one the memory
    /// already holds.
    ///
    /// A5.3's memory is receive-side: every position in it was read from the
    /// plane the correspondent writes, and a party never processes a frame it
    /// sealed itself. A second direction would file our own attempt numbers in a
    /// set bounded by the peer's window base.
    DedupDirectionMixed,
    /// A record dropping dedup entries while the `RS_n` they are scoped to is
    /// still retained.
    ///
    /// A5.3 ties eviction to *"**actual** `RS_n` retirement, not a fixed 14-day
    /// duration"*, because byte-novelty is what stops a co-host re-serving
    /// captured `RE-EST` bytes to re-fire the peer-state-regressed alarm — and
    /// that defence is live for exactly as long as the retained root can open
    /// those bytes. [`ResumeRecord::retire_retained`] is the one act that drops
    /// both together.
    DedupEvictedWhileRetained { stored: usize, offered: usize },
    /// More dedup entries than [`DEDUP_CAPACITY`], at rest or offered to
    /// [`DedupMemory::insert`].
    DedupFull { capacity: usize },
    /// At-rest bytes whose leg discriminator names no [`Leg`].
    UnknownLeg(u8),
    /// At-rest bytes whose direction discriminator names no
    /// [`Direction`].
    UnknownDirection(u8),
    /// At-rest bytes spelling an empty peer-acceptance slot — attempt `0` —
    /// beside a non-empty sealed `RE-ACK` or a set confirmation flag.
    ///
    /// The halves contradict each other the way [`Self::EmptySlotHasFrame`]'s do
    /// for the own slot, and are refused for the same reason: either could be
    /// the true one and nothing here can say which. A confirmation flag with no
    /// slot under it would be the worse repair of the two, since a confirmation
    /// that names no attempt locks a generation against every attempt.
    EmptyAcceptanceHasContent { frame_len: usize, confirmed: bool },
    /// The mirror: at-rest bytes spelling a real acceptance attempt beside a
    /// zero-length sealed `RE-ACK`.
    ///
    /// An acceptance slot exists to hold the bytes a re-serve sends, so one
    /// without them would re-serve an empty frame.
    AcceptanceHasNoFrame { attempt: u32 },
    /// A sealed frame of zero length offered to [`SealedReEst::seal`] or
    /// [`AcceptanceSlot::accept`].
    ///
    /// An occupied slot's whole purpose is to hold bytes a re-emit or a re-serve
    /// sends, so a slot holding none would emit an empty frame. Refused at
    /// construction rather than only at decode: an empty frame beside a real
    /// attempt encodes without complaint, and the record it produces then fails
    /// [`ResumeRecord::decode`] for ever — which wedges
    /// [`commit_resume`](crate::dm::persist::DmPersist::commit_resume)
    /// permanently, since every later write reads the stored record first.
    EmptyFrame,
    /// An own-initiation slot whose attempt disagrees with the record's own
    /// `attempt` counter.
    ///
    /// A9.2 lists *"the `attempt` counter"* and *"the sealed `RE-EST` frame
    /// bytes"* as separate fields, and the slot's copy of the number is bound to
    /// the bytes for the byte-identical re-emit (A9.1(a)). They are written in
    /// one atomic act (A8.1: commit-then-emit persists both before any
    /// emission), so they agree or the record is one no honest writer produced.
    AttemptSlotDisagrees { field: u32, slot: u32 },
    /// At-rest bytes carrying a generation for a slot standing empty.
    ///
    /// An empty slot is attempt `0`, a zero-length frame and a zero generation:
    /// there is no exchange for a generation to name. Refused rather than
    /// ignored, because a generation read back out of an empty slot would be a
    /// value nothing wrote and nothing checks.
    SlotGenerationWithoutAttempt { generation: u32 },
    /// At-rest bytes carrying retained-root bytes beside a clear presence flag.
    ///
    /// [`ResumeRecord::encode`] writes the absent case as an all-zero root, so
    /// non-zero bytes under a clear flag are a record this encoder did not
    /// write — a retained root the flag hides, or a flag the bytes contradict.
    RetainedBytesWithoutFlag,
    /// The same dedup position twice in one record's at-rest bytes.
    ///
    /// Accepting it would decode to a set one entry smaller than the bytes hold,
    /// so the record would re-encode to different bytes than it was read from —
    /// and the length the eviction bound is checked against would disagree with
    /// what is on disk.
    DuplicateDedupEntry,
    /// At-rest bytes carrying a `superseded_at_ms` for a retained `RS_n` that is
    /// absent, or a retained `RS_n` with no stamp.
    ///
    /// The stamp is what bounds the retention (A3.5's `T_RETIRE` runs from it),
    /// so a root without one has no ceiling and a stamp without a root bounds
    /// nothing.
    RetentionHalfPresent { present: bool },
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
    /// An occupied own slot whose stored ephemeral decapsulation key is absent.
    ///
    /// The slot's sealed `RE-EST` is re-emitted byte-identically after a crash
    /// (`docs/design/direct-messaging.md:1351`), which publishes an
    /// encapsulation key this party must still be able to decapsulate against.
    /// Loading the frame without its key would produce an initiation that can be
    /// re-sent for ever and can never be completed.
    OccupiedSlotHasNoEphemeralKey { attempt: u32 },
    /// An empty own slot carrying an ephemeral decapsulation key.
    ///
    /// The mirror of [`Self::OccupiedSlotHasNoEphemeralKey`], and refused for
    /// the reason [`Self::EmptySlotHasFrame`] is: [`ResumeRecord::encode`]
    /// writes the empty slot as a clear flag over an all-zero key, so these are
    /// bytes it did not write.
    EphemeralKeyWithoutSlot,
    /// A record in the superseded [`RESUME_MAGIC_V1`] layout.
    ///
    /// Named rather than reported as [`Self::Truncated`], which is what a v1
    /// body decoded under the v2 layout would otherwise produce: the record is
    /// intact and simply predates two fields, one of which has no truthful
    /// default. See [`RESUME_MAGIC_V1`].
    ObsoleteV1Layout,
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
            Self::AttemptAlreadyOpen { attempt } => {
                write!(f, "attempt {attempt} is still in flight")
            }
            Self::EmptySlotHasSequence { seq } => {
                write!(f, "an empty handshake slot names sequence {seq}")
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
            Self::OccupiedSlotHasNoEphemeralKey { attempt } => write!(
                f,
                "attempt {attempt} carries no ephemeral decapsulation key"
            ),
            Self::EphemeralKeyWithoutSlot => write!(
                f,
                "an empty handshake slot carries an ephemeral decapsulation key"
            ),
            Self::ObsoleteV1Layout => write!(
                f,
                "a resume record in the superseded daemonseed/dm/resume/v1 layout, which \
                 carries neither the own slot's ephemeral decapsulation key nor the \
                 re-rooted ratchet generation"
            ),
            Self::OwnSlotAbandonedWithoutAcceptance { attempt } => write!(
                f,
                "the initiation at attempt {attempt} was abandoned with no acceptance \
                 in its place and no generation advance"
            ),
            Self::EmptySlotWouldReplaceAttempt { stored } => write!(
                f,
                "a record with no re-establishment is behind the stored attempt {stored} \
                 at an unchanged generation"
            ),
            Self::ReconnectGenWouldRollBack { stored, offered } => write!(
                f,
                "reconnect generation {offered} is behind the stored {stored}"
            ),
            Self::AcceptanceWouldRollBack {
                stored_generation,
                stored_attempt,
                offered_generation,
                offered_attempt,
            } => write!(
                f,
                "accepted {offered_generation}:{offered_attempt} is behind the stored \
                 {stored_generation}:{stored_attempt}"
            ),
            Self::AcceptanceResealed {
                generation,
                attempt,
            } => write!(
                f,
                "accepted {generation}:{attempt} is already persisted under different \
                 sealed bytes"
            ),
            Self::ConfirmedAcceptanceCleared {
                generation,
                attempt,
            } => write!(
                f,
                "the confirmed acceptance {generation}:{attempt} may only be cleared by a \
                 generation advance"
            ),
            Self::ReEstBaseWouldRegress { stored, offered } => write!(
                f,
                "the re-establishment window base {offered} is behind the stored {stored}"
            ),
            Self::SupersededStampMoved { stored, offered } => write!(
                f,
                "the retained root was superseded at {stored} and may not be re-stamped at \
                 {offered}"
            ),
            Self::DedupEvictedWhileRetained { stored, offered } => write!(
                f,
                "{offered} dedup entries offered against {stored} stored while the \
                 superseded root is still retained"
            ),
            Self::DedupDirectionMixed => write!(
                f,
                "the dedup memory holds one plane and this position is on the other"
            ),
            Self::DedupFull { capacity } => {
                write!(f, "the dedup memory holds at most {capacity} entries")
            }
            Self::UnknownLeg(tag) => write!(f, "{tag} names no re-establishment leg"),
            Self::UnknownDirection(tag) => write!(f, "{tag} names no direction"),
            Self::EmptyAcceptanceHasContent {
                frame_len,
                confirmed,
            } => write!(
                f,
                "an empty acceptance slot carries {frame_len} bytes of sealed frame and \
                 confirmed={confirmed}"
            ),
            Self::AcceptanceHasNoFrame { attempt } => {
                write!(f, "accepted attempt {attempt} carries no sealed frame")
            }
            Self::EmptyFrame => write!(f, "a handshake slot may not hold an empty frame"),
            Self::AttemptSlotDisagrees { field, slot } => write!(
                f,
                "the attempt counter is {field} and its sealed slot names {slot}"
            ),
            Self::SlotGenerationWithoutAttempt { generation } => {
                write!(f, "an empty handshake slot names generation {generation}")
            }
            Self::RetainedBytesWithoutFlag => write!(
                f,
                "retained root bytes are present beside a clear retention flag"
            ),
            Self::DuplicateDedupEntry => {
                write!(f, "the same dedup position appears twice in one record")
            }
            Self::RetentionHalfPresent { present } => write!(
                f,
                "the retained root's presence flag is {present} and its supersede stamp \
                 disagrees"
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
    ///
    /// **Borrowed, not taken by value.** A `[u8; 32]` is `Copy`, so a by-value
    /// parameter leaves the caller holding an unwiped copy of a root on its own
    /// frame — the caller cannot reach an argument temporary to zeroize it.
    /// Borrowing keeps the bytes in whatever the caller already wipes.
    pub fn from_bytes(bytes: &[u8; ROOT_KEY_LEN]) -> Self {
        Self(*bytes)
    }
}

/// What one re-establishment produces: the successor retained root, the ratchet
/// root the resumed channel opens under, and the resumed channel's identifier.
///
/// **All three from one call, or none.** `docs/design/direct-messaging.md:722`
/// and `:724` derive the two roots from the same two inputs, and committing
/// `RS_{n+1}` without holding its `RK_0'` is the state that cannot be recovered
/// from — the retained root has moved on, the secret that produced the ratchet
/// root is gone, and no later call can rebuild it. The channel identifier is
/// bound into every signature and AAD the resumed channel writes, so a party
/// holding the roots without it can derive keys and still seal nothing.
/// [`reroot`] is the only way to make one, so the three cannot be spelled apart.
///
/// **`Clone` is deliberate**: one re-establishment feeds two consumers — the
/// ratchet the resumed channel runs on, and the record the commit writes — and
/// both take the value by value. Cloning duplicates a grouping that is already
/// fixed; it cannot produce a `next` belonging to a different `ratchet_root`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rerooted {
    next: CommittedRoot,
    ratchet_root: crate::dm::ratchet::RootKey,
    chan_id: [u8; ROOT_KEY_LEN],
}

impl Rerooted {
    /// The successor retained root `RS_{n+1}`, which replaces `RS_n` at rest.
    pub fn next(&self) -> &CommittedRoot {
        &self.next
    }

    /// The re-rooted ratchet root `RK_0'`.
    ///
    /// **Crate-private**, so a caller outside the crate holds a re-establishment
    /// result without ever holding the root the resumed channel's message keys
    /// descend from. [`crate::dm::ratchet::Ratchet::reestablished`] is its only
    /// reader.
    pub(crate) fn ratchet_root(&self) -> &crate::dm::ratchet::RootKey {
        &self.ratchet_root
    }

    /// The resumed channel's identifier `chan_id_{n+1}`.
    ///
    /// This is the value a resumed channel's frames bind into the
    /// authorship-signature preimage and the seal AAD, in place of the
    /// `chan_id` establishment deleted. A driver receives it from
    /// [`ResumeRecord::commit_reestablished`], which returns it so the commit
    /// and the identifier cannot be separated, and binds it into every frame on
    /// the resumed channel. **That path is not built**, so nothing outside the
    /// tests reads this accessor yet; the established-channel path binds the
    /// identifier derived at first contact.
    /// [`crate::dm::ratchet::Ratchet`] never holds it either way — a ratchet
    /// binds its conversation by the fingerprint of `AR`, and the identifier is
    /// bound one layer up, where sealing happens.
    pub fn chan_id(&self) -> &[u8; ROOT_KEY_LEN] {
        &self.chan_id
    }
}

impl std::fmt::Debug for Rerooted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rerooted(<redacted>)")
    }
}

/// Advance a retained re-establishment root by a freshly encapsulated secret,
/// yielding the successor root, the ratchet root the resumed channel opens
/// under, and the resumed channel's identifier.
///
/// `docs/design/direct-messaging.md:722` gives the ratchet root as
/// `RK_0' = advance_root(RS_n, ss_new)` — the previous root as extraction salt
/// and the fresh secret as IKM, so a party holding only `RS_n` cannot compute it
/// and a party holding only `ss_new` cannot either. `:724` gives the successor
/// as `RS_{n+1} = Expand(Extract(DM_REEST_SALT, RS_n ‖ ss_new), DM_REEST_NEXT)`,
/// a different extraction over the same two inputs, so neither output yields the
/// other.
///
/// The channel identifier is a **sibling of the successor root**, expanded from
/// that same extraction under [`domain::DM_REEST_CHAN_ID`]:
/// `chan_id_{n+1} = Expand(Extract(DM_REEST_SALT, RS_n ‖ ss_new), DM_REEST_CHAN_ID)`.
/// Establishment deletes the original `chan_id` with `ss0`
/// (`docs/design/direct-messaging.md:710`), so a resumed channel has none to
/// carry forward; deriving it here rather than retaining it keeps the at-rest
/// set to `AR` and `RS_n`.
///
/// Ratcheting the retained root is what stops it being a permanent at-rest
/// credential: without it a single copy of the sealed store would grant
/// channel-resume authority for the life of the correspondence
/// (`docs/design/direct-messaging.md:722`, Clause 1).
///
/// The caller is expected to write `RS_{n+1}` over `RS_n` and destroy the old
/// value; this function only computes.
pub fn reroot(
    previous: &CommittedRoot,
    ss_new: &[u8; ml_kem::SHARED_SECRET_LEN],
) -> Result<Rerooted, crate::dm::ratchet::RatchetError> {
    // The IKM widths are the KEM's and the root's, and they must agree for the
    // concatenation below to be the one the design writes. Stated once, here,
    // rather than by spelling one constant where the other belongs.
    const _: () = assert!(ml_kem::SHARED_SECRET_LEN == ROOT_KEY_LEN);
    // And the identifier's width is the frame layer's, because that is the
    // parameter it is handed to.
    const _: () = assert!(ROOT_KEY_LEN == crate::dm::firstcontact::ROOT_LEN);

    // `advance_root` consumes the root it advances, so a spent root cannot be
    // reused. The bytes are borrowed out of `previous` rather than copied
    // through a temporary this frame could not reach to wipe.
    let previous_key = crate::dm::ratchet::RootKey::from_bytes(previous.as_bytes());
    let ratchet_root = crate::dm::ratchet::advance_root(previous_key, ss_new)?;

    // `RS_n ‖ ss_new` is the extraction IKM, in that order. Zeroizing rather
    // than a bare `Vec`: it holds the retained root in the clear until it is
    // consumed, and a plain buffer would leave it in freed heap.
    let mut ikm = Zeroizing::new(Vec::with_capacity(ROOT_KEY_LEN + ss_new.len()));
    ikm.extend_from_slice(previous.as_bytes());
    ikm.extend_from_slice(ss_new);
    let hkdf = HkdfSha384::extract(Some(domain::DM_REEST_SALT), &ikm)
        .map_err(crate::dm::ratchet::RatchetError::Kdf)?;
    let mut next_bytes = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    hkdf.expand(domain::DM_REEST_NEXT, next_bytes.as_mut())
        .map_err(crate::dm::ratchet::RatchetError::Kdf)?;
    let mut chan_id = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    hkdf.expand(domain::DM_REEST_CHAN_ID, chan_id.as_mut())
        .map_err(crate::dm::ratchet::RatchetError::Kdf)?;

    Ok(Rerooted {
        next: CommittedRoot::from_bytes(&next_bytes),
        ratchet_root,
        // The field is wiped by this struct's own `ZeroizeOnDrop`, so the copy
        // made here is the last one; `chan_id` itself wipes as it leaves scope.
        chan_id: *chan_id,
    })
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
    /// window anchor, a peer acceptance recorded. Refusing an unmoved floor here
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
    /// conservative. If a re-establishment is ever made to restart `seq`,
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

    /// Name an attempt whose non-zero-ness the caller has already established.
    ///
    /// Takes a [`NonZeroU32`] rather than a `u32` returning `Option`, so the
    /// empty-slot spelling — attempt `0`, which orders below every real attempt
    /// — is unrepresentable here instead of being a case every caller has to
    /// remember to reject. [`crate::dm::reest`]'s trial-decryption scan builds
    /// its candidates this way and consequently has no zero branch to leave
    /// dead; its gate stores one of these rather than a bare `u32`.
    ///
    /// Crate-private, and it yields no [`FreshAttempt`]: it names an attempt
    /// without authorising a seal under it, which is why it is not a hole in
    /// A9.1. The authority to seal still comes only from [`Self::advance`] and
    /// [`FreshAttempt::first`].
    pub(crate) const fn from_nonzero(n: NonZeroU32) -> Self {
        Self(n.get())
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
        // Both ends of the range, not just the top. An occupied slot with no
        // bytes encodes without complaint and then fails `decode` for ever,
        // which wedges `commit_resume` — every later write reads the stored
        // record before it writes.
        if bytes.is_empty() {
            return Err(ResumeError::EmptyFrame);
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

/// Our own pending initiation: the generation it acts at, and the sealed
/// `RE-EST` bound to the attempt it was sealed under.
///
/// A3.14 gives the resume record *"two handshake slots, own-initiation and
/// peer-acceptance"*, and A3.4 says why they are two rather than one: *"a
/// party's own initiation does not consume the generation for acceptance"*. A
/// party holding an initiation at the same generation as an incoming `RE-EST`
/// is in a contest (A3.7), which one slot could not express — it would have to
/// overwrite one of the two frames the coin is about to choose between.
///
/// The generation is carried here rather than read off
/// [`ResumeRecord::reconnect_gen`] because they are different numbers: A3.4's
/// `reconnect_gen` advances only *"by a completed handshake"*, so an initiation
/// in flight sits at the generation it is trying to reach, one past the
/// committed one.
///
/// **The slot is zeroed, not edited.** A3.14 has both slots *"zeroed on
/// completion"*: an own slot ends when the `RE-ACK` folds, or when a lost coin
/// abandons it (A3.7), and either way the next record carries `None` here.
///
/// **The ephemeral's secret half travels with the sealed frame**, because the
/// two are useless apart. `docs/design/direct-messaging.md:1351` (A9.1(a)) makes
/// a re-emit of a persisted attempt the byte-identical stored `RE-EST`, so a
/// party that crashes after committing re-emits a leg carrying an encapsulation
/// key whose decapsulation key it must still hold to open the `RE-ACK` that
/// answers it. Minting a fresh keypair on recovery would publish one key and
/// hold another; keeping the key only in memory loses it at exactly the restart
/// this record exists to survive. Either way the answer never opens and the two
/// parties stop on roots that will never agree.
pub struct OwnSlot {
    generation: u32,
    seq: u64,
    sealed: SealedReEst,
    eph_dk: crate::dm::ratchet::EphemeralDecapKey,
}

impl OwnSlot {
    /// Occupy the slot with a sealed initiation at `generation`, and the secret
    /// half of the ephemeral that initiation published.
    ///
    /// The key is taken here rather than by a later setter so an occupied slot
    /// cannot exist without one: the frame and the key that opens its answer are
    /// supplied at the same moment or not at all.
    pub fn new(
        generation: u32,
        seq: u64,
        sealed: SealedReEst,
        eph_dk: crate::dm::ratchet::EphemeralDecapKey,
    ) -> Self {
        Self {
            generation,
            seq,
            sealed,
            eph_dk,
        }
    }

    /// The outbox sequence position the sealed `RE-EST` was addressed to.
    ///
    /// **Stored rather than recomputed, and that is what makes A9.1(a)'s
    /// byte-identical re-emit reachable.** `seq` is bound into the leg's seal
    /// key and into its signature preimage, so a re-emit that guessed a
    /// different position would publish bytes the peer scans at the wrong
    /// address and cannot verify. Recomputing it from the outbox's
    /// `next_send_seq` is not available: a give-up followed by a prune moves
    /// that counter, and the crash this slot exists to survive is exactly the
    /// window in which the enqueue that would have spent the number never
    /// happened.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The secret half of the ephemeral this initiation published — what
    /// [`crate::dm::reest::complete`] decapsulates the `RE-ACK` under.
    pub fn eph_dk(&self) -> &crate::dm::ratchet::EphemeralDecapKey {
        &self.eph_dk
    }

    /// The generation this initiation is trying to reach.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The attempt the frame was sealed under.
    pub fn attempt(&self) -> Attempt {
        self.sealed.attempt()
    }

    /// The sealed frame bound to its attempt — what a re-emit sends.
    pub fn sealed(&self) -> &SealedReEst {
        &self.sealed
    }
}

impl std::fmt::Debug for OwnSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnSlot")
            .field("generation", &self.generation)
            .field("seq", &self.seq)
            .field("sealed", &self.sealed)
            // Renders as `EphemeralDecapKey(<redacted>)`; the newtype makes that
            // decision, and repeating it here would be a second answer free to
            // disagree with it.
            .field("eph_dk", &self.eph_dk)
            .finish()
    }
}

/// The peer initiation we accepted: the generation and attempt it arrived
/// under, the sealed `RE-ACK` we answered it with, and whether the answer has
/// been confirmed.
///
/// **The stored `RE-ACK` bytes are the only copy of that answer.** A3.4 answers
/// a byte-identical replay by re-serving them — *"the stored `RE-ACK` is
/// re-served, byte-identical — safe because it is the same frame"* — and
/// re-deriving them is not available: the leg carries an ML-KEM ciphertext, the
/// encapsulation is randomized, and A9.2 records the same fact about the other
/// leg (*"`ss` → `eph_ct` is not invertible"*). Losing them costs the re-serve,
/// so they are durable state in this blob rather than a cache.
///
/// **`confirmed` is A5.1(ii)'s lock, persisted.** A6.1 says what sets it: *"the
/// first frame that opens under the re-rooted chain — content *or* RE-CONFIRM,
/// whichever arrives — confirms the candidate and ends supersede-eligibility"*.
/// Held only in memory it would reset on the restart this record exists to
/// survive, and a returning peer's stale attempt would then supersede a
/// candidate the two sides had already agreed on, stranding them on different
/// siblings. [`crate::dm::reest::ReEstGate::from_record`] reads it back.
pub struct AcceptanceSlot {
    generation: u32,
    attempt: Attempt,
    sealed_re_ack: Box<[u8]>,
    confirmed: bool,
}

impl AcceptanceSlot {
    /// Accept a peer initiation at `(generation, attempt)`, storing the sealed
    /// `RE-ACK` that answers it.
    ///
    /// Unconfirmed: [`Self::confirm`] is the only way to set the lock, so the
    /// two acts are separate calls and a caller cannot reach the locked state by
    /// filling in a field.
    ///
    /// Refuses a frame past [`MAX_SEALED_LEG_LEN`], which is a leg's length plus
    /// headroom rather than [`MAX_FRAME_LEN`]: two slots sized against the frame
    /// ceiling do not fit [`crate::storage::dm_store::RESUME_CAPACITY`].
    pub fn accept(
        generation: u32,
        attempt: Attempt,
        sealed_re_ack: Box<[u8]>,
    ) -> Result<Self, ResumeError> {
        if sealed_re_ack.len() > MAX_SEALED_LEG_LEN {
            return Err(ResumeError::FrameTooLong {
                len: sealed_re_ack.len(),
            });
        }
        // As [`SealedReEst::seal`]: an accepted attempt with no bytes would
        // re-serve an empty frame, and the record it encodes to never decodes
        // again.
        if sealed_re_ack.is_empty() {
            return Err(ResumeError::EmptyFrame);
        }
        Ok(Self {
            generation,
            attempt,
            sealed_re_ack,
            confirmed: false,
        })
    }

    /// Lock the slot: a frame has opened under the re-rooted chain (A6.1), so
    /// the candidate is confirmed and no differing attempt at this generation
    /// may supersede it (A5.1(ii)).
    ///
    /// Idempotent, and takes `self` by value so a caller cannot hold an
    /// unconfirmed copy of a slot it has just confirmed.
    pub fn confirm(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// The generation this acceptance consumed.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The attempt that was accepted.
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }

    /// The sealed `RE-ACK`, borrowed — the same bytes every call, which is
    /// A3.4's byte-identical re-serve at this layer.
    pub fn sealed_re_ack(&self) -> &[u8] {
        &self.sealed_re_ack
    }

    /// Whether a frame has opened under the re-rooted chain.
    pub fn confirmed(&self) -> bool {
        self.confirmed
    }
}

impl std::fmt::Debug for AcceptanceSlot {
    /// The frame's length rather than its bytes, the judgement
    /// [`SealedReEst`]'s own `Debug` makes for the same reason.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptanceSlot")
            .field("generation", &self.generation)
            .field("attempt", &self.attempt)
            .field("sealed_re_ack_len", &self.sealed_re_ack.len())
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

/// The superseded root a party keeps after committing its successor, with the
/// moment it was superseded.
///
/// A3.5: each party retains `RS_n` *"from its own commit of `RS_{n+1}` until its
/// confirming observation (A3.6) or `T_RETIRE`"*. What the retention buys is the
/// ability to open the peer's frames at the superseded generation — the contest
/// path (A3.7) and the regressed-peer recovery row.
///
/// **`superseded_at_ms` is write-once**, stamped at the *first* supersede (A5.4)
/// *"so `T_RETIRE` cannot slide forward per re-attempt"*. A record that
/// re-stamped it would extend, one re-attempt at a time, exactly the exposure
/// the ceiling exists to bound.
pub struct RetainedRoot {
    root: CommittedRoot,
    superseded_at_ms: i64,
}

impl Zeroize for RetainedRoot {
    /// Written out rather than derived because the stamp is a plain `i64` a
    /// derive would leave alone.
    ///
    /// It is reached through [`Retention`]'s `Option` field: `Option::zeroize`
    /// calls `value.zeroize()` and *then* takes the option, so both halves of
    /// this body run before the payload is dropped. `zeroize` 1.8.2 says why the
    /// take follows rather than replaces it — *"Without the take, the drop of
    /// the (zeroized) value isn't called, which might lead to a leak"*.
    ///
    /// A test at the group level cannot pin this body, because the take leaves
    /// `None` whatever the body did;
    /// `zeroizing_a_retained_root_wipes_its_root_and_its_stamp` calls it
    /// directly for that reason.
    fn zeroize(&mut self) {
        self.root.zeroize();
        self.superseded_at_ms = 0;
    }
}

impl RetainedRoot {
    /// Retain `root`, stamped at the moment it was superseded.
    pub fn new(root: CommittedRoot, superseded_at_ms: i64) -> Self {
        Self {
            root,
            superseded_at_ms,
        }
    }

    /// The retained root.
    pub fn root(&self) -> &CommittedRoot {
        &self.root
    }

    /// When it was superseded, in the caller's clock. Write-once.
    pub fn superseded_at_ms(&self) -> i64 {
        self.superseded_at_ms
    }
}

impl std::fmt::Debug for RetainedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedRoot")
            .field("root", &self.root)
            .field("superseded_at_ms", &self.superseded_at_ms)
            .finish()
    }
}

/// Which of the three re-establishment legs a [`DedupKey`] names.
///
/// Lives here rather than beside the legs themselves because the key is durable
/// state in this record and [`crate::dm::reest`] reads this module — a
/// dependency the other way would be a cycle. The tag bytes are at-rest wire,
/// so `reest` pins the mapping from its own frame-kind constants to these
/// variants in a test rather than leaving two spellings free to drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The returning side's ask.
    ReEst,
    /// The answer carrying the ciphertext.
    ReAck,
    /// The returning side settling the exchange.
    ReConfirm,
}

impl Leg {
    /// The at-rest discriminator. FROZEN — it is inside a durable record.
    const fn tag(self) -> u8 {
        match self {
            Self::ReEst => 1,
            Self::ReAck => 2,
            Self::ReConfirm => 3,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ReEst),
            2 => Some(Self::ReAck),
            3 => Some(Self::ReConfirm),
            _ => None,
        }
    }
}

/// The at-rest discriminator for a direction. FROZEN, for the same reason
/// [`Leg::tag`] is.
const fn direction_tag(dir: Direction) -> u8 {
    match dir {
        Direction::AToB => 1,
        Direction::BToA => 2,
    }
}

const fn direction_from_tag(tag: u8) -> Option<Direction> {
    match tag {
        1 => Some(Direction::AToB),
        2 => Some(Direction::BToA),
        _ => None,
    }
}

/// One position in A5.3's processed-handshake-frame memory:
/// `(gen, attempt, leg, dir, seq)`.
///
/// **`attempt` is load-bearing in the key**, and A5.3 says why in terms: *"two
/// legitimate different-attempt `RE-EST`s share `gen`/`seq` (the AAD is
/// attempt-blind …; only the KDF differs), so a position-only key would collide
/// them and wrongly drop a legitimate frame"*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupKey {
    generation: u32,
    attempt: Attempt,
    leg: Leg,
    direction: Direction,
    seq: u64,
}

impl DedupKey {
    /// Name the position a handshake frame arrived at.
    pub fn new(
        generation: u32,
        attempt: Attempt,
        leg: Leg,
        direction: Direction,
        seq: u64,
    ) -> Self {
        Self {
            generation,
            attempt,
            leg,
            direction,
            seq,
        }
    }

    /// The generation the frame acts at.
    pub fn generation(self) -> u32 {
        self.generation
    }

    /// The attempt it was sealed under.
    pub fn attempt(self) -> Attempt {
        self.attempt
    }

    /// Which leg it is.
    pub fn leg(self) -> Leg {
        self.leg
    }

    /// Which direction's pages it was read from.
    pub fn direction(self) -> Direction {
        self.direction
    }

    /// The sequence position it was fetched from.
    pub fn seq(self) -> u64 {
        self.seq
    }
}

/// Whether a handshake frame had been processed before.
///
/// An enum rather than a `bool` because both answers cause work and neither is
/// the "failure": a novel frame may fire the peer-state-regressed alarm, and a
/// repeat must not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Novelty {
    /// Not seen at this position before. A4.5's byte-novelty predicate is
    /// satisfied and a superseded-root frame may cause a transition.
    Novel,
    /// Already recorded. The frame is inert: it causes no transition and fires
    /// no alarm.
    Repeat,
}

/// A5.3's durable, retention-scoped memory of the handshake frames this
/// correspondence has already processed.
///
/// **Durable, not soft.** A5.3: *"a lost entry is a torn security invariant … a
/// co-host re-serves captured `RE-EST` bytes into an empty dedup → byte-novel →
/// re-fires the peer-state-regressed alarm, reopening MAJOR-CRYPTO-3's
/// inducibility"*. So it travels in the resume blob with the roots rather than
/// in the volatile schedule record A5.4 keeps for genuinely self-healing state.
///
/// **Its lifetime is the retained root's, and nothing else's.** A5.3 ties
/// eviction to *"actual `RS_n` retirement, not a fixed 14-day duration"*: byte
/// novelty only matters while `RS_n` is retained, because once it is gone a
/// superseded-root frame cannot open and cannot alarm. That is why the memory
/// has no `clear` of its own — [`ResumeRecord::retire_retained`] drops the root
/// and the memory in one act, so there is no spelling for emptying one without
/// the other.
///
/// Bounded at [`DEDUP_CAPACITY`], which A5.3 sizes as *"a few handshake frames
/// per attempt"* against A6.3's per-window cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DedupMemory {
    keys: Vec<DedupKey>,
}

impl DedupMemory {
    /// The plane every entry was read from, or `None` while the memory is
    /// empty.
    ///
    /// Established by the first entry rather than declared: a party learns which
    /// plane is inbound by receiving on it, and there is only ever one.
    pub fn direction(&self) -> Option<Direction> {
        self.keys.first().map(|key| key.direction)
    }
}

impl DedupMemory {
    /// An empty memory.
    pub const fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Record that a frame was processed at `key`, and say whether it was novel.
    ///
    /// [`Novelty::Repeat`] for a key already held, and the memory is unchanged —
    /// which is what makes a replay storm cost nothing.
    ///
    /// [`ResumeError::DedupFull`] rather than an eviction when the bound is
    /// reached: evicting to make room would drop a key whose frame can still be
    /// replayed, which is the torn invariant this memory exists to hold. The
    /// bound is sized against the population A5.3 and A6.3 allow, so reaching it
    /// means the window's cap has already been exceeded somewhere else.
    pub fn insert(&mut self, key: DedupKey) -> Result<Novelty, ResumeError> {
        // **One plane per memory.** A party processes only what arrives, and
        // everything that arrives is read from the plane the correspondent
        // writes — so a second direction is a frame this side sealed itself
        // being filed as one it opened, which would put our own attempt numbers
        // in a set the peer's window base is used to bound. Refused rather than
        // accommodated: it is not a state the design produces, and admitting it
        // would make the eviction's per-leg base the wrong number for half the
        // set.
        if let Some(established) = self.direction()
            && established != key.direction
        {
            return Err(ResumeError::DedupDirectionMixed);
        }
        if self.keys.contains(&key) {
            return Ok(Novelty::Repeat);
        }
        if self.keys.len() >= DEDUP_CAPACITY {
            return Err(ResumeError::DedupFull {
                capacity: DEDUP_CAPACITY,
            });
        }
        self.keys.push(key);
        Ok(Novelty::Novel)
    }

    /// Whether a frame at this position has been processed.
    pub fn contains(&self, key: DedupKey) -> bool {
        self.keys.contains(&key)
    }

    /// How many positions are held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether nothing has been processed.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The positions, in the order they were recorded — which is the order they
    /// encode in, so a round trip is byte-stable.
    pub fn keys(&self) -> &[DedupKey] {
        &self.keys
    }
}

/// The re-establishment handshake's own state: the committed generation and the
/// two slots A3.14 gives the record, with A7.3's window anchor.
///
/// Grouped rather than passed as loose arguments because they move together: a
/// completed handshake advances `reconnect_gen` and zeroes the own slot in the
/// same write (A3.4, A3.14), and the anchor is read against the own slot's
/// attempt.
#[derive(Debug, Default)]
pub struct ReEstState {
    /// A3.4's generation, advanced only by a completed handshake.
    pub reconnect_gen: u32,
    /// A6.1's `RE-EST` window base, **stored rather than derived from the
    /// acceptance slot**, and monotone for the correspondence's lifetime.
    ///
    /// A6.1 has the window *"slide with observed traffic"* — forward only. Read
    /// off the acceptance slot it would instead jump back to `0` at every
    /// completed handshake, because A3.14 zeroes that slot on completion, and
    /// attempts already evicted from the dedup memory would become openable
    /// again inside `[0, MAX_GAP]`.
    ///
    /// **Here rather than in [`Retention`]**, beside the other
    /// correspondence-lifetime counter: A6.1 scopes the window to the
    /// correspondence, not to whichever `RS_n` is retained at the moment.
    /// Retiring a root ends what the dedup memory is *for*; it does not unsee
    /// what the receiver has seen, and a base that reset at retirement would
    /// make [`ResumeRecord::retire_retained`] unwritable — the store refuses a
    /// base behind the stored one, so the retirement would be its own
    /// regression.
    pub last_seen_re_est: u32,
    /// A5.2's monotone attempt counter, *"a monotonic per-(correspondence,
    /// direction) counter … advancing on every `RE-EST` seal and persisted
    /// ahead of emission"*. `0` before the first attempt.
    ///
    /// **Its own field, not the own slot's copy**, and A9.2 lists the two
    /// separately for the reason A3.14 makes visible: the slot is *"zeroed on
    /// completion"*, and a counter read out of it would restart at `1` at every
    /// completed handshake — so the anti-rollback comparison would stop firing
    /// across exactly the boundary it exists to guard, and a replayed record
    /// from an earlier generation would be admitted. The slot keeps a copy
    /// because A9.1(a)'s re-emit needs the number bound to the bytes; this is
    /// the counter.
    pub attempt: u32,
    /// Our own pending initiation, or `None` while the slot stands empty.
    pub own: Option<OwnSlot>,
    /// The peer initiation we accepted, or `None` while the slot stands empty.
    pub acceptance: Option<AcceptanceSlot>,
    /// A7.3's `attempt_at_window_start`: the attempt number the current
    /// re-initiation window opened at, so *"attempts this window"* is
    /// `attempt − attempt_at_window_start` rather than a second stored counter
    /// a crash could disagree with.
    ///
    /// `0` before the first attempt, which [`Attempt::FIRST`] leaves free.
    pub attempt_at_window_start: u32,
    /// The clear ratchet generation the re-rooted chain opened at
    /// (`docs/design/direct-messaging.md:929`, A3.12).
    ///
    /// **The sweep compares a ratchet generation, not `reconnect_gen`.** The two
    /// count different things: `reconnect_gen` counts completed handshakes,
    /// while a frame's provenance is the clear ratchet generation it was sealed
    /// under, which advances on every direction switch. Comparing an entry's
    /// provenance against the reconnect counter would end live entries on an
    /// established channel — the numbers are unrelated in size — so the record
    /// stores the ratchet generation the sweep actually needs.
    ///
    /// `0` before the first re-establishment, when nothing has been superseded
    /// and [`crate::dm::outbox::Outbox::sweep_dead_chain`] ends nothing.
    pub reroot_ratchet_gen: u32,
}

impl ReEstState {
    /// The state a first establishment writes: generation `0`, both slots
    /// empty, the window anchored before the first attempt.
    pub fn first_establishment() -> Self {
        Self::default()
    }
}

/// Everything scoped to the retained `RS_n`: the root itself with its
/// write-once supersede stamp, the dedup memory whose lifetime is that root's,
/// and A5.4's retained-but-stopped flag.
///
/// The three are one group because retirement ends all of them at once — see
/// [`ResumeRecord::retire_retained`], which is the only act that does so.
#[derive(Debug, Default)]
pub struct Retention {
    /// The superseded root, retained until its confirming observation or
    /// `T_RETIRE` (A3.5).
    pub retained: Option<RetainedRoot>,
    /// A5.3's processed-frame memory, scoped to `retained`.
    pub dedup: DedupMemory,
    /// A5.4's durable retained-but-stopped flag: the stored handshake frames are
    /// kept for a re-serve, and their ladder has reached its give-up.
    ///
    /// Durable *"so emission-eligibility past give-up is never inferable from a
    /// losable schedule"* — a lost volatile schedule would otherwise default to
    /// rung-0-due-now and resurrect a re-seed the give-up had stopped.
    pub stopped: bool,
}

impl Retention {
    /// Nothing retained: what a correspondence carries before its first
    /// supersede, and what it carries again after retirement.
    pub fn none() -> Self {
        Self::default()
    }
}

impl Zeroize for Retention {
    fn zeroize(&mut self) {
        self.retained.zeroize();
        self.dedup.keys.clear();
        self.stopped = false;
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
    /// check and is indistinguishable from filler (A4.8).
    #[zeroize(skip)]
    pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
    /// The re-establishment root this party has committed to.
    committed_root: CommittedRoot,
    /// A3.4's generation, the committed authority every other record derives
    /// from. It advances only by a completed handshake and never goes backwards
    /// — `commit_resume` refuses a record that would.
    #[zeroize(skip)]
    reconnect_gen: u32,
    /// A5.2's monotone attempt counter. See [`ReEstState::attempt`] for why it
    /// is not read out of the own slot.
    #[zeroize(skip)]
    attempt: u32,
    /// A6.1's `RE-EST` window base. See [`ReEstState::last_seen_re_est`].
    #[zeroize(skip)]
    last_seen_re_est: u32,
    /// **Our own initiation slot**: the generation it acts at, and the sealed
    /// RE-EST bound to the attempt it was sealed under. The peer dedups a
    /// re-emit on the attempt (A9.4), and A9.1 permits a fresh secret only under
    /// a **new** one — so the two facts are carried bound together rather than
    /// as fields a caller could pair wrongly. See [`SealedReEst`] for the
    /// construction rule that enforces it.
    ///
    /// **`None` is the slot standing empty** rather than a missing field: a
    /// correspondence that has established and not yet re-established has a
    /// resume record and no re-establishment frame, and [`SealedReEst::seal`]
    /// cannot mint a stand-in for one because it consumes a [`FreshAttempt`] —
    /// spending attempt 1 on a frame that was never emitted, which
    /// `AttemptResealed` then refuses when the real first re-establishment
    /// arrives. At rest the slot is attempt `0` and a zero-length frame;
    /// [`Attempt::FIRST`] is `1`, so the spelling is free.
    ///
    /// The bytes are load-bearing in this blob (A9.2): ML-KEM encapsulation is
    /// randomized and `ss → eph_ct` is not invertible, so A9.1(a)'s
    /// byte-identical re-emit cannot be rebuilt from the key inputs. Recovery
    /// re-emits *these*, not a fresh encapsulation.
    ///
    /// The slot also carries the secret half of the ephemeral its `RE-EST`
    /// published, so the leg can still be completed after the restart that
    /// re-emits it. See [`OwnSlot`].
    ///
    /// `zeroize(skip)`, and the reason is now narrower than it was: the attempt
    /// counter, the generation and the sealed frame are none of them secrets,
    /// and the decapsulation key wipes itself. [`crate::dm::ratchet::EphemeralDecapKey`]
    /// is `ZeroizeOnDrop`, so dropping this record drops the slot and wipes the
    /// key without this derive reaching it — which is why the field is skipped
    /// rather than the type being made `Zeroize`.
    #[zeroize(skip)]
    own: Option<OwnSlot>,
    /// **The peer-acceptance slot** A3.14 names beside the own slot, carrying
    /// the sealed `RE-ACK` a re-serve sends and A5.1(ii)'s confirmation lock.
    /// See [`AcceptanceSlot`].
    #[zeroize(skip)]
    acceptance: Option<AcceptanceSlot>,
    /// The retained `RS_n`, the dedup memory scoped to it, and the
    /// retained-but-stopped flag. See [`Retention`].
    ///
    /// **Not skipped**: the retained root is a root. It is the one field of this
    /// group that is secret, and the group's own `Zeroize` is written out
    /// because the stamp beside it is a plain integer a derive would leave.
    retention: Retention,
    /// The durable send-side floor. See [`SendFloor`].
    #[zeroize(skip)]
    send_floor: SendFloor,
    /// A7.3's window anchor: the attempt number the current re-initiation
    /// window opened at. `0` before the first attempt.
    ///
    /// **An attempt number, not a timestamp.** A7.3 persists
    /// `attempt_at_window_start` and derives *"attempts this window"* as
    /// `attempt − attempt_at_window_start`; A8.2 then requires window membership
    /// and anchor reset be *"an idempotent derivation from durable `last_seen`
    /// … recomputed at load"*. A wall-clock anchor can satisfy neither: a
    /// rollover read off a clock tears at the boundary, and a crash across it
    /// would let a loop mint a fresh window's worth of attempts without the peer
    /// having opened one.
    #[zeroize(skip)]
    attempt_at_window_start: u32,
    /// The clear ratchet generation the re-rooted chain opened at, which the
    /// dead-chain sweep compares each outbox entry's provenance against. See
    /// [`ReEstState::reroot_ratchet_gen`].
    #[zeroize(skip)]
    reroot_ratchet_gen: u32,
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
            .field("reconnect_gen", &self.reconnect_gen)
            .field("reroot_ratchet_gen", &self.reroot_ratchet_gen)
            .field("send_floor", &self.send_floor)
            .field("attempt_at_window_start", &self.attempt_at_window_start)
            // Each renders its attempt and its frame's length; their own `Debug`
            // impls make the same redaction decision this one does, and
            // `RetainedRoot`'s root renders through `CommittedRoot`'s.
            .field("own", &self.own)
            .field("acceptance", &self.acceptance)
            .field("retention", &self.retention)
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
    /// **Both slots are `None` at first establishment.** The keys, the committed
    /// root and the floor are known the moment a correspondence exists; a sealed
    /// re-establishment frame is not, and there is nothing legitimate to put in
    /// its place. [`ReEstState::first_establishment`] and [`Retention::none`]
    /// are that state written down.
    ///
    /// **The two groups are structs rather than eleven positional arguments**,
    /// and the grouping is the design rather than a way to shorten a signature:
    /// each group's fields move together in one write and are read together at
    /// load. A [`ReEstState`] is what a completed handshake replaces wholesale —
    /// the generation advances and the own slot empties in the same act — and a
    /// [`Retention`] is what [`Self::retire_retained`] ends wholesale.
    pub fn new(
        s_pc: Box<[u8; ml_dsa::SK_LEN]>,
        pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
        committed_root: CommittedRoot,
        handshake: ReEstState,
        retention: Retention,
        send_floor: SendFloor,
    ) -> Self {
        let mut record = Self {
            s_pc,
            pk_pc,
            committed_root,
            reconnect_gen: handshake.reconnect_gen,
            attempt: handshake.attempt,
            last_seen_re_est: handshake.last_seen_re_est,
            own: handshake.own,
            acceptance: handshake.acceptance,
            retention,
            send_floor,
            attempt_at_window_start: handshake.attempt_at_window_start,
            reroot_ratchet_gen: handshake.reroot_ratchet_gen,
        };
        // An occupied acceptance slot IS the observation A6.1 slides the window
        // on, so building a record with one raises the base to it — a raise,
        // never a set, because the stored number may already be higher from an
        // exchange whose slot has since been zeroed.
        if let Some(slot) = record.acceptance.as_ref() {
            let observed = slot.attempt().get();
            if observed > record.last_seen_re_est {
                record.last_seen_re_est = observed;
            }
        }
        // Idempotent, so running it here costs nothing when the caller has
        // already run it and closes the gap when the caller has not.
        record.evict_dedup_below_window();
        record
    }

    /// Record that a peer `RE-EST` at `attempt` was accepted, sliding A6.1's
    /// window base forward and evicting what the new window can no longer reach.
    ///
    /// **The two acts are one call because they are one invariant.** The store
    /// refuses a commit that drops a dedup position at or above the base
    /// ([`commit_resume`](crate::dm::persist::DmPersist::commit_resume)), and
    /// eviction drops positions below it — so a base that moved without the
    /// eviction leaves entries the memory no longer needs, and an eviction
    /// without the base having moved is a shrink the store refuses. Neither is
    /// spellable separately.
    ///
    /// A raise, never a set: an observation at or below the stored base is a
    /// window this side has already left, and is inert.
    pub fn observe_accepted(&mut self, attempt: Attempt) {
        if attempt.get() > self.last_seen_re_est {
            self.last_seen_re_est = attempt.get();
            self.evict_dedup_below_window();
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

    /// A3.4's committed generation.
    /// The clear ratchet generation the re-rooted chain opened at — what
    /// [`crate::dm::outbox::Outbox::sweep_dead_chain`] compares each entry's
    /// provenance against. See [`ReEstState::reroot_ratchet_gen`].
    pub fn reroot_ratchet_gen(&self) -> u32 {
        self.reroot_ratchet_gen
    }

    /// Open a re-establishment attempt: occupy the own-initiation slot with a
    /// sealed `RE-EST` and the secret half of the ephemeral it published, and
    /// advance the attempt counter to the attempt those bytes were sealed under.
    ///
    /// **The counter and the slot move together because a record that carried
    /// one without the other is unwritable.**
    /// [`commit_resume`](crate::dm::persist::DmPersist::commit_resume) refuses a
    /// record whose slot names an attempt its counter does not
    /// ([`ResumeError::AttemptSlotDisagrees`]), and `decode` refuses the same
    /// pairing, so there is deliberately no way to set one from outside.
    ///
    /// **The slot's generation is `reconnect_gen + 1`, supplied here rather than
    /// by the caller.** [`OwnSlot`] carries the generation an initiation is
    /// *trying to reach*, which A3.4 puts one past the committed one — a
    /// distinction a caller passing a number would be free to get wrong, and
    /// which nothing downstream would report.
    ///
    /// Refused on an occupied slot ([`ResumeError::AttemptAlreadyOpen`]), and on
    /// a `sealed` whose attempt does not advance the counter
    /// ([`ResumeError::AttemptWouldRollBack`]). The window anchor is untouched:
    /// A8.2 moves it only on observed peer progress
    /// ([`crate::dm::reest::AttemptBudget::observe_peer_opened`]), so spending an
    /// attempt raises the toward-`C` count rather than resetting the window it
    /// is counted in.
    pub fn open_attempt(
        &mut self,
        seq: u64,
        sealed: SealedReEst,
        eph_dk: crate::dm::ratchet::EphemeralDecapKey,
    ) -> Result<(), ResumeError> {
        if let Some(held) = self.own.as_ref() {
            return Err(ResumeError::AttemptAlreadyOpen {
                attempt: held.attempt().get(),
            });
        }
        let offered = sealed.attempt().get();
        if offered <= self.attempt {
            return Err(ResumeError::AttemptWouldRollBack {
                stored: self.attempt,
                offered,
            });
        }
        self.attempt = offered;
        self.own = Some(OwnSlot::new(
            self.reconnect_gen.saturating_add(1),
            seq,
            sealed,
            eph_dk,
        ));
        Ok(())
    }

    /// Give up on the initiation in the own slot, keeping the attempt counter.
    ///
    /// **A3.8's *re-establishment failed* is a state the record has to be able
    /// to reach.** The design has a handshake leg *"reach its give-up"* and
    /// A3.13 forbids a terminal one — *"no confirmation step and no terminal
    /// state"* — so an initiation that will never complete has to be releasable
    /// without a contest (A3.7) and without a completion (A3.14), which are the
    /// only two acts that otherwise empty this slot.
    ///
    /// **The counter is untouched, which is what makes the release safe.** A5.2
    /// keeps `attempt` monotone for the correspondence's whole lifetime, so the
    /// next [`Self::open_attempt`] mints the successor of the abandoned number
    /// rather than reusing it — the key-reuse B-A4-2 closed. The generation does
    /// not move either: A3.4 advances it only by a *completed* handshake, and
    /// nothing completed.
    ///
    /// Inert on an empty slot, so a caller that cannot tell whether it has
    /// already given up may call it either way.
    pub fn abandon_attempt(&mut self) {
        self.own = None;
    }

    /// Commit one completed re-establishment, as one act.
    ///
    /// `docs/design/direct-messaging.md:935` (A3.14) has the whole transition
    /// commit intra-record: the successor root, the advanced counter, the
    /// superseded root with its stamp, and both slots emptied travel in one
    /// `replace_atomically`. This method is that act written down, so a caller
    /// cannot perform half of it — there is no setter for any of the fields it
    /// moves.
    ///
    /// What it does, in the order the design gives:
    ///
    /// - the successor `RS_{n+1}` from `next` becomes the committed root;
    /// - the root it replaces moves into [`Retention`] with `superseded_at_ms`
    ///   written **once**, at `now_ms`, because A3.5 runs the retirement ceiling
    ///   from that stamp and a stamp rewritten on a later commit would restart
    ///   the ceiling;
    /// - `reconnect_gen` advances by one — A3.4 advances it only here, by a
    ///   *completed* handshake;
    /// - `reroot_ratchet_gen` records the clear ratchet generation the resumed
    ///   chain opened at, which the dead-chain sweep reads;
    /// - the send floor is re-qualified by that same generation, its sequence
    ///   unchanged;
    /// - both handshake slots empty, because the exchange they held is over.
    ///
    /// **The send floor moves its generation here or the qualification does
    /// nothing.** A9.2 (`docs/design/direct-messaging.md:1355`, the
    /// qualification itself at `:1357`) qualifies the
    /// floor by generation so that *"re-established and nothing sent yet"* and
    /// *"a replayed stale resume blob"* are told apart, and the 2026-08-14 build
    /// note (`:1479`) records that as the field's only purpose. The pair can
    /// only distinguish them if a completed re-establishment raises the
    /// generation, so this is the one place that ever does. The sequence is
    /// carried across untouched: send `seq` is monotone per direction for the
    /// life of the conversation and does not restart at a new generation, which
    /// is the same build note's other half.
    ///
    /// **The ratchet root is not stored, and that is why the argument is a
    /// [`Rerooted`] rather than a [`CommittedRoot`].** Taking the pair means a
    /// caller cannot commit `RS_{n+1}` without having held `RK_0'` — the state
    /// that cannot be recovered from, since the secret that produced the ratchet
    /// root is gone by then. The ratchet root itself is dropped here: it belongs
    /// to [`crate::dm::ratchet`], which the caller has already built.
    ///
    /// **The resumed channel's identifier is RETURNED, not stored.** It is the
    /// last moment it can be handed over: `ss_new` is consumed by the act that
    /// minted it, and `Rerooted` is taken by value here, so a caller that
    /// committed without receiving it could never recompute it. Returning it
    /// makes that unrepresentable rather than a caller obligation.
    ///
    /// It is **not written to disk**, and that is deliberate:
    /// `docs/design/direct-messaging.md:670` keeps `chan_id` out of every
    /// at-rest encoding, and the identifier a re-establishment derives is
    /// session-lifetime in-memory state on exactly the terms the establishment
    /// identifier already is — held while the channel runs, lost with the
    /// process, re-minted by the next re-establishment. The caller binds it into
    /// the authorship-signature preimage and the seal AAD of every frame the
    /// resumed channel writes.
    ///
    /// **A previously retained root is replaced, not stacked.** One root is
    /// retained at a time — the one just superseded — and its dedup memory goes
    /// with it, because that memory exists to answer questions about frames
    /// openable under it.
    pub fn commit_reestablished(
        &mut self,
        next: Rerooted,
        ratchet_gen: u32,
        now_ms: i64,
    ) -> Zeroizing<[u8; ROOT_KEY_LEN]> {
        let chan_id = Zeroizing::new(*next.chan_id());
        let superseded = std::mem::replace(&mut self.committed_root, next.next().clone());
        self.retention = Retention {
            retained: Some(RetainedRoot::new(superseded, now_ms)),
            dedup: DedupMemory::new(),
            stopped: false,
        };
        // Saturating rather than wrapping: a wrap would put two different roots
        // on one generation number, and reaching `u32::MAX` completed handshakes
        // is not a state any peer following the protocol arrives at.
        self.reconnect_gen = self.reconnect_gen.saturating_add(1);
        self.reroot_ratchet_gen = ratchet_gen;
        self.send_floor = SendFloor::new(ratchet_gen, self.send_floor.seq);
        self.own = None;
        self.acceptance = None;
        chan_id
    }

    pub fn reconnect_gen(&self) -> u32 {
        self.reconnect_gen
    }

    /// Our own pending initiation, or `None` while the slot stands empty.
    pub fn own_slot(&self) -> Option<&OwnSlot> {
        self.own.as_ref()
    }

    /// The peer initiation we accepted, or `None` while the slot stands empty.
    pub fn acceptance(&self) -> Option<&AcceptanceSlot> {
        self.acceptance.as_ref()
    }

    /// The window base for scanning inbound `RE-EST` and `RE-CONFIRM` legs —
    /// A6.1's `last_seen` on the **responder's** side.
    ///
    /// **Stored and monotone, not read off the acceptance slot.** A6.1 has the
    /// window *"slide with observed traffic"*, forward only; A3.14 zeroes the
    /// acceptance slot on completion, so a base read from the slot would drop
    /// back to `0` at every completed handshake and re-admit attempts the dedup
    /// memory has already evicted. Occupying the slot *raises* this number —
    /// [`Self::new`] and [`Self::observe_accepted`] are the two places that do
    /// — and nothing lowers it while the retention lasts.
    ///
    /// A `RE-CONFIRM` settles the attempt that acceptance named, so it scans
    /// against the same base.
    ///
    /// `0` for a correspondence that has accepted nothing.
    ///
    /// Pass it as [`crate::dm::reest::scan_re_est`]'s and
    /// [`crate::dm::reest::scan_re_confirm`]'s `last_seen`.
    pub fn last_seen_re_est(&self) -> u32 {
        self.last_seen_re_est
    }

    /// The window base for scanning inbound `RE-ACK` legs — A6.1's `last_seen`
    /// on the **initiator's** side.
    ///
    /// **A different number from [`Self::last_seen_re_est`], and one derivation
    /// cannot serve both.** The two legs travel in opposite directions and are
    /// keyed on different attempt spaces: a `RE-EST` we receive was sealed under
    /// the *peer's* attempt counter, and a `RE-ACK` we receive answers one of
    /// *our own* attempts, so its window is rooted at our own counter. Scanning
    /// an inbound `RE-ACK` against the acceptance slot's number would put the
    /// window in the peer's space, where our current attempt need not sit at
    /// all — the lockout of A7.3 arriving through the wrong accessor.
    ///
    /// It is the counter rather than the own slot's copy, so it survives the
    /// completion that zeroes the slot (A3.14).
    ///
    /// Pass it as [`crate::dm::reest::scan_re_ack`]'s `last_seen`.
    pub fn last_seen_re_ack(&self) -> u32 {
        self.attempt
    }

    /// A5.2's monotone attempt counter, or `None` before the first attempt.
    ///
    /// **`None` orders below every [`Attempt`]**, which is what the anti-rollback
    /// comparison in
    /// [`commit_resume`](crate::dm::persist::DmPersist::commit_resume) needs and
    /// gets for free from `Option`'s derived ordering: a record with no
    /// re-establishment yet may be replaced by one carrying
    /// [`Attempt::FIRST`], and never the other way round.
    pub fn attempt(&self) -> Option<Attempt> {
        NonZeroU32::new(self.attempt).map(Attempt::from_nonzero)
    }

    /// The sealed frame bound to its attempt — what a re-emit sends.
    ///
    /// A re-emit path wants *this*, not the loose bytes: it carries the attempt
    /// the peer will dedup on (A9.4) alongside the frame, and there is no
    /// constructor on it that would re-seal either.
    pub fn sealed(&self) -> Option<&SealedReEst> {
        self.own.as_ref().map(OwnSlot::sealed)
    }

    /// The durable send-side floor.
    pub fn send_floor(&self) -> SendFloor {
        self.send_floor
    }

    /// A7.3's window anchor — the attempt the current window opened at.
    pub fn attempt_at_window_start(&self) -> u32 {
        self.attempt_at_window_start
    }

    /// The retained `RS_n` and its write-once supersede stamp, or `None` once it
    /// has retired.
    pub fn retained(&self) -> Option<&RetainedRoot> {
        self.retention.retained.as_ref()
    }

    /// A5.3's processed-handshake-frame memory.
    pub fn dedup(&self) -> &DedupMemory {
        &self.retention.dedup
    }

    /// A5.4's retained-but-stopped flag.
    pub fn retained_but_stopped(&self) -> bool {
        self.retention.stopped
    }

    /// Record that a handshake frame was processed at `key`, and say whether it
    /// was novel (A4.5's byte-novelty predicate, A5.3's memory).
    ///
    /// The caller persists the record afterwards; until it does, the memory has
    /// not survived a restart and the frame can be replayed novel again. That is
    /// commit-then-act in the same shape the rest of this record uses, and it is
    /// why this returns the answer rather than acting on it.
    pub fn note_processed(&mut self, key: DedupKey) -> Result<Novelty, ResumeError> {
        self.retention.dedup.insert(key)
    }

    /// Drop the dedup entries whose frames the scan can no longer open.
    ///
    /// **The bound on the memory, and it is A5.3's own argument applied to the
    /// other thing that makes a frame unopenable.** A5.3 evicts at retirement
    /// because *"once retired, a superseded-root frame cannot open and cannot
    /// alarm regardless"*. A5.2 gives the second cause: the receiver
    /// *"trial-decrypts over a bounded `attempt` window
    /// `[last_seen, last_seen + MAX_GAP]`, **rejecting anything beyond**"*, and
    /// A6.1 slides that base forward on observed attempts. An entry below its
    /// leg's base therefore names a frame the scan rejects before novelty is
    /// ever consulted — it cannot open, so it cannot alarm, so the memory of it
    /// buys nothing.
    ///
    /// Without this the set is unbounded in practice rather than in principle:
    /// the anchor rolls over inside one retention (A6.1), so a retained `RS_n`
    /// sees `C` attempts per window for as many windows as the peer answers,
    /// and a memory sized at one window's worth would start refusing legitimate
    /// handshake frames — an outcome A3.15's table does not contain.
    ///
    /// The bases are the record's own derivations, so this is an idempotent
    /// recomputation from durable state in A8.2's shape: running it twice
    /// changes nothing, and running it after a reload gives the same answer as
    /// running it before.
    ///
    /// **Private, and called from exactly two places** — [`Self::new`] and
    /// [`Self::observe_accepted`], the two moments the base can move. A public
    /// version would be an invariant the caller had to remember, and the store's
    /// no-shrink rule would refuse the commit of a record whose caller forgot.
    fn evict_dedup_below_window(&mut self) {
        let re_est_base = self.last_seen_re_est();
        let re_ack_base = self.last_seen_re_ack();
        // **The leg alone selects the base, because the direction is fixed
        // across the set.** [`DedupMemory::insert`] admits one plane, so every
        // entry here was read from the correspondent's plane: an inbound
        // `RE-EST` or `RE-CONFIRM` carries the peer's attempt and is scanned
        // against [`Self::last_seen_re_est`], and an inbound `RE-ACK` answers one
        // of ours and is scanned against [`Self::last_seen_re_ack`]. Were both
        // planes admitted the roles would swap for the second one and the leg
        // would no longer name a base; that is the state `insert` refuses.
        self.retention.dedup.keys.retain(|key| {
            let base = match key.leg {
                // A `RE-CONFIRM` settles the attempt the acceptance named, so it
                // is scanned against the same base as the `RE-EST` that opened
                // the exchange.
                Leg::ReEst | Leg::ReConfirm => re_est_base,
                Leg::ReAck => re_ack_base,
            };
            key.attempt.get() >= base
        });
    }

    /// Retire the retained `RS_n`: drop the root, its supersede stamp, its dedup
    /// memory and the retained-but-stopped flag, together.
    ///
    /// **The one act, because A5.3 scopes the memory's lifetime to the root's**
    /// — *"gated on **actual** `RS_n` retirement, not a fixed 14-day duration"*.
    /// Byte-novelty defends against a co-host re-serving captured `RE-EST` bytes
    /// to re-fire the peer-state-regressed alarm, and that defence is needed for
    /// exactly as long as the retained root can open those bytes: once it is
    /// gone the frame cannot open and cannot alarm. Neither field has a setter,
    /// so *"a still-live `RS_n` paired with an emptied dedup"* has no spelling
    /// here; `commit_resume` refuses it arriving from a caller that built a
    /// record by hand.
    ///
    /// Idempotent: retiring an already-retired retention is a write of the state
    /// it is already in.
    pub fn retire_retained(&mut self) {
        self.retention = Retention::none();
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
        self.sealed().map(SealedReEst::bytes)
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
        let own_generation = self.own.as_ref().map_or(0, OwnSlot::generation);
        // **The SLOT's attempt, not the counter.** They agree while the slot is
        // occupied and part company the moment a completion zeroes it (A3.14),
        // and writing the counter here would spell an occupied slot with no
        // frame — which `decode` then refuses for ever.
        let own_attempt = self.own.as_ref().map_or(0, |slot| slot.attempt().get());
        // Zero on an empty slot, which `decode` requires: sequence 0 is a real
        // position, so emptiness is carried by the attempt and this field has to
        // agree with it, or the record would re-encode to bytes it was not read
        // from.
        let own_seq = self.own.as_ref().map_or(0, OwnSlot::seq);
        // Fixed width whether the slot is occupied or not, so every field after
        // it sits at a constant offset — the same shape the retained root below
        // is written in.
        let own_dk = self.own.as_ref().map(|slot| slot.eph_dk().as_bytes());
        let own_frame = self.sealed_re_est().unwrap_or(&[]);
        let acc_generation = self
            .acceptance
            .as_ref()
            .map_or(0, AcceptanceSlot::generation);
        let acc_attempt = self
            .acceptance
            .as_ref()
            .map_or(0, |slot| slot.attempt().get());
        let acc_confirmed = self
            .acceptance
            .as_ref()
            .is_some_and(AcceptanceSlot::confirmed);
        let acc_frame = self
            .acceptance
            .as_ref()
            .map_or(&[][..], AcceptanceSlot::sealed_re_ack);
        let dedup = self.retention.dedup.keys();
        let mut out = Zeroizing::new(Vec::with_capacity(
            FIXED_LEN + own_frame.len() + acc_frame.len() + dedup.len() * DEDUP_ENTRY_LEN,
        ));
        out.extend_from_slice(RESUME_MAGIC);
        out.extend_from_slice(&Registry::default_write_suite().get().to_be_bytes());
        out.extend_from_slice(self.s_pc.as_ref());
        out.extend_from_slice(self.pk_pc.as_ref());
        out.extend_from_slice(self.committed_root.as_bytes());
        out.extend_from_slice(&self.reconnect_gen.to_be_bytes());
        out.extend_from_slice(&self.attempt.to_be_bytes());
        out.extend_from_slice(&own_generation.to_be_bytes());
        out.extend_from_slice(&own_attempt.to_be_bytes());
        out.extend_from_slice(&own_seq.to_be_bytes());
        match own_dk {
            Some(dk) => {
                out.push(1);
                out.extend_from_slice(dk);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; ml_kem::DK_LEN]);
            }
        }
        out.extend_from_slice(&acc_generation.to_be_bytes());
        out.extend_from_slice(&acc_attempt.to_be_bytes());
        out.push(u8::from(acc_confirmed));
        match self.retention.retained.as_ref() {
            Some(retained) => {
                out.push(1);
                out.extend_from_slice(retained.root().as_bytes());
                out.extend_from_slice(&retained.superseded_at_ms().to_be_bytes());
            }
            // The absent case still writes the fixed width, so the record's
            // layout does not depend on its contents and every field after this
            // one sits at a constant offset.
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; ROOT_KEY_LEN]);
                out.extend_from_slice(&0i64.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.send_floor.generation.to_be_bytes());
        out.extend_from_slice(&self.send_floor.seq.to_be_bytes());
        out.extend_from_slice(&self.attempt_at_window_start.to_be_bytes());
        out.extend_from_slice(&self.reroot_ratchet_gen.to_be_bytes());
        out.extend_from_slice(&self.last_seen_re_est.to_be_bytes());
        out.push(u8::from(self.retention.stopped));
        // `DEDUP_CAPACITY` bounds this far below `u16::MAX`, and `insert` is the
        // only way in, so the cast cannot truncate.
        out.extend_from_slice(&(dedup.len() as u16).to_be_bytes());
        for key in dedup {
            out.extend_from_slice(&key.generation.to_be_bytes());
            out.extend_from_slice(&key.attempt.get().to_be_bytes());
            out.push(key.leg.tag());
            out.push(direction_tag(key.direction));
            out.extend_from_slice(&key.seq.to_be_bytes());
        }
        out.extend_from_slice(&(own_frame.len() as u64).to_be_bytes());
        out.extend_from_slice(own_frame);
        out.extend_from_slice(&(acc_frame.len() as u64).to_be_bytes());
        out.extend_from_slice(acc_frame);
        out
    }

    /// Read the at-rest form back.
    ///
    /// **No clock argument, and the re-establishment window no longer wants
    /// one.** A7.3's anchor is an attempt number and A8.2 derives window
    /// membership from durable `last_seen`, so every value this decoder returns
    /// that bounds a window is a counter compared against another counter. The
    /// one stored timestamp left is `superseded_at_ms`, which A3.5 gives the
    /// refusal `dm::outbox` applies to `composed_at_ms` — *"a future
    /// `superseded_at_ms` refuses the record's decode rather than disabling the
    /// ceiling"*. That comparison needs a clock, which this call does not take
    /// and `dm::outbox::Outbox::decode` does; the refusal belongs at whichever
    /// layer reads the stamp against `T_RETIRE`, and this decoder returns it
    /// verbatim so that layer sees what was written.
    ///
    /// The frame lengths and the dedup count are checked against what remains
    /// **before** anything is reserved, so a corrupt length cannot drive an
    /// allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResumeError> {
        let mut r = Reader::new(bytes);
        // Both magics are the same width, so one read serves both comparisons
        // and a v1 record is refused by name rather than reported as a
        // truncation of the layout it predates.
        let magic = r.take(RESUME_MAGIC.len())?;
        if magic == RESUME_MAGIC_V1 {
            return Err(ResumeError::ObsoleteV1Layout);
        }
        if magic != RESUME_MAGIC {
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
        // **Through a zeroizing local, never a bare `[u8; ROOT_KEY_LEN]`.**
        // `r.array()` returns the root by value, and the copy the caller drops
        // is not the copy `CommittedRoot` wipes — the same reasoning the `s_pc`
        // read above records, which is why that one never builds a stack array
        // either.
        let mut root_bytes = Zeroizing::new(r.array::<ROOT_KEY_LEN>()?);
        let committed_root = CommittedRoot::from_bytes(&root_bytes);
        root_bytes.zeroize();
        let reconnect_gen = u32::from_be_bytes(r.array()?);
        let attempt_counter = u32::from_be_bytes(r.array()?);
        let own_generation = u32::from_be_bytes(r.array()?);
        let own_attempt = u32::from_be_bytes(r.array()?);
        let own_seq = u64::from_be_bytes(r.array()?);
        let own_dk_present = r.array::<1>()?[0] != 0;
        // **Boxed straight from the borrowed input, never through a stack
        // array**, for the reason the `s_pc` read above records: `r.array()`
        // would leave a 3 168-byte copy of a decapsulation key on this frame
        // after the box that follows it.
        let own_dk_bytes: Box<[u8; ml_kem::DK_LEN]> = r
            .take(ml_kem::DK_LEN)?
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| ResumeError::Truncated)?;
        let acc_generation = u32::from_be_bytes(r.array()?);
        let acc_attempt = u32::from_be_bytes(r.array()?);
        let acc_confirmed = r.array::<1>()?[0] != 0;
        let retained_present = r.array::<1>()?[0] != 0;
        let mut retained_bytes = Zeroizing::new(r.array::<ROOT_KEY_LEN>()?);
        let superseded_at_ms = i64::from_be_bytes(r.array()?);
        let generation = u32::from_be_bytes(r.array()?);
        let seq = u64::from_be_bytes(r.array()?);
        let attempt_at_window_start = u32::from_be_bytes(r.array()?);
        let reroot_ratchet_gen = u32::from_be_bytes(r.array()?);
        let last_seen_re_est = u32::from_be_bytes(r.array()?);
        let stopped = r.array::<1>()?[0] != 0;
        let dedup_count = usize::from(u16::from_be_bytes(r.array()?));
        if dedup_count > DEDUP_CAPACITY {
            return Err(ResumeError::DedupFull {
                capacity: DEDUP_CAPACITY,
            });
        }
        let mut dedup = DedupMemory::new();
        for _ in 0..dedup_count {
            let generation = u32::from_be_bytes(r.array()?);
            let attempt = u32::from_be_bytes(r.array()?);
            let leg_tag = r.array::<1>()?[0];
            let direction_tag = r.array::<1>()?[0];
            let seq = u64::from_be_bytes(r.array()?);
            // A key naming attempt `0` names the empty slot, which no frame ever
            // arrived under; refused as a truncation of the record's own
            // vocabulary rather than repaired into attempt 1.
            let attempt = NonZeroU32::new(attempt)
                .map(Attempt::from_nonzero)
                .ok_or(ResumeError::Truncated)?;
            let leg = Leg::from_tag(leg_tag).ok_or(ResumeError::UnknownLeg(leg_tag))?;
            let direction = direction_from_tag(direction_tag)
                .ok_or(ResumeError::UnknownDirection(direction_tag))?;
            if dedup.insert(DedupKey {
                generation,
                attempt,
                leg,
                direction,
                seq,
            })? == Novelty::Repeat
            {
                // Accepting it would decode to a set one entry smaller than the
                // bytes hold, so the record would re-encode to bytes it was not
                // read from.
                return Err(ResumeError::DuplicateDedupEntry);
            }
        }
        let own_len = Self::frame_len(&mut r, MAX_FRAME_LEN)?;
        let sealed_re_est: Box<[u8]> = r.take(own_len)?.to_vec().into_boxed_slice();
        let acc_len = Self::frame_len(&mut r, MAX_SEALED_LEG_LEN)?;
        let sealed_re_ack: Box<[u8]> = r.take(acc_len)?.to_vec().into_boxed_slice();
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
        let sealed = match own_attempt {
            0 if !sealed_re_est.is_empty() => {
                return Err(ResumeError::EmptySlotHasFrame {
                    len: sealed_re_est.len(),
                });
            }
            // An empty slot carries no ephemeral either. `encode` writes the
            // absent case as a clear flag over an all-zero key, so a set flag
            // here is bytes this encoder did not write.
            0 if own_dk_present => {
                return Err(ResumeError::EphemeralKeyWithoutSlot);
            }
            0 if own_generation != 0 => {
                return Err(ResumeError::SlotGenerationWithoutAttempt {
                    generation: own_generation,
                });
            }
            // Sequence 0 is a real position, so emptiness cannot be spelled by
            // the field itself; `encode` writes zero for an absent slot and a
            // record carrying anything else is bytes this encoder did not write.
            0 if own_seq != 0 => {
                return Err(ResumeError::EmptySlotHasSequence { seq: own_seq });
            }
            0 => None,
            n if sealed_re_est.is_empty() => {
                return Err(ResumeError::OccupiedSlotHasNoFrame { attempt: n });
            }
            // A stored `RE-EST` this party may have to re-emit byte-identically
            // is worthless without the key that opens its answer
            // (`docs/design/direct-messaging.md:1351`), so the pair is refused
            // rather than loaded into a slot that can never complete.
            n if !own_dk_present => {
                return Err(ResumeError::OccupiedSlotHasNoEphemeralKey { attempt: n });
            }
            n if n != attempt_counter => {
                return Err(ResumeError::AttemptSlotDisagrees {
                    field: attempt_counter,
                    slot: n,
                });
            }
            n => Some(SealedReEst::from_stored(Attempt(n), sealed_re_est)?),
        };
        let acceptance = match acc_attempt {
            0 if !sealed_re_ack.is_empty() || acc_confirmed => {
                return Err(ResumeError::EmptyAcceptanceHasContent {
                    frame_len: sealed_re_ack.len(),
                    confirmed: acc_confirmed,
                });
            }
            0 if acc_generation != 0 => {
                return Err(ResumeError::SlotGenerationWithoutAttempt {
                    generation: acc_generation,
                });
            }
            0 => None,
            n if sealed_re_ack.is_empty() => {
                return Err(ResumeError::AcceptanceHasNoFrame { attempt: n });
            }
            n => Some(AcceptanceSlot {
                generation: acc_generation,
                attempt: Attempt(n),
                sealed_re_ack,
                confirmed: acc_confirmed,
            }),
        };
        // The presence flag and the stamp have to agree: A3.5 runs `T_RETIRE`
        // from the stamp, so a retained root without one has no ceiling, and a
        // stamp without a root bounds nothing. `encode` writes the absent case as
        // an all-zero root and a zero stamp, so a zero stamp beside a set flag is
        // bytes this encoder did not write.
        let retained = match (retained_present, superseded_at_ms) {
            (true, 0) => {
                return Err(ResumeError::RetentionHalfPresent { present: true });
            }
            (false, stamp) if stamp != 0 => {
                return Err(ResumeError::RetentionHalfPresent { present: false });
            }
            // `encode` writes the absent case as an all-zero root, so bytes
            // under a clear flag are a retained root the flag hides or a flag
            // the bytes contradict; either way not a record this encoder wrote.
            (false, _) if retained_bytes.iter().any(|b| *b != 0) => {
                return Err(ResumeError::RetainedBytesWithoutFlag);
            }
            (true, stamp) => Some(RetainedRoot::new(
                CommittedRoot::from_bytes(&retained_bytes),
                stamp,
            )),
            (false, _) => None,
        };
        retained_bytes.zeroize();
        Ok(Self {
            s_pc,
            pk_pc,
            committed_root,
            reconnect_gen,
            attempt: attempt_counter,
            last_seen_re_est,
            own: sealed.map(|sealed| {
                OwnSlot::new(
                    own_generation,
                    own_seq,
                    sealed,
                    crate::dm::ratchet::EphemeralDecapKey::new(own_dk_bytes),
                )
            }),
            acceptance,
            retention: Retention {
                retained,
                dedup,
                stopped,
            },
            send_floor: SendFloor { generation, seq },
            attempt_at_window_start,
            reroot_ratchet_gen,
        })
    }

    /// A length prefix, checked against its ceiling before anything is reserved.
    fn frame_len(r: &mut Reader<'_>, max: usize) -> Result<usize, ResumeError> {
        let len = u64::from_be_bytes(r.array()?);
        let len = usize::try_from(len).map_err(|_| ResumeError::Truncated)?;
        if len > max {
            return Err(ResumeError::FrameTooLong { len });
        }
        Ok(len)
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
    use crate::dm::eph_dk_fixture;

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
        CommittedRoot::from_bytes(&pattern(seed, ROOT_KEY_LEN).try_into().unwrap())
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

    /// An occupied own-initiation slot at `generation`, sealed under `attempt`.
    fn own_slot(generation: u32, attempt: u32, seed: u8, len: usize) -> OwnSlot {
        own_slot_at(generation, 77, attempt, seed, len)
    }

    /// An occupied own-initiation slot at `generation`, addressed at `seq`.
    fn own_slot_at(generation: u32, seq: u64, attempt: u32, seed: u8, len: usize) -> OwnSlot {
        OwnSlot::new(
            generation,
            seq,
            SealedReEst::seal(fresh(attempt), pattern(seed, len).into_boxed_slice())
                .expect("the fixture is within MAX_FRAME_LEN"),
            eph_dk_fixture(),
        )
    }

    /// An occupied, unconfirmed peer-acceptance slot.
    fn acceptance_slot(generation: u32, attempt: u32, seed: u8, len: usize) -> AcceptanceSlot {
        AcceptanceSlot::accept(
            generation,
            Attempt::from_nonzero(NonZeroU32::new(attempt).expect("a real attempt")),
            pattern(seed, len).into_boxed_slice(),
        )
        .expect("the fixture is within MAX_SEALED_LEG_LEN")
    }

    /// A dedup key whose every component differs from its neighbours', so a
    /// codec that transposed two of them fails rather than passing.
    fn dedup_key(n: u32) -> DedupKey {
        let leg = match n % 3 {
            0 => Leg::ReEst,
            1 => Leg::ReAck,
            _ => Leg::ReConfirm,
        };
        // One plane: the memory admits a single direction, so a fixture that
        // alternated would be testing a state `insert` refuses.
        let direction = Direction::AToB;
        DedupKey::new(
            100 + n,
            Attempt::from_nonzero(NonZeroU32::new(200 + n).expect("non-zero")),
            leg,
            direction,
            u64::from(300 + n),
        )
    }

    /// A retention holding a superseded root, its stamp, three processed
    /// positions and the stopped flag — every field of the group non-default, so
    /// a codec that dropped one fails.
    fn full_retention() -> Retention {
        let mut dedup = DedupMemory::new();
        for n in 0..3 {
            assert_eq!(
                dedup.insert(dedup_key(n)).expect("inside DEDUP_CAPACITY"),
                Novelty::Novel
            );
        }
        Retention {
            retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
            dedup,
            stopped: true,
        }
    }

    /// Every slot occupied and every flag set, so a round trip that dropped any
    /// of them fails.
    fn populated() -> ResumeRecord {
        ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: 9,
                attempt: 7,
                last_seen_re_est: 0,
                own: Some(own_slot(10, 7, 0x44, 512)),
                acceptance: Some(acceptance_slot(8, 5, 0x66, 256).confirm()),
                attempt_at_window_start: 2,
                reroot_ratchet_gen: 0,
            },
            full_retention(),
            SendFloor::new(4, 100),
        )
    }

    /// The same record with both window bases set, so an eviction test can say
    /// what the scan can still reach without hand-writing either number.
    ///
    /// The `RE-EST` base is the acceptance slot's attempt and the `RE-ACK` base
    /// is the counter, so the two are set through the values they derive from.
    fn with_bases(record: ResumeRecord, re_est: u32, re_ack: u32) -> ResumeRecord {
        let mut rebuilt = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: record.reconnect_gen(),
                attempt: re_ack,
                last_seen_re_est: re_est,
                own: None,
                acceptance: (re_est > 0)
                    .then(|| acceptance_slot(record.reconnect_gen() + 1, re_est, 0x66, 32)),
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup: DedupMemory::new(),
                stopped: false,
            },
            SendFloor::new(0, 0),
        );
        for key in record.dedup().keys() {
            rebuilt
                .note_processed(*key)
                .expect("the set only moves across");
        }
        assert_eq!(rebuilt.last_seen_re_est(), re_est);
        assert_eq!(rebuilt.last_seen_re_ack(), re_ack);
        rebuilt
    }

    /// The same record with both handshake slots standing empty and nothing
    /// retained — what a first establishment writes.
    fn opening() -> ResumeRecord {
        ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState::first_establishment(),
            Retention::none(),
            SendFloor::new(0, 0),
        )
    }

    /// **Opening an attempt moves the counter and the slot in one act, and puts
    /// the slot one generation ahead of the committed one.**
    ///
    /// The three facts are asserted together because a record carrying any two
    /// of them is one `commit_resume` refuses: `AttemptSlotDisagrees` on a
    /// counter that does not match its slot, and a slot generation the peer
    /// never contests on one that names the committed generation instead of the
    /// one being reached.
    #[test]
    fn opening_an_attempt_advances_the_counter_and_occupies_the_slot() {
        let mut record = opening();
        assert_eq!(record.attempt(), None, "the fixture has attempted nothing");

        let sealed = SealedReEst::seal(fresh(1), pattern(0x9c, 128).into_boxed_slice())
            .expect("inside MAX_SEALED_LEG_LEN");
        let bytes = sealed.bytes().to_vec();
        record
            .open_attempt(77, sealed, eph_dk_fixture())
            .expect("a first attempt on an empty slot");

        assert_eq!(attempt_of(&record).get(), 1, "the counter did not advance");
        assert_eq!(
            record.own_slot().map(OwnSlot::generation),
            Some(record.reconnect_gen() + 1),
            "the slot must name the generation the initiation is reaching"
        );
        assert_eq!(
            frame_of(&record),
            bytes.as_slice(),
            "the slot holds bytes other than the ones sealed"
        );
        assert_eq!(
            record.attempt_at_window_start(),
            0,
            "spending an attempt moved the window anchor, which only peer \
             progress may do"
        );
    }

    /// **A second open on an occupied slot is refused rather than overwriting
    /// it** — A9.1(a)'s re-emit is the stored bytes, so a party holding an
    /// initiation has nothing to seal.
    ///
    /// The mirror control is the test above: the same call on an empty slot
    /// succeeds, so this is a refusal of the state rather than of the call.
    #[test]
    fn a_second_attempt_cannot_replace_one_still_in_flight() {
        let mut record = opening();
        record
            .open_attempt(
                77,
                SealedReEst::seal(fresh(1), pattern(0x9c, 128).into_boxed_slice())
                    .expect("inside MAX_SEALED_LEG_LEN"),
                eph_dk_fixture(),
            )
            .expect("the first attempt");
        let held = frame_of(&record).to_vec();

        let refused = record.open_attempt(
            78,
            SealedReEst::seal(fresh(2), pattern(0x3d, 128).into_boxed_slice())
                .expect("inside MAX_SEALED_LEG_LEN"),
            eph_dk_fixture(),
        );

        assert!(
            matches!(refused, Err(ResumeError::AttemptAlreadyOpen { attempt: 1 })),
            "expected the in-flight attempt to be named, got {refused:?}"
        );
        assert_eq!(
            frame_of(&record),
            held.as_slice(),
            "a refused open still replaced the slot's bytes"
        );
        assert_eq!(
            attempt_of(&record).get(),
            1,
            "a refused open moved the counter"
        );
    }

    /// **An attempt that does not advance the counter is refused**, which is the
    /// case a completed handshake leaves reachable: A3.14 zeroes the slot, so
    /// the emptiness alone would admit a re-seal of an attempt the peer has
    /// already answered.
    #[test]
    fn an_attempt_that_does_not_advance_the_counter_is_refused() {
        // The slot empty and the counter at 7 — the shape a completed handshake
        // leaves behind.
        let mut record = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: 9,
                attempt: 7,
                last_seen_re_est: 0,
                own: None,
                acceptance: None,
                attempt_at_window_start: 2,
                reroot_ratchet_gen: 0,
            },
            Retention::none(),
            SendFloor::new(4, 100),
        );

        let refused = record.open_attempt(
            78,
            SealedReEst::seal(fresh(7), pattern(0x3d, 128).into_boxed_slice())
                .expect("inside MAX_SEALED_LEG_LEN"),
            eph_dk_fixture(),
        );

        assert!(
            matches!(
                refused,
                Err(ResumeError::AttemptWouldRollBack {
                    stored: 7,
                    offered: 7
                })
            ),
            "expected a refusal naming both numbers, got {refused:?}"
        );
        assert!(
            record.own_slot().is_none(),
            "a refused open occupied the slot"
        );

        // The control: the successor is admitted, so the refusal above is about
        // the number rather than about the empty slot.
        record
            .open_attempt(
                77,
                SealedReEst::seal(fresh(8), pattern(0x3d, 128).into_boxed_slice())
                    .expect("inside MAX_SEALED_LEG_LEN"),
                eph_dk_fixture(),
            )
            .expect("the successor advances the counter");
        assert_eq!(attempt_of(&record).get(), 8);
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
        assert_eq!(after.reconnect_gen(), before.reconnect_gen());
        assert_eq!(
            after.attempt_at_window_start(),
            before.attempt_at_window_start()
        );
        assert_eq!(after.sealed_re_est(), before.sealed_re_est());
        assert_eq!(
            after.own_slot().map(OwnSlot::generation),
            before.own_slot().map(OwnSlot::generation)
        );
        let (after_acc, before_acc) = (
            after.acceptance().expect("the fixture accepts"),
            before.acceptance().expect("the fixture accepts"),
        );
        assert_eq!(after_acc.generation(), before_acc.generation());
        assert_eq!(after_acc.attempt(), before_acc.attempt());
        assert_eq!(after_acc.sealed_re_ack(), before_acc.sealed_re_ack());
        assert_eq!(after_acc.confirmed(), before_acc.confirmed());
        let (after_ret, before_ret) = (
            after.retained().expect("the fixture retains"),
            before.retained().expect("the fixture retains"),
        );
        assert_eq!(after_ret.root().as_bytes(), before_ret.root().as_bytes());
        assert_eq!(after_ret.superseded_at_ms(), before_ret.superseded_at_ms());
        assert_eq!(after.retained_but_stopped(), before.retained_but_stopped());
        assert_eq!(before.dedup().len(), 3, "the fixture must hold positions");
        assert_eq!(after.dedup().keys(), before.dedup().keys());

        // The fixture has to be non-degenerate for any of the above to mean
        // something: two fields holding the same bytes would let a crossed
        // decoder pass.
        assert_ne!(&before.s_pc()[..32], &before.pk_pc()[..32]);
        assert_ne!(&before.pk_pc()[..32], before.committed_root().as_bytes());
        // Every scalar against every other, so a later fixture edit cannot
        // hollow this test by making two of them equal. The earlier guard
        // covered three pairs and left the rest distinct only by accident.
        let scalars: [(&str, u64); 9] = [
            ("attempt", u64::from(attempt_of(&before).get())),
            (
                "floor_generation",
                u64::from(before.send_floor().generation()),
            ),
            ("seq", before.send_floor().seq()),
            ("reconnect_gen", u64::from(before.reconnect_gen())),
            (
                "own_generation",
                u64::from(before.own_slot().expect("occupied").generation()),
            ),
            ("acceptance_generation", u64::from(before_acc.generation())),
            ("acceptance_attempt", u64::from(before_acc.attempt().get())),
            (
                "attempt_at_window_start",
                u64::from(before.attempt_at_window_start()),
            ),
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
        let acceptance = record.acceptance().expect("the fixture accepts");
        let named = RESUME_MAGIC.len()
            + SUITE_ID_LEN
            + ml_dsa::SK_LEN
            + ml_dsa::PK_LEN
            + ROOT_KEY_LEN
            + 4 /* reconnect_gen */
            + 4 /* attempt counter */
            + 4 /* own slot generation */
            + 4 /* own slot attempt */
            + 8 /* own slot seq */
            + 1 /* own slot ephemeral key present */
            + ml_kem::DK_LEN /* own slot ephemeral decapsulation key */
            + 4 /* acceptance generation */
            + 4 /* acceptance attempt */
            + 1 /* acceptance confirmed */
            + 1 /* retained present */
            + ROOT_KEY_LEN /* retained RS_n */
            + 8 /* superseded_at_ms */
            + 4 /* send floor generation */
            + 8 /* send floor seq */
            + 4 /* attempt_at_window_start */
            + 4 /* reroot_ratchet_gen */
            + 4 /* last_seen_re_est */
            + 1 /* retained_but_stopped */
            + 2 /* dedup count */
            + record.dedup().len() * DEDUP_ENTRY_LEN
            + 8 /* own frame length prefix */
            + frame_of(&record).len()
            + 8 /* acceptance frame length prefix */
            + acceptance.sealed_re_ack().len();
        assert_eq!(
            encoded.len(),
            named,
            "a field is present that nothing names"
        );
        assert_eq!(
            encoded.len(),
            FIXED_LEN
                + frame_of(&record).len()
                + acceptance.sealed_re_ack().len()
                + record.dedup().len() * DEDUP_ENTRY_LEN
        );
    }

    /// A record's plaintext, assembled by hand so the two contradictory slot
    /// spellings can be written down at all.
    ///
    /// [`ResumeRecord::encode`] reads both halves from one `Option`, so neither
    /// spelling has an expression there; this is the second opinion the layout
    /// test uses, reused to reach the decoder's own guards.
    fn assembled(attempt: u32, frame: &[u8]) -> Vec<u8> {
        assembled_full(attempt, frame, 0, &[], false, None, &[])
    }

    /// Every field of the at-rest form, writable independently — which is what
    /// lets a test spell a slot whose halves contradict each other, a retained
    /// root missing its stamp, or a dedup entry naming no leg.
    fn assembled_full(
        own_attempt: u32,
        own_frame: &[u8],
        acc_attempt: u32,
        acc_frame: &[u8],
        acc_confirmed: bool,
        retained: Option<i64>,
        dedup: &[(u32, u32, u8, u8, u64)],
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(RESUME_MAGIC);
        out.extend_from_slice(&crate::crypto::suite::CNSA_2_0.id.get().to_be_bytes());
        out.extend_from_slice(&pattern(0x11, ml_dsa::SK_LEN));
        out.extend_from_slice(&pattern(0x22, ml_dsa::PK_LEN));
        out.extend_from_slice(&pattern(0x33, ROOT_KEY_LEN));
        out.extend_from_slice(&9u32.to_be_bytes()); // reconnect_gen
        out.extend_from_slice(&own_attempt.to_be_bytes()); // the attempt counter
        // An empty slot carries a zero generation: the decoder refuses a
        // generation naming an exchange that is not there.
        out.extend_from_slice(&if own_attempt == 0 { 0u32 } else { 10 }.to_be_bytes());
        out.extend_from_slice(&own_attempt.to_be_bytes()); // own slot attempt
        // An empty slot names sequence 0, because 0 is a real position and the
        // field cannot spell its own absence.
        out.extend_from_slice(&if own_attempt == 0 { 0u64 } else { 77 }.to_be_bytes());
        // An occupied slot carries the ephemeral its RE-EST published; an empty
        // one carries a clear flag over an all-zero key, which is what `encode`
        // writes and what the decoder refuses to see contradicted.
        out.push(u8::from(own_attempt != 0));
        out.extend_from_slice(&if own_attempt == 0 {
            [0u8; ml_kem::DK_LEN]
        } else {
            [0x3du8; ml_kem::DK_LEN]
        });
        out.extend_from_slice(&if acc_attempt == 0 { 0u32 } else { 8 }.to_be_bytes());
        out.extend_from_slice(&acc_attempt.to_be_bytes());
        out.push(u8::from(acc_confirmed));
        out.push(u8::from(retained.is_some()));
        // Zeros when the flag is clear: that is what `encode` writes for the
        // absent case, and the decoder refuses bytes hiding under a clear flag.
        out.extend_from_slice(&if retained.is_some() {
            pattern(0x55, ROOT_KEY_LEN)
        } else {
            vec![0u8; ROOT_KEY_LEN]
        });
        out.extend_from_slice(&retained.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&4u32.to_be_bytes()); // send floor generation
        out.extend_from_slice(&100u64.to_be_bytes()); // send floor seq
        out.extend_from_slice(&2u32.to_be_bytes()); // attempt_at_window_start
        out.extend_from_slice(&0u32.to_be_bytes()); // reroot_ratchet_gen
        // The window base: an occupied acceptance slot raises it to its attempt.
        out.extend_from_slice(&acc_attempt.to_be_bytes());
        out.push(0); // retained_but_stopped
        out.extend_from_slice(&(dedup.len() as u16).to_be_bytes());
        for (generation, attempt, leg, direction, seq) in dedup {
            out.extend_from_slice(&generation.to_be_bytes());
            out.extend_from_slice(&attempt.to_be_bytes());
            out.push(*leg);
            out.push(*direction);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        out.extend_from_slice(&(own_frame.len() as u64).to_be_bytes());
        out.extend_from_slice(own_frame);
        out.extend_from_slice(&(acc_frame.len() as u64).to_be_bytes());
        out.extend_from_slice(acc_frame);
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
        expected.extend_from_slice(&9u32.to_be_bytes()); // reconnect_gen
        expected.extend_from_slice(&7u32.to_be_bytes()); // the attempt counter
        expected.extend_from_slice(&10u32.to_be_bytes()); // own slot generation
        expected.extend_from_slice(&7u32.to_be_bytes()); // own slot attempt
        expected.extend_from_slice(&77u64.to_be_bytes()); // own slot seq
        expected.push(1); // own slot ephemeral decapsulation key present
        expected.extend_from_slice(&[0x3d; ml_kem::DK_LEN]); // that key
        expected.extend_from_slice(&8u32.to_be_bytes()); // acceptance generation
        expected.extend_from_slice(&5u32.to_be_bytes()); // acceptance attempt
        expected.push(1); // acceptance confirmed
        expected.push(1); // retained RS_n present
        expected.extend_from_slice(&pattern(0x55, ROOT_KEY_LEN)); // retained RS_n
        expected.extend_from_slice(&ANCHOR.to_be_bytes()); // superseded_at_ms
        expected.extend_from_slice(&4u32.to_be_bytes()); // floor generation
        expected.extend_from_slice(&100u64.to_be_bytes()); // floor seq
        expected.extend_from_slice(&2u32.to_be_bytes()); // attempt_at_window_start
        expected.extend_from_slice(&0u32.to_be_bytes()); // reroot_ratchet_gen
        expected.extend_from_slice(&5u32.to_be_bytes()); // last_seen_re_est
        expected.push(1); // retained_but_stopped
        expected.extend_from_slice(&3u16.to_be_bytes()); // dedup entry count
        for (generation, attempt, leg, direction, seq) in [
            (100u32, 200u32, 1u8, 1u8, 300u64),
            (101, 201, 2, 1, 301),
            (102, 202, 3, 1, 302),
        ] {
            expected.extend_from_slice(&generation.to_be_bytes());
            expected.extend_from_slice(&attempt.to_be_bytes());
            expected.push(leg);
            expected.push(direction);
            expected.extend_from_slice(&seq.to_be_bytes());
        }
        expected.extend_from_slice(&512u64.to_be_bytes()); // own frame length prefix
        expected.extend_from_slice(&pattern(0x44, 512)); // the sealed RE-EST
        expected.extend_from_slice(&256u64.to_be_bytes()); // acceptance length prefix
        expected.extend_from_slice(&pattern(0x66, 256)); // the sealed RE-ACK

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
    /// `sealed()` carries the attempt a re-emit dedups on and `sealed_re_est()`
    /// carries only the bytes; both read one [`OwnSlot`], so a change that gave
    /// either its own storage would let them disagree with nothing to say which
    /// was right.
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

    /// **`reroot` matches an independently computed HKDF-SHA384, on every
    /// output.**
    ///
    /// Same discipline as `roots_from_one_ss0_are_pinned_siblings` in
    /// `dm::ratchet`, and the same script — `hashlib`/`hmac`, no line shared with
    /// `oxicrypt`:
    ///
    /// ```text
    /// rs_n   = bytes.fromhex("a8042dbc77f2303ad708b1131d05e05a8382822ce9845c4285e5593d1b7e26dc")
    /// ss_new = bytes((0x22 ^ ((i * 7 + 0x5b) & 0xFF)) & 0xFF for i in range(32))
    ///
    /// ratchet_root = expand(extract(rs_n, ss_new), b"daemonseed/dm/ratchet/step/v2", 32)
    /// prk          = extract(b"daemonseed/dm/reest/salt/v1", rs_n + ss_new)
    /// next         = expand(prk, b"daemonseed/dm/reest/next/v1", 32)
    /// chan_id      = expand(prk, b"daemonseed/dm/reest/chanid/v1", 32)
    ///
    /// ratchet_root b011c303f26d81d50df4f057d12c4bb8cd4f10fd9aface16dae91163108f2f26
    /// next         4c4a76e8c6b371814e9e2662db50e8cb6356c25dc5c710162491e43c912f39c0
    /// chan_id      ce2baa5fe8bde40ce78dc354f735f01e2c91db39d7395436df6bcdf03ba99de3
    /// ```
    ///
    /// **`RS_n` here is deliberately the value `root_derivation_is_pinned` pins,
    /// so the ratchet-root vector has a control inside this crate.**
    /// `root_advance_is_pinned` in `dm::ratchet` pins
    /// `advance_root(root(0x11), ss(0x22))` at exactly the same hex, from the
    /// same two inputs — so if these two lines ever disagree, one of them is
    /// wrong and the pair says so rather than each passing alone. The two
    /// reproduced lines are also the control on the script itself: an
    /// independent implementation that disagreed with known-good outputs would
    /// be the thing at fault, and its third value would be worth nothing.
    ///
    /// The three outputs are different bytes from the same pair of inputs, which
    /// is the property `docs/design/direct-messaging.md:722` and `:724` require:
    /// none of the retained successor, the live ratchet root and the resumed
    /// channel's identifier is derivable from another. `chan_id` shares the
    /// successor's extraction and differs only by label, so a build that
    /// expanded it under `DM_REEST_NEXT` would collide the two — which the
    /// vector and the distinctness assertion both catch.
    #[test]
    fn reroot_is_pinned_on_every_output() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let rs_n = CommittedRoot::from_bytes(
            &hex::decode("a8042dbc77f2303ad708b1131d05e05a8382822ce9845c4285e5593d1b7e26dc")
                .expect("the vector is hex")
                .try_into()
                .expect("the vector is a root's width"),
        );
        let mut ss_new = [0u8; ROOT_KEY_LEN];
        for (i, b) in ss_new.iter_mut().enumerate() {
            *b = 0x22 ^ (i as u8).wrapping_mul(7).wrapping_add(0x5b);
        }

        let out = reroot(&rs_n, &ss_new).expect("the module is operational");
        assert_eq!(
            hex::encode(out.ratchet_root().as_bytes()),
            "b011c303f26d81d50df4f057d12c4bb8cd4f10fd9aface16dae91163108f2f26",
            "RK_0' must be advance_root(RS_n, ss_new), which dm::ratchet pins \
             independently for these same inputs"
        );
        assert_eq!(
            hex::encode(out.next().as_bytes()),
            "4c4a76e8c6b371814e9e2662db50e8cb6356c25dc5c710162491e43c912f39c0"
        );
        assert_eq!(
            hex::encode(out.chan_id()),
            "ce2baa5fe8bde40ce78dc354f735f01e2c91db39d7395436df6bcdf03ba99de3"
        );
        assert_ne!(
            out.next().as_bytes(),
            out.ratchet_root().as_bytes(),
            "the retained successor and the live ratchet root must not be one value"
        );
        assert_ne!(
            out.next().as_bytes(),
            out.chan_id(),
            "the resumed channel's identifier collided with the retained successor, \
             which is what expanding it under the successor's label produces"
        );
        assert_ne!(
            out.ratchet_root().as_bytes(),
            out.chan_id(),
            "the resumed channel's identifier collided with the live ratchet root"
        );
        assert_ne!(
            out.next().as_bytes(),
            rs_n.as_bytes(),
            "RS_n+1 that equalled RS_n would be a static at-rest credential"
        );
    }

    /// **Both outputs depend on both inputs**, in the shape
    /// `advance_depends_on_both_inputs` already uses one module over.
    ///
    /// A derivation that dropped `ss_new` would let a holder of the retained root
    /// alone compute the resumed channel's keys, and one that dropped `RS_n`
    /// would let a passive observer of the handshake do the same. Neither is
    /// visible from a single-vector KAT.
    #[test]
    fn reroot_depends_on_both_inputs() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let base = reroot(&root(0x33), &[0x01; ROOT_KEY_LEN]).expect("operational");
        let other_root = reroot(&root(0x44), &[0x01; ROOT_KEY_LEN]).expect("operational");
        let other_ss = reroot(&root(0x33), &[0x02; ROOT_KEY_LEN]).expect("operational");

        for (label, candidate) in [
            ("a different RS_n", &other_root),
            ("a different ss_new", &other_ss),
        ] {
            assert_ne!(
                base.next().as_bytes(),
                candidate.next().as_bytes(),
                "RS_n+1 ignored {label}"
            );
            assert_ne!(
                base.ratchet_root().as_bytes(),
                candidate.ratchet_root().as_bytes(),
                "RK_0' ignored {label}"
            );
            assert_ne!(
                base.chan_id(),
                candidate.chan_id(),
                "chan_id_n+1 ignored {label}"
            );
        }
    }

    /// **An occupied own slot carries its ephemeral through the round trip, and
    /// the two spellings that separate the frame from its key are refused.**
    ///
    /// `docs/design/direct-messaging.md:1351` re-emits the stored `RE-EST`
    /// byte-identically after a crash, which publishes an encapsulation key this
    /// party must still be able to decapsulate against. A slot that survived
    /// without its key would re-send for ever and never complete.
    #[test]
    fn the_own_slots_ephemeral_key_survives_the_round_trip() {
        let record = populated();
        let stored = ResumeRecord::decode(&record.encode()).expect("a populated record decodes");
        assert_eq!(
            stored
                .own_slot()
                .expect("the fixture's slot is occupied")
                .eph_dk()
                .as_bytes(),
            eph_dk_fixture().as_bytes(),
            "the ephemeral did not survive the round trip"
        );

        // A frame with no key: the state a build that kept the key in memory
        // would write.
        let frame = pattern(0x44, 64);
        let mut bytes = assembled_full(7, &frame, 0, &[], false, None, &[]);
        let flag_at = RESUME_MAGIC.len()
            + SUITE_ID_LEN
            + ml_dsa::SK_LEN
            + ml_dsa::PK_LEN
            + ROOT_KEY_LEN
            + 4 /* reconnect_gen */
            + 4 /* attempt counter */
            + 4 /* own slot generation */
            + 4 /* own slot attempt */;
        bytes[flag_at] = 0;
        bytes[flag_at + 1..flag_at + 1 + ml_kem::DK_LEN].fill(0);
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::OccupiedSlotHasNoEphemeralKey { attempt: 7 })
        );

        // And the mirror: a key beside an empty slot.
        let mut bytes = assembled_full(0, &[], 0, &[], false, None, &[]);
        bytes[flag_at] = 1;
        bytes[flag_at + 1..flag_at + 1 + ml_kem::DK_LEN].fill(0x3d);
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::EphemeralKeyWithoutSlot)
        );

        // Positive control: untouched, both buffers decode. Without it, a decoder
        // that refused everything would pass the two refusals above.
        assert!(ResumeRecord::decode(&assembled_full(7, &frame, 0, &[], false, None, &[])).is_ok());
        assert!(ResumeRecord::decode(&assembled_full(0, &[], 0, &[], false, None, &[])).is_ok());
    }

    /// **`commit_reestablished` moves every field of the transition, in one
    /// call**, and the assertions below name them one by one rather than
    /// comparing whole records — a whole-record comparison passes for a method
    /// that moved nothing if the expected value was built the same way.
    #[test]
    fn commit_reestablished_advances_every_field_of_the_transition() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut record = populated();
        let before_root = record.committed_root().as_bytes().to_vec();
        let before_gen = record.reconnect_gen();
        let before_floor = record.send_floor();
        assert!(
            before_floor.generation() < 41,
            "the fixture's floor must start below the generation the commit moves it to, \
             or the assertion on it could pass without the commit doing anything"
        );
        assert!(
            record.own_slot().is_some(),
            "the fixture must start occupied"
        );
        assert!(
            record.acceptance().is_some(),
            "the fixture must start occupied"
        );

        let rerooted = reroot(&root(0x77), &[0x09; ROOT_KEY_LEN]).expect("operational");
        let expected_next = rerooted.next().as_bytes().to_vec();
        let expected_chan_id = *rerooted.chan_id();
        let chan_id = record.commit_reestablished(rerooted, 41, 1_700_000_500_000);
        // The identifier is handed back rather than stored: `ss_new` is gone by
        // now, so a commit that did not return it would leave the resumed
        // channel with no way to name itself.
        assert_eq!(
            *chan_id, expected_chan_id,
            "the commit returned an identifier other than the one it was given"
        );
        assert_ne!(
            chan_id.as_slice(),
            record.committed_root().as_bytes(),
            "the identifier and the successor root must not be one value"
        );

        assert_eq!(
            record.committed_root().as_bytes().to_vec(),
            expected_next,
            "the successor did not become the committed root"
        );
        assert_eq!(record.reconnect_gen(), before_gen + 1);
        assert_eq!(record.reroot_ratchet_gen(), 41);
        // A9.2's discriminator: the floor's generation is re-qualified by the
        // ratchet generation the resumed chain opened at, and its sequence is
        // carried across untouched. A commit that left the generation where it
        // was would make "re-established, nothing sent" and "a replayed stale
        // blob" the same pair of numbers, which is the whole reason the floor
        // carries a generation at all.
        assert_eq!(
            record.send_floor().generation(),
            41,
            "the send floor was not re-qualified by the re-rooted generation"
        );
        assert_eq!(
            record.send_floor().seq(),
            before_floor.seq(),
            "send seq is monotone per direction and does not restart at a new generation"
        );
        assert!(record.own_slot().is_none(), "the own slot did not empty");
        assert!(
            record.acceptance().is_none(),
            "the acceptance slot did not empty"
        );
        let retained = record.retained().expect("the superseded root is retained");
        assert_eq!(
            retained.root().as_bytes().to_vec(),
            before_root,
            "the root that was superseded is not the one retained"
        );
        assert_eq!(retained.superseded_at_ms(), 1_700_000_500_000);
        assert!(
            record.dedup().is_empty(),
            "the dedup memory belongs to the root that was just replaced"
        );
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
        let mut dedup = DedupMemory::new();
        for n in 0..DEDUP_CAPACITY {
            assert_eq!(
                dedup
                    .insert(dedup_key(u32::try_from(n).expect("the capacity is small")))
                    .expect("at the capacity, not past it"),
                Novelty::Novel
            );
        }
        assert_eq!(dedup.len(), DEDUP_CAPACITY, "the fixture must fill the set");
        let at_ceiling = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: 0,
                attempt: 1,
                last_seen_re_est: 0,
                own: Some(OwnSlot::new(
                    0,
                    77,
                    SealedReEst::seal(
                        FreshAttempt::first(),
                        pattern(0x44, MAX_FRAME_LEN).into_boxed_slice(),
                    )
                    .expect("a frame of exactly MAX_FRAME_LEN is allowed"),
                    eph_dk_fixture(),
                )),
                acceptance: Some(
                    AcceptanceSlot::accept(
                        0,
                        Attempt::FIRST,
                        pattern(0x66, MAX_SEALED_LEG_LEN).into_boxed_slice(),
                    )
                    .expect("a frame of exactly MAX_SEALED_LEG_LEN is allowed"),
                ),
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup,
                stopped: true,
            },
            SendFloor::new(0, 0),
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
        // The first-establishment record, whose dedup memory is empty — so the
        // own frame's length prefix sits at a constant offset rather than one
        // that moves with the number of recorded positions.
        let record = opening();
        assert!(record.dedup().is_empty(), "the offset below assumes it");
        let mut bytes = record.encode();
        let len_at = FIXED_LEN - 16;
        bytes[len_at..len_at + 8].copy_from_slice(&(too_long as u64).to_be_bytes());
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::FrameTooLong { len: too_long })
        );
    }

    /// **A v1 record is refused by name, and a v2 record round-trips.**
    ///
    /// v2 widened the body by the own slot's ephemeral decapsulation key, its
    /// presence flag, and the re-rooted ratchet generation. Without the version
    /// in the magic a v1 body read under this layout simply runs out of bytes
    /// and reports [`ResumeError::Truncated`] — which names a corruption that
    /// did not happen and hides that the record is intact and merely older.
    ///
    /// Refused rather than read with the missing fields defaulted, because one
    /// of them has no truthful default: a v1 record whose own slot is occupied
    /// carries a sealed `RE-EST` that will be re-emitted byte-identically, and
    /// no value substitutes for the key that opens its answer.
    #[test]
    fn a_predecessor_layout_is_refused_by_name() {
        let current = populated().encode();
        assert_eq!(
            &current[..RESUME_MAGIC.len()],
            RESUME_MAGIC,
            "records are written under the current magic"
        );
        assert!(
            ResumeRecord::decode(&current).is_ok(),
            "positive control: the current layout decodes"
        );

        // The same body under the predecessor's magic. Both magics are the same
        // width, so nothing after the header moves and the only difference the
        // decoder can be reacting to is the version.
        assert_eq!(RESUME_MAGIC_V1.len(), RESUME_MAGIC.len());
        let mut older = current.to_vec();
        older[..RESUME_MAGIC_V1.len()].copy_from_slice(RESUME_MAGIC_V1);
        assert_eq!(
            ResumeRecord::decode(&older).err(),
            Some(ResumeError::ObsoleteV1Layout),
            "a v1 record must be refused by name rather than as a truncation"
        );

        // A genuinely v1-shaped body — the current one minus the three fields v2
        // added — reaches the same refusal, so the name does not depend on the
        // body happening to be the current width.
        let mut short = older;
        short.truncate(short.len() - (1 + ml_kem::DK_LEN + 4));
        assert_eq!(
            ResumeRecord::decode(&short).err(),
            Some(ResumeError::ObsoleteV1Layout)
        );

        // And the control that the refusal is about v1 specifically: an
        // unrecognised magic is still `BadMagic`, not this.
        let mut alien = current.to_vec();
        alien[0] ^= 1;
        assert_eq!(
            ResumeRecord::decode(&alien).err(),
            Some(ResumeError::BadMagic)
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
        for field in [
            "reconnect_gen: 9",
            "attempt_at_window_start: 2",
            "send_floor:",
            "confirmed: true",
            "superseded_at_ms:",
            "stopped: true",
        ] {
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

    // ---------------------------------------------------------------------
    // The two handshake slots (A3.14, A3.4).
    // ---------------------------------------------------------------------

    /// **Both slots round-trip independently, in all four occupancy states.**
    ///
    /// A3.14 gives the record two slots because A3.4's *"a party's own
    /// initiation does not consume the generation for acceptance"* makes the
    /// two facts independent — a party may hold either, both (the contest A3.7
    /// resolves) or neither.
    ///
    /// Kills a codec that carries one slot's occupancy into the other's — the
    /// mutation that reads `acc_attempt` from the own slot's field, which a
    /// round trip of a record with both slots at the same attempt would not
    /// notice. Every state here pairs distinct attempts for that reason.
    #[test]
    fn both_handshake_slots_survive_every_occupancy() {
        let states: [(Option<OwnSlot>, Option<AcceptanceSlot>); 4] = [
            (None, None),
            (Some(own_slot(10, 7, 0x44, 512)), None),
            (None, Some(acceptance_slot(8, 5, 0x66, 256))),
            (
                Some(own_slot(10, 7, 0x44, 512)),
                Some(acceptance_slot(8, 5, 0x66, 256)),
            ),
        ];
        assert_eq!(states.len(), 4, "every occupancy of two slots");
        for (own, acceptance) in states {
            let (own_seen, acc_seen) = (own.is_some(), acceptance.is_some());
            let own_attempt = own.as_ref().map_or(0, |slot| slot.attempt().get());
            let before = ResumeRecord::new(
                s_pc(0x11),
                pk_pc(0x22),
                root(0x33),
                ReEstState {
                    reconnect_gen: 9,
                    attempt: own_attempt,
                    last_seen_re_est: 0,
                    own,
                    acceptance,
                    attempt_at_window_start: 2,
                    reroot_ratchet_gen: 0,
                },
                Retention::none(),
                SendFloor::new(4, 100),
            );
            let after =
                ResumeRecord::decode(&before.encode()).expect("a fresh encoding must decode");
            assert_eq!(after.own_slot().is_some(), own_seen);
            assert_eq!(after.acceptance().is_some(), acc_seen);
            assert_eq!(
                after.own_slot().map(OwnSlot::generation),
                before.own_slot().map(OwnSlot::generation)
            );
            assert_eq!(after.attempt(), before.attempt());
            assert_eq!(after.sealed_re_est(), before.sealed_re_est());
            assert_eq!(
                after.acceptance().map(AcceptanceSlot::generation),
                before.acceptance().map(AcceptanceSlot::generation)
            );
            assert_eq!(
                after.acceptance().map(AcceptanceSlot::attempt),
                before.acceptance().map(AcceptanceSlot::attempt)
            );
            assert_eq!(
                after.acceptance().map(AcceptanceSlot::sealed_re_ack),
                before.acceptance().map(AcceptanceSlot::sealed_re_ack)
            );
        }
    }

    /// **A5.1(ii)'s confirmation lock is a stored bit, and it round-trips.**
    ///
    /// A6.1 sets it on *"the first frame that opens under the re-rooted chain"*.
    /// Held only in memory it would clear on the restart this record exists to
    /// survive, and a returning peer's stale attempt would then supersede a
    /// candidate both sides had settled.
    ///
    /// Kills a codec that writes a constant in the confirmation byte's place:
    /// both values are asserted through a round trip, so a hard-coded `0` fails
    /// the confirmed case and a hard-coded `1` fails the unconfirmed one.
    #[test]
    fn the_confirmation_flag_survives_the_round_trip_in_both_states() {
        for confirmed in [false, true] {
            let slot = acceptance_slot(8, 5, 0x66, 256);
            let slot = if confirmed { slot.confirm() } else { slot };
            assert_eq!(slot.confirmed(), confirmed);
            let before = ResumeRecord::new(
                s_pc(0x11),
                pk_pc(0x22),
                root(0x33),
                ReEstState {
                    reconnect_gen: 9,
                    attempt: 0,
                    last_seen_re_est: 0,
                    own: None,
                    acceptance: Some(slot),
                    attempt_at_window_start: 0,
                    reroot_ratchet_gen: 0,
                },
                Retention::none(),
                SendFloor::new(4, 100),
            );
            let after = ResumeRecord::decode(&before.encode()).expect("decodes");
            assert_eq!(
                after
                    .acceptance()
                    .expect("the slot is occupied")
                    .confirmed(),
                confirmed
            );
        }
    }

    /// **The acceptance slot's contradictory spellings are refused, not
    /// repaired.**
    ///
    /// The mirror of `the_decoder_refuses_a_slot_that_contradicts_itself` for
    /// the own slot: an empty slot with a frame, an empty slot claiming
    /// confirmation, and an occupied slot with no frame. A confirmation flag
    /// over no slot is the worst of the three to repair, because a confirmation
    /// naming no attempt would lock a generation against every attempt.
    ///
    /// Kills a decoder that reads the confirmation byte without checking the
    /// attempt beside it — the middle case, which the other two do not reach.
    #[test]
    fn the_decoder_refuses_an_acceptance_slot_that_contradicts_itself() {
        assert_eq!(
            ResumeRecord::decode(&assembled_full(0, &[], 0, &[9u8; 16], false, None, &[])).err(),
            Some(ResumeError::EmptyAcceptanceHasContent {
                frame_len: 16,
                confirmed: false
            })
        );
        assert_eq!(
            ResumeRecord::decode(&assembled_full(0, &[], 0, &[], true, None, &[])).err(),
            Some(ResumeError::EmptyAcceptanceHasContent {
                frame_len: 0,
                confirmed: true
            })
        );
        assert_eq!(
            ResumeRecord::decode(&assembled_full(0, &[], 5, &[], false, None, &[])).err(),
            Some(ResumeError::AcceptanceHasNoFrame { attempt: 5 })
        );
        // Positive control: the two agreeing spellings decode.
        assert!(ResumeRecord::decode(&assembled_full(0, &[], 0, &[], false, None, &[])).is_ok());
        assert!(
            ResumeRecord::decode(&assembled_full(0, &[], 5, &[9u8; 16], true, None, &[])).is_ok()
        );
    }

    // ---------------------------------------------------------------------
    // The retained root and A5.3's dedup memory.
    // ---------------------------------------------------------------------

    /// **A byte-identical replay at a position already recorded is inert.**
    ///
    /// A4.5's predicate: a superseded-root frame causes a transition only if its
    /// bytes are novel. A5.3 homes the memory here because *"a lost entry is a
    /// torn security invariant"* — a co-host re-serving captured `RE-EST` bytes
    /// into an empty memory re-fires the peer-state-regressed alarm.
    ///
    /// Kills an `insert` that pushes unconditionally: the second call would
    /// return `Novel` and the length would reach 2.
    #[test]
    fn a_replayed_position_is_a_repeat_and_does_not_grow_the_memory() {
        let mut dedup = DedupMemory::new();
        let key = dedup_key(0);
        assert_eq!(dedup.insert(key).expect("room"), Novelty::Novel);
        assert_eq!(dedup.len(), 1);
        assert_eq!(dedup.insert(key).expect("room"), Novelty::Repeat);
        assert_eq!(dedup.len(), 1, "a repeat may not grow the memory");
        assert!(dedup.contains(key));
        // A different position at the same generation is still novel, which is
        // what makes the assertion above about the key rather than about the
        // memory refusing everything after the first.
        assert_eq!(dedup.insert(dedup_key(1)).expect("room"), Novelty::Novel);
        assert_eq!(dedup.len(), 2);
    }

    /// **`attempt` is load-bearing in the dedup key.**
    ///
    /// A5.3 says why in terms: *"two legitimate different-attempt `RE-EST`s
    /// share `gen`/`seq` … so a position-only key would collide them and
    /// wrongly drop a legitimate frame"*.
    ///
    /// Kills a key that ignores any one of its five components: each pair below
    /// differs in exactly one, and every one must read as novel.
    #[test]
    fn every_component_of_the_dedup_key_discriminates() {
        let base = DedupKey::new(7, Attempt::FIRST, Leg::ReEst, Direction::AToB, 3);
        let two = Attempt::from_nonzero(NonZeroU32::new(2).expect("non-zero"));
        let variants = [
            DedupKey::new(8, Attempt::FIRST, Leg::ReEst, Direction::AToB, 3),
            DedupKey::new(7, two, Leg::ReEst, Direction::AToB, 3),
            DedupKey::new(7, Attempt::FIRST, Leg::ReAck, Direction::AToB, 3),
            DedupKey::new(7, Attempt::FIRST, Leg::ReEst, Direction::AToB, 4),
        ];
        assert_eq!(variants.len(), 4, "one variant per same-plane component");
        let mut dedup = DedupMemory::new();
        assert_eq!(dedup.insert(base).expect("room"), Novelty::Novel);
        for (i, variant) in variants.into_iter().enumerate() {
            assert_eq!(
                dedup.insert(variant).expect("room"),
                Novelty::Novel,
                "component {i} does not discriminate"
            );
        }
        assert_eq!(dedup.len(), 5);
        // **The fifth component, direction, discriminates at the KEY and is
        // refused at the MEMORY.** The two are different statements and both
        // matter: the key must tell the planes apart (or a position on one would
        // shadow the same position on the other), and the memory holds only the
        // plane a party receives on.
        let other_plane = DedupKey::new(7, Attempt::FIRST, Leg::ReEst, Direction::BToA, 3);
        assert_ne!(base, other_plane, "direction does not discriminate the key");
        assert_eq!(
            dedup.insert(other_plane).err(),
            Some(ResumeError::DedupDirectionMixed)
        );
        // Positive control: the base key, offered again unchanged, is a repeat —
        // so the novelty above is the components differing and not the memory
        // answering `Novel` to everything.
        assert_eq!(dedup.insert(base).expect("room"), Novelty::Repeat);
    }

    /// **The dedup memory is evicted when `RS_n` retires, and not before.**
    ///
    /// A5.3 gates eviction on *"**actual** `RS_n` retirement, not a fixed 14-day
    /// duration"*: byte-novelty matters for exactly as long as the retained root
    /// can open the frames the memory covers. [`ResumeRecord::retire_retained`]
    /// is the one act that ends both, so *"a still-live `RS_n` paired with an
    /// emptied dedup"* has no spelling.
    ///
    /// Kills a `retire_retained` that drops the root and leaves the memory (or
    /// the reverse): each half is asserted before and after, and the memory is
    /// non-empty going in.
    #[test]
    fn retiring_the_root_evicts_the_dedup_memory_and_nothing_else_does() {
        let mut record = populated();
        assert_eq!(record.dedup().len(), 3, "the fixture holds positions");
        assert!(record.retained().is_some());
        assert!(record.retained_but_stopped());

        // Recording another position does not retire anything.
        assert_eq!(
            record.note_processed(dedup_key(9)).expect("room"),
            Novelty::Novel
        );
        assert_eq!(record.dedup().len(), 4);
        assert!(
            record.retained().is_some(),
            "recording a position may not retire the root"
        );

        record.retire_retained();
        assert!(record.retained().is_none(), "the root did not retire");
        assert!(record.dedup().is_empty(), "the memory outlived its root");
        assert!(!record.retained_but_stopped());

        // Idempotent: retiring again is a write of the state it is already in.
        record.retire_retained();
        assert!(record.retained().is_none());
        assert!(record.dedup().is_empty());
    }

    /// **Retirement leaves the window base alone, so a retired record is
    /// writable after any accepted attempt.**
    ///
    /// A6.1 scopes the window to the correspondence, not to whichever `RS_n` is
    /// retained: retiring a root ends what the dedup memory is *for*, it does
    /// not unsee what the receiver has seen. With the base inside the retention
    /// group, `retire_retained` would reset it to `0` — and the store refuses a
    /// base behind the stored one, so retirement would be its own regression and
    /// could never be committed.
    ///
    /// Kills the base being reset by `retire_retained` — through the group
    /// assignment or otherwise: the assertion after retirement reads it back.
    #[test]
    fn retirement_leaves_the_window_base_where_it_stands() {
        let at = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let mut record = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState::first_establishment(),
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup: DedupMemory::new(),
                stopped: true,
            },
            SendFloor::new(0, 0),
        );
        record.observe_accepted(at(8));
        assert_eq!(record.last_seen_re_est(), 8);

        record.retire_retained();

        assert!(record.retained().is_none(), "the root did not retire");
        assert!(record.dedup().is_empty(), "the memory outlived its root");
        assert_eq!(
            record.last_seen_re_est(),
            8,
            "retirement reset the window base"
        );

        // And the base still governs: a position below it is evicted after
        // retirement exactly as it was before.
        record
            .note_processed(DedupKey::new(1, at(3), Leg::ReEst, Direction::AToB, 0))
            .expect("room");
        record.observe_accepted(at(9));
        assert_eq!(record.last_seen_re_est(), 9);
        assert!(
            record.dedup().is_empty(),
            "the below-base position survived the eviction"
        );
    }

    /// **A decoded record may hold a position below its own base, and the next
    /// observation evicts it.**
    ///
    /// [`ResumeRecord::decode`] builds the record field by field and runs no
    /// eviction, so a record written before its base moved decodes with entries
    /// the scan can no longer reach. That is benign — the store's rule licenses
    /// dropping exactly those — but it is a state the type admits, so it is
    /// pinned rather than assumed away.
    ///
    /// Kills a decoder that silently dropped such entries, which would make a
    /// record re-encode to bytes it was not read from.
    #[test]
    fn a_below_base_entry_survives_decode_and_goes_at_the_next_observation() {
        let at = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let mut dedup = DedupMemory::new();
        dedup
            .insert(DedupKey::new(1, at(2), Leg::ReEst, Direction::AToB, 0))
            .expect("room");
        // Built field by field rather than through `new`, which would evict it.
        let encoded = {
            let mut record = ResumeRecord::new(
                s_pc(0x11),
                pk_pc(0x22),
                root(0x33),
                ReEstState::first_establishment(),
                Retention {
                    retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                    dedup,
                    stopped: false,
                },
                SendFloor::new(0, 0),
            );
            assert_eq!(record.dedup().len(), 1, "the base is 0, so nothing evicts");
            // Raise the base WITHOUT the entry going: `observe_accepted` would
            // evict it, so the base is moved by rebuilding, which is what a
            // record written at a later base looks like.
            record = ResumeRecord::decode(&record.encode()).expect("decodes");
            let mut bytes = record.encode().to_vec();
            let base_at = FIXED_LEN - 8 - 8 - 2 - 1 - 4;
            bytes[base_at..base_at + 4].copy_from_slice(&7u32.to_be_bytes());
            bytes
        };

        let mut decoded = ResumeRecord::decode(&encoded).expect("decodes");
        assert_eq!(
            decoded.last_seen_re_est(),
            7,
            "the patched base did not land"
        );
        assert_eq!(
            decoded.dedup().len(),
            1,
            "decode dropped an entry it should have carried"
        );

        decoded.observe_accepted(at(8));
        assert!(
            decoded.dedup().is_empty(),
            "the next observation did not evict the below-base entry"
        );
    }

    /// **The dedup memory survives the round trip, keys and order intact.**
    ///
    /// Durable, per A5.4's rule that *"hard state (roots, counters, dedup
    /// memory, slots, keys, flags) lives in the durable resume record"*.
    ///
    /// Kills a codec that writes the count and drops the entries, and one that
    /// transposes two fields of a key — the fixture's keys differ in every
    /// component, so a transposition changes at least one of them.
    #[test]
    fn the_dedup_memory_survives_the_round_trip() {
        let before = populated();
        let after = ResumeRecord::decode(&before.encode()).expect("decodes");
        assert_eq!(before.dedup().len(), 3, "the fixture holds positions");
        assert_eq!(after.dedup().len(), before.dedup().len());
        assert_eq!(after.dedup().keys(), before.dedup().keys());
        for key in before.dedup().keys() {
            assert!(after.dedup().contains(*key));
        }
    }

    /// **A dedup entry naming no leg or no direction is refused at decode.**
    ///
    /// The tags are at-rest wire, so a record written by a build with a fourth
    /// leg is bytes this one cannot read; refusing names that rather than
    /// picking a variant.
    ///
    /// Kills a decoder that casts the tag byte into a variant by arithmetic
    /// instead of matching it.
    #[test]
    fn the_decoder_refuses_an_unknown_leg_or_direction_tag() {
        assert_eq!(
            ResumeRecord::decode(&assembled_full(
                0,
                &[],
                0,
                &[],
                false,
                None,
                &[(1, 1, 4, 1, 1)]
            ))
            .err(),
            Some(ResumeError::UnknownLeg(4))
        );
        assert_eq!(
            ResumeRecord::decode(&assembled_full(
                0,
                &[],
                0,
                &[],
                false,
                None,
                &[(1, 1, 1, 3, 1)]
            ))
            .err(),
            Some(ResumeError::UnknownDirection(3))
        );
        // Positive control: the same entry with both tags in range decodes, and
        // the entry actually lands.
        let ok = ResumeRecord::decode(&assembled_full(
            0,
            &[],
            0,
            &[],
            false,
            None,
            &[(1, 1, 1, 1, 1)],
        ))
        .expect("a well-formed entry decodes");
        assert_eq!(ok.dedup().len(), 1);
    }

    /// **The retained root and its supersede stamp are present together or not
    /// at all.**
    ///
    /// A3.5 runs `T_RETIRE` from the stamp, so a retained root without one has
    /// no ceiling and a stamp without a root bounds nothing.
    ///
    /// Kills a decoder that reads the presence flag and ignores the stamp beside
    /// it — the first case — and one that reads the stamp and ignores the flag,
    /// which would build a retention out of `encode`'s all-zero absent case.
    #[test]
    fn the_decoder_refuses_half_a_retention() {
        assert_eq!(
            ResumeRecord::decode(&assembled_full(0, &[], 0, &[], false, Some(0), &[])).err(),
            Some(ResumeError::RetentionHalfPresent { present: true })
        );
        // A stamp with the flag clear: written by hand, since `assembled_full`
        // derives the flag from the `Option`.
        let mut bytes = assembled_full(0, &[], 0, &[], false, None, &[]);
        let stamp_at = bytes.len() - 8 - 8 - 2 - 1 - 4 /* last_seen_re_est */
            - 4 /* reroot_ratchet_gen */ - 4 /* attempt_at_window_start */
            - 8 /* floor seq */ - 4 /* floor generation */ - 8 /* the stamp itself */;
        bytes[stamp_at..stamp_at + 8].copy_from_slice(&ANCHOR.to_be_bytes());
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::RetentionHalfPresent { present: false })
        );
        // Positive control: both halves present, and the record carries them.
        let ok = ResumeRecord::decode(&assembled_full(0, &[], 0, &[], false, Some(ANCHOR), &[]))
            .expect("a well-formed retention decodes");
        assert_eq!(ok.retained().expect("retained").superseded_at_ms(), ANCHOR);
    }

    /// **A first establishment writes both slots empty and nothing retained.**
    ///
    /// [`ReEstState::first_establishment`] and [`Retention::none`] are that
    /// state written down, and the record round-trips out of it — so the
    /// smallest record this module can produce is a decodable one rather than a
    /// shape only the populated fixture reaches.
    #[test]
    fn a_first_establishment_record_round_trips() {
        let before = opening();
        let after = ResumeRecord::decode(&before.encode()).expect("decodes");
        assert!(after.own_slot().is_none());
        assert!(after.acceptance().is_none());
        assert!(after.retained().is_none());
        assert!(after.dedup().is_empty());
        assert!(!after.retained_but_stopped());
        assert_eq!(after.reconnect_gen(), 0);
        assert_eq!(after.attempt_at_window_start(), 0);
        assert_eq!(after.last_seen_re_est(), 0);
        assert_eq!(after.last_seen_re_ack(), 0);
    }

    /// **The two window bases are different numbers, each read from its own
    /// side of the exchange.**
    ///
    /// A `RE-EST` we receive was sealed under the peer's attempt counter, so its
    /// window is rooted at the acceptance slot (A6.1); a `RE-ACK` we receive
    /// answers one of our own attempts, so its window is rooted at our own
    /// counter. One derivation cannot serve both.
    ///
    /// Kills either accessor being aliased to the other: the fixture's two
    /// numbers differ, so a single derivation fails one of the four assertions.
    #[test]
    fn the_two_window_bases_read_opposite_sides_of_the_exchange() {
        let record = populated();
        assert_eq!(
            record.acceptance().expect("occupied").attempt().get(),
            5,
            "the fixture's acceptance attempt"
        );
        assert_eq!(
            record.attempt().expect("occupied").get(),
            7,
            "the fixture's own counter, which must differ from the acceptance's"
        );
        assert_eq!(record.last_seen_re_est(), 5, "the responder's base");
        assert_eq!(record.last_seen_re_ack(), 7, "the initiator's base");
        assert_eq!(opening().last_seen_re_est(), 0, "nothing accepted yet");
        assert_eq!(opening().last_seen_re_ack(), 0, "nothing attempted yet");
    }

    /// **An initiator's `RE-ACK` base survives an empty acceptance slot.**
    ///
    /// A party that has only ever initiated has accepted nothing, so the
    /// acceptance slot stands empty while its own counter is far from zero.
    /// Reading the `RE-ACK` window off the acceptance slot would put the base at
    /// `0` and every inbound `RE-ACK` outside `[0, MAX_GAP]` — A7.3's lockout
    /// arriving through the wrong accessor.
    ///
    /// Kills `last_seen_re_ack` derived from the acceptance slot, and kills it
    /// derived from the own *slot* rather than the counter, since the slot here
    /// is empty while the counter is not.
    #[test]
    fn an_initiators_re_ack_base_is_its_own_counter_not_the_empty_acceptance() {
        let two_c = 16;
        let record = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: 4,
                attempt: two_c,
                last_seen_re_est: 0,
                own: None,
                acceptance: None,
                attempt_at_window_start: 8,
                reroot_ratchet_gen: 0,
            },
            Retention::none(),
            SendFloor::new(0, 0),
        );
        assert!(record.acceptance().is_none(), "the fixture accepts nothing");
        assert!(record.own_slot().is_none(), "and holds no sealed frame");
        assert_eq!(record.last_seen_re_ack(), two_c);
        assert_eq!(record.last_seen_re_est(), 0, "and the other base is not it");
    }

    /// **The memory refuses a key past its bound rather than evicting one.**
    ///
    /// Evicting to make room would drop a key whose frame can still be replayed,
    /// which is the torn invariant the memory exists to hold.
    ///
    /// Kills an `insert` that drops the oldest entry at the bound: the length
    /// would stay at [`DEDUP_CAPACITY`] and the call would return `Ok`.
    #[test]
    fn the_dedup_memory_refuses_rather_than_evicting_at_its_bound() {
        let mut dedup = DedupMemory::new();
        for n in 0..DEDUP_CAPACITY {
            dedup
                .insert(dedup_key(u32::try_from(n).expect("small")))
                .expect("inside the bound");
        }
        assert_eq!(dedup.len(), DEDUP_CAPACITY);
        let overflow = dedup_key(u32::try_from(DEDUP_CAPACITY).expect("small"));
        assert_eq!(
            dedup.insert(overflow).err(),
            Some(ResumeError::DedupFull {
                capacity: DEDUP_CAPACITY
            })
        );
        assert_eq!(dedup.len(), DEDUP_CAPACITY, "nothing was evicted");
        assert!(!dedup.contains(overflow));
        // A repeat at the bound is still answered, because it needs no room.
        assert_eq!(
            dedup.insert(dedup_key(0)).expect("no room needed"),
            Novelty::Repeat
        );
    }

    /// **`DedupFull` is unreachable under the design's own attempt budget.**
    ///
    /// A5.3 scopes the memory to `RS_n`'s whole retention, and A6.1 rolls the
    /// window anchor over *inside* that retention — so one retained root sees
    /// `C` attempts per window for as many windows as the peer answers, not `C`
    /// in total. What bounds the set is
    /// [`ResumeRecord::evict_dedup_below_window`]: A5.2 has the scan
    /// *"rejecting anything beyond"* `[last_seen, last_seen + MAX_GAP]`, so an
    /// entry below its leg's base names a frame that can no longer open.
    ///
    /// Three windows of `C` attempts, three legs each, with the base advancing
    /// as the peer answers. Refusing a legitimate handshake frame is an outcome
    /// A3.15's table does not contain, so `insert` must never fail here.
    ///
    /// Kills `evict_dedup_below_window` doing nothing (the set fills and
    /// `insert` returns `DedupFull`) and kills it evicting too much (the final
    /// assertion requires the current window's positions still present).
    #[test]
    fn three_windows_of_attempts_never_fill_the_dedup_memory() {
        const C: u32 = 8;
        let legs = [Leg::ReEst, Leg::ReAck, Leg::ReConfirm];
        let mut record = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState::first_establishment(),
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup: DedupMemory::new(),
                stopped: false,
            },
            SendFloor::new(0, 0),
        );
        let mut recorded = 0usize;
        for window in 0..3u32 {
            for step in 1..=C {
                let attempt = window * C + step;
                let a = Attempt::from_nonzero(NonZeroU32::new(attempt).expect("non-zero"));
                for leg in legs {
                    record
                        .note_processed(DedupKey::new(1, a, leg, Direction::AToB, 0))
                        .expect("a legitimate handshake frame is never refused");
                    recorded += 1;
                }
            }
            // Both bases move together, because in a live exchange they do: a
            // `RE-ACK` we process answers an attempt we sealed, so receiving one
            // at attempt N means our own counter already reached N. The record
            // is rebuilt with both advanced — the shape a re-establishment
            // write has — and `new` runs the eviction.
            let base = (window + 1) * C;
            let carried = record.dedup().clone();
            record = ResumeRecord::new(
                s_pc(0x11),
                pk_pc(0x22),
                root(0x33),
                ReEstState {
                    attempt: base,
                    last_seen_re_est: base,
                    ..ReEstState::first_establishment()
                },
                Retention {
                    retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                    dedup: carried,
                    stopped: false,
                },
                SendFloor::new(0, 0),
            );
            assert_eq!(record.last_seen_re_est(), base);
            assert_eq!(record.last_seen_re_ack(), base);
            assert!(
                record.dedup().len() <= DEDUP_CAPACITY,
                "window {window} overflowed the bound"
            );
        }
        assert_eq!(
            recorded,
            3 * (3 * C) as usize,
            "the drive was shorter than claimed"
        );
        // Non-degenerate: eviction kept the current window rather than emptying
        // the set, and dropped the windows the scan can no longer reach.
        assert!(!record.dedup().is_empty(), "eviction emptied the memory");
        let last = Attempt::from_nonzero(NonZeroU32::new(3 * C).expect("non-zero"));
        assert!(
            record
                .dedup()
                .contains(DedupKey::new(1, last, Leg::ReEst, Direction::AToB, 0))
        );
        let first = Attempt::from_nonzero(NonZeroU32::new(1).expect("non-zero"));
        assert!(
            !record
                .dedup()
                .contains(DedupKey::new(1, first, Leg::ReEst, Direction::AToB, 0))
        );
    }

    /// **An entry at or above its leg's window base is kept; one below is
    /// dropped; and the two legs use different bases.**
    ///
    /// A `RE-CONFIRM` settles the attempt the acceptance named, so it is scanned
    /// against the `RE-EST` base; a `RE-ACK` answers one of our own attempts and
    /// is scanned against our own counter.
    ///
    /// **The memory holds one plane, and the other is refused.**
    ///
    /// A5.3's memory is receive-side: a party processes only what arrives, and
    /// everything that arrives is read from the plane the correspondent writes.
    /// A frame this side sealed itself is never processed, so a second direction
    /// is not a state the design produces — and admitting it would file our own
    /// attempt numbers in a set the peer's window base is used to bound, where
    /// the eviction's per-leg base is the wrong number for half the set.
    ///
    /// Kills the direction check being dropped from `insert`: the second plane's
    /// position would be admitted as novel.
    #[test]
    fn the_dedup_memory_admits_one_plane_and_refuses_the_other() {
        let at = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let mut dedup = DedupMemory::new();
        assert_eq!(dedup.direction(), None, "an empty memory names no plane");

        for leg in [Leg::ReEst, Leg::ReAck, Leg::ReConfirm] {
            assert_eq!(
                dedup
                    .insert(DedupKey::new(1, at(4), leg, Direction::AToB, 0))
                    .expect("room"),
                Novelty::Novel,
                "every leg is admitted on the established plane"
            );
        }
        assert_eq!(dedup.len(), 3);
        assert_eq!(dedup.direction(), Some(Direction::AToB));

        for leg in [Leg::ReEst, Leg::ReAck, Leg::ReConfirm] {
            assert_eq!(
                dedup
                    .insert(DedupKey::new(1, at(4), leg, Direction::BToA, 0))
                    .err(),
                Some(ResumeError::DedupDirectionMixed),
                "the other plane is refused for every leg"
            );
        }
        assert_eq!(dedup.len(), 3, "a refused position may not be recorded");
    }

    /// Kills an eviction that applies one base to every leg: the `RE-ACK` entry
    /// here sits below the `RE-EST` base and above its own, so a single-base
    /// eviction drops it.
    #[test]
    fn eviction_uses_each_legs_own_window_base() {
        let at = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let mut record = with_bases(opening(), 0, 4);
        for (attempt, leg) in [
            (9, Leg::ReEst),
            (10, Leg::ReEst),
            (9, Leg::ReConfirm),
            (10, Leg::ReConfirm),
            (3, Leg::ReAck),
            (4, Leg::ReAck),
        ] {
            record
                .note_processed(DedupKey::new(1, at(attempt), leg, Direction::AToB, 0))
                .expect("room");
        }
        assert_eq!(record.dedup().len(), 6, "the fixture must hold all six");
        assert_eq!(record.last_seen_re_ack(), 4);
        // Raising the `RE-EST` base is what evicts; there is no separate call.
        record.observe_accepted(at(10));
        assert_eq!(record.last_seen_re_est(), 10);
        let kept: Vec<(u32, Leg)> = record
            .dedup()
            .keys()
            .iter()
            .map(|k| (k.attempt().get(), k.leg()))
            .collect();
        assert_eq!(
            kept,
            vec![(10, Leg::ReEst), (10, Leg::ReConfirm), (4, Leg::ReAck)],
            "each leg must be cut at its own base"
        );
    }

    /// **The `RE-EST` window base holds across the completion that zeroes the
    /// acceptance slot.**
    ///
    /// A3.14 zeroes the slot on completion, so a base read from it would drop
    /// back to `0` and re-admit attempts the dedup memory has already evicted —
    /// A5.2's scan would open, at the same base, frames it had already rejected.
    /// A6.1 has the window slide forward only.
    ///
    /// Kills `last_seen_re_est` reading the acceptance slot: with the slot
    /// zeroed it would answer `0` rather than the value it held.
    #[test]
    fn the_re_est_base_survives_a_completion() {
        let accepted = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: 4,
                attempt: 0,
                last_seen_re_est: 0,
                own: None,
                acceptance: Some(acceptance_slot(5, 10, 0x66, 64)),
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup: DedupMemory::new(),
                stopped: false,
            },
            SendFloor::new(0, 0),
        );
        assert_eq!(
            accepted.last_seen_re_est(),
            10,
            "occupying the slot must raise the base"
        );

        // The completion: both slots zeroed, the generation advanced, the
        // retention carried across as the store carries it.
        let completed = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                reconnect_gen: 5,
                attempt: 0,
                last_seen_re_est: accepted.last_seen_re_est(),
                own: None,
                acceptance: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup: DedupMemory::new(),
                stopped: false,
            },
            SendFloor::new(0, 0),
        );
        assert!(completed.acceptance().is_none(), "the fixture completed");
        assert_eq!(
            completed.last_seen_re_est(),
            10,
            "the base regressed across the completion"
        );
        // And it survives the at-rest round trip, which is where a base that
        // lived only in the slot would be lost for good.
        let reloaded = ResumeRecord::decode(&completed.encode()).expect("decodes");
        assert_eq!(reloaded.last_seen_re_est(), 10);
    }

    /// **Building a record runs the eviction, so a rebuilt one is consistent
    /// with its own base.**
    ///
    /// A caller assembling a record from parts — the acceptance slot from one
    /// place, the carried-over dedup memory from another — can hand [`Self::new`]
    /// a base already past some of those positions. Leaving them would be a
    /// memory holding frames A5.2's scan rejects, and the next write that did
    /// evict them would look to the store like an unexplained shrink.
    ///
    /// Kills the eviction being dropped from [`Self::new`]: the below-base entry
    /// would still be present in the record it returns.
    #[test]
    fn building_a_record_evicts_what_its_base_has_passed() {
        let at = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let mut dedup = DedupMemory::new();
        for attempt in [2, 9] {
            dedup
                .insert(DedupKey::new(
                    1,
                    at(attempt),
                    Leg::ReEst,
                    Direction::AToB,
                    0,
                ))
                .expect("room");
        }
        assert_eq!(dedup.len(), 2, "the fixture offers both");

        let record = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState {
                last_seen_re_est: 9,
                ..ReEstState::first_establishment()
            },
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup,
                stopped: false,
            },
            SendFloor::new(0, 0),
        );

        assert_eq!(record.last_seen_re_est(), 9);
        assert_eq!(
            record.dedup().len(),
            1,
            "the constructor left an entry its own base has passed"
        );
        assert!(
            record
                .dedup()
                .contains(DedupKey::new(1, at(9), Leg::ReEst, Direction::AToB, 0))
        );
    }

    /// **Raising the base is what evicts; there is no second call to forget.**
    ///
    /// The store refuses a commit that drops a dedup position at or above the
    /// base and licenses one below it, so the base and the eviction are one
    /// invariant read twice. A base that moved without the eviction leaves
    /// entries the memory no longer needs; an eviction without the base having
    /// moved is a shrink the store refuses.
    ///
    /// Kills `observe_accepted` raising the base without evicting: the entry
    /// below the new base would still be present afterwards.
    #[test]
    fn raising_the_base_evicts_without_a_separate_call() {
        let at = |n: u32| Attempt::from_nonzero(NonZeroU32::new(n).expect("non-zero"));
        let mut record = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            ReEstState::first_establishment(),
            Retention {
                retained: Some(RetainedRoot::new(root(0x55), ANCHOR)),
                dedup: DedupMemory::new(),
                stopped: false,
            },
            SendFloor::new(0, 0),
        );
        for attempt in [3, 9] {
            record
                .note_processed(DedupKey::new(
                    1,
                    at(attempt),
                    Leg::ReEst,
                    Direction::AToB,
                    0,
                ))
                .expect("room");
        }
        assert_eq!(record.dedup().len(), 2, "the fixture holds both");

        record.observe_accepted(at(9));

        assert_eq!(record.last_seen_re_est(), 9);
        assert_eq!(
            record.dedup().len(),
            1,
            "the below-base entry was not evicted"
        );
        assert!(
            record
                .dedup()
                .contains(DedupKey::new(1, at(9), Leg::ReEst, Direction::AToB, 0))
        );

        // An observation at or below the base is inert, so a stale one cannot
        // evict anything.
        record.observe_accepted(at(4));
        assert_eq!(
            record.last_seen_re_est(),
            9,
            "a stale observation moved the base"
        );
        assert_eq!(record.dedup().len(), 1);
    }

    /// **A frame of zero length is refused at construction, by both slots.**
    ///
    /// An occupied slot exists to hold the bytes a re-emit or a re-serve sends.
    /// An empty one encodes without complaint and then fails
    /// [`ResumeRecord::decode`] for ever, which wedges `commit_resume`
    /// permanently — every later write reads the stored record first.
    ///
    /// Kills either constructor checking only its upper bound.
    #[test]
    fn neither_slot_accepts_an_empty_frame() {
        assert_eq!(
            SealedReEst::seal(FreshAttempt::first(), Vec::new().into_boxed_slice()).err(),
            Some(ResumeError::EmptyFrame)
        );
        assert_eq!(
            AcceptanceSlot::accept(1, Attempt::FIRST, Vec::new().into_boxed_slice()).err(),
            Some(ResumeError::EmptyFrame)
        );
        // Positive control: one byte is enough, so the guard is on emptiness
        // rather than on some larger floor.
        assert!(SealedReEst::seal(FreshAttempt::first(), vec![1u8].into_boxed_slice()).is_ok());
        assert!(AcceptanceSlot::accept(1, Attempt::FIRST, vec![1u8].into_boxed_slice()).is_ok());
    }

    /// **The acceptance slot's own length ceiling is enforced and is reachable.**
    ///
    /// [`MAX_SEALED_LEG_LEN`] rather than [`MAX_FRAME_LEN`]: two slots sized at
    /// the frame ceiling do not fit
    /// [`crate::storage::dm_store::RESUME_CAPACITY`].
    ///
    /// Kills the bound being dropped from `accept`, and kills it being widened
    /// to `MAX_FRAME_LEN` — the refusal is asserted one byte over.
    #[test]
    fn the_acceptance_slot_refuses_a_frame_past_its_own_ceiling() {
        let too_long = MAX_SEALED_LEG_LEN + 1;
        assert_eq!(
            AcceptanceSlot::accept(
                1,
                Attempt::FIRST,
                pattern(0x66, too_long).into_boxed_slice()
            )
            .err(),
            Some(ResumeError::FrameTooLong { len: too_long })
        );
        // Positive control: exactly the ceiling is accepted, so the assertion
        // above is an off-by-one boundary rather than a blanket refusal.
        assert!(
            AcceptanceSlot::accept(
                1,
                Attempt::FIRST,
                pattern(0x66, MAX_SEALED_LEG_LEN).into_boxed_slice()
            )
            .is_ok()
        );
    }

    /// **The acceptance frame's length prefix is checked against the acceptance
    /// ceiling, before anything is reserved.**
    ///
    /// The own frame's prefix is checked against [`MAX_FRAME_LEN`] and the
    /// acceptance frame's against [`MAX_SEALED_LEG_LEN`], which is four times
    /// smaller. A decoder checking both against the larger number would reserve
    /// up to four times the acceptance slot's real ceiling from a corrupt
    /// length.
    ///
    /// Kills the acceptance prefix being bounded by `MAX_FRAME_LEN`: the patched
    /// length below sits between the two ceilings, so it is refused only under
    /// the correct one.
    #[test]
    fn a_corrupt_acceptance_length_is_refused_at_its_own_ceiling() {
        let record = opening();
        assert!(record.dedup().is_empty(), "the offset below assumes it");
        let over = MAX_SEALED_LEG_LEN + 1;
        assert!(
            over < MAX_FRAME_LEN,
            "the case must lie between the ceilings"
        );
        let mut bytes = record.encode();
        // The acceptance prefix is the last fixed field, and the own frame is
        // empty in this record.
        let len_at = FIXED_LEN - 8;
        bytes[len_at..len_at + 8].copy_from_slice(&(over as u64).to_be_bytes());
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::FrameTooLong { len: over })
        );
    }

    /// **A slot standing empty may not name a generation, in either slot.**
    ///
    /// An empty slot is attempt `0`, a zero-length frame and a zero generation:
    /// there is no exchange for a generation to name, so a value read back out
    /// of one would be something nothing wrote and nothing checks.
    ///
    /// Kills a decoder that reads either slot's generation without consulting
    /// the attempt beside it.
    #[test]
    fn the_decoder_refuses_a_generation_on_an_empty_slot() {
        // `assembled_full` derives each slot's generation from its attempt, so
        // the contradiction is written by hand.
        let base = assembled_full(0, &[], 0, &[], false, None, &[]);
        let own_gen_at = RESUME_MAGIC.len() + SUITE_ID_LEN + ml_dsa::SK_LEN + ml_dsa::PK_LEN
            + ROOT_KEY_LEN + 4 /* reconnect_gen */ + 4 /* attempt counter */;
        let acc_gen_at = own_gen_at + 4 /* own slot generation */ + 4 /* own slot attempt */
            + 8 /* own slot seq */ + 1 /* ephemeral key present */ + ml_kem::DK_LEN;
        for (offset, generation) in [(own_gen_at, 10u32), (acc_gen_at, 8u32)] {
            let mut bytes = base.clone();
            bytes[offset..offset + 4].copy_from_slice(&generation.to_be_bytes());
            assert_eq!(
                ResumeRecord::decode(&bytes).err(),
                Some(ResumeError::SlotGenerationWithoutAttempt { generation })
            );
        }
        // Positive control: untouched, the same buffer decodes.
        assert!(ResumeRecord::decode(&base).is_ok());
    }

    /// **Retained root bytes under a clear presence flag are refused.**
    ///
    /// [`ResumeRecord::encode`] writes the absent case as an all-zero root, so
    /// non-zero bytes under a clear flag are a retained root the flag hides or a
    /// flag the bytes contradict — and nothing here can say which.
    ///
    /// Kills a decoder that reads the flag and ignores the bytes.
    #[test]
    fn the_decoder_refuses_retained_bytes_under_a_clear_flag() {
        let mut bytes = assembled_full(0, &[], 0, &[], false, None, &[]);
        let root_at = RESUME_MAGIC.len()
            + SUITE_ID_LEN
            + ml_dsa::SK_LEN
            + ml_dsa::PK_LEN
            + ROOT_KEY_LEN
            + 4 /* reconnect_gen */
            + 4 /* attempt counter */
            + 4 /* own slot generation */
            + 4 /* own slot attempt */
            + 8 /* own slot seq */
            + 1 /* ephemeral key present */
            + ml_kem::DK_LEN
            + 4 /* acceptance generation */
            + 4 /* acceptance attempt */
            + 1 /* acceptance confirmed */
            + 1 /* retained present */;
        bytes[root_at..root_at + ROOT_KEY_LEN].copy_from_slice(&pattern(0x55, ROOT_KEY_LEN));
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::RetainedBytesWithoutFlag)
        );
    }

    /// **The same dedup position twice in one record is refused.**
    ///
    /// Accepting it would decode to a set one entry smaller than the bytes hold,
    /// so the record would re-encode to bytes it was not read from — and the
    /// length the eviction bound is checked against would disagree with disk.
    ///
    /// Kills a decoder that lets `insert`'s `Repeat` pass silently.
    #[test]
    fn the_decoder_refuses_a_duplicate_dedup_entry() {
        let entry = (100u32, 200u32, 1u8, 1u8, 300u64);
        assert_eq!(
            ResumeRecord::decode(&assembled_full(
                0,
                &[],
                0,
                &[],
                false,
                None,
                &[entry, entry]
            ))
            .err(),
            Some(ResumeError::DuplicateDedupEntry)
        );
        // Positive control: two DISTINCT entries decode, and both land.
        let other = (101u32, 201u32, 2u8, 1u8, 301u64);
        let ok = ResumeRecord::decode(&assembled_full(
            0,
            &[],
            0,
            &[],
            false,
            None,
            &[entry, other],
        ))
        .expect("distinct entries decode");
        assert_eq!(ok.dedup().len(), 2);
    }

    /// **An own slot whose attempt disagrees with the counter is refused at
    /// decode.**
    ///
    /// A9.2 lists the counter and the sealed frame bytes as separate fields, and
    /// A8.1's commit-then-emit writes both in one act, so they agree or the
    /// record is one no honest writer produced. A record whose slot disagreed
    /// would re-emit under a key neither number names.
    ///
    /// Kills a decoder that takes the two numbers from their own byte ranges
    /// without comparing them.
    #[test]
    fn the_decoder_refuses_a_slot_that_disagrees_with_the_counter() {
        let frame = pattern(0x44, 64);
        let mut bytes = assembled_full(7, &frame, 0, &[], false, None, &[]);
        let counter_at =
            RESUME_MAGIC.len() + SUITE_ID_LEN + ml_dsa::SK_LEN + ml_dsa::PK_LEN + ROOT_KEY_LEN + 4;
        bytes[counter_at..counter_at + 4].copy_from_slice(&9u32.to_be_bytes());
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::AttemptSlotDisagrees { field: 9, slot: 7 })
        );
        // Positive control: untouched, the agreeing pair decodes.
        assert!(ResumeRecord::decode(&assembled_full(7, &frame, 0, &[], false, None, &[])).is_ok());
    }
    /// **The hand-written `Zeroize` for the retention group wipes the retained
    /// root and its stamp.**
    ///
    /// `RetainedRoot` cannot use the derive: it holds a `CommittedRoot` beside a
    /// plain `i64`, and a derived impl over a group whose secret sits behind an
    /// `Option` is not what the record needs. A hand-written impl is one a later
    /// edit can empty out, and the retained root is what lets a party open the
    /// peer's frames at the superseded generation (A3.5) — as secret as the
    /// committed one.
    ///
    /// Kills `Zeroize for Retention` dropping any of its fields: each is
    /// asserted and each is non-default going in. It does **not** kill an
    /// emptied `Zeroize for RetainedRoot`, and the reason is the assertion
    /// rather than the reachability — `Option::zeroize` takes the option after
    /// delegating, so `retained` reads `None` whatever the delegated body did.
    /// The test below asserts the bytes instead.
    #[test]
    fn zeroizing_the_retention_group_wipes_the_retained_root() {
        let mut retention = full_retention();
        assert!(
            retention
                .retained
                .as_ref()
                .expect("the fixture retains")
                .root()
                .as_bytes()
                .iter()
                .any(|b| *b != 0),
            "the root is all-zero before the wipe, so wiping it proves nothing"
        );
        assert_eq!(
            retention
                .retained
                .as_ref()
                .expect("the fixture retains")
                .superseded_at_ms(),
            ANCHOR,
            "the stamp is unset before the wipe"
        );
        assert_eq!(retention.dedup.len(), 3, "the memory is populated");
        assert!(retention.stopped, "the flag is set");

        retention.zeroize();

        // `Option::zeroize` wipes the payload and then drops it, so the root is
        // gone rather than present-and-zero — which is the stronger of the two.
        assert!(retention.retained.is_none(), "the retained root survived");
        assert!(retention.dedup.is_empty(), "the memory survived");
        assert!(!retention.stopped, "the flag survived");
    }

    /// **A [`RetainedRoot`] zeroized directly wipes both of its halves.**
    ///
    /// A derive would leave the `i64` stamp alone, so the impl is written out.
    /// The group-level test above cannot pin it: `Option::zeroize` delegates and
    /// then takes the option, so `retained` reads `None` whether the delegated
    /// body wiped anything or not. Asserting the bytes needs a value that is
    /// still there afterwards, which means calling it directly.
    ///
    /// Kills the body being emptied, and kills a body that wipes the root and
    /// leaves the stamp: both halves are asserted, and both are non-zero going
    /// in.
    #[test]
    fn zeroizing_a_retained_root_wipes_its_root_and_its_stamp() {
        let mut retained = RetainedRoot::new(root(0x55), ANCHOR);
        assert!(
            retained.root().as_bytes().iter().any(|b| *b != 0),
            "the root is all-zero before the wipe, so wiping it proves nothing"
        );
        assert_ne!(retained.superseded_at_ms(), 0, "the stamp is unset");

        retained.zeroize();

        assert!(
            retained.root().as_bytes().iter().all(|b| *b == 0),
            "the retained root survived the wipe"
        );
        assert_eq!(
            retained.superseded_at_ms(),
            0,
            "the stamp survived the wipe"
        );
    }
}
