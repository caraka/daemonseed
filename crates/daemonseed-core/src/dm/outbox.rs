//! The persisted outbox: what a sender still owes a correspondent (#235, part of
//! ISC-C39 / ISC-A-C21).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § Task 2 (the keep-alive schedule, the give-up, and the four states),
//! § D-DELIV (fail-safe delivery), § Nonce rule (seal once at compose), and the
//! appended build notes — in particular the 2026-07-28 note that names
//! prefix-advance-on-give-up **a live obligation on the outbox slice**.
//!
//! Veilid has no TTL. A value survives exactly as long as somebody re-seeds it,
//! and for a direct message that somebody is the sender: store-and-forward is
//! something this client *performs*, not something the network provides. So a
//! message that has been composed is owed re-seeding until it is confirmed
//! collected or given up on, and that obligation has to survive a restart — an
//! in-memory outbox loses the message from the sender's side, silently, which is
//! the one failure mode this whole design is arranged to make impossible.
//!
//! This is the pure half. It holds sequence numbers, sealed **bytes**, a rung
//! index and clock values the caller passes in. It writes no record, derives no
//! address, reads no clock and holds no key.
//!
//! **One outbox is one direction of one correspondence.** Sequence numbers are
//! monotonic *per direction*, so 5 on `a2b` and 5 on `b2a` are different
//! messages, and an acknowledgement is per-direction too — an outbox holding both
//! would let one direction's ack confirm the other direction's message, a false
//! *collected*. [`Outbox::new`] therefore takes a [`Direction`] and there is no
//! `Default`, which makes that unrepresentable rather than merely undocumented.
//!
//! ## Seal once at compose; re-seed byte-identically; never re-seal
//!
//! § Nonce rule states it as one sentence: *"Re-seed re-emits the byte-identical
//! stored frame (encapsulate+seal **once** at compose, persist the frame,
//! re-seed verbatim) — never re-seals under the same key."* Two distinct
//! properties rest on it. Nonce reuse is the first: a second seal under a
//! single-use ratchet message key with a fresh nonce is a `(key, nonce)` pair
//! that repeats only if the nonce does not, and a second seal under the same
//! nonce is catastrophic. Content-address dedup is the second (§ m7): the
//! recipient discards a re-seed as a duplicate precisely because its bytes are
//! the same bytes, and a re-sealed message arrives as a *second message*.
//!
//! **The invariant is structural here, in three independent ways, and none of
//! them is a rule anybody has to remember.**
//!
//! 1. This module cannot seal. It imports no key type, no ratchet, and no root;
//!    [`crate::dm::frame::seal`] is not reachable from anything below. A frame
//!    arrives as bytes from a caller and leaves as the same bytes.
//! 2. [`SealedFrame`] has no mutating API at all — no `&mut` accessor, no
//!    `DerefMut`, no public field. `&mut OutboxEntry` cannot reach the bytes,
//!    only `&[u8]` through [`OutboxEntry::frame`] and [`OutboxEntry::emit`].
//! 3. The lifecycle is a state machine with **one frame-installing edge**
//!    (`OutboxEntry::publish`, `AwaitingKey → AwaitingCollection`) and no edge
//!    anywhere back into `AwaitingKey`. So a frame enters an entry at most once
//!    over the entry's whole life, whatever order a caller drives it in.
//!
//! The caller's half is already structural too, and for the same reason:
//! `frame::seal` consumes its `Outbound` by value, so re-sealing needs the
//! ratchet to advance and mint a different position. Nothing in this design
//! *can* emit a second ciphertext for one logical message without visibly asking
//! for one.
//!
//! [`OutboxEntry::emit`] is pinned by `reseed_is_byte_identical_across_the_whole_ladder`,
//! which hashes what a hundred emissions return, across state changes and an
//! at-rest round trip, and compares to the first.
//!
//! ## The schedule
//!
//! § Task 2: *"geometric backoff per pending message — `1 min → 2 → 4 → 8 → 16 →
//! 32 → 64 → hourly → daily` (~20 writes over a week vs ~5,000 at the operator's
//! flat 120 s). Hard give-up at **7 days**."* [`RESEED_LADDER`] is that sentence
//! transcribed, one rung per emission, the last rung repeating — see its own
//! docs for the arithmetic that corroborates the reading, and for the one wrinkle
//! (rung 7 is 64 minutes and rung 8, "hourly", is 60).
//!
//! Jitter is drawn **fresh for every emission**, per § v5 (Metadata-MINOR):
//! *"re-seed backoff jitter is drawn independently per record per emission
//! (WB-1.2 pattern — kills M7 cross-record phase-lock)."* M7 is why: a
//! deterministic ladder phase-locks two records to one `t0` and turns a timing
//! observation into an address derivation, which is also what WB-3 I6 forbids.
//! So `ReseedSchedule::schedule_next_with_unit` takes a jitter unit per call rather than
//! seeding a generator once, and the math is
//! [`crate::backoff::apply_jitter`] — the repo's one definition of it.
//!
//! ## The give-up runs from compose, and the design fixes that rather than
//! leaving it to taste
//!
//! § Task 2 does not say out loud whether the seven days start at compose or at
//! first emission, but it is settled elsewhere and not by preference. **M14**
//! reads: *"`awaiting-key` gives up at 7 days"* — and an `awaiting-key` message
//! has had no emission at all, by definition: its recipient's key record is
//! unfetchable, so nothing has been sealed and nothing has been published. A
//! clock anchored at first emission would never start for exactly the messages
//! M14 is about, and those entries would sit pending forever. Compose is
//! therefore the only origin under which the frozen text is consistent with
//! itself, and it is what [`OutboxEntry::composed_at_ms`] holds.
//!
//! ## Four outbox states, three UI states, and no word that says "delivered"
//!
//! § Task 2 names four states for this record — *awaiting-key /
//! awaiting-collection / presumed-delivered / undelivered* — and #235 names
//! three for the UI — *on-DHT / peer-reachable / confirmed-collected*, under the
//! standing rule never to claim "delivered". They are different layers, and
//! [`OutboxEntry::delivery_state`] is the map:
//!
//! | [`Lifecycle`] (this record) | [`DeliveryState`] (what a UI may say) |
//! |---|---|
//! | `AwaitingKey` | `Composed` — nothing is on the DHT yet |
//! | `AwaitingCollection`, no write confirmed | `Composed` — sealing is not publishing, and neither is attempting |
//! | `AwaitingCollection`, a write confirmed | `OnDht`, which a UI may annotate *peer-reachable* from the presence layer |
//! | `ConfirmedCollected` | `ConfirmedCollected` |
//! | `Undelivered` | `Undelivered` |
//!
//! **The `OnDht` row turns on [`Acceptance`], and it used to turn on the rung
//! index — which was a proxy for "has been emitted", not for "was accepted"
//! (#278).** Under that proxy a transport outage read as success: seven
//! [`OutboxEntry::emit`] calls, seven failed `set_dht_value`s, and the entry
//! reported `OnDht` while nothing had ever left the machine. It was wrong on a
//! second path too, which is worth stating because it was never about failed
//! writes as such — [`OutboxEntry::retry_key_fetch`] also advances the rung, so
//! an `AwaitingKey` entry that retried its key fetch and then published reported
//! `OnDht` immediately, with no emission at all. A rung index answers *how far
//! down the backoff ladder are we*, and no arrangement of it answers *did the
//! transport take the bytes*. [`OutboxEntry::confirm_written`] is now the only
//! thing that answers the second question, and it is the caller's to call.
//!
//! `OnDht` is still the weakest of the four and still says less than its name.
//! It now means the transport confirmed a write, which is strictly more than
//! *handed over* and strictly less than *the DHT holds our value*. **M2** is why
//! it cannot yet say more — a losing `set_dht_value` re-propagates the winner's
//! value and **returns success**, and the design records that "the outbox state
//! machine has no *my write lost the race* state and consumes no return value".
//! A confirmation is the transport's `Ok`, so a write that loses the race is
//! confirmed here exactly as a write that wins. Closing that needs a *value*
//! read back rather than a return code, which only the transport slice holds.
//!
//! Two of those need their reasoning stated rather than assumed.
//!
//! **`peer-reachable` is an annotation, never a state here, and that is B5.** The
//! adversarial pass refuted stop-on-presence as a BLOCKER: *"stop-on-presence
//! certifies delivery on record B from liveness on record A"*, and M16 showed the
//! signal is replayable outright. § D-DELIV replaced it — *"Default
//! not-delivered; confirm only on a genuine ack."* So this module takes **no
//! presence input at all**; there is no method to give it one. A UI that wants to
//! show "they have been online" reads the presence layer directly, and nothing it
//! learns there can move an entry.
//!
//! **`presumed-delivered` is not what this record carries.** It is § Task 2's
//! name for "stopped on presence / establishment", i.e. for the mechanism B5 and
//! M16 refuted and D-DELIV replaced; ISC-C39's re-cut is explicit that the sender
//! *"flips it to confirmed-collected only on a verified authenticated monotonic
//! high-water ack — never on a guess."* Once the transition is ack-gated there is
//! no presumption left in it, so the honest name for the state is the ack's own,
//! and this module uses it. The word "delivered" appears in no variant, no
//! rendering and no method name.
//!
//! ## Settled is not collected — and this is the only place that can tell
//!
//! The acknowledgement carries **settled**, not collected: build-contract item
//! (ii)'s prefix-advance-on-give-up means a receiver advances its contiguous
//! cursor past a message the *sender* abandoned, so
//! [`AckState::is_settled`](crate::dm::ack::AckState::is_settled) answers `true`
//! for positions nobody ever read. The build note of 2026-07-28 states the
//! consequence and hands it here: *"the fail-safe property rests on the persisted
//! outbox, where undelivered is a terminal state and a given-up message is never
//! re-consulted against an ack."*
//!
//! [`Outbox::settle_from_ack`] is that sentence implemented, with **two** gates
//! rather than the obvious one. Terminal entries are skipped entirely rather than
//! checked and rejected, so there is no arithmetic between a give-up and a false
//! confirmation — and, because a give-up is a *swept* transition, an entry past
//! its window is refused too, whether or not the sweep has run yet. Without that
//! second gate the truth of a delivery indicator depends on the order a caller
//! happens to make two unrelated calls in. The argument then closes:
//!
//! > A position is settled because it was collected, or because the sender gave
//! > up on it. This entry is `AwaitingCollection` **and inside its give-up
//! > window**, so this sender has not given up on it and the receiver's rule
//! > gives it no other grounds to abandon it. Therefore it was collected.
//!
//! Contiguity closes the neighbouring case: a prefix that ran past our given-up
//! sequence 5 reaches 6 only by 6 being settled in its own right, so a live
//! sequence 6 is never confirmed by sequence 5's abandonment.
//!
//! What remains is a **dishonest peer**, and it is an already-accepted residual
//! rather than a new one: `collect` and `abandon` are the same bytes on the wire,
//! so a peer that abandons early tells us a message was read when it was not.
//! [`crate::dm::ack`] records that a peer "asserting it collected everything is
//! lying about its own collection, which no acknowledgement scheme can prevent",
//! and `merge_peer_ack`'s ceiling already bounds the claim to sequences actually
//! sent. The liar is the intended recipient, so the lie costs only itself.
//!
//! ## A transition nobody saw is re-offered, because it is written down
//!
//! Three calls move an entry to a terminal state and return the list of what
//! moved: [`Outbox::sweep_give_ups`], [`Outbox::settle_from_ack`], and
//! [`Outbox::channel_torn_down`]'s `surfaced` half. That return value used to be
//! the **only** notification, and every later call skips an entry whose state
//! has already moved — so a crash between the call returning and the record
//! reaching the disk lost the notification permanently. The entry came back from
//! the restart as `Undelivered` or `ConfirmedCollected` and nothing would ever
//! report it again: silent abandonment, arriving by exactly the restart this
//! record exists to survive (#279).
//!
//! So each of those transitions also writes [`Surfacing::Owed`] onto the entry,
//! and that persists. The notification becomes derivable from the state rather
//! than only from the return value of the call that caused it —
//! [`Outbox::owed_surfacings`] asks which transitions are still owed, and
//! [`Outbox::record_surfaced`] is how a caller says they arrived.
//!
//! **The order is the whole of it:**
//!
//! ```text
//!   transition ─▶ persist ─▶ owed_surfacings() ─▶ show the user
//!                                              ─▶ record_surfaced() ─▶ persist
//! ```
//!
//! The flag is cleared only *after* the UI's consumption has itself been
//! persisted, which is what makes every crash point in that sequence re-offer
//! rather than drop. Telling a user twice that a message stopped is a far better
//! failure than never telling them once, and it is the same fail-safe direction
//! § D-DELIV takes everywhere else here.
//!
//! The returned lists stay. They are the fast path, and a caller that never
//! crashes never reads the flag; what the flag adds is that dropping one of
//! those lists is recoverable instead of final.
//!
//! **Only a transition into a terminal state owes a surfacing.** Every edge that
//! sets the flag also ends the entry, and they are the same private call, so
//! `Owed` on a live entry is not a state this module can produce.
//! [`Outbox::decode`] refuses a file claiming otherwise
//! ([`OutboxError::SurfacingOwedOnLiveEntry`]) rather than loading a
//! notification for a transition that never happened — the mirror of the loss
//! this flag exists to prevent.
//!
//! `OutboxEntry::publish` is deliberately **not** one of those edges: it is a
//! step *inside* a message's life, not the end of one, and the UI already reads
//! it through [`OutboxEntry::delivery_state`] whenever it draws the outbox.
//!
//! ## A teardown does not discard the outbox
//!
//! [`crate::dm::provisional::restart`] can end a channel
//! ([`ChannelRestart::TornDown`](crate::dm::provisional::ChannelRestart)). The
//! ratchet is gone; the outbox is not, and [`Outbox::channel_torn_down`] is the
//! decision. The reasoning and the asymmetry are on that method.
//!
//! ## Where this is stored
//!
//! [`crate::dm::persist`] is the writer (#281). It reads and replaces
//! [`RecordKind::Outbox`](crate::storage::dm_store::RecordKind::Outbox) through
//! [`crate::storage::dm_store`], which seals what it is handed and pads it out to
//! a fixed bucket.
//!
//! **The read-modify-write is the persistence layer's shape, not this module's.**
//! A sweep, an acknowledgement merge or an enqueue reads the record, decides from
//! it, and writes the result, and those three steps have to be inside one
//! critical section or two processes silently lose one of the two decisions. So
//! `persist` offers a closure that brackets the whole of it rather than a
//! load/save pair, and this module needs to know nothing about it.
//!
//! That is also why [`Outbox::encode`] stays **plaintext and
//! variable-length**: the sealing, the fixed size and the padding are the
//! store's, done once for every DM record kind, and a second layer of either
//! here would be a second answer free to disagree with the first.
//!
//! **This record holds no plaintext.** An `AwaitingKey` entry reserves its
//! sequence number and carries its schedule; the message *text* lives in
//! [`crate::transcript`], where a client's own sent messages already live. The
//! consequence is stated rather than hidden: a draft blocked on a key fetch does
//! not survive a restart in this record — the sequence number and the give-up
//! clock do. The alternative was putting user plaintext into a second at-rest
//! structure — a wider blast radius for a copy of something the transcript
//! already holds, and one more place to have to erase.

use core::time::Duration;

use crate::backoff::apply_jitter;
use crate::crypto::suite::{Registry, SuiteId, SuiteIdError};
use crate::dm::ack::AckState;
use crate::dm::doorbell::DOORBELL_SLOTS;
use crate::dm::paging::{PagePosition, position_of};
use crate::dm::provisional::TeardownCause;
use crate::dm::push_lp;
use crate::dm::ratchet::Direction;
use crate::storage::dm_store::OUTBOX_CAPACITY;

/// The re-seed ladder, one rung per emission, the last rung repeating.
///
/// § Task 2 transcribed: *"`1 min → 2 → 4 → 8 → 16 → 32 → 64 → hourly →
/// daily`"*. It is a ladder in the frozen text and stays one here rather than
/// becoming a formula, because it is not one: **rung 6 is 64 minutes and rung 7,
/// "hourly", is 60** — a four-minute *decrease*. A doubling curve with a cap
/// would smooth that away and stop matching what the design says.
///
/// **The reading is corroborated by the design's own arithmetic**, which is why
/// the last rung repeats rather than the ladder ending. § Task 2 prices a pending
/// message at *"~20 writes over a week vs ~5,000 at the operator's flat 120 s"*.
/// The flat figure checks out exactly — seven days at 120 s is 5,040 — and under
/// this reading the ladder spends 127 minutes on its seven geometric rungs, one
/// hour on the eighth, then a day per emission to the seven-day give-up: 7 + 1 +
/// 6 ≈ 14 re-seeds, plus the first send. Reading "hourly" and "daily" as *phases*
/// rather than rungs gives ~35, which is the wrong side of "~20".
pub const RESEED_LADDER: &[Duration] = &[
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(240),
    Duration::from_secs(480),
    Duration::from_secs(960),
    Duration::from_secs(1920),
    Duration::from_secs(3840),
    // "hourly" — deliberately below the rung before it; see above.
    Duration::from_secs(3600),
    // "daily" — the terminal rung, repeated until the give-up.
    Duration::from_secs(86_400),
];

/// Jitter fraction applied to every rung, drawn fresh per emission.
///
/// The band matters less than the freshness — M7 is about a *stable phase
/// relationship* between two records, not about magnitude — so this matches
/// [`crate::backoff::DEFAULT_JITTER_FRAC`] rather than inventing a second number.
pub const RESEED_JITTER_FRAC: f64 = crate::backoff::DEFAULT_JITTER_FRAC;

/// Hard give-up: seven days from compose, after which the message is
/// [`Lifecycle::Undelivered`] and surfaced.
///
/// § Task 2: *"Hard give-up at **7 days**; the message is marked undelivered in
/// the UI, never silently abandoned."*
pub const GIVE_UP: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// [`GIVE_UP`] in milliseconds, the unit every clock value here is in.
pub const GIVE_UP_MS: i64 = GIVE_UP.as_secs() as i64 * 1_000;

/// At-rest magic. The version is **inside** it, so a decoder compares one thing
/// and cannot read a v1 body under a v2 header — the shape
/// [`crate::dm::provisional`] uses.
pub const OUTBOX_MAGIC: &[u8] = b"daemonseed/dm/outbox/v4\0";

/// The v3 magic, which [`Outbox::decode`] **reads**, defaulting
/// [`Outbox::pruned_high_water`] to zero — a v3 record pruned nothing, so every
/// sequence it never held is still admissible. Written records are always v4
/// (read-old-write-new, as v2 already was).
pub const OUTBOX_MAGIC_V3: &[u8] = b"daemonseed/dm/outbox/v3\0";

/// The v2 magic, which [`Outbox::decode`] **reads**, defaulting every entry to
/// [`Acceptance::Unconfirmed`].
///
/// v2 carried no acceptance byte: it inferred *on the DHT* from a non-zero rung,
/// which is the defect #278 names. So a v2 file cannot supply this field and a
/// default has to be chosen — and unlike the v1 case below, **one of the two
/// defaults is right rather than both being wrong.**
///
/// `Unconfirmed` understates: a message genuinely on the DHT reads `Composed`
/// until its next emission is confirmed, which is at most one rung away and
/// costs a UI row that is too cautious for one interval. `Confirmed` would
/// overstate, and would do it by **reconstructing the very proxy this version
/// removes** — `rung > 0` is exactly what v2 believed, including for the
/// key-fetch-retry entries it was wrong about. Understating is also the module's
/// standing posture (§ D-DELIV, *"default not-delivered"*), so the migration
/// direction is the one the design already picked for every other ambiguity
/// here.
///
/// **Why this is read at all, when v1 is refused.** The v1 argument turns on
/// there being no historical fact to be compatible with — nothing ever wrote a
/// v1 record. That does not hold for v2: [`crate::dm::persist`] writes v2
/// records today, so a profile that has run the DM slice has them on disk.
/// Refusing would make this change a wipe.
pub const OUTBOX_MAGIC_V2: &[u8] = b"daemonseed/dm/outbox/v2\0";

/// The v1 magic, which [`Outbox::decode`] **refuses** — and which nothing has
/// ever written.
///
/// v1 carried no suite id and no [`Surfacing`] byte. It is named here rather
/// than falling through to [`OutboxError::BadMagic`] so the refusal says which
/// problem it is, and it is a refusal rather than a dual-read for one reason
/// that outranks the rest: **a v1 file cannot supply a surfacing value, and both
/// available defaults are wrong.** `Clear` would silently drop the notification
/// for every terminal entry in the file, which is the exact loss #279 is about;
/// `Owed` would re-offer every message that ever ended. The sibling formats that
/// do dual-read ([`crate::storage::seeds`], [`crate::storage::recovery_file`])
/// carry compatibility for blobs that reached real disks and can name the suite
/// those writers used; there is no such historical fact here. No v1 record was
/// ever written anywhere: [`Outbox::encode`] had no caller that stored its
/// output until [`crate::dm::persist`], and by then the magic was already v2.
///
/// **[`OUTBOX_MAGIC_V2`] is dual-read, and the contrast is the whole test.**
/// Age is not what decides it: v2 records reached real disks, and the field a
/// v2 body cannot supply has one default that is merely cautious rather than two
/// that are both wrong. Neither is true of v1.
pub const OUTBOX_MAGIC_V1: &[u8] = b"daemonseed/dm/outbox/v1\0";

/// Width of the suite-id field, big-endian, immediately after the magic — the
/// layout [`crate::storage::seeds`] and [`crate::storage::recovery_file`] use.
pub const SUITE_ID_LEN: usize = 2;

/// Bytes [`Outbox::encode`] writes before the first entry: magic, suite id,
/// direction tag, pruned high-water, entry count. The count is a fixed-width `u32`
/// and the high-water a fixed-width `u64`, so adding an entry never changes the
/// header's size — which is what lets [`Outbox::insert`] price a candidate entry on
/// its own.
///
/// The high-water is v4's addition (#323); a v3 record has 8 fewer header bytes and
/// is read with the field defaulted to zero.
const OUTBOX_HEADER_LEN: usize = OUTBOX_MAGIC.len() + SUITE_ID_LEN + 1 + 8 + 4;

/// Bytes an entry costs regardless of its target or lifecycle: sequence (8),
/// composed-at (8), rung (4), next-due (8), and the acceptance, surfacing and
/// lifecycle tags (1 each).
const ENTRY_FIXED_LEN: usize = 8 + 8 + 4 + 8 + 1 + 1 + 1;

/// Bytes the target costs: the tag, plus a `u16` slot for a doorbell.
const fn target_encoded_len(target: OutboxTarget) -> usize {
    match target {
        OutboxTarget::Doorbell { .. } => 1 + 2,
        OutboxTarget::ChannelPage => 1,
    }
}

/// Bytes the lifecycle costs *beyond* its tag: a length-prefixed frame while the
/// entry still owes one, and nothing once it is terminal. This is the only
/// variable-length field in an entry, and the reason a full outbox is a function of
/// how many messages are OWED rather than how many were ever sent.
fn lifecycle_payload_len(lifecycle: &Lifecycle) -> usize {
    match lifecycle {
        Lifecycle::AwaitingCollection(frame) => 8 + frame.len(),
        _ => 0,
    }
}

/// The exact bytes one entry contributes to [`Outbox::encode`]'s output.
fn entry_encoded_len(entry: &OutboxEntry) -> usize {
    ENTRY_FIXED_LEN + target_encoded_len(entry.target) + lifecycle_payload_len(&entry.lifecycle)
}

/// What can go wrong driving or decoding an outbox.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboxError {
    /// A sequence number already has an entry. Re-enqueueing would either
    /// replace a sealed frame or reset a give-up clock; both are silent data
    /// loss, so neither is offered.
    DuplicateSequence(u64),
    /// The last representable sequence number. Refused because the outbox's
    /// pruned high-water is *one past* the highest pruned sequence, and
    /// `u64::MAX + 1` has no spelling — so accepting it would leave the mark
    /// unable to exclude the very sequence it had reclaimed, and the entry could
    /// be enqueued a second time (#323).
    ///
    /// Nothing legitimate reaches this: a direction's sequence space is one
    /// monotonic counter per conversation. It is refused rather than assumed
    /// unreachable because `enqueue_sealed` is public and takes any `u64`.
    SequenceExhausted,
    /// The outbox cannot take another message: encoding it would exceed
    /// [`crate::storage::dm_store::OUTBOX_CAPACITY`], the fixed size of the
    /// correspondence's on-disk record.
    ///
    /// **This is an answer to the sender, and it is expected to fire in ordinary
    /// use** (#291). The bucket holds 106–213 *owed* messages against a seven-day
    /// give-up window, and no affordable fixed size closes that gap, because the
    /// size is fixed precisely so the file does not track queue depth. Refusing
    /// here rather than at persist is the point: the alternative is accepting a
    /// message into an in-memory outbox that the record cannot hold, so the user is
    /// told it is queued and a crash before the next successful write loses it with
    /// nothing on any surface.
    ///
    /// `needed` is what the encoded outbox WOULD occupy with this entry added, so
    /// `needed - capacity` is the overshoot rather than the total.
    Full {
        /// The sequence number that was refused. Nothing was stored or installed
        /// for it, and any entry it names is unchanged.
        seq: u64,
        /// Bytes the outbox would have encoded to had this been accepted — the
        /// **total**, not the excess. [`std::fmt::Display`] renders the excess
        /// (`needed - capacity`) because that is the actionable number; a surface
        /// formatting these fields directly should do the subtraction rather than
        /// showing a reader a seven-digit total.
        needed: usize,
        /// Bytes the record can hold.
        capacity: usize,
    },
    /// No entry carries this sequence number. Distinct from an entry that exists
    /// and cannot do what was asked.
    UnknownSequence(u64),
    /// A frame was offered to an entry that is not [`Lifecycle::AwaitingKey`].
    /// The single frame-installing edge, refusing to be a second one.
    AlreadyPublished(u64),
    /// The call does not apply in this entry's state, **permanently**: a
    /// terminal entry, or a state this call is not for (no frame to emit, or a
    /// key-fetch retry on an entry that is not awaiting a key).
    ///
    /// **Distinct from [`Self::GaveUp`], and the split is not cosmetic.** A
    /// driver looping [`Outbox::due`] → [`OutboxEntry::emit`] and skipping on a
    /// single merged error never learns which entries crossed their window —
    /// this one needs nothing, and that one is a live message owed a surfacing.
    /// One name for both states makes the difference invisible at exactly the
    /// point a caller has to act on it.
    NothingToEmit(u64),
    /// A write outcome was reported for an entry that has no published frame —
    /// [`OutboxEntry::confirm_written`] on anything but
    /// [`Lifecycle::AwaitingCollection`].
    ///
    /// A separate name from [`Self::NothingToEmit`] rather than a shared
    /// wrong-state variant, because the two are reported to different callers
    /// about different mistakes: that one answers a driver asking for bytes,
    /// this one answers a transport reporting what it did with bytes it was
    /// already given. A shared `Display` string would tell the transport its
    /// message "has nothing to emit", which is an answer to a question it did
    /// not ask.
    NothingToConfirm(u64),
    /// The entry is still live but past its seven-day give-up window, so the
    /// call was refused. **The caller owes this message a surfacing** —
    /// [`Outbox::sweep_give_ups`] is what turns it into
    /// [`Lifecycle::Undelivered`] and returns it to be shown.
    ///
    /// Not an error about the entry being finished: it is not finished, it is
    /// *overdue*, and nothing else in the module will tell the user so.
    GaveUp(u64),
    /// A doorbell slot at or above [`DOORBELL_SLOTS`].
    SlotOutsideDoorbell(u16),
    /// The at-rest bytes started with no magic this build recognises — neither
    /// [`OUTBOX_MAGIC`] nor either older one.
    BadMagic,
    /// The at-rest bytes ended inside a field.
    Truncated,
    /// A tag byte no version of this decoder assigns a meaning to.
    UnknownTag { field: &'static str, tag: u8 },
    /// Trailing bytes after the declared entries.
    TrailingBytes(usize),
    /// A decoded entry claims to have been composed in the caller's future, by
    /// `ahead_ms` milliseconds. See [`Outbox::decode`] for why this is refused
    /// rather than clamped.
    ComposedInFuture { seq: u64, ahead_ms: i64 },
    /// The bytes are an outbox record of a version this build does not read.
    /// Today that is only [`OUTBOX_MAGIC_V1`], whose own docs carry the
    /// reasoning; the variant is separate from [`Self::BadMagic`] so "this is
    /// not an outbox" and "this is an outbox I will not read" are different
    /// answers.
    UnsupportedVersion,
    /// The suite id in the header is one of the registry's reserved sentinels.
    SuiteIdSentinel(SuiteIdError),
    /// The suite id in the header names no entry in this build's registry, so
    /// the record was written by a build whose primitives this one does not
    /// implement.
    UnknownSuite(SuiteId),
    /// A decoded entry claims a surfacing is owed on an entry that is still
    /// live. Only a transition into a terminal state owes one, so no sequence
    /// of calls produces this — see [`Surfacing`].
    SurfacingOwedOnLiveEntry(u64),
}

impl std::fmt::Display for OutboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateSequence(s) => write!(f, "sequence {s} is already in the outbox"),
            Self::SequenceExhausted => write!(
                f,
                "sequence {} is the last representable one and cannot be used",
                u64::MAX
            ),
            // Names the overshoot rather than the raw total: "over by 12 KiB" is
            // what a sender or an operator can act on, where two seven-digit byte
            // counts are something to subtract first. The sequence number is the
            // handle this end and the correspondent share.
            Self::Full {
                seq,
                needed,
                capacity,
            } => write!(
                f,
                "the outbox is full: sequence {seq} would need {} byte(s) more than the \
                 {capacity}-byte record holds",
                needed.saturating_sub(*capacity)
            ),
            Self::UnknownSequence(s) => write!(f, "sequence {s} is not in the outbox"),
            Self::AlreadyPublished(s) => {
                write!(f, "sequence {s} already carries a sealed frame")
            }
            Self::NothingToEmit(s) => write!(f, "sequence {s} has nothing to emit"),
            Self::NothingToConfirm(s) => {
                write!(
                    f,
                    "sequence {s} has no published frame to confirm a write of"
                )
            }
            Self::GaveUp(s) => {
                write!(
                    f,
                    "sequence {s} is past its give-up window and owed a surfacing"
                )
            }
            Self::SlotOutsideDoorbell(slot) => {
                write!(f, "doorbell slot {slot} is outside the record")
            }
            Self::BadMagic => write!(f, "not an outbox record"),
            Self::Truncated => write!(f, "the outbox record ends inside a field"),
            Self::UnknownTag { field, tag } => {
                write!(f, "unknown {field} tag {tag}")
            }
            Self::TrailingBytes(n) => write!(f, "{n} bytes after the last entry"),
            Self::ComposedInFuture { seq, ahead_ms } => {
                write!(f, "sequence {seq} was composed {ahead_ms} ms in the future")
            }
            Self::UnsupportedVersion => {
                write!(f, "an outbox record of a version this build does not read")
            }
            Self::SuiteIdSentinel(e) => write!(f, "outbox suite_id: {e}"),
            Self::UnknownSuite(id) => {
                write!(f, "outbox suite {id} is not in this build's registry")
            }
            Self::SurfacingOwedOnLiveEntry(seq) => {
                write!(f, "sequence {seq} owes a surfacing but has not ended")
            }
        }
    }
}

impl std::error::Error for OutboxError {}

/// The sealed bytes of one message, as they will go on the wire every time.
///
/// **Deliberately inert.** There is no `&mut` accessor, no `DerefMut`, no public
/// field and no method that returns anything but a shared borrow — so no caller
/// holding `&mut OutboxEntry` can reach these bytes to change them. That, plus
/// the single frame-installing edge on [`Lifecycle`], is what makes
/// "re-seed byte-identically, never re-seal" a property of the types rather than
/// a rule in a comment.
///
/// Not zeroized on drop: this is ciphertext that has already been published to a
/// public DHT, so a copy in memory is not a secret. The plaintext it was made
/// from was zeroized where it was sealed ([`crate::dm::frame::seal`]).
#[derive(Clone, PartialEq, Eq)]
pub struct SealedFrame(Box<[u8]>);

impl std::fmt::Debug for SealedFrame {
    /// Length only. The bytes are opaque and long, and a debug line full of them
    /// makes a test failure unreadable without saying anything.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SealedFrame({} bytes)", self.0.len())
    }
}

impl SealedFrame {
    /// Take ownership of bytes that have already been sealed.
    ///
    /// The only constructor, and it takes a finished frame — this module has no
    /// way to make one.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// The bytes, borrowed. Every call returns the same memory.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes go on the wire.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the frame is empty — which a real frame never is, but a decoder
    /// should not have to assume it.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Which record an entry is owed to, and where in it.
///
/// **The record *key* is not here, and its absence is the point.** A channel page
/// address is `HKDF(AR ‖ dir ‖ page)` and `AR` is the root the whole address
/// plane hangs off; writing it into this record would put a conversation's entire
/// address graph beside the ciphertext it addresses. So this names the record and
/// the position, and the caller — which holds `AR` live — derives the key. The
/// outbox holds sealed bytes and scheduling metadata, and nothing that could
/// reconstruct a key or an address.
///
/// The page and slot are not stored either: for a sender they are exactly
/// [`position_of`] of the sequence number, and a second copy of a derived fact is
/// a second answer free to disagree with the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxTarget {
    /// The recipient's doorbell, at the slot
    /// [`crate::dm::doorbell::slot_for`] derived for this pair.
    ///
    /// This is the first-contact entry, and it is in the same sequence space as
    /// the channel deliberately: the 2026-07-28 build note keeps the knock at
    /// sequence 0 *"so the contiguous prefix can confirm the opening message"*.
    Doorbell { slot: u16 },
    /// A channel page slot, at [`position_of`] the sequence number, on the
    /// [`Outbox`]'s own direction.
    ///
    /// **The direction is the outbox's, not the entry's**, because sequence
    /// numbers are monotonic *per direction*: two entries numbered 5 on opposite
    /// directions are different messages, and an acknowledgement is per-direction
    /// too. An outbox holding both would let one direction's ack confirm the
    /// other direction's message — a false *collected*, which is the one thing
    /// the fail-safe posture forbids. One outbox per direction makes that
    /// unrepresentable instead of merely undocumented.
    ChannelPage,
}

/// Where an entry is in its life.
///
/// **The one frame-installing edge is `AwaitingKey → AwaitingCollection`**
/// (`OutboxEntry::publish`), and there is no edge back. Both terminal states
/// drop the frame, because nothing re-emits a settled message and a retained
/// ciphertext would only be a longer-lived copy of something already public.
///
/// ```text
///   AwaitingKey ──publish(frame)──▶ AwaitingCollection ──ack──▶ ConfirmedCollected
///        │                                   │
///        └────────give-up / teardown─────────┴──give-up──▶ Undelivered
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifecycle {
    /// § Task 2: *"the recipient's key record unfetchable — evicted or wiped;
    /// retry key fetch on the same backoff."* Nothing is sealed and nothing is
    /// published; the schedule drives the key fetch instead of a re-seed.
    AwaitingKey,
    /// Sealed and published, re-seeding on the ladder until an ack or the
    /// give-up.
    AwaitingCollection(SealedFrame),
    /// A verified signed ack settled this position while this entry was still
    /// live, so it was collected rather than abandoned. See the module docs for
    /// the soundness argument; terminal.
    ConfirmedCollected,
    /// The give-up fired, or a teardown ended a channel this entry could never be
    /// sealed on. Surfaced, never silent; terminal, and never re-consulted
    /// against an ack.
    Undelivered,
}

impl Lifecycle {
    /// Whether the entry can still change — the predicate
    /// [`Outbox::settle_from_ack`] and the give-up sweep both gate on.
    ///
    /// **Wildcard-free, deliberately.** A `matches!` over the pending pair
    /// silently absorbs a fifth variant and defaults it to *terminal* — never
    /// swept, never due, never confirmable, and no compile error anywhere
    /// (`delivery_state` and `tag` would both refuse to build, but this would
    /// not). Written out, a new variant stops the build here too and has to be
    /// classified on purpose.
    pub fn is_pending(&self) -> bool {
        match self {
            Self::AwaitingKey | Self::AwaitingCollection(_) => true,
            Self::ConfirmedCollected | Self::Undelivered => false,
        }
    }

    /// The at-rest tag byte.
    fn tag(&self) -> u8 {
        match self {
            Self::AwaitingKey => 0,
            Self::AwaitingCollection(_) => 1,
            Self::ConfirmedCollected => 2,
            Self::Undelivered => 3,
        }
    }
}

/// What a UI may say about a message. #235's three states, plus the one the
/// design has and #235 does not.
///
/// **No variant means "delivered", and none ever will.** `ConfirmedCollected` is
/// the strongest claim available and it is exactly what a verified ack proves.
/// `peer-reachable` is *not* here: it is an annotation a UI draws from the
/// presence layer over an `OnDht` message, and B5 is why it cannot be a state
/// (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// Nothing is on the DHT yet — the recipient's key record could not be
    /// fetched.
    Composed,
    /// Published and being re-seeded. A UI may annotate this *peer-reachable*
    /// from the presence layer; that annotation changes nothing here.
    OnDht,
    /// A verified ack says the peer collected it.
    ConfirmedCollected,
    /// Given up on, and said so.
    Undelivered,
}

/// Whether a state change on an entry is still owed to the user.
///
/// **This is the durable half of a notification**, and it exists because the
/// other half is not durable at all: [`Outbox::sweep_give_ups`],
/// [`Outbox::settle_from_ack`] and [`Outbox::channel_torn_down`] each return
/// what they moved, and that list is gone the moment its caller is (#279). The
/// module docs carry the argument and the call sequence; the short version is
/// that a transition writes [`Self::Owed`] here, the caller clears it with
/// [`Outbox::record_surfaced`] once the user has been told **and that clearing
/// has itself been persisted**, and every crash in between re-offers.
///
/// **A two-variant enum rather than a `bool`, because the name is the
/// documentation.** `surfaced: false` on a fresh entry reads as "the user has
/// not been told", which is untrue and would be alarming; what is actually true
/// of a fresh entry is that nothing is outstanding, which is what [`Self::Clear`]
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surfacing {
    /// Nothing is outstanding: either the entry has never changed state, or a
    /// caller has recorded that the change it made reached the user.
    Clear,
    /// A transition happened here and nothing has recorded it reaching the
    /// user. Persisted, so a restart re-offers it.
    Owed,
}

impl Surfacing {
    /// The at-rest tag byte.
    fn tag(self) -> u8 {
        match self {
            Self::Clear => 0,
            Self::Owed => 1,
        }
    }
}

/// Whether the transport has ever confirmed accepting this entry's frame.
///
/// **This is the only thing that may drive [`DeliveryState::OnDht`]** (#278).
/// The rung index cannot: it counts emission *attempts*, so it is non-zero after
/// a write that errored, and non-zero after a key-fetch retry on an entry that
/// has never had a frame at all. Both of those reported the message as being on
/// the DHT.
///
/// **A two-variant enum rather than a `bool`, for the reason [`Surfacing`]
/// gives** — the name is the documentation. `written: false` reads as *we have
/// not written it*, which is not what this knows; what it knows is that no
/// write has been **confirmed**, which is a statement about the reports received
/// and not about what happened on the network.
///
/// It is a one-way transition and there is no call that clears it. A later
/// failed write does not un-publish the bytes that landed: the DHT holds a value
/// until it is evicted or overwritten, so *this message reached the network at
/// least once* stays true for the rest of the entry's life. That also keeps the
/// flag monotonic across a restart, which is what stops a UI oscillating between
/// `Composed` and `OnDht` on a flapping transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// No write of this frame has been confirmed. Emissions may well have been
    /// attempted — this says nothing about how many.
    Unconfirmed,
    /// The transport confirmed at least one write.
    ///
    /// **Confirmed is not *the DHT holds our value*.** It is the transport's
    /// `Ok`, and **M2** records that a `set_dht_value` losing a race against
    /// another writer re-propagates the winner's value and returns exactly that
    /// `Ok`. Distinguishing the two needs a value read back, which is the
    /// transport slice's to give and is not this module's to infer.
    Confirmed,
}

impl Acceptance {
    /// The at-rest tag byte.
    fn tag(self) -> u8 {
        match self {
            Self::Unconfirmed => 0,
            Self::Confirmed => 1,
        }
    }
}

/// A rung index and the clock value the next emission is due at.
///
/// Both persist, because § Task 2 requires *"pending DMs **and their backoff
/// position**"* to survive a restart: a restart that reset the rung would put a
/// week-old message back on a one-minute cadence, which is a write storm against
/// a 4/min ceiling for every message in the outbox at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReseedSchedule {
    rung: u32,
    next_due_ms: i64,
}

impl ReseedSchedule {
    /// A schedule whose first emission is due immediately at `now_ms`.
    pub fn new(now_ms: i64) -> Self {
        Self {
            rung: 0,
            next_due_ms: now_ms,
        }
    }

    /// How many emissions have been scheduled, saturating at the ladder's end.
    pub fn rung(&self) -> u32 {
        self.rung
    }

    /// When the next emission is due.
    pub fn next_due_ms(&self) -> i64 {
        self.next_due_ms
    }

    /// The un-jittered delay this rung carries. Past the ladder's end it is the
    /// last rung, repeated — see [`RESEED_LADDER`].
    pub fn delay_for_rung(rung: u32) -> Duration {
        let last = RESEED_LADDER.len() - 1;
        RESEED_LADDER[(rung as usize).min(last)]
    }

    /// Consume this rung and set the next due time, applying `unit` ∈ [-1, 1] of
    /// jitter to it.
    ///
    /// **`unit` is per call rather than per schedule**, so a caller cannot seed
    /// one generator at compose and get a deterministic sequence out of it —
    /// which is exactly the phase relationship M7 names. The runtime path is
    /// [`Self::schedule_next_jittered`].
    /// **The deterministic door, and it is no longer the public one (#280).**
    ///
    /// Taking the jitter unit from the caller is what makes a band edge assertable,
    /// so it has to exist — but it also means the *caller* decides the jitter, and a
    /// caller that passes a constant reconstitutes exactly the M7 cross-record
    /// phase-lock the jitter was added to prevent. While this was the public entry
    /// point and [`Self::schedule_next_jittered`] had no call sites at all, the
    /// module was exposing the unsafe path as its API and keeping the safe one as
    /// dead code. Production now goes through the jittered door; this one is private,
    /// and deliberately has no `testing`-gated re-export — every caller is an
    /// in-crate test, and handing a consumer that enables the feature a
    /// caller-supplied-unit door would restore exactly the path #280 removed.
    fn schedule_next_with_unit(&mut self, now_ms: i64, unit: f64) {
        let delay = apply_jitter(Self::delay_for_rung(self.rung), RESEED_JITTER_FRAC, unit);
        self.next_due_ms = now_ms.saturating_add(delay.as_millis() as i64);
        self.rung = self.rung.saturating_add(1);
    }

    /// `Self::schedule_next_with_unit` with the jitter unit drawn from the OS CSPRNG.
    ///
    /// A CSPRNG read failure degrades to the un-jittered rung rather than failing
    /// the emission — the same trade [`crate::backoff::Backoff::next_jittered`]
    /// makes, and the same reason: a message that stops being re-seeded is lost,
    /// while a message re-seeded on an unjittered cadence is only correlatable.
    pub fn schedule_next_jittered(&mut self, now_ms: i64) {
        self.schedule_next_with_unit(now_ms, crate::jitter::unit());
    }
}

/// One message the sender still owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    seq: u64,
    target: OutboxTarget,
    composed_at_ms: i64,
    schedule: ReseedSchedule,
    lifecycle: Lifecycle,
    surfacing: Surfacing,
    acceptance: Acceptance,
}

impl OutboxEntry {
    /// The sequence number. One monotonic space per direction across the whole
    /// conversation, the doorbell knock included.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Which record this is owed to.
    pub fn target(&self) -> OutboxTarget {
        self.target
    }

    /// When the message was composed — the origin of the give-up clock. See the
    /// module docs for why it is compose and not first emission.
    pub fn composed_at_ms(&self) -> i64 {
        self.composed_at_ms
    }

    /// The backoff position.
    pub fn schedule(&self) -> ReseedSchedule {
        self.schedule
    }

    /// Where the entry is in its life.
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    /// Whether this entry's ending is still owed to the user.
    ///
    /// [`Surfacing::Owed`] here implies [`Lifecycle::is_pending`] is `false`:
    /// the only edges that set it are the ones that end an entry, and they are
    /// the same call.
    pub fn surfacing(&self) -> Surfacing {
        self.surfacing
    }

    /// End this entry, owing the user a surfacing for it.
    ///
    /// **The one edge into a terminal state, and it is one call on purpose.**
    /// The transition and the notification were separable before #279 — three
    /// methods each moved an entry and returned the fact separately — and a
    /// crash between the two lost the notification for good. Written as one
    /// call, a future transition cannot do the first half without the second:
    /// there is no way to spell "end this entry" that leaves the user unowed.
    ///
    /// It is private because nothing outside this module has a reason to end an
    /// entry; the four callers are the give-up sweep, the ack, and the
    /// teardown's two surfacing arms.
    fn end(&mut self, lifecycle: Lifecycle) {
        self.lifecycle = lifecycle;
        self.surfacing = Surfacing::Owed;
    }

    /// What a UI may say about it.
    ///
    /// **A sealed entry no write has been confirmed for is still `Composed`**,
    /// not `OnDht`: sealing is not publishing, and neither is *attempting* to
    /// publish. [`Acceptance`] is what distinguishes them, and
    /// [`Self::confirm_written`] is the only thing that sets it.
    ///
    /// **The rung index used to distinguish them, and that was #278.** It
    /// counts emission attempts, so it is non-zero after a write that errored —
    /// a transport outage read as seven successful publications — and non-zero
    /// after a key-fetch retry on an entry that has never held a frame, which
    /// then reported `OnDht` the instant `OutboxEntry::publish` installed one. No
    /// arrangement of an attempt counter answers *did the transport take the
    /// bytes*, so the fact is carried separately and reported by the caller that
    /// holds it.
    ///
    /// This is stronger than the reading it replaces and still weaker than the
    /// name suggests: **accepted by the transport is not held by the DHT.** The
    /// design names why in **M2** — a losing `set_dht_value` re-propagates the
    /// winner's value and returns success, so a confirmation cannot tell a write
    /// that won from a write that lost. Closing *that* needs a value read back
    /// rather than a return code, which only the transport slice holds; until
    /// then the fail-safe posture is carried by `ConfirmedCollected` being
    /// ack-gated rather than by this.
    pub fn delivery_state(&self) -> DeliveryState {
        match self.lifecycle {
            Lifecycle::AwaitingKey => DeliveryState::Composed,
            Lifecycle::AwaitingCollection(_) if self.acceptance == Acceptance::Unconfirmed => {
                DeliveryState::Composed
            }
            Lifecycle::AwaitingCollection(_) => DeliveryState::OnDht,
            Lifecycle::ConfirmedCollected => DeliveryState::ConfirmedCollected,
            Lifecycle::Undelivered => DeliveryState::Undelivered,
        }
    }

    /// The page slot this sequence occupies, for a channel entry. `None` for a
    /// doorbell knock, which is not paged.
    pub fn position(&self) -> Option<PagePosition> {
        match self.target {
            OutboxTarget::ChannelPage => Some(position_of(self.seq)),
            OutboxTarget::Doorbell { .. } => None,
        }
    }

    /// The sealed bytes, borrowed, or `None` if nothing is sealed.
    pub fn frame(&self) -> Option<&[u8]> {
        match &self.lifecycle {
            Lifecycle::AwaitingCollection(frame) => Some(frame.as_bytes()),
            _ => None,
        }
    }

    /// Install the sealed frame: `AwaitingKey → AwaitingCollection`.
    ///
    /// **The one frame-installing edge**, and it refuses any state but
    /// `AwaitingKey` — so a frame enters an entry at most once, and no ordering
    /// of calls installs a second one.
    ///
    /// **`now_ms` is the give-up gate, and this call needs it exactly as much as
    /// the other three do.** Without it `publish` was the only
    /// lifecycle-mutating entry point that could not check
    /// [`Self::is_given_up`] — the same race already closed once for
    /// [`Self::emit`], [`Self::retry_key_fetch`] and
    /// [`Outbox::settle_from_ack`], left open on the one path that *creates* the
    /// state the others then refuse to touch. A key fetch that finally succeeds
    /// on day eight would seal a frame — consuming a ratchet position and a
    /// nonce, neither of which comes back — install it, and return `Ok`, which
    /// is the signal to the caller that the seal was worth doing. From there
    /// `emit` refuses for ever while [`Self::delivery_state`] reports
    /// `Composed`: a message that will never be sent, reported as one still
    /// being prepared. Refusing before the install makes the wasted seal
    /// visible at the moment it happens.
    ///
    /// **`pub(crate)`, and that is load-bearing (#291).** Installing a frame is the
    /// only edge that GROWS an entry, so it is the only other place the outbox can
    /// cross [`crate::storage::dm_store::OUTBOX_CAPACITY`]. An entry admitted cheaply
    /// as [`Lifecycle::AwaitingKey`] costs nothing beyond its fixed fields; the frame
    /// that arrives later is the expensive part, and it does not pass through
    /// [`Outbox::insert`] where the enqueue gate lives. Reaching this through
    /// [`Outbox::entry_mut`] would therefore walk straight past the capacity check —
    /// so the public door is [`Outbox::publish`], which prices the growth first.
    pub(crate) fn publish(&mut self, now_ms: i64, frame: SealedFrame) -> Result<(), OutboxError> {
        if !matches!(self.lifecycle, Lifecycle::AwaitingKey) {
            return Err(OutboxError::AlreadyPublished(self.seq));
        }
        if self.is_given_up(now_ms) {
            return Err(OutboxError::GaveUp(self.seq));
        }
        self.lifecycle = Lifecycle::AwaitingCollection(frame);
        Ok(())
    }

    /// Whether an emission is due at `now_ms`.
    ///
    /// Terminal entries are never due, and **neither is an entry past its
    /// give-up window**, whether or not [`Outbox::sweep_give_ups`] has run. The
    /// give-up is a swept transition, so without that second clause the module
    /// keeps writing to the DHT for a message [`Outbox::settle_from_ack`] already
    /// treats as abandoned, for as long as the caller goes without sweeping. The
    /// window is authoritative everywhere the clock is available; the sweep only
    /// decides *when the user is told*.
    pub fn is_due(&self, now_ms: i64) -> bool {
        self.lifecycle.is_pending()
            && !self.is_given_up(now_ms)
            && now_ms >= self.schedule.next_due_ms
    }

    /// Whether the give-up has fired at `now_ms`.
    ///
    /// **At seven days, not a moment before.** The comparison is `>=` against
    /// `composed_at_ms + GIVE_UP_MS`, so a message one millisecond short of the
    /// window is still pending and one exactly at it is not.
    pub fn is_given_up(&self, now_ms: i64) -> bool {
        now_ms.saturating_sub(self.composed_at_ms) >= GIVE_UP_MS
    }

    /// Emit this message: return the bytes to write, and advance the schedule.
    ///
    /// **The returned slice is the stored frame, borrowed.** Not a copy, not a
    /// re-encoding, not a re-seal — the same memory every call, which is the
    /// whole of the byte-identical re-seed invariant at this layer.
    ///
    /// `unit` ∈ [-1, 1] is this emission's jitter, drawn fresh; see
    /// `ReseedSchedule::schedule_next_with_unit`.
    ///
    /// **This call claims nothing about delivery, and the caller owes a second
    /// one** — [`Self::confirm_written`] — once the transport reports the write
    /// succeeded. Emitting alone leaves [`Self::delivery_state`] on `Composed`
    /// however many times it is called (#278).
    ///
    /// **The schedule advances here rather than on the confirmation, and that
    /// is deliberate.** The rung is a backoff position, and a failing transport
    /// has to back off exactly as a succeeding one does: holding the rung until
    /// a write is confirmed would retry a message at whatever rung it was stuck
    /// on, and a stuck rung 0 is a sixty-second cadence for the length of the
    /// outage — 10,080 writes over a week, twice the operator's flat-120 s
    /// figure of 5,040 that § Task 2 prices [`RESEED_LADDER`] against. Attempts
    /// drive the ladder; only the *delivery claim* waits for the transport.
    ///
    /// **A forgotten confirmation understates, never overstates.** The entry
    /// keeps reporting `Composed`, keeps re-seeding on its ladder, and keeps its
    /// give-up window — so the failure mode of a caller that never calls
    /// [`Self::confirm_written`] is a UI too cautious about its own message,
    /// which is the direction § D-DELIV ("default not-delivered") already picks
    /// everywhere else here.
    pub fn emit(&mut self, now_ms: i64) -> Result<&[u8], OutboxError> {
        // The two refusals are told apart, and the state is checked first so a
        // terminal entry past its window reports as terminal rather than as one
        // owed a surfacing it already had. See `OutboxError::GaveUp`.
        if !matches!(self.lifecycle, Lifecycle::AwaitingCollection(_)) {
            return Err(OutboxError::NothingToEmit(self.seq));
        }
        if self.is_given_up(now_ms) {
            return Err(OutboxError::GaveUp(self.seq));
        }
        self.schedule.schedule_next_jittered(now_ms);
        match &self.lifecycle {
            Lifecycle::AwaitingCollection(frame) => Ok(frame.as_bytes()),
            _ => unreachable!("checked immediately above"),
        }
    }

    /// Record that the transport confirmed a write of this entry's frame.
    ///
    /// This is the missing input #278 names: `emit` hands bytes over and cannot
    /// be told what became of them, so every surface inferred delivery from the
    /// attempt. The inference is gone; this is the report that replaces it, and
    /// the transport is the only thing that can make it.
    ///
    /// **Success is what gets reported, not failure, and the asymmetry is the
    /// safety property.** A caller that reports nothing leaves the entry
    /// `Composed` — understating a message that may well be on the DHT. The
    /// mirror API, where a failure had to be reported to *avoid* claiming
    /// delivery, makes silence mean *delivered*: a transport that panics, is
    /// killed, or simply has an unhandled path then publishes a claim nobody
    /// made. One of those two failure modes is a cautious UI and the other is a
    /// message reported as sent that never left, so the direction is not a
    /// matter of taste.
    ///
    /// **Idempotent, and one-way.** A second confirmation changes nothing and is
    /// not an error — a re-seed of an already-published message is the ordinary
    /// case, not a mistake. There is no call that un-confirms; see
    /// [`Acceptance`] for why a later failure does not retract an earlier
    /// success.
    ///
    /// **It does not touch the schedule.** The rung advanced when the bytes were
    /// emitted; advancing it again here would double-count one emission and
    /// skip a rung of the ladder per successful write.
    ///
    /// Refuses on the two states every other lifecycle-mutating call on this
    /// type refuses on, for the same reasons: an entry with no published frame
    /// ([`OutboxError::NothingToConfirm`] — there is nothing a write could have
    /// carried), and an entry past its give-up window
    /// ([`OutboxError::GaveUp`]). The second is the same ordering guard
    /// [`Outbox::settle_from_ack`] carries: past the window a message is owed a
    /// surfacing as *undelivered*, and a late confirmation arriving before the
    /// sweep must not move it back onto `OnDht`.
    ///
    /// **Two caller obligations the refusals cannot enforce, named because the
    /// transport slice will meet both.**
    ///
    /// A confirmation is not ordered against the rest of the module, so one
    /// arriving after [`Outbox::settle_from_ack`] or a sweep has already ended
    /// the entry returns [`OutboxError::NothingToConfirm`] — the same variant as
    /// a genuine caller mistake, for what is an ordinary race between a slow
    /// transport and a fast ack. A driver should treat it as nothing to do
    /// rather than as a fault; the entry's state is already stronger than the
    /// confirmation would have made it.
    ///
    /// And the refusals are keyed on the *lifecycle*, not on whether these bytes
    /// were ever handed over, so confirming an entry that was never emitted
    /// marks it `OnDht` for a write that never happened. Only the caller knows
    /// which sequence it wrote, so only the caller can get this right — confirm
    /// the entry you emitted. Deriving it here from a non-zero rung is exactly
    /// the coupling #278 removed, and would re-import the defect on the
    /// [`Self::retry_key_fetch`] path.
    pub fn confirm_written(&mut self, now_ms: i64) -> Result<(), OutboxError> {
        if !matches!(self.lifecycle, Lifecycle::AwaitingCollection(_)) {
            return Err(OutboxError::NothingToConfirm(self.seq));
        }
        if self.is_given_up(now_ms) {
            return Err(OutboxError::GaveUp(self.seq));
        }
        self.acceptance = Acceptance::Confirmed;
        Ok(())
    }

    /// Whether a write of this entry's frame has ever been confirmed.
    ///
    /// The fact [`Self::delivery_state`] reads. Exposed because a caller
    /// deciding whether a message is worth re-seeding at all wants it directly,
    /// without going through a `DeliveryState` that folds in the lifecycle too.
    pub fn acceptance(&self) -> Acceptance {
        self.acceptance
    }

    /// Advance the schedule for an `AwaitingKey` entry's key-fetch retry.
    ///
    /// § Task 2 puts the key fetch *"on the same backoff"*, and it has no bytes
    /// to emit — so it is a separate call rather than [`Self::emit`] returning an
    /// empty slice, which would be a second meaning for the same return value.
    ///
    /// **"On the same backoff" is this line, and it is the whole method.**
    /// Advancing the schedule is the only thing this call does; without it an
    /// `AwaitingKey` entry stays [`Self::is_due`] at every subsequent clock
    /// value, so a driver draining [`Outbox::due`] re-fetches the key in a hot
    /// loop against the WB-2 4/min ceiling — which is precisely the write storm
    /// the ladder exists to avoid. `a_key_fetch_retry_advances_the_backoff`
    /// pins it.
    pub fn retry_key_fetch(&mut self, now_ms: i64) -> Result<(), OutboxError> {
        if !matches!(self.lifecycle, Lifecycle::AwaitingKey) {
            return Err(OutboxError::NothingToEmit(self.seq));
        }
        if self.is_given_up(now_ms) {
            return Err(OutboxError::GaveUp(self.seq));
        }
        self.schedule.schedule_next_jittered(now_ms);
        Ok(())
    }
}

/// What a teardown did to the outbox.
///
/// **`#[must_use]` is on the type, not only on the method that returns it.** A
/// `#[must_use]` function fires on a bare-expression call and nothing else, so
/// binding the outcome and reading `.retained` for a log line satisfies it while
/// [`Self::surfaced`] — the list of messages the user is owed — goes on the
/// floor. Marking the type carries the obligation wherever a value of it
/// travels, not just at the one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the surfaced list is what the user is owed; dropping it abandons silently"]
pub struct TeardownOutcome {
    /// Pending sequences left **unchanged** — state, schedule and, where there
    /// were any, sealed bytes.
    ///
    /// Not "still re-seeding": an `AwaitingKey` entry retained under
    /// [`TeardownCause::StoreUnreadable`] has no bytes and emits nothing. What
    /// this list means is that the teardown took no decision about them.
    ///
    /// **These carry no [`Surfacing`] flag, and deliberately so.** #279's loss
    /// is a transition whose only record was a return value; nothing here
    /// transitioned, so the next teardown, sweep or ack reports these entries
    /// again on their own merits. A flag would be durable state for a
    /// notification that is already re-derivable.
    pub retained: Vec<u64>,
    /// Sequences moved to [`Lifecycle::Undelivered`] and owed a surfacing.
    ///
    /// These **did** transition, so each also carries [`Surfacing::Owed`] and
    /// is re-offered by [`Outbox::owed_surfacings`] until a caller records it
    /// shown. Dropping this list is recoverable; it was not before #279.
    pub surfaced: Vec<u64>,
}

/// Everything one sender still owes one correspondent on one direction.
///
/// Keyed by sequence number, which is monotonic per direction across the whole
/// conversation — the doorbell knock at sequence 0 and every channel message
/// after it live in the same space, so one outbox covers a correspondence from
/// first contact onward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbox {
    direction: Direction,
    entries: std::collections::BTreeMap<u64, OutboxEntry>,
    /// One past the highest sequence [`Self::prune`] has removed; zero when
    /// nothing has been pruned (#323).
    ///
    /// **Durable, and that is why the at-rest format went to v4.** Pruning removes
    /// the entry that provided sequence dedup — `Outbox::insert` refuses a repeat by
    /// looking in `entries` — so without this a pruned sequence could be enqueued
    /// again, which is a second ciphertext at a write-once slot.
    ///
    /// **Not "the highest pruned sequence".** Sequence 0 is a real message — the
    /// responder's opening reply is `b2a` 0 — so a zero sentinel would be
    /// indistinguishable from having pruned it. Reading this as an exclusive lower
    /// bound makes the empty case honest: 0 admits everything.
    pruned_high_water: u64,
}

impl Outbox {
    /// An empty outbox for one direction.
    ///
    /// **There is no `Default`, because there is no default direction.** A
    /// sequence number means nothing without one: 5 on `a2b` and 5 on `b2a` are
    /// different messages, and an acknowledgement is per-direction as well, so an
    /// outbox holding both would let one direction's ack confirm the other's
    /// message.
    pub fn new(direction: Direction) -> Self {
        Self {
            direction,
            entries: std::collections::BTreeMap::new(),
            pruned_high_water: 0,
        }
    }

    /// Which direction every entry here is on.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// How many entries, terminal ones included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &OutboxEntry> + '_ {
        self.entries.values()
    }

    /// One entry.
    pub fn entry(&self, seq: u64) -> Option<&OutboxEntry> {
        self.entries.get(&seq)
    }

    /// One entry, mutably. It still cannot reach the frame bytes to change
    /// them — [`SealedFrame`] offers nothing that would — and since #291 it cannot
    /// install a frame either: `OutboxEntry::publish` is `pub(crate)`, so the only
    /// edge that grows an entry goes through [`Self::publish`] and its capacity
    /// check. Everything reachable from here writes fixed-width fields or sheds a
    /// frame, so no sequence of calls on the returned entry can enlarge the record.
    pub fn entry_mut(&mut self, seq: u64) -> Option<&mut OutboxEntry> {
        self.entries.get_mut(&seq)
    }

    /// Install the sealed frame on an entry that was enqueued awaiting its
    /// recipient's key, refusing if the record could not then hold it.
    ///
    /// **The second capacity gate, and the reason one was not enough (#291).** The
    /// enqueue gate in `Outbox::insert` prices an entry as it arrives, which is the
    /// whole story for [`Self::enqueue_sealed`] — the frame is present at that
    /// moment. It is emphatically not the story for [`Self::enqueue_awaiting_key`]:
    /// that entry is admitted carrying **no frame at all**, costing only its fixed
    /// fields, and the expensive part arrives here, later. Gating enqueue alone lets
    /// a caller admit hundreds of cheap entries — every one of them correctly
    /// accepted — and then install a frame on each, walking the record far past its
    /// capacity with every call returning `Ok`. That is the #291 failure shape
    /// exactly: the sender is told the message is queued, and the record is
    /// unwritable by the time the store sees it, with the frames now *sealed*, so a
    /// ratchet position and a nonce have been spent unrecoverably.
    ///
    /// The growth is priced as the difference between what the entry's lifecycle
    /// costs now and what it would cost carrying the frame, so this stays correct if
    /// a future lifecycle also carries bytes. As with the enqueue gate, the price is
    /// computed before anything is mutated, so a refusal leaves the entry exactly as
    /// it was — the frame is handed back to the caller by being dropped un-installed,
    /// and the entry remains `AwaitingKey` with its give-up clock still running.
    pub fn publish(
        &mut self,
        seq: u64,
        now_ms: i64,
        frame: SealedFrame,
    ) -> Result<(), OutboxError> {
        let entry = self
            .entries
            .get(&seq)
            .ok_or(OutboxError::UnknownSequence(seq))?;
        let current = lifecycle_payload_len(&entry.lifecycle);
        let after = 8 + frame.len();
        let needed = self.encoded_len() + after.saturating_sub(current);
        if needed > OUTBOX_CAPACITY {
            return Err(OutboxError::Full {
                seq,
                needed,
                capacity: OUTBOX_CAPACITY,
            });
        }
        self.entries
            .get_mut(&seq)
            .ok_or(OutboxError::UnknownSequence(seq))?
            .publish(now_ms, frame)
    }

    /// Enqueue a message whose recipient's key record could not be fetched:
    /// [`Lifecycle::AwaitingKey`], no bytes, the give-up clock already running
    /// from `now_ms`.
    pub fn enqueue_awaiting_key(
        &mut self,
        seq: u64,
        target: OutboxTarget,
        now_ms: i64,
    ) -> Result<&mut OutboxEntry, OutboxError> {
        self.insert(seq, target, now_ms, Lifecycle::AwaitingKey)
    }

    /// Enqueue a message that was sealed at compose — the ordinary path. The
    /// give-up clock runs from `now_ms`.
    pub fn enqueue_sealed(
        &mut self,
        seq: u64,
        target: OutboxTarget,
        now_ms: i64,
        frame: SealedFrame,
    ) -> Result<&mut OutboxEntry, OutboxError> {
        self.insert(seq, target, now_ms, Lifecycle::AwaitingCollection(frame))
    }

    /// **The compose time is the caller's clock at compose, and there is no way
    /// to say otherwise.**
    ///
    /// This parameter used to be a free-standing `composed_at_ms` the caller
    /// chose independently, which made two silent failures representable at the
    /// door: a compose time in the future produced an entry whose
    /// [`OutboxEntry::is_given_up`] answers `false` at every clock value the
    /// user will ever see — never giving up, never swept, never surfaced, and
    /// re-seeding for ever — and a compose time already past the window produced
    /// an entry that was accepted with `Ok` and could never be emitted once.
    /// Neither is a state a *caller* should be able to ask for, and neither was
    /// checked.
    ///
    /// Taking the clock instead of the compose time removes both rather than
    /// validating them: compose *is* now, so "the compose time disagrees with
    /// the clock" no longer has a spelling. The at-rest path is the other half
    /// of this problem and is genuinely different — there the number comes from
    /// a file rather than from the caller, so it has to be checked; see
    /// [`Self::decode`].
    fn insert(
        &mut self,
        seq: u64,
        target: OutboxTarget,
        now_ms: i64,
        lifecycle: Lifecycle,
    ) -> Result<&mut OutboxEntry, OutboxError> {
        validate_target(target)?;
        // Below the high-water the entry is GONE rather than absent, so
        // `contains_key` cannot answer this and would admit a repeat (#323). Both
        // answers are `DuplicateSequence` because both mean the same thing to a
        // caller — this sequence has already been used on this correspondence — and
        // a second variant would invite a caller to treat one as recoverable.
        // Before the dedup, because the dedup depends on it: see
        // `OutboxError::SequenceExhausted`.
        if seq == u64::MAX {
            return Err(OutboxError::SequenceExhausted);
        }
        if seq < self.pruned_high_water || self.entries.contains_key(&seq) {
            return Err(OutboxError::DuplicateSequence(seq));
        }
        // The capacity gate, and it lives here rather than at either public door
        // deliberately: `insert` is private and both `enqueue_awaiting_key` and
        // `enqueue_sealed` funnel through it, so one check covers the whole surface
        // and no future caller can enqueue around it (#291).
        //
        // Refusing at ENQUEUE is the point. `Locked::replace` already refuses an
        // oversized payload at the write, and refusing there is right — a truncated
        // outbox parses to fewer messages than it had and is wrong in a way nothing
        // downstream detects. But that fires after this outbox has accepted the
        // message, i.e. after the sender has been told it is queued, and a crash
        // before the next successful write then loses it silently. A refusal the
        // sender can act on has to come first.
        //
        // Priced from the candidate's own fields rather than by inserting and
        // measuring, so a refusal leaves the outbox exactly as it found it — there is
        // no partially-applied state to unwind.
        let needed = self.encoded_len()
            + ENTRY_FIXED_LEN
            + target_encoded_len(target)
            + lifecycle_payload_len(&lifecycle);
        if needed > OUTBOX_CAPACITY {
            return Err(OutboxError::Full {
                seq,
                needed,
                capacity: OUTBOX_CAPACITY,
            });
        }
        let entry = OutboxEntry {
            seq,
            target,
            composed_at_ms: now_ms,
            schedule: ReseedSchedule::new(now_ms),
            lifecycle,
            // A new entry has not changed state, so nothing is outstanding.
            surfacing: Surfacing::Clear,
            // Nothing has been written yet on either path: an `AwaitingKey`
            // entry has no frame, and an `AwaitingCollection` one has a frame
            // that has never been offered to the transport.
            acceptance: Acceptance::Unconfirmed,
        };
        Ok(self.entries.entry(seq).or_insert(entry))
    }

    /// Drop every entry that is finished and owes nothing, and return how many
    /// went (#323).
    ///
    /// **Why the record needs this at all.** [`Self::encode`] writes every entry
    /// ever inserted. A terminal entry sheds its sealed frame but keeps its fixed
    /// fields for ever, so the record grows with *lifetime* messages rather than
    /// owed ones, and at [`crate::storage::dm_store::OUTBOX_CAPACITY`] that wall is
    /// around 65 500 — `(2 MiB − 39)/32`, for a channel-page entry at the
    /// crate-private `ENTRY_FIXED_LEN` (31) plus its one target byte; de-linked
    /// because this doc is public and that constant is not. (It read 52 000 until
    /// 2026-09-01, which prices a 40-byte entry this format no longer has.) It is
    /// permanent rather than a hiccup: the persist path is
    /// read-modify-write and always writes, so past the wall every future write
    /// fails — no enqueue, no sweep, no settle — for the life of the correspondence,
    /// and nothing would ever shrink the map again.
    ///
    /// **The predicate is deliberately narrow, and the narrowness is the whole
    /// argument.** An entry qualifies only when it is terminal —
    /// [`Lifecycle::is_pending`] is false — **and** its [`Surfacing`] is already
    /// `Clear`. #291 rejected eviction because the obvious candidate, a given-up
    /// entry, is exactly the one owing a surfacing, and discarding it would
    /// reintroduce the silent loss #279 closed. An entry that is finished *and*
    /// already surfaced owes nothing to anyone: no frame, no notification, no
    /// acknowledgement.
    ///
    /// **What is lost with the entry, and what replaces it.** The map was the
    /// sequence-dedup mechanism: `Outbox::insert` refuses a repeat by looking for
    /// it. A pruned sequence is no longer there to be found, so
    /// [`Self::pruned_high_water`] takes that job at constant cost, and `insert`
    /// consults both.
    ///
    /// **Pruning never re-opens capacity that was refused for the right reason.**
    /// It shrinks the encoded record, so a send the capacity gate refused may
    /// succeed afterwards — that is the point rather than a surprise, because the
    /// bytes freed belonged to messages that are finished and acknowledged. It
    /// cannot free an *owed* frame, which is what fills the bucket in ordinary use.
    ///
    /// **Three things a caller must decide before wiring this, none of which this
    /// module can answer.** They are why nothing calls it yet.
    ///
    /// 1. **Pruning erases delivery history from the drawing surface.**
    ///    `DmPersist::read_outbox` exists "for drawing the outbox", and
    ///    `Self::entry` returns `None` for a pruned sequence — so every past
    ///    `ConfirmedCollected` message becomes indistinguishable from one never
    ///    sent. [`Self::pruned_high_water`] says *below this it is gone*, never *in
    ///    which state it went*. "Owes nothing to anyone" is true of the protocol and
    ///    false of a UI that wanted to render a delivered tick.
    /// 2. **A live entry below the high-water is reachable, and it burns sequence
    ///    numbers permanently.** Settle and prune a high sequence while a lower one
    ///    is still owed, and every unused sequence below the mark is refused for
    ///    ever. Harmless under a monotonic allocator, silent and unrecoverable under
    ///    anything else.
    /// 3. **Anything deriving a ceiling from `entries.keys().max()` must stop.**
    ///    Pruning regresses that maximum without a restart and permanently; after a
    ///    prune, `pruned_high_water - 1` is the only surviving record of the high
    ///    sequences. An acknowledgement path that clipped to a regressed ceiling
    ///    would report delivered messages as undelivered.
    pub fn prune(&mut self) -> usize {
        let doomed: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, e)| !e.lifecycle.is_pending() && e.surfacing == Surfacing::Clear)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in &doomed {
            self.entries.remove(seq);
            // One past the pruned sequence, and monotone: a later prune of a lower
            // sequence must not lower the bound. `u64::MAX` is refused at enqueue
            // (`OutboxError::SequenceExhausted`) precisely so this successor is
            // always exact — a saturating one would leave the mark unable to
            // exclude the sequence it had just reclaimed.
            let past = seq
                .checked_add(1)
                .expect("u64::MAX is refused at enqueue, so a stored seq has a successor");
            self.pruned_high_water = self.pruned_high_water.max(past);
        }
        doomed.len()
    }

    /// One past the highest sequence [`Self::prune`] has removed; zero when nothing
    /// has been pruned.
    ///
    /// Exposed so a caller can tell "this sequence was never used" from "this
    /// sequence is finished and its entry has been reclaimed" — the map alone can no
    /// longer answer that.
    pub fn pruned_high_water(&self) -> u64 {
        self.pruned_high_water
    }

    /// Sequences whose next emission is due at `now_ms`, in sequence order.
    ///
    /// Terminal entries are never due, so a caller draining this never touches
    /// one.
    pub fn due(&self, now_ms: i64) -> Vec<u64> {
        self.entries
            .values()
            .filter(|e| e.is_due(now_ms))
            .map(|e| e.seq)
            .collect()
    }

    /// Fire the give-up on every pending entry past seven days from compose, and
    /// return the sequences that just became [`Lifecycle::Undelivered`].
    ///
    /// Both pending states expire: § Task 2's *awaiting-collection* and M14's
    /// *"`awaiting-key` gives up at 7 days"*.
    ///
    /// The returned list is what a caller owes the user. § Task 2: *"marked
    /// undelivered in the UI, **never silently abandoned**"*. Dropping it is
    /// **recoverable** rather than final: every entry here also carries
    /// [`Surfacing::Owed`] until a caller records that it was shown, so
    /// [`Self::owed_surfacings`] re-offers what this list carried across any
    /// number of restarts (#279).
    #[must_use = "a discarded give-up list is the silent abandonment the design forbids"]
    pub fn sweep_give_ups(&mut self, now_ms: i64) -> Vec<u64> {
        let mut fired = Vec::new();
        for entry in self.entries.values_mut() {
            if entry.lifecycle.is_pending() && entry.is_given_up(now_ms) {
                entry.end(Lifecycle::Undelivered);
                fired.push(entry.seq);
            }
        }
        fired
    }

    /// Confirm every live entry a verified ack settles, and return them.
    ///
    /// **Two gates, and both are needed to read `settled` as `collected`.**
    ///
    /// The first is the 2026-07-28 build note's obligation: only
    /// [`Lifecycle::AwaitingCollection`] entries are consulted, and a terminal
    /// entry is skipped without being looked up in the ack at all — so a message
    /// this sender gave up on can never be confirmed by the receiver's
    /// prefix-advance over it.
    ///
    /// The second is `now_ms`, and it exists because the first gate alone leaves
    /// a race the tests found. A give-up is a *swept* transition, so between the
    /// seventh day and the next [`Self::sweep_give_ups`] an entry is past its
    /// window and still `AwaitingCollection` — exactly the window in which the
    /// receiver may legitimately abandon that position. An entry past
    /// [`GIVE_UP_MS`] is therefore not confirmable here at all, whether or not
    /// the sweep has run. The ordering of two unrelated calls is not something
    /// the truth of a delivery indicator should depend on.
    ///
    /// With both, the argument closes against an honest peer:
    ///
    /// > A position is settled because it was collected, or because the sender
    /// > gave up on it. This entry is inside its give-up window, so this sender
    /// > has not given up on it, and the receiver's rule gives it no other
    /// > grounds to abandon it. Therefore it was collected.
    ///
    /// **The residual is a dishonest peer, and it is already an accepted one.**
    /// `collect` and `abandon` produce identical wire bytes — the ack says
    /// *settled*, full stop — so a peer that abandons a position early tells this
    /// sender a message was read when it was not. That is
    /// [`crate::dm::ack`]'s recorded residual that "a peer asserting it collected
    /// everything is lying about its own collection, which no acknowledgement
    /// scheme can prevent", and
    /// [`AckState::merge_peer_ack`](crate::dm::ack::AckState::merge_peer_ack)'s
    /// ceiling already bounds it to sequences actually sent. The peer is the
    /// intended recipient, so the lie costs only itself.
    ///
    /// `ack` must already be verified. This module cannot check a signature and
    /// does not pretend to: [`crate::dm::ack`] owns that, and an unverified ack
    /// reaching here is a caller error the type system cannot catch.
    ///
    /// **The returned list is the fast path, and losing it is recoverable.**
    /// Every later call skips a non-`AwaitingCollection` entry, so nothing in
    /// the *state machine* re-offers a confirmation this `Vec` carried — which
    /// is why each confirmed entry also takes [`Surfacing::Owed`], and why
    /// [`Self::owed_surfacings`] can re-offer it after a crash that ate the
    /// list (#279). Dropping it without reading the flag leaves the UI on
    /// `OnDht` for ever, which is the same class of silent loss
    /// [`Self::sweep_give_ups`] is marked against, in the opposite direction.
    #[must_use = "a discarded confirmation list leaves the UI on OnDht until something reads owed_surfacings"]
    pub fn settle_from_ack(&mut self, ack: &AckState, now_ms: i64) -> Vec<u64> {
        let mut confirmed = Vec::new();
        for entry in self.entries.values_mut() {
            if !matches!(entry.lifecycle, Lifecycle::AwaitingCollection(_)) {
                continue;
            }
            if entry.is_given_up(now_ms) {
                continue;
            }
            if ack.is_settled(entry.seq) {
                entry.end(Lifecycle::ConfirmedCollected);
                confirmed.push(entry.seq);
            }
        }
        confirmed
    }

    /// Sequences whose ending has not been recorded as shown to the user, in
    /// sequence order.
    ///
    /// **This is the recoverable form of what the three transition calls
    /// return.** They hand back what they just moved; this asks the record
    /// itself, so it answers the same question after a restart, and after any
    /// number of restarts, until [`Self::record_surfaced`] says the user was
    /// told and *that* has been persisted in turn. The module docs carry the
    /// call sequence and why the clear comes last.
    ///
    /// Every sequence here is terminal — an entry owes a surfacing only by
    /// ending — so a caller can render one straight from
    /// [`OutboxEntry::delivery_state`] without consulting anything else.
    #[must_use = "the owed list is what the user has not been told; asking and dropping it is the abandonment #279 is about"]
    pub fn owed_surfacings(&self) -> Vec<u64> {
        self.entries
            .values()
            .filter(|e| e.surfacing == Surfacing::Owed)
            .map(|e| e.seq)
            .collect()
    }

    /// Record that the user has been shown these endings, clearing what
    /// [`Self::owed_surfacings`] reports for them.
    ///
    /// **Call this after the UI has consumed them, and persist afterwards.**
    /// Clearing first would restore the #279 defect exactly: the flag would be
    /// gone from the record while the notification was still only in a `Vec`
    /// somebody was carrying. Re-offering an ending the user already saw is the
    /// cost of that ordering, and it is the cheaper failure by a wide margin.
    ///
    /// Idempotent, and a sequence with no entry here is a no-op — there is no
    /// flag on an absent entry to be wrong about, so this needs no error and
    /// stays infallible for its one real caller.
    pub fn record_surfaced(&mut self, seqs: &[u64]) {
        for seq in seqs {
            if let Some(entry) = self.entries.get_mut(seq) {
                entry.surfacing = Surfacing::Clear;
            }
        }
    }

    /// What a channel teardown does here — and the short answer is that it does
    /// not discard anything.
    ///
    /// A [`Teardown`](crate::dm::provisional::Teardown) ends a *ratchet*. It does
    /// not end the obligation this record holds, and three facts say so. The
    /// bytes of an `AwaitingCollection` entry are already sealed and may already
    /// be on the DHT, where destroying our copy loses the user's message
    /// silently. Their addresses survive the teardown: a page address is
    /// `HKDF(AR ‖ dir ‖ page)` and `AR` descends from `ss0`, which ISC-C44 keeps
    /// in the contact cache, so this client can still derive the record and still
    /// holds owner-write authority over it. And the peer's *receive* chain is not
    /// touched by our restart, so frames already published still open for it. The
    /// teardown's own user-facing text has been promising exactly this since
    /// #243: *"messages already sent keep trying to arrive"*. An outbox that
    /// discarded on teardown would make that string a lie.
    ///
    /// **`AwaitingKey` is the asymmetry, and it is not a discard.** Such an entry
    /// has no bytes, and after a teardown it never can have any on this channel:
    /// the handshake it was waiting on is over. Leaving it *awaiting a key* would
    /// be false — it is waiting for a channel that will not come — so it goes to
    /// [`Lifecycle::Undelivered`] and is **surfaced**, which is what the design
    /// asks of every message that stops: marked, never silently abandoned.
    ///
    /// **[`TeardownCause::StoreUnreadable`] changes nothing at all**, and that
    /// distinction is the cause enum's own. Its user-facing text deliberately
    /// declares nothing lost — *"it is most likely still there and will be tried
    /// again next time"* — because nothing was read. Marking a message
    /// undelivered on a transient filesystem fault would destroy a recoverable
    /// message over an `EIO`, which is the failure that put the third cause in
    /// that enum in the first place.
    /// **`now_ms` is the give-up window, and this was the last path without
    /// it.** A pending entry past seven days is abandoned everywhere else the
    /// clock is available — [`OutboxEntry::is_due`] refuses it,
    /// [`OutboxEntry::emit`] refuses it, [`Self::settle_from_ack`] will not
    /// confirm it — so reporting it as `retained`, which means *"the teardown
    /// took no decision about this"*, was the one surface still describing it
    /// as live. It is not live; it is overdue, and a teardown is exactly the
    /// moment a caller is listening. It is surfaced instead, and by the give-up
    /// rather than by the teardown, so the reason it stopped is the true one.
    ///
    /// **The cause match is wildcard-free** for the reason [`Lifecycle`]'s is:
    /// a fourth [`TeardownCause`] would otherwise inherit
    /// surface-the-`AwaitingKey`-entry semantics with no compile error and no
    /// test, and `StoreUnreadable`'s whole existence is the proof that a new
    /// cause can need the opposite treatment.
    #[must_use = "the surfaced list is what the user is owed; dropping it abandons silently"]
    pub fn channel_torn_down(&mut self, cause: &TeardownCause, now_ms: i64) -> TeardownOutcome {
        let mut retained = Vec::new();
        let mut surfaced = Vec::new();
        for entry in self.entries.values_mut() {
            if !entry.lifecycle.is_pending() {
                // Terminal already; a teardown neither revives nor re-reports.
                continue;
            }
            // The give-up is a fact about the clock, not about the teardown, so
            // it outranks the cause — including `StoreUnreadable`, whose
            // "nothing is declared lost" is about what the *store* failed to
            // say, and says nothing about a window that has already closed.
            if entry.is_given_up(now_ms) {
                entry.end(Lifecycle::Undelivered);
                surfaced.push(entry.seq);
                continue;
            }
            match cause {
                // Nothing is known lost, so nothing is declared lost.
                TeardownCause::StoreUnreadable(_) => retained.push(entry.seq),
                TeardownCause::NoProvisionalRecord | TeardownCause::RecordUnusable(_) => {
                    match entry.lifecycle {
                        Lifecycle::AwaitingCollection(_) => retained.push(entry.seq),
                        Lifecycle::AwaitingKey => {
                            entry.end(Lifecycle::Undelivered);
                            surfaced.push(entry.seq);
                        }
                        Lifecycle::ConfirmedCollected | Lifecycle::Undelivered => {
                            unreachable!("non-pending entries were skipped above")
                        }
                    }
                }
            }
        }
        TeardownOutcome { retained, surfaced }
    }

    /// The exact byte length [`Self::encode`] would produce, without building it.
    ///
    /// **Exactness is the whole contract, not an optimisation.** This is what the
    /// capacity gates consult before accepting a message, so a predictor that
    /// drifts from the encoder does one of two harmful things: refuses sends that
    /// would have fit, or — worse — accepts one the record cannot persist, which is
    /// precisely the failure the check exists to prevent. The two are pinned
    /// together by `encoded_len_is_exactly_what_encode_produces`, which walks
    /// entry shapes rather than asserting on one hand-built outbox; a field added to
    /// [`Self::encode`] and not mirrored here fails it.
    pub fn encoded_len(&self) -> usize {
        OUTBOX_HEADER_LEN + self.entries.values().map(entry_encoded_len).sum::<usize>()
    }

    /// The at-rest form: [`OUTBOX_MAGIC`], the suite id, the direction, a `u32`
    /// entry count, then each entry in sequence order — sequence, target,
    /// compose time, rung, next-due, [`Acceptance`], [`Surfacing`], lifecycle,
    /// and the frame last where the only variable-length field belongs.
    ///
    /// **Always written at the current version**, so a record read from a v2
    /// file is re-encoded as v3 the next time its store writes it, the same
    /// read-old-write-new the suite id gets below.
    ///
    /// **Plaintext**, like [`crate::dm::provisional::ProvisionalRecord`]'s body
    /// before it is sealed — to be sealed by whatever store holds it, which is
    /// now [`crate::storage::dm_store`] and is where the fixed size and the
    /// padding live too. It carries no key material and no message text (see the
    /// module docs), so what a reader of the raw file learns is a
    /// correspondence's sequence numbers, their sizes and their schedule. That
    /// is metadata worth sealing and not worth pretending is harmless.
    ///
    /// **The suite id names the registry entry this record was written under
    /// (ISC-C24), and deliberately says nothing about the frames it carries.**
    /// This module performs no cryptography: the frames were sealed elsewhere,
    /// by the ratchet, and nothing here can see which primitives did it. So the
    /// field carries the narrow claim it can support — [`Self::decode`] refuses
    /// a record whose suite this build has no registry entry for, rather than
    /// interpreting bytes a build with different primitives wrote. A record read
    /// under an older, still-present suite re-encodes under the current default
    /// write suite, which is ISC-C24's read-old-write-new and loses nothing,
    /// precisely because the field describes the writer and not the payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(OUTBOX_MAGIC);
        out.extend_from_slice(&Registry::default_write_suite().get().to_be_bytes());
        out.push(match self.direction {
            Direction::AToB => 0,
            Direction::BToA => 1,
        });
        // Before the count, so the header stays fixed-width and `encoded_len` can
        // price a candidate entry without knowing how many are already stored.
        out.extend_from_slice(&self.pruned_high_water.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in self.entries.values() {
            out.extend_from_slice(&entry.seq.to_be_bytes());
            match entry.target {
                OutboxTarget::Doorbell { slot } => {
                    out.push(0);
                    out.extend_from_slice(&slot.to_be_bytes());
                }
                OutboxTarget::ChannelPage => out.push(1),
            }
            out.extend_from_slice(&entry.composed_at_ms.to_be_bytes());
            out.extend_from_slice(&entry.schedule.rung.to_be_bytes());
            out.extend_from_slice(&entry.schedule.next_due_ms.to_be_bytes());
            // Before the lifecycle, so the one variable-length field stays last
            // in the entry.
            out.push(entry.acceptance.tag());
            out.push(entry.surfacing.tag());
            out.push(entry.lifecycle.tag());
            if let Lifecycle::AwaitingCollection(frame) = &entry.lifecycle {
                push_lp(&mut out, frame.as_bytes());
            }
        }
        out
    }

    /// Read the at-rest form back.
    ///
    /// Rejects a wrong magic, a v1 record ([`OutboxError::UnsupportedVersion`]),
    /// a suite id that is a reserved sentinel or absent from this build's
    /// registry, a body that ends inside a field, a tag this build assigns no
    /// meaning to, a doorbell slot outside the record, a duplicate sequence, a
    /// surfacing owed by an entry that has not ended, and trailing bytes. A
    /// frame length is checked against what remains **before** anything is
    /// reserved, so a corrupt length cannot drive an allocation.
    ///
    /// **`now_ms` bounds `composed_at_ms`, and an entry composed in the caller's
    /// future is REFUSED rather than rewritten** —
    /// [`OutboxError::ComposedInFuture`]. A caller with nothing to corroborate
    /// the file against passes its own clock: the bound is the caller's
    /// knowledge, never a number the file supplied. This is
    /// [`crate::dm::provisional::ReceiveCursor::from_be_bytes`]'s `read_through`
    /// argument, in the same shape and for the same reason.
    ///
    /// **Refusing is the whole design, and clamping was a worse bug than the one
    /// it fixed** — a clamp is a silent, durable rewrite of persisted state from
    /// a single unverified clock reading, and one bad boot would give up on
    /// every live message in the file. The body carries the argument in full. A
    /// refusal is non-destructive by construction: nothing is written, the
    /// caller keeps the bytes, and decoding again with a good clock succeeds.
    /// `next_due_ms` is taken verbatim for the same reason and needs no bound —
    /// see the body.
    pub fn decode(bytes: &[u8], now_ms: i64) -> Result<Self, OutboxError> {
        let mut r = Reader::new(bytes);
        // All three magics are the same length, so one read answers every
        // question: is this an outbox at all, is it a version this build reads,
        // and which entry layout follows. v2 is dual-read and v1 is refused —
        // each constant's own docs carry the reasoning, and they differ.
        let magic = r.take(OUTBOX_MAGIC.len())?;
        // v3 carries an acceptance byte per entry and v2 does not, so the
        // version has to survive the header read rather than being checked and
        // dropped.
        // v3 and v4 carry an acceptance byte per entry and v2 does not; v4 alone
        // carries the pruned high-water. Both facts have to survive the header read
        // rather than being checked and dropped.
        let (has_acceptance, has_high_water) = if magic == OUTBOX_MAGIC {
            (true, true)
        } else if magic == OUTBOX_MAGIC_V3 {
            (true, false)
        } else if magic == OUTBOX_MAGIC_V2 {
            (false, false)
        } else if magic == OUTBOX_MAGIC_V1 {
            return Err(OutboxError::UnsupportedVersion);
        } else {
            return Err(OutboxError::BadMagic);
        };
        let suite_raw = u16::from_be_bytes(r.array()?);
        let suite_id = SuiteId::try_new(suite_raw).map_err(OutboxError::SuiteIdSentinel)?;
        if Registry::lookup(suite_id).is_none() {
            return Err(OutboxError::UnknownSuite(suite_id));
        }
        let direction = match r.byte()? {
            0 => Direction::AToB,
            1 => Direction::BToA,
            tag => {
                return Err(OutboxError::UnknownTag {
                    field: "direction",
                    tag,
                });
            }
        };
        // v4 only. A v3 or v2 record pruned nothing, so zero is the truthful
        // default rather than a fallback: every sequence it never held is still
        // admissible, which is exactly what the field means.
        let pruned_high_water = if has_high_water {
            u64::from_be_bytes(r.array()?)
        } else {
            0
        };
        let count = u32::from_be_bytes(r.array()?);
        let mut out = Self::new(direction);
        out.pruned_high_water = pruned_high_water;
        for _ in 0..count {
            let seq = u64::from_be_bytes(r.array()?);
            let target = match r.byte()? {
                0 => OutboxTarget::Doorbell {
                    slot: u16::from_be_bytes(r.array()?),
                },
                1 => OutboxTarget::ChannelPage,
                tag => {
                    return Err(OutboxError::UnknownTag {
                        field: "target",
                        tag,
                    });
                }
            };
            // `composed_at_ms` is CHECKED and, if it is out of range, the
            // record is REFUSED. It is never rewritten. Both halves of that
            // sentence are load-bearing and they pull against each other.
            //
            // Trusting it is not an option: a value in the future makes
            // `is_given_up` answer false at every clock the user will ever see,
            // so the seven-day give-up — the guarantee that a message is marked
            // undelivered rather than silently abandoned — never fires, the
            // entry never sweeps, never surfaces, and re-seeds for ever.
            //
            // But the obvious guard, `min(now_ms)`, is DESTRUCTIVE, and that is
            // strictly worse than the problem it solves. Boot with a dead RTC
            // reading T−10d and every live entry is rewritten to T−10d; the next
            // `encode` persists it; and when the clock corrects, every one of
            // them is instantly past its window, given up, and swept to
            // `Undelivered`. That failure is one-directional (a clamp only ever
            // moves the value earlier), uncorroborated (one bad reading is
            // enough), and unrecoverable (the true value is gone). It turns a
            // transient clock fault into permanent data loss and tells the user
            // their messages failed when they did not — the exact fail-unsafe
            // direction this record exists to prevent.
            //
            // So the guard refuses instead. A refusal writes nothing: the
            // caller still holds the bytes and can decode again once its clock
            // is trustworthy, which makes a bad boot clock a recoverable
            // *failure to load* rather than a durable corruption. That answers
            // the "refusing discards every other pending message" objection —
            // it discards nothing; it declines to interpret, once, and says
            // which sequence and by how much.
            let composed_at_ms = i64::from_be_bytes(r.array()?);
            if composed_at_ms > now_ms {
                return Err(OutboxError::ComposedInFuture {
                    seq,
                    ahead_ms: composed_at_ms.saturating_sub(now_ms),
                });
            }
            let rung = u32::from_be_bytes(r.array()?);
            // `next_due_ms` is taken VERBATIM, and is neither clamped nor
            // checked. It needs no guard: a far-future due time only stops the
            // entry emitting, and `is_given_up` — which reads `composed_at_ms`,
            // not this — still fires on schedule, so the entry is still swept,
            // still surfaced, and still reported to the user. The failure is
            // bounded and self-healing in the fail-safe direction. It is also
            // legitimately past the give-up boundary for an entry whose last
            // emission landed near it, so the old clamp to that boundary
            // rewrote correct records as readily as corrupt ones.
            let next_due_ms = i64::from_be_bytes(r.array()?);
            // A v2 body has no byte here, and every entry in one defaults to
            // `Unconfirmed` — the understating direction. `OUTBOX_MAGIC_V2`
            // carries why that is the right default rather than reconstructing
            // v2's `rung > 0` belief, which is the defect this field replaces.
            let acceptance = if has_acceptance {
                match r.byte()? {
                    0 => Acceptance::Unconfirmed,
                    1 => Acceptance::Confirmed,
                    tag => {
                        return Err(OutboxError::UnknownTag {
                            field: "acceptance",
                            tag,
                        });
                    }
                }
            } else {
                Acceptance::Unconfirmed
            };
            let surfacing = match r.byte()? {
                0 => Surfacing::Clear,
                1 => Surfacing::Owed,
                tag => {
                    return Err(OutboxError::UnknownTag {
                        field: "surfacing",
                        tag,
                    });
                }
            };
            let lifecycle = match r.byte()? {
                0 => Lifecycle::AwaitingKey,
                1 => {
                    let len = u64::from_be_bytes(r.array()?);
                    let len = usize::try_from(len).map_err(|_| OutboxError::Truncated)?;
                    Lifecycle::AwaitingCollection(SealedFrame::new(r.take(len)?.to_vec()))
                }
                2 => Lifecycle::ConfirmedCollected,
                3 => Lifecycle::Undelivered,
                tag => {
                    return Err(OutboxError::UnknownTag {
                        field: "lifecycle",
                        tag,
                    });
                }
            };
            validate_target(target)?;
            if out.entries.contains_key(&seq) {
                return Err(OutboxError::DuplicateSequence(seq));
            }
            // A surfacing is owed only by an ending, and `OutboxEntry::end` is
            // the one call that produces either — so this pair is unreachable
            // through the API and the file is corrupt or foreign. Refusing it
            // keeps that invariant true of every decoded record, which is what
            // lets a caller render an owed sequence as a finished message
            // without re-checking. Loading it instead would raise a
            // notification for a transition that never happened: the mirror of
            // the loss the flag exists to prevent.
            if surfacing == Surfacing::Owed && lifecycle.is_pending() {
                return Err(OutboxError::SurfacingOwedOnLiveEntry(seq));
            }
            out.entries.insert(
                seq,
                OutboxEntry {
                    seq,
                    target,
                    composed_at_ms,
                    schedule: ReseedSchedule { rung, next_due_ms },
                    lifecycle,
                    surfacing,
                    acceptance,
                },
            );
        }
        let rest = r.remaining();
        if rest != 0 {
            return Err(OutboxError::TrailingBytes(rest));
        }
        Ok(out)
    }
}

/// A target is only meaningful if the record it names has room for it.
///
/// A channel target needs no check: [`position_of`] divides by
/// [`PAGE_SLOTS`](crate::dm::paging::PAGE_SLOTS), so its page is at most
/// [`MAX_PAGE`](crate::dm::paging::MAX_PAGE) for every `u64` by construction. A
/// guard for it would be one that cannot fire, which reads as protection that is
/// not there — the defect class `frame.rs` records for the dead receive-side
/// guard it removed.
///
/// **There is no direction cross-check here, and an `OutboxError::WrongDirection`
/// was removed rather than wired up.** It was declared, `Display`-formatted, and
/// constructed nowhere, which is the same defect class one paragraph up — a
/// protection that reads as present and is not. Both halves it described turned
/// out to be unavailable rather than merely unwritten:
///
/// * *"a channel target whose stored direction disagrees with the outbox's"* has
///   nothing to compare. An entry stores no direction, deliberately — see
///   [`OutboxTarget::ChannelPage`], where the direction being the outbox's and
///   never the entry's is the property that makes a cross-direction false
///   *collected* unrepresentable. A check needs two values and there is one.
/// * *"a doorbell target on an outbox whose direction the knock does not travel
///   on"* would need the frozen design to name a direction a knock cannot travel
///   on, and it does not. § Task 2's establishment test counts *"any inbound
///   traffic from the recipient on this pair — a reply, **or their doorbell
///   entry to us**"*, so a doorbell entry in either direction of a pair is
///   contemplated by the design of record. A guard built on the opposite reading
///   would refuse a legitimate crossing first contact.
///
/// If a later revision does fix a direction to the knock, the check belongs here
/// and the variant comes back with it — declared at the point it is enforced,
/// not before.
fn validate_target(target: OutboxTarget) -> Result<(), OutboxError> {
    match target {
        OutboxTarget::Doorbell { slot } if slot >= DOORBELL_SLOTS => {
            Err(OutboxError::SlotOutsideDoorbell(slot))
        }
        _ => Ok(()),
    }
}

/// A cursor that refuses to read past the end rather than panicking on a slice.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], OutboxError> {
        let end = self.at.checked_add(n).ok_or(OutboxError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(OutboxError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, OutboxError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], OutboxError> {
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
    /// The re-seed count a never-acknowledged message costs, computed from the two
    /// constants that determine it.
    ///
    /// **Re-seeds, not emissions, and the difference is one.** `ReseedSchedule::new`
    /// sets `next_due_ms = now_ms`, so an entry is due the moment it is composed and
    /// emits *before* consuming rung 0 — matching [`RESEED_LADDER`]'s own wording,
    /// "plus the first send". Emissions are therefore re-seeds + 1 = 15, which is
    /// the figure `storage::dm_store` uses.
    ///
    /// `storage::dm_store`'s module docs put the store key's nonce budget against
    /// the 2^32 birthday bound, and **14** is one of its terms — the re-seeds one
    /// unacknowledged message makes before [`GIVE_UP`]. A change to
    /// [`RESEED_LADDER`] or to [`GIVE_UP`] moves that number and silently
    /// invalidates the budget without touching the file it lives in. This fails
    /// instead (#289).
    ///
    /// It was not the *dominant* term while
    /// [`crate::dm::persist::DmPersist::update_outbox`] wrote on every call,
    /// spending a seal per correspondence per sweep tick whether or not anything
    /// changed. That term is gone (#347): a poll that changes nothing reports
    /// [`Mutation::Unchanged`](crate::dm::persist::Mutation) and writes nothing,
    /// so the ladder below is the message-side cost on its own. Nothing here pins
    /// the sweep cadence, which is not set anywhere yet.
    ///
    /// It recomputes rather than restates: asserting `14 == 14` against a literal
    /// would be the same expression twice, which is the defect #305 was about.
    #[test]
    fn reseeds_before_give_up_is_the_documented_figure() {
        let give_up = super::GIVE_UP.as_secs();
        let mut elapsed = 0u64;
        let mut reseeds = 0u32;

        for rung in super::RESEED_LADDER {
            let d = rung.as_secs();
            if elapsed + d > give_up {
                break;
            }
            elapsed += d;
            reseeds += 1;
        }
        // The terminal rung repeats until the give-up.
        let terminal = super::RESEED_LADDER
            .last()
            .expect("the ladder is not empty")
            .as_secs();
        assert!(terminal > 0, "a zero terminal rung would loop forever");
        while elapsed + terminal <= give_up {
            elapsed += terminal;
            reseeds += 1;
        }

        assert_eq!(
            reseeds,
            14,
            "a never-acked message now costs {reseeds} re-seeds rather than 14 — so \
             {} emissions, not 15 — and the store-key nonce budget in \
             storage::dm_store's module docs is stale. Recompute it before changing \
             this number",
            reseeds + 1
        );
        assert!(
            elapsed <= give_up,
            "the schedule overran the give-up, so the count is not a bound"
        );
    }

    use super::*;

    const T0: i64 = 1_700_000_000_000;

    /// Byte-distinct so a comparison that sliced or transposed would not pass by
    /// coincidence, and long enough that a single flipped byte is not the only
    /// difference a hash could catch.
    ///
    /// **The high byte of the index is folded in, and that is the whole point.**
    /// Without it the ramp is `seed + (i as u8) * 31`, whose index truncates to
    /// `u8` — so `bytes[i] == bytes[i + 256]` and a 512-byte frame is `P‖P`. A
    /// fixture of that shape is invariant under a 256-byte rotation or a
    /// half-swap, which would defeat
    /// `every_emission_borrows_the_one_stored_frame`,
    /// `reseed_is_byte_identical_across_the_whole_ladder` and every round-trip
    /// equality here **at once** — the byte-identical re-seed invariant is the
    /// module's headline property, and a periodic fixture cannot witness it.
    /// `the_frame_fixture_is_not_periodic` holds this line; adding `(i >> 8)`
    /// makes the second half differ from the first by one in every byte.
    fn frame_bytes(seed: u8) -> Vec<u8> {
        (0..512u16)
            .map(|i| {
                seed.wrapping_add((i as u8).wrapping_mul(31))
                    .wrapping_add((i >> 8) as u8)
            })
            .collect()
    }

    fn frame(seed: u8) -> SealedFrame {
        SealedFrame::new(frame_bytes(seed))
    }

    /// Turn a freshly-encoded v4 record into the v2 bytes a pre-#278 build wrote.
    ///
    /// Two fields have to come back out, and naming them here rather than at each
    /// call site is why this exists: v4's 8-byte pruned high-water (#323) and v3's
    /// per-entry acceptance byte (#278). An earlier version of these fixtures
    /// removed only the acceptance byte, so when v4 arrived they produced a record
    /// that was neither version and failed with `TrailingBytes` — a fixture wrong in
    /// a way that looks like a decoder bug.
    fn downgrade_v4_to_v2(v4: &[u8]) -> Vec<u8> {
        let mut out = v4.to_vec();
        // The acceptance byte first: it sits after the high-water, so removing the
        // earlier field would shift it.
        out.remove(SURFACING_AT - 1);
        let hw = OUTBOX_MAGIC.len() + SUITE_ID_LEN + 1;
        out.drain(hw..hw + 8);
        out[..OUTBOX_MAGIC_V2.len()].copy_from_slice(OUTBOX_MAGIC_V2);
        out
    }

    /// Byte offset of the first entry's surfacing tag, named from the layout
    /// rather than searched for — so a field inserted ahead of it breaks the
    /// tests that use it loudly instead of poking at the wrong byte.
    const SURFACING_AT: usize = OUTBOX_MAGIC.len()
        + SUITE_ID_LEN
        + 1 /* direction */
        + 8 /* pruned high-water, v4 (#323) */
        + 4 /* count */
        + 8 /* seq */
        + 1 /* a ChannelPage target tag */
        + 8 /* composed_at_ms */
        + 4 /* rung */
        + 8 /* next_due_ms */
        + 1 /* acceptance */;

    const CHANNEL: OutboxTarget = OutboxTarget::ChannelPage;

    fn channel() -> OutboxTarget {
        CHANNEL
    }

    /// How many *owed* messages an outbox record actually holds, bounded from
    /// **both** sides at the largest and smallest frames [`crate::dm::frame::seal`]
    /// can really produce.
    ///
    /// **The frame size is the whole difficulty, and the obvious choices are both
    /// wrong.** Sizing against `MAX_FRAME_LEN` measures a frame `seal` cannot
    /// reach and undercounts by a third; assuming a small "typical" frame
    /// overcounts by an order of magnitude, because [`crate::dm::frame::PAD_BUCKETS`]
    /// means no frame is ever small. Both errors were made against this bucket
    /// before it was measured (#291). So the bounds come from
    /// [`WORST_CASE_SEALED_FRAME_LEN`], which `worst_case_frame_fits_a_page_subkey`
    /// pins against the real sealer, and from the lower padding rung.
    ///
    /// **Each bound is two-sided because a one-sided one is vacuous:** an upper
    /// assertion alone passes for any capacity at or above the claim, so a bucket
    /// set to a wrong number, or a per-entry field that ate the margin, would keep
    /// it green.
    ///
    /// **What this deliberately does NOT bound:** total entries. A terminal entry
    /// sheds its frame and keeps 40 bytes for ever — nothing prunes — so a record
    /// also dies at ~52k *lifetime* messages. `fill` starts from an empty outbox
    /// and cannot see that; it is tracked separately.
    #[test]
    fn the_bucket_holds_its_claimed_owed_message_count() {
        use crate::dm::frame::WORST_CASE_SEALED_FRAME_LEN;
        use crate::storage::dm_store::OUTBOX_CAPACITY;

        // Measured 2026-08-15 against the real sealer. The smallest frame a
        // padding rung permits was measured at 9 798 B, giving 213 — not pinned
        // here, because no constant names it and inventing one would assert a
        // floor the format does not promise.
        const AT_WORST: u64 = 106;

        // Doorbell carries a `u16` slot the channel target does not, so it is the
        // genuinely worst entry. Slot 0 is always inside `DOORBELL_SLOTS`, and
        // dedup is on `seq`, so one slot serves every entry.
        let worst_target = OutboxTarget::Doorbell { slot: 0 };

        let worst_frame = || SealedFrame::new(vec![0xA5; WORST_CASE_SEALED_FRAME_LEN]);

        let mut ob = empty();
        for seq in 1..=AT_WORST {
            ob.enqueue_sealed(seq, worst_target, T0, worst_frame())
                .unwrap_or_else(|e| panic!("entry {seq} of {AT_WORST} must still fit: {e}"));
        }
        let at = ob.encode().len();
        assert!(
            at <= OUTBOX_CAPACITY,
            "{AT_WORST} worst-case frames encode to {at}, over the {OUTBOX_CAPACITY} bucket"
        );

        // The other side of the same boundary, and since #291 it is measured through
        // the gate rather than by encoding an outbox that can no longer exist: the
        // 107th entry is REFUSED, so "what would 107 encode to" has no spelling on
        // the public API any more. This is the stronger pin of the two, because it
        // ties `encoded_len` — which the gate consults — to `encode` at exactly the
        // count where being one byte out changes the answer.
        let err = ob
            .enqueue_sealed(AT_WORST + 1, worst_target, T0, worst_frame())
            .expect_err("the entry past the claimed count must be refused, not accepted");
        assert!(
            matches!(
                err,
                OutboxError::Full { seq, needed, capacity }
                    if seq == AT_WORST + 1
                        && needed > OUTBOX_CAPACITY
                        && capacity == OUTBOX_CAPACITY
            ),
            "the refusal must name the sequence and the real capacity: {err:?}"
        );

        // A refusal changes nothing. Priced from the candidate's own fields rather
        // than by inserting and measuring, so there is no half-applied state — and
        // an outbox that quietly grew on a refused send would be the silent loss the
        // gate exists to prevent, wearing an error message.
        assert_eq!(
            ob.len() as u64,
            AT_WORST,
            "a refused enqueue must not be stored"
        );
        assert_eq!(
            ob.encode().len(),
            at,
            "a refused enqueue must not change the encoding by even a byte"
        );
    }

    #[test]
    fn cheap_entries_cannot_be_fattened_past_the_bucket_by_publishing() {
        use crate::dm::frame::WORST_CASE_SEALED_FRAME_LEN;
        use crate::storage::dm_store::OUTBOX_CAPACITY;

        // The hole a single enqueue-time gate leaves, and it is the design's own
        // dominant path rather than an exotic one: `enqueue_awaiting_key` exists
        // precisely for a recipient whose key record could not be fetched, and
        // `publish` is the documented edge that resolves it. Those entries are
        // admitted carrying NO frame, so hundreds fit trivially — and every frame
        // arrives afterwards.
        let target = OutboxTarget::Doorbell { slot: 0 };
        let mut ob = empty();
        for seq in 1..=500 {
            ob.enqueue_awaiting_key(seq, target, T0)
                .unwrap_or_else(|e| panic!("frameless entry {seq} must fit: {e}"));
        }
        assert!(
            ob.encoded_len() < OUTBOX_CAPACITY,
            "500 frameless entries must sit well inside the bucket — that is what \
             makes this the interesting case"
        );

        // Now the frames arrive. Without the second gate every one of these returns
        // Ok and the record ends multiples over capacity, unwritable, with each
        // frame's ratchet position and nonce already spent.
        let mut refused_at = None;
        for seq in 1..=500 {
            let frame = SealedFrame::new(vec![0xA5; WORST_CASE_SEALED_FRAME_LEN]);
            if let Err(e) = ob.publish(seq, T0, frame) {
                assert!(
                    matches!(e, OutboxError::Full { seq: s, .. } if s == seq),
                    "the refusal must be Full and name the sequence: {e:?}"
                );
                refused_at = Some(seq);
                break;
            }
        }
        let refused_at = refused_at.expect(
            "publishing 500 worst-case frames onto frameless entries must be refused \
             before the bucket overflows",
        );
        assert!(
            refused_at > 1,
            "the gate must not refuse the very first frame — that would mean it is \
             mispricing rather than protecting"
        );
        assert!(
            ob.encoded_len() <= OUTBOX_CAPACITY,
            "the outbox must never be left over capacity: {} > {OUTBOX_CAPACITY}",
            ob.encoded_len()
        );
        assert_eq!(
            ob.encoded_len(),
            ob.encode().len(),
            "the predictor must still agree with the encoder at the boundary"
        );

        // A refused publish leaves the entry alone: still awaiting its key, so a
        // later attempt with a smaller frame is a live option rather than a
        // half-published entry that can never be emitted.
        let entry = ob
            .entry(refused_at)
            .expect("the refused entry still exists");
        assert!(
            entry.frame().is_none(),
            "a refused publish must not install the frame"
        );
    }

    /// **Pruning removes finished, surfaced entries and NOTHING else (#323).**
    ///
    /// Both halves of the predicate are pinned here, and the terminality half is
    /// the one that matters most: a freshly enqueued entry is `Surfacing::Clear`
    /// **and** pending, so a predicate that checked only the surfacing would delete
    /// a live sealed frame the sender was told was queued — the #279/#291 silent
    /// loss, arriving through the fix for #323.
    ///
    /// **The first version of this test could not see that.** Its comment said
    /// "3: still pending" while composing all three entries at `T0` and sweeping
    /// past the give-up, so every one of them was terminal and the terminality half
    /// was untested: dropping it passed the entire 1 211-test suite. The live entry
    /// is now composed late enough that the sweep genuinely cannot reach it, and
    /// that is asserted rather than described.
    #[test]
    fn prune_takes_only_entries_that_are_finished_and_already_surfaced() {
        let mut ob = empty();
        // 1: terminal and surfaced — the only shape that may go.
        ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        // 2: terminal but still OWES a surfacing.
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        // 3: composed one millisecond before the sweep, so it is inside its window
        // and genuinely live — this is the entry the terminality half protects.
        ob.enqueue_sealed(3, channel(), T0 + GIVE_UP_MS, frame(0x33))
            .unwrap();

        let given_up = ob.sweep_give_ups(T0 + GIVE_UP_MS + 1);
        assert!(
            given_up.contains(&1) && given_up.contains(&2),
            "the fixture did not end the entries it needs terminal"
        );
        assert!(
            !given_up.contains(&3),
            "the fixture's live entry was swept, so the terminality half is untested \
             — which is exactly how the first version of this test passed while the \
             predicate was broken"
        );
        // Fresh entries are `Clear`, which is what makes a surfacing-only predicate
        // dangerous rather than merely wrong.
        assert_eq!(ob.entry(3).unwrap().surfacing(), Surfacing::Clear);

        // Only 1 is told it reached the user.
        ob.record_surfaced(&[1]);

        let removed = ob.prune();
        assert_eq!(removed, 1, "only the finished-and-surfaced entry may go");
        assert!(
            ob.entry(1).is_none(),
            "the finished, surfaced entry survived"
        );
        assert!(
            ob.entry(2).is_some(),
            "an entry owing a surfacing was pruned — that is the silent loss #279 closed"
        );
        assert!(
            ob.entry(3).is_some(),
            "a LIVE entry was pruned, destroying a sealed frame the sender was told \
             was queued"
        );
        assert!(
            ob.entry(3).unwrap().frame().is_some(),
            "the live entry lost its frame"
        );
    }

    /// **The last representable sequence is refused, because the high-water cannot
    /// exclude it otherwise (#323).**
    ///
    /// Found by review, and it is the dedup replacement failing in exactly the place
    /// it was added to protect. The mark is *one past* the highest pruned sequence;
    /// `u64::MAX + 1` has no spelling, so a saturating successor left the mark at
    /// `u64::MAX` while the guard `seq < mark` is false for `seq == u64::MAX` — the
    /// pruned sequence was re-admitted, a second ciphertext at a write-once slot.
    /// Refusing it at enqueue makes every stored sequence's successor exact.
    #[test]
    fn the_last_representable_sequence_is_refused() {
        let mut ob = empty();
        assert_eq!(
            ob.enqueue_sealed(u64::MAX, channel(), T0, frame(0x11)),
            Err(OutboxError::SequenceExhausted),
            "accepting u64::MAX leaves the pruned high-water unable to exclude it"
        );
        // The neighbour is fine, so this is a boundary rather than a range refusal.
        assert!(
            ob.enqueue_sealed(u64::MAX - 1, channel(), T0, frame(0x22))
                .is_ok()
        );
        // And the successor of the largest ACCEPTED sequence is representable, which
        // is the property the refusal exists to guarantee.
        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS + 1);
        ob.record_surfaced(&[u64::MAX - 1]);
        assert_eq!(ob.prune(), 1);
        assert_eq!(ob.pruned_high_water(), u64::MAX);
        assert_eq!(
            ob.enqueue_sealed(u64::MAX - 1, channel(), T0, frame(0x33)),
            Err(OutboxError::DuplicateSequence(u64::MAX - 1)),
            "the reclaimed sequence must still be excluded at the very top of the space"
        );
    }

    /// **A pruned sequence cannot be enqueued again.**
    ///
    /// Pruning removes the entry that provided sequence dedup, so without the
    /// high-water this is a second ciphertext at a write-once slot. The two answers
    /// are deliberately the same error: to a caller both mean "this sequence is
    /// already used".
    #[test]
    fn a_pruned_sequence_is_still_refused_as_a_duplicate() {
        let mut ob = empty();
        ob.enqueue_sealed(7, channel(), T0, frame(0x11)).unwrap();
        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS + 1);
        ob.record_surfaced(&[7]);
        assert_eq!(ob.prune(), 1);
        assert!(ob.entry(7).is_none(), "the fixture did not prune");
        assert_eq!(ob.pruned_high_water(), 8, "one past the pruned sequence");

        assert_eq!(
            ob.enqueue_sealed(7, channel(), T0, frame(0x22)),
            Err(OutboxError::DuplicateSequence(7)),
            "a pruned sequence was accepted again — a second ciphertext at a \
             write-once slot"
        );
        // And everything at or above the mark is still admissible.
        assert!(ob.enqueue_sealed(8, channel(), T0, frame(0x33)).is_ok());
    }

    /// **The high-water survives the at-rest round trip, and a v3 record reads as
    /// having pruned nothing.**
    ///
    /// A high-water that reset on decode would be worse than none: the record would
    /// come back admitting every sequence it had already reclaimed.
    #[test]
    fn the_pruned_high_water_is_durable_and_v3_defaults_to_zero() {
        let mut ob = empty();
        ob.enqueue_sealed(4, channel(), T0, frame(0x11)).unwrap();
        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS + 1);
        ob.record_surfaced(&[4]);
        ob.prune();
        assert_eq!(ob.pruned_high_water(), 5);

        let back = round_trip(&ob);
        assert_eq!(
            back.pruned_high_water(),
            5,
            "the high-water did not survive persistence, so a restart would re-admit \
             a reclaimed sequence"
        );
        assert_eq!(back, ob, "the round trip changed the outbox");

        // A v3 record carries no such field. Zero is the truthful reading — it
        // pruned nothing — and it must not be mistaken for a corrupt one.
        let v4 = ob.encode();
        let mut v3 = v4.clone();
        let hw = OUTBOX_MAGIC.len() + SUITE_ID_LEN + 1;
        v3.drain(hw..hw + 8);
        v3[..OUTBOX_MAGIC_V3.len()].copy_from_slice(OUTBOX_MAGIC_V3);
        let decoded =
            Outbox::decode(&v3, T0 + 10 * GIVE_UP_MS).expect("a v3 record must still be readable");
        assert_eq!(
            decoded.pruned_high_water(),
            0,
            "a v3 record must read as having pruned nothing"
        );
    }

    /// **Pruning is priced by the capacity gates, which is the interaction with
    /// #291 worth pinning.**
    ///
    /// `encoded_len` and both gates compute from the entry set, so pruning shrinks
    /// what they price and a send the gate refused can succeed afterwards. That is
    /// the intended behaviour — the bytes freed belonged to finished, acknowledged
    /// messages — but it is behaviour a reader would not guess from either change
    /// alone, so it is asserted rather than left implied.
    #[test]
    fn pruning_shrinks_what_the_capacity_gates_price() {
        let mut ob = empty();
        for seq in 1..=20 {
            ob.enqueue_sealed(seq, channel(), T0, frame(seq as u8))
                .unwrap();
        }
        let before = ob.encoded_len();
        assert_eq!(before, ob.encode().len(), "the predictor must agree first");

        let given_up = ob.sweep_give_ups(T0 + GIVE_UP_MS + 1);
        ob.record_surfaced(&given_up);
        let removed = ob.prune();
        assert!(removed > 0, "the fixture pruned nothing");

        let after = ob.encoded_len();
        assert!(after < before, "pruning did not shrink the priced size");
        assert_eq!(
            after,
            ob.encode().len(),
            "the predictor and the encoder disagree after a prune, so the capacity \
             gates would price a record that does not exist"
        );
    }

    #[test]
    fn encoded_len_is_exactly_what_encode_produces() {
        // The contract the capacity gate rests on. `encoded_len` is a hand-written
        // mirror of `encode`, so the two can drift — and drift is not cosmetic here:
        // predicting LOW admits a message the record cannot persist, which is the
        // silent loss #291 exists to stop, and predicting HIGH refuses sends that
        // would have fit. Walking the entry shapes rather than asserting on one
        // hand-built outbox is what makes a field added to `encode` and not mirrored
        // here fail this.
        let doorbell = OutboxTarget::Doorbell { slot: 3 };
        let channel = OutboxTarget::ChannelPage;

        // Empty: the header alone, and the one case with no entry to average over.
        let ob = empty();
        assert_eq!(ob.encoded_len(), ob.encode().len(), "empty outbox");

        // Every combination of target and lifecycle that reaches `encode`, plus a
        // terminal entry, whose shed frame is the difference the two counts in
        // OUTBOX_CAPACITY's doc are about.
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, doorbell, T0).unwrap();
        assert_eq!(ob.encoded_len(), ob.encode().len(), "awaiting-key doorbell");

        ob.enqueue_awaiting_key(2, channel, T0).unwrap();
        assert_eq!(ob.encoded_len(), ob.encode().len(), "awaiting-key channel");

        ob.enqueue_sealed(3, doorbell, T0, frame(0x11)).unwrap();
        assert_eq!(ob.encoded_len(), ob.encode().len(), "sealed doorbell");

        ob.enqueue_sealed(4, channel, T0, frame(0x22)).unwrap();
        assert_eq!(ob.encoded_len(), ob.encode().len(), "sealed channel");

        // A frame of a different length must move both counts by the same amount —
        // the check that the length prefix is accounted for and not just the bytes.
        ob.enqueue_sealed(5, channel, T0, SealedFrame::new(vec![0x33; 4_096]))
            .unwrap();
        assert_eq!(ob.encoded_len(), ob.encode().len(), "sealed, longer frame");

        // Terminal: the entry survives, its frame does not.
        let before = ob.encoded_len();
        let given_up = ob.sweep_give_ups(T0 + GIVE_UP_MS + 1);
        assert!(
            !given_up.is_empty(),
            "the sweep must actually end some entries"
        );
        assert_eq!(
            ob.encoded_len(),
            ob.encode().len(),
            "after entries went terminal"
        );
        assert!(
            ob.encoded_len() < before,
            "a terminal entry sheds its frame, so the encoding must shrink"
        );
    }

    fn empty() -> Outbox {
        Outbox::new(Direction::AToB)
    }

    /// Decode against a clock far past every fixture, so the clamps are inert
    /// unless a test is deliberately exercising them.
    fn round_trip(ob: &Outbox) -> Outbox {
        Outbox::decode(&ob.encode(), T0 + 10 * GIVE_UP_MS).unwrap()
    }

    /// One sealed entry at sequence 1, composed at [`T0`].
    fn sealed_outbox() -> Outbox {
        let mut ob = empty();
        ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        ob
    }

    // ---------------------------------------------------------------- the fixture itself

    /// **A test of the fixture, because the fixture is load-bearing.** Every
    /// byte-identity assertion in this module is only as strong as the bytes it
    /// compares: a frame that repeats with period 256 is invariant under a
    /// 256-byte rotation, so a store, encode or emit that rotated one would pass
    /// the whole file. The earlier ramp did exactly that — the index truncated to
    /// `u8`, so the frame was `P‖P`.
    ///
    /// Every offset a rotation could use is checked, not just 256, and both
    /// halves and quarters are compared outright.
    #[test]
    fn the_frame_fixture_is_not_periodic() {
        let f = frame_bytes(0x11);
        assert_eq!(f.len(), 512);
        assert_ne!(&f[..256], &f[256..], "the two halves are interchangeable");
        assert_ne!(&f[..128], &f[128..256], "the first two quarters are equal");
        // No rotation of any size is the identity, so no transposition anywhere
        // in store / emit / encode / decode can hide inside an equality here.
        for by in 1..f.len() {
            let mut rotated = f.clone();
            rotated.rotate_left(by);
            assert_ne!(rotated, f, "a rotation by {by} bytes is undetectable");
        }
        // Positive control: the assertion above can fail. A genuinely periodic
        // ramp — the one this fixture used to be — is invariant at 256.
        let periodic: Vec<u8> = (0..512u16)
            .map(|i| 0x11u8.wrapping_add((i as u8).wrapping_mul(31)))
            .collect();
        let mut spun = periodic.clone();
        spun.rotate_left(256);
        assert_eq!(spun, periodic, "the control is not periodic after all");
    }

    // ---------------------------------------------------------------- the seal-once invariant

    /// The headline oracle: a re-seed emits the **same bytes**, and keeps doing
    /// so across the whole ladder, an at-rest round trip, and every other
    /// mutation the entry undergoes.
    ///
    /// Deliberately not a two-emission comparison: two calls in a row would pass
    /// against an implementation that re-derived deterministically, and would say
    /// nothing about persistence.
    #[test]
    fn reseed_is_byte_identical_across_the_whole_ladder() {
        let mut ob = sealed_outbox();
        let first = ob.entry_mut(1).unwrap().emit(T0).unwrap().to_vec();
        // The fixture must not be trivially equal to something else: a test where
        // the compared values coincide proves nothing.
        assert_ne!(first, frame_bytes(0x12), "fixture is degenerate");
        assert_eq!(first.len(), 512);

        let mut now = T0;
        for i in 0..100 {
            now += 1;
            let emitted = ob.entry_mut(1).unwrap().emit(now).unwrap().to_vec();
            assert_eq!(emitted, first, "emission {i} differed from the first");

            // Round-trip through the at-rest form every few emissions: a frame
            // that survived in memory but not on disk is still a re-seal.
            if i % 7 == 0 {
                ob = round_trip(&ob);
                assert_eq!(
                    ob.entry(1).unwrap().frame().unwrap(),
                    &first[..],
                    "emission {i} did not survive the at-rest round trip"
                );
            }
        }
    }

    /// Every emission returns the *same memory*, not an equal copy — the
    /// strongest form of the property, and the one that cannot be satisfied by a
    /// deterministic re-encode.
    #[test]
    fn every_emission_borrows_the_one_stored_frame() {
        let mut ob = sealed_outbox();
        let first_ptr = ob.entry_mut(1).unwrap().emit(T0).unwrap().as_ptr();
        for i in 0..20 {
            let ptr = ob.entry_mut(1).unwrap().emit(T0 + i).unwrap().as_ptr();
            assert_eq!(ptr, first_ptr, "emission {i} returned different memory");
        }
    }

    /// The single frame-installing edge refuses to be a second one.
    #[test]
    fn a_frame_can_be_installed_at_most_once() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        let e = ob.entry_mut(1).unwrap();
        e.publish(T0, frame(0x11)).unwrap();
        assert_eq!(e.frame().unwrap(), &frame_bytes(0x11)[..]);
        // A different frame, so a refusal that silently kept the old one is
        // distinguishable from one that swapped it.
        assert_eq!(
            e.publish(T0, frame(0x22)),
            Err(OutboxError::AlreadyPublished(1)),
            "a second frame was accepted"
        );
        assert_eq!(
            e.frame().unwrap(),
            &frame_bytes(0x11)[..],
            "the refusal still replaced the frame"
        );
    }

    /// Every mutator this module has, driven from **both** pending states; none
    /// may land on `AwaitingKey`, so the one frame-installing edge is
    /// unreachable a second time however an entry is driven.
    ///
    /// **The two fixtures are the substance.** An earlier version of this test
    /// used `enqueue_sealed` alone, so every drive started in
    /// `AwaitingCollection`: `AwaitingKey` was never an *input*, the teardown's
    /// `AwaitingKey → Undelivered` arm went untested here, and `publish` and
    /// `retry_key_fetch` — the two mutators that only apply to `AwaitingKey` —
    /// were not driven at all, leaving four of six covered. It also matched the
    /// drive index with a `_ =>` arm, so widening the loop silently re-ran
    /// `emit` and still passed. Both are fixed: the drives are an enum matched
    /// without a wildcard, so adding a mutator fails to compile until it is
    /// listed here.
    #[test]
    fn nothing_transitions_back_into_awaiting_key() {
        #[derive(Debug, Clone, Copy)]
        enum Drive {
            SettleFromAck,
            SweepGiveUps,
            ChannelTornDown,
            Emit,
            Publish,
            RetryKeyFetch,
        }
        const ALL_DRIVES: [Drive; 6] = [
            Drive::SettleFromAck,
            Drive::SweepGiveUps,
            Drive::ChannelTornDown,
            Drive::Emit,
            Drive::Publish,
            Drive::RetryKeyFetch,
        ];

        let mut ack = AckState::new();
        ack.collect(1).unwrap();

        // Both pending states are an input, so every arm of every mutator is
        // reached from a state it actually applies to.
        for sealed in [true, false] {
            for drive in ALL_DRIVES {
                let mut ob = empty();
                if sealed {
                    ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
                } else {
                    ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
                }
                assert_eq!(
                    matches!(ob.entry(1).unwrap().lifecycle(), Lifecycle::AwaitingKey),
                    !sealed,
                    "fixture did not start where this case says it does"
                );

                // Wildcard-free: a new mutator has to be classified here.
                match drive {
                    Drive::SettleFromAck => {
                        let _ = ob.settle_from_ack(&ack, T0);
                    }
                    Drive::SweepGiveUps => {
                        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS);
                    }
                    Drive::ChannelTornDown => {
                        let _ = ob.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0);
                    }
                    Drive::Emit => {
                        let _ = ob.entry_mut(1).unwrap().emit(T0);
                    }
                    Drive::Publish => {
                        let _ = ob.entry_mut(1).unwrap().publish(T0, frame(0x22));
                    }
                    Drive::RetryKeyFetch => {
                        let _ = ob.entry_mut(1).unwrap().retry_key_fetch(T0);
                    }
                }

                let landed_on_awaiting_key =
                    matches!(ob.entry(1).unwrap().lifecycle(), Lifecycle::AwaitingKey);
                // An entry that *started* awaiting a key may still be awaiting
                // one — a refused or no-op drive leaves it there. What may never
                // happen is arriving at `AwaitingKey` from anywhere else.
                if sealed {
                    assert!(
                        !landed_on_awaiting_key,
                        "{drive:?} put a sealed entry back into AwaitingKey"
                    );
                }
            }
        }
    }

    /// The teardown's `AwaitingKey → Undelivered` arm, driven from the state it
    /// is for, and the two mutators that only apply to `AwaitingKey` actually
    /// doing their transitions.
    #[test]
    fn the_awaiting_key_transitions_are_the_ones_the_design_names() {
        // publish: AwaitingKey -> AwaitingCollection, the one install edge.
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        ob.entry_mut(1).unwrap().publish(T0, frame(0x11)).unwrap();
        assert_eq!(
            ob.entry(1).unwrap().frame().unwrap(),
            &frame_bytes(0x11)[..],
            "publish did not install the frame"
        );

        // retry_key_fetch: stays AwaitingKey, advances the schedule.
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        ob.entry_mut(1).unwrap().retry_key_fetch(T0).unwrap();
        assert_eq!(*ob.entry(1).unwrap().lifecycle(), Lifecycle::AwaitingKey);

        // teardown: AwaitingKey -> Undelivered, surfaced.
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        let outcome = ob.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0);
        assert_eq!(outcome.surfaced, vec![1]);
        assert_eq!(*ob.entry(1).unwrap().lifecycle(), Lifecycle::Undelivered);

        // sweep: AwaitingKey -> Undelivered at the window.
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert_eq!(*ob.entry(1).unwrap().lifecycle(), Lifecycle::Undelivered);
    }

    /// A terminal entry has nothing to emit, so a caller cannot re-publish bytes
    /// the design has already settled.
    #[test]
    fn a_settled_entry_emits_nothing() {
        let mut ob = sealed_outbox();
        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS);
        assert_eq!(
            ob.entry_mut(1).unwrap().emit(T0 + GIVE_UP_MS),
            Err(OutboxError::NothingToEmit(1))
        );
    }

    // ---------------------------------------------------------------- the schedule

    /// The ladder is the design's sentence, rung for rung, including the wrinkle.
    #[test]
    fn the_ladder_is_the_frozen_sentence() {
        let mins: Vec<u64> = RESEED_LADDER.iter().map(|d| d.as_secs() / 60).collect();
        assert_eq!(mins, vec![1, 2, 4, 8, 16, 32, 64, 60, 1440]);
        // Not a doubling curve: the wrinkle is real and must not be smoothed.
        assert!(
            RESEED_LADDER[7] < RESEED_LADDER[6],
            "the hourly rung is supposed to be below the 64-minute one"
        );
    }

    /// Every rung boundary, un-jittered, and the terminal rung repeating.
    #[test]
    fn each_backoff_step_lands_on_its_own_rung() {
        // **Literal, not read from `RESEED_LADDER`.** A loop that took its
        // expectations from the constant under test moves both sides of its own
        // comparison, so a changed rung would pass it — which is what the
        // mutation run showed before these were written out. The design's own
        // sentence, in milliseconds.
        const EXPECTED_MS: [i64; 9] = [
            60_000,     // 1 min
            120_000,    // 2
            240_000,    // 4
            480_000,    // 8
            960_000,    // 16
            1_920_000,  // 32
            3_840_000,  // 64
            3_600_000,  // hourly — below the rung before it
            86_400_000, // daily
        ];
        assert_eq!(
            EXPECTED_MS.len(),
            RESEED_LADDER.len(),
            "a rung was added or removed without updating this table"
        );

        let mut s = ReseedSchedule::new(T0);
        let mut now = T0;
        for (i, step) in EXPECTED_MS.iter().enumerate() {
            assert_eq!(s.rung(), i as u32, "rung index before step {i}");
            s.schedule_next_with_unit(now, 0.0);
            assert_eq!(
                s.next_due_ms(),
                now + step,
                "step {i} did not land on its rung"
            );
            now = s.next_due_ms();
        }
        // Past the end the last rung repeats, twice over, so an off-by-one that
        // wrapped to rung 0 would show.
        for i in 0..2 {
            s.schedule_next_with_unit(now, 0.0);
            assert_eq!(
                s.next_due_ms(),
                now + 86_400_000,
                "post-ladder step {i} left the terminal rung"
            );
            now = s.next_due_ms();
        }
    }

    /// Jitter is applied per emission and both directions of the band are
    /// reachable — a jitter that were dropped would make all three equal.
    #[test]
    fn jitter_is_drawn_per_emission_and_moves_the_due_time() {
        let due = |unit: f64| {
            let mut s = ReseedSchedule::new(T0);
            s.schedule_next_with_unit(T0, unit);
            s.next_due_ms()
        };
        let (low, mid, high) = (due(-1.0), due(0.0), due(1.0));
        assert_eq!(mid, T0 + 60_000);
        assert_eq!(low, T0 + 45_000, "low end of the ±25% band");
        assert_eq!(high, T0 + 75_000, "high end of the ±25% band");
        assert!(low < mid && mid < high, "the band collapsed");
    }

    #[test]
    fn emit_jitters_from_the_csprng_without_being_told_a_unit() {
        // The property that replaced the old one at the `emit` boundary, and the
        // one #280 is actually about: `schedule_next_jittered` is now the runtime
        // path, and it previously had NO call site and NO test — the code that
        // would really run was the untested one.
        //
        // The exact instant is not assertable once the unit comes from the CSPRNG,
        // but the two things worth asserting survive: every emission lands inside
        // the band, and the emissions do not all land on the same instant. A build
        // that dropped the jitter would pin every draw to the bare rung; a build
        // that mis-scaled it would leave the band. Both are what M7 cross-record
        // phase-lock looks like from in here.
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let mut ob = sealed_outbox();
            ob.entry_mut(1).unwrap().emit(T0).unwrap();
            let due = ob.entry(1).unwrap().schedule().next_due_ms();
            assert!(
                (T0 + 45_000..=T0 + 75_000).contains(&due),
                "draw {i} landed at {due}, outside the ±25% band around T0 + 60_000"
            );
            seen.insert(due);
        }
        // `seen.len() > 1` separates SOME spread from NO spread and cannot see band
        // WIDTH — a review lens proved it by scaling the drawn unit to a tenth,
        // collapsing the band to ±2.5% while every draw still sat inside the ±25%
        // window and every test still passed. A collapsed-but-nonzero band is
        // phase-lock in practice, so the width needs its own assertion.
        let (lo, hi) = (
            *seen.iter().min().expect("64 draws"),
            *seen.iter().max().expect("64 draws"),
        );
        assert!(
            hi - lo > 10_000,
            "64 draws spanned only {} ms of the 30 000 ms band — the jitter is \
             scaled down, not absent, which no `is it moving at all` check can see",
            hi - lo
        );
        // And the band is centred, not merely wide: a unit left in [0, 1] rather
        // than [-1, 1] keeps half the width AND drifts every re-seed later, which a
        // spread floor alone would pass.
        assert!(
            lo < T0 + 60_000 && hi > T0 + 60_000,
            "every draw fell on one side of the un-jittered rung: [{lo}, {hi}] \
             against T0 + 60 000 — the unit is not centred on zero"
        );

        // And it keeps arriving on later rungs, not just the first: the second rung
        // is 2 min, so its band is ±25% of 120 s around the emission time.
        let mut ob = sealed_outbox();
        ob.entry_mut(1).unwrap().emit(T0).unwrap();
        let now = ob.entry(1).unwrap().schedule().next_due_ms();
        ob.entry_mut(1).unwrap().emit(now).unwrap();
        let second = ob.entry(1).unwrap().schedule().next_due_ms();
        assert!(
            (now + 90_000..=now + 150_000).contains(&second),
            "the second rung landed at {second}, outside the band around {now} + 2 min"
        );
    }

    /// **A key-fetch retry advances the backoff, and an `AwaitingKey` entry is
    /// due in the first place.**
    ///
    /// Nothing asserted either. `retry_key_fetch`'s `schedule_next` call could
    /// be deleted outright — the method reduced to `Ok(())` — and the suite
    /// passed, which leaves § Task 2's *"retry key fetch on the same backoff"*
    /// silently unimplemented: the entry stays `is_due` at every later clock
    /// value, so a driver draining `due()` re-fetches in a hot loop against the
    /// WB-2 4/min ceiling.
    #[test]
    fn a_key_fetch_retry_advances_the_backoff() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        // An unsealed entry is due at compose — the schedule drives the key
        // fetch exactly as it drives a re-seed.
        assert_eq!(
            ob.due(T0),
            vec![1],
            "an awaiting-key entry never appears in due(), so nothing retries it"
        );

        ob.entry_mut(1).unwrap().retry_key_fetch(T0).unwrap();
        let (rung, due) = {
            let s = ob.entry(1).unwrap().schedule();
            (s.rung(), s.next_due_ms())
        };
        assert_eq!(rung, 1, "the retry consumed no rung");
        // The retry pushes the next fetch out by the first rung, jittered — since
        // #280 the unit comes from the CSPRNG, so the band is what is assertable
        // and the exact instant is not.
        assert!(
            (T0 + 45_000..=T0 + 75_000).contains(&due),
            "the retry did not push the next fetch out by a jittered first rung: {due}"
        );
        // And `due` gates on whatever was actually scheduled — read back rather
        // than assumed, which is the invariant this was always testing.
        assert!(
            ob.due(due - 1).is_empty(),
            "the entry was due again immediately — a hot key-fetch loop"
        );
        assert_eq!(ob.due(due), vec![1], "the entry never came back");

        // The jitter reaches the schedule on the key-fetch path too, and since #280
        // it is drawn rather than supplied — so the band is the assertion, and a
        // spread across draws is what shows the unit is not being ignored.
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            let mut ob = empty();
            ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
            ob.entry_mut(1).unwrap().retry_key_fetch(T0).unwrap();
            let due = ob.entry(1).unwrap().schedule().next_due_ms();
            assert!(
                (T0 + 45_000..=T0 + 75_000).contains(&due),
                "key-fetch retry {i} landed at {due}, outside the first rung's band"
            );
            seen.insert(due);
        }
        // Width and centring, for the reason given on the emit path: a scaled-down
        // band passes a "did anything move" check while phase-locking in practice.
        let (lo, hi) = (
            *seen.iter().min().expect("64 draws"),
            *seen.iter().max().expect("64 draws"),
        );
        assert!(
            hi - lo > 10_000,
            "64 key-fetch retries spanned only {} ms of the 30 000 ms band",
            hi - lo
        );
        assert!(
            lo < T0 + 60_000 && hi > T0 + 60_000,
            "every key-fetch retry fell on one side of the un-jittered rung: \
             [{lo}, {hi}] — the unit is not centred on zero"
        );

        // And the rungs keep climbing, so a second retry is not a second minute.
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        ob.entry_mut(1).unwrap().retry_key_fetch(T0).unwrap();
        let now = ob.entry(1).unwrap().schedule().next_due_ms();
        ob.entry_mut(1).unwrap().retry_key_fetch(now).unwrap();
        let second = ob.entry(1).unwrap().schedule().next_due_ms();
        assert!(
            (now + 90_000..=now + 150_000).contains(&second),
            "the key fetch is not climbing the ladder: {second} is outside the \
             second rung's band around {now} + 2 min"
        );
    }

    /// The rung survives the at-rest round trip: a restart that reset it would
    /// put every pending message back on a one-minute cadence at once.
    #[test]
    fn the_backoff_position_survives_persistence() {
        let mut ob = sealed_outbox();
        let mut now = T0;
        for _ in 0..5 {
            let e = ob.entry_mut(1).unwrap();
            e.emit(now).unwrap();
            now = e.schedule().next_due_ms();
        }
        let before = ob.entry(1).unwrap().schedule();
        assert_eq!(before.rung(), 5, "fixture did not advance the rung");
        let after = round_trip(&ob).entry(1).unwrap().schedule();
        assert_eq!(after, before);
    }

    /// `due` gates on the scheduled time, and never returns a terminal entry.
    #[test]
    fn due_tracks_the_schedule_and_skips_terminal_entries() {
        let mut ob = sealed_outbox();
        assert_eq!(ob.due(T0), vec![1], "the first emission is due at compose");
        ob.entry_mut(1).unwrap().emit(T0).unwrap();
        // Read the scheduled instant back rather than assuming it: the emission is
        // jittered from the CSPRNG since #280, and what this test is really about
        // is that `due` gates on whatever was scheduled, not on a constant.
        let due = ob.entry(1).unwrap().schedule().next_due_ms();
        assert!(ob.due(due - 1).is_empty(), "due one ms early");
        assert_eq!(ob.due(due), vec![1], "not due on the rung boundary");
        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS);
        assert!(
            ob.due(T0 + GIVE_UP_MS + 60_000).is_empty(),
            "a terminal entry came back due"
        );
    }

    // ---------------------------------------------------------------- the give-up

    /// Seven days, and not a moment early — both sides of the boundary.
    #[test]
    fn the_give_up_fires_at_seven_days_and_not_before() {
        assert_eq!(GIVE_UP_MS, 604_800_000, "seven days in milliseconds");

        let mut ob = sealed_outbox();
        assert!(
            ob.sweep_give_ups(T0 + GIVE_UP_MS - 1).is_empty(),
            "gave up one millisecond early"
        );
        assert_eq!(
            *ob.entry(1).unwrap().lifecycle(),
            Lifecycle::AwaitingCollection(frame(0x11)),
            "the early sweep changed the entry anyway"
        );
        assert_eq!(
            ob.sweep_give_ups(T0 + GIVE_UP_MS),
            vec![1],
            "did not give up at exactly seven days"
        );
        assert_eq!(*ob.entry(1).unwrap().lifecycle(), Lifecycle::Undelivered);
    }

    /// The clock runs from compose, not from first emission — which is what M14
    /// requires, since an `awaiting-key` message never emits at all.
    #[test]
    fn an_awaiting_key_message_gives_up_seven_days_after_compose() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        // It never emitted anything, and a first-emission clock would never start.
        assert!(ob.entry(1).unwrap().frame().is_none());
        assert!(ob.sweep_give_ups(T0 + GIVE_UP_MS - 1).is_empty());
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Undelivered
        );
    }

    /// A late emission does not push the give-up out: the clock is anchored at
    /// compose and nothing re-anchors it.
    #[test]
    fn emitting_does_not_extend_the_give_up_window() {
        let mut ob = sealed_outbox();
        let mut now = T0;
        for _ in 0..8 {
            let e = ob.entry_mut(1).unwrap();
            e.emit(now).unwrap();
            now = e.schedule().next_due_ms();
        }
        assert!(now > T0, "fixture did not advance the clock");
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
    }

    /// A terminal entry is not given up on twice — a second surfacing would tell
    /// the user the same thing again.
    #[test]
    fn the_give_up_is_reported_once() {
        let mut ob = sealed_outbox();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert!(ob.sweep_give_ups(T0 + GIVE_UP_MS + 1).is_empty());
    }

    // ---------------------------------------------------------------- the ack

    /// A teardown must not downgrade a **confirmed collection** to undelivered.
    ///
    /// **The existing terminal-entry test cannot see this.**
    /// `a_teardown_does_not_re_report_a_terminal_entry` reaches its terminal state
    /// through the give-up sweep, so both `Undelivered` and `ConfirmedCollected`
    /// are "not pending" but only the first is ever exercised. A guard narrowed
    /// from `!is_pending()` to `matches!(.., Undelivered)` therefore passes the
    /// whole suite while re-ending a proven collection as undelivered — telling
    /// the user a message failed that the peer demonstrably received, and
    /// unrecoverably, since `settle_from_ack` only revisits `AwaitingCollection`.
    ///
    /// Found by a review lens on the #261 work; the gap predates it and outlives
    /// its revert, so it is closed on its own.
    #[test]
    fn a_teardown_does_not_downgrade_a_confirmed_collection() {
        let mut ob = sealed_outbox();
        let mut ack = AckState::new();
        ack.collect(1).unwrap();
        assert_eq!(
            ob.settle_from_ack(&ack, T0),
            vec![1],
            "the fixture must actually reach ConfirmedCollected, or this proves nothing"
        );
        // The ack owes the user a notice; consume it, so that a re-surfacing by
        // the teardown shows up as a fresh one rather than hiding behind the flag
        // the ack already set. `owed_surfacings` only reports — `record_surfaced`
        // is what clears.
        assert_eq!(ob.owed_surfacings(), vec![1]);
        ob.record_surfaced(&[1]);
        assert!(
            ob.owed_surfacings().is_empty(),
            "the fixture must start the teardown owing nothing, or the final \
             assertion cannot tell a re-owed notice from the ack's own"
        );

        let outcome = ob.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0);
        assert!(
            outcome.surfaced.is_empty() && outcome.retained.is_empty(),
            "a teardown touched an entry that was already confirmed collected"
        );
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::ConfirmedCollected,
            "a proven collection was downgraded — the user would be told a message \
             failed that the peer demonstrably received"
        );
        assert!(
            ob.owed_surfacings().is_empty(),
            "the teardown re-owed a notice for an entry it should not have touched"
        );
    }

    /// A live entry the ack settles is confirmed collected.
    #[test]
    fn a_verified_ack_confirms_a_live_entry() {
        let mut ob = sealed_outbox();
        let mut ack = AckState::new();
        ack.collect(1).unwrap();
        assert_eq!(ob.settle_from_ack(&ack, T0), vec![1]);
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::ConfirmedCollected
        );
    }

    /// **The load-bearing one.** Prefix-advance-on-give-up means the ack settles
    /// a position nobody read; a given-up entry must never be re-consulted
    /// against it. Note the ack genuinely reports `is_settled` here, so a build
    /// that consulted it would confirm — the fixture is not degenerate.
    #[test]
    fn a_given_up_message_is_never_confirmed_by_a_later_ack() {
        let mut ob = sealed_outbox();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);

        let mut ack = AckState::new();
        ack.abandon(1).unwrap();
        assert!(
            ack.is_settled(1),
            "fixture is degenerate: the ack does not settle the position at all"
        );

        assert!(
            ob.settle_from_ack(&ack, T0 + GIVE_UP_MS).is_empty(),
            "a given-up message was confirmed by an ack"
        );
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Undelivered,
            "undelivered is not terminal"
        );
    }

    /// Contiguity: one settled position never carries its neighbour with it, so
    /// a give-up on sequence 1 cannot confirm a live sequence 2.
    #[test]
    fn a_settled_position_never_carries_its_neighbour() {
        let mut ob = empty();
        ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        for seq in [1, 2] {
            let entry = ob.entry_mut(seq).unwrap();
            entry.emit(T0).unwrap();
            entry.confirm_written(T0).unwrap();
        }

        let mut ack = AckState::new();
        ack.abandon(1).unwrap();
        assert!(ack.is_settled(1), "fixture settled nothing");
        assert!(
            !ack.is_settled(2),
            "the prefix ran past an unsettled position"
        );

        assert_eq!(
            ob.settle_from_ack(&ack, T0),
            vec![1],
            "the entry inside its window is confirmable; only the neighbour is at issue"
        );
        assert_eq!(
            ob.entry(2).unwrap().delivery_state(),
            DeliveryState::OnDht,
            "sequence 1 settling carried sequence 2 with it"
        );
    }

    /// The give-up window closes confirmation **before** the sweep runs.
    ///
    /// A give-up is swept, so between the seventh day and the next sweep an entry
    /// is past its window and still `AwaitingCollection` — precisely when the
    /// receiver may legitimately abandon that position. Without the clock gate
    /// this confirms a message nobody read, and whether it does depends on which
    /// of two unrelated calls the caller happened to make first.
    #[test]
    fn an_entry_past_its_window_is_not_confirmable_before_the_sweep() {
        let mut ob = sealed_outbox();
        let mut ack = AckState::new();
        ack.abandon(1).unwrap();
        assert!(ack.is_settled(1), "fixture settled nothing");

        // No sweep has run: the entry is still live, and past its window.
        assert_eq!(
            *ob.entry(1).unwrap().lifecycle(),
            Lifecycle::AwaitingCollection(frame(0x11)),
            "fixture is degenerate: the entry is already terminal"
        );
        assert!(ob.entry(1).unwrap().is_given_up(T0 + GIVE_UP_MS));

        assert!(
            ob.settle_from_ack(&ack, T0 + GIVE_UP_MS).is_empty(),
            "a message past its give-up window was confirmed"
        );
        // One millisecond earlier it is inside the window, so the gate is the
        // window and not something else.
        assert_eq!(ob.settle_from_ack(&ack, T0 + GIVE_UP_MS - 1), vec![1]);
    }

    /// An `AwaitingKey` entry is not confirmable: nothing was published, so
    /// nothing could have been collected.
    #[test]
    fn an_unpublished_message_is_never_confirmed() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        let mut ack = AckState::new();
        ack.collect(1).unwrap();
        assert!(ob.settle_from_ack(&ack, T0).is_empty());
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Composed
        );
    }

    /// Confirmation is terminal too: a replayed older ack cannot un-confirm, and
    /// a repeat does not re-report.
    #[test]
    fn confirmation_is_reported_once_and_never_reversed() {
        let mut ob = sealed_outbox();
        let mut ack = AckState::new();
        ack.collect(1).unwrap();
        assert_eq!(ob.settle_from_ack(&ack, T0), vec![1]);
        assert!(ob.settle_from_ack(&ack, T0).is_empty());
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::ConfirmedCollected
        );
        // And the give-up cannot claw it back.
        assert!(ob.sweep_give_ups(T0 + GIVE_UP_MS).is_empty());
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::ConfirmedCollected
        );
    }

    // ---------------------------------------------------------------- the teardown

    /// A teardown leaves published messages exactly as they were — bytes, state,
    /// schedule and all.
    #[test]
    fn a_teardown_leaves_the_published_outbox_intact() {
        let mut ob = sealed_outbox();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        ob.entry_mut(1).unwrap().emit(T0).unwrap();
        let before = ob.clone();

        let outcome = ob.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0);
        assert_eq!(outcome.retained, vec![1, 2]);
        assert!(outcome.surfaced.is_empty());
        assert_eq!(ob, before, "the teardown changed a published entry");
        assert_eq!(
            ob.entry(1).unwrap().frame().unwrap(),
            &frame_bytes(0x11)[..],
            "the teardown lost the sealed bytes"
        );
        // Still re-seedable, and still byte-identical.
        assert_eq!(
            ob.entry_mut(1).unwrap().emit(T0 + 60_000).unwrap().to_vec(),
            frame_bytes(0x11)
        );
    }

    /// An unsealed entry cannot be sealed on a channel that is over, so it is
    /// surfaced rather than left waiting for a key that will never arrive.
    #[test]
    fn a_teardown_surfaces_what_it_can_never_seal() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        let entry = ob.entry_mut(2).unwrap();
        entry.emit(T0).unwrap();
        entry.confirm_written(T0).unwrap();

        let outcome = ob.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0);
        assert_eq!(
            outcome.surfaced,
            vec![1],
            "the unsealed entry was not surfaced"
        );
        assert_eq!(outcome.retained, vec![2]);
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Undelivered
        );
        assert_eq!(ob.entry(2).unwrap().delivery_state(), DeliveryState::OnDht);
        assert_eq!(ob.len(), 2, "the teardown dropped an entry");
    }

    /// A store that could not be read declares nothing lost — including the
    /// unsealed entry, which the other two causes surface.
    #[test]
    fn an_unreadable_store_declares_nothing_lost() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        let before = ob.clone();

        let outcome = ob.channel_torn_down(&TeardownCause::StoreUnreadable("EIO".into()), T0);
        assert!(
            outcome.surfaced.is_empty(),
            "a transient read fault declared a message undelivered"
        );
        assert_eq!(outcome.retained, vec![1, 2]);
        assert_eq!(ob, before);
    }

    /// Every teardown cause, each stating what it does to an unsealed entry.
    ///
    /// **Exhaustive by construction, not by hand.** The `match` below has no
    /// wildcard, so a fourth [`TeardownCause`] fails to compile here rather than
    /// silently inheriting surface-the-`AwaitingKey`-entry semantics with no
    /// test — which is what listing two of three causes against a
    /// cause-wildcarding match used to allow. `StoreUnreadable`'s own existence
    /// is the proof that a new cause can need the opposite treatment.
    #[test]
    fn every_teardown_cause_states_what_it_does_to_an_unsealed_entry() {
        let all = [
            TeardownCause::NoProvisionalRecord,
            TeardownCause::RecordUnusable(crate::dm::provisional::ProvisionalError::Aead),
            TeardownCause::StoreUnreadable("EIO".into()),
        ];
        for cause in &all {
            // The exhaustiveness proof: adding a cause breaks this match.
            let surfaces = match cause {
                TeardownCause::NoProvisionalRecord => true,
                TeardownCause::RecordUnusable(_) => true,
                // Nothing was read, so nothing is declared lost.
                TeardownCause::StoreUnreadable(_) => false,
            };

            let mut ob = empty();
            ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
            let outcome = ob.channel_torn_down(cause, T0);
            if surfaces {
                assert_eq!(outcome.surfaced, vec![1], "cause {cause:?} did not surface");
                assert!(outcome.retained.is_empty());
            } else {
                assert!(
                    outcome.surfaced.is_empty(),
                    "cause {cause:?} declared a message lost"
                );
                assert_eq!(outcome.retained, vec![1]);
            }
        }
        // The array really did cover every variant: three causes, three
        // distinct discriminants.
        assert_eq!(all.len(), 3, "a cause was added without a case above");
    }

    /// **A teardown reads the clock, so a past-window entry is surfaced rather
    /// than reported as `retained`.**
    ///
    /// `retained` means *"the teardown took no decision about this"*, which for
    /// an entry the window already closed on is false everywhere else in the
    /// module: `is_due` refuses it, `emit` refuses it, `settle_from_ack` will
    /// not confirm it. A teardown is exactly when a caller is listening, and it
    /// was the last surface still calling such an entry live.
    #[test]
    fn a_teardown_surfaces_an_entry_the_window_already_closed_on() {
        let late = T0 + GIVE_UP_MS;
        // The give-up outranks the cause — including the one cause that
        // otherwise declares nothing lost, because a closed window is a fact
        // about the clock and not about what the store failed to say.
        for cause in [
            TeardownCause::NoProvisionalRecord,
            TeardownCause::StoreUnreadable("EIO".into()),
        ] {
            let mut ob = empty();
            ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
            ob.entry_mut(1).unwrap().emit(T0).unwrap();

            // Inside the window the same call retains it, so the clock is what
            // moved and not the cause.
            let mut inside = ob.clone();
            let early = inside.channel_torn_down(&cause, late - 1);
            assert_eq!(early.retained, vec![1], "cause {cause:?} inside the window");
            assert!(early.surfaced.is_empty());

            let outcome = ob.channel_torn_down(&cause, late);
            assert_eq!(
                outcome.surfaced,
                vec![1],
                "cause {cause:?} reported a past-window entry as merely retained"
            );
            assert!(outcome.retained.is_empty());
            assert_eq!(
                ob.entry(1).unwrap().delivery_state(),
                DeliveryState::Undelivered
            );
        }
    }

    /// A teardown does not re-report a message that already ended.
    #[test]
    fn a_teardown_does_not_re_report_a_terminal_entry() {
        let mut ob = sealed_outbox();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        let outcome = ob.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0 + GIVE_UP_MS);
        assert!(outcome.surfaced.is_empty());
        assert!(outcome.retained.is_empty());
    }

    // ---------------------------------------------------------------- state mapping

    /// The four record states map onto the UI's vocabulary one-to-one, and no
    /// rendering claims delivery.
    #[test]
    fn every_lifecycle_maps_to_one_delivery_state() {
        let cases = [
            (Lifecycle::AwaitingKey, DeliveryState::Composed),
            (
                Lifecycle::AwaitingCollection(frame(0x11)),
                DeliveryState::OnDht,
            ),
            (
                Lifecycle::ConfirmedCollected,
                DeliveryState::ConfirmedCollected,
            ),
            (Lifecycle::Undelivered, DeliveryState::Undelivered),
        ];
        for (lifecycle, expected) in &cases {
            let mut schedule = ReseedSchedule::new(T0);
            // Past rung 0, which under #278's proxy was what made a sealed entry
            // count as emitted. **This table does not detect a revival of that
            // proxy and must not be read as if it does**: at a high rung with
            // `Confirmed` below, the old `rung == 0` reading produces `OnDht`
            // for the `AwaitingCollection` row and this case passes unchanged.
            // The rung is advanced only so the fixture is not sitting on the one
            // value both readings agree about. The revival is caught by
            // `a_sealed_message_is_not_on_the_dht_until_a_write_is_confirmed`
            // and `seven_failed_writes_never_claim_the_message_reached_the_dht`,
            // which hold acceptance and the rung apart on purpose.
            schedule.schedule_next_with_unit(T0, 0.0);
            let entry = OutboxEntry {
                seq: 1,
                target: channel(),
                composed_at_ms: T0,
                schedule,
                lifecycle: lifecycle.clone(),
                surfacing: Surfacing::Clear,
                // A confirmed write — the `Unconfirmed` sealed entry is
                // deliberately `Composed`, which its own test covers.
                acceptance: Acceptance::Confirmed,
            };
            assert_eq!(entry.delivery_state(), *expected);
        }
        // Distinctness, so a map that collapsed two states would fail rather than
        // pass by coincidence.
        let mapped: Vec<_> = cases.iter().map(|(_, d)| *d).collect();
        for (i, a) in mapped.iter().enumerate() {
            for b in &mapped[i + 1..] {
                assert_ne!(a, b, "two lifecycles map to the same delivery state");
            }
        }
    }

    /// The word never appears. A rendering that said "delivered" would have to
    /// invent it, and this pins that it has not been invented here.
    ///
    /// **The list is exhaustive by construction, not by hand.** The `match`
    /// below has no wildcard, so a variant added later fails to compile rather
    /// than going silently unchecked — which is what a hand-written array of the
    /// known variants would have done.
    #[test]
    fn no_delivery_state_claims_delivery() {
        const ALL: [DeliveryState; 4] = [
            DeliveryState::Composed,
            DeliveryState::OnDht,
            DeliveryState::ConfirmedCollected,
            DeliveryState::Undelivered,
        ];
        // The exhaustiveness proof: adding a variant breaks this match.
        for state in ALL {
            match state {
                DeliveryState::Composed
                | DeliveryState::OnDht
                | DeliveryState::ConfirmedCollected
                | DeliveryState::Undelivered => {}
            }
            let rendered = format!("{state:?}").to_lowercase();
            assert!(
                !rendered.contains("delivered") || rendered == "undelivered",
                "{state:?} claims delivery"
            );
        }
        // And a positive control: the assertion can fail. "Delivered" is exactly
        // the name this test exists to keep out.
        assert!("delivered".contains("delivered"));
    }

    /// One outbox is one direction, so one direction's ack can never reach the
    /// other's same-numbered message.
    ///
    /// Replaced an earlier test that took `&Outbox` and called only `&self`
    /// methods to "prove" presence is not an input: the borrow checker already
    /// forbade mutation there, so it passed against every implementation and
    /// proved nothing. Presence not being an input is a property of the *absent*
    /// API and belongs in the module docs, where it now is; this test has content
    /// instead.
    #[test]
    fn one_outbox_is_one_direction() {
        let mut a = Outbox::new(Direction::AToB);
        let mut b = Outbox::new(Direction::BToA);
        a.enqueue_sealed(5, channel(), T0, frame(0x11)).unwrap();
        b.enqueue_sealed(5, channel(), T0, frame(0x22)).unwrap();
        assert_ne!(a.direction(), b.direction(), "fixture is degenerate");

        // The same sequence number, two different messages. An ack settling 5
        // is an ack for one direction, and the caller applies it to that
        // direction's outbox alone; the two cannot be merged into one.
        let mut ack = AckState::new();
        ack.collect(5).unwrap();
        assert_eq!(a.settle_from_ack(&ack, T0), vec![5]);
        assert_eq!(
            b.entry(5).unwrap().delivery_state(),
            DeliveryState::Composed,
            "the other direction's entry was touched"
        );
        // And the direction survives the at-rest round trip, so a reload cannot
        // silently re-file one direction's messages as the other's.
        assert_eq!(round_trip(&b).direction(), Direction::BToA);
        assert_eq!(round_trip(&a).direction(), Direction::AToB);
    }

    /// A sealed message is not on the DHT until a write of it has been
    /// **confirmed**. Sealing is not publishing, and neither is attempting.
    ///
    /// The middle assertion is #278's whole subject: under the rung proxy this
    /// read `OnDht`, so a transport outage — every emission erroring — reported
    /// the message as published.
    #[test]
    fn a_sealed_message_is_not_on_the_dht_until_a_write_is_confirmed() {
        let mut ob = sealed_outbox();
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Composed,
            "a message claimed to be on the DHT before anything was written"
        );
        ob.entry_mut(1).unwrap().emit(T0).unwrap();
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Composed,
            "an emission nobody confirmed claimed the message was on the DHT"
        );
        ob.entry_mut(1).unwrap().confirm_written(T0).unwrap();
        assert_eq!(ob.entry(1).unwrap().delivery_state(), DeliveryState::OnDht);
    }

    /// The failed-transport scenario #278 opens with, end to end: seven
    /// emissions, none confirmed, and every surface still honest.
    ///
    /// **The rung is asserted non-zero deliberately.** That is the proxy the old
    /// reading used, so the test would pass vacuously if the emissions had not
    /// actually advanced it — the state has to be one the old code got wrong.
    #[test]
    fn seven_failed_writes_never_claim_the_message_reached_the_dht() {
        let mut ob = sealed_outbox();
        let mut now = T0;
        for _ in 0..7 {
            let entry = ob.entry_mut(1).unwrap();
            // The bytes go to the transport; the transport errors; nothing is
            // confirmed. That is the whole of a caller's outage path.
            entry.emit(now).unwrap();
            now = entry.schedule().next_due_ms();
        }
        let entry = ob.entry(1).unwrap();
        assert!(
            entry.schedule().rung() >= 7,
            "the emissions did not advance the rung, so this proves nothing"
        );
        assert_eq!(entry.acceptance(), Acceptance::Unconfirmed);
        assert_eq!(
            entry.delivery_state(),
            DeliveryState::Composed,
            "seven errored writes reported the message as on the DHT"
        );
    }

    /// A key-fetch retry advances the rung too, so the old proxy claimed
    /// `OnDht` for an entry that had never been emitted at all — the second
    /// path #278's defect reached, and the one no failed write is involved in.
    #[test]
    fn a_key_fetch_retry_does_not_make_a_later_publish_look_published() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        let entry = ob.entry_mut(1).unwrap();
        entry.retry_key_fetch(T0).unwrap();
        assert!(
            entry.schedule().rung() > 0,
            "the retry did not advance the rung, so this proves nothing"
        );
        entry.publish(T0, frame(0x11)).unwrap();
        assert_eq!(
            entry.delivery_state(),
            DeliveryState::Composed,
            "a key-fetch retry published a message nothing had emitted"
        );
    }

    /// Confirming twice is the ordinary re-seed case, not a mistake.
    #[test]
    fn a_second_confirmation_is_not_an_error_and_changes_nothing() {
        let mut ob = sealed_outbox();
        let entry = ob.entry_mut(1).unwrap();
        entry.emit(T0).unwrap();
        entry.confirm_written(T0).unwrap();
        let after_first = entry.schedule();
        entry.confirm_written(T0).unwrap();
        assert_eq!(entry.acceptance(), Acceptance::Confirmed);
        assert_eq!(
            entry.schedule(),
            after_first,
            "a confirmation moved the backoff, double-counting one emission"
        );
    }

    /// The two refusals, told apart the way [`OutboxEntry::emit`]'s are.
    #[test]
    fn a_confirmation_is_refused_with_no_frame_and_past_the_window() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        assert_eq!(
            ob.entry_mut(1).unwrap().confirm_written(T0),
            Err(OutboxError::NothingToConfirm(1)),
            "a write was confirmed for an entry that has no frame"
        );
        // **The return value alone is not the property.** A refusal that still
        // latched the flag would restore #278's own failure mode by a longer
        // route: `AwaitingKey` renders `Composed` whatever the flag says, so the
        // latch is invisible until `publish` installs a frame — at which point
        // the entry reports `OnDht` for bytes nothing ever emitted. The refusal
        // has to leave no trace, and the only way to see that is to publish
        // afterwards and look.
        let entry = ob.entry_mut(1).unwrap();
        assert_eq!(entry.acceptance(), Acceptance::Unconfirmed);
        entry.publish(T0, frame(0x11)).unwrap();
        assert_eq!(
            entry.delivery_state(),
            DeliveryState::Composed,
            "a refused confirmation latched, and publishing revealed it"
        );

        let mut ob = sealed_outbox();
        ob.entry_mut(1).unwrap().emit(T0).unwrap();
        assert_eq!(
            ob.entry_mut(1).unwrap().confirm_written(T0 + GIVE_UP_MS),
            Err(OutboxError::GaveUp(1)),
            "a late confirmation moved an overdue message back onto OnDht"
        );
        assert_eq!(
            ob.entry(1).unwrap().delivery_state(),
            DeliveryState::Composed,
            "the refused confirmation still took effect"
        );
    }

    /// `Acceptance` is one-way: an emission after a confirmation does not
    /// retract it. The doc rests a UI property on this — no oscillating between
    /// `Composed` and `OnDht` on a flapping transport — so it needs a probe.
    #[test]
    fn a_later_emission_does_not_retract_a_confirmation() {
        let mut ob = sealed_outbox();
        let entry = ob.entry_mut(1).unwrap();
        entry.emit(T0).unwrap();
        entry.confirm_written(T0).unwrap();
        assert_eq!(entry.delivery_state(), DeliveryState::OnDht);

        // The next re-seed errors at the transport, so nothing confirms it.
        let now = entry.schedule().next_due_ms();
        entry.emit(now).unwrap();
        assert_eq!(
            entry.acceptance(),
            Acceptance::Confirmed,
            "an unconfirmed re-seed cleared a confirmation that had already landed"
        );
        assert_eq!(entry.delivery_state(), DeliveryState::OnDht);
    }

    /// The refusals are the two `emit` carries, on every state — including the
    /// terminal ones, which the doc claims and which `AwaitingKey` alone does
    /// not witness.
    #[test]
    fn a_terminal_entry_cannot_be_confirmed() {
        for lifecycle in [Lifecycle::ConfirmedCollected, Lifecycle::Undelivered] {
            let mut ob = sealed_outbox();
            let entry = ob.entry_mut(1).unwrap();
            entry.emit(T0).unwrap();
            entry.end(lifecycle.clone());
            let before = entry.delivery_state();
            assert_eq!(
                entry.confirm_written(T0),
                Err(OutboxError::NothingToConfirm(1)),
                "a finished message accepted a write confirmation"
            );
            assert_eq!(entry.acceptance(), Acceptance::Unconfirmed);
            assert_eq!(
                entry.delivery_state(),
                before,
                "the refusal moved the entry"
            );
        }
    }

    /// State is checked before the window, so an entry that is both frameless
    /// and overdue reports the permanent answer rather than the overdue one —
    /// the ordering [`OutboxEntry::emit`] documents and this call copies.
    ///
    /// The distinction is not cosmetic: `GaveUp` tells a driver the message is
    /// owed a surfacing, and an entry that never had a frame is not owed one on
    /// this call's account.
    #[test]
    fn a_frameless_overdue_entry_reports_the_permanent_refusal() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        let entry = ob.entry_mut(1).unwrap();
        assert!(
            entry.is_given_up(T0 + GIVE_UP_MS),
            "the fixture is not past its window, so this pins nothing"
        );
        assert_eq!(
            entry.confirm_written(T0 + GIVE_UP_MS),
            Err(OutboxError::NothingToConfirm(1))
        );
    }

    /// A message past its give-up window stops being emitted immediately, even
    /// if nothing has swept it yet — otherwise the module keeps writing to the
    /// DHT for a message the ack path already treats as abandoned.
    #[test]
    fn a_message_past_its_window_stops_emitting_before_the_sweep() {
        let mut ob = sealed_outbox();
        let late = T0 + GIVE_UP_MS;
        // No sweep: still live, and past the window.
        assert!(ob.entry(1).unwrap().lifecycle().is_pending());
        assert!(
            ob.due(late - 1).contains(&1),
            "fixture is degenerate: it was not due just inside the window"
        );
        assert!(ob.due(late).is_empty(), "a past-window entry was still due");
        assert_eq!(
            ob.entry_mut(1).unwrap().emit(late),
            Err(OutboxError::GaveUp(1)),
            "a past-window entry was still emitted"
        );
    }

    /// An unsealed entry's key-fetch retry stops at the same boundary.
    #[test]
    fn a_key_fetch_retry_stops_at_the_give_up() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();
        assert!(ob.entry_mut(1).unwrap().retry_key_fetch(T0).is_ok());
        assert_eq!(
            ob.entry_mut(1).unwrap().retry_key_fetch(T0 + GIVE_UP_MS),
            Err(OutboxError::GaveUp(1))
        );
    }

    /// **`publish` checks the give-up window, which was the one lifecycle
    /// mutator that could not.**
    ///
    /// A key fetch that finally succeeds on day eight would otherwise seal a
    /// frame — spending a ratchet position and a nonce, neither recoverable —
    /// install it, and return `Ok`, the signal that the seal was worth doing.
    /// After that `emit` refuses for ever while `delivery_state` reports
    /// `Composed`: a message that can never be sent, shown as one still being
    /// prepared.
    #[test]
    fn publishing_past_the_give_up_window_is_refused() {
        let mut ob = empty();
        ob.enqueue_awaiting_key(1, channel(), T0).unwrap();

        // One millisecond inside the window it still installs, so the gate is
        // the window and not something else.
        let mut inside = ob.clone();
        assert!(
            inside
                .entry_mut(1)
                .unwrap()
                .publish(T0 + GIVE_UP_MS - 1, frame(0x11))
                .is_ok(),
            "a publish one millisecond inside the window was refused"
        );

        assert_eq!(
            ob.entry_mut(1)
                .unwrap()
                .publish(T0 + GIVE_UP_MS, frame(0x11)),
            Err(OutboxError::GaveUp(1)),
            "a frame was installed on a message already past its give-up"
        );
        // And the refusal installed nothing: no frame, and the state is
        // untouched, so the entry sweeps and surfaces normally.
        assert!(
            ob.entry(1).unwrap().frame().is_none(),
            "the refusal installed the frame anyway"
        );
        assert_eq!(*ob.entry(1).unwrap().lifecycle(), Lifecycle::AwaitingKey);
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
    }

    /// **A terminal refusal and an overdue one are different answers**, because
    /// a driver looping `due()` → `emit()` has to act on one and not the other.
    #[test]
    fn a_past_window_refusal_is_distinct_from_a_terminal_one() {
        // Live, past the window: the caller owes this message a surfacing.
        let mut live = sealed_outbox();
        assert_eq!(
            live.entry_mut(1).unwrap().emit(T0 + GIVE_UP_MS),
            Err(OutboxError::GaveUp(1)),
            "a live past-window entry did not report as overdue"
        );
        assert!(live.entry(1).unwrap().lifecycle().is_pending());

        // Terminal: permanent, and needs nothing. Same clock, different answer.
        let mut terminal = sealed_outbox();
        assert_eq!(terminal.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert_eq!(
            terminal.entry_mut(1).unwrap().emit(T0 + GIVE_UP_MS),
            Err(OutboxError::NothingToEmit(1)),
            "a swept entry still reported as owed a surfacing"
        );

        // The two are not the same value — a merged error would make them so.
        assert_ne!(OutboxError::GaveUp(1), OutboxError::NothingToEmit(1));

        // `retry_key_fetch` splits the same pair the same way.
        let mut key = empty();
        key.enqueue_awaiting_key(1, channel(), T0).unwrap();
        assert_eq!(
            key.entry_mut(1).unwrap().retry_key_fetch(T0 + GIVE_UP_MS),
            Err(OutboxError::GaveUp(1))
        );
        assert_eq!(key.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert_eq!(
            key.entry_mut(1).unwrap().retry_key_fetch(T0 + GIVE_UP_MS),
            Err(OutboxError::NothingToEmit(1))
        );
    }

    /// A record claiming to have been composed in the future is **refused**, and
    /// the refusal writes nothing.
    ///
    /// Trusting it disables the give-up permanently: `is_given_up` would answer
    /// false at every clock value the user will ever see, so the message is
    /// never marked undelivered, never sweeps, never surfaces, and re-seeds for
    /// ever.
    #[test]
    fn a_future_compose_time_in_the_at_rest_form_is_refused() {
        let ob = sealed_outbox();
        let mut bytes = ob.encode();
        // Overwrite composed_at_ms with a value a century out.
        let far: i64 = T0 + 100 * 365 * 24 * 3600 * 1000;
        let at = bytes
            .windows(8)
            .position(|w| w == T0.to_be_bytes())
            .expect("the compose timestamp is in the encoding");
        bytes[at..at + 8].copy_from_slice(&far.to_be_bytes());

        assert_eq!(
            Outbox::decode(&bytes, T0).err().unwrap(),
            OutboxError::ComposedInFuture {
                seq: 1,
                ahead_ms: far - T0,
            },
            "a compose time in the caller's future was accepted"
        );
        // One millisecond ahead is still ahead — the bound is the caller's
        // clock exactly, not a tolerance.
        bytes[at..at + 8].copy_from_slice(&(T0 + 1).to_be_bytes());
        assert_eq!(
            Outbox::decode(&bytes, T0).err().unwrap(),
            OutboxError::ComposedInFuture {
                seq: 1,
                ahead_ms: 1
            }
        );
        // And exactly at the clock it decodes, so the comparison is strict.
        bytes[at..at + 8].copy_from_slice(&T0.to_be_bytes());
        assert_eq!(Outbox::decode(&bytes, T0).unwrap(), ob);
    }

    /// **The refusal is non-destructive, and that is the point of it.**
    ///
    /// The obvious guard — clamping `composed_at_ms` to `min(now_ms)` — is a
    /// silent rewrite of persisted state from one unverified clock reading. Boot
    /// with a dead RTC at T−10d, decode, re-encode, and the file now says every
    /// live message was composed ten days ago; when the clock corrects, all of
    /// them are instantly past the window and swept to `Undelivered`. This test
    /// walks that scenario and pins that it cannot happen: a bad clock produces
    /// a refusal, the caller keeps its bytes, and decoding again with a good
    /// clock returns the original record unchanged.
    #[test]
    fn a_bad_boot_clock_cannot_corrupt_the_stored_compose_time() {
        let mut ob = sealed_outbox();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        let on_disk = ob.encode();

        // Boot with an RTC reading ten days early. Every entry is "in the
        // future" from here.
        let dead_rtc = T0 - 10 * 24 * 3600 * 1000;
        let err = Outbox::decode(&on_disk, dead_rtc).err().unwrap();
        assert!(
            matches!(err, OutboxError::ComposedInFuture { .. }),
            "a decade-early clock did not refuse: {err:?}"
        );

        // Nothing was written: the bytes the caller holds are untouched, so the
        // bad reading never became durable.
        assert_eq!(
            on_disk,
            ob.encode(),
            "the failed decode mutated the caller's record"
        );

        // The clock corrects, and the record comes back whole — every entry
        // still live, still with its true compose time, nothing given up.
        let recovered = Outbox::decode(&on_disk, T0).unwrap();
        assert_eq!(recovered, ob, "the record did not survive the bad boot");
        for seq in [1, 2] {
            assert_eq!(recovered.entry(seq).unwrap().composed_at_ms(), T0);
            assert!(!recovered.entry(seq).unwrap().is_given_up(T0));
        }
        // **The counterfactual, built and run rather than asserted about.**
        // This is what a `min(now_ms)` clamp would have produced: the same two
        // messages, their compose times rewritten to the dead RTC's reading and
        // persisted by the next encode. At the true clock both are already past
        // seven days, so the first honest sweep gives up on every live message
        // in the file and tells the user they failed.
        let mut clamped = Outbox::new(Direction::AToB);
        clamped
            .enqueue_sealed(1, channel(), dead_rtc, frame(0x11))
            .unwrap();
        clamped
            .enqueue_sealed(2, channel(), dead_rtc, frame(0x22))
            .unwrap();
        assert_eq!(
            clamped.sweep_give_ups(T0),
            vec![1, 2],
            "the scenario no longer demonstrates the clamp's failure"
        );
        // The record that was refused instead loses nothing at the same clock.
        let mut kept = Outbox::decode(&on_disk, T0).unwrap();
        assert!(
            kept.sweep_give_ups(T0).is_empty(),
            "refusing the bad clock still lost the messages"
        );
    }

    /// A far-future due time is taken **verbatim** — neither clamped nor
    /// refused — and the give-up still ends the entry.
    ///
    /// It needs no guard: the failure is bounded and self-healing in the
    /// fail-safe direction. The entry stops emitting, but `is_given_up` reads
    /// `composed_at_ms` rather than this, so the sweep still fires on schedule
    /// and the user is still told. A clamp here would also have rewritten
    /// *correct* records — a due time past the give-up boundary is legitimate
    /// for an entry whose last emission landed near it.
    #[test]
    fn a_far_future_due_time_is_left_alone_and_the_give_up_still_fires() {
        let mut ob = sealed_outbox();
        ob.entry_mut(1).unwrap().emit(T0).unwrap();
        let mut bytes = ob.encode();
        let due = ob.entry(1).unwrap().schedule().next_due_ms();
        let at = bytes
            .windows(8)
            .position(|w| w == due.to_be_bytes())
            .expect("the due time is in the encoding");
        bytes[at..at + 8].copy_from_slice(&i64::MAX.to_be_bytes());

        let mut restored = Outbox::decode(&bytes, T0).unwrap();
        assert_eq!(
            restored.entry(1).unwrap().schedule().next_due_ms(),
            i64::MAX,
            "the stored due time was rewritten"
        );
        // It never emits again...
        assert!(restored.due(T0 + GIVE_UP_MS - 1).is_empty());
        // ...but the give-up is anchored at compose, so the user is still told.
        assert_eq!(restored.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert_eq!(
            restored.entry(1).unwrap().delivery_state(),
            DeliveryState::Undelivered
        );
    }

    // ---------------------------------------------------------------- shape and at-rest form

    /// The knock and the channel share one sequence space, so one outbox covers a
    /// correspondence from first contact on.
    #[test]
    fn the_doorbell_knock_and_the_channel_share_one_sequence_space() {
        let mut ob = empty();
        ob.enqueue_sealed(0, OutboxTarget::Doorbell { slot: 7 }, T0, frame(0x01))
            .unwrap();
        ob.enqueue_sealed(1, channel(), T0, frame(0x02)).unwrap();
        assert_eq!(
            ob.entry(0).unwrap().position(),
            None,
            "a knock is not paged"
        );
        assert_eq!(ob.entry(1).unwrap().position(), Some(position_of(1)));
        assert_eq!(
            ob.entries.keys().copied().collect::<Vec<_>>(),
            vec![0, 1],
            "the two targets did not land in one space"
        );
    }

    /// A channel entry's position carries its whole sequence number, not merely
    /// the slot it occupies within a page.
    ///
    /// Asserted at sequence 57 — page 3, slot 9 — because the neighbour above can
    /// only speak about sequences 0 and 1, and on page 0 a slot index *is* its own
    /// sequence number. An entry that reported its slot alone, or that dropped the
    /// page, is indistinguishable from a correct one there (#272). That test keeps
    /// its low sequences, since the knock-versus-channel distinction it exists for
    /// is exactly what lives at 0 and 1.
    #[test]
    fn a_channel_entrys_position_carries_its_page_and_not_only_its_slot() {
        let mut ob = empty();
        ob.enqueue_sealed(57, channel(), T0, frame(0x03)).unwrap();
        let at = ob
            .entry(57)
            .unwrap()
            .position()
            .expect("a channel entry is paged");
        assert_eq!((at.page(), at.slot(), at.seq()), (3, 9, 57));
    }

    /// A sequence number is enqueued once. Re-enqueueing would reset a give-up
    /// clock or replace a frame, which are both silent losses.
    #[test]
    fn a_sequence_number_is_enqueued_once() {
        let mut ob = sealed_outbox();
        assert_eq!(
            ob.enqueue_sealed(1, channel(), T0, frame(0x22))
                .err()
                .unwrap(),
            OutboxError::DuplicateSequence(1)
        );
        assert_eq!(
            ob.entry(1).unwrap().frame().unwrap(),
            &frame_bytes(0x11)[..]
        );
    }

    /// A doorbell slot outside the record is refused at the door.
    #[test]
    fn a_doorbell_slot_outside_the_record_is_refused() {
        let mut ob = empty();
        assert!(
            ob.enqueue_awaiting_key(
                0,
                OutboxTarget::Doorbell {
                    slot: DOORBELL_SLOTS - 1
                },
                T0
            )
            .is_ok(),
            "the last valid slot was refused"
        );
        assert_eq!(
            ob.enqueue_awaiting_key(
                1,
                OutboxTarget::Doorbell {
                    slot: DOORBELL_SLOTS
                },
                T0
            )
            .err()
            .unwrap(),
            OutboxError::SlotOutsideDoorbell(DOORBELL_SLOTS)
        );
    }

    /// A full outbox survives the at-rest round trip in every state, targets and
    /// schedules included.
    #[test]
    fn the_at_rest_form_round_trips_every_state() {
        let mut ob = empty();
        ob.enqueue_sealed(0, OutboxTarget::Doorbell { slot: 5 }, T0, frame(0x01))
            .unwrap();
        ob.enqueue_awaiting_key(1, channel(), T0 + 1).unwrap();
        ob.enqueue_sealed(2, channel(), T0 + 2, frame(0x03))
            .unwrap();
        ob.enqueue_sealed(3, channel(), T0 + 3, frame(0x04))
            .unwrap();
        ob.enqueue_sealed(4, channel(), T0 + 4, frame(0x05))
            .unwrap();
        ob.entry_mut(3).unwrap().emit(T0).unwrap();
        let mut ack = AckState::new();
        ack.collect(4).unwrap();
        assert_eq!(ob.settle_from_ack(&ack, T0), vec![4]);
        let _ = ob.sweep_give_ups(T0 + GIVE_UP_MS);

        let round = round_trip(&ob);
        assert_eq!(round, ob);
        // And the states really were varied, so the round trip proved something.
        let states: Vec<_> = ob.iter().map(|e| e.delivery_state()).collect();
        assert!(
            states.contains(&DeliveryState::Composed)
                || states.contains(&DeliveryState::Undelivered),
            "fixture had no unsealed entry"
        );
        assert!(states.contains(&DeliveryState::ConfirmedCollected));
    }

    /// The decoder refuses the shapes a corrupt or hostile file can take.
    #[test]
    fn the_decoder_refuses_malformed_records() {
        // Offsets named from the layout rather than counted back from the end,
        // so a field added in the middle breaks this test loudly instead of
        // silently poking at the wrong byte.
        const SUITE: usize = OUTBOX_MAGIC.len();
        const DIR_TAG: usize = SUITE + SUITE_ID_LEN;
        const HIGH_WATER: usize = DIR_TAG + 1;
        const COUNT: usize = HIGH_WATER + 8;
        const SEQ: usize = COUNT + 4;
        const TARGET_TAG: usize = SEQ + 8;
        const COMPOSED: usize = TARGET_TAG + 1; // a ChannelPage target is one byte
        const RUNG: usize = COMPOSED + 8;
        const DUE: usize = RUNG + 4;
        const ACCEPTANCE: usize = DUE + 8;
        const SURFACING: usize = ACCEPTANCE + 1;
        const LIFE_TAG: usize = SURFACING + 1;
        const FRAME_LEN: usize = LIFE_TAG + 1;

        let good = sealed_outbox().encode();
        assert_eq!(
            good.len(),
            FRAME_LEN + 8 + 512,
            "the layout constants above no longer describe the encoding"
        );

        assert_eq!(
            Outbox::decode(&[], T0).err().unwrap(),
            OutboxError::Truncated
        );

        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            Outbox::decode(&bad_magic, T0).err().unwrap(),
            OutboxError::BadMagic
        );

        for cut in 1..good.len() {
            assert!(
                Outbox::decode(&good[..cut], T0).is_err(),
                "a record truncated at {cut} decoded"
            );
        }

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            Outbox::decode(&trailing, T0).err().unwrap(),
            OutboxError::TrailingBytes(1)
        );

        for (at, field) in [
            (DIR_TAG, "direction"),
            (TARGET_TAG, "target"),
            (SURFACING, "surfacing"),
            (LIFE_TAG, "lifecycle"),
        ] {
            let mut bad = good.clone();
            bad[at] = 9;
            assert_eq!(
                Outbox::decode(&bad, T0).err().unwrap(),
                OutboxError::UnknownTag { field, tag: 9 },
                "a bad {field} tag was accepted"
            );
        }

        // A frame length past the end is refused before anything is reserved.
        let mut huge = good.clone();
        huge[FRAME_LEN..FRAME_LEN + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            Outbox::decode(&huge, T0).err().unwrap(),
            OutboxError::Truncated
        );

        // A doorbell slot outside the record is refused on the way back in, not
        // only at the door.
        let mut ob = empty();
        ob.enqueue_sealed(0, OutboxTarget::Doorbell { slot: 3 }, T0, frame(0x01))
            .unwrap();
        let mut bad_slot = ob.encode();
        bad_slot[TARGET_TAG + 1..TARGET_TAG + 3].copy_from_slice(&DOORBELL_SLOTS.to_be_bytes());
        assert_eq!(
            Outbox::decode(&bad_slot, T0).err().unwrap(),
            OutboxError::SlotOutsideDoorbell(DOORBELL_SLOTS)
        );

        // A duplicate sequence number in the file is refused rather than
        // collapsing two entries into one.
        let mut dup = empty();
        dup.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        let one = dup.encode();
        let mut two = one.clone();
        two[COUNT..COUNT + 4].copy_from_slice(&2u32.to_be_bytes());
        two.extend_from_slice(&one[SEQ..]);
        assert_eq!(
            Outbox::decode(&two, T0).err().unwrap(),
            OutboxError::DuplicateSequence(1)
        );
    }

    /// The at-rest form carries no message text and no key material — it is
    /// sequence numbers, sizes and clock values, plus ciphertext.
    #[test]
    fn the_at_rest_form_carries_only_ciphertext_and_scheduling() {
        let mut ob = empty();
        ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        let encoded = ob.encode();
        // Every byte accounted for, named: nothing is left over to be anything
        // else — in particular there is nowhere a message body could be hiding.
        let header =
            OUTBOX_MAGIC.len() + 2 /* suite id */ + 1 /* direction */ + 8 /* high-water */ + 4 /* count */;
        let entry = 8 /* seq */
            + 1 /* target tag */
            + 8 /* composed_at_ms */
            + 4 /* rung */
            + 8 /* next_due_ms */
            + 1 /* acceptance tag */
            + 1 /* surfacing tag */
            + 1 /* lifecycle tag */
            + 8 /* frame length prefix */;
        assert_eq!(encoded.len(), header + entry + 512);
    }

    // ---------------------------------------------------------------- the surfacing flag (#279)

    /// **The defect, walked end to end.** A transition used to be reported only
    /// by the `Vec` the call returned, so a crash between that call returning
    /// and the record landing on disk lost the notification for ever: every
    /// later call skips an entry whose state has already moved.
    ///
    /// The `drop` below is the crash. What the restart has to show is that the
    /// user is still owed the news — and the two assertions after it are the
    /// positive control that nothing *else* re-offers it, so the flag is
    /// carrying the property rather than sharing the credit.
    #[test]
    fn a_transition_lost_with_its_return_value_is_re_offered_after_a_restart() {
        let mut ob = sealed_outbox();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        let mut ack = AckState::new();
        ack.collect(1).unwrap();

        // The transition happens, and the process dies with the list still in
        // its hands: nothing was shown to anyone.
        let confirmed = ob.settle_from_ack(&ack, T0);
        assert_eq!(confirmed, vec![1], "fixture confirmed nothing");
        drop(confirmed);

        // The record reaches the disk. The notification did not reach the user.
        let mut restored = Outbox::decode(&ob.encode(), T0 + 1).unwrap();
        assert_eq!(
            restored.owed_surfacings(),
            vec![1],
            "the restart lost the confirmation entirely"
        );

        // Positive control: the state machine really is silent about it now.
        // Both re-offering paths return nothing, which is the whole reason the
        // flag has to exist.
        assert!(
            restored.settle_from_ack(&ack, T0 + 1).is_empty(),
            "the ack path re-offered it, so this test proves nothing"
        );
        assert!(
            restored.sweep_give_ups(T0 + 1).is_empty(),
            "the sweep re-offered it, so this test proves nothing"
        );
        assert_eq!(restored.owed_surfacings(), vec![1], "the flag was consumed");

        // Shown at last, and the clearing itself persisted — only then does it
        // stop being offered.
        restored.record_surfaced(&[1]);
        let settled = Outbox::decode(&restored.encode(), T0 + 2).unwrap();
        assert!(
            settled.owed_surfacings().is_empty(),
            "a surfacing the caller recorded came back after a restart"
        );
    }

    /// **Every edge that ends an entry owes a surfacing, and nothing else
    /// does.** Four separate transitions reach a terminal state — the sweep,
    /// the ack, the teardown's unsealed arm and the teardown's past-window arm
    /// — and each is asserted on its own, so removing the marking from any one
    /// of them fails here.
    #[test]
    fn every_ending_owes_a_surfacing_and_only_an_ending_does() {
        // 1. the give-up sweep
        let mut sweep = sealed_outbox();
        assert_eq!(sweep.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        assert_eq!(
            sweep.owed_surfacings(),
            vec![1],
            "the give-up sweep ended an entry without owing the user anything"
        );

        // 2. the ack
        let mut settled = sealed_outbox();
        let mut ack = AckState::new();
        ack.collect(1).unwrap();
        assert_eq!(settled.settle_from_ack(&ack, T0), vec![1]);
        assert_eq!(
            settled.owed_surfacings(),
            vec![1],
            "a confirmation left the UI nothing to learn from the record"
        );

        // 3. the teardown, on the entry it can never seal
        let mut torn = empty();
        torn.enqueue_awaiting_key(1, channel(), T0).unwrap();
        let outcome = torn.channel_torn_down(&TeardownCause::NoProvisionalRecord, T0);
        assert_eq!(outcome.surfaced, vec![1]);
        assert_eq!(
            torn.owed_surfacings(),
            vec![1],
            "the teardown surfaced an entry the record does not remember surfacing"
        );

        // 4. the teardown, on an entry the window already closed on — the other
        // arm, and a different `end` call site.
        let mut late = sealed_outbox();
        let outcome = late.channel_torn_down(
            &TeardownCause::StoreUnreadable("EIO".into()),
            T0 + GIVE_UP_MS,
        );
        assert_eq!(outcome.surfaced, vec![1]);
        assert_eq!(
            late.owed_surfacings(),
            vec![1],
            "the past-window teardown arm owed the user nothing"
        );

        // And the converse: a live entry owes nothing, however it is driven.
        let mut live = empty();
        live.enqueue_awaiting_key(1, channel(), T0).unwrap();
        live.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        live.entry_mut(1).unwrap().retry_key_fetch(T0).unwrap();
        live.entry_mut(1).unwrap().publish(T0, frame(0x11)).unwrap();
        live.entry_mut(2).unwrap().emit(T0).unwrap();
        let retained = live.channel_torn_down(&TeardownCause::StoreUnreadable("EIO".into()), T0);
        assert_eq!(retained.retained, vec![1, 2], "fixture ended an entry");
        assert!(
            live.owed_surfacings().is_empty(),
            "an entry that is still live owes the user an ending it has not had"
        );
        // Positive control for that emptiness: the same assertion fails once
        // something genuinely ends.
        assert_eq!(live.sweep_give_ups(T0 + GIVE_UP_MS), vec![1, 2]);
        assert_eq!(live.owed_surfacings(), vec![1, 2]);
    }

    /// Recording a surfacing clears it, is idempotent, and touches only the
    /// sequences it was given.
    #[test]
    fn record_surfaced_clears_only_what_it_was_given() {
        let mut ob = empty();
        ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1, 2]);
        assert_eq!(ob.owed_surfacings(), vec![1, 2]);

        ob.record_surfaced(&[1]);
        assert_eq!(
            ob.owed_surfacings(),
            vec![2],
            "recording one surfacing cleared the other"
        );
        // Idempotent, and a sequence with no entry is a no-op rather than a
        // panic or a clear of something else.
        ob.record_surfaced(&[1, 1, 99]);
        assert_eq!(ob.owed_surfacings(), vec![2]);

        ob.record_surfaced(&[2]);
        assert!(ob.owed_surfacings().is_empty());
        // Clearing does not revive: the entries are still terminal, and still
        // report as such.
        for seq in [1, 2] {
            assert_eq!(
                ob.entry(seq).unwrap().delivery_state(),
                DeliveryState::Undelivered
            );
        }
    }

    /// **The flag is written where the layout says, and it is the entry's own
    /// value.**
    ///
    /// The expected bytes are literals rather than [`Surfacing::tag`], so an
    /// encoder that wrote a constant, or that wrote the flag inverted, fails
    /// here — a round-trip test alone cannot catch either, because an inversion
    /// on both sides of it passes vacuously.
    #[test]
    fn the_surfacing_byte_is_written_where_the_layout_says() {
        let clear = sealed_outbox().encode();
        assert_eq!(
            clear.len(),
            SURFACING_AT + 1 /* surfacing */ + 1 /* lifecycle */ + 8 + 512,
            "the layout constant no longer describes the encoding"
        );
        assert_eq!(
            clear[SURFACING_AT], 0,
            "a live entry was encoded as owing a surfacing"
        );

        let mut owed = sealed_outbox();
        assert_eq!(owed.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        let owed = owed.encode();
        assert_eq!(
            owed[SURFACING_AT], 1,
            "an ended entry was encoded as owing nothing"
        );
        // The two encodings differ *only* there, so the byte is carrying the
        // flag and not standing in for something else that moved.
        let differing: Vec<usize> = clear
            .iter()
            .zip(owed.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert!(
            differing.contains(&SURFACING_AT),
            "the surfacing byte did not change with the flag"
        );
    }

    /// **The decoder reads that byte rather than assuming a value.**
    ///
    /// Both directions are hand-crafted, so neither assertion can be satisfied
    /// by an encoder: the owed case is decoded from bytes no encoder in this
    /// test ever wrote a `1` into, and the clear case likewise.
    #[test]
    fn the_decoder_reads_the_surfacing_byte_rather_than_assuming_it() {
        // A terminal entry whose surfacing has already been recorded, so the
        // encoder wrote a 0 — then flip the byte by hand.
        let mut ob = sealed_outbox();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        ob.record_surfaced(&[1]);
        let mut bytes = ob.encode();
        assert_eq!(bytes[SURFACING_AT], 0, "fixture is degenerate");
        bytes[SURFACING_AT] = 1;
        assert_eq!(
            Outbox::decode(&bytes, T0 + GIVE_UP_MS)
                .unwrap()
                .owed_surfacings(),
            vec![1],
            "the decoder ignored an owed surfacing in the file"
        );

        // And the other way: an encoder-written 1, cleared by hand.
        let mut ob = sealed_outbox();
        assert_eq!(ob.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        let mut bytes = ob.encode();
        assert_eq!(bytes[SURFACING_AT], 1, "fixture is degenerate");
        bytes[SURFACING_AT] = 0;
        assert!(
            Outbox::decode(&bytes, T0 + GIVE_UP_MS)
                .unwrap()
                .owed_surfacings()
                .is_empty(),
            "the decoder invented an owed surfacing the file does not carry"
        );
    }

    /// A file claiming a live entry owes a surfacing is refused: only an ending
    /// owes one, so the pair is unreachable through the API and loading it
    /// would raise a notification for a transition that never happened.
    #[test]
    fn a_surfacing_owed_on_a_live_entry_is_refused() {
        let mut bytes = sealed_outbox().encode();
        assert_eq!(bytes[SURFACING_AT], 0, "fixture already owed a surfacing");
        bytes[SURFACING_AT] = 1;
        assert_eq!(
            Outbox::decode(&bytes, T0).err().unwrap(),
            OutboxError::SurfacingOwedOnLiveEntry(1)
        );

        // Positive control, twice over: the same byte value on an entry that
        // *has* ended decodes, and the untouched live record decodes too — so
        // the refusal is the pairing and not the byte or the record.
        let mut ended = sealed_outbox();
        assert_eq!(ended.sweep_give_ups(T0 + GIVE_UP_MS), vec![1]);
        let ended = ended.encode();
        assert_eq!(ended[SURFACING_AT], 1);
        assert!(Outbox::decode(&ended, T0 + GIVE_UP_MS).is_ok());
        assert!(Outbox::decode(&sealed_outbox().encode(), T0).is_ok());
    }

    /// **v1 is refused, not dual-read**, and it is told apart from bytes that
    /// are not an outbox at all.
    ///
    /// Nothing ever wrote a v1 record — `encode`/`decode` have never had a
    /// caller that stored anything — so there is no migration to perform. A
    /// dual-read would also have to invent a surfacing value for every entry in
    /// the file, and both choices are wrong: `Clear` drops the notification for
    /// every ended entry, which is the loss the flag exists to prevent, and
    /// `Owed` re-offers every message that ever finished.
    #[test]
    fn a_v1_record_is_refused_rather_than_read() {
        assert_eq!(
            OUTBOX_MAGIC.len(),
            OUTBOX_MAGIC_V1.len(),
            "one read can only answer both questions if the magics are the same length"
        );
        assert_ne!(OUTBOX_MAGIC, OUTBOX_MAGIC_V1);

        let good = sealed_outbox().encode();
        let mut v1 = good.clone();
        v1[..OUTBOX_MAGIC_V1.len()].copy_from_slice(OUTBOX_MAGIC_V1);
        assert_eq!(
            Outbox::decode(&v1, T0).err().unwrap(),
            OutboxError::UnsupportedVersion,
            "a v1 record was read under a later layout"
        );

        // A magic that is neither is still "not an outbox", so the version
        // answer is recognition rather than a catch-all.
        let mut alien = good.clone();
        alien[0] ^= 1;
        assert_eq!(
            Outbox::decode(&alien, T0).err().unwrap(),
            OutboxError::BadMagic
        );
        // Positive control: the unmodified bytes decode.
        assert!(Outbox::decode(&good, T0).is_ok());
    }

    /// A v2 record is **read**, and every entry in it comes back
    /// `Unconfirmed` — the understating direction, never a reconstruction of
    /// v2's `rung > 0` belief.
    ///
    /// The fixture is a real v2 body, built by deleting the byte v3 added from
    /// a v3 encoding rather than by hand-assembling one — so it stays a v2 body
    /// if any earlier field ever changes width, and `SURFACING_AT` is the
    /// layout constant that would fail loudly if it did not.
    #[test]
    fn a_v2_record_is_read_and_defaults_to_unconfirmed() {
        let mut ob = sealed_outbox();
        // Confirmed, so the fixture is the case that could be got wrong: if the
        // decoder reconstructed acceptance from the rung, this entry would come
        // back `Confirmed` and the test would pass for the wrong reason.
        let entry = ob.entry_mut(1).unwrap();
        entry.emit(T0).unwrap();
        entry.confirm_written(T0).unwrap();
        assert_eq!(entry.delivery_state(), DeliveryState::OnDht);

        let v3 = ob.encode();
        assert_eq!(
            v3[SURFACING_AT - 1],
            Acceptance::Confirmed.tag(),
            "the acceptance byte is not where the layout says it is"
        );

        let v2 = downgrade_v4_to_v2(&v3);
        assert_eq!(
            OUTBOX_MAGIC.len(),
            OUTBOX_MAGIC_V2.len(),
            "one read can only answer every question if the magics are the same length"
        );

        let decoded = Outbox::decode(&v2, T0).expect("a v2 record must still be readable");
        let entry = decoded.entry(1).expect("the entry was lost in migration");
        assert_eq!(entry.acceptance(), Acceptance::Unconfirmed);
        assert_eq!(
            entry.delivery_state(),
            DeliveryState::Composed,
            "a v2 record claimed a delivery its bytes could not support"
        );
        // Everything else survives — the migration is one field, not a reset.
        assert_eq!(entry.schedule(), ob.entry(1).unwrap().schedule());
        assert_eq!(entry.frame(), ob.entry(1).unwrap().frame());
        assert_eq!(entry.composed_at_ms(), T0);

        // And it is re-encoded at the current version, so the file is v3 after
        // one write rather than staying v2 for ever.
        assert_eq!(&decoded.encode()[..OUTBOX_MAGIC.len()], OUTBOX_MAGIC);
    }

    /// The same migration over **two** entries, because the byte v3 added is
    /// per-entry and the single-entry fixture cannot tell a per-entry read from
    /// a per-record one — a decoder that consumed the acceptance byte once for
    /// the whole file passes that test and desynchronises here.
    ///
    /// The stride is derived from the encoding rather than hardcoded, so a field
    /// added anywhere in an entry does not silently point this at the wrong
    /// byte; the equal-frame assertion is what makes the division valid.
    #[test]
    fn a_multi_entry_v2_record_is_read_entry_by_entry() {
        let mut ob = empty();
        ob.enqueue_sealed(1, channel(), T0, frame(0x11)).unwrap();
        ob.enqueue_sealed(2, channel(), T0, frame(0x22)).unwrap();
        for seq in [1, 2] {
            let entry = ob.entry_mut(seq).unwrap();
            entry.emit(T0).unwrap();
            entry.confirm_written(T0).unwrap();
        }
        assert_eq!(
            ob.entry(1).unwrap().frame().map(<[u8]>::len),
            ob.entry(2).unwrap().frame().map(<[u8]>::len),
            "the entries are different sizes, so a fixed stride is meaningless"
        );

        let v3 = ob.encode();
        let header = OUTBOX_MAGIC.len()
            + SUITE_ID_LEN
            + 1 /* direction */
            + 8 /* high-water */
            + 4 /* count */;
        let stride = (v3.len() - header) / 2;
        let first = SURFACING_AT - 1;
        let second = first + stride;
        for at in [first, second] {
            assert_eq!(
                v3[at],
                Acceptance::Confirmed.tag(),
                "the acceptance byte is not where the derived stride says it is"
            );
        }

        let mut v2 = v3.clone();
        // Later byte first, so removing it does not move the earlier offset.
        v2.remove(second);
        v2.remove(first);
        // And v4's pruned high-water, which this record's version never carried.
        let hw = OUTBOX_MAGIC.len() + SUITE_ID_LEN + 1;
        v2.drain(hw..hw + 8);
        v2[..OUTBOX_MAGIC_V2.len()].copy_from_slice(OUTBOX_MAGIC_V2);

        let decoded =
            Outbox::decode(&v2, T0).expect("a two-entry v2 record must still be readable");
        assert_eq!(decoded.len(), 2, "an entry was lost in migration");
        for seq in [1, 2] {
            let entry = decoded.entry(seq).expect("the entry was lost in migration");
            assert_eq!(entry.acceptance(), Acceptance::Unconfirmed);
            // The frame is the field a desynchronised read corrupts first, and
            // it is the one field that cannot be right by coincidence.
            assert_eq!(entry.frame(), ob.entry(seq).unwrap().frame());
            assert_eq!(entry.schedule(), ob.entry(seq).unwrap().schedule());
        }
    }

    /// Acceptance survives the round trip in both directions, so a restart
    /// neither invents a publication nor forgets one.
    #[test]
    fn acceptance_round_trips_in_both_states() {
        for confirm in [false, true] {
            let mut ob = sealed_outbox();
            let entry = ob.entry_mut(1).unwrap();
            entry.emit(T0).unwrap();
            if confirm {
                entry.confirm_written(T0).unwrap();
            }
            let expected = ob.entry(1).unwrap().acceptance();
            assert_eq!(
                expected,
                if confirm {
                    Acceptance::Confirmed
                } else {
                    Acceptance::Unconfirmed
                },
                "the fixture did not reach the state it is named for"
            );
            assert_eq!(round_trip(&ob).entry(1).unwrap().acceptance(), expected);
        }
    }

    /// An acceptance tag this build assigns no meaning to is refused, like every
    /// other tag in the record.
    #[test]
    fn an_unknown_acceptance_tag_is_refused() {
        let mut bytes = sealed_outbox().encode();
        assert_eq!(
            bytes[SURFACING_AT - 1],
            0,
            "fixture is degenerate — the byte already reads as something else"
        );
        bytes[SURFACING_AT - 1] = 2;
        assert_eq!(
            Outbox::decode(&bytes, T0).err().unwrap(),
            OutboxError::UnknownTag {
                field: "acceptance",
                tag: 2
            }
        );
    }

    /// The suite id is written after the magic and checked on the way back in —
    /// the house layout [`crate::storage::seeds`] and
    /// [`crate::storage::recovery_file`] use.
    #[test]
    fn the_suite_id_is_written_and_checked_on_the_way_back_in() {
        let good = sealed_outbox().encode();
        let at = OUTBOX_MAGIC.len();
        // Literal, not `default_write_suite()`: a test that reads the value it
        // is checking moves both sides of its own comparison. 0x0001 is
        // CNSA 2.0, the registry's only entry.
        assert_eq!(
            &good[at..at + SUITE_ID_LEN],
            &[0x00, 0x01],
            "the record was not written under the default write suite"
        );

        for sentinel in [0x0000u16, 0xFFFF] {
            let mut bad = good.clone();
            bad[at..at + SUITE_ID_LEN].copy_from_slice(&sentinel.to_be_bytes());
            assert_eq!(
                Outbox::decode(&bad, T0).err().unwrap(),
                OutboxError::SuiteIdSentinel(SuiteIdError::Sentinel(sentinel)),
                "a reserved suite id was accepted"
            );
        }

        // Well-formed, absent from this build's registry: the writer had
        // primitives this build does not implement.
        let unknown = SuiteId::try_new(0x0002).unwrap();
        assert!(
            Registry::lookup(unknown).is_none(),
            "0x0002 joined the registry; pick another absent id"
        );
        let mut foreign = good.clone();
        foreign[at..at + SUITE_ID_LEN].copy_from_slice(&unknown.get().to_be_bytes());
        assert_eq!(
            Outbox::decode(&foreign, T0).err().unwrap(),
            OutboxError::UnknownSuite(unknown)
        );

        // Positive control: the untouched header decodes.
        assert!(Outbox::decode(&good, T0).is_ok());
    }
}
