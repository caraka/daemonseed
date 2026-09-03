//! Delivery acknowledgement — what the receiver has settled, and what the sender
//! may truthfully claim (ISC-C39 / ISC-A-C21).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § D-DELIV, § v3 (crypto F-3/F-6), § v6 (erasure F2), § Build-contract item (ii),
//! and the appended build notes.
//!
//! This module is the pure half of the acknowledgement: the key the ack is sealed
//! under, the preimage it is signed over, and the state machine that decides what
//! "collected up to here" means. It publishes nothing, reads nothing, and knows
//! about no record — the transport slice owns the ack record, its jittered
//! standalone cadence, and the piggyback path. The part of that cadence which is
//! decidable without a record — the client-global allowance governing how often a
//! standalone acknowledgement may be written at all — is
//! [`ack_budget`](crate::dm::ack_budget); what remains with the transport slice is
//! the record, the jitter within a window, and the piggyback.
//!
//! ## Why an acknowledgement exists at all
//!
//! Veilid has no TTL. A value survives exactly as long as somebody re-seeds it,
//! so "it is on the DHT" and "they read it" are different facts and the network
//! reports only the first. Every earlier draft tried to infer the second — from
//! lobby presence, from a peer writing *something*, from the message ageing out —
//! and each inference had the same failure: it certified delivery from evidence
//! that was compatible with permanent silent loss, and the sender's UI then said
//! *delivered* about a message nobody ever saw.
//!
//! So delivery here is **fail-safe**. A message defaults to *not delivered* and
//! flips to *confirmed-collected* on exactly one thing: an authenticated statement
//! by the peer that it holds that sequence number. Nothing else confirms. When the
//! ack itself is lost — and it can be, it lives on the same substrate — the cost
//! is extra re-seeding until it lands, or an honest *undelivered* at the seven-day
//! give-up. Never a false *delivered*.
//!
//! ## Two shapes in one statement, and both are needed
//!
//! **The high-water is a contiguous prefix**, not the highest sequence seen. That
//! distinction is the whole of the honesty. A max-seen scalar advanced past
//! everything below it, so one message lost out of ten would be reported as ten
//! collected — a false confirmation produced by the acknowledgement itself, which
//! is worse than having none.
//!
//! A contiguous prefix alone then has the opposite failure, and it is not
//! hypothetical: one permanently lost message holds the prefix at the gap
//! **forever**, so every message after it stays unconfirmed for the life of the
//! conversation however faithfully it was collected. The sender re-seeds all of
//! them to the give-up and reports a conversation of undelivered messages that
//! were in fact read.
//!
//! Hence the second shape: **a bounded set of collected sequence numbers beyond
//! the prefix**, so a message collected downstream of a permanent gap confirms
//! truthfully rather than sitting stuck behind it. It only ever lets truthful
//! confirmation reach *past* a gap; it never asserts anything about the gap.
//!
//! ## Why runs, and why a cap
//!
//! The set is stored and encoded as **runs** — `(gap, extra)` pairs — because that
//! is what makes it boundable. A run costs sixteen bytes whether it spans one
//! message or a billion, so the size of this structure tracks the number of
//! *gaps*, not the length of the conversation. A healthy conversation collecting
//! in order carries zero runs: everything folds into the prefix as it arrives.
//!
//! The number of runs is capped at [`MAX_ACK_RUNS`], and **the cap refuses rather
//! than truncates**. Truncation would drop a position that had been confirmed,
//! and un-confirming is the one direction this state must never move (see below).
//! A refusal instead leaves the state exactly as it was and reports
//! [`AckError::TooManyRuns`], which is loud, recoverable, and self-healing: the
//! positions that could not be recorded stay unconfirmed, the sender keeps
//! re-seeding them, and the give-up rule below collapses the accumulated gaps into
//! the prefix and frees the capacity again. The cost of a refusal is re-seeding, in
//! the fail-safe direction.
//!
//! ## Monotonic union-merge
//!
//! Both parties hold one of these: the receiver builds its own by collecting, the
//! sender holds a merged view of the acks it has received — and a receiver that
//! lost local state merges its own last published ack back into itself. Every
//! merge is a **union**: the high-water never regresses and no recorded position
//! is ever cleared.
//!
//! That is not tidiness. Acks arrive out of order, are re-seeded, and are replayed
//! by anyone who can copy a record — and while a channel page is owner-write-gated,
//! a *stale* ack is a value the peer genuinely signed, so no signature check
//! rejects it. Under any rule but union, replaying last week's ack would walk a
//! sender's confirmations backwards and resurrect messages the recipient is
//! holding. Under union it is a no-op.
//!
//! ## The ceiling: monotonic means a peer's claim must be bounded on arrival
//!
//! Union-merge is what makes a replay inert, and it is also what makes an
//! *inflated* claim permanent. A high-water only ever rises, so a peer that signs
//! one ack claiming `2^40` — through a bug or on purpose — moves this state
//! somewhere it has no way back from: every message the sender composes
//! afterwards reads as settled before it is even transmitted, and the UI says
//! delivered for messages the peer never received. That is the exact failure the
//! opening of this module exists to prevent, and it is not the same case as the
//! liar-about-its-own-collection noted on [`AckState::decode_unvalidated`] — that
//! one costs the liar its own messages, this one costs the *honest sender* the
//! truth about every message it will ever send.
//!
//! The bound is available locally and needs no trust: **the highest sequence
//! number we have actually sent on that direction.** A peer cannot have collected
//! what was never transmitted, so nothing above it is a claim any honest peer
//! could make. [`AckState::merge_peer_ack`] takes that ceiling as a required
//! argument — it is the only path by which a peer's statement enters this state,
//! and there is no shape of it that omits the bound.
//!
//! **It clips rather than refuses, and the reason is that a peer's ack is itself
//! monotonic.** A refusal is not a retry here: the peer's high-water never comes
//! back down, so a single over-ceiling ack would be re-seeded, re-refused, and
//! re-refused forever, taking with it the *truthful* low half of the same ack.
//! A local ceiling can legitimately lag — a client that published sequence 12 and
//! crashed before persisting its outbox recovers believing it sent 9 — and under
//! refusal that one crash would permanently report a whole conversation as
//! undelivered although it was read. Clipping keeps the honest prefix, discards
//! only what no honest peer could have claimed, and heals as the ceiling advances.
//! It is also strictly fail-safe: a clipped state is a subset of the claim, so the
//! error can only ever be toward *undelivered*.
//!
//! Clipping applies to the peer's copy alone. Our own retained state is never
//! clipped, because the ceiling can regress across a restart while our
//! confirmations may not — un-confirming is the one direction this state must not
//! move, whatever the reason.
//!
//! Because the clip changes the statement, it happens on the way into our state
//! and **not** in the decoder: a verifier rebuilds the signature preimage from the
//! decoded state, so a decoder that silently altered the state would rebuild a
//! preimage the peer's signature cannot match. The order is decode → verify →
//! merge under the ceiling.
//!
//! That leaves a decoded statement in the caller's hands with nothing bounding it,
//! so the decoder does not return an [`AckState`]: it returns a [`PeerAck`], which
//! has no query methods at all and can be spent only on
//! [`AckState::merge_peer_ack`]. There is no `is_settled` on it, no prefix to be
//! taken for a checked one, and nothing to query before the ceiling has been
//! applied — see [`PeerAck`] for the precise bound, which is about what can be
//! *asked*, not about bytes being unreachable.
//!
//! ## Prefix-advance-on-give-up, and the one thing this module cannot enforce
//!
//! Without a rule for permanent gaps the run set grows without bound: every
//! message the sender abandons at the seven-day give-up leaves a hole that nothing
//! will ever fill, and each hole is a run forever. [`AckState::abandon`] is that
//! rule — the receiver advances its cursor past a position both parties have given
//! up on, exactly as if it had been collected, and the runs above it fold into the
//! prefix.
//!
//! **Consequence, stated plainly because it is the sharp edge of this module:**
//! after `abandon`, [`AckState::is_settled`] answers `true` for that position.
//! What this state truthfully carries is *settled* — "stop re-seeding this, I will
//! never ask for it again" — and only the sender can tell settled-because-collected
//! from settled-because-abandoned, because only the sender knows which of its own
//! messages it gave up on. That is why the query is named for *settled* and not
//! for delivery: there is no method on this type that answers "was it received",
//! because this type does not know. The persisted outbox is where that is held:
//! *undelivered* is a terminal state and a given-up message is never re-consulted
//! against an ack. This module cannot enforce that, and a caller that consults an
//! ack about a message it has already abandoned will read an answer that means the
//! opposite of what it wants. `an_abandoned_position_reads_as_settled` pins the
//! behaviour so it is discovered here rather than in a UI.
//!
//! ## The key roots in `AR`, not in the ratchet
//!
//! `K_ack(dir)` derives from the conversation's retained address root, under a
//! salt and label of its own. Rooting it in the ratchet root was tried and refuted
//! (crypto F-3): the ratchet advances independently on each side, so two parties
//! at different generations would derive different ack keys and the acknowledgement
//! would go dark exactly when a conversation was busiest. `AR` is stable for the
//! life of the conversation, derivable by both parties from the first-contact
//! secret and by nobody else, so the ack key never desyncs and is still secret.
//!
//! It is **per-direction** (F-6) for the same reason every other DM derivation is:
//! one key covering both halves is one key whose compromise covers both halves,
//! and it invites an AES-GCM nonce collision across two independently-counting
//! writers.
//!
//! The honest cost, recorded in the frozen residuals: because `AR` is retained,
//! **acks are not forward-secret** even though message content is. A future
//! compromise of the identity key recovers `ss0`, hence `AR`, hence every ack this
//! conversation ever wrote. What that yields is a high-water counter and a gap
//! pattern — collection metadata of the same class as the address graph the same
//! compromise already exposes, and no message content whatsoever.
//!
//! ## `chan_id` never leaves
//!
//! An [`AckState`] holds no `chan_id` and neither its encoding nor its decoding
//! takes one. The identifier appears in exactly one place in this module — the
//! signature preimage — and it is a borrowed array there, so there is no shape in
//! this API that would carry it onto the wire. A receiver reconstructs it from the
//! record it derived; serializing it would collapse the address scatter the whole
//! channel rests on.

use std::ops::RangeInclusive;

use oxicrypt_kdf::HkdfSha384;

use crate::dm::domain;
use crate::dm::firstcontact::ROOT_LEN;
use crate::dm::paging::ADDRESS_ROOT_LEN;
use crate::dm::push_lp;
use crate::dm::ratchet::Direction;
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Byte length of the ack seal key — an AES-256 key.
pub const DM_ACK_SEAL_KEY_LEN: usize = 32;

/// How many runs the beyond-prefix set holds before an insert is refused.
///
/// **Sixty-four. It is a policy choice about when a conversation is degraded, not
/// a quantity derived from anywhere else** — and the honest statement of that
/// matters, because the neighbouring number it resembles bounds something
/// different. [`crate::dm::ratchet::MAX_SKIP`] (64) is how far a *single* skip
/// call will reach; [`crate::dm::ratchet::SKIPPED_KEY_CAPACITY`] (128) is how many
/// skipped keys the cache holds at once, and that second one is the ratchet
/// quantity comparable to a count of simultaneous outstanding gaps. `ratchet.rs`
/// says in as many words that conflating the two is a real defect, so this
/// constant does not claim to match either: it is set to 64 on its own argument,
/// below the ratchet's 128.
///
/// **Why below, and what it costs.** The two caps fail in opposite directions.
/// Exceeding the ratchet's cache *destroys keys* — the evicted messages become
/// permanently unopenable, silently and unrecoverably. Exceeding this cap
/// *refuses a record* — nothing is lost, the state is unchanged, and the give-up
/// rule frees the capacity again. Setting this at 128 would make the recoverable
/// failure arrive at the same moment as the unrecoverable one, so the cheaper
/// failure is deliberately made to bind first.
///
/// The price is a real window, stated rather than glossed: under alternating loss
/// the run set reaches 64 at sequence 127, and the next collected message is
/// refused **while the ratchet still holds every skipped key and opened that
/// message fine**. So between 65 and 128 interleaved outstanding positions, the
/// receiver displays messages it cannot acknowledge, the sender re-seeds them to
/// the seven-day give-up, and reports *undelivered* for messages that were in fact
/// read. That is the fail-safe direction and it is recoverable — the give-up rule
/// collapses the accumulated gaps and capacity returns — but it is a cost, not a
/// free bound. Raising this to 128 would close the window at the price of the
/// ordering above; it is a deliberate trade and either number needs the argument
/// restated, not just the constant edited.
///
/// It also fixes the encoded size: 2 + 64 × 16 = 1026 bytes. That is not why the
/// number is 64 — 128 runs would be 2050 bytes, equally negligible beside the
/// record this rides in — but it is what makes the bound cheap to carry.
pub const MAX_ACK_RUNS: usize = 64;

/// Bytes one encoded run occupies: a `u64` gap and a `u64` extent.
const RUN_LEN: usize = 16;

/// Bytes the encoded run count occupies.
const COUNT_LEN: usize = 2;

redacted_secret_newtype! {
    /// The AES-256 key one direction's acks are sealed under.
    ///
    /// Genuinely secret, like [`crate::dm::paging::DmPageOwnerSeed`] and unlike
    /// the world-derivable key-record and doorbell seeds: it descends from the
    /// first-contact encapsulation, so holding it means being one of the two
    /// parties.
    boxed pub struct DmAckSealKey([u8; DM_ACK_SEAL_KEY_LEN]);
}

/// Anything that can go wrong deriving, building, or reading an acknowledgement.
#[derive(Debug, PartialEq, Eq)]
pub enum AckError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// The operation would leave more than [`MAX_ACK_RUNS`] runs beyond the
    /// prefix, or a decoded ack declares more than that.
    ///
    /// **The state is unchanged**, deliberately: dropping a run to make room would
    /// un-confirm a position, and that is the one direction this state may not
    /// move. The positions that could not be recorded stay unconfirmed and the
    /// sender keeps re-seeding them, which is the fail-safe outcome.
    TooManyRuns { runs: usize, max: usize },
    /// A decoded run's arithmetic leaves the sequence space — a gap or extent that
    /// would carry it past `u64::MAX`, or two runs that overlap.
    RunOutOfRange,
    /// A decoded run sits at or below the contiguous prefix, so it would have been
    /// absorbed into it. Non-canonical: the same set has exactly one encoding, and
    /// accepting a second one would let a signature over the encoded bytes cover
    /// something the state does not.
    RunInPrefix { start: u64, first_free: u64 },
    /// The bytes are not a decodable run set — truncated, or longer than the runs
    /// they declare.
    Malformed,
}

impl std::fmt::Display for AckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "ack key derivation failed: {e}"),
            Self::TooManyRuns { runs, max } => write!(
                f,
                "the acknowledgement would hold {runs} runs beyond its prefix, more than the {max} it carries"
            ),
            Self::RunOutOfRange => {
                write!(f, "a run in the acknowledgement leaves the sequence space")
            }
            Self::RunInPrefix { start, first_free } => write!(
                f,
                "a run begins at {start}, at or below the first position beyond the prefix ({first_free})"
            ),
            Self::Malformed => write!(f, "not a decodable acknowledgement run set"),
        }
    }
}

impl std::error::Error for AckError {}

/// What [`AckState::merge_peer_ack`] had to do to the peer's claim to make it
/// mergeable.
///
/// Returned rather than logged because this module has no channel to report on;
/// the transport slice decides what a misbehaving peer costs.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAckOutcome {
    /// Everything the peer claimed sits inside what we have actually sent — the
    /// only outcome an honest, correctly-implemented peer produces.
    WithinCeiling,
    /// The peer claimed a position above the highest sequence number we have sent
    /// on that direction, and everything above it was dropped before the merge.
    ///
    /// Not a recoverable-error condition and not a routine one: a peer cannot have
    /// collected what was never transmitted, so this is either a broken client or
    /// a deliberate attempt to make the sender report messages as delivered before
    /// they are even composed. The merge still happened, carrying the part of the
    /// claim that was possible.
    ClippedToCeiling {
        /// The highest position the peer claimed to have settled.
        claimed: u64,
        /// The highest sequence number we have sent, which is what it was clipped
        /// to. `None` when we have sent nothing, in which case the whole claim was
        /// dropped.
        ceiling: Option<u64>,
    },
}

/// A peer's acknowledgement as the peer wrote it: well-formed, canonical, and
/// checked against **nothing we know**.
///
/// ## Why this is a separate type with almost no methods
///
/// The ceiling that bounds a peer's claim lives on [`AckState::merge_peer_ack`],
/// and it has to: a verifier rebuilds the signature preimage from the decoded
/// statement, so a decoder that clipped would rebuild a preimage the peer's
/// signature cannot match. The decoder therefore hands back an unbounded claim by
/// design. If that claim came back as an [`AckState`] it would arrive carrying
/// [`AckState::is_settled`], [`AckState::high_water`], [`AckState::runs`] and
/// [`AckState::beyond_runs`] — the whole query surface of a state we have
/// checked, answering from a `high_water` the peer chose. One signed ack claiming
/// `2^40` would then answer `true` for every position that will ever exist, to any
/// caller that asked before merging. The name `decode_unvalidated` and the
/// `#[must_use]` on [`PeerAckOutcome`] discourage that; a type with no such
/// methods makes it unrepresentable, which is the standard the rest of this module
/// already holds ([`crate::dm::paging::PagePosition`]'s private fields,
/// [`crate::dm::paging::DmPageOwnerSeed`]'s absent `Clone`).
///
/// The only things this type does are rebuild the preimage it was signed over
/// ([`Self::sig_input`]) and be consumed by [`AckState::merge_peer_ack`], which
/// applies the ceiling on the one path by which a peer's statement enters our
/// state. It is taken **by value** there, and is neither `Clone` nor `Copy`, so
/// one decoded statement merges once and a re-seeded ack is decoded again from
/// the bytes that carried it.
///
/// `Debug` is deliberately opaque for the same reason: a formatted `high_water`
/// and run list is the same unvalidated answer read a slower way.
///
/// **The property, stated exactly: nothing leaves this type that the caller did
/// not put into it.** [`Self::sig_input`] is the only output, and it is a pure
/// function of the `chan_id`, `dir`, `high_water` and bytes the caller itself
/// supplied — computable outside this crate, from those same four inputs, in
/// about eight lines. So it is a **convenience, not a disclosure**: it saves a
/// verifier from re-implementing a wire format, and discloses nothing. What is
/// gone is the *reading* of a peer's claim as a settlement verdict — no
/// `is_settled` to be called by accident, and no prefix a caller can mistake for
/// a checked one.
///
/// The sequence is **decode → verify the signature → merge**:
///
/// ```
/// use daemonseed_core::dm::ack::{AckState, PeerAck};
///
/// // Two bytes: a run count of zero. The peer claims a contiguous prefix of 4.
/// let peer: PeerAck = AckState::decode_unvalidated(Some(4), &[0, 0]).unwrap();
///
/// // ...verify a signature over `peer.sig_input(chan_id, dir)` here...
///
/// let mut ours = AckState::new();
/// ours.merge_peer_ack(peer, Some(4)).unwrap();
/// assert!(ours.is_settled(4));
/// ```
///
/// ## What is pinned, and how
///
/// Every block below is a **trait-bound probe** (`fn needs_x<T: X>() {}`) or a
/// function taking `&PeerAck` — deliberately, because **a one-character typo
/// inside a `compile_fail` block turns it into a permanently-passing test**. A
/// block that constructs its own fixture can be broken by mistyping `.unwrap()`,
/// and the running example above would not catch it: that example is a *separate
/// copy* of those lines, so it fires on a module-path rename and on nothing else.
/// These blocks have no fixture to mistype. The example above still earns its
/// place as the proof that the path and the flow compile at all.
///
/// No settlement query, under any of the four names [`AckState`] carries:
///
/// ```compile_fail
/// fn q(p: &daemonseed_core::dm::ack::PeerAck) { let _ = p.is_settled(0); }
/// ```
/// ```compile_fail
/// fn q(p: &daemonseed_core::dm::ack::PeerAck) { let _ = p.high_water(); }
/// ```
/// ```compile_fail
/// fn q(p: &daemonseed_core::dm::ack::PeerAck) { let _ = p.runs(); }
/// ```
/// ```compile_fail
/// fn q(p: &daemonseed_core::dm::ack::PeerAck) { let _ = p.beyond_runs(); }
/// ```
///
/// And no conversion back to an [`AckState`], which would hand the whole query
/// surface back by another door. Each of these is a total escape on its own:
///
/// ```compile_fail
/// fn needs_deref<T: core::ops::Deref>() {}
/// needs_deref::<daemonseed_core::dm::ack::PeerAck>();
/// ```
/// ```compile_fail
/// fn needs_as_ref<T: AsRef<daemonseed_core::dm::ack::AckState>>() {}
/// needs_as_ref::<daemonseed_core::dm::ack::PeerAck>();
/// ```
/// ```compile_fail
/// fn needs_borrow<T: core::borrow::Borrow<daemonseed_core::dm::ack::AckState>>() {}
/// needs_borrow::<daemonseed_core::dm::ack::PeerAck>();
/// ```
/// ```compile_fail
/// fn needs_into<T: Into<daemonseed_core::dm::ack::AckState>>() {}
/// needs_into::<daemonseed_core::dm::ack::PeerAck>();
/// ```
///
/// Not `Clone`, so the move into [`AckState::merge_peer_ack`] cannot be
/// sidestepped:
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<daemonseed_core::dm::ack::PeerAck>();
/// ```
///
/// Not `PartialEq`, which would let a claim be read out by bisection against
/// states the caller builds itself:
///
/// ```compile_fail
/// fn needs_eq<T: PartialEq>() {}
/// needs_eq::<daemonseed_core::dm::ack::PeerAck>();
/// ```
///
/// **Absent `Copy` is by construction, not verified.** The probe below passes,
/// but [`AckState`] owns a `Vec`, so no edit to this file could make `PeerAck`
/// `Copy` — there is no falsifying mutation, and a rule with no falsifying
/// mutation is recorded as by-construction rather than counted among the proven
/// ones.
///
/// ```compile_fail
/// fn needs_copy<T: Copy>() {}
/// needs_copy::<daemonseed_core::dm::ack::PeerAck>();
/// ```
///
/// **What this does not reach:** a query added under some *other* name, or a
/// blanket impl in a third crate. Neither is expressible as a bound here.
pub struct PeerAck(AckState);

impl PeerAck {
    /// The signature preimage this statement was signed over, for the channel and
    /// direction it arrived on.
    ///
    /// The one thing a holder of an unmerged peer ack legitimately needs, and the
    /// step that must happen before [`AckState::merge_peer_ack`]. It rebuilds the
    /// preimage from the decoded statement rather than from the bytes as handed
    /// over, which is what the canonical encoding buys: one set has exactly one
    /// spelling, so a signature over these bytes is a signature over the set.
    ///
    /// It answers nothing about settlement. What it returns is a function of the
    /// `high_water` the caller itself passed to
    /// [`AckState::decode_unvalidated`] and the bytes the caller itself supplied —
    /// no new fact about the peer's claim leaves the type through here.
    pub fn sig_input(&self, chan_id: &[u8; ROOT_LEN], dir: Direction) -> Vec<u8> {
        ack_sig_input(chan_id, dir, &self.0)
    }

    /// The decoded statement, for this module's own tests only.
    ///
    /// It exists so the decoder's own tests can assert on what was decoded
    /// without routing every one of them through a merge. **What contains the
    /// query surface is the private tuple field, not this gate** — `mod tests` is
    /// a descendant of `dm::ack` and could reach `self.0` either way. Private and
    /// `cfg(test)` so the intent is stated and no production path, in this module
    /// or any other, can compile a call to it.
    #[cfg(test)]
    fn state(&self) -> &AckState {
        &self.0
    }
}

impl std::fmt::Debug for PeerAck {
    /// Opaque on purpose. Printing the prefix and the runs would put the
    /// unvalidated claim back within reach of any caller willing to read a
    /// string, which is the surface this type exists to remove.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerAck(<unvalidated>)")
    }
}

/// Derive one direction's ack seal key:
/// `HKDF-SHA-384(salt = DM_ACK_SALT, ikm = AR, info = DM_ACK_SEAL ‖ lp(dir))`.
///
/// Deterministic and pure — no clock, no randomness, no network — so both parties
/// reach the same key from the same conversation whatever generation their
/// ratchets are at. That independence from the ratchet is the point: see the
/// module docs.
///
/// **The address root and the direction are the only inputs, and the signature is
/// what pins that** (finding F-3). Nothing about the ratchet — generation, chain
/// position, skipped keys — is reachable from here, so the key cannot desync under
/// ratchet skew by construction rather than by test. What the tests below do pin
/// is the far weaker property a signature cannot carry: that these two inputs
/// produce *these* bytes, and that neither input is ignored.
///
/// `direction` is the direction of the **messages being acknowledged**, not of the
/// ack itself. The party collecting `a2b` derives the `a2b` ack key. Stated
/// explicitly because the two readings are both plausible and they differ by
/// exactly one label, so a second implementer choosing the other one produces a
/// client whose acks never open — with no error to say why. Take the value from
/// [`crate::dm::ratchet::Ratchet::recv_direction`] when building an ack and from
/// [`send_direction`](crate::dm::ratchet::Ratchet::send_direction) when opening
/// the peer's, rather than mapping a role by hand.
pub fn derive_seal_key(
    address_root: &[u8; ADDRESS_ROOT_LEN],
    direction: Direction,
) -> Result<DmAckSealKey, AckError> {
    let hkdf =
        HkdfSha384::extract(Some(domain::DM_ACK_SALT), address_root).map_err(AckError::Kdf)?;

    let dir = direction.label();
    let mut info = Vec::with_capacity(domain::DM_ACK_SEAL.len() + dir.len() + 8);
    info.extend_from_slice(domain::DM_ACK_SEAL);
    push_lp(&mut info, dir);

    let key = derive_boxed_seed::<DM_ACK_SEAL_KEY_LEN>(&hkdf, &info).map_err(AckError::Kdf)?;
    Ok(DmAckSealKey(key))
}

/// The preimage an acknowledgement is signed over.
///
/// Binds, in order and each length-prefixed: the conversation, the direction, the
/// contiguous prefix, and the canonical encoding of every run beyond it.
///
/// **It takes the state rather than its two halves**, so there is no call shape
/// that signs a high-water and a run set which do not belong together. The
/// verifier decodes the arriving ack into an [`AckState`] — which rejects any
/// non-canonical encoding — and rebuilds this preimage from it, so the bytes
/// signed and the bytes carried are the same bytes by construction rather than by
/// the verifier remembering to compare them.
///
/// An absent prefix binds as a **zero-length component**, not as an omitted one,
/// the way [`crate::dm::frame::frame_sig_input`] binds an absent generation
/// ciphertext. `high_water = Some(0)` and `high_water = None` are different
/// statements — the first says sequence zero was collected — and a preimage that
/// could not tell them apart would let one be replayed as the other.
pub fn ack_sig_input(chan_id: &[u8; ROOT_LEN], dir: Direction, state: &AckState) -> Vec<u8> {
    let encoded = state.encode_beyond();
    let mut buf = Vec::with_capacity(domain::DM_ACK_SIG.len() + encoded.len() + 96);
    buf.extend_from_slice(domain::DM_ACK_SIG);
    push_lp(&mut buf, chan_id);
    push_lp(&mut buf, dir.label());
    match state.high_water() {
        Some(h) => push_lp(&mut buf, &h.to_be_bytes()),
        None => push_lp(&mut buf, &[]),
    }
    push_lp(&mut buf, &encoded);
    buf
}

/// One inclusive run of settled sequence numbers beyond the contiguous prefix.
///
/// Inclusive `[start, end]` rather than `start + length`, because a length is one
/// larger than the span it describes and a run covering the top of the sequence
/// space then has a length no `u64` can hold. The encoding carries `end - start`
/// for the same reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Run {
    start: u64,
    end: u64,
}

/// What one party has settled on one direction of one conversation.
///
/// Two pointers, and they answer different questions:
///
/// - the **contiguous prefix** ([`AckState::high_water`]) — the highest sequence
///   number with every position from zero up to it settled. `None` when nothing
///   contiguous has been settled yet, which is a real state: sequence zero is a
///   live position on both directions (on `a2b` it is the first-contact entry,
///   which arrives by doorbell), so there is no spare value to mean "nothing".
/// - the **runs beyond it** — settled positions with at least one unsettled
///   position below them.
///
/// It carries no `chan_id` and no conversation key; it is a statement about
/// sequence numbers and nothing else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckState {
    high_water: Option<u64>,
    /// Sorted, disjoint, and separated by at least one unsettled position — two
    /// runs that touched would be one run. Every `start` is at least two above the
    /// prefix, for the same reason. Length never exceeds [`MAX_ACK_RUNS`].
    beyond: Vec<Run>,
}

impl AckState {
    /// An acknowledgement that has settled nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The contiguous prefix: every sequence number from zero up to and including
    /// this one is settled. `None` when none is.
    pub fn high_water(&self) -> Option<u64> {
        self.high_water
    }

    /// The first page this state has **not** settled through: every page strictly
    /// below it holds nothing but settled positions.
    ///
    /// Settled, not collected, on exactly the terms [`Self::is_settled`] states —
    /// [`Self::abandon`] settles a position the sender gave up on, and this counts
    /// it. That is the answer a page holder wants: a given-up position is one
    /// nothing will ever ask about again, so a page made entirely of them is as
    /// finished as a page that was fully read.
    ///
    /// **The give-up that reaches this is the holder's OWN**, applied to the state
    /// it keeps about its own sends. A receiver has no route to the sender's
    /// give-up: the wire carries only the receiver's own `high_water` and runs, so
    /// nothing arrives saying a position was abandoned. See
    /// [`crate::dm::collect::Collection::retired_below`].
    ///
    /// Zero while the prefix is empty, which keeps a caller from retiring a page
    /// the conversation has not reached. A prefix covering the whole sequence
    /// space answers one above [`crate::dm::paging::MAX_PAGE`], the value no page can
    /// hold.
    pub fn settled_pages_below(&self) -> u64 {
        match self.high_water {
            // The first unsettled position is one above the prefix, and its page
            // is the lowest page still holding something unsettled.
            Some(h) => match h.checked_add(1) {
                Some(next) => crate::dm::paging::position_of(next).page(),
                None => crate::dm::paging::MAX_PAGE.saturating_add(1),
            },
            None => 0,
        }
    }

    /// How many runs sit beyond the prefix. Zero for a conversation collecting in
    /// order — everything folds into the prefix as it arrives — and bounded by
    /// [`MAX_ACK_RUNS`].
    pub fn runs(&self) -> usize {
        self.beyond.len()
    }

    /// Those runs themselves, ascending, each inclusive and separated from its
    /// neighbours by at least one unsettled position.
    ///
    /// Read-only, and it reports **settled** positions on the same terms as
    /// [`Self::is_settled`] — [`Self::abandon`] puts a position here that was
    /// never collected. Its holder is [`crate::dm::collect::Collection`], which
    /// reads the gaps between these runs as what is still outstanding rather
    /// than keeping a second copy of the same set.
    pub fn beyond_runs(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
        self.beyond.iter().map(|r| r.start..=r.end)
    }

    /// Record that this sequence number was **collected**: the message arrived,
    /// opened, and verified.
    ///
    /// Idempotent — a position already settled is a no-op, which matters because
    /// re-seeding makes duplicate arrivals ordinary traffic rather than an
    /// exception. If it closes the last hole below it the prefix advances over it
    /// and over everything the runs already held, which is what keeps the run set
    /// small in a merely-out-of-order conversation.
    pub fn collect(&mut self, seq: u64) -> Result<(), AckError> {
        self.settle(seq)
    }

    /// Record that this sequence number will **never** be collected, because the
    /// sender abandoned it at the seven-day give-up.
    ///
    /// Without this the run set is unbounded: a permanent gap is a hole nothing
    /// will ever fill, and each one is a run for the life of the conversation.
    /// Advancing the cursor past it is what makes "bounded" true under accumulated
    /// permanent loss.
    ///
    /// **This makes [`Self::is_settled`] answer `true` for `seq`.** The state
    /// carries *settled*, not *collected*, and only the sender can tell those
    /// apart — see the module docs. A caller that asks an ack about a message it
    /// gave up on will get an answer that means the opposite of what it reads.
    pub fn abandon(&mut self, seq: u64) -> Result<(), AckError> {
        self.settle(seq)
    }

    /// Is this sequence number **settled** — "stop re-seeding this, I will never
    /// ask for it again"?
    ///
    /// True when it is inside the contiguous prefix, or inside a run beyond it.
    /// **Anything else is `false`** — including sequence numbers far above
    /// everything this ack has ever heard of. Unknown is not settled: a delivery
    /// state that defaulted the other way would make every lost ack look like a
    /// delivered message, which is the failure the whole fail-safe posture exists
    /// to prevent.
    ///
    /// **Settled is not collected, and the difference is the whole reason this is
    /// not called `is_confirmed`.** [`Self::abandon`] settles a position the
    /// sender gave up on at the seven-day give-up, so this answers `true` for
    /// messages that were never received. Only the sender's persisted outbox can
    /// tell the two apart, because only the sender knows which of its own messages
    /// it abandoned; there *undelivered* is terminal and a given-up message is
    /// never re-consulted against an ack. A caller that maps this answer straight
    /// onto a *delivered* indicator will eventually show one for a message nobody
    /// read. See the module docs.
    pub fn is_settled(&self, seq: u64) -> bool {
        if let Some(h) = self.high_water
            && seq <= h
        {
            return true;
        }
        self.beyond.iter().any(|r| r.start <= seq && seq <= r.end)
    }

    /// Fold an acknowledgement **we ourselves published** back into this one, as a
    /// union.
    ///
    /// For the one trusted merge in the design: a receiver that lost local state
    /// recovering from its own last published ack. It takes no ceiling because
    /// there is nothing to bound — the statement is our own, and a replay of an
    /// older copy of it is a subset of what we already hold.
    ///
    /// The prefix takes the higher of the two and no settled position is ever
    /// cleared, so a stale ack — a genuinely signed value anyone able to read a
    /// record can replay — is a no-op rather than a rollback. See the module docs
    /// on why regression is the dangerous direction.
    ///
    /// Refuses with [`AckError::TooManyRuns`] if the union would exceed
    /// [`MAX_ACK_RUNS`], leaving `self` untouched. All-or-nothing on purpose:
    /// taking the runs that fit would drop the others, and dropping one of *our
    /// own* runs is the un-settling this method exists to make impossible.
    ///
    /// **Never reachable from a peer's bytes.** Anything that arrived from the
    /// other party goes through [`Self::merge_peer_ack`], which is the same union
    /// with the ceiling that makes it safe.
    pub fn merge_own_ack(&mut self, other: &Self) -> Result<(), AckError> {
        // `Option<u64>` orders `None` below every `Some`, which is exactly the
        // wanted meaning: no prefix is lower than a prefix of zero.
        let high = self.high_water.max(other.high_water);
        self.rebuild(high, &other.beyond)
    }

    /// Fold a **peer's** acknowledgement into this one, bounded by what we have
    /// actually sent.
    ///
    /// `highest_sent` is the highest sequence number we have transmitted on the
    /// direction this ack is about, or `None` if we have sent nothing on it. A
    /// peer cannot have collected what was never transmitted, so it is a ceiling
    /// no honest ack ever reaches, and it is available locally without trusting
    /// anybody. It is a required argument rather than a documented duty because
    /// this is the only path by which a peer's statement enters our state, and the
    /// merge is irreversible once it lands.
    ///
    /// **Anything above the ceiling is clipped away, not refused**, and only from
    /// the peer's copy — our own retained state is never clipped, because the
    /// ceiling can regress across a restart while our settled positions may not.
    /// The reasoning for clipping over refusing is in the module docs; the short
    /// form is that a peer's high-water is itself monotonic, so a refusal is
    /// permanent rather than a retry, and it would discard the truthful low half
    /// of the ack along with the impossible high half.
    ///
    /// The returned [`PeerAckOutcome`] reports whether a clip happened. Nothing
    /// legitimate produces one, so it is a peer-misbehaviour signal rather than a
    /// routine result — but it is returned rather than logged here, because this
    /// module has no channel to report on.
    ///
    /// Refuses with [`AckError::TooManyRuns`] on the same all-or-nothing terms as
    /// [`Self::merge_own_ack`], leaving `self` untouched.
    ///
    /// **Order matters: verify the signature first.** The clip changes the
    /// statement, so a verifier must rebuild the preimage from the state as
    /// decoded — [`PeerAck::sig_input`] — and check it *before* calling this. See
    /// [`Self::decode_unvalidated`].
    ///
    /// The peer's statement arrives as a [`PeerAck`] and is **consumed** here.
    /// What that buys is precise, and less than it may look: a [`PeerAck`] answers
    /// no question about settlement and this is the only thing that can be done
    /// with one, so **a caller cannot forget the ceiling** — it is a required
    /// argument on the only road in. It does not make an unbounded read
    /// impossible. `merge_peer_ack(peer, Some(u64::MAX))` bounds nothing and the
    /// merged result then answers for anything the peer claimed; the tests below
    /// use exactly that, named `NO_CLIP`, to exercise the union algebra with the
    /// clip standing aside. Passing a real ceiling is the caller's obligation, and
    /// the argument's presence is what makes it a decision rather than an
    /// omission.
    ///
    /// [`PeerAckOutcome::ClippedToCeiling`]'s `claimed` likewise reports the
    /// peer's raw, unvalidated top under any ceiling. That is deliberate — it is
    /// the misbehaviour signal, and it is worthless if it reports the clipped
    /// value — so it is one number about a claim that was rejected, not a query
    /// surface on a claim that was accepted.
    pub fn merge_peer_ack(
        &mut self,
        other: PeerAck,
        highest_sent: Option<u64>,
    ) -> Result<PeerAckOutcome, AckError> {
        let other = &other.0;
        let over = match (other.highest_settled(), highest_sent) {
            (Some(claimed), None) => Some(claimed),
            (Some(claimed), Some(ceiling)) if claimed > ceiling => Some(claimed),
            _ => None,
        };

        self.merge_own_ack(&other.clipped_to(highest_sent))?;

        Ok(match over {
            Some(claimed) => PeerAckOutcome::ClippedToCeiling {
                claimed,
                ceiling: highest_sent,
            },
            None => PeerAckOutcome::WithinCeiling,
        })
    }

    /// The highest sequence number this state settles, or `None` if it settles
    /// nothing.
    ///
    /// The runs are sorted and every one of them sits above the prefix, so the
    /// last run's end is the top whenever there is a run at all.
    fn highest_settled(&self) -> Option<u64> {
        self.beyond.last().map(|r| r.end).or(self.high_water)
    }

    /// A copy of this state claiming nothing above `ceiling`.
    ///
    /// Exactly what a party who had sent up to `ceiling` and no further could
    /// truthfully have claimed: the prefix is capped, runs entirely above the
    /// ceiling are dropped, and a run straddling it is trimmed to end there. A
    /// `None` ceiling means nothing was sent, so nothing can be settled.
    ///
    /// Every `start` is left where it was, so the "at least two above the prefix"
    /// invariant survives without renormalising: capping the prefix only ever
    /// lowers it, and dropping or trimming runs only ever shrinks them.
    fn clipped_to(&self, ceiling: Option<u64>) -> Self {
        let Some(ceiling) = ceiling else {
            return Self::new();
        };

        let mut beyond: Vec<Run> = Vec::with_capacity(self.beyond.len());
        for run in &self.beyond {
            // Sorted, so the first run starting above the ceiling ends the scan.
            if run.start > ceiling {
                break;
            }
            beyond.push(Run {
                start: run.start,
                end: run.end.min(ceiling),
            });
        }

        Self {
            high_water: self.high_water.map(|h| h.min(ceiling)),
            beyond,
        }
    }

    /// The canonical encoding of the runs beyond the prefix.
    ///
    /// `u16` count, then one `(gap, extent)` pair of big-endian `u64`s per run:
    /// `gap` is the distance from the first position that could legally start this
    /// run, and `extent` is `end - start`.
    ///
    /// **Canonical, and that is load-bearing rather than tidy.** One set has
    /// exactly one encoding — a decoder rejects everything else — so a signature
    /// over these bytes is a signature over the set, and a verifier can rebuild
    /// the preimage from the decoded state instead of trusting the bytes it was
    /// handed. Encoding the runs relatively is what makes it so: a gap is measured
    /// from `previous end + 2`, so there is no way to spell a run that touches or
    /// overlaps its neighbour, and no way to spell them out of order.
    ///
    /// It does **not** carry the high-water. That travels as its own field, is
    /// bound as its own component of the signature preimage, and is an argument to
    /// [`Self::decode_unvalidated`], because a run set is meaningless without knowing where
    /// the prefix it sits beyond ends.
    pub fn encode_beyond(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COUNT_LEN + self.beyond.len() * RUN_LEN);
        out.extend_from_slice(&(self.beyond.len() as u16).to_be_bytes());
        let mut cursor = 0u64;
        for run in &self.beyond {
            debug_assert!(run.start >= cursor, "the run invariant does not hold");
            out.extend_from_slice(&(run.start - cursor).to_be_bytes());
            out.extend_from_slice(&(run.end - run.start).to_be_bytes());
            // Saturation is unreachable with a run following: a next run would have
            // to start at least two above `run.end`, which cannot exist if that
            // addition overflowed. Saturating rather than checking keeps this total.
            cursor = run.end.saturating_add(2);
        }
        out
    }

    /// Rebuild a state from a prefix and the canonical encoding of its runs.
    ///
    /// Rejects anything [`Self::encode_beyond`] could not have produced: more runs
    /// than [`MAX_ACK_RUNS`], a truncated buffer, trailing bytes, arithmetic that
    /// leaves the sequence space, and any run at or below the prefix. Every one of
    /// those is a second spelling of a state that already has one, and accepting a
    /// second spelling would break the property the signature rests on.
    ///
    /// **A declared run extent never drives an allocation.** The run count is a
    /// `u16` checked against the cap before a single byte is reserved, and an
    /// extent is stored as the number it is — so an ack claiming a run of
    /// `u64::MAX` positions costs sixteen bytes and no time. That claim is
    /// *accepted*, not rejected: a peer asserting it collected everything is
    /// lying about its own collection, which no acknowledgement scheme can
    /// prevent and which costs the liar the messages it claims to have. What
    /// matters here is that the lie is cheap to read.
    ///
    /// **`unvalidated` is the whole name, and the return type enforces it.** What
    /// comes back is the peer's statement as the peer wrote it — well-formed and
    /// canonical, and nothing more. Neither `high_water` nor any run has been
    /// checked against what we actually sent. That is deliberate and it is the
    /// only shape that works: a verifier rebuilds the signature preimage from this
    /// statement, so a decoder that altered it would rebuild a preimage the peer's
    /// signature cannot match.
    ///
    /// So it does not come back as an [`AckState`]. It comes back as a
    /// [`PeerAck`], which answers no question about settlement and can only be
    /// spent on [`Self::merge_peer_ack`] — where the ceiling is a required
    /// argument. The sequence is **decode → verify the signature → merge**, and
    /// there is now no fourth thing to do with the result.
    pub fn decode_unvalidated(
        high_water: Option<u64>,
        encoded: &[u8],
    ) -> Result<PeerAck, AckError> {
        let count_bytes: [u8; COUNT_LEN] = encoded
            .get(..COUNT_LEN)
            .ok_or(AckError::Malformed)?
            .try_into()
            .expect("checked length");
        let count = u16::from_be_bytes(count_bytes) as usize;
        if count > MAX_ACK_RUNS {
            return Err(AckError::TooManyRuns {
                runs: count,
                max: MAX_ACK_RUNS,
            });
        }

        let body = &encoded[COUNT_LEN..];
        // One check for both truncation and trailing bytes: the length is exact or
        // these are not the bytes of this run set.
        if body.len() != count * RUN_LEN {
            return Err(AckError::Malformed);
        }

        // Only now, with `count` bounded by the cap, is anything reserved.
        let mut runs: Vec<Run> = Vec::with_capacity(count);
        let mut cursor = Some(0u64);
        for chunk in body.chunks_exact(RUN_LEN) {
            let base = cursor.ok_or(AckError::RunOutOfRange)?;
            let gap = u64::from_be_bytes(chunk[..8].try_into().expect("checked length"));
            let extent = u64::from_be_bytes(chunk[8..].try_into().expect("checked length"));

            let start = base.checked_add(gap).ok_or(AckError::RunOutOfRange)?;
            let end = start.checked_add(extent).ok_or(AckError::RunOutOfRange)?;

            let first_free = match high_water {
                None => 0,
                Some(h) => h.checked_add(1).ok_or(AckError::RunOutOfRange)?,
            };
            if start <= first_free {
                return Err(AckError::RunInPrefix { start, first_free });
            }

            runs.push(Run { start, end });
            cursor = end.checked_add(2);
        }

        Ok(PeerAck(Self {
            high_water,
            beyond: runs,
        }))
    }

    /// Settle one position. The single mutator; [`Self::collect`] and
    /// [`Self::abandon`] are its two meanings, and they differ to the caller and
    /// to the reader of an outbox, never to the state.
    fn settle(&mut self, seq: u64) -> Result<(), AckError> {
        if self.is_settled(seq) {
            return Ok(());
        }
        self.rebuild(
            self.high_water,
            &[Run {
                start: seq,
                end: seq,
            }],
        )
    }

    /// Take a prefix and some extra runs, normalise the union of them with our
    /// own, and install it — or refuse and change nothing.
    ///
    /// The one place the invariants are established, so [`Self::collect`],
    /// [`Self::abandon`] and [`Self::merge`] cannot drift into three slightly
    /// different notions of what a valid state is.
    fn rebuild(&mut self, high: Option<u64>, added: &[Run]) -> Result<(), AckError> {
        let mut runs: Vec<Run> = Vec::with_capacity(self.beyond.len() + added.len());
        runs.extend_from_slice(&self.beyond);
        runs.extend_from_slice(added);

        let mut runs = normalise(runs);
        let mut high = high;
        clip_to_prefix(&mut runs, high);
        absorb(&mut high, &mut runs);

        if runs.len() > MAX_ACK_RUNS {
            return Err(AckError::TooManyRuns {
                runs: runs.len(),
                max: MAX_ACK_RUNS,
            });
        }

        self.high_water = high;
        self.beyond = runs;
        Ok(())
    }
}

/// Sort and coalesce: overlapping runs become one, and so do merely *adjacent*
/// ones.
///
/// Coalescing the adjacent case is what keeps the encoding canonical — two runs
/// separated by nothing describe the same set as one run, and a set with two
/// spellings is a set a signature cannot pin.
fn normalise(mut runs: Vec<Run>) -> Vec<Run> {
    runs.sort_unstable();
    let mut out: Vec<Run> = Vec::with_capacity(runs.len());
    for run in runs {
        match out.last_mut() {
            // Saturating: a previous run reaching the top of the space swallows
            // everything after it, which is the right answer rather than an edge
            // case to reject.
            Some(prev) if run.start <= prev.end.saturating_add(1) => {
                prev.end = prev.end.max(run.end);
            }
            _ => out.push(run),
        }
    }
    out
}

/// Drop or trim runs that the prefix has grown over.
///
/// A merge can raise the prefix past runs we already held; leaving them would put
/// the same positions in both pointers, which the encoding has no way to spell.
fn clip_to_prefix(runs: &mut Vec<Run>, high: Option<u64>) {
    let Some(h) = high else {
        return;
    };
    runs.retain(|r| r.end > h);
    for run in runs.iter_mut() {
        if run.start <= h {
            run.start = h.saturating_add(1);
        }
    }
}

/// Pull the run that continues the prefix, if there is one, into the prefix.
///
/// After [`normalise`] the runs are separated by at least one unsettled position,
/// so at most one run can ever continue the prefix and this loop runs at most
/// once. It is a loop anyway, so that a future change to normalisation cannot
/// silently strand a run that should have been absorbed.
fn absorb(high: &mut Option<u64>, runs: &mut Vec<Run>) {
    while let Some(first) = runs.first().copied() {
        let wanted = match *high {
            None => 0,
            Some(h) => match h.checked_add(1) {
                Some(w) => w,
                // The prefix already covers the whole sequence space; nothing can
                // sit beyond it.
                None => return,
            },
        };
        if first.start != wanted {
            return;
        }
        *high = Some(first.end);
        runs.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn key(tag: u8, dir: Direction) -> String {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        hex::encode(derive_seal_key(&ar(tag), dir).unwrap().as_bytes())
    }

    /// Settle a list of positions, expecting every one to be accepted.
    fn settled(seqs: &[u64]) -> AckState {
        let mut state = AckState::new();
        for &seq in seqs {
            state.collect(seq).expect("within the cap");
        }
        state
    }

    /// The same statement as it would arrive from the other party: encoded,
    /// carried, and decoded back.
    ///
    /// A peer's ack reaches us only as bytes, and [`AckState::merge_peer_ack`]
    /// now takes only what came out of a decode, so these tests go the whole way
    /// round rather than handing a locally-built state straight to the merge.
    fn from_peer(state: &AckState) -> PeerAck {
        AckState::decode_unvalidated(state.high_water(), &state.encode_beyond())
            .expect("its own encoding")
    }

    // ---- K_ack -------------------------------------------------------------
    //
    // Known-answer vectors, captured from this implementation. As in `paging` and
    // `doorbell`, they guard against DRIFT: a uniform change to the label, the
    // salt, or the length-prefixing would keep every structural test below green
    // while producing a key no other implementation derives — acks that never
    // open, on a conversation that otherwise looks healthy. They cannot say the
    // derivation was right to begin with; the design doc and review do that.

    #[test]
    fn ack_seal_keys_are_pinned() {
        assert_eq!(
            key(0x41, Direction::AToB),
            "a82bba1401bb0fdbe513eebd262e941817dc0dbda5f843520feaac34d01a3578"
        );
        assert_eq!(
            key(0x41, Direction::BToA),
            "94512cf3e0bd7de976452d56eb2e54cb4a21b1153ef808eaa295310f964ccffa"
        );
    }

    /// Per-direction (finding F-6): one key across both halves is one key whose
    /// compromise covers both, and two independent writers under it invite a
    /// nonce collision.
    #[test]
    fn the_two_directions_derive_different_keys() {
        assert_ne!(key(0x41, Direction::AToB), key(0x41, Direction::BToA));
    }

    /// Two conversations must never share an ack key, however close their roots.
    #[test]
    fn distinct_conversations_derive_distinct_keys() {
        assert_ne!(key(0x41, Direction::AToB), key(0x42, Direction::AToB));
    }

    /// The ack key is a conversation secret, so it must not render itself.
    #[test]
    fn the_ack_key_does_not_render_its_bytes() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let k = derive_seal_key(&ar(0x41), Direction::AToB).unwrap();
        assert_eq!(format!("{k:?}"), "DmAckSealKey(<redacted>)");
    }

    // There is deliberately no test that the key "depends only on the address root
    // and the direction". `derive_seal_key` takes those two arguments and nothing
    // else, so the property is carried by the signature; any test of it compares a
    // call to itself and cannot fail for a deterministic implementation. The
    // rustdoc states it as by-construction, which is where it belongs.

    // ---- the signature preimage --------------------------------------------

    fn sig(dir: Direction, state: &AckState) -> String {
        hex::encode(ack_sig_input(&chan(0x51), dir, state))
    }

    #[test]
    fn ack_signature_preimages_are_pinned() {
        let state = settled(&[0, 1, 2, 5]);
        assert_eq!(
            sig(Direction::AToB, &state),
            concat!(
                // the domain, unprefixed, exactly as every other DM preimage
                // begins
                "6461656d6f6e736565642f646d2f61636b2f7369672f7633",
                // lp(chan_id)
                "0000000000000020",
                "c0c9cef7fce5ea939881868fb4bda2ab50595e474c757a636811161f040d323b",
                // lp(dir) — "a2b"
                "0000000000000003",
                "613262",
                // lp(BE64(high_water)) — 2, the contiguous prefix of 0,1,2
                "0000000000000008",
                "0000000000000002",
                // lp(the canonical run encoding) — one run, [5, 5]
                "0000000000000012",
                "0001",
                "0000000000000005",
                "0000000000000000",
            )
        );
    }

    /// The judgment call this module exists to get right: **the bitmap is signed.**
    /// The frozen text's preimage covers `chan_id ‖ high_water` and was written
    /// before the gap bitmap came back; since the bitmap decides confirmation, an
    /// unsigned one is forgeable by anyone able to write the record. Two states
    /// with the same high-water and different runs must not share a preimage.
    #[test]
    fn the_signature_covers_the_runs_beyond_the_prefix() {
        let a = settled(&[0, 5]);
        let b = settled(&[0, 6]);
        assert_eq!(
            a.high_water(),
            b.high_water(),
            "same prefix, by construction"
        );
        assert_ne!(sig(Direction::AToB, &a), sig(Direction::AToB, &b));
    }

    #[test]
    fn the_signature_covers_the_prefix() {
        assert_ne!(
            sig(Direction::AToB, &settled(&[0])),
            sig(Direction::AToB, &settled(&[0, 1]))
        );
    }

    /// An absent prefix is a real state — sequence zero is a live position, so
    /// there is no spare value to mean "nothing" — and it must not be confusable
    /// with a prefix of zero.
    #[test]
    fn an_absent_prefix_is_distinguishable_from_a_prefix_of_zero() {
        let nothing = AckState::new();
        let zero = settled(&[0]);
        assert_eq!(nothing.high_water(), None);
        assert_eq!(zero.high_water(), Some(0));
        assert_ne!(sig(Direction::AToB, &nothing), sig(Direction::AToB, &zero));
    }

    /// The direction is bound, so an ack cannot be replayed as the other half's.
    #[test]
    fn the_signature_covers_the_direction() {
        let state = settled(&[0, 1]);
        assert_ne!(sig(Direction::AToB, &state), sig(Direction::BToA, &state));
    }

    #[test]
    fn the_signature_covers_the_conversation() {
        let state = settled(&[0, 1]);
        assert_ne!(
            hex::encode(ack_sig_input(&chan(0x51), Direction::AToB, &state)),
            hex::encode(ack_sig_input(&chan(0x52), Direction::AToB, &state))
        );
    }

    // ---- the contiguous prefix ---------------------------------------------

    /// The prefix is the contiguous run from zero, never the highest seen. A
    /// max-seen scalar would report every position under a gap as collected —
    /// a false confirmation manufactured by the acknowledgement itself.
    #[test]
    fn the_prefix_is_contiguous_and_not_the_highest_seen() {
        let state = settled(&[0, 1, 9]);
        assert_eq!(state.high_water(), Some(1));
        assert!(!state.is_settled(2), "a gap must not be settled");
        assert!(state.is_settled(9), "but what is past it must be");
    }

    /// Closing the last hole advances the prefix over the run that was waiting
    /// beyond it, and that run leaves the set. This is what keeps the run set
    /// small in a merely-out-of-order conversation, and therefore what makes the
    /// bound cheap.
    #[test]
    fn filling_a_gap_advances_the_prefix_and_empties_the_run_set() {
        let mut state = settled(&[0, 1, 3, 4, 5]);
        assert_eq!(state.high_water(), Some(1));
        assert_eq!(state.runs(), 1);

        state.collect(2).unwrap();

        assert_eq!(state.high_water(), Some(5));
        assert_eq!(state.runs(), 0, "the absorbed run must leave the set");
    }

    /// The runs are readable, not only countable — a collector reads the gaps
    /// *between* them as what is still outstanding, and a count cannot say where
    /// a hole is.
    #[test]
    fn the_runs_are_readable_as_inclusive_ranges() {
        let state = settled(&[0, 1, 4, 5, 6, 9]);
        let runs: Vec<_> = state.beyond_runs().collect();
        assert_eq!(runs, vec![4..=6, 9..=9]);
        assert_eq!(runs.len(), state.runs());
    }

    #[test]
    fn collecting_in_order_never_builds_a_run() {
        let mut state = AckState::new();
        for seq in 0..1000 {
            state.collect(seq).unwrap();
            assert_eq!(state.runs(), 0, "an in-order conversation carries no runs");
        }
        assert_eq!(state.high_water(), Some(999));
    }

    /// Re-seeding makes duplicate arrivals ordinary traffic, so settling a
    /// position twice must be a no-op rather than an error or a second run.
    #[test]
    fn settling_a_position_twice_changes_nothing() {
        let mut state = settled(&[0, 1, 7]);
        let before = state.clone();
        state.collect(1).unwrap();
        state.collect(7).unwrap();
        assert_eq!(state, before);
    }

    // ---- prefix-advance-on-give-up -----------------------------------------

    /// The frozen build-contract rule (ii). Without it, every message the sender
    /// abandons is a run for the life of the conversation.
    #[test]
    fn abandoning_a_permanently_lost_message_advances_the_prefix() {
        let mut state = settled(&[0, 2, 3, 4]);
        assert_eq!(state.high_water(), Some(0));
        assert_eq!(state.runs(), 1);

        state.abandon(1).unwrap();

        assert_eq!(state.high_water(), Some(4));
        assert_eq!(state.runs(), 0);
    }

    /// The sharp edge, pinned so it is found here rather than in a UI: an
    /// abandoned position reads as settled. The state carries *settled*, never
    /// *collected*; only the sender's outbox knows which of its own messages it
    /// gave up on, and *undelivered* is terminal there precisely so this answer is
    /// never asked for.
    #[test]
    fn an_abandoned_position_reads_as_settled() {
        let mut state = AckState::new();
        state.abandon(0).unwrap();
        assert!(state.is_settled(0));
    }

    /// The boundedness claim, driven the way it actually fails: a conversation
    /// that accumulates permanent gaps forever. Without the give-up rule the run
    /// set grows once per gap and walks straight through the cap.
    #[test]
    fn the_run_set_stays_bounded_under_accumulated_permanent_gaps() {
        let mut state = AckState::new();
        for round in 0..(MAX_ACK_RUNS as u64 * 8) {
            let lost = round * 2;
            let kept = lost + 1;
            state.collect(kept).expect("within the cap");
            state.abandon(lost).expect("within the cap");
            assert!(
                state.runs() <= MAX_ACK_RUNS,
                "round {round} left {} runs",
                state.runs()
            );
        }
        assert_eq!(state.runs(), 0);
    }

    // ---- boundedness -------------------------------------------------------

    /// At the cap the insert is refused and the state is left exactly as it was.
    /// Truncating instead would drop a position that had been confirmed, and
    /// un-confirming is the one direction this state must never move.
    #[test]
    fn the_run_set_refuses_to_grow_past_its_cap_rather_than_truncating() {
        let mut state = AckState::new();
        // Every other position, from 1: each collected position is its own run,
        // because position 0 is never settled and neither is any even one.
        for i in 0..MAX_ACK_RUNS as u64 {
            state.collect(1 + i * 2).expect("within the cap");
        }
        assert_eq!(state.runs(), MAX_ACK_RUNS);
        assert_eq!(state.high_water(), None);

        let before = state.clone();
        let over = 1 + MAX_ACK_RUNS as u64 * 2;
        assert_eq!(
            state.collect(over),
            Err(AckError::TooManyRuns {
                runs: MAX_ACK_RUNS + 1,
                max: MAX_ACK_RUNS
            })
        );
        assert_eq!(state, before, "a refused insert must change nothing");
        assert!(
            !state.is_settled(over),
            "and must not confirm what it refused"
        );
    }

    /// A refusal is recoverable, not terminal: settling a position that closes a
    /// gap frees capacity again, which is what makes the cap a back-pressure
    /// signal rather than a wall.
    #[test]
    fn capacity_returns_when_a_gap_closes() {
        let mut state = AckState::new();
        for i in 0..MAX_ACK_RUNS as u64 {
            state.collect(1 + i * 2).unwrap();
        }
        assert!(state.collect(1 + MAX_ACK_RUNS as u64 * 2).is_err());

        state.collect(0).unwrap();
        state.collect(2).unwrap();
        assert!(state.collect(1 + MAX_ACK_RUNS as u64 * 2).is_ok());
    }

    #[test]
    fn max_ack_runs_is_pinned() {
        assert_eq!(MAX_ACK_RUNS, 64);
    }

    // ---- monotonic union-merge ---------------------------------------------
    //
    // A ceiling high enough to clip nothing, so these pin the union algebra alone
    // and a clip showing up in one of them is a failure rather than the point.

    const NO_CLIP: Option<u64> = Some(u64::MAX);

    /// A stale ack is a value the peer genuinely signed, so no signature check
    /// rejects a replay of it. Union is what makes the replay inert.
    #[test]
    fn a_replayed_stale_ack_is_a_no_op() {
        let stale = settled(&[0, 1, 2]);
        let mut current = settled(&[0, 1, 2, 3, 4, 5]);
        let before = current.clone();

        assert_eq!(
            current.merge_peer_ack(from_peer(&stale), NO_CLIP).unwrap(),
            PeerAckOutcome::WithinCeiling
        );

        assert_eq!(current, before);
    }

    #[test]
    fn merge_never_regresses_the_prefix() {
        let mut ahead = settled(&[0, 1, 2, 3]);
        let behind = AckState::new();
        assert_eq!(
            ahead.merge_peer_ack(from_peer(&behind), NO_CLIP).unwrap(),
            PeerAckOutcome::WithinCeiling
        );
        assert_eq!(ahead.high_water(), Some(3));
    }

    /// The other half of monotonicity, and the one a naive "take theirs" would
    /// break: our own runs must survive a merge with an ack that does not mention
    /// them.
    #[test]
    fn merge_never_unsets_a_settled_position() {
        let mut ours = settled(&[0, 9]);
        let theirs = settled(&[0, 1]);

        assert_eq!(
            ours.merge_peer_ack(from_peer(&theirs), NO_CLIP).unwrap(),
            PeerAckOutcome::WithinCeiling
        );

        assert!(ours.is_settled(9), "our own run was dropped");
        assert!(ours.is_settled(1), "theirs was not taken");
        assert_eq!(ours.high_water(), Some(1));
    }

    /// A merge that raises the prefix past runs we held must fold them in, not
    /// leave the same positions in both pointers — a shape the encoding cannot
    /// spell.
    #[test]
    fn merge_folds_our_runs_into_a_prefix_that_grew_past_them() {
        let mut ours = settled(&[0, 3, 4]);
        let theirs = settled(&[0, 1, 2, 3]);

        assert_eq!(
            ours.merge_peer_ack(from_peer(&theirs), NO_CLIP).unwrap(),
            PeerAckOutcome::WithinCeiling
        );

        assert_eq!(ours.high_water(), Some(4));
        assert_eq!(ours.runs(), 0);
    }

    /// The union algebra itself, on the trusted path: a receiver recovering from
    /// its own last published ack.
    #[test]
    fn merge_is_idempotent_and_commutative_in_effect() {
        let a = settled(&[0, 1, 5, 6, 11]);
        let b = settled(&[2, 5, 8]);

        let mut ab = a.clone();
        ab.merge_own_ack(&b).unwrap();
        ab.merge_own_ack(&b).unwrap();

        let mut ba = b.clone();
        ba.merge_own_ack(&a).unwrap();

        assert_eq!(ab, ba);
    }

    #[test]
    fn a_union_over_the_cap_is_refused_and_changes_nothing() {
        let mut ours = AckState::new();
        let mut theirs = AckState::new();
        for i in 0..MAX_ACK_RUNS as u64 {
            ours.collect(1 + i * 4).unwrap();
            theirs.collect(3 + i * 4).unwrap();
        }
        let before = ours.clone();

        assert!(matches!(
            ours.merge_peer_ack(from_peer(&theirs), NO_CLIP),
            Err(AckError::TooManyRuns { .. })
        ));
        assert_eq!(ours, before);
    }

    // ---- the ceiling on a peer's claim --------------------------------------

    /// The finding this ceiling exists for, driven at its worst: one signed ack
    /// claiming a high-water nobody could have reached. Merged unbounded it would
    /// settle every position that will ever exist — irreversibly, because the
    /// union only moves one way — and the sender would report *delivered* for
    /// messages it has not composed yet.
    #[test]
    fn a_peer_cannot_settle_a_position_we_never_sent() {
        let absurd = AckState::decode_unvalidated(Some(u64::MAX), &[0, 0]).unwrap();
        assert!(
            absurd.state().is_settled(9_000),
            "the decoded claim really does cover everything"
        );

        let mut ours = settled(&[0, 1, 2]);
        let outcome = ours.merge_peer_ack(absurd, Some(2)).unwrap();

        assert_eq!(
            outcome,
            PeerAckOutcome::ClippedToCeiling {
                claimed: u64::MAX,
                ceiling: Some(2),
            }
        );
        assert_eq!(ours.high_water(), Some(2), "the ceiling held");
        for seq in [3u64, 4, 9_000, u64::MAX] {
            assert!(!ours.is_settled(seq), "{seq} was never sent");
        }
    }

    /// The same lie told through a run rather than through the prefix. Bounding
    /// only `high_water` would leave this one open, and it settles positions just
    /// as effectively.
    #[test]
    fn the_ceiling_bounds_the_runs_and_not_only_the_prefix() {
        let mut theirs = settled(&[0, 1]);
        theirs.collect(1 << 40).unwrap();

        let mut ours = settled(&[0, 1]);
        let outcome = ours.merge_peer_ack(from_peer(&theirs), Some(1)).unwrap();

        assert_eq!(
            outcome,
            PeerAckOutcome::ClippedToCeiling {
                claimed: 1 << 40,
                ceiling: Some(1),
            }
        );
        assert!(!ours.is_settled(1 << 40), "an unsent run was taken");
        assert_eq!(ours.runs(), 0);
    }

    /// A run straddling the ceiling is trimmed to it rather than dropped whole:
    /// the part below the ceiling is a claim the peer could truthfully make, and
    /// discarding it would cost re-seeding for no gain.
    #[test]
    fn a_run_straddling_the_ceiling_is_trimmed_to_it() {
        let mut theirs = AckState::new();
        theirs.collect(5).unwrap();
        theirs.collect(6).unwrap();
        theirs.collect(7).unwrap();

        let mut ours = AckState::new();
        assert_eq!(
            ours.merge_peer_ack(from_peer(&theirs), Some(6)).unwrap(),
            PeerAckOutcome::ClippedToCeiling {
                claimed: 7,
                ceiling: Some(6),
            }
        );

        assert!(ours.is_settled(5));
        assert!(ours.is_settled(6));
        assert!(!ours.is_settled(7), "past the ceiling");
    }

    /// Having sent nothing, no position can be settled by anybody — and the whole
    /// claim goes, rather than its lowest position surviving as position zero.
    #[test]
    fn a_ceiling_of_nothing_sent_admits_nothing() {
        let theirs = settled(&[0, 1, 2, 9]);
        let mut ours = AckState::new();

        let outcome = ours.merge_peer_ack(from_peer(&theirs), None).unwrap();

        assert_eq!(
            outcome,
            PeerAckOutcome::ClippedToCeiling {
                claimed: 9,
                ceiling: None,
            }
        );
        assert_eq!(ours, AckState::new());
        assert!(!ours.is_settled(0));
    }

    /// Clipping is fail-safe, never un-settling: it applies to the peer's copy
    /// alone. Our own prefix can legitimately sit above the ceiling — a client
    /// that published sequence 12 and crashed before persisting its outbox
    /// recovers believing it sent 9 — and lowering it there would un-settle
    /// positions already confirmed, which is the one direction this state may not
    /// move.
    #[test]
    fn a_lagging_ceiling_never_claws_back_our_own_state() {
        let mut ours = settled(&[0, 1, 2, 3, 4]);
        let theirs = settled(&[0, 1]);

        // The ceiling (1) lags our own retained prefix (4). The peer's claim is
        // inside it, so nothing is clipped from them — and nothing may be clipped
        // from us either.
        assert_eq!(
            ours.merge_peer_ack(from_peer(&theirs), Some(1)).unwrap(),
            PeerAckOutcome::WithinCeiling
        );

        assert_eq!(ours.high_water(), Some(4), "our own prefix was clipped");
        assert!(ours.is_settled(4));
    }

    /// The reason for clipping rather than refusing: a peer's high-water is itself
    /// monotonic, so a refusal is permanent rather than a retry. The truthful low
    /// half of an over-claiming ack must survive, and the rest must arrive as soon
    /// as the ceiling catches up.
    #[test]
    fn an_over_claiming_ack_still_delivers_its_truthful_half_and_heals() {
        let theirs = settled(&[0, 1, 2, 3]);
        let mut ours = AckState::new();

        assert_eq!(
            ours.merge_peer_ack(from_peer(&theirs), Some(1)).unwrap(),
            PeerAckOutcome::ClippedToCeiling {
                claimed: 3,
                ceiling: Some(1),
            }
        );
        assert_eq!(ours.high_water(), Some(1), "the truthful half was kept");

        // The same re-seeded ack, once we know we sent the rest.
        let outcome = ours.merge_peer_ack(from_peer(&theirs), Some(3)).unwrap();
        assert_eq!(outcome, PeerAckOutcome::WithinCeiling);
        assert_eq!(ours.high_water(), Some(3), "and the rest arrived");
    }

    /// A claim that stops exactly at the ceiling is honest; the boundary must not
    /// read as an over-claim.
    #[test]
    fn a_claim_reaching_exactly_the_ceiling_is_not_clipped() {
        let theirs = settled(&[0, 1, 2]);
        let mut ours = AckState::new();

        let outcome = ours.merge_peer_ack(from_peer(&theirs), Some(2)).unwrap();

        assert_eq!(outcome, PeerAckOutcome::WithinCeiling);
        assert_eq!(ours.high_water(), Some(2));
    }

    /// The trusted path takes no ceiling and must not acquire one by accident:
    /// our own republished ack merges whole.
    #[test]
    fn our_own_republished_ack_merges_unbounded() {
        let published = settled(&[0, 1, 2, 40]);
        let mut recovered = AckState::new();

        recovered.merge_own_ack(&published).unwrap();

        assert_eq!(recovered, published);
    }

    // ---- settlement --------------------------------------------------------

    #[test]
    fn settlement_reads_the_prefix_and_the_runs() {
        let state = settled(&[0, 1, 2, 7, 8]);
        for seq in [0u64, 1, 2, 7, 8] {
            assert!(state.is_settled(seq), "{seq} is settled");
        }
        for seq in [3u64, 4, 5, 6, 9, 10_000] {
            assert!(!state.is_settled(seq), "{seq} is not");
        }
    }

    /// Fail-safe: everything this ack has never heard of is unsettled. A default
    /// the other way would turn every lost ack into a delivered message.
    #[test]
    fn an_unknown_position_is_not_settled() {
        let empty = AckState::new();
        for seq in [0u64, 1, 42, u64::MAX] {
            assert!(!empty.is_settled(seq));
        }
    }

    // ---- encode / decode ---------------------------------------------------

    fn round_trip(state: &AckState) {
        let encoded = state.encode_beyond();
        let back = from_peer(state);
        assert_eq!(back.state(), state);
        assert_eq!(
            back.state().encode_beyond(),
            encoded,
            "the encoding is not canonical"
        );
    }

    #[test]
    fn encoding_round_trips() {
        round_trip(&AckState::new());
        round_trip(&settled(&[0, 1, 2]));
        round_trip(&settled(&[5]));
        round_trip(&settled(&[0, 3, 4, 5, 9, 100, 101]));
        round_trip(&settled(&[u64::MAX - 1]));

        let mut wide = AckState::new();
        for i in 0..MAX_ACK_RUNS as u64 {
            wide.collect(1 + i * 3).unwrap();
        }
        round_trip(&wide);
    }

    /// The encoded size tracks the number of gaps, never the span. This is what
    /// makes "bounded" mean something on the wire.
    #[test]
    fn the_encoding_is_bounded_by_the_run_cap() {
        let mut wide = AckState::new();
        for i in 0..MAX_ACK_RUNS as u64 {
            wide.collect(1 + i * 1_000_000_000).unwrap();
        }
        assert_eq!(
            wide.encode_beyond().len(),
            COUNT_LEN + MAX_ACK_RUNS * RUN_LEN
        );
        assert_eq!(wide.encode_beyond().len(), 1026);
    }

    /// The adversarial shape the frozen design worries about, driven directly: a
    /// run claiming the entire sequence space. It must be read in constant space
    /// and constant time, because a decoder that materialised a bit per position
    /// would allocate from an attacker-controlled number.
    #[test]
    fn a_decode_never_allocates_from_a_declared_run_extent() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&1u16.to_be_bytes());
        encoded.extend_from_slice(&1u64.to_be_bytes()); // start at 1
        encoded.extend_from_slice(&(u64::MAX - 1).to_be_bytes()); // to the very top

        let decoded =
            AckState::decode_unvalidated(None, &encoded).expect("an absurd claim is still a claim");
        let claim = decoded.state();
        assert!(claim.is_settled(1));
        assert!(claim.is_settled(u64::MAX));
        assert!(!claim.is_settled(0), "position 0 is still outside it");
        assert_eq!(claim.runs(), 1, "sixteen bytes, one run");
    }

    /// The count is checked against the cap before a single byte is reserved.
    #[test]
    fn a_decode_rejects_more_runs_than_the_cap() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            AckState::decode_unvalidated(None, &encoded).unwrap_err(),
            AckError::TooManyRuns {
                runs: u16::MAX as usize,
                max: MAX_ACK_RUNS
            }
        );
    }

    #[test]
    fn a_decode_rejects_a_truncated_buffer() {
        assert_eq!(
            AckState::decode_unvalidated(None, &[]).unwrap_err(),
            AckError::Malformed
        );
        assert_eq!(
            AckState::decode_unvalidated(None, &[0]).unwrap_err(),
            AckError::Malformed
        );

        let mut short = Vec::new();
        short.extend_from_slice(&1u16.to_be_bytes());
        short.extend_from_slice(&[0u8; RUN_LEN - 1]);
        assert_eq!(
            AckState::decode_unvalidated(None, &short).unwrap_err(),
            AckError::Malformed
        );
    }

    #[test]
    fn a_decode_rejects_trailing_bytes() {
        let mut encoded = settled(&[5]).encode_beyond();
        encoded.push(0);
        assert_eq!(
            AckState::decode_unvalidated(None, &encoded).unwrap_err(),
            AckError::Malformed
        );
    }

    /// Arithmetic that leaves the sequence space is rejected rather than wrapped:
    /// a wrapped run would describe positions at the bottom of the space that the
    /// peer never claimed.
    #[test]
    fn a_decode_rejects_a_run_that_leaves_the_sequence_space() {
        let mut overflowing_extent = Vec::new();
        overflowing_extent.extend_from_slice(&1u16.to_be_bytes());
        overflowing_extent.extend_from_slice(&1u64.to_be_bytes());
        overflowing_extent.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            AckState::decode_unvalidated(None, &overflowing_extent).unwrap_err(),
            AckError::RunOutOfRange
        );

        let mut overflowing_gap = Vec::new();
        overflowing_gap.extend_from_slice(&2u16.to_be_bytes());
        overflowing_gap.extend_from_slice(&1u64.to_be_bytes());
        overflowing_gap.extend_from_slice(&(u64::MAX - 1).to_be_bytes());
        overflowing_gap.extend_from_slice(&0u64.to_be_bytes());
        overflowing_gap.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            AckState::decode_unvalidated(None, &overflowing_gap).unwrap_err(),
            AckError::RunOutOfRange
        );
    }

    /// A run at or below the prefix is a second spelling of a state that already
    /// has one, and the signature rests on there being only one.
    #[test]
    fn a_decode_rejects_a_run_inside_the_prefix() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&1u16.to_be_bytes());
        encoded.extend_from_slice(&3u64.to_be_bytes()); // start at 3
        encoded.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            AckState::decode_unvalidated(Some(5), &encoded).unwrap_err(),
            AckError::RunInPrefix {
                start: 3,
                first_free: 6
            }
        );

        // The boundary: a run starting exactly where the prefix would absorb it.
        let mut adjacent = Vec::new();
        adjacent.extend_from_slice(&1u16.to_be_bytes());
        adjacent.extend_from_slice(&6u64.to_be_bytes());
        adjacent.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            AckState::decode_unvalidated(Some(5), &adjacent).unwrap_err(),
            AckError::RunInPrefix {
                start: 6,
                first_free: 6
            }
        );

        // And with no prefix at all, a run at zero would have been the prefix.
        let mut at_zero = Vec::new();
        at_zero.extend_from_slice(&1u16.to_be_bytes());
        at_zero.extend_from_slice(&0u64.to_be_bytes());
        at_zero.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            AckState::decode_unvalidated(None, &at_zero).unwrap_err(),
            AckError::RunInPrefix {
                start: 0,
                first_free: 0
            }
        );
    }

    /// Two runs with nothing between them describe one run, so the encoding must
    /// have no way to spell them — otherwise one set has two encodings and a
    /// signature over the bytes stops being a signature over the set.
    #[test]
    fn adjacent_runs_are_unspellable() {
        // Gaps are measured from `previous end + 2`, so the smallest legal gap
        // already leaves one unsettled position; a decoder therefore cannot be
        // handed a touching pair at all.
        let mut touching = Vec::new();
        touching.extend_from_slice(&2u16.to_be_bytes());
        touching.extend_from_slice(&1u64.to_be_bytes()); // [1, 1]
        touching.extend_from_slice(&0u64.to_be_bytes());
        touching.extend_from_slice(&0u64.to_be_bytes()); // the closest possible next
        touching.extend_from_slice(&0u64.to_be_bytes());

        let decoded = AckState::decode_unvalidated(None, &touching).expect("well-formed");
        let claim = decoded.state();
        assert_eq!(claim.runs(), 2);
        assert!(claim.is_settled(1));
        assert!(!claim.is_settled(2), "the mandatory hole");
        assert!(claim.is_settled(3));
    }

    /// Round-tripping is the property a verifier depends on: it rebuilds the
    /// signature preimage from the decoded state rather than from the bytes it was
    /// handed, so the two must agree for every state.
    #[test]
    fn a_decoded_state_rebuilds_the_same_preimage() {
        for state in [
            AckState::new(),
            settled(&[0]),
            settled(&[0, 1, 2, 9, 10, 40]),
            settled(&[7]),
        ] {
            let encoded = state.encode_beyond();
            let decoded = AckState::decode_unvalidated(state.high_water(), &encoded).unwrap();
            assert_eq!(
                sig(Direction::AToB, &state),
                hex::encode(decoded.sig_input(&chan(0x51), Direction::AToB)),
                "a verifier would rebuild a different preimage"
            );
        }
    }

    /// `settled_pages_below` is the first page NOT settled through, and the
    /// distinction from "the page the prefix sits on" is the whole of it.
    ///
    /// **The failure this pins is an off-by-one that retires a live page.** A
    /// prefix in the middle of a page leaves the positions above it unsettled, so
    /// the page is not finished and a caller releasing every page below the answer
    /// must not be handed that page's own number. Reading the prefix's page and
    /// adding one gives exactly that, and agrees with the correct answer on every
    /// page-boundary case — so a test that only checks boundaries cannot see it.
    /// The mid-page rows below are what separate the two.
    #[test]
    fn settled_pages_below_is_the_first_page_holding_an_unsettled_position() {
        let slots = u64::from(crate::dm::paging::PAGE_SLOTS);

        // An empty prefix settles no page. Zero rather than `None` because the
        // caller's question is "how many pages below this may I release", and the
        // answer for a conversation that has settled nothing is none of them.
        assert_eq!(AckState::new().settled_pages_below(), 0);

        for (high_water, want, why) in [
            (
                0u64,
                0u64,
                "one position of page zero settled leaves fifteen unsettled",
            ),
            (
                slots / 2,
                0,
                "a prefix in the MIDDLE of page zero finishes no page",
            ),
            (
                slots - 2,
                0,
                "and neither does one position short of the page's end",
            ),
            (
                slots - 1,
                1,
                "the LAST position of page zero is what finishes it",
            ),
            (
                slots,
                1,
                "the first position of page one finishes page zero only",
            ),
            (
                2 * slots - 1,
                2,
                "and the last position of page one finishes page one",
            ),
        ] {
            let mut ack = AckState::new();
            for seq in 0..=high_water {
                ack.collect(seq).expect("the prefix fits");
            }
            assert_eq!(
                ack.high_water(),
                Some(high_water),
                "the fixture must have built the prefix it names"
            );
            assert_eq!(ack.settled_pages_below(), want, "{why}");
        }
    }

    /// A position the sender gave up on settles the page exactly as a collected one
    /// does — which is what keeps a page finished under permanent loss.
    ///
    /// [`AckState::abandon`] and [`AckState::collect`] are the same transition, so
    /// this is not a second rule; it is the one place the *consequence* for a page
    /// holder is visible. Without it a single unrecoverable position holds the
    /// answer at its page for the life of the conversation.
    ///
    /// The mixed run is the control: a page finished by give-ups alone would not
    /// show that the two settle into one prefix.
    #[test]
    fn a_given_up_position_settles_its_page_like_a_collected_one() {
        let slots = u64::from(crate::dm::paging::PAGE_SLOTS);
        let mut ack = AckState::new();
        for seq in 0..slots {
            if seq % 2 == 0 {
                ack.collect(seq).expect("the prefix fits");
            } else {
                ack.abandon(seq).expect("the prefix fits");
            }
        }
        assert_eq!(
            ack.high_water(),
            Some(slots - 1),
            "collected and given-up positions must build ONE prefix"
        );
        assert_eq!(
            ack.settled_pages_below(),
            1,
            "a page made of collected and given-up positions is as finished as one \
             that was wholly read"
        );
    }
}
