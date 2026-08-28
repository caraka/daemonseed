//! When a receiver writes a *standalone* acknowledgement, and which conversation
//! gets the allowance next.
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § D-DELIV; the policy itself is the decision recorded on issue #391.
//!
//! [`ack`](crate::dm::ack) owns what an acknowledgement *means*.
//! [`ack_budget`](crate::dm::ack_budget) owns whether a write fits inside the
//! client-wide allowance. This owns the third question, which neither of them
//! answers: **whether this conversation wants a write at all right now, and when
//! it stops wanting one for ever.** The three compose in that order — a
//! conversation must want a write before the budget is asked for it, and the
//! budget's answer is final.
//!
//! ## Why a receiver needs a stopping condition at all
//!
//! Veilid has no TTL, so an acknowledgement survives only as long as its writer
//! keeps rewriting it. The sender has a terminal state — the seven-day give-up —
//! and the receiver has none: nothing acknowledges an acknowledgement, so no
//! evidence ever reaches the receiver that it may stop. Reading the record back
//! does not help, because a record the sender consumed and a record the store
//! evicted are indistinguishable without a tombstone, and a tombstone is an
//! acknowledgement with the same problem. Left unbounded, a client spends its
//! whole non-chat write allowance on correspondences that ended years ago;
//! non-chat writes share one client-wide ceiling of four per minute, of which
//! acknowledgements have about one.
//!
//! Two things follow, and they are the whole module.
//!
//! ## The curve, and why it is linear between two fixed intervals
//!
//! A cadence that needs no evidence to stop is a cadence that *decays*, so the
//! interval between standalone acknowledgements is interpolated across the
//! sender's own give-up window: [`MAX_INTERVAL_MS`] while the whole window
//! remains, falling to [`MIN_INTERVAL_MS`] as it closes.
//!
//! **The endpoints carry the argument; the shape between them does not.**
//!
//! - At the far end, the receiver has no reason to refresh faster than the
//!   sender refreshes the message it is acknowledging. The sender's re-seed
//!   ladder ([`outbox::RESEED_LADDER`](crate::dm::outbox::RESEED_LADDER)) settles
//!   on a terminal rung of one day and repeats it to the give-up, so a receiver
//!   writing more often than daily, about a conversation in which nothing has
//!   happened, is buying nothing.
//! - At the near end, the interval must never want to fire faster than the
//!   client-global allowance could ever grant, which is
//!   [`ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS`](crate::dm::ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS).
//!   A floor below it would only manufacture refusals — the conversation would
//!   ask more often and be told no, spending scheduler wakeups to learn nothing.
//!
//! Between those two the shape is **unobservable**: nothing measures which
//! interval a mid-window acknowledgement was written on, and no party can tell a
//! linear ramp from a geometric one from the outside. The obvious alternative —
//! mirroring the sender's geometric ladder — needs an anchor instant and a rung
//! count, and the receiver has neither; it would be two invented parameters
//! buying a difference nobody can see. Linear interpolation uses the one fact
//! the receiver actually holds, *how much of the sender's window is left*, and
//! invents nothing.
//!
//! **Linear in the interval is superlinear in the rate, which is what
//! "accelerate the taper" asks for.** Writes per unit time is `1/interval`, so
//! an interval falling linearly toward the terminus drives the rate as
//! `1/(a - bt)` — it rises ever faster as the give-up approaches, and is capped
//! only by the floor, which is the client-global allowance. Acceleration is a
//! property of this curve, not an extra term bolted onto it.
//!
//! ## Why the terminus is where it is
//!
//! Past the sender's give-up the write cannot have an effect.
//! [`Outbox::settle_from_ack`](crate::dm::outbox::Outbox::settle_from_ack) skips
//! any entry for which [`is_given_up`](crate::dm::outbox::OutboxEntry::is_given_up)
//! holds, *before* consulting the acknowledgement at all, and
//! [`Lifecycle::Undelivered`](crate::dm::outbox::Lifecycle::Undelivered) is
//! terminal and never re-consulted against an ack. An acknowledgement arriving
//! after the sender's give-up is discarded by construction, so a write spent on
//! one is spent into a void. That much the sender's code proves.
//!
//! **What this module cannot prove is that its terminus lands on the sender's.**
//! The two are measured on different quantities. The sender's give-up is
//! `now_ms - composed_at_ms` on the sender's own local clock, against a value it
//! recorded itself at compose time and never transmits. This module's terminus is
//! `now_ms - sent_unix_ms` on the receiver's clock, against the peer-asserted
//! wire field — which is signed, and therefore authenticated *as a statement*,
//! but is not a measurement of anything this side can check. The two agree only
//! to the extent that the clocks agree and that `sent_unix_ms` tracks
//! `composed_at_ms`, and neither is guaranteed anywhere.
//!
//! So the residual is a skew, in both directions and neither of them fatal:
//!
//! - **The asserted time runs early** (a peer clock behind ours, or a message
//!   composed well before it was sent): the receiver terminates *before* the
//!   sender gives up, stopping acknowledgement while the sender is still
//!   listening. The sender then re-seeds to its own give-up and reports
//!   *undelivered* for a message that was in fact read. This is the direction
//!   that costs something, and it costs a false negative — never a false
//!   *delivered*, which is the failure the fail-safe posture actually forbids.
//! - **The asserted time runs late**: the receiver terminates after the sender
//!   has given up, and spends a few writes into the void the first paragraph
//!   describes. It costs write allowance and nothing else.
//!
//! The magnitude is the skew itself, one-for-one — a peer an hour behind moves
//! the receiver's terminus an hour early. Nothing here bounds it, and nothing
//! detects it. It is accepted rather than solved because an acknowledgement is
//! advisory: delaying or dropping one delays *confirmation* and never delivery.
//!
//! [`standalone_interval_ms`] reports the terminus as `None` rather than as a
//! very large interval. A large interval is a conversation that is merely quiet,
//! and a caller cannot drop it from its scheduling set; `None` is a conversation
//! with nothing left in it that a write could help.
//!
//! ## Why the floor is state and not part of the curve
//!
//! The curve is a function of the clock and of the sender's window. *"Something
//! new arrived"* is a function of neither, and folding it in would need a term
//! that resets on collection — state wearing a curve's clothes, and state this
//! module could only obtain by reading collection, which it has no access to and
//! deliberately wants none of.
//!
//! So [`StandaloneAckCadence::on_collected`] sets it explicitly and
//! [`StandaloneAckCadence::on_acked`] clears it. That shape buys two properties
//! a curve term could not:
//!
//! - **It survives a refused write.** The budget may say no; the floor stays
//!   raised until an acknowledgement is actually written, so the first ack after
//!   catch-up is not merely scheduled sooner, it is guaranteed.
//! - **The caller owns the trigger.** Nothing here inspects collection state, in
//!   the same spirit as the clock being an argument.
//!
//! The floor exists because the common case is not a one-sided conversation, it
//! is catch-up: a client starts, sweeps, collects everything unread, and
//! acknowledges it while the user is reading elsewhere. A reply carries the
//! high-water for free, so the standalone path is precisely the path that fires
//! on every session start and every return from offline — and on catch-up every
//! message is old by definition, so an unfloored curve would throttle exactly the
//! acknowledgements carrying new information.
//!
//! **The terminus outranks the floor**, and that is not a conflict. The floor
//! says the first acknowledgement after collecting is written *wherever the curve
//! has reached*; past the terminus there is no curve to have reached anywhere,
//! and the write would be discarded by the sender regardless.
//!
//! ## Ordering, and the two bounds on it
//!
//! When several conversations compete for the one allowance,
//! [`pick_next`] hands it to the oldest message. The give-up is a single
//! constant — seven days for every sender, not a per-sender value — so
//! *"oldest message first"* and *"nearest give-up first"* are the same ordering,
//! and the one to implement is the one that needs no arithmetic and no
//! per-sender state: ascending on the message's declared send time, a field the
//! frame already carries.
//!
//! This settles the deferral recorded in
//! [`ack_budget`](crate::dm::ack_budget), which leaves round-robin for "if a
//! starvation case is ever measured". Catch-up is that case and it is the normal
//! path. Round-robin is fair and blind; ordering by age spends the allowance on
//! the acknowledgement nearest to becoming worthless.
//!
//! **But the sort key is attacker-chosen, so the ordering is bounded twice.** The
//! declared send time is authenticated as a statement and is a measurement of
//! nothing; unqualified, oldest-first is an auction won by whoever names the
//! smallest integer, and the winner takes the whole allowance while every other
//! conversation's sender re-seeds to its give-up and reports messages undelivered
//! that were read. So [`pick_next`] clamps the key to one give-up window, which
//! removes the gain from lying big, and refuses to hand the same candidate two
//! consecutive rounds, which caps any one conversation at about half the
//! allowance. Both bounds, their limits, and what they do not fix are argued on
//! [`pick_next`] itself.
//!
//! The send time is sender-asserted. It is signed and bound to the channel, so
//! it is authenticated *as a statement*, and it is used here only to shape a
//! cadence — a skewed value shifts the curve and costs a few writes either way.
//! No correctness depends on it: an acknowledgement is advisory, so delaying one
//! delays confirmation and never delivery.
//!
//! ## The clock is an argument
//!
//! Nothing here reads a clock, for the reason [`collect`](crate::dm::collect)
//! gives about its own cadence: a value passed in is deterministically testable
//! and a timer is not. The give-up *window* is an argument for the same reason —
//! it has exactly one home, [`outbox::GIVE_UP_MS`](crate::dm::outbox::GIVE_UP_MS),
//! which this module points at rather than copies, and passing it lets a test
//! reach the floor across a window small enough to read instead of through seven
//! days of a constant.
//!
//! **A clock that goes backwards is not due**, which is the tie-break
//! [`ack_budget`](crate::dm::ack_budget) takes and the opposite of the one
//! [`collect`](crate::dm::collect) takes. The divergence is deliberate and the
//! rule behind it is the same in all three places: being early costs `collect` a
//! read, which is free, and costs this module a *write* against a ceiling with
//! about 0.4/min of headroom. This module gates a write, so it breaks the tie
//! the way the other write-gate does.

use crate::dm::ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS;

/// The shortest interval the taper will ever ask for.
///
/// Deliberately *is* the client-global allowance
/// ([`ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS`](crate::dm::ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS)),
/// not a copy of its value: a taper that wanted to fire faster than the budget
/// can ever grant would generate refusals and nothing else.
pub const MIN_INTERVAL_MS: i64 = STANDALONE_ACK_MIN_INTERVAL_MS;

/// The longest interval the taper will ever ask for: one day.
///
/// The terminal rung of
/// [`outbox::RESEED_LADDER`](crate::dm::outbox::RESEED_LADDER) is
/// `Duration::from_secs(86_400)`, repeated until the give-up, and this matches it
/// exactly — a receiver has no reason to refresh its acknowledgement faster than
/// the sender's own steady-state re-seed when nothing new has happened and the
/// give-up is still far off.
///
/// The ladder is the canonical home of that number and this is a pointer at it;
/// the `the_ceiling_matches_the_reseed_ladders_terminal_rung` test refuses the
/// drift a pointer cannot prevent on its own. (Named rather than linked: the
/// test module is `#[cfg(test)]` and so is not a rustdoc target.)
pub const MAX_INTERVAL_MS: i64 = 86_400_000;

/// The send time of the oldest pending message that is **still inside its own
/// give-up window**, or `None` when no pending message is.
///
/// `pending_sent_ms` is the declared send time of every message this receiver has
/// collected and **not yet covered by a written acknowledgement** — the whole set,
/// not a pre-reduced oldest. The caller rebuilds it after each write, so a message
/// that has been acknowledged stops holding the curve down even though the sender
/// may still be re-seeding it.
///
/// **The filtering is done here rather than left to the caller, and that is the
/// point of taking a set.** A message that has passed its own give-up is dead —
/// nothing written about it can be acted on — but it is still *pending*, because
/// nothing ever acknowledged it. A caller that reduced its own set to a single
/// oldest would hand over that dead message for ever, and
/// [`standalone_interval_ms`] would report the whole conversation terminated even
/// while a message sent this morning sat unacknowledged behind it. One eight-day
/// absence would silently end acknowledgement for a correspondence that is very
/// much alive. That failure is invisible from the call site, so the set is taken
/// whole and the module drops the dead entries itself.
///
/// `give_up_ms` is the sender's window,
/// [`outbox::GIVE_UP_MS`](crate::dm::outbox::GIVE_UP_MS) in production.
///
/// Three edges, each of which would otherwise be a silent wrong answer:
///
/// - **The give-up boundary is inclusive**, matching
///   [`is_given_up`](crate::dm::outbox::OutboxEntry::is_given_up): a message one
///   millisecond short of the window is still live, one exactly at it is not.
/// - **A send time in the future** — a peer's clock ahead of this one — is live,
///   and its negative age makes it the oldest, which drives the *ceiling*: the
///   least frequent cadence, which is the conservative side for a write gate.
/// - **A non-positive `give_up_ms`** has nothing live in it. The guard is
///   load-bearing rather than defensive: [`standalone_interval_ms`] divides by it.
#[must_use]
pub fn oldest_live_pending_ms(
    now_ms: i64,
    pending_sent_ms: impl IntoIterator<Item = i64>,
    give_up_ms: i64,
) -> Option<i64> {
    if give_up_ms <= 0 {
        return None;
    }

    pending_sent_ms
        .into_iter()
        .filter(|&sent_ms| now_ms.saturating_sub(sent_ms) < give_up_ms)
        .min()
}

/// The interval this conversation's standalone acknowledgements should be
/// spaced at now, or `None` when nothing is left that a write could help.
///
/// `pending_sent_ms` is the set [`oldest_live_pending_ms`] describes, and this is
/// that function composed with the curve: the oldest *live* pending message sets
/// the interval, and its absence is the terminus.
///
/// `None` therefore means one of three things, which a caller treats
/// identically — the set is empty, every message in it has passed its own
/// give-up, or `give_up_ms` is non-positive. It is returned rather than a very
/// large interval because the two are different facts: a large interval is a
/// conversation that is quiet, a `None` is one that may be dropped from the
/// scheduling set entirely. See the module docs for what the terminus rests on.
#[must_use]
pub fn standalone_interval_ms(
    now_ms: i64,
    pending_sent_ms: impl IntoIterator<Item = i64>,
    give_up_ms: i64,
) -> Option<i64> {
    let oldest_ms = oldest_live_pending_ms(now_ms, pending_sent_ms, give_up_ms)?;

    // `oldest_ms` is live, so `give_up_ms > 0` and `age_ms < give_up_ms` both
    // hold here — neither needs re-checking.
    let age_ms = now_ms.saturating_sub(oldest_ms);

    // Clamped rather than merely floored: a future send time makes `age_ms`
    // negative, and an unclamped remainder would exceed the window and push the
    // interpolation above the ceiling.
    let remaining_ms = give_up_ms.saturating_sub(age_ms).clamp(0, give_up_ms);

    // In `i128` because the exact product is wanted and the operands are a
    // caller's: seven days against the real span is about 5.2e16, comfortably
    // inside `i64`, but `give_up_ms` is an argument and nothing here vouches for
    // its magnitude. The quotient is in `[0, span]` because
    // `remaining_ms <= give_up_ms`, so the narrowing cast cannot lose anything.
    let span = MAX_INTERVAL_MS - MIN_INTERVAL_MS;
    let scaled = i128::from(remaining_ms) * i128::from(span) / i128::from(give_up_ms);
    Some(MIN_INTERVAL_MS + scaled as i64)
}

/// One conversation's standalone-acknowledgement cadence state.
///
/// Hold one per conversation — unlike
/// [`StandaloneAckBudget`](crate::dm::ack_budget::StandaloneAckBudget), which is
/// one per *client*. The two are not alternatives and neither substitutes for the
/// other: this decides whether a conversation wants a write, the budget decides
/// whether the client can afford one, and a write happens only when both agree.
///
/// **Deliberately neither `Copy` nor `Clone`.** [`Self::on_collected`] and
/// [`Self::on_acked`] take `&mut self`, so under `Copy` a by-value pass would
/// mutate a duplicate and leave the caller's own untouched — silently, with no
/// diagnostic. The floor flag is exactly the field that would go missing that
/// way: a duplicate that swallowed an `on_collected` would drop the guaranteed
/// catch-up acknowledgement, and a duplicate that swallowed an `on_acked` would
/// keep firing one. Without the derives the same code is a move error.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StandaloneAckCadence {
    /// When a standalone acknowledgement was last written. `None` before the
    /// first one, which is why a fresh conversation is due at once rather than
    /// owing an interval it never used — the reasoning
    /// [`StandaloneAckBudget::new`](crate::dm::ack_budget::StandaloneAckBudget::new)
    /// gives for a fresh budget granting immediately.
    last_acked_ms: Option<i64>,
    /// Whether something has been collected since the last standalone
    /// acknowledgement was written. Set by the caller; cleared only by a write,
    /// never by the passage of time.
    collected_since_ack: bool,
}

impl StandaloneAckCadence {
    /// A conversation that has never written a standalone acknowledgement, and
    /// so is due for one at once.
    pub const fn new() -> Self {
        Self {
            last_acked_ms: None,
            collected_since_ack: false,
        }
    }

    /// Record that new messages were collected for this conversation.
    ///
    /// Raises the floor: the next acknowledgement is due wherever the curve has
    /// reached. Idempotent — collecting twice before a write is the same as
    /// collecting once, because the floor guarantees *one* acknowledgement, not
    /// one per message.
    ///
    /// Nothing here inspects collection state; the caller says so, for the same
    /// reason the clock is an argument.
    pub fn on_collected(&mut self) {
        self.collected_since_ack = true;
    }

    /// Record that a standalone acknowledgement was written at `now_ms`.
    ///
    /// Call this on the write, never on the *decision* to write: a decision the
    /// budget then refuses must leave the floor raised, or catch-up loses the one
    /// acknowledgement the floor exists to guarantee.
    pub fn on_acked(&mut self, now_ms: i64) {
        self.last_acked_ms = Some(now_ms);
        self.collected_since_ack = false;
    }

    /// Whether this conversation wants a standalone acknowledgement written now.
    ///
    /// A `true` is a request, not a permission — the write still has to fit
    /// inside
    /// [`StandaloneAckBudget::request`](crate::dm::ack_budget::StandaloneAckBudget::request),
    /// and asking repeatedly costs nothing because this reads no state it also
    /// mutates.
    ///
    /// `pending_sent_ms` is the set [`oldest_live_pending_ms`] describes, passed
    /// whole: a message that has passed its own give-up is dropped here, so one
    /// stale message cannot terminate a conversation that also holds a fresh one.
    ///
    /// The three answers in order, and the order is the policy:
    ///
    /// 1. **Terminated** (`standalone_interval_ms` is `None`) — never due, even
    ///    with the floor raised. See the module docs: past the give-up the
    ///    sender discards the acknowledgement by construction. Note this is a
    ///    statement about the *live* set, so it means "nothing remains that a
    ///    write could help", never merely "the oldest thing here is old".
    /// 2. **Floor raised** — due immediately, wherever the curve has reached.
    /// 3. **Otherwise** the curve: due once the current interval has elapsed
    ///    since the last write, and immediately if there has never been one.
    ///
    /// **The interval is re-evaluated at `now_ms`, not frozen at the last
    /// write.** A conversation that has been waiting a long time is therefore
    /// measured against the interval the curve has *now* reached, which is
    /// narrower than the one in force when it last wrote — so the taper
    /// accelerates a waiting conversation as well as a writing one. The
    /// alternative, pinning the interval at the write, would leave a
    /// conversation that wrote once early in the window parked on a day-wide
    /// interval right through the give-up.
    ///
    /// **A `now_ms` earlier than the last write is not due.** It reads as still
    /// inside the interval, which parks the conversation for the size of the
    /// step; that is
    /// [`ack_budget`](crate::dm::ack_budget)'s tie-break and the opposite of
    /// [`collect`](crate::dm::collect)'s, because being early costs a write here
    /// and only a read there.
    ///
    /// A caller that needs to distinguish *not yet* from *never again* asks
    /// [`standalone_interval_ms`] directly; this collapses both to `false`
    /// because a scheduler acting on this answer treats them identically.
    #[must_use]
    pub fn is_due(
        &self,
        now_ms: i64,
        pending_sent_ms: impl IntoIterator<Item = i64>,
        give_up_ms: i64,
    ) -> bool {
        let Some(interval_ms) = standalone_interval_ms(now_ms, pending_sent_ms, give_up_ms) else {
            return false;
        };

        if self.collected_since_ack {
            return true;
        }

        let Some(last) = self.last_acked_ms else {
            return true;
        };

        now_ms.saturating_sub(last) >= interval_ms
    }
}

/// The candidate whose oldest pending message was sent first, under a bounded
/// reading of "first" and never the same candidate twice running.
///
/// Each item pairs a candidate with the declared send time of the oldest message
/// it is waiting to have acknowledged — on the wire the `sent_unix_ms` a frame
/// already carries. It is taken as a plain `i64` rather than as a frame, so this
/// module needs no dependency on [`frame`](crate::dm::frame) and a caller may
/// pass whatever it uses to name a conversation. **Build the key with
/// [`oldest_live_pending_ms`]**, not from the raw pending set: a conversation
/// whose oldest pending message has already passed its own give-up would
/// otherwise win rounds while being the one conversation a write cannot help.
///
/// `last_picked` is the candidate this returned on the previous round; the caller
/// remembers it. `None` on the first round, or whenever the caller does not want
/// the skip.
///
/// ## Why oldest-first needed bounding at all
///
/// The ordering key is a **peer-asserted** timestamp. It is signed, so it is
/// authenticated as a *statement*, but nothing about it is a measurement this
/// side can check, and nothing bounds what a peer may assert. Unqualified
/// oldest-first therefore hands a client-global allowance of about one write per
/// minute to whoever claims the oldest message — an ordering a hostile contact
/// wins by choosing an integer. It monopolizes the allowance, and the cost lands
/// on the *other* conversations: their acknowledgements never get written, their
/// senders re-seed to the give-up, and messages that were read are reported
/// undelivered.
///
/// Two bounds, in the order they apply:
///
/// **1. The key is clamped to one give-up window.** A message cannot legitimately
/// be older than `now_ms - give_up_ms` and still matter — past that it is dead by
/// the argument in the module docs — so anything claiming to be older is compared
/// *as if* it sat exactly on that floor. Claiming a year back therefore buys
/// nothing over claiming the floor, which removes the incentive to lie big. The
/// clamp is a no-op on any correctly-built key, because [`oldest_live_pending_ms`]
/// already admits only values strictly above that floor; it is here so this
/// function is bounded standing alone, rather than trusting its caller to have
/// filtered.
///
/// **2. A candidate does not win twice running.** When the clamped-oldest is
/// `last_picked`, the next-oldest takes the round instead. Clamping alone does
/// not stop a peer parking on the floor and winning every round; this does, and
/// it bounds any single conversation to at most every other round — **about half
/// the allowance, and no lower**. Half rather than less because skip-once cannot
/// tell a hostile contact alternating with one honest conversation from two
/// honest conversations taking turns, which is the correct outcome for the
/// latter; a stronger bound would need per-conversation history, which is state
/// this function deliberately does not hold.
///
/// ⚠️ **Residual, not solved here: an attacker with two identities alternates
/// between them and wins every round again**, because the skip is keyed on the
/// candidate and two contacts are two candidates. Bounding *that* is an
/// admission-control question, not an ordering one.
///
/// **The sole candidate still wins, even as `last_picked`.** Skipping there would
/// mean a client in one conversation never acknowledged anything, which is total
/// starvation produced by the anti-starvation rule. The same fallback covers a
/// set in which every candidate equals `last_picked`.
///
/// Stateless and independent of [`StandaloneAckCadence`] on purpose: the ordering
/// is a property of the competing set at one instant, so nothing is held between
/// calls and the caller may rebuild the set however it likes. `last_picked` is
/// the one thing it cannot recompute, so the caller passes it in rather than this
/// function growing a memory.
///
/// **Ties go to the earlier item in iteration order**, which is
/// [`Iterator::min_by_key`]'s documented behaviour and is pinned by a test rather
/// than assumed. Any tie-break is arbitrary — two messages sent in the same
/// millisecond are equally close to their give-ups — so the one to specify is the
/// one that makes the function deterministic for a caller building the set in a
/// stable order. The clamp creates ties on purpose, which is what makes it a
/// bound rather than a re-ordering.
///
/// `None` when there are no candidates: nothing is competing, so nothing wins.
#[must_use]
pub fn pick_next<T: PartialEq>(
    candidates: impl IntoIterator<Item = (T, i64)>,
    now_ms: i64,
    give_up_ms: i64,
    last_picked: Option<&T>,
) -> Option<T> {
    // Saturating so an extreme `now_ms` cannot wrap the floor to the far end of
    // the clock and invert every comparison. A non-positive `give_up_ms` puts the
    // floor at or after `now_ms`, which clamps every key together and leaves
    // iteration order deciding — safe, and unreachable through a caller that
    // built its keys with `oldest_live_pending_ms`, which yields nothing at all
    // for such a window.
    let floor_ms = now_ms.saturating_sub(give_up_ms);

    let mut ranked: Vec<(T, i64)> = candidates
        .into_iter()
        .map(|(candidate, sent_ms)| (candidate, sent_ms.max(floor_ms)))
        .collect();

    let oldest = oldest_index(&ranked)?;

    let Some(last) = last_picked else {
        return Some(ranked.swap_remove(oldest).0);
    };
    if ranked[oldest].0 != *last {
        return Some(ranked.swap_remove(oldest).0);
    }

    // Last round's winner is oldest again. Give the round to the oldest of
    // everything else, and fall back to it only when there is nothing else —
    // never starve a client that has one conversation.
    let alternative = ranked
        .iter()
        .enumerate()
        .filter(|(_, (candidate, _))| candidate != last)
        .min_by_key(|(_, (_, key_ms))| *key_ms)
        .map(|(index, _)| index);

    Some(ranked.swap_remove(alternative.unwrap_or(oldest)).0)
}

/// The index of the smallest key, or `None` for an empty slice.
///
/// Split out so both passes in [`pick_next`] break ties the same way —
/// first-in-iteration-order — rather than one of them acquiring a different rule
/// by being written twice.
fn oldest_index<T>(ranked: &[(T, i64)]) -> Option<usize> {
    ranked
        .iter()
        .enumerate()
        .min_by_key(|(_, (_, key_ms))| *key_ms)
        .map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::outbox::{GIVE_UP_MS, RESEED_LADDER};

    /// A readable stand-in for the seven-day window, used where a test is about
    /// the *shape* of the curve rather than about the real numbers. Ten seconds
    /// divides evenly into the endpoints being asserted.
    const SHORT_WINDOW_MS: i64 = 10_000;

    const T0: i64 = 1_700_000_000_000;

    /// The ceiling is the sender's terminal re-seed rung, and stays that way.
    ///
    /// The constant is written literally for readability, so nothing but this
    /// test stops the two drifting apart — and a drift would be invisible: the
    /// module would keep working, just at a cadence whose stated justification
    /// had stopped being true.
    #[test]
    fn the_ceiling_matches_the_reseed_ladders_terminal_rung() {
        let terminal = RESEED_LADDER
            .last()
            .expect("the re-seed ladder is never empty");
        assert_eq!(
            MAX_INTERVAL_MS,
            terminal.as_millis() as i64,
            "the taper ceiling must be the ladder's terminal rung, not merely near it"
        );
    }

    /// The floor is the client-global allowance itself, not a number that
    /// happens to equal it today.
    #[test]
    fn the_floor_is_the_client_global_allowance() {
        assert_eq!(MIN_INTERVAL_MS, STANDALONE_ACK_MIN_INTERVAL_MS);
    }

    /// The endpoints, pinned exactly against the real seven-day window.
    ///
    /// **Both ends and the midpoint, not one sample.** A single assertion at
    /// age zero is satisfied by a function that returns the ceiling always; a
    /// single one near the terminus by one that returns the floor always. The
    /// midpoint additionally pins the interpolation itself — half the window
    /// remaining is half the span above the floor, and no constant fits all
    /// three.
    #[test]
    fn the_curve_runs_from_the_ceiling_to_the_floor_across_the_window() {
        let span = MAX_INTERVAL_MS - MIN_INTERVAL_MS;
        for (age_ms, expected) in [
            (0i64, MAX_INTERVAL_MS),
            (GIVE_UP_MS / 2, MIN_INTERVAL_MS + span / 2),
            (GIVE_UP_MS - 1, MIN_INTERVAL_MS),
        ] {
            assert_eq!(
                standalone_interval_ms(T0 + age_ms, [T0], GIVE_UP_MS),
                Some(expected),
                "at an age of {age_ms} ms the interval must be exactly {expected} ms"
            );
        }
    }

    /// **The regression this module's shape exists to prevent.** One message that
    /// has passed its own give-up must not terminate a conversation that also
    /// holds a live one.
    ///
    /// The sequence: eight days offline, come back, collect a message sent eight
    /// days ago — dead on arrival, correctly never acknowledged, and permanently
    /// pending because nothing ever acknowledged it. A fresh message then arrives
    /// today. If the dead message still set the key, the whole correspondence
    /// would report terminated for ever while a message sent this morning sat
    /// unacknowledged behind it, and the floor could not rescue it because the
    /// terminus outranks the floor by design.
    ///
    /// The interval is asserted exactly, not merely as `Some`: the live message's
    /// age must be the one driving the curve, so a fresh message reads as the
    /// ceiling. Both orderings of the set are checked, because an implementation
    /// that took the first live entry rather than the oldest would pass one.
    #[test]
    fn a_given_up_message_does_not_terminate_a_conversation_holding_a_live_one() {
        let now = T0 + GIVE_UP_MS + 86_400_000;
        let dead_ms = T0;
        let fresh_ms = now;

        assert_eq!(
            standalone_interval_ms(now, [dead_ms], GIVE_UP_MS),
            None,
            "sanity: the stale message alone is genuinely terminated"
        );

        for pending in [[dead_ms, fresh_ms], [fresh_ms, dead_ms]] {
            assert_eq!(
                oldest_live_pending_ms(now, pending, GIVE_UP_MS),
                Some(fresh_ms),
                "the oldest LIVE message is the fresh one; the dead one is dropped"
            );
            assert_eq!(
                standalone_interval_ms(now, pending, GIVE_UP_MS),
                Some(MAX_INTERVAL_MS),
                "a conversation holding a live message is not terminated, and its \
                 curve is driven by that message's age"
            );
            assert!(
                StandaloneAckCadence::new().is_due(now, pending, GIVE_UP_MS),
                "and it is schedulable"
            );
        }
    }

    /// The oldest of several live messages sets the curve, not the newest and not
    /// the first in iteration order.
    #[test]
    fn the_oldest_live_message_sets_the_curve() {
        let now = T0 + GIVE_UP_MS / 2;
        // Deliberately unordered, with the oldest neither first nor last.
        let pending = [now - 1_000, now - GIVE_UP_MS / 4, now - 500];

        assert_eq!(
            oldest_live_pending_ms(now, pending, GIVE_UP_MS),
            Some(now - GIVE_UP_MS / 4)
        );

        let span = MAX_INTERVAL_MS - MIN_INTERVAL_MS;
        assert_eq!(
            standalone_interval_ms(now, pending, GIVE_UP_MS),
            Some(MIN_INTERVAL_MS + span * 3 / 4),
            "a quarter of the window elapsed leaves three quarters of the span"
        );
    }

    /// An empty pending set is terminated: there is nothing to acknowledge, so
    /// there is no interval to ask for.
    ///
    /// Asserted because it is the degenerate case a `min` over an empty iterator
    /// produces, and it must mean *nothing to do* rather than a panic or a
    /// spurious ceiling.
    #[test]
    fn an_empty_pending_set_is_terminated() {
        assert_eq!(oldest_live_pending_ms(T0, [], GIVE_UP_MS), None);
        assert_eq!(standalone_interval_ms(T0, [], GIVE_UP_MS), None);
        assert!(!StandaloneAckCadence::new().is_due(T0, [], GIVE_UP_MS));
    }

    /// A set in which every message has passed its own give-up is terminated —
    /// the whole-set form of the terminus.
    #[test]
    fn a_wholly_given_up_set_is_terminated() {
        let now = T0 + 10 * GIVE_UP_MS;
        let pending = [T0, T0 + 1_000, now - GIVE_UP_MS];
        assert_eq!(oldest_live_pending_ms(now, pending, GIVE_UP_MS), None);
        assert_eq!(standalone_interval_ms(now, pending, GIVE_UP_MS), None);
    }

    /// The interval never rises as the window closes, and actually traverses the
    /// whole range while doing so.
    ///
    /// The monotonicity assertion alone passes against a constant function, so
    /// the traversal is asserted too: the first sample is the ceiling, the last
    /// is the floor, and at least one strict decrease happened in between.
    #[test]
    fn the_interval_never_rises_as_the_window_closes() {
        // Ages span zero to one millisecond short of the give-up, so the last
        // sample is the last instant that is still inside the window.
        let samples: Vec<i64> = (0..=1_000)
            .map(|step| {
                let age_ms = (GIVE_UP_MS - 1) * step / 1_000;
                standalone_interval_ms(T0 + age_ms, [T0], GIVE_UP_MS)
                    .expect("every sample is inside the window")
            })
            .collect();

        assert!(
            samples.windows(2).all(|w| w[1] <= w[0]),
            "the taper must never widen as the give-up approaches"
        );
        assert_eq!(*samples.first().expect("sampled"), MAX_INTERVAL_MS);
        assert_eq!(*samples.last().expect("sampled"), MIN_INTERVAL_MS);
        assert!(
            samples.windows(2).any(|w| w[1] < w[0]),
            "with no strict decrease this test would pass against a constant interval, \
             which is the thing it exists to catch"
        );
    }

    /// The terminus is exact: one millisecond short of the window still tapers,
    /// exactly at it is over, and it stays over.
    ///
    /// This is the boundary
    /// [`is_given_up`](crate::dm::outbox::OutboxEntry::is_given_up) uses, and an
    /// off-by-one here would either spend a week of writes into a void or cut a
    /// conversation off a millisecond before its last useful acknowledgement.
    #[test]
    fn the_terminus_is_exact_at_the_give_up() {
        assert_eq!(
            standalone_interval_ms(T0 + GIVE_UP_MS - 1, [T0], GIVE_UP_MS),
            Some(MIN_INTERVAL_MS),
            "one millisecond short of the give-up is still inside the window"
        );
        assert_eq!(
            standalone_interval_ms(T0 + GIVE_UP_MS, [T0], GIVE_UP_MS),
            None,
            "exactly at the give-up is terminated, matching is_given_up's >="
        );
        assert_eq!(
            standalone_interval_ms(T0 + GIVE_UP_MS + 1, [T0], GIVE_UP_MS),
            None
        );
        assert_eq!(
            standalone_interval_ms(i64::MAX, [T0], GIVE_UP_MS),
            None,
            "and it does not come back at extreme clock values"
        );
    }

    /// A send time in the future clamps to the ceiling rather than escaping
    /// above it or wrapping.
    #[test]
    fn a_future_send_time_tapers_at_the_ceiling() {
        assert_eq!(
            standalone_interval_ms(T0, [T0 + 60_000], GIVE_UP_MS),
            Some(MAX_INTERVAL_MS)
        );
        assert_eq!(
            standalone_interval_ms(i64::MIN, [i64::MAX], GIVE_UP_MS),
            Some(MAX_INTERVAL_MS),
            "the widest possible negative age saturates to the ceiling, not past it"
        );
    }

    /// A non-positive window is terminated rather than dividing by zero.
    ///
    /// The guard is what stops the interpolation panicking, so this is a test of
    /// reachable behaviour and not of a defensive branch: `give_up_ms` is a
    /// caller's argument.
    #[test]
    fn a_non_positive_window_is_terminated() {
        for give_up_ms in [0i64, -1, i64::MIN] {
            assert_eq!(
                oldest_live_pending_ms(T0, [T0], give_up_ms),
                None,
                "a window of {give_up_ms} ms holds nothing live"
            );
            assert_eq!(
                standalone_interval_ms(T0, [T0], give_up_ms),
                None,
                "a window of {give_up_ms} ms has no interval to taper across"
            );
        }
    }

    /// A conversation nobody has acknowledged is due at once: a client that has
    /// just started should not owe an interval it never used.
    #[test]
    fn a_fresh_cadence_is_due_at_once() {
        let c = StandaloneAckCadence::new();
        assert!(c.is_due(T0, [T0], GIVE_UP_MS));
    }

    /// [`Default`] and [`StandaloneAckCadence::new`] agree.
    ///
    /// Untested, a `Default` impl that arrived with the floor already lowered —
    /// or with a `last_acked_ms` — is indistinguishable from the derive, and
    /// `Default` is one of the ways a caller can mint one.
    #[test]
    fn default_is_a_fresh_cadence_like_new() {
        assert_eq!(
            StandaloneAckCadence::default(),
            StandaloneAckCadence::new(),
            "a defaulted cadence must be an unfired one"
        );
        assert!(StandaloneAckCadence::default().is_due(T0, [T0], GIVE_UP_MS));
    }

    /// After a write, the next one is due exactly one interval later — not a
    /// millisecond before — where "one interval" is the curve's value **at the
    /// instant being asked about**, not at the write.
    ///
    /// Both assertions in a row therefore share one `now_ms` and differ only in
    /// when the last write was, which is the only way to pin the boundary
    /// without the curve moving between the two calls.
    ///
    /// Pinned at three ages so the interval being waited out is demonstrably the
    /// *curve's* and not a constant: the ceiling at the top of the window, the
    /// exact midpoint, and a quarter of the window remaining.
    #[test]
    fn the_curve_paces_writes_after_the_first() {
        let span = MAX_INTERVAL_MS - MIN_INTERVAL_MS;
        for (age_ms, interval) in [
            (0i64, MAX_INTERVAL_MS),
            (GIVE_UP_MS / 2, MIN_INTERVAL_MS + span / 2),
            (GIVE_UP_MS * 3 / 4, MIN_INTERVAL_MS + span / 4),
        ] {
            let sent = T0;
            let now = T0 + age_ms;

            let mut short = StandaloneAckCadence::new();
            short.on_acked(now - interval + 1);
            assert!(
                !short.is_due(now, [sent], GIVE_UP_MS),
                "at an age of {age_ms} ms, one millisecond short of {interval} ms is not due"
            );

            let mut exact = StandaloneAckCadence::new();
            exact.on_acked(now - interval);
            assert!(
                exact.is_due(now, [sent], GIVE_UP_MS),
                "at an age of {age_ms} ms, exactly {interval} ms since the write is due"
            );
        }
    }

    /// The taper accelerates a *waiting* conversation, not only a writing one:
    /// one write early in the window does not park it on a day-wide interval for
    /// the rest of the give-up.
    ///
    /// This is the consequence of evaluating the interval at `now_ms` rather
    /// than freezing it at the write, and it is asserted because an
    /// implementation that stored the interval alongside `last_acked_ms` would
    /// pass every other test here.
    #[test]
    fn a_conversation_that_wrote_once_early_still_tapers() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(T0);

        // Half a ceiling-interval later the curve has barely moved, so nothing
        // is due — the control that stops this passing against "always due".
        assert!(!c.is_due(T0 + MAX_INTERVAL_MS / 2, [T0], GIVE_UP_MS));

        // Well before a full day has elapsed, but with most of the window gone,
        // the interval the curve now asks for is already behind us.
        let now = T0 + GIVE_UP_MS * 9 / 10;
        assert!(
            now - T0 > MAX_INTERVAL_MS,
            "sanity: this instant is more than one ceiling-interval after the write"
        );
        assert!(
            c.is_due(now, [T0], GIVE_UP_MS),
            "a conversation waiting into the narrow end of the curve must become due there"
        );
    }

    /// The floor fires wherever the curve has reached — including one
    /// millisecond after a write, when the curve is at its widest.
    ///
    /// This is the catch-up case: everything collected at once, nothing to
    /// piggyback on, and the sender still inside its window.
    #[test]
    fn collecting_makes_an_acknowledgement_due_wherever_the_curve_has_reached() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(T0);
        assert!(
            !c.is_due(T0 + 1, [T0], GIVE_UP_MS),
            "without the floor, one millisecond into a day-wide interval is not due"
        );

        c.on_collected();
        assert!(
            c.is_due(T0 + 1, [T0], GIVE_UP_MS),
            "collecting must make the next acknowledgement due immediately"
        );
    }

    /// A write clears the floor; a decision that never became a write does not.
    ///
    /// The second half is the property the floor exists for. The budget refuses
    /// most requests, and a floor cleared by asking rather than by writing would
    /// drop exactly the catch-up acknowledgement it was raised to guarantee.
    #[test]
    fn only_a_write_clears_the_floor() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(T0);
        c.on_collected();

        // Asked repeatedly and refused by the budget every time: the floor holds.
        for ms in 1..=10 {
            assert!(
                c.is_due(T0 + ms, [T0], GIVE_UP_MS),
                "a refused request must not lower the floor"
            );
        }

        c.on_acked(T0 + 11);
        assert!(
            !c.is_due(T0 + 12, [T0], GIVE_UP_MS),
            "writing the acknowledgement lowers the floor, and the curve takes over"
        );
    }

    /// Collecting twice before a write is the same as collecting once: the floor
    /// guarantees one acknowledgement, not one per message.
    #[test]
    fn collecting_is_idempotent_until_a_write() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(T0);
        c.on_collected();
        c.on_collected();
        c.on_acked(T0 + 1);

        assert!(
            !c.is_due(T0 + 2, [T0], GIVE_UP_MS),
            "one write must satisfy any number of collections that preceded it"
        );
    }

    /// **The terminus outranks the floor.** A conversation past the give-up is
    /// never due, however much has just been collected.
    ///
    /// Both orderings are asserted — collect-then-terminate and
    /// terminate-then-collect — because an implementation that checked the floor
    /// first would pass one of them.
    #[test]
    fn a_terminated_conversation_is_never_due_even_after_collecting() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(T0);
        c.on_collected();
        assert!(
            !c.is_due(T0 + GIVE_UP_MS, [T0], GIVE_UP_MS),
            "past the give-up the sender discards the acknowledgement, so the floor \
             cannot make it worth writing"
        );

        let mut fresh = StandaloneAckCadence::new();
        assert!(
            !fresh.is_due(T0 + GIVE_UP_MS, [T0], GIVE_UP_MS),
            "and a conversation that never wrote one does not get a free write at the terminus"
        );
        fresh.on_collected();
        assert!(!fresh.is_due(T0 + GIVE_UP_MS, [T0], GIVE_UP_MS));
    }

    /// A clock that steps backwards is not due, and stays not-due for the size
    /// of the step.
    ///
    /// The tie-break [`ack_budget`](crate::dm::ack_budget) takes and the
    /// opposite of [`collect`](crate::dm::collect)'s, because this gates a write.
    /// The recovery instant is pinned rather than merely asserting "not due
    /// somewhere": a re-anchoring implementation would look identical at the
    /// first assertion and would grant an early write at the second.
    ///
    /// **The age is held at zero throughout** — the pending message's send time
    /// tracks `now_ms` — so the interval is the ceiling at every call and the
    /// clock tie-break is isolated from the curve. Otherwise a step back also
    /// moves the curve, and the two effects cannot be told apart.
    #[test]
    fn a_backwards_clock_parks_rather_than_firing_early() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(T0);

        let stepped_back = T0 - 10_000;
        assert!(
            !c.is_due(stepped_back, [stepped_back], GIVE_UP_MS),
            "a step back must not read as an elapsed interval"
        );
        assert!(
            !c.is_due(
                stepped_back + MAX_INTERVAL_MS,
                [stepped_back + MAX_INTERVAL_MS],
                GIVE_UP_MS
            ),
            "and must not re-anchor: one interval after the STEPPED-BACK instant is \
             still inside the interval measured from the write"
        );
        assert!(
            c.is_due(T0 + MAX_INTERVAL_MS, [T0 + MAX_INTERVAL_MS], GIVE_UP_MS),
            "the allowance renews one interval after the WRITE"
        );
    }

    /// The arithmetic holds at the extremes of the clock type rather than
    /// overflowing into a spurious due.
    #[test]
    fn extreme_clock_values_do_not_overflow() {
        let mut c = StandaloneAckCadence::new();
        c.on_acked(i64::MAX);
        assert!(
            !c.is_due(i64::MIN, [i64::MIN], GIVE_UP_MS),
            "the widest possible step back saturates rather than wrapping into a due"
        );
    }

    /// The whole curve is readable across a ten-second window, which is the
    /// shape argument stated once without seven days of arithmetic in the way.
    #[test]
    fn the_curve_is_the_same_shape_at_any_window_size() {
        let span = MAX_INTERVAL_MS - MIN_INTERVAL_MS;
        assert_eq!(
            standalone_interval_ms(T0, [T0], SHORT_WINDOW_MS),
            Some(MAX_INTERVAL_MS)
        );
        assert_eq!(
            standalone_interval_ms(T0 + SHORT_WINDOW_MS / 4, [T0], SHORT_WINDOW_MS),
            Some(MIN_INTERVAL_MS + span * 3 / 4),
            "three quarters of the window remaining is three quarters of the span"
        );
        assert_eq!(
            standalone_interval_ms(T0 + SHORT_WINDOW_MS, [T0], SHORT_WINDOW_MS),
            None
        );
    }

    /// An instant late enough in the fixture clock that `NOW - GIVE_UP_MS` is a
    /// readable, positive floor for the clamp tests.
    const NOW: i64 = T0 + 2 * GIVE_UP_MS;

    /// The oldest message wins, and the winner is neither first nor last in
    /// input order.
    ///
    /// **That placement is the whole point of the fixture.** A comparator that
    /// simply returned the head would pass a two-candidate test half the time
    /// and an ordered one always; with the minimum in the middle, neither
    /// "first wins" nor "last wins" can pass.
    #[test]
    fn pick_next_takes_the_oldest_from_the_middle_of_the_set() {
        let candidates = [
            ("alice", NOW - 5_000),
            ("bob", NOW - 9_000),
            ("carol", NOW - 1_000),
            ("dave", NOW - 7_000),
        ];
        assert_eq!(pick_next(candidates, NOW, GIVE_UP_MS, None), Some("bob"));

        // Reversed, so the answer cannot depend on where the minimum sits.
        let mut reversed = candidates;
        reversed.reverse();
        assert_eq!(pick_next(reversed, NOW, GIVE_UP_MS, None), Some("bob"));
    }

    /// Ties go to the earlier item in iteration order, deterministically.
    #[test]
    fn pick_next_breaks_a_tie_on_iteration_order() {
        assert_eq!(
            pick_next(
                [("first", NOW), ("second", NOW), ("third", NOW)],
                NOW,
                GIVE_UP_MS,
                None
            ),
            Some("first")
        );
    }

    /// Nothing competing means nothing wins.
    #[test]
    fn pick_next_on_an_empty_set_is_none() {
        assert_eq!(
            pick_next(Vec::<(&str, i64)>::new(), NOW, GIVE_UP_MS, None),
            None
        );
    }

    /// **Bound one: an absurdly old claim is clamped to the give-up floor rather
    /// than sorting below everything else without limit.**
    ///
    /// The attacker claims a send time thirty years back. Clamped, that key
    /// equals the floor — and an honest conversation sitting exactly on the floor
    /// therefore *ties* with it and wins on iteration order, which is the
    /// observable difference between a clamp and no clamp. Without the clamp the
    /// liar sorts strictly below and wins.
    ///
    /// The third assertion is the control: something genuinely *below* the floor
    /// in claimed terms but with an honest neighbour still above it must lose to
    /// nobody, so the clamp is shown to bound rather than to invert.
    #[test]
    fn pick_next_clamps_an_absurdly_old_claim_to_the_give_up_floor() {
        let floor_ms = NOW - GIVE_UP_MS;
        let thirty_years_ms = 30 * 365 * 24 * 60 * 60 * 1_000i64;

        assert_eq!(
            pick_next(
                [("honest", floor_ms), ("liar", floor_ms - thirty_years_ms)],
                NOW,
                GIVE_UP_MS,
                None
            ),
            Some("honest"),
            "clamped to the floor the liar only ties, and loses the tie on order"
        );

        // The mirror control: without a clamp the liar sorts strictly below and
        // takes the round. Asserting the un-clamped comparison directly would be
        // asserting the bug, so this asserts the clamp's own arithmetic instead.
        assert_eq!(
            (floor_ms - thirty_years_ms).max(floor_ms),
            floor_ms,
            "the clamp is what erases the thirty years"
        );

        assert_eq!(
            pick_next(
                [("liar", floor_ms - thirty_years_ms), ("newer", NOW - 1_000)],
                NOW,
                GIVE_UP_MS,
                None
            ),
            Some("liar"),
            "the clamp bounds the claim, it does not discard the candidate: against a \
             genuinely newer rival the floor still wins"
        );
    }

    /// **Bound two: the same candidate does not take two rounds running.**
    ///
    /// The attacker parks on the floor and would win every round on age alone;
    /// the skip hands round two to the next-oldest. The first call is asserted
    /// too, so the test cannot pass against an implementation that simply never
    /// picks the attacker.
    #[test]
    fn pick_next_skips_the_previous_winner() {
        let floor_ms = NOW - GIVE_UP_MS;
        let candidates = [
            ("attacker", floor_ms),
            ("honest_older", NOW - 60_000),
            ("honest_newer", NOW - 1_000),
        ];

        let first = pick_next(candidates, NOW, GIVE_UP_MS, None);
        assert_eq!(
            first,
            Some("attacker"),
            "on age alone the attacker takes the first round"
        );

        assert_eq!(
            pick_next(candidates, NOW, GIVE_UP_MS, first.as_ref()),
            Some("honest_older"),
            "and must not take the second: the next-oldest gets it instead"
        );
    }

    /// The skip yields to the next-*oldest*, not to whatever comes next in input
    /// order.
    ///
    /// The alternative is placed last in the set with the newest candidate ahead
    /// of it, so an implementation that skipped by advancing the iterator would
    /// return the wrong one.
    #[test]
    fn the_skipped_round_goes_to_the_next_oldest_not_the_next_in_order() {
        let candidates = [
            ("attacker", NOW - 90_000),
            ("newest", NOW - 1_000),
            ("second_oldest", NOW - 60_000),
        ];
        assert_eq!(
            pick_next(candidates, NOW, GIVE_UP_MS, Some(&"attacker")),
            Some("second_oldest")
        );
    }

    /// **The sole candidate still wins, even as the previous winner.**
    ///
    /// Skipping here would mean a client with one conversation never
    /// acknowledged anything — total starvation produced by the rule that exists
    /// to prevent starvation. The all-equal set is asserted alongside it because
    /// it takes the same fallback and a length check alone would miss it.
    #[test]
    fn the_sole_candidate_wins_even_as_the_previous_winner() {
        assert_eq!(
            pick_next([("solo", NOW - 1_000)], NOW, GIVE_UP_MS, Some(&"solo")),
            Some("solo"),
            "one conversation must never be starved by the anti-starvation rule"
        );

        assert_eq!(
            pick_next(
                [("solo", NOW - 1_000), ("solo", NOW - 9_000)],
                NOW,
                GIVE_UP_MS,
                Some(&"solo")
            ),
            Some("solo"),
            "a set holding nothing but the previous winner falls back to it too"
        );
    }

    /// Skipping applies only to the candidate that actually won last round.
    #[test]
    fn a_previous_winner_that_is_not_oldest_changes_nothing() {
        let candidates = [("alice", NOW - 9_000), ("bob", NOW - 1_000)];
        assert_eq!(
            pick_next(candidates, NOW, GIVE_UP_MS, Some(&"bob")),
            Some("alice"),
            "alice is oldest and is not the previous winner, so she wins outright"
        );
    }

    /// **The property both bounds exist for**: a conversation parked on the floor
    /// takes at most half the allowance rather than all of it.
    ///
    /// Ten rounds of a caller doing what the real one will — remember the winner,
    /// pass it back — against an attacker who always claims the oldest possible
    /// time. Both the share *and* the alternation are asserted: a share of five
    /// alone would also be satisfied by an implementation that gave the attacker
    /// the first five rounds and then stopped, which is a different and worse
    /// behaviour.
    #[test]
    fn a_floor_parked_attacker_takes_at_most_half_the_rounds() {
        let floor_ms = NOW - GIVE_UP_MS;
        let candidates = [
            ("attacker", floor_ms),
            ("honest_a", NOW - 60_000),
            ("honest_b", NOW - 30_000),
        ];

        let mut last: Option<&'static str> = None;
        let mut winners = Vec::new();
        for _ in 0..10 {
            let winner = pick_next(candidates, NOW, GIVE_UP_MS, last.as_ref())
                .expect("the set is never empty");
            winners.push(winner);
            last = Some(winner);
        }

        let attacker_rounds = winners.iter().filter(|w| **w == "attacker").count();
        assert_eq!(
            attacker_rounds, 5,
            "at most every other round, which is half of ten"
        );
        assert!(
            winners.windows(2).all(|w| w[0] != w[1]),
            "and never two in a row, which is the mechanism producing the half"
        );
        assert!(
            winners.contains(&"honest_a"),
            "an honest conversation must actually receive rounds; without this the \
             test would pass against a limiter that alternated two attackers"
        );
    }

    /// Draining a set one winner at a time hands the allowance out oldest-first,
    /// all the way down.
    ///
    /// `last_picked` is `None` throughout because each winner leaves the set, so
    /// no candidate can repeat and the skip has nothing to do — this pins the
    /// underlying ordering with the bound out of the way. A single-pick test
    /// cannot see a comparator that is right once and wrong on the remainder.
    #[test]
    fn draining_the_set_hands_the_allowance_out_oldest_first() {
        let mut remaining = vec![
            ("alice", NOW - 5_000),
            ("bob", NOW - 9_000),
            ("carol", NOW - 1_000),
            ("dave", NOW - 7_000),
        ];
        let mut order = Vec::new();

        while let Some(winner) = pick_next(
            remaining.iter().map(|&(name, sent)| (name, sent)),
            NOW,
            GIVE_UP_MS,
            None,
        ) {
            order.push(winner);
            remaining.retain(|&(name, _)| name != winner);
        }

        assert_eq!(order, vec!["bob", "dave", "alice", "carol"]);
    }
}
