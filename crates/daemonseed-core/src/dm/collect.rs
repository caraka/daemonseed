//! Collecting a conversation's inbound messages: the two pointers, and the
//! cadence that drives the sweep (#236, part of ISC-C42).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § v5 (erasure-MAJOR — speculative contiguous probing), § v6 (erasure F1 — the
//! probe frontier is distinct from the contiguous cursor; erasure F2 — the
//! beyond-prefix set), and the appended build notes.
//!
//! This is the pure half of collection. It holds page numbers, slot indices and
//! a clock value the caller passes in. It opens no frame, reads no record,
//! derives no key and starts no timer: the transport slice owns the sweep, the
//! watches and the wall clock.
//!
//! ## Two pointers, and neither is derived from the other
//!
//! The **probe frontier** ([`Collection::frontier_page`]) is how far ahead pages
//! have been reached. It advances on a page holding *any* populated slot, and
//! **not** on a page being full — the initiator's very first page has a
//! permanently empty first slot, because its sequence zero is the first-contact
//! entry and that travels by doorbell
//! ([`crate::dm::ratchet::FIRST_INITIATOR_CHANNEL_SEQ`]).
//!
//! The **contiguous cursor** ([`Collection::contiguous_through`]) is how far the
//! unbroken prefix runs, and it is what the delivery acknowledgement reports.
//! One message that is never recoverable holds it in place forever, by design.
//!
//! Anchoring the frontier to the cursor collapses them, and one permanently lost
//! message then stalls the whole rest of the conversation — the failure § v6
//! erasure F1 exists to close. So the frontier here is a **page number advanced
//! by observation**, never a function of a sequence number, and
//! [`crate::dm::paging::position_of`] is used only on the cursor side.
//!
//! The cursor does **floor** the frontier, and a floor is not an anchor. Settling
//! a position lifts the frontier to that position's page if the cursor has run
//! past it, and never pulls it back — so a frontier that has already run past a
//! permanent gap is untouched and the pointers stay distinct, while a page whose
//! sixteen slots are all unavailable stops being terminal: the give-up settles
//! them, the cursor crosses the page, and the frontier follows. The private
//! `Collection::floor_frontier_at_cursor` carries the argument in full.
//!
//! ## The cursor is the acknowledgement's, not a second copy of it
//!
//! A [`Collection`] owns an [`AckState`] rather than keeping a cursor beside one.
//! That type already holds exactly this shape — a contiguous prefix plus a
//! bounded set of settled positions beyond it — with the monotonicity, the run
//! cap and the give-up rule the acknowledgement needs. A second cursor would be
//! a second answer to the same question, free to disagree with the one that goes
//! on the wire.
//!
//! It carries that type's meaning with it, unchanged: the prefix is **settled**,
//! not collected. [`Collection::abandoned`] settles a position the sender gave up
//! on at the seven-day give-up, and nothing in this module can tell that apart
//! from a collected one afterwards. See [`crate::dm::ack`]'s module docs.
//!
//! Which position that is, this side decides for itself:
//! [`Collection::sweep_give_ups`] abandons a gap that has stood for
//! [`RECEIVE_GIVE_UP_MS`], accumulated across the sweeps the caller runs rather
//! than read off the wall clock. Nothing on the wire says a sender gave up, and
//! without this a single unrecoverable position holds a run of the
//! acknowledgement for the life of the conversation.
//!
//! ## Where the frame check sits, and why it is not here
//!
//! A frame declares its own sequence number and the slot it was found in implies
//! one; they must agree. That check is
//! [`crate::dm::frame::ParsedFrame::open`]'s `found_at` argument, one layer
//! above — it needs the parsed frame, and this module never parses one.
//!
//! What this module contributes to the same chain is the *other* half:
//! [`Collection::observe_page`] turns a swept `(page, slot)` into a
//! [`PagePosition`] through the checked constructor, so a slot the record cannot
//! have is rejected at the point of the mistake rather than aliasing another
//! page's sequence numbers; and [`Collection::collected`] takes that same
//! `PagePosition` rather than a bare `u64`, so the position a message was
//! *filed at* is the position it is *acknowledged at*, with no re-derivation
//! between them.
//!
//! ## The cadence is an argument
//!
//! [`Collection::probe_plan`] takes the current time in milliseconds and returns
//! the pages to sweep, or `None` when the interval has not elapsed. Nothing here
//! reads a clock, for the reason `daemonseed-veilid-net`'s `route_budget`
//! controller states about its own injected observations: a value passed in is
//! deterministically testable and a timer is not.
//!
//! ## What this module does not hold
//!
//! No persistence, no restore path, no transport, no contact cache, no block
//! list, and no notion of a conversation identity — a [`Collection`] is about one
//! direction of one conversation and knows nothing that would name it.
//!
//! **The store is no longer an open question, only an unconnected one.** That
//! store holds five fixed records per correspondence — resume state, provisional
//! handshake state, the outbox, the receive cursor and the contact cache — plus
//! the profile's block list; never a message archive.
//! [`crate::storage::dm_store`] exists, and a collection's cursor has a record
//! kind waiting for it — [`RecordKind::ReceiveCursor`](crate::storage::dm_store::RecordKind::ReceiveCursor),
//! written through [`DmPersist::advance_cursor`](crate::dm::persist::DmPersist::advance_cursor).
//! Nothing here calls it: what is missing is the wiring, not the decision.

use std::ops::RangeInclusive;

use crate::dm::ack::{AckError, AckState};
use crate::dm::outbox::{GIVE_UP, RESEED_LADDER};
use crate::dm::paging::{MAX_PAGE, PagePosition, position_of};

/// How long between probe cadences, in milliseconds.
///
/// **A policy choice; the frozen design specifies a cadence but names no
/// interval.** The probe is a read, so it sits outside the WB-2 write ceiling
/// decision #4 closes against, and it is a *backstop*: the watch on the current
/// and next page ([`Collection::watched`]) is the path a message normally
/// arrives by, and this catches what a missed or evicted watch dropped. Thirty
/// seconds is therefore chosen against sweep load and the shared op-gate rather
/// than against message latency, and it is the number a manual test would tune.
pub const PROBE_INTERVAL_MS: u64 = 30_000;

/// How many pages holding a hole one probe plan re-reads.
///
/// The plan always carries the current and next page; this bounds the *backfill*
/// beyond them, and is counted against those backfill entries alone. Unbounded
/// backfill would make a gappy conversation's every probe proportional to its
/// gap count, against a shared 16-permit op-gate and a per-record resweep
/// latency (#171) that the whole client competes for.
///
/// Two, with the oldest hole first, because the oldest hole is the one holding
/// the contiguous cursor — every later one is already reported past by the
/// beyond-prefix set (§ v6 erasure F2), so it costs confirmation latency and
/// nothing else.
///
/// A hole qualifies whether or not a settled position witnesses it: the pages
/// from the cursor up to the frontier are candidates on their own, because
/// [`Collection::outstanding`] reports only what sits below the highest settled
/// position and a page whose every frame failed to open settles nothing.
pub const MAX_BACKFILL_PAGES: usize = 2;

/// How wide the watched window is — how many pages [`Collection::watched`] names.
///
/// Two: the current page and the next one, for the speculative-contiguous reason
/// that method states. It is the **return type's own length**, so a caller
/// reasoning about how many page records a settled conversation keeps open reads
/// the same number the window is built from rather than a copy of it.
pub const WATCHED_PAGES: usize = 2;

/// The longest interval [`RESEED_LADDER`] ever waits between two re-seeds of
/// one message, in milliseconds.
///
/// Read from the ladder rather than written down, and read as a **maximum**
/// rather than as a position in it, so a rung added or reordered later moves
/// this rather than silently leaving it short.
const fn longest_reseed_interval_ms() -> u64 {
    let mut longest = 0u128;
    let mut rung = 0;
    while rung < RESEED_LADDER.len() {
        let interval = RESEED_LADDER[rung].as_millis();
        if interval > longest {
            longest = interval;
        }
        rung += 1;
    }
    longest as u64
}

/// How long a position may stay missing below the highest settled one before the
/// receiving side gives up on it, in milliseconds.
///
/// The sender's [`GIVE_UP`] plus one re-seed interval. The first term is the
/// point past which no copy of the message will be published again, so waiting
/// longer than it cannot recover anything; the margin covers the interval
/// between the sender's last re-seed and its give-up, during which a copy is
/// still on its way and the receiver would otherwise abandon a position it is
/// about to collect.
///
/// **It is the receiver's own clock throughout.** Nothing on the wire says a
/// sender gave up — an acknowledgement carries the receiver's own prefix and
/// runs, and nothing travels the other way — so this is measured from when the
/// gap was first observed here, and the margin is what makes that measurement
/// safe against the two clocks not agreeing to the millisecond.
pub const RECEIVE_GIVE_UP_MS: u64 = GIVE_UP.as_millis() as u64 + longest_reseed_interval_ms();

/// The most one call to [`Collection::sweep_give_ups`] may add to a gap's age,
/// in milliseconds.
///
/// A gap's age is **accumulated** across calls rather than measured from an
/// absolute origin, and this is what makes that worth doing. A host clock that
/// steps forward — a bad real-time clock corrected on the first successful time
/// sync — would otherwise age every standing gap by the size of the step in a
/// single call and abandon positions the sender is still re-seeding. That
/// failure is silent and permanent: an abandoned position is settled, and
/// [`Collection::observe_page`] filters settled positions out of what it offers,
/// so a copy still sitting on the page record is never opened. Capping one
/// call's contribution to a few cadences absorbs the step instead of believing
/// it, and costs a delay of at most the step in the case where the clock was
/// right.
///
/// Four cadences, so a caller that misses two or three in a row still ages a gap
/// at close to real time.
pub const AGE_STEP_CAP_MS: u64 = 4 * PROBE_INTERVAL_MS;

/// Anything that can go wrong folding a swept page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectError {
    /// The sweep reported a slot this record cannot have — a page opened under a
    /// shape that disagrees with [`crate::dm::paging::PAGE_SLOTS`], so every
    /// position it yields belongs to some other page.
    ///
    /// **The slot is the fault here, and the page is context.** A page too high
    /// to hold any position at all is
    /// [`CollectError::PageBeyondSequenceSpace`]; the two are separate because a
    /// single variant would report a perfectly legal slot as the culprit and
    /// send a reader looking at the record shape when the page number is what
    /// went wrong.
    SlotOutsideRecord {
        /// The page the sweep was of.
        page: u64,
        /// The slot index it reported.
        slot: u16,
    },
    /// The sweep was of a page above [`MAX_PAGE`], which holds no position
    /// whatever slot is named, because `page * PAGE_SLOTS + slot` leaves the
    /// sequence space.
    ///
    /// **The page is the fault, not the slot.** Reported before any slot is
    /// looked at, so the answer does not depend on what the sweep happened to
    /// find.
    PageBeyondSequenceSpace {
        /// The page the sweep was of.
        page: u64,
    },
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlotOutsideRecord { page, slot } => {
                write!(f, "slot {slot} is outside page {page}'s record")
            }
            Self::PageBeyondSequenceSpace { page } => write!(
                f,
                "page {page} is above the highest page a sequence number can live on ({MAX_PAGE})"
            ),
        }
    }
}

impl std::error::Error for CollectError {}

/// What folding one swept page yielded.
#[must_use]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageObservation {
    /// The populated positions this collection has not settled, ascending and
    /// deduplicated — what the caller opens.
    ///
    /// Positions already settled are filtered out. Re-seeding makes a page
    /// return bytes for positions already collected as ordinary traffic, and a
    /// message key is used once — re-presenting an opened frame to the ratchet
    /// is [`crate::dm::ratchet::RatchetError::AlreadyConsumed`], not a second
    /// copy of the message. A position settled by
    /// [`Collection::abandoned`] is filtered on the same terms, so bytes that
    /// arrive after a give-up are not offered.
    pub unsettled: Vec<PagePosition>,
    /// Whether this page moved the probe frontier.
    pub frontier_advanced: bool,
}

/// The collection state a UI reads: plain data, no borrows, no behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionView {
    /// The contiguous cursor — every position from zero up to it is settled.
    /// `None` when none is.
    ///
    /// **Settled, not collected**: [`Collection::abandoned`] advances it past a
    /// position that was never received.
    pub contiguous_through: Option<u64>,
    /// The probe frontier — the highest page observed holding a populated slot.
    /// `None` before any page has been observed holding one.
    pub frontier_page: Option<u64>,
    /// The unsettled positions below the highest settled one, as inclusive
    /// ranges, ascending.
    ///
    /// Ranges rather than positions because a hole can span pages, and the
    /// number of ranges is bounded by [`crate::dm::ack::MAX_ACK_RUNS`] while the
    /// number of positions is not.
    pub outstanding: Vec<RangeInclusive<u64>>,
}

/// One direction of one conversation, being collected.
#[derive(Clone, Debug, Default)]
pub struct Collection {
    /// The contiguous cursor and the settled set beyond it.
    ack: AckState,
    /// The probe frontier: the highest page observed holding a populated slot.
    frontier: Option<u64>,
    /// When [`Collection::probe_plan`] last handed out a plan.
    last_probe_ms: Option<u64>,
    /// How long each outstanding gap has been observed to stand.
    ///
    /// Rebuilt against [`Self::outstanding`] on every sweep, one entry per gap,
    /// so it is bounded by [`crate::dm::ack::MAX_ACK_RUNS`] exactly as the run
    /// set is and cannot accumulate entries for gaps that have closed.
    ///
    /// **Not persisted, because there is nothing to persist it beside.** The
    /// record a collection resumes from names a page and no settled set at all
    /// ([`Self::resuming_from_page`]), so a resumed collection has no gaps until
    /// it settles something after the restart, and an age carried across would
    /// belong to a gap this collection no longer knows it has. What a restart
    /// costs is therefore the age of any gap standing at the time, which is
    /// bounded by [`RECEIVE_GIVE_UP_MS`] and never by the life of the
    /// conversation.
    gap_ages: Vec<GapAge>,
}

/// How long one outstanding gap has stood, carried across sweeps.
#[derive(Clone, Debug)]
struct GapAge {
    /// The positions the gap covered when this entry was last rebuilt.
    ///
    /// **The gap is identified by the whole range, not by an endpoint.** Both
    /// endpoints move: collecting the gap's first position raises its start, and
    /// collecting inside it splits it in two. An entry keyed on an endpoint is
    /// therefore dropped as soon as that endpoint moves, and the gap's age
    /// restarts — so a gap being filled one position per sweep from either side
    /// would never age out at all, which is the case the horizon most needs to
    /// cover.
    range: RangeInclusive<u64>,
    /// The accumulated age, in milliseconds.
    age_ms: u64,
    /// The clock value the sweep that last touched this entry was given.
    last_seen_ms: u64,
}

/// Do two inclusive ranges share at least one position?
fn ranges_overlap(a: &RangeInclusive<u64>, b: &RangeInclusive<u64>) -> bool {
    a.start() <= b.end() && b.start() <= a.end()
}

impl Collection {
    /// A collection that has reached no page and settled no position.
    pub fn new() -> Self {
        Self::default()
    }

    /// A collection whose probe starts at the page a persisted
    /// [`ReceiveCursor`](crate::dm::provisional::ReceiveCursor) named, rather
    /// than at page zero.
    ///
    /// **The frontier is restored; the settled set is not, and the asymmetry is
    /// the record's, not a shortcut here.** The cursor is eight bytes naming a
    /// page — that is the whole of what survives a restart — so nothing on disk
    /// can say which positions inside that page were collected. A caller
    /// therefore resumes with an empty [`Self::ack`] and a frontier already at the
    /// page the cursor named, and the acknowledgement rebuilds from the first
    /// position settled after the restart rather than claiming a prefix it cannot
    /// vouch for. Under-claiming is the fail-safe direction — the sender re-seeds
    /// a message that was in fact read, which costs a round trip and never
    /// reports a message delivered that was not.
    ///
    /// **The limit this leaves is not a slow rescan, it is re-delivery, and a
    /// caller must close it before resuming a live collection.** With the
    /// frontier restored and nothing settled, [`Self::probe_plan`] backfills
    /// from page zero and [`Self::observe_page`] reports every position it finds
    /// there as unsettled — including ones this profile already collected and
    /// showed. A caller that opens and displays whatever `unsettled` names would
    /// show the user old messages as new, which ISC-A-C21 forbids. Nothing in
    /// this type can prevent that: the record it resumes from names a page and
    /// not a set, so the knowledge simply is not there. What closes it is a
    /// message log the caller consults before displaying, or a settled set that
    /// survives the restart alongside the cursor.
    ///
    /// A resumed correspondence reaches it only through a consumed
    /// re-establishment leg, which settles its position with no key schedule and
    /// so does not display anything; every other position stays unopenable until
    /// one is installed.
    ///
    /// `page` above [`MAX_PAGE`] yields [`Self::new`], because such a page holds
    /// no position and a probe started there would never find a message. The
    /// cursor's own constructors refuse that value, so this arm is reachable only
    /// by a caller passing a bare number.
    pub fn resuming_from_page(page: u64) -> Self {
        Self {
            ack: AckState::new(),
            frontier: (page <= MAX_PAGE).then_some(page),
            last_probe_ms: None,
            gap_ages: Vec::new(),
        }
    }

    /// Fold one swept page: `page`, and the slot indices that came back holding
    /// bytes.
    ///
    /// The frontier advances when the page holds **any** populated slot and sits
    /// above the frontier — never on the page being full, and never backwards,
    /// so a late sweep of an older page cannot pull it back over ground already
    /// reached.
    ///
    /// `populated` may arrive in any order and may repeat; the returned
    /// positions are ascending and deduplicated. A slot outside the record
    /// returns [`CollectError::SlotOutsideRecord`], and a `page` above
    /// [`MAX_PAGE`] returns [`CollectError::PageBeyondSequenceSpace`]; either
    /// **leaves this collection exactly as it was** — the page was opened under
    /// the wrong shape, or is not a page any position lives on, so nothing it
    /// reported is about the page that was asked for.
    ///
    /// The page bound is checked **before any slot**, so a page that holds no
    /// position is named as the fault whether or not the sweep found bytes in
    /// it.
    pub fn observe_page(
        &mut self,
        page: u64,
        populated: &[u16],
    ) -> Result<PageObservation, CollectError> {
        if page > MAX_PAGE {
            return Err(CollectError::PageBeyondSequenceSpace { page });
        }

        let mut slots: Vec<u16> = populated.to_vec();
        slots.sort_unstable();
        slots.dedup();

        let mut unsettled = Vec::with_capacity(slots.len());
        for slot in slots {
            let at = PagePosition::new(page, slot)
                .ok_or(CollectError::SlotOutsideRecord { page, slot })?;
            if !self.ack.is_settled(at.seq()) {
                unsettled.push(at);
            }
        }

        let frontier_advanced = !populated.is_empty() && self.frontier.is_none_or(|f| page > f);
        if frontier_advanced {
            self.frontier = Some(page);
        }

        Ok(PageObservation {
            unsettled,
            frontier_advanced,
        })
    }

    /// Record that the message at this position was collected — it arrived,
    /// opened and verified.
    ///
    /// Takes the [`PagePosition`] rather than a sequence number so the position
    /// a frame was checked against is the position it is acknowledged at, with
    /// no arithmetic in between.
    ///
    /// Idempotent, and refuses with [`AckError::TooManyRuns`] when the
    /// beyond-prefix set is full, leaving the state unchanged. That refusal does
    /// not un-collect anything — the message is opened and displayable — but
    /// **the acknowledgement of it is dropped here, not queued**. Nothing in
    /// this type retains a refused position, and re-offering it is not a
    /// recovery: [`Self::observe_page`] keeps listing it as unsettled, but its
    /// message key is already consumed, so opening the frame a second time is
    /// [`crate::dm::ratchet::RatchetError::AlreadyConsumed`] rather than a
    /// second copy of the message.
    ///
    /// **So a caller that wants the position acknowledged must retain it
    /// itself** and call this again once a closing gap or the give-up rule has
    /// freed capacity. A caller that discards it leaves the sender re-seeding to
    /// the seven-day give-up and reporting *undelivered* for a message that was
    /// in fact read — the fail-safe direction, and a real cost. See
    /// [`crate::dm::ack::MAX_ACK_RUNS`].
    pub fn collected(&mut self, at: PagePosition) -> Result<(), AckError> {
        self.ack.collect(at.seq())?;
        self.floor_frontier_at_cursor();
        Ok(())
    }

    /// Record that this sequence number will never be collected, because the
    /// sender has stopped re-seeding it at the seven-day give-up.
    ///
    /// Takes a bare sequence number rather than a [`PagePosition`], because a
    /// give-up names a message that never arrived — there is no slot it was
    /// found in.
    ///
    /// [`Self::sweep_give_ups`] is what calls this on the receiving side, on
    /// this side's own clock; a caller with some other reason to settle a
    /// position it will never receive may call it directly.
    ///
    /// **This settles the position**: it leaves
    /// [`Self::outstanding`] and the cursor advances over it, exactly as if it
    /// had been collected. Nothing after this can tell the two apart. See
    /// [`AckState::abandon`].
    ///
    /// It also lifts the frontier to the cursor's page if the cursor has run
    /// past it — a floor, never an anchor — which is what makes the give-up able
    /// to free a direction stalled on a wholly-lost page. See the module docs.
    pub fn abandoned(&mut self, seq: u64) -> Result<(), AckError> {
        self.ack.abandon(seq)?;
        self.floor_frontier_at_cursor();
        Ok(())
    }

    /// The pages to hold under a watch: the current page and the next one.
    ///
    /// Clock-free and cadence-free — a watch is standing, not periodic. The
    /// current page is the frontier, or page zero before any page has been
    /// reached.
    pub fn watched(&self) -> [u64; WATCHED_PAGES] {
        let current = self.frontier.unwrap_or(0);
        [current, current.saturating_add(1)]
    }

    /// The lowest page any future plan of this collection can still name: every
    /// page strictly below it is settled through **and** out of the watched
    /// window, so nothing here will ever ask for it again.
    ///
    /// Both halves are needed and neither implies the other. A page can be fully
    /// settled and still be the watched current page — the cursor reaching the
    /// last position of page `p` leaves the frontier at `p`, which
    /// [`Self::watched`] still holds — and a page can be below the frontier while
    /// [`Self::outstanding`] or the cursor-to-frontier span still name it as
    /// backfill. Taking the lower of the two is what makes this an answer about
    /// [`Self::probe_plan`] rather than about either pointer alone: a hole
    /// witnessed or unwitnessed lives at or above the first unsettled position,
    /// and the watched pair lives at or above the frontier.
    ///
    /// **A permanent hole pins this number for one horizon, and the receiver's
    /// own clock is what lifts it.** The prefix-advance-on-give-up rule the
    /// design states for the receiver — *"the receiver advances its contiguous
    /// cursor past a message the sender has abandoned at the 7-day give-up"* —
    /// reads as needing a signal that the sender gave up, and the wire carries
    /// none: an acknowledgement record and a frame's piggyback both carry only
    /// `high_water` and the beyond-prefix runs, which is the RECEIVER's
    /// statement about the sender's direction, and nothing travels the other way
    /// saying *I abandoned this position*. What replaces the signal is a
    /// measurement — [`Self::sweep_give_ups`] abandons a gap that has stayed
    /// missing for [`RECEIVE_GIVE_UP_MS`] — so a position that is never
    /// recoverable holds this number at its page for that horizon rather than
    /// for the life of the conversation, and its pages are released after it
    /// instead of by the transport's own capacity bound.
    ///
    /// **What a caller may do with it, and what it costs.** A transport holding
    /// one open record per page may release every page below this number. That
    /// release is not permanent: nothing here forbids the frontier or a later
    /// probe plan naming such a page again — an out-of-order arrival cannot,
    /// since the positions are settled, but a *restart* re-derives a collection
    /// from its stored cursor and probes from there. A released page named again
    /// is simply opened again by the ordinary open path, at the cost of one open.
    /// That cost is the accepted price of a bounded handle count; see
    /// `daemonseed-veilid-net`'s page-close path.
    pub fn retired_below(&self) -> u64 {
        self.watched()[0].min(self.ack.settled_pages_below())
    }

    /// The pages to sweep now, or `None` when the cadence has not elapsed.
    ///
    /// The plan is [`Self::watched`] followed by up to [`MAX_BACKFILL_PAGES`]
    /// pages holding a hole, oldest first, deduplicated: the pages
    /// [`Self::outstanding`] witnesses, then the pages from the cursor up to the
    /// frontier, which carry a hole whether or not anything settled above
    /// witnesses one. The next page is probed **regardless of the current page's
    /// fill state** —
    /// that is the whole of § v5's speculative contiguous probing, and it is why
    /// a page with one populated slot out of sixteen does not hold the sweep at
    /// that page.
    ///
    /// The clock is a `u64` of milliseconds from any epoch the caller likes,
    /// since only differences are read. A `now_ms` **below** the last one is
    /// treated as due rather than as a negative interval: a clock that stepped
    /// backwards must not park the probe for the size of the step.
    ///
    /// Calling this records the plan as issued, so it is `&mut self` and a
    /// second call inside the interval returns `None`.
    pub fn probe_plan(&mut self, now_ms: u64) -> Option<Vec<u64>> {
        if !self.probe_due(now_ms) {
            return None;
        }
        self.last_probe_ms = Some(now_ms);
        Some(self.pages_to_probe())
    }

    /// Give up on every gap that has stood longer than [`RECEIVE_GIVE_UP_MS`],
    /// and return the positions abandoned, ascending.
    ///
    /// **The age is accumulated, not measured from an origin.** Each call adds
    /// the time since the last one, capped at [`AGE_STEP_CAP_MS`], to every gap
    /// standing at both ends of that interval; a gap seen for the first time
    /// starts at zero, so the first call after a gap opens can abandon nothing.
    /// The cap is what a clock that steps forward runs into — see
    /// [`AGE_STEP_CAP_MS`], which carries that argument in full — and it makes
    /// this a count of observed cadences rather than a reading of the wall
    /// clock. A `now_ms` below the last one adds nothing at all.
    ///
    /// **The caller chooses the cadence.** Nothing here schedules anything, and
    /// the cap means calling this more often than the probe interval costs
    /// nothing but is not required either: what a caller must not do is let its
    /// own gaps between calls run far past the cap, which slows the horizon down
    /// in proportion.
    ///
    /// **A gap is identified by its whole range, and inherits the largest age
    /// among the entries it overlaps.** A gap that shrinks from below and a gap
    /// that a collected position splits in two are both the same gap continuing,
    /// so both halves keep the age the whole had; two gaps can never merge,
    /// because a settled position never becomes unsettled, so an inherited age
    /// never belongs to a longer-standing gap than the one it is inherited from.
    ///
    /// **What this settles was never received**, on exactly the terms
    /// [`Self::abandoned`] states: the cursor advances over it, the runs above
    /// it fold into the prefix, and nothing afterwards can tell an abandoned
    /// position from a collected one. That is the point — the acknowledgement
    /// carries a bounded number of runs ([`crate::dm::ack::MAX_ACK_RUNS`]), and
    /// a permanently lost position that is never settled holds one of them for
    /// the life of the conversation, so an unbounded number of losses eventually
    /// refuses every new collection and reports a live conversation as
    /// undelivered.
    ///
    /// A gap that has aged out is abandoned **whole**: it is one hole of one
    /// conversation and its positions are equally unrecoverable, so leaving part
    /// of it would keep the run the give-up exists to release. The positions go
    /// ascending from the gap's first, so each one extends the prefix or the run
    /// below it and none opens a new run; a refusal from the run set therefore
    /// cannot come from this ordering, and if one arrives anyway the sweep stops
    /// there, leaving what it has already settled settled and the rest for the
    /// next call.
    pub fn sweep_give_ups(&mut self, now_ms: u64) -> Vec<u64> {
        self.accumulate_gap_ages(now_ms);

        let due: Vec<RangeInclusive<u64>> = self
            .gap_ages
            .iter()
            .filter(|entry| entry.age_ms >= RECEIVE_GIVE_UP_MS)
            .map(|entry| entry.range.clone())
            .collect();

        let mut abandoned = Vec::new();
        'gaps: for range in due {
            for seq in range {
                if self.abandoned(seq).is_err() {
                    break 'gaps;
                }
                abandoned.push(seq);
            }
        }

        // Rebuilt against what stands now, so an entry never outlives the gap it
        // describes however the loop above ended. The second pass adds nothing:
        // it is called with the clock value the first pass already advanced the
        // ages to.
        if !abandoned.is_empty() {
            self.accumulate_gap_ages(now_ms);
        }
        abandoned
    }

    /// The contiguous cursor. **Settled, not collected** — see
    /// [`CollectionView::contiguous_through`].
    pub fn contiguous_through(&self) -> Option<u64> {
        self.ack.high_water()
    }

    /// The probe frontier: the highest page observed holding a populated slot.
    pub fn frontier_page(&self) -> Option<u64> {
        self.frontier
    }

    /// The unsettled positions below the highest settled one, as ascending
    /// inclusive ranges.
    ///
    /// Empty for a conversation collecting in order, and empty above the highest
    /// settled position — a position nothing has ever been settled past is not
    /// *missing*, it is simply not here yet.
    ///
    /// Below it, every unsettled position is genuinely missing rather than
    /// merely unread: a direction's sequence numbers are contiguous, so a
    /// settled position is proof that every position under it was written.
    pub fn outstanding(&self) -> Vec<RangeInclusive<u64>> {
        let mut lo = match self.ack.high_water() {
            Some(h) => match h.checked_add(1) {
                Some(next) => next,
                // The prefix covers the whole sequence space; nothing is above it.
                None => return Vec::new(),
            },
            None => 0,
        };

        let mut gaps = Vec::new();
        for run in self.ack.beyond_runs() {
            if *run.start() > lo {
                gaps.push(lo..=*run.start() - 1);
            }
            // A run's end is below the next run's start by at least two, so this
            // cannot overflow while another run follows; the value is unused
            // after the last one.
            lo = run.end().saturating_add(1);
        }
        gaps
    }

    /// The acknowledgement this collection has built, for the transport slice to
    /// encode, sign and publish.
    ///
    /// Read-only: every mutation goes through [`Self::collected`] or
    /// [`Self::abandoned`], so the cursor a UI reads and the cursor on the wire
    /// are the same one.
    pub fn ack(&self) -> &AckState {
        &self.ack
    }

    /// The whole readable state in one owned value.
    pub fn view(&self) -> CollectionView {
        CollectionView {
            contiguous_through: self.contiguous_through(),
            frontier_page: self.frontier,
            outstanding: self.outstanding(),
        }
    }

    /// Lift the frontier to the page holding the contiguous cursor, if the
    /// cursor has run past it.
    ///
    /// **A floor, not an anchor, and the distinction is the whole of § v6
    /// erasure F1.** F1 forbids the frontier being a *function of* the cursor:
    /// under that shape one permanently lost message pins the frontier at the
    /// gap and stalls the rest of the conversation forever. A lower bound is a
    /// different thing — it never pulls the frontier back, so a frontier that has
    /// already run past a permanent gap is untouched and the two pointers stay
    /// exactly as distinct as F1 requires. A reader who takes this for the defect
    /// F1 names is reading an anchor; the `never_pulls_it_back` test is the
    /// difference, pinned.
    ///
    /// **Why it has to exist.** The give-up rule is the design's own bound on
    /// permanent loss, and without this it cannot lift a stalled frontier. A page
    /// whose sixteen slots are all unavailable never advances the frontier, so
    /// the plan is `[p, p + 1]` forever; [`Self::abandoned`] settles that page's
    /// positions and the cursor advances over them, but `abandon` is `settle` and
    /// touches no page number, [`Self::outstanding`] is then empty, and nothing
    /// else in this type would ever move. One wholly-lost page would end the
    /// direction permanently — the failure the give-up exists to bound, caused
    /// by it.
    fn floor_frontier_at_cursor(&mut self) {
        let Some(high) = self.ack.high_water() else {
            return;
        };
        let page = position_of(high).page();
        if self.frontier.is_none_or(|f| page > f) {
            self.frontier = Some(page);
        }
    }

    /// Rebuild the gap ages against the gaps standing now, advancing each by the
    /// capped time since it was last seen.
    ///
    /// Rebuilding rather than editing in place is what bounds the list: the
    /// entries are exactly the current gaps, so nothing a closed gap left behind
    /// can be inherited by a gap that opens over the same positions later. The
    /// cost is one pass over the current gaps against the previous entries, both
    /// bounded by [`crate::dm::ack::MAX_ACK_RUNS`].
    fn accumulate_gap_ages(&mut self, now_ms: u64) {
        let gaps = self.outstanding();
        let mut rebuilt: Vec<GapAge> = Vec::with_capacity(gaps.len());
        for range in gaps {
            let inherited = self
                .gap_ages
                .iter()
                .filter(|entry| ranges_overlap(&entry.range, &range))
                .max_by_key(|entry| entry.age_ms);
            let age_ms = match inherited {
                Some(entry) => entry.age_ms.saturating_add(
                    now_ms
                        .saturating_sub(entry.last_seen_ms)
                        .min(AGE_STEP_CAP_MS),
                ),
                None => 0,
            };
            rebuilt.push(GapAge {
                range,
                age_ms,
                last_seen_ms: now_ms,
            });
        }
        self.gap_ages = rebuilt;
    }

    /// How many gap ages this collection is carrying, for this module's own
    /// tests.
    ///
    /// The list is bounded by being rebuilt from [`Self::outstanding`], and a
    /// bound nothing can read is a bound nothing can pin.
    #[cfg(test)]
    fn tracked_gaps(&self) -> usize {
        self.gap_ages.len()
    }

    /// The pages the contiguous cursor could still be held by: from the page of
    /// the first unsettled position up to the frontier, inclusive. `None` when
    /// the cursor has caught up with the frontier.
    ///
    /// Every page in it carries a hole that is genuinely **missing** rather than
    /// merely not-here-yet, and that is what makes it a backfill candidate
    /// without a settled position to witness it: a direction's sequence numbers
    /// are contiguous, so content observed at the frontier is proof that every
    /// position below it was written.
    ///
    /// [`Self::outstanding`] cannot see these. It reports the holes *below the
    /// highest settled position*, so a page whose every frame failed to open —
    /// the expected answer when the ephemeral-introducing frame is among the
    /// missing ones — settles nothing, witnesses nothing, and drops out of every
    /// plan the moment the frontier moves past it.
    fn unsettled_span(&self) -> Option<RangeInclusive<u64>> {
        let first_unsettled = match self.ack.high_water() {
            // `?` on the overflow: a prefix covering the whole sequence space
            // leaves nothing unsettled anywhere.
            Some(h) => h.checked_add(1)?,
            None => 0,
        };
        let lo = position_of(first_unsettled).page();
        match self.frontier {
            Some(f) if lo <= f => Some(lo..=f),
            // Above the frontier the watched pair already covers it, and nothing
            // below has been reached.
            _ => None,
        }
    }

    /// Has the probe interval elapsed?
    fn probe_due(&self, now_ms: u64) -> bool {
        match self.last_probe_ms {
            None => true,
            Some(last) => now_ms < last || now_ms - last >= PROBE_INTERVAL_MS,
        }
    }

    /// The watched pair, then the oldest pages holding a hole, bounded.
    ///
    /// The bound is counted against the **backfill entries alone**, which is what
    /// [`MAX_BACKFILL_PAGES`] documents. Counting whole-plan length instead ties
    /// the backfill's size to the watched pair being two *distinct* pages, and
    /// that is an invariant of [`Self::watched`] rather than of anything here.
    fn pages_to_probe(&self) -> Vec<u64> {
        let mut pages: Vec<u64> = Vec::with_capacity(2 + MAX_BACKFILL_PAGES);
        for page in self.watched() {
            if !pages.contains(&page) {
                pages.push(page);
            }
        }

        let mut backfill = 0usize;

        // Witnessed holes first, oldest first: a settled position above a hole
        // proves it, and the oldest is the one holding the cursor.
        'gaps: for gap in self.outstanding() {
            let first = position_of(*gap.start()).page();
            let last = position_of(*gap.end()).page();
            for page in first..=last {
                if backfill >= MAX_BACKFILL_PAGES {
                    break 'gaps;
                }
                if !pages.contains(&page) {
                    pages.push(page);
                    backfill += 1;
                }
            }
        }

        // Then the pages between the cursor and the frontier, witnessed or not.
        // Both loops are bounded: each iteration either spends backfill budget or
        // skips a page already in a list of at most `2 + MAX_BACKFILL_PAGES`.
        for page in self.unsettled_span().into_iter().flatten() {
            if backfill >= MAX_BACKFILL_PAGES {
                break;
            }
            if !pages.contains(&page) {
                pages.push(page);
                backfill += 1;
            }
        }

        pages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::ack::MAX_ACK_RUNS;
    use crate::dm::paging::PAGE_SLOTS;
    use crate::dm::ratchet::FIRST_INITIATOR_CHANNEL_SEQ;

    /// The position of a sequence number, for tests that speak in sequences.
    fn at(seq: u64) -> PagePosition {
        position_of(seq)
    }

    /// A resumed collection probes from the page the cursor named, and claims
    /// nothing about what is settled below it.
    ///
    /// Both halves are asserted against a fresh collection as the control: a
    /// `resuming_from_page` that ignored its argument would produce exactly the
    /// fresh plan, and one that fabricated a prefix would differ from the fresh
    /// cursor.
    #[test]
    fn a_resumed_collection_probes_from_the_cursor_and_settles_nothing() {
        const RESUMED_AT: u64 = 40;

        let fresh = Collection::new();
        let resumed = Collection::resuming_from_page(RESUMED_AT);

        assert_eq!(
            resumed.frontier_page(),
            Some(RESUMED_AT),
            "the frontier must resume at the page the cursor named"
        );
        assert_eq!(
            fresh.frontier_page(),
            None,
            "a fresh collection must have reached no page, or the assertion above is vacuous"
        );
        assert_eq!(
            resumed.contiguous_through(),
            fresh.contiguous_through(),
            "a resumed collection must claim exactly what a fresh one does: nothing"
        );
        assert!(
            resumed.outstanding().is_empty(),
            "nothing can be outstanding before anything has been settled"
        );

        let mut resumed = resumed;
        let plan = resumed
            .probe_plan(0)
            .expect("a collection that has never probed is due");
        assert_eq!(
            plan,
            vec![RESUMED_AT, RESUMED_AT + 1, 0, 1],
            "the plan must lead with the resumed page and the next one, then backfill \
             from the bottom — the cursor named a page, not a settled set"
        );
        assert_eq!(
            Collection::new()
                .probe_plan(0)
                .expect("a fresh collection is due"),
            vec![0, 1],
            "a fresh collection must plan only page zero and its successor, or the \
             resumed plan above proves nothing about the frontier"
        );

        // A page above the sequence space names no position, so it is not a page
        // a probe could start from.
        assert_eq!(
            Collection::resuming_from_page(MAX_PAGE + 1).frontier_page(),
            None,
            "a page outside the sequence space must resume nothing"
        );
    }

    /// Collect a sequence number, asserting the ack accepted it.
    fn collect(c: &mut Collection, seq: u64) {
        c.collected(at(seq)).expect("within the run cap");
    }

    /// Observe a page whose slots are known to be inside the record, discarding
    /// the fold result.
    fn reach(c: &mut Collection, page: u64, slots: &[u16]) {
        let _ = c
            .observe_page(page, slots)
            .expect("slots inside the record");
    }

    // ---- the frontier --------------------------------------------------------

    /// The frontier judges a page by holding *any* populated slot. A collector
    /// that waited for a full page would stall on the initiator's very first
    /// one, whose first slot is empty forever.
    #[test]
    fn one_populated_slot_reaches_a_page() {
        let mut c = Collection::new();
        let seen = c.observe_page(0, &[1]).unwrap();
        assert!(seen.frontier_advanced);
        assert_eq!(c.frontier_page(), Some(0));
        assert_eq!(at(FIRST_INITIATOR_CHANNEL_SEQ).slot(), 1, "slot 0 is empty");
    }

    /// A page holding nothing is not reached — the frontier is about content,
    /// and a probe that ran ahead of the writer must not drag it forward.
    #[test]
    fn an_empty_page_is_not_reached() {
        let mut c = Collection::new();
        let seen = c.observe_page(7, &[]).unwrap();
        assert!(!seen.frontier_advanced);
        assert_eq!(c.frontier_page(), None);
    }

    /// Sweeps complete out of order. A late sweep of an older page must not pull
    /// the frontier back over ground already reached, or the probe plan would
    /// oscillate.
    #[test]
    fn the_frontier_never_regresses() {
        let mut c = Collection::new();
        reach(&mut c, 5, &[0]);
        let seen = c.observe_page(2, &[3]).unwrap();
        assert!(!seen.frontier_advanced);
        assert_eq!(c.frontier_page(), Some(5));
    }

    /// **The headline of this module.** A message that is never recoverable
    /// holds the contiguous cursor at the gap forever; the frontier must run on
    /// regardless. A frontier anchored to the cursor would stall the whole rest
    /// of the conversation on one lost message (§ v6 erasure F1).
    #[test]
    fn a_permanent_gap_holds_the_cursor_and_not_the_frontier() {
        let mut c = Collection::new();
        for seq in [0u64, 1, 2, 4, 5] {
            reach(&mut c, at(seq).page(), &[at(seq).slot()]);
            collect(&mut c, seq);
        }
        // Sequence 3 never arrives, and the conversation runs on for two pages.
        let far = PAGE_SLOTS as u64 * 2;
        reach(&mut c, at(far).page(), &[at(far).slot()]);
        collect(&mut c, far);

        assert_eq!(
            c.contiguous_through(),
            Some(2),
            "the cursor sits at the gap"
        );
        assert_eq!(c.frontier_page(), Some(2), "the frontier ran past it");
        assert_eq!(c.outstanding(), vec![3..=3, 6..=31]);
    }

    /// The seven-day give-up is the design's own bound on permanent loss, so it
    /// has to be able to free a frontier that a wholly-lost page stalled. Without
    /// the floor, `abandon` is `settle` and touches no page number: the cursor
    /// crosses the dead page, `outstanding()` empties, and the plan stays the
    /// same two pages **forever** — one bad page ends the direction permanently,
    /// which is the failure the give-up exists to bound rather than to cause.
    #[test]
    fn the_give_up_lifts_a_frontier_stalled_by_a_wholly_lost_page() {
        let mut c = Collection::new();
        let slots: Vec<u16> = (0..PAGE_SLOTS).collect();
        reach(&mut c, 0, &slots);
        for seq in 0..PAGE_SLOTS as u64 {
            collect(&mut c, seq);
        }
        assert_eq!(c.watched(), [0, 1], "page 1 is the whole lookahead");

        // Page 1 is entirely unavailable: nothing is ever reached on it, so the
        // sender gives up on all sixteen of its positions.
        for seq in PAGE_SLOTS as u64..(PAGE_SLOTS as u64 * 2) {
            c.abandoned(seq).expect("within the run cap");
        }

        assert_eq!(c.contiguous_through(), Some(31), "the cursor crossed it");
        assert_eq!(c.frontier_page(), Some(1), "and lifted the frontier");
        assert_eq!(c.watched(), [1, 2], "so page 2 is reachable at last");
    }

    /// The floor must never become an anchor — anchoring is the § v6 erasure F1
    /// defect itself, and a lower bound is only a different thing if it cannot
    /// pull the frontier back. Pinned because the rustdoc claims exactly this and
    /// a reader will otherwise take the floor for the defect F1 names.
    #[test]
    fn the_cursor_floors_the_frontier_and_never_pulls_it_back() {
        let mut c = Collection::new();
        let far = PAGE_SLOTS as u64 * 4;
        reach(&mut c, at(far).page(), &[at(far).slot()]);
        collect(&mut c, far);
        assert_eq!(c.frontier_page(), Some(4));

        // The cursor settles one position at the very bottom and stays there.
        collect(&mut c, 0);
        assert_eq!(c.contiguous_through(), Some(0), "held by the gap at one");
        assert_eq!(c.frontier_page(), Some(4), "the frontier was pulled back");
    }

    // ---- folding a swept page ------------------------------------------------

    /// A slot the record cannot hold means the page was opened under the wrong
    /// shape, so every position it reports belongs to some other page. Rejected
    /// whole, with nothing recorded.
    #[test]
    fn a_slot_outside_the_record_is_rejected_and_changes_nothing() {
        let mut c = Collection::new();
        assert_eq!(
            c.observe_page(3, &[0, PAGE_SLOTS]),
            Err(CollectError::SlotOutsideRecord {
                page: 3,
                slot: PAGE_SLOTS
            })
        );
        assert_eq!(c.frontier_page(), None, "nothing was recorded");
    }

    /// A page too high to hold any position is the **page's** fault, not the
    /// slot's. One variant for both would report a perfectly legal slot 0 as
    /// outside the record and send a reader looking at the record shape.
    #[test]
    fn a_page_beyond_the_sequence_space_is_named_as_the_fault() {
        let mut c = Collection::new();
        assert_eq!(
            PagePosition::new(u64::MAX, 0),
            None,
            "slot 0 is legal; the page is what has no position"
        );
        assert_eq!(
            c.observe_page(u64::MAX, &[0]),
            Err(CollectError::PageBeyondSequenceSpace { page: u64::MAX })
        );
        assert_eq!(c.frontier_page(), None, "nothing was recorded");

        // Checked before any slot, so an empty sweep of it answers the same.
        assert_eq!(
            c.observe_page(u64::MAX, &[]),
            Err(CollectError::PageBeyondSequenceSpace { page: u64::MAX })
        );
    }

    /// Each variant says which of the two was at fault, in as many words.
    #[test]
    fn the_two_fold_errors_read_differently() {
        assert_eq!(
            CollectError::SlotOutsideRecord {
                page: 3,
                slot: PAGE_SLOTS
            }
            .to_string(),
            "slot 16 is outside page 3's record"
        );
        assert_eq!(
            CollectError::PageBeyondSequenceSpace { page: u64::MAX }.to_string(),
            format!(
                "page {} is above the highest page a sequence number can live on ({MAX_PAGE})",
                u64::MAX
            )
        );
    }

    /// The highest legal page is legal, and one past it is not — the boundary the
    /// fold shares with [`PagePosition::new`], read from the one constant that
    /// states it.
    #[test]
    fn the_fold_reaches_the_highest_page_and_no_further() {
        let mut c = Collection::new();
        assert!(c.observe_page(MAX_PAGE, &[0]).is_ok());
        assert_eq!(c.frontier_page(), Some(MAX_PAGE));
        assert!(c.observe_page(MAX_PAGE + 1, &[0]).is_err());
        assert_eq!(c.frontier_page(), Some(MAX_PAGE), "and recorded nothing");
    }

    /// A page's slots arrive from a sweep that fans out its GETs, so order is
    /// not guaranteed and a re-read can repeat one. The caller opens frames in
    /// sequence order, so this hands them back that way.
    ///
    /// On page 3 rather than page 0, because this and its neighbour below are the
    /// only tests of the fold's slot-to-sequence lift. On page 0 a slot index *is*
    /// its own sequence number, so the expected values would be the slot numbers
    /// themselves and a fold that handed back raw slots — or that hardcoded page
    /// zero — would pass unchallenged (#272). Here the two are distinct: slots
    /// 1, 3, 5 lift to sequences 49, 51, 53.
    #[test]
    fn positions_come_back_ascending_and_deduplicated() {
        let mut c = Collection::new();
        let seen = c.observe_page(3, &[5, 1, 5, 3]).unwrap();
        let seqs: Vec<u64> = seen.unsettled.iter().map(|p| p.seq()).collect();
        assert_eq!(seqs, vec![49, 51, 53]);
    }

    /// Re-seeding makes a page return bytes for messages already collected. A
    /// message key is used once, so offering those again would hand the ratchet
    /// frames it can only reject.
    ///
    /// On page 3 for the reason its neighbour above is: the settled-set lookup is
    /// keyed by sequence number, and on page 0 the sequence it is keyed by cannot
    /// be told apart from the slot it came from (#272). Slot 1 lifts to sequence
    /// 49 and slot 2 to sequence 50, so a fold that compared raw slots against
    /// settled sequences is caught.
    #[test]
    fn a_settled_position_is_not_offered_again() {
        let mut c = Collection::new();
        reach(&mut c, 3, &[1]);
        collect(&mut c, 49);
        let seen = c.observe_page(3, &[1, 2]).unwrap();
        let seqs: Vec<u64> = seen.unsettled.iter().map(|p| p.seq()).collect();
        assert_eq!(seqs, vec![50]);
    }

    // ---- the cadence ---------------------------------------------------------

    /// The interval is the only gate on a plan — not the frontier, not the fill
    /// state of any page.
    #[test]
    fn a_plan_is_issued_once_per_interval() {
        let mut c = Collection::new();
        assert!(c.probe_plan(1_000).is_some(), "the first call is due");
        assert!(c.probe_plan(1_001).is_none(), "inside the interval");
        assert!(
            c.probe_plan(1_000 + PROBE_INTERVAL_MS - 1).is_none(),
            "still inside the interval"
        );
        assert!(c.probe_plan(1_000 + PROBE_INTERVAL_MS).is_some());
    }

    /// A clock that stepped backwards must not park the probe for the size of
    /// the step.
    #[test]
    fn a_backwards_clock_does_not_park_the_probe() {
        let mut c = Collection::new();
        assert!(c.probe_plan(10_000_000).is_some());
        assert!(c.probe_plan(5).is_some(), "earlier than the last plan");
    }

    // ---- the plan ------------------------------------------------------------

    /// Speculative contiguous probing: the next page is swept regardless of how
    /// full the current one is. One populated slot out of sixteen is enough.
    #[test]
    fn the_plan_reads_past_a_page_that_is_nowhere_near_full() {
        let mut c = Collection::new();
        reach(&mut c, 4, &[0]);
        let plan = c.probe_plan(0).unwrap();
        assert_eq!(plan[..2], [4, 5]);
    }

    /// Before any page is reached the current page is zero, so a cold start
    /// sweeps the beginning of the conversation.
    #[test]
    fn a_cold_collection_probes_the_first_two_pages() {
        let mut c = Collection::new();
        assert_eq!(c.probe_plan(0).unwrap(), vec![0, 1]);
        assert_eq!(c.watched(), [0, 1]);
    }

    /// The backfill exists to advance the cursor, so it goes to the oldest gap
    /// first — every later gap is already reported past by the beyond-prefix
    /// set.
    #[test]
    fn the_plan_backfills_the_oldest_gap_first() {
        let mut c = Collection::new();
        // Two holes, each wholly inside its own page and the pages not adjacent,
        // so the order the plan visits them in is visible: 16..=17 on page 1,
        // 48..=49 on page 3.
        for seq in (0..16).chain(18..48).chain([50]) {
            collect(&mut c, seq);
        }
        assert_eq!(c.outstanding(), vec![16..=17, 48..=49]);

        reach(&mut c, 9, &[0]);
        let plan = c.probe_plan(0).unwrap();
        assert_eq!(plan, vec![9, 10, 1, 3], "watched pair, then the older hole");
    }

    /// A gappy conversation must not turn every probe into a sweep of its whole
    /// history — the op-gate is shared with the rest of the client.
    #[test]
    fn the_plan_is_bounded_however_many_gaps_there_are() {
        let mut c = Collection::new();
        let slots = PAGE_SLOTS as u64;
        for page in 0..40u64 {
            collect(&mut c, page * slots + 2);
        }
        reach(&mut c, 50, &[0]);
        let plan = c.probe_plan(0).unwrap();
        assert_eq!(plan.len(), 2 + MAX_BACKFILL_PAGES);
    }

    /// **A hole the frontier has already passed is still a hole.** A page can be
    /// populated and still open nothing — `UnknownEphemeral` is the expected
    /// answer when the frame introducing the ephemeral is among the missing ones
    /// — so the frontier moves, nothing settles above the prefix,
    /// [`Collection::outstanding`] is empty, and the page holding fifteen
    /// re-seeded messages falls out of every plan there will ever be. That is
    /// exactly the failure the backfill exists to prevent, surviving in the case
    /// where the frontier moved first.
    #[test]
    fn a_hole_below_the_frontier_is_backfilled_with_nothing_to_witness_it() {
        let mut c = Collection::new();
        reach(&mut c, 0, &[0]);
        collect(&mut c, 0);
        // Page 1 comes back populated, but none of its frames open.
        reach(&mut c, 1, &[0]);

        assert_eq!(c.frontier_page(), Some(1));
        assert_eq!(c.contiguous_through(), Some(0), "held at the hole");
        assert!(
            c.outstanding().is_empty(),
            "nothing is settled beyond the prefix, so nothing witnesses it"
        );

        let plan = c.probe_plan(0).unwrap();
        assert!(
            plan.contains(&0),
            "page 0 still holds fifteen messages the sender is re-seeding: {plan:?}"
        );
    }

    /// The bound is on the backfill, which is what its documentation claims —
    /// not on the plan as a whole. The two differ only when the watched pair
    /// collapses to one entry, which takes a frontier at `u64::MAX`; the fold
    /// refuses such a page, so this reaches in rather than leaving the bound
    /// resting on an invariant that lives in another method. The sibling
    /// `the_fold_reaches_the_highest_page_and_no_further` pins that invariant.
    #[test]
    fn the_cap_bounds_the_backfill_and_not_the_whole_plan() {
        let mut c = Collection::new();
        collect(&mut c, 0);
        collect(&mut c, 100);
        c.frontier = Some(u64::MAX);
        assert_eq!(c.watched(), [u64::MAX, u64::MAX], "the pair collapsed");

        let plan = c.probe_plan(0).unwrap();
        assert_eq!(plan[0], u64::MAX);
        assert_eq!(
            plan.len() - 1,
            MAX_BACKFILL_PAGES,
            "backfill entries past the one watched page: {plan:?}"
        );
    }

    // ---- the readable state --------------------------------------------------

    /// Collection in order leaves nothing outstanding: everything folds into the
    /// prefix as it arrives.
    #[test]
    fn nothing_is_outstanding_when_collection_is_in_order() {
        let mut c = Collection::new();
        for seq in 0..5 {
            collect(&mut c, seq);
        }
        assert_eq!(c.contiguous_through(), Some(4));
        assert!(c.outstanding().is_empty());
    }

    /// Holes are reported as ranges, because one can span pages and the count of
    /// ranges is bounded where the count of positions is not.
    #[test]
    fn outstanding_names_every_hole_below_the_highest_settled() {
        let mut c = Collection::new();
        for seq in [0u64, 1, 40, 41, 100] {
            collect(&mut c, seq);
        }
        assert_eq!(c.outstanding(), vec![2..=39, 42..=99]);
    }

    /// A give-up settles the position: it leaves the outstanding set and the
    /// cursor advances over it, which is what keeps the beyond-prefix set
    /// bounded under permanent loss.
    #[test]
    fn abandoning_a_hole_clears_it_and_advances_the_cursor() {
        let mut c = Collection::new();
        for seq in [0u64, 1, 3] {
            collect(&mut c, seq);
        }
        assert_eq!(c.outstanding(), vec![2..=2]);
        c.abandoned(2).unwrap();
        assert_eq!(c.contiguous_through(), Some(3));
        assert!(c.outstanding().is_empty());
    }

    /// The view reports the two pointers and the holes, and they are three
    /// different facts.
    #[test]
    fn the_view_carries_both_pointers_and_the_holes() {
        let mut c = Collection::new();
        collect(&mut c, 0);
        collect(&mut c, 5);
        reach(&mut c, 3, &[0]);
        assert_eq!(
            c.view(),
            CollectionView {
                contiguous_through: Some(0),
                frontier_page: Some(3),
                outstanding: vec![1..=4],
            }
        );
    }

    /// A refused acknowledgement is **dropped, not queued**, so the refusal has
    /// to reach the caller — the caller is the only thing that can retain the
    /// position. Nothing here holds it, and re-offering it is not a recovery: the
    /// position comes back as unsettled, but its message key is consumed, so
    /// opening the frame again is `AlreadyConsumed`. The recovery is this same
    /// call, once a closing gap frees capacity.
    #[test]
    fn a_refused_acknowledgement_is_dropped_and_the_refusal_reaches_the_caller() {
        let mut c = Collection::new();
        // Every other position from one: each is its own run, because position
        // zero is never settled and neither is any even one.
        for i in 0..MAX_ACK_RUNS as u64 {
            collect(&mut c, 1 + i * 2);
        }
        let over = at(1 + MAX_ACK_RUNS as u64 * 2);

        assert_eq!(
            c.collected(over),
            Err(AckError::TooManyRuns {
                runs: MAX_ACK_RUNS + 1,
                max: MAX_ACK_RUNS
            }),
            "a swallowed refusal leaves the caller believing it was acknowledged"
        );

        // Nothing retained it, and re-offering hands back the same position.
        let seen = c.observe_page(over.page(), &[over.slot()]).unwrap();
        assert_eq!(seen.unsettled, vec![over], "still unsettled, still offered");

        // The documented recovery, which is the caller calling again.
        c.collected(at(0)).expect("closes the first gap");
        c.collected(at(2)).expect("and the second");
        c.collected(over).expect("capacity returned");
    }

    /// The cursor a UI reads and the cursor that goes on the wire are one value.
    #[test]
    fn the_acknowledgement_is_the_same_cursor() {
        let mut c = Collection::new();
        collect(&mut c, 0);
        collect(&mut c, 1);
        assert_eq!(c.ack().high_water(), c.contiguous_through());
        assert_eq!(c.ack().high_water(), Some(1));
    }

    // ---- the receive-side give-up --------------------------------------------

    /// A clock value far enough above zero that a horizon fits below it.
    const T0: u64 = 1_000_000;

    /// One second, the margin the boundary control below sits inside.
    const A_SECOND_MS: u64 = 1_000;

    /// Sweep on the probe cadence from `from_ms` to `to_ms` inclusive, returning
    /// everything abandoned along the way.
    ///
    /// The horizon is days and the cadence is seconds, so a test that wants a
    /// gap to age has to march the clock rather than jump it — which is the
    /// behaviour under test, not an inconvenience of it. The horizon is a whole
    /// number of cadences, so a march that starts when a gap is first observed
    /// and ends a horizon later leaves its age exactly on the horizon.
    fn march(c: &mut Collection, from_ms: u64, to_ms: u64) -> Vec<u64> {
        let mut abandoned = Vec::new();
        let mut now = from_ms;
        while now <= to_ms {
            abandoned.extend(c.sweep_give_ups(now));
            now = now.saturating_add(PROBE_INTERVAL_MS);
        }
        abandoned
    }

    /// A position that never arrives is given up on once its gap has stood for
    /// the whole horizon: the cursor advances over it, and the run that was
    /// holding a position beyond the prefix folds into the prefix.
    ///
    /// The state before the horizon is asserted first, so "the cursor advanced"
    /// cannot be satisfied by a collection that was never holding a gap.
    #[test]
    fn a_gap_past_the_horizon_is_given_up_on() {
        let mut c = Collection::new();
        collect(&mut c, 1);
        collect(&mut c, 2);
        assert_eq!(
            c.contiguous_through(),
            None,
            "position zero is missing, so it holds the cursor"
        );
        assert_eq!(c.outstanding(), vec![0..=0], "and it is the one hole");
        assert_eq!(
            c.ack().runs(),
            1,
            "the two positions above it are one run beyond the prefix"
        );

        // The first sweep is what observes the gap, so it starts the gap's clock
        // and can give up on nothing.
        assert!(
            c.sweep_give_ups(T0).is_empty(),
            "a gap observed for the first time has aged nothing"
        );
        assert_eq!(c.contiguous_through(), None);

        assert_eq!(
            march(&mut c, T0, T0 + RECEIVE_GIVE_UP_MS),
            vec![0],
            "the position must be given up on once its gap has stood a horizon"
        );
        assert_eq!(
            c.contiguous_through(),
            Some(2),
            "the cursor must advance past the abandoned position and over the run above it"
        );
        assert_eq!(
            c.ack().runs(),
            0,
            "the run beyond the prefix must fold into the prefix"
        );
        assert!(
            c.outstanding().is_empty(),
            "nothing is outstanding once the hole is settled"
        );
    }

    /// One second short of the horizon the gap stands. The message may still be
    /// on its way: the sender re-seeds to its own give-up, and the margin past
    /// that is what the horizon adds.
    ///
    /// The last two assertions are the positive control — a horizon that never
    /// fired at all would satisfy everything above them.
    #[test]
    fn a_gap_one_second_short_of_the_horizon_stands() {
        let mut c = Collection::new();
        collect(&mut c, 1);

        // One cadence short of the horizon, then one sweep landing the age
        // exactly one second below it.
        assert!(
            march(&mut c, T0, T0 + RECEIVE_GIVE_UP_MS - PROBE_INTERVAL_MS).is_empty(),
            "a gap short of the horizon must not be given up on"
        );
        assert!(
            c.sweep_give_ups(T0 + RECEIVE_GIVE_UP_MS - A_SECOND_MS)
                .is_empty(),
            "a gap one second short of the horizon must not be given up on"
        );
        assert_eq!(
            c.contiguous_through(),
            None,
            "so it must still hold the cursor"
        );
        assert_eq!(c.outstanding(), vec![0..=0], "and must still be a hole");

        assert_eq!(
            c.sweep_give_ups(T0 + RECEIVE_GIVE_UP_MS),
            vec![0],
            "one second later the same gap must be given up on"
        );
        assert_eq!(c.contiguous_through(), Some(1));
    }

    /// A clock that steps forward does not age a gap by the size of the step.
    ///
    /// The dangerous direction: abandoning a position the sender has not given
    /// up on settles it, and a settled position is filtered out of everything
    /// [`Collection::observe_page`] offers, so the copy still on the record is
    /// never opened. The control below is the same collection aged the ordinary
    /// way, which must abandon — without it "nothing was abandoned" is satisfied
    /// by a horizon that cannot fire.
    #[test]
    fn a_clock_that_steps_forward_does_not_age_a_gap_by_the_step() {
        const A_MONTH_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

        let mut stepped = Collection::new();
        collect(&mut stepped, 1);
        assert!(stepped.sweep_give_ups(T0).is_empty(), "the gap is observed");
        assert!(
            stepped.sweep_give_ups(T0 + A_MONTH_MS).is_empty(),
            "one sweep after a clock step must add one capped interval, not a month"
        );
        assert_eq!(
            stepped.contiguous_through(),
            None,
            "the gap must still hold the cursor"
        );

        let mut marched = Collection::new();
        collect(&mut marched, 1);
        assert_eq!(
            march(&mut marched, T0, T0 + RECEIVE_GIVE_UP_MS),
            vec![0],
            "a collection aged on the cadence must reach the horizon"
        );
    }

    /// A gap filled from below keeps the age the whole gap had. Its first
    /// position moves every time one is collected, so an age keyed on that
    /// endpoint would restart on every sweep and the gap would never age out.
    #[test]
    fn a_gap_filled_from_below_does_not_restart_its_horizon() {
        let mut c = Collection::new();
        collect(&mut c, 3);
        assert_eq!(c.outstanding(), vec![0..=2], "three positions are missing");

        assert!(c.sweep_give_ups(T0).is_empty(), "the gap is observed");
        collect(&mut c, 0);
        assert_eq!(c.outstanding(), vec![1..=2], "the gap shrinks from below");

        assert_eq!(
            march(&mut c, T0, T0 + RECEIVE_GIVE_UP_MS),
            vec![1, 2],
            "the shrunken gap must age from when the whole gap was first observed"
        );
        assert_eq!(c.contiguous_through(), Some(3));
    }

    /// A gap split by a collected position keeps its age in both halves, for the
    /// same reason: one gap became two and neither is new.
    #[test]
    fn a_split_gap_keeps_its_age_in_both_halves() {
        let mut c = Collection::new();
        collect(&mut c, 5);
        assert_eq!(c.outstanding(), vec![0..=4]);

        assert!(c.sweep_give_ups(T0).is_empty(), "the gap is observed");
        collect(&mut c, 2);
        assert_eq!(
            c.outstanding(),
            vec![0..=1, 3..=4],
            "the collected position splits the gap in two"
        );

        assert_eq!(
            march(&mut c, T0, T0 + RECEIVE_GIVE_UP_MS),
            vec![0, 1, 3, 4],
            "both halves must age from the moment the whole gap was first observed"
        );
        assert_eq!(c.contiguous_through(), Some(5));
    }

    /// A gap is abandoned whole. Leaving part of it would keep the run the
    /// give-up exists to release.
    #[test]
    fn a_multi_position_gap_is_abandoned_whole() {
        let mut c = Collection::new();
        collect(&mut c, 3);
        assert_eq!(c.outstanding(), vec![0..=2]);

        assert_eq!(
            march(&mut c, T0, T0 + RECEIVE_GIVE_UP_MS),
            vec![0, 1, 2],
            "every position of the gap must be abandoned, in order"
        );
        assert!(c.outstanding().is_empty());
        assert_eq!(c.ack().runs(), 0);
        assert_eq!(c.contiguous_through(), Some(3));
    }

    /// Gaps age separately. Giving up on one leaves another's age exactly where
    /// it was, so a conversation that loses a position at a time does not
    /// restart every remaining gap's horizon each time one of them is settled.
    #[test]
    fn giving_up_on_one_gap_does_not_restart_another() {
        let mut c = Collection::new();
        // Two holes: position zero, and position two.
        collect(&mut c, 1);
        collect(&mut c, 3);
        assert_eq!(c.outstanding(), vec![0..=0, 2..=2], "two holes stand");

        assert!(c.sweep_give_ups(T0).is_empty(), "both gaps are observed");
        // Close the lower hole by collecting it, which leaves the upper one
        // holding the cursor with its own age untouched.
        collect(&mut c, 0);
        assert_eq!(c.outstanding(), vec![2..=2]);

        assert_eq!(
            march(&mut c, T0, T0 + RECEIVE_GIVE_UP_MS),
            vec![2],
            "the remaining gap must be given up on at its own first observation, \
             not at the moment the other hole closed"
        );
        assert_eq!(c.contiguous_through(), Some(3));
    }

    /// The age list is exactly the gaps that stand, so a conversation that opens
    /// and closes holes over and over carries no more entries than it has holes.
    ///
    /// The list is what bounds this state, and it is bounded only because it is
    /// rebuilt: an entry kept for a closed gap would also be an age a later gap
    /// over the same positions could inherit.
    #[test]
    fn gap_ages_do_not_accumulate_across_closed_gaps() {
        let mut c = Collection::new();
        let mut now = T0;
        for round in 0..8u64 {
            let base = round * 4;
            // Open two holes, sweep, then close them both.
            collect(&mut c, base + 1);
            collect(&mut c, base + 3);
            let _ = c.sweep_give_ups(now);
            now += PROBE_INTERVAL_MS;
            assert!(
                c.tracked_gaps() <= c.outstanding().len(),
                "round {round}: {} entries for {} gaps",
                c.tracked_gaps(),
                c.outstanding().len()
            );
            collect(&mut c, base);
            collect(&mut c, base + 2);
            let _ = c.sweep_give_ups(now);
            now += PROBE_INTERVAL_MS;
        }
        assert_eq!(
            c.contiguous_through(),
            Some(31),
            "the fixture must have closed every hole it opened"
        );
        assert_eq!(
            c.tracked_gaps(),
            0,
            "a collection with no holes must carry no ages"
        );
    }

    /// The horizon is the sender's give-up plus one re-seed interval, and the
    /// interval is the ladder's longest rung.
    #[test]
    fn the_horizon_is_the_give_up_plus_one_reseed_interval() {
        let longest = RESEED_LADDER
            .iter()
            .max()
            .expect("the ladder has rungs")
            .as_millis();
        assert_eq!(
            u128::from(RECEIVE_GIVE_UP_MS),
            GIVE_UP.as_millis() + longest,
            "the horizon must be the give-up plus the ladder's longest rung"
        );
    }
}
