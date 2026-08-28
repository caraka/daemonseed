//! The standalone-acknowledgement write budget — one client-global allowance,
//! not one per conversation.
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6),
//! § Build-contract spec-precision item (i), with the arithmetic it comes from in
//! § Decision #4.
//!
//! [`ack`](crate::dm::ack) owns what an acknowledgement *means*; this owns how
//! often one may be written on its own. They are deliberately apart — `ack`'s
//! header says the standalone cadence belongs to the slice that writes records,
//! and this module is the part of that cadence which is pure enough to decide
//! without one.
//!
//! ## Why the budget is global and not per channel
//!
//! A standalone acknowledgement is a non-chat DHT write, and non-chat writes
//! share one steady-state ceiling of **four per minute** across the whole client
//! (`docs/design/veilid-write-budget.md`, WB-2). Presence and share adverts
//! already spend about two of those, and the other direct-message writers — the
//! re-seed tail, doorbell keep-alive, key-record keep-alive — come to roughly
//! 0.13/min between them. Acknowledgements are the swing term: in read-heavy use
//! across three to five channels an uncapped rate reaches 3–5/min on its own,
//! which puts the client over the ceiling.
//!
//! **A per-channel interval does not fix that, and this is the whole reason the
//! type is shaped this way.** An interval of `I` applied to each of `N`
//! conversations permits `N/I` writes per minute in aggregate, so the breach
//! returns as soon as a user has several active conversations — the case the cap
//! exists for. Decision #4 originally specified a thirty-second per-channel
//! interval on exactly that mistake; the later spec-precision pass replaced it
//! with item (i): the cap **must** be a client-global aggregate of about one per
//! minute, **never per channel**. One [`StandaloneAckBudget`] per client is
//! therefore not a convenience — a second instance is the defect.
//!
//! ## What this does not decide
//!
//! **Fairness is not specified and is not invented here.** With one allowance
//! between them, whichever conversation asks first after the interval elapses
//! gets it, so a busy conversation can outpace a quiet one.
//!
//! The design's own answer to that is not the piggyback path — a standalone
//! acknowledgement exists precisely when there is no reply to ride on — but the
//! erasure pass's: when the aggregate budget is spent the acknowledgements queue,
//! the sender's continued re-seed covers the gap, and an acknowledgement is
//! advisory, so delaying one delays *confirmation* and not delivery. Nothing is
//! lost by losing the race; the sender keeps the message alive until it is
//! acknowledged. If a starvation case is ever measured, round-robin belongs
//! here — but not before then.
//!
//! Jitter is likewise elsewhere. This decides *whether* a write is within
//! budget, not *when* within a window it should land.
//!
//! ## The clock is an argument
//!
//! Nothing here reads a clock, for the reason [`collect`](crate::dm::collect)
//! gives about its own cadence: a value passed in is deterministically testable
//! and a timer is not.

/// The client-global minimum interval between standalone acknowledgements.
///
/// One per minute, from § Build-contract item (i). Expressed as an interval
/// rather than a rate because the check is against a single previous instant,
/// which needs no window bookkeeping and cannot drift.
pub const STANDALONE_ACK_MIN_INTERVAL_MS: i64 = 60_000;

/// Whether a standalone acknowledgement may be written now.
///
/// `#[must_use]` catches a caller that asks and then throws the answer away. It
/// does **not** catch one that reads the answer and writes anyway — that is a
/// lint against forgetting, not enforcement against disobeying, and `let _ =`
/// is its documented escape hatch. Nothing at this layer can enforce the second;
/// the write path is where that lives.
#[must_use = "a standalone acknowledgement must not be written unless this granted it"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPermit {
    /// Write it. The allowance is spent and does not renew until the interval
    /// has elapsed.
    Granted,
    /// Do not write it. `retry_after_ms` is how long remains of the interval, so
    /// a caller can schedule rather than poll.
    Refused {
        /// Milliseconds until the next allowance, never negative.
        retry_after_ms: i64,
    },
}

/// One client's whole allowance for standalone acknowledgements.
///
/// Hold **one** of these per client and share it across every conversation; see
/// the module header for why a per-conversation instance reintroduces the breach
/// this exists to close.
///
/// **Deliberately neither `Copy` nor `Clone`, and that is the invariant's only
/// real defence.** [`Self::request`] takes `&mut self`, so under `Copy` every
/// by-value pass would spend a *duplicate* allowance and leave the caller's own
/// untouched — silently, with no diagnostic, which is exactly the per-channel
/// breach in a shape no reviewer would see. Without it the same code is a move
/// error. A prose warning cannot do that work; the missing derive can.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StandaloneAckBudget {
    /// When the allowance was last spent. `None` before the first grant, which
    /// is why a fresh budget grants immediately rather than making a client wait
    /// out an interval it never used.
    last_granted_ms: Option<i64>,
}

impl StandaloneAckBudget {
    /// A budget that has never been spent, and so grants its first request.
    pub const fn new() -> Self {
        Self {
            last_granted_ms: None,
        }
    }

    /// Ask to write a standalone acknowledgement at `now_ms`.
    ///
    /// A grant spends the allowance; a refusal changes nothing, so refusing
    /// costs a caller nothing and may be repeated.
    ///
    /// **A clock that goes backwards refuses, and parks the budget for the size
    /// of the step.** `now_ms` is the caller's own clock and nothing here can
    /// vouch for it, so an instant before the last grant reads as still inside
    /// the interval and `retry_after_ms` reports the real remainder, however
    /// large.
    ///
    /// [`collect`](crate::dm::collect) takes the opposite decision on the same
    /// input — a backwards `now_ms` there is treated as *due*, so a step back
    /// cannot park the probe — and the divergence is deliberate rather than an
    /// oversight. Being early costs that module a read, which is free; being
    /// early costs this one a write against a ceiling with about 0.4/min of
    /// headroom, which is the breach the budget exists to prevent. Late is
    /// cheap here and early is not, so the two modules break the tie in
    /// opposite directions.
    ///
    /// **Re-anchoring to `now_ms` on a step back was considered and is unsound.**
    /// It bounds the stall to one interval, which is the attraction, but it moves
    /// the next allowance *earlier* in absolute time: granted at 100 s, stepped
    /// back to 50 s, re-anchored, the next grant lands at 110 s — ten seconds
    /// after the last one, six per minute. A caller that alternates two clocks
    /// gets an unbounded rate out of it. Parking is the conservative side of a
    /// tie that has no free answer.
    pub fn request(&mut self, now_ms: i64) -> AckPermit {
        let Some(last) = self.last_granted_ms else {
            self.last_granted_ms = Some(now_ms);
            return AckPermit::Granted;
        };

        let elapsed = now_ms.saturating_sub(last);
        if elapsed >= STANDALONE_ACK_MIN_INTERVAL_MS {
            self.last_granted_ms = Some(now_ms);
            return AckPermit::Granted;
        }

        AckPermit::Refused {
            // `elapsed` is below the interval, and is negative when the clock
            // stepped back — in which case this exceeds one interval, which is
            // the truth. It is not capped: a caller told to wait 60 s after an
            // hour-long step back would wake sixty times and be refused sixty
            // times. Saturating covers the extremes of the clock type; the
            // result is always positive because `elapsed < INTERVAL` here.
            retry_after_ms: STANDALONE_ACK_MIN_INTERVAL_MS.saturating_sub(elapsed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A budget nobody has spent grants at once: a client that has just started
    /// should not owe an interval it never used.
    #[test]
    fn a_fresh_budget_grants_its_first_request() {
        let mut b = StandaloneAckBudget::new();
        assert_eq!(b.request(1_700_000_000_000), AckPermit::Granted);
    }

    /// The second request inside the interval is refused, and is told how long
    /// remains rather than being left to poll.
    ///
    /// **Pinned at several offsets on purpose.** A single offset is satisfied by
    /// a constant: `retry_after_ms: 40_000` passes a test that only ever asks at
    /// +20 000 ms, and so does `if elapsed == 20_000 { 40_000 } else { … }`.
    /// Three offsets including both ends of the interval leave no constant that
    /// fits.
    #[test]
    fn a_refusal_reports_the_exact_remainder() {
        let t0 = 1_700_000_000_000i64;
        for (offset, expected) in [(1i64, 59_999i64), (20_000, 40_000), (59_999, 1)] {
            let mut b = StandaloneAckBudget::new();
            assert_eq!(b.request(t0), AckPermit::Granted);
            assert_eq!(
                b.request(t0 + offset),
                AckPermit::Refused {
                    retry_after_ms: expected
                },
                "at +{offset} ms the remainder must be exactly {expected} ms"
            );
        }
    }

    /// `Default` and [`StandaloneAckBudget::new`] agree.
    ///
    /// Untested, a `Default` impl that pre-spends the allowance is
    /// indistinguishable from the derive — and `Default` is one of the ways a
    /// caller can mint a budget.
    #[test]
    fn default_is_an_unspent_budget_like_new() {
        assert_eq!(StandaloneAckBudget::default(), StandaloneAckBudget::new());

        let mut d = StandaloneAckBudget::default();
        assert_eq!(
            d.request(1_700_000_000_000),
            AckPermit::Granted,
            "a defaulted budget must grant its first request, exactly as a new one does"
        );
    }

    /// The boundary is inclusive: exactly one interval later is a grant, not a
    /// refusal by one millisecond.
    #[test]
    fn the_interval_boundary_grants() {
        let t0 = 1_700_000_000_000i64;
        let mut b = StandaloneAckBudget::new();
        assert_eq!(b.request(t0), AckPermit::Granted);

        assert!(matches!(
            b.request(t0 + STANDALONE_ACK_MIN_INTERVAL_MS - 1),
            AckPermit::Refused { .. }
        ));
        assert_eq!(
            b.request(t0 + STANDALONE_ACK_MIN_INTERVAL_MS),
            AckPermit::Granted
        );
    }

    /// A refusal spends nothing, so being refused repeatedly does not push the
    /// next allowance further away.
    #[test]
    fn a_refusal_does_not_spend_the_allowance() {
        let t0 = 1_700_000_000_000i64;
        let mut b = StandaloneAckBudget::new();
        assert_eq!(b.request(t0), AckPermit::Granted);

        for ms in (1_000..60_000).step_by(1_000) {
            assert!(matches!(b.request(t0 + ms), AckPermit::Refused { .. }));
        }
        assert_eq!(
            b.request(t0 + STANDALONE_ACK_MIN_INTERVAL_MS),
            AckPermit::Granted,
            "the allowance renews an interval after the GRANT, not after the last refusal"
        );
    }

    /// **The property the type exists for**: many conversations draining at once
    /// share one allowance, so the aggregate rate is the budget and not a
    /// multiple of it.
    ///
    /// This is the case a per-channel interval gets wrong — `N` channels at one
    /// interval each permit `N` writes per interval. Both counts are asserted:
    /// without the refusal count the test would pass just as happily against a
    /// limiter that refused everything.
    #[test]
    fn many_channels_draining_together_do_not_exceed_one_allowance() {
        let t0 = 1_700_000_000_000i64;
        const CHANNELS: usize = 5;
        const MINUTES: i64 = 5;

        let mut budget = StandaloneAckBudget::new();
        let mut grants_at = Vec::new();
        let mut refused = 0usize;

        // Every channel wants to acknowledge every second for five minutes.
        for second in 0..(MINUTES * 60) {
            for _channel in 0..CHANNELS {
                let now = t0 + second * 1_000;
                match budget.request(now) {
                    AckPermit::Granted => grants_at.push(now - t0),
                    AckPermit::Refused { .. } => refused += 1,
                }
            }
        }

        // The timestamps, not merely the count. A count of five over five
        // minutes is satisfied by any interval between 60_001 and roughly
        // 74_000 ms, and by a limiter that counts calls and never reads the
        // clock at all — both wrong, both invisible to `granted == 5`.
        assert_eq!(
            grants_at,
            vec![0, 60_000, 120_000, 180_000, 240_000],
            "grants must land one per minute on the interval, not merely total five"
        );
        assert_eq!(
            refused,
            CHANNELS * (MINUTES * 60) as usize - grants_at.len(),
            "every request that was not granted must have been refused; a count that \
             does not add up means requests went unaccounted for"
        );
        assert!(
            refused > 0,
            "with no refusals this test would pass against a limiter that grants \
             everything, which is the thing it exists to catch"
        );
    }

    /// A clock that goes backwards refuses, and reports the whole wait rather
    /// than a capped one.
    ///
    /// The exact value is asserted, not a range: a range check between zero and
    /// one interval accepts almost any wrong answer, and it would have accepted
    /// the capped 60 000 this test exists to rule out. Ten seconds back means
    /// seventy seconds to wait, and saying sixty would cost the caller ten
    /// wasted wakeups.
    #[test]
    fn a_backwards_clock_refuses_and_reports_the_whole_wait() {
        let t0 = 1_700_000_000_000i64;
        let mut b = StandaloneAckBudget::new();
        assert_eq!(b.request(t0), AckPermit::Granted);

        assert_eq!(
            b.request(t0 - 10_000),
            AckPermit::Refused {
                retry_after_ms: 70_000
            },
            "a step back must not renew the allowance, and must not understate the wait"
        );
    }

    /// The saturating arithmetic holds at the extremes of the clock type rather
    /// than overflowing into a grant.
    #[test]
    fn extreme_clock_values_do_not_overflow_into_a_grant() {
        let mut b = StandaloneAckBudget::new();
        assert_eq!(b.request(i64::MAX), AckPermit::Granted);
        assert_eq!(
            b.request(i64::MIN),
            AckPermit::Refused {
                retry_after_ms: i64::MAX
            },
            "the widest possible step back saturates to the largest representable \
             wait, rather than wrapping into a grant"
        );
    }
}
