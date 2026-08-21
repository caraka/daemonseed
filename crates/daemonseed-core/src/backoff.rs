//! Client reconnect backoff curve + close-cause categorization (ISC-C26).
//!
//! When a server closes a connection — whether because its rate limiter
//! tripped (ISC-S17), or for any other reason — the close shape is
//! **uniform-by-design** (ISC-A-S12): the client cannot tell *which* budget it
//! exhausted, or even whether a limiter was involved at all. So the client's
//! job is narrow and honest:
//!
//! 1. **Back off** before retrying, on an exponential curve with jitter, so a
//!    population of clients refused at once does not retry in a synchronised
//!    herd. [`Backoff`] owns the per-server-id, per-session retry budget.
//! 2. **Categorise the close by the layer it happened at**, not by a guessed
//!    server-side cause. [`CloseCause`] maps the three observable layers to
//!    user-facing messages that never speculate about rate-limit internals
//!    (ISC-A-S12: a "you hit the bandwidth limit" message would be a guess and
//!    a lie).
//!
//! The backoff state machine is pure: [`Backoff::next`] takes a jitter `unit`
//! so tests are deterministic; [`Backoff::next_jittered`] is the runtime path
//! that samples the unit from the OS CSPRNG.

use core::time::Duration;

use crate::trust_events::TrustEventKey;

/// Base (first-retry) delay (ISC-C26).
pub const DEFAULT_BASE: Duration = Duration::from_secs(1);
/// Maximum delay the exponential curve saturates at (ISC-C26).
pub const DEFAULT_CAP: Duration = Duration::from_secs(60);
/// Retry budget per server-id per session before auto-retry pauses (ISC-C26).
pub const DEFAULT_MAX_RETRIES: u32 = 8;
/// Jitter fraction — ±25% applied at each step (ISC-C26).
pub const DEFAULT_JITTER_FRAC: f64 = 0.25;

/// Tunable backoff curve parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub cap: Duration,
    pub max_retries: u32,
    pub jitter_frac: f64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: DEFAULT_BASE,
            cap: DEFAULT_CAP,
            max_retries: DEFAULT_MAX_RETRIES,
            jitter_frac: DEFAULT_JITTER_FRAC,
        }
    }
}

impl BackoffPolicy {
    /// Deterministic (un-jittered) delay before retry `attempt` (0-based):
    /// `min(cap, base * 2^attempt)`. Saturates rather than overflowing.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        // 2^attempt as u128, saturating well before the shift would overflow.
        let factor: u128 = if attempt >= 127 {
            u128::MAX
        } else {
            1u128 << attempt
        };
        let scaled_ms = self.base.as_millis().saturating_mul(factor);
        let ms = scaled_ms.min(self.cap.as_millis());
        Duration::from_millis(ms as u64)
    }

    /// Apply ±`jitter_frac` jitter to `delay`. `unit` ∈ [-1.0, 1.0] selects the
    /// point in the jitter band; result = `delay * (1 + jitter_frac * unit)`,
    /// clamped to ≥ 0.
    pub fn jitter(&self, delay: Duration, unit: f64) -> Duration {
        apply_jitter(delay, self.jitter_frac, unit)
    }
}

/// Apply ±`frac` jitter to `delay`. `unit` ∈ [-1.0, 1.0] selects the point in
/// the band; result = `delay * (1 + frac * unit)`, clamped to ≥ 0.
///
/// **The one definition of jitter in the workspace**, free of any policy so a
/// caller with its own curve can reach it — [`crate::dm::outbox`] has an explicit
/// rung ladder rather than an exponential one, and a second copy of this
/// arithmetic beside it would be drift in the shape the DM design's own build
/// notes keep recording.
pub fn apply_jitter(delay: Duration, frac: f64, unit: f64) -> Duration {
    let unit = unit.clamp(-1.0, 1.0);
    let factor = (1.0 + frac * unit).max(0.0);
    delay.mul_f64(factor)
}

/// Per-server-id, per-session reconnect state (ISC-C26).
#[derive(Debug, Clone)]
pub struct Backoff {
    policy: BackoffPolicy,
    attempts: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    /// Fresh backoff with the default policy.
    pub fn new() -> Self {
        Self::with_policy(BackoffPolicy::default())
    }

    /// Fresh backoff with a custom policy.
    pub fn with_policy(policy: BackoffPolicy) -> Self {
        Self {
            policy,
            attempts: 0,
        }
    }

    /// Number of retries already consumed this session.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Whether the retry budget is exhausted — the client should surface the
    /// "server unreachable or rate-limiting you" UX and stop auto-retrying
    /// until the user explicitly retries (ISC-C26).
    pub fn exhausted(&self) -> bool {
        self.attempts >= self.policy.max_retries
    }

    /// Reset on a successful connection.
    pub fn reset(&mut self) {
        self.attempts = 0;
    }

    /// Delay before the next retry given jitter `unit` ∈ [-1.0, 1.0]; `None`
    /// once the budget is exhausted. Consumes one retry from the budget.
    pub fn next(&mut self, unit: f64) -> Option<Duration> {
        if self.exhausted() {
            return None;
        }
        let delay = self.policy.delay_for_attempt(self.attempts);
        self.attempts += 1;
        Some(self.policy.jitter(delay, unit))
    }

    /// Runtime path: same as [`Backoff::next`] but samples the jitter unit from
    /// the OS CSPRNG. A CSPRNG read failure degrades to no jitter (the
    /// deterministic curve) rather than failing the retry.
    pub fn next_jittered(&mut self) -> Option<Duration> {
        self.next(crate::jitter::unit())
    }

    /// The trust event to emit on a connection refusal in the current state
    /// (ISC-C26 / ISC-C28): [`TrustEventKey::ConnectionRateLimited`] (Transient)
    /// while retries remain, [`TrustEventKey::ConnectionRateLimitedExhausted`]
    /// (PersistentNonBlocking) once the budget is spent.
    pub fn refusal_event(&self) -> TrustEventKey {
        if self.exhausted() {
            TrustEventKey::ConnectionRateLimitedExhausted
        } else {
            TrustEventKey::ConnectionRateLimited
        }
    }
}

/// The observable layer at which a connection closed (ISC-C26). The client
/// distinguishes these three for the user even though the server's close shape
/// is uniform — because the *layer* is locally observable, whereas the
/// server-side *cause* is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCause {
    /// DNS / TCP RST / TLS handshake failure — never reached the application.
    NetworkFailure,
    /// Application-level close before APP_HELLO_ACK.
    RefusedBeforeHelloAck,
    /// Application-level close after a successful identity-proof.
    ClosedAfterAuth,
}

/// Every close cause, for exhaustiveness tests.
pub const ALL_CLOSE_CAUSES: &[CloseCause] = &[
    CloseCause::NetworkFailure,
    CloseCause::RefusedBeforeHelloAck,
    CloseCause::ClosedAfterAuth,
];

impl CloseCause {
    /// User-facing message for this close cause (ISC-C26). MUST NOT speculate
    /// about which rate-limit (if any) was hit — the close is non-informative
    /// by ISC-A-S12 design.
    pub fn user_message(&self) -> &'static str {
        match self {
            CloseCause::NetworkFailure => "Unable to reach server",
            CloseCause::RefusedBeforeHelloAck => "Server refused the connection",
            CloseCause::ClosedAfterAuth => "Server closed the connection unexpectedly",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    // ── exponential curve (ISC-C26 backoff) ────────────────────────────────

    #[test]
    fn delay_curve_doubles_from_one_second_capped_at_sixty() {
        let p = BackoffPolicy::default();
        assert_eq!(p.delay_for_attempt(0), secs(1));
        assert_eq!(p.delay_for_attempt(1), secs(2));
        assert_eq!(p.delay_for_attempt(2), secs(4));
        assert_eq!(p.delay_for_attempt(3), secs(8));
        assert_eq!(p.delay_for_attempt(4), secs(16));
        assert_eq!(p.delay_for_attempt(5), secs(32));
        assert_eq!(p.delay_for_attempt(6), secs(60)); // 64 capped to 60
        assert_eq!(p.delay_for_attempt(7), secs(60));
    }

    #[test]
    fn delay_curve_saturates_on_huge_attempt() {
        let p = BackoffPolicy::default();
        assert_eq!(p.delay_for_attempt(1000), secs(60));
    }

    // ── jitter (ISC-C26 ±25%) ──────────────────────────────────────────────

    #[test]
    fn jitter_low_high_and_center() {
        let p = BackoffPolicy::default();
        assert_eq!(p.jitter(secs(4), -1.0), Duration::from_millis(3000));
        assert_eq!(p.jitter(secs(4), 1.0), Duration::from_millis(5000));
        assert_eq!(p.jitter(secs(4), 0.0), Duration::from_millis(4000));
    }

    /// **The `unit` clamp is a bound on the caller, and nothing tested it.**
    ///
    /// `apply_jitter` is the workspace's one definition of jitter and is reached
    /// by `crate::dm::outbox::ReseedSchedule::schedule_next_with_unit` as well as by
    /// [`BackoffPolicy::jitter`]. Removing `unit.clamp(-1.0, 1.0)` lets a caller
    /// passing an out-of-band unit push the resulting delay arbitrarily far out
    /// — for the outbox that is a `next_due_ms` a caller can place past its own
    /// give-up, i.e. a message that stops being re-seeded on nothing but a bad
    /// argument.
    #[test]
    fn jitter_clamps_a_unit_outside_the_band() {
        let frac = DEFAULT_JITTER_FRAC;
        // Past the top of the band, the result stops moving.
        assert_eq!(
            apply_jitter(secs(4), frac, 5.0),
            apply_jitter(secs(4), frac, 1.0)
        );
        assert_eq!(apply_jitter(secs(4), frac, 1e9), secs(5));
        // And past the bottom.
        assert_eq!(
            apply_jitter(secs(4), frac, -5.0),
            apply_jitter(secs(4), frac, -1.0)
        );
        assert_eq!(apply_jitter(secs(4), frac, -1e9), secs(3));
        // Positive control: inside the band the unit still moves the result, so
        // these assertions are not passing because jitter does nothing at all.
        assert_ne!(
            apply_jitter(secs(4), frac, 1.0),
            apply_jitter(secs(4), frac, 0.0),
            "jitter is inert, so the clamp assertions above prove nothing"
        );
    }

    #[test]
    fn jitter_stays_within_band() {
        let p = BackoffPolicy::default();
        let base = secs(8);
        for unit in [-1.0, -0.5, 0.0, 0.5, 1.0] {
            let j = p.jitter(base, unit);
            assert!(j >= Duration::from_millis(6000), "unit {unit}: {j:?}");
            assert!(j <= Duration::from_millis(10000), "unit {unit}: {j:?}");
        }
    }

    // ── retry budget (ISC-C26) ─────────────────────────────────────────────

    #[test]
    fn budget_allows_eight_then_pauses() {
        let mut b = Backoff::new();
        for i in 0..8 {
            assert!(b.next(0.0).is_some(), "retry {i} should be allowed");
        }
        assert!(b.exhausted());
        assert!(b.next(0.0).is_none(), "9th retry must be refused");
    }

    #[test]
    fn reset_restores_budget() {
        let mut b = Backoff::new();
        for _ in 0..8 {
            b.next(0.0);
        }
        assert!(b.exhausted());
        b.reset();
        assert!(!b.exhausted());
        assert!(b.next(0.0).is_some());
    }

    #[test]
    fn next_follows_the_curve() {
        let mut b = Backoff::new();
        assert_eq!(b.next(0.0), Some(secs(1)));
        assert_eq!(b.next(0.0), Some(secs(2)));
        assert_eq!(b.next(0.0), Some(secs(4)));
    }

    /// The jitter band is the right WIDTH and is centred on the curve.
    ///
    /// [`next_jittered_stays_in_band_and_respects_budget`](Self::next_jittered_stays_in_band_and_respects_budget)
    /// asserts each draw lands inside `base ± 25%` and that the budget runs out.
    /// A range check cannot see band width, so three mutations to
    /// [`Backoff::next_jittered`] survive it, and this test carries one assertion
    /// against each:
    ///
    /// - **width** — scaling the drawn unit to a tenth collapses the band to ±2.5%
    ///   while every draw still sits inside the ±25% window. A collapsed-but-nonzero
    ///   band is phase-lock in practice, the whole thing the jitter exists to
    ///   prevent, and no "is it moving at all" check can see it.
    /// - **centring** — taking the unit's absolute value halves the width AND
    ///   pushes every retry systematically later than the curve. A spread floor
    ///   alone would pass it.
    /// - **population** — `unit().signum()` pins every draw to one of the two band
    ///   EDGES. It spans the full band and its edges straddle the curve, so it
    ///   satisfies both of the above while being *worse* than the collapse they
    ///   catch: a refused population splits into two synchronised herds instead of
    ///   one.
    ///
    /// The first two are the assertions the outbox grew for the same reason (#280).
    ///
    /// This draws 64 fresh first-attempt delays rather than walking the budget:
    /// the unit comes from the CSPRNG, so the only assertable facts are
    /// distributional and need a batch at ONE rung. The rungs a single session
    /// walks are covered by
    /// [`next_jittered_varies_within_one_session`](Self::next_jittered_varies_within_one_session),
    /// and the saturated rung by
    /// [`next_jittered_keeps_its_band_at_the_saturated_rung`](Self::next_jittered_keeps_its_band_at_the_saturated_rung).
    ///
    /// Not flaky, and the margin is not a guess: for 64 i.i.d. uniform draws the
    /// probability of spanning less than half the band is ~3.5e-18, and of landing
    /// entirely on one side ~1.1e-19. Both mutations named above are killed
    /// *deterministically* rather than probabilistically — the ±2.5% band is
    /// entirely below the floor, and `abs()` makes `lo < base_ns` unsatisfiable.
    #[test]
    fn next_jittered_spans_the_band_and_is_centred_on_the_curve() {
        const DRAWS: usize = 64;
        let base = BackoffPolicy::default().delay_for_attempt(0);
        let base_ns = base.as_nanos();

        let mut draws = Vec::with_capacity(DRAWS);
        for _ in 0..DRAWS {
            // A fresh budget each time, so every draw is attempt 0 and they are
            // directly comparable — walking the curve would confound width with
            // the doubling.
            let mut b = Backoff::new();
            draws.push(
                b.next_jittered()
                    .expect("first retry is within budget")
                    .as_nanos(),
            );
        }

        let lo = *draws.iter().min().expect("DRAWS is non-zero");
        let hi = *draws.iter().max().expect("DRAWS is non-zero");

        // Width. The full band is ±25% of the base, i.e. half of it. The floor is
        // half the band rather than a third: a third only kills a jitter scaled
        // below ~0.34, so a "tuned down" ±10% would survive, and half raises that
        // to ~0.52 at a false-failure probability of 3.5e-18. The stricter floor
        // is free.
        let band_ns = base_ns / 2;
        assert!(
            hi - lo > band_ns / 2,
            "{DRAWS} draws spanned only {} ns of the {band_ns} ns band — the jitter \
             is scaled down, not absent, which the in-band check cannot see",
            hi - lo
        );

        // Centring. A unit confined to one sign keeps half the width and drifts
        // every retry the same direction, which the spread floor alone would pass.
        assert!(
            lo < base_ns && hi > base_ns,
            "every draw fell on one side of the un-jittered {base_ns} ns curve: \
             [{lo}, {hi}] — the unit is not centred on zero"
        );

        // Population. The two assertions above read only `min` and `max`, so a
        // two-point distribution at the band edges satisfies both while being
        // strictly worse than the collapse they exist to catch. A continuous draw
        // gives 64 distinct nanosecond values here — the band holds ~5e8 of them,
        // so a collision is not a tail this suite meets — and any low-cardinality
        // mutation falls off a cliff to a handful.
        let distinct: std::collections::BTreeSet<u128> = draws.iter().copied().collect();
        assert!(
            distinct.len() > DRAWS / 2,
            "{DRAWS} draws produced only {} distinct delays — the unit is \
             quantised rather than continuous, which spanning the band and \
             straddling the curve cannot see",
            distinct.len()
        );
    }

    /// Jitter still applies once the curve saturates at [`DEFAULT_CAP`].
    ///
    /// Attempts 6 and up all carry the same 60 s un-jittered delay, and those are
    /// precisely the rungs where a refused population is largest — everyone still
    /// retrying a long outage is sitting on them. A mutation that skipped jitter at
    /// the cap (`if delay >= cap { 0.0 }`) is invisible to the first-rung batch
    /// above, and the in-band check cannot see it either, since the bare 60 s sits
    /// inside its own `[45 s, 75 s]` window.
    #[test]
    fn next_jittered_keeps_its_band_at_the_saturated_rung() {
        const DRAWS: usize = 64;
        const SATURATED: u32 = 6;
        let policy = BackoffPolicy::default();
        let base = policy.delay_for_attempt(SATURATED);
        assert_eq!(base, DEFAULT_CAP, "attempt {SATURATED} should be saturated");
        let base_ns = base.as_nanos();

        let mut draws = Vec::with_capacity(DRAWS);
        for _ in 0..DRAWS {
            let mut b = Backoff::new();
            // Walk to the saturated rung on the deterministic door, so the only
            // jittered draw is the one being measured.
            for _ in 0..SATURATED {
                b.next(0.0).expect("within budget");
            }
            draws.push(
                b.next_jittered()
                    .expect("attempt 6 is within the budget of 8")
                    .as_nanos(),
            );
        }

        let lo = *draws.iter().min().expect("DRAWS is non-zero");
        let hi = *draws.iter().max().expect("DRAWS is non-zero");
        let band_ns = base_ns / 2;
        assert!(
            hi - lo > band_ns / 2,
            "at the saturated rung {DRAWS} draws spanned only {} ns of the \
             {band_ns} ns band",
            hi - lo
        );
        assert!(
            lo < base_ns && hi > base_ns,
            "at the saturated rung every draw fell on one side of {base_ns} ns: \
             [{lo}, {hi}]"
        );
    }

    /// One session's retries are jittered independently of each other.
    ///
    /// Every other test here uses a fresh [`Backoff`] per draw, which cannot see
    /// state-dependence, and two mutations live in exactly that blind spot:
    ///
    /// - jitter applied only to the first retry — the batch tests are all attempt
    ///   0, and the later bare rungs still land inside the in-band check.
    /// - one unit drawn per [`Backoff`] and reused for all eight rungs, which is
    ///   session-level phase-lock: a client's whole retry sequence sits at the same
    ///   offset in the band. Sixty-four instances show full spread, so no batch
    ///   test can see it.
    ///
    /// Both are caught by walking ONE budget and comparing each rung against its
    /// own un-jittered delay.
    #[test]
    fn next_jittered_varies_within_one_session() {
        let policy = BackoffPolicy::default();
        let mut b = Backoff::new();

        let mut offsets = Vec::with_capacity(DEFAULT_MAX_RETRIES as usize);
        for attempt in 0..DEFAULT_MAX_RETRIES {
            let base = policy.delay_for_attempt(attempt);
            let drawn = b.next_jittered().expect("within budget");
            // The jitter factor this rung actually received, recovered by dividing
            // out the rung's own delay so the doubling curve does not confound it.
            offsets.push(drawn.as_nanos() as f64 / base.as_nanos() as f64);
        }

        // Not just the first rung. An exactly-unity factor needs the unit to land
        // exactly on zero, which has probability ~1e-16 per draw, so requiring most
        // of them to be jittered is safe while a first-rung-only mutation leaves
        // exactly one.
        let jittered = offsets.iter().filter(|f| **f != 1.0).count();
        assert!(
            jittered >= offsets.len() - 1,
            "only {jittered} of {} rungs were jittered — the unit is not being \
             drawn on every retry: {offsets:?}",
            offsets.len()
        );

        // And not one draw reused. Identical factors across every rung is a session
        // sitting at a fixed offset in the band for its whole life.
        //
        // **The threshold is load-bearing and a bare `> 0.0` is not.**
        // `delay_for_attempt` returns whole milliseconds and `mul_f64` rounds to
        // whole nanoseconds, so recovering the factor by division carries ~1e-9 of
        // rounding noise — nonzero at every rung even when the unit is genuinely
        // identical. A `> 0.0` assertion is satisfied by that rounding alone, and
        // the cached-unit mutation passes it.
        //
        // The factor band is `2 * jitter_frac` wide, so a fiftieth of it sits six
        // orders above the noise and far below any real spread. For 8 independent
        // draws the chance of spanning less than that is ~1e-11.
        let spread = offsets.iter().copied().fold(f64::NEG_INFINITY, f64::max)
            - offsets.iter().copied().fold(f64::INFINITY, f64::min);
        let factor_band = 2.0 * policy.jitter_frac;
        assert!(
            spread > factor_band / 50.0,
            "every rung in one session drew effectively the identical factor \
             (spread {spread:.3e} against a {factor_band} band) — the unit is \
             cached per Backoff rather than drawn per retry: {offsets:?}"
        );
    }

    /// [`apply_jitter`]'s `.max(0.0)` is a panic guard, and this is what says so.
    ///
    /// [`Duration::mul_f64`] panics on a negative or NaN factor. No in-tree caller
    /// can reach either — every `frac` in the tree is `0.25` and `jitter::unit`
    /// returns `[-1, 1]` by construction — so deleting the `.max(0.0)` leaves the
    /// whole workspace green while removing the only thing standing between a
    /// future caller's out-of-range policy and a panicking retry path.
    ///
    /// `f64::max` returns the non-NaN operand, which is why the NaN case lands on
    /// zero rather than propagating.
    #[test]
    fn apply_jitter_refuses_to_panic_on_a_negative_or_nan_factor() {
        // A `jitter_frac` above 1.0 drives the factor negative at the bottom of the
        // band. `BackoffPolicy::jitter_frac` is public, so this is reachable by
        // construction rather than hypothetical.
        assert_eq!(apply_jitter(secs(4), 2.0, -1.0), Duration::ZERO);
        // And a NaN unit, which `clamp` propagates rather than corrals.
        assert_eq!(
            apply_jitter(secs(4), DEFAULT_JITTER_FRAC, f64::NAN),
            Duration::ZERO
        );

        // Positive control: an ordinary factor is untouched by the guard, so the
        // two assertions above are not passing because the function returns zero
        // for everything.
        assert_eq!(apply_jitter(secs(4), DEFAULT_JITTER_FRAC, 0.0), secs(4));
    }

    #[test]
    fn next_jittered_stays_in_band_and_respects_budget() {
        let mut b = Backoff::new();
        for attempt in 0..8 {
            let base = BackoffPolicy::default().delay_for_attempt(attempt);
            let j = b.next_jittered().expect("within budget");
            let lo = base.mul_f64(0.75);
            let hi = base.mul_f64(1.25);
            assert!(
                j >= lo && j <= hi,
                "attempt {attempt}: {j:?} not in {lo:?}..{hi:?}"
            );
        }
        assert!(b.next_jittered().is_none());
    }

    // ── trust events (ISC-C26 / ISC-C28) ───────────────────────────────────

    #[test]
    fn refusal_event_is_transient_until_exhausted() {
        let mut b = Backoff::new();
        assert_eq!(b.refusal_event(), TrustEventKey::ConnectionRateLimited);
        for _ in 0..8 {
            b.next(0.0);
        }
        assert_eq!(
            b.refusal_event(),
            TrustEventKey::ConnectionRateLimitedExhausted
        );
    }

    // ── close-cause categorization (ISC-C26) ───────────────────────────────

    #[test]
    fn close_cause_messages() {
        assert_eq!(
            CloseCause::NetworkFailure.user_message(),
            "Unable to reach server"
        );
        assert_eq!(
            CloseCause::RefusedBeforeHelloAck.user_message(),
            "Server refused the connection"
        );
        assert_eq!(
            CloseCause::ClosedAfterAuth.user_message(),
            "Server closed the connection unexpectedly"
        );
    }

    #[test]
    fn close_cause_messages_never_speculate_about_limits() {
        // ISC-A-S12 / A-C18: the UX must not guess which rate-limit was hit.
        for cause in ALL_CLOSE_CAUSES {
            let m = cause.user_message().to_lowercase();
            for forbidden in ["rate", "limit", "bandwidth", "subscription", "budget"] {
                assert!(
                    !m.contains(forbidden),
                    "{cause:?} message leaks '{forbidden}': {m:?}"
                );
            }
        }
    }
}
