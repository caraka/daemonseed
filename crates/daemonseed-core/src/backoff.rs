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
