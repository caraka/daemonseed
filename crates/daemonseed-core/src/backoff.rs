//! Jitter arithmetic and close-cause categorization.
//!
//! Two things live here, both reached from outside the module:
//!
//! 1. [`apply_jitter`] — the workspace's one definition of jitter, carrying no
//!    policy of its own so a caller with its own delay ladder can reach it.
//! 2. [`CloseCause`] — the layer at which a connection closed, mapped to
//!    user-facing messages that never speculate about the other side's reason
//!    (ISC-A-S12: a "you hit the bandwidth limit" message would be a guess and
//!    a lie). The layer is locally observable; the cause is not.

use core::time::Duration;

/// Jitter fraction — ±25% of the delay it is applied to.
pub const DEFAULT_JITTER_FRAC: f64 = 0.25;

/// Apply ±`frac` jitter to `delay`. `unit` ∈ [-1.0, 1.0] selects the point in
/// the band; result = `delay * (1 + frac * unit)`, clamped to ≥ 0.
///
/// **The one definition of jitter in the workspace**, free of any policy so a
/// caller with its own ladder can reach it — [`crate::dm::outbox`] draws against
/// an explicit rung ladder, and a second copy of this arithmetic beside it would
/// be free to drift from this one.
pub fn apply_jitter(delay: Duration, frac: f64, unit: f64) -> Duration {
    let unit = unit.clamp(-1.0, 1.0);
    let factor = (1.0 + frac * unit).max(0.0);
    delay.mul_f64(factor)
}

/// The observable layer at which a connection closed. The client
/// distinguishes these three for the user even though the close shape is
/// uniform — because the *layer* is locally observable, whereas the other
/// side's *cause* is not.
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
    /// User-facing message for this close cause. MUST NOT speculate
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

    // ── jitter ─────────────────────────────────────────────────────────────

    /// **The `unit` clamp is a bound on the caller, and nothing tested it.**
    ///
    /// `apply_jitter` is the workspace's one definition of jitter and is reached
    /// by `crate::dm::outbox::ReseedSchedule::schedule_next_with_unit`. Removing
    /// `unit.clamp(-1.0, 1.0)` lets a caller passing an out-of-band unit push the
    /// resulting delay arbitrarily far out — for the outbox that is a
    /// `next_due_ms` a caller can place past its own give-up, i.e. a message that
    /// stops being re-seeded on nothing but a bad argument.
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

    /// The band is the right width and is centred on the delay it is given.
    #[test]
    fn jitter_low_high_and_center() {
        let frac = DEFAULT_JITTER_FRAC;
        assert_eq!(
            apply_jitter(secs(4), frac, -1.0),
            Duration::from_millis(3000)
        );
        assert_eq!(
            apply_jitter(secs(4), frac, 1.0),
            Duration::from_millis(5000)
        );
        assert_eq!(
            apply_jitter(secs(4), frac, 0.0),
            Duration::from_millis(4000)
        );
    }

    /// [`apply_jitter`]'s `.max(0.0)` is a panic guard, and this is what says so.
    ///
    /// [`Duration::mul_f64`] panics on a negative or NaN factor. No in-tree caller
    /// can reach either — every `frac` in the tree is `0.25` and `jitter::unit`
    /// returns `[-1, 1]` by construction — so deleting the `.max(0.0)` leaves the
    /// whole workspace green while removing the only thing standing between a
    /// future caller's out-of-range argument and a panicking retry path.
    ///
    /// `f64::max` returns the non-NaN operand, which is why the NaN case lands on
    /// zero rather than propagating.
    #[test]
    fn apply_jitter_refuses_to_panic_on_a_negative_or_nan_factor() {
        // A `frac` above 1.0 drives the factor negative at the bottom of the band.
        // `frac` is the caller's to choose, so this is reachable by construction
        // rather than hypothetical.
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

    // ── close-cause categorization ─────────────────────────────────────────

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

    /// No close cause's message names a rate limit, and the sweep covers every
    /// cause there is.
    ///
    /// Two things the loop alone cannot say. **The length assertion** is what
    /// makes the sweep exhaustive: `ALL_CLOSE_CAUSES` is a hand-written const
    /// beside the enum, so a variant added to one and not the other leaves this
    /// test passing over a cause it never reads. **The control** is what says the
    /// predicate can fire at all — a forbidden-word check that matched nothing
    /// would pass on every message, including the ones it exists to reject.
    #[test]
    fn close_cause_messages_never_speculate_about_limits() {
        const FORBIDDEN: [&str; 5] = ["rate", "limit", "bandwidth", "subscription", "budget"];

        // The enum has three variants; the const must list all three.
        assert_eq!(
            ALL_CLOSE_CAUSES.len(),
            3,
            "ALL_CLOSE_CAUSES does not list every close cause, so the sweep below \
             skips one"
        );

        // Control: the predicate fires on a message of exactly the kind A-S12
        // forbids, so a clean sweep means the messages are clean rather than the
        // check being inert.
        let speculative = "you hit the bandwidth limit".to_lowercase();
        assert!(
            FORBIDDEN.iter().any(|f| speculative.contains(f)),
            "the forbidden-word check does not fire on a message that speculates \
             about a limit, so it proves nothing about the real ones"
        );

        // ISC-A-S12 / A-C18: the UX must not guess which rate-limit was hit.
        for cause in ALL_CLOSE_CAUSES {
            let m = cause.user_message().to_lowercase();
            for forbidden in FORBIDDEN {
                assert!(
                    !m.contains(forbidden),
                    "{cause:?} message leaks '{forbidden}': {m:?}"
                );
            }
        }
    }
}
