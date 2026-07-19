//! An AIMD (additive-increase / multiplicative-decrease) window controller for
//! the fetcher-side adaptive concurrency (#128 D-1/D-2). The fetch in-flight
//! window climbs by one per healthy observation and halves on a latency breach —
//! the classic congestion-control response — bounded to `[floor, ceiling]`. The
//! ceiling is the static #109/#113 concurrency cap (which becomes the MAXIMUM);
//! the floor keeps at least one request in flight so a fetch never stalls to zero.
//!
//! The controller is **signal-agnostic and clock-free**: it consumes latency
//! observations (the injectable interactive-latency / congestion signal, #128) and
//! never reads a clock itself, so it is deterministically unit-testable with
//! synthetic samples — no fake-clock harness needed, the injected `Duration` *is*
//! the fake clock.
//!
//! **Live-wired at two fetch levels.** The GUI share fetcher drives one
//! controller per download at each level, both fed the per-chunk max-fragment
//! latency against `FRAGMENT_LATENCY_THRESHOLD`:
//!   - the **fragment** window (`new`, opens at the static ceiling — #128 D-1,
//!     commit `4e4aba6`), and
//!   - the **chunk** window (`slow_start`, opens gentle and climbs — #128 D-2,
//!     #204): a folder download's dominant fanout is chunks-per-file, and a cold
//!     open at the full ceiling can kill the fetch route under a sustained wide
//!     fanout before the controller ever sees a healthy sample (observed on
//!     Windows folder downloads). Slow-start opens below the ceiling so the route
//!     is never hit with a fanout it can't survive.

use std::time::Duration;

/// An AIMD fetch-concurrency window controller. See the module docs.
#[derive(Debug, Clone, Copy)]
pub struct AimdWindow {
    window: usize,
    floor: usize,
    ceiling: usize,
}

impl AimdWindow {
    /// A controller bounded to `[floor, ceiling]`, starting fully open at
    /// `ceiling` (the current static cap) so behaviour is unchanged until the
    /// first breach. `ceiling` is forced to at least 1; `floor` is clamped into
    /// `[1, ceiling]`.
    pub fn new(floor: usize, ceiling: usize) -> Self {
        let ceiling = ceiling.max(1);
        let floor = floor.clamp(1, ceiling);
        Self {
            window: ceiling,
            floor,
            ceiling,
        }
    }

    /// A *slow-starting* controller: it opens at `start` (clamped into
    /// `[floor, ceiling]`) rather than at the ceiling, then climbs additively
    /// while healthy. Use this where a cold fanout at the full ceiling would
    /// itself cause the breach it should avoid — a fetch route that dies under a
    /// sustained wide fanout before the controller ever observes a healthy sample
    /// (#204: Windows folder downloads). `new` (open-at-ceiling) stays the default
    /// where the ceiling is known-safe and slow-start would only cost warm-up.
    pub fn slow_start(start: usize, floor: usize, ceiling: usize) -> Self {
        let ceiling = ceiling.max(1);
        let floor = floor.clamp(1, ceiling);
        let window = start.clamp(floor, ceiling);
        Self {
            window,
            floor,
            ceiling,
        }
    }

    /// The current in-flight window — what a fetch passes as its concurrency cap.
    pub fn window(&self) -> usize {
        self.window
    }

    /// Additive-increase: one healthy step widens the window by 1, capped at the
    /// ceiling.
    pub fn on_healthy(&mut self) {
        self.window = self.window.saturating_add(1).min(self.ceiling);
    }

    /// Multiplicative-decrease: a breach halves the window, floored.
    pub fn on_breach(&mut self) {
        self.window = (self.window / 2).max(self.floor);
    }

    /// Feed one latency observation against `threshold`: at or over `threshold`
    /// is a breach (halve), under is healthy (climb). This is the injectable-signal
    /// entry point the oracle drives with synthetic samples.
    pub fn observe(&mut self, latency: Duration, threshold: Duration) {
        if latency >= threshold {
            self.on_breach();
        } else {
            self.on_healthy();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_open_at_ceiling_and_clamps_the_floor() {
        assert_eq!(AimdWindow::new(2, 8).window(), 8, "starts fully open");
        // A floor below 1 is clamped UP to 1 — breaching all the way down must floor
        // at 1, never 0 (a 0 floor would stall a wired fetch at zero concurrency).
        // Drive breaches, not just the initial window, so the clamp is exercised.
        let mut low = AimdWindow::new(0, 8);
        for _ in 0..10 {
            low.on_breach();
        }
        assert_eq!(
            low.window(),
            1,
            "floor clamped up to 1; breaches never reach 0"
        );
        // A floor above the ceiling is clamped DOWN to the ceiling.
        let mut z = AimdWindow::new(99, 4);
        for _ in 0..10 {
            z.on_breach();
        }
        assert_eq!(
            z.window(),
            4,
            "a floor clamped to the ceiling never drops below it"
        );
    }

    #[test]
    fn a_breach_halves_and_recovery_climbs_within_bounds() {
        let mut w = AimdWindow::new(1, 8); // window starts at 8
        w.on_breach();
        assert_eq!(w.window(), 4);
        w.on_breach();
        assert_eq!(w.window(), 2);
        w.on_breach();
        assert_eq!(w.window(), 1);
        w.on_breach();
        assert_eq!(w.window(), 1, "never below the floor");
        w.on_healthy();
        assert_eq!(w.window(), 2, "additive-increase by one");
        w.on_healthy();
        assert_eq!(w.window(), 3);
        for _ in 0..100 {
            w.on_healthy();
        }
        assert_eq!(w.window(), 8, "never above the ceiling");
    }

    #[test]
    fn observe_routes_a_latency_sample_against_the_threshold() {
        let mut w = AimdWindow::new(1, 8);
        let threshold = Duration::from_millis(200);
        // At or over the threshold is a breach.
        w.observe(Duration::from_millis(200), threshold);
        assert_eq!(w.window(), 4, "at-threshold latency breaches");
        w.observe(Duration::from_millis(500), threshold);
        assert_eq!(w.window(), 2);
        // Under the threshold climbs.
        w.observe(Duration::from_millis(10), threshold);
        assert_eq!(w.window(), 3);
    }

    #[test]
    fn slow_start_opens_below_the_ceiling_and_climbs() {
        let mut w = AimdWindow::slow_start(2, 1, 8);
        assert_eq!(
            w.window(),
            2,
            "opens at the slow-start value, not the ceiling"
        );
        w.on_healthy();
        assert_eq!(w.window(), 3, "climbs additively from the slow start");
        // `start` is clamped into `[floor, ceiling]`.
        assert_eq!(
            AimdWindow::slow_start(0, 1, 8).window(),
            1,
            "a start below the floor is clamped up to the floor"
        );
        assert_eq!(
            AimdWindow::slow_start(99, 1, 8).window(),
            8,
            "a start above the ceiling is clamped down to the ceiling"
        );
        // A breach still halves and the floor still holds from a slow start.
        let mut w = AimdWindow::slow_start(4, 1, 8);
        w.on_breach();
        assert_eq!(w.window(), 2);
    }
}
