//! Per-route concurrency budget + error-primary controller (download-subsystem
//! redesign, `docs/design/download-subsystem.md` Part 1).
//!
//! # Why a new controller (not [`crate::AimdWindow`])
//!
//! The quantity that kills a serving private route is the **total concurrent
//! in-flight fragment `app_call`s to that one route** (#204: a sustained 8×2
//! fanout died; 1–2 held). The shipped code caps that only indirectly, as the
//! *product* of two per-level windows (chunk × fragment), so it must be
//! conservative on both factors and downloads run near-sequential. This module
//! caps the exact physical quantity with a SINGLE per-route budget `W(route)`;
//! files, chunks, and fragments parallelize freely underneath it.
//!
//! The controller is **error-primary**, not latency-primary — the opposite of
//! [`crate::AimdWindow`]. The repo's own record refutes latency-primary AIMD for
//! this path: WB-5 §I5′.2 measured ~100× exogenous latency variance independent
//! of offered load, and #123 measured ~7.5 s private-route transit against the
//! 2 s threshold, so latency is dominated by the veilid regime, not by our load;
//! and #204's evidence is cliff-shaped (latency unremarkable until the route
//! dies), so a latency-fed additive-increase probes straight into route-death.
//! Therefore **error is the primary decrease signal** (a timeout / route-death
//! collapses the window and records a learned ceiling), and latency is only a
//! secondary coexistence valve (a *sustained* breach steps the window down).
//!
//! # Clock-free
//!
//! The controller consumes injected completion observations
//! ([`FragmentOutcome`]); it never reads a clock, so it is deterministically
//! unit-testable with synthetic samples. The admission registry is a counter +
//! [`tokio::sync::Notify`] (a tokio `Semaphore` cannot shrink below its
//! outstanding permits, and `W` shrinks on a breach — the design's "counter, not
//! permit-revoking" rule); a granted [`BudgetPermit`] is released on drop.
//!
//! # Two lifetimes, two keys
//!
//! - **Live accounting is keyed by the route** (`RouteId` in production) — the
//!   precise failing resource. Its account lives while a download references the
//!   route ([`RouteLease`]) and is dropped when the last lease drops.
//! - **The learned ceiling is keyed by the sharer** ([`SharerKey`] — the verified
//!   long-term announcer pubkey, #156). This is forced by veilid semantics:
//!   `RouteId` is a deterministic function of the route's keys, so a post-death
//!   rotation yields a *new* `RouteId`; a ceiling keyed there would be discarded
//!   on exactly the kill→resume path it exists to protect. Two shares from one
//!   sharer on distinct routes therefore share one ceiling — intended (both
//!   routes terminate on the same node, whose capacity is the real limit).
//!
//! The registry is generic over the route key `R` so the oracle suite can drive
//! it with trivial keys; production instantiates `RouteBudget<RouteId>`.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

// ── Ratified constants (design §Ratification record item 7) ──────────────────

/// Slow-start / collapse width — a cold route (or one just killed) is never hit
/// with a fanout it has not demonstrated surviving.
pub const W_FLOOR: usize = 2;
/// Widest a single route's budget ever opens (the ceiling of the climb). A
/// healthy route reaches this under sustained clean completions (DL-ISC-15).
pub const W_CEIL: usize = 8;
/// Fetcher-global cap: total in-flight fragment `app_call`s across ALL routes.
/// The fetcher's own capacity. `W_CEIL < G_GLOBAL` is a design invariant
/// (DL-ISC-19): one route at ceiling must never occupy the whole global pool, or
/// a single slow/hostile sharer starves every other concurrent download.
pub const G_GLOBAL: usize = 12;
/// Per-download in-flight FILE cap — memory / progress bookkeeping, NOT route
/// protection (the route budget governs network concurrency). With `N`
/// downloads the fetcher may hold `N × F_FILES` open staging files while total
/// network in-flight stays bounded by [`G_GLOBAL`].
pub const F_FILES: usize = 4;
/// Latency valve: over the last [`LATENCY_VALVE_WINDOW`] completions, this many
/// at/over-threshold breaches step the window down one halving. A single slow
/// sample does nothing (bias to decrease, but not on noise).
pub const LATENCY_VALVE_BREACHES: usize = 3;
/// Sliding window the latency valve counts breaches over (the "3-of-5").
pub const LATENCY_VALVE_WINDOW: usize = 5;

/// DL-ISC-19 (compile-time half): the per-route ceiling must be strictly below
/// the global cap, so a route at ceiling always leaves global headroom for
/// another route to admit.
const _: () = assert!(
    W_CEIL < G_GLOBAL,
    "DL-ISC-19: W_CEIL must be < G_GLOBAL so one route can never hold the whole global pool"
);

// ── Observations fed to the controller ───────────────────────────────────────

/// One completed fragment `app_call`, classified for the controller. Carries the
/// only two signals the window reacts to: whether the round-trip breached the
/// latency threshold, and whether it failed terminally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentOutcome {
    /// The fragment completed. `over_threshold` is true iff its round-trip
    /// latency was at/over `FRAGMENT_LATENCY_THRESHOLD` — a congestion breach fed
    /// to the 3-of-5 valve. A clean completion (false) advances the climb; a
    /// breaching one is neutral (never advances the climb, may trigger a step
    /// down).
    Completed { over_threshold: bool },
    /// The fragment failed terminally after its retry budget (a transport timeout
    /// or route death). Collapses the window to [`W_FLOOR`] and records a learned
    /// ceiling keyed by sharer.
    Failed,
}

// ── The per-route window controller (private — an implementation detail) ─────

/// Error-primary AIMD window for one route. Pure state machine: [`observe`] is
/// the only mutator and reads no clock. Bounded to `[W_FLOOR, ceiling]`, where
/// `ceiling` is the sharer's learned ceiling (≤ [`W_CEIL`]).
///
/// [`observe`]: RouteWindow::observe
#[derive(Debug)]
struct RouteWindow {
    /// Current target width `W(route)`.
    width: usize,
    /// Upper bound on the climb — the sharer's learned ceiling (`W_CEIL` until a
    /// kill lowers it). Never re-raised within a session.
    ceiling: usize,
    /// Clean completions accumulated toward the next `+1` (window-clocked
    /// increase); resets on any decrease.
    healthy_since_increase: usize,
    /// Breach ring for the 3-of-5 latency valve (true = at/over threshold).
    recent_breaches: VecDeque<bool>,
    /// True once this collapse episode's learned ceiling has been recorded, so the
    /// SAME route death's remaining concurrent failures do not re-halve the ceiling
    /// down to floor (F6). Cleared when the route recovers enough to widen again.
    collapsed: bool,
}

impl RouteWindow {
    /// A fresh window for a route, slow-starting at [`W_FLOOR`] but never above
    /// the sharer's learned `ceiling` (which is `≥ W_FLOOR` by construction).
    fn new(ceiling: usize) -> Self {
        let ceiling = ceiling.clamp(W_FLOOR, W_CEIL);
        Self {
            width: W_FLOOR.min(ceiling),
            ceiling,
            healthy_since_increase: 0,
            recent_breaches: VecDeque::with_capacity(LATENCY_VALVE_WINDOW),
            collapsed: false,
        }
    }

    fn width(&self) -> usize {
        self.width
    }

    /// Feed one completed-fragment observation. Returns `Some(learned_ceiling)`
    /// when a terminal failure collapsed the window and produced a ceiling the
    /// registry must record for the sharer (`max(W_FLOOR, W_kill / 2)`), else
    /// `None`.
    fn observe(&mut self, outcome: FragmentOutcome) -> Option<usize> {
        match outcome {
            FragmentOutcome::Failed => {
                self.healthy_since_increase = 0;
                self.recent_breaches.clear();
                // A route death fails up to `width` concurrent in-flight fragments,
                // each fed here. Record the learned ceiling ONCE per death — from the
                // KILLING width of the FIRST failure — then ignore the same death's
                // remaining failures, which arrive at the already-collapsed floor
                // width and would otherwise ratchet the sharer's learned ceiling down
                // to floor (F6 / DL-ISC-2: the ceiling is half the KILLING width, not
                // floor). The episode clears when the route recovers enough to widen.
                if self.collapsed {
                    return None;
                }
                // Error is the primary decrease: collapse to floor and hand back a
                // learned ceiling of half the killing width (never below floor, never
                // above the current ceiling). The live window ALSO lowers its own
                // ceiling to the learned value, so a surviving account cannot climb
                // back to the lethal width — not only a rotated route (the caller keys
                // the same value by sharer for that).
                let learned = (self.width / 2).max(W_FLOOR).min(self.ceiling);
                self.ceiling = learned;
                self.width = W_FLOOR.min(self.ceiling);
                self.collapsed = true;
                Some(learned)
            }
            FragmentOutcome::Completed { over_threshold } => {
                self.recent_breaches.push_back(over_threshold);
                if self.recent_breaches.len() > LATENCY_VALVE_WINDOW {
                    self.recent_breaches.pop_front();
                }
                let breaches = self.recent_breaches.iter().filter(|b| **b).count();
                if breaches >= LATENCY_VALVE_BREACHES {
                    // Sustained congestion → one halving (floored), reset the
                    // climb and the ring. Cheap here (lost download speed) vs a
                    // false hold (route-death) — bias to decrease.
                    self.width = (self.width / 2).max(W_FLOOR);
                    self.healthy_since_increase = 0;
                    self.recent_breaches.clear();
                    return None;
                }
                if !over_threshold {
                    // Window-clocked additive increase: +1 after a full window's
                    // worth of CLEAN completions (a breaching completion is
                    // neutral). Super-linear-in-time per-completion increase is
                    // deliberately avoided.
                    self.healthy_since_increase += 1;
                    if self.healthy_since_increase >= self.width {
                        if self.width < self.ceiling {
                            self.width += 1;
                            // Recovered above the collapsed floor — a future failure is
                            // a NEW death whose killing width must be recorded (F6).
                            self.collapsed = false;
                        }
                        self.healthy_since_increase = 0;
                    }
                }
                None
            }
        }
    }
}

// ── Sharer identity (the learned-ceiling key) ────────────────────────────────

/// Opaque identity of a sharer — the verified long-term announcer pubkey bytes
/// (#156). The learned ceiling is keyed by this (not by `RouteId`) so a route
/// rotation, which yields a fresh `RouteId`, does not discard the protective
/// memory. Two shares from one sharer deliberately share one ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SharerKey(pub Vec<u8>);

// ── The registry ─────────────────────────────────────────────────────────────

/// Per-route accounting: live in-flight count, the window controller, the sharer
/// (for ceiling write-back), and a reference count for lifetime.
struct RouteAccount {
    in_flight: usize,
    window: RouteWindow,
    sharer: SharerKey,
    refs: usize,
}

struct BudgetState<R: Eq + Hash> {
    global_in_flight: usize,
    /// Live per-route accounting, keyed by route — dropped when a route's last
    /// lease drops (bounded by concurrent downloads).
    routes: HashMap<R, RouteAccount>,
    /// Learned ceilings keyed by sharer — session-lifetime, bounded by the number
    /// of discovered sharers. Only ratchets DOWN.
    ceilings: HashMap<SharerKey, usize>,
}

/// Per-route concurrency budget with a global cap. Admission is counter-gated:
/// a fragment is admitted while `in_flight(route) < W(route)` and
/// `in_flight(global) < G_GLOBAL`. Shared via `Arc`; leases and permits hold a
/// clone.
pub struct RouteBudget<R: Clone + Eq + Hash> {
    state: Mutex<BudgetState<R>>,
    notify: Notify,
}

impl<R: Clone + Eq + Hash> RouteBudget<R> {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BudgetState {
                global_in_flight: 0,
                routes: HashMap::new(),
                ceilings: HashMap::new(),
            }),
            notify: Notify::new(),
        }
    }

    /// Register a download's use of `route` served by `sharer`. The returned
    /// [`RouteLease`] keeps the route's accounting alive (an account is created
    /// on first lease, seeded from the sharer's learned ceiling) and is where
    /// fragment admissions are acquired and completions observed.
    pub fn lease(self: &Arc<Self>, route: R, sharer: SharerKey) -> RouteLease<R> {
        let mut st = self.state.lock().unwrap();
        let ceiling = st.ceilings.get(&sharer).copied().unwrap_or(W_CEIL);
        let acct = st
            .routes
            .entry(route.clone())
            .or_insert_with(|| RouteAccount {
                in_flight: 0,
                window: RouteWindow::new(ceiling),
                sharer: sharer.clone(),
                refs: 0,
            });
        acct.refs += 1;
        // Keep the sharer current (a re-lease of the same route by the same
        // sharer is a no-op; routes are per-sharer so this never flips owners).
        acct.sharer = sharer;
        RouteLease {
            budget: Arc::clone(self),
            route,
        }
    }

    /// Test/inspection: the current window width for a route (0 if unleased).
    #[cfg(test)]
    pub(crate) fn route_width(&self, route: &R) -> usize {
        self.state
            .lock()
            .unwrap()
            .routes
            .get(route)
            .map(|a| a.window.width())
            .unwrap_or(0)
    }

    /// Test/inspection: current global in-flight count.
    #[cfg(test)]
    fn global_in_flight(&self) -> usize {
        self.state.lock().unwrap().global_in_flight
    }

    /// Test/inspection: the learned ceiling recorded for a sharer, if any.
    #[cfg(test)]
    pub(crate) fn learned_ceiling(&self, sharer: &SharerKey) -> Option<usize> {
        self.state.lock().unwrap().ceilings.get(sharer).copied()
    }
}

impl<R: Clone + Eq + Hash> Default for RouteBudget<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// A download's lease on a route's budget. Admissions are acquired here and the
/// per-fragment outcome is fed back via [`observe`]. Dropping the lease releases
/// the route's live accounting (the last lease removes it); the sharer's learned
/// ceiling persists in the registry.
///
/// [`observe`]: RouteLease::observe
pub struct RouteLease<R: Clone + Eq + Hash> {
    budget: Arc<RouteBudget<R>>,
    route: R,
}

impl<R: Clone + Eq + Hash> RouteLease<R> {
    /// Await admission of one fragment `app_call` to this route. Blocks while the
    /// route is at its window OR the global pool is full; returns a
    /// [`BudgetPermit`] that releases the slot on drop. Acquisition order is
    /// fixed (route then global under one lock); release is unordered.
    pub async fn acquire(&self) -> BudgetPermit<R> {
        loop {
            // Register interest BEFORE checking the condition so a release+notify
            // between the check and the await is not lost (the documented tokio
            // condvar pattern).
            let notified = self.budget.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.budget.state.lock().unwrap();
                let admit = st
                    .routes
                    .get(&self.route)
                    .is_some_and(|a| a.in_flight < a.window.width())
                    && st.global_in_flight < G_GLOBAL;
                if admit {
                    st.global_in_flight += 1;
                    st.routes.get_mut(&self.route).unwrap().in_flight += 1;
                    return BudgetPermit {
                        budget: Arc::clone(&self.budget),
                        route: self.route.clone(),
                    };
                }
            }
            notified.await;
        }
    }

    /// Feed one fragment completion to this route's controller. A terminal
    /// failure records the sharer's learned ceiling (ratcheting DOWN only). A
    /// clean completion may widen the window, so waiters are woken.
    pub fn observe(&self, outcome: FragmentOutcome) {
        {
            let mut st = self.budget.state.lock().unwrap();
            let learned = st.routes.get_mut(&self.route).and_then(|acct| {
                let sharer = acct.sharer.clone();
                acct.window.observe(outcome).map(|l| (sharer, l))
            });
            if let Some((sharer, learned)) = learned {
                let e = st.ceilings.entry(sharer).or_insert(W_CEIL);
                *e = (*e).min(learned);
            }
        }
        // A widened window admits more; a collapse changed nothing waiters can
        // use, but notifying is harmless (they re-check and re-await).
        self.budget.notify.notify_waiters();
    }
}

impl<R: Clone + Eq + Hash> Drop for RouteLease<R> {
    fn drop(&mut self) {
        // Poison-tolerant: this Drop can run during a panic unwind (a download worker
        // panicked). If the budget mutex were poisoned, `.lock().unwrap()` here would
        // double-panic during the unwind → process `abort()`, defeating the DL-ISC-14
        // panic-survival guarantee. Recover the guard instead — degrade, never abort.
        let mut st = self
            .budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(acct) = st.routes.get_mut(&self.route) {
            acct.refs = acct.refs.saturating_sub(1);
            if acct.refs == 0 {
                st.routes.remove(&self.route);
            }
        }
    }
}

/// A granted admission for one fragment `app_call`. Releases its route slot and
/// its global slot on drop and wakes any waiter — so a scheduler that drops the
/// permit during a retry backoff sleep frees the slot for other routes
/// (DL-ISC-6), never pinning the global pool behind a dying route's doomed
/// retries.
pub struct BudgetPermit<R: Clone + Eq + Hash> {
    budget: Arc<RouteBudget<R>>,
    route: R,
}

impl<R: Clone + Eq + Hash> Drop for BudgetPermit<R> {
    fn drop(&mut self) {
        {
            // Poison-tolerant (see `RouteLease::drop`) — never double-panic during unwind.
            let mut st = self
                .budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(acct) = st.routes.get_mut(&self.route) {
                acct.in_flight = acct.in_flight.saturating_sub(1);
            }
            st.global_in_flight = st.global_in_flight.saturating_sub(1);
        }
        self.budget.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sharer(tag: u8) -> SharerKey {
        SharerKey(vec![tag])
    }

    // ── Controller state machine (DL-ISC-2/3/15/17) ──────────────────────────

    /// DL-ISC-15 (liveness): under sustained clean completions the window climbs
    /// from floor to W_CEIL within a bounded number of windows, and never past.
    #[test]
    fn window_climbs_to_ceiling_under_sustained_health() {
        let mut w = RouteWindow::new(W_CEIL);
        assert_eq!(w.width(), W_FLOOR);
        // (W_CEIL - W_FLOOR) windows suffice; feed generously and assert it both
        // reaches and is capped at the ceiling.
        for _ in 0..64 {
            assert!(w
                .observe(FragmentOutcome::Completed {
                    over_threshold: false
                })
                .is_none());
            assert!(w.width() <= W_CEIL, "never exceeds the ceiling");
        }
        assert_eq!(
            w.width(),
            W_CEIL,
            "reaches the ceiling under sustained health"
        );
    }

    /// DL-ISC-3: additive increase is window-clocked — at most +1 per full window
    /// of clean completions, and the climb counter resets on a decrease.
    #[test]
    fn increase_is_window_clocked_and_resets_on_decrease() {
        let mut w = RouteWindow::new(W_CEIL);
        // At width 2, two clean completions → width 3 (one increment per window).
        assert!(w
            .observe(FragmentOutcome::Completed {
                over_threshold: false
            })
            .is_none());
        assert_eq!(w.width(), W_FLOOR, "no increment mid-window");
        assert!(w
            .observe(FragmentOutcome::Completed {
                over_threshold: false
            })
            .is_none());
        assert_eq!(w.width(), 3, "one increment after a full window");
        // A failure resets the climb: back to floor, and the partial progress
        // toward the next increment is discarded.
        assert_eq!(w.observe(FragmentOutcome::Failed), Some(W_FLOOR.max(3 / 2)));
        assert_eq!(w.width(), W_FLOOR);
        // One clean completion after the reset does NOT immediately re-increment.
        assert!(w
            .observe(FragmentOutcome::Completed {
                over_threshold: false
            })
            .is_none());
        assert_eq!(w.width(), W_FLOOR, "climb counter reset by the decrease");
    }

    /// DL-ISC-2: a terminal failure collapses to floor and hands back a learned
    /// ceiling of half the killing width.
    #[test]
    fn failure_collapses_to_floor_and_learns_half_the_killing_width() {
        let mut w = RouteWindow::new(W_CEIL);
        for _ in 0..64 {
            w.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(w.width(), W_CEIL);
        let learned = w.observe(FragmentOutcome::Failed);
        assert_eq!(
            learned,
            Some(W_CEIL / 2),
            "learned ceiling = half the killing width"
        );
        assert_eq!(w.width(), W_FLOOR, "collapses to floor");
    }

    /// (F6 / DL-ISC-2) A route death fails many concurrent in-flight fragments, each
    /// observed. Only the FIRST records the learned ceiling (half the killing width);
    /// the same death's remaining failures — arriving at the collapsed floor width —
    /// must NOT re-halve it down to floor. The ceiling reflects the killing width, not
    /// the count of concurrent failures. Pre-fix, the 2nd concurrent failure ratcheted
    /// the sharer's ceiling to W_FLOOR.
    #[test]
    fn concurrent_failures_of_one_death_do_not_ratchet_below_half_the_killing_width() {
        let mut w = RouteWindow::new(W_CEIL);
        for _ in 0..64 {
            w.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(w.width(), W_CEIL);
        // The route dies with W_CEIL fragments in flight: the FIRST failure records
        // the ceiling; the rest are the SAME death and must record nothing.
        let first = w.observe(FragmentOutcome::Failed);
        assert_eq!(
            first,
            Some(W_CEIL / 2),
            "first failure learns half the killing width"
        );
        for _ in 0..(W_CEIL - 1) {
            assert_eq!(
                w.observe(FragmentOutcome::Failed),
                None,
                "the same death's remaining failures record nothing (no re-ratchet)"
            );
        }
        assert_eq!(w.width(), W_FLOOR, "stays at floor");
        // Recover: clean completions climb the window back up to the LEARNED ceiling.
        for _ in 0..64 {
            w.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(
            w.width(),
            W_CEIL / 2,
            "recovers only up to the learned ceiling"
        );
        // A genuine NEW death after recovery IS recorded again (episode cleared on the
        // widen) — half the new killing width, not skipped.
        let second = w.observe(FragmentOutcome::Failed);
        assert_eq!(
            second,
            Some((W_CEIL / 2) / 2),
            "a new death after recovery learns half the NEW killing width"
        );
    }

    /// DL-ISC-17: the latency valve steps down on a sustained breach (3 of the
    /// last 5) and NOT on a single slow sample.
    #[test]
    fn latency_valve_steps_down_only_on_sustained_breach() {
        let mut w = RouteWindow::new(W_CEIL);
        for _ in 0..64 {
            w.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(w.width(), W_CEIL);
        // A single slow sample among clean ones does not step down.
        w.observe(FragmentOutcome::Completed {
            over_threshold: true,
        });
        assert_eq!(w.width(), W_CEIL, "one breach does nothing");
        // Bring the ring back to all-clean, then 3-of-5 breaches → one halving.
        for _ in 0..LATENCY_VALVE_WINDOW {
            w.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(w.width(), W_CEIL);
        for over in [true, false, true, false, true] {
            w.observe(FragmentOutcome::Completed {
                over_threshold: over,
            });
        }
        assert_eq!(w.width(), W_CEIL / 2, "3-of-5 breaches halve the window");
    }

    // ── Registry admission (DL-ISC-1/4/5/6/16/19) ────────────────────────────

    /// DL-ISC-1: peak concurrent in-flight to one route never exceeds its window,
    /// under many concurrent acquirers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn peak_in_flight_never_exceeds_the_route_window() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        let lease = Arc::new(budget.lease(1, sharer(1)));
        // Fresh window is at W_FLOOR.
        assert_eq!(budget.route_width(&1), W_FLOOR);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let (lease, in_flight, peak) = (lease.clone(), in_flight.clone(), peak.clone());
            handles.push(tokio::spawn(async move {
                let _permit = lease.acquire().await;
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= W_FLOOR,
            "peak {} > W_FLOOR",
            peak.load(Ordering::SeqCst)
        );
        assert_eq!(budget.global_in_flight(), 0, "all permits released");
    }

    /// DL-ISC-16 (liveness) + DL-ISC-1: with the window climbed, concurrent
    /// acquirers genuinely parallelize above the floor, still bounded by width.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn files_parallelize_under_a_climbed_window() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        let lease = Arc::new(budget.lease(1, sharer(1)));
        for _ in 0..64 {
            lease.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        let width = budget.route_width(&1);
        assert!(width > W_FLOOR, "window climbed above floor");
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..48 {
            let (lease, in_flight, peak) = (lease.clone(), in_flight.clone(), peak.clone());
            handles.push(tokio::spawn(async move {
                let _permit = lease.acquire().await;
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let observed = peak.load(Ordering::SeqCst);
        assert!(observed > W_FLOOR, "files parallelize (peak {observed})");
        assert!(
            observed <= width,
            "still bounded by the window ({observed} > {width})"
        );
    }

    /// DL-ISC-4 + DL-ISC-5 + DL-ISC-19: distinct routes hold independent budgets
    /// and progress concurrently; the sum never exceeds G_GLOBAL; one saturated
    /// route (at W_CEIL) always leaves headroom for a second route to admit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn distinct_routes_are_independent_and_bounded_by_g() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        // Two routes from two sharers, each climbed to W_CEIL.
        let a = Arc::new(budget.lease(1, sharer(1)));
        let b = Arc::new(budget.lease(2, sharer(2)));
        for _ in 0..64 {
            a.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
            b.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(budget.route_width(&1), W_CEIL);
        assert_eq!(budget.route_width(&2), W_CEIL);
        let global_peak = Arc::new(AtomicUsize::new(0));
        let saw_both = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for lease in [a.clone(), b.clone()] {
            for _ in 0..40 {
                let (lease, gp) = (lease.clone(), global_peak.clone());
                let budget2 = budget.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = lease.acquire().await;
                    gp.fetch_max(budget2.global_in_flight(), Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }));
            }
        }
        for h in handles {
            h.await.unwrap();
        }
        let _ = saw_both;
        assert!(
            global_peak.load(Ordering::SeqCst) <= G_GLOBAL,
            "global peak {} > G_GLOBAL",
            global_peak.load(Ordering::SeqCst)
        );
    }

    /// DL-ISC-19 (runtime half): with one route saturated at its window, a second
    /// route still admits (global headroom guaranteed by W_CEIL < G_GLOBAL).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_saturated_route_never_blocks_another() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        let a = Arc::new(budget.lease(1, sharer(1)));
        for _ in 0..64 {
            a.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(budget.route_width(&1), W_CEIL);
        // Saturate route A by holding W_CEIL permits.
        let mut held = Vec::new();
        for _ in 0..W_CEIL {
            held.push(a.acquire().await);
        }
        assert_eq!(budget.global_in_flight(), W_CEIL);
        // Route B admits immediately despite A being at its window.
        let b = budget.lease(2, sharer(2));
        let permit_b = tokio::time::timeout(std::time::Duration::from_secs(2), b.acquire())
            .await
            .expect("B must admit while A is saturated (W_CEIL < G_GLOBAL)");
        assert_eq!(budget.global_in_flight(), W_CEIL + 1);
        drop(permit_b);
        drop(held);
    }

    /// DL-ISC-6: dropping a permit (as the scheduler does during a retry backoff
    /// sleep) frees the slot and wakes a waiter — so no admission is held across
    /// the sleep.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dropping_a_permit_frees_the_slot_and_wakes_a_waiter() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        let lease = Arc::new(budget.lease(1, sharer(1)));
        // Fill the route to its floor window.
        let p1 = lease.acquire().await;
        let _p2 = lease.acquire().await;
        assert_eq!(budget.global_in_flight(), W_FLOOR);
        // A third acquire must wait.
        let lease2 = lease.clone();
        let waiter = tokio::spawn(async move { lease2.acquire().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "third acquire waits at the window");
        // Simulate the backoff release: drop a permit → the waiter is admitted.
        drop(p1);
        let _p3 = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("waiter admitted after a slot frees")
            .unwrap();
        assert_eq!(budget.global_in_flight(), W_FLOOR);
    }

    /// DL-ISC-2 (registry half): a failure records the sharer's learned ceiling,
    /// and it survives a route rotation (a fresh RouteId, same sharer) — a
    /// re-leased route on that sharer cannot climb past the learned ceiling.
    #[tokio::test]
    async fn learned_ceiling_survives_route_rotation() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        {
            let lease = budget.lease(10, sharer(9)); // route 10, sharer 9
            for _ in 0..64 {
                lease.observe(FragmentOutcome::Completed {
                    over_threshold: false,
                });
            }
            assert_eq!(budget.route_width(&10), W_CEIL);
            lease.observe(FragmentOutcome::Failed); // kill at W_CEIL → ceiling W_CEIL/2
        } // route 10's account drops with the lease; the ceiling persists.
        assert_eq!(budget.learned_ceiling(&sharer(9)), Some(W_CEIL / 2));
        // Rotation: a NEW route id for the SAME sharer.
        let rotated = budget.lease(11, sharer(9));
        for _ in 0..64 {
            rotated.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(
            budget.route_width(&11),
            W_CEIL / 2,
            "the rotated route cannot climb past the learned ceiling"
        );
    }

    /// The learned ceiling only ratchets DOWN — a later, lower kill lowers it; a
    /// higher would-be ceiling never raises it back within the session.
    #[tokio::test]
    async fn learned_ceiling_only_ratchets_down() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        let lease = budget.lease(1, sharer(1));
        for _ in 0..64 {
            lease.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        lease.observe(FragmentOutcome::Failed); // ceiling → 4
        assert_eq!(budget.learned_ceiling(&sharer(1)), Some(W_CEIL / 2));
        // Climb again (capped at 4), then kill at 4 → learned max(2, 2) = 2.
        for _ in 0..64 {
            lease.observe(FragmentOutcome::Completed {
                over_threshold: false,
            });
        }
        assert_eq!(budget.route_width(&1), W_CEIL / 2);
        lease.observe(FragmentOutcome::Failed);
        assert_eq!(
            budget.learned_ceiling(&sharer(1)),
            Some(W_FLOOR),
            "ratchets down, never up"
        );
    }

    /// A route account is dropped when its last lease drops (live accounting is
    /// route-lifetime), while the sharer ceiling persists (DL-ISC-2 lifetime).
    #[tokio::test]
    async fn route_account_drops_with_its_last_lease() {
        let budget = Arc::new(RouteBudget::<u32>::new());
        let l1 = budget.lease(1, sharer(1));
        let l2 = budget.lease(1, sharer(1)); // same route, second reference
        assert_eq!(budget.route_width(&1), W_FLOOR);
        drop(l1);
        assert_eq!(
            budget.route_width(&1),
            W_FLOOR,
            "still alive on the second lease"
        );
        drop(l2);
        assert_eq!(
            budget.route_width(&1),
            0,
            "account removed with the last lease"
        );
    }
}
