//! Consumer-side per-record **session-health tracker** — the K-consecutive-failed
//! detection state machine for the share-route self-heal (`docs/design/
//! consumer-route-self-heal.md` §RS-1.2/§RS-1.3, CRSH-ISC-2/9/11).
//!
//! Each frontend net actor feeds this tracker one [`SweepHealthInput`] per completed
//! steady/backlog sweep (surfaced as a `VeilidNetEvent::SweepHealth`). The tracker
//! maintains a per-record consecutive-all-failed counter and, after **K** consecutive
//! all-failed passes **while the DHT weather reads calm**, flags the record
//! **repair-due** — the signal step 3b's repair arm attaches to. This module is
//! *detection only*: it executes no repair, touches no network, and holds no veilid
//! types (generic over the record-key type `K`), so it lives in `daemonseed-core`
//! alongside [`crate::presence::ReapGate`] and is shared verbatim by the gui and tui
//! frontends and unit-tested without the transport.
//!
//! **The decision is network-state-sterile by construction (CRSH-ISC-11).** The sole
//! input to the repair-due decision is [`SweepHealthInput`], whose fields are *only*
//! sweep-result counts, watch state, and weather — no user-event-derived bit can enter,
//! so the repair-due signal (and, downstream, its emissions) cannot encode user
//! activity. This is the type-level anti-criterion the design's keystone rule rests on.

use std::collections::HashMap;
use std::hash::Hash;

/// The K-consecutive-all-failed detection threshold (§RS-1.2, CRSH-ISC-2). Initial
/// value 2, deliberately a named build-tunable rather than an inline literal: the
/// design's **repro-first gate** (§RS-1.3) tunes K against a reproduced dead-consumer
/// state before the detection constants are finalized, so this const is the single
/// knob that move touches.
pub const REPAIR_K_THRESHOLD: u32 = 2;

/// The DHT-weather reading gating a repair-due transition (CRSH-ISC-9). Sourced from
/// the existing WB-5.1 estimator (median-of-5 + hysteresis) via
/// [`crate::presence::ReapGate::suspend_reaping`] — consumed, never re-derived here:
/// `Elevated` == "reaping suspended". In an elevated regime GET timeouts are weather,
/// not death, so the transition is *delayed* (never cancelled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weather {
    /// Estimator reads calm — a completed all-failed streak may become repair-due.
    Calm,
    /// Estimator reads elevated (or within the reap-resume grace) — repair-due is
    /// suppressed until calm returns.
    Elevated,
}

/// The transport's view of the record's watch, an L2 detection rung (§RS-1.3). Whether
/// veilid 0.5.x surfaces watch-death usably is an open question for the build; until it
/// is wired the SweepHealth path always supplies [`WatchState::Unknown`] and detection
/// rides L1 (the GET-error streak) alone. The field exists so the L2 rung slots in
/// without reshaping the decision input — and so the input type is provably complete
/// over the design's three evidence sources (CRSH-ISC-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchState {
    /// Watch liveness not reported by the transport (the L1-only default).
    #[default]
    Unknown,
    /// The transport reports the record's watch alive.
    Live,
    /// The transport reports the record's watch dead — an immediate failed-pass signal.
    Dead,
}

/// The complete input to a repair-due decision — **network-state fields only**
/// (CRSH-ISC-11 anti-criterion). Constructed from a sweep's [`crate::presence`]-free
/// GET accounting, the transport watch state, and the weather estimator; there is
/// deliberately no constructor path that admits a user-event-derived value, so the
/// repair-due signal is a pure function of network state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepHealthInput {
    /// Subkey GETs issued this pass (`SweepOutcome::attempted`).
    pub attempted: u32,
    /// Subkey GETs that errored this pass (`SweepOutcome::failed`) — the L1 signal.
    pub failed: u32,
    /// Populated slots yielded this pass (`SweepOutcome::found`).
    pub found: u32,
    /// Transport watch state (L2 rung; [`WatchState::Unknown`] on the L1-only path).
    pub watch: WatchState,
    /// DHT-weather reading gating the repair-due transition (CRSH-ISC-9).
    pub weather: Weather,
}

impl SweepHealthInput {
    /// An **all-failed pass** (§RS-1.2 L1): the record was reached (`attempted > 0`),
    /// yielded nothing (`found == 0`), and at least one GET errored (`failed > 0`) — a
    /// dead-session signature, distinct from a merely empty record. A dead watch
    /// (L2) counts the same. Any populated slot, or a clean pass with zero GET errors,
    /// is a *successful* pass (`!is_failed_pass`) and resets the streak.
    fn is_failed_pass(&self) -> bool {
        matches!(self.watch, WatchState::Dead)
            || (self.attempted > 0 && self.found == 0 && self.failed > 0)
    }
}

/// The outcome of feeding one sweep pass to the tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairDecision {
    /// No action — the record is healthy, below threshold, or already flagged this
    /// death episode (the repair-due signal is latched, so it fires exactly once).
    NotDue,
    /// The all-failed streak has reached K, but the weather is elevated: the transition
    /// is **delayed** (CRSH-ISC-9), not cancelled. The streak is retained, so the next
    /// calm failed pass resumes straight to [`RepairDecision::RepairDue`].
    Suppressed,
    /// K consecutive all-failed passes in calm weather: this record is **repair-due**.
    /// Emitted exactly once per death episode (until a successful pass or [`
    /// SessionHealthTracker::clear`] resets it). Step 3b's repair arm attaches here.
    RepairDue,
}

/// Per-record detection state.
#[derive(Debug, Clone, Copy, Default)]
struct RecordHealth {
    /// Consecutive all-failed passes observed. Reset to 0 by any successful pass.
    consecutive_failed: u32,
    /// Latched once repair-due has been signalled, so the tracker signals `RepairDue`
    /// exactly once per death episode (CRSH-ISC-2) rather than on every subsequent
    /// failed pass. Cleared by a successful pass or by [`SessionHealthTracker::clear`]
    /// (the 3b repair-completion hook).
    repair_due_latched: bool,
}

/// The per-record session-health tracker (§RS-1.2). Generic over the record-key type so
/// it carries no veilid dependency: the frontends instantiate it with the transport's
/// `RecordKey`; tests use any `Eq + Hash + Clone` key.
#[derive(Debug, Clone, Default)]
pub struct SessionHealthTracker<K: Eq + Hash + Clone> {
    records: HashMap<K, RecordHealth>,
    /// The detection threshold (defaults to [`REPAIR_K_THRESHOLD`]; held as a field so
    /// the repro-first gate can override it without touching call sites, and so a
    /// per-record decaying backoff — step 3b — has somewhere to raise it).
    k_threshold: u32,
}

impl<K: Eq + Hash + Clone> SessionHealthTracker<K> {
    /// A fresh tracker at the default [`REPAIR_K_THRESHOLD`].
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            k_threshold: REPAIR_K_THRESHOLD,
        }
    }

    /// A tracker with an explicit K threshold (the repro-first gate's tuning entry).
    pub fn with_threshold(k_threshold: u32) -> Self {
        Self {
            records: HashMap::new(),
            k_threshold,
        }
    }

    /// Fold one completed sweep pass for `key`, returning the repair decision **taken at
    /// this pass's own tick** (CRSH-ISC-2: the decision rides the sweep-completion
    /// cursor tick that carries the K-th failed pass, never an intermediate
    /// error-observation between ticks — the caller invokes this once per completed
    /// sweep, so the aggregate `input` is the whole evidence for the tick).
    ///
    /// A failed pass advances the consecutive counter; on reaching K it becomes
    /// [`RepairDecision::RepairDue`] in calm weather (latched, so at-most-once per
    /// episode) or [`RepairDecision::Suppressed`] while elevated (the streak is kept, so
    /// calm resumes — never cancels). A successful pass resets the counter and clears
    /// the latch.
    pub fn observe(&mut self, key: K, input: SweepHealthInput) -> RepairDecision {
        let k = self.k_threshold;
        let entry = self.records.entry(key).or_default();
        if !input.is_failed_pass() {
            // Successful pass: the session is serving. Reset the streak and clear the
            // latch (a healed record must be able to re-arm if it dies again). Step 3b's
            // decaying backoff also resets here.
            entry.consecutive_failed = 0;
            entry.repair_due_latched = false;
            return RepairDecision::NotDue;
        }
        entry.consecutive_failed = entry.consecutive_failed.saturating_add(1);
        if entry.consecutive_failed < k {
            return RepairDecision::NotDue;
        }
        if entry.repair_due_latched {
            // Already flagged this episode — no duplicate repair (CRSH-ISC-2).
            return RepairDecision::NotDue;
        }
        match input.weather {
            Weather::Calm => {
                entry.repair_due_latched = true;
                RepairDecision::RepairDue
            }
            // CRSH-ISC-9: elevated regime suppresses the transition. The streak is NOT
            // reset and the latch is NOT set, so the next calm failed pass fires
            // RepairDue — suppression delays, it never cancels.
            Weather::Elevated => RepairDecision::Suppressed,
        }
    }

    /// Drop `key`'s detection state — the **step-3b repair-completion hook**: once a
    /// repair has re-established the record's session, the caller clears its history so
    /// the streak starts fresh. (A subsequent successful sweep would reset it anyway;
    /// this lets 3b reset immediately at repair time.) No-op for an untracked key.
    pub fn clear(&mut self, key: &K) {
        self.records.remove(key);
    }

    /// Whether `key` is currently latched repair-due (test/introspection helper).
    #[cfg(test)]
    fn is_repair_due(&self, key: &K) -> bool {
        self.records.get(key).is_some_and(|r| r.repair_due_latched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed sweep pass at the given weather (attempted>0, found==0, failed>0).
    fn failed(weather: Weather) -> SweepHealthInput {
        SweepHealthInput {
            attempted: 64,
            failed: 64,
            found: 0,
            watch: WatchState::Unknown,
            weather,
        }
    }

    /// A successful sweep pass (found>0).
    fn ok_pass(weather: Weather) -> SweepHealthInput {
        SweepHealthInput {
            attempted: 64,
            failed: 0,
            found: 1,
            watch: WatchState::Unknown,
            weather,
        }
    }

    // ── CRSH-ISC-2: K consecutive all-failed passes → exactly one repair at the K-th ──
    /// Paused-time (as the WB scheduler oracles do): each `observe` stands for one
    /// completed sweep at a cursor tick. K-1 failed passes yield no repair; the K-th, in
    /// calm, fires `RepairDue` exactly once; a further failed pass does not re-fire (the
    /// signal is latched, so the repair is dispatched once at the K-th pass's own tick,
    /// never repeatedly nor between ticks).
    #[tokio::test(start_paused = true)]
    async fn crsh_isc_2_repair_due_fires_once_at_the_kth_failed_pass() {
        assert_eq!(REPAIR_K_THRESHOLD, 2, "test written for K=2");
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
        let key = 0xABCDu64;
        let tick = std::time::Duration::from_secs(15); // STEADY_RESWEEP_TICK cadence

        // Pass 1 (K-1): below threshold, no repair.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::NotDue
        );
        tokio::time::sleep(tick).await;

        // Pass 2 (the K-th): repair-due fires, exactly here.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
        tokio::time::sleep(tick).await;

        // Pass 3: still failing, but the signal is latched — no duplicate repair.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::NotDue
        );
        assert!(tracker.is_repair_due(&key));
    }

    /// A successful pass before the K-th resets the streak, so death detection restarts.
    #[test]
    fn crsh_isc_2_a_successful_pass_resets_the_streak() {
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
        let key = 1u64;
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::NotDue
        );
        // Recovery: streak back to zero.
        assert_eq!(
            tracker.observe(key, ok_pass(Weather::Calm)),
            RepairDecision::NotDue
        );
        // One more failed pass is only the FIRST of a new streak — not yet repair-due.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::NotDue
        );
    }

    // ── CRSH-ISC-9: weather gating delays (never cancels) the repair-due transition ──
    /// K all-failed passes while elevated produce NO repair (first below threshold, then
    /// suppressed); a subsequent calm failed pass resumes straight to repair-due — the
    /// streak was retained across the elevated regime, proving suppression delays.
    #[tokio::test(start_paused = true)]
    async fn crsh_isc_9_elevated_suppresses_then_calm_resumes() {
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
        let key = 7u64;
        let tick = std::time::Duration::from_secs(15);

        // K failed passes, all elevated → never repair-due.
        assert_eq!(
            tracker.observe(key, failed(Weather::Elevated)),
            RepairDecision::NotDue // pass 1: below threshold
        );
        tokio::time::sleep(tick).await;
        assert_eq!(
            tracker.observe(key, failed(Weather::Elevated)),
            RepairDecision::Suppressed // pass 2: at threshold, but elevated → suppressed
        );
        assert!(
            !tracker.is_repair_due(&key),
            "elevated weather must not flag repair-due"
        );
        tokio::time::sleep(tick).await;

        // Calm returns: the retained streak resumes straight to repair-due.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
    }

    // ── CRSH-ISC-11: the decision input carries ONLY network-state fields ─────────────
    /// The type-level anti-criterion: a repair-due decision is constructible from
    /// sweep-result counts, watch state, and weather ALONE — no user-event-derived value
    /// participates. This test constructs the input and drives a repair-due decision from
    /// exactly those fields; the struct's field set (asserted by construction) is the
    /// compile-checkable guarantee that nothing else can enter the decision.
    #[test]
    fn crsh_isc_11_repair_decision_is_a_function_of_network_state_only() {
        // Constructed from network-state fields only — there is no field, and no
        // constructor, that admits a browse/render/roster/user event.
        let input = SweepHealthInput {
            attempted: 64,
            failed: 64,
            found: 0,
            watch: WatchState::Unknown,
            weather: Weather::Calm,
        };
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::with_threshold(1);
        // One all-failed pass at K=1 in calm → repair-due, derived from `input` alone.
        assert_eq!(tracker.observe(42, input), RepairDecision::RepairDue);

        // The L2 watch-death rung is likewise network-state: a dead watch is a failed
        // pass regardless of the GET counts.
        let dead_watch = SweepHealthInput {
            attempted: 0,
            failed: 0,
            found: 0,
            watch: WatchState::Dead,
            weather: Weather::Calm,
        };
        let mut t2: SessionHealthTracker<u64> = SessionHealthTracker::with_threshold(1);
        assert_eq!(t2.observe(1, dead_watch), RepairDecision::RepairDue);
    }

    /// The 3b repair-completion hook: `clear` drops a record's latched history so a
    /// re-established session starts detection fresh.
    #[test]
    fn clear_resets_a_repair_due_record() {
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::with_threshold(1);
        let key = 9u64;
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
        assert!(tracker.is_repair_due(&key));
        tracker.clear(&key);
        assert!(!tracker.is_repair_due(&key));
        // A fresh failed pass is again only the first of a new streak at K=1 → repair-due,
        // i.e. the record re-arms cleanly.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
    }

    /// Distinct records track independently — one dead record does not flag another.
    #[test]
    fn records_are_tracked_independently() {
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
        let (dead, live) = (1u64, 2u64);
        tracker.observe(dead, failed(Weather::Calm));
        assert_eq!(
            tracker.observe(dead, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
        // The healthy record, swept once and serving, is never flagged.
        assert_eq!(
            tracker.observe(live, ok_pass(Weather::Calm)),
            RepairDecision::NotDue
        );
        assert!(!tracker.is_repair_due(&live));
    }
}
