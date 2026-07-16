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

/// Cap on the per-record decaying-backoff multiplier (§RS-1.2 advisor rule). A record
/// whose repair does not restore service doubles its effective K-threshold per
/// consecutive failed repair (`1 → 2 → 4 → 8`), capped here, then holds — so a
/// permanently-dead record (abandoned circle, sharer gone forever) settles to one
/// bounded re-establishment attempt per `base_K × cap` cursor rounds instead of every
/// `base_K` rounds indefinitely (~52 min at the current census). The first successful
/// pass resets the multiplier to 1. `8` matches the design's initial cap.
pub const REPAIR_BACKOFF_CAP: u32 = 8;

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
    ///
    /// **Public** so the §RS-4 manual-Refresh fold arm can reuse the exact failed-pass
    /// predicate (CRSH-ISC-16): a Refresh-armed record re-establishes on a single failed
    /// pass, and the gate must not duplicate this expression.
    pub fn is_failed_pass(&self) -> bool {
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
#[derive(Debug, Clone, Copy)]
struct RecordHealth {
    /// Consecutive all-failed passes observed. Reset to 0 by any successful pass.
    consecutive_failed: u32,
    /// Latched once repair-due has been signalled, so the tracker signals `RepairDue`
    /// exactly once per death episode (CRSH-ISC-2) rather than on every subsequent
    /// failed pass. Cleared by a successful pass or by
    /// [`SessionHealthTracker::note_repair_dispatched`] (the 3b repair-dispatch hook).
    repair_due_latched: bool,
    /// Decaying-backoff multiplier on the K-threshold (§RS-1.2, capped at
    /// [`REPAIR_BACKOFF_CAP`]). The record's *effective* threshold is
    /// `base_K × backoff_mult`. Starts at 1; doubled by each repair dispatch
    /// ([`SessionHealthTracker::note_repair_dispatched`]) so a repair that fails to
    /// restore service costs the next death episode `× backoff_mult` more cadence
    /// rounds to re-detect; a successful pass resets it to 1.
    backoff_mult: u32,
}

impl Default for RecordHealth {
    fn default() -> Self {
        // `backoff_mult` MUST default to 1, not 0 — it multiplies the K-threshold, and a
        // 0 would make the effective threshold 0 and fire a repair on the first failed
        // pass. `derive(Default)` would give 0, so Default is hand-written.
        Self {
            consecutive_failed: 0,
            repair_due_latched: false,
            backoff_mult: 1,
        }
    }
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
        let base_k = self.k_threshold;
        let entry = self.records.entry(key).or_default();
        if !input.is_failed_pass() {
            // Successful pass: the session is serving. Reset the streak, clear the latch
            // (a healed record must be able to re-arm if it dies again), and reset the
            // decaying backoff — service restored means the last repair (if any) worked,
            // so the next death episode starts from the base K again (§RS-1.2).
            entry.consecutive_failed = 0;
            entry.repair_due_latched = false;
            entry.backoff_mult = 1;
            return RepairDecision::NotDue;
        }
        // The effective threshold is the base K scaled by this record's decaying backoff
        // (§RS-1.2): a record whose prior repair did not restore service needs
        // proportionally more failed passes before it is repair-due again.
        let k = base_k.saturating_mul(entry.backoff_mult);
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

    /// The **step-3b repair-dispatch hook** (§RS-1.2). Once a repair has been dispatched
    /// for `key`, the caller calls this to (a) reset the detection streak and clear the
    /// repair-due latch, so a still-dead record can re-detect on a fresh streak, and (b)
    /// **double the decaying-backoff multiplier** (capped at [`REPAIR_BACKOFF_CAP`]) so a
    /// repair that fails to restore service costs the next death episode proportionally
    /// more cadence rounds to re-detect. A subsequent *successful* pass ([`Self::observe`])
    /// resets the multiplier back to 1. No-op for an untracked key.
    ///
    /// This replaces a bare `clear` at the repair-due arm precisely because the backoff
    /// state must **survive** the streak reset — dropping the record entirely (as
    /// [`Self::clear`] does) would forget the backoff and let a permanently-dead record
    /// re-attempt every `base_K` rounds forever.
    pub fn note_repair_dispatched(&mut self, key: &K) {
        if let Some(entry) = self.records.get_mut(key) {
            entry.consecutive_failed = 0;
            entry.repair_due_latched = false;
            entry.backoff_mult = entry.backoff_mult.saturating_mul(2).min(REPAIR_BACKOFF_CAP);
        }
    }

    /// Drop `key`'s detection state entirely (backoff included) — for a record that is no
    /// longer tracked at all (e.g. an unsubscribed circle). Distinct from
    /// [`Self::note_repair_dispatched`], which preserves and bumps the backoff. No-op for
    /// an untracked key.
    pub fn clear(&mut self, key: &K) {
        self.records.remove(key);
    }

    /// Whether `key` is currently latched repair-due.
    ///
    /// This is the **drain-time re-check** (CRSH-ISC-24): before a queued repair is
    /// dispatched off `pending_repairs`, the frontend calls this to confirm the record is
    /// still repair-due, so a record that recovered *after* being queued is dropped from
    /// the queue rather than needlessly torn down and re-established. It returns `false` in
    /// exactly the two cases the drain must skip: (a) the record recovered — a successful
    /// [`Self::observe`] reset its streak and cleared the latch; (b) the repair was already
    /// dispatched — [`Self::note_repair_dispatched`] cleared the latch. It returns `true`
    /// only while the record is latched repair-due (after the K-th failed pass in calm),
    /// and `false` for an untracked key.
    pub fn is_repair_due(&self, key: &K) -> bool {
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

    // ── §RS-1.2 decaying backoff: a failed repair doubles K (cap 8×), success resets ──
    /// Each `note_repair_dispatched` (a repair that did NOT restore service, since the
    /// sweeps keep failing) doubles the effective K-threshold: base 2 → 4 → 8 → 16, then
    /// the multiplier caps at [`REPAIR_BACKOFF_CAP`] (8×) so it holds at effective 16. A
    /// single successful pass resets the multiplier, so the next episode is back to base K.
    #[test]
    fn crsh_backoff_doubles_k_on_failed_repair_caps_and_resets_on_success() {
        assert_eq!(REPAIR_K_THRESHOLD, 2, "test written for base K=2");
        assert_eq!(REPAIR_BACKOFF_CAP, 8, "test written for an 8× cap");

        /// Drive exactly `effective_k` failed passes: the first `effective_k − 1` are
        /// NotDue, the `effective_k`-th is RepairDue. Then dispatch a (failing) repair.
        fn run_episode(t: &mut SessionHealthTracker<u64>, key: u64, effective_k: u32) {
            for _ in 1..effective_k {
                assert_eq!(
                    t.observe(key, failed(Weather::Calm)),
                    RepairDecision::NotDue,
                    "below the effective threshold {effective_k}"
                );
            }
            assert_eq!(
                t.observe(key, failed(Weather::Calm)),
                RepairDecision::RepairDue,
                "repair-due at the effective threshold {effective_k}"
            );
            t.note_repair_dispatched(&key);
        }

        let mut t: SessionHealthTracker<u64> = SessionHealthTracker::new(); // base K = 2
        let key = 5u64;
        run_episode(&mut t, key, 2); // mult 1 → effective 2;  after dispatch mult→2
        run_episode(&mut t, key, 4); // mult 2 → effective 4;  after dispatch mult→4
        run_episode(&mut t, key, 8); // mult 4 → effective 8;  after dispatch mult→8
        run_episode(&mut t, key, 16); // mult 8 → effective 16; after dispatch mult→min(16,8)=8
        run_episode(&mut t, key, 16); // mult 8 (capped) → effective 16 again

        // A successful pass restores service → the backoff resets to 1.
        assert_eq!(
            t.observe(key, ok_pass(Weather::Calm)),
            RepairDecision::NotDue
        );
        run_episode(&mut t, key, 2); // back to base K = 2
    }

    /// `is_failed_pass` is part of the public surface (the gui §RS-4 Refresh fold arm
    /// calls it — CRSH-ISC-16) and returns the documented values: a reached-but-empty
    /// erroring pass and a dead watch are failed; a populated or clean pass is not.
    #[test]
    fn is_failed_pass_is_public_and_matches_the_documented_signature() {
        // Reached, zero found, at least one GET error → failed pass (L1).
        assert!(
            SweepHealthInput {
                attempted: 64,
                failed: 64,
                found: 0,
                watch: WatchState::Unknown,
                weather: Weather::Calm,
            }
            .is_failed_pass()
        );
        // Dead watch → failed pass (L2) regardless of the GET counts.
        assert!(
            SweepHealthInput {
                attempted: 0,
                failed: 0,
                found: 0,
                watch: WatchState::Dead,
                weather: Weather::Calm,
            }
            .is_failed_pass()
        );
        // A populated slot → successful pass even with a stray GET error.
        assert!(
            !SweepHealthInput {
                attempted: 64,
                failed: 1,
                found: 1,
                watch: WatchState::Unknown,
                weather: Weather::Calm,
            }
            .is_failed_pass()
        );
        // A clean pass with zero GET errors → successful pass.
        assert!(
            !SweepHealthInput {
                attempted: 64,
                failed: 0,
                found: 0,
                watch: WatchState::Unknown,
                weather: Weather::Calm,
            }
            .is_failed_pass()
        );
    }

    // ── CRSH-ISC-24: `is_repair_due` is the pub drain-time re-check (#180 F4/F5) ───────
    /// `is_repair_due` is public (callable outside `#[cfg(test)]` — the frontends' drain
    /// calls it) and returns the documented values across the recover/dispatch transitions
    /// the drain relies on: an untracked key is not due; after K failed passes in calm the
    /// record is latched repair-due (`true`); a subsequent successful `observe` — the
    /// record recovered while it sat queued (F4) — clears the latch (`false`), so the drain
    /// drops the stale entry; and `note_repair_dispatched` — an immediate dispatch (F5) —
    /// also clears the latch (`false`), so the drain will not pop-and-repair the same key a
    /// second time.
    #[test]
    fn crsh_isc_24_is_repair_due_tracks_recover_and_dispatch() {
        assert_eq!(REPAIR_K_THRESHOLD, 2, "test written for K=2");
        let mut tracker: SessionHealthTracker<u64> = SessionHealthTracker::new();
        let key = 0x24u64;

        // An untracked key is never repair-due.
        assert!(!tracker.is_repair_due(&key));

        // K=2 failed passes in calm → latched repair-due.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::NotDue
        );
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
        assert!(
            tracker.is_repair_due(&key),
            "latched repair-due after the K-th failed pass"
        );

        // F4: the record recovers while queued — a successful pass clears the latch, so a
        // drain re-check drops the stale queue entry instead of re-establishing it.
        assert_eq!(
            tracker.observe(key, ok_pass(Weather::Calm)),
            RepairDecision::NotDue
        );
        assert!(
            !tracker.is_repair_due(&key),
            "recovered → drain must drop the stale queued entry"
        );

        // Re-latch, then F5: an immediate dispatch clears the latch, so the drain will not
        // pop-and-dispatch the same key a second time.
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::NotDue
        );
        assert_eq!(
            tracker.observe(key, failed(Weather::Calm)),
            RepairDecision::RepairDue
        );
        assert!(tracker.is_repair_due(&key));
        tracker.note_repair_dispatched(&key);
        assert!(
            !tracker.is_repair_due(&key),
            "dispatched → drain must not double-repair"
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
