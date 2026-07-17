//! Consumer-side **parked browse-retry** state machine for the share-route self-heal
//! (`docs/design/consumer-route-self-heal.md` §RS-1.4, CRSH-ISC-6/15/19).
//!
//! When a browse-triggered manifest fetch fails, the reactive path performs **ZERO
//! network actions** (§RS-0, the design keystone): it marks the share's route
//! `Unresolved` and parks a **one-shot, generation-tagged** deferred retry here.
//!
//! Reframe (#180, 2026-07-17): the mark-fetchable-again is now owned by the
//! route-rotation fold (the frontend's `apply_discovery` clears `Unresolved` when the
//! route blob actually rotates — a purely-local no-network op, so no cursor-tick
//! decorrelation is owed and it works however long the sharer is away). This park is
//! therefore **housekeeping only** — it no longer re-fetches or clears `Unresolved`. It
//! is queried at the consumer's next steady-resweep **cursor tick** (never at the fold,
//! CRSH-ISC-15): a park whose generation advanced without a route rotation (a
//! content-only re-advert) is dropped as stale; on window expiry the retry is cleared and
//! a give-up hint surfaced — **never a prune** (CRSH-ISC-6, the share stays listed and
//! still recovers on a later rotation). A withdraw/re-add while parked drops the stale
//! retry (CRSH-ISC-19).
//!
//! This module is transport-free (no veilid types) and holds only local state, so it
//! lives in `daemonseed-core` alongside [`crate::session_health`] and is shared verbatim
//! by the gui and tui frontends and unit-tested without the transport.

use std::time::{Duration, Instant};

/// The parked-retry window (§RS-1.4, CRSH-ISC-6). It must cover detection + repair +
/// advert fold + one cursor tick: ≈ 390s detection + 60s repair + one tick + margin, so
/// the design's initial value is **10 minutes**. A named build-tunable (the single knob
/// the repro-first gate moves), never an inline literal.
pub const BROWSE_RETRY_WINDOW: Duration = Duration::from_secs(600);

/// A parked one-shot browse retry (§RS-1.4). Keyed in the frontend by `share_id`; carries
/// the discovered entry's **generation at park time** to detect a later advert fold, and
/// the share's `name` for the window-expiry give-up toast. Local state only — no network
/// (post-reframe #180 the park never re-fetches; the route-rotation fold marks the share
/// fetchable-again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedBrowseRetry {
    /// The share's display name, carried so the window-expiry give-up toast names the share.
    pub name: String,
    /// The discovered entry's generation when the retry was parked. A later accepted
    /// advert fold bumps the entry's generation strictly above this — the fire signal
    /// (CRSH-ISC-6). A withdraw drops the parked retry outright (CRSH-ISC-19), so the
    /// withdraw/re-add case never fires against the new advert's route.
    pub parked_generation: u64,
    /// Wall-clock deadline (`park time + `[`BROWSE_RETRY_WINDOW`]). On expiry the retry is
    /// cleared and failure surfaced — never a prune (CRSH-ISC-6).
    pub deadline: Instant,
}

impl ParkedBrowseRetry {
    /// Park a retry for a share at its current `generation`, windowed from `now`.
    pub fn park(name: String, generation: u64, now: Instant) -> Self {
        Self {
            name,
            parked_generation: generation,
            deadline: now + BROWSE_RETRY_WINDOW,
        }
    }
}

/// The action a parked retry calls for **at a cursor tick** — the decision is taken only
/// when the consumer's own cadence tick queries it, never at the advert-fold event
/// (CRSH-ISC-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkedRetryAction {
    /// A fresh advert has folded since the park (the entry's generation advanced). Post-reframe
    /// (#180) this is not itself a route refresh — a route rotation clears `Unresolved` at the
    /// fold — so the frontend drops this now-stale park at the tick (CRSH-ISC-6).
    Fire,
    /// The window elapsed with no fresh advert: surface failure and clear the parked
    /// entry — **no prune** (CRSH-ISC-6).
    Expire,
    /// The discovered entry is gone (verified withdraw / TTL): drop the parked retry
    /// silently — a withdraw/re-add never fires the stale-generation retry (CRSH-ISC-19).
    Drop,
    /// No fresh advert yet and still inside the window: keep waiting.
    Wait,
}

/// Decide a parked retry's action at a cursor tick (§RS-1.4). Pure — no network, and no
/// clock read beyond the passed `now`. `current_generation` is the discovered entry's
/// generation now, or `None` if the entry is gone. Fire takes priority over Expire so a
/// fresh advert that folds at the deadline edge is still retried.
pub fn parked_retry_action(
    parked: &ParkedBrowseRetry,
    current_generation: Option<u64>,
    now: Instant,
) -> ParkedRetryAction {
    match current_generation {
        // The share left the discovered map (verified withdraw): the parked retry is
        // stale — drop it. A subsequent re-add is a new discovery episode with its own
        // (absent) retry, so the withdraw/re-add case never fires (CRSH-ISC-19).
        None => ParkedRetryAction::Drop,
        // A fresh advert folded since the park (generation strictly advanced): fire on
        // THIS tick — never at the fold event (CRSH-ISC-6/15).
        Some(generation) if generation > parked.parked_generation => ParkedRetryAction::Fire,
        // No fresh advert; the window elapsed → surface failure, clear (no prune).
        _ if now >= parked.deadline => ParkedRetryAction::Expire,
        // No fresh advert, still inside the window.
        _ => ParkedRetryAction::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parked_at(generation: u64, deadline: Instant) -> ParkedBrowseRetry {
        ParkedBrowseRetry {
            name: "share".to_owned(),
            parked_generation: generation,
            deadline,
        }
    }

    // ── CRSH-ISC-6: a parked retry fires exactly once, on the first cursor tick after a
    //    fresh advert folds inside the window; on window expiry it surfaces error (no
    //    prune). The decision function is pure over an explicit `now`, so the tick cadence
    //    is modelled deterministically (each call = one cursor-tick query). ────────────
    #[test]
    fn crsh_isc_6_fires_on_the_first_tick_after_a_fresh_advert_folds() {
        let base = Instant::now();
        // Parked at generation 3, deep inside the window.
        let parked = parked_at(3, base + BROWSE_RETRY_WINDOW);

        // Tick 1: no fresh advert yet (generation unchanged) → wait, no fire.
        assert_eq!(
            parked_retry_action(&parked, Some(3), base),
            ParkedRetryAction::Wait
        );

        // A fresh advert folds → the entry's generation advances to 4. The NEXT tick
        // (a query with the advanced generation) fires — exactly once.
        assert_eq!(
            parked_retry_action(&parked, Some(4), base),
            ParkedRetryAction::Fire
        );
    }

    #[test]
    fn crsh_isc_6_window_expiry_surfaces_error_without_pruning() {
        let base = Instant::now();
        // Deadline already reached (park time was `base`), no fresh advert.
        let parked = parked_at(3, base);
        assert_eq!(
            parked_retry_action(&parked, Some(3), base + Duration::from_millis(1)),
            ParkedRetryAction::Expire // surface failure + clear; the caller does NOT prune
        );
    }

    // ── CRSH-ISC-15: the retry dispatch is decorrelated from the advert-fold event — it
    //    lands only when a cursor tick QUERIES the action, never at the fold. The fold
    //    only advances the entry's generation (local state); the action is a function of
    //    the generation observed AT the tick, so no fire exists until a tick queries. ──
    #[test]
    fn crsh_isc_15_dispatch_is_gated_on_a_tick_query_not_the_fold() {
        let base = Instant::now();
        let parked = parked_at(5, base + BROWSE_RETRY_WINDOW);
        // The advert has folded (generation is now 9), but firing only happens the moment
        // a cursor tick invokes `parked_retry_action` — the frontend never calls it inside
        // `apply_discovery`, so the fold event-turn dispatches nothing. Once a tick queries
        // with the advanced generation, and only then, the action is Fire.
        assert_eq!(
            parked_retry_action(&parked, Some(9), base),
            ParkedRetryAction::Fire
        );
    }

    // ── CRSH-ISC-19: a stale-generation retry (withdraw/re-add mid-park) is dropped. The
    //    withdraw removes the discovered entry → `current_generation` is `None` → Drop, so
    //    a later re-add (a fresh entry with a new generation) never fires this retry. ───
    #[test]
    fn crsh_isc_19_a_withdrawn_share_drops_the_stale_retry() {
        let base = Instant::now();
        let parked = parked_at(5, base + BROWSE_RETRY_WINDOW);
        assert_eq!(
            parked_retry_action(&parked, None, base),
            ParkedRetryAction::Drop
        );
    }

    #[test]
    fn park_windows_from_now() {
        let now = Instant::now();
        let p = ParkedBrowseRetry::park("s".to_owned(), 7, now);
        assert_eq!(p.parked_generation, 7);
        assert_eq!(p.deadline, now + BROWSE_RETRY_WINDOW);
    }
}
