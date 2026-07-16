//! Consumer-side **imported-route in-use guard** — defers a superseded private
//! route's release until no in-flight fetch/download is still streaming over it
//! (`docs/design/consumer-route-self-heal.md` §RS-3, CRSH-ISC-10a).
//!
//! A discovered share caches the sharer's private-route blob and re-imports it on
//! every browse/download (`import_route` dedups to a stable id — design Evidence 2).
//! When a fresh advert folds and **changes** that blob, the previously-imported route
//! is superseded and should be released. Releasing it the instant the advert lands
//! would break a fetch/download that is *streaming over that very route* — the exact
//! race §RS-3 closes. This guard makes the release fire on the **later** of the two
//! events: advert-replacement OR completion of the last in-flight fetch/download using
//! the route.
//!
//! It is *policy only*: it holds no veilid types (generic over the share-key type `S`
//! and the route-id type `R`), issues no release itself, and returns the route ids the
//! caller may now release. The frontend net actor owns the release (through
//! `release_tolerant`, off the guard's synchronous decisions), so this lives in
//! `daemonseed-core` alongside [`crate::session_health`] and is unit-tested without the
//! transport. The LRU/expiry in the transport's remote-route cache is the backstop for
//! anything the guard leaves untracked (design Evidence 2), so a rare double-supersede
//! mid-fetch that outruns the single deferred slot is bounded, never a leak.

use std::collections::HashMap;
use std::hash::Hash;

/// Per-share tracking: the current imported route, the count of in-flight
/// fetches/downloads over it, and at most one superseded route held back for release
/// until the share goes idle.
struct GuardEntry<R> {
    /// The last route imported for this share, or `None` before the first import (or
    /// after the route was superseded and released).
    route: Option<R>,
    /// Fetches/downloads currently in flight for this share.
    in_flight: u32,
    /// A superseded route awaiting release, withheld until `in_flight == 0`
    /// (CRSH-ISC-10a: release on the *later* of advert-replacement or in-flight
    /// completion). At most one — a second mid-flight supersede leaves the older route
    /// to the transport LRU backstop (Evidence 2), which is bounded, not a leak.
    pending_release: Option<R>,
    /// The share was withdrawn while a fetch was still in flight (CRSH-ISC-26): its
    /// `route` must be released and the whole entry dropped once the last in-flight
    /// fetch completes — releasing mid-download would kill the stream. Cleared by
    /// `note_fetch_started` (a fresh fetch means the share is live for us again, so a
    /// stale withdraw mark on a since-re-added share is void). When idle, withdrawal
    /// releases + removes immediately and this never persists on a stored entry.
    withdrawn: bool,
}

impl<R> Default for GuardEntry<R> {
    fn default() -> Self {
        Self {
            route: None,
            in_flight: 0,
            pending_release: None,
            withdrawn: false,
        }
    }
}

impl<R> GuardEntry<R> {
    /// An entry with no route, no in-flight fetch, and nothing pending carries no
    /// state — the map can drop it.
    fn is_empty(&self) -> bool {
        self.route.is_none() && self.in_flight == 0 && self.pending_release.is_none()
    }
}

/// The in-use guard over each discovered share's last-imported private route
/// (§RS-3, CRSH-ISC-10a). Fed by fetch spawn/finish and advert-replacement folds;
/// every mutator returns the route ids the caller may now release.
pub struct ImportedRouteGuard<S: Eq + Hash + Clone, R: Clone> {
    entries: HashMap<S, GuardEntry<R>>,
}

impl<S: Eq + Hash + Clone, R: Clone> Default for ImportedRouteGuard<S, R> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<S: Eq + Hash + Clone, R: Clone> ImportedRouteGuard<S, R> {
    /// A fresh, empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fetch/download for `share` is about to start (spawned or awaited). Its route
    /// id is not yet known on-loop; the in-flight count rises now so a concurrent
    /// advert-replacement defers its release until this fetch finishes.
    pub fn note_fetch_started(&mut self, share: S) {
        let entry = self.entries.entry(share).or_default();
        entry.in_flight += 1;
        // A fresh fetch means the share is live for us again — void any stale withdraw
        // mark left by a since-re-added share so its re-imported route is never released
        // out from under the new fetch (CRSH-ISC-26, the withdraw-racing-re-import case).
        entry.withdrawn = false;
    }

    /// A fetch/download for `share` finished. `imported` is the route it imported
    /// (`Some` on success / manifest-fail-after-import; `None` on import-fail or a
    /// dropped stale-generation outcome). Decrements the in-flight count, records the
    /// route, and — now that a fetch completed — flushes any route a prior
    /// advert-replacement left pending once the share is idle. Returns the routes the
    /// caller may release.
    #[must_use]
    pub fn note_fetch_finished(&mut self, share: &S, imported: Option<R>) -> Vec<R> {
        let mut release = Vec::new();
        let Some(entry) = self.entries.get_mut(share) else {
            // No matching start (defensive): still hold the imported route so a later
            // advert-replacement can release it rather than leak it.
            if let Some(route) = imported {
                self.entries.insert(
                    share.clone(),
                    GuardEntry {
                        route: Some(route),
                        in_flight: 0,
                        pending_release: None,
                        withdrawn: false,
                    },
                );
            }
            return release;
        };
        entry.in_flight = entry.in_flight.saturating_sub(1);
        if let Some(route) = imported {
            entry.route = Some(route);
        }
        if entry.in_flight == 0 {
            if let Some(pending) = entry.pending_release.take() {
                release.push(pending);
            }
            // (CRSH-ISC-26) A withdraw that arrived mid-fetch deferred its release to
            // here: now that the last in-flight fetch is done, release the share's
            // imported route and let `gc` drop the now-empty entry (no lingering
            // `{route: Some, in_flight: 0}` leaked until the transport LRU evicts it).
            if entry.withdrawn
                && let Some(route) = entry.route.take()
            {
                release.push(route);
            }
        }
        self.gc(share);
        release
    }

    /// A fresh advert for `share` folded and **replaced** its route blob, superseding
    /// the currently-imported route. If the share is idle (no in-flight fetch) the
    /// superseded route is returned for immediate release; otherwise it is held back
    /// and released when the last in-flight fetch finishes (CRSH-ISC-10a). Call this
    /// **only** when the route blob actually changed — an identical re-advert re-imports
    /// to the same id (Evidence 2), so releasing it would be pointless churn.
    #[must_use]
    pub fn note_advert_replaced(&mut self, share: &S) -> Option<R> {
        let entry = self.entries.get_mut(share)?;
        // Nothing imported yet → nothing to supersede.
        let superseded = entry.route.take()?;
        if entry.in_flight == 0 {
            self.gc(share);
            return Some(superseded);
        }
        // In use: defer. Keep at most one deferred route; a second mid-flight supersede
        // leaves the older superseded route to the transport LRU backstop (Evidence 2).
        if entry.pending_release.is_none() {
            entry.pending_release = Some(superseded);
        }
        None
    }

    /// A verified withdraw removed `share` from discovery, so its imported route should
    /// be released and the guard entry dropped — otherwise `note_fetch_finished` leaves a
    /// `{route: Some, in_flight: 0}` entry that no `gc` reclaims and no supersede releases,
    /// leaking the route until the transport LRU evicts it and growing `entries` unbounded
    /// across a long session of share-discovery churn (CRSH-ISC-26, §RS-3).
    ///
    /// If the share is idle (no in-flight fetch) the imported route is returned for
    /// immediate release and the entry is dropped now. If a fetch is still in flight a
    /// download may be streaming over the route, so the release is deferred to the
    /// **later** completion of that fetch (`note_fetch_finished` releases the route and
    /// drops the entry once `in_flight` reaches 0) and `None` is returned now — the same
    /// "whichever is later" discipline as `note_advert_replaced`.
    ///
    /// Idempotent: a second call for an already-withdrawn or absent share returns `None`,
    /// never handing the same route out twice. `entries` values are `take`n before being
    /// returned, and an actual double-release at the transport is itself a benign no-op
    /// (`release_tolerant` maps veilid's `InvalidArgument` to a trace), so a withdraw
    /// racing a concurrent re-import cannot double-free a route.
    #[must_use]
    pub fn note_share_withdrawn(&mut self, share: &S) -> Option<R> {
        let entry = self.entries.get_mut(share)?;
        if entry.in_flight == 0 {
            // Idle: release the current route now and drop the entry outright. When idle,
            // `pending_release` is always empty (a prior supersede released immediately or
            // was flushed by the fetch that reached idle), so `route` is the whole state.
            let route = entry.route.take();
            self.entries.remove(share);
            return route;
        }
        // In flight: defer. Mark the entry so the fetch's completion releases whatever
        // route it holds at idle and drops the entry (see `note_fetch_finished`). Marking
        // is idempotent; the route is not handed out here, so a re-withdraw returns `None`.
        entry.withdrawn = true;
        None
    }

    /// Drop a fully-idle, stateless entry so the map does not grow with dead shares.
    fn gc(&mut self, share: &S) {
        if self.entries.get(share).is_some_and(GuardEntry::is_empty) {
            self.entries.remove(share);
        }
    }

    /// The number of shares with tracked state — test/inspection only.
    #[cfg(test)]
    fn tracked_len(&self) -> usize {
        self.entries.len()
    }

    /// The route currently recorded for `share`, if any — test/inspection only.
    #[cfg(test)]
    fn route_for(&self, share: &S) -> Option<&R> {
        self.entries.get(share).and_then(|e| e.route.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CRSH-ISC-10a: a route is released on advert-replacement once the share is idle.
    #[test]
    fn releases_superseded_route_when_idle() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(1)).is_empty());
        assert_eq!(guard.route_for(&"s"), Some(&1));
        // Advert replaced while idle → release immediately.
        assert_eq!(guard.note_advert_replaced(&"s"), Some(1));
        assert_eq!(guard.tracked_len(), 0, "idle superseded entry is GC'd");
    }

    // CRSH-ISC-10a: "whichever is LATER" — advert replaces mid-fetch, so the release is
    // withheld until the in-flight fetch completes, not at the advert-fold event.
    #[test]
    fn defers_release_until_in_flight_fetch_completes() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        // First fetch imports route 1.
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(1)).is_empty());
        // A new fetch is in flight over route 1 …
        guard.note_fetch_started("s");
        // … when the advert is replaced: the release MUST NOT fire yet.
        assert_eq!(
            guard.note_advert_replaced(&"s"),
            None,
            "route in use — release deferred"
        );
        // The in-flight fetch completing is the later event → now route 1 releases.
        assert_eq!(guard.note_fetch_finished(&"s", None), vec![1]);
    }

    // The fetch can complete first; then the advert-replacement is the later event.
    #[test]
    fn releases_when_advert_replacement_is_the_later_event() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(7)).is_empty());
        // Idle now → advert-replacement releases straight away.
        assert_eq!(guard.note_advert_replaced(&"s"), Some(7));
    }

    // No route imported yet (import failed, or advert replaced before any fetch): the
    // guard supersedes nothing and releases nothing.
    #[test]
    fn no_release_when_nothing_imported() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        assert_eq!(guard.note_advert_replaced(&"s"), None);
        guard.note_fetch_started("s");
        assert_eq!(guard.note_fetch_finished(&"s", None), Vec::<u32>::new());
        // A failed fetch left the share with no route → still nothing to release.
        assert_eq!(guard.note_advert_replaced(&"s"), None);
        assert_eq!(guard.tracked_len(), 0);
    }

    // A second supersede while a fetch is still in flight keeps one deferred route; the
    // in-flight completion flushes it, and the newer route is retained as current.
    #[test]
    fn holds_one_deferred_route_across_double_supersede() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(1)).is_empty());
        // A fetch goes in flight, then two advert replacements land back-to-back.
        guard.note_fetch_started("s");
        assert_eq!(guard.note_advert_replaced(&"s"), None); // route 1 deferred
        // A newer fetch records route 2 while the first is still in flight.
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(2)).is_empty()); // in_flight 2→1
        assert_eq!(guard.note_advert_replaced(&"s"), None); // route 2 → newest pending (1 already held)
        // The last in-flight fetch finishing flushes exactly one deferred route.
        let released = guard.note_fetch_finished(&"s", None);
        assert_eq!(released.len(), 1, "one deferred route flushed on idle");
    }

    // CRSH-ISC-26: a withdraw of an IDLE share releases its imported route and drops the
    // entry immediately — no lingering `{route: Some, in_flight: 0}` leaked to the LRU.
    #[test]
    fn withdraw_releases_route_and_drops_entry_when_idle() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(9)).is_empty());
        assert_eq!(guard.route_for(&"s"), Some(&9));
        assert_eq!(
            guard.tracked_len(),
            1,
            "idle fetch leaves the route tracked"
        );
        // Withdraw while idle → route returned for release AND the entry is gone.
        assert_eq!(guard.note_share_withdrawn(&"s"), Some(9));
        assert_eq!(guard.tracked_len(), 0, "withdrawn idle entry is dropped");
    }

    // CRSH-ISC-26: a withdraw arriving mid-fetch does NOT release the route now (a
    // download may be streaming over it); the release + entry-drop fire on the LATER
    // completion of the in-flight fetch.
    #[test]
    fn withdraw_defers_release_to_in_flight_fetch_completion() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(4)).is_empty());
        // A new fetch is streaming over route 4 …
        guard.note_fetch_started("s");
        // … when the share is withdrawn: MUST NOT release mid-download.
        assert_eq!(
            guard.note_share_withdrawn(&"s"),
            None,
            "route in use — withdraw release deferred"
        );
        assert_eq!(
            guard.tracked_len(),
            1,
            "entry held until the fetch finishes"
        );
        // The in-flight fetch completing is the later event → route 4 releases + drops.
        assert_eq!(guard.note_fetch_finished(&"s", None), vec![4]);
        assert_eq!(
            guard.tracked_len(),
            0,
            "withdrawn entry dropped on completion"
        );
    }

    // CRSH-ISC-26 idempotency: a second withdraw hands out no route (idle: entry already
    // gone; in-flight: already marked) — the same route is never released twice.
    #[test]
    fn withdraw_is_idempotent() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        // Absent share → None.
        assert_eq!(guard.note_share_withdrawn(&"s"), None);
        // Idle share: first withdraw releases, second finds nothing.
        guard.note_fetch_started("s");
        assert!(guard.note_fetch_finished(&"s", Some(2)).is_empty());
        assert_eq!(guard.note_share_withdrawn(&"s"), Some(2));
        assert_eq!(guard.note_share_withdrawn(&"s"), None, "no double release");
        // In-flight share: first withdraw marks, second is a no-op, completion releases once.
        guard.note_fetch_started("t");
        assert!(guard.note_fetch_finished(&"t", Some(3)).is_empty());
        guard.note_fetch_started("t");
        assert_eq!(guard.note_share_withdrawn(&"t"), None);
        assert_eq!(
            guard.note_share_withdrawn(&"t"),
            None,
            "re-withdraw is a no-op"
        );
        assert_eq!(guard.note_fetch_finished(&"t", None), vec![3]);
        assert_eq!(guard.tracked_len(), 0);
    }

    // CRSH-ISC-26: a withdraw racing a concurrent re-import. The share is withdrawn while
    // a fetch is in flight, then a fresh fetch starts (a re-added share) BEFORE the first
    // completes. `note_fetch_started` voids the stale withdraw mark, so the re-imported
    // route is retained, not released out from under the live fetch.
    #[test]
    fn withdraw_then_reimport_retains_the_new_route() {
        let mut guard: ImportedRouteGuard<&str, u32> = ImportedRouteGuard::new();
        // Fetch A imports route 1 and is still in flight.
        guard.note_fetch_started("s");
        // Withdraw arrives mid-fetch → deferred.
        assert_eq!(guard.note_share_withdrawn(&"s"), None);
        // The share is re-added and a new fetch B starts → the withdraw mark is void.
        guard.note_fetch_started("s"); // in_flight now 2, withdrawn cleared
        // Fetch A completes (imports nothing) → not idle yet, nothing released.
        assert!(guard.note_fetch_finished(&"s", None).is_empty());
        // Fetch B completes importing the re-added route 5 → NOT released; share is live.
        assert!(guard.note_fetch_finished(&"s", Some(5)).is_empty());
        assert_eq!(
            guard.route_for(&"s"),
            Some(&5),
            "re-imported route retained"
        );
    }
}
