//! In-band share discovery catalog (unified share model; design-of-record:
//! `docs/design/unified-share-model.md`).
//!
//! The client-side replacement for the relay's `SharePublishRegistry`: instead
//! of asking the relay "what is published?", a client listens to a room/circle
//! stream, opens + verifies each [`wire::ShareAnnouncement`]
//! ([`crate::share_announce::open_announcement`]), and folds it into a
//! [`ShareCatalog`]. The catalog is what the share browser renders. It is
//! deliberately tiny and transport-free — both the TUI and the GUI net actors
//! hold one and feed it verified announcements, so discovery has a single shared
//! shape.
//!
//! ## Liveness (two-speed)
//!
//! - **Fast push:** a live announce/withdraw reaches subscribers in real time and
//!   is applied immediately ([`ShareCatalog::apply`]).
//! - **Slow reconcile:** a jittered timer prunes anything not re-announced within
//!   a TTL ([`ShareCatalog::prune`]), self-healing a missed announce/withdraw.
//!   The TTL is measured from the **local receive time** (a monotonic
//!   [`Instant`]), never the announcer's advisory wall-clock — there is no global
//!   clock and the relay stamps nothing. Callers MUST set the prune TTL to more
//!   than ~2 re-announce intervals so a single missed reconcile cycle does not
//!   drop a still-live share.
//! - **Fetch-failure backstop:** a crashed sharer cannot send a withdraw, so a
//!   fetcher that fails to reach a share removes it directly
//!   ([`ShareCatalog::remove`]).
//!
//! ## Ordering / replay
//!
//! Each announcement carries an advisory `sent_unix_ms` bound into its provenance
//! signature. For a share already known, an announcement (announce *or* withdraw)
//! whose `sent_unix_ms` is **older** than the stored one is ignored, so a
//! reordered or replayed stale frame cannot override a fresher state. One edge is
//! left to the TTL: a stale announce **replayed after** a withdraw (when the
//! entry is already gone, so there is nothing to compare against) can transiently
//! re-add a share — but with its old receive-time semantics it is bounded by, and
//! ages out within, the prune TTL. A persistent withdrawal tombstone would close
//! that window immediately; it is deferred until the threat model demands it
//! (`docs/design/unified-share-model.md`, "Relay replay buffer").

use std::collections::HashMap;
use std::time::{Duration, Instant};

use daemonseed_proto::v1 as wire;

/// One discovered share — the rendered row of the share browser, built from a
/// verified [`wire::ShareAnnouncement`]. Carries `sender_pubkey` so the UI can
/// bind the displayed handle to `SHA-384(sender_pubkey)[:12]` (ISC-C4 / ISC-C57)
/// rather than trusting the advisory `sender_handle`.
#[derive(Clone, Debug)]
pub struct DiscoveredShare {
    /// The share's opaque id (ISC-S21) — names the fetch rendezvous address.
    pub share_id: String,
    /// Display name of the shared folder.
    pub name: String,
    /// Sharer-assigned rating label (advisory).
    pub rating: String,
    /// The announcer's self-asserted display handle (`name#12hex`). Advisory —
    /// cross-check against `sender_pubkey` before trusting it.
    pub sender_handle: String,
    /// The announcer's ML-DSA-87 public key (provenance was already verified when
    /// the announcement was opened; kept for the ISC-C4 handle binding).
    pub sender_pubkey: Vec<u8>,
    /// The announcer's advisory wall-clock at announce time (unix ms). Used only
    /// for ordering successive announcements of the *same* share; never for TTL.
    pub announced_unix_ms: i64,
    /// Local monotonic receive time of the most recent announce. TTL pruning is
    /// measured from here.
    pub received_at: Instant,
}

/// What [`ShareCatalog::apply`] did with an announcement — lets a caller decide
/// whether the share browser needs a redraw without diffing the whole catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogChange {
    /// A previously-unknown share was inserted.
    Added,
    /// A known share's metadata / liveness was refreshed.
    Updated,
    /// A known share was withdrawn (removed).
    Removed,
    /// The announcement was a no-op (stale/reordered, or a withdraw of an
    /// unknown share).
    Unchanged,
}

/// The live set of shares discovered in ONE room/circle. The caller scopes it:
/// feed it only announcements opened under this room's key (it does not re-check
/// the announcement's `room` field — the subscription already namespaces that).
#[derive(Debug)]
pub struct ShareCatalog {
    entries: HashMap<String, DiscoveredShare>,
    ttl: Duration,
}

impl ShareCatalog {
    /// A new empty catalog pruning entries older than `ttl` (measured from local
    /// receive time). `ttl` MUST exceed ~2 re-announce intervals.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Fold a verified announcement into the catalog. The caller has already
    /// `open_announcement`'d it (so provenance is verified) and confirmed it
    /// belongs to this catalog's room. `now` is the local monotonic receive time.
    ///
    /// - `withdraw = true` → remove the share (if the withdraw is at least as new
    ///   as what we hold).
    /// - `withdraw = false` → insert a new share, or refresh a known one — unless
    ///   the announcement is older than the one we already have for that id.
    pub fn apply(&mut self, ann: &wire::ShareAnnouncement, now: Instant) -> CatalogChange {
        if ann.withdraw {
            match self.entries.get(&ann.share_id) {
                // A withdraw older than the live announce it would cancel is a
                // reorder/replay — ignore it.
                Some(cur) if ann.sent_unix_ms < cur.announced_unix_ms => CatalogChange::Unchanged,
                Some(_) => {
                    self.entries.remove(&ann.share_id);
                    CatalogChange::Removed
                }
                None => CatalogChange::Unchanged,
            }
        } else {
            match self.entries.get_mut(&ann.share_id) {
                Some(cur) if ann.sent_unix_ms < cur.announced_unix_ms => CatalogChange::Unchanged,
                Some(cur) => {
                    cur.name = ann.name.clone();
                    cur.rating = ann.rating.clone();
                    cur.sender_handle = ann.sender_handle.clone();
                    cur.sender_pubkey = ann.sender_pubkey.clone();
                    cur.announced_unix_ms = ann.sent_unix_ms;
                    cur.received_at = now;
                    CatalogChange::Updated
                }
                None => {
                    self.entries.insert(
                        ann.share_id.clone(),
                        DiscoveredShare {
                            share_id: ann.share_id.clone(),
                            name: ann.name.clone(),
                            rating: ann.rating.clone(),
                            sender_handle: ann.sender_handle.clone(),
                            sender_pubkey: ann.sender_pubkey.clone(),
                            announced_unix_ms: ann.sent_unix_ms,
                            received_at: now,
                        },
                    );
                    CatalogChange::Added
                }
            }
        }
    }

    /// Age out every share whose most recent announce is older than the TTL — the
    /// slow-reconcile half of liveness, called on the jittered timer. Returns the
    /// number pruned.
    pub fn prune(&mut self, now: Instant) -> usize {
        let ttl = self.ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, s| now.saturating_duration_since(s.received_at) < ttl);
        before - self.entries.len()
    }

    /// Remove a share explicitly — the fetch-failure backstop (a crashed sharer
    /// cannot withdraw, so a fetcher that cannot reach a share drops it). Returns
    /// whether a share was present.
    pub fn remove(&mut self, share_id: &str) -> bool {
        self.entries.remove(share_id).is_some()
    }

    /// The live shares, sorted by display name then `share_id` for a stable
    /// render order.
    pub fn entries(&self) -> Vec<DiscoveredShare> {
        let mut out: Vec<DiscoveredShare> = self.entries.values().cloned().collect();
        out.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.share_id.cmp(&b.share_id))
        });
        out
    }

    /// Number of live shares.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog holds no shares.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement(
        share_id: &str,
        name: &str,
        withdraw: bool,
        sent_unix_ms: i64,
    ) -> wire::ShareAnnouncement {
        wire::ShareAnnouncement {
            room: "lobby".to_owned(),
            sender_pubkey: vec![1, 2, 3],
            sender_handle: "river-otter#aabbccddeeff".to_owned(),
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            rating: "PG".to_owned(),
            withdraw,
            sent_unix_ms,
            signature: vec![9, 9, 9],
        }
    }

    #[test]
    fn announce_adds_then_refresh_updates() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(
            cat.apply(&announcement("a", "docs", false, 100), t0),
            CatalogChange::Added
        );
        assert_eq!(cat.len(), 1);
        // A newer announce for the same id refreshes (Updated), not duplicates.
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(
            cat.apply(&announcement("a", "docs v2", false, 200), t1),
            CatalogChange::Updated
        );
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.entries()[0].name, "docs v2");
    }

    #[test]
    fn stale_announce_for_known_share_is_ignored() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "fresh", false, 200), t0);
        // An older announce (lower sent_unix_ms) must not override the fresher one.
        assert_eq!(
            cat.apply(
                &announcement("a", "stale", false, 100),
                t0 + Duration::from_secs(1)
            ),
            CatalogChange::Unchanged
        );
        assert_eq!(cat.entries()[0].name, "fresh");
    }

    #[test]
    fn withdraw_removes_known_share() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "docs", false, 100), t0);
        assert_eq!(
            cat.apply(
                &announcement("a", "docs", true, 200),
                t0 + Duration::from_secs(1)
            ),
            CatalogChange::Removed
        );
        assert!(cat.is_empty());
    }

    #[test]
    fn withdraw_of_unknown_share_is_noop() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        assert_eq!(
            cat.apply(&announcement("ghost", "x", true, 100), Instant::now()),
            CatalogChange::Unchanged
        );
    }

    #[test]
    fn stale_withdraw_does_not_cancel_fresher_announce() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "docs", false, 200), t0);
        // A withdraw older than the live announce is a reorder/replay — ignored.
        assert_eq!(
            cat.apply(
                &announcement("a", "docs", true, 100),
                t0 + Duration::from_secs(1)
            ),
            CatalogChange::Unchanged
        );
        assert_eq!(cat.len(), 1);
    }

    #[test]
    fn prune_ages_out_only_stale_entries() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("old", "old", false, 100), t0);
        cat.apply(
            &announcement("new", "new", false, 100),
            t0 + Duration::from_secs(50),
        );
        // At t0 + 70s: "old" is 70s stale (> 60s TTL), "new" is 20s (< TTL).
        let pruned = cat.prune(t0 + Duration::from_secs(70));
        assert_eq!(pruned, 1);
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.entries()[0].share_id, "new");
    }

    #[test]
    fn refresh_resets_the_prune_clock() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "docs", false, 100), t0);
        // Re-announce at +50s resets received_at, so at +70s it is only 20s old.
        cat.apply(
            &announcement("a", "docs", false, 200),
            t0 + Duration::from_secs(50),
        );
        assert_eq!(cat.prune(t0 + Duration::from_secs(70)), 0);
        assert_eq!(cat.len(), 1);
    }

    #[test]
    fn explicit_remove_is_the_fetch_failure_backstop() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        cat.apply(&announcement("a", "docs", false, 100), Instant::now());
        assert!(cat.remove("a"));
        assert!(!cat.remove("a")); // already gone
        assert!(cat.is_empty());
    }

    #[test]
    fn entries_are_sorted_by_name_then_id() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("z", "banana", false, 100), t0);
        cat.apply(&announcement("a", "apple", false, 100), t0);
        cat.apply(&announcement("m", "apple", false, 100), t0);
        let names: Vec<_> = cat
            .entries()
            .into_iter()
            .map(|s| (s.name, s.share_id))
            .collect();
        assert_eq!(
            names,
            vec![
                ("apple".to_owned(), "a".to_owned()),
                ("apple".to_owned(), "m".to_owned()),
                ("banana".to_owned(), "z".to_owned()),
            ]
        );
    }
}
