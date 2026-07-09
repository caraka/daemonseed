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

use crate::handle::pubkey_fingerprint;

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

/// A public-share row as surfaced to clients — the in-band replacement for the
/// retired `wire::PublicShareListing` (#51). Plain client-side struct: the relay
/// no longer defines or carries this shape. Fields are the sharer's self-asserted
/// classification (advisory; never relay-policed).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ShareListing {
    pub share_id: String,
    pub name: String,
    pub rating: String,
    pub sharer_handle: String,
    /// #114: the announcer's `#12hex` fingerprint, derived from the VERIFIED
    /// `sender_pubkey` (`SHA-384(pubkey)[:12]`) — NOT parsed from the advisory,
    /// spoofable `sharer_handle`. Empty for own shares (rendered "you"). The UI
    /// reveals it on hover so a foreign sharer can be identity-checked against the
    /// same fingerprint the Lobby roster shows.
    pub sharer_fingerprint: String,
    /// True for a share this node published itself (rendered as "you"); false for
    /// a foreign discovered share, which shows the announcer's `sharer_handle` as
    /// the attribution (#114). Own shares are the caller's own, so their handle is
    /// not a discovery attribution.
    pub mine: bool,
}

impl From<&DiscoveredShare> for ShareListing {
    fn from(d: &DiscoveredShare) -> Self {
        Self {
            share_id: d.share_id.clone(),
            name: d.name.clone(),
            rating: d.rating.clone(),
            sharer_handle: d.sender_handle.clone(),
            // #114: the verified-pubkey fingerprint, the anti-spoof attribution the
            // UI reveals on hover (the advisory `sender_handle` carries no hash).
            sharer_fingerprint: pubkey_fingerprint(&d.sender_pubkey),
            mine: false, // a discovered share is a foreign announcer's
        }
    }
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
                // Owner-binding (#152): only the share's own announcer may withdraw
                // it. The lobby record is world-writable and the `share_id` is
                // publicly visible, so without this a foreign peer could scrape a
                // victim's `share_id`, self-sign a validly-provenanced withdraw for
                // it, and evict (censor) the share. `open_announcement` proves WHO
                // announced, not that they OWN this id — so we check ownership here.
                Some(cur) if ann.sender_pubkey != cur.sender_pubkey => CatalogChange::Unchanged,
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
                // First-writer-wins on identity (#152): a refresh may NOT change the
                // owner of a known `share_id`. Blocks the takeover/redirect exploit
                // where a foreign peer re-announces a victim's `share_id` under its
                // own key + route, so a fetcher intending the victim's share is
                // redirected. An honest owner always re-derives the same
                // `share_id = derive_share_id(sender_pubkey, root)`, so a differing
                // `sender_pubkey` for a live id is never legitimate.
                Some(cur) if ann.sender_pubkey != cur.sender_pubkey => CatalogChange::Unchanged,
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

    /// Reconcile one sharer's shares against a verified heartbeat's live-share
    /// digest (#76). For shares this catalog holds from `sharer_pubkey`: refresh
    /// the receive-time of those whose id is in `live_ids` (so share liveness
    /// rides the heartbeat — no periodic re-announce needed), and remove any
    /// absent from it (the sharer dropped them without a withdraw — self-healing).
    /// Digest ids not yet in the catalog are ignored — a full `ShareAnnouncement`
    /// (on change, or via a late-join roll-call) fills those in; the digest never
    /// fabricates a share, since it lacks the name/rating/rendezvous. Returns
    /// whether the visible set changed (a removal); a pure liveness refresh is not.
    pub fn reconcile_sharer(
        &mut self,
        sharer_pubkey: &[u8],
        live_ids: &[String],
        now: Instant,
    ) -> bool {
        let mut removed = false;
        self.entries.retain(|id, s| {
            if s.sender_pubkey != sharer_pubkey {
                return true;
            }
            if live_ids.iter().any(|d| d == id) {
                true
            } else {
                removed = true;
                false
            }
        });
        for id in live_ids {
            if let Some(s) = self.entries.get_mut(id)
                && s.sender_pubkey == sharer_pubkey
            {
                s.received_at = now;
            }
        }
        removed
    }

    /// Drop every share from one sharer — the prune-on-heartbeat-lapse backstop
    /// (#76): when a member's heartbeat ages out of the presence tracker, its
    /// shares go with it. Returns the number removed.
    pub fn prune_sharer(&mut self, sharer_pubkey: &[u8]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, s| s.sender_pubkey != sharer_pubkey);
        before - self.entries.len()
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

    #[test]
    fn share_listing_from_a_discovered_share_carries_the_announcer_handle_not_mine() {
        // #114: a foreign discovered share surfaces the ANNOUNCER's handle as its
        // attribution and is NOT marked `mine` — own shares are marked mine by the
        // client's own-share listing path (gui/relay `listings()`).
        let d = DiscoveredShare {
            share_id: "s1".to_owned(),
            name: "vacation".to_owned(),
            rating: "PG".to_owned(),
            sender_handle: "river-otter#aabbccddeeff".to_owned(),
            sender_pubkey: vec![1, 2, 3],
            announced_unix_ms: 100,
            received_at: Instant::now(),
        };
        let listing = ShareListing::from(&d);
        assert_eq!(listing.sharer_handle, "river-otter#aabbccddeeff");
        assert!(
            !listing.mine,
            "a discovered share is a foreign announcer's, not mine"
        );
    }

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

    /// #152 (censorship): a foreign peer that scraped a victim's public `share_id`
    /// cannot evict the share by self-signing a validly-provenanced withdraw for it.
    #[test]
    fn foreign_peer_cannot_withdraw_a_share_it_does_not_own() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "docs", false, 100), t0); // owner [1,2,3]
        // Attacker [9,9,9] forges a withdraw with a large sent_unix_ms.
        let mut forged = announcement("a", "docs", true, 1_000_000);
        forged.sender_pubkey = vec![9, 9, 9];
        assert_eq!(
            cat.apply(&forged, t0 + Duration::from_secs(1)),
            CatalogChange::Unchanged
        );
        assert_eq!(
            cat.len(),
            1,
            "the victim's share must survive the forged withdraw"
        );
        assert_eq!(cat.entries()[0].sender_pubkey, vec![1, 2, 3]);
    }

    /// #152 (takeover/redirect): a foreign peer cannot re-announce a known
    /// `share_id` under its own key/route to redirect fetchers. First-writer-wins
    /// on identity — the owner's metadata is untouched.
    #[test]
    fn foreign_peer_cannot_hijack_a_known_share_id() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "real", false, 100), t0); // owner [1,2,3]
        let mut forged = announcement("a", "evil", false, 1_000_000);
        forged.sender_pubkey = vec![9, 9, 9];
        forged.sender_handle = "attacker#ffffffffffff".to_owned();
        assert_eq!(
            cat.apply(&forged, t0 + Duration::from_secs(1)),
            CatalogChange::Unchanged
        );
        let e = &cat.entries()[0];
        assert_eq!(e.sender_pubkey, vec![1, 2, 3], "owner key must not change");
        assert_eq!(e.name, "real", "hijacker metadata must not overwrite");
        assert_eq!(e.sender_handle, "river-otter#aabbccddeeff");
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

    /// #76: a heartbeat digest refreshes in-digest shares' liveness and removes
    /// a sharer's shares absent from it.
    #[test]
    fn reconcile_refreshes_in_digest_and_removes_absent() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("s1", "one", false, 100), t0); // sharer pubkey [1,2,3]
        cat.apply(&announcement("s2", "two", false, 100), t0);
        assert_eq!(cat.len(), 2);
        // Digest says only s1 is live → s2 removed (sharer dropped it), s1 refreshed.
        let changed =
            cat.reconcile_sharer(&[1, 2, 3], &["s1".to_owned()], t0 + Duration::from_secs(30));
        assert!(changed);
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.entries()[0].share_id, "s1");
        // s1's received_at was refreshed to +30s → survives a prune at +50s (60s TTL).
        assert_eq!(cat.prune(t0 + Duration::from_secs(50)), 0);
    }

    /// #76: reconcile touches only the named sharer; another sharer's shares are
    /// untouched even with an empty digest.
    #[test]
    fn reconcile_only_touches_the_named_sharer() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("s1", "mine", false, 100), t0); // pubkey [1,2,3]
        let mut other = announcement("s2", "theirs", false, 100);
        other.sender_pubkey = vec![9, 9, 9];
        cat.apply(&other, t0);
        // Empty digest for [1,2,3] removes only s1; the other sharer's s2 stays.
        assert!(cat.reconcile_sharer(&[1, 2, 3], &[], t0));
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.entries()[0].share_id, "s2");
    }

    /// #76: prune_sharer drops all of one sharer's shares (heartbeat-lapse).
    #[test]
    fn prune_sharer_drops_all_of_one_sharer() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("s1", "a", false, 100), t0);
        cat.apply(&announcement("s2", "b", false, 100), t0);
        let mut other = announcement("s3", "c", false, 100);
        other.sender_pubkey = vec![9, 9, 9];
        cat.apply(&other, t0);
        assert_eq!(cat.prune_sharer(&[1, 2, 3]), 2);
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.entries()[0].share_id, "s3");
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
