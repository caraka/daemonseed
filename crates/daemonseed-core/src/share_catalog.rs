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
use crate::share_announce::share_binding_is_valid;

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
    /// The announcer's **self-asserted** display handle, verbatim from the signed
    /// `ShareAnnouncement`. It MAY be a bare name (a client with a display name set)
    /// OR a full `name#<12hex>` (a client that publishes its whole wire handle, e.g.
    /// the TUI). It is a DISPLAY label only — strip the `#<12hex>` for presentation
    /// ([`crate::handle::strip_handle_hash`]). It is NOT the identity: the sharer is
    /// authenticated by the announcement's ML-DSA-87 provenance signature over
    /// `sender_pubkey`, and the verified attribution to show is `sharer_fingerprint`.
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
    /// (#180 §RS-1.4) A discovered share whose last fetch failed and which is now
    /// **re-resolving**: the frontend marks its route `Unresolved` and keeps the share
    /// listed while a parked one-shot retry waits for a fresh advert. The UI renders it as
    /// "re-resolving" rather than removing it — the reactive path never prunes on a fetch
    /// failure (CRSH-ISC-5). Set by the frontend from its local discovered-route state;
    /// always `false` on a fresh listing and on own shares.
    pub unresolved: bool,
}

impl From<&DiscoveredShare> for ShareListing {
    fn from(d: &DiscoveredShare) -> Self {
        Self {
            share_id: d.share_id.clone(),
            name: d.name.clone(),
            rating: d.rating.clone(),
            sharer_handle: d.sender_handle.clone(),
            // #114: the verified-pubkey fingerprint, the anti-spoof attribution the
            // UI reveals on hover — derived from the signed `sender_pubkey`, never
            // parsed from the self-asserted `sender_handle` (which MAY carry a
            // `#<12hex>` and is a display label, not identity).
            sharer_fingerprint: pubkey_fingerprint(&d.sender_pubkey),
            mine: false, // a discovered share is a foreign announcer's
            // The catalog does not know the frontend's re-resolve state; the frontend
            // overlays it from its local discovered-route map (#180 §RS-1.4).
            unresolved: false,
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

    /// Ingest gate (#156): fold an announcement ONLY if it passes the
    /// receiver-verifiable binding check — `share_id ==
    /// derive_share_id_v2(sender_pubkey, root_commitment)` with a 48-byte
    /// commitment ([`share_binding_is_valid`]) — else it is a no-op. This is THE
    /// catalog ingest point every consumer folds through (relay + veilid), so the
    /// check runs BEFORE either the announce fold or the withdraw branch, on both.
    /// An absent / non-48-byte / non-derivable announcement folds nothing, with no
    /// legacy or owner-binding fallback arm (design §2/§3/§5 anti-requirement): an
    /// attacker can no longer occupy or censor a scraped victim `share_id` by
    /// pairing it with its own key. Callers MUST use this (not the raw `apply`,
    /// which is the pure catalog logic and does NOT check the binding).
    pub fn apply_verified(&mut self, ann: &wire::ShareAnnouncement, now: Instant) -> CatalogChange {
        if !share_binding_is_valid(ann) {
            return CatalogChange::Unchanged;
        }
        self.apply(ann, now)
    }

    /// Fold a verified announcement into the catalog. The caller has already
    /// `open_announcement`'d it (so provenance is verified) and confirmed it
    /// belongs to this catalog's room. `now` is the local monotonic receive time.
    ///
    /// **The v2 binding is NOT checked here — call `apply_verified` at every
    /// ingest point (#156).** This is the pure catalog state machine (continuity /
    /// ordering / TTL), left directly callable for unit tests that exercise that
    /// logic without constructing a fully-derived announcement.
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
                // First-writer-wins CONTINUITY (#152, demoted at #156): a refresh may
                // NOT change the owner of a known `share_id`. Since #156 the security
                // rests on the ingest binding check (`apply_verified`): a differing
                // `sender_pubkey` cannot even reach here with a valid id, because
                // `share_id == derive_share_id_v2(sender_pubkey, root_commitment)`
                // bakes the key in — a foreign key recomputes to a different id. This
                // clause is therefore now a pure continuity rule (a known id keeps its
                // first-seen key), NOT load-bearing for security. NB: no
                // "id-not-derivable ⇒ accept under owner-binding" escape may be added
                // here — that is exactly the reopening the binding check closes.
                Some(cur) if ann.sender_pubkey != cur.sender_pubkey => CatalogChange::Unchanged,
                Some(cur) if ann.sent_unix_ms < cur.announced_unix_ms => CatalogChange::Unchanged,
                // (#180 F3) An identical re-read — same owner, same timestamp, same
                // metadata — carries no new information (a genuine re-announce/route
                // rotation always bumps the timestamp, published atomically with the
                // route blob), so fold it as Unchanged to stop the consumer's steady
                // resweep spuriously bumping the discovered-entry generation. The pubkey
                // is already proven equal by the arm above; a NEWER-timestamp re-announce
                // (same metadata) still falls through to the Updated arm below — that is
                // the self-heal's re-advertise trigger and MUST keep folding Updated.
                Some(cur)
                    if ann.sent_unix_ms == cur.announced_unix_ms
                        && ann.name == cur.name
                        && ann.rating == cur.rating
                        && ann.sender_handle == cur.sender_handle =>
                {
                    // (#180 R2) Re-hearing keeps the share alive for the TTL prune
                    // (`received_at` is the liveness clock the prune ages against), but it
                    // carries no new content — refresh `received_at` yet fold `Unchanged` so
                    // the frontend skips the generation bump. The two behaviours (liveness
                    // re-hearing vs content-change signalling) are separated: a sharer's
                    // watchdog republishes the SAME sealed advert (only the route blob
                    // rotates) every ~150s, so without this the steady resweep always folds
                    // `Unchanged`, `received_at` freezes at discovery time, and the ~600s TTL
                    // prune ages out a live, actively-reswept share.
                    cur.received_at = now;
                    CatalogChange::Unchanged
                }
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
            // The pure-`apply` tests do not exercise the #156 binding (that is
            // `apply_verified`'s job, tested separately below); an arbitrary
            // commitment keeps the message well-formed.
            root_commitment: vec![0u8; 48],
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

    /// #180 F3/R2: an identical re-read (same owner + timestamp + metadata) folds as
    /// Unchanged — the consumer's steady resweep re-reading the same advert every
    /// cycle must not spuriously bump the discovered-entry generation — BUT it
    /// refreshes `received_at` (re-hearing keeps the share alive for the TTL prune).
    #[test]
    fn identical_reread_refreshes_received_at_but_folds_unchanged() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(
            cat.apply(&announcement("a", "docs", false, 100), t0),
            CatalogChange::Added
        );
        let before = cat.entries()[0].received_at;
        // Re-reading the exact same advert (same sent_unix_ms + metadata) later in
        // wall-clock time folds Unchanged (no generation bump)…
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(
            cat.apply(&announcement("a", "docs", false, 100), t1),
            CatalogChange::Unchanged
        );
        // …but received_at IS advanced to the re-read's `now` — re-hearing keeps the
        // share alive for the TTL prune (R2). Without this the prune would age out a
        // continuously-reheard live share.
        assert_eq!(cat.entries()[0].received_at, t1);
        assert!(cat.entries()[0].received_at > before);
        assert_eq!(cat.len(), 1);
    }

    /// #180 R2: a continuously-reheard live share is NOT aged out by the TTL prune.
    /// The identical re-read refreshes `received_at` (folding Unchanged), so a share
    /// reheard within the TTL survives a prune whose window since discovery exceeds
    /// the TTL — while a share never reheard is pruned after the TTL.
    #[test]
    fn reheard_share_survives_ttl_prune() {
        let ttl = Duration::from_secs(60);
        let mut cat = ShareCatalog::new(ttl);
        let t0 = Instant::now();
        cat.apply(&announcement("a", "docs", false, 100), t0);

        // Re-hear the identical advert just under the TTL (folds Unchanged, refreshes
        // received_at to t_reread).
        let t_reread = t0 + Duration::from_secs(50);
        assert_eq!(
            cat.apply(&announcement("a", "docs", false, 100), t_reread),
            CatalogChange::Unchanged
        );

        // Now prune at a time where elapsed since DISCOVERY > TTL (70s > 60s) but
        // elapsed since the RE-READ < TTL (20s < 60s): the reheard share must survive.
        let t_prune = t0 + Duration::from_secs(70);
        assert_eq!(
            cat.prune(t_prune),
            0,
            "a reheard live share must not be pruned"
        );
        assert_eq!(cat.len(), 1);

        // Contrast: an identical share never reheard IS pruned once the TTL elapses.
        let mut cold = ShareCatalog::new(ttl);
        cold.apply(&announcement("a", "docs", false, 100), t0);
        assert_eq!(
            cold.prune(t_prune),
            1,
            "a share never reheard is aged out after the TTL"
        );
        assert!(cold.is_empty());
    }

    /// #180 F3 (crux): a genuine re-announce carries the SAME metadata with a
    /// FRESHER timestamp and MUST still fold as Updated — that is the self-heal's
    /// re-advertise trigger. The identity gate keys on timestamp equality, not
    /// metadata-only.
    #[test]
    fn same_metadata_newer_timestamp_reannounce_folds_updated() {
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();
        cat.apply(&announcement("a", "docs", false, 100), t0);
        assert_eq!(
            cat.apply(
                &announcement("a", "docs", false, 200),
                t0 + Duration::from_secs(1)
            ),
            CatalogChange::Updated
        );
        assert_eq!(cat.entries()[0].announced_unix_ms, 200);
    }

    /// #180 F3: at an EQUAL timestamp, any real metadata difference (name, rating,
    /// or sender_handle) still folds as Updated — only a total identity is Unchanged.
    #[test]
    fn equal_timestamp_differing_metadata_folds_updated() {
        let t0 = Instant::now();
        // Differing name.
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        cat.apply(&announcement("a", "docs", false, 100), t0);
        assert_eq!(
            cat.apply(&announcement("a", "docs v2", false, 100), t0),
            CatalogChange::Updated
        );
        assert_eq!(cat.entries()[0].name, "docs v2");

        // Differing rating (same name + timestamp).
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        cat.apply(&announcement("a", "docs", false, 100), t0);
        let mut diff_rating = announcement("a", "docs", false, 100);
        diff_rating.rating = "R".to_owned();
        assert_eq!(cat.apply(&diff_rating, t0), CatalogChange::Updated);
        assert_eq!(cat.entries()[0].rating, "R");

        // Differing sender_handle (same name + rating + timestamp + owner pubkey).
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        cat.apply(&announcement("a", "docs", false, 100), t0);
        let mut diff_handle = announcement("a", "docs", false, 100);
        diff_handle.sender_handle = "river-otter#112233445566".to_owned();
        assert_eq!(cat.apply(&diff_handle, t0), CatalogChange::Updated);
        assert_eq!(cat.entries()[0].sender_handle, "river-otter#112233445566");
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

    // ── #156 ingest binding gate (apply_verified) ───────────────────────────

    use crate::identity::keys::SignKeypair;
    use crate::share_announce::{
        derive_root_commitment, derive_share_id_v2, derive_share_root_nonce,
    };

    fn signer(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    /// Build a genuinely v2-bound announcement for `(kp, root)`: derive the nonce,
    /// commitment, and id so `apply_verified` accepts it.
    fn verified_ann(
        kp: &SignKeypair,
        ikm: &[u8],
        root: &str,
        name: &str,
        withdraw: bool,
        sent_unix_ms: i64,
    ) -> wire::ShareAnnouncement {
        let nonce = derive_share_root_nonce(ikm, root);
        let rc = derive_root_commitment(root, &nonce);
        let share_id = derive_share_id_v2(kp.public_key(), &rc);
        wire::ShareAnnouncement {
            room: "lobby".to_owned(),
            sender_pubkey: kp.public_key().to_vec(),
            sender_handle: "river-otter#aabbccddeeff".to_owned(),
            share_id,
            root_commitment: rc.to_vec(),
            name: name.to_owned(),
            rating: "PG".to_owned(),
            withdraw,
            sent_unix_ms,
            signature: vec![9, 9, 9],
        }
    }

    /// #156: a genuine v2 announcement folds; a forged pairing (victim id under
    /// the attacker's key) folds NOTHING — on both the announce and the withdraw
    /// branch.
    #[test]
    fn apply_verified_folds_genuine_rejects_forged_pairing_both_branches() {
        let victim = signer(1);
        let attacker = signer(2);
        let ikm = [3u8; 32];
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        let t0 = Instant::now();

        let genuine = verified_ann(&victim, &ikm, "/srv/docs", "docs", false, 100);
        assert_eq!(cat.apply_verified(&genuine, t0), CatalogChange::Added);
        assert_eq!(cat.len(), 1);

        // Attacker scrapes the victim's id + rc, re-announces under its OWN key.
        let mut forged = genuine.clone();
        forged.sender_pubkey = attacker.public_key().to_vec();
        forged.name = "evil".to_owned();
        forged.sent_unix_ms = 1_000_000;
        assert_eq!(
            cat.apply_verified(&forged, t0 + Duration::from_secs(1)),
            CatalogChange::Unchanged,
            "a victim id under the attacker's key must not fold (binding check)"
        );
        assert_eq!(cat.entries()[0].name, "docs");

        // Same forged pairing on the WITHDRAW branch is equally inert.
        let mut forged_withdraw = forged.clone();
        forged_withdraw.withdraw = true;
        assert_eq!(
            cat.apply_verified(&forged_withdraw, t0 + Duration::from_secs(2)),
            CatalogChange::Unchanged
        );
        assert_eq!(
            cat.len(),
            1,
            "the victim's share survives a forged withdraw"
        );
    }

    /// #156 (unconditional reject): an announcement with an absent / non-48-byte
    /// commitment for a scraped victim id folds nothing — no fallback arm.
    #[test]
    fn apply_verified_rejects_absent_commitment_for_scraped_id() {
        let victim = signer(4);
        let ikm = [5u8; 32];
        let genuine = verified_ann(&victim, &ikm, "/data", "data", false, 100);
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        // Same id, but the commitment is stripped (proto3 empty-bytes default).
        let mut stripped = genuine.clone();
        stripped.root_commitment = Vec::new();
        assert_eq!(
            cat.apply_verified(&stripped, Instant::now()),
            CatalogChange::Unchanged
        );
        assert!(cat.is_empty());
    }

    /// #156 (circle-path parity): the binding gate is tier-independent — a circle
    /// share folds through the SAME `apply_verified`, so an insider forging a
    /// circle `share_id` under its own key folds nothing, exactly as on the lobby.
    #[test]
    fn apply_verified_circle_path_rejects_insider_forgery() {
        let owner = signer(6);
        let insider = signer(7);
        let ikm = [8u8; 32];
        let genuine = verified_ann(&owner, &ikm, "/circle/share", "cs", false, 100);
        let mut cat = ShareCatalog::new(Duration::from_secs(60));
        assert_eq!(
            cat.apply_verified(&genuine, Instant::now()),
            CatalogChange::Added
        );
        // An insider (circle member) forges the owner's id under its own key.
        let mut forged = genuine.clone();
        forged.sender_pubkey = insider.public_key().to_vec();
        forged.sent_unix_ms = 1_000_000;
        assert_eq!(
            cat.apply_verified(&forged, Instant::now()),
            CatalogChange::Unchanged
        );
        assert_eq!(cat.entries()[0].sender_pubkey, owner.public_key().to_vec());
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
