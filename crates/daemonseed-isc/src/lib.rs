//! ISC registry — the single source of truth for the ISC inventory.
//!
//! This is a **leaf crate with zero dependencies** so both
//! `daemonseed-integration-tests` (heavy — pulls core + proto) and `xtask`
//! (light) can read [`TOTAL`] and [`COVERED`] from ONE place. Before M15 the
//! count lived in two hand-maintained copies (this registry's `TOTAL` and a
//! `TOTAL_ISCS` mirror in xtask) that drifted; extracting the registry here
//! kills that mirror — `xtask` now reads [`TOTAL`] / [`COVERED`] directly.
//! `daemonseed-integration-tests::isc_coverage` re-exports this crate, so every
//! `m*_isc_coverage` test keeps registering against `isc_coverage::ISCS`
//! unchanged.
//!
//! Authoritative inventory: the repo-root `ISA.md` `## Criteria` (the ISC
//! document was promoted in-repo on 2026-05-29; there is no longer a vault
//! draft). [`ISCS`] tracks the **built, non-deferred** ISCs — it mirrors the
//! ISA `## Criteria` minus the deferred DM family and the vacant `C5`.
//!
//! Count invariants (kept aligned with `ISA.md` `## Criteria`):
//!
//! - 57 server-side: 32 positive (`ISC-S*`) + 25 negative (`ISC-A-S*`)
//!   (S31 added the #89 UploadMotd in-band signer-set MOTD)
//! - 123 client-side: 87 positive (`ISC-C*`) + 36 negative (`ISC-A-C*`)
//!   (M16 A1 added C66 manifest-preview + A-C33 no-blind-download, A2 added C67 selective-fetch,
//!   A3 added C68 choose-download-dir, A4 added C72 collapsible-folder-tree preview, C1 added C69
//!   multi-share-publish, C2 added C70 status-auto-clear, C3 added C71 generate-circle-phrase;
//!   M16 smoke fix added A-C34 publish-idempotency; M16 crown (serve-from-disk) added C73
//!   disk-backed publish/serve + C74 progress/cancel + C75 remove-defined-share + A-C35
//!   never-park/never-whole-share-in-RAM + A-C36 no-startup-index-lock, completed by the 1 MiB
//!   sub-file-chunking round (C73 amended to fixed CHUNK_SIZE relay-safe frames) which added C76
//!   robust-chunked-fetch (verify-before-append, stream-to-disk, inactivity timeout, clean
//!   partials) + A-C37 manifest-frame-budget publish refusal; M13 added C59-C62 circle
//!   persistence + A-C29/A-C30; M15 C added C63-C65 fetched-content browse/extract + A-C31/A-C32.
//!   Earlier: alpha2 share_id / share download / public rooms / client-lifecycle / portable.
//!   alpha3: C77/C78 unified-share + unread; C79/C80 connection resilience; C81 single-instance;
//!   C82 rename; C83-C86 + A-C38/A-C39 presence heartbeat; C87 + A-C40 graceful-EOS re-subscribe;
//!   A-C41 presence replay-freshness; C88 + A-C42 GUI Lobby roster;
//!   C89/C90 client signer authoring + self-determination;
//!   C91 GUI announcement + MOTD display panes;
//!   C92 signer-gated MOTD/announcement composer;
//!   C93 unread-gated announcements/MOTD landing;
//!   C94 GUI per-circle connected-presence;
//!   C95 palette rename-identity + live handle update;
//!   C96 GUI circle-detail name vectors;
//!   C97 right-click clipboard context menu on text fields;
//!   C98 GUI share-name persistence;
//!   WB-ISC-9/10/13 pos + WB-ISC-11/12 neg — the WB-3 write scheduler, #159.)
//! - 185 total
//!
//! Deliberately EXCLUDED from [`ISCS`] (and therefore from [`TOTAL`]) because
//! they are not built: the deferred direct-messaging family
//! (`C38-C46` / `A-C20-A-C25`, drafted in the ISA but post-MVP) and `C5`
//! (intentionally vacant — parking-lot reservation R5, folder encryption).

use std::collections::BTreeMap;

/// ISC class. Used by [`Coverage`] to look the ISC up in the right map and
/// reject same-string registration against the wrong half (e.g. registering
/// a positive test against `ISC-A-S1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IscClass {
    /// A positive ISC describes an end-state that must be reachable. A test
    /// satisfies it by producing that end-state.
    Positive,
    /// A negative ISC (`ISC-A-*`) describes a forbidden state. A test
    /// satisfies it by demonstrating the forbidden state cannot be reached
    /// — typically via a `should_panic`-style negative assertion or a
    /// property test that exhausts the space.
    Negative,
}

/// Every ISC known to this MVP, in declaration order from `ds-isc-draft.md`.
/// Length is [`TOTAL`].
pub const ISCS: &[(&str, IscClass)] = &[
    // ── server positive (32) ────────────────────────────────────────────
    ("ISC-S1", IscClass::Positive),
    ("ISC-S2a", IscClass::Positive),
    ("ISC-S2b", IscClass::Positive),
    ("ISC-S3", IscClass::Positive),
    ("ISC-S4", IscClass::Positive),
    ("ISC-S5", IscClass::Positive),
    ("ISC-S6", IscClass::Positive),
    ("ISC-S7", IscClass::Positive),
    ("ISC-S8", IscClass::Positive),
    ("ISC-S9", IscClass::Positive),
    ("ISC-S10", IscClass::Positive),
    ("ISC-S11", IscClass::Positive),
    ("ISC-S12", IscClass::Positive),
    ("ISC-S13", IscClass::Positive),
    ("ISC-S14", IscClass::Positive),
    ("ISC-S15", IscClass::Positive),
    ("ISC-S16", IscClass::Positive),
    ("ISC-S17", IscClass::Positive),
    ("ISC-S18", IscClass::Positive),
    ("ISC-S19", IscClass::Positive),
    ("ISC-S20", IscClass::Positive),
    ("ISC-S21", IscClass::Positive),
    ("ISC-S22", IscClass::Positive),
    ("ISC-S23", IscClass::Positive),
    ("ISC-S24", IscClass::Positive),
    ("ISC-S25", IscClass::Positive),
    ("ISC-S26", IscClass::Positive),
    ("ISC-S27", IscClass::Positive),
    ("ISC-S28", IscClass::Positive),
    ("ISC-S29", IscClass::Positive),
    ("ISC-S30", IscClass::Positive),
    // ── server positive (#89 UploadMotd: in-band signer-set MOTD) ────────
    ("ISC-S31", IscClass::Positive),
    // ── server negative (24) ────────────────────────────────────────────
    ("ISC-A-S1", IscClass::Negative),
    ("ISC-A-S2", IscClass::Negative),
    ("ISC-A-S3", IscClass::Negative),
    ("ISC-A-S4", IscClass::Negative),
    ("ISC-A-S4b", IscClass::Negative),
    ("ISC-A-S5", IscClass::Negative),
    ("ISC-A-S5b", IscClass::Negative),
    ("ISC-A-S6", IscClass::Negative),
    ("ISC-A-S7", IscClass::Negative),
    ("ISC-A-S8", IscClass::Negative),
    ("ISC-A-S9", IscClass::Negative),
    ("ISC-A-S10", IscClass::Negative),
    ("ISC-A-S11", IscClass::Negative),
    ("ISC-A-S12", IscClass::Negative),
    ("ISC-A-S13", IscClass::Negative),
    ("ISC-A-S14", IscClass::Negative),
    ("ISC-A-S15", IscClass::Negative),
    ("ISC-A-S16", IscClass::Negative),
    ("ISC-A-S17", IscClass::Negative),
    ("ISC-A-S18", IscClass::Negative),
    ("ISC-A-S19", IscClass::Negative),
    ("ISC-A-S20", IscClass::Negative),
    ("ISC-A-S21", IscClass::Negative),
    ("ISC-A-S22", IscClass::Negative),
    // ── server negative (presence heartbeat #74: relay does no heartbeat handling) ──
    ("ISC-A-S23", IscClass::Negative),
    // ── client positive (42) — C5 intentionally vacant (R5) ─────────────
    ("ISC-C1", IscClass::Positive),
    ("ISC-C2", IscClass::Positive),
    ("ISC-C3", IscClass::Positive),
    ("ISC-C4", IscClass::Positive),
    ("ISC-C4a", IscClass::Positive),
    ("ISC-C4b", IscClass::Positive),
    ("ISC-C6", IscClass::Positive),
    ("ISC-C7", IscClass::Positive),
    ("ISC-C8", IscClass::Positive),
    ("ISC-C9", IscClass::Positive),
    ("ISC-C10", IscClass::Positive),
    ("ISC-C11", IscClass::Positive),
    ("ISC-C12", IscClass::Positive),
    ("ISC-C13", IscClass::Positive),
    ("ISC-C14", IscClass::Positive),
    ("ISC-C15", IscClass::Positive),
    ("ISC-C16", IscClass::Positive),
    ("ISC-C17", IscClass::Positive),
    ("ISC-C18", IscClass::Positive),
    ("ISC-C19", IscClass::Positive),
    ("ISC-C20", IscClass::Positive),
    ("ISC-C21", IscClass::Positive),
    ("ISC-C22", IscClass::Positive),
    ("ISC-C23", IscClass::Positive),
    ("ISC-C24", IscClass::Positive),
    ("ISC-C25", IscClass::Positive),
    ("ISC-C26", IscClass::Positive),
    ("ISC-C27", IscClass::Positive),
    ("ISC-C28", IscClass::Positive),
    ("ISC-C29", IscClass::Positive),
    ("ISC-C30", IscClass::Positive),
    ("ISC-C31", IscClass::Positive),
    ("ISC-C32", IscClass::Positive),
    ("ISC-C33", IscClass::Positive),
    ("ISC-C34", IscClass::Positive),
    ("ISC-C35", IscClass::Positive),
    ("ISC-C36", IscClass::Positive),
    ("ISC-C37", IscClass::Positive),
    // ── client positive (alpha2: C47-C52 client-lifecycle/portable, C56-C58 public rooms) ──
    ("ISC-C47", IscClass::Positive),
    ("ISC-C48", IscClass::Positive),
    ("ISC-C49", IscClass::Positive),
    ("ISC-C50", IscClass::Positive),
    ("ISC-C51", IscClass::Positive),
    ("ISC-C52", IscClass::Positive),
    ("ISC-C56", IscClass::Positive),
    ("ISC-C57", IscClass::Positive),
    ("ISC-C58", IscClass::Positive),
    // ── client positive (M13 multi-circle persistence; M15 C fetched browse) ──
    ("ISC-C59", IscClass::Positive),
    ("ISC-C60", IscClass::Positive),
    ("ISC-C61", IscClass::Positive),
    ("ISC-C62", IscClass::Positive),
    ("ISC-C63", IscClass::Positive),
    ("ISC-C64", IscClass::Positive),
    ("ISC-C65", IscClass::Positive),
    ("ISC-C66", IscClass::Positive),
    ("ISC-C67", IscClass::Positive),
    ("ISC-C68", IscClass::Positive),
    // ── client positive (M16 C1 multi-share publish; C2 status-auto-clear; C3 generate-circle-phrase) ──
    ("ISC-C69", IscClass::Positive),
    ("ISC-C70", IscClass::Positive),
    ("ISC-C71", IscClass::Positive),
    // ── client positive (M16 A4 collapsible-folder-tree fetch preview) ──
    ("ISC-C72", IscClass::Positive),
    ("ISC-C73", IscClass::Positive),
    ("ISC-C74", IscClass::Positive),
    ("ISC-C75", IscClass::Positive),
    // ── client positive (M16 chunking completion: robust chunked fetch) ──
    ("ISC-C76", IscClass::Positive),
    // ── client positive (alpha3 unified-share-model: key-class safety) ──
    ("ISC-C77", IscClass::Positive),
    ("ISC-C78", IscClass::Positive),
    // ── client positive (alpha3 GUI connection resilience: drop detection + auto-reconnect) ──
    ("ISC-C79", IscClass::Positive),
    ("ISC-C80", IscClass::Positive),
    // ── client positive (single-instance profile-root guard) ──
    ("ISC-C81", IscClass::Positive),
    // ── client positive (rename identity: re-seal display name) ──
    ("ISC-C82", IscClass::Positive),
    // ── client positive (presence heartbeat #74: emit, wire-shape, tracker) ──
    ("ISC-C83", IscClass::Positive),
    ("ISC-C84", IscClass::Positive),
    ("ISC-C85", IscClass::Positive),
    // ── client positive (presence heartbeat #76: share liveness on the digest) ──
    ("ISC-C86", IscClass::Positive),
    // ── client positive (#80: graceful per-stream EOS re-subscribes, keeps session) ──
    ("ISC-C87", IscClass::Positive),
    // ── client positive (#75: GUI surfaces the live Lobby roster) ──
    ("ISC-C88", IscClass::Positive),
    // ── client positive (#90: client signer authoring + self-determination) ──
    ("ISC-C89", IscClass::Positive),
    ("ISC-C90", IscClass::Positive),
    // ── client positive (#91: GUI announcement + MOTD display panes) ──
    ("ISC-C91", IscClass::Positive),
    // ── client positive (#92: signer-gated MOTD/announcement composer) ──
    ("ISC-C92", IscClass::Positive),
    // ── client positive (#93: unread-gated announcements/MOTD landing) ──
    ("ISC-C93", IscClass::Positive),
    // ── client positive (#77: GUI per-circle connected-presence) ──
    ("ISC-C94", IscClass::Positive),
    // ── client positive (#66: rename identity from the Ctrl-K palette — live update) ──
    ("ISC-C95", IscClass::Positive),
    // ── client positive (#36: circle-detail name vectors) ──
    ("ISC-C96", IscClass::Positive),
    // ── client positive (#67: right-click Cut/Copy/Paste/Select-all context menu on text fields) ──
    ("ISC-C97", IscClass::Positive),
    // ── client positive (#41: GUI share-name persistence — a named share auto-republishes under it) ──
    ("ISC-C98", IscClass::Positive),
    // ── client negative (20) ────────────────────────────────────────────
    ("ISC-A-C1", IscClass::Negative),
    ("ISC-A-C2", IscClass::Negative),
    ("ISC-A-C3", IscClass::Negative),
    ("ISC-A-C4", IscClass::Negative),
    ("ISC-A-C5", IscClass::Negative),
    ("ISC-A-C6", IscClass::Negative),
    ("ISC-A-C7", IscClass::Negative),
    ("ISC-A-C8", IscClass::Negative),
    ("ISC-A-C9", IscClass::Negative),
    ("ISC-A-C10", IscClass::Negative),
    ("ISC-A-C11", IscClass::Negative),
    ("ISC-A-C12", IscClass::Negative),
    ("ISC-A-C13", IscClass::Negative),
    ("ISC-A-C14", IscClass::Negative),
    ("ISC-A-C15", IscClass::Negative),
    ("ISC-A-C16", IscClass::Negative),
    ("ISC-A-C17", IscClass::Negative),
    ("ISC-A-C18", IscClass::Negative),
    ("ISC-A-C19", IscClass::Negative),
    // ── client negative (alpha2 client-identity-lifecycle, E/F) ─────────
    ("ISC-A-C26", IscClass::Negative),
    ("ISC-A-C27", IscClass::Negative),
    ("ISC-A-C28", IscClass::Negative),
    // ── client negative (M13 cross-circle isolation; M15 C fetched safety) ──
    ("ISC-A-C29", IscClass::Negative),
    ("ISC-A-C30", IscClass::Negative),
    ("ISC-A-C31", IscClass::Negative),
    ("ISC-A-C32", IscClass::Negative),
    ("ISC-A-C33", IscClass::Negative),
    ("ISC-A-C34", IscClass::Negative),
    ("ISC-A-C35", IscClass::Negative),
    ("ISC-A-C36", IscClass::Negative),
    // ── client negative (M16 chunking completion: manifest frame budget) ──
    ("ISC-A-C37", IscClass::Negative),
    // ── client negative (presence heartbeat #74: no roster leak, no persist) ──
    ("ISC-A-C38", IscClass::Negative),
    ("ISC-A-C39", IscClass::Negative),
    // ── client negative (#80: a graceful EOS must not tear down the session) ──
    ("ISC-A-C40", IscClass::Negative),
    // ── client negative (#78: a replayed/stale-dated beacon must not refresh presence) ──
    ("ISC-A-C41", IscClass::Negative),
    // ── client negative (#75: the roster shows only the live set, no decorators/persistence) ──
    ("ISC-A-C42", IscClass::Negative),
    // ── write budget scheduler (#159 WB-3 funnel — docs/design/veilid-write-budget.md) ──
    // WB-ISC-9/10/13 positive; WB-ISC-11/12 anti (no-chat-drop / tombstone-dominance).
    ("WB-ISC-9", IscClass::Positive),
    ("WB-ISC-10", IscClass::Positive),
    ("WB-ISC-11", IscClass::Negative),
    ("WB-ISC-12", IscClass::Negative),
    ("WB-ISC-13", IscClass::Positive),
];

/// Total built, non-deferred ISCs tracked by this registry — the SINGLE source
/// of truth for the coverage denominator, read live by `xtask isc-coverage`.
/// Recount on every ISC add/remove (the `const _` assert below guards it
/// against [`ISCS`]).
pub const TOTAL: usize = 185;

const _: () = assert!(
    ISCS.len() == TOTAL,
    "ISCS length must match TOTAL — update both when adding/removing ISCs"
);

/// Per-milestone count of distinct ISCs that have at least one *registered*
/// integration test (the `m*_isc_coverage` test files each register their slice
/// and assert that slice's count). The sum is [`COVERED`]; `covered_sum_matches`
/// asserts the two agree, so bumping one without the other is caught.
///
/// This is the registered (integration-covered) count, distinct from ISCs that
/// only have unit coverage in core/tui — e.g. the M13/M15-C client ISCs
/// (C59-C65, A-C29-A-C32) are in [`ISCS`] (they are built) but are not yet
/// registered by an integration test, so they are not in this sum. Their
/// integration registration is a tracked follow-up; until then the honest
/// picture is `COVERED / TOTAL` with that gap visible.
pub const MILESTONE_COVERED: &[(&str, usize)] = &[
    ("M1", 17),
    ("M2", 12),
    ("M3", 5),
    ("M4a", 9),
    ("M4b", 5),
    ("M5", 7),
    ("M6", 12),
    ("M7", 5),
    ("M12", 0),
    ("alpha2", 28),
    ("alpha3", 10),
];

/// Distinct ISCs covered by a registered integration test — the SINGLE source
/// of truth for the coverage numerator, read live by `xtask isc-coverage`
/// (it replaced a hand-maintained `COVERED_ISCS` mirror in xtask). Equals the
/// sum of [`MILESTONE_COVERED`] (guarded by `covered_sum_matches`).
pub const COVERED: usize = 110;

const _: () = assert!(
    COVERED <= TOTAL,
    "COVERED must not exceed TOTAL — the covered numerator cannot exceed the ISC denominator"
);

/// Live coverage state. Tests register themselves against an ISC ID via
/// [`Coverage::register`], which routes to the right half (positive /
/// negative) based on the ID's class in [`ISCS`].
///
/// At M0 the registry is constructed empty; M1+ tests start populating it.
pub struct Coverage {
    pub positive_tests: BTreeMap<&'static str, Vec<&'static str>>,
    pub negative_tests: BTreeMap<&'static str, Vec<&'static str>>,
}

impl Coverage {
    /// Empty registry — M0 baseline.
    pub fn empty() -> Self {
        Self {
            positive_tests: BTreeMap::new(),
            negative_tests: BTreeMap::new(),
        }
    }

    /// Register a test against an ISC. Panics if the ISC ID is unknown
    /// (catches typos at test-startup time, not at xtask-run time).
    pub fn register(&mut self, isc_id: &'static str, test_id: &'static str) {
        let class = lookup_class(isc_id)
            .unwrap_or_else(|| panic!("unknown ISC id: {isc_id} — update isc_coverage::ISCS"));
        let map = match class {
            IscClass::Positive => &mut self.positive_tests,
            IscClass::Negative => &mut self.negative_tests,
        };
        map.entry(isc_id).or_default().push(test_id);
    }

    /// Number of distinct ISCs that have at least one registered test in
    /// the matching half. ISCs that only appear in the wrong half are NOT
    /// counted (positive ISCs need a positive test; negative ISCs need a
    /// negative test).
    pub fn covered_count(&self) -> usize {
        let mut count = 0usize;
        for (id, class) in ISCS.iter() {
            let map = match class {
                IscClass::Positive => &self.positive_tests,
                IscClass::Negative => &self.negative_tests,
            };
            if map.get(*id).is_some_and(|v| !v.is_empty()) {
                count += 1;
            }
        }
        count
    }

    /// Percent of ISCs covered (0.0 .. 100.0).
    pub fn percent_covered(&self) -> f64 {
        if TOTAL == 0 {
            return 0.0;
        }
        (self.covered_count() as f64) * 100.0 / (TOTAL as f64)
    }
}

fn lookup_class(isc_id: &str) -> Option<IscClass> {
    ISCS.iter()
        .find_map(|(id, c)| (*id == isc_id).then_some(*c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_count_matches_total() {
        assert_eq!(ISCS.len(), TOTAL);
    }

    #[test]
    fn isc_s20_is_registered_server_positive() {
        // ISC-S20 (circle-of-trust live relay) was formalized at M8 (F23) and
        // AGENTS.md tracks 94 ISCs, but this registry lagged at 93 — the M8
        // milestone never backfilled the entry. It is a server-positive ISC.
        assert_eq!(lookup_class("ISC-S20"), Some(IscClass::Positive));
    }

    #[test]
    fn registry_has_no_duplicates() {
        let mut seen = std::collections::BTreeSet::new();
        for (id, _) in ISCS.iter() {
            assert!(seen.insert(*id), "duplicate ISC id in registry: {id}");
        }
    }

    #[test]
    fn registry_class_distribution_matches_agents_md() {
        let (mut pos, mut neg) = (0usize, 0usize);
        for (_, c) in ISCS.iter() {
            match c {
                IscClass::Positive => pos += 1,
                IscClass::Negative => neg += 1,
            }
        }
        // ISA `## Criteria` (built, non-deferred): 56 server + 113 client = 169.
        //   server  31 pos + 25 neg = 56  (presence heartbeat #74: A-S23 neg)
        //   client  79 pos + 34 neg = 113 (M13 C59-C62 + A-C29/A-C30;
        //                                  M15 C  C63-C65 + A-C31/A-C32;
        //                                  M16 A1 C66 + A-C33; A2 C67; A3 C68;
        //                                  A4 C72; C1 C69; C2 C70; C3 C71;
        //                                  smoke fix A-C34 publish-idempotency;
        //                                  crown C73-C75 + A-C35/A-C36 serve-from-disk;
        //                                  chunking completion C76 robust-chunked-fetch
        //                                  + A-C37 manifest-frame-budget;
        //                                  unified share model C77 pos;
        //                                  client-side unread dot C78 pos, #64;
        //                                  connection resilience C79 drop-detection #72,
        //                                  C80 auto-reconnect #71;
        //                                  single-instance lock C81 pos, #60;
        //                                  rename-identity re-seal C82 pos, #66;
        //                                  presence heartbeat C83-C85 pos + A-C38/A-C39 neg, #74;
        //                                  share-liveness-on-heartbeat C86 pos, #76;
        //                                  graceful-EOS re-subscribe C87 pos + A-C40 neg, #80;
        //                                  presence replay-freshness A-C41 neg, #78;
        //                                  GUI Lobby roster surface C88 pos + A-C42 neg, #75;
        //                                  in-band UploadMotd S31 pos, #89;
        //                                  client signer authoring C89 + self-determination C90 pos, #90;
        //                                  GUI announcement + MOTD display panes C91 pos, #91;
        //                                  signer-gated MOTD/announcement composer C92 pos, #92;
        //                                  unread-gated announcements/MOTD landing C93 pos, #93;
        //                                  GUI per-circle connected-presence C94 pos, #77;
        //                                  palette rename-identity + live update C95 pos, #66;
        //                                  GUI circle-detail name vectors C96 pos, #36;
        //                                  right-click clipboard context menu C97 pos, #67;
        //                                  GUI share-name persistence C98 pos, #41;
        //                                  WB-3 write scheduler WB-ISC-9/10/13 pos +
        //                                  WB-ISC-11/12 neg, #159)
        //   total   122 pos + 63 neg = 185
        assert_eq!(pos, 122, "positive count drift");
        assert_eq!(neg, 63, "negative count drift");
    }

    /// COVERED is single-sourced and must agree with the per-milestone
    /// registered slices — bumping one without the other is a drift bug.
    #[test]
    fn covered_sum_matches() {
        let sum: usize = MILESTONE_COVERED.iter().map(|(_, n)| n).sum();
        assert_eq!(sum, COVERED, "MILESTONE_COVERED sum must equal COVERED");
    }

    #[test]
    fn m0_baseline_is_zero_percent() {
        let c = Coverage::empty();
        assert_eq!(c.covered_count(), 0);
        assert_eq!(c.percent_covered(), 0.0);
    }

    #[test]
    fn register_routes_to_correct_half() {
        let mut c = Coverage::empty();
        c.register("ISC-S1", "smoke_test_s1");
        c.register("ISC-A-S1", "smoke_negative_a_s1");
        assert!(c.positive_tests.contains_key("ISC-S1"));
        assert!(c.negative_tests.contains_key("ISC-A-S1"));
        assert_eq!(c.covered_count(), 2);
    }

    #[test]
    #[should_panic(expected = "unknown ISC id")]
    fn register_rejects_unknown_isc() {
        let mut c = Coverage::empty();
        c.register("ISC-FAKE", "typo_test");
    }
}
