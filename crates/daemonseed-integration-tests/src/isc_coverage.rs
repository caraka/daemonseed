//! ISC coverage registry.
//!
//! Authoritative source: `~/carakastan/Projects/DaemonSeed/ds-isc-draft.md`
//! (private phase). When the repo opens publicly, this list gets promoted
//! into the in-repo ISC document.
//!
//! Count invariants (must stay aligned with AGENTS.md "Standards target"
//! section and the project manifest):
//!
//! - 37 server-side: 21 positive (`ISC-S*`) + 16 negative (`ISC-A-S*`)
//! - 65 client-side: 43 positive (`ISC-C*`) + 22 negative (`ISC-A-C*`)
//!   (the alpha2 client-identity-lifecycle batch added C47–C51 +
//!   A-C26–A-C28; the DM family C38–C46 / A-C20–A-C25 stays alpha2-deferred
//!   and is not yet tracked here)
//! - 102 total
//!
//! `C5` is intentionally vacant (parking-lot reservation R5, folder
//! encryption — post-MVP).

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
    // ── server positive (21) ────────────────────────────────────────────
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
    // ── server negative (16) ────────────────────────────────────────────
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
    // ── client positive (38) — C5 intentionally vacant (R5) ─────────────
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
    // ── client positive (alpha2 client-identity-lifecycle, C/D/E/F) ─────
    ("ISC-C47", IscClass::Positive),
    ("ISC-C48", IscClass::Positive),
    ("ISC-C49", IscClass::Positive),
    ("ISC-C50", IscClass::Positive),
    ("ISC-C51", IscClass::Positive),
    // ── client negative (19) ────────────────────────────────────────────
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
];

/// Total ISCs tracked by this registry. Recount on every ISC add/remove.
pub const TOTAL: usize = 102;

const _: () = assert!(
    ISCS.len() == TOTAL,
    "ISCS length must match TOTAL — update both when adding/removing ISCs"
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
        // 37 server-side + 65 client-side = 102. Split:
        //   server  21 pos + 16 neg = 37  (ISC-S20 backfilled, M8/F23)
        //   client  43 pos + 22 neg = 65  (alpha2 client-identity-lifecycle
        //           added C47–C51 + A-C26/A-C27/A-C28)
        //   total   64 pos + 38 neg = 102
        assert_eq!(pos, 64, "positive count drift");
        assert_eq!(neg, 38, "negative count drift");
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
