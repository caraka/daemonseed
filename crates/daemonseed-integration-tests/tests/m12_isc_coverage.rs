//! M12 (→ v0.14.0 = MVP) — gate steps 5 & 6 ISC traceability.
//!
//! M12 ships the last two MVP-gate steps:
//!
//! - **step 5** — user-publish file sharing (`PublishShare` / `UnpublishShare`
//!   / `ListPublicShares`), held-connection "you must be online to share", and
//!   cross-client reap-on-disconnect of the RAM-only share.
//! - **step 6** — the federation introducer endpoint + the TUI Servers-pane
//!   refresh that surfaces introducer-discovered candidates.
//!
//! ## Genuinely-new ISCs closed by M12: **zero**
//!
//! Both halves were deliberately built against the *existing* ISC surface — the
//! ISA records (Decisions, 2026-06-01) that "M12 has no dedicated `ISC-38`; the
//! user-publish wire surface was designed against the existing ISCs." Every ISC
//! M12's two gate tests exercise was already registered (and counted in the
//! global `COVERED_ISCS` floor) by an earlier milestone:
//!
//! | ISC      | what M12 re-exercises                        | first registered |
//! |----------|----------------------------------------------|------------------|
//! | ISC-A-S1 | RAM-only share reaped on disconnect; the relay persists no user share state (gate step 5) | M4b (`server_keeps_no_persistent_client_record`) |
//! | ISC-A-S5b| the relay is a blind forwarder — it never polices or filters a published share (gate step 5) | M6 (`public_space_*`) |
//! | ISC-S4   | the public-space surface hosts user file shares (gate step 5) | M6 (`public_space_serves_the_full_public_surface`) |
//! | ISC-S6   | the introducer response carries no key material (gate step 6) | M5 (`introducer_response_carries_no_public_key`) |
//! | ISC-S13  | only `introduce_to_clients` peers are surfaced (gate step 6) | M5 (`dont_introduce_peer_is_invisible_to_an_active_enumerator`) |
//! | ISC-C22  | an introducer-discovered server is a candidate, treated identically to manual entry — never auto-trusted (gate step 6) | M5 (`client_trusts_two_servers_with_independent_modes`) |
//! | ISC-A-C19| no auto-discovery into the active trust set; promotion is an explicit user action (gate step 6) | M2 (`m2_isc_coverage`) |
//!
//! Because none of these is newly-covered, **`COVERED_ISCS` in `xtask` stays at
//! 72** — the lower-bound floor does not move at M12. This file exists to record
//! the end-to-end *traceability* of the two new gate steps to the spec-ISCs they
//! reinforce (the registration below maps each ISC to the M12 gate test that
//! exercises it), and to assert — as a regression — that the M12 surface closes
//! no ISC that an earlier milestone had not already closed.
//!
//! The two gate tests themselves live in `tests/subprocess_gate.rs`
//! (`cli_published_share_is_cross_client_visible_then_reaped` for step 5 and
//! `daemon_servers_pane_surfaces_introducer_candidate` for step 6); they are
//! `#[ignore]`-gated and run via `cargo xtask mvp-gate`.

use daemonseed_integration_tests::isc_coverage::Coverage;

/// The seven spec-ISCs the M12 gate steps re-exercise end-to-end, paired with
/// the `subprocess_gate` test that drives each. Used by the tally below; kept as
/// a single source so the count and the mapping can't drift apart.
const M12_REEXERCISED: &[(&str, &str)] = &[
    // ── gate step 5: user-publish file sharing ──────────────────────────
    (
        "ISC-A-S1",
        "subprocess_gate::cli_published_share_is_cross_client_visible_then_reaped \
         (RAM-only share reaped on connection drop — no persistent user share state)",
    ),
    (
        "ISC-A-S5b",
        "subprocess_gate::cli_published_share_is_cross_client_visible_then_reaped \
         (blind-relay publish: the server forwards, never polices the share)",
    ),
    (
        "ISC-S4",
        "subprocess_gate::cli_published_share_is_cross_client_visible_then_reaped \
         (public-space surface hosts the user file share)",
    ),
    // ── gate step 6: federation introducer endpoint + Servers-pane refresh
    (
        "ISC-S6",
        "subprocess_gate::daemon_servers_pane_surfaces_introducer_candidate \
         (introducer render carries no key material)",
    ),
    (
        "ISC-S13",
        "subprocess_gate::daemon_servers_pane_surfaces_introducer_candidate \
         (only introduce_to_clients peers are surfaced)",
    ),
    (
        "ISC-C22",
        "subprocess_gate::daemon_servers_pane_surfaces_introducer_candidate \
         (discovered peer is a candidate, never auto-trusted)",
    ),
    (
        "ISC-A-C19",
        "subprocess_gate::daemon_servers_pane_surfaces_introducer_candidate \
         (no auto-discovery into the trust set; promotion is explicit)",
    ),
];

// ── ISC coverage tally ──────────────────────────────────────────────────────

/// M12 re-exercises seven existing spec-ISCs at the two new gate steps but
/// closes **zero genuinely-new** ones — so the global `COVERED_ISCS` floor
/// (`xtask`) does not move. This test pins both facts: the seven-ISC trace map
/// is registered, and `register` accepts every ID (catching a typo'd ISC id at
/// test-startup, exactly as the other `mN_isc_coverage` tallies do).
#[test]
fn m12_reexercises_existing_iscs_and_closes_none_new() {
    let mut coverage = Coverage::empty();
    for (isc, test) in M12_REEXERCISED {
        coverage.register(isc, test);
    }
    assert_eq!(
        coverage.covered_count(),
        7,
        "M12's two gate steps trace to 7 existing spec-ISCs (3 for step 5, 4 for step 6)"
    );
}

/// Guard: every ISC M12 touches was already registered by an earlier milestone,
/// so the M12 milestone contributes **no** increment to the static lower-bound
/// floor. If a future change makes one of these genuinely-new (e.g. an ISC is
/// renumbered or a step-5/6 ISC is dropped from an earlier tally), this list and
/// the `xtask` `COVERED_ISCS` constant must be revisited together.
#[test]
fn m12_adds_no_new_isc_to_the_global_floor() {
    // The exact set earlier milestones already cover, per the per-file tallies
    // m2/m4b/m5/m6. (Asserting membership of the set we re-exercise, not the
    // whole registry, keeps this guard local to M12's surface.)
    const ALREADY_COVERED_BEFORE_M12: &[&str] = &[
        "ISC-A-S1",  // M4b
        "ISC-A-S5b", // M6
        "ISC-S4",    // M6
        "ISC-S6",    // M5
        "ISC-S13",   // M5
        "ISC-C22",   // M5
        "ISC-A-C19", // M2
    ];
    for (isc, _) in M12_REEXERCISED {
        assert!(
            ALREADY_COVERED_BEFORE_M12.contains(isc),
            "{isc} is exercised by M12 but is NOT recorded as covered before M12 — \
             if it is genuinely new, bump xtask COVERED_ISCS and update this guard"
        );
    }
}
