//! Alpha2 — portable mode (`--portable`) ISC traceability.
//!
//! ISC-C52 extends profile-root resolution (ISC-C35) with a `--portable` flag
//! that forces the current working directory to be the profile root and skips
//! the XDG fallback, so a fresh first-start writes its config / blob / `.dseed`
//! into the CWD rather than the system location. `--config` still takes
//! precedence when both are supplied.
//!
//! ## ISCs closed by this change: 1
//!
//! | ISC      | claim                                              | proving test |
//! |----------|----------------------------------------------------|--------------|
//! | ISC-C52  | `--portable` forces a fresh profile into the CWD, skipping XDG | `daemonseed_core::profile::resolve::tests::portable_fresh_targets_cwd_not_xdg` + `portable_skips_xdg_even_when_xdg_has_a_config` + `config_flag_wins_over_portable` |
//!
//! The behaviour is proved by the unit tests in
//! `crates/daemonseed-core/src/profile/resolve.rs` (registered by name below);
//! this file records the spec-ISC → test traceability, mirroring the
//! per-milestone `mNN_isc_coverage.rs` convention.

use daemonseed_integration_tests::isc_coverage::Coverage;

#[test]
fn alpha2_portable_closes_one_isc() {
    let mut coverage = Coverage::empty();
    coverage.register("ISC-C52", "portable_fresh_targets_cwd_not_xdg");
    coverage.register("ISC-C52", "portable_skips_xdg_even_when_xdg_has_a_config");
    coverage.register("ISC-C52", "config_flag_wins_over_portable");
    assert_eq!(
        coverage.covered_count(),
        1,
        "portable mode closes ISC-C52 (--portable forces the CWD as profile root)"
    );
}
