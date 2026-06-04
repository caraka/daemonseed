//! Alpha2 — opaque `share_id` ISC traceability.
//!
//! Item A of the alpha2 cycle replaces the published-share registry's monotonic
//! `share_id` counter (`format!("{n:016x}")` — first share `0000…`, all ids
//! sequential and enumerable) with a 128-bit OS-CSPRNG draw, hex-encoded, with
//! unique-in-registry retry. A guessable `share_id` is a guessable circle-of-trust
//! fetch-asset address, so the counter undercut the blind-relay privacy posture
//! (ISC-A-S2).
//!
//! ## ISCs closed by this change: 2
//!
//! | ISC        | claim                                                        | proving test |
//! |------------|-------------------------------------------------------------|--------------|
//! | ISC-S21    | `share_id` is 128-bit CSPRNG entropy, lowercase-hex, unique | `daemonseed_server::share::tests::share_id_is_opaque_128bit_lowercase_hex` + `many_share_ids_are_unique_and_well_formed` |
//! | ISC-A-S15  | `share_id` is never sequential / order-derived / enumerable | `daemonseed_server::share::tests::share_ids_are_not_sequential_or_order_derived` |
//!
//! The behaviour is proved by the unit tests in `crates/daemonseed-server/src/share.rs`
//! (registered by name below); this file records the spec-ISC → test traceability,
//! mirroring the per-milestone `mNN_isc_coverage.rs` convention.

use daemonseed_integration_tests::isc_coverage::Coverage;

#[test]
fn alpha2_opaque_share_id_closes_two_iscs() {
    let mut coverage = Coverage::empty();
    coverage.register("ISC-S21", "share_id_is_opaque_128bit_lowercase_hex");
    coverage.register("ISC-S21", "many_share_ids_are_unique_and_well_formed");
    coverage.register("ISC-A-S15", "share_ids_are_not_sequential_or_order_derived");
    assert_eq!(
        coverage.covered_count(),
        2,
        "item A closes ISC-S21 (opaque CSPRNG share_id) and ISC-A-S15 (anti: never enumerable)"
    );
}
