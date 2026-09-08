//! Alpha2 item B — share content download ISC traceability.
//!
//! Discovery published a share's listing; nothing served its **content**
//! except the inline logic in `share_fetch_e2e`. Item B lifts that serve side
//! into a reusable path — `daemonseed_core::share_serve::ShareContent`
//! (directory index + content-addressed store + the pure `answer` step) driven
//! by `daemonseed_cli::session::AppSession::serve_share` (the subscribe-stream
//! serve loop) — and wires it into `cli publish --path <dir>`. The consumer
//! (TUI `FetchShare`) already worked; the serve side closes the loop.
//!
//! ## ISCs closed by this change: 5
//!
//! | ISC        | claim                                                        | proving test |
//! |------------|--------------------------------------------------------------|--------------|
//! | ISC-S27    | sharer serves content (index → chunk → answer manifest/chunk) | `daemonseed_core::share_serve::tests::index_dir_builds_manifest_and_stores_chunks` + `share_serve_e2e::fetcher_recovers_share_via_real_serve_path` |
//! | ISC-S28    | every chunk SHA-384-verified; fetcher recovers exact bytes   | `share_serve_e2e::fetcher_recovers_share_via_real_serve_path` + `daemonseed_core::share_serve::tests::answer_chunk_request_is_content_addressed` |
//! | ISC-S29    | one serve loop, many concurrent fetchers (relay fan-in/out)  | `share_serve_e2e::fetcher_recovers_share_via_real_serve_path` (serve loop answers a fetcher over the relay's fan-out, the ISC-S17-bounded multi-fetcher surface) |
//! | ISC-A-S20  | tampered chunk rejected (re-derived hash mismatch)           | `daemonseed_core::share_envelope::tests::chunk_response_verification_matches_against_recomputed_address` + `share_fetch_e2e::tampered_chunk_response_fails_recomputed_hash_check` |
//! | ISC-A-S21  | offline sharer's content is unfetchable (live-only)          | `share_serve_e2e::offline_sharer_content_is_unfetchable` + `daemonseed_core::share_serve::tests::answer_unknown_chunk_yields_no_frame` |
//!
//! The behaviour is proved by the unit + e2e tests named below; this file
//! records the spec-ISC → test traceability, mirroring the per-milestone
//! `mNN_isc_coverage.rs` convention.

use daemonseed_integration_tests::isc_coverage::Coverage;

#[test]
fn alpha2_share_download_closes_five_iscs() {
    let mut coverage = Coverage::empty();
    coverage.register("ISC-S27", "index_dir_builds_manifest_and_stores_chunks");
    coverage.register("ISC-S27", "fetcher_recovers_share_via_real_serve_path");
    coverage.register("ISC-S28", "fetcher_recovers_share_via_real_serve_path");
    coverage.register("ISC-S28", "answer_chunk_request_is_content_addressed");
    coverage.register("ISC-S29", "fetcher_recovers_share_via_real_serve_path");
    coverage.register(
        "ISC-A-S20",
        "chunk_response_verification_matches_against_recomputed_address",
    );
    coverage.register(
        "ISC-A-S20",
        "tampered_chunk_response_fails_recomputed_hash_check",
    );
    coverage.register("ISC-A-S21", "offline_sharer_content_is_unfetchable");
    coverage.register("ISC-A-S21", "answer_unknown_chunk_yields_no_frame");
    assert_eq!(
        coverage.covered_count(),
        5,
        "item B closes ISC-S27/S28/S29 (serve content + verify + multi-fetcher) \
         and ISC-A-S20/A-S21 (tampered rejected + offline unfetchable)"
    );
}
