//! End-to-end exercise of the 4 surviving M3 spec-ISCs.
//!
//! Per `ds-mvp-implementation-plan.md:68-73`, M3 closes ISC-C24, A-C8,
//! S15, A-C9 — the suite registry + crypto-agility primitives.
//! (M3 also originally registered ISC-A-S10 server-src suite-transparency;
//! that anti-criterion was withdrawn at the v0.33.0 Veilid cutover — the
//! relay crate is gone — so its structural grep block was removed and its
//! coverage subsumes into ISC-A-S2 / ISC-C24.)
//! This test walks the public surface introduced by M3's four commits
//! and registers one coverage entry per surviving spec-ISC. The final
//! assertion pins the registered count to 4.

use daemonseed_core::crypto::policy::WritePolicy;
use daemonseed_core::crypto::suite::{CNSA_2_0, LifecycleState, Registry, SuiteId, WriteRefusal};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::storage::{recovery_file, seeds};
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_proto::v1::SuiteId as WireSuiteId;
use uuid::Uuid;

fn init_oxicrypt() {
    let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
}

fn fast_params() -> ArgonParams {
    ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

const STRONG_PASSPHRASE: &str = "correct horse battery staple table mountain";

#[test]
fn m3_iscs_exercise_end_to_end() {
    init_oxicrypt();
    let mut coverage = Coverage::empty();

    // ── ISC-C24: every cryptographic artifact the client authors carries
    // a suite_id resolved through the in-build registry. Walk the chain:
    // registry lookup → default write-suite → at-rest blob v2 round-trip
    // → recovery file v2 round-trip → wire-side proto round-trip →
    // touch_reseal (read-old-write-new on touch). All five touch points
    // must agree on the same SuiteId for the M3 single-entry registry.
    // ─────────────────────────────────────────────────────────────────────
    let cnsa = Registry::lookup(SuiteId::try_new(0x0001).unwrap()).unwrap();
    assert_eq!(*cnsa, CNSA_2_0);
    assert_eq!(Registry::default_write_suite().get(), 0x0001);

    let pid = Uuid::new_v4();
    let mnemonic = daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap();
    let phrase = mnemonic.to_phrase();
    let payload = seeds::Seeds::new(mnemonic.clone());

    let v2_blob = seeds::seal(&payload, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    let opened = seeds::open(&v2_blob, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    assert_eq!(opened.suite_id.get(), 0x0001);
    assert_eq!(opened.seeds.mnemonic.to_phrase(), phrase);
    assert!(!opened.legacy_v1);

    let dseed = recovery_file::seal(&mnemonic, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    let recovered = recovery_file::open(&dseed, STRONG_PASSPHRASE).unwrap();
    assert_eq!(recovered.suite_id.get(), 0x0001);
    assert_eq!(recovered.mnemonic.to_phrase(), phrase);
    assert!(!recovered.legacy_v1);

    // Wire shape exists and is reachable from downstream crates. The
    // encode/decode round-trip is covered by daemonseed-proto's own
    // tests; here we pin only the cross-crate visibility of the type.
    let wire = WireSuiteId { value: 0x0001 };
    assert_eq!(wire.value, 0x0001);

    // touch_reseal on a v2 blob produces a fresh v2 blob (new nonce, same
    // suite). The v1 → v2 migration is covered separately by the inline
    // tests; the registration here closes the public-API surface.
    let resealed = seeds::touch_reseal(&v2_blob, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    assert_ne!(resealed, v2_blob); // distinct nonce → distinct bytes
    let reopened = seeds::open(&resealed, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    assert_eq!(reopened.seeds.mnemonic.to_phrase(), phrase);

    coverage.register("ISC-C24", "m3_iscs::suite_id_tagging");

    // ── ISC-S15: server's own cryptographic material is tagged with a
    // suite_id per the registry; the suite-transparency clause is covered
    // by ISC-A-S10 below. Structural verification at M3: the registry
    // exposes a default write-suite the server consumes for its own
    // material, and identity-proof verification at M4b consults
    // Registry::lookup to map the signer's suite_id to a signature
    // algorithm. Until the server crate gains real handshake code the test
    // pins what M3 ships: the suite the server authors material under
    // resolves in-build. (The M7 deprecation policy that governs server
    // suite lifecycle keys its entries by this same SuiteId.)
    // ─────────────────────────────────────────────────────────────────────
    assert!(Registry::lookup(Registry::default_write_suite()).is_some());
    coverage.register("ISC-S15", "m3_iscs::server_suite_id_tagging_surface");

    // ── ISC-A-C8: client refuses to write under a deprecated suite at
    // compose time (per ISC-A-C8 write-suite-policy). In the flat,
    // metadata-free circle model  there is no per-circle min-suite
    // record, so the policy is enforced two ways:
    //   (a) the WritePolicy gate refuses any non-Active-write lifecycle
    //       state under the default (sub-minimum / deprecated suites), and
    //   (b) the circle key is *family-anchored* (Suite::family_token), so a
    //       cross-family suite derives a different cot_key — i.e. cross-
    //       family migration is structurally a new-circle event, never an
    //       in-place acceptance. `same_family` is the load-bearing
    //       discriminator. Sub-minimum *render-time* gating now lives in the
    //       server S16 deprecation policy + the client-local registry, not
    //       in a circle-level record.
    // (Synthetic deprecated-state coverage lives in the
    // crypto::suite::tests::resolve_for_write_branches unit test.)
    // ─────────────────────────────────────────────────────────────────────
    assert!(CNSA_2_0.same_family(&CNSA_2_0)); // within-family stable → same circle
    assert!(WritePolicy::default().permits(LifecycleState::ActiveWrite));
    assert!(!WritePolicy::default().permits(LifecycleState::ReadOnlyDeprecated));
    assert!(!WritePolicy::default().permits(LifecycleState::Removed));

    coverage.register(
        "ISC-A-C8",
        "m3_iscs::flat_circle_write_policy_and_family_anchor",
    );

    // ── ISC-A-C9: client must not silently bypass / auto-rotate identity
    // to escape a deprecation cutoff. At M3 no cutoff policy ships
    // (ISC-S16 / C25 land at M7), so the structural verification is:
    //   (a) no public daemonseed-core API auto-downgrades a write to a
    //       lower suite_id than the build's default,
    //   (b) no public API replaces identity material in response to a
    //       suite-state change,
    //   (c) every write goes through Registry::resolve_for_write, which
    //       fails closed on any non-Active-write state — verified by
    //       confirming WriteRefusal carries the offending id back to the
    //       caller for explicit handling (no silent fallback).
    // ─────────────────────────────────────────────────────────────────────
    let dummy_id = SuiteId::try_new(0x0042).unwrap();
    let refused = Registry::resolve_for_write(dummy_id).unwrap_err();
    assert_eq!(refused, WriteRefusal::Unknown(dummy_id));
    // touch_reseal is the only on-touch migration path; it picks the
    // build's default_write_suite, never an arbitrary id. Pin that.
    let resealed_blob =
        seeds::touch_reseal(&v2_blob, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    let resealed_open = seeds::open(&resealed_blob, STRONG_PASSPHRASE, pid, fast_params()).unwrap();
    assert_eq!(resealed_open.suite_id, Registry::default_write_suite());
    coverage.register("ISC-A-C9", "m3_iscs::no_silent_suite_downgrade");

    // ── Final assertion: 4 surviving M3 spec-ISCs registered. ─────────────
    assert_eq!(
        coverage.covered_count(),
        4,
        "expected 4 M3 ISCs registered, got {}",
        coverage.covered_count()
    );
    // 2 positive (C24, S15) + 2 negative (A-C8, A-C9) = 4 total.
    // (ISC-A-S10 was withdrawn at the v0.33.0 Veilid cutover.)
    assert_eq!(coverage.positive_tests.len(), 2);
    assert_eq!(coverage.negative_tests.len(), 2);
}
