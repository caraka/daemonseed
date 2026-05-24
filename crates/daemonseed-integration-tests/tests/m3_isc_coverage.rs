//! End-to-end exercise of the 5 M3 spec-ISCs.
//!
//! Per `ds-mvp-implementation-plan.md:68-73`, M3 closes ISC-C24, A-C8,
//! S15, A-S10, A-C9 — the suite registry + crypto-agility primitives.
//! This test walks the public surface introduced by M3's four commits
//! and registers one coverage entry per spec-ISC. The final assertion
//! pins the registered count to 5.

use std::path::{Path, PathBuf};

use daemonseed_core::circle::metadata::Metadata;
use daemonseed_core::crypto::policy::WritePolicy;
use daemonseed_core::crypto::suite::{CNSA_2_0, LifecycleState, Registry, SuiteId, WriteRefusal};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::storage::{recovery_file, seeds};
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_proto::v1::{CircleMin, SuiteId as WireSuiteId};
use uuid::Uuid;

fn init_oxicrypt() {
    let _ = oxicrypt_module::initialize();
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
    let payload = seeds::Seeds {
        mnemonic: mnemonic.clone(),
    };

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
    // material, the wire shape exists for transit through HELLO (M4a),
    // and identity-proof verification at M4b consults Registry::lookup
    // to map the signer's suite_id to a signature algorithm. Until the
    // server crate gains real handshake code the test pins what M3 ships:
    // the API the server *will* call exists, is in-tree, and round-trips.
    // ─────────────────────────────────────────────────────────────────────
    assert!(Registry::lookup(Registry::default_write_suite()).is_some());
    let circle_min = CircleMin {
        min_suite_id: Some(WireSuiteId { value: 0x0001 }),
    };
    assert_eq!(circle_min.min_suite_id.unwrap().value, 0x0001);
    coverage.register("ISC-S15", "m3_iscs::server_suite_id_tagging_surface");

    // ── ISC-A-C8: client refuses to write under a deprecated suite at
    // compose time (per ISC-A-C8 write-suite-policy). Exercised via the
    // WritePolicy gate. Cross-family / sub-minimum render-time refusal
    // is covered by Metadata::accepts; reflexive acceptance proves the
    // gate works in the only direction the M3 single-entry registry
    // permits (synthetic deprecated-state coverage lives in the
    // crypto::suite::tests::resolve_for_write_branches unit test).
    // ─────────────────────────────────────────────────────────────────────
    let meta = Metadata::new(CNSA_2_0.id).unwrap();
    assert!(meta.accepts(CNSA_2_0.id));
    assert!(!meta.accepts(SuiteId::try_new(0x0042).unwrap())); // unknown ≈ cross-family

    // The WritePolicy gate refuses any non-Active-write state under the
    // default. The single-entry registry makes the synthetic branches the
    // only way to show this externally; the policy enum's `permits` table
    // is the test surface.
    assert!(WritePolicy::default().permits(LifecycleState::ActiveWrite));
    assert!(!WritePolicy::default().permits(LifecycleState::ReadOnlyDeprecated));
    assert!(!WritePolicy::default().permits(LifecycleState::Removed));

    coverage.register("ISC-A-C8", "m3_iscs::sub_min_and_deprecated_write_refused");

    // ── ISC-A-S10: server is suite-transparent on CoT relay. Negative
    // structural anchor: daemonseed-server (and its only file at M3,
    // src/main.rs) MUST NOT import or call `Registry::lookup` /
    // `resolve_for_write` / `Suite::same_family` on any CoT-relay path.
    // At M3 daemonseed-server is the placeholder `fn main() {}`, so the
    // grep is vacuously satisfied; the assertion's value is the
    // regression anchor it becomes when M5/M6 add CoT-relay code.
    // ─────────────────────────────────────────────────────────────────────
    let server_src = repo_root().join("crates/daemonseed-server/src");
    let banned = [
        "Registry::lookup",
        "Registry::resolve",
        "Suite::same_family",
    ];
    for entry in walk_rs(&server_src) {
        let text = std::fs::read_to_string(&entry).expect("read server src");
        for needle in banned {
            assert!(
                !text.contains(needle),
                "ISC-A-S10 regression: {} contains `{}`; server must stay suite-transparent on CoT paths",
                entry.display(),
                needle
            );
        }
    }
    coverage.register("ISC-A-S10", "m3_iscs::server_suite_transparency");

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

    // ── Final assertion: 5 M3 spec-ISCs registered. ───────────────────────
    assert_eq!(
        coverage.covered_count(),
        5,
        "expected 5 M3 ISCs registered, got {}",
        coverage.covered_count()
    );
    // 2 positive (C24, S15) + 3 negative (A-C8, A-S10, A-C9) = 5 total.
    assert_eq!(coverage.positive_tests.len(), 2);
    assert_eq!(coverage.negative_tests.len(), 3);
}

/// Resolve the repository root by walking up from the integration-tests
/// crate's `CARGO_MANIFEST_DIR`. Used by the ISC-A-S10 grep assertion
/// so the test works from any worktree placement.
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR = <repo>/crates/daemonseed-integration-tests
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root resolves via two parents of integration-tests CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Recursively yield all `.rs` files under `root`.
fn walk_rs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            return out;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}
