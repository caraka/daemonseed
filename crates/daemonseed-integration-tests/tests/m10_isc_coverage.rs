//! M10 milestone — release distribution + update lifecycle — ISC coverage.
//!
//! This PR ships the **verifiable core** of M10: the release trust anchor and
//! N-of-M multi-sig verify (`daemonseed_core::release`), the server boot-gate
//! (`daemonseed_server::boot_gate`), and the client update-lifecycle FSM
//! (`daemonseed_core::release::update`). The substantive behaviour is unit-
//! tested in each owning module; this file pins the cross-crate demonstrations
//! and registers the milestone tally.
//!
//! ISCs closed by this PR: **S18** (release-signing verify), **C27** (update
//! lifecycle) — positive; **A-S13** (refuse-boot-on-failed-verify), **A-C11**
//! (verify-before-install / never-auto-install) — negative. It also registers
//! **S20** (CoT live relay), backfilled into the coverage registry this PR
//! (the M8 convention lapse left it unregistered).
//!
//! **Deferred to M10-infra (NOT closed here):** ISC-S18's real multi-sig +
//! Sigstore + reproducible build, the optional update-relay role, ISC-C7
//! (biometric/secure-enclave login) and ISC-C20 (OS-native autostart) — these
//! need a signing-key ceremony, accounts, and platform integration, not pure
//! logic.

use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::release::{
    ReleaseAnchor, ReleaseKey, ReleaseVersion, UpdateChannel, UpdateLifecycle, UpdateRecord,
    UpdateState,
};
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_server::boot_gate::{BootDecision, gate_boot_with};

fn ensure_module() {
    let _ = oxicrypt_module::initialize();
}

fn keypair(seed: u8) -> SignKeypair {
    ensure_module();
    SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
}

const DIGEST: &[u8] = b"daemonseed-server v0.12.0 reproducible-build digest";

/// S18 / A-S13 across the server→core boundary: the server's boot-gate consumes
/// core's N-of-M verify, and a tampered binary (a valid signature over
/// different bytes) is refused — never "boot anyway with a warning". This is
/// the cross-crate shape of "refuse to boot on failed verify".
#[test]
fn boot_gate_refuses_a_tampered_binary_end_to_end() {
    let release_key = keypair(1);
    let anchor = ReleaseAnchor::new(vec![ReleaseKey::new(*release_key.public_key())], 1).unwrap();
    let genuine_sig = release_key.sign(DIGEST).unwrap();

    // The genuine binary boots.
    assert_eq!(
        gate_boot_with(&anchor, DIGEST, &[&genuine_sig]),
        BootDecision::Boot
    );

    // A tampered digest under the same signature does not verify → refuse.
    let tampered = b"daemonseed-server v0.12.0 reproducible-build digest (PATCHED)";
    assert!(
        matches!(
            gate_boot_with(&anchor, tampered, &[&genuine_sig]),
            BootDecision::RefuseToBoot(_)
        ),
        "A-S13: a failed verify is always refuse, never boot-with-warning"
    );
}

/// C27 / A-C11: the update FSM verifies before applying and never auto-installs.
/// A genuine update reaches `Verified` but stays there until an explicit
/// confirm — verify does not install — and a forged artifact from a hostile
/// relay fails verification, is wiped, and never reaches the install-ready
/// state.
#[test]
fn update_lifecycle_verifies_before_apply_and_never_auto_installs() {
    let release_key = keypair(2);
    let anchor = ReleaseAnchor::new(vec![ReleaseKey::new(*release_key.public_key())], 1).unwrap();
    let sig = release_key.sign(DIGEST).unwrap();
    let running = ReleaseVersion::new(0, 11, 0);
    let target = ReleaseVersion::new(0, 12, 0);

    // Genuine update: verify → Verified (NOT installed), then explicit confirm.
    let mut fsm = UpdateLifecycle::new(running);
    fsm.discover(
        UpdateRecord {
            version: target,
            channel: UpdateChannel::Primary,
            emergency: false,
        },
        b"genuine-binary".to_vec(),
    );
    fsm.verify(&anchor, DIGEST, &[&sig], 1000);
    assert!(
        matches!(fsm.state(), UpdateState::Verified { .. }),
        "C27: a verified update parks at Verified, not installed"
    );
    assert!(
        !matches!(fsm.state(), UpdateState::ConfirmedReadyToInstall(_)),
        "A-C11: verify must never auto-install"
    );
    fsm.confirm(false).unwrap();
    assert!(matches!(
        fsm.state(),
        UpdateState::ConfirmedReadyToInstall(_)
    ));

    // Hostile relay: forged artifact fails verify, is wiped, never installs.
    let hostile = keypair(200);
    let forged = hostile.sign(DIGEST).unwrap();
    let mut victim = UpdateLifecycle::new(running);
    victim.discover(
        UpdateRecord {
            version: target,
            channel: UpdateChannel::RelayFallback,
            emergency: false,
        },
        b"forged-binary".to_vec(),
    );
    victim.verify(&anchor, DIGEST, &[&forged], 2000);
    assert!(
        matches!(victim.state(), UpdateState::Failed(_)),
        "A-C11: a forged relay artifact fails verification"
    );
    assert!(
        !victim.has_artifact(),
        "A-C11: a failed-verify artifact is wiped (no payload retention)"
    );
}

// ── ISC coverage tally ──────────────────────────────────────────────────────

#[test]
fn m10_core_closes_four_iscs_plus_s20_backfill() {
    let mut coverage = Coverage::empty();
    coverage.register(
        "ISC-S18",
        "daemonseed_core::release::verify::tests + m10::boot_gate_refuses_a_tampered_binary_end_to_end",
    );
    coverage.register(
        "ISC-C27",
        "daemonseed_core::release::update::tests + m10::update_lifecycle_verifies_before_apply_and_never_auto_installs",
    );
    coverage.register(
        "ISC-A-S13",
        "daemonseed_server::boot_gate::tests + m10::boot_gate_refuses_a_tampered_binary_end_to_end",
    );
    coverage.register(
        "ISC-A-C11",
        "daemonseed_core::release::update::tests::failed_verify_wipes_artifact_logs_and_emits_blocking_event + downgrade_requires_explicit_acknowledgement",
    );
    // S20 backfill: its substantive coverage is the M8 CoT live relay; the M8
    // milestone never got a coverage test (convention lapsed M7-M8), so register
    // the evidence pointer here alongside the registry-entry backfill.
    coverage.register(
        "ISC-S20",
        "daemonseed_server::cot (circle-of-trust live relay) + daemonseed_server::runtime serve path",
    );
    assert_eq!(
        coverage.covered_count(),
        5,
        "M10 core closes S18/C27 + A-S13/A-C11, plus the S20 backfill"
    );
}
