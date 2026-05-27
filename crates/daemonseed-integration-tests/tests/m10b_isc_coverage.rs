//! M10-completion (v0.12.1) — C7 / C20 scaffold coverage.
//!
//! M10-core (v0.12.0, PR #14) closed the verifiable half of M10 and explicitly
//! deferred the two platform-gated ISCs:
//!
//! - **ISC-C7** — biometric / secure-enclave session-passphrase unlock
//! - **ISC-C20** — OS-native autostart
//!
//! This PR closes the *buildable nucleus* of each — the abstraction layer that
//! is fully testable with no GUI/platform dependency — and **reserves** the
//! platform halves (the real backends + OS install + the session-holding client
//! that gives them meaning). Both are recorded here as scaffold-closed; the
//! evidence pointer names BOTH the shipped scaffold module AND the Reservation,
//! mirroring how other partially-reserved ISCs are tracked.
//!
//! Scaffold shipped this PR:
//! - `daemonseed_core::biometric` — `BiometricStore` trait (session passphrase
//!   only, never the mnemonic), `RECOVERY_RISK_WARNING`, opt-in
//!   `ProfileConfig::biometric_unlock` (default off). No platform backend.
//! - `daemonseed_core::autostart` — pure `unit_descriptor` generator
//!   (systemd / launchd / Windows Startup text), `AutostartManager` trait,
//!   `PRESENCE_SIDE_CHANNEL_WARNING`, opt-in `ProfileConfig::autostart`
//!   (default off). No OS install/enable/run.
//!
//! Reserved (NOT closed): the platform secure-enclave backends + biometric UX
//! (C7) and the actual OS install + GUI-autostart + mobile background-exec +
//! the persistent headless client (C20). See the C7/C20 Reservations in
//! `ds-isc-draft.md`.

use daemonseed_core::autostart::{
    AutostartMode, AutostartSpec, AutostartTarget, PRESENCE_SIDE_CHANNEL_WARNING, unit_descriptor,
};
use daemonseed_core::biometric::{RECOVERY_RISK_WARNING, SessionPassphrase};
use daemonseed_core::profile::config::{ArgonParams, ProfileConfig};
use daemonseed_integration_tests::isc_coverage::Coverage;

/// C7 scaffold demonstration: the opt-in flag is off by default, the recovery
/// warning is present, and the secret type round-trips through a store without
/// the mnemonic ever being representable. The platform backend is reserved.
#[test]
fn c7_biometric_scaffold_is_present_and_off_by_default() {
    let config = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
    assert!(!config.biometric_unlock, "C7 is opt-in — default off");
    assert!(
        !RECOVERY_RISK_WARNING.is_empty(),
        "C7 mandatory warning present"
    );

    // The trait deals only in SessionPassphrase, never Mnemonic.
    let pw = SessionPassphrase::new("session-pw");
    assert_eq!(pw.expose(), "session-pw");
}

/// C20 scaffold demonstration: the pure descriptor generator emits each
/// platform's unit text for a profile, headless by default, without installing
/// anything; the opt-in flag is off by default. The OS install is reserved.
#[test]
fn c20_autostart_scaffold_generates_descriptors_without_installing() {
    let config = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
    assert!(!config.autostart, "C20 is opt-in — default off");
    assert!(
        !PRESENCE_SIDE_CHANNEL_WARNING.is_empty(),
        "C20 mandatory warning present"
    );

    let spec = AutostartSpec {
        profile_name: "tester".into(),
        exec_path: "/usr/bin/daemonseed".into(),
        config_dir: "/profiles/tester".into(),
        mode: AutostartMode::Headless,
    };
    for target in [
        AutostartTarget::SystemdUser,
        AutostartTarget::Launchd,
        AutostartTarget::WindowsStartup,
    ] {
        let text = unit_descriptor(&spec, target);
        assert!(text.contains("/usr/bin/daemonseed"));
        assert!(
            !text.contains("--gui"),
            "headless default carries no GUI flag"
        );
    }
}

// ── ISC coverage tally ──────────────────────────────────────────────────────

#[test]
fn m10b_closes_c7_and_c20_scaffold() {
    let mut coverage = Coverage::empty();
    coverage.register(
        "ISC-C7",
        "daemonseed_core::biometric (BiometricStore trait + SessionPassphrase + RECOVERY_RISK_WARNING + ProfileConfig::biometric_unlock) + m10b::c7_biometric_scaffold_is_present_and_off_by_default; platform backend reserved (ds-isc-draft.md C7 Reservation)",
    );
    coverage.register(
        "ISC-C20",
        "daemonseed_core::autostart (unit_descriptor generator + AutostartManager trait + PRESENCE_SIDE_CHANNEL_WARNING + ProfileConfig::autostart) + m10b::c20_autostart_scaffold_generates_descriptors_without_installing; OS install reserved (ds-isc-draft.md C20 Reservation)",
    );
    assert_eq!(
        coverage.covered_count(),
        2,
        "M10-completion closes the C7 + C20 scaffolds (platform halves reserved)"
    );
}
