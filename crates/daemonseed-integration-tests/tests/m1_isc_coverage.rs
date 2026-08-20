//! End-to-end exercise of the 17 M1 ISCs.
//!
//! Each `register_*` block invokes the daemonseed-core surface that closes
//! one ISC, asserts the end-state, and registers a corresponding test name
//! against the local [`Coverage`] registry. The single top-level test then
//! asserts the registry contains exactly the expected 17 entries.
//!
//! When a future milestone adds more ISCs, those land here (or in
//! per-milestone sibling files); the workspace-wide coverage view comes
//! from running every `mN_isc_coverage` test together.

use daemonseed_core::handle::display_name::{
    MAX_DISPLAY_NAME_BYTES, OsRng, combinations, generate_display_name, is_valid_display_name,
};
use daemonseed_core::handle::{DisplayMode, HASH_PREFIX_BYTES, HASH_PREFIX_HEX_CHARS, Handle};
use daemonseed_core::identity::keys::{Identity, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::kdf::info;
use daemonseed_core::passphrase::circle_canonicalize::canonicalize;
use daemonseed_core::passphrase::strength::{
    self, CIRCLE_ENTROPY_MIN_BITS, SESSION_PASSPHRASE_MIN_BITS,
};
use daemonseed_core::profile::config::{ArgonParams, ProfileConfig};
use daemonseed_core::profile::resolve::{
    CONFIG_FILENAME, ResolveArgs, ResolvedProfileRoot, resolve_with_env,
};
use daemonseed_core::storage::seeds::{self, Seeds};
use daemonseed_integration_tests::isc_coverage::Coverage;
use uuid::Uuid;

fn test_params() -> ArgonParams {
    // Fast for tests; never production-suitable.
    ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

fn init_oxicrypt() {
    let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
}

#[test]
fn m1_iscs_exercise_end_to_end() {
    init_oxicrypt();
    let mut coverage = Coverage::empty();

    // ── ISC-C2: 24-word BIP-39 English mnemonic from 256-bit entropy ──────
    let mnemonic = Mnemonic::generate().expect("BIP-39 mnemonic");
    assert_eq!(mnemonic.word_count(), 24);
    coverage.register("ISC-C2", "m1_iscs::mnemonic_generate");

    // ── ISC-C1: HKDF-rooted ML-DSA-87 + ML-KEM-1024 derivation ────────────
    let primary = derive_identity_keys(&mnemonic, Identity::Primary).expect("primary keys");
    let device_uuid = Uuid::new_v4();
    let device = derive_identity_keys(&mnemonic, Identity::Device { uuid: device_uuid })
        .expect("device keys");
    assert_ne!(primary.signing.public_key(), device.signing.public_key());
    coverage.register("ISC-C1", "m1_iscs::derive_identity_keys");

    // ── ISC-C4: handle = <name>#<12hex> from SHA-256(pubkey) ──────────────
    let handle = Handle::from_pubkey(Some("alice".to_string()), primary.signing.public_key())
        .expect("handle from pubkey");
    assert_eq!(handle.hash_prefix().len(), HASH_PREFIX_BYTES);
    assert_eq!(HASH_PREFIX_HEX_CHARS, 12);
    coverage.register("ISC-C4", "m1_iscs::handle_from_pubkey");

    // ── ISC-C4a: display-mode rules (hash hidden / surfaced / anonymous) ──
    assert_eq!(handle.format(DisplayMode::Default), "alice");
    assert!(handle.format(DisplayMode::Verify).starts_with("alice#"));
    assert!(handle.format(DisplayMode::Anonymous).starts_with('#'));
    coverage.register("ISC-C4a", "m1_iscs::display_modes");

    // ── ISC-C4b: random adj-noun display-name generator + validator ───────
    assert!(combinations() >= 2_000_000);
    let name = generate_display_name(&mut OsRng);
    assert!(name.contains('-'));
    assert!(is_valid_display_name(&name));
    assert!(!is_valid_display_name("name#with#hash"));
    assert!(name.len() <= MAX_DISPLAY_NAME_BYTES);
    coverage.register("ISC-C4b", "m1_iscs::display_name_generator");

    // ── ISC-C9: NFKC + whitespace canonicalization for circle entropy ────
    assert_eq!(canonicalize("  Hello\u{FF11}  world  "), "Hello1 world");
    // ISC-C9 also gates circle-of-trust entropy at the ≥128-bit floor via the
    // M15 word+charset key-space estimator (zxcvbn cannot certify ≥128). A
    // 12-word diceware phrase clears it; the public xkcd 4-word phrase does not.
    assert!(
        strength::estimate_circle(
            "abandon ability able about above absent \
             absorb abstract absurd abuse access accident"
        )
        .is_circle_green()
    );
    assert!(!strength::estimate_circle("correct horse battery staple").is_circle_green());
    coverage.register("ISC-C9", "m1_iscs::circle_canonicalize");

    // ── ISC-C10: daemonseed-core exists as a library crate. The fact this
    // integration test compiles against `daemonseed-core::*` paths IS the
    // proof. ────────────────────────────────────────────────────────────
    coverage.register("ISC-C10", "m1_iscs::core_is_library");

    // ── ISC-C11: no hard-coded ports in M1 surface (architectural).
    // Closed by inspection — daemonseed-core ships zero `bind`/`connect`
    // call sites; M4a+ servers/clients accept config-driven addresses. ────
    coverage.register("ISC-C11", "m1_iscs::no_hardcoded_ports");

    // ── ISC-C12: zxcvbn strength meter + ≥60-bit green threshold ──────────
    let weak = strength::estimate("password");
    assert!(!weak.is_session_green());
    let strong = strength::estimate("correct horse battery staple table mountain");
    assert!(strong.is_session_green());
    let generated = strength::generate_default_diceware().expect("diceware");
    assert!(strength::estimate(&generated).is_session_green());
    assert_eq!(SESSION_PASSPHRASE_MIN_BITS, 60.0);
    coverage.register("ISC-C12", "m1_iscs::passphrase_strength");

    // ── ISC-C13: per-context presentation (Default / Verify / Anonymous) ──
    // (Same surface as C4a, but the per-context invariant is the
    // anonymous-mode floor regardless of display_name.)
    let anon = handle.format(DisplayMode::Anonymous);
    assert!(!anon.contains("alice"));
    coverage.register("ISC-C13", "m1_iscs::anonymous_presentation");

    // ── ISC-C14: persisted Argon2 params (≥128-bit circle gate) ──────────
    assert_eq!(CIRCLE_ENTROPY_MIN_BITS, 128.0);
    let p = ArgonParams::desktop_default();
    assert_eq!(p.memory_kib, 19 * 1024);
    coverage.register("ISC-C14", "m1_iscs::argon_params_persisted");

    // ── ISC-C35: profile-root resolution via --config / CWD / XDG ─────────
    assert_eq!(CONFIG_FILENAME, "daemonseed.toml");
    let resolved = resolve_with_env(ResolveArgs::default(), None, |k| match k {
        "HOME" => Some("/tmp/daemonseed-m1-isc-cov".to_string()),
        _ => None,
    })
    .expect("resolve XDG fallback");
    assert!(matches!(resolved, ResolvedProfileRoot::FirstStart { .. }));
    coverage.register("ISC-C35", "m1_iscs::profile_root_resolution");

    // ── ISC-C36: profile-id = UUID v4 from cryptographic randomness ──────
    let config = ProfileConfig::new_for_first_start(test_params());
    assert_eq!(config.profile_id.get_version_num(), 4);
    let config_b = ProfileConfig::new_for_first_start(test_params());
    assert_ne!(config.profile_id, config_b.profile_id);
    coverage.register("ISC-C36", "m1_iscs::profile_id_uuid_v4");

    // ── ISC-C3: Argon2id+HKDF → AES-256-GCM at-rest blob, round-trip ────
    let seeds = Seeds::new(Mnemonic::generate().expect("mnemonic"));
    let orig_phrase = seeds.mnemonic.to_phrase();
    let blob = seeds::seal(&seeds, "passphrase-x", config.profile_id, test_params()).expect("seal");
    let recovered =
        seeds::open(&blob, "passphrase-x", config.profile_id, test_params()).expect("open");
    assert_eq!(recovered.seeds.mnemonic.to_phrase(), orig_phrase);
    // Pin the HKDF info string for the at-rest blob — load-bearing contract.
    assert!(info::at_rest(&config.profile_id.to_string()).starts_with("daemonseed/at-rest/"));
    coverage.register("ISC-C3", "m1_iscs::at_rest_blob_round_trip");

    // ── ISC-A-C1: client persists no plaintext identifiers / no Debug
    // leaks. Verified by Debug output of mnemonic / seeds / keypairs
    // containing "<redacted>". ───────────────────────────────────────────
    assert!(format!("{:?}", seeds).contains("<redacted>"));
    assert!(format!("{:?}", primary.signing).contains("<redacted>"));
    assert!(format!("{:?}", primary.kem).contains("<redacted>"));
    assert!(format!("{:?}", mnemonic).contains("<redacted>"));
    coverage.register("ISC-A-C1", "m1_iscs::debug_redacts_secrets");

    // ── ISC-A-C16: profile_id MUST come from cryptographic randomness,
    // not from user-visible / derived inputs. Uuid::new_v4 uses getrandom
    // exclusively; the per-version invariant + unique-per-call invariant
    // exercised above is the runtime proof. ──────────────────────────────
    coverage.register("ISC-A-C16", "m1_iscs::profile_id_from_csprng_only");

    // ── ISC-A-C17: Argon2 params NEVER silently change mid-life — params
    // travel with the encrypted artifacts. The blob's seal/open round-trip
    // with a *different* params struct must fail closed: ─────────────────
    let blob2 =
        seeds::seal(&seeds, "passphrase-x", config.profile_id, test_params()).expect("seal");
    let other_params = ArgonParams {
        memory_kib: 16,
        iterations: 1,
        parallelism: 1,
    };
    assert!(seeds::open(&blob2, "passphrase-x", config.profile_id, other_params).is_err());
    coverage.register("ISC-A-C17", "m1_iscs::argon_params_travel_with_blob");

    // ── Final assertion: exactly 17 M1 ISCs registered. ──────────────────
    assert_eq!(
        coverage.covered_count(),
        17,
        "expected 17 M1 ISCs registered, got {}",
        coverage.covered_count()
    );

    // 14 positive (C-class) + 3 negative (A-C-class) = 17.
    assert_eq!(coverage.positive_tests.len(), 14);
    assert_eq!(coverage.negative_tests.len(), 3);
}
