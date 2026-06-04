//! alpha2 client-identity-lifecycle (PRD items C/D/E/F) — ISC coverage.
//!
//! The substantive behaviour for each new ISC is unit-tested in the crate that
//! owns it:
//! - C47 (default 3-word confirm): `daemonseed_tui::screens::first_start::tests`.
//! - C48 / A-C26 (chat circle requirement + no false echo):
//!   `daemonseed_tui::app::tests`.
//! - C49 / C50 / C51 / A-C28 (persist blob + `.dseed`, Unlock, no-clobber):
//!   `daemonseed_core::profile::persist::tests`.
//! - A-C27 ("back" never strands at enrollment): `daemonseed_tui::app::tests`.
//!
//! This file pins the end-to-end persist → Unlock round-trip (the cross-module
//! claim that the on-disk blob written at first-start opens on the next launch
//! and reaches the same identity), and registers the milestone's ISC tally.

use daemonseed_core::bootstrap::BootstrapAnchor;
use daemonseed_core::first_start::FirstStart;
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::profile::{
    blob_exists, load_for_unlock, session_materials_from_unlock, write_first_start,
};
use daemonseed_core::storage::seeds;
use daemonseed_integration_tests::isc_coverage::Coverage;
use std::path::PathBuf;
use uuid::Uuid;

fn ensure_module() {
    let _ = oxicrypt_module::initialize();
}

fn test_params() -> ArgonParams {
    ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

const STRONG: &str = "correct horse battery staple table mountain";

struct Tmp {
    path: PathBuf,
}
impl Tmp {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!("ds-alpha2-cov-{}", Uuid::new_v4())),
        }
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// D + E end-to-end (ISC-C49 / C50 / C51): a first-start's artifacts written to
/// the profile root reopen on the next launch (Unlock) and reconstruct the SAME
/// identity, with no mnemonic re-entry. This is the cross-module claim the
/// per-crate unit tests cannot make alone (persist + load + decrypt + re-derive).
#[test]
fn persist_then_unlock_round_trips_to_same_identity() {
    ensure_module();
    let tmp = Tmp::new();

    // First start: produce + persist (Item D).
    let sealed = FirstStart::new().initialize(STRONG, test_params()).unwrap();
    let phrase = sealed.display_phrase();
    let verified = sealed.verify_round_trip(&phrase).unwrap();
    let materials = verified
        .finalize(
            Some("alice".to_string()),
            BootstrapAnchor {
                server_id: "relay#aabbccddeeff".to_string(),
                address: "127.0.0.1:443".to_string(),
            },
        )
        .unwrap()
        .into_session_materials();
    let enrolled_prefix = *materials.handle.hash_prefix();

    write_first_start(&tmp.path, &materials, None, false).unwrap();
    assert!(blob_exists(&tmp.path), "C49: seeds.blob persisted");

    // Next launch: an existing blob → Unlock (Item E). Decrypt + reconstruct.
    let (config, blob) = load_for_unlock(&tmp.path).unwrap();
    let opened = seeds::open(&blob, STRONG, config.profile_id, config.argon2).unwrap();
    let session = session_materials_from_unlock(opened.seeds, config, blob, Vec::new()).unwrap();
    assert_eq!(
        session.handle.hash_prefix(),
        &enrolled_prefix,
        "C51: Unlock reaches the same identity hash as enrollment"
    );
    assert_eq!(
        session.bootstrap.server_id, "relay#aabbccddeeff",
        "C51/C37: Unlock recovers the persisted bootstrap relay"
    );
}

/// A-C28 end-to-end: re-running first-start against a root that already holds a
/// blob fails closed without an explicit confirm — the existing identity is not
/// silently destroyed.
#[test]
fn rerun_first_start_does_not_clobber_existing_blob() {
    ensure_module();
    let tmp = Tmp::new();
    let mk = || {
        let sealed = FirstStart::new().initialize(STRONG, test_params()).unwrap();
        let phrase = sealed.display_phrase();
        sealed
            .verify_round_trip(&phrase)
            .unwrap()
            .finalize(
                None,
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials()
    };
    write_first_start(&tmp.path, &mk(), None, false).unwrap();
    let original = std::fs::read(daemonseed_core::profile::blob_path(&tmp.path)).unwrap();
    // Second run, no confirm → refused, blob unchanged.
    assert!(
        write_first_start(&tmp.path, &mk(), None, false).is_err(),
        "A-C28: re-run without confirm must refuse to clobber"
    );
    let after = std::fs::read(daemonseed_core::profile::blob_path(&tmp.path)).unwrap();
    assert_eq!(
        original, after,
        "A-C28: existing blob left intact on refusal"
    );
}

// ── ISC coverage tally ──────────────────────────────────────────────────────

#[test]
fn alpha2_client_identity_closes_eight_iscs() {
    let mut coverage = Coverage::empty();
    coverage.register(
        "ISC-C47",
        "daemonseed_tui::screens::first_start::tests::default_enter_confirm_is_three_word_type_back",
    );
    coverage.register(
        "ISC-C48",
        "daemonseed_tui::app::tests::chat_empty_state_states_circle_requirement",
    );
    coverage.register(
        "ISC-C49",
        "daemonseed_core::profile::persist::tests::write_first_start_persists_blob_and_config + alpha2::persist_then_unlock_round_trips_to_same_identity",
    );
    coverage.register(
        "ISC-C50",
        "daemonseed_core::profile::persist::tests::write_first_start_saves_dseed_at_profile_root_by_default",
    );
    coverage.register(
        "ISC-C51",
        "daemonseed_core::profile::persist::tests::unlock_reconstructs_same_identity + alpha2::persist_then_unlock_round_trips_to_same_identity",
    );
    coverage.register(
        "ISC-A-C26",
        "daemonseed_tui::app::tests::enter_with_no_circle_does_not_echo_or_transmit",
    );
    coverage.register(
        "ISC-A-C27",
        "daemonseed_tui::app::tests::esc_in_main_opens_menu_never_enrollment",
    );
    coverage.register(
        "ISC-A-C28",
        "daemonseed_core::profile::persist::tests::write_first_start_refuses_to_clobber_without_confirm + alpha2::rerun_first_start_does_not_clobber_existing_blob",
    );
    assert_eq!(
        coverage.covered_count(),
        8,
        "alpha2 client-identity closes 8 ISCs (C47–C51 + A-C26/A-C27/A-C28)"
    );
}
