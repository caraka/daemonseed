//! #41 GUI share-name persistence — ISC-C98 coverage.
//!
//! Exercises the core persistence primitive the GUI publish write-through
//! populates: a published share's optional wire-facing name
//! ([`daemonseed_core::storage::seeds::PublishedShare::name`]) survives a
//! seal/open round-trip, with a custom name stored as `Some` and an un-named
//! share stored as `None` (the basename fallback at republish lives in the GUI
//! `net` layer's `republish_name`, unit-tested there). The GUI write-through
//! (`GuiState::persist_published` → `Profile::persist_published`) and the
//! publish-overlay name field are unit-tested IN the `daemonseed-gui` binary
//! crate (`state::tests::profile_round_trips_published_shares_across_reload`),
//! whose `pub` does not escape to this integration crate; the visible
//! peer-sees-the-name round-trip is felt-test-gated (ISA `## Criteria` ISC-C98
//! left `[ ]`). Registers ISC-C98.

use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::storage::seeds::{Seeds, open, seal};
use daemonseed_integration_tests::isc_coverage::Coverage;
use uuid::Uuid;

/// Cheap Argon2 params — single-digit-ms KDF so the suite doesn't bog. NEVER a
/// production setting (mirrors the seeds-module test params).
fn test_params() -> ArgonParams {
    ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

/// ISC-C98: a share named at publish persists its custom name and an un-named
/// share persists as the basename default (`None`) — both forms survive the
/// at-rest seal/open round-trip, and the keyed idempotency leaves a stored name
/// untouched on a re-publish of the same root. This is the persistence the GUI
/// auto-republish path reads to re-assert each share under the chosen name.
#[test]
fn published_share_name_persists_across_seal_open() {
    let _ = oxicrypt_module::initialize();
    let pid = Uuid::new_v4();
    let pp = "correct horse battery staple table mountain";
    let mut seeds = Seeds::new(Mnemonic::generate().unwrap());

    // A custom-named share and an un-named (basename-default) share.
    assert!(seeds.add_published("/home/alice/photos", Some("alice-photos".to_owned())));
    assert!(seeds.add_published("/home/alice/docs", None));
    // Idempotent, keyed on the root: a re-publish adds no duplicate and does NOT
    // change the stored name (a custom name is never clobbered on republish).
    assert!(!seeds.add_published("/home/alice/photos", Some("ignored-on-dup".to_owned())));

    let blob = seal(&seeds, pp, pid, test_params()).unwrap();
    let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
    let pubs = recovered.published();

    assert_eq!(pubs.len(), 2, "both published roots survive the round-trip");
    assert_eq!(pubs[0].root, "/home/alice/photos");
    assert_eq!(
        pubs[0].name.as_deref(),
        Some("alice-photos"),
        "the custom name persists verbatim and is not clobbered by the re-publish"
    );
    assert_eq!(pubs[1].root, "/home/alice/docs");
    assert_eq!(
        pubs[1].name, None,
        "an un-named share persists as None (republishes under the folder basename)"
    );
}

#[test]
fn isc_c98_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C98", "published_share_name_persists_across_seal_open");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C98 registered (#41 GUI share-name persistence)"
    );
}
