//! #36 circle-detail name vectors — ISC-C96 coverage.
//!
//! Exercises the core logic the GUI circle-detail sheet composes for its two
//! derived compare vectors: the relay-SCOPED adj-noun label
//! ([`default_circle_label`], keyed on the rendezvous `SHA-384(cot_key ‖
//! server_id)`) and the relay-INDEPENDENT `#<12hex>` fingerprint
//! ([`circle_fingerprint`], keyed on the phrase alone). The GUI accessors
//! (`GuiState::circle_deterministic_label_of` / `circle_fingerprint_of`) and the
//! sheet render (`apply_circle_detail`) are unit-tested IN the `daemonseed-gui`
//! binary crate (`state::tests::circle_detail_label_derives_from_net_contract_not_chosen_name`),
//! whose `pub` does not escape to this integration crate; the visible 3-vector
//! sheet render is felt-test-gated (ISA `## Criteria` ISC-C96 left `[ ]`).
//! Registers ISC-C96.

use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::circle_fingerprint;
use daemonseed_core::cot::{ASSET_ADDR_LEN, AssetAddr};
use daemonseed_integration_tests::isc_coverage::Coverage;

/// ISC-C96: the relay-scoped label and the universal fingerprint are derived from
/// independent inputs and DIVERGE — the fingerprint is keyed on the phrase alone
/// (relay-independent, the same everywhere), while the label is keyed on the relay
/// rendezvous (relay-scoped, matches only between members on the SAME relay). A
/// different rendezvous yields a different label; the fingerprint is unchanged.
#[test]
fn circle_detail_vectors_diverge_label_relay_scoped_fingerprint_universal() {
    let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
    let phrase =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    // The universal vector: phrase-keyed, relay-independent.
    let fp = circle_fingerprint(phrase);
    assert!(
        fp.starts_with('#'),
        "the fingerprint is the `#<12hex>` floor"
    );

    // The relay-scoped vector on relay A.
    let addr_a = AssetAddr::from_bytes([0x11; ASSET_ADDR_LEN]);
    let label_a = default_circle_label(&addr_a);
    assert_ne!(
        label_a, fp,
        "the relay-derived label diverges from the universal fingerprint once connected"
    );

    // A DIFFERENT relay rendezvous → a different label (relay-scoped), while the
    // fingerprint stays the same (relay-independent).
    let addr_b = AssetAddr::from_bytes([0x22; ASSET_ADDR_LEN]);
    let label_b = default_circle_label(&addr_b);
    assert_ne!(
        label_a, label_b,
        "the label is relay-scoped: a distinct rendezvous yields a distinct label"
    );
    assert_eq!(
        fp,
        circle_fingerprint(phrase),
        "the fingerprint is relay-independent: it does not change with the rendezvous"
    );

    // Deterministic: the same rendezvous always re-derives the same label.
    assert_eq!(
        label_a,
        default_circle_label(&addr_a),
        "the label is deterministic per rendezvous (members on the same relay match)"
    );
}

#[test]
fn isc_c96_covered() {
    let mut c = Coverage::empty();
    c.register(
        "ISC-C96",
        "circle_detail_vectors_diverge_label_relay_scoped_fingerprint_universal",
    );
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C96 registered (#36 circle-detail name vectors)"
    );
}
