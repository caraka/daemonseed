//! #36 circle-detail name vectors — ISC-C96 coverage.
//!
//! Exercises the core logic behind the two vectors the GUI circle-detail sheet
//! shows: the circle's name, which once the circle is joined is the adj-noun
//! label ([`default_circle_label`], keyed on the circle's rendezvous address), and
//! the `#<12hex>` fingerprint ([`circle_fingerprint`], keyed on the phrase alone).
//! The GUI accessor (`GuiState::circle_fingerprint_of`) and the sheet render
//! (`apply_circle_detail`) live IN the `daemonseed-gui` binary crate, whose `pub`
//! does not escape to this integration crate; the visible sheet render is manual
//! test-gated (ISA `## Criteria` ISC-C96 left `[ ]`).
//! Registers ISC-C96.

use daemonseed_core::circle::default_circle_label;
use daemonseed_core::circle::key::circle_fingerprint;
use daemonseed_core::cot::{ASSET_ADDR_LEN, AssetAddr};
use daemonseed_integration_tests::isc_coverage::Coverage;

/// ISC-C96: the joined circle's label and its fingerprint are derived from
/// independent inputs and DIVERGE — the fingerprint is keyed on the phrase alone,
/// while the label is keyed on the rendezvous address. A different rendezvous
/// yields a different label; the fingerprint is unchanged.
#[test]
fn circle_detail_label_and_fingerprint_diverge() {
    let _ = daemonseed_core::oxi::initialize_module();
    let phrase =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    // The fingerprint: phrase-keyed.
    let fp = circle_fingerprint(phrase);
    assert!(
        fp.starts_with('#'),
        "the fingerprint is the `#<12hex>` floor"
    );

    // The label for rendezvous A.
    let addr_a = AssetAddr::from_bytes([0x11; ASSET_ADDR_LEN]);
    let label_a = default_circle_label(&addr_a);
    assert_ne!(
        label_a, fp,
        "the label diverges from the fingerprint once joined"
    );

    // A DIFFERENT rendezvous → a different label, while the fingerprint stays
    // the same.
    let addr_b = AssetAddr::from_bytes([0x22; ASSET_ADDR_LEN]);
    let label_b = default_circle_label(&addr_b);
    assert_ne!(
        label_a, label_b,
        "a distinct rendezvous yields a distinct label"
    );
    assert_eq!(
        fp,
        circle_fingerprint(phrase),
        "the fingerprint does not change with the rendezvous"
    );

    // Deterministic: the same rendezvous always re-derives the same label.
    assert_eq!(
        label_a,
        default_circle_label(&addr_a),
        "the label is deterministic per rendezvous"
    );
}

#[test]
fn isc_c96_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C96", "circle_detail_label_and_fingerprint_diverge");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C96 registered (#36 circle-detail name vectors)"
    );
}
