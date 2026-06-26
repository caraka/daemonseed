//! #89 in-band MOTD upload — ISC-S31 coverage.
//!
//! Exercises the server's in-band MOTD ingest
//! ([`PublicSpaceState::upload_motd`]) at the library level: a whitelisted
//! signer's signed `MotdPayload` is verified against the signer whitelist (the
//! same trust model as `UploadPost`), persisted to the single MOTD slot, and
//! served (latest-validated-wins, ISC-S9). Registers ISC-S31.

use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_proto::v1 as wire;
use daemonseed_server::public_space::{PublicSpaceConfig, PublicSpaceState};
use prost::Message;
use tempfile::TempDir;

fn keypair(seed: u8) -> SignKeypair {
    let _ = oxicrypt_module::initialize();
    SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
}

fn motd_artifact(signer: &SignKeypair, text: &str, ts: i64) -> wire::SignedArtifact {
    let payload = wire::MotdPayload {
        text: text.to_owned(),
        signed_timestamp_ms: ts,
    };
    let signed_payload = payload.encode_to_vec();
    let signature = signer.sign(&signed_payload).unwrap().to_vec();
    wire::SignedArtifact {
        signed_payload,
        signer_pubkey: signer.public_key().to_vec(),
        signature,
    }
}

/// ISC-S31: a whitelisted signer sets the MOTD in-band via `upload_motd`; it is
/// persisted and served from the single slot (latest-validated-wins, ISC-S9).
#[test]
fn whitelisted_signer_sets_motd_in_band() {
    let signer = keypair(120);
    let server = keypair(99);
    let dir = TempDir::new().unwrap();
    let wl_path = dir.path().join("signers.txt");
    std::fs::write(&wl_path, format!("{}\n", hex::encode(signer.public_key()))).unwrap();
    let motd_path = dir.path().join("motd.signed");
    let cfg = PublicSpaceConfig {
        posts_dir: None,
        motd_path: Some(&motd_path),
        whitelist_path: Some(&wl_path),
        taxonomy: &[],
        topics: &[],
    };
    let state = PublicSpaceState::load(&cfg, server.public_key()).unwrap();
    assert!(state.get_motd().is_none(), "no MOTD until uploaded");

    state
        .upload_motd(motd_artifact(&signer, "relay is up", 1))
        .unwrap();

    let stored = state.get_motd().expect("MOTD set in-band");
    let text = wire::MotdPayload::decode(stored.signed_payload.as_slice())
        .unwrap()
        .text;
    assert_eq!(text, "relay is up");
    assert!(motd_path.exists(), "persisted to disk under motd_path");

    // Latest-validated-wins: a second upload replaces the slot.
    state
        .upload_motd(motd_artifact(&signer, "maintenance soon", 2))
        .unwrap();
    let text2 = wire::MotdPayload::decode(state.get_motd().unwrap().signed_payload.as_slice())
        .unwrap()
        .text;
    assert_eq!(text2, "maintenance soon");
}

#[test]
fn isc_s31_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-S31", "whitelisted_signer_sets_motd_in_band");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-S31 registered (in-band MOTD upload)"
    );
}

// ── #90 client signer authoring + self-determination (ISC-C89 / ISC-C90) ──
//
// Exercises the cli authoring half (`daemonseed_cli::public_space`) — the
// symmetric counterpart to the read/verify helpers — at the library level.

use daemonseed_cli::public_space::{
    composer_visible, local_key_is_whitelisted, sign_post, verify_served_post, whitelist_from_wire,
};

fn full_key_entry(signer: &SignKeypair) -> wire::SignerWhitelistEntry {
    wire::SignerWhitelistEntry {
        entry: Some(wire::signer_whitelist_entry::Entry::FullPubkey(
            signer.public_key().to_vec(),
        )),
    }
}

/// ISC-C89: a signer authors a post with `sign_post`; the served artifact
/// re-verifies against the published signer whitelist via `verify_served_post`
/// (the authoring counterpart to the verify-and-serve read path).
#[test]
fn client_signer_authoring_round_trips() {
    let signer = keypair(121);
    let artifact = sign_post(&signer, "announcements", "v2 shipped", 9).unwrap();
    let address = daemonseed_core::public_space::content_address(&artifact.signed_payload).unwrap();
    let post = wire::Post {
        artifact: Some(artifact),
        content_address: address.as_bytes().to_vec(),
    };
    let wl = whitelist_from_wire(&[full_key_entry(&signer)], None).unwrap();
    assert!(verify_served_post(&post, &wl).is_ok());
}

#[test]
fn isc_c89_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C89", "client_signer_authoring_round_trips");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C89 registered (signer authoring)"
    );
}

/// ISC-C90: signer self-determination — `local_key_is_whitelisted` is true iff
/// the local pubkey is on the relay's published whitelist; it gates the
/// in-client composer (#92) cryptographically, with no admin login.
#[test]
fn client_signer_self_determination() {
    let signer = keypair(122);
    let stranger = keypair(123);
    let entries = [full_key_entry(&signer)];
    assert_eq!(
        local_key_is_whitelisted(signer.public_key(), &entries),
        Ok(true)
    );
    assert_eq!(
        local_key_is_whitelisted(stranger.public_key(), &entries),
        Ok(false)
    );
}

#[test]
fn isc_c90_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C90", "client_signer_self_determination");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C90 registered (self-determination)"
    );
}

// ── #91 GUI announcement + MOTD display panes (ISC-C91) ───────────────────
//
// The data-prep + client re-verification (`daemonseed_gui::state::
// build_announcements_view`) is unit-tested IN the gui crate (a binary crate, so
// its `pub` does not escape to this integration crate). The test
// `build_announcements_view_verifies_motd_and_drops_unverifiable_post` proves the
// verified-in → correct-display-model-out behaviour and that an unverifiable post
// is dropped (ISC-A-S3). This registration records the coverage; the Slint
// rendering of the model is felt-test-gated (ISA `## Criteria` ISC-C91 left `[ ]`).

/// ISC-C91: the GUI announcements/MOTD data-prep verifies the relay's served MOTD
/// + posts client-side and drops anything unverifiable, producing the pane model.
#[test]
fn isc_c91_covered() {
    let mut c = Coverage::empty();
    c.register(
        "ISC-C91",
        "build_announcements_view_verifies_motd_and_drops_unverifiable_post",
    );
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C91 registered (GUI announcement + MOTD display panes)"
    );
}

// ── #92 signer-gated MOTD/announcement composer (ISC-C92) ─────────────────
//
// The shared gating predicate (`daemonseed_cli::public_space::composer_visible`)
// is what both clients (GUI + TUI) gate the composer affordance on: it is true iff
// the local stable identity key is on the relay's published whitelist, and fails
// CLOSED on an empty / malformed whitelist. The Slint composer + TUI composer that
// surface this verdict are felt-test-gated (ISA `## Criteria` ISC-C92 left `[ ]`).

/// ISC-C92: the signer-gated composer predicate — `composer_visible` is true only
/// when the local stable identity key is on the relay's published whitelist, and
/// false for a non-signer and a malformed/empty whitelist (fail-closed). This is
/// the boolean the GUI + TUI gate the MOTD/announcement composer on (D3).
#[test]
fn client_signer_composer_gating() {
    let signer = keypair(124);
    let stranger = keypair(125);
    let entries = [full_key_entry(&signer)];
    // On-list signer → composer shown.
    assert!(composer_visible(signer.public_key(), &entries));
    // Off-list key → composer hidden.
    assert!(!composer_visible(stranger.public_key(), &entries));
    // No published signers → composer hidden (read-only pane).
    assert!(!composer_visible(signer.public_key(), &[]));
    // Malformed published whitelist (no `entry` oneof) → fail-closed.
    let malformed = wire::SignerWhitelistEntry { entry: None };
    assert!(!composer_visible(signer.public_key(), &[malformed]));
}

#[test]
fn isc_c92_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C92", "client_signer_composer_gating");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C92 registered (signer-gated composer)"
    );
}
