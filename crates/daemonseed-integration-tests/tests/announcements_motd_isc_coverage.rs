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
