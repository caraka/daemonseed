//! Integration test (#232, ISC-C40): node A publishes its DM key record, and node
//! B — holding nothing but A's **public identity key** — derives the record's
//! address, fetches it, and verifies it.
//!
//! This is the live oracle for the whole discovery premise of direct messaging:
//! *anyone visible on a roster or in a transcript is DM-able with zero new
//! discovery surface*. B is given exactly what a real peer would already have —
//! the ML-DSA-87 public key that rides every provenance-signed artifact — and
//! nothing else. No shared secret, no key exchange, no handshake, no roster.
//!
//! It exists because the unit tests cannot reach this: they prove the crypto and
//! the arithmetic, but the address derivation only *means* anything if two
//! independent nodes compute the same DHT record from opposite ends. Nothing in
//! the shipping client calls the fetch path yet (that arrives with #233), so
//! without this test the read half of ISC-C40 would be unexercised over a real
//! network until a later slice.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! This VM cannot: something in the QEMU bridge eats the Veilid connection, so
//! attach returns `NotReady` after the full 180 s timeout (measured 2026-07-28).
//! Run it on a real-network host:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_dm_key_record -- --ignored --nocapture
//!
//! It drives the productized `VeilidNetHandle` surface the app drives, and reuses
//! the REAL daemonseed crypto (`dm::keyrec::{build_encoded, derive_owner_seed,
//! decode_and_verify}`) — no crypto is reimplemented here.

use daemonseed_core::dm::keyrec;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig};

/// A node config with a fresh daemonseed-derived node identity, a distinct listen
/// port, and its own storage dir — so two can coexist in one process. The node
/// identity is per-node and unrelated to the *user* identity whose key record is
/// under test.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_keyrec{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn a_published_key_record_is_found_and_verified_from_the_pubkey_alone() {
    oxicrypt_module::initialize().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-keyrec-it");
    let _ = std::fs::remove_dir_all(&base);

    // The USER identity under test. A fresh mnemonic per run: the key record's
    // address is deterministic in this identity and PERSISTS on the public DHT,
    // so a fixed identity would collide with previous runs' blobs.
    let alice = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary)
        .expect("alice identity");

    // Everything node B is allowed to know. In production this arrives on a chat
    // message, a share announcement, or a presence beacon — never out of band.
    let alice_pubkey = *alice.signing.public_key();

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5172", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config(":5173", &base.join("B")))
        .await
        .expect("start B");

    node_a
        .attach_and_wait(180)
        .await
        .expect("A public-internet-ready");
    node_b
        .attach_and_wait(180)
        .await
        .expect("B public-internet-ready");

    // ── A publishes ──────────────────────────────────────────────────────────
    let record = keyrec::build_encoded(
        &alice.signing,
        alice.kem.encapsulation_key(),
        keyrec::DM_KEY_RECORD_VERSION,
        keyrec::DM_KEY_RECORD_INVITE_ONLY,
    )
    .expect("build key record");

    // A derives its OWN record address from its OWN public key.
    let owner_seed_a = *keyrec::derive_owner_seed(&alice_pubkey)
        .expect("A derives owner seed")
        .as_bytes();

    node_a
        .publish_dm_key_record(owner_seed_a, record)
        .await
        .expect("A publishes its key record");

    // ── B finds it from the pubkey alone ─────────────────────────────────────
    // The load-bearing step: B derives the SAME address with no input from A
    // beyond the public identity key. If the derivation were not world-derivable
    // and deterministic, these two seeds would differ and the fetch would find
    // nothing.
    let owner_seed_b = *keyrec::derive_owner_seed(&alice_pubkey)
        .expect("B derives owner seed")
        .as_bytes();
    assert_eq!(
        owner_seed_a, owner_seed_b,
        "both ends must derive the same record address from the public key alone"
    );

    // DHT writes are eventually consistent; poll rather than assume convergence.
    let mut fetched = None;
    for attempt in 0..30 {
        match node_b.fetch_dm_key_record(owner_seed_b).await {
            Ok(Some(bytes)) => {
                fetched = Some(bytes);
                break;
            }
            Ok(None) => {
                eprintln!("attempt {attempt}: slot still empty, retrying");
            }
            Err(e) => {
                eprintln!("attempt {attempt}: fetch error {e}, retrying");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    let fetched = fetched.expect("B fetched A's key record within the convergence window");

    // ── B verifies ───────────────────────────────────────────────────────────
    let verified =
        keyrec::decode_and_verify(&fetched, &alice_pubkey).expect("record verifies against A");
    assert_eq!(verified.version, keyrec::DM_KEY_RECORD_VERSION);
    assert_eq!(verified.invite_only, keyrec::DM_KEY_RECORD_INVITE_ONLY);
    assert_eq!(
        &verified.kem_ek[..],
        &alice.kem.encapsulation_key()[..],
        "the encapsulation key B recovered must be the one A published — this is \
         what a first-contact sender would encapsulate to"
    );

    // ── and an impostor cannot pass ──────────────────────────────────────────
    // The same fetched bytes, checked against a DIFFERENT identity, must fail.
    // This is the property that makes a world-WRITABLE record safe: anyone can
    // overwrite the slot, but nobody can make a record verify for an identity
    // whose key they do not hold.
    let mallory = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary)
        .expect("mallory identity");
    assert!(
        keyrec::decode_and_verify(&fetched, mallory.signing.public_key()).is_err(),
        "a key record must never verify against an identity that did not sign it"
    );

    eprintln!("ISC-C40 live oracle: publish -> world-derivable address -> fetch -> verify OK");
}
