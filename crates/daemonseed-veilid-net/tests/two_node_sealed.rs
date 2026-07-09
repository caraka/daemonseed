//! Integration test (#97): a sealed daemonseed `CircleMessage` crosses a real
//! Veilid private route between two `VeilidNet` nodes and is recovered
//! byte-for-byte; an outsider key cannot open it.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! This VM's SLIRP NAT blocks attach, so run it on a real-network host
//! (e.g. orinoco). This crate is `[workspace] exclude`d, so `-p` won't resolve
//! it from the repo root — build from the crate's own directory:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_sealed -- --ignored --nocapture
//!
//! It drives the productized Phase-1 path end-to-end through the
//! `VeilidNetHandle` API (the same surface the app drives), reusing the REAL
//! daemonseed crypto (`derive_cot_key` / `seal_message` / `open_message`) — no
//! crypto is reimplemented, so the proof is the migration's, not a lookalike.

use std::time::Duration;

use daemonseed_core::circle::key::{derive_cot_key, EXAMPLE_ENTROPY};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidNetEvent};

/// A node config with a fresh daemonseed-derived identity (D3), a distinct
/// listen port, and its own storage dir — so two can coexist in one process.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_sealed{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn sealed_circle_message_crosses_a_private_route() {
    oxicrypt_module::initialize().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-it");
    let _ = std::fs::remove_dir_all(&base);

    // Both members derive the SAME content key INDEPENDENTLY — it is never sent
    // over Veilid, so the post-quantum content guarantee is transport-independent.
    let cot_key = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).expect("cot_key");

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5150", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, mut rx_b) = VeilidNet::start(node_config(":5151", &base.join("B")))
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

    // B publishes a private inbound route; A imports the opaque blob. The route
    // may report "try again" until it builds — retry until it does.
    let blob = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            match node_b.new_inbound_route().await {
                Ok(b) => break b,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => panic!("B route never built within 120s: {e}"),
            }
        }
    };
    let route = node_a
        .import_route(blob.blob)
        .await
        .expect("A import route");

    // Seal a real signed circle RoomMessage and send the opaque bytes over the route.
    let signer = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).expect("signer");
    let handle = "river-otter#aabbccddeeff";
    let body = "carried over a Veilid private route";
    let sealed = seal_message(&cot_key, &signer, handle, body, 1_700_000_000_000).expect("seal");

    // Retry the send until the route carries it; await B's inbound event.
    let sender = {
        let send_handle = node_a.clone();
        let route_s = route.clone();
        let sealed_s = sealed.clone();
        tokio::spawn(async move {
            loop {
                let _ = send_handle
                    .send_sealed(route_s.clone(), sealed_s.clone())
                    .await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
    };
    let wire_bytes = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            match rx_b.recv().await {
                Some(VeilidNetEvent::Inbound { bytes }) => break bytes,
                Some(_) => continue,
                None => panic!("B event stream closed before delivery"),
            }
        }
    })
    .await
    .expect("an inbound app_message reached B within 90s");
    sender.abort();

    // Oracle: the wire carried ciphertext, the member recovers it exactly, an
    // outsider cannot.
    assert!(
        !wire_bytes.windows(body.len()).any(|w| w == body.as_bytes()),
        "the plaintext body must never appear on the wire"
    );
    assert_eq!(wire_bytes, sealed, "B received exactly the bytes A sealed");

    let recovered = open_message(&cot_key, &wire_bytes).expect("a member opens it");
    assert_eq!(recovered.body, body);
    assert_eq!(recovered.sender_handle, handle);

    let outsider = derive_cot_key("a phrase no member ever agreed to", &CNSA_2_0).unwrap();
    assert!(
        open_message(&outsider, &wire_bytes).is_err(),
        "an outsider key must fail to open the same bytes"
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}
