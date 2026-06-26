//! Integration test (#99): a sealed daemonseed `CircleMessage` reaches a second
//! member through a shared-owner DFLT DHT **rendezvous record** — both members
//! derive the SAME record key from the circle entropy (no relay, no key
//! exchange) — and is recovered byte-for-byte; an outsider key cannot open it.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! This VM's SLIRP NAT blocks attach, so run it on a real-network host
//! (e.g. orinoco). This crate is `[workspace] exclude`d, so `-p` won't resolve
//! it from the repo root — build from the crate's own directory:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_circle -- --ignored --nocapture
//!
//! It drives the productized Phase-2 path end-to-end through the
//! `VeilidNetHandle` API (the surface the app drives), reusing the REAL
//! daemonseed crypto (`derive_circle_veilid_owner_seed` / `derive_cot_key` /
//! `seal_message` / `open_message`) — no crypto is reimplemented.

use std::time::Duration;

use daemonseed_core::circle::key::{derive_circle_veilid_owner_seed, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_proto::v1::CircleMessage;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidNetEvent};

/// A node config with a fresh daemonseed-derived node identity (D3), a distinct
/// listen port, and its own storage dir — so two can coexist in one process.
/// (The node identity is per-member; the *circle* rendezvous is shared and comes
/// from the circle entropy, not the node identity.)
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_circle{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn sealed_circle_message_reaches_a_second_member() {
    oxicrypt_module::initialize().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-circle-it");
    let _ = std::fs::remove_dir_all(&base);

    // The shared circle secret. Both members derive the SAME rendezvous-owner
    // seed (→ same DFLT record key = rendezvous address) AND the SAME content
    // key, INDEPENDENTLY — neither is ever sent over Veilid.
    let entropy = "two-node-circle oracle: a shared circle passphrase";
    let owner_seed = *derive_circle_veilid_owner_seed(entropy, &CNSA_2_0)
        .expect("owner seed")
        .as_bytes();
    let cot_key = derive_cot_key(entropy, &CNSA_2_0).expect("cot_key");

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5160", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, mut rx_b) = VeilidNet::start(node_config(":5161", &base.join("B")))
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

    // Seal a real CircleMessage; the wire carries only these opaque bytes.
    let original = CircleMessage {
        sender_handle: "river-otter#aabbccddeeff".to_owned(),
        body: "carried over a Veilid DHT circle rendezvous".to_owned(),
        sent_unix_ms: 1_700_000_000_000,
    };
    let sealed = seal_message(&cot_key, &original).expect("seal");

    // A publishes (creates + sets the rendezvous record → network-visible), then
    // keeps re-publishing: a created record isn't visible until first set, and
    // each set both refreshes it and triggers B's watch. (Mirrors #97's robust
    // sender loop; DHT propagation + watch latency are tens of seconds.)
    let publisher = {
        let a = node_a.clone();
        let seed = owner_seed;
        let payload = sealed.clone();
        tokio::spawn(async move {
            loop {
                let _ = a.publish_circle(seed, payload.clone()).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        })
    };

    // Give A's first publish a moment to make the record network-visible, then B
    // joins: opens the SAME rendezvous record (key derived independently from the
    // entropy), watches it, and sweeps it for the backlog. A's message arrives as
    // an Inbound event via the sweep and/or a watch ValueChange.
    tokio::time::sleep(Duration::from_secs(5)).await;
    node_b
        .subscribe_circle(owner_seed)
        .await
        .expect("B subscribe to circle");

    let wire_bytes = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match rx_b.recv().await {
                Some(VeilidNetEvent::Inbound { bytes }) => break bytes,
                Some(_) => continue,
                None => panic!("B event stream closed before delivery"),
            }
        }
    })
    .await
    .expect("an inbound circle message reached B within 120s");
    publisher.abort();

    // Oracle: the wire carried ciphertext, the member recovers it exactly, an
    // outsider cannot.
    assert!(
        !wire_bytes
            .windows(original.body.len())
            .any(|w| w == original.body.as_bytes()),
        "the plaintext body must never appear on the wire"
    );
    assert_eq!(wire_bytes, sealed, "B received exactly the bytes A sealed");

    let recovered = open_message(&cot_key, &wire_bytes).expect("a member opens it");
    assert_eq!(recovered.body, original.body);
    assert_eq!(recovered.sender_handle, original.sender_handle);

    let outsider = derive_cot_key("a phrase no member ever agreed to", &CNSA_2_0).unwrap();
    assert!(
        open_message(&outsider, &wire_bytes).is_err(),
        "an outsider key must fail to open the same bytes"
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}
