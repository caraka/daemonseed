//! Integration test (#99): a sealed daemonseed `CircleMessage` reaches a second
//! member through a shared-owner DFLT DHT **rendezvous record** — both members
//! derive the SAME record key from the circle entropy (no relay, no key
//! exchange) — and the second member opens it under the circle key; an outsider
//! key cannot. (The record is shared + persistent and the ring may hold several
//! slots, so the oracle is decryptability of an inbound, not byte-equality.)
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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use daemonseed_core::circle::key::{derive_circle_veilid_owner_seed, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
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
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-circle-it");
    let _ = std::fs::remove_dir_all(&base);

    // The shared circle secret. Both members derive the SAME rendezvous-owner
    // seed (→ same DFLT record key = rendezvous address) AND the SAME content
    // key, INDEPENDENTLY — neither is ever sent over Veilid. The rendezvous
    // record is DETERMINISTIC and PERSISTS on the public DHT, so a fixed phrase
    // would accumulate stale blobs across runs (each run's random node identity
    // writes a different member region that is never overwritten); make the
    // phrase unique per run so every run gets a fresh, isolated rendezvous.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let entropy = format!("two-node-circle oracle: a shared circle passphrase {nonce}");
    let owner_seed = *derive_circle_veilid_owner_seed(&entropy, &CNSA_2_0)
        .expect("owner seed")
        .as_bytes();
    let cot_key = derive_cot_key(&entropy, &CNSA_2_0).expect("cot_key");

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

    // Seal a real signed circle RoomMessage; the wire carries only opaque bytes.
    let signer = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).expect("signer");
    let handle = "river-otter#aabbccddeeff";
    let body = "carried over a Veilid DHT circle rendezvous";
    let sealed = seal_message(&cot_key, &signer, handle, body, 1_700_000_000_000).expect("seal");

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

    // Oracle: the shared record can surface several inbound blobs (this member's
    // ring slots, and possibly others), so the property is "at least one inbound
    // OPENS to A's message under the circle key" — NOT byte-equality of the first
    // blob (a fresh seal uses a random nonce, and the ring may hold > 1 slot).
    // Every blob must also be ciphertext (never the plaintext in the clear).
    let mut opened = None;
    let _ = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match rx_b.recv().await {
                Some(VeilidNetEvent::Inbound { bytes }) => {
                    assert!(
                        !bytes.windows(body.len()).any(|w| w == body.as_bytes()),
                        "the plaintext body must never appear on the wire"
                    );
                    match open_message(&cot_key, &bytes) {
                        Ok(m) if m.body == body && m.sender_handle == handle => {
                            eprintln!(
                                "[oracle] inbound {} bytes OPENED to A's message",
                                bytes.len()
                            );
                            opened = Some(bytes);
                            break;
                        }
                        Ok(_) => eprintln!(
                            "[oracle] inbound {} bytes opened but did not match (skip)",
                            bytes.len()
                        ),
                        Err(_) => eprintln!(
                            "[oracle] inbound {} bytes did not open under the circle key (skip)",
                            bytes.len()
                        ),
                    }
                }
                Some(_) => continue,
                None => break,
            }
        }
    })
    .await;
    publisher.abort();

    let matched = opened.expect("B received and opened A's sealed circle message within 120s");

    // An outsider key cannot open the recovered bytes.
    let outsider = derive_cot_key("a phrase no member ever agreed to", &CNSA_2_0).unwrap();
    assert!(
        open_message(&outsider, &matched).is_err(),
        "an outsider key must fail to open the message"
    );

    node_a
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
    node_b
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
}
