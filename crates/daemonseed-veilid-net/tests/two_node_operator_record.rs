//! Integration test (Phase 4 — announcements/MOTD, A-b): the operator-owned
//! announce record. A maintainer (node A, holding the project-announce owner seed)
//! publishes an operator payload to a NAMED current-state slot (`"motd"`, and a
//! content-addressed announcement item) on the owner-gated rendezvous record; a
//! client (node B) subscribes to the same record — via the same owner seed — and
//! reads each slot's bytes back byte-identical. This is the A-b transport oracle:
//! it proves the operator record carries opaque payloads to stable, named
//! last-writer-wins slots.
//!
//! Layering: veilid-net moves OPAQUE bytes; the payload's content-provenance (the
//! ML-DSA-87 `SignedArtifact` verified by `daemonseed_core::public_space::verify_artifact`
//! against the operator whitelist) is a core concern, tested there — the app packs
//! a `SignedArtifact` into these bytes. The **write-gate** (only a holder of the
//! owner seed may place an owner-signed subkey) is the Veilid single-owner DFLT
//! property; it is NOT exercised here because in the dev phase the owner seed is
//! in-source, so both nodes derive it (A derives it to write, B derives it to read).
//! In production the seed stays offline and only the owner PUBKEY is baked into
//! clients, which read but cannot write.
//!
//! `#[ignore]` — needs public Veilid attach; run on a real-network host:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_operator_record -- --ignored --nocapture

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_space::dev_project_announce_veilid_owner_seed;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidNetEvent};

fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_op_record{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn operator_record_slots_reach_a_second_node() {
    oxicrypt_module::initialize().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-op-record-it");
    let _ = std::fs::remove_dir_all(&base);

    // The operator/announce record's owner seed (A1 write-gate). In the dev phase
    // it derives from the in-source PROJECT_RELEASE_SEED, so both nodes compute it.
    let owner_seed = *dev_project_announce_veilid_owner_seed()
        .expect("dev announce owner seed")
        .as_bytes();

    // Two distinct operator payloads: the MOTD (fixed slot) and one announcement
    // item (content-addressed slot). Opaque to this layer — the app packs a signed
    // SignedArtifact here; the test only proves the bytes round-trip per slot. Made
    // unique per run so a stale slot from a prior run can't masquerade as a pass.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let motd_payload = format!("MOTD operator payload {nonce}").into_bytes();
    let announce_slot = format!("announce-{nonce:032x}");
    let announce_payload = format!("announcement item {nonce}").into_bytes();

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5166", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, mut rx_b) = VeilidNet::start(node_config(":5167", &base.join("B")))
        .await
        .expect("start B");

    node_a.attach_and_wait(180).await.expect("A ready");
    node_b.attach_and_wait(180).await.expect("B ready");

    // A (maintainer) writes both slots, then keeps re-writing so a created record
    // becomes network-visible and B's watch fires (DHT propagation is tens of secs).
    let publisher = {
        let a = node_a.clone();
        let seed = owner_seed;
        let motd = motd_payload.clone();
        let a_slot = announce_slot.clone();
        let ann = announce_payload.clone();
        tokio::spawn(async move {
            loop {
                let _ = a.publish_current_state(seed, "motd", motd.clone()).await;
                let _ = a.publish_current_state(seed, &a_slot, ann.clone()).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        })
    };

    tokio::time::sleep(Duration::from_secs(5)).await;
    node_b
        .subscribe_room(owner_seed)
        .await
        .expect("B subscribe to operator record");

    // Oracle: B must read BOTH the MOTD payload and the announcement payload back
    // byte-identical from the operator record within the window.
    let mut saw_motd = false;
    let mut saw_announce = false;
    let _ = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match rx_b.recv().await {
                Some(VeilidNetEvent::Inbound { bytes }) => {
                    if bytes == motd_payload {
                        eprintln!("[oracle] read MOTD slot ({} bytes)", bytes.len());
                        saw_motd = true;
                    } else if bytes == announce_payload {
                        eprintln!("[oracle] read announcement slot ({} bytes)", bytes.len());
                        saw_announce = true;
                    }
                    if saw_motd && saw_announce {
                        break;
                    }
                }
                Some(_) => continue,
                None => break,
            }
        }
    })
    .await;
    publisher.abort();

    assert!(
        saw_motd,
        "B must read the operator MOTD slot back byte-identical"
    );
    assert!(
        saw_announce,
        "B must read the operator announcement slot back byte-identical"
    );

    node_a.shutdown().await;
    node_b.shutdown().await;
}
