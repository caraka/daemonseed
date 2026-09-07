//! Integration test (Phase 4 — announcements/MOTD, A-b): the operator-owned
//! announce record. A writer (node A, holding a project seed and the announce
//! owner seed derived from it) publishes an operator payload to a NAMED
//! current-state slot (`"motd"`, and a content-addressed announcement item) on the
//! owner-gated rendezvous record; a reader (node B) subscribes to the same record
//! from the owner PUBLIC key alone and reads each slot's bytes back byte-identical.
//! This is the A-b transport oracle: it proves the operator record carries opaque
//! payloads to stable, named last-writer-wins slots, and that a party holding
//! nothing but the owner's public key reads them.
//!
//! The project seed is drawn fresh for each run. The record under test is therefore
//! a new one, owned by nobody else, and the test needs no secret: node B is handed
//! the owner public key as 32 bytes, exactly the shape in which a shipped client
//! holds the baked `PROJECT_ANNOUNCE_OWNER_PUBKEY`. What this does NOT exercise is
//! the real project identity — that the operator's runtime-loaded seed owns the
//! baked record is checked at load (`OperatorCredential`), and is observed end to
//! end by an operator instance and a second client on the live network.
//!
//! Layering: veilid-net moves OPAQUE bytes; the payload's content-provenance (the
//! ML-DSA-87 `SignedArtifact` verified by `daemonseed_core::public_space::verify_artifact`
//! against the operator whitelist) is a core concern, tested there — the app packs
//! a `SignedArtifact` into these bytes. The **write-gate** (only a holder of the
//! owner seed may place an owner-signed subkey) is the Veilid single-owner DFLT
//! property; it is NOT exercised here, as node B never attempts a write.
//!
//! `#[ignore]` — it attaches to the public Veilid network and takes minutes, so it
//! is opt-in rather than part of an ordinary test run:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_operator_record -- --ignored --nocapture

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_space::derive_project_announce_veilid_owner_seed;
use daemonseed_veilid_net::{
    OwnerPublic, OwnerSeed, RendezvousOwner, VeilidNet, VeilidNetConfig, VeilidNetEvent,
};

fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_op_record{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "attaches to the public Veilid network; opt-in, run with --ignored"]
async fn operator_record_slots_reach_a_second_node() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-op-record-it");
    let _ = std::fs::remove_dir_all(&base);

    // A fresh project seed for this run, and the announce owner seed derived from it
    // the way the operator derives its own. Held by node A only. Node B is handed the
    // owner's PUBLIC key as bytes and nothing else.
    let mut project_seed = [0u8; 32];
    getrandom::fill(&mut project_seed).expect("draw a project seed");
    let owner_seed = *derive_project_announce_veilid_owner_seed(&project_seed)
        .expect("derive the announce owner seed")
        .as_bytes();
    let owner_public = OwnerPublic::of_seed(&OwnerSeed::new(owner_seed));

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

    // A (the writer) creates the record on its first write, then keeps re-writing so
    // the record becomes network-visible and B's watch fires (DHT propagation is
    // tens of seconds).
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

    // B subscribes on the public key alone. A read-only subscribe of a record that
    // is not yet visible to B is a clean `Ok(false)` with no watch registered, so
    // the subscribe is retried until the record opens — and that is asserted on its
    // own, so "the record never became visible" and "the payloads never arrived"
    // are two different failures.
    let reader = RendezvousOwner::PublicOnly(owner_public);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut opened = false;
    while Instant::now() < deadline {
        opened = node_b
            .subscribe_room(reader.clone())
            .await
            .expect("B subscribe to operator record");
        if opened {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert!(
        opened,
        "B must open the operator record from the owner public key alone within the window"
    );
    eprintln!("[oracle] B opened the record read-only from the owner public key");

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

    node_a
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
    node_b
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
}
