//! Integration test (Phase 3 — share discovery): a sealed public-share
//! `ShareAnnouncement` reaches a second node through the shared-owner DFLT DHT
//! **lobby rendezvous** — both nodes derive the SAME record key from the public
//! room name alone (world-derivable, no relay, no key exchange) — and the second
//! node opens the announcement under the room key; an outsider (a different room
//! key) cannot. This is the Phase-3 discovery oracle: it proves the extracted
//! rendezvous engine carries a public-room payload exactly as it carries a
//! circle message, parameterized only by the owner-seed derivation.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! Where the network path blocks a public attach, the wait returns `NotReady`
//! after the full timeout. This crate is `[workspace] exclude`d, so `-p` won't resolve
//! it from the repo root — build from the crate's own directory:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_room -- --ignored --nocapture
//!
//! It drives the productized path end-to-end through the `VeilidNetHandle` API
//! (the surface the app drives), reusing the REAL daemonseed crypto
//! (`derive_room_veilid_owner_seed` / `derive_room_key` / `seal_public_announcement`
//! / `open_announcement`) — no crypto is reimplemented.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, SignKeypair};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::{derive_room_key, derive_room_veilid_owner_seed};
use daemonseed_core::share_announce::{
    derive_root_commitment, derive_share_id_v2, derive_share_root_nonce, open_announcement,
    seal_public_announcement, AnnouncementFields,
};
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig, VeilidNetEvent};

/// A node config with a fresh daemonseed-derived node identity (D3), a distinct
/// listen port, and its own storage dir — so two can coexist in one process.
/// (The node identity is per-node; the *room* rendezvous is shared and comes
/// from the public room name, not the node identity.)
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_room{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "attaches to the public Veilid network; opt-in, run with --ignored"]
async fn sealed_share_announcement_reaches_a_second_node() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-room-it");
    let _ = std::fs::remove_dir_all(&base);

    // The lobby is a PUBLIC room: its rendezvous owner derives from the room
    // name + family alone (world-derivable), so both nodes compute the SAME
    // record key with NO shared secret — the open-rendezvous property. The
    // record is deterministic and PERSISTS on the public DHT, so a fixed name
    // would accumulate stale blobs across runs; make the room name unique per
    // run so every run gets a fresh, isolated rendezvous.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let room = format!("lobby-oracle-{nonce}");
    let owner_seed = *derive_room_veilid_owner_seed(&room, &CNSA_2_0)
        .expect("owner seed")
        .as_bytes();
    let room_key = derive_room_key(&room, &CNSA_2_0).expect("room key");

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5162", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, mut rx_b) = VeilidNet::start(node_config(":5163", &base.join("B")))
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

    // Seal a real ShareAnnouncement under the public room key; the wire carries
    // only these opaque bytes (server-readable by design, but never cleartext).
    let announcer = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).expect("announcer keypair");
    // #156: a receiver-verifiable v2 binding — derive share_id from a real
    // root_commitment (secret-nonce-hidden folder root) so node B's
    // apply_verified accepts it. A random mint_share_id would be dropped.
    let share_ikm = [9u8; 32];
    let share_root = "/srv/vacation-photos";
    let nonce = derive_share_root_nonce(&share_ikm, share_root);
    let root_commitment = derive_root_commitment(share_root, &nonce);
    let share_id = derive_share_id_v2(announcer.public_key(), &root_commitment);
    let fields = AnnouncementFields {
        room: &room,
        sender_handle: "river-otter#aabbccddeeff",
        share_id: &share_id,
        root_commitment: &root_commitment,
        name: "vacation-photos",
        rating: "",
        withdraw: false,
        sent_unix_ms: 1_700_000_000_000,
    };
    let sealed =
        seal_public_announcement(&room_key, &announcer, &fields).expect("seal announcement");

    // A publishes (creates + sets the rendezvous record → network-visible), then
    // keeps re-publishing: a created record isn't visible until first set, and
    // each set both refreshes it and triggers B's watch. DHT propagation + watch
    // latency are tens of seconds.
    let publisher = {
        let a = node_a.clone();
        let seed = owner_seed;
        let payload = sealed.clone();
        tokio::spawn(async move {
            loop {
                let _ = a.publish_room(seed, payload.clone()).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        })
    };

    // Give A's first publish a moment to make the record network-visible, then B
    // joins the SAME lobby (owner seed derived independently from the room name),
    // watches it, and sweeps it for the backlog. A's announcement arrives as an
    // Inbound event via the sweep and/or a watch ValueChange.
    tokio::time::sleep(Duration::from_secs(5)).await;
    node_b
        .subscribe_room(owner_seed)
        .await
        .expect("B subscribe to lobby");

    // Oracle: the shared record can surface several inbound blobs, so the
    // property is "at least one inbound OPENS to A's announcement under the room
    // key" — NOT byte-equality (a fresh seal uses a random nonce). Every blob
    // must also be ciphertext — the share_id never appears in the clear.
    let mut opened = None;
    let _ = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match rx_b.recv().await {
                Some(VeilidNetEvent::Inbound { bytes }) => {
                    assert!(
                        !bytes
                            .windows(share_id.len())
                            .any(|w| w == share_id.as_bytes()),
                        "the share_id must never appear on the wire in the clear"
                    );
                    match open_announcement(&room_key, &bytes) {
                        Ok(a) if a.share_id == share_id && a.name == "vacation-photos" => {
                            eprintln!(
                                "[oracle] inbound {} bytes OPENED to A's announcement",
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
                            "[oracle] inbound {} bytes did not open under the room key (skip)",
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

    let matched = opened.expect("B received and opened A's sealed announcement within 120s");

    // An outsider watching a DIFFERENT room derives a different room key and
    // cannot open the recovered bytes (the public tier is server-readable, but
    // only to holders of THIS room's key).
    let outsider = derive_room_key("a-different-room-nobody-watches", &CNSA_2_0).unwrap();
    assert!(
        open_announcement(&outsider, &matched).is_err(),
        "an outsider room key must fail to open the announcement"
    );

    node_a
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
    node_b
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
}
