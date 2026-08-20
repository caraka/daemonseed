//! Integration test (Phase 4 — presence): two nodes converge a roster over the
//! shared-owner DFLT DHT **presence rendezvous** — a record DISTINCT from the
//! chat rendezvous (P1), derived world-derivably from the public room name alone
//! via `derive_room_presence_veilid_owner_seed`. Node A seals + emits a
//! `MemberHeartbeat` to its own `current_state_subkey` slot on the presence
//! record; node B subscribes to the same presence record, opens the heartbeat
//! under the room key, and folds it into a `PresenceTracker` — so B's roster
//! shows A. This is the P-a (#74) presence oracle: it proves the current-state
//! transport primitive (`publish_presence`) carries a sealed heartbeat exactly as
//! the append-ring carries a chat message, and that the receiver-side liveness
//! view (`PresenceTracker`) converges from live beacons alone (no relay, no
//! roster on the wire).
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! This VM's SLIRP NAT blocks attach, so run it on a real-network host
//! (e.g. orinoco). This crate is `[workspace] exclude`d, so `-p` won't resolve
//! it from the repo root — build from the crate's own directory:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_presence -- --ignored --nocapture
//!
//! It drives the productized path end-to-end through the `VeilidNetHandle` API
//! (the surface the app drives), reusing the REAL daemonseed crypto
//! (`derive_room_presence_veilid_owner_seed` / `derive_room_key` /
//! `seal_public_heartbeat` / `open_heartbeat` / `PresenceTracker`) — no crypto is
//! reimplemented.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::heartbeat::{open_heartbeat, seal_public_heartbeat, HeartbeatFields};
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, SignKeypair};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::presence::{PresenceChange, PresenceTracker, HEARTBEAT_MISS_COUNT};
use daemonseed_core::public_room::{derive_room_key, derive_room_presence_veilid_owner_seed};
use daemonseed_veilid_net::{PresenceBoundary, VeilidNet, VeilidNetConfig, VeilidNetEvent};

/// A node config with a fresh daemonseed-derived node identity (D3), a distinct
/// listen port, and its own storage dir — so two can coexist in one process.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_presence{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn presence_roster_converges_on_a_second_node() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-presence-it");
    let _ = std::fs::remove_dir_all(&base);

    // Unique room per run so the deterministic presence record is fresh (a fixed
    // name would accumulate stale beacons across runs on the persistent DHT).
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let room = format!("lobby-presence-oracle-{nonce}");
    // The PRESENCE record's owner seed — a sibling of the chat rendezvous owner,
    // so presence rides its OWN record (P1). World-derivable, so both nodes
    // independently compute the same presence rendezvous with no shared secret.
    let presence_owner_seed = *derive_room_presence_veilid_owner_seed(&room, &CNSA_2_0)
        .expect("presence owner seed")
        .as_bytes();
    let room_key = derive_room_key(&room, &CNSA_2_0).expect("room key");

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5164", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, mut rx_b) = VeilidNet::start(node_config(":5165", &base.join("B")))
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

    // A's member identity self-signs its beacon (provenance, ISC-C57). The handle
    // is advisory and sealed — it must never appear on the wire in the clear.
    let member_a = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).expect("member A keypair");
    let a_pubkey = member_a.public_key().to_vec();
    let a_handle = "river-otter#aabbccddeeff";

    // A seals + emits a heartbeat to ITS OWN current-state slot on the presence
    // record, then keeps re-beaconing: a created record isn't visible until first
    // set, and each set refreshes it + triggers B's watch. DHT propagation + watch
    // latency are tens of seconds.
    let publisher = {
        let a = node_a.clone();
        let seed = presence_owner_seed;
        let pubkey = a_pubkey.clone();
        let key_bytes = *room_key.as_bytes();
        tokio::spawn(async move {
            let room_key = daemonseed_core::public_room::PublicRoomKey::from_bytes(key_bytes);
            loop {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64;
                let fields = HeartbeatFields {
                    room: &room,
                    sender_handle: a_handle,
                    sent_unix_ms: now_ms,
                    live_share_ids: &[],
                    is_leave: false,
                };
                if let Ok(sealed) = seal_public_heartbeat(&room_key, &member_a, &fields) {
                    let _ = a
                        .publish_presence(seed, &pubkey, sealed, PresenceBoundary::Keepalive)
                        .await;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        })
    };

    // Give A's first beacon a moment to make the record network-visible, then B
    // subscribes to the SAME presence record (owner seed derived independently)
    // and folds inbound heartbeats into its tracker.
    tokio::time::sleep(Duration::from_secs(5)).await;
    node_b
        .subscribe_room(presence_owner_seed)
        .await
        .expect("B subscribe to presence record");

    let mut tracker = PresenceTracker::with_cadence(Duration::from_secs(15), HEARTBEAT_MISS_COUNT);
    let converged = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match rx_b.recv().await {
                Some(VeilidNetEvent::Inbound { bytes }) => {
                    assert!(
                        !bytes
                            .windows(a_handle.len())
                            .any(|w| w == a_handle.as_bytes()),
                        "the member handle must never appear on the wire in the clear"
                    );
                    // Only a heartbeat opens under the heartbeat AAD; a chat frame
                    // or announcement fails here (distinct AAD) and is skipped.
                    match open_heartbeat(&room_key, &bytes) {
                        Ok(hb) if hb.sender_pubkey == a_pubkey => {
                            let change = tracker.apply(&hb, Instant::now());
                            if change != PresenceChange::Unchanged {
                                eprintln!(
                                    "[oracle] heartbeat from A folded into roster ({change:?})"
                                );
                                return true;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    publisher.abort();

    assert!(
        converged,
        "B's roster must converge to include A from live presence beacons within 120s"
    );
    // The roster shows exactly A, bound to A's verified pubkey (the ISC-C4 handle
    // binding is the caller's, but the identity key is authoritative here).
    let members = tracker.members();
    assert_eq!(members.len(), 1, "roster holds exactly the one live member");
    assert_eq!(members[0].pubkey, a_pubkey, "the live member is A");

    node_a.shutdown().await;
    node_b.shutdown().await;
}
