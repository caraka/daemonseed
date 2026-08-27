//! Integration test (Phase 3 — share content): a public share's CONTENT crosses
//! real Veilid `app_call`s. The sharer serves owner-on-demand over a private
//! route (its blob hides its node/IP); the fetcher reassembles the fragmented,
//! room-key-sealed manifest + chunk and SHA-384-verifies the chunk against its
//! content address (ISC-S28 / ISC-A-S20). An outsider room key cannot open the
//! served content. This is the Phase-3 content-transfer oracle, complementing
//! `two_node_room.rs` (discovery): together they prove a fetcher can find a
//! share and pull its bytes with no relay.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! Where the network path blocks a public attach, the wait returns `NotReady`
//! after the full timeout. This crate is `[workspace] exclude`d, so `-p` won't resolve
//! it from the repo root — build from the crate's own directory:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_share -- --ignored --nocapture
//!
//! It drives the productized path end-to-end through the `VeilidNetHandle` API,
//! reusing the REAL daemonseed share stack (`hash_share` + `DiskShareContent` —
//! the same disk-backed source both front-ends publish through /
//! `seal_public_share_frame` / `open_share_frame` / the SHA-384 content
//! addressing) — no crypto is reimplemented.

use std::sync::Arc;
use std::time::Duration;

use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::derive_room_key;
use daemonseed_core::share_announce::mint_share_id;
use daemonseed_core::share_serve::{hash_share, DiskShareContent};
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig};

fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_share{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn public_share_content_crosses_app_call() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-share-it");
    let _ = std::fs::remove_dir_all(&base);

    // A small share whose single chunk's SEALED ChunkResponse spans >1 fragment,
    // so the live fetch exercises real multi-fragment reassembly over the wire.
    let share_dir = base.join("share");
    std::fs::create_dir_all(&share_dir).unwrap();
    let payload = vec![0x5Au8; 70_000];
    std::fs::write(share_dir.join("notes.bin"), &payload).unwrap();
    // Disk-backed, matching what a real client serves (#246) — the RAM source is
    // no longer on any publish path, so an end-to-end oracle built on it would
    // exercise a source nothing ships.
    let manifest = hash_share(
        &share_dir,
        &std::sync::atomic::AtomicBool::new(false),
        &mut |_, _| {},
    )
    .unwrap();
    let chunk0 = manifest.entries[0].chunks[0];
    let content = Arc::new(DiskShareContent::new(share_dir.clone(), manifest));

    // Public share: server-readable under the public room ("lobby") key.
    let room_key = derive_room_key("lobby", &CNSA_2_0).expect("room key");
    let rk = *room_key.as_bytes();
    let share_id = mint_share_id();

    let (sharer, _rx_s) = VeilidNet::start(node_config(":5164", &base.join("A")))
        .await
        .expect("start sharer");
    let (fetcher, _rx_f) = VeilidNet::start(node_config(":5165", &base.join("B")))
        .await
        .expect("start fetcher");

    sharer
        .attach_and_wait(180)
        .await
        .expect("sharer public-internet-ready");
    fetcher
        .attach_and_wait(180)
        .await
        .expect("fetcher public-internet-ready");

    sharer
        .serve_share(share_id.clone(), content.clone(), rk)
        .await
        .expect("register the share to serve");

    // The sharer publishes a private inbound route; the fetcher imports the
    // opaque blob and addresses its app_calls to it (anti-dox: the fetcher never
    // learns the sharer's node id/IP). The route may report "try again" until it
    // builds — retry.
    let blob = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            match sharer.new_inbound_route().await {
                Ok(b) => break b,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => panic!("sharer route never built within 120s: {e}"),
            }
        }
    };
    let route = fetcher.import_route(blob.blob).await.expect("import route");

    // Routes take a moment to become usable; retry the manifest fetch until it
    // lands. The manifest names the share's one file.
    let manifest = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            match fetcher.fetch_manifest(route.clone(), &share_id, rk).await {
                Ok(m) => break m,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => panic!("manifest never fetched within 120s: {e}"),
            }
        }
    };
    assert_eq!(manifest.len(), 1, "one file in the share");
    assert_eq!(manifest[0].rel_path, "notes.bin");

    // Fetch + reassemble + SHA-384-verify the chunk; the recovered bytes equal
    // the served file exactly.
    let budget = Arc::new(daemonseed_veilid_net::route_budget::RouteBudget::new());
    let lease = budget.lease(
        route.clone(),
        daemonseed_veilid_net::route_budget::SharerKey(vec![1u8]),
    );
    let (data, _lat) = fetcher
        .fetch_chunk_budgeted(route.clone(), &share_id, chunk0, rk, &lease)
        .await
        .expect("fetch + verify the chunk");
    assert_eq!(
        data, payload,
        "fetched chunk matches the served file (SHA-384-verified end to end)"
    );

    // An outsider watching a different room derives a different room key and
    // cannot open the served content (public-tier server-readability is scoped
    // to holders of THIS room's key).
    let outsider = *derive_room_key("a-room-nobody-watches", &CNSA_2_0)
        .unwrap()
        .as_bytes();
    assert!(
        fetcher
            .fetch_manifest(route.clone(), &share_id, outsider)
            .await
            .is_err(),
        "an outsider room key must fail to open the manifest"
    );

    sharer
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
    fetcher
        .shutdown(daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET)
        .await;
}
