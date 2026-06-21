//! In-band share discovery — announce / withdraw / roll-call round-trip
//! end-to-end (unified share model; `docs/design/unified-share-model.md`).
//!
//! In the unified share model the relay holds no share directory (ISC-A-S2): a
//! sharer publishes by posting a sealed, self-signed [`wire::ShareAnnouncement`]
//! into the lobby — the SAME `CircleOfTrust.Subscribe` stream chat uses — and a
//! discovering client folds each verified announcement into a
//! [`ShareCatalog`]. A withdraw is a matching announcement with `withdraw =
//! true`; a [`wire::ShareRollCall`] is the late-join request that live sharers
//! answer by re-announcing. This test drives all three through the real relay
//! on two `AppSession`s sharing one `CotRegistry`, exactly as `public_room_e2e`
//! does for chat:
//!
//!   - client A posts an announcement on the lobby asset; client B receives the
//!     relayed frame, opens + verifies it ([`open_announcement`]), and
//!     [`ShareCatalog::apply`] yields it with the right `share_id` / `name`;
//!   - the relay carried only ciphertext (the announcement is sealed under the
//!     public room key, ISC-A-S16 for the share tier);
//!   - A posts a withdraw; B's catalog drops the share;
//!   - A posts a roll-call; B receives + opens it ([`open_rollcall`]) — the
//!     request half a live sharer answers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use daemonseed_cli::session::AppSession;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::public_room::{DEFAULT_ROOM, derive_room_key, room_asset_address};
use daemonseed_core::share_announce::{
    AnnouncementFields, open_announcement, seal_public_announcement,
};
use daemonseed_core::share_catalog::{CatalogChange, ShareCatalog};
use daemonseed_core::share_rollcall::{RollCallFields, open_rollcall, seal_public_rollcall};
use daemonseed_proto::v1 as wire;
use daemonseed_server::cot::CotRegistry;
use daemonseed_server::public_space::{PublicSpaceService, PublicSpaceState, serve_application};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Stable wire server-id both daemons namespace their rendezvous address by.
const SERVER_ID: &[u8] = b"relay-test#001122334455";

/// Spawn a single-connection relay over one duplex server half, sharing the
/// given registry so multiple connections meet at the same rendezvous. NO
/// public-space whitelist is configured — in-band discovery needs none.
fn spawn_relay(
    server_io: tokio::io::DuplexStream,
    registry: CotRegistry,
) -> tokio::task::JoinHandle<Result<(), tonic::transport::Error>> {
    tokio::spawn(serve_application(
        server_io,
        PublicSpaceService::new(Arc::new(PublicSpaceState::empty())),
        registry,
        Arc::new(Vec::new()),
    ))
}

fn frame(addr: &[u8], payload: Vec<u8>) -> wire::CotFrame {
    wire::CotFrame {
        asset_address: addr.to_vec(),
        payload,
    }
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not met within ~2s");
}

/// Receive the next relayed frame within a bounded timeout.
async fn next_frame(inbound: &mut tonic::Streaming<wire::CotFrame>) -> wire::CotFrame {
    tokio::time::timeout(Duration::from_secs(5), inbound.message())
        .await
        .expect("a frame arrives within the timeout")
        .expect("response stream is healthy")
        .expect("a frame, not end-of-stream")
}

/// Unified share model: a sharer announces in-band over the lobby, a discovering
/// client folds the verified announcement into its catalog, a withdraw drops it,
/// and a roll-call (the late-join request) round-trips — all relay-blind.
#[tokio::test]
async fn announce_withdraw_rollcall_round_trip_through_relay() {
    let _ = oxicrypt_module::initialize();

    let registry = CotRegistry::new();
    let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
    let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_a = spawn_relay(a_server_io, registry.clone());
    let _srv_b = spawn_relay(b_server_io, registry.clone());

    let sess_a = AppSession::open(a_client_io).await.expect("A session");
    let sess_b = AppSession::open(b_client_io).await.expect("B session");

    // The lobby key is GLOBAL: A, B, and the relay all derive the byte-identical
    // key from public inputs (ISC-S22) — no shared secret. Announcements seal
    // under it; only the AAD distinguishes an announcement from chat.
    let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
    let addr = room_asset_address(&room_key, SERVER_ID).unwrap();
    let addr_bytes = addr.as_bytes().to_vec();

    // B subscribes (the discovering client). Hold b_tx to keep presence open.
    let mut cot_b = sess_b.circle_of_trust();
    let (b_tx, b_rx) = mpsc::channel::<wire::CotFrame>(8);
    b_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let mut b_in = cot_b
        .subscribe(ReceiverStream::new(b_rx))
        .await
        .expect("B subscribes")
        .into_inner();
    wait_until(|| registry.live_assets() >= 1).await;

    // A subscribes and announces. A and B are DIFFERENT identities — discovery
    // needs no shared secret beyond the public lobby key.
    let mut cot_a = sess_a.circle_of_trust();
    let (a_tx, a_rx) = mpsc::channel::<wire::CotFrame>(8);
    a_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let _a_in = cot_a
        .subscribe(ReceiverStream::new(a_rx))
        .await
        .expect("A subscribes")
        .into_inner();

    let sharer = SignKeypair::from_ml_dsa_seed(&[42u8; 32]).unwrap();
    let share_id = "0123456789abcdef0123456789abcdef";
    let announce = seal_public_announcement(
        &room_key,
        &sharer,
        &AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "river-otter#aabbccddeeff",
            share_id,
            name: "trip photos",
            rating: "PG",
            withdraw: false,
            sent_unix_ms: 1_700_000_000_000,
        },
    )
    .unwrap();
    a_tx.send(frame(&addr_bytes, announce)).await.unwrap();

    // B receives the relayed announcement.
    let received = next_frame(&mut b_in).await;
    assert_eq!(received.asset_address, addr_bytes, "routed by rendezvous");

    // ISC-A-S16 (share tier): the wire payload is ciphertext — the share name
    // never appears on the wire even though the relay holds the global key.
    assert!(
        !received
            .payload
            .windows("trip photos".len())
            .any(|w| w == b"trip photos"),
        "the relay must forward ciphertext, never the cleartext share name"
    );

    // B opens + verifies the announcement, then folds it into the catalog: a
    // previously-unknown share is Added with the right id/name.
    let mut catalog = ShareCatalog::new(Duration::from_secs(90));
    let opened = open_announcement(&room_key, &received.payload)
        .expect("B opens + verifies the announcement");
    assert_eq!(opened.share_id, share_id);
    assert_eq!(opened.name, "trip photos");
    assert!(!opened.withdraw);
    assert_eq!(
        opened.sender_pubkey,
        sharer.public_key().to_vec(),
        "provenance binds the announcement to the sharer's own identity"
    );
    assert_eq!(
        catalog.apply(&opened, Instant::now()),
        CatalogChange::Added,
        "a previously-unknown share is added"
    );
    assert_eq!(catalog.len(), 1);
    let row = &catalog.entries()[0];
    assert_eq!(row.share_id, share_id);
    assert_eq!(row.name, "trip photos");

    // A withdraws the share — a matching announcement with `withdraw = true` and
    // a fresher timestamp. B receives it, opens it, and the catalog Removes it.
    let withdraw = seal_public_announcement(
        &room_key,
        &sharer,
        &AnnouncementFields {
            room: DEFAULT_ROOM,
            sender_handle: "river-otter#aabbccddeeff",
            share_id,
            name: "trip photos",
            rating: "PG",
            withdraw: true,
            sent_unix_ms: 1_700_000_001_000,
        },
    )
    .unwrap();
    a_tx.send(frame(&addr_bytes, withdraw)).await.unwrap();

    let received = next_frame(&mut b_in).await;
    let opened =
        open_announcement(&room_key, &received.payload).expect("B opens + verifies the withdraw");
    assert!(opened.withdraw, "the withdraw flag survives the round-trip");
    assert_eq!(
        catalog.apply(&opened, Instant::now()),
        CatalogChange::Removed,
        "the withdraw drops the share from the catalog"
    );
    assert!(
        catalog.is_empty(),
        "the catalog is empty after the withdraw"
    );

    // Roll-call (the late-join request): A posts a sealed roll-call; B receives
    // + opens it. A live sharer answers a roll-call by re-announcing — here we
    // assert the request half round-trips, opens, and verifies.
    let requester = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).unwrap();
    let rollcall = seal_public_rollcall(
        &room_key,
        &requester,
        &RollCallFields {
            room: DEFAULT_ROOM,
            requester_handle: "lone-pine#001122334455",
            sent_unix_ms: 1_700_000_002_000,
        },
    )
    .unwrap();
    a_tx.send(frame(&addr_bytes, rollcall)).await.unwrap();

    let received = next_frame(&mut b_in).await;
    // A roll-call is NOT an announcement: the distinct AAD makes opening it as an
    // announcement fail closed (only the matching kind opens).
    assert!(
        open_announcement(&room_key, &received.payload).is_err(),
        "a roll-call must not open as an announcement (distinct AAD)"
    );
    let opened_rc =
        open_rollcall(&room_key, &received.payload).expect("B opens + verifies the roll-call");
    assert_eq!(
        opened_rc.requester_pubkey,
        requester.public_key().to_vec(),
        "the roll-call carries the requester's verified provenance"
    );
}
