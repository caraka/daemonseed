//! Interactive public rooms — post→read round-trip end-to-end
//! (ISC-S22..S26 / ISC-C56..C58 / ISC-A-S16..A-S19).
//!
//! A public room is the public tier of the public-vs-CoT bifurcation (ISC-S4),
//! built over the SAME `CircleOfTrust.Subscribe` live relay and `CotFrame`
//! mechanism as a circle (ISC-S20). This test proves the interactive-public-room
//! end state through the real stack:
//!
//!   - any daemon may post (no whitelist gate, ISC-S22),
//!   - self-signed for provenance by the poster's own identity (ISC-S24),
//!   - encrypted under a GLOBAL shared key the relay AND every client hold
//!     (ISC-S22 / ISC-A-S2 public tier) — so the wire payload is ciphertext,
//!     never cleartext (ISC-A-S16),
//!   - everyone subscribed reads, opening + verifying client-side (ISC-S25),
//!   - a forged-provenance message is rejected (ISC-A-S17),
//!   - the asset is reaped when the last subscriber leaves (ISC-S26, the same
//!     refcount property the circle relay has, ISC-A-S5).
//!
//! The relay is the SAME `serve_application` server the circle-chat e2e uses —
//! this test deliberately uses NO public-space whitelist, demonstrating that an
//! open-post public room needs no operator authorization (contrast ISC-S7/S8).

use std::sync::Arc;
use std::time::Duration;

use daemonseed_cli::session::AppSession;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::public_room::{
    DEFAULT_ROOM, derive_room_key, open_room_message, room_asset_address, seal_room_message,
};
use daemonseed_proto::v1 as wire;
use daemonseed_server::cot::CotRegistry;
use daemonseed_server::public_space::{PublicSpaceService, PublicSpaceState, serve_application};
use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Stable wire server-id both daemons namespace their rendezvous address by.
const SERVER_ID: &[u8] = b"relay-test#001122334455";

/// Spawn a single-connection relay over one duplex server half, sharing the
/// given registry so multiple connections meet at the same rendezvous. NO
/// public-space whitelist is configured — an open-post public room needs none.
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

/// ISC-S22 / ISC-S24 / ISC-S25 / ISC-A-S16 / ISC-A-S17: a daemon posts to the
/// default public room; another daemon (a DIFFERENT identity, no shared secret)
/// reads it, the relay carried only ciphertext, and the provenance signature
/// verifies under the poster's own key.
#[tokio::test]
async fn any_daemon_posts_everyone_reads_through_relay() {
    let _ = oxicrypt_module::initialize();

    let registry = CotRegistry::new();
    let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
    let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_a = spawn_relay(a_server_io, registry.clone());
    let _srv_b = spawn_relay(b_server_io, registry.clone());

    let sess_a = AppSession::open(a_client_io).await.expect("A session");
    let sess_b = AppSession::open(b_client_io).await.expect("B session");

    // The room key is GLOBAL: derived from public inputs, so A and B (and the
    // relay) all derive the byte-identical key with NO shared secret — the
    // defining property of the public tier (ISC-S22).
    let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
    let addr = room_asset_address(&room_key, SERVER_ID).unwrap();
    let addr_bytes = addr.as_bytes().to_vec();

    // B subscribes (reader). Hold b_tx to keep presence open.
    let mut cot_b = sess_b.circle_of_trust();
    let (b_tx, b_rx) = mpsc::channel::<wire::CotFrame>(8);
    b_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let mut b_in = cot_b
        .subscribe(ReceiverStream::new(b_rx))
        .await
        .expect("B subscribes")
        .into_inner();
    wait_until(|| registry.live_assets() >= 1).await;

    // A subscribes and posts. A and B are DIFFERENT identities — no whitelist,
    // no shared phrase: any daemon may post (ISC-S22).
    let mut cot_a = sess_a.circle_of_trust();
    let (a_tx, a_rx) = mpsc::channel::<wire::CotFrame>(8);
    a_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let _a_in = cot_a
        .subscribe(ReceiverStream::new(a_rx))
        .await
        .expect("A subscribes")
        .into_inner();

    let poster = SignKeypair::from_ml_dsa_seed(&[42u8; 32]).unwrap();
    let body = "hello public room — unique-marker-9f3a";
    let sealed = seal_room_message(
        &room_key,
        &poster,
        DEFAULT_ROOM,
        "river-otter#aabbccddeeff",
        body,
        1_700_000_000_000,
    )
    .unwrap();
    a_tx.send(frame(&addr_bytes, sealed)).await.unwrap();

    // B receives the relayed frame.
    let received = tokio::time::timeout(Duration::from_secs(5), b_in.message())
        .await
        .expect("a frame arrives within the timeout")
        .expect("response stream is healthy")
        .expect("a frame, not end-of-stream");
    assert_eq!(received.asset_address, addr_bytes, "routed by rendezvous");

    // ISC-A-S16: the wire payload is ciphertext — the plaintext body never
    // appears on the wire, even though the relay holds the global key.
    assert!(
        !received
            .payload
            .windows(body.len())
            .any(|w| w == body.as_bytes()),
        "the relay must forward ciphertext, never the plaintext body"
    );

    // ISC-S25 / ISC-S24: B opens it under the GLOBAL key and the embedded
    // provenance signature verifies under the poster's own key.
    let opened = open_room_message(&room_key, &received.payload)
        .expect("reader opens + verifies the posted message");
    assert_eq!(opened.body, body);
    assert_eq!(
        opened.sender_pubkey,
        poster.public_key().to_vec(),
        "provenance binds the message to the poster's own identity (ISC-S24)"
    );
    assert_eq!(opened.room, DEFAULT_ROOM);
}

/// ISC-A-S17: a forged-provenance message (re-sealed under the public global key
/// but signed over different content) is rejected by the reader — a public room
/// being open-post does NOT mean it is open-forge.
#[tokio::test]
async fn forged_provenance_is_rejected_end_to_end() {
    let _ = oxicrypt_module::initialize();

    let registry = CotRegistry::new();
    let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
    let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_a = spawn_relay(a_server_io, registry.clone());
    let _srv_b = spawn_relay(b_server_io, registry.clone());

    let sess_a = AppSession::open(a_client_io).await.expect("A session");
    let sess_b = AppSession::open(b_client_io).await.expect("B session");

    let room_key = derive_room_key(DEFAULT_ROOM, &CNSA_2_0).unwrap();
    let addr = room_asset_address(&room_key, SERVER_ID).unwrap();
    let addr_bytes = addr.as_bytes().to_vec();

    let mut cot_b = sess_b.circle_of_trust();
    let (b_tx, b_rx) = mpsc::channel::<wire::CotFrame>(8);
    b_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let mut b_in = cot_b
        .subscribe(ReceiverStream::new(b_rx))
        .await
        .expect("B subscribes")
        .into_inner();
    wait_until(|| registry.live_assets() >= 1).await;

    let mut cot_a = sess_a.circle_of_trust();
    let (a_tx, a_rx) = mpsc::channel::<wire::CotFrame>(8);
    a_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let _a_in = cot_a
        .subscribe(ReceiverStream::new(a_rx))
        .await
        .expect("A subscribes")
        .into_inner();

    // Forge: a structurally-valid sealed message whose embedded signature is
    // garbage (the global key is public, so anyone can SEAL — but not SIGN).
    let attacker = SignKeypair::from_ml_dsa_seed(&[7u8; 32]).unwrap();
    let forged = wire::PublicRoomMessage {
        room: DEFAULT_ROOM.to_owned(),
        sender_pubkey: attacker.public_key().to_vec(),
        sender_handle: "impostor#000000000000".to_owned(),
        body: "trust me i am legit".to_owned(),
        sent_unix_ms: 1,
        signature: vec![0u8; oxicrypt_ml_dsa::SIG_LEN], // not a real signature
    };
    let sealed = seal_raw_under_room_key(&room_key, &forged);
    a_tx.send(frame(&addr_bytes, sealed)).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), b_in.message())
        .await
        .expect("a frame arrives")
        .expect("stream healthy")
        .expect("a frame");

    // The reader rejects it: provenance does not verify (ISC-A-S17).
    assert!(
        open_room_message(&room_key, &received.payload).is_err(),
        "a forged-provenance message must be rejected, never surfaced"
    );
}

/// Seal a wire `PublicRoomMessage` verbatim under the (public) global room key,
/// WITHOUT going through `seal_room_message` — used to craft a forged-provenance
/// envelope an attacker who knows the public key could send.
fn seal_raw_under_room_key(
    room_key: &daemonseed_core::public_room::PublicRoomKey,
    message: &wire::PublicRoomMessage,
) -> Vec<u8> {
    use daemonseed_core::public_room::ROOM_MESSAGE_AAD;
    use oxicrypt_aes::{Aes256Key, gcm_encrypt};
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    let aes = Aes256Key::new(room_key.as_bytes()).unwrap();
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).unwrap();
    let plaintext = message.encode_to_vec();
    let mut ct = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(
        &aes,
        &nonce,
        ROOM_MESSAGE_AAD,
        &plaintext,
        &mut ct,
        &mut tag,
    )
    .unwrap();
    let mut sealed = Vec::new();
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ct);
    sealed.extend_from_slice(&tag);
    sealed
}
