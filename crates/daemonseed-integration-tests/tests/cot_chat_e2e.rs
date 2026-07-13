//! M11 — circle-of-trust chat round-trip end-to-end (ISC-10 / ISC-S20 / ISC-A-S2).
//!
//! Two circle members, each on their own connection to the relay, exchange a
//! chat message through the live `CircleOfTrust` relay using the real
//! client-side stack: `AppSession` (cli) for the tonic channel, the
//! `circle::message` AES-256-GCM envelope (core) for the payload, and the
//! `serve_application` relay (server) sharing one `CotRegistry` across both
//! connections. The duplex pairs stand in for the post-Authenticated TLS
//! streams; HTTP/2 carries the bidirectional `Subscribe` stream over each.
//!
//! This is the protocol-level proof the TUI chat screen is built on: the relay
//! forwards opaque ciphertext (it never holds `cot_key`), the recipient opens
//! it under the shared circle key, and a non-member cannot.

use std::sync::Arc;
use std::time::Duration;

use daemonseed_cli::session::AppSession;
use daemonseed_core::circle::key::{EXAMPLE_ENTROPY, derive_cot_key};
use daemonseed_core::circle::message::{open_message, seal_message};
use daemonseed_core::cot::asset_address;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_proto::v1 as wire;
use daemonseed_server::cot::CotRegistry;
use daemonseed_server::public_space::{PublicSpaceService, PublicSpaceState, serve_application};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Stable wire server-id both members namespace their rendezvous address by.
const SERVER_ID: &[u8] = b"relay-test#001122334455";

/// Spawn a single-connection relay over one duplex server half, sharing the
/// given registry so multiple connections meet at the same rendezvous.
fn spawn_relay(
    server_io: tokio::io::DuplexStream,
    registry: CotRegistry,
) -> tokio::task::JoinHandle<Result<(), tonic::transport::Error>> {
    tokio::spawn(serve_application(
        server_io,
        PublicSpaceService::new(Arc::new(PublicSpaceState::empty())),
        registry,
        // No federation peers in the CoT-chat relay scenario (M12 introducer arg).
        Arc::new(Vec::new()),
    ))
}

/// Name a rendezvous (first frame on a subscribe stream — empty payload, not
/// relayed) or carry a payload.
fn frame(addr: &[u8], payload: Vec<u8>) -> wire::CotFrame {
    wire::CotFrame {
        asset_address: addr.to_vec(),
        payload,
    }
}

/// Poll a condition on the shared runtime until true (deterministic ordering
/// without sleeping a fixed amount).
async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not met within ~2s");
}

#[tokio::test]
async fn two_members_chat_through_relay_with_sealed_envelope() {
    let _ = oxicrypt_module::initialize();

    // One shared relay registry; two independent connections to it.
    let registry = CotRegistry::new();
    let (a_client_io, a_server_io) = tokio::io::duplex(64 * 1024);
    let (b_client_io, b_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_a = spawn_relay(a_server_io, registry.clone());
    let _srv_b = spawn_relay(b_server_io, registry.clone());

    let sess_a = AppSession::open(a_client_io).await.expect("A session");
    let sess_b = AppSession::open(b_client_io).await.expect("B session");

    // Same circle phrase on both members → byte-identical cot_key → identical
    // rendezvous address. The address is keyed by the circle secret, so only a
    // member can compute it (the relay never can).
    let key_a = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
    let key_b = derive_cot_key(EXAMPLE_ENTROPY, &CNSA_2_0).unwrap();
    let addr = asset_address(&key_a, SERVER_ID).unwrap();
    assert_eq!(
        addr,
        asset_address(&key_b, SERVER_ID).unwrap(),
        "both members derive the same rendezvous address"
    );
    let addr_bytes = addr.as_bytes().to_vec();

    // B subscribes and names the asset (empty payload registers the rendezvous;
    // it is not relayed). Hold b_tx to keep B's presence open.
    let mut cot_b = sess_b.circle_of_trust();
    let (b_tx, b_rx) = mpsc::channel::<wire::CotFrame>(8);
    b_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let mut b_in = cot_b
        .subscribe(ReceiverStream::new(b_rx))
        .await
        .expect("B subscribes")
        .into_inner();

    // Block until the relay has registered B's subscription, so A's publish is
    // not a no-op against an empty asset (live-only relay).
    wait_until(|| registry.live_assets() >= 1).await;

    // A subscribes to the same asset, then seals and publishes a chat message.
    let mut cot_a = sess_a.circle_of_trust();
    let (a_tx, a_rx) = mpsc::channel::<wire::CotFrame>(8);
    a_tx.send(frame(&addr_bytes, Vec::new())).await.unwrap();
    let _a_in = cot_a
        .subscribe(ReceiverStream::new(a_rx))
        .await
        .expect("A subscribes")
        .into_inner();

    // Circle messages are now SIGNED (room↔circle convergence): A signs the
    // RoomMessage with its identity so authorship is verifiable.
    let signer =
        daemonseed_core::identity::keys::SignKeypair::from_ml_dsa_seed(&[7u8; 32]).unwrap();
    let handle = "river-otter#aabbccddeeff";
    let body = "meet at the usual place";
    let sealed = seal_message(&key_a, &signer, handle, body, 1_700_000_000_000).unwrap();
    a_tx.send(frame(&addr_bytes, sealed)).await.unwrap();

    // B receives the opaque frame the relay forwarded.
    let received = tokio::time::timeout(Duration::from_secs(5), b_in.message())
        .await
        .expect("a frame arrives within the timeout")
        .expect("response stream is healthy")
        .expect("a frame, not end-of-stream");

    // ISC-A-S2: the relay carried ciphertext, never the plaintext body.
    assert_ne!(
        received.payload,
        body.as_bytes(),
        "the relay must forward ciphertext, not the plaintext message"
    );
    assert_eq!(received.asset_address, addr_bytes, "routed by rendezvous");

    // ISC-10: B opens+verifies it under the shared circle key and recovers A's
    // signed message, including the provenance pubkey.
    let opened = open_message(&key_b, &received.payload).expect("member opens the message");
    assert_eq!(opened.body, body);
    assert_eq!(opened.sender_handle, handle);
    assert_eq!(opened.sender_pubkey, signer.public_key().to_vec());

    // A non-member (different phrase → different key) cannot open the frame —
    // the position the relay and any eavesdropper are structurally in.
    let outsider = derive_cot_key("a phrase no member ever agreed to", &CNSA_2_0).unwrap();
    assert!(
        open_message(&outsider, &received.payload).is_err(),
        "a non-member cannot decrypt the circle chat"
    );
}

#[test]
fn isc_c99_covered() {
    // ISC-C99: a circle chat message is self-signed for per-sender authorship
    // (the circle analog of ISC-S24 / ISC-C57), exercised end-to-end above by
    // `two_members_chat_through_relay_with_sealed_envelope`, which opens the
    // relayed message and asserts its `sender_pubkey` matches the signer. #150
    // registers the integration coverage the criterion had only at the unit
    // level (daemonseed_core::room_message::cannot_forge_authorship_as_another_member).
    let mut c = Coverage::empty();
    c.register(
        "ISC-C99",
        "two_members_chat_through_relay_with_sealed_envelope",
    );
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C99 registered (#150 circle-chat per-sender authorship)"
    );
}
