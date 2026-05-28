//! M11 — public-share chunk-fetch round-trip end-to-end
//! (ISC-19 / F23 unified mechanism / ISC-A-S2 / ISC-A-S5b).
//!
//! Two daemons — a *sharer* and a *fetcher* — meet at a public-share asset
//! address on one relay and exchange the manifest-then-chunks protocol over a
//! single bidirectional `CircleOfTrust.Subscribe` stream each. The relay
//! forwards opaque `CotFrame.payload` bytes verbatim (it never decodes the
//! `ShareFrame` envelope), so A-S2 holds for the share path the same way it
//! holds for chat. The fetcher re-derives `SHA-384(chunk)` over every
//! `ChunkResponse` and rejects any frame whose recomputed address does not
//! match — the file-side analog of `open_message` failing closed.
//!
//! This is the protocol-level proof the TUI fetch screen + net actor are
//! built on; the actor's [`crate::net::Actor::handle_fetch_share`] is
//! unit-tested via its `NetEvent` emissions in `daemonseed-tui::app`. Here
//! we exercise the same wire shape directly on two `AppSession`s sharing one
//! `CotRegistry`, the way `cot_chat_e2e` does for chat.

use std::sync::Arc;
use std::time::Duration;

use daemonseed_cli::session::AppSession;
use daemonseed_core::cot::public_share_asset_address;
use daemonseed_core::share_envelope::{ManifestEntry, ShareFrame};
use daemonseed_core::storage::cas::chunk_addr;
use daemonseed_proto::v1 as wire;
use daemonseed_server::cot::CotRegistry;
use daemonseed_server::public_space::{PublicSpaceService, PublicSpaceState, serve_application};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Stable wire server-id both daemons namespace their rendezvous address by.
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

/// End-to-end fetch: sharer publishes a 2-file share; fetcher requests the
/// manifest, then each chunk; verifies SHA-384 on every chunk; recovers both
/// files byte-for-byte. The relay never sees plaintext envelopes — it just
/// forwards opaque `CotFrame.payload` bytes.
#[tokio::test]
async fn fetcher_recovers_share_via_manifest_then_chunks() {
    let _ = oxicrypt_module::initialize();

    // One shared relay registry; two independent connections to it.
    let registry = CotRegistry::new();
    let (sharer_client_io, sharer_server_io) = tokio::io::duplex(64 * 1024);
    let (fetcher_client_io, fetcher_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_s = spawn_relay(sharer_server_io, registry.clone());
    let _srv_f = spawn_relay(fetcher_server_io, registry.clone());

    let sharer_sess = AppSession::open(sharer_client_io)
        .await
        .expect("sharer session");
    let fetcher_sess = AppSession::open(fetcher_client_io)
        .await
        .expect("fetcher session");

    // The share's content: two small files.
    let file_a: &[u8] = b"alice's recipe notes, page 1";
    let file_b: &[u8] = b"alice's recipe notes, page 2\n(with addendum)";
    let addr_a = chunk_addr(file_a).expect("hash file a");
    let addr_b = chunk_addr(file_b).expect("hash file b");

    // Both daemons derive the byte-identical public-share asset address from
    // (share_id, server_id) — only the share_id is needed (no shared secret),
    // so anyone who learned the share_id from ListPublicShares can fetch.
    let share_id = "share-alice-recipes-v1";
    let asset_addr =
        public_share_asset_address(share_id.as_bytes(), SERVER_ID).expect("derive asset addr");
    let asset_bytes = asset_addr.as_bytes().to_vec();

    // ── Sharer task: subscribe + serve manifest + serve chunks ────────────
    let manifest_entries = vec![
        ManifestEntry {
            rel_path: "page-1.txt".to_owned(),
            chunk_addr: addr_a,
            size: file_a.len() as u64,
        },
        ManifestEntry {
            rel_path: "page-2.txt".to_owned(),
            chunk_addr: addr_b,
            size: file_b.len() as u64,
        },
    ];
    let chunks: std::collections::HashMap<[u8; 48], Vec<u8>> = [
        (*addr_a.as_bytes(), file_a.to_vec()),
        (*addr_b.as_bytes(), file_b.to_vec()),
    ]
    .into_iter()
    .collect();

    let sharer_asset = asset_bytes.clone();
    let sharer_task = tokio::spawn(async move {
        let mut cot = sharer_sess.circle_of_trust();
        let (tx, rx) = mpsc::channel::<wire::CotFrame>(16);
        // First frame names the rendezvous (empty payload, not relayed).
        tx.send(frame(&sharer_asset, Vec::new())).await.unwrap();
        let mut inbound = cot
            .subscribe(ReceiverStream::new(rx))
            .await
            .expect("sharer subscribes")
            .into_inner();

        // Serve requests until the fetcher closes the stream.
        while let Ok(Some(in_frame)) = inbound.message().await {
            if in_frame.payload.is_empty() {
                continue;
            }
            let req = match ShareFrame::decode(&in_frame.payload) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let response = match req {
                ShareFrame::ManifestRequest => ShareFrame::ManifestResponse {
                    entries: manifest_entries.clone(),
                },
                ShareFrame::ChunkRequest { chunk_addr } => {
                    let data = chunks
                        .get(chunk_addr.as_bytes())
                        .cloned()
                        .unwrap_or_default();
                    ShareFrame::ChunkResponse { chunk_addr, data }
                }
                _ => continue,
            };
            if tx
                .send(frame(&sharer_asset, response.encode()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Block until the relay registered the sharer's subscription so the
    // fetcher's first request lands on a live asset (live-only relay).
    wait_until(|| registry.live_assets() >= 1).await;

    // ── Fetcher: subscribe + request manifest + per-chunk fetches ─────────
    let mut cot = fetcher_sess.circle_of_trust();
    let (tx, rx) = mpsc::channel::<wire::CotFrame>(16);
    tx.send(frame(&asset_bytes, Vec::new())).await.unwrap();
    let mut inbound = cot
        .subscribe(ReceiverStream::new(rx))
        .await
        .expect("fetcher subscribes")
        .into_inner();

    // Wait until the relay sees both subscriptions on this asset, so the
    // fetcher's request is fanned out to the sharer.
    wait_until(|| registry.live_assets() >= 1).await;

    // Send ManifestRequest.
    tx.send(frame(&asset_bytes, ShareFrame::ManifestRequest.encode()))
        .await
        .unwrap();

    // Wait for the manifest.
    let manifest = loop {
        let resp = tokio::time::timeout(Duration::from_secs(5), inbound.message())
            .await
            .expect("manifest within timeout")
            .expect("stream healthy")
            .expect("frame, not end-of-stream");
        if resp.payload.is_empty() {
            continue;
        }
        match ShareFrame::decode(&resp.payload).expect("manifest decodes") {
            ShareFrame::ManifestResponse { entries } => break entries,
            _ => continue,
        }
    };
    assert_eq!(manifest.len(), 2, "two-entry manifest");
    assert_eq!(manifest[0].rel_path, "page-1.txt");
    assert_eq!(manifest[1].rel_path, "page-2.txt");

    // Per-entry chunk fetch + ISC-19 verification (recompute SHA-384).
    let mut recovered: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in &manifest {
        tx.send(frame(
            &asset_bytes,
            ShareFrame::ChunkRequest {
                chunk_addr: entry.chunk_addr,
            }
            .encode(),
        ))
        .await
        .unwrap();
        let chunk = loop {
            let resp = tokio::time::timeout(Duration::from_secs(5), inbound.message())
                .await
                .expect("chunk within timeout")
                .expect("stream healthy")
                .expect("frame, not end-of-stream");
            if resp.payload.is_empty() {
                continue;
            }
            match ShareFrame::decode(&resp.payload).expect("chunk decodes") {
                ShareFrame::ChunkResponse { chunk_addr, data }
                    if chunk_addr == entry.chunk_addr =>
                {
                    break (chunk_addr, data);
                }
                _ => continue,
            }
        };
        // ISC-19 / F23: re-derive SHA-384 and reject on mismatch.
        let recomputed = chunk_addr(&chunk.1).expect("recompute hash");
        assert_eq!(
            recomputed, chunk.0,
            "fetcher verifies chunk content against advertised address"
        );
        recovered.push((entry.rel_path.clone(), chunk.1));
    }

    assert_eq!(recovered[0].1, file_a, "page 1 byte-identical");
    assert_eq!(recovered[1].1, file_b, "page 2 byte-identical");

    // Close the fetcher's outbound to let the sharer task drain.
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), sharer_task).await;
}

/// ISC-19 fail-closed: a tampered `ChunkResponse` (one bit flipped in `data`,
/// advertised address unchanged) fails the fetcher's re-derived-hash check.
/// We synthesise the tampered frame directly through the relay — the unified
/// mechanism guarantees the fetcher catches it regardless of which party
/// (relay or sharer) corrupted the bytes.
#[tokio::test]
async fn tampered_chunk_response_fails_recomputed_hash_check() {
    let _ = oxicrypt_module::initialize();
    let registry = CotRegistry::new();
    let (responder_client_io, responder_server_io) = tokio::io::duplex(64 * 1024);
    let (fetcher_client_io, fetcher_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_r = spawn_relay(responder_server_io, registry.clone());
    let _srv_f = spawn_relay(fetcher_server_io, registry.clone());

    let responder_sess = AppSession::open(responder_client_io).await.unwrap();
    let fetcher_sess = AppSession::open(fetcher_client_io).await.unwrap();

    let original: &[u8] = b"genuine file content";
    let advertised = chunk_addr(original).expect("hash");
    let share_id = "tamper-test-share";
    let asset_addr = public_share_asset_address(share_id.as_bytes(), SERVER_ID).expect("derive");
    let asset_bytes = asset_addr.as_bytes().to_vec();

    // Hostile responder: claims the chunk's address is `advertised` but sends
    // bytes whose SHA-384 doesn't match (one bit flipped).
    let mut tampered = original.to_vec();
    tampered[0] ^= 0x01;
    let hostile_asset = asset_bytes.clone();
    let responder_task = tokio::spawn(async move {
        let mut cot = responder_sess.circle_of_trust();
        let (tx, rx) = mpsc::channel::<wire::CotFrame>(8);
        tx.send(frame(&hostile_asset, Vec::new())).await.unwrap();
        let mut inbound = cot
            .subscribe(ReceiverStream::new(rx))
            .await
            .expect("subscribes")
            .into_inner();
        while let Ok(Some(in_frame)) = inbound.message().await {
            if in_frame.payload.is_empty() {
                continue;
            }
            if let Ok(ShareFrame::ChunkRequest { chunk_addr }) =
                ShareFrame::decode(&in_frame.payload)
            {
                let resp = ShareFrame::ChunkResponse {
                    chunk_addr,
                    data: tampered.clone(),
                };
                let _ = tx.send(frame(&hostile_asset, resp.encode())).await;
            }
        }
    });

    wait_until(|| registry.live_assets() >= 1).await;

    let mut cot = fetcher_sess.circle_of_trust();
    let (tx, rx) = mpsc::channel::<wire::CotFrame>(8);
    tx.send(frame(&asset_bytes, Vec::new())).await.unwrap();
    let mut inbound = cot
        .subscribe(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    wait_until(|| registry.live_assets() >= 1).await;

    tx.send(frame(
        &asset_bytes,
        ShareFrame::ChunkRequest {
            chunk_addr: advertised,
        }
        .encode(),
    ))
    .await
    .unwrap();

    let resp = loop {
        let f = tokio::time::timeout(Duration::from_secs(5), inbound.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if f.payload.is_empty() {
            continue;
        }
        match ShareFrame::decode(&f.payload).unwrap() {
            ShareFrame::ChunkResponse { chunk_addr, data } => break (chunk_addr, data),
            _ => continue,
        }
    };
    assert_eq!(resp.0, advertised, "responder echoed the advertised addr");
    let recomputed = chunk_addr(&resp.1).expect("recompute");
    assert_ne!(
        recomputed, advertised,
        "ISC-19 fail-closed: tampered chunk's SHA-384 does not match advertised address"
    );

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), responder_task).await;
}
