//! alpha2 item B — share content download, exercising the REAL serve path
//! (ISC-S27 / ISC-S28 / ISC-S29 / ISC-A-S20 / ISC-A-S21).
//!
//! Unlike `share_fetch_e2e` — which inlines the sharer's manifest/chunk logic
//! — this test drives the actual reusable serve path that `cli publish --path`
//! runs: [`daemonseed_core::share_serve::ShareContent`] (directory index +
//! content-addressed store + the pure `answer` step) wrapped by
//! [`daemonseed_cli::session::AppSession::serve_share`] (the subscribe-stream
//! serve loop). A fetcher meets it at the `(share_id, server_id)` fetch-asset,
//! requests the manifest then each chunk, SHA-384-verifies every chunk, and
//! recovers both files byte-for-byte.
//!
//! The serve↔consumer asset derivation agreement is structural: both sides call
//! [`daemonseed_core::cot::public_share_asset_address`] with the same inputs
//! (the opaque hex `share_id`, the `server_id` string). This test passes the
//! identical pair to both halves, so a fetch that finds the manifest *is* the
//! agreement proof — a mismatch would land on a dead asset and time out.

use std::sync::Arc;
use std::time::Duration;

use daemonseed_cli::session::AppSession;
use daemonseed_core::cot::public_share_asset_address;
use daemonseed_core::share_envelope::ShareFrame;
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::chunk_addr;
use daemonseed_proto::v1 as wire;
use daemonseed_server::cot::CotRegistry;
use daemonseed_server::public_space::{PublicSpaceService, PublicSpaceState, serve_application};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// A realistic opaque CSPRNG-style share id (32 lowercase hex chars, ISC-S21).
const SHARE_ID: &str = "9f3c1a77b2e04d6680aa1c2d3e4f5061";
/// The connected relay's server-id string — the same string `cli publish` and
/// the consumer pass into the asset derivation.
const SERVER_ID: &str = "relay-test#001122334455";

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

/// Write a two-file share directory and return its TempDir handle.
fn make_share_dir() -> (tempfile::TempDir, &'static [u8], &'static [u8]) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let file_a: &[u8] = b"alice's recipe notes, page 1";
    let file_b: &[u8] = b"alice's recipe notes, page 2\n(with addendum)";
    std::fs::write(dir.path().join("page-1.txt"), file_a).unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("page-2.txt"), file_b).unwrap();
    (dir, file_a, file_b)
}

/// ISC-S27 / ISC-S28 / ISC-S29 — end-to-end over the REAL serve path: a sharer
/// indexes a directory and serves it via `AppSession::serve_share`; a fetcher
/// recovers both files byte-for-byte, SHA-384-verifying every chunk.
#[tokio::test]
async fn fetcher_recovers_share_via_real_serve_path() {
    let _ = oxicrypt_module::initialize();

    let registry = CotRegistry::new();
    let (sharer_client_io, sharer_server_io) = tokio::io::duplex(64 * 1024);
    let (fetcher_client_io, fetcher_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_s = spawn_relay(sharer_server_io, registry.clone());
    let _srv_f = spawn_relay(fetcher_server_io, registry.clone());

    let sharer_sess = AppSession::open(sharer_client_io).await.expect("sharer");
    let fetcher_sess = AppSession::open(fetcher_client_io).await.expect("fetcher");

    let (dir, file_a, file_b) = make_share_dir();

    // ── Sharer: index the directory, run the REAL serve loop. ─────────────
    let content = ShareContent::index_dir(dir.path()).expect("index share dir");
    assert_eq!(content.file_count(), 2, "two files indexed");
    let sharer_task = tokio::spawn(async move {
        // Held until the fetcher drops the asset; returns Ok on graceful end.
        let _ = sharer_sess.serve_share(SERVER_ID, SHARE_ID, &content).await;
        // Keep `dir` alive for the lifetime of the serve loop.
        drop(dir);
    });

    // Block until the relay has the sharer's subscription live.
    wait_until(|| registry.live_assets() >= 1).await;

    // ── Fetcher: derive the SAME asset, request manifest then chunks. ─────
    let asset_addr =
        public_share_asset_address(SHARE_ID.as_bytes(), SERVER_ID.as_bytes()).expect("derive");
    let asset_bytes = asset_addr.as_bytes().to_vec();

    let mut cot = fetcher_sess.circle_of_trust();
    let (tx, rx) = mpsc::channel::<wire::CotFrame>(16);
    tx.send(frame(&asset_bytes, Vec::new())).await.unwrap();
    let mut inbound = cot
        .subscribe(ReceiverStream::new(rx))
        .await
        .expect("fetcher subscribes")
        .into_inner();

    tx.send(frame(&asset_bytes, ShareFrame::ManifestRequest.encode()))
        .await
        .unwrap();

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
    assert_eq!(
        manifest.len(),
        2,
        "two-entry manifest from the real serve path"
    );
    // Deterministic sort: page-1.txt before sub/page-2.txt.
    assert_eq!(manifest[0].rel_path, "page-1.txt");
    assert_eq!(manifest[1].rel_path, "sub/page-2.txt");

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
        // ISC-S28 / ISC-19: re-derive SHA-384 and reject on mismatch.
        let recomputed = chunk_addr(&chunk.1).expect("recompute hash");
        assert_eq!(
            recomputed, chunk.0,
            "fetcher verifies the served chunk against its advertised address"
        );
        recovered.push((entry.rel_path.clone(), chunk.1));
    }

    assert_eq!(recovered[0].1, file_a, "page 1 byte-identical");
    assert_eq!(recovered[1].1, file_b, "page 2 byte-identical");

    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), sharer_task).await;
}

/// ISC-A-S21 — an offline sharer's content is unfetchable. With NO sharer
/// serving the asset, the relay has no live fetch-asset (live-only, ISC-S20),
/// so the fetcher's ManifestRequest never gets an answer and the request times
/// out — the content is unavailable, never served stale by the relay.
#[tokio::test]
async fn offline_sharer_content_is_unfetchable() {
    let _ = oxicrypt_module::initialize();

    let registry = CotRegistry::new();
    let (fetcher_client_io, fetcher_server_io) = tokio::io::duplex(64 * 1024);
    let _srv_f = spawn_relay(fetcher_server_io, registry.clone());
    let fetcher_sess = AppSession::open(fetcher_client_io).await.expect("fetcher");

    // Same derivation the sharer WOULD use — but no sharer is online.
    let asset_addr =
        public_share_asset_address(SHARE_ID.as_bytes(), SERVER_ID.as_bytes()).expect("derive");
    let asset_bytes = asset_addr.as_bytes().to_vec();

    let mut cot = fetcher_sess.circle_of_trust();
    let (tx, rx) = mpsc::channel::<wire::CotFrame>(16);
    tx.send(frame(&asset_bytes, Vec::new())).await.unwrap();
    let mut inbound = cot
        .subscribe(ReceiverStream::new(rx))
        .await
        .expect("fetcher subscribes (its own reference makes the asset live)")
        .into_inner();

    // Only the fetcher is subscribed; nobody answers a ManifestRequest.
    tx.send(frame(&asset_bytes, ShareFrame::ManifestRequest.encode()))
        .await
        .unwrap();

    // No manifest arrives within a bounded wait — the content is unfetchable.
    let outcome = tokio::time::timeout(Duration::from_millis(600), async {
        loop {
            match inbound.message().await {
                Ok(Some(f)) if f.payload.is_empty() => continue,
                Ok(Some(f)) => {
                    if let Ok(ShareFrame::ManifestResponse { .. }) = ShareFrame::decode(&f.payload)
                    {
                        return true; // a manifest arrived — would be a failure
                    }
                }
                Ok(None) | Err(_) => return false, // stream ended, still no manifest
            }
        }
    })
    .await;

    assert!(
        matches!(outcome, Err(_) | Ok(false)),
        "no ManifestResponse for an offline sharer — content is unfetchable (ISC-A-S21)"
    );

    drop(tx);
}
