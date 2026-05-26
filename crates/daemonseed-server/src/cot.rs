//! Circle-of-trust live relay service (M8, F23) — server side of `cot.proto`.
//!
//! The relay is a blind forwarder. A member opens one bidirectional
//! [`CircleOfTrust::subscribe`] stream per circle-asset; the relay routes by
//! the opaque rendezvous address ([`daemonseed_core::cot::asset_address`]) and
//! fans each inbound frame out to every *other* current subscriber of the same
//! asset. It never decrypts a payload, never learns the circle or its
//! membership, and persists nothing (ISC-A-S2).
//!
//! ## Lifecycle = the stream (ISC-5 / ISC-7 / ISC-9 / ISC-10 / ISC-11, F23)
//!
//! Presence *is* the subscription stream. Opening one takes a reference to the
//! asset (`CotRegistry::subscribe`); the stream ending — a graceful close, or
//! h2 keepalive (configured on the server) detecting a dead peer — drops the
//! [`CotSubscribeStream`], whose `ReleaseGuard` releases the reference; the
//! asset and its routing entry are reaped the instant the refcount hits zero
//! (`CotRegistry::release`). There is no reconnect or multiplex state: the
//! relay is live-only (a frame sent while you are away is never delivered), so
//! an offline circle leaves no trace anywhere but its members' own machines.
//!
//! ## Why a per-subscriber id
//!
//! Fan-out uses a [`tokio::sync::broadcast`] channel per asset, which delivers
//! to *all* receivers including the sender's own. To avoid echoing a member's
//! frame back to itself, each subscription is tagged with a process-local
//! `u64` id (never on the wire — it does not weaken the relay's blindness), and
//! the outbound stream skips frames bearing its own id. A lagging subscriber
//! that overruns the channel simply misses frames (live-only; no backlog), it
//! does not stall the asset.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use daemonseed_core::cot::ASSET_ADDR_LEN;
use daemonseed_proto::v1::CotFrame;
use daemonseed_proto::v1::circle_of_trust_server::CircleOfTrust;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status, Streaming};

/// Per-asset broadcast depth. A subscriber more than this many frames behind
/// is told it lagged and skips the gap (live-only — there is no backlog to
/// replay).
const ASSET_CHANNEL_CAPACITY: usize = 256;

/// A frame in flight on an asset's fan-out channel, tagged with the local id of
/// the subscription that published it so the outbound side can skip its own.
#[derive(Clone)]
struct Relayed {
    from: u64,
    frame: Arc<CotFrame>,
}

struct Asset {
    tx: broadcast::Sender<Relayed>,
    /// Live subscriptions (ISC-9). The asset is reaped when this hits zero.
    refs: u32,
}

/// The relay's live circle-of-trust asset table — refcounted fan-out channels
/// keyed by rendezvous address. One instance is shared across every connection
/// the relay serves (cloning shares the inner `Arc`); it holds nothing on disk
/// and nothing survives the process (ISC-A-S5).
#[derive(Clone)]
pub struct CotRegistry {
    inner: Arc<Mutex<HashMap<[u8; ASSET_ADDR_LEN], Asset>>>,
    next_id: Arc<AtomicU64>,
}

impl Default for CotRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CotRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Take a reference to `addr`'s asset (creating it if new) and return a
    /// fresh subscription id plus a receiver on its fan-out channel (ISC-9).
    fn subscribe(&self, addr: &[u8; ASSET_ADDR_LEN]) -> (u64, broadcast::Receiver<Relayed>) {
        let mut map = self.inner.lock().expect("cot registry mutex poisoned");
        let asset = map.entry(*addr).or_insert_with(|| Asset {
            tx: broadcast::channel(ASSET_CHANNEL_CAPACITY).0,
            refs: 0,
        });
        asset.refs += 1;
        let rx = asset.tx.subscribe();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        (id, rx)
    }

    /// Fan `frame` out to every current subscriber of `addr` (tagged with the
    /// publishing subscription's id). A no-op if the asset is not live or has
    /// no receivers.
    fn publish(&self, addr: &[u8; ASSET_ADDR_LEN], from: u64, frame: Arc<CotFrame>) {
        let map = self.inner.lock().expect("cot registry mutex poisoned");
        if let Some(asset) = map.get(addr) {
            // Errors only when there are no receivers; nothing to deliver.
            let _ = asset.tx.send(Relayed { from, frame });
        }
    }

    /// Release one reference to `addr`'s asset; reap the asset (and its routing
    /// entry) the moment the refcount reaches zero (ISC-10). Returns the
    /// references remaining — `0` means the asset was reaped. Releasing an
    /// already-absent asset is a no-op returning `0`.
    fn release(&self, addr: &[u8; ASSET_ADDR_LEN]) -> u32 {
        let mut map = self.inner.lock().expect("cot registry mutex poisoned");
        match map.get_mut(addr) {
            Some(asset) => {
                asset.refs = asset.refs.saturating_sub(1);
                if asset.refs == 0 {
                    map.remove(addr);
                    0
                } else {
                    asset.refs
                }
            }
            None => 0,
        }
    }

    /// Number of live assets — for metrics/tests, never a wire query (a
    /// presence oracle would reopen the ISC-A-S2 enumeration channel).
    pub fn live_assets(&self) -> usize {
        self.inner
            .lock()
            .expect("cot registry mutex poisoned")
            .len()
    }
}

/// Releases the held asset reference when the subscription's outbound stream is
/// dropped — whether the client closed gracefully or h2 keepalive reaped a dead
/// peer. This is the single place a reference is returned, so presence tracking
/// can never leak a reference on any disconnect path.
struct ReleaseGuard {
    registry: CotRegistry,
    addr: [u8; ASSET_ADDR_LEN],
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.registry.release(&self.addr);
    }
}

/// The outbound half of a member's bidirectional subscription: co-subscribers'
/// frames, minus the member's own. Dropping it reaps the reference via the
/// embedded `ReleaseGuard`.
pub struct CotSubscribeStream {
    inner: BroadcastStream<Relayed>,
    my_id: u64,
    _guard: ReleaseGuard,
}

impl Stream for CotSubscribeStream {
    type Item = Result<CotFrame, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                // Skip our own frames (broadcast delivers to every receiver).
                Poll::Ready(Some(Ok(relayed))) if relayed.from == this.my_id => continue,
                Poll::Ready(Some(Ok(relayed))) => {
                    return Poll::Ready(Some(Ok((*relayed.frame).clone())));
                }
                // A lagged receiver missed frames (live-only — no replay); keep
                // going rather than tearing the stream down.
                Poll::Ready(Some(Err(_lagged))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The `CircleOfTrust` gRPC service — a thin handle over the shared
/// [`CotRegistry`].
#[derive(Clone)]
pub struct CotService {
    registry: CotRegistry,
}

impl CotService {
    /// Build a service over the relay's shared registry.
    pub fn new(registry: CotRegistry) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl CircleOfTrust for CotService {
    type SubscribeStream = CotSubscribeStream;

    async fn subscribe(
        &self,
        request: Request<Streaming<CotFrame>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let mut inbound = request.into_inner();

        // The first frame names the asset this stream joins. An empty stream or
        // a wrong-length address is a hard, uniform invalid-argument.
        let first = inbound.message().await?.ok_or_else(|| {
            Status::invalid_argument("subscribe stream closed before naming an asset")
        })?;
        let addr: [u8; ASSET_ADDR_LEN] = first
            .asset_address
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("asset_address must be 48 bytes"))?;

        let (my_id, rx) = self.registry.subscribe(&addr);

        // The first frame may itself carry a payload to relay.
        if !first.payload.is_empty() {
            self.registry.publish(&addr, my_id, Arc::new(first));
        }

        // Inbound pump: forward this member's subsequent frames to the asset.
        // A frame naming a different asset is dropped (a member cannot inject
        // into an asset it did not subscribe to). The pump ends when the
        // inbound half closes; the outbound guard owns the refcount, so no
        // release happens here.
        let pump_registry = self.registry.clone();
        tokio::spawn(async move {
            while let Ok(Some(frame)) = inbound.message().await {
                if frame.asset_address.as_slice() != addr {
                    continue;
                }
                pump_registry.publish(&addr, my_id, Arc::new(frame));
            }
        });

        Ok(Response::new(CotSubscribeStream {
            inner: BroadcastStream::new(rx),
            my_id,
            _guard: ReleaseGuard {
                registry: self.registry.clone(),
                addr,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR_A: [u8; ASSET_ADDR_LEN] = [0xa1; ASSET_ADDR_LEN];
    const ADDR_B: [u8; ASSET_ADDR_LEN] = [0xb2; ASSET_ADDR_LEN];

    fn frame(addr: [u8; ASSET_ADDR_LEN], payload: &[u8]) -> Arc<CotFrame> {
        Arc::new(CotFrame {
            asset_address: addr.to_vec(),
            payload: payload.to_vec(),
        })
    }

    /// ISC-9 — subscribing creates the asset and increments its refcount; a
    /// second subscriber shares the one asset.
    #[test]
    fn subscribe_increments_refcount() {
        let reg = CotRegistry::new();
        assert_eq!(reg.live_assets(), 0);
        let (_id1, _rx1) = reg.subscribe(&ADDR_A);
        let (_id2, _rx2) = reg.subscribe(&ADDR_A);
        assert_eq!(reg.live_assets(), 1, "one asset, two subscribers");
    }

    /// ISC-10 — releasing decrements; the asset is reaped only when the last
    /// reference goes (server-blind teardown).
    #[test]
    fn release_decrements_then_reaps_at_zero() {
        let reg = CotRegistry::new();
        let (_id1, _rx1) = reg.subscribe(&ADDR_A);
        let (_id2, _rx2) = reg.subscribe(&ADDR_A);
        assert_eq!(reg.release(&ADDR_A), 1, "one subscriber remains");
        assert_eq!(reg.live_assets(), 1, "asset still live");
        assert_eq!(reg.release(&ADDR_A), 0, "last reference released");
        assert_eq!(reg.live_assets(), 0, "asset reaped at zero (ISC-10/A-S5)");
    }

    /// Releasing an asset that no longer exists is a harmless no-op.
    #[test]
    fn release_absent_is_zero() {
        let reg = CotRegistry::new();
        assert_eq!(reg.release(&ADDR_A), 0);
    }

    /// A published frame reaches another subscriber of the same asset, tagged
    /// with the publisher's id (the outbound stream uses the tag to skip the
    /// publisher's own copy).
    #[test]
    fn publish_fans_out_with_sender_tag() {
        let reg = CotRegistry::new();
        let (sender_id, mut sender_rx) = reg.subscribe(&ADDR_A);
        let (_other_id, mut other_rx) = reg.subscribe(&ADDR_A);

        reg.publish(&ADDR_A, sender_id, frame(ADDR_A, b"hello circle"));

        let got = other_rx
            .try_recv()
            .expect("co-subscriber receives the frame");
        assert_eq!(got.from, sender_id);
        assert_eq!(got.frame.payload, b"hello circle");
        // The sender's own receiver also gets a copy (broadcast), tagged with
        // its own id — which the outbound CotSubscribeStream filters out.
        let echo = sender_rx.try_recv().expect("broadcast also reaches sender");
        assert_eq!(echo.from, sender_id);
    }

    /// Assets are isolated: a frame on one asset never reaches a subscriber of
    /// a different asset (distinct rendezvous addresses).
    #[test]
    fn publish_isolated_per_asset() {
        let reg = CotRegistry::new();
        let (_id_a, mut rx_a) = reg.subscribe(&ADDR_A);
        let (id_b, _rx_b) = reg.subscribe(&ADDR_B);

        reg.publish(&ADDR_B, id_b, frame(ADDR_B, b"other circle"));
        assert!(
            rx_a.try_recv().is_err(),
            "subscriber of ADDR_A hears nothing from ADDR_B"
        );
    }

    /// Publishing to an asset with no live subscribers is a no-op (it is not
    /// even live), not a panic.
    #[test]
    fn publish_to_absent_asset_is_noop() {
        let reg = CotRegistry::new();
        reg.publish(&ADDR_A, 0, frame(ADDR_A, b"nobody home"));
        assert_eq!(reg.live_assets(), 0);
    }

    /// The drop guard returns the subscription's reference even if the outbound
    /// stream is dropped without ever being polled — the disconnect /
    /// keepalive-death path that real clients exercise.
    #[test]
    fn release_guard_reaps_on_drop() {
        let reg = CotRegistry::new();
        let (_id, _rx) = reg.subscribe(&ADDR_A); // refs = 1
        assert_eq!(reg.live_assets(), 1);
        {
            let _guard = ReleaseGuard {
                registry: reg.clone(),
                addr: ADDR_A,
            };
            // _guard drops at end of scope → release → refs 1→0 → reaped.
        }
        assert_eq!(
            reg.live_assets(),
            0,
            "guard released the only reference; asset reaped (ISC-10)"
        );
    }

    /// End-to-end over a real in-process gRPC connection (ISC-7 / ISC-9 /
    /// ISC-10): two members open `Subscribe` streams to the same asset, one
    /// publishes a frame and the other receives it over the wire, and the
    /// asset is reaped once both disconnect. The duplex stands in for the
    /// post-Authenticated TLS stream; HTTP/2 multiplexes the two subscriptions
    /// over the one connection.
    #[tokio::test]
    async fn subscribe_relays_a_frame_then_reaps_on_disconnect() {
        use std::time::Duration;

        use crate::public_space::ServedConn;
        use daemonseed_proto::v1::circle_of_trust_client::CircleOfTrustClient;
        use daemonseed_proto::v1::circle_of_trust_server::CircleOfTrustServer;
        use hyper_util::rt::TokioIo;
        use tokio::sync::mpsc;
        use tokio_stream::wrappers::ReceiverStream;
        use tonic::transport::{Endpoint, Server};

        let registry = CotRegistry::new();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_registry = registry.clone();
        let server = tokio::spawn(async move {
            let incoming = tokio_stream::once(Ok::<_, std::io::Error>(ServedConn(server_io)));
            Server::builder()
                .add_service(CircleOfTrustServer::new(CotService::new(server_registry)))
                .serve_with_incoming(incoming)
                .await
        });

        let mut client_io = Some(client_io);
        let channel = Endpoint::try_from("http://[::1]:50051")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_| {
                let io = client_io.take().expect("connector invoked exactly once");
                async move { Ok::<_, std::io::Error>(TokioIo::new(io)) }
            }))
            .await
            .expect("in-memory connect over duplex");

        let mut client_b = CircleOfTrustClient::new(channel.clone());
        let mut client_a = CircleOfTrustClient::new(channel);
        let addr = vec![0xccu8; ASSET_ADDR_LEN];

        // B subscribes first (live-only: a receiver must exist before the
        // publish) and keeps its outbound half open by holding b_tx.
        let (b_tx, b_rx) = mpsc::channel::<CotFrame>(8);
        b_tx.send(CotFrame {
            asset_address: addr.clone(),
            payload: Vec::new(),
        })
        .await
        .unwrap();
        let mut b_in = client_b
            .subscribe(ReceiverStream::new(b_rx))
            .await
            .expect("B subscribes")
            .into_inner();

        // A subscribes (naming frame, empty → not relayed) and publishes one
        // payload frame.
        let (a_tx, a_rx) = mpsc::channel::<CotFrame>(8);
        a_tx.send(CotFrame {
            asset_address: addr.clone(),
            payload: Vec::new(),
        })
        .await
        .unwrap();
        a_tx.send(CotFrame {
            asset_address: addr.clone(),
            payload: b"hello over the wire".to_vec(),
        })
        .await
        .unwrap();
        let a_in = client_a
            .subscribe(ReceiverStream::new(a_rx))
            .await
            .expect("A subscribes")
            .into_inner();

        // B receives A's payload (ISC-7: the relay routed by asset address).
        let frame = tokio::time::timeout(Duration::from_secs(5), b_in.message())
            .await
            .expect("a frame arrives within the timeout")
            .expect("response stream is healthy")
            .expect("a frame, not end-of-stream");
        assert_eq!(frame.payload, b"hello over the wire");
        assert_eq!(registry.live_assets(), 1, "one asset, two members");

        // Both members disconnect → both references release → reap (ISC-10).
        drop(a_tx);
        drop(b_tx);
        drop(a_in);
        drop(b_in);
        drop(client_a);
        drop(client_b);
        let mut reaped = false;
        for _ in 0..100 {
            if registry.live_assets() == 0 {
                reaped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(reaped, "asset reaped once both members disconnect (ISC-10)");

        server.abort();
    }
}
