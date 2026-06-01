//! Federation introducer — response construction and the gRPC endpoint
//! (ISC-S6 / ISC-S13 / ISC-A-S7).
//!
//! [`introducer_response`] turns the operator's configured `[[peer]]` table
//! into an [`IntroducerResponse`] for a requesting client OR a peering server —
//! the same function serves both, because the no-keys + suppression rules are
//! identical on each path (ISC-S6, ISC-S12 introductions).
//!
//! [`IntroducerService`] (M12, gate step 6) exposes that builder over the
//! post-Authenticated gRPC stream as the `FederationIntroducer.Introduce` RPC —
//! the endpoint M5 never wired. It is a pure adapter: every introducer
//! invariant lives in [`introducer_response`], and the service adds no policy.
//!
//! Three invariants are enforced here, and the test suite is project-lifetime
//! regression surface:
//!
//! - **No keys (ISC-S6).** The response never carries a public key. This is
//!   structural — [`PeerTriple`] has no key field — so this module physically
//!   cannot leak one; the tests assert the shape stays that way.
//! - **Introduce-to-clients suppression (ISC-S13).** A peer with
//!   `introduce_to_clients = false` is omitted from every response.
//! - **Don't-introduce indistinguishability (ISC-A-S7).** A by-id query for a
//!   suppressed peer returns the *same* empty response as a query for a
//!   genuinely-unknown peer, so an active attacker cannot confirm a suspected
//!   peer's existence by asking for it.

use std::sync::Arc;

use daemonseed_proto::v1::federation_introducer_server::FederationIntroducer;
use daemonseed_proto::v1::{IntroducerQuery, IntroducerResponse, PeerTriple};
use tonic::{Request, Response, Status};

use crate::config::PeerConfig;

/// Build the introducer response for `query` from the configured `peers`.
///
/// An empty / unset `target_server_id` returns the full list of
/// introduce-to-clients peers; a populated one returns just that peer's triple
/// if it is both known and introducible, otherwise an empty list (ISC-A-S7).
pub fn introducer_response(peers: &[PeerConfig], query: &IntroducerQuery) -> IntroducerResponse {
    let target = query.target_server_id.as_deref().filter(|t| !t.is_empty());

    let triples = peers
        .iter()
        // ISC-S13: never reveal a don't-introduce peer.
        .filter(|p| p.introduce_to_clients)
        // ISC-S6-11: a by-id query narrows to the exact match; no target
        // returns the whole (already-filtered) list.
        .filter(|p| target.is_none_or(|t| p.server_id == t))
        .map(to_triple)
        .collect();

    IntroducerResponse { peers: triples }
}

/// Project a configured peer to a wire triple. `last_known_availability` is
/// left unset: the RAM-only availability producer is deferred past MVP (finding
/// F15). The full key is deliberately absent (ISC-S6) — `PeerTriple` has no
/// field for it.
fn to_triple(p: &PeerConfig) -> PeerTriple {
    PeerTriple {
        server_id: p.server_id.clone(),
        address: p.address.clone(),
        last_known_availability_unix_ms: None,
    }
}

/// The federation introducer gRPC service (M12, gate step 6 / ISC-S6).
///
/// A thin post-Authenticated adapter over [`introducer_response`]: it holds the
/// operator's configured peer table and answers `Introduce` queries with the
/// same filtered, key-free response the builder produces. Served over the
/// post-Authenticated stream alongside `PublicSpace` (M6) and `CircleOfTrust`
/// (M8) — reaching it is structurally impossible before identity-proof
/// (ISC-S19 / ISC-C23), so an introduction is only ever served to a verified
/// peer. All three introducer invariants — no keys (ISC-S6), don't-introduce
/// suppression (ISC-S13), unknown/suppressed indistinguishability (ISC-A-S7) —
/// live in [`introducer_response`] and its project-lifetime regression suite;
/// this type only adapts that pure function to the wire and never adds policy
/// of its own.
pub struct IntroducerService {
    /// Operator-configured federation peers, shared read-only across every
    /// connection (one `Arc` clone per `serve_application`). The peer table is
    /// process-lifetime config (ISC-S12); the service never mutates it.
    peers: Arc<Vec<PeerConfig>>,
}

impl IntroducerService {
    /// Wrap the operator's peer table as a servable introducer.
    pub fn new(peers: Arc<Vec<PeerConfig>>) -> Self {
        Self { peers }
    }
}

#[tonic::async_trait]
impl FederationIntroducer for IntroducerService {
    async fn introduce(
        &self,
        request: Request<IntroducerQuery>,
    ) -> Result<Response<IntroducerResponse>, Status> {
        // The entire policy — filtering, don't-introduce suppression, the
        // no-keys invariant — belongs to the builder. This handler is a pure
        // projection of in-memory operator config, so it cannot fail: an
        // unknown or suppressed query is a valid empty response (ISC-A-S7),
        // never an error status that would leak the peer's existence.
        Ok(Response::new(introducer_response(
            &self.peers,
            &request.into_inner(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::federation::trust::TrustMode;

    fn peer(server_id: &str, introduce: bool) -> PeerConfig {
        PeerConfig {
            server_id: server_id.to_owned(),
            address: format!("{server_id}.example:443"),
            trust_mode: TrustMode::Trusted,
            introduce_to_clients: introduce,
            key_hex: None,
        }
    }

    fn list_query() -> IntroducerQuery {
        IntroducerQuery {
            target_server_id: None,
        }
    }

    fn by_id(id: &str) -> IntroducerQuery {
        IntroducerQuery {
            target_server_id: Some(id.to_owned()),
        }
    }

    #[test]
    fn full_list_returns_all_introducible_peers() {
        let peers = vec![peer("a#0123456789ab", true), peer("b#0123456789ab", true)];
        let resp = introducer_response(&peers, &list_query());
        assert_eq!(resp.peers.len(), 2);
    }

    #[test]
    fn full_list_excludes_dont_introduce_peers() {
        let peers = vec![
            peer("a#0123456789ab", true),
            peer("secret#0123456789ab", false),
        ];
        let resp = introducer_response(&peers, &list_query());
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].server_id, "a#0123456789ab");
    }

    #[test]
    fn by_id_known_introducible_returns_one_triple() {
        let peers = vec![peer("a#0123456789ab", true), peer("b#0123456789ab", true)];
        let resp = introducer_response(&peers, &by_id("b#0123456789ab"));
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].server_id, "b#0123456789ab");
    }

    #[test]
    fn by_id_dont_introduce_peer_returns_empty() {
        // ISC-A-S7: a suppressed peer must look identical to an absent one.
        let peers = vec![peer("secret#0123456789ab", false)];
        let resp = introducer_response(&peers, &by_id("secret#0123456789ab"));
        assert!(resp.peers.is_empty());
    }

    #[test]
    fn by_id_unknown_peer_returns_empty() {
        let peers = vec![peer("a#0123456789ab", true)];
        let resp = introducer_response(&peers, &by_id("nobody#000000000000"));
        assert!(resp.peers.is_empty());
    }

    #[test]
    fn dont_introduce_and_unknown_responses_are_identical() {
        // The CVE-class assertion: an active enumerator querying a suspected
        // suppressed peer gets a byte-identical response to querying a name
        // that was never configured.
        let peers = vec![peer("secret#0123456789ab", false)];
        let suppressed = introducer_response(&peers, &by_id("secret#0123456789ab"));
        let unknown = introducer_response(&peers, &by_id("phantom#0123456789ab"));
        assert_eq!(suppressed, unknown);
    }

    #[test]
    fn triple_omits_availability_at_mvp() {
        // F15: no availability producer yet → field stays None on the wire.
        let peers = vec![peer("a#0123456789ab", true)];
        let resp = introducer_response(&peers, &list_query());
        assert_eq!(resp.peers[0].last_known_availability_unix_ms, None);
    }

    // ── Endpoint over the wire (M12 / gate step 6) ───────────────────────────
    //
    // The tests above exercise the pure builder; M5 already had those and yet
    // shipped no endpoint. These exercise the actual gRPC service through the
    // real `serve_application` registration path — the thing that was missing.

    /// The `Introduce` RPC is reachable over the post-Authenticated gRPC stream
    /// and returns the builder's filtered list: the introducible peer is served,
    /// the `introduce_to_clients = false` peer is suppressed (ISC-S13). This is
    /// the regression that proves the M5 "no endpoint" gap is closed.
    #[tokio::test]
    async fn introduce_endpoint_serves_filtered_peers_over_wire() {
        use std::io;

        use daemonseed_proto::v1::federation_introducer_client::FederationIntroducerClient;
        use hyper_util::rt::TokioIo;
        use tonic::transport::Endpoint;

        use crate::cot::CotRegistry;
        use crate::public_space::{PublicSpaceService, PublicSpaceState, serve_application};

        let peers = Arc::new(vec![
            peer("a#0123456789ab", true),
            peer("secret#0123456789ab", false),
        ]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_application(
            server_io,
            PublicSpaceService::new(Arc::new(PublicSpaceState::empty())),
            CotRegistry::new(),
            Arc::clone(&peers),
        ));

        let mut client_io = Some(client_io);
        let channel = Endpoint::try_from("http://[::1]:50051")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_| {
                let io = client_io.take().expect("connector invoked once");
                async move { Ok::<_, io::Error>(TokioIo::new(io)) }
            }))
            .await
            .expect("in-memory connect over duplex");
        let mut client = FederationIntroducerClient::new(channel);

        // Full-list query: only the introducible peer comes back over the wire.
        let full = client
            .introduce(list_query())
            .await
            .expect("Introduce routes")
            .into_inner();
        assert_eq!(
            full.peers.len(),
            1,
            "don't-introduce peer suppressed (ISC-S13)"
        );
        assert_eq!(full.peers[0].server_id, "a#0123456789ab");
        // ISC-S6 over the wire: PeerTriple structurally has no key field, so
        // there is nothing to assert-absent — the type system guarantees it.

        // ISC-A-S7 over the wire: a by-id query for the suppressed peer and for
        // a never-configured name return byte-identical empty responses, so an
        // active enumerator cannot confirm the suppressed peer's existence.
        let suppressed = client
            .introduce(by_id("secret#0123456789ab"))
            .await
            .expect("routes")
            .into_inner();
        let unknown = client
            .introduce(by_id("phantom#0123456789ab"))
            .await
            .expect("routes")
            .into_inner();
        assert!(suppressed.peers.is_empty());
        assert_eq!(
            suppressed, unknown,
            "suppressed and unknown indistinguishable on the wire"
        );

        drop(client);
        let _ = server.await;
    }
}
