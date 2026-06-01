//! Live application session over a post-`Authenticated` stream (M11).
//!
//! Once [`connect_session`] reaches `Authenticated` it hands back the live
//! [`AppStream`]. The application protocol on that stream is gRPC-over-h2 — the
//! exact thing the server runs via
//! [`serve_application`](daemonseed_server::public_space::serve_application).
//! [`AppSession`] is the client mirror: it builds one tonic [`Channel`] over the
//! single already-established stream, then hands out the generated service
//! clients. HTTP/2 multiplexes every RPC (and the long-lived `CircleOfTrust`
//! subscribe stream) over that one connection — there is never a second dial.
//!
//! The connector is invoked exactly once: the channel is built directly on the
//! supplied stream (no DNS, no TCP, no second TLS handshake), so the placeholder
//! authority URI is never resolved. This mirrors the server's
//! `serve_with_incoming(once(stream))` shape from the other end.
//!
//! Generic over the stream type so the same code path serves both production
//! (an [`AppStream`] = `TlsStream<TcpStream>`) and tests (an in-memory
//! `tokio::io::duplex` half), exactly as `serve_application` is generic on its
//! incoming transport.

use daemonseed_core::federation::discovered::{DiscoveredPeers, MergeOutcome};
use daemonseed_core::federation::store::TrustStore;
use daemonseed_proto::v1::IntroducerQuery;
use daemonseed_proto::v1::circle_of_trust_client::CircleOfTrustClient;
use daemonseed_proto::v1::federation_introducer_client::FederationIntroducerClient;
use daemonseed_proto::v1::public_space_client::PublicSpaceClient;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::{Channel, Endpoint};

/// A live application session: one tonic [`Channel`] multiplexed over a single
/// post-`Authenticated` stream. Clone-cheap clients are minted on demand; the
/// channel itself is shared (tonic `Channel` is internally reference-counted).
#[derive(Clone)]
pub struct AppSession {
    channel: Channel,
}

/// Why opening an [`AppSession`] over a live stream failed.
#[derive(Debug)]
pub enum SessionError {
    /// The tonic channel failed to come up over the stream (h2 preface /
    /// connector error). In practice unreachable for an in-memory connector on
    /// an already-open stream, but surfaced rather than panicked.
    Transport(tonic::transport::Error),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "application-session transport setup failed: {e}"),
        }
    }
}

impl core::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
        }
    }
}

impl AppSession {
    /// Build a session over an already-`Authenticated` `stream`.
    ///
    /// `stream` is consumed once by the tonic connector; the placeholder
    /// authority (`http://[::1]:50051`) is never resolved because no dial
    /// happens — the channel rides the stream as-is.
    pub async fn open<S>(stream: S) -> Result<Self, SessionError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut stream = Some(stream);
        let channel = Endpoint::try_from("http://[::1]:50051")
            .expect("static placeholder authority parses")
            .connect_with_connector(tower::service_fn(move |_| {
                let io = stream.take().expect("connector invoked exactly once");
                async move { Ok::<_, std::io::Error>(TokioIo::new(io)) }
            }))
            .await
            .map_err(SessionError::Transport)?;
        Ok(Self { channel })
    }

    /// A `PublicSpace` client over this session (MOTD, posts, taxonomy,
    /// whitelist, public-share listing, deprecation policy).
    pub fn public_space(&self) -> PublicSpaceClient<Channel> {
        PublicSpaceClient::new(self.channel.clone())
    }

    /// A `CircleOfTrust` client over this session (the bidirectional
    /// `Subscribe` live relay stream).
    pub fn circle_of_trust(&self) -> CircleOfTrustClient<Channel> {
        CircleOfTrustClient::new(self.channel.clone())
    }

    /// A `FederationIntroducer` client over this session (the introducer
    /// refresh, M12 gate step 6).
    pub fn introducer(&self) -> FederationIntroducerClient<Channel> {
        FederationIntroducerClient::new(self.channel.clone())
    }

    /// Refresh introducer-discovered peers: ask the connected relay's introducer
    /// for its full peer list and merge the result into `discovered` as
    /// candidates, returning the per-merge tally.
    ///
    /// Precautionary by construction (ISC-C22 / ISC-A-C19): this only reads
    /// `known` to skip already-configured servers and only writes `discovered`
    /// — it NEVER mutates the active trust set. A discovered peer becomes a
    /// candidate the user promotes explicitly ([`DiscoveredPeers::promote_trusted`]
    /// / [`DiscoveredPeers::promote_untrusted`]); discovery alone trusts nothing.
    /// The relay already excluded its `introduce_to_clients=false` peers
    /// server-side (ISC-S13), and the response carries no keys (ISC-S6).
    pub async fn refresh_introducer(
        &self,
        discovered: &mut DiscoveredPeers,
        known: &dyn TrustStore,
    ) -> Result<MergeOutcome, tonic::Status> {
        let response = self
            .introducer()
            .introduce(IntroducerQuery {
                target_server_id: None,
            })
            .await?
            .into_inner();
        Ok(discovered.merge(&response, known))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_proto::v1 as wire;
    use daemonseed_server::cot::CotRegistry;
    use daemonseed_server::public_space::{
        PublicSpaceService, PublicSpaceState, serve_application,
    };
    use std::sync::Arc;

    /// AppSession carries real PublicSpace RPCs over a single duplex stream
    /// (the in-memory stand-in for the post-Authenticated TLS stream): the
    /// client reaches GetMotd / ListPosts and gets well-formed empty results
    /// from an empty server. Proves the client mirror of serve_application.
    #[tokio::test]
    async fn app_session_routes_public_space_rpcs() {
        let state = Arc::new(PublicSpaceState::empty());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_application(
            server_io,
            PublicSpaceService::new(state),
            CotRegistry::new(),
            Arc::new(Vec::new()), // no federation peers (M12 introducer arg)
        ));

        let session = AppSession::open(client_io).await.expect("session opens");
        let mut ps = session.public_space();

        let motd = ps
            .get_motd(wire::GetMotdRequest {})
            .await
            .expect("GetMotd routes over the session")
            .into_inner()
            .motd;
        assert!(motd.is_none(), "empty server has no MOTD");

        let posts = ps
            .list_posts(wire::ListPostsRequest { topic: None })
            .await
            .expect("ListPosts routes over the session")
            .into_inner()
            .posts;
        assert!(posts.is_empty(), "empty server has no posts");

        // Dropping the session closes the connection; the single-connection
        // server future then resolves.
        drop(ps);
        drop(session);
        let _ = server.await;
    }

    /// Both service clients can be minted from one session and share the
    /// underlying channel (HTTP/2 multiplexes — no second dial).
    #[tokio::test]
    async fn one_session_mints_both_service_clients() {
        let state = Arc::new(PublicSpaceState::empty());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_application(
            server_io,
            PublicSpaceService::new(state),
            CotRegistry::new(),
            Arc::new(Vec::new()), // no federation peers (M12 introducer arg)
        ));

        let session = AppSession::open(client_io).await.expect("session opens");
        let _ps = session.public_space();
        let _cot = session.circle_of_trust();
        // A second public-space client over the same session also routes.
        let mut ps2 = session.public_space();
        ps2.get_motd(wire::GetMotdRequest {})
            .await
            .expect("second client over the same channel routes");

        drop(session);
        let _ = server.await;
    }

    /// End-to-end client refresh (M12, gate step 6): the client calls the
    /// relay's introducer over the session; the server-side ISC-S13 filter drops
    /// the `introduce_to_clients=false` peer, so only the introducible one lands
    /// in the client's discovered-candidate cache — and NOTHING enters the active
    /// trust store until the user promotes it (ISC-C22 / ISC-A-C19).
    #[tokio::test]
    async fn refresh_introducer_populates_discovered_candidates() {
        use daemonseed_core::federation::discovered::DiscoveredPeers;
        use daemonseed_core::federation::store::{InMemoryTrustStore, TrustStore};
        use daemonseed_core::federation::trust::TrustMode;
        use daemonseed_core::handle::Handle;
        use daemonseed_server::config::PeerConfig;

        let peer = |server_id: &str, address: &str, introduce: bool| PeerConfig {
            server_id: server_id.to_owned(),
            address: address.to_owned(),
            trust_mode: TrustMode::Trusted,
            introduce_to_clients: introduce,
            key_hex: None,
        };
        let peers = Arc::new(vec![
            peer("relay-b#0123456789ab", "b.example:443", true),
            peer("secret#0123456789ab", "secret.example:443", false),
        ]);

        let state = Arc::new(PublicSpaceState::empty());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_application(
            server_io,
            PublicSpaceService::new(state),
            CotRegistry::new(),
            peers,
        ));

        let session = AppSession::open(client_io).await.expect("session opens");
        let known = InMemoryTrustStore::new();
        let mut discovered = DiscoveredPeers::new();

        let outcome = session
            .refresh_introducer(&mut discovered, &known)
            .await
            .expect("introducer refresh routes");

        let b: Handle = "relay-b#0123456789ab".parse().unwrap();
        let secret: Handle = "secret#0123456789ab".parse().unwrap();
        assert_eq!(
            outcome.added, 1,
            "only the introducible peer is discovered (ISC-S13)"
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered.get(&b).unwrap().address, "b.example:443");
        assert!(
            discovered.get(&secret).is_none(),
            "don't-introduce peer never reaches the client"
        );

        // Precautionary (ISC-C22 / ISC-A-C19): the refresh trusted nothing —
        // promotion is an explicit, separate step that the user drives.
        assert!(
            known.get(&b).is_none(),
            "refresh must not write the active trust set"
        );
        let mut active = InMemoryTrustStore::new();
        let entry = discovered
            .promote_trusted(&b, &mut active)
            .expect("candidate promotes");
        assert_eq!(entry.mode, TrustMode::Trusted);
        assert_eq!(
            entry.pinned_key, None,
            "trusted promote pins on first contact, not now"
        );
        assert!(discovered.is_empty(), "promotion drains the candidate");

        drop(session);
        let _ = server.await;
    }
}
