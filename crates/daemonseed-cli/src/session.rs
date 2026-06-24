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

use daemonseed_core::cot::public_share_asset_address;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::federation::discovered::{DiscoveredPeers, MergeOutcome};
use daemonseed_core::federation::store::TrustStore;
use daemonseed_core::public_room::{DEFAULT_ROOM, RoomKeyError, derive_room_key};
use daemonseed_core::share_seal::{open_share_frame, seal_public_share_frame};
use daemonseed_core::share_serve::ChunkSource;
use daemonseed_proto::v1::IntroducerQuery;
use daemonseed_proto::v1::circle_of_trust_client::CircleOfTrustClient;
use daemonseed_proto::v1::federation_introducer_client::FederationIntroducerClient;
use daemonseed_proto::v1::public_space_client::PublicSpaceClient;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};

/// h2 keepalive PING cadence on an idle application channel (#72). Chosen below
/// the relay's ~30s h2 connection reap (ISA Out-of-Scope, "you must be online")
/// so a live-but-idle peer is kept alive while a genuinely dead half-open socket
/// is detected promptly.
const KEEPALIVE_INTERVAL: core::time::Duration = core::time::Duration::from_secs(15);

/// Bound on the PONG wait before a keepalive PING is treated as a dead
/// connection (#72): the channel errors, ending the inbound `Subscribe` stream.
/// Raised 10s → 30s (#80): the original 10s was tight enough that a slow PONG on a
/// high-latency / congested WAN tripped a spurious "dead connection", tearing down
/// a live session. 30s tolerates a slow ack while still detecting a genuine
/// half-open within `KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT` (~45s). Shared by the
/// GUI, TUI, and CLI via [`AppSession::open`]. (Belt-and-braces only: #80's
/// re-subscribe-then-fallback path recovers from a stream death regardless of why
/// it died, so this tuning is a performance optimization, not a correctness
/// dependency.)
const KEEPALIVE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(30);

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
            // h2 keepalive (#72): a half-open socket — e.g. the peer's host moves
            // to a new network namespace on a VPN swap, silently black-holing the
            // TCP connection — otherwise hangs a long-lived `Subscribe` stream
            // forever, because no bytes flow to trigger an error. Sending a PING on
            // an idle connection and bounding the PONG wait surfaces the dead link
            // as a stream error within `KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT`, so
            // the inbound reader's `Err(_)` exit arm fires and the actor reconnects
            // (#71) rather than waiting indefinitely.
            .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
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

    /// Serve a share's content to any number of fetchers over its circle-of-trust
    /// fetch-asset (alpha2 item B; ISC-S27 / ISC-S29). Returns `Ok(())` on a
    /// graceful end-of-stream (the relay reaped the asset, or the peer left);
    /// the caller typically races this against a Ctrl-C signal.
    ///
    /// The fetch-asset is derived from `(share_id, server_id)` via the **same**
    /// [`public_share_asset_address`] the consumer ([`crate::session`] mirror in
    /// the TUI net actor, and the integration tests) uses — byte-for-byte
    /// agreement is guaranteed by reusing the one function with the same inputs
    /// (the opaque hex `share_id` string, the connected `server_id` string). A
    /// single bidi `CircleOfTrust.Subscribe` stream names that asset; the relay
    /// fans every fetcher's `ManifestRequest` / `ChunkRequest` into this one
    /// stream and our responses back out, so one serve loop handles arbitrarily
    /// many concurrent fetchers (bounded by the relay's per-connection limiter,
    /// ISC-S17). Each reply is answered by `content` — any [`ChunkSource`]
    /// (the in-RAM `ShareContent` or the disk-backed `DiskShareContent`) — so
    /// its bytes hash to the advertised address by construction (ISC-S28);
    /// the serve side never fabricates a chunk it does not hold (ISC-A-S21).
    ///
    /// `content` is shared via [`Arc`] and every inbound frame is answered on
    /// the blocking pool ([`tokio::task::spawn_blocking`]), never inline:
    /// `ChunkSource::answer` does synchronous file I/O for a disk-backed
    /// chunk, and this loop runs as a `spawn_local` task on the TUI net
    /// actor's single-threaded `LocalSet` — an inline answer would park the
    /// entire actor (connects, chat, every other share) for the duration of a
    /// multi-GB read. Serving must never freeze the client's event loop
    /// (ISC-A-C7), so the blocking work is pushed off-runtime per request.
    pub async fn serve_share<C>(
        &self,
        server_id: &str,
        share_id: &str,
        content: Arc<C>,
    ) -> Result<(), ServeShareError>
    where
        C: ChunkSource + Send + Sync + 'static,
    {
        let asset_addr = public_share_asset_address(share_id.as_bytes(), server_id.as_bytes())
            .map_err(ServeShareError::Derive)?;
        let asset_bytes = asset_addr.as_bytes().to_vec();

        // The seal key for a PUBLIC share: the public room key, derived from
        // public inputs (the lobby room name + suite) — never from `share_id`.
        // Both serve and fetch sides derive it independently, so it is threaded
        // by *derivation here*, not passed in: `serve_share` serves public
        // shares only, the inputs are constants, and deriving locally keeps the
        // public signature unchanged and the fetcher↔sharer key agreement
        // structural (same function, same inputs) rather than a wired-through
        // parameter that could drift. Content frames ride sealed under it so
        // public-share traffic is structurally indistinguishable from circle
        // traffic on the wire (was cleartext); see
        // `docs/design/unified-share-model.md` workstream A.
        let room_key =
            derive_room_key(DEFAULT_ROOM, &CNSA_2_0).map_err(ServeShareError::RoomKey)?;

        // Outbound half: the naming frame (empty payload, names the rendezvous
        // and is not relayed) then our responses. Capacity is generous so a
        // burst of fetcher requests does not back-pressure the answer path.
        let (out_tx, out_rx) = mpsc::channel::<daemonseed_proto::v1::CotFrame>(64);
        out_tx
            .send(daemonseed_proto::v1::CotFrame {
                asset_address: asset_bytes.clone(),
                payload: Vec::new(),
            })
            .await
            .map_err(|_| ServeShareError::ChannelClosed)?;

        let mut cot = self.circle_of_trust();
        let mut inbound = cot
            .subscribe(ReceiverStream::new(out_rx))
            .await
            .map_err(ServeShareError::Subscribe)?
            .into_inner();

        // Serve loop: decode each inbound frame, answer requests from the
        // indexed content, relay the response back. Foreign / undecodable
        // frames are skipped (same fail-closed posture as the chat envelope).
        // Ends when the stream closes — returned as Ok.
        while let Some(frame) = inbound.message().await.map_err(ServeShareError::Stream)? {
            if frame.payload.is_empty() {
                continue; // naming-frame echo or noise
            }
            // Open the sealed request frame under the public room key. A
            // wrong-key / tampered / garbage payload fails closed — skipped
            // exactly as an undecodable `ShareFrame::decode` was before
            // (same fail-closed posture toward hostile relay noise).
            let Ok(req) = open_share_frame(&room_key, &frame.payload) else {
                continue;
            };
            // Answer off-runtime (ISC-A-C7, see the method doc): the disk
            // read behind a `ChunkRequest` is blocking, and this task may be
            // sharing a single-threaded `LocalSet` with the whole TUI actor.
            let source = Arc::clone(&content);
            let response = tokio::task::spawn_blocking(move || source.answer(&req))
                .await
                .expect("share answer task panicked");
            // Seal the response under the same public room key before it enters
            // `CotFrame.payload`. A seal failure (entropy/AEAD) drops this one
            // answer rather than panicking; the fetcher times out and retries.
            if let Some(response) = response
                && let Ok(sealed) = seal_public_share_frame(&room_key, &response)
                && out_tx
                    .send(daemonseed_proto::v1::CotFrame {
                        asset_address: asset_bytes.clone(),
                        payload: sealed,
                    })
                    .await
                    .is_err()
            {
                break; // outbound torn down — stop gracefully
            }
        }
        Ok(())
    }
}

/// Why serving a share's content failed.
#[derive(Debug)]
pub enum ServeShareError {
    /// Deriving the share's fetch-asset address failed (oxicrypt SHA-384
    /// power-up self-test has not passed in this process).
    Derive(oxicrypt_module::Error),
    /// Deriving the public room key (the content-frame seal key) failed —
    /// the oxicrypt KDF power-up self-test has not passed in this process.
    RoomKey(RoomKeyError),
    /// The local subscribe channel closed before the naming frame went out.
    ChannelClosed,
    /// The relay refused the `CircleOfTrust.Subscribe` stream.
    Subscribe(tonic::Status),
    /// The inbound stream errored mid-serve.
    Stream(tonic::Status),
}

impl core::fmt::Display for ServeShareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeShareError::Derive(e) => write!(f, "share fetch-asset derivation failed: {e}"),
            ServeShareError::RoomKey(e) => write!(f, "share seal-key derivation failed: {e}"),
            ServeShareError::ChannelClosed => {
                f.write_str("share serve channel closed before naming frame")
            }
            ServeShareError::Subscribe(s) => {
                write!(f, "share serve subscribe refused: {}", s.message())
            }
            ServeShareError::Stream(s) => write!(f, "share serve stream error: {}", s.message()),
        }
    }
}

impl core::error::Error for ServeShareError {}

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
        let ps = session.public_space();
        let cot = session.circle_of_trust();
        // A second public-space client over the same session also routes.
        let mut ps2 = session.public_space();
        ps2.get_motd(wire::GetMotdRequest {})
            .await
            .expect("second client over the same channel routes");

        // The single-connection server returns once the connection closes, which
        // requires dropping EVERY handle that owns a channel clone — the session
        // and all derived service clients (each holds its own `Channel` clone).
        drop(ps);
        drop(cot);
        drop(ps2);
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
