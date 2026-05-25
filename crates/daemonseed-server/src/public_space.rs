//! Public-space application service (M6) — the FIRST post-Authenticated
//! gRPC-over-h2 service in the protocol.
//!
//! ## Where this sits in the connection lifecycle
//!
//! Everything up to and including the identity-proof exchange runs as
//! length-prefixed prost frames on the raw TLS stream (see [`crate::hello`]
//! and [`crate::identity_proof`]). Once the per-connection driver advances the
//! type-state to [`daemonseed_core::connection::Authenticated`], that
//! connection *is* an application byte-stream (it impls `AsyncRead` +
//! `AsyncWrite`). This module serves the [`PublicSpace`] gRPC service over that
//! byte-stream. Earlier milestones deliberately dropped the `Authenticated`
//! connection ("M5+ serves the application stream"); M6 is where it gets
//! served.
//!
//! ## Why a single-connection tonic server (the retired risk)
//!
//! tonic's [`Server`](tonic::transport::Server) is normally driven by a TCP
//! listener. Here there is exactly one, already-TLS-terminated, already-
//! identity-proven connection. [`serve_public_space`] adapts it via
//! tonic's `serve_with_incoming` fed a one-element stream
//! ([`tokio_stream::once`]). The connection IO must
//! impl [`tonic::transport::server::Connected`]; that trait and the concrete
//! transport types are both foreign, so [`ServedConn`] is a local newtype that
//! supplies the impl (orphan rule). Its `ConnectInfo` is `()` because the peer
//! identity is already established by the identity-proof phase — tonic's
//! connect-info would be redundant.
//!
//! ## Spike status
//!
//! Every RPC currently returns [`tonic::Status::unimplemented`]. The real
//! posts / MOTD / signer-whitelist / taxonomy / public-share-listing logic
//! (ISC-S7 / S8 / S9 / S10 / C19 / F25) lands in the M6 server build-out; this
//! skeleton exists to pin the method set and prove the handoff compiles and
//! serves before that logic is written.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use daemonseed_proto::v1 as wire;
use daemonseed_proto::v1::public_space_server::{PublicSpace, PublicSpaceServer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status};

/// Public-space service state.
///
/// The M6 build-out populates this with the in-RAM posts store, the single-slot
/// MOTD, the signer whitelist, the rating taxonomy, and the public-share index.
/// The spike carries no state — every method returns `unimplemented`.
#[derive(Debug, Default)]
pub struct PublicSpaceService {}

#[tonic::async_trait]
impl PublicSpace for PublicSpaceService {
    async fn get_motd(
        &self,
        _request: Request<wire::GetMotdRequest>,
    ) -> Result<Response<wire::GetMotdResponse>, Status> {
        Err(Status::unimplemented("M6 spike: GetMotd"))
    }

    async fn list_posts(
        &self,
        _request: Request<wire::ListPostsRequest>,
    ) -> Result<Response<wire::ListPostsResponse>, Status> {
        Err(Status::unimplemented("M6 spike: ListPosts"))
    }

    async fn get_taxonomy(
        &self,
        _request: Request<wire::GetTaxonomyRequest>,
    ) -> Result<Response<wire::GetTaxonomyResponse>, Status> {
        Err(Status::unimplemented("M6 spike: GetTaxonomy"))
    }

    async fn get_signer_whitelist(
        &self,
        _request: Request<wire::GetSignerWhitelistRequest>,
    ) -> Result<Response<wire::GetSignerWhitelistResponse>, Status> {
        Err(Status::unimplemented("M6 spike: GetSignerWhitelist"))
    }

    async fn upload_post(
        &self,
        _request: Request<wire::UploadPostRequest>,
    ) -> Result<Response<wire::UploadPostResponse>, Status> {
        Err(Status::unimplemented("M6 spike: UploadPost"))
    }

    async fn delete_post(
        &self,
        _request: Request<wire::DeletePostRequest>,
    ) -> Result<Response<wire::DeletePostResponse>, Status> {
        Err(Status::unimplemented("M6 spike: DeletePost"))
    }

    async fn list_public_shares(
        &self,
        _request: Request<wire::ListPublicSharesRequest>,
    ) -> Result<Response<wire::ListPublicSharesResponse>, Status> {
        Err(Status::unimplemented("M6 spike: ListPublicShares"))
    }
}

/// Adapts a single already-established, authenticated transport into something
/// tonic will serve.
///
/// `tonic`'s incoming-connection IO must impl [`Connected`]; the trait is
/// foreign and the wrapped transport types (`Connection<Authenticated, _>`, the
/// concrete `TlsStream`, or a test duplex half) are foreign too, so the impl
/// has to live on a local newtype. `ConnectInfo = ()` — the peer is already
/// authenticated, so tonic's per-connection info is redundant here.
#[derive(Debug)]
pub struct ServedConn<S>(pub S);

impl<S: Send + 'static> Connected for ServedConn<S> {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl<S: AsyncRead + Unpin> AsyncRead for ServedConn<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServedConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Serve [`PublicSpace`] over a single already-Authenticated transport until
/// the peer closes the connection.
///
/// The caller passes the connection only after the identity-proof exchange has
/// advanced it to `Authenticated` (daemonseed-core type-state), so reaching
/// application traffic without a verified peer is a compile error upstream
/// (ISC-C23). `S` is any authenticated transport: in production a
/// `Connection<Authenticated, TlsStream<TcpStream>>`; in tests an in-memory
/// duplex half.
pub async fn serve_public_space<S>(
    stream: S,
    service: PublicSpaceService,
) -> Result<(), tonic::transport::Error>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let incoming = tokio_stream::once(Ok::<_, io::Error>(ServedConn(stream)));
    tonic::transport::Server::builder()
        .add_service(PublicSpaceServer::new(service))
        .serve_with_incoming(incoming)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_proto::v1::public_space_client::PublicSpaceClient;
    use hyper_util::rt::TokioIo;
    use tonic::transport::Endpoint;

    /// The whole point of the M6 spike: tonic serves the PublicSpace service
    /// over ONE already-established `AsyncRead + AsyncWrite` connection (here an
    /// in-memory duplex half standing in for the post-Authenticated TLS
    /// stream), and a client reaches every RPC. The skeleton answers
    /// `Unimplemented`, which is exactly the signal that the request was routed
    /// through the generated service — proving the handoff end-to-end, not just
    /// at compile time.
    #[tokio::test]
    async fn serves_public_space_over_single_duplex_connection() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(serve_public_space(server_io, PublicSpaceService::default()));

        // One-shot connector hands the client-side duplex half to tonic.
        let mut client_io = Some(client_io);
        let channel = Endpoint::try_from("http://[::1]:50051")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_| {
                let io = client_io.take().expect("connector invoked exactly once");
                async move { Ok::<_, io::Error>(TokioIo::new(io)) }
            }))
            .await
            .expect("in-memory connect over duplex");

        let mut client = PublicSpaceClient::new(channel);
        let status = client
            .get_motd(wire::GetMotdRequest {})
            .await
            .expect_err("spike skeleton returns unimplemented");
        assert_eq!(status.code(), tonic::Code::Unimplemented);

        // Dropping the client closes the connection; the single-connection
        // server future then resolves.
        drop(client);
        let _ = server.await;
    }
}
