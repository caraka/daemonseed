//! `APP_HELLO` / `APP_HELLO_ACK` / `APP_HELLO_REJECT` frame I/O.
//!
//! Wire frame shape (lives **here**, not in the proto schema): a 4-byte
//! big-endian `u32` length prefix followed by exactly that many bytes
//! of prost-encoded message. Length-prefix framing is the simplest
//! reliable shape that survives any TLS-record-boundary placement and
//! does not collide with the future tonic handoff (M4b transports
//! gRPC over h2 on a *fresh* h2 stream post-Authenticated; the HELLO
//! exchange owns the raw TLS stream up to that point).
//!
//! ## Framing constants
//!
//! - [`MAX_FRAME_BYTES`] caps the length prefix at 64 KiB. APP_HELLO
//!   carries a tiny number of `ProtocolVersion`s and short capability
//!   strings; a malformed peer sending a multi-gigabyte prefix is a
//!   straightforward DoS that the cap closes. The cap is also load-
//!   bearing for ISC-A-S3 (no resource exhaustion via single-frame
//!   amplification).
//!
//! ## Role uniformity (ISC-A-S6 / ISC-A-S9)
//!
//! The server's HELLO path branches **zero times** on intended peer
//! role: every connection arrives at this code path via the same
//! [`crate::runtime`] handler and exits through the same negotiated-
//! version or reject path. Trusted-mode and untrusted-mode clients,
//! and server-to-server peering connections, are wire-indistinguishable
//! to this layer. Per-pubkey policy lives downstream of HELLO in M4b's
//! identity-proof envelope.
//!
//! ## NO_COMMON_VERSION reject code
//!
//! Numeric constant [`REJECT_NO_COMMON_VERSION`] = 1, mirrored from
//! `daemonseed/v1/app_hello.proto`'s reject-code registry. The proto
//! file is canonical for the wire value; this constant exists so
//! Rust call sites avoid magic numbers and the test suite can
//! `assert_eq!` symbolically.

use core::fmt;
use std::error::Error;
use std::io;

use daemonseed_core::version::{
    DefaultNegotiator, NegotiationError, ProtocolVersion, SUPPORTED, VersionError,
    VersionNegotiator,
};
use daemonseed_proto::v1 as wire;
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Numeric `code` value carried by `APP_HELLO_REJECT` when there is no
/// MAJOR.MINOR overlap between the initiator's offer and the
/// responder's [`SUPPORTED`] set. Pinned to `1` in the proto file's
/// registry; never reuse, never repurpose, never reorder.
pub const REJECT_NO_COMMON_VERSION: i32 = 1;

/// Upper bound on the length-prefix value the framing layer accepts.
/// 64 KiB is comfortably larger than any sane HELLO (a few dozen
/// versions plus a short capability list); anything larger is treated
/// as a malformed peer and the connection is closed.
pub const MAX_FRAME_BYTES: usize = 65_536;

// ── Frame I/O primitives ─────────────────────────────────────────

/// Read one length-prefixed frame from `stream` and decode it as `M`.
///
/// Returns [`HelloError::FrameTooLarge`] if the prefix exceeds
/// [`MAX_FRAME_BYTES`] and [`HelloError::Decode`] if prost decoding
/// fails on the read bytes.
pub async fn read_frame<R, M>(stream: &mut R) -> Result<M, HelloError>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(HelloError::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(HelloError::FrameTooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(HelloError::Io)?;
    M::decode(buf.as_slice()).map_err(HelloError::Decode)
}

/// Encode `msg` and write it as a length-prefixed frame to `stream`.
///
/// Refuses to emit a frame whose encoded length exceeds
/// [`MAX_FRAME_BYTES`] — keeps the responder's behavior symmetric
/// with [`read_frame`]'s acceptance bound.
pub async fn write_frame<W, M>(stream: &mut W, msg: &M) -> Result<(), HelloError>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let bytes = msg.encode_to_vec();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(HelloError::FrameTooLarge {
            len: bytes.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(bytes.len()).expect("MAX_FRAME_BYTES fits in u32");
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(HelloError::Io)?;
    stream.write_all(&bytes).await.map_err(HelloError::Io)?;
    stream.flush().await.map_err(HelloError::Io)?;
    Ok(())
}

// ── Server-side HELLO orchestration ──────────────────────────────

/// Outcome of a server-side HELLO exchange. The server-side caller
/// (the per-connection runtime task) uses this to decide whether to
/// advance the type-state [`daemonseed_core::connection::Connection`]
/// to `Versioned` or close the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloOutcome {
    /// Negotiation succeeded with the carried version.
    Negotiated(ProtocolVersion),
    /// Negotiation failed and the responder wrote a
    /// `APP_HELLO_REJECT` with [`REJECT_NO_COMMON_VERSION`]. The
    /// caller should close the connection.
    Rejected {
        /// The peer's full offer, preserved verbatim so the test
        /// fixture / log line can render the actionable upgrade
        /// message.
        peer_offer: Vec<ProtocolVersion>,
    },
}

/// Drive the server's side of the post-TLS-handshake HELLO exchange.
///
/// Reads the initiator's `APP_HELLO`, applies [`DefaultNegotiator`]'s
/// "highest-mutual" selection, writes either an `APP_HELLO_ACK` with
/// the selected version or an `APP_HELLO_REJECT` carrying
/// [`REJECT_NO_COMMON_VERSION`] + this server's [`SUPPORTED`] list.
/// Returns the outcome so the caller can decide what to do next.
///
/// **Anti-criterion enforcement** (ISC-A-S9 / ISC-A2): this function
/// has zero branches conditioned on intended peer role. Whatever the
/// peer claims to be, the wire shape it sees back is identical.
///
/// **Anti-criterion enforcement** (ISC-A3): no per-pubkey state is
/// persisted. The `peer_offer` is held in a stack `Vec` for the
/// duration of the call and dropped on return.
pub async fn serve_hello<S>(stream: &mut S) -> Result<HelloOutcome, HelloError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello: wire::AppHello = read_frame(stream).await?;

    // Narrow proto3 `uint32 major/minor` into the core `u16` policy
    // shape. A malformed peer sending an out-of-range value gets the
    // same treatment as "no common version" — we don't share a wire
    // version with a peer whose own offer can't even round-trip our
    // type.
    let peer_offer = narrow_peer_offer(&hello.versions)?;

    let negotiator = DefaultNegotiator;
    match negotiator.select(&peer_offer) {
        Ok(selected) => {
            let ack = wire::AppHelloAck {
                version: Some(selected.to_wire()),
            };
            write_frame(stream, &ack).await?;
            Ok(HelloOutcome::Negotiated(selected))
        }
        Err(NegotiationError::NoCommonVersion { peer_supported }) => {
            let reject = wire::AppHelloReject {
                code: REJECT_NO_COMMON_VERSION,
                server_supported: SUPPORTED.iter().map(|v| v.to_wire()).collect(),
            };
            write_frame(stream, &reject).await?;
            Ok(HelloOutcome::Rejected {
                peer_offer: peer_supported,
            })
        }
        // `select` only ever returns `NoCommonVersion` on its failure
        // path; the other discriminants of `NegotiationError` are for
        // `verify_ack` / wire-narrowing. Treating an unreachable
        // discriminant as a panic is the right call — silently
        // re-mapping would obscure a real policy-layer change.
        Err(other) => unreachable!("VersionNegotiator::select returned {other:?}"),
    }
}

/// Narrow `repeated wire::ProtocolVersion` into a `Vec<ProtocolVersion>`,
/// surfacing any `u32`-too-large field as the same
/// [`HelloError::WireOutOfRange`] discriminant the wire-shape layer
/// produces elsewhere.
fn narrow_peer_offer(wire: &[wire::ProtocolVersion]) -> Result<Vec<ProtocolVersion>, HelloError> {
    let mut out = Vec::with_capacity(wire.len());
    for w in wire {
        out.push(ProtocolVersion::try_from_wire(w).map_err(HelloError::WireOutOfRange)?);
    }
    Ok(out)
}

// ── Errors ───────────────────────────────────────────────────────

/// Failures the HELLO frame layer can surface.
#[derive(Debug)]
pub enum HelloError {
    /// Read or write failed on the underlying transport.
    Io(io::Error),
    /// Decoding the bytes after a length prefix failed at the prost
    /// layer — the peer sent malformed protobuf for the message type
    /// we expected.
    Decode(prost::DecodeError),
    /// The length prefix exceeded [`MAX_FRAME_BYTES`]. Either the peer
    /// is malformed or this is a DoS attempt; close the connection.
    FrameTooLarge { len: usize, max: usize },
    /// The peer sent a `ProtocolVersion` whose `major` or `minor`
    /// exceeded `u16::MAX`. Treated the same as "no common version"
    /// at the call site — see `serve_hello`'s peer-offer narrowing.
    WireOutOfRange(VersionError),
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "HELLO frame I/O failed: {e}"),
            Self::Decode(e) => write!(f, "HELLO frame decode failed: {e}"),
            Self::FrameTooLarge { len, max } => {
                write!(f, "HELLO frame prefix {len} bytes exceeds cap {max}")
            }
            Self::WireOutOfRange(e) => write!(f, "HELLO peer wire shape out of range: {e}"),
        }
    }
}

impl Error for HelloError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    /// Helper: build an `AppHello` with one or more versions, MVP
    /// `tcp-tls13` transport capability, no `server_source`.
    fn mvp_hello(versions: &[(u16, u16)]) -> wire::AppHello {
        wire::AppHello {
            versions: versions
                .iter()
                .map(|(maj, min)| wire::ProtocolVersion {
                    major: *maj as u32,
                    minor: *min as u32,
                })
                .collect(),
            transport_capabilities: vec!["tcp-tls13".to_owned()],
            server_source: None,
        }
    }

    /// Server `serve_hello` happy path — peer offers `1.0`, server's
    /// MVP `SUPPORTED` is `[1.0]`, server writes `AppHelloAck { 1.0 }`
    /// and returns `Negotiated(1.0)`. Closes ISC-37 / 38 / 41.
    #[tokio::test]
    async fn serve_hello_negotiates_mutual_version() {
        let (mut client_end, mut server_end) = duplex(64 * 1024);

        let hello = mvp_hello(&[(1, 0)]);
        let client_handle = tokio::spawn(async move {
            write_frame(&mut client_end, &hello).await.unwrap();
            let ack: wire::AppHelloAck = read_frame(&mut client_end).await.unwrap();
            ack
        });

        let outcome = serve_hello(&mut server_end).await.unwrap();
        assert_eq!(
            outcome,
            HelloOutcome::Negotiated(ProtocolVersion::new(1, 0))
        );

        let ack = client_handle.await.unwrap();
        assert_eq!(
            ack.version.unwrap(),
            wire::ProtocolVersion { major: 1, minor: 0 }
        );
    }

    /// Server rejects when there's no MAJOR.MINOR overlap. The reject
    /// frame carries `REJECT_NO_COMMON_VERSION` and the server's full
    /// `SUPPORTED` list. Closes ISC-39.
    #[tokio::test]
    async fn serve_hello_rejects_with_no_common_version() {
        let (mut client_end, mut server_end) = duplex(64 * 1024);

        let hello = mvp_hello(&[(2, 0), (2, 1)]);
        let client_handle = tokio::spawn(async move {
            write_frame(&mut client_end, &hello).await.unwrap();
            let reject: wire::AppHelloReject = read_frame(&mut client_end).await.unwrap();
            reject
        });

        let outcome = serve_hello(&mut server_end).await.unwrap();
        match outcome {
            HelloOutcome::Rejected { peer_offer } => {
                assert_eq!(
                    peer_offer,
                    vec![ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 1)],
                    "rejected outcome must preserve the peer offer verbatim"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }

        let reject = client_handle.await.unwrap();
        assert_eq!(reject.code, REJECT_NO_COMMON_VERSION);
        assert_eq!(
            reject.server_supported,
            SUPPORTED.iter().map(|v| v.to_wire()).collect::<Vec<_>>(),
            "responder echoes its full SUPPORTED list"
        );
    }

    /// Length-prefix cap closes the obvious DoS — a peer sending a
    /// `u32::MAX` length prefix would otherwise force a huge
    /// allocation. We reject the prefix before reading the body.
    #[tokio::test]
    async fn read_frame_rejects_oversize_prefix() {
        let (mut client_end, mut server_end) = duplex(16);

        // Write a prefix one byte larger than the cap; no body bytes.
        let oversize = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
        tokio::spawn(async move {
            client_end.write_all(&oversize.to_be_bytes()).await.unwrap();
        });

        let err = read_frame::<_, wire::AppHello>(&mut server_end)
            .await
            .expect_err("prefix exceeds cap");
        match err {
            HelloError::FrameTooLarge { len, max } => {
                assert_eq!(len, MAX_FRAME_BYTES + 1);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    /// Round-trip an MVP `AppHello` through `write_frame`/`read_frame`
    /// to pin the wire-shape regression anchor commit 6 will lean on.
    #[tokio::test]
    async fn frame_round_trips_app_hello_mvp_offer() {
        let (mut a, mut b) = duplex(64 * 1024);
        let original = mvp_hello(&[(1, 0)]);
        let original_clone = original.clone();
        tokio::spawn(async move {
            write_frame(&mut a, &original_clone).await.unwrap();
        });
        let decoded: wire::AppHello = read_frame(&mut b).await.unwrap();
        assert_eq!(decoded, original);
    }

    /// Peer sending a `ProtocolVersion` with `major > u16::MAX` is
    /// surfaced as `WireOutOfRange`, not as a panic. Mirrors the
    /// `core::version::ProtocolVersion::try_from_wire` narrowing rule.
    #[tokio::test]
    async fn serve_hello_surfaces_out_of_range_wire_value() {
        let (mut client_end, mut server_end) = duplex(64 * 1024);

        let hello = wire::AppHello {
            versions: vec![wire::ProtocolVersion {
                major: u32::from(u16::MAX) + 1,
                minor: 0,
            }],
            transport_capabilities: vec!["tcp-tls13".to_owned()],
            server_source: None,
        };
        tokio::spawn(async move {
            write_frame(&mut client_end, &hello).await.unwrap();
        });

        let err = serve_hello(&mut server_end)
            .await
            .expect_err("major out of u16 range");
        assert!(matches!(err, HelloError::WireOutOfRange(_)));
    }
}
