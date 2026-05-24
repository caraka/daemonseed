//! `daemonseed-cli connect <server-id>` — drives the M4a wire round-trip.
//!
//! Resolves the address (bundled bootstrap anchor or `--address`
//! override), opens a TLS-1.3 connection to the configured port,
//! exchanges the post-handshake APP_HELLO frame, returns the negotiated
//! `ProtocolVersion` on success.
//!
//! The function is split out of `main.rs` so the integration test in
//! commit 6 can drive it without going through clap.

use core::fmt;
use std::error::Error;
use std::io;
use std::sync::Arc;

use daemonseed_core::bootstrap::bundled;
use daemonseed_core::version::{
    DefaultNegotiator, NegotiationError, ProtocolVersion, SUPPORTED, VersionError,
    VersionNegotiator,
};
use daemonseed_proto::v1 as wire;
use daemonseed_server::hello::{HelloError, write_frame};
use prost::Message;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::tofu_stub::AcceptAnyServerCert;

/// Default port the M4a server binds (per ISC-S5).
pub const DEFAULT_PORT: u16 = 443;

/// Outcome of a successful `connect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOutcome {
    /// The version both sides agreed to use.
    pub version: ProtocolVersion,
    /// The address actually dialled — useful for log lines.
    pub dialled: String,
}

/// Resolve `<server-id>` to a dial address.
///
/// Priority:
/// 1. `address_override` if `Some` (the CLI's `--address` flag)
/// 2. Bundled anchor `canonical.address` if its `server_id` matches
/// 3. Otherwise [`ConnectError::NoAddress`]
pub fn resolve_address(
    server_id: &str,
    address_override: Option<&str>,
) -> Result<String, ConnectError> {
    if let Some(addr) = address_override {
        return Ok(addr.to_owned());
    }

    if let Some(canonical) = bundled().canonical.as_ref()
        && canonical.server_id == server_id
    {
        // Bundled anchor stores hostname only; append the default
        // port. Operators publishing a non-default port use
        // `--address` for now (a richer anchor schema lands in M5
        // when federation surfaces grow).
        return Ok(format!("{}:{DEFAULT_PORT}", canonical.address));
    }

    Err(ConnectError::NoAddress {
        server_id: server_id.to_owned(),
    })
}

/// Build the M4a client-side `ClientConfig`.
///
/// Identical posture to the server: CNSA 2.0 hybrid provider, TLS 1.3
/// only, ALPN exactly `[b"h2"]`. The custom `ServerCertVerifier`
/// accepts any cert — see `tofu_stub::AcceptAnyServerCert` for the M4a
/// caveat and M4b plan.
pub fn build_client_config() -> Result<ClientConfig, rustls::Error> {
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(AcceptAnyServerCert::from_installed_provider())
        .with_no_client_auth();

    cfg.alpn_protocols = vec![b"h2".to_vec()];
    // Empty root store is fine — the AcceptAny verifier bypasses chain
    // validation anyway. M4b replaces both pieces in one swap.
    let _root_store: RootCertStore = RootCertStore::empty();
    Ok(cfg)
}

/// Run the end-to-end connect: TCP → TLS → AppHello → AppHelloAck.
///
/// Caller-contract: `install_provider()` AND
/// `oxicrypt_module::initialize_with_profile(.., Cnsa2)` must have
/// returned `Ok(())` before invoking this. The integration test
/// harness drives both; the binary's `main()` does the same.
pub async fn connect(server_id: &str, address: &str) -> Result<ConnectOutcome, ConnectError> {
    let client_cfg = build_client_config().map_err(|e| ConnectError::Rustls(e.to_string()))?;
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect(address)
        .await
        .map_err(|e| ConnectError::Tcp {
            address: address.to_owned(),
            source: e,
        })?;

    // SNI: the cert is self-signed so the name doesn't gate verification
    // (AcceptAny bypasses chain), but rustls still requires *some*
    // valid `ServerName`. Use a constant placeholder string; the M4b
    // identity-proof path makes the wire-vs-name binding via the
    // server-id pubkey-hash anyway.
    let server_name =
        ServerName::try_from("daemonseed.invalid").expect("static placeholder ServerName parses");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ConnectError::TlsHandshake(e.to_string()))?;

    let hello = wire::AppHello {
        versions: SUPPORTED.iter().map(|v| v.to_wire()).collect(),
        transport_capabilities: vec!["tcp-tls13".to_owned()],
        server_source: None,
    };
    write_frame(&mut tls, &hello)
        .await
        .map_err(ConnectError::HelloWrite)?;

    // Peek at the first byte of the next frame to disambiguate
    // AppHelloAck vs AppHelloReject. tonic-style frame discrimination
    // would normally use a different field tag; here we read the
    // length prefix, then decode generously: try Ack, if missing the
    // `version` field assume Reject. The prost types are distinct
    // shapes so we use a tagged probe.
    //
    // Simpler shape: read the response as Ack first; if Ack.version
    // is None *and* the body had any bytes, fall back to Reject
    // parse. Cleaner shape: define an oneof in the proto. For M4a,
    // we exploit the structural difference — Ack has tag 1 (message
    // ProtocolVersion), Reject has tag 1 (int32 code). We try Ack
    // first because the happy path is the common case; if the
    // version Option arrives populated, we Ack. If not, we re-read
    // the raw bytes as a Reject. To avoid double-reading we capture
    // the bytes once.
    let bytes = read_response_frame(&mut tls).await?;
    parse_response(&bytes, server_id).map(|v| ConnectOutcome {
        version: v,
        dialled: address.to_owned(),
    })
}

/// Read one length-prefixed frame body into a `Vec<u8>` so we can
/// try-decode as Ack first, then Reject. Uses
/// `daemonseed_server::hello::read_frame` indirectly by re-walking
/// the length prefix here — keeps the response-shape ambiguity
/// confined to one place.
async fn read_response_frame<S>(stream: &mut S) -> Result<Vec<u8>, ConnectError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| ConnectError::HelloWrite(HelloError::Io(e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > daemonseed_server::hello::MAX_FRAME_BYTES {
        return Err(ConnectError::HelloWrite(HelloError::FrameTooLarge {
            len,
            max: daemonseed_server::hello::MAX_FRAME_BYTES,
        }));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| ConnectError::HelloWrite(HelloError::Io(e)))?;
    Ok(buf)
}

/// Decode a response-frame body as either `AppHelloAck` or
/// `AppHelloReject`. Verifies the server's pick against our offer per
/// ISC-C23.
fn parse_response(bytes: &[u8], _server_id: &str) -> Result<ProtocolVersion, ConnectError> {
    // Try Ack first. If decode succeeds AND version is populated,
    // verify and return. If Ack decodes but version is None, the body
    // is ambiguous — fall through to Reject parse.
    if let Ok(ack) = wire::AppHelloAck::decode(bytes)
        && let Some(picked) = ack.version
    {
        let picked =
            ProtocolVersion::try_from_wire(&picked).map_err(ConnectError::WireOutOfRange)?;
        let negotiator = DefaultNegotiator;
        match negotiator.verify_ack(picked) {
            Ok(()) => return Ok(picked),
            Err(NegotiationError::OutOfSetAck { claimed }) => {
                return Err(ConnectError::OutOfSetAck { claimed });
            }
            Err(other) => unreachable!("verify_ack returned {other:?}"),
        }
    }

    // Reject path — decode as Reject, surface NoCommonVersion with
    // the responder's full SUPPORTED list.
    let reject = wire::AppHelloReject::decode(bytes)
        .map_err(|e| ConnectError::HelloDecode(e.to_string()))?;
    if reject.code == daemonseed_server::hello::REJECT_NO_COMMON_VERSION {
        let server_supported = reject
            .server_supported
            .iter()
            .map(ProtocolVersion::try_from_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ConnectError::WireOutOfRange)?;
        return Err(ConnectError::NoCommonVersion { server_supported });
    }
    Err(ConnectError::UnknownRejectCode { code: reject.code })
}

/// `connect` failure modes.
#[derive(Debug)]
pub enum ConnectError {
    /// `<server-id>` didn't match the bundled canonical anchor and no
    /// `--address` override was supplied.
    NoAddress { server_id: String },
    /// TCP dial failed.
    Tcp { address: String, source: io::Error },
    /// rustls `ClientConfig` build failed.
    Rustls(String),
    /// TLS handshake failed.
    TlsHandshake(String),
    /// AppHello write failed (length-prefix or body).
    HelloWrite(HelloError),
    /// Prost decode of the response body failed.
    HelloDecode(String),
    /// Responder's `AppHelloAck` carried a version not in our offer
    /// — protocol violation per ISC-C23.
    OutOfSetAck { claimed: ProtocolVersion },
    /// Responder's `AppHelloReject` carried `NO_COMMON_VERSION` + a
    /// non-empty `server_supported` — actionable upgrade message.
    NoCommonVersion {
        server_supported: Vec<ProtocolVersion>,
    },
    /// Responder's `AppHelloReject` carried an unrecognized code
    /// (forward-compat path — future additive reject codes from a
    /// newer responder).
    UnknownRejectCode { code: i32 },
    /// Responder's wire-shape `ProtocolVersion` had a `u32` field
    /// out of `u16` range.
    WireOutOfRange(VersionError),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAddress { server_id } => write!(
                f,
                "no address for server-id {server_id:?} (bundled anchor empty or mismatched; \
                 use --address <host:port> to override)"
            ),
            Self::Tcp { address, source } => write!(f, "tcp connect to {address} failed: {source}"),
            Self::Rustls(e) => write!(f, "rustls ClientConfig build failed: {e}"),
            Self::TlsHandshake(e) => write!(f, "TLS handshake failed: {e}"),
            Self::HelloWrite(e) => write!(f, "AppHello frame I/O failed: {e}"),
            Self::HelloDecode(e) => write!(f, "AppHello response decode failed: {e}"),
            Self::OutOfSetAck { claimed } => write!(
                f,
                "server picked version {claimed} which is not in our offer — closing per ISC-C23"
            ),
            Self::NoCommonVersion { server_supported } => {
                write!(
                    f,
                    "no common wire-protocol version; server supports {server_supported:?}, \
                     this client supports {SUPPORTED:?} — upgrade or downgrade to bridge"
                )
            }
            Self::UnknownRejectCode { code } => {
                write!(f, "server sent AppHelloReject with unknown code {code}")
            }
            Self::WireOutOfRange(e) => write!(f, "server wire shape out of range: {e}"),
        }
    }
}

impl Error for ConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tcp { source, .. } => Some(source),
            Self::HelloWrite(e) => Some(e),
            _ => None,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_address_uses_explicit_override() {
        let addr = resolve_address("anything", Some("127.0.0.1:8443")).unwrap();
        assert_eq!(addr, "127.0.0.1:8443");
    }

    #[test]
    fn resolve_address_errors_when_no_bundled_anchor_and_no_override() {
        let err =
            resolve_address("nobody#000000000000", None).expect_err("M2 bundled anchor is empty");
        match err {
            ConnectError::NoAddress { server_id } => assert_eq!(server_id, "nobody#000000000000"),
            other => panic!("expected NoAddress, got {other:?}"),
        }
    }

    /// Build a ClientConfig and assert the TLS-shape invariants the
    /// CLI shares with the server.
    #[test]
    fn build_client_config_pins_alpn_h2() {
        oxitls_rustls_provider::testing::ensure_module_operational();
        let _ = daemonseed_server::tls::install_provider();
        let cfg = build_client_config().expect("ClientConfig build");
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }

    /// Use the framing helper to assemble a synthetic AppHelloAck and
    /// confirm `parse_response` accepts it.
    #[test]
    fn parse_response_accepts_in_set_ack() {
        use prost::Message;
        let ack = wire::AppHelloAck {
            version: Some(wire::ProtocolVersion { major: 1, minor: 0 }),
        };
        let bytes = ack.encode_to_vec();
        let v = parse_response(&bytes, "test#000000000000").unwrap();
        assert_eq!(v, ProtocolVersion::new(1, 0));
    }

    #[test]
    fn parse_response_rejects_out_of_set_ack() {
        use prost::Message;
        let ack = wire::AppHelloAck {
            version: Some(wire::ProtocolVersion { major: 2, minor: 0 }),
        };
        let bytes = ack.encode_to_vec();
        let err = parse_response(&bytes, "test#000000000000")
            .expect_err("server picked something we didn't offer");
        match err {
            ConnectError::OutOfSetAck { claimed } => {
                assert_eq!(claimed, ProtocolVersion::new(2, 0));
            }
            other => panic!("expected OutOfSetAck, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_surfaces_no_common_version_reject() {
        use prost::Message;
        let reject = wire::AppHelloReject {
            code: daemonseed_server::hello::REJECT_NO_COMMON_VERSION,
            server_supported: vec![
                wire::ProtocolVersion { major: 2, minor: 0 },
                wire::ProtocolVersion { major: 2, minor: 1 },
            ],
        };
        let bytes = reject.encode_to_vec();
        let err = parse_response(&bytes, "test#000000000000").expect_err("rejected");
        match err {
            ConnectError::NoCommonVersion { server_supported } => {
                assert_eq!(
                    server_supported,
                    vec![ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 1)]
                );
            }
            other => panic!("expected NoCommonVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_surfaces_unknown_reject_code() {
        use prost::Message;
        let reject = wire::AppHelloReject {
            code: 99, // future additive code; M4a doesn't know it
            server_supported: vec![],
        };
        let bytes = reject.encode_to_vec();
        let err = parse_response(&bytes, "test#000000000000").expect_err("unknown code");
        match err {
            ConnectError::UnknownRejectCode { code } => assert_eq!(code, 99),
            other => panic!("expected UnknownRejectCode, got {other:?}"),
        }
    }
}
