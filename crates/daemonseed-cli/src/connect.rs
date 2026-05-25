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

use core::str::FromStr;

use daemonseed_core::bootstrap::bundled;
use daemonseed_core::federation::store::{TrustStore, apply_trust};
use daemonseed_core::federation::trust::TrustDecision;
use daemonseed_core::handle::Handle;
use daemonseed_core::identity_proof::{ChannelBindingError, derive_channel_binding};
use daemonseed_core::storage::seeds::CounterState;
use daemonseed_core::version::{
    DefaultNegotiator, NegotiationError, ProtocolVersion, SUPPORTED, VersionError,
    VersionNegotiator,
};
use daemonseed_proto::v1 as wire;
use daemonseed_server::hello::{HelloError, write_frame};
use daemonseed_server::identity_proof::now_unix_ms;
use prost::Message;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::identity_proof::{ClientIdentity, RustlsClientExporter, run_client_identity_proof};
use crate::tofu_stub::AcceptAnyServerCert;

/// Default port the M4a server binds (per ISC-S5).
pub const DEFAULT_PORT: u16 = 443;

/// Reference-client per-server concurrent-connection cap (ISC-A-C10).
///
/// A conformant client opens at most this many simultaneous connections to a
/// single server, so a well-meaning client doesn't look like an attack pattern
/// to a Pi-4-class operator. This is a reference-client commitment, not a
/// protocol-enforced limit: it is not enforceable against a hostile
/// non-conformant client, and Sybil resistance proper is deferred to post-MVP.
/// The M5 CLI opens exactly one connection per invocation, so it honours the
/// cap trivially; a multi-connection client (TUI, M11) consults this constant.
pub const MAX_CONCURRENT_CONNECTIONS_PER_SERVER: usize = 4;

/// Outcome of a successful `connect`. Reaching this value means the
/// connection completed the full identity-proof exchange and is
/// `Authenticated` — there is no "negotiated but unauthenticated" success
/// (ISC-47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOutcome {
    /// The version both sides agreed to use.
    pub version: ProtocolVersion,
    /// The address actually dialled — useful for log lines.
    pub dialled: String,
    /// The verified server handle (its identity-proof envelope's
    /// `claimed_handle`, proven self-consistent and equal to the dialed
    /// server-id).
    pub server_handle: String,
    /// A non-blocking key-rotation notice (ISC-C22): `Some(fingerprint)` when a
    /// trusted-mode server presented a new key that wasn't dismissed. The
    /// connection still succeeded; the caller surfaces this to the user.
    pub rotation_notice: Option<String>,
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

/// Run the end-to-end connect: TCP → TLS → AppHello → AppHelloAck →
/// identity-proof → `Authenticated`.
///
/// `identity` is the client's signing identity (D8: the binary injects an
/// ephemeral one); `counters` carries the monotonic send counter (ISC-19)
/// and the per-server highest-seen counter (ISC-34). Returns Ok only after
/// the connection reaches `Authenticated` (ISC-47).
///
/// Caller-contract: `install_provider()` AND
/// `oxicrypt_module::initialize_with_profile(.., Cnsa2)` must have
/// returned `Ok(())` before invoking this. The integration test
/// harness drives both; the binary's `main()` does the same.
pub async fn connect(
    server_id: &str,
    address: &str,
    identity: &ClientIdentity,
    counters: &mut CounterState,
    store: &mut dyn TrustStore,
) -> Result<ConnectOutcome, ConnectError> {
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
    // valid `ServerName`. Use a constant placeholder string; the
    // identity-proof path below makes the wire-vs-name binding via the
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
    let version = parse_response(&bytes, server_id)?;

    // Identity-proof (ISC-S19): derive the channel binding from THIS client
    // TLS session, then prove identity mutually. The immutable borrow of the
    // rustls connection ends with this block, before the envelope I/O takes
    // `&mut tls`.
    let wire_version = version.to_wire();
    let channel_binding = {
        let (_io, conn) = tls.get_ref();
        derive_channel_binding(&RustlsClientExporter::new(conn), wire_version)
            .map_err(ConnectError::ChannelBinding)?
    };
    let now = now_unix_ms();
    let verified = run_client_identity_proof(
        &mut tls,
        channel_binding,
        wire_version,
        identity,
        now,
        counters,
        server_id,
    )
    .await
    // ISC-46 / A-C18: collapse every identity-proof failure cause to one
    // opaque "refused" outcome — the user is told nothing about which check
    // failed. The typed cause is dropped here on purpose.
    .map_err(|_cause| ConnectError::IdentityProofRefused)?;

    // C22 trust slider — the SINGLE dialed-identity authority (A-C18). The
    // identity-proof above proved only that the server's envelope is
    // self-consistent (handle hashes to pubkey); it deliberately does NOT gate
    // on the dialed server-id, so this layer owns that decision:
    //   - first contact (no pin): trusted mode requires presented hash-prefix
    //     == the configured server-id (a wrong server / non-grinded MITM is
    //     refused here); untrusted mode requires the pre-configured key.
    //   - established pin: trusted mode accepts the pin, or surfaces a notice
    //     and re-pins on an operator rotation (a different key — different
    //     hash); untrusted mode refuses any change.
    //   - unknown server: fail closed.
    // Keeping the binding here (where the pin lives) is exactly what lets a
    // trusted-mode key rotation surface a notice instead of being refused
    // upstream. The store must hold an entry for the dialed server (the user
    // added it before connecting).
    let server_handle = Handle::from_str(server_id).map_err(|_| ConnectError::BadServerId)?;
    let presented_prefix = *Handle::from_pubkey(None, verified.pubkey())
        // Crypto module is operational by here (the proof just verified), so
        // this is unreachable in practice; fail closed if it ever isn't.
        .map_err(|_| ConnectError::TrustRefused)?
        .hash_prefix();
    let rotation_notice =
        match apply_trust(store, &server_handle, verified.pubkey(), &presented_prefix) {
            TrustDecision::Accept => None,
            TrustDecision::AcceptWithRotation { fingerprint } => Some(fingerprint),
            TrustDecision::Refuse => return Err(ConnectError::TrustRefused),
        };

    Ok(ConnectOutcome {
        version,
        dialled: address.to_owned(),
        server_handle: verified.handle().to_owned(),
        rotation_notice,
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
    /// Deriving the identity-proof channel binding from the client TLS
    /// session failed.
    ChannelBinding(ChannelBindingError),
    /// The post-HELLO identity-proof exchange failed. Deliberately carries
    /// no sub-cause: a bad server signature, a stale timestamp, a counter
    /// replay, a channel-binding mismatch, and a wrong-server-identity all
    /// collapse to this single opaque outcome (ISC-46 / ISC-A-C18). The
    /// client fails closed with no partial-trust continuation (ISC-45).
    IdentityProofRefused,
    /// `<server-id>` could not be parsed as a `<name>#<12hex>` handle.
    BadServerId,
    /// The C22 trust slider refused the server's key: a trusted-mode
    /// first-contact hash mismatch (wrong server-id or a MITM with a
    /// non-grinded key), an untrusted-mode key mismatch (including a
    /// legitimate rotation the user must re-import), or an unknown server.
    /// Distinct from `IdentityProofRefused`: this is actionable (check the
    /// server-id / re-import the key), not deliberately opaque.
    TrustRefused,
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
            Self::ChannelBinding(e) => write!(f, "channel-binding derivation failed: {e}"),
            Self::IdentityProofRefused => write!(
                f,
                "server refused the connection during identity-proof \
                 (the cause is deliberately not disclosed)"
            ),
            Self::BadServerId => {
                write!(f, "server-id is not a valid <name>#<12hex> handle")
            }
            Self::TrustRefused => write!(
                f,
                "server key rejected by the trust slider: wrong server-id, a \
                 MITM, or a key that changed in untrusted mode — verify the \
                 server-id or re-import the operator's current key"
            ),
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
    fn concurrent_connection_cap_default_is_four() {
        // ISC-A-C10: reference-client per-server concurrent-connection cap.
        assert_eq!(MAX_CONCURRENT_CONNECTIONS_PER_SERVER, 4);
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
            server_source: None,
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
            server_source: None,
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
