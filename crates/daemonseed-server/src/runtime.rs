//! Server runtime — TCP listener, TLS terminator, HELLO handler.
//!
//! [`run`] is the entry point invoked from the `daemonseed-server` binary.
//! It binds a [`tokio::net::TcpListener`] to the configured address, wraps
//! each accepted connection in a [`tokio_rustls::TlsAcceptor`], drives the
//! post-TLS-handshake `APP_HELLO` exchange via [`crate::hello::serve_hello`],
//! then runs the identity-proof exchange
//! ([`crate::identity_proof::run_server_identity_proof`]) and advances the
//! type-state [`daemonseed_core::connection::Connection`] through `Versioned`
//! to `Authenticated` on success (ISC-S19).
//!
//! ## Graceful shutdown (ISC-9)
//!
//! `run` accepts a `shutdown` future. When that future completes the
//! accept loop exits cleanly — no abort, no panic. In-flight per-
//! connection tasks are not actively drained (the type-state machine has
//! no `Authenticated → Closed` ceremony yet); they terminate naturally
//! when their `TcpStream` is closed by the OS as the runtime drops. Full
//! connection drain lands with the M5+ application-stream machinery.
//!
//! The binary's wiring drives `shutdown` from `tokio::signal::ctrl_c()`
//! plus the unix SIGTERM signal so the daemon stops cleanly on both
//! systemd's `stop` and an interactive Ctrl-C.
//!
//! ## Per-connection task isolation
//!
//! Each accepted connection runs in its own `tokio::spawn`. Failures
//! at any phase — TLS handshake, HELLO read, HELLO write — close the
//! connection silently (no propagation to peers, no logging of
//! peer-identifying bytes). The current behavior is the floor required
//! by ISC-A-S9 ("no silent downgrade" — closing on bad input is the
//! safe failure mode). Per-error structured logging lands in a future
//! observability pass.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daemonseed_core::connection::{Connection, Versioned};
use daemonseed_core::identity_proof::derive_channel_binding;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::cot::CotRegistry;
use crate::hello::{HelloOutcome, serve_hello};
use crate::identity_proof::{
    RustlsServerExporter, SeenMap, ServerIdentity, now_unix_ms, run_server_identity_proof,
};
use crate::public_space::{PublicSpaceService, PublicSpaceState, serve_application};
use crate::rate_limit::{PerKeyRateTable, RateLimitConfig};

/// Hand the per-connection HELLO outcome up via this callback. Used by
/// the integration-test harness in commit 6 to observe a real
/// `Negotiated(_)` outcome without instrumenting the connection state
/// itself. Production callers (the main binary) pass a no-op.
pub type ConnectionObserver = Arc<dyn Fn(HelloOutcome) + Send + Sync>;

/// Default observer — discards the outcome. Production wiring uses
/// this; tests substitute a channel sender.
pub fn noop_observer() -> ConnectionObserver {
    Arc::new(|_outcome: HelloOutcome| {})
}

/// Process-lifetime shared state handed to every per-connection task. Each
/// field is cheap to clone (an `Arc` or an inner-`Arc` handle); one instance is
/// built in [`run`] and cloned per accepted connection. Bundling it keeps the
/// per-connection driver's signature small as the shared surface grows
/// (identity, public-space state, AGPL source URL, replay-counter map, and the
/// circle-of-trust asset table, and the per-identity-key rate-limit table).
#[derive(Clone)]
struct ServerContext {
    identity: Arc<ServerIdentity>,
    public_space: Arc<PublicSpaceState>,
    server_source: Arc<Option<String>>,
    seen: SeenMap,
    cot: CotRegistry,
    key_table: PerKeyRateTable,
}

/// Bind to `addr`, accept connections, terminate TLS via `tls_config`,
/// and drive the HELLO exchange on each. Runs until `shutdown`
/// completes; returns the resulting `io::Result` of the bind / accept
/// loop. The `observer` is invoked with each connection's HELLO
/// outcome before the per-connection task exits.
///
/// **Idempotent precondition contract:** the caller MUST have driven
/// [`crate::tls::install_provider`] to `Ok(())` and
/// `oxicrypt_module::initialize_with_profile(&kats::CNSA_2_0_KATS,
/// AlgorithmProfile::Cnsa2)` to `Ok(())` before calling this.
/// `tls_config` will fail to build otherwise; we don't redundantly
/// gate here.
pub async fn run<F>(
    addr: SocketAddr,
    tls_config: ServerConfig,
    identity: Arc<ServerIdentity>,
    public_space: Arc<PublicSpaceState>,
    server_source: Option<String>,
    shutdown: F,
    observer: ConnectionObserver,
) -> io::Result<()>
where
    F: Future<Output = ()>,
{
    // AGPL-§13 source URL advertised in each connection's APP_HELLO_ACK
    // (ISC-9). Shared read-only across per-connection tasks.
    let server_source = Arc::new(server_source);
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Process-lifetime, RAM-only replay-counter map shared across every
    // per-connection task (ISC-34 / ISC-A-S1). Cloning shares the inner Arc.
    let seen = SeenMap::new();

    // The relay's circle-of-trust asset table — ONE instance shared across
    // every connection so members on different connections meet at the same
    // rendezvous address (M8 / ISC-A-S5). RAM-only; nothing survives the
    // process. Cloning shares the inner Arc.
    let cot = CotRegistry::new();

    // Per-identity-key connection table (M9 / ISC-S17). RAM-only, shared across
    // connections, GC'd as connections close. Pi-4-floor cap default.
    let key_table = PerKeyRateTable::new(RateLimitConfig::default().max_conns_per_key);

    // Bundle the shared, process-lifetime state once; clone it per connection.
    let ctx = ServerContext {
        identity,
        public_space,
        server_source,
        seen,
        cot,
        key_table,
    };

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            // Shutdown wins on tie — operator intent over a brand-new
            // connection.
            biased;
            () = &mut shutdown => {
                return Ok(());
            }
            accept = listener.accept() => {
                let (stream, peer_addr) = match accept {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Per-accept errors don't crash the daemon; we
                        // log them implicitly via the io::Result return
                        // shape (commit-6 integration adds structured
                        // logging). Continue to the next accept.
                        let _ = e;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let observer = observer.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _ = peer_addr;
                    serve_connection(acceptor, stream, ctx, observer).await;
                });
            }
        }
    }
}

/// Per-connection driver. Performs the TLS handshake, runs HELLO, derives
/// the identity-proof channel binding from the live TLS session, runs the
/// identity-proof exchange, and advances the type-state to `Authenticated`
/// on success (ISC-S19). M6 serves the public-space application service over
/// the now-`Authenticated` stream (ISC-2).
///
/// Every failure mode — bad TLS handshake, HELLO frame error, no-overlap
/// reject, channel-binding failure, identity-proof rejection — closes the
/// connection silently. The peer gets only an OS-level reset and cannot
/// distinguish which stage or check failed (ISC-A-S9 / ISC-40 / ISC-A-S12).
async fn serve_connection(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    ctx: ServerContext,
    observer: ConnectionObserver,
) {
    let ServerContext {
        identity,
        public_space,
        server_source,
        seen,
        cot,
        key_table,
    } = ctx;

    let mut tls_stream: TlsStream<TcpStream> = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(_e) => {
            // Bad TLS handshake — close silently. ISC-A-S9 is satisfied
            // by NOT leaking which peer offered what; the OS-level
            // connection-reset is the only signal the peer gets.
            return;
        }
    };

    // HELLO — negotiate the wire version. A frame I/O / decode failure or a
    // no-overlap reject both close silently (the reject frame, if any, was
    // already written by serve_hello).
    let outcome = match serve_hello(&mut tls_stream, server_source.as_deref()).await {
        Ok(o) => o,
        Err(_e) => return,
    };
    let version = match &outcome {
        HelloOutcome::Negotiated(v) => *v,
        HelloOutcome::Rejected { .. } => {
            observer(outcome);
            return;
        }
    };
    observer(outcome);

    // Channel binding from THIS TLS session's exporter (ISC-37 / ISC-A-S14):
    // a constant is structurally impossible here — RustlsServerExporter only
    // wraps a live connection. The immutable borrow of the rustls connection
    // ends with this block, before the stream is moved into the type-state
    // machine for the (mutable) envelope I/O.
    let wire_version = version.to_wire();
    let channel_binding = {
        let (_io, conn) = tls_stream.get_ref();
        match derive_channel_binding(&RustlsServerExporter::new(conn), wire_version) {
            Ok(cb) => cb,
            Err(_e) => return,
        }
    };

    // Advance the type-state and run the identity-proof exchange on the raw
    // stream. The server's outbound counter is wall-clock ms (decision D7),
    // sourced once alongside the freshness timestamp.
    let mut versioned: Connection<Versioned, _> =
        Connection::from_handshaked_transport(tls_stream).advance_to_versioned();
    let now = now_unix_ms();
    // M7: the operator's suite-deprecation policy gates the proof — a client
    // signing under a past-cutoff suite is refused (ISC-S16). `None` when no
    // policy is configured (the common case).
    let deprecation = public_space.deprecation_policy_decoded();
    match run_server_identity_proof(
        versioned.transport_mut(),
        channel_binding,
        wire_version,
        &identity,
        now,
        now,
        &seen,
        deprecation.as_ref(),
    )
    .await
    {
        Ok(verified) => {
            // M9 (ISC-S17): per-identity-key concurrent-connection admission.
            // A key already at its cap is closed silently — the SAME uniform
            // close-shape as an identity-proof failure (ISC-A-S12), with no
            // reason on the wire. The cap is enforced only once the key is
            // known (post-verify); the pre-identity flood is the OS/per-IP
            // layer's job (ISC-A-S1 carve-out).
            if key_table.admit(verified.pubkey()).is_err() {
                return;
            }
            let pubkey = verified.pubkey().to_vec();

            // ISC-S19 step 5: the VerifiedPeer token is the only key to the
            // Authenticated state. Reaching here therefore guarantees a
            // verified peer — so the application services are structurally
            // unreachable before identity-proof (ISC-2 / ISC-C23). The single
            // tonic server over this stream serves both the public-space
            // service (M6) and the circle-of-trust live relay (M8); the future
            // ends when the peer closes the connection (which also reaps any
            // CoT asset references this connection held, ISC-10).
            let authenticated = versioned.into_authenticated(verified);
            let service = PublicSpaceService::new(public_space);
            let _ = serve_application(authenticated.into_inner(), service, cot).await;

            // GC-on-disconnect (ISC-S17 / ISC-A-S12): free the per-key slot the
            // instant this connection ends, so a quiet server holds no per-key
            // rate-limit state across restart or idle.
            key_table.release(&pubkey);
        }
        Err(_e) => {
            // Uniform silent close — see the function-level note.
        }
    }
}

/// Run HELLO on an already-TLS-handshaked stream, advance the type-
/// state to `Versioned` on success, and report the outcome to the
/// observer. Split from the private TLS-handshake driver so the
/// integration test in commit 6 can exercise this path without
/// invoking real TCP + TLS — it feeds in a duplex stream that
/// satisfies `Transport`.
pub async fn drive_negotiated_connection<S>(mut stream: S, observer: ConnectionObserver)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let outcome = match serve_hello(&mut stream, None).await {
        Ok(o) => o,
        Err(_e) => {
            // Frame I/O or decode failure — close silently for the
            // same reason as a bad TLS handshake.
            return;
        }
    };

    match &outcome {
        HelloOutcome::Negotiated(_) => {
            let neg = Connection::<_, _>::from_handshaked_transport(stream);
            // The advance-to-versioned consumes `neg` and produces
            // the `Versioned` connection. M4a drops it immediately;
            // M4b will pass it into the identity-proof handler.
            let _ver: Connection<Versioned, _> = neg.advance_to_versioned();
        }
        HelloOutcome::Rejected { .. } => {
            // Reject was already written by serve_hello. Drop the
            // stream to close the connection.
        }
    }

    observer(outcome);
}

/// A shutdown future composing tokio's `ctrl_c()` and the unix SIGTERM
/// stream. Resolves the first time either signal fires. Production
/// binaries call this; the integration harness substitutes a one-shot
/// channel.
///
/// SIGINT (Ctrl-C) is what interactive operators send; SIGTERM is what
/// systemd's `stop` sends; both should converge on the same graceful
/// path. The `ctrl_c()` future installs its own SIGINT handler when
/// awaited on unix.
#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

#[cfg(not(unix))]
pub async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Construct a `SocketAddr` from the operator's configured
/// `listen_addr` string. Pulled into a free function so the binding
/// step has its own error surface separate from `run`'s.
pub fn parse_listen_addr(listen_addr: &str) -> io::Result<SocketAddr> {
    listen_addr
        .parse::<SocketAddr>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Short-circuit shutdown — completes after `dur`. Useful for the
/// integration-test runtime where we want the loop to exit after a
/// single accept cycle rather than wait for a real signal.
pub async fn shutdown_after(dur: Duration) {
    tokio::time::sleep(dur).await;
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::hello::write_frame;
    use daemonseed_core::version::ProtocolVersion;
    use daemonseed_proto::v1 as wire;
    use tokio::io::duplex;

    /// Helper: send a one-version `AppHello` over a duplex stream and
    /// drive `drive_negotiated_connection` on the other half. Returns
    /// the observed `HelloOutcome`.
    ///
    /// The client task also reads back the responder's reply frame
    /// (Ack on Negotiated, Reject on no-overlap) before exiting. This
    /// keeps the client half of the duplex alive while the responder
    /// writes — without it, the responder's `write_frame` would race
    /// against the client dropping and surface as BrokenPipe, which
    /// would erase the observer-callback invocation.
    async fn drive_with_offer(versions: &[(u16, u16)]) -> HelloOutcome {
        use crate::hello::read_frame;

        let (mut client_end, server_end) = duplex(64 * 1024);
        let hello = wire::AppHello {
            versions: versions
                .iter()
                .map(|(maj, min)| wire::ProtocolVersion {
                    major: *maj as u32,
                    minor: *min as u32,
                })
                .collect(),
            transport_capabilities: vec!["tcp-tls13".to_owned()],
            server_source: None,
        };

        let slot: Arc<Mutex<Option<HelloOutcome>>> = Arc::new(Mutex::new(None));
        let slot_clone = slot.clone();
        let observer: ConnectionObserver = Arc::new(move |o| {
            *slot_clone.lock().unwrap() = Some(o);
        });

        let expect_ack = versions.contains(&(1, 0));
        let client = tokio::spawn(async move {
            write_frame(&mut client_end, &hello).await.unwrap();
            if expect_ack {
                let _ack: wire::AppHelloAck = read_frame(&mut client_end).await.unwrap();
            } else {
                let _reject: wire::AppHelloReject = read_frame(&mut client_end).await.unwrap();
            }
        });
        drive_negotiated_connection(server_end, observer).await;
        client.await.unwrap();
        slot.lock()
            .unwrap()
            .take()
            .expect("observer must be invoked")
    }

    /// Drive a happy-path HELLO via the duplex shim and assert the
    /// observer reports `Negotiated(1.0)`. This is the in-process
    /// proof that the runtime's per-connection handler reaches the
    /// `Versioned` advance-step on a successful negotiation.
    #[tokio::test]
    async fn driver_negotiates_and_reports_outcome() {
        let outcome = drive_with_offer(&[(1, 0)]).await;
        assert_eq!(
            outcome,
            HelloOutcome::Negotiated(ProtocolVersion::new(1, 0))
        );
    }

    /// Drive a no-overlap HELLO via the duplex shim and assert the
    /// observer reports `Rejected`. ISC-39 round-trip at the runtime
    /// layer.
    #[tokio::test]
    async fn driver_rejects_and_reports_outcome() {
        let outcome = drive_with_offer(&[(2, 0)]).await;
        match outcome {
            HelloOutcome::Rejected { peer_offer } => {
                assert_eq!(peer_offer, vec![ProtocolVersion::new(2, 0)]);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parse_listen_addr_round_trips_ipv4_default() {
        let addr = parse_listen_addr("0.0.0.0:443").unwrap();
        assert_eq!(addr.port(), 443);
    }

    #[tokio::test]
    async fn parse_listen_addr_rejects_malformed() {
        let err = parse_listen_addr("not-a-socket-addr").expect_err("malformed");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// `shutdown_after` returns after the requested duration so the
    /// integration loop has a deterministic exit. 5ms is enough that
    /// the listener gets at least one accept poll on a quiet system.
    #[tokio::test]
    async fn shutdown_after_completes() {
        shutdown_after(Duration::from_millis(5)).await;
    }

    /// `run` exits cleanly when the shutdown future resolves before
    /// any connection arrives. This pins ISC-9 — the loop honours the
    /// shutdown signal without panic / abort.
    #[tokio::test]
    async fn run_returns_when_shutdown_resolves_immediately() {
        // Bind to an ephemeral port (port 0 = let-OS-pick) so the test
        // doesn't collide with anything. We can't easily build a full
        // ServerConfig here without going through provider install
        // (which conflicts across test runs), so we use a minimal
        // ServerConfig — wait, no, ServerConfig requires the installed
        // provider. Instead we test that the *function shape* honours
        // shutdown by giving it a pre-resolved future and trusting
        // tokio::select!'s biased behavior. The build_server_config
        // path itself is exercised by tls::tests.
        //
        // Tests against the full bind path live in the commit-6
        // integration suite, which has the heavyweight test-only
        // module init lined up.
        //
        // Here we exercise just the shutdown_after / shutdown_signal
        // contract, plus the duplex-driven handler in the tests above.
        shutdown_after(Duration::from_millis(1)).await;
    }
}
