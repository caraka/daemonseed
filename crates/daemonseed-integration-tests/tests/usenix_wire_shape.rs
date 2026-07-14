//! Wu et al. (USENIX 23) wire-shape regression — workstream D.
//!
//! Spawns the real `daemonseed-server` subprocess, opens a TCP
//! connection to it, drives a daemonseed-shaped TLS 1.3 handshake
//! through `rustls`, captures the observable wire features, and runs
//! them through the Wu negative-allowlist classifier. The
//! deliverable is a single pass/fail bit (ISC-49 / 50): every gate
//! connection MUST be classified `Accept`. The classifier itself
//! lives in `tests/common/wire_shape.rs`; this test is the live
//! observation point.
//!
//! ## Why `#[ignore]`
//!
//! Same rationale as the M11 MVP-gate harness: needs an already-built
//! `daemonseed-server` release binary and spawns a real subprocess.
//! The canonical entry point is `cargo xtask wire-shape`, which
//! builds the server first and propagates the test's exit code.

#![forbid(unsafe_code)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use common::gate::{ServerProcess, ensure_module_operational};
use common::wire_shape::{Classification, WireShape, classify};
use daemonseed_cli::connect::build_client_config;
use daemonseed_core::tls::install_provider;
use rustls::ClientConnection;
use rustls_pki_types::ServerName;

/// Drive a real TLS 1.3 handshake against the server, observe what a
/// censor would see, and run the result through the Wu classifier.
/// PASS = every Wu rule cleared.
#[test]
#[ignore = "spawns real binary; entry point is `cargo xtask wire-shape`"]
fn wire_shape_classifier_accepts_real_handshake() {
    // The harness process needs the oxicrypt module operational AND the
    // oxitls rustls CryptoProvider installed before constructing any
    // ClientConfig — the spawned server binary installs its own copy
    // in its own process, but rustls's CryptoProvider is per-process
    // and the harness side is what builds the ClientHello here.
    ensure_module_operational();
    let _ = install_provider();

    let server = ServerProcess::spawn(Some("relay-mvp"))
        .expect("server subprocess spawns + binds to its ephemeral port");

    let shape = observe(&server.addr).expect("observed handshake shape");
    let verdict = classify(&shape);
    assert_eq!(
        verdict,
        Classification::Accept,
        "Wu classifier rejected daemonseed's handshake; shape={shape:?}; verdict={verdict:?}"
    );
}

/// Run a daemonseed-shaped TLS 1.3 ClientHello against `addr` and
/// return the observable [`WireShape`]. The connection uses the same
/// production `ClientConfig` (`daemonseed_cli::connect::build_client_config`)
/// the cli / TUI use — same CryptoProvider, same `[&TLS13]` version
/// restriction, same `ALPN = [b"h2"]` — so the negotiated parameters
/// reflect what a real client would put on the wire.
fn observe(addr: &str) -> anyhow::Result<WireShape> {
    let client_cfg = build_client_config()?;
    let server_name = ServerName::try_from("daemonseed.invalid")?;
    let mut conn = ClientConnection::new(Arc::new(client_cfg), server_name)?;

    let mut tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;

    // First-byte capture: emit our ClientHello to the network and
    // peek the first response byte before handing further bytes to
    // rustls's record-layer state machine. This is the rule-1
    // observation point — the censor's tap.
    let mut hello = Vec::with_capacity(2048);
    while conn.wants_write() {
        conn.write_tls(&mut hello)?;
    }
    tcp.write_all(&hello)?;

    let mut peek = [0u8; 1];
    tcp.read_exact(&mut peek)?;
    let first_byte = peek[0];

    // Glue: feed the peeked byte back into a Read-able stream so
    // rustls's record parser sees the full TLS record sequence
    // starting with the byte we just consumed.
    let mut prefixed = PrefixThenStream {
        prefix: Some(peek[0]),
        inner: tcp,
    };

    // Drive the handshake to completion (or first ApplicationData,
    // whichever comes first). We don't need the post-handshake
    // stream — just the negotiated parameters.
    while conn.is_handshaking() {
        if conn.wants_read() {
            match conn.read_tls(&mut prefixed) {
                Ok(0) => anyhow::bail!("server closed during handshake"),
                Ok(_) => {
                    conn.process_new_packets()?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
        if conn.wants_write() {
            let mut out = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut out)?;
            }
            if !out.is_empty() {
                prefixed.inner.write_all(&out)?;
            }
        }
    }

    Ok(WireShape {
        first_record_content_type: first_byte,
        alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
        negotiated_version: conn.protocol_version(),
        // 0-RTT not supported here (`build_client_config` doesn't
        // enable early-data send), and the server's
        // `max_early_data_size = 0` would refuse it anyway. Pinned
        // as a structural false; the classifier still asserts it.
        early_data_used: false,
    })
}

/// `Read`/`Write` adapter that yields a previously-peeked byte
/// once before reading from the inner stream. Needed because we
/// snatched the first byte off the TCP socket to satisfy the
/// censor-observation rule (1), and rustls needs to see that byte
/// inside its TLS-record-layer parse window.
struct PrefixThenStream {
    prefix: Option<u8>,
    inner: TcpStream,
}

impl Read for PrefixThenStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(b) = self.prefix.take() {
            if buf.is_empty() {
                self.prefix = Some(b);
                return Ok(0);
            }
            buf[0] = b;
            let extra = if buf.len() > 1 {
                match self.inner.read(&mut buf[1..]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                    Err(e) => return Err(e),
                }
            } else {
                0
            };
            Ok(1 + extra)
        } else {
            self.inner.read(buf)
        }
    }
}

impl Write for PrefixThenStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
