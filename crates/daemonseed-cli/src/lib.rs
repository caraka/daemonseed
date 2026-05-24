//! daemonseed-cli library — exposes the `connect` happy path so the
//! commit-6 integration test can exercise the full client→server
//! round-trip in-process rather than spawning a subprocess.
//!
//! The binary entry point is `main.rs`; this module is the seam that
//! both `main` and the integration test call.
//!
//! ## M4a scope
//!
//! `connect` is intentionally narrow:
//!
//! - Resolves `<server-id>` to an address from the bundled bootstrap
//!   anchor or an explicit `--address` override (ISC-C37)
//! - Builds a `rustls::ClientConfig` against the same process-wide
//!   `cnsa_2_0_hybrid_provider` the server uses (`install_provider`
//!   is idempotent via `OnceLock`)
//! - Initiates the TLS 1.3 handshake with ALPN `h2`
//! - Sends `APP_HELLO` (length-prefixed prost via
//!   `daemonseed_server::hello::write_frame`)
//! - Reads `APP_HELLO_ACK` or `APP_HELLO_REJECT`
//! - On Ack: verifies the responder's pick is in our offer (ISC-C23)
//!   via `DefaultNegotiator::verify_ack`, returns Ok(version)
//! - On Reject `NO_COMMON_VERSION`: returns
//!   [`connect::ConnectError::NoCommonVersion`] with the responder's
//!   full list
//!
//! ## What's NOT in M4a
//!
//! - Real TOFU server-cert verification — the M4a CLI accepts any
//!   cert. Real verification (TOFU + identity-proof) lands in M4b.
//!   This is loud in the code (`AcceptAnyServerCert` verifier) and
//!   documented as such so it can't be mistaken for production-ready
//!   behaviour.
//! - Any subcommand other than `connect`
//! - Profile management, MOTD, posts, file sharing — all M5+ scope.

#![forbid(unsafe_code)]

pub mod connect;
pub mod tofu_stub;
