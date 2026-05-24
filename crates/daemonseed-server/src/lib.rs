//! daemonseed-server library surface.
//!
//! The binary entry point lives in `main.rs`; this `lib.rs` re-exports
//! the same modules so integration tests (commit-6 in M4a, end-to-end
//! in later milestones) can drive the server in-process rather than
//! spawning a subprocess.
//!
//! Public module map:
//!
//! - [`config`] — TOML config + path resolution (ISC-S3 / ISC-C35)
//! - [`identity`] — long-term ML-DSA-87 server keypair + server-id
//!   construction (ISC-S11)
//! - [`kats`] — assembled CNSA 2.0 KATS slice for production
//!   `oxicrypt_module::initialize_with_profile`
//! - [`tls`] — rustls `ServerConfig` builder + provider install
//!   (ISC-S2a / S2b / S5 / A-S9 / A6)
//! - [`hello`] — length-prefixed prost framing for `APP_HELLO` /
//!   `APP_HELLO_ACK` / `APP_HELLO_REJECT` (ISC-S14)
//! - [`runtime`] — TCP listener + TlsAcceptor + per-connection HELLO
//!   handler + SIGTERM-driven graceful shutdown (ISC-9 / S5)

#![forbid(unsafe_code)]

pub mod config;
pub mod hello;
pub mod identity;
pub mod kats;
pub mod runtime;
pub mod tls;
