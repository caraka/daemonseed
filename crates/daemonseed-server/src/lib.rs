//! daemonseed-server library surface.
//!
//! The binary entry point lives in `main.rs`; this `lib.rs` re-exports
//! the same modules so integration tests (commit-6 in M4a, end-to-end
//! in later milestones) can drive the server in-process rather than
//! spawning a subprocess.
//!
//! Public module map:
//!
//! - [`config`] — TOML config + path resolution (ISC-S3 / ISC-C35),
//!   including the federation `[[peer]]` table (ISC-S12 / ISC-S13)
//! - [`federation`] — introducer-response construction plus the
//!   `FederationIntroducer.Introduce` gRPC endpoint (M12, gate step 6) with the
//!   no-keys-in-introducer invariant (ISC-S6), introduce-to-clients
//!   suppression (ISC-S13), and don't-introduce indistinguishability
//!   (ISC-A-S7)
//! - [`identity`] — long-term ML-DSA-87 server keypair + server-id
//!   construction (ISC-S11)
//! - [`tls`] — rustls `ServerConfig` builder (ISC-S2a / S2b / S5 /
//!   A-S9); the process-wide provider install lives in
//!   `daemonseed_core::tls`
//! - [`hello`] — length-prefixed prost framing for `APP_HELLO` /
//!   `APP_HELLO_ACK` / `APP_HELLO_REJECT` (ISC-S14)
//! - [`identity_proof`] — post-HELLO identity-proof orchestration:
//!   channel binding off the live TLS session, signed-envelope exchange,
//!   and the `Versioned → Authenticated` gate (ISC-S19 / A-S14 / A-S12)
//! - [`runtime`] — TCP listener + TlsAcceptor + per-connection HELLO +
//!   identity-proof handler + SIGTERM-driven graceful shutdown (ISC-9 / S5)
//! - [`cot`] — circle-of-trust live relay: refcounted, reap-at-zero
//!   bidirectional `Subscribe` fan-out keyed by rendezvous address, served
//!   over the post-Authenticated stream alongside public-space (M8, F23)
//! - [`rate_limit`] — multi-granularity, RAM-only abuse/DoS rate limits:
//!   per-connection token bucket + subscription / verify caps, and a
//!   per-identity-key connection table GC'd on disconnect (M9, ISC-S17/A-S12)

#![forbid(unsafe_code)]

pub mod app_limit;
pub mod boot_gate;
pub mod config;
pub mod cot;
pub mod deprecation;
pub mod federation;
pub mod hello;
pub mod identity;
pub mod identity_proof;
pub mod public_space;
pub mod rate_limit;
pub mod runtime;
pub mod tls;
