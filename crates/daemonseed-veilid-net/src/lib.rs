//! # daemonseed-veilid-net — the Veilid transport layer (Phase 1)
//!
//! Replaces `daemonseed-server` (the relay) with the Veilid stack. This crate
//! owns one long-lived actor task (a `VeilidAPI` + `RoutingContext` + an update
//! pump), driven through a [`VeilidNetHandle`] command channel. The pump maps
//! raw `VeilidUpdate`s into typed [`VeilidNetEvent`]s the app/UI consumes.
//!
//! ## What is real here (Phase 1, proven in veilid-ds-spike)
//! - **Identity binding (D3):** the node key derives from the daemonseed
//!   mnemonic via [`daemonseed_core::identity::keys::VeilidNodeSeed`] — one
//!   phrase, one identity across content + transport.
//! - **1:1 sealed message over a private route:** allocate/import a private
//!   route, send daemonseed's opaque AES-256-GCM envelope via `app_message`.
//!   This layer carries CIPHERTEXT only — it never holds the content key or
//!   plaintext, which is what keeps the guarantee post-quantum regardless of
//!   Veilid's classical transport.
//!
//! ## Circles (Phase 2)
//! A circle's owner keypair is derived deterministically from the shared circle
//! entropy (a sibling of the content key), so every member computes the SAME
//! shared-owner DFLT DHT record key — the relay-free rendezvous address. Members
//! write sealed messages into per-member append-rings; a connecting member
//! sweeps the record for a bounded recent backlog and watches it for new writes
//! ([`VeilidNetHandle::publish_circle`] / [`VeilidNetHandle::subscribe_circle`]).
//!
//! ## What is stubbed (Phase 3+)
//! Public shares (≤32 KiB chunks + `ShareAnnouncement`), presence, and
//! announcements/MOTD return [`VeilidNetError::Unimplemented`]. Their Phase-0
//! mechanics are characterized in the migration design doc; this crate is where
//! they get built.
//!
//! ## Invariant
//! Content keys NEVER derive from Veilid (classical x25519) material. The seal/
//! open lives in `daemonseed-core`; this crate only moves opaque bytes.

/// Env-gated stderr trace for live attach/circle debugging on a real node.
///
/// Enabled when `DAEMONSEED_VEILID_TRACE` is set (any value); a zero-output
/// no-op otherwise. It exists because the attach and circle-rendezvous paths can
/// only be exercised on a real public-network host (a NAT'd VM blocks attach),
/// where no debugger attaches — so the next felt-test produces a decisive trace
/// instead of an inference. Not a logging framework: a deliberate, minimal probe
/// at the exact points the `veilid-migration` design's fault tree enumerates.
/// Reachable from dependent crates as `daemonseed_veilid_net::vtrace!`.
#[macro_export]
macro_rules! vtrace {
    ($($arg:tt)*) => {
        if ::std::env::var_os("DAEMONSEED_VEILID_TRACE").is_some() {
            ::std::eprintln!("[veilid-net] {}", ::std::format_args!($($arg)*));
        }
    };
}

pub mod actor;
mod circle;
pub mod config;
pub mod error;
pub mod event;
pub mod identity;

pub use actor::{VeilidNet, VeilidNetHandle};
pub use config::VeilidNetConfig;
pub use error::{Result, VeilidNetError};
pub use event::VeilidNetEvent;
