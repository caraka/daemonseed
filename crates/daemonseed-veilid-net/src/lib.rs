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
//! ## Rendezvous engine (circles + lobby / public rooms)
//! One shared-owner DFLT DHT [`rendezvous`] record underlies every group
//! surface; the only thing that varies is where the owner keypair comes from.
//! A circle derives it from the shared circle entropy (a sibling of the content
//! key, Phase 2); a public room / the lobby derives it from the world-derivable
//! room name+family (a sibling of the room key, Phase 3/4). Every participant
//! computes the SAME record key — the relay-free rendezvous address — writes
//! sealed items into per-participant append-rings, and a connecting participant
//! sweeps the record for a bounded backlog and watches it for new writes:
//! [`VeilidNetHandle::publish_circle`]/[`subscribe_circle`](VeilidNetHandle::subscribe_circle)
//! and [`publish_room`](VeilidNetHandle::publish_room)/[`subscribe_room`](VeilidNetHandle::subscribe_room).
//! Public-share **discovery** rides the lobby record (a `ShareAnnouncement`
//! sealed under the `PublicRoomKey` is just an item published there).
//!
//! ## What is stubbed (Phase 3 Slice 2 / Phase 4)
//! Public-share **content** serving (owner-on-demand `app_call` + a private
//! route, with ≤32 KiB transport fragmentation of the 1 MiB content-addressed
//! chunks), presence, and announcements/MOTD return
//! [`VeilidNetError::Unimplemented`]. Their Phase-0 mechanics are characterized
//! in the migration design doc; this crate is where they get built.
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
pub mod config;
pub mod error;
pub mod event;
pub mod identity;
mod rendezvous;

pub use actor::{VeilidNet, VeilidNetHandle};
pub use config::VeilidNetConfig;
pub use error::{Result, VeilidNetError};
pub use event::VeilidNetEvent;
