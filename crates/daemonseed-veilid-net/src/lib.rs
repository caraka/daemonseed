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
//! ## What is stubbed (Phase 2+)
//! Circles (DHT `SMPL` rendezvous + fan-out), public shares (≤32 KiB chunks +
//! `ShareAnnouncement`), presence, and announcements/MOTD return
//! [`VeilidNetError::Unimplemented`]. Their Phase-0 mechanics are characterized
//! in the migration design doc; this crate is where they get built.
//!
//! ## Invariant
//! Content keys NEVER derive from Veilid (classical x25519) material. The seal/
//! open lives in `daemonseed-core`; this crate only moves opaque bytes.

pub mod actor;
pub mod config;
pub mod error;
pub mod event;
pub mod identity;

pub use actor::{VeilidNet, VeilidNetHandle};
pub use config::VeilidNetConfig;
pub use error::{Result, VeilidNetError};
pub use event::VeilidNetEvent;
