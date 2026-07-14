//! daemonseed-tui — interactive terminal client for the Veilid-native daemonseed.
//!
//! A serverless, end-to-end-encrypted [`ratatui`] client: no relay and no TLS
//! handshake — all transport rides the Veilid DHT via the crate's `veilid_net`
//! actor (behind the [`net`] `NetCommand`/`NetEvent` contract). It drives
//! first-start (mnemonic, passphrase, recovery) and then the live session — the
//! public **Lobby** room, **circles** of trust, member **presence**, in-band
//! **share** discovery/fetch, and operator **announcements / MOTD**.
//!
//! ## Multi-circle carousel (ISC-C59..C62 / A-C29 / A-C30)
//!
//! A session can hold membership in several circles at once. Joining ADDS a
//! circle to the set ([`app::App::circles`]); it never evicts an existing one
//! (ISC-C59). A single active surface spans the lobby ([`app::Surface::Lobby`])
//! and the joined circles ([`app::Surface::Circle`]); `←`/`→` cycle the active
//! circle ([`app::App::cycle_active_circle`], ISC-C60) and compose posts to the
//! active surface — an active circle taking precedence over the auto-joined lobby
//! ([`app::App::active_chat_surface`]). The chat view is split: a lobby pane on
//! top, the active-circle pane (the carousel slot) on the bottom. Every stored
//! [`app::ChatLine`] carries a [`app::Surface`] tag and each pane renders only
//! its own surface's lines, so a line received on one surface can never bleed
//! into another (ISC-A-C29). A post seals under exactly the active circle's key
//! and an inbound frame is attributed to the single circle whose key opened it —
//! never guessed, never broadcast (ISC-A-C30); each circle carries a client-local
//! label assigned at join, never transmitted (ISC-C62). The membership set is
//! session-only but held in serialization-shaped data so persistence can be added
//! additively to the at-rest blob later (ISC-C59).
//!
//! ## Architecture
//!
//! The interactive logic is split out of the binary so unit tests can drive
//! it without a real terminal:
//!
//! - [`app::App`] — the screen state machine. Pure state + key handling; no
//!   terminal I/O. Every navigation and input transition is unit-testable.
//! - [`ui`] — pure render functions over a [`ratatui::Frame`], dispatched on
//!   the current [`app::Screen`].
//! - The binary ([`main`](../main.rs)) owns the terminal lifecycle (raw mode,
//!   alternate screen) and the event loop, and hosts the tokio runtime that
//!   runs network operations off the render thread.
//!
//! Keeping `App` terminal-free is what makes it deterministically testable:
//! the render is a pure function of state, and state advances only through
//! [`app::App::on_key`] (and, later, network-result messages).

#![forbid(unsafe_code)]

pub mod app;
pub mod net;
pub mod screens;
pub mod ui;

// The Veilid net actor — the only transport. It implements the
// `NetCommand`/`NetEvent` contract `net` defines; `net`'s `NetHandle::new`
// spawns it.
mod veilid_net;
