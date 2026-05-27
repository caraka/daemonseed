//! daemonseed-tui — interactive terminal client (M11 MVP gate).
//!
//! The TUI is the product surface for the MVP: a [`ratatui`] client that
//! drives the full daemonseed transaction — first-start (mnemonic, passphrase,
//! recovery), connect + identity-proof (reusing [`daemonseed_cli::connect`]),
//! public-space, circle-of-trust chat, file share/fetch, the C22 per-server
//! trust slider, the C28 trust-event taxonomy, and the F22 server-management
//! screen.
//!
//! ## Architecture
//!
//! The interactive logic is split out of the binary so the M11 gate harness
//! and unit tests can drive it without a real terminal:
//!
//! - [`app::App`] — the screen state machine. Pure state + key handling; no
//!   terminal I/O. Every navigation and input transition is unit-testable.
//! - [`ui`] — pure render functions over a [`ratatui::Frame`], dispatched on
//!   the current [`app::Screen`].
//! - The binary ([`main`](../main.rs)) owns the terminal lifecycle (raw mode,
//!   alternate screen) and the event loop, and hosts the tokio runtime that
//!   runs network operations off the render thread.
//!
//! Keeping `App` terminal-free is what makes the PTY gate harness deterministic:
//! the render is a pure function of state, and state advances only through
//! [`app::App::on_key`] (and, later, network-result messages).

#![forbid(unsafe_code)]

pub mod app;
pub mod net;
pub mod screens;
pub mod ui;
