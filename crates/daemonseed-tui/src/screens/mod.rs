//! Screen components.
//!
//! Each screen is a self-contained piece of interactive state with its own
//! `on_key` handler and render support, kept terminal-free so it can be
//! unit-tested and PTY-driven. [`crate::app::App`] owns the active screen
//! component and delegates key events to it.

pub mod first_start;
