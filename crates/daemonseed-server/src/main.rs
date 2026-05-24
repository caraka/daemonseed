//! daemonseed-server binary.
//!
//! M4a commit 3 lands the operator-facing modules (`config`, `identity`,
//! `tls`); the `main()` runtime that binds the listener, drives the
//! `APP_HELLO` post-handshake frame, and reaches the type-state
//! `Versioned` state lands in commit 4. Until then `main()` remains a
//! placeholder so the binary still compiles cleanly.

pub mod config;
pub mod identity;
pub mod tls;

fn main() {}
