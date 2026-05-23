//! daemonseed-proto — wire schema for the daemonseed protocol.
//!
//! All public Rust types in this crate are generated from `.proto` files under
//! `proto/`. `build.rs` invokes `tonic-build` on every `cargo build`, writing
//! fresh output to `OUT_DIR`. The `include!` macros below pull that output
//! into the crate's module tree at compile time.
//!
//! A committed snapshot of the generated code lives under `src/generated/`.
//! That snapshot is for inspection only — it is *not* what gets compiled.
//! `cargo xtask gen-proto` refreshes it; `cargo xtask check-proto` verifies
//! it still matches the live build output and fails in CI on drift.
//!
//! Licensing: this crate is Apache-2.0 OR MIT (Rust ecosystem default), even
//! though the rest of the workspace is AGPL-3.0-or-later. The schema needs to
//! be implementable in other languages without copyleft drag.

#![forbid(unsafe_code)]

/// Wire-protocol version 1 messages (`daemonseed.v1` proto package).
///
/// Per ISC-S14, MINOR bumps are additive-only; never reuse field numbers,
/// never repurpose enum values, never tighten validation after the field
/// has shipped. MAJOR bumps create a new `vN` module here.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/daemonseed.v1.rs"));
}
