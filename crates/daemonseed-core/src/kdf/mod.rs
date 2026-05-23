//! Key-derivation helpers and the load-bearing HKDF info-string registry.
//!
//! All HKDF info strings used anywhere in daemonseed live in [`info`] as
//! `pub const &str`s. Pinning them in one source-of-truth module means a
//! wire-visible regression test (D5 §5, lands in M4a) can byte-compare the
//! constants against the spec and trip immediately on drift.

pub mod info;
