//! daemonseed cross-crate integration tests + ISC coverage registry.
//!
//! Scope: registry only — every ISC ID from `ds-isc-draft.md` is listed
//! with its class (positive / negative). No tests are registered yet, so
//! `cargo xtask isc-coverage` reports the 0/93 baseline. Real test
//! registration starts in M1 onward.
//!
//! Coverage is split into `positive_tests` and `negative_tests` maps because
//! a `positive` ISC (e.g. "client renders rating taxonomy") passes when a
//! test produces the asserted end-state, while a `negative` ISC (e.g.
//! "server MUST NOT persist user identifiers") passes only when a test
//! actively demonstrates the forbidden state cannot be reached — a bare
//! `assert!(true)` against a negative ISC would be theatre, not coverage.

#![forbid(unsafe_code)]

pub mod isc_coverage;
