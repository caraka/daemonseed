//! daemonseed cross-crate integration tests + ISC coverage registry.
//!
//! Every ISC ID from `ISA.md` is listed with its class (positive / negative);
//! `cargo xtask isc-coverage` reports how many of them a registered test
//! covers, against the registry's live total.
//!
//! Coverage is split into `positive_tests` and `negative_tests` maps because
//! a `positive` ISC (e.g. "client renders rating taxonomy") passes when a
//! test produces the asserted end-state, while a `negative` ISC (e.g.
//! "server MUST NOT persist user identifiers") passes only when a test
//! actively demonstrates the forbidden state cannot be reached — a bare
//! `assert!(true)` against a negative ISC would be theatre, not coverage.

#![forbid(unsafe_code)]

pub mod isc_coverage;
