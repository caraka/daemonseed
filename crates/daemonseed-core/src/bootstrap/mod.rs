//! Bootstrap-relay discovery (ISC-C37).
//!
//! Daemonseed's first-start (ISC-C29 step 6) offers exactly two paths for
//! choosing the first server the client will connect to:
//!
//! 1. **Project canonical relay.** Pinned at build time in a bundled
//!    [`BootstrapAnchor`] (analogous to the release-signing trust anchor
//!    per ISC-A-C11). The binary's integrity guarantee makes this the
//!    "follow the project's choice" path.
//! 2. **Manual paste.** User supplies a `server-id + address` out-of-band
//!    (typed, pasted, scanned from a QR). Relief valve for censored
//!    networks where the canonical relay is the largest single target
//!    for state-level interdiction.
//!
//! Per ISC-A-C19 those two paths are exhaustive. No mDNS / DHT / broadcast
//! / introducer-without-a-relay handshake. The selected entry is persisted
//! to `daemonseed.toml` and is what step 7 will hand to the wire layer.

mod anchor;

pub use anchor::{BootstrapAnchor, BundledAnchor, bundled};
