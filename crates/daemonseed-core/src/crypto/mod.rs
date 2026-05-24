//! Cryptographic-agility primitives — suite registry, policy gates, and
//! family-discriminator helpers.
//!
//! The registry is the load-bearing piece of M3: every cryptographic artifact
//! the client authors (ISC-C24) carries a [`suite::SuiteId`] that resolves
//! through the registry to a concrete bundle of primitives. Per ISC-S15 the
//! family relationship between two suites is **implicit in the registry**
//! (encoded via [`suite::Suite::same_family`]) rather than a wire field, so
//! the registry topology can grow without a MAJOR-version bump.

pub mod suite;
