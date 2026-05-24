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

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::v1::{CircleMin, SuiteId, Version};

    /// `SuiteId` round-trips through prost encode/decode preserving the
    /// `value` field. M3 adds `SuiteId` to the v1 module; this test exists
    /// so the public surface is exercised at the proto-crate boundary.
    #[test]
    fn suite_id_round_trips() {
        let original = SuiteId { value: 0x0001 };
        let bytes = original.encode_to_vec();
        let decoded = SuiteId::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
    }

    /// `CircleMin` round-trips with a populated `min_suite_id`. The optional
    /// field arrives because proto3 messages are nullable by default; the
    /// app-layer constructor (in M6 when circle creation lands) always
    /// supplies a value, and a deserialized `None` MUST be rejected at the
    /// application boundary.
    #[test]
    fn circle_min_round_trips_with_suite_id() {
        let original = CircleMin {
            min_suite_id: Some(SuiteId { value: 0x0001 }),
        };
        let bytes = original.encode_to_vec();
        let decoded = CircleMin::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.min_suite_id.as_ref().unwrap().value, 0x0001);
    }

    /// The pre-existing `Version` message still encodes; M3's additions
    /// to the schema do not regress earlier work.
    #[test]
    fn version_message_still_round_trips() {
        let v = Version {
            major: 1,
            minor: 0,
            patch: 0,
            pre_release: String::new(),
        };
        let bytes = v.encode_to_vec();
        let decoded = Version::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, v);
    }
}
