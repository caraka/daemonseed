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

    use crate::v1::{AppHello, AppHelloAck, AppHelloReject, CotFrame, ProtocolVersion, SuiteId};

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

    /// `ProtocolVersion` is the wire-shape for SemVer MAJOR.MINOR. PATCH is
    /// deliberately absent from the wire per ISC-S14 — two implementations
    /// sharing MAJOR.MINOR are wire-compatible regardless of PATCH.
    #[test]
    fn protocol_version_round_trips() {
        let original = ProtocolVersion { major: 1, minor: 0 };
        let bytes = original.encode_to_vec();
        let decoded = ProtocolVersion::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
    }

    /// `AppHello` round-trips the MVP offer shape: one supported version,
    /// `tcp-tls13` as the sole transport capability (F29 anchor), and an
    /// unset `server_source` (F32 placeholder; population deferred to M6).
    #[test]
    fn app_hello_round_trips_mvp_offer() {
        let original = AppHello {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            transport_capabilities: vec!["tcp-tls13".to_string()],
            server_source: None,
        };
        let bytes = original.encode_to_vec();
        let decoded = AppHello::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.versions.len(), 1);
        assert_eq!(decoded.transport_capabilities, vec!["tcp-tls13"]);
        assert!(decoded.server_source.is_none());
    }

    /// `AppHello.server_source` round-trips when populated. This is the
    /// shape M6 will use once operators declare an AGPL §13 source URL.
    #[test]
    fn app_hello_round_trips_with_server_source() {
        let original = AppHello {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            transport_capabilities: vec!["tcp-tls13".to_string()],
            server_source: Some("https://example.invalid/daemonseed-source.tar.gz".to_string()),
        };
        let bytes = original.encode_to_vec();
        let decoded = AppHello::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.server_source.is_some());
    }

    /// `AppHelloAck` carries the single negotiated version. The version is
    /// `Option<ProtocolVersion>` on the generated type because proto3
    /// nested messages are nullable by default; the responder always
    /// supplies it (verified at the policy layer by M4a commit 2's
    /// `daemonseed_core::version::VersionNegotiator::verify_ack`).
    #[test]
    fn app_hello_ack_round_trips() {
        let original = AppHelloAck {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            server_source: None,
        };
        let bytes = original.encode_to_vec();
        let decoded = AppHelloAck::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.version.unwrap().major, 1);
    }

    /// `AppHelloReject` with `code = 1` (NO_COMMON_VERSION) carries the
    /// responder's full supported-version list. The integer code (rather
    /// than enum) gives forward compatibility: future additive reject
    /// codes from a newer responder still parse cleanly at an older
    /// initiator, which can render a generic "unrecognized reject code"
    /// message instead of failing at the proto-decode layer.
    #[test]
    fn app_hello_reject_round_trips_no_common_version() {
        let original = AppHelloReject {
            code: 1,
            server_supported: vec![
                ProtocolVersion { major: 2, minor: 0 },
                ProtocolVersion { major: 2, minor: 1 },
            ],
        };
        let bytes = original.encode_to_vec();
        let decoded = AppHelloReject::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.code, 1);
        assert_eq!(decoded.server_supported.len(), 2);
    }

    /// `CotFrame` round-trips the circle-of-trust relay frame: a 48-byte
    /// asset address (`SHA-384(cot_key, server_id)`, ISC-8) and an opaque
    /// ciphertext payload the relay forwards verbatim. M8 adds the protocol's
    /// first streaming RPC (`CircleOfTrust.Subscribe`); this exercises its
    /// message type at the proto-crate boundary.
    #[test]
    fn cot_frame_round_trips() {
        let original = CotFrame {
            asset_address: vec![0xab; 48],
            payload: b"opaque-ciphertext".to_vec(),
        };
        let bytes = original.encode_to_vec();
        let decoded = CotFrame::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.asset_address.len(), 48);
        assert_eq!(decoded.payload, b"opaque-ciphertext");
    }
}
