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

    use crate::v1::{
        AppHello, AppHelloAck, AppHelloReject, CotFrame, DmAdvert, DmChannelControl,
        DmChannelOpening, DmChannelSlot, DmHello, DmKeyRecord, DmMessageHeader, KeySelector,
        ProtocolVersion, SuiteId,
    };

    /// ML-KEM-1024 encapsulation key and ciphertext width.
    const KEM_LEN: usize = 1568;

    /// ML-DSA-87 signature width.
    const SIG_LEN: usize = 4627;

    /// ML-DSA-87 public key width.
    const IDENTITY_PK_LEN: usize = 2592;

    /// A `CotFrame` carrying a lobby rendezvous address and an opaque payload,
    /// encoded byte for byte under the field numbers the v0.36.3 schema
    /// assigns: `asset_address` is field 1 and `payload` is field 2, so the
    /// stream is tag `0x0a`, length 48, the address, tag `0x12`, length 22,
    /// the payload.
    ///
    /// `git show v0.36.3:crates/daemonseed-proto/proto/daemonseed/v1/cot.proto`
    /// carries those same two numbers, so this literal is the released
    /// encoding and not merely the current one. Pinning it as bytes rather
    /// than re-encoding at test time is what gives the test its teeth: a
    /// renumbering of either field makes the decode below read something
    /// other than what these bytes were built from.
    const LOBBY_COT_FRAME_V0_36_3: &[u8] = &[
        0x0a, 0x30, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
        0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x12, 0x16, 0x6c, 0x6f, 0x62, 0x62, 0x79, 0x2d, 0x66, 0x72,
        0x61, 0x6d, 0x65, 0x2d, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74,
    ];

    /// The address those bytes were built from: the 48 octets `0x00..=0x2f`.
    fn lobby_asset_address() -> Vec<u8> {
        (0u8..48).collect()
    }

    /// The payload those bytes were built from.
    const LOBBY_PAYLOAD: &[u8] = b"lobby-frame-ciphertext";

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
    /// `tcp-tls13` as the sole transport capability (anchor), and an
    /// unset `server_source` (placeholder; population deferred to M6).
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

    /// `DmKeyRecord` round-trips at the proto-crate boundary. The two byte
    /// fields are exact-length on the wire (ML-KEM-1024 EK = 1568, ML-DSA-87
    /// signature = 4627); prost itself enforces neither, which is why
    /// `daemonseed_core::dm::keyrec::verify` length-gates both before any
    /// signature check.
    #[test]
    fn dm_key_record_round_trips() {
        let original = DmKeyRecord {
            version: 7,
            kem_ek: vec![0xA5; 1568],
            invite_only: true,
            signature: vec![0x5A; 4627],
        };
        let bytes = original.encode_to_vec();
        let decoded = DmKeyRecord::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, original);
    }

    /// The reserved key-selector space. Alpha always writes `Static`; the enum
    /// exists so re-introducing one-time prekeys later needs no wire change.
    /// `Unspecified` is the proto3 zero default and is never written.
    #[test]
    fn key_selector_reserves_the_prekey_space() {
        assert_eq!(KeySelector::Unspecified as i32, 0);
        assert_eq!(KeySelector::Static as i32, 1);
        assert_eq!(KeySelector::default(), KeySelector::Unspecified);
    }

    /// A lobby `CotFrame` encoded under the v0.36.3 schema decodes under the
    /// current one, field for field.
    ///
    /// The point of the pinned literal is what it catches: the bytes fix
    /// `asset_address` at field 1 and `payload` at field 2, so renumbering
    /// either field in `cot.proto` makes this decode read something other than
    /// the values the bytes were built from, and the assertions below fail.
    /// Adding messages to the package cannot affect it, which is the property
    /// an additive change is claiming.
    ///
    /// The pin is the mechanism, not the assertions: re-encoding a `CotFrame`
    /// at test time and comparing it to itself would agree with any numbering
    /// whatsoever, so only a literal fixed to the released bytes detects a
    /// renumbering. The control block below covers field 1 by rewriting that
    /// field's tag; the literal covers field 2, whose length and contents the
    /// decode reads back unchanged only while `payload` is still field 2.
    #[test]
    fn lobby_cot_frame_from_v0_36_3_decodes_unchanged() {
        let decoded = CotFrame::decode(LOBBY_COT_FRAME_V0_36_3).unwrap();
        assert_eq!(decoded.asset_address, lobby_asset_address());
        assert_eq!(decoded.asset_address.len(), 48);
        assert_eq!(decoded.payload, LOBBY_PAYLOAD);

        // Control. Byte 0 is `asset_address`'s tag, field 1 wire type 2
        // (`0x0a`); rewriting it to `0x1a` is field 3 at the same wire type —
        // the encoding a renumbering of `asset_address` would produce. The
        // frame still decodes, because an unknown field is skipped, and that
        // is exactly why a decode that merely succeeds proves nothing: the
        // address comes back empty instead of the 48 octets above.
        let mut renumbered = LOBBY_COT_FRAME_V0_36_3.to_vec();
        assert_eq!(renumbered[0], 0x0a);
        renumbered[0] = 0x1a;
        let after = CotFrame::decode(renumbered.as_slice()).unwrap();
        assert_ne!(after.asset_address, lobby_asset_address());
        assert!(after.asset_address.is_empty());
        assert_eq!(after.payload, LOBBY_PAYLOAD);
    }

    /// The six conversation-record messages round-trip at the widths
    /// `docs/design/direct-messaging.md` § Records states, and a
    /// `DmMessageHeader` carrying one turn field without the other is
    /// representable on the wire.
    ///
    /// The schema does not forbid that half-populated header, and cannot: two
    /// `optional` fields are independent in proto3. The pairing is enforced a
    /// layer up, by `daemonseed_core::dm::channel::MessageHeader::decode`,
    /// which refuses one turn field without the other with
    /// `ChannelError::TurnFieldsIncomplete`. This test pins the boundary: the
    /// wire carries it, the decoder rejects it.
    #[test]
    fn dm_conversation_records_round_trip_at_design_widths() {
        let advert = DmAdvert {
            serial: 3,
            not_before: 1_700_000_000,
            kem_pk: vec![0x11; KEM_LEN],
            signature: vec![0x22; SIG_LEN],
        };
        let decoded = DmAdvert::decode(advert.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, advert);
        assert_eq!(decoded.kem_pk.len(), KEM_LEN);
        assert_eq!(decoded.signature.len(), SIG_LEN);

        let hello = DmHello {
            kem_ct: vec![0x33; KEM_LEN],
            sealed: vec![0x44; 12 + 64 + 16],
            pow_tag: vec![0x55; 8],
        };
        let decoded = DmHello::decode(hello.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, hello);
        assert_eq!(decoded.kem_ct.len(), KEM_LEN);

        let opening = DmChannelOpening {
            writer_identity_pk: vec![0x66; IDENTITY_PK_LEN],
            recipient_identity_pk: vec![0x77; IDENTITY_PK_LEN],
            first_ratchet_pk: vec![0x88; KEM_LEN],
            advert_serial: 3,
            signature: vec![0x99; SIG_LEN],
        };
        let decoded = DmChannelOpening::decode(opening.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, opening);
        assert_eq!(decoded.writer_identity_pk.len(), IDENTITY_PK_LEN);
        assert_eq!(decoded.recipient_identity_pk.len(), IDENTITY_PK_LEN);
        assert_eq!(decoded.first_ratchet_pk.len(), KEM_LEN);
        assert_eq!(decoded.signature.len(), SIG_LEN);

        let control = DmChannelControl {
            opening: Some(opening.clone()),
            collected_cursor: 12,
            closed: false,
        };
        let decoded = DmChannelControl::decode(control.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, control);
        assert_eq!(decoded.opening.unwrap(), opening);

        // A control record before its opening is written: the message field is
        // absent, which is a different state from an opening of zero bytes.
        let bare = DmChannelControl {
            opening: None,
            collected_cursor: 0,
            closed: true,
        };
        let decoded = DmChannelControl::decode(bare.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, bare);
        assert!(decoded.opening.is_none());
        assert!(decoded.closed);

        let turn_header = DmMessageHeader {
            device_id: 0,
            n: 4,
            m: 2,
            seq: 17,
            cursor: 9,
            kem_ct: Some(vec![0xaa; KEM_LEN]),
            kem_pk: Some(vec![0xbb; KEM_LEN]),
        };
        let decoded = DmMessageHeader::decode(turn_header.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, turn_header);
        assert_eq!(decoded.kem_ct.as_ref().unwrap().len(), KEM_LEN);
        assert_eq!(decoded.kem_pk.as_ref().unwrap().len(), KEM_LEN);

        let continuing = DmMessageHeader {
            kem_ct: None,
            kem_pk: None,
            ..turn_header.clone()
        };
        let decoded = DmMessageHeader::decode(continuing.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, continuing);
        assert!(decoded.kem_ct.is_none());
        assert!(decoded.kem_pk.is_none());

        // One turn field without the other. It encodes, it decodes, and it
        // comes back exactly as written — the schema carries it and the core
        // decoder is what refuses it.
        let half = DmMessageHeader {
            kem_ct: Some(vec![0xcc; KEM_LEN]),
            kem_pk: None,
            ..turn_header.clone()
        };
        let decoded = DmMessageHeader::decode(half.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, half);
        assert!(decoded.kem_ct.is_some());
        assert!(decoded.kem_pk.is_none());

        let slot = DmChannelSlot {
            header: Some(turn_header.clone()),
            body: vec![0xdd; 12 + 256 + 16],
        };
        let decoded = DmChannelSlot::decode(slot.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, slot);
        assert_eq!(decoded.header.unwrap(), turn_header);
    }

    /// Every field of every conversation-record message, pinned to the field
    /// number it carries in this schema.
    ///
    /// Each value below uses the smallest contents that still encode — one
    /// byte per `bytes` field, small non-zero integers, both turn fields set
    /// on the header, the opening present in the control — so the literal it
    /// is compared against is almost entirely tags. Renumbering any field of
    /// any of the six changes its tag byte and fails the assertion for that
    /// message; the round-trip test above would not notice, because a
    /// re-encode agrees with whatever numbering it was built under.
    ///
    /// The pin is updated only by a deliberate schema change, and a schema
    /// change that alters an existing number is forbidden here: MINOR bumps in
    /// this package are additive-only, so in practice the literals move only
    /// when a new field is added and its own bytes appear.
    #[test]
    fn dm_record_field_numbers_are_pinned() {
        // 0x08 field 1 varint · 0x10 field 2 varint · 0x1a field 3 bytes
        // · 0x22 field 4 bytes
        let advert = DmAdvert {
            serial: 1,
            not_before: 2,
            kem_pk: vec![0x01],
            signature: vec![0x02],
        };
        assert_eq!(
            advert.encode_to_vec(),
            vec![0x08, 0x01, 0x10, 0x02, 0x1a, 0x01, 0x01, 0x22, 0x01, 0x02],
        );

        // 0x0a field 1 bytes · 0x12 field 2 bytes · 0x1a field 3 bytes
        let hello = DmHello {
            kem_ct: vec![0x01],
            sealed: vec![0x02],
            pow_tag: vec![0x03],
        };
        assert_eq!(
            hello.encode_to_vec(),
            vec![0x0a, 0x01, 0x01, 0x12, 0x01, 0x02, 0x1a, 0x01, 0x03],
        );

        // 0x0a field 1 bytes · 0x12 field 2 bytes · 0x1a field 3 bytes
        // · 0x20 field 4 varint · 0x2a field 5 bytes
        let opening = DmChannelOpening {
            writer_identity_pk: vec![0x01],
            recipient_identity_pk: vec![0x02],
            first_ratchet_pk: vec![0x03],
            advert_serial: 4,
            signature: vec![0x05],
        };
        let opening_bytes = vec![
            0x0a, 0x01, 0x01, 0x12, 0x01, 0x02, 0x1a, 0x01, 0x03, 0x20, 0x04, 0x2a, 0x01, 0x05,
        ];
        assert_eq!(opening.encode_to_vec(), opening_bytes);

        // 0x0a field 1 message (length 14, the opening above) · 0x10 field 2
        // varint · 0x18 field 3 varint
        let control = DmChannelControl {
            opening: Some(opening),
            collected_cursor: 7,
            closed: true,
        };
        let mut expected = vec![0x0a, 0x0e];
        expected.extend_from_slice(&opening_bytes);
        expected.extend_from_slice(&[0x10, 0x07, 0x18, 0x01]);
        assert_eq!(control.encode_to_vec(), expected);

        // 0x08 field 1 varint · 0x10 field 2 varint · 0x18 field 3 varint
        // · 0x20 field 4 varint · 0x28 field 5 varint · 0x32 field 6 bytes
        // · 0x3a field 7 bytes
        let header = DmMessageHeader {
            device_id: 1,
            n: 2,
            m: 3,
            seq: 4,
            cursor: 5,
            kem_ct: Some(vec![0x06]),
            kem_pk: Some(vec![0x07]),
        };
        let header_bytes = vec![
            0x08, 0x01, 0x10, 0x02, 0x18, 0x03, 0x20, 0x04, 0x28, 0x05, 0x32, 0x01, 0x06, 0x3a,
            0x01, 0x07,
        ];
        assert_eq!(header.encode_to_vec(), header_bytes);

        // 0x0a field 1 message (length 16, the header above) · 0x12 field 2
        // bytes
        let slot = DmChannelSlot {
            header: Some(header),
            body: vec![0x08],
        };
        let mut expected = vec![0x0a, 0x10];
        expected.extend_from_slice(&header_bytes);
        expected.extend_from_slice(&[0x12, 0x01, 0x08]);
        assert_eq!(slot.encode_to_vec(), expected);
    }
}
