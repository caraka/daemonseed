//! Post-HELLO identity-proof envelope construction and channel binding
//! (ISC-S19, ISC-A-S14, ISC-A-C18).
//!
//! After APP_HELLO_ACK, both peers prove control of the long-term ML-DSA-87
//! key behind their claimed handle, bound to the current TLS session. This
//! module owns the **construction** half (channel-binding derivation + signed
//! envelope build); verification + the `Versioned → Authenticated` type-state
//! transition land alongside it.
//!
//! ## Channel binding (ISC-S19 step 1)
//!
//! Both peers derive a 32-byte value from the TLS 1.3 exporter (RFC 8446
//! §7.5) with a fixed label and the negotiated APP_HELLO version as context.
//! The exporter call needs the live rustls connection, which lives in the
//! server / cli crates — so this module defines the [`ChannelBindingSource`]
//! trait that the TLS-holding layer implements, while keeping the **label and
//! context byte-layout here in core**. Centralizing the inputs is the
//! load-bearing defense against the channel-binding asymmetry bug: if client
//! and server constructed the label/context independently, a one-byte
//! encoding difference would silently make every cross-peer proof fail (or,
//! worse, succeed against a constant). One definition, both peers.
//!
//! ## Signed input (decision D3)
//!
//! ISC-S19 step 2 literally signs `channel_binding || claimed_handle ||
//! claimed_pubkey || negotiated_version`. The freshness formalization
//! (`project_clocks_freshness`) requires the timestamp and counter to be
//! tamper-evident, so the signed input is **extended** to cover them. Variable-
//! length fields are length-delimited (u16 big-endian) so the concatenation is
//! unambiguous — a bare `||` of `handle` and `pubkey` would admit a
//! field-confusion attack where bytes shift across the boundary. Fixed-width
//! fields (channel_binding, version, timestamp, counter) are not delimited.

use crate::identity::keys::{SignKeypair, SignatureError};
use crate::kdf::info;
use daemonseed_proto::v1 as wire;

/// TLS 1.3 exporter label for the identity-proof channel binding (ISC-S19).
///
/// Tied to the single info-string registry entry
/// [`info::IDENTITY_PROOF_V1`] so the exporter label and the kdf-info registry
/// can never drift — the wire-visible regression test that pins the registry
/// string now also guards this label.
pub const CHANNEL_BINDING_LABEL: &[u8] = info::IDENTITY_PROOF_V1.as_bytes();

/// Channel-binding value length in bytes.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// A source of TLS 1.3 exporter output (RFC 8446 §7.5).
///
/// Implemented by the TLS-holding layer (server / cli) over the live rustls
/// connection (`rustls`'s `export_keying_material`). Core stays rustls-free
/// and testable: tests supply a recording fake to assert the label + context
/// without a real handshake.
pub trait ChannelBindingSource {
    /// Run the TLS exporter with `label` and `context`, filling `out`
    /// completely. Implementations MUST NOT substitute a constant for the
    /// exporter output (ISC-A-S14 / ISC-A-C18).
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), ChannelBindingError>;
}

/// Failure deriving the channel-binding value.
#[derive(Debug)]
pub enum ChannelBindingError {
    /// The TLS exporter call failed (e.g. handshake not complete).
    Export(String),
}

impl core::fmt::Display for ChannelBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelBindingError::Export(m) => write!(f, "TLS exporter failed: {m}"),
        }
    }
}

impl std::error::Error for ChannelBindingError {}

/// Fixed 8-byte exporter/context encoding of a negotiated version:
/// `major` (u32 BE) `||` `minor` (u32 BE).
fn version_context(v: &wire::ProtocolVersion) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&v.major.to_be_bytes());
    b[4..8].copy_from_slice(&v.minor.to_be_bytes());
    b
}

/// Derive the 32-byte channel binding, binding the proof to the negotiated
/// APP_HELLO version (ISC-S19 step 1 / ISC-A-S14). The fixed label is
/// [`CHANNEL_BINDING_LABEL`]; the exporter context is the version encoding.
pub fn derive_channel_binding(
    source: &impl ChannelBindingSource,
    negotiated_version: wire::ProtocolVersion,
) -> Result<[u8; CHANNEL_BINDING_LEN], ChannelBindingError> {
    let ctx = version_context(&negotiated_version);
    let mut out = [0u8; CHANNEL_BINDING_LEN];
    source.export_keying_material(CHANNEL_BINDING_LABEL, &ctx, &mut out)?;
    Ok(out)
}

/// Build the canonical signed input (decision D3). Variable-length fields are
/// u16-big-endian length-delimited; fixed-width fields are appended raw.
pub fn signing_input(
    channel_binding: &[u8; CHANNEL_BINDING_LEN],
    claimed_handle: &str,
    claimed_pubkey: &[u8],
    negotiated_version: wire::ProtocolVersion,
    signed_at_unix_ms: u64,
    counter: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(channel_binding);
    push_lp(&mut buf, claimed_handle.as_bytes());
    push_lp(&mut buf, claimed_pubkey);
    buf.extend_from_slice(&version_context(&negotiated_version));
    buf.extend_from_slice(&signed_at_unix_ms.to_be_bytes());
    buf.extend_from_slice(&counter.to_be_bytes());
    buf
}

/// Append a u16-BE length prefix followed by `bytes`.
fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("identity-proof field exceeds u16 length");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Construct and sign an identity-proof envelope (ISC-S19 step 2).
///
/// `signed_at_unix_ms` and `counter` are supplied by the caller — counter
/// state is sourced from the seeds blob by the orchestration layer. `suite_id`
/// is the local identity suite (MVP: 1 = CNSA 2.0). The signature covers the
/// [`signing_input`]; `channel_binding` and `negotiated_version` are recomputed
/// locally by the verifier and never ride the wire.
#[allow(clippy::too_many_arguments)]
pub fn build_envelope(
    signing: &SignKeypair,
    channel_binding: &[u8; CHANNEL_BINDING_LEN],
    claimed_handle: &str,
    role: wire::Role,
    suite_id: u32,
    negotiated_version: wire::ProtocolVersion,
    signed_at_unix_ms: u64,
    counter: u64,
) -> Result<wire::IdentityProof, SignatureError> {
    let pubkey = signing.public_key().to_vec();
    let input = signing_input(
        channel_binding,
        claimed_handle,
        &pubkey,
        negotiated_version,
        signed_at_unix_ms,
        counter,
    );
    let sig = signing.sign(&input)?;
    Ok(wire::IdentityProof {
        suite_id: Some(wire::SuiteId { value: suite_id }),
        role: role as i32,
        claimed_handle: claimed_handle.to_string(),
        claimed_pubkey: pubkey,
        signed_at_unix_ms,
        counter,
        signature: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::Identity;
    use crate::identity::keys::{derive_identity_keys, verify_signature};
    use crate::identity::mnemonic::Mnemonic;

    const ALL_ZEROS_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn ensure_oxicrypt_initialized() {
        let _ = oxicrypt_module::initialize();
    }

    /// Records the args passed to the exporter so tests can assert the
    /// label + context without a real TLS handshake. Returns a deterministic
    /// fill so distinct contexts produce distinct outputs.
    struct RecordingSource {
        last_label: std::cell::RefCell<Vec<u8>>,
        last_context: std::cell::RefCell<Vec<u8>>,
    }

    impl RecordingSource {
        fn new() -> Self {
            Self {
                last_label: std::cell::RefCell::new(Vec::new()),
                last_context: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl ChannelBindingSource for RecordingSource {
        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
            out: &mut [u8],
        ) -> Result<(), ChannelBindingError> {
            *self.last_label.borrow_mut() = label.to_vec();
            *self.last_context.borrow_mut() = context.to_vec();
            // Deterministic fill derived from label+context so different
            // contexts yield different bindings (mimics the exporter).
            for (i, b) in out.iter_mut().enumerate() {
                let mut acc = i as u8;
                for &x in label.iter().chain(context.iter()) {
                    acc = acc.wrapping_add(x);
                }
                *b = acc;
            }
            Ok(())
        }
    }

    fn v(major: u32, minor: u32) -> wire::ProtocolVersion {
        wire::ProtocolVersion { major, minor }
    }

    #[test]
    fn derive_uses_exact_label() {
        let src = RecordingSource::new();
        derive_channel_binding(&src, v(1, 0)).unwrap();
        assert_eq!(&*src.last_label.borrow(), CHANNEL_BINDING_LABEL);
    }

    #[test]
    fn derive_context_is_negotiated_version() {
        let src = RecordingSource::new();
        derive_channel_binding(&src, v(1, 0)).unwrap();
        // major=1, minor=0 → 00000001 00000000 (BE u32 pair).
        assert_eq!(&*src.last_context.borrow(), &[0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn derive_returns_32_bytes() {
        let src = RecordingSource::new();
        let cb = derive_channel_binding(&src, v(1, 0)).unwrap();
        assert_eq!(cb.len(), CHANNEL_BINDING_LEN);
    }

    #[test]
    fn distinct_versions_yield_distinct_bindings() {
        let src = RecordingSource::new();
        let a = derive_channel_binding(&src, v(1, 0)).unwrap();
        let b = derive_channel_binding(&src, v(1, 1)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn signing_input_is_length_delimited_unambiguous() {
        let cb = [7u8; CHANNEL_BINDING_LEN];
        // ("ab","cd") and ("a","bcd") must NOT collide once length-delimited.
        let x = signing_input(&cb, "ab", b"cd", v(1, 0), 0, 0);
        let y = signing_input(&cb, "a", b"bcd", v(1, 0), 0, 0);
        assert_ne!(x, y);
    }

    #[test]
    fn build_envelope_signature_verifies_over_signing_input() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        let cb = [3u8; CHANNEL_BINDING_LEN];
        let env = build_envelope(
            &keys.signing,
            &cb,
            "happy-bear#0011223344ff",
            wire::Role::Client,
            1,
            v(1, 0),
            1_700_000_000_000,
            5,
        )
        .unwrap();

        // Reconstruct the signed input and confirm the signature verifies.
        let input = signing_input(
            &cb,
            "happy-bear#0011223344ff",
            keys.signing.public_key(),
            v(1, 0),
            1_700_000_000_000,
            5,
        );
        let sig: [u8; oxicrypt_ml_dsa::SIG_LEN] = env.signature.clone().try_into().unwrap();
        verify_signature(keys.signing.public_key(), &input, &sig).unwrap();
    }

    #[test]
    fn build_envelope_populates_fields() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        let cb = [3u8; CHANNEL_BINDING_LEN];
        let env = build_envelope(
            &keys.signing,
            &cb,
            "srv#aabbccddeeff",
            wire::Role::Server,
            1,
            v(1, 0),
            1_700_000_000_000,
            9,
        )
        .unwrap();
        assert_eq!(env.role, wire::Role::Server as i32);
        assert_eq!(env.suite_id, Some(wire::SuiteId { value: 1 }));
        assert_eq!(env.claimed_handle, "srv#aabbccddeeff");
        assert_eq!(env.claimed_pubkey, keys.signing.public_key().to_vec());
        assert_eq!(env.signed_at_unix_ms, 1_700_000_000_000);
        assert_eq!(env.counter, 9);
    }
}
