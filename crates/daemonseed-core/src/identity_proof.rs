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

use core::str::FromStr;

use crate::crypto::suite::{Registry, SuiteId};
use crate::handle::Handle;
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};
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

/// Timestamp skew window for identity-proof freshness: **±5 minutes**
/// (decision D1, caraka 2026-05-24 — Matrix-federation middle ground, over a
/// fragile 120s and a wide ±15min). The per-key counter is the primary replay
/// defense; this is a coarse staleness gate. Hosts MUST run NTP — drift beyond
/// this window fails identity-proof against every peer.
pub const SKEW_WINDOW_MS: u64 = 5 * 60 * 1000;

/// A peer whose identity-proof envelope passed every verification check.
///
/// Constructible ONLY by [`verify_envelope`] returning `Ok` — possessing a
/// `VerifiedPeer` is type-level proof that verification succeeded, which is
/// exactly what gates the `Versioned → Authenticated` transition
/// (`Connection::into_authenticated`, ISC-S19 step 5 / ISC-C23).
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    handle: String,
    pubkey: Vec<u8>,
    counter: u64,
    counter_gap: bool,
}

impl VerifiedPeer {
    /// The verified peer's wire handle.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The verified peer's long-term ML-DSA-87 public key.
    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    /// The envelope's counter. The orchestration layer records this as the new
    /// highest-seen for this `(signer-key, target-server)` pair.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// True if the counter skipped ahead of the expected next value (missed
    /// messages). Informational — the caller logs it; it is NOT a failure
    /// (`project_clocks_freshness` gap-tolerance).
    pub fn counter_gap(&self) -> bool {
        self.counter_gap
    }
}

/// Opaque, uniform rejection of an identity-proof envelope.
///
/// Deliberately carries NO discriminator: a tampered signature, a wrong key,
/// a stale timestamp, a replayed counter, an unsupported suite, and a
/// handle/pubkey mismatch all collapse to this single value. Neither the
/// caller nor (via the connection it closes) the peer can tell which check
/// failed (ISC-A-S12 / ISC-A-C18 uniform close-shape).
///
/// Note: close-*shape* is uniform by construction here. Constant-*time* across
/// check types (the signature verify dominates and short-circuits run before
/// it create measurable timing variance) is a best-effort property of this
/// layer; structural delay-padding, if required, belongs in the server close
/// path per ISC-A-S12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyRejection;

impl core::fmt::Display for VerifyRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "identity-proof verification failed")
    }
}

impl std::error::Error for VerifyRejection {}

/// Verify an incoming identity-proof envelope (ISC-S19 step 4).
///
/// Runs every check; on any failure returns the uniform [`VerifyRejection`].
/// `channel_binding` and `negotiated_version` are recomputed locally by the
/// caller (never read from the envelope) — that is what makes a cross-session
/// replay fail by construction (the recomputed binding won't match the signed
/// one). `highest_seen_counter` is the last counter accepted from this signer
/// (`None` on first contact); see `project_clocks_freshness` for the
/// gap-vs-replay rule. The verification path is identical for client and
/// server envelopes — `role` is never an auth branch (ISC-A-S8).
pub fn verify_envelope(
    envelope: &wire::IdentityProof,
    channel_binding: &[u8; CHANNEL_BINDING_LEN],
    negotiated_version: wire::ProtocolVersion,
    now_unix_ms: u64,
    highest_seen_counter: Option<u64>,
) -> Result<VerifiedPeer, VerifyRejection> {
    // suite_id present, well-formed, and supported by the local registry.
    let suite_raw = envelope.suite_id.as_ref().ok_or(VerifyRejection)?.value;
    let suite_u16 = u16::try_from(suite_raw).map_err(|_| VerifyRejection)?;
    let suite_id = SuiteId::try_new(suite_u16).map_err(|_| VerifyRejection)?;
    if Registry::lookup(suite_id).is_none() {
        return Err(VerifyRejection);
    }

    // role must be a well-formed, non-unspecified value. Bookkeeping only — the
    // path below does NOT branch on which role it is (ISC-A-S8).
    match wire::Role::try_from(envelope.role) {
        Ok(wire::Role::Client | wire::Role::Server) => {}
        _ => return Err(VerifyRejection),
    }

    // handle ↔ pubkey binding: the handle's 12-hex hash component MUST equal
    // SHA-384(claimed_pubkey)[:12] (anchors ISC-C4 / ISC-S11 self-verification).
    let claimed = Handle::from_str(&envelope.claimed_handle).map_err(|_| VerifyRejection)?;
    let expected =
        Handle::from_pubkey(None, &envelope.claimed_pubkey).map_err(|_| VerifyRejection)?;
    if claimed.hash_prefix() != expected.hash_prefix() {
        return Err(VerifyRejection);
    }

    // signature over the canonical input. channel_binding + negotiated_version
    // are the caller's locally-recomputed values, so a captured envelope from
    // another session fails here.
    let pubkey: [u8; oxicrypt_ml_dsa::PK_LEN] = envelope
        .claimed_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| VerifyRejection)?;
    let sig: [u8; oxicrypt_ml_dsa::SIG_LEN] = envelope
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| VerifyRejection)?;
    let input = signing_input(
        channel_binding,
        &envelope.claimed_handle,
        &envelope.claimed_pubkey,
        negotiated_version,
        envelope.signed_at_unix_ms,
        envelope.counter,
    );
    verify_signature(&pubkey, &input, &sig).map_err(|_| VerifyRejection)?;

    // freshness: timestamp within ±SKEW_WINDOW_MS of the local clock.
    if now_unix_ms.abs_diff(envelope.signed_at_unix_ms) > SKEW_WINDOW_MS {
        return Err(VerifyRejection);
    }

    // replay: counter MUST advance past highest-seen. A skip (gap) is allowed
    // and flagged; a value <= highest-seen is a replay or rollback.
    let counter_gap = match highest_seen_counter {
        Some(h) => {
            if envelope.counter <= h {
                return Err(VerifyRejection);
            }
            envelope.counter > h + 1
        }
        None => false,
    };

    Ok(VerifiedPeer {
        handle: envelope.claimed_handle.clone(),
        pubkey: envelope.claimed_pubkey.clone(),
        counter: envelope.counter,
        counter_gap,
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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

    // ── Verification (ISC-S19 step 4, A-S14, A-C18) ──────────────────

    use crate::handle::{DisplayMode, Handle};
    use crate::identity::keys::IdentityKeys;

    const NOW: u64 = 1_700_000_000_000;

    fn primary_keys() -> IdentityKeys {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        derive_identity_keys(&m, Identity::Primary).unwrap()
    }

    fn device_keys() -> IdentityKeys {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        derive_identity_keys(
            &m,
            Identity::Device {
                uuid: uuid::Uuid::nil(),
            },
        )
        .unwrap()
    }

    /// A wire handle whose 12-hex hash component matches `keys`' pubkey.
    fn valid_handle(keys: &IdentityKeys) -> String {
        Handle::from_pubkey(Some("alice".to_string()), keys.signing.public_key())
            .unwrap()
            .format(DisplayMode::Verify)
    }

    fn env_for(
        keys: &IdentityKeys,
        cb: &[u8; CHANNEL_BINDING_LEN],
        handle: &str,
        suite: u32,
        ver: wire::ProtocolVersion,
        ts: u64,
        counter: u64,
    ) -> wire::IdentityProof {
        build_envelope(
            &keys.signing,
            cb,
            handle,
            wire::Role::Client,
            suite,
            ver,
            ts,
            counter,
        )
        .unwrap()
    }

    #[test]
    fn verify_accepts_valid_envelope() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        let peer = verify_envelope(&env, &cb, v(1, 0), NOW, None).unwrap();
        assert_eq!(peer.counter(), 1);
        assert!(!peer.counter_gap());
        assert_eq!(peer.pubkey(), keys.signing.public_key());
    }

    #[test]
    fn verify_rejects_handle_pubkey_mismatch() {
        let keys = primary_keys();
        let other = device_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        // Handle taken from `other`'s pubkey, but the envelope is signed by `keys`.
        let bad_handle = valid_handle(&other);
        let env = env_for(&keys, &cb, &bad_handle, 1, v(1, 0), NOW, 1);
        assert!(verify_envelope(&env, &cb, v(1, 0), NOW, None).is_err());
    }

    #[test]
    fn verify_rejects_unsupported_suite() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        // suite_id 999 is well-formed but absent from the registry.
        let env = env_for(&keys, &cb, &h, 999, v(1, 0), NOW, 1);
        assert!(verify_envelope(&env, &cb, v(1, 0), NOW, None).is_err());
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let mut env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        env.signature[0] ^= 0xff;
        assert!(verify_envelope(&env, &cb, v(1, 0), NOW, None).is_err());
    }

    #[test]
    fn verify_rejects_channel_binding_mismatch() {
        // The cross-session replay defense: an envelope built under one
        // channel binding fails when verified under a different one.
        let keys = primary_keys();
        let h = valid_handle(&keys);
        let env = env_for(&keys, &[1u8; CHANNEL_BINDING_LEN], &h, 1, v(1, 0), NOW, 1);
        assert!(verify_envelope(&env, &[2u8; CHANNEL_BINDING_LEN], v(1, 0), NOW, None).is_err());
    }

    #[test]
    fn verify_rejects_version_mismatch() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        assert!(verify_envelope(&env, &cb, v(1, 1), NOW, None).is_err());
    }

    #[test]
    fn verify_rejects_timestamp_outside_skew() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        // 6 minutes late — outside the ±5min window.
        assert!(verify_envelope(&env, &cb, v(1, 0), NOW + 6 * 60 * 1000, None).is_err());
    }

    #[test]
    fn verify_accepts_timestamp_within_skew() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        // 4 minutes late — inside the window.
        verify_envelope(&env, &cb, v(1, 0), NOW + 4 * 60 * 1000, None).unwrap();
    }

    #[test]
    fn verify_rejects_counter_replay() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 5);
        // counter == highest-seen → replay.
        assert!(verify_envelope(&env, &cb, v(1, 0), NOW, Some(5)).is_err());
    }

    #[test]
    fn verify_rejects_counter_decrease() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 3);
        assert!(verify_envelope(&env, &cb, v(1, 0), NOW, Some(5)).is_err());
    }

    #[test]
    fn verify_flags_counter_gap_but_accepts() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 9);
        let peer = verify_envelope(&env, &cb, v(1, 0), NOW, Some(5)).unwrap();
        assert!(peer.counter_gap());
    }

    #[test]
    fn verify_accepts_sequential_counter() {
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let env = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 6);
        let peer = verify_envelope(&env, &cb, v(1, 0), NOW, Some(5)).unwrap();
        assert!(!peer.counter_gap());
    }

    #[test]
    fn verify_path_is_role_uniform() {
        // A server-role envelope verifies through the identical path — role is
        // bookkeeping, not an auth boundary (ISC-S19 / A-S8).
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);
        let server_env = build_envelope(
            &keys.signing,
            &cb,
            &h,
            wire::Role::Server,
            1,
            v(1, 0),
            NOW,
            1,
        )
        .unwrap();
        verify_envelope(&server_env, &cb, v(1, 0), NOW, None).unwrap();
    }

    #[test]
    fn verify_rejection_is_uniform_across_causes() {
        // Two distinct failure causes return the SAME opaque rejection value —
        // the caller cannot distinguish which check failed (ISC-A-S12 / A-C18).
        let keys = primary_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let h = valid_handle(&keys);

        let mut bad_sig = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        bad_sig.signature[0] ^= 0xff;
        let r1 = verify_envelope(&bad_sig, &cb, v(1, 0), NOW, None).unwrap_err();

        let bad_skew = env_for(&keys, &cb, &h, 1, v(1, 0), NOW, 1);
        let r2 = verify_envelope(&bad_skew, &cb, v(1, 0), NOW + 6 * 60 * 1000, None).unwrap_err();

        assert_eq!(r1, r2);
    }
}
