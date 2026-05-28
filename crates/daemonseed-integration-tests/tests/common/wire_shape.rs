//! Wu et al. (USENIX Security 2023) negative-allowlist censor model.
//!
//! Implements the structural features the GFW classifier described in
//! the paper uses to *flag* anti-censorship traffic. Daemonseed's wire
//! shape — TLS 1.3 on :443 with ALPN `h2`, no 0-RTT — is engineered to
//! sit inside the *allowed* set, so the classifier MUST return
//! [`Classification::Accept`] for every gate-driven daemonseed
//! connection. A regression that breaks this property is exactly the
//! kind of bug that lets a censor blackhole the protocol in
//! production but doesn't show up in any unit test.
//!
//! The classifier intentionally does NOT try to be a faithful
//! reimplementation of every Wu feature. It captures the *load-
//! bearing rules for daemonseed*:
//!
//! 1. First TLS record content-type is `0x16` (Handshake). Wu's Ex5
//!    flags first-record types that aren't 0x16 — common with
//!    `obfs4` / `Shadowsocks` framing where the first byte is random.
//! 2. ALPN is `h2`. Wu's Ex4 flags rare-or-empty ALPNs as
//!    anti-censorship proxy fingerprints.
//! 3. Negotiated TLS version is 1.3. Older TLS versions stand out
//!    against the modern web's TLS 1.3 baseline.
//! 4. Server didn't accept 0-RTT early data. 0-RTT outside of a
//!    repeat session is anomalous and feature-flagged in Wu's
//!    follow-up traffic analyses.
//!
//! Each rule maps to one ISC checkbox (45/46/47/48); the integration
//! test feeds a real handshake's observed shape through `classify`
//! and asserts `Accept` (49); the xtask subcommand surfaces the
//! pass/fail bit (50).

#![allow(dead_code)] // Workstream D's only consumer for now is
// tests/usenix_wire_shape.rs; future workstreams (or follow-up
// post-MVP traffic analyses) will pull more of the surface.

/// What a third-party censor would observe about one gate
/// connection. Populated by the integration test from a real
/// daemonseed handshake; fed into [`classify`].
#[derive(Debug, Clone)]
pub struct WireShape {
    /// First byte of the server's response on the wire — the TLS
    /// record content type of whatever the server emitted in
    /// response to a ClientHello. Must be `0x16` (Handshake) for a
    /// well-formed TLS conversation.
    pub first_record_content_type: u8,
    /// The negotiated ALPN protocol identifier. `None` means the
    /// server didn't echo back an ALPN extension at all.
    pub alpn: Option<Vec<u8>>,
    /// The post-handshake TLS protocol version. Reported via
    /// rustls's `ProtocolVersion`; `None` if the handshake didn't
    /// complete far enough to negotiate.
    pub negotiated_version: Option<rustls::ProtocolVersion>,
    /// `true` if 0-RTT early data was consumed by the server.
    /// Daemonseed's server config sets `max_early_data_size = 0` so
    /// this is structurally always `false`; the classifier asserts
    /// it anyway.
    pub early_data_used: bool,
}

/// One classifier verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// The wire shape is indistinguishable from normal HTTPS to the
    /// modelled censor.
    Accept,
    /// The wire shape would be flagged. The message names the rule.
    Reject(String),
}

/// Run a WireShape through the negative-allowlist rules. Returns
/// the first reason the shape would be flagged, or `Accept` when
/// every rule passes.
pub fn classify(shape: &WireShape) -> Classification {
    if shape.first_record_content_type != 0x16 {
        return Classification::Reject(format!(
            "Wu Ex5: first record content-type was {:#04x}, expected 0x16 (TLS Handshake)",
            shape.first_record_content_type
        ));
    }
    match shape.alpn.as_deref() {
        Some(b"h2") => {}
        Some(other) => {
            return Classification::Reject(format!(
                "Wu Ex4: ALPN was {:?}, expected h2",
                String::from_utf8_lossy(other)
            ));
        }
        None => {
            return Classification::Reject(
                "Wu Ex4: no ALPN negotiated — rare/empty ALPN is a censorship-proxy fingerprint"
                    .to_owned(),
            );
        }
    }
    match shape.negotiated_version {
        Some(rustls::ProtocolVersion::TLSv1_3) => {}
        Some(other) => {
            return Classification::Reject(format!(
                "TLS version was {other:?}, expected TLS 1.3 (modern web baseline)"
            ));
        }
        None => {
            return Classification::Reject(
                "TLS handshake didn't complete enough to negotiate a version".to_owned(),
            );
        }
    }
    if shape.early_data_used {
        return Classification::Reject(
            "0-RTT early data was consumed; out-of-session 0-RTT is anomalous".to_owned(),
        );
    }
    Classification::Accept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn green() -> WireShape {
        WireShape {
            first_record_content_type: 0x16,
            alpn: Some(b"h2".to_vec()),
            negotiated_version: Some(rustls::ProtocolVersion::TLSv1_3),
            early_data_used: false,
        }
    }

    #[test]
    fn green_shape_classifies_accept() {
        assert_eq!(classify(&green()), Classification::Accept);
    }

    #[test]
    fn first_byte_not_handshake_rejects() {
        let mut s = green();
        s.first_record_content_type = 0x17;
        match classify(&s) {
            Classification::Reject(m) => assert!(m.contains("Ex5"), "got: {m}"),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn missing_alpn_rejects() {
        let mut s = green();
        s.alpn = None;
        match classify(&s) {
            Classification::Reject(m) => assert!(m.contains("Ex4"), "got: {m}"),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn non_h2_alpn_rejects() {
        let mut s = green();
        s.alpn = Some(b"http/1.1".to_vec());
        match classify(&s) {
            Classification::Reject(m) => assert!(m.contains("Ex4"), "got: {m}"),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn tls12_negotiated_rejects() {
        let mut s = green();
        s.negotiated_version = Some(rustls::ProtocolVersion::TLSv1_2);
        match classify(&s) {
            Classification::Reject(m) => assert!(m.contains("TLS 1.3"), "got: {m}"),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn early_data_used_rejects() {
        let mut s = green();
        s.early_data_used = true;
        match classify(&s) {
            Classification::Reject(m) => assert!(m.contains("0-RTT"), "got: {m}"),
            other => panic!("expected reject, got {other:?}"),
        }
    }
}
