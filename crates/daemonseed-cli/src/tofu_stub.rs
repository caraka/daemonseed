//! **M4a-only** server-certificate verifier — accepts any cert.
//!
//! This is a deliberate placeholder. Real verification (TOFU on first
//! contact + identity-proof envelope on every subsequent connection)
//! lands in M4b. M4a's CLI exists solely to drive the wire round-trip
//! and prove the `Negotiating → Versioned` advance composes against a
//! real TLS handshake.
//!
//! The verifier name spells out the danger so a grep for "TOFU" or
//! "AcceptAny" surfaces every site that needs to change in M4b. When
//! M4b lands, this module deletes wholesale and the client uses
//! `daemonseed_client::tofu::Tofu` (or whatever the M4b crate names
//! it).
//!
//! ## What this means in practice
//!
//! - A network-position MITM cannot be detected at the TLS layer in
//!   M4a. The application-layer identity-proof envelope in M4b is
//!   what closes that gap (channel-bound to the TLS exporter so a
//!   MITM that re-terminates TLS cannot replay the proof).
//! - The 12-hex hash prefix in the server-id is the human-checkable
//!   anchor; in M4b the client compares it against `SHA-384(server
//!   long-term ML-DSA-87 pubkey)` from the identity-proof.

use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// Server-cert verifier that accepts every server cert. Constructs
/// against the installed `CryptoProvider`'s signature schemes so the
/// TLS-1.3 signature-validation path still uses the CNSA-2.0 ML-DSA-87
/// codepoint (the *cert chain* is what we're not validating; the
/// per-handshake CertificateVerify still runs).
#[derive(Debug)]
pub struct AcceptAnyServerCert {
    signature_schemes: Vec<SignatureScheme>,
}

impl AcceptAnyServerCert {
    /// Construct from the process-wide installed `CryptoProvider`.
    /// Caller must have driven `install_provider()` first.
    pub fn from_installed_provider() -> Arc<Self> {
        let provider = CryptoProvider::get_default().expect(
            "CryptoProvider must be installed before AcceptAnyServerCert::from_installed_provider",
        );
        Arc::new(Self {
            signature_schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        })
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // M4a: skip every chain check. M4b replaces with TOFU +
        // identity-proof.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 path is never reached — `ClientConfig` is built
        // `with_protocol_versions(&[&TLS13])`. Implement only because
        // the trait requires it.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Delegate to rustls's stock TLS-1.3 signature-validation
        // helper, which routes the ML-DSA-87 codepoint (0x0906)
        // through the installed provider's `VerificationAlgorithm`
        // table. This is the load-bearing piece — the *chain* is
        // unchecked in M4a, but the per-handshake CertificateVerify
        // signature still has to be valid under the cert's public
        // key for the handshake to complete.
        let provider = CryptoProvider::get_default().expect("CryptoProvider installed");
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_schemes.clone()
    }
}

// `AcceptAnyServerCert` carries no runtime state beyond the immutable
// signature-scheme list, so a `dyn ServerCertVerifier` from it is
// trivially `Send + Sync`. The trait requires `Debug + Send + Sync`.
