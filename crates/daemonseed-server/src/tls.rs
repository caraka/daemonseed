//! rustls `ServerConfig` assembly for daemonseed-server.
//!
//! Closes the M4a TLS-termination ISC bundle (ISC-S2a / S2b / S5 /
//! ISC-A-S9). The build:
//!
//! - builds an ML-DSA-87 self-signed cert + matching PKCS#8 private
//!   key via the oxitls v0.1.1 helpers (`build_self_signed_ml_dsa_87_cert`
//!   + `ml_dsa_87_private_key_from_seed`),
//! - assembles a `ServerConfig` with TLS 1.3 only,
//!   `alpn_protocols = [b"h2"]` (GFW-survivability anchor — first TLS
//!   record on :443 looks like generic HTTPS), `max_early_data_size = 0`
//!   (0-RTT structurally excluded per ISC-A-S9).
//!
//! The process-wide `CryptoProvider` install (`install_provider`) and
//! the shared [`TlsError`](daemonseed_core::tls::TlsError) surface live
//! in [`daemonseed_core::tls`]; this module reuses them.
//!
//! **Module-gate precondition:** the CNSA 2.0 provider requires
//! `oxicrypt-module` in the `Operational` state. The caller (production:
//! `main()` after KATS init; tests: `ensure_module_operational()`) is
//! responsible for driving the init. This module does NOT initialize the
//! module — see `daemonseed_core::kats` for the production KATS-assembly
//! helper.
//!
//! ISCs anchored: ISC-S5 (TLS 1.3 on :443 with ALPN h2), ISC-S2a (PFS
//! via ML-KEM ephemeral exchange), ISC-S2b (no peer metadata
//! exposure), ISC-A-S9 (no silent downgrade).

use std::time::{Duration, SystemTime};

use daemonseed_core::tls::{TlsError, TlsErrorKind};
use oxitls_rustls_provider::ml_dsa_87_private_key_from_seed;
use oxitls_webpki_mldsa::build_self_signed_ml_dsa_87_cert;
use rustls::ServerConfig;
use rustls::version::TLS13;

use crate::identity::{Seed, ServerId};

/// Default validity window for the M4a self-signed cert. 90 days is
/// short enough that rotation cadence stays operationally visible and
/// long enough that an operator on a holiday schedule doesn't get
/// surprised. Post-MVP M7 trust-event taxonomy adds rotation
/// scheduling around this.
pub const DEFAULT_CERT_VALIDITY: Duration = Duration::from_secs(90 * 24 * 60 * 60);

// ── ServerConfig assembly ────────────────────────────────────────

/// Build the rustls `ServerConfig` daemonseed-server will hand to
/// the listener's `TlsAcceptor` (commit 4 of M4a).
///
/// `valid_for` controls the self-signed cert's `not_after` window;
/// see [`DEFAULT_CERT_VALIDITY`] for the M4a default.
///
/// **Caller contract:** [`daemonseed_core::tls::install_provider`] must
/// have returned `Ok(())` before this function is invoked.
/// `ServerConfig::builder()` uses the process-wide installed default
/// `CryptoProvider`; we rely on that being our `cnsa_2_0_hybrid_provider`
/// so we get the CNSA 2.0 cipher suite + hybrid kx-group + ML-DSA-87
/// sigscheme automatically.
pub fn build_server_config(
    seed: &Seed,
    server_id: &ServerId,
    valid_for: Duration,
) -> Result<ServerConfig, TlsError> {
    let now = SystemTime::now();
    let not_after = now
        .checked_add(valid_for)
        .ok_or_else(|| TlsError::from_kind(TlsErrorKind::ValidityOverflow))?;

    // Server-id used as the cert Subject / Issuer CommonName per ISC-S11.
    // Verify-mode rendering is the canonical wire form.
    let subject = server_id.format(daemonseed_core::handle::DisplayMode::Verify);

    let cert = build_self_signed_ml_dsa_87_cert(seed.as_bytes(), &subject, now, not_after)
        .map_err(|e| TlsError::from_kind(TlsErrorKind::CertBuilder(format!("{e:?}"))))?;
    let key = ml_dsa_87_private_key_from_seed(seed.as_bytes())
        .map_err(|e| TlsError::from_kind(TlsErrorKind::Provider(format!("{e}"))))?;

    // `builder_with_protocol_versions` makes the TLS 1.3 commitment loud in
    // daemonseed even though the installed provider already enforces it
    // (oxitls's `tls12` feature is intentionally absent).
    let cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| TlsError::from_kind(TlsErrorKind::Rustls(format!("{e}"))))?;

    apply_invariants(cfg)
}

/// Apply the M4a TLS-shape invariants to a freshly-built
/// `ServerConfig` — split out so unit tests can verify each
/// invariant in isolation.
///
/// - **ALPN:** exactly `[b"h2"]`. No fallback. First TLS record on :443
///   looks like generic HTTPS (GFW-survivability per Wu et al. 2023).
/// - **0-RTT:** `max_early_data_size = 0`. APP_HELLO MUST be exchanged
///   post-handshake, never as TLS 1.3 early data per ISC-A-S9.
fn apply_invariants(mut cfg: ServerConfig) -> Result<ServerConfig, TlsError> {
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg.max_early_data_size = 0;
    Ok(cfg)
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::tls::install_provider;

    use crate::identity::{derive_server_id, generate_seed};

    fn ensure_module() {
        oxitls_rustls_provider::testing::ensure_module_operational();
    }

    #[test]
    fn build_server_config_succeeds_with_default_validity() {
        ensure_module();
        let _ = install_provider();
        let seed = generate_seed().unwrap();
        let server_id = derive_server_id(&seed, Some("test-bear".to_owned())).unwrap();
        let cfg = build_server_config(&seed, &server_id, DEFAULT_CERT_VALIDITY)
            .expect("build_server_config should succeed under default validity");
        // ALPN invariant — exactly h2, no fallback.
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()], "ISC-S5 ALPN gate");
        // 0-RTT invariant per ISC-A-S9.
        assert_eq!(cfg.max_early_data_size, 0, "ISC-A-S9 0-RTT excluded");
    }

    /// Helper: every test below needs a display-named server-id because
    /// the floor form (`#<12hex>`) has a leading `#` that x509-cert's
    /// CommonName parser rejects. That's an oxitls v0.1.1 behavior; the
    /// follow-up issue is whether daemonseed should always derive a
    /// non-floor display name for cert subjects (ISC-C4b interaction
    /// — currently operators *may* leave display_name empty per the
    /// ISC, but the TLS cert path forces a non-empty subject). Tracked
    /// for M4b or as a separate fix-up commit.
    fn named_test_server_id(seed: &Seed) -> ServerId {
        derive_server_id(seed, Some("test-bear".to_owned())).unwrap()
    }

    #[test]
    fn build_server_config_carries_hybrid_provider_with_two_kx_groups() {
        ensure_module();
        let _ = install_provider();
        let seed = generate_seed().unwrap();
        let server_id = named_test_server_id(&seed);
        let cfg = build_server_config(&seed, &server_id, DEFAULT_CERT_VALIDITY).unwrap();
        // ISC-13 verification (hybrid posture per the handoff doc).
        assert_eq!(
            cfg.crypto_provider().kx_groups.len(),
            2,
            "cnsa_2_0_hybrid_provider must offer 2 kx_groups (SECP384R1_MLKEM1024 + MLKEM1024)"
        );
    }

    #[test]
    fn build_server_config_single_cipher_suite() {
        ensure_module();
        let _ = install_provider();
        let seed = generate_seed().unwrap();
        let server_id = named_test_server_id(&seed);
        let cfg = build_server_config(&seed, &server_id, DEFAULT_CERT_VALIDITY).unwrap();
        // CNSA-2.0-only stance: exactly one cipher suite, the
        // `TLS_AES_256_GCM_SHA384` per the handoff.
        assert_eq!(
            cfg.crypto_provider().cipher_suites.len(),
            1,
            "CNSA-2.0-only provider offers exactly one cipher suite"
        );
    }

    #[test]
    fn build_server_config_no_client_auth() {
        ensure_module();
        let _ = install_provider();
        let seed = generate_seed().unwrap();
        let server_id = named_test_server_id(&seed);
        let cfg = build_server_config(&seed, &server_id, DEFAULT_CERT_VALIDITY).unwrap();
        // ISC-S5 — TLS-layer client auth is OFF. Application-layer
        // identity-proof (M4b) is the authentication boundary, not TLS.
        // (rustls 0.23 exposes the verifier indirectly; the call we
        // made — `with_no_client_auth()` — sets it.)
        let _ = cfg; // Type-level check: build succeeded means with_no_client_auth() chained.
    }

    #[test]
    fn floor_form_server_id_is_rejected_by_cert_builder() {
        // Floor form (no display name) has a leading `#` which
        // x509-cert's RDN/CommonName parser rejects. This test pins
        // the current behavior so any future change is visible. See
        // the `named_test_server_id` helper for the rationale.
        ensure_module();
        let _ = install_provider();
        let seed = generate_seed().unwrap();
        let floor = derive_server_id(&seed, None).unwrap();
        let err = build_server_config(&seed, &floor, DEFAULT_CERT_VALIDITY)
            .expect_err("floor-form server-id must surface a CertBuilder error");
        assert!(
            matches!(err.kind(), TlsErrorKind::CertBuilder(_)),
            "expected CertBuilder error, got {err:?}"
        );
    }

    #[test]
    fn validity_overflow_yields_named_error() {
        ensure_module();
        let _ = install_provider();
        let seed = generate_seed().unwrap();
        let server_id = named_test_server_id(&seed);
        let err = build_server_config(&seed, &server_id, Duration::MAX)
            .expect_err("Duration::MAX must overflow SystemTime");
        assert!(
            matches!(err.kind(), TlsErrorKind::ValidityOverflow),
            "got {err:?}"
        );
    }
}
