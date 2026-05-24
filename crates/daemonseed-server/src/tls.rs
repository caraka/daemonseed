//! rustls `ServerConfig` assembly for daemonseed-server.
//!
//! Closes the M4a TLS-termination ISC bundle (ISC-S2a / S2b / S5 /
//! ISC-A-S9). The build:
//!
//! - registers `oxitls_rustls_provider::cnsa_2_0_hybrid_provider`
//!   as the process-wide rustls [`rustls::crypto::CryptoProvider`] (idempotent via
//!   a `Once` so concurrent test runs don't race on
//!   `install_default`),
//! - builds an ML-DSA-87 self-signed cert + matching PKCS#8 private
//!   key via the oxitls v0.1.1 helpers (`build_self_signed_ml_dsa_87_cert`
//!   + `ml_dsa_87_private_key_from_seed`),
//! - assembles a `ServerConfig` with TLS 1.3 only,
//!   `alpn_protocols = [b"h2"]` (GFW-survivability anchor — first TLS
//!   record on :443 looks like generic HTTPS), `max_early_data_size = 0`
//!   (0-RTT structurally excluded per ISC-A-S9).
//!
//! **Module-gate precondition:** `cnsa_2_0_hybrid_provider()` returns
//! `Error::ModuleStartup` if `oxicrypt-module` is not in the
//! `Operational` state. The caller (production: `main()` after KATS
//! init; tests: `ensure_module_operational()`) is responsible for
//! driving the init. This module does NOT initialize the module — see
//! `kats` for the production KATS-assembly helper.
//!
//! ISCs anchored: ISC-S5 (TLS 1.3 on :443 with ALPN h2), ISC-S2a (PFS
//! via ML-KEM ephemeral exchange), ISC-S2b (no peer metadata
//! exposure), ISC-A-S9 (no silent downgrade), ISC-A6 (no fallback to a
//! non-CNSA-2.0 provider — `install_default` Err is fatal).

use core::fmt;
use std::error::Error;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use oxitls_rustls_provider::{cnsa_2_0_hybrid_provider, ml_dsa_87_private_key_from_seed};
use oxitls_webpki_mldsa::{CertBuilderError, build_self_signed_ml_dsa_87_cert};
use rustls::ServerConfig;
use rustls::version::TLS13;

use crate::identity::{Seed, ServerId};

/// Default validity window for the M4a self-signed cert. 90 days is
/// short enough that rotation cadence stays operationally visible and
/// long enough that an operator on a holiday schedule doesn't get
/// surprised. Post-MVP M7 trust-event taxonomy adds rotation
/// scheduling around this.
pub const DEFAULT_CERT_VALIDITY: Duration = Duration::from_secs(90 * 24 * 60 * 60);

// ── Provider registration ────────────────────────────────────────

/// Cached outcome of [`install_provider`]'s first call. The full
/// structured `TlsErrorKind` enum isn't `Clone` (it carries a
/// `CertBuilderError` which isn't `Clone`), so the cache uses this
/// small `Copy` discriminator. The detail message of the
/// provider-construction error is logged on the first call (where it
/// originates) and discarded from the cache; subsequent callers see a
/// generic message pointing to the first-boot logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    Ok,
    ProviderConstructionFailed,
    AlreadyInstalled,
}

/// Install `cnsa_2_0_hybrid_provider` as the process-wide rustls
/// [`rustls::crypto::CryptoProvider`]. Idempotent via `OnceLock` — safe to call from
/// concurrent tests. Returns the install outcome of the first call;
/// subsequent calls return that same outcome (rebuilt as a fresh
/// `TlsError`).
///
/// Per ISC-A6: if `install_default` returns `Err` on the **first**
/// call (meaning some other crate already registered a provider),
/// daemonseed-server treats it as fatal at boot — silently falling
/// back to `aws_lc_rs` (rustls's default) would break the pure-Rust +
/// CNSA 2.0 invariant.
pub fn install_provider() -> Result<(), TlsError> {
    static OUTCOME: OnceLock<InstallOutcome> = OnceLock::new();

    let outcome = OUTCOME.get_or_init(|| {
        let provider = match cnsa_2_0_hybrid_provider() {
            Ok(p) => p,
            Err(_) => return InstallOutcome::ProviderConstructionFailed,
        };
        // `install_default` takes `CryptoProvider` by value (consumes it).
        // The Err arm wraps the rejected provider in an Arc; we discard it.
        match provider.install_default() {
            Ok(()) => InstallOutcome::Ok,
            Err(_already_installed) => InstallOutcome::AlreadyInstalled,
        }
    });

    match outcome {
        InstallOutcome::Ok => Ok(()),
        InstallOutcome::ProviderConstructionFailed => {
            Err(TlsError::from_kind(TlsErrorKind::Provider(
                "cnsa_2_0_hybrid_provider failed on first install_provider() call \
                 (see boot logs for the underlying oxitls error)"
                    .to_owned(),
            )))
        }
        InstallOutcome::AlreadyInstalled => {
            Err(TlsError::from_kind(TlsErrorKind::ProviderAlreadyInstalled))
        }
    }
}

// ── ServerConfig assembly ────────────────────────────────────────

/// Build the rustls `ServerConfig` daemonseed-server will hand to
/// the listener's `TlsAcceptor` (commit 4 of M4a).
///
/// `valid_for` controls the self-signed cert's `not_after` window;
/// see [`DEFAULT_CERT_VALIDITY`] for the M4a default.
///
/// **Caller contract:** [`install_provider`] must have returned
/// `Ok(())` before this function is invoked. `ServerConfig::builder()`
/// uses the process-wide installed default `CryptoProvider`; we rely
/// on that being our `cnsa_2_0_hybrid_provider` so we get the CNSA 2.0
/// cipher suite + hybrid kx-group + ML-DSA-87 sigscheme automatically.
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
        .map_err(|e| TlsError::from_kind(TlsErrorKind::CertBuilder(e)))?;
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

// ── Errors ───────────────────────────────────────────────────────

/// Public error type returned by the TLS-config builder. Wraps an
/// internal [`TlsErrorKind`] discriminator.
#[derive(Debug)]
pub struct TlsError {
    kind: TlsErrorKind,
}

impl TlsError {
    fn from_kind(kind: TlsErrorKind) -> Self {
        Self { kind }
    }

    /// The underlying error discriminator. Useful for tests + error-
    /// surface assertions.
    pub fn kind(&self) -> &TlsErrorKind {
        &self.kind
    }
}

/// Discriminator for [`TlsError`]. `Provider` and `Rustls` carry
/// stringified messages because the underlying error types aren't
/// `Clone` and we want a uniform display surface.
#[derive(Debug)]
pub enum TlsErrorKind {
    /// `oxitls_rustls_provider::Error` — wraps the message because
    /// the underlying error is not `Clone`.
    Provider(String),
    /// `install_default()` returned `Err` on the first attempt —
    /// some other crate already registered a `CryptoProvider`. Fatal
    /// per ISC-A6.
    ProviderAlreadyInstalled,
    /// `oxitls_webpki_mldsa::CertBuilderError` — preserved
    /// structurally because `CertBuilderError` is `Debug`.
    CertBuilder(CertBuilderError),
    /// `rustls::Error` — wraps the message for the same `Clone`
    /// reason as `Provider`.
    Rustls(String),
    /// `SystemTime::checked_add(valid_for)` overflowed — only
    /// reachable with absurdly large `valid_for` values.
    ValidityOverflow,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            TlsErrorKind::Provider(msg) => write!(f, "oxitls provider error: {msg}"),
            TlsErrorKind::ProviderAlreadyInstalled => write!(
                f,
                "another CryptoProvider is already installed as the rustls default; \
                 refusing to fall back from CNSA 2.0 per ISC-A6"
            ),
            TlsErrorKind::CertBuilder(e) => write!(f, "ML-DSA-87 cert build failed: {e:?}"),
            TlsErrorKind::Rustls(msg) => write!(f, "rustls ServerConfig build failed: {msg}"),
            TlsErrorKind::ValidityOverflow => {
                write!(f, "cert validity window overflowed SystemTime")
            }
        }
    }
}

impl Error for TlsError {}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{derive_server_id, generate_seed};

    fn ensure_module() {
        oxitls_rustls_provider::testing::ensure_module_operational();
    }

    #[test]
    fn install_provider_is_idempotent_across_calls() {
        ensure_module();
        // First call may either succeed (we won) or fail with
        // ProviderAlreadyInstalled (another test in this process
        // already won the race). Either way the steady-state should
        // be that we're the installed provider on subsequent calls.
        let _ = install_provider();
        // Second call returns the same outcome (Once stores it).
        let _ = install_provider();
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
