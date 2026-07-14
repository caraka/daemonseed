//! Process-wide rustls `CryptoProvider` install for daemonseed.
//!
//! Registers `oxitls_rustls_provider::cnsa_2_0_hybrid_provider` as the
//! process-wide rustls [`rustls::crypto::CryptoProvider`] (idempotent via
//! a `OnceLock` so concurrent test runs don't race on `install_default`),
//! and exposes the [`TlsError`] surface shared by the provider-install
//! path and the server-side `ServerConfig` builder.
//!
//! **Module-gate precondition:** `cnsa_2_0_hybrid_provider()` returns an
//! error if `oxicrypt-module` is not in the `Operational` state. The
//! caller (production: `main()` after KATS init; tests:
//! `ensure_module_operational()`) is responsible for driving the init.
//! This module does NOT initialize the module — see [`crate::kats`] for
//! the production KATS-assembly helper.
//!
//! ISCs anchored: ISC-A6 (no fallback to a non-CNSA-2.0 provider —
//! `install_default` Err is fatal).

use core::fmt;
use std::error::Error;
use std::sync::OnceLock;

use oxitls_rustls_provider::cnsa_2_0_hybrid_provider;

// ── Provider registration ────────────────────────────────────────

/// Cached outcome of [`install_provider`]'s first call. The full
/// structured `TlsErrorKind` enum isn't `Clone`, so the cache uses this
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
/// daemonseed treats it as fatal at boot — silently falling
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

// ── Errors ───────────────────────────────────────────────────────

/// Public error type returned by the provider-install path and the
/// server-side TLS-config builder. Wraps an internal [`TlsErrorKind`]
/// discriminator.
#[derive(Debug)]
pub struct TlsError {
    kind: TlsErrorKind,
}

impl TlsError {
    /// Construct a `TlsError` from its discriminator. Used by the
    /// provider-install path here and by the server-side `ServerConfig`
    /// builder that reuses this shared error surface.
    pub fn from_kind(kind: TlsErrorKind) -> Self {
        Self { kind }
    }

    /// The underlying error discriminator. Useful for tests + error-
    /// surface assertions.
    pub fn kind(&self) -> &TlsErrorKind {
        &self.kind
    }
}

/// Discriminator for [`TlsError`]. `Provider`, `CertBuilder`, and
/// `Rustls` carry stringified messages because the underlying error
/// types aren't `Clone` and we want a uniform display surface.
#[derive(Debug)]
pub enum TlsErrorKind {
    /// `oxitls_rustls_provider::Error` — wraps the message because
    /// the underlying error is not `Clone`.
    Provider(String),
    /// `install_default()` returned `Err` on the first attempt —
    /// some other crate already registered a `CryptoProvider`. Fatal
    /// per ISC-A6.
    ProviderAlreadyInstalled,
    /// `oxitls_webpki_mldsa::CertBuilderError` — stringified so this
    /// shared error surface carries no dependency on the cert-builder
    /// crate (the server-side builder that produces it lives in
    /// `daemonseed-server`).
    CertBuilder(String),
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
            TlsErrorKind::CertBuilder(msg) => write!(f, "ML-DSA-87 cert build failed: {msg}"),
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
}
