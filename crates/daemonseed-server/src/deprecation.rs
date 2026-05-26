//! Build + sign the operator's suite-deprecation policy from config (ISC-S16 /
//! ISC-A-S11, M7).
//!
//! The operator declares cutoffs in the `[crypto]` TOML table
//! ([`crate::config::CryptoConfig`]); this module turns that into a
//! [`DeprecationPolicy`], validates the F30 lead time, and signs it under the
//! **server-wide key** (the server's long-term signing keypair). The result is
//! installed on the public-space state and served via `GetDeprecationPolicy`.

use std::error::Error;
use std::fmt;

use daemonseed_core::crypto::deprecation::{
    DeprecationEntry, DeprecationPolicy, PolicyError, sign_policy,
};
use daemonseed_core::crypto::suite::{SuiteId, SuiteIdError};
use daemonseed_core::identity::keys::SignatureError;
use daemonseed_proto::v1 as wire;

use crate::config::ServerConfig;
use crate::identity_proof::ServerIdentity;

/// Failure building the signed deprecation policy from config.
#[derive(Debug)]
pub enum DeprecationBuildError {
    /// A configured `suite_id` exceeds the `u16` SuiteId range.
    SuiteIdRange(u32),
    /// A configured `suite_id` was a reserved sentinel.
    SuiteId(SuiteIdError),
    /// Policy validation failed (e.g. F30 cutoff too soon).
    Policy(PolicyError),
    /// Signing the policy under the server-wide key failed.
    Sign(SignatureError),
}

impl fmt::Display for DeprecationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeprecationBuildError::SuiteIdRange(v) => {
                write!(f, "configured suite_id {v} exceeds u16 range")
            }
            DeprecationBuildError::SuiteId(e) => write!(f, "configured suite_id: {e}"),
            DeprecationBuildError::Policy(e) => write!(f, "deprecation policy invalid: {e}"),
            DeprecationBuildError::Sign(e) => write!(f, "deprecation policy signing failed: {e}"),
        }
    }
}

impl Error for DeprecationBuildError {}

fn suite_id(raw: u32) -> Result<SuiteId, DeprecationBuildError> {
    let narrowed = u16::try_from(raw).map_err(|_| DeprecationBuildError::SuiteIdRange(raw))?;
    SuiteId::try_new(narrowed).map_err(DeprecationBuildError::SuiteId)
}

/// Build + sign the operator deprecation policy, or `None` when none is
/// configured (`deprecation_policy_version == 0`). F30 lead-time validation
/// runs against `now_ms` — a config with a cutoff sooner than the minimum lead
/// fails the boot rather than publishing a policy that cannot guarantee
/// warn-before-cutoff.
pub fn build_signed_deprecation_policy(
    cfg: &ServerConfig,
    identity: &ServerIdentity,
    now_ms: i64,
) -> Result<Option<(wire::SignedArtifact, DeprecationPolicy)>, DeprecationBuildError> {
    let crypto = &cfg.crypto;
    if crypto.deprecation_policy_version == 0 {
        return Ok(None);
    }

    let mut entries = Vec::with_capacity(crypto.deprecations.len());
    for e in &crypto.deprecations {
        entries.push(DeprecationEntry {
            suite_id: suite_id(e.suite_id)?,
            cutoff_unix_ms: e.cutoff_unix_ms,
            recommended_suite_id: suite_id(e.recommended_suite_id)?,
        });
    }

    let policy =
        DeprecationPolicy::build(crypto.deprecation_policy_version, now_ms, entries, now_ms)
            .map_err(DeprecationBuildError::Policy)?;
    let artifact =
        sign_policy(&policy, identity.signing_key()).map_err(DeprecationBuildError::Sign)?;
    Ok(Some((artifact, policy)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Seed, derive_server_id};
    use daemonseed_core::crypto::deprecation::verify_policy;

    const HOUR_MS: i64 = 3_600_000;

    fn test_identity() -> ServerIdentity {
        let _ = oxicrypt_module::initialize();
        let seed = Seed([5u8; 32]);
        let server_id =
            derive_server_id(&seed, Some("relay-bear".to_owned())).expect("module operational");
        ServerIdentity::from_seed(&seed, &server_id).unwrap()
    }

    fn cfg_with(version: u64, entries: &str) -> ServerConfig {
        let toml = format!(
            "key_path = \"/tmp/k\"\n[crypto]\ndeprecation_policy_version = {version}\n{entries}"
        );
        ServerConfig::from_toml(&toml).unwrap()
    }

    /// Version 0 (the default) publishes no policy.
    #[test]
    fn no_policy_when_version_zero() {
        let cfg = ServerConfig::from_toml("key_path = \"/tmp/k\"").unwrap();
        let identity = test_identity();
        let out = build_signed_deprecation_policy(&cfg, &identity, 1_000_000_000_000).unwrap();
        assert!(out.is_none());
    }

    /// A configured policy is built and signed under the server-wide key, and
    /// verifies against that key.
    #[test]
    fn builds_and_signs_under_server_wide_key() {
        let now = 1_000_000_000_000;
        let cfg = cfg_with(
            2,
            &format!(
                "[[crypto.deprecation]]\nsuite_id = 1\ncutoff_unix_ms = {}\nrecommended_suite_id = 2\n",
                now + 3 * HOUR_MS
            ),
        );
        let identity = test_identity();
        let (artifact, policy) = build_signed_deprecation_policy(&cfg, &identity, now)
            .unwrap()
            .unwrap();
        assert_eq!(policy.policy_version(), 2);
        // Verifies against the server's public key (the server-wide signer).
        let verified = verify_policy(&artifact, identity.public_key(), None).unwrap();
        assert_eq!(verified, policy);
    }

    /// F30: a config cutoff sooner than the minimum lead fails the build.
    #[test]
    fn rejects_cutoff_too_soon() {
        let now = 1_000_000_000_000;
        let cfg = cfg_with(
            1,
            &format!(
                "[[crypto.deprecation]]\nsuite_id = 1\ncutoff_unix_ms = {}\nrecommended_suite_id = 2\n",
                now + HOUR_MS // only 1h out; min lead is 2h
            ),
        );
        let identity = test_identity();
        let err = build_signed_deprecation_policy(&cfg, &identity, now).unwrap_err();
        assert!(matches!(err, DeprecationBuildError::Policy(_)));
    }
}
