//! `daemonseed.toml` schema + (de)serialization.
//!
//! The profile config holds:
//! - `profile_id` (UUID v4) per ISC-C36 / ISC-A-C16.
//! - `[argon2]` work-factor table per ISC-C14 / ISC-A-C17 — `memory_kib`,
//!   `iterations`, `parallelism`. Mirrored in the `.dseed` recovery file's
//!   cleartext header (ISC-C32) so recovery on a clean device can derive
//!   the same key.
//!
//! Editing the file is destructive: a missing or unparseable `profile_id`
//! refuses startup (per ISC-C36); changing Argon2 params silently is
//! forbidden by ISC-A-C17 — params travel with the encrypted artifacts.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Argon2id work factors persisted per profile (ISC-C14).
///
/// Defaults below match OWASP 2024 desktop guidance: 19 MiB memory, t=2,
/// p=1. Mobile profiles should reduce memory to land in the 250–500 ms
/// work-factor target on phone hardware; mobile-first-start derives those
/// at enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgonParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iteration count (Argon2 `t`).
    pub iterations: u32,
    /// Parallelism (Argon2 `p`).
    pub parallelism: u32,
}

impl ArgonParams {
    /// OWASP 2024 desktop defaults: 19 MiB memory, t=2, p=1.
    pub const fn desktop_default() -> Self {
        Self {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

}

impl Default for ArgonParams {
    fn default() -> Self {
        Self::desktop_default()
    }
}

/// Errors surfaced by [`ProfileConfig`] parse/build paths.
#[derive(Debug)]
pub enum ProfileConfigError {
    /// TOML parsing failed (syntax error, type mismatch, …).
    Toml(toml::de::Error),
    /// `profile_id` field is missing.
    MissingProfileId,
    /// `profile_id` is present but unparseable as a UUID.
    InvalidProfileId(uuid::Error),
    /// TOML serialization failed.
    Serialize(toml::ser::Error),
}

impl core::fmt::Display for ProfileConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProfileConfigError::Toml(e) => write!(f, "daemonseed.toml parse error: {e}"),
            ProfileConfigError::MissingProfileId => write!(
                f,
                "daemonseed.toml missing required `profile_id` field — \
                 recover from .dseed or re-enroll"
            ),
            ProfileConfigError::InvalidProfileId(e) => {
                write!(f, "daemonseed.toml `profile_id` is not a valid UUID: {e}")
            }
            ProfileConfigError::Serialize(e) => write!(f, "daemonseed.toml serialize error: {e}"),
        }
    }
}

impl std::error::Error for ProfileConfigError {}

/// The deserialized `daemonseed.toml` schema.
///
/// Construct via [`ProfileConfig::new_for_first_start`] at enrollment,
/// then persist with [`ProfileConfig::to_toml`]. Load existing profiles
/// with [`ProfileConfig::from_toml`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// UUID v4 drawn at first-start. Immutable for the life of the
    /// profile; rotating it invalidates every derived key (ISC-A-C16).
    pub profile_id: Uuid,

    /// Argon2 work factors. Persisted at first-start, never silently
    /// changed (ISC-A-C17). Re-key flows must run an explicit migration.
    #[serde(default = "ArgonParams::desktop_default")]
    pub argon2: ArgonParams,
}

impl ProfileConfig {
    /// Build a fresh config for first-start (ISC-C29 step 3). Generates a
    /// new UUID v4 from OS CSPRNG (`getrandom` via the `uuid` crate's `v4`
    /// feature — A-C16 forbids any user-derivable input).
    pub fn new_for_first_start(argon2: ArgonParams) -> Self {
        Self {
            profile_id: Uuid::new_v4(),
            argon2,
        }
    }

    /// Parse a `daemonseed.toml` file body. Surfaces ISC-C36's "missing /
    /// unparseable profile_id refuses to start" requirement as a specific
    /// error so the caller can route the user to recovery.
    pub fn from_toml(body: &str) -> Result<Self, ProfileConfigError> {
        // Two-stage parse: parse the raw table first so we can distinguish
        // "field missing" from "field present but invalid" with our own
        // error variants. serde's default behaviour would collapse both
        // into a generic Toml error.
        let raw: toml::Value = toml::from_str(body).map_err(ProfileConfigError::Toml)?;
        let table = raw
            .as_table()
            .ok_or(ProfileConfigError::MissingProfileId)?;

        let profile_id_raw = table
            .get("profile_id")
            .ok_or(ProfileConfigError::MissingProfileId)?;
        let profile_id_str = profile_id_raw.as_str().ok_or_else(|| {
            ProfileConfigError::InvalidProfileId(uuid::Uuid::from_slice(&[]).unwrap_err())
        })?;
        let profile_id =
            Uuid::parse_str(profile_id_str).map_err(ProfileConfigError::InvalidProfileId)?;

        // For the rest (argon2 + future fields) lean on serde so adding a
        // field doesn't require touching this function.
        let mut config: ProfileConfig = toml::from_str(body).map_err(ProfileConfigError::Toml)?;
        config.profile_id = profile_id;
        Ok(config)
    }

    /// Serialize to the canonical `daemonseed.toml` representation.
    pub fn to_toml(&self) -> Result<String, ProfileConfigError> {
        toml::to_string_pretty(self).map_err(ProfileConfigError::Serialize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_start_generates_random_uuid() {
        let a = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
        let b = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
        assert_ne!(a.profile_id, b.profile_id);
        // Version 4 = random UUID per RFC 4122.
        assert_eq!(a.profile_id.get_version_num(), 4);
    }

    #[test]
    fn round_trip_toml() {
        let original = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
        let s = original.to_toml().unwrap();
        let parsed = ProfileConfig::from_toml(&s).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn from_toml_uses_default_argon2_when_omitted() {
        let body = r#"profile_id = "123e4567-e89b-12d3-a456-426614174000""#;
        let c = ProfileConfig::from_toml(body).unwrap();
        assert_eq!(c.argon2, ArgonParams::desktop_default());
    }

    #[test]
    fn from_toml_preserves_non_default_argon2() {
        let body = r#"
            profile_id = "123e4567-e89b-12d3-a456-426614174000"
            [argon2]
            memory_kib = 65536
            iterations = 4
            parallelism = 2
        "#;
        let c = ProfileConfig::from_toml(body).unwrap();
        assert_eq!(c.argon2.memory_kib, 65536);
        assert_eq!(c.argon2.iterations, 4);
        assert_eq!(c.argon2.parallelism, 2);
    }

    #[test]
    fn from_toml_rejects_missing_profile_id() {
        let body = r#"
            [argon2]
            memory_kib = 19456
            iterations = 2
            parallelism = 1
        "#;
        match ProfileConfig::from_toml(body) {
            Err(ProfileConfigError::MissingProfileId) => {}
            other => panic!("expected MissingProfileId, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_rejects_invalid_profile_id() {
        let body = r#"profile_id = "not-a-uuid""#;
        match ProfileConfig::from_toml(body) {
            Err(ProfileConfigError::InvalidProfileId(_)) => {}
            other => panic!("expected InvalidProfileId, got {other:?}"),
        }
    }

    #[test]
    fn desktop_default_matches_owasp_2024() {
        let p = ArgonParams::desktop_default();
        // OWASP 2024 desktop: 19 MiB, t=2, p=1.
        assert_eq!(p.memory_kib, 19 * 1024);
        assert_eq!(p.iterations, 2);
        assert_eq!(p.parallelism, 1);
    }
}
