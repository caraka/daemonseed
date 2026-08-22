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

use crate::bootstrap::BootstrapAnchor;

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

    /// Largest memory cost read from a file: 1 GiB.
    ///
    /// A floor-hardware device (Raspberry Pi 4, 2 GiB) can still allocate this
    /// without the allocator aborting, which is the failure the bound exists to
    /// prevent — a ceiling that cannot be allocated on the smallest supported
    /// device is not a ceiling, it is the same abort at a smaller number.
    pub const MAX_OPENABLE_MEMORY_KIB: u32 = 1024 * 1024;

    /// Largest iteration count read from a file.
    pub const MAX_OPENABLE_ITERATIONS: u32 = 16;

    /// Largest parallelism read from a file.
    pub const MAX_OPENABLE_PARALLELISM: u32 = 16;

    /// Largest `memory_kib × iterations` read from a file.
    ///
    /// **The per-field ceilings do not bound the work; only their product
    /// does.** Argon2's cost is approximately linear in `m·t`, so a file may
    /// sit inside every individual limit and still name a corner far beyond
    /// any of them: 1 GiB at `t = 16` is sixteen times the work of 1 GiB at
    /// `t = 1`. Measured on a 12-core desktop, release build: `m·t ≈ 4.2e6`
    /// takes **20.2 s**, and the honest desktop default (`19456 × 2 = 38912`)
    /// takes **0.19 s** — so cost tracks the product at roughly 4.8 µs per
    /// unit. This ceiling is `2^21`, about **10 s** at that rate on this
    /// machine and correspondingly slower on a floor device, which is a bad
    /// afternoon rather than an unbounded one.
    ///
    /// It admits every configuration a cautious user would plausibly choose —
    /// 1 GiB at `t = 2`, or 256 MiB at `t = 8` — while refusing the corners
    /// that exist only in a forged file. It is 54× the desktop default's
    /// product.
    pub const MAX_OPENABLE_MEMORY_ITERATION_PRODUCT: u64 = 1 << 21;

    /// Whether these parameters are safe to hand to Argon2 when they came from
    /// a file header rather than from this profile's own config.
    ///
    /// **Every sealed-file header states its own KDF cost in the clear, and the
    /// key must be derived before the tag can be checked.** So an opener runs
    /// an attacker-chosen Argon2 *before* it can discover the file is forged:
    /// flipping one bit of `memory_kib` turns a 19 MiB derivation into a 2 TiB
    /// one, and the open never returns to reject anything. Authenticating the
    /// header does not help, because the authentication is downstream of the
    /// work. The only defence is to refuse absurd costs up front, which is what
    /// this is — and it costs an honest file nothing, since an honest file's
    /// parameters are a thousandfold below these ceilings.
    ///
    /// Zero is refused in every field: Argon2 rejects it anyway, and refusing
    /// here keeps the answer to "is this header usable" in one place.
    ///
    /// **The product check is the one that does the work** — see
    /// [`Self::MAX_OPENABLE_MEMORY_ITERATION_PRODUCT`]. The per-field ceilings
    /// bound the allocation; the product bounds the time, and a value can sit
    /// inside all three fields while costing minutes.
    ///
    /// This is applied to four readers, not three: the trust log, the
    /// spent-invite-token set, the `.dseed` recovery file, and
    /// [`ProfileConfig::from_toml`]. The last has no authenticator at all and
    /// is therefore the weakest, which makes it the most important of the four
    /// and the easiest to overlook — its parameters are TOML, not a binary
    /// header, so a search for header parsing does not find it.
    pub const fn is_openable(&self) -> bool {
        self.memory_kib > 0
            && self.iterations > 0
            && self.parallelism > 0
            && self.memory_kib <= Self::MAX_OPENABLE_MEMORY_KIB
            && self.iterations <= Self::MAX_OPENABLE_ITERATIONS
            && self.parallelism <= Self::MAX_OPENABLE_PARALLELISM
            && (self.memory_kib as u64) * (self.iterations as u64)
                <= Self::MAX_OPENABLE_MEMORY_ITERATION_PRODUCT
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
    /// The `argon2` table states a work factor outside
    /// [`ArgonParams::is_openable`].
    ///
    /// `daemonseed.toml` is cleartext with no authenticator of any kind, and
    /// its parameters go straight into key derivation, so it is the *weakest*
    /// of the four readers of these numbers and the one that most needs the
    /// bound. It is also downstream of the other three: a `.dseed` recovery
    /// writes its header's parameters into this file.
    ArgonParamsOutOfRange(ArgonParams),
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
            ProfileConfigError::ArgonParamsOutOfRange(p) => write!(
                f,
                "daemonseed.toml argon2 work factors out of range: \
                 memory_kib={} iterations={} parallelism={}",
                p.memory_kib, p.iterations, p.parallelism
            ),
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

    /// Opt-in biometric / secure-enclave session-passphrase unlock (ISC-C7).
    /// Default off. When enabled, a platform-holding client stores the
    /// session passphrase (never the mnemonic) via [`crate::biometric`];
    /// the user must first acknowledge [`crate::biometric::RECOVERY_RISK_WARNING`].
    #[serde(default)]
    pub biometric_unlock: bool,

    /// Opt-in OS-native autostart (ISC-C20). Default off. When enabled, a
    /// client installs a [`crate::autostart`] unit launching this profile
    /// headless on boot; the user must first acknowledge
    /// [`crate::autostart::PRESENCE_SIDE_CHANNEL_WARNING`].
    #[serde(default)]
    pub autostart: bool,

    /// The bootstrap relay chosen at first-start (ISC-C37). Persisted so the
    /// daily-login Unlock flow (ISC-C3 / Item E) can re-establish the
    /// connection without re-running the enrollment wizard. `None` on legacy
    /// M1–M12 profiles that predate the persisted bootstrap; the Unlock flow
    /// then reaches Main and lets the user pick a server from the Servers pane.
    #[serde(default)]
    pub bootstrap: Option<BootstrapAnchor>,
}

impl ProfileConfig {
    /// Build a fresh config for first-start (ISC-C29 step 3). Generates a
    /// new UUID v4 from OS CSPRNG (`getrandom` via the `uuid` crate's `v4`
    /// feature — A-C16 forbids any user-derivable input).
    pub fn new_for_first_start(argon2: ArgonParams) -> Self {
        Self {
            profile_id: Uuid::new_v4(),
            argon2,
            biometric_unlock: false,
            autostart: false,
            bootstrap: None,
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
        let table = raw.as_table().ok_or(ProfileConfigError::MissingProfileId)?;

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
        // The work factors are read here and handed to Argon2 by every caller
        // that unlocks a profile. Nothing authenticates this file, so bounding
        // them at the parse is the only place it can be done once. See
        // `ArgonParams::is_openable`.
        if !config.argon2.is_openable() {
            return Err(ProfileConfigError::ArgonParamsOutOfRange(config.argon2));
        }
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

    fn params(memory_kib: u32, iterations: u32, parallelism: u32) -> ArgonParams {
        ArgonParams {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    /// Each ceiling is pinned at its own boundary: the largest accepted value
    /// and the smallest rejected one, per field.
    ///
    /// **Without this, the ceilings are pinned to nothing.** Every call-site
    /// test uses `u32::MAX`, which passes for any ceiling below about four
    /// terabytes — so the numbers could be raised a thousandfold and the whole
    /// suite would stay green. A boundary pair is the only probe that can see
    /// a ceiling move.
    /// The ceilings are pinned to their literal values.
    ///
    /// **The boundary test below cannot do this job**, because it reads the
    /// constants to build its own inputs — so it stays green for any value of
    /// them, and the ceilings could be raised a thousandfold with the whole
    /// suite passing. These numbers were chosen against a measurement (see
    /// `MAX_OPENABLE_MEMORY_ITERATION_PRODUCT`); moving one should be a
    /// deliberate act that edits this test, not a silent one.
    #[test]
    fn the_openable_ceilings_are_the_values_that_were_measured() {
        assert_eq!(ArgonParams::MAX_OPENABLE_MEMORY_KIB, 1024 * 1024, "1 GiB");
        assert_eq!(ArgonParams::MAX_OPENABLE_ITERATIONS, 16);
        assert_eq!(ArgonParams::MAX_OPENABLE_PARALLELISM, 16);
        assert_eq!(
            ArgonParams::MAX_OPENABLE_MEMORY_ITERATION_PRODUCT,
            2 * 1024 * 1024,
            "about ten seconds of Argon2 on a desktop core"
        );
    }

    #[test]
    fn each_openable_ceiling_is_pinned_at_its_boundary() {
        let m = ArgonParams::MAX_OPENABLE_MEMORY_KIB;
        let t = ArgonParams::MAX_OPENABLE_ITERATIONS;
        let p = ArgonParams::MAX_OPENABLE_PARALLELISM;

        // Memory, at t=1 so the product bound is not what answers.
        assert!(
            params(m, 1, 1).is_openable(),
            "the ceiling itself is openable"
        );
        assert!(!params(m + 1, 1, 1).is_openable(), "one KiB past it is not");

        // Iterations, at a memory low enough that the product stays inside.
        assert!(params(1024, t, 1).is_openable());
        assert!(!params(1024, t + 1, 1).is_openable());

        // Parallelism.
        assert!(params(1024, 1, p).is_openable());
        assert!(!params(1024, 1, p + 1).is_openable());
    }

    /// Zero is refused in every field, not just the first one anybody thought
    /// to test.
    #[test]
    fn zero_is_refused_in_every_field() {
        assert!(
            params(1024, 1, 1).is_openable(),
            "control: the same params with no zero are openable"
        );
        assert!(!params(0, 1, 1).is_openable(), "memory_kib");
        assert!(!params(1024, 0, 1).is_openable(), "iterations");
        assert!(!params(1024, 1, 0).is_openable(), "parallelism");
    }

    /// The product ceiling refuses a corner that sits inside every per-field
    /// ceiling.
    ///
    /// This is the case the per-field limits cannot see: Argon2's cost is
    /// about linear in `memory_kib × iterations`, so max memory at max
    /// iterations is sixteen times the work of max memory alone while
    /// violating neither field.
    #[test]
    fn the_product_ceiling_refuses_an_in_range_corner() {
        let m = ArgonParams::MAX_OPENABLE_MEMORY_KIB;
        let t = ArgonParams::MAX_OPENABLE_ITERATIONS;
        let corner = params(m, t, 1);
        assert!(
            corner.memory_kib <= m && corner.iterations <= t,
            "control: inside both fields"
        );
        assert!(
            !corner.is_openable(),
            "max memory at max iterations must be refused by the product bound"
        );

        let product = ArgonParams::MAX_OPENABLE_MEMORY_ITERATION_PRODUCT;
        assert!(
            params((product / 2) as u32, 2, 1).is_openable(),
            "the product ceiling exactly is openable"
        );
        assert!(
            !params((product / 2) as u32 + 1, 2, 1).is_openable(),
            "one unit past the product ceiling is not"
        );
    }

    /// The shipped default must be comfortably inside every bound — a guard
    /// that refuses an honest profile is worse than no guard.
    #[test]
    fn the_desktop_default_is_openable() {
        let d = ArgonParams::desktop_default();
        assert!(d.is_openable());
        let product = (d.memory_kib as u64) * (d.iterations as u64);
        assert!(
            product * 8 <= ArgonParams::MAX_OPENABLE_MEMORY_ITERATION_PRODUCT,
            "the default should sit well inside the product bound, not at its edge"
        );
    }

    /// `from_toml` refuses work factors outside the bound. `daemonseed.toml`
    /// carries no authenticator, so this is the weakest of the four readers.
    #[test]
    fn from_toml_refuses_out_of_range_argon_params() {
        let ok = "profile_id = \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n\
                  [argon2]\nmemory_kib = 19456\niterations = 2\nparallelism = 1\n";
        assert!(
            ProfileConfig::from_toml(ok).is_ok(),
            "control: an honest config parses"
        );

        let absurd = "profile_id = \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n\
                      [argon2]\nmemory_kib = 4294967295\niterations = 2\nparallelism = 1\n";
        match ProfileConfig::from_toml(absurd) {
            Err(ProfileConfigError::ArgonParamsOutOfRange(p)) => {
                assert_eq!(p.memory_kib, u32::MAX);
            }
            other => panic!("expected ArgonParamsOutOfRange, got {other:?}"),
        }
    }

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
    fn optional_features_default_off_at_first_start() {
        // ISC-C7 / ISC-C20: biometric unlock and autostart are opt-in; a
        // freshly enrolled profile has both disabled.
        let c = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
        assert!(!c.biometric_unlock);
        assert!(!c.autostart);
    }

    #[test]
    fn optional_features_default_off_when_absent_from_toml() {
        // Existing M1–M10 profiles have neither field; they must still parse
        // and read as disabled (serde default), not fail.
        let body = r#"profile_id = "123e4567-e89b-12d3-a456-426614174000""#;
        let c = ProfileConfig::from_toml(body).unwrap();
        assert!(!c.biometric_unlock);
        assert!(!c.autostart);
    }

    #[test]
    fn optional_features_round_trip_when_enabled() {
        let mut c = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
        c.biometric_unlock = true;
        c.autostart = true;
        let parsed = ProfileConfig::from_toml(&c.to_toml().unwrap()).unwrap();
        assert!(parsed.biometric_unlock);
        assert!(parsed.autostart);
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
