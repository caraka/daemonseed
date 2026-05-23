//! HKDF info-string constants — the load-bearing registry.
//!
//! Every HKDF context used by daemonseed lives here as a `pub const &str`
//! (or as a function emitting a deterministic string from runtime
//! parameters). The byte content of these strings is part of the protocol
//! contract: changing any of them silently breaks identity continuity and
//! cross-version interop. Wire-visible regression tests (M4a / D5 §5)
//! byte-compare these constants against the published spec.
//!
//! Naming convention: `daemonseed/<area>/<subject>[/<discriminator>]`.
//! Every string is `daemonseed/`-prefixed for global namespace isolation
//! (so a daemonseed-derived key cannot collide with the same passphrase
//! used by some other application's HKDF).

// ── Identity (ISC-C1) ──────────────────────────────────────────────────────

/// HKDF salt for the BIP-39 → identity root derivation. Pins the daemonseed
/// usage of the BIP-39 seed apart from any other consumer of the same
/// mnemonic ecosystem (wallets, recovery tools, etc.).
pub const IDENTITY_ROOT_SALT: &[u8] = b"daemonseed/v1/identity-root";

/// Info-string prefix for the **primary** identity (ISC-C1, ISC-C13).
/// Per-domain suffix (`/sign`, `/kem-d`, `/kem-z`) appended at use-site
/// via [`primary`]; do not concatenate this manually.
const PRIMARY_PREFIX: &str = "daemonseed/identity/primary";

/// Info-string prefix template for the **per-device** identity (ISC-C1,
/// ISC-C13). The `<uuid>` placeholder is replaced by a stable
/// device-uuid generated at first enrollment.
const DEVICE_PREFIX_TEMPLATE: &str = "daemonseed/identity/device-{uuid}";

/// Domain separator for the ML-DSA-87 signing keypair seed.
pub const DOMAIN_SIGN: &str = "sign";

/// Domain separator for the ML-KEM-1024 `d` seed (per FIPS 203 keygen).
pub const DOMAIN_KEM_D: &str = "kem-d";

/// Domain separator for the ML-KEM-1024 `z` seed (per FIPS 203 keygen).
pub const DOMAIN_KEM_Z: &str = "kem-z";

/// Build the full HKDF info string for the primary identity's given domain.
/// `domain` is one of `DOMAIN_SIGN`, `DOMAIN_KEM_D`, `DOMAIN_KEM_Z`.
pub fn primary(domain: &str) -> String {
    format!("{PRIMARY_PREFIX}/{domain}")
}

/// Build the full HKDF info string for a per-device identity's given
/// domain. `uuid` must be the device's stable UUID, formatted as a 36-char
/// hyphenated string.
pub fn device(uuid: &str, domain: &str) -> String {
    let prefix = DEVICE_PREFIX_TEMPLATE.replace("{uuid}", uuid);
    format!("{prefix}/{domain}")
}

// ── At-rest blob + recovery (ISC-C3, ISC-C30) ──────────────────────────────

/// HKDF info-string template for the at-rest seeds blob key (ISC-C3).
/// `<profile-id>` is substituted by [`at_rest`] at use-site.
const AT_REST_TEMPLATE: &str = "daemonseed/at-rest/{profile_id}";

/// HKDF info-string template for the encrypted recovery file (`.dseed`)
/// key (ISC-C30 / ISC-C32). Distinct from at-rest so the same passphrase
/// produces independent keys for the two artifacts.
const RECOVERY_FILE_TEMPLATE: &str = "daemonseed/recovery-file/{profile_id}";

/// Build the at-rest-blob HKDF info string for a profile.
pub fn at_rest(profile_id: &str) -> String {
    AT_REST_TEMPLATE.replace("{profile_id}", profile_id)
}

/// Build the recovery-file HKDF info string for a profile.
pub fn recovery_file(profile_id: &str) -> String {
    RECOVERY_FILE_TEMPLATE.replace("{profile_id}", profile_id)
}

// ── Profile-scoped auxiliary keys (ISC-A-C6, ISC-C28) ─────────────────────

/// HKDF info-string template for the share-index key (ISC-A-C6).
const SHARE_INDEX_TEMPLATE: &str = "daemonseed/share-index/{profile_id}";

/// HKDF info-string template for the trust-events audit-log key (ISC-C28).
const TRUST_EVENTS_TEMPLATE: &str = "daemonseed/trust-events/{profile_id}";

/// Build the share-index HKDF info string for a profile.
pub fn share_index(profile_id: &str) -> String {
    SHARE_INDEX_TEMPLATE.replace("{profile_id}", profile_id)
}

/// Build the trust-events HKDF info string for a profile.
pub fn trust_events(profile_id: &str) -> String {
    TRUST_EVENTS_TEMPLATE.replace("{profile_id}", profile_id)
}

// ── Identity-proof channel binding (ISC-S19) ──────────────────────────────

/// HKDF info string for the identity-proof envelope channel-binding
/// (ISC-S19). Combined with the negotiated APP_HELLO version (per
/// ISC-A-S14) at use-site in M4b; this constant alone is the static half.
pub const IDENTITY_PROOF_V1: &str = "daemonseed/identity-proof/v1";

#[cfg(test)]
mod tests {
    use super::*;

    /// **Spec contract** — these byte sequences are protocol-visible and
    /// MUST NOT drift without a coordinated MINOR-version bump on ISC-S14.
    /// If a value changes, an existing daemonseed install loses every
    /// derived key. Edit only after reading ISC-C1 / ISC-C3 / ISC-C30 / etc.
    /// and updating the corresponding spec entry.
    ///
    /// Wire-visible regression test (M4a, D5 §5) will reference these same
    /// expected literals.
    #[test]
    fn identity_info_strings_are_pinned() {
        assert_eq!(primary(DOMAIN_SIGN), "daemonseed/identity/primary/sign");
        assert_eq!(primary(DOMAIN_KEM_D), "daemonseed/identity/primary/kem-d");
        assert_eq!(primary(DOMAIN_KEM_Z), "daemonseed/identity/primary/kem-z");
        assert_eq!(
            device("123e4567-e89b-12d3-a456-426614174000", DOMAIN_SIGN),
            "daemonseed/identity/device-123e4567-e89b-12d3-a456-426614174000/sign"
        );
    }

    #[test]
    fn at_rest_info_strings_are_pinned() {
        assert_eq!(
            at_rest("123e4567-e89b-12d3-a456-426614174000"),
            "daemonseed/at-rest/123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(
            recovery_file("123e4567-e89b-12d3-a456-426614174000"),
            "daemonseed/recovery-file/123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn auxiliary_info_strings_are_pinned() {
        assert_eq!(share_index("uuid"), "daemonseed/share-index/uuid");
        assert_eq!(trust_events("uuid"), "daemonseed/trust-events/uuid");
    }

    #[test]
    fn salt_and_identity_proof_constants() {
        assert_eq!(IDENTITY_ROOT_SALT, b"daemonseed/v1/identity-root");
        assert_eq!(IDENTITY_PROOF_V1, "daemonseed/identity-proof/v1");
    }
}
