//! Release-signing trust anchor (ISC-S18 / ISC-A-C11 / ISC-A-C19).
//!
//! The anchor is the binary-bound declaration of "these are the release-signing
//! public keys, and this many of them must sign". `bundled()` reads a
//! compile-time `include_str!`'d TOML at `release_anchor.toml`, so the value
//! travels with the release-signed binary — operators (or tampering attackers)
//! cannot alter the default at runtime (A-C19). This mirrors
//! [`crate::bootstrap::anchor`], which the bootstrap anchor's docs already name
//! as the analogue.
//!
//! **Pre-public phase.** No real release key exists yet — the bundled key array
//! is empty, exactly as the bootstrap anchor ships an empty `canonical` at M2.
//! The shape ships **1-of-1** (`threshold = 1`); a future signing-key ceremony
//! (deferred M10-infra) lands the real key by adding its hex public key to the
//! TOML and shipping a signed release, and ratchets toward N-of-M by adding
//! keys and raising `threshold`. Keeping the array+threshold shape now means
//! the ratchet is additive, never a refactor.

use serde::{Deserialize, Serialize};

use oxicrypt_ml_dsa as ml_dsa;

const RELEASE_ANCHOR_TOML_SRC: &str = include_str!("release_anchor.toml");

/// A single release-signing key in the trust anchor — an ML-DSA-87 public key.
/// Heap-boxed because the key is 2592 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ReleaseKey {
    public_key: Box<[u8; ml_dsa::PK_LEN]>,
}

impl ReleaseKey {
    /// Wrap a raw ML-DSA-87 public key.
    pub fn new(public_key: [u8; ml_dsa::PK_LEN]) -> Self {
        Self {
            public_key: Box::new(public_key),
        }
    }

    /// The raw ML-DSA-87 public key bytes.
    pub fn public_key(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.public_key
    }
}

impl core::fmt::Debug for ReleaseKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never dump 2592 bytes; a short prefix is enough to tell keys apart.
        f.debug_struct("ReleaseKey")
            .field(
                "pubkey_prefix",
                &format_args!("{:02x?}", &self.public_key[..4]),
            )
            .finish()
    }
}

/// A validated release-signing trust anchor: an ordered set of release-signing
/// keys plus the N-of-M threshold of distinct keys that must produce a valid
/// signature for an artifact to be accepted (ISC-S18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAnchor {
    keys: Vec<ReleaseKey>,
    threshold: u32,
}

/// Why a [`ReleaseAnchor`] could not be constructed — a degenerate anchor that
/// could never accept (or could trivially accept) an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// The key set is empty — nothing could ever sign.
    NoKeys,
    /// The threshold is zero (would accept an unsigned artifact) or exceeds the
    /// number of keys (could never be met).
    ThresholdOutOfRange,
}

impl ReleaseAnchor {
    /// Build an anchor from `keys` requiring `threshold` distinct valid
    /// signatures. Rejects a degenerate anchor: an empty key set, a zero
    /// threshold (which would accept an unsigned artifact), or a threshold
    /// larger than the key count (which could never be met).
    pub fn new(keys: Vec<ReleaseKey>, threshold: u32) -> Result<Self, AnchorError> {
        if keys.is_empty() {
            return Err(AnchorError::NoKeys);
        }
        if threshold == 0 || threshold as usize > keys.len() {
            return Err(AnchorError::ThresholdOutOfRange);
        }
        Ok(Self { keys, threshold })
    }

    /// The N-of-M threshold: distinct keys that must sign validly.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The release-signing keys (the M of N-of-M).
    pub fn keys(&self) -> &[ReleaseKey] {
        &self.keys
    }
}

/// Schema for the bundled `release_anchor.toml`. The key array is hex-encoded
/// ML-DSA-87 public keys; it is empty during the pre-public phase (no real
/// release key yet), and `threshold` ships at 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledReleaseAnchor {
    /// Schema version of the bundled file.
    pub version: u32,
    /// N-of-M threshold; the bundled shape ships 1-of-1.
    pub threshold: u32,
    /// Hex-encoded ML-DSA-87 release-signing public keys. Empty until the
    /// signing-key ceremony (M10-infra) publishes the real key.
    #[serde(default)]
    pub keys: Vec<String>,
}

impl BundledReleaseAnchor {
    /// Materialize a usable [`ReleaseAnchor`] from the bundled config, or `None`
    /// when no release key is published yet (pre-public phase) so the boot-gate
    /// and updater stay inert rather than verifying against an empty key set.
    /// Returns `None` on a malformed hex key or a degenerate threshold too —
    /// the bundled file is repo-shipped, so a parse failure is a build error to
    /// be caught by the round-trip test, not a runtime condition to chase.
    pub fn to_anchor(&self) -> Option<ReleaseAnchor> {
        if self.keys.is_empty() {
            return None;
        }
        let mut keys = Vec::with_capacity(self.keys.len());
        for h in &self.keys {
            let bytes = hex_decode(h)?;
            let arr: [u8; ml_dsa::PK_LEN] = bytes.try_into().ok()?;
            keys.push(ReleaseKey::new(arr));
        }
        ReleaseAnchor::new(keys, self.threshold).ok()
    }
}

/// The compile-time embedded bundled release anchor. The TOML body lives
/// alongside this module at `release_anchor.toml` and is read via
/// `include_str!`, so it travels with the release binary's signature.
///
/// A parse failure here is a programmer error — the file ships from this repo —
/// so we panic at first use rather than threading a `Result` through callers.
pub fn bundled() -> &'static BundledReleaseAnchor {
    use std::sync::OnceLock;
    static BUNDLED: OnceLock<BundledReleaseAnchor> = OnceLock::new();
    BUNDLED.get_or_init(|| {
        toml::from_str(RELEASE_ANCHOR_TOML_SRC).expect("bundled release_anchor.toml must parse")
    })
}

/// Decode a lowercase/uppercase hex string into bytes, or `None` if it is not
/// valid hex (odd length or a non-hex digit). Local to the anchor so the
/// bundled-key schema needs no extra dependency.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::SignKeypair;

    /// Lowercase-hex encode (test-only — the real keys are hex-decoded only).
    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn a_keypair(seed_byte: u8) -> SignKeypair {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[seed_byte; 32]).unwrap()
    }

    #[test]
    fn bundled_release_anchor_parses() {
        let a = bundled();
        assert_eq!(a.version, 1);
        assert_eq!(a.threshold, 1, "bundled shape ships 1-of-1");
    }

    #[test]
    fn bundled_has_no_real_key_yet() {
        // Pre-public phase: the signing-key ceremony (M10-infra) has not run, so
        // no real release key is bundled and `to_anchor` is inert. Mirrors the
        // bootstrap anchor's empty `canonical` at M2.
        assert!(bundled().keys.is_empty());
        assert!(bundled().to_anchor().is_none());
    }

    #[test]
    fn bundled_round_trips() {
        let a = bundled();
        let s = toml::to_string(a).unwrap();
        let b: BundledReleaseAnchor = toml::from_str(&s).unwrap();
        assert_eq!(*a, b);
    }

    #[test]
    fn to_anchor_materializes_a_populated_one_of_one() {
        // The ratchet path: a populated bundled file yields a usable anchor.
        let kp = a_keypair(7);
        let bundled = BundledReleaseAnchor {
            version: 1,
            threshold: 1,
            keys: vec![hex_encode(kp.public_key())],
        };
        let anchor = bundled
            .to_anchor()
            .expect("populated bundle yields an anchor");
        assert_eq!(anchor.threshold(), 1);
        assert_eq!(anchor.keys().len(), 1);
        assert_eq!(anchor.keys()[0].public_key(), kp.public_key());
    }

    #[test]
    fn to_anchor_rejects_malformed_hex_key() {
        let bundled = BundledReleaseAnchor {
            version: 1,
            threshold: 1,
            keys: vec!["not-hex".to_string()],
        };
        assert!(bundled.to_anchor().is_none());
    }

    #[test]
    fn anchor_new_rejects_empty_keys() {
        assert_eq!(ReleaseAnchor::new(vec![], 1), Err(AnchorError::NoKeys));
    }

    #[test]
    fn anchor_new_rejects_zero_threshold() {
        let kp = a_keypair(1);
        let key = ReleaseKey::new(*kp.public_key());
        assert_eq!(
            ReleaseAnchor::new(vec![key], 0),
            Err(AnchorError::ThresholdOutOfRange)
        );
    }

    #[test]
    fn anchor_new_rejects_threshold_above_key_count() {
        let kp = a_keypair(2);
        let key = ReleaseKey::new(*kp.public_key());
        assert_eq!(
            ReleaseAnchor::new(vec![key], 2),
            Err(AnchorError::ThresholdOutOfRange)
        );
    }

    #[test]
    fn hex_decode_round_trips_and_rejects_junk() {
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode("abc"), None, "odd length");
        assert_eq!(hex_decode("zz"), None, "non-hex digit");
    }
}
