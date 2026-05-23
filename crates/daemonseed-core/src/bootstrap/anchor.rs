//! Bootstrap-anchor structure (per ISC-C37 / ISC-A-C19).
//!
//! The anchor is the binary-bound declaration of "this is the canonical
//! relay the project recommends". `bundled()` reads a compile-time
//! `include_str!`'d TOML at `daemonseed-core/src/bootstrap/anchor.toml`,
//! so the value is bound to the release-signed binary — operators (or
//! tampering attackers) cannot alter the default at runtime per A-C19.
//!
//! At M2 the bundled anchor is intentionally **empty** — the project's
//! canonical relay does not yet exist; manual-paste is the only working
//! path. A later milestone (M11 or whenever the project relay stands up)
//! lands the real anchor by editing `anchor.toml` and bumping a binary
//! release.

use serde::{Deserialize, Serialize};

const ANCHOR_TOML_SRC: &str = include_str!("anchor.toml");

/// Schema for the bundled `anchor.toml`. `canonical` is optional — when
/// the field is absent the project hasn't yet published a canonical
/// relay and clients must fall back to manual-paste (ISC-A-C19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledAnchor {
    pub version: u32,
    pub canonical: Option<BootstrapAnchor>,
}

/// A single bootstrap-relay entry — server-id + address — independent of
/// how it was sourced (canonical vs manual-paste). Both paths in
/// ISC-C37 yield this same shape so downstream code never branches on
/// "did this come from the bundled anchor or from a paste".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapAnchor {
    /// Wire/storage server-id: `<server-name>#<12hex>` per ISC-S11 (uses
    /// the same handle format as clients, ISC-C4 family).
    pub server_id: String,
    /// Connect target — hostname or IP literal, no port (TLS-1.3 :443
    /// implied at MVP per ISC-S5).
    pub address: String,
}

/// Returns the compile-time embedded bundled anchor. The TOML body lives
/// alongside this module at `anchor.toml` and is read via `include_str!`,
/// so it travels with the release binary's signature.
///
/// Parsing failures here are programmer errors — the bundled file is
/// shipped from this repo, not user-controlled — so we panic at first
/// use rather than threading a Result through every caller.
pub fn bundled() -> &'static BundledAnchor {
    use std::sync::OnceLock;
    static BUNDLED: OnceLock<BundledAnchor> = OnceLock::new();
    BUNDLED.get_or_init(|| toml::from_str(ANCHOR_TOML_SRC).expect("bundled anchor.toml must parse"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_anchor_parses() {
        let a = bundled();
        assert_eq!(a.version, 1);
    }

    #[test]
    fn m2_bundled_canonical_is_empty() {
        // ISC-A-C19: at M2 the project canonical relay does not yet
        // exist. A future milestone fills in this field by editing
        // anchor.toml and shipping a signed release.
        assert!(bundled().canonical.is_none());
    }

    #[test]
    fn bundled_anchor_round_trips() {
        let a = bundled();
        let s = toml::to_string(a).unwrap();
        let b: BundledAnchor = toml::from_str(&s).unwrap();
        assert_eq!(*a, b);
    }
}
