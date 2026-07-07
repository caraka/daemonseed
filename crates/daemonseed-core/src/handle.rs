//! Daemonseed wire/storage handle.
//!
//! Per ISC-C4: every daemon's handle is `<display-name>#<first-12-hex-of-
//! SHA-384(primary-identity-pubkey)>`. The hash prefix is stable for the life
//! of the daemon's primary identity (ISC-C1) and identical across every
//! presentation the daemon makes (handle-only, primary, fully anonymous per
//! ISC-C13). 12 hex chars = 48 bits, chosen so prefix-grinding attacks are
//! economically unattractive at federation scale.
//!
//! The hash family is SHA-384, not SHA-256: CNSA 2.0 mandates a hash with
//! ≥192-bit security level (SHA-384 / SHA-512 / SHA3-384 / SHA3-512), and
//! oxicrypt-module's `AlgorithmProfile::Cnsa2` enforces that at the gate.
//! The 12-hex prefix selects 48 bits regardless of the underlying digest
//! length, so handle identification strength is unchanged from the pre-bump
//! shape; the change is about compliance, not strength.
//!
//! Display behavior follows ISC-C4a:
//! - `Default` — `<display-name>` only; hash hidden in normal chat / presence /
//!   listing UIs.
//! - `Verify` — full `<name>#<12hex>` for hover / long-press / explicit
//!   verification actions.
//! - `Collision` — full `<name>#<12hex>` when the current view contains a
//!   display-name collision (autocomplete + list disambiguation).
//! - `Anonymous` — floor `#<12hex>` even when display_name is set; signals
//!   "presenting anonymously" per ISC-C13.
//!
//! The hash prefix length is hardcoded at 12 hex chars (6 bytes) for the M1
//! foundation. Per ISC-C4, this is "tunable per-server via operator config";
//! the runtime-tunable path lands in M4a alongside server-config plumbing.

pub mod display_name;

use core::fmt;
use core::str::FromStr;

use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;

/// Hash-prefix length in bytes (6 bytes = 12 hex chars = 48 bits).
///
/// Fixed at this default per ISC-C4. Operator-config override is reserved
/// for M4a when the server-config substrate lands; lowering it increases
/// prefix-grinding risk and is discouraged.
pub const HASH_PREFIX_BYTES: usize = 6;

/// Hash-prefix length in hex characters (always `HASH_PREFIX_BYTES * 2`).
pub const HASH_PREFIX_HEX_CHARS: usize = HASH_PREFIX_BYTES * 2;

/// A daemonseed handle.
///
/// Constructed from a pubkey via [`Handle::from_pubkey`] (steady state) or
/// parsed from a string via [`FromStr`] (wire / storage / user-typed). The
/// hash prefix is derived deterministically from the pubkey and is not
/// independently settable — that invariant is the load-bearing piece of
/// ISC-C4's identity binding.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Handle {
    display_name: Option<String>,
    hash_prefix: [u8; HASH_PREFIX_BYTES],
}

/// Display behavior selector — see module docs for the ISC-C4a / C13 rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayMode {
    Default,
    Verify,
    Collision,
    Anonymous,
}

/// Errors returned by [`Handle::from_str`] when input doesn't match the
/// `<name>#<12hex>` (or floor `#<12hex>`) format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleParseError {
    /// No `#` found in the input string.
    MissingHashSeparator,
    /// The hex segment is not exactly `HASH_PREFIX_HEX_CHARS` characters.
    InvalidHashLength { found: usize, expected: usize },
    /// The hex segment contains non-hex characters.
    InvalidHashHex,
    /// The display-name portion contains a `#` — would alias with the
    /// hash-separator and break round-trip.
    DisplayNameHasHash,
}

impl fmt::Display for HandleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandleParseError::MissingHashSeparator => {
                write!(f, "missing '#' separator in handle")
            }
            HandleParseError::InvalidHashLength { found, expected } => {
                write!(f, "hash prefix must be {expected} hex chars, got {found}")
            }
            HandleParseError::InvalidHashHex => {
                write!(f, "hash prefix contains non-hex characters")
            }
            HandleParseError::DisplayNameHasHash => {
                write!(
                    f,
                    "display name contains '#', which would alias the hash separator"
                )
            }
        }
    }
}

impl std::error::Error for HandleParseError {}

impl Handle {
    /// Construct a handle by computing `SHA-384(pubkey)[:12]` and pairing it
    /// with the supplied display name.
    ///
    /// Returns the underlying oxicrypt error if SHA-384's power-up self-test
    /// has not yet passed; in normal operation this surfaces only on the
    /// first call in a fresh process.
    pub fn from_pubkey(display_name: Option<String>, pubkey: &[u8]) -> Result<Self, OxicryptError> {
        let digest = sha384(pubkey)?;
        let mut hash_prefix = [0u8; HASH_PREFIX_BYTES];
        hash_prefix.copy_from_slice(&digest[..HASH_PREFIX_BYTES]);
        Ok(Self {
            display_name,
            hash_prefix,
        })
    }

    /// Returns the raw 6-byte hash prefix.
    pub fn hash_prefix(&self) -> &[u8; HASH_PREFIX_BYTES] {
        &self.hash_prefix
    }

    /// Return a copy of this handle with its display name replaced, keeping the
    /// same hash prefix.
    ///
    /// This does NOT violate the ISC-C4 identity binding: the hash prefix is
    /// preserved exactly as derived from the pubkey (it is never set
    /// independently). The use case is first-start, where the handle is derived
    /// from the identity key *before* the user has chosen a display name, then
    /// the chosen name is attached once finalize validates it (ISC-C4b).
    pub fn with_display_name(&self, display_name: Option<String>) -> Handle {
        Handle {
            display_name,
            hash_prefix: self.hash_prefix,
        }
    }

    /// Bind a *transmitted* (self-asserted) handle string to the authoritative
    /// identity proven by `pubkey`, returning the handle that is safe to
    /// **display** (ISC-C57 / ISC-C4).
    ///
    /// A wire message carries a `sender_handle` the sender chose for itself and a
    /// `sender_pubkey` its provenance signature was verified under (ISC-S24 —
    /// checked by the opener before this is reached). The authoritative hash
    /// prefix is always `SHA-384(pubkey)[:12]`; the self-asserted display name is
    /// honored ONLY when the transmitted handle's hash component matches that
    /// prefix. A transmitted handle that is unparseable, or whose hash disagrees
    /// with the pubkey, drops to the verified floor (`#<authoritative-12hex>`) —
    /// so a spoofed `sender_handle` can never be rendered under another daemon's
    /// name. The returned handle's hash prefix is *always* the pubkey-derived
    /// truth, never the transmitted claim.
    ///
    /// Returns the underlying oxicrypt error only if SHA-384's power-up self-test
    /// has not passed — effectively unreachable on this path, since opening the
    /// message already exercised the same key material.
    pub fn display_bound(transmitted: &str, pubkey: &[u8]) -> Result<Handle, OxicryptError> {
        let authoritative = Handle::from_pubkey(None, pubkey)?;
        match transmitted.parse::<Handle>() {
            // Hash component matches the key → the self-asserted name is bound to
            // this identity; honor it (keeping the authoritative prefix).
            Ok(claimed) if claimed.hash_prefix == authoritative.hash_prefix => {
                Ok(authoritative.with_display_name(claimed.display_name))
            }
            // Unparseable, or hash disagrees with the pubkey → never show the
            // spoofable name; present the verified floor.
            _ => Ok(authoritative),
        }
    }

    /// Returns the display name, if set. `None` indicates floor presentation
    /// (`#<12hex>`).
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Returns `true` when the handle has no display name. The floor form is
    /// what every daemon falls back to when `display_name` is empty
    /// (ISC-C4b) or when presenting anonymously (ISC-C13).
    pub fn is_floor(&self) -> bool {
        self.display_name.is_none()
    }

    /// Render the handle per the requested display mode (ISC-C4a / C13).
    pub fn format(&self, mode: DisplayMode) -> String {
        let hex = hex::encode(self.hash_prefix);
        match (mode, self.display_name.as_deref()) {
            (DisplayMode::Default, Some(name)) => name.to_string(),
            (DisplayMode::Default, None) => format!("#{hex}"),
            (DisplayMode::Verify | DisplayMode::Collision, Some(name)) => {
                format!("{name}#{hex}")
            }
            (DisplayMode::Verify | DisplayMode::Collision, None) => format!("#{hex}"),
            (DisplayMode::Anonymous, _) => format!("#{hex}"),
        }
    }
}

/// The `#<12hex>` fingerprint of an identity public key — `SHA-384(pubkey)[:12]`,
/// the same value a handle presents at its verified floor (ISC-C4 / ISC-C57). #114:
/// lets a caller (e.g. the share browser) show the VERIFIED announcer fingerprint
/// without re-implementing the hashing. Returns an empty string only if SHA-384's
/// power-up self-test has not passed — effectively unreachable on any path that has
/// already opened a provenance-signed message.
pub fn pubkey_fingerprint(pubkey: &[u8]) -> String {
    Handle::from_pubkey(None, pubkey)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

impl fmt::Display for Handle {
    /// Canonical wire/storage form per ISC-C4: `<name>#<12hex>` or floor
    /// `#<12hex>` when no display name is set. Equivalent to
    /// `format(DisplayMode::Verify)`. `to_string()` round-trips through
    /// `FromStr`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = hex::encode(self.hash_prefix);
        match self.display_name.as_deref() {
            Some(name) => write!(f, "{name}#{hex}"),
            None => write!(f, "#{hex}"),
        }
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("display_name", &self.display_name)
            .field("hash_prefix", &hex::encode(self.hash_prefix))
            .finish()
    }
}

impl FromStr for Handle {
    type Err = HandleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `rfind` lets a display-name-with-# parse far enough to surface
        // DisplayNameHasHash; without rfind the parser would split on the
        // first '#' and accept invalid handles.
        let hash_idx = s.rfind('#').ok_or(HandleParseError::MissingHashSeparator)?;
        let name_segment = &s[..hash_idx];
        let hex_segment = &s[hash_idx + 1..];

        if hex_segment.len() != HASH_PREFIX_HEX_CHARS {
            return Err(HandleParseError::InvalidHashLength {
                found: hex_segment.len(),
                expected: HASH_PREFIX_HEX_CHARS,
            });
        }

        let mut hash_prefix = [0u8; HASH_PREFIX_BYTES];
        hex::decode_to_slice(hex_segment, &mut hash_prefix)
            .map_err(|_| HandleParseError::InvalidHashHex)?;

        if name_segment.contains('#') {
            return Err(HandleParseError::DisplayNameHasHash);
        }

        let display_name = if name_segment.is_empty() {
            None
        } else {
            Some(name_segment.to_string())
        };

        Ok(Self {
            display_name,
            hash_prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX_HEX: &str = "aabbccddeeff";
    const PREFIX_BYTES: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    /// Bootstrap oxicrypt's FIPS module for tests that exercise SHA-384.
    /// `initialize` is idempotent — after the first call it returns
    /// `AlreadyInitialized`, which we deliberately ignore.
    fn ensure_oxicrypt_initialized() {
        let _ = oxicrypt_module::initialize();
    }

    fn alice() -> Handle {
        Handle {
            display_name: Some("alice".to_string()),
            hash_prefix: PREFIX_BYTES,
        }
    }

    fn floor() -> Handle {
        Handle {
            display_name: None,
            hash_prefix: PREFIX_BYTES,
        }
    }

    // ── from_pubkey ────────────────────────────────────────────────────────

    #[test]
    fn from_pubkey_uses_sha384_first_12_hex() {
        ensure_oxicrypt_initialized();
        let pubkey = b"deterministic input";
        let h = Handle::from_pubkey(Some("alice".to_string()), pubkey).unwrap();

        // Recompute the expected prefix the same way Handle::from_pubkey does.
        let expected = sha384(pubkey).unwrap();
        assert_eq!(h.hash_prefix(), &expected[..6]);
    }

    #[test]
    fn from_pubkey_is_deterministic() {
        ensure_oxicrypt_initialized();
        let pubkey = b"same input every time";
        let h1 = Handle::from_pubkey(Some("alice".to_string()), pubkey).unwrap();
        let h2 = Handle::from_pubkey(Some("bob".to_string()), pubkey).unwrap();
        // Different display names; same pubkey → same hash prefix.
        assert_eq!(h1.hash_prefix(), h2.hash_prefix());
    }

    // ── parse — happy path ─────────────────────────────────────────────────

    #[test]
    fn parse_named_handle() {
        let h: Handle = "alice#aabbccddeeff".parse().unwrap();
        assert_eq!(h.display_name(), Some("alice"));
        assert_eq!(h.hash_prefix(), &PREFIX_BYTES);
    }

    #[test]
    fn parse_floor_handle() {
        let h: Handle = "#aabbccddeeff".parse().unwrap();
        assert!(h.is_floor());
        assert_eq!(h.display_name(), None);
        assert_eq!(h.hash_prefix(), &PREFIX_BYTES);
    }

    // ── parse — error cases ────────────────────────────────────────────────

    #[test]
    fn parse_missing_hash_separator() {
        assert_eq!(
            "alice".parse::<Handle>().unwrap_err(),
            HandleParseError::MissingHashSeparator
        );
    }

    #[test]
    fn parse_invalid_hash_length() {
        match "alice#abc".parse::<Handle>() {
            Err(HandleParseError::InvalidHashLength {
                found: 3,
                expected: 12,
            }) => {}
            other => {
                panic!("expected InvalidHashLength {{ found: 3, expected: 12 }}, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_invalid_hash_hex() {
        assert_eq!(
            "alice#zzzzzzzzzzzz".parse::<Handle>().unwrap_err(),
            HandleParseError::InvalidHashHex
        );
    }

    #[test]
    fn parse_rejects_display_name_with_hash() {
        // rfind('#') splits at the LAST '#', leaving "a#b" as the display name,
        // which the DisplayNameHasHash check then rejects.
        assert_eq!(
            "a#b#aabbccddeeff".parse::<Handle>().unwrap_err(),
            HandleParseError::DisplayNameHasHash
        );
    }

    // ── round-trip ─────────────────────────────────────────────────────────

    #[test]
    fn round_trip_named() {
        let h = alice();
        let s = h.to_string();
        let parsed: Handle = s.parse().unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn round_trip_floor() {
        let h = floor();
        let s = h.to_string();
        let parsed: Handle = s.parse().unwrap();
        assert_eq!(h, parsed);
    }

    // ── display modes ─────────────────────────────────────────────────────

    #[test]
    fn default_mode_hides_hash_when_named() {
        assert_eq!(alice().format(DisplayMode::Default), "alice");
    }

    #[test]
    fn default_mode_shows_floor_when_anonymous() {
        assert_eq!(
            floor().format(DisplayMode::Default),
            format!("#{PREFIX_HEX}")
        );
    }

    #[test]
    fn verify_mode_shows_full_handle() {
        assert_eq!(
            alice().format(DisplayMode::Verify),
            format!("alice#{PREFIX_HEX}")
        );
    }

    #[test]
    fn collision_mode_shows_full_handle() {
        assert_eq!(
            alice().format(DisplayMode::Collision),
            format!("alice#{PREFIX_HEX}")
        );
    }

    #[test]
    fn anonymous_mode_shows_floor_regardless_of_display_name() {
        // ISC-C13: anonymous presentation suppresses the display name even
        // when one is set.
        assert_eq!(
            alice().format(DisplayMode::Anonymous),
            format!("#{PREFIX_HEX}")
        );
    }

    #[test]
    fn display_trait_matches_verify_mode() {
        let h = alice();
        assert_eq!(h.to_string(), h.format(DisplayMode::Verify));
    }

    // ── prefix length invariants ───────────────────────────────────────────

    #[test]
    fn hash_prefix_length_is_six_bytes() {
        assert_eq!(HASH_PREFIX_BYTES, 6);
        assert_eq!(HASH_PREFIX_HEX_CHARS, 12);
    }

    // ── display_bound (ISC-C57 receive-side handle binding) ─────────────────

    #[test]
    fn display_bound_honors_name_when_hash_matches_pubkey() {
        ensure_oxicrypt_initialized();
        let pubkey = b"sender identity key";
        let truth = Handle::from_pubkey(None, pubkey).unwrap();
        let transmitted = format!("alice#{}", hex::encode(truth.hash_prefix()));

        let bound = Handle::display_bound(&transmitted, pubkey).unwrap();

        assert_eq!(bound.display_name(), Some("alice"));
        assert_eq!(bound.hash_prefix(), truth.hash_prefix());
        assert_eq!(bound.format(DisplayMode::Default), "alice");
    }

    #[test]
    fn display_bound_drops_to_floor_on_hash_mismatch() {
        // The spoof: an attacker signs with its OWN key (so sender_pubkey is
        // theirs) but asserts a sender_handle carrying a DIFFERENT hash prefix
        // to impersonate another daemon. The mismatch must collapse to floor.
        ensure_oxicrypt_initialized();
        let pubkey = b"real sender key";
        let truth = Handle::from_pubkey(None, pubkey).unwrap();
        let wrong_hex = "0123456789ab";
        assert_ne!(wrong_hex, hex::encode(truth.hash_prefix()).as_str());
        let transmitted = format!("bob#{wrong_hex}");

        let bound = Handle::display_bound(&transmitted, pubkey).unwrap();

        assert!(bound.is_floor(), "a spoofed display name must not survive");
        assert_eq!(bound.hash_prefix(), truth.hash_prefix());
        assert_eq!(
            bound.format(DisplayMode::Default),
            format!("#{}", hex::encode(truth.hash_prefix()))
        );
    }

    #[test]
    fn display_bound_drops_to_floor_on_unparseable_handle() {
        ensure_oxicrypt_initialized();
        let pubkey = b"third identity key";
        let bound = Handle::display_bound("no-hash-separator", pubkey).unwrap();
        assert!(bound.is_floor());
    }

    #[test]
    fn display_bound_floor_handle_stays_floor() {
        ensure_oxicrypt_initialized();
        let pubkey = b"fourth identity key";
        let truth = Handle::from_pubkey(None, pubkey).unwrap();
        let transmitted = format!("#{}", hex::encode(truth.hash_prefix()));

        let bound = Handle::display_bound(&transmitted, pubkey).unwrap();

        assert!(bound.is_floor());
        assert_eq!(bound.hash_prefix(), truth.hash_prefix());
    }
}
