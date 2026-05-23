//! BIP-39 24-word mnemonic — the daemon's identity seed (ISC-C2 / ISC-C1).
//!
//! Generated from 256-bit OS-CSPRNG entropy at first-start. Never persisted
//! to disk except inside the at-rest blob (ISC-C3) under the user's session
//! passphrase. The `Mnemonic` wrapper enforces three load-bearing invariants
//! that the raw `bip39::Mnemonic` does not guarantee on its own:
//!
//! 1. **24 words / 256-bit entropy.** ISC-C2 commits to the strongest BIP-39
//!    parameter set; `Mnemonic::from_phrase` refuses any other word count.
//! 2. **English wordlist.** ISC-C2 names the English wordlist as the
//!    default; later languages are post-MVP. The wrapper doesn't expose
//!    the language selector.
//! 3. **Zeroize on drop.** bip39's `ZeroizeOnDrop` derive (enabled via the
//!    `zeroize` feature) scrubs the wrapped value automatically. The
//!    `generate` constructor additionally zeroes the local entropy buffer
//!    before returning.
//!
//! The wrapper is *not* a security boundary against an attacker with the
//! address space — it is a discipline boundary that makes "the mnemonic
//! reached disk / log / Debug output" a refactor-time concern, not a
//! review-time one.

use core::fmt;

use bip39::Mnemonic as Bip39Mnemonic;
use zeroize::Zeroize;

/// ISC-C2: 256-bit entropy = 32 bytes = 24 BIP-39 words.
const ENTROPY_BYTES: usize = 32;

/// ISC-C2: word count is fixed at 24.
pub const WORD_COUNT: usize = 24;

/// A 24-word BIP-39 English mnemonic.
///
/// Construct via [`Mnemonic::generate`] (first-start) or
/// [`Mnemonic::from_phrase`] (recovery / import). Use [`Mnemonic::to_seed`]
/// to derive the 64-byte BIP-39 seed that feeds HKDF.
#[derive(Clone)]
pub struct Mnemonic(Bip39Mnemonic);

/// Errors surfaced by [`Mnemonic`] constructors.
#[derive(Debug)]
pub enum MnemonicError {
    /// The OS CSPRNG failed to fill the entropy buffer.
    EntropySource(getrandom::Error),
    /// The supplied phrase failed BIP-39 parsing (bad word, bad checksum,
    /// unsupported language, …).
    InvalidPhrase(bip39::Error),
    /// The supplied phrase parsed but is not a 24-word mnemonic.
    WrongWordCount { found: usize, expected: usize },
    /// Phrase parses but is not in the English wordlist.
    NotEnglish(bip39::Language),
}

impl fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MnemonicError::EntropySource(e) => write!(f, "OS CSPRNG entropy failed: {e}"),
            MnemonicError::InvalidPhrase(e) => write!(f, "invalid BIP-39 phrase: {e}"),
            MnemonicError::WrongWordCount { found, expected } => {
                write!(f, "expected {expected}-word mnemonic, got {found} words")
            }
            MnemonicError::NotEnglish(lang) => {
                write!(f, "mnemonic must use the English wordlist, got {lang:?}")
            }
        }
    }
}

impl std::error::Error for MnemonicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // getrandom::Error doesn't impl std::error::Error in v0.3, so we
            // surface its message via Display only.
            MnemonicError::EntropySource(_) => None,
            MnemonicError::InvalidPhrase(e) => Some(e),
            _ => None,
        }
    }
}

impl Mnemonic {
    /// Generate a fresh 24-word English mnemonic from 256 bits of OS CSPRNG
    /// entropy. The local entropy buffer is zeroized before this returns,
    /// regardless of outcome.
    pub fn generate() -> Result<Self, MnemonicError> {
        let mut entropy = [0u8; ENTROPY_BYTES];
        let result = getrandom::fill(&mut entropy).map_err(MnemonicError::EntropySource);
        let outcome = result.and_then(|_| {
            Bip39Mnemonic::from_entropy(&entropy)
                .map(Self)
                .map_err(MnemonicError::InvalidPhrase)
        });
        entropy.zeroize();
        outcome
    }

    /// Parse a phrase, verifying the BIP-39 checksum, the word count, and
    /// the English-wordlist invariant.
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let m = Bip39Mnemonic::parse(phrase).map_err(MnemonicError::InvalidPhrase)?;
        if m.word_count() != WORD_COUNT {
            return Err(MnemonicError::WrongWordCount {
                found: m.word_count(),
                expected: WORD_COUNT,
            });
        }
        if m.language() != bip39::Language::English {
            return Err(MnemonicError::NotEnglish(m.language()));
        }
        Ok(Self(m))
    }

    /// The 24-word phrase, space-separated. Useful for display at first-
    /// start (ISC-C31) and recovery flows.
    ///
    /// The returned `String` contains the same secret material as the
    /// mnemonic itself — treat it identically: do not log it, do not
    /// include it in Debug output, drop the binding as soon as it's no
    /// longer needed.
    pub fn to_phrase(&self) -> String {
        self.0.to_string()
    }

    /// BIP-39 PBKDF2-HMAC-SHA512 derivation. Returns the 64-byte seed that
    /// HKDF then expands into ML-DSA-87 + ML-KEM-1024 keypairs (commit 5).
    ///
    /// The `passphrase` argument is the BIP-39 mnemonic passphrase (NOT the
    /// daemonseed session passphrase). daemonseed always invokes this with
    /// an empty string at MVP; user-supplied BIP-39 passphrases are
    /// reserved for future scope where they'd surface in the recovery UX.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.0.to_seed(passphrase)
    }

    /// Number of words in the mnemonic. Always [`WORD_COUNT`] (24) for any
    /// `Mnemonic` constructed through this wrapper.
    pub fn word_count(&self) -> usize {
        self.0.word_count()
    }
}

/// `Debug` redacts the secret content — only the type name appears. This is
/// deliberate: a Debug-prints-everything default would let the mnemonic
/// reach log surfaces by accident.
impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("words", &"<redacted>")
            .field("word_count", &self.word_count())
            .finish()
    }
}

// bip39 v2's `Mnemonic` derives `ZeroizeOnDrop` under the `zeroize` feature
// (enabled in daemonseed's workspace deps), so dropping our wrapper drops
// the inner mnemonic, which zeroes its own entropy.

#[cfg(test)]
mod tests {
    use super::*;

    // Trezor BIP-39 test vector — 24-word "abandon × 23 art" with empty
    // passphrase. Pulled from the canonical test vectors at
    // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    // (the vector for hex-entropy "ffff...ff" maps to a different phrase;
    // we use the all-zero entropy → "abandon ... art" vector).
    const ALL_ZEROS_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const ALL_ZEROS_SEED_HEX: &str = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";

    // ── generate ─────────────────────────────────────────────────────────

    #[test]
    fn generate_produces_24_words() {
        let m = Mnemonic::generate().unwrap();
        assert_eq!(m.word_count(), 24);
        let phrase = m.to_phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn generate_produces_unique_mnemonics() {
        let a = Mnemonic::generate().unwrap();
        let b = Mnemonic::generate().unwrap();
        // 256 bits of entropy → collision probability is negligible.
        assert_ne!(a.to_phrase(), b.to_phrase());
    }

    // ── from_phrase happy path ────────────────────────────────────────────

    #[test]
    fn from_phrase_accepts_canonical_all_zeros_vector() {
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        assert_eq!(m.word_count(), 24);
        assert_eq!(m.to_phrase(), ALL_ZEROS_PHRASE);
    }

    // ── BIP-39 known-answer test ──────────────────────────────────────────

    #[test]
    fn trezor_vector_seed_matches() {
        // The Trezor reference seed for `abandon × 23 art` + empty
        // passphrase. This is the ground truth for our use of bip39's
        // `to_seed`; if this ever drifts, we've broken the BIP-39 contract.
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let seed = m.to_seed("");
        let expected_hex = ALL_ZEROS_SEED_HEX;
        assert_eq!(hex::encode(seed), expected_hex);
    }

    // ── from_phrase error cases ───────────────────────────────────────────

    #[test]
    fn from_phrase_rejects_12_word_mnemonic() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        match Mnemonic::from_phrase(twelve) {
            Err(MnemonicError::WrongWordCount {
                found: 12,
                expected: 24,
            }) => {}
            other => panic!("expected WrongWordCount, got {other:?}"),
        }
    }

    #[test]
    fn from_phrase_rejects_bad_checksum() {
        // Last word changed from "art" (valid checksum) to "abandon"
        // (invalid checksum for an all-zero entropy).
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        match Mnemonic::from_phrase(bad) {
            Err(MnemonicError::InvalidPhrase(_)) => {}
            other => panic!("expected InvalidPhrase (checksum), got {other:?}"),
        }
    }

    #[test]
    fn from_phrase_rejects_nonword() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        match Mnemonic::from_phrase(bad) {
            Err(MnemonicError::InvalidPhrase(_)) => {}
            other => panic!("expected InvalidPhrase (unknown word), got {other:?}"),
        }
    }

    // ── secret-hygiene invariants ─────────────────────────────────────────

    #[test]
    fn debug_redacts_phrase() {
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("<redacted>"), "Debug leaked: {dbg}");
        assert!(
            !dbg.contains("abandon"),
            "Debug leaked phrase content: {dbg}"
        );
        assert!(!dbg.contains("art"), "Debug leaked phrase content: {dbg}");
    }

    #[test]
    fn round_trip_phrase() {
        let original = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let phrase = original.to_phrase();
        let reparsed = Mnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(reparsed.to_phrase(), original.to_phrase());
    }
}
