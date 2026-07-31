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

/// The longest word in the BIP-39 English list, in bytes.
///
/// The list is a fixed, versioned artifact of BIP-39, so this is a property of
/// the standard rather than of any release — but it is asserted against the
/// actual list in this module's tests rather than trusted, because a wrong value
/// here silently under-reserves [`MAX_PHRASE_LEN`]. Every English word is ASCII,
/// so bytes and characters are the same count.
pub const MAX_WORD_LEN: usize = 8;

/// Upper bound on the byte length of a phrase from [`Mnemonic::to_phrase`] or
/// [`Mnemonic::write_phrase_into`]: 24 words at up to 8 bytes each, plus the 23
/// separating spaces.
///
/// An upper bound, not the exact length — words vary from 3 to 8 bytes, so a real
/// phrase is shorter. It exists so a caller assembling a secret payload can
/// reserve its buffer before the phrase goes into it, without first building the
/// phrase to measure it (#263).
pub const MAX_PHRASE_LEN: usize = WORD_COUNT * (MAX_WORD_LEN + 1) - 1;

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

    /// Append the 24-word phrase to `out`, allocating nothing of its own.
    ///
    /// The same secret as [`Self::to_phrase`], reaching the caller's buffer
    /// without a `String` in between. `bip39`'s `Display` writes each word
    /// straight to the formatter, so the words land in `out` and nowhere else —
    /// whereas `to_phrase` builds an owned `String` that the caller then copies
    /// out of and drops, leaving the phrase in a freed buffer (#263). Callers
    /// assembling a secret payload should prefer this; callers that genuinely
    /// want an owned phrase should hold `to_phrase`'s result in `Zeroizing`.
    ///
    /// This removes one transient. It says nothing about `out` itself: if `out`
    /// reallocates while growing, its own earlier buffers are freed with the
    /// phrase in them. Reserving [`MAX_PHRASE_LEN`] before the first call is what
    /// closes that half.
    pub fn write_phrase_into(&self, out: &mut String) {
        use core::fmt::Write as _;
        // `String`'s `fmt::Write` is infallible — it returns `Err` only if the
        // underlying writer can fail, and this one cannot.
        let _ = write!(out, "{}", self.0);
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

    // ── phrase-length bounds ─────────────────────────────────────────────

    /// `MAX_WORD_LEN` is checked against the wordlist, not trusted.
    ///
    /// It is the load-bearing term in `MAX_PHRASE_LEN`, which `Seeds` reserves
    /// against before writing the phrase into its payload buffer (#263). Too small
    /// and that reservation is short, the buffer reallocates, and the residue the
    /// reservation exists to prevent comes back — quietly, because the payload
    /// would still be correct. The positive half of the assertion (some word is
    /// exactly this long) is what stops a generously-rounded-up value from passing.
    #[test]
    fn max_word_len_matches_the_english_wordlist() {
        let longest = bip39::Language::English
            .word_list()
            .iter()
            .map(|w| w.len())
            .max()
            .expect("the BIP-39 English wordlist is not empty");
        assert_eq!(
            longest, MAX_WORD_LEN,
            "MAX_WORD_LEN does not match the wordlist, so MAX_PHRASE_LEN is wrong"
        );
    }

    /// `MAX_PHRASE_LEN` bounds a real phrase, and is reached by writing rather
    /// than assumed.
    #[test]
    fn max_phrase_len_bounds_a_generated_phrase() {
        let m = Mnemonic::generate().unwrap();

        let mut written = String::new();
        m.write_phrase_into(&mut written);

        // The two phrase paths must agree, or reserving for one and writing the
        // other proves nothing.
        assert_eq!(written, m.to_phrase());
        assert!(
            written.len() <= MAX_PHRASE_LEN,
            "phrase of {} bytes exceeds MAX_PHRASE_LEN of {MAX_PHRASE_LEN}",
            written.len()
        );
        // Control: a bound far above any real phrase would pass the line above
        // while making every reservation wasteful. 24 three-letter words plus 23
        // spaces is the shortest phrase BIP-39 can produce.
        assert!(written.len() >= WORD_COUNT * 4 - 1);
    }

    /// `write_phrase_into` appends rather than replacing — the payload builder in
    /// `Seeds::to_plaintext` relies on it writing into a buffer it does not own.
    #[test]
    fn write_phrase_into_appends_to_existing_content() {
        let m = Mnemonic::generate().unwrap();
        let mut out = String::from("prefix\n");
        m.write_phrase_into(&mut out);
        assert_eq!(out, format!("prefix\n{}", m.to_phrase()));
    }

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
