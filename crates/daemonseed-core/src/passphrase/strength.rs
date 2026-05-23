//! Passphrase strength estimator + diceware generator (ISC-C12, ISC-C9).
//!
//! ISC-C12 (session passphrase): real-time strength meter with a ≥60 bits
//! estimated-entropy floor (the "green" threshold). Commit is blocked
//! while the indicator is below green.
//!
//! ISC-C9 (circle-of-trust entropy): same estimator, higher threshold —
//! ≥128 bits.
//!
//! The estimator wraps `zxcvbn`'s `Entropy::guesses_log10` and converts
//! to bits. Diceware-style passphrase generation samples the BIP-39
//! English wordlist (2048 words = 11 bits/word) so a 6-word passphrase
//! delivers 66 bits — comfortably above the green threshold, regardless
//! of natural-language predictability discounts zxcvbn would otherwise
//! apply to a pattern-bearing input.

use bip39::Language;

use crate::passphrase::circle_canonicalize::canonicalize;

/// Result of estimating a passphrase's strength.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// zxcvbn score in `0..=4`. Anything below 3 is "weak" by zxcvbn's
    /// own labelling; daemonseed prefers the bits-based gate below.
    pub score: u8,
    /// Estimated bits of entropy. `log10(guesses) * log2(10)`. Infinite
    /// for empty input, which we surface as `0.0` for ergonomics.
    pub bits: f64,
}

/// Minimum bits-of-entropy for ISC-C12 (session passphrase).
pub const SESSION_PASSPHRASE_MIN_BITS: f64 = 60.0;

/// Minimum bits-of-entropy for ISC-C9 (circle-of-trust entropy).
pub const CIRCLE_ENTROPY_MIN_BITS: f64 = 128.0;

const BITS_PER_DIGIT: f64 = core::f64::consts::LOG2_10;

impl Strength {
    /// True iff the passphrase meets ISC-C12's ≥60-bit floor.
    pub fn is_session_green(&self) -> bool {
        self.bits >= SESSION_PASSPHRASE_MIN_BITS
    }

    /// True iff the input meets ISC-C9's ≥128-bit circle-of-trust floor.
    pub fn is_circle_green(&self) -> bool {
        self.bits >= CIRCLE_ENTROPY_MIN_BITS
    }
}

/// Estimate a passphrase's strength. Applies the same NFKC + whitespace
/// canonicalization (per ISC-C9) that key derivation will apply, so the
/// meter agrees with the underlying KDF on what "the passphrase is".
pub fn estimate(passphrase: &str) -> Strength {
    let canon = canonicalize(passphrase);
    let entropy = zxcvbn::zxcvbn(&canon, &[]);
    let raw_bits = entropy.guesses_log10() * BITS_PER_DIGIT;
    let bits = if raw_bits.is_finite() { raw_bits } else { 0.0 };
    Strength {
        score: entropy.score() as u8,
        bits,
    }
}

/// Errors from the diceware generator.
#[derive(Debug)]
pub enum DicewareError {
    EntropySource(getrandom::Error),
    /// At least 6 words are required to hit the ISC-C12 floor; fewer would
    /// underflow the deterministic 66-bit guarantee that justifies skipping
    /// the strength estimator on generator output.
    InsufficientWords {
        requested: usize,
        minimum: usize,
    },
}

impl core::fmt::Display for DicewareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DicewareError::EntropySource(e) => write!(f, "OS CSPRNG entropy failed: {e}"),
            DicewareError::InsufficientWords { requested, minimum } => write!(
                f,
                "diceware: {requested} words below the {minimum}-word floor"
            ),
        }
    }
}

impl std::error::Error for DicewareError {}

/// Minimum word count for the generator. 6 × log2(2048) = 66 bits, which
/// clears the ISC-C12 60-bit floor with margin.
pub const MIN_DICEWARE_WORDS: usize = 6;

/// Default word count for the diceware generator. 6 words = ~66 bits.
pub const DEFAULT_DICEWARE_WORDS: usize = 6;

/// Generate a space-separated diceware passphrase from `count` words drawn
/// from the BIP-39 English wordlist (2048 words). Uniformly random; uses
/// rejection sampling against the OS CSPRNG to avoid modulo bias.
pub fn generate_diceware(count: usize) -> Result<String, DicewareError> {
    if count < MIN_DICEWARE_WORDS {
        return Err(DicewareError::InsufficientWords {
            requested: count,
            minimum: MIN_DICEWARE_WORDS,
        });
    }

    let wordlist = Language::English.word_list();
    let len = wordlist.len();
    let bound = (u64::MAX / len as u64).saturating_mul(len as u64);

    let mut words = Vec::with_capacity(count);
    for _ in 0..count {
        let idx = sample_index(bound, len).map_err(DicewareError::EntropySource)?;
        words.push(wordlist[idx]);
    }
    Ok(words.join(" "))
}

/// Generate a default 6-word diceware passphrase.
pub fn generate_default_diceware() -> Result<String, DicewareError> {
    generate_diceware(DEFAULT_DICEWARE_WORDS)
}

fn sample_index(bound: u64, len: usize) -> Result<usize, getrandom::Error> {
    loop {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)?;
        let n = u64::from_le_bytes(buf);
        if n < bound {
            return Ok((n % len as u64) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── estimate ──────────────────────────────────────────────────────────

    #[test]
    fn weak_password_is_below_session_threshold() {
        let s = estimate("password");
        assert!(!s.is_session_green(), "passphrase {s:?} should be red");
    }

    #[test]
    fn long_random_passphrase_clears_session_threshold() {
        // A 6-word diceware-style sample we control — entropy is high
        // enough that zxcvbn rates it well past 60 bits.
        let s = estimate("correct horse battery staple table mountain");
        assert!(s.is_session_green(), "passphrase {s:?} should be green");
    }

    #[test]
    fn nfkc_canonicalization_is_applied_before_estimation() {
        // Compatibility-decomposable digits → ASCII digits. Both should
        // estimate identically after canonicalization.
        let a = estimate("password\u{FF11}\u{FF12}\u{FF13}");
        let b = estimate("password123");
        assert!((a.bits - b.bits).abs() < 1e-9);
    }

    #[test]
    fn empty_passphrase_reports_zero_bits() {
        let s = estimate("");
        assert_eq!(s.bits, 0.0);
        assert!(!s.is_session_green());
    }

    // ── diceware generator ────────────────────────────────────────────────

    #[test]
    fn generate_default_diceware_returns_six_words() {
        let p = generate_default_diceware().unwrap();
        assert_eq!(p.split_whitespace().count(), DEFAULT_DICEWARE_WORDS);
    }

    #[test]
    fn diceware_words_are_from_bip39_english() {
        let p = generate_diceware(6).unwrap();
        let wordlist: std::collections::HashSet<&'static str> =
            Language::English.word_list().iter().copied().collect();
        for word in p.split_whitespace() {
            assert!(
                wordlist.contains(word),
                "diceware word `{word}` not in BIP-39 English"
            );
        }
    }

    #[test]
    fn generate_diceware_always_clears_session_threshold() {
        // Run 32 samples — every one must be green.
        for _ in 0..32 {
            let p = generate_diceware(DEFAULT_DICEWARE_WORDS).unwrap();
            let s = estimate(&p);
            assert!(
                s.is_session_green(),
                "diceware sample `{p}` rated {s:?}, below session threshold"
            );
        }
    }

    #[test]
    fn generate_diceware_rejects_undersized_request() {
        match generate_diceware(MIN_DICEWARE_WORDS - 1) {
            Err(DicewareError::InsufficientWords { requested, minimum }) => {
                assert_eq!(requested, MIN_DICEWARE_WORDS - 1);
                assert_eq!(minimum, MIN_DICEWARE_WORDS);
            }
            other => panic!("expected InsufficientWords, got {other:?}"),
        }
    }

    #[test]
    fn diceware_outputs_are_distinct_across_calls() {
        // 2048^6 namespace makes collisions in 16 trials effectively
        // impossible; a constant generator would fail this.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            assert!(seen.insert(generate_diceware(6).unwrap()));
        }
    }

    // ── circle threshold ──────────────────────────────────────────────────

    #[test]
    fn circle_threshold_is_higher_than_session_threshold() {
        // ISC-C12: ≥60. ISC-C9: ≥128. The circle gate must be strictly
        // higher than the session gate. (Constants-only check is preferred
        // over a runtime assert; `const _` lifts it to compile time.)
        const _: () = assert!(CIRCLE_ENTROPY_MIN_BITS > SESSION_PASSPHRASE_MIN_BITS);
    }
}
