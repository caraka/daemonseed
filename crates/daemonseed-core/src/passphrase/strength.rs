//! Passphrase strength estimator + diceware generator (ISC-C12, ISC-C9).
//!
//! ISC-C12 (session passphrase): real-time strength meter with a ≥60 bits
//! estimated-entropy floor (the "green" threshold). Commit is blocked
//! while the indicator is below green.
//!
//! ISC-C9 (circle-of-trust entropy): a SEPARATE key-space estimator,
//! [`estimate_circle`], that can actually certify ≥128 bits — zxcvbn cannot
//! (it is a crack-difficulty model that saturates `guesses` at 2⁶⁴, so
//! [`Strength::bits`] never exceeds ~64 and a literal ≥128 gate through it would
//! reject every phrase; discovered M14, 2026-06-05). The circle estimator
//! combines two independent honest models so EITHER path reaches green
//! (caraka's M15 decision, 2026-06-05 — "words+charset, keep adding until
//! green, no formatting forced"):
//!   • word model — each DISTINCT BIP-39 word contributes log2(2048)=11 bits
//!     (repeats add 0, so `abandon ×12` cannot cheat the floor);
//!   • charset model — the RESIDUE (characters of non-wordlist tokens) adds
//!     `len × log2(distinct_chars)` bits. A word counted at 11 bits is NOT also
//!     counted character-by-character (no double-count that would green a 6-word
//!     phrase). 12 diceware words = 132 bits, OR a long mixed string ≈ green —
//!     neither format is forced.
//!   • anti-pattern veto — the additive sum over-credits periodic / sequential
//!     structure (`abcabc…` would read ~143 "bits"), so zxcvbn vetoes any phrase
//!     it rates trivially guessable (score < 2). zxcvbn is used here only as a
//!     low-end pattern detector; its 2⁶⁴ ceiling is irrelevant because the
//!     ≥128 magnitude comes from the key-space sum, not from zxcvbn.
//!
//! The estimator wraps `zxcvbn`'s `Entropy::guesses_log10` and converts
//! to bits. Diceware-style passphrase generation samples the BIP-39
//! English wordlist (2048 words = 11 bits/word) so a 6-word passphrase
//! delivers 66 bits — comfortably above the green threshold, regardless
//! of natural-language predictability discounts zxcvbn would otherwise
//! apply to a pattern-bearing input.

use std::collections::HashSet;
use std::sync::OnceLock;

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
}

/// Result of estimating a circle-of-trust phrase's strength (ISC-C9). Unlike
/// [`Strength`] (zxcvbn, session passphrases) this is a key-space estimate that
/// can actually reach the ≥128-bit floor. See the module docs for the model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CircleStrength {
    /// Estimated key-space bits: `distinct_wordlist_words × 11 + charset_residue`.
    pub bits: f64,
    /// zxcvbn flagged the phrase as trivially guessable (a repeat / sequence /
    /// dictionary pattern). Blocks green regardless of the raw key-space `bits`,
    /// closing the periodic-pattern over-credit the additive model alone leaves
    /// open (e.g. `abcabc…` = 90 chars × log2(3) ≈ 143 "bits").
    pub trivially_weak: bool,
}

impl CircleStrength {
    /// True iff the phrase meets ISC-C9's ≥128-bit circle-of-trust floor AND is
    /// not a trivially-guessable pattern — the real gate (M15). A 12-word
    /// diceware phrase (132 bits) or a sufficiently long, genuinely-varied mixed
    /// string both clear it; the public xkcd 4-word phrase (≤44 bits) and any
    /// periodic/sequential pattern do not.
    pub fn is_circle_green(&self) -> bool {
        self.bits >= CIRCLE_ENTROPY_MIN_BITS && !self.trivially_weak
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

/// log2(2048) — bits per BIP-39 word (the wordlist has exactly 2048 entries).
const BITS_PER_WORD: f64 = 11.0;

/// The BIP-39 English wordlist as a lookup set, built once. Used to credit
/// recognised words at a known per-word entropy in [`estimate_circle`].
fn bip39_word_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| Language::English.word_list().iter().copied().collect())
}

/// Estimate a circle-of-trust phrase's key-space entropy (ISC-C9). See the
/// module docs for the two-model (word + charset) design. The same NFKC +
/// whitespace canonicalization the KDF applies is applied first, so the meter
/// agrees with the key the phrase will actually derive.
pub fn estimate_circle(phrase: &str) -> CircleStrength {
    let canon = canonicalize(phrase);
    let words = bip39_word_set();

    // Word model: each DISTINCT recognised BIP-39 word is worth 11 bits.
    // Everything else is residue for the charset model. A word credited here is
    // NOT also fed to the charset model, so a pure diceware phrase scores
    // word-bits only (no inflated per-character double-count).
    let mut distinct_words: HashSet<&str> = HashSet::new();
    let mut residue = String::new();
    for token in canon.split_whitespace() {
        if words.contains(token) {
            distinct_words.insert(token);
        } else {
            residue.push_str(token);
        }
    }
    let word_bits = distinct_words.len() as f64 * BITS_PER_WORD;
    let charset_bits = charset_residue_bits(&residue);

    // Anti-pattern veto: the additive key-space sum counts characters/words as if
    // independent, which over-credits PERIODIC or SEQUENTIAL structure
    // (`abcabc…`, `abcdef…`). zxcvbn's repeat / sequence / dictionary matchers
    // catch exactly those below its 2⁶⁴ ceiling, so a phrase it rates trivially
    // guessable (score < 2 — under ~10⁶ estimated guesses) can never green
    // however long it is. Genuine diceware or random phrases score 3–4 and pass.
    // We use zxcvbn ONLY as this low-end pattern detector; its 2⁶⁴ cap (the M14
    // blocker) is irrelevant because the ≥128 magnitude comes from the sum above.
    let trivially_weak = canon.is_empty() || (zxcvbn::zxcvbn(&canon, &[]).score() as u8) < 2;

    CircleStrength {
        bits: word_bits + charset_bits,
        trivially_weak,
    }
}

/// Charset-model contribution of the residue: `len × log2(distinct_chars)`.
/// The distinct-character base (rather than the looser character-class pool) is
/// a conservative per-character ceiling — a single repeated character carries no
/// information, so `aaaa…` scores zero here. Longer-period patterns (`abcabc…`)
/// still over-credit through this formula; the zxcvbn veto in [`estimate_circle`]
/// is what actually blocks those.
fn charset_residue_bits(residue: &str) -> f64 {
    let len = residue.chars().count();
    if len == 0 {
        return 0.0;
    }
    let distinct = residue.chars().collect::<HashSet<char>>().len();
    if distinct <= 1 {
        return 0.0;
    }
    len as f64 * (distinct as f64).log2()
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

/// Word count for a generated circle phrase. 12 BIP-39 words ≈ 12 × 11 = 132 bits
/// of real entropy, clearing the ISC-C9 ≥128-bit circle floor with margin. Hidden
/// from the user (brief D3 — no exposed numbers).
pub const CIRCLE_DICEWARE_WORDS: usize = 12;

/// Generate a circle phrase that clears the SAME `is_circle_green` floor (ISC-C9)
/// the circle-join gate enforces, so a generated phrase is never one the join flow
/// would reject. This is the canonical home for both the GUI and the TUI circle-phrase
/// generators — neither reimplements the loop.
///
/// **Why rejection-sampling, not a bare `generate_diceware(12)`:** the generator draws
/// WITH replacement, so ~3% of 12-word phrases repeat a word. `estimate_circle` credits
/// only DISTINCT words (a conservative key-space model), so a phrase with one duplicate
/// scores 11 × 11 = 121 bits — below the 128 floor — even though its real entropy is
/// 132 bits. Resampling until `is_circle_green` keeps the generated phrase consistent
/// with the join gate and the "Looks strong" reassurance. The discarded draws carry the
/// same real entropy; excluding them costs nothing and the remaining phrase space is
/// still astronomically larger than 2¹²⁸.
pub fn generate_circle_phrase() -> Result<String, DicewareError> {
    for _ in 0..32 {
        let p = generate_diceware(CIRCLE_DICEWARE_WORDS)?;
        if estimate_circle(&p).is_circle_green() {
            return Ok(p);
        }
    }
    // Astronomically unreachable (≥32 consecutive sub-floor 12-word draws); return a
    // final attempt rather than panicking in a non-security display path.
    generate_diceware(CIRCLE_DICEWARE_WORDS)
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

    // ── circle key-space estimator (M15, ISC-C9) ──────────────────────────

    /// 12 distinct BIP-39 words = 12 × 11 = 132 bits → clears the ≥128 floor.
    /// This is the recommended "generate-then-type" path.
    #[test]
    fn twelve_diceware_words_clear_the_circle_floor() {
        // The first 12 BIP-39 English words — all distinct, all recognised.
        let phrase = "abandon ability able about above absent \
                      absorb abstract absurd abuse access accident";
        let s = estimate_circle(phrase);
        assert!(
            s.is_circle_green(),
            "12 diceware words rated {s:?}, expected ≥128 bits"
        );
        assert!(
            (s.bits - 132.0).abs() < 1e-9,
            "expected 132 bits, got {}",
            s.bits
        );
    }

    /// `generate_circle_phrase` must ALWAYS clear the ISC-C9 floor — the whole point
    /// of the rejection-sampling loop. A bare `generate_diceware(12)` would fail this
    /// ~1 − 0.97⁶⁴ ≈ 86% of the time (the ~3% per-draw dup-word flake compounds), so a
    /// 64-sample batch makes a regression to the bare generator practically certain to
    /// surface rather than hide behind a lucky single draw.
    #[test]
    fn generate_circle_phrase_always_clears_the_circle_floor() {
        for _ in 0..64 {
            let p = generate_circle_phrase().unwrap();
            assert_eq!(
                p.split_whitespace().count(),
                CIRCLE_DICEWARE_WORDS,
                "generated circle phrase must be {CIRCLE_DICEWARE_WORDS} words: {p:?}"
            );
            assert!(
                estimate_circle(&p).is_circle_green(),
                "generated circle phrase {p:?} must clear the ISC-C9 ≥128-bit floor every time"
            );
        }
    }

    /// The famous public xkcd phrase is only four words (two of which aren't even
    /// in BIP-39). It MUST be blocked — the interim M14 gate wrongly accepted it.
    #[test]
    fn public_xkcd_four_word_phrase_is_blocked() {
        let s = estimate_circle("correct horse battery staple");
        assert!(
            !s.is_circle_green(),
            "the public xkcd phrase rated {s:?}, must not green"
        );
    }

    /// A repeated word cannot inflate the count — only DISTINCT words score.
    #[test]
    fn repeated_word_does_not_inflate() {
        let s = estimate_circle("abandon abandon abandon abandon abandon abandon");
        // One distinct word = 11 bits, nowhere near the floor.
        assert!(
            (s.bits - 11.0).abs() < 1e-9,
            "expected 11 bits, got {}",
            s.bits
        );
        assert!(!s.is_circle_green());
    }

    /// A long, genuinely varied (non-sequential) non-wordlist string reaches
    /// green via the charset model alone — no diceware format is forced
    /// (caraka's M15 decision). It must NOT be a sequence, which zxcvbn vetoes.
    #[test]
    fn long_varied_string_reaches_green_via_charset() {
        // 34 random-looking distinct characters → ≈173 key-space bits, and
        // zxcvbn rates it strong (no repeat/sequence), so it greens.
        let s = estimate_circle("x7Qk!9zR2m@Lp4wV6sT1bN8dF3hJ5cG0aY");
        assert!(
            s.is_circle_green(),
            "a long varied string rated {s:?}, expected green"
        );
    }

    /// A single repeated character carries no information — zero charset bits and
    /// the zxcvbn veto both keep it red however long it is.
    #[test]
    fn repeated_character_never_greens() {
        let s = estimate_circle(&"a".repeat(200));
        assert_eq!(s.bits, 0.0, "a single repeated char must score 0 bits");
        assert!(!s.is_circle_green());
    }

    /// A small-alphabet PERIODIC pattern (`abcabc…`) has high additive "bits"
    /// (90 chars × log2(3) ≈ 143) but the zxcvbn anti-pattern veto keeps it red —
    /// this is the case the additive sum alone gets wrong.
    #[test]
    fn small_alphabet_pattern_stays_below_floor() {
        let s = estimate_circle(&"abc".repeat(30)); // 90 chars, 3 distinct
        assert!(s.trivially_weak, "a 3-char period must be vetoed by zxcvbn");
        assert!(
            !s.is_circle_green(),
            "a 3-character pattern rated {s:?}, must not green"
        );
    }

    /// Words and residue characters combine additively (no double-counting).
    #[test]
    fn words_and_residue_combine() {
        // 2 distinct words (22 bits) + residue "Xq7!vZ" (6 chars, 6 distinct →
        // 6 × log2(6) ≈ 15.5 bits) = ~37.5 bits.
        let s = estimate_circle("abandon ability Xq7!vZ");
        let expected = 22.0 + 6.0 * (6f64).log2();
        assert!(
            (s.bits - expected).abs() < 1e-9,
            "got {}, expected {expected}",
            s.bits
        );
    }

    /// Empty phrase is zero bits and never green.
    #[test]
    fn empty_circle_phrase_is_zero_bits() {
        let s = estimate_circle("");
        assert_eq!(s.bits, 0.0);
        assert!(!s.is_circle_green());
    }

    /// NFKC + whitespace canonicalization is applied before estimation, so the
    /// meter agrees with the key the KDF will derive (ISC-C9).
    #[test]
    fn circle_estimate_canonicalizes_first() {
        // Fullwidth-spaced and extra-whitespace variants must estimate identically
        // to the canonical single-spaced form.
        let a = estimate_circle("abandon   ability    able");
        let b = estimate_circle("abandon ability able");
        assert!((a.bits - b.bits).abs() < 1e-9);
    }
}
