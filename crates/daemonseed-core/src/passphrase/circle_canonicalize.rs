//! NFKC + whitespace canonicalization for entropy text inputs (ISC-C9).
//!
//! Circle-of-trust entropy is text-only (passphrase / sentence agreed among
//! circle members). For shared-text → shared-key to be deterministic across
//! members, every member must canonicalize identically before key
//! derivation. The rule per ISC-C9 is:
//!
//! 1. Unicode NFKC normalization (compatibility-decomposition followed by
//!    canonical composition — collapses "fullwidth 1" / "ligature ﬁ" /
//!    similar variants that look identical but encode differently).
//! 2. Strip leading and trailing whitespace.
//! 3. Collapse internal whitespace runs to a single ASCII space.
//!
//! The strength meter (ISC-C12 / ISC-C9 threshold) applies the same
//! canonicalization before estimation so the score the user sees matches
//! the entropy the KDF will actually consume.

use unicode_normalization::UnicodeNormalization;

/// Canonicalize an entropy text input per ISC-C9.
///
/// Idempotent: `canonicalize(canonicalize(s)) == canonicalize(s)`.
pub fn canonicalize(input: &str) -> String {
    // NFKC produces an iterator of `char`; collect to a String first so we
    // can run the whitespace pass over the normalized form (some Unicode
    // whitespace points become ASCII space under NFKC, which the next pass
    // then collapses).
    let nfkc: String = input.nfkc().collect();

    // Two-pass approach: trim + split-collapse. `split_whitespace` handles
    // every Unicode whitespace class, which is what we want — and it
    // implicitly drops leading and trailing runs.
    let mut out = String::with_capacity(nfkc.len());
    let mut first = true;
    for token in nfkc.split_whitespace() {
        if !first {
            out.push(' ');
        }
        out.push_str(token);
        first = false;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_leading_and_trailing_whitespace() {
        assert_eq!(canonicalize("  hello world  "), "hello world");
    }

    #[test]
    fn collapses_internal_whitespace() {
        assert_eq!(canonicalize("a     b\t\tc"), "a b c");
    }

    #[test]
    fn nfkc_compatibility_decomposes_fullwidth_digits() {
        // U+FF11 FULLWIDTH DIGIT ONE → "1" under NFKC.
        assert_eq!(
            canonicalize("password\u{FF11}\u{FF12}\u{FF13}"),
            "password123"
        );
    }

    #[test]
    fn nfkc_decomposes_ligatures() {
        // U+FB01 LATIN SMALL LIGATURE FI → "fi" under NFKC.
        assert_eq!(canonicalize("a\u{FB01}sh"), "afish");
    }

    #[test]
    fn nfkc_composes_combining_marks() {
        // Decomposed "café" (e + COMBINING ACUTE) composes to precomposed "é".
        let decomposed = "cafe\u{0301}";
        let canon = canonicalize(decomposed);
        // The composed form is one fewer byte (U+00E9 = 2 bytes vs e + combining = 3 bytes).
        assert_eq!(canon, "caf\u{00E9}");
    }

    #[test]
    fn idempotent() {
        let original = "  Ｈｅｌｌｏ\u{00A0}\u{2003}World  ";
        let once = canonicalize(original);
        let twice = canonicalize(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn preserves_non_whitespace_unicode() {
        // Non-Latin scripts and emoji pass through unchanged after trim/collapse.
        assert_eq!(canonicalize("  caraka 🌱  "), "caraka 🌱");
        assert_eq!(canonicalize("Ωmega Æthelred"), "Ωmega Æthelred");
    }

    #[test]
    fn empty_input_stays_empty() {
        assert_eq!(canonicalize(""), "");
        assert_eq!(canonicalize("   \t\n   "), "");
    }
}
