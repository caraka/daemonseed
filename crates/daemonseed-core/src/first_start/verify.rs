//! Type-back challenge for the skip-recovery-file backup-verify path
//! (ISC-C34).
//!
//! At first-start, a user who declines the encrypted recovery file
//! (ISC-C32) must demonstrate phrase capture by typing back N=3 random
//! words from the displayed mnemonic at positions chosen with
//! cryptographic randomness. The challenge is one-shot — generated once
//! per attempt, consumed by `verify_type_back`. Re-issuing the challenge
//! produces fresh positions.

use crate::handle::display_name::DisplayNameRng;

/// Number of words the user must type back. Pinned by ISC-C34's "N=3"
/// language; bumping requires a spec edit.
pub const TYPE_BACK_WORD_COUNT: usize = 3;

/// Maximum retry budget per type-back attempt before first-start
/// fail-closes. Wallet-ecosystem norm; not pinned by the ISC. Caller
/// (CLI / TUI) enforces this — the orchestrator doesn't track retries
/// itself.
#[allow(dead_code)]
pub const TYPE_BACK_MAX_RETRIES: usize = 3;

/// A type-back challenge. Carries the positions in the mnemonic the user
/// must reproduce and the expected words (kept private — only equality
/// checks are exposed). Construct via
/// [`Sealed::issue_type_back_challenge`](crate::first_start::Sealed::issue_type_back_challenge).
pub struct TypeBackChallenge {
    /// 0-based positions into the 24-word mnemonic.
    positions: Vec<usize>,
    /// The words at those positions — held privately so the challenge
    /// doesn't leak the answers via Debug.
    expected: Vec<String>,
}

impl core::fmt::Debug for TypeBackChallenge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TypeBackChallenge")
            .field("positions", &self.positions)
            .field("expected", &"<redacted>")
            .finish()
    }
}

impl TypeBackChallenge {
    /// Build a challenge by sampling [`TYPE_BACK_WORD_COUNT`] unique
    /// positions from the supplied 24-word phrase via the caller's RNG.
    /// `phrase` is the space-separated mnemonic (the 24 BIP-39 words).
    ///
    /// `rng` must satisfy [`DisplayNameRng`] — same trait the display-
    /// name generator uses, so a single CSPRNG abstraction covers both
    /// callsites.
    pub fn new<R: DisplayNameRng>(phrase: &str, rng: &mut R) -> Self {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let total = words.len();
        let target = TYPE_BACK_WORD_COUNT.min(total);

        // Sample without replacement: maintain a pool of remaining indices
        // and pick uniformly from it on each draw.
        let mut pool: Vec<usize> = (0..total).collect();
        let mut positions = Vec::with_capacity(target);
        let mut expected = Vec::with_capacity(target);
        for _ in 0..target {
            let pick = rng.random_index(pool.len());
            let pos = pool.swap_remove(pick);
            positions.push(pos);
            expected.push(words[pos].to_string());
        }
        // Sort positions ascending so the user types in word-order — more
        // natural UX than asking for word 17 then word 4 then word 22.
        let mut paired: Vec<(usize, String)> = positions.into_iter().zip(expected).collect();
        paired.sort_by_key(|(p, _)| *p);
        let (positions, expected): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        Self {
            positions,
            expected,
        }
    }

    /// 0-based positions the user must answer for, in ascending order.
    pub fn positions(&self) -> &[usize] {
        &self.positions
    }

    /// Number of words in the challenge.
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// `true` when there are no positions (only possible if the source
    /// phrase was empty — not a real BIP-39 state).
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Compare user-supplied answers (in the same order as [`positions`])
    /// against the expected words. Returns `true` iff every position
    /// matches verbatim.
    pub(crate) fn matches(&self, answers: &[String]) -> bool {
        if answers.len() != self.expected.len() {
            return false;
        }
        self.expected
            .iter()
            .zip(answers.iter())
            .all(|(e, a)| e.trim().eq_ignore_ascii_case(a.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test RNG that replays a sequence of indices.
    struct ReplayRng {
        seq: Vec<usize>,
        cursor: usize,
    }

    impl DisplayNameRng for ReplayRng {
        fn random_index(&mut self, len: usize) -> usize {
            let raw = self.seq[self.cursor];
            self.cursor += 1;
            raw % len
        }
    }

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn challenge_picks_three_unique_positions() {
        let mut rng = ReplayRng {
            seq: vec![0, 5, 10],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        assert_eq!(c.len(), 3);
        let pos = c.positions();
        let unique: std::collections::HashSet<_> = pos.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn positions_are_in_ascending_order() {
        let mut rng = ReplayRng {
            seq: vec![20, 0, 10],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        let pos = c.positions();
        for w in pos.windows(2) {
            assert!(w[0] < w[1], "positions not ascending: {pos:?}");
        }
    }

    #[test]
    fn matches_accepts_correct_answers() {
        let mut rng = ReplayRng {
            seq: vec![0, 1, 2],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        let answers: Vec<String> = c.expected.clone();
        assert!(c.matches(&answers));
    }

    #[test]
    fn matches_rejects_wrong_words() {
        let mut rng = ReplayRng {
            seq: vec![0, 1, 2],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        let answers = vec![
            "wrong".to_string(),
            "wrong".to_string(),
            "wrong".to_string(),
        ];
        assert!(!c.matches(&answers));
    }

    #[test]
    fn matches_rejects_wrong_count() {
        let mut rng = ReplayRng {
            seq: vec![0, 1, 2],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        assert!(!c.matches(&[c.expected[0].clone()]));
    }

    #[test]
    fn matches_tolerates_case_and_whitespace() {
        let mut rng = ReplayRng {
            seq: vec![0, 1, 2],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        let answers: Vec<String> = c
            .expected
            .iter()
            .map(|w| format!("  {}  ", w.to_uppercase()))
            .collect();
        assert!(c.matches(&answers));
    }

    #[test]
    fn debug_redacts_expected_words() {
        let mut rng = ReplayRng {
            seq: vec![0, 1, 2],
            cursor: 0,
        };
        let c = TypeBackChallenge::new(PHRASE, &mut rng);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<redacted>"));
        for w in &c.expected {
            assert!(!dbg.contains(w), "Debug leaked expected word `{w}`: {dbg}");
        }
    }

    #[test]
    fn fresh_rng_produces_different_positions() {
        // Two challenges sampled from different RNG sequences should
        // (usually) land on different positions. Cheap probabilistic
        // check; reasonable for the M2 invariant.
        let mut a_rng = ReplayRng {
            seq: vec![0, 5, 10],
            cursor: 0,
        };
        let mut b_rng = ReplayRng {
            seq: vec![1, 12, 22],
            cursor: 0,
        };
        let a = TypeBackChallenge::new(PHRASE, &mut a_rng);
        let b = TypeBackChallenge::new(PHRASE, &mut b_rng);
        assert_ne!(a.positions(), b.positions());
    }
}
