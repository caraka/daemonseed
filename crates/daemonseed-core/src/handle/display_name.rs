//! Display-name generator + validator (ISC-C4b).
//!
//! At enrollment the client offers a randomly generated `{adjective}-{noun}`
//! display name from an embedded curated wordlist. The user may regenerate,
//! override, or leave the name empty (floor-handle presentation).
//!
//! Wordlist source: Glitch's `friendly-words` project (MIT-licensed). The
//! original files live under [`wordlists/`] beside this module, embedded into
//! the binary at compile time via `include_str!`. Combined namespace size:
//! `1450 predicates × 3062 objects = 4,439,900` — comfortably above the
//! ISC-C4b ≥2M target so organic display-name collisions are rare without
//! deliberate effort.

use std::sync::OnceLock;

/// Embedded adjective list. Source: friendly-words `words/predicates.txt`.
const PREDICATES_SRC: &str = include_str!("wordlists/predicates.txt");

/// Embedded noun list. Source: friendly-words `words/objects.txt`.
const OBJECTS_SRC: &str = include_str!("wordlists/objects.txt");

static ADJECTIVES: OnceLock<Vec<&'static str>> = OnceLock::new();
static NOUNS: OnceLock<Vec<&'static str>> = OnceLock::new();

fn adjectives() -> &'static [&'static str] {
    ADJECTIVES.get_or_init(|| PREDICATES_SRC.lines().filter(|l| !l.is_empty()).collect())
}

fn nouns() -> &'static [&'static str] {
    NOUNS.get_or_init(|| OBJECTS_SRC.lines().filter(|l| !l.is_empty()).collect())
}

/// Total `{adjective}-{noun}` combinations available from the embedded
/// wordlists.
pub fn combinations() -> usize {
    adjectives().len() * nouns().len()
}

/// Maximum display-name length in bytes. Picked generously enough for
/// non-ASCII user overrides while still capping rendering edge cases.
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;

/// Source of randomness for [`generate_display_name`]. Production callers
/// use [`OsRng`]; tests inject deterministic implementations to make the
/// chosen `(adjective, noun)` pair reproducible.
pub trait DisplayNameRng {
    /// Return an unbiased random index in `[0, len)`. `len` is always > 0
    /// and < `usize::MAX`.
    fn random_index(&mut self, len: usize) -> usize;
}

/// Production RNG backed by the platform's OS CSPRNG via `getrandom`.
///
/// Each call fills an 8-byte buffer and rejection-samples to eliminate the
/// modulo bias that `u64 % len` introduces when `len` does not divide the
/// `u64` range cleanly. The expected rejection rate is `< len / 2^64`,
/// which is effectively zero for any practical wordlist size.
pub struct OsRng;

impl DisplayNameRng for OsRng {
    fn random_index(&mut self, len: usize) -> usize {
        debug_assert!(len > 0, "random_index(0) is undefined");
        // Compute the largest multiple of `len` that fits in `u64` — values
        // above that bound would bias the modulo, so we reject them.
        let bound = (u64::MAX / len as u64).saturating_mul(len as u64);
        loop {
            let mut buf = [0u8; 8];
            getrandom::fill(&mut buf).expect("OS CSPRNG unavailable");
            let n = u64::from_le_bytes(buf);
            if n < bound {
                return (n % len as u64) as usize;
            }
        }
    }
}

/// Generate a random `{adjective}-{noun}` display name.
///
/// At enrollment the user can re-roll by calling this repeatedly until they
/// like the result (ISC-C4b).
pub fn generate_display_name<R: DisplayNameRng>(rng: &mut R) -> String {
    let adj_list = adjectives();
    let noun_list = nouns();
    let adj = adj_list[rng.random_index(adj_list.len())];
    let noun = noun_list[rng.random_index(noun_list.len())];
    format!("{adj}-{noun}")
}

/// Validate a user-supplied display name.
///
/// Rejects names that:
/// - Are empty (use the floor-handle presentation instead).
/// - Contain `#` — would alias the handle hash separator (ISC-C4).
/// - Exceed [`MAX_DISPLAY_NAME_BYTES`] bytes.
/// - Contain ASCII control characters (newline, tab, NUL, …) — these break
///   rendering and lead to handle-confusion in chat UIs.
///
/// This is a permissive validator: it accepts any Unicode that survives the
/// above constraints, including emoji and non-Latin scripts. Stricter
/// per-server rules can apply on top via operator config (M4a+).
pub fn is_valid_display_name(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('#')
        && s.len() <= MAX_DISPLAY_NAME_BYTES
        && !s.chars().any(|c| c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic RNG for tests — returns indices from a pre-seeded
    /// sequence so each test sees the same `(adjective, noun)` pair.
    struct ReplayRng {
        sequence: Vec<usize>,
        cursor: usize,
    }

    impl ReplayRng {
        fn new(sequence: Vec<usize>) -> Self {
            Self {
                sequence,
                cursor: 0,
            }
        }
    }

    impl DisplayNameRng for ReplayRng {
        fn random_index(&mut self, len: usize) -> usize {
            let raw = self.sequence[self.cursor];
            self.cursor += 1;
            raw % len
        }
    }

    // ── wordlist invariants ────────────────────────────────────────────────

    #[test]
    fn adjective_count_meets_iscc4b_floor() {
        // The plan target is ≥1400 adjectives to hit ≥2M combos with the
        // noun list. Dropping below this is a regression.
        assert!(
            adjectives().len() >= 1400,
            "adjectives: only {} entries (need ≥1400)",
            adjectives().len()
        );
    }

    #[test]
    fn noun_count_meets_iscc4b_floor() {
        assert!(
            nouns().len() >= 1400,
            "nouns: only {} entries (need ≥1400)",
            nouns().len()
        );
    }

    #[test]
    fn combinations_clear_two_million_target() {
        // ISC-C4b wordlist sizing target: ≥2,000,000 combinations.
        assert!(
            combinations() >= 2_000_000,
            "{}-combo namespace below 2M target",
            combinations()
        );
    }

    #[test]
    fn no_blank_or_hash_bearing_words() {
        for word in adjectives().iter().chain(nouns().iter()) {
            assert!(!word.is_empty(), "empty wordlist entry");
            assert!(!word.contains('#'), "word `{word}` contains '#'");
            assert!(!word.contains('-'), "word `{word}` contains '-'");
            assert!(
                word.chars().all(|c| !c.is_whitespace()),
                "word `{word}` contains whitespace"
            );
        }
    }

    // ── generator ──────────────────────────────────────────────────────────

    #[test]
    fn generated_name_is_adj_dash_noun() {
        let mut rng = ReplayRng::new(vec![0, 0]);
        let name = generate_display_name(&mut rng);
        let (adj, noun) = name
            .split_once('-')
            .expect("generated name must contain '-' separator");
        assert!(adjectives().contains(&adj));
        assert!(nouns().contains(&noun));
    }

    #[test]
    fn replay_sequence_produces_first_words() {
        let mut rng = ReplayRng::new(vec![0, 0]);
        let name = generate_display_name(&mut rng);
        let expected = format!("{}-{}", adjectives()[0], nouns()[0]);
        assert_eq!(name, expected);
    }

    #[test]
    fn osrng_random_index_is_in_range() {
        let mut rng = OsRng;
        for _ in 0..100 {
            let idx = rng.random_index(7);
            assert!(idx < 7);
        }
    }

    #[test]
    fn osrng_random_index_explores_range() {
        // Sample ~1000 indices over a small space and confirm every value
        // shows up — modulo bias or constant-output bugs trip this.
        let mut rng = OsRng;
        let mut seen = [false; 5];
        for _ in 0..1000 {
            seen[rng.random_index(5)] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "OsRng failed to cover [0,5): {seen:?}"
        );
    }

    // ── validator ──────────────────────────────────────────────────────────

    #[test]
    fn accepts_plain_ascii() {
        assert!(is_valid_display_name("alice"));
        assert!(is_valid_display_name("Alice Bob"));
        assert!(is_valid_display_name("able-aardvark"));
    }

    #[test]
    fn accepts_unicode() {
        assert!(is_valid_display_name("caraka"));
        assert!(is_valid_display_name("Æthelred"));
        assert!(is_valid_display_name("Ωmega"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_display_name(""));
    }

    #[test]
    fn rejects_hash_separator() {
        assert!(!is_valid_display_name("alice#bob"));
        assert!(!is_valid_display_name("#"));
    }

    #[test]
    fn rejects_control_characters() {
        assert!(!is_valid_display_name("alice\n"));
        assert!(!is_valid_display_name("alice\tbob"));
        assert!(!is_valid_display_name("alice\0"));
    }

    #[test]
    fn rejects_overlong_names() {
        let long = "a".repeat(MAX_DISPLAY_NAME_BYTES + 1);
        assert!(!is_valid_display_name(&long));
        let at_limit = "a".repeat(MAX_DISPLAY_NAME_BYTES);
        assert!(is_valid_display_name(&at_limit));
    }
}
