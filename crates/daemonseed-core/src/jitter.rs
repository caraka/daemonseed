//! The jitter unit drawn from the OS CSPRNG, with the entropy read behind a seam.
//!
//! [`crate::dm::outbox::ReseedSchedule`] draws a `[-1, 1]` jitter unit at runtime
//! for DM re-seed spacing, and had the draw, the mapping and the failure degrade
//! written inline. That is two problems in one shape:
//!
//! - the **mapping** from eight bytes onto the band was never asserted anywhere;
//! - the **degrade** (`Err(_) => 0.0`, i.e. no jitter) was unreachable from a test,
//!   because `getrandom::fill` cannot be made to fail from inside one.
//!
//! [`unit_or_zero`] takes the fill as a parameter, so a test supplies a failing
//! one and the degrade becomes an ordinary branch. Production passes [`os_fill`].
//!
//! **What the degrade means, and what it does not.** Losing jitter is not losing
//! the operation: a retry still happens, a re-seed still happens, on the
//! deterministic curve. What is lost is de-correlation — and an entropy source
//! that fails is failing for every caller at once, so every record falls onto the
//! same curve simultaneously, which is the cross-record phase-lock the jitter
//! exists to prevent (#280). **Whether that should stay silent is an open
//! question, deliberately not settled here** (#280, #332): this module makes the
//! path reachable and testable, and changes no behaviour.
//!
//! [`crate::presence::next_keepalive_interval`] is a sibling but not a user: it
//! maps its bytes onto an inclusive span by modulo and degrades to that span's
//! midpoint, so it shares the shape without sharing the arithmetic.

/// Map eight CSPRNG bytes onto a jitter unit in `[-1, 1]`.
///
/// Little-endian, so the mapping matches what both call sites did before this
/// module existed and no schedule moves as a result of extracting it.
pub(crate) fn unit_from_bytes(buf: [u8; 8]) -> f64 {
    (u64::from_le_bytes(buf) as f64 / u64::MAX as f64) * 2.0 - 1.0
}

/// The production entropy source, adapted to [`unit_or_zero`]'s signature.
///
/// The error is discarded rather than carried: no caller can act on *why* the
/// CSPRNG failed, and the degrade is the same either way.
pub(crate) fn os_fill(buf: &mut [u8; 8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}

/// The same source, slice-typed, for callers that draw buffers of more than one
/// size — key generation and encapsulation seeds alongside an interval draw.
///
/// One definition rather than a second `getrandom` call beside each of them: the
/// production entropy source and its discarded error belong in one place, and a
/// module that grew its own would be the copy nobody keeps in step.
pub(crate) fn os_fill_bytes(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}

/// Draw a jitter unit, degrading to `0.0` — the band centre, i.e. no jitter — if
/// the source fails.
///
/// `fill` is a parameter rather than a direct `getrandom` call so the degrade is
/// reachable: it is the one branch here that cannot be provoked in production on
/// demand, and it is the one whose consequence is a correlation signal.
pub(crate) fn unit_or_zero(fill: impl FnOnce(&mut [u8; 8]) -> Result<(), ()>) -> f64 {
    let mut buf = [0u8; 8];
    match fill(&mut buf) {
        Ok(()) => unit_from_bytes(buf),
        Err(()) => 0.0,
    }
}

/// The runtime draw: [`unit_or_zero`] over [`os_fill`].
pub(crate) fn unit() -> f64 {
    unit_or_zero(os_fill)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band edges and centre, pinned exactly.
    ///
    /// Exact equality rather than a tolerance, because all three values are exact:
    /// `u64::MAX as f64` rounds to `2^64` and the all-ones numerator rounds to the
    /// same, so the ratio is exactly 1; `u64::MAX / 2` rounds to `2^63`, giving
    /// exactly 0.5 and so exactly 0.0 after the affine step.
    ///
    /// **This test is weaker than it looks, and the weakness is why the next one
    /// exists.** f64 has 53 bits of mantissa against 64 bits of input, so roughly
    /// the low 2^11 inputs all map to exactly -1.0 and the top ~1024 to exactly
    /// 1.0. Both assertions here would therefore survive an 11-bit error in the low
    /// bytes. The low bits are constrained by
    /// [`the_mapping_is_monotonic`](Self::the_mapping_is_monotonic), not by this.
    #[test]
    fn the_mapping_covers_the_band_from_edge_to_edge() {
        assert_eq!(unit_from_bytes([0x00; 8]), -1.0);
        assert_eq!(unit_from_bytes([0xFF; 8]), 1.0);
        assert_eq!(unit_from_bytes((u64::MAX / 2).to_le_bytes()), 0.0);
    }

    /// The mapping is increasing across the input range, so no region folds onto
    /// an earlier one.
    ///
    /// A mapping that used the bytes in the wrong order, or wrapped, would still
    /// hit both edges above while being useless for de-correlation — the edges are
    /// palindromic and so endianness-blind, and this is the test that is not.
    ///
    /// **Increasing, not injective.** Result ULP near the edges is `2^-52` while
    /// the input step is `2^-63`, so ~2048 distinct inputs share each output there.
    /// Order is preserved and nothing folds; two adjacent inputs producing the same
    /// unit is expected, not a defect, and this test's sampling interval (`2^60`) is
    /// far too coarse to observe it either way.
    #[test]
    fn the_mapping_is_monotonic() {
        let mut previous = f64::NEG_INFINITY;
        for step in 0..=16u64 {
            let raw = u64::MAX / 16 * step;
            let got = unit_from_bytes(raw.to_le_bytes());
            assert!(
                got > previous,
                "mapping is not increasing at step {step}: {got} followed {previous}"
            );
            previous = got;
        }
    }

    /// The degrade returns the band centre when the source fails — the branch
    /// #280 named as untestable, now driven.
    ///
    /// The success case is asserted alongside it with bytes that map to an edge,
    /// not to the centre. Asserting only the failure would pass on a run that
    /// succeeded and happened to draw the middle of the band, which is exactly
    /// the vacuous shape this test exists to avoid.
    #[test]
    fn an_entropy_failure_degrades_to_no_jitter() {
        assert_eq!(unit_or_zero(|_| Err(())), 0.0);

        assert_eq!(
            unit_or_zero(|buf| {
                *buf = [0x00; 8];
                Ok(())
            }),
            -1.0,
            "the success path is indistinguishable from the degrade, so the \
             degrade assertion above proves nothing"
        );
    }

    /// The fill is actually consulted — a `unit_or_zero` that ignored its
    /// parameter and called `getrandom` itself would pass every test above.
    #[test]
    fn the_supplied_fill_is_the_one_used() {
        let mut called = false;
        let got = unit_or_zero(|buf| {
            called = true;
            *buf = [0xFF; 8];
            Ok(())
        });
        assert!(called, "the supplied fill was never called");
        assert_eq!(got, 1.0);
    }

    /// The production source is wired to something real and varies.
    ///
    /// The production source is wired to something real, varies, and is not
    /// quantised.
    ///
    /// **The band assertion alone is vacuous:** the degrade returns `0.0`, which
    /// is inside the band, so an `os_fill` that always failed — or a `unit` that
    /// returned a constant — satisfies it. The cardinality assertion is what
    /// excludes a dead source, and it is the reason the 64 iterations exist.
    ///
    /// **The floor is a majority of the draws, not one.** A `> 1` floor separates
    /// SOME spread from NO spread and cannot see a draw quantised onto a handful
    /// of values — `unit().signum()` spans the whole band from two points, which
    /// is worse for de-correlation than a collapsed band because a population
    /// splits into two synchronised herds rather than one.
    ///
    /// Not flaky: the mapping has ~2^53 distinct outputs and the band holds far
    /// more of them than 64, so a collision is not a tail this suite meets, while
    /// any low-cardinality mutation falls off a cliff to a handful.
    ///
    /// Breadth only. Uniformity of the OS CSPRNG is not this crate's to assert.
    #[test]
    fn the_production_draw_is_live_and_lands_in_the_band() {
        const DRAWS: usize = 64;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..DRAWS {
            let u = unit();
            assert!((-1.0..=1.0).contains(&u), "drew {u}, outside the band");
            seen.insert(u.to_bits());
        }
        assert!(
            seen.len() > DRAWS / 2,
            "{DRAWS} draws produced only {} distinct values, so the source is \
             dead, constant, or quantised — the band assertion above sees none \
             of the three",
            seen.len()
        );
    }

    /// The low bits of the draw reach the output.
    ///
    /// A mapping that masked or discarded low bytes would still hit both edges and
    /// still be increasing at coarse sample points, while quietly cutting the
    /// entropy the jitter carries. Masking the low byte changes roughly 9% of
    /// outputs across the range — measured, not assumed — and the effect is
    /// concentrated where the ratio's exponent is small, so the pinned pair is
    /// taken from there rather than from mid-range.
    #[test]
    fn the_low_bits_of_the_draw_reach_the_output() {
        assert_ne!(
            unit_from_bytes(513u64.to_le_bytes()),
            unit_from_bytes(512u64.to_le_bytes()),
            "the low byte does not affect the unit, so input entropy is being discarded"
        );
    }

    /// Neither jitter file has re-inlined its own copy of the mapping.
    ///
    /// This is the regression the extraction exists to prevent and the only one
    /// the seam's own tests cannot see: reverting a site to a private
    /// `getrandom` draw leaves the whole crate green, because the entry point
    /// would still return a jittered value — just from a copy free to drift.
    /// `backoff.rs` is scanned as well as the call site, because it owns the
    /// jitter arithmetic and is where a draw would most plausibly reappear.
    ///
    /// A source check is the right instrument here precisely because the property
    /// *is* confined to these two files. The predicate is factored out so it can
    /// be driven by fixtures rather than only by reading real sources.
    #[test]
    fn neither_jitter_file_carries_a_mapping_of_its_own() {
        // Assembled from fragments so this file's own source cannot match.
        fn has_inline_mapping(src: &str) -> bool {
            src.contains(["u64::MAX as ", "f64"].concat().as_str())
        }

        assert!(
            has_inline_mapping("let x = (n as f64 / u64::MAX as f64) * 2.0 - 1.0;"),
            "the predicate does not detect the mapping it exists to find"
        );
        assert!(
            !has_inline_mapping("self.schedule_next_with_unit(now_ms, crate::jitter::unit())"),
            "the predicate fires on a call site that delegates correctly"
        );

        for (name, src) in [
            ("dm/outbox.rs", include_str!("dm/outbox.rs")),
            ("backoff.rs", include_str!("backoff.rs")),
        ] {
            assert!(
                !has_inline_mapping(src),
                "{name} carries its own copy of the jitter mapping; the draw \
                 belongs to jitter::unit"
            );
        }
    }
}
