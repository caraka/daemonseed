//! Steady-state resweep helper (#157 generalized).
//!
//! The round-robin cursor selector shared by the GUI and TUI net actors' steady-state
//! resweep clocks. Hoisted here from both actors (previously byte-identical copies) so
//! the one piece of delivery-correctness logic — never skip a subscribed record — has a
//! single home and a single oracle. Each actor keeps its own tick cadence and warmup
//! hand-off constants (they differ: the GUI hands off past its +60s warmup schedule, the
//! TUI clears only the connect-time login-sweep burst); only this pure selector is shared.

/// Round-robin selector for the steady-state resweep (#157 generalized). Given the
/// CURRENT subscribed record identities and the last-swept one, return the next record
/// to re-sweep: the smallest identity strictly greater than `last`, wrapping to the
/// smallest when `last` is `None`, is the largest, or has itself left the set.
/// **Key-based, not index-based** — a join/leave that reshapes the set between ticks
/// must never skip a record (an index cursor over a shifting `Vec` would reintroduce
/// the exact non-delivery bug this resweep exists to kill). An empty set yields `None`
/// (clean no-op). The identities are sorted+deduped in place so the traversal order is
/// stable across ticks regardless of the caller's insertion order.
///
/// **What an identity is, is the caller's choice, and it must be the SAME choice for
/// every record in one caller's set.** Anything stable and distinct per record serves:
/// a caller whose records all have a derivable owner seed can key on the seed, one
/// holding a record it can only read keys on the owner's public key. Mixing the two
/// within one set would make a cursor advance past a record it had not swept, which is
/// the skip this selector exists to prevent.
pub fn next_resweep_record(
    records: &mut Vec<[u8; 32]>,
    last: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    if records.is_empty() {
        return None;
    }
    records.sort_unstable();
    records.dedup();
    match last {
        None => records.first().copied(),
        Some(last) => records
            .iter()
            .copied()
            .find(|s| *s > last)
            .or_else(|| records.first().copied()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_resweep_record_is_key_based_and_survives_set_changes() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        // Empty set → clean no-op (edge case: no panic, no mod-by-zero).
        assert_eq!(next_resweep_record(&mut vec![], None), None);
        // First pick is the smallest, regardless of insertion order.
        assert_eq!(next_resweep_record(&mut vec![c, a, b], None), Some(a));
        // Advance to the next-greater key each tick.
        assert_eq!(next_resweep_record(&mut vec![a, b, c], Some(a)), Some(b));
        assert_eq!(next_resweep_record(&mut vec![a, b, c], Some(b)), Some(c));
        // Wrap at the end.
        assert_eq!(next_resweep_record(&mut vec![a, b, c], Some(c)), Some(a));
        // Single element re-selects itself (wrap).
        assert_eq!(next_resweep_record(&mut vec![a], Some(a)), Some(a));
        // Regression trap: a set change between ticks must NOT skip a record. Cursor at
        // `a`, `b` has left → next-greater is `c` (not a skipped slot or a panic).
        assert_eq!(next_resweep_record(&mut vec![a, c], Some(a)), Some(c));
        // Cursor points at a seed that has itself left the set → still advances to the
        // next-greater present seed.
        assert_eq!(next_resweep_record(&mut vec![a, c], Some(b)), Some(c));
    }
}
