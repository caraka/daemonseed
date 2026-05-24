//! Per-circle metadata (M3 type-only — circle creation arrives in M6).
//!
//! [`Metadata`] currently carries only the `min_suite_id` field per
//! ISC-C24's "circle-level minimum-suite policy". The field is private
//! and read-only after construction: per the same ISC, **ratcheting up an
//! existing circle's `min_suite_id` is post-MVP**, so the type
//! deliberately exposes no setter and the spec invariant becomes a
//! compile-time guarantee.
//!
//! ## Acceptance semantics (ISC-A-C8 render-time gate)
//!
//! [`Metadata::accepts`] returns `true` iff a candidate `suite_id`:
//!
//! 1. Resolves through [`Registry::lookup`] to a known suite, AND
//! 2. Shares the **same crypto family** (KDF + hash) as the circle's
//!    `min_suite_id`, AND
//! 3. Is **at or above** the `min_suite_id` numerically.
//!
//! Cross-family content is *not* accepted: per ISC-A-C8 cross-family
//! migration is a new-circle event, not an in-place acceptance. The
//! same-family check is what makes the family discriminator load-bearing
//! at render time.
//!
//! The accept/reject decision is intentionally render-time only here;
//! the persistent UX warning copy (per ISC-A-C8) lives at the client UI
//! layer that consumes `accepts`.

use crate::crypto::suite::{Registry, SuiteId};

/// Per-circle metadata carried alongside circle membership state. The
/// only field at M3 is the read-only `min_suite_id` per ISC-C24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// Minimum acceptable `suite_id` for content posted under this circle.
    /// Private + read-only after construction per ISC-A-C8 "ratcheting up
    /// an existing circle's minimum is post-MVP".
    min_suite_id: SuiteId,
}

impl Metadata {
    /// Construct a [`Metadata`] with the given `min_suite_id`. The suite
    /// MUST be present in the build's [`Registry`]; an unknown suite at
    /// circle-creation time would create a circle no member can read.
    pub fn new(min_suite_id: SuiteId) -> Result<Self, UnknownSuite> {
        if Registry::lookup(min_suite_id).is_none() {
            return Err(UnknownSuite(min_suite_id));
        }
        Ok(Self { min_suite_id })
    }

    /// Read-only accessor for the floor. There is intentionally no
    /// setter — see module docs.
    pub fn min_suite_id(&self) -> SuiteId {
        self.min_suite_id
    }

    /// Does this circle accept content tagged with `suite`? See module
    /// docs for the three-part rule.
    pub fn accepts(&self, suite: SuiteId) -> bool {
        let Some(candidate) = Registry::lookup(suite) else {
            return false;
        };
        let Some(floor) = Registry::lookup(self.min_suite_id) else {
            // Floor unknown to this build → cannot make an acceptance
            // decision; refuse safely. In practice `new` rejects unknown
            // floors at construction time so this branch is unreachable
            // unless a `Removed` lifecycle ever stranded an existing
            // circle (which is also a UX-surfaced new-circle event).
            return false;
        };
        if !candidate.same_family(floor) {
            return false;
        }
        suite >= self.min_suite_id
    }
}

/// Error from [`Metadata::new`] — the supplied `min_suite_id` is not
/// present in this build's registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSuite(pub SuiteId);

impl core::fmt::Display for UnknownSuite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "circle min_suite_id {} not present in this build's registry",
            self.0
        )
    }
}

impl core::error::Error for UnknownSuite {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::{CNSA_2_0, SuiteId};

    /// `new` accepts a known suite id and round-trips through
    /// `min_suite_id()`.
    #[test]
    fn new_accepts_known_suite() {
        let id = CNSA_2_0.id;
        let meta = Metadata::new(id).unwrap();
        assert_eq!(meta.min_suite_id(), id);
    }

    /// `new` rejects an unknown suite id — circle creation under a suite
    /// the build doesn't ship would lock everyone out.
    #[test]
    fn new_rejects_unknown_suite() {
        let unknown = SuiteId::try_new(0x0042).unwrap();
        assert_eq!(Metadata::new(unknown), Err(UnknownSuite(unknown)));
    }

    /// `accepts` is true iff the candidate suite is same-family and
    /// numerically at or above the floor. At M3 there is exactly one
    /// suite so the comparison degenerates to "same id"; the test asserts
    /// the reflexive case and the cross-family-reject branch by way of
    /// rejecting an unknown id.
    #[test]
    fn accepts_reflexive_at_floor() {
        let meta = Metadata::new(CNSA_2_0.id).unwrap();
        assert!(meta.accepts(CNSA_2_0.id));
    }

    /// Unknown suites are never accepted — even if the registry grew to
    /// contain that suite later, the build that asked the question can't
    /// verify the family relationship.
    #[test]
    fn accepts_rejects_unknown_candidate() {
        let meta = Metadata::new(CNSA_2_0.id).unwrap();
        let unknown = SuiteId::try_new(0x0042).unwrap();
        assert!(!meta.accepts(unknown));
    }

    /// `Debug` does not leak any secret — `min_suite_id` is non-secret
    /// per ISC-C36 (HKDF info / Argon2 salt are non-secret by design).
    /// The Debug surface is fine to expose for diagnostics.
    #[test]
    fn debug_includes_min_suite_id() {
        let meta = Metadata::new(CNSA_2_0.id).unwrap();
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("0x0001") || dbg.contains("SuiteId"));
    }
}
