//! Write-time policy gate (ISC-A-C8 compose-time enforcement).
//!
//! [`WritePolicy`] is the configurable knob callers pass to
//! [`crate::crypto::suite::Registry::resolve_for_write_with`] to choose how
//! strict the lifecycle gate should be. The default — [`WritePolicy::RefuseDeprecated`]
//! — matches the ISC-A-C8 client invariant: never write under a
//! `Read-only-deprecated` or `Removed` suite. The looser
//! [`WritePolicy::RefuseRemoved`] is reserved for operator-config scenarios
//! that will land with M7 (suite-deprecation policy); it allows writing
//! under a deprecated suite when no active-write suite is available. The
//! stricter [`WritePolicy::Allow`] disables the gate entirely and is for
//! testing only.

use crate::crypto::suite::LifecycleState;

/// Policy knob for the lifecycle-based write gate. See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WritePolicy {
    /// Refuse any non-`ActiveWrite` lifecycle state. Default for client
    /// code per ISC-A-C8.
    #[default]
    RefuseDeprecated,
    /// Refuse only `Removed` / `Proposed` states; allow `ActiveReadOnly` /
    /// `ReadOnlyDeprecated` writes. Reserved for operator-config use in
    /// M7 when a deployment explicitly permits writing under a deprecated
    /// suite as a fallback. Not used by client code in MVP.
    RefuseRemoved,
    /// Allow writes under any registered suite regardless of lifecycle.
    /// Test-only — never enabled in shipped client code.
    Allow,
}

impl WritePolicy {
    /// Should a write be permitted under a suite currently in `state`?
    ///
    /// Returns `true` iff the policy says the write is allowed. Used by
    /// `Registry::resolve_for_write_with` to drive the
    /// [`crate::crypto::suite::WriteRefusal`] dispatch.
    pub const fn permits(self, state: LifecycleState) -> bool {
        match self {
            WritePolicy::RefuseDeprecated => matches!(state, LifecycleState::ActiveWrite),
            WritePolicy::RefuseRemoved => matches!(
                state,
                LifecycleState::ActiveWrite
                    | LifecycleState::ActiveReadOnly
                    | LifecycleState::ReadOnlyDeprecated
            ),
            WritePolicy::Allow => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RefuseDeprecated` only permits `ActiveWrite`. Default policy.
    #[test]
    fn refuse_deprecated_only_permits_active_write() {
        let policy = WritePolicy::default();
        assert_eq!(policy, WritePolicy::RefuseDeprecated);
        assert!(policy.permits(LifecycleState::ActiveWrite));
        assert!(!policy.permits(LifecycleState::ActiveReadOnly));
        assert!(!policy.permits(LifecycleState::ReadOnlyDeprecated));
        assert!(!policy.permits(LifecycleState::Removed));
        assert!(!policy.permits(LifecycleState::Proposed));
    }

    /// `RefuseRemoved` permits any state except `Removed` / `Proposed`.
    #[test]
    fn refuse_removed_permits_through_deprecated() {
        let policy = WritePolicy::RefuseRemoved;
        assert!(policy.permits(LifecycleState::ActiveWrite));
        assert!(policy.permits(LifecycleState::ActiveReadOnly));
        assert!(policy.permits(LifecycleState::ReadOnlyDeprecated));
        assert!(!policy.permits(LifecycleState::Removed));
        assert!(!policy.permits(LifecycleState::Proposed));
    }

    /// `Allow` permits every lifecycle state. Test-only.
    #[test]
    fn allow_permits_everything() {
        let policy = WritePolicy::Allow;
        assert!(policy.permits(LifecycleState::ActiveWrite));
        assert!(policy.permits(LifecycleState::ActiveReadOnly));
        assert!(policy.permits(LifecycleState::ReadOnlyDeprecated));
        assert!(policy.permits(LifecycleState::Removed));
        assert!(policy.permits(LifecycleState::Proposed));
    }
}
