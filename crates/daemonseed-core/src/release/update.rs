//! Client update-lifecycle state machine (ISC-C27 / ISC-A-C11).
//!
//! [`UpdateLifecycle`] models the verify-before-apply discipline for in-app
//! updates as an explicit state machine, with the A-C11 hard rules enforced by
//! the type's shape rather than by remembering to check:
//!
//! - **Verify before apply.** The only path out of [`UpdateState::Available`]
//!   is [`UpdateLifecycle::verify`]; success goes to [`UpdateState::Verified`],
//!   failure to [`UpdateState::Failed`]. Nothing reaches the install-ready state
//!   without first passing N-of-M verification (ISC-A-C11 / A1).
//! - **Never auto-install.** The only path out of `Verified` is
//!   [`UpdateLifecycle::confirm`], which a caller invokes *after* explicit user
//!   confirmation. No method advances to install on its own — including for
//!   emergency updates (A2). "Silent auto-update is a coercion vector this
//!   protocol forecloses by construction."
//! - **No silent downgrade.** A verified update whose version is below the
//!   running version is flagged `is_downgrade`; `confirm` then refuses unless
//!   the caller passes an explicit downgrade acknowledgement (ISC-A-C11).
//! - **Wipe-and-log on failure.** A failed verify wipes the buffered artifact
//!   (no payload retention) and records exactly `(timestamp, channel,
//!   version-attempted, reason)` — the A-C11 failure-log tuple — then emits the
//!   blocking `UpdateVerificationFailed` trust event.
//! - **Source-agnostic trust.** Verification runs against the bundled anchor
//!   regardless of which channel served the bytes, so a relay fallback is no
//!   more trusted than the primary endpoint (ISC-C27 / ISC-A-C11). Using the
//!   fallback merely emits the transient `UpdateRelayFallbackUsed` event.
//!
//! Emitted trust events are the **existing** M7 [`TrustEventKey`] variants — no
//! new wire surface. The driver accumulates them for the caller (UI + audit
//! log) to drain via [`UpdateLifecycle::take_pending_events`].
//!
//! Out of scope (deferred M10-infra): the live HTTPS / relay fetch, the artifact
//! digest computation, and the actual binary swap. This module is the decision
//! logic those pieces drive; it never performs I/O.

use super::anchor::ReleaseAnchor;
use super::verify::{ReleaseVerifyError, verify_multisig};
use crate::trust_events::TrustEventKey;

/// A release binary's SemVer version. Distinct from
/// [`crate::version::ProtocolVersion`] (the wire-protocol MAJOR.MINOR): this is
/// the *binary release* version, and patch level matters for downgrade
/// detection. Field-order derive gives the correct precedence ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseVersion {
    /// SemVer major.
    pub major: u32,
    /// SemVer minor.
    pub minor: u32,
    /// SemVer patch.
    pub patch: u32,
}

impl ReleaseVersion {
    /// A release version.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Which channel served an update artifact. The relay fallback is **no more
/// trusted** than the primary — verification is against the bundled anchor
/// regardless (ISC-C27 / ISC-A-C11). The channel only affects which trust
/// event is emitted, never the verify outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateChannel {
    /// The project's primary HTTPS distribution endpoint.
    Primary,
    /// A daemonseed server's update-relay role (ISC-S18), used when the primary
    /// endpoint is unreachable. Untrusted as a source.
    RelayFallback,
}

/// A discovered update record — the metadata known before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRecord {
    /// The version the artifact claims to be.
    pub version: ReleaseVersion,
    /// The channel that served it.
    pub channel: UpdateChannel,
    /// Whether this is a signed emergency security update (ISC-C27 emergency
    /// flow). Emergency changes the affordance, never the auto-install rule.
    pub emergency: bool,
}

/// One A-C11 failure-log entry. Deliberately carries no payload — only the
/// tuple A-C11 permits: `(timestamp, channel, version-attempted, reason)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureLogEntry {
    /// When the failure occurred (UTC ms).
    pub timestamp_unix_ms: i64,
    /// The channel the failed artifact came from.
    pub channel: UpdateChannel,
    /// The version that failed to verify.
    pub version_attempted: ReleaseVersion,
    /// The verification failure reason (local only).
    pub reason: ReleaseVerifyError,
}

/// The update lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateState {
    /// No update known.
    Idle,
    /// An update was discovered but not yet verified.
    Available(UpdateRecord),
    /// Verified against the anchor; awaiting explicit user confirmation. When
    /// `is_downgrade`, confirmation must explicitly acknowledge the downgrade.
    Verified {
        /// The verified record.
        record: UpdateRecord,
        /// The target version is below the running version (ISC-A-C11).
        is_downgrade: bool,
    },
    /// The user explicitly confirmed; the artifact is ready to hand to the
    /// (deferred) installer. Reachable ONLY via [`UpdateLifecycle::confirm`].
    ConfirmedReadyToInstall(UpdateRecord),
    /// Verification failed; the artifact was wiped and the failure logged.
    Failed(FailureLogEntry),
}

/// Why [`UpdateLifecycle::confirm`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmError {
    /// `confirm` was called outside the `Verified` state — there is nothing
    /// verified to install (enforces verify-before-apply).
    NotVerified,
    /// The verified update is a downgrade and the caller did not explicitly
    /// acknowledge it (ISC-A-C11 no-silent-downgrade).
    DowngradeNotAcknowledged,
}

/// The client update-lifecycle driver. Holds the current state, the running
/// version (for downgrade detection), the buffered artifact (wiped on failure),
/// the A-C11 failure log, and the pending trust events for the caller to drain.
#[derive(Debug)]
pub struct UpdateLifecycle {
    state: UpdateState,
    current_version: ReleaseVersion,
    artifact: Option<Vec<u8>>,
    failure_log: Vec<FailureLogEntry>,
    pending_events: Vec<TrustEventKey>,
}

impl UpdateLifecycle {
    /// A fresh lifecycle for a client running `current_version`.
    pub fn new(current_version: ReleaseVersion) -> Self {
        Self {
            state: UpdateState::Idle,
            current_version,
            artifact: None,
            failure_log: Vec::new(),
            pending_events: Vec::new(),
        }
    }

    /// Record a discovered update and buffer its artifact bytes → `Available`.
    /// Using the relay fallback emits the transient `UpdateRelayFallbackUsed`
    /// event (the fetch used a fallback; the source is still untrusted). Does
    /// NOT verify or install — that is [`verify`](Self::verify)'s job.
    pub fn discover(&mut self, record: UpdateRecord, artifact: Vec<u8>) {
        if record.channel == UpdateChannel::RelayFallback {
            self.pending_events
                .push(TrustEventKey::UpdateRelayFallbackUsed);
        }
        self.artifact = Some(artifact);
        self.state = UpdateState::Available(record);
    }

    /// Verify the buffered artifact's `signatures` over `message` against
    /// `anchor`. On success → `Verified` (flagging a downgrade if the target is
    /// below the running version; emitting the blocking
    /// `EmergencySecurityUpdateAvailable` for an emergency record). On failure →
    /// wipe the artifact, append the A-C11 failure-log tuple, emit the blocking
    /// `UpdateVerificationFailed`, and go to `Failed`. A no-op unless currently
    /// `Available`.
    pub fn verify(
        &mut self,
        anchor: &ReleaseAnchor,
        message: &[u8],
        signatures: &[&[u8]],
        now_ms: i64,
    ) {
        let UpdateState::Available(record) = &self.state else {
            return;
        };
        let record = record.clone();

        match verify_multisig(anchor, message, signatures) {
            Ok(()) => {
                let is_downgrade = record.version < self.current_version;
                if record.emergency {
                    self.pending_events
                        .push(TrustEventKey::EmergencySecurityUpdateAvailable);
                }
                self.state = UpdateState::Verified {
                    record,
                    is_downgrade,
                };
            }
            Err(reason) => {
                // A-C11: wipe the artifact (no payload retention), log the
                // tuple, surface the blocking failure event.
                self.artifact = None;
                let entry = FailureLogEntry {
                    timestamp_unix_ms: now_ms,
                    channel: record.channel,
                    version_attempted: record.version,
                    reason,
                };
                self.failure_log.push(entry);
                self.pending_events
                    .push(TrustEventKey::UpdateVerificationFailed);
                self.state = UpdateState::Failed(entry);
            }
        }
    }

    /// Explicitly confirm a verified update → `ConfirmedReadyToInstall`. This is
    /// the ONLY path past `Verified`; nothing auto-advances here, including
    /// emergency updates (ISC-A-C11). A downgrade requires
    /// `acknowledge_downgrade == true`, else `DowngradeNotAcknowledged`.
    pub fn confirm(&mut self, acknowledge_downgrade: bool) -> Result<(), ConfirmError> {
        let UpdateState::Verified {
            record,
            is_downgrade,
        } = &self.state
        else {
            return Err(ConfirmError::NotVerified);
        };
        if *is_downgrade && !acknowledge_downgrade {
            return Err(ConfirmError::DowngradeNotAcknowledged);
        }
        let record = record.clone();
        self.state = UpdateState::ConfirmedReadyToInstall(record);
        Ok(())
    }

    /// The current state.
    pub fn state(&self) -> &UpdateState {
        &self.state
    }

    /// The A-C11 failure log (append-only, payload-free).
    pub fn failure_log(&self) -> &[FailureLogEntry] {
        &self.failure_log
    }

    /// Whether the artifact bytes are currently buffered. `false` after a
    /// verification failure (the artifact is wiped).
    pub fn has_artifact(&self) -> bool {
        self.artifact.is_some()
    }

    /// Drain the trust events accumulated since the last drain, for the caller
    /// to surface in the UI and record in the audit log.
    pub fn take_pending_events(&mut self) -> Vec<TrustEventKey> {
        std::mem::take(&mut self.pending_events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::SignKeypair;
    use crate::release::anchor::{ReleaseAnchor, ReleaseKey};
    use crate::trust_events::{TrustEventClass, class_of};

    const MSG: &[u8] = b"daemonseed v0.12.0 manifest digest";

    fn kp(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn anchor(k: &SignKeypair) -> ReleaseAnchor {
        ReleaseAnchor::new(vec![ReleaseKey::new(*k.public_key())], 1).unwrap()
    }

    fn rec(version: ReleaseVersion, channel: UpdateChannel, emergency: bool) -> UpdateRecord {
        UpdateRecord {
            version,
            channel,
            emergency,
        }
    }

    fn running() -> ReleaseVersion {
        ReleaseVersion::new(0, 11, 0)
    }

    fn newer() -> ReleaseVersion {
        ReleaseVersion::new(0, 12, 0)
    }

    #[test]
    fn discover_moves_idle_to_available() {
        let mut fsm = UpdateLifecycle::new(running());
        assert_eq!(fsm.state(), &UpdateState::Idle);
        let r = rec(newer(), UpdateChannel::Primary, false);
        fsm.discover(r.clone(), b"artifact".to_vec());
        assert_eq!(fsm.state(), &UpdateState::Available(r));
        assert!(fsm.has_artifact());
    }

    #[test]
    fn verify_advances_to_verified_only_on_valid_signature() {
        let k = kp(1);
        let mut fsm = UpdateLifecycle::new(running());
        fsm.discover(
            rec(newer(), UpdateChannel::Primary, false),
            b"artifact".to_vec(),
        );
        let sig = k.sign(MSG).unwrap();
        fsm.verify(&anchor(&k), MSG, &[&sig], 1000);
        assert!(matches!(
            fsm.state(),
            UpdateState::Verified {
                is_downgrade: false,
                ..
            }
        ));
    }

    #[test]
    fn verified_does_not_auto_install() {
        // ISC-26 / A2: reaching Verified must NOT be ConfirmedReadyToInstall —
        // verify never installs; only an explicit confirm() does.
        let k = kp(1);
        let mut fsm = UpdateLifecycle::new(running());
        fsm.discover(
            rec(newer(), UpdateChannel::Primary, false),
            b"artifact".to_vec(),
        );
        let sig = k.sign(MSG).unwrap();
        fsm.verify(&anchor(&k), MSG, &[&sig], 1000);
        assert!(!matches!(
            fsm.state(),
            UpdateState::ConfirmedReadyToInstall(_)
        ));
        // Only confirm() advances it.
        assert_eq!(fsm.confirm(false), Ok(()));
        assert!(matches!(
            fsm.state(),
            UpdateState::ConfirmedReadyToInstall(_)
        ));
    }

    #[test]
    fn confirm_before_verify_is_rejected() {
        // A1: nothing installs before Verified.
        let mut fsm = UpdateLifecycle::new(running());
        assert_eq!(fsm.confirm(false), Err(ConfirmError::NotVerified));
        fsm.discover(
            rec(newer(), UpdateChannel::Primary, false),
            b"artifact".to_vec(),
        );
        assert_eq!(fsm.confirm(false), Err(ConfirmError::NotVerified));
    }

    #[test]
    fn failed_verify_wipes_artifact_logs_and_emits_blocking_event() {
        // ISC-23 / 24 / 25.
        let k = kp(1);
        let stranger = kp(99);
        let mut fsm = UpdateLifecycle::new(running());
        fsm.discover(
            rec(newer(), UpdateChannel::RelayFallback, false),
            b"artifact".to_vec(),
        );
        let _ = fsm.take_pending_events(); // drop the fallback event for clarity
        let bad = stranger.sign(MSG).unwrap(); // not an anchor key
        fsm.verify(&anchor(&k), MSG, &[&bad], 4242);

        // wiped
        assert!(!fsm.has_artifact(), "artifact must be wiped on failure");
        // logged tuple
        assert_eq!(fsm.failure_log().len(), 1);
        let e = fsm.failure_log()[0];
        assert_eq!(e.timestamp_unix_ms, 4242);
        assert_eq!(e.channel, UpdateChannel::RelayFallback);
        assert_eq!(e.version_attempted, newer());
        assert_eq!(e.reason, ReleaseVerifyError::UnrecognizedSignature);
        // blocking event
        let events = fsm.take_pending_events();
        assert!(events.contains(&TrustEventKey::UpdateVerificationFailed));
        assert_eq!(
            class_of(TrustEventKey::UpdateVerificationFailed),
            TrustEventClass::Blocking
        );
        assert!(matches!(fsm.state(), UpdateState::Failed(_)));
    }

    #[test]
    fn emergency_update_emits_blocking_event_but_still_needs_confirm() {
        // ISC-27 / 28: emergency surfaces a blocking event yet never auto-installs.
        let k = kp(1);
        let mut fsm = UpdateLifecycle::new(running());
        fsm.discover(
            rec(newer(), UpdateChannel::Primary, true),
            b"artifact".to_vec(),
        );
        let sig = k.sign(MSG).unwrap();
        fsm.verify(&anchor(&k), MSG, &[&sig], 1000);
        let events = fsm.take_pending_events();
        assert!(events.contains(&TrustEventKey::EmergencySecurityUpdateAvailable));
        assert_eq!(
            class_of(TrustEventKey::EmergencySecurityUpdateAvailable),
            TrustEventClass::Blocking
        );
        // Still parked at Verified — emergency does not bypass confirmation.
        assert!(matches!(fsm.state(), UpdateState::Verified { .. }));
        assert!(!matches!(
            fsm.state(),
            UpdateState::ConfirmedReadyToInstall(_)
        ));
    }

    #[test]
    fn downgrade_requires_explicit_acknowledgement() {
        // ISC-29: a lower target version is flagged and confirm refuses without
        // an explicit downgrade acknowledgement.
        let k = kp(1);
        let older = ReleaseVersion::new(0, 10, 0); // below running 0.11.0
        let mut fsm = UpdateLifecycle::new(running());
        fsm.discover(
            rec(older, UpdateChannel::Primary, false),
            b"artifact".to_vec(),
        );
        let sig = k.sign(MSG).unwrap();
        fsm.verify(&anchor(&k), MSG, &[&sig], 1000);
        assert!(matches!(
            fsm.state(),
            UpdateState::Verified {
                is_downgrade: true,
                ..
            }
        ));
        assert_eq!(
            fsm.confirm(false),
            Err(ConfirmError::DowngradeNotAcknowledged)
        );
        // Explicit acknowledgement lets it through.
        assert_eq!(fsm.confirm(true), Ok(()));
    }

    #[test]
    fn relay_fallback_is_no_more_trusted_than_primary() {
        // ISC-30: verification outcome is identical regardless of channel — the
        // anchor is the trust root, not the source. ISC-31: using the fallback
        // emits the transient UpdateRelayFallbackUsed event at discover.
        let k = kp(1);
        let sig = k.sign(MSG).unwrap();

        let mut via_primary = UpdateLifecycle::new(running());
        via_primary.discover(rec(newer(), UpdateChannel::Primary, false), b"a".to_vec());
        via_primary.verify(&anchor(&k), MSG, &[&sig], 1);

        let mut via_relay = UpdateLifecycle::new(running());
        via_relay.discover(
            rec(newer(), UpdateChannel::RelayFallback, false),
            b"a".to_vec(),
        );
        let relay_events = via_relay.take_pending_events();
        via_relay.verify(&anchor(&k), MSG, &[&sig], 1);

        // Same verified outcome regardless of channel.
        assert!(matches!(via_primary.state(), UpdateState::Verified { .. }));
        assert!(matches!(via_relay.state(), UpdateState::Verified { .. }));
        // Fallback emitted the transient event; primary did not.
        assert!(relay_events.contains(&TrustEventKey::UpdateRelayFallbackUsed));
        assert_eq!(
            class_of(TrustEventKey::UpdateRelayFallbackUsed),
            TrustEventClass::Transient
        );
    }

    #[test]
    fn a_bad_relay_artifact_cannot_inject_a_binary() {
        // The censorship-survivability property: a hostile relay serving a
        // forged binary fails verification exactly as any other bad artifact.
        let k = kp(1);
        let hostile = kp(123);
        let mut fsm = UpdateLifecycle::new(running());
        fsm.discover(
            rec(newer(), UpdateChannel::RelayFallback, false),
            b"evil".to_vec(),
        );
        let forged = hostile.sign(MSG).unwrap();
        fsm.verify(&anchor(&k), MSG, &[&forged], 9);
        assert!(matches!(fsm.state(), UpdateState::Failed(_)));
        assert!(!fsm.has_artifact());
    }
}
