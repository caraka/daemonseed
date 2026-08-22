//! Trust-event taxonomy and audit log — ISC-C28 / ISC-A-C12 (M7).
//!
//! Every **trust-state event** (an event whose existence reflects a security
//! decision, anomaly, or required user awareness) is rendered according to a
//! uniform four-class affordance taxonomy ([`TrustEventClass`]). This module
//! pins the *semantics*: the closed [`TrustEventKey`] enum, the key→class
//! mapping ([`class_of`]), the frozen-forever stable string form
//! ([`event_key_string`] / [`event_key_from_str`], closes risk R9), and the
//! bounded, encrypted audit log ([`TrustEventLog`] + [`seal_log`] /
//! [`open_log`]). Visual treatment lives with each GUI implementation
//! (ISC-C6 / ISC-C10); the TUI build-out is M11.
//!
//! ## Stability contract (ISC-C28)
//!
//! [`TrustEventKey`] is a **closed wire-stability surface**. Variants may be
//! *added* but never *renamed or removed*: third-party clients (ISC-C10) and
//! the on-disk audit log persist the stable string form, so a rename silently
//! corrupts history. Each key has **exactly one** class — state transitions are
//! modelled as two distinct keys (e.g. `connection-rate-limited` →
//! `connection-rate-limited-exhausted`), never as a class change on one key.
//!
//! ## A-C12 invariants, structurally enforced
//!
//! - **No class degradation:** [`class_of`] is a total pure function with no
//!   override parameter. There is no API to remap a key to a lower class, and
//!   no "disable security warnings" toggle exists in this module.
//! - **No global dismissal:** dismissal is keyed by `(event-key, scope)` via
//!   [`TrustEventLog::dismiss`]; there is no dismiss-all entry point.
//! - **Transient asymmetry:** [`TrustEventLog::append`] records every
//!   non-`Transient` event and silently drops `Transient` ones (keeping the log
//!   bounded against high-frequency keys); dismissing an event never removes its
//!   log entry — the log records *that it occurred*, distinct from *that it was
//!   dismissed*.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::deprecation::DeprecationPolicy;
use crate::crypto::suite::SuiteId;
use crate::kdf::info;
use crate::profile::config::ArgonParams;
use crate::storage::dm_store::RecordKind;
use crate::storage::seeds::{AEAD_KEY_LEN, ARGON2_OUTPUT_LEN, NONCE_LEN, TAG_LEN};

/// Default audit-log filename at the profile root (finding F24).
pub const AUDIT_LOG_FILENAME: &str = "trust-events.log";

/// Default bounded capacity of the audit log (ISC-C28). Oldest entries are
/// pruned beyond this; configurable per user preference.
pub const DEFAULT_LOG_CAP: usize = 10_000;

/// The four affordance classes (ISC-C28). The taxonomy is intentionally small
/// to constrain implementer drift — events fit a class, not the other way
/// round. Implementations MUST NOT invent sub-classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEventClass {
    /// Prevents the affected functional path until the user acts. Reserved for
    /// security decisions the user MUST consciously make.
    Blocking,
    /// Surfaces on every app start until the condition resolves or the user
    /// dismisses it for that specific event-key. Does not block operation.
    PersistentNonBlocking,
    /// Notification-style; auto-dismisses. Informational, no action required.
    /// Not recorded in the audit log (the intentional asymmetry).
    Transient,
    /// No UI surface at event time; recorded in the audit log for later review.
    LogOnly,
}

/// The closed set of trust-event keys (ISC-C28). See the module-level stability
/// contract. New keys append here; existing keys are never renamed or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustEventKey {
    /// Trusted-mode server key rotation observed (ISC-C22).
    ServerKeyRotated,
    /// Untrusted-mode server key mismatch — refuse connection (ISC-C22).
    ServerKeyMismatch,
    /// A suite the client uses is approaching its deprecation cutoff (ISC-C25).
    SuiteDeprecationPending,
    /// A suite the client uses is at/past its cutoff (ISC-C25).
    SuiteDeprecationCutoffHit,
    /// Circle content below the circle's minimum suite (ISC-A-C8).
    CircleContentBelowMinSuite,
    /// Circle's suite family is cross-family deprecated (ISC-A-C8).
    CircleCrossFamilyDeprecated,
    /// No common protocol version at APP_HELLO (ISC-C23).
    NoCommonVersion,
    /// Connection refused by the server's rate limiter, mid auto-backoff (ISC-C26).
    ConnectionRateLimited,
    /// Rate-limit retry budget exhausted (ISC-C26).
    ConnectionRateLimitedExhausted,
    /// A release-channel update artifact failed signature verification (ISC-A-C11).
    UpdateVerificationFailed,
    /// An emergency security update is available (ISC-C27).
    EmergencySecurityUpdateAvailable,
    /// A peer's identity-proof suite is unsupported by this build (ISC-C24/S15).
    UnsupportedIdentityProofSuite,
    /// The server's deprecation policy was missing / unparseable / unsigned (ISC-A-C9).
    ServerDeprecationPolicyUnreadable,
    /// The server served a deprecation policy older than one already seen —
    /// active-attack signal (ISC-A-S11 / ISC-C25).
    ServerDeprecationPolicyRollback,
    /// A release update was fetched from a server fallback, not the primary
    /// endpoint (ISC-C27).
    UpdateRelayFallbackUsed,
    /// The cached deprecation policy is past its TTL and could not be refreshed
    /// (ISC-A-C9).
    ServerDeprecationPolicyExpiredOffline,
    /// Concurrent federation-peer key rotations diverged during partition-heal
    /// (finding F31).
    FederationPeerKeyDivergence,
    /// A federated server advertised no AGPL §13 source URL (finding F32).
    ServerSourceUnverified,
    /// An established DM channel did not survive a restart and was torn down
    /// (ISC-C44 / #243).
    ///
    /// Not an anomaly — the design persists no steady-state ratchet, because a
    /// chain written down is a chain that was not deleted. The event exists
    /// because the *user* must be told: without it a conversation that can no
    /// longer send or receive still renders as an open thread, which is the
    /// silent death #243 opened on.
    DmChannelTornDownOnRestart,
    /// A DM channel's provisional handshake record did not open or did not
    /// validate, so a handshake in progress is stranded (#243).
    ///
    /// Distinct from the key above because the condition and the remedy differ —
    /// an introduction to re-send rather than a conversation to re-establish —
    /// and because this one can also mean tampering or a partial rollback of the
    /// record, which deserves its own audit-log line.
    DmProvisionalHandshakeLost,
    /// A DM channel's provisional record could not be READ from the store at
    /// startup -- an I/O or permission failure, not a cryptographic one (#243).
    ///
    /// Deliberately not [`Self::DmProvisionalHandshakeLost`]. That key means the
    /// introduction is gone and must be sent again; this one means the record is
    /// most likely still on disk and untouched, and the next start may resume it.
    /// Collapsing the two would tell a user to re-introduce themselves over a
    /// transient `EIO`, destroying a handshake that was recoverable.
    DmProvisionalRecordUnreadable,
    /// A DM record could not be erased: it would not open for writing and
    /// restoring owner-write did not help.
    ///
    /// Surfaced rather than retried because the condition is **permanent**. The
    /// delete is deliberately fail-closed — erasing the record is the
    /// forward-secrecy premise, and for the provisional record it is `ss0`, which
    /// roots `RK0` — so the daemon will refuse for ever rather than report a
    /// success that leaves the secret readable. That makes it a state only a human
    /// can clear, and a correspondence stuck in it cannot complete establishment.
    DmRecordErasureBlocked,
}

/// Every key, in declaration order. Used by exhaustiveness tests and any caller
/// that needs to enumerate the taxonomy (e.g. a future Trust History filter).
pub const ALL_EVENT_KEYS: &[TrustEventKey] = &[
    TrustEventKey::ServerKeyRotated,
    TrustEventKey::ServerKeyMismatch,
    TrustEventKey::SuiteDeprecationPending,
    TrustEventKey::SuiteDeprecationCutoffHit,
    TrustEventKey::CircleContentBelowMinSuite,
    TrustEventKey::CircleCrossFamilyDeprecated,
    TrustEventKey::NoCommonVersion,
    TrustEventKey::ConnectionRateLimited,
    TrustEventKey::ConnectionRateLimitedExhausted,
    TrustEventKey::UpdateVerificationFailed,
    TrustEventKey::EmergencySecurityUpdateAvailable,
    TrustEventKey::UnsupportedIdentityProofSuite,
    TrustEventKey::ServerDeprecationPolicyUnreadable,
    TrustEventKey::ServerDeprecationPolicyRollback,
    TrustEventKey::UpdateRelayFallbackUsed,
    TrustEventKey::ServerDeprecationPolicyExpiredOffline,
    TrustEventKey::FederationPeerKeyDivergence,
    TrustEventKey::ServerSourceUnverified,
    TrustEventKey::DmChannelTornDownOnRestart,
    TrustEventKey::DmProvisionalHandshakeLost,
    TrustEventKey::DmProvisionalRecordUnreadable,
    TrustEventKey::DmRecordErasureBlocked,
];

/// The affordance class for a key (ISC-C28 per-event assignment table). Total
/// and pure — there is deliberately no way to override the mapping (A-C12
/// no-class-degradation).
pub const fn class_of(key: TrustEventKey) -> TrustEventClass {
    use TrustEventClass::*;
    use TrustEventKey::*;
    match key {
        ServerKeyRotated => PersistentNonBlocking,
        ServerKeyMismatch => Blocking,
        SuiteDeprecationPending => PersistentNonBlocking,
        SuiteDeprecationCutoffHit => Blocking,
        CircleContentBelowMinSuite => Blocking,
        CircleCrossFamilyDeprecated => PersistentNonBlocking,
        NoCommonVersion => Blocking,
        ConnectionRateLimited => Transient,
        ConnectionRateLimitedExhausted => PersistentNonBlocking,
        UpdateVerificationFailed => Blocking,
        EmergencySecurityUpdateAvailable => Blocking,
        UnsupportedIdentityProofSuite => Blocking,
        ServerDeprecationPolicyUnreadable => PersistentNonBlocking,
        ServerDeprecationPolicyRollback => Blocking,
        UpdateRelayFallbackUsed => Transient,
        ServerDeprecationPolicyExpiredOffline => PersistentNonBlocking,
        FederationPeerKeyDivergence => PersistentNonBlocking,
        ServerSourceUnverified => LogOnly,
        // Both surface at every start until acted on, and neither blocks: the
        // affected path is already gone, so there is nothing for a blocking
        // affordance to hold back and no decision for the user to make. Not
        // `Transient` either — a transient event is not written to the audit
        // log, and a conversation ending unannounced in the log is the defect
        // these keys exist to close.
        DmChannelTornDownOnRestart => PersistentNonBlocking,
        DmProvisionalHandshakeLost => PersistentNonBlocking,
        // Recurs at every start until the store is readable again, and must be
        // audited: a channel that could not be read is a channel that did not
        // resume, and an unexplained non-resumption is the #243 defect wearing
        // an operational hat.
        DmProvisionalRecordUnreadable => PersistentNonBlocking,
        // Recurs at every start until a human fixes the record's mode, and must be
        // audited: the daemon is refusing to proceed, so a user who is not told
        // sees a correspondence that simply never establishes. Not `Blocking` —
        // there is no decision for the user to make here and nothing to hold back
        // that the refusal has not already stopped.
        DmRecordErasureBlocked => PersistentNonBlocking,
    }
}

/// The stable, frozen-forever string form of a key (ISC-C28, closes R9). These
/// strings are persisted in the audit log and consumed by third-party clients;
/// **never change one** once shipped.
pub const fn event_key_string(key: TrustEventKey) -> &'static str {
    use TrustEventKey::*;
    match key {
        ServerKeyRotated => "server-key-rotated",
        ServerKeyMismatch => "server-key-mismatch",
        SuiteDeprecationPending => "suite-deprecation-pending",
        SuiteDeprecationCutoffHit => "suite-deprecation-cutoff-hit",
        CircleContentBelowMinSuite => "circle-content-below-min-suite",
        CircleCrossFamilyDeprecated => "circle-cross-family-deprecated",
        NoCommonVersion => "no-common-version",
        ConnectionRateLimited => "connection-rate-limited",
        ConnectionRateLimitedExhausted => "connection-rate-limited-exhausted",
        UpdateVerificationFailed => "update-verification-failed",
        EmergencySecurityUpdateAvailable => "emergency-security-update-available",
        UnsupportedIdentityProofSuite => "unsupported-identity-proof-suite",
        ServerDeprecationPolicyUnreadable => "server-deprecation-policy-unreadable",
        ServerDeprecationPolicyRollback => "server-deprecation-policy-rollback",
        UpdateRelayFallbackUsed => "update-relay-fallback-used",
        ServerDeprecationPolicyExpiredOffline => "server-deprecation-policy-expired-offline",
        FederationPeerKeyDivergence => "federation-peer-key-divergence",
        ServerSourceUnverified => "server-source-unverified",
        DmChannelTornDownOnRestart => "dm-channel-torn-down-on-restart",
        DmProvisionalHandshakeLost => "dm-provisional-handshake-lost",
        DmProvisionalRecordUnreadable => "dm-provisional-record-unreadable",
        DmRecordErasureBlocked => "dm-record-erasure-blocked",
    }
}

/// Parse a key from its stable string form. The inverse of [`event_key_string`];
/// returns `None` for an unknown string (e.g. a key from a newer build).
///
/// **The audit-log decoder treats that `None` as a malformed body and loses
/// every entry**, which is the same forward-compatibility exposure the
/// record-kind field used to have and no longer does. It is not fixed the same
/// way because it cannot be: a key is not optional, so there is no field to
/// degrade — the choices are dropping the entry (silent loss from an audit log)
/// or failing (loud loss of the whole log), and picking between them is a
/// decision about audit-log semantics, not a repair. Recorded here so the
/// exposure is visible at the site rather than inferred from the decoder.
pub fn event_key_from_str(s: &str) -> Option<TrustEventKey> {
    ALL_EVENT_KEYS
        .iter()
        .copied()
        .find(|k| event_key_string(*k) == s)
}

/// Resolution status of a trust event (part of the ISC-C28 log tuple).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStatus {
    /// The underlying condition has not been resolved.
    Unresolved,
    /// The underlying condition has been resolved (e.g. user migrated suite).
    Resolved,
}

/// One audit-log entry. The shape is fixed by ISC-C28 / ISC-A-C12: no message
/// content, no per-circle membership, no recently-contacted records — only this
/// tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEvent {
    /// UTC wall-clock milliseconds the event occurred.
    pub timestamp_unix_ms: i64,
    /// The stable event key.
    pub key: TrustEventKey,
    /// The server-id the event concerns, if any (contextual scope).
    pub server_id: Option<String>,
    /// The suite-id the event concerns, if any (contextual scope).
    pub suite_id: Option<SuiteId>,
    /// The *kind* of object the event concerns, if the key has one.
    ///
    /// A closed-set, non-identifying scope discriminant (ISC-C28). It names a
    /// type of record, never an instance: [`RecordKind`] carries no path, no
    /// correspondence label and no correspondent, so a log full of these
    /// cannot be joined into the recently-contacted set ISC-A-C1 forbids.
    /// That is exactly why the correspondence itself is *not* here, and will
    /// not be.
    pub record_kind: Option<RecordKind>,
    /// Whether the underlying condition has been resolved.
    pub resolution: ResolutionStatus,
    /// When the user dismissed the affordance, if they did. Distinct from
    /// resolution: dismissal acknowledges, it does not fix.
    pub dismissed_at_unix_ms: Option<i64>,
}

impl TrustEvent {
    /// A freshly-observed event with no record-kind scope: unresolved,
    /// undismissed. Every key but the erasure one is raised this way, and the
    /// signature is what holds them to `record_kind: None`.
    pub fn observed(
        timestamp_unix_ms: i64,
        key: TrustEventKey,
        server_id: Option<String>,
        suite_id: Option<SuiteId>,
    ) -> Self {
        TrustEventScope::bare(key).observed_at(timestamp_unix_ms, server_id, suite_id)
    }
}

/// What a raising site knows about an event before a clock is read: its stable
/// key, plus the kind of object at stake where the key has one.
///
/// **The pairing is the point.** `DmStoreError::event` used to return the key
/// alone, so the `RecordKind` its `ErasureBlocked` variant already held was
/// discarded at the one hop between knowing it and reporting it. Returning the
/// two together means a caller cannot reach the key without being handed the
/// kind, and [`Self::observed_at`] is the whole path from here to a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEventScope {
    /// The stable event key.
    pub key: TrustEventKey,
    /// The kind of object at stake, for keys whose subject is a kind.
    pub record_kind: Option<RecordKind>,
}

impl TrustEventScope {
    /// A key whose subject is not a kind of record.
    pub const fn bare(key: TrustEventKey) -> Self {
        Self {
            key,
            record_kind: None,
        }
    }

    /// A key scoped to the kind of record it concerns.
    pub const fn for_record(key: TrustEventKey, record_kind: RecordKind) -> Self {
        Self {
            key,
            record_kind: Some(record_kind),
        }
    }

    /// Stamp this scope with the moment it was observed: unresolved,
    /// undismissed.
    pub fn observed_at(
        self,
        timestamp_unix_ms: i64,
        server_id: Option<String>,
        suite_id: Option<SuiteId>,
    ) -> TrustEvent {
        TrustEvent {
            timestamp_unix_ms,
            key: self.key,
            server_id,
            suite_id,
            record_kind: self.record_kind,
            resolution: ResolutionStatus::Unresolved,
            dismissed_at_unix_ms: None,
        }
    }
}

/// The contextual scope a dismissal applies to (ISC-A-C12: dismissal is per
/// `(event-key, scope)`, never global). Two events share a scope iff their
/// `server_id` and `suite_id` both match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DismissalScope {
    /// Server-id the dismissal is scoped to.
    pub server_id: Option<String>,
    /// Suite-id the dismissal is scoped to.
    pub suite_id: Option<SuiteId>,
}

/// A bounded, in-memory trust-event audit log (ISC-C28). Persisted encrypted
/// via [`seal_log`] / [`open_log`].
#[derive(Debug, Clone)]
pub struct TrustEventLog {
    entries: Vec<TrustEvent>,
    cap: usize,
}

impl Default for TrustEventLog {
    fn default() -> Self {
        Self::new(DEFAULT_LOG_CAP)
    }
}

impl TrustEventLog {
    /// An empty log with an explicit capacity.
    pub fn new(cap: usize) -> Self {
        Self {
            entries: Vec::new(),
            cap,
        }
    }

    /// Append an event. `Transient`-class events are silently dropped (the
    /// ISC-A-C12 asymmetry — they surface in the UI but are not logged, keeping
    /// the log bounded against high-frequency keys). Any other class is
    /// recorded, then the log is pruned to its cap (oldest first).
    pub fn append(&mut self, event: TrustEvent) {
        if class_of(event.key) == TrustEventClass::Transient {
            return;
        }
        self.entries.push(event);
        self.prune_to(self.cap);
    }

    /// All logged events, oldest first.
    pub fn entries(&self) -> &[TrustEvent] {
        &self.entries
    }

    /// Number of logged events.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Prune to at most `cap` entries, dropping the oldest. Also resets the
    /// running cap so future appends honor the new bound.
    pub fn prune_to(&mut self, cap: usize) {
        self.cap = cap;
        if self.entries.len() > cap {
            let excess = self.entries.len() - cap;
            self.entries.drain(0..excess);
        }
    }

    /// Mark every entry matching `(key, scope)` as dismissed at `at_unix_ms`.
    /// Dismissal never removes an entry (ISC-A-C12: the log records that the
    /// event occurred, distinct from that it was dismissed). Scoped by
    /// `(event-key, server_id, suite_id)` so dismissing one server's event does
    /// not dismiss another's (no global dismissal).
    pub fn dismiss(&mut self, key: TrustEventKey, scope: &DismissalScope, at_unix_ms: i64) {
        for e in &mut self.entries {
            if e.key == key && e.server_id == scope.server_id && e.suite_id == scope.suite_id {
                e.dismissed_at_unix_ms = Some(at_unix_ms);
            }
        }
    }
}

// ── Deprecation → trust-event bridge (ISC-C25 / ISC-14, client side) ──────

/// A trust signal derived from a fetched deprecation policy for one affected
/// suite (ISC-C25). Carries everything the blocking/persistent affordance needs
/// — the same fields ISC-S16 would have put on the wire reject, sourced from the
/// signed policy the client holds (see `crypto::deprecation` design note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationSignal {
    /// `SuiteDeprecationCutoffHit` (blocking) at/past the cutoff, else
    /// `SuiteDeprecationPending` (persistent-non-blocking).
    pub key: TrustEventKey,
    /// The affected suite.
    pub suite_id: SuiteId,
    /// The cutoff instant (UTC ms).
    pub cutoff_unix_ms: i64,
    /// The operator-recommended migration target.
    pub recommended_suite_id: SuiteId,
}

/// Derive the trust signals a client should surface for a verified policy, given
/// the suites it currently uses (default-write, identity, joined circles) and
/// the current time (ISC-C25 / ISC-14 / ISC-27). A suite at/past its cutoff
/// yields a **blocking** `SuiteDeprecationCutoffHit`; one still before its
/// cutoff yields a **persistent-non-blocking** `SuiteDeprecationPending`.
///
/// This function only *reports*. It never rotates identity material or
/// downgrades a suite (ISC-A-C9 / ISC-A3): there is no mutation path here, so a
/// client cannot silently escape a cutoff.
pub fn assess_deprecation(
    policy: &DeprecationPolicy,
    in_use: &[SuiteId],
    now_ms: i64,
) -> Vec<DeprecationSignal> {
    policy
        .affected(in_use)
        .into_iter()
        .map(|e| DeprecationSignal {
            key: if now_ms >= e.cutoff_unix_ms {
                TrustEventKey::SuiteDeprecationCutoffHit
            } else {
                TrustEventKey::SuiteDeprecationPending
            },
            suite_id: e.suite_id,
            cutoff_unix_ms: e.cutoff_unix_ms,
            recommended_suite_id: e.recommended_suite_id,
        })
        .collect()
}

/// The trust-event key for an unreadable / unverifiable / missing server
/// deprecation policy (ISC-A-C9). The client falls back to its local registry
/// lifecycle and surfaces this persistent-non-blocking warning — it never
/// treats an unreadable policy as permission to downgrade a suite.
pub const fn unreadable_policy_event() -> TrustEventKey {
    TrustEventKey::ServerDeprecationPolicyUnreadable
}

// ── Encrypted persistence (ISC-C28 / ISC-C36 / finding F24) ───────────────

/// The audit-log path for a profile root: `<profile-root>/trust-events.log`.
pub fn audit_log_path(profile_root: &Path) -> PathBuf {
    profile_root.join(AUDIT_LOG_FILENAME)
}

/// Errors from [`seal_log`] / [`open_log`].
#[derive(Debug)]
pub enum AuditLogError {
    /// Argon2id stage failed (bad params).
    Argon2(argon2::Error),
    /// HKDF stage failed.
    Hkdf(oxicrypt_kdf::KdfError),
    /// AES-256 key init failed.
    AesKeyInit(oxicrypt_module::Error),
    /// AES-GCM mode error (non-auth).
    AesMode(oxicrypt_aes::ModeError),
    /// AEAD authentication failed — wrong passphrase or tampered file.
    AuthenticationFailed,
    /// Entropy source failed while generating the nonce.
    EntropySource(getrandom::Error),
    /// The file was structurally malformed.
    Malformed(&'static str),
}

impl core::fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuditLogError::Argon2(e) => write!(f, "argon2: {e}"),
            AuditLogError::Hkdf(e) => write!(f, "HKDF: {e:?}"),
            AuditLogError::AesKeyInit(e) => write!(f, "AES-256 key init: {e:?}"),
            AuditLogError::AesMode(e) => write!(f, "AES-GCM mode error: {e:?}"),
            AuditLogError::AuthenticationFailed => {
                write!(
                    f,
                    "audit-log authentication failed (wrong passphrase or tampering)"
                )
            }
            AuditLogError::EntropySource(e) => write!(f, "entropy source: {e}"),
            AuditLogError::Malformed(m) => write!(f, "malformed audit log: {m}"),
        }
    }
}

impl std::error::Error for AuditLogError {}

/// Magic prefix for the **v1** encrypted audit-log body: entries end at
/// `dismissed_at_unix_ms`, with no record-kind field.
///
/// Still read, never written. See [`BodyVersion`] for why the version had to
/// move here rather than being inferred.
const MAGIC_V1: &[u8] = b"DSTRUSTLOG1";

/// Magic prefix for the **v2** body: every entry carries a trailing optional
/// record-kind (ISC-C28). What [`seal_log`] writes.
const MAGIC_V2: &[u8] = b"DSTRUSTLOG2";

/// The magic [`seal_log`] writes.
const MAGIC: &[u8] = MAGIC_V2;

/// Which body layout a file's magic declares.
///
/// **This exists because the body is not self-describing and adding a field
/// could not be made backward-compatible without it.** The body is a bare
/// `u32` count followed by that many entries laid end to end: no per-entry
/// length, no field tags, no terminator. A reader therefore finds entry *n+1*
/// only by having consumed entry *n* to exactly the right byte. Appending an
/// optional field — presence byte and all — moves every subsequent entry, so a
/// v2 reader handed a v1 body reads the next entry's timestamp as this entry's
/// record-kind presence byte and desynchronises from there;
/// `a_v1_body_does_not_parse_as_v2` is the positive control for that claim.
///
/// Both magics are the same length, so the header layout, `HEADER_LEN` and the
/// AAD construction are untouched — and because the magic is inside the AAD,
/// the version is authenticated: a file downgraded from v2 to v1 by editing
/// eleven cleartext bytes fails the tag rather than decoding short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyVersion {
    /// No record-kind field; every decoded entry gets `record_kind: None`.
    V1,
    /// Trailing optional record-kind per entry.
    V2,
}

const PROFILE_ID_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + PROFILE_ID_LEN + 4 + 4 + 4; // + argon params

/// Encrypt a log into the on-disk layout. Key = the daemonseed two-stage KDF
/// (Argon2id with salt = profile-id, then HKDF-SHA-384 with info
/// `daemonseed/trust-events/<profile-id>`) — independent of the at-rest blob
/// and share-index keys (ISC-C28). AEAD = AES-256-GCM. The cleartext header
/// (magic + profile-id + argon params) is AAD so tampering fails the open.
pub fn seal_log(
    log: &TrustEventLog,
    passphrase: &str,
    profile_id: Uuid,
    argon2: ArgonParams,
) -> Result<Vec<u8>, AuditLogError> {
    let mut key = derive_audit_log_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(AuditLogError::AesKeyInit)?;
    key.zeroize();

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(AuditLogError::EntropySource)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(profile_id.as_bytes());
    header.extend_from_slice(&argon2.memory_kib.to_le_bytes());
    header.extend_from_slice(&argon2.iterations.to_le_bytes());
    header.extend_from_slice(&argon2.parallelism.to_le_bytes());

    let plaintext = encode_log(log);
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(&aes, &nonce, &header, &plaintext, &mut ciphertext, &mut tag)
        .map_err(AuditLogError::AesMode)?;

    let mut out = Vec::with_capacity(header.len() + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt an audit log written by [`seal_log`]. Reads the profile-id and
/// argon params from the cleartext header; the caller supplies only the file
/// bytes and the passphrase.
pub fn open_log(bytes: &[u8], passphrase: &str) -> Result<TrustEventLog, AuditLogError> {
    if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(AuditLogError::Malformed("shorter than minimum header"));
    }
    let version = match &bytes[..MAGIC_V2.len()] {
        m if m == MAGIC_V2 => BodyVersion::V2,
        m if m == MAGIC_V1 => BodyVersion::V1,
        _ => return Err(AuditLogError::Malformed("magic prefix mismatch")),
    };
    let mut cursor = MAGIC.len();
    let profile_id = Uuid::from_slice(&bytes[cursor..cursor + PROFILE_ID_LEN])
        .map_err(|_| AuditLogError::Malformed("bad profile-id"))?;
    cursor += PROFILE_ID_LEN;
    let memory_kib = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let iterations = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let parallelism = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let argon2 = ArgonParams {
        memory_kib,
        iterations,
        parallelism,
    };

    let header = &bytes[..cursor];
    let nonce: [u8; NONCE_LEN] = bytes[cursor..cursor + NONCE_LEN].try_into().unwrap();
    cursor += NONCE_LEN;
    let ciphertext_len = bytes.len() - cursor - TAG_LEN;
    let ciphertext = &bytes[cursor..cursor + ciphertext_len];
    let tag: [u8; TAG_LEN] = bytes[cursor + ciphertext_len..].try_into().unwrap();

    let mut key = derive_audit_log_key(passphrase, profile_id, argon2)?;
    let aes = Aes256Key::new(&key).map_err(AuditLogError::AesKeyInit)?;
    key.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, &nonce, header, ciphertext, &tag, &mut plaintext).map_err(|e| match e {
        oxicrypt_aes::ModeError::TagMismatch => AuditLogError::AuthenticationFailed,
        other => AuditLogError::AesMode(other),
    })?;

    let log = decode_log(&plaintext, version).ok_or(AuditLogError::Malformed("bad log body"))?;
    plaintext.zeroize();
    Ok(log)
}

/// Two-stage Argon2id + HKDF-SHA-384 key derivation for the audit log. Mirrors
/// the at-rest / recovery-file derivation but with the trust-events info string
/// (ISC-C28 / ISC-C36), so a compromise of one key does not implicate the others.
fn derive_audit_log_key(
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<[u8; AEAD_KEY_LEN], AuditLogError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::default(),
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(AuditLogError::Argon2)?,
    );
    let mut intermediate = [0u8; ARGON2_OUTPUT_LEN];
    let salt: [u8; 16] = *profile_id.as_bytes();
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut intermediate)
        .map_err(AuditLogError::Argon2)?;

    let info_str = info::trust_events(&profile_id.to_string());
    let hkdf = HkdfSha384::from_prk(&intermediate).map_err(AuditLogError::Hkdf)?;
    intermediate.zeroize();

    let mut key = [0u8; AEAD_KEY_LEN];
    hkdf.expand(info_str.as_bytes(), &mut key)
        .map_err(AuditLogError::Hkdf)?;
    Ok(key)
}

// ── Log body codec ────────────────────────────────────────────────────────
//
// Local-only encoding (never on the wire). Each event-key is stored by its
// stable string (ISC-C28), so a reordering of the enum cannot corrupt history;
// the record-kind uses `RecordKind::stable_str` for the same reason.
// Little-endian integers; optionals are a 1-byte presence flag + payload.
//
// The body carries no version of its own — it is versioned by the file's magic
// (see `BodyVersion`), which is inside the AAD and so authenticated.

fn encode_log(log: &TrustEventLog) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(log.entries.len() as u32).to_le_bytes());
    for e in &log.entries {
        out.extend_from_slice(&e.timestamp_unix_ms.to_le_bytes());
        let key_str = event_key_string(e.key).as_bytes();
        out.extend_from_slice(&(key_str.len() as u16).to_le_bytes());
        out.extend_from_slice(key_str);
        match &e.server_id {
            Some(s) => {
                out.push(1);
                out.extend_from_slice(&(s.len() as u16).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            None => out.push(0),
        }
        match e.suite_id {
            Some(s) => {
                out.push(1);
                out.extend_from_slice(&s.get().to_le_bytes());
            }
            None => out.push(0),
        }
        out.push(match e.resolution {
            ResolutionStatus::Unresolved => 0,
            ResolutionStatus::Resolved => 1,
        });
        match e.dismissed_at_unix_ms {
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.to_le_bytes());
            }
            None => out.push(0),
        }
        // v2 only. Last in the entry so a v1 body is a prefix of the v2 form
        // for its first entry — which is a readability property, not a
        // compatibility one: see `BodyVersion`.
        match e.record_kind {
            Some(k) => {
                out.push(1);
                let s = k.stable_str().as_bytes();
                out.extend_from_slice(&(s.len() as u16).to_le_bytes());
                out.extend_from_slice(s);
            }
            None => out.push(0),
        }
    }
    out
}

fn decode_log(bytes: &[u8], version: BodyVersion) -> Option<TrustEventLog> {
    let mut c = Cursor::new(bytes);
    let count = c.u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let timestamp_unix_ms = c.i64()?;
        let key_len = c.u16()? as usize;
        let key_str = c.bytes(key_len)?;
        let key = event_key_from_str(core::str::from_utf8(key_str).ok()?)?;
        let server_id = if c.u8()? == 1 {
            let len = c.u16()? as usize;
            Some(core::str::from_utf8(c.bytes(len)?).ok()?.to_owned())
        } else {
            None
        };
        let suite_id = if c.u8()? == 1 {
            Some(SuiteId::try_new(c.u16()?).ok()?)
        } else {
            None
        };
        let resolution = match c.u8()? {
            0 => ResolutionStatus::Unresolved,
            1 => ResolutionStatus::Resolved,
            _ => return None,
        };
        let dismissed_at_unix_ms = if c.u8()? == 1 { Some(c.i64()?) } else { None };
        let record_kind = match version {
            // A v1 entry ends here. Reading a presence byte would consume the
            // next entry's first timestamp byte.
            BodyVersion::V1 => None,
            // **Framing errors fail the body; vocabulary misses degrade the
            // field.** The presence byte and the length are structure — losing
            // either means the cursor no longer knows where the next entry
            // starts, and there is nothing to do but stop. The *string* is a
            // vocabulary token, and not recognising one is a normal
            // consequence of reading a log a newer build wrote: the version
            // tag covers layout growth, and adding a fifth `RecordKind` does
            // not move the layout, so a newer build keeps writing `MAGIC_V2`
            // and a rollback meets a kind this build has never heard of.
            //
            // Propagating that miss with `?` cost the reader **every entry in
            // the log** — one unopenable audit history because one event named
            // a kind. So the miss lands on this field alone; the entry, its
            // timestamp, its key and its class all survive, which is the state
            // this build would have recorded anyway before the field existed.
            //
            // Non-UTF-8 falls the same way rather than failing: the bytes are
            // AEAD-authenticated, so they are what some build of ours wrote,
            // and a writer bug is not a reason to destroy the reader's history.
            //
            // **The cost, stated rather than hidden:** a decode-then-reseal on
            // the older build writes the degraded `None` back, so the
            // discriminant is lost for good rather than merely unread. That is
            // the price of `RecordKind` staying closed, and it is the right
            // side of the trade — an `Unknown(String)` variant would put an
            // unbounded caller-unvalidated string into the one log ISC-A-C1
            // governs, and would force `file_name`, `capacity`, `bucket_len`,
            // `on_disk_len` and `is_sealed` to invent an answer for a kind that
            // has no record on disk.
            BodyVersion::V2 if c.u8()? == 1 => {
                let len = c.u16()? as usize;
                let raw = c.bytes(len)?;
                core::str::from_utf8(raw)
                    .ok()
                    .and_then(RecordKind::from_stable_str)
            }
            BodyVersion::V2 => None,
        };
        entries.push(TrustEvent {
            timestamp_unix_ms,
            key,
            server_id,
            suite_id,
            record_kind,
            resolution,
            dismissed_at_unix_ms,
        });
    }
    // The decoded log carries however many entries were persisted; cap is
    // re-applied by the caller's preference, defaulting to the standard bound.
    let cap = entries.len().max(DEFAULT_LOG_CAP);
    Some(TrustEventLog { entries, cap })
}

/// Minimal forward-only byte cursor for [`decode_log`]. Every read is
/// bounds-checked and returns `None` on underflow.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(raw: u16) -> SuiteId {
        SuiteId::try_new(raw).unwrap()
    }

    fn fast_params() -> ArgonParams {
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Every key maps to exactly one class, and the count matches the C28 table
    /// plus the two M7 additions (F31, F32), the three DM restart keys (#243) and
    /// the erasure-blocked key (#296 work, added with `Locked::delete`'s repair)
    /// = 22.
    ///
    /// **Adding a key touches SEVEN sites, and the two that bite are the two no
    /// grep for the key's name can reach.** Six of the seven name the key — the
    /// enum, `ALL_EVENT_KEYS`, `class_of`, the frozen string table,
    /// `a_dm_teardown_reaches_the_audit_log` and `class_assignments_match_c28_table`
    /// — so a name search finds them *once they are written*. This bare count is the
    /// seventh and names nothing, but the compiler fails on it, so it cannot be
    /// forgotten quietly.
    ///
    /// `class_assignments_match_c28_table` is the genuinely dangerous one. It
    /// hand-lists `class_of` assertions, so omitting a key leaves it **passing on a
    /// shorter list** — no compiler error, and a name grep run before writing it
    /// reports the site as simply not existing. It was missed when
    /// `DmRecordErasureBlocked` was added and found only by review.
    ///
    /// The durable lesson is not the number, which will go stale: **a hand-listed
    /// table is invisible to both the compiler and a name grep, so enumerate the
    /// class by reading the module rather than by trusting any list — including
    /// this one.**
    #[test]
    fn every_key_has_a_class() {
        assert_eq!(ALL_EVENT_KEYS.len(), 22);
        for &k in ALL_EVENT_KEYS {
            // `class_of` is total; this just exercises every arm.
            let _ = class_of(k);
        }
    }

    /// The class assignments match the ISC-C28 per-event table verbatim.
    #[test]
    fn class_assignments_match_c28_table() {
        use TrustEventClass::*;
        use TrustEventKey::*;
        assert_eq!(class_of(ServerKeyRotated), PersistentNonBlocking);
        assert_eq!(class_of(ServerKeyMismatch), Blocking);
        assert_eq!(class_of(SuiteDeprecationPending), PersistentNonBlocking);
        assert_eq!(class_of(SuiteDeprecationCutoffHit), Blocking);
        assert_eq!(class_of(CircleContentBelowMinSuite), Blocking);
        assert_eq!(class_of(CircleCrossFamilyDeprecated), PersistentNonBlocking);
        assert_eq!(class_of(NoCommonVersion), Blocking);
        assert_eq!(class_of(ConnectionRateLimited), Transient);
        assert_eq!(
            class_of(ConnectionRateLimitedExhausted),
            PersistentNonBlocking
        );
        assert_eq!(class_of(UpdateVerificationFailed), Blocking);
        assert_eq!(class_of(EmergencySecurityUpdateAvailable), Blocking);
        assert_eq!(class_of(UnsupportedIdentityProofSuite), Blocking);
        assert_eq!(
            class_of(ServerDeprecationPolicyUnreadable),
            PersistentNonBlocking
        );
        assert_eq!(class_of(ServerDeprecationPolicyRollback), Blocking);
        assert_eq!(class_of(UpdateRelayFallbackUsed), Transient);
        assert_eq!(
            class_of(ServerDeprecationPolicyExpiredOffline),
            PersistentNonBlocking
        );
        assert_eq!(class_of(FederationPeerKeyDivergence), PersistentNonBlocking);
        assert_eq!(class_of(ServerSourceUnverified), LogOnly);
        assert_eq!(class_of(DmChannelTornDownOnRestart), PersistentNonBlocking);
        assert_eq!(class_of(DmProvisionalHandshakeLost), PersistentNonBlocking);
        assert_eq!(
            class_of(DmProvisionalRecordUnreadable),
            PersistentNonBlocking
        );
        assert_eq!(class_of(DmRecordErasureBlocked), PersistentNonBlocking);
    }

    /// A teardown must reach the audit log, which is what makes it loud rather
    /// than merely returned (ISC-A-C12). `append` drops `Transient` events, so a
    /// key mis-classed as transient would leave a conversation ending with no
    /// record anywhere — the #243 failure mode wearing a different hat.
    #[test]
    fn a_dm_teardown_reaches_the_audit_log() {
        for key in [
            TrustEventKey::DmChannelTornDownOnRestart,
            TrustEventKey::DmProvisionalHandshakeLost,
            TrustEventKey::DmProvisionalRecordUnreadable,
            TrustEventKey::DmRecordErasureBlocked,
        ] {
            let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
            log.append(TrustEvent::observed(1_000, key, None, None));
            assert_eq!(
                log.entries().len(),
                1,
                "{} was dropped by the log",
                event_key_string(key)
            );
        }
    }

    /// Stable strings round-trip and are all distinct (no two keys collide).
    #[test]
    fn event_key_strings_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for &k in ALL_EVENT_KEYS {
            let s = event_key_string(k);
            assert!(seen.insert(s), "duplicate stable string: {s}");
            assert_eq!(event_key_from_str(s), Some(k));
        }
        assert_eq!(event_key_from_str("not-a-real-key"), None);
    }

    /// `append` records non-transient events and silently drops transient ones
    /// (ISC-A-C12 asymmetry).
    #[test]
    fn append_skips_transient_records_others() {
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(TrustEvent::observed(
            1,
            TrustEventKey::ConnectionRateLimited,
            None,
            None,
        ));
        assert_eq!(log.len(), 0, "transient must not be logged");
        log.append(TrustEvent::observed(
            2,
            TrustEventKey::SuiteDeprecationPending,
            Some("srv".into()),
            Some(sid(1)),
        ));
        assert_eq!(log.len(), 1);
        log.append(TrustEvent::observed(
            3,
            TrustEventKey::ServerSourceUnverified,
            None,
            None,
        ));
        assert_eq!(log.len(), 2, "log-only IS recorded");
    }

    /// `prune_to` keeps the newest entries and drops the oldest.
    #[test]
    fn prune_to_drops_oldest() {
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        for i in 0..5 {
            log.append(TrustEvent::observed(
                i,
                TrustEventKey::ServerKeyRotated,
                None,
                None,
            ));
        }
        log.prune_to(2);
        assert_eq!(log.len(), 2);
        assert_eq!(log.entries()[0].timestamp_unix_ms, 3);
        assert_eq!(log.entries()[1].timestamp_unix_ms, 4);
    }

    /// `append` honors the cap automatically (bounded log, ISC-C28).
    #[test]
    fn append_respects_cap() {
        let mut log = TrustEventLog::new(3);
        for i in 0..10 {
            log.append(TrustEvent::observed(
                i,
                TrustEventKey::ServerKeyRotated,
                None,
                None,
            ));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[0].timestamp_unix_ms, 7);
    }

    /// Dismissal is scoped to `(key, server_id, suite_id)` — dismissing one
    /// server's event does not touch another's (A-C12 no global dismissal), and
    /// the entry survives dismissal (the log records occurrence).
    #[test]
    fn dismiss_is_per_key_and_scope() {
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(TrustEvent::observed(
            1,
            TrustEventKey::ServerKeyRotated,
            Some("srv-a".into()),
            None,
        ));
        log.append(TrustEvent::observed(
            2,
            TrustEventKey::ServerKeyRotated,
            Some("srv-b".into()),
            None,
        ));

        log.dismiss(
            TrustEventKey::ServerKeyRotated,
            &DismissalScope {
                server_id: Some("srv-a".into()),
                suite_id: None,
            },
            100,
        );

        let a = &log.entries()[0];
        let b = &log.entries()[1];
        assert_eq!(a.dismissed_at_unix_ms, Some(100));
        assert_eq!(b.dismissed_at_unix_ms, None, "other server not dismissed");
        assert_eq!(log.len(), 2, "dismissal does not remove entries");
    }

    /// The audit log path is `<root>/trust-events.log` (F24).
    #[test]
    fn audit_log_path_is_profile_root_file() {
        let p = audit_log_path(Path::new("/profiles/alice"));
        assert_eq!(p, PathBuf::from("/profiles/alice/trust-events.log"));
    }

    /// A log round-trips through seal → open under the right passphrase.
    #[test]
    fn seal_then_open_round_trips() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([3u8; 16]);
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(TrustEvent::observed(
            1234,
            TrustEventKey::SuiteDeprecationCutoffHit,
            Some("srv-a".into()),
            Some(sid(1)),
        ));
        log.append(TrustEvent::observed(
            5678,
            TrustEventKey::ServerDeprecationPolicyRollback,
            None,
            None,
        ));

        let sealed = seal_log(
            &log,
            "correct horse battery staple",
            profile_id,
            fast_params(),
        )
        .unwrap();
        let opened = open_log(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(opened.entries(), log.entries());
    }

    /// The wrong passphrase fails authentication (does not silently return junk).
    #[test]
    fn open_rejects_wrong_passphrase() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([4u8; 16]);
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(TrustEvent::observed(
            1,
            TrustEventKey::ServerKeyMismatch,
            None,
            None,
        ));
        let sealed = seal_log(&log, "right-pass", profile_id, fast_params()).unwrap();
        let err = open_log(&sealed, "wrong-pass").unwrap_err();
        assert!(matches!(err, AuditLogError::AuthenticationFailed));
    }

    /// ISC-C25 / ISC-14 / ISC-27: a suite past its cutoff yields a blocking
    /// `SuiteDeprecationCutoffHit`; a suite before its cutoff yields a
    /// persistent-non-blocking `SuiteDeprecationPending`. Both carry the
    /// migration target.
    #[test]
    fn assess_deprecation_classifies_by_cutoff() {
        use crate::crypto::deprecation::{DeprecationEntry, DeprecationPolicy};
        let now = 1_000_000_000_000;
        let three_h = 3 * 3_600_000;
        let policy = DeprecationPolicy::build(
            1,
            now,
            vec![DeprecationEntry {
                suite_id: sid(1),
                cutoff_unix_ms: now + three_h,
                recommended_suite_id: sid(2),
            }],
            now,
        )
        .unwrap();

        // Before cutoff → pending (persistent-non-blocking).
        let pending = assess_deprecation(&policy, &[sid(1)], now);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].key, TrustEventKey::SuiteDeprecationPending);
        assert_eq!(
            class_of(pending[0].key),
            TrustEventClass::PersistentNonBlocking
        );
        assert_eq!(pending[0].recommended_suite_id, sid(2));

        // At/past cutoff → cutoff-hit (blocking).
        let hit = assess_deprecation(&policy, &[sid(1)], now + three_h);
        assert_eq!(hit[0].key, TrustEventKey::SuiteDeprecationCutoffHit);
        assert_eq!(class_of(hit[0].key), TrustEventClass::Blocking);

        // A suite the client does not use yields nothing.
        assert!(assess_deprecation(&policy, &[sid(2)], now).is_empty());
    }

    /// ISC-A-C9: an unreadable policy maps to the persistent-non-blocking
    /// fallback warning (and never to a downgrade — there is no such path).
    #[test]
    fn unreadable_policy_is_persistent_warning() {
        assert_eq!(
            unreadable_policy_event(),
            TrustEventKey::ServerDeprecationPolicyUnreadable
        );
        assert_eq!(
            class_of(unreadable_policy_event()),
            TrustEventClass::PersistentNonBlocking
        );
    }

    // ── Body codec: the record-kind field and the v1→v2 bridge ────────────

    /// The v2 body of the two-entry fixture below, byte for byte.
    ///
    /// **Derived independently of the encoder** — laid out from the format
    /// comment above `encode_log`, not captured from a run of it. That is the
    /// whole value: a round-trip test passes under any self-consistent layout,
    /// including one that swapped two adjacent optional fields, and the
    /// persisted log has no second implementation to disagree with it.
    const V2_BODY_KAT: &str = "020000007b68e5cf8b0100001900646d2d7265636f72642d6572617375\
72652d626c6f636b65640105007372762d610101000001ea16b04c02000000010b0070726f766973696f6e61\
6cffffffffffffffff13007365727665722d6b65792d6d69736d617463680000010000";

    /// The same two entries in the **v1** layout: identical up to each entry's
    /// `dismissed_at_unix_ms`, with no record-kind field at all. This is what a
    /// log written before this change holds.
    const V1_BODY_KAT: &str = "020000007b68e5cf8b0100001900646d2d7265636f72642d6572617375\
72652d626c6f636b65640105007372762d610101000001ea16b04c02000000ffffffffffffffff1300736572\
7665722d6b65792d6d69736d6174636800000100";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex must be whole bytes");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// The two entries both KATs describe. Built by hand rather than through
    /// `observed` so `resolution` and `dismissed_at_unix_ms` can be non-default.
    fn kat_entries() -> Vec<TrustEvent> {
        vec![
            TrustEvent {
                timestamp_unix_ms: 1_700_000_000_123,
                key: TrustEventKey::DmRecordErasureBlocked,
                server_id: Some("srv-a".into()),
                suite_id: Some(sid(1)),
                record_kind: Some(RecordKind::Provisional),
                resolution: ResolutionStatus::Unresolved,
                dismissed_at_unix_ms: Some(9_876_543_210),
            },
            TrustEvent {
                timestamp_unix_ms: -1,
                key: TrustEventKey::ServerKeyMismatch,
                server_id: None,
                suite_id: None,
                record_kind: None,
                resolution: ResolutionStatus::Resolved,
                dismissed_at_unix_ms: None,
            },
        ]
    }

    fn log_of(entries: Vec<TrustEvent>) -> TrustEventLog {
        TrustEventLog {
            entries,
            cap: DEFAULT_LOG_CAP,
        }
    }

    /// The v2 body encodes to exactly the pinned bytes.
    #[test]
    fn the_v2_body_encoding_is_byte_pinned() {
        let encoded = encode_log(&log_of(kat_entries()));
        assert_eq!(
            hex(&encoded),
            V2_BODY_KAT,
            "the persisted layout moved; a shipped log would no longer parse"
        );
        // And the bytes mean what they say, rather than merely being stable.
        let back = decode_log(&encoded, BodyVersion::V2).expect("the KAT decodes");
        assert_eq!(back.entries(), kat_entries().as_slice());
    }

    /// **The claim that an appended optional field is backward-compatible on
    /// its own is false, and this is the positive control for that.**
    ///
    /// The body is a count followed by entries laid end to end — no per-entry
    /// length, no field tags. A v2 reader handed a v1 body reads the next
    /// entry's first timestamp byte as this entry's record-kind presence byte
    /// and desynchronises. Here it desynchronises into a length it cannot
    /// satisfy and reports failure; nothing guarantees that, which is the
    /// point — a body that desynchronised into *plausible* fields would return
    /// wrong entries under an `Ok`. The version tag is what removes the
    /// question.
    #[test]
    fn a_v1_body_does_not_parse_as_v2() {
        let v1 = unhex(V1_BODY_KAT);
        // Control: the same bytes read correctly when read as what they are.
        assert!(
            decode_log(&v1, BodyVersion::V1).is_some(),
            "the v1 fixture must be a valid v1 body, or the case below is vacuous"
        );
        assert!(
            decode_log(&v1, BodyVersion::V2).is_none(),
            "a v1 body must not silently parse as v2"
        );
    }

    /// A v1 body decodes with `record_kind: None`, every other field intact.
    #[test]
    fn a_v1_body_decodes_with_no_record_kind() {
        let decoded = decode_log(&unhex(V1_BODY_KAT), BodyVersion::V1).expect("v1 decodes");
        let mut expected = kat_entries();
        expected[0].record_kind = None;
        assert_eq!(decoded.entries(), expected.as_slice());
        assert!(
            decoded.entries().iter().all(|e| e.record_kind.is_none()),
            "nothing in a v1 log can name a record kind"
        );
    }

    /// End to end: a **file** written by the pre-change build opens today.
    ///
    /// The header is rebuilt here with `MAGIC_V1` and the body from the v1 KAT,
    /// so this is a genuine old file rather than the new encoder with a field
    /// switched off. It exercises the half `decode_log` cannot: that `open_log`
    /// reads the version off the magic, and that the magic being inside the AAD
    /// does not stop a v1 file authenticating.
    #[test]
    fn a_v1_file_still_opens_after_the_version_bump() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([7u8; 16]);
        let params = fast_params();
        let sealed = seal_body_as_v1(&unhex(V1_BODY_KAT), "old-pass", profile_id, params);

        let opened = open_log(&sealed, "old-pass").expect("a v1 file must still open");
        let mut expected = kat_entries();
        expected[0].record_kind = None;
        assert_eq!(opened.entries(), expected.as_slice());
    }

    /// A v1 file whose magic is edited to v2 fails authentication rather than
    /// decoding short — the magic is AAD, so the version is authenticated.
    #[test]
    fn a_v1_file_relabelled_as_v2_fails_the_tag() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([8u8; 16]);
        let mut sealed =
            seal_body_as_v1(&unhex(V1_BODY_KAT), "old-pass", profile_id, fast_params());
        sealed[..MAGIC_V2.len()].copy_from_slice(MAGIC_V2);
        assert!(matches!(
            open_log(&sealed, "old-pass"),
            Err(AuditLogError::AuthenticationFailed)
        ));
    }

    /// The other direction of the same guarantee: a **v2** file relabelled as
    /// v1 also fails the tag. The lens that reviewed this noticed the pair was
    /// only pinned one way — a version tag inside the AAD is worth nothing if
    /// it authenticates only the downgrade.
    #[test]
    fn a_v2_file_relabelled_as_v1_fails_the_tag() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([10u8; 16]);
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(
            TrustEventScope::for_record(
                TrustEventKey::DmRecordErasureBlocked,
                RecordKind::Provisional,
            )
            .observed_at(1, None, None),
        );
        let mut sealed = seal_log(&log, "pass", profile_id, fast_params()).unwrap();
        assert!(open_log(&sealed, "pass").is_ok(), "control");
        sealed[..MAGIC_V1.len()].copy_from_slice(MAGIC_V1);
        assert!(matches!(
            open_log(&sealed, "pass"),
            Err(AuditLogError::AuthenticationFailed)
        ));
    }

    /// Seal a pre-supplied body under the **v1** magic, reproducing what the
    /// pre-change `seal_log` wrote. Mirrors `seal_log` exactly but for the
    /// magic and for taking the body rather than encoding one.
    fn seal_body_as_v1(
        body: &[u8],
        passphrase: &str,
        profile_id: Uuid,
        argon2: ArgonParams,
    ) -> Vec<u8> {
        let mut key = derive_audit_log_key(passphrase, profile_id, argon2).unwrap();
        let aes = Aes256Key::new(&key).unwrap();
        key.zeroize();
        let nonce = [0x5Au8; NONCE_LEN];

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC_V1);
        header.extend_from_slice(profile_id.as_bytes());
        header.extend_from_slice(&argon2.memory_kib.to_le_bytes());
        header.extend_from_slice(&argon2.iterations.to_le_bytes());
        header.extend_from_slice(&argon2.parallelism.to_le_bytes());

        let mut ciphertext = vec![0u8; body.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, &header, body, &mut ciphertext, &mut tag).unwrap();

        let mut out = header;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        out
    }

    /// A record kind survives a full seal → open.
    #[test]
    fn a_record_kind_round_trips_through_seal_and_open() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([9u8; 16]);
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        for kind in RecordKind::ALL {
            log.append(
                TrustEventScope::for_record(TrustEventKey::DmRecordErasureBlocked, kind)
                    .observed_at(1_000, None, None),
            );
        }
        let sealed = seal_log(&log, "pass", profile_id, fast_params()).unwrap();
        let opened = open_log(&sealed, "pass").unwrap();
        assert_eq!(
            opened
                .entries()
                .iter()
                .map(|e| e.record_kind)
                .collect::<Vec<_>>(),
            RecordKind::ALL.map(Some).to_vec(),
            "each kind must come back as itself, in order"
        );
    }

    /// **Every key but the erasure one encodes no record kind.**
    ///
    /// `observed` is the only constructor the other twenty-one keys use and it
    /// cannot set one, so this is a guard against a future careless `Some`
    /// reaching the log — and against the field being populated by default,
    /// which the round-trip tests above would not notice.
    #[test]
    fn every_other_key_encodes_no_record_kind() {
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        let mut logged = 0usize;
        for &key in ALL_EVENT_KEYS {
            let before = log.len();
            log.append(TrustEvent::observed(
                1,
                key,
                Some("srv".into()),
                Some(sid(1)),
            ));
            logged += log.len() - before;
        }
        assert!(
            logged >= ALL_EVENT_KEYS.len() - 4,
            "the fixture must actually log most keys, or this is near-vacuous: {logged}"
        );
        assert_eq!(log.len(), logged, "cap must not have pruned the fixture");
        assert!(
            log.entries().iter().all(|e| e.record_kind.is_none()),
            "only a raise site with a kind may set one"
        );

        // And it is absent from the bytes, not merely from the struct: every
        // entry's trailing presence byte reads 0.
        let body = encode_log(&log);
        let decoded = decode_log(&body, BodyVersion::V2).expect("round-trips");
        assert_eq!(decoded.len(), logged);
        assert!(decoded.entries().iter().all(|e| e.record_kind.is_none()));
        assert_eq!(
            *body.last().unwrap(),
            0,
            "the last entry's record-kind presence byte must be absent-0"
        );
    }

    /// Replace the first occurrence of `needle` in `hay`; panics if absent, so
    /// a fixture that stopped substituting cannot pass as one that did.
    fn substitute(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
        let at = hay
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the fixture must contain the token it substitutes");
        assert!(
            !hay[at + needle.len()..]
                .windows(needle.len())
                .any(|w| w == needle),
            "the token must occur exactly once, or the substitution is ambiguous"
        );
        let mut out = hay[..at].to_vec();
        out.extend_from_slice(with);
        out.extend_from_slice(&hay[at + needle.len()..]);
        out
    }

    /// A three-entry log whose middle entry names a record kind.
    fn three_entries_with_a_kind_in_the_middle() -> TrustEventLog {
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(TrustEvent::observed(
            1,
            TrustEventKey::ServerKeyMismatch,
            Some("srv-a".into()),
            None,
        ));
        log.append(
            TrustEventScope::for_record(
                TrustEventKey::DmRecordErasureBlocked,
                RecordKind::Provisional,
            )
            .observed_at(2, None, Some(sid(1))),
        );
        log.append(TrustEvent::observed(
            3,
            TrustEventKey::ServerKeyRotated,
            None,
            None,
        ));
        log
    }

    /// **An unrecognised record kind costs the FIELD, never the log.**
    ///
    /// A fifth `RecordKind` would not move the layout, so a newer build keeps
    /// writing `MAGIC_V2` and the version tag — the mechanism built for format
    /// evolution — never fires for *vocabulary* growth. Before this, a user who
    /// rolled a build back after one blocked erasure had their entire
    /// trust-event history refuse to open.
    #[test]
    fn an_unknown_record_kind_costs_the_field_and_not_the_log() {
        let body = encode_log(&three_entries_with_a_kind_in_the_middle());

        // Control: unsubstituted, all three entries decode and the middle one
        // still names its kind. Without this the case below is vacuous — a
        // decoder that always returned three `None`s would satisfy it.
        let control = decode_log(&body, BodyVersion::V2).expect("the fixture decodes");
        assert_eq!(control.len(), 3);
        assert_eq!(
            control
                .entries()
                .iter()
                .map(|e| e.record_kind)
                .collect::<Vec<_>>(),
            vec![None, Some(RecordKind::Provisional), None]
        );

        // Same length, so nothing about the framing moves — only the token.
        let unknown = substitute(&body, b"provisional", b"prov1s1onal");
        assert_eq!(unknown.len(), body.len(), "the framing must be untouched");
        let decoded = decode_log(&unknown, BodyVersion::V2)
            .expect("an unknown kind must not destroy the log");
        assert_eq!(decoded.len(), 3, "every entry must survive");
        assert!(
            decoded.entries().iter().all(|e| e.record_kind.is_none()),
            "the unknown kind degrades to absent"
        );
        // The rest of the entry survives with it — not just the count.
        assert_eq!(
            decoded
                .entries()
                .iter()
                .map(|e| (e.timestamp_unix_ms, e.key, e.suite_id))
                .collect::<Vec<_>>(),
            control
                .entries()
                .iter()
                .map(|e| (e.timestamp_unix_ms, e.key, e.suite_id))
                .collect::<Vec<_>>(),
            "only the record-kind field may differ"
        );
    }

    /// The same degradation for a kind of a *different* length, and for one
    /// that is not UTF-8 at all — the string is vocabulary either way.
    #[test]
    fn an_unknown_kind_degrades_whatever_its_bytes() {
        let body = encode_log(&three_entries_with_a_kind_in_the_middle());
        // Length-prefixed, so a longer token needs its `u16` corrected too.
        let longer = substitute(
            &body,
            &[11u8, 0][..]
                .iter()
                .copied()
                .chain(*b"provisional")
                .collect::<Vec<_>>(),
            &[15u8, 0][..]
                .iter()
                .copied()
                .chain(*b"quantum-lockbox")
                .collect::<Vec<_>>(),
        );
        for (label, bytes) in [
            ("a longer unknown token", longer),
            (
                "a non-UTF-8 token",
                substitute(&body, b"provisional", b"prov\xffs\xfeonal"),
            ),
        ] {
            let decoded = decode_log(&bytes, BodyVersion::V2)
                .unwrap_or_else(|| panic!("{label} lost the log"));
            assert_eq!(decoded.len(), 3, "{label} must leave every entry readable");
            assert!(decoded.entries().iter().all(|e| e.record_kind.is_none()));
        }
    }

    /// **The mirror control: framing damage still fails the body.**
    ///
    /// Degrading a vocabulary miss must not turn the decoder into one that
    /// tolerates a cursor it has lost track of. A record-kind length longer
    /// than the bytes that remain is not a kind this build does not know — it
    /// means the next entry cannot be found.
    #[test]
    fn a_lying_record_kind_length_still_fails_the_body() {
        let body = encode_log(&three_entries_with_a_kind_in_the_middle());
        assert!(decode_log(&body, BodyVersion::V2).is_some(), "control");
        let lying = substitute(
            &body,
            &[11u8, 0][..]
                .iter()
                .copied()
                .chain(*b"provisional")
                .collect::<Vec<_>>(),
            &[0xffu8, 0xff][..]
                .iter()
                .copied()
                .chain(*b"provisional")
                .collect::<Vec<_>>(),
        );
        assert!(
            decode_log(&lying, BodyVersion::V2).is_none(),
            "a length past the end of the body is corruption, not vocabulary"
        );
    }

    /// **Every truncation of a body is refused, none is decoded short.**
    ///
    /// The mirror control for the degradation above, and it had to be this
    /// rather than a single lying length: making the record-kind read
    /// non-structural (`c.bytes(len).unwrap_or(b"")`) still *failed* on a lying
    /// length inside a three-entry body, because the desynchronised cursor ran
    /// into trouble further down and the test could not tell the two apart.
    /// A one-entry body truncated at the record-kind field is where the
    /// difference is visible: the loop ends, and a decoder that shrugged at the
    /// short read returns an entry it never finished reading.
    #[test]
    fn no_truncation_of_a_body_decodes_short() {
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(
            TrustEventScope::for_record(
                TrustEventKey::DmRecordErasureBlocked,
                RecordKind::Provisional,
            )
            .observed_at(2, Some("srv-a".into()), Some(sid(1))),
        );
        let body = encode_log(&log);
        assert!(
            decode_log(&body, BodyVersion::V2).is_some(),
            "the whole body must decode, or the sweep below is vacuous"
        );
        assert!(body.len() > 40, "the sweep must have real prefixes to try");
        for cut in 0..body.len() {
            assert!(
                decode_log(&body[..cut], BodyVersion::V2).is_none(),
                "a body cut at {cut} of {} decoded short",
                body.len()
            );
        }
    }

    /// The scope pairing: `bare` cannot set a kind, `for_record` always does,
    /// and `observed` is `bare`.
    #[test]
    fn a_bare_scope_never_acquires_a_record_kind() {
        assert_eq!(
            TrustEventScope::bare(TrustEventKey::ServerKeyMismatch).record_kind,
            None
        );
        assert_eq!(
            TrustEvent::observed(1, TrustEventKey::ServerKeyMismatch, None, None).record_kind,
            None
        );
        for kind in RecordKind::ALL {
            assert_eq!(
                TrustEventScope::for_record(TrustEventKey::DmRecordErasureBlocked, kind)
                    .observed_at(1, None, None)
                    .record_kind,
                Some(kind)
            );
        }
    }

    /// ISC-C28 / ISC-A-C1: the discriminant is closed and carries no payload,
    /// so a log full of them cannot become a recently-contacted set.
    ///
    /// **The `Debug` check is the redaction half.** `TrustEvent` derives
    /// `Debug`, so whatever a future `RecordKind` variant carried would be
    /// rendered wherever an event is. Today each variant renders as its bare
    /// name; a variant gaining a field — a path, a label, a correspondent —
    /// would render as `Name(..)` and fail here, which is the point at which
    /// that redaction question has to be answered rather than inherited.
    #[test]
    fn a_record_kind_names_a_type_and_never_an_instance() {
        for kind in RecordKind::ALL {
            let rendered = format!("{kind:?}");
            assert!(
                rendered.chars().all(|c| c.is_ascii_alphabetic()),
                "a kind must render as a bare variant name, with no payload: {rendered}"
            );
            let event = TrustEventScope::for_record(TrustEventKey::DmRecordErasureBlocked, kind)
                .observed_at(1, None, None);
            let debug = format!("{event:?}");
            assert!(
                debug.contains(&rendered),
                "the kind must be visible in the event's Debug: {debug}"
            );
        }
    }

    /// Tampering with the ciphertext fails authentication (AAD + AEAD).
    #[test]
    fn open_rejects_tampered_bytes() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let profile_id = Uuid::from_bytes([5u8; 16]);
        let mut log = TrustEventLog::new(DEFAULT_LOG_CAP);
        log.append(TrustEvent::observed(
            1,
            TrustEventKey::ServerKeyMismatch,
            None,
            None,
        ));
        let mut sealed = seal_log(&log, "pass", profile_id, fast_params()).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open_log(&sealed, "pass").is_err());
    }
}
