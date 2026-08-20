//! Suite-deprecation policy — ISC-S16 / ISC-A-S11 / ISC-C25 / finding F30 (M7).
//!
//! A server operator declares per-suite **deprecation cutoffs**: peers may keep
//! signing identity-proofs under a suite until its cutoff, after which the
//! server refuses them (ISC-S16). The policy is published through the M6
//! public-space serving path as a [`wire::SignedArtifact`] whose inner payload
//! is a [`wire::DeprecationPolicyPayload`], signed under the **server-wide key**
//! (ISC-A-S11). Clients fetch it on connect, verify the signature against the
//! pinned server key, replay-protect on the monotonic `policy_version`, and
//! surface warnings (ISC-C25).
//!
//! ## Where the explicit cutoff reason comes from (design note)
//!
//! ISC-S16 speaks of the server refusing with an explicit
//! `SUITE_DEPRECATED_PAST_CUTOFF { suite_id, cutoff, recommended_suite_id }`.
//! The M4b identity-proof exchange is a simultaneous envelope swap that ends
//! with the client opening gRPC-over-h2, and every proof failure is a
//! deliberately **uniform silent close** (ISC-40 / A-S12 / A-C18, anti-oracle).
//! Rather than break that invariant with a bespoke reject frame, the server
//! enforces the cutoff with the same uniform close, and the **client derives**
//! the actionable reason from the signed policy it already holds — every field
//! the reject would carry ([`DeprecationEntry`]) is in the policy. See
//! [`DeprecationPolicy::is_past_cutoff`] and [`DeprecationPolicy::entry_for`].
//!
//! ## F30 — warn-before-cutoff guarantee
//!
//! Clients cache the policy for [`CACHE_TTL`] (ISC-C25, one hour). To guarantee
//! a client refreshes and sees a cutoff *before* it hits, the server refuses to
//! sign a policy whose cutoff is less than [`MIN_CUTOFF_LEAD`] (2x the cache
//! TTL) into the future ([`DeprecationPolicy::build`]). This is a server-side
//! construction invariant; clients honor whatever they are served and do not
//! re-check the lead time.

use std::collections::HashMap;
use std::time::Duration;

use daemonseed_proto::v1 as wire;
use oxicrypt_ml_dsa as ml_dsa;
use prost::Message;

use crate::crypto::suite::{SuiteId, SuiteIdError};
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};

/// Client policy cache TTL (ISC-C25). One hour.
pub const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Minimum lead time between signing and a cutoff (finding F30): twice the
/// cache TTL, so a client refreshing within one TTL window always sees a cutoff
/// at least one TTL before it hits — warn-before-cutoff is guaranteed.
pub const MIN_CUTOFF_LEAD: Duration = Duration::from_secs(2 * 3600);

/// One operator-declared suite-deprecation cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeprecationEntry {
    /// The suite being retired.
    pub suite_id: SuiteId,
    /// UTC wall-clock milliseconds at/after which the suite is refused.
    pub cutoff_unix_ms: i64,
    /// Operator-recommended successor suite (surfaced in the migration prompt).
    pub recommended_suite_id: SuiteId,
}

/// A validated, decoded deprecation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationPolicy {
    policy_version: u64,
    signed_timestamp_ms: i64,
    entries: Vec<DeprecationEntry>,
}

/// Why a deprecation policy was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The signed payload did not decode as a `DeprecationPolicyPayload`, or a
    /// numeric field was out of range.
    Decode,
    /// A `suite_id` in the policy was a reserved sentinel.
    SuiteId(SuiteIdError),
    /// Server-side construction (F30): a cutoff is sooner than [`MIN_CUTOFF_LEAD`].
    CutoffTooSoon {
        /// The offending suite.
        suite_id: SuiteId,
        /// Milliseconds of lead time the cutoff actually had (may be negative).
        lead_ms: i64,
    },
    /// The artifact's signer key did not equal the pinned server-wide key, or
    /// the ML-DSA-87 signature did not verify. Uniform — sub-cause is opaque.
    Signature,
    /// The offered policy version is below the client's cached version for this
    /// server (ISC-A-S11 rollback / replay protection).
    VersionRollback {
        /// Highest version the client has already accepted for this server.
        cached: u64,
        /// Version the server just offered.
        offered: u64,
    },
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyError::Decode => write!(f, "deprecation policy failed to decode"),
            PolicyError::SuiteId(e) => write!(f, "deprecation policy suite id: {e}"),
            PolicyError::CutoffTooSoon { suite_id, lead_ms } => write!(
                f,
                "cutoff for suite {suite_id} is only {lead_ms} ms out; \
                 minimum lead is {} ms (F30)",
                MIN_CUTOFF_LEAD.as_millis()
            ),
            PolicyError::Signature => write!(f, "deprecation policy signature did not verify"),
            PolicyError::VersionRollback { cached, offered } => write!(
                f,
                "deprecation policy rollback: offered version {offered} < cached {cached}"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl DeprecationPolicy {
    /// Server-side construction. Validates F30 lead time for every entry
    /// against `now_ms` (signing time). Returns [`PolicyError::CutoffTooSoon`]
    /// for the first entry whose cutoff is sooner than [`MIN_CUTOFF_LEAD`].
    pub fn build(
        policy_version: u64,
        signed_timestamp_ms: i64,
        entries: Vec<DeprecationEntry>,
        now_ms: i64,
    ) -> Result<Self, PolicyError> {
        let min_lead = MIN_CUTOFF_LEAD.as_millis() as i64;
        for e in &entries {
            // Saturating: a pathological operator-config cutoff (e.g. i64::MIN)
            // must fail the F30 guard cleanly, never panic or wrap to a bogus
            // positive lead.
            let lead = e.cutoff_unix_ms.saturating_sub(now_ms);
            if lead < min_lead {
                return Err(PolicyError::CutoffTooSoon {
                    suite_id: e.suite_id,
                    lead_ms: lead,
                });
            }
        }
        Ok(Self {
            policy_version,
            signed_timestamp_ms,
            entries,
        })
    }

    /// Monotonic policy version (ISC-A-S11 rollback anchor).
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Signing-time wall-clock milliseconds (freshness; not the rollback anchor).
    pub fn signed_timestamp_ms(&self) -> i64 {
        self.signed_timestamp_ms
    }

    /// The declared cutoffs.
    pub fn entries(&self) -> &[DeprecationEntry] {
        &self.entries
    }

    /// Canonical signed payload — the prost encoding of the wire payload. The
    /// ML-DSA-87 signature is computed over exactly these bytes (the same
    /// signed-payload-is-authoritative contract as posts / MOTD).
    pub fn to_signed_payload(&self) -> Vec<u8> {
        let payload = wire::DeprecationPolicyPayload {
            policy_version: self.policy_version,
            signed_timestamp_ms: self.signed_timestamp_ms,
            entries: self
                .entries
                .iter()
                .map(|e| wire::SuiteDeprecationEntry {
                    suite_id: u32::from(e.suite_id.get()),
                    cutoff_unix_ms: e.cutoff_unix_ms,
                    recommended_suite_id: u32::from(e.recommended_suite_id.get()),
                })
                .collect(),
        };
        payload.encode_to_vec()
    }

    /// Client-side decode from a signed payload. Validates that every suite id
    /// is in range; does **not** re-check F30 (clients honor what they are
    /// served).
    pub fn from_signed_payload(bytes: &[u8]) -> Result<Self, PolicyError> {
        let payload =
            wire::DeprecationPolicyPayload::decode(bytes).map_err(|_| PolicyError::Decode)?;
        let mut entries = Vec::with_capacity(payload.entries.len());
        for e in payload.entries {
            entries.push(DeprecationEntry {
                suite_id: decode_suite_id(e.suite_id)?,
                cutoff_unix_ms: e.cutoff_unix_ms,
                recommended_suite_id: decode_suite_id(e.recommended_suite_id)?,
            });
        }
        Ok(Self {
            policy_version: payload.policy_version,
            signed_timestamp_ms: payload.signed_timestamp_ms,
            entries,
        })
    }

    /// The cutoff entry for `suite_id`, if the policy names it.
    pub fn entry_for(&self, suite_id: SuiteId) -> Option<&DeprecationEntry> {
        self.entries.iter().find(|e| e.suite_id == suite_id)
    }

    /// Whether `suite_id` is at or past its cutoff as of `now_ms`. A suite the
    /// policy does not name is never past cutoff.
    pub fn is_past_cutoff(&self, suite_id: SuiteId, now_ms: i64) -> bool {
        self.entry_for(suite_id)
            .is_some_and(|e| now_ms >= e.cutoff_unix_ms)
    }

    /// Entries whose suite intersects the client's in-use suite set
    /// (default-write, identity material, joined circles) — ISC-C25 affected-
    /// suite detection.
    pub fn affected<'a>(&'a self, in_use: &[SuiteId]) -> Vec<&'a DeprecationEntry> {
        self.entries
            .iter()
            .filter(|e| in_use.contains(&e.suite_id))
            .collect()
    }
}

fn decode_suite_id(raw: u32) -> Result<SuiteId, PolicyError> {
    let narrowed = u16::try_from(raw).map_err(|_| PolicyError::Decode)?;
    SuiteId::try_new(narrowed).map_err(PolicyError::SuiteId)
}

/// Sign a policy under the server-wide key, producing the [`wire::SignedArtifact`]
/// the public-space service serves (ISC-A-S11). The signer pubkey carried in
/// the artifact is the server-wide key clients pin against.
pub fn sign_policy(
    policy: &DeprecationPolicy,
    signer: &SignKeypair,
) -> Result<wire::SignedArtifact, SignatureError> {
    let signed_payload = policy.to_signed_payload();
    let signature = signer.sign(&signed_payload)?;
    Ok(wire::SignedArtifact {
        signed_payload,
        signer_pubkey: signer.public_key().to_vec(),
        signature: signature.to_vec(),
    })
}

/// Verify and decode a fetched policy (ISC-C25). Three checks, fail-closed:
///
/// 1. The artifact's signer key equals the pinned server-wide key (ISC-A-S11 —
///    the policy MUST be signed under the server-wide key, not any whitelisted
///    post signer).
/// 2. The ML-DSA-87 signature verifies over the signed payload.
/// 3. If the client has a cached version for this server, the offered version
///    is not below it (rollback protection).
pub fn verify_policy(
    artifact: &wire::SignedArtifact,
    server_wide_pubkey: &[u8; ml_dsa::PK_LEN],
    cached_version: Option<u64>,
) -> Result<DeprecationPolicy, PolicyError> {
    if artifact.signer_pubkey.as_slice() != server_wide_pubkey.as_slice() {
        return Err(PolicyError::Signature);
    }
    let signature: &[u8; ml_dsa::SIG_LEN] = artifact
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PolicyError::Signature)?;
    verify_signature(server_wide_pubkey, &artifact.signed_payload, signature)
        .map_err(|_| PolicyError::Signature)?;

    let policy = DeprecationPolicy::from_signed_payload(&artifact.signed_payload)?;
    if let Some(cached) = cached_version
        && policy.policy_version < cached
    {
        return Err(PolicyError::VersionRollback {
            cached,
            offered: policy.policy_version,
        });
    }
    Ok(policy)
}

/// Client-side per-server policy cache (ISC-C25 / A-C9). Keyed by server-id
/// string. Tracks the fetch time so callers can enforce the [`CACHE_TTL`] and
/// refuse to treat a stale entry as authoritative (no offline-mode acceptance).
#[derive(Debug, Default)]
pub struct PolicyCache {
    by_server: HashMap<String, CachedPolicy>,
}

#[derive(Debug, Clone)]
struct CachedPolicy {
    policy: DeprecationPolicy,
    fetched_at_ms: i64,
}

impl PolicyCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the cached policy for `server_id`, recording the fetch
    /// time. The caller is expected to have already run [`verify_policy`]
    /// (signature + rollback) before inserting.
    pub fn insert(&mut self, server_id: &str, policy: DeprecationPolicy, fetched_at_ms: i64) {
        self.by_server.insert(
            server_id.to_owned(),
            CachedPolicy {
                policy,
                fetched_at_ms,
            },
        );
    }

    /// The highest accepted policy version for `server_id`, for replay
    /// protection on the next fetch (ISC-C25).
    pub fn cached_version(&self, server_id: &str) -> Option<u64> {
        self.by_server
            .get(server_id)
            .map(|c| c.policy.policy_version)
    }

    /// The cached policy for `server_id` only if it is still within
    /// [`CACHE_TTL`] of `now_ms`. A past-TTL entry returns `None` — the caller
    /// MUST refetch on connect (ISC-A-C9: no offline acceptance of stale
    /// policies).
    pub fn fresh<'a>(&'a self, server_id: &str, now_ms: i64) -> Option<&'a DeprecationPolicy> {
        self.by_server.get(server_id).and_then(|c| {
            if now_ms.saturating_sub(c.fetched_at_ms) <= CACHE_TTL.as_millis() as i64 {
                Some(&c.policy)
            } else {
                None
            }
        })
    }

    /// Whether the cached entry for `server_id` is past its TTL (or absent).
    /// `true` means a fresh fetch is required before the policy is authoritative.
    pub fn is_stale(&self, server_id: &str, now_ms: i64) -> bool {
        self.fresh(server_id, now_ms).is_none()
    }

    /// The earliest cutoff across **all** cached servers for `suite_id`
    /// (ISC-C25 cross-server caution — the user must be ready for the strictest
    /// deadline they actually face). `None` if no cached server deprecates it.
    pub fn earliest_cutoff(&self, suite_id: SuiteId) -> Option<i64> {
        self.by_server
            .values()
            .filter_map(|c| c.policy.entry_for(suite_id).map(|e| e.cutoff_unix_ms))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::CNSA_2_0;

    fn sid(raw: u16) -> SuiteId {
        SuiteId::try_new(raw).unwrap()
    }

    /// A second registered-shape suite id for "recommended successor" use in
    /// tests. Its presence in the registry is irrelevant to policy logic — the
    /// policy only carries ids, it does not resolve them.
    fn successor() -> SuiteId {
        sid(0x0002)
    }

    fn deprecated() -> SuiteId {
        CNSA_2_0.id
    }

    const HOUR_MS: i64 = 3_600_000;

    fn keypair() -> SignKeypair {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[7u8; 32]).unwrap()
    }

    /// F30: a cutoff at least 2x the cache TTL out is accepted.
    #[test]
    fn build_accepts_cutoff_with_sufficient_lead() {
        let now = 1_000_000_000_000;
        let entries = vec![DeprecationEntry {
            suite_id: deprecated(),
            cutoff_unix_ms: now + 3 * HOUR_MS,
            recommended_suite_id: successor(),
        }];
        let policy = DeprecationPolicy::build(1, now, entries, now).unwrap();
        assert_eq!(policy.policy_version(), 1);
        assert_eq!(policy.entries().len(), 1);
    }

    /// F30: a cutoff sooner than 2x the cache TTL is refused at construction.
    #[test]
    fn build_refuses_cutoff_too_soon() {
        let now = 1_000_000_000_000;
        let entries = vec![DeprecationEntry {
            suite_id: deprecated(),
            cutoff_unix_ms: now + HOUR_MS, // only 1h out; min lead is 2h
            recommended_suite_id: successor(),
        }];
        let err = DeprecationPolicy::build(1, now, entries, now).unwrap_err();
        assert!(matches!(err, PolicyError::CutoffTooSoon { .. }));
    }

    /// F30: a cutoff already in the past is refused (negative lead).
    #[test]
    fn build_refuses_past_cutoff() {
        let now = 1_000_000_000_000;
        let entries = vec![DeprecationEntry {
            suite_id: deprecated(),
            cutoff_unix_ms: now - HOUR_MS,
            recommended_suite_id: successor(),
        }];
        let err = DeprecationPolicy::build(1, now, entries, now).unwrap_err();
        match err {
            PolicyError::CutoffTooSoon { lead_ms, .. } => assert!(lead_ms < 0),
            other => panic!("expected CutoffTooSoon, got {other:?}"),
        }
    }

    /// F30 guard must not panic or wrap on a pathological extreme cutoff —
    /// `i64::MIN` saturates to a hugely-negative lead and is refused cleanly.
    #[test]
    fn build_handles_extreme_cutoff_without_overflow() {
        let now = 1_000_000_000_000;
        let entries = vec![DeprecationEntry {
            suite_id: deprecated(),
            cutoff_unix_ms: i64::MIN,
            recommended_suite_id: successor(),
        }];
        let err = DeprecationPolicy::build(1, now, entries, now).unwrap_err();
        assert!(matches!(err, PolicyError::CutoffTooSoon { .. }));
    }

    /// A signed policy round-trips through sign → verify → decode.
    #[test]
    fn sign_then_verify_round_trips() {
        let kp = keypair();
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(
            5,
            now,
            vec![DeprecationEntry {
                suite_id: deprecated(),
                cutoff_unix_ms: now + 3 * HOUR_MS,
                recommended_suite_id: successor(),
            }],
            now,
        )
        .unwrap();

        let artifact = sign_policy(&policy, &kp).unwrap();
        let verified = verify_policy(&artifact, kp.public_key(), None).unwrap();
        assert_eq!(verified, policy);
        assert_eq!(verified.policy_version(), 5);
    }

    /// Verification fails when the artifact is signed by a key other than the
    /// pinned server-wide key (ISC-A-S11: policy MUST be server-wide-signed).
    #[test]
    fn verify_rejects_wrong_signer() {
        let kp = keypair();
        let other = SignKeypair::from_ml_dsa_seed(&[9u8; 32]).unwrap();
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(1, now, vec![], now).unwrap();
        let artifact = sign_policy(&policy, &kp).unwrap();
        // Pinned key is `other`, but the artifact was signed by `kp`.
        let err = verify_policy(&artifact, other.public_key(), None).unwrap_err();
        assert_eq!(err, PolicyError::Signature);
    }

    /// Verification fails when the signed payload is tampered after signing.
    #[test]
    fn verify_rejects_tampered_payload() {
        let kp = keypair();
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(1, now, vec![], now).unwrap();
        let mut artifact = sign_policy(&policy, &kp).unwrap();
        artifact.signed_payload.push(0xFF);
        let err = verify_policy(&artifact, kp.public_key(), None).unwrap_err();
        assert_eq!(err, PolicyError::Signature);
    }

    /// Rollback protection: a version below the cached value is refused (A-S11).
    #[test]
    fn verify_rejects_version_rollback() {
        let kp = keypair();
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(3, now, vec![], now).unwrap();
        let artifact = sign_policy(&policy, &kp).unwrap();
        let err = verify_policy(&artifact, kp.public_key(), Some(7)).unwrap_err();
        assert_eq!(
            err,
            PolicyError::VersionRollback {
                cached: 7,
                offered: 3
            }
        );
    }

    /// An equal-or-higher version than cached is accepted (monotonic, not strict).
    #[test]
    fn verify_accepts_equal_or_higher_version() {
        let kp = keypair();
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(7, now, vec![], now).unwrap();
        let artifact = sign_policy(&policy, &kp).unwrap();
        assert!(verify_policy(&artifact, kp.public_key(), Some(7)).is_ok());
    }

    /// `is_past_cutoff` is true at/after the cutoff, false before, and false for
    /// an unnamed suite.
    #[test]
    fn is_past_cutoff_boundary() {
        let now = 1_000_000_000_000;
        let cutoff = now + 3 * HOUR_MS;
        let policy = DeprecationPolicy::build(
            1,
            now,
            vec![DeprecationEntry {
                suite_id: deprecated(),
                cutoff_unix_ms: cutoff,
                recommended_suite_id: successor(),
            }],
            now,
        )
        .unwrap();

        assert!(!policy.is_past_cutoff(deprecated(), cutoff - 1));
        assert!(policy.is_past_cutoff(deprecated(), cutoff));
        assert!(policy.is_past_cutoff(deprecated(), cutoff + 1));
        // A suite the policy does not name is never past cutoff.
        assert!(!policy.is_past_cutoff(successor(), cutoff + HOUR_MS));
    }

    /// `affected` returns only entries whose suite is in the in-use set.
    #[test]
    fn affected_filters_by_in_use_suites() {
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(
            1,
            now,
            vec![DeprecationEntry {
                suite_id: deprecated(),
                cutoff_unix_ms: now + 3 * HOUR_MS,
                recommended_suite_id: successor(),
            }],
            now,
        )
        .unwrap();

        assert_eq!(policy.affected(&[deprecated()]).len(), 1);
        assert_eq!(policy.affected(&[successor()]).len(), 0);
        assert_eq!(policy.affected(&[]).len(), 0);
    }

    /// The cache returns a fresh policy within the TTL and `None` past it.
    #[test]
    fn cache_respects_ttl() {
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(1, now, vec![], now).unwrap();
        let mut cache = PolicyCache::new();
        cache.insert("server-a", policy, now);

        assert!(cache.fresh("server-a", now).is_some());
        assert!(cache.fresh("server-a", now + HOUR_MS).is_some()); // within 1h
        assert!(cache.fresh("server-a", now + HOUR_MS + 1).is_none()); // past 1h
        assert!(cache.is_stale("server-a", now + 2 * HOUR_MS));
        assert!(cache.is_stale("unknown-server", now));
    }

    /// Cross-server earliest cutoff governs (ISC-C25 cross-server caution).
    #[test]
    fn cache_earliest_cutoff_across_servers() {
        let now = 1_000_000_000_000;
        let early = now + 3 * HOUR_MS;
        let late = now + 10 * HOUR_MS;
        let policy_a = DeprecationPolicy::build(
            1,
            now,
            vec![DeprecationEntry {
                suite_id: deprecated(),
                cutoff_unix_ms: late,
                recommended_suite_id: successor(),
            }],
            now,
        )
        .unwrap();
        let policy_b = DeprecationPolicy::build(
            1,
            now,
            vec![DeprecationEntry {
                suite_id: deprecated(),
                cutoff_unix_ms: early,
                recommended_suite_id: successor(),
            }],
            now,
        )
        .unwrap();
        let mut cache = PolicyCache::new();
        cache.insert("server-a", policy_a, now);
        cache.insert("server-b", policy_b, now);

        assert_eq!(cache.earliest_cutoff(deprecated()), Some(early));
        assert_eq!(cache.earliest_cutoff(successor()), None);
    }

    /// `cached_version` reports the stored version for rollback protection.
    #[test]
    fn cache_reports_cached_version() {
        let now = 1_000_000_000_000;
        let policy = DeprecationPolicy::build(42, now, vec![], now).unwrap();
        let mut cache = PolicyCache::new();
        cache.insert("server-a", policy, now);
        assert_eq!(cache.cached_version("server-a"), Some(42));
        assert_eq!(cache.cached_version("unknown"), None);
    }
}
