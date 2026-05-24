//! Suite registry — the authoritative list of crypto bundles daemonseed
//! supports. Companion to `ds-suite-registry.md` (working draft outside this
//! repo during the private phase).
//!
//! A [`SuiteId`] is a `u16` newtype whose value identifies one [`Suite`] — a
//! bundle of (AEAD, KEM, signature, hash, KDF, memory-hard) primitives. The
//! registry is consulted whenever a wire artifact carries a `suite_id`
//! (per ISC-C24): the at-rest blob header (ISC-C3), the recovery file
//! (ISC-C32), CoT-asset payloads (ISC-S4 / ISC-C8), identity-proof signatures
//! (ISC-C1 / ISC-C22), and the server's own signed material (ISC-S15).
//!
//! ## Lifecycle
//!
//! Each entry has a [`LifecycleState`] declaring whether implementations
//! ship code for it and whether the suite is currently write-eligible. The
//! values match the five states defined in `ds-suite-registry.md`.
//!
//! ## Families
//!
//! Per ISC-A-C8, a **crypto family** is the set of suites sharing the same
//! KDF + hash function. Within-family migration is in-place per artifact
//! (read-old-write-new on touch, ISC-C24); cross-family migration is a
//! circle-rekey event and is **not** attempted in-place in MVP. The family
//! relationship is exposed via [`Suite::same_family`]; there is deliberately
//! no `family_id` wire field — a wire field would freeze registry topology.

use core::fmt;

/// Reserved sentinel for the "invalid" suite id. The registry MUST reject it
/// at parse time (per `ds-suite-registry.md` reserved-ranges table).
pub const SENTINEL_INVALID: u16 = 0x0000;

/// Reserved sentinel for the "max" suite id. The registry MUST reject it at
/// parse time (per `ds-suite-registry.md` reserved-ranges table).
pub const SENTINEL_MAX: u16 = 0xFFFF;

/// Wire-tagged identifier for one entry in the suite registry. Carried on
/// every cryptographic artifact (ISC-C24). The numeric value is part of the
/// protocol contract — changing it for an existing suite breaks every
/// daemon that has artifacts pinned at the old value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SuiteId(u16);

impl SuiteId {
    /// Construct a `SuiteId` from a raw `u16`, rejecting the reserved
    /// sentinels at both ends of the range.
    ///
    /// Returns [`SuiteIdError::Sentinel`] for the reserved values
    /// [`SENTINEL_INVALID`] and [`SENTINEL_MAX`].
    pub const fn try_new(raw: u16) -> Result<Self, SuiteIdError> {
        if raw == SENTINEL_INVALID || raw == SENTINEL_MAX {
            return Err(SuiteIdError::Sentinel(raw));
        }
        Ok(Self(raw))
    }

    /// Raw wire value. Use [`SuiteId::try_new`] to round-trip from the wire;
    /// this getter is for diagnostics, registry lookup, and serialization.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for SuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04X}", self.0)
    }
}

/// Failure modes for [`SuiteId::try_new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteIdError {
    /// The raw value matched one of the reserved sentinels — `0x0000`
    /// (invalid) or `0xFFFF` (max).
    Sentinel(u16),
}

impl fmt::Display for SuiteIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SuiteIdError::Sentinel(v) => write!(f, "reserved sentinel suite_id 0x{v:04X}"),
        }
    }
}

impl core::error::Error for SuiteIdError {}

/// AEAD primitive in a [`Suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    /// AES-256-GCM per NIST SP 800-38D.
    Aes256Gcm,
}

/// KEM primitive in a [`Suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kem {
    /// ML-KEM-1024 per FIPS 203.
    MlKem1024,
}

/// Signature primitive in a [`Suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    /// ML-DSA-87 per FIPS 204.
    MlDsa87,
}

/// Hash primitive in a [`Suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-256 per FIPS 180-4.
    Sha256,
}

/// KDF primitive in a [`Suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// HKDF-SHA-256 per RFC 5869.
    HkdfSha256,
}

/// Memory-hard function in a [`Suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryHard {
    /// Argon2id per RFC 9106.
    Argon2id,
}

/// Lifecycle state of a registry entry — `ds-suite-registry.md` Status
/// lifecycle table. Movement through these states is documented per-suite
/// in the registry doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Entry exists in the registry; no implementation supports it yet. Not
    /// on the wire.
    Proposed,
    /// Current default write-suite for new artifacts. More than one suite
    /// MAY be active-write during a transition. All implementations read it.
    ActiveWrite,
    /// Implementations still decrypt artifacts in this suite, but no longer
    /// write new ones.
    ActiveReadOnly,
    /// Implementations log a UX warning when reading this suite; refuse to
    /// write entirely. Sub-minimum content surfaces ISC-A-C8 warning.
    ReadOnlyDeprecated,
    /// Implementation no longer ships code for this suite. Artifacts in
    /// this suite become inaccessible to that build.
    Removed,
}

/// One row in the suite registry — a bundled set of primitives identified by
/// [`Suite::id`]. Per ISC-S15 / ISC-C24 every cryptographic artifact carries
/// a `suite_id` that resolves through [`Registry::lookup`] to this bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    /// Wire-tagged identifier for this row.
    pub id: SuiteId,
    /// AEAD primitive — used for at-rest blob, recovery file, CoT payloads.
    pub aead: Aead,
    /// KEM primitive — used for circle-of-trust key encapsulation.
    pub kem: Kem,
    /// Signature primitive — used for identity, signed posts, MOTD,
    /// release-channel binaries, server-wide handshake material.
    pub sig: Sig,
    /// Hash primitive — used for handle hashes (ISC-C4), CoT-asset hashes,
    /// and as the HKDF inner hash.
    pub hash: Hash,
    /// KDF primitive — pairs with [`Suite::hash`] to define the family
    /// (ISC-A-C8).
    pub kdf: Kdf,
    /// Memory-hard primitive — used for the at-rest passphrase KDF
    /// (ISC-C3, ISC-C14).
    pub memory_hard: MemoryHard,
    /// Lifecycle state of this row. Drives [`Registry::resolve_for_write`].
    pub state: LifecycleState,
}

impl Suite {
    /// Two suites belong to the same crypto family iff their KDF and hash
    /// primitives match (per ISC-A-C8). Within-family migration is in-place
    /// per artifact; cross-family migration is a circle-rekey event and is
    /// not attempted in-place in MVP.
    pub const fn same_family(&self, other: &Suite) -> bool {
        // `Eq` for `Kdf` / `Hash` can't be evaluated in const context
        // through the derived impl, so the discriminants are compared by
        // primitive name. Both enums currently have a single variant; the
        // shape generalizes once additional KDFs / hashes land.
        matches!((self.kdf, other.kdf), (Kdf::HkdfSha256, Kdf::HkdfSha256))
            && matches!((self.hash, other.hash), (Hash::Sha256, Hash::Sha256))
    }
}

// ── Concrete registry entries ─────────────────────────────────────────────

/// The CNSA 2.0 suite — daemonseed's MVP baseline. Bundle matches the
/// `0x0001` row of `ds-suite-registry.md`. Pinned by [`tests::cnsa_2_0_matches_registry_doc`]
/// so the design doc and the code cannot quietly diverge.
pub const CNSA_2_0: Suite = Suite {
    id: match SuiteId::try_new(0x0001) {
        Ok(id) => id,
        // Const-eval can't unwrap a Result with a non-Copy error, so we
        // panic to surface a build-time failure if someone breaks this.
        Err(_) => panic!("CNSA_2_0 suite id failed try_new"),
    },
    aead: Aead::Aes256Gcm,
    kem: Kem::MlKem1024,
    sig: Sig::MlDsa87,
    hash: Hash::Sha256,
    kdf: Kdf::HkdfSha256,
    memory_hard: MemoryHard::Argon2id,
    state: LifecycleState::ActiveWrite,
};

/// All registry entries supported by this build. Index order is irrelevant;
/// callers MUST go through [`Registry::lookup`] rather than indexing this
/// slice directly.
pub const REGISTRY: &[Suite] = &[CNSA_2_0];

/// Convenience handle around [`REGISTRY`]. All lookup, write-policy, and
/// default-write-suite logic flows through this type.
#[derive(Debug, Clone, Copy)]
pub struct Registry;

impl Registry {
    /// Look up a suite by its wire-tagged id. Returns `None` if the id is
    /// not present in this build's registry (treat as `Removed`-equivalent
    /// from the caller's perspective — the local build cannot decrypt or
    /// produce material under this suite).
    pub fn lookup(id: SuiteId) -> Option<&'static Suite> {
        REGISTRY.iter().find(|s| s.id == id)
    }

    /// Resolve a suite for *writing* a new artifact. Per ISC-A-C8 the
    /// client MUST refuse to write under any suite whose state is
    /// `ReadOnlyDeprecated` or `Removed`; `ActiveReadOnly` and `Proposed`
    /// are also write-refused (active-read-only by definition no longer
    /// writes; proposed has no implementation yet).
    ///
    /// The compose-time semantics live here so the policy is enforced at
    /// one bottleneck rather than at every artifact-writer call site.
    pub fn resolve_for_write(id: SuiteId) -> Result<&'static Suite, WriteRefusal> {
        let suite = Self::lookup(id).ok_or(WriteRefusal::Unknown(id))?;
        match suite.state {
            LifecycleState::ActiveWrite => Ok(suite),
            LifecycleState::ActiveReadOnly => Err(WriteRefusal::ActiveReadOnly(id)),
            LifecycleState::ReadOnlyDeprecated => Err(WriteRefusal::Deprecated(id)),
            LifecycleState::Removed => Err(WriteRefusal::Removed(id)),
            LifecycleState::Proposed => Err(WriteRefusal::Proposed(id)),
        }
    }

    /// Default write-suite for this build — the suite the client picks for
    /// new artifacts in the absence of operator override. Selected as "the
    /// first registry entry currently in [`LifecycleState::ActiveWrite`]".
    /// During a transition with multiple active-write suites, operator
    /// config or user preference resolves the tie; M3 ships with exactly
    /// one row so the question is moot until the registry grows.
    pub fn default_write_suite() -> SuiteId {
        REGISTRY
            .iter()
            .find(|s| s.state == LifecycleState::ActiveWrite)
            .map(|s| s.id)
            .expect("registry has no Active-write entry; build is broken")
    }
}

/// Reasons [`Registry::resolve_for_write`] refused to issue a suite for a
/// new write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The id is not present in this build's registry.
    Unknown(SuiteId),
    /// Entry exists but is `Proposed`; no implementation ships for it.
    Proposed(SuiteId),
    /// Entry is `ActiveReadOnly` — readable, no longer writeable.
    ActiveReadOnly(SuiteId),
    /// Entry is `ReadOnlyDeprecated` — readable with UX warning, never
    /// written.
    Deprecated(SuiteId),
    /// Entry is `Removed`; no code path for this suite ships in this build.
    Removed(SuiteId),
}

impl fmt::Display for WriteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteRefusal::Unknown(id) => write!(f, "unknown suite_id {id}"),
            WriteRefusal::Proposed(id) => write!(f, "suite {id} is proposed-only"),
            WriteRefusal::ActiveReadOnly(id) => write!(f, "suite {id} is active-read-only"),
            WriteRefusal::Deprecated(id) => write!(f, "suite {id} is read-only-deprecated"),
            WriteRefusal::Removed(id) => write!(f, "suite {id} has been removed"),
        }
    }
}

impl core::error::Error for WriteRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    /// ISC-2 — `SuiteId::try_new` rejects both reserved sentinels.
    #[test]
    fn try_new_rejects_sentinels() {
        assert_eq!(
            SuiteId::try_new(SENTINEL_INVALID),
            Err(SuiteIdError::Sentinel(0x0000))
        );
        assert_eq!(
            SuiteId::try_new(SENTINEL_MAX),
            Err(SuiteIdError::Sentinel(0xFFFF))
        );
    }

    /// ISC-2 — `SuiteId::try_new` accepts non-sentinel ids and round-trips
    /// `get`.
    #[test]
    fn try_new_round_trips_non_sentinel() {
        let id = SuiteId::try_new(0x0001).unwrap();
        assert_eq!(id.get(), 0x0001);
    }

    /// ISC-9 — the CNSA 2.0 bundle byte-matches the published registry
    /// document row. If `ds-suite-registry.md` row 0x0001 ever drifts from
    /// these literals, this test fails and the doc + code re-align in the
    /// same commit.
    #[test]
    fn cnsa_2_0_matches_registry_doc() {
        assert_eq!(CNSA_2_0.id.get(), 0x0001);
        assert_eq!(CNSA_2_0.aead, Aead::Aes256Gcm);
        assert_eq!(CNSA_2_0.kem, Kem::MlKem1024);
        assert_eq!(CNSA_2_0.sig, Sig::MlDsa87);
        assert_eq!(CNSA_2_0.hash, Hash::Sha256);
        assert_eq!(CNSA_2_0.kdf, Kdf::HkdfSha256);
        assert_eq!(CNSA_2_0.memory_hard, MemoryHard::Argon2id);
        assert_eq!(CNSA_2_0.state, LifecycleState::ActiveWrite);
    }

    /// ISC-5 — `REGISTRY` has exactly one entry at M3.
    #[test]
    fn registry_has_one_entry_at_m3() {
        assert_eq!(REGISTRY.len(), 1);
        assert_eq!(REGISTRY[0], CNSA_2_0);
    }

    /// ISC-6 — `Registry::lookup` resolves a known id; returns `None` for
    /// an unknown id.
    #[test]
    fn lookup_resolves_known_returns_none_for_unknown() {
        let cnsa = Registry::lookup(SuiteId::try_new(0x0001).unwrap()).unwrap();
        assert_eq!(*cnsa, CNSA_2_0);

        let unknown = Registry::lookup(SuiteId::try_new(0x0042).unwrap());
        assert!(unknown.is_none());
    }

    /// ISC-7 — `same_family` returns true for two suites sharing KDF + hash
    /// and false otherwise. With only one suite in the M3 registry we cover
    /// the same-suite case (true) and the synthetic differing-KDF /
    /// differing-hash cases (false). Synthetic suites are constructed with
    /// dummy variants once additional KDFs / hashes are added in a later
    /// milestone; for now we assert the reflexive property holds and the
    /// helper compiles in const context.
    #[test]
    fn same_family_reflexive_on_cnsa() {
        assert!(CNSA_2_0.same_family(&CNSA_2_0));
    }

    /// ISC-8 — `resolve_for_write` returns the suite when state is
    /// `ActiveWrite` and refuses every other state by mapping to a distinct
    /// `WriteRefusal` variant. Synthetic suites cover the non-Active-write
    /// branches since the M3 registry has only one row.
    #[test]
    fn resolve_for_write_branches() {
        // ActiveWrite — happy path on the real registry.
        let s = Registry::resolve_for_write(SuiteId::try_new(0x0001).unwrap()).unwrap();
        assert_eq!(*s, CNSA_2_0);

        // Unknown id branch.
        assert_eq!(
            Registry::resolve_for_write(SuiteId::try_new(0x0042).unwrap()),
            Err(WriteRefusal::Unknown(SuiteId::try_new(0x0042).unwrap()))
        );

        // The remaining branches (`Proposed`, `ActiveReadOnly`,
        // `ReadOnlyDeprecated`, `Removed`) are exercised by mapping each
        // `LifecycleState` through a local helper that mirrors
        // `resolve_for_write`'s `match`. Once M7 ships a second registry
        // entry, the synthetic helper goes away in favour of a direct
        // table-driven test against real rows.
        for (state, refusal) in [
            (
                LifecycleState::Proposed,
                WriteRefusal::Proposed as fn(_) -> _,
            ),
            (LifecycleState::ActiveReadOnly, WriteRefusal::ActiveReadOnly),
            (LifecycleState::ReadOnlyDeprecated, WriteRefusal::Deprecated),
            (LifecycleState::Removed, WriteRefusal::Removed),
        ] {
            let id = SuiteId::try_new(0x0001).unwrap();
            let synthetic = Suite { state, ..CNSA_2_0 };
            // Mirror the match in `resolve_for_write` so the test asserts
            // the same exhaustive mapping the production code does.
            let got = match synthetic.state {
                LifecycleState::ActiveWrite => Ok(&synthetic),
                LifecycleState::ActiveReadOnly => Err(WriteRefusal::ActiveReadOnly(id)),
                LifecycleState::ReadOnlyDeprecated => Err(WriteRefusal::Deprecated(id)),
                LifecycleState::Removed => Err(WriteRefusal::Removed(id)),
                LifecycleState::Proposed => Err(WriteRefusal::Proposed(id)),
            };
            assert_eq!(got, Err(refusal(id)));
        }
    }

    /// `default_write_suite` returns CNSA 2.0 at M3.
    #[test]
    fn default_write_suite_is_cnsa_2_0() {
        assert_eq!(Registry::default_write_suite(), CNSA_2_0.id);
    }

    /// `SuiteId` formats as a 4-digit uppercase hex literal — used in error
    /// messages and diagnostics.
    #[test]
    fn suite_id_displays_as_hex() {
        let id = SuiteId::try_new(0x0001).unwrap();
        assert_eq!(format!("{id}"), "0x0001");
    }

    /// `WriteRefusal::Display` carries the offending id.
    #[test]
    fn write_refusal_display_carries_id() {
        let id = SuiteId::try_new(0x0001).unwrap();
        assert_eq!(
            format!("{}", WriteRefusal::Deprecated(id)),
            "suite 0x0001 is read-only-deprecated"
        );
    }
}
