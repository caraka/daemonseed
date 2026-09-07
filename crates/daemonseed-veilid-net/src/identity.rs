//! D3 — turn the daemonseed-derived [`VeilidNodeSeed`] into a VLD0 node keypair
//! and the routing-table identity groups that pin it.
//!
//! VLD0 is Ed25519, so the seed IS the secret and the public is its verifying
//! key — byte-identical to veilid-core's own `vld0_generate_keypair`, minus the
//! RNG (proven in veilid-ds-spike `phase0-d3`).

use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use daemonseed_core::identity::keys::{
    KeyDerivationError, SignKeypair, VeilidNodeSeed, IDENTITY_PK_LEN,
};
use daemonseed_core::public_space::{
    project_release_pubkey, AnnounceOwnerError, ProjectReleaseSeed, ProjectReleaseSeedError,
    ProjectReleaseSeedSource, SeedOrigin,
};
use ed25519_dalek::SigningKey;
use veilid_core::{
    BarePublicKey, KeyPair, PublicKey, PublicKeyGroup, SecretKeyGroup, CRYPTO_KIND_VLD0,
};

use crate::error::{Result, VeilidNetError};

/// Build a VLD0 keypair from any 32-byte Ed25519 seed — the node identity (D3)
/// or a rendezvous-owner seed (a circle's, a public room's). VLD0 is Ed25519,
/// so the seed IS the secret and the public is its verifying key.
///
/// **Residual, for callers holding a genuinely secret seed (a DM page's, #244).**
/// The returned `KeyPair` *contains* the seed — it is the VLD0 secret — held in
/// veilid's `BareSecretKey`, a plain `Bytes` with no zeroize-on-drop. Three more
/// unwiped copies exist for the length of this call: the `format!` below
/// materialises the secret as a base64 `String`, `sk.to_bytes()` materialises it as
/// a bare `[u8; 32]` temporary to feed that encode, and `SigningKey` itself holds
/// it (that one IS wiped — dalek zeroizes on drop, which is why the `zeroize`
/// feature is declared explicitly in `Cargo.toml` rather than inherited from
/// defaults). All are unavoidable while veilid's own key types are the signing
/// interface.
///
/// **Per-operation derivation does NOT bound the secret's lifetime, and it is
/// important not to believe that it does.** Handing the keypair to
/// `open_dht_record` / `create_dht_record` — which every path that creates a record,
/// or that opens one it may later write, does — makes veilid retain a clone in
/// `OpenedRecord.writer` (`veilid-core-0.5.7`, `storage_manager/record_store/
/// opened_record.rs`), a struct that derives `Debug` over that secret and lives as
/// long as the record stays open. daemonseed opens a record once per session and,
/// for every family whose cardinality is bounded by peers rather than by traffic,
/// never closes it (see `rendezvous::open_cached`), so for those the copy is
/// effectively process-lifetime and is NOT under a caller's control. **DM channel
/// pages are the exception, and a bound is what makes them one:** they are held in a
/// `rendezvous::DM_PAGE_CACHE_CAPACITY` LRU whose eviction closes the record
/// (`rendezvous::open_page_bounded`, #252), so a page's retained writer clone lives
/// to its eviction — **and still to process exit in any session that never exceeds
/// the bound**, which is the ordinary case for a handful of conversations. The
/// residual is bounded under sustained traffic, not converted into something
/// short-lived. Closing the record is the only lever on that clone, which is why
/// #252 is a key-hygiene fix as much as a resource one.
///
/// What a caller CAN control is everything on this side of that boundary: derive
/// per operation, never cache a keypair yourself, and never key a long-lived map on
/// a seed. Use [`rendezvous_owner_public_bytes`] when only a record *identity* is
/// wanted, which needs no secret at all.
fn vld0_keypair(seed: &[u8; 32]) -> Result<KeyPair> {
    let sk = SigningKey::from_bytes(seed);
    let pk = sk.verifying_key();
    let s = format!(
        "VLD0:{}:{}",
        URL_SAFE_NO_PAD.encode(pk.to_bytes()),
        URL_SAFE_NO_PAD.encode(sk.to_bytes())
    );
    KeyPair::from_str(&s).map_err(|e| VeilidNetError::Identity(e.to_string()))
}

/// Build the VLD0 node keypair from a daemonseed Veilid node seed (D3).
pub fn node_keypair(seed: &VeilidNodeSeed) -> Result<KeyPair> {
    seed.with_bytes(vld0_keypair)
}

/// Build the VLD0 **rendezvous-owner** keypair from a deterministic owner seed
/// (a circle's, Phase 2; a public room's, Phase 3/4). Every participant derives
/// the same keypair, so all compute the same DHT record key and can write
/// owner-signed subkeys.
pub fn rendezvous_owner_keypair(owner_seed: &[u8; 32]) -> Result<KeyPair> {
    vld0_keypair(owner_seed)
}

/// A rendezvous-owner keypair's 32-byte Ed25519 **public** key, as raw bytes.
///
/// The same value [`rendezvous_owner_keypair`] puts in `KeyPair::key()`, reached
/// without the string round-trip and without the fallible parse: VLD0 is Ed25519,
/// so the public key is exactly 32 bytes for every possible seed, which is what
/// lets this be total where `rendezvous_owner_keypair` is not. Pinned equal to the
/// keypair's own public key by
/// `owner_public_bytes_is_the_keypairs_own_public_key` below, so the two cannot
/// drift.
///
/// Exists so a record can be *identified* without the secret being carried: the
/// DHT address derives from this key, so it separates records at least as
/// precisely as the seed does, and it is public by construction (#244).
///
/// **Residual:** `SigningKey::from_bytes` copies the seed into a `SigningKey`,
/// which is `ZeroizeOnDrop` — the copy is wiped when this function returns. No
/// copy of the seed outlives the call.
pub fn rendezvous_owner_public_bytes(owner_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(owner_seed)
        .verifying_key()
        .to_bytes()
}

/// The VLD0-kinded [`PublicKey`] naming a rendezvous owner, built from the raw 32
/// public bytes alone.
///
/// The reader-side counterpart to [`rendezvous_owner_keypair`]: it yields exactly
/// the value that keypair's `key()` yields for the same owner, so it addresses the
/// same DHT record with no owner secret ever derived or held. That matters for the
/// one rendezvous record whose owner secret is maintainer-held — the project
/// announce/MOTD record — where a reader must never derive the secret it would only
/// hold to discard. Circles and public rooms are deliberately unlike it:
/// every member holds the owner secret there because every member writes.
///
/// Total, like [`rendezvous_owner_public_bytes`] and for the same reason — a VLD0
/// public key is exactly 32 bytes for every possible input, so nothing here can
/// fail. The kind must be VLD0: `get_dht_record_key` runs the owner key through
/// `check_public_key`, and a foreign kind would either be rejected or name a
/// different address. Pinned equal to the keypair's own `PublicKey` by
/// `owner_public_key_matches_the_keypairs_public_key` below.
pub fn owner_public_key(owner_public: &[u8; 32]) -> PublicKey {
    PublicKey::new(CRYPTO_KIND_VLD0, BarePublicKey::new(owner_public))
}

/// The baked 32-byte Ed25519 public key owning the project-announce/MOTD DHT
/// record (F17 / ISC-15, Phase 4 A1).
///
/// A client needs this and nothing else to address, read, watch and verify that
/// record — [`owner_public_key`] turns it into the VLD0 `PublicKey`
/// `get_dht_record_key` consumes. It confers no write capability: the owner SECRET
/// is what gates writes, and only the maintainer holds it.
///
/// It lives in this crate rather than in `daemonseed-core` for two reasons. Ed25519
/// is a transport-layer concern — `daemonseed-core` has no ed25519 dependency and
/// gains none — so this is the only crate that can derive the value at all. And the
/// transport-owner key is deliberately domain-separated from the F17 content-signing
/// key: they descend from one project seed through different derivations, so keeping
/// them in different crates matches a split the design already enforces.
///
/// Baked rather than derived: the project seed is not in the source tree. The one
/// instance that holds it — the operator — checks its derived owner key against
/// this constant when it loads the seed ([`OperatorCredential`]), so a seed and a
/// constant that do not belong together are refused before the first write rather
/// than pointing a fleet at a record nobody writes. `project_announce_owner_pubkey_kat`
/// pins the value.
pub const PROJECT_ANNOUNCE_OWNER_PUBKEY: [u8; 32] = [
    0xca, 0x40, 0x6b, 0xe7, 0x2b, 0x15, 0xea, 0xb6, 0xe5, 0xc9, 0x7a, 0x51, 0xa9, 0xdb, 0x4c, 0x35,
    0x05, 0x4a, 0x57, 0xb1, 0xda, 0x76, 0x45, 0xc0, 0x5d, 0xb4, 0x3a, 0x32, 0x6e, 0xed, 0xe3, 0x1c,
];

// ── What the operator instance holds (F17 / ISC-15) ──────────────────────────

/// The operator instance's credential: the project-release signing keypair and the
/// announce record's owner seed, both derived from one runtime-loaded project
/// seed and both checked against the keys baked into this build before either is
/// handed out.
///
/// Held for the session by the instance that writes the announce record, the way
/// the identity signing key is held; every other instance has no value of this
/// type and subscribes the record on [`PROJECT_ANNOUNCE_OWNER_PUBKEY`] alone. It is
/// deliberately not `Clone`, and `Debug` is redacted. The signer zeroes on drop
/// (`SignKeypair`); the owner seed is the same [`OwnerSeed`] every write site
/// already copies by value, whose doc records why wiping this copy would bound
/// nothing.
pub struct OperatorCredential {
    signer: SignKeypair,
    owner_seed: OwnerSeed,
}

impl fmt::Debug for OperatorCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorCredential(<redacted>)")
    }
}

impl OperatorCredential {
    /// The shipped entry point: load the seed from `source`, checked against the
    /// baked [`daemonseed_core::public_space::project_release_pubkey`], then derive
    /// the owner seed, checked against [`PROJECT_ANNOUNCE_OWNER_PUBKEY`].
    ///
    /// `Ok(None)` is an instance given no seed — the ordinary reader. Every other
    /// failure is an error an operator must see. The owner check is what a rotation
    /// must satisfy: a rotation that restamped one constant and not the other fails
    /// here, on the operator, at Connect.
    ///
    /// The two constants are named in this function and nowhere else on the load
    /// path; a test can only reach the owner check through [`Self::from_seed`], so
    /// what a rotation must additionally verify by hand is that the operator build
    /// launched with the new seed reports itself as the operator.
    pub fn load(
        source: &ProjectReleaseSeedSource,
    ) -> core::result::Result<Option<(Self, SeedOrigin)>, OperatorCredentialError> {
        let Some((seed, origin)) = source.load().map_err(OperatorCredentialError::Seed)? else {
            return Ok(None);
        };
        let credential = Self::from_seed(
            &seed,
            project_release_pubkey(),
            &PROJECT_ANNOUNCE_OWNER_PUBKEY,
        )?;
        Ok(Some((credential, origin)))
    }

    /// Derive both halves from `seed` and check each against its expectation: the
    /// signing key against `expected_signer`, the owner key against
    /// `expected_owner`. Both checks run on every path that builds a credential, so
    /// a value of this type always holds keys that were checked, whichever way it
    /// was built.
    ///
    /// The expectations are parameters so the checks have a positive control: a test
    /// seed builds a credential against its own derived keys and is refused against
    /// any other. [`Self::load`] passes the baked constants. Requires the oxicrypt
    /// module to be operational.
    pub fn from_seed(
        seed: &ProjectReleaseSeed,
        expected_signer: &[u8; IDENTITY_PK_LEN],
        expected_owner: &[u8; 32],
    ) -> core::result::Result<Self, OperatorCredentialError> {
        let signer = seed
            .signing_keypair()
            .map_err(OperatorCredentialError::Signer)?;
        if signer.public_key() != expected_signer {
            return Err(OperatorCredentialError::NotTheBakedSigner);
        }
        let owner = seed
            .announce_owner_seed()
            .map_err(OperatorCredentialError::Owner)?;
        let owner_seed = OwnerSeed::new(*owner.as_bytes());
        if &rendezvous_owner_public_bytes(owner_seed.as_bytes()) != expected_owner {
            return Err(OperatorCredentialError::NotTheBakedOwner);
        }
        Ok(Self { signer, owner_seed })
    }

    /// The keypair MOTD and announcements are signed with.
    pub fn signer(&self) -> &SignKeypair {
        &self.signer
    }

    /// The announce record's owner seed, for the write sites and for subscribing
    /// the record as its owner.
    pub fn owner_seed(&self) -> &OwnerSeed {
        &self.owner_seed
    }
}

/// Why an operator credential could not be built.
#[derive(Debug)]
pub enum OperatorCredentialError {
    /// The seed could not be loaded or is not the project-release seed.
    Seed(ProjectReleaseSeedError),
    /// The ML-DSA keygen over the seed failed.
    Signer(KeyDerivationError),
    /// The owner-seed derivation failed.
    Owner(AnnounceOwnerError),
    /// The seed derived a signing key that is not the one this build trusts.
    NotTheBakedSigner,
    /// The seed derived an owner key that is not the one baked into this build:
    /// the seed and the constant do not belong together.
    NotTheBakedOwner,
}

impl fmt::Display for OperatorCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seed(e) => write!(f, "{e}"),
            Self::Signer(e) => write!(f, "project-release signing key derivation failed: {e}"),
            Self::Owner(e) => write!(f, "announce owner key derivation failed: {e}"),
            Self::NotTheBakedSigner => f.write_str(
                "the seed derives a project-release signing key that is not the one this build trusts",
            ),
            Self::NotTheBakedOwner => f.write_str(
                "the seed derives an announce owner key that is not the one this build trusts",
            ),
        }
    }
}

impl std::error::Error for OperatorCredentialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Seed(e) => Some(e),
            Self::Signer(e) => Some(e),
            Self::Owner(e) => Some(e),
            Self::NotTheBakedSigner | Self::NotTheBakedOwner => None,
        }
    }
}

// ── How a party holds a rendezvous record's owner (#244) ─────────────────────

/// A rendezvous record's 32-byte Ed25519 **owner seed** — the VLD0 secret that
/// signs every write to that record.
///
/// A newtype rather than a bare `[u8; 32]` because an owner seed and an owner
/// public key are the same shape: code that put one where the other belonged
/// type-checked everywhere, and changed only which record was addressed and what
/// travelled there. `owner_public_bytes_is_not_the_seed` pins the two values
/// apart; the two types keep them apart wherever either is carried, passed or
/// stored. What they do not close is the choice of bytes at the moment of
/// wrapping: [`OwnerSeed::new`] takes a raw array and cannot tell a seed from
/// anything else 32 bytes long.
///
/// [`fmt::Debug`] is redacted. **Deliberately NOT zeroize-on-drop**, which is a
/// claim about what a wipe here would buy rather than about how secret a seed is.
/// [`rendezvous_owner_keypair`] records that veilid retains its own non-zeroizing
/// clone of the derived secret for as long as the record stays open, so wiping
/// this copy bounds nothing; and every seed that legitimately reaches this type
/// belongs to a party entitled to keep it — a circle's and a
/// public room's are derived by every member because every member writes, and the
/// project-announce owner's is provisioned to the single instance that writes that
/// record. The per-conversation secret seeds, a direct-message page's and an
/// acknowledgement record's, travel instead as their own boxed, redacted,
/// zeroize-on-drop address types (`DmPageAddress`, `DmAckAddress`) and never reach
/// this type.
#[derive(Clone)]
pub struct OwnerSeed([u8; 32]);

impl OwnerSeed {
    /// Wrap an already-derived rendezvous-owner seed.
    ///
    /// Deliberately open, and it has to be: the derivations live in
    /// `daemonseed-core` (`circle::key::derive_circle_veilid_owner_seed`,
    /// `public_room::derive_room_veilid_owner_seed`,
    /// `public_space::derive_project_announce_veilid_owner_seed`) and return core
    /// types this crate does not depend on, so the caller that derived a seed is
    /// the one that wraps it. What the type closes is the confusion between a seed
    /// and a public key, not the choice of which seed to wrap.
    pub fn new(owner_seed: [u8; 32]) -> Self {
        Self(owner_seed)
    }

    /// The raw seed, for [`rendezvous_owner_keypair`] and the other primitives
    /// that consume it.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OwnerSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerSeed(<redacted>)")
    }
}

/// A rendezvous owner's 32-byte Ed25519 **public** key — enough to address, read
/// and watch the record, and never enough to write to it.
///
/// The constructor discipline is what this type is for. [`OwnerPublic::of_seed`]
/// runs the one-way derivation; [`OwnerPublic::baked`] admits a key that was
/// already public when it was written into the source. Those two are the only
/// ways in — there is deliberately no `From<[u8; 32]>` and no public field — so
/// nothing turns into an `OwnerPublic` by assignment. `baked` is the one route
/// that does not derive, which is why each baked key carries its own test
/// against the derivation.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerPublic([u8; 32]);

impl OwnerPublic {
    /// Derive an owner's public key from its seed — [`rendezvous_owner_public_bytes`],
    /// which is one-way, total, and the same value the owner keypair carries.
    pub fn of_seed(owner_seed: &OwnerSeed) -> Self {
        Self(rendezvous_owner_public_bytes(&owner_seed.0))
    }

    /// Admit a public key that is baked into the source, such as
    /// [`PROJECT_ANNOUNCE_OWNER_PUBKEY`].
    ///
    /// `const`, so a baked key resolves at compile time and needs no runtime
    /// derivation — which is the point of baking it: the seed it descends from can
    /// then leave the source tree entirely. The one thing this constructor cannot
    /// check is that its argument is a public key rather than a seed, so each baked
    /// key carries its own test against the derivation
    /// (`baked_project_announce_owner_pubkey_matches_seed_derivation`).
    pub const fn baked(owner_public: [u8; 32]) -> Self {
        Self(owner_public)
    }

    /// The raw public key, for the engine primitives that address a record with it
    /// ([`owner_public_key`], `rendezvous::open_read_only`).
    ///
    /// Reading the bytes out is safe in a way that reading an [`OwnerSeed`]'s out is
    /// not — a public key is the record's identity on the network — but it stays a
    /// named accessor rather than a public field so the one-way construction above
    /// remains the only way IN.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OwnerPublic {
    /// Renders a 4-byte prefix only: enough to tell two records apart in a trace,
    /// never enough to reconstruct the value.
    ///
    /// A public key is not itself a secret, so the truncation is not protecting it.
    /// It bounds the other case: [`OwnerPublic::baked`] takes a raw array and cannot
    /// tell a public key from a seed, so a mis-wrapped seed would otherwise print in
    /// full through every derived `Debug` that contains one — [`RendezvousOwner`]'s
    /// among them. Truncating here caps what any of them can emit, whatever the
    /// wrapped bytes turn out to be.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, ..] = self.0;
        write!(f, "OwnerPublic({a:02x}{b:02x}{c:02x}{d:02x}..)")
    }
}

/// How **this** party holds a rendezvous record's owner.
///
/// Named by possession rather than by record class, because possession is the
/// property the engine branches on and record class is not: the instance that
/// writes the project-announce/MOTD record holds that record's owner seed, while
/// every client holds only its public key, and those are the same record.
///
/// - [`RendezvousOwner::Held`] — a circle or public-room member, and the instance
///   that writes the announce record. Every member of a circle or a room derives
///   the owner seed because every member writes, so subscribing may deterministically
///   create a record that does not exist yet.
/// - [`RendezvousOwner::PublicOnly`] — a client reading the announce/MOTD record.
///   It carries no secret at all, so no path reachable from it can produce one.
///
/// **One record may be held as either variant, including within a single process.**
/// Every piece of per-record state the engine keeps — the open cache, the record
/// locks, the repair in-flight set — is keyed on the owner's public key, which both
/// variants yield, so the two variants name the same entries rather than splitting
/// them: a record subscribed as `PublicOnly` and repaired as `Held` stays one record
/// everywhere the engine tracks it, on one open-cache entry and behind one lock.
///
/// Whether the cached handle happens to carry a writer does not decide whether a
/// write succeeds. `rendezvous::publish_at_subkey`, this crate's only write
/// site, passes its own writer explicitly, and veilid prefers the call's writer over
/// the handle's (`veilid-core-0.5.7 src/storage_manager/set_value.rs:82-85`) — so
/// which variant opened the record first has no bearing on a write made through it.
///
/// **That is the assumption the mixing rests on, and it is worth stating because it
/// is the thing a later change can remove:** a write site that stopped passing an
/// explicit writer would fall back to whatever the cached handle holds, and would
/// then fail whenever some other path had opened the record read-only first.
#[derive(Clone, Debug)]
pub enum RendezvousOwner {
    /// This party holds the owner seed, so it can address, read and write the
    /// record.
    Held(OwnerSeed),
    /// This party holds only the owner's public key, so it can address, read and
    /// watch the record and nothing else.
    PublicOnly(OwnerPublic),
}

impl RendezvousOwner {
    /// The `Held` owner of a seed the caller has just derived — the one-step form
    /// of `Held(OwnerSeed::new(seed))`, since every seed-holding call site derives
    /// its seed immediately before the call.
    pub fn held(owner_seed: [u8; 32]) -> Self {
        Self::Held(OwnerSeed::new(owner_seed))
    }

    /// The owner's 32-byte public key, whichever variant this is: derived for
    /// [`Self::Held`], already held for [`Self::PublicOnly`].
    ///
    /// Total, and one value per record rather than one per variant, so a caller
    /// keying per-record state on it — a resweep cursor, a `RecordKey` → owner map —
    /// gets the same identity for a record however it happens to hold that record's
    /// owner.
    pub fn public_bytes(&self) -> [u8; 32] {
        match self {
            Self::Held(seed) => rendezvous_owner_public_bytes(seed.as_bytes()),
            Self::PublicOnly(public) => *public.as_bytes(),
        }
    }

    /// Resolve into the veilid key the engine opens the record with.
    ///
    /// Fallible only on the [`Self::Held`] side, where
    /// [`rendezvous_owner_keypair`] builds veilid's key types from the seed;
    /// [`Self::PublicOnly`] is total, as [`owner_public_key`] is.
    pub fn resolve(&self) -> Result<ResolvedOwner> {
        Ok(match self {
            Self::Held(seed) => ResolvedOwner::Writer(rendezvous_owner_keypair(seed.as_bytes())?),
            Self::PublicOnly(public) => ResolvedOwner::ReadOnly(public.clone()),
        })
    }
}

/// A [`RendezvousOwner`] resolved into what the engine opens the record with.
///
/// One difference reaches the network and it is the whole point: a [`Self::Writer`]
/// opens with the owner keypair, so it may create the record; a [`Self::ReadOnly`]
/// opens with no writer at all, so the record must already exist and no owner secret
/// is derived to open it. Everything else — the DHT address, the open-cache id, the
/// record lock — comes from [`Self::public_key`], which is the same value in both
/// arms for the same record.
///
/// The read-only arm is not a write barrier on the resulting handle; see
/// [`RendezvousOwner`] for what does bound writes and what that depends on.
///
/// No [`fmt::Debug`], deliberately: veilid's `KeyPair` renders its secret half,
/// which is the rendering [`OwnerSeed`] is redacted to avoid. This type is a
/// short-lived resolution step inside the engine, never stored and never traced, so
/// it needs none.
pub enum ResolvedOwner {
    /// The owner keypair: address, read, watch, create and write.
    Writer(KeyPair),
    /// The owner's public key alone: address, read and watch an existing record.
    ReadOnly(OwnerPublic),
}

impl ResolvedOwner {
    /// The record's owner public key — its identity in the open cache and the
    /// record locks.
    ///
    /// Identical across the two arms for one record, which is what keeps a reader
    /// and a writer of the same record on one cache entry and one lock instead of
    /// two of each.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Writer(keypair) => keypair.key(),
            Self::ReadOnly(public) => owner_public_key(public.as_bytes()),
        }
    }
}

/// This node's 32-byte Ed25519 public key — a pure function of the node seed,
/// used to spread members across the circle record's subkey regions.
pub fn node_public_bytes(seed: &VeilidNodeSeed) -> [u8; 32] {
    seed.with_bytes(|b| SigningKey::from_bytes(b).verifying_key().to_bytes())
}

/// Build the `(public_keys, secret_keys)` groups to pin this identity in the
/// veilid `routing_table` config (empty groups = "generate fresh").
pub fn identity_groups(seed: &VeilidNodeSeed) -> Result<(PublicKeyGroup, SecretKeyGroup)> {
    let kp = node_keypair(seed)?;
    let mut pks = PublicKeyGroup::new();
    pks.add(kp.key());
    let mut sks = SecretKeyGroup::new();
    sks.add(kp.secret());
    Ok((pks, sks))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed test project seed and the owner key it derives — the expectation
    /// a credential is checked against, built the way a rotation builds the real one.
    fn test_project_seed() -> (ProjectReleaseSeed, [u8; IDENTITY_PK_LEN], [u8; 32]) {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let seed = ProjectReleaseSeed::from_bytes([0x11; 32]);
        let signer = *seed
            .signing_keypair()
            .expect("derive the signer")
            .public_key();
        let owner = seed.announce_owner_seed().expect("derive the owner seed");
        (
            seed,
            signer,
            rendezvous_owner_public_bytes(owner.as_bytes()),
        )
    }

    /// The check a rotation must satisfy on both baked keys: the SAME seed that
    /// builds a credential against its own derived keys is refused against another
    /// signing key and against another owner key, each named by its own error. A
    /// rotation that restamped one constant and not the other fails here, on the
    /// operator, before any write.
    #[test]
    fn operator_credential_checks_the_owner_key_it_is_given() {
        let (seed, signer, owner) = test_project_seed();
        let credential =
            OperatorCredential::from_seed(&seed, &signer, &owner).expect("positive control");
        assert_eq!(
            rendezvous_owner_public_bytes(credential.owner_seed().as_bytes()),
            owner
        );
        assert_eq!(credential.signer().public_key(), &signer);
        let mut other_owner = owner;
        other_owner[0] ^= 1;
        assert!(matches!(
            OperatorCredential::from_seed(&seed, &signer, &other_owner).unwrap_err(),
            OperatorCredentialError::NotTheBakedOwner
        ));
        let mut other_signer = signer;
        other_signer[0] ^= 1;
        assert!(matches!(
            OperatorCredential::from_seed(&seed, &other_signer, &owner).unwrap_err(),
            OperatorCredentialError::NotTheBakedSigner
        ));
        // The baked constants refuse the test seed on both halves, so `load`'s
        // arguments are not derived from the seed under test.
        assert!(matches!(
            OperatorCredential::from_seed(&seed, project_release_pubkey(), &owner).unwrap_err(),
            OperatorCredentialError::NotTheBakedSigner
        ));
        assert!(matches!(
            OperatorCredential::from_seed(&seed, &signer, &PROJECT_ANNOUNCE_OWNER_PUBKEY)
                .unwrap_err(),
            OperatorCredentialError::NotTheBakedOwner
        ));
    }

    /// The shipped entry point refuses a seed that is not the project-release seed
    /// and reports no operator when no seed is supplied. It cannot be driven past
    /// the signing-key check without the real seed; the owner check is covered
    /// through `from_seed` above.
    #[test]
    fn operator_credential_load_refuses_a_foreign_seed_and_reports_absence() {
        let (seed, _, _) = test_project_seed();
        let hex: String = seed.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let source = ProjectReleaseSeedSource::new(
            Some(daemonseed_core::public_space::ProjectReleaseSeedText::from_os_string(hex.into())),
            None,
        );
        assert!(matches!(
            OperatorCredential::load(&source).unwrap_err(),
            OperatorCredentialError::Seed(ProjectReleaseSeedError::NotTheProjectSeed { .. })
        ));
        let none = ProjectReleaseSeedSource::new(None, None);
        assert!(OperatorCredential::load(&none).unwrap().is_none());
    }

    /// ISC-15 trust-anchor KAT for the transport half: the baked owner key clients
    /// address the announce record with. Catches a half-done rotation that edited
    /// the constant to a third value.
    #[test]
    fn project_announce_owner_pubkey_kat() {
        let hex: String = PROJECT_ANNOUNCE_OWNER_PUBKEY
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, "ca406be72b15eab6e5c97a51a9db4c35054a57b1da7645c05db43a326eede31c",
            "the announce owner key (record address) changed unexpectedly"
        );
    }

    /// The announce record a retired project identity owned is not the baked one:
    /// a build that carries this constant reads a record the retired seed cannot
    /// write. The retired key is a public value and is pinned here so a rotation
    /// cannot be half-reverted to it.
    #[test]
    fn retired_announce_owner_key_is_not_current() {
        const RETIRED: [u8; 32] = [
            0x99, 0x0a, 0xd4, 0x3d, 0xc3, 0x74, 0x82, 0x2b, 0xe8, 0xc7, 0xa9, 0xb9, 0x84, 0x55,
            0xcc, 0xd5, 0xc6, 0x85, 0xe3, 0xe7, 0x72, 0x30, 0x39, 0x03, 0x34, 0x98, 0xd0, 0x97,
            0xcf, 0x7e, 0xc4, 0xa7,
        ];
        assert_ne!(PROJECT_ANNOUNCE_OWNER_PUBKEY, RETIRED);
    }

    /// The record the former world-known dev placeholder seed owned is not the
    /// baked one: the announce record moved off the seed every clone of the old
    /// tree held.
    #[test]
    fn former_dev_owner_seed_record_is_orphaned() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let old =
            daemonseed_core::public_space::derive_project_announce_veilid_owner_seed(&[0x5d; 32])
                .unwrap();
        assert_ne!(
            rendezvous_owner_public_bytes(old.as_bytes()),
            PROJECT_ANNOUNCE_OWNER_PUBKEY,
            "the baked owner key must not be the dev placeholder's record"
        );
    }

    /// The baked owner key is disjoint from every world-derivable rendezvous owner
    /// (the lobby room, its presence sibling, and a circle named like it), so the
    /// operator channel never shares a record with an open rendezvous.
    #[test]
    fn baked_owner_key_is_disjoint_from_world_derivable_owners() {
        use daemonseed_core::circle::key::{
            derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
        };
        use daemonseed_core::crypto::suite::CNSA_2_0;
        use daemonseed_core::public_room::{
            derive_room_presence_veilid_owner_seed, derive_room_veilid_owner_seed,
        };
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let world: [[u8; 32]; 4] = [
            *derive_room_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            *derive_room_presence_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            *derive_circle_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes(),
            *derive_circle_presence_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes(),
        ];
        for seed in world {
            assert_ne!(
                rendezvous_owner_public_bytes(&seed),
                PROJECT_ANNOUNCE_OWNER_PUBKEY
            );
        }
    }

    /// **The two ways to reach a rendezvous owner's public key agree.**
    ///
    /// [`rendezvous_owner_public_bytes`] exists as a second, total path to a value
    /// [`rendezvous_owner_keypair`] also computes, and callers rely on them naming
    /// the SAME record: the write funnel keys a page's FIFO/coalescing scope on the
    /// bytes, while the open cache and record locks key on the `KeyPair`'s own
    /// `PublicKey` (#244). If these drifted, one page would be two records to the
    /// engine — two lock identities, two cache entries, and a coalescing scope that
    /// no longer matches the thing being written, none of it visible on any surface.
    #[test]
    fn owner_public_bytes_is_the_keypairs_own_public_key() {
        // Byte-distinct seeds: a run of equal bytes would pass under a derivation
        // that mis-sliced its input.
        for tag in [0u8, 1, 0x5c, 0xff] {
            let mut seed = [0u8; 32];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = tag ^ (i as u8).wrapping_mul(31).wrapping_add(7);
            }
            let kp = rendezvous_owner_keypair(&seed).expect("derive the owner keypair");
            assert_eq!(
                rendezvous_owner_public_bytes(&seed).as_slice(),
                kp.key().value().as_ref(),
                "the raw-bytes path and the KeyPair path must name one public key"
            );
        }
    }

    /// **The pubkey-only address path feeds `get_dht_record_key` the very same
    /// `PublicKey` the keypair path does.**
    ///
    /// `rendezvous::rendezvous_key` and `rendezvous::rendezvous_key_from_owner_public`
    /// share one body, and its only varying input is the `PublicKey` passed to
    /// `VeilidAPI::get_dht_record_key(schema, owner_key, None)`. That call is a pure
    /// function of its three arguments — local crypto, no network round-trip
    /// (veilid-core 0.5.7, `src/veilid_api/api.rs`) — and the other two are fixed by
    /// the shared `RecordShape`. So equal `PublicKey` inputs give equal record
    /// addresses, which is the whole claim: a reader holding only the 32 owner
    /// public bytes derives the record a holder of the owner keypair derives.
    ///
    /// Asserted on the `PublicKey` rather than on the two addresses because
    /// `get_dht_record_key` needs a live `VeilidAPI`, which a unit test cannot build.
    /// Both halves of the tagged value are compared: the bare bytes, and the crypto
    /// kind that decides which cryptosystem `check_public_key` measures them against.
    #[test]
    fn owner_public_key_matches_the_keypairs_public_key() {
        // Byte-distinct seeds, per the sibling test above: a run of equal bytes
        // would pass under a derivation that mis-sliced its input.
        for tag in [0u8, 1, 0x5c, 0xff] {
            let mut seed = [0u8; 32];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = tag ^ (i as u8).wrapping_mul(31).wrapping_add(7);
            }
            let kp = rendezvous_owner_keypair(&seed).expect("derive the owner keypair");
            let from_public = owner_public_key(&rendezvous_owner_public_bytes(&seed));
            assert_eq!(
                from_public.kind(),
                kp.key().kind(),
                "the pubkey-only path must tag the key with the kind the keypair path does"
            );
            assert_eq!(
                from_public.value().as_ref(),
                kp.key().value().as_ref(),
                "the pubkey-only path must carry the keypair's own public key bytes"
            );
            // Whole-value equality last, so a field added to the tagged type later is
            // caught rather than silently left out of the two comparisons above.
            assert_eq!(
                from_public,
                kp.key(),
                "both paths must hand get_dht_record_key one identical PublicKey"
            );
        }
    }

    /// **Mirror control: distinct owners give distinct keys, so distinct records.**
    ///
    /// The comparison that carries this is [`owner_public_key`] against *itself* on
    /// two owners, not against the other owner's keypair. Measured, not assumed: a
    /// stub returning a fixed constant fails the test above but **passes** a
    /// keypair-only comparison, because a constant is unequal to a real public key
    /// too. Only holding the constructor against its own output on a second input
    /// makes it prove that the input is read at all.
    ///
    /// What it protects is record separation. The DHT address is a function of this
    /// key, so two owners colliding here would be one record on the network — the
    /// maintainer-owned announce record and any other owner's silently sharing an
    /// address, with nothing on any surface to show it.
    #[test]
    fn owner_public_key_of_a_different_seed_is_a_different_key() {
        let a = owner_public_key(&rendezvous_owner_public_bytes(&[0x11u8; 32]));
        let b = owner_public_key(&rendezvous_owner_public_bytes(&[0x12u8; 32]));
        assert_ne!(
            a.value().as_ref(),
            b.value().as_ref(),
            "distinct owners must not collapse to one record address"
        );
        assert_ne!(a, b, "distinct owners must give distinct keys");

        // And neither is the *other* owner's key — the cross-path direction of the
        // same separation claim.
        let kp = rendezvous_owner_keypair(&[0x11u8; 32]).expect("derive the owner keypair");
        assert_ne!(
            b,
            kp.key(),
            "one owner's key must not name another's record"
        );
    }

    /// **The public key is not the seed.** Load-bearing rather than obvious: the
    /// funnel's record id is `[u8; 32]` and so is the seed, so a regression that
    /// put the secret back where the identity belongs would still type-check
    /// everywhere (#244).
    #[test]
    fn owner_public_bytes_is_not_the_seed() {
        let seed = [0x9du8; 32];
        assert_ne!(
            rendezvous_owner_public_bytes(&seed),
            seed,
            "the record identity must not BE the owner seed"
        );
    }

    /// A VLD0 public key is exactly 32 bytes, which is what lets it stand in for a
    /// `schedule::RecordId` without a fallible length check on the write path.
    #[test]
    fn a_vld0_public_key_is_thirty_two_bytes() {
        let kp = rendezvous_owner_keypair(&[0x11u8; 32]).expect("derive the owner keypair");
        assert_eq!(kp.key().value().len(), 32);
    }

    /// A byte-distinct seed for `tag`, matching the sibling tests above: a run of
    /// equal bytes would pass under a derivation that mis-sliced its input.
    fn distinct_seed(tag: u8) -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = tag ^ (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        seed
    }

    /// **`OwnerPublic::of_seed` IS the one-way derivation**, not a wrap of whatever
    /// it was handed.
    ///
    /// Both directions are asserted, and the second is the one that carries the
    /// claim: a constructor that simply stored its argument would satisfy "distinct
    /// seeds give distinct keys" and every equality against another `of_seed` call,
    /// and would still be handing the record's write secret to every reader that
    /// asked for its identity.
    #[test]
    fn owner_public_of_seed_runs_the_derivation() {
        for tag in [0u8, 1, 0x5c, 0xff] {
            let seed = distinct_seed(tag);
            assert_eq!(
                OwnerPublic::of_seed(&OwnerSeed::new(seed)),
                OwnerPublic::baked(rendezvous_owner_public_bytes(&seed)),
                "of_seed must yield exactly the derived public bytes"
            );
            assert_ne!(
                OwnerPublic::of_seed(&OwnerSeed::new(seed)),
                OwnerPublic::baked(seed),
                "of_seed must not carry the seed it was derived from"
            );
        }
    }

    /// **Mirror control: the seed is read.** Two owners must not collapse to one
    /// public key, or one record — the separation
    /// `owner_public_key_of_a_different_seed_is_a_different_key` states at the
    /// `PublicKey` layer, restated at the layer callers actually construct.
    #[test]
    fn owner_public_of_a_different_seed_is_a_different_key() {
        assert_ne!(
            OwnerPublic::of_seed(&OwnerSeed::new(distinct_seed(0))),
            OwnerPublic::of_seed(&OwnerSeed::new(distinct_seed(1))),
        );
    }

    /// **An owner seed never renders its bytes**, however it is nested.
    ///
    /// The control is the byte value a derived `Debug` would print: `0xab` renders
    /// as `171` in an array, so its absence is evidence the redaction ran rather
    /// than evidence the assertion is vacuous.
    #[test]
    fn an_owner_seed_debug_is_redacted() {
        let rendered = format!("{:?}", OwnerSeed::new([0xabu8; 32]));
        assert_eq!(rendered, "OwnerSeed(<redacted>)");
        assert!(!rendered.contains("171"), "the seed bytes must not render");

        let nested = format!("{:?}", RendezvousOwner::held([0xabu8; 32]));
        assert_eq!(nested, "Held(OwnerSeed(<redacted>))");
        assert!(!nested.contains("171"), "the seed bytes must not render");
    }

    /// **An owner public key renders only a short prefix**, however it is nested.
    ///
    /// `baked` cannot tell a public key from a seed, so the bound has to hold for
    /// whatever bytes it was handed, not merely for keys.
    ///
    /// The control that carries the claim is the second assertion, and it is aimed
    /// at the rendering a derived `Debug` produces: the array in decimal, against
    /// which a hex-only exclusion would pass vacuously. Asserting the decimal form is
    /// absent is what fails if the truncation is removed.
    #[test]
    fn an_owner_public_debug_is_truncated() {
        let bytes = distinct_seed(0x77);
        let full_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let derived_form = format!("{bytes:?}");

        let rendered = format!("{:?}", OwnerPublic::baked(bytes));
        assert!(
            !rendered.contains(&derived_form),
            "the whole key must not render in the form a derived Debug would print"
        );
        assert!(
            !rendered.contains(&full_hex),
            "the whole key must not render in hex either"
        );
        assert_eq!(rendered, format!("OwnerPublic({}..)", &full_hex[..8]));
        assert!(
            rendered.len() < full_hex.len(),
            "the rendering must be shorter than the value it describes"
        );

        let nested = format!(
            "{:?}",
            RendezvousOwner::PublicOnly(OwnerPublic::baked(bytes))
        );
        assert_eq!(
            nested,
            format!("PublicOnly(OwnerPublic({}..))", &full_hex[..8])
        );
        assert!(
            !nested.contains(&derived_form),
            "nesting must not restore the full rendering"
        );

        // Mirror control: truncated is not collapsed — two records stay distinct in a
        // trace, or the prefix would identify nothing.
        assert_ne!(
            format!("{:?}", OwnerPublic::baked(distinct_seed(0x78))),
            rendered
        );
    }

    /// **Only a `Held` owner resolves to a writer.**
    ///
    /// The `PublicOnly` half is the property the whole type exists for: a reader's
    /// owner carries no secret, so no engine path reachable from it can produce one.
    /// That is what makes "a reader cannot write this record" a fact about what the
    /// type can yield rather than a convention about which functions get called —
    /// the write site takes a `&KeyPair`, and this arm has none to give it.
    #[test]
    fn only_a_held_owner_resolves_to_a_writer() {
        let seed = distinct_seed(0x5c);
        let held = RendezvousOwner::held(seed)
            .resolve()
            .expect("resolve a held owner");
        let ResolvedOwner::Writer(keypair) = &held else {
            panic!("a held owner must resolve to a writer");
        };
        assert_eq!(
            keypair.key(),
            owner_public_key(&rendezvous_owner_public_bytes(&seed)),
            "the writer must be this seed's keypair, not some other owner's"
        );

        let reader = RendezvousOwner::PublicOnly(OwnerPublic::baked(PROJECT_ANNOUNCE_OWNER_PUBKEY))
            .resolve()
            .expect("resolve a public-key-only owner");
        assert!(
            matches!(reader, ResolvedOwner::ReadOnly(_)),
            "a public-key-only owner must not resolve to a writer"
        );
    }

    /// **The two variants of one record name the SAME record.**
    ///
    /// The reader arm and the writer arm share the open cache, the record locks and
    /// the repair in-flight set, all keyed on the owner public key — so if the two
    /// resolutions disagreed, one record would be two entries in each, and a reader's
    /// writerless handle would sit beside a writer's instead of colliding with it.
    /// The mirror control is the second assertion: two different owners must still be
    /// two records, or the equality above would hold for the wrong reason.
    #[test]
    fn both_variants_of_one_record_resolve_to_one_public_key() {
        let seed = OwnerSeed::new(distinct_seed(0x21));
        let held = RendezvousOwner::Held(seed.clone());
        let reader = RendezvousOwner::PublicOnly(OwnerPublic::of_seed(&seed));

        assert_eq!(held.public_bytes(), reader.public_bytes());
        assert_eq!(
            held.resolve().unwrap().public_key(),
            reader.resolve().unwrap().public_key(),
        );

        let other = RendezvousOwner::held(distinct_seed(0x22));
        assert_ne!(held.public_bytes(), other.public_bytes());
        assert_ne!(
            held.resolve().unwrap().public_key(),
            other.resolve().unwrap().public_key(),
        );
    }
}
