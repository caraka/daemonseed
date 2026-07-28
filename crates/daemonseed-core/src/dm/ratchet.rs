//! The conversation's key schedule — a post-quantum double ratchet (ISC-C42).
//!
//! This module is the arithmetic of forward secrecy: every key a DM message is
//! sealed under, where it comes from, and when it is destroyed. It holds no wire
//! format and no transport; the frame that carries these keys' output, and the
//! state machine that drives the generations, sit alongside it.
//!
//! ## The three levels
//!
//! ```text
//!   ss0 ──► RK₀ ──(encapsulate)──► RK₁ ──(encapsulate)──► RK₂ ──► …   roots
//!            │                      │                      │
//!            ▼                      ▼                      ▼
//!          CK₍dir,0₎              CK₍dir,1₎              CK₍dir,2₎      chains
//!            │                      │
//!            ├─► MK, CK' ─► MK, CK' ─► …                              messages
//! ```
//!
//! - A **root** advances only when someone encapsulates to the other party's
//!   fresh ephemeral key. That is the step that heals a compromise: an attacker
//!   holding every key in existence at generation `G` learns nothing about `G+1`,
//!   because `G+1` mixes in a secret they never saw. It is the reason this is a
//!   ratchet rather than a key schedule.
//! - A **chain** is one direction's run of messages under one root. Each direction
//!   has its own, from distinct labels, so the two parties never derive the same
//!   message key. An earlier draft used a single shared chain and thereby produced
//!   identical keys on both sides — which under a fixed nonce is catastrophic and
//!   under a random one is still a deletion wedge, since each party's advance
//!   destroys the other's key.
//! - A **message key** is used once and forgotten. `MK` and the successor `CK` are
//!   siblings of one extraction, so recovering a message key yields nothing about
//!   the chain it came from and nothing about any other message.
//!
//! ## What forward secrecy actually means here
//!
//! Deleting a chain key makes its past messages unrecoverable — that much is
//! ordinary. What is specific to this design is the boundary: `ss0` is
//! encapsulated to the recipient's **static** key, so everything before the
//! recipient's first reply is recoverable from a future compromise of that key.
//! Forward secrecy begins at the first generation step. The module cannot fix
//! that, and the design does not pretend otherwise — see
//! [`super::firstcontact`]'s "what is NOT forward-secret" and the hello-grade UI
//! requirement that is the actual mitigation.
//!
//! Addressing is deliberately *not* forward-secret either: `AR` is retained for
//! the life of the conversation, so a compromise of the static key reveals the
//! address graph even though it cannot reveal content. That asymmetry is
//! intentional and recorded — it is what lets a party who has been offline for a
//! month still find the conversation.
//!
//! ## Out-of-order delivery, and why there are two bounds
//!
//! Messages arrive late, out of order, and sometimes never. A chain only steps
//! forward, so opening message 7 before message 5 destroys 5's key unless it is
//! kept. [`SkippedKeys`] keeps them, bounded.
//!
//! **Two separate bounds, and conflating them is a real defect.** [`MAX_SKIP`] is
//! how far a *single* [`skip`] call will reach — the frozen design's per-direction
//! limit. [`SKIPPED_KEY_CAPACITY`] is how many keys the cache holds at once, and
//! it is deliberately **twice** `MAX_SKIP`, because processing one message across
//! a ratchet generation change is *two* skip batches: first to the end of the
//! previous chain (the frame's chain base says how far), then along the new chain
//! to the arriving sequence number. Sizing the cache at `MAX_SKIP` would let that
//! ordinary, benign step evict the previous chain's tail — which is precisely the
//! backlog the generation header exists to preserve.
//!
//! ## The caller's half of the contract
//!
//! Two invariants this module cannot enforce, both load-bearing:
//!
//! 1. **Commit skipped keys only after the arriving frame authenticates.** A
//!    sequence number is read from a frame that cannot be verified until the key
//!    it names exists, so it is attacker-controlled at the moment it is used. If a
//!    caller files skipped keys before the AEAD open succeeds, a peer can name a
//!    distant sequence number, flush the cache with keys nobody will ever ask for,
//!    and permanently strand messages it has already published — for the cost of
//!    one write. An attacker without the chain key cannot produce a frame that
//!    opens, so gating the commit on authentication closes it entirely. The
//!    bounded work done before that point is the accepted cost.
//! 2. **One [`SkippedKeys`] per conversation.** [`KeySlot`] identifies a key
//!    within a channel, not across channels: `(generation 0, a2b, seq 4)` exists
//!    in every conversation a client holds. A cache shared between two would hand
//!    one conversation's key to the other's lookup, and the resulting
//!    authentication failure is indistinguishable from tampering.
//!
//! Beyond the cache bound the oldest entry is evicted and its message becomes
//! permanently unreadable — a real, bounded loss, not a hypothetical one, and the
//! honest cost of refusing to let a peer make us allocate without limit.

use std::collections::VecDeque;

use oxicrypt_kdf::HkdfSha384;
use zeroize::Zeroize;

use crate::dm::domain;
use crate::secret_seed::redacted_secret_newtype;

/// Expand a PRK into a key class, zeroizing the transient stack buffer on
/// **both** the success and the error path.
///
/// `[u8; N]` is `Copy` and has no `Drop`, so wrapping one in a zeroize-on-drop
/// newtype protects only the copy that moved *into* the newtype — the original
/// stays live in the stack frame until something else happens to overwrite it. A
/// core dump, a swap page, or a hibernate image taken afterwards would contain it
/// in cleartext, which is precisely what this module claims not to leave behind.
/// The wrapping happens inside this helper so the buffer can be cleared after it,
/// which is why the constructor is passed in rather than applied by the caller.
///
/// Repo convention (#135) — same shape as
/// [`crate::secret_seed::derive_boxed_seed`] and `firstcontact::seal_key`.
fn expand_secret<const N: usize, T>(
    expand: impl FnOnce(&mut [u8; N]) -> Result<(), oxicrypt_kdf::KdfError>,
    wrap: impl FnOnce([u8; N]) -> T,
) -> Result<T, RatchetError> {
    let mut buf = [0u8; N];
    let outcome = expand(&mut buf)
        .map(|()| wrap(buf))
        .map_err(RatchetError::Kdf);
    buf.zeroize();
    outcome
}

/// Length of a ratchet root key.
pub const ROOT_KEY_LEN: usize = 32;

/// Length of a chain key.
pub const CHAIN_KEY_LEN: usize = 32;

/// Length of a message key — an AES-256 key.
pub const MESSAGE_KEY_LEN: usize = 32;

/// How far a single [`skip`] call will reach along one chain.
///
/// A frozen-design contract, not a tuning knob: the design builds its accepted
/// residual around exactly this number ("a burst of more than 64 out-of-order
/// gaps evicts oldest skipped keys"), so silently halving it would ship a peer
/// that refuses catch-ups the design guarantees, with nothing visible to a
/// reviewer. `max_skip_is_pinned` holds the value.
pub const MAX_SKIP: usize = 64;

/// How many skipped message keys the cache holds at once.
///
/// **Twice [`MAX_SKIP`], and the factor is load-bearing** — see the module docs.
/// One message arriving across a generation change causes two skip batches into
/// this one cache; at `MAX_SKIP` the second batch would evict the first.
pub const SKIPPED_KEY_CAPACITY: usize = 2 * MAX_SKIP;

/// Which way a message travels. Bound into the chain derivation, and into every
/// authorship signature, so a frame can never be replayed back at its sender.
///
/// Absolute, not relative to whoever is asking — use [`Role`] to get the right
/// one, rather than mapping by hand at each call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Initiator to recipient — the party that knocked, speaking.
    AToB,
    /// Recipient to initiator — the party that was knocked at, replying.
    BToA,
}

impl Direction {
    /// The HKDF `info` label for this direction's chain key.
    const fn chain_info(self) -> &'static [u8] {
        match self {
            Self::AToB => domain::DM_CHAIN_A2B,
            Self::BToA => domain::DM_CHAIN_B2A,
        }
    }

    /// The ASCII literal bound into signatures and addresses.
    ///
    /// **The single source of these two strings.** They are frozen wire bytes
    /// inside a signature preimage, so a second definition elsewhere is a drift
    /// that would only surface as an unverifiable signature between two versions
    /// of this client.
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::AToB => b"a2b",
            Self::BToA => b"b2a",
        }
    }
}

/// Which end of the conversation we are.
///
/// Exists so no call site has to map an absolute [`Direction`] onto "mine" or
/// "theirs". Getting that mapping wrong in one of its two uses derives a single
/// chain for both directions on both sides — which is not an immediate seal
/// break, since every seal carries a random nonce, but is exactly the deletion
/// wedge the two-chain design exists to prevent: each party's advance destroys
/// the other's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// We sent the first-contact entry.
    Initiator,
    /// We were knocked at.
    Recipient,
}

impl Role {
    /// The direction we send on.
    pub const fn send_dir(self) -> Direction {
        match self {
            Self::Initiator => Direction::AToB,
            Self::Recipient => Direction::BToA,
        }
    }

    /// The direction we receive on.
    pub const fn recv_dir(self) -> Direction {
        match self {
            Self::Initiator => Direction::BToA,
            Self::Recipient => Direction::AToB,
        }
    }
}

redacted_secret_newtype! {
    /// A ratchet root. Advanced by encapsulating to the peer's fresh ephemeral,
    /// and destroyed as soon as its successor exists.
    inline pub struct RootKey([u8; ROOT_KEY_LEN]);
}

redacted_secret_newtype! {
    /// One direction's chain key at one position.
    ///
    /// Every function that steps a chain takes this **by value**, so the caller's
    /// copy is gone afterward and "delete the chain key you stepped" is a compile
    /// error rather than a convention.
    inline pub struct ChainKey([u8; CHAIN_KEY_LEN]);
}

redacted_secret_newtype! {
    /// A single message's key. Used once.
    inline pub struct MessageKey([u8; MESSAGE_KEY_LEN]);
}

/// A key-schedule failure. Every variant here is a local condition: nothing in
/// this module parses attacker-supplied bytes, so there is no authentication
/// failure to report and no reason to make one uniform.
#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    /// HKDF failed — the module is not operational.
    Kdf(oxicrypt_kdf::KdfError),
    /// A caller asked to skip further than [`MAX_SKIP`] in one call.
    ///
    /// Separate from silent truncation on purpose: a peer claiming a sequence
    /// number far beyond what we have seen is either badly desynchronised or
    /// trying to make us derive keys, and the caller has to decide which. Folding
    /// it into "message did not open" would hide both, and truncating would hand
    /// back keys filed at positions no message will ever claim.
    SkipTooLarge { requested: u64, max: usize },
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "ratchet key derivation failed: {e}"),
            Self::SkipTooLarge { requested, max } => write!(
                f,
                "message skips {requested} keys ahead, more than the {max} one catch-up will derive"
            ),
        }
    }
}

impl std::error::Error for RatchetError {}

/// Derive the initial ratchet root from the encapsulated first-contact secret.
///
/// A third sibling of the extraction that produces `AR` and `chan_id` in
/// [`super::firstcontact::derive_channel_roots`] — same PRK, distinct label. The
/// three are siblings rather than a chain so that no one of them is derivable
/// from another: the retained addressing root must never yield the ratchet root
/// it outlives. `the_three_roots_from_ss0_are_independent` is what holds that.
pub fn derive_root(ss0: &[u8; 32]) -> Result<RootKey, RatchetError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_ROOT_SALT), ss0).map_err(RatchetError::Kdf)?;
    expand_secret::<ROOT_KEY_LEN, _>(|b| hkdf.expand(domain::DM_RATCHET_ROOT, b), RootKey)
}

/// Advance the root by one generation, mixing in a freshly encapsulated secret.
///
/// The previous root is the extraction **salt** and the new secret the **IKM**,
/// which is what makes the result depend on both: an attacker who learns only the
/// new secret cannot compute it without the old root, and one who holds the old
/// root cannot compute it without the new secret. Losing either direction of that
/// would cost the post-compromise heal this step exists for.
pub fn advance_root(previous: RootKey, encapsulated: &[u8; 32]) -> Result<RootKey, RatchetError> {
    let hkdf =
        HkdfSha384::extract(Some(previous.as_bytes()), encapsulated).map_err(RatchetError::Kdf)?;
    expand_secret::<ROOT_KEY_LEN, _>(|b| hkdf.expand(domain::DM_RATCHET_STEP, b), RootKey)
}

/// Derive one direction's chain key from a root.
///
/// Both directions are derivable from every root even though, in practice, only
/// the generation's sender uses one of them: a receiver never has to reason about
/// which party owns which generation, it just derives the chain for the direction
/// the frame declares.
pub fn chain_key(root: &RootKey, dir: Direction) -> Result<ChainKey, RatchetError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_CHAIN_SALT), root.as_bytes())
        .map_err(RatchetError::Kdf)?;
    expand_secret::<CHAIN_KEY_LEN, _>(|b| hkdf.expand(dir.chain_info(), b), ChainKey)
}

/// Take one symmetric step: yield this position's message key and the next chain
/// key.
///
/// Consumes the chain key it steps, so the used position cannot be stepped twice
/// or left alive by accident. Both outputs come from one extraction under sibling
/// labels, so a compromised message key reveals neither its chain nor its
/// successor — which is what makes deleting the chain key sufficient to protect
/// everything before it.
pub fn chain_step(ck: ChainKey) -> Result<(MessageKey, ChainKey), RatchetError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_CHAIN_STEP_SALT), ck.as_bytes())
        .map_err(RatchetError::Kdf)?;
    // The message key is wrapped before the second expand runs, so if that one
    // fails the early return drops a zeroize-on-drop value rather than abandoning
    // a live AES-256 key in the stack frame.
    let mk = expand_secret::<MESSAGE_KEY_LEN, _>(|b| hkdf.expand(domain::DM_MK, b), MessageKey)?;
    let next = expand_secret::<CHAIN_KEY_LEN, _>(|b| hkdf.expand(domain::DM_CK, b), ChainKey)?;
    Ok((mk, next))
}

/// Derive `count` message keys along a chain, tagged with the slots they belong
/// to, and return the chain key that follows them.
///
/// This is what a receiver does when a message arrives ahead of the ones before
/// it: the chain cannot rewind, so the intervening keys must be derived now and
/// kept, or the messages they belong to become unreadable the moment this one is
/// opened. It is also the whole of the generation-change path, where a receiver
/// runs out the previous chain before switching.
///
/// **The slots come back attached.** An earlier shape returned bare keys and left
/// the caller to reconstruct positions from a base it tracked separately; an
/// off-by-one there files every key one slot out, every recovered message then
/// fails to open, and the failure is indistinguishable from tampering. The
/// positions are computed here, once, by the code that knows them.
///
/// `count == 0` derives nothing and hands the chain key straight back, which is
/// the ordinary in-order case and needs no special-casing at the call site. To
/// reach a target position, skip the gap and then take one [`chain_step`].
///
/// **The bound is the point.** `count` derives from a sequence number in a frame
/// we cannot authenticate without the keys this call produces. Refusing past
/// [`MAX_SKIP`] is what stops a peer naming `u64::MAX` and making us derive until
/// the process dies. See the module docs for the other half of that defence,
/// which is the caller's.
pub fn skip(
    ck: ChainKey,
    from: KeySlot,
    count: u64,
) -> Result<(Vec<(KeySlot, MessageKey)>, ChainKey), RatchetError> {
    if count > MAX_SKIP as u64 {
        return Err(RatchetError::SkipTooLarge {
            requested: count,
            max: MAX_SKIP,
        });
    }
    let mut derived = Vec::with_capacity(count as usize);
    let mut current = ck;
    for offset in 0..count {
        let (mk, next) = chain_step(current)?;
        derived.push((
            KeySlot {
                seq: from.seq.saturating_add(offset),
                ..from
            },
            mk,
        ));
        current = next;
    }
    Ok((derived, current))
}

/// Where a skipped key belongs: a generation, a direction, and a position.
///
/// All three are needed. Two generations of the same direction hold different
/// chains, and a bare sequence number would collide across them — silently
/// handing a receiver the wrong key and producing an authentication failure that
/// looks exactly like tampering.
///
/// **Scoped to one conversation, not across them.** `(generation 0, a2b, seq 4)`
/// exists in every channel a client holds, so a [`SkippedKeys`] must belong to
/// exactly one — see the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySlot {
    pub generation: u32,
    pub direction: Direction,
    pub seq: u64,
}

/// Message keys derived past, held for messages that have not arrived yet.
///
/// Bounded at [`SKIPPED_KEY_CAPACITY`] and insertion-ordered: when it is full the
/// oldest entry is dropped, because the oldest gap is the one least likely to
/// ever be filled. Eviction is permanent message loss, so it is deliberately
/// observable — [`Self::evicted`] counts it rather than letting a silently
/// shrinking cache pass for a healthy one.
///
/// One per conversation. See [`KeySlot`].
#[derive(Debug)]
pub struct SkippedKeys {
    entries: VecDeque<(KeySlot, MessageKey)>,
    evicted: u64,
}

impl Default for SkippedKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl SkippedKeys {
    /// An empty cache, pre-allocated to its full capacity.
    ///
    /// Pre-allocated deliberately: a growing `VecDeque` reallocates and copies,
    /// leaving message-key bytes in freed memory that `ZeroizeOnDrop` never
    /// reaches. Since the bound is fixed, there is no reason to ever reallocate.
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(SKIPPED_KEY_CAPACITY),
            evicted: 0,
        }
    }

    /// How many keys are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether any key is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many keys have been dropped to stay inside [`SKIPPED_KEY_CAPACITY`].
    /// Every one is a message that can no longer be read.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Store a key for a message we have stepped over.
    ///
    /// Re-inserting an occupied slot replaces the existing entry rather than
    /// growing a duplicate, so a retransmitted header cannot make the cache hold
    /// two keys for one position. Note what this does *not* cover: a peer naming
    /// many *distinct* far-ahead sequence numbers still fills the cache and
    /// evicts. That variant is closed by the caller, by committing skipped keys
    /// only after the arriving frame authenticates — see the module docs.
    pub fn insert(&mut self, slot: KeySlot, key: MessageKey) {
        if let Some(existing) = self.entries.iter_mut().find(|(s, _)| *s == slot) {
            existing.1 = key;
            return;
        }
        if self.entries.len() == SKIPPED_KEY_CAPACITY {
            self.entries.pop_front();
            self.evicted += 1;
        }
        self.entries.push_back((slot, key));
    }

    /// Store a batch of keys, as returned by [`skip`].
    pub fn insert_all(&mut self, keys: impl IntoIterator<Item = (KeySlot, MessageKey)>) {
        for (slot, key) in keys {
            self.insert(slot, key);
        }
    }

    /// Take the key for a slot, removing it — a message key is used once, so
    /// leaving it behind after a successful open would keep a usable key alive for
    /// no reason.
    pub fn take(&mut self, slot: &KeySlot) -> Option<MessageKey> {
        let at = self.entries.iter().position(|(s, _)| s == slot)?;
        self.entries.remove(at).map(|(_, k)| k)
    }

    /// Whether a slot is held, without consuming it.
    pub fn contains(&self, slot: &KeySlot) -> bool {
        self.entries.iter().any(|(s, _)| s == slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-distinct inputs throughout: `[1u8; 32]` and `[2u8; 32]` would pass
    /// under a derivation that transposed its arguments, and a run of equal bytes
    /// would pass under one that mis-slices. These do not.
    fn ss(tag: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = tag ^ (i as u8).wrapping_mul(7).wrapping_add(0x5b);
        }
        out
    }

    /// Every derivation runs through the crypto module, which refuses to operate
    /// until its self-tests have passed.
    fn root(tag: u8) -> RootKey {
        let _ = oxicrypt_module::initialize();
        derive_root(&ss(tag)).unwrap()
    }

    /// A distinguishable message key per tag, wide enough that the cache tests
    /// cannot alias two tags onto one value however large the bound grows.
    fn mk_key(tag: u64) -> MessageKey {
        let mut out = [0u8; MESSAGE_KEY_LEN];
        out[..8].copy_from_slice(&tag.to_be_bytes());
        for (i, b) in out.iter_mut().enumerate().skip(8) {
            *b = (i as u8).wrapping_mul(31).wrapping_add(0x9e);
        }
        MessageKey(out)
    }

    fn slot(generation: u32, seq: u64) -> KeySlot {
        KeySlot {
            generation,
            direction: Direction::AToB,
            seq,
        }
    }

    fn a2b_chain(tag: u8) -> ChainKey {
        chain_key(&root(tag), Direction::AToB).unwrap()
    }

    // ---- known-answer vectors ------------------------------------------------
    //
    // These pin the wire. A uniform change to any label, salt, or argument order
    // keeps every round-trip in this file green while making this implementation
    // unable to talk to any other — which is exactly the failure a round-trip test
    // cannot see. The vectors are the only thing standing between that and a
    // silent incompatibility.

    #[test]
    fn root_derivation_is_pinned() {
        assert_eq!(
            hex::encode(root(0x11).as_bytes()),
            "a8042dbc77f2303ad708b1131d05e05a8382822ce9845c4285e5593d1b7e26dc"
        );
    }

    #[test]
    fn root_advance_is_pinned() {
        assert_eq!(
            hex::encode(advance_root(root(0x11), &ss(0x22)).unwrap().as_bytes()),
            "b011c303f26d81d50df4f057d12c4bb8cd4f10fd9aface16dae91163108f2f26"
        );
    }

    #[test]
    fn chain_keys_are_pinned() {
        let rk0 = root(0x11);
        assert_eq!(
            hex::encode(chain_key(&rk0, Direction::AToB).unwrap().as_bytes()),
            "d36f63b2925dd4a53c25215c90300a9f4aa6056f16710cd34acd5f33a0cd6a43"
        );
        assert_eq!(
            hex::encode(chain_key(&rk0, Direction::BToA).unwrap().as_bytes()),
            "98bab9a3d3351428f89c46134f98d51d881e312df1fdb1c768bba56c0b4fcaa0"
        );
    }

    #[test]
    fn chain_step_is_pinned() {
        let (mk0, ck1) = chain_step(a2b_chain(0x11)).unwrap();
        assert_eq!(
            hex::encode(mk0.as_bytes()),
            "19c1e45223e0826a7fc6ac8cb53c75ae5a18e241dce22520bba8dc85a0732411"
        );
        assert_eq!(
            hex::encode(ck1.as_bytes()),
            "0cb20e55f40a9fc319e065e895ffb548b69d53b2aa7a25d0af7eaa83fc532164"
        );
    }

    #[test]
    fn direction_labels_are_pinned() {
        assert_eq!(Direction::AToB.label(), b"a2b");
        assert_eq!(Direction::BToA.label(), b"b2a");
    }

    /// The frozen design builds its accepted out-of-order residual around this
    /// exact number, and every other test in this file refers to it symbolically —
    /// so without this line the constant is re-keyable to anything with the whole
    /// suite still green.
    #[test]
    fn max_skip_is_pinned() {
        assert_eq!(MAX_SKIP, 64);
    }

    /// The factor of two is not cosmetic: one message arriving across a
    /// generation change causes two skip batches into this one cache.
    #[test]
    fn the_cache_holds_two_full_catch_ups() {
        assert_eq!(SKIPPED_KEY_CAPACITY, 2 * MAX_SKIP);
        assert_eq!(SKIPPED_KEY_CAPACITY, 128);
    }

    // ---- separation ----------------------------------------------------------

    /// The defect that broke the single-chain draft: if both directions derived
    /// the same chain, both parties would produce identical message keys.
    #[test]
    fn the_two_directions_derive_different_chains() {
        let rk = root(0x11);
        assert_ne!(
            chain_key(&rk, Direction::AToB).unwrap().as_bytes(),
            chain_key(&rk, Direction::BToA).unwrap().as_bytes()
        );
    }

    /// `MK` and the successor `CK` are siblings of one extraction. If the labels
    /// collided, a message key would BE the next chain key and every message after
    /// a single compromise would fall.
    #[test]
    fn message_key_is_not_the_next_chain_key() {
        let ck = a2b_chain(0x11);
        let original = *ck.as_bytes();
        let (mk, next) = chain_step(ck).unwrap();
        assert_ne!(mk.as_bytes(), next.as_bytes());
        assert_ne!(mk.as_bytes(), &original);
        assert_ne!(next.as_bytes(), &original);
    }

    /// A root and the chain derived from it must not coincide, or the addressing
    /// root's retention would leak the chain it outlives.
    #[test]
    fn root_and_chain_are_distinct() {
        let rk = root(0x11);
        assert_ne!(
            rk.as_bytes(),
            chain_key(&rk, Direction::AToB).unwrap().as_bytes()
        );
    }

    /// The three-sibling property both this module and `dm::domain` assert in
    /// prose, tested rather than claimed: one `ss0`, three outputs, pairwise
    /// distinct. Without this, a label chosen wrongly from birth would be pinned
    /// by the KATs as if it were correct.
    #[test]
    fn the_three_roots_from_ss0_are_independent() {
        let _ = oxicrypt_module::initialize();
        let ss0 = ss(0x11);
        let rk = derive_root(&ss0).unwrap();
        let roots = crate::dm::firstcontact::derive_channel_roots(&ss0).unwrap();

        assert_ne!(rk.as_bytes(), &roots.ar);
        assert_ne!(rk.as_bytes(), &roots.chan_id);
        assert_ne!(roots.ar, roots.chan_id);
    }

    /// Distinct conversations must not share a root.
    #[test]
    fn distinct_secrets_give_distinct_roots() {
        assert_ne!(root(0x11).as_bytes(), root(0x12).as_bytes());
    }

    /// The generation step depends on BOTH its inputs. Two separate assertions,
    /// because an implementation that dropped the salt would still pass the first
    /// and one that dropped the IKM would still pass the second.
    #[test]
    fn advance_depends_on_both_inputs() {
        let fresh = ss(0x22);
        let other = ss(0x23);

        assert_ne!(
            advance_root(root(0x11), &fresh).unwrap().as_bytes(),
            advance_root(root(0x12), &fresh).unwrap().as_bytes(),
            "the previous root must affect the result"
        );
        assert_ne!(
            advance_root(root(0x11), &fresh).unwrap().as_bytes(),
            advance_root(root(0x11), &other).unwrap().as_bytes(),
            "the encapsulated secret must affect the result"
        );
    }

    /// An advanced root must not equal the root that would be derived from the
    /// same secret at first contact — different purposes, different labels.
    #[test]
    fn advance_is_domain_separated_from_first_derivation() {
        let fresh = ss(0x22);
        assert_ne!(
            advance_root(root(0x11), &fresh).unwrap().as_bytes(),
            derive_root(&fresh).unwrap().as_bytes()
        );
    }

    /// A chain only goes forward, and no position repeats. Sixteen steps rather
    /// than two or three: a chain that cycled with a short period would pass a
    /// three-step check and reuse keys in ordinary use.
    #[test]
    fn a_chain_never_repeats_a_key() {
        let mut ck = a2b_chain(0x11);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let (mk, next) = chain_step(ck).unwrap();
            assert!(seen.insert(*mk.as_bytes()), "message key repeated");
            assert!(seen.insert(*next.as_bytes()), "chain key repeated");
            ck = next;
        }
        assert_eq!(seen.len(), 32);
    }

    /// The same chain position must be reproducible — a receiver derives it
    /// independently of the sender, from its own copy of the chain key.
    #[test]
    fn stepping_is_deterministic() {
        let (mk_1, ck_1) = chain_step(a2b_chain(0x11)).unwrap();
        let (mk_2, ck_2) = chain_step(a2b_chain(0x11)).unwrap();
        assert_eq!(mk_1.as_bytes(), mk_2.as_bytes());
        assert_eq!(ck_1.as_bytes(), ck_2.as_bytes());
    }

    // ---- roles ---------------------------------------------------------------

    /// The mapping each party applies. If both roles agreed on a direction, both
    /// would derive one chain and each would destroy the other's keys.
    #[test]
    fn the_two_roles_send_and_receive_opposite_ways() {
        assert_eq!(Role::Initiator.send_dir(), Direction::AToB);
        assert_eq!(Role::Initiator.recv_dir(), Direction::BToA);
        assert_eq!(Role::Recipient.send_dir(), Direction::BToA);
        assert_eq!(Role::Recipient.recv_dir(), Direction::AToB);

        for role in [Role::Initiator, Role::Recipient] {
            assert_ne!(role.send_dir(), role.recv_dir());
        }
        assert_eq!(Role::Initiator.send_dir(), Role::Recipient.recv_dir());
        assert_eq!(Role::Recipient.send_dir(), Role::Initiator.recv_dir());
    }

    // ---- catching up ---------------------------------------------------------

    /// Skipping nothing derives nothing and returns the chain untouched — the
    /// ordinary in-order case, which must need no special-casing.
    #[test]
    fn skipping_nothing_returns_the_chain_untouched() {
        let ck = a2b_chain(0x11);
        let original = *ck.as_bytes();
        let (derived, same) = skip(ck, slot(0, 1), 0).unwrap();

        assert!(derived.is_empty());
        assert_eq!(same.as_bytes(), &original);
    }

    /// The keys handed back for the gap must be the very keys an in-order
    /// receiver would have derived, at the very positions it would have filed
    /// them. If either were off by one, every recovered message would fail to
    /// open and look like tampering.
    #[test]
    fn catching_up_yields_the_keys_it_stepped_over_at_the_right_slots() {
        let mut in_order = Vec::new();
        let mut walk = a2b_chain(0x11);
        for _ in 0..4 {
            let (mk, next) = chain_step(walk).unwrap();
            in_order.push(*mk.as_bytes());
            walk = next;
        }

        let from = KeySlot {
            generation: 3,
            direction: Direction::BToA,
            seq: 40,
        };
        let (derived, after) = skip(a2b_chain(0x11), from, 3).unwrap();

        assert_eq!(derived.len(), 3);
        for (offset, (got_slot, got_key)) in derived.iter().enumerate() {
            assert_eq!(got_slot.generation, 3);
            assert_eq!(got_slot.direction, Direction::BToA);
            assert_eq!(got_slot.seq, 40 + offset as u64, "slot positions drifted");
            assert_eq!(got_key.as_bytes(), &in_order[offset]);
        }

        // The chain key handed back is the one the next position steps from.
        let (next_mk, _) = chain_step(after).unwrap();
        assert_eq!(next_mk.as_bytes(), &in_order[3]);
    }

    /// The bound is a refusal, not a truncation. Removing the check makes this
    /// test hang rather than fail — which is the whole argument for having it.
    #[test]
    fn catching_up_refuses_more_than_one_catch_up_will_derive() {
        assert_eq!(
            skip(a2b_chain(0x11), slot(0, 1), MAX_SKIP as u64)
                .unwrap()
                .0
                .len(),
            MAX_SKIP
        );

        let err = skip(a2b_chain(0x11), slot(0, 1), MAX_SKIP as u64 + 1).unwrap_err();
        assert_eq!(
            err,
            RatchetError::SkipTooLarge {
                requested: MAX_SKIP as u64 + 1,
                max: MAX_SKIP,
            }
        );
    }

    /// A sequence number from an unauthenticated frame is attacker-controlled.
    #[test]
    fn an_absurd_sequence_number_is_refused_immediately() {
        assert!(matches!(
            skip(a2b_chain(0x11), slot(0, 1), u64::MAX).unwrap_err(),
            RatchetError::SkipTooLarge { .. }
        ));
    }

    /// The seam between the two halves of this module: keys derived by `skip` are
    /// filed under slots `take` will actually find. Tested end to end because an
    /// off-by-one here is invisible in either half alone.
    #[test]
    fn skipped_keys_round_trip_through_the_cache() {
        let from = slot(2, 17);
        let (derived, _) = skip(a2b_chain(0x11), from, 5).unwrap();
        let expected: Vec<_> = derived.iter().map(|(s, k)| (*s, *k.as_bytes())).collect();

        let mut cache = SkippedKeys::new();
        cache.insert_all(derived);
        assert_eq!(cache.len(), 5);

        for (want_slot, want_key) in expected {
            assert_eq!(
                cache.take(&want_slot).expect("slot was filed").as_bytes(),
                &want_key
            );
        }
        assert!(cache.is_empty());
        assert!(!cache.contains(&slot(2, 17)));
    }

    /// A generation change is two catch-ups for one message. At a capacity of
    /// `MAX_SKIP` the second batch would evict the first — the exact backlog the
    /// generation header exists to preserve.
    #[test]
    fn a_generation_change_does_not_evict_the_previous_chains_tail() {
        let mut cache = SkippedKeys::new();

        let (old_chain, _) = skip(a2b_chain(0x11), slot(4, 100), MAX_SKIP as u64).unwrap();
        let first_old = old_chain[0].0;
        cache.insert_all(old_chain);

        let (new_chain, _) = skip(a2b_chain(0x12), slot(5, 0), MAX_SKIP as u64).unwrap();
        cache.insert_all(new_chain);

        assert_eq!(cache.len(), SKIPPED_KEY_CAPACITY);
        assert_eq!(cache.evicted(), 0, "one ratchet step must evict nothing");
        assert!(
            cache.contains(&first_old),
            "the previous chain's oldest key survived the generation change"
        );
    }

    // ---- redaction -----------------------------------------------------------

    /// Every key type in this module is one `debug!` away from a log file. Exact
    /// string matches rather than "does not contain the hex": a `Debug` that
    /// leaked the bytes in decimal, or as a slice, would pass a substring check.
    #[test]
    fn key_types_do_not_render_their_bytes() {
        let rk = root(0x11);
        let ck = a2b_chain(0x11);
        let (mk, _) = chain_step(a2b_chain(0x11)).unwrap();

        assert_eq!(format!("{rk:?}"), "RootKey(<redacted>)");
        assert_eq!(format!("{ck:?}"), "ChainKey(<redacted>)");
        assert_eq!(format!("{mk:?}"), "MessageKey(<redacted>)");
    }

    /// The cache holds message keys, so its own `Debug` must not print them
    /// either — a cache is exactly what someone reaches for when debugging
    /// out-of-order delivery.
    #[test]
    fn the_skipped_cache_does_not_render_its_keys() {
        let mut skipped = SkippedKeys::new();
        let key = mk_key(0x31);
        let bytes = hex::encode(key.as_bytes());
        skipped.insert(slot(0, 4), key);

        let rendered = format!("{skipped:?}");
        assert!(rendered.contains("<redacted>"), "got {rendered}");
        assert!(!rendered.contains(&bytes));
        assert!(
            !rendered.contains("49"),
            "no decimal byte rendering: {rendered}"
        );
    }

    // ---- the skipped-key cache -----------------------------------------------

    #[test]
    fn a_stored_key_comes_back_once() {
        let mut skipped = SkippedKeys::new();
        let expected = *mk_key(0x31).as_bytes();
        skipped.insert(slot(0, 4), mk_key(0x31));

        assert!(skipped.contains(&slot(0, 4)));
        assert_eq!(skipped.take(&slot(0, 4)).unwrap().as_bytes(), &expected);
        assert!(!skipped.contains(&slot(0, 4)));
        assert!(skipped.take(&slot(0, 4)).is_none());
    }

    /// A sequence number alone does not identify a key. If the cache keyed on it,
    /// generation 1's message 4 would be handed generation 0's key.
    #[test]
    fn slots_are_distinguished_by_generation_and_direction() {
        let mut skipped = SkippedKeys::new();
        skipped.insert(slot(0, 4), mk_key(0x31));
        skipped.insert(slot(1, 4), mk_key(0x32));
        skipped.insert(
            KeySlot {
                generation: 0,
                direction: Direction::BToA,
                seq: 4,
            },
            mk_key(0x33),
        );

        assert_eq!(skipped.len(), 3);
        assert_eq!(
            skipped.take(&slot(0, 4)).unwrap().as_bytes(),
            mk_key(0x31).as_bytes()
        );
        assert_eq!(
            skipped.take(&slot(1, 4)).unwrap().as_bytes(),
            mk_key(0x32).as_bytes()
        );
    }

    #[test]
    fn the_cache_holds_its_capacity_and_evicts_the_oldest() {
        let mut skipped = SkippedKeys::new();
        for n in 0..SKIPPED_KEY_CAPACITY as u64 {
            skipped.insert(slot(0, n), mk_key(n));
        }
        assert_eq!(skipped.len(), SKIPPED_KEY_CAPACITY);
        assert_eq!(skipped.evicted(), 0);

        skipped.insert(slot(0, SKIPPED_KEY_CAPACITY as u64), mk_key(0xffff));

        assert_eq!(skipped.len(), SKIPPED_KEY_CAPACITY, "the bound is a bound");
        assert_eq!(skipped.evicted(), 1);
        assert!(!skipped.contains(&slot(0, 0)), "the oldest went first");
        assert!(skipped.contains(&slot(0, 1)));
        assert!(skipped.contains(&slot(0, SKIPPED_KEY_CAPACITY as u64)));
    }

    /// A peer that repeats one sequence number must not be able to push our real
    /// backlog out of the cache. Without the replace-in-place branch this test
    /// fails: the cache would hold a capacity's worth of one slot and nothing
    /// else.
    #[test]
    fn repeating_one_slot_does_not_evict_the_backlog() {
        let mut skipped = SkippedKeys::new();
        skipped.insert(slot(0, 0), mk_key(1));
        skipped.insert(slot(0, 1), mk_key(2));

        let writes = SKIPPED_KEY_CAPACITY as u64 * 2;
        for n in 0..writes {
            skipped.insert(slot(0, 1), mk_key(n));
        }

        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped.evicted(), 0);
        assert!(skipped.contains(&slot(0, 0)), "the backlog survived");
        assert_eq!(
            skipped.take(&slot(0, 1)).unwrap().as_bytes(),
            mk_key(writes - 1).as_bytes(),
            "the newest write for a slot wins"
        );
    }

    #[test]
    fn an_empty_cache_reports_itself_empty() {
        let mut skipped = SkippedKeys::new();
        assert!(skipped.is_empty());
        skipped.insert(slot(0, 0), mk_key(1));
        assert!(!skipped.is_empty());
        skipped.take(&slot(0, 0));
        assert!(skipped.is_empty());
    }
}
