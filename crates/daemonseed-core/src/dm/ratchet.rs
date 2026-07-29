//! The conversation's key schedule — a post-quantum double ratchet (ISC-C38).
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
//!
//! ## Surviving a restart
//!
//! `ss0` does not rebuild a running conversation. It yields generation zero's
//! root and nothing else — not the generations since, not the ephemerals a peer's
//! next step will encapsulate to, not where either chain has reached. A party
//! rebuilt from it comes back at generation zero while its peer carries on: every
//! frame then takes the advancing path, looks for an ephemeral that party no
//! longer holds, and fails with [`RatchetError::UnknownEphemeral`] — in both
//! directions, permanently, with nothing on either end reporting it.
//!
//! [`Ratchet::snapshot`] and [`Ratchet::restore`] are the way across a restart,
//! and [`RatchetSnapshot::encode`] / [`RatchetSnapshot::decode`] are its at-rest
//! form. **The encoding is the plaintext of a record, not the record**: it is a
//! complete set of live keys in the clear and must be sealed by whatever store
//! holds it, exactly as `ss0` is. `chan_id` is never part of it — see
//! [`RatchetSnapshot`].

use std::collections::VecDeque;

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_kem as ml_kem;
use zeroize::{Zeroize, Zeroizing};

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

/// The furthest a receiver will step a chain in one call, retaining or not.
///
/// [`MAX_SKIP`] bounds how many keys are *kept*; this bounds how many are
/// *derived*. The two differ because a chain cannot be indexed — reaching
/// position `n` means stepping to it — so a receiver returning from a long
/// absence has to walk past the messages it lost in order to read the ones it
/// did not. Refusing instead would leave it unable to read anything on that
/// chain, which is a far worse outcome than the loss the design already accepts.
///
/// Sixteen catch-ups' worth: enough to walk back into a conversation that ran on
/// without us, small enough that a peer naming an absurd sequence number buys a
/// bounded number of HKDF steps and nothing else.
pub const MAX_CATCH_UP: u64 = 16 * MAX_SKIP as u64;

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
#[derive(Debug)]
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
    /// An ML-KEM or crypto-module operation failed at the module boundary.
    Module(oxicrypt_module::Error),
    /// The OS entropy source failed while minting an ephemeral or an
    /// encapsulation.
    EntropySource,
    /// A frame claims a new generation but carries no ciphertext to root it in.
    ///
    /// Every message of a generation repeats that ciphertext precisely so this
    /// cannot happen through ordinary loss; seeing it means a malformed or
    /// truncated frame.
    MissingCiphertext { generation: u32 },
    /// A frame claims a generation whose step would need an ephemeral we no
    /// longer hold — reordering deeper than [`EPHEMERAL_WINDOW`], or a frame that
    /// could not have been produced by a peer following the protocol.
    UnknownEphemeral { generation: u32 },
    /// This position's key was used and destroyed, and it is not in the
    /// skipped-key cache. Ordinary: re-seeding makes duplicates routine traffic,
    /// and a caller should discard them by content address before asking. It can
    /// also mean the key was evicted or abandoned, which is permanent loss — check
    /// [`Ratchet::losses`] to tell a busy conversation from a lossy one.
    AlreadyConsumed { generation: u32, seq: u64 },
    /// The frame belongs to a generation behind the one we receive on, and its key
    /// was not cached. Same practical handling as [`Self::AlreadyConsumed`], but
    /// distinguishable because it means the peer is behind us rather than repeating
    /// itself.
    GenerationTooOld { frame: u32, current: u32 },
    /// The frame claims a sequence number before its own chain begins. No honest
    /// peer produces this; it is malformed or hostile, on a record only the two
    /// parties can write.
    SeqBeforeChainBase { chain_base: u64, seq: u64 },
    /// The generation counter would overflow. Unreachable by any peer following
    /// the protocol — reaching it needs 2^32 round trips — but the alternative is
    /// a wrapping counter that collides two roots on one generation number.
    GenerationExhausted,
    /// The chain cursor would step past the last sequence number there is.
    /// Unreachable by any peer following the protocol, and refused rather than
    /// left to the arithmetic: this crate's release profile sets no
    /// `overflow-checks`, so the wrap is silent there, and a cursor wrapping to
    /// zero rewrites the write-once page slot sequence zero already owns.
    SequenceExhausted { seq: u64 },
    /// A frame sits further ahead on its chain than [`MAX_CATCH_UP`] — further
    /// than a receiver will walk in one step. Not recoverable by retrying the
    /// same frame; the conversation re-anchors at the peer's next ratchet step.
    BacklogTooWide { gap: u64, max: u64 },
    /// The two halves of the opening ephemeral are not a keypair. Caught at
    /// construction because ML-KEM would not catch it later: decapsulation never
    /// fails, so the mismatch would surface as every reply being rejected forever.
    MismatchedEphemeral,
    /// The chain this operation needs does not exist yet — the initiator has had
    /// no reply, or the recipient has not sent.
    NotYetEstablished,
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "ratchet key derivation failed: {e}"),
            Self::SkipTooLarge { requested, max } => write!(
                f,
                "message skips {requested} keys ahead, more than the {max} one catch-up will derive"
            ),
            Self::Module(e) => write!(f, "crypto module unavailable: {e:?}"),
            Self::EntropySource => write!(f, "the entropy source failed"),
            Self::MissingCiphertext { generation } => write!(
                f,
                "a frame at generation {generation} carries no ratchet ciphertext"
            ),
            Self::UnknownEphemeral { generation } => write!(
                f,
                "no ephemeral held for the step into generation {generation}"
            ),
            Self::AlreadyConsumed { generation, seq } => write!(
                f,
                "the key for generation {generation} sequence {seq} was already used or lost"
            ),
            Self::GenerationTooOld { frame, current } => write!(
                f,
                "a frame from generation {frame} arrived while receiving on {current}"
            ),
            Self::SeqBeforeChainBase { chain_base, seq } => write!(
                f,
                "sequence {seq} is before its own chain, which begins at {chain_base}"
            ),
            Self::GenerationExhausted => write!(f, "the ratchet generation counter is exhausted"),
            Self::SequenceExhausted { seq } => write!(
                f,
                "sequence {seq} is the last there is, and the chain cannot step past it"
            ),
            Self::BacklogTooWide { gap, max } => write!(
                f,
                "a frame sits {gap} positions ahead, beyond the {max} one catch-up walks"
            ),
            Self::MismatchedEphemeral => {
                write!(f, "the opening ephemeral's two halves are not a keypair")
            }
            Self::NotYetEstablished => {
                write!(f, "the conversation has no chain in that direction yet")
            }
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
pub(crate) fn derive_root(ss0: &[u8; 32]) -> Result<RootKey, RatchetError> {
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
pub(crate) fn advance_root(
    previous: RootKey,
    encapsulated: &[u8; 32],
) -> Result<RootKey, RatchetError> {
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
pub(crate) fn chain_key(root: &RootKey, dir: Direction) -> Result<ChainKey, RatchetError> {
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
pub(crate) fn chain_step(ck: ChainKey) -> Result<(MessageKey, ChainKey), RatchetError> {
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
pub(crate) fn skip(
    ck: ChainKey,
    from: KeySlot,
    count: u64,
) -> Result<(SkippedBatch, ChainKey), RatchetError> {
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

/// Step a chain forward `count` times, discarding every key.
///
/// For positions a receiver has written off: the chain still has to be walked to
/// get past them, but nothing is kept, so the derived keys never reach the cache
/// and never reach a caller.
fn burn(ck: ChainKey, count: u64) -> Result<ChainKey, RatchetError> {
    let mut current = ck;
    for _ in 0..count {
        let (_discarded, next) = chain_step(current)?;
        current = next;
    }
    Ok(current)
}

/// Message keys derived for positions that have not arrived, each tagged with
/// the slot it must be filed under.
pub type SkippedBatch = Vec<(KeySlot, MessageKey)>;

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

    /// Borrow the key for a slot without consuming it.
    ///
    /// Separate from [`Self::take`] because a key must only be removed once the
    /// frame that claimed it has authenticated; taking first and reinserting on
    /// failure would make a failed open observable in the cache's ordering.
    pub fn peek(&self, slot: &KeySlot) -> Option<&MessageKey> {
        self.entries.iter().find(|(s, _)| s == slot).map(|(_, k)| k)
    }

    /// Whether a slot is held, without consuming it.
    pub fn contains(&self, slot: &KeySlot) -> bool {
        self.entries.iter().any(|(s, _)| s == slot)
    }

    /// Rebuild a cache from a snapshot's entries and its eviction count.
    ///
    /// Takes the entries in the order they were held, because that order is what
    /// decides which key eviction destroys next; rebuilding it as a set would
    /// make a restart quietly re-pick the victim.
    ///
    /// **Takes the whole deque by value and never copies out of it.** Moving keys
    /// between two collections would leave a copy of every message key in the
    /// abandoned buffer, which is freed without being zeroized — the exact leak
    /// [`Self::new`]'s pre-allocation exists to avoid. The decoder builds this
    /// deque at full capacity and it is adopted unchanged.
    ///
    /// Refuses more entries than [`SKIPPED_KEY_CAPACITY`] rather than dropping
    /// the excess, which would silently destroy keys from a record we ourselves
    /// wrote and leave `evicted` understating the loss.
    ///
    /// Refuses a repeated [`KeySlot`] for the same reason: [`Self::insert`]
    /// maintains one entry per slot, so a second is capacity that no lookup can
    /// ever reach — [`Self::peek`] and [`Self::take`] both stop at the first
    /// match — while still counting toward the bound and toward
    /// [`DeliveryLosses::pending`], which reports it as a message still
    /// recoverable.
    fn restore(
        entries: VecDeque<(KeySlot, MessageKey)>,
        evicted: u64,
    ) -> Result<Self, RatchetSnapshotError> {
        if entries.len() > SKIPPED_KEY_CAPACITY {
            return Err(RatchetSnapshotError::TooManySkippedKeys {
                count: entries.len(),
                max: SKIPPED_KEY_CAPACITY,
            });
        }
        // Quadratic over a deque bounded at `SKIPPED_KEY_CAPACITY`, run once per
        // restore. A hash set would need a copy of every slot to build.
        for (at, (slot, _)) in entries.iter().enumerate() {
            if entries.iter().skip(at + 1).any(|(later, _)| later == slot) {
                return Err(RatchetSnapshotError::DuplicateSkippedKey { slot: *slot });
            }
        }
        Ok(Self { entries, evicted })
    }
}

/// How many of our own ephemeral secrets to keep, indexed by the generation that
/// published them.
///
/// **The lookup provably only ever matches the newest.** Our generations and the
/// peer's are disjoint — they alternate — so an ephemeral tagged with the peer's
/// generation cannot exist; and a step is taken only against a peer ephemeral we
/// have not consumed, which pins the newest of ours at exactly one past the
/// generation we receive on. An advancing frame is therefore always looking for
/// the one at the back. An older frame never reaches the lookup at all: its key
/// is in the skipped-key cache, and that path returns first.
///
/// The second is kept as a margin against that reasoning being wrong, not because
/// any path needs it — a mistake there kills the conversation permanently, while
/// the cost of being wrong in this direction is one retained decapsulation key.
/// It is not, as an earlier comment here claimed, there to cover reordering.
pub const EPHEMERAL_WINDOW: usize = 2;

/// The first channel sequence number the initiator uses.
///
/// **One, not zero** — the initiator's sequence zero is the first-contact entry,
/// which travels via the recipient's doorbell rather than the channel. Keeping
/// one monotonic sequence per direction across the whole conversation is what
/// lets the delivery acknowledgement's contiguous prefix confirm the opening
/// message; a channel-local numbering would force it to special-case the one
/// message that did not arrive by channel. The consequence is that the
/// initiator's first page has an empty first slot, which is harmless because a
/// page is judged reached by holding any populated slot, never by being full.
pub const FIRST_INITIATOR_CHANNEL_SEQ: u64 = 1;

/// The first channel sequence number the recipient uses — its opening reply,
/// which is the first thing either party writes to the channel itself.
pub const FIRST_RECIPIENT_CHANNEL_SEQ: u64 = 0;

redacted_secret_newtype! {
    /// The secret half of one of our ratchet ephemerals.
    boxed pub struct EphemeralDecapKey([u8; ml_kem::DK_LEN]);
}

impl EphemeralDecapKey {
    /// Take ownership of a decapsulation key.
    ///
    /// The macro that builds this newtype gives it a private field, which is
    /// right for the seeds it was written for — those are only ever *produced*
    /// inside their own module. This one is an *input*, so it needs a way in.
    pub fn new(dk: Box<[u8; ml_kem::DK_LEN]>) -> Self {
        Self(dk)
    }

    /// Whether this key is the secret half of `ek`.
    ///
    /// **Worth checking, because getting it wrong is silent.** ML-KEM
    /// decapsulation never fails — a mismatched key yields a pseudorandom shared
    /// secret rather than an error — so an initiator opened with two halves of
    /// different keypairs would derive a wrong root at the first ratchet step and
    /// then reject every reply forever, indistinguishably from tampering.
    ///
    /// FIPS 203 embeds the encapsulation key inside the decapsulation key
    /// (`dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`), so this is a memcmp against a slice we
    /// already hold rather than a derivation.
    pub fn matches(&self, ek: &[u8; ml_kem::EK_LEN]) -> bool {
        const EK_OFFSET: usize = ml_kem::DK_LEN - ml_kem::EK_LEN - 64;
        &self.as_bytes()[EK_OFFSET..EK_OFFSET + ml_kem::EK_LEN] == ek.as_slice()
    }
}

/// One of our ephemeral keypairs, tagged with the generation that published it.
struct Ephemeral {
    generation: u32,
    ek: Box<[u8; ml_kem::EK_LEN]>,
    dk: EphemeralDecapKey,
}

impl std::fmt::Debug for Ephemeral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ephemeral(generation: {}, <redacted>)", self.generation)
    }
}

/// One direction's chain under one root, and where along it we are.
#[derive(Clone, Debug)]
struct Chain {
    generation: u32,
    direction: Direction,
    key: ChainKey,
    /// The sequence number of this chain's first message.
    base: u64,
    /// The next sequence number this chain will produce a key for.
    next: u64,
}

impl Chain {
    fn slot(&self, seq: u64) -> KeySlot {
        KeySlot {
            generation: self.generation,
            direction: self.direction,
            seq,
        }
    }

    /// Advance to `target`, returning the keys stepped over, the key at the
    /// target, and the chain positioned after it.
    /// Advance to `target`, returning the keys worth keeping, the key at the
    /// target, the chain positioned after it, and how many keys were walked past
    /// without being kept.
    ///
    /// **A gap wider than one catch-up loses its oldest keys rather than the
    /// message that revealed it.** Refusing outright would be the safer-looking
    /// choice and is the wrong one: a chain has no index, so a receiver that
    /// refuses can never move its cursor, every later frame on that chain sits
    /// further ahead still, and the whole inbound direction dies while continuing
    /// to look alive from both ends. The frozen design's residual is bounded
    /// per-message loss, never unbounded-downstream loss — so the oldest keys past
    /// the retention bound are dropped, counted, and the arriving message opens.
    ///
    /// **The successor cursor is computed with `checked_add`, not `+ 1`.** The
    /// workspace defines no `[profile.release]`, so `overflow-checks` is off in
    /// release and a target at [`u64::MAX`] would wrap the cursor to zero rather
    /// than panic — silently rewriting the write-once page slot sequence zero
    /// already owns.
    fn advance_to(
        self,
        target: u64,
    ) -> Result<(SkippedBatch, u64, MessageKey, Self), RatchetError> {
        if target < self.next {
            return Err(RatchetError::AlreadyConsumed {
                generation: self.generation,
                seq: target,
            });
        }
        let after = target
            .checked_add(1)
            .ok_or(RatchetError::SequenceExhausted { seq: target })?;
        let Self {
            generation,
            direction,
            base,
            ..
        } = self;
        let gap = target - self.next;
        if gap > MAX_CATCH_UP {
            return Err(RatchetError::BacklogTooWide {
                gap,
                max: MAX_CATCH_UP,
            });
        }
        let abandoned = gap.saturating_sub(MAX_SKIP as u64);
        let from = self.slot(self.next + abandoned);
        let key = if abandoned > 0 {
            burn(self.key, abandoned)?
        } else {
            self.key
        };
        let (skipped, key) = skip(key, from, gap - abandoned)?;
        let (message_key, next_key) = chain_step(key)?;
        Ok((
            skipped,
            abandoned,
            message_key,
            Self {
                key: next_key,
                next: after,
                base,
                generation,
                direction,
            },
        ))
    }

    /// Derive every remaining key up to (but not including) `end` and discard the
    /// chain — what a receiver does to the previous chain when the peer ratchets.
    ///
    /// Returns the keys derived and, when the gap is wider than one catch-up can
    /// cover, how many were **abandoned** instead.
    ///
    /// **Abandoning rather than refusing is the whole point.** `end` arrives in a
    /// frame we have not authenticated, so the work has to be bounded; but
    /// refusing outright would drop the arriving message too, and every later
    /// frame from that peer carries a wider gap still — so one long absence would
    /// wedge the conversation permanently in a direction that still looks alive
    /// from both ends. The frozen design already accepts losing keys past the
    /// bound; it does not accept losing the conversation. So the old chain is let
    /// go, the count is reported, and the message that triggered it still opens.
    fn drain_to(self, end: u64) -> Result<(SkippedBatch, u64), RatchetError> {
        let count = end.saturating_sub(self.next);
        if count > MAX_CATCH_UP {
            // Too far gone to walk. The chain is being retired anyway, so the
            // whole of its remaining backlog is written off at no cost — which is
            // what stops an unauthenticated `chain_base` buying unbounded work.
            return Ok((Vec::new(), count));
        }
        let keep = count.min(MAX_SKIP as u64);
        let abandoned = count - keep;
        let from = self.slot(self.next + abandoned);
        // Walking the whole gap would be unbounded work on an unauthenticated
        // number, and the chain is discarded here anyway — so the oldest keys are
        // written off without being derived at all. That is only sound because
        // this chain is being retired: nothing downstream needs the positions it
        // skips over.
        let key = if abandoned > 0 {
            burn(self.key, abandoned)?
        } else {
            self.key
        };
        let (drained, _spent) = skip(key, from, keep)?;
        Ok((drained, abandoned))
    }
}

/// What a frame carries about its place in the ratchet.
///
/// `chain_base` is the frozen design's `PN` stated absolutely rather than as a
/// count. Sequence numbers here are monotonic per direction across the whole
/// conversation — they address the page a message lives in — unlike a per-chain
/// index that restarts at every ratchet step, so an absolute base is both
/// unambiguous under loss and directly usable: it is exactly where the previous
/// chain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Which root this message's chain hangs from.
    pub generation: u32,
    /// The sequence number of the first message of this chain.
    pub chain_base: u64,
    /// This message's sequence number.
    pub seq: u64,
}

/// A message key to seal with, and everything the frame must carry to let the
/// far end derive it.
pub struct Outbound {
    pub key: MessageKey,
    pub header: FrameHeader,
    /// The direction this message travels — what the authorship signature and the
    /// page address must bind, taken from here rather than re-derived per site.
    pub direction: Direction,
    /// The ciphertext that created this generation, repeated on **every** message
    /// of it. Without the repetition, losing the one message that opened a
    /// generation would make the whole rest of the conversation undecryptable
    /// rather than costing that single message. `None` only in the initiator's
    /// opening burst, which hangs from the first-contact secret directly.
    pub eph_ct: Option<Box<[u8; ml_kem::CT_LEN]>>,
    /// Our current ephemeral. The far end encapsulates to it to take the next
    /// generation step, which is the point at which our compromise heals.
    pub eph_ek: Box<[u8; ml_kem::EK_LEN]>,
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound")
            .field("header", &self.header)
            .field("has_eph_ct", &self.eph_ct.is_some())
            .finish_non_exhaustive()
    }
}

/// The conversation's live ratchet state.
///
/// Holds the current root, the two chains, our recent ephemerals and the
/// skipped-key cache. One per conversation — [`KeySlot`] identifies a key within
/// a channel, not across channels, so the cache inside must not be shared.
///
/// ## Generations alternate, and that is what makes the ephemeral lookup work
///
/// A generation belongs to exactly one sender: the initiator opens at generation
/// zero, the recipient's reply is generation one, the initiator's next send is
/// two. A party can only step by encapsulating to an ephemeral the other side
/// published, and the only way to publish one is to send — so a peer can never be
/// more than one generation ahead of our last send. A frame at generation `G`
/// therefore always targets the ephemeral we published at `G-1`, which needs no
/// selector on the wire, and skipping a whole generation is structurally
/// impossible rather than merely unlikely.
///
/// ## Receiving never mutates on an unauthenticated frame
///
/// [`Self::receive`] takes the caller's open-and-verify as a closure and applies
/// its state changes only if that closure succeeds. This is deliberate rather
/// than convenient: a frame's sequence number cannot be checked before the key it
/// names has been derived, so a peer could otherwise name a distant sequence
/// number, make us fill the skipped-key cache with keys nobody will ever ask for,
/// and permanently strand messages it has already published — one write, and the
/// backlog is gone. Deriving the keys costs bounded work; *committing* them is
/// what does damage, and that now cannot happen for a frame that did not open.
pub struct Ratchet {
    role: Role,
    generation: u32,
    root: RootKey,
    send: Option<Chain>,
    recv: Option<Chain>,
    ephemerals: VecDeque<Ephemeral>,
    /// The peer's latest ephemeral, tagged with the generation that published it.
    peer_eph: Option<(u32, Box<[u8; ml_kem::EK_LEN]>)>,
    /// The generation of the peer ephemeral we last stepped against.
    ///
    /// **This comparison is what stops a burst re-stepping the ratchet.** A
    /// generation's ephemeral is repeated on every one of its messages, so
    /// without it each arriving frame would look like a fresh ephemeral and our
    /// next send would step again against a key we had already used —
    /// encapsulating to an ephemeral the peer has moved past, leaving it unable
    /// to derive the step at all. Only the generation tag distinguishes the
    /// repeats; the ephemeral bytes are identical.
    ///
    /// An older frame arriving late cannot rewind this, because its key comes
    /// from the skipped-key cache and that path returns before any ephemeral is
    /// recorded.
    consumed_peer_generation: Option<u32>,
    gen_ct: Option<Box<[u8; ml_kem::CT_LEN]>>,
    next_send_seq: u64,
    skipped: SkippedKeys,
    abandoned: u64,
}

/// What the ratchet has had to give up, and what it is still holding.
///
/// Named rather than a bare tuple of counts, which would be transposable at the
/// call site — and these three mean very different things to a user interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLosses {
    /// Skipped keys currently held for messages that have not arrived.
    pub pending: usize,
    /// Keys dropped to stay inside the cache bound. Each is a message that can no
    /// longer be read.
    pub evicted: u64,
    /// Keys never derived because a peer got further ahead in one generation than
    /// a single catch-up covers. Each is likewise a message that can no longer be
    /// read, but the cause is a long absence rather than a crowded cache.
    pub abandoned: u64,
}

impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet")
            .field("role", &self.role)
            .field("generation", &self.generation)
            .field("next_send_seq", &self.next_send_seq)
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

impl Ratchet {
    /// Open the ratchet as the party that sent the first-contact entry.
    ///
    /// `eph_ek` / `eph_dk` are the opening ratchet ephemeral the entry carried —
    /// the recipient encapsulates to it in its reply, and without the secret half
    /// that first step, and the forward secrecy it establishes, is lost.
    pub fn initiator(
        ss0: &[u8; 32],
        eph_ek: Box<[u8; ml_kem::EK_LEN]>,
        eph_dk: EphemeralDecapKey,
    ) -> Result<Self, RatchetError> {
        if !eph_dk.matches(&eph_ek) {
            return Err(RatchetError::MismatchedEphemeral);
        }
        let root = derive_root(ss0)?;
        let send = Chain {
            generation: 0,
            direction: Direction::AToB,
            key: chain_key(&root, Direction::AToB)?,
            base: FIRST_INITIATOR_CHANNEL_SEQ,
            next: FIRST_INITIATOR_CHANNEL_SEQ,
        };
        let mut ephemerals = VecDeque::with_capacity(EPHEMERAL_WINDOW);
        ephemerals.push_back(Ephemeral {
            generation: 0,
            ek: eph_ek,
            dk: eph_dk,
        });
        Ok(Self {
            role: Role::Initiator,
            generation: 0,
            root,
            send: Some(send),
            recv: None,
            ephemerals,
            peer_eph: None,
            consumed_peer_generation: None,
            gen_ct: None,
            next_send_seq: FIRST_INITIATOR_CHANNEL_SEQ,
            skipped: SkippedKeys::new(),
            abandoned: 0,
        })
    }

    /// Open the ratchet as the party that was knocked at, from the verified entry.
    ///
    /// `peer_eph_ek` is the initiator's opening ephemeral. Holding it is what lets
    /// the first reply take the generation step that begins forward secrecy.
    pub fn recipient(
        ss0: &[u8; 32],
        peer_eph_ek: Box<[u8; ml_kem::EK_LEN]>,
    ) -> Result<Self, RatchetError> {
        let root = derive_root(ss0)?;
        let recv = Chain {
            generation: 0,
            direction: Direction::AToB,
            key: chain_key(&root, Direction::AToB)?,
            base: FIRST_INITIATOR_CHANNEL_SEQ,
            next: FIRST_INITIATOR_CHANNEL_SEQ,
        };
        Ok(Self {
            role: Role::Recipient,
            generation: 0,
            root,
            send: None,
            recv: Some(recv),
            ephemerals: VecDeque::with_capacity(EPHEMERAL_WINDOW),
            peer_eph: Some((0, peer_eph_ek)),
            consumed_peer_generation: None,
            gen_ct: None,
            next_send_seq: FIRST_RECIPIENT_CHANNEL_SEQ,
            skipped: SkippedKeys::new(),
            abandoned: 0,
        })
    }

    /// Which end of the conversation this is.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The current root generation.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// What this conversation is holding and what it has lost. Both loss counts
    /// are permanent and belong in front of a user, not only in a log.
    pub fn losses(&self) -> DeliveryLosses {
        DeliveryLosses {
            pending: self.skipped.len(),
            evicted: self.skipped.evicted(),
            abandoned: self.abandoned,
        }
    }

    /// The direction we send on, and the one we receive on.
    ///
    /// Exposed because the frame layer needs the direction at three places per
    /// message — the authorship signature, the page address, and the receive-side
    /// signature reconstruction — and mapping a role onto a direction by hand at
    /// each of them is exactly what [`Role`] exists to prevent.
    pub fn send_direction(&self) -> Direction {
        self.role.send_dir()
    }

    /// See [`Self::send_direction`].
    pub fn recv_direction(&self) -> Direction {
        self.role.recv_dir()
    }

    /// Mint the key for our next outbound message, taking a generation step first
    /// if the peer has published a fresh ephemeral since our last one.
    pub fn send_next(&mut self) -> Result<Outbound, RatchetError> {
        if let Some((generation, _)) = self.peer_eph.as_ref()
            && self.consumed_peer_generation != Some(*generation)
        {
            self.step_forward()?;
        }
        // Cloned rather than taken: `advance_to` consumes the chain, so taking it
        // out and restoring it afterwards would destroy it on any failure in
        // between and leave this conversation unable to send anything ever again
        // — from a transient crypto-module fault, and reported as though the
        // conversation had never been established.
        let chain = self.send.clone().ok_or(RatchetError::NotYetEstablished)?;
        let seq = self.next_send_seq;
        let (skipped, abandoned, key, chain) = chain.advance_to(seq)?;
        debug_assert!(skipped.is_empty(), "sending never skips its own chain");
        debug_assert_eq!(abandoned, 0, "sending never walks past its own chain");

        let header = FrameHeader {
            generation: chain.generation,
            chain_base: chain.base,
            seq,
        };
        let eph_ek = self
            .ephemerals
            .back()
            .ok_or(RatchetError::NotYetEstablished)?
            .ek
            .clone();

        self.send = Some(chain);
        self.next_send_seq += 1;
        Ok(Outbound {
            key,
            header,
            direction: self.role.send_dir(),
            eph_ct: self.gen_ct.clone(),
            eph_ek,
        })
    }

    /// Take a generation step: encapsulate to the peer's latest ephemeral, re-root
    /// the ratchet on the result, mint a fresh ephemeral of our own, and start a
    /// new sending chain.
    fn step_forward(&mut self) -> Result<(), RatchetError> {
        let (peer_generation, peer_ek) = self
            .peer_eph
            .clone()
            .ok_or(RatchetError::NotYetEstablished)?;

        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).map_err(|_| RatchetError::EntropySource)?;
        let encapsulated = ml_kem::encapsulate(&peer_ek, &m);
        m.zeroize();
        let (mut ss, ct) = encapsulated.map_err(RatchetError::Module)?;

        // The clone is deliberate: `advance_root` consumes its input so a spent
        // root cannot be reused, and the clone is zeroized when it is consumed
        // while assigning the successor drops (and zeroizes) the original.
        let advanced = advance_root(self.root.clone(), &ss);
        ss.zeroize();
        let root = advanced?;

        let mut d = [0u8; ml_kem::SEED_LEN];
        let mut z = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut d).map_err(|_| RatchetError::EntropySource)?;
        getrandom::fill(&mut z).map_err(|_| RatchetError::EntropySource)?;
        let generated = ml_kem::keygen(&d, &z);
        d.zeroize();
        z.zeroize();
        let (ek, mut dk) = generated.map_err(RatchetError::Module)?;

        let generation = self
            .generation
            .checked_add(1)
            .ok_or(RatchetError::GenerationExhausted)?;
        let send = Chain {
            generation,
            direction: self.role.send_dir(),
            key: chain_key(&root, self.role.send_dir())?,
            base: self.next_send_seq,
            next: self.next_send_seq,
        };

        self.root = root;
        self.generation = generation;
        self.send = Some(send);
        self.gen_ct = Some(Box::new(ct));
        self.consumed_peer_generation = Some(peer_generation);
        self.ephemerals.push_back(Ephemeral {
            generation,
            ek: Box::new(ek),
            dk: EphemeralDecapKey(Box::new(dk)),
        });
        dk.zeroize();
        while self.ephemerals.len() > EPHEMERAL_WINDOW {
            self.ephemerals.pop_front();
        }
        Ok(())
    }

    /// Derive the key for an inbound frame, hand it to `open`, and advance the
    /// ratchet **only if `open` succeeds**.
    ///
    /// `open` returns `Err` for a frame that did not authenticate; the ratchet is
    /// then untouched, including the skipped-key cache, and the caller's own error
    /// comes back unchanged so it can still tell a bad tag from a bad signature.
    /// See the type docs for why that ordering is load-bearing rather than tidy.
    ///
    /// A duplicate of a message already opened returns
    /// [`RatchetError::AlreadyConsumed`]: its key was used once and destroyed.
    /// Re-seeding means duplicates are ordinary traffic, so a caller is expected to
    /// discard them by content address before reaching here.
    pub fn receive<T, E>(
        &mut self,
        header: &FrameHeader,
        eph_ct: Option<&[u8; ml_kem::CT_LEN]>,
        peer_eph_ek: &[u8; ml_kem::EK_LEN],
        open: impl FnOnce(&MessageKey) -> Result<T, E>,
    ) -> Result<Result<T, E>, RatchetError> {
        if header.seq < header.chain_base {
            return Err(RatchetError::SeqBeforeChainBase {
                chain_base: header.chain_base,
                seq: header.seq,
            });
        }
        let direction = self.role.recv_dir();
        let slot = KeySlot {
            generation: header.generation,
            direction,
            seq: header.seq,
        };

        // A message we had already stepped past. Its key is spoken for; nothing
        // else about the ratchet moves.
        if let Some(cached) = self.skipped.peek(&slot) {
            let key = cached.clone();
            let outcome = open(&key);
            if outcome.is_ok() {
                self.skipped.take(&slot);
            }
            return Ok(outcome);
        }

        let current = self.recv.as_ref().map(|c| c.generation);
        let advancing = match current {
            Some(g) if header.generation == g => false,
            Some(g) if header.generation > g => true,
            None => true,
            Some(current) => {
                return Err(RatchetError::GenerationTooOld {
                    frame: header.generation,
                    current,
                });
            }
        };

        // Everything below is computed against clones, so an unauthenticated
        // frame leaves no trace.
        let (drained, abandoned, next_root, chain) = if advancing {
            let ct = eph_ct.ok_or(RatchetError::MissingCiphertext {
                generation: header.generation,
            })?;
            let target =
                header
                    .generation
                    .checked_sub(1)
                    .ok_or(RatchetError::UnknownEphemeral {
                        generation: header.generation,
                    })?;
            let eph = self
                .ephemerals
                .iter()
                .find(|e| e.generation == target)
                .ok_or(RatchetError::UnknownEphemeral {
                    generation: header.generation,
                })?;
            let mut ss =
                ml_kem::decapsulate(eph.dk.as_bytes(), ct).map_err(RatchetError::Module)?;
            let advanced = advance_root(self.root.clone(), &ss);
            ss.zeroize();
            let next_root = advanced?;

            // Run the previous chain out to where this one starts, so the messages
            // still in flight behind the ratchet step stay readable.
            let (drained, abandoned) = match self.recv.clone() {
                Some(old) => old.drain_to(header.chain_base)?,
                None => (Vec::new(), 0),
            };
            let chain = Chain {
                generation: header.generation,
                direction,
                key: chain_key(&next_root, direction)?,
                base: header.chain_base,
                next: header.chain_base,
            };
            (drained, abandoned, Some(next_root), chain)
        } else {
            let chain = self.recv.clone().ok_or(RatchetError::NotYetEstablished)?;
            (Vec::new(), 0, None, chain)
        };

        let (skipped, walked_past, key, chain) = chain.advance_to(header.seq)?;

        let outcome = open(&key);
        let Ok(_) = &outcome else {
            return Ok(outcome);
        };

        if let Some(root) = next_root {
            self.root = root;
            self.generation = self.generation.max(header.generation);
        }
        self.abandoned += abandoned + walked_past;
        self.skipped.insert_all(drained);
        self.skipped.insert_all(skipped);
        self.recv = Some(chain);
        self.peer_eph = Some((header.generation, Box::new(*peer_eph_ek)));
        Ok(outcome)
    }

    /// Everything this conversation needs to come back exactly where it is.
    ///
    /// Infallible and non-destructive: the live ratchet is untouched and keeps
    /// working, so a client may snapshot on a cadence rather than only at
    /// shutdown. The cost is not merely a duplicate of every key the conversation
    /// holds: each snapshot a cadence leaves behind on the medium is a
    /// forward-secrecy rollback point for as long as it survives there. See
    /// [`RatchetSnapshot`] for the erasure that obliges of the caller.
    pub fn snapshot(&self) -> RatchetSnapshot {
        // Two separately-persisted numbers that are always equal, checked where
        // they are read rather than only where they are written back — see
        // `RatchetSnapshotError::SendCursorMismatch`.
        debug_assert!(
            self.send
                .as_ref()
                .is_none_or(|c| c.next == self.next_send_seq),
            "the sending chain's cursor and next_send_seq have diverged"
        );
        // Likewise: the sending chain and our newest ephemeral are created in one
        // operation at both sites that create either, so their generations are
        // one fact recorded twice — see `RatchetSnapshotError::
        // EphemeralGenerationMismatch`, which is where it is read back.
        debug_assert_eq!(
            self.send.as_ref().map(|c| c.generation),
            self.ephemerals.back().map(|e| e.generation),
            "the sending chain and the newest ephemeral name different generations"
        );

        let mut skipped = VecDeque::with_capacity(SKIPPED_KEY_CAPACITY);
        for (slot, key) in &self.skipped.entries {
            skipped.push_back((*slot, key.clone()));
        }

        RatchetSnapshot {
            role: self.role,
            generation: self.generation,
            root: self.root.clone(),
            send: self.send.as_ref().map(ChainSnapshot::of),
            recv: self.recv.as_ref().map(ChainSnapshot::of),
            ephemerals: self.ephemerals.iter().map(EphemeralSnapshot::of).collect(),
            peer_eph: self
                .peer_eph
                .as_ref()
                .map(|(generation, ek)| (*generation, ek.clone())),
            consumed_peer_generation: self.consumed_peer_generation,
            gen_ct: self.gen_ct.clone(),
            next_send_seq: self.next_send_seq,
            skipped,
            evicted: self.skipped.evicted(),
            abandoned: self.abandoned,
        }
    }

    /// Rebuild a conversation from its snapshot.
    ///
    /// Every check here is an integrity check on a record **we** wrote, and which
    /// its store is expected to seal — not a parse of anything a peer supplied.
    /// Each exists because the alternative is a ratchet that runs on and derives
    /// wrong keys. ML-KEM decapsulation never fails, so a restored state that is
    /// subtly wrong does not announce itself: it rejects every message the peer
    /// sends, forever, exactly as tampering would.
    ///
    /// **What these catch is corruption and *partial* rollback** — one field
    /// older or otherwise inconsistent with the rest. A rollback to a wholly
    /// consistent *earlier* snapshot passes every check here, because such a
    /// record is indistinguishable from the state it once was; the one rollback
    /// that matters is therefore not detected in this module, and closing it
    /// needs a monotonic counter outside it. See [`RatchetSnapshot`] for the
    /// erasure obligation that keeps such a record from existing.
    pub fn restore(snapshot: RatchetSnapshot) -> Result<Self, RatchetSnapshotError> {
        let RatchetSnapshot {
            role,
            generation,
            root,
            send,
            recv,
            ephemerals,
            peer_eph,
            consumed_peer_generation,
            gen_ct,
            next_send_seq,
            skipped,
            evicted,
            abandoned,
        } = snapshot;

        // The direction of each chain is not stored: it is a function of the
        // role, and a second copy could disagree with it. Disagreeing here means
        // deriving one chain for both directions, which is the deletion wedge
        // `Role` exists to prevent.
        let send = send.map(|c| c.into_chain(role.send_dir()));
        let recv = recv.map(|c| c.into_chain(role.recv_dir()));

        // An initiator has had a sending chain since it was constructed and a
        // recipient a receiving one; neither is ever removed. A snapshot missing
        // its role's chain is not a state this module can produce.
        let established = match role {
            Role::Initiator => send.is_some(),
            Role::Recipient => recv.is_some(),
        };
        if !established {
            return Err(RatchetSnapshotError::MissingChain { role });
        }

        for chain in [send.as_ref(), recv.as_ref()].into_iter().flatten() {
            if chain.next < chain.base {
                return Err(RatchetSnapshotError::ChainCursorBeforeBase {
                    base: chain.base,
                    next: chain.next,
                });
            }
            // One step short of wrapping. `Chain::advance_to` refuses the step
            // rather than wrapping, so accepting this restores a conversation
            // that is permanently unable to move in that direction; refusing
            // here fails at the record instead of at the first message.
            if chain.next == u64::MAX {
                return Err(RatchetSnapshotError::ChainCursorExhausted {
                    direction: chain.direction,
                });
            }
            // A chain is created at the generation the conversation is at or
            // moves to, and the conversation's own counter never goes back — so
            // a chain ahead of it is corruption. Accepting one is silent in the
            // worst direction: the sending chain's generation is what every
            // outbound header announces, so a chain restored ahead would state a
            // root the key it carries was not derived from. Loud at the peer,
            // silent here, and that direction never recovers.
            if chain.generation > generation {
                return Err(RatchetSnapshotError::ChainGenerationAhead {
                    direction: chain.direction,
                    chain: chain.generation,
                    generation,
                });
            }
        }

        // The two numbers are separately persisted and always equal, so a
        // disagreement is corruption. Accepting one would seal messages under
        // keys at positions their own headers do not claim — a silent
        // wrong-key failure indistinguishable from tampering at the far end.
        //
        // The chainless case is checked too, not skipped: a recipient that has
        // not yet sent is the one state with no chain to compare against, and it
        // has exactly one legal sequence number. Leaving it unchecked would let
        // the only value that can be wrong there be the only one nothing looks
        // at — and a sequence number restored too high writes a frame into a
        // page slot no reader will look in, while one restored too low reuses a
        // position the write-once mapping assumes is untouched.
        let expected = match send.as_ref() {
            Some(chain) => chain.next,
            None => FIRST_RECIPIENT_CHANNEL_SEQ,
        };
        if next_send_seq != expected {
            return Err(RatchetSnapshotError::SendCursorMismatch {
                expected,
                next_send_seq,
            });
        }

        if ephemerals.len() > EPHEMERAL_WINDOW {
            return Err(RatchetSnapshotError::TooManyEphemerals {
                count: ephemerals.len(),
                max: EPHEMERAL_WINDOW,
            });
        }

        // A sending chain and an ephemeral of our own are created together, at
        // both sites that create either — the initiator's constructor and
        // `step_forward` — and the window is trimmed from the front only once it
        // is over-full, so neither outlives the other. Restoring a sending chain
        // without one leaves a conversation that is established and permanently
        // unable to send, reporting itself as `NotYetEstablished` — the one error
        // name that describes the opposite of what happened. (A recipient
        // legitimately holds neither until it first sends, which is why this is
        // keyed on the chain rather than the role.)
        if send.is_some() && ephemerals.is_empty() {
            return Err(RatchetSnapshotError::MissingOpeningEphemeral);
        }

        // The mirror on the peer's side. A recipient is handed the initiator's
        // opening ephemeral at construction and only ever replaces it, so a
        // recipient holding none is a state this module cannot produce — and one
        // that restores clean, then reports its first send as `NotYetEstablished`
        // for want of the chain the step it skipped would have created. The same
        // error name describing the opposite of what happened, again. (An
        // initiator legitimately holds none until the first reply, which is why
        // this is not symmetric.)
        if role == Role::Recipient && peer_eph.is_none() {
            return Err(RatchetSnapshotError::MissingPeerEphemeral);
        }

        let mut held: VecDeque<Ephemeral> = VecDeque::with_capacity(EPHEMERAL_WINDOW);
        for eph in ephemerals {
            // The newest is taken from the back, so the order is load-bearing:
            // restored out of order, our next send would publish an ephemeral
            // the peer has already stepped past.
            if let Some(previous) = held.back()
                && previous.generation >= eph.generation
            {
                return Err(RatchetSnapshotError::EphemeralsOutOfOrder {
                    previous: previous.generation,
                    next: eph.generation,
                });
            }
            // The same check the initiator's constructor makes, for the same
            // reason: two halves of different keypairs decapsulate silently to a
            // pseudorandom secret rather than reporting anything.
            if !eph.dk.matches(&eph.ek) {
                return Err(RatchetSnapshotError::MismatchedEphemeral {
                    generation: eph.generation,
                });
            }
            held.push_back(Ephemeral {
                generation: eph.generation,
                ek: eph.ek,
                dk: eph.dk,
            });
        }

        // The generation tags are what an advancing frame is looked up by, and
        // nothing else in this record relates them to the conversation's own
        // counter. A tag that drifted restores clean and then rejects every
        // advancing frame with `UnknownEphemeral`, forever, while outbound keeps
        // working — so it is bracketed here, on two derivable facts.
        //
        // The range: the only thing that lifts `generation` past our newest
        // ephemeral is a step against that ephemeral, which lifts it by exactly
        // one, and nothing lowers it. So the conversation sits at the newest
        // ephemeral's generation or one past it, and nowhere else.
        if let Some(newest) = held.back().map(|e| e.generation)
            && (generation < newest || generation > newest.saturating_add(1))
        {
            return Err(RatchetSnapshotError::EphemeralGenerationOutOfRange { newest, generation });
        }

        // The pairing: both sites that mint an ephemeral start a sending chain
        // at the same generation in the same operation, so the two numbers are
        // one fact recorded twice — checked here rather than only where it is
        // written, exactly as `next_send_seq` is. This is what catches a newest
        // tag one *below* the truth, which the range above cannot: such a tag
        // still brackets `generation` legally while naming an ephemeral no
        // advancing frame will ever ask for.
        if let (Some(send), Some(newest)) = (send.as_ref(), held.back())
            && send.generation != newest.generation
        {
            return Err(RatchetSnapshotError::EphemeralGenerationMismatch {
                send: send.generation,
                newest: newest.generation,
            });
        }

        Ok(Self {
            role,
            generation,
            root,
            send,
            recv,
            ephemerals: held,
            peer_eph,
            consumed_peer_generation,
            gen_ct,
            next_send_seq,
            skipped: SkippedKeys::restore(skipped, evicted)?,
            abandoned,
        })
    }
}

// ---- persistence (#243) -----------------------------------------------------

/// Magic and format version of an encoded [`RatchetSnapshot`].
///
/// **The version is inside the magic, not a field beside it.** A decoder then
/// has exactly one thing to compare and no way to read a v1 body under a v2
/// header — a format that cannot say what it is does not survive its first
/// change, and one that says it twice can contradict itself.
pub const RATCHET_SNAPSHOT_MAGIC: &[u8] = b"daemonseed/dm/ratchet-state/v1\0";

/// Encoded length of one chain: generation, key, base, cursor.
const CHAIN_ENTRY_LEN: usize = 4 + CHAIN_KEY_LEN + 8 + 8;

/// Encoded length of one retained ephemeral: generation, and both halves.
const EPHEMERAL_ENTRY_LEN: usize = 4 + ml_kem::EK_LEN + ml_kem::DK_LEN;

/// Encoded length of one skipped key: its slot's three parts, and the key.
const SKIPPED_ENTRY_LEN: usize = 4 + 1 + 8 + MESSAGE_KEY_LEN;

/// Encoded length of everything that is present unconditionally: the role, the
/// generation, the root, and the three counters.
const FIXED_BODY_LEN: usize = 1 + 4 + ROOT_KEY_LEN + 8 + 8 + 8;

// Discriminants start at one, so a zeroed or truncated-then-padded buffer names
// no valid role, direction, or presence rather than decoding as the first
// variant of each.
const TAG_ABSENT: u8 = 1;
const TAG_PRESENT: u8 = 2;
const ROLE_INITIATOR: u8 = 1;
const ROLE_RECIPIENT: u8 = 2;
const DIR_A2B: u8 = 1;
const DIR_B2A: u8 = 2;

/// Why a snapshot could not be decoded or restored.
///
/// Separate from [`RatchetError`], whose documented property is that nothing in
/// it parses bytes. These variants all do. The bytes come from a record this
/// client wrote, and which its store is expected to seal, so none of them is an
/// authentication failure and there is no reason to make them uniform — each
/// names the specific corruption or partial rollback it caught, which is what a
/// diagnosis needs. None detects a rollback to a wholly consistent earlier
/// record; see [`Ratchet::restore`].
#[derive(Debug, PartialEq, Eq)]
pub enum RatchetSnapshotError {
    /// The bytes do not begin with [`RATCHET_SNAPSHOT_MAGIC`].
    BadMagic,
    /// A field ran off the end of the buffer.
    Truncated,
    /// The buffer holds bytes past the end of the snapshot.
    TrailingBytes { extra: usize },
    /// A role byte that is neither initiator nor recipient.
    InvalidRole { value: u8 },
    /// A direction byte that is neither `a2b` nor `b2a`.
    InvalidDirection { value: u8 },
    /// A presence byte that is neither absent nor present.
    InvalidPresence { value: u8 },
    /// More retained ephemerals than [`EPHEMERAL_WINDOW`].
    TooManyEphemerals { count: usize, max: usize },
    /// More skipped keys than [`SKIPPED_KEY_CAPACITY`].
    TooManySkippedKeys { count: usize, max: usize },
    /// Two entries in the skipped-key cache claim one [`KeySlot`].
    DuplicateSkippedKey { slot: KeySlot },
    /// The snapshot has no chain in the direction its role always sends or
    /// receives on.
    MissingChain { role: Role },
    /// A snapshot with a sending chain retains no ephemeral of its own. The two
    /// are created together, and without the ephemeral every send fails —
    /// reported as a conversation that was never established, which such a
    /// snapshot is not.
    MissingOpeningEphemeral,
    /// A recipient's snapshot holds no ephemeral of the peer's. It has held the
    /// initiator's opening one since construction, and without it the generation
    /// step every reply owes is never taken.
    MissingPeerEphemeral,
    /// A chain's cursor sits before its own first message.
    ChainCursorBeforeBase { base: u64, next: u64 },
    /// A chain's cursor sits at the last sequence number there is, one step from
    /// wrapping to zero.
    ChainCursorExhausted { direction: Direction },
    /// A chain hangs from a generation ahead of the conversation's own. Its
    /// frames would announce a root the key they carry does not come from.
    ChainGenerationAhead {
        direction: Direction,
        chain: u32,
        generation: u32,
    },
    /// The newest retained ephemeral's generation does not bracket the
    /// conversation's own: a step can only lift the generation to one past the
    /// newest ephemeral, and never leaves it behind.
    EphemeralGenerationOutOfRange { newest: u32, generation: u32 },
    /// The newest retained ephemeral was not published by the generation the
    /// sending chain hangs from. The two are created together at every site that
    /// creates either, so a disagreement names an ephemeral no advancing frame
    /// can ask for.
    EphemeralGenerationMismatch { send: u32, newest: u32 },
    /// The next outbound sequence number disagrees with the sending chain's
    /// cursor — or, for a recipient that has not sent, with the one sequence
    /// number it is allowed to start from. No state this module produces can.
    SendCursorMismatch { expected: u64, next_send_seq: u64 },
    /// Retained ephemerals are not in ascending generation order, so the newest
    /// is not the one at the back.
    EphemeralsOutOfOrder { previous: u32, next: u32 },
    /// A retained ephemeral's two halves are not a keypair.
    MismatchedEphemeral { generation: u32 },
}

impl std::fmt::Display for RatchetSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a daemonseed DM ratchet snapshot"),
            Self::Truncated => write!(f, "the snapshot ends mid-field"),
            Self::TrailingBytes { extra } => {
                write!(f, "{extra} bytes follow the end of the snapshot")
            }
            Self::InvalidRole { value } => write!(f, "{value} is not a conversation role"),
            Self::InvalidDirection { value } => write!(f, "{value} is not a message direction"),
            Self::InvalidPresence { value } => write!(f, "{value} is not a presence marker"),
            Self::TooManyEphemerals { count, max } => write!(
                f,
                "the snapshot holds {count} ephemerals, more than the {max} retained"
            ),
            Self::TooManySkippedKeys { count, max } => write!(
                f,
                "the snapshot holds {count} skipped keys, more than the cache's {max}"
            ),
            Self::DuplicateSkippedKey { slot } => write!(
                f,
                "two skipped keys claim generation {} {:?} sequence {}",
                slot.generation, slot.direction, slot.seq
            ),
            Self::MissingChain { role } => {
                write!(f, "a {role:?} snapshot carries no chain of its own")
            }
            Self::MissingOpeningEphemeral => write!(
                f,
                "a snapshot that can send retains no ephemeral of its own"
            ),
            Self::MissingPeerEphemeral => {
                write!(f, "a recipient snapshot holds no ephemeral of the peer's")
            }
            Self::ChainCursorBeforeBase { base, next } => write!(
                f,
                "a chain beginning at {base} has its cursor at {next}, before itself"
            ),
            Self::ChainCursorExhausted { direction } => write!(
                f,
                "the {direction:?} chain's cursor is at the last sequence number there is"
            ),
            Self::ChainGenerationAhead {
                direction,
                chain,
                generation,
            } => write!(
                f,
                "the {direction:?} chain hangs from generation {chain}, ahead of the conversation's {generation}"
            ),
            Self::EphemeralGenerationOutOfRange { newest, generation } => write!(
                f,
                "generation {generation} is not reachable from a newest ephemeral at {newest}"
            ),
            Self::EphemeralGenerationMismatch { send, newest } => write!(
                f,
                "the sending chain hangs from generation {send} while the newest ephemeral is {newest}'s"
            ),
            Self::SendCursorMismatch {
                expected,
                next_send_seq,
            } => write!(
                f,
                "the next sequence is {next_send_seq} where the sending chain says {expected}"
            ),
            Self::EphemeralsOutOfOrder { previous, next } => write!(
                f,
                "ephemeral generation {next} follows {previous}, so the newest is not last"
            ),
            Self::MismatchedEphemeral { generation } => write!(
                f,
                "generation {generation}'s ephemeral halves are not a keypair"
            ),
        }
    }
}

impl std::error::Error for RatchetSnapshotError {}

/// One direction's chain as it stands, in a form that can be written down.
///
/// Carries no direction: that is a function of the [`Role`], which the snapshot
/// holds once. Two copies of one fact can disagree, and the disagreement here
/// derives a single chain for both directions.
///
/// **`base` is read on the sending side only.** A sender puts it in every frame
/// header; a receiver sets it from the header it was given and never looks at it
/// again, so dropping it from a *receiving* chain's snapshot breaks no test —
/// verified by mutation, and the one field here with no oracle behind it. It is
/// persisted anyway, because a `Chain` has a base and a snapshot that silently
/// invented one would be the kind of divergence between the live and restored
/// shapes this whole module refuses to have.
struct ChainSnapshot {
    generation: u32,
    key: ChainKey,
    base: u64,
    next: u64,
}

impl ChainSnapshot {
    fn of(chain: &Chain) -> Self {
        Self {
            generation: chain.generation,
            key: chain.key.clone(),
            base: chain.base,
            next: chain.next,
        }
    }

    fn into_chain(self, direction: Direction) -> Chain {
        Chain {
            generation: self.generation,
            direction,
            key: self.key,
            base: self.base,
            next: self.next,
        }
    }
}

/// One of our ephemeral keypairs, in a form that can be written down.
struct EphemeralSnapshot {
    generation: u32,
    ek: Box<[u8; ml_kem::EK_LEN]>,
    dk: EphemeralDecapKey,
}

impl EphemeralSnapshot {
    fn of(eph: &Ephemeral) -> Self {
        Self {
            generation: eph.generation,
            ek: eph.ek.clone(),
            // Copied through a heap buffer rather than `Box::new(*bytes)`, which
            // would materialise the whole decapsulation key in this stack frame
            // on the way to the allocation and leave it there.
            dk: EphemeralDecapKey::new(boxed_copy(eph.dk.as_bytes())),
        }
    }
}

/// Copy `bytes` into a fresh heap allocation without a stack-sized temporary.
///
/// `Box::new(*array)` builds the array as a value first, so a secret copied that
/// way lives in the caller's frame until something overwrites it — the same
/// hazard [`expand_secret`] exists for. A zeroed `Vec` is allocated on the heap
/// directly and written in place.
fn boxed_copy<const N: usize>(bytes: &[u8; N]) -> Box<[u8; N]> {
    let mut buf = vec![0u8; N].into_boxed_slice();
    buf.copy_from_slice(bytes);
    match buf.try_into() {
        Ok(exact) => exact,
        // Unreachable: the buffer was allocated at exactly `N`. Not `expect`,
        // whose message would render the bytes it failed to convert.
        Err(_) => unreachable!("a buffer allocated at N is N long"),
    }
}

/// Everything a conversation needs to resume, and nothing it can rebuild.
///
/// ## What is in it, and what deliberately is not
///
/// The [`Role`] (which decides both chain directions), the generation, the
/// current root, both chains with their keys and cursors, our retained
/// ephemerals, the peer's latest ephemeral and the generation we last stepped
/// against, the next outbound sequence number, the skipped-key cache in its
/// eviction order, and the two permanent loss counters.
///
/// **Not `ss0`**, which the root already descends from. **Not `AR` or
/// `chan_id`**: `chan_id` is never serialized anywhere — the AAD carries it and
/// a receiver recomputes it from the record it opened, and writing it down
/// collapses the address scatter the whole channel rests on. A caller storing
/// one snapshot per conversation therefore needs its own local identifier for
/// the record; `chan_id` is not it.
///
/// ## This is key material in the clear
///
/// A snapshot holds the root, both chain keys, every skipped message key, and
/// every retained decapsulation key. Every one of those fields is a zeroize-on-
/// drop newtype, so dropping the snapshot destroys them — there is deliberately
/// no `Drop` on the container itself, because that would forbid moving the keys
/// *out* of it and force [`Ratchet::restore`] to clone every one at the moment
/// it is trying not to duplicate them.
///
/// It is **not [`Clone`]**, for the same reason: a snapshot is already a
/// complete duplicate of a conversation's live keys, and the one use for a
/// second copy — encoding it twice — is served by [`Self::encode`] taking
/// `&self`.
///
/// [`Self::encode`] produces the **plaintext** of an at-rest record. It is not
/// sealed, not authenticated, and not integrity-protected; whatever stores it
/// must do to it what the profile store does to the mnemonic.
///
/// ## A superseded snapshot must be erased, not merely replaced
///
/// **A store writes each new snapshot *over* the last one; it does not leave the
/// last one behind.** A superseded snapshot is not a stale copy of secrets that
/// are still current — it is a live decryption capability for a generation the
/// conversation has already left. It carries the root of that generation *and*
/// the decapsulation keys of the ephemerals published in it, and the ciphertexts
/// that generation's frames were sealed under are already on the wire and
/// already recorded by anyone watching. So one recovered superseded snapshot
/// yields the plaintext of every message from its generation forward, up to our
/// next self-generated step — which is precisely the forward secrecy the whole
/// ratchet exists to provide.
///
/// That makes erasure-in-place a **requirement on the store**, not a tidiness
/// preference, and it is the property a naive cadence gets wrong: appending,
/// journaling, or copy-on-write leaves every past snapshot recoverable, and a
/// higher cadence then makes the exposure worse rather than better. This module
/// cannot enforce it — the obligation is stated here because whoever builds the
/// store is the only one who can meet it.
pub struct RatchetSnapshot {
    role: Role,
    generation: u32,
    root: RootKey,
    send: Option<ChainSnapshot>,
    recv: Option<ChainSnapshot>,
    ephemerals: Vec<EphemeralSnapshot>,
    peer_eph: Option<(u32, Box<[u8; ml_kem::EK_LEN]>)>,
    consumed_peer_generation: Option<u32>,
    gen_ct: Option<Box<[u8; ml_kem::CT_LEN]>>,
    next_send_seq: u64,
    skipped: VecDeque<(KeySlot, MessageKey)>,
    evicted: u64,
    abandoned: u64,
}

impl std::fmt::Debug for RatchetSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetSnapshot")
            .field("role", &self.role)
            .field("generation", &self.generation)
            .field("next_send_seq", &self.next_send_seq)
            .field("ephemerals", &self.ephemerals.len())
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

impl RatchetSnapshot {
    /// Exact encoded length, so the buffer is allocated once.
    ///
    /// A growing `Vec` reallocates and copies, leaving key bytes in freed memory
    /// that nothing zeroizes — the same reason [`SkippedKeys::new`] pre-allocates.
    fn encoded_len(&self) -> usize {
        RATCHET_SNAPSHOT_MAGIC.len()
            + FIXED_BODY_LEN
            + 1
            + self.send.as_ref().map_or(0, |_| CHAIN_ENTRY_LEN)
            + 1
            + self.recv.as_ref().map_or(0, |_| CHAIN_ENTRY_LEN)
            + 1
            + self.peer_eph.as_ref().map_or(0, |_| 4 + ml_kem::EK_LEN)
            + 1
            + self.consumed_peer_generation.map_or(0, |_| 4)
            + 1
            + self.gen_ct.as_ref().map_or(0, |_| ml_kem::CT_LEN)
            + 2
            + self.ephemerals.len() * EPHEMERAL_ENTRY_LEN
            + 2
            + self.skipped.len() * SKIPPED_ENTRY_LEN
    }

    /// The at-rest encoding: `MAGIC ‖ body`, every integer big-endian, every
    /// optional field led by a presence marker, every repeated field led by a
    /// `u16` count.
    ///
    /// Fixed-width throughout — a chain key is thirty-two bytes because a chain
    /// key is thirty-two bytes — so there are no interior length prefixes to
    /// disagree with the values they describe.
    ///
    /// The result is [`Zeroizing`] because it is a set of live keys in the
    /// clear: a caller that seals it and drops the plaintext leaves nothing
    /// behind.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(RATCHET_SNAPSHOT_MAGIC);
        out.push(match self.role {
            Role::Initiator => ROLE_INITIATOR,
            Role::Recipient => ROLE_RECIPIENT,
        });
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(self.root.as_bytes());
        out.extend_from_slice(&self.next_send_seq.to_be_bytes());
        out.extend_from_slice(&self.evicted.to_be_bytes());
        out.extend_from_slice(&self.abandoned.to_be_bytes());

        for chain in [self.send.as_ref(), self.recv.as_ref()] {
            match chain {
                None => out.push(TAG_ABSENT),
                Some(chain) => {
                    out.push(TAG_PRESENT);
                    out.extend_from_slice(&chain.generation.to_be_bytes());
                    out.extend_from_slice(chain.key.as_bytes());
                    out.extend_from_slice(&chain.base.to_be_bytes());
                    out.extend_from_slice(&chain.next.to_be_bytes());
                }
            }
        }

        match self.peer_eph.as_ref() {
            None => out.push(TAG_ABSENT),
            Some((generation, ek)) => {
                out.push(TAG_PRESENT);
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(ek.as_slice());
            }
        }

        match self.consumed_peer_generation {
            None => out.push(TAG_ABSENT),
            Some(generation) => {
                out.push(TAG_PRESENT);
                out.extend_from_slice(&generation.to_be_bytes());
            }
        }

        match self.gen_ct.as_ref() {
            None => out.push(TAG_ABSENT),
            Some(ct) => {
                out.push(TAG_PRESENT);
                out.extend_from_slice(ct.as_slice());
            }
        }

        // Both counts fit a `u16` by construction: one is bounded by
        // `EPHEMERAL_WINDOW` and the other by `SKIPPED_KEY_CAPACITY`, and the
        // decoder refuses anything larger before it allocates.
        out.extend_from_slice(&(self.ephemerals.len() as u16).to_be_bytes());
        for eph in &self.ephemerals {
            out.extend_from_slice(&eph.generation.to_be_bytes());
            out.extend_from_slice(eph.ek.as_slice());
            out.extend_from_slice(eph.dk.as_bytes());
        }

        out.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        for (slot, key) in &self.skipped {
            out.extend_from_slice(&slot.generation.to_be_bytes());
            out.push(match slot.direction {
                Direction::AToB => DIR_A2B,
                Direction::BToA => DIR_B2A,
            });
            out.extend_from_slice(&slot.seq.to_be_bytes());
            out.extend_from_slice(key.as_bytes());
        }

        debug_assert_eq!(out.len(), self.encoded_len(), "encoded length drifted");
        Zeroizing::new(out)
    }

    /// Read an encoded snapshot back.
    ///
    /// Rejects a foreign magic, a field that runs off the end, a count past its
    /// bound *before* allocating for it, and bytes trailing the end. What it does
    /// **not** do is check that the state makes sense as a conversation — that is
    /// [`Ratchet::restore`]'s job, which is why the two are separate calls.
    ///
    /// `bytes` still holds every key after this returns; a caller that read them
    /// from a sealed record should keep them in a buffer it zeroizes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetSnapshotError> {
        let mut r = Reader::new(bytes);
        if r.take(RATCHET_SNAPSHOT_MAGIC.len())? != RATCHET_SNAPSHOT_MAGIC {
            return Err(RatchetSnapshotError::BadMagic);
        }

        let role = match r.u8()? {
            ROLE_INITIATOR => Role::Initiator,
            ROLE_RECIPIENT => Role::Recipient,
            value => return Err(RatchetSnapshotError::InvalidRole { value }),
        };
        let generation = r.u32()?;
        let root = r.secret(RootKey)?;
        let next_send_seq = r.u64()?;
        let evicted = r.u64()?;
        let abandoned = r.u64()?;

        let mut chains = [None, None];
        for slot in &mut chains {
            *slot = match r.presence()? {
                false => None,
                true => Some(ChainSnapshot {
                    generation: r.u32()?,
                    key: r.secret(ChainKey)?,
                    base: r.u64()?,
                    next: r.u64()?,
                }),
            };
        }
        let [send, recv] = chains;

        let peer_eph = match r.presence()? {
            false => None,
            true => Some((r.u32()?, r.boxed::<{ ml_kem::EK_LEN }>()?)),
        };
        let consumed_peer_generation = match r.presence()? {
            false => None,
            true => Some(r.u32()?),
        };
        let gen_ct = match r.presence()? {
            false => None,
            true => Some(r.boxed::<{ ml_kem::CT_LEN }>()?),
        };

        let count = r.bounded_count(EPHEMERAL_WINDOW, |count, max| {
            RatchetSnapshotError::TooManyEphemerals { count, max }
        })?;
        let mut ephemerals = Vec::with_capacity(count);
        for _ in 0..count {
            ephemerals.push(EphemeralSnapshot {
                generation: r.u32()?,
                ek: r.boxed::<{ ml_kem::EK_LEN }>()?,
                dk: EphemeralDecapKey::new(r.boxed::<{ ml_kem::DK_LEN }>()?),
            });
        }

        let count = r.bounded_count(SKIPPED_KEY_CAPACITY, |count, max| {
            RatchetSnapshotError::TooManySkippedKeys { count, max }
        })?;
        // At the cache's full capacity, so the deque `restore` adopts never
        // reallocates and no message key is ever copied between buffers.
        let mut skipped = VecDeque::with_capacity(SKIPPED_KEY_CAPACITY);
        for _ in 0..count {
            let slot = KeySlot {
                generation: r.u32()?,
                direction: match r.u8()? {
                    DIR_A2B => Direction::AToB,
                    DIR_B2A => Direction::BToA,
                    value => return Err(RatchetSnapshotError::InvalidDirection { value }),
                },
                seq: r.u64()?,
            };
            skipped.push_back((slot, r.secret(MessageKey)?));
        }

        r.finish()?;
        Ok(Self {
            role,
            generation,
            root,
            send,
            recv,
            ephemerals,
            peer_eph,
            consumed_peer_generation,
            gen_ct,
            next_send_seq,
            skipped,
            evicted,
            abandoned,
        })
    }
}

/// A bounds-checked forward cursor over an encoded snapshot.
///
/// Every read goes through [`Self::take`], so there is one place a length is
/// checked and no call site does its own slicing.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], RatchetSnapshotError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(RatchetSnapshotError::Truncated)?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or(RatchetSnapshotError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, RatchetSnapshotError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RatchetSnapshotError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("checked length"),
        ))
    }

    fn u64(&mut self) -> Result<u64, RatchetSnapshotError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("checked length"),
        ))
    }

    fn presence(&mut self) -> Result<bool, RatchetSnapshotError> {
        match self.u8()? {
            TAG_ABSENT => Ok(false),
            TAG_PRESENT => Ok(true),
            value => Err(RatchetSnapshotError::InvalidPresence { value }),
        }
    }

    /// A count, refused past `max` **before** anything is reserved for it.
    fn bounded_count(
        &mut self,
        max: usize,
        err: impl FnOnce(usize, usize) -> RatchetSnapshotError,
    ) -> Result<usize, RatchetSnapshotError> {
        let count = u16::from_be_bytes(self.take(2)?.try_into().expect("checked length")) as usize;
        if count > max {
            return Err(err(count, max));
        }
        Ok(count)
    }

    /// Read `N` bytes into a key class, zeroizing the transient stack buffer —
    /// the same shape as [`expand_secret`], and for the same reason.
    fn secret<const N: usize, T>(
        &mut self,
        wrap: impl FnOnce([u8; N]) -> T,
    ) -> Result<T, RatchetSnapshotError> {
        let read = self.take(N)?;
        let mut buf = [0u8; N];
        buf.copy_from_slice(read);
        let out = wrap(buf);
        buf.zeroize();
        Ok(out)
    }

    /// Read `N` bytes straight into a heap allocation, with no stack copy at all.
    fn boxed<const N: usize>(&mut self) -> Result<Box<[u8; N]>, RatchetSnapshotError> {
        let read = self.take(N)?;
        let mut buf = vec![0u8; N].into_boxed_slice();
        buf.copy_from_slice(read);
        match buf.try_into() {
            Ok(exact) => Ok(exact),
            Err(_) => unreachable!("a buffer allocated at N is N long"),
        }
    }

    fn finish(self) -> Result<(), RatchetSnapshotError> {
        match self.bytes.len().checked_sub(self.at) {
            Some(0) | None => Ok(()),
            Some(extra) => Err(RatchetSnapshotError::TrailingBytes { extra }),
        }
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
        assert!(
            matches!(
                err,
                RatchetError::SkipTooLarge { requested, max }
                    if requested == MAX_SKIP as u64 + 1 && max == MAX_SKIP
            ),
            "expected a refusal carrying both numbers, got {err:?}"
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

    // ---- the live ratchet ----------------------------------------------------

    /// A fresh ML-KEM keypair for the initiator's opening ephemeral.
    fn opening_ephemeral() -> ([u8; ml_kem::EK_LEN], [u8; ml_kem::DK_LEN]) {
        let _ = oxicrypt_module::initialize();
        let mut d = [0u8; ml_kem::SEED_LEN];
        let mut z = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut d).unwrap();
        getrandom::fill(&mut z).unwrap();
        ml_kem::keygen(&d, &z).unwrap()
    }

    /// Two ratchets over one first-contact secret, as they stand the moment the
    /// recipient has opened the entry.
    fn pair() -> (Ratchet, Ratchet) {
        let ss0 = ss(0x11);
        let (ek, dk) = opening_ephemeral();
        let initiator =
            Ratchet::initiator(&ss0, Box::new(ek), EphemeralDecapKey::new(Box::new(dk))).unwrap();
        let recipient = Ratchet::recipient(&ss0, Box::new(ek)).unwrap();
        (initiator, recipient)
    }

    /// Hand a frame to the far end and return the key it derived.
    fn deliver(to: &mut Ratchet, out: &Outbound) -> Result<Result<[u8; 32], ()>, RatchetError> {
        to.receive(&out.header, out.eph_ct.as_deref(), &out.eph_ek, |k| {
            Ok(*k.as_bytes())
        })
    }

    /// Deliver and assert both ends agree on the key.
    fn deliver_ok(to: &mut Ratchet, out: &Outbound) {
        let got = deliver(to, out)
            .expect("no key-schedule failure")
            .expect("the frame opened");
        assert_eq!(
            &got,
            out.key.as_bytes(),
            "the two ends derived different keys"
        );
    }

    /// The property the whole module exists for: whatever the sender sealed
    /// under, the receiver independently derives.
    #[test]
    fn a_message_opens_at_the_far_end() {
        let (mut a, mut b) = pair();
        let out = a.send_next().unwrap();
        deliver_ok(&mut b, &out);
    }

    /// The initiator's channel sequence starts at one because its sequence zero
    /// is the first-contact entry, which travelled by doorbell. The recipient's
    /// opening reply is the first thing written to the channel itself.
    #[test]
    fn the_two_directions_start_at_the_documented_sequence_numbers() {
        let (mut a, mut b) = pair();
        assert_eq!(
            a.send_next().unwrap().header.seq,
            FIRST_INITIATOR_CHANNEL_SEQ
        );
        assert_eq!(a.send_next().unwrap().header.seq, 2);

        let reply = b.send_next().unwrap();
        assert_eq!(reply.header.seq, FIRST_RECIPIENT_CHANNEL_SEQ);
        assert_eq!(b.send_next().unwrap().header.seq, 1);
    }

    /// Generations belong to one sender each and alternate. This is what makes a
    /// frame at generation `G` always target the ephemeral published at `G-1`,
    /// with no selector on the wire.
    #[test]
    fn generations_alternate_between_the_two_parties() {
        let (mut a, mut b) = pair();

        let opening = a.send_next().unwrap();
        assert_eq!(opening.header.generation, 0);
        assert!(
            opening.eph_ct.is_none(),
            "the opening burst roots in the first-contact secret, not a step"
        );
        deliver_ok(&mut b, &opening);

        let reply = b.send_next().unwrap();
        assert_eq!(reply.header.generation, 1);
        assert!(reply.eph_ct.is_some(), "a reply must carry its step");
        deliver_ok(&mut a, &reply);

        let second = a.send_next().unwrap();
        assert_eq!(second.header.generation, 2);
        deliver_ok(&mut b, &second);

        let third = b.send_next().unwrap();
        assert_eq!(third.header.generation, 3);
        deliver_ok(&mut a, &third);
    }

    /// A run of messages in one direction must NOT keep stepping the ratchet: the
    /// peer publishes one ephemeral per generation and repeats it on every frame,
    /// so treating each repeat as fresh would encapsulate to a key the peer has
    /// already moved past and leave it unable to derive the step at all.
    #[test]
    fn a_repeated_peer_ephemeral_does_not_step_the_ratchet_again() {
        let (mut a, mut b) = pair();
        for _ in 0..3 {
            let out = a.send_next().unwrap();
            deliver_ok(&mut b, &out);
        }

        let first = b.send_next().unwrap();
        let second = b.send_next().unwrap();
        let third = b.send_next().unwrap();
        assert_eq!(first.header.generation, 1);
        assert_eq!(second.header.generation, 1, "a burst is one generation");
        assert_eq!(third.header.generation, 1);

        deliver_ok(&mut a, &first);
        deliver_ok(&mut a, &second);
        deliver_ok(&mut a, &third);
    }

    /// Out-of-order arrival within one chain: the later message opens first, and
    /// the ones it stepped over stay readable.
    #[test]
    fn messages_that_arrive_out_of_order_still_open() {
        let (mut a, mut b) = pair();
        let sent: Vec<_> = (0..4).map(|_| a.send_next().unwrap()).collect();

        deliver_ok(&mut b, &sent[3]);
        assert_eq!(b.losses().pending, 3, "the gap was kept");

        deliver_ok(&mut b, &sent[0]);
        deliver_ok(&mut b, &sent[2]);
        deliver_ok(&mut b, &sent[1]);
        assert_eq!(
            b.losses(),
            DeliveryLosses {
                pending: 0,
                evicted: 0,
                abandoned: 0
            },
            "every gap was filled, none lost"
        );
    }

    /// The case the two-bound cache sizing exists for: messages still in flight
    /// from before a ratchet step must survive the step. The receiver runs the
    /// previous chain out to where the new one begins.
    #[test]
    fn messages_in_flight_survive_a_generation_change() {
        let (mut a, mut b) = pair();
        let burst: Vec<_> = (0..5).map(|_| a.send_next().unwrap()).collect();

        // Only the first of the burst gets through before the reply.
        deliver_ok(&mut b, &burst[0]);
        let reply = b.send_next().unwrap();
        deliver_ok(&mut a, &reply);

        // A ratchets and sends again; that frame reaches B before the stragglers.
        let after_step = a.send_next().unwrap();
        assert_eq!(after_step.header.generation, 2);
        deliver_ok(&mut b, &after_step);

        // The four stragglers from generation 0 still open.
        for straggler in &burst[1..] {
            deliver_ok(&mut b, straggler);
        }
        assert_eq!(b.losses().evicted, 0, "nothing was evicted");
    }

    /// Every message of a generation repeats the ciphertext that created it, so
    /// losing the message that opened a generation costs that message and nothing
    /// more. Without the repetition the whole downstream conversation would be
    /// undecryptable.
    #[test]
    fn losing_the_first_message_of_a_generation_costs_only_that_message() {
        let (mut a, mut b) = pair();
        let opening = a.send_next().unwrap();
        deliver_ok(&mut b, &opening);
        let reply = b.send_next().unwrap();
        deliver_ok(&mut a, &reply);

        let first = a.send_next().unwrap();
        let second = a.send_next().unwrap();
        let third = a.send_next().unwrap();
        assert_eq!(first.header.generation, 2);

        // The generation's opening message never arrives; the second one carries
        // the same ciphertext and establishes the generation on its own.
        deliver_ok(&mut b, &second);
        deliver_ok(&mut b, &third);
        // And the lost one still opens if it turns up later.
        deliver_ok(&mut b, &first);
    }

    /// The load-bearing ordering: a frame that does not authenticate must leave
    /// the ratchet exactly as it was — including the skipped-key cache, which is
    /// what a peer would otherwise be able to flush with one unauthenticated
    /// write.
    #[test]
    fn a_frame_that_does_not_authenticate_changes_nothing() {
        let (mut a, mut b) = pair();
        let sent: Vec<_> = (0..3).map(|_| a.send_next().unwrap()).collect();
        deliver_ok(&mut b, &sent[0]);

        let before = (b.generation(), b.losses());

        // A frame claiming a far-ahead sequence number, which fails to open.
        let hostile = FrameHeader {
            generation: 0,
            chain_base: sent[0].header.chain_base,
            seq: sent[0].header.seq + 40,
        };
        let rejected = b
            .receive(&hostile, None, &sent[0].eph_ek, |_| Err::<(), ()>(()))
            .expect("deriving is allowed; committing is not");
        assert!(rejected.is_err());

        assert_eq!(
            (b.generation(), b.losses()),
            before,
            "an unauthenticated frame moved the ratchet"
        );

        // And the genuine backlog is still readable.
        deliver_ok(&mut b, &sent[1]);
        deliver_ok(&mut b, &sent[2]);
    }

    /// A rejected frame must not consume the cached key it named either.
    #[test]
    fn a_rejected_frame_does_not_consume_a_cached_key() {
        let (mut a, mut b) = pair();
        let sent: Vec<_> = (0..3).map(|_| a.send_next().unwrap()).collect();
        deliver_ok(&mut b, &sent[2]);
        assert_eq!(b.losses().pending, 2);

        let rejected = b
            .receive(
                &sent[0].header,
                None,
                &sent[0].eph_ek,
                |_| Err::<(), ()>(()),
            )
            .unwrap();
        assert!(rejected.is_err());
        assert_eq!(b.losses().pending, 2, "the cached key was consumed anyway");

        deliver_ok(&mut b, &sent[0]);
        assert_eq!(b.losses().pending, 1);
    }

    /// A message key is used once. Re-presenting an opened frame finds nothing,
    /// which is what makes deleting keys meaningful.
    #[test]
    fn a_message_key_is_not_available_twice() {
        let (mut a, mut b) = pair();
        let out = a.send_next().unwrap();
        deliver_ok(&mut b, &out);

        let err = deliver(&mut b, &out).unwrap_err();
        assert!(
            matches!(err, RatchetError::AlreadyConsumed { .. }),
            "got {err:?}"
        );
    }

    /// A frame claiming a new generation with no ciphertext to root it in cannot
    /// arise from ordinary loss, since every frame of a generation repeats it.
    #[test]
    fn a_generation_step_without_its_ciphertext_is_refused() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());
        let reply = b.send_next().unwrap();

        let mut a2 = pair().0;
        let err = a2
            .receive(&reply.header, None, &reply.eph_ek, |k| {
                Ok::<_, ()>(*k.as_bytes())
            })
            .unwrap_err();
        assert!(
            matches!(err, RatchetError::MissingCiphertext { generation: 1 }),
            "got {err:?}"
        );
    }

    /// Reordering deeper than the ephemeral window is refused rather than served
    /// a key derived from the wrong secret — ML-KEM decapsulation never fails, so
    /// a wrong ephemeral would silently yield a wrong shared secret.
    #[test]
    fn a_step_needing_a_forgotten_ephemeral_is_refused() {
        let (mut a, _b) = pair();
        let out = a.send_next().unwrap();
        let ct = [0u8; ml_kem::CT_LEN];
        let far_future = FrameHeader {
            generation: 99,
            chain_base: 0,
            seq: 0,
        };
        let err = a
            .receive(&far_future, Some(&ct), &out.eph_ek, |k| {
                Ok::<_, ()>(*k.as_bytes())
            })
            .unwrap_err();
        assert!(
            matches!(err, RatchetError::UnknownEphemeral { generation: 99 }),
            "got {err:?}"
        );
    }

    /// The recipient cannot send before it has a chain, and the ratchet says so
    /// rather than inventing one.
    #[test]
    fn a_conversation_reports_what_it_cannot_do_yet() {
        let (a, b) = pair();
        assert_eq!(a.role(), Role::Initiator);
        assert_eq!(b.role(), Role::Recipient);
        assert_eq!(a.generation(), 0);
        assert_eq!(b.generation(), 0);
    }

    /// Twenty messages each way, interleaved. Nothing accumulates, nothing is
    /// lost, and the two ends never disagree about a key.
    #[test]
    fn a_long_conversation_stays_in_step() {
        let (mut a, mut b) = pair();
        for round in 0..20 {
            let from_a = a.send_next().unwrap();
            deliver_ok(&mut b, &from_a);
            let from_b = b.send_next().unwrap();
            deliver_ok(&mut a, &from_b);
            assert_eq!(a.losses().pending, 0, "round {round}");
            assert_eq!(b.losses().pending, 0, "round {round}");
        }
        // Two steps per round — one each way — and both ends land on the same
        // generation because each adopts the other's on receipt.
        assert_eq!(a.generation(), 39);
        assert_eq!(b.generation(), 39);
    }

    /// An older message arriving after the ratchet has moved on is served from
    /// the skipped-key cache, and that path must return before anything else
    /// moves — in particular before the peer ephemeral is recorded. Otherwise the
    /// straggler would reinstate a generation's ephemeral the peer has long since
    /// replaced, and our next send would step against a key it cannot use.
    #[test]
    fn an_old_message_arriving_late_does_not_rewind_the_peer_ephemeral() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());

        let early = b.send_next().unwrap();
        let later = b.send_next().unwrap();
        assert_eq!(early.header.generation, 1);
        deliver_ok(&mut a, &later);
        assert_eq!(a.losses().pending, 1, "the straggler's key was kept");

        deliver_ok(&mut b, &a.send_next().unwrap());
        let from_b = b.send_next().unwrap();
        assert_eq!(from_b.header.generation, 3);
        deliver_ok(&mut a, &from_b);

        // The straggler finally lands, out of the cache.
        deliver_ok(&mut a, &early);

        // The next send must be the step past generation 3, not a re-step against
        // generation 1's ephemeral.
        let next = a.send_next().unwrap();
        assert_eq!(next.header.generation, 4);
        deliver_ok(&mut b, &next);
    }

    /// The two halves of the opening ephemeral must be a keypair. ML-KEM never
    /// reports a mismatch — decapsulation returns a pseudorandom secret — so
    /// without this check the conversation would derive a wrong root at the first
    /// step and reject every reply forever, looking exactly like tampering.
    #[test]
    fn an_opening_ephemeral_from_two_keypairs_is_refused() {
        let ss0 = ss(0x11);
        let (ek, _dk) = opening_ephemeral();
        let (_other_ek, other_dk) = opening_ephemeral();

        let err = Ratchet::initiator(
            &ss0,
            Box::new(ek),
            EphemeralDecapKey::new(Box::new(other_dk)),
        )
        .unwrap_err();
        assert!(
            matches!(err, RatchetError::MismatchedEphemeral),
            "got {err:?}"
        );
    }

    /// A receiver returning from a long absence must lose the messages it missed,
    /// never the direction. Refusing the catch-up would leave its cursor frozen,
    /// every later frame further ahead still, and the inbound half permanently
    /// dead while both ends still looked healthy.
    #[test]
    fn a_backlog_wider_than_one_catch_up_loses_messages_not_the_channel() {
        let (mut a, mut b) = pair();
        let sent: Vec<_> = (0..(MAX_SKIP + 20))
            .map(|_| a.send_next().unwrap())
            .collect();

        // B was away and only ever collects the newest.
        let newest = sent.last().unwrap();
        deliver_ok(&mut b, newest);

        let losses = b.losses();
        assert!(losses.abandoned > 0, "the walked-past keys were counted");
        assert_eq!(
            losses.abandoned + losses.pending as u64,
            (MAX_SKIP + 19) as u64,
            "every position before the newest is accounted for"
        );

        // And the channel keeps working in both directions.
        let reply = b.send_next().unwrap();
        deliver_ok(&mut a, &reply);
        deliver_ok(&mut b, &a.send_next().unwrap());
    }

    /// The same, across a ratchet step: a previous chain too far gone to walk is
    /// retired outright rather than blocking the step, so the conversation
    /// re-anchors on the new chain instead of dying. This is the path where
    /// refusing would have been permanent — every later frame carries a wider gap
    /// still, so the inbound half would never recover.
    #[test]
    fn a_generation_step_over_an_unwalkable_backlog_re_anchors() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());
        deliver_ok(&mut a, &b.send_next().unwrap());

        // One generation-2 frame gets through, so B can step later.
        deliver_ok(&mut b, &a.send_next().unwrap());

        // Then A runs far ahead on generation 2 and B hears none of it.
        for _ in 0..(MAX_CATCH_UP + 100) {
            let _unheard = a.send_next().unwrap();
        }

        // B replies, publishing a fresh ephemeral; A steps to generation 4.
        deliver_ok(&mut a, &b.send_next().unwrap());
        let after_step = a.send_next().unwrap();
        assert_eq!(after_step.header.generation, 4);

        // B's generation-2 chain is now unwalkably far behind. The step must land
        // anyway.
        deliver_ok(&mut b, &after_step);
        assert!(
            b.losses().abandoned > MAX_CATCH_UP,
            "the retired chain's backlog was counted, not silently dropped"
        );

        // Both directions still work.
        deliver_ok(&mut a, &b.send_next().unwrap());
        deliver_ok(&mut b, &a.send_next().unwrap());
    }

    /// Beyond what one catch-up will walk, the frame is refused rather than
    /// costing unbounded work — but with an error that says it is a backlog, not
    /// an attack.
    #[test]
    fn a_frame_beyond_the_catch_up_bound_is_refused_by_distance() {
        let (mut a, mut b) = pair();
        let first = a.send_next().unwrap();
        deliver_ok(&mut b, &first);

        let far = FrameHeader {
            generation: first.header.generation,
            chain_base: first.header.chain_base,
            seq: first.header.seq + MAX_CATCH_UP + 2,
        };
        let err = b
            .receive(&far, None, &first.eph_ek, |k| Ok::<_, ()>(*k.as_bytes()))
            .unwrap_err();
        assert!(
            matches!(err, RatchetError::BacklogTooWide { gap, max } if gap == MAX_CATCH_UP + 1 && max == MAX_CATCH_UP),
            "got {err:?}"
        );
    }

    /// A sequence number before its own chain begins is not something an honest
    /// peer produces, and it is caught before any work is done.
    #[test]
    fn a_sequence_before_its_own_chain_is_rejected() {
        let (mut a, mut b) = pair();
        let out = a.send_next().unwrap();
        let bad = FrameHeader {
            generation: 0,
            chain_base: 10,
            seq: 4,
        };
        let err = b
            .receive(&bad, None, &out.eph_ek, |k| Ok::<_, ()>(*k.as_bytes()))
            .unwrap_err();
        assert!(
            matches!(
                err,
                RatchetError::SeqBeforeChainBase {
                    chain_base: 10,
                    seq: 4
                }
            ),
            "got {err:?}"
        );
    }

    /// A frame from behind the generation we receive on is distinguishable from a
    /// duplicate — the peer is behind us, rather than repeating itself.
    #[test]
    fn a_frame_from_an_older_generation_says_so() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());
        let reply = b.send_next().unwrap();
        deliver_ok(&mut a, &reply);
        let second = a.send_next().unwrap();
        deliver_ok(&mut b, &second);

        // A frame at generation 0 now, whose position was never cached.
        let stale = FrameHeader {
            generation: 0,
            chain_base: 1,
            seq: 900,
        };
        let err = b
            .receive(&stale, None, &second.eph_ek, |k| Ok::<_, ()>(*k.as_bytes()))
            .unwrap_err();
        assert!(
            matches!(
                err,
                RatchetError::GenerationTooOld {
                    frame: 0,
                    current: 2
                }
            ),
            "got {err:?}"
        );
    }

    /// The caller's own failure reason survives the round trip, so a bad AEAD tag
    /// and a bad signature stay distinguishable to the layer that can tell them
    /// apart.
    #[test]
    fn the_callers_error_comes_back_unchanged() {
        let (mut a, mut b) = pair();
        let out = a.send_next().unwrap();

        #[derive(Debug, PartialEq)]
        enum Why {
            BadSignature,
        }
        let outcome = b
            .receive(&out.header, out.eph_ct.as_deref(), &out.eph_ek, |_| {
                Err::<(), _>(Why::BadSignature)
            })
            .unwrap();
        assert_eq!(outcome, Err(Why::BadSignature));

        // And the frame is still openable afterwards, because nothing committed.
        deliver_ok(&mut b, &out);
    }

    /// The ratchet holds keys and ephemerals; its `Debug` must not print them.
    #[test]
    fn the_ratchet_does_not_render_its_secrets() {
        let (mut a, _b) = pair();
        let out = a.send_next().unwrap();
        let rendered = format!("{a:?}");
        assert!(!rendered.contains(&hex::encode(out.key.as_bytes())));
        assert!(rendered.contains("Initiator"));
        assert!(!format!("{out:?}").contains(&hex::encode(out.key.as_bytes())));
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

    // ---- surviving a restart (#243) ------------------------------------------

    /// The pair, plus the material a client holds *without* a snapshot: the
    /// first-contact secret and the initiator's opening ephemeral, which § v5
    /// (V4-2) already requires persisting. Everything the restart tests do to
    /// rebuild from that alone is therefore the best case, not a strawman.
    #[allow(clippy::type_complexity)]
    fn pair_and_opening_material() -> (
        Ratchet,
        Ratchet,
        [u8; 32],
        [u8; ml_kem::EK_LEN],
        [u8; ml_kem::DK_LEN],
    ) {
        let ss0 = ss(0x11);
        let (ek, dk) = opening_ephemeral();
        let initiator =
            Ratchet::initiator(&ss0, Box::new(ek), EphemeralDecapKey::new(Box::new(dk))).unwrap();
        let recipient = Ratchet::recipient(&ss0, Box::new(ek)).unwrap();
        (initiator, recipient, ss0, ek, dk)
    }

    /// Take a conversation across a restart the way a client would: snapshot,
    /// encode, drop everything, decode, restore. The encoding is on the path
    /// deliberately — a round trip that skipped it would prove the shape and not
    /// the format.
    fn through_a_restart(live: &Ratchet) -> Ratchet {
        let encoded = live.snapshot().encode();
        let decoded = RatchetSnapshot::decode(&encoded).expect("the snapshot decodes");
        Ratchet::restore(decoded).expect("the snapshot restores")
    }

    /// Drive the pair to the state a restart actually has to survive: two
    /// generation steps behind it, one of B's messages sitting unread in A's
    /// skipped-key cache, and one more from B in flight that A has not seen.
    ///
    /// Returns the straggler and the in-flight frame, both undelivered.
    fn conversation_mid_flight(a: &mut Ratchet, b: &mut Ratchet) -> (Outbound, Outbound) {
        deliver_ok(b, &a.send_next().unwrap()); // generation 0, sequence 1
        let straggler = b.send_next().unwrap(); // generation 1, sequence 0
        let after_it = b.send_next().unwrap(); // generation 1, sequence 1
        deliver_ok(a, &after_it); // out of order: the straggler's key is kept
        deliver_ok(b, &a.send_next().unwrap()); // A steps to generation 2
        deliver_ok(b, &a.send_next().unwrap()); // generation 2, sequence 3
        let in_flight = b.send_next().unwrap(); // B steps to generation 3
        (straggler, in_flight)
    }

    /// **The oracle for #243.** A restarts; B does not, and never learns that A
    /// did. Everything that made the conversation live has to survive the round
    /// trip: the root and both chains, the ephemeral B's next step encapsulates
    /// to, the key for a message that arrived out of order before the restart,
    /// and the sequence numbering.
    #[test]
    fn a_restored_ratchet_keeps_talking_to_a_peer_that_never_restarted() {
        let (mut a, mut b) = pair();
        let (straggler, in_flight) = conversation_mid_flight(&mut a, &mut b);

        let before = a.snapshot();
        assert_eq!(before.generation, 2);
        assert_eq!(a.losses().pending, 1, "a key is held for the straggler");

        let restored = through_a_restart(&a);
        drop(a);
        let mut a = restored;

        // A frame from B that steps a generation, decapsulated with an ephemeral
        // A published before the restart.
        deliver_ok(&mut a, &in_flight);
        assert_eq!(a.generation(), 3);

        // And the message that was already skipped past, out of the restored
        // cache.
        deliver_ok(&mut a, &straggler);
        assert_eq!(a.losses().pending, 0, "the restored cache was drained");

        // A sends again: the sequence continues rather than restarting, the
        // generation step lands, and B — which never restarted — opens it.
        let after = a.send_next().unwrap();
        assert_eq!(after.header.seq, 4, "the sequence restarted");
        assert_eq!(after.header.generation, 4);
        deliver_ok(&mut b, &after);

        // And B's reply still opens at A, so the channel is live both ways.
        deliver_ok(&mut a, &b.send_next().unwrap());
    }

    /// The state of the world **before** the fix, pinned so the defect cannot
    /// quietly come back as a "simplification". A client that kept only what the
    /// frozen design already asks it to keep — `ss0` and its opening ephemeral —
    /// cannot rebuild a running conversation from them.
    ///
    /// The failure is doubly silent: the rebuilt ratchet reports no losses at
    /// all, so nothing on either end distinguishes it from a healthy channel.
    #[test]
    fn rebuilding_from_ss0_alone_leaves_the_conversation_permanently_dead() {
        let (mut a, mut b, ss0, ek, dk) = pair_and_opening_material();
        let (_straggler, in_flight) = conversation_mid_flight(&mut a, &mut b);
        drop(a);

        // The best a client can do without a snapshot.
        let mut rebuilt =
            Ratchet::initiator(&ss0, Box::new(ek), EphemeralDecapKey::new(Box::new(dk))).unwrap();

        // Inbound: B's next frame needs the ephemeral A published at generation
        // 2, and the rebuilt state holds only the opening one.
        let err = deliver(&mut rebuilt, &in_flight).unwrap_err();
        assert!(
            matches!(err, RatchetError::UnknownEphemeral { generation: 3 }),
            "got {err:?}"
        );

        // Outbound: the sequence restarts at the opening message's, at a
        // generation B has long since moved past.
        let out = rebuilt.send_next().unwrap();
        assert_eq!(out.header.seq, FIRST_INITIATOR_CHANNEL_SEQ);
        assert_eq!(out.header.generation, 0);
        let err = deliver(&mut b, &out).unwrap_err();
        assert!(
            matches!(
                err,
                RatchetError::GenerationTooOld {
                    frame: 0,
                    current: 2
                }
            ),
            "got {err:?}"
        );

        // And nothing anywhere says so.
        assert_eq!(
            rebuilt.losses(),
            DeliveryLosses {
                pending: 0,
                evicted: 0,
                abandoned: 0
            },
            "a dead conversation reported itself healthy"
        );
    }

    /// The peer's ephemeral is what a generation step encapsulates to, and
    /// losing it costs no message — it costs the *heal*. A restored ratchet that
    /// dropped it would keep sending happily on the old root, so nothing but the
    /// generation number reports the loss.
    #[test]
    fn a_restored_ratchet_still_takes_the_generation_step_it_owed() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());
        deliver_ok(&mut a, &b.send_next().unwrap());

        let mut a = through_a_restart(&a);

        let out = a.send_next().unwrap();
        assert_eq!(out.header.generation, 2, "the owed step was not taken");
        assert!(out.eph_ct.is_some(), "a step must carry its ciphertext");
        deliver_ok(&mut b, &out);
    }

    /// The mirror image: a step already taken must not be taken again. A peer
    /// repeats one ephemeral on every message of its generation, so a restored
    /// ratchet that forgot which one it had consumed would encapsulate to a key
    /// the peer has moved past — and the peer cannot derive that step at all.
    #[test]
    fn a_restored_ratchet_does_not_re_step_against_an_ephemeral_it_already_used() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());
        deliver_ok(&mut a, &b.send_next().unwrap());
        deliver_ok(&mut b, &a.send_next().unwrap()); // A steps to generation 2

        let mut a = through_a_restart(&a);

        let out = a.send_next().unwrap();
        assert_eq!(out.header.generation, 2, "the ratchet stepped twice");
        assert_eq!(out.header.seq, 3);
        deliver_ok(&mut b, &out);
    }

    /// Every message of a generation repeats the ciphertext that created it, so
    /// that losing the one message which opened the generation costs only that
    /// message. A restart must not break the repetition: here B never receives
    /// the message that opened generation 2, and the first message A sends
    /// *after* restoring has to establish it on its own.
    ///
    /// The chain base rides the same path — B has to be told where the new chain
    /// starts, or it walks the chain from the wrong position and derives a key
    /// that does not open anything.
    #[test]
    fn a_restored_ratchet_still_repeats_its_generation_ciphertext() {
        let (mut a, mut b) = pair();
        deliver_ok(&mut b, &a.send_next().unwrap());
        deliver_ok(&mut a, &b.send_next().unwrap());
        let _lost = a.send_next().unwrap(); // opens generation 2; B never sees it

        let mut a = through_a_restart(&a);

        let out = a.send_next().unwrap();
        assert_eq!(out.header.generation, 2);
        assert_eq!(out.header.chain_base, 2, "the chain's start was forgotten");
        assert!(
            out.eph_ct.is_some(),
            "the generation ciphertext was not repeated"
        );
        deliver_ok(&mut b, &out);
    }

    /// The two permanent loss counts are what stand between a user and a
    /// conversation that quietly ate two hundred messages. A restart that reset
    /// them would make the damage unreportable — and this is the receiving side,
    /// so it also covers restoring a recipient, whose sending chain does not
    /// exist yet.
    #[test]
    fn a_restored_ratchet_reports_the_losses_it_inherited() {
        let (mut a, mut b) = pair();

        // Three rounds of "A runs ahead, B collects only the newest": the first
        // fills half the cache, the second fills it, the third starts evicting.
        for _ in 0..3 {
            let sent: Vec<_> = (0..(MAX_SKIP + 20))
                .map(|_| a.send_next().unwrap())
                .collect();
            deliver_ok(&mut b, sent.last().unwrap());
        }

        let before = b.losses();
        assert!(before.pending > 0 && before.evicted > 0 && before.abandoned > 0);

        let b = through_a_restart(&b);
        assert_eq!(b.losses(), before, "the inherited losses were not carried");
        assert_eq!(b.role(), Role::Recipient);

        // And it is a working conversation, not just a working report.
        let mut b = b;
        deliver_ok(&mut a, &b.send_next().unwrap());
        deliver_ok(&mut b, &a.send_next().unwrap());
    }

    // ---- the at-rest encoding -------------------------------------------------

    /// The format says what it is, and a decoder handed a version it does not
    /// know says so rather than reading the next field's bytes as this one's.
    #[test]
    fn the_snapshot_encoding_is_versioned() {
        assert_eq!(RATCHET_SNAPSHOT_MAGIC, b"daemonseed/dm/ratchet-state/v1\0");

        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut bytes = a.snapshot().encode().to_vec();

        assert!(RatchetSnapshot::decode(&bytes).is_ok());
        bytes[..RATCHET_SNAPSHOT_MAGIC.len()].copy_from_slice(b"daemonseed/dm/ratchet-state/v2\0");
        assert_eq!(
            RatchetSnapshot::decode(&bytes).unwrap_err(),
            RatchetSnapshotError::BadMagic
        );
    }

    /// The length is computed, not discovered, so the buffer is allocated once
    /// and never reallocated — a growing `Vec` leaves key bytes in freed memory
    /// that nothing zeroizes.
    #[test]
    fn the_encoded_length_is_exact() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let snapshot = a.snapshot();
        assert_eq!(snapshot.encode().len(), snapshot.encoded_len());

        // And on the sparsest state there is, where every optional field really
        // is absent: a recipient before it has sent or received anything, so no
        // sending chain, no peer ephemeral, no consumed generation, no
        // generation ciphertext, no retained ephemerals and an empty cache.
        let sparse = pair().1.snapshot();
        assert!(
            sparse.send.is_none()
                && sparse.consumed_peer_generation.is_none()
                && sparse.gen_ct.is_none()
                && sparse.ephemerals.is_empty()
                && sparse.skipped.is_empty(),
            "this is meant to be the all-absent case: {sparse:?}"
        );
        assert_eq!(sparse.encode().len(), sparse.encoded_len());
        assert!(RatchetSnapshot::decode(&sparse.encode()).is_ok());
    }

    /// One byte short and one byte long are different failures, and neither is
    /// allowed to be silent: a short record would read the next field off the
    /// end, and a long one is a record this code did not write.
    #[test]
    fn a_truncated_or_padded_snapshot_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let bytes = a.snapshot().encode();

        assert_eq!(
            RatchetSnapshot::decode(&bytes[..bytes.len() - 1]).unwrap_err(),
            RatchetSnapshotError::Truncated
        );
        assert_eq!(
            RatchetSnapshot::decode(&[]).unwrap_err(),
            RatchetSnapshotError::Truncated
        );

        let mut padded = bytes.to_vec();
        padded.push(0);
        assert_eq!(
            RatchetSnapshot::decode(&padded).unwrap_err(),
            RatchetSnapshotError::TrailingBytes { extra: 1 }
        );
    }

    /// A count is checked against its bound **before** anything is reserved for
    /// it, so a corrupt record cannot make this process allocate.
    #[test]
    fn an_oversized_count_is_refused_before_it_is_reserved() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let snapshot = a.snapshot();
        let (ephemerals, skipped) = (snapshot.ephemerals.len(), snapshot.skipped.len());
        let bytes = snapshot.encode();

        let skipped_count_at = bytes.len() - 2 - skipped * SKIPPED_ENTRY_LEN;
        let mut broken = bytes.to_vec();
        broken[skipped_count_at..skipped_count_at + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            RatchetSnapshot::decode(&broken).unwrap_err(),
            RatchetSnapshotError::TooManySkippedKeys {
                count: u16::MAX as usize,
                max: SKIPPED_KEY_CAPACITY,
            }
        );

        let eph_count_at = skipped_count_at - 2 - ephemerals * EPHEMERAL_ENTRY_LEN;
        let mut broken = bytes.to_vec();
        broken[eph_count_at..eph_count_at + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            RatchetSnapshot::decode(&broken).unwrap_err(),
            RatchetSnapshotError::TooManyEphemerals {
                count: u16::MAX as usize,
                max: EPHEMERAL_WINDOW,
            }
        );
    }

    /// Every discriminant starts at one, so a zeroed byte names no valid variant
    /// rather than decoding as the first of each.
    #[test]
    fn a_corrupt_discriminant_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let bytes = a.snapshot().encode();

        let mut broken = bytes.to_vec();
        broken[RATCHET_SNAPSHOT_MAGIC.len()] = 0;
        assert_eq!(
            RatchetSnapshot::decode(&broken).unwrap_err(),
            RatchetSnapshotError::InvalidRole { value: 0 }
        );

        let mut broken = bytes.to_vec();
        broken[RATCHET_SNAPSHOT_MAGIC.len() + FIXED_BODY_LEN] = 0;
        assert_eq!(
            RatchetSnapshot::decode(&broken).unwrap_err(),
            RatchetSnapshotError::InvalidPresence { value: 0 }
        );
    }

    /// The conversation's address root and channel identifier must not be
    /// derivable from a stored snapshot: `chan_id` is never serialized anywhere,
    /// and writing `AR` down beside the keys would put the whole address graph
    /// in one record.
    #[test]
    fn a_snapshot_carries_no_channel_identifier() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let bytes = a.snapshot().encode();

        let roots = crate::dm::firstcontact::derive_channel_roots(&ss(0x11)).unwrap();
        assert!(
            !bytes
                .windows(roots.chan_id.len())
                .any(|w| w == roots.chan_id),
            "chan_id must never be serialized"
        );
        assert!(
            !bytes.windows(roots.ar.len()).any(|w| w == roots.ar),
            "the address root does not belong in the key record"
        );
    }

    /// A snapshot is one `debug!` away from a log file, exactly as the keys
    /// inside it are.
    #[test]
    fn a_snapshot_does_not_render_its_secrets() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let snapshot = a.snapshot();
        let rendered = format!("{snapshot:?}");

        assert!(!rendered.contains(&hex::encode(snapshot.root.as_bytes())));
        for (_, key) in &snapshot.skipped {
            assert!(!rendered.contains(&hex::encode(key.as_bytes())));
        }
        assert!(rendered.contains("Initiator"));
    }

    // ---- integrity checks on our own record ----------------------------------

    /// ML-KEM never reports a mismatch, so a snapshot whose ephemeral halves
    /// drifted apart would restore cleanly and then reject every reply forever.
    /// It is caught at the point of the mistake instead, as at construction.
    #[test]
    fn a_snapshot_whose_ephemeral_halves_disagree_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();

        // A whole decapsulation key from a different keypair, which is the shape
        // the mistake actually takes — a record assembled from two sources, or
        // an index off by one.
        let (_other_ek, other_dk) = opening_ephemeral();
        let generation = snapshot.ephemerals[0].generation;
        snapshot.ephemerals[0].dk = EphemeralDecapKey::new(Box::new(other_dk));

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::MismatchedEphemeral { generation }
        );
    }

    /// The newest ephemeral is taken from the back of the queue, so restoring
    /// them out of order would publish one the peer has already stepped past.
    #[test]
    fn ephemerals_restored_out_of_order_are_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        assert!(snapshot.ephemerals.len() >= 2, "the test needs two");

        let (previous, next) = (
            snapshot.ephemerals[1].generation,
            snapshot.ephemerals[0].generation,
        );
        snapshot.ephemerals.reverse();
        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::EphemeralsOutOfOrder { previous, next }
        );
    }

    /// An initiator has had a sending chain since it was constructed; a snapshot
    /// without one is not a state this module produces.
    #[test]
    fn a_snapshot_missing_its_own_chain_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        snapshot.send = None;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::MissingChain {
                role: Role::Initiator
            }
        );
    }

    /// The sending chain's cursor and the next outbound sequence number are two
    /// recordings of one fact. Accepting a disagreement would seal messages under
    /// keys at positions their own headers do not claim.
    #[test]
    fn a_send_cursor_disagreeing_with_the_sequence_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        let expected = snapshot.send.as_ref().unwrap().next;
        snapshot.next_send_seq += 1;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::SendCursorMismatch {
                expected,
                next_send_seq: expected + 1,
            }
        );
    }

    /// The one state with no sending chain to compare against — a recipient that
    /// has not sent — is checked against the only sequence number it may hold,
    /// rather than skipped for want of something to compare to.
    #[test]
    fn a_recipient_that_has_not_sent_may_hold_only_its_first_sequence() {
        let (_a, b) = pair();
        let mut snapshot = b.snapshot();
        assert!(
            snapshot.send.is_none(),
            "the test needs a recipient pre-send"
        );
        snapshot.next_send_seq = 9999;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::SendCursorMismatch {
                expected: FIRST_RECIPIENT_CHANNEL_SEQ,
                next_send_seq: 9999,
            }
        );
    }

    /// An initiator has retained an ephemeral since construction, so a snapshot
    /// without one is a state this module cannot produce — and one that would
    /// otherwise restore cleanly and then report every failed send as a
    /// conversation that was never established.
    #[test]
    fn an_initiator_snapshot_without_its_ephemeral_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        snapshot.ephemerals.clear();

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::MissingOpeningEphemeral
        );
    }

    /// A chain cannot have reached a position before its own first message.
    #[test]
    fn a_chain_cursor_before_its_base_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        let chain = snapshot.recv.as_mut().unwrap();
        chain.base = chain.next + 1;
        let (base, next) = (chain.base, chain.next);

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::ChainCursorBeforeBase { base, next }
        );
    }

    /// A chain's generation is what its frames announce. Restored ahead of the
    /// conversation's own, every outbound header claims a root the key it carries
    /// was not derived from: loud at the peer, silent at us, and that direction
    /// never recovers.
    #[test]
    fn a_chain_ahead_of_the_conversations_generation_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let generation = a.generation();
        let mut snapshot = a.snapshot();
        snapshot.send.as_mut().unwrap().generation = 4242;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::ChainGenerationAhead {
                direction: Role::Initiator.send_dir(),
                chain: 4242,
                generation,
            }
        );
    }

    /// Nothing else in the record relates an ephemeral's generation tag to the
    /// conversation's own. A drifted tag restores clean and then answers every
    /// advancing frame with `UnknownEphemeral`, forever, while outbound carries
    /// on working — the failure that looks exactly like a peer gone quiet.
    #[test]
    fn an_ephemeral_tagged_past_the_conversations_generation_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let generation = a.generation();
        let mut snapshot = a.snapshot();
        let newest = generation + 2;
        snapshot.ephemerals.last_mut().unwrap().generation = newest;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::EphemeralGenerationOutOfRange { newest, generation }
        );
    }

    /// The same drift one generation **low**, which the range check above cannot
    /// see: a newest tag at `generation - 1` still brackets the conversation
    /// legally, because that is exactly where a party sits between receiving a
    /// step and taking its own. Only the sending chain contradicts it — the two
    /// are minted in one operation — and that is what this catches.
    #[test]
    fn an_ephemeral_tagged_below_its_sending_chain_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        let send = snapshot.send.as_ref().unwrap().generation;
        let newest = send - 1;
        snapshot.ephemerals.last_mut().unwrap().generation = newest;

        // The range check passes this: it is a legal bracket.
        assert!(snapshot.generation >= newest && snapshot.generation <= newest + 1);
        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::EphemeralGenerationMismatch { send, newest }
        );
    }

    /// The mirror of the initiator's own opening ephemeral: a recipient is handed
    /// the peer's at construction and only ever replaces it. Without it the first
    /// send takes no generation step, so it finds no sending chain and reports a
    /// conversation that was never established — which this one was.
    #[test]
    fn a_recipient_snapshot_without_the_peers_ephemeral_is_refused() {
        let (_a, b) = pair();
        let mut snapshot = b.snapshot();
        assert!(snapshot.peer_eph.is_some(), "the test needs one to remove");
        snapshot.peer_eph = None;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::MissingPeerEphemeral
        );
    }

    /// A cursor one step from the end of the sequence space. `advance_to` refuses
    /// the step rather than wrapping it, so restoring this would rebuild a
    /// conversation permanently unable to send — caught at the record instead.
    #[test]
    fn a_chain_cursor_at_the_last_sequence_number_is_refused() {
        let (mut a, mut b) = pair();
        conversation_mid_flight(&mut a, &mut b);
        let mut snapshot = a.snapshot();
        snapshot.send.as_mut().unwrap().next = u64::MAX;
        snapshot.next_send_seq = u64::MAX;

        assert_eq!(
            Ratchet::restore(snapshot).unwrap_err(),
            RatchetSnapshotError::ChainCursorExhausted {
                direction: Role::Initiator.send_dir(),
            }
        );
    }

    /// **This crate's release profile sets no `overflow-checks`**, so a wrapping
    /// cursor is not a debug panic there — it is a silent return to sequence
    /// zero, whose write-once page slot is already spoken for. The step is
    /// refused instead.
    #[test]
    fn advancing_to_the_last_sequence_number_is_refused_rather_than_wrapping() {
        let last = Chain {
            generation: 0,
            direction: Direction::AToB,
            key: a2b_chain(0x11),
            base: 0,
            next: u64::MAX - 1,
        };

        // The position before it is ordinary, and lands the cursor on the last.
        let (_, _, _, at_the_end) = last.clone().advance_to(u64::MAX - 1).unwrap();
        assert_eq!(at_the_end.next, u64::MAX);

        let err = at_the_end.advance_to(u64::MAX).unwrap_err();
        assert!(
            matches!(err, RatchetError::SequenceExhausted { seq } if seq == u64::MAX),
            "expected a refusal naming the position, got {err:?}"
        );
    }

    /// `insert` keeps one entry per slot, and `peek` / `take` stop at the first
    /// match — so a second entry for one slot is capacity nothing can reach,
    /// counted by `losses().pending` as a message still recoverable.
    #[test]
    fn a_cache_holding_two_keys_for_one_slot_is_refused() {
        let mut entries = VecDeque::new();
        entries.push_back((slot(0, 7), mk_key(1)));
        entries.push_back((slot(0, 8), mk_key(2)));
        entries.push_back((slot(0, 7), mk_key(3)));

        assert_eq!(
            SkippedKeys::restore(entries, 0).unwrap_err(),
            RatchetSnapshotError::DuplicateSkippedKey { slot: slot(0, 7) }
        );
    }

    /// The cache is bounded, and a record claiming more entries than it holds is
    /// refused rather than silently evicting keys we ourselves wrote.
    #[test]
    fn a_cache_larger_than_its_bound_is_refused() {
        let mut entries = VecDeque::new();
        for n in 0..=SKIPPED_KEY_CAPACITY as u64 {
            entries.push_back((slot(0, n), mk_key(n)));
        }
        let count = entries.len();
        assert_eq!(
            SkippedKeys::restore(entries, 0).unwrap_err(),
            RatchetSnapshotError::TooManySkippedKeys {
                count,
                max: SKIPPED_KEY_CAPACITY,
            }
        );
    }
}
