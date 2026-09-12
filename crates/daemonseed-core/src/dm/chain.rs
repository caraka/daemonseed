//! The **key schedule** — one root chain per direction, re-keyed by an
//! ML-KEM-1024 encapsulation at the start of every turn.
//!
//! `docs/design/direct-messaging.md` § Keys and forward secrecy gives the
//! derivation. For a direction X→Y at X's turn `n`:
//!
//! ```text
//!   R_X^n        = HKDF(R_X^{n-1}, ss_Y^m, ss_X^n)   the turn's root
//!   CK_X         = HKDF(R_X^n, "chain")              the turn's chain
//!   CK_X, mk_seq = HKDF(CK_X, "step")                per message
//! ```
//!
//! Five rules govern it:
//!
//! - **The turn rule.** A turn is the first message X writes after having read
//!   a turn of Y's that X had not seen before, or after
//!   [`Direction::force_next_turn`]. At turn start X mints a fresh
//!   [`RatchetKeypair`], encapsulates to the latest `pk_Y^m` it has read,
//!   derives `R_X^n` from the previous root and both secrets, resets the
//!   chain, and puts `kem_ct` and the fresh public key in that message's
//!   header. Later messages in the turn carry none, so
//!   [`channel::MessageHeader::starts_turn`] is exactly "this message opened a
//!   turn".
//! - **The retention rule.** A reader keeps its two most recent own turns,
//!   newest first. A header names the one it was encapsulated to as its `m`;
//!   one naming an older turn is [`ChainError::SecretGone`]. The older of the
//!   two is dropped as soon as a message encapsulated to the newer has been
//!   opened, which is what lets crossing turns both open while the window
//!   stays at [`OWN_TURNS_RETAINED`].
//! - **The deletion rule.** Every message key is used once and its buffer
//!   zeroized before the call returns, by the writer at seal time and by the
//!   reader at open time. Nothing stores one, so a second open of a sequence
//!   already opened is [`ChainError::AlreadyOpened`] rather than a repeat.
//! - **The ordering rule.** Within a direction messages are totally ordered by
//!   `seq`, so a header whose sequence is not the next expected is
//!   [`ChainError::OutOfOrder`] and there is no store of skipped keys.
//! - **The reset rule.** [`reset_all`] sets the force-turn flag on every
//!   direction and returns [`ResetAction::RotateAdvert`], the advert rotation
//!   the caller performs now. The rotation itself lives in
//!   [`crate::dm::advert`]; this module names it and performs nothing.
//!
//! **Three points the design leaves open are read here, and the readings are
//! what the code implements.**
//!
//! - *Where each direction's first root comes from.* Both are seeded from
//!   `ss0`, the secret the hello encapsulated. The initiator's turn 0 is open
//!   the moment [`initiate`] returns, so its first message carries no turn
//!   fields — turn 0's ML-KEM step is the hello's own encapsulation, which
//!   `ss0` already is, and the ratchet public key it mints travels in the
//!   channel opening rather than in a header. The acceptor's turn 0 is a
//!   ratchet turn like every other, encapsulated to the initiator's first
//!   ratchet key as read from that opening, so its first message does carry
//!   them.
//! - *What the acceptor's first root mixes.* The previous root and the new
//!   secret alone: at that point it has decapsulated nothing of the
//!   initiator's, so the peer-secret input is absent and is length-prefixed as
//!   empty. Every later root mixes all three.
//! - *Which chain label a direction uses.* One label for both, because each
//!   direction's root is its own from its first own turn onwards. The two are
//!   not separate from the start: both are seeded from `ss0`, so the seed root
//!   and the chain derived from it are one value on both sides, and they
//!   diverge at each side's first own step. What keeps the two directions off
//!   one chain is therefore the state and not the label — the acceptor's
//!   sending half holds no chain at all until its first turn
//!   ([`Direction`]), so the chain the initiator runs off the shared seed is
//!   not reachable from it.
//!
//! Everything here is pure: no I/O, no clock, no ambient randomness except the
//! AEAD nonce the shared envelope primitive draws. Entropy for a keypair and
//! an encapsulation is a fill function the caller supplies, and every fallible
//! crypto call returns [`ChainError`].
//!
//! Serves FC3.

use oxicrypt_aes::Aes256Key;
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::dm::{channel, domain, push_lp};
use crate::secret_seed::redacted_secret_newtype;

/// Length of a direction's root.
pub const ROOT_LEN: usize = 32;

/// Length of a chain key.
pub const CHAIN_KEY_LEN: usize = 32;

/// Length of a message key — an AES-256 key.
pub const MESSAGE_KEY_LEN: usize = 32;

/// Own turns a reader retains, newest first.
///
/// Two is what makes crossing turns open: each side may start a turn
/// encapsulated to the other's previous key without having read the other's
/// new one, so the previous key has to outlive its replacement by exactly one.
pub const OWN_TURNS_RETAINED: usize = 2;

redacted_secret_newtype! {
    /// One direction's root at one turn. Replaced at every turn start and
    /// never retained past its successor.
    inline pub struct Root([u8; ROOT_LEN]);
}

redacted_secret_newtype! {
    /// One direction's chain key at one position within a turn.
    ///
    /// The `step` that advances a chain takes this **by value**, so the
    /// caller's binding is gone once
    /// it returns and the stepped position is not left lying beside its
    /// successor. The type is `Clone`, as every key class here is, so that is
    /// a default rather than a guarantee: a caller that wants a second copy of
    /// a position can still make one.
    inline pub struct ChainKey([u8; CHAIN_KEY_LEN]);
}

redacted_secret_newtype! {
    /// A single message's key. Used once, then zeroized.
    inline pub struct MessageKey([u8; MESSAGE_KEY_LEN]);
}

redacted_secret_newtype! {
    /// The secret one turn's ML-KEM encapsulation yields on both sides.
    inline pub struct TurnSecret([u8; ml_kem::SHARED_SECRET_LEN]);
}

redacted_secret_newtype! {
    /// The secret half of one turn's ratchet keypair.
    boxed pub struct RatchetDecapKey([u8; ml_kem::DK_LEN]);
}

/// Rebuild a key-schedule secret from bytes read back out of the profile's
/// at-rest store.
///
/// Every secret here is derived, and a restart cannot redo the derivation:
/// the inputs are the previous turn's material, which the restart destroyed.
/// So a [`ConversationSnapshot`] written to disk has to come back as the same
/// values, and `from_bytes` is the only way in. `pub(crate)` — the store
/// ([`crate::dm::store`]) is the single caller, and nothing outside this crate
/// has any business minting a chain position.
macro_rules! restore_from_bytes {
    ($name:ident, $len:expr, inline) => {
        impl $name {
            pub(crate) fn from_bytes(bytes: &[u8; $len]) -> Self {
                Self(*bytes)
            }
        }
    };
    ($name:ident, $len:expr, boxed) => {
        impl $name {
            pub(crate) fn from_bytes(bytes: &[u8; $len]) -> Self {
                Self(Box::new(*bytes))
            }
        }
    };
}

restore_from_bytes!(Root, ROOT_LEN, inline);
restore_from_bytes!(ChainKey, CHAIN_KEY_LEN, inline);
restore_from_bytes!(TurnSecret, ml_kem::SHARED_SECRET_LEN, inline);
restore_from_bytes!(RatchetDecapKey, ml_kem::DK_LEN, boxed);

/// One turn's ratchet keypair. The decapsulation key is zeroized on drop.
pub struct RatchetKeypair {
    /// The public half, written into the turn's first header.
    pub pk: Box<[u8; ml_kem::EK_LEN]>,
    /// The secret half, retained until the retention rule drops it.
    pub dk: RatchetDecapKey,
}

impl RatchetKeypair {
    /// A byte-for-byte copy of both halves.
    ///
    /// Not `Clone`: copying a decapsulation key is what a state snapshot and a
    /// device clone both do, and it should be written where it happens rather
    /// than reachable by a derive.
    fn duplicate(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            dk: RatchetDecapKey(Box::new(*self.dk.as_bytes())),
        }
    }
}

impl std::fmt::Debug for RatchetKeypair {
    /// Renders neither half: the public key is `ml_kem::EK_LEN` bytes and the
    /// secret one has no business on a log surface.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RatchetKeypair(<redacted>)")
    }
}

/// Why a key-schedule operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// HKDF failed — the crypto module is not operational.
    Kdf(oxicrypt_kdf::KdfError),
    /// The caller's fill function could not supply entropy for a keypair or
    /// an encapsulation.
    Entropy,
    /// A turn is due and this direction has read no peer ratchet key to
    /// encapsulate to.
    NoPeerKey,
    /// A header naming an own turn outside the retention window: the secret
    /// it was encapsulated to is deleted and no message under it can ever
    /// open again.
    SecretGone {
        /// The own turn the header names.
        named: u64,
    },
    /// A sequence already opened. The chain has moved past it and no skipped
    /// key is stored, so the key is gone.
    AlreadyOpened {
        /// The sequence the header names.
        seq: u64,
    },
    /// A sequence other than the next expected one. Within a direction
    /// messages are totally ordered, so this is a gap or a reordering rather
    /// than something to reconcile.
    OutOfOrder {
        /// The sequence this direction is at.
        expected: u64,
        /// The sequence the header names.
        found: u64,
    },
    /// A header carrying no turn fields on a direction whose first turn has
    /// not been read. There is no chain to step yet.
    NoTurn,
    /// A header carrying `kem_ct` without `kem_pk`, or the reverse. One alone
    /// names a ratchet key the reader cannot obtain, so it is refused before
    /// any derivation runs over it — the same condition
    /// [`channel::ChannelError::TurnFieldsIncomplete`] reports at decode, in
    /// this module's error so a caller handles one kind.
    TurnFieldsIncomplete,
    /// A turn minted by a previous seal has not been retained yet. Sealing
    /// again would drop a secret the peer is about to encapsulate to.
    PendingTurnNotTaken,
    /// The body did not open: a wrong key, a tampered ciphertext, or an
    /// associated-data mismatch. Uniform by design.
    Aead,
    /// The crypto module refused an AES, ML-KEM or key-generation call.
    Module(oxicrypt_module::Error),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "chain HKDF failed: {e:?}"),
            Self::Entropy => write!(f, "chain: the entropy source failed"),
            Self::NoPeerKey => write!(f, "chain: a turn is due with no peer ratchet key read"),
            Self::SecretGone { named } => {
                write!(f, "chain: the secret for own turn {named} is deleted")
            }
            Self::AlreadyOpened { seq } => write!(f, "chain: sequence {seq} is already opened"),
            Self::OutOfOrder { expected, found } => {
                write!(f, "chain: expected sequence {expected}, got {found}")
            }
            Self::NoTurn => write!(f, "chain: no turn of this direction has been read"),
            Self::TurnFieldsIncomplete => {
                write!(
                    f,
                    "chain header: one turn field is present without the other"
                )
            }
            Self::PendingTurnNotTaken => write!(f, "chain: the minted turn has not been retained"),
            Self::Aead => write!(f, "chain: the message body did not open"),
            Self::Module(e) => write!(f, "chain: the crypto module refused: {e:?}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<EnvelopeError> for ChainError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_)
            | EnvelopeError::TooShort
            | EnvelopeError::Decrypt(_)
            | EnvelopeError::Encrypt(_) => Self::Aead,
        }
    }
}

/// Expand a PRK into a key class, zeroizing the transient stack buffer on both
/// the success and the error path.
///
/// `[u8; N]` is `Copy` and has no `Drop`, so wrapping one in a zeroize-on-drop
/// newtype protects only the copy that moved *into* the newtype — the original
/// stays live in the frame until something overwrites it. The wrapping happens
/// inside this helper so the buffer can be cleared after it.
fn expand_secret<const N: usize, T>(
    expand: impl FnOnce(&mut [u8; N]) -> Result<(), oxicrypt_kdf::KdfError>,
    wrap: impl FnOnce([u8; N]) -> T,
) -> Result<T, ChainError> {
    let mut buf = [0u8; N];
    let outcome = expand(&mut buf)
        .map(|()| wrap(buf))
        .map_err(ChainError::Kdf);
    buf.zeroize();
    outcome
}

/// The root both directions start from: `HKDF(ss0, DM_CHANNEL_ROOT)`.
///
/// One value on both sides, because `ss0` is. What separates the two
/// directions is the first turn taken on each, not this seed.
fn seed_root(ss0: &[u8; ml_kem::SHARED_SECRET_LEN]) -> Result<Root, ChainError> {
    let hkdf =
        HkdfSha384::extract(Some(domain::DM_CHANNEL_ROOT_SALT), ss0).map_err(ChainError::Kdf)?;
    expand_secret::<ROOT_LEN, _>(|b| hkdf.expand(domain::DM_CHANNEL_ROOT, b), Root)
}

/// Advance a direction's root by one turn: the previous root is the extraction
/// **salt** and `lp(ss_peer) ‖ lp(ss_own)` the **IKM**.
///
/// Making the previous root the salt is what ties a turn to its ancestor: an
/// attacker holding only the new secret cannot compute the root without the
/// old one, and one holding the old root cannot compute it without the new
/// secret. Both secrets are length-prefixed, so an absent peer secret — the
/// acceptor's first turn — is a distinct input from a shorter present one.
fn advance_root(
    previous: &Root,
    peer_ss: Option<&TurnSecret>,
    own_ss: &TurnSecret,
) -> Result<Root, ChainError> {
    let mut ikm = Vec::with_capacity(2 * (8 + ml_kem::SHARED_SECRET_LEN));
    push_lp(
        &mut ikm,
        peer_ss.map(|s| s.as_bytes().as_slice()).unwrap_or(&[]),
    );
    push_lp(&mut ikm, own_ss.as_bytes());
    let extracted = HkdfSha384::extract(Some(previous.as_bytes()), &ikm);
    ikm.zeroize();
    let hkdf = extracted.map_err(ChainError::Kdf)?;
    expand_secret::<ROOT_LEN, _>(|b| hkdf.expand(domain::DM_CHANNEL_ROOT, b), Root)
}

/// Derive a turn's chain key from its root: `HKDF(R, DM_CHANNEL_CHAIN)`.
fn chain_from_root(root: &Root) -> Result<ChainKey, ChainError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_CHANNEL_CHAIN_SALT), root.as_bytes())
        .map_err(ChainError::Kdf)?;
    expand_secret::<CHAIN_KEY_LEN, _>(|b| hkdf.expand(domain::DM_CHANNEL_CHAIN, b), ChainKey)
}

/// Take one step along a chain: this position's message key and the successor
/// chain key, both from one extraction under sibling labels.
///
/// Consumes the chain key it steps, so a position cannot be stepped twice.
/// Siblings rather than a chain, so a compromised message key yields neither
/// the chain it came from nor its successor — which is what makes deleting the
/// chain key sufficient to protect everything before it.
fn step(ck: ChainKey) -> Result<(MessageKey, ChainKey), ChainError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_CHANNEL_STEP_SALT), ck.as_bytes())
        .map_err(ChainError::Kdf)?;
    let mk =
        expand_secret::<MESSAGE_KEY_LEN, _>(|b| hkdf.expand(domain::DM_CHANNEL_MK, b), MessageKey)?;
    let next =
        expand_secret::<CHAIN_KEY_LEN, _>(|b| hkdf.expand(domain::DM_CHANNEL_CK, b), ChainKey)?;
    Ok((mk, next))
}

/// Mint a turn's ratchet keypair from the caller's entropy.
fn mint(mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>) -> Result<RatchetKeypair, ChainError> {
    let mut d = [0u8; ml_kem::SEED_LEN];
    let mut z = [0u8; ml_kem::SEED_LEN];
    let drawn = fill(&mut d).and_then(|()| fill(&mut z));
    if drawn.is_err() {
        d.zeroize();
        z.zeroize();
        return Err(ChainError::Entropy);
    }
    let mut generated = ml_kem::keygen(&d, &z);
    d.zeroize();
    z.zeroize();
    // Bound by reference, so the secret half stays reachable inside the
    // `Result` and the zeroize below clears it; moving a `Copy` array out
    // would leave that copy on this frame with nothing able to reach it. It
    // does NOT reach the temporary `Box::new(*dk)` materialises on the way
    // into the allocation — the crate's API offers no way to build the box
    // without that copy, so one copy is left for the frame to overwrite.
    match generated {
        Ok((ref ek, ref mut dk)) => {
            let pair = RatchetKeypair {
                pk: Box::new(*ek),
                dk: RatchetDecapKey(Box::new(*dk)),
            };
            dk.zeroize();
            Ok(pair)
        }
        Err(e) => Err(ChainError::Module(e)),
    }
}

/// Encapsulate to a peer's ratchet key, yielding the turn's secret and the
/// ciphertext the header carries.
fn encapsulate(
    peer_pk: &[u8; ml_kem::EK_LEN],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<(TurnSecret, Box<[u8; ml_kem::CT_LEN]>), ChainError> {
    let mut m = [0u8; ml_kem::SEED_LEN];
    if fill(&mut m).is_err() {
        m.zeroize();
        return Err(ChainError::Entropy);
    }
    let encapsulated = ml_kem::encapsulate(peer_pk, &m);
    m.zeroize();
    let (mut ss, ct) = encapsulated.map_err(ChainError::Module)?;
    let secret = TurnSecret(ss);
    ss.zeroize();
    Ok((secret, Box::new(ct)))
}

/// Seal a body under a message key, then zeroize the key's working buffer.
fn seal_under(mk: MessageKey, aad: &[u8], body: &[u8]) -> Result<Vec<u8>, ChainError> {
    let mut raw = *mk.as_bytes();
    drop(mk);
    let outcome = match Aes256Key::new(&raw) {
        Ok(key) => seal_envelope(&key, aad, body).map_err(ChainError::from),
        Err(e) => Err(ChainError::Module(e)),
    };
    finish_with(&mut raw);
    outcome
}

/// Open a body under a message key, then zeroize the key's working buffer.
fn open_under(mk: MessageKey, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, ChainError> {
    let mut raw = *mk.as_bytes();
    drop(mk);
    let outcome = match Aes256Key::new(&raw) {
        Ok(key) => open_envelope(&key, aad, sealed).map_err(ChainError::from),
        Err(e) => Err(ChainError::Module(e)),
    };
    finish_with(&mut raw);
    outcome
}

/// Zeroize a message key's working buffer, recording what it held immediately
/// before and what it holds immediately after.
///
/// Under `cfg(test)` the record is the evidence `last_key_use` hands a test:
/// the `after` half is read back out of the very buffer the `before` half was
/// copied from, so an assertion over it is about this buffer rather than about
/// a claim made of it.
fn finish_with(raw: &mut [u8; MESSAGE_KEY_LEN]) {
    #[cfg(test)]
    let before = *raw;
    raw.zeroize();
    #[cfg(test)]
    record_key_use(KeyUse {
        before,
        after: *raw,
    });
}

/// What one seal or open did with its message key's working buffer.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyUse {
    /// The bytes the buffer held immediately before zeroization.
    pub before: [u8; MESSAGE_KEY_LEN],
    /// The bytes the same buffer held immediately after it.
    pub after: [u8; MESSAGE_KEY_LEN],
}

#[cfg(test)]
thread_local! {
    static LAST_KEY_USE: std::cell::Cell<Option<KeyUse>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn record_key_use(use_: KeyUse) {
    LAST_KEY_USE.with(|slot| slot.set(Some(use_)));
}

/// The most recent [`KeyUse`] on this thread, or `None` before any seal or
/// open has run on it.
#[cfg(test)]
pub(crate) fn last_key_use() -> Option<KeyUse> {
    LAST_KEY_USE.with(|slot| slot.get())
}

/// One turn this party minted: the number a peer header names as its `m`, the
/// keypair, and the secret the turn encapsulated.
///
/// The secret is absent for exactly one turn — the initiator's turn 0, whose
/// ML-KEM step is the hello's own encapsulation rather than a ratchet one.
pub struct OwnTurn {
    /// The turn number a peer header names as its `m`.
    pub m: u64,
    /// The keypair a peer encapsulates to.
    pub keypair: RatchetKeypair,
    /// The secret the turn encapsulated, absent only for the initiator's
    /// turn 0.
    pub ss: Option<TurnSecret>,
}

impl OwnTurn {
    /// A byte-for-byte copy, which is what a state snapshot is.
    fn duplicate(&self) -> Self {
        Self {
            m: self.m,
            keypair: self.keypair.duplicate(),
            ss: self.ss.clone(),
        }
    }
}

/// One turn of the peer's that this party has read: the number its headers
/// carry as `n`, the ratchet key to encapsulate back to, and the secret this
/// party decapsulated from it.
pub struct PeerTurn {
    /// The peer's turn number, as its headers carry it in `n`.
    pub m: u64,
    /// The peer's ratchet public key at that turn.
    pub pk: Box<[u8; ml_kem::EK_LEN]>,
    /// The secret this party decapsulated from it, absent only for the
    /// initiator's turn 0.
    pub ss: Option<TurnSecret>,
}

impl PeerTurn {
    /// A byte-for-byte copy, which is what a state snapshot is.
    fn duplicate(&self) -> Self {
        Self {
            m: self.m,
            pk: self.pk.clone(),
            ss: self.ss.clone(),
        }
    }
}

/// What the sending side has read of the peer since its last message.
///
/// A turn is due when this names a peer turn the direction had not seen
/// before, or when the force-turn flag is set.
pub enum TurnInput<'a> {
    /// Nothing of the peer's has been read since the last message.
    Unchanged,
    /// The peer's turn `m` has been read: the ratchet key it published and the
    /// secret this party decapsulated from it.
    PeerTurn {
        /// The peer's turn number.
        m: u64,
        /// The peer's ratchet public key at that turn.
        peer_pk: &'a [u8; ml_kem::EK_LEN],
        /// The secret this party decapsulated from that turn.
        peer_ss: Option<&'a TurnSecret>,
    },
}

/// What a reset asks of the caller once every direction is flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a reset is not complete until the advert is rotated"]
pub enum ResetAction {
    /// Rotate the advert now, through
    /// [`crate::dm::advert::AdvertKeys::rotate_now`], which is the
    /// off-schedule rotation this reset calls for. The rotation lives there;
    /// this module performs none.
    RotateAdvert,
}

/// The sending half of one direction.
///
/// `chain` is `None` until this direction has stepped a root of its own. The
/// acceptor's sending half opens that way: it holds the seed root as the value
/// its first turn advances from, and no chain at all, so the chain the
/// initiator's direction runs off that same seed is not reachable from here.
pub struct Direction {
    root: Root,
    chain: Option<ChainKey>,
    n: u64,
    m_seen: Option<u64>,
    seq: u64,
    cursor: u64,
    peer_pk: Option<Box<[u8; ml_kem::EK_LEN]>>,
    peer_ss: Option<TurnSecret>,
    pending_turn: Option<OwnTurn>,
    force_turn: bool,
}

impl std::fmt::Debug for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direction")
            .field("n", &self.n)
            .field("opened", &self.chain.is_some())
            .field("m_seen", &self.m_seen)
            .field("seq", &self.seq)
            .field("cursor", &self.cursor)
            .field("force_turn", &self.force_turn)
            .finish()
    }
}

impl Direction {
    /// The turn this direction is writing.
    pub fn turn(&self) -> u64 {
        self.n
    }

    /// The sequence the next message will carry.
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Set the collection cursor the next header publishes — this party's
    /// contiguous collected count over the peer's messages (§ Delivery).
    ///
    /// Crate-private: [`Conversation::seal`] reads the cursor off the reading
    /// half, so a caller setting its own could publish a count of messages
    /// nobody collected.
    pub(crate) fn set_cursor(&mut self, cursor: u64) {
        self.cursor = cursor;
    }

    /// Make the next message start a turn, whatever has been read.
    ///
    /// The flag survives until a message actually starts a turn, so a reset
    /// followed by no send leaves the next send still obliged to re-key.
    pub fn force_next_turn(&mut self) {
        self.force_turn = true;
    }

    /// Whether the next message will start a turn given `input`.
    fn turn_due(&self, input: &TurnInput<'_>) -> bool {
        if self.force_turn {
            return true;
        }
        match input {
            TurnInput::Unchanged => false,
            TurnInput::PeerTurn { m, .. } => self.m_seen.is_none_or(|seen| *m > seen),
        }
    }

    /// The turn this seal minted, if it started one. Taken by the owner of the
    /// retention window; [`ChainError::PendingTurnNotTaken`] refuses a second
    /// seal until it has been.
    fn take_pending_turn(&mut self) -> Option<OwnTurn> {
        self.pending_turn.take()
    }

    /// Seal one message: start a turn where `input` makes one due, step the
    /// chain, derive the message key, seal `body` under
    /// [`channel::message_aad`], and delete the key.
    ///
    /// Nothing in `self` moves until the seal has succeeded: every value is
    /// derived into a local and committed at the end, so a failed seal leaves
    /// the direction exactly where it was and the same sequence is sealable
    /// again.
    ///
    /// Crate-private, because a turn it starts has to reach the retention
    /// window before the next one: [`Conversation::seal`] is the public seal
    /// and drains the minted turn itself, which is what makes
    /// [`ChainError::PendingTurnNotTaken`] an internal invariant rather than a
    /// state a caller can reach.
    pub(crate) fn seal(
        &mut self,
        input: TurnInput<'_>,
        body: &[u8],
        device_id: u32,
        mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<(channel::MessageHeader, Vec<u8>), ChainError> {
        if self.pending_turn.is_some() {
            return Err(ChainError::PendingTurnNotTaken);
        }
        let due = self.turn_due(&input);

        // Whatever the input named is what this message's `m` reports and what
        // a later forced turn encapsulates to, so it is read before the branch.
        let (mut peer_pk, mut peer_ss, mut m_seen) = (None, None, self.m_seen);
        if let TurnInput::PeerTurn {
            m,
            peer_pk: pk,
            peer_ss: ss,
        } = input
            && m_seen.is_none_or(|seen| m > seen)
        {
            peer_pk = Some(Box::new(*pk));
            peer_ss = Some(ss.cloned());
            m_seen = Some(m);
        }
        let peer_pk = peer_pk.or_else(|| self.peer_pk.clone());
        let peer_ss = peer_ss.unwrap_or_else(|| self.peer_ss.clone());

        let (root, chain, n, minted) = if due {
            let pk = peer_pk.as_ref().ok_or(ChainError::NoPeerKey)?;
            let keypair = mint(&mut fill)?;
            let (own_ss, kem_ct) = encapsulate(pk, &mut fill)?;
            let root = advance_root(&self.root, peer_ss.as_ref(), &own_ss)?;
            let chain = chain_from_root(&root)?;
            let n = if self.chain.is_some() {
                self.n + 1
            } else {
                self.n
            };
            (root, chain, n, Some((keypair, own_ss, kem_ct)))
        } else {
            let chain = self.chain.clone().ok_or(ChainError::NoTurn)?;
            (self.root.clone(), chain, self.n, None)
        };

        let header = channel::MessageHeader {
            device_id,
            n,
            m: m_seen.unwrap_or(0),
            seq: self.seq,
            cursor: self.cursor,
            kem_ct: minted.as_ref().map(|(_, _, ct)| ct.clone()),
            kem_pk: minted.as_ref().map(|(pair, _, _)| pair.pk.clone()),
        };
        let (mk, next_chain) = step(chain)?;
        let sealed = seal_under(mk, &channel::message_aad(&header), body)?;

        self.root = root;
        self.chain = Some(next_chain);
        self.n = n;
        self.m_seen = m_seen;
        self.seq += 1;
        self.peer_pk = peer_pk;
        self.peer_ss = peer_ss;
        self.force_turn = false;
        if let Some((keypair, own_ss, _)) = minted {
            self.pending_turn = Some(OwnTurn {
                m: n,
                keypair,
                ss: Some(own_ss),
            });
        }
        Ok((header, sealed))
    }
}

/// The reading half of one direction: the peer's root and chain, the peer's
/// latest ratchet key, and this party's retained own turns.
pub struct Receiving {
    root: Root,
    chain: Option<ChainKey>,
    n: u64,
    next_seq: u64,
    own_turns: [Option<OwnTurn>; OWN_TURNS_RETAINED],
    peer_latest: Option<PeerTurn>,
}

impl std::fmt::Debug for Receiving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiving")
            .field("n", &self.n)
            .field("opened", &self.chain.is_some())
            .field("next_seq", &self.next_seq)
            .field("retained_own_turns", &self.retained_own_turns())
            .finish()
    }
}

impl Receiving {
    /// The sequence this side expects next.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The peer turn this side has read up to.
    pub fn turn(&self) -> u64 {
        self.n
    }

    /// How many own turns are retained — at most [`OWN_TURNS_RETAINED`].
    pub fn retained_own_turns(&self) -> usize {
        self.own_turns.iter().filter(|t| t.is_some()).count()
    }

    /// Retain a freshly minted own turn, dropping the third-oldest.
    fn retain(&mut self, turn: OwnTurn) {
        self.own_turns[1] = self.own_turns[0].take();
        self.own_turns[0] = Some(turn);
    }

    /// Open one message: recompute the peer's root where the header starts a
    /// turn, run the chain forward one position, open the body, and delete the
    /// key.
    ///
    /// Nothing in `self` moves until the open has succeeded, so a body that
    /// fails to authenticate leaves the chain where it was and the genuine
    /// message at that sequence still opens.
    ///
    /// A header carrying one turn field without the other is
    /// [`ChainError::TurnFieldsIncomplete`], refused before any derivation:
    /// [`channel::MessageHeader::decode`] rejects that shape on the wire, but a
    /// header reaching this call need not have come through it, and reading a
    /// ciphertext without the public key it pairs with would derive a root off
    /// a decapsulation no peer performed.
    pub fn open(
        &mut self,
        header: &channel::MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        if header.seq < self.next_seq {
            return Err(ChainError::AlreadyOpened { seq: header.seq });
        }
        if header.seq > self.next_seq {
            return Err(ChainError::OutOfOrder {
                expected: self.next_seq,
                found: header.seq,
            });
        }

        let (root, chain, n, read) = match (&header.kem_ct, &header.kem_pk) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ChainError::TurnFieldsIncomplete);
            }
            (Some(kem_ct), Some(kem_pk)) => {
                let own = self
                    .own_turns
                    .iter()
                    .flatten()
                    .find(|t| t.m == header.m)
                    .ok_or(ChainError::SecretGone { named: header.m })?;
                let mut decapsulated = ml_kem::decapsulate(own.keypair.dk.as_bytes(), kem_ct)
                    .map_err(ChainError::Module)?;
                let peer_ss = TurnSecret(decapsulated);
                decapsulated.zeroize();
                let root = advance_root(&self.root, own.ss.as_ref(), &peer_ss)?;
                let chain = chain_from_root(&root)?;
                let read = PeerTurn {
                    m: header.n,
                    pk: kem_pk.clone(),
                    ss: Some(peer_ss),
                };
                (root, chain, header.n, Some(read))
            }
            (None, None) => {
                let chain = self.chain.clone().ok_or(ChainError::NoTurn)?;
                (self.root.clone(), chain, self.n, None)
            }
        };

        let (mk, next_chain) = step(chain)?;
        let body = open_under(mk, &channel::message_aad(header), ciphertext)?;

        self.root = root;
        self.chain = Some(next_chain);
        self.n = n;
        self.next_seq += 1;
        if let Some(read) = read {
            // A message encapsulated to the newer of the two has been opened,
            // which is the condition the design puts on deleting the older.
            if self.own_turns[0].as_ref().is_some_and(|t| t.m == header.m) {
                self.own_turns[1] = None;
            }
            self.peer_latest = Some(read);
        }
        Ok(body)
    }
}

/// Both halves of one conversation, and the only thing that keeps them in
/// step.
///
/// The two halves are crossed: a direction's next root mixes the secret its
/// *reading* half decapsulated, and a reading half's root recomputation mixes
/// the secret its *sending* half encapsulated. Each secret therefore exists in
/// exactly one place, and this type carries it across rather than letting the
/// two halves each keep a copy that can disagree.
pub struct Conversation {
    sending: Direction,
    receiving: Receiving,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("sending", &self.sending)
            .field("receiving", &self.receiving)
            .finish()
    }
}

impl Conversation {
    /// The sending half.
    pub fn sending(&self) -> &Direction {
        &self.sending
    }

    /// The reading half.
    pub fn receiving(&self) -> &Receiving {
        &self.receiving
    }

    /// Seal one message, publishing the reading half's cursor in its header
    /// and retaining any turn the seal minted.
    pub fn seal(
        &mut self,
        body: &[u8],
        device_id: u32,
        fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    ) -> Result<(channel::MessageHeader, Vec<u8>), ChainError> {
        let input = match &self.receiving.peer_latest {
            Some(peer) => TurnInput::PeerTurn {
                m: peer.m,
                peer_pk: &peer.pk,
                peer_ss: peer.ss.as_ref(),
            },
            None => TurnInput::Unchanged,
        };
        self.sending.set_cursor(self.receiving.next_seq);
        let sealed = self.sending.seal(input, body, device_id, fill)?;
        if let Some(turn) = self.sending.take_pending_turn() {
            self.receiving.retain(turn);
        }
        Ok(sealed)
    }

    /// Open one message of the peer's.
    pub fn open(
        &mut self,
        header: &channel::MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        self.receiving.open(header, ciphertext)
    }

    /// Everything a restart needs to resume this conversation.
    ///
    /// Taken by copy rather than by move, so a caller persists the state its
    /// next write depends on before performing that write — the ordering
    /// § Flows, *Restart at any point* requires — and keeps using the live
    /// conversation afterwards.
    pub fn snapshot(&self) -> ConversationSnapshot {
        ConversationSnapshot {
            sending: DirectionState {
                root: self.sending.root.clone(),
                chain: self.sending.chain.clone(),
                n: self.sending.n,
                m_seen: self.sending.m_seen,
                seq: self.sending.seq,
                cursor: self.sending.cursor,
                peer_pk: self.sending.peer_pk.clone(),
                peer_ss: self.sending.peer_ss.clone(),
                pending_turn: self.sending.pending_turn.as_ref().map(OwnTurn::duplicate),
                force_turn: self.sending.force_turn,
            },
            receiving: ReceivingState {
                root: self.receiving.root.clone(),
                chain: self.receiving.chain.clone(),
                n: self.receiving.n,
                next_seq: self.receiving.next_seq,
                own_turns: [
                    self.receiving.own_turns[0].as_ref().map(OwnTurn::duplicate),
                    self.receiving.own_turns[1].as_ref().map(OwnTurn::duplicate),
                ],
                peer_latest: self.receiving.peer_latest.as_ref().map(PeerTurn::duplicate),
            },
        }
    }

    /// Rebuild a conversation from a snapshot.
    ///
    /// Total in its input and fallible in nothing: every field is state this
    /// module wrote, so there is no derivation to redo on the way back and a
    /// resumed conversation sits exactly where the snapshot was taken.
    pub fn restore(state: ConversationSnapshot) -> Self {
        let ConversationSnapshot { sending, receiving } = state;
        Self {
            sending: Direction {
                root: sending.root,
                chain: sending.chain,
                n: sending.n,
                m_seen: sending.m_seen,
                seq: sending.seq,
                cursor: sending.cursor,
                peer_pk: sending.peer_pk,
                peer_ss: sending.peer_ss,
                pending_turn: sending.pending_turn,
                force_turn: sending.force_turn,
            },
            receiving: Receiving {
                root: receiving.root,
                chain: receiving.chain,
                n: receiving.n,
                next_seq: receiving.next_seq,
                own_turns: receiving.own_turns,
                peer_latest: receiving.peer_latest,
            },
        }
    }
}

/// One conversation's key-schedule state at rest, both halves.
///
/// Every secret in it is a zeroize-on-drop newtype, so a snapshot a caller
/// drops takes its key material with it.
pub struct ConversationSnapshot {
    /// The sending half's state.
    pub sending: DirectionState,
    /// The reading half's state.
    pub receiving: ReceivingState,
}

/// The sending half of one direction at rest.
pub struct DirectionState {
    /// The root of the turn being written.
    pub root: Root,
    /// The chain at its next position, absent before this direction's first
    /// own turn.
    pub chain: Option<ChainKey>,
    /// The turn being written.
    pub n: u64,
    /// The peer turn consumed by the last message written.
    pub m_seen: Option<u64>,
    /// The sequence the next message will carry.
    pub seq: u64,
    /// The collection cursor the next header will publish.
    pub cursor: u64,
    /// The peer's latest ratchet public key, to encapsulate the next turn to.
    pub peer_pk: Option<Box<[u8; ml_kem::EK_LEN]>>,
    /// The peer secret the next turn's root will mix.
    pub peer_ss: Option<TurnSecret>,
    /// A turn minted by a seal and not yet retained.
    pub pending_turn: Option<OwnTurn>,
    /// Whether the next message is obliged to start a turn.
    pub force_turn: bool,
}

/// The reading half of one direction at rest.
pub struct ReceivingState {
    /// The root of the peer turn being read.
    pub root: Root,
    /// The chain at its next position, absent before the peer's first turn.
    pub chain: Option<ChainKey>,
    /// The peer turn being read.
    pub n: u64,
    /// The sequence expected next.
    pub next_seq: u64,
    /// The retained own turns, newest first.
    pub own_turns: [Option<OwnTurn>; OWN_TURNS_RETAINED],
    /// The peer's latest turn as read.
    pub peer_latest: Option<PeerTurn>,
}

/// What [`initiate`] hands back: the conversation and the ratchet public key
/// the channel opening publishes.
pub struct Opening {
    /// The initiator's turn-0 ratchet public key, signed into the channel
    /// opening so the acceptor can encapsulate its own first turn to it.
    pub ratchet_pk: Box<[u8; ml_kem::EK_LEN]>,
    /// The conversation, with turn 0 of the initiator's direction open.
    pub conversation: Conversation,
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opening")
            .field("conversation", &self.conversation)
            .finish_non_exhaustive()
    }
}

/// Open a conversation as the initiator, from the hello's shared secret.
///
/// Turn 0 of the initiator's direction is open on return: its ML-KEM step is
/// the hello's own encapsulation, so the first message carries no turn fields
/// and [`Opening::ratchet_pk`] travels in the channel opening instead.
pub fn initiate(
    ss0: &crate::dm::advert::AdvertSharedSecret,
    fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<Opening, ChainError> {
    let root = seed_root(ss0.as_bytes())?;
    let chain = chain_from_root(&root)?;
    let keypair = mint(fill)?;
    let ratchet_pk = keypair.pk.clone();
    let mut receiving = fresh_receiving(&root, None);
    receiving.retain(OwnTurn {
        m: 0,
        keypair,
        ss: None,
    });
    Ok(Opening {
        ratchet_pk,
        conversation: Conversation {
            sending: Direction {
                root,
                chain: Some(chain),
                n: 0,
                m_seen: None,
                seq: 0,
                cursor: 0,
                peer_pk: None,
                peer_ss: None,
                pending_turn: None,
                force_turn: false,
            },
            receiving,
        },
    })
}

/// Open a conversation as the acceptor, from the hello's shared secret and the
/// initiator's first ratchet key as read from its channel opening.
///
/// The acceptor's turn 0 is a ratchet turn like every other, so its first
/// message carries `kem_ct` and `kem_pk`. Its reading half starts with the
/// initiator's turn 0 already open, which is what makes the initiator's first
/// message — carrying no turn fields — readable.
pub fn accept(
    ss0: &crate::dm::advert::AdvertSharedSecret,
    initiator_ratchet_pk: &[u8; ml_kem::EK_LEN],
) -> Result<Conversation, ChainError> {
    let root = seed_root(ss0.as_bytes())?;
    let mut receiving = fresh_receiving(&root, Some(chain_from_root(&root)?));
    receiving.peer_latest = Some(PeerTurn {
        m: 0,
        pk: Box::new(*initiator_ratchet_pk),
        ss: None,
    });
    Ok(Conversation {
        sending: Direction {
            root,
            chain: None,
            n: 0,
            m_seen: None,
            seq: 0,
            cursor: 0,
            peer_pk: None,
            peer_ss: None,
            pending_turn: None,
            force_turn: false,
        },
        receiving,
    })
}

/// A reading half at the seed root. `chain` is `Some` only where the peer's
/// turn 0 is already established, which is the acceptor reading the initiator.
fn fresh_receiving(root: &Root, chain: Option<ChainKey>) -> Receiving {
    Receiving {
        root: root.clone(),
        chain,
        n: 0,
        next_seq: 0,
        own_turns: [None, None],
        peer_latest: None,
    }
}

/// Force a new turn on every conversation and name the advert rotation the
/// reset also requires.
///
/// One [`ResetAction`] for the whole slice, because the advert is one record
/// for the identity rather than one per correspondent: the caller performs
/// [`crate::dm::advert::AdvertKeys::rotate_now`] once, however many
/// conversations were flagged. It is returned rather than performed here
/// because it belongs to that module, and a reset that silently rotated would
/// leave this one holding advert state it has no other reason to hold.
pub fn reset_all(conversations: &mut [Conversation]) -> ResetAction {
    for conversation in conversations.iter_mut() {
        conversation.sending.force_next_turn();
    }
    ResetAction::RotateAdvert
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::advert;
    use crate::identity::keys::SignKeypair;

    /// A moment inside every advert's usability window.
    const NOW: u64 = 1_700_000_000;

    /// A seeded fill. Deterministic, so a failing run replays from the source
    /// alone, and never constant, so two keypairs from one instance differ.
    struct Seeded(u64);

    impl Seeded {
        fn at(seed: u64) -> Self {
            Self(seed)
        }

        fn fill(&mut self, buf: &mut [u8]) -> Result<(), ()> {
            for b in buf.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    fn counting_fill(byte: u8) -> impl FnMut(&mut [u8]) -> Result<(), ()> {
        let mut counter = byte;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// A shared secret by the real path: `AdvertSharedSecret` is constructible
    /// only by encapsulating to or decapsulating an advert key.
    fn ss0(seed: u8) -> advert::AdvertSharedSecret {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let signer = SignKeypair::from_ml_dsa_seed(&[seed; 32]).expect("derive a signer");
        let keys = advert::AdvertKeys::new(NOW, counting_fill(seed)).expect("advert keys");
        let bytes = keys.advert_bytes(&signer).expect("advert bytes");
        let verified = advert::verify(signer.public_key(), &bytes).expect("verify the advert");
        advert::encapsulate_to(&verified, NOW, counting_fill(seed ^ 0x5a))
            .expect("encapsulate")
            .shared_secret
    }

    /// Two conversations sharing one `ss0`, the initiator's first ratchet key
    /// already handed to the acceptor as a channel opening would.
    fn pair() -> (Conversation, Conversation, Seeded, Seeded) {
        let secret = ss0(0x21);
        let mut entropy = Seeded::at(11);
        let opening = initiate(&secret, |b| entropy.fill(b)).expect("initiate");
        let acceptor = accept(&secret, &opening.ratchet_pk).expect("accept");
        (
            opening.conversation,
            acceptor,
            Seeded::at(101),
            Seeded::at(202),
        )
    }

    impl Conversation {
        /// A copy of this conversation, which is what copying a device makes,
        /// built through the shipped snapshot rather than beside it.
        fn clone_state(&self) -> Self {
            Self::restore(self.snapshot())
        }

        /// Retain one own turn instead of [`OWN_TURNS_RETAINED`] — the control
        /// for the crossing-turns test.
        fn forget_older_own_turn(&mut self) {
            self.receiving.own_turns[1] = None;
        }
    }

    // ── the exchange ────────────────────────────────────────────────────────

    /// Ten messages each way, strictly alternating. Every message opens with
    /// the body that was sealed, and the turn fields appear on exactly the
    /// first message of each turn.
    ///
    /// The turn-field assertion is the control on the body assertion: bodies
    /// would still round-trip if every message re-keyed, or if none did, so
    /// the headers are what say the turn rule is the one running.
    #[test]
    fn an_alternating_exchange_opens_every_message() {
        let (mut a, mut b, mut ea, mut eb) = pair();

        for round in 0..10u64 {
            let body = format!("a says {round}");
            let (header, sealed) = a.seal(body.as_bytes(), 0, |x| ea.fill(x)).expect("a seals");
            // The initiator's turn 0 is open from `initiate`, so only its very
            // first message carries no turn fields; every later one starts a
            // turn, having just read one of the acceptor's.
            assert_eq!(
                header.starts_turn(),
                round > 0,
                "a's message {round} carries the wrong turn fields"
            );
            assert_eq!(header.seq, round, "a's sequence is the message count");
            assert_eq!(b.open(&header, &sealed).expect("b opens"), body.as_bytes());

            let reply = format!("b says {round}");
            let (header, sealed) = b
                .seal(reply.as_bytes(), 0, |x| eb.fill(x))
                .expect("b seals");
            assert!(
                header.starts_turn(),
                "every one of b's messages follows a turn of a's it had not seen"
            );
            assert_eq!(a.open(&header, &sealed).expect("a opens"), reply.as_bytes());
        }

        // A second message inside one turn carries no turn fields, which is
        // the other half of the rule the loop above cannot show.
        let (first, sealed_first) = a.seal(b"one", 0, |x| ea.fill(x)).expect("a seals");
        let mk_first = last_key_use().expect("a seal records its key").before;
        let (second, sealed_second) = a.seal(b"two", 0, |x| ea.fill(x)).expect("a seals again");
        let mk_second = last_key_use().expect("a seal records its key").before;
        assert!(first.starts_turn(), "the turn's first message re-keys");
        assert!(
            !second.starts_turn(),
            "a later message in the turn does not"
        );
        // The chain advances within a turn as well as across turns. Both
        // messages open either way, so this is what a chain that handed out one
        // key twice would fail — and it would reuse an AES-GCM key, not merely
        // repeat a value.
        assert_ne!(
            mk_first, mk_second,
            "two messages of one turn must not share a message key"
        );
        assert_eq!(b.open(&first, &sealed_first).unwrap(), b"one");
        assert_eq!(b.open(&second, &sealed_second).unwrap(), b"two");
    }

    /// The cursor a header publishes is the reading half's contiguous count,
    /// which is what § Delivery has a reply carry.
    #[test]
    fn a_header_publishes_the_reading_halfs_cursor() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (header, sealed) = a.seal(b"one", 0, |x| ea.fill(x)).unwrap();
        assert_eq!(header.cursor, 0, "a has collected nothing yet");
        b.open(&header, &sealed).unwrap();

        let (reply, sealed) = b.seal(b"two", 0, |x| eb.fill(x)).unwrap();
        assert_eq!(reply.cursor, 1, "b has collected a's first message");
        a.open(&reply, &sealed).unwrap();
    }

    // ── crossing turns ──────────────────────────────────────────────────────

    /// Both sides start a turn without having read the other's, each
    /// encapsulating to the key the other has already replaced. Both messages
    /// open, off the older of the two retained own turns.
    ///
    /// A strictly alternating exchange never crosses — each side's turn
    /// consumes the peer turn that made it due, so at most one side is ever
    /// due. What makes two turns cross is a side starting one it did not read
    /// its way into, which is what a reset does, so the reset flag is what puts
    /// the two writers in the same moment here.
    ///
    /// Control: the same header and ciphertext against a reading half holding
    /// one own turn instead of two fails `SecretGone`, so the opens above are
    /// the retention window and not something else.
    #[test]
    fn crossing_turns_both_open_and_one_retained_turn_refuses() {
        let (mut a, mut b, mut ea, mut eb) = pair();

        // Alternate until each side holds a fresh turn and the one before it.
        let (h, s) = a.seal(b"a1", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b1", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();
        let (h, s) = a.seal(b"a2", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b2", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();

        // a is due and b is not, so b is the side the reset moves.
        let (a_header, a_sealed) = a.seal(b"crossing from a", 0, |x| ea.fill(x)).unwrap();
        b.sending.force_next_turn();
        let (b_header, b_sealed) = b.seal(b"crossing from b", 0, |x| eb.fill(x)).unwrap();
        assert!(a_header.starts_turn() && b_header.starts_turn());
        assert_eq!(a.receiving().retained_own_turns(), OWN_TURNS_RETAINED);
        assert_eq!(b.receiving().retained_own_turns(), OWN_TURNS_RETAINED);

        // Each names the other's earlier turn, which is the crossing case.
        assert_eq!(a_header.m, a.sending().turn() - 1);
        assert_eq!(b_header.m, b.sending().turn() - 1);

        let mut narrowed = a.clone_state();
        assert_eq!(a.open(&b_header, &b_sealed).unwrap(), b"crossing from b");
        assert_eq!(b.open(&a_header, &a_sealed).unwrap(), b"crossing from a");

        // The control, on the same header and ciphertext.
        narrowed.forget_older_own_turn();
        assert_eq!(narrowed.receiving().retained_own_turns(), 1);
        assert_eq!(
            narrowed.open(&b_header, &b_sealed),
            Err(ChainError::SecretGone { named: b_header.m }),
            "with one retained turn the crossing message cannot open"
        );
    }

    /// The older own turn is deleted once a message encapsulated to the newer
    /// has been opened.
    ///
    /// Control: the window held both immediately before that open, so the drop
    /// below is the rule firing and not a window that was never filled.
    #[test]
    fn the_older_own_turn_goes_once_the_newer_is_used() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a1", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b1", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();

        let (h, s) = a.seal(b"a2", 0, |x| ea.fill(x)).unwrap();
        assert_eq!(
            a.receiving().retained_own_turns(),
            OWN_TURNS_RETAINED,
            "the control"
        );
        b.open(&h, &s).unwrap();

        let (h, s) = b.seal(b"b2", 0, |x| eb.fill(x)).unwrap();
        assert_eq!(h.m, 1, "b encapsulated to a's newest turn");
        a.open(&h, &s).unwrap();
        assert_eq!(a.receiving().retained_own_turns(), 1);
    }

    // ── ordering and deletion ───────────────────────────────────────────────

    /// A second open of a sequence already opened fails: the chain has moved
    /// past it and no skipped key is stored.
    ///
    /// Control: the first open succeeded with the body that was sealed.
    #[test]
    fn a_second_open_of_one_sequence_fails() {
        let (mut a, mut b, mut ea, _) = pair();
        let (header, sealed) = a.seal(b"once", 0, |x| ea.fill(x)).unwrap();
        assert_eq!(b.open(&header, &sealed).unwrap(), b"once", "the control");
        assert_eq!(
            b.open(&header, &sealed),
            Err(ChainError::AlreadyOpened { seq: 0 })
        );
    }

    /// A sequence other than the next expected is refused.
    ///
    /// Control: the message it skipped opens, and the skipped one then opens
    /// after it.
    #[test]
    fn an_out_of_order_header_is_refused() {
        let (mut a, mut b, mut ea, _) = pair();
        let (first, sealed_first) = a.seal(b"first", 0, |x| ea.fill(x)).unwrap();
        let (second, sealed_second) = a.seal(b"second", 0, |x| ea.fill(x)).unwrap();

        assert_eq!(
            b.open(&second, &sealed_second),
            Err(ChainError::OutOfOrder {
                expected: 0,
                found: 1
            })
        );
        assert_eq!(b.open(&first, &sealed_first).unwrap(), b"first");
        assert_eq!(b.open(&second, &sealed_second).unwrap(), b"second");
    }

    /// A continuing header on a reading half that has read no turn has no
    /// chain to step.
    #[test]
    fn a_continuing_header_with_no_turn_read_is_refused() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (turn, sealed) = b.seal(b"b", 0, |x| eb.fill(x)).unwrap();
        let continuing = channel::MessageHeader::continuing(0, turn.n, turn.m, turn.seq, 0);
        assert_eq!(a.open(&continuing, &sealed), Err(ChainError::NoTurn));
        // Control: the turn-starting header the continuing one was built from
        // opens on the same reading half.
        assert_eq!(a.open(&turn, &sealed).unwrap(), b"b");
    }

    /// The message key's buffer is zeroized before `seal` and before `open`
    /// return.
    ///
    /// Control: the copy taken from the same buffer immediately before the
    /// zeroization is non-zero, so the assertion is about a buffer that held a
    /// key rather than one that was never written.
    #[test]
    fn the_message_key_buffer_is_zeroized_on_both_sides() {
        let (mut a, mut b, mut ea, _) = pair();
        let (header, sealed) = a.seal(b"deleted after use", 0, |x| ea.fill(x)).unwrap();
        let after_seal = last_key_use().expect("a seal records its key use");
        assert_ne!(after_seal.before, [0u8; MESSAGE_KEY_LEN], "the control");
        assert_eq!(after_seal.after, [0u8; MESSAGE_KEY_LEN]);

        b.open(&header, &sealed).unwrap();
        let after_open = last_key_use().expect("an open records its key use");
        assert_ne!(after_open.before, [0u8; MESSAGE_KEY_LEN], "the control");
        assert_eq!(after_open.after, [0u8; MESSAGE_KEY_LEN]);
        assert_eq!(
            after_open.before, after_seal.before,
            "both sides used one key"
        );
    }

    // ── the associated data ─────────────────────────────────────────────────

    /// The header is bound to the body it heads: a sequence or turn number
    /// rewritten after the seal leaves a body that does not open.
    ///
    /// Control: the untouched header opens the same ciphertext.
    #[test]
    fn a_rewritten_header_field_fails_the_open() {
        let (mut a, mut b, mut ea, _) = pair();
        let (header, sealed) = a.seal(b"bound to its header", 0, |x| ea.fill(x)).unwrap();

        let mut tampered = header.clone();
        tampered.cursor = header.cursor + 1;
        assert_eq!(b.open(&tampered, &sealed), Err(ChainError::Aead));

        let mut renumbered = header.clone();
        renumbered.n = header.n + 1;
        assert_eq!(b.open(&renumbered, &sealed), Err(ChainError::Aead));

        assert_eq!(
            b.open(&header, &sealed).unwrap(),
            b"bound to its header",
            "the control"
        );
    }

    // ── reset ───────────────────────────────────────────────────────────────

    /// A forced turn re-keys the next message with nothing new read, and
    /// `reset_all` flags every direction and names the advert rotation.
    #[test]
    fn a_forced_turn_re_keys_the_next_message() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();
        // The turn that peer turn made due, so the next message is not due.
        let (h, s) = a.seal(b"a2", 0, |x| ea.fill(x)).unwrap();
        assert!(h.starts_turn());
        b.open(&h, &s).unwrap();

        // Control: with nothing new read the next message would not re-key.
        let (h, s) = a.seal(b"same turn", 0, |x| ea.fill(x)).unwrap();
        assert!(!h.starts_turn(), "no new inbound, no new turn");
        b.open(&h, &s).unwrap();

        let mut conversations = [a];
        assert_eq!(reset_all(&mut conversations), ResetAction::RotateAdvert);
        let [mut a] = conversations;
        let (h, s) = a.seal(b"after reset", 0, |x| ea.fill(x)).unwrap();
        assert!(
            h.starts_turn(),
            "the reset forced a turn with no new inbound"
        );
        assert_eq!(b.open(&h, &s).unwrap(), b"after reset");
    }

    /// One `reset_all` flags every conversation it is given, not only the
    /// first, and answers with one advert rotation for all of them.
    #[test]
    fn reset_all_flags_every_conversation() {
        let (first, _, _, _) = pair();
        let (second, _, _, _) = pair();
        let mut conversations = [first, second];
        // Control: neither is flagged before the call.
        assert!(!conversations.iter().any(|c| c.sending.force_turn));
        assert_eq!(reset_all(&mut conversations), ResetAction::RotateAdvert);
        assert!(conversations.iter().all(|c| c.sending.force_turn));
    }

    // ── forward secrecy against a clone ─────────────────────────────────────

    /// A copy of the reading state taken at one moment reads the rest of the
    /// turn it was taken in and nothing past the next turn.
    ///
    /// This is § Keys' *After the compromise* case: once each party has
    /// completed one turn the other has read, later messages are secret again.
    /// The snapshot holds the two own turns that existed when it was taken; the
    /// turn the live side mints afterwards is the one the peer then
    /// encapsulates to, and the snapshot has no secret for it.
    ///
    /// Control: the message inside the turn the snapshot was taken in still
    /// opens from the snapshot, so the failure below is the new turn and not a
    /// snapshot that never worked.
    #[test]
    fn a_snapshot_reads_its_own_turn_and_not_the_next() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a1", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b1", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();

        let mut cloned = a.clone_state();

        // Inside the turn the snapshot was taken in.
        let (h, s) = b.seal(b"still readable", 0, |x| eb.fill(x)).unwrap();
        assert!(
            !h.starts_turn(),
            "b has read nothing new, so the turn holds"
        );
        assert_eq!(
            cloned.open(&h, &s).unwrap(),
            b"still readable",
            "the control"
        );
        a.open(&h, &s).unwrap();

        // The live side takes a turn the snapshot never saw, and b's reply
        // encapsulates to it.
        let (h, s) = a.seal(b"a2", 0, |x| ea.fill(x)).unwrap();
        assert!(h.starts_turn());
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"past the heal", 0, |x| eb.fill(x)).unwrap();
        assert!(h.starts_turn());
        assert_eq!(
            cloned.open(&h, &s),
            Err(ChainError::SecretGone { named: h.m }),
            "the snapshot holds no secret for the turn a minted after it"
        );
        assert_eq!(
            a.open(&h, &s).unwrap(),
            b"past the heal",
            "the live side reads it"
        );
    }

    // ── restart ─────────────────────────────────────────────────────────────

    /// A snapshot taken mid-turn restores a conversation that keeps reading and
    /// writing where it left off, in both directions.
    ///
    /// Control: the same snapshot with `force_turn` cleared does not start a
    /// turn on its next send while the one carrying it does, so the flag is
    /// genuinely carried rather than defaulted.
    #[test]
    fn a_snapshot_restores_a_conversation_mid_turn() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a1", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b1", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();
        // a has just started turn 1, so the snapshot is taken inside it.
        let (h, s) = a.seal(b"a2", 0, |x| ea.fill(x)).unwrap();
        assert!(h.starts_turn());
        b.open(&h, &s).unwrap();

        let mut resumed = Conversation::restore(a.snapshot());
        assert_eq!(resumed.sending().next_seq(), a.sending().next_seq());
        assert_eq!(resumed.receiving().next_seq(), a.receiving().next_seq());

        let (h, s) = b.seal(b"b2", 0, |x| eb.fill(x)).unwrap();
        assert_eq!(resumed.open(&h, &s).unwrap(), b"b2", "it reads on");
        let (h, s) = resumed.seal(b"a3", 0, |x| ea.fill(x)).unwrap();
        assert!(h.starts_turn(), "and re-keys on the turn b2 made due");
        assert_eq!(b.open(&h, &s).unwrap(), b"a3", "and b opens what it wrote");

        resumed.sending.force_next_turn();
        let flagged = resumed.snapshot();
        assert!(flagged.sending.force_turn);
        let mut cleared = resumed.snapshot();
        cleared.sending.force_turn = false;
        let (forced, _) = Conversation::restore(flagged)
            .seal(b"x", 0, |x| ea.fill(x))
            .unwrap();
        assert!(forced.starts_turn(), "the restored flag forces a turn");
        let (unforced, _) = Conversation::restore(cleared)
            .seal(b"x", 0, |x| ea.fill(x))
            .unwrap();
        assert!(
            !unforced.starts_turn(),
            "the control: with the flag cleared the same state does not"
        );
    }

    /// A seal whose entropy fails leaves the direction untouched, and the same
    /// seal then succeeds with a working fill at the same sequence.
    #[test]
    fn a_failed_seal_leaves_the_direction_where_it_was() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a1", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (h, s) = b.seal(b"b1", 0, |x| eb.fill(x)).unwrap();
        a.open(&h, &s).unwrap();
        a.sending.force_next_turn();
        let before = a.snapshot();

        assert_eq!(
            a.seal(b"lost", 0, |_: &mut [u8]| Err(())),
            Err(ChainError::Entropy)
        );
        assert_eq!(a.sending.seq, before.sending.seq, "the sequence held");
        assert_eq!(a.sending.n, before.sending.n, "the turn held");
        assert_eq!(
            a.sending.m_seen, before.sending.m_seen,
            "the peer turn held"
        );
        assert!(a.sending.force_turn, "the force-turn flag survived");
        assert!(a.sending.pending_turn.is_none(), "no turn was left pending");

        let (h, s) = a.seal(b"kept", 0, |x| ea.fill(x)).unwrap();
        assert!(h.starts_turn(), "the flag still fires on the retry");
        assert_eq!(h.seq, before.sending.seq, "at the sequence that failed");
        assert_eq!(b.open(&h, &s).unwrap(), b"kept");
    }

    /// A forced turn before any peer ratchet key has been read has nothing to
    /// encapsulate to.
    ///
    /// Control: with the flag cleared the same state seals inside the turn the
    /// initiator opened, so the refusal is the missing peer key.
    #[test]
    fn a_forced_turn_with_no_peer_key_read_is_refused() {
        let (mut a, _b, mut ea, _eb) = pair();
        a.sending.force_next_turn();
        assert_eq!(
            a.seal(b"nowhere", 0, |x| ea.fill(x)),
            Err(ChainError::NoPeerKey)
        );
        a.sending.force_turn = false;
        assert!(a.seal(b"here", 0, |x| ea.fill(x)).is_ok(), "the control");
    }

    /// A header carrying one turn field without the other is refused before any
    /// derivation runs over it.
    ///
    /// Control: the complete header opens the same ciphertext.
    #[test]
    fn a_header_carrying_one_turn_field_is_refused() {
        let (mut a, mut b, mut ea, mut eb) = pair();
        let (h, s) = a.seal(b"a1", 0, |x| ea.fill(x)).unwrap();
        b.open(&h, &s).unwrap();
        let (turn, sealed) = b.seal(b"b1", 0, |x| eb.fill(x)).unwrap();
        assert!(turn.starts_turn());

        let mut ct_only = turn.clone();
        ct_only.kem_pk = None;
        assert_eq!(
            a.open(&ct_only, &sealed),
            Err(ChainError::TurnFieldsIncomplete)
        );
        let mut pk_only = turn.clone();
        pk_only.kem_ct = None;
        assert_eq!(
            a.open(&pk_only, &sealed),
            Err(ChainError::TurnFieldsIncomplete)
        );
        assert_eq!(a.open(&turn, &sealed).unwrap(), b"b1", "the control");
    }

    // ── the derivation itself ───────────────────────────────────────────────

    /// Known-answer test over the derivation, from a fixed `ss0` and fixed
    /// ratchet secrets drawn from a seeded fill.
    ///
    /// It pins the seed root, the seed root's chain key, the root after one
    /// turn, and the message key and successor chain key at the first position
    /// of that turn — every value the derivation produces. Nothing
    /// else in this module would notice a re-plumbed derivation: every other
    /// test seals and opens through the same code on both sides, so a changed
    /// salt, label, input order or length prefix passes them all while
    /// silently breaking every peer running the shipped one.
    #[test]
    fn the_derivation_is_pinned() {
        let secret = ss0(0x21);
        let root = seed_root(secret.as_bytes()).unwrap();
        let chain = chain_from_root(&root).unwrap();
        let mut entropy = Seeded::at(7);
        let keypair = mint(|b| entropy.fill(b)).unwrap();
        let (own_ss, _) = encapsulate(&keypair.pk, |b| entropy.fill(b)).unwrap();
        let turned = advance_root(&root, None, &own_ss).unwrap();
        let (mk, next) = step(chain_from_root(&turned).unwrap()).unwrap();
        // The three-input form, which every turn after the first uses: the
        // absent case above cannot pin where the peer secret sits in the IKM or
        // how it is length-prefixed.
        let peer_ss = TurnSecret([0x5au8; ml_kem::SHARED_SECRET_LEN]);
        let mixed = advance_root(&root, Some(&peer_ss), &own_ss).unwrap();

        assert_eq!(
            hex(root.as_bytes()),
            "736b7e9144e5c294933889168c63ebce6825eb8d9480453e2314bfe3d5b06b3c",
            "the seed root"
        );
        assert_eq!(
            hex(chain.as_bytes()),
            "17791fdcb0198db3632f95a2dd9d4a3004b13c8c6c791167638ad493a3c7bdb0",
            "the seed root's chain key"
        );
        assert_eq!(
            hex(turned.as_bytes()),
            "0fff1d85fb2fffca250d05f24a1641c5a165e48bfbc0c9b32a22a3fca5bbc218",
            "the root after one turn"
        );
        assert_eq!(
            hex(mk.as_bytes()),
            "6cbf039dfeb87a0eecb3b0e83a943394bf3d7a504617b333dc3be76944ad3919",
            "the turn's first message key"
        );
        assert_eq!(
            hex(next.as_bytes()),
            "e1f816b60805be274d7e494f840597dbf150c02a8e38ca3d8e8df42963b626d1",
            "the successor chain key"
        );
        assert_eq!(
            hex(mixed.as_bytes()),
            "bd3f79449e984e8e7692fa4da28e235165f722c7179f51e7714c4ce49ace9fc2",
            "the root with a peer secret present"
        );
    }

    /// A peer secret mixed into a root changes it, so the three-input step is
    /// the one running rather than a two-input one that ignores an argument.
    #[test]
    fn the_peer_secret_is_an_input_to_the_root() {
        let secret = ss0(0x21);
        let root = seed_root(secret.as_bytes()).unwrap();
        let mut entropy = Seeded::at(7);
        let keypair = mint(|b| entropy.fill(b)).unwrap();
        let (own_ss, _) = encapsulate(&keypair.pk, |b| entropy.fill(b)).unwrap();
        let (peer_ss, _) = encapsulate(&keypair.pk, |b| entropy.fill(b)).unwrap();

        let without = advance_root(&root, None, &own_ss).unwrap();
        let with = advance_root(&root, Some(&peer_ss), &own_ss).unwrap();
        assert_ne!(without.as_bytes(), with.as_bytes());
        // Control: the same inputs twice give the same root, so the inequality
        // above is the peer secret and not nondeterminism.
        assert_eq!(
            advance_root(&root, Some(&peer_ss), &own_ss)
                .unwrap()
                .as_bytes(),
            with.as_bytes()
        );
    }

    /// Secrets render as redacted rather than as key material.
    #[test]
    fn secrets_are_redacted_in_debug() {
        let (a, _, _, _) = pair();
        assert_eq!(format!("{:?}", Root([1u8; ROOT_LEN])), "Root(<redacted>)");
        let rendered = format!("{a:?}");
        assert!(rendered.contains("Conversation"), "got: {rendered}");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
