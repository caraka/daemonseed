//! The conversation state a direct-messaging client keeps on disk: the advert
//! KEM secrets, one record per correspondence, and the ciphertext of every
//! message a correspondent has not yet collected.
//!
//! Serves FC2.
//!
//! `docs/design/direct-messaging.md` § On-disk records gives the three records
//! and § Flows gives the order they are written in. Everything here is under
//! [`crate::storage::dm_store`]'s at-rest seal, so this module decides record
//! *shape* and write *order* and nothing about keys or files.
//!
//! ## The ordering contract
//!
//! Every DHT write is preceded by the persist of the state that write depends
//! on, and the store never advances key-schedule state on a caller's behalf:
//! the caller takes a snapshot, persists it, and only then writes. A send is
//! three acts in this order, and the order is the whole of the restart
//! argument:
//!
//! 1. [`Store::persist_outbox`] — the exact bytes the slot will hold.
//! 2. [`Store::update_conv`] — the advanced key schedule and `send_seq`. This
//!    is the commit: until it lands, the message has not been sent.
//! 3. the DHT write of the slot.
//!
//! A crash between 1 and 2 leaves an outbox entry at a sequence the
//! conversation record has not reached. [`Store::load`] treats such an entry as
//! an uncommitted seal and does not report it: nothing was written to the
//! network, the key schedule is where it was, and the caller re-seals the same
//! message at the same sequence. A crash between 2 and 3 leaves a committed
//! entry whose slot is empty; [`Store::load`] reports it as outstanding and the
//! caller rewrites the slot from the stored bytes, byte for byte, because the
//! bytes cannot be reproduced — the seal that made them is randomized.
//!
//! A collection is the mirror: persist the advanced read cursor, then publish
//! it. Publishing first would let a correspondent stop offering messages this
//! side has not recorded as read, and those messages are then unreachable.
//!
//! ## What is not here
//!
//! No message store. A received body is returned to the caller and never
//! written; a sent body exists on disk only as the ciphertext in the outbox,
//! which is deleted once the correspondent's cursor passes it.
//!
//! No home for a channel opening either: an evicted `CHAN.0` is re-signed from
//! the identity key and the conversation generation, so it needs no stored
//! bytes, unlike the hello, whose randomized encapsulation cannot be repeated.
//!
//! ## Record shapes
//!
//! Each record is one fixed width, whatever it holds: a magic naming the record
//! and its version, then fixed-width fields, absent values written as a zero
//! flag byte followed by their own width in zeros. A record's size therefore
//! reports nothing about its contents — no conversation's turn depth, no
//! correspondence's queue depth — which is the property
//! [`crate::storage::dm_store`]'s fixed buckets exist to give and which a
//! variable-length encoding inside a fixed bucket would keep but a
//! record-per-sequence outbox would lose.

use std::path::PathBuf;

use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroizing;

use crate::dm::advert::{
    AdvertDecapKey, AdvertKeys, AdvertSharedSecret, AdvertSnapshot, RetiredSnapshot,
};
use crate::dm::chain::{
    CHAIN_KEY_LEN, ChainKey, ConversationSnapshot, DirectionState, OWN_TURNS_RETAINED, OwnTurn,
    PeerTurn, ROOT_LEN, RatchetDecapKey, RatchetKeypair, ReceivingState, Root, TurnSecret,
};
use crate::dm::channel::{CHANNEL_SUBKEY_LEN, OPENING_LEN, RING_SLOTS};
use crate::dm::drop::{DROP_SUBKEYS, HELLO_LEN, HELLO_LOOKUP_KEY_LEN, HELLO_R_LEN};
use crate::storage::dm_store::{
    CorrespondenceLabel, DmStore, DmStoreError, Locked, LockedProfile, RecordKind,
};
use crate::storage::seeds::AEAD_KEY_LEN;

/// The magic heading the advert-keys record.
const ADVERT_KEYS_MAGIC: &[u8] = b"daemonseed/dm/store/self/v1\0";

/// The magic heading a conversation record.
const CONV_MAGIC: &[u8] = b"daemonseed/dm/store/conv/v1\0";

/// The magic heading a conversation's outbox record.
const CONV_OUTBOX_MAGIC: &[u8] = b"daemonseed/dm/store/obox/v1\0";

/// The version byte every record carries after its magic.
///
/// The magic already names a version and the two move together; the byte is
/// what a format change that keeps the same record identity turns over, so a
/// reader's refusal names a version rather than failing to recognise the record
/// at all.
const RECORD_VERSION: u8 = 1;

/// A flag byte's two accepted values. Any other byte is a corrupt record rather
/// than a truthy value, because nothing this module writes produces one.
const ABSENT: u8 = 0;
/// See [`ABSENT`].
const PRESENT: u8 = 1;

/// Bytes one retained turn takes: its number, both halves of its ratchet
/// keypair, and its shared secret as an optional field.
const OWN_TURN_LEN: usize = 8 + ml_kem::EK_LEN + ml_kem::DK_LEN + 1 + ml_kem::SHARED_SECRET_LEN;

/// Bytes one read peer turn takes: its number, the peer's ratchet public key,
/// and the secret decapsulated from it as an optional field.
const PEER_TURN_LEN: usize = 8 + ml_kem::EK_LEN + 1 + ml_kem::SHARED_SECRET_LEN;

/// Bytes a [`DirectionState`] takes.
const SENDING_LEN: usize = ROOT_LEN
    + (1 + CHAIN_KEY_LEN)
    + 8
    + (1 + 8)
    + 8
    + 8
    + (1 + ml_kem::EK_LEN)
    + (1 + ml_kem::SHARED_SECRET_LEN)
    + (1 + OWN_TURN_LEN)
    + 1;

/// Bytes a [`ReceivingState`] takes.
const RECEIVING_LEN: usize = ROOT_LEN
    + (1 + CHAIN_KEY_LEN)
    + 8
    + 8
    + OWN_TURNS_RETAINED * (1 + OWN_TURN_LEN)
    + (1 + PEER_TURN_LEN);

/// Bytes a [`ConversationSnapshot`] takes.
const SNAPSHOT_LEN: usize = SENDING_LEN + RECEIVING_LEN;

/// Bytes an outstanding hello takes in the conversation record: the presence
/// flag, the slot, `r`, the encapsulation, the sealed hello as written, and the
/// advert serial it was encapsulated to.
const HELLO_FIELD_LEN: usize = 1 + 2 + HELLO_R_LEN + ml_kem::CT_LEN + HELLO_LEN + 8;

/// Bytes the advert-keys record occupies, and so
/// [`RecordKind::AdvertKeys`]'s bucket.
pub const ADVERT_KEYS_RECORD_LEN: usize =
    ADVERT_KEYS_MAGIC.len() + 1 + 8 + 8 + ml_kem::DK_LEN + (1 + 8 + 8 + ml_kem::DK_LEN);

/// Bytes a conversation record occupies, and so
/// [`RecordKind::Conversation`]'s bucket.
pub const CONV_RECORD_LEN: usize = CONV_MAGIC.len()
    + 1
    + ml_dsa::PK_LEN
    + HELLO_LOOKUP_KEY_LEN
    + HELLO_LOOKUP_KEY_LEN
    + 8
    + 8
    + 8
    + 8
    + 8
    + 1
    + HELLO_FIELD_LEN
    + (1 + ml_kem::SHARED_SECRET_LEN)
    + (1 + ml_kem::CT_LEN)
    + (1 + ml_kem::SHARED_SECRET_LEN)
    + (1 + 8)
    + (1 + OPENING_LEN)
    + SNAPSHOT_LEN;

/// Bytes one outbox entry takes: an occupancy flag, the sequence it holds, the
/// ciphertext length, and a whole subkey of space for the ciphertext.
const CONV_OUTBOX_ENTRY_LEN: usize = 1 + 8 + 4 + CHANNEL_SUBKEY_LEN;

/// Bytes the outbox record occupies, and so
/// [`RecordKind::ConversationOutbox`]'s bucket: one entry per ring slot,
/// allocated whether the correspondence owes anything or not.
pub const CONV_OUTBOX_RECORD_LEN: usize =
    CONV_OUTBOX_MAGIC.len() + 1 + (RING_SLOTS as usize) * CONV_OUTBOX_ENTRY_LEN;

/// Why a store operation failed.
#[derive(Debug)]
pub enum StoreError {
    /// The record store refused, or could not read or write.
    Store(DmStoreError),
    /// A record opened under the right key and did not decode.
    Corrupt {
        /// Which record.
        kind: RecordKind,
        /// What about it did not decode.
        reason: &'static str,
    },
    /// [`Store::persist_outbox`] was handed a sequence whose ring slot already
    /// holds a different one. The correspondent's cursor has not reached that
    /// sequence, so overwriting it would drop a message that is still owed.
    OutboxSlotOccupied {
        /// The sequence offered.
        offered: u64,
        /// The sequence the slot holds.
        holding: u64,
    },
    /// A ciphertext longer than the subkey it is destined for.
    CiphertextTooLong {
        /// The length offered.
        len: usize,
    },
    /// [`Store::update_conv`] was asked to change a correspondence that holds
    /// no conversation record.
    MissingConversation,
    /// The crate-private door that establishes a correspondence was asked for
    /// one that already holds a record. Changing it is
    /// [`Store::update_conv`]'s job.
    ConversationExists,
    /// [`Store::update_advert_keys`] was asked to change advert state the
    /// profile has never written.
    MissingAdvertKeys,
}

impl From<DmStoreError> for StoreError {
    fn from(e: DmStoreError) -> Self {
        Self::Store(e)
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Corrupt { kind, reason } => {
                write!(
                    f,
                    "the {} record did not decode: {reason}",
                    kind.stable_str()
                )
            }
            Self::OutboxSlotOccupied { offered, holding } => write!(
                f,
                "sequence {offered} maps onto the ring slot holding {holding}, \
                 which the correspondent has not collected"
            ),
            Self::CiphertextTooLong { len } => write!(
                f,
                "a {len}-byte ciphertext does not fit a {CHANNEL_SUBKEY_LEN}-byte subkey"
            ),
            Self::MissingConversation => {
                write!(f, "the correspondence holds no conversation record")
            }
            Self::ConversationExists => {
                write!(f, "the correspondence already holds a conversation record")
            }
            Self::MissingAdvertKeys => write!(f, "the profile holds no advert key state"),
        }
    }
}

impl core::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

/// An unanswered first-contact hello, held as the bytes that were written
/// rather than as the inputs that made them.
///
/// **The sealed hello is stored, not reproduced.** Re-encapsulating to the
/// correspondent's advert key would yield a different `ss0`, and `ss0` is what
/// seeds the conversation root that every ciphertext already in the outbox was
/// sealed under — so a rewrite from fresh inputs would publish a hello opening
/// a conversation the sender can no longer speak. A crash between the seal and
/// the drop write, and an eviction of the slot afterwards, are therefore both
/// answered by writing these bytes again unchanged.
#[derive(Clone, PartialEq, Eq)]
pub struct OutstandingHello {
    /// The drop subkey the hello was written to, below [`DROP_SUBKEYS`].
    pub slot: u16,
    /// The value the slot was derived from, and which the correspondent needs
    /// to erase the slot the hello occupies.
    pub r: [u8; HELLO_R_LEN],
    /// The ML-KEM ciphertext the hello publishes — the first
    /// [`ml_kem::CT_LEN`] bytes of [`Self::sealed`], held alongside it because
    /// the sender compares it against nothing else when an advert rotates.
    pub kem_ct: Box<[u8; ml_kem::CT_LEN]>,
    /// The hello exactly as written to the slot.
    pub sealed: Box<[u8; HELLO_LEN]>,
    /// The advert serial this hello encapsulated to. A correspondent that has
    /// rotated past it is what obliges a re-encapsulation, and that is a new
    /// hello rather than a rewrite of this one.
    pub advert_serial: u64,
}

impl core::fmt::Debug for OutstandingHello {
    /// Renders the slot and the serial; the rest is key material and a seal.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutstandingHello")
            .field("slot", &self.slot)
            .field("advert_serial", &self.advert_serial)
            .finish_non_exhaustive()
    }
}

/// One correspondence's durable state, as the design's CONV record.
pub struct ConvState {
    /// The correspondent's identity public key.
    pub peer_identity_pk: Box<[u8; ml_dsa::PK_LEN]>,
    /// The lookup key of the channel this side writes.
    pub outgoing_lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The lookup key of the channel this side reads.
    pub incoming_lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The conversation generation both channels were derived under.
    pub generation: u64,
    /// The key schedule, both halves.
    pub conversation: ConversationSnapshot,
    /// The sequence the next message this side sends will carry.
    pub send_seq: u64,
    /// The correspondent's cursor over this side's messages.
    pub peer_collected: u64,
    /// This side's cursor over the correspondent's messages.
    pub my_collected: u64,
    /// The cursor this side has published into its own control subkey.
    ///
    /// Below [`Self::my_collected`] while a collection has been recorded and
    /// not yet published, which is the state a stop between the two leaves.
    pub cursor_published: u64,
    /// Whether this side's own first contact is still awaiting an acceptance.
    ///
    /// Distinct from [`Self::outstanding_hello`], which is set on both sides
    /// of a first contact: a hello of this side's own is outstanding whether
    /// it opened the conversation or accepted one.
    pub awaiting_acceptance: bool,
    /// The hello awaiting collection, while there is one.
    pub outstanding_hello: Option<OutstandingHello>,
    /// The secret this side's own hello established.
    ///
    /// Seals this side's control subkey and nothing else. Absent until this
    /// side has encapsulated a hello of its own.
    pub own_hello_secret: Option<AdvertSharedSecret>,
    /// The encapsulation this side's own hello carries.
    ///
    /// Persisted beside the secret because it is what the correspondent
    /// decapsulates to reach it: a rewritten hello that carried a fresh
    /// ciphertext would establish a secret this record does not hold.
    pub own_hello_kem_ct: Option<Box<[u8; ml_kem::CT_LEN]>>,
    /// The secret the correspondent's hello established.
    ///
    /// Opens the correspondent's control subkey and nothing else. Absent until
    /// the correspondent's hello has been opened.
    pub peer_hello_secret: Option<AdvertSharedSecret>,
    /// The advert serial the correspondent's channel opening binds.
    ///
    /// The serial of this side's own advert that the correspondent
    /// encapsulated to, which is what refuses a hello relayed into a channel
    /// addressed to somebody else. Persisted so an acceptance completed by a
    /// later run re-verifies that opening rather than trusting this record.
    pub peer_advert_serial: Option<u64>,
    /// This side's signed channel opening, as the bytes its control subkey
    /// carries.
    ///
    /// Persisted rather than rebuilt: the ML-DSA signature is randomized, so a
    /// rewritten control record would otherwise carry an opening whose bytes
    /// differ from the one already published.
    pub own_opening: Option<Box<[u8; OPENING_LEN]>>,
}

impl core::fmt::Debug for ConvState {
    /// Renders the numbers and nothing else: every other field is a key or a
    /// key schedule.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConvState")
            .field("generation", &self.generation)
            .field("send_seq", &self.send_seq)
            .field("peer_collected", &self.peer_collected)
            .field("my_collected", &self.my_collected)
            .field("cursor_published", &self.cursor_published)
            .field("awaiting_acceptance", &self.awaiting_acceptance)
            .field("outstanding_hello", &self.outstanding_hello.is_some())
            .finish_non_exhaustive()
    }
}

/// One message still owed to a correspondent: its sequence and the exact bytes
/// its slot must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// The message's sequence within this side's direction.
    pub seq: u64,
    /// The bytes the slot holds, as written.
    pub ciphertext: Vec<u8>,
}

/// One correspondence as a launch reads it.
#[derive(Debug)]
pub struct LoadedConv {
    /// Which correspondence.
    pub peer: CorrespondenceLabel,
    /// Its durable state.
    pub state: ConvState,
    /// The messages committed but not yet collected, ascending by sequence.
    /// Every one of them has a slot to be rewritten if the network no longer
    /// holds it.
    pub outstanding_outbox: Vec<OutboxEntry>,
}

/// Everything a launch reads back.
#[derive(Debug)]
pub struct Loaded {
    /// The advert KEM state, absent on a profile that has never published one.
    pub advert_keys: Option<AdvertSnapshot>,
    /// Every correspondence holding a conversation record, in the order
    /// [`DmStore::correspondences`] gives.
    pub convs: Vec<LoadedConv>,
}

/// The direct-messaging layer's disk.
pub struct Store {
    inner: DmStore,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store").field("inner", &self.inner).finish()
    }
}

impl Store {
    /// Open the store under `root`, sealed under the profile's at-rest key.
    pub fn open(
        root: impl Into<PathBuf>,
        at_rest_key: &[u8; AEAD_KEY_LEN],
    ) -> Result<Self, StoreError> {
        Ok(Self {
            inner: DmStore::open(root, at_rest_key)?,
        })
    }

    /// The record store beneath, for a caller that needs to name a
    /// correspondence or enumerate what a profile holds.
    pub fn records(&self) -> &DmStore {
        &self.inner
    }

    /// Write the advert KEM state.
    ///
    /// Ordered before the advert record's own DHT write: an advert published
    /// under a key whose secret did not reach disk is one nobody can open a
    /// hello to, including its owner.
    pub fn persist_advert_keys(&self, snapshot: &AdvertSnapshot) -> Result<(), StoreError> {
        let bytes = encode_advert_keys(snapshot);
        self.inner.profile_critical_section::<_, StoreError>(|g| {
            g.replace(RecordKind::AdvertKeys, &bytes)?;
            Ok(())
        })
    }

    /// Read the advert KEM state back, or `None` where none has been written.
    pub fn load_advert_keys(&self) -> Result<Option<AdvertSnapshot>, StoreError> {
        self.inner
            .profile_critical_section::<_, StoreError>(|g| read_advert_keys(g))
    }

    /// Rotate, prune or otherwise change the advert state inside a single
    /// profile critical section.
    ///
    /// **Rotation is read-decide-write**, and the decision is destructive: a
    /// rotation drops the key that was retained, and a hello encapsulated to a
    /// dropped key opens for nobody. Two of them straddling each other retire
    /// two generations where one was due, so the door that reads and the door
    /// that writes have to be the same one.
    ///
    /// Refuses [`StoreError::MissingAdvertKeys`] where no state has been
    /// written: there is nothing here to rotate, and minting a first keypair is
    /// [`Store::persist_advert_keys`]'s job.
    pub fn update_advert_keys<R>(
        &self,
        f: impl FnOnce(&mut AdvertKeys) -> R,
    ) -> Result<R, StoreError> {
        self.inner.profile_critical_section::<_, StoreError>(|g| {
            let snapshot = read_advert_keys(g)?.ok_or(StoreError::MissingAdvertKeys)?;
            let mut keys = AdvertKeys::restore(snapshot);
            let out = f(&mut keys);
            g.replace(
                RecordKind::AdvertKeys,
                &encode_advert_keys(&keys.snapshot()),
            )?;
            Ok(out)
        })
    }

    /// Write a correspondence's first conversation record.
    ///
    /// **Creates, never replaces**, and refuses
    /// [`StoreError::ConversationExists`] where a record is already there.
    /// A whole-record write built from a caller's own memory is the lost update
    /// wearing a legitimate name: the caller reconstructs every field, including
    /// the ones it does not track — an outstanding hello above all — and writes
    /// its blanks over whatever another path persisted. Every later change goes
    /// through [`Store::update_conv`], which reads under the same lock it writes
    /// under and so cannot spell that.
    ///
    /// `pub(crate)`: the correspondence is established by
    /// [`crate::dm::flows::first_contact`] and [`crate::dm::flows::accept`],
    /// and crate visibility is what keeps a whole-record write unspellable
    /// from outside.
    pub(crate) fn create_conv(
        &self,
        peer: &CorrespondenceLabel,
        state: &ConvState,
    ) -> Result<(), StoreError> {
        self.inner.critical_section::<_, StoreError>(peer, |g| {
            if g.read(RecordKind::Conversation)?.is_some() {
                return Err(StoreError::ConversationExists);
            }
            g.replace(RecordKind::Conversation, &encode_conv(state))?;
            Ok(())
        })
    }

    /// Read one correspondence's state, or `None` where it holds no record.
    ///
    /// Under the lock, like every other read here. The unlocked door exists and
    /// is correct for a question with no write behind it, but there is no such
    /// caller on this path: a launch reads in order to write, and a read that
    /// decides something and writes it back in a second section is exactly the
    /// lost update [`DmStore::critical_section`] exists to make unspellable.
    /// [`Store::update_conv`] is the door that changes what this returns.
    pub fn load_conv(&self, peer: &CorrespondenceLabel) -> Result<Option<ConvState>, StoreError> {
        self.inner
            .critical_section::<_, StoreError>(peer, |g| read_conv(g))
    }

    /// Read, change and write back one correspondence's state inside a single
    /// critical section.
    ///
    /// **The door every caller that both reads and writes must use.** A
    /// [`Store::load_conv`] followed by a whole-record write is two
    /// sections with a gap, and a concurrent writer's change lands in that gap
    /// and is silently overwritten — losing a collected cursor, which shows a
    /// correspondent's message as never read, or a `send_seq`, which puts two
    /// messages at one sequence.
    ///
    /// Refuses [`StoreError::MissingConversation`] rather than creating a
    /// record: there is nothing this could invent a conversation from.
    pub fn update_conv<R>(
        &self,
        peer: &CorrespondenceLabel,
        f: impl FnOnce(&mut ConvState) -> R,
    ) -> Result<R, StoreError> {
        self.inner.critical_section::<_, StoreError>(peer, |g| {
            let mut state = read_conv(g)?.ok_or(StoreError::MissingConversation)?;
            let out = f(&mut state);
            g.replace(RecordKind::Conversation, &encode_conv(&state))?;
            Ok(out)
        })
    }

    /// Remove one correspondence's conversation and outbox records.
    ///
    /// Both in one section, so no reader sees a conversation without the
    /// ciphertext it still owes or an outbox with no conversation to place it
    /// in. The correspondence's directory stays: it is what
    /// [`DmStore::critical_section`] establishes by being entered, and removing
    /// it is the record store's business rather than this module's.
    pub fn delete_conv(&self, peer: &CorrespondenceLabel) -> Result<(), StoreError> {
        self.inner.critical_section::<_, StoreError>(peer, |g| {
            g.delete(RecordKind::ConversationOutbox)?;
            g.delete(RecordKind::Conversation)?;
            Ok(())
        })
    }

    /// Record the exact ciphertext written to `seq`'s slot, before it is
    /// written.
    ///
    /// Refuses [`StoreError::OutboxSlotOccupied`] when `seq`'s ring position
    /// already holds a different sequence. That is the ring's own rule — a
    /// sequence maps onto the slot of one 63 messages older — surfacing here
    /// rather than as a silently dropped entry, and a caller reaching it has
    /// skipped [`Store::delete_outbox_through`].
    pub fn persist_outbox(
        &self,
        peer: &CorrespondenceLabel,
        seq: u64,
        ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        if ciphertext.len() > CHANNEL_SUBKEY_LEN {
            return Err(StoreError::CiphertextTooLong {
                len: ciphertext.len(),
            });
        }
        self.inner.critical_section::<_, StoreError>(peer, |g| {
            let mut table = read_outbox(g.read(RecordKind::ConversationOutbox)?.as_deref())?;
            let at = ring_index(seq);
            if let Some(held) = &table[at]
                && held.seq != seq
            {
                return Err(StoreError::OutboxSlotOccupied {
                    offered: seq,
                    holding: held.seq,
                });
            }
            table[at] = Some(OutboxEntry {
                seq,
                ciphertext: ciphertext.to_vec(),
            });
            g.replace(RecordKind::ConversationOutbox, &encode_conv_outbox(&table))?;
            Ok(())
        })
    }

    /// Drop every outbox entry below `cursor` — the correspondent has collected
    /// them, so their slots are free and their ciphertext is no longer owed.
    pub fn delete_outbox_through(
        &self,
        peer: &CorrespondenceLabel,
        cursor: u64,
    ) -> Result<(), StoreError> {
        self.inner.critical_section::<_, StoreError>(peer, |g| {
            let Some(raw) = g.read(RecordKind::ConversationOutbox)? else {
                return Ok(());
            };
            let mut table = read_outbox(Some(&raw))?;
            let mut changed = false;
            for slot in table.iter_mut() {
                if slot
                    .as_ref()
                    .is_some_and(|e| crate::dm::channel::collected(e.seq, cursor))
                {
                    *slot = None;
                    changed = true;
                }
            }
            if changed {
                g.replace(RecordKind::ConversationOutbox, &encode_conv_outbox(&table))?;
            }
            Ok(())
        })
    }

    /// Everything a launch needs: the advert state and every correspondence,
    /// each with the messages whose slots may need rewriting.
    ///
    /// **An outbox entry is outstanding only while
    /// `peer_collected <= seq < send_seq`.** An entry at or above `send_seq`
    /// was sealed by a run that died before its conversation record committed:
    /// no slot was written, the key schedule never advanced past it, and
    /// reporting it would rewrite a slot for a message the correspondent is not
    /// expecting. An entry below `peer_collected` has been collected and is
    /// waiting for the next [`Store::delete_outbox_through`].
    pub fn load(&self) -> Result<Loaded, StoreError> {
        let advert_keys = self.load_advert_keys()?;
        let mut convs = Vec::new();
        for peer in self.inner.correspondences()? {
            // One section per correspondence, holding the conversation record
            // and its outbox together: read apart, the two can straddle a
            // writer and disagree about which sequences are still owed, and the
            // launch would then rewrite a slot the correspondent has collected
            // or leave one it has not.
            let read = self.inner.critical_section::<_, StoreError>(&peer, |g| {
                let Some(state) = read_conv(g)? else {
                    return Ok(None);
                };
                let table = read_outbox(g.read(RecordKind::ConversationOutbox)?.as_deref())?;
                Ok(Some((state, table)))
            })?;
            let Some((state, table)) = read else {
                continue;
            };
            let mut outstanding: Vec<OutboxEntry> = table
                .into_iter()
                .flatten()
                .filter(|e| e.seq >= state.peer_collected && e.seq < state.send_seq)
                .collect();
            outstanding.sort_unstable_by_key(|e| e.seq);
            convs.push(LoadedConv {
                peer,
                state,
                outstanding_outbox: outstanding,
            });
        }
        Ok(Loaded { advert_keys, convs })
    }
}

/// The advert-keys record under an open profile guard, or `None` where the
/// profile has none. An empty payload is the record every [`DmStore::open`]
/// creates and nothing has written to yet.
fn read_advert_keys(g: &LockedProfile<'_>) -> Result<Option<AdvertSnapshot>, StoreError> {
    let Some(bytes) = g.read(RecordKind::AdvertKeys)? else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    // Wrapped on receipt, for `read_conv`'s reason: the payload is two
    // decapsulation keys.
    let bytes = Zeroizing::new(bytes);
    Ok(Some(decode_advert_keys(&bytes)?))
}

/// The conversation record under an open guard, or `None` where there is none.
fn read_conv(g: &Locked<'_>) -> Result<Option<ConvState>, StoreError> {
    let Some(bytes) = g.read(RecordKind::Conversation)? else {
        return Ok(None);
    };
    // Wrapped on receipt: the record is a whole key schedule, and the plain
    // `Vec` the store hands back would otherwise outlive the decode.
    let bytes = Zeroizing::new(bytes);
    Ok(Some(decode_conv(&bytes)?))
}

/// Which entry of the outbox table a sequence occupies.
///
/// The ring's own mapping, not the channel's subkey number: the table has one
/// entry per ring slot, and the ring guarantees that two sequences sharing an
/// entry are never outstanding together.
fn ring_index(seq: u64) -> usize {
    (seq % RING_SLOTS) as usize
}

// ── encoding ────────────────────────────────────────────────────────────────

/// A fixed-width writer. Every field lands at a constant offset, so a record's
/// length reports nothing about what it holds.
struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    fn with_capacity(n: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(n)))
    }

    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    /// `v`, then `width - v.len()` zeros.
    fn padded(&mut self, v: &[u8], width: usize) {
        self.0.extend_from_slice(v);
        self.0
            .extend_from_slice(&vec![0u8; width.saturating_sub(v.len())]);
    }

    /// A present-or-absent field: a flag byte, then `width` bytes that are the
    /// value or zeros.
    fn opt(&mut self, v: Option<&[u8]>, width: usize) {
        match v {
            Some(b) => {
                self.u8(PRESENT);
                self.padded(b, width);
            }
            None => {
                self.u8(ABSENT);
                self.padded(&[], width);
            }
        }
    }

    fn opt_u64(&mut self, v: Option<u64>) {
        self.opt(v.map(u64::to_be_bytes).as_ref().map(|b| &b[..]), 8);
    }

    fn own_turn(&mut self, turn: Option<&OwnTurn>) {
        match turn {
            Some(t) => {
                self.u8(PRESENT);
                self.u64(t.m);
                self.bytes(t.keypair.pk.as_slice());
                self.bytes(t.keypair.dk.as_bytes());
                self.opt(
                    t.ss.as_ref().map(|s| &s.as_bytes()[..]),
                    ml_kem::SHARED_SECRET_LEN,
                );
            }
            None => {
                self.u8(ABSENT);
                self.padded(&[], OWN_TURN_LEN);
            }
        }
    }

    fn peer_turn(&mut self, turn: Option<&PeerTurn>) {
        match turn {
            Some(t) => {
                self.u8(PRESENT);
                self.u64(t.m);
                self.bytes(t.pk.as_slice());
                self.opt(
                    t.ss.as_ref().map(|s| &s.as_bytes()[..]),
                    ml_kem::SHARED_SECRET_LEN,
                );
            }
            None => {
                self.u8(ABSENT);
                self.padded(&[], PEER_TURN_LEN);
            }
        }
    }
}

/// A fixed-width reader whose every refusal names the record it was reading.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    kind: RecordKind,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], kind: RecordKind) -> Self {
        Self { bytes, at: 0, kind }
    }

    fn corrupt(&self, reason: &'static str) -> StoreError {
        StoreError::Corrupt {
            kind: self.kind,
            reason,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| self.corrupt("a field length overflowed"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| self.corrupt("the record ended inside a field"))?;
        self.at = end;
        Ok(slice)
    }

    /// One fixed-width field, in a buffer that zeroizes when it is dropped.
    ///
    /// Most fields this reads are key material, and the plain array a decoder
    /// would otherwise build is a copy of it on the stack that outlives the
    /// newtype taking ownership of the bytes. The wrapper costs nothing and
    /// removes the whole class, so it is not per-field judgement about which
    /// arrays are secret.
    fn array<const N: usize>(&mut self) -> Result<Zeroizing<[u8; N]>, StoreError> {
        let slice = self.take(N)?;
        let mut out = Zeroizing::new([0u8; N]);
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn boxed<const N: usize>(&mut self) -> Result<Box<[u8; N]>, StoreError> {
        Ok(Box::new(*self.array::<N>()?))
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(*self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(*self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(*self.array::<8>()?))
    }

    /// A flag byte, refusing anything this module's writer cannot produce.
    fn flag(&mut self) -> Result<bool, StoreError> {
        match self.u8()? {
            ABSENT => Ok(false),
            PRESENT => Ok(true),
            _ => Err(self.corrupt("a presence flag held neither 0 nor 1")),
        }
    }

    fn opt_array<const N: usize>(&mut self) -> Result<Option<Zeroizing<[u8; N]>>, StoreError> {
        let present = self.flag()?;
        let value = self.array::<N>()?;
        Ok(present.then_some(value))
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, StoreError> {
        Ok(self.opt_array::<8>()?.map(|b| u64::from_be_bytes(*b)))
    }

    fn own_turn(&mut self) -> Result<Option<OwnTurn>, StoreError> {
        let present = self.flag()?;
        let m = self.u64()?;
        let pk = self.boxed::<{ ml_kem::EK_LEN }>()?;
        let dk = self.array::<{ ml_kem::DK_LEN }>()?;
        let ss = self.opt_array::<{ ml_kem::SHARED_SECRET_LEN }>()?;
        let ss = ss.as_deref();
        Ok(present.then(|| OwnTurn {
            m,
            keypair: RatchetKeypair {
                pk,
                dk: RatchetDecapKey::from_bytes(&dk),
            },
            ss: ss.map(TurnSecret::from_bytes),
        }))
    }

    fn peer_turn(&mut self) -> Result<Option<PeerTurn>, StoreError> {
        let present = self.flag()?;
        let m = self.u64()?;
        let pk = self.boxed::<{ ml_kem::EK_LEN }>()?;
        let ss = self.opt_array::<{ ml_kem::SHARED_SECRET_LEN }>()?;
        let ss = ss.as_deref();
        Ok(present.then(|| PeerTurn {
            m,
            pk,
            ss: ss.map(TurnSecret::from_bytes),
        }))
    }

    /// The magic and version at the head of a record.
    fn header(&mut self, magic: &[u8]) -> Result<(), StoreError> {
        if self.take(magic.len())? != magic {
            return Err(self.corrupt("the record does not begin with its magic"));
        }
        if self.u8()? != RECORD_VERSION {
            return Err(self.corrupt("the record carries an unknown version"));
        }
        Ok(())
    }

    /// Every byte of the record was accounted for.
    fn finish(self) -> Result<(), StoreError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(self.corrupt("the record is not its kind's fixed width"))
        }
    }
}

/// Encode the advert KEM state.
pub(crate) fn encode_advert_keys(snapshot: &AdvertSnapshot) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::with_capacity(ADVERT_KEYS_RECORD_LEN);
    w.bytes(ADVERT_KEYS_MAGIC);
    w.u8(RECORD_VERSION);
    w.u64(snapshot.serial);
    w.u64(snapshot.not_before);
    w.bytes(snapshot.decapsulation_key.as_bytes());
    match &snapshot.previous {
        Some(p) => {
            w.u8(PRESENT);
            w.u64(p.serial);
            w.u64(p.retired_at);
            w.bytes(p.decapsulation_key.as_bytes());
        }
        None => {
            w.u8(ABSENT);
            w.padded(&[], 8 + 8 + ml_kem::DK_LEN);
        }
    }
    w.0
}

/// Decode the advert KEM state.
pub(crate) fn decode_advert_keys(bytes: &[u8]) -> Result<AdvertSnapshot, StoreError> {
    let mut r = Reader::new(bytes, RecordKind::AdvertKeys);
    r.header(ADVERT_KEYS_MAGIC)?;
    let serial = r.u64()?;
    let not_before = r.u64()?;
    let dk = r.array::<{ ml_kem::DK_LEN }>()?;
    let has_previous = r.flag()?;
    let prev_serial = r.u64()?;
    let retired_at = r.u64()?;
    let prev_dk = r.array::<{ ml_kem::DK_LEN }>()?;
    r.finish()?;
    Ok(AdvertSnapshot {
        serial,
        not_before,
        decapsulation_key: AdvertDecapKey::from_bytes(&dk),
        previous: has_previous.then(|| RetiredSnapshot {
            serial: prev_serial,
            retired_at,
            decapsulation_key: AdvertDecapKey::from_bytes(&prev_dk),
        }),
    })
}

/// Encode one correspondence's state.
pub(crate) fn encode_conv(state: &ConvState) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::with_capacity(CONV_RECORD_LEN);
    w.bytes(CONV_MAGIC);
    w.u8(RECORD_VERSION);
    w.bytes(state.peer_identity_pk.as_slice());
    w.bytes(&state.outgoing_lookup_key);
    w.bytes(&state.incoming_lookup_key);
    w.u64(state.generation);
    w.u64(state.send_seq);
    w.u64(state.peer_collected);
    w.u64(state.my_collected);
    w.u64(state.cursor_published);
    w.u8(u8::from(state.awaiting_acceptance));
    match &state.outstanding_hello {
        Some(h) => {
            w.u8(PRESENT);
            w.u16(h.slot);
            w.bytes(&h.r);
            w.bytes(h.kem_ct.as_slice());
            w.bytes(h.sealed.as_slice());
            w.u64(h.advert_serial);
        }
        None => {
            w.u8(ABSENT);
            w.padded(&[], HELLO_FIELD_LEN - 1);
        }
    }
    w.opt(
        state.own_hello_secret.as_ref().map(|s| &s.as_bytes()[..]),
        ml_kem::SHARED_SECRET_LEN,
    );
    w.opt(
        state.own_hello_kem_ct.as_ref().map(|c| c.as_slice()),
        ml_kem::CT_LEN,
    );
    w.opt(
        state.peer_hello_secret.as_ref().map(|s| &s.as_bytes()[..]),
        ml_kem::SHARED_SECRET_LEN,
    );
    w.opt_u64(state.peer_advert_serial);
    w.opt(
        state.own_opening.as_ref().map(|o| o.as_slice()),
        OPENING_LEN,
    );

    let sending = &state.conversation.sending;
    w.bytes(sending.root.as_bytes());
    w.opt(
        sending.chain.as_ref().map(|c| &c.as_bytes()[..]),
        CHAIN_KEY_LEN,
    );
    w.u64(sending.n);
    w.opt_u64(sending.m_seen);
    w.u64(sending.seq);
    w.u64(sending.cursor);
    w.opt(
        sending.peer_pk.as_ref().map(|p| p.as_slice()),
        ml_kem::EK_LEN,
    );
    w.opt(
        sending.peer_ss.as_ref().map(|s| &s.as_bytes()[..]),
        ml_kem::SHARED_SECRET_LEN,
    );
    w.own_turn(sending.pending_turn.as_ref());
    w.u8(u8::from(sending.force_turn));

    let receiving = &state.conversation.receiving;
    w.bytes(receiving.root.as_bytes());
    w.opt(
        receiving.chain.as_ref().map(|c| &c.as_bytes()[..]),
        CHAIN_KEY_LEN,
    );
    w.u64(receiving.n);
    w.u64(receiving.next_seq);
    for turn in &receiving.own_turns {
        w.own_turn(turn.as_ref());
    }
    w.peer_turn(receiving.peer_latest.as_ref());
    w.0
}

/// Decode one correspondence's state.
pub(crate) fn decode_conv(bytes: &[u8]) -> Result<ConvState, StoreError> {
    let mut r = Reader::new(bytes, RecordKind::Conversation);
    r.header(CONV_MAGIC)?;
    let peer_identity_pk = r.boxed::<{ ml_dsa::PK_LEN }>()?;
    let outgoing_lookup_key = *r.array::<HELLO_LOOKUP_KEY_LEN>()?;
    let incoming_lookup_key = *r.array::<HELLO_LOOKUP_KEY_LEN>()?;
    let generation = r.u64()?;
    let send_seq = r.u64()?;
    let peer_collected = r.u64()?;
    let my_collected = r.u64()?;
    let cursor_published = r.u64()?;
    let awaiting_acceptance = r.flag()?;
    if cursor_published > my_collected {
        return Err(r.corrupt("the published cursor is above this side's collection cursor"));
    }
    if peer_collected > send_seq {
        return Err(r.corrupt("the correspondent's cursor is above this side's send sequence"));
    }
    let has_hello = r.flag()?;
    let hello_slot = r.u16()?;
    let hello_r = r.array::<HELLO_R_LEN>()?;
    let hello_kem_ct = r.boxed::<{ ml_kem::CT_LEN }>()?;
    let hello_sealed = r.boxed::<HELLO_LEN>()?;
    let hello_serial = r.u64()?;
    if has_hello {
        if hello_slot >= DROP_SUBKEYS {
            return Err(r.corrupt("the outstanding hello names a slot the drop does not have"));
        }
        if hello_sealed[..ml_kem::CT_LEN] != hello_kem_ct[..] {
            return Err(
                r.corrupt("the outstanding hello's encapsulation is not the one it opens with")
            );
        }
    }

    let own_hello_secret = r
        .opt_array::<{ ml_kem::SHARED_SECRET_LEN }>()?
        .as_deref()
        .map(AdvertSharedSecret::from_bytes);
    let own_hello_kem_ct = r.opt_array::<{ ml_kem::CT_LEN }>()?.map(|b| Box::new(*b));
    let peer_hello_secret = r
        .opt_array::<{ ml_kem::SHARED_SECRET_LEN }>()?
        .as_deref()
        .map(AdvertSharedSecret::from_bytes);
    let peer_advert_serial = r.opt_u64()?;
    let own_opening = r.opt_array::<OPENING_LEN>()?.map(|b| Box::new(*b));

    let sending_root = r.array::<ROOT_LEN>()?;
    let sending = DirectionState {
        root: Root::from_bytes(&sending_root),
        chain: r
            .opt_array::<CHAIN_KEY_LEN>()?
            .map(|b| ChainKey::from_bytes(&b)),
        n: r.u64()?,
        m_seen: r.opt_u64()?,
        seq: r.u64()?,
        cursor: r.u64()?,
        peer_pk: r.opt_array::<{ ml_kem::EK_LEN }>()?.map(|b| Box::new(*b)),
        peer_ss: r
            .opt_array::<{ ml_kem::SHARED_SECRET_LEN }>()?
            .as_deref()
            .map(TurnSecret::from_bytes),
        pending_turn: r.own_turn()?,
        force_turn: r.flag()?,
    };

    let receiving_root = r.array::<ROOT_LEN>()?;
    let receiving = ReceivingState {
        root: Root::from_bytes(&receiving_root),
        chain: r
            .opt_array::<CHAIN_KEY_LEN>()?
            .map(|b| ChainKey::from_bytes(&b)),
        n: r.u64()?,
        next_seq: r.u64()?,
        own_turns: [r.own_turn()?, r.own_turn()?],
        peer_latest: r.peer_turn()?,
    };
    r.finish()?;

    Ok(ConvState {
        peer_identity_pk,
        outgoing_lookup_key,
        incoming_lookup_key,
        generation,
        conversation: ConversationSnapshot { sending, receiving },
        send_seq,
        peer_collected,
        my_collected,
        cursor_published,
        awaiting_acceptance,
        outstanding_hello: has_hello.then_some(OutstandingHello {
            slot: hello_slot,
            r: *hello_r,
            kem_ct: hello_kem_ct,
            sealed: hello_sealed,
            advert_serial: hello_serial,
        }),
        own_hello_secret,
        own_hello_kem_ct,
        peer_hello_secret,
        peer_advert_serial,
        own_opening,
    })
}

/// The outbox as one entry per ring slot.
type OutboxTable = Vec<Option<OutboxEntry>>;

/// Encode the outbox table.
pub(crate) fn encode_conv_outbox(table: &[Option<OutboxEntry>]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::with_capacity(CONV_OUTBOX_RECORD_LEN);
    w.bytes(CONV_OUTBOX_MAGIC);
    w.u8(RECORD_VERSION);
    for slot in table {
        match slot {
            Some(e) => {
                w.u8(PRESENT);
                w.u64(e.seq);
                w.u32(e.ciphertext.len() as u32);
                w.padded(&e.ciphertext, CHANNEL_SUBKEY_LEN);
            }
            None => {
                w.u8(ABSENT);
                w.padded(&[], CONV_OUTBOX_ENTRY_LEN - 1);
            }
        }
    }
    w.0
}

/// Decode the outbox table.
pub(crate) fn decode_conv_outbox(bytes: &[u8]) -> Result<OutboxTable, StoreError> {
    let mut r = Reader::new(bytes, RecordKind::ConversationOutbox);
    r.header(CONV_OUTBOX_MAGIC)?;
    let mut table = Vec::with_capacity(RING_SLOTS as usize);
    for index in 0..RING_SLOTS {
        let present = r.flag()?;
        let seq = r.u64()?;
        let len = r.u32()? as usize;
        let body = r.take(CHANNEL_SUBKEY_LEN)?;
        if !present {
            table.push(None);
            continue;
        }
        // The entry's position *is* its sequence, modulo the ring. A record
        // holding a sequence somewhere other than where `ring_index` puts it
        // would be read back at a position no write would ever overwrite, so
        // the entry would survive every `delete_outbox_through` and be offered
        // for rewrite for ever.
        if seq % RING_SLOTS != index {
            return Err(r.corrupt("an entry holds a sequence that is not its ring position"));
        }
        let ciphertext = body
            .get(..len)
            .ok_or_else(|| r.corrupt("an entry's length runs past its slot"))?
            .to_vec();
        table.push(Some(OutboxEntry { seq, ciphertext }));
    }
    r.finish()?;
    Ok(table)
}

/// The outbox table from a record that may not exist yet.
fn read_outbox(bytes: Option<&[u8]>) -> Result<OutboxTable, StoreError> {
    match bytes {
        Some(raw) if !raw.is_empty() => decode_conv_outbox(raw),
        _ => Ok(vec![None; RING_SLOTS as usize]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    use crate::dm::advert;
    use crate::dm::chain::{Conversation, accept, initiate};
    use crate::dm::channel::{self, MessageHeader, Ring};
    use crate::dm::drop as drop_plane;
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
    fn shared_secret(seed: u8) -> advert::AdvertSharedSecret {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let signer = SignKeypair::from_ml_dsa_seed(&[seed; 32]).expect("derive a signer");
        let keys = advert::AdvertKeys::new(NOW, counting_fill(seed)).expect("advert keys");
        let bytes = keys.advert_bytes(&signer).expect("advert bytes");
        let verified = advert::verify(signer.public_key(), &bytes).expect("verify the advert");
        advert::encapsulate_to(&verified, NOW, counting_fill(seed ^ 0x5a))
            .expect("encapsulate")
            .shared_secret
    }

    /// An advert state that has rotated once, so the record's retained-key
    /// field is exercised rather than written as zeros.
    fn rotated_advert() -> AdvertSnapshot {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut keys = advert::AdvertKeys::new(NOW, counting_fill(0x11)).expect("advert keys");
        let rotation = keys
            .rotate_if_due(NOW + advert::ROTATION_PERIOD_SECS, counting_fill(0x44))
            .expect("rotate");
        assert!(rotation.happened(), "the control: the state did rotate");
        let snapshot = keys.snapshot();
        assert!(
            snapshot.previous.is_some(),
            "the control: a rotated state retains its previous key"
        );
        snapshot
    }

    /// An outstanding hello by the real path: a real encapsulation to a real
    /// advert, sealed by `dm::drop`, so the stored bytes are the bytes a drop
    /// slot would hold.
    fn outstanding_hello() -> OutstandingHello {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let signer = SignKeypair::from_ml_dsa_seed(&[0x31; 32]).expect("derive a signer");
        let keys = advert::AdvertKeys::new(NOW, counting_fill(0x31)).expect("advert keys");
        let bytes = keys.advert_bytes(&signer).expect("advert bytes");
        let verified = advert::verify(signer.public_key(), &bytes).expect("verify the advert");
        let encap =
            advert::encapsulate_to(&verified, NOW, counting_fill(0x77)).expect("encapsulate");
        let r = [0x5c; HELLO_R_LEN];
        let sealed = drop_plane::seal_hello(&encap, &lookup(A_CHANNEL), &r, signer.public_key())
            .expect("seal the hello");
        OutstandingHello {
            slot: drop_plane::slot_for(&r).expect("the slot"),
            r,
            kem_ct: encap.ciphertext.clone(),
            sealed: Box::new(
                <[u8; HELLO_LEN]>::try_from(sealed.as_slice()).expect("a hello is HELLO_LEN bytes"),
            ),
            advert_serial: encap.serial,
        }
    }

    fn at_rest_key(b: u8) -> [u8; AEAD_KEY_LEN] {
        [b; AEAD_KEY_LEN]
    }

    fn label(b: u8) -> CorrespondenceLabel {
        CorrespondenceLabel::from_bytes([b; 32])
    }

    fn identity_pk(b: u8) -> Box<[u8; ml_dsa::PK_LEN]> {
        Box::new([b; ml_dsa::PK_LEN])
    }

    fn lookup(b: u8) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        [b; HELLO_LOOKUP_KEY_LEN]
    }

    /// A conversation state over `conv`, with the numbers the caller names.
    fn conv_state(
        conv: &Conversation,
        send_seq: u64,
        peer_collected: u64,
        my_collected: u64,
        hello: Option<OutstandingHello>,
    ) -> ConvState {
        ConvState {
            peer_identity_pk: identity_pk(0x7e),
            outgoing_lookup_key: lookup(0xa1),
            incoming_lookup_key: lookup(0xb1),
            generation: 3,
            conversation: conv.snapshot(),
            send_seq,
            peer_collected,
            my_collected,
            cursor_published: my_collected,
            awaiting_acceptance: false,
            outstanding_hello: hello,
            own_hello_secret: Some(shared_secret(0x44)),
            own_hello_kem_ct: Some(Box::new([0x77u8; ml_kem::CT_LEN])),
            peer_hello_secret: Some(shared_secret(0x55)),
            peer_advert_serial: Some(9),
            own_opening: Some(Box::new([0x66u8; OPENING_LEN])),
        }
    }

    /// Two conversations sharing one `ss0`, the initiator's first ratchet key
    /// already handed to the acceptor as a channel opening would.
    fn pair() -> (Conversation, Conversation) {
        let secret = shared_secret(0x21);
        let mut entropy = Seeded::at(11);
        let opening = initiate(&secret, |b| entropy.fill(b)).expect("initiate");
        let acceptor = accept(&secret, &opening.ratchet_pk).expect("accept");
        (opening.conversation, acceptor)
    }

    // ── round trip ──────────────────────────────────────────────────────────

    /// Each record kind survives the at-rest seal, and a store opened under a
    /// different key cannot read any of them.
    ///
    /// The byte comparison is over a re-encode rather than over the struct,
    /// which has no equality; the control on it is the *live* assertion below
    /// it, where a conversation rebuilt from the decoded snapshot opens a
    /// message sealed after the snapshot was taken. Equal bytes would still
    /// pass if both encodings were empty; opening a message would not.
    #[test]
    fn every_record_kind_round_trips_and_a_wrong_key_opens_none_of_them() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut a, mut b) = pair();
        let mut ea = Seeded::at(101);
        let mut eb = Seeded::at(202);

        // An exchange first, so the snapshot holds a stepped chain, a retained
        // own turn and a read peer turn rather than the state `initiate` left.
        let (header, sealed) = a.seal(b"first", 0, |x| ea.fill(x)).expect("a seals");
        assert_eq!(b.open(&header, &sealed).expect("b opens"), b"first");
        let (header, sealed) = b.seal(b"reply", 0, |x| eb.fill(x)).expect("b seals");
        assert_eq!(a.open(&header, &sealed).expect("a opens"), b"reply");

        let advert = rotated_advert();
        let hello = outstanding_hello();
        let state = conv_state(&a, 1, 0, 1, Some(hello.clone()));
        let ciphertext: Vec<u8> = (0..3_000u32).map(|i| (i % 251) as u8).collect();

        let store = Store::open(tmp.path(), &at_rest_key(1)).unwrap();
        store.persist_advert_keys(&advert).unwrap();
        store.create_conv(&label(1), &state).unwrap();
        store.persist_outbox(&label(1), 0, &ciphertext).unwrap();
        drop(store);

        let store = Store::open(tmp.path(), &at_rest_key(1)).unwrap();
        let loaded = store.load().unwrap();

        let read_advert = loaded.advert_keys.expect("the advert record is there");
        assert_eq!(
            encode_advert_keys(&read_advert).to_vec(),
            encode_advert_keys(&advert).to_vec(),
            "the advert record did not round trip"
        );
        assert_eq!(read_advert.previous.expect("retained key").serial, 0);

        assert_eq!(loaded.convs.len(), 1, "one correspondence was written");
        let conv = loaded.convs.into_iter().next().unwrap();
        assert_eq!(conv.peer, label(1));
        assert_eq!(
            encode_conv(&conv.state).to_vec(),
            encode_conv(&state).to_vec(),
            "the conversation record did not round trip"
        );
        let read_hello = conv
            .state
            .outstanding_hello
            .as_ref()
            .expect("the hello round trips");
        assert_eq!(read_hello.slot, hello.slot);
        assert_eq!(read_hello.r, hello.r);
        assert_eq!(read_hello.kem_ct, hello.kem_ct);
        assert_eq!(read_hello.sealed, hello.sealed);
        assert_eq!(read_hello.advert_serial, hello.advert_serial);
        // The controls on those five: none of them is a default, and the
        // sealed bytes are the ones a drop slot holds rather than a copy of
        // the encapsulation.
        assert_ne!(hello.slot, 0);
        assert_ne!(hello.advert_serial, u64::MAX);
        assert_eq!(hello.sealed.len(), HELLO_LEN);
        assert_ne!(&hello.sealed[ml_kem::CT_LEN..], &[0u8; 8][..]);
        // The five fields the cursor and control-record paths depend on, each
        // asserted against the value written rather than against a default.
        assert_eq!(conv.state.cursor_published, state.cursor_published);
        assert_eq!(conv.state.peer_advert_serial, Some(9));
        assert_eq!(conv.state.awaiting_acceptance, state.awaiting_acceptance);
        assert_eq!(
            conv.state
                .own_hello_secret
                .as_ref()
                .expect("the own hello secret round trips")
                .as_bytes(),
            shared_secret(0x44).as_bytes()
        );
        assert_eq!(
            conv.state
                .peer_hello_secret
                .as_ref()
                .expect("the peer hello secret round trips")
                .as_bytes(),
            shared_secret(0x55).as_bytes()
        );
        assert_eq!(
            conv.state
                .own_hello_kem_ct
                .as_ref()
                .expect("the hello encapsulation round trips")
                .as_slice(),
            &[0x77u8; ml_kem::CT_LEN][..]
        );
        assert_eq!(
            conv.state
                .own_opening
                .as_ref()
                .expect("the opening round trips")
                .as_slice(),
            &[0x66u8; OPENING_LEN][..]
        );
        // The control on the three absence-capable fields: the same record
        // with all three absent round trips as absent, so `Some` above is the
        // value written and not a decoder that always reports one.
        let bare = conv_state(&a, 0, 0, 0, None);
        let bare = ConvState {
            own_hello_secret: None,
            own_hello_kem_ct: None,
            peer_hello_secret: None,
            peer_advert_serial: None,
            own_opening: None,
            ..bare
        };
        let decoded = decode_conv(&encode_conv(&bare)).expect("a bare record decodes");
        assert!(decoded.own_hello_secret.is_none());
        assert!(decoded.own_hello_kem_ct.is_none());
        assert!(decoded.peer_hello_secret.is_none());
        assert!(decoded.peer_advert_serial.is_none());
        assert!(decoded.own_opening.is_none());
        assert_eq!(
            conv.outstanding_outbox,
            vec![OutboxEntry {
                seq: 0,
                ciphertext: ciphertext.clone()
            }],
            "the outbox record did not round trip"
        );

        // The live control: the decoded key schedule is the one `a` had, so a
        // message `b` seals now opens under it.
        let mut restored = Conversation::restore(conv.state.conversation);
        let (header, sealed) = b
            .seal(b"after the snapshot", 0, |x| eb.fill(x))
            .expect("seal");
        assert_eq!(
            restored
                .open(&header, &sealed)
                .expect("the restored a opens"),
            b"after the snapshot"
        );
        drop(store);

        // The wrong key opens nothing, and says so rather than reading zeros.
        let wrong = Store::open(tmp.path(), &at_rest_key(2)).unwrap();
        assert!(
            matches!(
                wrong.load(),
                Err(StoreError::Store(DmStoreError::NotAuthentic { .. }))
            ),
            "a store opened under another key must refuse, not decode"
        );
    }

    /// A sequence whose ring position is held by an uncollected message is
    /// refused rather than overwriting it.
    #[test]
    fn an_outbox_entry_is_never_overwritten_by_a_sequence_that_shares_its_ring_slot() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path(), &at_rest_key(3)).unwrap();
        store.persist_outbox(&label(4), 0, b"first").unwrap();
        // The control: the same sequence again is a re-seal, and is allowed.
        store.persist_outbox(&label(4), 0, b"first again").unwrap();

        let err = store
            .persist_outbox(&label(4), RING_SLOTS, b"a full ring later")
            .expect_err("the slot is occupied");
        assert!(matches!(
            err,
            StoreError::OutboxSlotOccupied {
                offered,
                holding: 0
            } if offered == RING_SLOTS
        ));

        store.delete_outbox_through(&label(4), 1).unwrap();
        store
            .persist_outbox(&label(4), RING_SLOTS, b"a full ring later")
            .expect("the slot is free once the cursor passes it");
    }

    // ── the fault-injection harness ─────────────────────────────────────────

    /// The network, as a map from a channel's lookup key and subkey to the
    /// bytes in that slot, plus the cursor each channel publishes.
    #[derive(Default)]
    struct FakeDht {
        slots: HashMap<([u8; HELLO_LOOKUP_KEY_LEN], u16), Vec<u8>>,
        cursors: HashMap<[u8; HELLO_LOOKUP_KEY_LEN], u64>,
        writes: usize,
    }

    impl FakeDht {
        fn write_slot(&mut self, key: [u8; HELLO_LOOKUP_KEY_LEN], subkey: u16, bytes: Vec<u8>) {
            self.writes += 1;
            self.slots.insert((key, subkey), bytes);
        }

        fn slot(&self, key: &[u8; HELLO_LOOKUP_KEY_LEN], subkey: u16) -> Option<&Vec<u8>> {
            self.slots.get(&(*key, subkey))
        }

        fn evict(&mut self, key: &[u8; HELLO_LOOKUP_KEY_LEN], subkey: u16) {
            self.slots.remove(&(*key, subkey));
        }

        fn write_cursor(&mut self, key: [u8; HELLO_LOOKUP_KEY_LEN], cursor: u64) {
            self.writes += 1;
            self.cursors.insert(key, cursor);
        }

        fn cursor(&self, key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> Option<u64> {
            self.cursors.get(key).copied()
        }
    }

    /// The order a client performs its persists and its DHT writes in.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Order {
        /// The design's: every DHT write follows the persist it depends on.
        PersistFirst,
        /// The mutation: a collector publishes its cursor before recording it,
        /// so a correspondent can free a slot for a message this side has not
        /// durably read.
        PublishCursorBeforePersist,
    }

    /// The client died at this step boundary.
    struct Abort;

    /// How many more persists or DHT writes this client performs before it
    /// dies. `None` is a client that runs to the end of its work.
    struct Budget {
        left: Option<usize>,
        spent: usize,
    }

    impl Budget {
        fn unlimited() -> Self {
            Self {
                left: None,
                spent: 0,
            }
        }

        fn of(n: usize) -> Self {
            Self {
                left: Some(n),
                spent: 0,
            }
        }

        /// Consume one act, or report the abort that happens at this boundary
        /// — before the act, so a budget of `n` performs exactly `n` of them.
        fn act(&mut self) -> Result<(), Abort> {
            if self.left.is_some_and(|l| self.spent >= l) {
                return Err(Abort);
            }
            self.spent += 1;
            Ok(())
        }
    }

    /// Which side of the conversation.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Side {
        A,
        B,
    }

    /// One step of the scripted flow.
    #[derive(Clone, Copy)]
    enum Op {
        Send(Side, &'static [u8]),
        Collect(Side),
    }

    /// A profile: its store root and its at-rest key.
    struct Profile {
        root: tempfile::TempDir,
        key: [u8; AEAD_KEY_LEN],
    }

    /// One run of a client: it launches, does one op, and is dropped. Nothing
    /// it holds in memory outlives it, which is what makes a relaunch read the
    /// disk rather than its own recollection.
    struct Client {
        store: Store,
        label: CorrespondenceLabel,
        out_key: [u8; HELLO_LOOKUP_KEY_LEN],
        in_key: [u8; HELLO_LOOKUP_KEY_LEN],
        conv: Conversation,
        ring: Ring,
        my_collected: u64,
        opened: Vec<Vec<u8>>,
    }

    impl Client {
        /// Launch from the disk, and do what § Flows requires of a launch:
        /// rewrite any outstanding slot the network no longer holds, byte for
        /// byte.
        fn launch(profile: &Profile, label: CorrespondenceLabel, dht: &mut FakeDht) -> Self {
            let store = Store::open(profile.root.path(), &profile.key).expect("open the store");
            let loaded = store.load().expect("load");
            let found = loaded
                .convs
                .into_iter()
                .find(|c| c.peer == label)
                .expect("the conversation is on disk");
            let LoadedConv {
                state,
                outstanding_outbox,
                ..
            } = found;
            for entry in &outstanding_outbox {
                let subkey = channel::slot_for(entry.seq);
                if dht.slot(&state.outgoing_lookup_key, subkey) != Some(&entry.ciphertext) {
                    dht.write_slot(state.outgoing_lookup_key, subkey, entry.ciphertext.clone());
                }
            }
            Self {
                store,
                label,
                out_key: state.outgoing_lookup_key,
                in_key: state.incoming_lookup_key,
                conv: Conversation::restore(state.conversation),
                ring: Ring::restore(state.send_seq, state.peer_collected).expect("the ring"),
                my_collected: state.my_collected,
                opened: Vec::new(),
            }
        }

        /// Write back only the fields this client tracks.
        ///
        /// Through `update_conv` rather than a whole-record write: a client
        /// holds the key schedule and the three cursors and nothing else, and
        /// rebuilding the record from that would blank every field it does not
        /// know about — the outstanding hello first.
        fn persist(&self) {
            self.store
                .update_conv(&self.label, |state| {
                    state.conversation = self.conv.snapshot();
                    state.send_seq = self.ring.send_seq();
                    state.peer_collected = self.ring.peer_collected();
                    state.my_collected = self.my_collected;
                })
                .expect("persist the conversation");
        }

        /// Seal one message and get it onto the network, in the order § Flows
        /// gives: the ciphertext, then the state that commits it, then the
        /// write.
        fn send(
            &mut self,
            body: &[u8],
            entropy: &mut Seeded,
            dht: &mut FakeDht,
            budget: &mut Budget,
        ) -> Result<(), Abort> {
            let seq = self.ring.reserve().expect("the ring has room");
            let (header, sealed) = self
                .conv
                .seal(body, 0, |x| entropy.fill(x))
                .expect("seal the body");
            let mut ciphertext = header.encode();
            ciphertext.extend_from_slice(&sealed);

            budget.act()?;
            self.store
                .persist_outbox(&self.label, seq, &ciphertext)
                .expect("persist the outbox");
            budget.act()?;
            self.persist();
            budget.act()?;
            // The ordering contract, observed rather than assumed: what is
            // about to go into the slot is read back out of the store, so a
            // write that got ahead of either persist fails here rather than
            // passing as a run that happened to converge.
            let owed = self
                .store
                .load()
                .expect("load")
                .convs
                .into_iter()
                .find(|c| c.peer == self.label)
                .expect("a record")
                .outstanding_outbox;
            assert!(
                owed.iter()
                    .any(|e| e.seq == seq && e.ciphertext == ciphertext),
                "a slot is written before its bytes reached disk"
            );
            dht.write_slot(self.out_key, channel::slot_for(seq), ciphertext);
            Ok(())
        }

        /// Read everything the correspondent has written since this side's
        /// cursor, record the cursor, publish it, and free what the
        /// correspondent has collected.
        fn collect(
            &mut self,
            dht: &mut FakeDht,
            budget: &mut Budget,
            order: Order,
        ) -> Result<(), Abort> {
            if let Some(c) = dht.cursor(&self.in_key) {
                self.ring.advance_peer_collected(c);
            }
            loop {
                let subkey = channel::slot_for(self.my_collected);
                let Some(raw) = dht.slot(&self.in_key, subkey).cloned() else {
                    break;
                };
                let (header, sealed) = MessageHeader::decode(&raw).expect("decode the header");
                if header.seq != self.my_collected {
                    break;
                }
                let body = self.conv.open(&header, sealed).expect("open the message");
                self.ring.advance_peer_collected(header.cursor);
                self.opened.push(body);
                self.my_collected += 1;
            }

            match order {
                Order::PersistFirst => {
                    budget.act()?;
                    self.persist();
                    budget.act()?;
                    dht.write_cursor(self.out_key, self.my_collected);
                }
                Order::PublishCursorBeforePersist => {
                    budget.act()?;
                    dht.write_cursor(self.out_key, self.my_collected);
                    budget.act()?;
                    self.persist();
                }
            }

            budget.act()?;
            let collected = self.ring.peer_collected();
            self.store
                .delete_outbox_through(&self.label, collected)
                .expect("free the collected entries");
            // A slot below the correspondent's cursor is free for the ring to
            // reuse, so the network is no longer obliged to hold it.
            for seq in 0..collected {
                dht.evict(&self.out_key, channel::slot_for(seq));
            }
            Ok(())
        }
    }

    /// What the assertions compare: each side's durable position.
    #[derive(Debug, PartialEq, Eq)]
    struct EndState {
        a: (u64, u64, u64),
        b: (u64, u64, u64),
    }

    /// The whole run: two profiles, the network they share, and the script.
    struct Run {
        a: Profile,
        b: Profile,
        dht: FakeDht,
        entropy_a: Seeded,
        entropy_b: Seeded,
    }

    const LABEL_A: u8 = 0xa0;
    const LABEL_B: u8 = 0xb0;
    const A_CHANNEL: u8 = 0xa1;
    const B_CHANNEL: u8 = 0xb1;

    /// What each side sends, in order. Two messages one way and one back is
    /// the smallest script that exercises every step the flow has: a second
    /// message inside one turn, a reply that starts a turn of its own, and a
    /// collection that moves a correspondent's cursor off zero.
    const FROM_A: [&[u8]; 2] = [b"a says nought", b"a says one"];
    /// See [`FROM_A`].
    const FROM_B: [&[u8]; 1] = [b"b says nought"];

    /// The scripted flow, as § Flows' ordinary-message and reply steps.
    const SCRIPT: [Op; 6] = [
        Op::Send(Side::A, FROM_A[0]),
        Op::Send(Side::A, FROM_A[1]),
        Op::Collect(Side::B),
        Op::Send(Side::B, FROM_B[0]),
        Op::Collect(Side::A),
        Op::Collect(Side::B),
    ];

    impl Run {
        /// Both profiles, with the conversation established on each side's
        /// disk before the script starts.
        fn new() -> Self {
            let a = Profile {
                root: tempfile::tempdir().unwrap(),
                key: at_rest_key(0x0a),
            };
            let b = Profile {
                root: tempfile::tempdir().unwrap(),
                key: at_rest_key(0x0b),
            };
            let (conv_a, conv_b) = pair();

            let store_a = Store::open(a.root.path(), &a.key).unwrap();
            store_a
                .create_conv(
                    &label(LABEL_A),
                    &ConvState {
                        peer_identity_pk: identity_pk(0xbb),
                        outgoing_lookup_key: lookup(A_CHANNEL),
                        incoming_lookup_key: lookup(B_CHANNEL),
                        generation: 0,
                        conversation: conv_a.snapshot(),
                        send_seq: 0,
                        peer_collected: 0,
                        my_collected: 0,
                        cursor_published: 0,
                        awaiting_acceptance: false,
                        outstanding_hello: None,
                        own_hello_secret: None,
                        own_hello_kem_ct: None,
                        peer_hello_secret: None,
                        peer_advert_serial: None,
                        own_opening: None,
                    },
                )
                .unwrap();
            let store_b = Store::open(b.root.path(), &b.key).unwrap();
            store_b
                .create_conv(
                    &label(LABEL_B),
                    &ConvState {
                        peer_identity_pk: identity_pk(0xaa),
                        outgoing_lookup_key: lookup(B_CHANNEL),
                        incoming_lookup_key: lookup(A_CHANNEL),
                        generation: 0,
                        conversation: conv_b.snapshot(),
                        send_seq: 0,
                        peer_collected: 0,
                        my_collected: 0,
                        cursor_published: 0,
                        awaiting_acceptance: false,
                        outstanding_hello: None,
                        own_hello_secret: None,
                        own_hello_kem_ct: None,
                        peer_hello_secret: None,
                        peer_advert_serial: None,
                        own_opening: None,
                    },
                )
                .unwrap();

            Self {
                a,
                b,
                dht: FakeDht::default(),
                entropy_a: Seeded::at(7_001),
                entropy_b: Seeded::at(9_001),
            }
        }

        fn profile(&self, side: Side) -> (&Profile, CorrespondenceLabel) {
            match side {
                Side::A => (&self.a, label(LABEL_A)),
                Side::B => (&self.b, label(LABEL_B)),
            }
        }

        /// One op by one freshly launched client, which is then dropped. An
        /// abort is the drop happening early.
        fn step(&mut self, op: Op, budget: &mut Budget, order: Order) {
            let side = match op {
                Op::Send(s, _) | Op::Collect(s) => s,
            };
            let (profile, lbl) = match side {
                Side::A => (&self.a, label(LABEL_A)),
                Side::B => (&self.b, label(LABEL_B)),
            };
            let mut client = Client::launch(profile, lbl, &mut self.dht);
            let outcome = match op {
                Op::Send(Side::A, body) => {
                    client.send(body, &mut self.entropy_a, &mut self.dht, budget)
                }
                Op::Send(Side::B, body) => {
                    client.send(body, &mut self.entropy_b, &mut self.dht, budget)
                }
                Op::Collect(_) => client.collect(&mut self.dht, budget, order),
            };
            drop(outcome);
        }

        /// Run the script, then settle: re-send whatever a dropped send never
        /// committed, and collect until both sides are quiet. The settling is
        /// the application retrying its own unsent message and polling on its
        /// normal schedule, and it is never budgeted — the abort has already
        /// happened.
        fn run(&mut self, abort_at: Option<usize>, order: Order) {
            let mut budget = match abort_at {
                Some(n) => Budget::of(n),
                None => Budget::unlimited(),
            };
            for op in SCRIPT {
                self.step(op, &mut budget, order);
            }

            let mut settle = Budget::unlimited();
            for _ in 0..4 {
                for side in [Side::A, Side::B] {
                    // What is still to send is read from the disk, not from a
                    // counter: a send that committed and then died before its
                    // DHT write is already sent, and re-sending it would put a
                    // second message at a sequence the correspondent will only
                    // ever read once.
                    let script: &[&'static [u8]] = match side {
                        Side::A => &FROM_A,
                        Side::B => &FROM_B,
                    };
                    let committed = self.position(side).0 as usize;
                    if committed < script.len() {
                        let body = script[committed];
                        self.step(Op::Send(side, body), &mut settle, order);
                    }
                    self.step(Op::Collect(side), &mut settle, order);
                }
            }
        }

        fn position(&self, side: Side) -> (u64, u64, u64) {
            let (profile, lbl) = self.profile(side);
            let store = Store::open(profile.root.path(), &profile.key).unwrap();
            let state = store.load_conv(&lbl).unwrap().expect("a record");
            (state.send_seq, state.my_collected, state.peer_collected)
        }

        fn end_state(&self) -> EndState {
            EndState {
                a: self.position(Side::A),
                b: self.position(Side::B),
            }
        }

        /// Every outstanding entry's bytes are the bytes in its slot.
        fn outbox_matches_the_network(&self, side: Side) {
            let (profile, lbl) = self.profile(side);
            let store = Store::open(profile.root.path(), &profile.key).unwrap();
            let loaded = store.load().unwrap();
            let conv = loaded
                .convs
                .into_iter()
                .find(|c| c.peer == lbl)
                .expect("a record");
            for entry in &conv.outstanding_outbox {
                assert_eq!(
                    self.dht.slot(
                        &conv.state.outgoing_lookup_key,
                        channel::slot_for(entry.seq)
                    ),
                    Some(&entry.ciphertext),
                    "{side:?}'s slot for {} differs from its outbox",
                    entry.seq
                );
            }
        }
    }

    /// The reference end state, and the assertions every fault run is held to.
    fn assert_converged(run: &Run, reference: &EndState) {
        let end = run.end_state();
        assert_eq!(
            end.a.0,
            FROM_A.len() as u64,
            "a committed every message it meant to send"
        );
        assert_eq!(
            end.b.0,
            FROM_B.len() as u64,
            "b committed every message it meant to send"
        );
        assert_eq!(end.b.1, end.a.0, "b collected every message a committed");
        assert_eq!(end.a.1, end.b.0, "a collected every message b committed");
        // Nothing is shown as collected that the correspondent did not open.
        assert!(
            end.a.2 <= end.b.1,
            "a believes b collected {} of {} it has read",
            end.a.2,
            end.b.1
        );
        assert!(
            end.b.2 <= end.a.1,
            "b believes a collected {} of {} it has read",
            end.b.2,
            end.a.1
        );
        run.outbox_matches_the_network(Side::A);
        run.outbox_matches_the_network(Side::B);
        assert_eq!(&end, reference, "the run did not reach the reference state");
    }

    /// The reference run, uninterrupted, and the control on every assertion
    /// the fault runs make: the bodies themselves arrive, in order.
    fn reference_run() -> (EndState, usize) {
        let mut run = Run::new();
        run.run(None, Order::PersistFirst);
        let end = run.end_state();
        assert_eq!(end.a.0, FROM_A.len() as u64);
        assert_eq!(end.b.1, FROM_A.len() as u64);
        assert!(run.dht.writes > 0, "the run wrote nothing to the network");
        (end, run.dht.writes)
    }

    /// Every message opens, in order, on an uninterrupted run — the control on
    /// the harness itself, since every convergence assertion below compares
    /// cursors rather than bodies.
    #[test]
    fn the_uninterrupted_flow_delivers_every_body_in_order() {
        let mut run = Run::new();
        let mut budget = Budget::unlimited();
        let mut delivered_to_b = Vec::new();
        let mut delivered_to_a = Vec::new();

        for op in SCRIPT {
            let side = match op {
                Op::Send(s, _) | Op::Collect(s) => s,
            };
            let (profile, lbl) = match side {
                Side::A => (&run.a, label(LABEL_A)),
                Side::B => (&run.b, label(LABEL_B)),
            };
            let mut client = Client::launch(profile, lbl, &mut run.dht);
            match op {
                Op::Send(Side::A, body) => {
                    client
                        .send(body, &mut run.entropy_a, &mut run.dht, &mut budget)
                        .ok();
                }
                Op::Send(Side::B, body) => {
                    client
                        .send(body, &mut run.entropy_b, &mut run.dht, &mut budget)
                        .ok();
                }
                Op::Collect(s) => {
                    client
                        .collect(&mut run.dht, &mut budget, Order::PersistFirst)
                        .ok();
                    match s {
                        Side::A => delivered_to_a.extend(client.opened.clone()),
                        Side::B => delivered_to_b.extend(client.opened.clone()),
                    }
                }
            }
        }

        assert_eq!(
            delivered_to_b,
            FROM_A.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
            "b did not read a's messages in order"
        );
        assert_eq!(
            delivered_to_a,
            FROM_B.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
            "a did not read b's messages in order"
        );
    }

    /// Abort at every step boundary of the flow, relaunch from the disk, and
    /// require the run to reach the state the uninterrupted run reaches.
    fn abort_at_every_boundary(order: Order) {
        let (reference, _) = reference_run();
        let total = {
            let mut counting = Run::new();
            let mut budget = Budget::of(usize::MAX);
            for op in SCRIPT {
                counting.step(op, &mut budget, Order::PersistFirst);
            }
            budget.spent
        };
        assert!(total > 10, "the flow has {total} step boundaries");

        for boundary in 0..total {
            let mut run = Run::new();
            run.run(Some(boundary), order);
            assert_converged(&run, &reference);
        }
    }

    /// The design's order survives an abort at every step boundary.
    #[test]
    fn an_abort_at_any_step_boundary_converges_to_the_uninterrupted_state() {
        abort_at_every_boundary(Order::PersistFirst);
    }

    /// The mutation control. A collector that publishes its cursor before
    /// recording it tells the correspondent to free a slot for a message this
    /// side has not durably read; the abort between the two makes that message
    /// unreachable, and no later run can recover it.
    #[test]
    #[should_panic(expected = "collected every message")]
    fn publishing_a_cursor_before_persisting_it_loses_a_message() {
        abort_at_every_boundary(Order::PublishCursorBeforePersist);
    }

    /// An outstanding slot the network has dropped is rewritten on the next
    /// launch, byte for byte, because the seal that made those bytes cannot be
    /// repeated.
    #[test]
    fn a_launch_rewrites_an_evicted_slot_byte_for_byte() {
        let mut run = Run::new();
        let mut budget = Budget::unlimited();
        run.step(
            Op::Send(Side::A, FROM_A[0]),
            &mut budget,
            Order::PersistFirst,
        );

        let subkey = channel::slot_for(0);
        let written = run
            .dht
            .slot(&lookup(A_CHANNEL), subkey)
            .cloned()
            .expect("the send wrote the slot");
        run.dht.evict(&lookup(A_CHANNEL), subkey);
        assert!(
            run.dht.slot(&lookup(A_CHANNEL), subkey).is_none(),
            "the control: the slot really is gone"
        );

        let before = run.dht.writes;
        let client = Client::launch(&run.a, label(LABEL_A), &mut run.dht);
        drop(client);

        assert_eq!(
            run.dht.slot(&lookup(A_CHANNEL), subkey),
            Some(&written),
            "the launch must restore the exact bytes"
        );
        assert_eq!(run.dht.writes, before + 1, "one rewrite, not a re-seal");

        // And a launch with nothing missing rewrites nothing.
        let before = run.dht.writes;
        let client = Client::launch(&run.a, label(LABEL_A), &mut run.dht);
        drop(client);
        assert_eq!(run.dht.writes, before, "a matching slot is left alone");

        // A slot holding the wrong bytes is the other half of the rule, and
        // the one an absence check alone never reaches: the network kept a
        // value, so nothing looks missing.
        run.dht
            .write_slot(lookup(A_CHANNEL), subkey, b"other bytes".to_vec());
        let before = run.dht.writes;
        let client = Client::launch(&run.a, label(LABEL_A), &mut run.dht);
        drop(client);
        assert_eq!(
            run.dht.slot(&lookup(A_CHANNEL), subkey),
            Some(&written),
            "a slot holding different bytes must be corrected"
        );
        assert_eq!(run.dht.writes, before + 1, "one rewrite, not a re-seal");
    }

    /// The drop slot this profile's helloes are written to. The drop plane is
    /// not modelled further here; what the store owes is the bytes.
    fn drop_key() -> [u8; HELLO_LOOKUP_KEY_LEN] {
        lookup(0xdd)
    }

    /// § Flows step 4 persists CONV before the drop write. An abort between
    /// them leaves the hello on disk, and what a relaunch offers for the write
    /// is the sealed bytes unchanged — re-encapsulating would mint a different
    /// `ss0` and orphan every ciphertext already in the outbox.
    #[test]
    fn a_hello_persisted_before_its_drop_write_is_offered_for_rewrite_unchanged() {
        let mut run = Run::new();
        let hello = outstanding_hello();

        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        store
            .update_conv(&label(LABEL_A), |state| {
                state.outstanding_hello = Some(hello.clone());
            })
            .unwrap();
        drop(store);

        // The abort is here: the drop write never happened.
        assert!(
            run.dht.slot(&drop_key(), hello.slot).is_none(),
            "the control: the drop slot is empty"
        );

        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        let loaded = store.load().unwrap();
        let read = loaded
            .convs
            .iter()
            .find(|c| c.peer == label(LABEL_A))
            .expect("a record")
            .state
            .outstanding_hello
            .clone()
            .expect("the hello survived the abort");
        assert_eq!(read.slot, hello.slot);
        assert_eq!(read.advert_serial, hello.advert_serial);
        assert_eq!(read.kem_ct, hello.kem_ct);
        assert_eq!(
            read.sealed, hello.sealed,
            "a rewrite must be byte-identical"
        );

        run.dht
            .write_slot(drop_key(), read.slot, read.sealed.to_vec());
        assert_eq!(
            run.dht.slot(&drop_key(), hello.slot),
            Some(&hello.sealed.to_vec()),
            "the slot holds the bytes that were sealed, not a fresh hello"
        );
    }

    /// An outbox entry at `send_seq` was sealed by a run that died before its
    /// conversation record committed it. No slot was written, so a launch must
    /// neither offer it nor write it.
    #[test]
    fn an_outbox_entry_at_send_seq_is_an_uncommitted_seal() {
        let mut run = Run::new();
        // One act: the outbox persist lands, the conversation record does not.
        let mut budget = Budget::of(1);
        run.step(
            Op::Send(Side::A, FROM_A[0]),
            &mut budget,
            Order::PersistFirst,
        );

        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        // The control: the seal really did reach the disk.
        let raw = store
            .records()
            .read_unlocked(&label(LABEL_A), RecordKind::ConversationOutbox)
            .unwrap()
            .expect("an outbox record");
        let table = decode_conv_outbox(&raw).unwrap();
        assert!(
            table.iter().flatten().any(|e| e.seq == 0),
            "the control: the ciphertext is on disk"
        );

        let loaded = store.load().unwrap();
        let conv = loaded
            .convs
            .iter()
            .find(|c| c.peer == label(LABEL_A))
            .expect("a record");
        assert_eq!(conv.state.send_seq, 0, "the send never committed");
        assert!(
            conv.outstanding_outbox.is_empty(),
            "an entry at send_seq is an uncommitted seal"
        );
        drop(store);

        let before = run.dht.writes;
        let client = Client::launch(&run.a, label(LABEL_A), &mut run.dht);
        drop(client);
        assert_eq!(
            run.dht.writes, before,
            "a launch writes nothing for an uncommitted seal"
        );
    }

    /// Both of a correspondence's records go in one act, and a load stops
    /// offering it.
    #[test]
    fn deleting_a_conversation_removes_both_of_its_records() {
        let mut run = Run::new();
        let mut budget = Budget::unlimited();
        run.step(
            Op::Send(Side::A, FROM_A[0]),
            &mut budget,
            Order::PersistFirst,
        );

        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        assert_eq!(
            store.load().unwrap().convs.len(),
            1,
            "the control: the conversation is there first"
        );
        store.delete_conv(&label(LABEL_A)).unwrap();
        assert!(
            store.load().unwrap().convs.is_empty(),
            "a deleted conversation is still offered"
        );

        let mut files = Vec::new();
        all_files(run.a.root.path(), &mut files);
        assert!(!files.is_empty(), "the walk found nothing");
        for kind in [RecordKind::Conversation, RecordKind::ConversationOutbox] {
            assert!(
                !files
                    .iter()
                    .any(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some(kind.file_name())),
                "{} survived the delete",
                kind.file_name()
            );
        }
        // A second delete is not an error: the postcondition already holds.
        store.delete_conv(&label(LABEL_A)).unwrap();
    }

    /// A conversation record that will not decode stops the whole load rather
    /// than dropping that correspondence out of the answer.
    #[test]
    fn load_refuses_a_conversation_record_it_cannot_decode() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path(), &at_rest_key(9)).unwrap();
        let (a, _b) = pair();
        store
            .create_conv(&label(9), &conv_state(&a, 0, 0, 0, None))
            .unwrap();
        // The mirror control: the good record is offered.
        assert_eq!(store.load().unwrap().convs.len(), 1);

        store
            .records()
            .critical_section::<_, DmStoreError>(&label(9), |g| {
                g.replace(RecordKind::Conversation, b"not a conversation record")
            })
            .unwrap();
        assert!(
            matches!(
                store.load(),
                Err(StoreError::Corrupt {
                    kind: RecordKind::Conversation,
                    ..
                })
            ),
            "a record that will not decode must be refused, not skipped"
        );
    }

    // ── what a decoder refuses ──────────────────────────────────────────────

    /// Byte offset of the conversation record's `send_seq`.
    const CONV_SEND_SEQ_AT: usize =
        CONV_MAGIC.len() + 1 + ml_dsa::PK_LEN + 2 * HELLO_LOOKUP_KEY_LEN + 8;
    /// Byte offset of the conversation record's hello presence flag: past
    /// `send_seq`, `peer_collected`, `my_collected`, `cursor_published` and
    /// the `awaiting_acceptance` flag.
    const CONV_HELLO_AT: usize = CONV_SEND_SEQ_AT + 8 + 8 + 8 + 8 + 1;

    /// A good conversation record with a hello, as bytes.
    fn conv_bytes_with_hello() -> Vec<u8> {
        let (a, _b) = pair();
        let state = conv_state(&a, 4, 2, 0, Some(outstanding_hello()));
        encode_conv(&state).to_vec()
    }

    #[test]
    fn a_record_carrying_an_unknown_version_is_refused() {
        let (a, _b) = pair();
        let cases: Vec<(&str, Vec<u8>, usize)> = vec![
            (
                "advert keys",
                encode_advert_keys(&rotated_advert()).to_vec(),
                ADVERT_KEYS_MAGIC.len(),
            ),
            ("conversation", conv_bytes_with_hello(), CONV_MAGIC.len()),
            (
                "outbox",
                encode_conv_outbox(&vec![None; RING_SLOTS as usize]).to_vec(),
                CONV_OUTBOX_MAGIC.len(),
            ),
        ];
        let _ = &a;
        for (name, good, version_at) in cases {
            // The control: the byte this test moves really is the version.
            assert_eq!(good[version_at], RECORD_VERSION, "{name}");
            let decode = |bytes: &[u8]| -> Result<(), StoreError> {
                match name {
                    "advert keys" => decode_advert_keys(bytes).map(|_| ()),
                    "conversation" => decode_conv(bytes).map(|_| ()),
                    _ => decode_conv_outbox(bytes).map(|_| ()),
                }
            };
            // The mirror control: untouched, it decodes.
            decode(&good).unwrap_or_else(|e| panic!("{name} must decode: {e}"));

            let mut bumped = good.clone();
            bumped[version_at] = RECORD_VERSION + 1;
            match decode(&bumped) {
                Err(StoreError::Corrupt { reason, .. }) => assert!(
                    reason.contains("version"),
                    "{name} refused for the wrong reason: {reason}"
                ),
                other => panic!("{name} accepted an unknown version: {other:?}"),
            }
        }
    }

    #[test]
    fn an_outbox_entry_away_from_its_ring_position_is_refused() {
        let mut table: OutboxTable = vec![None; RING_SLOTS as usize];
        table[0] = Some(OutboxEntry {
            seq: 0,
            ciphertext: b"a message".to_vec(),
        });
        let good = encode_conv_outbox(&table).to_vec();
        // The mirror control.
        assert_eq!(
            decode_conv_outbox(&good).unwrap()[0].as_ref().unwrap().seq,
            0
        );

        // Entry 0's sequence sits after the magic, the version and the flag.
        let seq_at = CONV_OUTBOX_MAGIC.len() + 1 + 1;
        assert_eq!(
            &good[seq_at..seq_at + 8],
            &0u64.to_be_bytes(),
            "the control"
        );
        let mut moved = good;
        moved[seq_at..seq_at + 8].copy_from_slice(&1u64.to_be_bytes());
        assert!(matches!(
            decode_conv_outbox(&moved),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_hello_naming_a_slot_the_drop_does_not_have_is_refused() {
        let good = conv_bytes_with_hello();
        // The mirror control.
        assert!(decode_conv(&good).unwrap().outstanding_hello.is_some());
        assert_eq!(
            good[CONV_HELLO_AT], PRESENT,
            "the control: a hello is there"
        );

        let mut wide = good;
        wide[CONV_HELLO_AT + 1..CONV_HELLO_AT + 3].copy_from_slice(&DROP_SUBKEYS.to_be_bytes());
        assert!(matches!(
            decode_conv(&wide),
            Err(StoreError::Corrupt { .. })
        ));
    }

    /// A hello another path persisted survives an ordinary send.
    ///
    /// The send writes back the key schedule and the three cursors; every
    /// other field is one the sending client never held, and a whole-record
    /// write built from its memory is what used to erase them.
    #[test]
    fn a_send_does_not_erase_a_hello_another_path_persisted() {
        let mut run = Run::new();
        let hello = outstanding_hello();
        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        store
            .update_conv(&label(LABEL_A), |state| {
                state.outstanding_hello = Some(hello.clone());
            })
            .unwrap();
        // The control: it is on disk before the send.
        assert!(
            store
                .load_conv(&label(LABEL_A))
                .unwrap()
                .expect("a record")
                .outstanding_hello
                .is_some()
        );
        drop(store);

        let mut budget = Budget::unlimited();
        run.step(
            Op::Send(Side::A, FROM_A[0]),
            &mut budget,
            Order::PersistFirst,
        );

        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        let state = store.load_conv(&label(LABEL_A)).unwrap().expect("a record");
        assert_eq!(state.send_seq, 1, "the control: the send did commit");
        let read = state
            .outstanding_hello
            .as_ref()
            .expect("the send erased the hello");
        assert_eq!(read.sealed, hello.sealed);
        assert_eq!(read.slot, hello.slot);
        // And the fields the client never held are still the record's.
        assert_eq!(state.outgoing_lookup_key, lookup(A_CHANNEL));
        assert_eq!(state.peer_identity_pk, identity_pk(0xbb));
    }

    /// A correspondence is established once. A second attempt is refused rather
    /// than replacing the record with the caller's idea of it.
    #[test]
    fn creating_a_conversation_twice_is_refused() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path(), &at_rest_key(0x2c)).unwrap();
        let (a, _b) = pair();
        // The control: the first one lands.
        store
            .create_conv(&label(0x2c), &conv_state(&a, 0, 0, 0, None))
            .unwrap();
        assert!(store.load_conv(&label(0x2c)).unwrap().is_some());
        assert!(matches!(
            store.create_conv(&label(0x2c), &conv_state(&a, 0, 0, 0, None)),
            Err(StoreError::ConversationExists)
        ));
    }

    /// A rotation driven through the store keeps the key it retired, so a hello
    /// already encapsulated to the previous serial still opens.
    #[test]
    fn a_rotation_through_the_store_persists_the_retired_key() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path(), &at_rest_key(0x2d)).unwrap();

        // Nothing to rotate before a first state is written.
        assert!(matches!(
            store.update_advert_keys(|_| ()),
            Err(StoreError::MissingAdvertKeys)
        ));

        let keys = advert::AdvertKeys::new(NOW, counting_fill(0x61)).expect("advert keys");
        let first_serial = keys.serial();
        store.persist_advert_keys(&keys.snapshot()).unwrap();
        // The control: no key is retained yet.
        assert!(
            store
                .load_advert_keys()
                .unwrap()
                .expect("a record")
                .previous
                .is_none()
        );

        let rotated = store
            .update_advert_keys(|k| {
                k.rotate_if_due(NOW + advert::ROTATION_PERIOD_SECS, counting_fill(0x62))
                    .expect("rotate")
            })
            .unwrap();
        assert!(rotated.happened(), "the control: the state did rotate");

        let read = store.load_advert_keys().unwrap().expect("a record");
        assert_ne!(read.serial, first_serial, "the current key moved on");
        let retained = read.previous.expect("the retired key was persisted");
        assert_eq!(retained.serial, first_serial);
    }

    #[test]
    fn a_hello_whose_encapsulation_is_not_the_one_it_opens_with_is_refused() {
        let good = conv_bytes_with_hello();
        // The mirror control.
        assert!(decode_conv(&good).unwrap().outstanding_hello.is_some());

        // The stored `kem_ct` sits after the flag, the slot and `r`; the sealed
        // hello opens with the same bytes.
        let kem_ct_at = CONV_HELLO_AT + 1 + 2 + HELLO_R_LEN;
        let sealed_at = kem_ct_at + ml_kem::CT_LEN;
        assert_eq!(
            good[kem_ct_at..kem_ct_at + ml_kem::CT_LEN],
            good[sealed_at..sealed_at + ml_kem::CT_LEN],
            "the control: the two copies agree before the patch"
        );

        let mut skewed = good;
        skewed[kem_ct_at] ^= 0xff;
        assert!(matches!(
            decode_conv(&skewed),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_cursor_above_this_sides_send_sequence_is_refused() {
        let good = conv_bytes_with_hello();
        // The mirror control, and the control on the offset.
        assert_eq!(decode_conv(&good).unwrap().peer_collected, 2);
        assert_eq!(
            &good[CONV_SEND_SEQ_AT..CONV_SEND_SEQ_AT + 8],
            &4u64.to_be_bytes(),
            "the control: send_seq is where this test thinks"
        );

        let mut ahead = good;
        let at = CONV_SEND_SEQ_AT + 8;
        ahead[at..at + 8].copy_from_slice(&5u64.to_be_bytes());
        assert!(matches!(
            decode_conv(&ahead),
            Err(StoreError::Corrupt { .. })
        ));
    }

    // ── no plaintext after close ────────────────────────────────────────────

    /// Every file under `root`, read whole.
    fn all_files(root: &Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(root).expect("read the directory") {
            let entry = entry.expect("an entry");
            let path = entry.path();
            if entry.file_type().expect("a file type").is_dir() {
                all_files(&path, out);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap_or_default()));
            }
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// After a conversation closes, no file either profile wrote holds the
    /// plaintext of anything sent or received.
    #[test]
    fn no_file_holds_the_plaintext_of_a_body_after_close() {
        const SENTINEL_A: &[u8] = b"sentinel-from-a-46f2b1c8";
        const SENTINEL_B: &[u8] = b"sentinel-from-b-9d03ae57";

        let mut run = Run::new();
        let mut budget = Budget::unlimited();
        run.step(
            Op::Send(Side::A, SENTINEL_A),
            &mut budget,
            Order::PersistFirst,
        );
        run.step(Op::Collect(Side::B), &mut budget, Order::PersistFirst);
        run.step(
            Op::Send(Side::B, SENTINEL_B),
            &mut budget,
            Order::PersistFirst,
        );
        run.step(Op::Collect(Side::A), &mut budget, Order::PersistFirst);
        // One more, left uncollected, so an outbox entry is outstanding at the
        // moment everything closes.
        run.step(
            Op::Send(Side::A, SENTINEL_A),
            &mut budget,
            Order::PersistFirst,
        );

        let mut files = Vec::new();
        all_files(run.a.root.path(), &mut files);
        all_files(run.b.root.path(), &mut files);
        assert!(files.len() > 4, "the walk found {} files", files.len());

        for (path, bytes) in &files {
            for sentinel in [SENTINEL_A, SENTINEL_B] {
                assert!(
                    !contains(bytes, sentinel),
                    "{} holds a body in the clear",
                    path.display()
                );
            }
        }

        // The positive control on the search: it does find a sentinel that is
        // there.
        let decoy = tempfile::tempdir().unwrap();
        let decoy_path = decoy.path().join("decoy.bin");
        std::fs::write(
            &decoy_path,
            [b"padding".as_slice(), SENTINEL_A, b"more"].concat(),
        )
        .unwrap();
        let mut decoys = Vec::new();
        all_files(decoy.path(), &mut decoys);
        assert!(
            decoys.iter().any(|(_, b)| contains(b, SENTINEL_A)),
            "the search cannot find a sentinel it is shown"
        );

        // The control the design names: the ciphertext outbox is present, at
        // its kind's fixed size, and still holds the outstanding message —
        // which is readable only through the store's key.
        let store = Store::open(run.a.root.path(), &run.a.key).unwrap();
        let loaded = store.load().unwrap();
        let conv = loaded
            .convs
            .into_iter()
            .find(|c| c.peer == label(LABEL_A))
            .expect("a's record");
        assert_eq!(
            conv.outstanding_outbox.len(),
            1,
            "one message is still owed to b"
        );
        let outbox_files: Vec<_> = files
            .iter()
            .filter(|(p, _)| {
                p.file_name().and_then(|n| n.to_str())
                    == Some(RecordKind::ConversationOutbox.file_name())
            })
            .collect();
        assert!(
            !outbox_files.is_empty(),
            "the control: a ciphertext outbox record is present"
        );
        for (path, bytes) in &outbox_files {
            assert_eq!(
                bytes.len(),
                RecordKind::ConversationOutbox.on_disk_len(),
                "{} is not the outbox record's fixed size",
                path.display()
            );
        }
        assert_eq!(
            run.dht.slot(
                &lookup(A_CHANNEL),
                channel::slot_for(conv.outstanding_outbox[0].seq)
            ),
            Some(&conv.outstanding_outbox[0].ciphertext),
            "the stored ciphertext is the one on the network"
        );
    }
}
