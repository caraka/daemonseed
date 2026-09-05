//! The wiring between the direct-messaging records and the disk (#281).
//!
//! The disk here is [`crate::storage::dm_store`], which holds the state a
//! correspondence needs in order to carry on — reconnect material, a handshake
//! still in progress, the unsettled outbox, how far reading has got, what is
//! known about the correspondent — plus the profile's block list. **It is not
//! where messages are kept:** a received message is never written there, and
//! sent content lives there only until its outbox entry settles or gives up.
//!
//! Every type this module binds already existed and already knew its own at-rest
//! shape. What did not exist was a **writer**: nothing anywhere under `dm/` ever
//! handed a byte to [`crate::storage::dm_store`], so `ProvisionalRecord::seal`,
//! [`Outbox::encode`] and [`ReceiveCursor::to_be_bytes`] were shapes the modules
//! could produce and nothing kept. Three consequences followed, and the first is
//! the reason this module exists:
//!
//! - **`ss0` was never erased.** [`crate::dm::provisional`] states that the
//!   record is deleted when the channel establishes, and the erasure of `ss0` is
//!   the forward-secrecy premise for trimming the ratchet at all. With no writer
//!   there was no deletion, because there was nothing to delete from.
//! - The outbox's persisted form had no store, so a give-up or a settlement that
//!   the user was never shown could not be re-offered after a restart (#279).
//! - [`crate::dm::provisional::restart`] — the whole of #243's loud teardown —
//!   had no call site, so the decision it exists to force was never taken.
//!
//! ## Why here rather than in `storage`
//!
//! [`crate::storage::dm_store`] is deliberately ignorant of what a DM record
//! *means*: it seals opaque bytes into a fixed bucket, derives the filename, and
//! holds the lock. Everything this module adds is DM semantics — which context a
//! provisional record must be opened under, that a record becoming a ratchet is
//! the moment it must stop existing, that a cursor read back from disk is a hint
//! needing corroboration however it was stored. Putting that in `storage` would make a storage
//! module import half of `dm` to know when a delete is due; putting it in `dm`
//! costs one import of the store and leaves each side knowing its own business.
//!
//! ## The lock, and which calls take it
//!
//! The store's own split is reproduced here rather than flattened, because
//! flattening it is the defect it was shaped to prevent. Entering
//! [`DmStore::critical_section`] **establishes** the correspondence directory on
//! disk, so a call that only asks a question must not enter one — and a call
//! that reads, decides, and writes back **must**, or two processes lose one of
//! the two decisions silently.
//!
//! So: [`DmPersist::read_outbox`], [`DmPersist::read_cursor`] and
//! [`DmPersist::read_contact`] are questions and take no lock;
//! [`DmPersist::update_outbox`], [`DmPersist::advance_cursor`] and
//! [`DmPersist::update_contact`] are read-modify-write and hold the lock across
//! the whole of it. There is deliberately **no** `save_outbox` taking an
//! [`Outbox`] the caller loaded earlier: that pair is exactly the lost-update the
//! store's API refuses to let anyone spell, re-offered one layer up.
//!
//! None of the calls here nests inside another, so
//! [`DmStoreError::Reentrant`]
//! is not reachable through this module's own composition — the restart path
//! reads without the lock and [`PendingHandshake::establish`] takes it afterwards,
//! rather than inside it.
//!
//! ## Two seals, on purpose
//!
//! A provisional record reaches the store **already sealed** by
//! [`ProvisionalRecord::seal`], and the store seals what it is handed a second
//! time. That is not an oversight, and the store expects it —
//! [`RecordKind::Provisional`]'s bucket is exactly
//! [`PROVISIONAL_RECORD_LEN`](crate::dm::provisional::PROVISIONAL_RECORD_LEN),
//! the *sealed* record's size.
//!
//! The two bindings are different facts and neither implies the other. The
//! record's own seal binds [`RecordContext`] — the correspondent's key-record
//! address and the first-contact epoch — which is what makes a record lifted from
//! another channel fail to open instead of resuming as the wrong correspondent.
//! The store's seal binds the [`CorrespondenceLabel`] and the record kind, which
//! is what stops a blob being moved between slots or between correspondences on
//! disk. The store cannot check the first: a label is an opaque 32 bytes whose
//! derivation is not decided (#288), so it is not the channel context and cannot
//! stand in for it. The record cannot check the second: it never learns which
//! slot it was written to.
//!
//! The cost is one extra AEAD pass over ~4.8 KiB per handshake write, which is
//! paid once per knock. Dropping either layer would drop a check nothing else
//! performs.
//!
//! ## What erasure means here
//!
//! [`PendingHandshake::establish`] deletes the provisional record, and
//! [`Locked::delete`](crate::storage::dm_store::Locked::delete) overwrites it in
//! place — two fsynced phases — before unlinking the name and fsyncing the
//! directory. So `ss0` is gone from the filesystem's view, from every subsequent
//! read, and from the blocks the filesystem believes it wrote. What it is **not**
//! gone from is the medium: the FTL and copy-on-write bound that
//! [`crate::dm::provisional`] records and the store repeats for every kind.
//!
//! The erase is not free of consequence. A crash inside it destroys a handshake
//! that a pre-scrub crash would have left resumable; [`PendingHandshake::establish`]
//! carries the argument for accepting that, and an interrupted erase is reported
//! as a lost record rather than an unreadable store.

use std::path::PathBuf;

use oxicrypt_aes::Aes256Key;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use zeroize::{Zeroize, Zeroizing};

use crate::dm::block_list::{BlockList, BlockListError};
use crate::dm::contact_cache::{ContactCacheError, ContactRecord};
use crate::dm::firstcontact::{
    ChannelRoots, FirstContactError, ROOT_LEN, VerifiedFirstContact, derive_channel_roots,
};
use crate::dm::outbox::{Outbox, OutboxError, TeardownOutcome};
use crate::dm::provisional::{
    ChannelRestart, ProvisionalError, ProvisionalRecord, ReceiveCursor, RecordContext, Teardown,
    derive_seal_key, restart,
};
use crate::dm::ratchet::{Direction, Ratchet, RatchetError};
use crate::dm::resume::{ReEstState, ResumeError, ResumeRecord, Retention, SendFloor};
use crate::storage::dm_store::{
    CorrespondenceLabel, DmStore, DmStoreError, OUTBOX_CAPACITY, RECEIVE_CURSOR_LEN, RecordKind,
};
use crate::storage::seeds::AEAD_KEY_LEN;

/// Why a persisted DM record could not be read or written.
///
/// Each variant keeps its source error whole rather than rendering it: a caller
/// deciding what to do about a failed write needs
/// [`AtomicReplaceError`](crate::storage::atomic_file::AtomicReplaceError)'s
/// distinction between "untouched" and "state unknown", and a flattened string
/// would not carry it.
#[derive(Debug)]
pub enum DmPersistError {
    /// The store could not read, write or delete.
    Store(DmStoreError),
    /// A provisional record could not be sealed or opened.
    Record(ProvisionalError),
    /// The outbox record could not be decoded, or a caller's own outbox call
    /// inside [`DmPersist::update_outbox`] failed.
    Outbox(OutboxError),
    /// A resume record would not encode, decode, or replace the stored one.
    Resume(ResumeError),
    /// The stored contact record would not decode, or a caller's own contact
    /// call inside [`DmPersist::update_contact`] failed.
    Contact(ContactCacheError),
    /// The stored block list would not decode, or the caller's own change to it
    /// pushed it past the ceiling.
    BlockList(BlockListError),
    /// The profile has no block-list record.
    ///
    /// **Not answered as an empty list, which is the whole point.**
    /// [`crate::storage::dm_store::DmStore::open`] creates the record on every
    /// open, so absence means it was removed after that — and the one thing a
    /// removal wants is for the next read to report that nobody is blocked.
    /// Every other record can be absent legitimately; this one cannot, so it is
    /// the one whose absence is an error.
    BlockListMissing,
    /// The record's ratchet could not be opened, so the channel did not
    /// establish. The provisional record is **still on disk**: see
    /// [`PendingHandshake::establish`] for why that is the safe direction.
    Ratchet(RatchetError),
    /// The stored outbox is for the other direction than the caller asked for.
    ///
    /// One correspondence has one outbox — this side's — so a caller naming the
    /// other direction has confused which end it is. Refused rather than
    /// silently answered with the record's own direction, which would let one
    /// direction's acknowledgement settle the other's messages.
    OutboxDirectionMismatch {
        stored: Direction,
        requested: Direction,
    },
    /// The persisted receive cursor names a page the caller's own reading does
    /// not support, or one past the last page that can hold a position.
    ///
    /// **The stored number is deliberately not carried.** The seal says who wrote
    /// the record, never that its number is right, and
    /// an error that handed it back would be a route by which a caller could
    /// corroborate the value against itself — the one thing
    /// [`ReceiveCursor::from_be_bytes`]'s `read_through` argument exists to
    /// prevent. The remedy needs no number: sweep from
    /// [`ReceiveCursor::START`].
    CursorNotCorroborated { read_through: u64 },
    /// The receive-cursor record opened and its payload is not
    /// [`RECEIVE_CURSOR_LEN`] bytes.
    ///
    /// **Reachable from a well-formed file, which is why it is its own error.**
    /// The store's fixed size is a property of the *file*; the payload inside the
    /// seal carries its own length prefix, so a record written with a shorter
    /// payload is a full-width, authentic file holding something this module
    /// cannot read as a page number. Reporting it as the store's
    /// [`DmStoreError::WrongFileLen`] would describe a 40-byte file as being
    /// however many bytes the payload is.
    ///
    /// The payload itself is not carried, for
    /// [`Self::CursorNotCorroborated`]'s reason: the remedy is to sweep from
    /// [`ReceiveCursor::START`] and needs no number.
    CursorPayloadWrongLen { expected: usize, actual: usize },
    /// More than one correspondence holds the long-term identity key
    /// [`DmPersist::correspondence_for_pk_lt`] was asked about, so it has no
    /// single answer.
    ///
    /// **Refused rather than resolved.** Nothing in the store forbids it: a
    /// label is minted per correspondence and a contact record's keys are
    /// write-once, so two first contacts with one identity — a racing pair, or a
    /// second correspondence deliberately established — leave two records
    /// holding one `pk_lt`. Answering with either of them would route a knock
    /// into one of two correspondences by whichever the scan reached first,
    /// which is a fact about nothing the caller can see. A `last_seen_ms`
    /// tiebreak would be worse: it invents a policy the protocol has not
    /// decided, and it decides it silently.
    ///
    /// **The labels are deliberately not carried, and the count is.** A label is
    /// the stable per-correspondence identifier whose [`core::fmt::Debug`] is
    /// redacted precisely so it does not reach a log through an error; the count
    /// is what says the store needs attention and reveals nothing the caller did
    /// not already supply.
    AmbiguousCorrespondent { matches: usize },
    /// A correspondence already holds this identity key, so a second
    /// establishment was refused.
    ///
    /// **The refusal is the point, and it is why this is not a warning.**
    /// Minting a second label for one identity makes that identity
    /// [`Self::AmbiguousCorrespondent`] on every later lookup, permanently, with
    /// nothing able to say which of the two is real. The duplicate is refused
    /// where it would be created rather than diagnosed afterwards, where nothing
    /// can resolve it.
    ///
    /// The label is deliberately absent, for [`Self::AmbiguousCorrespondent`]'s
    /// reason: it is redacted in `Debug` precisely so it does not reach a log
    /// through an error. A caller that needs it asks
    /// [`DmPersist::correspondence_for_pk_lt`], which is where the answer lives.
    AlreadyEstablished,
    /// The correspondence's contact record names a different identity than the
    /// caller's.
    ///
    /// Distinct from [`Self::AlreadyEstablished`], which is one identity in two
    /// places; this is two identities under one label. A label is either minted
    /// for a recipient or recovered from that recipient's own provisional
    /// record, so neither route produces it and a caller that reaches it has
    /// mixed up two correspondences. Refused rather than written through: the
    /// write would replace one correspondent's record with another's, and
    /// nothing afterwards could say what the first one held.
    CorrespondenceHoldsAnotherIdentity,
    /// A call that must find a contact record found none.
    ///
    /// Absence is ordinary for [`DmPersist::read_contact`] and is not ordinary
    /// here: this is raised only where the caller is filling in a field of a
    /// record it has already established exists, so it says the record was
    /// never written or has been removed underneath. Seeding one instead would
    /// mean inventing the identity key and address root a record must carry.
    ContactRecordMissing,
    /// A channel root could not be derived from a stored contact record.
    ///
    /// The store read fine; the crypto module or the KDF underneath it did not.
    /// Its own variant rather than folded into [`Self::Contact`], which means the
    /// bytes would not decode — a record that decoded and then failed to derive
    /// is a fault in this process, not in what is on disk, and the remedy
    /// differs.
    FirstContact(FirstContactError),
}

impl std::fmt::Display for DmPersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "dm store: {e}"),
            Self::Record(e) => write!(f, "provisional record: {e}"),
            Self::Outbox(e) => write!(f, "outbox: {e}"),
            Self::Resume(e) => write!(f, "resume record: {e}"),
            Self::Contact(e) => write!(f, "contact record: {e}"),
            Self::BlockList(e) => write!(f, "block list: {e}"),
            Self::BlockListMissing => f.write_str(
                "the profile's block-list record is missing; the store creates it at open and \
                 provision_block_list re-creates it, so its absence means it was removed or \
                 that open's best-effort creation was skipped",
            ),
            Self::Ratchet(e) => write!(f, "ratchet: {e}"),
            Self::OutboxDirectionMismatch { stored, requested } => write!(
                f,
                "the stored outbox is {} and {} was asked for",
                direction_label(*stored),
                direction_label(*requested)
            ),
            Self::CursorNotCorroborated { read_through } => write!(
                f,
                "the persisted receive cursor is past what has been read \
                 (through page {read_through}), so it cannot be believed"
            ),
            Self::CursorPayloadWrongLen { expected, actual } => write!(
                f,
                "the receive cursor's payload is {expected} bytes, this record \
                 opened to {actual}"
            ),
            Self::AmbiguousCorrespondent { matches } => write!(
                f,
                "{matches} correspondences hold the same long-term identity key, \
                 so there is no single correspondence for it"
            ),
            Self::AlreadyEstablished => f.write_str(
                "a correspondence already holds this identity key, so establishing a second \
                 one was refused",
            ),
            Self::CorrespondenceHoldsAnotherIdentity => {
                f.write_str("this correspondence's contact record names a different identity key")
            }
            Self::ContactRecordMissing => {
                f.write_str("this correspondence has no contact record to write into")
            }
            Self::FirstContact(e) => write!(f, "channel roots: {e}"),
        }
    }
}

impl std::error::Error for DmPersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            Self::Record(e) => Some(e),
            Self::Outbox(e) => Some(e),
            Self::Resume(e) => Some(e),
            Self::Contact(e) => Some(e),
            Self::BlockList(e) => Some(e),
            Self::Ratchet(e) => Some(e),
            Self::FirstContact(e) => Some(e),
            Self::BlockListMissing
            | Self::OutboxDirectionMismatch { .. }
            | Self::CursorNotCorroborated { .. }
            | Self::CursorPayloadWrongLen { .. }
            | Self::AmbiguousCorrespondent { .. }
            | Self::AlreadyEstablished
            | Self::CorrespondenceHoldsAnotherIdentity
            | Self::ContactRecordMissing => None,
        }
    }
}

impl DmPersistError {
    /// Whether this says a *record on disk* is unreadable, as opposed to the
    /// environment being unusable or the record being readable but unbelievable.
    ///
    /// **The caller this exists for is a repair.** A record that will not read
    /// cannot be written past either, so the only way out is to replace it — and
    /// the decision to overwrite must not be taken on an IO failure, which says
    /// nothing about the bytes, nor on
    /// [`Self::CursorNotCorroborated`], which is a record that read perfectly
    /// well and holds a number this session cannot vouch for. At a cold start
    /// every stored page above zero is uncorroborated, so treating that as a
    /// repair would rewrite a healthy cursor on every boot.
    ///
    /// Exhaustive, so a new variant has to be classified rather than defaulting
    /// into the repairing half.
    pub fn is_unreadable_record(&self) -> bool {
        match self {
            Self::Store(e) => is_unreadable_record(e),
            Self::CursorPayloadWrongLen { .. } => true,
            Self::Record(_)
            | Self::Outbox(_)
            | Self::Resume(_)
            | Self::Contact(_)
            | Self::BlockList(_)
            | Self::BlockListMissing
            | Self::Ratchet(_)
            | Self::OutboxDirectionMismatch { .. }
            | Self::CursorNotCorroborated { .. }
            | Self::AmbiguousCorrespondent { .. }
            | Self::AlreadyEstablished
            | Self::CorrespondenceHoldsAnotherIdentity
            | Self::ContactRecordMissing
            | Self::FirstContact(_) => false,
        }
    }

    /// Whether retrying the same call could ever answer differently.
    ///
    /// **The caller this exists for is a write that is retried on a timer.** A
    /// refusal that is a fact about bytes already on disk, or about a key that
    /// is already recorded, answers the same way on every later attempt — so a
    /// caller that keeps retrying it re-reads a sealed record for the life of
    /// the session and holds open whatever it was deferring until the write
    /// lands. A refusal from the environment says nothing about the request and
    /// is worth trying again.
    ///
    /// Every [`ContactCacheError`] is settled: each is a statement about a
    /// payload's shape, its timestamps, or a key already written down, and none
    /// of them changes because time passed. A store error is settled exactly
    /// when [`Self::is_unreadable_record`] says the bytes on disk are the
    /// problem, which is the same split that decides whether a record may be
    /// replaced.
    ///
    /// Exhaustive, so a new variant has to be classified rather than defaulting
    /// into the retrying half.
    pub fn retrying_cannot_help(&self) -> bool {
        match self {
            Self::Store(e) => is_unreadable_record(e),
            Self::CursorPayloadWrongLen { .. } => true,
            Self::Contact(_)
            | Self::ContactRecordMissing
            | Self::CorrespondenceHoldsAnotherIdentity
            | Self::AlreadyEstablished
            | Self::AmbiguousCorrespondent { .. }
            | Self::OutboxDirectionMismatch { .. } => true,
            Self::Record(_)
            | Self::Outbox(_)
            | Self::Resume(_)
            | Self::BlockList(_)
            | Self::BlockListMissing
            | Self::Ratchet(_)
            | Self::CursorNotCorroborated { .. }
            | Self::FirstContact(_) => false,
        }
    }
}

impl From<DmStoreError> for DmPersistError {
    fn from(e: DmStoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ProvisionalError> for DmPersistError {
    fn from(e: ProvisionalError) -> Self {
        Self::Record(e)
    }
}

impl From<ResumeError> for DmPersistError {
    fn from(e: ResumeError) -> Self {
        Self::Resume(e)
    }
}

impl From<ContactCacheError> for DmPersistError {
    fn from(e: ContactCacheError) -> Self {
        Self::Contact(e)
    }
}

impl From<BlockListError> for DmPersistError {
    fn from(e: BlockListError) -> Self {
        Self::BlockList(e)
    }
}

impl From<OutboxError> for DmPersistError {
    fn from(e: OutboxError) -> Self {
        Self::Outbox(e)
    }
}

impl From<RatchetError> for DmPersistError {
    fn from(e: RatchetError) -> Self {
        Self::Ratchet(e)
    }
}

impl From<FirstContactError> for DmPersistError {
    fn from(e: FirstContactError) -> Self {
        Self::FirstContact(e)
    }
}

/// The wire label for a direction, for rendering an error.
///
/// [`Direction::label`]'s bytes are frozen wire and already the single source of
/// them, so this reads them rather than writing the strings a second time; they
/// are ASCII by construction there.
fn direction_label(direction: Direction) -> String {
    String::from_utf8_lossy(direction.label()).into_owned()
}

/// Whether a mutator actually changed the record it was handed.
///
/// Returned by the closure [`DmPersist::update_outbox`] takes. The write it
/// guards is a *seal*, and seals draw from a birthday bound on a single key that
/// nothing counts (#289, #347) — so "did anything change" is the question that
/// decides whether a scarce resource is spent, and the caller is the only party
/// that can answer it.
///
/// **It is a return type rather than a convention because a convention is
/// exactly what fails silently here.** A caller that forgets to report cannot
/// compile. Both variants carry the closure's own value, so reporting costs the
/// caller nothing but the word.
///
/// `#[must_use]` covers the case the closure position does not: a helper
/// returning a `Mutation` whose result is discarded as a bare statement. In the
/// closure position itself the value is the return value, so it cannot be
/// dropped and still type-check — the attribute is not what makes reporting
/// mandatory there.
///
/// A report of `Unchanged` that is not true would discard the caller's mutation
/// silently. Debug builds check it; see [`DmPersist::update_outbox`].
#[must_use = "the record is written, and a seal spent, on the strength of this answer"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation<T> {
    /// The record was changed and must be written back.
    Changed(T),
    /// The record is exactly as it was found: no write, and so no seal.
    Unchanged(T),
}

/// The encoded size at which [`DmPersist::update_outbox`] starts calling
/// [`Outbox::prune`] (#323).
///
/// **Why there is a threshold at all rather than pruning on every call.**
/// Pruning is not free to the *product*: it discards the only record of which
/// terminal state a message reached, and nothing else retains that (see
/// [`DmPersist::update_outbox`]). Half of
/// [`OUTBOX_CAPACITY`] is about **32 700** lifetime messages on one
/// correspondence — a terminal `ChannelPage` entry costs 32 bytes, and about
/// 30 800 for a 34-byte `Doorbell` one — far beyond what an ordinary conversation
/// reaches, so under this mark nothing is ever discarded and the full delivery
/// history stays readable. (`Outbox::prune`'s own docs say "around 52 000" for
/// the whole 2 MiB bucket; that figure is priced from a 40-byte entry the format
/// no longer has, and the wall is nearer 65 500.) Above it the record is on its way to the wall the issue is about,
/// where the alternative to discarding history is a record that can no longer be
/// written at all and whose history is therefore unreadable anyway.
///
/// **Why half, and not nearer the wall.** What fills the bucket in ordinary use
/// is *owed* frames, which pruning cannot touch — the measured worst case is
/// around 106 of them. Leaving a whole capacity's worth of headroom means a
/// record that crosses this mark on terminal entries still has room for every
/// owed frame it can hold, so the prune is never racing the send path for the
/// same bytes.
pub(crate) const OUTBOX_PRUNE_THRESHOLD: usize = OUTBOX_CAPACITY / 2;

/// A profile's DM records on disk, and the keys they are written under.
///
/// Holds the store and the provisional record's seal key together because both
/// derive from the one `at_rest_key`: no call site passes a key, so no call site
/// can pass the store's key where the record's belongs or the other way round.
pub struct DmPersist {
    store: DmStore,
    /// [`crate::dm::provisional::derive_seal_key`]'s output — the *record's* key,
    /// which is not the store's. The store derives its own under its own label;
    /// deriving one key for both would let a provisional record and a store blob
    /// open as each other wherever their other inputs coincided.
    provisional_key: Aes256Key,
}

impl core::fmt::Debug for DmPersist {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Neither key is printed; the store's own `Debug` shows the root.
        f.debug_struct("DmPersist")
            .field("store", &self.store)
            .finish()
    }
}

impl DmPersist {
    /// Open the records at `root` under the profile's at-rest key.
    ///
    /// Both keys come from that one input, so the records are protected by the
    /// passphrase the profile already has and nothing here holds a secret with a
    /// lifetime of its own.
    pub fn open(
        root: impl Into<PathBuf>,
        at_rest_key: &[u8; AEAD_KEY_LEN],
    ) -> Result<Self, DmPersistError> {
        let store = DmStore::open(root, at_rest_key)?;
        let provisional_key = derive_seal_key(at_rest_key)?;
        Ok(Self {
            store,
            provisional_key,
        })
    }

    /// The store underneath, for enumeration and for the record kinds this
    /// module does not own.
    ///
    /// **A shared borrow of [`DmStore`] can write.**
    /// [`DmStore::critical_section`] takes `&self` and hands out a mutable
    /// guard, so this accessor reaches [`Locked::replace`](crate::storage::dm_store::Locked::replace) and therefore reaches
    /// [`RecordKind::Resume`] — around every guard
    /// [`Self::commit_resume`] applies.
    ///
    /// **Not closed at the store, deliberately.** [`Locked::replace`](crate::storage::dm_store::Locked::replace) is a
    /// kind-parametric byte primitive that cannot check a `ResumeRecord`
    /// invariant, and refusing one kind inside it would put a `dm::resume`
    /// rule in a module that knows nothing about the type — while the caller
    /// that wanted to write raw bytes would still reach
    /// [`DmStore::read_unlocked`] and the file itself. The guards' actual
    /// contract is narrower than it looks and is worth stating: they bound what
    /// *this module's* write path can do to a record, which is what makes
    /// `commit_resume` safe to call, not what any code in the process can do to
    /// the file.
    pub fn store(&self) -> &DmStore {
        &self.store
    }

    /// Write the provisional record for a knock that has been sent.
    ///
    /// Seals under `ctx` first — see the module docs on the two seals — and
    /// replaces whatever was in the slot. A knock is idempotent per
    /// (correspondent, epoch), so re-writing a record for the same context is a
    /// retry of one handshake rather than a second one.
    ///
    /// This *establishes* the correspondence on disk, which is correct here:
    /// there is a handshake in flight for it.
    pub fn save_provisional(
        &self,
        correspondence: &CorrespondenceLabel,
        ctx: &RecordContext<'_>,
        record: &ProvisionalRecord,
    ) -> Result<(), DmPersistError> {
        let sealed = record.seal(&self.provisional_key, ctx)?;
        self.store
            .critical_section(correspondence, |guard| -> Result<(), DmPersistError> {
                guard.replace(RecordKind::Provisional, &sealed)?;
                Ok(())
            })
    }
}

/// Whether a restart decision may also tidy the store on its way past.
///
/// A named pair rather than a `bool`, because the two call sites differ in what
/// the caller is *doing* — establishing this correspondence, or asking about it
/// — and a bare `true` at a call site says nothing about which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cleaning {
    /// Delete a lingering provisional record found beside a resume record. For a
    /// caller acting on this correspondence.
    Perform,
    /// Touch nothing. For a caller asking a question about a correspondence it
    /// may have no other business with.
    Skip,
}

impl DmPersist {
    /// Decide what a channel does at startup, from what its store holds (#243).
    ///
    /// The call site [`crate::dm::provisional::restart`] was written for. The
    /// three outcomes it distinguishes are preserved end to end: a record that
    /// opens resumes the handshake, a record that is absent or unusable tears the
    /// channel down loudly, and a store that could not be *read* tears it down
    /// without declaring anything lost.
    ///
    /// **The resume record is consulted first, and that is structural rather
    /// than advisory** (`docs/design/direct-messaging.md` § A4.8). A first
    /// establishment writes the resume record and then deletes the provisional
    /// one, so both records present is the crash window between those two
    /// writes; reading the provisional record first would answer
    /// [`StoredChannelRestart::HandshakeResumes`] and re-run first establishment
    /// on a channel that already has one. A lingering provisional record is
    /// therefore ignored, and deleted on the way past — the same erasure
    /// [`PendingHandshake::commit`] performs, and a failure to perform it here
    /// costs another pass rather than the answer.
    ///
    /// **A resume record that will not read tears the channel down as an
    /// unreadable store, never as an absent record.** Falling through to the
    /// provisional record would offer a destructive fresh first contact over
    /// what may be an `EIO`, so the fail-closed direction is the arm that
    /// declares nothing lost.
    ///
    /// ⚠️ **Two different faults collapse into that one arm, and the collapse is
    /// a real limitation rather than an equivalence.** A store fault is
    /// transient and `StoreUnreadable`'s contract — nothing lost, retry — fits
    /// it. A resume record whose *plaintext* will not decode is a permanent
    /// record-level fault, and reporting it the same way means every restart
    /// retries a record that will never read, with the user never told to
    /// re-establish. The honest arm would be
    /// [`TeardownCause::RecordUnusable`](crate::dm::provisional::TeardownCause::RecordUnusable),
    /// which carries a
    /// [`crate::dm::provisional::ProvisionalError`] and cannot
    /// carry a [`ResumeError`] — so the collapse is forced by that type, and
    /// splitting it needs a variant that does not exist.
    /// `a_resume_record_that_will_not_decode_tears_the_channel_down` pins what
    /// the collapse actually produces.
    ///
    /// **Reads without the lock, deliberately.** This is a question asked of
    /// every channel at startup, and entering a critical section to ask it would
    /// create a correspondence directory for each one — turning the directory
    /// listing, the one thing readable at rest without any key, from a list of
    /// established correspondences into a list of everything ever probed (#253).
    ///
    /// The resumption arm hands back a [`PendingHandshake`] rather than the
    /// record itself, which is what keeps establishment and erasure together;
    /// see that type.
    pub fn restart_channel(
        &self,
        correspondence: &CorrespondenceLabel,
        ctx: &RecordContext<'_>,
    ) -> StoredChannelRestart<'_> {
        self.restart_channel_with(correspondence, ctx, Cleaning::Perform)
    }

    /// The same question, asked of a correspondence the caller is **not** acting
    /// on, and answered without writing anything.
    ///
    /// **A lookup must not delete.** [`Self::restart_channel`] cleans a lingering
    /// provisional record on its way past, which is right for a caller that is
    /// about to establish or resume *this* correspondence and wrong for one
    /// walking the store asking "is this the one?". `DmMachine::provisional_label`
    /// is that caller: it scans every stored correspondence looking for the
    /// recipient's, so the cleaning version writes to every correspondence it
    /// walks past that holds a readable resume record — deleting a record
    /// belonging to a conversation the caller named nothing about.
    ///
    /// **Stated precisely, because the obvious stronger claim is false.** The
    /// scan matches only [`StoredChannelRestart::HandshakeResumes`], and a
    /// correspondence in the crash window answers
    /// [`StoredChannelRestart::Established`] — the resume record is read first —
    /// so it is skipped whether or not the cleaning runs. The deletion therefore
    /// does *not* cause a missed match or a wrongly minted label. What it does
    /// is write, unasked, to correspondences the caller is not acting on.
    ///
    /// It also takes **no lock at all**, where the cleaning version takes one per
    /// correspondence that has a resume record. Both reads here are unlocked, so
    /// a scan across the store costs nothing beyond the reads and creates no
    /// correspondence directory (#253).
    ///
    /// The cleaning is not skipped, only moved: it stays with the callers that
    /// know they are establishing, and [`Self::sweep_lingering_provisionals`] is
    /// what closes the crash window across the store. Without that sweep this
    /// method would trade a destructive lookup for an `ss0` that nothing ever
    /// scrubs, which is the worse of the two.
    ///
    /// ⚠️ **A peek still hands back a handle that can write.** The
    /// [`StoredChannelRestart::HandshakeResumes`] arm carries a
    /// [`PendingHandshake`], whose `establish` / `commit` endings write and
    /// erase. Nothing in the type prevents it; a caller that is only asking must
    /// drop it.
    pub fn peek_channel_restart(
        &self,
        correspondence: &CorrespondenceLabel,
        ctx: &RecordContext<'_>,
    ) -> StoredChannelRestart<'_> {
        self.restart_channel_with(correspondence, ctx, Cleaning::Skip)
    }

    /// Delete every provisional record left beside a readable resume record,
    /// across the whole store. Returns how many were deleted.
    ///
    /// **This is where the A4.8 crash window is actually closed.** A crash
    /// between `commit_resume` and its best-effort erase leaves a provisional
    /// record holding `ss0` — which roots `RK0`, and so every message key the
    /// ratchet believes it deleted — beside the resume record that supersedes
    /// it. [`Self::restart_channel`] cleans one such record when a caller
    /// happens to ask about that correspondence, and no caller asks about a
    /// correspondence it is not already acting on, so on its own it leaves the
    /// record for as long as nothing touches that conversation.
    ///
    /// A sweep is the right shape and a lookup is not: this is called by
    /// something rebuilding *every* correspondence, so deleting a record for
    /// each is the job rather than a side effect. It is also the reason
    /// [`Self::peek_channel_restart`] can decline to clean without losing
    /// anything.
    ///
    /// **Best-effort per correspondence, and deliberately so.** A store that
    /// will not enumerate returns the error, because then nothing was swept and
    /// the caller should know; a single correspondence that will not read is
    /// skipped and counted out, because one unreadable record must not stop the
    /// others being scrubbed.
    pub fn sweep_lingering_provisionals(&self) -> Result<usize, DmPersistError> {
        let mut cleaned = 0;
        for correspondence in self.store.correspondences()? {
            let Ok(Some(bytes)) = self
                .store
                .read_unlocked(&correspondence, RecordKind::Resume)
            else {
                continue;
            };
            if ResumeRecord::decode(&Zeroizing::new(bytes)).is_err() {
                continue;
            }
            // Under the lock, and re-reading inside it: the record may have been
            // deleted between the read above and here, which `clean_lingering_provisional`
            // already treats as nothing to do.
            let before = self
                .store
                .read_unlocked(&correspondence, RecordKind::Provisional);
            self.clean_lingering_provisional(&correspondence);
            if matches!(before, Ok(Some(_))) {
                cleaned += 1;
            }
        }
        Ok(cleaned)
    }

    /// One body for both, so the two can never answer the same question
    /// differently. Only the cleaning differs.
    fn restart_channel_with(
        &self,
        correspondence: &CorrespondenceLabel,
        ctx: &RecordContext<'_>,
        cleaning: Cleaning,
    ) -> StoredChannelRestart<'_> {
        // A4.8's read order. Unlocked like the read below it and for the same
        // reason: asking every channel this question under the lock would create
        // a correspondence directory per channel (#253).
        match self.store.read_unlocked(correspondence, RecordKind::Resume) {
            Ok(Some(bytes)) => {
                // `Zeroizing`: this plaintext holds a signing key, as
                // `read_resume` notes at the same decode.
                return match ResumeRecord::decode(&Zeroizing::new(bytes)) {
                    Ok(record) => {
                        match cleaning {
                            Cleaning::Perform => self.clean_lingering_provisional(correspondence),
                            Cleaning::Skip => {}
                        }
                        StoredChannelRestart::Established(Box::new(record))
                    }
                    Err(e) => self.decide(correspondence, self.unreadable(&e, ctx)),
                };
            }
            Ok(None) => {}
            Err(e) => return self.decide(correspondence, self.unreadable(&e, ctx)),
        }
        // An interrupted erase is a record the store **lost**, not a store it
        // could not read, and the difference is load-bearing rather than
        // cosmetic. `StoreUnreadable`'s whole contract is that "nothing is
        // declared lost and nothing is asked of the user", and it makes the
        // outbox retain what it has queued — correct for an `EIO` over a record
        // still sitting on disk, wrong here, where the payload is destroyed and
        // is not coming back. Reporting it that way would leave the caller
        // waiting on a handshake that no longer exists.
        //
        // `NoProvisionalRecord` already documents itself as covering "a record
        // the store lost", where the remedy is to start the conversation again —
        // which is exactly the remedy here. See `PendingHandshake::establish` for
        // why this window exists at all and why it was accepted.
        let read = match self
            .store
            .read_unlocked(correspondence, RecordKind::Provisional)
        {
            Err(DmStoreError::ErasureInterrupted { .. }) => Ok(None),
            other => other,
        };
        // Borrowed rather than moved so the store's error survives as itself:
        // `restart` needs only `Display`, and lowering the error to `None` here
        // is precisely the collapse its `Result` argument exists to refuse.
        let borrowed = match &read {
            Ok(bytes) => Ok(bytes.as_deref()),
            Err(e) => Err(e),
        };
        self.decide(
            correspondence,
            restart(borrowed, &self.provisional_key, ctx),
        )
    }

    /// Carry [`crate::dm::provisional::restart`]'s decision into this module's
    /// enum, attaching the store to the resumption arm.
    ///
    /// One place, so the two call sites cannot answer the same decision
    /// differently.
    fn decide(
        &self,
        correspondence: &CorrespondenceLabel,
        decision: ChannelRestart,
    ) -> StoredChannelRestart<'_> {
        match decision {
            ChannelRestart::HandshakeResumes(record) => {
                StoredChannelRestart::HandshakeResumes(PendingHandshake {
                    persist: self,
                    correspondence: *correspondence,
                    record,
                })
            }
            ChannelRestart::TornDown(teardown) => StoredChannelRestart::TornDown(teardown),
        }
    }

    /// The teardown for a resume record that could not be read.
    ///
    /// Routed through [`crate::dm::provisional::restart`] rather than built
    /// here, because [`Teardown`] is constructible only by that call — which is
    /// what makes holding one proof the decision was taken. The argument is
    /// `Err`, so the answer is always `StoreUnreadable` carrying `e`'s rendering
    /// and the key is never consulted.
    fn unreadable<E: std::fmt::Display>(&self, e: &E, ctx: &RecordContext<'_>) -> ChannelRestart {
        restart(Err::<Option<&[u8]>, &E>(e), &self.provisional_key, ctx)
    }

    /// Delete a provisional record left beside a resume record, and say nothing
    /// if it will not go.
    ///
    /// The lingering record is A4.8's create-first crash window. It is already
    /// ignored by the time this runs — the caller has the resume record and is
    /// answering [`StoredChannelRestart::Established`] — so the delete is the
    /// erasure of a superseded `ss0` rather than a step the answer depends on,
    /// and a store that refuses it is asked again at the next restart.
    ///
    /// **The look and the delete are one critical section**, which is not
    /// tidiness: deciding from [`DmStore::read_unlocked`] and then deleting
    /// through a second call is the read-decide-write split that read's own
    /// documentation refuses, and a writer landing a *fresh* provisional record
    /// in the gap would have that one deleted instead of the stale one. The lock
    /// creates a correspondence directory where none existed (#253), which is
    /// harmless here and only here: the caller reached this holding a decoded
    /// resume record, so the directory is already on disk.
    fn clean_lingering_provisional(&self, correspondence: &CorrespondenceLabel) {
        let _ =
            self.store
                .critical_section(correspondence, |guard| -> Result<(), DmPersistError> {
                    if guard.read(RecordKind::Provisional)?.is_some() {
                        guard.delete(RecordKind::Provisional)?;
                    }
                    Ok(())
                });
    }

    /// Read the outbox **to look at it**, without the lock.
    ///
    /// `Ok(None)` means this correspondence has no outbox record — a
    /// correspondence that has never queued anything — and creates nothing on the
    /// way past.
    ///
    /// **Anything that decides from what this returns and then writes must use
    /// [`Self::update_outbox`] instead.** Two calls in a row can straddle a
    /// writer, so a read here followed by a write elsewhere loses whatever
    /// another process decided in between: the silent send loss the store's lock
    /// exists to prevent, arriving through the layer above it. This is for
    /// drawing the outbox, not for driving it.
    ///
    /// `now_ms` is the caller's own clock, and an entry claiming to have been
    /// composed after it is refused rather than rewritten — see
    /// [`Outbox::decode`].
    pub fn read_outbox(
        &self,
        correspondence: &CorrespondenceLabel,
        now_ms: i64,
    ) -> Result<Option<Outbox>, DmPersistError> {
        match self
            .store
            .read_unlocked(correspondence, RecordKind::Outbox)?
        {
            Some(bytes) => Ok(Some(Outbox::decode(&bytes, now_ms)?)),
            None => Ok(None),
        }
    }

    /// Load the outbox, let `f` change it, and write it back — all under one
    /// lock.
    ///
    /// **`f` reports whether it mutated, and a report of
    /// [`Mutation::Unchanged`] costs no seal** (#347).
    ///
    /// The closure is the point, for [`DmStore::critical_section`]'s reason: a
    /// sweep, an acknowledgement merge or an enqueue reads the record, decides
    /// from it, and writes the result, and those three steps have to be one
    /// critical section or two processes silently lose one of the two decisions.
    ///
    /// `direction` seeds a **new** outbox when the correspondence has none. If a
    /// record exists and names the other direction the call is refused
    /// ([`DmPersistError::OutboxDirectionMismatch`]) rather than answered with
    /// the record's own direction: one correspondence has one outbox, so a
    /// caller naming the other end is confused about which side it is, and
    /// quietly correcting it would hide that.
    ///
    /// **Nothing is written if `f` fails.** The record is replaced only after
    /// `f` returns `Ok`, so a failed call leaves the correspondence exactly as it
    /// was and the caller may retry.
    ///
    /// **A successful call writes when `f` says it changed something — or when
    /// the prune below reclaimed entries.** The second clause is the whole of the
    /// exception and it is stated here rather than only where it is implemented,
    /// because anyone sizing the #289 seal budget reads this paragraph: an
    /// over-threshold record whose closure reports `Unchanged` still spends one
    /// seal if terminal entries were reclaimed, once per backlog rather than once
    /// per tick. Everything below is otherwise unaffected. An
    /// earlier version of this method always wrote, and said so: *"one redundant
    /// write against having to trust every caller to report whether it
    /// mutated"*. That trade was made without knowing the price. #289 measured
    /// it: the write is a *seal*, seals draw from a 2^32 birthday bound on one
    /// key, and a sweep spends one per correspondence per tick whether or not
    /// anything happened — five hundred correspondences on a sixty-second tick
    /// reach 61% of the bound in ten years having sent nothing at all. That made
    /// the polling cadence a cryptographic parameter disguised as a latency
    /// knob. Reporting decouples the two: a no-op tick is free, so the cadence
    /// can be chosen on responsiveness alone.
    ///
    /// The trust the old comment declined to extend is now structural rather
    /// than conventional — [`Mutation`] is the closure's return type, so a
    /// caller cannot fail to answer, and `#[must_use]` catches building the
    /// answer and dropping it.
    ///
    /// **A record that does not exist yet is created only if `f` changes it, and
    /// the prune does not weaken this.** A fresh correspondence has nothing to
    /// reclaim, so its `encoded_len` is a bare header, the threshold is not met
    /// and `pruned` is zero: `Unchanged` on a fresh correspondence writes no
    /// outbox record and spends no seal — an empty record stores no fact worth one, and
    /// [`Self::read_outbox`] already distinguishes "nothing queued" from "never
    /// queued anything".
    ///
    /// **It is not true that such a call creates nothing**, and the difference
    /// matters to anyone testing for absence: taking the lock precedes the
    /// closure, so [`DmStore::critical_section`] has already made the
    /// correspondence's directory and its lock file by the time `f` runs. What
    /// is absent afterwards is the record and the seal, not the directory.
    ///
    /// One consequence is deliberate and worth naming: the direction guard
    /// above engages only once something has actually been queued, because
    /// until then there is no stored direction for a later caller to
    /// contradict. `a_no_op_does_not_pin_the_direction` pins that, so a change
    /// that quietly restores the old materialising behaviour fails a test
    /// rather than passing one.
    ///
    /// **`Unchanged` is a promise the caller can break, and in debug builds it
    /// is checked.** A closure that mutates and then reports `Unchanged` would
    /// discard the mutation silently — no error, no seal, no warning — which is
    /// the one failure this type cannot prevent by construction, because
    /// `#[must_use]` catches a dropped answer and not a wrong one. Under
    /// `debug_assertions` the record is re-encoded and compared, so a lying
    /// closure fails loudly wherever tests run. **Release builds take the caller
    /// at its word, and since the prune the consequence of a lie is no longer
    /// uniform:** a mutation reported as `Unchanged` is discarded when nothing was
    /// pruned and *persisted* when something was, so the same lying closure has
    /// opposite on-disk outcomes decided only by the record's size. Neither is
    /// data loss and both are caught in debug; it is stated because the old text
    /// implied one outcome. The check costs a second [`Outbox::encode`] per call
    /// in debug builds, and a third on the `Changed` path and on the pruning
    /// `Unchanged` path alike; `RecordKind::Outbox`
    /// caps at 2 MiB, so a debug-build sweep over a large outbox pays for that
    /// repeatedly. It is deliberate — this is the method whose callers are
    /// hardest to audit — but it is not free.
    ///
    /// **Migration rides a changing record, not a poll.** [`Outbox::encode`]
    /// always writes the current magic and write suite, so under the old
    /// unconditional write *any* tick re-encoded a stale record and carried it
    /// forward (the read-old-write-new half of ISC-C24). Now only a mutating
    /// tick does, and a correspondence whose outbox never changes keeps the
    /// magic and suite it was stored under indefinitely. That is safe while
    /// [`Outbox::decode`] still accepts them and becomes data loss when one is
    /// retired, as `OUTBOX_MAGIC_V1` already has been — the record would decode
    /// no longer and its entries would be unreachable through this method.
    /// Whatever retires a version owes an explicit migration pass; it can no
    /// longer assume the sweep performed one.
    ///
    /// # This call prunes, and three things follow for anyone above it (#323)
    ///
    /// Once the record reaches half of [`OUTBOX_CAPACITY`] — the crate-private
    /// `OUTBOX_PRUNE_THRESHOLD`, de-linked because this doc is public and that
    /// constant is not — this method calls
    /// [`Outbox::prune`] before running `f`, dropping every entry that is
    /// terminal and already surfaced. Without it the record grows with *lifetime*
    /// messages rather than owed ones and dies for good at
    /// [`OUTBOX_CAPACITY`]; past that wall every write here fails, so no
    /// enqueue, no sweep and no settle ever succeeds again on that
    /// correspondence. The reclaim happens ahead of `f` so that an enqueue's
    /// capacity gate sees the freed bytes.
    ///
    /// **1. Delivery history above the threshold is gone, and the acknowledgement
    /// cannot stand in for it.** After a prune [`Outbox::entry`] answers `None`,
    /// and [`Outbox::pruned_high_water`] records only *that* a sequence is gone,
    /// never which terminal state it reached. The obvious substitute is wrong in
    /// the dangerous direction:
    /// [`AckState::is_settled`](crate::dm::ack::AckState::is_settled) reports
    /// `true` for a sequence this sender **gave up on**, because a receiver's
    /// contiguous prefix advances past a permanently lost message — so a surface
    /// that fell back to the ack would show *delivered* for a message nobody
    /// read. Nothing else retains the distinction. What the prune does not
    /// endanger is the [#279] obligation: an entry is only ever taken once its
    /// [`Surfacing`](crate::dm::outbox::Surfacing) is `Clear`, meaning the
    /// outcome already reached the user. A surface that must *re-render* an old
    /// outcome needs its own message log; this record is a delivery queue with a
    /// bounded retention, not the history.
    ///
    /// **2. Sequence allocation must be monotonic, and pruning is a second place
    /// that now depends on it.** The invariant is not new — a direction's
    /// sequence space is one monotonic counter per conversation, and the
    /// acknowledgement is a contiguous prefix plus ascending runs, so a
    /// gap-filling allocator was already unrepresentable. Pruning makes it bite
    /// sooner: settling and pruning a high sequence while a lower one is still
    /// owed raises the high-water past the unused sequences beneath it, and both
    /// enqueue doors refuse those for ever. Entries still present below the
    /// mark stay fully reachable; it is the *unused* numbers that are burnt.
    ///
    /// **3. A ceiling must not come from the surviving entries.** Pruning
    /// regresses the maximum sequence the map holds, permanently and without a
    /// restart. Anything needing "the highest sequence we have sent" — above all
    /// [`AckState::merge_peer_ack`](crate::dm::ack::AckState::merge_peer_ack),
    /// whose ceiling clips a peer's claim — must take the greater of that maximum
    /// and [`Outbox::pruned_high_water`], never the maximum alone, or it will
    /// clip a truthful acknowledgement and report delivered messages as
    /// undelivered.
    ///
    /// **The seal cost of the trigger.** A prune that finds nothing costs
    /// nothing: `Unchanged` still writes nothing, so a no-op tick on an
    /// over-threshold record stays free and #289's argument is untouched. A prune
    /// that *does* free entries under an `Unchanged` closure spends one seal, and
    /// only until the backlog is cleared — the cost tracks message volume, which
    /// the budget already scales with, rather than polling cadence, which it does
    /// not. Under a `Changed` closure the prune rides a write that was happening
    /// anyway and costs nothing at all. Below the threshold not even the scan
    /// runs.
    ///
    /// [#279]: https://github.com/caraka/daemonseed/issues/279
    pub fn update_outbox<T>(
        &self,
        correspondence: &CorrespondenceLabel,
        direction: Direction,
        now_ms: i64,
        f: impl FnOnce(&mut Outbox) -> Result<Mutation<T>, DmPersistError>,
    ) -> Result<T, DmPersistError> {
        self.store
            .critical_section(correspondence, |guard| -> Result<T, DmPersistError> {
                let mut outbox = match guard.read(RecordKind::Outbox)? {
                    Some(bytes) => {
                        let stored = Outbox::decode(&bytes, now_ms)?;
                        if stored.direction() != direction {
                            return Err(DmPersistError::OutboxDirectionMismatch {
                                stored: stored.direction(),
                                requested: direction,
                            });
                        }
                        stored
                    }
                    None => Outbox::new(direction),
                };
                // Reclaim *before* the closure, not after (#323).
                // `Outbox::insert`'s capacity gate prices a candidate against
                // `Outbox::encoded_len`, so bytes freed after the closure has run
                // are bytes the enqueue the closure just attempted was already
                // refused for. A prune that happens after the decision it exists
                // to inform rescues the write and abandons the send.
                //
                // A failing closure discards the prune with everything else, so
                // "nothing is written if `f` fails" is unaffected: the reclaim is
                // in memory until one of the two arms below writes it.
                let pruned = if outbox.encoded_len() >= OUTBOX_PRUNE_THRESHOLD {
                    outbox.prune()
                } else {
                    0
                };
                // Debug builds hold the before-image so an `Unchanged` report
                // that is not true fails here rather than silently discarding
                // the caller's mutation. Taken *after* the prune deliberately, so
                // the check still measures the closure alone — a before-image
                // taken earlier would differ by the prune on every pruning call
                // and the check would have to be skipped exactly where the
                // closure is hardest to audit. Release builds take the report at
                // its word; see this method's docs.
                #[cfg(debug_assertions)]
                let before = outbox.encode();
                match f(&mut outbox)? {
                    Mutation::Changed(out) => {
                        guard.replace(RecordKind::Outbox, &outbox.encode())?;
                        Ok(out)
                    }
                    Mutation::Unchanged(out) => {
                        // `#[cfg]`, not `debug_assert_eq!`: that macro's body is
                        // type-checked in every profile, so it would demand
                        // `before` in release builds where the capture above does
                        // not exist. The attribute removes the statement outright.
                        #[cfg(debug_assertions)]
                        assert_eq!(
                            before,
                            outbox.encode(),
                            "an update reported Mutation::Unchanged after changing the outbox; \
                             the change would have been discarded without a trace"
                        );
                        // The closure changed nothing, but the prune above did.
                        // Dropping it here would not corrupt anything — the
                        // stored record is simply left as it was found — but the
                        // scan would be repeated on every call for ever and the
                        // record would never actually shrink.
                        if pruned > 0 {
                            guard.replace(RecordKind::Outbox, &outbox.encode())?;
                        }
                        Ok(out)
                    }
                }
            })
    }

    /// Commit a re-establishment resume record and hand back the sealed RE-EST
    /// bytes to emit (A9.2).
    ///
    /// **`Ok(None)` where the record's handshake slot is empty**, which is the
    /// state a record written at first establishment is in: there is a record
    /// and there is nothing to emit. The two anti-rollback guards below read the
    /// empty slot as ordering beneath every attempt, so a first establishment is
    /// replaceable by the first real re-establishment and never the reverse.
    ///
    /// **The whole record replaces the stored one in a single
    /// `replace_atomically`**, so no crash can pair a committed root with a
    /// stale attempt. There is no call here that writes part of a record.
    ///
    /// **Returning the sealed bytes is ergonomics, not proof, and an earlier
    /// version of this comment overclaimed it.** It said the ordering was "a
    /// property of the signature" because the frame was unreachable without a
    /// completed write. That is false: the caller built the record and therefore
    /// already holds those bytes, and
    /// [`ResumeRecord::sealed_re_est`](crate::dm::resume::ResumeRecord::sealed_re_est)
    /// is public on an unpersisted record — emit-then-crash-before-commit is
    /// perfectly spellable. It cannot be made structural at this layer, because
    /// the bytes originate above it. What this shape does buy is that the
    /// *convenient* path is the correct one.
    ///
    /// **An attempt may not be re-sealed, and may not regress.** A9.1 makes a
    /// re-emit of a persisted attempt the byte-identical persisted seal, and the
    /// peer dedups on `attempt` (A9.4) — so committing different sealed bytes
    /// under an attempt the peer has already seen leaves this party holding a
    /// secret the peer will never confirm, the permanent `UnknownEphemeral`
    /// divergence. This is the only layer that can see both the offered record
    /// and the stored one, so it is the only place the invariant can be
    /// enforced **against what is on disk**.
    ///
    /// **These guards are not superseded by
    /// [`SealedReEst`](crate::dm::resume::SealedReEst), and the division is worth
    /// stating.** That type stops `SealedReEst::seal` being *called* with an
    /// attempt already in hand, which removes the caller's mistake at compile
    /// time. It does no more than that: it cannot know what another process, or
    /// this one before a restart, already persisted — a `FreshAttempt` minted
    /// from a stale in-memory attempt is perfectly well-typed and perfectly
    /// wrong — and it does not constrain `ResumeRecord::decode`, which rebuilds
    /// the pairing from at-rest bytes with no token at all. So the type closes
    /// one spelling and this call closes the invariant; neither is redundant and
    /// removing either reopens a real path.
    ///
    /// **A stored record that will not decode wedges this call** — every future
    /// commit for that correspondence fails rather than overwriting it. That is
    /// deliberate and it is the fail-closed direction: the stored record holds
    /// the anti-rollback bounds, and silently replacing an unreadable one
    /// discards them. It is the same trade
    /// [`Outbox::decode`](crate::dm::outbox::Outbox::decode) makes in refusing
    /// rather than repairing, and the same disposition question `Locked::delete`
    /// carries.
    ///
    /// **The send-side floor may not regress.** A stored record whose floor is
    /// ahead of the offered one is [`ResumeError::FloorWouldRollBack`], refused
    /// rather than overwritten: the floor is the anti-rollback bound for this
    /// party's own sequence numbers, and a write that moved it backwards would
    /// re-authorise sequences already spent. An *unmoved* floor is admitted —
    /// see [`SendFloor::admits`](crate::dm::resume::SendFloor::admits) for why
    /// the guard here is weaker than advancing the floor itself.
    pub fn commit_resume(
        &self,
        correspondence: &CorrespondenceLabel,
        record: &ResumeRecord,
    ) -> Result<Option<Vec<u8>>, DmPersistError> {
        let encoded = record.encode();
        self.store.critical_section(
            correspondence,
            |guard| -> Result<Option<Vec<u8>>, DmPersistError> {
                if let Some(bytes) = guard.read(RecordKind::Resume)? {
                    let stored = ResumeRecord::decode(&Zeroizing::new(bytes))?;
                    Self::guard_attempt_counter(record, &stored)?;
                    Self::guard_own_slot(record, &stored)?;
                    // **The pseudonym pair may not change, whatever the slot
                    // holds.** Without this, two records whose handshake slots
                    // are both empty are indistinguishable to every guard above:
                    // the attempts compare equal, so the sealed-bytes comparison
                    // that discriminates same-attempt records never runs, and an
                    // unmoved floor is admitted. A second first-establishment
                    // write would replace `s_pc` and `pk_pc` and report success,
                    // leaving this side signing under a key the correspondent
                    // never saw and rejecting every frame the correspondent
                    // sends — on disk, unspeakable, with nothing reported. The
                    // occupied slot is covered by the sealed-bytes comparison;
                    // this covers both.
                    //
                    // A plain comparison rather than a constant-time one: both
                    // sides are this party's own material and the caller already
                    // holds the offered copy, so there is no secret here that the
                    // comparison could leak to whoever can call this.
                    if record.s_pc() != stored.s_pc() || record.pk_pc() != stored.pk_pc() {
                        return Err(ResumeError::PseudonymPairChanged.into());
                    }
                    Self::guard_reconnect_gen(record, &stored)?;
                    Self::guard_acceptance(record, &stored)?;
                    Self::guard_confirm_slot(record, &stored)?;
                    Self::guard_retention(record, &stored)?;
                    if !stored.send_floor().admits(record.send_floor()) {
                        return Err(ResumeError::FloorWouldRollBack {
                            stored: stored.send_floor(),
                            offered: record.send_floor(),
                        }
                        .into());
                    }
                }
                guard.replace(RecordKind::Resume, &encoded)?;
                Ok(record.sealed_re_est().map(<[u8]>::to_vec))
            },
        )
    }

    /// A5.2's attempt counter is monotone for the correspondence's whole
    /// lifetime, so it never returns to an earlier value and never returns to
    /// none.
    ///
    /// **It is compared against the record's `attempt` field, not against the
    /// own slot's copy.** A3.14 zeroes the slot on completion, so a comparison
    /// reading the slot would see `None` after every completed handshake and
    /// then admit a fresh attempt `1` — the counter would restart, and the
    /// guard would stop firing across exactly the boundary it exists to hold.
    /// A9.2 lists the counter and the sealed frame bytes as separate fields for
    /// this reason.
    ///
    /// The **reseal** half stays on the slot, because that is where the bytes
    /// are: one attempt may not be sealed twice under different bytes (A9.1).
    fn guard_attempt_counter(
        record: &ResumeRecord,
        stored: &ResumeRecord,
    ) -> Result<(), DmPersistError> {
        let offered = record.attempt().map_or(0, |a| a.get());
        let held = stored.attempt().map_or(0, |a| a.get());
        if offered == 0 && held > 0 {
            // Reported apart from the ordinary rollback because no `Attempt` is
            // ever `0`: a message naming `offered: 0` would name a value that
            // cannot exist. This is a first establishment arriving over a
            // re-establishment.
            return Err(ResumeError::EmptySlotWouldReplaceAttempt { stored: held }.into());
        }
        if offered < held {
            return Err(ResumeError::AttemptWouldRollBack {
                stored: held,
                offered,
            }
            .into());
        }
        // The slot's copy of the number is bound to the bytes a re-emit sends,
        // so a record whose slot disagrees with its counter would re-emit under
        // a key neither number names. `decode` refuses the same pairing; this
        // stops one reaching disk in the first place.
        if let Some(slot) = record.own_slot()
            && slot.attempt().get() != offered
        {
            return Err(ResumeError::AttemptSlotDisagrees {
                field: offered,
                slot: slot.attempt().get(),
            }
            .into());
        }
        if let (Some(offered_slot), Some(held_slot)) = (record.own_slot(), stored.own_slot())
            && offered_slot.attempt() == held_slot.attempt()
            && offered_slot.sealed().bytes() != held_slot.sealed().bytes()
        {
            return Err(ResumeError::AttemptResealed {
                attempt: held_slot.attempt().get(),
            }
            .into());
        }
        Ok(())
    }

    /// An occupied own slot is emptied by exactly two acts, and this refuses
    /// every other way of arriving at an empty one.
    ///
    /// **A3.7's abandonment is one write at an unchanged generation.** The coin's
    /// loser *"abandons its own handshake and answers the winner's frame as an
    /// ordinary responder — abandonment and acceptance committed together,
    /// intra-record"*. The generation does not move: A3.4 advances it only by a
    /// *completed* handshake, which is two legs later. So the abandonment is
    /// recognised by what replaces the initiation — an acceptance slot newly
    /// occupying the generation the abandoned initiation was contesting.
    ///
    /// **A3.14's completion is the other act**, and it does advance the
    /// generation: a folded `RE-ACK` ends the exchange, A3.4 advances
    /// `reconnect_gen`, and the slot is zeroed in the same write.
    ///
    /// **A3.8's give-up is the third act, and the record has to be able to
    /// reach it.** A handshake leg *"reached its give-up"* is one of A3.8's loud
    /// states and A3.13 forbids a terminal one, so an initiation that will never
    /// complete must be releasable with no contest and no completion —
    /// [`ResumeRecord::abandon_attempt`] is that release. It is admitted here by
    /// the attempt counter standing still: A5.2 keeps the counter monotone for
    /// the correspondence's lifetime, so a record that empties the slot while
    /// still naming the abandoned attempt has given the number up rather than
    /// forgotten it, and the next [`ResumeRecord::open_attempt`] mints its
    /// successor.
    ///
    /// **What that trades is stated rather than glossed.** This guard can no
    /// longer tell a deliberate give-up from a caller that dropped the slot by
    /// accident, because the two produce identical bytes. What the counter buys
    /// instead is the property the guard existed for: no later attempt can reuse
    /// the abandoned number, so nothing seals a second frame under a key the
    /// peer has already answered.
    ///
    /// What stays refused is an initiation that disappears while the counter
    /// moves with it — a slot emptied by a write that also minted a fresh
    /// attempt, which is a re-establishment this side would go on believing it
    /// had in flight.
    fn guard_own_slot(record: &ResumeRecord, stored: &ResumeRecord) -> Result<(), DmPersistError> {
        let (Some(held), None) = (stored.own_slot(), record.own_slot()) else {
            return Ok(());
        };
        if record.reconnect_gen() > stored.reconnect_gen() {
            return Ok(());
        }
        if record.attempt() == stored.attempt() {
            return Ok(());
        }
        let contested = record.acceptance().is_some_and(|offered| {
            offered.generation() == held.generation()
                && stored.acceptance().map(|s| (s.generation(), s.attempt()))
                    != Some((offered.generation(), offered.attempt()))
        });
        if contested {
            return Ok(());
        }
        Err(ResumeError::OwnSlotAbandonedWithoutAcceptance {
            attempt: held.attempt().get(),
        }
        .into())
    }

    /// A3.4's generation is strictly monotonic — it *"advances only by a
    /// completed handshake"* — so a record offering an earlier one describes a
    /// state this correspondence has already left.
    ///
    /// It is checked before the acceptance and retention guards because both of
    /// them read the generation to decide what a legitimate write looks like: a
    /// generation advance is what licenses clearing a confirmed acceptance and
    /// what licenses retaining a fresh `RS_n`, so a generation that could go
    /// backwards would license either of those by going backwards first.
    fn guard_reconnect_gen(
        record: &ResumeRecord,
        stored: &ResumeRecord,
    ) -> Result<(), DmPersistError> {
        if record.reconnect_gen() < stored.reconnect_gen() {
            return Err(ResumeError::ReconnectGenWouldRollBack {
                stored: stored.reconnect_gen(),
                offered: record.reconnect_gen(),
            }
            .into());
        }
        Ok(())
    }

    /// The peer-acceptance slot's three guards, the mirror of what the own slot
    /// already had.
    ///
    /// **No rollback within a generation.** A5.1(i) admits a *higher* attempt
    /// superseding an unconfirmed candidate and A3.4 drops a lower one, so a
    /// stored acceptance never moves backwards — not in its generation, and not
    /// in its attempt at one generation.
    ///
    /// **No reseal of an accepted attempt.** A3.4 re-serves *the stored*
    /// `RE-ACK`, byte-identical, and those bytes are the only copy: the leg
    /// carries a randomized ML-KEM ciphertext. Replacing them under one accepted
    /// pair would answer one question twice, and the peer — deduping on the
    /// attempt (A9.4) — confirms the first, leaving the two sides on different
    /// siblings.
    ///
    /// **No clearing a confirmed slot without a generation advance.** A5.1(ii)
    /// locks a confirmed candidate. The lock is durable so it survives a
    /// restart, and the one write that legitimately ends it is the advance that
    /// retires the whole exchange.
    fn guard_acceptance(
        record: &ResumeRecord,
        stored: &ResumeRecord,
    ) -> Result<(), DmPersistError> {
        let Some(held) = stored.acceptance() else {
            return Ok(());
        };
        let advanced = record.reconnect_gen() > stored.reconnect_gen();
        match record.acceptance() {
            Some(offered) => {
                if (offered.generation(), offered.attempt()) < (held.generation(), held.attempt()) {
                    return Err(ResumeError::AcceptanceWouldRollBack {
                        stored_generation: held.generation(),
                        stored_attempt: held.attempt().get(),
                        offered_generation: offered.generation(),
                        offered_attempt: offered.attempt().get(),
                    }
                    .into());
                }
                if offered.generation() == held.generation()
                    && offered.attempt() == held.attempt()
                    && offered.sealed_re_ack() != held.sealed_re_ack()
                {
                    return Err(ResumeError::AcceptanceResealed {
                        generation: held.generation(),
                        attempt: held.attempt().get(),
                    }
                    .into());
                }
                if held.confirmed()
                    && !advanced
                    && (offered.generation(), offered.attempt())
                        != (held.generation(), held.attempt())
                {
                    return Err(ResumeError::ConfirmedAcceptanceCleared {
                        generation: held.generation(),
                        attempt: held.attempt().get(),
                    }
                    .into());
                }
            }
            None if held.confirmed() && !advanced => {
                return Err(ResumeError::ConfirmedAcceptanceCleared {
                    generation: held.generation(),
                    attempt: held.attempt().get(),
                }
                .into());
            }
            None => {}
        }
        Ok(())
    }

    /// The confirm slot's two guards, the mirror of what the own slot has.
    ///
    /// **The settling leg's bytes are the only copy, and dropping them strands
    /// the peer.** A9.1(a) makes a `RE-CONFIRM` unreproducible from its inputs —
    /// it is a randomized seal — and A3.15 row 4 has it re-seeding until the
    /// answering side opens it. A write that emptied the slot while the exchange
    /// it settles still stands would therefore leave the responder waiting for a
    /// frame no later pass can rebuild: it retires at `T_RETIRE` while this side
    /// has already advanced, which is the split-brain commit-then-emit exists to
    /// remove. Every other durable slot on this record is guarded against
    /// exactly that, and this one was not.
    ///
    /// **Two acts legitimately empty it, and both are recognisable.** A3.6's
    /// confirming observation retires the leg with the retained root it belongs
    /// to, so the write that clears the slot also clears the retention — that is
    /// the shape [`ResumeRecord::retire_confirm`] produces, paired with
    /// [`ResumeRecord::retire_retained`]. And a later exchange supersedes it: a
    /// generation past the one the stored leg settles means the correspondence
    /// has moved on, and no observation of the old leg can arrive any more.
    /// Anything else is a record built from a read that predates the completion,
    /// and it is refused.
    ///
    /// **No rollback within the slot**, on the terms
    /// [`Self::guard_acceptance`] states for its own: a stored leg settling a
    /// later generation is never replaced by one settling an earlier, and the
    /// bytes at one generation are never re-sealed — the answering side dedups
    /// on what it has already opened, so a second seal at one generation is a
    /// frame it will refuse while this side waits on it.
    fn guard_confirm_slot(
        record: &ResumeRecord,
        stored: &ResumeRecord,
    ) -> Result<(), DmPersistError> {
        let Some(held) = stored.confirm_slot() else {
            return Ok(());
        };
        match record.confirm_slot() {
            Some(offered) => {
                if offered.generation() < held.generation() {
                    return Err(ResumeError::ConfirmSlotWouldRollBack {
                        stored: held.generation(),
                        offered: offered.generation(),
                    }
                    .into());
                }
                if offered.generation() == held.generation() && offered.sealed() != held.sealed() {
                    return Err(ResumeError::ConfirmResealed {
                        generation: held.generation(),
                    }
                    .into());
                }
                Ok(())
            }
            // The confirming observation, which ends the retained root in the
            // same write, or a later exchange the stored leg cannot belong to.
            None if stored.retained().is_some() && record.retained().is_none() => Ok(()),
            None if record.reconnect_gen() > held.generation() => Ok(()),
            None => Err(ResumeError::ConfirmSlotDropped {
                generation: held.generation(),
            }
            .into()),
        }
    }

    /// The retained `RS_n`'s two guards.
    ///
    /// **`superseded_at_ms` is write-once per retained root.** A5.4 stamps it at
    /// the *first* supersede *"so `T_RETIRE` cannot slide forward per
    /// re-attempt"*. The guard keys on the root's own bytes rather than on
    /// presence, which is what makes it per-`RS_n`: retiring one root and
    /// retaining its successor is a new stamp on a new root, and re-stamping the
    /// same root is the sliding ceiling. Compared plainly rather than in
    /// constant time — both copies are this party's own material and the caller
    /// already holds the offered one, the same reasoning the pseudonym guard
    /// above records.
    ///
    /// **Dedup entries may not be dropped while their root is still retained.**
    /// A5.3 gates eviction on *"actual `RS_n` retirement"*, because byte-novelty
    /// is what stops a co-host re-serving captured `RE-EST` bytes to re-fire the
    /// peer-state-regressed alarm, and that defence is live for exactly as long
    /// as the retained root can open those bytes.
    /// [`ResumeRecord::retire_retained`] drops both together and is the only
    /// call that does; this refuses the pairing arriving from a record built
    /// field by field.
    fn guard_retention(record: &ResumeRecord, stored: &ResumeRecord) -> Result<(), DmPersistError> {
        // **Ahead of the retention checks, because the base is not scoped to a
        // root being retained.** A6.1's window slides with observed traffic for
        // the life of the correspondence; retiring `RS_n` ends what the memory
        // is for, not what the receiver has seen.
        if record.last_seen_re_est() < stored.last_seen_re_est() {
            return Err(ResumeError::ReEstBaseWouldRegress {
                stored: stored.last_seen_re_est(),
                offered: record.last_seen_re_est(),
            }
            .into());
        }
        let Some(held) = stored.retained() else {
            return Ok(());
        };
        let Some(offered) = record.retained() else {
            return Ok(());
        };
        if offered.root().as_bytes() != held.root().as_bytes() {
            return Ok(());
        }
        if offered.superseded_at_ms() != held.superseded_at_ms() {
            return Err(ResumeError::SupersededStampMoved {
                stored: held.superseded_at_ms(),
                offered: offered.superseded_at_ms(),
            }
            .into());
        }
        // **A subset test above the window base, and no test below it.** A write
        // that removes one key and adds another keeps the count and drops a
        // position, and the frame it covered becomes byte-novel again — the
        // alarm A5.3 exists to stop a co-host re-firing. So every stored
        // position must still be present *unless the window has moved past it*:
        // A5.2's scan rejects an attempt below the base, so such a frame can
        // never open and can never alarm, which is the one shrink the design
        // licenses. That exception is what makes the record's own eviction
        // committable at all; without it the memory could only ever grow, and a
        // long retention would reach `DedupFull` and refuse a legitimate
        // handshake frame.
        let base_for = |leg| match leg {
            crate::dm::resume::Leg::ReEst | crate::dm::resume::Leg::ReConfirm => {
                record.last_seen_re_est()
            }
            crate::dm::resume::Leg::ReAck => record.last_seen_re_ack(),
        };
        if stored
            .dedup()
            .keys()
            .iter()
            .any(|key| key.attempt().get() >= base_for(key.leg()) && !record.dedup().contains(*key))
        {
            return Err(ResumeError::DedupEvictedWhileRetained {
                stored: stored.dedup().len(),
                offered: record.dedup().len(),
            }
            .into());
        }
        Ok(())
    }

    /// Read the persisted resume record, or `Ok(None)` if none was written.
    ///
    /// **No clock argument**, unlike [`Self::read_outbox`]: nothing in this
    /// record drives a terminal transition, so there is no stored timestamp
    /// whose corruption could switch a guarantee off — the reasoning is on
    /// [`ResumeRecord::decode`].
    pub fn read_resume(
        &self,
        correspondence: &CorrespondenceLabel,
    ) -> Result<Option<ResumeRecord>, DmPersistError> {
        self.store
            .critical_section(correspondence, |guard| -> Result<_, DmPersistError> {
                match guard.read(RecordKind::Resume)? {
                    // `Zeroizing`: this plaintext holds a signing key, and the
                    // store zeroizes only its own copy.
                    Some(bytes) => Ok(Some(ResumeRecord::decode(&Zeroizing::new(bytes))?)),
                    None => Ok(None),
                }
            })
    }

    /// Read the persisted receive cursor, bounded by what the caller has
    /// genuinely read.
    ///
    /// `Ok(None)` means no cursor was persisted, and the caller starts at
    /// [`ReceiveCursor::START`].
    ///
    /// **`read_through` is a parameter, not something recovered from the file,
    /// and this call is the only way the file's number is reachable.** The
    /// record is sealed (#389), which says who wrote it and nothing about
    /// whether the number is right — this profile writing a wrong one seals just
    /// as well; a cursor set past what was actually read makes a sweep start
    /// beyond unread pages, which are then never revisited — messages that
    /// arrived, silently never delivered. Because the read and the bound happen
    /// inside this one call, the unbounded value never exists as anything a
    /// caller could hold and hand back as its own corroboration.
    ///
    /// A number this reading does not support is
    /// [`DmPersistError::CursorNotCorroborated`], not `Ok(None)`: absence and
    /// refusal have the same remedy — start from `START` — but only one of them
    /// means somebody wrote a number we will not act on.
    pub fn read_cursor(
        &self,
        correspondence: &CorrespondenceLabel,
        read_through: u64,
    ) -> Result<Option<ReceiveCursor>, DmPersistError> {
        match self
            .store
            .read_unlocked(correspondence, RecordKind::ReceiveCursor)?
        {
            Some(raw) => Ok(Some(decode_cursor(&raw, read_through)?)),
            None => Ok(None),
        }
    }

    /// Move the persisted cursor to `page`, and say what happened.
    ///
    /// Read-modify-write under one lock, because
    /// [`ReceiveCursor::advance_to`]'s backwards check is against the cursor's
    /// *current* value — done as a separate read and write, a concurrent
    /// advance between the two would be overwritten by the older number.
    ///
    /// [`CursorAdvance::moved`] is `false` for the refusal
    /// [`ReceiveCursor::advance_to`] returns: backwards, past the last usable
    /// page, or past `read_through`. Nothing is written in that case, so a
    /// refused advance cannot leave a cursor the next read would decline to
    /// believe.
    ///
    /// A correspondence with no cursor yet starts from [`ReceiveCursor::START`],
    /// which is the same thing a receiver with no persisted cursor does.
    ///
    /// **A record that will not read is replaced, not reported**
    /// ([`CursorAdvance::repaired`]). A `cursor.bin` that is the wrong width, does
    /// not authenticate, or holds an interrupted erase cannot be read *or*
    /// written past: the read fails inside every critical section, so the record
    /// stays exactly as it is and **no session ever persists this
    /// correspondence's progress again** — every advance it would make is
    /// refused at the read, permanently, with nothing but a trace line saying so.
    ///
    /// The from-zero rescan at a cold start is *not* the discriminator, and
    /// saying it was would be wrong: a cold start reads with `read_through` of
    /// zero, so a perfectly healthy stored page above zero is uncorroborated
    /// there too and yields the same rescan. What the wrecked record loses is
    /// everything after that — the advances the session goes on to make, which a
    /// healthy record keeps and this one cannot. Nothing is
    /// adopted by repairing it — the stored number is discarded unread and what
    /// lands is the caller's own page, already bounded by `read_through` — so the
    /// repair can only cost a rescan, which is the failure this cursor is allowed
    /// to have. Where the caller's page does not advance past
    /// [`ReceiveCursor::START`] the record is still rewritten, because clearing
    /// the unreadable one is the whole point.
    ///
    /// **Only an unreadable record is repaired.** A store error that is about the
    /// environment rather than the record — IO, a lock, a key — propagates: it
    /// says nothing about what is on disk, and overwriting a record on the
    /// strength of it would destroy a good one. A
    /// [`DmPersistError::CursorNotCorroborated`] propagates too: that record read
    /// perfectly well, and refusing it while leaving it alone is the documented
    /// behaviour of a number this session cannot vouch for.
    pub fn advance_cursor(
        &self,
        correspondence: &CorrespondenceLabel,
        page: u64,
        read_through: u64,
    ) -> Result<CursorAdvance, DmPersistError> {
        self.store.critical_section(
            correspondence,
            |guard| -> Result<CursorAdvance, DmPersistError> {
                let (mut cursor, repaired) = match guard.read(RecordKind::ReceiveCursor) {
                    Ok(Some(raw)) => match decode_cursor(&raw, read_through) {
                        Ok(cursor) => (cursor, false),
                        // The record opened and holds something that is not a
                        // cursor — unreadable in the sense that matters.
                        Err(DmPersistError::CursorPayloadWrongLen { .. }) => {
                            (ReceiveCursor::START, true)
                        }
                        Err(e) => return Err(e),
                    },
                    Ok(None) => (ReceiveCursor::START, false),
                    Err(e) if is_unreadable_record(&e) => (ReceiveCursor::START, true),
                    Err(e) => return Err(e.into()),
                };
                let moved = cursor.advance_to(page, read_through);
                if !moved && !repaired {
                    return Ok(CursorAdvance {
                        moved: false,
                        repaired: false,
                    });
                }
                guard.replace(RecordKind::ReceiveCursor, &cursor.to_be_bytes())?;
                Ok(CursorAdvance { moved, repaired })
            },
        )
    }

    /// Read what is known about the correspondent, or `Ok(None)` if nothing has
    /// been recorded (ISC-C44).
    ///
    /// **No lock, like [`Self::read_outbox`] and unlike [`Self::read_resume`].**
    /// Asking whether a correspondent is known is a question, and entering
    /// [`DmStore::critical_section`] would answer it by making the
    /// correspondence exist on disk (#253) — the directory names under the store
    /// root are the one thing an adversary holding the disk reads without a key,
    /// so they must name established correspondences and not every label anyone
    /// looked up.
    ///
    /// **Anything that decides from what this returns and then writes must use
    /// [`Self::update_contact`] instead**, for [`Self::read_outbox`]'s reason:
    /// two calls in a row straddle a writer, and the sighting one of them was
    /// recording is then lost.
    ///
    /// **A record that will not decode is an error, not `Ok(None)`**, which is
    /// what [`Self::read_outbox`] and [`Self::read_resume`] do with theirs.
    /// Absence and unreadability have different remedies: the first means run
    /// first contact, and the second means a record that holds `pk_pc` — the key
    /// every frame's authorship is checked against — is on disk and cannot be
    /// read, which is not a thing to answer by silently starting again.
    ///
    /// **That separation is bounded, and the bound is inherited rather than
    /// chosen here.** The store's read maps `NotFound` on *any* component of the
    /// path to `Ok(None)`, so a vanished store root, a deleted profile directory
    /// and a correspondence that was never written are one answer. `Ok(None)`
    /// therefore means "nothing readable is there", not "this correspondent is
    /// unknown to a store that is otherwise intact" — a caller that would do
    /// something drastic on absence, such as re-running first contact for every
    /// correspondent at once, has to establish that the root is still there
    /// itself. What this call does separate is a record that exists and will not
    /// decode, which is never reported as absence.
    ///
    /// **`pk_pc` may be absent, and absence is a state rather than a fault.**
    /// An initiator's record is written when its first-contact entry is sent
    /// and carries no pseudonym until the acceptance arrives, so a caller that
    /// needs the key must say what it does without one. See
    /// [`ContactRecord::pk_pc`].
    ///
    /// **Known limitation: a recorded key is write-once through this module.**
    /// [`Self::record_correspondent_pseudonym`] fills an absent one and
    /// [`ContactRecord::record_pseudonym`] refuses to replace a recorded one
    /// with a different key, so a correspondent who rotates `PK_pc` leaves a
    /// record this API cannot repair — every later frame fails authorship
    /// against the stale key and the only remedy is out-of-band. That refusal
    /// is deliberate rather than overlooked: an unconditional overwrite is the
    /// lost update this whole shape exists to refuse, so a rotation path has to
    /// say what authorises the new key, which is a protocol question and not a
    /// wiring one.
    pub fn read_contact(
        &self,
        correspondence: &CorrespondenceLabel,
    ) -> Result<Option<ContactRecord>, DmPersistError> {
        match self
            .store
            .read_unlocked(correspondence, RecordKind::ContactCache)?
        {
            // `Zeroizing`: this kind carries no seal of its own, so the store
            // hands back the record as cleartext, and that cleartext holds the
            // channel's address root — and the store zeroizes only its own copy.
            Some(bytes) => Ok(Some(ContactRecord::decode(&Zeroizing::new(bytes))?)),
            None => Ok(None),
        }
    }

    /// Which correspondence holds `pk_lt`, or `Ok(None)` if none does (#261).
    ///
    /// The question a knock asks: a frame arrives carrying a long-term identity
    /// key, and the receiver has to know whether that identity is one it already
    /// corresponds with and under which label.
    ///
    /// **A correspondence still waiting to be accepted answers too**, because
    /// that is the case the mapping exists for: an initiator writes its record
    /// when it sends its first-contact entry and the acceptance it is waiting
    /// on names nothing but the correspondent's identity key, so a lookup that
    /// skipped pseudonym-less records could not route the one frame the
    /// correspondence is waiting for. **Callers that mean *established* must
    /// say so** by reading the record — see [`ContactRecord::pk_pc`] — because
    /// a label alone no longer distinguishes the two.
    ///
    /// **Derived, never stored, and that is a design decision rather than an
    /// omission** (`docs/design/direct-messaging.md` § A3.14: *"No journal, no
    /// index, no count"*). A persisted `pk_lt`-to-label index would be a second
    /// record that has to commit with the contact record it describes, and the
    /// store's whole no-journal argument rests on there being no invariant whose
    /// truth requires two records to have committed together. So the mapping is
    /// re-derived from the contact records themselves, which are its single
    /// authority. It is also the cheap direction: a scan spends **no seal** —
    /// the store's scarce resource is spent by writes — and it fires per opened
    /// knock, at first-contact rate, on a path that is already doing key
    /// agreement.
    ///
    /// **No cache, deliberately.** One rebuilt at open is permitted and is not
    /// built here, because it would have to be invalidated by every writer and
    /// this process is not the only one: the store's lock exists because two
    /// processes may hold one root, so a cached answer would be the "two calls
    /// straddle a writer" staleness [`Self::read_contact`] warns about, widened
    /// from a two-call window to the lifetime of the process. Build one when a
    /// measurement says the scan costs something.
    ///
    /// **Two or more matches is [`DmPersistError::AmbiguousCorrespondent`], not
    /// a winner.** See that variant. The cost is that the scan cannot stop at
    /// the first match — every correspondence is read on every call, which is
    /// what makes the ambiguity detectable at all.
    ///
    /// **A contact record that will not decode fails the whole lookup**, rather
    /// than being skipped, which is [`Self::read_contact`]'s propagation carried
    /// up unchanged rather than softened one layer above it. Skipping would
    /// merge unreadable back into absent, and the merged answer is the dangerous
    /// one: the unreadable record may be the very correspondence sought, so the
    /// caller would be told this identity is unknown, run first contact against
    /// a correspondent it already has, and mint a second label — manufacturing
    /// exactly the duplicate the paragraph above refuses to resolve. Failing
    /// closed leaves the disk untouched and the decision with the caller.
    ///
    /// **Not a snapshot, and not a read-modify-write**, per
    /// [`Self::read_contact`]: a writer can establish a correspondence between
    /// this call and whatever is done with its answer. A caller that decides
    /// from the label and then writes must do so under
    /// [`Self::update_contact`].
    pub fn correspondence_for_pk_lt(
        &self,
        pk_lt: &[u8; ml_dsa::PK_LEN],
    ) -> Result<Option<CorrespondenceLabel>, DmPersistError> {
        let mut first = None;
        let mut matches = 0usize;
        for label in self.store.correspondences()? {
            // A correspondence with no contact record is skipped, not an error:
            // `critical_section` establishes the directory by being entered, so
            // an established correspondence that has not yet recorded who it is
            // with is an ordinary state. A record that *exists* and will not
            // decode is the other case entirely, and `?` carries it out.
            let Some(contact) = self.read_contact(&label)? else {
                continue;
            };
            // Not a secret and not a constant-time comparison: `pk_lt` is a
            // public key the caller already holds, and the scan's timing is a
            // function of how many correspondences exist, which the directory
            // listing states outright to anyone holding the disk.
            if contact.pk_lt() == pk_lt {
                matches += 1;
                first.get_or_insert(label);
            }
        }
        match matches {
            0 => Ok(None),
            1 => Ok(first),
            matches => Err(DmPersistError::AmbiguousCorrespondent { matches }),
        }
    }

    /// Answer an opened first-contact entry against what is already on disk, and
    /// stop the outbox where that entry means the correspondent lost their
    /// at-rest state (#261).
    ///
    /// **The signal, and why the doorbell carries it.** A first-contact entry is
    /// evidence of establishment in the other direction (`docs/design/
    /// direct-messaging.md` § Task 2), so a fresh one from an identity we already
    /// hold a correspondence with is the one thing an established correspondent
    /// has no reason to send. Re-establishment after a restart is an ordinary
    /// frame on the channel plane, addressed under the `AR` a restart keeps.
    ///
    /// **A restart cannot reach the acting branch, and neither can a re-seed.**
    /// The predicate is [`ContactRecord::addresses_same_channel`], not the mere
    /// existence of a correspondence, and the difference is not caution: the
    /// design has first-contact messages re-seeding on the full schedule until
    /// evidence of establishment, so entries from an introduction that *worked*
    /// keep arriving for up to seven days afterwards. Firing on those would mark
    /// live messages undelivered on a healthy correspondence — the same harm as
    /// firing on a restart, arriving by a route a "did a known identity knock?"
    /// test would not see. A re-seed carries the recorded `ss0` and so the
    /// recorded root; only a new `ss0` yields a new one.
    ///
    /// **[`DmPersistError::AmbiguousCorrespondent`] fails closed and marks
    /// nothing**, which is the answer this path adds to that variant's own
    /// refusal to guess. Ending an entry is terminal —
    /// [`Outbox::channel_torn_down`] skips non-pending entries, so a later
    /// correct answer cannot revive one — and with two correspondences holding
    /// one identity key there is no way to say which one's queue belongs to the
    /// lost state. Acting on both would declare a healthy correspondence's
    /// messages undelivered; acting on either would do it by a coin toss the
    /// caller cannot see. Refusing costs only the optimisation: the entries fall
    /// back to the seven-day give-up, which is wasteful and never false.
    ///
    /// **What the user is told, and by what route.** The entries reach
    /// [`Lifecycle::Undelivered`](crate::dm::outbox::Lifecycle::Undelivered) —
    /// the same terminal state the give-up produces, because it is the same
    /// truth — and the *reason* travels beside them in the returned
    /// [`Teardown`], whose
    /// [`TrustEventKey`](crate::trust_events::TrustEventKey) and user-facing text
    /// are its own. The reason is deliberately not stored on the entry: a
    /// lifecycle carrying a cause would be a new tag in the outbox's at-rest
    /// encoding, and #235 asks for delivery states that are true, not for a
    /// delivery queue that is also a history.
    ///
    /// Touches the outbox and nothing else. The new first contact is a separate
    /// offer, accepted or declined on its own terms, and no pending frame is
    /// migrated onto it — they are sealed under a chain it does not have.
    ///
    /// `direction` names this side's outbox, as [`Self::update_outbox`] requires.
    #[must_use = "the surfaced sequences are what the user is owed; dropping them abandons silently"]
    pub fn correspondent_state_lost(
        &self,
        knock: &VerifiedFirstContact,
        direction: Direction,
        now_ms: i64,
    ) -> Result<StateLoss, DmPersistError> {
        let Some(correspondence) = self.correspondence_for_pk_lt(knock.pk_lt())? else {
            return Ok(StateLoss::NoCorrespondence);
        };
        // Present by construction: `correspondence_for_pk_lt` matched on a
        // contact record, and it propagates rather than skipping one that will
        // not decode. A concurrent writer could still have removed it between the
        // two reads, and that reads as "no correspondence to act on" — the same
        // conservative answer as never having found one.
        let Some(contact) = self.read_contact(&correspondence)? else {
            return Ok(StateLoss::NoCorrespondence);
        };
        // **A correspondence still waiting to be accepted says nothing about
        // the correspondent's state, and its root would say the wrong thing.**
        // Such a record was written by this side's own knock, under the root of
        // an `ss0` this side encapsulated; a knock arriving from that identity
        // carries the root of an `ss0` THEY encapsulated, so the two never
        // match and the comparison below would read a mutual knock — each side
        // knocking before either answered — as the correspondent having lost
        // their at-rest state. That would mark this side's own pending entries
        // undelivered, terminally, on a correspondence that is about to work.
        // The inference this method draws needs an established correspondence
        // to be about; an absent `pk_pc` says there is not one yet.
        if contact.pk_pc().is_none() {
            return Ok(StateLoss::NoCorrespondence);
        }
        if contact.addresses_same_channel(&knock.roots().ar()) {
            return Ok(StateLoss::SameChannel(correspondence));
        }
        let teardown = Teardown::correspondent_state_lost();
        let outcome = self.update_outbox(&correspondence, direction, now_ms, |outbox| {
            let outcome = outbox.channel_torn_down(teardown.cause(), now_ms);
            // Nothing surfaced means no entry was pending, which under this cause
            // means nothing changed at all — this arm ends every pending entry,
            // so it leaves none behind in `retained`. `Unchanged` then spends no
            // seal on a correspondence with an idle queue.
            Ok(if outcome.surfaced.is_empty() {
                Mutation::Unchanged(outcome)
            } else {
                Mutation::Changed(outcome)
            })
        })?;
        Ok(StateLoss::Confirmed {
            correspondence,
            teardown,
            outcome,
        })
    }

    /// Load the contact record, let `f` change it, and write it back — all under
    /// one lock.
    ///
    /// **`f` reports whether it mutated, and a report of
    /// [`Mutation::Unchanged`] costs no seal** — [`Self::update_outbox`]'s shape,
    /// for [`Self::update_outbox`]'s two reasons, and both of them apply here.
    ///
    /// **Read-modify-write, because the record's own guard is against its
    /// *current* value.** [`ContactRecord::observed_at`] refuses a sighting
    /// earlier than the last one recorded; performed as a separate read and
    /// write, a concurrent sighting landing between the two would be overwritten
    /// by the older number and `last_seen_ms` would come to understate when the
    /// contact was last seen — exactly the rewind the in-memory guard exists to
    /// refuse, arriving through the layer above it. Anything keying eviction or
    /// staleness on that stamp then discards a live contact. There is
    /// deliberately no `save_contact` taking a record the caller loaded earlier:
    /// that pair is the lost update, re-offered one layer up.
    ///
    /// **Why the conditional shape, when a contact is only *observed* by an
    /// event.** The change is event-driven; the **call** is not. `last_seen_ms`
    /// moves when a frame actually arrives, but the natural call site is the
    /// receive sweep — poll a correspondent's pages, then record the sighting —
    /// and most ticks of that sweep find nothing. Under an unconditional write
    /// this kind would join the outbox in the budget #289 measured and #347
    /// removed: one seal per correspondence per tick against a 2^32 birthday
    /// bound on a single per-profile key, spent by clients that sent and
    /// received nothing. Reporting decouples the polling cadence from the key's
    /// lifetime, so the cadence stays a latency choice. The refusals cost
    /// nothing either: a sighting `observed_at` declines, and a re-record of an
    /// instant already stored, are both `Unchanged`.
    ///
    /// **[`ContactRecord::observed_at`]'s bool is not the [`Mutation`] answer**,
    /// and a sweep that reads it as one gives back the saving above. It reports
    /// that the record now *reflects* a sighting at `at_ms`, which includes
    /// re-recording the instant already stored: the guard is `at_ms <
    /// last_seen_ms`, so the equal case is accepted, returns `true`, and changes
    /// nothing. Derive the answer from the stamp instead —
    /// `c.last_seen_ms() < at_ms && c.observed_at(at_ms)` is `true` exactly when
    /// the record moved, and short-circuits away the call that would not.
    ///
    /// `seed` supplies the record when the correspondence has none — first
    /// contact, where the keys and the address root are in hand. **It is a
    /// closure so it is built only when it is needed:** a seed carries the
    /// address root in the clear, and a sweep that constructs one per tick to
    /// discard it makes a live copy of that root on every call that already has
    /// a stored record.
    /// When a record does exist the seed is not built at all and the stored
    /// record is what `f` sees — a caller cannot displace `first_seen_ms`, or an
    /// advanced `last_seen_ms`, with a stale in-memory copy.
    ///
    /// **A seeded record is written whatever `f` reports, and this is where the
    /// shape departs from [`Self::update_outbox`] rather than copying it.**
    /// There, `Unchanged` on an absent record correctly writes nothing:
    /// `Outbox::new(direction)` is empty and derivable from the argument, so
    /// dropping it loses no fact. A seed is the opposite — `pk_lt`, `pk_pc` and
    /// the address root have no other home — and the losing call is the
    /// ordinary one: seed
    /// at the local clock, then record a sighting stamped earlier (a
    /// sender-supplied time, or a clock read taken before the seed's).
    /// `observed_at` refuses it, `f` honestly reports `Unchanged`, and under
    /// `update_outbox`'s rule the correspondent would stay unknown while every
    /// later tick re-seeded and lost it again — no error, no seal, no trace.
    /// Relative to the empty slot it was found in, a seeded record **is** the
    /// change, so `f`'s report is consulted only for a record that was already
    /// there. The seal that costs is one per correspondence for its whole life,
    /// not one per tick.
    ///
    /// **Nothing is written if `f` fails.** The record is replaced only after
    /// `f` returns `Ok`, so a failed call leaves the correspondence exactly as
    /// it was and the caller may retry. Taking the lock still establishes the
    /// correspondence's directory before `f` runs; what a refusal leaves absent
    /// is the record and the seal.
    ///
    /// **A stored record that will not decode wedges this call**, exactly as it
    /// does [`Self::commit_resume`], and for the same reason: the decode is
    /// `?`-propagated and never falls through to `seed`. Recovering by
    /// re-seeding would overwrite `first_seen_ms` and — where the stored bytes
    /// are merely unreadable to *this* build — a live correspondent's pseudonym
    /// and address root, silently, on a path no caller asked to be destructive.
    /// Fail closed and let the caller decide.
    ///
    /// **`Unchanged` is a promise the caller can break, and in debug builds it
    /// is checked** — again as [`Self::update_outbox`] does, and by comparison
    /// rather than [`assert_eq!`], because this record's encoding carries the
    /// channel's address root and `assert_eq!` would render it into the panic
    /// message. The check runs only
    /// on the stored path, which is the only path where a false report can lose
    /// anything: on the seeded path the write happens regardless, so the case
    /// the guard structurally cannot see is one that no longer exists.
    pub fn update_contact<T>(
        &self,
        correspondence: &CorrespondenceLabel,
        seed: impl FnOnce() -> Result<ContactRecord, DmPersistError>,
        f: impl FnOnce(&mut ContactRecord) -> Result<Mutation<T>, DmPersistError>,
    ) -> Result<T, DmPersistError> {
        self.store
            .critical_section(correspondence, |guard| -> Result<T, DmPersistError> {
                // `seeded` is not recoverable after the fact — a seed and a
                // stored record are the same type — and it decides whether `f`'s
                // report is consulted at all.
                let (mut contact, seeded) = match guard.read(RecordKind::ContactCache)? {
                    // `Zeroizing` for `Self::read_contact`'s reason: the store's
                    // answer for this kind is cleartext and holds the address
                    // root. Propagated, never recovered from by re-seeding — see
                    // this method's docs.
                    Some(bytes) => (ContactRecord::decode(&Zeroizing::new(bytes))?, false),
                    None => (seed()?, true),
                };
                // Debug builds hold the before-image so an `Unchanged` report
                // that is not true fails here rather than silently discarding
                // the caller's mutation.
                #[cfg(debug_assertions)]
                let before = contact.encode();
                let (out, changed) = match f(&mut contact)? {
                    Mutation::Changed(out) => (out, true),
                    Mutation::Unchanged(out) => {
                        // `#[cfg]`, not `debug_assert!`: that macro's body is
                        // type-checked in every profile, so it would demand
                        // `before` in release builds where the capture above
                        // does not exist.
                        #[cfg(debug_assertions)]
                        if !seeded {
                            assert!(
                                before.as_slice() == contact.encode().as_slice(),
                                "an update reported Mutation::Unchanged after changing the \
                                 contact record; the change would have been discarded without \
                                 a trace"
                            );
                        }
                        (out, false)
                    }
                };
                // A seeded record is written whatever `f` reported: relative to
                // the empty slot it was found in, it is itself the change, and
                // the facts it carries have no other home.
                if changed || seeded {
                    guard.replace(RecordKind::ContactCache, &contact.encode())?;
                }
                Ok(out)
            })
    }

    /// Record that this side has sent a first-contact entry to `pk_lt` under
    /// `correspondence`, before the entry is published.
    ///
    /// **The initiator's half of the contact cache, and the only thing that
    /// survives a restart taken before the acceptance arrives.**
    /// [`Self::correspondence_for_pk_lt`] reads contact records and nothing
    /// else, so without one an initiator cannot answer which correspondence a
    /// correspondent's identity key belongs to: the acceptance it is waiting
    /// for is never collected, and everything the correspondent composes
    /// re-emits to the outbox's seven-day give-up. The record holds `pk_lt`, the
    /// address root the entry addresses the channel under, and no pseudonym —
    /// that key first crosses in the acceptance frame, and
    /// [`Self::record_correspondent_pseudonym`] is where it lands.
    ///
    /// **`AR` is replaced when a record is already there, and that is why this
    /// is not [`Self::update_contact`].** A second entry to a recipient a
    /// knock already failed for is legitimate and reuses the same label, but it
    /// encapsulates a fresh `ss0` and so addresses a different channel; a
    /// mutator that could only move timestamps would leave the record naming
    /// the root of an entry nothing will ever answer. No method on
    /// [`ContactRecord`] replaces a root for the same reason — an established
    /// correspondence's root must not be replaceable at all — so the record is
    /// rebuilt here, under the store's lock, from the fields the new entry
    /// carries.
    ///
    /// **`first_seen_ms` survives that rebuild**: the correspondence began when
    /// this side first knocked, and a retry is the same correspondence still
    /// waiting. `last_seen_ms` moves to `now_ms` where that is not a rewind.
    ///
    /// **An established correspondence is
    /// [`DmPersistError::AlreadyEstablished`].** Knocking at an identity this
    /// side already corresponds with reads at the far end as evidence of lost
    /// at-rest state and ends every message they have queued for us, so the
    /// state that would do it is refused where it would be written rather than
    /// diagnosed afterwards. A record naming a *different* identity is
    /// [`DmPersistError::CorrespondenceHoldsAnotherIdentity`]: the label is not
    /// this recipient's, and writing through it would replace someone else's
    /// contact record with this one.
    ///
    /// **A DIFFERENT correspondence already holding this identity is
    /// [`DmPersistError::AlreadyEstablished`] too, and this is the refusal that
    /// keeps the identity routable.** [`Self::correspondence_for_pk_lt`] is the
    /// only path from a correspondent's identity key to the correspondence
    /// waiting on them, and it refuses to choose between two — so a second
    /// record for one identity makes that identity
    /// [`DmPersistError::AmbiguousCorrespondent`] permanently, and every
    /// consumer of the lookup then fails closed on it. The state arises without
    /// anything going wrong: an entry re-sent after its handshake record has
    /// aged past both live first-contact epochs cannot recover the label it was
    /// written under, so a caller that minted a fresh one would land here. The
    /// remedy is to write through the label this call names in the refusal —
    /// ask [`Self::correspondence_for_pk_lt`] before minting.
    ///
    /// **The scan is taken before the lock and is not a lock**, exactly as
    /// [`Self::accept_first_contact`]'s is: a concurrent writer can create a
    /// second correspondence between the scan and the write, and the duplicate
    /// that leaves is detectable where a silently-written one is not.
    ///
    /// # What the extra file discloses to someone holding the disk
    ///
    /// This write puts a contact record beside the provisional record of a
    /// correspondence that has not been accepted, where before there was only
    /// the provisional one. Record filenames are fixed, so presence is readable
    /// without any key — and that is already priced: record presence reveals
    /// handshake state, and a present provisional record means an unconfirmed
    /// handshake (`docs/design/direct-messaging.md`, § *What is actually
    /// keyless*).
    ///
    /// **The residual covers this, and nothing needs to be added to it.** The
    /// two records are present together in exactly one state and it is the
    /// state the provisional record already announces on its own, so the second
    /// filename carries no bit the first does not. The pairing is not a new
    /// signal either: a contact record whose correspondence has no provisional
    /// record beside it is the established case the design already expects to
    /// find one in.
    ///
    /// **What the residual does NOT price is the other direction: a provisional
    /// record with NO contact record beside it is now a state of its own.** It
    /// is the shape [`Self::accept_first_contact`] leaves behind when it
    /// supersedes an unanswered entry to an identity it is establishing, and the
    /// shape a caller leaves if this write is refused after the handshake record
    /// was written. Someone holding the disk and no key can tell that from an
    /// ordinary pending knock, where the design's passage speaks only of what
    /// `provisional.bin`'s presence discloses on its own.
    pub fn record_first_contact_sent(
        &self,
        correspondence: &CorrespondenceLabel,
        pk_lt: Box<[u8; ml_dsa::PK_LEN]>,
        ar: Zeroizing<[u8; ROOT_LEN]>,
        now_ms: i64,
    ) -> Result<(), DmPersistError> {
        if self
            .correspondence_for_pk_lt(&pk_lt)?
            .is_some_and(|held| held != *correspondence)
        {
            return Err(DmPersistError::AlreadyEstablished);
        }
        self.store
            .critical_section(correspondence, |guard| -> Result<(), DmPersistError> {
                // `Zeroizing` for `Self::read_contact`'s reason: this kind
                // carries no seal of its own, so the store hands back cleartext
                // that holds the channel's address root.
                let stored = match guard.read(RecordKind::ContactCache)? {
                    Some(bytes) => Some(ContactRecord::decode(&Zeroizing::new(bytes))?),
                    None => None,
                };
                let (first_seen_ms, last_seen_ms) = match &stored {
                    Some(existing) => {
                        if existing.pk_lt() != pk_lt.as_ref() {
                            return Err(DmPersistError::CorrespondenceHoldsAnotherIdentity);
                        }
                        if existing.pk_pc().is_some() {
                            return Err(DmPersistError::AlreadyEstablished);
                        }
                        (
                            existing.first_seen_ms(),
                            existing.last_seen_ms().max(now_ms),
                        )
                    }
                    None => (now_ms, now_ms),
                };
                let record = ContactRecord::new(pk_lt, None, ar, first_seen_ms, last_seen_ms)?;
                guard.replace(RecordKind::ContactCache, &record.encode())?;
                Ok(())
            })
    }

    /// Fill in the correspondent's pseudonym key on a record that was written
    /// without one, returning whether it was newly recorded.
    ///
    /// The other end of [`Self::record_first_contact_sent`]: an initiator's
    /// record holds no `pk_pc` until the acceptance frame carries one, and this
    /// is the call that writes it down once that frame has verified. `false`
    /// means the identical key was already recorded — a re-presented acceptance
    /// — and costs no seal.
    ///
    /// **A different key is
    /// [`DmPersistError::Contact`]`(`[`ContactCacheError::PseudonymAlreadyRecorded`]`)`,
    /// not a replacement**, and the guard is the record's own; see
    /// [`ContactRecord::record_pseudonym`].
    ///
    /// **A correspondence with no record at all is
    /// [`DmPersistError::ContactRecordMissing`], never a record seeded here.**
    /// An acceptance names the correspondence it answers, and this call knows
    /// neither the identity key nor the address root that a record must carry —
    /// seeding one would mean inventing them. Absence says the entry this
    /// acceptance answers was never recorded as sent, which is a fault in the
    /// caller's ordering rather than something to paper over.
    ///
    /// `now_ms` is recorded as a sighting, because an acceptance is one.
    pub fn record_correspondent_pseudonym(
        &self,
        correspondence: &CorrespondenceLabel,
        pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
        now_ms: i64,
    ) -> Result<bool, DmPersistError> {
        self.update_contact(
            correspondence,
            || Err(DmPersistError::ContactRecordMissing),
            |contact| {
                let recorded = contact.record_pseudonym(pk_pc)?;
                // `observed_at`'s bool is not the `Mutation` answer — see
                // `update_contact`. The stamp is what says whether it moved.
                let observed = contact.last_seen_ms() < now_ms && contact.observed_at(now_ms);
                Ok(if recorded || observed {
                    Mutation::Changed(recorded)
                } else {
                    Mutation::Unchanged(recorded)
                })
            },
        )
    }

    /// The profile's block list.
    ///
    /// **Takes no lock**, like [`Self::read_contact`] and for one of its two
    /// reasons. The commit is `rename(2)`, so this reads either the whole old
    /// list or the whole new one and never a mixture; a lock would only serialise
    /// it behind an unrelated writer. The *other* reason a correspondence read
    /// avoids the lock — that taking one establishes the correspondence — has no
    /// force here, since the record exists from the store's first open.
    ///
    /// What decides it is the caller: the two suppression predicates are asked on
    /// the doorbell and channel paths, per knock and per sweep, and neither
    /// writes anything on the strength of the answer. Anything that reads the
    /// list and then *changes* it must use [`Self::update_block_list`], which is
    /// the read and the write in one critical section.
    ///
    /// **An absent record is [`DmPersistError::BlockListMissing`], not an empty
    /// list.** See that variant: this is a revocation list, and the failure mode
    /// of answering absence with "nobody is blocked" is silent unblocking.
    pub fn read_block_list(&self) -> Result<BlockList, DmPersistError> {
        match self.store.read_profile_unlocked(RecordKind::BlockList)? {
            Some(bytes) => Ok(BlockList::decode(&bytes)?),
            None => Err(DmPersistError::BlockListMissing),
        }
    }

    /// Write an empty block list, and only if there is none.
    ///
    /// **Not the ordinary creator, and it is worth being exact about that.**
    /// [`DmStore::open`] already brings every profile-level record into
    /// existence, so on almost every open this finds the record there and
    /// writes nothing. What it closes is that creation's own documented gap:
    /// it is best-effort, it takes the profile lock with `try_acquire`, and a
    /// second opener that finds the lock held returns with the record still
    /// absent. [`Self::read_block_list`] and [`Self::update_block_list`] both
    /// refuse an absent record — deliberately, because a revocation list that
    /// reads as empty when it is missing is silent unblocking — so inside that
    /// window a client can neither consult nor change its block list, and
    /// nothing retries until the next open.
    ///
    /// **What it costs, stated rather than hidden.** Because it cannot tell
    /// that window from a record an attacker with the disk deleted, calling it
    /// re-creates an empty list in both cases. That is the same exposure
    /// `DmStore::open` already accepts for the same reason, not a new one — but
    /// a caller that runs it should say what it traded, and
    /// [`Self::read_block_list`]'s refusal is what makes the removal visible
    /// in the window before it runs.
    ///
    /// Returns whether it wrote. An existing list — empty or full — is left
    /// exactly as it is, so this can never discard a block.
    pub fn provision_block_list(&self) -> Result<bool, DmPersistError> {
        self.store
            .profile_critical_section(|guard| -> Result<bool, DmPersistError> {
                if guard.read(RecordKind::BlockList)?.is_some() {
                    return Ok(false);
                }
                guard.replace(RecordKind::BlockList, &BlockList::new().encode()?)?;
                Ok(true)
            })
    }

    /// Load the block list, let `f` change it, and write it back — all under the
    /// profile lock.
    ///
    /// **Unconditional: there is no [`Mutation`] here, and the departure from
    /// [`Self::update_contact`] is deliberate.** That shape exists to protect the
    /// store's seal budget, which is spent by record *writes* and is dominated by
    /// polling — an `update_contact` fires on every sweep tick whether or not the
    /// contact was seen, so most of its calls must cost nothing. This one is
    /// driven by a person clicking *block* or *unblock*: a handful of writes a
    /// year, against a budget of 2^32. Asking the caller to classify a write
    /// that cheap would buy nothing and would add the one failure mode
    /// `Mutation` carries — a mis-reported `Unchanged` silently discarding a
    /// revocation, which is the change least tolerable to lose.
    ///
    /// So a no-op call costs one seal. That is the whole price, and it is the
    /// right way round: writing when nothing changed wastes a seal, while not
    /// writing when something did loses a block.
    ///
    /// **Nothing is written if `f` fails**, and nothing is written if the
    /// resulting list is over the ceiling — [`BlockList::encode`] refuses before
    /// the replace, so a caller that blocks a 513th identity leaves the stored
    /// 512 exactly as they were.
    pub fn update_block_list<T>(
        &self,
        f: impl FnOnce(&mut BlockList) -> Result<T, DmPersistError>,
    ) -> Result<T, DmPersistError> {
        self.store
            .profile_critical_section(|guard| -> Result<T, DmPersistError> {
                let bytes = guard
                    .read(RecordKind::BlockList)?
                    .ok_or(DmPersistError::BlockListMissing)?;
                let mut list = BlockList::decode(&bytes)?;
                let out = f(&mut list)?;
                guard.replace(RecordKind::BlockList, &list.encode()?)?;
                Ok(out)
            })
    }

    /// Establish the ACCEPTOR's side of a correspondence from a verified knock.
    ///
    /// The counterpart of [`PendingHandshake::establish`], which is the
    /// INITIATOR's: that one resumes a handshake this side started and erases
    /// the record it started from; this one has no record to erase, because the
    /// `ss0` this side answers under arrived inside the entry and is never
    /// written: the contact record stores the root derived from it.
    ///
    /// **It is one act for the reason `establish` is one act.** Minting the
    /// label, opening the ratchet and recording who the correspondence is with
    /// are three steps that are only ever correct together: a label is minted
    /// from the CSPRNG and cannot be recomputed
    /// ([`CorrespondenceLabel::mint`]), so a caller that minted one, built a
    /// ratchet, and then failed to write the contact record would hold a live
    /// conversation whose `ss0`, `pk_pc` and name exist nowhere but in RAM.
    /// Offering the three separately is offering that ordering to be got wrong.
    ///
    /// **The ratchet is built before the record is written**, matching
    /// `establish`: a module fault building it leaves the disk untouched, and
    /// the knock can be accepted again. A failure of the *write* leaves a
    /// minted label with no record — the correspondence directory may exist and
    /// hold nothing, which [`Self::correspondence_for_pk_lt`] already skips as
    /// an ordinary state — and the caller is told, so it may accept again
    /// rather than carry on with a ratchet nothing remembers.
    ///
    /// **Nothing else is written.** The provisional record is the initiator's
    /// and the acceptor has none; the resume record needs a committed root and
    /// a sealed re-establishment frame, neither of which exists until the
    /// channel has actually re-established, so there is nothing here it could
    /// hold.
    ///
    /// **A second establishment for one identity is
    /// [`DmPersistError::AlreadyEstablished`], not a second label.** The check
    /// is a `correspondence_for_pk_lt` scan taken first, and it is not
    /// belt-and-braces: two labels holding one `pk_lt` make every later lookup
    /// [`DmPersistError::AmbiguousCorrespondent`], which
    /// [`Self::correspondent_state_lost`] then refuses to act on — so the
    /// identity is unroutable for the life of the store and nothing can say
    /// which of the two was real. Refusing costs one scan on a path already
    /// doing key agreement. It is not a lock: a concurrent writer can establish
    /// between the scan and the write, which is the same window
    /// [`Self::correspondence_for_pk_lt`] documents, and the duplicate it
    /// leaves is detectable where a silently-minted one is not.
    ///
    /// # When both parties knocked at once
    ///
    /// Each side can send a first-contact entry before either has answered.
    /// Both then hold a record written by their own entry, and one of them
    /// answers the other's — so for a moment two correspondences exist for the
    /// same identity, which is the state that makes every later lookup for it
    /// ambiguous and unroutable.
    ///
    /// **The acceptance wins: the record written by this side's own unanswered
    /// entry is removed, and the correspondence established here is the one
    /// that survives.** The alternative is for the acceptance to take over the
    /// label the unanswered entry already holds, which avoids the leftover
    /// described next but leaves that entry's queued opening message sitting
    /// under a label whose channel has changed beneath it. What the choice made
    /// here costs is a correspondence directory with no contact record: the
    /// unanswered entry keeps its own queue, nothing will answer it, and no
    /// lookup names it again. The two parties still converge on one
    /// conversation, because the entry each of them sent is answered by the
    /// other.
    ///
    /// `s_pc` is this side's own per-correspondent signing key, minted by the
    /// caller for this conversation. It is taken here because establishment is
    /// the moment it acquires its only at-rest home: it is not derivable from
    /// the shared secret or from the mnemonic, so a correspondence established
    /// without writing it can never sign a re-establishment leg
    /// (`docs/design/direct-messaging.md:1056`, A4.8).
    ///
    /// `now_ms` stamps both `first_seen_ms` and `last_seen_ms`: the knock is
    /// the first and so far only sighting.
    pub fn accept_first_contact(
        &self,
        verified: VerifiedFirstContact,
        s_pc: &[u8; ml_dsa::SK_LEN],
        now_ms: i64,
    ) -> Result<(CorrespondenceLabel, Ratchet), DmPersistError> {
        // A second establishment for one identity is refused HERE, because
        // afterwards nothing can undo it: two labels holding one `pk_lt` make
        // every later `correspondence_for_pk_lt` return
        // `AmbiguousCorrespondent`, which in turn makes
        // `correspondent_state_lost` refuse to act and leaves the identity
        // unroutable for the life of the store.
        if let Some(existing) = self.correspondence_for_pk_lt(verified.pk_lt())? {
            match self.read_contact(&existing)? {
                Some(contact) if contact.pk_pc().is_some() => {
                    return Err(DmPersistError::AlreadyEstablished);
                }
                // A record with no pseudonym is this side's own unanswered
                // knock at the same identity — a mutual knock, where each side
                // knocked before either answered. It is superseded rather than
                // refused: the conversation the two of them end up holding is
                // the one being established here, and the knock this side sent
                // is answered, if at all, on a channel this establishment does
                // not use. The record is removed FIRST so that no moment exists
                // in which two records hold this identity key; what a failure
                // between the two writes leaves behind is a correspondence
                // whose identity is not indexed, which is the state every
                // unanswered knock was in before it was recorded at all.
                //
                // **This arm is the guard on the removal**, which has none of
                // its own: it has read the record and found no pseudonym, so
                // the established case cannot reach `forget_contact`.
                Some(_) => self.forget_contact(&existing)?,
                None => {}
            }
        }
        // Copied out before `into_ss0` consumes the knock. Each is a public key
        // rather than a secret; the one secret, `ss0`, is moved.
        let pk_lt = Box::new(*verified.pk_lt());
        let pk_pc = Box::new(*verified.pk_pc());
        let eph_ek = Box::new(*verified.eph_ek());
        let label = CorrespondenceLabel::mint()?;
        let ss0 = verified.into_ss0();
        let ratchet = Ratchet::recipient(&ss0, eph_ek)?;
        // The contact record stores `AR` and never `ss0` (§ D-PFS, design lines
        // 706 and 710): retaining `ss0` for the life of the correspondence would
        // regenerate `RK0` and with it every message key the ratchet believes it
        // deleted. So the root is derived here, from the `ss0` this frame
        // already holds and destroys on the way out, and only the root crosses
        // into the record.
        // The bare copy is cleared rather than left in the frame — `decode`'s
        // #135 pattern. `ChannelRoots` destroys its own copy and `chan_id` with
        // it, but the value read out of it lands in an unprotected stack slot on
        // the way into the wrapper, and this module's own docs argue `AR` is
        // worth erasing.
        let roots = derive_channel_roots(&ss0)?;
        let mut bare_ar = roots.ar();
        let ar = Zeroizing::new(bare_ar);
        bare_ar.zeroize();
        // **The resume record is written before the contact record, and the
        // order is the crash rule.** The contact record's pseudonym is what every
        // later lookup reads as "established", so a crash between the two writes
        // in the other order would leave a correspondence that is established and
        // has no `S_pc` — unable to sign a re-establishment leg, and with no
        // derivation that could recover the key, because `S_pc` is at-rest-only
        // and not mnemonic-derivable (`docs/design/direct-messaging.md:1056`,
        // A4.8). Written first, the same crash leaves a resume record under a
        // correspondence no lookup names, which is the state every unanswered
        // knock is already in.
        //
        // Both handshake slots stand empty and nothing is retained: the keys, the
        // root and the floor are what a correspondence has the moment it exists,
        // and a sealed re-establishment frame is not.
        self.commit_resume(
            &label,
            &ResumeRecord::new(
                Box::new(*s_pc),
                pk_pc.clone(),
                roots.rs0().clone(),
                ReEstState::first_establishment(),
                Retention::none(),
                // Nothing has been sent on this channel: the acceptance is
                // composed after this call returns. The floor rises at the first
                // completed re-establishment.
                SendFloor::new(0, 0),
            )?,
        )?;
        // Seeded, so the record is written whatever the mutator reports — see
        // `update_contact`. There is nothing to change about a record built
        // from the knock in the same call.
        self.update_contact(
            &label,
            move || Ok(ContactRecord::new(pk_lt, Some(pk_pc), ar, now_ms, now_ms)?),
            |_| Ok(Mutation::Unchanged(())),
        )?;
        Ok((label, ratchet))
    }

    /// Remove a correspondence's contact record, refusing to remove an
    /// established one.
    ///
    /// **The one way a contact record leaves the disk.** A record with no
    /// pseudonym holds facts a knock can restate — the identity knocked at and
    /// the root that knock addressed — so losing it costs the knock its index
    /// and nothing else. A record with one is the only copy of the key every
    /// frame's authorship is checked against, and removing it would leave a
    /// live conversation unable to verify its correspondent with no way back.
    ///
    /// **The caller is what keeps this off an established record.** There is
    /// one, [`Self::accept_first_contact`], and it reaches here only from the
    /// match arm that has just read the record and found no pseudonym in it.
    /// A second guard here would re-read the same bytes to ask the same
    /// question, and nothing could ever drive it — a guard no fixture can make
    /// fire is not a guard, so the check lives once, where a new caller has to
    /// write it.
    ///
    /// Absence is `Ok(())`: the state being asked for is the state that holds.
    fn forget_contact(&self, correspondence: &CorrespondenceLabel) -> Result<(), DmPersistError> {
        self.store
            .critical_section(correspondence, |guard| -> Result<(), DmPersistError> {
                guard.delete(RecordKind::ContactCache)?;
                Ok(())
            })
    }
}

/// What [`DmPersist::advance_cursor`] did.
///
/// **Two facts rather than one bool, because the second is a health signal.** A
/// repair means a `cursor.bin` was found unreadable and replaced; the
/// correspondence carries on either way, so a caller that only wants to know
/// whether the number moved reads [`Self::moved`] and is unaffected. What the
/// repair must not be is silent — an unreadable record is either tampering or
/// corruption, and a driver that fixes one without saying so reports a healthy
/// channel while the disk is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "an ignored advance is a cursor that may not have moved, or a record that was repaired"]
pub struct CursorAdvance {
    moved: bool,
    repaired: bool,
}

impl CursorAdvance {
    /// Whether the stored cursor advanced to the requested page.
    pub fn moved(self) -> bool {
        self.moved
    }

    /// Whether an unreadable record was replaced on the way.
    ///
    /// Independent of [`Self::moved`]: a repair whose caller-supplied page does
    /// not advance past [`ReceiveCursor::START`] still rewrites the record.
    pub fn repaired(self) -> bool {
        self.repaired
    }
}

/// Whether this store error says the *record* is unreadable, as opposed to the
/// environment being unusable.
///
/// **The split is what makes the repair safe.** The first class is a fact about
/// bytes on disk that no retry improves, and replacing them loses nothing that
/// could be recovered. The second says nothing about the record at all — an IO
/// failure, a lock, a key that will not derive — and a repair on the strength of
/// one would overwrite a record that may be perfectly good.
///
/// Written as an exhaustive match rather than a wildcard so a new variant has to
/// be classified here instead of defaulting into the repairing half.
fn is_unreadable_record(e: &DmStoreError) -> bool {
    match e {
        DmStoreError::WrongFileLen { .. }
        | DmStoreError::NotAuthentic { .. }
        | DmStoreError::ErasureInterrupted { .. }
        | DmStoreError::CorruptPayloadLen { .. } => true,
        DmStoreError::Io { .. }
        | DmStoreError::Write { .. }
        | DmStoreError::Lock(_)
        | DmStoreError::Reentrant
        | DmStoreError::WrongScope { .. }
        | DmStoreError::Kdf
        | DmStoreError::Module
        | DmStoreError::EntropySource(_)
        | DmStoreError::ErasureBlocked { .. }
        | DmStoreError::PayloadTooLong { .. } => false,
    }
}

/// Read a cursor's at-rest bytes, bounded by `read_through`.
///
/// One body for both the locked and the unlocked path, so the bound cannot be
/// applied in one and forgotten in the other.
fn decode_cursor(raw: &[u8], read_through: u64) -> Result<ReceiveCursor, DmPersistError> {
    // The store's fixed size bounds the FILE, not the payload: the seal carries a
    // length prefix, so a record written with fewer bytes opens and unpads to
    // fewer bytes from a perfectly well-formed record. That is this module's
    // shape to check, and reporting it as the store's file-length error described
    // a full-width file as being the payload's length.
    let bytes: [u8; RECEIVE_CURSOR_LEN] =
        raw.try_into()
            .map_err(|_| DmPersistError::CursorPayloadWrongLen {
                expected: RECEIVE_CURSOR_LEN,
                actual: raw.len(),
            })?;

    ReceiveCursor::from_be_bytes(bytes, read_through)
        .ok_or(DmPersistError::CursorNotCorroborated { read_through })
}

/// What an opened first-contact entry meant for what is already on disk (#261).
///
/// Three facts, three answers, for [`DmPersist::restart_channel`]'s reason: a
/// two-valued "was this state loss?" would have to fold *this identity is not
/// known* together with *this is the introduction we already accepted, arriving
/// again*, and those two differ in everything a caller does next.
///
/// A [`DmPersistError::AmbiguousCorrespondent`] is not a fourth arm here. It is
/// the error, deliberately: see [`DmPersist::correspondent_state_lost`].
#[derive(Debug)]
#[must_use = "an unread answer leaves the pending queue's fate undecided"]
pub enum StateLoss {
    /// No correspondence holds this identity — an ordinary first contact from a
    /// stranger, and nothing at rest is affected.
    NoCorrespondence,
    /// The entry addresses the channel already recorded for this identity, so it
    /// is the introduction that established it, re-seeded. **Not state loss**,
    /// and nothing was touched.
    SameChannel(CorrespondenceLabel),
    /// A known correspondent knocked under a channel we do not hold: their
    /// at-rest state is gone. Every pending entry in `outcome.surfaced` is now
    /// [`Lifecycle::Undelivered`](crate::dm::outbox::Lifecycle::Undelivered) and
    /// is owed to the user, with `teardown` carrying why.
    Confirmed {
        /// The correspondence whose queue was stopped.
        correspondence: CorrespondenceLabel,
        /// The ending, for its trust event and its user-facing text.
        teardown: Teardown,
        /// What the outbox did. `retained` is empty under this cause.
        outcome: TeardownOutcome,
    },
}

/// What a stored channel does at startup — [`ChannelRestart`], with the
/// resumption arm carrying its store.
///
/// The teardown arm is [`Teardown`] itself, unchanged: the decision is
/// [`crate::dm::provisional::restart`]'s and this module does not get a second
/// opinion on it.
#[derive(Debug)]
#[must_use = "a discarded restart decision is the silent rebuild #243 abolished"]
pub enum StoredChannelRestart<'a> {
    /// A resume record was present and opened: the correspondence is
    /// established, and this is what it needs to speak — our own `S_pc` and the
    /// correspondent's `PK_pc` above all.
    ///
    /// **Ahead of the other two arms, and that ordering is A4.8's read order**
    /// (`docs/design/direct-messaging.md` § A4.8): a resume record is the
    /// authority, and a provisional record lying beside it is a crash between
    /// the two writes of a first establishment, not a handshake to resume.
    /// Answering `HandshakeResumes` there would re-run first establishment on an
    /// already-established channel — a fresh `ss0` and a colliding sequence
    /// space.
    ///
    /// Boxed because a [`ResumeRecord`] carries an ML-DSA-87 keypair's worth of
    /// bytes and every other arm is small.
    Established(Box<ResumeRecord>),
    /// The record opened. [`PendingHandshake::establish`] is what finishes it.
    HandshakeResumes(PendingHandshake<'a>),
    /// The channel is over, and [`Teardown`] is the statement the user gets.
    /// Its [`Teardown::event`] is the trust event that must be surfaced.
    TornDown(Teardown),
}

/// A provisional record that is on disk and open in memory, and the only path
/// this module offers from one to a [`Ratchet`].
///
/// **This type is how the erasure is kept attached to the act that licenses
/// it.** It owns the record and exposes no way to take it out: the borrowing
/// accessors hand back what a resuming handshake needs and nothing else, and the
/// only consuming method is [`Self::commit`], which deletes.
///
/// **The act being paired is the PEER BEING VERIFIED, not a ratchet being
/// opened**, and the split into [`Self::ratchet`] and [`Self::commit`] is what
/// says so. An initiator derives its ratchet the moment it knocks — the opening
/// burst hangs off the first-contact secret and waits on nothing — but it cannot
/// verify the acceptor until the acceptance lands, and across that window the
/// record is the only at-rest home for `ss0` and the opening ephemeral. Deleting
/// at the derivation would strand the channel on a restart in exactly the window
/// the record exists for. [`Self::establish`] remains the pair, for the caller
/// whose two moments are one.
///
/// **What that does and does not cover, stated exactly.**
/// [`ProvisionalRecord::open`] and `ProvisionalRecord::into_ratchet` are public
/// on their own and remain so; anyone holding the sealed bytes and the seal key
/// can still make a ratchet without deleting anything. What this guarantees is
/// narrower and is the part that was broken: **nothing that reads a record from
/// the store ever yields a bare record**, so the establishment path that
/// actually exists cannot skip the erasure. Closing the wider hole means
/// demoting `into_ratchet`, which is a published API decision rather than a
/// wiring one.
#[derive(Debug)]
#[must_use = "a resumed handshake that is neither established nor dropped leaves ss0 on disk"]
pub struct PendingHandshake<'a> {
    persist: &'a DmPersist,
    correspondence: CorrespondenceLabel,
    record: ProvisionalRecord,
}

impl PendingHandshake<'_> {
    /// The opening ephemeral's public half, which the recipient's reply
    /// encapsulates to.
    pub fn eph_ek(&self) -> &[u8; ml_kem::EK_LEN] {
        self.record.eph_ek()
    }

    /// The channel's address root `AR`, recomputed from `ss0` — what a resuming
    /// handshake derives its page addresses from.
    pub fn address_root(&self) -> Result<[u8; ROOT_LEN], FirstContactError> {
        self.record.address_root()
    }

    /// Both channel roots, for a party resuming a handshake it cannot finish
    /// from `AR` alone.
    ///
    /// An initiator whose process ended before the acceptance arrived holds
    /// nothing about the conversation in memory. To collect that acceptance it
    /// must address the correspondent's pages, which takes `AR`, **and** open
    /// the frame it finds there, which binds `chan_id` into the AEAD — so the
    /// pair is what a resumption needs and `AR` on its own leaves the frame
    /// unreadable.
    ///
    /// See [`ProvisionalRecord::channel_roots`] for why handing `chan_id` back
    /// here does not weaken the rule that it is never written down.
    pub fn channel_roots(&self) -> Result<ChannelRoots, FirstContactError> {
        self.record.channel_roots()
    }

    /// Establish the channel: open the ratchet **and** erase the record.
    ///
    /// The two halves are one call because separating them is the defect. The
    /// record holds `ss0`, `ss0` roots `RK0`, and its erasure is the premise
    /// under which the steady-state ratchet is not persisted at all — so a
    /// caller that established a channel and forgot to delete would leave the
    /// conversation's opening secret on disk while every later chain key was
    /// being deleted on use, which is the forward-secrecy claim inverted.
    ///
    /// **The ratchet is built first, and a failed deletion returns an error
    /// rather than the ratchet.** Both orderings can fail; they fail
    /// differently. Deleting first and then failing to open the ratchet would
    /// destroy a handshake over what is most plausibly a transient module fault.
    /// Opening first and then failing to delete leaves the record on disk — the
    /// caller is told, does not get a ratchet, and finds the record again on the
    /// next [`DmPersist::restart_channel`].
    ///
    /// **A crash inside the erase itself is not recoverable, and that is the
    /// accepted trade.** The deletion scrubs before it unlinks
    /// ([`Locked::delete`](crate::storage::dm_store::Locked::delete)), so a crash
    /// after the scrub's first barrier leaves a record that no longer opens: a
    /// handshake that a pre-scrub crash would have left resumable is destroyed.
    /// Three things settle it that way. The trade is **forced by the design** —
    /// the steady-state ratchet is deliberately never persisted, which is what
    /// makes erasing `ss0` worth anything, so there is nothing to durably commit
    /// before the delete and no restructuring survives the crash without
    /// persisting exactly what the design refuses. The two losses **differ in
    /// kind** — a destroyed provisional record costs the availability of one
    /// in-progress handshake, recoverable by redoing first contact; leaving the
    /// blocks intact costs the confidentiality of `ss0`, which roots `RK0` and
    /// reopens the early chain, permanently, against a later key compromise. And
    /// the **frequencies are asymmetric** — the scrub protects every
    /// establishment, while this window is bounded by two fsyncs on one small
    /// file inside a single critical section.
    ///
    /// The failure stays legible rather than silent: an interrupted erase reads
    /// as [`DmStoreError::ErasureInterrupted`]
    /// and never as tampering, and [`DmPersist::restart_channel`] maps it to a
    /// lost record rather than an unreadable store, so the caller is told the
    /// handshake is gone instead of being told to keep waiting for it.
    pub fn establish(self) -> Result<Ratchet, DmPersistError> {
        // The CONSUMING derivation, deliberately, rather than
        // [`Self::ratchet`] followed by [`Self::commit`]: a caller whose two
        // moments are one has no window to keep the record for, so it takes the
        // path that leaves no second copy of the decapsulation key.
        let Self {
            persist,
            correspondence,
            record,
        } = self;
        let ratchet = record.into_ratchet()?;
        erase(persist, correspondence)?;
        Ok(ratchet)
    }

    /// Establish the channel and write the resume record first (A4.8).
    ///
    /// [`Self::establish`]'s ordering with the write A4.8 puts ahead of the
    /// erasure: **create the resume record, then delete the provisional one**
    /// (`docs/design/direct-messaging.md` § A4.8). The resume record is the
    /// correspondence's only at-rest home for our `S_pc` and the
    /// correspondent's `PK_pc` — neither is derivable from the shared secret or
    /// the mnemonic — so a channel established without it is on disk and
    /// unspeakable after the next restart.
    ///
    /// **The order is what makes the crash window recoverable.** Deleting first
    /// and crashing leaves neither record, which
    /// [`DmPersist::restart_channel`] reads as an ordinary established teardown;
    /// writing first and crashing leaves both, which the same call reads as
    /// established, because it consults the resume record first.
    ///
    /// **A failed resume write is an error and nothing has been destroyed** —
    /// the provisional record is still on disk and the establishment can be
    /// taken again. **A failed erase is not an error**, which is what
    /// "best-effort" means here: the resume record is committed, the channel is
    /// established, and refusing the ratchet over an unscrubbed provisional
    /// record would destroy a working correspondence. The superseded `ss0` is
    /// erased by [`DmPersist::sweep_lingering_provisionals`] instead, which a
    /// client runs when it rebuilds its correspondences — so the leak is bounded
    /// by one restart rather than permanent. **It is bounded by the sweep and
    /// not by [`DmPersist::restart_channel`]**, which only reaches a
    /// correspondence some caller is already acting on and would therefore leave
    /// the record for as long as that conversation stayed untouched.
    pub fn establish_with_resume(self, resume: &ResumeRecord) -> Result<Ratchet, DmPersistError> {
        let Self {
            persist,
            correspondence,
            record,
        } = self;
        let ratchet = record.into_ratchet()?;
        commit_then_erase(persist, correspondence, resume)?;
        Ok(ratchet)
    }

    /// Write the resume record, then erase — [`Self::commit`] under A4.8's write
    /// order.
    ///
    /// The pair to [`Self::ratchet`], for the initiator whose two moments are
    /// apart: the ratchet is in hand from the knock, and the correspondent is
    /// verified when the acceptance lands, which is the moment the resume record
    /// can name a `PK_pc` and the provisional record stops being needed. The two
    /// failures are [`Self::establish_with_resume`]'s.
    pub fn commit_with_resume(self, resume: &ResumeRecord) -> Result<(), DmPersistError> {
        let Self {
            persist,
            correspondence,
            ..
        } = self;
        commit_then_erase(persist, correspondence, resume)
    }

    /// Derive the ratchet and leave the record exactly where it is.
    ///
    /// **The half of [`Self::establish`] that is safe to take early.** An
    /// initiator holds a ratchet from the moment it knocks — its opening burst
    /// hangs off the first-contact secret and waits on nothing — but it cannot
    /// verify the acceptor until the acceptance lands, and until then the record
    /// is the only thing that could resume the handshake across a restart. So
    /// the derivation moves here and the erasure stays in [`Self::commit`],
    /// which the caller runs when the acceptance verifies.
    ///
    /// **This does not weaken the pairing [`Self::establish`] exists to
    /// enforce**, because the two halves are still the only things this type
    /// offers and `#[must_use]` still refuses a handshake that is neither
    /// committed nor dropped. What it does is move the act being paired: no
    /// longer "a ratchet was opened" but "the peer was verified". A caller that
    /// derives and never commits leaves `ss0` on disk exactly as one that
    /// established and never deleted would have — and that is the *resumable*
    /// state the design asks for in this window, not a leak, because the
    /// acceptance has not happened yet.
    pub fn ratchet(&self) -> Result<Ratchet, DmPersistError> {
        Ok(self.record.to_ratchet()?)
    }

    /// Erase the record, and nothing else.
    ///
    /// The moment the conversation stops being resumable from disk, which is the
    /// moment it no longer needs to be: the peer is verified, the ratchet is in
    /// hand, and `ss0` — which roots `RK0` — has no further use. Every word of
    /// [`Self::establish`]'s note on the crash window applies here unchanged; it
    /// is the same critical section.
    pub fn commit(self) -> Result<(), DmPersistError> {
        let Self {
            persist,
            correspondence,
            ..
        } = self;
        erase(persist, correspondence)
    }
}

/// A4.8's write order, in the one place both endings reach it — so the two
/// cannot drift into writing and deleting in different orders.
fn commit_then_erase(
    persist: &DmPersist,
    correspondence: CorrespondenceLabel,
    resume: &ResumeRecord,
) -> Result<(), DmPersistError> {
    persist.commit_resume(&correspondence, resume)?;
    // Best-effort, per A4.8, and the discarded error is the point rather than an
    // oversight: the resume record is committed, so the correspondence is
    // established whatever happens next, and `sweep_lingering_provisionals`
    // erases what is left behind. See `establish_with_resume`.
    let _ = erase(persist, correspondence);
    Ok(())
}

/// The critical section both endings share, so the two cannot drift into
/// deleting different things.
fn erase(persist: &DmPersist, correspondence: CorrespondenceLabel) -> Result<(), DmPersistError> {
    persist
        .store
        .critical_section(&correspondence, |guard| -> Result<(), DmPersistError> {
            guard.delete(RecordKind::Provisional)?;
            Ok(())
        })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dm::eph_dk_fixture;
    use std::path::Path;

    use crate::dm::block_list::BLOCK_LIST_MAX_ENTRIES;

    use zeroize::Zeroizing;

    use crate::crypto::suite::Registry;
    use crate::dm::contact_cache::{CONTACT_RECORD_LEN, CONTACT_RECORD_VERSION};
    use crate::dm::firstcontact::{SS0_LEN, VerifiedFirstContact, derive_channel_roots};
    use crate::dm::keyrec;
    use crate::dm::outbox::{DeliveryState, OUTBOX_MAGIC, OutboxTarget, SealedFrame, Surfacing};
    use crate::dm::paging::MAX_PAGE;
    use crate::dm::provisional::{PROVISIONAL_RECORD_LEN, TeardownCause};
    use crate::dm::ratchet::EphemeralDecapKey;
    use crate::dm::resume::SendFloor;
    use crate::storage::dm_store::CORRESPONDENCE_LABEL_LEN;
    use crate::trust_events::TrustEventKey;

    const AT_REST: [u8; AEAD_KEY_LEN] = [0x7Eu8; AEAD_KEY_LEN];

    const ADDR_A: [u8; keyrec::DM_KEYREC_OWNER_SEED_LEN] =
        [0x11u8; keyrec::DM_KEYREC_OWNER_SEED_LEN];
    const ADDR_B: [u8; keyrec::DM_KEYREC_OWNER_SEED_LEN] =
        [0x22u8; keyrec::DM_KEYREC_OWNER_SEED_LEN];

    /// A day in milliseconds, for stepping over the give-up window.
    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    fn persist(dir: &Path) -> DmPersist {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        DmPersist::open(dir.join("dm"), &AT_REST).expect("opens")
    }

    fn label(seed: u8) -> CorrespondenceLabel {
        CorrespondenceLabel::from_bytes([seed; CORRESPONDENCE_LABEL_LEN])
    }

    fn ctx() -> RecordContext<'static> {
        RecordContext {
            recipient_keyrec_addr: &ADDR_A,
            fc_epoch: 7,
        }
    }

    /// A different correspondent, same epoch.
    fn other_ctx() -> RecordContext<'static> {
        RecordContext {
            recipient_keyrec_addr: &ADDR_B,
            fc_epoch: 7,
        }
    }

    fn ss0() -> [u8; SS0_LEN] {
        // Byte-distinct, so a mis-sliced derivation would not pass by
        // coincidence.
        let mut out = [0u8; SS0_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0x10u8.wrapping_add(i as u8 * 7);
        }
        out
    }

    fn record() -> ProvisionalRecord {
        let (ek, dk) = ml_kem::keygen(&[0x33u8; ml_kem::SEED_LEN], &[0x44u8; ml_kem::SEED_LEN])
            .expect("keygen");
        ProvisionalRecord::new(
            Zeroizing::new(ss0()),
            Box::new(ek),
            EphemeralDecapKey::new(Box::new(dk)),
        )
        .expect("a matched pair")
    }

    /// Where a record lands, spelled out in the test rather than asked of the
    /// store — so a change to the store's own derivation shows up here as a
    /// failure instead of being followed silently.
    fn record_path(p: &DmPersist, l: &CorrespondenceLabel, file: &str) -> std::path::PathBuf {
        p.store().root().join(hex::encode(l.as_bytes())).join(file)
    }

    // ---- the record's erasure on establishment -----------------------------

    /// **The test this module exists for.** Establishment must take `ss0` off
    /// the disk, and the assertion is on the store's own answer afterwards —
    /// not on a call having been made.
    ///
    /// Three independent readings, because one of them alone could pass for the
    /// wrong reason: the store says the record is absent, the file itself is
    /// gone from the filesystem, and a fresh restart decision reaches
    /// [`TeardownCause::NoProvisionalRecord`] — which is what a *later run* of
    /// the client would actually observe.
    #[test]
    fn establishment_erases_the_provisional_record() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(1);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");

        // Positive control: the record really is there before establishment, so
        // the assertions below cannot pass against a record that was never
        // written.
        let path = record_path(&p, &l, "provisional.bin");
        assert!(
            path.exists(),
            "the record was not written in the first place"
        );
        assert!(
            p.store()
                .read_unlocked(&l, RecordKind::Provisional)
                .expect("reads")
                .is_some()
        );

        let pending = match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => pending,
            StoredChannelRestart::TornDown(t) => panic!("a saved record must resume: {t}"),
        };
        pending.establish().expect("establishes");

        assert!(
            p.store()
                .read_unlocked(&l, RecordKind::Provisional)
                .expect("reads")
                .is_none(),
            "ss0 is still readable from the store after establishment"
        );
        assert!(!path.exists(), "the record file survived establishment");
        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::TornDown(t) => {
                assert_eq!(t.cause(), &TeardownCause::NoProvisionalRecord);
            }
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("an established channel resumed its own handshake")
            }
        }
    }

    /// **A lookup must not delete.** [`DmPersist::peek_channel_restart`] answers
    /// the restart question and leaves the store exactly as it found it;
    /// [`DmPersist::restart_channel`] answers the same question and cleans.
    ///
    /// The fixture is A4.8's crash window — the resume record written, the
    /// provisional one not yet deleted — because that is the only state in which
    /// the cleaning branch is reachable at all.
    ///
    /// **The two halves are each other's control**, and neither is sufficient
    /// alone: without the second, a `peek` that simply never reached the cleaning
    /// branch would pass; without the first, a `restart_channel` that had quietly
    /// stopped cleaning would pass. Run in this order against one fixture, they
    /// pin the difference rather than either behaviour on its own.
    #[test]
    fn peeking_a_restart_leaves_a_lingering_provisional_record_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(0x5C);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");
        p.commit_resume(&l, &resume_record(1, SendFloor::new(4, 100)))
            .expect("commits");

        let path = record_path(&p, &l, "provisional.bin");
        assert!(
            path.exists(),
            "the fixture did not build the crash window this test is about"
        );

        match p.peek_channel_restart(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {}
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("a resume record was written, so the handshake must not resume")
            }
            StoredChannelRestart::TornDown(t) => panic!("a readable resume record tore down: {t}"),
        }
        assert!(
            path.exists(),
            "a lookup deleted a record belonging to a correspondence it was only asking about"
        );

        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {}
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("a resume record was written, so the handshake must not resume")
            }
            StoredChannelRestart::TornDown(t) => panic!("a readable resume record tore down: {t}"),
        }
        assert!(
            !path.exists(),
            "the cleaning version left the lingering record behind, so the assertion \
             above proves nothing about the peek"
        );
    }

    /// **The sweep closes A4.8's crash window across the store, and leaves a
    /// live handshake alone.**
    ///
    /// Three correspondences, and the third is what makes this a predicate
    /// rather than a delete-everything: two in the crash window (resume record
    /// written, provisional not yet erased) and one holding only a provisional
    /// record, which is an ordinary handshake in flight and must survive. A
    /// sweep that deleted unconditionally passes both crash-window assertions
    /// and fails on that one.
    ///
    /// The returned count is asserted too, so a sweep that deleted the right
    /// files by some other route — or reported work it did not do — is caught.
    #[test]
    fn the_sweep_scrubs_superseded_provisional_records_and_spares_live_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (a, b, live) = (label(0x71), label(0x72), label(0x73));

        for l in [&a, &b] {
            p.save_provisional(l, &ctx(), &record()).expect("saves");
            p.commit_resume(l, &resume_record(1, SendFloor::new(4, 100)))
                .expect("commits");
        }
        p.save_provisional(&live, &ctx(), &record()).expect("saves");

        let paths: Vec<_> = [&a, &b, &live]
            .iter()
            .map(|l| record_path(&p, l, "provisional.bin"))
            .collect();
        assert!(
            paths.iter().all(|path| path.exists()),
            "the fixture did not write all three provisional records"
        );

        assert_eq!(
            p.sweep_lingering_provisionals().expect("sweeps"),
            2,
            "the sweep did not report scrubbing exactly the two superseded records"
        );

        assert!(!paths[0].exists(), "a superseded record survived the sweep");
        assert!(!paths[1].exists(), "a superseded record survived the sweep");
        assert!(
            paths[2].exists(),
            "the sweep deleted a handshake still in flight, which has no resume record"
        );
    }

    /// **The split's first half: deriving a ratchet leaves the record where it
    /// is.** The initiator holds one from the moment it knocks and cannot
    /// verify its correspondent until the acceptance lands, so consuming here
    /// would strand the channel on any restart inside that window — the exact
    /// window `{ss0, the opening ephemeral DK}` is persisted for.
    ///
    /// Read three ways, the same three
    /// `establishment_erases_the_provisional_record` reads, so the two tests
    /// are each other's control: whatever one asserts is present, the other
    /// asserts is gone.
    #[test]
    fn a_derived_ratchet_leaves_the_record_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(20);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");
        let path = record_path(&p, &l, "provisional.bin");

        let fingerprint = match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                let r = pending.ratchet().expect("derives a ratchet");
                // The `PendingHandshake` drops here, uncommitted.
                *r.ar_fingerprint()
            }
            StoredChannelRestart::TornDown(t) => panic!("a saved record must resume: {t}"),
        };

        assert!(path.exists(), "the record file was erased by a derivation");
        assert!(
            p.store()
                .read_unlocked(&l, RecordKind::Provisional)
                .expect("reads")
                .is_some(),
            "the store no longer holds a record a derivation was not to touch"
        );
        // The reading that matters to a restarting client: it resumes, and
        // resumes into the SAME conversation. A record that opened into a
        // different one would satisfy every assertion above.
        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                let again = pending.ratchet().expect("derives again");
                assert_eq!(
                    again.ar_fingerprint(),
                    &fingerprint,
                    "the resumed handshake opened a different conversation"
                );
            }
            StoredChannelRestart::TornDown(t) => {
                panic!("an underived record must still resume: {t}")
            }
        }

        // **And the derived ratchet holds a WORKING decapsulation key.** The
        // fingerprint above is a hash of `ss0` and says nothing at all about
        // `eph_dk` — a derivation that handed the ratchet an all-zero copy, or
        // a copy zeroized a line too early, would pass every assertion so far
        // and then fail to open the acceptor's very first frame, which is the
        // one thing this window exists to make possible. So the far end is
        // built for real and its first frame is driven through.
        let derived = match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                pending.ratchet().expect("derives once more")
            }
            StoredChannelRestart::TornDown(t) => panic!("must resume: {t}"),
        };
        let recipient_ek = record();
        let mut far = Ratchet::recipient(&ss0(), Box::new(*recipient_ek.eph_ek()))
            .expect("the acceptor's ratchet");
        let outbound = far.send_next().expect("the acceptor's first key");
        assert!(
            outbound.eph_ct.is_some(),
            "the acceptor's first frame must carry the ciphertext this decapsulates"
        );
        let mut derived = derived;
        let opened = derived
            .receive(
                &outbound.header,
                outbound.eph_ct.as_deref(),
                &outbound.eph_ek,
                |key| Ok::<_, ()>(*key.as_bytes()),
            )
            .expect("the derived ratchet accepts the position")
            .expect("the closure cannot fail");
        assert_eq!(
            opened,
            *outbound.key.as_bytes(),
            "the derived ratchet decapsulated to a different message key, so the \
             copied decapsulation key is not the record's"
        );
    }

    /// `establish()` is exactly `ratchet()` followed by `commit()`.
    ///
    /// **Two implementations of one act, so they can drift.** `establish` takes
    /// the consuming derivation and its own erase; the split takes the
    /// borrowing one and `commit`. If those ever produced different ratchets,
    /// or erased differently, a caller's choice between them would change
    /// behaviour — and nothing else in this module would notice, because each
    /// is tested only against itself.
    #[test]
    fn establish_is_the_derivation_and_the_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (split, whole) = (label(22), label(23));

        p.save_provisional(&split, &ctx(), &record())
            .expect("saves");
        p.save_provisional(&whole, &ctx(), &record())
            .expect("saves");

        let by_split = match p.restart_channel(&split, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                let r = pending.ratchet().expect("derives");
                match p.restart_channel(&split, &ctx()) {
                    StoredChannelRestart::Established(_) => {
                        panic!("nothing wrote a resume record, so nothing can find one")
                    }
                    StoredChannelRestart::HandshakeResumes(again) => {
                        again.commit().expect("commits")
                    }
                    StoredChannelRestart::TornDown(t) => panic!("must still resume: {t}"),
                }
                r
            }
            StoredChannelRestart::TornDown(t) => panic!("must resume: {t}"),
        };
        let by_whole = match p.restart_channel(&whole, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                pending.establish().expect("establishes")
            }
            StoredChannelRestart::TornDown(t) => panic!("must resume: {t}"),
        };

        assert_eq!(
            by_split.ar_fingerprint(),
            by_whole.ar_fingerprint(),
            "the two endings opened different conversations"
        );
        assert_eq!(
            by_split.next_send_seq(),
            by_whole.next_send_seq(),
            "the two endings opened chains at different positions"
        );
        for (name, l) in [("the split", split), ("establish", whole)] {
            assert!(
                !record_path(&p, &l, "provisional.bin").exists(),
                "{name} left the record on disk"
            );
        }
    }

    /// **The split's second half: committing erases, and needs no ratchet.**
    /// The act the erasure is paired with is the peer being verified, and by
    /// then the ratchet is long since in hand — so `commit` takes no
    /// derivation, and a caller that never derived can still erase.
    #[test]
    fn commit_erases_the_record_without_a_ratchet() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(21);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");
        let path = record_path(&p, &l, "provisional.bin");
        assert!(
            path.exists(),
            "the record was not written in the first place"
        );

        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                pending.commit().expect("commits");
            }
            StoredChannelRestart::TornDown(t) => panic!("a saved record must resume: {t}"),
        }

        assert!(!path.exists(), "the record file survived the commit");
        assert!(
            p.store()
                .read_unlocked(&l, RecordKind::Provisional)
                .expect("reads")
                .is_none(),
            "ss0 is still readable from the store after the commit"
        );
        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::TornDown(t) => {
                assert_eq!(t.cause(), &TeardownCause::NoProvisionalRecord);
            }
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("a committed handshake resumed itself")
            }
        }
    }

    /// Establishment erases *this* correspondence's record and no other's — the
    /// delete is scoped by the guard it is taken on.
    #[test]
    fn establishment_leaves_another_correspondences_record_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (mine, theirs) = (label(2), label(3));

        p.save_provisional(&mine, &ctx(), &record()).expect("saves");
        p.save_provisional(&theirs, &ctx(), &record())
            .expect("saves");

        match p.restart_channel(&mine, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                pending.establish().expect("establishes");
            }
            StoredChannelRestart::TornDown(t) => panic!("must resume: {t}"),
        }

        assert!(
            p.store()
                .read_unlocked(&theirs, RecordKind::Provisional)
                .expect("reads")
                .is_some(),
            "establishing one channel erased another's record"
        );
    }

    /// The record survives the process it was written in: a second
    /// [`DmPersist`] over the same root recovers the same handshake. Both keys
    /// are re-derived from `at_rest_key`, so this also pins that neither is
    /// process-lifetime state.
    #[test]
    fn a_saved_record_resumes_in_a_new_process() {
        let tmp = tempfile::tempdir().unwrap();
        let l = label(4);
        let original = record();
        let (ek, root) = (*original.eph_ek(), original.address_root().expect("a root"));

        {
            let p = persist(tmp.path());
            p.save_provisional(&l, &ctx(), &original).expect("saves");
        }

        let p = persist(tmp.path());
        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::HandshakeResumes(pending) => {
                assert_eq!(pending.eph_ek(), &ek, "a different opening ephemeral");
                assert_eq!(
                    pending.address_root().expect("a root"),
                    root,
                    "a different address root, so a different ss0"
                );
                pending.establish().expect("establishes");
            }
            StoredChannelRestart::TornDown(t) => panic!("must resume: {t}"),
        }
    }

    // ---- restart's three answers, wired to a real store ---------------------

    /// A correspondence nothing ever wrote tears down, **and asking does not
    /// create it**. The second half is the store's `read_unlocked` contract, and
    /// it is checked here because this is the call that would break it — a
    /// startup sweep asking about every channel through a critical section would
    /// turn the directory listing into a list of everything ever probed (#253).
    #[test]
    fn asking_about_an_unknown_channel_tears_down_and_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(5);

        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::TornDown(t) => {
                assert_eq!(t.cause(), &TeardownCause::NoProvisionalRecord);
            }
            StoredChannelRestart::HandshakeResumes(_) => panic!("resumed from nothing"),
        }
        assert!(
            !p.store().root().join(hex::encode(l.as_bytes())).exists(),
            "asking about a channel brought its correspondence into existence"
        );
    }

    /// An interrupted erase is a record the store **lost**, never a store it
    /// could not read.
    ///
    /// The distinction drives behaviour rather than wording: `StoreUnreadable`
    /// promises "nothing is declared lost" and makes the outbox retain what it
    /// has queued, so reporting a destroyed handshake that way leaves the caller
    /// waiting on one that cannot come back.
    ///
    /// [`a_record_moved_between_correspondences_does_not_resume`] is this one's
    /// positive control: it pins that a store error which is *not* an interrupted
    /// erase still produces `StoreUnreadable`. Neither test can pass by
    /// collapsing every error to one answer, which is the failure mode a
    /// single-sided assertion here would hide.
    #[test]
    fn an_interrupted_erase_reads_as_a_lost_record_not_an_unreadable_store() {
        use crate::storage::dm_store::ERASURE_SENTINEL;

        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(9);
        p.save_provisional(&l, &ctx(), &record()).expect("saves");

        // The crash window: the scrub's first barrier landed, the unlink did not.
        let path = record_path(&p, &l, "provisional.bin");
        let mut raw = std::fs::read(&path).expect("reads");
        let sentinel_len = ERASURE_SENTINEL.len().min(raw.len());
        raw[..sentinel_len].copy_from_slice(&ERASURE_SENTINEL[..sentinel_len]);
        std::fs::write(&path, &raw).expect("writes");

        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::TornDown(t) => assert_eq!(
                t.cause(),
                &TeardownCause::NoProvisionalRecord,
                "an interrupted erase must report the record as lost, not the store as unreadable"
            ),
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("resumed from a record that was mid-erase")
            }
        }
    }

    /// A record saved for one channel does not resume another. The record's own
    /// seal is what refuses this; the store's cannot, because the label is not
    /// the channel context.
    #[test]
    fn a_record_does_not_resume_under_another_channels_context() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(6);
        p.save_provisional(&l, &ctx(), &record()).expect("saves");

        match p.restart_channel(&l, &other_ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::TornDown(t) => match t.cause() {
                TeardownCause::RecordUnusable(_) => {}
                other => panic!("expected an unusable record, got {other:?}"),
            },
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("resumed as the wrong correspondent")
            }
        }
    }

    /// A record's bytes moved into another correspondence's slot do not open.
    /// This is the store's seal refusing, not the record's — the two bindings
    /// catch different confusions, which is the whole reason both are applied.
    #[test]
    fn a_record_moved_between_correspondences_does_not_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (from, to) = (label(7), label(8));
        p.save_provisional(&from, &ctx(), &record()).expect("saves");
        // Establish the destination directory the ordinary way, then overwrite
        // its record with the source's bytes.
        p.save_provisional(&to, &ctx(), &record()).expect("saves");
        let stolen = std::fs::read(record_path(&p, &from, "provisional.bin")).expect("reads");
        std::fs::write(record_path(&p, &to, "provisional.bin"), &stolen).expect("writes");

        match p.restart_channel(&to, &ctx()) {
            StoredChannelRestart::Established(_) => {
                panic!("nothing wrote a resume record, so nothing can find one")
            }
            StoredChannelRestart::TornDown(t) => match t.cause() {
                // The store refuses before the record is ever reached, so this
                // is a failed *read*, and `restart` is right not to declare the
                // handshake lost over it.
                TeardownCause::StoreUnreadable(_) => {}
                other => panic!("expected an unreadable store, got {other:?}"),
            },
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("a record from another correspondence's slot opened")
            }
        }
    }

    /// The record reaches the disk sealed twice, and the file's length is the
    /// evidence: the store's bucket, nonce and tag wrap a payload that is
    /// already a complete sealed record.
    #[test]
    fn the_record_is_sealed_by_both_layers() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(9);
        p.save_provisional(&l, &ctx(), &record()).expect("saves");

        let on_disk = std::fs::metadata(record_path(&p, &l, "provisional.bin"))
            .expect("stat")
            .len() as usize;
        assert_eq!(on_disk, RecordKind::Provisional.on_disk_len());
        assert!(
            on_disk > PROVISIONAL_RECORD_LEN,
            "the file is no larger than the record's own sealed form, so only \
             one layer was applied"
        );
        // And the store's payload is exactly the record's sealed length, which
        // is what makes the bucket fit with no slack.
        assert_eq!(
            p.store()
                .read_unlocked(&l, RecordKind::Provisional)
                .expect("reads")
                .expect("present")
                .len(),
            PROVISIONAL_RECORD_LEN
        );
    }

    // ---- the outbox --------------------------------------------------------

    /// An outbox written under the lock comes back with its entry intact.
    #[test]
    fn an_outbox_round_trips_through_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(10);
        let now = 1_700_000_000_000i64;

        p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                4,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![0xAB; 12]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("updates");

        let loaded = p.read_outbox(&l, now).expect("reads").expect("present");
        assert_eq!(loaded.direction(), Direction::AToB);
        assert_eq!(loaded.len(), 1);
        let entry = loaded.entry(4).expect("the entry");
        assert_eq!(entry.composed_at_ms(), now);
        assert_eq!(entry.frame(), Some(&[0xABu8; 12][..]));
    }

    /// #347: a call that changes nothing spends **no seal**.
    ///
    /// The seal is the scarce resource, not the write. #289 measured this
    /// method's unconditional write as the dominant consumer of the store key's
    /// nonce budget — five hundred correspondences on a sixty-second tick reach
    /// 61% of 2^32 in ten years having sent nothing at all.
    ///
    /// **Two assertions, and the first is what makes the second mean anything.**
    /// A real mutation has to move the counter, or "zero seals" is
    /// indistinguishable from an instrument that never counts. The counter is
    /// asserted rather than the record's bytes: unchanged bytes imply no seal
    /// only while the write path is the sole reason bytes could stay put, and a
    /// skipped write is exactly what is being introduced here.
    #[test]
    fn a_no_op_update_spends_no_seal() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(38);
        let now = 1_700_000_000_000i64;

        let before_seed = p.store().seal_count();
        p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                7,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![0xCD; 12]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");

        let after_seed = p.store().seal_count();
        assert_eq!(
            after_seed - before_seed,
            1,
            "a mutating update must spend exactly one seal. The delta, not \
             `> 0`, is what makes the rest of this test mean anything: a write \
             re-added to the record-absent arm would spend its extra seal here, \
             inside the seed, silently inflating the baseline the no-op below is \
             compared against — and the probe would pass while carrying the very \
             regression it exists to catch"
        );

        p.update_outbox(&l, Direction::AToB, now, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");

        assert_eq!(
            p.store().seal_count(),
            after_seed,
            "an update that changed nothing must not seal"
        );
    }

    /// A no-op call does not pin the direction, because it stores no record.
    ///
    /// The mirror of `an_outbox_for_the_other_direction_is_refused`: that pins
    /// the refusal once an entry exists, this pins that there is nothing to
    /// refuse before one does. Without it, a change that restored the old
    /// materialising write would restore the refusal with it and no test would
    /// notice — the behaviour would silently revert to what #347 removed.
    #[test]
    fn a_no_op_does_not_pin_the_direction() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(39);
        let now = 1_700_000_000_000i64;

        // Snapshotted after the open, which itself seals the profile records
        // the store creates. The claim is about this call, so the delta is what
        // it has to be measured against.
        let before = p.store().seal_count();
        p.update_outbox(&l, Direction::AToB, now, |_| Ok(Mutation::Unchanged(())))
            .expect("a no-op against an absent record is not an error");

        assert_eq!(
            p.store().seal_count() - before,
            0,
            "a no-op against an absent record must not seal"
        );
        assert!(
            p.read_outbox(&l, now).expect("reads").is_none(),
            "no record was written, so there is none to read"
        );

        p.update_outbox(&l, Direction::BToA, now, |outbox| {
            outbox.enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![7]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("the other direction is accepted: nothing recorded the first");

        let loaded = p.read_outbox(&l, now).expect("reads").expect("present");
        assert_eq!(loaded.direction(), Direction::BToA);
    }

    /// A closure that changes the outbox and reports `Unchanged` is caught in
    /// debug builds rather than silently discarding the change.
    ///
    /// This is the one error [`Mutation`] cannot refuse by construction: the
    /// type forces an answer and cannot force a true one. Without this test the
    /// check has never executed in either direction, and an assertion nothing
    /// exercises is indistinguishable from one that cannot fire.
    #[test]
    #[should_panic(expected = "reported Mutation::Unchanged after changing the outbox")]
    #[cfg(debug_assertions)]
    fn a_lying_unchanged_report_is_caught_in_debug_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(41);
        let now = 1_700_000_000_000i64;

        let _ = p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![0x22; 8]),
                0,
            )?;
            // The lie: a real mutation reported as no change at all.
            Ok(Mutation::Unchanged(()))
        });
    }

    /// An empty sweep costs no seal — the composition #347 exists for.
    ///
    /// `sweep_give_ups` returning nothing and being reported as `Unchanged` must
    /// not write. The empty return is covered at unit level and the write is
    /// covered by the counter; nothing covered the two *together*, which is the
    /// entire claim of the change.
    #[test]
    fn a_sweep_that_gives_up_on_nothing_spends_no_seal() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(40);
        let now = 1_700_000_000_000i64;

        p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![0x11; 8]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");
        let after_seed = p.store().seal_count();

        // The same instant the entry was composed: nothing is anywhere near its
        // give-up window, so the empty branch is the one under test.
        let swept = p
            .update_outbox(&l, Direction::AToB, now, |outbox| {
                let given_up = outbox.sweep_give_ups(now);
                Ok(if given_up.is_empty() {
                    Mutation::Unchanged(given_up)
                } else {
                    Mutation::Changed(given_up)
                })
            })
            .expect("sweeps");

        assert!(
            swept.is_empty(),
            "the entry is not past its window; a non-empty sweep here would mean \
             this test exercised the Changed arm and proved nothing"
        );
        assert_eq!(
            p.store().seal_count(),
            after_seed,
            "a sweep that gave up on nothing must not seal"
        );
    }

    /// A correspondence with no outbox reads as `None` rather than as an empty
    /// one — "nothing queued" and "never queued anything" are different facts,
    /// and the second must not create a record to report itself.
    #[test]
    fn an_absent_outbox_is_none_and_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(11);
        assert!(p.read_outbox(&l, 0).expect("reads").is_none());
        assert!(!p.store().root().join(hex::encode(l.as_bytes())).exists());
    }

    /// **Bytes no encoder in this suite wrote.** The header is assembled here
    /// field by field and handed straight to the store, so a decoder that agreed
    /// with a wrong encoder would fail rather than pass: this pins the magic, the
    /// big-endian suite id, the direction tag and the big-endian entry count
    /// against literals, and since #323 the big-endian pruned high-water that sits
    /// between the direction and the count.
    #[test]
    fn a_hand_written_outbox_header_decodes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(12);

        let mut raw = Vec::new();
        raw.extend_from_slice(OUTBOX_MAGIC);
        raw.extend_from_slice(&Registry::default_write_suite().get().to_be_bytes());
        raw.push(1); // direction tag: BToA
        raw.extend_from_slice(&0u64.to_be_bytes()); // pruned high-water: nothing pruned
        raw.extend_from_slice(&0u64.to_be_bytes()); // next_send_seq: nothing sent
        raw.extend_from_slice(&0u32.to_be_bytes()); // last_clear_gen: the first chain
        raw.extend_from_slice(&0u32.to_be_bytes()); // no entries
        p.store()
            .critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, &raw))
            .expect("writes");

        let loaded = p.read_outbox(&l, 0).expect("reads").expect("present");
        assert_eq!(
            loaded.direction(),
            Direction::BToA,
            "the direction tag is not read as written"
        );
        assert!(loaded.is_empty());
    }

    /// The other direction's outbox is refused rather than quietly answered
    /// with the record's own direction.
    #[test]
    fn an_outbox_for_the_other_direction_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(13);
        let now = 1_700_000_000_000i64;

        // Seeded with a real entry, not an empty no-op call: since #347 an
        // `Unchanged` report writes nothing, so a no-op seed would leave no
        // stored direction for the second call to contradict and the refusal
        // under test could never fire.
        p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![9]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("updates");
        let err = p
            .update_outbox(&l, Direction::BToA, now, |_| Ok(Mutation::Unchanged(())))
            .expect_err("must refuse");
        match err {
            DmPersistError::OutboxDirectionMismatch { stored, requested } => {
                assert_eq!(stored, Direction::AToB);
                assert_eq!(requested, Direction::BToA);
            }
            other => panic!("expected a direction mismatch, got {other}"),
        }
    }

    /// A failing update writes nothing: the record is exactly what it was, so a
    /// caller may retry without having half-applied anything.
    #[test]
    fn a_failed_update_leaves_the_outbox_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(14);
        let now = 1_700_000_000_000i64;

        p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![1]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("updates");
        let before = std::fs::read(record_path(&p, &l, "outbox.bin")).expect("reads");

        let err = p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                2,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![2]),
                0,
            )?;
            // A duplicate: the module's own refusal, raised after a change was
            // already made to the in-memory copy.
            outbox.enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![3]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        });
        assert!(matches!(
            err,
            Err(DmPersistError::Outbox(OutboxError::DuplicateSequence(1)))
        ));

        assert_eq!(
            std::fs::read(record_path(&p, &l, "outbox.bin")).expect("reads"),
            before,
            "a failed update wrote to the record"
        );
        let loaded = p.read_outbox(&l, now).expect("reads").expect("present");
        assert_eq!(loaded.len(), 1, "the abandoned entry was persisted");
    }

    /// The durable surfacing flag (#279) survives the store: a give-up swept in
    /// one run is still owed a notification in the next. This is the whole point
    /// of the v2 record, and it could only ever be observed once something
    /// stored it.
    #[test]
    fn an_owed_surfacing_survives_a_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let l = label(15);
        let composed = 1_700_000_000_000i64;
        let later = composed + 8 * DAY_MS;

        {
            let p = persist(tmp.path());
            p.update_outbox(&l, Direction::AToB, composed, |outbox| {
                outbox.enqueue_sealed(
                    1,
                    OutboxTarget::ChannelPage,
                    composed,
                    SealedFrame::new(vec![0x5A; 8]),
                    0,
                )?;
                Ok(Mutation::Changed(()))
            })
            .expect("updates");

            let swept = p
                .update_outbox(&l, Direction::AToB, later, |outbox| {
                    // The shape every sweep caller wants: a tick that gave up on
                    // nothing reports `Unchanged` and costs no seal, which is
                    // the whole point of #347.
                    let given_up = outbox.sweep_give_ups(later);
                    Ok(if given_up.is_empty() {
                        Mutation::Unchanged(given_up)
                    } else {
                        Mutation::Changed(given_up)
                    })
                })
                .expect("sweeps");
            assert_eq!(swept, vec![1], "the entry was not past its window");
        }

        // A new process: the returned list from the sweep is gone, and only the
        // persisted flag can still report it.
        let p = persist(tmp.path());
        let loaded = p.read_outbox(&l, later).expect("reads").expect("present");
        assert_eq!(loaded.owed_surfacings(), vec![1]);
        assert_eq!(
            loaded.entry(1).expect("the entry").surfacing(),
            Surfacing::Owed
        );
    }

    // ---- the outbox prune caller (#323) -------------------------------------

    /// Bytes of one terminal channel entry: the fixed fields plus a
    /// `ChannelPage` tag, with no frame because a terminal entry has shed it.
    /// Spelled out rather than imported so a change to either constant shows up
    /// here as a failure instead of being tracked silently.
    const TERMINAL_ENTRY_LEN: usize =
        (8 /* seq */ + 8 /* composed_at_ms */ + 4 /* rung */ + 8 /* next_due_ms */
            + 4 /* sealed_under_gen */ + 1 /* acceptance */ + 1 /* surfacing */
            + 1 /* lifecycle */)
            + 1 /* a ChannelPage target tag */;

    /// How many prunable entries the fixtures below plant.
    ///
    /// Sized so the bytes they free comfortably exceed one padded entry, which
    /// is what `the_reclaim_precedes_the_closure_and_rescues_a_refused_enqueue`
    /// needs: too few and whether the rescue succeeds depends on where the fill
    /// loop happened to stop, so the test would pass or fail on arithmetic
    /// nobody chose.
    const PRUNABLE: u64 = 200;

    /// Plant `PRUNABLE` terminal, already-surfaced entries at sequences
    /// `1..=PRUNABLE`, then pad with live frames until the record is over
    /// [`OUTBOX_PRUNE_THRESHOLD`].
    ///
    /// The padding is deliberately made of *owed* frames, which pruning cannot
    /// touch: it is the only way to cross a 1 MiB threshold without enqueuing
    /// tens of thousands of entries, and it is also the realistic shape — a large
    /// outbox is large because of what it still owes.
    ///
    /// Returns the first sequence the fixture has not used.
    fn plant_over_threshold(outbox: &mut Outbox, t0: i64, later: i64) -> u64 {
        for seq in 1..=PRUNABLE {
            outbox
                .enqueue_awaiting_key(seq, OutboxTarget::ChannelPage, t0)
                .expect("enqueues");
        }
        let given_up = outbox.sweep_give_ups(later);
        assert_eq!(
            given_up.len(),
            PRUNABLE as usize,
            "the fixture depends on every planted entry going terminal"
        );
        outbox.record_surfaced(&given_up);

        let mut seq = PRUNABLE + 1;
        while outbox.encoded_len() < OUTBOX_PRUNE_THRESHOLD {
            outbox
                .enqueue_sealed(
                    seq,
                    OutboxTarget::ChannelPage,
                    later,
                    SealedFrame::new(vec![0xA5; 100_000]),
                    0,
                )
                .expect("enqueues");
            seq += 1;
        }
        seq
    }

    /// Above the threshold, an update prunes: the finished entries leave the
    /// record and it gets smaller by exactly their size.
    ///
    /// The byte delta is asserted exactly rather than as "smaller". A prune that
    /// removed one entry and a prune that removed all eight both shrink the
    /// record, and only the exact figure separates them from a prune whose
    /// predicate has quietly narrowed.
    #[test]
    fn an_over_threshold_update_prunes_and_the_record_shrinks() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(60);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        p.update_outbox(&l, Direction::AToB, t0, |outbox| {
            plant_over_threshold(outbox, t0, later);
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");

        let seeded = p.read_outbox(&l, later).expect("reads").expect("present");
        assert!(
            seeded.encoded_len() >= OUTBOX_PRUNE_THRESHOLD,
            "the fixture never crossed the threshold, so nothing below tests the trigger"
        );
        for seq in 1..=PRUNABLE {
            assert!(
                seeded.entry(seq).is_some(),
                "seeding must not prune: the record was under the threshold when \
                 that call took its reclaim decision"
            );
        }
        let before = seeded.encoded_len();

        // A call that changes nothing. Everything that happens to the record here
        // is the prune.
        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");

        let after = p.read_outbox(&l, later).expect("reads").expect("present");
        for seq in 1..=PRUNABLE {
            assert!(
                after.entry(seq).is_none(),
                "sequence {seq} is terminal and surfaced, so the prune owed us its bytes"
            );
        }
        assert_eq!(
            before - after.encoded_len(),
            PRUNABLE as usize * TERMINAL_ENTRY_LEN,
            "the record must shrink by exactly the pruned entries; a different \
             figure means the prune took the wrong set"
        );
        assert_eq!(
            after.pruned_high_water(),
            PRUNABLE + 1,
            "one past the highest sequence reclaimed"
        );
    }

    /// Below the threshold nothing is pruned, however prunable it is.
    ///
    /// This is the product half of the trigger: an ordinary correspondence keeps
    /// its full delivery history, because it will never come near the wall the
    /// prune exists to prevent.
    #[test]
    fn a_below_threshold_update_never_prunes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(61);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        p.update_outbox(&l, Direction::AToB, t0, |outbox| {
            for seq in 1..=PRUNABLE {
                outbox.enqueue_awaiting_key(seq, OutboxTarget::ChannelPage, t0)?;
            }
            let given_up = outbox.sweep_give_ups(later);
            outbox.record_surfaced(&given_up);
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");

        let seeded = p.read_outbox(&l, later).expect("reads").expect("present");
        assert!(
            seeded.encoded_len() < OUTBOX_PRUNE_THRESHOLD,
            "the fixture is meant to be small; it proves nothing if it is not"
        );
        // The control: every entry here *would* be taken by a prune, so the
        // survival below is the threshold's doing and not the predicate's.
        assert_eq!(
            seeded.clone().prune(),
            PRUNABLE as usize,
            "the fixture must be fully prunable, or it cannot show the threshold holding it back"
        );

        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");

        let after = p.read_outbox(&l, later).expect("reads").expect("present");
        assert_eq!(after.len(), PRUNABLE as usize);
        assert_eq!(after.pruned_high_water(), 0, "nothing was reclaimed");
    }

    /// The seal cost of the trigger, both halves.
    ///
    /// A prune that frees entries under an `Unchanged` closure spends exactly one
    /// seal, and the very next identical call spends none — so the cost tracks
    /// the backlog and not the polling cadence, which is the property #289 bought
    /// and #347 implemented.
    #[test]
    fn the_prune_spends_one_seal_for_the_backlog_and_none_thereafter() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(62);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        p.update_outbox(&l, Direction::AToB, t0, |outbox| {
            plant_over_threshold(outbox, t0, later);
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");

        let before = p.store().seal_count();
        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");
        assert_eq!(
            p.store().seal_count() - before,
            1,
            "a prune that actually reclaimed entries has to write them away, and \
             the write is one seal"
        );

        // Nothing is prunable now, and the record is still over the threshold, so
        // the scan runs and finds nothing. That must be free.
        let settled = p.store().seal_count();
        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");
        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");
        assert_eq!(
            p.store().seal_count(),
            settled,
            "a scan that reclaims nothing must not seal; if it does, every tick on \
             every large correspondence spends a seal for ever"
        );
        assert!(
            p.read_outbox(&l, later)
                .expect("reads")
                .expect("present")
                .encoded_len()
                >= OUTBOX_PRUNE_THRESHOLD,
            "the free calls above only mean something while the record is still \
             over the threshold and the scan is therefore still running"
        );
    }

    /// The reclaim happens before the closure, so it frees space the enqueue's
    /// own capacity gate can see.
    ///
    /// The refusal is demonstrated, not assumed: the same enqueue is first run
    /// against the unpruned record and must fail with
    /// [`OutboxError::Full`]. Without that control this test would pass just as
    /// well if the record had never been near capacity at all.
    #[test]
    fn the_reclaim_precedes_the_closure_and_rescues_a_refused_enqueue() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(63);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        // Fill to the point where one more small frame does not fit, but the
        // eight prunable entries are worth more than it needs.
        let admitted = p
            .update_outbox(&l, Direction::AToB, t0, |outbox| {
                let mut seq = plant_over_threshold(outbox, t0, later);
                loop {
                    let frame = SealedFrame::new(vec![0x5A; 4_096]);
                    match outbox.enqueue_sealed(seq, OutboxTarget::ChannelPage, later, frame, 0) {
                        Ok(_) => seq += 1,
                        Err(OutboxError::Full { .. }) => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(Mutation::Changed(seq))
            })
            .expect("seeds");

        // The control. This copy is what is on disk, unpruned, and it refuses.
        let mut unpruned = p.read_outbox(&l, later).expect("reads").expect("present");
        let refused = unpruned.enqueue_sealed(
            admitted,
            OutboxTarget::ChannelPage,
            later,
            SealedFrame::new(vec![0x5A; 4_096]),
            0,
        );
        assert!(
            matches!(refused, Err(OutboxError::Full { .. })),
            "the record is not actually full, so nothing below is a rescue: {refused:?}"
        );

        // The same enqueue through the persist path, where the prune runs first.
        p.update_outbox(&l, Direction::AToB, later, |outbox| {
            outbox.enqueue_sealed(
                admitted,
                OutboxTarget::ChannelPage,
                later,
                SealedFrame::new(vec![0x5A; 4_096]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("the prune ran before the closure, so the gate had the freed bytes");

        let after = p.read_outbox(&l, later).expect("reads").expect("present");
        assert!(
            after.entry(admitted).is_some(),
            "the rescued message must actually be in the record"
        );
    }

    /// Pads with live frames at the *low* sequences and plants the prunable
    /// entries *above* them, which is the shape decision 3 is about: the prune
    /// then takes the highest sequences the record holds and the surviving
    /// maximum genuinely regresses.
    ///
    /// Returns the highest sequence ever used and the highest that survives.
    fn plant_prunable_above_the_pads(outbox: &mut Outbox, t0: i64, later: i64) -> (u64, u64) {
        let mut pad = 1u64;
        while outbox.encoded_len() < OUTBOX_PRUNE_THRESHOLD {
            outbox
                .enqueue_sealed(
                    pad,
                    OutboxTarget::ChannelPage,
                    later,
                    SealedFrame::new(vec![0xA5; 100_000]),
                    0,
                )
                .expect("enqueues");
            pad += 1;
        }
        let highest_pad = pad - 1;
        for seq in pad..pad + PRUNABLE {
            outbox
                .enqueue_awaiting_key(seq, OutboxTarget::ChannelPage, t0)
                .expect("enqueues");
        }
        let given_up = outbox.sweep_give_ups(later);
        assert_eq!(
            given_up.len(),
            PRUNABLE as usize,
            "the pads were composed at `later` and must not expire; only the high \
             entries are meant to go terminal"
        );
        outbox.record_surfaced(&given_up);
        (pad + PRUNABLE - 1, highest_pad)
    }

    /// Decision 3: after a prune the surviving entries' maximum is genuinely
    /// lower than the highest sequence sent, and only the high-water recovers it.
    ///
    /// A ceiling is what
    /// [`AckState::merge_peer_ack`](crate::dm::ack::AckState::merge_peer_ack)
    /// clips a peer's claim to, so a regressed one reports delivered messages as
    /// undelivered. The two derivations must actually *differ* here, or a
    /// `merge_peer_ack` rewritten to clip against the map alone would pass.
    #[test]
    fn a_ceiling_from_the_surviving_entries_regresses_and_the_high_water_does_not() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(64);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        let (true_ceiling, highest_pad) = p
            .update_outbox(&l, Direction::AToB, t0, |outbox| {
                Ok(Mutation::Changed(plant_prunable_above_the_pads(
                    outbox, t0, later,
                )))
            })
            .expect("seeds");
        assert_eq!(
            p.read_outbox(&l, later)
                .expect("reads")
                .expect("present")
                .iter()
                .map(|e| e.seq())
                .max(),
            Some(true_ceiling),
            "before the prune both derivations agree; the divergence below is the prune's"
        );

        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");
        let after = p.read_outbox(&l, later).expect("reads").expect("present");

        let naive = after
            .iter()
            .map(|e| e.seq())
            .max()
            .expect("the pads survive");
        let corrected = naive.max(after.pruned_high_water().saturating_sub(1));

        assert_eq!(naive, highest_pad);
        assert!(
            naive < true_ceiling,
            "the derivations do not differ, so this fixture cannot tell a correct \
             ceiling from a regressed one: naive {naive}, sent {true_ceiling}"
        );
        assert_eq!(
            true_ceiling - naive,
            PRUNABLE,
            "the map is short by exactly the reclaimed range"
        );
        assert_eq!(
            corrected, true_ceiling,
            "the high-water is the only surviving record of the ceiling, and a \
             clip against `naive` would report {PRUNABLE} delivered messages as \
             undelivered"
        );
    }

    /// Decision 2: a live entry below the high-water stays reachable, and the
    /// unused sequences beneath the mark are what is burnt.
    ///
    /// Harmless under the monotonic per-direction counter the design already
    /// requires; this pins which of the two things actually happens, because the
    /// costly misreading is that pruning loses live entries.
    #[test]
    fn a_live_entry_below_the_high_water_survives_and_unused_sequences_do_not() {
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;
        let mut outbox = Outbox::new(Direction::AToB);

        // 2 is still owed; 5 finishes and is surfaced. 3 and 4 are never used.
        outbox
            .enqueue_sealed(
                5,
                OutboxTarget::ChannelPage,
                t0,
                SealedFrame::new(vec![0x11; 8]),
                0,
            )
            .expect("enqueues");
        let gone = outbox.sweep_give_ups(later);
        outbox.record_surfaced(&gone);
        outbox
            .enqueue_sealed(
                2,
                OutboxTarget::ChannelPage,
                later,
                SealedFrame::new(vec![0x22; 8]),
                0,
            )
            .expect("enqueues");

        assert_eq!(outbox.prune(), 1, "only sequence 5 qualifies");
        assert_eq!(outbox.pruned_high_water(), 6);
        assert!(
            outbox.entry(2).is_some(),
            "a live entry below the mark is reachable; pruning does not reach it"
        );
        for burnt in [3u64, 4] {
            assert!(
                matches!(
                    outbox.enqueue_sealed(
                        burnt,
                        OutboxTarget::ChannelPage,
                        later,
                        SealedFrame::new(vec![0x33; 8]),
                        0
                    ),
                    Err(OutboxError::DuplicateSequence(_))
                ),
                "sequence {burnt} was never used and is now refused for ever"
            );
        }
        outbox
            .enqueue_sealed(
                6,
                OutboxTarget::ChannelPage,
                later,
                SealedFrame::new(vec![0x44; 8]),
                0,
            )
            .expect("a monotonic allocator's next sequence is at the mark, and is accepted");
    }

    /// Decision 1: what the prune discards, nothing else retains — and the
    /// acknowledgement is the wrong place to look for it.
    ///
    /// One entry ends collected and one ends abandoned. After the prune the
    /// record cannot tell them apart, and neither can the ack: its contiguous
    /// prefix advances past a permanently lost message, so `is_settled` answers
    /// `true` for both. A surface that fell back to it would show *delivered* for
    /// a message nobody read.
    #[test]
    fn a_pruned_outcome_is_unrecoverable_and_the_ack_cannot_stand_in() {
        use crate::dm::ack::AckState;

        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        let mut ack = AckState::new();
        for seq in 0..=2 {
            ack.collect(seq).expect("collects");
        }

        let mut outbox = Outbox::new(Direction::AToB);
        outbox
            .enqueue_awaiting_key(1, OutboxTarget::ChannelPage, t0)
            .expect("enqueues");
        let abandoned = outbox.sweep_give_ups(later);
        assert_eq!(abandoned, vec![1]);
        outbox
            .enqueue_sealed(
                2,
                OutboxTarget::ChannelPage,
                later,
                SealedFrame::new(vec![0x77; 8]),
                0,
            )
            .expect("enqueues");
        let collected = outbox.settle_from_ack(&ack, later);
        assert_eq!(collected, vec![2]);

        assert_eq!(
            outbox.entry(1).expect("present").delivery_state(),
            DeliveryState::Undelivered
        );
        assert_eq!(
            outbox.entry(2).expect("present").delivery_state(),
            DeliveryState::ConfirmedCollected
        );

        outbox.record_surfaced(&[1, 2]);
        assert_eq!(outbox.prune(), 2);

        assert!(outbox.entry(1).is_none());
        assert!(outbox.entry(2).is_none());
        assert!(
            ack.is_settled(1) && ack.is_settled(2),
            "the ack reports the abandoned message as settled just as it does the \
             collected one, which is precisely why it cannot rebuild the distinction"
        );
    }

    /// A closure that fails after the prune has run writes nothing at all — the
    /// reclaim is discarded with everything else.
    ///
    /// The record is compared byte for byte, so a `guard.replace` moved up to sit
    /// immediately after the prune is caught here. That mutation compiles, leaves
    /// every other test in this file passing, and is invisible in release builds
    /// to the debug-only lying-`Unchanged` assert — this is the test that holds
    /// it.
    #[test]
    fn a_failing_closure_after_a_prune_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(65);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        p.update_outbox(&l, Direction::AToB, t0, |outbox| {
            plant_over_threshold(outbox, t0, later);
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");

        let before_bytes = std::fs::read(record_path(&p, &l, "outbox.bin")).expect("reads");
        let before_seals = p.store().seal_count();

        // The refusal is a duplicate of a *surviving* pad sequence, so it does not
        // depend on the prune having happened and cannot pass for the wrong reason.
        let err = p.update_outbox(&l, Direction::AToB, later, |outbox| {
            outbox.enqueue_sealed(
                PRUNABLE + 1,
                OutboxTarget::ChannelPage,
                later,
                SealedFrame::new(vec![0x01; 8]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        });
        assert!(
            matches!(err, Err(DmPersistError::Outbox(OutboxError::DuplicateSequence(s))) if s == PRUNABLE + 1),
            "the fixture must actually fail inside the closure: {err:?}"
        );

        assert_eq!(
            std::fs::read(record_path(&p, &l, "outbox.bin")).expect("reads"),
            before_bytes,
            "a failed update wrote to the record; the prune must not reach the disk \
             on a path the closure never completed"
        );
        assert_eq!(
            p.store().seal_count(),
            before_seals,
            "a failed update spent a seal"
        );
        let reloaded = p.read_outbox(&l, later).expect("reads").expect("present");
        for seq in 1..=PRUNABLE {
            assert!(
                reloaded.entry(seq).is_some(),
                "sequence {seq} was reclaimed in memory and the reclaim was persisted \
                 despite the closure failing"
            );
        }
    }

    /// A terminal entry costs the fixed length and nothing more, because it has
    /// shed its frame — which is what `TERMINAL_ENTRY_LEN` above claims and what
    /// the whole prune is worth.
    ///
    /// Every other fixture here plants `AwaitingKey` entries, whose lifecycle
    /// carries no frame at any point, so none of them measures the shedding.
    #[test]
    fn a_terminal_entry_has_shed_its_frame_and_costs_only_the_fixed_length() {
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;
        let mut outbox = Outbox::new(Direction::AToB);
        let header = outbox.encoded_len();

        outbox
            .enqueue_sealed(
                1,
                OutboxTarget::ChannelPage,
                t0,
                SealedFrame::new(vec![0xEE; 4_096]),
                0,
            )
            .expect("enqueues");
        assert_eq!(
            outbox.encoded_len(),
            header + TERMINAL_ENTRY_LEN + 8 + 4_096,
            "while it is owed, the entry costs its length-prefixed frame too"
        );

        let gone = outbox.sweep_give_ups(later);
        assert_eq!(gone, vec![1]);
        assert_eq!(
            outbox.encoded_len(),
            header + TERMINAL_ENTRY_LEN,
            "going terminal sheds the frame, and what is left is what the prune reclaims"
        );

        outbox.record_surfaced(&gone);
        assert_eq!(outbox.prune(), 1);
        assert_eq!(outbox.encoded_len(), header, "the entry is gone entirely");
    }

    /// The trigger fires *at* the threshold, not only above it.
    ///
    /// `>=` and `>` differ on exactly one record size and no padded fixture will
    /// ever land on it by accident, so this one is built to the byte.
    #[test]
    fn a_record_exactly_at_the_threshold_is_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(66);
        let t0 = 1_700_000_000_000i64;
        let later = t0 + 8 * DAY_MS;

        p.update_outbox(&l, Direction::AToB, t0, |outbox| {
            for seq in 1..=PRUNABLE {
                outbox.enqueue_awaiting_key(seq, OutboxTarget::ChannelPage, t0)?;
            }
            let given_up = outbox.sweep_give_ups(later);
            outbox.record_surfaced(&given_up);

            let mut seq = PRUNABLE + 1;
            while OUTBOX_PRUNE_THRESHOLD - outbox.encoded_len() > 200_000 {
                outbox.enqueue_sealed(
                    seq,
                    OutboxTarget::ChannelPage,
                    later,
                    SealedFrame::new(vec![0xA5; 100_000]),
                    0,
                )?;
                seq += 1;
            }
            // One last entry sized so the record lands exactly on the mark: a
            // live entry costs the fixed length, an eight-byte frame prefix, and
            // the frame.
            let gap = OUTBOX_PRUNE_THRESHOLD - outbox.encoded_len();
            outbox.enqueue_sealed(
                seq,
                OutboxTarget::ChannelPage,
                later,
                SealedFrame::new(vec![0x5A; gap - (TERMINAL_ENTRY_LEN + 8)]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");

        let seeded = p.read_outbox(&l, later).expect("reads").expect("present");
        assert_eq!(
            seeded.encoded_len(),
            OUTBOX_PRUNE_THRESHOLD,
            "the fixture is only a boundary test while it is exactly on the boundary"
        );

        p.update_outbox(&l, Direction::AToB, later, |_| Ok(Mutation::Unchanged(())))
            .expect("updates");

        let after = p.read_outbox(&l, later).expect("reads").expect("present");
        for seq in 1..=PRUNABLE {
            assert!(
                after.entry(seq).is_none(),
                "sequence {seq} survived a record sitting exactly on the threshold, \
                 so the comparison excludes the boundary"
            );
        }
    }

    // ---- the receive cursor ------------------------------------------------

    /// The cursor advances, persists, and is read back — and a caller that has
    /// read less than the file claims does not get the file's number.
    #[test]
    fn a_cursor_advances_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(16);

        assert!(p.read_cursor(&l, 100).expect("reads").is_none());
        assert!(p.advance_cursor(&l, 12, 20).expect("advances").moved());
        assert_eq!(
            p.read_cursor(&l, 20)
                .expect("reads")
                .expect("present")
                .page(),
            12
        );
    }

    /// **Bytes no encoder in this suite wrote.** Eight literal big-endian bytes
    /// go in through the store and must read as page 7; the same eight in the
    /// other order must not. A `to_be_bytes`/`from_be_bytes` pair that agreed on
    /// little-endian would pass a round trip and fail both halves of this.
    #[test]
    fn a_hand_written_cursor_is_read_big_endian() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (be, le) = (label(17), label(18));

        p.store()
            .critical_section::<_, DmStoreError>(&be, |g| {
                g.replace(RecordKind::ReceiveCursor, &[0, 0, 0, 0, 0, 0, 0, 7])
            })
            .expect("writes");
        assert_eq!(
            p.read_cursor(&be, 7)
                .expect("reads")
                .expect("present")
                .page(),
            7
        );

        p.store()
            .critical_section::<_, DmStoreError>(&le, |g| {
                g.replace(RecordKind::ReceiveCursor, &[7, 0, 0, 0, 0, 0, 0, 0])
            })
            .expect("writes");
        // Read big-endian this is 0x0700_0000_0000_0000 — past both MAX_PAGE and
        // anything a caller has read, so it must be refused rather than
        // returning 7.
        assert!(matches!(
            p.read_cursor(&le, 7),
            Err(DmPersistError::CursorNotCorroborated { read_through: 7 })
        ));
    }

    /// A cursor past what the caller has read is refused, not returned and not
    /// silently reported as absent.
    #[test]
    fn a_cursor_past_what_was_read_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(19);
        assert!(p.advance_cursor(&l, 40, 40).expect("advances").moved());

        assert!(matches!(
            p.read_cursor(&l, 3),
            Err(DmPersistError::CursorNotCorroborated { read_through: 3 })
        ));
        // The same file, corroborated: the refusal was about the caller's
        // knowledge and not about the record.
        assert_eq!(
            p.read_cursor(&l, 40)
                .expect("reads")
                .expect("present")
                .page(),
            40
        );
    }

    /// A refused advance writes nothing, so it cannot leave behind a number the
    /// next read would decline to believe.
    #[test]
    fn a_refused_advance_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(20);
        assert!(p.advance_cursor(&l, 9, 9).expect("advances").moved());
        let before = std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads");

        // Backwards, and past what was read: both refusals.
        assert!(!p.advance_cursor(&l, 4, 9).expect("refuses").moved());
        assert!(!p.advance_cursor(&l, 50, 20).expect("refuses").moved());
        assert!(
            !p.advance_cursor(&l, MAX_PAGE + 1, u64::MAX)
                .expect("refuses")
                .moved()
        );

        assert_eq!(
            std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads"),
            before,
            "a refused advance wrote to the record"
        );
    }

    /// This module supplies exactly eight bytes, and the disk holds none of
    /// them (#389).
    ///
    /// The payload width is this module's contract — [`decode_cursor`] refuses
    /// anything else — and it is checked from this side because this is the
    /// module that produces it. The store's side is the file: sealed, padded to
    /// one width, and carrying the page number nowhere a reader without the key
    /// can find it.
    #[test]
    fn the_cursor_is_eight_sealed_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(21);
        assert!(p.advance_cursor(&l, 258, 258).expect("advances").moved());

        let raw = std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads");
        assert_eq!(
            raw.len(),
            RecordKind::ReceiveCursor.on_disk_len(),
            "the record is not a sealed record's width"
        );

        let page = 258u64.to_be_bytes();
        // Positive control: the same search over the same width finds the value
        // when it is planted, so the absence below is absence.
        let mut planted = raw.clone();
        planted[..RECEIVE_CURSOR_LEN].copy_from_slice(&page);
        assert!(planted.windows(RECEIVE_CURSOR_LEN).any(|w| w == page));
        assert!(
            !raw.windows(RECEIVE_CURSOR_LEN).any(|w| w == page),
            "the page number is on disk verbatim"
        );

        // And the value is still recoverable through the one call that bounds
        // it, so the assertion above is not about a write that never happened.
        assert_eq!(
            p.read_cursor(&l, 258).expect("reads").map(|c| c.page()),
            Some(258)
        );
    }

    /// A full-width, authentic record whose payload is not eight bytes is
    /// refused as a payload-shape error, not as a file-length one.
    ///
    /// The store's fixed size bounds the file; the seal carries the payload's
    /// own length prefix, so `replace(ReceiveCursor, &[..3])` writes a valid
    /// 40-byte record that opens to three bytes. A file-length error cannot
    /// describe that: `WrongFileLen { expected: 8, actual: 3 }` reads as a
    /// three-byte file.
    #[test]
    fn a_cursor_record_whose_payload_is_not_eight_bytes_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(23);

        for short in [0usize, 3, RECEIVE_CURSOR_LEN - 1] {
            p.store()
                .critical_section::<_, DmStoreError>(&l, |g| {
                    g.replace(RecordKind::ReceiveCursor, &vec![0xABu8; short])
                })
                .expect("writes");

            // The file is well-formed: full width, and it opens. Without this the
            // refusal below could be about a damaged record.
            let raw = std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads");
            assert_eq!(raw.len(), RecordKind::ReceiveCursor.on_disk_len());
            assert_eq!(
                p.store()
                    .read_unlocked(&l, RecordKind::ReceiveCursor)
                    .expect("opens")
                    .map(|v| v.len()),
                Some(short),
                "the record must open to the short payload"
            );

            let err = p
                .read_cursor(&l, u64::MAX)
                .expect_err("a short cursor payload must not decode");
            assert!(
                matches!(
                    err,
                    DmPersistError::CursorPayloadWrongLen {
                        expected: RECEIVE_CURSOR_LEN,
                        actual,
                    } if actual == short
                ),
                "got {err:?}"
            );
        }

        // Positive control: eight bytes in the same slot decode, so the refusals
        // above are the payload width and not a correspondence that stopped
        // working. Written through the store rather than `advance_cursor`, which
        // repairs an unreadable record and would make this pass either way.
        p.store()
            .critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::ReceiveCursor, &11u64.to_be_bytes())
            })
            .expect("writes");

        assert_eq!(
            p.read_cursor(&l, 11).expect("reads").map(|c| c.page()),
            Some(11)
        );
    }

    /// An unreadable `cursor.bin` is replaced by the next advance, and says so.
    ///
    /// **The wedge this closes.** The advance's read happens inside its critical
    /// section, so a record that will not read fails the write too: the bad bytes
    /// stay, every boot rescans from page zero, every frame comes back
    /// already-consumed, and the only report is a trace line. Both shapes are
    /// driven — a tampered full-width record and a clear eight-byte one — because
    /// they fail at different checks (`NotAuthentic` and `WrongFileLen`) and a
    /// repair keyed on one would leave the other wedged.
    ///
    /// Nothing is adopted: what lands is this caller's own page.
    #[test]
    fn an_unreadable_cursor_record_is_repaired_by_the_next_advance() {
        for (name, wreck) in [
            (
                "tampered",
                Box::new(|raw: Vec<u8>| {
                    let mut b = raw;
                    // Flip a ciphertext byte: full width, authentic-looking, and
                    // it will not open.
                    let last = b.len() - 1;
                    b[last] ^= 0xFF;
                    b
                }) as Box<dyn Fn(Vec<u8>) -> Vec<u8>>,
            ),
            (
                "clear eight bytes",
                Box::new(|_: Vec<u8>| 4_096u64.to_be_bytes().to_vec()),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let p = persist(tmp.path());
            let l = label(24);
            let path = record_path(&p, &l, "cursor.bin");

            assert!(
                p.advance_cursor(&l, 3, 3).expect("advances").moved(),
                "{name}: setup"
            );
            let good = std::fs::read(&path).expect("reads");
            std::fs::write(&path, wreck(good.clone())).expect("wrecks the record");

            // Positive control: the record really is unreadable now, so the
            // repair below is a repair and not a no-op.
            assert!(
                p.read_cursor(&l, u64::MAX).is_err(),
                "{name}: the wrecked record still reads"
            );

            let advance = p.advance_cursor(&l, 5, 5).expect("advances over a wreck");
            assert!(advance.repaired(), "{name}: the repair was not reported");
            assert!(advance.moved(), "{name}: the caller's page did not land");

            // The record is valid, sealed, and holds the caller's own number —
            // never the wrecked file's.
            let raw = std::fs::read(&path).expect("reads");
            assert_eq!(
                raw.len(),
                RecordKind::ReceiveCursor.on_disk_len(),
                "{name}: the repaired record is not a sealed record's width"
            );
            assert_eq!(
                p.read_cursor(&l, 5).expect("reads").map(|c| c.page()),
                Some(5),
                "{name}: the repaired cursor does not read back"
            );

            // And the repair is reported once: the next advance over a healthy
            // record is an ordinary one.
            let next = p.advance_cursor(&l, 6, 6).expect("advances");
            assert!(next.moved(), "{name}: the next advance did not move");
            assert!(!next.repaired(), "{name}: the repair was reported twice");
        }
    }

    /// An environment failure is not a licence to overwrite the record.
    ///
    /// The repair above keys on the record being unreadable. `is_unreadable_record`
    /// is the split, and it is exhaustive so a new store error has to be
    /// classified rather than defaulting into the repairing half — this pins both
    /// sides of it, since a mutation that returned `true` for everything would
    /// make a failed lock or a failed IO destroy a good cursor.
    ///
    /// The public [`DmPersistError::is_unreadable_record`] is driven here too,
    /// including the arm the `Store` wrapper cannot reach
    /// ([`DmPersistError::CursorPayloadWrongLen`]) and the one that matters most
    /// to a cold start ([`DmPersistError::CursorNotCorroborated`], which is a
    /// record that read perfectly well).
    #[test]
    fn only_an_unreadable_record_licenses_a_repair() {
        for e in [
            DmStoreError::WrongFileLen {
                kind: RecordKind::ReceiveCursor,
                expected: 40,
                actual: 8,
            },
            DmStoreError::NotAuthentic {
                kind: RecordKind::ReceiveCursor,
            },
            DmStoreError::ErasureInterrupted {
                kind: RecordKind::ReceiveCursor,
            },
            DmStoreError::CorruptPayloadLen {
                kind: RecordKind::ReceiveCursor,
                declared: 99,
                capacity: RECEIVE_CURSOR_LEN,
            },
        ] {
            assert!(is_unreadable_record(&e), "{e:?} must license a repair");
        }

        for e in [
            DmStoreError::Reentrant,
            DmStoreError::Kdf,
            DmStoreError::Module,
            DmStoreError::Io {
                path: std::path::PathBuf::from("/nonexistent"),
                source: std::io::Error::other("disk"),
            },
        ] {
            assert!(!is_unreadable_record(&e), "{e:?} must not license a repair");
        }

        // The public wrapper, including the two arms that are not a `Store`
        // error at all and so cannot be reached through the loops above.
        assert!(
            DmPersistError::CursorPayloadWrongLen {
                expected: RECEIVE_CURSOR_LEN,
                actual: 3,
            }
            .is_unreadable_record(),
            "a record that opens to the wrong payload width must license a repair"
        );
        assert!(
            !DmPersistError::CursorNotCorroborated { read_through: 0 }.is_unreadable_record(),
            "an uncorroborated cursor read perfectly well — repairing it would \
             rewrite a healthy record at every cold start"
        );
        assert!(
            DmPersistError::Store(DmStoreError::NotAuthentic {
                kind: RecordKind::ReceiveCursor,
            })
            .is_unreadable_record(),
            "the wrapper must carry the store's own verdict through"
        );
        assert!(
            !DmPersistError::BlockListMissing.is_unreadable_record(),
            "an unrelated variant must not license a repair"
        );
    }

    /// A cursor file left in the clear is refused, not adopted (#389).
    ///
    /// **Nothing migrates, deliberately.** The at-rest format is unreleased, so
    /// no such file exists in the field; the store's migrations
    /// (`storage::seeds::touch_reseal`, `storage::recovery_file::open_v1`) exist
    /// for formats that shipped and are gated on an explicit magic, which
    /// `cursor.bin` has never had — a legacy file is distinguishable only by its
    /// width. Accepting one would leave a permanent door that takes an
    /// unauthenticated page number off the disk, which is the whole of what this
    /// change closed.
    ///
    /// The refusal needs no new code: the file is not the kind's width, so the
    /// store's own length check names it. What this pins is that it stays a
    /// refusal — a value planted in the clear is never handed back as a cursor.
    ///
    /// **The advance path does not refuse it, it repairs it**
    /// (`an_unreadable_cursor_record_is_repaired_by_the_next_advance`), because a
    /// record that will not read cannot be written past either and would wedge
    /// the correspondence for ever. Repairing adopts nothing, and the assertion
    /// that the caller's own page — not the clear file's number — is what reads
    /// back afterwards is what says so.
    #[test]
    fn a_clear_cursor_file_is_refused_rather_than_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(22);

        // Establish the correspondence and a real cursor, then overwrite it with
        // exactly what the pre-#389 store wrote: eight clear bytes.
        assert!(p.advance_cursor(&l, 3, 3).expect("advances").moved());
        let path = record_path(&p, &l, "cursor.bin");
        let decoy = 4_096u64.to_be_bytes();
        std::fs::write(&path, decoy).expect("plants the decoy");

        let err = p
            .read_cursor(&l, u64::MAX)
            .expect_err("a clear cursor must not read as a cursor");
        assert!(
            matches!(
                err,
                DmPersistError::Store(DmStoreError::WrongFileLen {
                    kind: RecordKind::ReceiveCursor,
                    ..
                })
            ),
            "got {err:?}"
        );

        // The advance path does not adopt it either, and does not wedge on it:
        // it repairs (`an_unreadable_cursor_record_is_repaired_by_the_next_advance`
        // drives both shapes) and what lands is the caller's own page, never the
        // decoy's 4096.
        let advance = p.advance_cursor(&l, 5, 5).expect("repairs and advances");
        assert!(
            advance.repaired(),
            "the clear file was not reported repaired"
        );
        assert!(advance.moved(), "the caller's own page did not land");
        assert_ne!(
            std::fs::read(&path).expect("reads"),
            decoy,
            "the clear bytes are still on disk"
        );
        // Nothing from the decoy is adopted: 4096 was the number in the clear
        // and 5 is what this caller supplied, bounded by its own reading.
        assert_eq!(
            p.read_cursor(&l, u64::MAX)
                .expect("reads")
                .map(|c| c.page()),
            Some(5),
            "the decoy's number survived the repair"
        );

        // Reported once: a second advance over the now-healthy record is
        // ordinary.
        let next = p.advance_cursor(&l, 6, 6).expect("advances");
        assert!(next.moved() && !next.repaired(), "the repair repeated");

        // Positive control: the repaired record reads back as the caller's page,
        // so the refusal above is about the clear file and not about a
        // correspondence that stopped working.
        p.store()
            .critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::ReceiveCursor, &9u64.to_be_bytes())
            })
            .expect("writes");

        assert_eq!(
            p.read_cursor(&l, u64::MAX)
                .expect("reads")
                .map(|c| c.page()),
            Some(9)
        );
    }
    // ------------------------------------------------------------ the resume record (A9.2)

    fn resume_record(attempt: u32, floor: SendFloor) -> ResumeRecord {
        resume_record_sealed(attempt, floor, 0xA5)
    }

    /// The per-correspondent signing key an acceptance hands
    /// [`DmPersist::accept_first_contact`] to write into the resume record.
    ///
    /// Fixed bytes rather than a keygen: the call stores the key and never signs
    /// with it, so what these tests read back is whatever they passed in.
    fn accepting_s_pc() -> [u8; ml_dsa::SK_LEN] {
        [0x71u8; ml_dsa::SK_LEN]
    }

    /// Walk to `attempt` the way a real caller must.
    ///
    /// There is no shortcut on purpose: `FreshAttempt` is mintable only by
    /// [`FreshAttempt::first`] and [`Attempt::advance`], so a fixture that wants
    /// attempt N walks there. That keeps these tests exercising the API a
    /// production caller is actually given rather than a test-only back door.
    fn fresh(attempt: u32) -> crate::dm::resume::FreshAttempt {
        let mut token = crate::dm::resume::FreshAttempt::first();
        while token.attempt().get() < attempt {
            token = token
                .attempt()
                .advance()
                .expect("the fixture stays far below u32::MAX");
        }
        assert_eq!(
            token.attempt().get(),
            attempt,
            "the walk overshot — every fixture attempt must be reachable from FIRST"
        );
        token
    }

    /// The stored record's attempt as a number, which is what these assertions
    /// compare — and an `expect` on the slot, because every fixture here
    /// occupies it.
    fn attempt_number(p: &DmPersist, l: &CorrespondenceLabel) -> u32 {
        p.read_resume(l)
            .expect("reads")
            .expect("there")
            .attempt()
            .expect("the fixture's handshake slot is occupied")
            .get()
    }

    fn resume_record_sealed(attempt: u32, floor: SendFloor, seal: u8) -> ResumeRecord {
        ResumeRecord::new(
            Box::new([0x11u8; oxicrypt_ml_dsa::SK_LEN]),
            Box::new([0x22u8; oxicrypt_ml_dsa::PK_LEN]),
            crate::dm::resume::CommittedRoot::from_bytes(
                &[0x33u8; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            crate::dm::resume::ReEstState {
                reconnect_gen: 0,
                attempt,
                last_seen_re_est: 0,
                own: Some(crate::dm::resume::OwnSlot::new(
                    1,
                    77,
                    crate::dm::resume::SealedReEst::seal(
                        fresh(attempt),
                        vec![seal; 256].into_boxed_slice(),
                    )
                    .expect("within MAX_FRAME_LEN"),
                    eph_dk_fixture(),
                )),
                acceptance: None,
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        )
        .expect("the fixture's pairings are coherent")
    }

    /// The commit returns the bytes to emit, and only after the record is on
    /// disk — so there is no ordering in which an emitted attempt is not also a
    /// persisted one.
    #[test]
    fn a_commit_persists_the_record_and_hands_back_the_frame() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x51);

        assert!(
            p.read_resume(&l).expect("reads").is_none(),
            "fixture is not empty"
        );

        let record = resume_record(1, SendFloor::new(4, 100));
        let emitted = p.commit_resume(&l, &record).expect("commits");
        assert_eq!(
            emitted.as_deref(),
            record.sealed_re_est(),
            "the caller was handed something other than the persisted seal"
        );

        let stored = p
            .read_resume(&l)
            .expect("reads")
            .expect("a record was committed");
        assert_eq!(stored.attempt(), crate::dm::resume::Attempt::FIRST.into());
        assert_eq!(stored.send_floor(), SendFloor::new(4, 100));
        assert_eq!(
            stored.sealed_re_est(),
            record.sealed_re_est(),
            "A9.1's byte-identical re-emit is unavailable after a restart"
        );
        assert_eq!(stored.s_pc(), record.s_pc());
    }

    /// The send-side floor is an anti-rollback bound, so a write carrying an
    /// earlier one is refused rather than overwriting it.
    #[test]
    fn a_commit_may_not_move_the_send_floor_backwards() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x52);

        p.commit_resume(&l, &resume_record(1, SendFloor::new(4, 100)))
            .expect("first commit");

        let err = p
            .commit_resume(&l, &resume_record(2, SendFloor::new(4, 99)))
            .expect_err("a regressing floor was accepted");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::FloorWouldRollBack { .. })
            ),
            "wrong error: {err:?}"
        );

        // And the refusal wrote nothing: the stored record is untouched, which
        // a refusal that had already replaced the file would not leave.
        let stored = p.read_resume(&l).expect("reads").expect("still there");
        assert_eq!(stored.attempt(), crate::dm::resume::Attempt::FIRST.into());
        assert_eq!(stored.send_floor(), SendFloor::new(4, 100));
    }

    /// An unmoved floor is admitted, because a resume record is rewritten for
    /// reasons the send side knows nothing about — a new attempt, here.
    #[test]
    fn a_commit_with_an_unmoved_floor_is_admitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x53);
        let floor = SendFloor::new(4, 100);

        p.commit_resume(&l, &resume_record(1, floor))
            .expect("first commit");
        p.commit_resume(&l, &resume_record(2, floor))
            .expect("an unmoved floor was refused on a new attempt");

        assert_eq!(attempt_number(&p, &l), 2);
    }

    /// A generation bump that carries the sequence forward is admitted — the
    /// bump itself is never the rollback.
    #[test]
    fn a_commit_under_a_new_generation_is_admitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x54);

        p.commit_resume(&l, &resume_record(1, SendFloor::new(4, 100)))
            .expect("first commit");
        p.commit_resume(&l, &resume_record(2, SendFloor::new(5, 100)))
            .expect("a generation bump was read as a rollback");
    }

    /// **But it may not carry the sequence backwards.** Lexicographically
    /// `(5, 0)` outranks `(4, 100)`, so a write guard deferring to `Ord` would
    /// admit this — and against the ratchet as built, where send `seq` never
    /// restarts, it discards 100 spent sequences. See `SendFloor::admits`.
    #[test]
    fn a_generation_bump_may_not_carry_the_sequence_backwards() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x57);

        p.commit_resume(&l, &resume_record(1, SendFloor::new(4, 100)))
            .expect("first commit");
        let err = p
            .commit_resume(&l, &resume_record(2, SendFloor::new(5, 0)))
            .expect_err("a sequence rollback rode in on a generation bump");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::FloorWouldRollBack { .. })
            ),
            "wrong error: {err:?}"
        );
    }

    /// **A re-establishment cannot carry the send floor's generation backwards
    /// either, and the persist guard is what stops it.**
    ///
    /// `ResumeRecord::commit_reestablished` writes the floor with a plain
    /// `SendFloor::new(ratchet_gen, seq)` rather than through
    /// `SendFloor::advance_to`, so the type itself refuses nothing at that
    /// point — a caller handing it a ratchet generation below the stored floor's
    /// spells a rollback the record would happily hold. What refuses it is
    /// `commit_resume`'s `SendFloor::admits` gate, which requires **both**
    /// components non-decreasing.
    ///
    /// This is the mirror of `a_generation_bump_may_not_carry_the_sequence_backwards`:
    /// that one drops the sequence under a rising generation, this one drops the
    /// generation while the sequence stands still. Both are rollbacks and both
    /// must be refused, and neither test catches the other's direction.
    #[test]
    fn a_reestablishment_may_not_carry_the_floor_generation_backwards() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x5E);
        let now = 1_700_000_000_000i64;

        p.commit_resume(&l, &resume_record(1, SendFloor::new(5, 100)))
            .expect("first commit");
        let before = p.read_resume(&l).expect("reads").expect("there");
        let before_root = before.committed_root().as_bytes().to_vec();
        let before_gen = before.reconnect_gen();
        assert_eq!(before.send_floor(), SendFloor::new(5, 100));

        let rerooted = || {
            crate::dm::resume::reroot(
                &crate::dm::resume::CommittedRoot::from_bytes(
                    &[0x33u8; crate::dm::ratchet::ROOT_KEY_LEN],
                ),
                &[0x09u8; 32],
            )
            .expect("the module is operational")
        };
        let confirm_slot = |generation: u32| {
            crate::dm::resume::ConfirmSlot::new(
                generation,
                200,
                vec![0xCFu8; 64].into_boxed_slice(),
            )
            .expect("within the leg ceiling")
        };

        // The re-rooted chain opens at a generation BELOW the stored floor's.
        let mut rolled_back = resume_record(1, SendFloor::new(5, 100));
        let _chan_id = rolled_back.commit_reestablished(rerooted(), 3, now, confirm_slot(3));
        assert_eq!(
            rolled_back.send_floor(),
            SendFloor::new(3, 100),
            "the record itself does not refuse the rollback, which is why the guard must"
        );
        let err = p
            .commit_resume(&l, &rolled_back)
            .expect_err("a floor generation rollback was persisted");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::FloorWouldRollBack { .. })
            ),
            "wrong error: {err:?}"
        );

        // And the refused write left the record exactly as it was.
        let after = p.read_resume(&l).expect("reads").expect("there");
        assert_eq!(after.send_floor(), SendFloor::new(5, 100));
        assert_eq!(after.committed_root().as_bytes().to_vec(), before_root);
        assert_eq!(after.reconnect_gen(), before_gen);

        // Positive control: the same act at a generation above the floor's is
        // admitted, so the refusal is about the direction rather than about a
        // guard that refuses every re-establishment.
        let mut forward = resume_record(1, SendFloor::new(5, 100));
        let _chan_id = forward.commit_reestablished(rerooted(), 7, now, confirm_slot(7));
        p.commit_resume(&l, &forward)
            .expect("a forward re-establishment must be admitted");
        assert_eq!(
            p.read_resume(&l)
                .expect("reads")
                .expect("there")
                .send_floor(),
            SendFloor::new(7, 100)
        );
    }

    /// A9.1: a persisted attempt is re-emitted as the byte-identical persisted
    /// seal, so committing **different** bytes under one is refused.
    ///
    /// Without this the peer, which dedups on `attempt`, has already seen the
    /// first seal and drops the second as a duplicate — leaving this party
    /// holding a secret the peer will never confirm, which is the permanent
    /// `UnknownEphemeral` divergence.
    #[test]
    fn a_persisted_attempt_may_not_be_resealed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x58);
        let floor = SendFloor::new(4, 100);

        p.commit_resume(&l, &resume_record_sealed(1, floor, 0xA5))
            .expect("first commit");

        // Re-committing the SAME attempt with the SAME bytes is the ordinary
        // idempotent case and must still work.
        p.commit_resume(&l, &resume_record_sealed(1, floor, 0xA5))
            .expect("an identical re-commit of one attempt was refused");

        let err = p
            .commit_resume(&l, &resume_record_sealed(1, floor, 0x5A))
            .expect_err("a persisted attempt was re-sealed");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::AttemptResealed { attempt: 1 })
            ),
            "wrong error: {err:?}"
        );

        // The refusal wrote nothing: the first seal is still the stored one, so
        // recovery still re-emits the bytes the peer actually saw.
        let stored = p.read_resume(&l).expect("reads").expect("there");
        assert_eq!(stored.sealed_re_est(), Some(&[0xA5u8; 256][..]));

        // And a NEW attempt may carry fresh bytes — that is A9.1's other half.
        p.commit_resume(&l, &resume_record_sealed(2, floor, 0x5A))
            .expect("a new attempt was refused fresh bytes");
    }

    /// The attempt counter is monotone, for the same reason the floor is.
    #[test]
    fn a_commit_may_not_move_the_attempt_backwards() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x59);
        let floor = SendFloor::new(4, 100);

        p.commit_resume(&l, &resume_record(5, floor))
            .expect("first commit");
        let err = p
            .commit_resume(&l, &resume_record(4, floor))
            .expect_err("an attempt regression was accepted");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::AttemptWouldRollBack {
                    stored: 5,
                    offered: 4
                })
            ),
            "wrong error: {err:?}"
        );
        assert_eq!(attempt_number(&p, &l), 5);
    }

    /// Two correspondences do not share a resume record.
    #[test]
    fn a_resume_record_is_per_correspondence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());

        p.commit_resume(&label(0x55), &resume_record(1, SendFloor::new(1, 1)))
            .expect("commits");
        assert!(
            p.read_resume(&label(0x56)).expect("reads").is_none(),
            "one correspondence's resume record was visible to another"
        );
    }

    // ------------------------------------------- first establishment (A4.8)

    /// A per-correspondent pseudonym keypair, deterministic in `tag` so two of
    /// them are distinct and reproducible.
    fn pseudonym(tag: u8) -> crate::identity::keys::SignKeypair {
        crate::identity::keys::SignKeypair::from_ml_dsa_seed(
            &[tag; crate::identity::keys::ML_DSA_SEED_LEN],
        )
        .expect("the module is initialized by `persist`")
    }

    /// The record a first establishment writes: the pseudonym pair, and a
    /// handshake slot standing empty because no re-establishment frame exists.
    fn opening_record(
        ours: &crate::identity::keys::SignKeypair,
        theirs: &crate::identity::keys::SignKeypair,
        floor: SendFloor,
    ) -> ResumeRecord {
        ResumeRecord::new(
            Box::new(*ours.secret_key()),
            Box::new(*theirs.public_key()),
            crate::dm::resume::CommittedRoot::from_bytes(
                &[0x77u8; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            crate::dm::resume::ReEstState::first_establishment(),
            crate::dm::resume::Retention::none(),
            floor,
        )
        .expect("the fixture's pairings are coherent")
    }

    /// A re-establishment record carrying the same pseudonym pair as
    /// [`opening_record`], so a fixture can advance the attempt without also
    /// changing the keys — which the pair guard refuses independently.
    fn re_established_record(
        ours: &crate::identity::keys::SignKeypair,
        theirs: &crate::identity::keys::SignKeypair,
        attempt: u32,
        floor: SendFloor,
    ) -> ResumeRecord {
        ResumeRecord::new(
            Box::new(*ours.secret_key()),
            Box::new(*theirs.public_key()),
            crate::dm::resume::CommittedRoot::from_bytes(
                &[0x77u8; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            crate::dm::resume::ReEstState {
                reconnect_gen: 0,
                attempt,
                last_seen_re_est: 0,
                own: Some(crate::dm::resume::OwnSlot::new(
                    1,
                    77,
                    crate::dm::resume::SealedReEst::seal(
                        fresh(attempt),
                        vec![0xA5u8; 256].into_boxed_slice(),
                    )
                    .expect("within MAX_FRAME_LEN"),
                    eph_dk_fixture(),
                )),
                acceptance: None,
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        )
        .expect("the fixture's pairings are coherent")
    }

    /// A correspondence established in one process can still sign and verify in
    /// the next one.
    ///
    /// The keys are exercised rather than compared: reading the bytes back only
    /// says the encoding round-tripped, and what the correspondence needs is
    /// that the recovered secret signs under the public half the peer holds, and
    /// that the recovered verifying key accepts what the peer signs. The
    /// crossed-key control at the end is what stops both halves passing under
    /// one key.
    #[test]
    fn a_correspondence_signs_and_verifies_after_a_restart() {
        const OUTBOUND: &[u8] = b"a frame this party sends";
        const INBOUND: &[u8] = b"a frame the correspondent sends";

        let dir = tempfile::tempdir().expect("tempdir");
        let l = label(0x61);
        let ours = pseudonym(0x01);
        let theirs = pseudonym(0x02);

        {
            let p = persist(dir.path());
            p.save_provisional(&l, &ctx(), &record()).expect("saves");
            let pending = match p.restart_channel(&l, &ctx()) {
                StoredChannelRestart::HandshakeResumes(pending) => pending,
                other => panic!("a saved record must resume: {other:?}"),
            };
            pending
                .establish_with_resume(&opening_record(&ours, &theirs, SendFloor::new(0, 0)))
                .expect("establishes");
        }

        // The store is dropped and reopened at the same path, which is what a
        // restart leaves the next process holding.
        let p = persist(dir.path());
        let stored = match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(record) => record,
            other => panic!("an established correspondence was lost: {other:?}"),
        };
        assert!(
            stored.attempt().is_none(),
            "a first establishment claimed a re-establishment attempt"
        );

        let outbound = oxicrypt_ml_dsa::sign(stored.s_pc(), OUTBOUND, &[])
            .expect("the recovered signing key signs");
        crate::identity::keys::verify_signature(ours.public_key(), OUTBOUND, &outbound)
            .expect("the recovered signing key is not this party's pseudonym");

        let inbound = theirs.sign(INBOUND).expect("the correspondent signs");
        crate::identity::keys::verify_signature(stored.pk_pc(), INBOUND, &inbound)
            .expect("the recovered verifying key is not the correspondent's pseudonym");

        // The control: one key verifying both would pass every assertion above.
        assert!(
            crate::identity::keys::verify_signature(stored.pk_pc(), OUTBOUND, &outbound).is_err(),
            "the two recovered keys are halves of one keypair"
        );
    }

    /// A crash between A4.8's two writes leaves both records, and the loader
    /// reads the resume record as the authority.
    ///
    /// The provisional record is present at the moment of the read — asserted,
    /// not assumed, because a fixture that had already lost it would pass while
    /// testing nothing — and gone afterwards, which is the "ignored and cleaned"
    /// half of the same line.
    #[test]
    fn both_records_present_reads_as_established_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x62);
        let ours = pseudonym(0x03);
        let theirs = pseudonym(0x04);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");
        p.commit_resume(&l, &opening_record(&ours, &theirs, SendFloor::new(0, 0)))
            .expect("commits");

        let path = record_path(&p, &l, "provisional.bin");
        assert!(
            path.exists(),
            "the fixture never reached the crash window it exists to describe"
        );

        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::Established(stored) => {
                assert_eq!(stored.pk_pc(), theirs.public_key());
            }
            other => panic!("a resume record beside a provisional one lost: {other:?}"),
        }

        assert!(
            !path.exists(),
            "a provisional record beside a resume record was left on disk"
        );
    }

    /// The resume record is written **before** the provisional record is
    /// erased, so a refused write leaves the handshake exactly where it was.
    ///
    /// Under the reverse order the erase would already have happened and this
    /// establishment would be unrepeatable — the correspondence lost to a store
    /// that answered a question wrongly. The refusal is arranged through the
    /// anti-rollback guard, which is the one way a resume write fails without
    /// the store itself being broken.
    #[test]
    fn a_refused_resume_write_leaves_the_provisional_record_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x63);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");
        let pending = match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::HandshakeResumes(pending) => pending,
            other => panic!("a saved record must resume: {other:?}"),
        };

        // A later attempt lands between the handshake being taken up and the
        // establishment committing, so the establishment's own write regresses
        // it and is refused.
        p.commit_resume(&l, &resume_record(3, SendFloor::new(0, 0)))
            .expect("commits");

        let err = pending
            .establish_with_resume(&opening_record(
                &pseudonym(0x05),
                &pseudonym(0x06),
                SendFloor::new(0, 0),
            ))
            .expect_err("a rolled-back resume write was accepted");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::EmptySlotWouldReplaceAttempt { stored: 3 })
            ),
            "wrong error: {err:?}"
        );
        assert!(
            record_path(&p, &l, "provisional.bin").exists(),
            "the provisional record was erased before the resume write was accepted"
        );
    }

    /// An empty handshake slot survives the round trip, hands back nothing to
    /// emit, and admits a genuine first attempt over it.
    #[test]
    fn an_empty_handshake_slot_round_trips_and_admits_a_first_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x64);
        let floor = SendFloor::new(0, 0);
        let ours = pseudonym(0x07);
        let theirs = pseudonym(0x08);
        let opening = opening_record(&ours, &theirs, floor);

        assert_eq!(
            p.commit_resume(&l, &opening).expect("commits"),
            None,
            "an empty handshake slot handed back bytes to emit"
        );

        let stored = p.read_resume(&l).expect("reads").expect("a record");
        assert!(
            stored.attempt().is_none(),
            "attempt 0 decoded as an attempt"
        );
        assert_eq!(stored.sealed_re_est(), None);
        assert_eq!(stored.s_pc(), opening.s_pc());
        assert_eq!(stored.pk_pc(), opening.pk_pc());

        // Rewriting the same empty slot is not a re-seal: the record is written
        // again for reasons the handshake slot knows nothing about.
        p.commit_resume(&l, &opening)
            .expect("an unchanged empty slot was refused");

        p.commit_resume(&l, &re_established_record(&ours, &theirs, 1, floor))
            .expect("a first attempt was refused over an empty slot");
        assert_eq!(attempt_number(&p, &l), 1);
    }

    /// The empty slot orders below every attempt, so it may not replace one.
    ///
    /// The direction that matters: a record written at first establishment
    /// arriving after a re-establishment has been persisted would discard the
    /// attempt the peer has already deduped on.
    #[test]
    fn an_empty_handshake_slot_may_not_replace_a_persisted_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x65);
        let floor = SendFloor::new(0, 0);

        p.commit_resume(&l, &resume_record(1, floor))
            .expect("commits");
        let err = p
            .commit_resume(
                &l,
                &opening_record(&pseudonym(0x09), &pseudonym(0x0A), floor),
            )
            .expect_err("an empty slot replaced a persisted attempt");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::EmptySlotWouldReplaceAttempt { stored: 1 })
            ),
            "wrong error: {err:?}"
        );
        assert_eq!(
            attempt_number(&p, &l),
            1,
            "the refusal replaced the stored record anyway"
        );
    }

    /// The floor guard reads the same on an empty handshake slot as on an
    /// occupied one — it is a bound on this party's own sequence numbers and has
    /// nothing to do with the slot.
    #[test]
    fn the_floor_guard_is_unchanged_by_an_empty_handshake_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x66);
        let ours = pseudonym(0x0B);
        let theirs = pseudonym(0x0C);

        p.commit_resume(&l, &opening_record(&ours, &theirs, SendFloor::new(4, 100)))
            .expect("commits");
        let err = p
            .commit_resume(&l, &opening_record(&ours, &theirs, SendFloor::new(4, 99)))
            .expect_err("a regressing floor was accepted on an empty slot");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::FloorWouldRollBack { .. })
            ),
            "wrong error: {err:?}"
        );
        p.commit_resume(&l, &opening_record(&ours, &theirs, SendFloor::new(4, 101)))
            .expect("an advancing floor was refused on an empty slot");
    }

    /// **A second first establishment may not change the pseudonym pair.**
    ///
    /// Two records whose handshake slots are both empty carry the same attempt
    /// (none) and the same frame (none), so the sealed-bytes comparison that
    /// discriminates two same-attempt records has nothing to compare, and an
    /// unmoved floor is admitted. Without a guard on the pair itself the second
    /// write wins and reports success, leaving this side signing under a key the
    /// correspondent never saw.
    ///
    /// Each half is offered on its own so a guard that checked only one of them
    /// fails here. The stored pair is read back at the end: a refusal that had
    /// already replaced the file would return an error and still lose the keys.
    #[test]
    fn a_second_first_establishment_may_not_change_the_pseudonym_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x69);
        let floor = SendFloor::new(0, 0);
        let ours = pseudonym(0x11);
        let theirs = pseudonym(0x12);

        p.commit_resume(&l, &opening_record(&ours, &theirs, floor))
            .expect("commits");

        for (what, offered) in [
            (
                "our own signing key",
                opening_record(&pseudonym(0x13), &theirs, floor),
            ),
            (
                "the correspondent's verifying key",
                opening_record(&ours, &pseudonym(0x14), floor),
            ),
        ] {
            let err = p
                .commit_resume(&l, &offered)
                .err()
                .unwrap_or_else(|| panic!("{what} was replaced silently"));
            assert!(
                matches!(
                    err,
                    DmPersistError::Resume(ResumeError::PseudonymPairChanged)
                ),
                "wrong error for {what}: {err:?}"
            );
        }

        // Identical is still admitted: the record is rewritten for reasons the
        // pseudonym pair knows nothing about.
        p.commit_resume(&l, &opening_record(&ours, &theirs, SendFloor::new(0, 1)))
            .expect("an unchanged pair was refused");

        let stored = p.read_resume(&l).expect("reads").expect("a record");
        assert_eq!(stored.s_pc(), ours.secret_key());
        assert_eq!(stored.pk_pc(), theirs.public_key());
    }

    /// The pair guard holds across a re-establishment too: the stored slot being
    /// occupied does not license changing the keys.
    #[test]
    fn a_re_establishment_may_not_change_the_pseudonym_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x6A);
        let floor = SendFloor::new(0, 0);

        p.commit_resume(&l, &resume_record(1, floor))
            .expect("commits");
        let mut different = resume_record_sealed(2, floor, 0x5A);
        different = ResumeRecord::new(
            Box::new(*pseudonym(0x15).secret_key()),
            Box::new(*different.pk_pc()),
            crate::dm::resume::CommittedRoot::from_bytes(
                &[0x33u8; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            crate::dm::resume::ReEstState {
                reconnect_gen: different.reconnect_gen(),
                attempt: 2,
                last_seen_re_est: 0,
                own: different.sealed().map(|s| {
                    crate::dm::resume::OwnSlot::new(
                        1,
                        77,
                        crate::dm::resume::SealedReEst::seal(
                            fresh(2),
                            s.bytes().to_vec().into_boxed_slice(),
                        )
                        .expect("within MAX_FRAME_LEN"),
                        eph_dk_fixture(),
                    )
                }),
                acceptance: None,
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        )
        .expect("the fixture's pairings are coherent");
        let err = p
            .commit_resume(&l, &different)
            .expect_err("a new attempt carried a new signing key");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::PseudonymPairChanged)
            ),
            "wrong error: {err:?}"
        );
    }

    /// `commit_with_resume` is the split path's ending, and takes the same write
    /// order: the resume record lands and the provisional record goes.
    #[test]
    fn commit_with_resume_writes_the_record_and_erases_the_handshake() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x6B);
        let theirs = pseudonym(0x16);

        p.save_provisional(&l, &ctx(), &record()).expect("saves");
        let pending = match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::HandshakeResumes(pending) => pending,
            other => panic!("a saved record must resume: {other:?}"),
        };
        // The half taken early, which is why this ending exists at all.
        pending.ratchet().expect("derives a ratchet");
        pending
            .commit_with_resume(&opening_record(
                &pseudonym(0x17),
                &theirs,
                SendFloor::new(0, 0),
            ))
            .expect("commits");

        assert!(
            !record_path(&p, &l, "provisional.bin").exists(),
            "the provisional record survived the commit"
        );
        let stored = p.read_resume(&l).expect("reads").expect("a record");
        assert_eq!(stored.pk_pc(), theirs.public_key());
    }

    /// A resume record whose plaintext will not decode tears the channel down as
    /// an unreadable store — the collapse `restart_channel` documents.
    ///
    /// Pinned because it is a limitation rather than a property: the honest
    /// answer for a permanent record-level fault is `RecordUnusable`, which
    /// cannot carry a `ResumeError`. This test is what will fail, loudly, if a
    /// later change splits them — which is the point of writing it down.
    ///
    /// The record is sealed by the store and only its *plaintext* is nonsense,
    /// so the seal opens and the decode is what fails. A tampered file would
    /// fail one layer earlier and prove something else.
    #[test]
    fn a_resume_record_that_will_not_decode_tears_the_channel_down() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x6C);

        p.store()
            .critical_section(&l, |guard| -> Result<(), DmPersistError> {
                // At least `RESUME_MAGIC.len()` bytes, so the reader gets as far
                // as comparing the magic and refuses on that rather than on the
                // length. A shorter payload ends inside the first field and
                // reports a different error.
                guard.replace(RecordKind::Resume, &[b'X'; 64])?;
                Ok(())
            })
            .expect("seals the nonsense");

        match p.restart_channel(&l, &ctx()) {
            StoredChannelRestart::TornDown(t) => match t.cause() {
                // The decode failure itself, rendered: the seal opened and the
                // plaintext underneath is what `ResumeRecord::decode` refused.
                // Pinned against the specific decode error's own rendering, and
                // the sealed payload is deliberately not that string: an
                // assertion satisfied by the bytes written cannot tell a
                // decoder that ran from one that echoed.
                TeardownCause::StoreUnreadable(rendered) => assert_eq!(
                    rendered.as_str(),
                    ResumeError::BadMagic.to_string().as_str(),
                    "the teardown did not carry the decode failure: {rendered}"
                ),
                other => panic!("expected an unreadable store, got {other:?}"),
            },
            other => panic!("a corrupt resume record did not tear the channel down: {other:?}"),
        }
    }

    /// The file's length says nothing about whether the handshake slot is
    /// occupied. The field itself is variable — a length prefix and a frame —
    /// and the constant on-disk size comes from the store padding every record
    /// of a kind to one bucket.
    ///
    /// A padding-removal mutation goes red at the store's own
    /// `debug_assert_eq!` before the comparison below is reached, so in a debug
    /// build that assertion is what catches it; this test's own comparison
    /// carries the claim in a release build.
    ///
    /// The inequality at the end is the control: the two plaintexts differ in
    /// length, so equal files are the store's padding rather than a coincidence
    /// of the fixtures.
    ///
    /// **In a debug build the comparison below is not what catches a padding
    /// regression.** The store asserts its own "every record of a kind is one
    /// size on disk" invariant in a `debug_assert_eq!`
    /// ([`crate::storage::dm_store`]), which fires while the record is being
    /// written and therefore before either `metadata` call here is reached — so
    /// removing the padding turns this test red at that internal assertion
    /// rather than at `empty_len == occupied_len`. The comparison earns its keep
    /// in a release build, where the store's assertion is compiled out and this
    /// is the only thing looking.
    #[test]
    fn the_on_disk_length_does_not_report_the_handshake_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let empty = label(0x67);
        let occupied = label(0x68);
        let floor = SendFloor::new(0, 0);
        let opening = opening_record(&pseudonym(0x0D), &pseudonym(0x0E), floor);
        let re_established = resume_record(1, floor);

        p.commit_resume(&empty, &opening).expect("commits");
        p.commit_resume(&occupied, &re_established)
            .expect("commits");

        let empty_len = std::fs::metadata(record_path(&p, &empty, "resume.bin"))
            .expect("reads")
            .len();
        let occupied_len = std::fs::metadata(record_path(&p, &occupied, "resume.bin"))
            .expect("reads")
            .len();
        assert_eq!(
            empty_len, occupied_len,
            "the file's size reports whether a re-establishment frame is stored"
        );

        assert_ne!(
            opening.encode().len(),
            re_established.encode().len(),
            "the fixtures encode to one length, so the sizes above agree for the wrong reason"
        );
    }
    // ------------------------------------------------------------ the contact cache (ISC-C44)

    const FIRST_SEEN: i64 = 1_700_000_000_000;
    const LAST_SEEN: i64 = 1_700_000_123_456;

    /// Byte-distinct, so an encoding that transposed its two keys would not pass
    /// by coincidence.
    fn pk(tag: u8) -> Box<[u8; oxicrypt_ml_dsa::PK_LEN]> {
        let mut out = vec![0u8; oxicrypt_ml_dsa::PK_LEN].into_boxed_slice();
        for (i, b) in out.iter_mut().enumerate() {
            *b = tag.wrapping_add((i as u8).wrapping_mul(3));
        }
        out.try_into().expect("allocated at PK_LEN")
    }

    /// A record whose every field is a function of `tag`, so two fixtures built
    /// with different tags disagree in all four stored facts — which is what
    /// lets an assertion, rather than a `panic!` in a seed, carry the kill.
    /// **The root is derived, not invented.** `ROOT_LEN` and `SS0_LEN` are both
    /// 32, so a fixture handing `ContactRecord::new` an `ss0` where an `AR`
    /// belongs compiles and stores the wrong kind of value with nothing
    /// complaining. Deriving it here keeps the fixture the shape production
    /// writes, and lets a test compare against `derive_channel_roots` over the
    /// same secret.
    fn contact_tagged(tag: u8, first_seen: i64, last_seen: i64) -> ContactRecord {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut secret = ss0();
        secret[0] ^= tag;
        let ar = Zeroizing::new(derive_channel_roots(&secret).expect("derives").ar());
        ContactRecord::new(
            pk(tag),
            Some(pk(tag.wrapping_add(0x7F))),
            ar,
            first_seen,
            last_seen,
        )
        .expect("ordered timestamps")
    }

    fn contact(first_seen: i64, last_seen: i64) -> ContactRecord {
        contact_tagged(0x01, first_seen, last_seen)
    }

    /// Seed a correspondence with `record`, through the ordinary writer.
    fn seed_contact(p: &DmPersist, l: &CorrespondenceLabel, record: ContactRecord) {
        p.update_contact(l, || Ok(record), |_| Ok(Mutation::Changed(())))
            .expect("seeds");
    }

    /// The sweep's own idiom, and the only correct one: `observed_at`'s bool
    /// says the record *reflects* a sighting, which is true of a re-record of
    /// the stored instant. Only the stamp says whether anything moved.
    fn observe(c: &mut ContactRecord, at_ms: i64) -> Mutation<bool> {
        if c.last_seen_ms() < at_ms && c.observed_at(at_ms) {
            Mutation::Changed(true)
        } else {
            Mutation::Unchanged(false)
        }
    }

    /// Overwrite the stored contact record with `bytes`, around the reader — the
    /// only way to put a payload on disk that `ContactRecord::encode` would
    /// never produce, which is what the refusal tests need.
    fn write_contact_bytes(p: &DmPersist, l: &CorrespondenceLabel, bytes: &[u8]) {
        p.store()
            .critical_section(l, |guard| -> Result<(), DmStoreError> {
                guard.replace(RecordKind::ContactCache, bytes)
            })
            .expect("writes");
    }

    /// **The oracle for the pair.** Every stored field comes back through the
    /// store's seal, including `ss0` — which is checked by the root it
    /// recomputes, since the record never hands the secret out.
    #[test]
    fn a_contact_record_round_trips_through_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x61);

        assert!(
            p.read_contact(&l).expect("reads").is_none(),
            "fixture is not empty"
        );

        seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));

        let stored = p
            .read_contact(&l)
            .expect("reads")
            .expect("a record was written");

        // Control on the fixture: the two keys are distinct, so a write that
        // stored one of them twice cannot pass the two assertions below.
        assert_ne!(
            pk(0x01),
            pk(0x80),
            "the fixture's two keys are the same key"
        );
        assert_eq!(stored.pk_lt(), pk(0x01).as_ref());
        assert_eq!(stored.pk_pc(), Some(pk(0x80).as_ref()));

        // Likewise: distinct stamps, so a read that took one field twice fails.
        assert_ne!(
            FIRST_SEEN, LAST_SEEN,
            "the two timestamps are the same value"
        );
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), LAST_SEEN);

        assert_eq!(
            stored.address_root(),
            contact(FIRST_SEEN, LAST_SEEN).address_root(),
            "the address root did not survive the store's seal"
        );
    }

    /// The record survives the process that wrote it: a second [`DmPersist`]
    /// over the same root recovers it, and the store key is re-derived from
    /// `at_rest_key` rather than being process-lifetime state.
    #[test]
    fn a_contact_record_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = label(0x6B);
        let root = {
            let p = persist(dir.path());
            seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));
            p.read_contact(&l)
                .expect("reads")
                .expect("there")
                .address_root()
        };

        let p = persist(dir.path());
        let stored = p
            .read_contact(&l)
            .expect("reads")
            .expect("the record did not survive the process that wrote it");
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), LAST_SEEN);
        assert_eq!(stored.pk_pc(), Some(pk(0x80).as_ref()));
        assert_eq!(
            stored.address_root(),
            root,
            "the address root did not survive the restart"
        );
    }

    /// **The oracle for issue #402.** An initiator writes its first-contact
    /// entry, the process ends before the correspondent answers, and the next
    /// process collects that acceptance by the correspondent's identity key —
    /// which is the only thing the acceptance names.
    ///
    /// The lookup is the whole of it: `correspondence_for_pk_lt` reads contact
    /// records and nothing else, so an initiator that wrote none until
    /// acceptance would answer `Ok(None)` here, the acceptance would never be
    /// routed to the entry it answers, and everything the correspondent
    /// composed would re-emit to the outbox's seven-day give-up.
    #[test]
    fn an_unanswered_first_contact_survives_a_restart_and_collects_its_acceptance() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let l = label(0x71);
        let correspondent = pk(0x11);
        let their_pk_pc = pk(0x22);
        let ar = derive_channel_roots(&ss0()).expect("derives").ar();

        {
            let p = persist(dir.path());
            p.record_first_contact_sent(&l, correspondent.clone(), Zeroizing::new(ar), FIRST_SEEN)
                .expect("the entry was not recorded");
        }

        // The restart: a second `DmPersist` over the same root, holding nothing
        // the first one held.
        let p = persist(dir.path());
        let found = p
            .correspondence_for_pk_lt(&correspondent)
            .expect("lookup")
            .expect("the correspondent's identity key names no correspondence");
        assert_eq!(found, l);

        let waiting = p.read_contact(&found).expect("reads").expect("a record");
        assert_eq!(
            waiting.pk_pc(),
            None,
            "an entry that has not been accepted recorded a pseudonym"
        );
        assert_eq!(
            waiting.first_seen_ms(),
            FIRST_SEEN,
            "the correspondence is dated from when the entry was sent"
        );
        assert_eq!(waiting.address_root(), ar);

        // The acceptance, collected by identity key alone.
        assert!(
            p.record_correspondent_pseudonym(&found, their_pk_pc.clone(), LAST_SEEN)
                .expect("records"),
            "the pseudonym the acceptance carried was not newly recorded"
        );

        let accepted = p.read_contact(&found).expect("reads").expect("a record");
        assert_eq!(accepted.pk_pc(), Some(their_pk_pc.as_ref()));
        assert_eq!(accepted.last_seen_ms(), LAST_SEEN);
        assert_eq!(
            accepted.first_seen_ms(),
            FIRST_SEEN,
            "the acceptance re-dated a correspondence that began at the entry"
        );
    }

    /// A second entry to the same recipient re-addresses the record, because it
    /// encapsulates a fresh `ss0` and so addresses a different channel. The
    /// correspondence's own start is not moved by the retry.
    #[test]
    fn a_second_first_contact_entry_re_addresses_the_record_it_finds() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x72);
        let correspondent = pk(0x11);

        let first = derive_channel_roots(&ss0()).expect("derives").ar();
        let mut retry_secret = ss0();
        retry_secret[0] ^= 0xAA;
        let retry = derive_channel_roots(&retry_secret).expect("derives").ar();
        assert_ne!(first, retry, "the two entries address one channel");

        p.record_first_contact_sent(&l, correspondent.clone(), Zeroizing::new(first), FIRST_SEEN)
            .expect("the first entry was not recorded");
        p.record_first_contact_sent(&l, correspondent.clone(), Zeroizing::new(retry), LAST_SEEN)
            .expect("the retry was not recorded");

        let stored = p.read_contact(&l).expect("reads").expect("a record");
        assert_eq!(
            stored.address_root(),
            retry,
            "the record still addresses the channel of an entry nothing will answer"
        );
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), LAST_SEEN);
        assert_eq!(stored.pk_pc(), None);
    }

    /// An entry sent to an identity this side already corresponds with is
    /// refused where it would be written. Knocking at an established
    /// correspondent reads at the far end as this side having lost its at-rest
    /// state, which ends every message they have queued.
    #[test]
    fn an_entry_to_an_established_correspondent_is_refused() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x73);
        let established = contact_tagged(0x01, FIRST_SEEN, LAST_SEEN);
        let root = established.address_root();
        seed_contact(&p, &l, established);

        let ar = derive_channel_roots(&ss0()).expect("derives").ar();
        assert!(
            matches!(
                p.record_first_contact_sent(&l, pk(0x01), Zeroizing::new(ar), LAST_SEEN),
                Err(DmPersistError::AlreadyEstablished)
            ),
            "an entry was written over an established correspondence"
        );
        let stored = p.read_contact(&l).expect("reads").expect("a record");
        assert_eq!(
            stored.address_root(),
            root,
            "the refused entry re-addressed the channel"
        );
        assert!(
            stored.pk_pc().is_some(),
            "the refused entry cleared the pseudonym"
        );

        // A label holding someone else's record is the other refusal, and it is
        // a different answer: this one is about two identities under one label.
        assert!(
            matches!(
                p.record_first_contact_sent(&l, pk(0x33), Zeroizing::new(ar), LAST_SEEN),
                Err(DmPersistError::CorrespondenceHoldsAnotherIdentity)
            ),
            "an entry was written into another correspondent's record"
        );
    }

    /// The replace-guard, through the call the driver makes: a second, different
    /// pseudonym is refused and the stored record keeps the key every frame
    /// already collected was verified against.
    #[test]
    fn filling_a_pseudonym_twice_with_different_keys_is_refused_on_disk() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x74);
        let ar = derive_channel_roots(&ss0()).expect("derives").ar();
        p.record_first_contact_sent(&l, pk(0x11), Zeroizing::new(ar), FIRST_SEEN)
            .expect("the entry was not recorded");

        assert!(
            p.record_correspondent_pseudonym(&l, pk(0x22), FIRST_SEEN)
                .expect("records"),
            "the first pseudonym was not recorded"
        );
        // Idempotent, and it costs no seal: a re-presented acceptance carries
        // the key already recorded.
        let before = p.store().seal_count();
        assert!(
            !p.record_correspondent_pseudonym(&l, pk(0x22), FIRST_SEEN)
                .expect("re-records"),
            "re-recording the same key reported a change"
        );
        assert_eq!(
            p.store().seal_count(),
            before,
            "an unchanged record spent a seal"
        );

        assert!(
            matches!(
                p.record_correspondent_pseudonym(&l, pk(0x44), LAST_SEEN),
                Err(DmPersistError::Contact(
                    ContactCacheError::PseudonymAlreadyRecorded
                ))
            ),
            "a second pseudonym was accepted"
        );
        assert_eq!(
            p.read_contact(&l)
                .expect("reads")
                .expect("a record")
                .pk_pc(),
            Some(pk(0x22).as_ref()),
            "the refused key displaced the recorded one"
        );
    }

    /// A correspondence with no record at all is named as such, rather than
    /// seeded from a call that knows neither the identity key nor the address
    /// root a record must carry.
    #[test]
    fn filling_a_pseudonym_on_an_unrecorded_correspondence_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        assert!(
            matches!(
                p.record_correspondent_pseudonym(&label(0x75), pk(0x22), FIRST_SEEN),
                Err(DmPersistError::ContactRecordMissing)
            ),
            "a record was invented for a correspondence that has none"
        );
    }

    /// A record's file moved into another correspondence's slot does not open:
    /// the store's seal binds the [`CorrespondenceLabel`] as AAD, and this kind
    /// has no second seal behind it.
    #[test]
    fn a_contact_record_moved_between_correspondences_does_not_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let (from, to) = (label(0x6C), label(0x6D));

        seed_contact(&p, &from, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        // Establish the destination the ordinary way, then overwrite its file
        // with the source's bytes.
        seed_contact(&p, &to, contact_tagged(0x02, FIRST_SEEN, LAST_SEEN));
        let stolen = std::fs::read(record_path(&p, &from, "contact-cache.bin")).expect("reads");
        assert_ne!(
            stolen,
            std::fs::read(record_path(&p, &to, "contact-cache.bin")).expect("reads"),
            "the two correspondences hold the same bytes, so this test moves nothing"
        );
        std::fs::write(record_path(&p, &to, "contact-cache.bin"), &stolen).expect("writes");

        match p
            .read_contact(&to)
            .expect_err("a record from another correspondence's slot opened")
        {
            DmPersistError::Store(DmStoreError::NotAuthentic {
                kind: RecordKind::ContactCache,
            }) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// A contact update that changes nothing spends **no seal** (#347).
    ///
    /// **Two assertions, and the first is what makes the second mean anything.**
    /// A real mutation has to move the counter, or "zero seals" is
    /// indistinguishable from an instrument that never counts.
    #[test]
    fn a_no_op_contact_update_spends_no_seal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x62);

        let before_seed = p.store().seal_count();
        seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));
        let after_seed = p.store().seal_count();
        assert_eq!(
            after_seed - before_seed,
            1,
            "a seeding update must spend exactly one seal — the delta, not \
             `> 0`, is what makes the rest of this test mean anything"
        );

        p.update_contact(
            &l,
            || panic!("a record exists"),
            |_| Ok(Mutation::Unchanged(())),
        )
        .expect("updates");
        assert_eq!(
            p.store().seal_count(),
            after_seed,
            "an update that changed nothing must not seal"
        );

        // The sweep's shape: a sighting `observed_at` refuses outright.
        p.update_contact(
            &l,
            || panic!("a record exists"),
            |c| Ok(observe(c, FIRST_SEEN + 1)),
        )
        .expect("updates");
        assert_eq!(
            p.store().seal_count(),
            after_seed,
            "a refused sighting must not seal"
        );
    }

    /// **A re-record of the instant already stored must not seal**, and it is
    /// the case the obvious idiom gets wrong: `observed_at` guards
    /// `at_ms < last_seen_ms`, so the equal case returns `true` while changing
    /// nothing, and a `Mutation` derived from that bool spends a seal per tick
    /// per contact — the very cost the conditional shape exists to avoid.
    #[test]
    fn an_idempotent_re_record_of_a_contact_spends_no_seal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x6E);

        seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));
        let after_seed = p.store().seal_count();

        // Positive control on the trap: the bool alone says "recorded", so an
        // idiom keying `Mutation` on it would report `Changed` here.
        let mut in_memory = contact(FIRST_SEEN, LAST_SEEN);
        assert!(
            in_memory.observed_at(LAST_SEEN),
            "the equal case is refused, so this test guards nothing"
        );

        let moved = p
            .update_contact(
                &l,
                || panic!("a record exists"),
                |c| {
                    assert_eq!(c.last_seen_ms(), LAST_SEEN, "the fixture is not at rest");
                    Ok(observe(c, LAST_SEEN))
                },
            )
            .expect("updates");

        assert!(!moved, "a re-record of the stored instant moved the stamp");
        assert_eq!(
            p.store().seal_count(),
            after_seed,
            "re-recording the stored instant spent a seal"
        );
    }

    /// Asking whether a correspondent is known must not answer itself into
    /// existence (#253) — the reason the reader takes no lock.
    #[test]
    fn an_absent_contact_is_none_and_the_question_creates_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x63);
        let before = p.store().seal_count();
        let correspondence_dir = p.store().root().join(hex::encode(l.as_bytes()));

        assert!(p.read_contact(&l).expect("reads").is_none());
        assert!(
            !correspondence_dir.exists(),
            "asking whether a correspondent is known established the correspondence"
        );
        assert_eq!(
            p.store().seal_count() - before,
            0,
            "a question spent a seal"
        );
    }

    /// **A seeded record is written whatever `f` reports.** The seed carries
    /// `pk_lt`, `pk_pc` and `ss0` — three facts with no other home — and the
    /// losing call is the ordinary one: seed at the local clock, then record a
    /// sighting stamped earlier. `observed_at` refuses it and `f` honestly says
    /// `Unchanged`; under `update_outbox`'s rule the correspondent would stay
    /// unknown, with no error and no trace, and every later tick would re-seed
    /// and lose it again.
    #[test]
    fn a_seeded_contact_record_is_written_even_when_f_reports_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x6F);
        let before = p.store().seal_count();

        // The frame's stamp is behind the clock the seed was built at, which is
        // what makes the refusal below the honest report and not a contrivance.
        let recorded = p
            .update_contact(
                &l,
                || Ok(contact(FIRST_SEEN, LAST_SEEN)),
                |c| Ok(observe(c, LAST_SEEN - 1)),
            )
            .expect("seeds");
        assert!(
            !recorded,
            "the earlier sighting was taken, so this test never reaches the Unchanged arm"
        );

        let stored = p
            .read_contact(&l)
            .expect("reads")
            .expect("the seeded record was destroyed by an Unchanged report");
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), LAST_SEEN);
        assert_eq!(stored.pk_pc(), Some(pk(0x80).as_ref()));
        assert_eq!(
            p.store().seal_count() - before,
            1,
            "seeding must spend exactly one seal — and exactly one, so the \
             write is the seed's and not a second one"
        );

        // And the seal is per correspondence for its life, not per tick: the
        // record now exists, so a later no-op takes the stored path and is free.
        p.update_contact(
            &l,
            || panic!("a record exists"),
            |_| Ok(Mutation::Unchanged(())),
        )
        .expect("updates");
        assert_eq!(
            p.store().seal_count() - before,
            1,
            "a no-op after seeding spent a seal"
        );
    }

    /// **The oracle for read-modify-write.** The closure sees what is on disk,
    /// never the seed — so a caller holding a stale record cannot displace
    /// `first_seen_ms`, rewind an advanced `last_seen_ms`, or substitute a key.
    /// The seed disagrees in every stored field, so each assertion kills
    /// independently of the flag that pins the seed as unbuilt.
    #[test]
    fn a_contact_update_sees_the_stored_record_and_never_the_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x64);
        let seed_built = std::cell::Cell::new(false);

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        let stored_root = p
            .read_contact(&l)
            .expect("reads")
            .expect("there")
            .address_root();

        p.update_contact(
            &l,
            || {
                seed_built.set(true);
                Ok(contact_tagged(0x02, FIRST_SEEN + 1, LAST_SEEN + 1))
            },
            |c| {
                assert_eq!(
                    c.first_seen_ms(),
                    FIRST_SEEN,
                    "the seed's first_seen displaced the stored one"
                );
                assert_eq!(
                    c.last_seen_ms(),
                    LAST_SEEN,
                    "the seed's last_seen displaced the stored one"
                );
                assert_eq!(
                    c.pk_lt(),
                    pk(0x01).as_ref(),
                    "the seed's long-term key displaced the stored one"
                );
                assert_eq!(
                    c.address_root(),
                    stored_root,
                    "the seed's address root displaced the stored one"
                );
                Ok(Mutation::Unchanged(()))
            },
        )
        .expect("updates");

        assert!(
            !seed_built.get(),
            "the seed was built for a correspondence that already has a record"
        );
    }

    /// The monotonic guard runs against the **stored** stamp, and a refusal
    /// writes nothing — the whole reason this is one critical section.
    #[test]
    fn a_contact_sighting_that_would_rewind_the_stored_stamp_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x65);

        seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));

        // Positive control: a later sighting IS taken and IS persisted, so the
        // refusal below is the guard and not a mutator that stopped working.
        let moved = p
            .update_contact(
                &l,
                || panic!("a record exists"),
                |c| Ok(observe(c, LAST_SEEN + 1_000)),
            )
            .expect("updates");
        assert!(moved, "a later sighting was refused");
        assert_eq!(
            p.read_contact(&l)
                .expect("reads")
                .expect("there")
                .last_seen_ms(),
            LAST_SEEN + 1_000
        );

        // The rewind: after the fixture's own LAST_SEEN, so a guard that only
        // checked `first_seen_ms` would admit it.
        const { assert!(FIRST_SEEN < LAST_SEEN, "the fixture straddles no guard") };
        let moved = p
            .update_contact(
                &l,
                || panic!("a record exists"),
                |c| Ok(observe(c, LAST_SEEN)),
            )
            .expect("updates");
        assert!(!moved, "an earlier sighting rewound the stored stamp");
        assert_eq!(
            p.read_contact(&l)
                .expect("reads")
                .expect("there")
                .last_seen_ms(),
            LAST_SEEN + 1_000,
            "a refused sighting moved the stored stamp"
        );
    }

    /// A failing closure writes nothing: the record is exactly what it was, so a
    /// caller may retry without having half-applied anything.
    #[test]
    fn a_failed_contact_update_leaves_the_record_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x70);

        seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));
        let before = std::fs::read(record_path(&p, &l, "contact-cache.bin")).expect("reads");
        let seals = p.store().seal_count();

        // Annotated because the closure only ever takes its `Err` arm, which
        // leaves `T` with nothing to infer it from.
        let err: Result<(), DmPersistError> = p.update_contact(
            &l,
            || panic!("a record exists"),
            |c| {
                // A real change, made before the refusal: the write must not
                // ride out on it.
                assert!(c.observed_at(LAST_SEEN + 1), "the fixture did not mutate");
                Err(DmPersistError::Contact(
                    ContactCacheError::TimestampsOutOfOrder {
                        first_seen_ms: FIRST_SEEN,
                        last_seen_ms: FIRST_SEEN - 1,
                    },
                ))
            },
        );
        assert!(
            matches!(
                err,
                Err(DmPersistError::Contact(
                    ContactCacheError::TimestampsOutOfOrder { .. }
                ))
            ),
            "wrong error: {err:?}"
        );

        assert_eq!(
            std::fs::read(record_path(&p, &l, "contact-cache.bin")).expect("reads"),
            before,
            "a failed update wrote to the record"
        );
        assert_eq!(
            p.store().seal_count(),
            seals,
            "a failed update spent a seal"
        );
    }

    /// A payload of the wrong length is refused **by length**, not read as a
    /// field that landed wrong.
    ///
    /// The store's own `WrongFileLen` cannot catch this: a sealed kind is padded
    /// to its bucket and carries its true length in an interior prefix, so every
    /// short payload is one file size on disk and the length check that matters
    /// is the record's own.
    #[test]
    fn a_truncated_contact_record_is_refused_by_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x66);
        let encoded = contact(FIRST_SEEN, LAST_SEEN).encode();

        // Positive control: written whole, through the same path, it reads.
        write_contact_bytes(&p, &l, &encoded);
        p.read_contact(&l).expect("reads").expect("present");

        for len in [0, 1, CONTACT_RECORD_LEN - 1] {
            write_contact_bytes(&p, &l, &encoded[..len]);
            let err = p
                .read_contact(&l)
                .expect_err("a record of the wrong length was accepted");
            match &err {
                DmPersistError::Contact(ContactCacheError::WrongLength { expected, actual }) => {
                    assert_eq!(*expected, CONTACT_RECORD_LEN);
                    assert_eq!(*actual, len);
                }
                other => panic!("wrong error for a {len}-byte record: {other:?}"),
            }
            // The rendered form is what a caller surfaces, and it must name the
            // record rather than reporting a bare number from nowhere.
            let rendered = err.to_string();
            assert!(
                rendered.starts_with("contact record: ") && rendered.contains(&len.to_string()),
                "unhelpful rendering: {rendered}"
            );
        }
    }

    /// A same-length record this build does not read fails **by name**, so a
    /// future shape change cannot be mis-parsed as this one — and a corrupt
    /// record is refused rather than degraded to `Ok(None)`.
    #[test]
    fn a_contact_record_with_a_wrong_version_byte_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x67);
        let mut bytes = contact(FIRST_SEEN, LAST_SEEN).encode().to_vec();

        bytes[0] = CONTACT_RECORD_VERSION + 1;
        write_contact_bytes(&p, &l, &bytes);
        let err = p
            .read_contact(&l)
            .expect_err("a record from an unknown version was accepted");
        match &err {
            DmPersistError::Contact(ContactCacheError::UnsupportedVersion { found, expected }) => {
                assert_eq!(*found, CONTACT_RECORD_VERSION + 1);
                assert_eq!(*expected, CONTACT_RECORD_VERSION);
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert!(
            err.to_string().starts_with("contact record: "),
            "unhelpful rendering: {err}"
        );

        // Positive control: restored, the same bytes through the same path read.
        bytes[0] = CONTACT_RECORD_VERSION;
        write_contact_bytes(&p, &l, &bytes);
        p.read_contact(&l).expect("reads").expect("present");
    }

    // ---- the pk_lt lookup (#261) -------------------------------------------

    /// The lookup answers with the correspondence that holds the key, over a
    /// store holding several — and answers `None` for a key no record holds.
    ///
    /// The `pk_pc` case is the control that matters: every fixture's `pk_pc` is
    /// also a stored key, so a lookup comparing the wrong field would pass every
    /// other assertion here and fail only this one.
    #[test]
    fn a_pk_lt_lookup_names_the_correspondence_that_holds_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());

        // Before anything is seeded: absence, over a store that exists.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01).as_ref())
                .expect("scans"),
            None,
            "an empty store named a correspondence"
        );

        let seeded = [
            (label(0xA1), 0x01u8),
            (label(0xA2), 0x02),
            (label(0xA3), 0x03),
        ];
        for (l, tag) in &seeded {
            seed_contact(&p, l, contact_tagged(*tag, FIRST_SEEN, LAST_SEEN));
        }

        for (l, tag) in &seeded {
            assert_eq!(
                p.correspondence_for_pk_lt(pk(*tag).as_ref())
                    .expect("scans"),
                Some(*l),
                "the lookup named the wrong correspondence for tag {tag:#04x}"
            );
        }

        // A key nothing holds.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x2A).as_ref())
                .expect("scans"),
            None,
            "an unknown key matched a correspondence"
        );

        // A key that is stored, but as `pk_pc` rather than `pk_lt`.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01u8.wrapping_add(0x7F)).as_ref())
                .expect("scans"),
            None,
            "the lookup matched against pk_pc"
        );
    }

    /// A correspondence established without a contact record is skipped rather
    /// than failing the scan: entering a critical section creates the directory,
    /// so an established correspondence that has recorded nothing yet is an
    /// ordinary state and not a corrupt one.
    #[test]
    fn a_correspondence_with_no_contact_record_is_skipped_by_a_pk_lt_lookup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let bare = label(0xB1);
        let known = label(0xB2);

        p.store()
            .critical_section(&bare, |_| -> Result<(), DmStoreError> { Ok(()) })
            .expect("establishes");
        assert!(
            p.read_contact(&bare).expect("reads").is_none(),
            "the bare correspondence has a contact record, so this test proves nothing"
        );
        assert!(
            p.store().correspondences().expect("lists").contains(&bare),
            "the bare correspondence is not listed, so the skip is never exercised"
        );

        // With only the bare correspondence there, the scan runs and finds
        // nothing rather than failing.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01).as_ref())
                .expect("scans"),
            None
        );

        seed_contact(&p, &known, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01).as_ref())
                .expect("scans"),
            Some(known),
            "the bare correspondence stopped the scan reaching the seeded one"
        );
    }

    /// **Two correspondences holding one `pk_lt` is an error, not a winner.**
    /// Without this the lookup would answer from whichever directory the scan
    /// reached first and route a knock into one of two correspondences by
    /// filesystem order.
    #[test]
    fn two_correspondences_holding_one_pk_lt_are_ambiguous_rather_than_arbitrary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let (one, two, other) = (label(0xC1), label(0xC2), label(0xC3));

        seed_contact(&p, &one, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_contact(&p, &other, contact_tagged(0x02, FIRST_SEEN, LAST_SEEN));

        // Positive control: with one holder the key resolves, so the refusal
        // below is the duplicate and not the lookup failing generally.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01).as_ref())
                .expect("scans"),
            Some(one)
        );

        seed_contact(&p, &two, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));

        match p
            .correspondence_for_pk_lt(pk(0x01).as_ref())
            .expect_err("a duplicated pk_lt resolved to one correspondence")
        {
            DmPersistError::AmbiguousCorrespondent { matches } => assert_eq!(matches, 2),
            other => panic!("wrong error: {other:?}"),
        }

        // The ambiguity is about the one key: every other correspondence still
        // resolves, so the refusal is not a wedged store.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x02).as_ref())
                .expect("scans"),
            Some(other)
        );

        // A third holder counts too: `matches` is the number found, not a flag
        // spelled as one. Narrowing the arm to `2 => Err(..)` passes every
        // assertion above and fails here.
        let three = label(0xC4);
        seed_contact(&p, &three, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        let err = p
            .correspondence_for_pk_lt(pk(0x01).as_ref())
            .expect_err("three holders resolved to one correspondence");
        match &err {
            DmPersistError::AmbiguousCorrespondent { matches } => assert_eq!(*matches, 3),
            other => panic!("wrong error: {other:?}"),
        }

        // The rendering asserted is the *returned* error's, not one built here
        // — otherwise this checks `Display` and says nothing about the value the
        // lookup produced. It names the count and the fact, and no label.
        let rendered = err.to_string();
        assert!(
            rendered.contains('3') && rendered.contains("long-term identity key"),
            "unhelpful rendering: {rendered}"
        );
        assert!(
            !rendered.contains(&hex::encode(one.as_bytes()))
                && !rendered.contains(&hex::encode(two.as_bytes())),
            "a label reached the rendered error: {rendered}"
        );

        // It wraps nothing: the ambiguity is this function's own finding, not a
        // failure handed up from a record or the store.
        assert!(
            std::error::Error::source(&err).is_none(),
            "AmbiguousCorrespondent reported a source"
        );
    }

    /// **A store error during the scan is propagated, not read as "no
    /// correspondence holds this key".** Absence sends the caller to first
    /// contact, which mints a second label for an identity that already has one
    /// — the ambiguity the test above refuses to resolve, arriving through the
    /// enumeration instead of through the records.
    #[test]
    fn a_store_error_during_the_scan_fails_the_lookup_rather_than_answering_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xE1);
        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));

        // Positive control: the key resolves while the store is intact.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01).as_ref())
                .expect("scans"),
            Some(l)
        );

        std::fs::remove_dir_all(p.store().root()).expect("removes");
        match p
            .correspondence_for_pk_lt(pk(0x01).as_ref())
            .expect_err("a vanished store answered that the key is unknown")
        {
            DmPersistError::Store(DmStoreError::Io { .. }) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// **An unreadable contact record fails the lookup; it is not skipped.**
    /// Skipping would report the sought identity as unknown while its record is
    /// on disk, and the caller's remedy for unknown is to run first contact —
    /// minting a second correspondence for one identity, which is the very
    /// duplicate the test above refuses to resolve.
    #[test]
    fn an_unreadable_contact_record_fails_a_pk_lt_lookup_rather_than_being_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let (sought, corrupt) = (label(0xD1), label(0xD2));

        seed_contact(&p, &sought, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_contact(&p, &corrupt, contact_tagged(0x02, FIRST_SEEN, LAST_SEEN));

        // Positive control: both readable, the key resolves.
        assert_eq!(
            p.correspondence_for_pk_lt(pk(0x01).as_ref())
                .expect("scans"),
            Some(sought)
        );

        let mut bytes = contact_tagged(0x02, FIRST_SEEN, LAST_SEEN)
            .encode()
            .to_vec();
        bytes[0] = CONTACT_RECORD_VERSION + 1;
        write_contact_bytes(&p, &corrupt, &bytes);

        // The sought record is still perfectly readable on its own — so a `None`
        // or a `Some` here would be the scan quietly walking past the other one.
        assert!(p.read_contact(&sought).expect("reads").is_some());
        match p
            .correspondence_for_pk_lt(pk(0x01).as_ref())
            .expect_err("an unreadable contact record was skipped")
        {
            DmPersistError::Contact(ContactCacheError::UnsupportedVersion { .. }) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// **A stored record that will not decode wedges every later update**, and
    /// does not fall through to the seed. Re-seeding would overwrite
    /// `first_seen_ms` and a live `ss0` on a path no caller asked to be
    /// destructive; `commit_resume` fails closed for the same reason. Without
    /// this test a "recover by re-seeding" edit passes the whole suite, because
    /// the corruption tests above only exercise the reader.
    #[test]
    fn a_corrupt_contact_record_wedges_every_update() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x71);
        let mut bytes = contact(FIRST_SEEN, LAST_SEEN).encode().to_vec();
        bytes[0] = CONTACT_RECORD_VERSION + 1;
        write_contact_bytes(&p, &l, &bytes);
        let seals = p.store().seal_count();

        // Annotated for `a_failed_contact_update_leaves_the_record_untouched`'s
        // reason: a closure that only diverges infers no `T`.
        let err: Result<(), DmPersistError> = p.update_contact(
            &l,
            || panic!("the update recovered from a corrupt record by re-seeding"),
            |_| panic!("the closure ran against a record that does not decode"),
        );
        assert!(
            matches!(
                err,
                Err(DmPersistError::Contact(
                    ContactCacheError::UnsupportedVersion { .. }
                ))
            ),
            "wrong error: {err:?}"
        );
        assert_eq!(
            p.store().seal_count(),
            seals,
            "a wedged update wrote something"
        );

        // And the bytes are still there for whatever decides what to do about
        // them — refusing must not be a slow delete.
        assert_eq!(
            std::fs::read(record_path(&p, &l, "contact-cache.bin"))
                .expect("reads")
                .len(),
            RecordKind::ContactCache.on_disk_len()
        );
    }

    /// An `Unchanged` report that is not true is caught in debug builds, rather
    /// than silently discarding the caller's sighting.
    ///
    /// This is the one error [`Mutation`] cannot refuse by construction: the
    /// type forces an answer and cannot force a true one. It is checked on the
    /// stored path only — on the seeded path the write happens regardless, so
    /// there is nothing a false report can lose.
    #[test]
    #[should_panic(expected = "reported Mutation::Unchanged after changing the")]
    #[cfg(debug_assertions)]
    fn a_lying_unchanged_contact_report_is_caught_in_debug_builds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x68);

        seed_contact(&p, &l, contact(FIRST_SEEN, LAST_SEEN));

        let _ = p.update_contact(
            &l,
            || panic!("a record exists"),
            |c| {
                assert!(
                    c.observed_at(LAST_SEEN + 5),
                    "the fixture's mutation was refused"
                );
                // The lie: a real sighting reported as no change at all.
                Ok(Mutation::Unchanged(()))
            },
        );
    }

    /// Two correspondences do not share a contact record.
    #[test]
    fn a_contact_record_is_per_correspondence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());

        seed_contact(&p, &label(0x69), contact(FIRST_SEEN, LAST_SEEN));
        assert!(
            p.read_contact(&label(0x6A)).expect("reads").is_none(),
            "one correspondence's contact record was visible to another"
        );
    }
    // ---- the block list ---------------------------------------------------

    /// A key whose bytes depend on `seed` throughout, so a round trip that
    /// truncated or shifted could not pass.
    fn block_key(seed: u16) -> [u8; oxicrypt_ml_dsa::PK_LEN] {
        let mut k = [0u8; oxicrypt_ml_dsa::PK_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u16).wrapping_mul(31).wrapping_add(seed) as u8;
        }
        // Both halves of the seed land in their own byte, so keys are distinct
        // across the whole `u16` range rather than colliding every 256 seeds —
        // which at a 512-entry ceiling would silently halve the fixture.
        k[0] = (seed >> 8) as u8;
        k[1] = seed as u8;
        k
    }

    /// The record's whole reason for existing: a block survives a restart.
    #[test]
    fn a_block_survives_reopening_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let blocked = block_key(11);
        let stranger = block_key(12);

        {
            let p = persist(tmp.path());
            assert!(
                p.read_block_list().unwrap().is_empty(),
                "a fresh profile blocks nobody"
            );
            p.update_block_list(|list| Ok(list.block(&blocked)))
                .unwrap();
        }

        let reopened = persist(tmp.path());
        let list = reopened.read_block_list().unwrap();
        assert!(list.is_blocked(&blocked), "the block did not survive");
        assert!(
            !list.is_blocked(&stranger),
            "and it blocked only the identity it named"
        );

        // Reversal, across another restart.
        reopened
            .update_block_list(|list| Ok(list.unblock(&blocked)))
            .unwrap();
        assert!(
            !persist(tmp.path())
                .read_block_list()
                .unwrap()
                .is_blocked(&blocked),
            "an unblock did not survive"
        );
    }

    /// **The privacy claim, as one assertion.** The record is the same number of
    /// bytes holding nobody, one identity, and the full 512.
    ///
    /// The occupancy is read back at each step, so a run where the writes
    /// silently did nothing — which would also produce three equal sizes — fails
    /// here rather than passing as the property under test.
    #[test]
    fn the_records_size_does_not_track_how_many_identities_are_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let path = p.store().root().join(RecordKind::BlockList.file_name());

        let mut sizes = Vec::new();
        let mut occupancies = Vec::new();
        for count in [0usize, 1, BLOCK_LIST_MAX_ENTRIES] {
            p.update_block_list(|list| {
                while list.len() < count {
                    let seed = list.len() as u16;
                    assert!(list.block(&block_key(seed)), "duplicate fixture key");
                }
                Ok(())
            })
            .unwrap();
            occupancies.push(p.read_block_list().unwrap().len());
            sizes.push(std::fs::metadata(&path).unwrap().len());
        }

        assert_eq!(
            occupancies,
            vec![0, 1, BLOCK_LIST_MAX_ENTRIES],
            "the writes must actually have changed the occupancy"
        );
        assert!(
            sizes.windows(2).all(|w| w[0] == w[1]),
            "blocking nobody and blocking 512 must be the same size on disk: {sizes:?}"
        );
        assert_eq!(
            sizes[0] as usize,
            RecordKind::BlockList.on_disk_len(),
            "and that size is the kind's fixed one"
        );
    }

    /// The ceiling refuses the write and leaves the stored list intact.
    #[test]
    fn blocking_past_the_ceiling_refuses_and_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());

        p.update_block_list(|list| {
            for seed in 0..BLOCK_LIST_MAX_ENTRIES {
                assert!(list.block(&block_key(seed as u16)));
            }
            Ok(())
        })
        .unwrap();

        let one_too_many = block_key(BLOCK_LIST_MAX_ENTRIES as u16);
        let refused = p.update_block_list(|list| Ok(list.block(&one_too_many)));
        assert!(
            matches!(
                refused,
                Err(DmPersistError::BlockList(BlockListError::Full { .. }))
            ),
            "the 513th identity must be refused: {refused:?}"
        );

        let stored = p.read_block_list().unwrap();
        assert_eq!(
            stored.len(),
            BLOCK_LIST_MAX_ENTRIES,
            "the refused write must leave the stored list exactly as it was"
        );
        assert!(!stored.is_blocked(&one_too_many));
    }

    /// A removed record is an error, never an empty list.
    ///
    /// Answering absence with "nobody is blocked" would make deleting one file
    /// the whole of a block bypass.
    #[test]
    fn a_removed_block_list_record_is_refused_rather_than_read_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let path = p.store().root().join(RecordKind::BlockList.file_name());

        // Control: it reads before the removal.
        p.read_block_list().unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(
            matches!(p.read_block_list(), Err(DmPersistError::BlockListMissing)),
            "a removed revocation list must not read as an empty one"
        );
        assert!(matches!(
            p.update_block_list(|list| Ok(list.len())),
            Err(DmPersistError::BlockListMissing)
        ));
    }

    // ---- state loss versus restart (#261) ----------------------------------

    /// The `ss0` a contact record built by `contact_tagged` holds, so a knock can
    /// be built to match one or to differ from it deliberately.
    fn ss0_tagged(tag: u8) -> [u8; SS0_LEN] {
        let mut out = ss0();
        out[0] ^= tag;
        out
    }

    /// An opened first-contact entry from the identity `pk(tag)`, carrying
    /// `secret` as its encapsulated `ss0`.
    ///
    /// The roots are derived from that secret rather than passed in, because it
    /// is exactly their agreement with `ss0` that the predicate reads; a fixture
    /// free to disagree could pass while the production derivation was wrong.
    fn knock(tag: u8, secret: [u8; SS0_LEN]) -> VerifiedFirstContact {
        let roots = derive_channel_roots(&secret).expect("roots");
        let mut ek = vec![0u8; oxicrypt_ml_kem::EK_LEN].into_boxed_slice();
        for (i, b) in ek.iter_mut().enumerate() {
            *b = tag.wrapping_add((i as u8).wrapping_mul(5));
        }
        VerifiedFirstContact::new_for_test(
            pk(tag),
            pk(tag.wrapping_add(0x7F)),
            ek.try_into().expect("allocated at EK_LEN"),
            0,
            FIRST_SEEN,
            "hello again".to_string(),
            secret,
            roots,
        )
    }

    /// One unsealed entry and one sealed one, the two shapes a teardown parts.
    fn seed_two_pending(p: &DmPersist, l: &CorrespondenceLabel, now: i64) {
        p.update_outbox(l, Direction::AToB, now, |outbox| {
            outbox.enqueue_awaiting_key(1, OutboxTarget::ChannelPage, now)?;
            outbox.enqueue_sealed(
                2,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![0x5C; 8]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");
    }

    /// Both entries as the store holds them, so an assertion reads what was
    /// persisted rather than what an in-memory outbox was left saying.
    fn stored_states(p: &DmPersist, l: &CorrespondenceLabel, now: i64) -> Vec<DeliveryState> {
        let ob = p.read_outbox(l, now).expect("reads").expect("present");
        [1u64, 2]
            .into_iter()
            .map(|seq| ob.entry(seq).expect("the entry").delivery_state())
            .collect()
    }

    /// **A known correspondent knocking under a channel we do not hold stops the
    /// queue at once — both entry shapes, sealed included.**
    ///
    /// The sealed half is the whole of #261: every other teardown keeps a sealed
    /// frame re-seeding, because the correspondent can still derive its address
    /// and still open it. Here they can do neither.
    #[test]
    fn a_fresh_channel_from_a_known_correspondent_ends_every_pending_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB1);
        let now = FIRST_SEEN;

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_two_pending(&p, &l, now);
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Composed, DeliveryState::Composed],
            "the fixture did not start pending"
        );

        // A different `ss0` from the same identity: they minted a new one, which
        // only a correspondent who lost their at-rest state does.
        let fresh = knock(0x01, ss0_tagged(0xAA));
        let (correspondence, teardown, outcome) =
            match p.correspondent_state_lost(&fresh, Direction::AToB, now) {
                Ok(StateLoss::Confirmed {
                    correspondence,
                    teardown,
                    outcome,
                }) => (correspondence, teardown, outcome),
                other => panic!("a fresh channel was not read as state loss: {other:?}"),
            };

        assert_eq!(correspondence, l);
        assert_eq!(outcome.surfaced, vec![1, 2]);
        assert!(
            outcome.retained.is_empty(),
            "an entry was left re-seeding into an address that cannot be read"
        );
        assert_eq!(
            teardown.event(),
            TrustEventKey::DmCorrespondentStateLost,
            "the user would be told the wrong thing about why this stopped"
        );

        // Persisted, not merely returned — the whole point of the persist-side
        // call, and what stops the re-seed surviving the next load.
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Undelivered, DeliveryState::Undelivered]
        );
        let reloaded = p.read_outbox(&l, now).expect("reads").expect("present");
        for seq in [1u64, 2] {
            let entry = reloaded.entry(seq).expect("the entry");
            assert!(
                !entry.is_due(now + 7 * DAY_MS),
                "entry {seq} is still due to be re-seeded"
            );
            assert_eq!(
                entry.surfacing(),
                Surfacing::Owed,
                "entry {seq} stopped without anything owed to the user"
            );
        }
    }

    /// **The restart control: a correspondent who kept their at-rest state
    /// cannot reach the acting branch, and their queue is untouched.**
    ///
    /// A restart re-establishes on the channel plane under the `AR` it still
    /// holds, so the only first-contact entry it can produce is the *same* entry
    /// re-seeded — which the design has it doing on the full schedule until it
    /// sees evidence of establishment, for up to seven days after an
    /// introduction that worked. Firing on that would mark live messages
    /// undelivered on a healthy correspondence.
    ///
    /// The two knocks differ only in `ss0`, so a predicate that fired on "a
    /// known identity knocked" passes the test above and fails here.
    #[test]
    fn a_reseeded_entry_from_an_established_correspondent_is_not_state_loss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB2);
        let now = FIRST_SEEN;

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_two_pending(&p, &l, now);

        // The same `ss0` the record was written from: the introduction we
        // already accepted, arriving again.
        let reseed = knock(0x01, ss0_tagged(0x01));
        match p.correspondent_state_lost(&reseed, Direction::AToB, now) {
            Ok(StateLoss::SameChannel(named)) => assert_eq!(named, l),
            other => panic!("a re-seed was read as state loss: {other:?}"),
        }
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Composed, DeliveryState::Composed],
            "a re-seed ended a live message"
        );

        // And our own restart, the other thing that must not fire: the teardown
        // it produces keeps every sealed frame trying to arrive.
        let torn = p
            .update_outbox(&l, Direction::AToB, now, |outbox| {
                Ok(Mutation::Changed(outbox.channel_torn_down(
                    &TeardownCause::NoProvisionalRecord,
                    now,
                )))
            })
            .expect("tears down");
        assert_eq!(
            torn.retained,
            vec![2],
            "our own restart abandoned a sealed frame"
        );
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Undelivered, DeliveryState::Composed],
            "our own restart did not leave the sealed frame alone"
        );
    }

    /// A knock from an identity this side has knocked at, and not yet been
    /// accepted by, is not state loss.
    ///
    /// **Kills a `correspondent_state_lost` that reads a pseudonym-less record
    /// like any other.** Such a record was written by this side's own entry,
    /// under the root of an `ss0` this side encapsulated; the knock carries the
    /// root of an `ss0` the correspondent encapsulated, so the two roots never
    /// agree and the root comparison would report state loss on every mutual
    /// knock — ending this side's own pending messages on a correspondence that
    /// is about to work. The inference needs an established correspondence to
    /// be about.
    #[test]
    fn a_knock_from_an_identity_whose_entry_is_unanswered_is_not_state_loss() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB8);
        let now = FIRST_SEEN;

        // This side's entry, under one root.
        let ours = derive_channel_roots(&ss0_tagged(0x11))
            .expect("derives")
            .ar();
        p.record_first_contact_sent(&l, pk(0x11), Zeroizing::new(ours), FIRST_SEEN)
            .expect("the entry was not recorded");
        seed_two_pending(&p, &l, now);

        // Their entry, under another — which is what every knock from them
        // carries, because the secret is theirs.
        let theirs = knock(0x11, ss0_tagged(0x22));
        assert_ne!(
            theirs.roots().ar(),
            ours,
            "the fixture's two entries address one channel, so the roots agree \
             for the wrong reason"
        );
        match p.correspondent_state_lost(&theirs, Direction::AToB, now) {
            Ok(StateLoss::NoCorrespondence) => {}
            other => {
                panic!("an unanswered entry of our own was read as their state loss: {other:?}")
            }
        }
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Composed, DeliveryState::Composed],
            "a mutual knock ended this side's own pending messages"
        );
    }

    /// Both parties knocking before either answers leaves one correspondence
    /// holding the identity, not two.
    ///
    /// **Kills an `accept_first_contact` that leaves this side's own
    /// pseudonym-less record where it found it.** Two records under one
    /// identity make [`DmPersist::correspondence_for_pk_lt`] answer
    /// [`DmPersistError::AmbiguousCorrespondent`] for ever, and every consumer
    /// of that lookup fails closed on it — the identity becomes unroutable for
    /// the life of the store, which is worse than either record alone.
    #[test]
    fn accepting_a_knock_supersedes_our_own_unanswered_entry_to_that_identity() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let ours = label(0xB9);
        let ar = derive_channel_roots(&ss0_tagged(0x33))
            .expect("derives")
            .ar();
        p.record_first_contact_sent(&ours, pk(0x33), Zeroizing::new(ar), FIRST_SEEN)
            .expect("the entry was not recorded");
        assert_eq!(
            p.correspondence_for_pk_lt(&pk(0x33)).expect("lookup"),
            Some(ours),
            "the fixture did not record the entry it is about"
        );

        let (label, _ratchet) = p
            .accept_first_contact(knock(0x33, ss0_tagged(0x44)), &accepting_s_pc(), LAST_SEEN)
            .expect("the acceptance was refused");
        assert_ne!(label, ours, "the acceptance reused the entry's own label");

        assert_eq!(
            p.correspondence_for_pk_lt(&pk(0x33)).expect("lookup"),
            Some(label),
            "the identity no longer names a single correspondence"
        );
        assert!(
            p.read_contact(&ours).expect("reads").is_none(),
            "the superseded record is still on disk"
        );
        assert!(
            p.read_contact(&label)
                .expect("reads")
                .expect("a record")
                .pk_pc()
                .is_some(),
            "the established record carries no pseudonym"
        );
    }

    /// A second entry to one identity never lands under a second label.
    ///
    /// **Kills a `record_first_contact_sent` that only checks the label it was
    /// given.** A handshake record ages out after two first-contact epochs, so
    /// a caller re-sending an entry after that cannot recover the label from
    /// the record and may mint a fresh one. Writing through it would put a
    /// second contact record under one identity, which is the permanently
    /// unroutable state.
    #[test]
    fn a_second_entry_under_a_fresh_label_is_refused() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let first = label(0xBA);
        let second = label(0xBB);
        let ar = derive_channel_roots(&ss0_tagged(0x55))
            .expect("derives")
            .ar();

        p.record_first_contact_sent(&first, pk(0x55), Zeroizing::new(ar), FIRST_SEEN)
            .expect("the entry was not recorded");
        assert!(
            matches!(
                p.record_first_contact_sent(&second, pk(0x55), Zeroizing::new(ar), LAST_SEEN),
                Err(DmPersistError::AlreadyEstablished)
            ),
            "a second label took a second record for one identity"
        );
        assert!(
            p.read_contact(&second).expect("reads").is_none(),
            "the refused write left a record behind"
        );
        assert_eq!(
            p.correspondence_for_pk_lt(&pk(0x55)).expect("lookup"),
            Some(first),
            "the identity stopped naming a single correspondence"
        );
    }

    /// **An identity no correspondence holds touches nothing.** An ordinary
    /// first contact from a stranger, which is most of them.
    #[test]
    fn a_first_contact_from_an_unknown_identity_is_not_state_loss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB3);
        let now = FIRST_SEEN;

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_two_pending(&p, &l, now);

        let stranger = knock(0x40, ss0_tagged(0x40));
        match p.correspondent_state_lost(&stranger, Direction::AToB, now) {
            Ok(StateLoss::NoCorrespondence) => {}
            other => panic!("a stranger was read as a correspondent: {other:?}"),
        }
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Composed, DeliveryState::Composed],
            "a stranger's knock ended someone else's messages"
        );
    }

    /// **Two correspondences holding one identity key stop nothing at all.**
    ///
    /// Failing closed: ending an entry is terminal, so a wrong guess here cannot
    /// be undone by a later correct answer, and there is nothing in the store
    /// that says which queue belongs to the lost state. Refusing costs only the
    /// optimisation — both queues fall back to the give-up.
    #[test]
    fn an_ambiguous_correspondent_stops_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let (one, two) = (label(0xB4), label(0xB5));
        let now = FIRST_SEEN;

        seed_contact(&p, &one, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_two_pending(&p, &one, now);
        seed_two_pending(&p, &two, now);

        // Positive control: with one holder the call really does act, so the
        // refusal below is the duplicate rather than a fixture that never fired.
        let fresh = knock(0x01, ss0_tagged(0xAA));
        assert!(matches!(
            p.correspondent_state_lost(&fresh, Direction::AToB, now),
            Ok(StateLoss::Confirmed { .. })
        ));

        // Re-seed the first queue and add the duplicate holder.
        p.update_outbox(&one, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(
                3,
                OutboxTarget::ChannelPage,
                now,
                SealedFrame::new(vec![0x77; 4]),
                0,
            )?;
            Ok(Mutation::Changed(()))
        })
        .expect("seeds");
        seed_contact(&p, &two, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));

        match p
            .correspondent_state_lost(&fresh, Direction::AToB, now)
            .expect_err("an ambiguous identity was resolved to one correspondence")
        {
            DmPersistError::AmbiguousCorrespondent { matches } => assert_eq!(matches, 2),
            other => panic!("wrong error: {other:?}"),
        }

        for (l, seqs) in [(one, vec![3u64]), (two, vec![1, 2])] {
            let ob = p.read_outbox(&l, now).expect("reads").expect("present");
            for seq in seqs {
                assert!(
                    ob.entry(seq).expect("the entry").is_due(now),
                    "the refusal still ended entry {seq}"
                );
            }
        }
    }

    /// **A correspondence with an idle queue costs no seal**, so the signal can
    /// be answered on every knock without the store paying for it.
    #[test]
    fn state_loss_on_an_idle_queue_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB6);
        let now = FIRST_SEEN;

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        assert!(
            p.read_outbox(&l, now).expect("reads").is_none(),
            "the fixture already had an outbox"
        );

        let fresh = knock(0x01, ss0_tagged(0xAA));
        match p.correspondent_state_lost(&fresh, Direction::AToB, now) {
            Ok(StateLoss::Confirmed { outcome, .. }) => {
                assert!(outcome.surfaced.is_empty());
                assert!(outcome.retained.is_empty());
            }
            other => panic!("a fresh channel was not read as state loss: {other:?}"),
        }
        assert!(
            p.read_outbox(&l, now).expect("reads").is_none(),
            "an idle queue was written back as an empty record"
        );
    }

    /// **An unreadable contact record fails the call; it does not read as a
    /// stranger.** Reading it as absence would answer `NoCorrespondence` for an
    /// identity whose record is on disk, and the caller's remedy for a stranger
    /// is to run first contact — minting a second correspondence for one
    /// identity, which is the duplicate this path refuses to resolve. Softening
    /// the propagation to `.ok().flatten()` fails here and nowhere else.
    #[test]
    fn an_unreadable_contact_record_fails_the_call_rather_than_reading_as_a_stranger() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB7);
        let now = FIRST_SEEN;

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_two_pending(&p, &l, now);
        let fresh = knock(0x01, ss0_tagged(0xAA));

        // Positive control: readable, the call reaches its decision.
        assert!(matches!(
            p.correspondent_state_lost(&fresh, Direction::AToB, now),
            Ok(StateLoss::Confirmed { .. })
        ));

        // Re-seed the queue, then corrupt the record around the reader.
        seed_two_pending(&p, &label(0xB8), now);
        let mut bytes = contact_tagged(0x01, FIRST_SEEN, LAST_SEEN)
            .encode()
            .to_vec();
        bytes[0] = CONTACT_RECORD_VERSION + 1;
        write_contact_bytes(&p, &l, &bytes);

        match p
            .correspondent_state_lost(&fresh, Direction::AToB, now)
            .expect_err("an unreadable contact record read as a stranger")
        {
            DmPersistError::Contact(ContactCacheError::UnsupportedVersion { .. }) => {}
            other => panic!("wrong error: {other:?}"),
        }
        // The other correspondence's queue is untouched: the refusal stopped
        // before any write, rather than half-marking the store.
        let ob = p
            .read_outbox(&label(0xB8), now)
            .expect("reads")
            .expect("present");
        assert!(ob.entry(2).expect("the entry").is_due(now));
    }

    /// **`direction` is used, not decorative.** Every other test here passes
    /// `AToB`, so hardcoding the direction inside the call would survive all of
    /// them; a caller confused about which end it is must be refused rather than
    /// quietly answered with the record's own direction.
    #[test]
    fn the_wrong_direction_is_refused_and_marks_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0xB9);
        let now = FIRST_SEEN;

        seed_contact(&p, &l, contact_tagged(0x01, FIRST_SEEN, LAST_SEEN));
        seed_two_pending(&p, &l, now); // seeded AToB
        let fresh = knock(0x01, ss0_tagged(0xAA));

        match p
            .correspondent_state_lost(&fresh, Direction::BToA, now)
            .expect_err("the other direction was accepted")
        {
            DmPersistError::OutboxDirectionMismatch { stored, requested } => {
                assert_eq!(stored, Direction::AToB);
                assert_eq!(requested, Direction::BToA);
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert_eq!(
            stored_states(&p, &l, now),
            vec![DeliveryState::Composed, DeliveryState::Composed],
            "a refused call still ended a message"
        );

        // Positive control: the right direction on the same fixture does act,
        // so the refusal above is the direction and not a wedged store.
        assert!(matches!(
            p.correspondent_state_lost(&fresh, Direction::AToB, now),
            Ok(StateLoss::Confirmed { .. })
        ));
    }

    /// **`DmPersistError::FirstContact` renders, sources and converts.** A
    /// variant no test constructs is a variant whose `Display` and `source` are
    /// whatever they were typed as.
    #[test]
    fn a_channel_root_failure_renders_and_keeps_its_source() {
        let err: DmPersistError = FirstContactError::Aead.into();
        match &err {
            DmPersistError::FirstContact(FirstContactError::Aead) => {}
            other => panic!("the From impl built the wrong variant: {other:?}"),
        }
        let rendered = err.to_string();
        assert!(
            rendered.starts_with("channel roots: ") && rendered.contains("did not open"),
            "unhelpful rendering: {rendered}"
        );
        // It wraps something, unlike the variants that are this module's own
        // findings — so a caller can reach the underlying fault.
        assert!(
            std::error::Error::source(&err).is_some(),
            "a wrapped first-contact error reported no source"
        );
    }

    // ---- the acceptor's establishment -------------------------------------

    /// `accept_first_contact` is one act: the correspondence it returns is the
    /// one `correspondence_for_pk_lt` finds, and the record it wrote carries
    /// the knock's own keys.
    ///
    /// The lookup is the positive control that matters — a call that minted a
    /// label and built a ratchet without writing anything would return the same
    /// pair and leave the identity unknown on disk.
    ///
    /// **This is also the production guard for § D-PFS**, and the only one.
    /// `ROOT_LEN` and `SS0_LEN` are both 32, so writing `*ss0` where the derived
    /// root belongs compiles clean; the `addresses_same_channel` assertion below
    /// is what kills it. `dm::contact_cache`'s own `ss0`-absence scan cannot —
    /// the type has no field for it to find.
    #[test]
    fn accepting_a_knock_establishes_a_findable_correspondence() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());

        assert!(
            p.correspondence_for_pk_lt(&pk(9))
                .expect("lookup")
                .is_none(),
            "the identity is unknown before the accept"
        );

        let knock = knock(9, ss0());
        let expected_pk_pc = *knock.pk_pc();
        let (label, ratchet) = p
            .accept_first_contact(knock, &accepting_s_pc(), FIRST_SEEN)
            .expect("accepts");

        assert_eq!(
            p.correspondence_for_pk_lt(&pk(9)).expect("lookup"),
            Some(label),
            "the accepted identity resolves to the label that was returned"
        );
        let stored = p.read_contact(&label).expect("read").expect("a record");
        assert_eq!(stored.pk_lt().as_slice(), pk(9).as_slice());
        assert_eq!(
            stored
                .pk_pc()
                .expect("the acceptor records a pseudonym")
                .as_slice(),
            expected_pk_pc.as_slice()
        );
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), FIRST_SEEN);
        // The ratchet handed back is over the same `ss0` the record's root came
        // from: `accept_first_contact` derives `AR` from the established secret
        // and stores that, and the ratchet's conversation fingerprint derives
        // from the same value, so agreement here is agreement about which
        // secret was established.
        assert!(
            stored.addresses_same_channel(&derive_channel_roots(&ss0()).expect("roots").ar()),
            "the stored record does not address the knock's channel"
        );
        assert_eq!(
            ratchet.ar_fingerprint(),
            &crate::dm::firstcontact::conversation_binding(&ss0()).expect("binding"),
            "the ratchet is over a different conversation than the record"
        );
    }

    /// **The acceptor's establishment writes a complete resume record**, so the
    /// correspondence can speak a re-establishment leg after the next restart.
    ///
    /// Every field asserted here is one that cannot be recovered from anywhere
    /// else once this call returns: `S_pc` is not derivable from the shared
    /// secret or the mnemonic, the peer's `PK_pc` arrived only in the knock, and
    /// `RS_0` is an Expand sibling of an `ss0` the establishment destroys. A
    /// record missing any of them is a correspondence that reads as established
    /// and can never re-establish.
    #[test]
    fn accepting_a_knock_writes_the_resume_record_a_reconnect_needs() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());

        let knock = knock(9, ss0());
        let expected_pk_pc = *knock.pk_pc();
        let (label, _ratchet) = p
            .accept_first_contact(knock, &accepting_s_pc(), FIRST_SEEN)
            .expect("accepts");

        let resume = p
            .read_resume(&label)
            .expect("reads")
            .expect("the acceptance wrote a resume record");
        assert_eq!(
            resume.s_pc().as_slice(),
            accepting_s_pc().as_slice(),
            "the signing key the caller minted is not the one on disk"
        );
        assert_eq!(
            resume.pk_pc().as_slice(),
            expected_pk_pc.as_slice(),
            "the record verifies legs under a key the correspondent never signed with"
        );
        assert_eq!(
            resume.committed_root().as_bytes(),
            derive_channel_roots(&ss0())
                .expect("roots")
                .rs0()
                .as_bytes(),
            "the committed re-establishment root is not the sibling of the established secret"
        );
        assert_eq!(
            resume.reconnect_gen(),
            0,
            "a first establishment has completed no handshake"
        );
        assert!(
            resume.own_slot().is_none() && resume.acceptance().is_none(),
            "a first establishment has no handshake in flight to record"
        );
        assert!(
            resume.retained().is_none(),
            "a first establishment has superseded no root"
        );
        assert_eq!(
            resume.send_floor(),
            SendFloor::new(0, 0),
            "the acceptor has sent nothing, so its floor is the opening one"
        );
        assert_eq!(
            resume.attempt(),
            None,
            "a first establishment has attempted no re-establishment"
        );
    }

    /// **The write order inside `accept_first_contact` is not pinned by a test,
    /// and the limit is the store rather than the argument**: nothing here can
    /// make the contact write fail while the resume write succeeds, so the state
    /// the ordering exists to avoid — an established correspondence with no
    /// `S_pc` — has no fixture that reaches it. What is pinned is that both
    /// records are present after a successful accept
    /// (`accepting_a_knock_writes_the_resume_record_a_reconnect_needs` and
    /// `accepting_a_knock_establishes_a_findable_correspondence`), and the order
    /// itself is stated at the call site.
    #[test]
    fn accepting_a_knock_leaves_both_records_present() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (label, _ratchet) = p
            .accept_first_contact(knock(9, ss0()), &accepting_s_pc(), FIRST_SEEN)
            .expect("accepts");
        assert!(p.read_resume(&label).expect("reads").is_some());
        assert!(p.read_contact(&label).expect("reads").is_some());
    }

    /// The acceptor's establishment writes NO provisional record. That record is
    /// the initiator's, and one written here would be `ss0` left on disk with
    /// nothing that ever deletes it.
    #[test]
    fn accepting_a_knock_writes_no_provisional_record() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let (label, _ratchet) = p
            .accept_first_contact(knock(9, ss0()), &accepting_s_pc(), FIRST_SEEN)
            .expect("accepts");

        // Positive control: the contact record IS there, so the assertion below
        // is not passing against a correspondence that was never established.
        assert!(
            p.read_contact(&label).expect("read").is_some(),
            "the contact record was not written in the first place"
        );
        assert!(
            p.store()
                .read_unlocked(&label, RecordKind::Provisional)
                .expect("read")
                .is_none(),
            "the acceptor wrote a provisional record"
        );
    }

    /// Two accepts of two different identities mint two labels.
    #[test]
    fn two_accepts_mint_two_labels() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let mut other = ss0();
        other[0] ^= 0xFF;
        let (a, _) = p
            .accept_first_contact(knock(9, ss0()), &accepting_s_pc(), FIRST_SEEN)
            .expect("accepts");
        let (b, _) = p
            .accept_first_contact(knock(11, other), &accepting_s_pc(), FIRST_SEEN)
            .expect("accepts");
        assert_ne!(a, b, "each accept minted its own label");
        assert_eq!(p.store().correspondences().expect("list").len(), 2);
    }

    /// A second accept for one identity is refused, and the first
    /// correspondence is still the only one.
    ///
    /// The lookup after the refusal is the half that matters: a version that
    /// minted a second label would also return `Ok`, so asserting only on the
    /// error would pass against a store that had already been made ambiguous.
    #[test]
    fn a_second_accept_for_one_identity_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());

        let (first, _r) = p
            .accept_first_contact(knock(9, ss0()), &accepting_s_pc(), FIRST_SEEN)
            .expect("the first accept establishes");

        // A genuinely different knock from the same identity — a fresh `ss0`,
        // so it is not the same entry arriving twice.
        let mut other = ss0();
        other[0] ^= 0xFF;
        let err = p
            .accept_first_contact(knock(9, other), &accepting_s_pc(), FIRST_SEEN)
            .expect_err("the second accept is refused");
        assert!(
            matches!(err, DmPersistError::AlreadyEstablished),
            "wrong refusal: {err:?}"
        );

        assert_eq!(
            p.correspondence_for_pk_lt(&pk(9)).expect("lookup"),
            Some(first),
            "the identity still resolves to exactly one correspondence"
        );
        assert_eq!(
            p.store().correspondences().expect("list").len(),
            1,
            "the refused accept left a second correspondence behind"
        );
    }

    /// A write failure inside the accept leaves nothing established.
    ///
    /// The store root is made unwritable, so `update_contact`'s replace fails
    /// while every derivation before it succeeds — which is the ordering the
    /// method's docs claim, tested rather than asserted.
    #[test]
    #[cfg(unix)]
    fn an_accept_whose_write_fails_establishes_nothing() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let root = p.store().root().to_path_buf();

        // Positive control: the root is writable, and an accept here would
        // succeed — asserted by doing one and then undoing the profile.
        assert!(root.is_dir(), "the store root was never created");

        let mut perms = std::fs::metadata(&root).expect("metadata").permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&root, perms).expect("chmod");

        let result = p.accept_first_contact(knock(9, ss0()), &accepting_s_pc(), FIRST_SEEN);

        let mut perms = std::fs::metadata(&root).expect("metadata").permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&root, perms).expect("chmod back");

        assert!(result.is_err(), "an unwritable store still accepted");
        assert_eq!(
            p.correspondence_for_pk_lt(&pk(9)).expect("lookup"),
            None,
            "a failed accept left a correspondence behind"
        );
    }

    // ---- block-list provisioning -------------------------------------------

    /// A store that already has its block list is left alone, and one whose
    /// record is gone gets it back.
    ///
    /// The removal is the positive control, and it is the case the call exists
    /// for: `DmStore::open` creates the record best-effort under
    /// `try_acquire`, so a second opener racing the first returns with it
    /// absent, and every consult and change then refuses until something
    /// re-creates it.
    #[test]
    fn provisioning_replaces_a_missing_block_list_and_only_then() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());

        assert!(
            p.read_block_list().expect("read").is_empty(),
            "the store's own open did not create the record"
        );
        assert!(
            !p.provision_block_list().expect("provision"),
            "provisioning wrote over the record the store had already created"
        );

        // The record's own file name, spelled out here rather than asked of
        // the store, so a change to the store's naming fails here instead of
        // being followed silently.
        let path = p.store().root().join("block-list.bin");
        assert!(path.exists(), "the record is not where this test looks");
        std::fs::remove_file(&path).expect("remove");
        assert!(
            matches!(p.read_block_list(), Err(DmPersistError::BlockListMissing)),
            "removing the file did not make the record absent"
        );

        assert!(p.provision_block_list().expect("provision"), "it wrote");
        assert!(p.read_block_list().expect("read").is_empty());
        assert!(
            !p.provision_block_list().expect("provision"),
            "a second provision wrote again"
        );
    }

    /// Provisioning never discards a block.
    #[test]
    fn provisioning_leaves_an_existing_block_list_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        p.update_block_list(|list| {
            assert!(list.block(&pk(4)));
            Ok(())
        })
        .expect("block");

        assert!(
            !p.provision_block_list().expect("provision"),
            "provisioning wrote over an existing list"
        );
        let list = p.read_block_list().expect("read");
        assert_eq!(list.len(), 1, "the block survived provisioning");
        assert!(list.is_blocked(&pk(4)));
    }

    // ---------------------------------------------------------------------
    // The second handshake slot and the retained root, at the store.
    // ---------------------------------------------------------------------

    /// A record carrying whatever the caller wants in each group, with the
    /// pseudonym pair the other resume fixtures use — the pair guard refuses a
    /// change to it independently, so every fixture here must share one.
    /// **The settling leg's slot is guarded like every other durable slot on the
    /// record, and the gap it closes is a stranded peer.**
    ///
    /// A9.1(a) makes a `RE-CONFIRM` unreproducible from its inputs, and A3.15
    /// row 4 has it re-seeding until the answering side opens it — so a write
    /// built from a record read BEFORE the completion drops the only copy of a
    /// frame the peer is still waiting for. The peer then retires at `T_RETIRE`
    /// while this side has already advanced, which is the split-brain
    /// commit-then-emit exists to remove.
    ///
    /// Three refusals and two admissions, because the two writes that
    /// legitimately end the slot have to keep working: the confirming
    /// observation, which retires the retained root in the same act, and a later
    /// exchange the stored leg cannot belong to.
    #[test]
    fn the_settling_leg_may_not_be_dropped_re_sealed_or_rolled_back() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::tempdir().expect("temp dir");
        let p = persist(dir.path());
        let l = label(0xB1);
        let floor = SendFloor::new(0, 0);
        let confirm = |generation: u32, seed: u8| {
            crate::dm::resume::ConfirmSlot::new(generation, 200, vec![seed; 64].into_boxed_slice())
                .expect("within the leg ceiling")
        };
        let state = |generation: u32, slot: Option<crate::dm::resume::ConfirmSlot>| {
            crate::dm::resume::ReEstState {
                reconnect_gen: generation,
                confirm: slot,
                ..crate::dm::resume::ReEstState::first_establishment()
            }
        };
        let retained = || crate::dm::resume::Retention {
            retained: Some(crate::dm::resume::RetainedRoot::new(
                crate::dm::resume::CommittedRoot::from_bytes(
                    &[0x55u8; crate::dm::ratchet::ROOT_KEY_LEN],
                ),
                1_700_000_000_000,
            )),
            dedup: crate::dm::resume::DedupMemory::new(),
            stopped: false,
        };

        p.commit_resume(
            &l,
            &resume_with(state(4, Some(confirm(4, 0xC1))), retained(), floor),
        )
        .expect("the completion commits");

        // The stale write: a record read before the completion, so its slot is
        // empty and its generation has not moved.
        assert_eq!(
            p.commit_resume(&l, &resume_with(state(4, None), retained(), floor))
                .err()
                .map(|e| format!("{e}")),
            Some(
                "resume record: the settling leg of generation 4 may only be cleared by \
                 its confirming observation or a later exchange"
                    .to_string()
            ),
            "a stale write dropped the only copy of the settling leg"
        );
        // A second seal at one generation, which the peer dedups away.
        assert_eq!(
            p.commit_resume(
                &l,
                &resume_with(state(4, Some(confirm(4, 0xC2))), retained(), floor)
            )
            .err()
            .map(|e| format!("{e}")),
            Some(
                "resume record: the settling leg of generation 4 is already persisted \
                 under different sealed bytes"
                    .to_string()
            ),
            "the settling leg was re-sealed at one generation"
        );
        // A leg for an earlier exchange.
        assert_eq!(
            p.commit_resume(
                &l,
                &resume_with(state(4, Some(confirm(3, 0xC3))), retained(), floor)
            )
            .err()
            .map(|e| format!("{e}")),
            Some(
                "resume record: a settling leg for generation 3 is behind the stored 4".to_string()
            ),
            "the settling leg rolled back"
        );

        // **Both admissions, or the guard is a lock rather than a guard.** The
        // confirming observation ends the leg and the retained root together;
        // and a record whose generation has moved past the exchange the leg
        // settles has left it behind.
        p.commit_resume(
            &l,
            &resume_with(state(4, None), crate::dm::resume::Retention::none(), floor),
        )
        .expect("the confirming observation clears the slot");
        p.commit_resume(
            &l,
            &resume_with(state(4, Some(confirm(4, 0xC1))), retained(), floor),
        )
        .expect("re-committing the same leg is admitted");
        p.commit_resume(&l, &resume_with(state(5, None), retained(), floor))
            .expect("a later exchange leaves the old leg behind");
    }

    fn resume_with(
        handshake: crate::dm::resume::ReEstState,
        retention: crate::dm::resume::Retention,
        floor: SendFloor,
    ) -> ResumeRecord {
        ResumeRecord::new(
            Box::new([0x11u8; oxicrypt_ml_dsa::SK_LEN]),
            Box::new([0x22u8; oxicrypt_ml_dsa::PK_LEN]),
            crate::dm::resume::CommittedRoot::from_bytes(
                &[0x33u8; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            handshake,
            retention,
            floor,
        )
        .expect("the fixture's pairings are coherent")
    }

    fn attempt_of(n: u32) -> crate::dm::resume::Attempt {
        crate::dm::resume::Attempt::from_nonzero(
            std::num::NonZeroU32::new(n).expect("a real attempt"),
        )
    }

    fn acceptance(generation: u32, attempt: u32, seal: u8) -> crate::dm::resume::AcceptanceSlot {
        crate::dm::resume::AcceptanceSlot::accept(
            generation,
            attempt_of(attempt),
            55,
            vec![seal; 128].into_boxed_slice(),
        )
        .expect("within MAX_SEALED_LEG_LEN")
    }

    fn own(generation: u32, attempt: u32, seal: u8) -> crate::dm::resume::OwnSlot {
        crate::dm::resume::OwnSlot::new(
            generation,
            77,
            crate::dm::resume::SealedReEst::seal(
                fresh(attempt),
                vec![seal; 128].into_boxed_slice(),
            )
            .expect("within MAX_FRAME_LEN"),
            eph_dk_fixture(),
        )
    }

    fn dedup_key(n: u32) -> crate::dm::resume::DedupKey {
        crate::dm::resume::DedupKey::new(
            100 + n,
            attempt_of(200 + n),
            crate::dm::resume::Leg::ReEst,
            crate::dm::ratchet::Direction::AToB,
            u64::from(300 + n),
        )
    }

    /// **A5.1(ii)'s confirmation lock survives the store being dropped and
    /// reopened.**
    ///
    /// A6.1 sets the lock on the first frame that opens under the re-rooted
    /// chain, and A5.4 homes it in the durable record. Held in memory it would
    /// clear on exactly the restart this feature exists to survive, and a
    /// returning peer's stale attempt would then supersede a candidate both
    /// sides had settled.
    ///
    /// The store is dropped and rebuilt over the same directory, so the gate
    /// below is built from bytes that went to disk rather than from a value
    /// still in hand.
    ///
    /// Kills a codec or accessor that loses `confirmed`: the reloaded gate would
    /// answer `Emit` to the differing attempt instead of `Locked`.
    #[test]
    fn the_confirmation_lock_survives_a_reopen_and_then_refuses_a_differing_attempt() {
        use crate::dm::reest::{ReEstAdmission, ReEstGate};
        let dir = tempfile::tempdir().expect("tempdir");
        let l = label(0x7A);
        let floor = SendFloor::new(0, 0);

        {
            let p = persist(dir.path());
            p.commit_resume(
                &l,
                &resume_with(
                    crate::dm::resume::ReEstState {
                        reconnect_gen: 6,
                        attempt: 0,
                        last_seen_re_est: 0,
                        own: None,
                        acceptance: Some(acceptance(7, 5, 0xC1).confirm()),
                        confirm: None,
                        attempt_at_window_start: 0,
                        reroot_ratchet_gen: 0,
                    },
                    crate::dm::resume::Retention::none(),
                    floor,
                ),
            )
            .expect("commits");
        }

        let p = persist(dir.path());
        let reloaded = p
            .read_resume(&l)
            .expect("reads")
            .expect("the record is on disk");
        assert!(
            reloaded
                .acceptance()
                .expect("the slot is occupied")
                .confirmed(),
            "the lock did not survive the reopen"
        );

        let mut gate = ReEstGate::from_record(&reloaded);
        assert!(gate.is_confirmed());
        assert_eq!(
            gate.admit(7, attempt_of(6), || panic!("the budget was consulted")),
            ReEstAdmission::Locked
        );
    }

    /// **A supersede is admitted while the candidate is unconfirmed** — the
    /// control for the test above.
    ///
    /// A5.1(i): *"an unconfirmed `RS_{n+1}` may be superseded by a newer
    /// attempt's"*. Without this, a build that reported every reloaded slot as
    /// confirmed would pass there.
    ///
    /// Kills a `from_record` that hard-codes the lock on.
    #[test]
    fn an_unconfirmed_slot_reloads_and_admits_a_supersede() {
        use crate::dm::reest::{ReEstAdmission, ReEstGate};
        let dir = tempfile::tempdir().expect("tempdir");
        let l = label(0x7B);
        let floor = SendFloor::new(0, 0);

        {
            let p = persist(dir.path());
            p.commit_resume(
                &l,
                &resume_with(
                    crate::dm::resume::ReEstState {
                        reconnect_gen: 6,
                        attempt: 0,
                        last_seen_re_est: 0,
                        own: None,
                        acceptance: Some(acceptance(7, 5, 0xC1)),
                        confirm: None,
                        attempt_at_window_start: 0,
                        reroot_ratchet_gen: 0,
                    },
                    crate::dm::resume::Retention::none(),
                    floor,
                ),
            )
            .expect("commits");
        }

        let p = persist(dir.path());
        let reloaded = p
            .read_resume(&l)
            .expect("reads")
            .expect("the record is on disk");
        assert!(
            !reloaded
                .acceptance()
                .expect("the slot is occupied")
                .confirmed()
        );
        let mut gate = ReEstGate::from_record(&reloaded);
        assert_eq!(gate.admit(7, attempt_of(6), || true), ReEstAdmission::Emit);
        assert_eq!(gate.accepted().map(|(g, a)| (g, a.get())), Some((7, 6)));
    }

    /// **A3.7's coin-loser commits its abandonment and its acceptance together,
    /// at an unchanged generation, and the store admits that write.**
    ///
    /// A3.7: the loser *"abandons its own handshake and answers the winner's
    /// frame as an ordinary responder — abandonment and acceptance committed
    /// together, intra-record"*. `reconnect_gen` does not move: A3.4 advances it
    /// only by a *completed* handshake, which is two legs later. A guard keyed
    /// on the generation alone would refuse the one write A3.7 requires.
    ///
    /// Kills a guard that demands a generation advance to empty the own slot
    /// (the loser's commit would be refused) and a guard deleted outright (the
    /// second half, an initiation that disappears with nothing in its place,
    /// would be admitted). Both are asserted.
    #[test]
    fn the_coin_losers_abandonment_commits_beside_its_acceptance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x7C);
        let floor = SendFloor::new(0, 0);

        // Our own initiation contesting generation 5, committed at 4.
        let stored = resume_with(
            crate::dm::resume::ReEstState {
                reconnect_gen: 4,
                attempt: 3,
                last_seen_re_est: 0,
                own: Some(own(5, 3, 0xA1)),
                acceptance: None,
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        );
        p.commit_resume(&l, &stored).expect("commits");

        // A slot emptied by a write that ALSO minted a fresh attempt: refused.
        // The counter moving is what separates this from A3.8's give-up — the
        // initiation did not end, it was replaced by one nothing recorded.
        let vanished = resume_with(
            crate::dm::resume::ReEstState {
                reconnect_gen: 4,
                attempt: 4,
                last_seen_re_est: 0,
                own: None,
                acceptance: None,
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        );
        let err = p
            .commit_resume(&l, &vanished)
            .expect_err("an initiation may not disappear under a fresh attempt");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::OwnSlotAbandonedWithoutAcceptance {
                    attempt: 3
                })
            ),
            "wrong error: {err:?}"
        );

        // A3.8's give-up, which `ResumeRecord::abandon_attempt` writes: the slot
        // empties and the counter stands still, so the next attempt is the
        // successor of the one given up and nothing reuses its key.
        let mut abandoned = resume_with(
            crate::dm::resume::ReEstState {
                reconnect_gen: 4,
                attempt: 3,
                last_seen_re_est: 0,
                own: Some(own(5, 3, 0xA1)),
                acceptance: None,
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        );
        abandoned.abandon_attempt();
        p.commit_resume(&l, &abandoned)
            .expect("a give-up that keeps its counter commits");
        assert_eq!(attempt_number(&p, &l), 3);
        // And the record it leaves takes the successor, never the same number.
        let mut resumed = p.read_resume(&l).expect("reads").expect("there");
        resumed
            .open_attempt(
                9,
                crate::dm::resume::SealedReEst::seal(
                    fresh(4),
                    vec![0xC3u8; 256].into_boxed_slice(),
                )
                .expect("inside MAX_FRAME_LEN"),
                crate::dm::eph_dk_fixture(),
            )
            .expect("the abandoned slot is free");
        p.commit_resume(&l, &resumed)
            .expect("the successor commits");
        assert_eq!(attempt_number(&p, &l), 4);

        // Back to the contested fixture for the coin-loser's own commit below.
        p.store
            .critical_section(&l, |guard| -> Result<(), DmPersistError> {
                guard.replace(RecordKind::Resume, &stored.encode())?;
                Ok(())
            })
            .expect("the fixture restores");

        // The coin-loser's actual commit: own slot cleared, the winner's frame
        // accepted at the SAME generation the abandoned initiation contested,
        // and `reconnect_gen` unmoved.
        let loser = resume_with(
            crate::dm::resume::ReEstState {
                reconnect_gen: 4,
                attempt: 3,
                last_seen_re_est: 0,
                own: None,
                acceptance: Some(acceptance(5, 1, 0xB2)),
                confirm: None,
                attempt_at_window_start: 0,
                reroot_ratchet_gen: 0,
            },
            crate::dm::resume::Retention::none(),
            floor,
        );
        p.commit_resume(&l, &loser)
            .expect("A3.7 commits the abandonment and the acceptance together");
        let after = p.read_resume(&l).expect("reads").expect("on disk");
        assert!(after.own_slot().is_none(), "the abandonment did not land");
        assert_eq!(
            after.acceptance().expect("accepted").generation(),
            5,
            "the acceptance did not land at the contested generation"
        );
        assert_eq!(
            after.reconnect_gen(),
            4,
            "the generation must not have moved"
        );
        assert_eq!(
            after.attempt().map(|a| a.get()),
            Some(3),
            "the counter survives the slot being zeroed"
        );
    }

    /// **The monotone counter survives the completion that zeroes the own slot,
    /// so a later attempt cannot restart at 1.**
    ///
    /// A5.2 makes `attempt` monotone for the correspondence's whole lifetime and
    /// A9.2 lists it apart from the sealed frame bytes. Read out of the slot —
    /// which A3.14 zeroes on completion — the counter would restart at every
    /// completed handshake, and the rollback guard would stop firing across
    /// exactly the boundary it exists to hold.
    ///
    /// Kills `guard_attempt_counter` comparing the own slot instead of the
    /// field: after the completion the stored slot is `None`, so a slot-based
    /// comparison has nothing to refuse and admits attempt 1 over 5.
    #[test]
    fn the_attempt_counter_outlives_the_slot_a_completion_zeroes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x81);
        let floor = SendFloor::new(0, 0);

        p.commit_resume(
            &l,
            &resume_with(
                crate::dm::resume::ReEstState {
                    reconnect_gen: 4,
                    attempt: 5,
                    last_seen_re_est: 0,
                    own: Some(own(5, 5, 0xA1)),
                    acceptance: None,
                    confirm: None,
                    attempt_at_window_start: 0,
                    reroot_ratchet_gen: 0,
                },
                crate::dm::resume::Retention::none(),
                floor,
            ),
        )
        .expect("commits");

        // The completion: the generation advances and the slot is zeroed.
        p.commit_resume(
            &l,
            &resume_with(
                crate::dm::resume::ReEstState {
                    reconnect_gen: 5,
                    attempt: 5,
                    last_seen_re_est: 0,
                    own: None,
                    acceptance: None,
                    confirm: None,
                    attempt_at_window_start: 5,
                    reroot_ratchet_gen: 0,
                },
                crate::dm::resume::Retention::none(),
                floor,
            ),
        )
        .expect("a completion empties the slot and advances the generation");
        let after = p.read_resume(&l).expect("reads").expect("on disk");
        assert!(after.own_slot().is_none(), "the completion did not land");
        assert_eq!(
            after.attempt().map(|a| a.get()),
            Some(5),
            "the counter reset"
        );

        // A fresh initiation at attempt 1 below the stored counter of 5 is a
        // rollback, and is refused.
        let err = p
            .commit_resume(
                &l,
                &resume_with(
                    crate::dm::resume::ReEstState {
                        reconnect_gen: 5,
                        attempt: 1,
                        last_seen_re_est: 0,
                        own: Some(own(6, 1, 0xA2)),
                        acceptance: None,
                        confirm: None,
                        attempt_at_window_start: 0,
                        reroot_ratchet_gen: 0,
                    },
                    crate::dm::resume::Retention::none(),
                    floor,
                ),
            )
            .expect_err("the counter may not restart after a completion");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::AttemptWouldRollBack {
                    stored: 5,
                    offered: 1
                })
            ),
            "wrong error: {err:?}"
        );
        // The control: the next legitimate attempt is admitted.
        p.commit_resume(
            &l,
            &resume_with(
                crate::dm::resume::ReEstState {
                    reconnect_gen: 5,
                    attempt: 6,
                    last_seen_re_est: 0,
                    own: Some(own(6, 6, 0xA2)),
                    acceptance: None,
                    confirm: None,
                    attempt_at_window_start: 5,
                    reroot_ratchet_gen: 0,
                },
                crate::dm::resume::Retention::none(),
                floor,
            ),
        )
        .expect("attempt 6 continues the counter");
    }

    /// **`reconnect_gen` is monotone.**
    ///
    /// A3.4: generations *"advance only by a completed handshake"* and are
    /// strictly monotonic, so a record offering an earlier one describes a state
    /// this correspondence has already left — and, since a generation advance is
    /// what licenses clearing a confirmed acceptance, a generation that could go
    /// backwards would license that by going backwards first.
    ///
    /// Kills a guard written `<=`, which would refuse an unchanged generation —
    /// the ordinary case, since most resume writes change something else.
    #[test]
    fn the_reconnect_generation_never_rolls_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x7D);
        let floor = SendFloor::new(0, 0);

        let at = |generation: u32| {
            resume_with(
                crate::dm::resume::ReEstState {
                    reconnect_gen: generation,
                    attempt: 0,
                    last_seen_re_est: 0,
                    own: None,
                    acceptance: None,
                    confirm: None,
                    attempt_at_window_start: 0,
                    reroot_ratchet_gen: 0,
                },
                crate::dm::resume::Retention::none(),
                floor,
            )
        };
        p.commit_resume(&l, &at(4)).expect("commits");
        let err = p
            .commit_resume(&l, &at(3))
            .expect_err("a generation may not roll back");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::ReconnectGenWouldRollBack {
                    stored: 4,
                    offered: 3
                })
            ),
            "wrong error: {err:?}"
        );
        // Both directions of the boundary, so a `<=` guard fails here.
        p.commit_resume(&l, &at(4))
            .expect("an unchanged generation is legal");
        p.commit_resume(&l, &at(5)).expect("an advance is legal");
    }

    /// **The acceptance slot's three guards.**
    ///
    /// No attempt rollback within a generation (A5.1(i) admits only a higher
    /// one, A3.4 drops a lower); no reseal of an accepted attempt (A3.4 re-serves
    /// *the stored* `RE-ACK`, and its randomized ML-KEM ciphertext is not
    /// re-derivable); no clearing a confirmed slot without a generation advance
    /// (A5.1(ii)'s lock).
    ///
    /// Kills each guard on its own: the three cases fail with three distinct
    /// errors, and the legal writes after each are the controls that stop a
    /// guard refusing everything.
    #[test]
    fn the_acceptance_slot_may_not_roll_back_reseal_or_clear_a_confirmation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x7E);
        let floor = SendFloor::new(0, 0);
        // The window base is the highest attempt this correspondence has
        // accepted, and it never goes backwards (A6.1), so every record here
        // carries the highest the test reaches. The acceptance-slot guards under
        // test are independent of it.
        let at = |generation: u32, slot: Option<crate::dm::resume::AcceptanceSlot>| {
            resume_with(
                crate::dm::resume::ReEstState {
                    reconnect_gen: generation,
                    attempt: 0,
                    last_seen_re_est: 8,
                    own: None,
                    acceptance: slot,
                    confirm: None,
                    attempt_at_window_start: 0,
                    reroot_ratchet_gen: 0,
                },
                crate::dm::resume::Retention::none(),
                floor,
            )
        };

        p.commit_resume(&l, &at(7, Some(acceptance(7, 5, 0xC1))))
            .expect("commits");

        let err = p
            .commit_resume(&l, &at(7, Some(acceptance(7, 4, 0xC1))))
            .expect_err("an accepted attempt may not roll back");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::AcceptanceWouldRollBack {
                    stored_generation: 7,
                    stored_attempt: 5,
                    offered_generation: 7,
                    offered_attempt: 4
                })
            ),
            "wrong error: {err:?}"
        );

        let err = p
            .commit_resume(&l, &at(7, Some(acceptance(7, 5, 0xC2))))
            .expect_err("an accepted attempt may not be resealed");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::AcceptanceResealed {
                    generation: 7,
                    attempt: 5
                })
            ),
            "wrong error: {err:?}"
        );

        // The supersede is legal while unconfirmed, which is the control for the
        // rollback guard above.
        p.commit_resume(&l, &at(7, Some(acceptance(7, 6, 0xC3))))
            .expect("a higher attempt supersedes an unconfirmed candidate");
        // Now confirm it, and the clearing guard engages.
        p.commit_resume(&l, &at(7, Some(acceptance(7, 6, 0xC3).confirm())))
            .expect("confirming is a legal write");
        for offered in [None, Some(acceptance(7, 8, 0xC4))] {
            let err = p
                .commit_resume(&l, &at(7, offered))
                .expect_err("a confirmed slot may not be cleared or moved");
            assert!(
                matches!(
                    err,
                    DmPersistError::Resume(ResumeError::ConfirmedAcceptanceCleared {
                        generation: 7,
                        attempt: 6
                    })
                ),
                "wrong error: {err:?}"
            );
        }
        // The generation advance is what legitimately ends the lock.
        p.commit_resume(&l, &at(8, None))
            .expect("a generation advance retires the exchange");
        assert!(
            p.read_resume(&l)
                .expect("reads")
                .expect("on disk")
                .acceptance()
                .is_none()
        );
    }

    /// **`superseded_at_ms` is write-once per retained `RS_n`.**
    ///
    /// A5.4 stamps it at the *first* supersede *"so `T_RETIRE` cannot slide
    /// forward per re-attempt"*. Re-stamping would extend, one re-attempt at a
    /// time, the window a stale copy of the superseded root enjoys.
    ///
    /// Kills a guard keyed on presence rather than on the root's own bytes: the
    /// last write here retains a *different* root, which is a new `RS_n` and a
    /// legitimately new stamp, and a presence-keyed guard would refuse it.
    #[test]
    fn the_supersede_stamp_is_write_once_per_retained_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x7F);
        let floor = SendFloor::new(0, 0);
        let retaining = |seed: u8, stamp: i64| {
            resume_with(
                crate::dm::resume::ReEstState::first_establishment(),
                crate::dm::resume::Retention {
                    retained: Some(crate::dm::resume::RetainedRoot::new(
                        crate::dm::resume::CommittedRoot::from_bytes(
                            &[seed; crate::dm::ratchet::ROOT_KEY_LEN],
                        ),
                        stamp,
                    )),
                    dedup: crate::dm::resume::DedupMemory::new(),
                    stopped: false,
                },
                floor,
            )
        };

        p.commit_resume(&l, &retaining(0x91, 1_700_000_000_000))
            .expect("commits");
        let err = p
            .commit_resume(&l, &retaining(0x91, 1_700_000_999_999))
            .expect_err("the stamp may not slide forward");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::SupersededStampMoved {
                    stored: 1_700_000_000_000,
                    offered: 1_700_000_999_999
                })
            ),
            "wrong error: {err:?}"
        );
        // Re-offering the same stamp for the same root is the ordinary case.
        p.commit_resume(&l, &retaining(0x91, 1_700_000_000_000))
            .expect("an unchanged stamp is legal");
        // A different root is a different `RS_n`, and carries its own stamp.
        p.commit_resume(&l, &retaining(0x92, 1_700_000_999_999))
            .expect("a new retained root carries a new stamp");
    }

    /// **Dedup entries may not be dropped while their `RS_n` is still
    /// retained, and survive a reopen.**
    ///
    /// A5.3 gates eviction on *"actual `RS_n` retirement"*, because byte-novelty
    /// is what stops a co-host re-serving captured `RE-EST` bytes to re-fire the
    /// peer-state-regressed alarm — and that defence is live for exactly as long
    /// as the retained root can open those bytes. The memory is durable for the
    /// same reason: *"a lost entry is a torn security invariant"*.
    ///
    /// Kills the guard's removal (the shrinking write would be admitted) and a
    /// codec that drops the memory (the reloaded record would hold none).
    #[test]
    fn dedup_entries_survive_a_reopen_and_may_not_be_dropped_before_retirement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let l = label(0x80);
        let floor = SendFloor::new(0, 0);
        let root = |seed: u8| {
            crate::dm::resume::CommittedRoot::from_bytes(&[seed; crate::dm::ratchet::ROOT_KEY_LEN])
        };
        let retaining = |entries: u32, seed: u8| {
            let mut dedup = crate::dm::resume::DedupMemory::new();
            for n in 0..entries {
                dedup.insert(dedup_key(n)).expect("inside DEDUP_CAPACITY");
            }
            resume_with(
                crate::dm::resume::ReEstState::first_establishment(),
                crate::dm::resume::Retention {
                    retained: Some(crate::dm::resume::RetainedRoot::new(
                        root(seed),
                        1_700_000_000_000,
                    )),
                    dedup,
                    stopped: true,
                },
                floor,
            )
        };

        {
            let p = persist(dir.path());
            p.commit_resume(&l, &retaining(3, 0x91)).expect("commits");
        }

        let p = persist(dir.path());
        let reloaded = p
            .read_resume(&l)
            .expect("reads")
            .expect("the record is on disk");
        assert_eq!(reloaded.dedup().len(), 3, "the memory did not survive");
        assert!(reloaded.dedup().contains(dedup_key(0)));
        assert!(reloaded.retained_but_stopped(), "the flag did not survive");

        let err = p
            .commit_resume(&l, &retaining(1, 0x91))
            .expect_err("the memory may not shrink while its root is retained");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::DedupEvictedWhileRetained {
                    stored: 3,
                    offered: 1
                })
            ),
            "wrong error: {err:?}"
        );

        // Growing is the ordinary case, so the guard is not refusing every
        // write to the memory.
        p.commit_resume(&l, &retaining(4, 0x91))
            .expect("recording a further position is legal");

        // Retirement is what drops both, and `retire_retained` is the only act
        // that spells it — after which the memory is legitimately empty.
        let mut retired = retaining(4, 0x91);
        retired.retire_retained();
        assert!(retired.retained().is_none());
        assert!(retired.dedup().is_empty());
        p.commit_resume(&l, &retired)
            .expect("retirement drops the root and its memory together");
        let after = p.read_resume(&l).expect("reads").expect("on disk");
        assert!(after.retained().is_none());
        assert!(after.dedup().is_empty());
    }

    /// **A dedup write that swaps one key for another is refused, not just one
    /// that shrinks the set.**
    ///
    /// A5.3's memory is what stops a co-host re-serving captured `RE-EST` bytes
    /// to re-fire the peer-state-regressed alarm. A write that removes one
    /// position and adds another keeps the count and drops a position, and the
    /// frame it covered becomes byte-novel again — the same tear, invisible to a
    /// length comparison.
    ///
    /// Kills the guard comparing lengths instead of testing that every stored
    /// position is still present.
    #[test]
    fn a_dedup_write_may_not_swap_one_position_for_another() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x82);
        let floor = SendFloor::new(0, 0);
        let holding = |keys: &[u32]| {
            let mut dedup = crate::dm::resume::DedupMemory::new();
            for n in keys {
                dedup.insert(dedup_key(*n)).expect("inside DEDUP_CAPACITY");
            }
            resume_with(
                crate::dm::resume::ReEstState::first_establishment(),
                crate::dm::resume::Retention {
                    retained: Some(crate::dm::resume::RetainedRoot::new(
                        crate::dm::resume::CommittedRoot::from_bytes(
                            &[0x91; crate::dm::ratchet::ROOT_KEY_LEN],
                        ),
                        1_700_000_000_000,
                    )),
                    dedup,
                    stopped: false,
                },
                floor,
            )
        };

        p.commit_resume(&l, &holding(&[0, 1, 2])).expect("commits");
        // Same count, one position swapped out.
        let err = p
            .commit_resume(&l, &holding(&[0, 1, 9]))
            .expect_err("a stored position may not be dropped");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::DedupEvictedWhileRetained {
                    stored: 3,
                    offered: 3
                })
            ),
            "wrong error: {err:?}"
        );
        // The control: a superset is admitted, so the guard is on the set rather
        // than on the set being unchanged.
        p.commit_resume(&l, &holding(&[0, 1, 2, 9]))
            .expect("recording a further position is legal");
    }

    /// **A generation advance may carry a new acceptance pair over a confirmed
    /// one.**
    ///
    /// A5.1(ii) locks a confirmed candidate, and A3.4 ends that lock the only
    /// way it can end: the completed handshake that advances `reconnect_gen`
    /// retires the whole exchange, and the next generation's acceptance is a
    /// different exchange. Without this the accepting direction of the lock is
    /// untested and a guard that refused every write over a confirmed slot would
    /// pass.
    ///
    /// Kills `&& !advanced` being dropped from the guard's occupied arm.
    #[test]
    fn a_generation_advance_carries_a_new_acceptance_over_a_confirmed_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x83);
        let floor = SendFloor::new(0, 0);
        let at = |generation: u32, slot: Option<crate::dm::resume::AcceptanceSlot>| {
            resume_with(
                crate::dm::resume::ReEstState {
                    reconnect_gen: generation,
                    attempt: 0,
                    last_seen_re_est: 0,
                    own: None,
                    acceptance: slot,
                    confirm: None,
                    attempt_at_window_start: 0,
                    reroot_ratchet_gen: 0,
                },
                crate::dm::resume::Retention::none(),
                floor,
            )
        };

        p.commit_resume(&l, &at(6, Some(acceptance(7, 5, 0xC1).confirm())))
            .expect("commits");
        // The same pair at an unchanged generation is the control: refused.
        // Attempt 6, not 1: A5.2 makes the peer's counter monotone for the
        // correspondence's lifetime, so a later acceptance never carries a lower
        // attempt than one already observed.
        let err = p
            .commit_resume(&l, &at(6, Some(acceptance(8, 6, 0xC5))))
            .expect_err("a confirmed slot may not move without an advance");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::ConfirmedAcceptanceCleared {
                    generation: 7,
                    attempt: 5
                })
            ),
            "wrong error: {err:?}"
        );
        // With the advance, the next generation's acceptance lands.
        p.commit_resume(&l, &at(7, Some(acceptance(8, 6, 0xC5))))
            .expect("a generation advance retires the confirmed exchange");
        let after = p.read_resume(&l).expect("reads").expect("on disk");
        let slot = after.acceptance().expect("accepted");
        assert_eq!((slot.generation(), slot.attempt().get()), (8, 6));
        assert!(!slot.confirmed(), "the new candidate inherits no lock");
    }

    /// **The store licenses exactly the shrink the record's eviction performs,
    /// and no other.**
    ///
    /// A dedup position is kept only while the frame it guards can still open
    /// and raise an alarm. The scan rejects any attempt below the window base,
    /// so a position below the base guards a frame that can never open and
    /// dropping it is legal; a position at or above the base still guards an
    /// openable frame, so dropping it is refused. Without the first half the
    /// memory could only grow, the record's own eviction would be
    /// uncommittable, and a long retention would reach `DedupFull` and refuse a
    /// legitimate handshake frame (A5.3).
    ///
    /// Kills the guard testing the whole stored set rather than the part at or
    /// above the offered base (the first commit would be refused) and kills the
    /// base bound being dropped altogether (the second would be admitted).
    #[test]
    fn a_dedup_position_below_the_window_base_may_be_dropped_and_one_above_may_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x84);
        let floor = SendFloor::new(0, 0);
        let at = |n: u32| attempt_of(n);
        let key = |attempt: u32| {
            crate::dm::resume::DedupKey::new(
                1,
                at(attempt),
                crate::dm::resume::Leg::ReEst,
                crate::dm::ratchet::Direction::AToB,
                0,
            )
        };
        let holding = |base: u32, attempts: &[u32]| {
            let mut dedup = crate::dm::resume::DedupMemory::new();
            for a in attempts {
                dedup.insert(key(*a)).expect("inside DEDUP_CAPACITY");
            }
            resume_with(
                crate::dm::resume::ReEstState {
                    last_seen_re_est: base,
                    ..crate::dm::resume::ReEstState::first_establishment()
                },
                crate::dm::resume::Retention {
                    retained: Some(crate::dm::resume::RetainedRoot::new(
                        crate::dm::resume::CommittedRoot::from_bytes(
                            &[0x91; crate::dm::ratchet::ROOT_KEY_LEN],
                        ),
                        1_700_000_000_000,
                    )),
                    dedup,
                    stopped: false,
                },
                floor,
            )
        };

        p.commit_resume(&l, &holding(3, &[3, 4, 9]))
            .expect("commits");

        // The base advanced to 9, so attempts 3 and 4 can no longer open and
        // dropping them is the eviction the record performs.
        p.commit_resume(&l, &holding(9, &[9]))
            .expect("a below-base position may be dropped once the base has passed it");

        // Attempt 9 is AT the base, so it is still reachable and may not go.
        let err = p
            .commit_resume(&l, &holding(9, &[]))
            .expect_err("a position at the base is still reachable");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::DedupEvictedWhileRetained { .. })
            ),
            "wrong error: {err:?}"
        );
    }

    /// **The window base never goes backwards inside one retention.**
    ///
    /// A6.1 has the window slide with observed traffic, forward only. The base
    /// is what both the record's eviction and the store's no-shrink rule read to
    /// decide which positions still matter, so a base that could regress would
    /// let a later write re-admit frames an earlier one had put out of reach —
    /// and would re-open the very drop the guard above had just licensed.
    ///
    /// Kills the regression check being absent, and kills it written `<=`, which
    /// would refuse an unchanged base — the ordinary case, since most resume
    /// writes change something else.
    #[test]
    fn the_re_est_window_base_never_regresses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = persist(dir.path());
        let l = label(0x85);
        let floor = SendFloor::new(0, 0);
        let at_base = |base: u32| {
            resume_with(
                crate::dm::resume::ReEstState {
                    last_seen_re_est: base,
                    ..crate::dm::resume::ReEstState::first_establishment()
                },
                crate::dm::resume::Retention {
                    retained: None,
                    dedup: crate::dm::resume::DedupMemory::new(),
                    stopped: false,
                },
                floor,
            )
        };

        p.commit_resume(&l, &at_base(7)).expect("commits");
        let err = p
            .commit_resume(&l, &at_base(6))
            .expect_err("the base may not regress");
        assert!(
            matches!(
                err,
                DmPersistError::Resume(ResumeError::ReEstBaseWouldRegress {
                    stored: 7,
                    offered: 6
                })
            ),
            "wrong error: {err:?}"
        );
        // Both directions of the boundary, so a `<=` guard fails here.
        p.commit_resume(&l, &at_base(7))
            .expect("an unchanged base is legal");
        p.commit_resume(&l, &at_base(8))
            .expect("a slide forward is legal");
    }
}
