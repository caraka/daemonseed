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
//! the moment it must stop existing, that a cursor read from an unsealed file is
//! a hint needing corroboration. Putting that in `storage` would make a storage
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
use zeroize::Zeroizing;

use crate::dm::block_list::{BlockList, BlockListError};
use crate::dm::contact_cache::{ContactCacheError, ContactRecord};
use crate::dm::firstcontact::{FirstContactError, ROOT_LEN};
use crate::dm::outbox::{Outbox, OutboxError};
use crate::dm::provisional::{
    ChannelRestart, ProvisionalError, ProvisionalRecord, ReceiveCursor, RecordContext, Teardown,
    derive_seal_key, restart,
};
use crate::dm::ratchet::{Direction, Ratchet, RatchetError};
use crate::dm::resume::{ResumeError, ResumeRecord};
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
    /// **The stored number is deliberately not carried.** The cursor's file is
    /// unsealed by design, so anything able to write it chooses that number, and
    /// an error that handed it back would be a route by which a caller could
    /// corroborate the value against itself — the one thing
    /// [`ReceiveCursor::from_be_bytes`]'s `read_through` argument exists to
    /// prevent. The remedy needs no number: sweep from
    /// [`ReceiveCursor::START`].
    CursorNotCorroborated { read_through: u64 },
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
                "the profile's block-list record is missing; it is created at every store open, \
                 so its absence means it was removed",
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
            Self::AmbiguousCorrespondent { matches } => write!(
                f,
                "{matches} correspondences hold the same long-term identity key, \
                 so there is no single correspondence for it"
            ),
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
            Self::BlockListMissing
            | Self::OutboxDirectionMismatch { .. }
            | Self::CursorNotCorroborated { .. }
            | Self::AmbiguousCorrespondent { .. } => None,
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

    /// The store underneath, for enumeration and for tests.
    ///
    /// Read-only: [`DmStore`]'s mutating surface lives on the guard its own
    /// [`DmStore::critical_section`] hands out, so a shared borrow cannot write
    /// a record around this module.
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

    /// Decide what a channel does at startup, from what its store holds (#243).
    ///
    /// The call site [`crate::dm::provisional::restart`] was written for. The
    /// three outcomes it distinguishes are preserved end to end: a record that
    /// opens resumes the handshake, a record that is absent or unusable tears the
    /// channel down loudly, and a store that could not be *read* tears it down
    /// without declaring anything lost.
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
        match restart(borrowed, &self.provisional_key, ctx) {
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
    ) -> Result<Vec<u8>, DmPersistError> {
        let encoded = record.encode();
        self.store
            .critical_section(correspondence, |guard| -> Result<Vec<u8>, DmPersistError> {
                if let Some(bytes) = guard.read(RecordKind::Resume)? {
                    let stored = ResumeRecord::decode(&Zeroizing::new(bytes))?;
                    if record.attempt() < stored.attempt() {
                        return Err(ResumeError::AttemptWouldRollBack {
                            stored: stored.attempt().get(),
                            offered: record.attempt().get(),
                        }
                        .into());
                    }
                    if record.attempt() == stored.attempt()
                        && record.sealed_re_est() != stored.sealed_re_est()
                    {
                        return Err(ResumeError::AttemptResealed {
                            attempt: record.attempt().get(),
                        }
                        .into());
                    }
                    if !stored.send_floor().admits(record.send_floor()) {
                        return Err(ResumeError::FloorWouldRollBack {
                            stored: stored.send_floor(),
                            offered: record.send_floor(),
                        }
                        .into());
                    }
                }
                guard.replace(RecordKind::Resume, &encoded)?;
                Ok(record.sealed_re_est().to_vec())
            })
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
    /// cursor is unsealed by design, so anything able to write the file chooses
    /// that number; a cursor set past what was actually read makes a sweep start
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

    /// Move the persisted cursor to `page`, and say whether it moved.
    ///
    /// Read-modify-write under one lock, because
    /// [`ReceiveCursor::advance_to`]'s backwards check is against the cursor's
    /// *current* value — done as a separate read and write, a concurrent
    /// advance between the two would be overwritten by the older number.
    ///
    /// `Ok(false)` is the refusal [`ReceiveCursor::advance_to`] returns:
    /// backwards, past the last usable page, or past `read_through`. Nothing is
    /// written in that case, so a refused advance cannot leave a cursor the next
    /// read would decline to believe.
    ///
    /// A correspondence with no cursor yet starts from [`ReceiveCursor::START`],
    /// which is the same thing a receiver with no persisted cursor does.
    pub fn advance_cursor(
        &self,
        correspondence: &CorrespondenceLabel,
        page: u64,
        read_through: u64,
    ) -> Result<bool, DmPersistError> {
        self.store
            .critical_section(correspondence, |guard| -> Result<bool, DmPersistError> {
                let mut cursor = match guard.read(RecordKind::ReceiveCursor)? {
                    Some(raw) => decode_cursor(&raw, read_through)?,
                    None => ReceiveCursor::START,
                };
                if !cursor.advance_to(page, read_through) {
                    return Ok(false);
                }
                guard.replace(RecordKind::ReceiveCursor, &cursor.to_be_bytes())?;
                Ok(true)
            })
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
    /// **Known limitation: the keys are write-once through this module.**
    /// [`ContactRecord::observed_at`] is the record's only `&mut self` method
    /// and [`Self::update_contact`] ignores its seed once a record exists, so a
    /// correspondent who rotates `PK_pc` leaves a record this API cannot repair
    /// — every later frame fails authorship against the stale key and the only
    /// remedy is out-of-band. Replacing a stored record is deliberately absent
    /// rather than overlooked: an unconditional overwrite is the lost update
    /// this whole shape exists to refuse, so a rotation path has to say what
    /// authorises the new key, which is a protocol question and not a wiring
    /// one.
    pub fn read_contact(
        &self,
        correspondence: &CorrespondenceLabel,
    ) -> Result<Option<ContactRecord>, DmPersistError> {
        match self
            .store
            .read_unlocked(correspondence, RecordKind::ContactCache)?
        {
            // `Zeroizing`: this plaintext *is* the correspondence's `ss0` — this
            // kind carries no seal of its own, so the store hands back the
            // cleartext record — and the store zeroizes only its own copy.
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
    /// contact, where the keys and `ss0` are in hand. **It is a closure so it is
    /// built only when it is needed:** a seed carries `ss0` in the clear, and a
    /// sweep that constructs one per tick to discard it makes a live copy of the
    /// correspondence secret on every call that already has a stored record.
    /// When a record does exist the seed is not built at all and the stored
    /// record is what `f` sees — a caller cannot displace `first_seen_ms`, or an
    /// advanced `last_seen_ms`, with a stale in-memory copy.
    ///
    /// **A seeded record is written whatever `f` reports, and this is where the
    /// shape departs from [`Self::update_outbox`] rather than copying it.**
    /// There, `Unchanged` on an absent record correctly writes nothing:
    /// `Outbox::new(direction)` is empty and derivable from the argument, so
    /// dropping it loses no fact. A seed is the opposite — `pk_lt`, `pk_pc` and
    /// `ss0` have no other home — and the losing call is the ordinary one: seed
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
    /// are merely unreadable to *this* build — a live `ss0`, silently, on a path
    /// no caller asked to be destructive. Fail closed and let the caller decide.
    ///
    /// **`Unchanged` is a promise the caller can break, and in debug builds it
    /// is checked** — again as [`Self::update_outbox`] does, and by comparison
    /// rather than [`assert_eq!`], because this record's encoding *is* `ss0` and
    /// `assert_eq!` would render it into the panic message. The check runs only
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
                    // answer for this kind is cleartext `ss0`. Propagated, never
                    // recovered from by re-seeding — see this method's docs.
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
}

/// Read a cursor's at-rest bytes, bounded by `read_through`.
///
/// One body for both the locked and the unlocked path, so the bound cannot be
/// applied in one and forgotten in the other.
fn decode_cursor(raw: &[u8], read_through: u64) -> Result<ReceiveCursor, DmPersistError> {
    // The store checks every file against its kind's fixed size before returning
    // it, so a slice of another length cannot arrive here. Reported rather than
    // unwrapped anyway: the alternative is a panic in a public path if that check
    // ever moves.
    let bytes: [u8; RECEIVE_CURSOR_LEN] =
        raw.try_into().map_err(|_| DmStoreError::WrongFileLen {
            kind: RecordKind::ReceiveCursor,
            expected: RECEIVE_CURSOR_LEN,
            actual: raw.len(),
        })?;
    ReceiveCursor::from_be_bytes(bytes, read_through)
        .ok_or(DmPersistError::CursorNotCorroborated { read_through })
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
    /// The record opened. [`PendingHandshake::establish`] is what finishes it.
    HandshakeResumes(PendingHandshake<'a>),
    /// The channel is over, and [`Teardown`] is the statement the user gets.
    /// Its [`Teardown::event`] is the trust event that must be surfaced.
    TornDown(Teardown),
}

/// A provisional record that is on disk and open in memory, and the only path
/// this module offers from one to a [`Ratchet`].
///
/// **This type is how establishment and erasure are kept inseparable.** It owns
/// the record and exposes no way to take it out: the two borrowing accessors
/// hand back what a resuming handshake needs and nothing else, and the one
/// consuming method — [`Self::establish`] — builds the ratchet *and* deletes the
/// record. There is no ordering for a caller to get wrong and no second call to
/// forget, because there is no second call.
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
        let Self {
            persist,
            correspondence,
            record,
        } = self;
        let ratchet = record.into_ratchet()?;
        persist
            .store
            .critical_section(&correspondence, |guard| -> Result<(), DmPersistError> {
                guard.delete(RecordKind::Provisional)?;
                Ok(())
            })?;
        Ok(ratchet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::dm::block_list::BLOCK_LIST_MAX_ENTRIES;

    use zeroize::Zeroizing;

    use crate::crypto::suite::Registry;
    use crate::dm::contact_cache::{CONTACT_RECORD_LEN, CONTACT_RECORD_VERSION};
    use crate::dm::firstcontact::SS0_LEN;
    use crate::dm::keyrec;
    use crate::dm::outbox::{DeliveryState, OUTBOX_MAGIC, OutboxTarget, SealedFrame, Surfacing};
    use crate::dm::paging::MAX_PAGE;
    use crate::dm::provisional::{PROVISIONAL_RECORD_LEN, TeardownCause};
    use crate::dm::ratchet::EphemeralDecapKey;
    use crate::dm::resume::SendFloor;
    use crate::storage::dm_store::CORRESPONDENCE_LABEL_LEN;

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
            StoredChannelRestart::TornDown(t) => {
                assert_eq!(t.cause(), &TeardownCause::NoProvisionalRecord);
            }
            StoredChannelRestart::HandshakeResumes(_) => {
                panic!("an established channel resumed its own handshake")
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
            outbox.enqueue_sealed(1, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![7]))?;
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
            outbox.enqueue_sealed(1, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![9]))?;
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
            outbox.enqueue_sealed(1, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![1]))?;
            Ok(Mutation::Changed(()))
        })
        .expect("updates");
        let before = std::fs::read(record_path(&p, &l, "outbox.bin")).expect("reads");

        let err = p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(2, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![2]))?;
            // A duplicate: the module's own refusal, raised after a change was
            // already made to the in-memory copy.
            outbox.enqueue_sealed(1, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![3]))?;
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
    const TERMINAL_ENTRY_LEN: usize = (8 + 8 + 4 + 8 + 1 + 1 + 1) + 1;

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
                    match outbox.enqueue_sealed(seq, OutboxTarget::ChannelPage, later, frame) {
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
                        SealedFrame::new(vec![0x33; 8])
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
        assert!(p.advance_cursor(&l, 12, 20).expect("advances"));
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
        assert!(p.advance_cursor(&l, 40, 40).expect("advances"));

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
        assert!(p.advance_cursor(&l, 9, 9).expect("advances"));
        let before = std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads");

        // Backwards, and past what was read: both refusals.
        assert!(!p.advance_cursor(&l, 4, 9).expect("refuses"));
        assert!(!p.advance_cursor(&l, 50, 20).expect("refuses"));
        assert!(
            !p.advance_cursor(&l, MAX_PAGE + 1, u64::MAX)
                .expect("refuses")
        );

        assert_eq!(
            std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads"),
            before,
            "a refused advance wrote to the record"
        );
    }

    /// The cursor file is the one unsealed record, and it is exactly its eight
    /// bytes — the store's own contract, checked from this side because this is
    /// the module that supplies the payload.
    #[test]
    fn the_cursor_is_eight_unsealed_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(21);
        assert!(p.advance_cursor(&l, 258, 258).expect("advances"));

        let raw = std::fs::read(record_path(&p, &l, "cursor.bin")).expect("reads");
        assert_eq!(raw.len(), RECEIVE_CURSOR_LEN);
        assert_eq!(
            raw,
            258u64.to_be_bytes(),
            "the page number is not on disk verbatim"
        );
    }
    // ------------------------------------------------------------ the resume record (A9.2)

    fn resume_record(attempt: u32, floor: SendFloor) -> ResumeRecord {
        resume_record_sealed(attempt, floor, 0xA5)
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

    fn resume_record_sealed(attempt: u32, floor: SendFloor, seal: u8) -> ResumeRecord {
        ResumeRecord::new(
            Box::new([0x11u8; oxicrypt_ml_dsa::SK_LEN]),
            Box::new([0x22u8; oxicrypt_ml_dsa::PK_LEN]),
            crate::dm::resume::CommittedRoot::from_bytes(
                [0x33u8; crate::dm::ratchet::ROOT_KEY_LEN],
            ),
            crate::dm::resume::SealedReEst::seal(
                fresh(attempt),
                vec![seal; 256].into_boxed_slice(),
            )
            .expect("within MAX_FRAME_LEN"),
            floor,
            1_700_000_000_000,
            2,
        )
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
            emitted,
            record.sealed_re_est(),
            "the caller was handed something other than the persisted seal"
        );

        let stored = p
            .read_resume(&l)
            .expect("reads")
            .expect("a record was committed");
        assert_eq!(stored.attempt().get(), 1);
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
        assert_eq!(stored.attempt().get(), 1);
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

        assert_eq!(
            p.read_resume(&l)
                .expect("reads")
                .expect("there")
                .attempt()
                .get(),
            2
        );
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
        assert_eq!(stored.sealed_re_est(), &[0xA5u8; 256]);

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
        assert_eq!(
            p.read_resume(&l)
                .expect("reads")
                .expect("there")
                .attempt()
                .get(),
            5
        );
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
    fn contact_tagged(tag: u8, first_seen: i64, last_seen: i64) -> ContactRecord {
        let mut secret = ss0();
        secret[0] ^= tag;
        ContactRecord::new(
            pk(tag),
            pk(tag.wrapping_add(0x7F)),
            Zeroizing::new(secret),
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
        assert_eq!(stored.pk_pc(), pk(0x80).as_ref());

        // Likewise: distinct stamps, so a read that took one field twice fails.
        assert_ne!(
            FIRST_SEEN, LAST_SEEN,
            "the two timestamps are the same value"
        );
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), LAST_SEEN);

        assert_eq!(
            stored.address_root().expect("derives"),
            contact(FIRST_SEEN, LAST_SEEN)
                .address_root()
                .expect("derives"),
            "ss0 did not survive the store's seal"
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
                .expect("derives")
        };

        let p = persist(dir.path());
        let stored = p
            .read_contact(&l)
            .expect("reads")
            .expect("the record did not survive the process that wrote it");
        assert_eq!(stored.first_seen_ms(), FIRST_SEEN);
        assert_eq!(stored.last_seen_ms(), LAST_SEEN);
        assert_eq!(stored.pk_pc(), pk(0x80).as_ref());
        assert_eq!(
            stored.address_root().expect("derives"),
            root,
            "ss0 did not survive the restart"
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
        assert_eq!(stored.pk_pc(), pk(0x80).as_ref());
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
            .address_root()
            .expect("derives");

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
                    c.address_root().expect("derives"),
                    stored_root,
                    "the seed's ss0 displaced the stored one"
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
}
