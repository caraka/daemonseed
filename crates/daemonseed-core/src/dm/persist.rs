//! The wiring between the direct-messaging records and the disk (#281).
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
//! So: [`DmPersist::read_outbox`] and [`DmPersist::read_cursor`] are questions
//! and take no lock; [`DmPersist::update_outbox`] and
//! [`DmPersist::advance_cursor`] are read-modify-write and hold the lock across
//! the whole of it. There is deliberately **no** `save_outbox` taking an
//! [`Outbox`] the caller loaded earlier: that pair is exactly the lost-update the
//! store's API refuses to let anyone spell, re-offered one layer up.
//!
//! None of the calls here nests inside another, so
//! [`DmStoreError::Reentrant`](crate::storage::dm_store::DmStoreError::Reentrant)
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
use oxicrypt_ml_kem as ml_kem;
use zeroize::Zeroizing;

use crate::dm::firstcontact::{FirstContactError, ROOT_LEN};
use crate::dm::outbox::{Outbox, OutboxError};
use crate::dm::provisional::{
    ChannelRestart, ProvisionalError, ProvisionalRecord, ReceiveCursor, RecordContext, Teardown,
    derive_seal_key, restart,
};
use crate::dm::ratchet::{Direction, Ratchet, RatchetError};
use crate::dm::resume::{ResumeError, ResumeRecord};
use crate::storage::dm_store::{
    CorrespondenceLabel, DmStore, DmStoreError, RECEIVE_CURSOR_LEN, RecordKind,
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
}

impl std::fmt::Display for DmPersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "dm store: {e}"),
            Self::Record(e) => write!(f, "provisional record: {e}"),
            Self::Outbox(e) => write!(f, "outbox: {e}"),
            Self::Resume(e) => write!(f, "resume record: {e}"),
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
            Self::Ratchet(e) => Some(e),
            Self::OutboxDirectionMismatch { .. } | Self::CursorNotCorroborated { .. } => None,
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
    /// was and the caller may retry. A successful call always writes, even if
    /// `f` changed nothing — one redundant write against having to trust every
    /// caller to report whether it mutated.
    pub fn update_outbox<T>(
        &self,
        correspondence: &CorrespondenceLabel,
        direction: Direction,
        now_ms: i64,
        f: impl FnOnce(&mut Outbox) -> Result<T, DmPersistError>,
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
                let out = f(&mut outbox)?;
                guard.replace(RecordKind::Outbox, &outbox.encode())?;
                Ok(out)
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
    /// as [`DmStoreError::ErasureInterrupted`](crate::storage::dm_store::DmStoreError::ErasureInterrupted)
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

    use zeroize::Zeroizing;

    use crate::crypto::suite::Registry;
    use crate::dm::firstcontact::SS0_LEN;
    use crate::dm::keyrec;
    use crate::dm::outbox::{OUTBOX_MAGIC, OutboxTarget, SealedFrame, Surfacing};
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
        let _ = oxicrypt_module::initialize();
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
            Ok(())
        })
        .expect("updates");

        let loaded = p.read_outbox(&l, now).expect("reads").expect("present");
        assert_eq!(loaded.direction(), Direction::AToB);
        assert_eq!(loaded.len(), 1);
        let entry = loaded.entry(4).expect("the entry");
        assert_eq!(entry.composed_at_ms(), now);
        assert_eq!(entry.frame(), Some(&[0xABu8; 12][..]));
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
    /// against literals.
    #[test]
    fn a_hand_written_outbox_header_decodes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = persist(tmp.path());
        let l = label(12);

        let mut raw = Vec::new();
        raw.extend_from_slice(OUTBOX_MAGIC);
        raw.extend_from_slice(&Registry::default_write_suite().get().to_be_bytes());
        raw.push(1); // direction tag: BToA
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

        p.update_outbox(&l, Direction::AToB, now, |_| Ok(()))
            .expect("updates");
        let err = p
            .update_outbox(&l, Direction::BToA, now, |_| Ok(()))
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
            Ok(())
        })
        .expect("updates");
        let before = std::fs::read(record_path(&p, &l, "outbox.bin")).expect("reads");

        let err = p.update_outbox(&l, Direction::AToB, now, |outbox| {
            outbox.enqueue_sealed(2, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![2]))?;
            // A duplicate: the module's own refusal, raised after a change was
            // already made to the in-memory copy.
            outbox.enqueue_sealed(1, OutboxTarget::ChannelPage, now, SealedFrame::new(vec![3]))?;
            Ok(())
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
                Ok(())
            })
            .expect("updates");

            let swept = p
                .update_outbox(&l, Direction::AToB, later, |outbox| {
                    Ok(outbox.sweep_give_ups(later))
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
}
