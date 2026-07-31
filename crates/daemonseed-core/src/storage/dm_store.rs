//! The DM record store: the one place a direct-messaging record reaches the
//! disk, and the place the lock becomes impossible to forget (#286, Amendment
//! A9's build-obligation list, `docs/design/direct-messaging.md`).
//!
//! ## Why a store at all, when [`super::atomic_file`] already writes durably
//!
//! Three invariants have had no enforcement point anywhere in this tree, and
//! none of them is expressible in a free function that takes a path and some
//! bytes.
//!
//! **The lock must bracket a read-modify-write, both halves together.**
//! `rename(2)` serializes readers against writers, not writers against writers,
//! so two processes that both read a record, both decide, and both write,
//! silently lose one decision — the cardinal silent-send-loss the single-writer
//! discipline exists to prevent. Taking the lock inside
//! [`super::atomic_file::replace_atomically`] would serialize the write half and
//! leave that read-then-write window wide open, while *reading* as safe; its own
//! module docs say so and decline to take it. So the lock is taken here, and
//! every mutation lives on the guard it hands out:
//! [`DmStore::critical_section`] holds it for the whole closure, and
//! [`Locked::replace`] / [`Locked::delete`] exist only on the guard. There is no
//! way to spell a write that is not under the lock.
//!
//! A *plain single-record read* is the one thing that does not need the lock,
//! and [`DmStore::read_unlocked`] is it. The rename is atomic, so a reader of
//! one record sees either the whole old file or the whole new one and never a
//! mixture; a lock buys such a reader nothing. It buys the store something
//! important instead, which is why the two are separate calls rather than one
//! with a flag: taking the lock **creates** the correspondence directory, so a
//! caller that only wanted to ask whether a correspondence exists would bring it
//! into existence by asking (#253). The directory names are the one thing
//! visible at rest without any key, and they are meant to name the
//! correspondences that were *established* — not every label anyone ever probed.
//! So the read path creates nothing and the write path is honest about
//! establishing what it locks.
//!
//! **The filename is derived, never passed.** A record is named by its
//! [`RecordKind`] and the [`CorrespondenceLabel`] the guard was opened for. No
//! caller supplies a path, so writing one correspondence's state over another's,
//! or an outbox over a resume record, is not a mistake to be careful about — it
//! is unrepresentable. That is the reason `replace_atomically` is demoted to
//! `pub(crate)` in this commit: left public with a path argument, it is a second
//! door into the same directory with none of this on it.
//!
//! **Every record of a kind is the same size on disk.** A directory whose file
//! sizes vary leaks progress and pending volume — how far a handshake has got,
//! how many messages are owed. [`RecordKind::on_disk_len`] is a constant per
//! kind, [`Locked::replace`] pads every payload out to it and refuses anything
//! that will not fit, and [`Locked::read`] strips the padding again. The true
//! length travels in a length prefix *inside* the sealed plaintext (the
//! [`crate::dm::LEN_PREFIX`] convention, shared with the frame paddings) — put
//! outside it, the prefix would hand back the exact length the padding was
//! there to hide.
//!
//! ## What the store does and does not protect
//!
//! Every kind except [`RecordKind::ReceiveCursor`] is sealed with
//! [`seal_envelope`] before it reaches the disk, so the store holds opaque bytes
//! (ISC-A-C6). The AAD binds the record kind and the correspondence label, so a
//! blob lifted from one slot cannot be replayed into another — the key is
//! per-*profile*, exactly as [`crate::dm::provisional::derive_seal_key`]'s is,
//! and without a per-slot binding every file in a profile would be an
//! interchangeable ciphertext.
//!
//! **One key, random nonces, and no bound on the number of seals.**
//! [`derive_store_key`] produces a single AES-256-GCM key per profile, and
//! [`seal_envelope`] draws a fresh random 96-bit nonce for every record it
//! writes. That key covers every correspondence and every record kind for the
//! whole life of the profile, and nothing anywhere counts the seals. Random
//! 96-bit nonces collide on the birthday bound, so the standard guidance is to
//! keep one key under roughly 2^32 encryptions; past that, a repeated nonce
//! becomes likely, and a nonce repeat under GCM is not a graceful degradation —
//! it leaks the XOR of the two plaintexts and compromises the authentication
//! key. Every [`Locked::replace`] is one encryption, so the budget is spent by
//! record *writes*, not by bytes or by correspondences.
//!
//! At any realistic volume this is unreachable: 2^32 writes is billions of
//! record updates against a store whose records are per-correspondence
//! handshake and queue state. It is recorded here because **nothing warns as the
//! count grows** — there is no counter, no rotation, and no re-key, so if a
//! future caller ever writes in a loop the first symptom would be a silent loss
//! of the guarantee rather than an error. Rotation is deliberately not
//! implemented: it needs a key epoch in every record's AAD and a migration for
//! records already on disk, which is a record-format decision that belongs with
//! the format, not with this module.
//!
//! The cursor is **not** sealed, deliberately:
//! [`crate::dm::provisional::ReceiveCursor`] documents it as not secret, and its
//! `from_be_bytes` already refuses a value it cannot corroborate against the
//! caller's own knowledge. Sealing it here would suggest the number can be
//! trusted because it decrypted, which is the belief that type is built to
//! deny.
//!
//! Two things this store does **not** do, stated so no one reads them into it:
//!
//! - **It does not erase.** [`Locked::delete`] unlinks the name and makes the
//!   unlink durable. The blocks behind it are not overwritten, and on an SSD or
//!   a copy-on-write filesystem they could not usefully be — the same bound
//!   [`crate::dm::provisional`] records for `ss0`. What deletion buys is that
//!   the record is gone from the filesystem's view, not from the medium.
//! - **It does not make the directory's shape invariant.** Fixed sizes hold
//!   across clean runs. A process killed between a temp sibling's creation and
//!   its rename leaves that sibling behind, so the entry count still tracks how
//!   often the writer died mid-write until [`DmStore::open`]'s sweep runs.
//!   Enumeration ([`Locked::present`]) is immune either way, because it derives
//!   the names it looks for rather than reading what happens to be there.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_kdf::HkdfSha384;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::dm::provisional::PROVISIONAL_RECORD_LEN;
use crate::dm::{LEN_PREFIX, domain, push_lp, unpad};
use crate::storage::atomic_file::{
    AtomicReplaceError, Durability, FileLock, LockError, RealDurability, TMP_INFIX,
    replace_atomically,
};
use crate::storage::seeds::AEAD_KEY_LEN;

/// Bytes in a [`CorrespondenceLabel`].
pub const CORRESPONDENCE_LABEL_LEN: usize = 32;

/// The per-correspondence lock file's name.
///
/// It lives *inside* the correspondence directory rather than in a sibling
/// lock tree, so there is exactly one place on disk that names the set of
/// correspondences. A second directory keyed by the same labels would be a
/// second copy of that metadata, free to disagree and equally readable.
const LOCK_FILE_NAME: &str = ".lock";

/// Largest payload a [`RecordKind::Resume`] record may carry.
///
/// A9.2's field set is the sealed `RE-EST` frame bytes, `S_pc` and `PK_pc`, the
/// committed generation and attempt counters, the two handshake slots and the
/// dedup memory. A sealed frame alone is bounded by
/// [`crate::dm::frame::MAX_FRAME_LEN`] (32 KiB), so 64 KiB leaves the rest of
/// that set roughly as much room again.
///
/// **This number is a guess against a record format that is not built yet.** If
/// a resume record outgrows it, [`Locked::replace`] refuses the write with
/// [`DmStoreError::PayloadTooLong`] — loudly, at the moment of the write, with
/// both numbers in the message. It never truncates, and it never silently grows
/// the file: growing it is a deliberate edit here, and because the bucket is the
/// on-disk size, that edit changes the length of every existing record and
/// therefore needs a migration. Sizing it generously now is much cheaper than
/// resizing it later.
pub const RESUME_CAPACITY: usize = 65_536;

/// Largest payload a [`RecordKind::Outbox`] record may carry.
///
/// [`crate::dm::outbox::Outbox::encode`] is variable-length by nature: a header,
/// then one entry per message still owed, each carrying its sealed frame. At
/// [`crate::dm::frame::MAX_FRAME_LEN`] this holds seven worst-case frames and
/// far more typical ones.
///
/// **The trade is disk against the leak.** Every correspondence pays this in
/// full whether it owes one message or none, which is the price of the file
/// size not tracking the queue depth. The overflow behaviour is
/// [`RESUME_CAPACITY`]'s: refused at the write with
/// [`DmStoreError::PayloadTooLong`], never truncated. A sender that can queue
/// more than this owes the design a decision about what to do when the outbox
/// is full — a refusal to persist is not, on its own, an answer.
pub const OUTBOX_CAPACITY: usize = 262_144;

/// Bytes in a persisted [`crate::dm::provisional::ReceiveCursor`] — its
/// `to_be_bytes` form, verbatim.
pub const RECEIVE_CURSOR_LEN: usize = 8;

/// Which record. The other half of a record's identity is the
/// [`CorrespondenceLabel`] its [`Locked`] guard was opened for; together they
/// determine the path, so no caller ever names a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    /// A9's re-establishment resume record: the durable home of every piece of
    /// hard crypto state a reconnect needs.
    Resume,
    /// The initiator's provisional handshake record
    /// ([`crate::dm::provisional::ProvisionalRecord`]), already sealed under its
    /// own per-channel context before it gets here.
    Provisional,
    /// The persisted outbox ([`crate::dm::outbox::Outbox::encode`]) — what this
    /// side still owes the correspondent.
    Outbox,
    /// How far the receiver has read ([`crate::dm::provisional::ReceiveCursor`]).
    /// The one unsealed kind.
    ReceiveCursor,
}

impl RecordKind {
    /// Every kind, for enumeration. Hand-maintained, and held to the enum by
    /// `record_kind_all_is_complete`.
    pub const ALL: [RecordKind; 4] = [
        RecordKind::Resume,
        RecordKind::Provisional,
        RecordKind::Outbox,
        RecordKind::ReceiveCursor,
    ];

    /// The file name inside the correspondence directory.
    ///
    /// Fixed strings, and none of them contains [`TMP_INFIX`] — which is what
    /// makes name-derived enumeration immune to orphaned temp siblings without
    /// having to filter them out. `record_names_cannot_collide_with_a_temp_sibling`
    /// pins that.
    const fn file_name(self) -> &'static str {
        match self {
            RecordKind::Resume => "resume.bin",
            RecordKind::Provisional => "provisional.bin",
            RecordKind::Outbox => "outbox.bin",
            RecordKind::ReceiveCursor => "cursor.bin",
        }
    }

    /// The largest payload [`Locked::replace`] accepts for this kind.
    ///
    /// For [`RecordKind::ReceiveCursor`] this is also the *smallest*: see
    /// [`RecordKind::is_sealed`].
    pub const fn capacity(self) -> usize {
        match self {
            RecordKind::Resume => RESUME_CAPACITY,
            // The record is already one fixed size by construction, so the
            // store's bucket is exactly it — no slack, nothing to choose.
            RecordKind::Provisional => PROVISIONAL_RECORD_LEN,
            RecordKind::Outbox => OUTBOX_CAPACITY,
            RecordKind::ReceiveCursor => RECEIVE_CURSOR_LEN,
        }
    }

    /// The padded plaintext length: the length prefix plus [`Self::capacity`].
    ///
    /// The unsealed kind carries no prefix — there is nowhere secret to put one,
    /// and it has no padding to describe.
    pub const fn bucket_len(self) -> usize {
        if self.is_sealed() {
            LEN_PREFIX + self.capacity()
        } else {
            self.capacity()
        }
    }

    /// The exact size of this kind's file on disk, for every record of it.
    ///
    /// This — not [`Self::bucket_len`] — is the number the privacy argument
    /// rests on, and `every_record_file_is_exactly_its_kinds_on_disk_len` is
    /// what holds the code to it.
    pub const fn on_disk_len(self) -> usize {
        if self.is_sealed() {
            NONCE_LEN + self.bucket_len() + TAG_LEN
        } else {
            self.bucket_len()
        }
    }

    /// Whether this kind is sealed at rest. Everything but the cursor is.
    pub const fn is_sealed(self) -> bool {
        !matches!(self, RecordKind::ReceiveCursor)
    }

    /// The byte this kind contributes to the seal's AAD.
    ///
    /// Explicit values rather than the enum's discriminant, so reordering the
    /// variants — an edit with no other consequence — cannot silently move every
    /// existing record's AAD and make the whole store fail to open.
    /// `aad_tags_are_byte_pinned` is the tripwire.
    const fn aad_tag(self) -> u8 {
        match self {
            RecordKind::Resume => 1,
            RecordKind::Provisional => 2,
            RecordKind::Outbox => 3,
            // Assigned but never used: the cursor is not sealed, so it has no
            // AAD. It is here so the mapping stays total and a later decision to
            // seal it does not have to invent a value that might collide.
            RecordKind::ReceiveCursor => 4,
        }
    }
}

/// Which correspondence a record belongs to — an opaque 32-byte name supplied by
/// the caller.
///
/// **How this value is derived is NOT decided, and is deliberately not decided
/// here.** It is a privacy-relevant choice that belongs to the collection slice,
/// not to a storage module: it must not be `chan_id`, which
/// [`crate::dm::provisional`] states must never be serialized anywhere, and this
/// module declines to derive it from the key-record address on its own
/// initiative either, because that address is world-derivable and would make the
/// directory listing a list of who the user talks to. Until that decision is
/// made, this type is a name the caller chooses and the store only ever compares
/// and hex-encodes; nothing in the store depends on any property of it beyond
/// distinctness.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrespondenceLabel([u8; CORRESPONDENCE_LABEL_LEN]);

impl CorrespondenceLabel {
    /// A label over the caller's bytes.
    pub const fn from_bytes(bytes: [u8; CORRESPONDENCE_LABEL_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes back.
    pub const fn as_bytes(&self) -> &[u8; CORRESPONDENCE_LABEL_LEN] {
        &self.0
    }

    /// The directory name: lowercase hex, so the label survives a round trip
    /// through any filesystem's name rules unchanged.
    fn dir_name(&self) -> String {
        hex::encode(self.0)
    }
}

/// Redacted. The label is a stable per-correspondence identifier, so a `Debug`
/// that rendered it would put "which conversation" into every log line and error
/// report that happens to format one. It is not a secret from anyone holding the
/// disk — it is the directory name — but that is not a reason to also emit it
/// where the disk is not.
impl core::fmt::Debug for CorrespondenceLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CorrespondenceLabel(..)")
    }
}

/// Derive the store's at-rest seal key from the profile's at-rest key material.
///
/// [`crate::dm::provisional::derive_seal_key`]'s construction under this module's
/// own label pair. Its own label rather than the provisional record's: that key
/// protects one record kind's contents, this one protects every record's *slot*,
/// and deriving both from one label would let a provisional record and a store
/// blob open as each other wherever the inputs coincided.
///
/// Per-profile, like every at-rest key here. The per-record separation is the
/// AAD's job ([`seal_aad`]), not the key's.
fn derive_store_key(at_rest_key: &[u8; AEAD_KEY_LEN]) -> Result<Aes256Key, DmStoreError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_STORE_SALT), at_rest_key)
        .map_err(|_| DmStoreError::Kdf)?;
    // Cleared on both paths: `[u8; N]` is `Copy` with no `Drop`, so the copy that
    // moved into `Aes256Key` is the only one anything protects and the original
    // would otherwise stay live in this frame (#135).
    let mut key = [0u8; AEAD_KEY_LEN];
    let outcome = hkdf
        .expand(domain::DM_STORE_SEAL, &mut key)
        .map_err(|_| DmStoreError::Kdf)
        .and_then(|()| Aes256Key::new(&key).map_err(|_| DmStoreError::Module));
    key.zeroize();
    outcome
}

/// The AAD a record's seal binds: the domain label, then the correspondence and
/// the kind, length-prefixed.
///
/// [`crate::dm::provisional`]'s `seal_aad` construction — prefix, then
/// length-prefixed fields — so the two cannot be parsed into each other and
/// neither can be extended by an implementation that guesses.
///
/// Both fields are load-bearing and neither implies the other. Without the
/// label, one correspondence's record opens in another's directory and the
/// channel resumes as the wrong correspondent. Without the kind, two records of
/// the same size in one correspondence are interchangeable ciphertexts.
fn seal_aad(label: &CorrespondenceLabel, kind: RecordKind) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain::DM_STORE_AAD.len() + CORRESPONDENCE_LABEL_LEN + 32);
    aad.extend_from_slice(domain::DM_STORE_AAD);
    push_lp(&mut aad, label.as_bytes());
    push_lp(&mut aad, &[kind.aad_tag()]);
    aad
}

/// Pad `payload` out to `kind`'s bucket: `len(4, LE) ‖ payload ‖ CSPRNG filler`.
///
/// [`crate::dm::pad_to_bucket`]'s layout and prefix convention, with two
/// differences that both matter. The bucket is fixed per kind rather than the
/// smallest of a ladder — a ladder would make the file size a coarse report of
/// the payload size, which is the leak this exists to close. And the filler is
/// drawn from the CSPRNG rather than zeroed.
///
/// **What the CSPRNG filler is and is not for.** It is not what makes the record
/// indistinguishable on disk: the plaintext goes under AES-256-GCM, so zero
/// filler and random filler produce ciphertext no one without the key can tell
/// apart, and it is the *fixed bucket* that hides the length. What it buys is
/// narrower — the padded plaintext exists in memory before the seal and in a
/// core dump or a swapped page after it, and a zero-filled buffer announces the
/// payload's true length there without needing the key at all.
fn pad_with_filler(kind: RecordKind, payload: &[u8]) -> Result<Vec<u8>, DmStoreError> {
    debug_assert!(kind.is_sealed(), "an unsealed kind has no padding");
    let capacity = kind.capacity();
    if payload.len() > capacity {
        return Err(DmStoreError::PayloadTooLong {
            kind,
            capacity,
            actual: payload.len(),
        });
    }

    let mut buf = vec![0u8; kind.bucket_len()];
    let end = LEN_PREFIX + payload.len();
    buf[..LEN_PREFIX].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    buf[LEN_PREFIX..end].copy_from_slice(payload);
    if let Err(e) = getrandom::fill(&mut buf[end..]) {
        buf.zeroize();
        return Err(DmStoreError::EntropySource(e));
    }
    Ok(buf)
}

/// The root of a profile's DM records: one directory per correspondence, one
/// fixed-size file per record kind inside it.
///
/// Holds the derived seal key, so no call site ever passes one and no call site
/// can pass the wrong one.
pub struct DmStore {
    root: PathBuf,
    key: Aes256Key,
    /// Which thread holds a [`Locked`] guard for which label, right now.
    ///
    /// `flock` attaches to the open file description, not to the thread, so a
    /// second [`FileLock::acquire`] on a lock this same thread already holds
    /// opens a second description and blocks on it forever. This set turns that
    /// hang into [`DmStoreError::Reentrant`]. See [`DmStore::critical_section`].
    ///
    /// **Keyed by thread, not merely by label, and that distinction is the
    /// whole correctness argument.** Two *different* threads contending for one
    /// label is not a deadlock and must not be reported as one: each opens its
    /// own description, the second blocks on the `flock`, the first finishes and
    /// releases, and the second proceeds — the exclusion working exactly as
    /// designed. Only the thread that is itself holding the lock can wait on
    /// itself forever, because only it is the thread that would have to return
    /// in order to release. Keying on the label alone would refuse the
    /// legitimate case, which is the case a shared `DmStore` produces.
    held: Mutex<HeldSet>,
}

impl core::fmt::Debug for DmStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The key is deliberately absent, and the root is the only field worth
        // printing anyway.
        f.debug_struct("DmStore").field("root", &self.root).finish()
    }
}

impl DmStore {
    /// Open (creating if needed) the store rooted at `root`, and sweep any
    /// orphaned temp siblings a previously killed process left behind.
    ///
    /// `at_rest_key` is the profile's key — the same material that protects the
    /// mnemonic and the contact cache — so the records are protected by the
    /// passphrase the profile already has, and the store never holds a secret
    /// with a lifetime of its own.
    ///
    /// **The sweep is not under any lock, and does not need to be.** It removes
    /// only names containing [`TMP_INFIX`], and a live writer's sibling has a
    /// CSPRNG suffix no other process can predict; removing one under a
    /// concurrent writer would cost that writer its in-flight write, reported as
    /// [`AtomicReplaceError::NotLanded`] or `Indeterminate`, never a committed
    /// record. Two stores opening at once can only race to remove the same dead
    /// file, and a `NotFound` on removal is not an error.
    pub fn open(
        root: impl Into<PathBuf>,
        at_rest_key: &[u8; AEAD_KEY_LEN],
    ) -> Result<Self, DmStoreError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| DmStoreError::io(&root, e))?;
        let key = derive_store_key(at_rest_key)?;
        let store = Self {
            root,
            key,
            held: Mutex::new(HeldSet::new()),
        };
        store.sweep_orphans()?;
        Ok(store)
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of `kind`'s record for `correspondence`. Derived, never
    /// supplied — the one place the two halves of a record's identity become a
    /// path, so [`Locked`] and the lock-free read cannot drift apart.
    fn record_path(&self, correspondence: &CorrespondenceLabel, kind: RecordKind) -> PathBuf {
        self.root
            .join(correspondence.dir_name())
            .join(kind.file_name())
    }

    /// Read one record **without taking the lock, and without creating
    /// anything** — the probe.
    ///
    /// `Ok(None)` covers both "this correspondence has no such record" and "this
    /// correspondence does not exist here at all", and neither case leaves a
    /// directory, a lock file or anything else behind. That is the whole point:
    /// [`DmStore::critical_section`] *establishes* the correspondence on disk
    /// just by being entered, so asking a question through it would answer
    /// "does this exist?" by making it exist (#253). The set of directory names
    /// under the root is the one thing an adversary holding the disk can read
    /// without any key, and it is supposed to name established correspondences
    /// rather than every label that was ever looked up.
    ///
    /// **Why no lock is needed.** [`super::atomic_file::replace_atomically`]
    /// commits with `rename(2)`, which is atomic: a concurrent writer swaps one
    /// whole file for another, so this read returns either the complete old
    /// record or the complete new one. There is no interleaving to exclude, and
    /// a torn or half-written record is not among the outcomes.
    ///
    /// **What it does not give you.** It is not a read-modify-write, and it is
    /// not a snapshot. Two calls in a row can straddle a writer and disagree,
    /// and any decision made from what this returns can be stale by the time it
    /// is acted on. A caller that reads a record, decides something from it, and
    /// writes the result **must** do all three inside one
    /// [`DmStore::critical_section`] — doing it with this call and a separate
    /// write is precisely the silent-send-loss the lock exists to prevent.
    pub fn read_unlocked(
        &self,
        correspondence: &CorrespondenceLabel,
        kind: RecordKind,
    ) -> Result<Option<Vec<u8>>, DmStoreError> {
        self.read_record(
            &self.record_path(correspondence, kind),
            correspondence,
            kind,
        )
    }

    /// Which record kinds exist for `correspondence`, without taking the lock
    /// and without creating anything.
    ///
    /// The enumeration counterpart of [`DmStore::read_unlocked`], and it exists
    /// for the same reason: asking what a correspondence holds is a *question*,
    /// and a question must not answer itself into existence. With enumeration
    /// reachable only through [`Locked::present`], a caller that merely wanted
    /// to look would have to establish the correspondence first — the same
    /// defect as the probe path, one level down.
    ///
    /// Carries [`Locked::present`]'s guarantee and its caveat both: the names
    /// are derived rather than listed, so nothing stray in the directory can
    /// appear as a record; and the answer is not a snapshot, so a writer can
    /// add or remove a record between two calls.
    pub fn present_unlocked(
        &self,
        correspondence: &CorrespondenceLabel,
    ) -> Result<Vec<RecordKind>, DmStoreError> {
        let mut present = Vec::new();
        for kind in RecordKind::ALL {
            let path = self.record_path(correspondence, kind);
            match std::fs::metadata(&path) {
                Ok(_) => present.push(kind),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(DmStoreError::io(&path, e)),
            }
        }
        Ok(present)
    }

    /// The read both paths share: [`Locked::read`] under the lock, and
    /// [`DmStore::read_unlocked`] without it. See [`Locked::read`] for the error
    /// semantics.
    fn read_record(
        &self,
        path: &Path,
        label: &CorrespondenceLabel,
        kind: RecordKind,
    ) -> Result<Option<Vec<u8>>, DmStoreError> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            // Covers a missing record, a missing correspondence directory and a
            // missing root alike, and creates none of them on the way past.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(DmStoreError::io(path, e)),
        };

        if raw.len() != kind.on_disk_len() {
            return Err(DmStoreError::WrongFileLen {
                kind,
                expected: kind.on_disk_len(),
                actual: raw.len(),
            });
        }
        if !kind.is_sealed() {
            return Ok(Some(raw));
        }

        let aad = seal_aad(label, kind);
        let mut plain = open_envelope(&self.key, &aad, &raw)
            .map_err(|e| DmStoreError::from_envelope(kind, e))?;
        // `unpad` bounds-checks the declared length against the buffer rather
        // than slicing past it, so a corrupt prefix is a refusal and never a
        // panic. It can only be reached at all by something holding the key.
        let payload = match unpad(&plain) {
            Some(payload) => payload.to_vec(),
            None => {
                let declared = declared_len(&plain);
                plain.zeroize();
                return Err(DmStoreError::CorruptPayloadLen {
                    kind,
                    declared,
                    capacity: kind.capacity(),
                });
            }
        };
        plain.zeroize();
        Ok(Some(payload))
    }

    /// Remove every orphaned temp sibling under the root, returning how many
    /// went (#286).
    ///
    /// [`super::atomic_file`] removes its sibling on every path that *returns* an
    /// error, but a process that does not live to return one — SIGKILL, OOM kill,
    /// power cut — leaves it forever, and its own docs name sweeping them as an
    /// obligation on the store rather than a service it provides. Until they are
    /// swept the directory's entry count grows with the number of abnormal
    /// terminations, which is a coarse signal the fixed-size layout is otherwise
    /// arranged to deny.
    fn sweep_orphans(&self) -> Result<usize, DmStoreError> {
        let mut removed = 0usize;
        let entries = std::fs::read_dir(&self.root).map_err(|e| DmStoreError::io(&self.root, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| DmStoreError::io(&self.root, e))?;
            // Only correspondence directories are swept. `replace_atomically`
            // places a sibling next to its target, and every target this store
            // names is inside one, so a temp file cannot land at the root.
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let dir = entry.path();
            let inner = std::fs::read_dir(&dir).map_err(|e| DmStoreError::io(&dir, e))?;
            for candidate in inner {
                let candidate = candidate.map_err(|e| DmStoreError::io(&dir, e))?;
                if !is_temp_sibling(&candidate.file_name()) {
                    continue;
                }
                match std::fs::remove_file(candidate.path()) {
                    Ok(()) => removed += 1,
                    // Another store's sweep won the race; the file is gone
                    // either way, which is all this cares about.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(DmStoreError::io(&candidate.path(), e)),
                }
            }
        }
        Ok(removed)
    }

    /// Run `f` holding this correspondence's exclusive lock for the whole of it.
    ///
    /// The closure is the point. The lock's lifetime brackets everything the
    /// closure does, so a read, a decision and the write that follows from it are
    /// one critical section against every other process — which a
    /// lock-inside-the-write API cannot express, and which is exactly where the
    /// silent-send-loss lives.
    ///
    /// **Entering this establishes the correspondence on disk.** Acquiring the
    /// lock creates the correspondence directory and the lock file inside it,
    /// before `f` runs and whether or not `f` ever writes a record — and nothing
    /// removes an empty correspondence directory afterwards. So this is for
    /// writers and for read-modify-write, and asking a *question* about a
    /// correspondence belongs in [`DmStore::read_unlocked`], which creates
    /// nothing. Probing through here would make the directory listing name every
    /// label ever looked at rather than every correspondence established (#253).
    ///
    /// **The error plumbing.** `f` returns the caller's own error type, and the
    /// store's own failures convert into it through `E: From<DmStoreError>`. That
    /// keeps the return a plain `Result<T, E>` rather than a nested one, so `?`
    /// works normally inside the closure and at the call site. A caller with no
    /// error type of its own passes `E = DmStoreError` and relies on the
    /// reflexive `From` in core; a caller with one writes the `From` impl once.
    ///
    /// **Reentering it on the same thread for the same correspondence is an
    /// error, not a hang.** `flock` attaches to the open file description rather
    /// than to the thread, so a nested call for a label this thread already
    /// holds — directly, or through a helper several frames down — would open a
    /// second description and block forever on a lock it is itself holding, with
    /// the outer closure unable to return and the inner unable to proceed. This
    /// returns [`DmStoreError::Reentrant`] instead.
    ///
    /// The check is scoped to the calling **thread**, and nothing wider. Another
    /// thread of this process, and another process entirely, both still block on
    /// the `flock` until this section ends — that is the exclusion working as
    /// intended, and neither can deadlock on it, because the holder is not the
    /// one waiting.
    ///
    /// Blocks until the lock is available. Both the `flock` and this thread's
    /// claim on the label are released when the guard drops, including on an
    /// unwind, so a panicking closure cannot strand either.
    pub fn critical_section<T, E>(
        &self,
        correspondence: &CorrespondenceLabel,
        f: impl FnOnce(&mut Locked<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<DmStoreError>,
    {
        // Claimed BEFORE the `flock` is attempted, which is the whole mechanism:
        // once the blocking acquire has begun there is no thread left to notice
        // that it will never finish.
        let claim = self.claim(correspondence).map_err(E::from)?;

        let dir = self.root.join(correspondence.dir_name());
        let lock_path = dir.join(LOCK_FILE_NAME);
        // `FileLock::acquire` creates the lock file's parent, so this is also
        // what brings a new correspondence's directory into existence — under
        // the lock, before anything reads. A failure here drops `claim`, so a
        // lock that could not be taken does not leave the label marked as held.
        let lock = FileLock::acquire(&lock_path).map_err(|e| E::from(DmStoreError::Lock(e)))?;
        let mut locked = Locked {
            store: self,
            label: *correspondence,
            dir,
            _lock: lock,
            _claim: claim,
        };
        f(&mut locked)
    }

    /// Mark `correspondence` as held by the calling thread, or refuse if that
    /// thread already holds it.
    ///
    /// The returned guard releases the claim on drop, including on an unwind —
    /// a panicking closure that left the entry behind would convert a panic into
    /// a permanent lockout of that correspondence for the life of the thread.
    fn claim(
        &self,
        correspondence: &CorrespondenceLabel,
    ) -> Result<ReentryClaim<'_>, DmStoreError> {
        let key = (std::thread::current().id(), *correspondence);
        let mut held = lock_held_set(&self.held);
        if !held.insert(key) {
            return Err(DmStoreError::Reentrant);
        }
        drop(held);
        Ok(ReentryClaim {
            held: &self.held,
            key,
        })
    }
}

/// Take the held-set's mutex, recovering from poisoning.
///
/// The mutex is only ever held for a single set insert or remove, never across
/// user code, so a panic while holding it is not a reachable state — but
/// `unwrap`ping here would turn even an unreachable poisoning into a store that
/// can never be locked again, including inside [`ReentryClaim`]'s `Drop` where a
/// panic would abort. The set's contents are still exactly correct after a
/// poisoning, because nothing can leave it half-updated.
type HeldSet = HashSet<(std::thread::ThreadId, CorrespondenceLabel)>;

fn lock_held_set(held: &Mutex<HeldSet>) -> std::sync::MutexGuard<'_, HeldSet> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

/// One thread's claim on one correspondence label, released on drop.
struct ReentryClaim<'a> {
    held: &'a Mutex<HeldSet>,
    key: (std::thread::ThreadId, CorrespondenceLabel),
}

impl Drop for ReentryClaim<'_> {
    fn drop(&mut self) {
        lock_held_set(self.held).remove(&self.key);
    }
}

/// One correspondence's records, with its lock held.
///
/// Every record operation lives here rather than on [`DmStore`], so holding one
/// of these is the proof that the lock is held — there is no read, write or
/// delete reachable without it.
pub struct Locked<'a> {
    store: &'a DmStore,
    label: CorrespondenceLabel,
    dir: PathBuf,
    /// Dropped with the rest of the guard, releasing the `flock`.
    ///
    /// Declared before [`Self::_claim`] because fields drop in declaration
    /// order: the cross-process lock must be gone before this process is allowed
    /// to claim the label again, or a re-entry could be admitted while the
    /// `flock` this guard took is still held.
    _lock: FileLock,
    /// Dropped after `_lock`, releasing this thread's claim on the label.
    _claim: ReentryClaim<'a>,
}

impl core::fmt::Debug for Locked<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Locked").field("dir", &self.dir).finish()
    }
}

impl Locked<'_> {
    /// This correspondence's label.
    pub fn label(&self) -> &CorrespondenceLabel {
        &self.label
    }

    /// The path of `kind`'s record. Derived, never supplied.
    fn path(&self, kind: RecordKind) -> PathBuf {
        self.store.record_path(&self.label, kind)
    }

    /// Read `kind`'s record, or `Ok(None)` if it does not exist.
    ///
    /// The same read as [`DmStore::read_unlocked`], with the lock already held —
    /// which matters only when the result is about to be *written back*. Reading
    /// here is not safer than reading there; it is safer to *decide* here,
    /// because the write that follows is inside the same critical section.
    ///
    /// **Absence is not an error.** A correspondence with no outbox yet and a
    /// correspondence whose outbox could not be read are entirely different
    /// situations, and collapsing them would let a transient I/O failure read as
    /// "nothing owed" — a silent send loss arriving through the read path
    /// instead of the write path.
    ///
    /// A file of the wrong size is [`DmStoreError::WrongFileLen`] rather than the
    /// uniform authentication failure, so a truncation is diagnosable; a file of
    /// the right size that does not authenticate is
    /// [`DmStoreError::NotAuthentic`], which a wrong key, a wrong slot, a wrong
    /// correspondence, corruption and tampering all produce indistinguishably
    /// (ISC-A-C18).
    pub fn read(&self, kind: RecordKind) -> Result<Option<Vec<u8>>, DmStoreError> {
        self.store.read_record(&self.path(kind), &self.label, kind)
    }

    /// Replace `kind`'s record with `bytes`, padded to the kind's fixed size and
    /// (except for the cursor) sealed.
    ///
    /// Refuses a payload larger than [`RecordKind::capacity`] with
    /// [`DmStoreError::PayloadTooLong`] rather than truncating: a truncated
    /// record is a record that opens, parses to something shorter than it was,
    /// and is wrong in a way nothing downstream can detect.
    ///
    /// [`RecordKind::ReceiveCursor`] is unsealed and therefore carries no length
    /// prefix, so its payload must be **exactly** [`RECEIVE_CURSOR_LEN`] — there
    /// is nowhere to record that a shorter one was padded.
    ///
    /// On error the destination is in the state
    /// [`DmStoreError::Write`]'s inner [`AtomicReplaceError`] names — untouched,
    /// unknown, or already holding the new bytes but not durably. That
    /// distinction is preserved rather than flattened precisely because a
    /// commit-then-emit caller has to act on it.
    pub fn replace(&mut self, kind: RecordKind, bytes: &[u8]) -> Result<(), DmStoreError> {
        let sealed = if kind.is_sealed() {
            let mut plain = pad_with_filler(kind, bytes)?;
            let aad = seal_aad(&self.label, kind);
            let outcome = seal_envelope(&self.store.key, &aad, &plain)
                .map_err(|e| DmStoreError::from_envelope(kind, e));
            plain.zeroize();
            outcome?
        } else {
            if bytes.len() != kind.capacity() {
                return Err(DmStoreError::UnsealedPayloadNotExact {
                    kind,
                    expected: kind.capacity(),
                    actual: bytes.len(),
                });
            }
            bytes.to_vec()
        };

        debug_assert_eq!(
            sealed.len(),
            kind.on_disk_len(),
            "every record of a kind is one size on disk"
        );
        replace_atomically(&self.path(kind), &sealed)
            .map_err(|source| DmStoreError::Write { kind, source })
    }

    /// Delete `kind`'s record, and make the deletion durable.
    ///
    /// Deleting a record that is not there is `Ok(())`: the postcondition is
    /// "this record does not exist", and it already holds.
    ///
    /// **What "durable" means here, exactly.** The name is unlinked and the
    /// parent directory is fsynced, so the removal survives a power cut rather
    /// than reverting to a directory entry still naming the record. It does
    /// **not** overwrite the blocks the record occupied, and on an SSD's FTL or a
    /// copy-on-write filesystem it could not usefully — the bound
    /// [`crate::dm::provisional`] already records for `ss0`. An adversary with
    /// the raw flash is outside what this can deliver, and nothing here should be
    /// read as claiming otherwise.
    pub fn delete(&mut self, kind: RecordKind) -> Result<(), DmStoreError> {
        let path = self.path(kind);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(DmStoreError::io(&path, e)),
        }
        RealDurability
            .sync_dir(&self.dir)
            .map_err(|e| DmStoreError::io(&self.dir, e))
    }

    /// Which record kinds exist for this correspondence.
    ///
    /// **Derived, not listed.** This asks after each of [`RecordKind::ALL`]'s
    /// derived names in turn rather than reading the directory, so an orphaned
    /// temp sibling — or anything else that happens to be in there — cannot
    /// appear as a record, whether or not [`DmStore::open`]'s sweep has run.
    ///
    /// The same enumeration as [`DmStore::present_unlocked`], with the lock
    /// already held. One body, so the two cannot drift into disagreeing about
    /// what counts as a record.
    pub fn present(&self) -> Result<Vec<RecordKind>, DmStoreError> {
        self.store.present_unlocked(&self.label)
    }
}

/// Whether `name` is a temp sibling left by [`super::atomic_file`].
///
/// The comparison is over the lossy form, which is safe in both directions here:
/// [`TMP_INFIX`] is pure ASCII, so a valid occurrence survives the conversion
/// intact (no false negative) and the replacement character cannot manufacture
/// one (no false positive).
fn is_temp_sibling(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().contains(TMP_INFIX)
}

/// The length a padded plaintext declares, for reporting a corrupt one.
///
/// Only ever called on a buffer already known to be a full bucket, so the prefix
/// is present; `0` is a defensive floor rather than a reachable answer.
fn declared_len(plain: &[u8]) -> usize {
    plain
        .get(..LEN_PREFIX)
        .and_then(|p| <[u8; LEN_PREFIX]>::try_from(p).ok())
        .map_or(0, |p| u32::from_le_bytes(p) as usize)
}

/// Why a store operation could not be completed.
#[derive(Debug)]
pub enum DmStoreError {
    /// Filesystem I/O failed, at the path named.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The correspondence's lock could not be acquired. Nothing was read or
    /// written.
    Lock(LockError),

    /// A critical section was requested for a correspondence the calling thread
    /// already holds one for. Nothing was read or written.
    ///
    /// **This is a bug in the caller, reported instead of a deadlock.** `flock`
    /// is per open file description, so the nested acquire would have blocked
    /// forever on a lock this very thread is holding. The fix is always to
    /// restructure so the correspondence is entered once and the inner work
    /// takes the existing [`Locked`] guard, never to retry — a retry cannot
    /// succeed, since the thread that would have to release is the one retrying.
    ///
    /// The label is deliberately absent: it is the same identifier
    /// [`CorrespondenceLabel`]'s `Debug` declines to render, and an error that is
    /// by construction about a label the caller already has in hand does not
    /// need to put it in a log line.
    Reentrant,

    /// A durable replacement failed.
    ///
    /// **The inner error is the useful half and is deliberately not flattened.**
    /// [`AtomicReplaceError::NotLanded`] means the destination is untouched and
    /// a retry is safe; `Indeterminate` means its state is unknown and must be
    /// re-read before anything is emitted; `LandedNotDurable` means the new
    /// bytes are readable *now* but can revert on power loss. A caller doing
    /// commit-then-emit acts differently on each, so collapsing them into one
    /// "the write failed" would be reporting a write that landed as one that did
    /// not.
    Write {
        kind: RecordKind,
        source: AtomicReplaceError,
    },

    /// HKDF failed deriving the store key — an unrecoverable crypto-module
    /// condition.
    Kdf,

    /// An AES key-init or a non-authentication AEAD mode error at the module
    /// boundary. Most plausibly the crypto module not yet initialised, which is
    /// retryable — which is why it is kept out of [`Self::NotAuthentic`], where
    /// it would read as tampering.
    Module,

    /// The OS entropy source failed drawing the padding filler or a nonce.
    /// Distinct from an I/O error because in a crypto application an unavailable
    /// CSPRNG is an alarm in its own right.
    EntropySource(getrandom::Error),

    /// The record did not authenticate: a wrong key, a record from another
    /// correspondence, a record of another kind, corruption, or tampering —
    /// deliberately indistinguishable (ISC-A-C18).
    NotAuthentic { kind: RecordKind },

    /// The file is not this kind's fixed size. Checked before the open so a
    /// truncation is diagnosable rather than arriving as the uniform
    /// authentication failure.
    WrongFileLen {
        kind: RecordKind,
        expected: usize,
        actual: usize,
    },

    /// The payload is larger than the kind's bucket. Refused rather than
    /// truncated.
    PayloadTooLong {
        kind: RecordKind,
        capacity: usize,
        actual: usize,
    },

    /// An unsealed kind was handed a payload that is not exactly its size. It
    /// carries no length prefix, so a short payload could not be recovered.
    UnsealedPayloadNotExact {
        kind: RecordKind,
        expected: usize,
        actual: usize,
    },

    /// The record opened, and the length prefix inside it does not fit the
    /// bucket. Only reachable by something holding the key, so this is
    /// corruption inside an authenticated plaintext rather than an attack.
    CorruptPayloadLen {
        kind: RecordKind,
        declared: usize,
        capacity: usize,
    },
}

impl DmStoreError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        DmStoreError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    /// Map an envelope failure, preserving the authentication/module split.
    ///
    /// [`crate::dm::provisional`]'s mapping, for the same reason: routing a
    /// retryable module state to the authentication variant would report an
    /// intact record as tampered.
    fn from_envelope(kind: RecordKind, e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(e) => DmStoreError::EntropySource(e),
            EnvelopeError::Decrypt(ModeError::TagMismatch) | EnvelopeError::TooShort => {
                DmStoreError::NotAuthentic { kind }
            }
            EnvelopeError::Decrypt(_) | EnvelopeError::Encrypt(_) => DmStoreError::Module,
        }
    }
}

impl core::fmt::Display for DmStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DmStoreError::Io { path, source } => {
                write!(f, "dm store I/O failed at {}: {source}", path.display())
            }
            DmStoreError::Lock(e) => write!(f, "dm store lock: {e}"),
            DmStoreError::Reentrant => write!(
                f,
                "this thread already holds a critical section for that correspondence"
            ),
            DmStoreError::Write { kind, source } => {
                write!(f, "writing the {kind:?} record: {source}")
            }
            DmStoreError::Kdf => write!(f, "dm store key derivation failed"),
            DmStoreError::Module => write!(f, "crypto module unavailable"),
            DmStoreError::EntropySource(e) => write!(f, "the entropy source failed: {e}"),
            DmStoreError::NotAuthentic { kind } => {
                write!(f, "the {kind:?} record did not open")
            }
            DmStoreError::WrongFileLen {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "a {kind:?} record is {expected} bytes on disk, this one is {actual}"
            ),
            DmStoreError::PayloadTooLong {
                kind,
                capacity,
                actual,
            } => write!(
                f,
                "a {kind:?} payload holds at most {capacity} bytes, this one is {actual}"
            ),
            DmStoreError::UnsealedPayloadNotExact {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "an unsealed {kind:?} payload is exactly {expected} bytes, this one is {actual}"
            ),
            DmStoreError::CorruptPayloadLen {
                kind,
                declared,
                capacity,
            } => write!(
                f,
                "the {kind:?} record declares a {declared}-byte payload, past its {capacity}-byte bucket"
            ),
        }
    }
}

impl core::error::Error for DmStoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            DmStoreError::Io { source, .. } => Some(source),
            DmStoreError::Lock(e) => Some(e),
            DmStoreError::Write { source, .. } => Some(source),
            // `getrandom::Error` only implements `Error` under getrandom's `std`
            // feature, which this build does not enable, so the cause is carried
            // in `Display` rather than dropped.
            DmStoreError::EntropySource(_)
            | DmStoreError::Reentrant
            | DmStoreError::Kdf
            | DmStoreError::Module
            | DmStoreError::NotAuthentic { .. }
            | DmStoreError::WrongFileLen { .. }
            | DmStoreError::PayloadTooLong { .. }
            | DmStoreError::UnsealedPayloadNotExact { .. }
            | DmStoreError::CorruptPayloadLen { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    const AT_REST: [u8; AEAD_KEY_LEN] = [0x3Cu8; AEAD_KEY_LEN];
    const OTHER_AT_REST: [u8; AEAD_KEY_LEN] = [0xC3u8; AEAD_KEY_LEN];

    fn label(seed: u8) -> CorrespondenceLabel {
        CorrespondenceLabel::from_bytes([seed; CORRESPONDENCE_LABEL_LEN])
    }

    fn store(dir: &Path) -> DmStore {
        let _ = oxicrypt_module::initialize();
        DmStore::open(dir.join("dm"), &AT_REST).unwrap()
    }

    /// A payload of `len` with recognisable, position-dependent content, so a
    /// round trip that silently shifts or truncates cannot pass.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    // ---- invariant 1: the filename is derived ------------------------------

    #[test]
    fn record_kind_all_is_complete() {
        // Exhaustive match: adding a variant without adding it to `ALL` fails to
        // compile here rather than silently vanishing from enumeration.
        for kind in RecordKind::ALL {
            match kind {
                RecordKind::Resume
                | RecordKind::Provisional
                | RecordKind::Outbox
                | RecordKind::ReceiveCursor => {}
            }
        }
        let mut names: Vec<_> = RecordKind::ALL.iter().map(|k| k.file_name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), RecordKind::ALL.len(), "two kinds share a name");
    }

    #[test]
    fn record_names_cannot_collide_with_a_temp_sibling() {
        for kind in RecordKind::ALL {
            assert!(
                !is_temp_sibling(std::ffi::OsStr::new(kind.file_name())),
                "{} would be swept as an orphan",
                kind.file_name()
            );
        }
        // Positive control: the predicate does match the shape it is for.
        assert!(is_temp_sibling(std::ffi::OsStr::new(
            "resume.bin.tmp.0011aabb"
        )));
    }

    #[test]
    fn a_record_lands_at_its_derived_path() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(1);
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"x"))
            .unwrap();

        let expected = tmp.path().join("dm").join(l.dir_name()).join("resume.bin");
        assert!(expected.exists(), "the path is derived from kind + label");
    }

    // ---- invariant 2: fixed-size buckets -----------------------------------

    #[test]
    fn bucket_sizes_are_pinned() {
        // The provisional record's size is the module's, not a copy of it.
        assert_eq!(RecordKind::Provisional.capacity(), PROVISIONAL_RECORD_LEN);
        assert_eq!(PROVISIONAL_RECORD_LEN, 4813, "the sealed record's size");
        assert_eq!(RecordKind::Resume.capacity(), 65_536);
        assert_eq!(RecordKind::Outbox.capacity(), 262_144);
        assert_eq!(RecordKind::ReceiveCursor.capacity(), 8);

        assert_eq!(RecordKind::ReceiveCursor.on_disk_len(), 8, "unsealed");
        for kind in RecordKind::ALL.iter().filter(|k| k.is_sealed()) {
            assert_eq!(
                kind.on_disk_len(),
                NONCE_LEN + LEN_PREFIX + kind.capacity() + TAG_LEN
            );
        }
    }

    #[test]
    fn aad_tags_are_byte_pinned() {
        assert_eq!(RecordKind::Resume.aad_tag(), 1);
        assert_eq!(RecordKind::Provisional.aad_tag(), 2);
        assert_eq!(RecordKind::Outbox.aad_tag(), 3);
        assert_eq!(RecordKind::ReceiveCursor.aad_tag(), 4);
        let mut tags: Vec<_> = RecordKind::ALL.iter().map(|k| k.aad_tag()).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), RecordKind::ALL.len(), "two kinds share a tag");
    }

    #[test]
    fn every_record_file_is_exactly_its_kinds_on_disk_len() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(2);

        // Wildly different payload lengths per kind; the files must not differ.
        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::Resume, &payload(0))?;
            g.replace(RecordKind::Provisional, &payload(PROVISIONAL_RECORD_LEN))?;
            g.replace(RecordKind::Outbox, &payload(9))?;
            g.replace(RecordKind::ReceiveCursor, &7u64.to_be_bytes())
        })
        .unwrap();

        for kind in RecordKind::ALL {
            let path = tmp
                .path()
                .join("dm")
                .join(l.dir_name())
                .join(kind.file_name());
            assert_eq!(
                std::fs::metadata(&path).unwrap().len() as usize,
                kind.on_disk_len(),
                "{kind:?} must be one fixed size on disk"
            );
        }
    }

    /// The privacy claim in one assertion: two payloads of very different
    /// lengths in the same slot produce files of identical size.
    #[test]
    fn the_file_size_does_not_track_the_payload_size() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(3);
        let path = tmp.path().join("dm").join(l.dir_name()).join("outbox.bin");

        let mut sizes = Vec::new();
        for len in [0usize, 1, 4_096, OUTBOX_CAPACITY] {
            s.critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::Outbox, &payload(len))
            })
            .unwrap();
            sizes.push(std::fs::metadata(&path).unwrap().len());
        }
        assert!(
            sizes.windows(2).all(|w| w[0] == w[1]),
            "an empty outbox and a full one must be the same size on disk: {sizes:?}"
        );
    }

    #[test]
    fn a_payload_larger_than_its_bucket_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(4);

        for kind in [
            RecordKind::Resume,
            RecordKind::Provisional,
            RecordKind::Outbox,
        ] {
            // Positive control: exactly at capacity is accepted and recovers,
            // so the refusal below is about the extra byte and not about size
            // in general.
            let exact = payload(kind.capacity());
            let read_back = s
                .critical_section::<_, DmStoreError>(&l, |g| {
                    g.replace(kind, &exact)?;
                    g.read(kind)
                })
                .unwrap();
            assert_eq!(read_back.as_deref(), Some(exact.as_slice()));

            let over = payload(kind.capacity() + 1);
            let err = s
                .critical_section::<_, DmStoreError>(&l, |g| g.replace(kind, &over))
                .unwrap_err();
            assert!(
                matches!(err, DmStoreError::PayloadTooLong { capacity, actual, .. }
                    if capacity == kind.capacity() && actual == kind.capacity() + 1),
                "{kind:?} must refuse an oversized payload, got {err:?}"
            );

            // And the refusal must not have disturbed what was there.
            let still = s
                .critical_section::<_, DmStoreError>(&l, |g| g.read(kind))
                .unwrap();
            assert_eq!(still.as_deref(), Some(exact.as_slice()));
        }
    }

    #[test]
    fn the_unsealed_cursor_demands_its_exact_size() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(5);

        // Positive control: the exact size works.
        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::ReceiveCursor, &42u64.to_be_bytes())
        })
        .unwrap();

        for bad in [vec![0u8; 7], vec![0u8; 9]] {
            let err = s
                .critical_section::<_, DmStoreError>(&l, |g| {
                    g.replace(RecordKind::ReceiveCursor, &bad)
                })
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    DmStoreError::UnsealedPayloadNotExact { expected: 8, .. }
                ),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn the_payload_length_is_recovered_exactly() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(6);

        for len in [0usize, 1, 2, 255, 256, 65_535, RESUME_CAPACITY] {
            let want = payload(len);
            let got = s
                .critical_section::<_, DmStoreError>(&l, |g| {
                    g.replace(RecordKind::Resume, &want)?;
                    g.read(RecordKind::Resume)
                })
                .unwrap();
            assert_eq!(
                got.as_deref(),
                Some(want.as_slice()),
                "a {len}-byte payload must come back at {len} bytes, byte for byte"
            );
        }
    }

    /// The filler must be *random*, which is strictly more than being different
    /// each time.
    ///
    /// Difference alone is satisfied by any deterministic source — a static
    /// counter written into the buffer, or `counter ^ position` — and such a
    /// source would put a predictable pattern in the padded plaintext that the
    /// filler exists to deny to a core dump or a swapped page. So this checks
    /// the two things a deterministic source cannot fake at once: that a fixed
    /// position moves across calls, and that the byte values are distributed the
    /// way a CSPRNG's are rather than swept uniformly the way a counter's are.
    #[test]
    fn the_filler_is_drawn_fresh_and_is_not_zeroes() {
        const CALLS: usize = 32;
        let kind = RecordKind::Resume;
        let body = b"short";
        let tail = LEN_PREFIX + body.len();

        let samples: Vec<Vec<u8>> = (0..CALLS)
            .map(|_| pad_with_filler(kind, body).unwrap())
            .collect();

        for s in &samples {
            assert_eq!(
                s[..tail],
                samples[0][..tail],
                "the prefix and payload are the same every call"
            );
        }
        assert_ne!(
            samples[0][tail..],
            samples[1][tail..],
            "the filler must be drawn per call"
        );
        assert!(
            samples[0][tail..].iter().any(|&x| x != 0),
            "the filler must not be zeroes"
        );

        // A fixed position must take many different values across calls. With 32
        // draws the expected number of distinct bytes is ~30; a source that is
        // constant per position could not reach 16 and a genuine CSPRNG falls
        // below it only with vanishing probability.
        for pos in (tail..kind.bucket_len()).step_by(4_096) {
            let distinct: HashSet<u8> = samples.iter().map(|s| s[pos]).collect();
            assert!(
                distinct.len() >= 16,
                "byte {pos} took only {} distinct values across {CALLS} calls",
                distinct.len()
            );
        }

        // And the value distribution must look drawn, not swept. Over ~2M filler
        // bytes each of the 256 values is expected ~8_190 times with a standard
        // deviation near 90, so the spread between the most and least common
        // runs to several hundred. A counter — `ctr`, or `ctr ^ position` —
        // sweeps every value almost exactly equally often and lands near zero
        // spread, while a constant-ish source leaves most buckets empty.
        let mut histogram = [0usize; 256];
        for s in &samples {
            for &byte in &s[tail..] {
                histogram[byte as usize] += 1;
            }
        }
        let most = *histogram.iter().max().unwrap();
        let least = *histogram.iter().min().unwrap();
        assert!(least > 0, "some byte value never appeared in the filler");
        assert!(
            most - least >= 150,
            "the filler's byte distribution is too even to be drawn: \
             most common {most}, least common {least}"
        );
    }

    #[test]
    fn round_trip_per_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(7);

        let cases: [(RecordKind, Vec<u8>); 4] = [
            (RecordKind::Resume, payload(1_234)),
            (RecordKind::Provisional, payload(PROVISIONAL_RECORD_LEN)),
            (RecordKind::Outbox, payload(20_000)),
            (RecordKind::ReceiveCursor, 99u64.to_be_bytes().to_vec()),
        ];

        for (kind, want) in &cases {
            s.critical_section::<_, DmStoreError>(&l, |g| g.replace(*kind, want))
                .unwrap();
        }
        // Read in a *separate* critical section, so the round trip goes through
        // the disk rather than through anything held in memory.
        for (kind, want) in &cases {
            let got = s
                .critical_section::<_, DmStoreError>(&l, |g| g.read(*kind))
                .unwrap();
            assert_eq!(got.as_ref(), Some(want), "{kind:?} did not round trip");
        }
    }

    #[test]
    fn an_absent_record_reads_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(8);

        s.critical_section::<_, DmStoreError>(&l, |g| {
            // Positive control: a record that IS there reads as `Some`, so the
            // `None`s below are absence and not a read that never happened.
            g.replace(RecordKind::Outbox, b"owed")?;
            assert_eq!(
                g.read(RecordKind::Outbox).unwrap().as_deref(),
                Some(&b"owed"[..])
            );

            for kind in [
                RecordKind::Resume,
                RecordKind::Provisional,
                RecordKind::ReceiveCursor,
            ] {
                assert_eq!(g.read(kind).unwrap(), None, "{kind:?}");
            }
            Ok(())
        })
        .unwrap();
    }

    /// Both directions, because the check is an equality and a mutation that
    /// weakened it to `raw.len() < kind.on_disk_len()` would still refuse a
    /// truncation while letting an over-long file through to the open.
    #[test]
    fn a_wrong_sized_file_is_diagnosable_rather_than_an_auth_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(9);
        let path = tmp.path().join("dm").join(l.dir_name()).join("resume.bin");

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"body"))
            .unwrap();
        let intact = std::fs::read(&path).unwrap();
        // Positive control: it reads at the right length.
        assert!(
            s.critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
                .unwrap()
                .is_some()
        );

        let mut short = intact.clone();
        short.truncate(intact.len() - 1);
        let mut long = intact.clone();
        long.push(0);

        for raw in [short, long] {
            std::fs::write(&path, &raw).unwrap();
            let err = s
                .critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    DmStoreError::WrongFileLen { expected, actual, .. }
                        if expected == RecordKind::Resume.on_disk_len() && actual == raw.len()
                ),
                "a {}-byte file where {} is required must be diagnosable, got {err:?}",
                raw.len(),
                RecordKind::Resume.on_disk_len()
            );
        }
    }

    #[test]
    fn delete_removes_one_record_and_leaves_the_others() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(10);

        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::Resume, b"resume")?;
            g.replace(RecordKind::Outbox, b"outbox")?;
            g.delete(RecordKind::Resume)?;

            assert_eq!(g.read(RecordKind::Resume).unwrap(), None);
            // Positive control: the sibling is untouched, so the `None` above is
            // a deletion and not a store that lost everything.
            assert_eq!(
                g.read(RecordKind::Outbox).unwrap().as_deref(),
                Some(&b"outbox"[..])
            );
            assert_eq!(g.present().unwrap(), vec![RecordKind::Outbox]);

            // Deleting what is already gone is not an error.
            g.delete(RecordKind::Resume)
        })
        .unwrap();
    }

    // ---- invariant 3: sealed at rest, AAD-bound ----------------------------

    #[test]
    fn a_record_from_another_correspondence_does_not_open() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let (a, b) = (label(11), label(12));

        s.critical_section::<_, DmStoreError>(&a, |g| g.replace(RecordKind::Resume, b"A's state"))
            .unwrap();
        s.critical_section::<_, DmStoreError>(&b, |g| g.replace(RecordKind::Resume, b"B's state"))
            .unwrap();

        let root = tmp.path().join("dm");
        let a_path = root.join(a.dir_name()).join("resume.bin");
        let b_path = root.join(b.dir_name()).join("resume.bin");
        let a_bytes = std::fs::read(&a_path).unwrap();

        // Positive control: A's own bytes back in A's slot still open, so the
        // failure below is the AAD binding and not the copy itself.
        std::fs::write(&a_path, &a_bytes).unwrap();
        assert_eq!(
            s.critical_section::<_, DmStoreError>(&a, |g| g.read(RecordKind::Resume))
                .unwrap()
                .as_deref(),
            Some(&b"A's state"[..])
        );

        std::fs::write(&b_path, &a_bytes).unwrap();
        let err = s
            .critical_section::<_, DmStoreError>(&b, |g| g.read(RecordKind::Resume))
            .unwrap_err();
        assert!(
            matches!(err, DmStoreError::NotAuthentic { .. }),
            "a record spliced from another correspondence must fail to open, got {err:?}"
        );
    }

    /// The kind binding needs a blob of the right *length* for the target slot
    /// but sealed under the wrong kind's AAD — otherwise the length check fires
    /// first and proves nothing about the AAD. So this seals one by hand.
    #[test]
    fn a_record_sealed_for_another_kind_does_not_open() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(13);
        let path = tmp.path().join("dm").join(l.dir_name()).join("resume.bin");

        // Bring the directory into existence.
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"original"))
            .unwrap();

        let plain = pad_with_filler(RecordKind::Resume, b"spliced").unwrap();

        // Positive control: the same plaintext under the RIGHT kind's AAD opens.
        let right = seal_envelope(&s.key, &seal_aad(&l, RecordKind::Resume), &plain).unwrap();
        assert_eq!(right.len(), RecordKind::Resume.on_disk_len());
        std::fs::write(&path, &right).unwrap();
        assert_eq!(
            s.critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
                .unwrap()
                .as_deref(),
            Some(&b"spliced"[..])
        );

        // Same bytes, same length, same slot — only the kind in the AAD differs.
        let wrong = seal_envelope(&s.key, &seal_aad(&l, RecordKind::Outbox), &plain).unwrap();
        assert_eq!(wrong.len(), RecordKind::Resume.on_disk_len());
        std::fs::write(&path, &wrong).unwrap();
        let err = s
            .critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
            .unwrap_err();
        assert!(
            matches!(err, DmStoreError::NotAuthentic { .. }),
            "a blob sealed for another kind must fail to open, got {err:?}"
        );
    }

    #[test]
    fn a_record_does_not_open_under_another_profiles_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dm");
        let l = label(14);

        let _ = oxicrypt_module::initialize();
        let ours = DmStore::open(&root, &AT_REST).unwrap();
        ours.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"ours"))
            .unwrap();

        // Positive control: our own key reads it.
        assert!(
            ours.critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
                .unwrap()
                .is_some()
        );

        let theirs = DmStore::open(&root, &OTHER_AT_REST).unwrap();
        let err = theirs
            .critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
            .unwrap_err();
        assert!(
            matches!(err, DmStoreError::NotAuthentic { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn the_cursor_is_stored_unsealed_and_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(15);
        let bytes = 1234u64.to_be_bytes();

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::ReceiveCursor, &bytes))
            .unwrap();

        let raw =
            std::fs::read(tmp.path().join("dm").join(l.dir_name()).join("cursor.bin")).unwrap();
        assert_eq!(
            raw,
            bytes.to_vec(),
            "the cursor is documented as not secret and is stored as it is"
        );
    }

    // ---- invariant 4: the orphan sweep -------------------------------------

    #[test]
    fn open_sweeps_orphans_and_leaves_real_records_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dm");
        let l = label(16);
        let dir = root.join(l.dir_name());

        {
            let s = store(tmp.path());
            s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"alive"))
                .unwrap();
        }

        // What a SIGKILL between `create_new` and `rename` leaves behind.
        let orphans = [
            dir.join("resume.bin.tmp.00112233445566778899aabb"),
            dir.join("outbox.bin.tmp.ffeeddccbbaa998877665544"),
        ];
        for orphan in &orphans {
            std::fs::write(orphan, b"half-written").unwrap();
        }
        // Positive control: they are genuinely there before the sweep, so their
        // absence afterwards is the sweep and not a path that never existed.
        assert!(orphans.iter().all(|o| o.exists()));

        let s = store(tmp.path());
        assert!(
            orphans.iter().all(|o| !o.exists()),
            "the sweep must remove orphaned temp siblings"
        );
        assert_eq!(
            s.critical_section::<_, DmStoreError>(&l, |g| g.read(RecordKind::Resume))
                .unwrap()
                .as_deref(),
            Some(&b"alive"[..]),
            "the sweep must not touch a real record"
        );
        assert!(
            dir.join(LOCK_FILE_NAME).exists(),
            "the sweep must not remove the lock file"
        );
    }

    #[test]
    fn enumeration_skips_temp_siblings_whether_or_not_the_sweep_has_run() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(17);
        let dir = tmp.path().join("dm").join(l.dir_name());

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, b"owed"))
            .unwrap();
        // Created AFTER `open`, so no sweep has seen it.
        let orphan = dir.join("resume.bin.tmp.0123456789abcdef01234567");
        std::fs::write(&orphan, b"half-written").unwrap();

        let present = s
            .critical_section::<_, DmStoreError>(&l, |g| g.present())
            .unwrap();
        assert_eq!(
            present,
            vec![RecordKind::Outbox],
            "an unswept orphan must not appear as a record"
        );
        assert!(orphan.exists(), "and enumeration must not have removed it");
    }

    // ---- the lock ----------------------------------------------------------

    /// Two independent [`DmStore`] handles on one root, one per thread — the
    /// same shape as two processes, since `flock` excludes per open file
    /// description.
    ///
    /// **A [`std::sync::Barrier`], not a sleep, is what makes the contention
    /// real.** Both threads are fully constructed and released at the same
    /// instant, so they genuinely race for the lock; without that, a test rests
    /// on a sleep being longer than thread-start skew, which is an assumption
    /// about scheduling rather than a proof of overlap. The sleep that remains
    /// is inside the section and does a different job: it widens the window in
    /// which a lock that failed to exclude would be caught in the act.
    #[test]
    fn two_critical_sections_on_one_correspondence_serialize() {
        static INSIDE: AtomicBool = AtomicBool::new(false);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dm");
        let _ = oxicrypt_module::initialize();
        let l = label(18);
        let start = std::sync::Barrier::new(2);

        std::thread::scope(|scope| {
            for _ in 0..2 {
                let root = root.clone();
                let start = &start;
                scope.spawn(move || {
                    let s = DmStore::open(&root, &AT_REST).unwrap();
                    // Neither thread passes this line until both have reached
                    // it, so the acquire below is a genuine simultaneous race.
                    start.wait();
                    s.critical_section::<_, DmStoreError>(&l, |g| {
                        assert!(
                            !INSIDE.swap(true, Ordering::SeqCst),
                            "two critical sections on one correspondence overlapped"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let out = g.replace(RecordKind::Outbox, b"owed");
                        INSIDE.store(false, Ordering::SeqCst);
                        out
                    })
                    .unwrap();
                });
            }
        });
    }

    /// The positive control for the test above: the threads are genuinely
    /// concurrent, and the lock is per correspondence rather than store-wide.
    /// Each side blocks until the other reports it is inside, so if these
    /// serialized the recv would time out.
    #[test]
    fn different_correspondences_do_not_serialize() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dm");
        let _ = oxicrypt_module::initialize();

        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();
        let wait = std::time::Duration::from_secs(10);

        let arrived = std::thread::scope(|scope| {
            let one = {
                let root = root.clone();
                scope.spawn(move || {
                    let s = DmStore::open(&root, &AT_REST).unwrap();
                    s.critical_section::<_, DmStoreError>(&label(19), |_| {
                        tx_a.send(()).unwrap();
                        Ok(rx_b.recv_timeout(wait).is_ok())
                    })
                    .unwrap()
                })
            };
            let two = {
                let root = root.clone();
                scope.spawn(move || {
                    let s = DmStore::open(&root, &AT_REST).unwrap();
                    s.critical_section::<_, DmStoreError>(&label(20), |_| {
                        tx_b.send(()).unwrap();
                        Ok(rx_a.recv_timeout(wait).is_ok())
                    })
                    .unwrap()
                })
            };
            (one.join().unwrap(), two.join().unwrap())
        });

        assert_eq!(
            arrived,
            (true, true),
            "each side must observe the other inside its own critical section"
        );
    }

    // ---- the write's stage distinction -------------------------------------

    /// `rename(2)` refuses to replace a non-empty directory with a file, which
    /// drives a genuine syscall failure at the rename rather than a simulated
    /// one — the one stage the store cannot otherwise reach, and the one whose
    /// whole purpose is telling the caller to re-read before emitting.
    #[test]
    fn a_write_that_fails_at_the_rename_surfaces_as_indeterminate() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(21);
        let dir = tmp.path().join("dm").join(l.dir_name());

        // Positive control: an ordinary write to this slot succeeds first.
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, b"fine"))
            .unwrap();

        let blocked = dir.join("resume.bin");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("occupant"), b"in the way").unwrap();

        let err = s
            .critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"blocked"))
            .unwrap_err();
        assert!(
            matches!(
                err,
                DmStoreError::Write {
                    kind: RecordKind::Resume,
                    source: AtomicReplaceError::Indeterminate(_),
                }
            ),
            "the stage distinction must survive the store's error type, got {err:?}"
        );
        assert!(
            blocked.join("occupant").exists(),
            "the failed write must not have disturbed the destination"
        );
    }

    // ---- the probe must not materialize what it asks about (#253) ----------

    #[test]
    fn a_probe_does_not_materialize_the_correspondence() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let root = tmp.path().join("dm");
        let unknown = label(23);

        for kind in RecordKind::ALL {
            assert_eq!(
                s.read_unlocked(&unknown, kind).unwrap(),
                None,
                "{kind:?} of an unknown correspondence"
            );
        }

        // The claim that matters. The directory names under the root are the one
        // thing readable at rest without any key, so a probe that left one
        // behind would make that listing name every label ever looked at.
        assert!(
            !root.join(unknown.dir_name()).exists(),
            "asking about a correspondence must not create it"
        );
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "the store root must still be empty after {} probes",
            RecordKind::ALL.len()
        );

        // Positive control: an established correspondence reads back through the
        // very same call, so the `None`s above are absence and not a read path
        // that never runs.
        s.critical_section::<_, DmStoreError>(&unknown, |g| g.replace(RecordKind::Outbox, b"owed"))
            .unwrap();
        assert_eq!(
            s.read_unlocked(&unknown, RecordKind::Outbox)
                .unwrap()
                .as_deref(),
            Some(&b"owed"[..])
        );
        assert_eq!(s.read_unlocked(&unknown, RecordKind::Resume).unwrap(), None);
    }

    /// Enumeration is a question too. With `present` reachable only through a
    /// critical section, "which records does this correspondence have?" would
    /// have established it — the probe defect one level down, and just as
    /// visible in the one listing that is readable at rest without a key.
    #[test]
    fn enumerating_a_correspondence_does_not_materialize_it() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let root = tmp.path().join("dm");
        let unknown = label(71);

        assert!(
            s.present_unlocked(&unknown).unwrap().is_empty(),
            "an unknown correspondence holds nothing"
        );
        assert!(
            !root.join(unknown.dir_name()).exists(),
            "enumerating a correspondence must not create it"
        );
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "the store root must still be empty after an enumeration"
        );

        // Positive control: the same call reports the real records of a
        // correspondence that does exist, so the empty answer above is absence
        // rather than an enumeration that never looks at anything.
        let known = label(72);
        s.critical_section::<_, DmStoreError>(&known, |g| {
            g.replace(RecordKind::Outbox, b"owed")?;
            g.replace(RecordKind::ReceiveCursor, &[0u8; RECEIVE_CURSOR_LEN])
        })
        .unwrap();
        let mut found = s.present_unlocked(&known).unwrap();
        found.sort_by_key(|k| k.aad_tag());
        let mut want = vec![RecordKind::Outbox, RecordKind::ReceiveCursor];
        want.sort_by_key(|k| k.aad_tag());
        assert_eq!(found, want, "and it names exactly the records that exist");
    }

    /// The other half of the pair, pinned so the split stays honest: entering a
    /// critical section *does* establish the correspondence, even if the closure
    /// writes nothing. That is the documented behaviour and the whole reason
    /// [`DmStore::read_unlocked`] exists.
    #[test]
    fn entering_a_critical_section_establishes_the_correspondence() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(24);
        let dir = tmp.path().join("dm").join(l.dir_name());

        assert!(!dir.exists(), "not there before");
        s.critical_section::<_, DmStoreError>(&l, |_| Ok(()))
            .unwrap();
        assert!(
            dir.exists(),
            "a critical section establishes the correspondence even when it writes nothing"
        );
        assert!(
            s.critical_section::<_, DmStoreError>(&l, |g| g.present())
                .unwrap()
                .is_empty(),
            "and it holds no records"
        );
    }

    // ---- reentrancy and unwind --------------------------------------------

    /// Run `f` on its own thread and fail loudly if it does not finish.
    ///
    /// Both tests below have a regression mode that *hangs* rather than fails —
    /// a `flock` acquired twice on one thread never returns. A hung assertion
    /// proves nothing and stalls the suite, so the work runs on a thread that is
    /// never joined and the timeout is the verdict.
    fn within_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("the store blocked forever instead of returning")
    }

    #[test]
    fn a_reentrant_critical_section_is_an_error_rather_than_a_deadlock() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_path_buf();

        let (nested_other, reentered) = within_timeout(move || {
            let s = store(&path);
            let l = label(25);

            s.critical_section::<_, DmStoreError>(&l, |_| {
                // Positive control: nesting a *different* correspondence is
                // legitimate and must still work, so the refusal below is about
                // re-entering one label and not about nesting at all.
                let other = s
                    .critical_section::<_, DmStoreError>(&label(26), |g| {
                        g.replace(RecordKind::Outbox, b"other")
                    })
                    .is_ok();

                // The same label on the same thread: `flock` would block here
                // forever on a lock this thread is holding.
                let again = s.critical_section::<_, DmStoreError>(&l, |_| Ok(()));
                Ok((other, matches!(again, Err(DmStoreError::Reentrant))))
            })
            .unwrap()
        });

        assert!(nested_other, "a different correspondence must still nest");
        assert!(
            reentered,
            "re-entering one correspondence on one thread must be a loud error"
        );
    }

    #[test]
    fn a_panicking_closure_releases_the_lock_and_the_claim() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_path_buf();

        let (panicked, reusable) = within_timeout(move || {
            let s = store(&path);
            let l = label(27);

            // The default panic hook prints as this unwinds; that output is the
            // test working, not a failure. The hook is deliberately left alone
            // because replacing it is global and other tests run in parallel.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                s.critical_section::<(), DmStoreError>(&l, |_| {
                    panic!("the closure fails inside the critical section")
                })
            }));

            // The same correspondence must still be usable. If the `flock`
            // leaked, this blocks forever and `within_timeout` reports it; if
            // only the in-process claim leaked, it comes back `Reentrant`.
            let after = s.critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::Outbox, b"after the panic")
            });
            (outcome.is_err(), after.is_ok())
        });

        // Positive control: the panic really happened, so the success below is
        // recovery and not a closure that quietly returned.
        assert!(panicked, "the closure was supposed to panic");
        assert!(
            reusable,
            "an unwind must release both the flock and this thread's claim"
        );
    }

    // ---- the length prefix inside an authentic record ----------------------

    /// [`DmStoreError::CorruptPayloadLen`] is only reachable through a record
    /// that *authenticated*, so it needs a hand-sealed one — the same technique
    /// as `a_record_sealed_for_another_kind_does_not_open`. Without this, a
    /// mutation that let `unpad` trust the declared length and slice past the
    /// buffer would survive every other test in this module.
    #[test]
    fn a_corrupt_length_prefix_is_refused_rather_than_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(28);
        let kind = RecordKind::Resume;
        let path = tmp.path().join("dm").join(l.dir_name()).join("resume.bin");

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(kind, b"original"))
            .unwrap();

        let mut plain = pad_with_filler(kind, b"body").unwrap();
        let seal = |plain: &[u8]| seal_envelope(&s.key, &seal_aad(&l, kind), plain).unwrap();
        let read = || s.critical_section::<_, DmStoreError>(&l, |g| g.read(kind));

        // Positive control: hand-sealed with an honest prefix, it opens — so the
        // refusals below are the prefix and not the hand-sealing.
        std::fs::write(&path, seal(&plain)).unwrap();
        assert_eq!(read().unwrap().as_deref(), Some(&b"body"[..]));

        // Boundary control: a payload declared at exactly the capacity is the
        // largest legal one and must still open, pinning the check as `>` and
        // not `>=`.
        plain[..LEN_PREFIX].copy_from_slice(&(kind.capacity() as u32).to_le_bytes());
        std::fs::write(&path, seal(&plain)).unwrap();
        assert_eq!(read().unwrap().map(|p| p.len()), Some(kind.capacity()));

        // One byte past the bucket, and a wild value. Each must be a refusal —
        // reaching these assertions at all is the proof it is not a panic.
        for declared in [kind.capacity() as u32 + 1, u32::MAX] {
            plain[..LEN_PREFIX].copy_from_slice(&declared.to_le_bytes());
            let sealed = seal(&plain);
            assert_eq!(sealed.len(), kind.on_disk_len(), "still a valid-size file");
            std::fs::write(&path, &sealed).unwrap();

            let err = read().unwrap_err();
            assert!(
                matches!(
                    err,
                    DmStoreError::CorruptPayloadLen { declared: d, capacity, .. }
                        if d == declared as usize && capacity == kind.capacity()
                ),
                "a record declaring {declared} bytes must be refused, got {err:?}"
            );
        }
    }

    /// Domain separation from [`crate::dm::provisional::derive_seal_key`], which
    /// the module docs assert and nothing tested. Collapsing the two derivations
    /// onto one HKDF label pair would leave every other test in this module
    /// green.
    #[test]
    fn a_record_sealed_under_the_provisional_records_key_does_not_open() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(29);
        let kind = RecordKind::Provisional;
        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join("provisional.bin");

        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(kind, &payload(PROVISIONAL_RECORD_LEN))
        })
        .unwrap();

        let plain = pad_with_filler(kind, b"lifted").unwrap();
        let aad = seal_aad(&l, kind);

        // Positive control: this exact plaintext, this exact AAD, this exact
        // slot — sealed under the store's key it opens.
        std::fs::write(&path, seal_envelope(&s.key, &aad, &plain).unwrap()).unwrap();
        assert_eq!(
            s.critical_section::<_, DmStoreError>(&l, |g| g.read(kind))
                .unwrap()
                .as_deref(),
            Some(&b"lifted"[..])
        );

        // Everything held identical except the key's HKDF labels. The store's
        // AAD is used deliberately rather than the provisional module's: with
        // both the key and the AAD changed the read would fail for either
        // reason, and the test would pass even with the key derivations
        // collapsed. Isolating the key is what makes this catch that.
        let theirs = crate::dm::provisional::derive_seal_key(&AT_REST).unwrap();
        let wrong = seal_envelope(&theirs, &aad, &plain).unwrap();
        assert_eq!(wrong.len(), kind.on_disk_len(), "still a valid-size file");
        std::fs::write(&path, &wrong).unwrap();

        let err = s
            .critical_section::<_, DmStoreError>(&l, |g| g.read(kind))
            .unwrap_err();
        assert!(
            matches!(err, DmStoreError::NotAuthentic { .. }),
            "the store key and the provisional record's key must be different keys, got {err:?}"
        );
    }

    #[test]
    fn the_label_does_not_render_itself() {
        let rendered = format!("{:?}", label(22));
        assert_eq!(rendered, "CorrespondenceLabel(..)");
        // Positive control: the bytes ARE reachable when asked for explicitly.
        assert_eq!(label(22).as_bytes(), &[22u8; CORRESPONDENCE_LABEL_LEN]);
    }
}
