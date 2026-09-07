//! The DM record store: the one place a direct-messaging record reaches the
//! disk, and the place the lock becomes impossible to forget (#286, Amendment
//! A9's build-obligation list, `docs/design/direct-messaging.md`).
//!
//! **It is not where messages are kept.** The word *store* invites that reading
//! and it is wrong. What is held is the state a correspondence needs in order to
//! carry on: [`RecordKind::Resume`], the crypto state a reconnect wants;
//! [`RecordKind::Provisional`], a handshake still in progress;
//! [`RecordKind::Outbox`], what has been sent and is not yet settled;
//! [`RecordKind::ReceiveCursor`], how far reading has got; and
//! [`RecordKind::ContactCache`], what is known about the correspondent. One
//! further kind belongs to the profile rather than to any correspondence:
//! [`RecordKind::BlockList`], the identities the user refuses.
//!
//! **Message content is here only while a message is in flight**, inside an
//! outbox entry awaiting collection. Once that entry settles or gives up the
//! content is dropped and delivery metadata is all that remains. **A received
//! message is never written here at all.**
//!
//! ## Why a store at all, when `super::atomic_file` already writes durably
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
//! `super::atomic_file::replace_atomically` would serialize the write half and
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
//! `crate::dm::LEN_PREFIX` convention, shared with the frame paddings) — put
//! outside it, the prefix would hand back the exact length the padding was
//! there to hide.
//!
//! ## What the store does and does not protect
//!
//! Every kind is sealed with `seal_envelope` before it reaches the disk, so the
//! store holds opaque bytes and nothing else (ISC-A-C6). The AAD binds the record kind and the correspondence label, so a
//! blob lifted from one slot cannot be replayed into another — the key is
//! per-*profile*, exactly as [`crate::dm::provisional::derive_seal_key`]'s is,
//! and without a per-slot binding every file in a profile would be an
//! interchangeable ciphertext.
//!
//! ## Two scopes: per-correspondence, and per-profile
//!
//! Almost every kind is per-correspondence, and everything above is written for
//! those. [`RecordKind::scope`] names the exception: a **profile-level** record
//! belongs to the profile itself, lives as a fixed-name file at the store root,
//! takes the profile's own lock ([`DmStore::profile_critical_section`]), and
//! seals under [`domain::DM_STORE_PROFILE_AAD`] — which binds the kind and, of
//! necessity, no label.
//!
//! **The scope is forced by the data, not chosen for convenience.**
//! [`RecordKind::BlockList`] names identities a user refuses, and refusing
//! somebody does not require ever having corresponded with them — the doorbell
//! plane exists precisely for the stranger's first contact — so there is no
//! correspondence whose directory could hold it. Reserving a
//! [`CorrespondenceLabel`] value for it is not available either:
//! [`CorrespondenceLabel::from_bytes`] is a `const fn` over any 32 bytes and
//! [`CorrespondenceLabel::mint`] draws them from the CSPRNG, so every 32-byte
//! value is a real label and no reserved one is distinguishable from a minted
//! one.
//!
//! Everything else is inherited rather than re-implemented: one padding, one
//! seal, one atomic replace, one orphan sweep — and the sweep covers root-level
//! temp siblings for that reason, since a profile record's `replace_atomically`
//! sibling lands at the root.
//!
//! **One key, random nonces, and no bound on the number of seals.**
//! `derive_store_key` produces a single AES-256-GCM key per profile, and
//! `seal_envelope` draws a fresh random 96-bit nonce for every record it
//! writes. That key covers every correspondence and every record kind for the
//! whole life of the profile, and nothing anywhere counts the seals. Random
//! 96-bit nonces collide on the birthday bound, so the standard guidance is to
//! keep one key under roughly 2^32 encryptions; past that, a repeated nonce
//! becomes likely, and a nonce repeat under GCM is not a graceful degradation —
//! it leaks the XOR of the two plaintexts and compromises the authentication
//! key. Every [`Locked::replace`] is one encryption, so the budget is spent by
//! record *writes*, not by bytes or by correspondences.
//!
//! **The arithmetic, because "unreachable at any realistic volume" was asserted
//! here and is wrong (#289).** The budget is spent by record writes, and the term
//! that dominates is not messages at all.
//!
//! **Polling was the governing cost.** [`crate::dm::persist::DmPersist::update_outbox`]
//! wrote on every successful call, so every `sweep_give_ups`, `settle_from_ack`
//! and `channel_torn_down` poll spent one seal per correspondence per tick
//! whether or not anything happened. Over ten years, with no messages sent at
//! all, that is what an idle correspondence cost:
//!
//! | correspondences | sweep tick | seals | of 2^32 |
//! |---|---|---|---|
//! | 500 | 60 s | 2.63 G | **61%** |
//! | 500 | 10 min | 263 M | 6.1% |
//! | 500 | 1 h | 43.8 M | 1.0% |
//! | 50 | 1 h | 4.4 M | 0.1% |
//!
//! **A poll that changes nothing no longer spends a seal** (#347). The closure
//! reports [`Mutation::Unchanged`](crate::dm::persist::Mutation) and the write is
//! skipped, so an idle correspondence pays none of that table and the sweep
//! cadence is a latency choice again rather than a cryptographic one.
//!
//! The table still bounds the *active* case: a correspondence that genuinely
//! changes on every tick pays exactly these rows, so the cadence is not free —
//! it is merely no longer charged for doing nothing. The cadence is still unset;
//! there is no transport driver to set it.
//!
//! Messages are the smaller term. An ordinary message costs 4 seals (enqueue,
//! first emission rewriting outbox and resume, ack settlement) and one never
//! acknowledged costs 32 — it rides [`crate::dm::outbox::RESEED_LADDER`] to
//! [`crate::dm::outbox::GIVE_UP`] for **15 emissions**, being due immediately on
//! compose and then after each rung. At 4 seals it takes a billion messages to
//! reach the bound alone.
//!
//! ⚠️ **The "rewriting outbox and resume" half is still the higher reading.** The
//! resume record now has production writers —
//! [`DmPersist::accept_first_contact`](crate::dm::persist::DmPersist::accept_first_contact)
//! writes one at the acceptor's establishment,
//! [`commit_with_resume`](crate::dm::persist::PendingHandshake::commit_with_resume)
//! writes one at the initiator's, and the load-time re-establishment pass writes
//! one per opened attempt — but none of those is an *emission*. A message's
//! re-seed rewrites the outbox alone. So the per-message costs are 3 and 17
//! rather than 4 and 32, and the figures above stay at the higher reading
//! deliberately: a resume write per emission is what a later slice may add, and
//! the bound must not have to be re-derived when it does.
//!
//! What the resume record does cost is **one seal per establishment** and one per
//! re-establishment attempt, both per correspondence rather than per message, so
//! neither is a term beside the poll table.
//!
//! Not counted: `RecordKind::Provisional` writes (per-correspondence, first
//! contact only), and the per-message accounting over-counts because one
//! correspondence has one outbox, so several due entries settle in one seal.
//! Both are small against the poll term.
//!
//! **The cursor became a term in this budget when it was sealed** (#389), and
//! its size is not yet measured. What bounds it is that
//! [`crate::dm::persist::DmPersist::advance_cursor`] writes only when the number
//! genuinely moves — a refused or unchanged advance returns before the replace —
//! so the draw is one seal per *advance*, not one per receive poll. An advance
//! is one page of received messages rather than one message, which puts it below
//! the per-message terms above for any correspondence whose pages fill. The
//! rate under representative traffic is an open measurement; there is no
//! transport driver cadence to measure it against yet, which is the same reason
//! the poll table's cadence is still unset.
//!
//! `reseeds_before_give_up_is_the_documented_figure` pins the ladder arithmetic to
//! the constants it is computed from, so a cadence change fails rather than
//! silently invalidating this.
//!
//! **Nothing warns as the count grows** — no counter, no rotation, no re-key — so
//! the first symptom of crossing it would be a silent loss of the guarantee rather
//! than an error. Rotation is deliberately not implemented: it needs a key epoch
//! in every record's AAD and a migration for records already on disk, which is a
//! record-format decision that belongs with the format, not with this module.
//!
//! **The cursor is sealed like everything else** (#389). It was the one kind
//! written in the clear, on the argument that
//! [`crate::dm::provisional::ReceiveCursor`] is not secret. It is not secret;
//! it is a *disclosure* — eight plaintext bytes naming how far reading has got
//! is a monotone proxy for how many messages a correspondence has received,
//! legible to anyone holding the disk and no key. The directory name discloses
//! that a correspondence exists; its file contents should not go on to
//! disclose its volume.
//!
//! **The seal does not make the number trustworthy, and nothing here should be
//! read as saying it does.** A cursor that opens says only that something
//! holding this profile's key wrote it, which includes this profile writing a
//! wrong one. [`crate::dm::persist::DmPersist::read_cursor`] still bounds every
//! value it recovers by what the caller has actually read
//! ([`crate::dm::provisional::ReceiveCursor::from_be_bytes`]'s `read_through`),
//! and that check is what the correctness of a resumed sweep rests on — before
//! this change and after it.
//!
//! Two things this store does **not** do, stated so no one reads them into it:
//!
//! - **It does not erase from the medium.** [`Locked::delete`] overwrites the
//!   record in place before unlinking the name — two fsynced phases, every
//!   [`RecordKind`] — so the payload is gone from every subsequent read and from
//!   the blocks the filesystem believes it wrote. What it cannot reach is the
//!   hardware beneath: an SSD's FTL remaps an overwrite onto a fresh block and a
//!   copy-on-write filesystem writes a new extent by design, so an adversary
//!   holding the raw flash is outside what any store here delivers. The same
//!   bound [`crate::dm::provisional`] records for `ss0`. Note the asymmetry with
//!   *replacement*, which is `rename(2)` and scrubs nothing — deliberate, and
//!   argued where the trade is taken.
//! - **It does not make the directory's shape invariant.** Fixed sizes hold
//!   across clean runs. A process killed between a temp sibling's creation and
//!   its rename leaves that sibling behind, so the entry count still tracks how
//!   often the writer died mid-write until [`DmStore::open`]'s sweep runs.
//!   Enumeration ([`Locked::present`]) is immune either way, because it derives
//!   the names it looks for rather than reading what happens to be there.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_kdf::HkdfSha384;
use zeroize::Zeroize;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::dm::block_list::BLOCK_LIST_CAPACITY;
use crate::dm::contact_cache::CONTACT_RECORD_LEN;
use crate::dm::provisional::PROVISIONAL_RECORD_LEN;
use crate::dm::resume::MAX_ENCODED_LEN;
use crate::dm::{LEN_PREFIX, domain, push_lp, unpad};
use crate::storage::atomic_file::{
    AtomicReplaceError, Durability, FileLock, LockError, RealDurability, TMP_INFIX,
    replace_atomically,
};
use crate::storage::seeds::AEAD_KEY_LEN;

/// Marks a record whose erasure began and did not finish (#293).
///
/// Written and fsynced as the first phase of [`Locked::delete`], so a crash
/// during a scrub leaves a record a reader can *name* rather than one that
/// merely fails to open. Without it an interrupted erase is byte-indistinguishable
/// from a truncated or tampered record, and a power cut would surface to the
/// user as a possible attack — the false alarm that teaches people to ignore
/// real ones.
///
/// It cannot collide with a live record: every kind begins with a random nonce.
/// `pub(crate)` so a sibling module's tests can synthesise the exact crash state
/// — sentinel written, unlink not reached — rather than approximating it. Never
/// used directly by the write or read paths: both go through
/// [`erasure_sentinel`], and through [`sentinel_for_width`] beneath it, which is
/// the only place the length bound is expressed.
pub(crate) const ERASURE_SENTINEL: &[u8; 32] = b"daemonseed/dm/store/erased/v1\0\0\0";

/// The sentinel prefix for `kind`, bounded by that kind's own record length.
///
/// **One definition, because two would be a bug that no test could see.** The
/// writer ([`scrub_in_place`]) and the reader ([`DmStore::read_record`]) must
/// agree byte for byte: a writer that stamps more than the reader matches leaves
/// an erase that reads as an ordinary record, and one that stamps less leaves it
/// reading as `WrongFileLen` — the truncation shape the sentinel exists to
/// displace. Expressing the bound twice made that agreement a convention held by
/// nothing; expressing it here makes disagreement unconstructible.
///
/// **The bound bites for no current kind, and stays anyway.** Every kind is
/// `NONCE_LEN + LEN_PREFIX + capacity + TAG_LEN` ≥ 33 bytes, so every prefix is
/// the whole 32 — including the cursor, which is the kind the bound was written
/// for and was 8 bytes until #389 sealed it. The bound is the guard that makes a
/// short kind unable to *grow* its own file mid-erase; removing it now would put
/// that failure one variant away, with nothing between.
///
/// **Two floors this must not cross, and both are load-bearing rather than
/// tidiness** — `record_kinds_admit_a_usable_sentinel` holds them over the kinds
/// that exist:
///
/// 1. **At least [`NONCE_LEN`].** Phase 1's durability barrier
///    is what makes the crash window safe, and it is safe *because* those bytes
///    overwrite the AEAD nonce. Shortening the prefix below the nonce would leave
///    an openable record across the window with nothing failing anywhere.
/// 2. **Never empty.** `raw.starts_with(&[])` is unconditionally true, so a kind
///    with a zero-length record would read every record it has as an interrupted
///    erase.
fn erasure_sentinel(kind: RecordKind) -> &'static [u8] {
    sentinel_for_width(kind.on_disk_len())
}

/// The sentinel truncated to `width`.
///
/// **The width is a parameter so the truncation has a seam a fixture can
/// reach.** No kind is shorter than the sentinel any more, so over
/// [`RecordKind::ALL`] the `min` is a no-op and deleting it changes nothing any
/// test could observe — the guard would read as held while being unpinned.
/// `the_sentinel_never_exceeds_the_record_it_stamps` drives this directly with
/// widths no kind has, which is the only way the bound is checked at all.
fn sentinel_for_width(width: usize) -> &'static [u8] {
    &ERASURE_SENTINEL[..ERASURE_SENTINEL.len().min(width)]
}

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
/// **No longer a guess: the format exists and its worst case is computed.**
/// [`crate::dm::resume::MAX_ENCODED_LEN`] is the arithmetic sum of every fixed
/// field plus [`crate::dm::frame::MAX_FRAME_LEN`], which
/// [`crate::dm::resume::SealedReEst::seal`] refuses to exceed and
/// [`crate::dm::resume::ResumeRecord::decode`] re-checks before allocating — so
/// it is a real ceiling rather than a typical case, and this constant is checked against it
/// by the `const` assertion immediately below — not by a test, because both
/// sides are `const` and a runtime assertion over two constants is a probe that
/// cannot fire (`clippy::assertions_on_constants` says so). A field added to the
/// record that outgrows this bucket fails the **build**.
///
/// The headroom left over is deliberate. A9.2's field set is closed today, but
/// the re-establishment protocol that produces it is not built, and a record
/// that grows after records exist needs a migration — see below.
///
/// If a resume record outgrows this, [`Locked::replace`] refuses the write with
/// [`DmStoreError::PayloadTooLong`] — loudly, at the moment of the write, with
/// both numbers in the message. It never truncates, and it never silently grows
/// the file: growing it is a deliberate edit here, and because the bucket is the
/// on-disk size, that edit changes the length of every existing record and
/// therefore needs a migration. Sizing it generously now is much cheaper than
/// resizing it later.
pub const RESUME_CAPACITY: usize = 65_536;

/// The bucket holds the worst case, checked at **compile time**.
///
/// A runtime test of this would be a probe that cannot fire: both sides are
/// `const`, so the comparison is settled before any test runs — which is what
/// `clippy::assertions_on_constants` says when it refuses one. A `const`
/// assertion states the same fact where it is actually decided, and a field
/// added to [`crate::dm::resume::ResumeRecord`] that outgrows this bucket then
/// fails the **build** rather than a test somebody might not run.
const _: () = assert!(
    MAX_ENCODED_LEN <= RESUME_CAPACITY,
    "the worst-case resume record exceeds RESUME_CAPACITY"
);

/// Largest payload a [`RecordKind::Outbox`] record may carry.
///
/// [`crate::dm::outbox::Outbox::encode`] is variable-length by nature: a header,
/// then one entry per message, each *owed* entry carrying its sealed frame. Per
/// entry the fixed fields cost about forty bytes.
///
/// **Two counts matter and they differ by two orders of magnitude.**
///
/// *Owed* messages — those still carrying a frame — are the binding one:
/// **106 at [`crate::dm::frame::WORST_CASE_SEALED_FRAME_LEN`], 213 at the
/// smallest frame a padding rung permits** (both measured 2026-08-15; the first
/// is pinned by `the_bucket_holds_its_claimed_owed_message_count`).
///
/// *Lifetime* messages are the second: a terminal entry sheds its frame but
/// keeps its forty bytes for ever, and **nothing prunes**, so a record also dies
/// at ~52 000 messages ever sent. That ceiling is far away and is tracked
/// separately; the owed count is what ordinary use reaches.
///
/// **Do not size this against [`crate::dm::frame::MAX_FRAME_LEN`], and do not
/// assume a small typical frame.** Both errors were made here before the frame
/// was measured (#291): the cap is a subkey bound `seal` cannot reach, and
/// [`crate::dm::frame::PAD_BUCKETS`] means no frame is ever small. Sizing
/// against either produces a number off by a third in one direction or an order
/// of magnitude in the other.
///
/// **The consequence, stated because the arithmetic does not flatter this
/// design:** the give-up window is seven days, and 106–213 owed messages is well
/// under a day of chatty sending. No affordable fixed size closes that gap —
/// covering a thousand owed messages costs ~20 MB *per correspondence* — because
/// frame padding multiplies against the fixed bucket. So the send-path refusal
/// #291 tracks is **the mechanism, not a backstop**: it is expected to fire in
/// ordinary use.
///
/// **That refusal is built.** [`crate::dm::outbox::Outbox`] prices a candidate
/// entry against this constant before accepting it and answers
/// [`crate::dm::outbox::OutboxError::Full`], so a sender is told at enqueue rather
/// than discovering it at the write — the gate sits inside the private `insert`
/// that both public enqueue doors funnel through, so nothing can enqueue around
/// it. What it does NOT decide is what the user is shown; that surface is still
/// open.
///
/// **The trade is disk against the leak.** Every correspondence pays this in
/// full whether it owes one message or none, which is the price of the file
/// size not tracking the queue depth. The overflow behaviour is
/// [`RESUME_CAPACITY`]'s: refused at the write with
/// [`DmStoreError::PayloadTooLong`], never truncated.
pub const OUTBOX_CAPACITY: usize = 2_097_152;

/// Bytes in a persisted [`crate::dm::provisional::ReceiveCursor`] — its
/// `to_be_bytes` form. The record's *payload* length, not its length on disk:
/// the cursor is sealed and padded like every other kind, so
/// [`RecordKind::ReceiveCursor`]'s [`RecordKind::on_disk_len`] is larger.
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
    ///
    /// **Sealed like every other kind** (#389). It held the store's one
    /// plaintext record until then, and eight clear bytes of read-through page
    /// number is a per-correspondence message-volume disclosure to anyone
    /// holding the disk. Sealing it does not make the number *trustworthy* —
    /// [`crate::dm::persist::DmPersist::read_cursor`] bounds every value it
    /// recovers by what the caller has actually read, and that is still the
    /// only thing standing behind it.
    ReceiveCursor,
    /// What is known about the correspondent themselves
    /// ([`crate::dm::contact_cache::ContactRecord`]) — their long-term and
    /// pseudonym public keys, the correspondence's address root `AR`, and when
    /// they were first and last seen. **Not `ss0`**: § D-PFS retains only `AR`,
    /// and [`crate::dm::contact_cache`] says why.
    ///
    /// **Arrives as plaintext**, unlike [`RecordKind::Provisional`]. This record
    /// carries no seal of its own, so this store's seal and its AAD are the
    /// whole of its protection, and `AR` is live in the payload until
    /// [`Locked::replace`] seals it. Weakening either for this kind is therefore
    /// not the defence-in-depth trade it would be for a pre-sealed kind — there
    /// is no second layer behind it. `crate::dm::contact_cache` argues why the
    /// record has no seal of its own.
    ContactCache,
    /// The identities this profile refuses ([`crate::dm::block_list::BlockList`])
    /// — the one kind that belongs to the **profile** rather than to a
    /// correspondence.
    ///
    /// **It has no correspondence label because a block does not have one.** A
    /// blocked identity is one there need never have been an established
    /// correspondence with — that is the doorbell plane's whole case — so there
    /// is no directory it could live in. Its file sits at the store root, its
    /// AAD binds [`domain::DM_STORE_PROFILE_AAD`] and this kind's tag and
    /// nothing else, and [`DmStore::profile_critical_section`] is the lock that
    /// brackets a change to it.
    ///
    /// **Created by every [`DmStore::open`]**, so its presence reports only that
    /// a profile has a DM store, never that anyone has blocked anybody. The
    /// bucket is [`crate::dm::block_list::BLOCK_LIST_CAPACITY`] — the ratified
    /// 512-identity ceiling in full — so the file is one size whether it holds
    /// nobody or all 512.
    BlockList,
}

/// Whether a [`RecordKind`] belongs to one correspondence or to the profile.
///
/// The two differ in three things that all follow from the same fact: a
/// profile-level record has no [`CorrespondenceLabel`]. It has no directory (it
/// sits at the root), no label in its AAD, and its own lock rather than a
/// correspondence's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordScope {
    /// One record per correspondence, inside that correspondence's directory.
    Correspondence,
    /// One record per profile, at the store root.
    Profile,
}

impl RecordKind {
    /// Every kind, for enumeration. Hand-maintained, and held to the enum by
    /// `record_kind_all_is_complete`.
    ///
    /// **Spans both scopes**, so a caller enumerating one correspondence's
    /// records filters on [`RecordKind::scope`] rather than walking this
    /// directly — [`DmStore::present_unlocked`] is that filter and is the only
    /// enumeration a caller needs.
    pub const ALL: [RecordKind; 6] = [
        RecordKind::Resume,
        RecordKind::Provisional,
        RecordKind::Outbox,
        RecordKind::ReceiveCursor,
        RecordKind::ContactCache,
        RecordKind::BlockList,
    ];

    /// The stable string form, for local persistence.
    ///
    /// **Deliberately not the enum's discriminant and deliberately not
    /// the record's file name.** A discriminant makes a reordering of the enum
    /// silently rewrite history, which is the same reason
    /// [`crate::trust_events`] stores event keys by string; a file name is a
    /// storage-layout detail that a later layout change would be free to move,
    /// and a persisted log must not be hostage to that. These strings are
    /// frozen once written to a log.
    pub const fn stable_str(self) -> &'static str {
        match self {
            RecordKind::Resume => "resume",
            RecordKind::Provisional => "provisional",
            RecordKind::Outbox => "outbox",
            RecordKind::ReceiveCursor => "receive-cursor",
            RecordKind::ContactCache => "contact-cache",
            RecordKind::BlockList => "block-list",
        }
    }

    /// Parse a kind from [`Self::stable_str`]; `None` for an unknown string
    /// (e.g. a kind from a newer build).
    ///
    /// **That `None` is a first-class answer, not a failure**, and the one
    /// caller honours it: the audit-log decoder degrades the event's
    /// `record_kind` to absent and keeps the entry. A fifth variant would not
    /// move the log's layout, so the format's version tag never fires for it
    /// and a rollback is exactly when this returns `None` — the doc used to
    /// promise this and the decoder used to discard the whole log instead.
    pub fn from_stable_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.stable_str() == s)
    }

    /// The file name inside the correspondence directory.
    ///
    /// Fixed strings, and none of them contains [`TMP_INFIX`] — which is what
    /// makes name-derived enumeration immune to orphaned temp siblings without
    /// having to filter them out. `record_names_cannot_collide_with_a_temp_sibling`
    /// pins that.
    pub(crate) const fn file_name(self) -> &'static str {
        match self {
            RecordKind::Resume => "resume.bin",
            RecordKind::Provisional => "provisional.bin",
            RecordKind::Outbox => "outbox.bin",
            RecordKind::ReceiveCursor => "cursor.bin",
            RecordKind::ContactCache => "contact-cache.bin",
            RecordKind::BlockList => "block-list.bin",
        }
    }

    /// The largest payload [`Locked::replace`] accepts for this kind.
    pub const fn capacity(self) -> usize {
        match self {
            RecordKind::Resume => RESUME_CAPACITY,
            // The record is already one fixed size by construction, so the
            // store's bucket is exactly it — no slack, nothing to choose.
            RecordKind::Provisional => PROVISIONAL_RECORD_LEN,
            RecordKind::Outbox => OUTBOX_CAPACITY,
            RecordKind::ReceiveCursor => RECEIVE_CURSOR_LEN,
            // As with `Provisional`: the record is already one fixed size by
            // construction, so the store's bucket is exactly it.
            RecordKind::ContactCache => CONTACT_RECORD_LEN,
            // The ratified 512-identity ceiling in full, so the record's size
            // never reports how many of those slots are used.
            RecordKind::BlockList => BLOCK_LIST_CAPACITY,
        }
    }

    /// The padded plaintext length: the length prefix plus [`Self::capacity`].
    pub const fn bucket_len(self) -> usize {
        LEN_PREFIX + self.capacity()
    }

    /// The exact size of this kind's file on disk, for every record of it.
    ///
    /// This — not [`Self::bucket_len`] — is the number the privacy argument
    /// rests on, and `every_record_file_is_exactly_its_kinds_on_disk_len` is
    /// what holds the code to it.
    pub const fn on_disk_len(self) -> usize {
        NONCE_LEN + self.bucket_len() + TAG_LEN
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
            // Reserved before it was needed, for exactly this: the cursor was
            // unsealed and had no AAD, and sealing it (#389) took the value that
            // was already held for it rather than inventing one that might
            // collide with a kind already on disk.
            RecordKind::ReceiveCursor => 4,
            RecordKind::ContactCache => 5,
            RecordKind::BlockList => 6,
        }
    }

    /// Refuse this kind if it does not belong to `guard`'s scope.
    ///
    /// **A returned error, not a `debug_assert`.** The guards are `pub` over one
    /// `pub` enum spanning both scopes, so a mismatch is caller-reachable in a
    /// release build, where an assertion does not exist. See
    /// [`DmStoreError::WrongScope`] for what each direction would otherwise
    /// write.
    fn require_scope(self, guard: RecordScope) -> Result<(), DmStoreError> {
        if self.scope() == guard {
            Ok(())
        } else {
            Err(DmStoreError::WrongScope { kind: self, guard })
        }
    }

    /// Whether this kind belongs to one correspondence or to the profile.
    ///
    /// A method rather than a second hand-maintained array: a new variant that
    /// forgot to say which it is fails to compile here, where a variant missing
    /// from an array would silently vanish from every enumeration.
    pub const fn scope(self) -> RecordScope {
        match self {
            RecordKind::Resume
            | RecordKind::Provisional
            | RecordKind::Outbox
            | RecordKind::ReceiveCursor
            | RecordKind::ContactCache => RecordScope::Correspondence,
            RecordKind::BlockList => RecordScope::Profile,
        }
    }
}

/// Which correspondence a record belongs to — an opaque 32-byte name supplied by
/// the caller.
///
/// **A label is minted from the CSPRNG, never derived** ([`Self::mint`]; decided
/// 2026-08-07, `docs/design/direct-messaging.md` § *What names a correspondence
/// directory on disk*, #288). It must not be `chan_id`, which
/// [`crate::dm::provisional`] states must never be serialized anywhere; and it
/// must not be the key-record address, which is world-derivable from a harvested
/// public key, so a derived name would let anyone who can read the directory
/// test membership over any candidate pubkey with no key at all.
///
/// **What minting buys over a *salted* derivation is narrower than "unlinkable",
/// and worth stating precisely.** The mapping has to be persisted somewhere —
/// the contact cache — and that cache lives on the same disk under the same
/// profile key, so an attacker who obtains the key obtains the mapping either
/// way. The real differential is against the attacker who has the *disk* and a
/// set of candidate pubkeys: a salt is a standing oracle that answers "is this
/// pubkey a correspondent?" for every directory, **including orphaned ones whose
/// cache entry is long gone**, whereas a minted label reveals only what the
/// cache still holds. Deleting a contact deletes its linkage; under a derived
/// scheme the linkage outlives the contact for as long as the salt does.
///
/// The cost is that a label cannot be recomputed: minting, recording and
/// directory creation must be ordered so a crash leaves either nothing or
/// something a sweep can identify (the obligation on the collection slice,
/// #236).
///
/// The store depends on no property of a label beyond distinctness — it only
/// ever compares and hex-encodes — so it remains correct for any caller-supplied
/// value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrespondenceLabel([u8; CORRESPONDENCE_LABEL_LEN]);

impl CorrespondenceLabel {
    /// Mint a fresh label from the CSPRNG — the only way a *new* correspondence
    /// should acquire one.
    ///
    /// 32 bytes of `getrandom`, so two correspondences collide with probability
    /// negligible against any number of them a profile will hold, and no
    /// observer can predict or recognise a label without the contact cache that
    /// records it. The caller persists the result; there is no second chance to
    /// derive it (see the type docs).
    pub fn mint() -> Result<Self, DmStoreError> {
        let mut bytes = [0u8; CORRESPONDENCE_LABEL_LEN];
        getrandom::fill(&mut bytes).map_err(DmStoreError::EntropySource)?;
        Ok(Self(bytes))
    }

    /// A label over the caller's bytes — for a correspondence whose label was
    /// already minted and persisted. [`Self::mint`] is what creates one.
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

    /// The inverse of [`Self::dir_name`]: the label a directory name encodes, or
    /// `None` if this name is not one this store wrote.
    ///
    /// **Strict, because the answer is used to decide what is a correspondence
    /// at all.** Exactly `2 * CORRESPONDENCE_LABEL_LEN` characters, and every one
    /// of them lowercase hex — not `hex::decode`'s own rules, which accept
    /// uppercase and would let one label round-trip through two distinct names
    /// on a case-sensitive filesystem and collide on a case-insensitive one.
    /// Only the exact form [`Self::dir_name`] produces is accepted, so the pair
    /// is a bijection and `a_label_round_trips_through_its_directory_name` holds
    /// it there.
    ///
    /// A rejected name is not an error: the root holds the profile lock and the
    /// profile records too, and a caller may have put something of its own
    /// there. See [`DmStore::correspondences`] for why that is a skip rather
    /// than a refusal.
    fn from_dir_name(name: &std::ffi::OsStr) -> Option<Self> {
        let name = name.to_str()?;
        if name.len() != 2 * CORRESPONDENCE_LABEL_LEN
            || !name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0u8; CORRESPONDENCE_LABEL_LEN];
        hex::decode_to_slice(name, &mut bytes).ok()?;
        Some(Self(bytes))
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
    // No scope assertion here, deliberately. The scope is enforced at every
    // guard door by `RecordKind::require_scope`, which is a returned error and
    // therefore exists in the build that ships; an assertion here would add
    // nothing to that and would make the one thing worth proving untestable —
    // `a_record_sealed_in_one_scope_does_not_open_in_the_other` builds the
    // *wrong* AAD on purpose and shows the record refuses to open under it.
    let mut aad = Vec::with_capacity(domain::DM_STORE_AAD.len() + CORRESPONDENCE_LABEL_LEN + 32);
    aad.extend_from_slice(domain::DM_STORE_AAD);
    push_lp(&mut aad, label.as_bytes());
    push_lp(&mut aad, &[kind.aad_tag()]);
    aad
}

/// The AAD a **profile-level** record's seal binds: its own domain label, then
/// the record-kind tag, length-prefixed.
///
/// **One field, because there is only one to bind.** A profile record has no
/// correspondence — that is what makes it profile-level — so the label
/// [`seal_aad`] binds has no value here, and binding a placeholder would invent
/// a correspondence that does not exist. What replaces it is the separate domain
/// prefix: [`domain::DM_STORE_PROFILE_AAD`] rather than
/// [`domain::DM_STORE_AAD`], so the two constructions have fixed and different
/// field lists and neither can be parsed as the other.
///
/// The kind tag is still load-bearing and is shared with [`seal_aad`]'s space:
/// tags are unique across every kind in both scopes, so a second profile kind
/// can never open as this one.
fn profile_seal_aad(kind: RecordKind) -> Vec<u8> {
    // See `seal_aad` for why this deliberately does not assert the scope.
    let mut aad = Vec::with_capacity(domain::DM_STORE_PROFILE_AAD.len() + 8);
    aad.extend_from_slice(domain::DM_STORE_PROFILE_AAD);
    push_lp(&mut aad, &[kind.aad_tag()]);
    aad
}

/// The AAD for whichever scope `label` names: `Some` for a correspondence
/// record, `None` for a profile one.
///
/// One dispatch, used by the read and the write alike, so the two cannot come to
/// disagree about which construction a kind is sealed under — which would
/// present as every record of that kind failing to authenticate.
fn aad_for(label: Option<&CorrespondenceLabel>, kind: RecordKind) -> Vec<u8> {
    match label {
        Some(label) => seal_aad(label, kind),
        None => profile_seal_aad(kind),
    }
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

/// The root of a profile's DM records: one directory per correspondence with one
/// fixed-size file per correspondence record kind inside it, plus one
/// fixed-size file at the root per profile record kind.
///
/// Holds the derived seal key, so no call site ever passes one and no call site
/// can pass the wrong one.
pub struct DmStore {
    root: PathBuf,
    key: Aes256Key,
    /// Which thread holds a [`Locked`] or [`LockedProfile`] guard for which
    /// lock, right now.
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

    /// How many records this store has sealed. **Test builds only.**
    ///
    /// The module header's *"nothing anywhere counts the seals"* stays true of
    /// the shipped store; this exists so a test can assert a seal *budget*
    /// directly instead of inferring one from whether a record's bytes changed.
    ///
    /// Byte-identity is the tempting proxy and it is a weaker instrument for the
    /// same question. Every seal draws a fresh random nonce, so unchanged bytes
    /// do imply no seal happened — but only while the write path is the sole
    /// reason bytes could stay put. The moment a write is skipped for some
    /// unrelated reason the proxy passes for the wrong reason, and a write being
    /// skipped is precisely the change this counter is here to police.
    #[cfg(test)]
    seals: AtomicU64,
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
    /// **The correspondence sweep is not under any lock, and does not need to
    /// be.** It removes only names containing `TMP_INFIX`, and a live writer's
    /// sibling has a CSPRNG suffix no other process can predict; removing one
    /// under a concurrent writer would cost that writer its in-flight write,
    /// reported as [`AtomicReplaceError::NotLanded`] or `Indeterminate`, never a
    /// committed record. Two stores opening at once can only race to remove the
    /// same dead file, and a `NotFound` on removal is not an error.
    ///
    /// **The ROOT sweep is different and does take the lock, because that
    /// argument does not survive at the root.** A profile record's writer holds
    /// the profile lock across its whole read-modify-write, so an unlocked sweep
    /// can land between that writer's scrub-free `rename(2)` and its cleanup:
    /// scrub the temp file *after* the rename committed it and the live record
    /// is a zeroed inode that every later read reports as
    /// [`DmStoreError::ErasureInterrupted`]. That is a committed record lost,
    /// which is precisely what the paragraph above promises cannot happen — so
    /// the root branch runs inside [`Self::profile_critical_section`], where no
    /// writer can be mid-commit.
    ///
    /// **Opening a store never blocks on that lock and never fails because of
    /// it.** The profile housekeeping takes the lock with
    /// [`FileLock::try_acquire`] and skips its whole body when another holder
    /// has it; the holder is itself a store that has done, or is doing, exactly
    /// that work.
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
            #[cfg(test)]
            seals: AtomicU64::new(0),
        };
        store.sweep_orphans()?;
        store.tend_profile_records();
        Ok(store)
    }

    /// Sweep the root's own temp siblings and bring every profile-level record
    /// into existence, empty, if it is not already there — **best-effort, under
    /// the profile lock, and never able to stop a store opening.**
    ///
    /// **Why the record is created at open at all.** One created the first time
    /// someone blocks somebody would make its presence the answer to "does this
    /// user block anyone", readable from the disk with no key — the same class
    /// of leak the fixed size exists to close, and enough to make the fixed size
    /// pointless. Created for every profile, its existence reports only that a
    /// DM store was opened.
    ///
    /// **Returns nothing, and that is deliberate.** The sweep beside it
    /// ([`Self::sweep_orphans`]) already argues this case: a failure here must
    /// not make the whole store unopenable, because every correspondence read —
    /// none of which touches this record — would go with it. A read-only mount,
    /// a full disk or a lost permission would otherwise brick every profile that
    /// predates this record, on a path none of them asked for. What is lost by
    /// failing soft is bounded and lands where it can be seen:
    /// [`crate::dm::persist::DmPersist::read_block_list`] refuses a missing
    /// record loudly rather than reading it as "nobody is blocked".
    ///
    /// **The lock is taken with [`FileLock::try_acquire`], so `open` cannot
    /// hang.** [`Self::profile_critical_section`] blocks by design and is held
    /// across caller-supplied closures of unbounded duration; making a *startup*
    /// path wait on that would let one process inside `update_block_list` stall
    /// every other process's `open` with no timeout and no error — and, within
    /// one process, two `DmStore`s on one root have separate held-sets, so an
    /// `open` nested inside a profile section would block on the first fd's
    /// `flock` for ever (`flock(2)` does not pass on a second descriptor). When
    /// the lock is already held, this skips its whole body: the holder is
    /// itself a store that has done, or is doing, exactly this work.
    ///
    /// **The skip has one transient, and it fails closed.** A second opener can
    /// find the lock held in the window after the first takes it and before the
    /// record is written, and so returns with the record still absent. A read
    /// then refuses with `BlockListMissing` rather than reporting that nobody is
    /// blocked, and the next open retries because the presence check is re-run
    /// under the lock every time. The window is real; what it cannot do is
    /// unblock anyone.
    ///
    /// **The check and the write are both inside the lock.** Two opens racing
    /// would otherwise both find the record absent and both create it, and the
    /// loser's write would land on top of the winner's — no loss today, when the
    /// created value is always empty, and a silent reset of a real block list
    /// the moment anything else is ever created here.
    ///
    /// An empty payload is the empty record: it is padded and sealed like any
    /// other, so the file is its kind's full fixed size from the first open.
    fn tend_profile_records(&self) {
        let Ok(claim) = self.claim(LockScope::Profile) else {
            return;
        };
        let lock_path = self.root.join(LOCK_FILE_NAME);
        let Ok(Some(lock)) = FileLock::try_acquire(&lock_path) else {
            return;
        };
        let mut guard = LockedProfile {
            store: self,
            _lock: lock,
            _claim: claim,
        };

        // Inside the lock, so no profile writer can be between its `rename(2)`
        // and its cleanup while this scrubs.
        let _ = self.sweep_root_orphans();

        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Profile)
        {
            // Presence, not readability. A record that exists and will not open
            // is a record with something in it, and re-creating it here would
            // answer an unreadable block list by silently unblocking everybody —
            // at every start, on a path nobody asked to be destructive. It is
            // left exactly where it is, to fail loudly at the read that wants it.
            if matches!(guard.present(kind), Ok(false)) {
                let _ = guard.replace(kind, &[]);
            }
        }
    }

    /// Remove the root's own orphaned temp siblings, returning how many went.
    ///
    /// [`Self::sweep_orphans`]'s body for the one directory that also holds
    /// records: a profile record's target *is* the root, so
    /// `replace_atomically` leaves its sibling there and a sweep that only
    /// descended into correspondence directories would leave it for ever.
    ///
    /// **Called only from [`Self::tend_profile_records`], which holds the
    /// profile lock.** Unlocked it could scrub a temp file whose `rename(2)`
    /// has already committed it, turning a live record into a zeroed inode.
    fn sweep_root_orphans(&self) -> Result<usize, DmStoreError> {
        let mut removed = 0usize;
        let entries = std::fs::read_dir(&self.root).map_err(|e| DmStoreError::io(&self.root, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| DmStoreError::io(&self.root, e))?;
            // `read_dir`'s file type does not follow symlinks, so this is the
            // real type of the entry itself.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() || !is_temp_sibling(&entry.file_name()) {
                continue;
            }
            if !remove_orphan(&entry.path(), file_type) {
                continue;
            }
            removed += 1;
        }
        Ok(removed)
    }

    /// How many records this store has sealed since it was opened. **Test
    /// builds only** — see the `seals` field for why byte-identity is not an
    /// adequate substitute.
    #[cfg(test)]
    pub(crate) fn seal_count(&self) -> u64 {
        self.seals.load(Ordering::Relaxed)
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of `kind`'s record for `correspondence`. Derived, never
    /// supplied — the one place the two halves of a record's identity become a
    /// path, so [`Locked`] and the lock-free read cannot drift apart.
    fn record_path(&self, correspondence: &CorrespondenceLabel, kind: RecordKind) -> PathBuf {
        debug_assert_eq!(
            kind.scope(),
            RecordScope::Correspondence,
            "a profile record has no correspondence directory"
        );
        self.root
            .join(correspondence.dir_name())
            .join(kind.file_name())
    }

    /// The path of a profile-level record. Derived, never supplied, exactly as
    /// [`Self::record_path`] is — the difference is only that the profile is the
    /// whole of the record's identity, so the file sits at the root.
    ///
    /// **It cannot collide with a correspondence directory.** Those are named by
    /// [`CorrespondenceLabel::dir_name`], which is 64 lowercase hex characters
    /// and contains no `.`; every record file name ends `.bin`.
    fn profile_record_path(&self, kind: RecordKind) -> PathBuf {
        debug_assert_eq!(
            kind.scope(),
            RecordScope::Profile,
            "a correspondence record belongs in its correspondence's directory"
        );
        self.root.join(kind.file_name())
    }

    /// Seal `bytes` into `kind`'s bucket and replace the file at `path` with it.
    ///
    /// **The one write path, shared by both scopes**, so a profile record is
    /// padded to its fixed size, sealed under its own AAD and committed by
    /// `rename(2)` by exactly the code that does it for a correspondence
    /// record — not by a second implementation that would be free to drift on
    /// any of the three.
    ///
    /// It is private and takes a path, which is safe only because the two guards
    /// are the only callers and each derives that path from a kind it has
    /// already scoped. [`Locked::replace`] and [`LockedProfile::replace`] are the
    /// doors; there is still no way to spell a write outside a lock.
    fn write_record(
        &self,
        path: &Path,
        label: Option<&CorrespondenceLabel>,
        kind: RecordKind,
        bytes: &[u8],
    ) -> Result<(), DmStoreError> {
        let sealed = {
            let mut plain = pad_with_filler(kind, bytes)?;
            let aad = aad_for(label, kind);
            let outcome = seal_envelope(&self.key, &aad, &plain)
                .map_err(|e| DmStoreError::from_envelope(kind, e));
            plain.zeroize();
            let sealed = outcome?;
            // Counted after the seal succeeded, not before it is attempted: a
            // failure inside `seal_envelope` draws no nonce, so counting the
            // attempt would model a budget the failed call never spent.
            #[cfg(test)]
            self.seals.fetch_add(1, Ordering::Relaxed);
            sealed
        };

        debug_assert_eq!(
            sealed.len(),
            kind.on_disk_len(),
            "every record of a kind is one size on disk"
        );
        replace_atomically(path, &sealed).map_err(|source| DmStoreError::Write { kind, source })
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
    /// **Why no lock is needed.** `super::atomic_file::replace_atomically`
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
        kind.require_scope(RecordScope::Correspondence)?;
        self.read_record(
            &self.record_path(correspondence, kind),
            Some(correspondence),
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
        // Correspondence kinds only. A profile record lives at the root and
        // belongs to no correspondence, so asking after it here would report the
        // same answer for every label and would be a fact about the profile
        // wearing a correspondence's name.
        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Correspondence)
        {
            let path = self.record_path(correspondence, kind);
            match std::fs::metadata(&path) {
                Ok(_) => present.push(kind),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(DmStoreError::io(&path, e)),
            }
        }
        Ok(present)
    }

    /// Every correspondence established under this root, without taking a lock
    /// and without creating anything.
    ///
    /// The other axis of [`DmStore::present_unlocked`]: that call answers "which
    /// records does *this* correspondence hold", this one answers "which
    /// correspondences are there". Neither establishes anything, for
    /// [`DmStore::read_unlocked`]'s reason — asking must not answer itself into
    /// existence (#253).
    ///
    /// **What is a correspondence here is decided by the name, not by a list of
    /// things to skip.** The root also holds the profile lock and one file per
    /// profile-scoped [`RecordKind`] ([`RecordScope::Profile`]), and a
    /// skip-list naming them would have to be extended by hand every time a
    /// profile record is added — the failure being silent, since a missed name
    /// is reported as a correspondence rather than as an error. So the test runs
    /// the other way: an entry is a correspondence exactly when its name is
    /// `CorrespondenceLabel::from_dir_name`'s inverse of a label — de-linked
    /// because that reader is private, and it stays private: nothing outside
    /// this module turns a name back into a label — and it resolves to a
    /// directory. `no_profile_record_name_can_be_read_as_a_correspondence` pins
    /// the answer for every profile-scoped kind's file name and for the lock —
    /// **on length, which is all those names need**, so it is not what holds the
    /// character class. That belongs to
    /// `a_label_round_trips_through_its_directory_name`, whose upper-case case
    /// is the only one the class uniquely refuses (`hex::decode_to_slice` would
    /// accept it).
    ///
    /// **A missing root is an error, not an empty list.** A failing `read_dir`
    /// is propagated whole: "the store root is gone" and "this profile
    /// corresponds with nobody" have different remedies, and only one of them
    /// is answered by establishing a correspondence.
    ///
    /// **A directory here means the correspondence exists, not that it holds any
    /// record.** [`DmStore::critical_section`] establishes the directory by
    /// being entered, so one that was entered and wrote nothing is listed. A
    /// caller wanting only correspondences with a particular record asks
    /// [`DmStore::present_unlocked`] about each.
    ///
    /// **Sorted**, so two runs over one store agree. `read_dir` yields in
    /// whatever order the filesystem holds, and a caller that stops at the first
    /// match would otherwise be choosing by directory layout.
    ///
    /// Carries [`DmStore::present_unlocked`]'s caveat: the answer is not a
    /// snapshot, so a writer can establish or remove a correspondence between
    /// two calls.
    pub fn correspondences(&self) -> Result<Vec<CorrespondenceLabel>, DmStoreError> {
        let mut found = Vec::new();
        let entries = std::fs::read_dir(&self.root).map_err(|e| DmStoreError::io(&self.root, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| DmStoreError::io(&self.root, e))?;
            // The name first, so an entry that is not a label costs no syscall
            // — the profile records and the lock never reach the type check.
            let Some(label) = CorrespondenceLabel::from_dir_name(&entry.file_name()) else {
                continue;
            };
            let path = entry.path();
            // **Errors propagate; only a vanished entry is a skip.** `file_type`
            // is free only while the directory supplies `d_type`; where it does
            // not (`ftype=0` XFS, several FUSE and network filesystems) std
            // falls back to `lstat`, which can fail for reasons that are not
            // absence. Swallowing those would report an empty list for a store
            // full of correspondences, and the caller's remedy for "not there"
            // is to mint a second label for an identity that already has one —
            // the ambiguity this enumeration exists to let
            // `crate::dm::persist::DmPersist::correspondence_for_pk_lt` detect.
            // `Self::sweep_root_orphans` may skip, because a missed orphan
            // merely survives; here the direction of the failure is inverted.
            // `NotFound` alone is real absence, as in `Self::read_record`.
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(DmStoreError::io(&path, e)),
            };
            // **A symlink is followed here, unlike in `sweep_root_orphans`.**
            // That sweep must not follow one, because it deletes what it finds.
            // This must, because `Self::read_record` reads through
            // `std::fs::read`, which follows — so refusing here would make the
            // enumerator and the reader disagree about which correspondences
            // exist after an ordinary relocation (move the directory elsewhere,
            // symlink it back), and the lookup would answer absence for a record
            // it can read perfectly well.
            let is_dir = if file_type.is_symlink() {
                match std::fs::metadata(&path) {
                    Ok(meta) => meta.is_dir(),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(DmStoreError::io(&path, e)),
                }
            } else {
                file_type.is_dir()
            };
            if is_dir {
                found.push(label);
            }
        }
        found.sort_unstable();
        Ok(found)
    }

    /// The read both paths share: [`Locked::read`] under the lock, and
    /// [`DmStore::read_unlocked`] without it. See [`Locked::read`] for the error
    /// semantics.
    fn read_record(
        &self,
        path: &Path,
        label: Option<&CorrespondenceLabel>,
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

        // An erase that began and did not finish. Named rather than left to
        // fail as a seal-open error, so a power cut mid-`delete` cannot present
        // as a tampered record (#293).
        //
        // Through `erasure_sentinel`, which is also what the writer uses — the
        // two cannot drift, because there is only one of them.
        //
        // No legitimate record can match: every kind opens with a random nonce,
        // and a 32-byte prefix of a fixed string is not one.
        if raw.starts_with(erasure_sentinel(kind)) {
            return Err(DmStoreError::ErasureInterrupted { kind });
        }

        let aad = aad_for(label, kind);
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
            // Correspondence directories only. The root's own temp siblings
            // are swept by `sweep_root_orphans`, which runs under the profile
            // lock — this sweep is unlocked, and unlocked it could scrub a
            // profile record's sibling after the `rename(2)` that committed it.
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
                let Ok(file_type) = candidate.file_type() else {
                    continue;
                };
                if !remove_orphan(&candidate.path(), file_type) {
                    continue;
                }
                removed += 1;
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
        let claim = self
            .claim(LockScope::Correspondence(*correspondence))
            .map_err(E::from)?;

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

    /// Read one profile-level record **without taking the lock**.
    ///
    /// [`DmStore::read_unlocked`]'s call, one scope up, and lock-free for the
    /// same reason: the commit is `rename(2)`, so a reader sees the whole old
    /// record or the whole new one and a lock buys it nothing.
    ///
    /// **Its second reason does not apply here, and that is worth saying rather
    /// than inheriting.** A correspondence read avoids the lock partly because
    /// taking it *establishes* the correspondence on disk; the profile record is
    /// created by [`DmStore::open`] regardless, so there is nothing this call
    /// could bring into existence by asking. What remains is the plain one:
    /// asking whether an identity is blocked is a question with no write behind
    /// it, and it is asked on the doorbell and channel paths where serialising
    /// every reader behind an unrelated writer would be a real cost for no
    /// correctness.
    ///
    /// A caller that reads, decides and writes back **must** use
    /// [`DmStore::profile_critical_section`] instead.
    pub fn read_profile_unlocked(&self, kind: RecordKind) -> Result<Option<Vec<u8>>, DmStoreError> {
        kind.require_scope(RecordScope::Profile)?;
        self.read_record(&self.profile_record_path(kind), None, kind)
    }

    /// Run `f` holding the profile's exclusive lock for the whole of it.
    ///
    /// [`DmStore::critical_section`]'s contract, over the records that belong to
    /// the profile rather than to a correspondence: the closure is the point,
    /// the read and the write that follows from it are one critical section, and
    /// reentering it on the same thread is [`DmStoreError::Reentrant`] rather
    /// than a hang.
    ///
    /// **It establishes nothing.** The lock file sits at the store root, which
    /// [`DmStore::open`] has already created, so unlike a correspondence section
    /// entering this brings no new thing into existence and reveals nothing by
    /// having been entered.
    pub fn profile_critical_section<T, E>(
        &self,
        f: impl FnOnce(&mut LockedProfile<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<DmStoreError>,
    {
        // Claimed before the blocking acquire, for `critical_section`'s reason.
        let claim = self.claim(LockScope::Profile).map_err(E::from)?;
        let lock_path = self.root.join(LOCK_FILE_NAME);
        let lock = FileLock::acquire(&lock_path).map_err(|e| E::from(DmStoreError::Lock(e)))?;
        let mut locked = LockedProfile {
            store: self,
            _lock: lock,
            _claim: claim,
        };
        f(&mut locked)
    }

    /// Mark `scope` as held by the calling thread, or refuse if that thread
    /// already holds it.
    ///
    /// The returned guard releases the claim on drop, including on an unwind —
    /// a panicking closure that left the entry behind would convert a panic into
    /// a permanent lockout of that correspondence for the life of the thread.
    fn claim(&self, scope: LockScope) -> Result<ReentryClaim<'_>, DmStoreError> {
        let me = std::thread::current().id();
        let key = (me, scope);
        let mut held = lock_held_set(&self.held);
        // **The scope ordering: profile before correspondence.** Both closures
        // are caller-supplied, so a caller taking the two locks in one order
        // while another takes them in the other deadlocks across processes —
        // and a cross-process deadlock has nothing to convert it into an error,
        // because neither thread is waiting on a lock it holds itself. One
        // forbidden direction is enough to close the cycle, and this is the
        // direction nothing in the tree takes: a profile section may contain a
        // correspondence one, never the reverse.
        //
        // **The guarantee is per `DmStore` instance, not per root.** `held` is
        // this store's set, so a thread holding a correspondence lock through
        // one store and entering another store's profile section on the same
        // root is not refused here and blocks on the real `flock`. Two stores on
        // one root is already the caveat `open` carries above; this is the same
        // limit reached from the other side, and it is stated rather than
        // implied because the refusal above reads like a total guarantee.
        if scope == LockScope::Profile
            && held
                .iter()
                .any(|(t, s)| *t == me && matches!(s, LockScope::Correspondence(_)))
        {
            return Err(DmStoreError::Reentrant);
        }
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
type HeldSet = HashSet<(std::thread::ThreadId, LockScope)>;

/// Which lock a thread holds: one correspondence's, or the profile's.
///
/// **The profile lock is a peer of the correspondence locks, not a parent.** It
/// excludes writers of the profile records and nothing else, so a block-list
/// change and an outbox write proceed concurrently — which is correct, because
/// they share no file. Keeping both in one held-set is what makes the
/// reentrancy check total: a helper that took the profile lock from inside
/// another profile section would otherwise block on itself for ever, exactly as
/// a nested correspondence section would.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum LockScope {
    Profile,
    Correspondence(CorrespondenceLabel),
}

fn lock_held_set(held: &Mutex<HeldSet>) -> std::sync::MutexGuard<'_, HeldSet> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

/// One thread's claim on one correspondence label, released on drop.
struct ReentryClaim<'a> {
    held: &'a Mutex<HeldSet>,
    key: (std::thread::ThreadId, LockScope),
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
        kind.require_scope(RecordScope::Correspondence)?;
        self.store
            .read_record(&self.path(kind), Some(&self.label), kind)
    }

    /// Replace `kind`'s record with `bytes`, padded to the kind's fixed size and
    /// sealed.
    ///
    /// Refuses a payload larger than [`RecordKind::capacity`] with
    /// [`DmStoreError::PayloadTooLong`] rather than truncating: a truncated
    /// record is a record that opens, parses to something shorter than it was,
    /// and is wrong in a way nothing downstream can detect.
    ///
    /// A payload *shorter* than the capacity is padded and recovered exactly,
    /// [`RecordKind::ReceiveCursor`] included — it was the one kind that had to
    /// be handed exactly its width, because unsealed it had nowhere to record
    /// that it had been padded (#389). What still requires the cursor to be
    /// eight bytes is [`crate::dm::persist`], which is the module that supplies
    /// the payload and the only one that decodes it.
    ///
    /// On error the destination is in the state
    /// [`DmStoreError::Write`]'s inner [`AtomicReplaceError`] names — untouched,
    /// unknown, or already holding the new bytes but not durably. That
    /// distinction is preserved rather than flattened precisely because a
    /// commit-then-emit caller has to act on it.
    pub fn replace(&mut self, kind: RecordKind, bytes: &[u8]) -> Result<(), DmStoreError> {
        kind.require_scope(RecordScope::Correspondence)?;
        self.store
            .write_record(&self.path(kind), Some(&self.label), kind, bytes)
    }

    /// Delete `kind`'s record, and make the deletion durable.
    ///
    /// Deleting a record that is not there is `Ok(())`: the postcondition is
    /// "this record does not exist", and it already holds.
    ///
    /// **The record is scrubbed before it is unlinked** (#293). Unlinking alone
    /// leaves the record's blocks unreferenced but intact, so an adversary who
    /// reads unallocated blocks and later obtains the profile key recovers the
    /// sealed record and opens it — for the provisional record that is `ss0`,
    /// which roots `RK0` and reopens the early chain. Every kind is scrubbed,
    /// not only that one: the resume record holds A9.2's key material under the
    /// same later-compromise threat.
    ///
    /// Two phases, and the order is the point. An erasure sentinel is written
    /// and **fsynced first**, so a crash from that moment on leaves something a
    /// reader can identify as an interrupted erase
    /// ([`DmStoreError::ErasureInterrupted`]) rather than as a truncated or
    /// tampered record. The body is then overwritten and fsynced, and only then
    /// is the name unlinked and the directory fsynced.
    ///
    /// **The fsync between the scrub and the unlink is load-bearing, not
    /// hygiene.** Without it the overwrite may still be dirty page cache when
    /// the name goes away, and a filesystem is free to never write those blocks
    /// at all — the scrub would be a no-op that looked like a fix.
    ///
    /// **The ceiling, stated honestly.** On an SSD the FTL remaps an overwrite
    /// to a fresh erase block, and a copy-on-write filesystem writes a new
    /// extent by design; in both cases the original blocks survive untouched.
    /// This buys real erasure on ext4-over-LUKS on rotating or dm-mapped
    /// storage and buys nothing against an adversary with the raw flash. It is
    /// best-effort by construction and no caller should read it as a guarantee.
    ///
    /// Deleting a record that is not there is `Ok(())`: the postcondition is
    /// "this record does not exist", and it already holds.
    pub fn delete(&mut self, kind: RecordKind) -> Result<(), DmStoreError> {
        // Before anything, and not as a `debug_assert`: a profile kind here
        // would derive a path that does not exist, find nothing to scrub, and
        // return `Ok(())` — a delete that reports success having deleted
        // nothing, which for an erasure path is the worst available answer.
        kind.require_scope(RecordScope::Correspondence)?;
        let path = self.path(kind);

        // Phase 1 + 2: scrub. A record that vanished between the caller's last
        // look and here is not an error — the postcondition already holds.
        match std::fs::OpenOptions::new().write(true).open(&path) {
            Ok(file) => scrub_in_place(&file, &path, kind)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            // A record whose mode lost owner-write cannot be scrubbed, and this
            // stays FAIL-CLOSED: erasing the record is the forward-secrecy premise
            // — for the provisional record it is `ss0`, which roots `RK0` — so a
            // delete that reported success while leaving the secret on disk would
            // be the worst possible answer. The orphan sweep's fail-soft is not the
            // precedent for this one; it removes temp files, not secrets.
            //
            // What was wrong was narrower than the refusal. The design reasoned
            // about *transient* faults, and `EACCES` on a read-only record is
            // permanent: every retry takes the same branch, so
            // `PendingHandshake::establish` — which builds the ratchet AND deletes
            // — wedges that correspondence for ever, reporting a generic I/O error
            // indistinguishable from a slow disk.
            //
            // So: one repair attempt, then a loud, distinct failure. Restoring
            // owner-write is the whole repair — the file is ours and the mode is
            // the only thing in the way — and if the retry still fails, the caller
            // gets a variant that names the condition and carries the trust event
            // it must be surfaced as, rather than a generic error it will retry
            // against for ever.
            Err(e) if is_permanent_write_refusal(&e) => {
                match repair_owner_write(&path) {
                    Ok(()) => match std::fs::OpenOptions::new().write(true).open(&path) {
                        Ok(file) => scrub_in_place(&file, &path, kind)?,
                        Err(again) if again.kind() == std::io::ErrorKind::NotFound => {
                            return Ok(());
                        }
                        // Only a still-permanent refusal is the wedge. A transient
                        // fault on the retry — EIO, EMFILE, EINTR — is an ordinary
                        // error and must stay retryable, or the repair would convert
                        // a bad second into a state that "recurs at every start until
                        // a human clears it". That is the mirror of the bug being
                        // fixed here and would be no better.
                        Err(again) if is_permanent_write_refusal(&again) => {
                            return Err(DmStoreError::ErasureBlocked {
                                kind,
                                scrubbed: false,
                                source: again,
                            });
                        }
                        Err(again) => return Err(DmStoreError::io(&path, again)),
                    },
                    Err(_) => {
                        return Err(DmStoreError::ErasureBlocked {
                            kind,
                            scrubbed: false,
                            source: e,
                        });
                    }
                }
            }
            Err(e) => return Err(DmStoreError::io(&path, e)),
        }

        // Phase 3: unlink, then make the removal itself durable.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // The same permanent class as the open above, one step later and with
            // a different cause: unlinking needs write on the *directory*, which no
            // repair of the file's own mode reaches. Found by this change's own
            // probe — the first version covered only the open, and a read-only
            // parent directory wedged exactly as before while looking retryable.
            //
            // The consequence is milder and the variant's doc says so: the scrub
            // has already run, so the secret is gone and only an empty record
            // lingers. Forward secrecy is intact; what is not is the caller's
            // ability to make progress, and that is what the loud variant restores.
            Err(e) if is_permanent_write_refusal(&e) => {
                return Err(DmStoreError::ErasureBlocked {
                    kind,
                    scrubbed: true,
                    source: e,
                });
            }
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

/// The profile's own records, with the profile lock held.
///
/// [`Locked`]'s counterpart for the records that belong to no correspondence.
/// It is a separate type rather than a flag on [`Locked`] because the two differ
/// in what they can name: everything reachable from here derives its path from a
/// [`RecordKind`] alone, with no label to supply or to get wrong.
///
/// **There is no `delete` door, and this is the pin for that.** A profile record
/// is created by every [`DmStore::open`] precisely so its presence carries no
/// information; a door that removed one would put that information back.
///
/// ```compile_fail
/// use daemonseed_core::storage::dm_store::{DmStore, DmStoreError, RecordKind};
/// fn no_such_door(store: &DmStore) {
///     let _ = store.profile_critical_section::<_, DmStoreError>(|guard| {
///         guard.delete(RecordKind::BlockList)
///     });
/// }
/// ```
///
/// **That is not the same as the mismatch being unrepresentable, and it was
/// described here as though it were.** [`RecordKind`] is one `pub` enum spanning
/// both scopes, so a caller can hand either guard a kind belonging to the other;
/// every door on both guards refuses it with [`DmStoreError::WrongScope`]. What
/// the split buys is that the *label* cannot be wrong, not that the kind cannot
/// be.
pub struct LockedProfile<'a> {
    store: &'a DmStore,
    /// Declared before [`Self::_claim`], for [`Locked`]'s drop-order reason.
    _lock: FileLock,
    _claim: ReentryClaim<'a>,
}

impl core::fmt::Debug for LockedProfile<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedProfile")
            .field("root", &self.store.root)
            .finish()
    }
}

impl LockedProfile<'_> {
    /// Read `kind`'s record, or `Ok(None)` if it does not exist.
    ///
    /// [`Locked::read`]'s semantics exactly, including that absence is not an
    /// error and that a wrong-sized file is [`DmStoreError::WrongFileLen`] while
    /// a right-sized one that does not authenticate is
    /// [`DmStoreError::NotAuthentic`].
    pub fn read(&self, kind: RecordKind) -> Result<Option<Vec<u8>>, DmStoreError> {
        kind.require_scope(RecordScope::Profile)?;
        self.store
            .read_record(&self.store.profile_record_path(kind), None, kind)
    }

    /// Whether `kind`'s record exists, without opening it.
    ///
    /// The distinction from [`Self::read`] returning `Some` is the whole reason
    /// this exists: a record that is present and unreadable must not be mistaken
    /// for an absent one by anything that would react by creating a fresh empty
    /// one over the top.
    pub fn present(&self, kind: RecordKind) -> Result<bool, DmStoreError> {
        kind.require_scope(RecordScope::Profile)?;
        let path = self.store.profile_record_path(kind);
        match std::fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(DmStoreError::io(&path, e)),
        }
    }

    /// Replace `kind`'s record with `bytes`, padded to the kind's fixed size and
    /// sealed.
    ///
    /// [`Locked::replace`]'s body, reached through the same private write path,
    /// so the padding, the seal and the atomic commit are one implementation
    /// across both scopes. Refuses an over-long payload with
    /// [`DmStoreError::PayloadTooLong`] rather than truncating.
    ///
    /// **There is deliberately no `delete`.** A profile record is created by
    /// every [`DmStore::open`] precisely so that its presence carries no
    /// information; a door that removes one would put that information back, and
    /// nothing needs it — an empty block list is written as an empty payload,
    /// which is a value rather than an absence. The erasure machinery is still
    /// inherited on the read side: [`DmStoreError::ErasureInterrupted`] is
    /// recognised here as for any other kind, so a future delete cannot land
    /// without it.
    pub fn replace(&mut self, kind: RecordKind, bytes: &[u8]) -> Result<(), DmStoreError> {
        kind.require_scope(RecordScope::Profile)?;
        let path = self.store.profile_record_path(kind);
        self.store.write_record(&path, None, kind, bytes)
    }
}

/// Whether an I/O error is a write refusal that will still be there next time.
///
/// **The distinction the whole repair rests on.** A permanent refusal wedges the
/// correspondence and must be reported as its own condition; a transient one is an
/// ordinary error a caller should retry. Getting the set wrong is harmful in both
/// directions — too narrow and a permanent fault keeps looking retryable (a
/// read-only mount was missed exactly this way, because EROFS is
/// `ReadOnlyFilesystem` and not `PermissionDenied`), too wide and a bad second
/// becomes a trust event that recurs at every start until a human clears it.
///
/// `PermissionDenied` covers both EACCES and EPERM, so a lost mode bit, an
/// immutable attribute and a missing search bit on the parent all land here.
fn is_permanent_write_refusal(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
    )
}

/// Restore owner-write on a record whose mode lost it, so it can be scrubbed.
///
/// **One attempt, and only the mode.** The file is ours — it lives under the
/// profile directory this process owns — so a lost owner-write bit is the entire
/// class of permission fault this can fix, and fixing it is what turns a permanent
/// wedge back into an ordinary delete. Anything else denying the open (an immutable
/// attribute, a read-only mount, a MAC policy) is outside what a mode change
/// reaches, and the caller reports it rather than looping.
///
/// The existing permissions are read and only the owner-write bit is added, so a
/// deliberately restrictive mode is not widened beyond what the scrub needs — this
/// never makes a record more readable than it was.
#[cfg(unix)]
fn repair_owner_write(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    let mode = perms.mode();
    perms.set_mode(mode | 0o200);
    std::fs::set_permissions(path, perms)
}

/// Non-unix builds have no mode bit to restore, so the repair is a no-op that
/// reports failure — the caller then returns the same loud, distinct error it
/// would have on a failed repair, rather than pretending it tried something.
#[cfg(not(unix))]
fn repair_owner_write(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no owner-write repair on this platform",
    ))
}

/// Overwrite `file`'s whole length in two fsynced phases: sentinel, then body.
///
/// Split because the phases answer different questions. Phase 1 makes an
/// interrupted erase *nameable* — after its barrier, any crash leaves the
/// sentinel on the medium, so a reader reports [`DmStoreError::ErasureInterrupted`]
/// instead of a corrupt record. Phase 2 destroys the payload. Collapsing them
/// into one write would leave a torn write looking like tampering, which is the
/// state phase 1 exists to prevent.
///
/// Both barriers are real fsyncs through [`Durability`], not `flush` — a flush
/// pushes bytes to the kernel and stops there, and the unlink that follows would
/// be free to discard them still-dirty.
///
/// **The sentinel is bounded by the record's own length**, so a kind shorter than
/// the 32-byte sentinel cannot be *grown* by its own erase: phase 2's loop would
/// never be entered and a reader would report [`DmStoreError::WrongFileLen`] —
/// precisely the truncation shape the sentinel exists to displace. No current
/// kind is that short ([`RecordKind::ReceiveCursor`] was, until #389 sealed it),
/// so the bound is unobservable through any kind and is pinned instead at
/// [`sentinel_for_width`], which takes the width as an argument for that reason.
/// Both this function and [`DmStore::read_record`] reach it through
/// [`erasure_sentinel`], so the writer and the reader cannot disagree about it.
///
/// **The overwrite covers the file's real length, never only its declared one.**
/// A file longer than its kind is refused on read, but it can exist on disk — and
/// bounding the loop by `on_disk_len` alone would leave that tail unscrubbed,
/// which is the one outcome this function exists to prevent.
fn scrub_in_place(file: &std::fs::File, path: &Path, kind: RecordKind) -> Result<(), DmStoreError> {
    use std::io::{Seek, SeekFrom, Write};

    let io = |e: std::io::Error| DmStoreError::io(path, e);

    let declared = kind.on_disk_len();
    let actual = file.metadata().map_err(io)?.len();
    let len = (declared as u64).max(actual);

    // Phase 1 — the sentinel, made durable before anything else changes.
    let sentinel = erasure_sentinel(kind);
    let mut f = file;
    f.seek(SeekFrom::Start(0)).map_err(io)?;
    f.write_all(sentinel).map_err(io)?;
    RealDurability.sync_file(file).map_err(io)?;

    // Phase 2 — the rest of the record.
    zero_from(file, sentinel.len() as u64, len).map_err(io)?;
    RealDurability.sync_file(file).map_err(io)?;
    Ok(())
}

/// Overwrite `[from, len)` with zeros, in bounded chunks so a large bucket (the
/// outbox is the biggest) does not allocate a second copy of itself.
fn zero_from(mut f: &std::fs::File, from: u64, len: u64) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    const CHUNK: usize = 8 * 1024;
    let zeros = [0u8; CHUNK];
    f.seek(SeekFrom::Start(from))?;
    let mut written = from;
    while written < len {
        let n = (CHUNK as u64).min(len - written);
        f.write_all(&zeros[..n as usize])?;
        written += n;
    }
    Ok(())
}

/// Overwrite an orphaned temp sibling before it is unlinked.
///
/// A crashed [`super::atomic_file`] write leaves behind whatever had reached the
/// file when the process died — which may be the **whole sealed record**, since
/// the kill can land after `write_all` and before the barrier. So unlinking a
/// sibling unscrubbed reopens precisely the exposure [`Locked::delete`] exists to
/// close, by a path that never passes through `delete` at all. The overwrite is
/// bounded by the file's actual length rather than any kind's declared one, so a
/// partial sibling is handled by the same code without a special case.
///
/// No sentinel is written. A sentinel exists to make an interrupted erase
/// *nameable* to a reader, and nothing ever reads a temp sibling as a record:
/// [`Locked::present`] derives the names it looks for rather than listing the
/// directory. There is no state here to name, only bytes to destroy.
/// Scrub and unlink one orphaned temp sibling; report whether it went.
///
/// **One body for both sweeps.** The root branch and the per-correspondence
/// branch had begun to state the same policy twice, and two copies of a policy
/// are a policy that will disagree with itself.
///
/// **A symlink is skipped and never opened.** `read_dir`'s file type does not
/// follow links, so this sees the entry's own type: a co-resident attacker who
/// drops `x.tmp.y` at the root pointing anywhere writable would otherwise have
/// that target opened for writing, zeroed and unlinked by the next `open`. The
/// root is the reachable half — it exists before any correspondence does — but
/// the check belongs to both, and [`FileLock::acquire`] already refuses a
/// symlinked lock path for the same reason.
///
/// **Everything else is fail-soft, and that is deliberate.** The sweeps run
/// inside [`DmStore::open`], so an error would make the whole store unopenable:
/// a mode-0444 sibling, or a directory whose name happens to match, would brick
/// it permanently for every correspondence. Skipping leaves the file exactly
/// where it already was, unscrubbed — the state before the sweep existed.
///
/// Scrubbed **before** it is unlinked, for the reason [`Locked::delete`] scrubs:
/// the sibling may hold a whole sealed record, so unlinking it bare leaves
/// recoverable ciphertext in unallocated blocks. Unlinking without scrubbing is
/// the one option worse than both, since it launders the ciphertext out of reach
/// while reporting success.
fn remove_orphan(path: &Path, file_type: std::fs::FileType) -> bool {
    if file_type.is_symlink() || file_type.is_dir() {
        return false;
    }
    if scrub_orphan(path).is_err() {
        return false;
    }
    match std::fs::remove_file(path) {
        Ok(()) => true,
        // Another store's sweep won the race; the file is gone either way,
        // which is all this cares about.
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

fn scrub_orphan(path: &Path) -> Result<(), DmStoreError> {
    let io = |e: std::io::Error| DmStoreError::io(path, e);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(io)?;
    let len = file.metadata().map_err(io)?.len();
    zero_from(&file, 0, len).map_err(io)?;
    RealDurability.sync_file(&file).map_err(io)
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

    /// A critical section was requested that the calling thread would block on
    /// for ever. Nothing was read or written.
    ///
    /// **Two shapes, both deadlocks, both refused here.** The same lock again —
    /// a correspondence, or the profile, that this thread already holds. And the
    /// profile lock while holding a correspondence one: that is the forbidden
    /// half of the scope ordering (profile before correspondence), refused
    /// because a caller taking the two in one order while another takes them in
    /// the other deadlocks across processes, where nothing can convert it into
    /// an error.
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

    /// A record kind was asked for through the guard of the other scope.
    ///
    /// **Refused rather than served, because both wrong answers are silent.** A
    /// profile kind reached through [`Locked`] would write
    /// `<root>/<label>/block-list.bin` sealed under the *correspondence* AAD —
    /// a second, per-correspondence block list that
    /// [`DmStore::read_profile_unlocked`] can never see, so a block would appear
    /// to be taken and would suppress nothing. A correspondence kind reached
    /// through [`LockedProfile`] would put that record at the store root under
    /// the profile AAD, where nothing that reads a correspondence's records
    /// looks and where the file name says which kind it is.
    /// Neither is reachable through any in-tree caller; both are reachable
    /// through the public guards, which is exactly when a `debug_assert` is the
    /// wrong instrument — it is compiled out of the build that ships.
    WrongScope {
        kind: RecordKind,
        /// The scope the guard that was asked serves.
        guard: RecordScope,
    },

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
    /// The record carries the erasure sentinel: a [`Locked::delete`] began and
    /// was interrupted before the unlink (#293).
    ///
    /// **Its own variant because the remedy and the story differ.** The record
    /// is gone for practical purposes — its payload is scrubbed or being
    /// scrubbed — but it is gone *because this daemon deleted it*, not because
    /// anything tampered with it. Folding this into the seal-open failure would
    /// report a power cut as a possible attack, and a user who is told that
    /// once too often stops believing it when it is true.
    ErasureInterrupted { kind: RecordKind },

    /// The record could not be opened for writing, so it could not be scrubbed,
    /// and a repair of its mode did not help.
    ///
    /// **Its own variant because the condition is PERMANENT and a generic I/O
    /// error is not.** Every other write failure here is something a caller may
    /// sensibly retry; this one takes the same branch every time. A correspondence
    /// whose record cannot be erased cannot complete `establish` — which builds the
    /// ratchet *and* deletes — so it wedges silently, and reported as
    /// [`DmStoreError::Io`] it is indistinguishable from a slow disk that will
    /// eventually come good.
    ///
    /// **The refusal itself is correct and is not what this variant changes.**
    /// Erasing the record is the forward-secrecy premise; a delete that reported
    /// success while leaving the secret readable would be worse than any error.
    /// What this adds is that the failure is *nameable*: see [`Self::event`] for
    /// the trust event it must be surfaced as.
    ///
    /// **Two causes, and they differ in how much is at stake.** If the *record*
    /// would not open, nothing was scrubbed and the sealed secret is still on
    /// disk. If the record scrubbed but its *directory* refused the unlink, the
    /// secret is already gone and only an empty file remains — forward secrecy
    /// holds, and what is blocked is only the caller's progress. Both are reported
    /// the same way because both wedge the correspondence permanently, and the
    /// remedy is the same human act.
    ErasureBlocked {
        kind: RecordKind,
        /// Whether the record's payload was successfully overwritten before the
        /// failure. **This is a disclosure fact, not a detail:** `false` means the
        /// sealed secret is still readable on disk, `true` means it is already gone
        /// and only an empty file could not be unlinked. Reporting the second as
        /// the first would tell an operator a secret is exposed when it is not.
        scrubbed: bool,
        source: std::io::Error,
    },

    /// The payload is larger than the kind's bucket. Refused rather than
    /// truncated.
    PayloadTooLong {
        kind: RecordKind,
        capacity: usize,
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
            // The path embeds the correspondence's hex directory name, so
            // rendering it here would undo [`CorrespondenceLabel`]'s `Debug`
            // redaction by the back door: an I/O error reaching a log line, a
            // crash report or a GUI toast would carry a stable
            // per-correspondence identifier. Name the file within the
            // correspondence — which is one of four fixed names and identifies
            // nobody — and drop the directory.
            DmStoreError::Io { path, source } => {
                let leaf = path
                    .file_name()
                    .map_or_else(|| "<unnamed>".into(), |n| n.to_string_lossy());
                write!(f, "dm store I/O failed on {leaf}: {source}")
            }
            DmStoreError::Lock(e) => write!(f, "dm store lock: {e}"),
            DmStoreError::Reentrant => write!(
                f,
                "this thread already holds a critical section that the requested one would \
                 block on for ever"
            ),
            DmStoreError::WrongScope { kind, guard } => write!(
                f,
                "the {kind:?} record is {:?}-scoped and was asked for through a {guard:?} guard",
                kind.scope()
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
            DmStoreError::ErasureBlocked {
                kind,
                scrubbed: false,
                source,
            } => write!(
                f,
                "the {kind:?} record could not be opened for writing, so it could \
                 not be erased, and restoring owner-write did not help ({source}); \
                 the record still holds its sealed contents and this correspondence \
                 cannot proceed until that is fixed"
            ),
            DmStoreError::ErasureBlocked {
                kind,
                scrubbed: true,
                source,
            } => write!(
                f,
                "the {kind:?} record was erased but could not be removed ({source}); \
                 its contents are already overwritten, so nothing sealed remains \
                 readable, but the empty record cannot be unlinked and this \
                 correspondence cannot proceed until that is fixed"
            ),
            DmStoreError::ErasureInterrupted { kind } => write!(
                f,
                "the {kind:?} record was being erased and the erase did not \
                 finish; its contents are gone, and this is a deletion that was \
                 cut short, not a tampered record"
            ),
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

impl DmStoreError {
    /// The trust event this failure must be surfaced as, if any.
    ///
    /// Same shape as `dm::provisional::Teardown::event`, and for the same reason:
    /// a returned value a caller could ignore would not be a fix, while a classed
    /// event it is forbidden to down-class is. Only the permanent conditions get
    /// one — a retryable I/O error is not a trust event, it is a bad minute.
    ///
    /// [`Self::ErasureBlocked`] is
    /// [`PersistentNonBlocking`](crate::trust_events::TrustEventClass::PersistentNonBlocking):
    /// it recurs at every start until a human fixes the record's mode, and it is
    /// written to the audit log, because a correspondence that silently never
    /// establishes is the failure this exists to make visible.
    ///
    /// **It carries the [`RecordKind`], and that is what the scope type is
    /// for.** One key fires for every kind and they do not cost the same:
    /// a blocked [`RecordKind::Provisional`] erasure leaves `ss0` readable,
    /// which roots `RK0` — the forward-secrecy premise the fail-closed delete
    /// exists to protect — while [`RecordKind::ReceiveCursor`] holds one page
    /// number and no key material at all. Returning the key
    /// alone told a user their record would not erase and left them unable to
    /// tell those two apart. The kind is a closed-set discriminant naming a
    /// *type* of record, never an instance, so it says nothing about who the
    /// correspondence is with (ISC-C28 / ISC-A-C1).
    pub fn event(&self) -> Option<crate::trust_events::TrustEventScope> {
        match self {
            Self::ErasureBlocked { kind, .. } => {
                Some(crate::trust_events::TrustEventScope::for_record(
                    crate::trust_events::TrustEventKey::DmRecordErasureBlocked,
                    *kind,
                ))
            }
            _ => None,
        }
    }
}

impl core::error::Error for DmStoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            DmStoreError::Io { source, .. } => Some(source),
            DmStoreError::Lock(e) => Some(e),
            DmStoreError::Write { source, .. } => Some(source),
            DmStoreError::ErasureBlocked { source, .. } => Some(source),
            // `getrandom::Error` only implements `Error` under getrandom's `std`
            // feature, which this build does not enable, so the cause is carried
            // in `Display` rather than dropped.
            DmStoreError::EntropySource(_)
            | DmStoreError::Reentrant
            | DmStoreError::WrongScope { .. }
            | DmStoreError::Kdf
            | DmStoreError::Module
            | DmStoreError::NotAuthentic { .. }
            | DmStoreError::ErasureInterrupted { .. }
            | DmStoreError::WrongFileLen { .. }
            | DmStoreError::PayloadTooLong { .. }
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

    /// Every name at the store root, split into directories and files.
    ///
    /// **Both halves are asserted, and asserting only the directories was a real
    /// weakening.** The count this replaced (`read_dir(root).count() == 0`)
    /// caught anything appearing at the root at all — including a profile-record
    /// creation that lost its scope filter and wrote `resume.bin`, `outbox.bin`
    /// and a plaintext `cursor.bin` there on every open. Counting directories
    /// alone makes every one of those invisible.
    fn root_entries(root: &Path) -> (Vec<String>, Vec<String>) {
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().unwrap().is_dir() {
                dirs.push(name);
            } else {
                files.push(name);
            }
        }
        dirs.sort();
        files.sort();
        (dirs, files)
    }

    /// The exact set of files a store's root holds when no correspondence has
    /// been established: the profile lock, and one record per profile kind.
    fn expected_root_files() -> Vec<String> {
        let mut files = vec![LOCK_FILE_NAME.to_string()];
        files.extend(
            RecordKind::ALL
                .into_iter()
                .filter(|k| k.scope() == RecordScope::Profile)
                .map(|k| k.file_name().to_string()),
        );
        files.sort();
        files
    }

    fn store(dir: &Path) -> DmStore {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        DmStore::open(dir.join("dm"), &AT_REST).unwrap()
    }

    /// A mint that never wrote to the buffer returns all-zeros and every other
    /// property here still holds for it — distinctness would fail, but only
    /// after two calls, and a partial fill (a short read into a zeroed tail)
    /// would pass distinctness outright. This is the probe for "the CSPRNG
    /// actually filled all 32 bytes".
    #[test]
    fn a_minted_label_is_not_the_zero_label_nor_zero_tailed() {
        let l = CorrespondenceLabel::mint().unwrap();
        assert_ne!(
            l.as_bytes(),
            &[0u8; CORRESPONDENCE_LABEL_LEN],
            "mint returned an unfilled buffer"
        );
        // A short fill leaves a zeroed tail that whole-value distinctness cannot
        // see. Every 8-byte window carrying at least one non-zero byte is a
        // ~2^-64 false alarm per window and catches a truncated fill.
        for (i, window) in l.as_bytes().chunks(8).enumerate() {
            assert!(
                window.iter().any(|&b| b != 0),
                "byte window {i} is all-zero — the fill looks truncated"
            );
        }
    }

    #[test]
    fn minted_labels_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            assert!(
                seen.insert(*CorrespondenceLabel::mint().unwrap().as_bytes()),
                "mint produced a duplicate within 256 draws"
            );
        }
        assert_eq!(seen.len(), 256, "the probe itself collected nothing");
    }

    /// A counter derives a *different* value every draw and at every byte
    /// position, so it survives distinctness, the zero-tail probe and the
    /// per-position variance probe — measured, not assumed. What it cannot hide
    /// is that its output is an affine function of a monotone counter: the
    /// byte-wise difference between successive draws is the *same* difference
    /// every time. Real CSPRNG output has no such invariant.
    ///
    /// This kills the whole affine-of-a-counter class, not one hand-picked
    /// mutation. It is still not proof of randomness — no unit test is; a mint
    /// seeded from a low-entropy source would pass everything here. That
    /// guarantee rests on `mint`'s body being one auditable call to
    /// `getrandom::fill` over the whole buffer, and these probes exist to keep
    /// it that way.
    #[test]
    fn successive_minted_labels_do_not_differ_by_a_fixed_step() {
        let draws: Vec<_> = (0..4)
            .map(|_| *CorrespondenceLabel::mint().unwrap().as_bytes())
            .collect();
        assert_eq!(draws.len(), 4, "the probe itself collected nothing");

        let delta = |a: &[u8; CORRESPONDENCE_LABEL_LEN], b: &[u8; CORRESPONDENCE_LABEL_LEN]| {
            let mut d = [0u8; CORRESPONDENCE_LABEL_LEN];
            for i in 0..CORRESPONDENCE_LABEL_LEN {
                d[i] = b[i].wrapping_sub(a[i]);
            }
            d
        };
        let d0 = delta(&draws[0], &draws[1]);
        let d1 = delta(&draws[1], &draws[2]);
        let d2 = delta(&draws[2], &draws[3]);
        assert!(
            !(d0 == d1 && d1 == d2),
            "three successive draws differ by an identical byte-wise step — \
             mint looks like a counter, not a CSPRNG"
        );
    }

    /// The label's whole job on disk is to be a directory name, so pin the shape
    /// that reaches the filesystem rather than only the bytes behind it.
    #[test]
    fn a_minted_labels_dir_name_is_64_lowercase_hex_chars() {
        let name = CorrespondenceLabel::mint().unwrap().dir_name();
        assert_eq!(name.len(), CORRESPONDENCE_LABEL_LEN * 2);
        assert!(
            name.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "dir name is not lowercase hex: {name}"
        );
    }

    /// Distinctness and a non-zero tail are satisfied by things that are not
    /// random — measured, not assumed: a mint of 4 CSPRNG bytes followed by 28
    /// constant ones passes both. It dies here, because a constant filler pins
    /// its byte positions across draws.
    ///
    /// With 32 draws a truly random position repeats one value throughout with
    /// probability 256 * (1/256)^32, which is nil; the assertion is effectively
    /// flake-free while still catching any position that never varies.
    ///
    /// **This does not establish randomness** — see
    /// `successive_minted_labels_do_not_differ_by_a_fixed_step` for the counter
    /// case, which varies at every position and survives this one.
    #[test]
    fn every_byte_position_of_a_minted_label_varies_across_draws() {
        const DRAWS: usize = 32;
        let labels: Vec<_> = (0..DRAWS)
            .map(|_| *CorrespondenceLabel::mint().unwrap().as_bytes())
            .collect();
        assert_eq!(labels.len(), DRAWS, "the probe itself collected nothing");

        for pos in 0..CORRESPONDENCE_LABEL_LEN {
            let first = labels[0][pos];
            assert!(
                labels.iter().any(|l| l[pos] != first),
                "byte position {pos} held {first:#04x} across all {DRAWS} draws — \
                 that position is not random"
            );
        }
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
                | RecordKind::ReceiveCursor
                | RecordKind::ContactCache
                | RecordKind::BlockList => {}
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
        assert_eq!(PROVISIONAL_RECORD_LEN, 12_301, "the sealed record's size");
        assert_eq!(RecordKind::Resume.capacity(), 65_536);
        assert_eq!(RecordKind::Outbox.capacity(), 2_097_152);
        assert_eq!(RecordKind::ReceiveCursor.capacity(), 8);
        // The contact record's size is the module's, not a copy of it.
        assert_eq!(RecordKind::ContactCache.capacity(), CONTACT_RECORD_LEN);
        assert_eq!(
            CONTACT_RECORD_LEN, 5234,
            "the encoded contact record's size"
        );
        // The ratified 512-identity ceiling, in bytes, and its arithmetic
        // written out so a change to either factor has to be deliberate.
        assert_eq!(RecordKind::BlockList.capacity(), BLOCK_LIST_CAPACITY);
        assert_eq!(BLOCK_LIST_CAPACITY, 512 * 2592);

        // Every kind, with no exemption: the cursor's exemption is what #389
        // removed, so a loop that filtered any kind out would be the shape of
        // the defect rather than a test of the fix.
        assert_eq!(RecordKind::ALL.len(), 6, "the loop must cover every kind");
        for kind in RecordKind::ALL {
            assert_eq!(
                kind.on_disk_len(),
                NONCE_LEN + LEN_PREFIX + kind.capacity() + TAG_LEN,
                "{kind:?} is not a sealed record's width on disk"
            );
        }
        // The cursor's own width, written out: eight bytes of page number no
        // longer make an eight-byte file.
        assert_eq!(
            RecordKind::ReceiveCursor.on_disk_len(),
            NONCE_LEN + LEN_PREFIX + RECEIVE_CURSOR_LEN + TAG_LEN
        );
        assert_eq!(RecordKind::ReceiveCursor.on_disk_len(), 40);
    }

    #[test]
    fn aad_tags_are_byte_pinned() {
        assert_eq!(RecordKind::Resume.aad_tag(), 1);
        assert_eq!(RecordKind::Provisional.aad_tag(), 2);
        assert_eq!(RecordKind::Outbox.aad_tag(), 3);
        assert_eq!(RecordKind::ReceiveCursor.aad_tag(), 4);
        assert_eq!(RecordKind::ContactCache.aad_tag(), 5);
        assert_eq!(RecordKind::BlockList.aad_tag(), 6);
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
            g.replace(RecordKind::ContactCache, &payload(CONTACT_RECORD_LEN))?;
            g.replace(RecordKind::ReceiveCursor, &7u64.to_be_bytes())
        })
        .unwrap();

        for kind in RecordKind::ALL {
            // A profile record has no correspondence directory; it is at the
            // root, and `DmStore::open` has already created it.
            let path = match kind.scope() {
                RecordScope::Correspondence => tmp
                    .path()
                    .join("dm")
                    .join(l.dir_name())
                    .join(kind.file_name()),
                RecordScope::Profile => tmp.path().join("dm").join(kind.file_name()),
            };
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

    // ---- the profile scope -------------------------------------------------

    /// The record exists from the first open, at its kind's fixed size, holding
    /// an empty payload.
    ///
    /// All three halves matter and they fail differently. A record created only
    /// on first use would make its presence report that the feature is in use; a
    /// record sized to its contents would report how much of it is in use; and a
    /// record whose empty state is an absence rather than a value would make
    /// every reader treat "nobody is blocked" as an error.
    #[test]
    fn a_profile_record_exists_from_the_first_open_at_its_fixed_size() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Profile)
        {
            let path = tmp.path().join("dm").join(kind.file_name());
            assert_eq!(
                std::fs::metadata(&path).unwrap().len() as usize,
                kind.on_disk_len(),
                "{kind:?} must be created at its fixed size"
            );
            assert_eq!(
                s.read_profile_unlocked(kind).unwrap(),
                Some(Vec::new()),
                "{kind:?} must open to an empty payload, not to an absence"
            );
        }
        // Positive control: the loop above ran over something.
        assert!(
            RecordKind::ALL
                .iter()
                .any(|k| k.scope() == RecordScope::Profile),
            "no profile kind exists, so the assertions above tested nothing"
        );
    }

    /// A second open does not overwrite what the first one left.
    ///
    /// The creation at open is unconditional in *when* it runs and conditional in
    /// *what* it does; a version that skipped the presence check would pass every
    /// assertion above and silently reset the list at every start.
    #[test]
    fn reopening_the_store_does_not_reset_a_profile_record() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = payload(64);
        {
            let s = store(tmp.path());
            s.profile_critical_section::<_, DmStoreError>(|g| {
                g.replace(RecordKind::BlockList, &payload)
            })
            .unwrap();
        }

        let reopened = store(tmp.path());
        assert_eq!(
            reopened
                .read_profile_unlocked(RecordKind::BlockList)
                .unwrap(),
            Some(payload),
            "reopening must not write over an existing profile record"
        );
    }

    /// A profile record's temp sibling lands at the **root**, so the sweep has to
    /// reach root-level files — and must still leave everything else alone.
    #[test]
    fn a_root_level_temp_sibling_is_swept_and_an_ordinary_root_file_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let root = {
            let s = store(tmp.path());
            s.root().to_path_buf()
        };

        let orphan = root.join(format!("block-list.bin{TMP_INFIX}0011aabb"));
        let bystander = root.join("not-a-temp-sibling");
        std::fs::write(&orphan, vec![7u8; 128]).unwrap();
        std::fs::write(&bystander, b"left alone").unwrap();

        let _reopened = store(tmp.path());

        assert!(
            !orphan.exists(),
            "a root-level temp sibling must be swept at open"
        );
        // Both controls: a file the sweep must not touch, and the record itself.
        assert!(
            bystander.exists(),
            "the sweep must remove only temp siblings"
        );
        assert!(
            root.join(RecordKind::BlockList.file_name()).exists(),
            "the sweep must not remove the record it sits beside"
        );
    }

    /// Reentering the profile section on one thread is refused, not hung.
    ///
    /// `flock` attaches to the open file description, so the nested acquire would
    /// block on a lock this same thread holds and never return — the failure the
    /// held-set exists to convert into an error, here for the scope that was
    /// added last.
    #[test]
    fn a_nested_profile_critical_section_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        let nested = s.profile_critical_section::<_, DmStoreError>(|_| {
            s.profile_critical_section::<_, DmStoreError>(|_| Ok(()))
        });
        assert!(
            matches!(nested, Err(DmStoreError::Reentrant)),
            "a nested profile section must be refused: {nested:?}"
        );

        // Control: the same call outside a section succeeds, so the refusal above
        // is about nesting and not about the section being broken.
        s.profile_critical_section::<_, DmStoreError>(|_| Ok(()))
            .unwrap();
    }

    /// The two AAD constructions cannot be parsed into each other, and the
    /// profile one carries no label.
    #[test]
    fn the_profile_aad_is_a_separate_construction_carrying_no_label() {
        let profile = profile_seal_aad(RecordKind::BlockList);
        assert!(
            profile.starts_with(domain::DM_STORE_PROFILE_AAD),
            "a profile record seals under its own domain prefix"
        );
        assert!(
            !profile.starts_with(domain::DM_STORE_AAD),
            "the two prefixes must not be one a prefix of the other"
        );
        // The label is 32 bytes; a construction carrying one cannot be this short.
        assert!(
            profile.len() < domain::DM_STORE_PROFILE_AAD.len() + CORRESPONDENCE_LABEL_LEN,
            "the profile AAD must bind no correspondence label"
        );

        // Control: the correspondence construction does bind one, and differs.
        let correspondence = seal_aad(&label(9), RecordKind::ContactCache);
        assert!(correspondence.starts_with(domain::DM_STORE_AAD));
        assert_ne!(profile, correspondence);
    }

    /// **The splice, end to end.** One file, one kind, one length — only the
    /// AAD differs, and it does not open.
    ///
    /// The byte comparison above would pass for two constructions that were
    /// merely different; this seals through the real write path and reopens
    /// through the real read path, so it is the AAD's *effect* under the cipher
    /// that is pinned rather than the shape of a `Vec<u8>`.
    #[test]
    fn a_record_sealed_in_one_scope_does_not_open_in_the_other() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(41);

        // Profile record, read back with the correspondence construction.
        s.profile_critical_section::<_, DmStoreError>(|g| {
            g.replace(RecordKind::BlockList, &payload(96))
        })
        .unwrap();
        let profile_path = s.root().join(RecordKind::BlockList.file_name());
        assert_eq!(
            s.read_record(&profile_path, None, RecordKind::BlockList)
                .unwrap(),
            Some(payload(96)),
            "control: the record opens under its own AAD"
        );
        assert!(
            matches!(
                s.read_record(&profile_path, Some(&l), RecordKind::BlockList),
                Err(DmStoreError::NotAuthentic { .. })
            ),
            "a profile record must not open under a correspondence AAD"
        );

        // And the reverse.
        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::ContactCache, &payload(64))
        })
        .unwrap();
        let corr_path = s.record_path(&l, RecordKind::ContactCache);
        assert_eq!(
            s.read_record(&corr_path, Some(&l), RecordKind::ContactCache)
                .unwrap(),
            Some(payload(64)),
            "control: the record opens under its own AAD"
        );
        assert!(
            matches!(
                s.read_record(&corr_path, None, RecordKind::ContactCache),
                Err(DmStoreError::NotAuthentic { .. })
            ),
            "a correspondence record must not open under the profile AAD"
        );
    }

    /// A profile kind handed to the correspondence guard is refused, in a
    /// **release** build as much as a debug one.
    ///
    /// What it would otherwise do: write `<root>/<label>/block-list.bin` sealed
    /// under the correspondence AAD — a second block list no profile read can
    /// ever see, so a block would appear taken and would suppress nothing.
    #[test]
    fn a_profile_kind_is_refused_by_the_correspondence_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(42);

        let wrong = |r: Result<(), DmStoreError>| {
            matches!(
                r,
                Err(DmStoreError::WrongScope {
                    kind: RecordKind::BlockList,
                    guard: RecordScope::Correspondence,
                })
            )
        };
        s.critical_section::<_, DmStoreError>(&l, |g| {
            assert!(wrong(g.read(RecordKind::BlockList).map(|_| ())));
            assert!(wrong(g.replace(RecordKind::BlockList, b"x")));
            // A delete that found nothing would answer `Ok(())` — an erasure
            // reporting success having erased nothing.
            assert!(wrong(g.delete(RecordKind::BlockList)));
            Ok(())
        })
        .unwrap();
        assert!(wrong(
            s.read_unlocked(&l, RecordKind::BlockList).map(|_| ())
        ));

        assert!(
            !tmp.path()
                .join("dm")
                .join(l.dir_name())
                .join(RecordKind::BlockList.file_name())
                .exists(),
            "no second, per-correspondence block list may exist"
        );
        // Control: the same guard serves its own kinds.
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, b"owed"))
            .unwrap();
    }

    /// A correspondence kind handed to the profile guard is refused.
    ///
    /// A correspondence record written here would land at the store root under
    /// the profile AAD, where no reader of a correspondence's records looks.
    #[test]
    fn a_correspondence_kind_is_refused_by_the_profile_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        s.profile_critical_section::<_, DmStoreError>(|g| {
            for kind in [
                RecordKind::Resume,
                RecordKind::Provisional,
                RecordKind::Outbox,
                RecordKind::ReceiveCursor,
                RecordKind::ContactCache,
            ] {
                let body = vec![0u8; kind.capacity().min(8)];
                assert!(
                    matches!(
                        g.replace(kind, &body),
                        Err(DmStoreError::WrongScope {
                            guard: RecordScope::Profile,
                            ..
                        })
                    ),
                    "{kind:?} must be refused by the profile guard"
                );
                assert!(matches!(g.read(kind), Err(DmStoreError::WrongScope { .. })));
                assert!(matches!(
                    g.present(kind),
                    Err(DmStoreError::WrongScope { .. })
                ));
            }
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            s.read_profile_unlocked(RecordKind::Resume),
            Err(DmStoreError::WrongScope { .. })
        ));

        // The root holds exactly what it should — no `cursor.bin` in the clear.
        let (_, files) = root_entries(&tmp.path().join("dm"));
        assert_eq!(files, expected_root_files());
    }

    /// Opening a store never waits on the profile lock.
    ///
    /// The lock is held across caller-supplied closures of unbounded duration,
    /// so an `open` that blocked on it would stall in startup for as long as
    /// some other process chose to stay inside `update_block_list`.
    #[test]
    fn opening_a_store_does_not_block_on_a_held_profile_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let first = store(tmp.path());
        let held = FileLock::acquire(&first.root().join(LOCK_FILE_NAME)).unwrap();

        // `flock(2)` does not pass on a second descriptor, so a blocking
        // acquire here would hang this very thread — no second process needed.
        let second = DmStore::open(tmp.path().join("dm"), &AT_REST);
        assert!(second.is_ok(), "open must not wait on the profile lock");
        drop(held);

        // And nested inside a section of another store on the same root, which
        // has its own held-set and so gets no reentrancy refusal to save it.
        first
            .profile_critical_section::<_, DmStoreError>(|_| {
                DmStore::open(tmp.path().join("dm"), &AT_REST).map(|_| ())
            })
            .expect("a nested open must not hang");
    }

    /// The root sweep runs **inside** the profile lock.
    ///
    /// Observable rather than asserted about the source: with the lock held
    /// elsewhere the housekeeping is skipped whole, so the orphan survives that
    /// open and is swept by the next one. An unlocked sweep would take it on the
    /// first — which is the state in which it can scrub a record whose
    /// `rename(2)` has already committed it.
    #[test]
    fn the_root_sweep_is_skipped_while_the_profile_lock_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let root = store(tmp.path()).root().to_path_buf();
        let orphan = root.join(format!("block-list.bin{TMP_INFIX}deadbeef"));

        std::fs::write(&orphan, vec![3u8; 64]).unwrap();
        let held = FileLock::acquire(&root.join(LOCK_FILE_NAME)).unwrap();
        let _blocked = store(tmp.path());
        assert!(
            orphan.exists(),
            "the root sweep must not run while another holder has the profile lock"
        );

        drop(held);
        let _free = store(tmp.path());
        assert!(
            !orphan.exists(),
            "control: with the lock free the same open sweeps it"
        );
    }

    /// A symlinked temp sibling is skipped, never opened and zeroed.
    ///
    /// The root is reachable before any correspondence exists, so a co-resident
    /// attacker can drop one there and have the next `open` destroy whatever it
    /// points at. `FileLock::acquire` already refuses a symlinked lock path;
    /// this is the same guard on the same directory.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_temp_sibling_is_not_followed_by_the_sweep() {
        let tmp = tempfile::tempdir().unwrap();
        let root = store(tmp.path()).root().to_path_buf();

        let target = tmp.path().join("precious");
        std::fs::write(&target, b"do not touch").unwrap();
        let link = root.join(format!("block-list.bin{TMP_INFIX}00ff"));
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let _reopened = store(tmp.path());

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"do not touch",
            "the sweep followed a symlink and destroyed its target"
        );
        // Control: a real temp sibling beside it still goes.
        let real = root.join(format!("block-list.bin{TMP_INFIX}11ee"));
        std::fs::write(&real, vec![9u8; 32]).unwrap();
        let _again = store(tmp.path());
        assert!(!real.exists(), "a real temp sibling must still be swept");
    }

    /// Profile-before-correspondence: the forbidden order is refused, the
    /// permitted one works.
    ///
    /// Both closures are caller-supplied, so opposite orders across two
    /// processes deadlock with nothing able to convert it into an error —
    /// neither thread is waiting on a lock it holds itself.
    #[test]
    fn taking_the_profile_lock_inside_a_correspondence_section_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(43);

        let out = s.critical_section::<_, DmStoreError>(&l, |_| {
            s.profile_critical_section::<_, DmStoreError>(|_| Ok(()))
        });
        assert!(
            matches!(out, Err(DmStoreError::Reentrant)),
            "the forbidden order must be refused: {out:?}"
        );

        // Control: the permitted order is not refused, and the claim taken by
        // the refused attempt above did not leak.
        s.profile_critical_section::<_, DmStoreError>(|_| {
            s.critical_section::<_, DmStoreError>(&l, |_| Ok(()))
        })
        .expect("profile then correspondence is the permitted order");
    }

    /// Two threads cannot be inside the profile section at once.
    ///
    /// Reentrancy is a different property: it is about one thread and is served
    /// by the held-set. This is the exclusion itself, which is the `flock`'s.
    #[test]
    fn two_threads_cannot_hold_the_profile_section_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let inside = AtomicBool::new(false);
        let overlaps = AtomicBool::new(false);

        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    for _ in 0..20 {
                        s.profile_critical_section::<_, DmStoreError>(|_| {
                            if inside.swap(true, Ordering::SeqCst) {
                                overlaps.store(true, Ordering::SeqCst);
                            }
                            std::thread::sleep(std::time::Duration::from_micros(200));
                            inside.store(false, Ordering::SeqCst);
                            Ok(())
                        })
                        .unwrap();
                    }
                });
            }
        });
        assert!(
            !overlaps.load(Ordering::SeqCst),
            "two threads were inside the profile section together"
        );
    }

    /// A panicking closure strands neither the lock nor the claim.
    #[test]
    fn a_panicking_profile_closure_releases_both_guards() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.profile_critical_section::<(), DmStoreError>(|_| panic!("closure blew up"))
        }));
        assert!(panicked.is_err(), "the panic must propagate");

        // Both halves: the claim (or this is `Reentrant`) and the `flock` (or
        // this hangs — which the test harness reports as a timeout, not a pass).
        s.profile_critical_section::<_, DmStoreError>(|g| g.read(RecordKind::BlockList))
            .expect("the section must be usable again");
    }

    /// The profile scope inherits the read path's three refusals.
    ///
    /// `LockedProfile::replace`'s docs claim the erasure sentinel is inherited;
    /// nothing pinned it, and a claim nothing pins is a claim that can quietly
    /// stop being true.
    #[test]
    fn a_profile_record_inherits_the_read_paths_refusals() {
        let tmp = tempfile::tempdir().unwrap();
        let path = {
            let s = store(tmp.path());
            s.profile_critical_section::<_, DmStoreError>(|g| {
                g.replace(RecordKind::BlockList, &payload(32))
            })
            .unwrap();
            s.root().join(RecordKind::BlockList.file_name())
        };

        // Wrong profile key.
        let other = DmStore::open(tmp.path().join("dm"), &OTHER_AT_REST).unwrap();
        assert!(matches!(
            other.read_profile_unlocked(RecordKind::BlockList),
            Err(DmStoreError::NotAuthentic {
                kind: RecordKind::BlockList
            })
        ));

        // Wrong size.
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, &good[..good.len() - 1]).unwrap();
        let s = store(tmp.path());
        assert!(matches!(
            s.read_profile_unlocked(RecordKind::BlockList),
            Err(DmStoreError::WrongFileLen { .. })
        ));

        // An erase that began and did not finish.
        let mut half = good.clone();
        half[..ERASURE_SENTINEL.len()].copy_from_slice(ERASURE_SENTINEL);
        std::fs::write(&path, &half).unwrap();
        assert!(matches!(
            s.read_profile_unlocked(RecordKind::BlockList),
            Err(DmStoreError::ErasureInterrupted {
                kind: RecordKind::BlockList
            })
        ));

        // Control: restored, it reads.
        std::fs::write(&path, &good).unwrap();
        assert_eq!(
            s.read_profile_unlocked(RecordKind::BlockList).unwrap(),
            Some(payload(32))
        );
    }

    /// The store's own ceiling refusal, which is not `BlockList::encode`'s.
    #[test]
    fn the_store_refuses_a_profile_payload_over_its_bucket() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let capacity = RecordKind::BlockList.capacity();

        let refused = s.profile_critical_section::<_, DmStoreError>(|g| {
            g.replace(RecordKind::BlockList, &vec![0u8; capacity + 1])
        });
        assert!(
            matches!(
                refused,
                Err(DmStoreError::PayloadTooLong {
                    kind: RecordKind::BlockList,
                    ..
                })
            ),
            "{refused:?}"
        );
        // Control: exactly the capacity is accepted, so the refusal is the
        // ceiling and not the write path being broken.
        s.profile_critical_section::<_, DmStoreError>(|g| {
            g.replace(RecordKind::BlockList, &vec![0u8; capacity])
        })
        .unwrap();
    }

    /// A profile record that cannot be created does not make the store
    /// unopenable.
    ///
    /// **The branch beside it argues this exact case the other way.**
    /// `sweep_orphans` fails soft because an error inside `open` takes the whole
    /// store with it, and every correspondence read — none of which touches the
    /// profile record — goes with it. A store predating this record, on a
    /// read-only mount or a full disk, must still open and still serve its
    /// correspondences.
    #[cfg(unix)]
    #[test]
    fn a_profile_record_that_cannot_be_created_leaves_the_store_openable() {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            write_bit_is_enforced(),
            "vacuous where the write bit does not constrain the process"
        );

        let tmp = tempfile::tempdir().unwrap();
        let l = label(44);
        let root = {
            let s = store(tmp.path());
            s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, b"owed"))
                .unwrap();
            s.root().to_path_buf()
        };
        // The state a store predating this record is in: no profile record, and
        // a medium that will not take one.
        std::fs::remove_file(root.join(RecordKind::BlockList.file_name())).unwrap();
        std::fs::remove_file(root.join(LOCK_FILE_NAME)).unwrap();
        let original = std::fs::metadata(&root).unwrap().permissions();
        let mut readonly = original.clone();
        readonly.set_mode(0o555);
        std::fs::set_permissions(&root, readonly).unwrap();

        let reopened = DmStore::open(&root, &AT_REST);
        let restore = std::fs::set_permissions(&root, original);

        let reopened = reopened.expect("a store must open on a medium it cannot write");
        assert_eq!(
            reopened.read_unlocked(&l, RecordKind::Outbox).unwrap(),
            Some(b"owed".to_vec()),
            "the correspondence records must still be readable"
        );
        // The loss is bounded and lands where it can be seen: the record is
        // absent, and the read of it refuses loudly rather than answering
        // "nobody is blocked".
        assert_eq!(
            reopened
                .read_profile_unlocked(RecordKind::BlockList)
                .unwrap(),
            None
        );
        restore.unwrap();

        // Control: writable again, the next open creates it.
        let s = store(tmp.path());
        assert!(
            s.read_profile_unlocked(RecordKind::BlockList)
                .unwrap()
                .is_some(),
            "the creation must resume once the medium allows it"
        );
    }

    /// A record file name can never be the lock file's.
    #[test]
    fn no_record_name_collides_with_the_lock_file() {
        for kind in RecordKind::ALL {
            assert_ne!(
                kind.file_name(),
                LOCK_FILE_NAME,
                "{kind:?} would be written over the lock file"
            );
        }
    }

    /// **A read-only record is repaired and erased, not wedged for ever.**
    ///
    /// `establish` builds the ratchet AND deletes, so a delete that can never
    /// succeed takes the whole correspondence with it — and before this the failure
    /// was a generic I/O error, indistinguishable from a slow disk a caller would
    /// keep retrying against.
    ///
    /// **Guarded on not being root, and that guard is the whole validity of the
    /// test.** Root ignores the write bit, so as root the `open` succeeds, the
    /// repair path is never entered, and every assertion below passes while
    /// exercising nothing. A vacuous pass on a forward-secrecy path is exactly the
    /// shape worth refusing to ship, so this fails loudly rather than skipping
    /// silently if the CI user ever changes.
    #[cfg(unix)]
    #[test]
    fn a_read_only_record_is_repaired_and_erased_rather_than_wedging() {
        use std::os::unix::fs::PermissionsExt;

        assert!(
            write_bit_is_enforced(),
            "this case is vacuous where the write bit does not constrain the \
             process (root, or a permissive mount): the open would succeed, the \
             repair path would never be reached, and every assertion below would \
             pass while exercising nothing"
        );

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(9);
        let path = tmp.path().join("dm").join(l.dir_name()).join("outbox.bin");

        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::Outbox, &payload(4_096))
        })
        .unwrap();

        // Take owner-write away, which is the permanent fault: every retry of the
        // old code took the same branch.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o400);
        std::fs::set_permissions(&path, perms).unwrap();
        // Control: the open really is refused in this state, so the repair below is
        // doing something rather than papering over a file that was writable anyway.
        assert_eq!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied,
            "the fixture did not actually make the record unwritable"
        );

        s.critical_section::<_, DmStoreError>(&l, |g| g.delete(RecordKind::Outbox))
            .expect("a read-only record must be repaired and erased, not refused");
        assert!(
            !path.exists(),
            "the record survived a delete that reported success"
        );
    }

    /// The **unlink** site: the record's directory is unwritable, so the file's mode
    /// is repaired, the scrub runs, and `remove_file` is refused.
    ///
    /// **What actually happens here, corrected after review.** An earlier version of
    /// this comment claimed the *repair* failed because `set_permissions` needs to
    /// modify within the directory. It does not — chmod needs only the search bit on
    /// the parent, which `0o500` grants — so the repair succeeds (mode 000 → 200),
    /// the payload IS overwritten, and only the unlink is refused. The assertion
    /// below was inverted on the same misreading: it called a surviving file
    /// "the secret is not reported as erased when it is not", when the secret was in
    /// fact already erased.
    ///
    /// So this is the `scrubbed: true` case, and it is the milder one: forward
    /// secrecy holds and what is blocked is progress. The `scrubbed: false` case is
    /// covered separately below.
    #[cfg(unix)]
    #[test]
    fn an_unrepairable_erasure_is_a_distinct_error_carrying_its_trust_event() {
        use std::os::unix::fs::PermissionsExt;

        assert!(
            write_bit_is_enforced(),
            "vacuous where the write bit does not constrain the process"
        );

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(11);
        let dir = tmp.path().join("dm").join(l.dir_name());
        let path = dir.join("outbox.bin");

        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::Outbox, &payload(4_096))
        })
        .unwrap();

        // Mode 000 on the FILE and a read-only DIRECTORY. The repair *succeeds*
        // — chmod needs ownership, not directory write — so the scrub runs and
        // it is the unlink, which needs write on the directory, that is refused.
        // (This comment previously said the repair itself failed, which would
        // have made this the `scrubbed: false` case; the assertions below have
        // always said `scrubbed: true`, and they are what is right. Staging a
        // failed repair needs a read-only mount, an immutable attribute or a
        // MAC policy — see `only_a_permanent_write_refusal_takes_the_erasure_blocked_branch`.)
        let mut fp = std::fs::metadata(&path).unwrap().permissions();
        fp.set_mode(0o000);
        std::fs::set_permissions(&path, fp).unwrap();
        let mut dp = std::fs::metadata(&dir).unwrap().permissions();
        dp.set_mode(0o500);
        std::fs::set_permissions(&dir, dp).unwrap();

        let err = s
            .critical_section::<_, DmStoreError>(&l, |g| g.delete(RecordKind::Outbox))
            .expect_err("an unrepairable record must not report a successful delete");

        // Restore before asserting, so a failing assertion cannot leave the
        // temp dir undeletable.
        let mut dp = std::fs::metadata(&dir).unwrap().permissions();
        dp.set_mode(0o700);
        std::fs::set_permissions(&dir, dp).unwrap();

        assert!(
            matches!(
                err,
                DmStoreError::ErasureBlocked {
                    kind: RecordKind::Outbox,
                    scrubbed: true,
                    ..
                }
            ),
            "the failure must be its own variant AND report that the payload was \
             already overwritten — telling an operator a secret is still readable \
             when it is not is its own harm: {err:?}"
        );
        assert!(
            err.to_string().contains("nothing sealed remains readable"),
            "the message must not claim the record still holds its contents: {err}"
        );
        assert_eq!(
            err.event(),
            Some(crate::trust_events::TrustEventScope::for_record(
                crate::trust_events::TrustEventKey::DmRecordErasureBlocked,
                RecordKind::Outbox,
            )),
            "the failure must carry the trust event it is surfaced as, and the \
             kind of record at stake with it"
        );
        assert_eq!(
            crate::trust_events::class_of(err.event().unwrap().key),
            crate::trust_events::TrustEventClass::PersistentNonBlocking,
            "a wedged correspondence must recur at every start until a human fixes it"
        );
        // The file is still there — the unlink was refused — but its payload is
        // gone. Assert the erasure actually happened rather than inferring it: a
        // file surviving with its sealed contents intact would be the
        // `scrubbed: false` case, and reporting it as this one is the defect the
        // split field exists to prevent.
        assert!(path.exists(), "the unlink was refused, so the file remains");
        // The repair left the file mode 200 (write-only), so read has to be restored
        // before it can be inspected — the file being unreadable is an artefact of
        // the fixture, not of the code under test.
        let mut fp = std::fs::metadata(&path).unwrap().permissions();
        fp.set_mode(0o600);
        std::fs::set_permissions(&path, fp).unwrap();
        let after = std::fs::read(&path).expect("the file is readable again");
        assert!(
            !after.is_empty(),
            "the scrubbed record should still occupy its bucket"
        );
    }

    /// The stable strings are unique, round-trip, and are not the file names.
    ///
    /// The last clause is the one worth pinning: reusing `file_name` would have
    /// been free today and would have tied a persisted audit log to the storage
    /// layout, so that renaming a file on disk silently rewrote history.
    #[test]
    fn record_kind_stable_strings_round_trip_and_are_their_own() {
        let mut seen: Vec<&str> = Vec::new();
        for kind in RecordKind::ALL {
            let s = kind.stable_str();
            assert_eq!(RecordKind::from_stable_str(s), Some(kind));
            assert_ne!(
                s,
                kind.file_name(),
                "the persisted form must not be the storage layout"
            );
            assert!(!seen.contains(&s), "stable strings must be unique: {s}");
            seen.push(s);
        }
        // A literal, deliberately, and not `RecordKind::ALL.len()`. The loop
        // pushes once per member of `ALL`, so comparing against `ALL.len()` is a
        // tautology that holds for any set of kinds — it would keep passing if a
        // member were silently replaced by another. The literal is the only part
        // of this test that notices the enum changing shape.
        assert_eq!(seen.len(), 6, "six kinds, six distinct stable strings");
        assert_eq!(RecordKind::from_stable_str("resume.bin"), None);
        assert_eq!(RecordKind::from_stable_str("nope"), None);
    }

    /// Every kind reaches the trust event as *itself* — end to end, through the
    /// unlink site, one separate erasure per kind.
    ///
    /// **The kinds do not cost the same, which is the whole reason the event
    /// carries one.** A blocked [`RecordKind::Provisional`] erasure leaves
    /// `ss0` on disk; [`RecordKind::ReceiveCursor`] holds one page number.
    /// `an_unrepairable_erasure_is_a_distinct_error_carrying_its_trust_event`
    /// pins one kind, which a hardcoded `RecordKind::Outbox` at the raise site
    /// would satisfy; this pins every kind, so it cannot be.
    #[cfg(unix)]
    #[test]
    fn every_kind_reaches_the_erasure_event_as_itself() {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            write_bit_is_enforced(),
            "vacuous where the write bit does not constrain the process"
        );

        // Guards the loop against a future `ALL` that stops covering the enum,
        // which would make every assertion below vacuously true for the kinds
        // it dropped.
        // The guard has to count the set the loop actually walks. Guarding
        // `ALL.len()` instead would trip on a new *profile* kind, which this
        // loop never touches, while a new *correspondence* kind — the one case
        // that would silently go uncovered — left it green.
        assert_eq!(
            RecordKind::ALL
                .iter()
                .filter(|k| k.scope() == RecordScope::Correspondence)
                .count(),
            5,
            "one erasure per correspondence kind"
        );

        // Correspondence kinds only: a profile record has no `delete` door at
        // all (see `LockedProfile`), so there is no unlink site for it to reach.
        for (i, kind) in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Correspondence)
            .enumerate()
        {
            let tmp = tempfile::tempdir().unwrap();
            let s = store(tmp.path());
            let l = label(80 + i as u8);
            let dir = tmp.path().join("dm").join(l.dir_name());
            let path = dir.join(kind.file_name());

            // Every kind is padded, so a short body is legal for all of them and
            // keeps the fixture cheap.
            let body = payload(kind.capacity().min(64));
            s.critical_section::<_, DmStoreError>(&l, |g| g.replace(kind, &body))
                .unwrap();

            // Read-only directory: the scrub succeeds, the unlink cannot.
            let mut dp = std::fs::metadata(&dir).unwrap().permissions();
            dp.set_mode(0o500);
            std::fs::set_permissions(&dir, dp).unwrap();

            let err = s
                .critical_section::<_, DmStoreError>(&l, |g| g.delete(kind))
                .expect_err("an unlinkable record must not report a successful delete");

            let mut dp = std::fs::metadata(&dir).unwrap().permissions();
            dp.set_mode(0o700);
            std::fs::set_permissions(&dir, dp).unwrap();
            assert!(path.exists(), "the unlink was refused, so the file remains");

            assert_eq!(
                err.event(),
                Some(crate::trust_events::TrustEventScope::for_record(
                    crate::trust_events::TrustEventKey::DmRecordErasureBlocked,
                    kind,
                )),
                "the event must name the kind actually erased, not a fixed one: {err:?}"
            );
        }
    }

    /// The kind survives the hop from the error to the trust event, for every
    /// kind and both disclosure states.
    ///
    /// **This is the probe for the two raise sites a unit test cannot stage.**
    /// The open site's two `ErasureBlocked` returns need an open that is refused
    /// *and* a repair that cannot help — a read-only mount, an immutable
    /// attribute, or a MAC policy, none of which a normal user can arrange here
    /// (the reasoning is `only_a_permanent_write_refusal_takes_the_erasure_blocked_branch`'s,
    /// and unchanged). What all three sites share is this hop: each builds the
    /// variant from the `kind` it was called with, and `event` reads it back.
    /// Constructing the variant directly covers the half of the threading that
    /// is reachable, and this test says plainly that it is only that half.
    #[test]
    fn every_kind_survives_the_hop_from_error_to_trust_event() {
        assert_eq!(RecordKind::ALL.len(), 6, "one case per kind");
        for kind in RecordKind::ALL {
            for scrubbed in [false, true] {
                let err = DmStoreError::ErasureBlocked {
                    kind,
                    scrubbed,
                    source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                };
                let scope = err.event().expect("a blocked erasure is a trust event");
                assert_eq!(
                    scope.key,
                    crate::trust_events::TrustEventKey::DmRecordErasureBlocked
                );
                assert_eq!(
                    scope.record_kind,
                    Some(kind),
                    "the kind must not be discarded between the error and the event"
                );
            }
        }
    }

    /// No other `DmStoreError` invents a record kind — or a trust event.
    ///
    /// The mirror control for the two tests above: a threading fix that made
    /// `event` return a kind unconditionally would pass both of them.
    #[test]
    fn no_other_store_error_carries_a_trust_event() {
        let others = [
            DmStoreError::Reentrant,
            DmStoreError::Kdf,
            DmStoreError::Module,
            DmStoreError::ErasureInterrupted {
                kind: RecordKind::Provisional,
            },
            DmStoreError::WrongFileLen {
                kind: RecordKind::Resume,
                expected: 1,
                actual: 2,
            },
        ];
        for err in others {
            assert_eq!(
                err.event(),
                None,
                "only a blocked erasure is a trust event: {err:?}"
            );
        }
    }

    /// Whether the write bit actually constrains this process.
    ///
    /// **Behavioural, not an identity check, and deliberately so.** The property
    /// the cases below depend on is "a mode without owner-write refuses an open for
    /// writing" — root is merely the usual reason it would not hold, and a uid
    /// comparison is a proxy for it. Proxies read wrong: the first version of this
    /// asked `/proc/self`'s owner, which on this very host disagrees with `id -u`,
    /// so the guard could have reported root while the tests ran as a normal user
    /// or the reverse.
    ///
    /// This asks the filesystem the same question the code under test asks, in the
    /// same temp directory, one line before it matters.
    #[cfg(unix)]
    fn write_bit_is_enforced() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let probe = tmp.path().join("probe");
        std::fs::write(&probe, b"x").expect("write probe");
        let mut perms = std::fs::metadata(&probe).expect("stat probe").permissions();
        perms.set_mode(0o400);
        std::fs::set_permissions(&probe, perms).expect("chmod probe");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&probe)
            .is_err()
    }

    /// The **open** site's decision logic, probed directly because the scenario
    /// cannot be staged as a normal user.
    ///
    /// Review found that site — the one the whole change is about — completely
    /// unprobed: reverting either of its `ErasureBlocked` returns to a generic `Io`
    /// was caught by nothing, while the milder unlink site had two tests. Staging it
    /// end-to-end needs an open that is refused AND a repair that cannot help, and
    /// as a normal user owning the file there is no such arrangement: chmod succeeds
    /// whenever the parent is searchable, and removing the search bit refuses the
    /// **lock** before `delete` is ever reached (verified — the attempt failed with
    /// `Lock(Io(PermissionDenied))`).
    ///
    /// The real instances are a read-only mount, an immutable attribute, or a MAC
    /// policy, none of which a unit test can arrange here. So this probes the
    /// predicate that decides the branch, which is what blocker-class bug it was:
    /// **EROFS is `ReadOnlyFilesystem`, not `PermissionDenied`**, and the first
    /// version of the guard matched only the latter — so a read-only mount, the
    /// classic permanent write refusal, still reported as retryable.
    ///
    /// What remains uncovered is stated rather than implied: no test drives a real
    /// unopenable-and-unrepairable record through `delete`.
    #[test]
    fn only_a_permanent_write_refusal_takes_the_erasure_blocked_branch() {
        // EACCES and EPERM both map to PermissionDenied; EROFS is its own kind and
        // was the one originally missed.
        for code in [
            13, /* EACCES */
            1,  /* EPERM */
            30, /* EROFS */
        ] {
            let e = std::io::Error::from_raw_os_error(code);
            assert!(
                is_permanent_write_refusal(&e),
                "errno {code} ({:?}) must be treated as permanent",
                e.kind()
            );
        }
        // Transient faults must stay retryable: classing one as permanent turns a
        // bad second into a trust event that recurs at every start until a human
        // clears it, which is the mirror of the bug being fixed.
        for code in [
            5,  /* EIO */
            4,  /* EINTR */
            28, /* ENOSPC */
            24, /* EMFILE */
        ] {
            let e = std::io::Error::from_raw_os_error(code);
            assert!(
                !is_permanent_write_refusal(&e),
                "errno {code} ({:?}) is transient and must stay retryable",
                e.kind()
            );
        }
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

    /// The cursor takes the ordinary bucket rules, both ends.
    ///
    /// Before #389 it took neither: unsealed it carried no length prefix, so the
    /// store had to demand exactly [`RECEIVE_CURSOR_LEN`] and a shorter payload
    /// was an error. Sealed, a shorter one is padded and recovered exactly like
    /// any other kind, and only an over-long one is refused. What still requires
    /// eight bytes is `crate::dm::persist`, which decodes them —
    /// `the_cursor_is_eight_sealed_bytes` there is that half.
    #[test]
    fn a_short_cursor_payload_round_trips_and_an_over_long_one_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(5);

        // Positive control: the full width works.
        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::ReceiveCursor, &42u64.to_be_bytes())
        })
        .unwrap();

        for short in [vec![], vec![0u8; 1], vec![0xEEu8; RECEIVE_CURSOR_LEN - 1]] {
            let got = s
                .critical_section::<_, DmStoreError>(&l, |g| {
                    g.replace(RecordKind::ReceiveCursor, &short)?;
                    g.read(RecordKind::ReceiveCursor)
                })
                .unwrap();
            assert_eq!(
                got.as_deref(),
                Some(short.as_slice()),
                "a short cursor payload must come back exactly as it went in"
            );
        }

        let err = s
            .critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::ReceiveCursor, &[0u8; RECEIVE_CURSOR_LEN + 1])
            })
            .unwrap_err();
        assert!(
            matches!(
                err,
                DmStoreError::PayloadTooLong {
                    kind: RecordKind::ReceiveCursor,
                    capacity: RECEIVE_CURSOR_LEN,
                    actual: 9,
                }
            ),
            "got {err:?}"
        );
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

    /// The point of #293: the payload must be *gone from the bytes*, not merely
    /// unreferenced. Scrub without unlinking so the file survives to be read
    /// back — a test that deleted first could only observe absence, which an
    /// unlink alone already produces and which is exactly the thing that was
    /// not enough.
    #[test]
    fn a_scrub_overwrites_the_payload_it_replaces() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(60);
        let secret = payload(4096);

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, &secret))
            .unwrap();

        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join(RecordKind::Outbox.file_name());

        // Positive control: the sealed record is on disk and is NOT the sentinel
        // yet, so a scrub that did nothing would be visible below.
        let before = std::fs::read(&path).unwrap();
        assert_eq!(before.len(), RecordKind::Outbox.on_disk_len());
        assert!(!before.starts_with(ERASURE_SENTINEL));

        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        scrub_in_place(&file, &path, RecordKind::Outbox).unwrap();
        drop(file);

        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), before.len(), "a scrub must not resize");
        assert!(after.starts_with(ERASURE_SENTINEL), "sentinel not written");
        assert!(
            after[ERASURE_SENTINEL.len()..].iter().all(|&b| b == 0),
            "the body past the sentinel is not scrubbed"
        );
        assert_ne!(before, after, "the scrub changed nothing");
    }

    /// Every other scrub test here calls [`scrub_in_place`] directly, so none of
    /// them pins that `delete` *reaches* it — measured, not assumed: reverting
    /// `delete` to a plain unlink passed all of them. `delete` destroys its own
    /// evidence by unlinking, so the observable is the barrier count: a
    /// scrubbing delete drives two file barriers and one directory barrier,
    /// where a plain unlink drives only the directory one.
    #[test]
    fn delete_reaches_the_scrub_and_not_only_the_unlink() {
        use crate::storage::atomic_file::{dir_syncs, file_syncs};
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(64);
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Provisional, b"ss0"))
            .unwrap();

        let files_before = file_syncs();
        let dirs_before = dir_syncs();
        s.critical_section::<_, DmStoreError>(&l, |g| g.delete(RecordKind::Provisional))
            .unwrap();

        assert_eq!(
            file_syncs() - files_before,
            2,
            "delete did not drive the scrub's two file barriers — it is unlinking without scrubbing"
        );
        assert!(
            dir_syncs() > dirs_before,
            "delete did not make the unlink durable"
        );
        assert!(
            s.read_unlocked(&l, RecordKind::Provisional)
                .unwrap()
                .is_none(),
            "the record should be gone"
        );
    }

    /// The fsync between the scrub and the unlink is the difference between an
    /// erasure and a no-op that looks like one: without it the overwrite can sit
    /// in dirty page cache and be discarded when the name goes away. Nothing
    /// about the resulting *bytes* would differ in a test, so assert the
    /// barriers were actually performed.
    #[test]
    fn a_scrub_drives_two_real_file_barriers() {
        use crate::storage::atomic_file::file_syncs;

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(61);
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"k"))
            .unwrap();

        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join(RecordKind::Resume.file_name());
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();

        let before = file_syncs();
        scrub_in_place(&file, &path, RecordKind::Resume).unwrap();
        let after = file_syncs();

        assert_eq!(
            after - before,
            2,
            "expected one barrier for the sentinel and one for the body"
        );
    }

    /// A crash between the two barriers leaves the sentinel and nothing else.
    /// The reader must name that state rather than reporting the uniform
    /// authentication failure a tampered record produces.
    #[test]
    fn a_half_scrubbed_record_reads_as_an_interrupted_erase() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(62);
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"k"))
            .unwrap();

        // Simulate the crash window: sentinel present, body untouched.
        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join(RecordKind::Resume.file_name());
        let mut raw = std::fs::read(&path).unwrap();
        raw[..ERASURE_SENTINEL.len()].copy_from_slice(ERASURE_SENTINEL);
        std::fs::write(&path, &raw).unwrap();

        let err = s
            .read_unlocked(&l, RecordKind::Resume)
            .expect_err("a sentinel-bearing record must not read as a record");
        assert!(
            matches!(err, DmStoreError::ErasureInterrupted { kind } if kind == RecordKind::Resume),
            "wrong error for an interrupted erase: {err}"
        );
        // The distinction is the whole point — it must not read as tampering.
        assert!(!matches!(err, DmStoreError::NotAuthentic { .. }));
    }

    /// Every kind is scrubbed, not only the provisional record that #293 named,
    /// and the postcondition is stated over the **whole** file so no assertion
    /// here can go vacuous.
    ///
    /// The version this replaces asserted `after[ERASURE_SENTINEL.len()..]` was
    /// all zero. On [`RecordKind::ReceiveCursor`], which was then 8 unsealed
    /// bytes against a 32-byte sentinel, that is an empty slice and trivially
    /// true, so the test passed while the cursor was not scrubbed at all. It
    /// also never called `delete`,
    /// despite its name; that half is now
    /// `delete_reaches_the_scrub_for_every_kind`.
    #[test]
    fn scrub_erases_every_record_kind_without_resizing() {
        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Correspondence)
        {
            let tmp = tempfile::tempdir().unwrap();
            let s = store(tmp.path());
            let l = label(63);
            let body: &[u8] = b"secret";
            s.critical_section::<_, DmStoreError>(&l, |g| g.replace(kind, body))
                .unwrap();

            let path = tmp
                .path()
                .join("dm")
                .join(l.dir_name())
                .join(kind.file_name());
            let sentinel = &ERASURE_SENTINEL[..ERASURE_SENTINEL.len().min(kind.on_disk_len())];

            // Positive control: a real record of the right width is there and is
            // not already scrubbed, so a scrub that did nothing fails below.
            let before = std::fs::read(&path).unwrap();
            assert_eq!(before.len(), kind.on_disk_len(), "{kind:?}: wrong width");
            assert!(!before.starts_with(sentinel), "{kind:?}: already scrubbed");

            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            scrub_in_place(&file, &path, kind).unwrap();
            drop(file);

            let after = std::fs::read(&path).unwrap();

            // Kills the unbounded-sentinel defect directly: writing all 32 bytes
            // grew the cursor 8 -> 32, which a reader reports as `WrongFileLen`
            // — the truncation shape the sentinel exists to displace.
            assert_eq!(
                after.len(),
                before.len(),
                "{kind:?}: a scrub must not resize the record"
            );

            // Stated over every byte, so it covers the cursor — where the
            // sentinel spans the entire record and there is no tail — exactly as
            // it covers the sealed kinds, where there is.
            assert!(
                after
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| if i < sentinel.len() {
                        b == sentinel[i]
                    } else {
                        b == 0
                    }),
                "{kind:?}: the scrubbed record is not the sentinel followed by zeros"
            );
            assert_ne!(before, after, "{kind:?}: the scrub changed nothing");
        }
    }

    /// `delete` must reach the scrub for **every** kind, not just the provisional
    /// record the barrier test above pins. `delete` unlinks and so destroys its
    /// own byte-level evidence; the observable is the barrier count, which the
    /// seam already exposes.
    #[test]
    fn delete_reaches_the_scrub_for_every_kind() {
        use crate::storage::atomic_file::file_syncs;
        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Correspondence)
        {
            let tmp = tempfile::tempdir().unwrap();
            let s = store(tmp.path());
            let l = label(65);
            let body: &[u8] = b"secret";
            s.critical_section::<_, DmStoreError>(&l, |g| g.replace(kind, body))
                .unwrap();

            let files_before = file_syncs();
            s.critical_section::<_, DmStoreError>(&l, |g| g.delete(kind))
                .unwrap();

            assert_eq!(
                file_syncs() - files_before,
                2,
                "{kind:?}: delete did not drive the scrub's two file barriers — \
                 it is unlinking without scrubbing"
            );
            assert!(
                s.read_unlocked(&l, kind).unwrap().is_none(),
                "{kind:?}: the record should be gone"
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

        let _ = crate::kats::initialize_module_unsigned_test_binary();
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

    /// The cursor's value is not on the disk, and the value the store hands back
    /// is not whatever the disk happens to hold (#389).
    ///
    /// Two halves, because one alone would pass on a broken store. Absence of
    /// the plaintext is checked against the *file's whole bytes* rather than a
    /// prefix, so a cursor written verbatim anywhere in the record fails. And a
    /// decoy planted in the clear — a bare eight-byte page number as the whole
    /// file — must not read back as a cursor, which is what shows the value is being
    /// recovered from the seal and not from the bytes.
    #[test]
    fn the_cursor_is_sealed_at_rest_and_a_clear_one_is_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(15);
        let page = 0x0102_0304_0506_0708u64;
        let bytes = page.to_be_bytes();
        let path = tmp.path().join("dm").join(l.dir_name()).join("cursor.bin");

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::ReceiveCursor, &bytes))
            .unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert_eq!(
            raw.len(),
            RecordKind::ReceiveCursor.on_disk_len(),
            "the record is not a sealed record's width"
        );
        // Positive control on the search itself, run over a buffer of the same
        // width with the value planted at the worst place to find it — the last
        // eight bytes. Without this the negative below could be a windowing bug
        // that can never match anything.
        let mut planted = raw.clone();
        let tail = planted.len() - RECEIVE_CURSOR_LEN;
        planted[tail..].copy_from_slice(&bytes);
        assert!(
            planted.windows(RECEIVE_CURSOR_LEN).any(|w| w == bytes),
            "the search cannot find a needle that is there"
        );

        assert!(
            !raw.windows(RECEIVE_CURSOR_LEN).any(|w| w == bytes),
            "the cursor's value is on disk in the clear"
        );
        // The store still returns it, so the assertion above is about the disk
        // and not about a write that never happened.
        assert_eq!(
            s.read_unlocked(&l, RecordKind::ReceiveCursor)
                .unwrap()
                .as_deref(),
            Some(&bytes[..])
        );

        // A decoy in the clear: exactly the eight bytes the store wrote before
        // #389, in exactly the place it wrote them.
        let decoy = 9_999u64.to_be_bytes();
        std::fs::write(&path, decoy).unwrap();
        let err = s
            .read_unlocked(&l, RecordKind::ReceiveCursor)
            .expect_err("a clear cursor must not read as a cursor");
        assert!(
            matches!(
                err,
                DmStoreError::WrongFileLen {
                    kind: RecordKind::ReceiveCursor,
                    expected,
                    actual: RECEIVE_CURSOR_LEN,
                } if expected == RecordKind::ReceiveCursor.on_disk_len()
            ),
            "got {err:?}"
        );
    }

    /// Two writes of the *same* cursor value are two different records.
    ///
    /// **The cursor is where a nonce repeat would land first.** It is the
    /// store's highest-frequency write and its payload is eight bytes with almost
    /// no entropy, so a fixed nonce under one key leaks the XOR of two page
    /// numbers directly and, worse, makes the file byte-identical whenever the
    /// value is — turning "did this correspondence advance?" back into something
    /// readable without a key, which is the whole disclosure #389 closed.
    ///
    /// Stated over the nonce prefix *and* over the whole record: the prefix is
    /// what a constant-nonce mutation changes, and the whole record is what a
    /// mutation reusing a *drawn* nonce for a second write would change. Neither
    /// alone is enough.
    #[test]
    fn two_writes_of_one_cursor_value_are_two_different_records() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(19);
        let same = 77u64.to_be_bytes();
        let path = tmp.path().join("dm").join(l.dir_name()).join("cursor.bin");

        let mut seen: Vec<Vec<u8>> = Vec::new();
        for _ in 0..4 {
            s.critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::ReceiveCursor, &same)
            })
            .unwrap();
            let raw = std::fs::read(&path).unwrap();
            assert_eq!(
                raw.len(),
                RecordKind::ReceiveCursor.on_disk_len(),
                "the record is not a sealed record's width"
            );
            seen.push(raw);
        }
        assert_eq!(seen.len(), 4, "the loop must have written four records");

        for (i, a) in seen.iter().enumerate() {
            for b in seen.iter().skip(i + 1) {
                assert_ne!(
                    a[..NONCE_LEN],
                    b[..NONCE_LEN],
                    "two writes of one value drew the same nonce"
                );
                assert_ne!(a, b, "two writes of one value are byte-identical on disk");
            }
        }

        // Positive control: the value really is the same each time, so the
        // differences above are the nonce and not a changing payload.
        assert_eq!(
            s.read_unlocked(&l, RecordKind::ReceiveCursor)
                .unwrap()
                .as_deref(),
            Some(&same[..])
        );
    }

    /// Reopening the store reads the same cursor back.
    ///
    /// `round_trip_per_kind` writes and reads through one `DmStore`, which holds
    /// the derived key in memory for the whole test. This one drops that store
    /// and derives the key again from the at-rest secret, so what it pins is that
    /// the key is a pure function of that secret rather than anything a single
    /// open happened to hold.
    ///
    /// **What kills it, and what does not.** Zero-filling the sealed payload kills
    /// this and twenty other tests, so it evidences nothing about this one. The
    /// faithful control is an ephemeral per-open key — mixing random bytes into
    /// `derive_store_key`'s HKDF info — which kills exactly five tests: this one
    /// and four about profile records and the orphan sweep, none of which touches
    /// the cursor. That is the class this test is the cursor's member of.
    #[test]
    fn a_sealed_cursor_survives_reopening_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let l = label(16);
        let bytes = 4_242u64.to_be_bytes();

        {
            let s = store(tmp.path());
            s.critical_section::<_, DmStoreError>(&l, |g| {
                g.replace(RecordKind::ReceiveCursor, &bytes)
            })
            .unwrap();
        }

        let reopened = store(tmp.path());
        assert_eq!(
            reopened
                .read_unlocked(&l, RecordKind::ReceiveCursor)
                .unwrap()
                .as_deref(),
            Some(&bytes[..]),
            "the cursor did not survive a reopen"
        );
    }

    /// A sealed cursor copied into another correspondence's directory does not
    /// open there.
    ///
    /// The AAD binds the correspondence label as well as the kind, so the seal
    /// is what stops a cursor being moved between correspondences — the same
    /// property every other kind has had, and the one the plaintext cursor had
    /// none of: before #389 the same eight bytes were valid in any directory.
    #[test]
    fn a_sealed_cursor_does_not_open_in_another_correspondence() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let mine = label(17);
        let theirs = label(18);

        s.critical_section::<_, DmStoreError>(&mine, |g| {
            g.replace(RecordKind::ReceiveCursor, &7u64.to_be_bytes())
        })
        .unwrap();
        // The other correspondence exists and holds a cursor of its own, so the
        // copy below overwrites a real record rather than creating a directory.
        s.critical_section::<_, DmStoreError>(&theirs, |g| {
            g.replace(RecordKind::ReceiveCursor, &1u64.to_be_bytes())
        })
        .unwrap();

        let dir = |l: &CorrespondenceLabel| tmp.path().join("dm").join(l.dir_name());
        let lifted = std::fs::read(dir(&mine).join("cursor.bin")).unwrap();

        // Positive control: it opens where it was sealed.
        assert!(
            s.read_unlocked(&mine, RecordKind::ReceiveCursor)
                .unwrap()
                .is_some()
        );

        std::fs::write(dir(&theirs).join("cursor.bin"), &lifted).unwrap();
        let err = s
            .read_unlocked(&theirs, RecordKind::ReceiveCursor)
            .expect_err("a cursor from another correspondence must not open");
        assert!(
            matches!(
                err,
                DmStoreError::NotAuthentic {
                    kind: RecordKind::ReceiveCursor
                }
            ),
            "got {err:?}"
        );
    }

    // ---- invariant 4: the orphan sweep -------------------------------------

    /// An orphan is a **complete sealed record**, not a fragment, so the sweep
    /// must scrub it before unlinking — otherwise ciphertext the store promises
    /// to erase leaves by a path that never passes through `delete`.
    ///
    /// The sweep destroys its own byte-level evidence by unlinking, so the
    /// observable is the barrier count — and it is measured **differentially**
    /// against an otherwise identical open with no orphans present. An absolute
    /// threshold would pass vacuously if `open` happened to drive enough barriers
    /// of its own; the delta cannot. `scrub_orphan_zeroes_the_whole_file` holds
    /// the byte-level half.
    #[test]
    fn the_sweep_scrubs_orphans_before_unlinking_them() {
        use crate::storage::atomic_file::file_syncs;

        /// One populated correspondence, optionally with two orphans beside it.
        fn setup(with_orphans: bool) -> (tempfile::TempDir, Vec<std::path::PathBuf>) {
            let tmp = tempfile::tempdir().unwrap();
            let l = label(17);
            let dir = tmp.path().join("dm").join(l.dir_name());
            {
                let s = store(tmp.path());
                s.critical_section::<_, DmStoreError>(&l, |g| {
                    g.replace(RecordKind::Resume, b"alive")
                })
                .unwrap();
            }
            let orphans = if with_orphans {
                let paths = vec![
                    dir.join("resume.bin.tmp.00112233445566778899aabb"),
                    dir.join("outbox.bin.tmp.ffeeddccbbaa998877665544"),
                ];
                for p in &paths {
                    std::fs::write(p, [0xC3u8; 512]).unwrap();
                }
                paths
            } else {
                Vec::new()
            };
            (tmp, orphans)
        }

        // Control: the same open, same record, no orphans. Whatever `open` costs
        // in barriers on its own is measured here rather than guessed at.
        let (control_tmp, _) = setup(false);
        let before = file_syncs();
        let control_store = store(control_tmp.path());
        let baseline = file_syncs() - before;
        drop(control_store);

        let (tmp, orphans) = setup(true);
        assert!(
            orphans.iter().all(|o| o.exists()),
            "positive control: the orphans must be there before the sweep"
        );
        let before = file_syncs();
        let swept = store(tmp.path());
        let measured = file_syncs() - before;

        assert_eq!(
            measured - baseline,
            2,
            "the sweep drove no extra file barrier per orphan — it is unlinking \
             complete sealed records without scrubbing them"
        );
        assert!(
            orphans.iter().all(|o| !o.exists()),
            "the sweep must still remove the orphans"
        );
        drop(swept);
    }

    /// A scrubbed **cursor** must read back as an interrupted erase.
    ///
    /// This is the probe the read-side bound had none of, and the gap was not
    /// cosmetic. While the cursor was 8 unsealed bytes it was the *only* input
    /// that could tell a bounded read from an unbounded one, every other kind
    /// being `NONCE_LEN + LEN_PREFIX + capacity + TAG_LEN` ≥ 33. Sealing it
    /// (#389) took that discriminating power away rather than the property, so
    /// this test pins the cursor's ordinary behaviour and
    /// `record_kinds_admit_a_usable_sentinel` is what holds the bound itself.
    /// Every other `ErasureInterrupted` assertion in the tree
    /// was on a ≥32-byte kind, which is why reverting `read_record` to
    /// `raw.starts_with(ERASURE_SENTINEL)` left the whole suite green: an 8-byte
    /// file cannot start with 32 bytes, so it fell through to the unsealed arm
    /// and came back as `Ok(Some(..))` — a **valid-looking cursor made of
    /// sentinel bytes**.
    #[test]
    fn a_scrubbed_cursor_reads_as_an_interrupted_erase() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(66);
        s.critical_section::<_, DmStoreError>(&l, |g| {
            g.replace(RecordKind::ReceiveCursor, &[0xA5; RECEIVE_CURSOR_LEN])
        })
        .unwrap();

        // Positive control: it reads as a record before the scrub.
        assert!(
            s.read_unlocked(&l, RecordKind::ReceiveCursor)
                .unwrap()
                .is_some(),
            "the cursor must be readable before it is scrubbed"
        );

        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join(RecordKind::ReceiveCursor.file_name());
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        scrub_in_place(&file, &path, RecordKind::ReceiveCursor).unwrap();
        drop(file);

        let err = s
            .read_unlocked(&l, RecordKind::ReceiveCursor)
            .expect_err("a scrubbed cursor must not read as a cursor");
        assert!(
            matches!(
                err,
                DmStoreError::ErasureInterrupted { kind } if kind == RecordKind::ReceiveCursor
            ),
            "wrong error for a scrubbed cursor: {err}"
        );
    }

    /// The truncation itself, driven at widths no [`RecordKind`] has.
    ///
    /// Every kind is 40 bytes or more, so `min(32, on_disk_len)` is a no-op over
    /// the whole enum and deleting it would leave every other test green. This
    /// drives [`sentinel_for_width`] directly, which is the only fixture that
    /// reaches the bound at all.
    #[test]
    fn the_sentinel_never_exceeds_the_record_it_stamps() {
        // The bound: widths below the sentinel's own length. A sentinel wider
        // than the record grows the file, and phase 2's zeroing loop — bounded
        // by the record's length — never runs.
        for width in [1usize, 3, RECEIVE_CURSOR_LEN, ERASURE_SENTINEL.len() - 1] {
            let s = sentinel_for_width(width);
            assert_eq!(s.len(), width, "a {width}-byte record got a wider stamp");
            assert_eq!(s, &ERASURE_SENTINEL[..width]);
        }

        // Positive control: at or above the sentinel's length it is not
        // truncated, so the assertions above are the bound and not a helper
        // that returns short for everything.
        for width in [ERASURE_SENTINEL.len(), 40, 1024] {
            assert_eq!(
                sentinel_for_width(width),
                &ERASURE_SENTINEL[..],
                "a {width}-byte record must get the whole sentinel"
            );
        }

        // And no kind reaches the truncating branch, which is why it needs a
        // fixture of its own: this is the fact that makes every other assertion
        // about the bound vacuous.
        assert_eq!(
            RecordKind::ALL.len(),
            6,
            "the sweep below must not be empty"
        );
        assert!(
            RecordKind::ALL
                .iter()
                .all(|k| k.on_disk_len() >= ERASURE_SENTINEL.len()),
            "a kind is short enough to truncate — fold it back into \
             record_kinds_admit_a_usable_sentinel"
        );
    }

    /// The two floors the bounded sentinel must not cross, named in
    /// [`erasure_sentinel`]'s docs and held here **over the kinds that exist**.
    ///
    /// The nonce floor is the load-bearing one: phase 1's barrier makes the crash
    /// window safe *because* those bytes land on the AEAD nonce. Shortening the
    /// prefix below `NONCE_LEN` would leave a still-openable record across the
    /// window with nothing anywhere failing.
    ///
    /// It does not reach the truncation, which no kind is short enough to
    /// exercise: `the_sentinel_never_exceeds_the_record_it_stamps` drives that
    /// against [`sentinel_for_width`] instead.
    #[test]
    fn record_kinds_admit_a_usable_sentinel() {
        for kind in RecordKind::ALL {
            let sentinel = erasure_sentinel(kind);
            assert!(
                !sentinel.is_empty(),
                "{kind:?}: an empty sentinel makes `starts_with` always true, so \
                 every record of this kind would read as an interrupted erase"
            );
            assert!(
                sentinel.len() >= NONCE_LEN,
                "{kind:?}: the sentinel must cover the AEAD nonce, else a \
                 crash mid-erase leaves an openable record"
            );
        }
    }

    /// A file longer than its kind keeps no unscrubbed tail.
    ///
    /// The `max(declared, actual)` branch had no coverage at all: every other
    /// fixture is exact-width, so `let len = declared` survived the suite — on the
    /// very line whose doc calls the unscrubbed tail the one outcome the function
    /// exists to prevent.
    #[test]
    fn a_longer_than_declared_file_is_scrubbed_to_its_real_length() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(67);
        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Resume, b"k"))
            .unwrap();

        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join(RecordKind::Resume.file_name());

        // Append a tail past the declared width, as a truncated-then-regrown file
        // or a partial overwrite could leave.
        let declared = RecordKind::Resume.on_disk_len();
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(&[0xD7; 1024]);
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(raw.len(), declared + 1024, "fixture is not over-long");

        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        scrub_in_place(&file, &path, RecordKind::Resume).unwrap();
        drop(file);

        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), declared + 1024, "a scrub must not resize");
        assert!(
            after[declared..].iter().all(|&b| b == 0),
            "the tail past the declared length was left unscrubbed"
        );
        // And the tail assertion is not vacuous.
        assert_eq!(after[declared..].len(), 1024);
    }

    /// The byte-level half of the orphan claim: zeroed end to end, and no
    /// sentinel — a sentinel names an interrupted erase *to a reader*, and
    /// nothing ever reads a temp sibling as a record.
    #[test]
    fn scrub_orphan_zeroes_the_whole_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("resume.bin.tmp.0123456789abcdef01234567");
        let secret = [0xC3u8; 4096];
        std::fs::write(&path, secret).unwrap();

        // Positive control: the payload is genuinely there first.
        let before = std::fs::read(&path).unwrap();
        assert!(before.contains(&0xC3), "nothing to scrub");

        scrub_orphan(&path).unwrap();

        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), before.len(), "a scrub must not resize");
        assert!(
            after.iter().all(|&b| b == 0),
            "the orphan kept payload bytes"
        );
    }

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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();

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

        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Correspondence)
        {
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
        // Directories, not entries: the root also holds the profile records and
        // the profile lock, which `DmStore::open` creates for every store and
        // which say nothing about any correspondence.
        let probes = RecordKind::ALL
            .iter()
            .filter(|k| k.scope() == RecordScope::Correspondence)
            .count();
        let (dirs, files) = root_entries(&root);
        assert!(
            dirs.is_empty(),
            "the store root must name no correspondence after {probes} probes: {dirs:?}"
        );
        assert_eq!(
            files,
            expected_root_files(),
            "and must hold exactly the profile lock and the profile records"
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
        let (dirs, files) = root_entries(&root);
        assert!(
            dirs.is_empty(),
            "the store root must name no correspondence after an enumeration: {dirs:?}"
        );
        assert_eq!(
            files,
            expected_root_files(),
            "and must hold exactly the profile lock and the profile records"
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

    /// A label's directory name reads back as the same label, and the reader
    /// accepts nothing else. Without the second half the store would list a
    /// correspondence under a name it could never have written.
    #[test]
    fn a_label_round_trips_through_its_directory_name() {
        for seed in [0u8, 1, 0x5A, 0xFF] {
            let l = label(seed);
            let name = l.dir_name();
            assert_eq!(
                CorrespondenceLabel::from_dir_name(std::ffi::OsStr::new(&name)),
                Some(l),
                "a label's own directory name did not read back"
            );
        }

        // The forms that must be refused, each a different way of being not the
        // name `dir_name` writes.
        let name = label(0xAB).dir_name();
        for bad in [
            String::new(),
            name[..name.len() - 1].to_string(),
            format!("{name}0"),
            name.to_uppercase(),
            format!("{}g", &name[..name.len() - 1]),
            "not-a-label".to_string(),
        ] {
            assert_eq!(
                CorrespondenceLabel::from_dir_name(std::ffi::OsStr::new(&bad)),
                None,
                "{bad:?} was read as a correspondence label"
            );
        }
    }

    /// The enumerator names exactly the correspondences that were established:
    /// not the profile lock, not the profile records, and not a directory whose
    /// name no label produces.
    #[test]
    fn correspondences_names_every_established_correspondence_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let root = tmp.path().join("dm");

        // A store that has only ever been opened holds the profile lock and the
        // profile records, and no correspondence — so an answer that included
        // either would be visible here before anything else is written.
        assert!(
            s.correspondences().unwrap().is_empty(),
            "a store with no correspondence named one"
        );
        assert_eq!(
            root_entries(&root),
            (Vec::new(), expected_root_files()),
            "the fixture is not the root this test assumes"
        );

        // This test does not assert the ordering — the set is what it is
        // checking, and a fixture whose creation order happened to match
        // `read_dir`'s would make an ordering assertion here pass for free.
        // `correspondences_are_sorted_whatever_order_they_were_created` owns
        // that, and checks its own fixture before asserting.
        let established = [label(30), label(31), label(32)];
        for l in &established {
            s.critical_section::<_, DmStoreError>(l, |_| Ok(()))
                .unwrap();
        }
        // One of them holds a record and the others hold none: a directory is
        // the correspondence, and an empty one is still established.
        s.critical_section::<_, DmStoreError>(&established[1], |g| {
            g.replace(RecordKind::Outbox, b"owed")
        })
        .unwrap();

        // Names that must not be read as correspondences: a directory of the
        // right length that is not hex, the same label in upper case, and one
        // character short.
        let real = established[0].dir_name();
        for stray in [
            "not-a-correspondence".to_string(),
            real.to_uppercase(),
            real[..real.len() - 1].to_string(),
        ] {
            std::fs::create_dir(root.join(stray)).unwrap();
        }

        // And a *file* whose name is a perfectly good label: a correspondence is
        // a directory, so the name test alone is not the whole filter.
        std::fs::write(root.join(label(33).dir_name()), b"not a correspondence").unwrap();

        let mut want: Vec<String> = established.iter().map(|l| l.dir_name()).collect();
        want.sort();
        let got: Vec<String> = s
            .correspondences()
            .unwrap()
            .iter()
            .map(|l| l.dir_name())
            .collect();
        assert_eq!(got, want);
    }

    /// No profile record's file name, and not the lock's, reads as a
    /// correspondence label — the guard against a future
    /// [`RecordScope::Profile`] kind whose file name nobody re-checked.
    ///
    /// **What this covers, stated exactly, because it is narrower than it
    /// looks.** Every real name here is refused on its *length* alone. The final
    /// loop stretches each to a label's exact length — the shape a future kind
    /// would need before length stopped saving us — and those are refused by the
    /// character class, but `hex::decode_to_slice` behind it would refuse them
    /// equally, so **no case in this test uniquely kills the character class**:
    /// deleting it leaves every assertion here passing, as a mutation run
    /// confirmed. The class's one unique job is refusing *upper-case* hex, which
    /// the decoder accepts, and
    /// `a_label_round_trips_through_its_directory_name`'s `to_uppercase` case is
    /// the sole thing that kills its deletion.
    #[test]
    fn no_profile_record_name_can_be_read_as_a_correspondence() {
        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Profile)
        {
            assert_eq!(
                CorrespondenceLabel::from_dir_name(std::ffi::OsStr::new(kind.file_name())),
                None,
                "{kind:?}'s file name reads as a correspondence label"
            );
        }
        assert_eq!(
            CorrespondenceLabel::from_dir_name(std::ffi::OsStr::new(LOCK_FILE_NAME)),
            None,
            "the profile lock's name reads as a correspondence label"
        );

        // Positive control: the loop above ran over something, and the assertion
        // it makes is one a label would fail.
        assert!(
            RecordKind::ALL
                .into_iter()
                .any(|k| k.scope() == RecordScope::Profile),
            "no profile-scoped kind exists, so the loop asserted nothing"
        );

        // The case that does reach the character class: the length gate cannot
        // be what refuses these.
        for kind in RecordKind::ALL
            .into_iter()
            .filter(|k| k.scope() == RecordScope::Profile)
        {
            let name: String = kind
                .file_name()
                .chars()
                .cycle()
                .take(2 * CORRESPONDENCE_LABEL_LEN)
                .collect();
            assert_eq!(name.len(), 2 * CORRESPONDENCE_LABEL_LEN);
            assert_eq!(
                CorrespondenceLabel::from_dir_name(std::ffi::OsStr::new(&name)),
                None,
                "{name:?} passed the character class"
            );
        }
    }

    /// **Determinism is asserted rather than inherited from the filesystem, and
    /// the fixture proves it can tell the difference before asserting anything.**
    ///
    /// The obvious version of this test — establish them in descending order and
    /// assert the answer is ascending — is not portable and was actively wrong
    /// here: `read_dir` on this tmpfs returns neither insertion order nor sorted
    /// order (it came back reverse-of-insertion), so seeding descending made the
    /// *unsorted* answer already sorted and the mutation survived. There is no
    /// creation order that is safe to assume. So the raw order is **read** and
    /// checked: if it already matches sorted order the fixture cannot detect a
    /// missing sort, and this fails as a fixture defect rather than passing.
    #[test]
    fn correspondences_are_sorted_whatever_order_they_were_created() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let root = tmp.path().join("dm");
        let scattered = [
            label(0x5A),
            label(0x0A),
            label(0xF0),
            label(0x33),
            label(0x91),
            label(0x02),
            label(0xCC),
            label(0x40),
        ];
        for l in &scattered {
            s.critical_section::<_, DmStoreError>(l, |_| Ok(()))
                .unwrap();
        }

        let mut want: Vec<String> = scattered.iter().map(|l| l.dir_name()).collect();
        want.sort();

        // The control, and it is the whole point: what `read_dir` hands the
        // enumerator, in its own order, restricted to the correspondences.
        let raw: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| want.contains(n))
            .collect();
        assert_eq!(raw.len(), scattered.len(), "the control lost an entry");
        assert_ne!(
            raw, want,
            "this filesystem already returns the correspondences sorted, so the \
             fixture cannot detect a missing sort"
        );

        assert_eq!(
            s.correspondences()
                .unwrap()
                .iter()
                .map(|l| l.dir_name())
                .collect::<Vec<_>>(),
            want
        );
    }

    /// **A correspondence reached through a symlink is a correspondence**, and
    /// the reason is agreement with the reader: `read_record` goes through
    /// `std::fs::read`, which follows symlinks, so an enumerator that did not
    /// would report absence for a record the store reads perfectly well — and
    /// the caller's remedy for absence is to establish a *second* correspondence
    /// for the same identity. Contrast `sweep_root_orphans`, which must not
    /// follow one because it deletes what it finds.
    #[test]
    fn a_correspondence_behind_a_symlink_is_enumerated_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let root = tmp.path().join("dm");
        let l = label(44);

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(RecordKind::Outbox, b"owed"))
            .unwrap();

        // Relocate the directory out of the root and symlink it back — the
        // ordinary "this disk is full" move.
        let elsewhere = tmp.path().join("relocated");
        std::fs::rename(root.join(l.dir_name()), &elsewhere).unwrap();
        assert_eq!(
            s.correspondences().unwrap(),
            Vec::new(),
            "the relocated correspondence is still listed, so the symlink proves nothing"
        );
        std::os::unix::fs::symlink(&elsewhere, root.join(l.dir_name())).unwrap();

        assert_eq!(
            s.correspondences().unwrap(),
            vec![l],
            "a correspondence the store can read was not enumerated"
        );
        // And the reader agrees, which is the whole point of following.
        assert_eq!(
            s.read_unlocked(&l, RecordKind::Outbox).unwrap().as_deref(),
            Some(&b"owed"[..])
        );

        // A symlink to a *file* is still not a correspondence: following resolves
        // the target's kind, it does not accept any link.
        let target = tmp.path().join("a-file");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, root.join(label(45).dir_name())).unwrap();
        assert_eq!(
            s.correspondences().unwrap(),
            vec![l],
            "a symlink to a file was enumerated as a correspondence"
        );

        // A dangling symlink named as a label is absence, not an error.
        std::os::unix::fs::symlink(
            tmp.path().join("nothing-here"),
            root.join(label(46).dir_name()),
        )
        .unwrap();
        assert_eq!(
            s.correspondences().unwrap(),
            vec![l],
            "a dangling symlink was enumerated as a correspondence"
        );
    }

    /// **An IO error that is not absence is propagated, not read as "no such
    /// correspondence".** The drivable half of that rule: a symlink into an
    /// unsearchable directory makes `metadata` fail with `PermissionDenied`,
    /// which is exactly the shape of failure that must never be mistaken for a
    /// correspondence not existing — the caller's remedy for absence is to mint
    /// a second label for an identity that already has one.
    ///
    /// Skipped when the tests run as root, which searches a `000` directory
    /// regardless. Nothing is asserted in that case, and the assertion below is
    /// what says so out loud rather than passing quietly.
    #[test]
    fn an_unreadable_correspondence_is_an_error_rather_than_an_absent_one() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let root = tmp.path().join("dm");

        let blocked = tmp.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        let target = blocked.join("real");
        std::fs::create_dir(&target).unwrap();
        let l = label(48);
        std::os::unix::fs::symlink(&target, root.join(l.dir_name())).unwrap();

        // Positive control: while the parent is searchable it enumerates, so the
        // refusal below is the permission and not the symlink.
        assert_eq!(s.correspondences().unwrap(), vec![l]);

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let answer = s.correspondences();
        // **Probed while the mode is still 000.** Reading it after the restore
        // below always says the directory is searchable, which silently turns
        // this whole test into an early return — it passed under a mutation that
        // swallows the error before that was caught.
        let mode_is_enforced = std::fs::metadata(&target).is_err();
        // Restore before asserting, so a failure does not leave an undeletable
        // tempdir behind.
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).unwrap();

        if !mode_is_enforced {
            // Root, or a filesystem ignoring the mode. Say so; do not pass.
            eprintln!("skipped: this user can search a 000 directory");
            return;
        }
        match answer.expect_err("an unreadable correspondence was reported as absent") {
            DmStoreError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// **A store root that is not there is an error, not an empty list.**
    /// Answering absence would tell `correspondence_for_pk_lt`'s caller that an
    /// identity it corresponds with is unknown, and the remedy for unknown is to
    /// mint a second label — manufacturing the very ambiguity the lookup exists
    /// to detect, through the enumeration meant to prevent it.
    #[test]
    fn a_vanished_store_root_is_an_error_rather_than_no_correspondences() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(47);
        s.critical_section::<_, DmStoreError>(&l, |_| Ok(()))
            .unwrap();

        // Positive control: it answers before the root goes.
        assert_eq!(s.correspondences().unwrap(), vec![l]);

        std::fs::remove_dir_all(tmp.path().join("dm")).unwrap();
        match s
            .correspondences()
            .expect_err("a vanished store root was reported as no correspondences")
        {
            DmStoreError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("wrong error: {other:?}"),
        }
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

    /// A contact record survives the whole path — encoded by its own module,
    /// padded and sealed by the store, written, read, unpadded and decoded —
    /// with every stored field intact and the file at the kind's fixed size.
    ///
    /// Compared field by field rather than as bytes, because the fields are what
    /// a caller uses. The stored root is read back through
    /// `ContactRecord::address_root`, the only accessor over it.
    #[test]
    fn a_contact_record_round_trips_through_the_store() {
        use crate::dm::contact_cache::ContactRecord;
        use crate::dm::firstcontact::ROOT_LEN;
        use oxicrypt_ml_dsa as ml_dsa;

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let l = label(31);
        let kind = RecordKind::ContactCache;

        let pk_lt: Box<[u8; ml_dsa::PK_LEN]> = Box::new([0x11u8; ml_dsa::PK_LEN]);
        let pk_pc: Box<[u8; ml_dsa::PK_LEN]> = Box::new([0x22u8; ml_dsa::PK_LEN]);
        assert_ne!(pk_lt, pk_pc, "the fixture's two keys are the same key");
        // Byte-distinct, so a field written or read reversed does not round-trip
        // by coincidence — the same control the two public keys carry.
        let mut ar = [0u8; ROOT_LEN];
        for (i, b) in ar.iter_mut().enumerate() {
            *b = 0x33u8.wrapping_add(i as u8 * 5);
        }
        const FIRST: i64 = 1_700_000_000_000;
        const LAST: i64 = 1_700_000_999_999;
        assert_ne!(FIRST, LAST, "the two timestamps are the same value");

        let encoded = ContactRecord::new(
            pk_lt.clone(),
            Some(pk_pc.clone()),
            zeroize::Zeroizing::new(ar),
            FIRST,
            LAST,
        )
        .unwrap()
        .encode();
        assert_eq!(encoded.len(), kind.capacity(), "the bucket is the record");

        s.critical_section::<_, DmStoreError>(&l, |g| g.replace(kind, &encoded))
            .unwrap();

        let path = tmp
            .path()
            .join("dm")
            .join(l.dir_name())
            .join("contact-cache.bin");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            kind.on_disk_len(),
            "a contact record must be one fixed size on disk"
        );

        // `Locked::read` hands back a plain `Vec<u8>`, and for this kind that
        // payload is the cleartext address root. `decode` takes a `Zeroizing` buffer so the
        // wrapping cannot be forgotten; this is what that looks like at a call site.
        let read = zeroize::Zeroizing::new(
            s.critical_section::<_, DmStoreError>(&l, |g| g.read(kind))
                .unwrap()
                .expect("the record is there"),
        );
        assert_eq!(*read, *encoded, "the store handed back other bytes");

        let reopened = ContactRecord::decode(&read).expect("decodes");
        assert_eq!(reopened.pk_lt(), pk_lt.as_ref());
        assert_eq!(reopened.pk_pc(), Some(pk_pc.as_ref()));
        assert_eq!(reopened.first_seen_ms(), FIRST);
        assert_eq!(reopened.last_seen_ms(), LAST);
        assert_eq!(
            reopened.address_root(),
            ar,
            "the address root did not survive the store"
        );
    }

    /// **The oracle for what protects a contact record.** The record carries no
    /// seal of its own, so the store's AAD is the whole of its binding: without
    /// it, copying one correspondence's contact record over another's would open
    /// cleanly and hand a signature check the wrong pseudonym key.
    ///
    /// `a_record_from_another_correspondence_does_not_open` makes this point for
    /// `Resume`. It is made again here rather than assumed, because this kind is
    /// the one with nothing behind the store to catch a splice.
    #[test]
    fn a_contact_record_from_another_correspondence_does_not_open() {
        use crate::dm::contact_cache::ContactRecord;
        use crate::dm::firstcontact::ROOT_LEN;
        use oxicrypt_ml_dsa as ml_dsa;

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let (a, b) = (label(32), label(33));
        let kind = RecordKind::ContactCache;

        let encode = |tag: u8| {
            ContactRecord::new(
                Box::new([tag; ml_dsa::PK_LEN]),
                Some(Box::new([tag ^ 0xFF; ml_dsa::PK_LEN])),
                zeroize::Zeroizing::new([tag; ROOT_LEN]),
                1_700_000_000_000,
                1_700_000_000_001,
            )
            .unwrap()
            .encode()
        };

        s.critical_section::<_, DmStoreError>(&a, |g| g.replace(kind, &encode(0xA1)))
            .unwrap();
        s.critical_section::<_, DmStoreError>(&b, |g| g.replace(kind, &encode(0xB2)))
            .unwrap();

        let root = tmp.path().join("dm");
        let a_path = root.join(a.dir_name()).join("contact-cache.bin");
        let b_path = root.join(b.dir_name()).join("contact-cache.bin");
        let a_bytes = std::fs::read(&a_path).unwrap();

        // Positive control: A's own bytes back in A's slot still open, so the
        // failure below is the AAD binding and not the copy itself.
        std::fs::write(&a_path, &a_bytes).unwrap();
        let back = zeroize::Zeroizing::new(
            s.critical_section::<_, DmStoreError>(&a, |g| g.read(kind))
                .unwrap()
                .expect("A's record is there"),
        );
        assert_eq!(
            ContactRecord::decode(&back).unwrap().pk_lt(),
            &[0xA1u8; ml_dsa::PK_LEN],
            "the control read back a different correspondence's record"
        );

        std::fs::write(&b_path, &a_bytes).unwrap();
        let err = s
            .critical_section::<_, DmStoreError>(&b, |g| g.read(kind))
            .unwrap_err();
        assert!(
            matches!(err, DmStoreError::NotAuthentic { .. }),
            "a contact record spliced from another correspondence must fail to \
             open, got {err:?}"
        );

        // And the same record under another profile's key: the second half of
        // what the store is doing for a kind that seals nothing itself.
        std::fs::write(&a_path, &a_bytes).unwrap();
        let theirs = DmStore::open(&root, &OTHER_AT_REST).unwrap();
        let err = theirs
            .critical_section::<_, DmStoreError>(&a, |g| g.read(kind))
            .unwrap_err();
        assert!(
            matches!(err, DmStoreError::NotAuthentic { .. }),
            "another profile's key opened a contact record, got {err:?}"
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
