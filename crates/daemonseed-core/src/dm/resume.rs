//! The re-establishment resume record: everything a reconnect needs that a
//! restart would otherwise destroy (A9.2, part of ISC-C39 / ISC-A-C21).
//!
//! Design of record: `docs/design/direct-messaging.md`, **Amendment A9**
//! (RATIFIED 2026-07-30), § A9.2 in particular, plus § A4's enumeration at
//! `:1061` and the store's atomicity contract in A8.2.
//!
//! A channel that goes down mid-re-establishment has to come back holding
//! *exactly* what it held before, and A9.1 makes that literal: a re-emit of an
//! already-persisted attempt is the **byte-identical persisted seal**. ML-KEM
//! encapsulation is randomized and `ss → eph_ct` is not invertible, so that
//! seal cannot be reproduced from its key inputs — it has to have been written
//! down. That single fact is why this record exists and why it is one blob
//! rather than several.
//!
//! ## One write, not seven
//!
//! A9.2's field list is not a bag of related values; it is the **set that must
//! agree with itself**. A crash that paired a committed root with a stale
//! attempt would re-emit under a key the peer will never confirm, and the
//! divergence is permanent — `RatchetError::UnknownEphemeral`
//! ([`crate::dm::ratchet`]) with no path back. So every field travels in one
//! [`ResumeRecord`], written by one `replace_atomically` through
//! [`crate::storage::dm_store`], and there is no API here that writes a part of
//! it. "Commit-then-emit is provably a single atomic act" is a property of
//! there being nothing else to call.
//!
//! ## The two high-waters are not both here, and that is the point
//!
//! A9.2 names them apart because A8.2 had collided them, and they have
//! **opposite durability**:
//!
//! | | lives | scope | here? |
//! |---|---|---|---|
//! | **send-side floor** ([`SendFloor`]) | durable, in this record | the conversation | **yes** |
//! | receive-side peer high-water | the ratchet, in RAM | one session, reset per `chan_id` | **no** |
//!
//! The receive side is discharged by loud teardown and bounded by eviction; a
//! copy of it here would be a second answer to a question the ratchet already
//! answers, free to disagree with it and with no oracle to say which was right
//! — the objection `dm::collect` raises against keeping a second cursor. There
//! is deliberately **no field** for it, so a future edit that wants one has to
//! add it on purpose rather than fill one in.
//!
//! ## What this module does not do
//!
//! It holds bytes and orders two integers. It seals nothing, derives nothing,
//! reads no clock and encapsulates nothing: [`ResumeRecord::encode`] is
//! plaintext, and `dm_store` seals it, pads it to the kind's fixed bucket and
//! refuses an oversized payload — the same split [`crate::dm::outbox`] uses.

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError};
use crate::dm::frame::MAX_FRAME_LEN;
use crate::dm::ratchet::ROOT_KEY_LEN;
use crate::secret_seed::redacted_secret_newtype;
use oxicrypt_ml_dsa as ml_dsa;

/// At-rest magic. The version is **inside** it, so a decoder compares one thing
/// and cannot read an older body under a newer header — the shape
/// [`crate::dm::outbox`] and [`crate::dm::provisional`] both use.
pub const RESUME_MAGIC: &[u8] = b"daemonseed/dm/resume/v1\0";

/// Width of the suite-id field, big-endian, immediately after the magic.
pub const SUITE_ID_LEN: usize = 2;

/// Every fixed-width field of the encoding, in order, so the worst case below
/// is arithmetic rather than a guess.
const FIXED_LEN: usize = RESUME_MAGIC.len()
    + SUITE_ID_LEN
    + ml_dsa::SK_LEN /* s_pc */
    + ml_dsa::PK_LEN /* pk_pc */
    + ROOT_KEY_LEN /* committed_root */
    + 4 /* attempt */
    + 4 /* send_floor.generation */
    + 8 /* send_floor.seq */
    + 8 /* window_anchor_ms */
    + 4 /* toward_c */
    + 8 /* sealed RE-EST length prefix */;

/// The largest [`ResumeRecord::encode`] output this build can produce.
///
/// **Computed, not estimated.** Every field but one is fixed-width, and the one
/// that is not is bounded by [`MAX_FRAME_LEN`] — which
/// [`ResumeRecord::new`] refuses to exceed, so this is a real ceiling rather
/// than a typical case. [`crate::storage::dm_store::RESUME_CAPACITY`] is sized
/// against it, and `the_capacity_holds_the_worst_case` pins the relationship in
/// the direction that matters: if a field is added here and the constant is not
/// revisited, that test fails rather than a write failing on a user's disk.
pub const MAX_ENCODED_LEN: usize = FIXED_LEN + MAX_FRAME_LEN;

/// What can go wrong building or decoding a resume record.
#[derive(Debug, PartialEq, Eq)]
pub enum ResumeError {
    /// A sealed RE-EST frame longer than [`MAX_FRAME_LEN`]. Refused at
    /// construction as well as at decode, so an oversized record has no
    /// spelling rather than being caught one layer later by the store.
    FrameTooLong { len: usize },
    /// The at-rest bytes started with no magic this build recognises.
    BadMagic,
    /// The at-rest bytes ended inside a field.
    Truncated,
    /// Trailing bytes after the record.
    TrailingBytes(usize),
    /// The suite id in the header is one of the registry's reserved sentinels.
    SuiteIdSentinel(SuiteIdError),
    /// The suite id names no entry in this build's registry, so the record was
    /// written by a build whose primitives this one does not implement.
    UnknownSuite(SuiteId),
    /// A [`SendFloor`] that does not advance on the one it replaces. The stored
    /// floor is returned alongside so a caller can report both.
    FloorWouldRollBack {
        stored: SendFloor,
        offered: SendFloor,
    },
    /// A record offered under an earlier `attempt` than the stored one.
    AttemptWouldRollBack { stored: u32, offered: u32 },
    /// A record offered under an `attempt` that is already persisted, carrying
    /// **different** sealed RE-EST bytes.
    ///
    /// A9.1: a re-emit of an already-persisted attempt is always the
    /// byte-identical persisted seal, and a fresh secret is permitted only under
    /// a **new** attempt. The peer dedups on `attempt` (A9.4), so it has already
    /// seen the first seal and will drop the second as a duplicate — leaving the
    /// recovering party holding a secret the peer will never confirm, which is
    /// the permanent `UnknownEphemeral` divergence
    /// ([`crate::dm::ratchet`]) A9.1 exists to forbid.
    AttemptResealed { attempt: u32 },
}

impl std::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLong { len } => {
                write!(
                    f,
                    "a sealed RE-EST frame of {len} bytes exceeds {MAX_FRAME_LEN}"
                )
            }
            Self::BadMagic => write!(f, "not a resume record"),
            Self::Truncated => write!(f, "the resume record ends inside a field"),
            Self::TrailingBytes(n) => write!(f, "{n} bytes after the record"),
            Self::SuiteIdSentinel(e) => write!(f, "resume suite_id: {e}"),
            Self::UnknownSuite(id) => {
                write!(f, "resume suite {id} is not in this build's registry")
            }
            Self::AttemptWouldRollBack { stored, offered } => {
                write!(f, "attempt {offered} is behind the stored attempt {stored}")
            }
            Self::AttemptResealed { attempt } => write!(
                f,
                "attempt {attempt} is already persisted under different sealed bytes"
            ),
            Self::FloorWouldRollBack { stored, offered } => write!(
                f,
                "send floor {}:{} does not advance on the stored {}:{}",
                offered.generation(),
                offered.seq(),
                stored.generation(),
                stored.seq()
            ),
        }
    }
}

impl std::error::Error for ResumeError {}

redacted_secret_newtype! {
    /// The committed re-establishment root.
    ///
    /// Distinct from [`RootKey`](crate::dm::ratchet::RootKey) on purpose: that
    /// is the running ratchet's root, advanced and destroyed as its successor
    /// appears, and this is the one a re-establishment **committed** — the value
    /// a resuming party must fold from, not the value it is currently using.
    /// Giving them one type would let a caller persist a live ratchet root here,
    /// which is the forward secrecy `dm::ratchet` deletes chains to protect.
    inline pub struct CommittedRoot([u8; ROOT_KEY_LEN]);
}

impl CommittedRoot {
    /// Wrap raw bytes. The caller is handing over a secret; nothing here copies
    /// it anywhere that does not zeroize.
    pub fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// The send-side floor: how far this party's own sequence numbers have gone,
/// qualified by the generation they went there under.
///
/// **The field order IS the comparison.** `derive(Ord)` on a struct compares
/// fields in declaration order, so `generation` first and `seq` second gives
/// exactly A9.2's lexicographic rule with no hand-written comparison to get
/// wrong — and no way to write a comparison that disagrees with the encoding,
/// since the encoder walks the same order.
///
/// **Why the generation is carried at all.** A9.2's stated reason is that a
/// committed re-establishment root starts a new generation "under which send
/// `seq` legitimately restarts at 0", so an unqualified floor would read the
/// restart as a rollback. **That premise does not hold against the ratchet as
/// built**: `Ratchet::step_send` starts a new generation's chain at the current
/// `next_send_seq` and never resets it, so send `seq` is monotone for the life
/// of the conversation. The qualification is kept anyway, and the reasoning is
/// recorded here rather than left to be rediscovered:
///
/// 1. A9.2 ratifies the lexicographic ordering, and it is the ordering a
///    re-establishment path that *does* restart `seq` would need. Building the
///    weaker thing now would have to be found and undone later, by someone who
///    no longer has this paragraph.
/// 2. The ordering being lexicographic does **not** make it a safe write guard
///    on its own — `(5, 0)` outranks `(4, u64::MAX)`, so a bare `>=` admits a
///    sequence rollback across a generation bump. That is why
///    [`Self::admits`] requires both components to be non-decreasing rather
///    than deferring to [`Ord`]. An earlier draft of this comment claimed
///    lexicographic ordering "contains plain `seq` ordering — every rollback a
///    bare counter catches, this catches"; that is **false**, it was caught in
///    review, and it is recorded here because it is the exact reasoning error
///    that would justify deleting the guard.
///
/// So do not "simplify" the generation away on the grounds that the stated
/// justification does not hold. The justification is wrong; the field is right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SendFloor {
    generation: u32,
    seq: u64,
}

impl SendFloor {
    /// The floor at a generation and sequence.
    pub fn new(generation: u32, seq: u64) -> Self {
        Self { generation, seq }
    }

    /// The generation this floor was reached under.
    pub fn generation(self) -> u32 {
        self.generation
    }

    /// How far this party's own sequence numbers have gone.
    pub fn seq(self) -> u64 {
        self.seq
    }

    /// The later of two floors, or [`ResumeError::FloorWouldRollBack`] if the
    /// offered one is not later.
    ///
    /// **Equal is refused, not accepted.** A floor that has not moved is not
    /// evidence of progress, and accepting it would let a caller persist a write
    /// that reports success while advancing nothing — the shape #278 records one
    /// module over. A caller with genuinely nothing to advance has no reason to
    /// write.
    pub fn advance_to(self, offered: Self) -> Result<Self, ResumeError> {
        if offered > self {
            Ok(offered)
        } else {
            Err(ResumeError::FloorWouldRollBack {
                stored: self,
                offered,
            })
        }
    }

    /// Whether a record carrying `offered` may replace one carrying `self`.
    ///
    /// **Deliberately weaker than [`Self::advance_to`], and the difference is
    /// not an oversight.** That call advances the floor and refuses a value
    /// that stands still, because standing still is not progress. This one
    /// guards a *record write*, and a resume record is rewritten for reasons
    /// that have nothing to do with the send side — a new `attempt`, a new
    /// window anchor, a fresh toward-`C` count. Refusing an unmoved floor here
    /// would refuse those writes, so the invariant this enforces is the only one
    /// that is actually true of the send side: **it never goes backwards.**
    ///
    /// **Both components must be non-decreasing, and that is deliberately
    /// stricter than [`Ord`].** Lexicographically `(5, 0)` outranks
    /// `(4, u64::MAX)`, so an `offered >= self` guard would admit a floor whose
    /// sequence dropped by up to 2⁶⁴ as long as the generation went up — and
    /// against the ratchet as built, where send `seq` never restarts, that is a
    /// real rollback of spent sequences rather than the false alarm A9.2's
    /// qualification exists to avoid. Writing the floor as `(G+1, 0)` is exactly
    /// what A9.2's own restart-at-0 prose invites, which is what makes this the
    /// dangerous spelling rather than a theoretical one.
    ///
    /// So the ordering stays lexicographic as A9.2 ratifies — that is what
    /// [`Ord`] and [`Self::advance_to`] use — and only this **write guard** is
    /// conservative. If the unbuilt re-establishment path does restart `seq`,
    /// relaxing this to the plain comparison is then a deliberate, reviewed
    /// change rather than a hole nobody notices. The question is filed.
    pub fn admits(self, offered: Self) -> bool {
        offered.generation >= self.generation && offered.seq >= self.seq
    }
}

/// Everything a re-establishment needs to survive a restart, in one blob.
///
/// **Every field here is one A9.2 enumerates**, and the list is closed: the
/// module docs give the argument for what is deliberately absent.
///
/// The secret halves zero on drop. `s_pc` is a per-correspondent ML-DSA-87
/// signing key that is **at-rest only and not mnemonic-derivable** (§ Keys), so
/// unlike the long-term identity there is no re-derivation path — losing this
/// record loses the ability to sign as that pseudonym at all, which is why the
/// key is in it rather than being fetched from somewhere on resume.
#[derive(ZeroizeOnDrop)]
pub struct ResumeRecord {
    /// **Ours**, and secret: the per-correspondent signing key `msg_sig` is
    /// produced under. Without it every leg we send after the restart is
    /// unsignable.
    s_pc: Box<[u8; ml_dsa::SK_LEN]>,
    /// **The peer's**, and public: the verifying key every inbound leg's
    /// `msg_sig` is checked against. Without it an inbound leg fails signature
    /// check and is indistinguishable from filler (A4, `:1061`).
    #[zeroize(skip)]
    pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
    /// The re-establishment root this party has committed to.
    committed_root: CommittedRoot,
    /// Which attempt this record describes. The peer dedups a re-emit on it
    /// (A9.4), and A9.1 permits a fresh secret only under a **new** one.
    #[zeroize(skip)]
    attempt: u32,
    /// The durable send-side floor. See [`SendFloor`].
    #[zeroize(skip)]
    send_floor: SendFloor,
    /// The re-establishment window's anchor, in the caller's clock.
    #[zeroize(skip)]
    window_anchor_ms: i64,
    /// How far this correspondence has progressed toward `C`.
    #[zeroize(skip)]
    toward_c: u32,
    /// **The sealed RE-EST frame, verbatim.** A9.1(a) requires a re-emit of a
    /// persisted attempt to be the byte-identical persisted seal, and A9.2 makes
    /// this field load-bearing for it: ML-KEM encapsulation is randomized and
    /// `ss → eph_ct` is not invertible, so these bytes cannot be rebuilt from
    /// the key inputs. Recovery re-emits *this*, not a fresh encapsulation.
    #[zeroize(skip)]
    sealed_re_est: Box<[u8]>,
}

impl std::fmt::Debug for ResumeRecord {
    /// Redacted by hand rather than derived: `s_pc` is a signing key and
    /// `committed_root` is a root, so one `debug!(?record)` would put both in a
    /// log — the defect `dm::firstcontact` records for a decrypted body.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumeRecord")
            .field("s_pc", &"<redacted>")
            .field("pk_pc", &"<peer verifying key>")
            .field("committed_root", &self.committed_root)
            .field("attempt", &self.attempt)
            .field("send_floor", &self.send_floor)
            .field("window_anchor_ms", &self.window_anchor_ms)
            .field("toward_c", &self.toward_c)
            .field("sealed_re_est_len", &self.sealed_re_est.len())
            .finish()
    }
}

impl ResumeRecord {
    /// Build a record. Refuses a sealed frame past [`MAX_FRAME_LEN`].
    ///
    /// **All of it or none of it.** There is no builder and no field setter:
    /// the fields have to agree with each other, so the only way to have a
    /// record is to have supplied every part of one at the same moment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        s_pc: Box<[u8; ml_dsa::SK_LEN]>,
        pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
        committed_root: CommittedRoot,
        attempt: u32,
        send_floor: SendFloor,
        window_anchor_ms: i64,
        toward_c: u32,
        sealed_re_est: Box<[u8]>,
    ) -> Result<Self, ResumeError> {
        if sealed_re_est.len() > MAX_FRAME_LEN {
            return Err(ResumeError::FrameTooLong {
                len: sealed_re_est.len(),
            });
        }
        Ok(Self {
            s_pc,
            pk_pc,
            committed_root,
            attempt,
            send_floor,
            window_anchor_ms,
            toward_c,
            sealed_re_est,
        })
    }

    /// Our per-correspondent signing key.
    pub fn s_pc(&self) -> &[u8; ml_dsa::SK_LEN] {
        &self.s_pc
    }

    /// The peer's per-correspondent verifying key.
    pub fn pk_pc(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.pk_pc
    }

    /// The committed re-establishment root.
    pub fn committed_root(&self) -> &CommittedRoot {
        &self.committed_root
    }

    /// Which attempt this record describes.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The durable send-side floor.
    pub fn send_floor(&self) -> SendFloor {
        self.send_floor
    }

    /// The re-establishment window's anchor.
    pub fn window_anchor_ms(&self) -> i64 {
        self.window_anchor_ms
    }

    /// Progress toward `C`.
    pub fn toward_c(&self) -> u32 {
        self.toward_c
    }

    /// The sealed RE-EST frame, borrowed — the same bytes every call, which is
    /// A9.1(a)'s byte-identical re-emit at this layer.
    pub fn sealed_re_est(&self) -> &[u8] {
        &self.sealed_re_est
    }

    /// The at-rest form, plaintext. `dm_store` seals it.
    ///
    /// Field order matches [`Self::decode`] byte for byte, and the one
    /// variable-length field is last so nothing after it depends on its length.
    ///
    /// **`Zeroizing`, because this buffer holds a signing key.** `dm_store`
    /// zeroizes the padded copy it seals from and not the caller's bytes, so a
    /// plain `Vec` here would leave `s_pc` and the committed root in freed heap
    /// on every commit. [`crate::dm::provisional`] wraps its plaintext the same
    /// way on both seal and open, for the same reason.
    ///
    /// **The suite id is stamped at the current default write suite**, so a
    /// record read under an older still-registered suite is re-encoded under
    /// the current one — ISC-C24's read-old-write-new, exactly as
    /// [`crate::dm::outbox`] does it, and it loses nothing because the field
    /// describes the writer rather than the payload.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(FIXED_LEN + self.sealed_re_est.len()));
        out.extend_from_slice(RESUME_MAGIC);
        out.extend_from_slice(&Registry::default_write_suite().get().to_be_bytes());
        out.extend_from_slice(self.s_pc.as_ref());
        out.extend_from_slice(self.pk_pc.as_ref());
        out.extend_from_slice(self.committed_root.as_bytes());
        out.extend_from_slice(&self.attempt.to_be_bytes());
        out.extend_from_slice(&self.send_floor.generation.to_be_bytes());
        out.extend_from_slice(&self.send_floor.seq.to_be_bytes());
        out.extend_from_slice(&self.window_anchor_ms.to_be_bytes());
        out.extend_from_slice(&self.toward_c.to_be_bytes());
        out.extend_from_slice(&(self.sealed_re_est.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.sealed_re_est);
        out
    }

    /// Read the at-rest form back.
    ///
    /// **No clock argument.** `window_anchor_ms` is taken verbatim: nothing in
    /// this build computes a terminal transition from it, so a corrupt value
    /// costs re-establishment timing rather than switching a guarantee off —
    /// the distinction `dm::outbox::Outbox::decode` draws between the give-up
    /// clock and `next_due_ms`.
    ///
    /// **That is a statement about consumers that do not exist yet, so it is a
    /// re-check rather than a settled property.** When the re-establishment
    /// window logic lands, a future-dated anchor is the same clock-rollback
    /// class `Outbox::decode` refuses, and this decision has to be made again
    /// against what actually reads the field.
    ///
    /// The frame length is checked against what remains **before** anything is
    /// reserved, so a corrupt length cannot drive an allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResumeError> {
        let mut r = Reader::new(bytes);
        if r.take(RESUME_MAGIC.len())? != RESUME_MAGIC {
            return Err(ResumeError::BadMagic);
        }
        let suite_raw = u16::from_be_bytes(r.array()?);
        let suite_id = SuiteId::try_new(suite_raw).map_err(ResumeError::SuiteIdSentinel)?;
        if Registry::lookup(suite_id).is_none() {
            return Err(ResumeError::UnknownSuite(suite_id));
        }
        // **Boxed straight from the borrowed input, never through a stack
        // array.** `r.array()` would return `[u8; SK_LEN]` by value — a 4,896-byte
        // copy of a signing key left on the stack after the `Box::new` that
        // follows it. `to_vec()` allocates at exact capacity, so
        // `into_boxed_slice` reuses that allocation rather than copying again,
        // and the conversion to a fixed-size box reuses it a second time.
        let s_pc: Box<[u8; ml_dsa::SK_LEN]> = r
            .take(ml_dsa::SK_LEN)?
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| ResumeError::Truncated)?;
        let pk_pc: Box<[u8; ml_dsa::PK_LEN]> = Box::new(r.array()?);
        let committed_root = CommittedRoot::from_bytes(r.array()?);
        let attempt = u32::from_be_bytes(r.array()?);
        let generation = u32::from_be_bytes(r.array()?);
        let seq = u64::from_be_bytes(r.array()?);
        let window_anchor_ms = i64::from_be_bytes(r.array()?);
        let toward_c = u32::from_be_bytes(r.array()?);
        let len = u64::from_be_bytes(r.array()?);
        let len = usize::try_from(len).map_err(|_| ResumeError::Truncated)?;
        if len > MAX_FRAME_LEN {
            return Err(ResumeError::FrameTooLong { len });
        }
        let sealed_re_est: Box<[u8]> = r.take(len)?.to_vec().into_boxed_slice();
        let rest = r.remaining();
        if rest != 0 {
            return Err(ResumeError::TrailingBytes(rest));
        }
        Ok(Self {
            s_pc,
            pk_pc,
            committed_root,
            attempt,
            send_floor: SendFloor { generation, seq },
            window_anchor_ms,
            toward_c,
            sealed_re_est,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ResumeError> {
        let end = self.at.checked_add(n).ok_or(ResumeError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(ResumeError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResumeError> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("take returned exactly N bytes"))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: i64 = 1_700_000_000_000;

    /// Byte-distinct and position-dependent, so a comparison that sliced,
    /// transposed or truncated could not pass by coincidence.
    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                seed.wrapping_add((i as u8).wrapping_mul(31))
                    .wrapping_add((i >> 8) as u8)
            })
            .collect()
    }

    fn s_pc(seed: u8) -> Box<[u8; ml_dsa::SK_LEN]> {
        Box::new(pattern(seed, ml_dsa::SK_LEN).try_into().unwrap())
    }

    fn pk_pc(seed: u8) -> Box<[u8; ml_dsa::PK_LEN]> {
        Box::new(pattern(seed, ml_dsa::PK_LEN).try_into().unwrap())
    }

    fn root(seed: u8) -> CommittedRoot {
        CommittedRoot::from_bytes(pattern(seed, ROOT_KEY_LEN).try_into().unwrap())
    }

    /// Every field set to a value distinct from every other field's, so a
    /// decoder that crossed two of them fails rather than passing.
    fn populated() -> ResumeRecord {
        ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            7,
            SendFloor::new(4, 100),
            ANCHOR,
            3,
            pattern(0x44, 512).into_boxed_slice(),
        )
        .expect("the fixture is within MAX_FRAME_LEN")
    }

    #[test]
    fn every_field_survives_the_round_trip() {
        let before = populated();
        let after = ResumeRecord::decode(&before.encode()).expect("a fresh encoding must decode");

        assert_eq!(after.s_pc(), before.s_pc());
        assert_eq!(after.pk_pc(), before.pk_pc());
        assert_eq!(
            after.committed_root().as_bytes(),
            before.committed_root().as_bytes()
        );
        assert_eq!(after.attempt(), before.attempt());
        assert_eq!(after.send_floor(), before.send_floor());
        assert_eq!(after.window_anchor_ms(), before.window_anchor_ms());
        assert_eq!(after.toward_c(), before.toward_c());
        assert_eq!(after.sealed_re_est(), before.sealed_re_est());

        // The fixture has to be non-degenerate for any of the above to mean
        // something: two fields holding the same bytes would let a crossed
        // decoder pass.
        assert_ne!(&before.s_pc()[..32], &before.pk_pc()[..32]);
        assert_ne!(&before.pk_pc()[..32], before.committed_root().as_bytes());
        // Every scalar against every other, so a later fixture edit cannot
        // hollow this test by making two of them equal. The earlier guard
        // covered three pairs and left the rest distinct only by accident.
        let scalars: [(&str, u64); 5] = [
            ("attempt", u64::from(before.attempt())),
            ("generation", u64::from(before.send_floor().generation())),
            ("seq", before.send_floor().seq()),
            ("toward_c", u64::from(before.toward_c())),
            ("frame_len", before.sealed_re_est().len() as u64),
        ];
        for (i, (na, a)) in scalars.iter().enumerate() {
            for (nb, b) in &scalars[i + 1..] {
                assert_ne!(a, b, "fixture is degenerate: {na} and {nb} are both {a}");
            }
        }
    }

    /// Every byte accounted for and named — so there is nowhere in this record
    /// a receive-side peer high-water could be hiding, which is the property
    /// A9.2 asks for and the module docs argue for.
    #[test]
    fn the_encoding_has_room_for_nothing_else() {
        let record = populated();
        let encoded = record.encode();
        let named = RESUME_MAGIC.len()
            + SUITE_ID_LEN
            + ml_dsa::SK_LEN
            + ml_dsa::PK_LEN
            + ROOT_KEY_LEN
            + 4 /* attempt */
            + 4 /* generation */
            + 8 /* seq */
            + 8 /* window_anchor_ms */
            + 4 /* toward_c */
            + 8 /* frame length prefix */
            + record.sealed_re_est().len();
        assert_eq!(
            encoded.len(),
            named,
            "a field is present that nothing names"
        );
        assert_eq!(encoded.len(), FIXED_LEN + record.sealed_re_est().len());
    }

    /// A9.2's lexicographic rule, in the direction that matters: a generation
    /// bump outranks any sequence under the previous generation.
    #[test]
    fn the_floor_orders_by_generation_before_sequence() {
        let old = SendFloor::new(4, 100);
        let new_generation = SendFloor::new(5, 0);
        assert!(
            new_generation > old,
            "a generation bump read as a rollback — the exact false alarm the qualification exists to prevent"
        );
        assert_eq!(old.advance_to(new_generation), Ok(new_generation));

        // And within one generation it is an ordinary anti-rollback bound.
        assert!(SendFloor::new(4, 101) > old);
        assert_eq!(
            old.advance_to(SendFloor::new(4, 99)),
            Err(ResumeError::FloorWouldRollBack {
                stored: old,
                offered: SendFloor::new(4, 99)
            })
        );
    }

    /// The two guards differ on the one case that separates them, and each is
    /// used where its rule is the true one.
    #[test]
    fn admits_accepts_the_standstill_that_advance_to_refuses() {
        let floor = SendFloor::new(4, 100);

        // The case they disagree on.
        assert!(
            floor.admits(floor),
            "a record rewrite with an unmoved floor was refused"
        );
        assert!(
            floor.advance_to(floor).is_err(),
            "standing still counted as progress"
        );

        // And they agree everywhere else, in both directions — so the
        // difference is exactly the standstill and not a second divergence.
        let later = SendFloor::new(4, 101);
        assert!(floor.admits(later) && floor.advance_to(later).is_ok());
        let earlier = SendFloor::new(4, 99);
        assert!(!floor.admits(earlier) && floor.advance_to(earlier).is_err());
    }

    /// Standing still is not progress, and is refused rather than silently
    /// accepted.
    #[test]
    fn an_unmoved_floor_is_refused() {
        let stored = SendFloor::new(4, 100);
        assert_eq!(
            stored.advance_to(stored),
            Err(ResumeError::FloorWouldRollBack {
                stored,
                offered: stored
            })
        );
    }

    /// An earlier generation never outranks a later one however far its
    /// sequence ran — the half a bare sequence counter gets wrong.
    #[test]
    fn a_high_sequence_under_an_old_generation_does_not_outrank_a_new_one() {
        let new_generation = SendFloor::new(5, 0);
        let old_but_far = SendFloor::new(4, u64::MAX);
        assert!(old_but_far < new_generation);
        assert!(new_generation.advance_to(old_but_far).is_err());
    }

    /// **The write guard does NOT defer to that ordering.** A generation bump
    /// carrying a lower sequence is lexicographically "later" and is still a
    /// rollback of spent sequences against the ratchet as built, so `admits`
    /// refuses it while `Ord` ranks it higher. The two disagreeing here is the
    /// design, not an inconsistency — see `SendFloor::admits`.
    #[test]
    fn a_generation_bump_may_not_smuggle_a_sequence_rollback() {
        let stored = SendFloor::new(4, 100);
        let bumped_but_lower = SendFloor::new(5, 0);

        assert!(
            bumped_but_lower > stored,
            "the ordering is no longer lexicographic, so this pins nothing"
        );
        assert!(
            !stored.admits(bumped_but_lower),
            "a generation bump smuggled a sequence rollback past the write guard"
        );
        // A bump that also carries the sequence forward is fine — the guard
        // refuses the rollback, not the bump.
        assert!(stored.admits(SendFloor::new(5, 100)));
        assert!(stored.admits(SendFloor::new(5, 101)));
    }

    /// The store's bucket holds the worst case this module can produce. Sized
    /// against `MAX_ENCODED_LEN` rather than against a typical record, so a
    /// field added here fails this test instead of failing a write on a disk.
    #[test]
    fn the_capacity_holds_the_worst_case() {
        // The bucket relationship itself is a `const` assertion in `dm_store`,
        // where both constants live and where the build can enforce it. What is
        // genuinely a runtime fact, and all this test asserts, is that the bound
        // is REAL rather than generous: a record actually built at the frame
        // ceiling encodes to exactly it.
        let at_ceiling = ResumeRecord::new(
            s_pc(0x11),
            pk_pc(0x22),
            root(0x33),
            1,
            SendFloor::new(0, 0),
            ANCHOR,
            0,
            pattern(0x44, MAX_FRAME_LEN).into_boxed_slice(),
        )
        .expect("a frame of exactly MAX_FRAME_LEN is allowed");
        assert_eq!(at_ceiling.encode().len(), MAX_ENCODED_LEN);
    }

    #[test]
    fn an_oversized_frame_is_refused_at_construction_and_at_decode() {
        let too_long = MAX_FRAME_LEN + 1;
        assert_eq!(
            ResumeRecord::new(
                s_pc(0x11),
                pk_pc(0x22),
                root(0x33),
                1,
                SendFloor::new(0, 0),
                ANCHOR,
                0,
                pattern(0x44, too_long).into_boxed_slice(),
            )
            .err(),
            Some(ResumeError::FrameTooLong { len: too_long })
        );

        // The decoder cannot lean on the constructor, because the bytes it reads
        // did not come through it. A corrupt length is refused BEFORE anything
        // is reserved, so it cannot drive an allocation.
        let mut bytes = populated().encode();
        let len_at = FIXED_LEN - 8;
        bytes[len_at..len_at + 8].copy_from_slice(&(too_long as u64).to_be_bytes());
        assert_eq!(
            ResumeRecord::decode(&bytes).err(),
            Some(ResumeError::FrameTooLong { len: too_long })
        );
    }

    #[test]
    fn the_decoder_refuses_malformed_records() {
        let good = populated().encode();
        assert!(ResumeRecord::decode(&good).is_ok(), "positive control");

        let mut alien = good.clone();
        alien[0] ^= 1;
        assert_eq!(
            ResumeRecord::decode(&alien).err(),
            Some(ResumeError::BadMagic)
        );

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            ResumeRecord::decode(&trailing).err(),
            Some(ResumeError::TrailingBytes(1))
        );

        // Every prefix ends inside a field. Truncation is the one failure a
        // reader cannot detect by looking at a single field, so it is checked
        // exhaustively rather than at a sampled offset.
        for cut in 0..good.len() {
            assert!(
                ResumeRecord::decode(&good[..cut]).is_err(),
                "a record truncated at {cut} decoded"
            );
        }
    }

    /// One `debug!(?record)` must not put a signing key or a root in a log.
    #[test]
    fn debug_redacts_both_secret_halves() {
        let record = populated();
        let shown = format!("{record:?}");
        // **Named per field, not a bare substring search.** An earlier version
        // asserted only that the output contained `<redacted>` somewhere — which
        // `CommittedRoot(<redacted>)` satisfies on its own, so it said nothing
        // whatever about `s_pc`. A review mutation printing the signing key
        // verbatim passed the whole test.
        assert!(
            shown.contains(r#"s_pc: "<redacted>""#),
            "the signing key field is not redacted: {shown}"
        );
        assert!(
            shown.contains("committed_root: CommittedRoot(<redacted>)"),
            "the committed root field is not redacted: {shown}"
        );
        // Positive control: the non-secret fields ARE shown, so the assertions
        // above are not passing because `Debug` prints nothing useful.
        assert!(shown.contains("attempt: 7"), "Debug shows nothing at all");
        assert!(shown.contains("sealed_re_est_len: 512"));

        // **The byte backstop is format-agnostic, because the previous one was
        // not.** It matched lowercase hex only, while Rust's derived `Debug` for
        // `[u8; N]` prints DECIMAL — so it missed exactly the rendering the
        // compiler emits by default, which is the one a mistake would produce.
        let head = &record.s_pc()[..8];
        for rendering in [
            head.iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            head.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            head.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        ] {
            assert!(
                !shown.contains(&rendering),
                "the signing key's bytes reached the Debug output as {rendering}"
            );
        }
    }

    /// The suite id is validated, not merely read past. Deleting the check
    /// outright was invisible to the suite until these two cases existed.
    #[test]
    fn a_record_naming_an_unusable_suite_is_refused() {
        let at = RESUME_MAGIC.len();

        let mut sentinel = populated().encode().to_vec();
        sentinel[at..at + SUITE_ID_LEN].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            matches!(
                ResumeRecord::decode(&sentinel),
                Err(ResumeError::SuiteIdSentinel(_))
            ),
            "a reserved sentinel suite id was accepted"
        );

        // A well-formed id this build's registry does not know — a record from a
        // build whose primitives we do not implement.
        let mut unknown = populated().encode().to_vec();
        // NOT `u16::MAX`: that is the reserved SENTINEL_MAX and would take the
        // branch above instead, which is how the first draft of this test passed
        // its sentinel case and failed its unknown one.
        unknown[at..at + SUITE_ID_LEN].copy_from_slice(&0xFFFEu16.to_be_bytes());
        assert!(
            matches!(
                ResumeRecord::decode(&unknown),
                Err(ResumeError::UnknownSuite(_))
            ),
            "an unregistered suite id was accepted"
        );

        // Positive control: the same bytes with the suite untouched decode.
        assert!(ResumeRecord::decode(&populated().encode()).is_ok());
    }
}
