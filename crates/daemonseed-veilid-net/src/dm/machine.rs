//! The DM driver's decision half: pure step functions returning effects.
//!
//! The machine reads no clock and performs no I/O over the DHT. Each step takes
//! the wall time its caller read and returns what should happen, so ordering and
//! cadence decisions are checkable by value rather than by racing paused time —
//! the same split [`crate::route_budget`] and [`crate::schedule`] are built on.
//!
//! One deliberate impurity: the machine owns its [`DmPersist`], because that
//! store's mutation API is designed to be called at the mutation site and a
//! temporary directory is available to every test. The seam is over what a test
//! cannot have — the DHT — not over disk.
//!
//! ## What is here, and what is not
//!
//! Three planes, all of them decided here. The **doorbell**: our own doorbell is
//! swept on the cadence, every populated slot goes through [`Admitter`] in its
//! documented order, an admitted knock from a stranger is held until the user
//! answers it, and an outbound knock is composed, proof-minted off the loop and
//! published. The **channel**: due outbox entries are emitted on their re-seed
//! ladder, the pages [`Collection::probe_plan`] names are swept, and a frame
//! that opens and verifies becomes a message. The **acknowledgement**: what this
//! side collected is written on a tapering standalone cadence under a
//! client-global allowance, and what the correspondent collected is folded from
//! its piggyback or its record and settles this side's outbox.
//!
//! What is NOT here is anything that reads a clock or touches the DHT. Both
//! arrive as arguments, which is what makes every decision above checkable by
//! value.

use std::sync::Arc;
use std::time::Duration;

use daemonseed_core::dm::ack::{AckState, PeerAck, PeerAckOutcome};
use daemonseed_core::dm::ack_budget::{AckPermit, StandaloneAckBudget};
use daemonseed_core::dm::ack_cadence::{self, StandaloneAckCadence};
use daemonseed_core::dm::ack_record::{self, DmAckAddress};
use daemonseed_core::dm::admission::{AdmissionCounters, AdmissionOutcome, Admitter, SeenSet};
use daemonseed_core::dm::block_list::{BlockList, BlockListError};
use daemonseed_core::dm::collect::Collection;
use daemonseed_core::dm::doorbell;
use daemonseed_core::dm::firstcontact::{
    self, recipient_hash, FirstContactError, FirstContactRequest, FirstContactState,
    VerifiedFirstContact, AR_FINGERPRINT_LEN, ROOT_LEN,
};
use daemonseed_core::dm::frame::{self, AuthorKeys, WORST_CASE_SEALED_FRAME_LEN};
use daemonseed_core::dm::keyrec::KEM_EK_LEN;
use daemonseed_core::dm::keyrec::{
    self, DmKeyRecordError, KeyRecordCache, DM_KEYREC_OWNER_SEED_LEN,
};
use daemonseed_core::dm::outbox::{
    DeliveryState, Lifecycle, OutboxEntry, OutboxError, OutboxTarget, ReseedSchedule, SealedFrame,
    GIVE_UP_MS,
};
use daemonseed_core::dm::paging::{
    position_of, DmPageAddress, PagePosition, Receiving, Sending, ADDRESS_ROOT_LEN, PAGE_SLOTS,
};
use daemonseed_core::dm::persist::{
    DmPersist, DmPersistError, Mutation, StateLoss, StoredChannelRestart,
};
use daemonseed_core::dm::pow;
use daemonseed_core::dm::provisional::{RecordContext, TeardownCause};
use daemonseed_core::dm::ratchet::{
    Direction, Ratchet, RatchetError, ReconnectSide, Role, FIRST_RECIPIENT_CHANNEL_SEQ,
};
use daemonseed_core::dm::reest::{self, AttemptBudget, ContestOutcome, ReEstAdmission, ReEstGate};
use daemonseed_core::dm::resume::{
    AcceptanceSlot, Attempt, CommittedRoot, ConfirmSlot, DedupKey, Leg, Novelty, OwnSlot,
    ReEstState, Rerooted, ResumeRecord, Retention, SealedReEst, SendFloor, T_RETIRE_MS,
};
use daemonseed_core::dm::token::SpentTokenSet;
use daemonseed_core::identity::keys::{SignKeypair, IDENTITY_PK_LEN, ML_DSA_SEED_LEN};
use daemonseed_core::storage::dm_store::CorrespondenceLabel;
use daemonseed_core::trust_events::TrustEventKey;

use crate::actor::{DmPageRecord, DmPageSweep, DoorbellDispatch, DoorbellSweep};
use crate::dm::driver::{DmDriverConfig, SpentTokenStore};
use crate::dm::types::{
    AcceptFailure, DmCommand, DmEvent, DmIdentity, PkLt, RefusalReason, RequestId,
};

/// How many verified knocks may be held awaiting an answer.
///
/// A held request owns a [`VerifiedFirstContact`], which carries the sender's
/// keys, the conversation secret and the message — so the bound is on memory an
/// unanswered stranger can make us hold. Past it a knock is dropped at the
/// sweep and surfaces nothing; the sender re-seeds on their own schedule, so a
/// request refused for room here reappears once the user has cleared some.
pub const PENDING_REQUEST_CAP: usize = 64;

/// Consecutive faulty re-arm attempts after which a stored handshake is treated
/// as unusable.
///
/// **Small on purpose.** Each attempt costs two sealed reads and the thing it is
/// waiting for is a store that recovers within a tick or two; a record still
/// unreadable after this many is one nothing is going to repair, and reading it
/// for the rest of the session buys nothing. What giving up costs is the
/// acceptance for one entry, which the correspondent's own re-seed offers again.
const REARM_FAULT_CEILING: u8 = 8;

/// Consecutive faulty attempts after which a collected acceptance's pseudonym
/// stops being written.
///
/// **Small for the reason above, and giving up costs something different.** The
/// re-arm gives up an acceptance the correspondent will offer again; this gives
/// up the disk's memory of a conversation that has already verified, so the
/// contact record is left torn and the next accept or knock for that identity
/// repairs it. Both are bounded because the thing being waited on is a store
/// that recovers within a tick or two, and neither is worth a sealed read on
/// every tick for the rest of the session.
const PSEUDONYM_WRITE_FAULT_CEILING: u8 = 8;

/// The sending-direction sequence number the first-contact knock occupies.
///
/// The same number as
/// [`FIRST_RECIPIENT_CHANNEL_SEQ`](daemonseed_core::dm::ratchet::FIRST_RECIPIENT_CHANNEL_SEQ)
/// and a different fact: that one is the acceptor's first channel *send*, this
/// is the initiator's knock. They are spelled apart because only one of them is
/// carried by doorbell, and confusing the two settles a position on the wrong
/// direction.
const KNOCK_CHANNEL_SEQ: u64 = 0;

/// How many distinct send times one correspondence's pending set holds.
///
/// The set is what the standalone taper is measured against, and a correspondent
/// decides how many messages go into it — so without a ceiling a flood buys
/// unbounded memory per conversation, inside one give-up window, from a party who
/// only has to keep writing.
///
/// **The overflow drops the SECOND-NEWEST, so the oldest and the newest both
/// survive.** The oldest is the taper's key and the newest is what says anything
/// is still live at all: dropping either would change an answer, where dropping
/// from the middle only makes the interval more conservative for a while — fewer
/// writes, which is the fail-safe side of a cadence.
const PENDING_SENT_CAP: usize = 256;

/// One thing the shell should do as a result of a step.
///
/// Its [`Debug`] names the variant and, for an event, the event's own redacted
/// rendering. A `DhtOp` is shown by its kind alone: the ops carry sealed
/// entries and boxed owner seeds, and a step's effects are exactly what a
/// failing assertion prints.
pub(crate) enum DmEffect {
    /// Spawn one DHT operation off the loop.
    Dht(DhtOp),
    /// Send one event to the front end.
    Emit(DmEvent),
    /// Run one CPU-bound job off the loop, on a blocking thread.
    Compute(ComputeJob),
}

impl core::fmt::Debug for DmEffect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DmEffect::Dht(op) => write!(f, "Dht({})", op.kind().name()),
            DmEffect::Emit(event) => write!(f, "Emit({event:?})"),
            DmEffect::Compute(ComputeJob::MintFirstContact(_)) => {
                f.write_str("Compute(MintFirstContact)")
            }
            DmEffect::Compute(ComputeJob::SaveSpentTokens(_)) => {
                f.write_str("Compute(SaveSpentTokens)")
            }
        }
    }
}

/// What a DHT operation belongs to, carried out and handed back unchanged so the
/// machine can attribute an outcome without remembering dispatch order.
pub(crate) struct OpTag {
    /// The conversation's `AR` fingerprint, where the operation has one.
    ///
    /// The doorbell plane has no conversation until a knock is accepted; every
    /// channel-plane operation carries one, and it is what a page sweep's
    /// outcome is attributed by.
    pub conversation: Option<[u8; AR_FINGERPRINT_LEN]>,
    /// The message sequence number, where the operation has one — an outbox
    /// emission, so the write's outcome can confirm the entry that produced it.
    pub seq: Option<u64>,
    /// The page a sweep addressed.
    ///
    /// **Carried rather than recovered from the result**, because an empty page
    /// comes back with no position in it and a page number is exactly what
    /// [`Collection::observe_page`] needs. Recovering it from the first
    /// populated slot would work on every page that had something in it and
    /// silently do nothing on the ones that did not.
    pub page: Option<u64>,
    /// The correspondent a channel-plane write belongs to.
    ///
    /// **Distinct from `conversation`, and needed because they have different
    /// lifetimes.** A conversation fingerprint exists only while a ratchet does;
    /// a queued doorbell entry outlives one, and its write still has to be
    /// confirmed against the entry it came from.
    pub correspondent: Option<PkLt>,
    /// The correspondent an in-flight introduction is addressed to.
    ///
    /// A first contact has no conversation yet — that is what it is for — so
    /// the key-record fetch it starts with cannot be attributed by
    /// `conversation`. The recipient's own identity key is what names it.
    pub introduction: Option<PkLt>,
}

impl OpTag {
    /// A tag naming nothing — the doorbell sweep, which belongs to no
    /// conversation and to no introduction.
    pub(crate) fn none() -> Self {
        Self {
            conversation: None,
            seq: None,
            page: None,
            correspondent: None,
            introduction: None,
        }
    }

    /// A tag naming one in-flight introduction.
    fn introduction(recipient: PkLt) -> Self {
        Self {
            conversation: None,
            seq: None,
            page: None,
            correspondent: None,
            introduction: Some(recipient),
        }
    }

    /// A tag naming one conversation, and optionally the sequence number or the
    /// page the operation is about.
    fn channel(
        conversation: [u8; AR_FINGERPRINT_LEN],
        seq: Option<u64>,
        page: Option<u64>,
    ) -> Self {
        Self {
            conversation: Some(conversation),
            seq,
            page,
            correspondent: None,
            introduction: None,
        }
    }
}

impl core::fmt::Debug for OpTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The introduction's `PkLt` names a person; only its presence is shown.
        f.debug_struct("OpTag")
            .field("conversation", &self.conversation.map(|_| "<AR>"))
            .field("seq", &self.seq)
            .field("page", &self.page)
            .field(
                "correspondent",
                &self.correspondent.as_ref().map(|_| "PkLt(..)"),
            )
            .field(
                "introduction",
                &self.introduction.as_ref().map(|_| "PkLt(..)"),
            )
            .finish()
    }
}

/// One DHT operation, as the machine asks for it.
pub(crate) enum DhtOp {
    /// Fetch a correspondent's key record.
    FetchKeyRecord { tag: OpTag, owner_seed: [u8; 32] },
    /// Write one sealed first-contact entry into a recipient's doorbell.
    PublishDoorbell {
        tag: OpTag,
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
    },
    /// Sweep our own doorbell.
    SweepDoorbell { tag: OpTag, owner_seed: [u8; 32] },
    /// Publish one sealed channel frame.
    PublishPage {
        tag: OpTag,
        address: DmPageAddress<Sending>,
        frame: Vec<u8>,
    },
    /// Sweep one receiving page.
    SweepPage {
        tag: OpTag,
        address: DmPageAddress<Receiving>,
    },
    /// Give one channel page's record back (#252).
    ///
    /// Direction-erased, unlike the two operations above, because a close acts on
    /// the record rather than on its contents: a sending page and a receiving one
    /// are given back the same way, and the type that separates them exists to stop
    /// a *read* or a *write* going to the wrong stream.
    ClosePage { tag: OpTag, address: DmPageRecord },
    /// Publish one direction's acknowledgement record.
    PublishAck {
        tag: OpTag,
        address: DmAckAddress,
        record: Vec<u8>,
    },
    /// Fetch the correspondent's acknowledgement.
    FetchAck { tag: OpTag, address: DmAckAddress },
}

/// Which of the eight operations an outcome came from.
///
/// **A tag cannot answer this and is not meant to.** A tag names what the
/// operation belongs to — a conversation, an introduction — and a doorbell sweep
/// belongs to neither, so it is tagged with nothing at all. An `Err` carrying
/// only that tag is indistinguishable from every other untagged failure, which
/// is exactly the case where the machine has to know a sweep is no longer in
/// flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DhtOpKind {
    FetchKeyRecord,
    PublishDoorbell,
    SweepDoorbell,
    PublishPage,
    SweepPage,
    PublishAck,
    FetchAck,
    ClosePage,
}

impl DhtOpKind {
    /// This kind's name, for a trace line that carries no payload.
    pub(crate) fn name(self) -> &'static str {
        match self {
            DhtOpKind::FetchKeyRecord => "FetchKeyRecord",
            DhtOpKind::PublishDoorbell => "PublishDoorbell",
            DhtOpKind::SweepDoorbell => "SweepDoorbell",
            DhtOpKind::PublishPage => "PublishPage",
            DhtOpKind::SweepPage => "SweepPage",
            DhtOpKind::PublishAck => "PublishAck",
            DhtOpKind::FetchAck => "FetchAck",
            DhtOpKind::ClosePage => "ClosePage",
        }
    }
}

impl DhtOp {
    /// This operation's kind.
    pub(crate) fn kind(&self) -> DhtOpKind {
        match self {
            DhtOp::FetchKeyRecord { .. } => DhtOpKind::FetchKeyRecord,
            DhtOp::PublishDoorbell { .. } => DhtOpKind::PublishDoorbell,
            DhtOp::SweepDoorbell { .. } => DhtOpKind::SweepDoorbell,
            DhtOp::PublishPage { .. } => DhtOpKind::PublishPage,
            DhtOp::SweepPage { .. } => DhtOpKind::SweepPage,
            DhtOp::PublishAck { .. } => DhtOpKind::PublishAck,
            DhtOp::FetchAck { .. } => DhtOpKind::FetchAck,
            DhtOp::ClosePage { .. } => DhtOpKind::ClosePage,
        }
    }

    /// The tag this operation carries.
    fn tag(&self) -> &OpTag {
        match self {
            DhtOp::FetchKeyRecord { tag, .. }
            | DhtOp::PublishDoorbell { tag, .. }
            | DhtOp::SweepDoorbell { tag, .. }
            | DhtOp::PublishPage { tag, .. }
            | DhtOp::SweepPage { tag, .. }
            | DhtOp::PublishAck { tag, .. }
            | DhtOp::FetchAck { tag, .. }
            | DhtOp::ClosePage { tag, .. } => tag,
        }
    }

    /// What the shell should record about this operation before spawning it, so
    /// a task that panics can still release whatever the machine is holding for
    /// it.
    ///
    /// **The page operation is decided first, and the introduction takes whatever
    /// it does not claim.** Testing the introduction first would be correct only
    /// for as long as no sweep or page write ever carries one — which holds while
    /// an introduction's operations are a key-record fetch and a doorbell write —
    /// and the day one did, the record slot it was holding would leak with nothing
    /// reporting it.
    ///
    /// A page sweep or page write whose tag is missing its conversation or its page
    /// names no slot to release, so it **falls through** to the introduction rather
    /// than to nothing: ordering the two must not make either case narrower than it
    /// was, and a partial tag is exactly where that is easy to do by accident.
    pub(crate) fn panicked_job(&self) -> Option<PanickedJob> {
        let page_op = match self {
            DhtOp::SweepDoorbell { .. } => Some(PanickedJob::DoorbellSweep),
            DhtOp::SweepPage { tag, .. } => match (tag.conversation, tag.page) {
                (Some(conversation), Some(page)) => {
                    Some(PanickedJob::PageSweep { conversation, page })
                }
                _ => None,
            },
            // A page WRITE holds a slot too, since #252: `publishing_pages` is what
            // stops the close path handing a record back mid-write, and a dead write
            // that released nothing would hold it for the life of the driver.
            DhtOp::PublishPage { tag, .. } => match (tag.conversation, tag.page) {
                (Some(conversation), Some(page)) => {
                    Some(PanickedJob::PagePublish { conversation, page })
                }
                _ => None,
            },
            _ => None,
        };
        page_op.or_else(|| {
            self.tag()
                .introduction
                .as_ref()
                .map(|pk| PanickedJob::Dht(Box::new(**pk)))
        })
    }
}

/// What one completed DHT operation yielded.
pub(crate) enum DhtResult {
    /// A key-record fetch; `None` is the awaiting-key state.
    KeyRecord(Option<Vec<u8>>),
    /// A write completed.
    Written,
    /// A doorbell sweep.
    Doorbell(DoorbellSweep),
    /// A page sweep.
    Page(DmPageSweep),
    /// An acknowledgement fetch; `None` is no confirmation yet.
    Ack(Option<Vec<u8>>),
    /// An acknowledgement write completed.
    ///
    /// **Deliberately not [`Self::Written`]**, which every other write maps to.
    /// A page or doorbell write confirms the outbox entry its tag names; an
    /// acknowledgement write has no entry, and what it advances instead is the
    /// receiver's own standalone cadence. Folding the two would either advance
    /// the cadence on a page write or leave it un-advanced on its own, and the
    /// second is the expensive one: a cadence that never records its write
    /// re-asks on every tick and spends the client-global allowance on one
    /// conversation.
    AckWritten,
    /// A page record was handed back — `true` where one was actually closed.
    ///
    /// `false` is not a failure: a page nobody opened, one the transport's own
    /// capacity bound already reclaimed, and one an operation is still holding all
    /// answer it. See `VeilidNetHandle::close_dm_page`.
    Closed(bool),
}

/// One completed DHT operation, tagged with what asked for it.
pub(crate) struct DhtOutcome {
    /// Which operation produced it.
    ///
    /// **Carried rather than recovered from the result**, because the failure
    /// paths have no result to recover it from: an `Err` is one error type for
    /// all eight operations, and the doorbell sweep's tag names nothing. A sweep
    /// the machine cannot recognise on its way back is a sweep it goes on
    /// believing is in flight, and a record whose sweep is permanently in flight
    /// is a record this driver never reads again.
    pub kind: DhtOpKind,
    /// The tag the machine attached to the operation.
    pub tag: OpTag,
    /// The operation's result.
    pub result: crate::Result<DhtResult>,
}

/// One CPU-bound job, as the machine asks for it.
///
/// Separate from [`DhtOp`] because the shell runs it on a **blocking** thread
/// rather than as an ordinary task: the proof of work inside
/// [`firstcontact::build`] takes seconds at production difficulty, and a driver
/// that ran it on its own loop would stop answering commands, stop sweeping and
/// stop ticking for the whole of it.
pub(crate) enum ComputeJob {
    /// Compose and proof-mint one first-contact entry.
    MintFirstContact(Box<MintRequest>),
    /// Seal the spent-token set over its file.
    ///
    /// Off the loop for the same reason a mint is: the seal runs Argon2id, which
    /// is hundreds of milliseconds at honest parameters and seconds at cautious
    /// ones, and on the driver's own task that is the whole client's DM going
    /// quiet for the duration.
    SaveSpentTokens(Box<SaveSpentRequest>),
}

/// One spent-token write, owned so the job is `'static`.
pub(crate) struct SaveSpentRequest {
    /// Where and under what the set is sealed.
    pub store: SpentTokenStore,
    /// The set as it stood when the write was decided.
    pub set: SpentTokenSet,
}

impl core::fmt::Debug for SaveSpentRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SaveSpentRequest")
            .field("entries", &self.set.len())
            .finish_non_exhaustive()
    }
}

/// Everything one first-contact mint needs, owned, so the job is `'static`.
pub(crate) struct MintRequest {
    /// The recipient's long-term identity key.
    pub recipient: PkLt,
    /// Our long-term signing key, which signs `bind_lt`.
    pub signing_lt: Arc<SignKeypair>,
    /// The pseudonym minted for this correspondent, which signs `msg_sig` and
    /// will sign every message of the conversation.
    ///
    /// Handed back on [`MintOutcome`] rather than dropped with the request: it
    /// signs every later frame of this conversation, so a mint that consumed it
    /// would leave the channel unable to speak.
    pub signing_pc: SignKeypair,
    /// The recipient's static encapsulation key, from their verified record.
    pub kem_ek_b: Box<[u8; KEM_EK_LEN]>,
    /// The recipient's key-record owner seed — what the seal and the proof both
    /// bind, and what the provisional record is sealed under.
    pub recipient_keyrec_addr: [u8; DM_KEYREC_OWNER_SEED_LEN],
    /// The first-contact epoch, bound by the seal and by the proof.
    pub fc_epoch: u64,
    /// Our claimed compose time, in unix milliseconds.
    pub sent_unix_ms: i64,
    /// The first message.
    pub body: String,
    /// The difficulty to mint at.
    pub difficulty: pow::PowDifficulty,
}

impl core::fmt::Debug for MintRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The body is plaintext and both keypairs hold secret halves.
        f.debug_struct("MintRequest")
            .field("recipient", &"PkLt(..)")
            .field("fc_epoch", &self.fc_epoch)
            .field("sent_unix_ms", &self.sent_unix_ms)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// What one first-contact mint produced, carried back with what the machine
/// needs in order to place it.
pub(crate) struct MintOutcome {
    /// The recipient the entry was composed for.
    pub recipient: PkLt,
    /// The pseudonym the entry was signed with, returned so the conversation
    /// keeps it.
    pub signing_pc: SignKeypair,
    /// The epoch it was composed in — the provisional record's context.
    pub fc_epoch: u64,
    /// The recipient's key-record owner seed — the rest of that context.
    pub recipient_keyrec_addr: [u8; DM_KEYREC_OWNER_SEED_LEN],
    /// The sealed entry and the state the sender must keep.
    pub result: Result<(Vec<u8>, FirstContactState), FirstContactError>,
}

impl core::fmt::Debug for MintOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The entry is a sealed knock and the state holds the opening ephemeral.
        f.debug_struct("MintOutcome")
            .field("recipient", &"PkLt(..)")
            .field("fc_epoch", &self.fc_epoch)
            .field(
                "result",
                &match &self.result {
                    Ok((entry, _)) => format!("Ok({} bytes)", entry.len()),
                    Err(e) => format!("Err({e})"),
                },
            )
            .finish_non_exhaustive()
    }
}

/// One completed off-loop operation, of either kind.
///
/// Both arms reach [`DmMachine::on_outcome`], because both are "something the
/// shell was asked to do, finished": giving the mint its own step function
/// would duplicate the attribution the tag already performs.
#[derive(Debug)]
pub(crate) enum DmOutcome {
    /// A DHT operation.
    Dht(DhtOutcome),
    /// A first-contact mint.
    Mint(Box<MintOutcome>),
    /// A spent-token write. `Err` carries the rendered failure.
    SpentSaved(Result<(), String>),
    /// A spawned job's task panicked, with whatever the shell recorded about
    /// what it was.
    ///
    /// A panic is not an outcome the job produced, so it cannot travel inside
    /// one — and every job this driver spawns leaves state behind that only its
    /// own completion clears. `None` is a job that left none.
    Panicked { job: Option<PanickedJob> },
}

/// What a task that panicked was doing, recorded by the shell at spawn.
///
/// **The kinds are separated because their consequences are**, not for
/// bookkeeping. An untagged panic is a no-op, and a no-op is wrong for every
/// one of these: a dead mint or DHT task leaves its recipient recorded as in
/// flight for ever, and a dead spent-token write leaves the file behind the set
/// in memory — under an invite-only policy, restoring every invite spent since
/// the last successful write.
pub(crate) enum PanickedJob {
    /// The proof-of-work mint for one introduction.
    Mint(PkLt),
    /// A DHT operation belonging to one introduction.
    Dht(PkLt),
    /// The spent-token write.
    SpentSave,
    /// A sweep of our own doorbell.
    ///
    /// The machine holds one sweep of a record at a time, so a dead sweep whose
    /// death nothing reports leaves the doorbell recorded as in flight for the
    /// life of the driver — which is a driver that never hears another knock.
    DoorbellSweep,
    /// A sweep of one receiving page, by the conversation and page it addressed.
    PageSweep {
        conversation: [u8; AR_FINGERPRINT_LEN],
        page: u64,
    },
    /// A write to one sending page, by the conversation and page it addressed.
    ///
    /// The twin of [`Self::PageSweep`], and needed for the same reason with a
    /// different consequence. A write records its page as in flight so the close
    /// path cannot hand the record back under it; a dead write whose death nothing
    /// reports leaves that page in flight for the life of the driver, and the close
    /// path skips it for ever — a sending page that can never be reclaimed except
    /// by the transport's own capacity bound.
    PagePublish {
        conversation: [u8; AR_FINGERPRINT_LEN],
        page: u64,
    },
}

impl core::fmt::Debug for PanickedJob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PanickedJob::Mint(_) => f.write_str("Mint(PkLt(..))"),
            PanickedJob::Dht(_) => f.write_str("Dht(PkLt(..))"),
            PanickedJob::SpentSave => f.write_str("SpentSave"),
            PanickedJob::DoorbellSweep => f.write_str("DoorbellSweep"),
            // The conversation fingerprint names a correspondence; only the page
            // is shown, on the terms `OpTag`'s own rendering states.
            PanickedJob::PagePublish { page, .. } => {
                write!(f, "PagePublish {{ conversation: \"<AR>\", page: {page} }}")
            }
            PanickedJob::PageSweep { page, .. } => {
                write!(f, "PageSweep {{ conversation: \"<AR>\", page: {page} }}")
            }
        }
    }
}

impl core::fmt::Debug for DhtOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DhtOutcome")
            .field("kind", &self.kind)
            .field("tag", &self.tag)
            .field("ok", &self.result.is_ok())
            .finish()
    }
}

/// A knock awaiting the user's answer.
struct Held {
    /// What identifies it to the front end.
    id: RequestId,
    /// The verified knock itself.
    knock: Box<VerifiedFirstContact>,
    /// The first-contact epoch this knock was ADMITTED in.
    ///
    /// Not the epoch it was minted for — [`VerifiedFirstContact`] carries
    /// neither the hash nor the epoch, and admission accepts a proof at the
    /// current epoch or the one before, so the two differ by at most one. It is
    /// enough for expiry, which is all it is used for: a request whose
    /// admitting epoch has fallen outside the accept window names an entry no
    /// longer replayable, and holding it any longer holds the sender's keys and
    /// message for a conversation that cannot resume.
    admitted_epoch: u64,
}

/// An introduction between the command that asked for it and the key record it
/// is waiting on.
struct Introduction {
    /// The recipient.
    recipient: PkLt,
    /// The first message, held until there is a key to seal it to.
    body: String,
}

/// One correspondence this session holds, and what it needs to speak on it.
///
/// **What survives a restart and what does not, because the split decides what
/// a recovered correspondence can do.** The resume record carries this side's
/// `S_pc` and the correspondent's `PK_pc`, so a correspondence read back from
/// disk can sign and verify every re-establishment leg, and the address root
/// comes back with it — which is what makes the whole exchange reachable. The
/// key schedule and the channel identifier do not survive and are not meant to:
/// a completed re-establishment mints both again.
///
/// **The one thing that does not come back is this side's own pseudonym
/// KEYPAIR.** [`SignKeypair`] holds a secret half and a public half, and only
/// the secret half is at rest — the record enumerates `S_pc` and the *peer's*
/// `PK_pc`, and ML-DSA offers no way to recover a public key from a private
/// one. Legs are unaffected, because a leg's signature preimage binds no public
/// key. An ordinary channel frame binds this side's own `PK_pc`
/// ([`frame::seal`]), so composing one after a restart is not reachable; see
/// [`DmMachine::send`], which refuses it.
struct Correspondence {
    /// The correspondent's long-term identity key.
    pk_lt: PkLt,
    /// The store label this correspondence's records live under — its outbox,
    /// its receive cursor, its contact record.
    label: CorrespondenceLabel,
    /// The conversation key schedule.
    ///
    /// `None` for a correspondence found on disk at startup and nothing else.
    /// A ratchet has no at-rest record, so it is exactly the correspondences
    /// established in this process that can be spoken on; see this struct's own
    /// note above and [`RefusalReason::NotEstablishedThisSession`].
    ratchet: Option<Ratchet>,
    /// Our per-contact pseudonym — what signs every frame we send here.
    ///
    /// `None` exactly when `ratchet` is: the pseudonym is minted in the process
    /// that establishes the correspondence and has nowhere at rest to live.
    signing_pc: Option<SignKeypair>,
    /// The correspondent's pseudonym — what every frame they send is verified
    /// against.
    ///
    /// Known from the knock on the acceptor's side, and from the ACCEPT on the
    /// initiator's — **the acceptor's first channel frame, at its sequence
    /// zero, whose sealed body carries the pseudonym and the long-term identity
    /// binding that vouches for it** (`frame::seal_accept`,
    /// [`ParsedFrame::open_accept`]).
    ///
    /// `None` on the initiator's side until that frame lands, which is a real
    /// state rather than a gap: an initiator can send from the moment it knocks
    /// — its opening burst hangs off the first-contact secret — but it can
    /// verify nothing before the acceptance, so a frame it sweeps at any later
    /// sequence is left unsettled and counted on
    /// [`DmEvent::ChannelHealth`]'s `peer_pseudonym_unknown` until the ACCEPT
    /// arrives and the next sweep retries it.
    ///
    /// **Read back at startup from the contact record**, which holds the
    /// correspondent's pseudonym from the moment the acceptance is collected.
    /// A correspondence whose entry has not been accepted has none recorded,
    /// and comes back `None` — the same state it was in before the process
    /// ended. This side's OWN pseudonym keypair is a different matter: its
    /// at-rest home is the resume record (A4.8 / A9.2), this driver writes
    /// none, and a restart loses it.
    peer_pk_pc: Option<Box<[u8; IDENTITY_PK_LEN]>>,
    /// The conversation's channel id, derived from `ss0` at establishment or
    /// from the re-rooted secret at a re-establishment.
    ///
    /// `None` alongside a `None` ratchet on an established correspondence,
    /// because nothing at rest carries `ss0` once the handshake is over. Before
    /// the acceptance the provisional record still holds it, so both are
    /// recomputed — see [`DmMachine::rearm_handshake`]; after a completed
    /// re-establishment the identifier is the one
    /// [`ResumeRecord::commit_reestablished`] returns.
    channel: Option<ChannelRoots>,
    /// The conversation's address root — every page and acknowledgement record
    /// this correspondence will ever use hangs off it.
    ///
    /// **Known for the life of the correspondence, unlike everything else that
    /// addresses it.** `AR` is written into the contact record at establishment
    /// and read back at every load, and a re-establishment does not re-root it
    /// (`docs/design/direct-messaging.md:1481`). So a correspondence whose key
    /// schedule a restart destroyed can still address the plane its
    /// re-establishment legs travel on, which is what makes recovery reachable
    /// at all.
    address_root: [u8; ADDRESS_ROOT_LEN],
    /// The candidate this side committed when it answered a peer's `RE-EST`,
    /// held until the `RE-CONFIRM` settles it.
    ///
    /// **In memory, and only in memory.** The record at rest carries the
    /// candidate root itself; what this holds is the pair the resumed channel is
    /// opened on — the ratchet root and the channel identifier — and A5.4 keeps
    /// both out of every at-rest encoding. A restart inside the window between
    /// answering and confirming therefore loses the resumed channel's
    /// identifier: the record still settles correctly and the generation still
    /// advances, and the channel comes back addressable but not speakable until
    /// the next re-establishment.
    candidate: Option<Rerooted>,
    /// How many `RE-ACK`s this session has composed for this correspondence.
    ///
    /// A8.4's answer-side emission cap, counted here because the design bounds
    /// the *response* rate and nothing else: see [`RESPONSE_EMISSION_CAP`] for
    /// what this is and what it is not.
    re_acks_answered: u32,
    /// Whether this session has already said the retention ceiling fired with
    /// no confirming observation.
    ///
    /// The ceiling is a wall clock, so the condition stays true for ever once it
    /// is met; one event per session names it without repeating on every tick.
    retire_ceiling_surfaced: bool,
    /// Whether this session has already said a re-establishment leg reached its
    /// give-up unanswered.
    ///
    /// A3.13 forbids a terminal state, so the correspondence goes on opening
    /// fresh attempts and each may reach its own give-up; one event per session
    /// names the condition rather than each occurrence.
    leg_give_up_surfaced: bool,
    /// Whether this session has already said it will answer no more
    /// re-establishments for this correspondence.
    ///
    /// A8.4's cap refuses without accepting anything, so a correspondent that
    /// keeps trying keeps being refused; one event per session names the state
    /// without turning a bounded refusal into a per-frame stream.
    response_cap_surfaced: bool,
    /// Whether this session has already surfaced that the correspondent is
    /// re-presenting an exchange this side has settled.
    ///
    /// A3.8 has every anomaly loud and A3.13 forbids a terminal state, so the
    /// peer keeps re-emitting and this side keeps deduping; one event per
    /// session names the condition without turning a bounded recovery into a
    /// per-sweep stream.
    peer_regression_surfaced: bool,
    /// What has been collected on the receiving direction.
    collection: Collection,
    /// The highest page this session has actually swept — the corroboration
    /// [`DmPersist::advance_cursor`] refuses to move the stored cursor without.
    ///
    /// **This session's own knowledge, never a number read back from the file.**
    /// A value taken from the record and handed back as its own bound would be
    /// checking a number against itself, and sealing the record (#389) does not
    /// change that: the seal says the profile's key wrote it, not that the page
    /// it names was ever read.
    read_through: u64,
    /// Whether this correspondence's `cursor.bin` was found unreadable at seed
    /// and has not been repaired yet.
    ///
    /// **Set here rather than repaired on the spot because a repair is a write,
    /// and it should be reported.** `seed_from_store` builds correspondences
    /// inside `DmMachine::new`, which returns a machine and no effects, so a
    /// repair taken there could never reach a health event. Carried to the next
    /// tick instead, where the counter moves and
    /// [`Correspondence::health_event`] surfaces it.
    ///
    /// The tick is the right place and the fold is not: a correspondence whose
    /// record is wrecked has no live channel until it re-establishes, so it may
    /// never fold a page at all — and the fold's own repair only runs when the
    /// contiguous prefix moved, which for a correspondence receiving nothing new
    /// is never.
    cursor_unreadable: bool,
    /// Positions opened and displayed whose acknowledgement the beyond-prefix
    /// set had no room for, retried at the head of the next fold.
    ///
    /// Retained rather than dropped because the message key is already spent:
    /// re-offering the slot yields
    /// [`RatchetError::AlreadyConsumed`], never a second copy, so a discarded
    /// position is one the sender re-seeds to the give-up and reports
    /// undelivered for a message that was in fact read.
    owed_acks: Vec<PagePosition>,
    /// Give-ups this session has already told the front end about.
    ///
    /// **Not a substitute for the record's own flag**, which stays owed until
    /// [`DmCommand::Surfaced`] answers it — this only stops the same run
    /// repeating itself on every tick. A restart empties it, so anything the
    /// front end never answered is offered again, which is the #279 direction.
    offered_this_session: Vec<u64>,
    /// This correspondence's channel-plane accounting, cumulative.
    health: ChannelCounters,
    /// When this side last wrote a standalone acknowledgement for the receiving
    /// direction, and whether anything has been collected since.
    ///
    /// One per correspondence, against the one client-global
    /// [`StandaloneAckBudget`] on the machine: this decides whether a
    /// conversation *wants* a write, the budget decides whether the client can
    /// afford one, and a write happens only where both agree.
    ///
    /// **Not persisted, and that is a recorded limit rather than an
    /// oversight.** After a restart the taper restarts from the floor, so the
    /// first tick of a new process writes one acknowledgement per correspondence
    /// it collected on, spaced by the budget. The cost is bounded write
    /// allowance; the alternative is a record whose absence would have to be
    /// distinguished from a conversation that genuinely never wrote one.
    ack_cadence: StandaloneAckCadence,
    /// The send times of the messages this session has opened on the receiving
    /// direction — what the taper measures the sender's give-up from.
    ///
    /// **Sorted ascending, deduplicated, and capped at [`PENDING_SENT_CAP`].**
    /// Sorted so [`Self::prune_pending`] can drop the dead as a prefix rather
    /// than rewriting the whole vector, and so the cap knows which entries it is
    /// choosing between; see the constant for which one overflow drops.
    ///
    /// **The frame's own asserted send time, clamped to the moment it was
    /// collected.** [`ack_cadence`](daemonseed_core::dm::ack_cadence) interpolates
    /// across the sender's window, and the sender measures that window from its
    /// own compose instant, so `sent_unix_ms` is the only value on the wire that
    /// tracks it — a receipt time would restart the window at collection. The
    /// clamp is [`Self::note_pending`]'s and is load-bearing rather than tidy;
    /// the reasoning is there.
    ///
    /// **Entries are never removed on acknowledgement, only aged out.** Nothing
    /// acknowledges an acknowledgement, so this side never learns its record was
    /// read; a set cleared on write would terminate the cadence immediately and
    /// leave the record un-refreshed, which on a store with no TTL is the same
    /// as never having written it. What bounds the set instead is the give-up:
    /// [`ack_cadence::oldest_live_pending_ms`] drops anything past its own
    /// window, and [`Self::prune_pending`] applies the identical rule.
    pending_sent_ms: Vec<i64>,
    /// What the correspondent has acknowledged of what THIS side sent — the
    /// retained own state every peer acknowledgement, piggybacked or standalone,
    /// is merged into under this side's own ceiling.
    ///
    /// Retained rather than rebuilt per fold because a merge is a union: a
    /// peer's later statement may settle a run this side already holds and say
    /// nothing about an earlier one, and a fresh state per fold would un-settle
    /// everything the previous statement carried.
    own_ack: AckState,
    /// The last refusal [`DmMachine::fire_accept`] reported for this
    /// correspondence, so the tick's retry does not repeat itself.
    ///
    /// `None` once an acceptance is composed, so a conversation that fails,
    /// recovers and fails the same way again reports both times.
    last_accept_refusal: Option<RefusalReason>,
    /// The context this correspondence's provisional record was sealed under,
    /// while that record is still on disk.
    ///
    /// **The initiator holds its record until the ACCEPT verifies**, because
    /// `{ss0, the opening ephemeral DK}` is the only at-rest state that could
    /// resume the handshake across a restart in that window, and without the
    /// ephemeral DK this side cannot decapsulate the acceptor's first
    /// generation ciphertext. Erasing it is the act a verified ACCEPT licenses:
    /// [`PendingHandshake::commit`].
    ///
    /// The context has to be carried because a record opens only under the one
    /// it was sealed with — its AAD binds `fc_epoch`, and an acceptance may
    /// land in a later epoch than the knock did, so the current epoch is not
    /// the right key. `None` on the acceptor's side, which never writes one, and
    /// after the erasure.
    provisional: Option<(ProvisionalContext, u64)>,
    /// Whether a stored handshake may still be re-armed for this
    /// correspondence.
    ///
    /// Set only where the store says a first-contact entry was sent and not yet
    /// accepted, which is the one state whose ratchet and channel roots can be
    /// recomputed from disk. Cleared by the attempt itself, whether or not it
    /// found anything — see [`DmMachine::rearm_handshake`] for why one
    /// conclusive attempt is all a session gets.
    rearm_handshake: bool,
    /// Consecutive re-arm attempts that ended in a fault rather than an answer.
    ///
    /// Bounds the retry that a store fault earns: see
    /// [`REARM_FAULT_CEILING`].
    rearm_faults: u8,
    /// Whether a collected acceptance's pseudonym still has to reach the
    /// contact record.
    ///
    /// Set when the write that records it was refused, which leaves this
    /// session able to speak on the conversation and the disk unable to
    /// remember who it is with. The tick retries the write and erases the
    /// handshake record once it lands; until then that record stays, because it
    /// is the only state a restart could re-arm from.
    pseudonym_unwritten: bool,
    /// Consecutive attempts at that write that ended in a fault rather than an
    /// answer. Bounded by [`PSEUDONYM_WRITE_FAULT_CEILING`].
    pseudonym_faults: u8,
    /// Whether this correspondence still owes the load-time re-establishment
    /// pass — the dead-chain sweep and the reconnect decision.
    ///
    /// Set only where the store says a correspondence is established, which is
    /// the one state that has a resume record to sweep against and a retained
    /// root to speak a leg under. Cleared when the pass **completes**, so a
    /// store fault leaves the work owed to the next tick rather than skipped for
    /// the session — see [`DmMachine::resume_channel`].
    resume_owed: bool,
    /// Consecutive load-time passes that ended in a store fault rather than an
    /// answer. It is the backoff's rung, saturating at
    /// [`REARM_FAULT_CEILING`]'s.
    resume_faults: u8,
    /// When the next load-time pass may run.
    ///
    /// A3.15 row 6 has the unreadable case retry *"on a backoff"*, so a fault
    /// pushes this forward by [`ReseedSchedule::delay_for_rung`] at the fault
    /// count — the ladder the outbox already re-seeds on, reused rather than a
    /// second cadence to reason about. `None` before the first fault.
    resume_retry_due_ms: Option<i64>,
    /// Whether this session has already told the front end that the resume
    /// record will not read.
    ///
    /// A3.8 has the unreadable case *"loud on first occurrence, never a silent
    /// loop"*, and the retry runs on a cadence; without this the same event
    /// would go out on each of them.
    resume_surfaced: bool,
    /// Whether this session has already said the backoff reached its top rung.
    ///
    /// The pass is never abandoned — A3.13 forbids a terminal state — so a store
    /// that has not recovered by [`REARM_FAULT_CEILING`] would otherwise retry
    /// at a day's cadence for ever with nothing said after the first fault. One
    /// further event names that, once.
    resume_ceiling_surfaced: bool,
}

/// The recipient key-record address half of a
/// [`RecordContext`], owned rather than borrowed so a correspondence can hold
/// it across ticks.
type ProvisionalContext = [u8; DM_KEYREC_OWNER_SEED_LEN];

/// The identifier a live channel's frames bind.
///
/// **The address root is NOT here**, and its absence is what keeps one answer to
/// one question. A conversation's address plane outlives its key schedule: `AR`
/// is written into the contact record at establishment and re-read at every
/// load, while `chan_id` is session-lifetime state a restart destroys and only a
/// completed re-establishment re-mints. Holding both in one struct meant a
/// restarted correspondence had neither, so the plane it must read to recover
/// was unaddressable — and a copy kept beside the durable one would be a second
/// answer free to disagree with it. The root lives on
/// [`Correspondence::address_root`], for the life of the correspondence.
struct ChannelRoots {
    /// The channel id every frame's seal and signature bind. Never serialized
    /// (§ v4 minor invariant).
    chan_id: [u8; ROOT_LEN],
}

/// What one correspondence's channel plane has counted, cumulative for this
/// session. Mirrors [`DmEvent::ChannelHealth`]'s fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ChannelCounters {
    partial_sweeps: u64,
    already_consumed: u64,
    unopenable: u64,
    peer_pseudonym_unknown: u64,
    peer_acks_deferred: u64,
    peer_acks_clipped: u64,
    peer_acks_unverified: u64,
    cursor_records_repaired: u64,
    leg_folds_deferred: u64,
    leg_unaddressable: u64,
}

impl core::fmt::Debug for Correspondence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `signing_pc` holds a secret key and both public halves name a person;
        // the roots address the conversation.
        f.debug_struct("Correspondence")
            .field("peer_pk_pc_known", &self.peer_pk_pc.is_some())
            .field("live", &self.ratchet.is_some())
            .field("read_through", &self.read_through)
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

impl Correspondence {
    /// The three things a live channel needs together, or nothing.
    ///
    /// **One accessor rather than three unwraps**, because they are set in one
    /// act and are meaningless apart: a ratchet with no pseudonym cannot sign,
    /// and a pseudonym with no roots cannot address. Every caller that speaks on
    /// the channel goes through here, so "established this session" has one
    /// spelling.
    fn live(&self) -> Option<(&Ratchet, &SignKeypair, &ChannelRoots)> {
        match (&self.ratchet, &self.signing_pc, &self.channel) {
            (Some(r), Some(pc), Some(ch)) => Some((r, pc, ch)),
            _ => None,
        }
    }

    /// The conversation every record of this correspondence is tagged with.
    ///
    /// **Derived from the address root, never read off the ratchet**, so one
    /// correspondence has one answer whether or not a key schedule exists. The
    /// two are the same value — a ratchet carries a fingerprint of the `AR` it
    /// was opened on — but only this one survives a restart, and a tag that
    /// changed shape with the key schedule would route a re-establishment leg's
    /// outcome to no correspondence at all.
    ///
    /// `None` only where the hash itself fails, which is a module fault rather
    /// than a state.
    fn conversation(&self) -> Option<[u8; AR_FINGERPRINT_LEN]> {
        firstcontact::ar_fingerprint(&self.address_root).ok()
    }

    /// Record that a frame asserting `sent_unix_ms` was collected at `now_ms`.
    ///
    /// **The send time is clamped to `now_ms`, and that is what stops a peer
    /// pinning the cadence open for ever.** `sent_unix_ms` is peer-asserted and
    /// signed, which authenticates it as a *statement* and bounds it in no other
    /// way. A frame claiming a send time in the future never satisfies
    /// `now_ms - sent_ms >= give_up_ms`, so it never ages out of
    /// [`Self::prune_pending`] or out of
    /// [`ack_cadence::oldest_live_pending_ms`]: the conversation never
    /// terminates, writes for ever, and — because the key is the smallest value —
    /// wins [`ack_cadence::pick_next`] against every honest correspondence at
    /// once. Clamping costs nothing on an honest frame and keeps the
    /// conservative direction for ordinary clock skew, because a send time at
    /// `now_ms` is the oldest a *live* message can be at collection: it yields
    /// the ceiling interval, which is the least frequent cadence.
    ///
    /// Duplicates are dropped rather than stored: two messages sent in the same
    /// millisecond are one point on the curve.
    fn note_pending(&mut self, sent_unix_ms: i64, now_ms: i64) {
        let sent_ms = sent_unix_ms.min(now_ms);
        let Err(at) = self.pending_sent_ms.binary_search(&sent_ms) else {
            return;
        };
        self.pending_sent_ms.insert(at, sent_ms);
        if self.pending_sent_ms.len() > PENDING_SENT_CAP {
            // The last of the oldest block, so index zero and the final index —
            // the taper's key and the liveness witness — are both untouched.
            self.pending_sent_ms.remove(PENDING_SENT_CAP - 1);
        }
    }

    /// Drop every pending send time that has passed the sender's own give-up.
    ///
    /// The same predicate [`ack_cadence::oldest_live_pending_ms`] filters by, so
    /// the first entry left is that function's answer. Sorted ascending, so the
    /// dead are a prefix and the scan stops at the first live one.
    fn prune_pending(&mut self, now_ms: i64) {
        let dead = self
            .pending_sent_ms
            .partition_point(|&sent_ms| now_ms.saturating_sub(sent_ms) >= GIVE_UP_MS);
        self.pending_sent_ms.drain(..dead);
    }

    /// Emit this correspondence's accounting if anything moved since `before`.
    fn health_event(&self, before: ChannelCounters) -> Option<DmEffect> {
        if self.health == before {
            return None;
        }
        Some(DmEffect::Emit(DmEvent::ChannelHealth {
            with: Box::new(*self.pk_lt),
            partial_sweeps: self.health.partial_sweeps,
            already_consumed: self.health.already_consumed,
            unopenable: self.health.unopenable,
            peer_pseudonym_unknown: self.health.peer_pseudonym_unknown,
            peer_acks_deferred: self.health.peer_acks_deferred,
            peer_acks_clipped: self.health.peer_acks_clipped,
            peer_acks_unverified: self.health.peer_acks_unverified,
            cursor_records_repaired: self.health.cursor_records_repaired,
            leg_folds_deferred: self.health.leg_folds_deferred,
            leg_unaddressable: self.health.leg_unaddressable,
        }))
    }
}

/// What the shell loaded for the spent-token set before the driver task began.
pub(crate) struct SpentTokens {
    /// The set as it was read, or an empty one where there was nothing to read.
    pub set: SpentTokenSet,
    /// Where to write it back, when it is written back at all.
    pub store: Option<SpentTokenStore>,
    /// Whether the stored set could not be read.
    ///
    /// **Poison, not a warning.** A file that is present and will not open is a
    /// set of grants this driver cannot see, and writing the in-memory set over
    /// it would discard every one of them — turning an unreadable suppression
    /// plane into an erased one. So a poisoned store is never written, for the
    /// life of the driver.
    pub poisoned: bool,
}

/// The driver's decision half.
pub(crate) struct DmMachine {
    identity: DmIdentity,
    persist: DmPersist,
    cfg: DmDriverConfig,
    last_tick_ms: Option<i64>,
    /// Our own doorbell's owner seed, derived once by the shell before the task
    /// started. Not optional: a driver that cannot derive its own doorbell is
    /// permanently deaf, and that is refused at construction.
    doorbell_owner: [u8; 32],
    /// Our own key-record owner seed — what a knock's seal and proof of work
    /// bind, so admission needs it to verify either.
    keyrec_addr: [u8; DM_KEYREC_OWNER_SEED_LEN],
    /// What each slot held at the last sweep — admission's step 0.
    previous_slots: std::collections::BTreeMap<u16, Vec<u8>>,
    /// Entry hashes already processed, per live epoch. In memory by design.
    seen: SeenSet,
    /// Admission's accounting, accumulated across every sweep.
    admission: AdmissionCounters,
    /// Consumed invite-token nonces, and where they are kept.
    spent: SpentTokens,
    /// Verified knocks awaiting accept or decline, bounded by
    /// [`PENDING_REQUEST_CAP`].
    pending: Vec<Held>,
    /// Introductions awaiting a key record, then a mint.
    outbound: Vec<Introduction>,
    /// Recipients whose introduction is between the key record and the
    /// doorbell write having landed.
    ///
    /// [`firstcontact::build`] must never be called twice for one introduction —
    /// every call encapsulates a fresh `ss0`, which the receiver reads as the
    /// sender having lost their at-rest state — so a second `FirstContact` for a
    /// recipient already in flight is refused rather than queued. The recipient
    /// stays here until the write's own outcome lands, so a failed publish is
    /// still attributable.
    minting: Vec<PkLt>,
    /// The label each recipient's provisional record was written under.
    ///
    /// One label per recipient, never one per attempt: a second label would be
    /// a second correspondence directory holding a live `ss0` that nothing ever
    /// establishes or erases.
    provisionals: Vec<(PkLt, CorrespondenceLabel)>,
    /// Correspondences established this session.
    correspondences: Vec<Correspondence>,
    /// Provisional records whose erasure was attempted and did not succeed,
    /// under the label and context they were written beneath.
    ///
    /// **These have no correspondence to hang from any more.** A mutual knock
    /// re-points this side's entry at the label the acceptance established, so
    /// a record left behind under the OLD label is unreachable from the entry
    /// that used to name it — and the record is the conversation's opening
    /// secret, kept out of a `Vec` only by having been deleted. So the handle
    /// moves here rather than being dropped, and every tick tries again until
    /// the store says the record is gone.
    pending_erase: Vec<(CorrespondenceLabel, ProvisionalContext, u64)>,
    /// The client-global allowance for standalone acknowledgements.
    ///
    /// **One per driver, shared across every correspondence**, which is the
    /// whole reason the ordering below exists: the ceiling is client-wide, so a
    /// per-conversation budget would multiply it by the number of contacts a
    /// stranger can create.
    ack_budget: StandaloneAckBudget,
    /// The correspondence that took the last standalone-acknowledgement
    /// allowance, so [`ack_cadence::pick_next`] can decline to give it two
    /// rounds running.
    last_ack_picked: Option<CorrespondenceLabel>,
    /// When the budget said it would next grant, from the `retry_after_ms` of
    /// its last refusal.
    ///
    /// Folded into [`Self::next_due_ms`] so a driver whose idle cadence is
    /// slower than the allowance still wakes to write the acknowledgement it was
    /// refused, rather than deferring it a whole tick.
    ack_retry_due_ms: Option<i64>,
    /// Whether a sweep of our own doorbell is in flight.
    ///
    /// **A cadence is not a rate limit.** The tick asks for a sweep every
    /// interval; nothing about the interval bounds how long one sweep takes. A
    /// doorbell sweep reads every subkey of the record, and on a real
    /// distributed hash table each of those is a network round trip — so a sweep
    /// routinely outlives several ticks, and a driver that emitted one per tick
    /// regardless would hold a dozen sweeps of the SAME record open at once,
    /// every one of them competing for the same read permits and slowing the
    /// others down. One at a time is not a throttle bolted on; it is the only
    /// number of sweeps of one record that has ever been useful.
    ///
    /// What it costs is bounded and small: a sweep that lands between two ticks
    /// does not schedule anything of its own, so the longest a knock can sit
    /// unread is one whole sweep plus one tick.
    sweeping_doorbell: bool,
    /// The highest key-record version verified for each identity, keyed by the
    /// identity's own long-term key — the design's M1 rollback bound.
    ///
    /// The record is world-writable, so anyone can plant an *authentic* record
    /// the owner signed before a rotation. The bound is what refuses it: a
    /// version below the highest already verified for that identity never
    /// becomes the key an introduction is sealed to.
    ///
    /// **Session-scoped for alpha, and that is a scope rather than a
    /// requirement.** The design ratifies the rule — *"Readers cache highest
    /// verified `version`, never regress"* — and accepts the cold reader, one
    /// with no cached version at all, as the alpha residual; a restart is one of
    /// those readers, so the bound this holds dies with the process. Making it
    /// durable is a later change, not a blocked one: its entry point is
    /// [`KeyRecordCache::from_verified`], and its shape is a profile-scoped
    /// record of capped per-identity entries, as
    /// [`RecordKind::BlockList`](daemonseed_core::storage::dm_store::RecordKind)
    /// already is. It is not the contact record: that is written at
    /// establishment, and a key record is fetched before a correspondence
    /// exists. Held per identity rather than per correspondence for the same
    /// reason — the bound has to exist before the correspondence does.
    ///
    /// One entry per identity whose record has been *verified*, so it grows
    /// only with introductions the user asked for, exactly as `provisionals`
    /// does.
    key_records: Vec<(PkLt, KeyRecordCache)>,
    /// The receiving pages whose sweep is in flight, by conversation and page.
    ///
    /// Keyed per page rather than per conversation because the probe plan is
    /// per page: two different pages of one conversation are two different
    /// records, and holding one open says nothing about the other.
    sweeping_pages: std::collections::BTreeSet<([u8; AR_FINGERPRINT_LEN], u64)>,
    /// The sending pages whose publish is in flight, by conversation and page.
    ///
    /// **Not a second [`Self::sweeping_pages`] and not foldable into it.** That set
    /// answers "may this page be swept again"; this one exists solely so the close
    /// path can tell whether a write to a page is still outstanding. They cannot
    /// share a set because they name *different records*: the two directions of one
    /// page number derive two owner seeds, so `(conversation, page)` present in both
    /// sets is two records, and a single set would let a sweep of the receiving page
    /// hold the sending one open.
    ///
    /// **A COUNT per page, not a set, and the sweep side gets away with a set only
    /// because of a property this side does not have.** `probe` skips a page already
    /// in `sweeping_pages`, so one page never has two sweeps outstanding and
    /// presence is enough. `due_emissions` issues a write per due entry and one page
    /// holds `PAGE_SLOTS` of them, so a tick routinely puts sixteen writes on one
    /// record: under a set the first outcome to land would release the page while
    /// fifteen writes were still running, and a settlement arriving then would close
    /// the record under them. This is the same refcount the transport's own
    /// `PageLease` is, one layer up and for the same reason.
    ///
    /// Unlike the sweep set it gates nothing about issuing writes — the outbox's own
    /// cadence decides that, and a re-seed of the same slot is ordinary.
    publishing_pages: std::collections::BTreeMap<([u8; AR_FINGERPRINT_LEN], u64), usize>,
    /// The receiving pages this session has asked the transport to open, less the
    /// ones it has asked it to close.
    ///
    /// **What the close path iterates, and it has to be tracked here rather than
    /// derived.** Which pages are open is a fact about what this machine has already
    /// asked for; the collection knows only which pages it *would* ask for now. A
    /// close computed from the collection alone would name pages nothing opened —
    /// harmless but pointless traffic — and would miss the pages a probe plan
    /// reached before a give-up moved the cursor past them, which are exactly the
    /// ones worth reclaiming.
    open_recv_pages: std::collections::BTreeSet<([u8; AR_FINGERPRINT_LEN], u64)>,
    /// The sending pages this session has asked the transport to open, less the ones
    /// it has asked it to close. The write-side twin of [`Self::open_recv_pages`].
    open_send_pages: std::collections::BTreeSet<([u8; AR_FINGERPRINT_LEN], u64)>,
    /// The conversations this session has torn down.
    ///
    /// **A teardown ends the conversation but leaves the ratchet and the channel
    /// roots in place**, and `live()` reads exactly those — so without this every
    /// planner goes on treating a torn-down correspondence as ordinary. The
    /// receiving pages handed back at teardown would be re-planned and re-opened on
    /// the next probe cadence, which is not merely wasted work: a close and a sweep
    /// of one record from the same tick is the open/close race the eviction path's
    /// victim lock exists to exclude, reached from a direction that lock does not
    /// cover.
    ///
    /// Held here rather than on the correspondence for the reason the page sets are:
    /// the conversation fingerprint is the key every channel-plane decision is
    /// already made against.
    ///
    /// **Cleared by nothing, and bounded by teardowns rather than by traffic.** One
    /// entry per conversation this driver has torn down, so it grows with a count the
    /// user drives — a correspondent losing their at-rest state — not with message
    /// volume, which is the growth #252 is about. Thirty-two bytes each.
    ///
    /// A stale entry cannot collide with a live conversation, which is what makes
    /// keeping it safe. `ar_fingerprint` is derived from `ss0`, and re-establishment
    /// encapsulates a fresh `ss0` — that is what a knock IS — so a re-established
    /// correspondence carries a fingerprint this set has never seen. A collision
    /// would need two conversations to share a first-contact secret.
    torn_down: std::collections::BTreeSet<[u8; AR_FINGERPRINT_LEN]>,
    /// How many leg-scan candidates every swept slot has cost, cumulative.
    ///
    /// **The instrument for A3.9's bounded-trial-cost claim.** Each candidate
    /// costs at most `MAX_GAP + 1` AEAD opens, so this number times that one is
    /// the whole trial-decryption cost a correspondent can drive by writing
    /// bytes that are not legs. It is counted rather than reasoned about because
    /// the bound is what makes the scan safe to run on unauthenticated input,
    /// and a candidate added later would raise it silently.
    leg_scan_candidates: u64,
}

impl DmMachine {
    /// Build the machine over the state the shell prepared.
    ///
    /// The owner seeds arrive derived and the spent set arrives loaded: both
    /// are one-off work the shell does before the task starts, so neither the
    /// derivation's failure mode nor Argon2id's cost lands on the driver's loop.
    pub(crate) fn new(
        identity: DmIdentity,
        persist: DmPersist,
        cfg: DmDriverConfig,
        doorbell_owner: [u8; 32],
        keyrec_addr: [u8; DM_KEYREC_OWNER_SEED_LEN],
        spent: SpentTokens,
    ) -> Self {
        let correspondences = seed_from_store(&persist);
        Self {
            identity,
            persist,
            cfg,
            last_tick_ms: None,
            doorbell_owner,
            keyrec_addr,
            previous_slots: std::collections::BTreeMap::new(),
            seen: SeenSet::new(),
            admission: AdmissionCounters::default(),
            spent,
            pending: Vec::new(),
            outbound: Vec::new(),
            minting: Vec::new(),
            provisionals: Vec::new(),
            correspondences,
            pending_erase: Vec::new(),
            ack_budget: StandaloneAckBudget::new(),
            last_ack_picked: None,
            ack_retry_due_ms: None,
            sweeping_doorbell: false,
            key_records: Vec::new(),
            sweeping_pages: std::collections::BTreeSet::new(),
            publishing_pages: std::collections::BTreeMap::new(),
            open_recv_pages: std::collections::BTreeSet::new(),
            open_send_pages: std::collections::BTreeSet::new(),
            torn_down: std::collections::BTreeSet::new(),
            leg_scan_candidates: 0,
        }
    }

    /// Step on a front-end command.
    pub(crate) fn on_command(&mut self, now_ms: i64, cmd: DmCommand) -> Vec<DmEffect> {
        match cmd {
            DmCommand::FirstContact { recipient, body } => {
                self.start_introduction(now_ms, recipient, body)
            }
            DmCommand::Accept { request } => self.accept(now_ms, &request),
            DmCommand::Decline { request } => {
                // Persists nothing. Declining is the absence of a record, so
                // there is no state to write and nothing to tell the sender:
                // their view is byte-identical to a recipient who never came
                // online.
                self.pending.retain(|held| held.id != request);
                Vec::new()
            }
            DmCommand::Block { pk_lt } => self.set_blocked(&pk_lt, true),
            DmCommand::Unblock { pk_lt } => self.set_blocked(&pk_lt, false),
            DmCommand::Send { to, body } => self.send(now_ms, &to, body),
            DmCommand::Surfaced { to, seqs } => self.record_surfaced(now_ms, &to, &seqs),
            // The shell breaks its loop on this and never asks the machine.
            DmCommand::Shutdown => Vec::new(),
        }
    }

    /// Step on the idle cadence.
    ///
    /// The doorbell is swept on this cadence and on nothing else. An empty
    /// sweep is the ordinary state; the sweep's own accounting rides out on
    /// [`DmEvent::DoorbellHealth`], because an empty slot list alone means both
    /// "nobody knocked" and "every GET errored".
    ///
    /// **A tick whose previous sweep has not come back asks for nothing.** See
    /// [`Self::sweeping_doorbell`]: the cadence says how often to look, not how
    /// many looks may be open at once, and the answer to the second question is
    /// one.
    ///
    /// **The block list is read once for the whole tick, and only where
    /// something can ask it.** Every correspondence tests the same list against
    /// its own correspondent, and one tick is one instant, so a second read
    /// inside the loop could not return a different answer; a tick with no
    /// correspondences never touches the store at all.
    ///
    /// The reads in [`Self::on_page`] and [`Self::on_peer_ack`] are a different
    /// question, not a repeat of this one: an outcome arrives on a later tick
    /// than the one that asked for it, so the list has to be re-read at the
    /// moment the bytes are folded to catch a block taken while the operation
    /// was in flight. That one is priced per outcome, which is what it is worth.
    pub(crate) fn on_tick(&mut self, now_ms: i64) -> Vec<DmEffect> {
        self.last_tick_ms = Some(now_ms);
        let mut out = Vec::new();
        if !self.sweeping_doorbell {
            self.sweeping_doorbell = true;
            out.push(DmEffect::Dht(DhtOp::SweepDoorbell {
                tag: OpTag::none(),
                owner_seed: self.doorbell_owner,
            }));
        }
        if !self.correspondences.is_empty() {
            // `None` is the fail-closed answer, on the doorbell plane's own
            // terms: a list that cannot be read must not be read as "nobody is
            // blocked", so nothing is swept until it can be.
            let block_list = match self.persist.read_block_list() {
                Ok(list) => Some(list),
                Err(e) => {
                    crate::vtrace!("dm driver: block list unreadable, sweeping no channel: {e}");
                    // Once per tick, by construction: the read is one call per
                    // tick and this is its only failure path.
                    out.push(DmEffect::Emit(DmEvent::BlockListUnreadable));
                    None
                }
            };
            for index in 0..self.correspondences.len() {
                self.rearm_handshake(now_ms, index);
                out.extend(self.retry_pseudonym_write(now_ms, index));
                // Before the give-up sweep, which is what surfaces whatever the
                // dead-chain sweep inside this call just ended.
                out.extend(self.resume_channel(now_ms, index));
                // After the load pass, because that is what writes the record
                // this one keeps up, and before the emission scan, because a leg
                // it re-queues is due on the same tick.
                out.extend(self.reest_upkeep(now_ms, index));
                out.extend(self.repair_cursor(index));
                out.extend(self.give_ups(now_ms, index));
                out.extend(self.due_emissions(now_ms, index));
                out.extend(self.probe(now_ms, index, block_list.as_ref()));
                out.extend(self.ack_fetches(now_ms, index, block_list.as_ref()));
            }
        }
        // **After the per-correspondence pass, and once for all of them**, because
        // the standalone allowance is client-global: deciding it inside the loop
        // would hand it to whichever correspondence the store happened to
        // enumerate first, where `pick_next` gives it to the one whose sender has
        // been waiting longest.
        out.extend(self.standalone_acks(now_ms));
        out
    }

    /// Try again to write a collected acceptance's pseudonym into the contact
    /// record, and release the handshake record once it lands.
    ///
    /// **The pair is what makes a refused write recoverable.** The acceptance
    /// has verified and this session holds the pseudonym, so the conversation
    /// works; what is missing is the disk's memory of it. Until the write
    /// succeeds the handshake record stays, because it is the only state a
    /// restart can re-arm from — a correspondence that lost both would come back
    /// waiting for an acceptance it can no longer open. When the write lands the
    /// record is owed to the erase list rather than deleted here, so a store
    /// that refuses the deletion is retried by the same tick that retries every
    /// other one.
    ///
    /// **A refusal that no later attempt can change ends the retry AND releases
    /// the handshake record**, which is the opposite of what holding on to it
    /// achieves. A contact record that is absent, will not decode, or already
    /// holds a different pseudonym answers the same way for ever
    /// ([`DmPersistError::retrying_cannot_help`]), so retrying re-reads a sealed
    /// record every tick for the life of the session — and because the erase
    /// waits on the write, `ss0` would be kept on disk indefinitely against a
    /// write that will never succeed. The design deletes `ss0` at establishment
    /// regardless, and this correspondence is established: the acceptance
    /// verified. What is left is a torn contact record, which the correspondent
    /// repairs by knocking again or this side repairs by accepting one — and
    /// neither of those needs the opening secret.
    ///
    /// **A fault that keeps recurring ends the same way, at
    /// [`PSEUDONYM_WRITE_FAULT_CEILING`] consecutive attempts.** A store that
    /// has not recovered by then is indistinguishable at each attempt from one
    /// about to, so an unbounded retry reads and writes a sealed record every
    /// tick for the life of the session and withholds the erase for exactly as
    /// long. Giving up costs what the settled case costs, and for the same
    /// reason: the acceptance verified, so the correspondence is established
    /// whatever the disk remembers.
    fn retry_pseudonym_write(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        if !self.correspondences[index].pseudonym_unwritten {
            return Vec::new();
        }
        let Some(pk_pc) = self.correspondences[index].peer_pk_pc.clone() else {
            // Unreachable through `on_page`, which installs the key in the same
            // arm that sets the flag. Cleared rather than retried for ever: with
            // no key there is nothing this call could write.
            self.correspondences[index].pseudonym_unwritten = false;
            return Vec::new();
        };
        let label = self.correspondences[index].label;
        match self
            .persist
            .record_correspondent_pseudonym(&label, pk_pc, now_ms)
        {
            Ok(_) => {
                // **The establishment finishes here too, not only in
                // `on_page`.** This is the same transition arriving late: the
                // acceptance verified earlier and only the disk was behind, so
                // the resume record is owed exactly as it is on the prompt path.
                // Releasing the handshake record without writing it would leave
                // an established correspondence with no `S_pc`.
                let (persist, correspondences) = (&self.persist, &mut self.correspondences);
                let outcome = match correspondences[index].peer_pk_pc.clone() {
                    Some(peer_pk_pc) => establish_provisional(
                        persist,
                        &mut correspondences[index],
                        &peer_pk_pc,
                        now_ms,
                    ),
                    None => Establishment::Complete,
                };
                match outcome {
                    Establishment::Complete => {
                        self.stop_owing_the_pseudonym(index, label);
                    }
                    // **The pseudonym stays owed**, so the pair comes back to the
                    // next tick. The fault counter is the same one the write's
                    // own faults raise, so a store that never recovers is bounded
                    // by one ceiling rather than by two.
                    Establishment::Retry => {
                        let faults = self.correspondences[index]
                            .pseudonym_faults
                            .saturating_add(1);
                        self.correspondences[index].pseudonym_faults = faults;
                        if faults >= PSEUDONYM_WRITE_FAULT_CEILING {
                            crate::vtrace!(
                                "dm driver: the resume record still would not commit after \
                                 {faults} attempts"
                            );
                            self.stop_owing_the_pseudonym(index, label);
                        }
                    }
                    Establishment::Unrecoverable => {
                        self.stop_owing_the_pseudonym(index, label);
                        let owed = pending_seqs(&self.persist, &label, now_ms);
                        return cannot_resume(&self.correspondences[index], owed);
                    }
                }
            }
            Err(e) if e.retrying_cannot_help() => {
                crate::vtrace!("dm driver: the pseudonym will never record: {e}");
                self.stop_owing_the_pseudonym(index, label);
            }
            Err(e) => {
                crate::vtrace!("dm driver: the pseudonym still would not record: {e}");
                let faults = self.correspondences[index]
                    .pseudonym_faults
                    .saturating_add(1);
                self.correspondences[index].pseudonym_faults = faults;
                if faults >= PSEUDONYM_WRITE_FAULT_CEILING {
                    crate::vtrace!(
                        "dm driver: giving up on the pseudonym after {PSEUDONYM_WRITE_FAULT_CEILING} faults"
                    );
                    self.stop_owing_the_pseudonym(index, label);
                }
            }
        }
        Vec::new()
    }

    /// Stop retrying the pseudonym write and release the handshake record it
    /// was holding.
    ///
    /// One body for all three endings — the write landed, it never can, or it
    /// has faulted too many times running — so none of them can drift into
    /// releasing a different amount. The record goes to the erase list rather
    /// than being deleted here, so a store that refuses the deletion is retried
    /// by the same tick that retries every other one.
    fn stop_owing_the_pseudonym(&mut self, index: usize, label: CorrespondenceLabel) {
        self.correspondences[index].pseudonym_unwritten = false;
        if let Some((keyrec_addr, fc_epoch)) = self.correspondences[index].provisional.take() {
            self.pending_erase.push((label, keyrec_addr, fc_epoch));
        }
    }

    /// Recompute the ratchet and channel roots of a correspondence whose
    /// first-contact entry has been sent and not yet accepted.
    ///
    /// **Without this a restarted initiator can find its correspondence and
    /// still not read it.** The contact record says which correspondence a
    /// correspondent's identity key belongs to; it deliberately holds no `ss0`,
    /// so it yields neither a ratchet nor the `chan_id` every frame's seal
    /// binds. Both come back from the provisional record, which stays on disk
    /// for exactly this window — until an acceptance verifies — and the
    /// acceptance is an ordinary channel frame that cannot be opened without
    /// them. So a correspondence left unarmed sweeps nothing, opens nothing,
    /// and the correspondent's messages re-emit until their outbox gives up on
    /// them.
    ///
    /// **The context is rebuilt rather than remembered.** A provisional record
    /// opens only under the context it was sealed with, which binds the
    /// recipient's key-record address and the first-contact epoch. The address
    /// derives from the correspondent's identity key, which the contact record
    /// holds; the epoch does not, so both live epochs are tried, exactly as the
    /// lookup that finds a recipient's existing label does.
    ///
    /// **One CONCLUSIVE attempt per session, and a store fault is not
    /// conclusive.** Epochs only move forward, so a record that is absent or
    /// will not decode at both epochs tried here will answer the same way on
    /// every later tick — retrying that would re-read two sealed records for
    /// the life of the entry and never answer differently. A store that could
    /// not be read says nothing about the record at all, and clearing the flag
    /// on one would leave the correspondence without a ratchet for the rest of
    /// the session over a fault that may already have passed, which is exactly
    /// the state this call exists to prevent. So the flag survives that answer
    /// and the next tick tries again. An entry that outlives its epochs is the
    /// bound this leaves, and it is the same bound the label lookup carries.
    ///
    /// **A key derivation that fails is decisive too.** The correspondent's
    /// key-record address is derived from a `pk_lt` held in memory and reads no
    /// disk, so a later tick runs the identical computation over the identical
    /// bytes and cannot answer differently.
    ///
    /// **The retry is bounded at [`REARM_FAULT_CEILING`] consecutive faults.** A
    /// store fault that never clears — a truncated record nothing repairs — is
    /// indistinguishable at each attempt from one that is about to, so an
    /// unbounded retry re-reads two sealed records every tick for the life of
    /// the session. Past the ceiling the record is treated as unusable, which is
    /// the answer the same bytes would have given if the store had managed to
    /// classify them.
    ///
    /// A correspondence that is re-armed carries its provisional context
    /// forward, so the record is erased where every other path erases it: when
    /// the acceptance verifies.
    fn rearm_handshake(&mut self, now_ms: i64, index: usize) {
        if !self.correspondences[index].rearm_handshake {
            return;
        }
        let Self {
            persist,
            correspondences,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        let keyrec_addr = match keyrec::derive_owner_seed(&correspondence.pk_lt) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: correspondent key-record derivation failed: {e}");
                correspondence.rearm_handshake = false;
                return;
            }
        };
        let current = keyrec::fc_epoch(unix_secs(now_ms));
        // Set by any answer that a later tick could answer differently: a store
        // that would not read, or a crypto fault deriving from a record that
        // did. Absence and an undecodable record are not among them.
        let mut retryable = false;
        for fc_epoch in [current, current.saturating_sub(1)] {
            let ctx = RecordContext {
                recipient_keyrec_addr: &keyrec_addr,
                fc_epoch,
            };
            // `peek_`, not `restart_channel`: this asks whether a handshake is
            // there and takes nothing on the answer, so the cleaning form would
            // delete a record the caller has not finished with.
            let pending = match persist.peek_channel_restart(&correspondence.label, &ctx) {
                daemonseed_core::dm::persist::StoredChannelRestart::HandshakeResumes(pending) => {
                    pending
                }
                daemonseed_core::dm::persist::StoredChannelRestart::Established(_) => continue,
                daemonseed_core::dm::persist::StoredChannelRestart::TornDown(teardown) => {
                    if let TeardownCause::StoreUnreadable(cause) = teardown.cause() {
                        crate::vtrace!("dm driver: the stored handshake would not read: {cause}");
                        retryable = true;
                    }
                    continue;
                }
            };
            let roots = match pending.channel_roots() {
                Ok(roots) => roots,
                Err(e) => {
                    crate::vtrace!("dm driver: the stored handshake's roots would not derive: {e}");
                    retryable = true;
                    continue;
                }
            };
            let ratchet = match pending.ratchet() {
                // The handle is dropped uncommitted: the record it names is
                // what the acceptance will be opened against, and erasing it
                // here would take the conversation's opening secret with it.
                Ok(ratchet) => ratchet,
                Err(e) => {
                    crate::vtrace!("dm driver: the stored handshake would not open: {e}");
                    retryable = true;
                    continue;
                }
            };
            correspondence.channel = Some(ChannelRoots {
                chan_id: roots.chan_id,
            });
            correspondence.ratchet = Some(ratchet);
            correspondence.provisional = Some((keyrec_addr, fc_epoch));
            correspondence.rearm_handshake = false;
            return;
        }
        if !retryable {
            correspondence.rearm_handshake = false;
            crate::vtrace!(
                "dm driver: no stored handshake opened for a correspondence awaiting its acceptance"
            );
            return;
        }
        correspondence.rearm_faults = correspondence.rearm_faults.saturating_add(1);
        if correspondence.rearm_faults >= REARM_FAULT_CEILING {
            correspondence.rearm_handshake = false;
            crate::vtrace!(
                "dm driver: giving up on a stored handshake after {REARM_FAULT_CEILING} faults"
            );
        }
    }

    /// Replace a `cursor.bin` the seed found unreadable, once.
    ///
    /// **A record that will not read cannot be written past either**, so without
    /// this the correspondence carries a wrecked cursor for the life of the
    /// profile: every session re-reads it, fails, and starts its sweep from page
    /// zero. Nothing is adopted by replacing it — the stored bytes were never
    /// decoded — and what lands is this session's own position, which for a
    /// correspondence that has swept nothing is [`ReceiveCursor::START`]. The
    /// cost is one rescan, which is the failure this cursor is allowed to have.
    ///
    /// Runs here rather than in the fold for two reasons: the fold's repair only
    /// fires when the contiguous prefix moved, and a correspondence with no live
    /// channel folds no pages at all.
    ///
    /// The flag is cleared on any successful advance, so this is one write per
    /// wrecked record rather than one per tick. An advance that fails leaves it
    /// set: the record is still unreadable and the next tick tries again.
    fn repair_cursor(&mut self, index: usize) -> Vec<DmEffect> {
        let correspondence = &mut self.correspondences[index];
        if !correspondence.cursor_unreadable {
            return Vec::new();
        }
        let before = correspondence.health;
        let page = correspondence
            .collection
            .contiguous_through()
            .map_or(0, |through| position_of(through).page());
        match self
            .persist
            .advance_cursor(&correspondence.label, page, correspondence.read_through)
        {
            Ok(advance) => {
                correspondence.cursor_unreadable = false;
                if advance.repaired() {
                    crate::vtrace!("dm driver: an unreadable receive cursor was repaired");
                    correspondence.health.cursor_records_repaired += 1;
                }
            }
            Err(e) => {
                crate::vtrace!(
                    "dm driver: an unreadable receive cursor would not be repaired: {e}"
                );
            }
        }
        correspondence.health_event(before).into_iter().collect()
    }

    /// Step on a completed off-loop operation.
    pub(crate) fn on_outcome(&mut self, now_ms: i64, outcome: DmOutcome) -> Vec<DmEffect> {
        match outcome {
            DmOutcome::Mint(mint) => self.on_mint(now_ms, *mint),
            DmOutcome::SpentSaved(Ok(())) => Vec::new(),
            DmOutcome::SpentSaved(Err(e)) => {
                crate::vtrace!("dm driver: spent-token write failed: {e}");
                // Poisoned from here on: the file's relationship to the set in
                // memory is now unknown, and a later write would be this set
                // laid over whatever is actually there.
                self.spent.poisoned = true;
                vec![DmEffect::Emit(DmEvent::SpentTokensNotPersisted)]
            }
            DmOutcome::Panicked { job } => match job {
                Some(PanickedJob::Mint(recipient)) => {
                    self.refuse_introduction(&recipient, RefusalReason::MintPanicked, None)
                }
                Some(PanickedJob::Dht(recipient)) => {
                    self.refuse_introduction(&recipient, RefusalReason::TaskPanicked, None)
                }
                // The set in memory is now ahead of the file by an unknown
                // amount, exactly as a failed write leaves it — and a later
                // write would lay this set over whatever is actually there.
                Some(PanickedJob::SpentSave) => {
                    crate::vtrace!("dm driver: the spent-token write panicked");
                    self.spent.poisoned = true;
                    vec![DmEffect::Emit(DmEvent::SpentTokensNotPersisted)]
                }
                // A dead sweep yields nothing, so the only thing to do about it
                // is stop waiting on it. Left in flight it is the expensive
                // failure the flag exists to prevent, running the other way: not
                // a stack of sweeps of one record but none of them, for ever.
                Some(PanickedJob::DoorbellSweep) => {
                    self.sweeping_doorbell = false;
                    Vec::new()
                }
                Some(PanickedJob::PageSweep { conversation, page }) => {
                    self.sweeping_pages.remove(&(conversation, page));
                    self.close_freed_after_teardown(
                        DhtOpKind::SweepPage,
                        &OpTag::channel(conversation, None, Some(page)),
                    )
                }
                // Same reasoning, the write side: a slot left held is a sending page
                // the close path refuses for ever.
                Some(PanickedJob::PagePublish { conversation, page }) => {
                    release_publish(&mut self.publishing_pages, conversation, page);
                    self.close_freed_after_teardown(
                        DhtOpKind::PublishPage,
                        &OpTag::channel(conversation, None, Some(page)),
                    )
                }
                None => Vec::new(),
            },
            DmOutcome::Dht(DhtOutcome { kind, tag, result }) => {
                // **Before the result is handed on, and on the success and
                // failure paths alike.** A sweep that came back is a sweep no
                // longer in flight whatever it came back with, and doing this
                // inside the `Ok` arms alone would leave a transport failure
                // holding the record shut.
                self.release_sweep(kind, &tag);
                // The release may have freed the last page a torn-down conversation
                // was holding, and no later signal would reach it. Collected before
                // the result is folded, so a fold that returns early cannot drop it.
                let mut freed = self.close_freed_after_teardown(kind, &tag);
                let folded = match result {
                    Err(e) => {
                        crate::vtrace!("dm driver: operation failed: {e}");
                        // An introduction whose fetch or write failed on the
                        // transport is refused rather than left in flight: the
                        // front end may ask again, and a silently retained
                        // introduction would refuse that second ask as a duplicate.
                        match tag.introduction {
                            Some(recipient) => self.refuse_introduction(
                                &recipient,
                                RefusalReason::PublishFailed,
                                None,
                            ),
                            None => Vec::new(),
                        }
                    }
                    Ok(DhtResult::Doorbell(sweep)) => self.on_doorbell(now_ms, sweep),
                    Ok(DhtResult::KeyRecord(record)) => match tag.introduction {
                        Some(recipient) => self.on_key_record(now_ms, recipient, record),
                        None => Vec::new(),
                    },
                    Ok(DhtResult::Written) => {
                        // The doorbell write landed, so the introduction is no
                        // longer in flight and a later `FirstContact` to this
                        // recipient is a new one rather than a duplicate.
                        if let Some(recipient) = tag.introduction.as_ref() {
                            self.minting
                                .retain(|pk| pk.as_slice() != recipient.as_slice());
                        }
                        self.confirm_written(now_ms, &tag)
                    }
                    Ok(DhtResult::Page(sweep)) => self.on_page(now_ms, &tag, sweep),
                    Ok(DhtResult::Ack(record)) => self.on_peer_ack(now_ms, &tag, record),
                    Ok(DhtResult::AckWritten) => self.on_ack_written(now_ms, &tag),
                    // Nothing to fold. The page left `open_recv_pages` /
                    // `open_send_pages` when the close was ASKED for, not when it
                    // came back — see `Self::retire_pages`, which states why a
                    // refused close is left to the transport's capacity bound rather
                    // than re-queued here.
                    //
                    // The answer is still read: a close that reclaimed nothing is
                    // either a page this machine thought it had opened and had not,
                    // or one an operation outlived the machine's own in-flight
                    // tracking of it. Neither is an error and both are worth a line,
                    // because from here on the record's only route back is the
                    // transport's capacity bound.
                    Ok(DhtResult::Closed(true)) => Vec::new(),
                    Ok(DhtResult::Closed(false)) => {
                        crate::vtrace!(
                            "dm driver: a page close reclaimed no record (page {:?})",
                            tag.page
                        );
                        Vec::new()
                    }
                };
                freed.extend(folded);
                freed
            }
        }
    }

    /// Record that an operation is no longer in flight — a sweep for the page and
    /// doorbell planners, a page write for the close path.
    ///
    /// Keyed on the operation's own kind rather than on the shape of its result,
    /// which is what makes it work on the failure path: an `Err` is the same
    /// type for every operation, and the doorbell sweep's tag names nothing at
    /// all.
    fn release_sweep(&mut self, kind: DhtOpKind, tag: &OpTag) {
        match kind {
            DhtOpKind::SweepDoorbell => self.sweeping_doorbell = false,
            DhtOpKind::SweepPage => {
                // Every page sweep is tagged with both, by `probe`, which is the
                // only thing that emits one — and a tag missing either names no
                // key to release, so the slot would be held for ever with
                // nothing reporting it.
                debug_assert!(
                    tag.conversation.is_some() && tag.page.is_some(),
                    "a page sweep must be tagged with its conversation and page"
                );
                if let (Some(conversation), Some(page)) = (tag.conversation, tag.page) {
                    self.sweeping_pages.remove(&(conversation, page));
                }
            }
            // A write whose outcome has landed is a write no longer running against
            // the record, so the close path may hand that record back. Released on
            // the failure path too, for `release_sweep`'s own reason: a transport
            // failure that left the slot held would pin the page open for the
            // session.
            DhtOpKind::PublishPage => {
                if let (Some(conversation), Some(page)) = (tag.conversation, tag.page) {
                    release_publish(&mut self.publishing_pages, conversation, page);
                }
            }
            DhtOpKind::FetchKeyRecord
            | DhtOpKind::PublishDoorbell
            | DhtOpKind::PublishAck
            | DhtOpKind::FetchAck
            // A close holds nothing: it is what releases, and it takes no slot of
            // its own. A close whose task panicked has left the transport's own
            // state exactly as it found it.
            | DhtOpKind::ClosePage => {}
        }
    }

    /// When the shell should next wake the machine if nothing else happens.
    ///
    /// The idle cadence, or the moment the standalone-acknowledgement allowance
    /// renews where that lands sooner. **Only strictly sooner, and only in the
    /// future**: a deadline already passed would be handed back as a wait of
    /// zero and spin the shell's loop at the speed of the scheduler.
    pub(crate) fn next_due_ms(&self, now_ms: i64) -> i64 {
        let idle = now_ms.saturating_add(duration_as_ms(self.cfg.idle_tick));
        match self.ack_retry_due_ms {
            Some(due) if due > now_ms && due < idle => due,
            _ => idle,
        }
    }

    /// The wall time of the last tick this machine saw, if it has seen one.
    ///
    /// The shell reads it back onto its probe, so the value the machine recorded
    /// is the value an oracle asserts — a probe fed the shell's own `now` instead
    /// would pass whether or not the machine ever stored anything.
    pub(crate) fn last_tick_ms(&self) -> Option<i64> {
        self.last_tick_ms
    }

    /// The sequence number the next channel send would take, when this session
    /// holds exactly one live correspondence.
    ///
    /// **A probe read, and the only way an oracle can see the ratchet did not
    /// move.** A refused send that stepped the ratchet anyway is invisible in
    /// every other observable — no event, no write, no store change — so
    /// without this the "nothing was spent" claim cannot be tested. `None` when
    /// there is not exactly one live correspondence, so an oracle cannot read it
    /// as a number about the wrong conversation.
    pub(crate) fn only_next_send_seq(&self) -> Option<u64> {
        let mut live = self.correspondences.iter().filter_map(|c| c.live());
        let (ratchet, _, _) = live.next()?;
        live.next().is_none().then(|| ratchet.next_send_seq())
    }

    /// The resumed probe frontier of the single correspondence recovered from
    /// disk, for the oracle that pins the cursor seeding.
    ///
    /// A recovered correspondence is the one with neither a ratchet nor a
    /// pseudonym; `None` when there is not exactly one, or when it reached no
    /// page.
    pub(crate) fn only_resumed_frontier(&self) -> Option<u64> {
        let mut seeded = self
            .correspondences
            .iter()
            .filter(|c| c.ratchet.is_none() && c.signing_pc.is_none());
        let first = seeded.next()?;
        if seeded.next().is_some() {
            return None;
        }
        first.collection.frontier_page()
    }

    /// The correspondences this session holds, for the machine's own oracles.
    #[cfg(test)]
    pub(crate) fn correspondence_count(&self) -> usize {
        self.correspondences.len()
    }

    /// How many knocks are held awaiting an answer, for the machine's own
    /// oracles.
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    // ---- the channel plane: sending ----------------------------------------

    /// Send one message on an established channel.
    ///
    /// **The order is priced-refused-sealed-queued, and the first two steps come
    /// before the ratchet moves.** [`Ratchet::send_next`] takes a step with no
    /// step back, so a refusal discovered after it has burnt a sequence number
    /// that will never be transmitted — and the correspondent's contiguous
    /// prefix then waits on that number for the seven-day give-up while every
    /// later message sits beyond the prefix. So the body cap and the outbox's
    /// capacity are both asked *first*, and the capacity ask is priced against
    /// [`WORST_CASE_SEALED_FRAME_LEN`] because no caller can know its frame's
    /// real length before sealing it. That over-refuses by the margin between a
    /// real frame and the largest possible one; over-refusing is a message the
    /// user can send again, and the alternative is a hole nothing can fill.
    ///
    /// **The ask and the enqueue are two writes with a seal between them, and
    /// that is sound only because one driver owns the store.** Each takes the
    /// store's own lock, so a second writer could fill the record in the gap and
    /// the enqueue would then fail where the ask said yes — reported as
    /// [`RefusalReason::StoreFailure`] rather than as a capacity refusal, with
    /// the sequence number spent. One driver per profile is the invariant that
    /// keeps that unreachable; a second writer would need the two steps merged
    /// under one lock, which means sealing inside the closure.
    fn send(&mut self, now_ms: i64, to: &PkLt, body: String) -> Vec<DmEffect> {
        let Some(index) = self.index_of(to) else {
            return vec![DmEffect::Emit(refused(
                to,
                RefusalReason::NotEstablishedThisSession,
                None,
            ))];
        };
        let Some((ratchet, _, _)) = self.correspondences[index].live() else {
            return vec![DmEffect::Emit(refused(
                to,
                RefusalReason::NotEstablishedThisSession,
                None,
            ))];
        };
        let label = self.correspondences[index].label;
        let direction = ratchet.send_direction();
        let next_seq = ratchet.next_send_seq();

        // Checked here rather than left to `seal`, which reports it only after
        // the ratchet has already stepped.
        if body.len() > firstcontact::DM_BODY_CAP {
            return vec![DmEffect::Emit(refused(
                to,
                RefusalReason::BodyTooLarge,
                None,
            ))];
        }

        // The ask. `Unchanged` because nothing is written: this is a question
        // about the record, taken under the same lock and after the same prune
        // the enqueue below will see.
        let asked = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                Ok(Mutation::Unchanged(outbox.room_for(
                    next_seq,
                    OutboxTarget::ChannelPage,
                    WORST_CASE_SEALED_FRAME_LEN,
                )))
            });
        match asked {
            Ok(Ok(())) => {}
            Ok(Err(OutboxError::Full { needed, .. })) => {
                return vec![DmEffect::Emit(refused(
                    to,
                    RefusalReason::OutboxFull { needed },
                    None,
                ))];
            }
            Ok(Err(e)) => {
                crate::vtrace!("dm driver: the outbox refused sequence {next_seq}: {e}");
                return vec![DmEffect::Emit(refused(
                    to,
                    RefusalReason::StoreFailure,
                    None,
                ))];
            }
            Err(e) => {
                crate::vtrace!("dm driver: the outbox could not be read: {e}");
                return vec![DmEffect::Emit(refused(
                    to,
                    RefusalReason::StoreFailure,
                    None,
                ))];
            }
        }

        // Disjoint borrows: the identity's own public key is read while the
        // correspondence is held mutably for the ratchet step.
        let Self {
            identity,
            persist,
            correspondences,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        let recipient = match recipient_hash(&correspondence.pk_lt) {
            Ok(h) => h,
            Err(e) => {
                crate::vtrace!("dm driver: recipient hash failed: {e}");
                return vec![DmEffect::Emit(refused(to, RefusalReason::Module, None))];
            }
        };
        let (Some(ratchet), Some(signing_pc), Some(channel)) = (
            correspondence.ratchet.as_mut(),
            correspondence.signing_pc.as_ref(),
            correspondence.channel.as_ref(),
        ) else {
            return vec![DmEffect::Emit(refused(
                to,
                RefusalReason::NotEstablishedThisSession,
                None,
            ))];
        };
        // Past this line a sequence number has been spent.
        let outbound = match ratchet.send_next() {
            Ok(o) => o,
            Err(e) => {
                crate::vtrace!("dm driver: the ratchet refused to mint a key: {e}");
                return vec![DmEffect::Emit(refused(to, RefusalReason::SealFailed, None))];
            }
        };
        let seq = outbound.header.seq;
        // The piggybacked acknowledgement rides for free: `seal` reads the
        // collection's own state, so a message going out carries what has come
        // in without a second record, a second write, or a second signature.
        // Read before the seal, which consumes the outbound. This is the entry's
        // sealing-chain provenance, and the ratchet will have moved past it by
        // the time anything asks.
        let sealed_under_gen = outbound.header.generation;
        let sealed = match frame::seal(
            outbound,
            &channel.chan_id,
            signing_pc,
            identity.signing.public_key(),
            &recipient,
            now_ms,
            &body,
            Some(correspondence.collection.ack()),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                crate::vtrace!("dm driver: the frame would not seal: {e}");
                return vec![DmEffect::Emit(refused(to, RefusalReason::SealFailed, None))];
            }
        };
        let queued = persist.update_outbox(&label, direction, now_ms, |outbox| {
            outbox.enqueue_sealed(
                seq,
                OutboxTarget::ChannelPage,
                now_ms,
                SealedFrame::new(sealed),
                sealed_under_gen,
            )?;
            Ok(Mutation::Changed(()))
        });
        if let Err(e) = queued {
            // The ask said there was room and the record has not been touched
            // since, so this is a store fault rather than the capacity refusal
            // — and the sequence number IS spent, because the seal is behind us.
            crate::vtrace!("dm driver: sequence {seq} sealed and could not be queued: {e}");
            return vec![DmEffect::Emit(refused(
                to,
                RefusalReason::StoreFailure,
                None,
            ))];
        }
        vec![DmEffect::Emit(DmEvent::Delivery {
            to: Box::new(**to),
            seq,
            state: DeliveryState::Composed,
        })]
    }

    /// The UI has shown these delivery states, so stop re-offering them (#279).
    ///
    /// **This is the only thing that clears the durable flag**, and it runs
    /// after the event reached the front end rather than in the write that
    /// produced it — the ordering [`Outbox::record_surfaced`] requires. The
    /// in-memory suppression is dropped alongside it, so a sequence the front
    /// end never answered is offered again on the next run.
    fn record_surfaced(&mut self, now_ms: i64, to: &PkLt, seqs: &[u64]) -> Vec<DmEffect> {
        let Some(index) = self.index_of(to) else {
            return Vec::new();
        };
        let label = self.correspondences[index].label;
        let Some(direction) = self.stored_direction(&label, now_ms) else {
            return Vec::new();
        };
        match self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                outbox.record_surfaced(seqs);
                Ok(Mutation::Changed(()))
            }) {
            Ok(()) => {
                self.correspondences[index]
                    .offered_this_session
                    .retain(|seq| !seqs.contains(seq));
            }
            Err(e) => {
                crate::vtrace!("dm driver: the surfacing record could not be written: {e}");
            }
        }
        Vec::new()
    }

    /// Turn the seven-day window into events, for this correspondence.
    ///
    /// **Nothing is cleared here, and that is the #279 ordering.**
    /// [`Outbox::record_surfaced`] must run *after* the user has been told, not
    /// in the write that swept: clearing first puts the flag out of the record
    /// while the notification is still in a `Vec` somebody is carrying, so a
    /// crash in between loses it for good. So the flag stays owed until
    /// [`DmCommand::Surfaced`] says the front end has shown it, and every crash
    /// before that re-offers.
    ///
    /// Re-offering on every tick is what an in-memory set suppresses instead:
    /// the record keeps the durable obligation and this session declines to
    /// repeat itself, so a front end sees one event per give-up per run and a
    /// restart before the answer sees it again.
    ///
    /// **The direction comes from the stored record, not from a ratchet.** An
    /// outbox outlives the key schedule, so a correspondence recovered from disk
    /// still owes its user the fate of everything queued in it.
    fn give_ups(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let label = self.correspondences[index].label;
        let Some(direction) = self.stored_direction(&label, now_ms) else {
            return Vec::new();
        };
        let owed = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                let swept = outbox.sweep_give_ups(now_ms);
                // The full owed list, never only what the sweep moved: an entry
                // owed by a previous run's give-up is owed just the same.
                //
                // **Every owed sequence still has its entry**, which is why
                // there is no fallback state here. `Outbox::owed_surfacings`
                // reads the live entry map for `Surfacing::Owed`, and
                // `Outbox::prune` removes only entries whose surfacing is
                // `Surfacing::Clear` — so an entry cannot be pruned while it is
                // owed, and a sequence that reaches this map has an entry
                // behind it by construction. A `map_or` default here would be a
                // state no path produces, and it would read as a delivery
                // verdict rather than as the dead branch it is.
                let owed: Vec<(u64, DeliveryState)> = outbox
                    .owed_surfacings()
                    .into_iter()
                    .filter_map(|seq| outbox.entry(seq).map(|e| (seq, e.delivery_state())))
                    .collect();
                // **Read here rather than from a second `read_outbox`.** The
                // record is already open, decoded and authenticated inside this
                // closure, so a second pass would be a file read plus an AEAD open
                // per correspondence per tick for a value already in hand.
                //
                // Every given-up entry, not only the ones this sweep moved. A
                // refusal at `MAX_ACK_RUNS` leaves the position unsettled, and
                // re-offering it is what lets a later pass take it once the cap
                // frees; `abandon` is idempotent, so re-offering a settled one
                // costs a comparison.
                let given_up: Vec<u64> = outbox
                    .iter()
                    .filter(|e| e.delivery_state() == DeliveryState::Undelivered)
                    .map(|e| e.seq())
                    .collect();
                let out = (owed, given_up);
                Ok(if swept.is_empty() {
                    Mutation::Unchanged(out)
                } else {
                    Mutation::Changed(out)
                })
            });
        let (owed, given_up) = match owed {
            Ok(pair) => pair,
            Err(e) => {
                crate::vtrace!("dm driver: the give-up sweep failed: {e}");
                return Vec::new();
            }
        };
        // **The give-up settles the position for the page close, and only on this
        // side.** A message this sender abandoned is one nothing will re-seed and
        // nothing will ever ask about again, so the page holding it is finished
        // whether or not the correspondent ever acknowledged it. Without this a
        // single permanently-undelivered message pins `own_ack`'s prefix, and every
        // sending page of the conversation from that position on stays open for the
        // life of the process — the growth #252 is about, reached through the one
        // door the acknowledgement cannot close.
        //
        // `own_ack` is LOCAL: the record this side publishes is built from
        // `collection.ack()`, the receiving direction, so nothing settled here
        // reaches the wire and no peer is told a message it never sent was
        // collected. The outbox is unaffected for the same reason
        // `Outbox::settle_from_ack` states — a terminal entry is skipped before the
        // ack is consulted, so a given-up message can never be confirmed by a prefix
        // that walked over it.
        //
        for seq in given_up {
            if let Err(e) = self.correspondences[index].own_ack.abandon(seq) {
                crate::vtrace!("dm driver: sequence {seq} would not settle as given up: {e}");
            }
        }

        let correspondence = &mut self.correspondences[index];
        let mut out = Vec::new();
        for (seq, state) in owed {
            if correspondence.offered_this_session.contains(&seq) {
                continue;
            }
            correspondence.offered_this_session.push(seq);
            out.push(DmEffect::Emit(DmEvent::Delivery {
                to: Box::new(*correspondence.pk_lt),
                seq,
                state,
            }));
        }
        // The give-up is a settlement like any other, so the pages it finished are
        // offered here for the same reason `on_page` and `on_peer_ack` offer theirs.
        out.extend(self.retire_pages(index));
        out
    }

    /// One correspondence's load-time re-establishment work: the dead-chain
    /// sweep, and then the decision whether to open a re-establishment.
    ///
    /// **The sweep is a derivation re-run at every load, not a transaction**
    /// (`docs/design/direct-messaging.md:927`, A3.12), so a crash between the
    /// resume record's commit and this pass is repaired here rather than
    /// prevented.
    ///
    /// **The reconnect decision is UNSEALED mail, not any mail.** A4.2's cause 2
    /// is *"an entry composed while no chain exists"* — an entry that cannot
    /// seal without a channel and would otherwise run to `Undelivered` with no
    /// `RE-EST` ever sent. An already-sealed entry is cause 1: it re-seeds on its
    /// own persisted ladder against the chain it was sealed under, and does not
    /// need this handshake to make progress. Gating on it would open a
    /// re-establishment for a conversation that is only waiting for an
    /// acknowledgement.
    ///
    /// **A persisted attempt is re-emitted, never re-sealed** (A9.1(a),
    /// `:1351`), and the position it goes back to is the one stored in the slot
    /// rather than a fresh `next_send_seq`: `seq` is bound into the leg's seal
    /// key and signature, so any other number publishes bytes the peer cannot
    /// verify at an address it is not reading.
    ///
    /// **Commit before emit.** The record carrying the sealed leg is written
    /// first and the outbox entry follows, so a crash between them leaves a
    /// record whose bytes this pass re-emits unchanged and a wire that never saw
    /// the attempt at all.
    ///
    /// **The pass is owed until it completes.** A store that would not answer
    /// this tick may answer the next, and a flag cleared on the way past would
    /// leave the correspondence unswept and unattempted for the life of the
    /// session over a fault that had already gone. What bounds the retry is
    /// [`REARM_FAULT_CEILING`], the same number and the same argument as the
    /// handshake re-arm beside it.
    ///
    /// The swept entries are not surfaced here: `sweep_dead_chain` leaves each
    /// one owing a surfacing in the record, and [`Self::give_ups`] — which runs
    /// after this in the same tick — is what reads that obligation and tells the
    /// front end.
    ///
    /// **What happens to the leg this queues.** It is published by
    /// [`Self::due_emissions`] like any other entry, addressed by
    /// `msg_addr(dir, seq)` off the address root and the outbox's stored
    /// direction rather than off a key schedule the restart destroyed, and it
    /// re-seeds on the ordinary ladder from a first dispatch drawn out of A5.5's
    /// reconnect-cadence band. Its give-up clock runs from the enqueue like
    /// every other entry's: what a leg is exempt from is the give-up *sweep*,
    /// which reports a message that failed to arrive, and
    /// [`Self::reest_upkeep`] is what ends it instead — through
    /// [`Outbox::abandon_leg`], with A3.8's *re-establishment failed* rather
    /// than a delivery report at a sequence the user composed nothing at.
    fn resume_channel(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        if !self.correspondences[index].resume_owed {
            return Vec::new();
        }
        // A3.15 row 6's backoff: a pass that faulted is not asked again until
        // its rung comes round. Nothing is owed to a correspondence that has
        // never faulted, so the first pass runs on the tick that finds it.
        if self.correspondences[index]
            .resume_retry_due_ms
            .is_some_and(|due| now_ms < due)
        {
            return Vec::new();
        }
        let label = self.correspondences[index].label;
        let mut record = match self.persist.read_resume(&label) {
            Ok(Some(record)) => record,
            // **A3.15 row 6, the `absent` half.** The contact record says this
            // correspondence is established and no resume record stands beside
            // it, so nothing can sign a leg and nothing can ever re-root the
            // chain. The design has this *"surface the recovery offer"*, and the
            // offer is a fresh first contact.
            Ok(None) => {
                self.correspondences[index].resume_owed = false;
                let owed = pending_seqs(&self.persist, &label, now_ms);
                return cannot_resume(&self.correspondences[index], owed);
            }
            // **A3.15 row 6, the `unreadable` half: loud on first occurrence,
            // and it keeps retrying.** A record that is present and will not
            // read is most likely still intact on disk, so offering a
            // destructive fresh first contact over it would spend an invite
            // token to destroy a working channel — which is why the design
            // splits this case from `absent` above rather than merging them. The
            // event fires once per session; the retry is what the flag left set
            // buys.
            Err(e) => {
                crate::vtrace!("dm driver: the resume record will not read: {e}");
                return self.resume_fault(now_ms, index);
            }
        };
        let direction = match self.persist.read_outbox(&label, now_ms) {
            Ok(Some(outbox)) => outbox.direction(),
            // No outbox record: nothing has ever been queued, so there is no
            // dead chain to sweep and no mail to re-establish for. Settled, not
            // faulted.
            Ok(None) => {
                self.correspondences[index].resume_owed = false;
                return Vec::new();
            }
            // A store that would not answer says nothing about whether an outbox
            // exists, so this is the fault path rather than the settled one —
            // `stored_direction` folds the two together, which is right for a
            // caller that only wants to drive what it can see and wrong for a
            // pass that has to run exactly once.
            Err(e) => {
                crate::vtrace!("dm driver: the outbox direction would not read: {e}");
                return self.resume_fault(now_ms, index);
            }
        };
        // **The acceptor's knock position is re-settled here, and it has to be
        // somewhere.** `collection_accepting_a_knock` settles sequence zero of
        // the receiving plane at the moment a knock is accepted, because the
        // knock arrived by doorbell and no page will ever hold it — and a
        // collection rebuilt from a stored cursor loses that, so the contiguous
        // prefix would never start and every acknowledgement this side writes
        // would carry a permanent hole under it. It was unreachable while a
        // resumed correspondence swept nothing; it is reachable now.
        //
        // The acceptor is the side whose outbox sends `b2a`; the initiator's own
        // sequence zero is the acceptance, which is a real page frame and must
        // stay unsettled until it opens. Idempotent, so the retry a store fault
        // earns costs nothing.
        if direction == Direction::BToA {
            if let Err(e) = self.correspondences[index]
                .collection
                .collected(position_of(KNOCK_CHANNEL_SEQ))
            {
                crate::vtrace!("dm driver: the knock's own position would not re-settle: {e}");
            }
        }
        let held = record
            .own_slot()
            .map(|slot| (slot.seq(), slot.sealed().bytes().to_vec()));
        let held_seq = held.as_ref().map(|(seq, _)| *seq);
        let reroot_gen = record.reroot_ratchet_gen();
        let floor = record.send_floor();
        let surveyed = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                // **The floor is checked before the sweep, and a refusal changes
                // nothing.** A9.2's send-side floor is durable and the outbox's
                // own counters are not, so an outbox behind it is a record that
                // has been rolled back — and the sweep is a derivation from the
                // resume record onto exactly that outbox. Running it over a
                // rolled-back record would end entries against a generation the
                // outbox never reached.
                let position = SendFloor::new(outbox.last_clear_gen(), outbox.next_send_seq());
                if !floor.admits(position) {
                    return Ok(Mutation::Unchanged(ResumeSurvey::FloorRegressed {
                        floor,
                        position,
                    }));
                }
                let fired = outbox.sweep_dead_chain(reroot_gen);
                // **Keyed on the stored sequence, not on a live frame's bytes.**
                // `OutboxEntry::frame` answers `Some` only while an entry is
                // awaiting collection, so a byte comparison goes empty the moment
                // a give-up or a sweep ends the leg — and every later load would
                // read that as "never queued" and spend another sequence on the
                // same stale attempt.
                let leg = held_seq.map(|seq| {
                    if outbox.entry(seq).is_some() {
                        LegState::Queued
                    } else if outbox.next_send_seq() > seq {
                        // The sequence was spent and its entry has since been
                        // pruned. The bytes are bound to that position and
                        // cannot move to another.
                        LegState::Stale
                    } else {
                        LegState::Missing
                    }
                });
                let survey = ResumeSurvey::Surveyed {
                    unsealed_pending: outbox
                        .iter()
                        .any(|entry| matches!(entry.lifecycle(), Lifecycle::AwaitingKey)),
                    next_seq: outbox.next_send_seq(),
                    leg,
                };
                Ok(if fired.is_empty() {
                    Mutation::Unchanged(survey)
                } else {
                    Mutation::Changed(survey)
                })
            });
        let survey = match surveyed {
            Ok(survey) => survey,
            Err(e) => {
                crate::vtrace!("dm driver: the dead-chain sweep did not run: {e}");
                return self.resume_fault(now_ms, index);
            }
        };
        let (unsealed_pending, next_seq, leg) = match survey {
            ResumeSurvey::FloorRegressed { floor, position } => {
                crate::vtrace!(
                    "dm driver: the outbox is at {position:?}, behind the resume record's \
                     floor {floor:?}; nothing is swept and no attempt is opened"
                );
                self.correspondences[index].resume_owed = false;
                return Vec::new();
            }
            ResumeSurvey::Surveyed {
                unsealed_pending,
                next_seq,
                leg,
            } => (unsealed_pending, next_seq, leg),
        };
        match (leg, held) {
            (Some(LegState::Queued), _) => {
                self.correspondences[index].resume_owed = false;
                return Vec::new();
            }
            // **The slot is released here, not left occupied.** The stored bytes
            // are bound to a sequence the outbox has spent, so they can never go
            // back on the wire — and leaving the slot would make
            // `ResumeRecord::open_attempt` refuse for ever, which is the
            // dead-end state A3.13 forbids. The counter stands still, so the
            // next attempt is the successor of the one given up.
            (Some(LegState::Stale), Some((seq, _))) => {
                crate::vtrace!(
                    "dm driver: the stored attempt is addressed at sequence {seq}, which the \
                     outbox has moved past"
                );
                record.abandon_attempt();
                if let Err(e) = self.persist.commit_resume(&label, &record) {
                    crate::vtrace!("dm driver: the give-up would not commit: {e}");
                    return self.resume_fault(now_ms, index);
                }
                // **The pass stays owed, which is what makes the give-up an exit
                // rather than an end.** The slot is free now, so the next tick
                // opens the successor of the attempt just abandoned; leaving the
                // flag clear would make a replacement wait for a restart, which
                // is A3.13's dead-end state wearing a different clock.
                self.correspondences[index].resume_owed = true;
                let owed = pending_seqs(&self.persist, &label, now_ms);
                return cannot_resume(&self.correspondences[index], owed);
            }
            (Some(LegState::Missing), Some((seq, bytes))) => {
                if !requeue_leg(
                    &self.persist,
                    &label,
                    direction,
                    now_ms,
                    seq,
                    &bytes,
                    LegDispatch::ReconnectBand,
                ) {
                    return self.resume_fault(now_ms, index);
                }
                self.correspondences[index].resume_owed = false;
                return Vec::new();
            }
            // A leg state is derived from the stored slot's own sequence, so a
            // state with no slot behind it is a value the survey cannot produce.
            // Named rather than unwrapped: an `expect` here would abort the
            // driver over a correspondence, and the honest answer is to leave
            // this one alone and say so.
            (Some(state), None) => {
                crate::vtrace!(
                    "dm driver: the outbox survey reported {state:?} for a record with no \
                     handshake slot"
                );
                self.correspondences[index].resume_owed = false;
                return Vec::new();
            }
            (None, _) => {}
        }
        if !unsealed_pending {
            self.correspondences[index].resume_owed = false;
            return Vec::new();
        }
        if AttemptBudget::from_record(&record).exhausted() {
            // **Loud, not a trace.** A3.8 has every anomaly classed and
            // suppression-protected, and a window with no attempts left is a
            // conversation that will not come back on its own: nothing here
            // moves the anchor but a peer opening one of our attempts, and no
            // attempt can be sent to be opened.
            let owed = pending_seqs(&self.persist, &label, now_ms);
            crate::vtrace!(
                "dm driver: this re-initiation window has spent every attempt it admits, \
                 with {} message(s) owed",
                owed.len()
            );
            self.correspondences[index].resume_owed = false;
            return cannot_resume(&self.correspondences[index], owed);
        }
        // The generation the initiation is REACHING, one past the committed one:
        // A3.4 advances `reconnect_gen` only on a completed handshake, and
        // `ReEstGate` drops a leg at or below the generation its own record has
        // committed. Both sides compute it from their own committed number, so
        // neither reads it off the wire.
        let generation = record.reconnect_gen().saturating_add(1);
        let fresh = match record.attempt() {
            Some(attempt) => attempt.advance(),
            None => Some(daemonseed_core::dm::resume::FreshAttempt::first()),
        };
        let Some(fresh) = fresh else {
            // The counter is at its ceiling. The same record answers the same
            // way on every later tick, so this is settled rather than faulted.
            crate::vtrace!("dm driver: the attempt counter has no successor");
            self.correspondences[index].resume_owed = false;
            return Vec::new();
        };
        let (eph_ek, eph_dk) = match reest::mint_ephemeral() {
            Ok(pair) => pair,
            Err(e) => {
                crate::vtrace!("dm driver: the re-establishment ephemeral would not mint: {e}");
                return self.resume_fault(now_ms, index);
            }
        };
        let leg = match reest::seal_re_est(
            record.committed_root(),
            direction,
            generation,
            next_seq,
            &fresh,
            &eph_ek,
            record.s_pc(),
        ) {
            Ok(leg) => leg,
            Err(e) => {
                crate::vtrace!("dm driver: the RE-EST leg would not seal: {e}");
                return self.resume_fault(now_ms, index);
            }
        };
        let sealed = match SealedReEst::seal(fresh, leg.into_boxed_slice()) {
            Ok(sealed) => sealed,
            // A length refusal, and every leg is one length: the same bytes
            // answer the same way on every tick, so this is settled.
            Err(e) => {
                crate::vtrace!("dm driver: the sealed leg would not bind to its attempt: {e}");
                self.correspondences[index].resume_owed = false;
                return Vec::new();
            }
        };
        let bytes = sealed.bytes().to_vec();
        if let Err(e) = record.open_attempt(next_seq, sealed, eph_dk) {
            // A refusal about the record's own state — an occupied slot, a
            // counter that does not advance — which the same record repeats.
            crate::vtrace!("dm driver: the attempt would not open on the record: {e}");
            self.correspondences[index].resume_owed = false;
            return Vec::new();
        }
        if let Err(e) = self.persist.commit_resume(&label, &record) {
            crate::vtrace!("dm driver: the opened attempt would not commit: {e}");
            return self.resume_fault(now_ms, index);
        }
        if !requeue_leg(
            &self.persist,
            &label,
            direction,
            now_ms,
            next_seq,
            &bytes,
            LegDispatch::ReconnectBand,
        ) {
            // The record holds the attempt and the wire has seen nothing, which
            // is exactly the crash window the re-emit path recovers: the next
            // pass finds the slot occupied and its sequence unspent, and queues
            // the same bytes. So this is owed, not settled.
            return self.resume_fault(now_ms, index);
        }
        self.correspondences[index].resume_owed = false;
        Vec::new()
    }

    /// One correspondence's per-tick re-establishment upkeep: no stored leg is
    /// lost, no leg lives for ever, and no retained root outlives its ceiling.
    ///
    /// **Idempotent, and run at every tick rather than once at load**, on the
    /// same reasoning A3.12 gives the dead-chain sweep: every decision here is a
    /// derivation from two durable facts — the record's slots and the outbox's
    /// entries — so re-running it costs a read and changes nothing, and a crash
    /// between any commit and the enqueue that should have followed it is
    /// repaired by the next pass instead of being prevented by a transaction.
    ///
    /// Five things, in an order that matters only where noted:
    ///
    /// 1. **`T_RETIRE`** (A3.5): a retained `RS_n` past its write-once
    ///    `superseded_at_ms` plus the ceiling is retired with the dedup memory
    ///    scoped to it, and A3.8's *re-establishment unconfirmed* is raised. An
    ///    actor able to suppress frames therefore buys at most the window, and
    ///    pays with an event.
    /// 2. **The initiator's confirming observation** (A3.6): *"the ordinary
    ///    acknowledgement settling `RE-CONFIRM`'s sequence position within its
    ///    give-up window"*. When the stored settling leg's own entry has been
    ///    confirmed collected inside that window, the leg is released and the
    ///    retained root retires with it.
    /// 3. **Stored legs go back on the wire** (A9.1(a)): a slot holding sealed
    ///    bytes whose outbox entry is absent is re-queued at the sequence the
    ///    slot records. This is the crash-between-commit-and-enqueue recovery,
    ///    and it covers all three legs — the own slot's `RE-EST` on the
    ///    reconnect band, the acceptance slot's `RE-ACK` and the confirm slot's
    ///    `RE-CONFIRM` on the ordinary ladder.
    /// 4. **Orphan legs are retired** (A3.12): a pending leg entry whose
    ///    sequence matches no live slot belongs to an exchange the record has
    ///    moved past, and nothing will ever answer it.
    /// 5. **Leg give-up** (A3.8's *re-establishment failed*): a leg unanswered
    ///    for `GIVE_UP` ends — not on the user-facing undelivered list, which is
    ///    for messages, but through [`Outbox::abandon_leg`] — and where it was
    ///    this side's own initiation the attempt is released so the next pass
    ///    opens its successor. A3.13 forbids a terminal state, so the pass is
    ///    left owed rather than stopped.
    ///
    /// Step 3 runs after steps 1 and 2 so a leg retired by either is not
    /// re-queued in the same pass; step 5 runs last so a leg re-queued by step 3
    /// is judged on the give-up clock it actually carries.
    fn reest_upkeep(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let label = self.correspondences[index].label;
        // An unestablished correspondence has no resume record and nothing to
        // keep up; `resume_channel` owns the loud paths for one that should.
        if self.correspondences[index].peer_pk_pc.is_none() {
            return Vec::new();
        }
        let Some(direction) = self.stored_direction(&label, now_ms) else {
            return Vec::new();
        };
        let Ok(Some(mut record)) = self.persist.read_resume(&label) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut dirty = false;

        // ── 1. the retention ceiling ─────────────────────────────────────────
        let expired = record
            .retained()
            .is_some_and(|held| now_ms.saturating_sub(held.superseded_at_ms()) >= T_RETIRE_MS);
        if expired {
            record.retire_retained();
            dirty = true;
            if !self.correspondences[index].retire_ceiling_surfaced {
                self.correspondences[index].retire_ceiling_surfaced = true;
                out.push(DmEffect::Emit(DmEvent::ReestablishmentAnomaly {
                    with: Box::new(*self.correspondences[index].pk_lt),
                    event: TrustEventKey::DmReestablishmentUnconfirmed,
                }));
            }
        }

        // ── 2. the initiator's confirming observation ────────────────────────
        if let Some(confirm) = record.confirm_slot() {
            // **A store that would not answer is not an observation.** Folding
            // the fault into `false` reads the same as *the peer has not
            // collected it yet*, which is the safe direction here — the leg
            // stays owed — but it is still a fault worth a line, on the terms
            // every sibling read in this pass states. The verdict itself is
            // deliberately conservative: an absent entry means the leg was
            // pruned or never queued, and neither is a confirming observation.
            let settled = match self.persist.read_outbox(&label, now_ms) {
                Ok(Some(outbox)) => outbox.entry(confirm.seq()).is_some_and(|entry| {
                    entry.delivery_state() == DeliveryState::ConfirmedCollected
                }),
                Ok(None) => false,
                Err(e) => {
                    crate::vtrace!(
                        "dm driver: the outbox would not read for the confirming \
                         observation: {e}"
                    );
                    false
                }
            };
            if settled {
                record.retire_confirm();
                // A3.6 makes this the same observation the retention ceiling was
                // the fallback for, so the root goes with the leg.
                record.retire_retained();
                dirty = true;
            }
        }

        // ── 3. every stored leg is queued, or re-queued ──────────────────────
        let mut stored: Vec<(u64, Vec<u8>, LegDispatch)> = Vec::new();
        if let Some(slot) = record.own_slot() {
            stored.push((
                slot.seq(),
                slot.sealed().bytes().to_vec(),
                LegDispatch::ReconnectBand,
            ));
        }
        if let Some(slot) = record.acceptance() {
            stored.push((
                slot.seq(),
                slot.sealed_re_ack().to_vec(),
                LegDispatch::Ladder,
            ));
        }
        if let Some(slot) = record.confirm_slot() {
            stored.push((slot.seq(), slot.sealed().to_vec(), LegDispatch::Ladder));
        }
        let live: Vec<u64> = stored.iter().map(|(seq, _, _)| *seq).collect();
        for (seq, bytes, dispatch) in &stored {
            requeue_leg(
                &self.persist,
                &label,
                direction,
                now_ms,
                *seq,
                bytes,
                *dispatch,
            );
        }

        // ── 4 and 5. orphans, and the give-up ────────────────────────────────
        let swept = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                let pending: Vec<(u64, bool)> = outbox
                    .iter()
                    .filter(|entry| {
                        matches!(entry.target(), OutboxTarget::ReEstablishmentLeg)
                            && entry.lifecycle().is_pending()
                    })
                    .map(|entry| (entry.seq(), entry.is_given_up(now_ms)))
                    .collect();
                let mut given_up = Vec::new();
                let mut changed = false;
                for (seq, past_give_up) in pending {
                    if !live.contains(&seq) {
                        changed |= outbox.retire_leg(seq);
                    } else if past_give_up {
                        changed |= outbox.abandon_leg(seq);
                        given_up.push(seq);
                    }
                }
                Ok(if changed {
                    Mutation::Changed(given_up)
                } else {
                    Mutation::Unchanged(given_up)
                })
            });
        let given_up = match swept {
            Ok(given_up) => given_up,
            Err(e) => {
                crate::vtrace!("dm driver: the leg sweep did not run: {e}");
                Vec::new()
            }
        };
        if !given_up.is_empty() {
            // **The own slot is released, so the next pass opens a successor.**
            // A3.13 forbids a dead end and A5.2 keeps the counter monotone, so
            // the abandoned number is never reused.
            if record
                .own_slot()
                .is_some_and(|slot| given_up.contains(&slot.seq()))
            {
                record.abandon_attempt();
                dirty = true;
                self.correspondences[index].resume_owed = true;
                self.correspondences[index].resume_retry_due_ms = None;
            }
            if !self.correspondences[index].leg_give_up_surfaced {
                self.correspondences[index].leg_give_up_surfaced = true;
                out.push(DmEffect::Emit(DmEvent::ReestablishmentAnomaly {
                    with: Box::new(*self.correspondences[index].pk_lt),
                    event: TrustEventKey::DmReestablishmentFailed,
                }));
            }
        }

        if dirty {
            if let Err(e) = self.persist.commit_resume(&label, &record) {
                // Every change above is a derivation from durable state, so a
                // refused commit costs one pass: the next tick reads the same facts
                // and reaches the same answers.
                crate::vtrace!("dm driver: the re-establishment upkeep would not commit: {e}");
            }
        }
        out
    }

    /// Keep the load-time pass owed after a store fault, widen the retry, and
    /// say so once.
    ///
    /// **The flag survives the fault**, which is the whole of the difference
    /// between a transient answer and a settled one: a correspondence whose
    /// resume record could not be read this tick is one to ask again, not one to
    /// leave unswept for the session.
    ///
    /// **A3.15 row 6 says the retry is on a BACKOFF, so it is.** The delay is
    /// [`ReseedSchedule::delay_for_rung`](daemonseed_core::dm::outbox::ReseedSchedule::delay_for_rung) at the fault count — the outbox's own
    /// re-seed ladder, reused rather than a second cadence — so a store that
    /// keeps refusing is asked at a minute, then two, then four, and finally
    /// once an hour, instead of costing two sealed reads on every tick for the
    /// life of the session.
    ///
    /// **Hourly is the ceiling, not the ladder's daily rung, and A3.15 row 6 is
    /// why.** The design's reason for retrying at all is that the record is
    /// *"most likely still on disk and untouched"* and offering a destructive
    /// fresh first contact over an `EIO` would spend an invite token to destroy a
    /// working channel — so the retry exists to pick the correspondence up when
    /// the store heals. A daily rung leaves a healed store unread for up to a
    /// day; an hourly one costs two sealed reads an hour, which is nothing beside
    /// the poll table [`crate::dm`]'s store module prices. Reaching the ladder's
    /// top rung would mean raising [`REARM_FAULT_CEILING`], and that number is
    /// the handshake re-arm's too.
    ///
    /// **The pass is never abandoned.** A3.13 forbids a terminal state, and a
    /// correspondence given up on here is one whose user is told nothing further
    /// however long the disk stays broken. Past [`REARM_FAULT_CEILING`] the
    /// backoff simply stops widening — the ladder repeats its top rung, which is
    /// the shape [`RESEED_LADDER`] itself has — and one further event says the
    /// retry has reached that cadence.
    ///
    /// The event is A3.15 row 6's `unreadable` half and fires on the first fault
    /// of a run: the design has it *"loud on first occurrence, never a silent
    /// loop"*, and one per retry is that loop.
    fn resume_fault(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let correspondence = &mut self.correspondences[index];
        let faults = correspondence
            .resume_faults
            .saturating_add(1)
            .min(REARM_FAULT_CEILING);
        correspondence.resume_faults = faults;
        let delay = ReseedSchedule::delay_for_rung(u32::from(faults).saturating_sub(1));
        correspondence.resume_retry_due_ms = Some(now_ms.saturating_add(duration_as_ms(delay)));
        let at_ceiling = faults >= REARM_FAULT_CEILING && !correspondence.resume_ceiling_surfaced;
        if at_ceiling {
            correspondence.resume_ceiling_surfaced = true;
        } else if correspondence.resume_surfaced {
            return Vec::new();
        }
        correspondence.resume_surfaced = true;
        let cause = if at_ceiling {
            "the resume record has not read for the whole backoff"
        } else {
            "the resume record will not read"
        };
        vec![DmEffect::Emit(DmEvent::ChannelLost {
            with: Box::new(*correspondence.pk_lt),
            cause: TeardownCause::StoreUnreadable(cause.into()),
            event: TrustEventKey::DmProvisionalRecordUnreadable,
            surfaced: Vec::new(),
        })]
    }

    /// The direction the stored outbox was written for, or `None` when there is
    /// no record and so nothing to drive.
    ///
    /// **Read from the store rather than from the ratchet**, because the two
    /// have different lifetimes: the record survives a restart and the key
    /// schedule does not, and a queued knock still has to be re-seeded and still
    /// has to be given up on.
    fn stored_direction(&self, label: &CorrespondenceLabel, now_ms: i64) -> Option<Direction> {
        stored_direction(&self.persist, label, now_ms)
    }

    /// Emit every entry the re-seed ladder says is due, for this correspondence.
    ///
    /// [`OutboxEntry::emit`] advances the jittered backoff, so the emission and
    /// the schedule move together under one lock: an entry whose bytes were
    /// handed to the transport is not due again until its next rung, whatever
    /// the transport then does with them.
    ///
    /// **A doorbell entry needs no key schedule and is re-seeded without one.**
    /// Its address is a pure function of the correspondent's public identity key
    /// and its bytes are in the record, so a correspondence recovered from disk
    /// keeps re-seeding an unconfirmed knock — which is the whole point of
    /// queueing the knock rather than publishing it once. A channel entry is
    /// different: its address descends from the ratchet, so without one there is
    /// no page to write to, and such an entry is left un-emitted rather than
    /// having its backoff advanced for a write that cannot happen.
    fn due_emissions(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        self.retry_pending_erases();
        // **A refused acceptance is retried here, and nowhere else.**
        // `fire_accept` runs once, inside the accept, and every one of its
        // refusals is recoverable — a full outbox drains, a store fault
        // clears. Without a retry the acceptor keeps a conversation the
        // initiator can write to and can never read, permanently and silently,
        // because the acceptance is the only frame that carries this side's
        // pseudonym and nothing else carries it.
        //
        // **The condition is the unspent sequence, not a missing entry.**
        // `fire_accept` spends sequence zero before it can fail on anything but
        // the outbox ask, so an acceptor whose chain is still at zero is one
        // whose acceptance was never composed. An entry-absence test would fire
        // again after a give-up pruned the entry and re-compose at a sequence
        // number the peer has already been shown.
        if let Some((ratchet, _, _)) = self.correspondences[index].live() {
            if ratchet.send_direction() == Direction::BToA
                && ratchet.next_send_seq() == FIRST_RECIPIENT_CHANNEL_SEQ
            {
                let retried = self.fire_accept(now_ms, index);
                let mut out = retried;
                out.extend(self.due_emissions_only(now_ms, index));
                return out;
            }
        }
        self.due_emissions_only(now_ms, index)
    }

    /// Try again to erase every provisional record a previous attempt could
    /// not reach.
    ///
    /// Cheap and idempotent: the list is empty on every tick but the ones
    /// following a store fault, and a record the store now says is absent
    /// leaves the list for good. Runs on the tick rather than at the failure,
    /// because the failure is by definition a moment the store could not be
    /// written.
    fn retry_pending_erases(&mut self) {
        if self.pending_erase.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending_erase);
        self.pending_erase = pending
            .into_iter()
            .filter(|(label, keyrec_addr, fc_epoch)| {
                match erase_record(&self.persist, label, keyrec_addr, *fc_epoch) {
                    Erasure::Deleted | Erasure::Absent => false,
                    Erasure::Retry => true,
                }
            })
            .collect();
    }

    /// The emission scan proper, without the acceptance retry above it.
    fn due_emissions_only(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let label = self.correspondences[index].label;
        let Some(direction) = self.stored_direction(&label, now_ms) else {
            return Vec::new();
        };
        // A torn-down conversation writes no more channel frames: its pages were
        // handed back, and a write would re-open the record that was released. The
        // gate is folded into `live` because it answers the same question the
        // channel-page arm below asks — is there a channel to write on — and the
        // doorbell arm is deliberately left alone, a re-seeded knock being how a
        // correspondence that lost its state is re-established.
        let live = self.correspondences[index]
            .live()
            .is_some_and(|(r, _, _)| !self.torn_down.contains(r.ar_fingerprint()));
        let address_root = self.correspondences[index].address_root;
        let emitted = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                let mut out: Vec<(u64, OutboxTarget, Vec<u8>)> = Vec::new();
                let mut unaddressable = 0u64;
                for seq in outbox.due(now_ms) {
                    let Some(entry) = outbox.entry_mut(seq) else {
                        continue;
                    };
                    let target = entry.target();
                    if matches!(target, OutboxTarget::ChannelPage) && !live {
                        continue;
                    }
                    // **A leg whose record address will not derive is skipped
                    // BEFORE `emit`, and that is the whole of it.** `emit`
                    // advances the jittered ladder whatever the caller then does
                    // with the bytes, so a leg picked up while its address is
                    // underivable would walk `RESEED_LADDER` end to end against
                    // a write that never happens — and a derivation that starts
                    // working again would find the entry on the hourly rung with
                    // its give-up nearly spent. Counted, not silent: the address
                    // is a pure function of the address root, so a refusal here
                    // is a module fault rather than a state.
                    if matches!(target, OutboxTarget::ReEstablishmentLeg)
                        && !leg_addressable(&address_root, direction, seq)
                    {
                        unaddressable += 1;
                        continue;
                    }
                    // A refusal here is `NothingToEmit` or `GaveUp`; the first
                    // is not this call's business and the second is the sweep's,
                    // which ran before it.
                    match entry.emit(now_ms) {
                        Ok(bytes) => out.push((seq, target, bytes.to_vec())),
                        Err(e) => {
                            crate::vtrace!("dm driver: sequence {seq} was due and refused: {e}");
                        }
                    }
                }
                Ok(if out.is_empty() {
                    Mutation::Unchanged((out, unaddressable))
                } else {
                    Mutation::Changed((out, unaddressable))
                })
            });
        let (emitted, unaddressable) = match emitted {
            Ok(pair) => pair,
            Err(e) => {
                crate::vtrace!("dm driver: the due-entry scan failed: {e}");
                return Vec::new();
            }
        };
        self.correspondences[index].health.leg_unaddressable += unaddressable;
        let correspondence = &self.correspondences[index];
        let torn_down = &self.torn_down;
        // Derived from the address root, so a correspondence read back from disk
        // tags its writes with the same conversation a live one does — which is
        // what routes a re-establishment leg's own outcome back to it.
        let conversation = correspondence.conversation();
        // Collected rather than inserted in the loop: `correspondence` is borrowed
        // from `self` for the whole of it, so the sets cannot be reached until it
        // ends.
        let mut opened_send: Vec<([u8; AR_FINGERPRINT_LEN], u64)> = Vec::new();
        let mut out = Vec::new();
        for (seq, target, frame) in emitted {
            match target {
                OutboxTarget::ChannelPage => {
                    let Some((ratchet, _, _)) = correspondence.live() else {
                        continue;
                    };
                    let address = match DmPageAddress::sending(
                        &correspondence.address_root,
                        ratchet,
                        position_of(seq),
                    ) {
                        Ok(address) => address,
                        Err(e) => {
                            crate::vtrace!("dm driver: page address derivation failed: {e}");
                            continue;
                        }
                    };
                    // The page is now carried on the tag, so the outcome can say
                    // which record's write finished. It is the address's own page
                    // rather than a second derivation from `seq`.
                    let page = address.at().page();
                    // `conversation` is `Some` on every path that reaches here: this
                    // arm returned above unless `live()` answered, and that is the
                    // same call the tag's conversation comes from.
                    opened_send.extend(conversation.map(|c| (c, page)));
                    out.push(DmEffect::Dht(DhtOp::PublishPage {
                        tag: OpTag {
                            conversation,
                            seq: Some(seq),
                            page: Some(page),
                            correspondent: Some(Box::new(*correspondence.pk_lt)),
                            introduction: None,
                        },
                        address,
                        frame,
                    }));
                }
                // **A leg is published exactly where an ordinary frame of the
                // same sequence would be, and without a key schedule.** It is
                // *"shaped exactly like an ordinary frame"* and rides *"at its
                // own sequence position"*
                // (`docs/design/direct-messaging.md:917`, `:887`), so its record
                // is `msg_addr(dir, seq)` off the same address root; what it
                // cannot use is the ratchet-bound derivation, because the party
                // writing a leg has just come back from the restart that
                // destroyed its ratchet.
                //
                // **The bytes are the stored bytes.** `emit` above borrowed them
                // out of the entry and nothing re-seals them, which is A9.1(a)'s
                // byte-identical re-emit reaching the wire.
                OutboxTarget::ReEstablishmentLeg => {
                    let Some(conversation) = conversation else {
                        continue;
                    };
                    if torn_down.contains(&conversation) {
                        continue;
                    }
                    let address =
                        match DmPageAddress::sending_on(&address_root, direction, position_of(seq))
                        {
                            Ok(address) => address,
                            Err(e) => {
                                crate::vtrace!("dm driver: leg address derivation failed: {e}");
                                continue;
                            }
                        };
                    let page = address.at().page();
                    opened_send.push((conversation, page));
                    out.push(DmEffect::Dht(DhtOp::PublishPage {
                        tag: OpTag {
                            conversation: Some(conversation),
                            seq: Some(seq),
                            page: Some(page),
                            correspondent: Some(Box::new(*correspondence.pk_lt)),
                            introduction: None,
                        },
                        address,
                        frame,
                    }));
                }
                // The knock, re-seeded. Its bytes come back from the outbox
                // unchanged, which is the whole reason it is queued there: a
                // second `firstcontact::build` would encapsulate a fresh `ss0`
                // and read at the far end as this side having lost its state.
                OutboxTarget::Doorbell { slot } => {
                    let owner_seed = match doorbell::derive_owner_seed(&correspondence.pk_lt) {
                        Ok(seed) => *seed.as_bytes(),
                        Err(e) => {
                            crate::vtrace!("dm driver: doorbell derivation failed: {e}");
                            continue;
                        }
                    };
                    out.push(DmEffect::Dht(DhtOp::PublishDoorbell {
                        tag: OpTag {
                            conversation,
                            seq: Some(seq),
                            page: None,
                            correspondent: Some(Box::new(*correspondence.pk_lt)),
                            introduction: None,
                        },
                        owner_seed,
                        slot,
                        entry: frame,
                        dispatch: DoorbellDispatch::Reseed,
                    }));
                }
            }
        }
        for key in opened_send {
            self.open_send_pages.insert(key);
            // One borrow per write, released when that write's own outcome lands —
            // see the field: a tick puts many writes on one page, and presence alone
            // would let the first outcome release the record under the rest.
            *self.publishing_pages.entry(key).or_insert(0) += 1;
        }
        out
    }

    /// Ask the collection which receiving pages to sweep now.
    ///
    /// **A page whose sweep is still in flight is skipped**, on the terms
    /// [`Self::sweeping_doorbell`] states: one sweep of one record at a time.
    /// The plan is still consumed — [`Collection::probe_plan`] records itself as
    /// issued whatever the caller does with it — which is the behaviour wanted
    /// here: the sweep already open will deliver the page, so a second plan for
    /// it inside one cadence would buy nothing.
    ///
    /// **A blocked correspondent's channel is not swept**, which is the channel
    /// plane of the block list. The design of record states both planes in one
    /// line: *"The block list (re-cut ISC-C46) drops a blocked sender's doorbell
    /// entries at sweep (matched on the sealed `sender_pubkey_hash`) and stops
    /// sweeping their outbox. Silent and unilateral; the blocked sender's view
    /// is byte-identical to 'never came online' …"*
    /// (`docs/design/direct-messaging.md`). The quoted line is the design's, not
    /// the criterion's: ISC-C46 carries only the not-read half, and the
    /// byte-identical half is ISC-A-C23's bounded residual. Suppression is
    /// therefore READING
    /// only, and the split runs along that word. **Reads stop:** this planner,
    /// [`Self::ack_fetches`], and the two fold paths that meet an outcome after
    /// the block ([`Self::on_page`], [`Self::on_peer_ack`]). **Writes do not:**
    /// [`Self::due_emissions`] keeps publishing queued entries on their existing
    /// schedule and [`Self::standalone_acks`] keeps writing acknowledgements for
    /// what was collected before the block, because the design line governs what
    /// a blocked correspondent's records get *read* and says nothing about what
    /// this side publishes.
    ///
    /// **What that split costs, stated because nothing else states it.** An
    /// entry queued for a blocked correspondent goes on re-seeding to the
    /// seven-day give-up and is then surfaced `DeliveryState::Undelivered` —
    /// even where the correspondent collected it and wrote the acknowledgement
    /// saying so, because that acknowledgement is one of the reads the block
    /// stops. The report is wrong about the message and right about this side's
    /// knowledge; it is bounded by the give-up, and it is the price of leaving
    /// writes alone rather than an oversight.
    ///
    /// `block_list` is `None` where the list could not be read, and nothing is
    /// swept in that case: `on_doorbell` fails closed for the same reason, and a
    /// plane that answered "nobody is blocked" to an unreadable revocation list
    /// would silently unblock everyone.
    ///
    /// **Asked before the cadence is spent**, so a block leaves the collection's
    /// probe schedule exactly where it was and an unblock resumes on the next
    /// tick rather than after a skipped cadence.
    fn probe(
        &mut self,
        now_ms: i64,
        index: usize,
        block_list: Option<&BlockList>,
    ) -> Vec<DmEffect> {
        // Read before the destructure below borrows the whole machine, and read
        // for every correspondence rather than only the ratchet-less ones: the
        // outbox is the one place the correspondence's direction is durable, so
        // it is the only source a restarted party has.
        let peer_direction = self
            .stored_direction(&self.correspondences[index].label, now_ms)
            .map(Direction::opposite);
        let Self {
            correspondences,
            sweeping_pages,
            open_recv_pages,
            torn_down,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        // **A correspondence with no key schedule still sweeps, and that is what
        // makes a restart recoverable.** The plane the correspondent writes is
        // where a re-establishment leg arrives, and a party that stopped reading
        // it until it had a ratchet would be waiting for a frame it had made
        // itself unable to receive. What it can *open* is decided per slot by
        // `on_page`; what it can *address* is the address root, which outlives
        // every restart.
        //
        // The two states that sweep are a live channel and an established
        // correspondence read back from disk — the second recognised by the
        // correspondent's pseudonym being on record, which is the same test
        // `seed_from_store` uses to decide a resume record exists.
        if correspondence.ratchet.is_none() && correspondence.peer_pk_pc.is_none() {
            return Vec::new();
        }
        let Some(block_list) = block_list else {
            return Vec::new();
        };
        if block_list.suppresses_channel(&correspondence.pk_lt) {
            return Vec::new();
        }
        // The cadence is consumed whether or not the sweep can proceed, so a
        // correspondence that cannot verify anything reports once per cadence
        // rather than once per tick.
        let Some(plan) = correspondence.collection.probe_plan(probe_ms(now_ms)) else {
            return Vec::new();
        };
        let Some(conversation) = correspondence.conversation() else {
            crate::vtrace!("dm driver: the conversation fingerprint would not derive");
            return Vec::new();
        };
        // A torn-down conversation plans nothing. The pages were handed back at
        // teardown, and re-planning them would re-open the very records that were
        // released — see `Self::torn_down`.
        if torn_down.contains(&conversation) {
            return Vec::new();
        }
        let address_root = correspondence.address_root;
        // **An initiator that has not yet seen the acceptance still sweeps**,
        // because the acceptance itself arrives by sweep: it is an ordinary
        // channel frame at the acceptor's sequence zero. What it cannot do is
        // open anything later than that, which `on_page` decides per slot.
        let ratchet = correspondence.ratchet.as_ref();
        let mut out = Vec::new();
        for page in plan {
            if sweeping_pages.contains(&(conversation, page)) {
                continue;
            }
            let derived = match (ratchet, peer_direction) {
                (Some(ratchet), _) => DmPageAddress::receiving(&address_root, ratchet, page),
                (None, Some(direction)) => {
                    DmPageAddress::receiving_on(&address_root, direction, page)
                }
                // No key schedule and no stored outbox to read a direction from,
                // so there is no plane to name. A correspondence in this state
                // has never queued anything, which is also nothing to recover.
                (None, None) => continue,
            };
            match derived {
                Ok(address) => {
                    sweeping_pages.insert((conversation, page));
                    // Recorded here and nowhere else: this is the only site that
                    // asks the transport to open a receiving page, so the set can
                    // neither miss one nor name one that was never opened.
                    open_recv_pages.insert((conversation, page));
                    out.push(DmEffect::Dht(DhtOp::SweepPage {
                        tag: OpTag::channel(conversation, None, Some(page)),
                        address,
                    }));
                }
                // Recorded as in flight only where an address was derived: a
                // page whose sweep was never asked for is not one to wait on.
                Err(e) => crate::vtrace!("dm driver: receiving address derivation failed: {e}"),
            }
        }
        out
    }

    /// Hand back every page record of one correspondence the driver will not
    /// address again (#252).
    ///
    /// **Driven by settlement, never by a clock.** A page record is opened once and
    /// served from a cache thereafter, so left alone the count of open records grows
    /// with message volume: a new page owner seed appears every `PAGE_SLOTS`
    /// messages, per direction, per conversation, plus every page a probe reaches
    /// ahead of the frontier. Every other record family this client holds is bounded
    /// by peers — one rendezvous record per circle, one key record and one doorbell
    /// per correspondent — so this is the one family that needs a release, and the
    /// only thing that knows when a page is finished is the state that settles it.
    ///
    /// Two signals, one per direction, and neither is a timer:
    ///
    /// - **Receiving**, `recv_below` from [`Collection::retired_below`]: a page
    ///   below both the watched window and the first unsettled position. No probe
    ///   plan this collection can produce will name it again — the watched pair sits
    ///   at or above the frontier, and every hole, witnessed or not, sits at or
    ///   above the first unsettled position.
    /// - **Sending**, `send_below` from [`AckState::settled_pages_below`] over
    ///   `own_ack`: a page every position of which is settled, by the
    ///   correspondent's acknowledgement or by this side's own seven-day give-up —
    ///   [`Self::give_ups`] abandons a given-up position into that state, because a
    ///   message this sender will never re-seed is one the page is finished with.
    ///   Without that half a single permanently-undelivered message pins the prefix
    ///   and no sending page of the conversation closes again.
    ///
    /// **The receiving side has no give-up, and that is the wire's doing rather than
    /// an omission here.** The design's prefix-advance-on-give-up rule needs the
    /// receiver to learn that the sender abandoned a position, and no record carries
    /// that: an acknowledgement and a frame's piggyback both carry the receiver's own
    /// `high_water` and runs and nothing travelling the other way. So a permanently
    /// lost inbound position pins `recv_below` at its page, and the receiving pages
    /// from there on stay open until the transport's capacity bound reclaims them.
    /// See [`Collection::retired_below`].
    ///
    /// **A page whose operation is in flight is skipped, not closed.** Closing a
    /// record mid-sweep turns its remaining reads into `outcome.failed`, the signal
    /// a collector is told to read as record ill-health, and mid-write it loses the
    /// message. [`Self::sweeping_pages`] holds the receiving side and
    /// [`Self::publishing_pages`] the sending one; a page skipped here is simply
    /// offered again at the next settlement, and if none comes the transport's own
    /// capacity bound reclaims it. **A torn-down conversation has no next
    /// settlement**, so the outcome that frees the slot offers its pages instead —
    /// see [`Self::close_freed_after_teardown`].
    ///
    /// **A page is dropped from the open set when the close is ASKED for, not when
    /// it lands.** The alternative — waiting for the outcome — would re-offer the
    /// same page on every settlement until it did, which for a record the transport
    /// is refusing to close (something is still holding it) is an unbounded stream
    /// of closes for one page. The cost of this direction is that a refused close
    /// leaves a record open with nothing here tracking it; that record is exactly
    /// what the capacity bound exists to catch, so it is bounded, not leaked.
    ///
    /// **A closed page a later plan names again is simply re-opened**, by the
    /// ordinary open path, at the cost of one open. That cannot happen from an
    /// out-of-order arrival — the positions are settled — but a restart re-derives a
    /// collection from its stored cursor and probes from there, so it can happen.
    /// This is the accepted cost of a bounded record count: one open, against a
    /// count that would otherwise only rise.
    fn close_pages(&mut self, index: usize, recv_below: u64, send_below: u64) -> Vec<DmEffect> {
        let Self {
            correspondences,
            sweeping_pages,
            publishing_pages,
            open_recv_pages,
            open_send_pages,
            ..
        } = self;
        let correspondence = &correspondences[index];
        // No ratchet, no address to derive. A correspondence with no live channel
        // opened no page this session, so there is nothing of its to hand back.
        let Some((ratchet, _, _)) = correspondence.live() else {
            return Vec::new();
        };
        let conversation = *ratchet.ar_fingerprint();
        let address_root = correspondence.address_root;
        let mut out = Vec::new();

        let retiring: Vec<u64> = open_recv_pages
            .iter()
            .filter(|(c, page)| *c == conversation && *page < recv_below)
            .map(|(_, page)| *page)
            .filter(|page| !sweeping_pages.contains(&(conversation, *page)))
            .collect();
        for page in retiring {
            match DmPageAddress::receiving(&address_root, ratchet, page) {
                Ok(address) => {
                    open_recv_pages.remove(&(conversation, page));
                    out.push(DmEffect::Dht(DhtOp::ClosePage {
                        tag: OpTag::channel(conversation, None, Some(page)),
                        address: DmPageRecord::Receiving(address),
                    }));
                }
                // Left in the set rather than dropped: an address that would not
                // derive names a record still open, and forgetting it here would
                // lose the only handle on it this machine has.
                Err(e) => crate::vtrace!("dm driver: receiving close address failed: {e}"),
            }
        }

        let retiring: Vec<u64> = open_send_pages
            .iter()
            .filter(|(c, page)| *c == conversation && *page < send_below)
            .map(|(_, page)| *page)
            .filter(|page| !publishing_pages.contains_key(&(conversation, *page)))
            .collect();
        for page in retiring {
            // Slot zero, because a close names a RECORD and the owner seed derives
            // from the root, the direction and the page — never the slot. Any slot
            // of the page would derive the same record; zero is the one that always
            // exists.
            let Some(at) = PagePosition::new(page, 0) else {
                crate::vtrace!("dm driver: a sending page held no position to close");
                continue;
            };
            match DmPageAddress::sending(&address_root, ratchet, at) {
                Ok(address) => {
                    open_send_pages.remove(&(conversation, page));
                    out.push(DmEffect::Dht(DhtOp::ClosePage {
                        tag: OpTag::channel(conversation, None, Some(page)),
                        address: DmPageRecord::Sending(address),
                    }));
                }
                Err(e) => crate::vtrace!("dm driver: sending close address failed: {e}"),
            }
        }
        out
    }

    /// Hand back the pages this correspondence's own settlement has finished with.
    ///
    /// The two bounds come from the two states that settle, so a page is released by
    /// the same fold that settled its last position — see [`Self::close_pages`].
    fn retire_pages(&mut self, index: usize) -> Vec<DmEffect> {
        let recv_below = self.correspondences[index].collection.retired_below();
        let send_below = self.correspondences[index].own_ack.settled_pages_below();
        self.close_pages(index, recv_below, send_below)
    }

    /// Hand back **every** page record of one correspondence, because its channel is
    /// gone.
    ///
    /// A teardown ends the conversation on this side: the outbox's pending entries
    /// are terminal, and the conversation is recorded in [`Self::torn_down`], which
    /// is what actually stops a plan or a write naming these records again — the
    /// ratchet and the channel roots survive a teardown, and every planner reads
    /// exactly those, so the flag rather than the teardown is what makes the
    /// statement true. Settlement is therefore the wrong question — [`u64::MAX`]
    /// says every page rather than every settled one — and a torn-down conversation
    /// is the one case where a page below the frontier and a page above it are
    /// equally finished.
    fn close_all_pages(&mut self, index: usize) -> Vec<DmEffect> {
        self.close_pages(index, u64::MAX, u64::MAX)
    }

    /// Hand back the pages of a TORN-DOWN conversation that an outcome has just
    /// freed.
    ///
    /// **Without this, "every page of a torn-down conversation" is false for exactly
    /// the pages that were busy at the moment of the teardown.** `close_all_pages`
    /// skips a page whose sweep or write is in flight — it must, since closing a
    /// record mid-operation is the fault the guard exists for — and after a teardown
    /// nothing reaches that page again: `probe` and `ack_fetches` are gated on
    /// [`Self::torn_down`], and `retire_pages` is bounded by a settlement that a
    /// dead conversation will never produce. The page would sit open until the
    /// transport's capacity bound evicted it.
    ///
    /// So the outcome that releases the slot is the signal, and it is the last one
    /// this conversation will ever produce. Called from every path that releases
    /// one, the panic path included: a task that died still frees the slot, and a
    /// torn-down conversation has nothing else coming.
    ///
    /// **Scoped to the page the outcome actually freed, and that is what stops it
    /// cascading.** A `ClosePage` outcome frees no slot and names no page, so a
    /// close cannot beget another pass: the chain ends at one, and a tick that tears
    /// a conversation down issues a bounded burst rather than one proportional to
    /// the pages it holds.
    ///
    /// A no-op for a live conversation, which is every call but the rare one.
    fn close_freed_after_teardown(&mut self, kind: DhtOpKind, tag: &OpTag) -> Vec<DmEffect> {
        // Only the two operations that hold a page slot free one. Everything else —
        // a close, an acknowledgement, a doorbell write — names no page to hand back.
        let sending = match kind {
            DhtOpKind::SweepPage => false,
            DhtOpKind::PublishPage => true,
            _ => return Vec::new(),
        };
        let (Some(conversation), Some(page)) = (tag.conversation, tag.page) else {
            return Vec::new();
        };
        if !self.torn_down.contains(&conversation) {
            return Vec::new();
        }
        let Some(index) = self.index_of_conversation(&conversation) else {
            return Vec::new();
        };
        // One past the freed page, on that direction only. Pages BELOW it are swept
        // up too, which is right rather than incidental: on a torn-down conversation
        // every open page is finished, and one whose own outcome landed earlier has
        // no other signal coming.
        let above = page.saturating_add(1);
        if sending {
            self.close_pages(index, 0, above)
        } else {
            self.close_pages(index, above, 0)
        }
    }

    /// One write landed: record it against the entry that produced it.
    ///
    /// **Attributed by the correspondent, not by the conversation.** A queued
    /// doorbell entry outlives the key schedule that names a conversation, and
    /// its write still has to stop being due.
    fn confirm_written(&mut self, now_ms: i64, tag: &OpTag) -> Vec<DmEffect> {
        let (Some(correspondent), Some(seq)) = (tag.correspondent.as_ref(), tag.seq) else {
            return Vec::new();
        };
        let Some(index) = self.index_of(correspondent) else {
            return Vec::new();
        };
        let label = self.correspondences[index].label;
        let Some(direction) = self.stored_direction(&label, now_ms) else {
            return Vec::new();
        };
        let confirmed = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                match outbox.entry_mut(seq).map(|e| e.confirm_written(now_ms)) {
                    Some(Ok(())) => Ok(Mutation::Changed(true)),
                    // An ordinary race, both of them: the entry settled or was
                    // pruned between the write being dispatched and its outcome
                    // arriving. Neither is a fault and neither is a change.
                    Some(Err(OutboxError::NothingToConfirm(_))) | None => {
                        Ok(Mutation::Unchanged(false))
                    }
                    Some(Err(e)) => Err(e.into()),
                }
            });
        match confirmed {
            Ok(true) => vec![DmEffect::Emit(DmEvent::Delivery {
                to: Box::new(*self.correspondences[index].pk_lt),
                seq,
                state: DeliveryState::OnDht,
            })],
            Ok(false) => Vec::new(),
            Err(e) => {
                crate::vtrace!("dm driver: sequence {seq} could not be confirmed: {e}");
                Vec::new()
            }
        }
    }

    // ---- the channel plane: collecting -------------------------------------

    /// Fold one swept page.
    ///
    /// **A partial sweep folds nothing** (policy R4). A page the transport did
    /// not read every slot of cannot say a position is *absent*, only that it
    /// was not seen — and the collection's whole job is to distinguish those.
    /// Advancing the frontier or the cursor on a partial read walks past
    /// messages that were there, and no later sweep revisits them. So the page
    /// is left exactly as it was and re-planned on the next cadence.
    fn on_page(&mut self, now_ms: i64, tag: &OpTag, sweep: DmPageSweep) -> Vec<DmEffect> {
        let (Some(conversation), Some(page)) = (tag.conversation, tag.page) else {
            return Vec::new();
        };
        let Some(index) = self.index_of_conversation(&conversation) else {
            return Vec::new();
        };
        // **The sweep-time check cannot carry this on its own.** A sweep is
        // planned on one tick and its outcome arrives on a later one, so a block
        // landing inside that window would otherwise surface exactly the
        // messages it was meant to stop — once for every sweep already in
        // flight, which is the moment a user reaches for the block.
        //
        // The frames are dropped and nothing is settled: no position is offered
        // to the collection, no acknowledgement is owed, no cursor advances. The
        // record is the sender's and is still there, so an unblock re-collects
        // this page rather than having walked past it.
        match self.persist.read_block_list() {
            Ok(list) if list.suppresses_channel(&self.correspondences[index].pk_lt) => {
                return Vec::new();
            }
            Ok(_) => {}
            Err(e) => {
                crate::vtrace!("dm driver: block list unreadable, folding no page: {e}");
                return Vec::new();
            }
        }
        // Read before the destructure below borrows the machine, and read from the
        // outbox because that is where the correspondence's direction is durable:
        // a page a restarted party sweeps has no ratchet to ask.
        let peer_direction = self
            .stored_direction(&self.correspondences[index].label, now_ms)
            .map(Direction::opposite);
        let Self {
            identity,
            persist,
            correspondences,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        let before = correspondence.health;
        // **A complete read is not the absence of a failure.** The transport
        // reports an absent record as `attempted: 0` and a run that stopped part
        // way as an `attempted` below the record's subkey count with `failed`
        // still zero — so a rule reading `failed` alone folds a half-read page
        // as though every empty slot were genuinely empty, which walks past
        // messages no later sweep revisits.
        let outcome = sweep.outcome;
        let complete = outcome.failed == 0
            && (outcome.attempted == 0 || outcome.attempted == u32::from(PAGE_SLOTS));
        if !complete {
            correspondence.health.partial_sweeps += 1;
            return correspondence.health_event(before).into_iter().collect();
        }
        // This session has now genuinely read this page, which is the only thing
        // that may bound the stored cursor.
        correspondence.read_through = correspondence.read_through.max(page);

        // The slot indices are what the collection folds; the bytes stay beside
        // it, keyed by the position they were found at, because a position is
        // what `open` must be given and a slot index alone has lost the page.
        let populated: Vec<u16> = sweep.slots.iter().map(|(at, _)| at.slot()).collect();
        let bytes: std::collections::BTreeMap<PagePosition, Vec<u8>> =
            sweep.slots.into_iter().collect();
        let observation = match correspondence.collection.observe_page(page, &populated) {
            Ok(observation) => observation,
            Err(e) => {
                crate::vtrace!("dm driver: page {page} would not fold: {e}");
                correspondence.health.unopenable += 1;
                return correspondence.health_event(before).into_iter().collect();
            }
        };

        let cursor_before = correspondence.collection.contiguous_through();
        let mut out = Vec::new();
        // **Collected here and pushed after the borrow ends**, the shape
        // `due_emissions` uses for its own deferred writes: `correspondence` is
        // borrowed from `self` for the whole fold, so `self.pending_erase`
        // cannot be reached from inside it.
        let mut owed_erase: Option<(CorrespondenceLabel, ProvisionalContext, u64)> = None;

        // The retry queue first: a position whose acknowledgement the
        // beyond-prefix set had no room for is already opened and displayed, so
        // it needs settling and nothing else.
        let owed = std::mem::take(&mut correspondence.owed_acks);
        for at in owed {
            if correspondence.collection.collected(at).is_err() {
                correspondence.owed_acks.push(at);
            } else {
                correspondence.ack_cadence.on_collected();
            }
        }

        // Read lazily and once, then threaded through every leg fold on this
        // page — see the leg arm below.
        let mut resume: Option<Option<ResumeRecord>> = None;
        let mut scans: u64 = 0;
        let mut scan_faults: u64 = 0;
        let recipient = match recipient_hash(identity.signing.public_key()) {
            Ok(h) => h,
            Err(e) => {
                crate::vtrace!("dm driver: own recipient hash failed: {e}");
                return Vec::new();
            }
        };
        let peer_pk_lt: PkLt = Box::new(*correspondence.pk_lt);
        for at in observation.unsettled {
            let Some(encoded) = bytes.get(&at) else {
                continue;
            };
            // **Set by every path that hands the slot to the re-establishment
            // scan, and read once below.** A leg is not a channel frame — it is
            // a fixed-length AEAD blob under a key derived from the retained
            // root — so it reaches this loop as bytes that do not parse, or that
            // parse and do not open, or that arrive at a correspondence with no
            // key schedule at all. Those are three different-looking failures of
            // one attempt, and the flag is what keeps the answer to *"is this a
            // leg?"* in one place rather than three.
            let mut unopened = false;
            'frame: {
                let parsed = match frame::parse(encoded) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        crate::vtrace!("dm driver: a swept slot is not a frame: {e}");
                        unopened = true;
                        break 'frame;
                    }
                };
                // **Before the acceptance, only the acceptance can be opened.** An
                // initiator holds no pseudonym for its correspondent until the
                // ACCEPT lands, so a frame at any later sequence is refused as
                // *pending* — the slot is left unsettled, nothing is offered to the
                // ratchet, and the sweep after the acceptance retries it. Counted,
                // not silent: `peer_pseudonym_unknown` is what says a conversation
                // is waiting on its acceptance rather than idle.
                let accepting = correspondence.peer_pk_pc.is_none();
                if accepting && at.seq() != FIRST_RECIPIENT_CHANNEL_SEQ {
                    correspondence.health.peer_pseudonym_unknown += 1;
                    // Not `unopened`: a correspondence still waiting for its
                    // acceptance has no resume record and no retained root, so
                    // there is no leg the scan below could open and the trial
                    // decryption would be work spent to reach the same answer.
                    break 'frame;
                }
                // **No key schedule is a re-establishment case, not a stop.** This
                // used to leave the loop, on the reading that a correspondence
                // without a ratchet can open nothing — which is true of channel
                // frames and false of the legs that arrive precisely because the
                // ratchet is gone. The slot goes to the scan below instead.
                let (Some(ratchet), Some(channel)) = (
                    correspondence.ratchet.as_mut(),
                    correspondence.channel.as_ref(),
                ) else {
                    unopened = true;
                    break 'frame;
                };
                let direction = ratchet.recv_direction();
                // Nested on purpose: the outer result is the ratchet's verdict on
                // the position and the inner one this frame's own authentication.
                // The ratchet commits nothing when the inner one fails, so a frame
                // that does not authenticate has not spent its key — which is what
                // makes a forged acceptance cost one refused open rather than a
                // conversation.
                let opened = if accepting {
                    ratchet.receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |key| {
                        parsed
                            .open_accept(
                                key,
                                &channel.chan_id,
                                direction,
                                at,
                                &recipient,
                                &peer_pk_lt,
                            )
                            .map(|accepted| (accepted.frame, Some(accepted.peer_pk_pc)))
                    })
                } else {
                    let author = AuthorKeys {
                        pc: correspondence
                            .peer_pk_pc
                            .as_ref()
                            .expect("the pseudonym is known on this branch"),
                        lt: &peer_pk_lt,
                    };
                    ratchet.receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |key| {
                        parsed
                            .open(key, &channel.chan_id, direction, at, &recipient, author)
                            .map(|verified| (verified, None))
                    })
                };
                match opened {
                    Ok(Ok((verified, installed))) => {
                        // **One act: install the pseudonym, and erase the record
                        // that existed only until it arrived.** Past this point the
                        // conversation is verifiable and `ss0` — which roots `RK0`
                        // — has no further use, so keeping it would be the
                        // forward-secrecy claim inverted. It runs only here,
                        // after a verified acceptance: a failed open leaves the
                        // ratchet, the record and the slot exactly as they were.
                        if let Some(pk_pc) = installed {
                            // **The record is written first, and the handshake
                            // record is erased only if that write succeeded.** The
                            // contact record was created when the entry was sent
                            // and has held no pseudonym since; this is the one
                            // transition it makes. Erasing the handshake record
                            // regardless would destroy the only state a restart
                            // could re-arm from while leaving the pseudonym
                            // unrecorded — a correspondence that comes back
                            // waiting for an acceptance it can no longer open, and
                            // no later frame could ever establish it. So a refused
                            // write keeps both the handle and the record, and the
                            // tick retries the pair.
                            match persist.record_correspondent_pseudonym(
                                &correspondence.label,
                                pk_pc.clone(),
                                now_ms,
                            ) {
                                Ok(_) => {
                                    // **The pseudonym stays owed until the resume
                                    // record lands.** The two writes are not one
                                    // act, and the contact record's pseudonym is
                                    // what every later lookup reads as
                                    // *established* — so a store fault between them
                                    // would leave a correspondence that reads as
                                    // established and holds no `S_pc`, with nothing
                                    // owing the write that would fix it. Keeping the
                                    // flag set is what puts the pair back in front
                                    // of the next tick.
                                    match establish_provisional(
                                        persist,
                                        correspondence,
                                        &pk_pc,
                                        now_ms,
                                    ) {
                                        Establishment::Complete => {}
                                        Establishment::Retry => {
                                            correspondence.pseudonym_unwritten = true;
                                        }
                                        Establishment::Unrecoverable => {
                                            let owed = pending_seqs(
                                                persist,
                                                &correspondence.label,
                                                now_ms,
                                            );
                                            out.extend(cannot_resume(correspondence, owed));
                                            // **A handshake record the erase could
                                            // not reach goes onto the retry list,
                                            // not into the dark.** The
                                            // correspondence is finished either way,
                                            // but the record still holds `ss0` —
                                            // which roots `RK0` — and the context
                                            // beside it is the only thing that can
                                            // ever open it again. Dropping the
                                            // handle here would turn a transient
                                            // store fault into a permanent leak of
                                            // the secret the establishment exists to
                                            // destroy.
                                            if let Some((keyrec_addr, fc_epoch)) =
                                                correspondence.provisional.take()
                                            {
                                                owed_erase = Some((
                                                    correspondence.label,
                                                    keyrec_addr,
                                                    fc_epoch,
                                                ));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    crate::vtrace!(
                                        "dm driver: the pseudonym would not record: {e}"
                                    );
                                    correspondence.pseudonym_unwritten = true;
                                }
                            }
                            correspondence.peer_pk_pc = Some(pk_pc);
                        }
                        if correspondence.collection.collected(at).is_err() {
                            correspondence.owed_acks.push(at);
                        } else {
                            // The floor: the first standalone acknowledgement after
                            // new messages goes whatever the curve says, so a
                            // conversation that has been quiet for days still
                            // confirms the message that broke the silence at once.
                            correspondence.ack_cadence.on_collected();
                        }
                        // The frame's own asserted send time, clamped to now; see
                        // `note_pending` for both halves of why.
                        correspondence.note_pending(verified.sent_unix_ms, now_ms);
                        // The piggybacked half of the fold. It takes the identical
                        // decode-verify-merge path a standalone record takes; only
                        // what authenticated it differs, and that already happened
                        // above, inside the open.
                        if let Some(peer) = verified.peer_ack {
                            out.extend(fold_peer_ack(persist, correspondence, now_ms, peer));
                        }
                        out.push(DmEffect::Emit(DmEvent::Message {
                            from: Box::new(*correspondence.pk_lt),
                            seq: verified.seq,
                            body: verified.body,
                            sent_unix_ms: verified.sent_unix_ms,
                        }));
                    }
                    // Ordinary under re-seeds: the sender re-presents a frame this
                    // side has already opened, and will until an acknowledgement
                    // reaches it.
                    Err(RatchetError::AlreadyConsumed { .. }) => {
                        correspondence.health.already_consumed += 1;
                    }
                    // **The slot is left unsettled, never abandoned.** Abandonment
                    // settles a position permanently and is the sender's give-up
                    // signal, not a reader's verdict on bytes it could not open.
                    // Page owner-write authority is symmetric, so anyone can write
                    // a slot; the authorship signature is what separates the
                    // correspondent's writes from everybody else's, and a frame
                    // that fails it says nothing about the frame that may yet
                    // arrive.
                    Err(e) => {
                        crate::vtrace!("dm driver: the ratchet refused a swept frame: {e}");
                        unopened = true;
                    }
                    Ok(Err(e)) => {
                        crate::vtrace!("dm driver: a swept frame did not authenticate: {e}");
                        correspondence.health.unopenable += 1;
                    }
                }
            }
            if !unopened {
                continue;
            }
            // **The one place a re-establishment leg is recognised.** Nothing on
            // the wire says a frame is one (A3.9), so what happens here is a
            // bounded trial decryption against the leg kinds this side's own
            // record says it is waiting for — and a slot that is not one of them
            // is counted unopenable exactly as it was before.
            let Some(peer_direction) = peer_direction else {
                correspondence.health.unopenable += 1;
                continue;
            };
            // **The record is opened once per page, not once per slot.** It is a
            // sealed blob carrying a signing key, and a page holding one leg
            // among sixteen frames would otherwise pay the AEAD open sixteen
            // times. The outer `None` is *not read yet*; the inner one is *there
            // is no record*, which is the state `resume_channel` surfaces as
            // unresumable and in which no leg can have been sealed.
            if resume.is_none() {
                resume = Some(match persist.read_resume(&correspondence.label) {
                    Ok(record) => record,
                    Err(e) => {
                        crate::vtrace!(
                            "dm driver: the resume record will not read for a leg scan: {e}"
                        );
                        None
                    }
                });
            }
            let Some(record) = resume.as_mut().and_then(Option::as_mut) else {
                correspondence.health.unopenable += 1;
                continue;
            };
            let fold = fold_leg(
                persist,
                correspondence,
                record,
                now_ms,
                at,
                encoded,
                peer_direction,
                &mut scans,
                &mut scan_faults,
            );
            out.extend(fold.effects);
            match fold.outcome {
                LegOutcome::NotALeg => correspondence.health.unopenable += 1,
                // **The position stays unsettled and nothing was written.** The
                // fold decided nothing, so settling here would walk past the
                // only copy of a frame this side still owes an answer to; the
                // correspondent's own re-seed is what brings it back.
                LegOutcome::Retry => correspondence.health.leg_folds_deferred += 1,
                // **A consumed leg settles its position, and the alternative is
                // worse than it looks.** A leg rides the outbox at its own
                // sequence in the same space every message uses, so a position
                // left unsettled pins the contiguous prefix under it for the
                // life of the correspondence: every later message is reported
                // beyond the prefix, the run set grows toward its cap, and the
                // sender re-seeds a leg nothing will ever confirm.
                LegOutcome::Consumed => {
                    if correspondence.collection.collected(at).is_err() {
                        correspondence.owed_acks.push(at);
                    }
                }
            }
        }
        correspondence.health.leg_folds_deferred += scan_faults;
        // A3.9's bound, asserted where it is spent rather than described
        // elsewhere: one slot is scanned against at most this many leg kinds.
        debug_assert!(
            scans <= LEG_SCAN_CANDIDATES * u64::from(PAGE_SLOTS),
            "a swept page scanned more leg candidates than the bound allows"
        );

        // The cursor moves only on the contiguous prefix, and only as far as the
        // page that prefix now reaches — bounded by what this session has
        // actually swept.
        let cursor_now = correspondence.collection.contiguous_through();
        if let Some(through) = cursor_now.filter(|_| cursor_now != cursor_before) {
            let reached = position_of(through).page();
            match persist.advance_cursor(
                &correspondence.label,
                reached,
                correspondence.read_through,
            ) {
                // A `cursor.bin` that would not read has been replaced with this
                // session's own page rather than left to wedge the
                // correspondence for ever. It is counted because an unreadable
                // record is tampering or corruption either way, and a driver
                // that repairs one silently reports a healthy channel over a
                // disk that is not.
                Ok(advance) if advance.repaired() => {
                    crate::vtrace!("dm driver: an unreadable receive cursor was repaired");
                    correspondence.health.cursor_records_repaired += 1;
                    correspondence.cursor_unreadable = false;
                }
                Ok(_) => correspondence.cursor_unreadable = false,
                Err(e) => crate::vtrace!("dm driver: the receive cursor would not advance: {e}"),
            }
        }
        out.extend(correspondence.health_event(before));
        self.leg_scan_candidates = self.leg_scan_candidates.saturating_add(scans);
        if let Some(entry) = owed_erase {
            self.pending_erase.push(entry);
        }
        // The fold that settled a position is the signal that may have finished a
        // page, so the release is asked for here rather than on the tick: a timer
        // would either lag the settlement or ask when nothing had changed.
        out.extend(self.retire_pages(index));
        out
    }

    /// The correspondence holding this identity, if this session holds one.
    fn index_of(&self, pk_lt: &[u8; IDENTITY_PK_LEN]) -> Option<usize> {
        self.correspondences
            .iter()
            .position(|c| c.pk_lt.as_slice() == pk_lt.as_slice())
    }

    /// The correspondence one channel-plane operation belongs to.
    ///
    /// **Matched on the address root's fingerprint, not on the ratchet's copy of
    /// it.** The two are the same value, and only one of them survives a restart
    /// — so a lookup that read the ratchet would route every outcome of a
    /// re-establishment sweep or leg publish to no correspondence at all, which
    /// is the exact state the operation exists to leave.
    fn index_of_conversation(&self, conversation: &[u8; AR_FINGERPRINT_LEN]) -> Option<usize> {
        self.correspondences
            .iter()
            .position(|c| c.conversation().as_ref() == Some(conversation))
    }

    // ---- the channel plane: acknowledging ----------------------------------

    /// Ask this correspondence's correspondent what it has collected of what we
    /// sent.
    ///
    /// **On the existing tick, with no timer of its own.** A fetch is one gated
    /// GET and costs nothing but a read, so a second cadence would buy a
    /// confirmation arriving sooner by less than one idle tick at the price of a
    /// second schedule to reason about.
    ///
    /// Skipped where there is nothing outstanding: an outbox whose every entry
    /// has already been confirmed or given up has no answer a peer could supply,
    /// and asking anyway would poll for the life of the conversation.
    ///
    /// The address is derived from `send_direction`, never from a role: the two
    /// readings differ by one label, and the other one addresses a record the
    /// peer never writes, with no error to say why.
    ///
    /// **A blocked correspondent's record is not fetched**, on the terms
    /// [`Self::probe`] states: an acknowledgement is a read of their record, and
    /// folding one reports a blocked party's collection. `block_list` carries the
    /// tick's one read of the list — `None` where it could not be read, which
    /// fetches nothing, fail-closed for [`Self::probe`]'s reason.
    fn ack_fetches(
        &self,
        now_ms: i64,
        index: usize,
        block_list: Option<&BlockList>,
    ) -> Vec<DmEffect> {
        let correspondence = &self.correspondences[index];
        let Some((ratchet, _, _)) = correspondence.live() else {
            return Vec::new();
        };
        // A torn-down conversation asks nothing of its correspondent's records, on
        // the terms `Self::torn_down` states.
        if self.torn_down.contains(ratchet.ar_fingerprint()) {
            return Vec::new();
        }
        // **A blocked correspondent's acknowledgement record is one of their
        // records**, so the same suppression [`Self::probe`] applies to their
        // pages applies here: the design stops reading a blocked correspondent,
        // and a fetched acknowledgement is a read that surfaces
        // `DeliveryState::ConfirmedCollected` for a party the user has refused.
        // `None` — an unreadable list — fetches nothing, on the fail-closed
        // terms stated there.
        let Some(block_list) = block_list else {
            return Vec::new();
        };
        if block_list.suppresses_channel(&correspondence.pk_lt) {
            return Vec::new();
        }
        // **Nothing to verify a record against is nothing to fetch.** An
        // initiator holds no pseudonym for its correspondent until the acceptance
        // lands, and a record fetched before then could only be discarded — so
        // the read is skipped rather than spent and thrown away.
        if correspondence.peer_pk_pc.is_none() {
            return Vec::new();
        }
        let outstanding = match self.persist.read_outbox(&correspondence.label, now_ms) {
            Ok(Some(outbox)) => outbox.iter().any(|entry| {
                matches!(
                    entry.delivery_state(),
                    DeliveryState::Composed | DeliveryState::OnDht
                )
            }),
            Ok(None) => false,
            Err(e) => {
                crate::vtrace!("dm driver: the outbox would not read: {e}");
                false
            }
        };
        if !outstanding {
            return Vec::new();
        }
        let address = match DmAckAddress::for_direction(
            &correspondence.address_root,
            ratchet.send_direction(),
        ) {
            Ok(address) => address,
            Err(e) => {
                crate::vtrace!("dm driver: ack address derivation failed: {e}");
                return Vec::new();
            }
        };
        vec![DmEffect::Dht(DhtOp::FetchAck {
            tag: OpTag::channel(*ratchet.ar_fingerprint(), None, None),
            address,
        })]
    }

    /// Fold a fetched acknowledgement record.
    ///
    /// **`None` is the ordinary state, not a failure.** An unwritten or evicted
    /// record means the correspondent has confirmed nothing yet, which is what
    /// every conversation looks like before its first collection; treating it as
    /// an error would put a transport fault and an absence of confirmation on the
    /// same footing, and under a fail-safe posture those must stay apart.
    ///
    /// The order is decode-and-verify, then merge under this side's own ceiling.
    /// Nothing between the two may consult the claim: [`PeerAck`] exists to make
    /// that unspellable, and the ceiling is a required argument on the only road
    /// in.
    fn on_peer_ack(&mut self, now_ms: i64, tag: &OpTag, record: Option<Vec<u8>>) -> Vec<DmEffect> {
        let Some(record) = record else {
            return Vec::new();
        };
        let Some(conversation) = tag.conversation else {
            return Vec::new();
        };
        let Some(index) = self.index_of_conversation(&conversation) else {
            return Vec::new();
        };
        // Re-asked here for [`Self::on_page`]'s reason: the fetch was decided on
        // an earlier tick, and a record folded now would settle this side's
        // outbox and surface `ConfirmedCollected` for an identity blocked since.
        // The record is left unfolded rather than refused, so an unblock folds
        // it on the next fetch.
        match self.persist.read_block_list() {
            Ok(list) if list.suppresses_channel(&self.correspondences[index].pk_lt) => {
                return Vec::new();
            }
            Ok(_) => {}
            Err(e) => {
                crate::vtrace!("dm driver: block list unreadable, folding no acknowledgement: {e}");
                return Vec::new();
            }
        }
        let Self {
            persist,
            correspondences,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        let before = correspondence.health;
        let verified = {
            let Some((ratchet, _, channel)) = correspondence.live() else {
                return Vec::new();
            };
            // The initiator holds no pseudonym for its correspondent until the
            // acceptance lands, so there is nothing to verify a record against
            // yet. Not counted: this is a conversation waiting on its
            // acceptance, which `peer_pseudonym_unknown` already reports from
            // the sweep that meets it first.
            let Some(peer_pk_pc) = correspondence.peer_pk_pc.as_deref() else {
                return Vec::new();
            };
            ack_record::decode_and_verify(
                &record,
                &channel.chan_id,
                ratchet.send_direction(),
                &correspondence.address_root,
                peer_pk_pc,
            )
        };
        let peer = match verified {
            Ok(peer) => peer,
            Err(e) => {
                crate::vtrace!("dm driver: a fetched acknowledgement did not verify: {e}");
                correspondence.health.peer_acks_unverified += 1;
                return correspondence.health_event(before).into_iter().collect();
            }
        };
        let mut out = fold_peer_ack(persist, correspondence, now_ms, peer);
        out.extend(correspondence.health_event(before));
        // A peer acknowledgement settles SENDING positions, so it can finish a
        // sending page. It is not the only signal that does — `give_ups` settles a
        // position this side abandoned — but it is the one that arrives here.
        out.extend(self.retire_pages(index));
        out
    }

    /// One standalone acknowledgement write landed: the cadence may advance.
    ///
    /// **On the write, never on the decision to write.** A decision the budget
    /// refused, or a build that failed, must leave the floor raised — otherwise
    /// the one acknowledgement the floor exists to guarantee after a collection
    /// is lost, and the sender re-seeds to its give-up for a message that was
    /// read.
    fn on_ack_written(&mut self, now_ms: i64, tag: &OpTag) -> Vec<DmEffect> {
        let Some(conversation) = tag.conversation else {
            return Vec::new();
        };
        let Some(index) = self.index_of_conversation(&conversation) else {
            return Vec::new();
        };
        self.correspondences[index].ack_cadence.on_acked(now_ms);
        Vec::new()
    }

    /// Write the standalone acknowledgements this tick's allowance affords.
    ///
    /// Three questions in the order the design composes them: a correspondence
    /// must *want* a write ([`StandaloneAckCadence::is_due`]), the competing set
    /// must *choose* one ([`ack_cadence::pick_next`], oldest pending first), and
    /// the client-global [`StandaloneAckBudget`] must *afford* it. The budget's
    /// answer is final, and a refusal is scheduled rather than polled — its
    /// `retry_after_ms` becomes a wake time in [`Self::next_due_ms`].
    ///
    /// The loop keeps asking while candidates remain, so a grant does not end the
    /// round: it is the budget that ends it, which is the one place the ceiling
    /// is enforced.
    fn standalone_acks(&mut self, now_ms: i64) -> Vec<DmEffect> {
        // Cleared here, so a stale wake time cannot outlive the refusal that set
        // it: only a refusal in this same pass may put one back.
        self.ack_retry_due_ms = None;
        for correspondence in &mut self.correspondences {
            correspondence.prune_pending(now_ms);
        }
        let mut due: Vec<(CorrespondenceLabel, i64)> = Vec::new();
        for correspondence in &self.correspondences {
            if correspondence.live().is_none() {
                continue;
            }
            // **Skipped HERE, before the pick and before the grant.** The write
            // itself is refused in `publish_standalone_ack`, but a candidate that
            // reaches the pick has already cost the client-global permit — one per
            // sixty seconds — and spent it on a write that never happens. Worse, a
            // teardown ends neither `live()` nor the pending set, and
            // `prune_pending` ages an entry out only at its give-up, so a dead
            // correspondence would carry the OLDEST key and win `pick_next` for up
            // to a week; two of them alternate under the anti-repeat rule and a live
            // conversation is never served at all. The teardown clears the pending
            // set as well, so this is the second of two gates rather than the only
            // one.
            if correspondence
                .ratchet
                .as_ref()
                .is_some_and(|r| self.torn_down.contains(r.ar_fingerprint()))
            {
                continue;
            }
            // **The set is scanned once and the answer reused.** The key is built
            // with `oldest_live_pending_ms`, never from the raw set — a
            // conversation whose oldest pending message has passed its own
            // give-up would otherwise win rounds while being the one conversation
            // a write cannot help — and `is_due` then asks its question of that
            // one value, because the oldest live entry is the only member either
            // answer depends on. Passing the whole set twice would walk it twice
            // for an identical result.
            let Some(oldest_ms) = ack_cadence::oldest_live_pending_ms(
                now_ms,
                correspondence.pending_sent_ms.iter().copied(),
                GIVE_UP_MS,
            ) else {
                continue;
            };
            if !correspondence
                .ack_cadence
                .is_due(now_ms, [oldest_ms], GIVE_UP_MS)
            {
                continue;
            }
            due.push((correspondence.label, oldest_ms));
        }

        let mut out = Vec::new();
        while !due.is_empty() {
            let Some(label) = ack_cadence::pick_next(
                due.iter().copied(),
                now_ms,
                GIVE_UP_MS,
                self.last_ack_picked.as_ref(),
            ) else {
                break;
            };
            due.retain(|(candidate, _)| *candidate != label);
            match self.ack_budget.request(now_ms) {
                AckPermit::Granted => {
                    self.last_ack_picked = Some(label);
                    let Some(index) = self.correspondences.iter().position(|c| c.label == label)
                    else {
                        continue;
                    };
                    out.extend(self.publish_standalone_ack(index));
                }
                AckPermit::Refused { retry_after_ms } => {
                    self.ack_retry_due_ms = Some(now_ms.saturating_add(retry_after_ms));
                    break;
                }
            }
        }
        out
    }

    /// Build and address one correspondence's standalone acknowledgement.
    ///
    /// `recv_direction`, because the record acknowledges the messages this side
    /// *collected*: the party collecting `a2b` writes the `a2b` record. Signed
    /// under the conversation's pseudonym key, which is the same key that signs
    /// every frame here and never the long-term identity key.
    ///
    /// A build or derivation failure spends the allowance and writes nothing.
    /// That is the conservative side: the alternative is releasing the allowance
    /// on a path that has already failed once, which turns a module fault into a
    /// retry loop against the client-wide ceiling.
    fn publish_standalone_ack(&self, index: usize) -> Vec<DmEffect> {
        let correspondence = &self.correspondences[index];
        let Some((ratchet, signing_pc, channel)) = correspondence.live() else {
            return Vec::new();
        };
        // A torn-down conversation writes no more of its own records either. The
        // acknowledgement is not a page, so nothing here is re-opened by it — what
        // it would be is this side telling a correspondent whose channel is gone
        // what it collected, on a cadence whose pending set the teardown left
        // unpruned. See `Self::torn_down`.
        if self.torn_down.contains(ratchet.ar_fingerprint()) {
            return Vec::new();
        }
        let direction = ratchet.recv_direction();
        let record = match ack_record::build_encoded(
            correspondence.collection.ack(),
            &channel.chan_id,
            direction,
            &correspondence.address_root,
            signing_pc,
        ) {
            Ok(record) => record,
            Err(e) => {
                crate::vtrace!("dm driver: the acknowledgement record would not build: {e}");
                return Vec::new();
            }
        };
        let address = match DmAckAddress::for_direction(&correspondence.address_root, direction) {
            Ok(address) => address,
            Err(e) => {
                crate::vtrace!("dm driver: ack address derivation failed: {e}");
                return Vec::new();
            }
        };
        vec![DmEffect::Dht(DhtOp::PublishAck {
            tag: OpTag::channel(*ratchet.ar_fingerprint(), None, None),
            address,
            record,
        })]
    }

    // ---- the inbound half --------------------------------------------------

    /// Verify one sweep's slots and decide what each one meant.
    fn on_doorbell(&mut self, now_ms: i64, sweep: DoorbellSweep) -> Vec<DmEffect> {
        let current_fc_epoch = keyrec::fc_epoch(unix_secs(now_ms));
        // Both bounded sets are aged BEFORE anything is admitted, so a sweep
        // never verifies against a window that has already moved on: the seen
        // set drops epochs outside the accept window, and the spent set drops
        // nonces whose tokens expired past the retention period.
        self.seen.retire(current_fc_epoch);
        let pruned = self.spent.set.prune(unix_secs(now_ms));

        // **An unreadable block list ends the sweep before anything is
        // recorded**, and both halves of that matter. Fail-closed is the
        // store's own direction — an absent record is `BlockListMissing`
        // rather than an empty list, because answering absence with "nobody is
        // blocked" is silent unblocking. Returning *before* the loop is the
        // other half: dropping per slot would still have run admission, which
        // records the entry in the seen set and its bytes in `previous_slots`,
        // so the same entry could never be admitted again once the list was
        // readable. A sweep that decides nothing must also remember nothing.
        let block_list = match self.persist.read_block_list() {
            Ok(list) => list,
            Err(e) => {
                crate::vtrace!("dm driver: block list unreadable, dropping the sweep: {e}");
                return vec![DmEffect::Emit(self.health(sweep.outcome, 0))];
            }
        };

        // A held request whose admitting epoch has fallen out of the accept
        // window names an entry that can no longer be presented, so answering
        // it could not establish anything.
        self.pending
            .retain(|held| held.admitted_epoch + 1 >= current_fc_epoch);

        // Step 0's memory is bounded by the doorbell itself: a slot the record
        // no longer holds cannot be the "unchanged" case for anything, so
        // keeping its bytes is a leak that grows with every slot ever written.
        let present: std::collections::BTreeSet<u16> =
            sweep.slots.iter().map(|(slot, _)| *slot).collect();
        self.previous_slots.retain(|slot, _| present.contains(slot));

        let mut out = Vec::new();
        let mut lookup_failures = 0u64;
        let mut pending_full = 0u64;
        let spent_before = self.spent.set.len();
        for (slot, bytes) in sweep.slots {
            // **The cap is checked BEFORE admission, not after.** Admission
            // records an entry's hash in the seen set the moment its proof of
            // work passes, so a knock refused for room *after* being admitted
            // is a knock that can never be presented again — sixty-four
            // unanswered requests would permanently deafen first contact rather
            // than pausing it. Skipping the slot entirely leaves the entry
            // unrecorded, so the sender's next re-seed finds room once the user
            // has answered something.
            //
            // The cost, named: a known correspondent's state-loss signal is not
            // read either while the list is full. That is bounded by the user
            // answering one request, and the alternative burns the entry.
            if self.pending.len() >= PENDING_REQUEST_CAP {
                pending_full += 1;
                continue;
            }
            let lookup_failed = std::cell::Cell::new(false);
            let admitted = self.admit_slot(now_ms, slot, &bytes, &lookup_failed);
            let AdmissionOutcome::Admitted {
                verified,
                idempotent,
                entry_hash,
                ..
            } = admitted
            else {
                self.previous_slots.insert(slot, bytes);
                continue;
            };
            // **A slot whose contact lookup failed is left exactly as it was
            // found.** The closure fails closed to "already known", which is
            // the safe answer for admission — it cannot surface a second
            // request for an existing correspondent — but it is a *guess* about
            // this entry, and acting on it would report a stranger as a
            // correspondent whose channel direction is unknown. So the decision
            // is deferred rather than taken: the entry hash is forgotten and
            // the slot's bytes are not recorded, which is what makes the next
            // sweep try again instead of dropping it as `Seen` or `Unchanged`
            // for ever.
            if lookup_failed.get() {
                lookup_failures += 1;
                self.seen.forget(&entry_hash);
                continue;
            }
            self.previous_slots.insert(slot, bytes);
            if block_list.suppresses_knock(&verified) {
                continue;
            }
            out.extend(self.surface(
                now_ms,
                current_fc_epoch,
                slot,
                entry_hash,
                verified,
                idempotent,
            ));
        }

        out.push(DmEffect::Emit(self.health(sweep.outcome, pending_full)));
        if lookup_failures > 0 {
            out.push(DmEffect::Emit(DmEvent::ContactLookupFailed));
        }
        // Written only when a nonce was actually consumed or expired — under
        // `AdmissionPolicy::Open` that is never, because the token field is not
        // looked at at all.
        if self.spent.set.len() != spent_before || pruned > 0 {
            out.extend(self.save_spent());
        }
        out
    }

    /// This sweep's record health, carrying admission's running totals.
    fn health(&self, outcome: crate::SweepOutcome, pending_full: u64) -> DmEvent {
        DmEvent::DoorbellHealth {
            outcome,
            admission: self.admission,
            pending_full,
        }
    }

    /// Run one slot through [`Admitter`] in its documented order.
    fn admit_slot(
        &mut self,
        now_ms: i64,
        slot: u16,
        bytes: &[u8],
        lookup_failed: &std::cell::Cell<bool>,
    ) -> AdmissionOutcome {
        let now_unix_secs = unix_secs(now_ms);
        // Disjoint field borrows: the seen and spent sets are taken mutably by
        // the admitter while the closure holds the store and the pending list.
        let Self {
            identity,
            persist,
            cfg,
            previous_slots,
            keyrec_addr,
            seen,
            spent,
            pending,
            admission,
            ..
        } = self;
        let previous = previous_slots.get(&slot).map(Vec::as_slice);
        let mut admitter = Admitter {
            recipient_dk: identity.kem.decapsulation_key(),
            recipient_pk_lt: identity.signing.public_key(),
            recipient_keyrec_addr: keyrec_addr,
            current_fc_epoch: keyrec::fc_epoch(now_unix_secs),
            now_unix_secs,
            policy: cfg.policy,
            difficulty: cfg.pow_difficulty,
            seen,
            spent: &mut spent.set,
            // Carried in and back out, so the totals are the machine's across
            // every sweep rather than one slot's, discarded.
            counters: *admission,
        };
        let outcome = admitter.admit(bytes, previous, |pk| {
            if pending.iter().any(|held| held.knock.pk_lt() == pk) {
                return true;
            }
            match established_with(persist, pk) {
                Ok(found) => found,
                // Fail closed: an unreadable or ambiguous store must not read
                // as "this identity is a stranger", which would surface a
                // second contact request for an existing correspondent. The
                // cost is that a stranger's knock is dropped for as long as the
                // store stays that way, which is why it is reported rather than
                // only traced.
                Err(e) => {
                    crate::vtrace!("dm driver: correspondence lookup failed: {e}");
                    lookup_failed.set(true);
                    true
                }
            }
        });
        *admission = admitter.counters;
        outcome
    }

    /// Turn one admitted knock into what the front end is owed.
    fn surface(
        &mut self,
        now_ms: i64,
        current_fc_epoch: u64,
        slot: u16,
        entry_hash: [u8; pow::ENTRY_HASH_LEN],
        verified: Box<VerifiedFirstContact>,
        idempotent: bool,
    ) -> Vec<DmEffect> {
        if idempotent {
            return self.on_known_correspondent(now_ms, &verified);
        }
        if self.pending.len() >= PENDING_REQUEST_CAP {
            crate::vtrace!("dm driver: {PENDING_REQUEST_CAP} requests already held, dropping one");
            return Vec::new();
        }
        let id = RequestId { slot, entry_hash };
        let event = DmEvent::ContactRequest {
            request: id.clone(),
            from: Box::new(*verified.pk_lt()),
            body: verified.body().to_string(),
            sent_unix_ms: verified.sent_unix_ms(),
        };
        self.pending.push(Held {
            id,
            knock: verified,
            admitted_epoch: current_fc_epoch,
        });
        vec![DmEffect::Emit(event)]
    }

    /// A knock from an identity we already correspond with.
    ///
    /// Only [`DmPersist::correspondent_state_lost`] can tell whether it is the
    /// introduction that established us arriving again — which is ordinary, and
    /// happens for up to the seven-day give-up — or the correspondent having
    /// lost their at-rest state, which ends every pending message we hold for
    /// them.
    ///
    /// **The direction is not guessed.** That call names this side's outbox and
    /// it is destructive: under the state-loss cause every pending entry becomes
    /// undelivered, terminally. The direction lives on the ratchet, which this
    /// session holds only for correspondences it established itself
    /// ([`ContactRecord`](daemonseed_core::dm::contact_cache::ContactRecord)
    /// records `pk_lt`, `pk_pc` and `ss0`, and no role), so after a restart it
    /// is simply not known here — and trying one direction and then the other
    /// would run the destructive call on a coin toss. The user is told instead,
    /// and the queue falls back to the seven-day give-up, which is wasteful and
    /// never false.
    fn on_known_correspondent(
        &mut self,
        now_ms: i64,
        knock: &VerifiedFirstContact,
    ) -> Vec<DmEffect> {
        let Some(direction) = self
            .correspondences
            .iter()
            .find(|c| c.pk_lt.as_slice() == knock.pk_lt().as_slice())
            .and_then(|c| c.ratchet.as_ref())
            .map(Ratchet::send_direction)
        else {
            crate::vtrace!("dm driver: no ratchet for a knocking correspondent, deciding nothing");
            return vec![DmEffect::Emit(DmEvent::ChannelDirectionUnknown {
                with: Box::new(*knock.pk_lt()),
            })];
        };
        match self
            .persist
            .correspondent_state_lost(knock, direction, now_ms)
        {
            Ok(StateLoss::NoCorrespondence) | Ok(StateLoss::SameChannel(_)) => Vec::new(),
            Ok(StateLoss::Confirmed {
                teardown, outcome, ..
            }) => {
                // Every page of the conversation, because a teardown ends it: the
                // pending entries are terminal, and the conversation is recorded in
                // `torn_down` just below, which is what actually stops a later plan
                // or write naming these records — the ratchet and the channel roots
                // survive a teardown and every planner reads exactly those. Taken
                // BEFORE the event is built, because `teardown` is consumed building
                // it and the index is what the close needs.
                let mut out = match self
                    .correspondences
                    .iter()
                    .position(|c| c.pk_lt.as_slice() == knock.pk_lt().as_slice())
                {
                    Some(index) => {
                        // **Recorded as torn down BEFORE the pages are handed
                        // back**, so no planner can name one of these records
                        // between the two. A teardown leaves the ratchet and the
                        // channel roots in place and every planner reads exactly
                        // those, so without this the next probe cadence re-opens
                        // the receiving pair this close just released.
                        if let Some(conversation) = self.correspondences[index]
                            .ratchet
                            .as_ref()
                            .map(|r| *r.ar_fingerprint())
                        {
                            self.torn_down.insert(conversation);
                        }
                        // The acknowledgement cadence's own state, dropped with the
                        // channel it was keeping. Left in place it is a set of
                        // positions this side owes an acknowledgement for on a
                        // channel that no longer exists, ageing out only at each
                        // entry's give-up — a week of a dead correspondence holding
                        // the oldest key in every scheduling round.
                        self.correspondences[index].pending_sent_ms.clear();
                        self.close_all_pages(index)
                    }
                    None => Vec::new(),
                };
                out.push(DmEffect::Emit(DmEvent::ChannelLost {
                    with: Box::new(*knock.pk_lt()),
                    // The taxonomy's key is what makes this ending loud rather than
                    // a line in a trace (ISC-C28, `docs/design/direct-messaging.md`
                    // — loud teardown). Both fields read the same `cause`, and
                    // `into_cause` consumes the teardown, so this ordering is the
                    // compiler's rather than a convention to keep: written the other
                    // way round it does not build.
                    event: teardown.event(),
                    cause: teardown.into_cause(),
                    // The sequences the user is owed. Dropping them would leave
                    // this event saying a channel ended and nothing saying which
                    // messages ended with it.
                    surfaced: outcome.surfaced,
                }));
                out
            }
            Err(e) => {
                crate::vtrace!("dm driver: state-loss check failed: {e}");
                Vec::new()
            }
        }
    }

    /// Accept one held request: establish the correspondence on our side.
    ///
    /// **A failure puts the request back.** The user answered it, and an accept
    /// that removed the request and then failed would leave nothing on screen
    /// to answer again and nothing saying why the channel never appeared.
    fn accept(&mut self, now_ms: i64, request: &RequestId) -> Vec<DmEffect> {
        let Some(index) = self.pending.iter().position(|held| &held.id == request) else {
            // A stale accept — the request was declined, blocked away, expired,
            // or the driver restarted since it was shown.
            return Vec::new();
        };
        let held = self.pending.remove(index);
        let pk_lt: PkLt = Box::new(*held.knock.pk_lt());
        // Copied before the box is moved into the correspondence: the
        // acceptance below has to find the entry it just recorded.
        let pk_lt_for_accept: [u8; IDENTITY_PK_LEN] = *pk_lt;
        let peer_pk_pc = Box::new(*held.knock.pk_pc());
        // Copied out before the knock is consumed. Both are derivations of
        // `ss0`, which `accept_first_contact` moves, so this is the last point
        // either can be read — and without them the channel has no address and
        // no seal binding.
        let channel = ChannelRoots {
            chan_id: held.knock.roots().chan_id,
        };
        let address_root = held.knock.roots().ar;

        // **The recoverable refusals are taken here, before the knock is
        // consumed.** `accept_first_contact` moves the `VerifiedFirstContact`
        // — `ss0` leaves it by a consuming accessor and there is no way back —
        // so a refusal raised inside it arrives with the request already
        // destroyed. Asking the two questions that can be asked without it
        // means the two failures a user can actually do something about leave
        // the request on screen to answer again.
        match self.established_with(&pk_lt) {
            Ok(true) => return self.hold_again(held, AcceptFailure::AlreadyEstablished),
            Ok(false) => {}
            Err(e) => {
                crate::vtrace!("dm driver: correspondence lookup failed: {e}");
                return self.hold_again(held, AcceptFailure::StoreFailure);
            }
        }
        // The acceptor's pseudonym for this conversation. Minted here rather
        // than at the sweep so a declined knock costs no keygen, and before the
        // knock is consumed so its failure is recoverable too.
        let signing_pc = match mint_pseudonym() {
            Ok(k) => k,
            Err(e) => {
                crate::vtrace!("dm driver: pseudonym keygen failed: {e}");
                return self.hold_again(held, AcceptFailure::StoreFailure);
            }
        };

        // The pseudonym's secret half travels into the establishment because
        // that write is its only at-rest home: it is minted from the CSPRNG here
        // and is not derivable from the mnemonic or the shared secret, so a
        // correspondence established without it could never sign a
        // re-establishment leg.
        match self
            .persist
            .accept_first_contact(*held.knock, signing_pc.secret_key(), now_ms)
        {
            Ok((label, ratchet)) => {
                // **Updated in place where an entry already exists**, never
                // pushed a second time. A mutual knock — each side knocking
                // before either answered — leaves this side holding a
                // correspondence it minted as an initiator AND accepting one as
                // a recipient, and two entries for one `pk_lt` would make
                // `index_of` answer with whichever came first for ever, so
                // sends and sweeps would use different halves of the same
                // conversation.
                if let Some(index) = self.index_of(&pk_lt) {
                    // **The record this side was holding is erased FIRST, under
                    // the label it was written beneath.** A mutual knock leaves
                    // this side holding a provisional record from its own
                    // introduction; accepting THEIR knock establishes the
                    // conversation by a different route, so that record's
                    // window is over. It has to go before the label is
                    // overwritten: the record lives under the old label, and
                    // the context that addresses it would name a directory this
                    // entry no longer points at — leaving `{ss0, the opening
                    // ephemeral DK}` on disk with nothing able to reach it.
                    //
                    // Erasing it also means the acceptance path below cannot
                    // strand it: `on_page` erases only when it installs a
                    // pseudonym, and this branch has just installed one.
                    let (persist, correspondences) = (&self.persist, &mut self.correspondences);
                    let old_label = correspondences[index].label;
                    // The outcome is read for its trace only: this handle is
                    // being abandoned either way, and a record that was already
                    // gone is the ordinary answer on a knock the correspondent
                    // never collected.
                    match erase_provisional(persist, &mut correspondences[index]) {
                        Erasure::Absent => crate::vtrace!(
                            "dm driver: the superseded knock's handshake record was already gone"
                        ),
                        Erasure::Deleted | Erasure::Retry => {}
                    }
                    // **What the erase could not reach is carried out, not
                    // dropped.** The entry is about to name a different label,
                    // so a handle left on it would address the wrong directory
                    // — but the record still exists, and the context is the
                    // only thing that can ever open it again. It moves to the
                    // machine's retry list, keyed on the label it was written
                    // under, and every tick tries again.
                    let leftover = correspondences[index].provisional.take();
                    let existing = &mut correspondences[index];
                    existing.label = label;
                    existing.ratchet = Some(ratchet);
                    existing.signing_pc = Some(signing_pc);
                    existing.peer_pk_pc = Some(peer_pk_pc);
                    existing.channel = Some(channel);
                    existing.address_root = address_root;
                    existing.provisional = None;
                    if let Some((keyrec_addr, fc_epoch)) = leftover {
                        self.pending_erase.push((old_label, keyrec_addr, fc_epoch));
                    }
                } else {
                    self.correspondences.push(Correspondence {
                        pk_lt,
                        label,
                        ratchet: Some(ratchet),
                        signing_pc: Some(signing_pc),
                        peer_pk_pc: Some(peer_pk_pc),
                        channel: Some(channel),
                        address_root,
                        candidate: None,
                        re_acks_answered: 0,
                        response_cap_surfaced: false,
                        retire_ceiling_surfaced: false,
                        leg_give_up_surfaced: false,
                        peer_regression_surfaced: false,
                        collection: collection_accepting_a_knock(),
                        read_through: 0,
                        cursor_unreadable: false,
                        owed_acks: Vec::new(),
                        offered_this_session: Vec::new(),
                        health: ChannelCounters::default(),
                        ack_cadence: StandaloneAckCadence::new(),
                        pending_sent_ms: Vec::new(),
                        own_ack: AckState::new(),
                        last_accept_refusal: None,
                        // The acceptor holds no provisional record: it was
                        // never the one waiting on a reply.
                        provisional: None,
                        rearm_handshake: false,
                        rearm_faults: 0,
                        pseudonym_unwritten: false,
                        pseudonym_faults: 0,
                        resume_owed: false,
                        resume_faults: 0,
                        resume_retry_due_ms: None,
                        resume_surfaced: false,
                        resume_ceiling_surfaced: false,
                    });
                }
                // **The acceptance fires here, in the same call**, because the
                // design's ACCEPT is not a message the user composes — it is
                // what tells the initiator which pseudonym to verify against,
                // and until it lands the initiator can read nothing this side
                // writes. Waiting for the first typed reply would leave a
                // conversation the initiator can send into and never hear from.
                let index = self
                    .index_of(&pk_lt_for_accept)
                    .expect("the correspondence was just recorded");
                self.fire_accept(now_ms, index)
            }
            // Past the consuming call. The knock is gone, so the request
            // cannot be re-held — the user is told, and re-establishing needs
            // the sender's next re-seed, which their own schedule provides.
            Err(e) => {
                crate::vtrace!("dm driver: accept failed after the knock was consumed: {e}");
                let reason = match e {
                    DmPersistError::AlreadyEstablished => AcceptFailure::AlreadyEstablished,
                    _ => AcceptFailure::StoreFailure,
                };
                vec![DmEffect::Emit(DmEvent::AcceptFailed {
                    request: held.id,
                    from: pk_lt,
                    reason,
                })]
            }
        }
    }

    /// Compose and queue the ACCEPT for a correspondence just established as
    /// the acceptor.
    ///
    /// **The frozen design fires this the instant the user accepts, not when
    /// they first type.** The acceptance is what carries this side's pseudonym
    /// and its long-term binding to the initiator; until it lands, the
    /// initiator holds a channel it can write to and cannot read, because a
    /// channel frame carries no pseudonym key and page owner-write authority is
    /// symmetric. So it is queued here, in the same call as the establishment,
    /// and from that point it is an outbox entry like any other — re-seeded on
    /// the ladder, given up on at the same seven days.
    ///
    /// **The order is the one [`Self::send`] documents, and for the same
    /// reason.** The outbox is asked for room BEFORE [`Ratchet::send_next`]
    /// takes its irreversible step, so a full record refuses while sequence
    /// zero is still unspent. Past the step there is no way back: the sequence
    /// is burnt, there is no second acceptance path, and the initiator
    /// stays unable to verify until the reconnect legs (A3 / A4) exist. That is
    /// reported as a refusal rather than swallowed.
    /// Compose the acceptance, and report a refusal only when it is NEWS.
    ///
    /// **The retry runs every tick, so an unchanged refusal would be emitted
    /// every tick too** — a full outbox that stays full would fill the front
    /// end's event stream with the identical pair for as long as it takes to
    /// drain, which is exactly the condition under which a user is least able
    /// to read it. The last reason is remembered per correspondence and a
    /// repeat is silent; a *different* reason is a genuinely new fact and is
    /// emitted.
    ///
    /// Cleared on success, so a conversation that fails, recovers, and fails
    /// the same way again says so both times.
    fn fire_accept(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        match self.compose_accept(now_ms, index) {
            Ok(out) => {
                self.correspondences[index].last_accept_refusal = None;
                out
            }
            Err(reason) => {
                if self.correspondences[index].last_accept_refusal == Some(reason) {
                    return Vec::new();
                }
                self.correspondences[index].last_accept_refusal = Some(reason);
                let to = *self.correspondences[index].pk_lt;
                accept_refused(&to, reason)
            }
        }
    }

    fn compose_accept(
        &mut self,
        now_ms: i64,
        index: usize,
    ) -> Result<Vec<DmEffect>, RefusalReason> {
        let label = self.correspondences[index].label;
        let to: PkLt = Box::new(*self.correspondences[index].pk_lt);
        let Some((ratchet, _, _)) = self.correspondences[index].live() else {
            crate::vtrace!("dm driver: the acceptance has no key schedule to send on");
            return Err(RefusalReason::NotEstablishedThisSession);
        };
        let direction = ratchet.send_direction();
        let next_seq = ratchet.next_send_seq();

        // The ask, priced exactly as a send's is: no caller can know a frame's
        // real length before sealing it, so the worst case is what is reserved.
        let asked = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                Ok(Mutation::Unchanged(outbox.room_for(
                    next_seq,
                    OutboxTarget::ChannelPage,
                    WORST_CASE_SEALED_FRAME_LEN,
                )))
            });
        match asked {
            Ok(Ok(())) => {}
            Ok(Err(OutboxError::Full { needed, .. })) => {
                return Err(RefusalReason::OutboxFull { needed });
            }
            Ok(Err(e)) => {
                crate::vtrace!("dm driver: the outbox refused the acceptance: {e}");
                return Err(RefusalReason::StoreFailure);
            }
            Err(e) => {
                crate::vtrace!("dm driver: the outbox could not be read for the acceptance: {e}");
                return Err(RefusalReason::StoreFailure);
            }
        }

        let Self {
            identity,
            persist,
            correspondences,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        let recipient = match recipient_hash(&correspondence.pk_lt) {
            Ok(h) => h,
            Err(e) => {
                crate::vtrace!("dm driver: recipient hash failed for the acceptance: {e}");
                return Err(RefusalReason::Module);
            }
        };
        let (Some(ratchet), Some(signing_pc), Some(channel)) = (
            correspondence.ratchet.as_mut(),
            correspondence.signing_pc.as_ref(),
            correspondence.channel.as_ref(),
        ) else {
            return Err(RefusalReason::NotEstablishedThisSession);
        };
        // Past this line a sequence number has been spent.
        let outbound = match ratchet.send_next() {
            Ok(o) => o,
            Err(e) => {
                crate::vtrace!("dm driver: the ratchet refused the acceptance key: {e}");
                return Err(RefusalReason::SealFailed);
            }
        };
        let seq = outbound.header.seq;
        debug_assert_eq!(
            seq, FIRST_RECIPIENT_CHANNEL_SEQ,
            "the acceptance is the acceptor's first channel write"
        );
        // Read before the seal, which consumes the outbound — see the sibling
        // read on the ordinary send path.
        let sealed_under_gen = outbound.header.generation;
        let sealed = match frame::seal_accept(
            outbound,
            &channel.chan_id,
            signing_pc,
            &identity.signing,
            &recipient,
            now_ms,
            Some(correspondence.collection.ack()),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                crate::vtrace!("dm driver: the acceptance would not seal: {e}");
                return Err(RefusalReason::SealFailed);
            }
        };
        let queued = persist.update_outbox(&label, direction, now_ms, |outbox| {
            outbox.enqueue_sealed(
                seq,
                OutboxTarget::ChannelPage,
                now_ms,
                SealedFrame::new(sealed),
                sealed_under_gen,
            )?;
            Ok(Mutation::Changed(()))
        });
        if let Err(e) = queued {
            crate::vtrace!("dm driver: the acceptance sealed and could not be queued: {e}");
            return Err(RefusalReason::StoreFailure);
        }
        Ok(vec![DmEffect::Emit(DmEvent::Delivery {
            to,
            seq,
            state: DeliveryState::Composed,
        })])
    }

    /// Put a request back on the held list and say why it was not established.
    fn hold_again(&mut self, held: Held, reason: AcceptFailure) -> Vec<DmEffect> {
        let event = DmEvent::AcceptFailed {
            request: held.id.clone(),
            from: Box::new(*held.knock.pk_lt()),
            reason,
        };
        self.pending.push(held);
        vec![DmEffect::Emit(event)]
    }

    /// Block or unblock one identity on both suppression planes.
    ///
    /// **The stored list is the whole of the state, and an established
    /// correspondence is left standing.** Blocking writes one record; the next
    /// tick reads it and stops sweeping that correspondent's pages
    /// ([`Self::probe`]), and unblocking resumes them on the tick after it. The
    /// channel is not torn down, the ratchet is not stepped, the outbox is not
    /// touched and the contact cache keeps its row — the design suppresses
    /// *reading* a blocked correspondent, not the record of the correspondence,
    /// so a block is reversible with nothing to rebuild.
    ///
    /// The one thing it changes beyond the list is what is already on screen: a
    /// held request from that identity is dropped, because a block is meant to
    /// take effect on the request in front of the user and not only on the next
    /// one to arrive. That drop is conditional on the write having landed — a
    /// refused one leaves both the list and the held request as they were.
    fn set_blocked(&mut self, pk_lt: &PkLt, blocked: bool) -> Vec<DmEffect> {
        let result = self.persist.update_block_list(|list: &mut BlockList| {
            if blocked {
                list.block(pk_lt);
            } else {
                list.unblock(pk_lt);
            }
            Ok(())
        });
        let out = match result {
            Ok(()) => {
                if blocked {
                    // **Inside the `Ok` arm, because the list is what makes the
                    // drop correct.** A refused write leaves the identity
                    // unblocked, and dropping its held request anyway would
                    // discard a request that is still legitimate — until a
                    // restart or a fresh entry, since its entry hash is already
                    // in the seen set and the sender's re-seed would be read as
                    // `Seen` rather than surfaced again.
                    self.pending
                        .retain(|held| held.knock.pk_lt().as_slice() != pk_lt.as_slice());
                }
                Vec::new()
            }
            // The 513th identity. The stored 512 are left exactly as they were
            // — `BlockList::encode` refuses before the replace — so this is a
            // ceiling reached, not a list damaged, and the user is the only one
            // who can decide what to remove.
            Err(DmPersistError::BlockList(BlockListError::Full { count })) => {
                vec![DmEffect::Emit(DmEvent::BlockListFull { count })]
            }
            Err(e) => {
                crate::vtrace!("dm driver: block list update failed: {e}");
                Vec::new()
            }
        };
        out
    }

    // ---- the outbound half -------------------------------------------------

    /// Start one introduction: fetch the recipient's key record.
    fn start_introduction(&mut self, _now_ms: i64, recipient: PkLt, body: String) -> Vec<DmEffect> {
        if self.introduction_in_flight(&recipient) {
            crate::vtrace!("dm driver: an introduction to this recipient is already in flight");
            return vec![DmEffect::Emit(refused(
                &recipient,
                RefusalReason::AlreadyInFlight,
                None,
            ))];
        }
        // **First contact is for strangers.** Knocking at an identity we
        // already correspond with is read at the far end as evidence we lost
        // our at-rest state, and their client answers it by ending every
        // message they have queued for us — so an unguarded `FirstContact` from
        // the UI is a way to destroy a live conversation from the wrong button.
        match self.established_with(&recipient) {
            Ok(true) => {
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::AlreadyEstablished,
                    None,
                ))];
            }
            Ok(false) => {}
            Err(e) => {
                // Fail closed for the same reason the sweep does: an unreadable
                // store must not read as "this identity is a stranger".
                crate::vtrace!("dm driver: correspondence lookup failed: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::StoreFailure,
                    None,
                ))];
            }
        }
        let owner_seed = match keyrec::derive_owner_seed(&recipient) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: recipient key-record derivation failed: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::Module,
                    None,
                ))];
            }
        };
        let tag = OpTag::introduction(Box::new(*recipient));
        self.outbound.push(Introduction { recipient, body });
        vec![DmEffect::Dht(DhtOp::FetchKeyRecord { tag, owner_seed })]
    }

    /// The recipient's key record came back.
    fn on_key_record(
        &mut self,
        now_ms: i64,
        recipient: PkLt,
        record: Option<Vec<u8>>,
    ) -> Vec<DmEffect> {
        let Some(index) = self
            .outbound
            .iter()
            .position(|i| i.recipient.as_slice() == recipient.as_slice())
        else {
            return Vec::new();
        };
        let introduction = self.outbound.remove(index);
        // `None` is the awaiting-key state, not a transport failure: the record
        // was evicted, wiped, or never published. Nothing is composed and
        // nothing is written — an entry sealed to no key is not an entry.
        let Some(bytes) = record else {
            crate::vtrace!("dm driver: no key record for this recipient");
            return vec![DmEffect::Emit(refused(
                &recipient,
                RefusalReason::NoKeyRecord,
                None,
            ))];
        };
        // **Verified THROUGH the session's bound, never beside it.** A record
        // that verifies is not yet a record to use: the address is world-
        // writable, so an authentic pre-rotation blob can be replayed into it,
        // and only the highest version already verified for this identity tells
        // the two apart. The bound is written here, on the fetch, because this
        // is the only place a key record is read.
        //
        // **The bound is carried in a detached cache and written back only where
        // a record verified.** An entry is the record of a verified fetch, so
        // creating one first would leave an empty entry behind for every
        // malformed or forged blob served at that address — a list anyone able
        // to write the record could grow without holding a key. A refused fetch
        // touches nothing.
        let mut cache = self
            .key_records
            .iter()
            .find(|(pk, _)| pk.as_slice() == recipient.as_slice())
            .map(|(_, held)| held.clone())
            .unwrap_or_default();
        let kem_ek_b = match cache.accept_encoded(&bytes, &recipient) {
            Ok(v) => v.kem_ek.clone(),
            Err(DmKeyRecordError::VersionRegression { cached, offered }) => {
                crate::vtrace!(
                    "dm driver: key record rolled back, cached {cached} offered {offered}"
                );
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::KeyRecordRollback,
                    None,
                ))];
            }
            Err(e) => {
                crate::vtrace!("dm driver: key record did not verify: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::KeyRecordInvalid,
                    None,
                ))];
            }
        };
        self.remember_key_record_bound(&recipient, cache);
        let signing_pc = match mint_pseudonym() {
            Ok(k) => k,
            Err(e) => {
                crate::vtrace!("dm driver: pseudonym keygen failed: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::Module,
                    None,
                ))];
            }
        };
        let recipient_keyrec_addr = match keyrec::derive_owner_seed(&recipient) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: recipient key-record derivation failed: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::Module,
                    None,
                ))];
            }
        };
        self.minting.push(Box::new(*recipient));
        vec![DmEffect::Compute(ComputeJob::MintFirstContact(Box::new(
            MintRequest {
                recipient,
                signing_lt: self.identity.signing.clone(),
                signing_pc,
                kem_ek_b,
                recipient_keyrec_addr,
                fc_epoch: keyrec::fc_epoch(unix_secs(now_ms)),
                sent_unix_ms: now_ms,
                body: introduction.body,
                difficulty: self.cfg.pow_difficulty,
            },
        )))]
    }

    /// The entry is minted: persist our side, then knock.
    fn on_mint(&mut self, now_ms: i64, mint: MintOutcome) -> Vec<DmEffect> {
        let MintOutcome {
            recipient,
            signing_pc,
            fc_epoch,
            recipient_keyrec_addr,
            result,
        } = mint;
        let (entry, state) = match result {
            Ok(pair) => pair,
            Err(e) => {
                crate::vtrace!("dm driver: first-contact build failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::MintFailed, None);
            }
        };
        // **A conversation already established with this identity is never
        // overwritten by a mint, and the case that reaches here is the mutual
        // knock.** Each side knocks before either answers; this side then
        // accepts THEIR knock while its own introduction is still between the
        // key record and the mint. The accept established the correspondence
        // and installed their pseudonym; letting the mint land on top of it
        // would replace the label, the ratchet and the channel roots of a live
        // conversation, and re-point the entry at a provisional record whose
        // erasure `on_page` can no longer reach — it erases only when it
        // installs a pseudonym, and one is installed already. Refused before
        // anything is written, so no record is created to strand.
        //
        // `peer_pk_pc.is_some()` is the test rather than `ratchet.is_some()`,
        // because a second mint after a failed knock is legitimate: it reuses
        // the same label, overwrites the same record, and that entry has no
        // pseudonym for its correspondent.
        if self
            .index_of(&recipient)
            .is_some_and(|i| self.correspondences[i].peer_pk_pc.is_some())
        {
            crate::vtrace!("dm driver: this identity is already established; the mint is dropped");
            return self.refuse_introduction(&recipient, RefusalReason::AlreadyEstablished, None);
        }
        // **One provisional label per recipient, never one per attempt.** A
        // second label is a second correspondence directory holding a live
        // `ss0` that nothing will ever establish or erase, so the label is
        // reused where one is already known.
        let label = match self.provisional_label(&recipient, &recipient_keyrec_addr, fc_epoch) {
            Ok(label) => label,
            Err(e) => {
                crate::vtrace!("dm driver: correspondence label mint failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
            }
        };
        // Read before `into_provisional` moves the state: the record recomputes
        // both from `ss0` and hands back neither, and `chan_id` is never
        // serialized at all (§ v4 minor invariant).
        let channel = ChannelRoots {
            chan_id: state.roots().chan_id,
        };
        let address_root = state.roots().ar;
        let record = match state.into_provisional() {
            Ok(r) => r,
            Err(e) => {
                crate::vtrace!("dm driver: provisional record build failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
            }
        };
        // Persisted BEFORE the write is asked for. The record holds the opening
        // ephemeral, and a knock published against a record that was never
        // written is a handshake the recipient can complete and we cannot.
        if let Err(e) = self.persist.save_provisional(
            &label,
            &RecordContext {
                recipient_keyrec_addr: &recipient_keyrec_addr,
                fc_epoch,
            },
            &record,
        ) {
            crate::vtrace!("dm driver: provisional record write failed: {e}");
            return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
        }
        // **The contact record is written HERE, before the entry is published,
        // and it is what a restart taken before the acceptance depends on.**
        // The provisional record above holds the handshake's secrets and says
        // nothing about who this correspondence is with, so on its own it
        // leaves `DmPersist::correspondence_for_pk_lt` unable to map the
        // correspondent's identity key back to this label — and that mapping is
        // how an acceptance is routed to the entry it answers. Without it a
        // restart strands the knock: the acceptance is never collected and
        // every message the correspondent composes re-emits to the outbox's
        // seven-day give-up. The record carries no pseudonym; the correspondent's
        // is installed by `on_page` when their acceptance verifies.
        if let Err(e) = self.persist.record_first_contact_sent(
            &label,
            Box::new(*recipient),
            zeroize::Zeroizing::new(address_root),
            now_ms,
        ) {
            crate::vtrace!("dm driver: contact record write failed: {e}");
            // **The handshake record written a moment ago goes with the
            // refusal.** A refused introduction prunes this session's memory of
            // it and deletes nothing, so leaving it would strand `ss0` on disk
            // in a correspondence nothing can reach: the startup seed skips a
            // directory with no contact record, and the sweep that collects
            // superseded handshake records only looks beside a resume record,
            // which this correspondence has never had. A deletion the store
            // refuses goes to the retry list rather than being dropped, because
            // the context naming that record is the only thing that can ever
            // open it again.
            let unreached =
                match erase_record(&self.persist, &label, &recipient_keyrec_addr, fc_epoch) {
                    Erasure::Deleted | Erasure::Absent => false,
                    Erasure::Retry => true,
                };
            if unreached {
                self.pending_erase
                    .push((label, recipient_keyrec_addr, fc_epoch));
            }
            return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
        }
        let owner_seed = match doorbell::derive_owner_seed(&recipient) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: recipient doorbell derivation failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::Module, None);
            }
        };
        let slot = match doorbell::slot_for(&self.identity.doorbell_slot_secret, &recipient) {
            Ok(slot) => slot,
            Err(e) => {
                crate::vtrace!("dm driver: doorbell slot derivation failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::Module, None);
            }
        };
        // **The initiator's ratchet opens here, and the record STAYS.** The
        // opening burst hangs from the first-contact secret directly — nothing
        // about it waits on the correspondent — so a channel send is possible
        // from this moment. What is *not* possible yet is verifying the
        // correspondent, and the frozen design keeps `{ss0, the opening
        // ephemeral DK}` on disk for exactly that window: without the ephemeral
        // DK this side cannot decapsulate the acceptor's first generation
        // ciphertext, so consuming the record here would strand the channel on
        // any restart before the acceptance lands. `PendingHandshake::ratchet`
        // derives without erasing; the erasure is `commit`, and it runs in
        // `on_page` the moment an ACCEPT verifies.
        let ratchet = match self.persist.restart_channel(
            &label,
            &RecordContext {
                recipient_keyrec_addr: &recipient_keyrec_addr,
                fc_epoch,
            },
        ) {
            StoredChannelRestart::HandshakeResumes(pending) => match pending.ratchet() {
                // The `PendingHandshake` drops here, uncommitted and
                // deliberately: the record it names is the thing being kept.
                Ok(ratchet) => ratchet,
                Err(e) => {
                    crate::vtrace!("dm driver: the initiator's ratchet would not open: {e}");
                    return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
                }
            },
            // The label was minted for this introduction, so a resume record
            // under it is a correspondence that already exists — not the
            // handshake just written. Refused rather than resumed: this path
            // opens a ratchet from a fresh `ss0`, which would collide with the
            // established channel's sequence space.
            //
            // **No trust event.** Nothing was torn down here — the channel is
            // alive and this introduction is what is refused — so there is no
            // teardown whose key ISC-A-C12 would owe an audit entry for.
            StoredChannelRestart::Established(_) => {
                crate::vtrace!("dm driver: the label just minted is already established");
                return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
            }
            // **The refusal carries the teardown's classed key.** The channel
            // this introduction was opening is gone, ISC-A-C12 owes that an
            // audit entry, and the refusal is the only event a front end sees
            // for it, so the key travels on the refusal.
            //
            // **No test drives this arm**, because nothing inside this call
            // produces it: `restart_channel` reads the record
            // `save_provisional` wrote above, under the same label and the same
            // context. What reaches it comes from outside the call. The write
            // takes the store's lock and the read does not, so an erase another
            // writer left interrupted reads back as `NoProvisionalRecord` with
            // no error anywhere, and a genuine read fault reads back as
            // `StoreUnreadable`. A hit here is a question about the other
            // writer first and the disk second. Everything downstream of the
            // key is pinned from `refuse_introduction` on.
            StoredChannelRestart::TornDown(teardown) => {
                crate::vtrace!(
                    "dm driver: the record just written would not open: {:?}",
                    teardown.cause()
                );
                let event = teardown.event();
                return self.refuse_introduction(
                    &recipient,
                    RefusalReason::StoreFailure,
                    Some(event),
                );
            }
        };
        let conversation = *ratchet.ar_fingerprint();
        let direction = ratchet.send_direction();
        self.provisionals
            .retain(|(pk, _)| pk.as_slice() != recipient.as_slice());

        // **The correspondence is recorded BEFORE the enqueue**, so a fallible
        // step cannot return with the ratchet dropped and the correspondence
        // unrecorded — a channel nothing could speak on. The provisional
        // context rides with it, because the record it names is still on disk
        // and only this side knows the epoch it was sealed under.
        if let Some(index) = self.index_of(&recipient) {
            let existing = &mut self.correspondences[index];
            existing.label = label;
            existing.ratchet = Some(ratchet);
            existing.signing_pc = Some(signing_pc);
            existing.channel = Some(channel);
            existing.address_root = address_root;
            existing.provisional = Some((recipient_keyrec_addr, fc_epoch));
        } else {
            self.correspondences.push(Correspondence {
                pk_lt: Box::new(*recipient),
                label,
                ratchet: Some(ratchet),
                signing_pc: Some(signing_pc),
                // Filled in by the acceptor's ACCEPT, which is the only frame
                // that carries a pseudonym. See the field.
                peer_pk_pc: None,
                channel: Some(channel),
                address_root,
                candidate: None,
                re_acks_answered: 0,
                response_cap_surfaced: false,
                retire_ceiling_surfaced: false,
                leg_give_up_surfaced: false,
                peer_regression_surfaced: false,
                collection: Collection::new(),
                read_through: 0,
                cursor_unreadable: false,
                owed_acks: Vec::new(),
                offered_this_session: Vec::new(),
                health: ChannelCounters::default(),
                ack_cadence: StandaloneAckCadence::new(),
                pending_sent_ms: Vec::new(),
                own_ack: AckState::new(),
                last_accept_refusal: None,
                provisional: Some((recipient_keyrec_addr, fc_epoch)),
                rearm_handshake: false,
                rearm_faults: 0,
                pseudonym_unwritten: false,
                pseudonym_faults: 0,
                resume_owed: false,
                resume_faults: 0,
                resume_retry_due_ms: None,
                resume_surfaced: false,
                resume_ceiling_surfaced: false,
            });
        }

        // **Sequence zero is queued in the outbox, not merely published.** The
        // knock shares the channel's sequence space so the contiguous prefix can
        // confirm the opening message, and queueing it here is what makes a
        // re-seed re-emit the identical bytes — a second `firstcontact::build`
        // would encapsulate a fresh `ss0` and read at the far end as this side
        // having lost its state. It also makes a failed publish an unconfirmed
        // entry rather than an orphan: nothing else would ever try again.
        let queued = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                outbox.enqueue_sealed(
                    KNOCK_CHANNEL_SEQ,
                    OutboxTarget::Doorbell { slot },
                    now_ms,
                    SealedFrame::new(entry.clone()),
                    // The knock is the conversation's opening write and hangs
                    // from no ratchet chain, so it names generation zero — the
                    // first chain, which is what it precedes.
                    0,
                )?;
                Ok(Mutation::Changed(()))
            });
        if let Err(e) = queued {
            crate::vtrace!("dm driver: the knock could not be queued: {e}");
            return self.refuse_introduction(&recipient, RefusalReason::StoreFailure, None);
        }

        // The recipient stays in `minting` until this write's outcome lands, so
        // a refused write is still attributable to the introduction that asked
        // for it. The tag also carries the conversation and sequence zero, so
        // the same outcome confirms the outbox entry the bytes came from.
        vec![
            DmEffect::Emit(DmEvent::Delivery {
                to: Box::new(*recipient),
                seq: 0,
                state: DeliveryState::Composed,
            }),
            DmEffect::Dht(DhtOp::PublishDoorbell {
                tag: OpTag {
                    conversation: Some(conversation),
                    seq: Some(0),
                    page: None,
                    correspondent: Some(Box::new(*recipient)),
                    introduction: Some(Box::new(*recipient)),
                },
                owner_seed,
                slot,
                entry,
                dispatch: DoorbellDispatch::FirstSend,
            }),
        ]
    }

    /// The label this recipient's provisional record belongs under.
    ///
    /// In-memory first; then the store, because a restart empties the map while
    /// the record survives; and only then a fresh mint. The store lookup asks
    /// [`DmPersist::peek_channel_restart`] under this recipient's context at each
    /// live epoch — the non-writing form, because this walks correspondences it
    /// is not acting on — and a record opens only under the context it was
    /// sealed with,
    /// so a record that opens IS this recipient's. A record older than the
    /// accept window will not open and a new label is minted, which is the
    /// bound this leaves: the outbox's seven-day give-up window is longer than
    /// the first-contact epoch window, so a knock still being re-seeded can
    /// outlive the record that names where its provisional state lives.
    fn provisional_label(
        &mut self,
        recipient: &PkLt,
        recipient_keyrec_addr: &[u8; DM_KEYREC_OWNER_SEED_LEN],
        fc_epoch: u64,
    ) -> Result<CorrespondenceLabel, DmPersistError> {
        if let Some((_, label)) = self
            .provisionals
            .iter()
            .find(|(pk, _)| pk.as_slice() == recipient.as_slice())
        {
            return Ok(*label);
        }
        for epoch in [fc_epoch, fc_epoch.saturating_sub(1)] {
            let ctx = RecordContext {
                recipient_keyrec_addr,
                fc_epoch: epoch,
            };
            for label in self.persist.store().correspondences()? {
                // `peek_`, not `restart_channel`: this walks every correspondence
                // on disk asking whether it is the recipient's, so the cleaning
                // version would delete a lingering provisional record for every
                // one it passed that held a readable resume record — writing to
                // conversations this call named nothing about, and taking a lock
                // on each. It would not change which label is returned: the arm
                // below matches only `HandshakeResumes`, and a correspondence in
                // that state answers `Established`. Cleaning belongs to the
                // callers that know they are establishing, and to
                // `sweep_lingering_provisionals` at startup.
                if let daemonseed_core::dm::persist::StoredChannelRestart::HandshakeResumes(
                    pending,
                ) = self.persist.peek_channel_restart(&label, &ctx)
                {
                    // Dropped rather than established: this is a lookup, and
                    // establishing here would erase the record the write is
                    // about to replace.
                    drop(pending);
                    self.provisionals.push((Box::new(**recipient), label));
                    return Ok(label);
                }
            }
        }
        // **A correspondence already recorded for this identity is reused, and
        // this is the last thing standing between a re-sent entry and an
        // unroutable identity.** The peek above finds a label only while the
        // provisional record still opens, which is the two live first-contact
        // epochs; the contact record has no such window, so an entry re-sent
        // after that has passed still finds its label here. Minting instead
        // would put a second contact record under a second label for one
        // identity, and `correspondence_for_pk_lt` refuses to choose between
        // two — the identity would be unroutable for the life of the store.
        if let Some(label) = self.persist.correspondence_for_pk_lt(recipient)? {
            self.provisionals.push((Box::new(**recipient), label));
            return Ok(label);
        }
        let label = CorrespondenceLabel::mint()?;
        self.provisionals.push((Box::new(**recipient), label));
        Ok(label)
    }

    /// [`established_with`] over this machine's store.
    ///
    /// The free function is what the doorbell sweep reaches, because that path
    /// destructures `self` to borrow the seen and spent sets alongside it.
    fn established_with(
        &self,
        pk_lt: &[u8; IDENTITY_PK_LEN],
    ) -> Result<bool, daemonseed_core::dm::persist::DmPersistError> {
        established_with(&self.persist, pk_lt)
    }

    /// Whether this recipient already has an introduction between the command
    /// and the doorbell write.
    fn introduction_in_flight(&self, recipient: &[u8; IDENTITY_PK_LEN]) -> bool {
        self.outbound
            .iter()
            .any(|i| i.recipient.as_slice() == recipient.as_slice())
            || self
                .minting
                .iter()
                .any(|pk| pk.as_slice() == recipient.as_slice())
    }

    /// Store the bound a verified fetch established for one identity.
    ///
    /// Called only where a record verified, so an entry always means "a record
    /// for this identity has been verified in this process". A cache holds no
    /// identity binding of its own, so the entry and the pubkey every `accept`
    /// was checked against are keyed the same way.
    fn remember_key_record_bound(&mut self, of: &[u8; IDENTITY_PK_LEN], cache: KeyRecordCache) {
        match self
            .key_records
            .iter_mut()
            .find(|(pk, _)| pk.as_slice() == of.as_slice())
        {
            Some((_, held)) => *held = cache,
            None => self.key_records.push((Box::new(*of), cache)),
        }
    }

    /// Drop an in-flight introduction and tell the front end it did not
    /// proceed.
    ///
    /// `event` is the classed trust event where the refusal is a channel torn
    /// down, and `None` where it is not — see [`DmEvent::Refused`]'s field of
    /// that name for why the key travels on the event.
    fn refuse_introduction(
        &mut self,
        recipient: &PkLt,
        reason: RefusalReason,
        event: Option<TrustEventKey>,
    ) -> Vec<DmEffect> {
        let before = self.outbound.len() + self.minting.len();
        self.outbound
            .retain(|i| i.recipient.as_slice() != recipient.as_slice());
        self.minting
            .retain(|pk| pk.as_slice() != recipient.as_slice());
        // Nothing was in flight, so nothing is refused and `event` goes with
        // it. A teardown cannot be lost this way. It is raised from `on_mint`,
        // which runs for a recipient `on_key_record` pushed into `minting`, and
        // between that push and the teardown the only operation tagged with
        // this introduction is the doorbell publish `on_mint` itself asks for —
        // so no outcome naming this recipient can have arrived to drop it, and
        // `introduction_in_flight` refuses a second attempt for as long as it
        // sits there. The other removals, this function's own four lines above
        // included, all run on an introduction that is ending rather than one
        // still minting.
        if self.outbound.len() + self.minting.len() == before {
            return Vec::new();
        }
        vec![DmEffect::Emit(refused(recipient, reason, event))]
    }

    /// Ask for the spent-token set to be written back, where one is kept.
    ///
    /// **Refused outright once poisoned.** A store whose file would not open
    /// holds grants this driver never saw, and writing the in-memory set over
    /// it would spend them all again on the next start.
    fn save_spent(&mut self) -> Vec<DmEffect> {
        if self.spent.poisoned {
            return Vec::new();
        }
        let Some(store) = self.spent.store.as_ref() else {
            return Vec::new();
        };
        vec![DmEffect::Compute(ComputeJob::SaveSpentTokens(Box::new(
            SaveSpentRequest {
                store: store.clone(),
                set: self.spent.set.clone(),
            },
        )))]
    }
}

/// Erase this correspondence's provisional record, if it still holds one, and
/// forget the handle only once the record is actually gone.
///
/// **The take is conditional, and that is the whole of it.** The context is the
/// only handle to the record: it names the epoch the record was sealed under,
/// and a record opens under no other. Clearing it on a failed erase would leave
/// `{ss0, the opening ephemeral DK}` on disk with nothing left that could ever
/// address it again — a transient store fault turned into a permanent leak of
/// the secret that roots `RK0`.
///
/// So the handle is dropped on exactly two outcomes: the delete succeeded, or
/// the store says there is no record there
/// ([`TeardownCause::NoProvisionalRecord`]). Every other teardown cause is a
/// statement about the store or the ciphertext at this moment, not about
/// whether the record exists, so the handle is kept and the next call tries
/// again.
/// The direction the stored outbox was written for, or `None` when there is no
/// record and so nothing to drive.
///
/// Free rather than a method because the acknowledgement fold runs with the
/// machine destructured — it holds `&DmPersist` and one `&mut Correspondence`,
/// and cannot also hold `&self`.
fn stored_direction(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    now_ms: i64,
) -> Option<Direction> {
    match persist.read_outbox(label, now_ms) {
        Ok(Some(outbox)) => Some(outbox.direction()),
        Ok(None) => None,
        Err(e) => {
            crate::vtrace!("dm driver: the outbox would not read: {e}");
            None
        }
    }
}

/// Merge one verified peer acknowledgement into this correspondence's retained
/// own state, then settle the outbox against the union.
///
/// **The one fold, reached from both paths.** A piggybacked acknowledgement and
/// a fetched standalone record differ only in what authenticated them — this
/// frame's `msg_sig` or the record's own signature — and by the time either
/// reaches here it is a verified [`PeerAck`] and nothing else. Two folds would be
/// two places for the ceiling to be forgotten.
///
/// **The state is retained, not rebuilt.** A merge is a union: a later statement
/// may settle a run this side already holds and say nothing about an earlier one,
/// so a fresh state per fold would un-settle everything the previous one carried.
///
/// The ceiling is the highest sequence this side has actually transmitted. A peer
/// cannot have collected what was never sent, so a claim above it is clipped —
/// never refused, which would discard the truthful low half with the impossible
/// high half — and counted as the misbehaviour signal it is.
fn fold_peer_ack(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    now_ms: i64,
    peer: PeerAck,
) -> Vec<DmEffect> {
    // `next_send_seq` is the number the NEXT send would take, so the highest
    // actually spent is one below it; a chain that has sent nothing has no
    // ceiling at all, which clips a peer's whole claim away.
    //
    // **This is the highest SEALED, which can sit one above the highest
    // ENQUEUED.** `send` steps the ratchet and then asks the outbox, so a seal
    // whose enqueue was refused for room leaves the ceiling naming a sequence
    // that was never queued and will never be transmitted. Nothing observable
    // follows: a peer cannot settle an entry that does not exist, and the entry
    // that would occupy that sequence is exactly the one the refusal means will
    // never be written. It is one above the tightest ceiling available, and
    // tighter would mean reading the outbox on the fold path for no change in
    // any answer.
    let highest_sent = correspondence
        .ratchet
        .as_ref()
        .and_then(|ratchet| ratchet.next_send_seq().checked_sub(1));
    match correspondence.own_ack.merge_peer_ack(peer, highest_sent) {
        Ok(PeerAckOutcome::WithinCeiling) => {}
        Ok(PeerAckOutcome::ClippedToCeiling { .. }) => {
            correspondence.health.peer_acks_clipped += 1;
        }
        // All-or-nothing, so `own_ack` is untouched and nothing is lost: the
        // peer's statement is monotonic and re-written, so a later fold carries
        // everything this one would have.
        Err(e) => {
            crate::vtrace!("dm driver: a peer acknowledgement would not merge: {e}");
            correspondence.health.peer_acks_deferred += 1;
            return Vec::new();
        }
    }
    settle_from_own_ack(persist, correspondence, now_ms)
}

/// Release one borrow on a sending page, dropping the entry entirely at zero so the
/// map holds only pages a write is actually running against.
///
/// A free function rather than a method because both call sites reach it while the
/// machine is partly destructured. Saturating: an outcome for a page the map does not
/// hold is a double release, which costs nothing and must not underflow into a page
/// held for ever.
fn release_publish(
    publishing: &mut std::collections::BTreeMap<([u8; AR_FINGERPRINT_LEN], u64), usize>,
    conversation: [u8; AR_FINGERPRINT_LEN],
    page: u64,
) {
    if let std::collections::btree_map::Entry::Occupied(mut held) =
        publishing.entry((conversation, page))
    {
        let n = held.get_mut();
        *n = n.saturating_sub(1);
        if *n == 0 {
            held.remove();
        }
    }
}

/// Confirm every outbox entry the retained own state now settles, and report
/// each one to the front end.
///
/// [`Outbox::settle_from_ack`] moves an entry out of
/// [`Lifecycle::AwaitingCollection`](daemonseed_core::dm::outbox::Lifecycle) as
/// it confirms it and skips every entry past its give-up, so a sequence is
/// reported here exactly once and a message this sender abandoned can never be
/// confirmed by a late acknowledgement that walks over it.
///
/// The state is read back from the entry rather than named as a constant: the
/// entry is what the front end is being told about, and a hard-coded state would
/// keep reporting one after a future transition stopped producing it.
fn settle_from_own_ack(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    now_ms: i64,
) -> Vec<DmEffect> {
    let label = correspondence.label;
    let Some(direction) = stored_direction(persist, &label, now_ms) else {
        return Vec::new();
    };
    // Cloned because the closure needs the state while `update_outbox` holds the
    // record's own lock, and the borrow checker cannot see that the two are
    // disjoint.
    let ack = correspondence.own_ack.clone();
    let settled = persist.update_outbox(&label, direction, now_ms, |outbox| {
        let settled = outbox.settle_from_ack(&ack, now_ms);
        // **A settled re-establishment leg is not a delivery, and is filtered
        // out here rather than at the front end.** A leg rides the outbox at its
        // own sequence position, so a peer's acknowledgement settles it exactly
        // as it settles a message — but the user composed nothing at that
        // sequence, and reporting one would put a delivery for a message that
        // does not exist in front of them. Same argument
        // `Outbox::sweep_give_ups` makes for skipping legs, at the other end of
        // the entry's life.
        let states: Vec<(u64, DeliveryState)> = settled
            .iter()
            .filter_map(|&seq| outbox.entry(seq).map(|entry| (seq, entry)))
            .filter(|(_, entry)| !matches!(entry.target(), OutboxTarget::ReEstablishmentLeg))
            .map(|(seq, entry)| (seq, entry.delivery_state()))
            .collect();
        Ok(if settled.is_empty() {
            Mutation::Unchanged(states)
        } else {
            Mutation::Changed(states)
        })
    });
    let states = match settled {
        Ok(states) => states,
        Err(e) => {
            crate::vtrace!("dm driver: the acknowledgement would not settle: {e}");
            return Vec::new();
        }
    };
    states
        .into_iter()
        .map(|(seq, state)| {
            // Recorded as offered, on the same terms a give-up is: the entry's
            // durable surfacing stays owed until `DmCommand::Surfaced` answers
            // it, and this only stops the tick's own re-offer repeating what the
            // fast path has already said. A restart before the answer offers it
            // again, which is the #279 direction.
            correspondence.offered_this_session.push(seq);
            DmEffect::Emit(DmEvent::Delivery {
                to: Box::new(*correspondence.pk_lt),
                seq,
                state,
            })
        })
        .collect()
}

/// The acceptor's receiving collection, with the knock already settled.
///
/// **The knock arrived, and nothing else will ever say so.** The initiator queues
/// its first-contact entry at sequence zero of the sending direction and re-seeds
/// it until acknowledged — that is what makes a re-seed re-emit identical bytes —
/// but it was carried by doorbell, and no page in the receiving stream will ever
/// hold it. A collection that waits for a page therefore never settles position
/// zero: the contiguous prefix never starts, every acknowledgement this side
/// writes is a run set with a permanent hole under it, and the opening message of
/// every conversation is re-seeded to the seven-day give-up and then reported
/// undelivered for a message the user read and answered.
///
/// Settling it here is what the outbox note at the knock's enqueue means by *"the
/// knock shares the channel's sequence space so the contiguous prefix can confirm
/// the opening message"*.
///
/// A refusal is unreachable — the beyond-prefix set of a fresh collection has room
/// for one position by construction — and is traced rather than propagated so the
/// accept, which has already established the channel, is not undone by it.
///
/// **The resume path re-applies it**, in [`DmMachine::resume_channel`], because
/// `seed_from_store` rebuilds a correspondence with a fresh [`AckState`] and
/// would otherwise lose the settled knock position with the rest of the
/// collection. The acceptor is the side whose outbox sends `b2a`, which is what
/// that pass keys on; an initiator's own sequence zero is the acceptance, a real
/// page frame that must stay unsettled until it opens.
fn collection_accepting_a_knock() -> Collection {
    let mut collection = Collection::new();
    if let Err(e) = collection.collected(position_of(KNOCK_CHANNEL_SEQ)) {
        crate::vtrace!("dm driver: the knock's own position would not settle: {e}");
    }
    collection
}

/// Whether the store holds an ESTABLISHED correspondence with this identity.
///
/// [`DmPersist::correspondence_for_pk_lt`] answers for both an established
/// correspondence and one whose own first-contact entry is still unanswered,
/// because the second is what routes an acceptance back to the entry it
/// answers. Every caller here means the first: an unanswered entry of this
/// side's own must not make the correspondent a stranger — the admission gate
/// would then stop offering their knock, and a mutual knock, where each side
/// knocks before either answers, would leave both sides waiting for an
/// acceptance neither can send.
///
/// A record with no pseudonym is the unanswered case; see
/// [`ContactRecord::pk_pc`](daemonseed_core::dm::contact_cache::ContactRecord::pk_pc).
/// A record that vanishes between the two reads answers "not established",
/// which refuses nothing and leaves every write downstream to take the store's
/// own lock.
fn established_with(
    persist: &DmPersist,
    pk_lt: &[u8; IDENTITY_PK_LEN],
) -> Result<bool, daemonseed_core::dm::persist::DmPersistError> {
    let Some(label) = persist.correspondence_for_pk_lt(pk_lt)? else {
        return Ok(false);
    };
    Ok(persist
        .read_contact(&label)?
        .is_some_and(|contact| contact.pk_pc().is_some()))
}

fn erase_provisional(persist: &DmPersist, correspondence: &mut Correspondence) -> Erasure {
    let Some((keyrec_addr, fc_epoch)) = correspondence.provisional else {
        return Erasure::Absent;
    };
    let outcome = erase_record(persist, &correspondence.label, &keyrec_addr, fc_epoch);
    match outcome {
        // The record is gone either way, so the handle names a directory nothing
        // will look in again.
        Erasure::Deleted | Erasure::Absent => correspondence.provisional = None,
        // The record is still there and this context is the only thing that can
        // open it, so the handle is what the caller has to keep.
        Erasure::Retry => {}
    }
    outcome
}

/// When a queued leg's **first** emission is due.
///
/// **Two bands, because the design gives the two halves of the handshake
/// different reasons to wait.** They are not a tuning choice: one of them is a
/// metadata requirement and the other is an availability requirement, and
/// applying either to the other's leg breaks the property it was written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegDispatch {
    /// A wide randomized delay at reconnect-cadence scale
    /// (`docs/design/direct-messaging.md:1152`, A5.5).
    ///
    /// The `RE-EST` this side opens at load is *gated on the restart by
    /// construction* — an entry composed offline to a quiet peer can only
    /// first-dispatch after a boot — so k of them share one instant, and a
    /// minute-scale spread around it *"satisfies I6's letter and fails its
    /// purpose"*.
    ReconnectBand,
    /// The ordinary re-seed ladder's first rung.
    ///
    /// The answering and settling legs are not gated on a boot: they are
    /// composed when an exchange reaches them, at whatever moment that is, so
    /// there is no shared instant for a wide band to spread. A3.10 says so for
    /// the `RE-ACK` in terms — *"the ladder's first rung is the latency floor"*
    /// — and A8.4 makes it load-bearing rather than incidental, bounding the
    /// answering side's quiet window *"below the expected overlap so recovery is
    /// mechanical"*. A reconnect-band delay here would put hours between an
    /// opened `RE-EST` and its answer, which is the availability failure A8.4
    /// exists to refuse. A4.3 puts `RE-CONFIRM` on the same footing: *"composed
    /// and persisted immediately, and dispatched through the jittered funnel
    /// like every other leg, with no promptness requirement."*
    Ladder,
}

/// How many `RE-ACK`s one correspondence may compose in one session.
///
/// **A8.4's answer-side emission cap, and no more than that.** The design splits
/// two rates: *"the bound applies only to post-openability response emission"*,
/// while *"A3.13's unbounded backoff is retained on pre-authentication
/// open-attempt work"*. Only the real correspondent can produce an openable
/// `RE-EST`, so a low cap here bounds what the genuine peer can ask for and
/// nothing an attacker can drive — the trial-decryption work an unopenable frame
/// costs is bounded separately, by the scan window.
///
/// **What this is NOT, said plainly because the design names something larger.**
/// A3.13 specifies *participation backoff*: a growing delay on the K-th
/// completed re-establishment inside a sliding 24-hour window, decaying as the
/// window slides. Neither the delay nor the decay is built. This is a flat
/// count, held in memory and reset by a restart, that refuses past its ceiling
/// and says so once — the emission bound A8.4 asks for, and not the rate-shaping
/// A3.13 asks for.
///
/// Set at [`reest::ATTEMPT_CEILING`] because the two count the same exchanges
/// from opposite ends: a correspondent whose window admits `C` initiations
/// cannot legitimately ask for more than `C` answers in it.
const RESPONSE_EMISSION_CAP: u32 = reest::ATTEMPT_CEILING;

/// The most leg kinds one otherwise-unopenable slot is scanned against.
///
/// **This bounds the CANDIDATES, and each candidate bounds its own opens.**
/// [`reest::scan_re_est`] and its siblings walk an attempt window of at most
/// `MAX_GAP + 1` and refuse anything beyond it, which is their claim and is
/// tested where they are; this one is the count of times that walk is entered
/// for one slot. The product is the whole trial-decryption cost of a slot that
/// is not a leg. It is a bound the tests assert rather than a knob.
const LEG_SCAN_CANDIDATES: u64 = 4;

/// What one slot's trial decryption as a re-establishment leg came to.
///
/// **Three answers, because "a leg opened" and "the fold finished" are different
/// facts and the position depends on the second.** A slot the fold consumed is
/// settled; a slot whose fold stopped part way is not, because the frame still
/// has work to do and settling it would walk past the only copy of it. The
/// earlier two-state version conflated them, so a store fault mid-fold silently
/// discarded a peer initiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegOutcome {
    /// No leg kind this side expects opened these bytes. Still a channel frame
    /// that may open later, and counted unopenable exactly as before.
    NotALeg,
    /// A leg opened and the fold ran to its end. The position settles and
    /// whatever the fold recorded is on disk.
    Consumed,
    /// A leg opened and the fold could not finish — a store fault, a module
    /// fault, a counter that would not read. Nothing was committed, the position
    /// stays unsettled, and the peer's own re-seed brings the frame back.
    ///
    /// **Bounded by the peer's ladder, not by anything here.** The frame is
    /// re-presented until the peer's leg gives up (A3.8), which is the same
    /// clock every other unopened position runs on.
    Retry,
}

/// What a leg fold did, and what the front end is owed for it.
struct LegFold {
    outcome: LegOutcome,
    effects: Vec<DmEffect>,
}

impl LegFold {
    /// No leg here.
    fn not_a_leg() -> Self {
        Self {
            outcome: LegOutcome::NotALeg,
            effects: Vec::new(),
        }
    }

    /// A leg opened, the fold finished, and there is nothing to tell the user.
    fn consumed() -> Self {
        Self {
            outcome: LegOutcome::Consumed,
            effects: Vec::new(),
        }
    }

    /// A leg opened and the fold stopped part way.
    fn retry() -> Self {
        Self {
            outcome: LegOutcome::Retry,
            effects: Vec::new(),
        }
    }
}

/// One leg, opened and verified, with every borrow of the resume record already
/// released.
///
/// **Owned rather than borrowed, and that is what the enum is for.** Choosing
/// which leg kind to try reads the record — the slots, the roots, the window
/// bases — and acting on what opened writes it. Carrying the result out as owned
/// values ends the read before the write begins, so the two phases cannot be
/// interleaved by accident.
enum OpenedLeg {
    /// The answer to an initiation of ours (step 5).
    ReAck(reest::OpenedReAck),
    /// The settlement of an exchange we answered (step 6).
    ReConfirm(reest::OpenedReConfirm),
    /// A peer initiation this side must answer (step 4).
    ///
    /// **The root travels with it, because there are two it can arrive under.**
    /// A peer at rest seals under this side's committed root; a peer still
    /// pushing an exchange this side has already answered seals under the root
    /// that exchange started from, which by then is the *retained* one. The
    /// answer has to be sealed under whichever it was, or the initiator opens
    /// nothing.
    ReEst {
        /// The opened leg.
        opened: reest::OpenedReEst,
        /// The root it opened under, and the one its answer is sealed under.
        root: CommittedRoot,
    },
    /// A peer initiation at a generation this side has already committed,
    /// opened under the root it still retains (step 8, divergence row 14).
    Regressed {
        /// The committed generation the frame was sealed at.
        generation: u32,
        /// The attempt it re-presents.
        attempt: Attempt,
    },
}

/// Run one scan candidate, telling an ordinary miss apart from a fault.
///
/// **`.ok()` collapsed three different answers into one.** A leg that simply
/// did not open under this candidate's key is the ordinary case and says
/// nothing; a signature that did not verify is A3.8's anomaly — only a party
/// holding the committed root can produce one — and a module or derivation fault
/// is a sick crypto module. Silently trying the next candidate for all three
/// hides the two that matter behind the one that does not.
fn scanned<T>(result: Result<T, reest::ReEstError>, faults: &mut u64) -> Option<T> {
    match result {
        Ok(opened) => Some(opened),
        // The bytes are not this leg kind, or not a leg at all. The scan's own
        // uniform close-shape (ISC-A-S12) is deliberate and nothing is inferred
        // from it.
        Err(reest::ReEstError::DidNotOpen | reest::ReEstError::Truncated) => None,
        Err(e) => {
            *faults = faults.saturating_add(1);
            crate::vtrace!("dm driver: a leg scan candidate faulted: {e}");
            None
        }
    }
}

/// Try one otherwise-unopenable slot as the re-establishment leg (or legs) this
/// side's own state expects.
///
/// **Every discriminator comes from this side's record; nothing is announced on
/// the wire** (A3.9, `docs/design/direct-messaging.md:917`). A leg carries no
/// clear field naming its kind, its generation or its attempt: the reader
/// supplies the first two from what it is waiting for and the scan recovers the
/// third by trial decryption over a window of at most `MAX_GAP + 1` attempts
/// ascending from `last_seen` (A5.2).
///
/// **The candidate list, and why it is not always one.** A3.9 allows *"one
/// bounded AEAD attempt per otherwise-unopenable frame with the expected
/// generation's key, plus the contest key while a contest is live"*, and A3.5
/// says what retention buys: *"the ability to open the peer's frames at the
/// superseded generation"*. So:
///
/// 1. **`RE-ACK`, while our own initiation stands.** An occupied own slot means
///    we are waiting for exactly this.
/// 2. **`RE-CONFIRM`, while an acceptance of ours stands unconfirmed.** We
///    answered a peer initiation and the exchange settles when its third leg
///    arrives. Ahead of the `RE-EST` candidate because it is the more specific
///    state: A5.1(ii)'s lock is about this exchange, and a party holding an
///    unconfirmed candidate is waiting on its settlement rather than on a fresh
///    initiation.
/// 3. **`RE-EST` at one past our committed generation.** The at-rest case, and
///    A3.9's *"contest key"* when candidate 1 also applies — a party holding its
///    own initiation must still be able to open the peer's, or A3.7's coin never
///    fires and both sides wait for each other.
/// 4. **`RE-EST` at the generation an open exchange is at, under the retained
///    `RS_n`.** A3.5 retains the superseded root for exactly this. It is what
///    makes A3.4's idempotent re-serve and A5.1's supersede reachable at all —
///    this side's committed root moves at the answer while the peer keeps
///    sealing under the root the exchange started from — and, once the exchange
///    is over, it is how the divergence table's row 14 is reached.
///
/// [`LEG_SCAN_CANDIDATES`] is the count, and each costs at most `MAX_GAP + 1`
/// opens, so an unopenable slot costs a bounded constant however many arrive.
///
/// The record is read ONCE per swept page by the caller and threaded through
/// here: it is a sealed blob carrying a signing key, and opening it per slot
/// would pay that cost sixteen times for a page holding one leg.
// Nine parameters against clippy's threshold of seven. Grouping them behind a
// struct would name the same values twice — every one is a distinct input the
// scan or the fold reads, and the two counters are out-parameters the caller
// aggregates per page.
#[allow(clippy::too_many_arguments)]
fn fold_leg(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    record: &mut ResumeRecord,
    now_ms: i64,
    at: PagePosition,
    encoded: &[u8],
    peer_direction: Direction,
    scans: &mut u64,
    faults: &mut u64,
) -> LegFold {
    if encoded.len() != reest::LEG_LEN {
        return LegFold::not_a_leg();
    }
    let seq = at.seq();
    let peer_pk_pc = *record.pk_pc();
    let opened = {
        let dir = peer_direction;
        let mut found = None;
        if let Some(slot) = record.own_slot() {
            *scans += 1;
            found = scanned(
                reest::scan_re_ack(
                    record.committed_root(),
                    dir,
                    slot.generation(),
                    seq,
                    record.last_seen_re_ack(),
                    encoded,
                    &peer_pk_pc,
                ),
                faults,
            )
            .map(OpenedLeg::ReAck);
        }
        if found.is_none() {
            if let Some(acceptance) = record.acceptance().filter(|a| !a.confirmed()) {
                *scans += 1;
                found = scanned(
                    reest::scan_re_confirm(
                        record.committed_root(),
                        dir,
                        acceptance.generation(),
                        seq,
                        record.last_seen_re_est(),
                        encoded,
                        &peer_pk_pc,
                    ),
                    faults,
                )
                .map(OpenedLeg::ReConfirm);
            }
        }
        if found.is_none() {
            *scans += 1;
            found = scanned(
                reest::scan_re_est(
                    record.committed_root(),
                    dir,
                    record.reconnect_gen().saturating_add(1),
                    seq,
                    record.last_seen_re_est(),
                    encoded,
                    &peer_pk_pc,
                ),
                faults,
            )
            .map(|opened| OpenedLeg::ReEst {
                opened,
                root: record.committed_root().clone(),
            });
        }
        if found.is_none() {
            if let Some(retained) = record.retained() {
                // **Which generation the retained root is speaking at depends on
                // whether an exchange is open under it.** With an unconfirmed
                // acceptance standing, this side has committed a candidate and
                // its committed root has moved on — but the peer has not, and
                // goes on re-emitting and re-attempting under `RS_n` at the
                // exchange's own generation. With no acceptance standing, the
                // exchange is over and a frame under `RS_n` is row 14.
                let generation = record
                    .acceptance()
                    .map_or_else(|| record.reconnect_gen(), AcceptanceSlot::generation);
                let root = retained.root().clone();
                *scans += 1;
                found = scanned(
                    reest::scan_re_est(
                        &root,
                        dir,
                        generation,
                        seq,
                        record.last_seen_re_est(),
                        encoded,
                        &peer_pk_pc,
                    ),
                    faults,
                )
                .map(|opened| {
                    if generation > record.reconnect_gen() {
                        OpenedLeg::ReEst { opened, root }
                    } else {
                        OpenedLeg::Regressed {
                            generation,
                            attempt: opened.attempt(),
                        }
                    }
                });
            }
        }
        found
    };
    let Some(opened) = opened else {
        return LegFold::not_a_leg();
    };
    match opened {
        OpenedLeg::ReAck(opened) => fold_re_ack(
            persist,
            correspondence,
            record,
            now_ms,
            seq,
            peer_direction,
            opened,
        ),
        OpenedLeg::ReConfirm(opened) => fold_re_confirm(
            persist,
            correspondence,
            record,
            now_ms,
            seq,
            peer_direction,
            opened,
        ),
        OpenedLeg::ReEst { opened, root } => fold_re_est(
            persist,
            correspondence,
            record,
            now_ms,
            seq,
            peer_direction,
            opened,
            &root,
        ),
        OpenedLeg::Regressed {
            generation,
            attempt,
        } => fold_regressed(
            persist,
            correspondence,
            record,
            generation,
            attempt,
            seq,
            peer_direction,
        ),
    }
}

/// The two counters a re-establishment reads off the outbox: the highest clear
/// ratchet generation this side has persisted, and the sequence its next write
/// takes.
///
/// **Read together, under one lock, because the pair is what the re-rooted
/// ratchet is opened on.** Read apart they can straddle another write, and a
/// generation paired with a sequence from a different moment opens a chain at a
/// position the outbox has already spent.
fn outbox_counters(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    direction: Direction,
    now_ms: i64,
) -> Option<(u32, u64)> {
    match persist.update_outbox(label, direction, now_ms, |outbox| {
        Ok(Mutation::Unchanged((
            outbox.last_clear_gen(),
            outbox.next_send_seq(),
        )))
    }) {
        Ok(counters) => Some(counters),
        Err(e) => {
            crate::vtrace!("dm driver: the outbox counters would not read: {e}");
            None
        }
    }
}

/// End every re-establishment leg still queued on this direction, and run the
/// dead-chain sweep.
///
/// **Called at a completion, on both sides, and it is one of a leg's two
/// terminal edges.** Both outbox sweeps skip legs, so an exchange that finished
/// would otherwise leave its `RE-EST` and `RE-ACK` re-seeding on the ladder for
/// the life of the record — writes for a handshake nobody is waiting on.
/// [`Outbox::retire_leg`] is the right edge here and not
/// [`Outbox::abandon_leg`]: the completion is proof the correspondent opened
/// these legs.
///
/// **The settling leg is enqueued after this call, never before.** A
/// `RE-CONFIRM` composed at the same completion is the one leg that still has
/// work to do; retiring it in the same pass would end the exchange from the
/// peer's point of view before the frame that tells the peer so had been sent.
///
/// **The dead-chain sweep rides the same lock, and it is not a second job.**
/// A3.12 makes the sweep *"a derivation, not a transaction"*: entries sealed
/// under a chain older than the committed re-root generation can never be
/// opened, so they end Undelivered, and the condition is decidable from two
/// persisted facts. Running it here is running it at the moment the second fact
/// changed; `resume_channel` runs the identical derivation at every load, which
/// is what makes a crash between the resume-record commit and this one heal
/// itself rather than needing a transaction. The entries it ends carry
/// `Surfacing::Owed`, so what the user is told is the next tick's `give_ups`
/// re-offer rather than anything returned from here.
fn retire_finished_legs(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    direction: Direction,
    now_ms: i64,
    reroot_ratchet_gen: u32,
) {
    let retired = persist.update_outbox(label, direction, now_ms, |outbox| {
        let ended_chain = outbox.sweep_dead_chain(reroot_ratchet_gen);
        let legs: Vec<u64> = outbox
            .iter()
            .filter(|entry| {
                matches!(entry.target(), OutboxTarget::ReEstablishmentLeg)
                    && entry.lifecycle().is_pending()
            })
            .map(OutboxEntry::seq)
            .collect();
        let mut ended = 0usize;
        for seq in legs {
            if outbox.retire_leg(seq) {
                ended += 1;
            }
        }
        Ok(if ended == 0 && ended_chain.is_empty() {
            Mutation::Unchanged(ended)
        } else {
            Mutation::Changed(ended)
        })
    });
    if let Err(e) = retired {
        // The legs stay queued and keep re-seeding, which costs writes and loses
        // nothing: the exchange is already committed, and the next completion or
        // the next load offers them again.
        crate::vtrace!("dm driver: the finished legs would not retire: {e}");
    }
}

/// Whether a leg at `seq` has a record address on this side's plane.
///
/// Asked before [`OutboxEntry::emit`] spends a rung, and asked with the same
/// derivation the publish below performs — the derivation is pure, so the two
/// cannot disagree, and the alternative was carrying an address out of a closure
/// that holds the record's lock.
fn leg_addressable(address_root: &[u8; ADDRESS_ROOT_LEN], direction: Direction, seq: u64) -> bool {
    match DmPageAddress::sending_on(address_root, direction, position_of(seq)) {
        Ok(_) => true,
        Err(e) => {
            crate::vtrace!("dm driver: a queued leg has no derivable address: {e}");
            false
        }
    }
}

/// Which end of the conversation a party sending on `direction` is.
///
/// The ratchet's own mapping run backwards, for the one caller that holds a
/// direction and no key schedule: `AToB` is the party that knocked.
fn role_for(send_direction: Direction) -> Role {
    match send_direction {
        Direction::AToB => Role::Initiator,
        Direction::BToA => Role::Recipient,
    }
}

/// Persist a record whose dedup memory a fold has just written to.
///
/// **Only a DISPOSITIONED path calls this**, and the distinction is A5.3's.
/// Recording a frame as processed is the statement *this side has decided what
/// this frame means* — dropped, locked, conceded to the coin. A fold that
/// stopped on a store fault or a module fault decided nothing, and committing
/// the key there would make the peer's re-seed inert while this side never
/// answered it: the exchange would stall in silence, which A3.15 does not admit.
/// Those paths return [`LegOutcome::Retry`] and write nothing.
///
/// `false` where the commit was refused, so the caller can leave the position
/// unsettled rather than settling one whose memory did not land.
fn commit_after_dedup(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    record: &ResumeRecord,
) -> bool {
    match persist.commit_resume(label, record) {
        Ok(_) => true,
        Err(e) => {
            crate::vtrace!("dm driver: the processed-frame memory would not commit: {e}");
            false
        }
    }
}

/// Queue a leg's stored bytes at the position they were sealed for, if the
/// outbox does not already hold that position.
///
/// The re-emit half of A9.1(a), shared by every stored leg: the own slot's
/// `RE-EST`, the acceptance slot's `RE-ACK` and the confirm slot's
/// `RE-CONFIRM`. `true` where the entry is there afterwards, whether this call
/// put it there or found it.
fn requeue_leg(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    direction: Direction,
    now_ms: i64,
    seq: u64,
    bytes: &[u8],
    dispatch: LegDispatch,
) -> bool {
    let queued = persist.update_outbox(label, direction, now_ms, |outbox| {
        if outbox.entry(seq).is_some() {
            return Ok(Mutation::Unchanged(true));
        }
        // The sequence was spent and its entry pruned. The bytes are bound to
        // that position and cannot move to another, so there is no re-emit.
        if outbox.next_send_seq() > seq {
            return Ok(Mutation::Unchanged(false));
        }
        let entry = outbox.enqueue_sealed(
            seq,
            OutboxTarget::ReEstablishmentLeg,
            now_ms,
            SealedFrame::new(bytes.to_vec()),
            0,
        )?;
        if matches!(dispatch, LegDispatch::ReconnectBand) {
            entry.defer_first_dispatch(now_ms)?;
        }
        Ok(Mutation::Changed(true))
    });
    match queued {
        Ok(queued) => queued,
        Err(e) => {
            crate::vtrace!("dm driver: a stored leg would not re-queue: {e}");
            false
        }
    }
}

/// Step 4 and step 7: a peer `RE-EST` opened at a generation this side answers.
///
/// The order is the design's and is fixed
/// (`docs/design/direct-messaging.md:893`, A5.3, A3.7, A9.4(ii), A3.14):
/// `note_processed` → the contest → `ReEstGate::admit` with the response-emission
/// budget → the answer → **commit** → enqueue. Nothing is emitted here; the
/// enqueue puts the `RE-ACK` on this side's own ladder, which is what A4.2 means
/// by *"reading updates local state and emits nothing in the same turn"*.
#[allow(clippy::too_many_arguments)]
fn fold_re_est(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    record: &mut ResumeRecord,
    now_ms: i64,
    seq: u64,
    peer_direction: Direction,
    opened: reest::OpenedReEst,
    root: &CommittedRoot,
) -> LegFold {
    let label = correspondence.label;
    let our_direction = peer_direction.opposite();
    let generation = opened.generation();
    let attempt = opened.attempt();
    let key = DedupKey::new(generation, attempt, Leg::ReEst, peer_direction, seq);
    let novelty = match record.note_processed(key) {
        Ok(novelty) => novelty,
        Err(e) => {
            crate::vtrace!("dm driver: a peer initiation would not be recorded as seen: {e}");
            return LegFold::retry();
        }
    };
    if novelty == Novelty::Repeat {
        // **A3.4: an accepted generation is inert, and the re-serve is the
        // stored bytes on their own ladder.** Normally that ladder already holds
        // them and this read causes nothing, which is A4.2. What it must not do
        // is answer *quiet* while the answer is not queued at all: a crash
        // between the commit that accepted the initiation and the enqueue leaves
        // the only copy of the `RE-ACK` in the slot, and the peer's re-seed is
        // the one thing that will ever ask for it again.
        if let Some(slot) = record
            .acceptance()
            .filter(|slot| slot.generation() == generation && slot.attempt() == attempt)
        {
            let (slot_seq, bytes) = (slot.seq(), slot.sealed_re_ack().to_vec());
            requeue_leg(
                persist,
                &label,
                our_direction,
                now_ms,
                slot_seq,
                &bytes,
                LegDispatch::Ladder,
            );
        }
        return LegFold::consumed();
    }
    let contest = match reest::contest_outcome(
        root,
        generation,
        our_direction,
        record.own_slot().map(OwnSlot::generation),
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            crate::vtrace!("dm driver: the tiebreak coin would not expand: {e}");
            return LegFold::retry();
        }
    };
    if contest == ContestOutcome::WeSurvive {
        // A3.7: the coin's winner does nothing with the loser's frame and keeps
        // waiting for the answer to its own. That is a disposition, so the
        // memory of having seen it is owed to disk.
        if !commit_after_dedup(persist, &label, record) {
            return LegFold::retry();
        }
        return LegFold::consumed();
    }
    let answered = correspondence.re_acks_answered;
    let mut charged = false;
    let mut gate = ReEstGate::from_record(record);
    let admission = gate.admit(generation, attempt, || {
        if answered >= RESPONSE_EMISSION_CAP {
            return false;
        }
        charged = true;
        true
    });
    if admission == ReEstAdmission::Withheld {
        // **Neither deduped nor settled**, because the admission's own contract
        // says *"nothing was accepted, so the same attempt may be admitted
        // later"*. Recording the key would make the very attempt the cap
        // deferred inert when the cap frees, and settling the position would
        // walk past the frame that carries it.
        let mut effects = Vec::new();
        if !correspondence.response_cap_surfaced {
            correspondence.response_cap_surfaced = true;
            effects.push(DmEffect::Emit(DmEvent::ReestablishmentAnomaly {
                with: Box::new(*correspondence.pk_lt),
                event: TrustEventKey::DmReestablishmentBackoffEngaged,
            }));
        }
        return LegFold {
            outcome: LegOutcome::Retry,
            effects,
        };
    }
    if admission != ReEstAdmission::Emit {
        // Dropped, Locked and ReServe are dispositions: this side has decided
        // what the frame means and will decide the same way next time.
        crate::vtrace!("dm driver: a peer initiation was not admitted: {admission:?}");
        if !commit_after_dedup(persist, &label, record) {
            return LegFold::retry();
        }
        return LegFold::consumed();
    }
    let Some((_, our_seq)) = outbox_counters(persist, &label, our_direction, now_ms) else {
        return LegFold::retry();
    };
    let eph_ek = *opened.eph_ek();
    let authority = opened.answer();
    let (rerooted, eph_ct) = match reest::answer(root, &eph_ek) {
        Ok(pair) => pair,
        Err(e) => {
            crate::vtrace!("dm driver: the re-establishment answer would not encapsulate: {e}");
            return LegFold::retry();
        }
    };
    // **Sealed under the root the initiation opened under, which the scan
    // carried here.** For a first answer that is this side's committed root, and
    // the candidate committed below replaces it; for a supersede it is the
    // retained `RS_n`, because the peer never saw the candidate and is still
    // sealing under the root the exchange started from.
    let re_ack = match reest::seal_re_ack(
        root,
        our_direction,
        our_seq,
        authority,
        &eph_ct,
        record.s_pc(),
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            crate::vtrace!("dm driver: the RE-ACK would not seal: {e}");
            return LegFold::retry();
        }
    };
    let slot = match AcceptanceSlot::accept(
        generation,
        attempt,
        our_seq,
        re_ack.clone().into_boxed_slice(),
    ) {
        Ok(slot) => slot,
        Err(e) => {
            crate::vtrace!("dm driver: the acceptance slot would not take the answer: {e}");
            return LegFold::retry();
        }
    };
    let abandon_own = contest == ContestOutcome::WeAbandon;
    // **Read before the slot is emptied, and abandoned after the commit.** A3.7's
    // loser *"abandons its own handshake"*, and the handshake is not only the
    // slot: the leg it published is an outbox entry with its own ladder, which
    // would go on re-seeding an initiation this side has just conceded. The
    // coin's outcome is what ends it, because nothing else can — the give-up
    // sweep skips legs.
    let abandoned = abandon_own
        .then(|| record.own_slot().map(OwnSlot::seq))
        .flatten();
    drop(record.accept_peer_initiation(rerooted.clone(), slot, abandon_own, now_ms));
    if let Err(e) = persist.commit_resume(&label, record) {
        // Nothing is on the wire and nothing is queued, so the peer's ladder
        // re-presents the same initiation and the next sweep answers it.
        crate::vtrace!("dm driver: the answered initiation would not commit: {e}");
        return LegFold::retry();
    }
    if charged {
        correspondence.re_acks_answered = answered.saturating_add(1);
    }
    if let Some(seq) = abandoned {
        let ended = persist.update_outbox(&label, our_direction, now_ms, |outbox| {
            let ended = outbox.abandon_leg(seq);
            Ok(if ended {
                Mutation::Changed(ended)
            } else {
                Mutation::Unchanged(ended)
            })
        });
        if let Err(e) = ended {
            crate::vtrace!("dm driver: the conceded initiation's leg would not end: {e}");
        }
    }
    // **Held for the settlement, and only in memory.** The record at rest
    // carries the candidate root; the ratchet root and the resumed channel's
    // identifier are what A5.4 keeps out of every at-rest encoding, so the
    // exchange has to reach its `RE-CONFIRM` inside one session for the channel
    // to come back speakable.
    correspondence.candidate = Some(rerooted);
    requeue_leg(
        persist,
        &label,
        our_direction,
        now_ms,
        our_seq,
        &re_ack,
        LegDispatch::Ladder,
    );
    LegFold::consumed()
}

/// Step 5: the answer to an initiation of ours opened.
///
/// A5.1(iii) first — an answer below our current attempt names a superseded
/// exchange and is discarded, *"otherwise a late `RE-ACK` from a superseded
/// attempt would let the initiator lock a root the responder has already
/// discarded"*. Then the completion, in an order the two crash windows decide:
/// the settling `RE-CONFIRM` is **sealed before the commit and persisted by
/// it**, so a seal that fails leaves the record and the ratchet exactly as they
/// were and the exchange is still drivable, and a crash after the commit
/// re-emits stored bytes rather than needing bytes nobody can rebuild (A9.1(a)).
/// The ratchet is installed last, after the leg is on disk.
fn fold_re_ack(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    record: &mut ResumeRecord,
    now_ms: i64,
    seq: u64,
    peer_direction: Direction,
    opened: reest::OpenedReAck,
) -> LegFold {
    let label = correspondence.label;
    let our_direction = peer_direction.opposite();
    let generation = opened.generation();
    let attempt = opened.attempt();
    let key = DedupKey::new(generation, attempt, Leg::ReAck, peer_direction, seq);
    match record.note_processed(key) {
        Ok(Novelty::Novel) => {}
        Ok(Novelty::Repeat) => return LegFold::consumed(),
        Err(e) => {
            crate::vtrace!("dm driver: an answer would not be recorded as seen: {e}");
            return LegFold::retry();
        }
    }
    let current = record.attempt().map_or(0, Attempt::get);
    if attempt.get() < current {
        crate::vtrace!(
            "dm driver: an answer at attempt {} is below the current {current}",
            attempt.get()
        );
        if !commit_after_dedup(persist, &label, record) {
            return LegFold::retry();
        }
        return LegFold::consumed();
    }
    let Some((last_clear_gen, our_seq)) = outbox_counters(persist, &label, our_direction, now_ms)
    else {
        return LegFold::retry();
    };
    let Some(slot) = record.take_own_slot() else {
        crate::vtrace!("dm driver: an answer arrived with no initiation to complete");
        if !commit_after_dedup(persist, &label, record) {
            return LegFold::retry();
        }
        return LegFold::consumed();
    };
    let rerooted =
        match reest::complete(record.committed_root(), slot.into_eph_dk(), opened.eph_ct()) {
            Ok(rerooted) => rerooted,
            Err(e) => {
                crate::vtrace!("dm driver: the answer would not decapsulate: {e}");
                return LegFold::retry();
            }
        };
    // **Ahead of the highest generation either record remembers.** The outbox
    // carries the clear counter for frames it has sealed and the resume record
    // carries the one a previous re-establishment opened at; a channel that has
    // re-established without sending anything since has the second and not the
    // first, so the floor is the larger of the two. A repeated generation would
    // put two different roots on one number and rewrite a write-once page slot
    // (A3.9, `docs/design/direct-messaging.md:917`).
    let floor_gen = last_clear_gen.max(record.reroot_ratchet_gen());
    let ratchet_gen = floor_gen.saturating_add(1);
    let settled_generation = record.reconnect_gen().saturating_add(1);
    // **Sealed BEFORE the commit, and under values the commit has not applied
    // yet**: the successor root the commit is about to install, and the
    // generation it is about to reach. A seal that fails here has changed
    // nothing — the record still holds the initiation, the ratchet is still
    // absent, and the peer's `RE-ACK` re-seeds into a later sweep that completes
    // the exchange.
    let confirm_bytes = match reest::seal_re_confirm(
        rerooted.next(),
        our_direction,
        settled_generation,
        our_seq,
        attempt,
        record.s_pc(),
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            crate::vtrace!("dm driver: the RE-CONFIRM would not seal: {e}");
            return LegFold::retry();
        }
    };
    let confirm = match ConfirmSlot::new(
        settled_generation,
        our_seq,
        confirm_bytes.clone().into_boxed_slice(),
    ) {
        Ok(slot) => slot,
        Err(e) => {
            crate::vtrace!("dm driver: the settling leg would not bind to its position: {e}");
            return LegFold::retry();
        }
    };
    // A8.2's window rollover: the peer has opened one of our attempts, which is
    // the one observation that moves the anchor.
    let rolled = AttemptBudget::from_record(record).observe_peer_opened(attempt);
    record.set_window_anchor(rolled.anchor());
    let chan_id = record.commit_reestablished(rerooted.clone(), ratchet_gen, now_ms, confirm);
    if let Err(e) = persist.commit_resume(&label, record) {
        // The wire has seen nothing and the record on disk is unchanged, so the
        // peer's `RE-ACK` re-seeds and a later sweep completes the exchange from
        // the slot the next load reads back.
        crate::vtrace!("dm driver: the completed re-establishment would not commit: {e}");
        return LegFold::retry();
    }
    // Before the settling leg is queued, never after: the `RE-CONFIRM` is the
    // one leg of this exchange that still has work to do.
    retire_finished_legs(persist, &label, our_direction, now_ms, ratchet_gen);
    requeue_leg(
        persist,
        &label,
        our_direction,
        now_ms,
        our_seq,
        &confirm_bytes,
        LegDispatch::Ladder,
    );
    // **The chain opens one past the settling leg's own position.** A
    // `RE-CONFIRM` rides the outbox at its own sequence, so the first content
    // frame of the resumed channel takes the next one.
    let ratchet = match Ratchet::reestablished(
        &rerooted,
        role_for(our_direction),
        ReconnectSide::Initiated {
            last_persisted_generation: floor_gen,
        },
        ratchet_gen,
        our_seq.saturating_add(1),
        &correspondence.address_root,
    ) {
        Ok(ratchet) => ratchet,
        Err(e) => {
            crate::vtrace!("dm driver: the resumed ratchet would not open: {e}");
            return LegFold::consumed();
        }
    };
    correspondence.ratchet = Some(ratchet);
    correspondence.channel = Some(ChannelRoots { chan_id: *chan_id });
    correspondence.candidate = None;
    LegFold::consumed()
}

/// Step 6: the settlement of an exchange this side answered.
///
/// A3.6's confirming observation on the answering side, and A3.5's retirement
/// fires with it: the candidate is confirmed, `reconnect_gen` advances, `RS_n`
/// and the memory scoped to it go together, and both handshake slots empty — one
/// act, one write.
fn fold_re_confirm(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    record: &mut ResumeRecord,
    now_ms: i64,
    seq: u64,
    peer_direction: Direction,
    opened: reest::OpenedReConfirm,
) -> LegFold {
    let label = correspondence.label;
    let our_direction = peer_direction.opposite();
    let generation = opened.generation();
    let attempt = opened.attempt();
    let key = DedupKey::new(generation, attempt, Leg::ReConfirm, peer_direction, seq);
    match record.note_processed(key) {
        Ok(Novelty::Novel) => {}
        Ok(Novelty::Repeat) => return LegFold::consumed(),
        Err(e) => {
            crate::vtrace!("dm driver: a settlement would not be recorded as seen: {e}");
            return LegFold::retry();
        }
    }
    let settles = record
        .acceptance()
        .is_some_and(|slot| slot.generation() == generation && slot.attempt() == attempt);
    if !settles {
        crate::vtrace!("dm driver: a settlement named an exchange this side is not holding");
        if !commit_after_dedup(persist, &label, record) {
            return LegFold::retry();
        }
        return LegFold::consumed();
    }
    let Some((last_clear_gen, our_seq)) = outbox_counters(persist, &label, our_direction, now_ms)
    else {
        return LegFold::retry();
    };
    let floor_gen = last_clear_gen.max(record.reroot_ratchet_gen());
    let ratchet_gen = floor_gen.saturating_add(1);
    if !record.confirm_acceptance(ratchet_gen) {
        if !commit_after_dedup(persist, &label, record) {
            return LegFold::retry();
        }
        return LegFold::consumed();
    }
    if let Err(e) = persist.commit_resume(&label, record) {
        crate::vtrace!("dm driver: the settled re-establishment would not commit: {e}");
        return LegFold::retry();
    }
    retire_finished_legs(persist, &label, our_direction, now_ms, ratchet_gen);
    // **Without the candidate the record is correct and the channel is not
    // speakable.** A restart between answering and settling loses the ratchet
    // root and the resumed channel's identifier, which A5.4 keeps out of every
    // at-rest encoding; the generation advanced and the retained root retired
    // regardless. The pass is left owed so the next tick opens a fresh attempt,
    // rather than the correspondence sitting addressable and mute until a
    // restart.
    let Some(candidate) = correspondence.candidate.take() else {
        crate::vtrace!(
            "dm driver: an exchange settled with no candidate in memory, so a fresh \
             attempt is owed"
        );
        correspondence.resume_owed = true;
        correspondence.resume_retry_due_ms = None;
        return LegFold::consumed();
    };
    let ratchet = match Ratchet::reestablished(
        &candidate,
        role_for(our_direction),
        ReconnectSide::Answered {
            last_persisted_generation: floor_gen,
            // The settling leg rode the peer's outbox at this position, so the
            // first content frame of the resumed chain takes the next one.
            peer_next_send_seq: seq.saturating_add(1),
            // **What the peer's first frame under the re-rooted chain offers.**
            // A leg carries no clear ratchet header, so nothing has offered a
            // generation yet and this side passes its own; the offer arrives
            // with the first content frame, which is unbuilt. The adoption rule
            // lives in `Ratchet::reestablished` so the value has one meaning
            // whichever side supplies it.
            offered_generation: ratchet_gen,
        },
        ratchet_gen,
        our_seq,
        &correspondence.address_root,
    ) {
        Ok(ratchet) => ratchet,
        Err(e) => {
            crate::vtrace!("dm driver: the resumed ratchet would not open: {e}");
            return LegFold::consumed();
        }
    };
    correspondence.ratchet = Some(ratchet);
    correspondence.channel = Some(ChannelRoots {
        chan_id: *candidate.chan_id(),
    });
    LegFold::consumed()
}

/// Step 8, the divergence table's row 14: a peer initiation at a generation this
/// side has already committed, opened under the root it still retains.
///
/// **Deduped, and loud once.** The exchange is settled here, so there is nothing
/// to answer and nothing to supersede: the acceptance slot the frame names was
/// zeroed by the completion. A3.8 classes *peer state regressed*
/// `PersistentNonBlocking` and A3.15 admits no silent row, so the state is
/// reported — but only on a **novel** frame. A5.3's memory is durable precisely
/// so a co-host re-serving captured bytes cannot re-fire the alarm; surfacing
/// before consulting it would hand that oracle straight back.
fn fold_regressed(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    record: &mut ResumeRecord,
    generation: u32,
    attempt: Attempt,
    seq: u64,
    peer_direction: Direction,
) -> LegFold {
    let label = correspondence.label;
    let key = DedupKey::new(generation, attempt, Leg::ReEst, peer_direction, seq);
    match record.note_processed(key) {
        Ok(Novelty::Novel) => {}
        // Already seen at this position, so the frame is inert and says nothing
        // new about the peer.
        Ok(Novelty::Repeat) => return LegFold::consumed(),
        Err(e) => {
            crate::vtrace!("dm driver: a regressed initiation would not be recorded as seen: {e}");
            return LegFold::retry();
        }
    }
    if !commit_after_dedup(persist, &label, record) {
        return LegFold::retry();
    }
    if correspondence.peer_regression_surfaced {
        return LegFold::consumed();
    }
    correspondence.peer_regression_surfaced = true;
    LegFold {
        outcome: LegOutcome::Consumed,
        effects: vec![DmEffect::Emit(DmEvent::ReestablishmentAnomaly {
            with: Box::new(*correspondence.pk_lt),
            event: TrustEventKey::DmPeerStateRegressed,
        })],
    }
}

/// Where the resume record's stored attempt stands against the outbox.
///
/// **Three states, because the middle one is not recoverable and the other two
/// are.** The leg's sequence is bound into its seal key and its signature, so
/// the bytes can only go back to the position they were sealed for — and once
/// that position has been spent and pruned, no re-emit exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegState {
    /// The outbox holds an entry at the stored sequence. Nothing is owed.
    Queued,
    /// The sequence has been spent and its entry pruned, so the stored bytes
    /// have no address left. The attempt cannot be re-emitted or replaced.
    Stale,
    /// The sequence is unspent: the crash the slot survived happened between the
    /// commit and the enqueue, and the stored bytes go back where they belong.
    Missing,
}

/// What one load-time pass learned from the outbox, under the store's lock.
#[derive(Debug)]
enum ResumeSurvey {
    /// The outbox stands behind the resume record's durable send floor, so the
    /// record family has been rolled back and no derivation from it is safe.
    FloorRegressed {
        floor: SendFloor,
        position: SendFloor,
    },
    /// What the pass needs to decide: whether unsealed mail is waiting, where an
    /// attempt would be addressed, and where the stored one stands.
    Surveyed {
        unsealed_pending: bool,
        next_seq: u64,
        leg: Option<LegState>,
    },
}

/// Tell the user one correspondence cannot be resumed, and name what it owes.
///
/// **One event for three arrivals at one state**, because the user's remedy is
/// the same in all three and the taxonomy already has the words for it.
/// [`TeardownCause::NoProvisionalRecord`] renders as *"this conversation cannot
/// be resumed, because nothing was kept that could carry it on; messages already
/// sent keep trying to arrive, and a new conversation has to be started"*, and
/// its key [`TrustEventKey::DmChannelTornDownOnRestart`] is
/// `PersistentNonBlocking`, which ISC-A-C12 forbids suppressing. Every clause is
/// true of a correspondence whose `S_pc` did not survive, of one whose handshake
/// record is gone before `RS_0` could be derived, and of one whose only speakable
/// attempt sits at a sequence the outbox has moved past.
///
/// `surfaced` carries what the user is owed rather than an empty list: these are
/// messages they believed were on their way, and this event is the only place
/// their fate is stated. A store that will not answer contributes none, which
/// understates and never overstates.
fn cannot_resume(correspondence: &Correspondence, surfaced: Vec<u64>) -> Vec<DmEffect> {
    vec![DmEffect::Emit(DmEvent::ChannelLost {
        with: Box::new(*correspondence.pk_lt),
        cause: TeardownCause::NoProvisionalRecord,
        event: TrustEventKey::DmChannelTornDownOnRestart,
        surfaced,
    })]
}

/// The sequence numbers one correspondence still owes its user, read from the
/// stored outbox.
///
/// An empty list on a store that will not answer, which understates the loss and
/// never overstates it — the direction § D-DELIV picks everywhere else here.
fn pending_seqs(persist: &DmPersist, label: &CorrespondenceLabel, now_ms: i64) -> Vec<u64> {
    match persist.read_outbox(label, now_ms) {
        Ok(Some(outbox)) => outbox
            .iter()
            .filter(|entry| entry.lifecycle().is_pending())
            .map(OutboxEntry::seq)
            .collect(),
        Ok(None) => Vec::new(),
        Err(e) => {
            crate::vtrace!("dm driver: the outbox would not read for what it owes: {e}");
            Vec::new()
        }
    }
}

/// What one initiator-side establishment did to the disk.
///
/// **Three answers rather than a bool, because two of the failures have opposite
/// remedies.** A store that could not be read this tick is a correspondence to
/// try again; a handshake record that is gone, or a pseudonym key that did not
/// survive the restart before the acceptance, is one that can never speak a
/// re-establishment leg and whose user has to be told so. A single `false`
/// collapsed those into "keep the handle", which retries the second for the life
/// of the session and reports nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Establishment {
    /// The resume record is on disk and the handshake record is gone.
    Complete,
    /// A transient store answer. The handle is kept and the tick tries again.
    Retry,
    /// This correspondence can never re-establish. Either its handshake record
    /// is gone, so `RS_0` — an Expand sibling of an `ss0` establishment destroys
    /// — cannot be derived; or this side's per-correspondent signing key did not
    /// survive the restart that preceded the acceptance, and `S_pc` is neither
    /// mnemonic-derivable nor recoverable from the shared secret
    /// (`docs/design/direct-messaging.md:1056`). Recovery is a fresh first
    /// contact, and the caller owes the user that in words.
    Unrecoverable,
}

/// The initiator's establishment: write the resume record a reconnect needs,
/// then erase the handshake record it supersedes.
///
/// **This is [`erase_provisional`] plus the write A4.8 puts ahead of the
/// erasure** (`docs/design/direct-messaging.md:1056`), and the two sites are
/// separate because only one of them is an establishment. `erase_provisional`
/// also runs where this side's own knock is *abandoned* — a mutual knock, where
/// accepting the correspondent's entry establishes the conversation under a
/// different label — and a resume record written there would describe a channel
/// nothing speaks on.
///
/// **A lost pseudonym key ends the correspondence, loudly.** `S_pc` is minted
/// from the CSPRNG when the entry is sent and its only at-rest home is the
/// record written here, so an initiator whose process ended before the
/// acceptance arrived comes back without it and can never sign a leg. The
/// handshake record is still erased — `ss0` roots `RK0`, and keeping it is the
/// forward-secrecy claim inverted — and the answer is
/// [`Establishment::Unrecoverable`], which the caller turns into the classed
/// event a user can act on. The state that leaves behind is one the load path
/// reads correctly on its own: an established contact record with no resume
/// record beside it is A3.15 row 6, `RS` absent, which
/// [`DmMachine::resume_channel`] surfaces as the recovery offer at every start.
///
/// The floor starts at the outbox's own counters, which is what this side has
/// spent on the channel so far; it rises at the first completed
/// re-establishment.
fn establish_provisional(
    persist: &DmPersist,
    correspondence: &mut Correspondence,
    peer_pk_pc: &[u8; IDENTITY_PK_LEN],
    now_ms: i64,
) -> Establishment {
    let Some((keyrec_addr, fc_epoch)) = correspondence.provisional else {
        return Establishment::Complete;
    };
    let Some(signing_pc) = correspondence.signing_pc.as_ref() else {
        crate::vtrace!(
            "dm driver: this side's pseudonym key did not survive the restart, so this \
             correspondence can never sign a re-establishment leg"
        );
        // Whatever the erase answers, the correspondence is unrecoverable: with
        // no `S_pc` nothing can sign a leg, and with the record gone nothing can
        // derive `RS_0` either. Both roads end at the same event.
        match erase_provisional(persist, correspondence) {
            Erasure::Deleted | Erasure::Absent => {}
            Erasure::Retry => crate::vtrace!(
                "dm driver: the handshake record of a correspondence that cannot re-establish \
                 would not erase"
            ),
        }
        return Establishment::Unrecoverable;
    };
    let floor = match persist.read_outbox(&correspondence.label, now_ms) {
        Ok(Some(outbox)) => SendFloor::new(outbox.last_clear_gen(), outbox.next_send_seq()),
        // Nothing has been queued on this channel, so nothing has been spent.
        Ok(None) => SendFloor::new(0, 0),
        Err(e) => {
            crate::vtrace!("dm driver: the outbox would not read for the send floor: {e}");
            return Establishment::Retry;
        }
    };
    let outcome = establish_record(
        persist,
        &correspondence.label,
        &keyrec_addr,
        fc_epoch,
        signing_pc,
        peer_pk_pc,
        floor,
    );
    if outcome == Establishment::Complete {
        correspondence.provisional = None;
    }
    outcome
}

/// Write one correspondence's first resume record and erase the handshake
/// record beside it.
///
/// **The committed re-establishment root comes from the handshake record and
/// nowhere else.** `RS_0`
/// is an Expand sibling of the `ss0` extraction
/// (`docs/design/direct-messaging.md:302`), and establishment destroys `ss0` — so
/// the last moment it can be read is from the record this call is about to
/// erase. [`PendingHandshake::commit_with_resume`] is the ordering: the resume
/// record is written first, the erase is best-effort behind it, and a crash
/// between the two leaves both records, which the loader resolves in the resume
/// record's favour.
///
/// [`Establishment::Retry`] on every outcome that leaves the handshake record
/// where it was, so the caller keeps the handle that is the only thing able to
/// open it again — the contract [`erase_record`] states in its own terms.
fn establish_record(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    keyrec_addr: &ProvisionalContext,
    fc_epoch: u64,
    signing_pc: &SignKeypair,
    peer_pk_pc: &[u8; IDENTITY_PK_LEN],
    floor: SendFloor,
) -> Establishment {
    let ctx = RecordContext {
        recipient_keyrec_addr: keyrec_addr,
        fc_epoch,
    };
    match persist.restart_channel(label, &ctx) {
        // A resume record is already the authority here, so this establishment
        // has run before. The store says whether the erase behind it landed.
        StoredChannelRestart::Established(_) => {
            match persist.store().read_unlocked(
                label,
                daemonseed_core::storage::dm_store::RecordKind::Provisional,
            ) {
                Ok(None) => Establishment::Complete,
                // The erase behind an earlier pass did not land. Nothing here is
                // wrong with the correspondence; the record is owed a delete and
                // the caller keeps the handle that addresses it.
                Ok(Some(_)) => Establishment::Retry,
                // **An I/O error is its own arm, not "the record is still
                // there".** The two answers are indistinguishable in a
                // `matches!` and lead to the same retry, but only one of them is
                // a fault, and a store that will not read is worth a trace line
                // where a record still awaiting its delete is not.
                Err(e) => {
                    crate::vtrace!(
                        "dm driver: the store would not say whether the handshake record \
                         is gone: {e}"
                    );
                    Establishment::Retry
                }
            }
        }
        StoredChannelRestart::HandshakeResumes(pending) => {
            let roots = match pending.channel_roots() {
                Ok(roots) => roots,
                Err(e) => {
                    crate::vtrace!("dm driver: the channel roots would not derive: {e}");
                    return Establishment::Retry;
                }
            };
            let resume = ResumeRecord::new(
                Box::new(*signing_pc.secret_key()),
                Box::new(*peer_pk_pc),
                roots.rs0.clone(),
                ReEstState::first_establishment(),
                Retention::none(),
                floor,
            );
            match pending.commit_with_resume(&resume) {
                Ok(()) => Establishment::Complete,
                Err(e) => {
                    crate::vtrace!("dm driver: the resume record would not commit: {e}");
                    Establishment::Retry
                }
            }
        }
        StoredChannelRestart::TornDown(teardown) => match teardown.cause() {
            // No handshake record survives, so there is no `ss0` to derive
            // `RS_0` from and no resume record can ever be written for this
            // correspondence. Reported rather than answered `true`: the disk is
            // tidy and the conversation is finished, and only the first of those
            // was ever what the caller asked about.
            TeardownCause::NoProvisionalRecord => Establishment::Unrecoverable,
            cause => {
                crate::vtrace!(
                    "dm driver: the provisional record would not open to establish: {cause:?}"
                );
                Establishment::Retry
            }
        },
    }
}

/// What became of one provisional record.
///
/// **Three answers rather than a bool, because the middle one is not the same
/// news as the first.** A record this call deleted and a record that was
/// already gone both leave the caller free to drop its handle, and a `true`
/// covering both loses the one difference that matters: a record that vanished
/// took `ss0` with it, so `RS_0` can never be derived and the correspondence can
/// never re-establish. That is a user-visible state, and collapsing it into
/// success is how it stayed unreported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Erasure {
    /// The record was deleted by this call.
    Deleted,
    /// The store says there is no record here. Nothing to erase, and nothing
    /// left that a re-establishment could be derived from.
    Absent,
    /// The store could not be read, the ciphertext did not open, or the
    /// correspondent's state was lost. None of those says the record is gone, so
    /// the caller keeps the handle that is the only thing able to address it.
    Retry,
}

/// Erase one provisional record, and say what became of it.
///
/// **The return value is the whole interface**, because the caller's only
/// correct reaction to a failure is to keep the handle. The context names the
/// epoch the record was sealed under and a record opens under no other, so a
/// handle dropped on a failed erase leaves `{ss0, the opening ephemeral DK}` on
/// disk with nothing left that could ever address it — a transient store fault
/// turned into a permanent leak of the secret that roots `RK0`.
fn erase_record(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    keyrec_addr: &ProvisionalContext,
    fc_epoch: u64,
) -> Erasure {
    let ctx = RecordContext {
        recipient_keyrec_addr: keyrec_addr,
        fc_epoch,
    };
    match persist.restart_channel(label, &ctx) {
        // A resume record is the authority, and the loader erases a provisional
        // record left beside it — so the erase this call exists to perform has
        // already been attempted. It is best-effort there, so the answer comes
        // from the store rather than from the arm.
        StoredChannelRestart::Established(_) => {
            match persist.store().read_unlocked(
                label,
                daemonseed_core::storage::dm_store::RecordKind::Provisional,
            ) {
                Ok(None) => Erasure::Deleted,
                Ok(Some(_)) => Erasure::Retry,
                Err(e) => {
                    crate::vtrace!(
                        "dm driver: the store would not say whether the handshake record \
                         is gone: {e}"
                    );
                    Erasure::Retry
                }
            }
        }
        StoredChannelRestart::HandshakeResumes(pending) => match pending.commit() {
            Ok(()) => Erasure::Deleted,
            Err(e) => {
                crate::vtrace!("dm driver: the provisional record would not erase: {e}");
                Erasure::Retry
            }
        },
        StoredChannelRestart::TornDown(teardown) => match teardown.cause() {
            TeardownCause::NoProvisionalRecord => Erasure::Absent,
            cause => {
                crate::vtrace!(
                    "dm driver: the provisional record would not open to erase: {cause:?}"
                );
                Erasure::Retry
            }
        },
    }
}

/// The two events one refused acceptance owes a front end.
///
/// **A delivery state AND a reason, because they answer different questions.**
/// A successful acceptance reports `Delivery { seq: 0, Composed }`, so a failed
/// one that said nothing on the delivery plane would leave sequence zero
/// looking as though it had never been attempted — the one position whose
/// absence the initiator cannot recover from. And a bare delivery state would
/// drop [`RefusalReason::OutboxFull`]'s `needed`, which is the only thing here a
/// user can act on.
///
/// The acceptance is a channel frame, so [`DmEvent::Refused`] is the documented
/// event for it — "a first contact, or a channel send" — and the reason says
/// which plane it belongs to. It is retried on the next tick from
/// `DmMachine::due_emissions`; this pair is the statement of the current
/// attempt, not a final verdict.
fn accept_refused(recipient: &[u8; IDENTITY_PK_LEN], reason: RefusalReason) -> Vec<DmEffect> {
    vec![
        DmEffect::Emit(DmEvent::Delivery {
            to: Box::new(*recipient),
            seq: FIRST_RECIPIENT_CHANNEL_SEQ,
            state: DeliveryState::Undelivered,
        }),
        DmEffect::Emit(refused(recipient, reason, None)),
    ]
}

/// A first contact that did not proceed.
///
/// [`Acceptance::Unconfirmed`] is all this layer can say about the write: no
/// emission of this introduction has been confirmed, which is true of every
/// path here — nothing reaches this function after a confirmed doorbell write.
/// `reason` is the part that varies and the part a front end acts on.
///
/// The driver's only construction of [`DmEvent::Refused`], tests aside.
/// `event` is a parameter rather than a second constructor: a refusal that ends
/// a channel owes the taxonomy an audit entry, and passing the key in at the
/// single construction site is what keeps every other refusal's `None` an
/// explicit statement instead of a default nothing states.
fn refused(
    recipient: &[u8; IDENTITY_PK_LEN],
    reason: RefusalReason,
    event: Option<TrustEventKey>,
) -> DmEvent {
    DmEvent::Refused {
        to: Box::new(*recipient),
        acceptance: daemonseed_core::dm::outbox::Acceptance::Unconfirmed,
        reason,
        event,
    }
}

/// The correspondences already on disk, as this session can hold them.
///
/// **Every one of these is deaf and mute, and that is the honest state rather
/// than a stub.** A [`Ratchet`] has no at-rest record and the pseudonym pair is
/// homed in a resume record that cannot be written until the channel has
/// re-established once (A4.8 / A9.2), so a correspondence established before
/// this process began has no key schedule here: it cannot open what it sweeps
/// and cannot sign what it would send. What it does carry is the correspondent's
/// identity, the store label its records live under, the correspondent's
/// pseudonym as the contact record recorded it, and a collection seeded from the
/// persisted cursor — so the correspondence is *listed*, a
/// [`DmCommand::Send`] to it is refused in as many words rather than silently
/// dropped, and re-establishment has somewhere to land.
///
/// **The persisted cursor is read against a `read_through` of zero, which is
/// what this session has genuinely swept: nothing.** The bound is the caller's
/// own knowledge or it is not a bound at all — the record's seal (#389) attests
/// to who wrote the number, never to the number being right. A
/// stored page above zero is therefore refused rather than believed, and the
/// collection resumes from the start — a full rescan, which is the failure that
/// type is allowed to have.
///
/// A store that will not enumerate, a contact record that will not decode and a
/// cursor that will not corroborate are each traced and skipped rather than
/// fatal: a driver that refused to start over one unreadable correspondence
/// would take every other correspondence down with it.
fn seed_from_store(persist: &DmPersist) -> Vec<Correspondence> {
    // A4.8's crash window is closed here, once, before anything is rebuilt: a
    // crash between the resume record's write and its best-effort erase leaves a
    // provisional record holding `ss0` — which roots `RK0` and every message key
    // the ratchet believes it deleted — beside the resume record that supersedes
    // it. This is the one caller that walks every correspondence knowing it is
    // rebuilding all of them, so the sweep belongs here and not in a lookup.
    match persist.sweep_lingering_provisionals() {
        Ok(0) => {}
        Ok(n) => crate::vtrace!("dm driver: scrubbed {n} superseded provisional record(s)"),
        Err(e) => crate::vtrace!("dm driver: the lingering-record sweep did not run: {e}"),
    }
    let labels = match persist.store().correspondences() {
        Ok(labels) => labels,
        Err(e) => {
            crate::vtrace!("dm driver: the store would not enumerate: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for label in labels {
        let record = match persist.read_contact(&label) {
            Ok(Some(record)) => record,
            // A label with no contact record is a correspondence that was never
            // established — a provisional handshake, or a directory left by a
            // refused accept.
            Ok(None) => continue,
            Err(e) => {
                crate::vtrace!("dm driver: a contact record would not decode: {e}");
                continue;
            }
        };
        // **Unreadable and uncorroborated are different answers here, and only
        // one of them is a fault.** Every stored page above zero is
        // uncorroborated at a cold start — `read_through` is zero, because this
        // session has swept nothing — so that is the ordinary case and the
        // remedy is the rescan this seed already performs. A record that will
        // not read at all is a fault, and one that cannot be written past
        // either: it is flagged here for the next tick to replace.
        let mut cursor_unreadable = false;
        let page = match persist.read_cursor(&label, 0) {
            Ok(Some(cursor)) => cursor.page(),
            Ok(None) => 0,
            Err(e) if e.is_unreadable_record() => {
                crate::vtrace!("dm driver: the stored cursor will not read: {e}");
                cursor_unreadable = true;
                0
            }
            Err(e) => {
                crate::vtrace!("dm driver: the stored cursor was not corroborated: {e}");
                0
            }
        };
        out.push(Correspondence {
            pk_lt: Box::new(*record.pk_lt()),
            label,
            ratchet: None,
            signing_pc: None,
            // Absent on a correspondence whose first-contact entry has been
            // sent and not yet accepted, which is the state the record was
            // written in. `on_page` reads the same absence as "only the
            // acceptance can be opened", so a restarted initiator resumes
            // waiting for the frame it was waiting for rather than treating the
            // conversation as verifiable.
            peer_pk_pc: record.pk_pc().map(|pk_pc| Box::new(*pk_pc)),
            channel: None,
            // The one addressing fact that survives a restart, and what makes
            // the re-establishment plane reachable at all — see the field.
            address_root: record.address_root(),
            candidate: None,
            re_acks_answered: 0,
            response_cap_surfaced: false,
            retire_ceiling_surfaced: false,
            leg_give_up_surfaced: false,
            peer_regression_surfaced: false,
            collection: Collection::resuming_from_page(page),
            read_through: 0,
            cursor_unreadable,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            // Named by the re-arm below, which is the only thing here that
            // knows the epoch a stored handshake was sealed under. Nothing is
            // erased on the strength of a handle this seed invented.
            provisional: None,
            // Set from the record, which distinguishes an established
            // correspondence from one whose first-contact entry is still
            // unanswered. Only the second has a stored handshake to
            // recompute a ratchet and channel roots from.
            rearm_handshake: record.pk_pc().is_none(),
            // The mirror of the line above: a record holding a pseudonym is an
            // established correspondence, which is the one state with a resume
            // record behind it.
            resume_owed: record.pk_pc().is_some(),
            resume_faults: 0,
            resume_retry_due_ms: None,
            resume_surfaced: false,
            resume_ceiling_surfaced: false,
            rearm_faults: 0,
            // Nothing is owed on a record read back from disk: the pseudonym
            // it holds is already written down, and one it does not hold has
            // not been collected.
            pseudonym_unwritten: false,
            pseudonym_faults: 0,
        });
    }
    out
}

/// Unix milliseconds as the unsigned value the collection's cadence takes.
///
/// **The one conversion between the two clock types, and it is here so it is
/// not spelled `as` at four call sites.** The outbox and the persist layer take
/// `i64` because their values are wall times that must be comparable to a
/// seven-day give-up; [`Collection::probe_plan`] takes `u64` because it reads
/// only differences and any epoch will do. A pre-epoch clock saturates to zero
/// rather than wrapping to 292 million years hence, which would park the probe
/// for the size of the step.
fn probe_ms(now_ms: i64) -> u64 {
    u64::try_from(now_ms.max(0)).unwrap_or(0)
}

/// Unix seconds from unix milliseconds, floored at zero.
///
/// A pre-epoch clock reads as epoch rather than wrapping: the epoch derivation
/// takes an unsigned value, and a negative millisecond count cast into one
/// would place the sweep 292 million years out.
fn unix_secs(now_ms: i64) -> u64 {
    u64::try_from(now_ms.max(0) / 1000).unwrap_or(0)
}

/// A fresh per-contact pseudonym keypair.
///
/// Minted from the CSPRNG rather than derived: a pseudonym derived from the
/// identity seed and the correspondent would be recomputable by anyone who
/// later learned both, which is the linkage the pseudonym exists to break.
fn mint_pseudonym() -> Result<SignKeypair, Box<dyn std::error::Error + Send + Sync>> {
    let mut seed = [0u8; ML_DSA_SEED_LEN];
    getrandom::fill(&mut seed).map_err(|e| Box::new(e) as Box<_>)?;
    let keypair = SignKeypair::from_ml_dsa_seed(&seed).map_err(|e| Box::new(e) as Box<_>);
    zeroize::Zeroize::zeroize(&mut seed);
    keypair
}

/// Run one first-contact mint. **Blocks for seconds** at production difficulty.
pub(crate) fn run_mint(request: MintRequest) -> MintOutcome {
    let MintRequest {
        recipient,
        signing_lt,
        signing_pc,
        kem_ek_b,
        recipient_keyrec_addr,
        fc_epoch,
        sent_unix_ms,
        body,
        difficulty,
    } = request;
    let result = firstcontact::build(FirstContactRequest {
        signing_lt: &signing_lt,
        signing_pc: &signing_pc,
        recipient_pk_lt: &recipient,
        kem_ek_b: &kem_ek_b,
        fc_epoch,
        sent_unix_ms,
        body: &body,
        token: None,
        difficulty,
    });
    MintOutcome {
        recipient,
        signing_pc,
        fc_epoch,
        recipient_keyrec_addr,
        result,
    }
}

/// A duration as milliseconds, saturating rather than wrapping. A configuration
/// large enough to overflow an `i64` of milliseconds is 292 million years out and
/// is clamped rather than folded back into the past.
pub(crate) fn duration_as_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::dm::mock::{MockCall, MockDht};

    use daemonseed_core::dm::admission::AdmissionPolicy;
    use daemonseed_core::dm::firstcontact::{derive_channel_roots, FirstContactRequest, SS0_LEN};
    use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
    use daemonseed_core::identity::mnemonic::Mnemonic;
    use daemonseed_core::storage::seeds::AEAD_KEY_LEN;

    use crate::dm::driver::DmDriverConfig;

    const AT_REST: [u8; AEAD_KEY_LEN] = [7u8; AEAD_KEY_LEN];
    const BASE_MS: i64 = 1_234_567_890_123;
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art";

    fn keys() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Primary,
        )
        .expect("identity")
    }

    /// A second correspondent, so a test can tell a per-identity bound from a
    /// shared one.
    fn other_peer_identity() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Device {
                uuid: uuid::Uuid::from_bytes([0x3Bu8; 16]),
            },
        )
        .expect("second peer identity")
    }

    /// A machine over a scratch store, with the derivations the shell would
    /// have done.
    fn machine(dir: &tempfile::TempDir) -> DmMachine {
        let k = keys();
        let persist = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let doorbell_owner = *doorbell::derive_owner_seed(k.signing.public_key())
            .expect("doorbell")
            .as_bytes();
        let keyrec_addr = *keyrec::derive_owner_seed(k.signing.public_key())
            .expect("keyrec")
            .as_bytes();
        DmMachine::new(
            DmIdentity {
                signing: Arc::new(k.signing),
                kem: k.kem,
                doorbell_slot_secret: k.dm_doorbell_slot_secret,
            },
            persist,
            DmDriverConfig {
                idle_tick: Duration::from_secs(30),
                policy: AdmissionPolicy::Open,
                pow_difficulty: pow::PowDifficulty::reduced_for_test(4),
            },
            doorbell_owner,
            keyrec_addr,
            SpentTokens {
                set: SpentTokenSet::new(),
                store: None,
                poisoned: false,
            },
        )
    }

    /// A knock assembled without opening a seal, for the paths that never look
    /// at one.
    ///
    /// Deliberate and greppable: `VerifiedFirstContact::new_for_test` is core's
    /// own hole in the type's invariant, compiled only under its `testing`
    /// feature. It is right here and wrong anywhere the *verification* is what
    /// is under test — every oracle in `driver.rs` that exercises admission
    /// mints a real entry through `firstcontact::build` instead. What these
    /// tests are about is the bookkeeping around an already-admitted knock, and
    /// minting sixty-five real ones to check a bound would cost sixty-five
    /// proofs of work and sixty-five keygens to prove nothing extra.
    fn fake_knock(tag: u8) -> Box<VerifiedFirstContact> {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let mut ss0 = [0u8; SS0_LEN];
        for (i, b) in ss0.iter_mut().enumerate() {
            *b = tag.wrapping_add(i as u8).wrapping_mul(3).wrapping_add(1);
        }
        let roots = derive_channel_roots(&ss0).expect("roots");
        let pk = |t: u8| -> Box<[u8; IDENTITY_PK_LEN]> {
            let mut out = vec![0u8; IDENTITY_PK_LEN].into_boxed_slice();
            for (i, b) in out.iter_mut().enumerate() {
                *b = t.wrapping_add((i as u8).wrapping_mul(7));
            }
            out.try_into().expect("allocated at PK_LEN")
        };
        let mut ek = vec![0u8; KEM_EK_LEN].into_boxed_slice();
        for (i, b) in ek.iter_mut().enumerate() {
            *b = tag.wrapping_add((i as u8).wrapping_mul(5));
        }
        Box::new(VerifiedFirstContact::new_for_test(
            pk(tag),
            pk(tag.wrapping_add(0x7F)),
            ek.try_into().expect("allocated at EK_LEN"),
            0,
            BASE_MS,
            "hello".to_string(),
            ss0,
            roots,
        ))
    }

    fn hash(tag: u8) -> [u8; pow::ENTRY_HASH_LEN] {
        [tag; pow::ENTRY_HASH_LEN]
    }

    /// M1. The held-request list stops at its cap, and the knock past it is
    /// dropped rather than queued.
    ///
    /// The count at the cap is the positive control: without it, "the 65th
    /// surfaced nothing" is satisfied by a machine that surfaced nothing at all.
    #[test]
    fn the_held_request_list_stops_at_its_cap() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        for i in 0..PENDING_REQUEST_CAP {
            let effects = m.surface(
                BASE_MS,
                epoch,
                i as u16,
                hash(i as u8),
                fake_knock(i as u8),
                false,
            );
            assert_eq!(effects.len(), 1, "knock {i} surfaced nothing");
        }
        assert_eq!(m.pending_count(), PENDING_REQUEST_CAP, "the list filled");

        let over = m.surface(BASE_MS, epoch, 999, hash(0xFE), fake_knock(0xFE), false);
        assert!(over.is_empty(), "the knock past the cap surfaced anyway");
        assert_eq!(
            m.pending_count(),
            PENDING_REQUEST_CAP,
            "the knock past the cap was held anyway"
        );
    }

    /// M2. Blocking an identity drops the request it already has on screen.
    #[test]
    fn blocking_drops_a_held_request() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        let knock = fake_knock(3);
        let pk_lt: PkLt = Box::new(*knock.pk_lt());
        m.surface(BASE_MS, epoch, 1, hash(3), knock, false);
        // Positive control: the request is there to be dropped.
        assert_eq!(m.pending_count(), 1);

        // A different identity first: the block must drop the blocked one and
        // nothing else.
        let other = fake_knock(4);
        m.surface(BASE_MS, epoch, 2, hash(4), other, false);
        assert_eq!(m.pending_count(), 2);

        m.on_command(BASE_MS, DmCommand::Block { pk_lt });
        assert_eq!(
            m.pending_count(),
            1,
            "the block dropped the wrong number of requests"
        );
    }

    /// M2b. A block the store refused leaves the held request on screen.
    ///
    /// **The drop and the write stand or fall together.** A refused write leaves
    /// the identity unblocked, so a request dropped anyway is a request the user
    /// never answered and will not be shown again until a restart or a fresh
    /// entry: its entry hash is already in the seen set, so the sender's next
    /// re-seed reads as `Seen` rather than surfacing, and that set is in memory —
    /// a restart inside the accept window clears it and the same re-seed
    /// surfaces. The successful case is `blocking_drops_a_held_request`; this is
    /// the other arm of the same branch.
    #[test]
    fn a_refused_block_keeps_the_held_request() {
        use daemonseed_core::dm::block_list::BLOCK_LIST_MAX_ENTRIES;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        m.persist
            .update_block_list(|list| {
                for i in 0..BLOCK_LIST_MAX_ENTRIES {
                    let mut key = vec![0u8; IDENTITY_PK_LEN].into_boxed_slice();
                    key[0] = (i >> 8) as u8;
                    key[1] = (i & 0xFF) as u8;
                    let key: Box<[u8; IDENTITY_PK_LEN]> =
                        key.try_into().expect("allocated at PK_LEN");
                    assert!(list.block(&key), "fixture key {i} was a duplicate");
                }
                Ok(())
            })
            .expect("fill");

        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));
        let knock = fake_knock(3);
        let pk_lt: PkLt = Box::new(*knock.pk_lt());
        m.surface(BASE_MS, epoch, 1, hash(3), knock, false);
        assert_eq!(m.pending_count(), 1, "the request is not there to be kept");

        let effects = m.on_command(
            BASE_MS,
            DmCommand::Block {
                pk_lt: pk_lt.clone(),
            },
        );
        assert!(
            matches!(
                &effects[..],
                [DmEffect::Emit(DmEvent::BlockListFull { .. })]
            ),
            "the fixture's list was not full, so the refusal below never happened: {effects:?}"
        );
        assert!(
            !m.persist
                .read_block_list()
                .expect("read")
                .is_blocked(&pk_lt),
            "the refused block was stored anyway"
        );
        assert_eq!(
            m.pending_count(),
            1,
            "a refused block dropped the held request it did not block"
        );
    }

    /// M3. A held request whose admitting epoch has left the accept window is
    /// dropped at the next sweep.
    #[test]
    fn a_stale_held_request_expires_at_the_next_sweep() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        m.surface(BASE_MS, epoch, 1, hash(3), fake_knock(3), false);
        assert_eq!(m.pending_count(), 1);

        // One epoch on: still inside the accept window, so it stays.
        let one_on = BASE_MS + i64::try_from(period_ms()).expect("period fits");
        m.on_doorbell(one_on, empty_sweep());
        assert_eq!(
            m.pending_count(),
            1,
            "a request one epoch old was dropped too early"
        );

        // Two epochs on: the entry can no longer be presented at all.
        let two_on = BASE_MS + 2 * i64::try_from(period_ms()).expect("period fits");
        m.on_doorbell(two_on, empty_sweep());
        assert_eq!(m.pending_count(), 0, "a stale request was still held");
    }

    /// One first-contact period, in milliseconds.
    fn period_ms() -> u64 {
        daemonseed_core::dm::keyrec::FC_PERIOD_SECS * 1000
    }

    fn empty_sweep() -> DoorbellSweep {
        DoorbellSweep {
            slots: Vec::new(),
            outcome: crate::SweepOutcome::default(),
        }
    }

    /// M4. A `FirstContact` to a recipient already in flight is refused and
    /// starts nothing.
    #[test]
    fn a_second_introduction_to_one_recipient_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let recipient: PkLt = Box::new(*fake_knock(11).pk_lt());

        let first = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: recipient.clone(),
                body: "one".into(),
            },
        );
        assert_eq!(first.len(), 1, "the first introduction started nothing");
        assert!(matches!(
            first[0],
            DmEffect::Dht(DhtOp::FetchKeyRecord { .. })
        ));

        let second = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient,
                body: "two".into(),
            },
        );
        assert_eq!(second.len(), 1);
        assert!(
            matches!(
                &second[0],
                DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::AlreadyInFlight,
                    ..
                })
            ),
            "the duplicate was not refused as a duplicate"
        );
    }

    /// A refusal raised by a teardown carries that teardown's classed key, and
    /// carries it as the teardown states it.
    ///
    /// The key is what the audit log and the affordance class are keyed on, and
    /// [`DmEvent::Refused`] is the only event a front end sees for an
    /// introduction that ends this way — so a refusal that dropped it would
    /// leave the teardown stated in words and absent from the taxonomy.
    ///
    /// The teardown is a real one, from `restart` over an unreadable store, and
    /// it enters through `refuse_introduction` — the call `on_mint`'s teardown
    /// arm makes. What is pinned is the key's route from there to the emitted
    /// event; `on_mint`'s own arm is not driven, and says so.
    #[test]
    fn a_refusal_raised_by_a_teardown_carries_its_classed_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let recipient: PkLt = Box::new(*fake_knock(12).pk_lt());

        // A real teardown, so the key under assertion is the one core derives
        // from the cause rather than one the test chose.
        let seal_key = daemonseed_core::dm::provisional::derive_seal_key(&[0x11u8; AEAD_KEY_LEN])
            .expect("seal key");
        let addr = [0x22u8; keyrec::DM_KEYREC_OWNER_SEED_LEN];
        let unreadable = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "seeds.bin");
        let teardown = match daemonseed_core::dm::provisional::restart(
            Err(unreadable),
            &seal_key,
            &RecordContext {
                recipient_keyrec_addr: &addr,
                fc_epoch: 7,
            },
        ) {
            daemonseed_core::dm::provisional::ChannelRestart::TornDown(t) => t,
            daemonseed_core::dm::provisional::ChannelRestart::HandshakeResumes(_) => {
                panic!("nothing was read, so nothing resumes")
            }
        };
        assert_eq!(
            teardown.cause(),
            &TeardownCause::StoreUnreadable("seeds.bin".into()),
            "the fixture built a different teardown than the one asserted below"
        );

        // An introduction has to be in flight, or the refusal drops nothing and
        // emits nothing.
        let started = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: recipient.clone(),
                body: "one".into(),
            },
        );
        assert!(
            matches!(&started[..], [DmEffect::Dht(DhtOp::FetchKeyRecord { .. })]),
            "the introduction did not start: {started:?}"
        );

        // The control: a refusal that tears nothing down claims no trust event,
        // so the key below is carried rather than always present.
        let duplicate = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: recipient.clone(),
                body: "two".into(),
            },
        );
        assert!(
            matches!(
                &duplicate[..],
                [DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::AlreadyInFlight,
                    event: None,
                    ..
                })]
            ),
            "a refusal that tore no channel down claimed a trust event: {duplicate:?}"
        );

        let out = m.refuse_introduction(
            &recipient,
            RefusalReason::StoreFailure,
            Some(teardown.event()),
        );
        let [DmEffect::Emit(DmEvent::Refused { reason, event, .. })] = &out[..] else {
            panic!("the teardown did not refuse the introduction: {out:?}");
        };
        assert_eq!(*reason, RefusalReason::StoreFailure);
        assert_eq!(
            *event,
            Some(TrustEventKey::DmProvisionalRecordUnreadable),
            "the refusal did not carry the teardown's classed key"
        );
    }

    /// M5. A failed spent-token write poisons the store and says so, and no
    /// later write is attempted.
    ///
    /// Poisoning is the half that matters: after a failed write the file's
    /// relationship to the set in memory is unknown, and a later write would
    /// lay this set over whatever is actually there.
    #[test]
    fn a_failed_spent_token_write_poisons_the_store() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.spent.store = Some(crate::dm::driver::SpentTokenStore {
            profile_root: dir.path().to_path_buf(),
            passphrase: zeroize::Zeroizing::new("hunter2".to_string()),
            profile_id: uuid::Uuid::from_bytes([1u8; 16]),
            argon2: daemonseed_core::profile::config::ArgonParams {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        });

        // Positive control: an unpoisoned store asks for the write.
        assert_eq!(m.save_spent().len(), 1, "a healthy store wrote nothing");

        let effects = m.on_outcome(BASE_MS, DmOutcome::SpentSaved(Err("disk full".into())));
        assert_eq!(effects.len(), 1);
        assert!(
            matches!(effects[0], DmEffect::Emit(DmEvent::SpentTokensNotPersisted)),
            "a failed write said nothing"
        );
        assert!(
            m.save_spent().is_empty(),
            "a poisoned store was written to anyway"
        );
    }

    /// M6. A panicked mint releases the introduction it was carrying.
    ///
    /// Without it the recipient stays recorded as in flight for the life of the
    /// driver and every later `FirstContact` to them is refused as a duplicate
    /// — one panic silently ending first contact with one person.
    #[test]
    fn a_panicked_mint_releases_its_introduction() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let recipient: PkLt = Box::new(*fake_knock(12).pk_lt());

        m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: recipient.clone(),
                body: "one".into(),
            },
        );
        // Positive control: it really is in flight, so the release below is
        // releasing something.
        assert!(m.introduction_in_flight(&recipient));

        let effects = m.on_outcome(
            BASE_MS,
            DmOutcome::Panicked {
                job: Some(PanickedJob::Mint(recipient.clone())),
            },
        );
        assert!(
            matches!(
                &effects[..],
                [DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::MintPanicked,
                    ..
                })]
            ),
            "a panicked mint was not refused: {effects:?}"
        );
        assert!(
            !m.introduction_in_flight(&recipient),
            "the introduction is still in flight after its task died"
        );
    }

    /// M7. The 513th block is refused and said out loud.
    ///
    /// The list is filled in ONE update rather than 512 commands: the ceiling
    /// is `BlockList::encode`'s and the machine's job is only to recognise the
    /// refusal, so 512 seals would buy nothing but minutes.
    #[test]
    fn the_five_hundred_and_thirteenth_block_is_reported() {
        use daemonseed_core::dm::block_list::BLOCK_LIST_MAX_ENTRIES;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        m.persist
            .update_block_list(|list| {
                for i in 0..BLOCK_LIST_MAX_ENTRIES {
                    let mut key = vec![0u8; IDENTITY_PK_LEN].into_boxed_slice();
                    key[0] = (i >> 8) as u8;
                    key[1] = (i & 0xFF) as u8;
                    let key: Box<[u8; IDENTITY_PK_LEN]> =
                        key.try_into().expect("allocated at PK_LEN");
                    assert!(list.block(&key), "fixture key {i} was a duplicate");
                }
                Ok(())
            })
            .expect("fill");
        assert_eq!(
            m.persist.read_block_list().expect("read").len(),
            BLOCK_LIST_MAX_ENTRIES,
            "the fixture did not fill the list"
        );

        // One more, from an identity not already in it.
        let over: PkLt = Box::new(*fake_knock(0xC3).pk_lt());
        let effects = m.on_command(BASE_MS, DmCommand::Block { pk_lt: over });
        assert!(
            matches!(
                &effects[..],
                [DmEffect::Emit(DmEvent::BlockListFull { count })]
                    if *count == BLOCK_LIST_MAX_ENTRIES + 1
            ),
            "the refused block was not reported: {effects:?}"
        );
        assert_eq!(
            m.persist.read_block_list().expect("read").len(),
            BLOCK_LIST_MAX_ENTRIES,
            "the refused block changed the stored list"
        );
    }

    /// M8. An accept the store refuses puts the request back and says why.
    ///
    /// The re-held request is the half that matters: the user answered it, and
    /// an accept that removed it and then failed would leave nothing on screen
    /// to answer again and nothing saying why the channel never appeared.
    #[test]
    fn a_refused_accept_puts_the_request_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        let knock = fake_knock(21);
        let pk_lt: PkLt = Box::new(*knock.pk_lt());
        let effects = m.surface(BASE_MS, epoch, 1, hash(21), knock, false);
        let DmEffect::Emit(DmEvent::ContactRequest { request, .. }) = &effects[0] else {
            panic!("the knock did not surface: {effects:?}");
        };
        let request = request.clone();

        // Establish that identity behind the machine's back, so the accept
        // meets `AlreadyEstablished` from the store rather than from a stub.
        m.persist
            .accept_first_contact(*fake_knock(21), &[0x71u8; oxicrypt_ml_dsa::SK_LEN], BASE_MS)
            .expect("the out-of-band establish succeeds");

        // Positive control: the request really is held before the accept.
        assert_eq!(m.pending_count(), 1);

        let out = m.on_command(BASE_MS, DmCommand::Accept { request });
        assert!(
            matches!(
                &out[..],
                [DmEffect::Emit(DmEvent::AcceptFailed {
                    reason: AcceptFailure::AlreadyEstablished,
                    ..
                })]
            ),
            "a refused accept said nothing: {out:?}"
        );
        assert_eq!(
            m.pending_count(),
            1,
            "the refused accept dropped the request the user answered"
        );
        assert_eq!(
            m.correspondence_count(),
            0,
            "a refused accept recorded a correspondence anyway"
        );
        let _ = pk_lt;
    }

    /// M9. Both bounded sets are aged at the top of a sweep.
    ///
    /// The seen set retires epochs outside the accept window and the spent set
    /// prunes nonces past their retention. Neither has any other caller, so
    /// without this they grow for the life of the driver — and a `SeenSet`
    /// still holding a stale epoch would keep skipping entries that are legal
    /// to present again.
    #[test]
    fn a_sweep_ages_both_bounded_sets() {
        use daemonseed_core::dm::token::SPENT_RETENTION_SECS;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        m.seen.insert(epoch.saturating_sub(5), hash(1));
        m.spent.set.insert([2u8; 32], unix_secs(BASE_MS));
        // Positive controls: both are there to be aged.
        assert_eq!(m.seen.len(), 1, "the seen set fixture is empty");
        assert_eq!(m.spent.set.len(), 1, "the spent set fixture is empty");

        // A sweep far enough on that both are out of their windows.
        let later =
            BASE_MS + i64::try_from((SPENT_RETENTION_SECS + 60) * 1000).expect("retention fits");
        m.on_doorbell(later, empty_sweep());

        assert_eq!(m.seen.len(), 0, "a stale epoch survived the sweep");
        assert_eq!(m.spent.set.len(), 0, "an expired nonce survived the sweep");
    }

    /// A real knock at this machine's own identity, minted at the reduced
    /// difficulty. Distinct from `fake_knock`: this one has to survive
    /// admission, so nothing about it can be assembled.
    fn real_knock(body: &str) -> Vec<u8> {
        let own = keys();
        let sender = derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Device {
                uuid: uuid::Uuid::from_bytes([0x5Au8; 16]),
            },
        )
        .expect("sender identity");
        let (entry, _state) = daemonseed_core::dm::firstcontact::build(FirstContactRequest {
            signing_lt: &sender.signing,
            signing_pc: &SignKeypair::from_ml_dsa_seed(&[0x41u8; ML_DSA_SEED_LEN])
                .expect("pseudonym"),
            recipient_pk_lt: own.signing.public_key(),
            kem_ek_b: own.kem.encapsulation_key(),
            fc_epoch: keyrec::fc_epoch(unix_secs(BASE_MS)),
            sent_unix_ms: BASE_MS,
            body,
            token: None,
            difficulty: pow::PowDifficulty::reduced_for_test(4),
        })
        .expect("the knock is composed");
        entry
    }

    fn sweep_of(slots: Vec<(u16, Vec<u8>)>) -> DoorbellSweep {
        let found = u32::try_from(slots.len()).unwrap_or(u32::MAX);
        DoorbellSweep {
            slots,
            outcome: crate::SweepOutcome {
                attempted: 32,
                failed: 0,
                found,
            },
        }
    }

    /// M10. A knock arriving while the held list is full is SKIPPED, not
    /// discarded — and it surfaces once a request is answered.
    ///
    /// The second sweep is the whole control. Checking the cap after admission
    /// would leave the entry's hash in the seen set, so the identical bytes
    /// would come back as a `Seen` drop for ever and this second sweep would
    /// surface nothing — which is what sixty-four unanswered requests
    /// permanently deafening first contact looks like.
    #[test]
    fn a_knock_arriving_at_a_full_list_is_skipped_and_surfaces_later() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        // Fill to the cap with assembled knocks: what is under test is the
        // bound, not the verification.
        for i in 0..PENDING_REQUEST_CAP {
            m.surface(
                BASE_MS,
                epoch,
                i as u16,
                hash(i as u8),
                fake_knock(i as u8),
                false,
            );
        }
        assert_eq!(m.pending_count(), PENDING_REQUEST_CAP, "the list filled");

        let entry = real_knock("let me in");
        let effects = m.on_doorbell(BASE_MS, sweep_of(vec![(200, entry.clone())]));
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ContactRequest { .. }))),
            "a knock surfaced past the cap: {effects:?}"
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::DoorbellHealth {
                    pending_full: 1,
                    ..
                })
            )),
            "the skipped knock was not reported: {effects:?}"
        );
        // Nothing about it was recorded, which is what makes the retry work.
        assert_eq!(m.seen.len(), 0, "the skipped entry was recorded as seen");
        assert!(
            m.previous_slots.is_empty(),
            "the skipped slot's bytes were recorded"
        );

        // Answer one, freeing a slot, and sweep the SAME bytes again.
        let answered = m.pending[0].id.clone();
        m.on_command(BASE_MS, DmCommand::Decline { request: answered });
        assert_eq!(m.pending_count(), PENDING_REQUEST_CAP - 1);

        let effects = m.on_doorbell(BASE_MS, sweep_of(vec![(200, entry)]));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ContactRequest { .. }))),
            "the skipped knock never came back: {effects:?}"
        );
    }

    /// M11. A panicked spent-token write poisons the store and says so.
    ///
    /// A panic is not a failure the job can report — it returns nothing — so
    /// without the shell's own tag this lands as a no-op, and under an
    /// invite-only policy that silently restores every invite spent since the
    /// last write that landed.
    #[test]
    fn a_panicked_spent_token_write_poisons_the_store() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.spent.store = Some(crate::dm::driver::SpentTokenStore {
            profile_root: dir.path().to_path_buf(),
            passphrase: zeroize::Zeroizing::new("hunter2".to_string()),
            profile_id: uuid::Uuid::from_bytes([1u8; 16]),
            argon2: daemonseed_core::profile::config::ArgonParams {
                memory_kib: 8,
                iterations: 1,
                parallelism: 1,
            },
        });
        // Positive control: an unpoisoned store asks for the write.
        assert_eq!(m.save_spent().len(), 1, "a healthy store wrote nothing");

        let effects = m.on_outcome(
            BASE_MS,
            DmOutcome::Panicked {
                job: Some(PanickedJob::SpentSave),
            },
        );
        assert!(
            matches!(
                &effects[..],
                [DmEffect::Emit(DmEvent::SpentTokensNotPersisted)]
            ),
            "a panicked write said nothing: {effects:?}"
        );
        assert!(
            m.save_spent().is_empty(),
            "a store poisoned by a panic was written to anyway"
        );
    }

    /// M12. A panicked DHT task refuses its introduction as a task panic, not
    /// as a mint panic.
    ///
    /// The two say different things about what to retry: a mint that panicked
    /// will panic again on the same input, a transport task that did is worth
    /// another attempt.
    #[test]
    fn a_panicked_dht_task_is_not_reported_as_a_panicked_mint() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let recipient: PkLt = Box::new(*fake_knock(13).pk_lt());
        m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: recipient.clone(),
                body: "one".into(),
            },
        );
        assert!(m.introduction_in_flight(&recipient));

        let effects = m.on_outcome(
            BASE_MS,
            DmOutcome::Panicked {
                job: Some(PanickedJob::Dht(recipient.clone())),
            },
        );
        assert!(
            matches!(
                &effects[..],
                [DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::TaskPanicked,
                    ..
                })]
            ),
            "a panicked DHT task was misreported: {effects:?}"
        );
        assert!(!m.introduction_in_flight(&recipient));
    }

    /// M13. Step 0's memory holds only the slots the doorbell still has.
    #[test]
    fn a_sweep_forgets_slots_the_record_no_longer_holds() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");

        m.on_doorbell(
            BASE_MS,
            sweep_of(vec![(3, vec![0u8; 9]), (4, vec![1u8; 9])]),
        );
        // Positive control: both slots were recorded, so the drop below is
        // dropping something.
        assert_eq!(m.previous_slots.len(), 2, "the fixture recorded nothing");

        m.on_doorbell(BASE_MS, sweep_of(vec![(4, vec![1u8; 9])]));
        assert_eq!(
            m.previous_slots.keys().copied().collect::<Vec<_>>(),
            vec![4],
            "a slot the doorbell no longer holds was kept"
        );
    }

    /// M14. A slot whose contact lookup failed is left exactly as it was found,
    /// and is read normally once the store is readable again.
    ///
    /// The closure fails closed to "already known", which is the safe answer
    /// for admission — it cannot surface a second request for an existing
    /// correspondent — but acting on that guess reports a stranger as a
    /// correspondent whose channel direction is unknown, with the entry already
    /// recorded as seen. One undecodable contact record would then make every
    /// stranger's knock vanish for good.
    ///
    /// The second sweep is the control: without the `forget` and the withheld
    /// `previous_slots` insert, the identical bytes come back as a `Seen` drop
    /// and nothing surfaces.
    #[test]
    fn a_slot_whose_lookup_failed_is_retried_rather_than_decided() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");

        // One correspondence with a contact record that will not decode. The
        // lookup propagates that rather than skipping it, so EVERY later
        // lookup fails — which is the defect this is about.
        let label = daemonseed_core::storage::dm_store::CorrespondenceLabel::mint().expect("label");
        let seeded = fake_knock(0x40);
        m.persist
            .update_contact(
                &label,
                || {
                    // `AR`, not `ss0` — the record stores the derived root
                    // (§ D-PFS). Both are 32 bytes, so passing the secret here
                    // would compile and seed a record production could never
                    // write.
                    let ar = zeroize::Zeroizing::new(
                        daemonseed_core::dm::firstcontact::derive_channel_roots(
                            seeded.ss0_for_test(),
                        )
                        .expect("derives")
                        .ar,
                    );
                    Ok(daemonseed_core::dm::contact_cache::ContactRecord::new(
                        Box::new(*seeded.pk_lt()),
                        Some(Box::new(*seeded.pk_pc())),
                        ar,
                        BASE_MS,
                        BASE_MS,
                    )?)
                },
                |_| Ok(daemonseed_core::dm::persist::Mutation::Unchanged(())),
            )
            .expect("seed");
        let record = m
            .persist
            .store()
            .root()
            .join(
                label
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
            .join("contact-cache.bin");
        let healthy = std::fs::read(&record).expect("the seeded record is on disk");
        std::fs::write(&record, vec![0xEEu8; healthy.len()]).expect("corrupt it");
        // Positive control: the lookup really does fail now.
        assert!(
            m.persist.correspondence_for_pk_lt(seeded.pk_lt()).is_err(),
            "the corruption did not break the lookup"
        );

        let entry = real_knock("still a stranger");
        let effects = m.on_doorbell(BASE_MS, sweep_of(vec![(201, entry.clone())]));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ContactLookupFailed))),
            "the failed lookup was not reported: {effects:?}"
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::ContactRequest { .. })
                    | DmEffect::Emit(DmEvent::ChannelDirectionUnknown { .. })
            )),
            "a guess was acted on: {effects:?}"
        );
        assert_eq!(m.seen.len(), 0, "the undecided entry was recorded as seen");
        assert!(
            m.previous_slots.is_empty(),
            "the undecided slot's bytes were recorded"
        );

        // Repair the store and sweep the SAME bytes.
        std::fs::write(&record, &healthy).expect("repair");
        let effects = m.on_doorbell(BASE_MS, sweep_of(vec![(201, entry)]));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ContactRequest { .. }))),
            "the deferred knock never came back: {effects:?}"
        );
    }

    // ---- the acceptance ---------------------------------------------------

    /// A machine over a scratch store for a NAMED identity, so two of them can
    /// face each other in one test without a driver or a transport.
    fn machine_as(k: IdentityKeys, dir: &tempfile::TempDir) -> DmMachine {
        let persist = DmPersist::open(dir.path().join("dm"), &AT_REST).expect("persist");
        let doorbell_owner = *doorbell::derive_owner_seed(k.signing.public_key())
            .expect("doorbell")
            .as_bytes();
        let keyrec_addr = *keyrec::derive_owner_seed(k.signing.public_key())
            .expect("keyrec")
            .as_bytes();
        DmMachine::new(
            DmIdentity {
                signing: Arc::new(k.signing),
                kem: k.kem,
                doorbell_slot_secret: k.dm_doorbell_slot_secret,
            },
            persist,
            DmDriverConfig {
                idle_tick: Duration::from_secs(30),
                policy: AdmissionPolicy::Open,
                pow_difficulty: pow::PowDifficulty::reduced_for_test(4),
            },
            doorbell_owner,
            keyrec_addr,
            SpentTokens {
                set: SpentTokenSet::new(),
                store: None,
                poisoned: false,
            },
        )
    }

    /// **The scan behind a first contact does not write to the correspondences
    /// it walks past.**
    ///
    /// `provisional_label` asks every stored correspondence whether it is this
    /// recipient's. Asking through `restart_channel` would delete a lingering
    /// provisional record on each one holding a readable resume record — a
    /// conversation the call named nothing about. This drives the machine, not
    /// the persist layer, because the wiring is the claim: `dm::persist`'s own
    /// tests already pin that the peek does not clean and `restart_channel`
    /// does, and neither of them says which one this scan reaches.
    ///
    /// The bystander is put in A4.8's crash window deliberately, since that is
    /// the only state in which the cleaning branch is reachable at all.
    #[test]
    fn a_first_contact_scan_does_not_scrub_a_bystanders_provisional_record() {
        use daemonseed_core::dm::ratchet::ROOT_KEY_LEN;
        use daemonseed_core::dm::resume::{
            CommittedRoot, ReEstState, ResumeRecord, Retention, SendFloor,
        };
        use daemonseed_core::storage::dm_store::RecordKind;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut a = machine(&dir);

        // The bystander: a real knock, so its provisional record is written the
        // way production writes one.
        let bystander_peer = peer_identity();
        let _ = knock_as_initiator(&mut a, &bystander_peer);
        let bystander = sole_label(&a);

        // Into the crash window: the resume record committed, the provisional
        // record not yet erased.
        a.persist
            .commit_resume(
                &bystander,
                &ResumeRecord::new(
                    Box::new([0x11u8; oxicrypt_ml_dsa::SK_LEN]),
                    Box::new([0x22u8; oxicrypt_ml_dsa::PK_LEN]),
                    CommittedRoot::from_bytes(&[0x33u8; ROOT_KEY_LEN]),
                    ReEstState::first_establishment(),
                    Retention::none(),
                    SendFloor::new(0, 0),
                ),
            )
            .expect("commits");

        let present = |m: &DmMachine| {
            m.persist
                .store()
                .read_unlocked(&bystander, RecordKind::Provisional)
                .expect("reads")
                .is_some()
        };
        assert!(present(&a), "the fixture did not build the crash window");

        // A first contact with somebody else, which is what runs the scan. The
        // in-memory map has no entry for this recipient, so it falls through to
        // the store.
        let _ = knock_as_initiator(&mut a, &third_identity());

        assert!(
            present(&a),
            "the first-contact scan deleted a provisional record belonging to a \
             correspondence it was only asking about"
        );
    }

    /// The one correspondence label in a machine's store.
    fn sole_label(m: &DmMachine) -> CorrespondenceLabel {
        let labels = m.persist.store().correspondences().expect("list");
        assert_eq!(labels.len(), 1, "expected exactly one correspondence");
        labels[0]
    }

    /// A second identity, distinct from `keys()`, for the far end.
    fn peer_identity() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Device {
                uuid: uuid::Uuid::from_bytes([0x7Cu8; 16]),
            },
        )
        .expect("peer identity")
    }

    /// M20. Accepting a knock queues the acceptance at sequence zero, on the
    /// channel, in the same call.
    ///
    /// **The design fires this on acceptance, not on the first typed reply.**
    /// Until it lands the initiator holds a channel it can write to and cannot
    /// read — a channel frame carries no pseudonym key — so an acceptance that
    /// waited for a message would leave every silent acceptor invisible.
    ///
    /// The spent sequence number is the second half: seq 0 is the acceptor's
    /// first and only opening position, so a queued entry that did not come
    /// from a real ratchet step would leave the chain able to mint it twice.
    #[test]
    fn accepting_a_knock_queues_the_accept_at_sequence_zero() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        m.persist.provision_block_list().expect("provision");
        let epoch = keyrec::fc_epoch(unix_secs(BASE_MS));

        let effects = m.surface(BASE_MS, epoch, 1, hash(41), fake_knock(41), false);
        let DmEffect::Emit(DmEvent::ContactRequest { request, .. }) = &effects[0] else {
            panic!("the knock did not surface: {effects:?}");
        };
        let request = request.clone();

        let out = m.on_command(BASE_MS, DmCommand::Accept { request });
        let composed: Vec<u64> = out
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::Delivery {
                    seq,
                    state: DeliveryState::Composed,
                    ..
                }) => Some(*seq),
                _ => None,
            })
            .collect();
        assert_eq!(
            composed,
            vec![0],
            "accepting must compose exactly sequence zero, got {out:?}"
        );

        let label = sole_label(&m);
        let outbox = m
            .persist
            .read_outbox(&label, BASE_MS)
            .expect("the outbox reads")
            .expect("the acceptance is queued");
        assert_eq!(
            outbox.direction(),
            Direction::BToA,
            "the acceptance travels on the acceptor's own direction"
        );
        let entry = outbox.entry(0).expect("sequence zero is queued");
        assert_eq!(
            entry.target(),
            OutboxTarget::ChannelPage,
            "the acceptance is a channel frame, not a doorbell entry"
        );
        // The bytes are a real frame at sequence zero — not a placeholder that
        // would satisfy every assertion above.
        let parsed = frame::parse(entry.frame().expect("the entry holds its bytes"))
            .expect("the queued acceptance parses as a channel frame");
        assert_eq!(parsed.header().seq, 0);
        assert_eq!(
            m.only_next_send_seq(),
            Some(1),
            "sequence zero must have been spent by a real ratchet step"
        );
    }

    /// M21. A full outbox refuses the acceptance BEFORE the sequence number is
    /// spent.
    ///
    /// `Ratchet::send_next` has no step backwards, so a refusal taken after it
    /// burns the acceptor's only opening position: sequence zero would be gone,
    /// the initiator would never learn the pseudonym, and there is no
    /// second acceptance path. The unspent cursor afterwards is the whole
    /// assertion — the refusal event alone is satisfied by a machine that
    /// refused *after* stepping.
    #[test]
    fn a_full_outbox_refuses_the_accept_before_the_sequence_is_spent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let knock = fake_knock(42);
        let pk_lt: PkLt = Box::new(*knock.pk_lt());
        let peer_pk_pc = Box::new(*knock.pk_pc());
        let channel = ChannelRoots {
            chan_id: knock.roots().chan_id,
        };
        let address_root = knock.roots().ar;
        let (label, ratchet) = m
            .persist
            .accept_first_contact(*knock, &[0x71u8; oxicrypt_ml_dsa::SK_LEN], BASE_MS)
            .expect("the establish succeeds");
        m.correspondences.push(Correspondence {
            pk_lt,
            label,
            ratchet: Some(ratchet),
            signing_pc: Some(mint_pseudonym().expect("pseudonym")),
            peer_pk_pc: Some(peer_pk_pc),
            channel: Some(channel),
            address_root,
            candidate: None,
            re_acks_answered: 0,
            response_cap_surfaced: false,
            retire_ceiling_surfaced: false,
            leg_give_up_surfaced: false,
            peer_regression_surfaced: false,
            collection: Collection::new(),
            read_through: 0,
            cursor_unreadable: false,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            provisional: None,
            rearm_handshake: false,
            rearm_faults: 0,
            pseudonym_unwritten: false,
            pseudonym_faults: 0,
            resume_owed: false,
            resume_faults: 0,
            resume_retry_due_ms: None,
            resume_surfaced: false,
            resume_ceiling_surfaced: false,
        });
        assert_eq!(
            m.only_next_send_seq(),
            Some(0),
            "the acceptor's first channel position is zero"
        );

        // Filled from outside, at positions well above zero, so the refusal is
        // about capacity rather than about the sequence space.
        let mut filled = 0u64;
        for seq in 100..1_000u64 {
            let wrote = m
                .persist
                .update_outbox(&label, Direction::BToA, BASE_MS, |outbox| {
                    Ok(Mutation::Changed(
                        outbox
                            .enqueue_sealed(
                                seq,
                                OutboxTarget::ChannelPage,
                                BASE_MS,
                                SealedFrame::new(vec![0xA5; WORST_CASE_SEALED_FRAME_LEN]),
                                0,
                            )
                            .is_ok(),
                    ))
                });
            match wrote {
                Ok(true) => filled += 1,
                _ => break,
            }
        }
        assert!(filled > 50, "the record took only {filled} entries to fill");

        let out = m.fire_accept(BASE_MS, 0);
        assert!(
            out.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::OutboxFull { .. },
                    ..
                })
            )),
            "a full outbox must refuse the acceptance and say so, got {out:?}"
        );
        assert_eq!(
            m.only_next_send_seq(),
            Some(0),
            "the acceptance was refused after the ratchet had already stepped"
        );

        // **The same refusal, again, is silent.** The retry runs on every tick,
        // so a full record that stays full would otherwise repeat this pair for
        // as long as it takes to drain.
        assert!(
            m.fire_accept(BASE_MS, 0).is_empty(),
            "an unchanged refusal was reported twice"
        );

        // Sequence zero stays unspent, so the tick's retry keeps the
        // conversation recoverable — see
        // `an_uncomposed_acceptance_is_composed_by_the_next_tick`.
        let _ = &label;
    }

    /// M28. An acceptance that was never composed is composed by the next tick,
    /// exactly once.
    ///
    /// **`fire_accept` runs once, inside the accept, and every one of its
    /// refusals is recoverable.** Without a retry an acceptor whose store was
    /// briefly full keeps a conversation the initiator can write to and can
    /// never read, permanently and silently — the acceptance is the only frame
    /// carrying this side's pseudonym.
    ///
    /// **The condition is the unspent sequence, and the second tick is what
    /// pins it.** A retry keyed on the outbox ENTRY being absent would fire
    /// again the moment a give-up pruned it, composing a second acceptance at a
    /// sequence the peer has already been shown — so the second tick must find
    /// nothing to do, with the sequence now at one.
    #[test]
    fn an_uncomposed_acceptance_is_composed_by_the_next_tick() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let knock = fake_knock(45);
        let pk_lt: PkLt = Box::new(*knock.pk_lt());
        let peer_pk_pc = Box::new(*knock.pk_pc());
        let channel = ChannelRoots {
            chan_id: knock.roots().chan_id,
        };
        let address_root = knock.roots().ar;
        let (label, ratchet) = m
            .persist
            .accept_first_contact(*knock, &[0x71u8; oxicrypt_ml_dsa::SK_LEN], BASE_MS)
            .expect("the establish succeeds");
        // Established, and its acceptance never composed — the state a refused
        // `fire_accept` leaves behind.
        m.correspondences.push(Correspondence {
            pk_lt,
            label,
            ratchet: Some(ratchet),
            signing_pc: Some(mint_pseudonym().expect("pseudonym")),
            peer_pk_pc: Some(peer_pk_pc),
            channel: Some(channel),
            address_root,
            candidate: None,
            re_acks_answered: 0,
            response_cap_surfaced: false,
            retire_ceiling_surfaced: false,
            leg_give_up_surfaced: false,
            peer_regression_surfaced: false,
            collection: Collection::new(),
            read_through: 0,
            cursor_unreadable: false,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            provisional: None,
            rearm_handshake: false,
            rearm_faults: 0,
            pseudonym_unwritten: false,
            pseudonym_faults: 0,
            resume_owed: false,
            resume_faults: 0,
            resume_retry_due_ms: None,
            resume_surfaced: false,
            resume_ceiling_surfaced: false,
        });
        assert_eq!(
            m.only_next_send_seq(),
            Some(0),
            "the fixture must start with the acceptance uncomposed"
        );

        let out = m.due_emissions(BASE_MS, 0);
        assert_eq!(
            m.only_next_send_seq(),
            Some(1),
            "the tick did not compose the deferred acceptance: {out:?}"
        );
        assert!(
            out.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Delivery {
                    seq: 0,
                    state: DeliveryState::Composed,
                    ..
                })
            )),
            "the retry composed silently: {out:?}"
        );
        let queued = m
            .persist
            .read_outbox(&label, BASE_MS)
            .expect("the outbox reads")
            .expect("the outbox exists");
        assert_eq!(
            queued
                .entry(0)
                .expect("the acceptance is queued at sequence zero")
                .target(),
            OutboxTarget::ChannelPage
        );

        let again = m.due_emissions(BASE_MS, 0);
        assert_eq!(
            m.only_next_send_seq(),
            Some(1),
            "a second tick composed a second acceptance: {again:?}"
        );
        assert!(
            !again.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Delivery {
                    seq: 0,
                    state: DeliveryState::Composed,
                    ..
                })
            )),
            "a second tick re-announced the acceptance: {again:?}"
        );
    }

    /// M27. A provisional record the accept could not erase is erased on a
    /// later tick.
    ///
    /// **The handle is the only thing that can ever open the record again.** It
    /// names the epoch the record was sealed under, and a record opens under no
    /// other — so dropping it on a failed erase leaves the conversation's
    /// opening secret on disk permanently, from what may have been a moment's
    /// store fault. The mutual-knock branch re-points the entry at a different
    /// label, so the handle cannot simply stay on the correspondence either; it
    /// moves to the machine's retry list, keyed on the label it was written
    /// under.
    ///
    /// The fault here is real rather than mocked: the record's own bytes are
    /// corrupted, which is exactly `TeardownCause::RecordUnusable` — a
    /// statement about the ciphertext at this moment, not about whether the
    /// record exists. Restoring them is the store recovering.
    #[test]
    fn a_record_the_erase_could_not_reach_is_erased_on_a_later_tick() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let a_keys = keys();
        let b_keys = peer_identity();
        let mut a = machine(&dir_a);
        let mut b = machine_as(peer_identity(), &dir_b);
        a.persist.provision_block_list().expect("provision A");
        b.persist.provision_block_list().expect("provision B");

        let _a_knock = knock_as_initiator(&mut a, &b_keys);
        let b_knock = knock_as_initiator(&mut b, &a_keys);
        let files = provisional_files(&a);
        assert_eq!(files.len(), 1, "A must hold exactly one record to corrupt");
        let path = files[0].clone();
        let healthy = std::fs::read(&path).expect("the record reads");

        // The transient fault: the ciphertext no longer opens.
        let mut broken = healthy.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0xFF;
        std::fs::write(&path, &broken).expect("the record writes");

        // A accepts B's knock, which is where the erase is attempted.
        let out = a.on_doorbell(BASE_MS, sweep_of(vec![(b_knock.0, b_knock.1)]));
        let request = out
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("A was not offered B's knock");
        a.on_command(BASE_MS, DmCommand::Accept { request });

        assert_eq!(
            a.pending_erase.len(),
            1,
            "a record the erase could not reach was forgotten instead of queued"
        );
        assert!(
            path.exists(),
            "the fixture did not leave a record to retry against"
        );
        assert!(
            a.correspondences[0].provisional.is_none(),
            "the handle must have moved off the entry, whose label has changed"
        );

        // The store recovers, and the next tick finishes the job.
        std::fs::write(&path, &healthy).expect("the record is restored");
        a.due_emissions(BASE_MS, 0);
        assert!(
            a.pending_erase.is_empty(),
            "the retry did not clear the record it was holding"
        );
        assert!(
            !has_provisional(&a),
            "the conversation's opening secret is still on disk"
        );
    }

    /// Every `provisional.bin` under a machine's store root.
    fn provisional_files(m: &DmMachine) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(m.persist.store().root())
            .expect("the store root reads")
            .filter_map(|e| {
                let p = e.expect("a directory entry").path().join("provisional.bin");
                p.exists().then_some(p)
            })
            .collect()
    }

    /// Drive one machine through the whole outbound first-contact path, up to
    /// and including the mint, and hand back the knock it published.
    ///
    /// Nothing is faked: the key record is the one the far identity would
    /// publish, the entry is `firstcontact::build`'s, and the correspondence
    /// left behind is a genuine initiator with no pseudonym for its
    /// correspondent — which is the state every test below is about.
    fn knock_as_initiator(a: &mut DmMachine, peer: &IdentityKeys) -> (u16, Vec<u8>) {
        knock_as_initiator_at(a, peer, BASE_MS)
    }

    /// [`knock_as_initiator`] at a named instant, for a test that has to cross
    /// a first-contact epoch boundary.
    fn knock_as_initiator_at(
        a: &mut DmMachine,
        peer: &IdentityKeys,
        now_ms: i64,
    ) -> (u16, Vec<u8>) {
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());
        let out = a.on_command(
            now_ms,
            DmCommand::FirstContact {
                recipient: pk_lt.clone(),
                body: "knock".into(),
            },
        );
        assert!(
            matches!(&out[..], [DmEffect::Dht(DhtOp::FetchKeyRecord { .. })]),
            "the introduction did not ask for a key record: {out:?}"
        );
        let record = keyrec::build_encoded(
            &peer.signing,
            peer.kem.encapsulation_key(),
            keyrec::DM_KEY_RECORD_VERSION,
            keyrec::DM_KEY_RECORD_INVITE_ONLY,
        )
        .expect("key record");
        let mut out = a.on_key_record(now_ms, pk_lt, Some(record));
        assert_eq!(out.len(), 1, "the key record did not start a mint: {out:?}");
        let DmEffect::Compute(ComputeJob::MintFirstContact(request)) = out.remove(0) else {
            panic!("the key record did not start a mint");
        };
        let out = a.on_mint(now_ms, run_mint(*request));
        out.iter()
            .find_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishDoorbell { entry, slot, .. }) => {
                    Some((*slot, entry.clone()))
                }
                _ => None,
            })
            .expect("the mint did not publish a knock")
    }

    /// What the driver did with a fetched key record.
    #[derive(Debug, PartialEq, Eq)]
    enum Fetched {
        /// Verified, adopted, and the introduction went on to mint.
        Adopted,
        /// Refused, carrying the reason the front end was told.
        Refused(RefusalReason),
    }

    /// The rollback bound this session holds for `peer`, if it holds one.
    fn bound(m: &DmMachine, peer: &IdentityKeys) -> Option<u64> {
        m.key_records
            .iter()
            .find(|(pk, _)| pk.as_slice() == peer.signing.public_key().as_slice())
            .and_then(|(_, cache)| cache.version())
    }

    /// Serve one key record at `version` for `peer` and say what the driver did
    /// with it, leaving the machine able to fetch that identity again.
    ///
    /// The introduction carries a body over `DM_BODY_CAP`, so the mint a
    /// verified record starts refuses and the introduction is dropped with
    /// nothing written. That is what makes a second fetch reachable:
    /// `start_introduction` refuses an identity already in flight and one
    /// already holding a correspondence on disk, so a completed first contact
    /// never fetches again. The bound is written on the fetch, before the mint
    /// is asked for, so it is recorded either way.
    fn fetch_key_record(m: &mut DmMachine, peer: &IdentityKeys, version: u64) -> Fetched {
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());
        let out = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: pk_lt.clone(),
                body: "x".repeat(firstcontact::DM_BODY_CAP + 1),
            },
        );
        assert!(
            matches!(&out[..], [DmEffect::Dht(DhtOp::FetchKeyRecord { .. })]),
            "the introduction did not ask for a key record: {out:?}"
        );
        let record = keyrec::build_encoded(
            &peer.signing,
            peer.kem.encapsulation_key(),
            version,
            keyrec::DM_KEY_RECORD_INVITE_ONLY,
        )
        .expect("key record");
        let mut out = m.on_key_record(BASE_MS, pk_lt, Some(record));
        assert_eq!(out.len(), 1, "one fetch, one outcome: {out:?}");
        match out.remove(0) {
            DmEffect::Compute(ComputeJob::MintFirstContact(request)) => {
                let out = m.on_mint(BASE_MS, run_mint(*request));
                assert!(!out.is_empty(), "the mint said nothing at all");
                assert!(
                    out.iter().any(|e| matches!(
                        e,
                        DmEffect::Emit(DmEvent::Refused {
                            reason: RefusalReason::MintFailed,
                            ..
                        })
                    )),
                    "the over-cap body did not stop the mint: {out:?}"
                );
                Fetched::Adopted
            }
            DmEffect::Emit(DmEvent::Refused { reason, .. }) => Fetched::Refused(reason),
            other => panic!("the fetch was neither minted nor refused: {other:?}"),
        }
    }

    /// Design M1. A replayed pre-rotation record is authentic and is refused
    /// anyway, and the version the session verified stays where it was.
    #[test]
    fn a_replayed_older_key_record_is_refused_and_the_bound_holds() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let peer = peer_identity();

        assert_eq!(fetch_key_record(&mut m, &peer, 3), Fetched::Adopted);
        assert_eq!(bound(&m, &peer), Some(3));

        assert_eq!(
            fetch_key_record(&mut m, &peer, 2),
            Fetched::Refused(RefusalReason::KeyRecordRollback),
            "an older authentic record must not be sealed to"
        );
        assert_eq!(
            bound(&m, &peer),
            Some(3),
            "a refused record must not move the bound"
        );
    }

    /// A reader with no bound takes what it is served — the accepted M1
    /// residual — and version zero is an ordinary first sighting rather than a
    /// missing one.
    ///
    /// The second half is what makes the first half mean anything: having
    /// adopted zero, the machine bounds from zero. "Never verified" and
    /// "verified version zero" have to stay distinguishable, or a bound read as
    /// `unwrap_or(0)` would refuse the very record this adopts.
    #[test]
    fn a_cold_reader_adopts_version_zero_and_then_bounds_from_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let peer = peer_identity();
        assert!(
            m.key_records.is_empty(),
            "a fresh machine must hold no bound at all"
        );

        assert_eq!(fetch_key_record(&mut m, &peer, 0), Fetched::Adopted);
        assert_eq!(m.key_records.len(), 1, "one identity, one bound");
        assert_eq!(bound(&m, &peer), Some(0));

        assert_eq!(fetch_key_record(&mut m, &peer, 1), Fetched::Adopted);
        assert_eq!(bound(&m, &peer), Some(1));
        assert_eq!(
            fetch_key_record(&mut m, &peer, 0),
            Fetched::Refused(RefusalReason::KeyRecordRollback),
            "a bound of zero is a bound, not an absent one"
        );
        assert_eq!(bound(&m, &peer), Some(1));
    }

    /// One cache per correspondent, and the key is the whole of what makes it
    /// so: a `KeyRecordCache` holds no identity binding of its own, so a lookup
    /// that ignored the key would let one correspondent's rotation set the floor
    /// for everyone — refusing strangers whose records are perfectly good and
    /// leaking, through the refusal, that some other identity has rotated.
    #[test]
    fn each_correspondent_carries_its_own_bound() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let first = peer_identity();
        let second = other_peer_identity();
        assert_ne!(
            first.signing.public_key().as_slice(),
            second.signing.public_key().as_slice(),
            "the fixture is one identity twice, so it can prove nothing about keying"
        );

        assert_eq!(fetch_key_record(&mut m, &first, 5), Fetched::Adopted);
        assert_eq!(m.key_records.len(), 1);

        // The second identity's first record is its own cold read. The first
        // identity's higher bound must not reach across to it.
        assert_eq!(fetch_key_record(&mut m, &second, 2), Fetched::Adopted);
        assert_eq!(m.key_records.len(), 2, "two identities, two bounds");
        assert_eq!(bound(&m, &first), Some(5));
        assert_eq!(bound(&m, &second), Some(2));

        // And each refuses against its own floor, not the other's.
        assert_eq!(
            fetch_key_record(&mut m, &second, 1),
            Fetched::Refused(RefusalReason::KeyRecordRollback)
        );
        assert_eq!(
            fetch_key_record(&mut m, &first, 4),
            Fetched::Refused(RefusalReason::KeyRecordRollback)
        );
        assert_eq!(bound(&m, &first), Some(5));
        assert_eq!(bound(&m, &second), Some(2));
    }

    /// A rotation is what the bound exists to protect: the higher version is
    /// adopted, and the version that was good a moment ago is refused from then
    /// on.
    #[test]
    fn a_higher_version_advances_the_bound_and_the_old_one_is_then_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let peer = peer_identity();

        assert_eq!(fetch_key_record(&mut m, &peer, 3), Fetched::Adopted);
        assert_eq!(bound(&m, &peer), Some(3));
        assert_eq!(fetch_key_record(&mut m, &peer, 4), Fetched::Adopted);
        assert_eq!(bound(&m, &peer), Some(4));

        assert_eq!(
            fetch_key_record(&mut m, &peer, 3),
            Fetched::Refused(RefusalReason::KeyRecordRollback),
            "the version the rotation replaced must not come back"
        );
        assert_eq!(bound(&m, &peer), Some(4));
    }

    /// **The bound is this session's, and the residual that leaves is pinned
    /// here rather than implied.** The design's key-record section says readers
    /// "cache highest verified `version`, never regress (rollback M1 = a cold
    /// reader accepts an old authentic record; residual accepted for alpha)" —
    /// a restarted client is one of those cold readers, so the record its
    /// previous session refused is adopted without complaint. Nothing at rest
    /// carries the bound: the key record is fetched before a correspondence
    /// exists to hold it, and the contact record's five fixed-width fields are
    /// the store's whole bucket for that kind.
    #[test]
    fn the_bound_is_this_sessions_and_a_restart_takes_the_older_record_again() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();

        let mut first = machine(&dir);
        assert_eq!(fetch_key_record(&mut first, &peer, 3), Fetched::Adopted);
        assert_eq!(
            fetch_key_record(&mut first, &peer, 2),
            Fetched::Refused(RefusalReason::KeyRecordRollback)
        );
        drop(first);

        let mut restarted = machine(&dir);
        assert!(
            restarted.key_records.is_empty(),
            "a restarted machine must hold no bound"
        );
        assert_eq!(
            fetch_key_record(&mut restarted, &peer, 2),
            Fetched::Adopted,
            "the bound is session-scoped: a restart reads as a cold reader"
        );
        assert_eq!(bound(&restarted, &peer), Some(2));
    }

    /// Ask for an introduction and serve bytes that verify against nothing.
    ///
    /// The address is world-writable, so this is an ordinary input rather than
    /// an exceptional one: anyone at all can write the record.
    fn serve_unverifiable_key_record(m: &mut DmMachine, peer: &IdentityKeys) -> RefusalReason {
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());
        let out = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: pk_lt.clone(),
                body: "knock".into(),
            },
        );
        assert!(
            matches!(&out[..], [DmEffect::Dht(DhtOp::FetchKeyRecord { .. })]),
            "the introduction did not ask for a key record: {out:?}"
        );
        let mut out = m.on_key_record(BASE_MS, pk_lt, Some(vec![0xffu8; 64]));
        assert_eq!(out.len(), 1, "one fetch, one outcome: {out:?}");
        match out.remove(0) {
            DmEffect::Emit(DmEvent::Refused { reason, .. }) => reason,
            other => panic!("unverifiable bytes were not refused: {other:?}"),
        }
    }

    /// A fetch that verifies nothing leaves no bound behind.
    ///
    /// An entry is the record of a *verified* record, and the address anyone can
    /// write to is the same one this reads — so an entry created before the
    /// bytes were checked would be a list any stranger could grow, one identity
    /// per address they choose to write.
    #[test]
    fn a_fetch_that_does_not_verify_leaves_no_bound() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let peer = peer_identity();

        assert_eq!(
            serve_unverifiable_key_record(&mut m, &peer),
            RefusalReason::KeyRecordInvalid
        );
        assert_eq!(
            m.key_records.len(),
            0,
            "an unverifiable fetch must leave no bound"
        );

        // A record that does verify leaves exactly one entry, and a later bad
        // fetch neither duplicates it nor disturbs what it holds.
        assert_eq!(fetch_key_record(&mut m, &peer, 3), Fetched::Adopted);
        assert_eq!(m.key_records.len(), 1, "one identity, one entry");
        assert_eq!(
            serve_unverifiable_key_record(&mut m, &peer),
            RefusalReason::KeyRecordInvalid
        );
        assert_eq!(m.key_records.len(), 1, "a refused fetch must add no entry");
        assert_eq!(
            bound(&m, &peer),
            Some(3),
            "a refused fetch must not move the bound"
        );
    }

    /// A record that is not there refuses as the awaiting-key state, leaves no
    /// bound, and leaves the recipient introducible again.
    ///
    /// Absence is expected rather than exceptional — the record is retained by
    /// capacity only, so an owner offline long enough is evicted — and each half
    /// matters on its own: a bound recorded for an unanswered fetch would be a
    /// floor derived from nothing, and an introduction left in flight would
    /// refuse the user's retry as a duplicate of an attempt that already ended.
    #[test]
    fn a_missing_key_record_refuses_and_leaves_the_recipient_introducible() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let peer = peer_identity();
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());

        let out = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: pk_lt.clone(),
                body: "knock".into(),
            },
        );
        assert!(
            matches!(&out[..], [DmEffect::Dht(DhtOp::FetchKeyRecord { .. })]),
            "the introduction did not ask for a key record: {out:?}"
        );

        let mut out = m.on_key_record(BASE_MS, pk_lt.clone(), None);
        assert_eq!(out.len(), 1, "one fetch, one outcome: {out:?}");
        match out.remove(0) {
            DmEffect::Emit(DmEvent::Refused { reason, .. }) => assert_eq!(
                reason,
                RefusalReason::NoKeyRecord,
                "an absent record is the awaiting-key state, not a bad one"
            ),
            other => panic!("an absent record was not refused: {other:?}"),
        }
        assert_eq!(
            m.key_records.len(),
            0,
            "an unanswered fetch must leave no bound"
        );

        // The retry is a fresh introduction, not a duplicate of one still held.
        let out = m.on_command(
            BASE_MS,
            DmCommand::FirstContact {
                recipient: pk_lt,
                body: "knock".into(),
            },
        );
        assert!(
            matches!(&out[..], [DmEffect::Dht(DhtOp::FetchKeyRecord { .. })]),
            "a retry after an unanswered fetch must fetch again: {out:?}"
        );
    }

    /// A re-fetch of the same version is the ordinary case, not a rollback: the
    /// owner re-seeds the identical record against eviction on a slow schedule,
    /// so refusing it would refuse the record's own keep-alive.
    #[test]
    fn an_equal_version_re_fetch_is_adopted_and_the_bound_is_unmoved() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let peer = peer_identity();

        assert_eq!(fetch_key_record(&mut m, &peer, 3), Fetched::Adopted);
        assert_eq!(bound(&m, &peer), Some(3));
        assert_eq!(
            fetch_key_record(&mut m, &peer, 3),
            Fetched::Adopted,
            "a re-seed of the version already held must not read as a rollback"
        );
        assert_eq!(bound(&m, &peer), Some(3));
        assert_eq!(m.key_records.len(), 1, "one identity, one entry");
    }

    /// M22. An initiator that has not yet seen the acceptance still sweeps.
    ///
    /// The acceptance arrives BY sweep — it is an ordinary channel frame at the
    /// acceptor's sequence zero — so a probe that refused to plan while the
    /// pseudonym was unknown would be waiting for something only the sweep can
    /// deliver. The `SweepPage` effect is the whole assertion; the correspondence
    /// underneath it has `peer_pk_pc: None`, the state a pseudonym-gated probe
    /// would refuse to plan in.
    #[test]
    fn an_initiator_sweeps_before_it_knows_the_pseudonym() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let _ = knock_as_initiator(&mut m, &peer_identity());
        // The state under test: a live correspondence whose correspondent has
        // not yet said which key to verify against.
        assert!(
            m.correspondences[0].peer_pk_pc.is_none(),
            "a fresh initiator must not already hold a pseudonym"
        );

        let list = stored_block_list(&m);
        let out = m.probe(BASE_MS, 0, Some(&list));
        let swept: Vec<u64> = out
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::SweepPage { tag, .. }) => tag.page,
                _ => None,
            })
            .collect();
        assert!(
            !swept.is_empty(),
            "an initiator awaiting its acceptance must still sweep, got {out:?}"
        );
        assert!(
            swept.contains(&0),
            "the acceptance sits on page zero, so page zero must be planned: {swept:?}"
        );
        assert!(
            m.correspondences[0].peer_pk_pc.is_none(),
            "the fixture stopped being the case it was written for"
        );
    }

    /// The block list a tick would hand [`DmMachine::probe`], read from the
    /// store the machine is actually using.
    fn stored_block_list(m: &DmMachine) -> BlockList {
        m.persist.read_block_list().expect("the block list reads")
    }

    /// The path of the profile's block-list record.
    ///
    /// The name is `RecordKind::BlockList`'s and that accessor is crate-private
    /// to `daemonseed-core`, so it is spelled out here — with the file asserted
    /// present, which is what makes a rename fail this rather than silently
    /// turning "unreadable" into "the path was wrong".
    fn block_list_record(m: &DmMachine) -> std::path::PathBuf {
        let path = m.persist.store().root().join("block-list.bin");
        assert!(
            path.exists(),
            "the block-list record is not at {}",
            path.display()
        );
        path
    }

    /// The pages a batch of effects asked to sweep, in emission order.
    fn swept_pages(effects: &[DmEffect]) -> Vec<u64> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::SweepPage { tag, .. }) => tag.page,
                _ => None,
            })
            .collect()
    }

    /// One page sweep's outcome, as the shell would hand it back.
    fn page_outcome(
        conversation: [u8; AR_FINGERPRINT_LEN],
        page: u64,
        result: crate::Result<DhtResult>,
    ) -> DmOutcome {
        DmOutcome::Dht(DhtOutcome {
            kind: DhtOpKind::SweepPage,
            tag: OpTag::channel(conversation, None, Some(page)),
            result,
        })
    }

    /// A complete sweep of a page nothing has been written to.
    fn empty_page(conversation: [u8; AR_FINGERPRINT_LEN]) -> DhtResult {
        DhtResult::Page(DmPageSweep {
            conversation,
            slots: Vec::new(),
            outcome: crate::SweepOutcome {
                attempted: u32::from(PAGE_SLOTS),
                failed: 0,
                found: 0,
            },
        })
    }

    /// M22b. A page whose sweep is still in flight is not asked for again, and
    /// the sweep's outcome releases it however it ended.
    ///
    /// **The cadence is not a rate limit.** A page sweep is one read per subkey
    /// of the record, so on a real distributed hash table it routinely outlives
    /// several cadences — and a probe that planned the same page on every one of
    /// them would hold a stack of sweeps of one record open at once, each
    /// competing with the others for the same read permits.
    ///
    /// The first plan is the positive control: without it "the second plan asked
    /// for nothing" is satisfied by a probe that never planned anything at all.
    #[test]
    fn a_page_sweep_in_flight_is_not_asked_for_twice() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let _ = knock_as_initiator(&mut m, &peer_identity());
        let conversation = conversation_of(&m, 0);
        let list = stored_block_list(&m);

        let first = swept_pages(&m.probe(BASE_MS, 0, Some(&list)));
        assert_eq!(
            first,
            vec![0, 1],
            "the watched pair must be planned, or every assertion below is vacuous"
        );

        // The cadence has elapsed, so the plan is issued again — and every page
        // in it is one this machine is already waiting on.
        let second = swept_pages(&m.probe(BASE_MS + PROBE_MS, 0, Some(&list)));
        assert!(
            second.is_empty(),
            "a page already being swept must not be swept again: {second:?}"
        );

        // ── a sweep that came back releases its page ─────────────────────────
        m.on_outcome(
            BASE_MS + PROBE_MS,
            page_outcome(conversation, 0, Ok(empty_page(conversation))),
        );
        let third = swept_pages(&m.probe(BASE_MS + 2 * PROBE_MS, 0, Some(&list)));
        assert_eq!(
            third,
            vec![0],
            "the page whose sweep landed must be planned again, and only it"
        );

        // ── so does one that failed ──────────────────────────────────────────
        //
        // The expensive direction: a transport failure that left the slot held
        // would make this machine permanently deaf on page one, and nothing
        // about it would look wrong.
        m.on_outcome(
            BASE_MS + 2 * PROBE_MS,
            page_outcome(
                conversation,
                1,
                Err(crate::VeilidNetError::Actor("no route".into())),
            ),
        );
        let fourth = swept_pages(&m.probe(BASE_MS + 3 * PROBE_MS, 0, Some(&list)));
        assert_eq!(
            fourth,
            vec![1],
            "a failed sweep must release its page: {fourth:?}"
        );

        // ── and so does a sweep whose task died ──────────────────────────────
        //
        // The third way, and the only one that produces no outcome at all, which
        // is why the shell records the page at spawn.
        m.on_outcome(
            BASE_MS + 3 * PROBE_MS,
            DmOutcome::Panicked {
                job: Some(PanickedJob::PageSweep {
                    conversation,
                    page: 0,
                }),
            },
        );
        let fifth = swept_pages(&m.probe(BASE_MS + 4 * PROBE_MS, 0, Some(&list)));
        assert_eq!(
            fifth,
            vec![0],
            "a panicked sweep must release its page: {fifth:?}"
        );
    }

    /// The conversation and page of every sweep a batch of effects asked for.
    fn swept_channels(effects: &[DmEffect]) -> Vec<([u8; AR_FINGERPRINT_LEN], u64)> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::SweepPage { tag, .. }) => Some((tag.conversation?, tag.page?)),
                _ => None,
            })
            .collect()
    }

    /// Hand back an empty outcome for every sweep in `swept`, so the pages are
    /// no longer in flight and the next tick may plan them again.
    fn release_sweeps(m: &mut DmMachine, swept: &[([u8; AR_FINGERPRINT_LEN], u64)], now_ms: i64) {
        for (conversation, page) in swept {
            m.on_outcome(
                now_ms,
                page_outcome(*conversation, *page, Ok(empty_page(*conversation))),
            );
        }
    }

    /// M28. A blocked correspondent's channel stops being swept at the next
    /// tick, and an unblock resumes it at the tick after.
    ///
    /// **The second correspondence is the mirror control**, and without it the
    /// whole assertion is satisfied by a machine that stopped sweeping
    /// everything — which is exactly what the fail-closed path does when the
    /// list cannot be read. One blocked and one not, in one tick, separates
    /// suppression from silence.
    ///
    /// Nothing is torn down: the block writes one record and the tick reads it,
    /// so the resumption below needs no re-establishment, no second knock and no
    /// state the block had to keep.
    #[test]
    fn a_blocked_correspondence_is_not_swept_and_an_unblock_resumes_it() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;

        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_c = tempfile::tempdir().expect("temp dir C");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        let mut a = machine(&dir_a);
        let mut c = machine_as(third_identity(), &dir_c);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        establish_pair(&mut c, &mut b, &b_keys);
        assert_eq!(
            b.correspondences.len(),
            2,
            "the fixture needs one correspondence to block and one to leave alone"
        );
        let blocked_pk = *keys().signing.public_key();
        assert_eq!(
            b.correspondences[0].pk_lt.as_slice(),
            blocked_pk.as_slice(),
            "the fixture's correspondences are not in the order the assertions read them"
        );
        let blocked = conversation_of(&b, 0);
        let allowed = conversation_of(&b, 1);

        // ── the control: both are swept while nobody is blocked ──────────────
        let first = swept_channels(&b.on_tick(BASE_MS));
        assert!(
            first
                .iter()
                .any(|(conversation, _)| *conversation == blocked),
            "the correspondence about to be blocked was not swept to begin with: {first:?}"
        );
        assert!(
            first
                .iter()
                .any(|(conversation, _)| *conversation == allowed),
            "the control correspondence was not swept to begin with: {first:?}"
        );
        release_sweeps(&mut b, &first, BASE_MS);

        // ── blocked ──────────────────────────────────────────────────────────
        b.on_command(
            BASE_MS,
            DmCommand::Block {
                pk_lt: Box::new(blocked_pk),
            },
        );
        let second = swept_channels(&b.on_tick(BASE_MS + PROBE_MS));
        // Vacuous on its own if `second` is empty — the `allowed` assertion
        // below is what makes this one mean "one correspondence, not the plane".
        assert!(
            !second
                .iter()
                .any(|(conversation, _)| *conversation == blocked),
            "a blocked correspondent's channel was still swept: {second:?}"
        );
        assert!(
            second
                .iter()
                .any(|(conversation, _)| *conversation == allowed),
            "the block silenced the whole channel plane instead of one \
             correspondence: {second:?}"
        );
        // The correspondence is still there, whole: the design blocks reading,
        // not the record.
        assert_eq!(
            b.correspondences.len(),
            2,
            "the block tore a correspondence down"
        );
        assert!(
            b.correspondences[0].live().is_some(),
            "the block tore the blocked correspondence's channel down"
        );
        release_sweeps(&mut b, &second, BASE_MS + PROBE_MS);

        // ── unblocked ────────────────────────────────────────────────────────
        b.on_command(
            BASE_MS + PROBE_MS,
            DmCommand::Unblock {
                pk_lt: Box::new(blocked_pk),
            },
        );
        let third = swept_channels(&b.on_tick(BASE_MS + 2 * PROBE_MS));
        assert!(
            third
                .iter()
                .any(|(conversation, _)| *conversation == blocked),
            "an unblocked correspondent's channel was not swept again: {third:?}"
        );
    }

    /// A correspondence receiving nothing new still gets its wrecked cursor
    /// repaired, on the tick, and counted once.
    ///
    /// **The gap this closes.** The fold's repair runs only when the contiguous
    /// prefix moved, and a correspondence whose channel did not survive the
    /// restart folds no pages at all — so a wrecked record on a quiet
    /// correspondence stayed wrecked and uncounted for the life of the profile.
    /// The fixture is a cold start over an existing store, which is the only way
    /// the seed path runs.
    #[test]
    fn a_quiet_correspondence_has_its_wrecked_cursor_repaired_on_the_tick() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // A cursor record on disk, then wrecked in place.
        let label_b = b.correspondences[0].label;
        b.persist
            .store()
            .critical_section::<_, daemonseed_core::storage::dm_store::DmStoreError>(
                &label_b,
                |g| {
                    g.replace(
                        daemonseed_core::storage::dm_store::RecordKind::ReceiveCursor,
                        &0u64.to_be_bytes(),
                    )
                },
            )
            .expect("writes a cursor to wreck");
        let path = dir_b
            .path()
            .join("dm")
            .join(
                label_b
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
            .join("cursor.bin");
        let mut wrecked = std::fs::read(&path).expect("reads");
        let last = wrecked.len() - 1;
        wrecked[last] ^= 0xFF;
        std::fs::write(&path, &wrecked).expect("tampers with the record");
        drop(b);

        // Cold start over the same store: the seed reads the wrecked record.
        let mut restarted = machine_as(peer_identity(), &dir_b);
        assert_eq!(
            restarted.correspondences.len(),
            1,
            "the seed found no correspondence, so nothing below is about a cursor"
        );
        // Positive control: nothing has been repaired before the tick, and the
        // record really is unreadable.
        assert_eq!(
            restarted.correspondences[0].health.cursor_records_repaired, 0,
            "the seed repaired without a tick"
        );
        assert!(
            restarted.persist.read_cursor(&label_b, u64::MAX).is_err(),
            "the wrecked record still reads"
        );

        // No page is folded and no channel is live: the tick is the only path.
        let effects = restarted.on_tick(BASE_MS);
        assert_eq!(
            restarted.correspondences[0].health.cursor_records_repaired, 1,
            "the quiet correspondence's cursor was not repaired"
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::ChannelHealth {
                    cursor_records_repaired: 1,
                    ..
                })
            )),
            "the repair never reached a health event: {effects:?}"
        );
        assert!(
            restarted.persist.read_cursor(&label_b, u64::MAX).is_ok(),
            "the record is still unreadable after the repair"
        );
        // The cleared flag is what stops the next tick writing again, and the
        // "counted once" assertion below cannot see it: leaving the flag set
        // makes the second tick re-read a record that is healthy by then, take
        // an ordinary advance, and increment nothing — no repair, and no
        // evidence that one was not attempted.
        assert!(
            !restarted.correspondences[0].cursor_unreadable,
            "the flag survived the repair, so every tick re-reads the record"
        );

        // Release the doorbell sweep the first tick planned, so the next tick
        // has something of its own to emit. Without that, "no health event" is
        // satisfied by a tick that produced nothing at all — which is a tick
        // that says nothing about repairs.
        restarted.on_outcome(
            BASE_MS + 1,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::SweepDoorbell,
                tag: OpTag::none(),
                result: Ok(DhtResult::Doorbell(DoorbellSweep {
                    slots: Vec::new(),
                    outcome: crate::SweepOutcome {
                        attempted: 0,
                        failed: 0,
                        found: 0,
                    },
                })),
            }),
        );
        let again = restarted.on_tick(BASE_MS + 2);
        assert!(
            !again.is_empty(),
            "the second tick emitted nothing at all, so its lack of a health \
             event is not evidence about repairs"
        );
        assert_eq!(
            restarted.correspondences[0].health.cursor_records_repaired, 1,
            "the repair was counted twice"
        );
        assert!(
            !again
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ChannelHealth { .. }))),
            "a second health event fired for a repair that did not happen: {again:?}"
        );
    }

    /// A cold start over a healthy cursor that is *ahead* repairs nothing.
    ///
    /// **The mirror of the repair, and the one that stops it over-firing.** The
    /// seed reads with a `read_through` of zero — this session has swept nothing
    /// — so every stored page above zero comes back as
    /// `CursorNotCorroborated`. That is the ordinary case for a healthy profile,
    /// and treating it as a fault would rewrite a good cursor down to `START` on
    /// every boot, silently costing a full rescan and reporting a repair that
    /// repaired nothing. Nothing here is wrecked: the record is authentic, its
    /// number believable once this session has read that far, and the tick must
    /// leave it exactly as it is.
    #[test]
    fn a_cold_start_over_an_uncorroborated_cursor_repairs_nothing() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // A healthy cursor, genuinely earned: written with its own page as the
        // corroboration, exactly as a session that had swept that far would.
        let label_b = b.correspondences[0].label;
        assert!(
            b.persist
                .advance_cursor(&label_b, 9, 9)
                .expect("advances")
                .moved(),
            "the fixture cursor did not advance, so nothing below is about one"
        );
        let on_disk = std::fs::read(
            dir_b
                .path()
                .join("dm")
                .join(
                    label_b
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                )
                .join("cursor.bin"),
        )
        .expect("reads");
        drop(b);

        let mut restarted = machine_as(peer_identity(), &dir_b);
        assert_eq!(restarted.correspondences.len(), 1, "the seed found nothing");
        // Positive control on the fixture: at a cold start this healthy record
        // IS refused, and refused as uncorroborated rather than as unreadable —
        // which is exactly the confusion this test exists to catch.
        let err = restarted
            .persist
            .read_cursor(&label_b, 0)
            .expect_err("a page above zero cannot be corroborated by a fresh session");
        assert!(
            matches!(
                err,
                DmPersistError::CursorNotCorroborated { read_through: 0 }
            ),
            "got {err:?}"
        );
        assert!(
            !restarted.correspondences[0].cursor_unreadable,
            "an uncorroborated cursor was flagged as unreadable"
        );

        let effects = restarted.on_tick(BASE_MS);
        assert_eq!(
            restarted.correspondences[0].health.cursor_records_repaired, 0,
            "a healthy cursor was repaired"
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ChannelHealth { .. }))),
            "a health event fired for a repair that must not have happened: {effects:?}"
        );
        assert_eq!(
            std::fs::read(
                dir_b
                    .path()
                    .join("dm")
                    .join(
                        label_b
                            .as_bytes()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>(),
                    )
                    .join("cursor.bin"),
            )
            .expect("reads"),
            on_disk,
            "the record was rewritten"
        );
        // And it is still believed by a session that has read that far.
        assert_eq!(
            restarted
                .persist
                .read_cursor(&label_b, 9)
                .expect("reads")
                .map(|c| c.page()),
            Some(9),
            "the healthy cursor did not survive the tick"
        );
    }

    /// An unreadable `cursor.bin` is repaired on the fold that would advance it,
    /// counted, and counted once.
    ///
    /// **The wedge without it.** The advance reads inside its own critical
    /// section, so a record that will not read fails the write too: the bad bytes
    /// stay, and every later session rescans from page zero and finds every frame
    /// already consumed. Both wreck shapes are driven — a tampered full-width
    /// record and a clear eight-byte one — because they fail at different checks.
    #[test]
    fn an_unreadable_receive_cursor_is_repaired_and_counted_once() {
        for (name, clear) in [("tampered", false), ("clear eight bytes", true)] {
            let dir_a = tempfile::tempdir().expect("temp dir A");
            let dir_b = tempfile::tempdir().expect("temp dir B");
            let mut a = machine(&dir_a);
            let b_keys = peer_identity();
            let mut b = machine_as(peer_identity(), &dir_b);
            b.persist.provision_block_list().expect("provision");
            establish_pair(&mut a, &mut b, &b_keys);

            a.on_command(
                BASE_MS,
                DmCommand::Send {
                    to: Box::new(*b_keys.signing.public_key()),
                    body: "one".into(),
                },
            );
            let label_a = sole_label(&a);
            let frame = queued_frame(&a, &label_a, 1);
            let conversation = conversation_of(&b, 0);

            // A cursor record for B's correspondence, then wrecked in place.
            let label_b = b.correspondences[0].label;
            b.persist
                .store()
                .critical_section::<_, daemonseed_core::storage::dm_store::DmStoreError>(
                    &label_b,
                    |g| {
                        g.replace(
                            daemonseed_core::storage::dm_store::RecordKind::ReceiveCursor,
                            &0u64.to_be_bytes(),
                        )
                    },
                )
                .expect("writes a cursor to wreck");
            let path = b
                .persist
                .store()
                .root()
                .join(
                    label_b
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                )
                .join("cursor.bin");
            let good = std::fs::read(&path).expect("reads");
            if clear {
                std::fs::write(&path, 4_096u64.to_be_bytes()).expect("plants a clear cursor");
            } else {
                let mut wrecked = good.clone();
                let last = wrecked.len() - 1;
                wrecked[last] ^= 0xFF;
                std::fs::write(&path, &wrecked).expect("tampers with the record");
            }
            // Positive control: the record really is unreadable, so the repair
            // below is a repair and not a no-op.
            assert!(
                b.persist.read_cursor(&label_b, u64::MAX).is_err(),
                "{name}: the wrecked record still reads"
            );

            let effects = fold_page(&mut b, conversation, 0, vec![(position_of(1), frame)]);
            assert_eq!(
                b.correspondences[0].health.cursor_records_repaired, 1,
                "{name}: the repair was not counted"
            );
            assert!(
                effects.iter().any(|e| matches!(
                    e,
                    DmEffect::Emit(DmEvent::ChannelHealth {
                        cursor_records_repaired: 1,
                        ..
                    })
                )),
                "{name}: the repair never reached a health event: {effects:?}"
            );
            assert!(
                b.persist.read_cursor(&label_b, u64::MAX).is_ok(),
                "{name}: the record is still unreadable"
            );

            // Counted once: the next fold over a healthy record adds nothing.
            let before = b.correspondences[0].health.cursor_records_repaired;
            let _ = fold_page(&mut b, conversation, 0, Vec::new());
            assert_eq!(
                b.correspondences[0].health.cursor_records_repaired, before,
                "{name}: the repair was counted twice"
            );
        }
    }

    /// M29. A page outcome that arrives for a correspondence blocked since its
    /// sweep was asked for surfaces nothing and settles nothing.
    ///
    /// **The sweep-time check cannot cover this**, and the window is the one a
    /// user is most likely to be inside: a block landing between the plan and
    /// its outcome would otherwise surface the messages it was meant to stop.
    ///
    /// Settling nothing is the second half and the one with a consequence. A
    /// dropped position that had been settled would be lost for good — the
    /// collection never revisits a settled position — so the unblocked fold at
    /// the end is what proves the frames were only dropped. The first fold is
    /// the control: without it, "no message" is satisfied by a fixture whose
    /// frame never opened at all.
    #[test]
    fn a_page_arriving_after_a_block_surfaces_nothing_and_settles_nothing() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "read after the block".into(),
            },
        );
        let label_a = sole_label(&a);
        let frame = queued_frame(&a, &label_a, 1);
        let conversation = conversation_of(&b, 0);
        let blocked_pk = *keys().signing.public_key();

        b.on_command(
            BASE_MS,
            DmCommand::Block {
                pk_lt: Box::new(blocked_pk),
            },
        );
        let settled_before = b.correspondences[0].collection.contiguous_through();
        let dropped = fold_page(
            &mut b,
            conversation,
            0,
            vec![(position_of(1), frame.clone())],
        );
        assert!(
            messages_in(&dropped).is_empty(),
            "a blocked correspondent's page surfaced a message: {dropped:?}"
        );
        assert_eq!(
            b.correspondences[0].collection.contiguous_through(),
            settled_before,
            "the dropped page settled a position, so an unblock can never \
             re-collect it"
        );
        assert!(
            b.correspondences[0].owed_acks.is_empty(),
            "the dropped page owed an acknowledgement for a message nobody saw"
        );

        // ── unblocked: the same bytes, from the same record ──────────────────
        b.on_command(
            BASE_MS,
            DmCommand::Unblock {
                pk_lt: Box::new(blocked_pk),
            },
        );
        let surfaced = fold_page(&mut b, conversation, 0, vec![(position_of(1), frame)]);
        assert_eq!(
            messages_in(&surfaced),
            vec!["read after the block".to_string()],
            "the unblocked fold did not recover the message the block dropped: \
             {surfaced:?}"
        );
    }

    /// M30. An unreadable block list sweeps no channel at all.
    ///
    /// The doorbell plane already fails closed here, for the reason that governs
    /// both: a revocation list read as "nobody is blocked" is silent unblocking.
    /// The channel plane costs the same to get wrong and is the plane a block
    /// lands on for an established correspondent.
    ///
    /// The first tick is the positive control, and the store read afterwards is
    /// the second: without them, "no sweeps" is satisfied by a fixture that had
    /// no live correspondence and by a record that was never actually broken.
    #[test]
    fn an_unreadable_block_list_sweeps_no_channel() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;

        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let readable = b.on_tick(BASE_MS);
        let first = swept_channels(&readable);
        assert!(
            !first.is_empty(),
            "the fixture swept nothing while its list was readable, so the \
             assertion below would hold for the wrong reason"
        );
        assert!(
            !ack_fetches_in(&readable).is_empty(),
            "the fixture asked for no acknowledgement while its list was \
             readable, so the fetch assertion below would hold for the wrong \
             reason: {readable:?}"
        );
        release_sweeps(&mut b, &first, BASE_MS);

        let record = block_list_record(&b);
        std::fs::remove_file(&record).expect("remove the block-list record");
        assert!(
            b.persist.read_block_list().is_err(),
            "removing the record did not make the list unreadable"
        );

        let effects = b.on_tick(BASE_MS + PROBE_MS);
        let second = swept_channels(&effects);
        assert!(
            second.is_empty(),
            "an unreadable block list swept a channel anyway: {second:?}"
        );
        assert!(
            ack_fetches_in(&effects).is_empty(),
            "an unreadable block list fetched an acknowledgement anyway: {effects:?}"
        );
        // Exactly one, not at least one: a blind plane has to be reported, and a
        // report per correspondence would grow with the contact list.
        assert_eq!(
            effects
                .iter()
                .filter(|e| matches!(e, DmEffect::Emit(DmEvent::BlockListUnreadable)))
                .count(),
            1,
            "a tick that could not read its block list must say so once: {effects:?}"
        );
    }

    /// The conversations named by every acknowledgement fetch in a batch of
    /// effects.
    fn ack_fetches_in(effects: &[DmEffect]) -> Vec<[u8; AR_FINGERPRINT_LEN]> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::FetchAck { tag, .. }) => tag.conversation,
                _ => None,
            })
            .collect()
    }

    /// M31. A blocked correspondent's acknowledgement record is neither fetched
    /// nor folded.
    ///
    /// **An acknowledgement is a read of their record**, so the plane the design
    /// closes covers it: folding one settles this side's outbox and reports
    /// `ConfirmedCollected` for a party the user has refused. The record arriving
    /// anyway is the in-flight case — the fetch was decided a tick before the
    /// block — and it is dropped rather than refused, so the unfolded claim is
    /// still good after an unblock.
    ///
    /// The tick before the block is the control on the fetch, and the fold after
    /// the unblock is the control on the drop: without them, "nothing was
    /// fetched" holds for a conversation with nothing outstanding and "nothing
    /// settled" holds for a record that never verified.
    #[test]
    fn a_blocked_correspondents_acknowledgement_is_not_fetched_or_folded() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;

        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "the message the acknowledgement would settle".into(),
            },
        );
        let conversation = conversation_of(&a, 0);
        let blocked_pk = *b_keys.signing.public_key();
        let label_a = sole_label(&a);

        // ── the control: an outstanding entry is asked about ─────────────────
        let first = a.on_tick(BASE_MS);
        assert_eq!(
            ack_fetches_in(&first),
            vec![conversation],
            "the fixture asked for no acknowledgement to begin with: {first:?}"
        );
        release_sweeps(&mut a, &swept_channels(&first), BASE_MS);

        // ── blocked: nothing is asked for ────────────────────────────────────
        a.on_command(
            BASE_MS,
            DmCommand::Block {
                pk_lt: Box::new(blocked_pk),
            },
        );
        let second = a.on_tick(BASE_MS + PROBE_MS);
        assert!(
            ack_fetches_in(&second).is_empty(),
            "a blocked correspondent's acknowledgement record was fetched: {second:?}"
        );

        // ── and one that arrives anyway settles nothing ──────────────────────
        let record = ack_record_from(&b, 0, &[1]);
        let dropped = ack_fetched(&mut a, BASE_MS + PROBE_MS, conversation, record.clone());
        assert!(
            !deliveries_in(&dropped)
                .iter()
                .any(|(_, state)| *state == DeliveryState::ConfirmedCollected),
            "a blocked correspondent's acknowledgement was folded: {dropped:?}"
        );
        assert_ne!(
            outbox_state(&a, &label_a, 1, BASE_MS + PROBE_MS),
            DeliveryState::ConfirmedCollected,
            "the dropped acknowledgement settled the outbox anyway"
        );

        // ── unblocked: the same record, folded ───────────────────────────────
        a.on_command(
            BASE_MS + PROBE_MS,
            DmCommand::Unblock {
                pk_lt: Box::new(blocked_pk),
            },
        );
        let folded = ack_fetched(&mut a, BASE_MS + PROBE_MS, conversation, record);
        assert!(
            deliveries_in(&folded)
                .iter()
                .any(|(seq, state)| *seq == 1 && *state == DeliveryState::ConfirmedCollected),
            "the unblocked fold did not settle the sequence the block deferred: {folded:?}"
        );
    }

    /// M32. An unreadable block list folds no page.
    ///
    /// The sweep-time refusal and this one are separate branches: a page whose
    /// sweep was planned while the list was readable still arrives, and folding
    /// it would read a record the plane has just been forbidden to read. The
    /// repaired fold at the end is the control on both halves — it shows the
    /// frame was dropped rather than settled, and that the fixture's frame opens
    /// at all.
    #[test]
    fn an_unreadable_block_list_folds_no_page() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "folded only once the list reads".into(),
            },
        );
        let label_a = sole_label(&a);
        let frame = queued_frame(&a, &label_a, 1);
        let conversation = conversation_of(&b, 0);

        let record = block_list_record(&b);
        let healthy = record.with_extension("held");
        std::fs::copy(&record, &healthy).expect("keep the healthy record");
        std::fs::remove_file(&record).expect("remove the block-list record");
        assert!(
            b.persist.read_block_list().is_err(),
            "removing the record did not make the list unreadable"
        );

        let settled_before = b.correspondences[0].collection.contiguous_through();
        let dropped = fold_page(
            &mut b,
            conversation,
            0,
            vec![(position_of(1), frame.clone())],
        );
        assert!(
            messages_in(&dropped).is_empty(),
            "a page folded while the block list was unreadable: {dropped:?}"
        );
        assert_eq!(
            b.correspondences[0].collection.contiguous_through(),
            settled_before,
            "the dropped page settled a position the fold never surfaced"
        );

        // Repaired, and the same bytes fold.
        std::fs::rename(&healthy, &record).expect("repair the record");
        let surfaced = fold_page(&mut b, conversation, 0, vec![(position_of(1), frame)]);
        assert_eq!(
            messages_in(&surfaced),
            vec!["folded only once the list reads".to_string()],
            "the repaired fold did not recover the message: {surfaced:?}"
        );
    }

    /// M33. An unreadable block list folds no acknowledgement.
    ///
    /// The sibling of `an_unreadable_block_list_folds_no_page` on the other fold
    /// path, and a separate branch from the fetch refusal: a fetch decided while
    /// the list was readable still returns, and folding what it returns would
    /// settle this side's outbox off a read the plane has just been forbidden to
    /// make. The repaired fold is the control on both halves — it shows the
    /// record was dropped rather than consumed, and that the fixture's record
    /// verifies at all.
    #[test]
    fn an_unreadable_block_list_folds_no_acknowledgement() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "settled only once the list reads".into(),
            },
        );
        let label_a = sole_label(&a);
        let conversation = conversation_of(&a, 0);
        let record = ack_record_from(&b, 0, &[1]);

        let stored = block_list_record(&a);
        let healthy = stored.with_extension("held");
        std::fs::copy(&stored, &healthy).expect("keep the healthy record");
        std::fs::remove_file(&stored).expect("remove the block-list record");
        assert!(
            a.persist.read_block_list().is_err(),
            "removing the record did not make the list unreadable"
        );

        let dropped = ack_fetched(&mut a, BASE_MS, conversation, record.clone());
        assert!(
            !deliveries_in(&dropped)
                .iter()
                .any(|(_, state)| *state == DeliveryState::ConfirmedCollected),
            "an acknowledgement folded while the block list was unreadable: {dropped:?}"
        );
        assert_ne!(
            outbox_state(&a, &label_a, 1, BASE_MS),
            DeliveryState::ConfirmedCollected,
            "the dropped acknowledgement settled the outbox anyway"
        );

        // Repaired, and the same record folds.
        std::fs::rename(&healthy, &stored).expect("repair the record");
        let folded = ack_fetched(&mut a, BASE_MS, conversation, record);
        assert!(
            deliveries_in(&folded)
                .iter()
                .any(|(seq, state)| *seq == 1 && *state == DeliveryState::ConfirmedCollected),
            "the repaired fold did not settle the sequence: {folded:?}"
        );
    }

    /// M23. The initiator's provisional record survives the mint and every
    /// unverified frame, and is erased by a verified acceptance — nothing
    /// earlier.
    ///
    /// **This is the timing the frozen design names, and it is easy to get
    /// wrong.** `{ss0, the opening ephemeral DK}` is what a restart in the
    /// knock-to-acceptance window resumes from, and without the ephemeral DK
    /// this side cannot decapsulate the acceptor's first generation ciphertext
    /// — so consuming the record at the mint strands the channel over exactly
    /// the interval the record exists for.
    ///
    /// Three readings, in order, each one the control on the next: after the
    /// mint the handshake still resumes; after a frame that does NOT verify it
    /// still resumes; after the real acceptance it does not. Without the middle
    /// one, "erased by the acceptance" is satisfied by anything at all arriving.
    #[test]
    fn a_knock_leaves_the_provisional_record_until_the_accept_opens() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        let b_pk_lt: PkLt = Box::new(*b_keys.signing.public_key());

        // ── A knocks ──────────────────────────────────────────────────────
        let entry = knock_as_initiator(&mut a, &b_keys);
        let _ = &b_pk_lt;

        let label_a = sole_label(&a);
        let ctx_a = a.correspondences[0]
            .provisional
            .expect("the initiator must be holding its record's context");
        let resumes = |a: &DmMachine| {
            matches!(
                a.persist.restart_channel(
                    &label_a,
                    &RecordContext {
                        recipient_keyrec_addr: &ctx_a.0,
                        fc_epoch: ctx_a.1,
                    },
                ),
                StoredChannelRestart::HandshakeResumes(_)
            )
        };
        assert!(
            resumes(&a),
            "the mint consumed the record the acceptance window needs"
        );

        let conversation = *a.correspondences[0]
            .ratchet
            .as_ref()
            .expect("A's ratchet")
            .ar_fingerprint();

        // ── B admits the knock and accepts, which composes the acceptance ──
        let out = b.on_doorbell(BASE_MS, sweep_of(vec![(entry.0, entry.1)]));
        let request = out
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("B was not offered the knock");
        b.on_command(BASE_MS, DmCommand::Accept { request });
        let label_b = sole_label(&b);
        let accept_bytes = queued_frame(&b, &label_b, 0);

        // ── a FORGED acceptance reaches the open path and changes nothing ──
        //
        // B's real acceptance with one byte of its seal flipped: it parses, the
        // ratchet accepts the position, and the AEAD refuses it inside the
        // closure. That is the only shape on which "the record was not erased"
        // is a claim about the commit rather than about `parse` — random bytes
        // never get that far.
        let forged = fold_page(
            &mut a,
            conversation,
            0,
            vec![(position_of(0), tampered(&accept_bytes))],
        );
        assert!(
            messages_in(&forged).is_empty(),
            "a forged acceptance produced a message: {forged:?}"
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_none(),
            "a forged acceptance installed a pseudonym"
        );
        assert!(
            resumes(&a),
            "a forged acceptance erased the record only a verified one may erase"
        );
        assert!(
            a.correspondences[0].provisional.is_some(),
            "a forged acceptance dropped the handle to the record"
        );

        // ── A collects the real one, installs, and erases the record ──────
        // The slot the forgery occupied was left unsettled, which is what lets
        // the genuine frame be offered at the same position afterwards.
        let out = fold_page(
            &mut a,
            conversation,
            0,
            vec![(position_of(0), accept_bytes.clone())],
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_some(),
            "the acceptance did not install a pseudonym: {out:?}"
        );
        assert_eq!(
            messages_in(&out),
            vec![String::new()],
            "the acceptance must surface once, with an empty body: {out:?}"
        );
        assert!(
            !resumes(&a),
            "the provisional record survived a verified acceptance"
        );
        assert!(
            a.correspondences[0].provisional.is_none(),
            "the correspondence still names a record that is gone"
        );

        // ── the sender re-seeds it, and nothing happens twice ─────────────
        //
        // A sender re-seeds until acknowledged, so these exact bytes come back
        // on every sweep. **The settled set is what stops them, not the
        // ratchet**: `Collection::observe_page` filters a position it has
        // already settled out of the unsettled list, so the frame is never
        // offered to the ratchet a second time and `already_consumed` does NOT
        // move — the counter that would move if the filter were removed. And
        // the erase is not re-attempted, because the handle is already gone.
        let consumed_before = a.correspondences[0].health.already_consumed;
        let again = fold_page(
            &mut a,
            conversation,
            0,
            vec![(position_of(0), accept_bytes)],
        );
        assert!(
            messages_in(&again).is_empty(),
            "the acceptance surfaced twice under a re-seed: {again:?}"
        );
        assert!(
            !again
                .iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::Refused { .. }))),
            "a re-seeded acceptance was refused: {again:?}"
        );
        assert_eq!(
            a.correspondences[0].health.already_consumed, consumed_before,
            "the settled set must filter the re-seed before the ratchet sees it"
        );
        assert!(
            a.correspondences[0].provisional.is_none(),
            "a re-seed re-armed the record handle"
        );
        assert!(!resumes(&a), "a re-seed resurrected the record");
    }

    /// M24. Before the acceptance, a frame at any later sequence is left
    /// unsettled and counted — never opened, never abandoned.
    ///
    /// **The branch this covers had no test.** An initiator holds no pseudonym
    /// until the acceptance lands, so B's ordinary reply at sequence one is
    /// unverifiable when it arrives: page owner-write authority is symmetric,
    /// so opening it would be trusting bytes anyone able to write the page
    /// could have put there. It is left in place for the sweep after the
    /// acceptance.
    ///
    /// **The second fold is the positive control, and it is what makes the
    /// first assertion mean "not yet" rather than "never".** Without it a
    /// machine that discarded the frame outright, or one that settled the slot,
    /// would pass — and the message would be lost with nothing saying so.
    #[test]
    fn a_reply_before_the_acceptance_is_left_unsettled_and_counted() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");

        let entry = knock_as_initiator(&mut a, &b_keys);
        let conversation = *a.correspondences[0]
            .ratchet
            .as_ref()
            .expect("A's ratchet")
            .ar_fingerprint();

        let out = b.on_doorbell(BASE_MS, sweep_of(vec![(entry.0, entry.1)]));
        let request = out
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("B was not offered the knock");
        b.on_command(BASE_MS, DmCommand::Accept { request });
        b.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*a.identity.signing.public_key()),
                body: "before you know me".into(),
            },
        );
        let label_b = sole_label(&b);
        let accept_bytes = queued_frame(&b, &label_b, 0);
        let reply_bytes = queued_frame(&b, &label_b, 1);

        // ── the reply alone, with no pseudonym installed ──────────────────
        let before = a.correspondences[0].health.peer_pseudonym_unknown;
        let out = fold_page(
            &mut a,
            conversation,
            0,
            vec![(position_of(1), reply_bytes.clone())],
        );
        assert!(
            messages_in(&out).is_empty(),
            "a frame this side cannot verify was opened anyway: {out:?}"
        );
        assert_eq!(
            a.correspondences[0].health.peer_pseudonym_unknown,
            before + 1,
            "the refusal must be counted once for the position it left alone"
        );
        assert_eq!(
            a.correspondences[0].health.unopenable, 0,
            "a frame refused as pending is not a frame that failed to open"
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_none(),
            "the fixture stopped being the case it was written for"
        );

        // ── the acceptance lands, then the same frame is offered again ────
        let out = fold_page(
            &mut a,
            conversation,
            0,
            vec![(position_of(0), accept_bytes)],
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_some(),
            "the acceptance did not install a pseudonym: {out:?}"
        );
        let out = fold_page(&mut a, conversation, 0, vec![(position_of(1), reply_bytes)]);
        assert_eq!(
            messages_in(&out),
            vec!["before you know me".to_string()],
            "the slot the refusal left unsettled was not retried: {out:?}"
        );
    }

    /// M25. A mutual knock leaves no provisional record behind, on either side.
    ///
    /// **Two ways in and one conversation.** Each side knocks the other before
    /// either has answered, so each holds a provisional record from its own
    /// introduction AND accepts the other's knock. Two things could strand
    /// `{ss0, the opening ephemeral DK}` on disk: the accept overwriting the
    /// entry's label while its record still lives under the old one, and a
    /// mint landing on top of a correspondence a pseudonym is already installed
    /// for — after which `on_page`'s erase, which runs only when it installs
    /// one, can never reach it.
    ///
    /// The record is the conversation's opening secret; `ss0` roots `RK0`, and
    /// erasing it is the premise under which the steady-state ratchet is never
    /// persisted at all. One left behind is that claim inverted, permanently
    /// and silently.
    #[test]
    fn a_mutual_knock_leaves_no_provisional_record_on_either_side() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let a_keys = keys();
        let b_keys = peer_identity();
        let mut a = machine(&dir_a);
        let mut b = machine_as(peer_identity(), &dir_b);
        a.persist.provision_block_list().expect("provision A");
        b.persist.provision_block_list().expect("provision B");

        // Both knock, neither has answered.
        let a_knock = knock_as_initiator(&mut a, &b_keys);
        let b_knock = knock_as_initiator(&mut b, &a_keys);
        assert!(
            has_provisional(&a) && has_provisional(&b),
            "the fixture must start with a record on each side"
        );

        // Both accept, each other's.
        for (m, knock) in [(&mut a, b_knock), (&mut b, a_knock)] {
            let out = m.on_doorbell(BASE_MS, sweep_of(vec![(knock.0, knock.1)]));
            let request = out
                .iter()
                .find_map(|e| match e {
                    DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => {
                        Some(request.clone())
                    }
                    _ => None,
                })
                .expect("the knock was not offered");
            m.on_command(BASE_MS, DmCommand::Accept { request });
        }

        for (name, m) in [("A", &a), ("B", &b)] {
            assert_eq!(
                m.correspondence_count(),
                1,
                "{name} holds more than one entry for one identity"
            );
            assert!(
                m.correspondences[0].provisional.is_none(),
                "{name} still names a provisional record after accepting"
            );
            assert!(
                m.correspondences[0].peer_pk_pc.is_some(),
                "{name} did not install the pseudonym its accept carried"
            );
            assert!(
                !has_provisional(m),
                "{name} left the conversation's opening secret on disk"
            );
        }
    }

    /// M26. A knock this driver sent is on disk under the recipient's identity
    /// key before the entry is published, and a restart finds it there.
    ///
    /// **The entry the driver publishes names nothing the acceptance can be
    /// routed by.** An acceptance arrives carrying the correspondent's identity
    /// key and nothing else this side knows, and the only path from that key to
    /// a correspondence is a contact record — so an initiator that wrote none
    /// until the acceptance verified would, after a restart, have no
    /// correspondence to collect it into. The correspondent's messages then
    /// re-emit until the outbox gives up on them, seven days later, and are
    /// surfaced to them as undelivered.
    ///
    /// The record carries no pseudonym, and the restarted correspondence does
    /// not either: that absence is what tells the page sweep only the
    /// acceptance may be opened. The acceptance is then delivered to the
    /// restarted driver and collected, which is the whole of what the
    /// correspondent's queued messages wait on.
    #[test]
    fn a_knock_survives_a_restart_and_collects_the_acceptance_it_was_waiting_for() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let peer = peer_identity();
        let peer_pk = *peer.signing.public_key();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision B");

        let (label, acceptance) = {
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let entry = knock_as_initiator(&mut a, &peer);

            let label = a
                .persist
                .correspondence_for_pk_lt(&peer_pk)
                .expect("lookup")
                .expect("the knock recorded no correspondence for its recipient");
            assert_eq!(
                label, a.correspondences[0].label,
                "the record is under a label this driver does not hold"
            );
            let record = a
                .persist
                .read_contact(&label)
                .expect("reads")
                .expect("a record");
            assert_eq!(record.pk_lt().as_slice(), peer_pk.as_slice());
            assert_eq!(
                record.pk_pc(),
                None,
                "the initiator recorded a pseudonym it cannot know yet"
            );
            assert_eq!(
                record.address_root(),
                a.correspondences[0].address_root,
                "the record addresses a channel this driver is not using"
            );
            // The correspondent answers while this side is still running, so
            // the acceptance is waiting on their pages when it comes back.
            let offered = b.on_doorbell(BASE_MS, sweep_of(vec![entry]));
            let request = offered
                .iter()
                .find_map(|e| match e {
                    DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => {
                        Some(request.clone())
                    }
                    _ => None,
                })
                .expect("the correspondent was not offered the entry");
            b.on_command(BASE_MS, DmCommand::Accept { request });
            let label_b = b.correspondences[b.correspondences.len() - 1].label;
            (label, queued_frame_at(&b, &label_b, 0, BASE_MS))
        };

        // The restart: a second machine over the same store, seeded from disk,
        // holding nothing the first one held.
        let mut a = machine(&dir);
        assert_eq!(
            a.correspondence_count(),
            1,
            "the unanswered correspondence did not survive the restart"
        );
        assert_eq!(a.correspondences[0].label, label);
        assert_eq!(a.correspondences[0].pk_lt.as_slice(), peer_pk.as_slice());
        assert!(
            a.correspondences[0].peer_pk_pc.is_none(),
            "a correspondence still waiting for its acceptance came back verifiable"
        );
        assert_eq!(
            a.persist
                .correspondence_for_pk_lt(&peer_pk)
                .expect("lookup"),
            Some(label),
            "the restarted driver cannot route an acceptance by identity key"
        );
        assert!(
            a.correspondences[0].ratchet.is_none(),
            "the seed produced a ratchet, so the re-arm below proves nothing"
        );

        // The tick that re-arms it from the stored handshake.
        a.on_tick(BASE_MS);
        assert!(
            a.correspondences[0].ratchet.is_some() && a.correspondences[0].channel.is_some(),
            "the stored handshake was not re-armed, so no page can be opened"
        );

        let conversation = conversation_of(&a, 0);
        let out = fold_page_at(
            &mut a,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(0), acceptance)],
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_some(),
            "the restarted driver did not collect the acceptance: {out:?}"
        );
        assert_eq!(
            a.correspondences[0]
                .peer_pk_pc
                .as_deref()
                .map(|k| k.as_slice()),
            a.persist
                .read_contact(&label)
                .expect("reads")
                .expect("a record")
                .pk_pc()
                .map(|k| k.as_slice()),
            "the collected pseudonym did not reach the record a later restart reads"
        );
        assert_eq!(
            messages_in(&out),
            vec![String::new()],
            "the acceptance must surface once, with an empty body: {out:?}"
        );
    }

    /// One first-contact epoch, in the milliseconds the driver counts in.
    const FC_PERIOD_MS: i64 = (daemonseed_core::dm::keyrec::FC_PERIOD_SECS as i64) * 1000;

    /// M27. A restarted correspondence plans the sweep that fetches its
    /// acceptance.
    ///
    /// **Kills a page sweep that keeps requiring this side's own pseudonym
    /// keypair.** An initiator that restarts before its entry is accepted has
    /// lost that keypair — it is minted from the CSPRNG and nothing writes it
    /// down before establishment — while the ratchet and channel roots come
    /// back from the stored handshake. Requiring it would leave the
    /// correspondence planning nothing, so the acceptance would never be
    /// fetched and the test that folds a page by hand would never notice.
    #[test]
    fn a_restarted_correspondence_plans_the_sweep_that_fetches_its_acceptance() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();
        {
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let _ = knock_as_initiator(&mut a, &peer);
        }

        let mut a = machine(&dir);
        assert!(
            a.correspondences[0].signing_pc.is_none(),
            "the restart kept a pseudonym keypair, so this proves nothing"
        );
        let out = a.on_tick(BASE_MS);
        let swept: Vec<_> = out
            .iter()
            .filter(|e| matches!(e, DmEffect::Dht(DhtOp::SweepPage { .. })))
            .collect();
        assert!(
            !swept.is_empty(),
            "a restarted correspondence planned no page sweep: {out:?}"
        );
    }

    /// M28. The stored handshake is re-armed from the PREVIOUS first-contact
    /// epoch as well as the current one.
    ///
    /// **Kills a re-arm that only tries the epoch it is running in.** A record
    /// is sealed under the epoch its entry was composed in, and an acceptance
    /// arrives whenever the correspondent gets to it — commonly in the epoch
    /// after. Trying one epoch would strand every entry that outlived the week
    /// it was sent in.
    #[test]
    fn a_stored_handshake_is_re_armed_from_the_previous_epoch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();
        {
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let _ = knock_as_initiator(&mut a, &peer);
        }

        let later = BASE_MS + FC_PERIOD_MS;
        assert_ne!(
            keyrec::fc_epoch(unix_secs(later)),
            keyrec::fc_epoch(unix_secs(BASE_MS)),
            "the fixture did not cross an epoch boundary"
        );
        let mut a = machine(&dir);
        a.on_tick(later);
        assert!(
            a.correspondences[0].ratchet.is_some(),
            "a handshake sealed one epoch ago was not re-armed"
        );
    }

    /// M29. An established correspondence is never re-armed, and a tick leaves
    /// it holding no handshake record.
    ///
    /// **Kills a seed that marks every correspondence for re-arming.** An
    /// established one has no handshake record — it was erased when the
    /// acceptance verified — so a re-arm would read two sealed records per
    /// correspondence on the first tick of every session and could only ever
    /// answer that there is nothing there. Worse, a handle installed on the
    /// strength of some other record would name something for the erase to
    /// delete.
    #[test]
    fn an_established_correspondence_is_not_re_armed() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_identity();
        {
            let mut a = machine(&dir_a);
            let mut b = machine_as(peer_identity(), &dir_b);
            a.persist.provision_block_list().expect("provision A");
            b.persist.provision_block_list().expect("provision B");
            establish_pair(&mut a, &mut b, &b_keys);
        }

        let mut a = machine(&dir_a);
        assert!(
            a.correspondences[0].peer_pk_pc.is_some(),
            "the fixture did not establish the correspondence it is about"
        );
        assert!(
            !a.correspondences[0].rearm_handshake,
            "an established correspondence was marked for re-arming"
        );
        a.on_tick(BASE_MS);
        assert!(
            a.correspondences[0].provisional.is_none(),
            "a tick gave an established correspondence a handshake record to erase"
        );
        assert!(
            a.correspondences[0].ratchet.is_none(),
            "a tick armed a ratchet for a correspondence with no stored handshake"
        );
    }

    /// M30. A store that will not read leaves the re-arm to the next tick.
    ///
    /// **Kills a one-shot flag cleared before the attempt.** Absence and an
    /// undecodable record answer the same way on every later tick, so one
    /// attempt is right for them; a store that could not be read says nothing
    /// about the record, and giving up on it would leave the correspondence
    /// without a ratchet for the rest of the session — the very state the
    /// re-arm exists to prevent. The fault here is made by truncating the
    /// record, which the store reports as a file it cannot read.
    #[test]
    fn a_store_fault_leaves_the_re_arm_for_the_next_tick() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();
        {
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let _ = knock_as_initiator(&mut a, &peer);
        }

        let mut a = machine(&dir);
        let files = provisional_files(&a);
        assert_eq!(files.len(), 1, "the fixture must hold exactly one record");
        let path = files[0].clone();
        let healthy = std::fs::read(&path).expect("the record reads");
        std::fs::write(&path, &healthy[..healthy.len() - 1]).expect("the record writes");

        a.on_tick(BASE_MS);
        assert!(
            a.correspondences[0].ratchet.is_none(),
            "the truncated record was read anyway, so the fault is not the fixture's"
        );
        assert!(
            a.correspondences[0].rearm_handshake,
            "a store fault gave up the re-arm for the whole session"
        );

        std::fs::write(&path, &healthy).expect("the record is restored");
        a.on_tick(BASE_MS);
        assert!(
            a.correspondences[0].ratchet.is_some(),
            "the tick after the store recovered did not re-arm"
        );
    }

    /// M31. A refused pseudonym write keeps the handshake record, and the tick
    /// finishes the pair.
    ///
    /// **Kills an erase that runs whatever the write did.** The acceptance is
    /// the only frame carrying the correspondent's pseudonym. Erasing the
    /// handshake record while that key is unrecorded destroys the one state a
    /// restart could re-arm from and leaves the contact record still waiting,
    /// so the correspondence would come back unable to open the acceptance
    /// again — and no later frame could establish it.
    #[test]
    fn a_refused_pseudonym_write_keeps_the_handshake_record_until_it_lands() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let peer = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision B");
        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let entry = knock_as_initiator(&mut a, &peer);

        let offered = b.on_doorbell(BASE_MS, sweep_of(vec![entry]));
        let request = offered
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("the correspondent was not offered the entry");
        b.on_command(BASE_MS, DmCommand::Accept { request });
        let label_b = b.correspondences[b.correspondences.len() - 1].label;
        let acceptance = queued_frame_at(&b, &label_b, 0, BASE_MS);

        // The fault: the record the pseudonym must be written into is gone, so
        // the write is refused and nothing about the acceptance itself changes.
        // Named the way the store names it: the directory is the label in hex.
        let dir_name: String = a.correspondences[0]
            .label
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let contact = a
            .persist
            .store()
            .root()
            .join(dir_name)
            .join("contact-cache.bin");
        let held = std::fs::read(&contact).expect("the record reads");
        std::fs::remove_file(&contact).expect("the record is removed");

        let conversation = conversation_of(&a, 0);
        fold_page_at(
            &mut a,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(0), acceptance)],
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_some(),
            "the acceptance verified and was not installed in memory"
        );
        assert!(
            has_provisional(&a),
            "the handshake record was erased while the pseudonym was unrecorded"
        );
        assert!(
            a.correspondences[0].pseudonym_unwritten,
            "the refused write was not queued for retry"
        );

        // The record comes back, and the next tick writes the pseudonym and
        // releases the handshake record.
        std::fs::write(&contact, &held).expect("the record is restored");
        a.on_tick(BASE_MS);
        assert!(
            !a.correspondences[0].pseudonym_unwritten,
            "the retry did not write the pseudonym"
        );
        assert!(
            a.persist
                .read_contact(&a.correspondences[0].label)
                .expect("reads")
                .expect("a record")
                .pk_pc()
                .is_some(),
            "the retry reported success without writing the key"
        );
        assert!(
            !has_provisional(&a),
            "the handshake record outlived the write that releases it"
        );
    }

    /// M32. An entry re-sent after its handshake record has aged out never
    /// mints a second correspondence for the identity.
    ///
    /// **Kills a re-send that mints a fresh label.** The lookup that recovers a
    /// recipient's correspondence only opens a handshake record at the two live
    /// first-contact epochs; past that it finds nothing, and a mint would put a
    /// second contact record under a second label for one identity.
    /// `correspondence_for_pk_lt` refuses to choose between two, so the
    /// identity would be unroutable for the life of the store — every consumer
    /// of that lookup fails closed on the refusal, and no later event undoes
    /// it.
    ///
    /// The re-send is itself refused, and that is asserted rather than worked
    /// around: the reused correspondence still holds the first entry at the
    /// knock's sequence, and the outbox refuses a second entry at a sequence it
    /// already carries. What matters here is that the refusal leaves the
    /// identity naming one correspondence, which a user can act on, where a
    /// second label would leave it naming none.
    #[test]
    fn an_entry_re_sent_after_its_handshake_record_ages_out_mints_no_second_correspondence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();
        let peer_pk = *peer.signing.public_key();
        let first = {
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let _ = knock_as_initiator(&mut a, &peer);
            a.correspondences[0].label
        };

        // Two epochs on, in a session that remembers nothing: the record
        // written above opens under neither of the epochs a lookup may try, so
        // the label can only come from the contact record.
        let later = BASE_MS + 2 * FC_PERIOD_MS;
        let mut a = machine(&dir);
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());
        a.on_command(
            later,
            DmCommand::FirstContact {
                recipient: pk_lt.clone(),
                body: "knock".into(),
            },
        );
        let record = keyrec::build_encoded(
            &peer.signing,
            peer.kem.encapsulation_key(),
            keyrec::DM_KEY_RECORD_VERSION,
            keyrec::DM_KEY_RECORD_INVITE_ONLY,
        )
        .expect("key record");
        let mut out = a.on_key_record(later, pk_lt, Some(record));
        let DmEffect::Compute(ComputeJob::MintFirstContact(request)) = out.remove(0) else {
            panic!("the key record did not start a mint");
        };
        let out = a.on_mint(later, run_mint(*request));
        assert!(
            out.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::StoreFailure,
                    ..
                })
            )),
            "the re-sent entry was expected to be refused at the queue: {out:?}"
        );

        assert_eq!(
            a.persist.store().correspondences().expect("list").len(),
            1,
            "the re-sent entry minted a second correspondence"
        );
        assert_eq!(
            a.persist
                .correspondence_for_pk_lt(&peer_pk)
                .expect("lookup"),
            Some(first),
            "the identity stopped naming a single correspondence"
        );
        assert_eq!(
            a.correspondences.len(),
            1,
            "the driver holds two entries for one identity"
        );
    }

    /// M33. A pseudonym write that can never succeed stops retrying and
    /// releases the handshake record.
    ///
    /// **Kills a retry with no conclusive/retryable split.** A contact record
    /// that is absent or will not decode answers the same way on every tick, so
    /// an unconditional retry re-reads a sealed record for the life of the
    /// session — and because the erase waits on the write, the opening secret
    /// stays on disk against a write that will never land. The correspondence
    /// is established either way: the acceptance verified.
    #[test]
    fn a_pseudonym_write_that_can_never_succeed_releases_the_handshake_record() {
        let (mut a, contact) = accepted_with_a_refused_pseudonym_write();
        assert!(
            has_provisional(&a),
            "the fixture did not leave a handshake record to release"
        );

        // The record is not merely missing but unreadable, which no later tick
        // can improve on.
        std::fs::write(&contact, vec![0u8; 8]).expect("the record writes");
        a.on_tick(BASE_MS);
        assert!(
            !a.correspondences[0].pseudonym_unwritten,
            "a refusal no retry can change is still queued for retry"
        );
        assert!(
            !has_provisional(&a),
            "the opening secret is held against a write that will never land"
        );

        // And nothing is retried afterwards: the flag stays clear across a
        // second tick, so the give-up is not re-armed by the next one.
        a.on_tick(BASE_MS);
        assert!(
            !a.correspondences[0].pseudonym_unwritten,
            "the give-up was undone by the next tick"
        );
    }

    /// M34. A refused contact-record write leaves no handshake record behind.
    ///
    /// **Kills a refusal that deletes nothing.** The refusal prunes this
    /// session's memory of the introduction, so a handshake record left on disk
    /// holds the opening secret in a correspondence nothing can reach: the
    /// startup seed skips a directory with no contact record, and the sweep for
    /// superseded handshake records only looks beside a resume record, which
    /// this correspondence never had.
    #[test]
    fn a_refused_contact_record_write_leaves_no_handshake_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();
        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");

        // The label the introduction will use, chosen here so the record that
        // refuses the write can be put in place before it runs. It holds a
        // different identity, which is the one refusal that leaves every other
        // read on this path answering normally.
        let label = CorrespondenceLabel::mint().expect("label");
        a.provisionals
            .push((Box::new(*peer.signing.public_key()), label));
        a.persist
            .record_first_contact_sent(
                &label,
                Box::new(*other_peer_identity().signing.public_key()),
                zeroize::Zeroizing::new([0x5Cu8; ADDRESS_ROOT_LEN]),
                BASE_MS,
            )
            .expect("the standing record was not written");

        let out = introduce(&mut a, &peer, BASE_MS);
        assert!(
            out.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::StoreFailure,
                    ..
                })
            )),
            "the fixture did not refuse the introduction: {out:?}"
        );
        assert!(
            !has_provisional(&a),
            "the refused introduction stranded the conversation's opening secret"
        );
        assert!(
            a.pending_erase.is_empty(),
            "the erase was deferred when it had already succeeded"
        );
    }

    /// M35. A store fault that never clears is given up on at the ceiling.
    ///
    /// **Kills an unbounded retry.** A truncated record nothing repairs answers
    /// `StoreUnreadable` on every tick, and at each attempt that is
    /// indistinguishable from a fault about to clear — so without a bound the
    /// re-arm reads two sealed records every tick for the life of the session.
    /// The boundary is asserted from both sides so the ceiling is the number the
    /// constant names.
    #[test]
    fn a_store_fault_that_never_clears_is_given_up_at_the_ceiling() {
        let dir = tempfile::tempdir().expect("temp dir");
        let peer = peer_identity();
        {
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let _ = knock_as_initiator(&mut a, &peer);
        }

        let mut a = machine(&dir);
        let files = provisional_files(&a);
        assert_eq!(files.len(), 1, "the fixture must hold exactly one record");
        let healthy = std::fs::read(&files[0]).expect("the record reads");
        std::fs::write(&files[0], &healthy[..healthy.len() - 1]).expect("the record writes");

        for tick in 1..REARM_FAULT_CEILING {
            a.on_tick(BASE_MS);
            assert!(
                a.correspondences[0].rearm_handshake,
                "the re-arm was abandoned after {tick} fault(s), below the ceiling"
            );
        }
        a.on_tick(BASE_MS);
        assert!(
            !a.correspondences[0].rearm_handshake,
            "a fault that never clears is retried past the ceiling"
        );

        // Even a store that recovers afterwards is not re-armed: the give-up is
        // the answer, not a pause.
        std::fs::write(&files[0], &healthy).expect("the record is restored");
        a.on_tick(BASE_MS);
        assert!(
            a.correspondences[0].ratchet.is_none(),
            "the abandoned re-arm ran again"
        );
    }

    /// M36. A contact record that is not there at all is a settled refusal.
    ///
    /// **Kills a classification that reads a missing record as worth retrying.**
    /// The other settled cases are bytes that will not decode; absence is the
    /// one that arrives with no bytes to look at, and reading it as transient
    /// would retry a write that has nothing to write into — holding the
    /// conversation's opening secret on disk for the life of the session
    /// against a record no tick brings back.
    #[test]
    fn a_missing_contact_record_is_a_settled_refusal() {
        let (mut a, contact) = accepted_with_a_refused_pseudonym_write();
        assert!(
            !contact.exists(),
            "the fixture must leave the record absent, not merely unreadable"
        );
        assert!(
            has_provisional(&a),
            "the fixture did not leave a handshake record to release"
        );

        a.on_tick(BASE_MS);
        assert!(
            !a.correspondences[0].pseudonym_unwritten,
            "an absent record is still queued for retry"
        );
        assert!(
            !has_provisional(&a),
            "the opening secret is held against a record no tick brings back"
        );
    }

    /// M37. A store fault that never clears ends the pseudonym write at the
    /// ceiling.
    ///
    /// **Kills an unbounded retry of the transient half.** A settled refusal
    /// stops on the first tick; a fault does not, and without a bound it reads
    /// and writes a sealed record every tick for the life of the session while
    /// withholding the erase for exactly as long — the sibling re-arm loop is
    /// bounded for the same reason. The boundary is asserted from both sides so
    /// the ceiling is the number the constant names.
    #[test]
    fn a_faulting_pseudonym_write_is_given_up_at_the_ceiling() {
        let (mut a, contact) = accepted_with_a_refused_pseudonym_write();

        // A directory where the record belongs: the write faults on every
        // attempt and never reports anything about bytes.
        std::fs::create_dir(&contact).expect("the obstruction is created");

        for tick in 1..PSEUDONYM_WRITE_FAULT_CEILING {
            a.on_tick(BASE_MS);
            assert!(
                a.correspondences[0].pseudonym_unwritten,
                "the write was abandoned after {tick} fault(s), below the ceiling"
            );
            assert!(
                has_provisional(&a),
                "the handshake record was released after {tick} fault(s)"
            );
        }
        a.on_tick(BASE_MS);
        assert!(
            !a.correspondences[0].pseudonym_unwritten,
            "a fault that never clears is retried past the ceiling"
        );
        assert!(
            !has_provisional(&a),
            "the give-up did not release the handshake record"
        );
    }

    /// A correspondence whose acceptance was collected while the contact record
    /// could not be written, with the path to that record.
    fn accepted_with_a_refused_pseudonym_write() -> (DmMachine, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let peer = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision B");
        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let entry = knock_as_initiator(&mut a, &peer);

        let offered = b.on_doorbell(BASE_MS, sweep_of(vec![entry]));
        let request = offered
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("the correspondent was not offered the entry");
        b.on_command(BASE_MS, DmCommand::Accept { request });
        let label_b = b.correspondences[b.correspondences.len() - 1].label;
        let acceptance = queued_frame_at(&b, &label_b, 0, BASE_MS);

        let contact = a
            .persist
            .store()
            .root()
            .join(label_dir(&a.correspondences[0].label))
            .join("contact-cache.bin");
        std::fs::remove_file(&contact).expect("the record is removed");
        let conversation = conversation_of(&a, 0);
        fold_page_at(
            &mut a,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(0), acceptance)],
        );
        assert!(
            a.correspondences[0].pseudonym_unwritten,
            "the fixture did not refuse the pseudonym write"
        );
        // The temp dirs are leaked deliberately: the machine reads its store for
        // the rest of the test, and dropping them here would remove it.
        std::mem::forget((dir, dir_b));
        (a, contact)
    }

    /// The directory a correspondence's records live in: its label in hex.
    fn label_dir(label: &CorrespondenceLabel) -> String {
        label
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Drive one introduction through the key record and the mint, returning
    /// what the mint produced.
    fn introduce(a: &mut DmMachine, peer: &IdentityKeys, now_ms: i64) -> Vec<DmEffect> {
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());
        a.on_command(
            now_ms,
            DmCommand::FirstContact {
                recipient: pk_lt.clone(),
                body: "knock".into(),
            },
        );
        let record = keyrec::build_encoded(
            &peer.signing,
            peer.kem.encapsulation_key(),
            keyrec::DM_KEY_RECORD_VERSION,
            keyrec::DM_KEY_RECORD_INVITE_ONLY,
        )
        .expect("key record");
        let mut out = a.on_key_record(now_ms, pk_lt, Some(record));
        let DmEffect::Compute(ComputeJob::MintFirstContact(request)) = out.remove(0) else {
            panic!("the key record did not start a mint");
        };
        a.on_mint(now_ms, run_mint(*request))
    }

    /// Whether any correspondence directory in this machine's store still holds
    /// a provisional record.
    ///
    /// **Asked of the store, not of the correspondence.** The strand this
    /// guards against is precisely a record whose in-memory handle was
    /// overwritten, so a machine that forgot the record entirely would pass an
    /// in-memory check while the file sat there.
    fn has_provisional(m: &DmMachine) -> bool {
        m.persist
            .store()
            .correspondences()
            .expect("list")
            .into_iter()
            .any(|l| {
                m.persist
                    .store()
                    .read_unlocked(
                        &l,
                        daemonseed_core::storage::dm_store::RecordKind::Provisional,
                    )
                    .expect("read")
                    .is_some()
            })
    }

    /// M26. `fire_accept` reports every refusal it takes; none of them return
    /// silently.
    ///
    /// A refusal that returned `Vec::new()` would leave the front end with a
    /// conversation it believes was accepted and an initiator that can never
    /// verify it — the acceptance is the only frame carrying this side's
    /// pseudonym. The two post-`send_next` paths (a seal fault, and an enqueue
    /// the ask had already approved) are unreachable from a single-writer test
    /// by construction, and are the class `send` documents: they need a second
    /// writer to fill the record between the ask and the enqueue.
    #[test]
    fn a_refused_acceptance_is_always_reported() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut m = machine(&dir);
        let knock = fake_knock(44);
        let pk_lt: PkLt = Box::new(*knock.pk_lt());
        let peer_pk_pc = Box::new(*knock.pk_pc());
        let channel = ChannelRoots {
            chan_id: knock.roots().chan_id,
        };
        let address_root = knock.roots().ar;
        let (label, _ratchet) = m
            .persist
            .accept_first_contact(*knock, &[0x71u8; oxicrypt_ml_dsa::SK_LEN], BASE_MS)
            .expect("the establish succeeds");
        // No ratchet: the correspondence exists and cannot be spoken on, which
        // is the state a restart leaves behind.
        m.correspondences.push(Correspondence {
            pk_lt,
            label,
            ratchet: None,
            signing_pc: None,
            peer_pk_pc: Some(peer_pk_pc),
            channel: Some(channel),
            address_root,
            candidate: None,
            re_acks_answered: 0,
            response_cap_surfaced: false,
            retire_ceiling_surfaced: false,
            leg_give_up_surfaced: false,
            peer_regression_surfaced: false,
            collection: Collection::new(),
            read_through: 0,
            cursor_unreadable: false,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            provisional: None,
            rearm_handshake: false,
            rearm_faults: 0,
            pseudonym_unwritten: false,
            pseudonym_faults: 0,
            resume_owed: false,
            resume_faults: 0,
            resume_retry_due_ms: None,
            resume_surfaced: false,
            resume_ceiling_surfaced: false,
        });

        let out = m.fire_accept(BASE_MS, 0);
        assert!(
            out.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Delivery {
                    seq: 0,
                    state: DeliveryState::Undelivered,
                    ..
                })
            )),
            "a refused acceptance must say sequence zero did not go: {out:?}"
        );
        assert!(
            out.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::Refused {
                    reason: RefusalReason::NotEstablishedThisSession,
                    ..
                })
            )),
            "a refused acceptance must say why: {out:?}"
        );
    }

    /// Fold one page into `m`, as a completed sweep of the slots given.
    fn fold_page(
        m: &mut DmMachine,
        conversation: [u8; AR_FINGERPRINT_LEN],
        page: u64,
        slots: Vec<(PagePosition, Vec<u8>)>,
    ) -> Vec<DmEffect> {
        fold_page_at(m, BASE_MS, conversation, page, slots)
    }

    /// The bytes of one queued outbox entry.
    fn queued_frame(m: &DmMachine, label: &CorrespondenceLabel, seq: u64) -> Vec<u8> {
        m.persist
            .read_outbox(label, BASE_MS)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .entry(seq)
            .unwrap_or_else(|| panic!("sequence {seq} is queued"))
            .frame()
            .expect("the entry holds its bytes")
            .to_vec()
    }

    /// A frame whose SEAL has been tampered with, one byte deep.
    ///
    /// **Not garbage, and the difference is the whole point of using it.**
    /// Random bytes fail `frame::parse` and never reach the ratchet or
    /// `open_accept` at all, so a test built on them says nothing about what
    /// happens on the open path. This still parses — the clear header is
    /// untouched — so the ratchet accepts the position, the closure runs, and
    /// the AEAD is what refuses it. That is the path a forged acceptance takes,
    /// and the only one on which "nothing was committed" can be observed.
    fn tampered(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let last = out.len() - 1;
        out[last] ^= 0xFF;
        out
    }

    /// The message bodies in a batch of effects.
    fn messages_in(effects: &[DmEffect]) -> Vec<String> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::Message { body, .. }) => Some(body.clone()),
                _ => None,
            })
            .collect()
    }

    // ---- the acknowledgement plane ----------------------------------------

    /// A third identity, distinct from `keys()` and `peer_identity()`, so a
    /// receiver can hold two correspondences competing for one allowance.
    fn third_identity() -> IdentityKeys {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(
            &Mnemonic::from_phrase(TEST_MNEMONIC).expect("mnemonic"),
            Identity::Device {
                uuid: uuid::Uuid::from_bytes([0x2Au8; 16]),
            },
        )
        .expect("third identity")
    }

    /// Fold one page into `m` at a named instant, as a completed sweep.
    ///
    /// [`fold_page`] pins the clock at [`BASE_MS`]; the cadence tests need the
    /// fold and the ticks that follow it to sit on one timeline.
    fn fold_page_at(
        m: &mut DmMachine,
        now_ms: i64,
        conversation: [u8; AR_FINGERPRINT_LEN],
        page: u64,
        slots: Vec<(PagePosition, Vec<u8>)>,
    ) -> Vec<DmEffect> {
        let found = u32::try_from(slots.len()).unwrap_or(u32::MAX);
        // Through `on_outcome` rather than straight into `on_page`, because that
        // is the only path that releases the page's in-flight slot: a fixture
        // calling the fold directly would leave every page it delivered recorded
        // as still being swept, and the ticks after it would plan nothing.
        m.on_outcome(
            now_ms,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::SweepPage,
                tag: OpTag::channel(conversation, None, Some(page)),
                result: Ok(DhtResult::Page(DmPageSweep {
                    conversation,
                    slots,
                    outcome: crate::SweepOutcome {
                        attempted: u32::from(PAGE_SLOTS),
                        failed: 0,
                        found,
                    },
                })),
            }),
        )
    }

    /// Knock, accept, and carry the acceptance back, so both machines hold a
    /// live correspondence and each knows the other's pseudonym.
    ///
    /// Nothing is faked: the entry is `firstcontact::build`'s, the acceptance is
    /// the frame `fire_accept` queued, and A installs the pseudonym by opening
    /// it. The initiator half matters here — every acknowledgement A fetches is
    /// verified against a key only the acceptance carries, so a fixture that
    /// stopped at the accept would exercise the "not yet knowable" arm and
    /// nothing else.
    ///
    /// `b` must have been provisioned already; two calls against one acceptor
    /// share it.
    fn establish_pair(a: &mut DmMachine, b: &mut DmMachine, b_keys: &IdentityKeys) {
        let entry = knock_as_initiator(a, b_keys);
        let out = b.on_doorbell(BASE_MS, sweep_of(vec![entry]));
        let request = out
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("B was not offered the knock");
        b.on_command(BASE_MS, DmCommand::Accept { request });
        let index = b.correspondences.len() - 1;
        let label_b = b.correspondences[index].label;
        let acceptance = queued_frame_at(b, &label_b, 0, BASE_MS);
        let conversation = conversation_of(a, 0);
        let out = fold_page_at(
            a,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(0), acceptance)],
        );
        assert!(
            a.correspondences[0].peer_pk_pc.is_some(),
            "the acceptance did not install a pseudonym: {out:?}"
        );
    }

    /// One outbox entry's delivery state, read from the record.
    fn outbox_state(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        seq: u64,
        now_ms: i64,
    ) -> DeliveryState {
        m.persist
            .read_outbox(label, now_ms)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .entry(seq)
            .unwrap_or_else(|| panic!("sequence {seq} is queued"))
            .delivery_state()
    }

    /// The bytes of one queued outbox entry, read at a named instant.
    ///
    /// [`queued_frame`] pins the read at [`BASE_MS`]; an entry composed later
    /// than that is refused as composed in the future, which is the store
    /// correctly declining to read a record against a clock behind it.
    fn queued_frame_at(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        seq: u64,
        now_ms: i64,
    ) -> Vec<u8> {
        m.persist
            .read_outbox(label, now_ms)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .entry(seq)
            .unwrap_or_else(|| panic!("sequence {seq} is queued"))
            .frame()
            .expect("the entry holds its bytes")
            .to_vec()
    }

    /// The sealing generation the outbox recorded for one queued entry.
    fn queued_sealing_gen(m: &DmMachine, label: &CorrespondenceLabel, seq: u64) -> u32 {
        m.persist
            .read_outbox(label, BASE_MS)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .entry(seq)
            .unwrap_or_else(|| panic!("sequence {seq} is queued"))
            .sealed_under_gen()
    }

    /// **Both send paths record the generation the frame was actually sealed
    /// under, not a constant.**
    ///
    /// The value is what `Outbox::sweep_dead_chain` compares against the
    /// re-rooted generation, so an entry filed under the wrong one is either
    /// destroyed while live or re-seeded into a chain the peer has torn down.
    /// Every other assertion about the field reads it back as zero — the
    /// fresh-entry, awaiting-key and migration defaults all agree on that — so a
    /// send path writing a literal zero satisfies all of them. Both paths are
    /// checked here against a **non-zero** generation read off the ratchet
    /// itself.
    #[test]
    fn both_send_paths_record_the_generation_they_sealed_under() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // The acceptance path: B's first channel write, at sequence zero.
        let label_b = sole_label(&b);
        let accept_gen = queued_sealing_gen(&b, &label_b, 0);
        assert_ne!(
            accept_gen, 0,
            "the fixture's acceptance sealed under generation zero, so this case cannot \
             tell the recorded value from the default"
        );
        assert_eq!(
            accept_gen,
            b.correspondences[0]
                .ratchet
                .as_ref()
                .expect("B holds a live ratchet")
                .generation(),
            "the acceptance was filed under a generation its ratchet never sealed at"
        );

        // The ordinary send path: A's first channel message, at sequence one.
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "the first channel message".into(),
            },
        );
        let label_a = sole_label(&a);
        let send_gen = queued_sealing_gen(&a, &label_a, 1);
        assert_ne!(
            send_gen, 0,
            "the fixture's send sealed under generation zero, so this case cannot tell \
             the recorded value from the default"
        );
        assert_eq!(
            send_gen,
            a.correspondences[0]
                .ratchet
                .as_ref()
                .expect("A holds a live ratchet")
                .generation(),
            "the message was filed under a generation its ratchet never sealed at"
        );

        // And the header the sweep's peer will read agrees with what was filed,
        // so the two sides of the comparison come from one number.
        assert_eq!(
            a.persist
                .read_outbox(&label_a, BASE_MS)
                .expect("reads")
                .expect("exists")
                .last_clear_gen(),
            send_gen,
            "the header counter and the entry's provenance disagree"
        );
    }

    /// The initiator's conversation fingerprint.
    fn conversation_of(m: &DmMachine, index: usize) -> [u8; AR_FINGERPRINT_LEN] {
        *m.correspondences[index]
            .ratchet
            .as_ref()
            .expect("a live ratchet")
            .ar_fingerprint()
    }

    /// The conversations named by every `PublishAck` in a batch of effects.
    fn ack_publishes(effects: &[DmEffect]) -> Vec<[u8; AR_FINGERPRINT_LEN]> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishAck { tag, .. }) => tag.conversation,
                _ => None,
            })
            .collect()
    }

    /// The delivery states reported in a batch of effects, as `(seq, state)`.
    fn deliveries_in(effects: &[DmEffect]) -> Vec<(u64, DeliveryState)> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::Delivery { seq, state, .. }) => Some((*seq, *state)),
                _ => None,
            })
            .collect()
    }

    /// Tell `m` that the standalone acknowledgement it asked to write landed.
    fn ack_written(m: &mut DmMachine, now_ms: i64, conversation: [u8; AR_FINGERPRINT_LEN]) {
        m.on_outcome(
            now_ms,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::PublishAck,
                tag: OpTag::channel(conversation, None, None),
                result: Ok(DhtResult::AckWritten),
            }),
        );
    }

    /// Hand `m` one fetched acknowledgement record for `conversation`.
    fn ack_fetched(
        m: &mut DmMachine,
        now_ms: i64,
        conversation: [u8; AR_FINGERPRINT_LEN],
        record: Vec<u8>,
    ) -> Vec<DmEffect> {
        m.on_outcome(
            now_ms,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::FetchAck,
                tag: OpTag::channel(conversation, None, None),
                result: Ok(DhtResult::Ack(Some(record))),
            }),
        )
    }

    /// Build one acknowledgement record the way `other` would publish it for the
    /// messages it received, over the sequence numbers `settled` names.
    ///
    /// The keys and roots are the far machine's own, so the only thing a test
    /// chooses is the claim — which is what makes an over-claim distinguishable
    /// from a forgery: this signs correctly and lies, and `forged_ack_record`
    /// signs wrongly.
    fn ack_record_from(other: &DmMachine, index: usize, settled: &[u64]) -> Vec<u8> {
        let correspondence = &other.correspondences[index];
        let (ratchet, signing_pc, channel) = correspondence.live().expect("a live correspondence");
        let mut state = AckState::new();
        for &seq in settled {
            state.collect(seq).expect("the claim fits");
        }
        ack_record::build_encoded(
            &state,
            &channel.chan_id,
            ratchet.recv_direction(),
            &correspondence.address_root,
            signing_pc,
        )
        .expect("the record builds")
    }

    /// The same record, signed under a pseudonym that is not the
    /// correspondent's.
    fn forged_ack_record(other: &DmMachine, index: usize, settled: &[u64]) -> Vec<u8> {
        let correspondence = &other.correspondences[index];
        let (ratchet, _, channel) = correspondence.live().expect("a live correspondence");
        let mut state = AckState::new();
        for &seq in settled {
            state.collect(seq).expect("the claim fits");
        }
        let impostor = mint_pseudonym().expect("an impostor's pseudonym");
        ack_record::build_encoded(
            &state,
            &channel.chan_id,
            ratchet.recv_direction(),
            &correspondence.address_root,
            &impostor,
        )
        .expect("the record builds")
    }

    /// M26. The standalone cadence accelerates toward the sender's give-up and
    /// stops at it.
    ///
    /// **The measurement is a count per third of the window, not a predicted
    /// instant.** Asserting "due at exactly t" would re-derive
    /// [`ack_cadence::standalone_interval_ms`] inside the test and pass on any
    /// bug the two shared; counting how many acknowledgements a fixed march of
    /// the clock produces in each third measures the curve's *shape* against
    /// nothing but the clock. A taper replaced by any constant interval gives
    /// the three thirds equal counts, which is what the control below turns on.
    ///
    /// The floor is the first count: B has collected new messages, so the first
    /// acknowledgement goes whatever the curve says.
    ///
    /// Past the give-up the count is zero — not small, zero. The sender discards
    /// an acknowledgement arriving after its own give-up by construction, so a
    /// write spent there is spent into a void.
    #[test]
    fn the_standalone_cadence_accelerates_and_stops_at_the_give_up() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // A's first channel message, composed at BASE_MS: the one pending
        // message the whole taper is measured against.
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "the message under the taper".into(),
            },
        );
        let label_a = sole_label(&a);
        let frame = queued_frame(&a, &label_a, 1);
        let conversation = conversation_of(&b, 0);
        let folded = fold_page_at(
            &mut b,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(1), frame)],
        );
        assert_eq!(
            messages_in(&folded).len(),
            1,
            "the fixture must actually have collected a message: {folded:?}"
        );
        assert_eq!(
            b.correspondences[0].pending_sent_ms,
            vec![BASE_MS],
            "the taper must be keyed on the frame's own asserted send time"
        );

        // A fixed march of the clock, one tick every half hour, from the compose
        // instant to a whole window past it.
        const STEP_MS: i64 = 30 * 60 * 1000;
        let third = GIVE_UP_MS / 3;
        let mut counts = [0u64; 3];
        let mut after_give_up = 0u64;
        let mut now = BASE_MS;
        while now <= BASE_MS + GIVE_UP_MS + third {
            // The cadence step directly, not the whole tick: `on_tick` also
            // sweeps give-ups, re-emits the outbox and plans probes, and three
            // hundred rounds of that is minutes of sealed-record churn saying
            // nothing about the curve. That `on_tick` reaches this at all is
            // pinned by `one_allowance_serves_the_older_pending_first_and_defers_the_other`
            // and by the driver's own round-trip oracle.
            let effects = b.standalone_acks(now);
            let published = ack_publishes(&effects);
            for conversation in &published {
                // On the write, never on the decision: the cadence advances only
                // because the record landed.
                ack_written(&mut b, now, *conversation);
            }
            let written = published.len() as u64;
            let age = now - BASE_MS;
            if age >= GIVE_UP_MS {
                after_give_up += written;
            } else {
                counts[usize::try_from(age / third).unwrap_or(2).min(2)] += written;
            }
            now += STEP_MS;
        }

        assert!(
            counts[0] >= 1,
            "the floor must fire once new messages have been collected: {counts:?}"
        );
        assert!(
            counts[0] < counts[1],
            "the taper must write more often as the sender's window closes: {counts:?}"
        );
        assert!(
            counts[1] < counts[2],
            "the taper must keep accelerating into the last third: {counts:?}"
        );
        // The exact shape, pinned. The curve is deterministic — no jitter, no
        // randomness — so these are a measurement and not a range: any constant
        // interval flattens them to three equal numbers.
        assert_eq!(
            counts,
            [3, 5, 24],
            "the taper's shape moved. These are recomputable rather than merely \
             recorded: the interval is linear from MIN_INTERVAL_MS (60 s) at the \
             give-up to MAX_INTERVAL_MS (24 h) a whole window before it, a write \
             is due once that interval has elapsed since the last one, the clock \
             is sampled every {STEP_MS} ms across GIVE_UP_MS ({GIVE_UP_MS} ms), \
             and each count is the writes falling in one third of that window"
        );
        assert_eq!(
            after_give_up, 0,
            "an acknowledgement was written past the sender's give-up: {counts:?}"
        );
        // The terminus is a set that emptied itself, not a flag: every send time
        // aged out of the window, so nothing is left for a write to help.
        assert!(
            b.correspondences[0].pending_sent_ms.is_empty(),
            "the pending set must age out with the sender's window, leaving: {:?}",
            b.correspondences[0].pending_sent_ms
        );
    }

    /// M27. One allowance, two conversations: the older pending goes first and
    /// the other is told when to come back.
    ///
    /// The ceiling is client-wide, so the two questions are separate and both
    /// have to hold: [`ack_cadence::pick_next`] decides *which* conversation the
    /// round belongs to, and [`StandaloneAckBudget`] decides how many rounds
    /// there are. Dropping the budget gives two writes in one tick, which is the
    /// breach the budget exists to close.
    #[test]
    fn one_allowance_serves_the_older_pending_first_and_defers_the_other() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_c = tempfile::tempdir().expect("temp dir C");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        let mut a = machine(&dir_a);
        let mut c = machine_as(third_identity(), &dir_c);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        establish_pair(&mut c, &mut b, &b_keys);
        assert_eq!(
            b.correspondences.len(),
            2,
            "the fixture needs two correspondences competing for one allowance"
        );

        // The two messages are composed a full minute apart, so "older" is not a
        // tie the iteration order could decide.
        const GAP_MS: i64 = 60_000;
        let older = BASE_MS;
        let newer = BASE_MS + GAP_MS;
        for (sender, at) in [(&mut a, older), (&mut c, newer)] {
            sender.on_command(
                at,
                DmCommand::Send {
                    to: Box::new(*b_keys.signing.public_key()),
                    body: "one each".into(),
                },
            );
        }
        let older_conversation = conversation_of(&a, 0);
        let newer_conversation = conversation_of(&c, 0);
        for (sender, conversation, at) in [
            (&a, older_conversation, older),
            (&c, newer_conversation, newer),
        ] {
            let label = sole_label(sender);
            let frame = queued_frame_at(sender, &label, 1, newer);
            let folded = fold_page_at(&mut b, at, conversation, 0, vec![(position_of(1), frame)]);
            assert_eq!(
                messages_in(&folded).len(),
                1,
                "each fixture message must have been collected: {folded:?}"
            );
        }

        // ── one tick, one write ──────────────────────────────────────────────
        let tick = newer + 1;
        let effects = b.on_tick(tick);
        let published = ack_publishes(&effects);
        assert_eq!(
            published.len(),
            1,
            "the client-global allowance granted more than one write in a tick: {published:?}"
        );
        assert_eq!(
            published[0], older_conversation,
            "the round must go to the conversation whose sender has waited longest"
        );
        assert_eq!(
            b.ack_retry_due_ms,
            Some(tick + daemonseed_core::dm::ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS),
            "the refusal must be scheduled rather than polled"
        );
        // The fold into the wake time is only visible where the idle cadence is
        // slower than the allowance; at the default 30 s tick the idle deadline
        // is already the sooner of the two.
        let slow = tick + 300_000;
        b.cfg.idle_tick = Duration::from_secs(300);
        assert_eq!(
            b.next_due_ms(tick),
            tick + daemonseed_core::dm::ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS,
            "a driver slower than the allowance must wake for the deferred write"
        );
        assert!(slow > b.next_due_ms(tick), "the fold must shorten the wait");
        b.cfg.idle_tick = Duration::from_secs(30);
        ack_written(&mut b, tick, published[0]);

        // ── the winner does not take two rounds running ──────────────────────
        //
        // **The older conversation is made due again on purpose.** Its key is
        // still the oldest — its sender has been waiting longest, and collecting
        // a second message does not change that — so oldest-first alone would
        // hand it the next round too, and the round after, for as long as it
        // keeps writing. What stops it is the previous winner being remembered,
        // and nothing else: a client-global allowance handed to whoever claims
        // the oldest message is an ordering a hostile contact wins by choosing an
        // integer.
        a.on_command(
            tick,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "and another".into(),
            },
        );
        let label_a = sole_label(&a);
        let second = queued_frame_at(&a, &label_a, 2, tick);
        let folded = fold_page_at(
            &mut b,
            tick,
            older_conversation,
            0,
            vec![(position_of(2), second)],
        );
        assert_eq!(
            messages_in(&folded).len(),
            1,
            "the older conversation must be due again, or the skip below is vacuous: {folded:?}"
        );

        // ── the allowance renews, and the deferred conversation takes it ──────
        let later = tick + daemonseed_core::dm::ack_budget::STANDALONE_ACK_MIN_INTERVAL_MS;
        let effects = b.on_tick(later);
        let published = ack_publishes(&effects);
        assert_eq!(
            published,
            vec![newer_conversation],
            "the deferred conversation must take the next allowance, even against \
             an older one that has just collected again"
        );
    }

    /// M28. A peer acknowledgement claiming more than we sent is clipped to the
    /// ceiling, counted, and settles nothing above it.
    ///
    /// A correspondent cannot have collected what was never transmitted, so the
    /// claim is a misbehaviour signal rather than a routine result. It is clipped
    /// and not refused: refusing would discard the truthful low half along with
    /// the impossible high half, and a peer's high-water is monotonic, so the
    /// refusal would be permanent rather than a retry.
    #[test]
    fn an_over_claiming_acknowledgement_is_clipped_counted_and_settles_to_the_ceiling() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        for body in ["one", "two"] {
            a.on_command(
                BASE_MS,
                DmCommand::Send {
                    to: Box::new(*b_keys.signing.public_key()),
                    body: body.into(),
                },
            );
        }
        // The knock at zero plus two channel messages: the highest sequence this
        // side has actually put on the wire is two.
        assert_eq!(
            a.only_next_send_seq(),
            Some(3),
            "the fixture must have spent sequences zero to two"
        );

        let conversation = conversation_of(&a, 0);
        // The knock at zero is already confirmed: the acceptance piggybacked the
        // acceptor's own state, which settles it. Stated so its absence below
        // reads as *already settled* rather than as a claim that did not land.
        let label_a = sole_label(&a);
        assert_eq!(
            outbox_state(&a, &label_a, 0, BASE_MS),
            DeliveryState::ConfirmedCollected,
            "the acceptance's piggyback must already have confirmed the knock"
        );

        let record = ack_record_from(&b, 0, &[0, 1, 2, 3, 4, 5]);
        let effects = ack_fetched(&mut a, BASE_MS, conversation, record);

        let mut settled = deliveries_in(&effects);
        settled.sort_unstable_by_key(|(seq, _)| *seq);
        assert_eq!(
            settled,
            vec![
                (1, DeliveryState::ConfirmedCollected),
                (2, DeliveryState::ConfirmedCollected),
            ],
            "the claim must settle up to the ceiling and no further: {effects:?}"
        );
        assert_eq!(
            a.correspondences[0].health.peer_acks_clipped, 1,
            "an over-claim must be counted as the misbehaviour signal it is"
        );
        assert_eq!(
            a.correspondences[0].health.peer_acks_deferred, 0,
            "a clip is not a refused merge"
        );

        // ── the clipped-away claim was not retained ──────────────────────────
        //
        // **Absent from one event list is not the same as not settled.** The
        // merge is a union into retained state, so a claim taken whole rather
        // than clipped would sit there silently and confirm sequence three the
        // moment this side sent it — against a statement the peer made before
        // the message existed. So a third message is sent and a SECOND record is
        // folded, this one claiming nothing above the original ceiling: if the
        // clip held, sequence three is still where the send left it.
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "three".into(),
            },
        );
        let narrow = ack_record_from(&b, 0, &[0, 1]);
        let effects = ack_fetched(&mut a, BASE_MS, conversation, narrow);
        assert_eq!(
            deliveries_in(&effects),
            Vec::new(),
            "a record claiming nothing new must settle nothing: {effects:?}"
        );
        assert_eq!(
            outbox_state(&a, &label_a, 3, BASE_MS),
            DeliveryState::Composed,
            "the sequence the first record claimed above the ceiling must be \
             where the send left it — no write has been confirmed for it, so \
             `Composed` rather than `OnDht` is its state in a machine with no \
             transport"
        );
    }

    /// M29. A standalone record signed by the wrong pseudonym settles nothing.
    ///
    /// The record's address descends from the conversation's secret address root,
    /// so a third party cannot write one — but the fetch is still a read of
    /// untrusted bytes, and the signature is the only thing that separates the
    /// correspondent's statement from anybody else's. It fails closed: nothing is
    /// merged, nothing is settled, and the outbox keeps re-seeding.
    ///
    /// The honest record is fetched afterwards on the same fixture, which is the
    /// positive control: without it, "nothing settled" is satisfied by a driver
    /// that folds no record at all.
    #[test]
    fn a_standalone_record_signed_by_the_wrong_pseudonym_settles_nothing() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "one".into(),
            },
        );
        let conversation = conversation_of(&a, 0);

        let effects = ack_fetched(
            &mut a,
            BASE_MS,
            conversation,
            forged_ack_record(&b, 0, &[0, 1]),
        );
        assert_eq!(
            deliveries_in(&effects),
            Vec::new(),
            "a record that did not verify settled an outbox entry: {effects:?}"
        );
        assert_eq!(
            a.correspondences[0].health.peer_acks_unverified, 1,
            "a record that did not verify must be counted"
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                DmEffect::Emit(DmEvent::ChannelHealth {
                    peer_acks_unverified: 1,
                    ..
                })
            )),
            "the count must reach the front end: {effects:?}"
        );

        // The positive control: the same fixture, the same claim, a signature
        // that verifies. Sequence zero is already confirmed by the acceptance's
        // own piggyback, so sequence one is what this settles.
        let effects = ack_fetched(
            &mut a,
            BASE_MS,
            conversation,
            ack_record_from(&b, 0, &[0, 1]),
        );
        assert_eq!(
            deliveries_in(&effects),
            vec![(1, DeliveryState::ConfirmedCollected)],
            "the same fixture must settle under a record that DOES verify: {effects:?}"
        );
    }

    /// M30. The give-up beats a late acknowledgement.
    ///
    /// A message past its seven-day window is `Undelivered`, and `Undelivered` is
    /// terminal: an acknowledgement arriving afterwards settles nothing, whether
    /// or not the sweep has already run. Reporting *collected* for a message this
    /// sender abandoned is the one failure the fail-safe posture forbids
    /// outright, so the event list is asserted whole rather than searched for the
    /// state that should be there.
    #[test]
    fn a_late_acknowledgement_cannot_settle_a_given_up_message() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "nobody read this".into(),
            },
        );
        let conversation = conversation_of(&a, 0);

        let past = BASE_MS + GIVE_UP_MS;
        let mut given_up = deliveries_in(&a.on_tick(past));
        given_up.sort_unstable_by_key(|(seq, _)| *seq);
        // Sequence zero is the knock; the acceptance's own piggyback confirmed
        // it at establishment and this run has already said so, so the tick
        // reports only the message under test.
        assert_eq!(
            given_up,
            vec![(1, DeliveryState::Undelivered)],
            "the message nobody read must be reported undelivered at the give-up"
        );

        let effects = ack_fetched(&mut a, past, conversation, ack_record_from(&b, 0, &[0, 1]));
        assert_eq!(
            deliveries_in(&effects),
            Vec::new(),
            "a late acknowledgement settled a message this sender gave up on: {effects:?}"
        );
    }

    /// M31. Each of the two gates holds the give-up rule on its own.
    ///
    /// `Outbox::settle_from_ack` refuses a given-up entry twice over — by
    /// lifecycle and by the clock — and M30 runs them together, so it passes
    /// while either one is intact. These two fixtures separate them, because
    /// there is a real window in which only one applies and the ordering of two
    /// unrelated calls is not something the truth of a delivery indicator should
    /// depend on.
    ///
    /// **Before the sweep, only the clock gate applies.** A give-up is a swept
    /// transition, so between the seventh day and the next tick the entry is past
    /// its window and still `AwaitingCollection` — exactly the window in which
    /// the receiver may legitimately abandon that position and write an ack that
    /// says *settled*.
    ///
    /// **After a settle, only the lifecycle gate applies.** A confirmed entry is
    /// inside its window and terminal, and a record re-fetched on the next tick
    /// carries the identical claim; a second confirmation for one message is a
    /// front end told twice.
    #[test]
    fn each_give_up_gate_refuses_a_late_acknowledgement_on_its_own() {
        // ── the clock gate alone: past the window, before any sweep ──────────
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "nobody read this either".into(),
            },
        );
        let conversation = conversation_of(&a, 0);
        let label_a = sole_label(&a);
        let past = BASE_MS + GIVE_UP_MS;
        assert_eq!(
            outbox_state(&a, &label_a, 1, past),
            DeliveryState::Composed,
            "the fixture must reach the give-up with the entry still live, or the \
             lifecycle gate is doing this work instead"
        );
        let effects = ack_fetched(&mut a, past, conversation, ack_record_from(&b, 0, &[0, 1]));
        assert_eq!(
            deliveries_in(&effects),
            Vec::new(),
            "an entry past its window must not settle before the sweep has run: {effects:?}"
        );

        // ── the lifecycle gate alone: settled, inside the window ─────────────
        let dir_c = tempfile::tempdir().expect("temp dir C");
        let dir_d = tempfile::tempdir().expect("temp dir D");
        let mut c = machine(&dir_c);
        let mut d = machine_as(peer_identity(), &dir_d);
        d.persist.provision_block_list().expect("provision");
        establish_pair(&mut c, &mut d, &b_keys);
        c.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "read in time".into(),
            },
        );
        let conversation = conversation_of(&c, 0);
        let effects = ack_fetched(
            &mut c,
            BASE_MS,
            conversation,
            ack_record_from(&d, 0, &[0, 1]),
        );
        assert_eq!(
            deliveries_in(&effects),
            vec![(1, DeliveryState::ConfirmedCollected)],
            "the fixture must actually settle once, or the re-fetch below is vacuous: {effects:?}"
        );
        let effects = ack_fetched(
            &mut c,
            BASE_MS,
            conversation,
            ack_record_from(&d, 0, &[0, 1]),
        );
        assert_eq!(
            deliveries_in(&effects),
            Vec::new(),
            "the same claim, re-fetched on the next tick, confirmed a message \
             twice: {effects:?}"
        );
    }

    /// M32. A record from another conversation settles nothing.
    ///
    /// **A replay across conversations, and every layer refuses it.** The record
    /// is genuine — this acceptor built and signed it — but for a different
    /// correspondent: its address root derives a different sealing key, its
    /// `chan_id` is bound in the AAD and in the signature preimage, and its
    /// pseudonym is a fresh key minted per contact. So it fails at the AEAD
    /// before any signature is examined, which is the layer a reader reaches
    /// first.
    ///
    /// The honest record afterwards is the positive control: without it,
    /// "nothing settled" is satisfied by a fixture that folds nothing at all.
    #[test]
    fn a_record_from_another_conversation_settles_nothing() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_c = tempfile::tempdir().expect("temp dir C");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        let mut a = machine(&dir_a);
        let mut c = machine_as(third_identity(), &dir_c);
        establish_pair(&mut a, &mut b, &b_keys);
        establish_pair(&mut c, &mut b, &b_keys);
        assert_eq!(
            b.correspondences.len(),
            2,
            "the fixture needs the acceptor to hold two conversations"
        );
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "meant for A".into(),
            },
        );
        let conversation = conversation_of(&a, 0);

        // The acceptor's record for its OTHER correspondent, handed to A.
        let elsewhere = ack_record_from(&b, 1, &[0, 1]);
        let effects = ack_fetched(&mut a, BASE_MS, conversation, elsewhere);
        assert_eq!(
            deliveries_in(&effects),
            Vec::new(),
            "a record built for another conversation settled an entry: {effects:?}"
        );
        assert_eq!(
            a.correspondences[0].health.peer_acks_unverified, 1,
            "a record that will not open must be counted"
        );

        let effects = ack_fetched(
            &mut a,
            BASE_MS,
            conversation,
            ack_record_from(&b, 0, &[0, 1]),
        );
        assert_eq!(
            deliveries_in(&effects),
            vec![(1, DeliveryState::ConfirmedCollected)],
            "the same fixture must settle under this conversation's own record: {effects:?}"
        );
    }

    /// M33. A send time in the future cannot pin the cadence open.
    ///
    /// `sent_unix_ms` is peer-asserted and signed, which authenticates it as a
    /// statement and bounds it in no other way. Stored verbatim, a time in the
    /// future never satisfies `now_ms - sent_ms >= give_up_ms`, so the entry
    /// never ages out: the conversation never terminates, writes a standalone
    /// acknowledgement for ever against a sender that gave up years ago, and —
    /// because the ordering key is the smallest value — takes the client-global
    /// allowance from every honest correspondence while doing it.
    ///
    /// The clamp is what closes it, and the give-up is the observable: past the
    /// window there must be no write at all.
    #[test]
    fn a_send_time_in_the_future_still_ages_out_of_the_pending_set() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // Ten years ahead of the collector's clock, asserted by a frame that is
        // otherwise entirely well formed and opens normally.
        const TEN_YEARS_MS: i64 = 10 * 365 * 24 * 60 * 60 * 1000;
        let ahead = BASE_MS + TEN_YEARS_MS;
        a.on_command(
            ahead,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "from the future".into(),
            },
        );
        let label_a = sole_label(&a);
        let frame = queued_frame_at(&a, &label_a, 1, ahead);
        let conversation = conversation_of(&b, 0);
        let folded = fold_page_at(
            &mut b,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(1), frame)],
        );
        assert_eq!(
            messages_in(&folded),
            vec!["from the future".to_string()],
            "the fixture must have collected the frame, or nothing is pending: {folded:?}"
        );
        // **No assertion on the clamped value here, deliberately.** The clamp is
        // asserted by its consequence below: a shape check at this point would
        // fail first under any mutation and leave the thing that actually
        // matters — that the cadence stops — untested.

        // A march past the give-up, at the same half-hour step the taper test
        // uses, counting only what is written after the window has closed.
        const STEP_MS: i64 = 30 * 60 * 1000;
        let mut written_before = 0u64;
        let mut written_after = 0u64;
        let mut now = BASE_MS;
        while now <= BASE_MS + GIVE_UP_MS + STEP_MS * 4 {
            let effects = b.standalone_acks(now);
            let published = ack_publishes(&effects);
            for conversation in &published {
                ack_written(&mut b, now, *conversation);
            }
            if now - BASE_MS >= GIVE_UP_MS {
                written_after += published.len() as u64;
            } else {
                written_before += published.len() as u64;
            }
            now += STEP_MS;
        }
        assert!(
            written_before >= 1,
            "the fixture must have acknowledged the message while it was live, \
             or the silence afterwards is silence about nothing"
        );
        assert_eq!(
            written_after, 0,
            "a peer-asserted future send time kept the cadence writing past the \
             sender's own give-up"
        );
        assert!(
            b.correspondences[0].pending_sent_ms.is_empty(),
            "the clamped entry must age out with the window, leaving: {:?}",
            b.correspondences[0].pending_sent_ms
        );
    }

    // ---- handing page records back (#252) ----------------------------------

    /// Run every page operation in `effects` against `dht`, so the mock's record
    /// bookkeeping sees exactly what the machine asked the transport for.
    ///
    /// Routed through the driver's own `dispatch`, never through a match written
    /// here: a fixture that called the seam method itself would prove the mock
    /// counts what the fixture asked for, which is not the question. The results
    /// are dropped — what a page *contains* is fed back by `fold_page_at`, and
    /// what this is reading is which records are open.
    async fn run_page_ops(dht: &std::sync::Arc<MockDht>, effects: Vec<DmEffect>) {
        for effect in effects {
            let DmEffect::Dht(op) = effect else {
                continue;
            };
            if matches!(
                op.kind(),
                DhtOpKind::SweepPage | DhtOpKind::PublishPage | DhtOpKind::ClosePage
            ) {
                crate::dm::driver::dispatch(dht.clone(), op).await;
            }
        }
    }

    /// How many page closes the mock has been asked for, and how many released a
    /// record. Read from the log rather than the counter, because a close of a
    /// page nothing opened is the same call as one that reclaims a record.
    fn closes_seen(dht: &MockDht) -> (usize, usize) {
        let log = dht.log();
        let asked: Vec<bool> = log
            .iter()
            .filter_map(|call| match call {
                MockCall::ClosePage { closed, .. } => Some(*closed),
                _ => None,
            })
            .collect();
        (asked.len(), asked.iter().filter(|c| **c).count())
    }

    /// Queue `count` channel messages from `from` to `to`, and fold each one into
    /// `to` on the page it belongs to, one page at a time.
    ///
    /// Returns the sequence numbers queued, so a caller can assert it actually
    /// sent what it asked for rather than trusting the loop.
    fn queue_sends(from: &mut DmMachine, to_pk: &[u8; IDENTITY_PK_LEN], count: usize) -> Vec<u64> {
        let label = sole_label(from);
        let mut seqs = Vec::new();
        for _ in 0..count {
            let out = from.on_command(
                BASE_MS,
                DmCommand::Send {
                    to: Box::new(*to_pk),
                    body: "m".into(),
                },
            );
            let seq = deliveries_in(&out)
                .into_iter()
                .find_map(|(seq, state)| (state == DeliveryState::Composed).then_some(seq))
                .expect("a send must compose an entry");
            seqs.push(seq);
        }
        let _ = label;
        seqs
    }

    /// M22e. The count of open page records does not grow with the length of a
    /// conversation: once a page is settled and out of the watched window it is
    /// handed back, and what stays open is the window itself.
    ///
    /// **The failure this pins is monotonic growth, so it needs more than one
    /// page.** A new page owner seed appears every `PAGE_SLOTS` messages per
    /// direction, and every other record family this client holds is bounded by
    /// peers — so a conversation that never gives a page back is the one shape
    /// whose open-record count rises with traffic and never falls.
    ///
    /// The width is read from `collect`'s own constant, not written as a two: the
    /// claim is that what remains open is the watched window, and a literal would
    /// keep passing if the window were widened.
    ///
    /// Two controls, and the assertion means nothing without either. The
    /// conversation is asserted to have REACHED more distinct pages than the
    /// window — a peak-held-open control would be satisfiable only by the bug,
    /// since reclamation working means the peak never rises — and every close is
    /// asserted to have released a record the mock was holding, so the count
    /// cannot be reached by closing pages nobody opened.
    #[tokio::test(start_paused = true)]
    async fn the_open_page_count_stays_at_the_watched_window_across_a_long_conversation() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;
        /// How many whole pages the correspondent fills. Two is the least that can
        /// show a count falling back rather than merely never rising.
        const FULL_PAGES: u64 = 2;

        // The width, from the constant the plan is built from, so every count below
        // is compared against the window rather than against a literal two that only
        // happens to equal it. No assertion pins the two together because none can:
        // `watched()` RETURNS `[u64; WATCHED_PAGES]`, so the equality is the type's
        // and a test of it could never fail. The control that carries this test is
        // `reached.len() > width` at the foot.
        let width = daemonseed_core::dm::collect::WATCHED_PAGES;

        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let dht = std::sync::Arc::new(MockDht::new(Duration::from_millis(1)));
        let list = stored_block_list(&a);
        let conversation = conversation_of(&a, 0);
        let label_b = sole_label(&b);
        let a_pk = *keys().signing.public_key();

        // One frame past the last full page, so the frontier reaches the page
        // above the settled ones — a page is retired by BOTH pointers passing it.
        let last_seq = FULL_PAGES * u64::from(PAGE_SLOTS);
        let queued = queue_sends(&mut b, &a_pk, last_seq as usize);
        assert_eq!(
            queued.first().copied(),
            Some(1),
            "the acceptor's channel sends must start above its acceptance"
        );
        assert_eq!(
            queued.last().copied(),
            Some(last_seq),
            "the fixture must have queued through the first slot of the page above"
        );

        let mut now = BASE_MS;
        for page in 0..=FULL_PAGES {
            // The plan first, so the pages this fold is about are records the
            // transport is actually holding open.
            now += PROBE_MS;
            let planned = a.probe(now, 0, Some(&list));
            let asked = swept_pages(&planned);
            assert!(
                !asked.is_empty(),
                "page {page}'s plan asked for nothing, so nothing below is open"
            );
            run_page_ops(&dht, planned).await;
            assert!(
                dht.open_page_count() <= width,
                "the count of open records must never exceed the window, and it did \
                 at page {page}: {}",
                dht.open_page_count()
            );

            // Every sweep this plan asked for comes back, which is what
            // production guarantees and what this test is NOT about: a page left
            // in flight is skipped by the close path on purpose, and the test that
            // pins that is its own. The page under test is released by its fold.
            for other in asked.into_iter().filter(|p| *p != page) {
                let out = a.on_outcome(
                    now,
                    page_outcome(conversation, other, Ok(empty_page(conversation))),
                );
                run_page_ops(&dht, out).await;
            }

            let slots: Vec<(PagePosition, Vec<u8>)> = queued
                .iter()
                .copied()
                .filter(|seq| position_of(*seq).page() == page)
                .map(|seq| {
                    (
                        position_of(seq),
                        queued_frame_at(&b, &label_b, seq, BASE_MS),
                    )
                })
                .collect();
            assert!(
                !slots.is_empty(),
                "page {page} carried no frames, so it settles nothing"
            );
            let folded = fold_page_at(&mut a, now, conversation, page, slots);
            assert!(
                !messages_in(&folded).is_empty(),
                "page {page} folded no message: {folded:?}"
            );
            run_page_ops(&dht, folded).await;
        }

        // One more cadence, so the count read below is the STEADY state — the
        // window as the plan would next ask for it — rather than whatever the last
        // fold happened to leave behind.
        now += PROBE_MS;
        let planned = a.probe(now, 0, Some(&list));
        assert_eq!(
            swept_pages(&planned).len(),
            width,
            "the settled conversation's plan must be the watched window and nothing \
             else: {planned:?}"
        );
        run_page_ops(&dht, planned).await;

        // The positive control, and it has to be the pages the conversation
        // REACHED rather than the peak held open: reclamation working perfectly
        // means the peak never exceeds the window, so a peak-based control can only
        // be satisfied by the bug. A conversation spanning more distinct pages than
        // the window is one an open-once transport would be holding more than the
        // window for.
        let mut reached: Vec<u64> = dht
            .log()
            .into_iter()
            .filter_map(|call| match call {
                MockCall::SweepPage { page, .. } => Some(page),
                _ => None,
            })
            .collect();
        reached.sort_unstable();
        reached.dedup();
        assert!(
            reached.len() > width,
            "the conversation only ever reached {} distinct pages, which is not more \
             than the window: nothing here could have been reclaimed",
            reached.len()
        );
        assert_eq!(
            dht.open_page_count(),
            width,
            "a settled conversation must hold exactly the watched window open"
        );
        let (asked, closed) = closes_seen(&dht);
        assert_eq!(
            asked, closed,
            "every close asked for must have released a record the transport was \
             holding; a close of an unopened page reclaims nothing"
        );
        assert_eq!(
            closed,
            usize::try_from(FULL_PAGES).expect("small"),
            "one record per settled page must have been handed back"
        );
    }

    /// M22f. A page whose sweep is in flight is not handed back until that sweep's
    /// outcome lands.
    ///
    /// Closing a record mid-sweep turns its remaining reads into `outcome.failed`
    /// — the signal a collector is told to read as record ill-health — so the page
    /// is skipped rather than closed, and offered again by the next settlement.
    /// The outcome landing IS that next settlement, which is what makes the
    /// deferral bounded rather than a leak.
    ///
    /// The control is the second half: without the close arriving after the
    /// outcome, "it was not closed" is satisfied by a machine that never closes
    /// anything.
    #[tokio::test(start_paused = true)]
    async fn a_page_with_a_sweep_in_flight_is_not_closed_until_the_outcome_lands() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;

        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let list = stored_block_list(&a);
        let conversation = conversation_of(&a, 0);
        let label_b = sole_label(&b);
        let a_pk = *keys().signing.public_key();
        let last_seq = u64::from(PAGE_SLOTS);
        let queued = queue_sends(&mut b, &a_pk, last_seq as usize);

        let frames = |page: u64| -> Vec<(PagePosition, Vec<u8>)> {
            queued
                .iter()
                .copied()
                .filter(|seq| position_of(*seq).page() == page)
                .map(|seq| {
                    (
                        position_of(seq),
                        queued_frame_at(&b, &label_b, seq, BASE_MS),
                    )
                })
                .collect()
        };

        // Page zero's own sweep comes back, so it is settled and released.
        let planned = a.probe(BASE_MS, 0, Some(&list));
        assert_eq!(
            swept_pages(&planned),
            vec![0, 1],
            "the watched pair must be planned, or the flight below is not arranged"
        );
        let folded = fold_page_at(&mut a, BASE_MS, conversation, 0, frames(0));
        assert!(
            !messages_in(&folded).is_empty(),
            "page zero folded nothing: {folded:?}"
        );

        // Page zero is asked for AGAIN and left in flight. Page one's outcome has
        // never been delivered, so it is skipped and the plan is page zero alone.
        let now = BASE_MS + PROBE_MS;
        let replanned = a.probe(now, 0, Some(&list));
        assert_eq!(
            swept_pages(&replanned),
            vec![0],
            "page zero must be back in flight, or the case under test is absent"
        );

        // Page one's fold settles the last position of page zero and lifts the
        // frontier, so page zero is now retirable in every respect but one.
        let folded = fold_page_at(&mut a, now, conversation, 1, frames(1));
        assert!(
            !messages_in(&folded).is_empty(),
            "page one folded nothing: {folded:?}"
        );
        assert!(
            closed_pages(&folded).is_empty(),
            "a page whose sweep is in flight must not be handed back: {folded:?}"
        );

        // The outcome lands: the sweep is no longer in flight, and the fold it
        // arrives through is the settlement that offers the page again.
        let landed = a.on_outcome(
            now,
            page_outcome(conversation, 0, Ok(empty_page(conversation))),
        );
        assert_eq!(
            closed_pages(&landed),
            vec![0],
            "the outcome landing must release the page it was holding: {landed:?}"
        );
    }

    /// M22g. A torn-down channel hands back every page record of its
    /// conversation, settled or not.
    ///
    /// A teardown ends the conversation on this side — the ratchet opens nothing
    /// more and the pending entries are terminal — so settlement is the wrong
    /// question: a page above the frontier is as finished as one below it. Both
    /// directions are covered, because a conversation holds records it wrote as
    /// well as records it read.
    #[tokio::test(start_paused = true)]
    async fn a_torn_down_channel_hands_back_every_page_of_its_conversation() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let conversation = conversation_of(&b, 0);
        let list = stored_block_list(&b);

        // B's own acceptance is queued at sequence zero, so a tick publishes it:
        // that is the sending page. The tick also plans the watched pair, which is
        // the receiving side.
        let ticked = b.on_tick(BASE_MS);
        let swept = swept_pages(&ticked);
        assert_eq!(
            swept,
            vec![0, 1],
            "the watched pair must have been planned: {ticked:?}"
        );
        let published: Vec<u64> = ticked
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, .. }) => tag.page,
                _ => None,
            })
            .collect();
        assert_eq!(
            published,
            vec![0],
            "the acceptance must have been published, or no sending page is open"
        );

        // Both in-flight operations come back, so neither direction is skipped for
        // being busy — the case under test is the teardown, not the guard.
        b.on_outcome(
            BASE_MS,
            page_outcome(conversation, 0, Ok(empty_page(conversation))),
        );
        b.on_outcome(
            BASE_MS,
            page_outcome(conversation, 1, Ok(empty_page(conversation))),
        );
        b.on_outcome(
            BASE_MS,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::PublishPage,
                tag: OpTag {
                    conversation: Some(conversation),
                    seq: Some(0),
                    page: Some(0),
                    correspondent: Some(Box::new(*keys().signing.public_key())),
                    introduction: None,
                },
                result: Ok(DhtResult::Written),
            }),
        );

        // A knocks again from a machine that lost its state, which is what makes
        // the re-knock a teardown rather than an ordinary re-send.
        let dir_a2 = tempfile::tempdir().expect("temp dir A2");
        let mut a2 = machine(&dir_a2);
        let (_, entry) = knock_as_initiator(&mut a2, &b_keys);
        let _ = &a;
        let _ = &list;
        let out = b.on_doorbell(BASE_MS, sweep_of(vec![(11, entry)]));
        // The length first: a search over an empty batch answers the same as a
        // search that found nothing, and only one of those is the case under test.
        assert!(
            !out.is_empty(),
            "the re-knock produced no effects at all, so nothing below is a search"
        );
        assert!(
            out.iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ChannelLost { .. }))),
            "the re-knock did not tear the channel down: {out:?}"
        );

        let mut closed = closed_pages(&out);
        closed.sort_unstable();
        assert_eq!(
            closed,
            vec![0, 0, 1],
            "a teardown must hand back both directions of page zero and the \
             unsettled receiving page above it: {out:?}"
        );
    }

    /// M22h. A sending page every position of which this side gave up on is handed
    /// back, so a permanently undelivered message does not pin its page open.
    ///
    /// **The give-up is the only thing that can settle these positions, and without
    /// it the bound has a hole the size of the conversation.** The correspondent
    /// never acknowledges a message they never received, so `own_ack`'s prefix stops
    /// at the first lost position, `settled_pages_below` answers zero for ever, and
    /// no sending page closes again for the life of the process — the growth #252 is
    /// about, reached through the one door an acknowledgement cannot close.
    ///
    /// A whole page is filled, because a page is finished only when every position
    /// it holds is settled, and the positions above the highest one ever sent are
    /// not going to be. That is the rule working rather than a limit of the fixture:
    /// the page still being written to must stay open.
    ///
    /// The control is the state before the give-up: the page is asserted NOT
    /// closable while the messages are merely unacknowledged, so the close afterwards
    /// is the give-up and not the passage of time.
    #[test]
    fn a_given_up_sending_page_is_handed_back() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // Sequence zero is the knock, which the establishment already settled, so
        // filling page zero means the fifteen channel positions above it.
        let b_pk = *b_keys.signing.public_key();
        let queued = queue_sends(&mut a, &b_pk, usize::from(PAGE_SLOTS) - 1);
        assert_eq!(
            queued.last().copied(),
            Some(u64::from(PAGE_SLOTS) - 1),
            "the fixture must have filled page zero"
        );

        let conversation = conversation_of(&a, 0);
        let ticked = a.on_tick(BASE_MS);
        let published: Vec<u64> = ticked
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, .. }) => tag.seq,
                _ => None,
            })
            .collect();
        assert_eq!(
            published.len(),
            queued.len(),
            "every queued message must have been published, or no sending page is \
             open: {ticked:?}"
        );
        for seq in &published {
            written(&mut a, BASE_MS, conversation, &b_pk, *seq);
        }

        // The control: unacknowledged is not settled, so the page stays.
        assert_eq!(
            a.correspondences[0].own_ack.settled_pages_below(),
            0,
            "unacknowledged positions must settle no page, or the close below is \
             not the give-up"
        );
        assert!(
            a.open_send_pages.contains(&(conversation, 0)),
            "the sending page must be open before the give-up"
        );

        let past = BASE_MS + GIVE_UP_MS + 1;
        let given = a.give_ups(past, 0);
        let undelivered: Vec<u64> = deliveries_in(&given)
            .into_iter()
            .filter(|(_, state)| *state == DeliveryState::Undelivered)
            .map(|(seq, _)| seq)
            .collect();
        assert_eq!(
            undelivered, queued,
            "the fixture must actually have given up on every message: {given:?}"
        );
        assert_eq!(
            a.correspondences[0].own_ack.settled_pages_below(),
            1,
            "the give-up must settle the page through"
        );
        assert_eq!(
            closed_pages(&given),
            vec![0],
            "a page every position of which is settled — by collection or by this \
             side's own give-up — must be handed back: {given:?}"
        );
        assert!(
            !a.open_send_pages.contains(&(conversation, 0)),
            "and it must leave the open set"
        );
    }

    /// M22i. A page WRITE that panicked releases the slot it was holding, so the
    /// close path can still reach that sending page.
    ///
    /// The twin of the sweep case, and the consequence differs. A dead sweep leaves
    /// a page that is never read again; a dead write leaves a page that is never
    /// *closed* again — `publishing_pages` is what stops the close path handing a
    /// record back mid-write, so a slot nothing releases refuses that page for the
    /// life of the driver.
    ///
    /// The control is the give-up before the panic outcome: the page is asserted
    /// unclosable while one write is still in flight, so the close afterwards is the
    /// release and not the settlement.
    #[test]
    fn a_panicked_page_write_releases_the_page_it_was_holding() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let b_pk = *b_keys.signing.public_key();
        let queued = queue_sends(&mut a, &b_pk, usize::from(PAGE_SLOTS) - 1);
        let conversation = conversation_of(&a, 0);
        let ticked = a.on_tick(BASE_MS);
        let writes: Vec<&DhtOp> = ticked
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(op @ DhtOp::PublishPage { .. }) => Some(op),
                _ => None,
            })
            .collect();
        assert_eq!(
            writes.len(),
            queued.len(),
            "every queued message must have been published: {ticked:?}"
        );
        // What the shell records BEFORE spawning, which is the only route from a
        // dead task back to the slot the machine is holding.
        let job = writes[0].panicked_job();
        assert!(
            matches!(job, Some(PanickedJob::PagePublish { page: 0, .. })),
            "a page write must record the slot it holds: {job:?}"
        );
        // Every other write lands; the first one's task dies.
        let landed: Vec<u64> = writes[1..]
            .iter()
            .filter_map(|op| match op {
                DhtOp::PublishPage { tag, .. } => tag.seq,
                _ => None,
            })
            .collect();
        for seq in landed {
            written(&mut a, BASE_MS, conversation, &b_pk, seq);
        }
        assert!(
            a.publishing_pages.contains_key(&(conversation, 0)),
            "the dead write must still be recorded in flight, or the release below \
             is vacuous"
        );

        // The give-up settles every position, so the ONLY thing left holding the
        // page is the dead write.
        let past = BASE_MS + GIVE_UP_MS + 1;
        let given = a.give_ups(past, 0);
        assert_eq!(
            a.correspondences[0].own_ack.settled_pages_below(),
            1,
            "the give-up must have settled the page through, or the refusal below \
             is settlement rather than the in-flight slot"
        );
        assert!(
            closed_pages(&given).is_empty(),
            "a page whose write is in flight must not be handed back: {given:?}"
        );

        a.on_outcome(past, DmOutcome::Panicked { job });
        assert!(
            !a.publishing_pages.contains_key(&(conversation, 0)),
            "the panicked write must have released its slot"
        );
        let given = a.give_ups(past + 1, 0);
        assert_eq!(
            closed_pages(&given),
            vec![0],
            "and the page must then be reachable by the close path: {given:?}"
        );
    }

    /// Tell `m` that one page write it asked for landed.
    fn written(
        m: &mut DmMachine,
        now_ms: i64,
        conversation: [u8; AR_FINGERPRINT_LEN],
        correspondent: &[u8; IDENTITY_PK_LEN],
        seq: u64,
    ) {
        m.on_outcome(
            now_ms,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::PublishPage,
                tag: OpTag {
                    conversation: Some(conversation),
                    seq: Some(seq),
                    page: Some(position_of(seq).page()),
                    correspondent: Some(Box::new(*correspondent)),
                    introduction: None,
                },
                result: Ok(DhtResult::Written),
            }),
        );
    }

    /// M22k. A peer acknowledgement that settles a whole sending page hands that
    /// page back, and leaves the page above it open.
    ///
    /// **The only Sending close otherwise under test is the teardown's, which passes
    /// [`u64::MAX`] and bypasses the settlement bound entirely.** So without this the
    /// bound `settled_pages_below` computes has no oracle on the path that actually
    /// uses it, and an off-by-one that retired a page still holding unsettled
    /// positions would pass the whole suite.
    ///
    /// The page above is the control, and it is the half that separates the correct
    /// bound from `prefix's page + 1`: page one is asserted STILL OPEN with its first
    /// position acknowledged, which is exactly the state the off-by-one would
    /// release.
    #[test]
    fn a_peer_acknowledgement_hands_back_the_sending_page_it_finishes() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // Page zero's fifteen channel positions plus the first of page one, so both
        // pages are open and only one of them is finished.
        let b_pk = *b_keys.signing.public_key();
        let queued = queue_sends(&mut a, &b_pk, usize::from(PAGE_SLOTS));
        assert_eq!(
            queued.last().copied(),
            Some(u64::from(PAGE_SLOTS)),
            "the fixture must reach the first position of page one"
        );
        let conversation = conversation_of(&a, 0);
        let ticked = a.on_tick(BASE_MS);
        let published: Vec<u64> = ticked
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, .. }) => tag.seq,
                _ => None,
            })
            .collect();
        assert_eq!(
            published.len(),
            queued.len(),
            "every queued message must have been published: {ticked:?}"
        );
        for seq in &published {
            written(&mut a, BASE_MS, conversation, &b_pk, *seq);
        }
        assert!(
            a.open_send_pages.contains(&(conversation, 0))
                && a.open_send_pages.contains(&(conversation, 1)),
            "both sending pages must be open before the acknowledgement"
        );

        // B says it collected everything A sent, which settles page zero through and
        // exactly one position of page one.
        let settled: Vec<u64> = (0..=u64::from(PAGE_SLOTS)).collect();
        let record = ack_record_from(&b, 0, &settled);
        let folded = ack_fetched(&mut a, BASE_MS, conversation, record);
        assert_eq!(
            a.correspondences[0].own_ack.high_water(),
            Some(u64::from(PAGE_SLOTS)),
            "the fixture must have merged the acknowledgement it built"
        );
        assert_eq!(
            closed_pages(&folded),
            vec![0],
            "the finished page must be handed back and the page above it left \
             alone: {folded:?}"
        );
        assert!(
            !a.open_send_pages.contains(&(conversation, 0)),
            "page zero must leave the open set"
        );
        assert!(
            a.open_send_pages.contains(&(conversation, 1)),
            "page one still holds fifteen unsettled positions and must stay open — \
             this is the assertion an off-by-one in the bound fails"
        );
    }

    /// M22l. A sending page whose publish is in flight is not handed back until that
    /// write's outcome lands.
    ///
    /// The write-side mirror of the sweep case, and the guard is a refcount rather
    /// than a flag: a tick puts a write on every due position of a page, so presence
    /// alone would let the first outcome release the record while the rest were
    /// still running.
    ///
    /// The control is the second half: without the close arriving once the last
    /// write lands, "it was not closed" is satisfied by a machine that never closes
    /// a sending page at all.
    #[test]
    fn a_page_with_a_publish_in_flight_is_not_closed_until_the_outcome_lands() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let b_pk = *b_keys.signing.public_key();
        let queued = queue_sends(&mut a, &b_pk, usize::from(PAGE_SLOTS) - 1);
        let conversation = conversation_of(&a, 0);
        let ticked = a.on_tick(BASE_MS);
        let published: Vec<u64> = ticked
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, .. }) => tag.seq,
                _ => None,
            })
            .collect();
        assert_eq!(
            published.len(),
            queued.len(),
            "every queued message must have been published: {ticked:?}"
        );
        // All but one land. The page is one write short of quiet, which is the whole
        // case: under a flag rather than a refcount it would already read as free.
        for seq in &published[1..] {
            written(&mut a, BASE_MS, conversation, &b_pk, *seq);
        }
        assert!(
            a.publishing_pages.contains_key(&(conversation, 0)),
            "one write must still be in flight, or nothing below is a refusal"
        );

        // Everything is settled, so settlement is not what is holding the page.
        let settled: Vec<u64> = (0..u64::from(PAGE_SLOTS)).collect();
        let record = ack_record_from(&b, 0, &settled);
        let folded = ack_fetched(&mut a, BASE_MS, conversation, record);
        assert_eq!(
            a.correspondences[0].own_ack.settled_pages_below(),
            1,
            "the acknowledgement must have finished the page, or the refusal below \
             is settlement rather than the in-flight write"
        );
        assert!(
            closed_pages(&folded).is_empty(),
            "a page whose write is in flight must not be handed back: {folded:?}"
        );

        // The last write lands, releasing the page. Its own outcome is NOT a
        // settlement pass — `confirm_written` folds the outbox entry and never calls
        // `retire_pages` — so the page is not offered again there, and something has
        // to drive the next one. `give_ups` below is the cheapest such pass: it
        // settles nothing new here (everything is already acknowledged) and ends in
        // the same `retire_pages` every settlement path ends in.
        let landed = a.on_outcome(
            BASE_MS,
            DmOutcome::Dht(DhtOutcome {
                kind: DhtOpKind::PublishPage,
                tag: OpTag {
                    conversation: Some(conversation),
                    seq: Some(published[0]),
                    page: Some(0),
                    correspondent: Some(Box::new(b_pk)),
                    introduction: None,
                },
                result: Ok(DhtResult::Written),
            }),
        );
        assert!(
            !a.publishing_pages.contains_key(&(conversation, 0)),
            "the last write's outcome must have released the page"
        );
        assert!(
            closed_pages(&landed).is_empty(),
            "the write's own outcome folds the outbox and offers no page: {landed:?}"
        );
        let given = a.give_ups(BASE_MS + 1, 0);
        assert_eq!(
            closed_pages(&given),
            vec![0],
            "and the page must then be handed back: {given:?}"
        );
    }

    /// M22m. A page whose sweep was in flight at teardown is handed back when that
    /// sweep's outcome lands, and not before.
    ///
    /// **The residual the teardown close alone leaves.** `close_all_pages` skips a
    /// page an operation is holding, as it must; and after a teardown nothing
    /// reaches that page again — `probe` and `ack_fetches` are gated, and
    /// `retire_pages` is bounded by a settlement a dead conversation will never
    /// produce. Without the release path offering it, that record sits open until
    /// the transport's capacity bound evicts it, which is the one class of page the
    /// teardown claims to reclaim and would not.
    ///
    /// Both halves are asserted: the page is NOT among the teardown's closes, and it
    /// IS closed, exactly once, when its outcome arrives.
    #[test]
    fn a_page_in_flight_at_teardown_is_handed_back_when_its_outcome_lands() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        let conversation = conversation_of(&b, 0);
        let ticked = b.on_tick(BASE_MS);
        let planned = swept_pages(&ticked);
        assert_eq!(
            planned,
            vec![0, 1],
            "the watched pair must be in flight, or there is no busy page to strand"
        );
        // Page one's sweep comes back; page zero's is left running. So exactly one
        // receiving page is busy at the moment of the teardown.
        b.on_outcome(
            BASE_MS,
            page_outcome(conversation, 1, Ok(empty_page(conversation))),
        );

        let dir_a2 = tempfile::tempdir().expect("temp dir A2");
        let mut a2 = machine(&dir_a2);
        let (_, entry) = knock_as_initiator(&mut a2, &b_keys);
        let _ = &a;
        let out = b.on_doorbell(BASE_MS, sweep_of(vec![(11, entry)]));
        assert!(
            out.iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ChannelLost { .. }))),
            "the re-knock did not tear the channel down: {out:?}"
        );
        let mut at_teardown = closed_pages(&out);
        at_teardown.sort_unstable();
        assert!(
            !at_teardown.is_empty(),
            "the teardown must close the pages that were free, or the omission below \
             is not about the busy one"
        );
        assert!(
            !at_teardown.contains(&0),
            "the page whose sweep is in flight must NOT be closed at teardown: \
             {at_teardown:?}"
        );

        // The sweep comes back. It is the last signal this conversation will ever
        // produce, and it is what hands the page back.
        let landed = b.on_outcome(
            BASE_MS,
            page_outcome(conversation, 0, Ok(empty_page(conversation))),
        );
        assert_eq!(
            closed_pages(&landed),
            vec![0],
            "the outcome that freed the page must hand it back: {landed:?}"
        );
        // Exactly once: the page left the open set, so a second outcome offers
        // nothing.
        let again = b.on_outcome(
            BASE_MS,
            page_outcome(conversation, 0, Ok(empty_page(conversation))),
        );
        assert!(
            closed_pages(&again).is_empty(),
            "a page already handed back must not be closed twice: {again:?}"
        );
    }

    /// M22n. A torn-down correspondence does not compete for the client-global
    /// acknowledgement allowance, however old the positions it still holds.
    ///
    /// **The write gate alone is not enough, and the failure it leaves is
    /// starvation rather than a stray write.** `publish_standalone_ack` refuses the
    /// write, but a candidate that reaches the pick has already spent the permit —
    /// one per sixty seconds, client-global — on a write that never happens. And a
    /// teardown ends neither `live()` nor the pending set, whose entries age out
    /// only at their own give-up, so a dead correspondence carries the OLDEST key
    /// and wins every round for up to a week. Two of them alternate under the
    /// anti-repeat rule and a live conversation is never served at all.
    ///
    /// The positions are collected AFTER the teardown here, which is the case the
    /// scan gate exists for rather than a contrivance: a sweep issued before the
    /// teardown lands after it, `on_page` folds it, and the pending set the teardown
    /// cleared is repopulated. That is also what keeps this test honest about which
    /// of the two gates it is exercising — with an empty pending set the scan would
    /// skip the correspondence anyway and the gate could be deleted unnoticed.
    ///
    /// The control is the age: the torn-down correspondence's position is a full
    /// minute older, so "the live one won" cannot be the iteration order.
    #[test]
    fn a_torn_down_correspondence_does_not_take_the_acknowledgement_allowance() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_c = tempfile::tempdir().expect("temp dir C");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        let mut a = machine(&dir_a);
        let mut c = machine_as(third_identity(), &dir_c);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        establish_pair(&mut c, &mut b, &b_keys);
        assert_eq!(
            b.correspondences.len(),
            2,
            "the fixture needs two correspondences competing for one allowance"
        );
        let doomed = conversation_of(&a, 0);
        let live = conversation_of(&c, 0);

        const GAP_MS: i64 = 60_000;
        let older = BASE_MS;
        let newer = BASE_MS + GAP_MS;
        for (sender, at) in [(&mut a, older), (&mut c, newer)] {
            sender.on_command(
                at,
                DmCommand::Send {
                    to: Box::new(*b_keys.signing.public_key()),
                    body: "one each".into(),
                },
            );
        }

        // The live conversation's message is collected first, so B genuinely owes
        // one acknowledgement before anything is torn down.
        let label_c = sole_label(&c);
        let frame_c = queued_frame_at(&c, &label_c, 1, newer);
        let folded = fold_page_at(&mut b, newer, live, 0, vec![(position_of(1), frame_c)]);
        assert_eq!(
            messages_in(&folded).len(),
            1,
            "the live conversation's message must have been collected: {folded:?}"
        );

        // A's channel is torn down: a re-knock from a machine that lost its state.
        let dir_a2 = tempfile::tempdir().expect("temp dir A2");
        let mut a2 = machine(&dir_a2);
        let (_, entry) = knock_as_initiator(&mut a2, &b_keys);
        let out = b.on_doorbell(newer, sweep_of(vec![(11, entry)]));
        assert!(
            out.iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ChannelLost { .. }))),
            "the re-knock did not tear the channel down: {out:?}"
        );
        let doomed_index = b
            .correspondences
            .iter()
            .position(|corr| {
                corr.ratchet
                    .as_ref()
                    .is_some_and(|r| *r.ar_fingerprint() == doomed)
            })
            .expect("the torn-down correspondence is still held");
        assert!(
            b.correspondences[doomed_index].pending_sent_ms.is_empty(),
            "the teardown must drop the cadence state it was keeping"
        );

        // A sweep issued before the teardown lands after it, refilling the pending
        // set with a position a full minute OLDER than the live one's.
        let label_a = sole_label(&a);
        let frame_a = queued_frame_at(&a, &label_a, 1, newer);
        let folded = fold_page_at(&mut b, newer, doomed, 0, vec![(position_of(1), frame_a)]);
        assert_eq!(
            messages_in(&folded).len(),
            1,
            "the late fold must have collected: {folded:?}"
        );
        assert_eq!(
            b.correspondences[doomed_index].pending_sent_ms,
            vec![older],
            "the torn-down correspondence must hold the OLDER position, or it was \
             never a competitor and this test decides nothing"
        );

        // One tick, one permit.
        let tick = newer + 1;
        let effects = b.on_tick(tick);
        assert_eq!(
            ack_publishes(&effects),
            vec![live],
            "the allowance must go to the live conversation: {effects:?}"
        );
        // The effects cannot show a permit SPENT on a write that never happened, so
        // the pick itself is asserted: it is what the budget was charged for.
        let live_label = b
            .correspondences
            .iter()
            .find(|corr| {
                corr.ratchet
                    .as_ref()
                    .is_some_and(|r| *r.ar_fingerprint() == live)
            })
            .expect("the live correspondence is held")
            .label;
        assert_eq!(
            b.last_ack_picked,
            Some(live_label),
            "the permit must have been charged to the live correspondence"
        );
        assert_ne!(
            live_label, b.correspondences[doomed_index].label,
            "the two labels must differ, or the assertion above cannot tell them apart"
        );
    }

    /// M22j. A torn-down conversation plans nothing more, so the pages handed back
    /// at teardown are not re-opened by the next cadence.
    ///
    /// **The teardown does not remove the ratchet or the channel roots, and every
    /// planner reads exactly those.** So without a flag the receiving pair released
    /// at teardown is re-planned within one probe interval — which is not merely
    /// wasted work: a close and a sweep of one record issued from the same tick is
    /// the open/close race the eviction path's victim lock exists to exclude,
    /// reached from a direction that lock does not cover.
    ///
    /// The control is the tick BEFORE the teardown, which must plan something: three
    /// silent ticks prove nothing about a machine that was never planning.
    #[test]
    fn a_torn_down_conversation_plans_nothing_more() {
        const PROBE_MS: i64 = daemonseed_core::dm::collect::PROBE_INTERVAL_MS as i64;

        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let mut a = machine(&dir_a);
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);

        // One message collected, so B OWES an acknowledgement: the ack record is the
        // one channel-plane emitter that is a write of B's own rather than a read of
        // A's, and without something to acknowledge it never fires — which would
        // make the `PublishAck` half of the filter below a needle that matches
        // nothing whatever the teardown did.
        let conversation = conversation_of(&b, 0);
        let label_a = sole_label(&a);
        a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(*b_keys.signing.public_key()),
                body: "one message to acknowledge".into(),
            },
        );
        let frame = queued_frame_at(&a, &label_a, 1, BASE_MS);
        let folded = fold_page_at(
            &mut b,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(1), frame)],
        );
        assert!(
            !messages_in(&folded).is_empty(),
            "the fixture must have collected a message: {folded:?}"
        );

        let before = b.on_tick(BASE_MS);
        let planned = swept_pages(&before);
        assert!(
            !planned.is_empty(),
            "the tick before the teardown must plan sweeps, or three silent ticks \
             after it prove nothing: {before:?}"
        );
        assert_eq!(
            ack_publishes(&before),
            vec![conversation],
            "and it must write the acknowledgement it owes, or the PublishAck half \
             of the filter below matches nothing whatever the teardown did: \
             {before:?}"
        );
        // **Every one of those sweeps comes back before the teardown, and without
        // this the test is vacuous.** A page whose sweep is in flight is skipped by
        // the planner on its own terms, so leaving them open would make the ticks
        // below silent whatever the teardown did — the silence has to be the
        // teardown's and nothing else's.
        for page in planned {
            b.on_outcome(
                BASE_MS,
                page_outcome(conversation, page, Ok(empty_page(conversation))),
            );
        }

        // A knocks again from a machine that lost its state.
        let dir_a2 = tempfile::tempdir().expect("temp dir A2");
        let mut a2 = machine(&dir_a2);
        let (_, entry) = knock_as_initiator(&mut a2, &b_keys);
        let _ = &a;
        let out = b.on_doorbell(BASE_MS, sweep_of(vec![(11, entry)]));
        assert!(
            !out.is_empty(),
            "the re-knock produced no effects at all, so nothing below is a search"
        );
        assert!(
            out.iter()
                .any(|e| matches!(e, DmEffect::Emit(DmEvent::ChannelLost { .. }))),
            "the re-knock did not tear the channel down: {out:?}"
        );

        let mut now = BASE_MS;
        for tick in 0..3 {
            now += PROBE_MS;
            let effects = b.on_tick(now);
            let named: Vec<&DmEffect> = effects
                .iter()
                .filter(|e| match e {
                    DmEffect::Dht(DhtOp::SweepPage { tag, .. })
                    | DmEffect::Dht(DhtOp::PublishPage { tag, .. })
                    | DmEffect::Dht(DhtOp::FetchAck { tag, .. })
                    // The acknowledgement record is this conversation's too, and it
                    // is the one emitter that is a WRITE of our own rather than a
                    // read of theirs — so leaving it out of the filter would let a
                    // torn-down conversation keep writing while the test reported
                    // silence.
                    | DmEffect::Dht(DhtOp::PublishAck { tag, .. }) => {
                        tag.conversation == Some(conversation)
                    }
                    _ => false,
                })
                .collect();
            assert!(
                named.is_empty(),
                "tick {tick} named a record of a torn-down conversation: {named:?}"
            );
        }
    }

    // ---- the load-time re-establishment pass (A3.12, A5.5, A9.1) -----------

    /// Rewrite one correspondence's resume record with a different re-root
    /// generation, keeping every other field the store's guards compare.
    fn set_reroot_generation(m: &DmMachine, label: &CorrespondenceLabel, ratchet_gen: u32) {
        let stored = read_resume(m, label);
        let rewritten = ResumeRecord::new(
            Box::new(*stored.s_pc()),
            Box::new(*stored.pk_pc()),
            stored.committed_root().clone(),
            ReEstState {
                reconnect_gen: stored.reconnect_gen() + 1,
                reroot_ratchet_gen: ratchet_gen,
                ..ReEstState::first_establishment()
            },
            Retention::none(),
            stored.send_floor(),
        );
        m.persist
            .commit_resume(label, &rewritten)
            .expect("the rewritten record commits");
    }

    /// One correspondence's resume record, or a panic naming what was there.
    fn read_resume(m: &DmMachine, label: &CorrespondenceLabel) -> ResumeRecord {
        m.persist
            .read_resume(label)
            .expect("the resume record reads")
            .expect("the establishment wrote one")
    }

    /// Queue one sealed channel entry at `seq`, sealed under `gen`.
    fn queue_at_generation(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        direction: Direction,
        seq: u64,
        gen: u32,
    ) {
        m.persist
            .update_outbox(label, direction, BASE_MS, |outbox| {
                outbox.enqueue_sealed(
                    seq,
                    OutboxTarget::ChannelPage,
                    BASE_MS,
                    SealedFrame::new(vec![0xC7; 64]),
                    gen,
                )?;
                Ok(Mutation::Changed(()))
            })
            .expect("the entry queues");
    }

    /// Queue one entry that has no chain to seal against — A4.2's cause 2, and
    /// the only state that opens a re-establishment.
    fn queue_unsealed(m: &DmMachine, label: &CorrespondenceLabel, direction: Direction, seq: u64) {
        m.persist
            .update_outbox(label, direction, BASE_MS, |outbox| {
                outbox.enqueue_awaiting_key(seq, OutboxTarget::ChannelPage, BASE_MS)?;
                Ok(Mutation::Changed(()))
            })
            .expect("the entry queues");
    }

    /// Put one established correspondence into the state a crash between the
    /// resume-record commit and the outbox enqueue leaves behind, and hand back
    /// the sequence the leg was sealed for and its bytes.
    ///
    /// **The sequence is the outbox's live `next_send_seq`, never a literal.**
    /// It is bound into the leg's seal key and its signature, so a fixture that
    /// invented one would be testing a re-emit no production path can produce.
    fn crash_after_committing_an_attempt(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        direction: Direction,
    ) -> (u64, Vec<u8>) {
        let mut record = read_resume(m, label);
        let seq = m
            .persist
            .read_outbox(label, BASE_MS)
            .expect("the outbox reads")
            .map_or(0, |outbox| outbox.next_send_seq());
        let fresh = daemonseed_core::dm::resume::FreshAttempt::first();
        let (eph_ek, eph_dk) = reest::mint_ephemeral().expect("the ephemeral mints");
        let leg = reest::seal_re_est(
            record.committed_root(),
            direction,
            record.reconnect_gen() + 1,
            seq,
            &fresh,
            &eph_ek,
            record.s_pc(),
        )
        .expect("the leg seals");
        let bytes = leg.clone();
        record
            .open_attempt(
                seq,
                SealedReEst::seal(fresh, leg.into_boxed_slice()).expect("inside the length cap"),
                eph_dk,
            )
            .expect("the slot is empty");
        m.persist
            .commit_resume(label, &record)
            .expect("the opened attempt commits");
        (seq, bytes)
    }

    /// The sequence numbers whose queued frame is exactly `bytes`.
    fn queued_at_bytes(m: &DmMachine, label: &CorrespondenceLabel, bytes: &[u8]) -> Vec<u64> {
        queued_at_bytes_at(m, label, bytes, BASE_MS)
    }

    /// The same, read at a named instant.
    ///
    /// [`queued_at_bytes`] pins the read at [`BASE_MS`]; an entry composed later
    /// than that is refused as composed in the future, which is the store
    /// correctly declining to read a record against a clock behind it.
    fn queued_at_bytes_at(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        bytes: &[u8],
        now_ms: i64,
    ) -> Vec<u64> {
        m.persist
            .read_outbox(label, now_ms)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .iter()
            .filter(|entry| entry.frame() == Some(bytes))
            .map(|entry| entry.seq())
            .collect()
    }

    /// Establish A with B and hand back A's label, leaving both machines alive.
    fn established_initiator(
        dir: &tempfile::TempDir,
        dir_b: &tempfile::TempDir,
    ) -> (DmMachine, DmMachine, CorrespondenceLabel) {
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), dir_b);
        b.persist.provision_block_list().expect("provision B");
        let mut a = machine(dir);
        a.persist.provision_block_list().expect("provision");
        establish_pair(&mut a, &mut b, &b_keys);
        let label = a.correspondences[0].label;
        (a, b, label)
    }

    /// Every correspondence one batch of effects reports as lost.
    fn lost(effects: &[DmEffect]) -> Vec<(TrustEventKey, Vec<u64>)> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::ChannelLost {
                    event, surfaced, ..
                }) => Some((*event, surfaced.clone())),
                _ => None,
            })
            .collect()
    }

    /// The sequence numbers one batch of effects reports as undelivered.
    fn undelivered_seqs(effects: &[DmEffect]) -> Vec<u64> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::Delivery {
                    seq,
                    state: DeliveryState::Undelivered,
                    ..
                }) => Some(*seq),
                _ => None,
            })
            .collect()
    }

    /// M40. **A crash between committing an attempt and queueing it re-emits the
    /// stored bytes at the stored sequence, and seals nothing new.**
    ///
    /// A9.1(a) makes a re-emit of a persisted attempt the byte-identical stored
    /// seal, and the position is half of that: `seq` is bound into the leg's
    /// seal key and its signature preimage, so bytes replayed at another
    /// position open at an address the peer is not reading and verify against a
    /// preimage it does not compute.
    #[test]
    fn a_crash_between_the_commit_and_the_queue_re_emits_the_stored_leg() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let label = {
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            queue_unsealed(&a, &label, Direction::AToB, 40);
            crash_after_committing_an_attempt(&a, &label, Direction::AToB);
            label
        };
        let (held_seq, held) = {
            let a = machine(&dir);
            let slot = read_resume(&a, &label);
            let slot = slot
                .own_slot()
                .expect("the crash left an attempt in flight");
            (slot.seq(), slot.sealed().bytes().to_vec())
        };
        assert!(
            queued_at_bytes(&machine(&dir), &label, &held).is_empty(),
            "the fixture queued the leg, so there is no crash window to recover from"
        );

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        a.on_tick(BASE_MS);

        assert_eq!(
            queued_at_bytes(&a, &label, &held),
            vec![held_seq],
            "the stored leg did not go back to the sequence it was sealed for"
        );
        let after = read_resume(&a, &label);
        assert_eq!(
            after.sealed_re_est().map(<[u8]>::to_vec),
            Some(held),
            "the record's sealed bytes changed under a re-emit"
        );
        assert_eq!(
            after
                .own_slot()
                .map(daemonseed_core::dm::resume::OwnSlot::seq),
            Some(held_seq),
            "the record's stored sequence moved under a re-emit"
        );

        // **And the bytes that reach the wire are the same bytes.** The
        // assertions above are about the record and the outbox; A9.1(a) is about
        // what is published, and the publish is a separate step that could
        // re-derive rather than re-send. The clock runs past the reconnect band
        // because a leg's first dispatch is drawn from it (A5.5).
        let mut clock = BASE_MS;
        let mut published: Vec<Vec<u8>> = Vec::new();
        for _ in 0..4 {
            clock += duration_as_ms(daemonseed_core::dm::outbox::RECONNECT_FIRST_DISPATCH) * 2;
            published.extend(a.on_tick(clock).iter().filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, frame, .. })
                    if tag.seq == Some(held_seq) =>
                {
                    Some(frame.clone())
                }
                _ => None,
            }));
            if !published.is_empty() {
                break;
            }
        }
        assert_eq!(
            published.len(),
            1,
            "the re-emitted leg was published {} times in the window",
            published.len()
        );
        assert_eq!(
            published[0],
            after.sealed_re_est().expect("the slot holds its bytes"),
            "the leg on the wire is not the leg in the record"
        );
    }

    /// M41. **A second load does not queue the same leg twice, and neither does
    /// one whose queued entry has since ended.**
    ///
    /// **The ended entry is the half a byte-comparison check gets wrong.**
    /// `OutboxEntry::frame` answers `Some` only while an entry awaits
    /// collection, so after a give-up such a check reads the leg as never
    /// queued — and then reads its own spent sequence as one the outbox has
    /// moved past, which is the unrecoverable state. The correspondence is
    /// reported lost over an entry that is sitting right there, already
    /// surfaced by the give-up that ended it. That is what the silence assertion
    /// below catches; the sequence assertion alone does not.
    #[test]
    fn a_second_load_does_not_queue_the_same_leg_twice() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let label = {
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            queue_unsealed(&a, &label, Direction::AToB, 40);
            crash_after_committing_an_attempt(&a, &label, Direction::AToB);
            label
        };
        let seq = {
            let mut a = machine(&dir);
            a.on_tick(BASE_MS);
            let seq = read_resume(&a, &label).own_slot().expect("in flight").seq();
            assert!(
                a.persist
                    .read_outbox(&label, BASE_MS)
                    .expect("reads")
                    .expect("there")
                    .entry(seq)
                    .is_some(),
                "the first load did not queue the leg, so the second proves nothing"
            );
            seq
        };

        // The entry ends, which is what empties a byte comparison while the
        // sequence stays spent. A teardown rather than the give-up sweep,
        // because that sweep spares this target — and a correspondent whose
        // state was lost ends every pending entry, legs included.
        {
            let a = machine(&dir);
            a.persist
                .update_outbox(
                    &label,
                    Direction::AToB,
                    BASE_MS + GIVE_UP_MS + 1,
                    |outbox| {
                        let outcome = outbox.channel_torn_down(
                            &TeardownCause::CorrespondentStateLost,
                            BASE_MS + GIVE_UP_MS + 1,
                        );
                        assert!(outcome.surfaced.contains(&seq), "the fixture ended nothing");
                        Ok(Mutation::Changed(()))
                    },
                )
                .expect("the teardown runs");
        }

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let out = a.on_tick(BASE_MS + GIVE_UP_MS + 1);

        assert_eq!(
            lost(&out),
            Vec::new(),
            "a queued leg whose entry has ended was reported unrecoverable: {out:?}"
        );
        let queued: Vec<u64> = a
            .persist
            .read_outbox(&label, BASE_MS + GIVE_UP_MS + 1)
            .expect("reads")
            .expect("there")
            .iter()
            .filter(|entry| entry.seq() >= seq)
            .map(|entry| entry.seq())
            .collect();
        assert_eq!(
            queued,
            vec![seq],
            "a second load queued the leg again at a fresh sequence"
        );
    }

    /// M42. **The load path runs the dead-chain sweep; it ends only what was
    /// sealed below the re-root generation, spares the knock, and the same tick
    /// tells the user.**
    ///
    /// A3.12 makes the sweep a derivation re-run at every load, so this is the
    /// driver's half of it: the core's tests say what the sweep decides, and
    /// nothing but this says that a restart runs it. The entry at the re-root
    /// generation and the doorbell entry beside it are the two controls — a
    /// sweep that ended everything destroys live messages and an outstanding
    /// first contact, and would pass a test that only checked the first.
    #[test]
    fn the_load_path_ends_only_entries_sealed_below_the_re_root_generation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let label = {
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            set_reroot_generation(&a, &label, 5);
            queue_at_generation(&a, &label, Direction::AToB, 20, 3);
            queue_at_generation(&a, &label, Direction::AToB, 21, 5);
            // A knock still awaiting collection, at a generation the re-root
            // replaced. Only its target spares it — the real knock this
            // correspondence sent has already been settled by the acceptance,
            // so it is not the control this needs.
            a.persist
                .update_outbox(&label, Direction::AToB, BASE_MS, |outbox| {
                    outbox.enqueue_sealed(
                        22,
                        OutboxTarget::Doorbell { slot: 3 },
                        BASE_MS,
                        SealedFrame::new(vec![0xD0; 64]),
                        3,
                    )?;
                    Ok(Mutation::Changed(()))
                })
                .expect("the knock queues");
            label
        };

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        assert_eq!(
            outbox_state(&a, &label, 20, BASE_MS),
            DeliveryState::Composed,
            "the fixture queued nothing to sweep"
        );
        assert_eq!(
            outbox_state(&a, &label, 22, BASE_MS),
            DeliveryState::Composed,
            "the fixture has no live doorbell entry, so the exemption is untested"
        );
        let out = a.on_tick(BASE_MS);

        assert_eq!(
            outbox_state(&a, &label, 20, BASE_MS),
            DeliveryState::Undelivered,
            "an entry sealed under a chain the re-root replaced was left live"
        );
        assert_eq!(
            outbox_state(&a, &label, 21, BASE_MS),
            DeliveryState::Composed,
            "an entry sealed under the re-rooted chain was ended as dead"
        );
        assert_eq!(
            outbox_state(&a, &label, 22, BASE_MS),
            DeliveryState::Composed,
            "the outstanding knock was ended by the channel's dead-chain sweep"
        );
        assert_eq!(
            undelivered_seqs(&out),
            vec![20],
            "the tick did not surface exactly the swept entry: {out:?}"
        );
    }

    /// M43. **A leg goes onto the ANSWERING side's direction record too.**
    ///
    /// Kills a load path that names one direction: an acceptor's outbox runs
    /// `b2a`, and an enqueue against `a2b` is refused as a direction mismatch,
    /// so the leg would never be queued and the failure would be a trace line.
    #[test]
    fn an_acceptor_queues_its_leg_on_its_own_direction_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let label_b = {
            let b_keys = peer_identity();
            let mut b = machine_as(peer_identity(), &dir_b);
            b.persist.provision_block_list().expect("provision B");
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            establish_pair(&mut a, &mut b, &b_keys);
            let label_b = b.correspondences[b.correspondences.len() - 1].label;
            assert_eq!(
                b.persist
                    .read_outbox(&label_b, BASE_MS)
                    .expect("reads")
                    .expect("the acceptance queued one")
                    .direction(),
                Direction::BToA,
                "the acceptor's outbox is not the direction this test is about"
            );
            queue_unsealed(&b, &label_b, Direction::BToA, 40);
            crash_after_committing_an_attempt(&b, &label_b, Direction::BToA);
            label_b
        };

        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision B");
        let seq = read_resume(&b, &label_b)
            .own_slot()
            .expect("in flight")
            .seq();
        b.on_tick(BASE_MS);

        assert!(
            b.persist
                .read_outbox(&label_b, BASE_MS)
                .expect("reads")
                .expect("there")
                .entry(seq)
                .is_some(),
            "the acceptor's leg was not queued on its own direction record"
        );
    }

    /// M44. **Only UNSEALED mail opens a re-establishment.**
    ///
    /// A4.2's cause 2 is an entry that cannot seal without a chain. A sealed
    /// entry re-seeds on its own persisted ladder against the chain it was
    /// sealed under and needs no handshake, so opening one for it puts a leg on
    /// the wire for a conversation that is only waiting for an acknowledgement.
    /// The unsealed case is the positive control: without it a pass that never
    /// opened anything would pass.
    #[test]
    fn a_sealed_pending_entry_opens_no_attempt_and_an_unsealed_one_does() {
        for (unsealed, expected) in [(false, None), (true, Some(1u32))] {
            let dir = tempfile::tempdir().expect("temp dir");
            let dir_b = tempfile::tempdir().expect("temp dir B");
            let label = {
                let (a, _b, label) = established_initiator(&dir, &dir_b);
                if unsealed {
                    queue_unsealed(&a, &label, Direction::AToB, 40);
                } else {
                    queue_at_generation(&a, &label, Direction::AToB, 40, 0);
                }
                label
            };
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            a.on_tick(BASE_MS);
            assert_eq!(
                read_resume(&a, &label).attempt().map(|a| a.get()),
                expected,
                "unsealed = {unsealed}: the pass opened the wrong number of attempts"
            );
        }
    }

    /// M45. **An outbox behind the resume record's durable send floor stops the
    /// pass.**
    ///
    /// A9.2 makes the floor durable precisely so a rolled-back record family is
    /// not silently trusted, and the sweep is a derivation from the resume
    /// record onto that outbox. The at-floor case is the control: without it a
    /// pass that refused every correspondence would pass.
    #[test]
    fn an_outbox_behind_the_stored_floor_stops_the_pass() {
        // The establishment seeds the floor from the outbox, so the low case is
        // the value already stored rather than zero — `commit_resume` refuses a
        // floor that goes backwards, which is a different guard from the one
        // this test is about.
        for (floor_seq, opens) in [(1u64, true), (999u64, false)] {
            let dir = tempfile::tempdir().expect("temp dir");
            let dir_b = tempfile::tempdir().expect("temp dir B");
            let label = {
                let (a, _b, label) = established_initiator(&dir, &dir_b);
                queue_unsealed(&a, &label, Direction::AToB, 40);
                let stored = read_resume(&a, &label);
                a.persist
                    .commit_resume(
                        &label,
                        &ResumeRecord::new(
                            Box::new(*stored.s_pc()),
                            Box::new(*stored.pk_pc()),
                            stored.committed_root().clone(),
                            ReEstState::first_establishment(),
                            Retention::none(),
                            SendFloor::new(0, floor_seq),
                        ),
                    )
                    .expect("the floor commits");
                label
            };
            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            a.on_tick(BASE_MS);
            assert_eq!(
                read_resume(&a, &label).attempt().is_some(),
                opens,
                "floor seq {floor_seq}: the pass made the wrong call on a rolled-back outbox"
            );
        }
    }

    /// Overwrite one record with bytes that will not decode, and hand back the
    /// original so the fault can be cleared again.
    fn corrupt(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        kind: daemonseed_core::storage::dm_store::RecordKind,
    ) -> Vec<u8> {
        let good = m
            .persist
            .store()
            .read_unlocked(label, kind)
            .expect("reads")
            .expect("the record exists");
        m.persist
            .store()
            .critical_section(label, |guard| -> Result<(), DmPersistError> {
                guard.replace(kind, b"not a record of this kind")?;
                Ok(())
            })
            .expect("the fixture writes");
        good
    }

    /// Put `bytes` back where [`corrupt`] found them.
    fn restore(
        m: &DmMachine,
        label: &CorrespondenceLabel,
        kind: daemonseed_core::storage::dm_store::RecordKind,
        bytes: &[u8],
    ) {
        m.persist
            .store()
            .critical_section(label, |guard| -> Result<(), DmPersistError> {
                guard.replace(kind, bytes)?;
                Ok(())
            })
            .expect("the fixture restores");
    }

    /// One retry rung's worth of clock, plus a millisecond.
    fn past_rung(rung: u32) -> i64 {
        duration_as_ms(ReseedSchedule::delay_for_rung(rung)) + 1
    }

    /// M46. **A store fault at either read leaves the pass owed, and a later
    /// tick completes it** — plus the classed event A3.15 row 6 owes on the way
    /// past.
    ///
    /// Both records are faulted in turn because they fail at different points:
    /// the resume record before the pass has a direction to work with, the
    /// outbox record at the read that supplies it. A pass that cleared its flag
    /// on the way in would leave the correspondence unswept and unattempted for
    /// the life of the session over a fault that had already gone.
    #[test]
    fn a_store_fault_leaves_the_load_time_pass_owed_for_the_next_tick() {
        use daemonseed_core::storage::dm_store::RecordKind;

        for kind in [RecordKind::Resume, RecordKind::Outbox] {
            let dir = tempfile::tempdir().expect("temp dir");
            let dir_b = tempfile::tempdir().expect("temp dir B");
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            queue_unsealed(&a, &label, Direction::AToB, 40);
            drop(a);

            let mut a = machine(&dir);
            a.persist.provision_block_list().expect("provision");
            let good = corrupt(&a, &label, kind);

            let faulted = a.on_tick(BASE_MS);
            assert_eq!(
                lost(&faulted)
                    .iter()
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>(),
                vec![TrustEventKey::DmProvisionalRecordUnreadable],
                "a {kind:?} that will not read was not surfaced: {faulted:?}"
            );
            assert!(
                a.correspondences[0].resume_owed,
                "the {kind:?} fault cleared the flag, so the pass will never run again"
            );

            restore(&a, &label, kind, &good);
            a.on_tick(BASE_MS + past_rung(0));

            assert!(
                read_resume(&a, &label).attempt().is_some(),
                "the pass did not complete on the tick after a {kind:?} fault cleared"
            );
            assert!(!a.correspondences[0].resume_owed);
        }
    }

    /// M55. **A handshake record whose erase failed goes onto the retry list,
    /// even when the correspondence it belonged to is finished.**
    ///
    /// The lost-`S_pc` path answers `Unrecoverable` whatever the erase did, so a
    /// store fault there used to drop the handle with the record still on disk —
    /// and that record holds `ss0`, which roots `RK0`, addressable only by the
    /// context the handle carried. The correspondence being unrecoverable is not
    /// a reason to stop erasing its opening secret.
    ///
    /// The fault is the provisional record itself: corrupted, `restart_channel`
    /// answers `RecordUnusable`, which is the erase's retry case. Restored, the
    /// next tick's retry finds it and deletes it — so the assertion is the
    /// record's absence rather than the list's length, and a fixture that never
    /// wrote a record could not pass it.
    #[test]
    fn a_failed_erase_on_an_unrecoverable_correspondence_is_retried() {
        use daemonseed_core::storage::dm_store::RecordKind;

        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let b_keys = peer_identity();
        let mut b = machine_as(peer_identity(), &dir_b);
        b.persist.provision_block_list().expect("provision B");
        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");

        // A knocks, B accepts, and B's acceptance is in hand — but A's pseudonym
        // key is gone, which is the state a restart before the acceptance leaves.
        let entry = knock_as_initiator(&mut a, &b_keys);
        let label = a.correspondences[0].label;
        let out = b.on_doorbell(BASE_MS, sweep_of(vec![entry]));
        let request = out
            .iter()
            .find_map(|e| match e {
                DmEffect::Emit(DmEvent::ContactRequest { request, .. }) => Some(request.clone()),
                _ => None,
            })
            .expect("B was not offered the knock");
        b.on_command(BASE_MS, DmCommand::Accept { request });
        let label_b = b.correspondences[b.correspondences.len() - 1].label;
        let acceptance = queued_frame_at(&b, &label_b, 0, BASE_MS);
        a.correspondences[0].signing_pc = None;
        let good = corrupt(&a, &label, RecordKind::Provisional);

        let conversation = conversation_of(&a, 0);
        let folded = fold_page_at(
            &mut a,
            BASE_MS,
            conversation,
            0,
            vec![(position_of(0), acceptance)],
        );

        assert_eq!(
            lost(&folded)
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>(),
            vec![TrustEventKey::DmChannelTornDownOnRestart],
            "a correspondence with no pseudonym key was not surfaced: {folded:?}"
        );
        assert!(
            a.persist
                .store()
                .read_unlocked(&label, RecordKind::Provisional)
                .expect("reads")
                .is_some(),
            "the fixture erased the record, so there is no failed erase to retry"
        );

        restore(&a, &label, RecordKind::Provisional, &good);
        a.on_tick(BASE_MS);

        assert!(
            a.persist
                .store()
                .read_unlocked(&label, RecordKind::Provisional)
                .expect("reads")
                .is_none(),
            "the handshake record survived the retry tick, so `ss0` is on disk with \
             nothing that will ever address it again"
        );
    }

    /// M52. **The unreadable retry widens, never abandons, and says so once when
    /// it reaches the top rung.**
    ///
    /// A3.15 row 6 has the retry on a backoff and A3.13 forbids a terminal
    /// state, so a store that never recovers must keep being asked — at a widening
    /// cadence rather than on every tick, and with the user told once that the
    /// cadence has stopped widening rather than told nothing for ever.
    #[test]
    fn the_unreadable_retry_widens_and_surfaces_its_ceiling_once() {
        use daemonseed_core::storage::dm_store::RecordKind;

        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (a, _b, label) = established_initiator(&dir, &dir_b);
        queue_unsealed(&a, &label, Direction::AToB, 40);
        drop(a);

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let _good = corrupt(&a, &label, RecordKind::Resume);

        let first = a.on_tick(BASE_MS);
        assert_eq!(lost(&first).len(), 1, "the first fault said nothing");
        // A tick inside the first rung asks nothing and says nothing.
        let inside = a.on_tick(BASE_MS + 1);
        assert!(
            lost(&inside).is_empty(),
            "a tick inside the backoff faulted again: {inside:?}"
        );
        assert_eq!(
            a.correspondences[0].resume_faults, 1,
            "a tick inside the backoff spent a rung"
        );

        // Walk the ladder to the ceiling and past it, one rung per tick.
        let mut clock = BASE_MS;
        let mut surfaces = lost(&first).len();
        for rung in 0..u32::from(REARM_FAULT_CEILING) + 3 {
            clock += past_rung(rung.min(u32::from(REARM_FAULT_CEILING) - 1));
            surfaces += lost(&a.on_tick(clock)).len();
        }

        assert_eq!(
            a.correspondences[0].resume_faults, REARM_FAULT_CEILING,
            "the fault count did not saturate at the ceiling"
        );
        assert!(
            a.correspondences[0].resume_owed,
            "the pass was abandoned, which is the dead-end state A3.13 forbids"
        );
        assert_eq!(
            surfaces, 2,
            "expected exactly two events — the first fault and the ceiling — got {surfaces}"
        );
    }

    /// M53. **A stale attempt releases its slot, so the next pass can open one.**
    ///
    /// Without the release `open_attempt` refuses for ever on the occupied slot,
    /// and every later boot re-emits the same loss event over a correspondence
    /// nothing can move — the dead-end state A3.13 forbids. The counter is what
    /// keeps the release safe: the attempt that follows is the successor of the
    /// one given up, never a reuse of its key.
    #[test]
    fn a_stale_attempt_releases_its_slot_and_the_next_pass_opens_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let label = {
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            queue_unsealed(&a, &label, Direction::AToB, 40);
            let (seq, _) = crash_after_committing_an_attempt(&a, &label, Direction::AToB);
            // The leg's sequence spent and its entry pruned: the position the
            // stored bytes are bound to no longer exists.
            a.persist
                .update_outbox(&label, Direction::AToB, BASE_MS, |outbox| {
                    outbox.enqueue_sealed(
                        seq,
                        OutboxTarget::ChannelPage,
                        BASE_MS,
                        SealedFrame::new(vec![0x11; 32]),
                        0,
                    )?;
                    outbox
                        .entry_mut(seq)
                        .expect("just enqueued")
                        .confirm_written(BASE_MS)?;
                    Ok(Mutation::Changed(()))
                })
                .expect("the fixture spends the sequence");
            a.persist
                .update_outbox(&label, Direction::AToB, BASE_MS, |outbox| {
                    let ended = outbox.sweep_dead_chain(u32::MAX);
                    assert!(ended.contains(&seq), "the fixture ended nothing");
                    outbox.record_surfaced(&ended);
                    let pruned = outbox.prune();
                    assert!(pruned > 0, "the fixture pruned nothing");
                    Ok(Mutation::Changed(()))
                })
                .expect("the fixture prunes");
            label
        };

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let out = a.on_tick(BASE_MS);
        assert_eq!(
            lost(&out).iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            vec![TrustEventKey::DmChannelTornDownOnRestart],
            "a stale attempt was not surfaced: {out:?}"
        );
        assert!(
            read_resume(&a, &label).own_slot().is_none(),
            "the stale attempt kept its slot, so nothing can ever open another"
        );

        // The NEXT TICK of the same session opens the successor of the
        // abandoned attempt: a give-up that needed a restart to be replaced
        // would be a dead end with a longer clock.
        assert!(
            a.correspondences[0].resume_owed,
            "the give-up left the pass unowed, so a replacement waits for a restart"
        );
        a.on_tick(BASE_MS);
        let after = read_resume(&a, &label);
        assert_eq!(
            after.attempt().map(|a| a.get()),
            Some(2),
            "the pass after a give-up did not open the abandoned attempt's successor"
        );
    }

    /// M54. **A queued leg is published to this side's own direction record, and
    /// never surfaces as a message that failed to arrive.**
    ///
    /// Three claims, and the clock runs past `GIVE_UP_MS` so all three are
    /// reachable. The leg reaches the wire: it is addressed by
    /// `msg_addr(dir, seq)` off the address root alone, which is the derivation a
    /// party with no key schedule has (A3.2, A3.9). Its ladder advances, because
    /// it is now a write like any other. And the give-up sweep still spares it,
    /// so it does not turn up as a delivery failure at a sequence the user never
    /// sent — the unsealed entry beside it is the control that says the sweep
    /// ran at all.
    #[test]
    fn a_queued_leg_is_published_and_never_surfaced_as_a_lost_message() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (a, _b, label) = established_initiator(&dir, &dir_b);
        queue_unsealed(&a, &label, Direction::AToB, 40);
        let (seq, _) = crash_after_committing_an_attempt(&a, &label, Direction::AToB);
        drop(a);

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        a.on_tick(BASE_MS);
        assert!(
            a.persist
                .read_outbox(&label, BASE_MS)
                .expect("reads")
                .expect("there")
                .entry(seq)
                .is_some(),
            "the fixture queued no leg"
        );

        // Well past the leg's first dispatch, every rung after it, AND the
        // seven-day give-up — which is where the second claim lives: a leg
        // swept by `sweep_give_ups` would be `Undelivered` here and owed a
        // surfacing a user reads as a lost message.
        let mut clock = BASE_MS;
        let mut surfaced: Vec<u64> = Vec::new();
        let mut published: Vec<u64> = Vec::new();
        while clock < BASE_MS + GIVE_UP_MS * 2 {
            clock += duration_as_ms(daemonseed_core::dm::outbox::RECONNECT_FIRST_DISPATCH) * 2;
            let effects = a.on_tick(clock);
            surfaced.extend(undelivered_seqs(&effects));
            published.extend(effects.iter().filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, .. }) if tag.seq == Some(seq) => Some(seq),
                _ => None,
            }));
        }
        assert!(
            !published.is_empty(),
            "the leg was never published, so the ladder assertion below is about \
             a write that does not happen"
        );
        assert!(
            clock > BASE_MS + GIVE_UP_MS,
            "the clock never reached the give-up, so half this test is vacuous"
        );
        // The unsealed entry the fixture queued IS a user message and gives up
        // at seven days like any other — it is the control that says the sweep
        // ran at all. The leg's own sequence must not be in that list.
        assert!(
            surfaced.contains(&40),
            "the give-up sweep never fired, so the leg's absence proves nothing"
        );
        assert!(
            !surfaced.contains(&seq),
            "the leg was surfaced as a message that failed to arrive: {surfaced:?}"
        );

        let outbox = a
            .persist
            .read_outbox(&label, clock)
            .expect("reads")
            .expect("there");
        let entry = outbox.entry(seq).expect("the leg is still queued");
        assert!(
            entry.schedule().rung() > 0,
            "the leg never spent a rung, so nothing dispatched it"
        );
        assert_eq!(
            published.len(),
            entry.schedule().rung() as usize,
            "the number of page writes and the rungs the ladder spent disagree, so \
             something other than the dispatch moved one of them: {published:?}"
        );
    }

    // ---- the re-establishment exchange, end to end (A3.2, A5.1, A3.7) ------

    /// Everything one side needs to drive a re-establishment by hand: its
    /// machine, its store label, and the direction its own outbox sends on.
    struct Side {
        machine: DmMachine,
        label: CorrespondenceLabel,
        /// Every sequence this side has reported Undelivered, across every tick
        /// of the exchange.
        ///
        /// **Accumulated rather than read off one tick, because the report is
        /// one-shot per session.** `give_ups` suppresses a repeat with
        /// `offered_this_session`, so a fixture that ticks to drive the
        /// handshake and then asks a later tick what was surfaced is asking
        /// after the answer has already been given — and reads *nothing was
        /// surfaced* for an entry that was.
        surfaced: Vec<u64>,
    }

    impl Side {
        /// The conversation both sides' records are tagged with.
        fn conversation(&self) -> [u8; AR_FINGERPRINT_LEN] {
            self.machine.correspondences[0]
                .conversation()
                .expect("the address root fingerprints")
        }

        /// This side's resume record.
        fn resume(&self) -> ResumeRecord {
            read_resume(&self.machine, &self.label)
        }
    }

    /// Establish A and B, queue one message A cannot seal, then drop both
    /// machines and rebuild them over the same stores.
    ///
    /// **The mail is queued before the drop and unsealed on purpose.** A4.2's
    /// cause 2 is the only standing cause that opens a re-establishment: *"an
    /// entry composed while no chain exists"*. Without one the load-time pass
    /// finds nothing owed and opens no attempt, and every assertion below would
    /// be about a handshake that never started.
    fn restart_both(
        dir_a: &tempfile::TempDir,
        dir_b: &tempfile::TempDir,
        pending_seq: u64,
    ) -> (Side, Side) {
        let (a, b, label_a) = established_initiator(dir_a, dir_b);
        let label_b = b.correspondences[0].label;
        queue_unsealed(&a, &label_a, Direction::AToB, pending_seq);
        drop(a);
        drop(b);

        let machine_a = machine(dir_a);
        machine_a
            .persist
            .provision_block_list()
            .expect("provision A");
        let machine_b = machine_as(peer_identity(), dir_b);
        machine_b
            .persist
            .provision_block_list()
            .expect("provision B");
        assert_eq!(
            machine_a.correspondences.len(),
            1,
            "A's store did not seed its correspondence back"
        );
        assert_eq!(
            machine_b.correspondences.len(),
            1,
            "B's store did not seed its correspondence back"
        );
        assert!(
            machine_a.correspondences[0].ratchet.is_none()
                && machine_b.correspondences[0].ratchet.is_none(),
            "a rebuilt machine came back holding a key schedule, so this is not a restart"
        );
        (
            Side {
                machine: machine_a,
                label: label_a,
                surfaced: Vec::new(),
            },
            Side {
                machine: machine_b,
                label: label_b,
                surfaced: Vec::new(),
            },
        )
    }

    /// Long enough for a leg drawn from the reconnect band to be due.
    ///
    /// The band is `RECONNECT_FIRST_DISPATCH ± RECONNECT_JITTER_FRAC`, so its
    /// top edge is the base plus three quarters of it; twice the base clears
    /// that with room and does not depend on the draw.
    fn past_the_reconnect_band(from_ms: i64) -> i64 {
        from_ms + duration_as_ms(daemonseed_core::dm::outbox::RECONNECT_FIRST_DISPATCH) * 2
    }

    /// Every page write one batch of effects asks for, as `(seq, page, bytes)`.
    fn page_writes(effects: &[DmEffect]) -> Vec<(u64, u64, Vec<u8>)> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishPage { tag, frame, .. }) => {
                    Some((tag.seq?, tag.page?, frame.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Tick `from` until it writes a page, then hand every one of those writes
    /// to `to` as a swept page and return what `to` made of them.
    ///
    /// **The clock is the sender's own, and it is advanced past the reconnect
    /// band on the first tick and by the ladder's rungs after that.** A leg's
    /// first dispatch is drawn from a band of hours (A5.5), so a fixture ticking
    /// at second scale would report *"no leg was published"* for a leg that is
    /// simply not due yet.
    fn carry_one_leg(from: &mut Side, to: &mut Side, at_ms: i64) -> (Vec<DmEffect>, i64) {
        let mut clock = at_ms;
        let mut writes = Vec::new();
        for _ in 0..8 {
            clock = past_the_reconnect_band(clock);
            let effects = from.machine.on_tick(clock);
            from.surfaced.extend(undelivered_seqs(&effects));
            writes = page_writes(&effects);
            if !writes.is_empty() {
                break;
            }
        }
        assert_eq!(
            writes.len(),
            1,
            "expected exactly one page write to carry, got {}",
            writes.len()
        );
        let (seq, page, bytes) = writes.remove(0);
        let conversation = to.conversation();
        let folded = fold_page_at(
            &mut to.machine,
            clock,
            conversation,
            page,
            vec![(position_of(seq), bytes)],
        );
        (folded, clock)
    }

    /// M68. **A correspondence survives a restart of BOTH stores: three legs,
    /// one committed root on each side, and the retained root retired on the
    /// answering side's confirming observation.**
    ///
    /// Nothing here is a fixture past the establishment. The `RE-EST` B opens is
    /// the frame A's load-time pass sealed and published; the `RE-ACK` A opens is
    /// the one B's answer sealed; the `RE-CONFIRM` B settles on is the one A's
    /// completion sealed. Every discriminator each side needs — the leg kind, the
    /// generation, the attempt — comes from its own record, because a leg carries
    /// none of them (A3.9).
    ///
    /// **What is asserted, and why each one:**
    ///
    /// - both sides reach `reconnect_gen` 1, which is A3.4's *"advances only by a
    ///   completed handshake"* observed from both ends;
    /// - both hold a key schedule again, so the exchange produced a channel and
    ///   not merely a record;
    /// - B's retained `RS_0` is **gone**, which is A3.5's retirement at the
    ///   confirming observation, and A's is **still held**, because its own
    ///   confirming observation is an acknowledgement that has not happened;
    /// - both handshake slots are empty on both sides (A3.14);
    /// - the entry sealed under the dead chain ends Undelivered exactly once
    ///   (A3.12), and the pending unsealed entry does not — it was never sealed
    ///   under any chain.
    #[test]
    fn two_drivers_survive_a_restart_of_both_stores() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        // Sealed under the chain the restart destroyed, so the sweep must end it
        // once the re-root generation is committed. Queued at a sequence above
        // the pending one so the leg's own position is not the one under test.
        queue_at_generation(&a.machine, &a.label, Direction::AToB, 2, 0);

        // ── A opens an attempt at load, and publishes it a band later ────────
        a.machine.on_tick(BASE_MS);
        let opened = a.resume();
        assert_eq!(
            opened.attempt().map(Attempt::get),
            Some(1),
            "A's load-time pass opened no attempt, so there is no handshake to carry"
        );

        // ── leg 1: A → B, the RE-EST ─────────────────────────────────────────
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let answered = b.resume();
        let acceptance = answered
            .acceptance()
            .expect("B did not answer A's initiation");
        assert_eq!(
            (acceptance.generation(), acceptance.attempt().get()),
            (1, 1),
            "B accepted an exchange other than the one A opened"
        );
        assert!(
            !acceptance.confirmed(),
            "B locked the candidate before any frame opened under the re-rooted chain"
        );
        assert_eq!(
            answered.reconnect_gen(),
            0,
            "B advanced its generation on an exchange it had only answered"
        );
        assert!(
            answered.retained().is_some(),
            "B committed a candidate without retaining the root it supersedes"
        );

        // ── leg 2: B → A, the RE-ACK ─────────────────────────────────────────
        let (_, t2) = carry_one_leg(&mut b, &mut a, t1);
        let completed = a.resume();
        assert_eq!(
            completed.reconnect_gen(),
            1,
            "A did not complete on the answer to its own initiation"
        );
        assert!(
            completed.own_slot().is_none(),
            "A completed and kept its initiation slot"
        );
        assert!(
            a.machine.correspondences[0].ratchet.is_some(),
            "A committed a root and opened no chain on it"
        );
        assert!(
            completed.retained().is_some(),
            "A retired RS_0 with no confirming observation of its own"
        );

        // ── leg 3: A → B, the RE-CONFIRM ─────────────────────────────────────
        let (_, t3) = carry_one_leg(&mut a, &mut b, t2);
        let settled = b.resume();
        assert_eq!(
            settled.reconnect_gen(),
            1,
            "B did not advance its generation on the settling leg"
        );
        assert!(
            settled.acceptance().is_none(),
            "B settled the exchange and kept the acceptance slot"
        );
        assert!(
            settled.retained().is_none(),
            "B kept RS_0 past its confirming observation"
        );
        assert!(
            b.machine.correspondences[0].ratchet.is_some(),
            "B settled the exchange and opened no chain"
        );
        assert_eq!(
            settled.committed_root().as_bytes(),
            completed.committed_root().as_bytes(),
            "the two sides committed different roots"
        );

        // ── the dead chain is surfaced exactly once ──────────────────────────
        //
        // **Across every tick, not the last one.** The sweep fires inside the
        // fold that completed the exchange, so the report goes out on the next
        // tick of the run — which is one of the ticks that carried the third
        // leg. Asking afterwards asks after the answer.
        for _ in 0..3 {
            let effects = a.machine.on_tick(t3 + 1);
            a.surfaced.extend(undelivered_seqs(&effects));
        }
        assert_eq!(
            a.surfaced,
            vec![2],
            "the entry sealed under the dead chain was not surfaced exactly once: {:?}",
            a.surfaced
        );

        // ── no leg outlives the exchange ─────────────────────────────────────
        //
        // Both outbox sweeps skip legs, so a completion that did not end them
        // leaves the handshake re-seeding for the life of the record. The tick
        // loop past the give-up is the positive control: it would publish them
        // if any were still pending, and it is also where a leg-scoped give-up
        // would fire if one had been left behind.
        assert_eq!(
            outbox_state(&a.machine, &a.label, 1, t3 + 1),
            DeliveryState::Composed,
            "the unsealed entry was ended by a sweep it hangs off no chain for"
        );

        // The answering side is finished with every leg the moment it settles.
        assert_eq!(
            pending_legs(&b.machine, &b.label, t3 + 1),
            Vec::<u64>::new(),
            "the settling side left a leg re-seeding after the exchange completed"
        );
        // The initiating side keeps exactly one: the settling leg it is still
        // owed a confirming observation for (A3.6). Its `RE-EST` is finished
        // with, and so is everything before it.
        let owed = a
            .resume()
            .confirm_slot()
            .expect("the completion persisted a settling leg")
            .seq();
        assert_eq!(
            pending_legs(&a.machine, &a.label, t3 + 1),
            vec![owed],
            "the initiating side kept a leg the exchange finished with"
        );

        // Past the give-up, nothing is pending on either side and nothing is
        // published: A3.13 forbids a terminal state, so the last leg ends
        // through its own give-up rather than re-seeding for ever.
        let mut clock = t3 + 1;
        let mut leg_writes = 0usize;
        for _ in 0..4 {
            clock += GIVE_UP_MS / 2;
            for side in [&mut a, &mut b] {
                let effects = side.machine.on_tick(clock);
                leg_writes += effects
                    .iter()
                    .filter(|e| {
                        matches!(e, DmEffect::Dht(DhtOp::PublishPage { tag, .. })
                            if tag.seq == Some(owed))
                    })
                    .count();
            }
        }
        assert!(
            leg_writes <= 1,
            "the settling leg was published {leg_writes} times past its give-up"
        );
        for side in [&a, &b] {
            assert_eq!(
                pending_legs(&side.machine, &side.label, clock),
                Vec::<u64>::new(),
                "a leg outlived its give-up"
            );
        }
    }

    /// Tick one side until it writes a page, and hand back every write with the
    /// clock it happened at. The other half of [`carry_one_leg`], for the cases
    /// that need both sides to write before either reads.
    fn publish_one_leg(side: &mut Side, at_ms: i64) -> (u64, u64, Vec<u8>, i64) {
        let mut clock = at_ms;
        let mut writes = Vec::new();
        for _ in 0..8 {
            clock = past_the_reconnect_band(clock);
            let effects = side.machine.on_tick(clock);
            side.surfaced.extend(undelivered_seqs(&effects));
            writes = page_writes(&effects);
            if !writes.is_empty() {
                break;
            }
        }
        assert_eq!(writes.len(), 1, "expected exactly one page write");
        let (seq, page, bytes) = writes.remove(0);
        (seq, page, bytes, clock)
    }

    /// Deliver one already-published leg to a side as a swept page.
    fn deliver(to: &mut Side, at_ms: i64, seq: u64, page: u64, bytes: Vec<u8>) -> Vec<DmEffect> {
        let conversation = to.conversation();
        fold_page_at(
            &mut to.machine,
            at_ms,
            conversation,
            page,
            vec![(position_of(seq), bytes)],
        )
    }

    /// M56. **Simultaneous initiation is decided by the coin: one side abandons
    /// and answers, the other ignores, and both end on one root.**
    ///
    /// A3.7's contest, reached the way the design says it is reached — *"a party
    /// consults its own resume record; if it holds a pending initiation at the
    /// same generation, the contest fires at that moment, locally"*. Both sides
    /// hold mail they cannot seal, so both open an attempt at load and both
    /// publish before either reads.
    ///
    /// **The asymmetry is the assertion.** The coin is a function of the shared
    /// retained root and the generation, so both sides compute the same winner
    /// without exchanging anything — which means exactly one acceptance slot is
    /// occupied after the two frames cross. Asserting *"one of the two"* rather
    /// than naming a side is deliberate: the winner depends on the root the
    /// fixture's establishment produced, and pinning it would be pinning the
    /// fixture rather than the rule.
    #[test]
    fn simultaneous_initiation_is_decided_by_the_coin() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        queue_unsealed(&b.machine, &b.label, Direction::BToA, 1);

        a.machine.on_tick(BASE_MS);
        b.machine.on_tick(BASE_MS);
        assert_eq!(
            (
                a.resume().attempt().map(Attempt::get),
                b.resume().attempt().map(Attempt::get)
            ),
            (Some(1), Some(1)),
            "both sides must have opened an attempt, or there is no contest to decide"
        );

        // Both publish before either reads, which is the crossing case.
        let (a_seq, a_page, a_bytes, t1) = publish_one_leg(&mut a, BASE_MS);
        let (b_seq, b_page, b_bytes, t2) = publish_one_leg(&mut b, BASE_MS);
        let at = t1.max(t2);
        deliver(&mut b, at, a_seq, a_page, a_bytes);
        deliver(&mut a, at, b_seq, b_page, b_bytes);

        let a_after = a.resume();
        let b_after = b.resume();
        let answered: Vec<&str> = [("A", &a_after), ("B", &b_after)]
            .into_iter()
            .filter(|(_, r)| r.acceptance().is_some())
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            answered.len(),
            1,
            "the coin left {} sides answering, so both or neither committed a \
             candidate: {answered:?}",
            answered.len()
        );
        let (loser, winner) = if answered == ["A"] {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        assert!(
            loser.resume().own_slot().is_none(),
            "the coin's loser answered and kept its own initiation"
        );
        assert!(
            winner.resume().own_slot().is_some(),
            "the coin's winner dropped the initiation it is still waiting on"
        );

        // The winner's own exchange completes: the loser's RE-ACK, then the
        // winner's RE-CONFIRM.
        let (_, t3) = carry_one_leg(loser, winner, at);
        let (_, _t4) = carry_one_leg(winner, loser, t3);
        assert_eq!(
            (
                winner.resume().reconnect_gen(),
                loser.resume().reconnect_gen()
            ),
            (1, 1),
            "the contest did not converge on one completed handshake"
        );
        assert_eq!(
            winner.resume().committed_root().as_bytes(),
            loser.resume().committed_root().as_bytes(),
            "the two sides committed different roots out of one contest"
        );

        // **The winner's memory of the frame it ignored is DURABLE.** A3.7 has
        // the winner do nothing with the loser's `RE-EST`, and A5.3 makes doing
        // nothing a decision that has to survive a restart: without the key on
        // disk the same bytes are byte-novel again at the next load, and a
        // co-host holding them can drive the alarm the memory exists to refuse.
        // Read back through a rebuilt machine, because an in-memory check would
        // pass for a record that was never written.
        let winner_dir = if answered == ["A"] { &dir_b } else { &dir_a };
        let reloaded = read_resume(
            &machine_as(
                if answered == ["A"] {
                    peer_identity()
                } else {
                    keys()
                },
                winner_dir,
            ),
            &winner.label,
        );
        assert!(
            reloaded
                .dedup()
                .keys()
                .iter()
                .any(|key| key.leg() == Leg::ReEst),
            "the coin's winner did not persist the initiation it ignored: {:?}",
            reloaded.dedup().keys()
        );
    }

    /// M57. **A replayed first leg is deduped: no second answer is sealed, and
    /// the stored one is untouched.**
    ///
    /// A3.4 in two halves. *"A byte-identical replay of an accepted generation's
    /// `RE-EST` is answered idempotently: the stored `RE-ACK` is re-served,
    /// byte-identical"* — so the bytes in the acceptance slot must be the same
    /// after the replay as before it, because they are the only copy and the leg
    /// carries a randomized ML-KEM ciphertext that cannot be reproduced. And
    /// A4.2: *"reading updates local state and emits nothing in the same turn"*
    /// — so the replay must not put a second `RE-ACK` in the outbox, however
    /// many times it arrives.
    ///
    /// **The dedup memory's own count is the positive control.** Without it,
    /// *"no second answer"* is satisfied by a machine that never looked at the
    /// second frame at all.
    #[test]
    fn a_replayed_first_leg_is_deduped_and_answered_from_the_stored_bytes() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (seq, page, bytes, t1) = publish_one_leg(&mut a, BASE_MS);

        deliver(&mut b, t1, seq, page, bytes.clone());
        let first = b.resume();
        let stored = first
            .acceptance()
            .expect("B did not answer the initiation")
            .sealed_re_ack()
            .to_vec();
        let seen_once = first.dedup().len();
        let first_keys = first.dedup().keys().to_vec();
        assert_eq!(
            seen_once, 1,
            "the answer recorded {seen_once} processed frames, so the memory the \
             replay must hit is not the one under test"
        );
        let queued_once = leg_entries(&b.machine, &b.label, t1);
        assert_eq!(
            queued_once.len(),
            1,
            "B queued {} legs for one initiation: {queued_once:?}",
            queued_once.len()
        );

        // **B is restarted before the replay, and that is what puts the durable
        // memory in the path rather than the collection.** Inside one session a
        // settled position is filtered out of every later sweep, so the same
        // bytes never reach the scan at all — the exactly-once property there
        // belongs to `Collection`, not to A5.3. The memory is *durable*
        // precisely for the case the collection cannot cover: a restart rebuilds
        // the collection from the stored cursor, the position comes back
        // unsettled, and the replay does reach the scan.
        b.machine = machine_as(peer_identity(), &dir_b);
        b.machine
            .persist
            .provision_block_list()
            .expect("provision B");
        assert_eq!(
            b.resume().dedup().len(),
            seen_once,
            "the processed-frame memory did not survive the restart, so the replay \
             below meets an empty one and the dedup is not what refuses it"
        );

        // The identical bytes, at the identical position, twice.
        //
        // **The replay must actually OPEN, or every assertion below is
        // vacuous.** B committed a candidate when it answered, so its committed
        // root has moved past the one these bytes were sealed under; the frame
        // reaches the dedup only because the scan also tries the retained root
        // at the generation the exchange is at. `unopenable` is what says it
        // did: a slot the scan could not place counts there, and a leg it placed
        // does not.
        let before_unopenable = b.machine.correspondences[0].health.unopenable;
        let before_scans = b.machine.leg_scan_candidates;
        // Every slot this stretch of the test hands to the scan, so the bound
        // below is measured against what actually happened.
        let mut delivered: Vec<u64> = Vec::new();
        let replay_one = deliver(&mut b, t1, seq, page, bytes.clone());
        delivered.push(seq);
        let replay_two = deliver(&mut b, t1, seq, page, bytes.clone());
        delivered.push(seq);
        assert_eq!(
            b.machine.correspondences[0].health.unopenable, before_unopenable,
            "the replayed leg was not opened at all, so nothing below is a test of \
             what happens when it is"
        );
        // **A4.2: reading emits nothing in the same turn.** A replay that put an
        // operation on the wire would be the page-to-page confirmation oracle
        // A4.2 exists to remove, whatever it did to the record.
        let writes: Vec<&DmEffect> = replay_one
            .iter()
            .chain(replay_two.iter())
            .filter(|e| matches!(e, DmEffect::Dht(_)))
            .collect();
        assert!(
            writes.is_empty(),
            "the replay caused {} operation(s) in the same turn: {writes:?}",
            writes.len()
        );
        // **The positive control for `unopenable`.** Without it, "the count did
        // not move" is satisfied by a machine that never scanned at all. A
        // leg-length run of bytes that is not a leg is exactly what the scan is
        // asked to reject, and it is the only shape that reaches every
        // candidate.
        let garbage = position_of(seq).seq() + 1;
        deliver(
            &mut b,
            t1,
            garbage,
            position_of(garbage).page(),
            vec![0xA5u8; daemonseed_core::dm::reest::LEG_LEN],
        );
        delivered.push(garbage);
        assert_eq!(
            b.machine.correspondences[0].health.unopenable,
            before_unopenable + 1,
            "a leg-length slot that is not a leg was not counted unopenable, so the \
             count above proves nothing"
        );
        // **A3.9's bounded trial cost, counted in CANDIDATES.** What is measured
        // here is how many leg kinds one slot is scanned against; each of those
        // bounds its own attempt window inside `reest`, which is a separate
        // claim with its own tests there and is not asserted from this layer.
        //
        // The slot count is derived from the deliveries above rather than
        // written down beside them: a fixture that grew a delivery and left a
        // literal behind would raise the real cost and keep passing.
        let slots = u64::try_from(delivered.len()).expect("a small fixture");
        assert_eq!(slots, 3, "the fixture's deliveries and its count disagree");
        assert!(
            b.machine.leg_scan_candidates - before_scans <= LEG_SCAN_CANDIDATES * slots,
            "{slots} swept slots cost {} leg-scan candidates, above the bound of {}",
            b.machine.leg_scan_candidates - before_scans,
            LEG_SCAN_CANDIDATES * slots
        );

        let after = b.resume();
        // **The KEYS, not the count.** A memory that dropped one position and
        // added another keeps its length and loses the entry that stops a
        // co-host re-firing the alarm — which is the shrink A5.3 forbids while
        // the root is retained, arriving through a comparison that cannot see
        // it.
        assert_eq!(
            after.dedup().keys(),
            first_keys.as_slice(),
            "a byte-identical replay changed the processed-frame memory"
        );
        assert_eq!(after.dedup().len(), seen_once);
        assert_eq!(
            after
                .acceptance()
                .expect("the acceptance survived the replay")
                .sealed_re_ack(),
            stored.as_slice(),
            "the replay re-sealed the answer instead of leaving the stored bytes alone"
        );
        assert_eq!(
            leg_entries(&b.machine, &b.label, t1),
            queued_once,
            "the replay queued a second answer"
        );
    }

    /// The sequences of every re-establishment leg still awaiting collection.
    fn pending_legs(m: &DmMachine, label: &CorrespondenceLabel, now_ms: i64) -> Vec<u64> {
        m.persist
            .read_outbox(label, now_ms)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .iter()
            .filter(|entry| {
                matches!(entry.target(), OutboxTarget::ReEstablishmentLeg)
                    && entry.lifecycle().is_pending()
            })
            .map(OutboxEntry::seq)
            .collect()
    }

    /// The sequences of every re-establishment leg queued on one side.
    fn leg_entries(m: &DmMachine, label: &CorrespondenceLabel, now_ms: i64) -> Vec<u64> {
        m.persist
            .read_outbox(label, now_ms)
            .expect("the outbox reads")
            .expect("the outbox exists")
            .iter()
            .filter(|entry| matches!(entry.target(), OutboxTarget::ReEstablishmentLeg))
            .map(OutboxEntry::seq)
            .collect()
    }

    /// Move the acceptance slot's stored answer onto an unspent sequence,
    /// leaving its bytes alone, and hand back the sequence.
    ///
    /// **This is what a crash between the accepting commit and the enqueue looks
    /// like from the record's side.** The slot names a position and the outbox
    /// has not spent it, which is the only state a re-queue can recover: a
    /// position the outbox HAS spent is `LegState::Stale`, where the bytes are
    /// bound to a number they can never go back to. Retiring the queued entry
    /// instead would produce the second state while claiming to test the first.
    fn reseat_acceptance(m: &DmMachine, label: &CorrespondenceLabel, seq: u64) -> u64 {
        let stored = read_resume(m, label);
        let slot = stored.acceptance().expect("an acceptance to move");
        let moved = rebuilt(
            &stored,
            ReEstState {
                reconnect_gen: stored.reconnect_gen(),
                attempt: stored.attempt().map_or(0, Attempt::get),
                last_seen_re_est: stored.last_seen_re_est(),
                own: None,
                acceptance: Some(
                    AcceptanceSlot::accept(
                        slot.generation(),
                        slot.attempt(),
                        seq,
                        slot.sealed_re_ack().to_vec().into_boxed_slice(),
                    )
                    .expect("within the ceiling"),
                ),
                confirm: None,
                attempt_at_window_start: stored.attempt_at_window_start(),
                reroot_ratchet_gen: stored.reroot_ratchet_gen(),
            },
        );
        m.persist
            .commit_resume(label, &moved)
            .expect("moving a slot's position commits");
        seq
    }

    /// The same, for the settling leg's slot.
    fn reseat_confirm(m: &DmMachine, label: &CorrespondenceLabel, seq: u64) -> u64 {
        let stored = read_resume(m, label);
        let slot = stored.confirm_slot().expect("a settling leg to move");
        let moved = rebuilt(
            &stored,
            ReEstState {
                reconnect_gen: stored.reconnect_gen(),
                attempt: stored.attempt().map_or(0, Attempt::get),
                last_seen_re_est: stored.last_seen_re_est(),
                own: None,
                acceptance: None,
                confirm: Some(
                    ConfirmSlot::new(
                        slot.generation(),
                        seq,
                        slot.sealed().to_vec().into_boxed_slice(),
                    )
                    .expect("within the ceiling"),
                ),
                attempt_at_window_start: stored.attempt_at_window_start(),
                reroot_ratchet_gen: stored.reroot_ratchet_gen(),
            },
        );
        m.persist
            .commit_resume(label, &moved)
            .expect("moving a slot's position commits");
        seq
    }

    /// One record with a replacement handshake state, every other field carried
    /// across so the store's guards compare like with like.
    fn rebuilt(stored: &ResumeRecord, handshake: ReEstState) -> ResumeRecord {
        ResumeRecord::new(
            Box::new(*stored.s_pc()),
            Box::new(*stored.pk_pc()),
            stored.committed_root().clone(),
            handshake,
            Retention {
                retained: stored.retained().map(|held| {
                    daemonseed_core::dm::resume::RetainedRoot::new(
                        held.root().clone(),
                        held.superseded_at_ms(),
                    )
                }),
                dedup: stored.dedup().clone(),
                stopped: stored.retained_but_stopped(),
            },
            stored.send_floor(),
        )
    }

    /// Every effect in a batch that is a re-establishment anomaly, with its key.
    fn anomalies(effects: &[DmEffect]) -> Vec<TrustEventKey> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::ReestablishmentAnomaly { event, .. }) => Some(*event),
                _ => None,
            })
            .collect()
    }

    /// M58. **A leg unanswered to its give-up ends, says so once, and the next
    /// pass opens the successor attempt.**
    ///
    /// A3.8's *re-establishment failed*, with A3.13's *"no terminal state"* as
    /// the second half: the entry leaves the wire, the attempt counter stands so
    /// the successor cannot reuse a number the peer may have answered, and the
    /// load-time pass is left owed rather than stopped. The user is told through
    /// the classed event and NOT through the undelivered list — a leg sits at a
    /// sequence they composed nothing at.
    #[test]
    fn a_leg_that_reaches_its_give_up_ends_and_the_next_pass_re_opens() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, _b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let opened = a.resume();
        let seq = opened.own_slot().expect("an attempt is open").seq();
        assert_eq!(opened.attempt().map(Attempt::get), Some(1));

        // Nobody ever answers. Past the seven days the leg's own entry carries.
        let past = BASE_MS + GIVE_UP_MS + 1;
        let effects = a.machine.on_tick(past);
        assert_eq!(
            anomalies(&effects),
            vec![TrustEventKey::DmReestablishmentFailed],
            "the give-up was silent: {effects:?}"
        );
        // The unsealed message beside it IS a user message and gives up at seven
        // days like any other, which is the control that says the sweep ran at
        // all. The leg's own sequence must not be in that list.
        let surfaced = undelivered_seqs(&effects);
        assert!(
            surfaced.contains(&1),
            "the give-up sweep never fired, so the leg's absence proves nothing"
        );
        assert!(
            !surfaced.contains(&seq),
            "the leg was reported as a message that failed to arrive: {surfaced:?}"
        );
        assert_eq!(
            outbox_state(&a.machine, &a.label, seq, past),
            DeliveryState::Undelivered,
            "the leg is still pending after its give-up"
        );
        assert!(
            a.resume().own_slot().is_none(),
            "the given-up attempt kept its slot, which is A3.13's dead end"
        );
        assert!(
            a.machine.correspondences[0].resume_owed,
            "the pass was not left owed, so a replacement waits for a restart"
        );
        // Mail waiting again, queued BEFORE the next tick: A4.2's cause 2 is the
        // only standing cause that opens an attempt, and the entry the fixture
        // started with gave up on the same tick the leg did — a tick with no
        // mail settles the pass and there is nothing left to re-open.
        a.machine
            .persist
            .update_outbox(&a.label, Direction::AToB, past, |outbox| {
                let next = outbox.next_send_seq();
                outbox.enqueue_awaiting_key(next, OutboxTarget::ChannelPage, past)?;
                Ok(Mutation::Changed(()))
            })
            .expect("the fixture queues");
        // Said once, not once per tick.
        assert_eq!(
            anomalies(&a.machine.on_tick(past + 1)),
            Vec::new(),
            "the give-up repeated itself on the next tick"
        );
        // And the successor opens rather than reusing the abandoned number.
        assert_eq!(
            a.resume().attempt().map(Attempt::get),
            Some(2),
            "the pass after a give-up did not open the abandoned attempt's successor"
        );
    }

    /// M59. **The retention ceiling fires, retires the root with the memory
    /// scoped to it, and says so once.**
    ///
    /// A3.5's `T_RETIRE`: *"at the ceiling without confirmation the party retires
    /// `RS_n` regardless and surfaces the unconfirmed re-establishment"*. Measured
    /// from the write-once supersede stamp, so a re-attempt cannot slide it.
    #[test]
    fn the_retention_ceiling_retires_the_root_and_is_loud_once() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        assert!(
            b.resume().retained().is_some(),
            "B did not retain a root, so there is no ceiling to fire"
        );
        let stamp = b.resume().retained().expect("retained").superseded_at_ms();

        // One tick short of the ceiling changes nothing — the control that says
        // the assertion below is about the ceiling and not about time passing.
        // Other anomalies fire in this window — every leg's own seven-day
        // give-up is well inside fourteen days — so the control is on the
        // ceiling's own key rather than on silence.
        let effects = b.machine.on_tick(stamp + T_RETIRE_MS - 1);
        assert!(
            b.resume().retained().is_some(),
            "the root retired before its ceiling: {effects:?}"
        );
        assert!(
            !anomalies(&effects).contains(&TrustEventKey::DmReestablishmentUnconfirmed),
            "the ceiling fired a tick early: {effects:?}"
        );

        let effects = b.machine.on_tick(stamp + T_RETIRE_MS);
        assert!(
            anomalies(&effects).contains(&TrustEventKey::DmReestablishmentUnconfirmed),
            "the ceiling fired silently: {effects:?}"
        );
        let after = b.resume();
        assert!(after.retained().is_none(), "the root outlived its ceiling");
        assert!(
            after.dedup().is_empty(),
            "the memory scoped to the retired root outlived it"
        );
        assert!(
            !anomalies(&b.machine.on_tick(stamp + T_RETIRE_MS + 1))
                .contains(&TrustEventKey::DmReestablishmentUnconfirmed),
            "the ceiling repeated itself on the next tick"
        );
        let _ = t1;
    }

    /// M60. **A crash between the commit that accepted an initiation and the
    /// enqueue that queued the answer re-queues the stored bytes.**
    ///
    /// A9.1(a) at the answering side: the `RE-ACK` carries a randomized ML-KEM
    /// ciphertext and the acceptance slot is its only copy, so the recovery has
    /// to be a re-queue of the stored bytes at the stored sequence and cannot be
    /// a fresh seal. Without the sequence in the slot there is no position to
    /// re-queue them to.
    #[test]
    fn a_crash_after_accepting_re_queues_the_stored_answer() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let slot = b.resume();
        let slot = slot.acceptance().expect("B answered");
        let (seq, stored) = (slot.seq(), slot.sealed_re_ack().to_vec());
        assert_eq!(
            queued_at_bytes_at(&b.machine, &b.label, &stored, t1),
            vec![seq],
            "the answer was not queued at the sequence the slot records"
        );

        // **The crash window spelled as the record spells it**: the commit
        // landed naming a position, and the enqueue that would have spent that
        // position never ran. Retiring the queued entry instead would spend the
        // sequence, which is the different and genuinely unrecoverable state
        // `LegState::Stale` names.
        let unspent = reseat_acceptance(&b.machine, &b.label, seq + 7);
        assert!(
            queued_at_bytes_at(&b.machine, &b.label, &stored, t1) == vec![seq],
            "the fixture moved the queued bytes as well as the slot"
        );

        b.machine.on_tick(t1 + 1);
        assert_eq!(
            queued_at_bytes_at(&b.machine, &b.label, &stored, t1 + 1),
            vec![unspent],
            "the stored answer did not go back to the sequence the slot records"
        );
        // The entry at the position the slot no longer names is an orphan, and
        // the same pass ends it: nothing will ever answer a leg the record has
        // moved past.
        assert_eq!(
            outbox_state(&b.machine, &b.label, seq, t1 + 1),
            DeliveryState::ConfirmedCollected,
            "the orphaned entry is still re-seeding"
        );
        assert_eq!(
            b.resume()
                .acceptance()
                .expect("the slot survived")
                .sealed_re_ack(),
            stored.as_slice(),
            "the recovery re-sealed the answer instead of re-queueing it"
        );
    }

    /// M61. **A crash between the commit that completed an exchange and the
    /// enqueue that queued the settling leg re-queues the stored bytes**, and a
    /// `RE-CONFIRM` that will not seal installs nothing.
    ///
    /// The second half is the one that matters most: before the fix the fold
    /// advanced the record and installed the ratchet whatever the seal did, so a
    /// failure left this side speaking under a root the peer would never confirm
    /// — one-way divergence, rendered healthy. The ordering closes it, and the
    /// assertion here is that the settling leg is on disk before anything is
    /// installed.
    #[test]
    fn a_crash_after_completing_re_queues_the_settling_leg() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let (_, t2) = carry_one_leg(&mut b, &mut a, t1);
        let confirm = a.resume();
        let confirm = confirm
            .confirm_slot()
            .expect("the completion persisted its settling leg");
        let (seq, stored) = (confirm.seq(), confirm.sealed().to_vec());
        assert_eq!(
            queued_at_bytes_at(&a.machine, &a.label, &stored, t2),
            vec![seq],
            "the settling leg was not queued at the sequence the slot records"
        );

        // The same crash window as the answering side's, at the third leg.
        let unspent = reseat_confirm(&a.machine, &a.label, seq + 7);
        a.machine.on_tick(t2 + 1);
        assert_eq!(
            queued_at_bytes_at(&a.machine, &a.label, &stored, t2 + 1),
            vec![unspent],
            "the stored settling leg did not go back to the sequence the slot records"
        );
        assert_eq!(
            outbox_state(&a.machine, &a.label, seq, t2 + 1),
            DeliveryState::ConfirmedCollected,
            "the orphaned entry is still re-seeding"
        );
    }

    /// M62. **An orphan leg — one at a sequence no slot names — is retired at
    /// the next pass.**
    ///
    /// A3.12's derivation shape: the record's slots are the live set, so a
    /// pending leg outside it belongs to an exchange the record has moved past
    /// and nothing will ever answer it. Left alone it re-seeds for the life of
    /// the correspondence, because both outbox sweeps skip legs.
    #[test]
    fn an_orphan_leg_is_retired_at_the_next_pass() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, _b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let live = a.resume().own_slot().expect("an attempt is open").seq();
        // A leg at a sequence the record names nowhere.
        let orphan = live + 5;
        a.machine
            .persist
            .update_outbox(&a.label, Direction::AToB, BASE_MS, |outbox| {
                outbox.enqueue_sealed(
                    orphan,
                    OutboxTarget::ReEstablishmentLeg,
                    BASE_MS,
                    SealedFrame::new(vec![0xAB; 64]),
                    0,
                )?;
                Ok(Mutation::Changed(()))
            })
            .expect("the fixture queues");

        a.machine.on_tick(BASE_MS + 1);
        assert_eq!(
            outbox_state(&a.machine, &a.label, orphan, BASE_MS + 1),
            DeliveryState::ConfirmedCollected,
            "the orphan leg is still pending"
        );
        assert_eq!(
            outbox_state(&a.machine, &a.label, live, BASE_MS + 1),
            DeliveryState::Composed,
            "the sweep retired the leg the record still names"
        );
    }

    /// M63. **A confirmed acceptance is not scanned for a `RE-CONFIRM`.**
    ///
    /// A5.1(ii) locks a confirmed candidate, and the scan's second candidate is
    /// gated on the lock being open. Deleting that gate would keep offering the
    /// settling-leg key for an exchange already settled — one wasted candidate
    /// per slot for the life of the retention, and a settling leg for a
    /// generation this side has left accepted where it should be inert.
    #[test]
    fn a_confirmed_acceptance_is_not_scanned_for_a_settlement() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let (_, t2) = carry_one_leg(&mut b, &mut a, t1);
        // A's settling leg, captured before it is delivered.
        let confirm = a.resume();
        let confirm = confirm.confirm_slot().expect("A completed");
        let (seq, bytes) = (confirm.seq(), confirm.sealed().to_vec());
        let page = position_of(seq).page();

        // B's acceptance, locked by hand: the confirmed state is otherwise
        // reached and left in one act, so nothing persists it.
        let stored = b.resume();
        let slot = stored.acceptance().expect("B answered");
        let locked = ResumeRecord::new(
            Box::new(*stored.s_pc()),
            Box::new(*stored.pk_pc()),
            stored.committed_root().clone(),
            ReEstState {
                reconnect_gen: stored.reconnect_gen(),
                attempt: stored.attempt().map_or(0, Attempt::get),
                last_seen_re_est: stored.last_seen_re_est(),
                own: None,
                acceptance: Some(
                    AcceptanceSlot::accept(
                        slot.generation(),
                        slot.attempt(),
                        slot.seq(),
                        slot.sealed_re_ack().to_vec().into_boxed_slice(),
                    )
                    .expect("within the ceiling")
                    .confirm(),
                ),
                confirm: None,
                attempt_at_window_start: stored.attempt_at_window_start(),
                reroot_ratchet_gen: stored.reroot_ratchet_gen(),
            },
            Retention {
                retained: stored.retained().map(|held| {
                    daemonseed_core::dm::resume::RetainedRoot::new(
                        held.root().clone(),
                        held.superseded_at_ms(),
                    )
                }),
                dedup: stored.dedup().clone(),
                stopped: stored.retained_but_stopped(),
            },
            stored.send_floor(),
        );
        drop(stored);
        b.machine
            .persist
            .commit_resume(&b.label, &locked)
            .expect("the lock commits");

        let before = b.machine.correspondences[0].health.unopenable;
        let conversation = b.conversation();
        fold_page_at(
            &mut b.machine,
            t2,
            conversation,
            page,
            vec![(position_of(seq), bytes)],
        );
        assert_eq!(
            b.machine.correspondences[0].health.unopenable,
            before + 1,
            "a settling leg opened against an acceptance A5.1(ii) has locked"
        );
        assert_eq!(
            b.resume().reconnect_gen(),
            0,
            "the locked exchange advanced its generation"
        );
    }

    /// M64. **A correspondent speaking under a root this side has superseded is
    /// reported once, changes nothing, and is inert on every later delivery.**
    ///
    /// A3.8's *peer state regressed*, and the state A3.5's retention exists to
    /// make openable at all: *"the ability to open the peer's frames at the
    /// superseded generation"*. The initiating side reaches it — it completes,
    /// retains `RS_n`, and its own confirming observation has not arrived — so a
    /// peer that rolled back to before the exchange goes on initiating at the
    /// generation and under the root the exchange started from.
    ///
    /// **The frame is sealed from real records, not invented.** The signing key
    /// is the peer's own `S_pc` and the root is the one this side retains, which
    /// is exactly what a rolled-back peer holds; nothing else would open.
    ///
    /// **The second delivery is the other half.** A5.3's memory is durable
    /// precisely so a co-host holding captured bytes cannot re-fire the alarm on
    /// demand; a build that surfaced before consulting it would hand that oracle
    /// straight back, and only a second delivery catches it.
    #[test]
    fn a_peer_under_a_superseded_root_is_reported_once() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        // B's signing key and the root both sides started from, read before the
        // exchange moves either.
        let b_s_pc = *b.resume().s_pc();
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let (_, t2) = carry_one_leg(&mut b, &mut a, t1);
        assert_eq!(
            a.resume().reconnect_gen(),
            1,
            "A did not complete, so nothing below is about a superseded root"
        );
        let held = a.resume();
        let retained_root = held
            .retained()
            .expect("A retains RS_n until its own confirming observation")
            .root()
            .clone();
        drop(held);

        // What a B rolled back to before its answer would send: a fresh attempt
        // at the generation the exchange reached, under the root it started
        // from. `attempt` 2 rather than 1, so the frame is byte-novel and the
        // alarm is not refused by the memory of the first exchange.
        let seq = 40u64;
        let (eph_ek, _) = reest::mint_ephemeral().expect("the ephemeral mints");
        let fresh = Attempt::FIRST.advance().expect("attempt space remains");
        let leg = reest::seal_re_est(
            &retained_root,
            Direction::BToA,
            1,
            seq,
            &fresh,
            &eph_ek,
            &b_s_pc,
        )
        .expect("the leg seals");

        let page = position_of(seq).page();
        let first = deliver(&mut a, t2 + 1, seq, page, leg.clone());
        assert_eq!(
            anomalies(&first),
            vec![TrustEventKey::DmPeerStateRegressed],
            "a peer under the superseded root was silent: {first:?}"
        );
        assert_eq!(
            a.resume().reconnect_gen(),
            1,
            "a regressed initiation moved the committed generation"
        );
        assert!(
            a.resume().acceptance().is_none(),
            "a regressed initiation was answered"
        );

        // A is restarted, so the collection does not filter the position out
        // before the scan sees it: the DURABLE memory is what must refuse the
        // second delivery, and only a durable one can.
        a.machine = machine(&dir_a);
        a.machine
            .persist
            .provision_block_list()
            .expect("provision A");
        let again = deliver(&mut a, t2 + 2, seq, page, leg);
        assert_eq!(
            anomalies(&again),
            Vec::new(),
            "a replay re-fired the alarm, which is the oracle A5.3's durability closes"
        );
    }

    /// M65. **The answer-side emission cap refuses without accepting, says so
    /// once, and leaves the refused attempt admissible.**
    ///
    /// A8.4 bounds *"post-openability response emission"* and nothing else, and
    /// [`ReEstAdmission::Withheld`]'s own contract is that *"nothing was
    /// accepted, so the same attempt may be admitted later"* — so a withheld
    /// frame must not be recorded as processed and must not settle its position,
    /// or the attempt the cap deferred is inert when the cap frees.
    ///
    /// The initiations are sealed from real records — the peer's own `S_pc` and
    /// the root both sides committed at establishment — because nothing else
    /// opens. Ascending attempts at one generation are A5.1's supersede, which
    /// is the cheapest way to reach the cap: each is admitted, each charges, and
    /// only the count is under test.
    #[test]
    fn the_answer_side_cap_withholds_without_accepting_and_is_loud_once() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, b) = restart_both(&dir_a, &dir_b, 1);
        let b_s_pc = *b.resume().s_pc();
        let root = a.resume().committed_root().clone();

        let seal_at = |attempt: u32, seq: u64| {
            let (eph_ek, _) = reest::mint_ephemeral().expect("the ephemeral mints");
            let mut fresh = Attempt::FIRST;
            let mut token = daemonseed_core::dm::resume::FreshAttempt::first();
            for _ in 1..attempt {
                token = fresh.advance().expect("attempt space remains");
                fresh = token.attempt();
            }
            reest::seal_re_est(&root, Direction::BToA, 1, seq, &token, &eph_ek, &b_s_pc)
                .expect("the leg seals")
        };

        let mut surfacings = 0usize;
        let mut admitted = 0u32;
        for attempt in 1..=RESPONSE_EMISSION_CAP + 1 {
            let seq = 100 + u64::from(attempt);
            let effects = deliver(
                &mut a,
                BASE_MS,
                seq,
                position_of(seq).page(),
                seal_at(attempt, seq),
            );
            surfacings += anomalies(&effects)
                .iter()
                .filter(|key| **key == TrustEventKey::DmReestablishmentBackoffEngaged)
                .count();
            if a.resume()
                .acceptance()
                .is_some_and(|slot| slot.attempt().get() == attempt)
            {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, RESPONSE_EMISSION_CAP,
            "the cap admitted {admitted} answers, not the {RESPONSE_EMISSION_CAP} it allows"
        );
        assert_eq!(
            surfacings, 1,
            "the cap surfaced {surfacings} times rather than once per session"
        );
        let withheld = RESPONSE_EMISSION_CAP + 1;
        assert!(
            a.resume()
                .acceptance()
                .is_some_and(|slot| slot.attempt().get() == RESPONSE_EMISSION_CAP),
            "the withheld attempt was accepted anyway"
        );
        // **Neither deduped nor settled.** Both would make the deferred attempt
        // inert when the cap frees: the memory would refuse it as a repeat, and
        // the settled position would never be offered to the scan again.
        assert!(
            !a.resume()
                .dedup()
                .keys()
                .iter()
                .any(|key| key.attempt().get() == withheld),
            "the withheld attempt was recorded as processed"
        );
        a.machine.correspondences[0].re_acks_answered = 0;
        let seq = 100 + u64::from(withheld);
        deliver(
            &mut a,
            BASE_MS,
            seq,
            position_of(seq).page(),
            seal_at(withheld, seq),
        );
        assert!(
            a.resume()
                .acceptance()
                .is_some_and(|slot| slot.attempt().get() == withheld),
            "the attempt the cap deferred was not admissible once the cap freed"
        );
    }

    /// M66. **A fold that opened a leg and could not finish leaves the position
    /// unsettled, writes nothing, and is offered the frame again.**
    ///
    /// A4.2 says reading updates local state; it does not say a read that
    /// FAILED may settle the position it could not act on. Settling one would
    /// walk past the only copy of a frame this side still owes an answer to, and
    /// no later sweep would offer it again — the exchange stalls in silence,
    /// which A3.15's table does not admit.
    ///
    /// A full dedup memory is the reachable failure: A5.3 refuses an eviction
    /// while the root is retained, so a memory at [`DEDUP_CAPACITY`] refuses the
    /// insert rather than making room. Reaching it needs no fault injection,
    /// which is why it is the one chosen.
    #[test]
    fn a_fold_that_could_not_finish_leaves_its_position_unsettled() {
        use daemonseed_core::dm::resume::{DedupMemory, DEDUP_CAPACITY};
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (seq, page, bytes, t1) = publish_one_leg(&mut a, BASE_MS);

        // B's memory, filled to its capacity with positions the window still
        // reaches, so the insert the fold performs is refused.
        let stored = b.resume();
        let mut dedup = DedupMemory::new();
        for n in 0..DEDUP_CAPACITY {
            dedup
                .insert(DedupKey::new(
                    1,
                    Attempt::FIRST,
                    Leg::ReEst,
                    Direction::AToB,
                    9_000 + n as u64,
                ))
                .expect("inside the capacity");
        }
        assert_eq!(dedup.len(), DEDUP_CAPACITY, "the fixture must fill the set");
        let filled = ResumeRecord::new(
            Box::new(*stored.s_pc()),
            Box::new(*stored.pk_pc()),
            stored.committed_root().clone(),
            ReEstState {
                reconnect_gen: stored.reconnect_gen(),
                attempt: stored.attempt().map_or(0, Attempt::get),
                last_seen_re_est: stored.last_seen_re_est(),
                own: None,
                acceptance: None,
                confirm: None,
                attempt_at_window_start: stored.attempt_at_window_start(),
                reroot_ratchet_gen: stored.reroot_ratchet_gen(),
            },
            Retention {
                // A retained root is what makes the memory unshrinkable, which
                // is what makes the insert refuse rather than evict.
                retained: Some(daemonseed_core::dm::resume::RetainedRoot::new(
                    stored.committed_root().clone(),
                    BASE_MS,
                )),
                dedup,
                stopped: false,
            },
            stored.send_floor(),
        );
        drop(stored);
        b.machine
            .persist
            .commit_resume(&b.label, &filled)
            .expect("the filled memory commits");

        let before = b.machine.correspondences[0].health.leg_folds_deferred;
        deliver(&mut b, t1, seq, page, bytes.clone());
        assert_eq!(
            b.machine.correspondences[0].health.leg_folds_deferred,
            before + 1,
            "the fold did not defer, so nothing below is about one that did"
        );
        assert!(
            b.resume().acceptance().is_none(),
            "a fold that could not finish committed an acceptance anyway"
        );

        // **Offered again**, which is the whole claim: a settled position is
        // filtered out of every later sweep before the scan sees it, so a second
        // deferral is only possible if the first left the position alone.
        deliver(&mut b, t1, seq, page, bytes);
        assert_eq!(
            b.machine.correspondences[0].health.leg_folds_deferred,
            before + 2,
            "the deferred position was settled, so the frame was never offered again"
        );
    }

    /// M67. **An exchange that settles with no candidate in memory owes a fresh
    /// attempt rather than stalling.**
    ///
    /// A5.4 keeps the ratchet root and the resumed channel's identifier out of
    /// every at-rest encoding, so a restart between answering and settling loses
    /// both. The record still settles correctly — the generation advances and
    /// the retained root retires — and the channel comes back addressable and
    /// mute. Leaving the pass unowed there would make the next re-establishment
    /// wait for a restart, which is A3.13's dead end reached by a different
    /// road.
    #[test]
    fn settling_with_no_candidate_owes_a_fresh_attempt() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let (_, t2) = carry_one_leg(&mut b, &mut a, t1);
        let (seq, page, bytes, t3) = publish_one_leg(&mut a, t2);

        // B restarts between answering and settling: the record survives, the
        // candidate does not.
        b.machine = machine_as(peer_identity(), &dir_b);
        b.machine
            .persist
            .provision_block_list()
            .expect("provision B");
        assert!(
            b.resume().acceptance().is_some(),
            "the restart lost the acceptance, so this is not the window under test"
        );
        // One tick first, so the load-time pass settles and clears the flag: a
        // freshly seeded correspondence owes that pass anyway, and asserting on
        // a flag nothing has cleared would pass whatever the settlement did.
        b.machine.on_tick(t3);
        assert!(
            !b.machine.correspondences[0].resume_owed,
            "the load-time pass did not settle, so the flag below is not the \
             settlement's doing"
        );

        deliver(&mut b, t3, seq, page, bytes);
        let settled = b.resume();
        assert_eq!(
            settled.reconnect_gen(),
            1,
            "the settlement did not land without a candidate"
        );
        assert!(
            settled.retained().is_none(),
            "the retained root outlived it"
        );
        assert!(
            b.machine.correspondences[0].ratchet.is_none(),
            "a channel came back speakable with no candidate to open it on"
        );
        assert!(
            b.machine.correspondences[0].resume_owed,
            "the pass was not left owed, so the next attempt waits for a restart"
        );
    }

    /// M69. **An absent outbox entry is not a confirming observation.**
    ///
    /// A3.6 gives the initiating side one: *"the ordinary acknowledgement
    /// settling `RE-CONFIRM`'s sequence position within its give-up window"*. An
    /// entry that is simply not there says nothing of the sort — it was pruned,
    /// or a crash lost it before the enqueue — and reading it as a settlement
    /// would drop the only copy of the settling leg and retire the retained root
    /// with it, which is the split-brain A3.5's ceiling exists to bound. A store
    /// that would not answer reaches the same verdict for the same reason, and
    /// the same arm.
    #[test]
    fn an_absent_settling_entry_is_not_a_confirming_observation() {
        let dir_a = tempfile::tempdir().expect("temp dir A");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let (mut a, mut b) = restart_both(&dir_a, &dir_b, 1);
        a.machine.on_tick(BASE_MS);
        let (_, t1) = carry_one_leg(&mut a, &mut b, BASE_MS);
        let (_, t2) = carry_one_leg(&mut b, &mut a, t1);
        let seq = a
            .resume()
            .confirm_slot()
            .expect("the completion persisted its settling leg")
            .seq();
        assert!(
            a.resume().retained().is_some(),
            "A retired RS_n before any observation, so nothing below is a test of one"
        );

        // The entry vanishes without ever being collected — a prune, or a crash
        // between the commit and the enqueue.
        a.machine
            .persist
            .update_outbox(&a.label, Direction::AToB, t2, |outbox| {
                assert!(
                    outbox.retire_leg(seq),
                    "the fixture must end the queued leg"
                );
                assert!(outbox.prune() > 0, "the fixture must remove it");
                Ok(Mutation::Changed(()))
            })
            .expect("the fixture writes");

        a.machine.on_tick(t2 + 1);
        assert!(
            a.resume().confirm_slot().is_some(),
            "an absent entry was read as a settlement and the settling leg was dropped"
        );
        assert!(
            a.resume().retained().is_some(),
            "an absent entry retired the root the settling leg is retained for"
        );
    }

    /// M47. **An established correspondence with no resume record is loud, and
    /// names a fresh first contact as the remedy.**
    ///
    /// A3.15 row 6's `absent` half. Reachable two ways and the same answer to
    /// both: a correspondence established before the resume record was written
    /// at all, and one whose initiator lost `S_pc` to a restart before its
    /// acceptance arrived.
    #[test]
    fn an_established_correspondence_with_no_resume_record_is_surfaced() {
        use daemonseed_core::storage::dm_store::RecordKind;

        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let _label = {
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            queue_unsealed(&a, &label, Direction::AToB, 40);
            a.persist
                .store()
                .critical_section(&label, |guard| -> Result<(), DmPersistError> {
                    guard.delete(RecordKind::Resume)?;
                    Ok(())
                })
                .expect("the fixture removes it");
            label
        };

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let out = a.on_tick(BASE_MS);

        assert_eq!(
            lost(&out),
            vec![(TrustEventKey::DmChannelTornDownOnRestart, vec![40])],
            "a correspondence that can never re-establish was not surfaced with \
             what it owes: {out:?}"
        );
    }

    /// M48. **An exhausted re-initiation window is surfaced with the mail it is
    /// holding**, not returned as a trace.
    ///
    /// A3.8 has every anomaly classed and suppression-protected. The window is
    /// exhausted at `ATTEMPT_CEILING` attempts against a window anchor, and
    /// nothing here moves that anchor but a peer opening one of our attempts —
    /// so the state is one the conversation does not leave on its own.
    #[test]
    fn an_exhausted_re_initiation_window_is_surfaced() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let _label = {
            let (a, _b, label) = established_initiator(&dir, &dir_b);
            queue_unsealed(&a, &label, Direction::AToB, 40);
            let stored = read_resume(&a, &label);
            a.persist
                .commit_resume(
                    &label,
                    &ResumeRecord::new(
                        Box::new(*stored.s_pc()),
                        Box::new(*stored.pk_pc()),
                        stored.committed_root().clone(),
                        ReEstState {
                            attempt: daemonseed_core::dm::reest::ATTEMPT_CEILING,
                            ..ReEstState::first_establishment()
                        },
                        Retention::none(),
                        stored.send_floor(),
                    ),
                )
                .expect("the exhausted window commits");
            label
        };

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let out = a.on_tick(BASE_MS);

        assert_eq!(
            lost(&out),
            vec![(TrustEventKey::DmChannelTornDownOnRestart, vec![40])],
            "an exhausted window was not surfaced with the mail it holds: {out:?}"
        );
    }

    /// M49. **The late pseudonym write finishes the establishment**, so a
    /// correspondence whose contact write was refused once still ends up with a
    /// resume record.
    ///
    /// The state is the one `on_page` leaves behind when
    /// `record_correspondent_pseudonym` is refused: the acceptance verified, the
    /// pseudonym is owed, and the handshake record is still held because it is
    /// the only thing a restart could re-arm from. Without the establishment on
    /// this path the retry releases that record into an established
    /// correspondence carrying no `S_pc`.
    #[test]
    fn a_retried_pseudonym_write_writes_the_resume_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let peer = peer_identity();
        let _ = knock_as_initiator(&mut a, &peer);
        let label = a.correspondences[0].label;
        assert!(
            a.correspondences[0].provisional.is_some(),
            "the knock left no handshake record, so this path is not reachable"
        );
        assert!(
            a.persist.read_resume(&label).expect("reads").is_none(),
            "the knock wrote a resume record, so the write below proves nothing"
        );
        a.correspondences[0].peer_pk_pc = Some(Box::new([0x5cu8; IDENTITY_PK_LEN]));
        a.correspondences[0].pseudonym_unwritten = true;

        let out = a.retry_pseudonym_write(BASE_MS, 0);

        assert!(
            out.is_empty(),
            "a write that landed reported the correspondence lost: {out:?}"
        );
        let resume = a
            .persist
            .read_resume(&label)
            .expect("reads")
            .expect("the retry owes a resume record");
        assert_eq!(
            resume.pk_pc().as_slice(),
            [0x5cu8; IDENTITY_PK_LEN].as_slice(),
            "the record verifies legs under a key the acceptance never carried"
        );
        assert!(
            !a.correspondences[0].pseudonym_unwritten,
            "the pseudonym is still owed after a write that landed"
        );
        assert!(
            a.correspondences[0].provisional.is_none(),
            "the handshake record was not released once its resume record landed"
        );
    }

    /// M50. **Establishing twice is idempotent.** The second pass finds a resume
    /// record already standing and answers `Complete` rather than writing a
    /// second one over it — `commit_resume` refuses a changed pseudonym pair, so
    /// a second write is an error rather than a no-op, and answering anything
    /// but `Complete` leaves the caller holding a handle for a record that is
    /// already gone.
    ///
    /// `establish_record` is called directly because that is the only way to
    /// reach the arm: `establish_provisional` releases its handle on the first
    /// success and returns before this arm on every later call.
    #[test]
    fn establishing_an_already_established_correspondence_changes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        let peer = peer_identity();
        let _ = knock_as_initiator(&mut a, &peer);
        let label = a.correspondences[0].label;
        let (keyrec_addr, fc_epoch) = a.correspondences[0]
            .provisional
            .expect("the knock left a handshake record");
        let peer_pk_pc = [0x5cu8; IDENTITY_PK_LEN];
        let signing_pc = a.correspondences[0]
            .signing_pc
            .take()
            .expect("the knock minted a pseudonym");

        let first = establish_record(
            &a.persist,
            &label,
            &keyrec_addr,
            fc_epoch,
            &signing_pc,
            &peer_pk_pc,
            SendFloor::new(0, 0),
        );
        assert_eq!(first, Establishment::Complete);
        let after_first = read_resume(&a, &label).encode().to_vec();

        let second = establish_record(
            &a.persist,
            &label,
            &keyrec_addr,
            fc_epoch,
            &signing_pc,
            &peer_pk_pc,
            SendFloor::new(0, 0),
        );

        assert_eq!(
            second,
            Establishment::Complete,
            "a second establishment did not read the standing resume record as done"
        );
        assert_eq!(
            read_resume(&a, &label).encode().to_vec(),
            after_first,
            "a second establishment rewrote the resume record"
        );
    }

    /// M51. **A correspondence with no ratchet refuses a send in as many
    /// words.**
    ///
    /// Pinned because the re-emit's sequence recovery no longer depends on it,
    /// and something else might: a path that queued on a downed channel would
    /// move `next_send_seq` under a committed attempt's stored position.
    #[test]
    fn a_correspondence_with_no_ratchet_refuses_a_send() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_b = tempfile::tempdir().expect("temp dir B");
        let peer_pk = {
            let (a, _b, _label) = established_initiator(&dir, &dir_b);
            *a.correspondences[0].pk_lt
        };

        let mut a = machine(&dir);
        a.persist.provision_block_list().expect("provision");
        assert!(
            a.correspondences[0].ratchet.is_none(),
            "the reload kept a ratchet, so this proves nothing"
        );
        let out = a.on_command(
            BASE_MS,
            DmCommand::Send {
                to: Box::new(peer_pk),
                body: "into a channel that is down".into(),
            },
        );

        let reasons: Vec<RefusalReason> = out
            .iter()
            .filter_map(|e| match e {
                DmEffect::Emit(DmEvent::Refused { reason, .. }) => Some(*reason),
                _ => None,
            })
            .collect();
        assert_eq!(
            reasons,
            vec![RefusalReason::NotEstablishedThisSession],
            "a send on a ratchet-less correspondence was not refused: {out:?}"
        );
    }

    /// Every page a batch of effects asks the transport to close.
    fn closed_pages(effects: &[DmEffect]) -> Vec<u64> {
        effects
            .iter()
            .filter_map(|e| match e {
                DmEffect::Dht(DhtOp::ClosePage { tag, .. }) => tag.page,
                _ => None,
            })
            .collect()
    }
}
