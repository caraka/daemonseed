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
use daemonseed_core::dm::keyrec::{self, DM_KEYREC_OWNER_SEED_LEN};
use daemonseed_core::dm::outbox::{
    DeliveryState, OutboxError, OutboxTarget, SealedFrame, GIVE_UP_MS,
};
use daemonseed_core::dm::paging::{
    position_of, DmPageAddress, PagePosition, Receiving, Sending, ADDRESS_ROOT_LEN, PAGE_SLOTS,
};
use daemonseed_core::dm::persist::{
    DmPersist, DmPersistError, Mutation, StateLoss, StoredChannelRestart,
};
use daemonseed_core::dm::pow;
use daemonseed_core::dm::provisional::{RecordContext, TeardownCause};
use daemonseed_core::dm::ratchet::{Direction, Ratchet, RatchetError, FIRST_RECIPIENT_CHANNEL_SEQ};
use daemonseed_core::dm::token::SpentTokenSet;
use daemonseed_core::identity::keys::{SignKeypair, IDENTITY_PK_LEN, ML_DSA_SEED_LEN};
use daemonseed_core::storage::dm_store::CorrespondenceLabel;

use crate::actor::{DmPageSweep, DoorbellDispatch, DoorbellSweep};
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
    /// Publish one direction's acknowledgement record.
    PublishAck {
        tag: OpTag,
        address: DmAckAddress,
        record: Vec<u8>,
    },
    /// Fetch the correspondent's acknowledgement.
    FetchAck { tag: OpTag, address: DmAckAddress },
}

/// Which of the seven operations an outcome came from.
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
            | DhtOp::FetchAck { tag, .. } => tag,
        }
    }

    /// What the shell should record about this operation before spawning it, so
    /// a task that panics can still release whatever the machine is holding for
    /// it.
    ///
    /// **The sweep is decided first, and the introduction takes whatever it does
    /// not claim.** Testing the introduction first would be correct only for as
    /// long as no sweep ever carries one — true today, since an introduction's
    /// operations are a key-record fetch and a doorbell write — and the day one
    /// did, the record slot it was holding would leak with nothing reporting it.
    ///
    /// A page sweep whose tag is missing its conversation or its page names no
    /// slot to release, so it **falls through** to the introduction rather than
    /// to nothing: ordering the two must not make either case narrower than it
    /// was, and a partial tag is exactly where that is easy to do by accident.
    pub(crate) fn panicked_job(&self) -> Option<PanickedJob> {
        let sweep = match self {
            DhtOp::SweepDoorbell { .. } => Some(PanickedJob::DoorbellSweep),
            DhtOp::SweepPage { tag, .. } => match (tag.conversation, tag.page) {
                (Some(conversation), Some(page)) => {
                    Some(PanickedJob::PageSweep { conversation, page })
                }
                _ => None,
            },
            _ => None,
        };
        sweep.or_else(|| {
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
}

/// One completed DHT operation, tagged with what asked for it.
pub(crate) struct DhtOutcome {
    /// Which operation produced it.
    ///
    /// **Carried rather than recovered from the result**, because the failure
    /// paths have no result to recover it from: an `Err` is one error type for
    /// all seven operations, and the doorbell sweep's tag names nothing. A sweep
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
/// **This state does not survive a restart, and that is a real gap rather than
/// an oversight.** The design homes our own `S_pc` and the correspondent's
/// `PK_pc` in the resume record (A4.8 / A9.2), and
/// [`ResumeRecord::new`](daemonseed_core::dm::resume::ResumeRecord::new)
/// cannot be written at first establishment: it requires a
/// [`SealedReEst`](daemonseed_core::dm::resume::SealedReEst), which is a sealed
/// re-establishment frame and therefore does not exist until the channel has
/// actually re-established once. So a correspondence established in this
/// process can be signed and verified for as long as this process lives, and a
/// restart before the first re-establishment loses the pseudonym pair with no
/// path back — the correspondence is on disk, and nothing can speak on it.
/// Closing that needs a way to commit the pair at establishment, which is a
/// change to what the resume record requires and not a wiring one.
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
    /// **Still in-memory only.** The at-rest home for the pseudonym pair is the
    /// resume record (A4.8 / A9.2), which cannot be written before the channel
    /// has re-established once, so a restart loses this exactly as it loses the
    /// ratchet — one event, not two.
    peer_pk_pc: Option<Box<[u8; IDENTITY_PK_LEN]>>,
    /// The conversation's address root and channel id, derived from `ss0` at
    /// establishment. `None` alongside a `None` ratchet, and for the same
    /// reason — nothing at rest carries them.
    channel: Option<ChannelRoots>,
    /// What has been collected on the receiving direction.
    collection: Collection,
    /// The highest page this session has actually swept — the corroboration
    /// [`DmPersist::advance_cursor`] refuses to move the stored cursor without.
    ///
    /// **This session's own knowledge, never a number read back from the file.**
    /// The cursor record is unsealed by design, so a value taken from it and
    /// handed back as its own bound would be checking an untrusted number
    /// against itself.
    read_through: u64,
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
}

/// The recipient key-record address half of a
/// [`RecordContext`], owned rather than borrowed so a correspondence can hold
/// it across ticks.
type ProvisionalContext = [u8; DM_KEYREC_OWNER_SEED_LEN];

/// The conversation's two derived roots, held together because they are derived
/// together and are meaningless apart.
struct ChannelRoots {
    /// The address root every page and acknowledgement record hangs off.
    address_root: [u8; ADDRESS_ROOT_LEN],
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
    /// The receiving pages whose sweep is in flight, by conversation and page.
    ///
    /// Keyed per page rather than per conversation because the probe plan is
    /// per page: two different pages of one conversation are two different
    /// records, and holding one open says nothing about the other.
    sweeping_pages: std::collections::BTreeSet<([u8; AR_FINGERPRINT_LEN], u64)>,
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
            sweeping_pages: std::collections::BTreeSet::new(),
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
        for index in 0..self.correspondences.len() {
            out.extend(self.give_ups(now_ms, index));
            out.extend(self.due_emissions(now_ms, index));
            out.extend(self.probe(now_ms, index));
            out.extend(self.ack_fetches(now_ms, index));
        }
        // **After the per-correspondence pass, and once for all of them**, because
        // the standalone allowance is client-global: deciding it inside the loop
        // would hand it to whichever correspondence the store happened to
        // enumerate first, where `pick_next` gives it to the one whose sender has
        // been waiting longest.
        out.extend(self.standalone_acks(now_ms));
        out
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
                    self.refuse_introduction(&recipient, RefusalReason::MintPanicked)
                }
                Some(PanickedJob::Dht(recipient)) => {
                    self.refuse_introduction(&recipient, RefusalReason::TaskPanicked)
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
                    Vec::new()
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
                match result {
                    Err(e) => {
                        crate::vtrace!("dm driver: operation failed: {e}");
                        // An introduction whose fetch or write failed on the
                        // transport is refused rather than left in flight: the
                        // front end may ask again, and a silently retained
                        // introduction would refuse that second ask as a duplicate.
                        match tag.introduction {
                            Some(recipient) => {
                                self.refuse_introduction(&recipient, RefusalReason::PublishFailed)
                            }
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
                }
            }
        }
    }

    /// Record that a sweep is no longer in flight.
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
            DhtOpKind::FetchKeyRecord
            | DhtOpKind::PublishDoorbell
            | DhtOpKind::PublishPage
            | DhtOpKind::PublishAck
            | DhtOpKind::FetchAck => {}
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
            ))];
        };
        let Some((ratchet, _, _)) = self.correspondences[index].live() else {
            return vec![DmEffect::Emit(refused(
                to,
                RefusalReason::NotEstablishedThisSession,
            ))];
        };
        let label = self.correspondences[index].label;
        let direction = ratchet.send_direction();
        let next_seq = ratchet.next_send_seq();

        // Checked here rather than left to `seal`, which reports it only after
        // the ratchet has already stepped.
        if body.len() > firstcontact::DM_BODY_CAP {
            return vec![DmEffect::Emit(refused(to, RefusalReason::BodyTooLarge))];
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
                ))];
            }
            Ok(Err(e)) => {
                crate::vtrace!("dm driver: the outbox refused sequence {next_seq}: {e}");
                return vec![DmEffect::Emit(refused(to, RefusalReason::StoreFailure))];
            }
            Err(e) => {
                crate::vtrace!("dm driver: the outbox could not be read: {e}");
                return vec![DmEffect::Emit(refused(to, RefusalReason::StoreFailure))];
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
                return vec![DmEffect::Emit(refused(to, RefusalReason::Module))];
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
            ))];
        };
        // Past this line a sequence number has been spent.
        let outbound = match ratchet.send_next() {
            Ok(o) => o,
            Err(e) => {
                crate::vtrace!("dm driver: the ratchet refused to mint a key: {e}");
                return vec![DmEffect::Emit(refused(to, RefusalReason::SealFailed))];
            }
        };
        let seq = outbound.header.seq;
        // The piggybacked acknowledgement rides for free: `seal` reads the
        // collection's own state, so a message going out carries what has come
        // in without a second record, a second write, or a second signature.
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
                return vec![DmEffect::Emit(refused(to, RefusalReason::SealFailed))];
            }
        };
        let queued = persist.update_outbox(&label, direction, now_ms, |outbox| {
            outbox.enqueue_sealed(
                seq,
                OutboxTarget::ChannelPage,
                now_ms,
                SealedFrame::new(sealed),
            )?;
            Ok(Mutation::Changed(()))
        });
        if let Err(e) = queued {
            // The ask said there was room and the record has not been touched
            // since, so this is a store fault rather than the capacity refusal
            // — and the sequence number IS spent, because the seal is behind us.
            crate::vtrace!("dm driver: sequence {seq} sealed and could not be queued: {e}");
            return vec![DmEffect::Emit(refused(to, RefusalReason::StoreFailure))];
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
                Ok(if swept.is_empty() {
                    Mutation::Unchanged(owed)
                } else {
                    Mutation::Changed(owed)
                })
            });
        let owed = match owed {
            Ok(owed) => owed,
            Err(e) => {
                crate::vtrace!("dm driver: the give-up sweep failed: {e}");
                return Vec::new();
            }
        };
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
        out
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
                !erase_record(&self.persist, label, keyrec_addr, *fc_epoch)
            })
            .collect();
    }

    /// The emission scan proper, without the acceptance retry above it.
    fn due_emissions_only(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let label = self.correspondences[index].label;
        let Some(direction) = self.stored_direction(&label, now_ms) else {
            return Vec::new();
        };
        let live = self.correspondences[index].live().is_some();
        let emitted = self
            .persist
            .update_outbox(&label, direction, now_ms, |outbox| {
                let mut out: Vec<(u64, OutboxTarget, Vec<u8>)> = Vec::new();
                for seq in outbox.due(now_ms) {
                    let Some(entry) = outbox.entry_mut(seq) else {
                        continue;
                    };
                    let target = entry.target();
                    if matches!(target, OutboxTarget::ChannelPage) && !live {
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
                    Mutation::Unchanged(out)
                } else {
                    Mutation::Changed(out)
                })
            });
        let emitted = match emitted {
            Ok(emitted) => emitted,
            Err(e) => {
                crate::vtrace!("dm driver: the due-entry scan failed: {e}");
                return Vec::new();
            }
        };
        let correspondence = &self.correspondences[index];
        // A conversation tag only exists where a ratchet does; a doorbell
        // re-seed on a restored correspondence is attributed by its recipient
        // instead, which is what the write's own outcome carries back.
        let conversation = correspondence.live().map(|(r, _, _)| *r.ar_fingerprint());
        let mut out = Vec::new();
        for (seq, target, frame) in emitted {
            match target {
                OutboxTarget::ChannelPage => {
                    let Some((ratchet, _, channel)) = correspondence.live() else {
                        continue;
                    };
                    let address = match DmPageAddress::sending(
                        &channel.address_root,
                        ratchet,
                        position_of(seq),
                    ) {
                        Ok(address) => address,
                        Err(e) => {
                            crate::vtrace!("dm driver: page address derivation failed: {e}");
                            continue;
                        }
                    };
                    out.push(DmEffect::Dht(DhtOp::PublishPage {
                        tag: OpTag {
                            conversation,
                            seq: Some(seq),
                            page: None,
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
    fn probe(&mut self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let Self {
            correspondences,
            sweeping_pages,
            ..
        } = self;
        let correspondence = &mut correspondences[index];
        if correspondence.live().is_none() {
            return Vec::new();
        }
        // The cadence is consumed whether or not the sweep can proceed, so a
        // correspondence that cannot verify anything reports once per cadence
        // rather than once per tick.
        let Some(plan) = correspondence.collection.probe_plan(probe_ms(now_ms)) else {
            return Vec::new();
        };
        // **An initiator that has not yet seen the acceptance still sweeps**,
        // because the acceptance itself arrives by sweep: it is an ordinary
        // channel frame at the acceptor's sequence zero. What it cannot do is
        // open anything later than that, which `on_page` decides per slot.
        let Some((ratchet, _, channel)) = correspondence.live() else {
            return Vec::new();
        };
        let conversation = *ratchet.ar_fingerprint();
        let mut out = Vec::new();
        for page in plan {
            if sweeping_pages.contains(&(conversation, page)) {
                continue;
            }
            match DmPageAddress::receiving(&channel.address_root, ratchet, page) {
                Ok(address) => {
                    sweeping_pages.insert((conversation, page));
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
            let parsed = match frame::parse(encoded) {
                Ok(parsed) => parsed,
                Err(e) => {
                    crate::vtrace!("dm driver: a swept slot is not a frame: {e}");
                    correspondence.health.unopenable += 1;
                    continue;
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
                continue;
            }
            // `break`, never `return`: messages already opened from earlier
            // slots of this same page are in `out`, and the cursor advance and
            // the health event below are owed whatever stopped the loop.
            let (Some(ratchet), Some(channel)) = (
                correspondence.ratchet.as_mut(),
                correspondence.channel.as_ref(),
            ) else {
                break;
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
                        correspondence.peer_pk_pc = Some(pk_pc);
                        erase_provisional(persist, correspondence);
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
                    correspondence.health.unopenable += 1;
                }
                Ok(Err(e)) => {
                    crate::vtrace!("dm driver: a swept frame did not authenticate: {e}");
                    correspondence.health.unopenable += 1;
                }
            }
        }

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
                Ok(_) => {}
                Err(e) => crate::vtrace!("dm driver: the receive cursor would not advance: {e}"),
            }
        }
        out.extend(correspondence.health_event(before));
        out
    }

    /// The correspondence holding this identity, if this session holds one.
    fn index_of(&self, pk_lt: &[u8; IDENTITY_PK_LEN]) -> Option<usize> {
        self.correspondences
            .iter()
            .position(|c| c.pk_lt.as_slice() == pk_lt.as_slice())
    }

    /// The correspondence one channel-plane operation belongs to.
    fn index_of_conversation(&self, conversation: &[u8; AR_FINGERPRINT_LEN]) -> Option<usize> {
        self.correspondences.iter().position(|c| {
            c.ratchet
                .as_ref()
                .is_some_and(|r| r.ar_fingerprint() == conversation)
        })
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
    fn ack_fetches(&self, now_ms: i64, index: usize) -> Vec<DmEffect> {
        let correspondence = &self.correspondences[index];
        let Some((ratchet, _, channel)) = correspondence.live() else {
            return Vec::new();
        };
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
        let address =
            match DmAckAddress::for_direction(&channel.address_root, ratchet.send_direction()) {
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
                &channel.address_root,
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
        let direction = ratchet.recv_direction();
        let record = match ack_record::build_encoded(
            correspondence.collection.ack(),
            &channel.chan_id,
            direction,
            &channel.address_root,
            signing_pc,
        ) {
            Ok(record) => record,
            Err(e) => {
                crate::vtrace!("dm driver: the acknowledgement record would not build: {e}");
                return Vec::new();
            }
        };
        let address = match DmAckAddress::for_direction(&channel.address_root, direction) {
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
            match persist.correspondence_for_pk_lt(pk) {
                Ok(found) => found.is_some(),
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
            }) => vec![DmEffect::Emit(DmEvent::ChannelLost {
                with: Box::new(*knock.pk_lt()),
                cause: teardown.into_cause(),
                // The sequences the user is owed. Dropping them would leave
                // this event saying a channel ended and nothing saying which
                // messages ended with it.
                surfaced: outcome.surfaced,
            })],
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
            address_root: held.knock.roots().ar,
            chan_id: held.knock.roots().chan_id,
        };

        // **The recoverable refusals are taken here, before the knock is
        // consumed.** `accept_first_contact` moves the `VerifiedFirstContact`
        // — `ss0` leaves it by a consuming accessor and there is no way back —
        // so a refusal raised inside it arrives with the request already
        // destroyed. Asking the two questions that can be asked without it
        // means the two failures a user can actually do something about leave
        // the request on screen to answer again.
        match self.persist.correspondence_for_pk_lt(&pk_lt) {
            Ok(Some(_)) => return self.hold_again(held, AcceptFailure::AlreadyEstablished),
            Ok(None) => {}
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

        match self.persist.accept_first_contact(*held.knock, now_ms) {
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
                    erase_provisional(persist, &mut correspondences[index]);
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
                        collection: collection_accepting_a_knock(),
                        read_through: 0,
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
            Ok(()) => Vec::new(),
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
        if blocked {
            // A held request from a blocked identity is dropped: the block is
            // meant to take effect on what is already on screen, not only on
            // what arrives next.
            self.pending
                .retain(|held| held.knock.pk_lt().as_slice() != pk_lt.as_slice());
        }
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
            ))];
        }
        // **First contact is for strangers.** Knocking at an identity we
        // already correspond with is read at the far end as evidence we lost
        // our at-rest state, and their client answers it by ending every
        // message they have queued for us — so an unguarded `FirstContact` from
        // the UI is a way to destroy a live conversation from the wrong button.
        match self.persist.correspondence_for_pk_lt(&recipient) {
            Ok(Some(_)) => {
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::AlreadyEstablished,
                ))];
            }
            Ok(None) => {}
            Err(e) => {
                // Fail closed for the same reason the sweep does: an unreadable
                // store must not read as "this identity is a stranger".
                crate::vtrace!("dm driver: correspondence lookup failed: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::StoreFailure,
                ))];
            }
        }
        let owner_seed = match keyrec::derive_owner_seed(&recipient) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: recipient key-record derivation failed: {e}");
                return vec![DmEffect::Emit(refused(&recipient, RefusalReason::Module))];
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
            ))];
        };
        let verified = match keyrec::decode_and_verify(&bytes, &recipient) {
            Ok(v) => v,
            Err(e) => {
                crate::vtrace!("dm driver: key record did not verify: {e}");
                return vec![DmEffect::Emit(refused(
                    &recipient,
                    RefusalReason::KeyRecordInvalid,
                ))];
            }
        };
        let signing_pc = match mint_pseudonym() {
            Ok(k) => k,
            Err(e) => {
                crate::vtrace!("dm driver: pseudonym keygen failed: {e}");
                return vec![DmEffect::Emit(refused(&recipient, RefusalReason::Module))];
            }
        };
        let recipient_keyrec_addr = match keyrec::derive_owner_seed(&recipient) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: recipient key-record derivation failed: {e}");
                return vec![DmEffect::Emit(refused(&recipient, RefusalReason::Module))];
            }
        };
        self.minting.push(Box::new(*recipient));
        vec![DmEffect::Compute(ComputeJob::MintFirstContact(Box::new(
            MintRequest {
                recipient,
                signing_lt: self.identity.signing.clone(),
                signing_pc,
                kem_ek_b: verified.kem_ek,
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
                return self.refuse_introduction(&recipient, RefusalReason::MintFailed);
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
            return self.refuse_introduction(&recipient, RefusalReason::AlreadyEstablished);
        }
        // **One provisional label per recipient, never one per attempt.** A
        // second label is a second correspondence directory holding a live
        // `ss0` that nothing will ever establish or erase, so the label is
        // reused where one is already known.
        let label = match self.provisional_label(&recipient, &recipient_keyrec_addr, fc_epoch) {
            Ok(label) => label,
            Err(e) => {
                crate::vtrace!("dm driver: correspondence label mint failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::StoreFailure);
            }
        };
        // Read before `into_provisional` moves the state: the record recomputes
        // both from `ss0` and hands back neither, and `chan_id` is never
        // serialized at all (§ v4 minor invariant).
        let channel = ChannelRoots {
            address_root: state.roots().ar,
            chan_id: state.roots().chan_id,
        };
        let record = match state.into_provisional() {
            Ok(r) => r,
            Err(e) => {
                crate::vtrace!("dm driver: provisional record build failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::StoreFailure);
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
            return self.refuse_introduction(&recipient, RefusalReason::StoreFailure);
        }
        let owner_seed = match doorbell::derive_owner_seed(&recipient) {
            Ok(seed) => *seed.as_bytes(),
            Err(e) => {
                crate::vtrace!("dm driver: recipient doorbell derivation failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::Module);
            }
        };
        let slot = match doorbell::slot_for(&self.identity.doorbell_slot_secret, &recipient) {
            Ok(slot) => slot,
            Err(e) => {
                crate::vtrace!("dm driver: doorbell slot derivation failed: {e}");
                return self.refuse_introduction(&recipient, RefusalReason::Module);
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
                    return self.refuse_introduction(&recipient, RefusalReason::StoreFailure);
                }
            },
            StoredChannelRestart::TornDown(teardown) => {
                crate::vtrace!(
                    "dm driver: the record just written would not open: {:?}",
                    teardown.cause()
                );
                return self.refuse_introduction(&recipient, RefusalReason::StoreFailure);
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
                collection: Collection::new(),
                read_through: 0,
                owed_acks: Vec::new(),
                offered_this_session: Vec::new(),
                health: ChannelCounters::default(),
                ack_cadence: StandaloneAckCadence::new(),
                pending_sent_ms: Vec::new(),
                own_ack: AckState::new(),
                last_accept_refusal: None,
                provisional: Some((recipient_keyrec_addr, fc_epoch)),
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
                )?;
                Ok(Mutation::Changed(()))
            });
        if let Err(e) = queued {
            crate::vtrace!("dm driver: the knock could not be queued: {e}");
            return self.refuse_introduction(&recipient, RefusalReason::StoreFailure);
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
    /// [`DmPersist::restart_channel`] under this recipient's context at each
    /// live epoch — a record opens only under the context it was sealed with,
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
                if let daemonseed_core::dm::persist::StoredChannelRestart::HandshakeResumes(
                    pending,
                ) = self.persist.restart_channel(&label, &ctx)
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
        let label = CorrespondenceLabel::mint()?;
        self.provisionals.push((Box::new(**recipient), label));
        Ok(label)
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

    /// Drop an in-flight introduction and tell the front end it did not
    /// proceed.
    fn refuse_introduction(&mut self, recipient: &PkLt, reason: RefusalReason) -> Vec<DmEffect> {
        let before = self.outbound.len() + self.minting.len();
        self.outbound
            .retain(|i| i.recipient.as_slice() != recipient.as_slice());
        self.minting
            .retain(|pk| pk.as_slice() != recipient.as_slice());
        if self.outbound.len() + self.minting.len() == before {
            return Vec::new();
        }
        vec![DmEffect::Emit(refused(recipient, reason))]
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

/// A first contact that did not proceed.
///
/// [`Acceptance::Unconfirmed`] is all this layer can say about the write: no
/// emission of this introduction has been confirmed, which is true of every
/// path here — nothing reaches this function after a confirmed doorbell write.
/// `reason` is the part that varies and the part a front end acts on.
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
        let states: Vec<(u64, DeliveryState)> = settled
            .iter()
            .filter_map(|&seq| outbox.entry(seq).map(|entry| (seq, entry.delivery_state())))
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
/// ⚠️ **The resume path must re-apply this, and does not yet.** `seed_from_store`
/// rebuilds a correspondence with a fresh [`AckState`], so a restart loses the
/// settled knock position exactly as it loses the rest of the collection. It is
/// unreachable today for an unrelated reason — a resumed correspondence has no
/// key schedule, so it opens nothing and acknowledges nothing — which is why it
/// is named here rather than fixed: whatever restores a live correspondence
/// across a restart has to restore this position with it, or the first
/// acknowledgement written after a restart re-opens the hole under the prefix.
fn collection_accepting_a_knock() -> Collection {
    let mut collection = Collection::new();
    if let Err(e) = collection.collected(position_of(KNOCK_CHANNEL_SEQ)) {
        crate::vtrace!("dm driver: the knock's own position would not settle: {e}");
    }
    collection
}

fn erase_provisional(persist: &DmPersist, correspondence: &mut Correspondence) {
    let Some((keyrec_addr, fc_epoch)) = correspondence.provisional else {
        return;
    };
    if erase_record(persist, &correspondence.label, &keyrec_addr, fc_epoch) {
        correspondence.provisional = None;
    }
}

/// Erase one provisional record, and say whether it is now gone.
///
/// **The return value is the whole interface**, because the caller's only
/// correct reaction to a failure is to keep the handle. The context names the
/// epoch the record was sealed under and a record opens under no other, so a
/// handle dropped on a failed erase leaves `{ss0, the opening ephemeral DK}` on
/// disk with nothing left that could ever address it — a transient store fault
/// turned into a permanent leak of the secret that roots `RK0`.
///
/// `true` on exactly two outcomes: the delete succeeded, or the store says
/// there is no record there. Every other teardown cause is a statement about
/// the store or the ciphertext at this moment, not about whether the record
/// exists.
fn erase_record(
    persist: &DmPersist,
    label: &CorrespondenceLabel,
    keyrec_addr: &ProvisionalContext,
    fc_epoch: u64,
) -> bool {
    let ctx = RecordContext {
        recipient_keyrec_addr: keyrec_addr,
        fc_epoch,
    };
    match persist.restart_channel(label, &ctx) {
        StoredChannelRestart::HandshakeResumes(pending) => match pending.commit() {
            Ok(()) => true,
            Err(e) => {
                crate::vtrace!("dm driver: the provisional record would not erase: {e}");
                false
            }
        },
        StoredChannelRestart::TornDown(teardown) => match teardown.cause() {
            // Gone. Nothing to erase and nothing to retry.
            TeardownCause::NoProvisionalRecord => true,
            // The store could not be read, the ciphertext did not open, or the
            // correspondent's state was lost. None of those says the record is
            // absent, so the caller keeps its handle.
            cause => {
                crate::vtrace!(
                    "dm driver: the provisional record would not open to erase: {cause:?}"
                );
                false
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
        DmEffect::Emit(refused(recipient, reason)),
    ]
}

fn refused(recipient: &[u8; IDENTITY_PK_LEN], reason: RefusalReason) -> DmEvent {
    DmEvent::Refused {
        to: Box::new(*recipient),
        acceptance: daemonseed_core::dm::outbox::Acceptance::Unconfirmed,
        reason,
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
/// what this session has genuinely swept: nothing.** The cursor record is
/// unsealed by design, so anything able to write the file chooses that number,
/// and the bound is the caller's own knowledge or it is not a bound at all. A
/// stored page above zero is therefore refused rather than believed, and the
/// collection resumes from the start — a full rescan, which is the failure that
/// type is allowed to have.
///
/// A store that will not enumerate, a contact record that will not decode and a
/// cursor that will not corroborate are each traced and skipped rather than
/// fatal: a driver that refused to start over one unreadable correspondence
/// would take every other correspondence down with it.
fn seed_from_store(persist: &DmPersist) -> Vec<Correspondence> {
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
        let page = match persist.read_cursor(&label, 0) {
            Ok(Some(cursor)) => cursor.page(),
            Ok(None) => 0,
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
            peer_pk_pc: Some(Box::new(*record.pk_pc())),
            channel: None,
            collection: Collection::resuming_from_page(page),
            read_through: 0,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            // A correspondence on disk is one that was established; nothing
            // provisional survives it.
            provisional: None,
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
            .accept_first_contact(*fake_knock(21), BASE_MS)
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
                    Ok(daemonseed_core::dm::contact_cache::ContactRecord::new(
                        Box::new(*seeded.pk_lt()),
                        Box::new(*seeded.pk_pc()),
                        zeroize::Zeroizing::new(*seeded.ss0_for_test()),
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
            address_root: knock.roots().ar,
            chan_id: knock.roots().chan_id,
        };
        let (label, ratchet) = m
            .persist
            .accept_first_contact(*knock, BASE_MS)
            .expect("the establish succeeds");
        m.correspondences.push(Correspondence {
            pk_lt,
            label,
            ratchet: Some(ratchet),
            signing_pc: Some(mint_pseudonym().expect("pseudonym")),
            peer_pk_pc: Some(peer_pk_pc),
            channel: Some(channel),
            collection: Collection::new(),
            read_through: 0,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            provisional: None,
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
            address_root: knock.roots().ar,
            chan_id: knock.roots().chan_id,
        };
        let (label, ratchet) = m
            .persist
            .accept_first_contact(*knock, BASE_MS)
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
            collection: Collection::new(),
            read_through: 0,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            provisional: None,
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
        let pk_lt: PkLt = Box::new(*peer.signing.public_key());
        let out = a.on_command(
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
        let record = keyrec::build_encoded(
            &peer.signing,
            peer.kem.encapsulation_key(),
            keyrec::DM_KEY_RECORD_VERSION,
            keyrec::DM_KEY_RECORD_INVITE_ONLY,
        )
        .expect("key record");
        let mut out = a.on_key_record(BASE_MS, pk_lt, Some(record));
        assert_eq!(out.len(), 1, "the key record did not start a mint: {out:?}");
        let DmEffect::Compute(ComputeJob::MintFirstContact(request)) = out.remove(0) else {
            panic!("the key record did not start a mint");
        };
        let out = a.on_mint(BASE_MS, run_mint(*request));
        out.iter()
            .find_map(|e| match e {
                DmEffect::Dht(DhtOp::PublishDoorbell { entry, slot, .. }) => {
                    Some((*slot, entry.clone()))
                }
                _ => None,
            })
            .expect("the mint did not publish a knock")
    }

    /// M22. An initiator that has not yet seen the acceptance still sweeps.
    ///
    /// The acceptance arrives BY sweep — it is an ordinary channel frame at the
    /// acceptor's sequence zero — so a probe that refused to plan while the
    /// pseudonym was unknown would be waiting for something only the sweep can
    /// deliver. The `SweepPage` effect is the whole assertion; the correspondence
    /// underneath it has `peer_pk_pc: None`, which is the state that used to
    /// suppress it.
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

        let out = m.probe(BASE_MS, 0);
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

        let first = swept_pages(&m.probe(BASE_MS, 0));
        assert_eq!(
            first,
            vec![0, 1],
            "the watched pair must be planned, or every assertion below is vacuous"
        );

        // The cadence has elapsed, so the plan is issued again — and every page
        // in it is one this machine is already waiting on.
        let second = swept_pages(&m.probe(BASE_MS + PROBE_MS, 0));
        assert!(
            second.is_empty(),
            "a page already being swept must not be swept again: {second:?}"
        );

        // ── a sweep that came back releases its page ─────────────────────────
        m.on_outcome(
            BASE_MS + PROBE_MS,
            page_outcome(conversation, 0, Ok(empty_page(conversation))),
        );
        let third = swept_pages(&m.probe(BASE_MS + 2 * PROBE_MS, 0));
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
        let fourth = swept_pages(&m.probe(BASE_MS + 3 * PROBE_MS, 0));
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
        let fifth = swept_pages(&m.probe(BASE_MS + 4 * PROBE_MS, 0));
        assert_eq!(
            fifth,
            vec![0],
            "a panicked sweep must release its page: {fifth:?}"
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
            address_root: knock.roots().ar,
            chan_id: knock.roots().chan_id,
        };
        let (label, _ratchet) = m
            .persist
            .accept_first_contact(*knock, BASE_MS)
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
            collection: Collection::new(),
            read_through: 0,
            owed_acks: Vec::new(),
            offered_this_session: Vec::new(),
            health: ChannelCounters::default(),
            ack_cadence: StandaloneAckCadence::new(),
            pending_sent_ms: Vec::new(),
            own_ack: AckState::new(),
            last_accept_refusal: None,
            provisional: None,
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
            &channel.address_root,
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
            &channel.address_root,
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
}
