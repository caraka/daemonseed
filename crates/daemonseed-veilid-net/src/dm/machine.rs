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
//! This is the **doorbell half**: our own doorbell is swept on the cadence,
//! every populated slot goes through [`Admitter`] in its documented order, an
//! admitted knock from a stranger is held until the user answers it, and an
//! outbound knock is composed, proof-minted off the loop, and published. The
//! channel plane — sending on an established correspondence, page sweeps,
//! acknowledgements and the outbox's re-seed cadence — is items 3 and 4, and
//! nothing here decides any of it.

use std::sync::Arc;
use std::time::Duration;

use daemonseed_core::dm::ack_record::DmAckAddress;
use daemonseed_core::dm::admission::{AdmissionCounters, AdmissionOutcome, Admitter, SeenSet};
use daemonseed_core::dm::block_list::{BlockList, BlockListError};
use daemonseed_core::dm::doorbell;
use daemonseed_core::dm::firstcontact::{
    self, FirstContactError, FirstContactRequest, FirstContactState, VerifiedFirstContact,
    AR_FINGERPRINT_LEN,
};
use daemonseed_core::dm::keyrec::KEM_EK_LEN;
use daemonseed_core::dm::keyrec::{self, DM_KEYREC_OWNER_SEED_LEN};
use daemonseed_core::dm::paging::{DmPageAddress, Receiving, Sending};
use daemonseed_core::dm::persist::{DmPersist, DmPersistError, StateLoss};
use daemonseed_core::dm::pow;
use daemonseed_core::dm::provisional::RecordContext;
use daemonseed_core::dm::ratchet::Ratchet;
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
pub(crate) const PENDING_REQUEST_CAP: usize = 64;

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
            DmEffect::Dht(op) => write!(f, "Dht({})", op.kind()),
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
    // Items 3-4 tag channel-plane operations with it; the doorbell plane has no
    // conversation until a knock is accepted.
    #[allow(dead_code)]
    pub conversation: Option<[u8; AR_FINGERPRINT_LEN]>,
    /// The message sequence number, where the operation has one.
    // Item 3 tags an outbox emission with its sequence number.
    #[allow(dead_code)]
    pub seq: Option<u64>,
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
            introduction: None,
        }
    }

    /// A tag naming one in-flight introduction.
    fn introduction(recipient: PkLt) -> Self {
        Self {
            conversation: None,
            seq: None,
            introduction: Some(recipient),
        }
    }
}

impl core::fmt::Debug for OpTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The introduction's `PkLt` names a person; only its presence is shown.
        f.debug_struct("OpTag")
            .field("conversation", &self.conversation.map(|_| "<AR>"))
            .field("seq", &self.seq)
            .field(
                "introduction",
                &self.introduction.as_ref().map(|_| "PkLt(..)"),
            )
            .finish()
    }
}

/// One DHT operation, as the machine asks for it.
//
// The channel-plane variants — PublishPage, SweepPage, PublishAck, FetchAck —
// are dispatched and oracle-covered but constructed by nothing yet: items 3 and
// 4 construct them.
#[allow(dead_code)]
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

impl DhtOp {
    /// This operation's kind, for a trace line that carries no payload.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            DhtOp::FetchKeyRecord { .. } => "FetchKeyRecord",
            DhtOp::PublishDoorbell { .. } => "PublishDoorbell",
            DhtOp::SweepDoorbell { .. } => "SweepDoorbell",
            DhtOp::PublishPage { .. } => "PublishPage",
            DhtOp::SweepPage { .. } => "SweepPage",
            DhtOp::PublishAck { .. } => "PublishAck",
            DhtOp::FetchAck { .. } => "FetchAck",
        }
    }

    /// The introduction this operation belongs to, where it has one.
    ///
    /// The shell reads it before spawning, so a task that panics can still be
    /// traced back to the introduction it was carrying.
    pub(crate) fn introduction(&self) -> Option<PkLt> {
        let tag = match self {
            DhtOp::FetchKeyRecord { tag, .. }
            | DhtOp::PublishDoorbell { tag, .. }
            | DhtOp::SweepDoorbell { tag, .. }
            | DhtOp::PublishPage { tag, .. }
            | DhtOp::SweepPage { tag, .. }
            | DhtOp::PublishAck { tag, .. }
            | DhtOp::FetchAck { tag, .. } => tag,
        };
        tag.introduction.as_ref().map(|pk| Box::new(**pk))
    }
}

/// What one completed DHT operation yielded.
//
// `Page` and `Ack` carry payloads the machine matches on but does not yet read:
// items 3 and 4 read them.
#[allow(dead_code)]
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
}

/// One completed DHT operation, tagged with what asked for it.
pub(crate) struct DhtOutcome {
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
    /// would leave the channel unable to speak the moment item 3 tried.
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
}

impl core::fmt::Debug for PanickedJob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PanickedJob::Mint(_) => f.write_str("Mint(PkLt(..))"),
            PanickedJob::Dht(_) => f.write_str("Dht(PkLt(..))"),
            PanickedJob::SpentSave => f.write_str("SpentSave"),
        }
    }
}

impl core::fmt::Debug for DhtOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DhtOutcome")
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
    /// The conversation key schedule.
    ///
    /// `None` on the initiator's side until the correspondent replies: the
    /// initiator's ratchet opens from the provisional record on that reply,
    /// which is item 3. The entry exists before then so the pseudonym below is
    /// not the thing that gets lost in between.
    ratchet: Option<Ratchet>,
    /// Our per-contact pseudonym — what signs every frame we send here.
    // Item 3 signs with it; item 2's job is only to make sure the mint's copy
    // is not the one that gets dropped.
    #[allow(dead_code)]
    signing_pc: SignKeypair,
    /// The correspondent's pseudonym — what every frame they send is verified
    /// against.
    ///
    /// Known from the knock on the acceptor's side. `None` on the initiator's
    /// until the correspondent's first frame carries it, which is item 3.
    peer_pk_pc: Option<Box<[u8; IDENTITY_PK_LEN]>>,
}

impl core::fmt::Debug for Correspondence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `signing_pc` holds a secret key and both public halves name a person.
        f.debug_struct("Correspondence")
            .field("peer_pk_pc_known", &self.peer_pk_pc.is_some())
            .finish_non_exhaustive()
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
            correspondences: Vec::new(),
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
            // Items 3 and 4. The channel plane decides nothing yet.
            DmCommand::Send { .. } | DmCommand::Surfaced { .. } => Vec::new(),
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
    pub(crate) fn on_tick(&mut self, now_ms: i64) -> Vec<DmEffect> {
        self.last_tick_ms = Some(now_ms);
        vec![DmEffect::Dht(DhtOp::SweepDoorbell {
            tag: OpTag::none(),
            owner_seed: self.doorbell_owner,
        })]
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
                None => Vec::new(),
            },
            DmOutcome::Dht(DhtOutcome { tag, result }) => match result {
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
                    if let Some(recipient) = tag.introduction {
                        self.minting
                            .retain(|pk| pk.as_slice() != recipient.as_slice());
                    }
                    Vec::new()
                }
                // Items 3 and 4 read these.
                Ok(DhtResult::Page(_)) | Ok(DhtResult::Ack(_)) => Vec::new(),
            },
        }
    }

    /// When the shell should next wake the machine if nothing else happens.
    pub(crate) fn next_due_ms(&self, now_ms: i64) -> i64 {
        now_ms.saturating_add(duration_as_ms(self.cfg.idle_tick))
    }

    /// The wall time of the last tick this machine saw, if it has seen one.
    ///
    /// The shell reads it back onto its probe, so the value the machine recorded
    /// is the value an oracle asserts — a probe fed the shell's own `now` instead
    /// would pass whether or not the machine ever stored anything.
    pub(crate) fn last_tick_ms(&self) -> Option<i64> {
        self.last_tick_ms
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
        let peer_pk_pc = Box::new(*held.knock.pk_pc());

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
            Ok((_label, ratchet)) => {
                self.correspondences.push(Correspondence {
                    pk_lt,
                    ratchet: Some(ratchet),
                    signing_pc,
                    peer_pk_pc: Some(peer_pk_pc),
                });
                Vec::new()
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
        let _ = now_ms;
        // Our own pseudonym for this conversation is kept from here: it signs
        // every later frame, and nothing else holds it — see `Correspondence`
        // for the at-rest gap that leaves.
        if !self
            .correspondences
            .iter()
            .any(|c| c.pk_lt.as_slice() == recipient.as_slice())
        {
            self.correspondences.push(Correspondence {
                pk_lt: Box::new(*recipient),
                // The initiator's ratchet opens from the provisional record
                // when the correspondent replies, which is item 3.
                ratchet: None,
                signing_pc,
                // Learned from that reply, likewise item 3's.
                peer_pk_pc: None,
            });
        }
        // The recipient stays in `minting` until this write's outcome lands, so
        // a refused write is still attributable to the introduction that asked
        // for it. The knock's re-seed cadence — the geometric backoff and the
        // seven-day give-up — is item 4's, driven from the outbox.
        vec![DmEffect::Dht(DhtOp::PublishDoorbell {
            tag: OpTag::introduction(recipient),
            owner_seed,
            slot,
            entry,
            dispatch: DoorbellDispatch::FirstSend,
        })]
    }

    /// The label this recipient's provisional record belongs under.
    ///
    /// In-memory first; then the store, because a restart empties the map while
    /// the record survives; and only then a fresh mint. The store lookup asks
    /// [`DmPersist::restart_channel`] under this recipient's context at each
    /// live epoch — a record opens only under the context it was sealed with,
    /// so a record that opens IS this recipient's. A record older than the
    /// accept window will not open and a new label is minted, which is the
    /// bound this leaves: the give-up window is item 4's and is longer than the
    /// epoch window.
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
fn refused(recipient: &[u8; IDENTITY_PK_LEN], reason: RefusalReason) -> DmEvent {
    DmEvent::Refused {
        to: Box::new(*recipient),
        acceptance: daemonseed_core::dm::outbox::Acceptance::Unconfirmed,
        reason,
    }
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
}
