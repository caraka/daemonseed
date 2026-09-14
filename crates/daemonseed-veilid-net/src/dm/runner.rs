//! The direct-messaging runner: the long-running task that drives one
//! identity's conversations over a record store.
//!
//! Serves FC1, FC2 and FC4.
//!
//! [`spawn_runner`] starts one task on the caller's multi-thread tokio runtime.
//! The task owns one record store and one [`Store`], opened at
//! `<profile_root>/dm-store`, and calls [`daemonseed_core::dm::flows`] directly,
//! one call at a time. A front end reaches it only through [`RunnerHandle`]:
//! [`RunnerCommand`]s go in on a bounded queue, [`RunnerEvent`]s come out on
//! another, and a command is served between flow calls, never during one.
//!
//! ## Startup
//!
//! Once the store has loaded, the task reports the [`RunnerEvent::Roster`],
//! reopens every channel this side owns, restores or mints the advert keys and
//! repairs the advert, and scans the drop. Only then does it look at what a
//! previous run left: a first contact or an acceptance that stopped part way
//! is carried on, an outstanding hello is re-encapsulated where it is still
//! awaiting acceptance and rewritten where the network has lost it, and every
//! control subkey and outstanding message slot the network reports lost is
//! rewritten. The scan comes first because a hello the correspondent has
//! already accepted must be recognised, not re-encapsulated.
//!
//! ## Schedule
//!
//! - **Collection**, every [`RunnerConfig::tick`] jittered by ±20 %: the drop
//!   scan, every established conversation's ring, the correspondent's published
//!   cursor where messages are outstanding, and the delivery reports those
//!   produce.
//! - **Repair**, per conversation with anything outstanding, on § Delivery's
//!   interval (40 to 60 minutes, daily after seven days): the same look at
//!   what is left undone that startup takes, preceded by a drop scan for a
//!   conversation still awaiting acceptance.
//! - **Advert**, on § Write budget's 40 to 60 minute band: the weekly rotation,
//!   the advert keys reloaded from the store, so a reset's rotation is seen, and
//!   a rewrite where the network holds no number for the record, where this
//!   node's number and the network's differ, or where the bytes this node reads
//!   back are not the current key's advert. That read is served from this node's
//!   local copy, and the matching numbers are what tie that copy to the network.
//!   Each rewrite the network takes, and each poll whose numbers match and whose
//!   bytes are the current key's advert, is recorded as the published advert,
//!   which a later reset rotates past.
//!
//! The schedule reads [`tokio::time`], so a paused test clock drives it, and the
//! wall-clock time the flows and events see advances with it.
//!
//! ## What counts as lost
//!
//! Every repair decision comes from an inspect that reports, per subkey, this
//! node's sequence number beside the network's. A channel subkey, which only
//! its owner writes, is rewritten where the network holds nothing or holds an
//! older number. A drop slot or an advert, which anyone may write, is
//! rewritten where the two numbers differ at all, and an advert also where the
//! bytes this node reads back for it, which are its local copy, are not the
//! current key's advert. An outstanding hello is also
//! rewritten where this node's copy of its slot holds bytes other than the
//! hello the store holds. A subkey Veilid still has queued for its flush is
//! never rewritten.
//!
//! A network number that is absent from a report that came back is an
//! eviction, even when every subkey's is absent: Veilid builds the report with
//! no network numbers whenever its fanout gathered no copy of the record
//! (`veilid-core-0.5.7 src/storage_manager/inspect_record.rs:257-262`), which
//! is what a record every reached node has dropped looks like. A node that could
//! not ask the network gets no report at all: an inspect issued while it is not
//! online is refused with `TryAgain`
//! (`src/storage_manager/inspect_record.rs:205-206`), and a fanout that ran out
//! of time surfaces as an error of the read that carried it. The report itself
//! carries no count of the nodes it reached
//! (`src/veilid_api/types/dht/dht_record_report.rs:13-23`), so the error is the
//! only signal that the network was not asked: such an inspect writes nothing,
//! and its record kind's inspect counter counts it, the `_timeouts` one where
//! [`RunnerRecords::classify`] says the call ran out of time and the
//! `_failures` one where it was refused.
//!
//! A report with no network number on any subkey is also what a node that is
//! attached but whose routing table is not yet warm gets, because its fanout
//! reaches nothing that holds the record. So a whole record is taken as
//! dropped only when the same pass shows the network answering: this node's own
//! advert, which it publishes and keeps, is inspected once in the pass, and
//! only if it shows a network number is the record rewritten. Otherwise the
//! pass writes nothing for that record, and
//! [`HealthCounters::network_not_answering`] counts it.
//!
//! ## What a front end sees
//!
//! A hello from an unknown identity becomes a [`RunnerEvent::ContactRequest`]
//! and one from an established correspondent a [`RunnerEvent::StartedOver`],
//! each under a [`ContactRequestId`] that names this run as well as the hello,
//! so an id from an earlier run is refused. The verified request behind an id
//! is held in memory and replaced on every complete scan. A blocked sender's
//! hello and a rewrite of a hello already collected only move a
//! [`HealthCounters`] field, and so does a verified hello the scan could not
//! settle. A message's sequence number is derived from the collection cursor
//! and its `received_at` is stamped here: nothing is added to the wire. Every
//! command that carries a [`CommandToken`] is answered by an event carrying it.
//!
//! ## Stopping
//!
//! [`RunnerHandle::shutdown`] asks the task to stop, keeps reading its events
//! while it finishes the flow call in progress, and waits at most
//! [`RunnerConfig::grace`]. It returns every event not yet read and answers
//! every command still queued. Once stop is asked for, the task starts no flow
//! call that writes.
//!
//! A flow call still running when the grace period ends is not interrupted.
//! It may still save a collection cursor or an acceptance to the store, and
//! the bodies that collection read exist nowhere else: they reach the caller
//! only through the [`TaskEnd`] in [`ShutdownOutcome::TimedOut`], and are lost
//! if that [`TaskEnd`] is dropped unfinished. The task holds the store open
//! until it ends, so the same profile must not be opened again, by a runner or
//! anything else, until [`TaskEnd::finish`] has returned or
//! [`TaskEnd::is_finished`] reads true. Anything the call left pending is
//! resumed by the next startup.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use daemonseed_core::dm::advert::{
    self, AdvertAction, AdvertError, AdvertKeys, AdvertOwnerSeed, InspectReport,
};
use daemonseed_core::dm::block_list::{BlockList, BlockListError};
use daemonseed_core::dm::channel::{self, ChannelError, ChannelOpening, ChannelOwnerSeed, Control};
use daemonseed_core::dm::delivery::{self, ClosedMarker};
use daemonseed_core::dm::drop::{self as drop_plane, DropOwnerSeed, HELLO_LOOKUP_KEY_LEN};
use daemonseed_core::dm::flows::{
    self, FirstContact, FlowError, Me, RecordError, Records, Surfaced,
};
use daemonseed_core::dm::store::{
    ConvState, LoadedConv, OutboxEntry, OutstandingHello, Store, StoreError,
};
use daemonseed_core::identity::keys::{DmChannelRootSecret, SignKeypair, IDENTITY_PK_LEN};
use daemonseed_core::storage::dm_store::{CorrespondenceLabel, DmStoreError, RecordKind};
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::dm::records::WriteCountsSnapshot;

/// How often collection runs, before jitter.
pub const DEFAULT_TICK: Duration = Duration::from_secs(60);

/// How long [`RunnerHandle::shutdown`] waits for the flow call in progress.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(10);

/// Capacity of the command queue.
pub const COMMAND_QUEUE: usize = 64;

/// Capacity of the event queue.
pub const EVENT_QUEUE: usize = 256;

/// The directory under the profile root the runner's [`Store`] lives in.
pub const STORE_DIR: &str = "dm-store";

/// How far either side of [`RunnerConfig::tick`] a collection may land, in
/// percent.
const TICK_JITTER_PERCENT: u128 = 20;

/// The lookup key a conversation record holds before its channel is opened.
const NO_LOOKUP_KEY: [u8; HELLO_LOOKUP_KEY_LEN] = [0u8; HELLO_LOOKUP_KEY_LEN];

/// An identity's long-term public key.
pub type IdentityPk = Box<[u8; IDENTITY_PK_LEN]>;

/// One subkey of an inspected record: this node's sequence number, the
/// network's, and whether Veilid still has the subkey queued for its flush.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SubkeyReport {
    /// The sequence number of this node's copy.
    pub local_seq: Option<u64>,
    /// The sequence number the network holds, as if this node's copy did not
    /// exist.
    pub network_seq: Option<u64>,
    /// Whether the subkey is still queued to leave this node.
    pub pending: bool,
}

/// The record store a runner drives: the flows' seven reads and writes, plus
/// what the schedule needs that no flow performs.
pub trait RunnerRecords: Records {
    /// Every subkey of the channel at `lookup_key`, indexed by subkey.
    fn inspect_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Result<Vec<SubkeyReport>, RecordError>;

    /// Every subkey of the advert record the seed owns, indexed by subkey.
    fn inspect_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> Result<Vec<SubkeyReport>, RecordError>;

    /// Every slot of the drop the seed owns, indexed by slot.
    fn inspect_drop(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
    ) -> Result<Vec<SubkeyReport>, RecordError>;

    /// Write `bytes` to subkey 0 of the advert record the seed owns. One write.
    fn publish_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError>;

    /// Erase a channel record this side owns.
    fn erase_channel(&mut self, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN])
        -> Result<(), RecordError>;

    /// How many writes of each kind this store has submitted.
    fn write_counts(&self) -> WriteCountsSnapshot;

    /// How a failed call failed, which decides the [`HealthCounters`] field it
    /// is counted in. A store that cannot tell reports every failure as
    /// [`RecordFailure::Refused`].
    fn classify(error: &RecordError) -> RecordFailure {
        let _ = error;
        RecordFailure::Refused
    }

    /// The failure of the drop inspect a scan takes before its first slot read,
    /// if one failed since this was last asked. The slot read goes on without
    /// the scan and reads every slot, so the failure is not the read's; the
    /// runner counts it under the drop inspect counters. A store that takes no
    /// such inspect has none.
    fn take_scan_failure(&mut self) -> Option<RecordError> {
        None
    }

    /// Whether a scan's failure and the failure of the slot read after it, both
    /// [`RecordFailure::Local`], are the same local refusal, which is counted
    /// once. A store that cannot tell answers `false`, and both are counted.
    fn same_local_refusal(scan: &RecordError, read: &RecordError) -> bool {
        let _ = (scan, read);
        false
    }
}

/// How a failed record store call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFailure {
    /// The network or the transport refused the call.
    Refused,
    /// The call ran out of time.
    TimedOut,
    /// The call was refused before it reached the network: a write or an
    /// erasure of a channel this process has not opened, a record address or
    /// owner key that would not derive, a runtime the store cannot use, a record
    /// a write's confirmation finds this node no longer holds, a write the
    /// store's scheduler never took, or a call the transport refused before
    /// sending it. Counted in [`HealthCounters::local_refusals`] and under no
    /// record call's counter.
    Local,
}

/// How a runner paces itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerConfig {
    /// The collection interval, before ±20 % jitter.
    pub tick: Duration,
    /// How long a shutdown waits for the flow call in progress.
    pub grace: Duration,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            tick: DEFAULT_TICK,
            grace: DEFAULT_GRACE,
        }
    }
}

/// The shortest collection interval a runner uses; a shorter one is raised to it.
pub const MIN_TICK: Duration = Duration::from_millis(1);

/// The longest collection interval a runner uses; a longer one is lowered to it.
pub const MAX_TICK: Duration = Duration::from_secs(24 * 60 * 60);

impl RunnerConfig {
    /// This configuration with its tick held within [`MIN_TICK`]..=[`MAX_TICK`],
    /// as [`spawn_runner`] applies it.
    pub fn clamped(self) -> Self {
        Self {
            tick: self.tick.clamp(MIN_TICK, MAX_TICK),
            grace: self.grace,
        }
    }
}

/// Everything [`spawn_runner`] needs.
pub struct RunnerParts<R> {
    /// The record store the flows run over.
    pub records: R,
    /// The identity signing keypair.
    pub signer: Arc<SignKeypair>,
    /// The identity's channel root secret, moved in.
    pub channel_root: DmChannelRootSecret,
    /// The profile's at-rest key, which seals the store.
    pub at_rest_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// The profile directory; the store opens at [`STORE_DIR`] beneath it.
    pub profile_root: PathBuf,
    /// The schedule.
    pub config: RunnerConfig,
}

/// A caller-chosen value echoed on the event that answers a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandToken(pub u64);

/// The id a runner gives a surfaced hello: a value drawn once per run, and a
/// serial within the run.
///
/// No code outside the runner can make one unless the crate's `test-support`
/// feature is on, which it is not by default:
#[cfg_attr(
    not(feature = "test-support"),
    doc = "```compile_fail\nlet _ = daemonseed_veilid_net::dm::runner::ContactRequestId::for_test(1, 2);\n```"
)]
#[cfg_attr(
    feature = "test-support",
    doc = "with it on, [`ContactRequestId::for_test`] makes one."
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContactRequestId {
    epoch: u64,
    serial: u64,
}

impl ContactRequestId {
    /// An id made from its two parts, the value drawn for a run and the serial
    /// within that run, for a front end's own tests to build the events a runner
    /// sends.
    ///
    /// Only with the `test-support` feature, which is off by default. Without it
    /// no code outside the runner can make an id, so an accept can only name a
    /// request a runner surfaced.
    #[cfg_attr(
        feature = "test-support",
        doc = "```\nuse daemonseed_veilid_net::dm::runner::ContactRequestId;\n\nassert_eq!(ContactRequestId::for_test(1, 2), ContactRequestId::for_test(1, 2));\nassert_ne!(ContactRequestId::for_test(1, 2), ContactRequestId::for_test(1, 3));\n```"
    )]
    #[cfg(feature = "test-support")]
    pub fn for_test(epoch: u64, serial: u64) -> Self {
        Self { epoch, serial }
    }
}

/// What a front end asks a runner to do.
pub enum RunnerCommand {
    /// Open a conversation with the identity `peer_identity_pk`, carrying
    /// `body` as its first message.
    FirstContact {
        /// Echoed on the answer.
        token: CommandToken,
        /// The correspondent's identity public key.
        peer_identity_pk: IdentityPk,
        /// The first message.
        body: Vec<u8>,
    },
    /// Send `body` on an established conversation.
    Send {
        /// Echoed on the answer.
        token: CommandToken,
        /// The conversation.
        peer: CorrespondenceLabel,
        /// The message.
        body: Vec<u8>,
    },
    /// Accept a surfaced contact request, replying with `reply`.
    Accept {
        /// Echoed on the answer.
        token: CommandToken,
        /// The request, as [`RunnerEvent::ContactRequest`] named it.
        request: ContactRequestId,
        /// The first message of this side's direction. Required.
        reply: Vec<u8>,
    },
    /// Block an identity: its hellos are dropped and its conversation is no
    /// longer read.
    Block {
        /// The identity public key to block.
        peer: IdentityPk,
    },
    /// Remove an identity from the block list.
    Unblock {
        /// The identity public key to unblock.
        peer: IdentityPk,
    },
    /// Delete a conversation: write the closed marker, erase this side's
    /// channel and drop the local records.
    DeleteConversation {
        /// Echoed on the answer.
        token: CommandToken,
        /// The conversation.
        peer: CorrespondenceLabel,
    },
    /// Stop the runner.
    Shutdown,
}

impl RunnerCommand {
    /// The token the command's answer carries, where it has one.
    fn token(&self) -> Option<CommandToken> {
        match self {
            Self::FirstContact { token, .. }
            | Self::Send { token, .. }
            | Self::Accept { token, .. }
            | Self::DeleteConversation { token, .. } => Some(*token),
            Self::Block { .. } | Self::Unblock { .. } | Self::Shutdown => None,
        }
    }
}

impl core::fmt::Debug for RunnerCommand {
    /// Names the command and its token; bodies and keys are left out.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FirstContact { token, .. } => write!(f, "FirstContact({token:?})"),
            Self::Send { token, .. } => write!(f, "Send({token:?})"),
            Self::Accept { token, request, .. } => write!(f, "Accept({token:?}, {request:?})"),
            Self::Block { .. } => f.write_str("Block"),
            Self::Unblock { .. } => f.write_str("Unblock"),
            Self::DeleteConversation { token, .. } => write!(f, "DeleteConversation({token:?})"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

/// Whether a conversation's own first contact has been accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationState {
    /// This side's first contact is awaiting acceptance, or this side's
    /// acceptance of the correspondent's has not finished.
    Pending,
    /// Both directions are open.
    Established,
}

/// One conversation as a roster lists it.
pub struct ConversationSummary {
    /// The conversation.
    pub peer: CorrespondenceLabel,
    /// The correspondent's identity public key.
    pub peer_identity_pk: IdentityPk,
    /// Pending or established.
    pub state: ConversationState,
    /// The correspondent's cursor over this side's messages: every sequence
    /// below it has been collected.
    pub peer_collected: u64,
    /// How many of this side's messages the correspondent has not collected.
    pub uncollected: u64,
}

impl core::fmt::Debug for ConversationSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConversationSummary")
            .field("peer", &self.peer)
            .field("state", &self.state)
            .field("peer_collected", &self.peer_collected)
            .field("uncollected", &self.uncollected)
            .finish_non_exhaustive()
    }
}

/// Why a command did not go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No conversation under that label.
    UnknownConversation,
    /// No held request under that id in this run.
    UnknownRequest,
    /// The request is a correspondent starting over, which cannot be accepted.
    StartedOverNotAcceptable,
    /// 63 messages are uncollected; send again once the correspondent's cursor
    /// advances.
    RingFull,
    /// This side's first contact has not been accepted yet.
    AwaitingAcceptance,
    /// This side's acceptance of the correspondent's first contact has not
    /// finished; the repair poll carries it on.
    AcceptanceUnfinished,
    /// A conversation with that identity is already established.
    AlreadyEstablished,
    /// The correspondent publishes no advert.
    NoAdvert,
    /// Every drop slot the hello picked was taken; the repair poll retries.
    DropFull,
    /// The block list holds its maximum number of identities.
    BlockListFull,
    /// The local store refused.
    Store,
    /// The record store refused.
    Network,
    /// A flow refused for a reason not named above.
    Flow,
    /// The runner stopped before serving the command.
    ShuttingDown,
}

/// Named failure and drop counters, since the runner started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HealthCounters {
    /// Advert reads that failed for a reason other than running out of time.
    pub advert_read_failures: u64,
    /// Advert reads that ran out of time.
    pub advert_read_timeouts: u64,
    /// Advert inspects that failed for a reason other than running out of time.
    pub advert_inspect_failures: u64,
    /// Advert inspects that ran out of time.
    pub advert_inspect_timeouts: u64,
    /// Advert writes that failed for a reason other than running out of time.
    pub advert_write_failures: u64,
    /// Advert writes that ran out of time.
    pub advert_write_timeouts: u64,
    /// Advert keys that would not derive, sign or decide a poll.
    pub advert_failures: u64,
    /// Records whose report held no network number on any subkey in a pass
    /// where this node's own advert showed none either, or where the inspect of
    /// that advert failed, so nothing was rewritten. A failed inspect is also
    /// counted under its own advert inspect counter.
    pub network_not_answering: u64,
    /// Drop slot reads that failed for a reason other than running out of time.
    pub drop_read_failures: u64,
    /// Drop slot reads that ran out of time.
    pub drop_read_timeouts: u64,
    /// Drop slot writes and erasures that failed for a reason other than
    /// running out of time.
    pub drop_write_failures: u64,
    /// Drop slot writes and erasures that ran out of time.
    pub drop_write_timeouts: u64,
    /// Drop inspects that failed for a reason other than running out of time,
    /// including the one a scan takes before its first slot read.
    pub drop_inspect_failures: u64,
    /// Drop inspects that ran out of time, including the one a scan takes
    /// before its first slot read.
    pub drop_inspect_timeouts: u64,
    /// Channel opens that failed for a reason other than running out of time,
    /// or reopened a record other than the stored one.
    pub channel_open_failures: u64,
    /// Channel opens that ran out of time.
    pub channel_open_timeouts: u64,
    /// Channel subkey reads that failed for a reason other than running out of
    /// time.
    pub channel_read_failures: u64,
    /// Channel subkey reads that ran out of time.
    pub channel_read_timeouts: u64,
    /// Channel inspects that failed for a reason other than running out of time.
    pub channel_inspect_failures: u64,
    /// Channel inspects that ran out of time.
    pub channel_inspect_timeouts: u64,
    /// Channel subkey writes that failed for a reason other than running out of
    /// time.
    pub channel_write_failures: u64,
    /// Channel subkey writes that ran out of time.
    pub channel_write_timeouts: u64,
    /// Channel erasures that failed for a reason other than running out of time.
    pub channel_erase_failures: u64,
    /// Channel erasures that ran out of time.
    pub channel_erase_timeouts: u64,
    /// Record store calls refused before they reached the network, as
    /// [`RecordFailure::Local`] lists them. None is counted under a record
    /// call's own counter.
    pub local_refusals: u64,
    /// Hellos from a blocked identity, dropped.
    pub hellos_dropped: u64,
    /// Rewrites of a hello already collected, erased.
    pub hellos_already_collected: u64,
    /// Verified hellos a scan could not settle.
    pub hellos_unsettled: u64,
    /// Flow calls on a conversation that failed for a reason other than the
    /// record store or the local store.
    pub conversation_failures: u64,
    /// Local store and block list operations the schedule could not complete.
    pub store_failures: u64,
    /// Held requests dropped, oldest-seen first, to keep at most one per drop
    /// slot.
    pub requests_evicted: u64,
}

/// What a runner reports.
pub enum RunnerEvent {
    /// Every conversation, at startup and whenever the set or a state changes.
    Roster(Vec<ConversationSummary>),
    /// A hello from an unknown identity, awaiting [`RunnerCommand::Accept`].
    ContactRequest {
        /// The id to accept it under.
        request: ContactRequestId,
        /// The identity that signed its channel opening.
        from: IdentityPk,
    },
    /// A new hello from an established correspondent.
    StartedOver {
        /// The id it is held under.
        request: ContactRequestId,
        /// The identity that signed its channel opening.
        from: IdentityPk,
    },
    /// A collected message.
    Message {
        /// The conversation.
        from: CorrespondenceLabel,
        /// Its sequence number in the correspondent's direction.
        seq: u64,
        /// The opened body.
        body: Vec<u8>,
        /// When this runner collected it, in Unix milliseconds.
        received_at: u64,
    },
    /// A message of this side's own reached the local store and its slot.
    Sent {
        /// The token of the command that sent it.
        token: CommandToken,
        /// The conversation.
        peer: CorrespondenceLabel,
        /// Its sequence number.
        seq: u64,
    },
    /// A conversation was deleted.
    Deleted {
        /// The token of the command that deleted it.
        token: CommandToken,
        /// The conversation.
        peer: CorrespondenceLabel,
    },
    /// The correspondent has collected every message of this side's up to and
    /// including `through_seq`.
    Delivered {
        /// The conversation.
        peer: CorrespondenceLabel,
        /// The highest sequence collected.
        through_seq: u64,
    },
    /// This side's own first contact was accepted.
    Accepted {
        /// The conversation.
        peer: CorrespondenceLabel,
    },
    /// A command did not go.
    Refused {
        /// The command's token; `None` for a block or unblock.
        token: Option<CommandToken>,
        /// Why.
        reason: Refusal,
    },
    /// The counters, once at startup and then when they change.
    Health(HealthCounters),
}

impl core::fmt::Debug for RunnerEvent {
    /// Names the event and its numbers; bodies and keys are left out.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Roster(rows) => f.debug_tuple("Roster").field(rows).finish(),
            Self::ContactRequest { request, .. } => write!(f, "ContactRequest({request:?})"),
            Self::StartedOver { request, .. } => write!(f, "StartedOver({request:?})"),
            Self::Message { from, seq, .. } => write!(f, "Message({from:?}, {seq})"),
            Self::Sent { token, peer, seq } => write!(f, "Sent({token:?}, {peer:?}, {seq})"),
            Self::Deleted { token, peer } => write!(f, "Deleted({token:?}, {peer:?})"),
            Self::Delivered { peer, through_seq } => {
                write!(f, "Delivered({peer:?}, {through_seq})")
            }
            Self::Accepted { peer } => write!(f, "Accepted({peer:?})"),
            Self::Refused { token, reason } => write!(f, "Refused({token:?}, {reason:?})"),
            Self::Health(counters) => f.debug_tuple("Health").field(counters).finish(),
        }
    }
}

/// Why a runner stopped at startup.
#[derive(Debug)]
pub enum RunnerError {
    /// The store would not open, load or persist.
    Store(StoreError),
    /// The advert keys would not mint.
    Advert(AdvertError),
}

impl core::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "direct-message store: {e}"),
            Self::Advert(e) => write!(f, "advert keys: {e}"),
        }
    }
}

impl core::error::Error for RunnerError {}

/// How the task ended during a [`RunnerHandle::shutdown`].
#[derive(Debug)]
pub enum ShutdownOutcome {
    /// The task returned within the grace period.
    Finished(Result<(), RunnerError>),
    /// The task panicked.
    Panicked,
    /// The grace period ran out with a flow call still in progress. The call
    /// was not interrupted; the [`TaskEnd`] reports when the task has ended
    /// and hands back what it emits until then.
    TimedOut(TaskEnd),
}

/// What [`RunnerHandle::shutdown`] returns: how the task ended, and every event
/// it emitted that had not been read.
#[derive(Debug)]
pub struct RunnerStop {
    /// How the task ended.
    pub outcome: ShutdownOutcome,
    /// The events not read before the shutdown, in the order they were emitted,
    /// followed by a [`RunnerEvent::Refused`] for every command still queued.
    pub undelivered: Vec<RunnerEvent>,
}

/// A runner task still inside a flow call when its shutdown's grace period
/// ended.
///
/// The call finishes on its own. Until the task has ended it holds the store
/// open, so the profile must not be opened again before [`Self::finish`]
/// returns or [`Self::is_finished`] reads true. Dropping this value drops the
/// task's event stream: the task then ends at its next event, and the bodies of
/// a collection the call completed are lost.
pub struct TaskEnd {
    task: JoinHandle<Result<(), RunnerError>>,
    events: mpsc::Receiver<RunnerEvent>,
}

impl core::fmt::Debug for TaskEnd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskEnd")
            .field("finished", &self.task.is_finished())
            .finish_non_exhaustive()
    }
}

impl TaskEnd {
    /// Whether the task has ended.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Wait for the task to end, reading its events meanwhile, and return how
    /// it ended with every event it emitted after the shutdown returned.
    pub async fn finish(mut self) -> RunnerStop {
        let mut undelivered = Vec::new();
        let outcome = loop {
            tokio::select! {
                biased;
                Some(event) = self.events.recv() => undelivered.push(event),
                joined = &mut self.task => break match joined {
                    Ok(result) => ShutdownOutcome::Finished(result),
                    Err(_) => ShutdownOutcome::Panicked,
                },
            }
        };
        while let Ok(event) = self.events.try_recv() {
            undelivered.push(event);
        }
        RunnerStop {
            outcome,
            undelivered,
        }
    }
}

/// The command queue's receiving end, shared between the task and its handle.
///
/// The task holds the lock only while it waits for its next wake, so a handle
/// whose shutdown timed out, with the task inside a flow call, can take it and
/// answer what is still queued.
type CommandQueue = Arc<tokio::sync::Mutex<mpsc::Receiver<RunnerCommand>>>;

/// A running runner: its command queue, its event stream, and its task.
///
/// Dropping the handle stops the runner after the flow call in progress and
/// discards every event not yet read; [`Self::shutdown`] returns them instead.
pub struct RunnerHandle {
    commands: mpsc::Sender<RunnerCommand>,
    queued: CommandQueue,
    events: mpsc::Receiver<RunnerEvent>,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<Result<(), RunnerError>>>,
    grace: Duration,
}

impl core::fmt::Debug for RunnerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RunnerHandle")
            .field("grace", &self.grace)
            .finish_non_exhaustive()
    }
}

impl RunnerHandle {
    /// A sender for the command queue.
    pub fn commands(&self) -> mpsc::Sender<RunnerCommand> {
        self.commands.clone()
    }

    /// Queue a command, waiting for room. Gives the command back where the
    /// runner has stopped.
    pub async fn send(&self, command: RunnerCommand) -> Result<(), RunnerCommand> {
        self.commands.send(command).await.map_err(|e| e.0)
    }

    /// The next event, or `None` once the runner has stopped and every event
    /// has been read.
    pub async fn next_event(&mut self) -> Option<RunnerEvent> {
        self.events.recv().await
    }

    /// The next event if one is waiting.
    pub fn try_next_event(&mut self) -> Option<RunnerEvent> {
        self.events.try_recv().ok()
    }

    /// Stop the runner, waiting at most the configured grace period, and return
    /// every event it emitted that had not been read.
    ///
    /// Once this is called the task starts no flow call that writes, and every
    /// command still queued is answered with [`Refusal::ShuttingDown`]: by the
    /// task where it ends within the grace period, and here where it does not.
    /// Events are read while the task finishes, so a collection already in
    /// progress delivers its messages.
    ///
    /// A flow call still running when the grace period ends is not interrupted,
    /// and the outcome is [`ShutdownOutcome::TimedOut`] with a [`TaskEnd`]. That
    /// call may still save a collection cursor or an acceptance. The bodies it
    /// read reach the caller only through [`TaskEnd::finish`] and are lost if the
    /// [`TaskEnd`] is dropped. The task holds the store open until it ends, so
    /// the same profile must not be opened again before [`TaskEnd::finish`]
    /// returns or [`TaskEnd::is_finished`] reads true.
    pub async fn shutdown(mut self) -> RunnerStop {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.commands.try_send(RunnerCommand::Shutdown);
        let deadline = Instant::now() + self.grace;
        let mut undelivered = Vec::new();
        let Some(mut task) = self.task.take() else {
            return RunnerStop {
                outcome: ShutdownOutcome::Finished(Ok(())),
                undelivered,
            };
        };
        let timed_out = loop {
            tokio::select! {
                biased;
                Some(event) = self.events.recv() => undelivered.push(event),
                joined = &mut task => break Err(match joined {
                    Ok(result) => ShutdownOutcome::Finished(result),
                    Err(_) => ShutdownOutcome::Panicked,
                }),
                () = tokio::time::sleep_until(deadline) => break Ok(()),
            }
        };
        while let Ok(event) = self.events.try_recv() {
            undelivered.push(event);
        }
        let outcome = match timed_out {
            Err(ended) => ended,
            Ok(()) => {
                // The task is inside a flow call and not waiting on its queue,
                // so the queue is free to answer here.
                if let Ok(mut queue) = self.queued.try_lock() {
                    queue.close();
                    while let Ok(command) = queue.try_recv() {
                        if let Some(token) = command.token() {
                            undelivered.push(RunnerEvent::Refused {
                                token: Some(token),
                                reason: Refusal::ShuttingDown,
                            });
                        }
                    }
                }
                let (_, closed) = mpsc::channel(1);
                let events = std::mem::replace(&mut self.events, closed);
                ShutdownOutcome::TimedOut(TaskEnd { task, events })
            }
        };
        RunnerStop {
            outcome,
            undelivered,
        }
    }
}

impl Drop for RunnerHandle {
    /// A dropped handle stops the runner after the flow call in progress.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Start a runner on the current tokio runtime.
///
/// With [`crate::dm::VeilidRecords`] the runtime must be multi-thread, because
/// every record store call blocks a worker.
pub fn spawn_runner<R>(parts: RunnerParts<R>) -> RunnerHandle
where
    R: RunnerRecords + Send + 'static,
{
    let mut parts = parts;
    parts.config = parts.config.clamped();
    let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE);
    let queued: CommandQueue = Arc::new(tokio::sync::Mutex::new(command_rx));
    let (event_tx, events) = mpsc::channel(EVENT_QUEUE);
    let stop = Arc::new(AtomicBool::new(false));
    let grace = parts.config.grace;
    let task = tokio::spawn(run(parts, Arc::clone(&queued), event_tx, Arc::clone(&stop)));
    RunnerHandle {
        commands,
        queued,
        events,
        stop,
        task: Some(task),
        grace,
    }
}

/// What woke the task.
enum Wake {
    /// A command arrived, or the queue closed.
    Command(Option<RunnerCommand>),
    /// Something on the schedule is due.
    Due,
}

/// Why the task stops before its loop would.
enum Halt {
    /// A startup failure.
    Error(RunnerError),
    /// Asked to stop, or nobody reads the events any more.
    Stopped,
}

impl From<StoreError> for Halt {
    fn from(e: StoreError) -> Self {
        Self::Error(RunnerError::Store(e))
    }
}

impl From<AdvertError> for Halt {
    fn from(e: AdvertError) -> Self {
        Self::Error(RunnerError::Advert(e))
    }
}

/// The task body: startup, then commands and the schedule until stopped, then
/// an answer for every command still queued.
async fn run<R: RunnerRecords>(
    parts: RunnerParts<R>,
    commands: CommandQueue,
    events: mpsc::Sender<RunnerEvent>,
    stop: Arc<AtomicBool>,
) -> Result<(), RunnerError> {
    let mut runner = match Runner::start(parts, events, stop).await {
        Ok(runner) => runner,
        Err(Halt::Error(e)) => {
            runner_refuse_unstarted(&commands).await;
            return Err(e);
        }
        Err(Halt::Stopped) => return Ok(()),
    };
    let result = loop {
        if runner.stopping() {
            break Ok(());
        }
        let due = runner.next_due();
        let wake = {
            let mut queue = commands.lock().await;
            tokio::select! {
                biased;
                command = queue.recv() => Wake::Command(command),
                () = tokio::time::sleep_until(due) => Wake::Due,
            }
        };
        let step = match wake {
            Wake::Command(None | Some(RunnerCommand::Shutdown)) => Err(Halt::Stopped),
            Wake::Command(Some(command)) => match runner.serve(command).await {
                Ok(()) => runner.report_health().await,
                halted => halted,
            },
            Wake::Due => runner.run_due().await,
        };
        match step {
            Ok(()) => {}
            Err(Halt::Error(e)) => break Err(e),
            Err(Halt::Stopped) => break Ok(()),
        }
    };
    // A counter the last command or pass moved is reported before the queue is
    // answered, however the loop ended. A closed event stream has no reader to
    // report to.
    let _ = runner.report_health().await;
    runner.refuse_queued(&commands).await;
    result
}

/// Close the queue of a runner whose startup failed. Its handle sees every
/// later send refused, and the event stream closes as the task returns.
async fn runner_refuse_unstarted(commands: &CommandQueue) {
    commands.lock().await.close();
}

/// A held, surfaced hello.
enum Held {
    /// A contact request, with what [`flows::accept`] proceeds from.
    Request(flows::ContactRequest),
    /// A correspondent starting over.
    StartedOver(IdentityPk),
}

impl Held {
    fn identity(&self) -> &[u8; IDENTITY_PK_LEN] {
        match self {
            Self::Request(request) => &request.identity,
            Self::StartedOver(identity) => identity,
        }
    }
}

/// A surfaced hello held under its id, with the scan that last saw it.
struct HeldRequest {
    held: Held,
    seen: u64,
}

/// Keep at most `cap` held requests, dropping the ones seen longest ago, and
/// say how many were dropped.
fn retain_newest(requests: &mut BTreeMap<ContactRequestId, HeldRequest>, cap: usize) -> u64 {
    let over = requests.len().saturating_sub(cap);
    if over == 0 {
        return 0;
    }
    let mut order: Vec<(u64, ContactRequestId)> = requests
        .iter()
        .map(|(id, entry)| (entry.seen, *id))
        .collect();
    order.sort_unstable();
    for (_, id) in order.into_iter().take(over) {
        requests.remove(&id);
    }
    u64::try_from(over).unwrap_or(u64::MAX)
}

/// When a conversation's outstanding records are next looked at.
struct Repair {
    /// When the conversation was first seen with something outstanding, in
    /// Unix seconds.
    since_secs: u64,
    /// When the next look is due.
    due: Instant,
}

/// Wall-clock time that advances with [`tokio::time`].
struct Clock {
    wall_ms: u64,
    started: Instant,
}

impl Clock {
    fn start() -> Self {
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            wall_ms,
            started: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.wall_ms.saturating_add(elapsed)
    }

    fn now_secs(&self) -> u64 {
        self.now_ms() / 1000
    }
}

/// A record store whose every failure moves a [`HealthCounters`] field.
struct Tracked<R> {
    inner: R,
    health: HealthCounters,
    /// Drop slot reads that failed, however they failed, since the runner
    /// started. A scan during which this rose left a slot unread, so it is
    /// partial and must not drop the requests it did not see. The drop inspect a
    /// scan takes is not a slot read and is not counted here: a scan whose
    /// inspect failed reads every slot.
    failed_drop_reads: u64,
}

/// `result`, having counted it if it failed, as `classify` says it failed:
/// against `failures` where it was refused, against `timeouts` where it ran out
/// of time, and against [`HealthCounters::local_refusals`] where it never
/// reached the network.
fn tally<T>(
    result: Result<T, RecordError>,
    classify: fn(&RecordError) -> RecordFailure,
    health: &mut HealthCounters,
    failures: fn(&mut HealthCounters) -> &mut u64,
    timeouts: fn(&mut HealthCounters) -> &mut u64,
) -> Result<T, RecordError> {
    if let Err(error) = &result {
        match classify(error) {
            RecordFailure::Refused => *failures(health) += 1,
            RecordFailure::TimedOut => *timeouts(health) += 1,
            RecordFailure::Local => health.local_refusals += 1,
        }
    }
    result
}

impl<R: RunnerRecords> Records for Tracked<R> {
    fn read_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        let result = self.inner.read_advert(owner, subkeys);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.advert_read_failures,
            |h| &mut h.advert_read_timeouts,
        )
    }

    fn read_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        let result = self.inner.read_drop_slot(owner, subkeys, slot);
        if result.is_err() {
            self.failed_drop_reads += 1;
        }
        if let Some(scan) = self.inner.take_scan_failure() {
            // A scan refused locally is followed by its read refusing for the
            // same local reason: that is one refusal, counted with the read.
            let one_local_refusal = R::classify(&scan) == RecordFailure::Local
                && matches!(&result, Err(read) if R::classify(read) == RecordFailure::Local
                    && R::same_local_refusal(&scan, read));
            if !one_local_refusal {
                let _ = tally::<()>(
                    Err(scan),
                    R::classify,
                    &mut self.health,
                    |h| &mut h.drop_inspect_failures,
                    |h| &mut h.drop_inspect_timeouts,
                );
            }
        }
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.drop_read_failures,
            |h| &mut h.drop_read_timeouts,
        )
    }

    fn write_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        let result = self.inner.write_drop_slot(owner, subkeys, slot, bytes);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.drop_write_failures,
            |h| &mut h.drop_write_timeouts,
        )
    }

    fn erase_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<(), RecordError> {
        let result = self.inner.erase_drop_slot(owner, subkeys, slot);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.drop_write_failures,
            |h| &mut h.drop_write_timeouts,
        )
    }

    fn open_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        subkeys: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        let result = self.inner.open_channel(owner, subkeys);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.channel_open_failures,
            |h| &mut h.channel_open_timeouts,
        )
    }

    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        let result = self.inner.read_channel(lookup_key, subkey);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.channel_read_failures,
            |h| &mut h.channel_read_timeouts,
        )
    }

    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        let result = self.inner.write_channel(lookup_key, subkey, bytes);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.channel_write_failures,
            |h| &mut h.channel_write_timeouts,
        )
    }
}

impl<R: RunnerRecords> Tracked<R> {
    fn inspect_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Result<Vec<SubkeyReport>, RecordError> {
        let result = self.inner.inspect_channel(lookup_key);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.channel_inspect_failures,
            |h| &mut h.channel_inspect_timeouts,
        )
    }

    fn inspect_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
    ) -> Result<Vec<SubkeyReport>, RecordError> {
        let result = self.inner.inspect_advert(owner, advert::ADVERT_SUBKEYS);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.advert_inspect_failures,
            |h| &mut h.advert_inspect_timeouts,
        )
    }

    fn inspect_drop(&mut self, owner: &DropOwnerSeed) -> Result<Vec<SubkeyReport>, RecordError> {
        let result = self.inner.inspect_drop(owner, drop_plane::DROP_SUBKEYS);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.drop_inspect_failures,
            |h| &mut h.drop_inspect_timeouts,
        )
    }

    fn publish_advert(&mut self, owner: &AdvertOwnerSeed, bytes: &[u8]) -> Result<(), RecordError> {
        let result = self
            .inner
            .publish_advert(owner, advert::ADVERT_SUBKEYS, bytes);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.advert_write_failures,
            |h| &mut h.advert_write_timeouts,
        )
    }

    fn erase_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Result<(), RecordError> {
        let result = self.inner.erase_channel(lookup_key);
        tally(
            result,
            R::classify,
            &mut self.health,
            |h| &mut h.channel_erase_failures,
            |h| &mut h.channel_erase_timeouts,
        )
    }
}

/// Why the block list could not be read or changed.
enum BlockListFailure {
    /// The store refused; every such refusal is answered the same way.
    Store,
    /// The list is full or its record does not decode.
    List(BlockListError),
}

impl From<DmStoreError> for BlockListFailure {
    fn from(_: DmStoreError) -> Self {
        Self::Store
    }
}

impl From<BlockListError> for BlockListFailure {
    fn from(e: BlockListError) -> Self {
        Self::List(e)
    }
}

/// Read the block list, let `change` change it, and write it back, all under the
/// profile lock. An absent record is the empty list and is created.
fn update_block_list(
    store: &Store,
    change: impl FnOnce(&mut BlockList),
) -> Result<BlockList, BlockListFailure> {
    store
        .records()
        .profile_critical_section(|guard| -> Result<BlockList, BlockListFailure> {
            let mut list = match guard.read(RecordKind::BlockList)? {
                Some(bytes) => BlockList::decode(&bytes)?,
                None => BlockList::new(),
            };
            change(&mut list);
            guard.replace(RecordKind::BlockList, &list.encode()?)?;
            Ok(list)
        })
}

/// Entropy from the operating system, in the shape the flows take it.
fn os_fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}

/// `tick`, moved by up to [`TICK_JITTER_PERCENT`] either way.
///
/// The position in that band is where a draw from
/// [`delivery::next_poll_interval_os`] landed in its own band, so the runner
/// has one jitter source and it is core's.
fn jittered(tick: Duration) -> Duration {
    let min = delivery::POLL_INTERVAL_MIN;
    let span = delivery::POLL_INTERVAL_MAX.saturating_sub(min).as_nanos();
    let position = delivery::next_poll_interval_os(0, 0)
        .saturating_sub(min)
        .as_nanos()
        .min(span);
    let nanos = tick.as_nanos();
    let low = nanos - nanos / 100 * TICK_JITTER_PERCENT;
    let width = nanos / 100 * 2 * TICK_JITTER_PERCENT;
    let offset = width
        .saturating_mul(position)
        .checked_div(span)
        .unwrap_or(width / 2)
        .min(width);
    Duration::from_nanos(u64::try_from(low.saturating_add(offset)).unwrap_or(u64::MAX))
}

/// Whether a subkey anyone may write needs its owner's bytes put back: the
/// network holds nothing, or a number that differs from this node's in either
/// direction. A subkey still queued for the flush does not.
fn differs(report: SubkeyReport) -> bool {
    !report.pending && (report.network_seq.is_none() || report.network_seq != report.local_seq)
}

/// The report for one subkey, or no numbers where the report did not reach it.
fn report_at(reports: &[SubkeyReport], subkey: usize) -> SubkeyReport {
    reports.get(subkey).copied().unwrap_or_default()
}

/// Whether a subkey only its owner writes has been lost: the network holds
/// nothing, or an older number than this node's. A subkey still queued for the
/// flush has not been lost.
fn behind(report: SubkeyReport) -> bool {
    if report.pending {
        return false;
    }
    match (report.local_seq, report.network_seq) {
        (_, None) => true,
        (Some(local), Some(network)) => network < local,
        (None, Some(_)) => false,
    }
}

/// Whether a conversation's own first contact stopped after its conversation
/// record was created and before its hello was persisted, which leaves the
/// opening, sequence 0's slot and the hello to write.
fn first_contact_incomplete(state: &ConvState) -> bool {
    state.awaiting_acceptance && state.outstanding_hello.is_none()
}

/// Whether a conversation has anything the repair poll looks after.
fn outstanding(conv: &LoadedConv) -> bool {
    conv.state.outstanding_hello.is_some()
        || !conv.outstanding_outbox.is_empty()
        || first_contact_incomplete(&conv.state)
        || conv.state.acceptance_pending
}

/// The roster rows for `convs`.
fn summaries(convs: &[LoadedConv]) -> Vec<ConversationSummary> {
    convs
        .iter()
        .map(|conv| ConversationSummary {
            peer: conv.peer,
            peer_identity_pk: conv.state.peer_identity_pk.clone(),
            state: if conv.state.awaiting_acceptance || conv.state.acceptance_pending {
                ConversationState::Pending
            } else {
                ConversationState::Established
            },
            peer_collected: conv.state.peer_collected,
            uncollected: conv
                .state
                .send_seq
                .saturating_sub(conv.state.peer_collected),
        })
        .collect()
}

/// The refusal a front end is given for a flow's error.
fn refusal_for(error: &FlowError) -> Refusal {
    match error {
        FlowError::Store(StoreError::MissingConversation) => Refusal::UnknownConversation,
        FlowError::Store(_) => Refusal::Store,
        FlowError::Channel(ChannelError::RingFull { .. }) => Refusal::RingFull,
        FlowError::AwaitingAcceptance => Refusal::AwaitingAcceptance,
        FlowError::AlreadyEstablished => Refusal::AlreadyEstablished,
        FlowError::NoAdvert => Refusal::NoAdvert,
        FlowError::DropFull => Refusal::DropFull,
        FlowError::Records(_) => Refusal::Network,
        _ => Refusal::Flow,
    }
}

/// Count a flow failure the schedule met. A record store failure is already
/// counted where the store refused. A conversation whose delete is under way
/// refuses every flow until the delete finishes, and that refusal is not a
/// failure.
fn note_failure(health: &mut HealthCounters, error: &FlowError) {
    match error {
        FlowError::Records(_) | FlowError::DeletePending => {}
        FlowError::Store(_) => health.store_failures += 1,
        _ => health.conversation_failures += 1,
    }
}

/// A control record for this side's own channel, sealed under this side's
/// control key and carrying this side's opening, where the conversation holds
/// both.
fn own_control(
    state: &ConvState,
    build: impl FnOnce(ChannelOpening) -> Control,
) -> Option<Vec<u8>> {
    let key = state.own_control_key.as_ref()?;
    let opening = ChannelOpening::decode(state.own_opening.as_ref()?.as_slice()).ok()?;
    channel::seal_control_with_key(key, &build(opening)).ok()
}

/// The closed-marker control record for a conversation being deleted.
fn closed_control(state: &ConvState, marker: ClosedMarker) -> Option<Vec<u8>> {
    own_control(state, |opening| marker.control(Some(opening)))
}

/// The control record this side's channel holds while the conversation runs:
/// the opening and the cursor last published.
fn current_control(state: &ConvState) -> Option<Vec<u8>> {
    own_control(state, |opening| Control {
        opening: Some(opening),
        collected_cursor: state.cursor_published,
        closed: false,
    })
}

/// The runner's state between flow calls.
struct Runner<R> {
    records: Tracked<R>,
    store: Store,
    signer: Arc<SignKeypair>,
    channel_root: DmChannelRootSecret,
    advert_keys: AdvertKeys,
    config: RunnerConfig,
    events: mpsc::Sender<RunnerEvent>,
    stop: Arc<AtomicBool>,
    clock: Clock,
    request_epoch: u64,
    next_request: u64,
    scans: u64,
    requests: BTreeMap<ContactRequestId, HeldRequest>,
    delivered: HashMap<CorrespondenceLabel, u64>,
    repairs: HashMap<CorrespondenceLabel, Repair>,
    next_tick: Instant,
    next_advert_poll: Instant,
    last_scan: Option<Instant>,
    /// Whether the network answers in the current pass, once asked.
    answering: Option<bool>,
    health_reported: HealthCounters,
}

impl<R: RunnerRecords> Runner<R> {
    /// Open the store and run startup, in the order the module docs give.
    async fn start(
        parts: RunnerParts<R>,
        events: mpsc::Sender<RunnerEvent>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, Halt> {
        let RunnerParts {
            records,
            signer,
            channel_root,
            at_rest_key,
            profile_root,
            config,
        } = parts;
        let clock = Clock::start();
        let store = Store::open(profile_root.join(STORE_DIR), &at_rest_key)?;
        drop(at_rest_key);

        let loaded = store.load()?;
        events
            .send(RunnerEvent::Roster(summaries(&loaded.convs)))
            .await
            .map_err(|_| Halt::Stopped)?;

        let (advert_keys, minted) = match loaded.advert_keys {
            Some(snapshot) => (AdvertKeys::restore(snapshot), false),
            None => {
                let keys = AdvertKeys::new(clock.now_secs(), os_fill)?;
                store.persist_advert_keys(&keys.snapshot())?;
                (keys, true)
            }
        };
        let mut epoch = [0u8; 8];
        let request_epoch = match os_fill(&mut epoch) {
            Ok(()) => u64::from_le_bytes(epoch),
            Err(()) => clock.now_ms(),
        };
        let now = Instant::now();
        let mut runner = Self {
            records: Tracked {
                inner: records,
                health: HealthCounters::default(),
                failed_drop_reads: 0,
            },
            store,
            signer,
            channel_root,
            advert_keys,
            config,
            events,
            stop,
            clock,
            request_epoch,
            next_request: 0,
            scans: 0,
            requests: BTreeMap::new(),
            delivered: loaded
                .convs
                .iter()
                .map(|conv| (conv.peer, conv.state.peer_collected))
                .collect(),
            repairs: HashMap::new(),
            next_tick: now + jittered(config.tick),
            next_advert_poll: now + advert::next_poll_interval_os(),
            last_scan: None,
            answering: None,
            health_reported: HealthCounters::default(),
        };

        runner.reopen_channels(&loaded.convs)?;
        runner.refresh_advert(minted);
        runner.answering = None;
        runner.scan_drop().await?;
        for conv in runner.store.load()?.convs {
            runner.check_stop()?;
            runner.resume_incomplete(&conv).await?;
        }
        for conv in runner.store.load()?.convs {
            runner.check_stop()?;
            runner.rewrite_hello(&conv.peer, &conv.state);
        }
        for conv in runner.store.load()?.convs {
            runner.check_stop()?;
            runner.rewrite_evicted(&conv.state, &conv.outstanding_outbox);
            runner.reschedule(&conv);
        }
        let health = runner.records.health;
        runner.health_reported = health;
        runner.emit(RunnerEvent::Health(health)).await?;
        Ok(runner)
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn check_stop(&self) -> Result<(), Halt> {
        if self.stopping() {
            Err(Halt::Stopped)
        } else {
            Ok(())
        }
    }

    async fn emit(&mut self, event: RunnerEvent) -> Result<(), Halt> {
        self.events.send(event).await.map_err(|_| Halt::Stopped)
    }

    async fn refuse(&mut self, token: Option<CommandToken>, reason: Refusal) -> Result<(), Halt> {
        self.emit(RunnerEvent::Refused { token, reason }).await
    }

    /// Answer every command still queued with [`Refusal::ShuttingDown`].
    async fn refuse_queued(&mut self, commands: &CommandQueue) {
        let tokens: Vec<CommandToken> = {
            let mut queue = commands.lock().await;
            queue.close();
            std::iter::from_fn(|| queue.try_recv().ok())
                .filter_map(|command| command.token())
                .collect()
        };
        for token in tokens {
            if self
                .refuse(Some(token), Refusal::ShuttingDown)
                .await
                .is_err()
            {
                return;
            }
        }
    }

    async fn emit_roster(&mut self) -> Result<(), Halt> {
        match self.store.load() {
            Ok(loaded) => {
                self.emit(RunnerEvent::Roster(summaries(&loaded.convs)))
                    .await
            }
            Err(_) => {
                self.records.health.store_failures += 1;
                Ok(())
            }
        }
    }

    /// One [`RunnerEvent::Message`] per body, numbered from `first`.
    async fn emit_bodies(
        &mut self,
        from: CorrespondenceLabel,
        first: u64,
        bodies: Vec<Vec<u8>>,
    ) -> Result<(), Halt> {
        for (seq, body) in (first..).zip(bodies) {
            let received_at = self.clock.now_ms();
            self.emit(RunnerEvent::Message {
                from,
                seq,
                body,
                received_at,
            })
            .await?;
        }
        Ok(())
    }

    /// Every conversation, and `Err` where the store would not load.
    fn load_convs(&mut self) -> Result<Vec<LoadedConv>, ()> {
        match self.store.load() {
            Ok(loaded) => Ok(loaded.convs),
            Err(_) => {
                self.records.health.store_failures += 1;
                Err(())
            }
        }
    }

    /// One conversation by label.
    fn load_one(&mut self, peer: &CorrespondenceLabel) -> Result<Option<LoadedConv>, ()> {
        Ok(self
            .load_convs()?
            .into_iter()
            .find(|conv| &conv.peer == peer))
    }

    /// The conversation with an identity.
    fn conv_with(&mut self, identity: &[u8; IDENTITY_PK_LEN]) -> Result<Option<LoadedConv>, ()> {
        Ok(self
            .load_convs()?
            .into_iter()
            .find(|conv| conv.state.peer_identity_pk.as_slice() == identity.as_slice()))
    }

    /// The earliest moment anything on the schedule is due.
    fn next_due(&self) -> Instant {
        self.repairs
            .values()
            .map(|repair| repair.due)
            .fold(self.next_tick.min(self.next_advert_poll), Instant::min)
    }

    /// Open every channel this side owns, so the record store can write it.
    fn reopen_channels(&mut self, convs: &[LoadedConv]) -> Result<(), Halt> {
        for conv in convs {
            self.check_stop()?;
            let stored = conv.state.outgoing_lookup_key;
            if stored == NO_LOOKUP_KEY {
                continue;
            }
            let Ok(owner) = channel::derive_owner_seed(
                &self.channel_root,
                &conv.state.peer_identity_pk,
                conv.state.generation,
            ) else {
                self.records.health.local_refusals += 1;
                continue;
            };
            if let Ok(lookup_key) = self.records.open_channel(&owner, channel::CHANNEL_SUBKEYS) {
                if lookup_key != stored {
                    crate::vtrace!(
                        "dm runner: a reopened channel is not the one the store recorded"
                    );
                    self.records.health.channel_open_failures += 1;
                }
            }
        }
        Ok(())
    }

    /// The canonical advert bytes, counting a signing failure.
    fn canonical_advert(&mut self) -> Option<Vec<u8>> {
        match self.advert_keys.advert_bytes(&self.signer) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                self.records.health.advert_failures += 1;
                None
            }
        }
    }

    /// Rotate the advert when due and publish it where it is new, or where the
    /// network's copy is missing or differs.
    fn refresh_advert(&mut self, minted: bool) {
        let owner = match advert::derive_owner_seed(self.signer.public_key()) {
            Ok(owner) => owner,
            Err(_) => {
                self.records.health.advert_failures += 1;
                return;
            }
        };
        let mut rewrite = None;
        if minted {
            rewrite = self.canonical_advert();
        } else {
            let now = self.clock.now_secs();
            match self
                .store
                .update_advert_keys(|keys| keys.rotate_if_due(now, os_fill))
            {
                Ok(Ok(rotation)) => {
                    // A reload that fails leaves the keys last loaded, which at
                    // worst republishes and re-marks a key already published.
                    match self.store.load_advert_keys() {
                        Ok(Some(snapshot)) => self.advert_keys = AdvertKeys::restore(snapshot),
                        Ok(None) | Err(_) => self.records.health.store_failures += 1,
                    }
                    if rotation.happened() {
                        rewrite = self.canonical_advert();
                    }
                }
                Ok(Err(_)) => self.records.health.advert_failures += 1,
                Err(_) => self.records.health.store_failures += 1,
            }
            if rewrite.is_none() {
                if let Ok(reports) = self.records.inspect_advert(&owner) {
                    let report = report_at(&reports, advert::ADVERT_SUBKEY as usize);
                    if !report.pending {
                        let observed = InspectReport {
                            local_seq: report.local_seq,
                            network_seq: report.network_seq,
                        };
                        // The bytes, not only the numbers: a record whose numbers
                        // match can still hold an advert of a key a reset has
                        // since rotated away. A read that fails leaves the report
                        // to decide.
                        let fetched = self
                            .records
                            .read_advert(&owner, advert::ADVERT_SUBKEYS)
                            .ok()
                            .flatten();
                        match self
                            .advert_keys
                            .on_poll(&self.signer, &observed, fetched.as_deref())
                        {
                            Ok(actions) => {
                                rewrite = actions
                                    .into_iter()
                                    .next()
                                    .map(|AdvertAction::Rewrite(bytes)| bytes);
                                // With bytes to compare, no rewrite means the
                                // network holds the current key's advert: it is
                                // confirmed published. The mark only moves forward,
                                // so marking again on each intact poll changes
                                // nothing.
                                if rewrite.is_none() && fetched.is_some() {
                                    self.mark_advert_published();
                                }
                            }
                            Err(_) => self.records.health.advert_failures += 1,
                        }
                    }
                }
            }
        }
        if let Some(bytes) = rewrite {
            if self.stopping() {
                return;
            }
            if self.records.publish_advert(&owner, &bytes).is_ok() {
                self.mark_advert_published();
            }
        }
    }

    /// Record the current advert key as confirmed published, which is what lets
    /// a reset rotate past it. The store refuses a serial above its own current
    /// key's, which names no advert this profile built; that is counted as a
    /// local refusal.
    fn mark_advert_published(&mut self) {
        match self.store.mark_advert_published(self.advert_keys.serial()) {
            Ok(()) => {}
            Err(StoreError::UnbuiltAdvertSerial { .. }) => self.records.health.local_refusals += 1,
            Err(_) => self.records.health.store_failures += 1,
        }
    }

    /// Scan the drop and surface what it holds, returning the block list the
    /// scan used, or `None` where the block list could not be read and nothing
    /// was scanned.
    async fn scan_drop(&mut self) -> Result<Option<BlockList>, Halt> {
        self.check_stop()?;
        let blocked = match self
            .store
            .records()
            .read_profile_unlocked(RecordKind::BlockList)
        {
            Ok(Some(bytes)) => BlockList::decode(&bytes).ok(),
            Ok(None) => update_block_list(&self.store, |_| {}).ok(),
            Err(_) => None,
        };
        let Some(blocked) = blocked else {
            self.records.health.store_failures += 1;
            return Ok(None);
        };
        let unread_before = self.records.failed_drop_reads;
        let me = Me {
            signer: &self.signer,
            channel_root: &self.channel_root,
        };
        let collected = flows::collect(
            &self.store,
            &mut self.records,
            &me,
            &self.advert_keys,
            |identity| blocked.is_blocked(identity),
        );
        self.last_scan = Some(Instant::now());
        let partial = self.records.failed_drop_reads > unread_before;
        match collected {
            Ok(surfaced) => self.surface(surfaced, partial).await?,
            Err(e) => note_failure(&mut self.records.health, &e),
        }
        Ok(Some(blocked))
    }

    /// Carry on a first contact or an acceptance a previous call stopped part
    /// way.
    async fn resume_incomplete(&mut self, conv: &LoadedConv) -> Result<(), Halt> {
        self.check_stop()?;
        let state = &conv.state;
        let peer = conv.peer;
        if first_contact_incomplete(state) {
            // The record already holds sequence 0, the encapsulation and the
            // opening, so the flow only redoes writes.
            match flows::continue_first_contact(&self.store, &mut self.records, &peer, os_fill) {
                Ok(_) | Err(FlowError::AlreadyEstablished) => {}
                Err(e) => note_failure(&mut self.records.health, &e),
            }
            return Ok(());
        }
        if !state.acceptance_pending {
            return Ok(());
        }
        let now = self.clock.now_secs();
        let me = Me {
            signer: &self.signer,
            channel_root: &self.channel_root,
        };
        let continued =
            flows::continue_acceptance(&self.store, &mut self.records, &me, &peer, os_fill, now);
        match continued {
            Ok(accepted) => {
                // The bodies and the cursor are recorded by the step that
                // finished the acceptance, so they number back from it.
                match self.store.load_conv(&peer) {
                    Ok(Some(finished)) => {
                        let first = finished
                            .my_collected
                            .saturating_sub(accepted.bodies.len() as u64);
                        self.emit_bodies(peer, first, accepted.bodies).await?;
                    }
                    Ok(None) | Err(_) => self.records.health.store_failures += 1,
                }
                self.emit_roster().await?;
            }
            Err(FlowError::AlreadyEstablished) => {}
            Err(e) => note_failure(&mut self.records.health, &e),
        }
        Ok(())
    }

    /// Clear an acceptor's outstanding hello once the correspondent's cursor
    /// shows it has read this side's channel, which it can only have found
    /// through that hello. Returns whether the hello is settled.
    ///
    /// The initiator's hello is cleared by [`flows::recognise_acceptance`]; no
    /// flow clears the acceptor's.
    fn settle_hello(&mut self, peer: &CorrespondenceLabel, state: &ConvState) -> bool {
        if state.outstanding_hello.is_none()
            || state.awaiting_acceptance
            || state.peer_collected == 0
        {
            return false;
        }
        if self
            .store
            .update_conv(peer, |state| state.outstanding_hello = None)
            .is_err()
        {
            self.records.health.store_failures += 1;
        }
        true
    }

    /// Re-encapsulate an outstanding hello still awaiting acceptance where the
    /// correspondent's advert has rotated past it, then write the persisted
    /// hello where the drop inspect shows its slot's numbers differ, or where
    /// this node's copy of the slot holds other bytes. Nothing is written where
    /// the drop inspect fails.
    ///
    /// Called only after a drop scan, so a hello the correspondent has already
    /// accepted has been recognised and is no longer awaiting acceptance.
    fn rewrite_hello(&mut self, peer: &CorrespondenceLabel, state: &ConvState) {
        if state.outstanding_hello.is_none() || self.stopping() {
            return;
        }
        // An acceptor learns its hello back was read only from the
        // correspondent's cursor, which collection alone refreshes; take it
        // now, so a hello already read is settled rather than rewritten.
        let refreshed: LoadedConv;
        let state = if !state.awaiting_acceptance && state.peer_collected == 0 {
            self.refresh_peer_cursor(peer);
            match self.load_one(peer) {
                Ok(Some(conv)) => {
                    refreshed = conv;
                    &refreshed.state
                }
                Ok(None) | Err(()) => return,
            }
        } else {
            state
        };
        if self.settle_hello(peer, state) {
            return;
        }
        if state.awaiting_acceptance {
            if self.stopping() {
                return;
            }
            let now = self.clock.now_secs();
            match flows::refresh_first_contact(&self.store, &mut self.records, peer, os_fill, now) {
                Ok(true) | Err(FlowError::AlreadyAccepted) => return,
                Ok(false) => {}
                Err(e) => note_failure(&mut self.records.health, &e),
            }
        }
        // Read again: a refresh that persisted its hello and then stopped has
        // changed the bytes the slot owes.
        let Ok(Some(conv)) = self.load_one(peer) else {
            return;
        };
        let Some(hello) = conv.state.outstanding_hello.as_ref() else {
            return;
        };
        let Ok(owner) = drop_plane::derive_owner_seed(&conv.state.peer_identity_pk) else {
            self.records.health.conversation_failures += 1;
            return;
        };
        let Ok(reports) = self.records.inspect_drop(&owner) else {
            return;
        };
        if self.dropped_but_unanswered(&reports) {
            return;
        }
        let lost = differs(report_at(&reports, usize::from(hello.slot)));
        if !lost && !self.slot_holds_other_bytes(&owner, hello) {
            return;
        }
        if self.stopping() {
            return;
        }
        if let Err(e) = flows::resume_first_contact(&self.store, &mut self.records, peer) {
            note_failure(&mut self.records.health, &e);
        }
    }

    /// Whether the network answers in this pass: this node's own advert shows a
    /// network number. Asked at most once per pass, and only when a record's
    /// report held no network number at all.
    fn network_answering(&mut self) -> bool {
        if let Some(answering) = self.answering {
            return answering;
        }
        let answering = match advert::derive_owner_seed(self.signer.public_key()) {
            Ok(owner) => self.records.inspect_advert(&owner).is_ok_and(|reports| {
                report_at(&reports, advert::ADVERT_SUBKEY as usize)
                    .network_seq
                    .is_some()
            }),
            Err(_) => {
                self.records.health.advert_failures += 1;
                false
            }
        };
        self.answering = Some(answering);
        answering
    }

    /// Whether a report with no network number on any subkey came from a pass
    /// in which the network does not answer, counting it when it did. A report
    /// with any network number is the network answering.
    fn dropped_but_unanswered(&mut self, reports: &[SubkeyReport]) -> bool {
        if reports.iter().any(|report| report.network_seq.is_some()) {
            return false;
        }
        if self.network_answering() {
            return false;
        }
        self.records.health.network_not_answering += 1;
        true
    }

    /// Whether this node's copy of a drop slot holds bytes other than the
    /// persisted hello.
    ///
    /// A re-encapsulated hello that was persisted and never written leaves the
    /// slot holding the earlier hello at the sequence number this node wrote it
    /// under, which no sequence comparison tells apart from an intact slot. A
    /// read that fails decides nothing and is counted where the store refused.
    fn slot_holds_other_bytes(&mut self, owner: &DropOwnerSeed, hello: &OutstandingHello) -> bool {
        match self
            .records
            .read_drop_slot(owner, drop_plane::DROP_SUBKEYS, hello.slot)
        {
            Ok(held) => held.as_deref() != Some(hello.sealed.as_slice()),
            Err(_) => false,
        }
    }

    /// Rewrite this side's channel where the network has lost it: the control
    /// subkey, resealed from the conversation record, and every outstanding
    /// message slot, from the outbox.
    fn rewrite_evicted(&mut self, state: &ConvState, entries: &[OutboxEntry]) {
        let lookup_key = state.outgoing_lookup_key;
        if lookup_key == NO_LOOKUP_KEY {
            return;
        }
        let has_control = state.own_control_key.is_some() && state.own_opening.is_some();
        if entries.is_empty() && !has_control {
            return;
        }
        let Ok(reports) = self.records.inspect_channel(&lookup_key) else {
            return;
        };
        if self.dropped_but_unanswered(&reports) {
            return;
        }
        if has_control
            && !self.stopping()
            && behind(report_at(&reports, usize::from(channel::CONTROL_SUBKEY)))
        {
            match current_control(state) {
                Some(control) => {
                    let _ =
                        self.records
                            .write_channel(&lookup_key, channel::CONTROL_SUBKEY, &control);
                }
                None => self.records.health.conversation_failures += 1,
            }
        }
        for entry in entries {
            if self.stopping() {
                return;
            }
            let subkey = channel::slot_for(entry.seq);
            if behind(report_at(&reports, usize::from(subkey))) {
                let _ = self
                    .records
                    .write_channel(&lookup_key, subkey, &entry.ciphertext);
            }
        }
    }

    /// Set a conversation's next repair look, or drop it where nothing is
    /// outstanding.
    fn reschedule(&mut self, conv: &LoadedConv) {
        if !outstanding(conv) {
            self.repairs.remove(&conv.peer);
            return;
        }
        let now = self.clock.now_secs();
        let since_secs = self
            .repairs
            .get(&conv.peer)
            .map_or(now, |repair| repair.since_secs);
        let due = Instant::now() + delivery::next_poll_interval_os(since_secs, now);
        self.repairs.insert(conv.peer, Repair { since_secs, due });
    }

    /// Put a conversation on the repair schedule if it is not on it.
    fn ensure_repair(&mut self, peer: CorrespondenceLabel) {
        if !self.repairs.contains_key(&peer) {
            let now = self.clock.now_secs();
            let due = Instant::now() + delivery::next_poll_interval_os(now, now);
            self.repairs.insert(
                peer,
                Repair {
                    since_secs: now,
                    due,
                },
            );
        }
    }

    /// Serve one command.
    async fn serve(&mut self, command: RunnerCommand) -> Result<(), Halt> {
        if self.stopping() {
            if let Some(token) = command.token() {
                self.refuse(Some(token), Refusal::ShuttingDown).await?;
            }
            return Err(Halt::Stopped);
        }
        match command {
            RunnerCommand::FirstContact {
                token,
                peer_identity_pk,
                body,
            } => self.first_contact(token, &peer_identity_pk, &body).await,
            RunnerCommand::Send { token, peer, body } => self.send(token, peer, &body).await,
            RunnerCommand::Accept {
                token,
                request,
                reply,
            } => self.accept(token, request, reply).await,
            RunnerCommand::Block { peer } => self.set_blocked(&peer, true).await,
            RunnerCommand::Unblock { peer } => self.set_blocked(&peer, false).await,
            RunnerCommand::DeleteConversation { token, peer } => self.delete(token, peer).await,
            RunnerCommand::Shutdown => Ok(()),
        }
    }

    async fn first_contact(
        &mut self,
        token: CommandToken,
        peer_identity_pk: &[u8; IDENTITY_PK_LEN],
        body: &[u8],
    ) -> Result<(), Halt> {
        let now = self.clock.now_secs();
        let me = Me {
            signer: &self.signer,
            channel_root: &self.channel_root,
        };
        let outcome = flows::first_contact(
            &self.store,
            &mut self.records,
            &me,
            peer_identity_pk,
            body,
            os_fill,
            now,
        );
        match outcome {
            Ok(FirstContact::Opened { peer, .. } | FirstContact::Rewrote { peer, .. }) => {
                self.delivered.entry(peer).or_insert(0);
                self.ensure_repair(peer);
                self.emit(RunnerEvent::Sent {
                    token,
                    peer,
                    seq: 0,
                })
                .await?;
                self.emit_roster().await
            }
            Err(e) => {
                self.refuse(Some(token), refusal_for(&e)).await?;
                // A refusal part way leaves a pending conversation behind; the
                // repair poll carries it on.
                if let Ok(Some(conv)) = self.conv_with(peer_identity_pk) {
                    if conv.state.awaiting_acceptance {
                        self.ensure_repair(conv.peer);
                        return self.emit_roster().await;
                    }
                }
                Ok(())
            }
        }
    }

    async fn send(
        &mut self,
        token: CommandToken,
        peer: CorrespondenceLabel,
        body: &[u8],
    ) -> Result<(), Halt> {
        match flows::send_message(&self.store, &mut self.records, &peer, body, os_fill) {
            Ok(seq) => {
                self.ensure_repair(peer);
                self.emit(RunnerEvent::Sent { token, peer, seq }).await
            }
            Err(FlowError::AwaitingAcceptance) if matches!(self.store.load_conv(&peer), Ok(Some(state)) if state.acceptance_pending) => {
                self.refuse(Some(token), Refusal::AcceptanceUnfinished)
                    .await
            }
            Err(e) => self.refuse(Some(token), refusal_for(&e)).await,
        }
    }

    async fn accept(
        &mut self,
        token: CommandToken,
        request: ContactRequestId,
        reply: Vec<u8>,
    ) -> Result<(), Halt> {
        let identity = match self.requests.get(&request).map(|entry| &entry.held) {
            None => None,
            Some(Held::StartedOver(_)) => {
                return self
                    .refuse(Some(token), Refusal::StartedOverNotAcceptable)
                    .await
            }
            Some(Held::Request(held)) => Some(held.identity.clone()),
        };
        let Some(identity) = identity else {
            return self.refuse(Some(token), Refusal::UnknownRequest).await;
        };
        let first = match self.conv_with(&identity) {
            Ok(Some(conv)) => conv.state.my_collected,
            Ok(None) | Err(()) => 0,
        };
        let now = self.clock.now_secs();
        let outcome = match self.requests.get(&request).map(|entry| &entry.held) {
            Some(Held::Request(held)) => {
                let me = Me {
                    signer: &self.signer,
                    channel_root: &self.channel_root,
                };
                flows::accept(
                    &self.store,
                    &mut self.records,
                    &me,
                    held,
                    &reply,
                    os_fill,
                    now,
                )
            }
            Some(Held::StartedOver(_)) | None => {
                return self.refuse(Some(token), Refusal::UnknownRequest).await
            }
        };
        match outcome {
            Ok(accepted) => {
                self.requests.remove(&request);
                let peer = accepted.peer;
                self.delivered.entry(peer).or_insert(0);
                self.emit_bodies(peer, first, accepted.bodies).await?;
                // The reply is sequence 0 of this side's direction on every
                // path through an acceptance.
                self.emit(RunnerEvent::Sent {
                    token,
                    peer,
                    seq: 0,
                })
                .await?;
                self.ensure_repair(peer);
                self.emit_roster().await
            }
            Err(e) => {
                let reason = refusal_for(&e);
                self.refuse(Some(token), reason).await?;
                // A refusal after the conversation record was created leaves an
                // acceptance the record alone can finish: the repair poll does,
                // and so does an Accept of the same request.
                if let Ok(Some(conv)) = self.conv_with(&identity) {
                    self.ensure_repair(conv.peer);
                    return self.emit_roster().await;
                }
                Ok(())
            }
        }
    }

    async fn set_blocked(
        &mut self,
        identity: &[u8; IDENTITY_PK_LEN],
        block: bool,
    ) -> Result<(), Halt> {
        let updated = update_block_list(&self.store, |list| {
            if block {
                list.block(identity);
            } else {
                list.unblock(identity);
            }
        });
        match updated {
            Ok(_) => {
                if block {
                    self.requests
                        .retain(|_, entry| entry.held.identity() != identity);
                }
                Ok(())
            }
            Err(BlockListFailure::List(BlockListError::Full { .. })) => {
                self.refuse(None, Refusal::BlockListFull).await
            }
            Err(_) => self.refuse(None, Refusal::Store).await,
        }
    }

    async fn delete(&mut self, token: CommandToken, peer: CorrespondenceLabel) -> Result<(), Halt> {
        let erase = match delivery::prepare_delete(&self.store, &peer, true) {
            Ok(erase) => erase,
            Err(StoreError::MissingConversation) => {
                return self.refuse(Some(token), Refusal::UnknownConversation).await
            }
            Err(_) => return self.refuse(Some(token), Refusal::Store).await,
        };
        if erase.lookup_key != NO_LOOKUP_KEY {
            let state = match self.store.load_conv(&peer) {
                Ok(Some(state)) => state,
                Ok(None) => return self.refuse(Some(token), Refusal::UnknownConversation).await,
                Err(_) => return self.refuse(Some(token), Refusal::Store).await,
            };
            if let Some(marker) = erase.marker {
                match closed_control(&state, marker) {
                    Some(control) => {
                        let written = self.records.write_channel(
                            &erase.lookup_key,
                            channel::CONTROL_SUBKEY,
                            &control,
                        );
                        if written.is_err() {
                            return self.refuse(Some(token), Refusal::Network).await;
                        }
                    }
                    None => self.records.health.conversation_failures += 1,
                }
            }
            if self.records.erase_channel(&erase.lookup_key).is_err() {
                return self.refuse(Some(token), Refusal::Network).await;
            }
        }
        if delivery::finish_delete(&self.store, &peer).is_err() {
            return self.refuse(Some(token), Refusal::Store).await;
        }
        self.repairs.remove(&peer);
        self.delivered.remove(&peer);
        self.emit(RunnerEvent::Deleted { token, peer }).await?;
        self.emit_roster().await
    }

    /// Run everything the schedule has due, then report the counters if they
    /// moved.
    async fn run_due(&mut self) -> Result<(), Halt> {
        self.answering = None;
        if Instant::now() >= self.next_tick {
            self.collect_tick().await?;
            self.next_tick = Instant::now() + jittered(self.config.tick);
        }
        if Instant::now() >= self.next_advert_poll {
            self.check_stop()?;
            self.refresh_advert(false);
            self.next_advert_poll = Instant::now() + advert::next_poll_interval_os();
        }
        let now = Instant::now();
        let due: Vec<CorrespondenceLabel> = self
            .repairs
            .iter()
            .filter(|(_, repair)| repair.due <= now)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in due {
            self.check_stop()?;
            self.repair(&peer).await?;
        }
        // A repair that left its conversation due is put back a full interval,
        // so the schedule never wakes on it again at once.
        let floor = Instant::now() + delivery::POLL_INTERVAL_MIN;
        for repair in self.repairs.values_mut() {
            if repair.due <= now {
                repair.due = floor;
            }
        }
        self.report_health().await
    }

    /// Emit [`RunnerEvent::Health`] where a counter has moved since the last
    /// report.
    async fn report_health(&mut self) -> Result<(), Halt> {
        let health = self.records.health;
        if health == self.health_reported {
            return Ok(());
        }
        self.health_reported = health;
        self.emit(RunnerEvent::Health(health)).await
    }

    /// Push a conversation's repair back after the store would not load.
    fn defer_repair(&mut self, peer: &CorrespondenceLabel) {
        if let Some(repair) = self.repairs.get_mut(peer) {
            repair.due = Instant::now() + delivery::POLL_INTERVAL_MIN;
        }
    }

    /// One repair look at one conversation: a drop scan first where it is still
    /// awaiting acceptance, then what startup does for it.
    async fn repair(&mut self, peer: &CorrespondenceLabel) -> Result<(), Halt> {
        let awaiting = match self.load_one(peer) {
            Ok(Some(conv)) => conv.state.awaiting_acceptance,
            Ok(None) => {
                self.repairs.remove(peer);
                return Ok(());
            }
            Err(()) => {
                self.defer_repair(peer);
                return Ok(());
            }
        };
        let scan_stale = self
            .last_scan
            .is_none_or(|at| at.elapsed() >= self.config.tick);
        if awaiting && scan_stale {
            self.scan_drop().await?;
        }
        self.check_stop()?;
        if let Ok(Some(conv)) = self.load_one(peer) {
            self.resume_incomplete(&conv).await?;
        }
        self.check_stop()?;
        if let Ok(Some(conv)) = self.load_one(peer) {
            self.rewrite_hello(peer, &conv.state);
        }
        self.check_stop()?;
        match self.load_one(peer) {
            Ok(Some(conv)) => {
                self.rewrite_evicted(&conv.state, &conv.outstanding_outbox);
                self.reschedule(&conv);
            }
            Ok(None) => {
                self.repairs.remove(peer);
            }
            Err(()) => self.defer_repair(peer),
        }
        Ok(())
    }

    /// One collection pass: the drop, then every established conversation.
    async fn collect_tick(&mut self) -> Result<(), Halt> {
        let Some(blocked) = self.scan_drop().await? else {
            return Ok(());
        };
        let Ok(convs) = self.load_convs() else {
            return Ok(());
        };
        for conv in &convs {
            self.check_stop()?;
            if conv.state.awaiting_acceptance
                || conv.state.acceptance_pending
                || blocked.is_blocked(&conv.state.peer_identity_pk)
            {
                continue;
            }
            self.collect_conversation(conv).await?;
        }
        Ok(())
    }

    /// Read one established conversation's ring, then its correspondent's
    /// cursor where messages are outstanding, and report what was delivered.
    async fn collect_conversation(&mut self, conv: &LoadedConv) -> Result<(), Halt> {
        let peer = conv.peer;
        match flows::collect_batch(&self.store, &mut self.records, &peer) {
            Ok(batch) => {
                let first = batch.my_collected.saturating_sub(batch.bodies.len() as u64);
                self.emit_bodies(peer, first, batch.bodies).await?;
            }
            Err(e) => note_failure(&mut self.records.health, &e),
        }
        if conv.state.send_seq > conv.state.peer_collected {
            self.check_stop()?;
            self.refresh_peer_cursor(&peer);
        }
        self.report_delivery(&peer).await
    }

    /// Read the correspondent's published cursor and take it into the
    /// conversation record where it is ahead, never past `send_seq`.
    fn refresh_peer_cursor(&mut self, peer: &CorrespondenceLabel) {
        match flows::peer_cursor(&self.store, &mut self.records, peer) {
            Ok(Some(cursor)) => {
                let recorded = self.store.update_conv(peer, |state| {
                    let cursor = cursor.min(state.send_seq);
                    if cursor > state.peer_collected {
                        state.peer_collected = cursor;
                    }
                });
                if recorded.is_err() {
                    self.records.health.store_failures += 1;
                }
            }
            Ok(None) => {}
            Err(e) => note_failure(&mut self.records.health, &e),
        }
    }

    /// Emit [`RunnerEvent::Delivered`] where the correspondent's cursor has
    /// moved past what was last reported, and drop the outbox entries it passed.
    async fn report_delivery(&mut self, peer: &CorrespondenceLabel) -> Result<(), Halt> {
        let state = match self.store.load_conv(peer) {
            Ok(Some(state)) => state,
            Ok(None) => return Ok(()),
            Err(_) => {
                self.records.health.store_failures += 1;
                return Ok(());
            }
        };
        self.settle_hello(peer, &state);
        let reported = self.delivered.get(peer).copied().unwrap_or(0);
        if state.peer_collected <= reported {
            return Ok(());
        }
        self.delivered.insert(*peer, state.peer_collected);
        if self
            .store
            .delete_outbox_through(peer, state.peer_collected)
            .is_err()
        {
            self.records.health.store_failures += 1;
        }
        self.emit(RunnerEvent::Delivered {
            peer: *peer,
            through_seq: state.peer_collected - 1,
        })
        .await
    }

    /// Map one scan's surfaced hellos onto events and counters, and replace the
    /// held requests with this scan's. A scan that could not read every slot
    /// keeps the requests it did not see.
    async fn surface(&mut self, surfaced: Vec<Surfaced>, partial: bool) -> Result<(), Halt> {
        self.scans += 1;
        let seen = self.scans;
        let prior: BTreeSet<ContactRequestId> = self.requests.keys().copied().collect();
        let mut held = if partial {
            std::mem::take(&mut self.requests)
        } else {
            BTreeMap::new()
        };
        let mut fresh = Vec::new();
        let mut accepted = Vec::new();
        for item in surfaced {
            match item {
                Surfaced::Dropped { .. } => self.records.health.hellos_dropped += 1,
                Surfaced::AlreadyCollected { .. } => {
                    self.records.health.hellos_already_collected += 1
                }
                Surfaced::Failed { .. } => self.records.health.hellos_unsettled += 1,
                Surfaced::Accepted(acceptance) => accepted.push(acceptance),
                Surfaced::ContactRequest(request) => {
                    let id = self.request_id(&held, &request.identity, false);
                    if !prior.contains(&id) && !held.contains_key(&id) {
                        fresh.push(RunnerEvent::ContactRequest {
                            request: id,
                            from: request.identity.clone(),
                        });
                    }
                    held.insert(
                        id,
                        HeldRequest {
                            held: Held::Request(request),
                            seen,
                        },
                    );
                }
                Surfaced::StartedOver { identity } => {
                    let id = self.request_id(&held, &identity, true);
                    if !prior.contains(&id) && !held.contains_key(&id) {
                        fresh.push(RunnerEvent::StartedOver {
                            request: id,
                            from: identity.clone(),
                        });
                    }
                    held.insert(
                        id,
                        HeldRequest {
                            held: Held::StartedOver(identity),
                            seen,
                        },
                    );
                }
            }
        }
        self.records.health.requests_evicted +=
            retain_newest(&mut held, usize::from(drop_plane::DROP_SUBKEYS));
        self.requests = held;
        for event in fresh {
            self.emit(event).await?;
        }
        let roster_changed = !accepted.is_empty();
        for acceptance in accepted {
            let peer = acceptance.peer;
            self.emit(RunnerEvent::Accepted { peer }).await?;
            match self.store.load_conv(&peer) {
                Ok(Some(state)) => {
                    let first = state
                        .my_collected
                        .saturating_sub(acceptance.bodies.len() as u64);
                    self.emit_bodies(peer, first, acceptance.bodies).await?;
                }
                Ok(None) | Err(_) => self.records.health.store_failures += 1,
            }
            self.report_delivery(&peer).await?;
        }
        if roster_changed {
            self.emit_roster().await?;
        }
        Ok(())
    }

    /// The id a surfaced hello is held under: the one this identity's hello of
    /// the same kind already has, in this scan or the last, or a new one.
    fn request_id(
        &mut self,
        this_scan: &BTreeMap<ContactRequestId, HeldRequest>,
        identity: &[u8; IDENTITY_PK_LEN],
        started_over: bool,
    ) -> ContactRequestId {
        let same = |held: &Held| {
            matches!(held, Held::StartedOver(_)) == started_over && held.identity() == identity
        };
        let existing = this_scan
            .iter()
            .chain(self.requests.iter())
            .find(|(_, entry)| same(&entry.held))
            .map(|(id, _)| *id);
        existing.unwrap_or_else(|| {
            self.next_request += 1;
            ContactRequestId {
                epoch: self.request_epoch,
                serial: self.next_request,
            }
        })
    }
}

#[cfg(test)]
mod tests;
