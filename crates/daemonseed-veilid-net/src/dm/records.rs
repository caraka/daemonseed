//! The direct-messaging record store, over the Veilid distributed hash table.
//!
//! Serves FC1 and FC2.
//!
//! [`VeilidRecords`] implements [`daemonseed_core::dm::flows::Records`] — the
//! seven reads and writes `docs/design/direct-messaging.md` § Flows performs
//! against the three record kinds § Records describes — against real DHT
//! records rather than against a map in memory. The flows are written over that
//! trait and nothing else, so this module is the whole of their reach to the
//! network, and a conversation that runs here is the same conversation that
//! runs against the counting fake. FC2 is served by what survives a restart:
//! a record store holds no conversation state, so a relaunch reopens its own
//! channels and rewrites from the store rather than from anything kept here.
//!
//! ## Addressing
//!
//! An advert and a drop are addressed by an owner seed derived from a public
//! identity key, so every party computes the same one. A channel is addressed
//! by the lookup key its hello discloses, and that lookup key is the owner's
//! 32-byte public key: it derives the record's address, it is public by
//! construction, and it confers no write capability. So a correspondent reads a
//! channel from the lookup key alone, and only the owner — who holds the seed
//! the public key came from — can write it.
//!
//! A record's subkey count is part of its address, so every method that takes
//! one addresses under the count it was given. [`Records::read_channel`] and
//! [`Records::write_channel`] take none, because a lookup key carries none;
//! they use the count [`Records::open_channel`] recorded for a channel this
//! side owns, and [`CHANNEL_SUBKEYS`] for one it only reads.
//!
//! ## Scanning a drop
//!
//! § Flows' collection reads every slot of a 256-slot drop, and almost all of
//! them are empty. A read per slot is a network round trip per slot, so a scan
//! of an empty drop would cost more than the budget a step has for the whole
//! hop. [`Records::read_drop_slot`] at slot 0 therefore inspects the record
//! once — the same `inspect_dht_record` report under `DHTReportScope::SyncSet`
//! that § Eviction detection rests on — and answers every slot the network
//! reports nothing for without a read. Only slots the network says hold
//! something are fetched.
//!
//! ## Writes
//!
//! Every write is submitted to the shared write scheduler as a
//! [`WriteRequest::direct_message`], which is chat-class and never coalesced,
//! and the calling method waits for that request's reply. Nothing here calls
//! `set_dht_value` itself: the scheduler is what holds the layer inside the
//! write budget § Write budget states, and a write that went around it would be
//! outside that budget with nothing reporting it. Each submission also counts
//! against its kind, which [`VeilidRecords::write_counts`] reports, so that
//! budget is a number a caller can assert rather than a claim.
//!
//! Erasing a drop slot is a write of an empty value to that subkey, which is
//! what a world-writable slot offers in place of a delete. Erasing a channel
//! record this side owns is [`VeilidRecords::erase_channel`], which closes and
//! deletes the record from this node's own store: nothing is sent, and what
//! ends the record is this node no longer refreshing it. It sits outside the
//! trait because the flows never erase a channel — tearing one down is the
//! delete flow's business.
//!
//! ## Transient refusals
//!
//! A node that has just attached is routable before it is ready, and Veilid
//! answers an operation issued in that window with `TryAgain: offline, try
//! again later` rather than with a result. That is a fact about this node's own
//! startup and not about the record, so it must not reach the flows: a flow
//! that saw it would report the correspondent's message missing, and a step
//! that saw it would fail with everything on the network intact. Every network
//! call here is therefore retried on a bounded backoff — eight attempts, two
//! seconds doubling to a thirty-second cap — and only a refusal that is still
//! refusing at the end of them is an error. A write is retried inside its
//! dispatch, so one submission stays one entry on the funnel and one charge
//! against the budget. Anything that is not transient is returned on the first
//! attempt, unchanged.
//!
//! ## Confirmation
//!
//! A write has not happened until the network holds it, and Veilid does not say
//! which it did. `set_value` returns `Ok` for a value it could only keep in this
//! node's local store — the node offline at that moment, or the fanout finished
//! short of consensus — and flushes it in the background later
//! (`veilid-core-0.5.7 src/storage_manager/set_value.rs:108-119, 596-624`;
//! `AllowOffline(false)` does not help, `set_value.rs:170-172` turns the second
//! case's refusal back into `Ok` with the value written nowhere). A sender that
//! stops the moment its write returns, which is what § Flows lets a sender do,
//! would leave with the value still on its machine and no report of it. So every
//! subkey write here is followed by a confirmation: a `Local` inspect of the
//! record, which asks no other node, reporting the subkey's local sequence
//! number and whether Veilid still has that subkey queued for its background
//! flush. A write went out when the subkey has a number and is not queued. One
//! that is queued is polled, from `CONFIRM_POLL_FIRST` doubling to
//! `CONFIRM_POLL_MAX`, for at most `CONFIRM_BUDGET`: the flush is what moves
//! the value, and the poll only watches for it to leave the queue. An `inspect`
//! is a read, so the write budget is unchanged, and a write still queued at the
//! end of the budget is an error to the flows, which is the truth of it.
//!
//! What the confirmation proves is that the value left this machine, as
//! `set_value` judges it — enough nodes answered its fanout to call the write
//! done rather than queue it. It does not prove every holder has it, and
//! on a slot anyone may write it does not prove the bytes there are this
//! node's rather than a later writer's — the flows read a slot back after
//! writing it and re-pick on a clobber, and that stays their job.
//!
//! ## The synchronous seam
//!
//! [`Records`] is synchronous and every transport path here is `async`, so each
//! method bridges with [`tokio::task::block_in_place`] around
//! [`Handle::block_on`]. **That is correct only on a multi-thread runtime
//! worker**: `block_in_place` moves the current task's work off the worker so
//! the other tasks on it keep running, and on a current-thread runtime it
//! panics. The flavor is therefore checked at construction *and* at every
//! bridged call, because the value is [`Send`] and the thread that built it is
//! not necessarily the thread that uses it.
//!
//! This is the seam the two-node oracle drives, and it is deliberately the
//! narrowest thing that could be. A driver that wanted the flows on its own
//! loop would want an asynchronous trait in `daemonseed-core` instead, and
//! taking one later changes this module and no caller of it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use daemonseed_core::dm::advert::{AdvertOwnerSeed, ADVERT_SUBKEY};
use daemonseed_core::dm::channel::{ChannelOwnerSeed, CHANNEL_SUBKEYS, CONTROL_SUBKEY};
use daemonseed_core::dm::drop::{DropOwnerSeed, HELLO_LOOKUP_KEY_LEN};
use daemonseed_core::dm::flows::{RecordError, Records};
use daemonseed_core::identity::keys::{DmChannelRootSecret, SignKeypair};
use daemonseed_core::storage::seeds::AEAD_KEY_LEN;
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::sync::oneshot;
use veilid_core::{KeyPair, RoutingContext, ValueSeqNum, VeilidAPI};
use zeroize::Zeroizing;

use crate::actor::{funnel_record_key, gated_bounded_get, ProdWrite};
use crate::dht_gate::DhtGate;
use crate::dm::runner::{RecordFailure, RunnerConfig, RunnerParts, RunnerRecords, SubkeyReport};
use crate::error::{Result, VeilidNetError};
use crate::identity;
use crate::rendezvous::{self, RecordShape, RendezvousHandle};
use crate::schedule::{DirectMessageWrite, WriteRequest, WriteSchedulerHandle};

/// The node state a read reaches the network through.
///
/// Held as one value because the parts are not independent: the caches and the
/// locks are the ones the actor's own read and write paths use, so a record
/// store built over a private set of them would open records the rest of the
/// node already has open and serialize against nothing.
pub(crate) struct Transport {
    pub(crate) gate: Arc<DhtGate>,
    pub(crate) api: VeilidAPI,
    pub(crate) rc: RoutingContext,
    pub(crate) opened: Arc<rendezvous::OpenCache>,
    pub(crate) record_locks: Arc<rendezvous::RecordLocks>,
}

/// What [`VeilidRecords`] is built from: the node state reads reach the network
/// through, and the funnel every write goes through.
///
/// The two halves are separate because they are reached separately — a write
/// touches the scheduler and never the routing context, which is what lets the
/// write path be exercised without a node. Obtained from
/// [`VeilidNetHandle::dm_records_parts`](crate::VeilidNetHandle::dm_records_parts),
/// which is the only thing that can hand out the actor's own.
pub struct VeilidRecordsParts {
    pub(crate) transport: Transport,
    pub(crate) sched: WriteSchedulerHandle<ProdWrite>,
}

/// Why a [`VeilidRecords`] would not build, or would not bridge a call.
///
/// Both variants are about the runtime the caller is on, because that is the
/// one precondition this type has that a caller can get wrong and that no later
/// error would name: a method reached from the wrong runtime panics inside
/// tokio rather than returning, and the panic names `block_in_place`, not this
/// module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordsError {
    /// There is no tokio runtime on this thread.
    NoRuntime,
    /// The runtime on this thread is not multi-threaded, so the synchronous
    /// bridge every method uses would panic.
    NotMultiThread,
    /// A write or an erasure named a channel this process has not opened, so
    /// its owner keypair is not held.
    ChannelNotOpened,
    /// A subkey count outside the range a record can be addressed with.
    SubkeyCount(u16),
    /// A record's owner keypair would not derive from its seed.
    OwnerKey,
}

impl core::fmt::Display for RecordsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRuntime => f.write_str(
                "no tokio runtime on this thread: the record store bridges every \
                 synchronous method onto one",
            ),
            Self::NotMultiThread => f.write_str(
                "the tokio runtime on this thread is not multi-thread: the record \
                 store's synchronous bridge needs a multi-thread worker",
            ),
            Self::ChannelNotOpened => f.write_str(
                "this channel has not been opened in this process, so its owner \
                 keypair is not held: open it before writing it",
            ),
            Self::SubkeyCount(subkeys) => write!(
                f,
                "subkey count {subkeys} is outside 1..={} — it is part of the record \
                 address, so no record can be named with it",
                rendezvous::MAX_SUBKEY_COUNT
            ),
            Self::OwnerKey => {
                f.write_str("the record's owner keypair would not derive from its seed")
            }
        }
    }
}

impl core::error::Error for RecordsError {}

/// How many writes of each kind one record store has submitted.
///
/// § Write budget states a ceiling per flow — four writes for a first contact,
/// one for an ordinary message, at most one cursor per collection batch — and a
/// count per kind is what turns that into something a caller can assert. The
/// kinds are separated because the budgets are: a single total cannot tell a
/// hello from the message slot it opened a conversation with.
#[derive(Debug, Default)]
struct WriteCounts {
    hello: AtomicU64,
    erase: AtomicU64,
    control: AtomicU64,
    ring: AtomicU64,
    advert: AtomicU64,
}

impl WriteCounts {
    /// Charge one write of `kind`.
    fn charge(&self, kind: DirectMessageWrite) {
        let counter = match kind {
            DirectMessageWrite::Hello => &self.hello,
            DirectMessageWrite::HelloErase | DirectMessageWrite::ChannelErase => &self.erase,
            DirectMessageWrite::ChannelOpening
            | DirectMessageWrite::Cursor
            | DirectMessageWrite::ClosedMarker => &self.control,
            DirectMessageWrite::MessageSlot | DirectMessageWrite::SlotRepair => &self.ring,
            DirectMessageWrite::Advert => &self.advert,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// What has been charged so far.
    fn snapshot(&self) -> WriteCountsSnapshot {
        WriteCountsSnapshot {
            hello: self.hello.load(Ordering::Relaxed),
            erase: self.erase.load(Ordering::Relaxed),
            control: self.control.load(Ordering::Relaxed),
            ring: self.ring.load(Ordering::Relaxed),
            advert: self.advert.load(Ordering::Relaxed),
        }
    }
}

/// One record store's writes so far, counted per record kind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WriteCountsSnapshot {
    /// Hellos written into a drop slot.
    pub hello: u64,
    /// Erasures: a drop slot emptied, or a channel record deleted.
    pub erase: u64,
    /// Writes of a channel's control subkey — an opening, a cursor, a closed
    /// marker.
    pub control: u64,
    /// Writes of a channel's message ring — a message, or a repair of one.
    pub ring: u64,
    /// Advert publications.
    pub advert: u64,
}

impl WriteCountsSnapshot {
    /// Every write except the advert's.
    ///
    /// An advert is published on the layer's own weekly schedule rather than by
    /// any flow, so it is counted apart from the writes § Write budget's flows
    /// are measured in.
    pub fn flow_writes(&self) -> u64 {
        self.hello + self.erase + self.control + self.ring
    }
}

/// The funnel half of the record store: what a write does, and nothing a read
/// needs.
struct Writer {
    sched: WriteSchedulerHandle<ProdWrite>,
    counts: WriteCounts,
}

impl Writer {
    fn new(sched: WriteSchedulerHandle<ProdWrite>) -> Self {
        Self {
            sched,
            counts: WriteCounts::default(),
        }
    }

    /// Submit one write to the funnel and wait for its reply.
    ///
    /// The wait is what makes a synchronous method mean what it says: the flows
    /// order every persist before the write it enables and count writes against
    /// the budget, and a method that returned at enqueue would report a write
    /// that had not happened and might still fail.
    ///
    /// Charged before it is submitted, so a write the scheduler then refuses is
    /// still counted: the budget is about how many writes the layer *attempts*,
    /// which is what the substrate's rate ceiling is measured against.
    fn submit(
        &self,
        record: [u8; 32],
        kind: DirectMessageWrite,
        write: RecordWrite,
    ) -> core::result::Result<(), RecordError> {
        wait_for_reply(self.send(record, kind, write))
    }

    /// Charge one write and hand it to the funnel, returning where its reply
    /// will arrive.
    fn send(
        &self,
        record: [u8; 32],
        kind: DirectMessageWrite,
        write: RecordWrite,
    ) -> oneshot::Receiver<Result<()>> {
        self.counts.charge(kind);
        let (reply, replied) = oneshot::channel();
        self.sched.enqueue(WriteRequest::direct_message(
            record,
            kind,
            ProdWrite::DmRecord(write),
            Some(reply),
        ));
        replied
    }
}

/// Wait for a submitted write's reply.
///
/// A reply the scheduler dropped without sending is a refusal, not a local
/// one: the scheduler may have dispatched the write before it went, so the
/// write may have been sent.
fn wait_for_reply(replied: oneshot::Receiver<Result<()>>) -> core::result::Result<(), RecordError> {
    block(async move {
        replied
            .await
            .map_err(|_| VeilidNetError::Actor("the write scheduler dropped the reply".into()))?
    })
    .map_err(RecordError::new)
}

/// A channel record this side owns, as [`Records::open_channel`] left it.
///
/// The keypair is what a later [`Records::write_channel`] signs with, and the
/// shape is the subkey count that channel was addressed under. Both are held
/// because the trait's write method takes neither: a lookup key is a public key
/// and a public key is not a write capability, and it carries no subkey count.
struct OwnChannel {
    owner: KeyPair,
    shape: RecordShape,
}

/// What one pass over a drop found the network holding, before any slot was
/// read.
///
/// Scoped to one scan and to one drop: it is a snapshot of an instant, and a
/// slot written after it was taken is found by the next scan. Nothing decides
/// on it except which slots are worth a read, so a stale entry costs a read or
/// defers a hello to the next poll — never a wrong answer about a hello that
/// was read.
struct DropScan {
    owner: [u8; 32],
    populated: Vec<bool>,
}

impl DropScan {
    /// Whether this scan is of the drop `owner` owns.
    fn covers(&self, owner: &[u8; 32]) -> bool {
        &self.owner == owner
    }

    /// Whether `slot` is worth a read.
    ///
    /// A slot past what the scan covers is read: a report that did not reach a
    /// slot says nothing about it, and skipping it on that basis would hide a
    /// hello.
    fn needs_get(&self, slot: u16) -> bool {
        self.populated
            .get(usize::from(slot))
            .copied()
            .unwrap_or(true)
    }
}

/// The direct-messaging record store over the Veilid distributed hash table.
///
/// **Every method must be called from a multi-thread tokio runtime worker.**
/// The trait is synchronous and the transport is not, so each method blocks the
/// current worker on the transport future through
/// [`tokio::task::block_in_place`], which panics on a current-thread runtime.
/// [`Self::new`] refuses to build anywhere that would panic and every bridged
/// call re-checks, because this value is [`Send`] and may be used from a thread
/// other than the one that built it.
pub struct VeilidRecords {
    transport: Transport,
    writer: Writer,
    /// The channels this side owns, by the lookup key
    /// [`Records::open_channel`] returned for each.
    ///
    /// Populated by `open_channel` and read by `write_channel`, so a channel
    /// this process has not opened cannot be written by it. That is the
    /// contract rather than a limitation: a relaunch re-derives its own
    /// channels' owner seeds from the identity, the correspondent and the
    /// generation its store holds, and opens them again before it writes.
    own_channels: HashMap<[u8; HELLO_LOOKUP_KEY_LEN], OwnChannel>,
    /// What the current scan of a drop found, where one is in progress.
    drop_scan: Option<DropScan>,
    /// The failure of the last scan a slot read took, until the runner takes
    /// it through [`RunnerRecords::take_scan_failure`].
    scan_failure: Option<RecordError>,
}

impl core::fmt::Debug for VeilidRecords {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VeilidRecords")
            .field("own_channels", &self.own_channels.len())
            .field("writes", &self.writer.counts.snapshot())
            .finish_non_exhaustive()
    }
}

impl VeilidRecords {
    /// Build a record store over the transport `parts` describe.
    ///
    /// Fails where the current thread is not a multi-thread runtime worker —
    /// see the type's own documentation for why that is checked here as well as
    /// at every call.
    pub fn new(parts: VeilidRecordsParts) -> core::result::Result<Self, RecordsError> {
        require_multi_thread()?;
        Ok(Self {
            transport: parts.transport,
            writer: Writer::new(parts.sched),
            own_channels: HashMap::new(),
            drop_scan: None,
            scan_failure: None,
        })
    }

    /// How many writes of each kind this store has submitted.
    pub fn write_counts(&self) -> WriteCountsSnapshot {
        self.writer.counts.snapshot()
    }

    /// Erase a channel record this side owns — the delete flow's teardown of
    /// `docs/design/direct-messaging.md` § Delivery.
    ///
    /// Not a trait method: the flows never erase a channel, because a
    /// conversation is torn down by the party that decides to, not by a step of
    /// first contact or of an ordinary message. `lookup_key` must name a
    /// channel [`Records::open_channel`] opened in this process: a lookup key
    /// is a public key, so the owner keypair a deletion needs is held only for
    /// the channels this process opened.
    ///
    /// **The deletion is local, and creates nothing.** A record this node does
    /// not hold is already in the state a deletion produces, so an absent one
    /// is a success and not an open. What Veilid removes is this node's own
    /// copy, and what it stops is this node refreshing it; storage nodes
    /// holding a copy keep serving it until they evict it. That is the whole of
    /// what an owner can do, and it is what § Delivery's teardown asks for: the
    /// record ends because nobody rewrites it. A caller that wants the
    /// correspondent to see the conversation closed writes the marker first,
    /// through [`Records::write_channel`].
    ///
    /// **A failed erase keeps the channel open.** The owner keypair stays held,
    /// so the delete can be retried in the same process. An erase that went
    /// through ends the channel, and this side does not write it again.
    pub fn erase_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> core::result::Result<(), RecordError> {
        let (kind, write) = channel_erase_write(self.own(lookup_key)?);
        let erased = self.write(*lookup_key, kind, write);
        release_erased(&mut self.own_channels, lookup_key, &erased);
        erased
    }

    /// Submit one subkey write to the funnel, wait for its reply, then wait for
    /// the network to hold it — the whole of what a write means here (§
    /// Confirmation in the module docs).
    fn write(
        &self,
        record: [u8; 32],
        kind: DirectMessageWrite,
        write: RecordWrite,
    ) -> core::result::Result<(), RecordError> {
        let target = write.confirm_target();
        self.writer.submit(record, kind, write)?;
        match target {
            Some(target) => self.confirm(kind, target),
            None => Ok(()),
        }
    }

    /// Poll the record until the network's sequence number for the written
    /// subkey has reached this node's, or the budget is spent.
    ///
    /// Reached the way a read reaches a record — under the record's lock for
    /// the open, then one bounded `inspect` under a read permit — and never
    /// from inside the funnel: the dispatch end runs under a write permit, and
    /// a read permit acquired there would be the cross-pool hold the gate
    /// forbids. Nothing is written by the poll; the flush Veilid queued is what
    /// moves the value, and the poll watches for it.
    fn confirm(
        &self,
        kind: DirectMessageWrite,
        target: ConfirmTarget,
    ) -> core::result::Result<(), RecordError> {
        let transport = &self.transport;
        let what = format!("{kind:?} write to subkey {}", target.subkey);
        block(confirm_on_network(
            &what,
            CONFIRM_BUDGET,
            (CONFIRM_POLL_FIRST, CONFIRM_POLL_MAX),
            || {
                let target = &target;
                async move {
                    let open = async {
                        let record_lock =
                            rendezvous::record_lock(&transport.record_locks, &target.owner.key());
                        let _open_guard = record_lock.lock().await;
                        rendezvous::open_cached_optional(
                            &transport.opened,
                            &rendezvous::cached_record_id(&target.owner.key(), target.shape),
                            rendezvous::open_only(
                                &transport.gate,
                                &transport.api,
                                &transport.rc,
                                &target.owner,
                                target.shape,
                            ),
                        )
                        .await
                    };
                    confirm_probe(target.subkey, open, |handle| async move {
                        rendezvous::inspect_local_pending(&transport.gate, &transport.rc, &handle)
                            .await
                    })
                    .await
                }
            },
        ))
        .map_err(RecordError::new)
    }

    /// Publish this identity's advert to subkey 0 of its advert record —
    /// § Flows' precondition, the record a first contact reads.
    ///
    /// Not a trait method: the flows read an advert and never write one,
    /// because publishing is the advert schedule's job — weekly rotation and a
    /// rewrite on detected loss — rather than a step of any flow.
    pub fn publish_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
        bytes: &[u8],
    ) -> core::result::Result<(), RecordError> {
        let (record, write) = subkey_write(owner.as_bytes(), subkeys, ADVERT_SUBKEY, bytes)?;
        self.write(record, DirectMessageWrite::Advert, write)
    }

    /// Every subkey of the channel at `lookup_key`, as this node's sequence
    /// number beside the network's — the report
    /// `docs/design/direct-messaging.md` § Eviction detection reads an eviction
    /// from.
    ///
    /// Two reads: a `Local` inspect for this node's numbers and for which
    /// subkeys Veilid still has queued for its background flush, and a
    /// `SyncSet` inspect for the network's numbers, which reports as if the
    /// local copy did not exist. Both reports must start at subkey 0. A channel
    /// this process opened is opened under the owner keypair and the shape it
    /// was opened with; any other is opened read-only under [`CHANNEL_SUBKEYS`].
    /// A record this node does not hold reports no number on either side, and so
    /// does a subkey past the end of a report that did not reach it.
    ///
    /// A report that comes back with no network numbers is the network holding
    /// no copy: Veilid builds it that way whenever its fanout gathered no copy of
    /// the record (`veilid-core-0.5.7 src/storage_manager/inspect_record.rs:257-262`),
    /// and the report carries no count of the nodes reached
    /// (`src/veilid_api/types/dht/dht_record_report.rs:13-23`). A node that could
    /// not ask gets an error instead: an inspect issued while it is not online is
    /// refused with `TryAgain` (`src/storage_manager/inspect_record.rs:205-206`),
    /// retried here and returned as an error once the retries are spent, and a
    /// read that runs past its bound is an error too.
    pub fn inspect_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        let own = self
            .own_channels
            .get(lookup_key)
            .map(|own| (own.owner.clone(), own.shape));
        let shape = match &own {
            Some((_, shape)) => *shape,
            None => shape_of(CHANNEL_SUBKEYS)?,
        };
        let transport = &self.transport;
        let lookup_key = *lookup_key;
        block(retry_transient("dm records channel inspect", || {
            let own = own.clone();
            async move {
                let owner = identity::owner_public_key(&lookup_key);
                let handle = {
                    let record_lock = rendezvous::record_lock(&transport.record_locks, &owner);
                    let _open_guard = record_lock.lock().await;
                    let id = rendezvous::cached_record_id(&owner, shape);
                    match own {
                        Some((keypair, _)) => {
                            rendezvous::open_cached_optional(
                                &transport.opened,
                                &id,
                                rendezvous::open_only(
                                    &transport.gate,
                                    &transport.api,
                                    &transport.rc,
                                    &keypair,
                                    shape,
                                ),
                            )
                            .await?
                        }
                        None => {
                            rendezvous::open_cached_optional(
                                &transport.opened,
                                &id,
                                rendezvous::open_read_only(
                                    &transport.gate,
                                    &transport.api,
                                    &transport.rc,
                                    &lookup_key,
                                    shape,
                                ),
                            )
                            .await?
                        }
                    }
                };
                inspect_both(transport, handle, shape.o_cnt()).await
            }
        }))
        .map_err(RecordError::new)
    }

    /// Every subkey of the advert record the seed owns, as this node's sequence
    /// number beside the network's — what an advert repair decides from.
    ///
    /// The same two reads as [`Self::inspect_channel`], over a record opened
    /// without creating it.
    pub fn inspect_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        self.inspect_record(owner.as_bytes(), subkeys)
    }

    /// Every slot of the drop the seed owns, as this node's sequence number
    /// beside the network's — how a sender learns that the hello it placed
    /// there is no longer what the network holds.
    ///
    /// The same two reads as [`Self::inspect_channel`], over a record opened
    /// without creating it. The scan [`Records::read_drop_slot`] keeps is left
    /// as it is: an inspect writes nothing.
    pub fn inspect_drop(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        self.inspect_record(owner.as_bytes(), subkeys)
    }

    /// Every subkey of the record `owner_seed` owns, inspected on both sides.
    fn inspect_record(
        &self,
        owner_seed: &[u8; 32],
        subkeys: u16,
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        let shape = shape_of(subkeys)?;
        let owner = &owner_keypair(owner_seed)?;
        let transport = &self.transport;
        block(retry_transient("dm records inspect", || async move {
            let handle = open_for_read(transport, owner, shape).await?;
            inspect_both(transport, handle, subkeys).await
        }))
        .map_err(RecordError::new)
    }

    /// The channel this side owns under `lookup_key`, or a refusal naming what
    /// the caller has to do first.
    fn own(
        &self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> core::result::Result<&OwnChannel, RecordError> {
        self.own_channels
            .get(lookup_key)
            .ok_or_else(|| RecordError::new(RecordsError::ChannelNotOpened))
    }

    /// Read one subkey of the record `owner_seed` owns, under `subkeys`.
    ///
    /// `Ok(None)` is an empty or absent subkey — the ordinary state of a record
    /// nobody has written yet, and of one a storage node has evicted — and is
    /// deliberately distinct from `Err`, which is the transport failing to
    /// answer. The open does not create: a read that materialized the record it
    /// was reading would turn "not written" into "written empty by me".
    fn read_subkey(
        &mut self,
        owner_seed: &[u8; 32],
        subkeys: u16,
        subkey: u32,
    ) -> core::result::Result<Option<Vec<u8>>, RecordError> {
        let shape = shape_of(subkeys)?;
        let owner = &owner_keypair(owner_seed)?;
        let transport = &self.transport;
        block(retry_transient("dm records read", || async move {
            let Some(handle) = open_for_read(transport, owner, shape).await? else {
                return Ok(None);
            };
            get_subkey(&transport.gate, &transport.rc, &handle, subkey).await
        }))
        .map_err(RecordError::new)
    }

    /// Drop the scan of `owner_seed`'s drop, if it is the current one.
    ///
    /// **A write to a drop makes this process's snapshot of it wrong about the
    /// slot it just wrote.** A hello's read-back reads the slot it was placed
    /// in, and a scan taken before the write says that slot holds nothing — so
    /// the read-back would come back empty, the flow would read that as a
    /// clobbered slot, and it would re-pick and write a second time. The scan
    /// exists to save reads; it must never cost a write.
    fn forget_scan_of(&mut self, owner_seed: &[u8; 32]) {
        if self
            .drop_scan
            .as_ref()
            .is_some_and(|scan| scan.covers(owner_seed))
        {
            self.drop_scan = None;
        }
    }

    /// Take a scan of the drop `owner_seed` owns, for the pass beginning now.
    ///
    /// An error means the scan could not be taken and every slot is to be read —
    /// a transport that will not answer an inspect must never be read as a drop
    /// that holds nothing, because that would silently discard every hello in
    /// it. An absent record is the opposite case and is an answer: it has no
    /// slots at all, so the scan says so and the pass costs nothing.
    fn scan_drop(
        &self,
        owner_seed: &[u8; 32],
        subkeys: u16,
    ) -> core::result::Result<DropScan, RecordError> {
        let shape = shape_of(subkeys)?;
        let owner = &owner_keypair(owner_seed)?;
        let transport = &self.transport;
        let scanned = block(retry_transient("dm records drop inspect", || async move {
            let Some(handle) = open_for_read(transport, owner, shape).await? else {
                return Ok(None);
            };
            rendezvous::inspect_sync_set(&transport.gate, &transport.rc, &handle)
                .await
                .map(Some)
        }));
        match scanned {
            Ok(Some(seqs)) => Ok(DropScan {
                owner: *owner_seed,
                populated: populated_subkeys(&seqs, subkeys),
            }),
            Ok(None) => Ok(DropScan {
                owner: *owner_seed,
                populated: vec![false; usize::from(subkeys)],
            }),
            Err(e) => {
                crate::vtrace!("dm records: drop inspect failed ({e}); reading every slot");
                Err(RecordError::new(e))
            }
        }
    }
}

impl Records for VeilidRecords {
    fn read_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<Option<Vec<u8>>, RecordError> {
        self.read_subkey(owner.as_bytes(), subkeys, ADVERT_SUBKEY)
    }

    /// Read one drop slot, skipping the read where the network says the slot
    /// holds nothing.
    ///
    /// Slot 0 is the start of a pass over the whole drop, so it is where the
    /// scan is taken; every later slot of that pass is answered from it. A
    /// caller reading a single slot rather than scanning — a hello's read-back
    /// — reads through whatever scan is current, which either says the slot
    /// holds something and it is fetched, or is of another drop and ignored. A
    /// scan that fails leaves every slot to be read, and its failure is kept for
    /// [`RunnerRecords::take_scan_failure`], since the read itself goes on.
    fn read_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> core::result::Result<Option<Vec<u8>>, RecordError> {
        let owner_seed = *owner.as_bytes();
        if slot == 0 {
            self.drop_scan = match self.scan_drop(&owner_seed, subkeys) {
                Ok(scan) => Some(scan),
                Err(failure) => {
                    self.scan_failure = Some(failure);
                    None
                }
            };
        }
        if let Some(scan) = &self.drop_scan {
            if scan.covers(&owner_seed) && !scan.needs_get(slot) {
                return Ok(None);
            }
        }
        self.read_subkey(&owner_seed, subkeys, u32::from(slot))
    }

    fn write_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
        bytes: &[u8],
    ) -> core::result::Result<(), RecordError> {
        let (kind, record, write) = drop_slot_write(owner.as_bytes(), subkeys, slot, Some(bytes))?;
        self.forget_scan_of(owner.as_bytes());
        self.write(record, kind, write)
    }

    /// An erasure is a write of an empty value to the slot.
    ///
    /// A drop's owner key is derived from public information, so anyone can
    /// write any slot and nobody can delete the record; emptying the subkey is
    /// what the substrate offers in place of a delete, and it is one write like
    /// any other.
    ///
    /// Unlike a hello, an erasure keeps the current scan. The scan is forgotten
    /// on a hello because the hello's read-back would otherwise be answered
    /// from a snapshot that predates it; nothing reads an erased slot back
    /// expecting content, and the snapshot stays right about every other slot.
    /// Forgetting it here turned the rest of a collection pass — every slot
    /// after the one erased, 111 of them on a first contact — into a network
    /// read of an absent subkey each, ten minutes of a step that otherwise
    /// takes one. Keeping it costs at most one read, of the erased slot,
    /// answering empty.
    fn erase_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> core::result::Result<(), RecordError> {
        let (kind, record, write) = drop_slot_write(owner.as_bytes(), subkeys, slot, None)?;
        self.write(record, kind, write)
    }

    /// Open or create the channel record the seed owns, and return the lookup
    /// key a hello discloses for it.
    ///
    /// The lookup key is the owner's public key: it is what the record's
    /// address derives from, so it names the record exactly, and it is public
    /// by construction, so disclosing it in a hello discloses no write
    /// capability. The keypair and the shape are kept against the writes that
    /// follow, which address the record by that lookup key and so carry
    /// neither.
    fn open_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        let (shape, keypair, lookup_key) = channel_open_plan(owner.as_bytes(), subkeys)?;
        let transport = &self.transport;
        let opening = keypair.clone();
        block(retry_transient("dm records channel open", || {
            let opening = opening.clone();
            async move {
                let record_lock = rendezvous::record_lock(&transport.record_locks, &opening.key());
                let _open_guard = record_lock.lock().await;
                rendezvous::open_cached(
                    &transport.opened,
                    &rendezvous::cached_record_id(&opening.key(), shape),
                    rendezvous::open_or_create(
                        &transport.gate,
                        &transport.api,
                        &transport.rc,
                        &opening,
                        shape,
                    ),
                )
                .await
                .map(|_| ())
            }
        }))
        .map_err(RecordError::new)?;
        self.own_channels.insert(
            lookup_key,
            OwnChannel {
                owner: keypair,
                shape,
            },
        );
        Ok(lookup_key)
    }

    /// Read one subkey of the channel at `lookup_key`.
    ///
    /// A lookup key carries no subkey count, so the count is the one
    /// [`Records::open_channel`] recorded for a channel this side owns and
    /// [`CHANNEL_SUBKEYS`] for one it only reads. The two are the same number
    /// for every channel the flows open; holding the recorded one is what keeps
    /// that a fact about the record rather than an assumption about the layer.
    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> core::result::Result<Option<Vec<u8>>, RecordError> {
        let shape = self
            .own_channels
            .get(lookup_key)
            .map(|own| own.shape)
            .map_or_else(|| shape_of(CHANNEL_SUBKEYS), Ok)?;
        let transport = &self.transport;
        let lookup_key = *lookup_key;
        let subkey = u32::from(subkey);
        block(retry_transient("dm records channel read", || async move {
            let owner = identity::owner_public_key(&lookup_key);
            let handle = {
                let record_lock = rendezvous::record_lock(&transport.record_locks, &owner);
                let _open_guard = record_lock.lock().await;
                rendezvous::open_cached_optional(
                    &transport.opened,
                    &rendezvous::cached_record_id(&owner, shape),
                    rendezvous::open_read_only(
                        &transport.gate,
                        &transport.api,
                        &transport.rc,
                        &lookup_key,
                        shape,
                    ),
                )
                .await?
            };
            let Some(handle) = handle else {
                return Ok(None);
            };
            get_subkey(&transport.gate, &transport.rc, &handle, subkey).await
        }))
        .map_err(RecordError::new)
    }

    /// Write one subkey of the channel at `lookup_key`.
    ///
    /// The kind distinguishes the control subkey from a message slot, because
    /// § Write budget counts them separately.
    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> core::result::Result<(), RecordError> {
        let own = self.own(lookup_key)?;
        let write = RecordWrite {
            owner: own.owner.clone(),
            shape: own.shape,
            what: What::Subkey {
                subkey: u32::from(subkey),
                value: bytes.to_vec(),
            },
        };
        self.write(*lookup_key, channel_write_kind(subkey), write)
    }
}

impl RunnerRecords for VeilidRecords {
    /// A [`VeilidNetError::TimedOut`] ran out of time. That variant is built where
    /// the timeout is first seen, from the typed error: an open or a read cut
    /// off at its bound, a call Veilid answered with `Timeout`, and a write the
    /// network had not taken when its confirmation budget ran out. Local, never
    /// having reached the network: a [`RecordsError`] (an unopened channel, an
    /// unusable subkey count, an owner key that would not derive) and a
    /// [`VeilidNetError::Local`] (a runtime the bridge cannot use, a record this
    /// node just wrote and no longer holds, a write the scheduler never took
    /// because it is gone, or a call Veilid refused before sending it). Every
    /// other failure is a refusal: transient refusals whose retries were spent,
    /// and a [`VeilidNetError::Actor`], a reply the scheduler dropped or a
    /// dispatch task that panicked, which may come after the write was sent.
    fn classify(error: &RecordError) -> RecordFailure {
        let inner = error.inner();
        if inner.downcast_ref::<RecordsError>().is_some() {
            return RecordFailure::Local;
        }
        match inner.downcast_ref::<VeilidNetError>() {
            Some(VeilidNetError::TimedOut(_)) => RecordFailure::TimedOut,
            Some(VeilidNetError::Local(_)) => RecordFailure::Local,
            _ => RecordFailure::Refused,
        }
    }

    fn take_scan_failure(&mut self) -> Option<RecordError> {
        self.scan_failure.take()
    }

    /// The same [`RecordsError`], or a [`VeilidNetError::Local`] naming the same
    /// refusal.
    fn same_local_refusal(scan: &RecordError, read: &RecordError) -> bool {
        let (scan, read) = (scan.inner(), read.inner());
        match (
            scan.downcast_ref::<RecordsError>(),
            read.downcast_ref::<RecordsError>(),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => matches!(
                (
                    scan.downcast_ref::<VeilidNetError>(),
                    read.downcast_ref::<VeilidNetError>(),
                ),
                (Some(VeilidNetError::Local(a)), Some(VeilidNetError::Local(b))) if a == b
            ),
        }
    }

    fn inspect_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        VeilidRecords::inspect_channel(self, lookup_key)
    }

    fn inspect_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        VeilidRecords::inspect_advert(self, owner, subkeys)
    }

    fn inspect_drop(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<Vec<SubkeyReport>, RecordError> {
        VeilidRecords::inspect_drop(self, owner, subkeys)
    }

    fn publish_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
        bytes: &[u8],
    ) -> core::result::Result<(), RecordError> {
        VeilidRecords::publish_advert(self, owner, subkeys, bytes)
    }

    fn erase_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> core::result::Result<(), RecordError> {
        VeilidRecords::erase_channel(self, lookup_key)
    }

    /// Open the channel record the seed owns without creating it. `None` is
    /// Veilid finding no such record, which is not evidence that no node holds
    /// one; a record this node does not hold has no local copy to erase.
    fn open_existing_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        subkeys: u16,
    ) -> core::result::Result<Option<[u8; HELLO_LOOKUP_KEY_LEN]>, RecordError> {
        let (shape, keypair, lookup_key) = channel_open_plan(owner.as_bytes(), subkeys)?;
        let transport = &self.transport;
        let opening = keypair.clone();
        let opened = block(retry_transient(
            "dm records channel open without create",
            || {
                let opening = opening.clone();
                async move {
                    let record_lock =
                        rendezvous::record_lock(&transport.record_locks, &opening.key());
                    let _open_guard = record_lock.lock().await;
                    rendezvous::open_cached_optional(
                        &transport.opened,
                        &rendezvous::cached_record_id(&opening.key(), shape),
                        rendezvous::open_only(
                            &transport.gate,
                            &transport.api,
                            &transport.rc,
                            &opening,
                            shape,
                        ),
                    )
                    .await
                    .map(|handle| handle.is_some())
                }
            },
        ))
        .map_err(RecordError::new)?;
        if !opened {
            return Ok(None);
        }
        self.own_channels.insert(
            lookup_key,
            OwnChannel {
                owner: keypair,
                shape,
            },
        );
        Ok(Some(lookup_key))
    }

    fn write_counts(&self) -> WriteCountsSnapshot {
        VeilidRecords::write_counts(self)
    }
}

impl RunnerParts<VeilidRecords> {
    /// The parts of a runner over the Veilid distributed hash table: a
    /// [`VeilidRecords`] built from `parts`, and the identity, key and profile
    /// directory the runner needs beside it.
    ///
    /// Fails where [`VeilidRecords::new`] does, which is on any thread that is
    /// not a multi-thread tokio runtime worker.
    pub fn over_veilid(
        parts: VeilidRecordsParts,
        signer: Arc<SignKeypair>,
        channel_root: DmChannelRootSecret,
        at_rest_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
        profile_root: PathBuf,
        config: RunnerConfig,
    ) -> core::result::Result<Self, RecordsError> {
        Ok(Self {
            records: VeilidRecords::new(parts)?,
            signer,
            channel_root,
            at_rest_key,
            profile_root,
            config,
        })
    }
}

/// Both inspects of one open record, as one [`SubkeyReport`] per subkey.
///
/// `None` is a record this node does not hold, which reports no number on
/// either side for every subkey.
async fn inspect_both(
    transport: &Transport,
    handle: Option<RendezvousHandle>,
    subkeys: u16,
) -> Result<Vec<SubkeyReport>> {
    let Some(handle) = handle else {
        return Ok(vec![SubkeyReport::default(); usize::from(subkeys)]);
    };
    let local = rendezvous::inspect_local_pending(&transport.gate, &transport.rc, &handle).await?;
    let network = rendezvous::inspect_sync_set(&transport.gate, &transport.rc, &handle).await?;
    Ok(seq_reports(&local, &network, subkeys))
}

/// One report per subkey of an `o_cnt`-subkey record, from a `Local` report and
/// a positional list of network numbers.
///
/// A subkey past the end of either list has no number on that side: a report
/// that did not reach a subkey says nothing about it. A subkey Veilid still
/// has queued for its flush is marked pending, whatever its numbers say.
fn seq_reports(
    local: &rendezvous::LocalPending,
    network: &[ValueSeqNum],
    o_cnt: u16,
) -> Vec<SubkeyReport> {
    (0..o_cnt)
        .map(|subkey| {
            let i = usize::from(subkey);
            SubkeyReport {
                local_seq: local.seqs.get(i).and_then(|s| s.to_option()).map(u64::from),
                network_seq: network.get(i).and_then(|s| s.to_option()).map(u64::from),
                pending: local.pending.contains(u32::from(subkey)),
            }
        })
        .collect()
}

/// The record and subkey a submitted write is confirmed at.
///
/// Taken from the write before the funnel consumes it, because the confirmation
/// runs after the reply and the write is gone by then.
struct ConfirmTarget {
    owner: KeyPair,
    shape: RecordShape,
    subkey: u32,
}

/// One direct-messaging write, as the scheduler carries it to dispatch.
///
/// The owner keypair rides in the token because the write is owner-signed and
/// the dispatch end is what signs it. For an advert or a drop that keypair is
/// derived from public information and confers nothing; for a channel it is the
/// record's write capability, held for the length of the queue by the same
/// process that already holds it to have submitted the write at all.
pub(crate) struct RecordWrite {
    owner: KeyPair,
    shape: RecordShape,
    what: What,
}

/// What a [`RecordWrite`] does to the record it names.
enum What {
    /// Set one subkey. An empty value is an erasure of that subkey.
    Subkey { subkey: u32, value: Vec<u8> },
    /// Delete the record from this node's local store.
    Delete,
}

impl RecordWrite {
    /// Where to confirm this write once the funnel has performed it: the
    /// subkey it sets, or nothing for a delete, which is local and has no
    /// network state to reach.
    fn confirm_target(&self) -> Option<ConfirmTarget> {
        match &self.what {
            What::Subkey { subkey, .. } => Some(ConfirmTarget {
                owner: self.owner.clone(),
                shape: self.shape,
                subkey: *subkey,
            }),
            What::Delete => None,
        }
    }

    /// Perform the write. Called by the scheduler's dispatch end, under the
    /// permit its lane acquired.
    pub(crate) async fn dispatch(
        self,
        gate: &Arc<DhtGate>,
        api: &VeilidAPI,
        rc: &RoutingContext,
        opened: &rendezvous::OpenCache,
        record_locks: &rendezvous::RecordLocks,
    ) -> Result<()> {
        // Serialized against any other operation on this record, as every other
        // write path in this crate is: two writes to one record must not have
        // their opens interleaved, and a concurrent read of it must not race the
        // open either.
        let record_lock = rendezvous::record_lock(record_locks, &self.owner.key());
        let _write_guard = record_lock.lock().await;
        let id = rendezvous::cached_record_id(&self.owner.key(), self.shape);
        // Retried HERE rather than at submission, so a node that is not routable
        // yet costs attempts and not writes: one submission stays one entry on
        // the funnel and one charge against § Write budget, however many times
        // the transport had to be asked.
        match self.what {
            What::Subkey { subkey, value } => {
                retry_transient("dm records write", || async {
                    let handle = rendezvous::open_cached(
                        opened,
                        &id,
                        rendezvous::open_or_create(gate, api, rc, &self.owner, self.shape),
                    )
                    .await?;
                    rendezvous::publish_at_subkey(rc, &handle, &self.owner, subkey, value.clone())
                        .await
                })
                .await
            }
            What::Delete => {
                // Opened without creating: a record this node does not hold is
                // already in the state a deletion produces, and creating one in
                // order to delete it would put a record on the network that
                // nobody asked for.
                let opened_handle = retry_transient("dm records erase open", || {
                    rendezvous::open_cached_optional(
                        opened,
                        &id,
                        rendezvous::open_only(gate, api, rc, &self.owner, self.shape),
                    )
                })
                .await?;
                // Forgotten before the delete rather than after it: a failed
                // delete leaves a record whose local state this node has just
                // closed, so a cached handle to it is wrong either way.
                rendezvous::forget_cached(opened, &id);
                match opened_handle {
                    Some(handle) => {
                        retry_transient("dm records erase", || {
                            rendezvous::delete_record(rc, &handle)
                        })
                        .await
                    }
                    None => Ok(()),
                }
            }
        }
    }
}

/// Open the record `owner` owns for reading, without creating it.
async fn open_for_read(
    transport: &Transport,
    owner: &KeyPair,
    shape: RecordShape,
) -> Result<Option<RendezvousHandle>> {
    let record_lock = rendezvous::record_lock(&transport.record_locks, &owner.key());
    let _open_guard = record_lock.lock().await;
    rendezvous::open_cached_optional(
        &transport.opened,
        &rendezvous::cached_record_id(&owner.key(), shape),
        rendezvous::open_only(&transport.gate, &transport.api, &transport.rc, owner, shape),
    )
    .await
}

/// The owner keypair of the record `owner_seed` names, or
/// [`RecordsError::OwnerKey`] where it will not derive. Derived before any call
/// is bridged, so a read, a write and an open all refuse the same way.
fn owner_keypair(owner_seed: &[u8; 32]) -> core::result::Result<KeyPair, RecordError> {
    identity::rendezvous_owner_keypair(owner_seed)
        .map_err(|_| RecordError::new(RecordsError::OwnerKey))
}

/// The refusal a write's confirmation reaches when the record it just wrote is
/// not held here any more: something on this node removed it, so no probe of
/// the network can answer for it.
fn not_held_locally(subkey: u32) -> VeilidNetError {
    VeilidNetError::Local(format!(
        "{subkey}: the record this node just wrote is not held locally"
    ))
}

/// One bounded, permitted GET of `subkey`, as bytes or as an empty slot.
///
/// A subkey holding no bytes reads as `None`, the same as one never written.
/// An erasure of a world-writable slot *is* a write of no bytes, so the two are
/// one state to every reader, and the counting fake the flows are written
/// against returns `None` for both.
async fn get_subkey(
    gate: &Arc<DhtGate>,
    rc: &RoutingContext,
    handle: &RendezvousHandle,
    subkey: u32,
) -> Result<Option<Vec<u8>>> {
    let got = gated_bounded_get(
        gate,
        "dm records",
        rc.get_dht_value(handle.key().clone(), subkey, true),
    )
    .await?;
    Ok(got
        .map(|v| v.data().to_vec())
        .filter(|bytes| !bytes.is_empty()))
}

/// One flag per subkey of an `o_cnt`-subkey record: whether the network
/// reported a sequence number for it.
///
/// A report shorter than the record — which Veilid may return, since it reports
/// on the range it actually covered — leaves the subkeys it did not reach
/// readable, or a scan would skip slots on the strength of a report that never
/// looked at them.
fn populated_subkeys(network_seqs: &[ValueSeqNum], o_cnt: u16) -> Vec<bool> {
    (0..usize::from(o_cnt))
        .map(|i| match network_seqs.get(i) {
            Some(seq) => seq.to_option().is_some(),
            None => true,
        })
        .collect()
}

/// The record id and dispatch token for one write to a subkey of the record
/// `owner_seed` owns.
///
/// Every fallible thing a write decides before it reaches the funnel happens
/// here, and none of it touches the network: the subkey count becomes a shape,
/// the seed becomes the keypair the write is signed under, and the record id
/// the funnel orders on is the owner's public key. Separated from the method
/// that submits it so those decisions can be read back without a running node.
fn subkey_write(
    owner_seed: &[u8; 32],
    subkeys: u16,
    subkey: u32,
    value: &[u8],
) -> core::result::Result<([u8; 32], RecordWrite), RecordError> {
    let shape = shape_of(subkeys)?;
    let owner = owner_keypair(owner_seed)?;
    Ok((
        funnel_record_key(owner_seed),
        RecordWrite {
            owner,
            shape,
            what: What::Subkey {
                subkey,
                value: value.to_vec(),
            },
        },
    ))
}

/// Stop holding a channel whose erase went through, and keep one whose erase failed.
fn release_erased(
    own_channels: &mut HashMap<[u8; HELLO_LOOKUP_KEY_LEN], OwnChannel>,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    erased: &core::result::Result<(), RecordError>,
) {
    if erased.is_ok() {
        own_channels.remove(lookup_key);
    }
}

/// The kind and dispatch token for erasing a channel record this side owns.
///
/// A delete names no subkey: what it removes is the record, not a value in it,
/// which is the one thing an owner of a record only it writes can do that a
/// writer of a world-writable slot cannot.
fn channel_erase_write(own: &OwnChannel) -> (DirectMessageWrite, RecordWrite) {
    (
        DirectMessageWrite::ChannelErase,
        RecordWrite {
            owner: own.owner.clone(),
            shape: own.shape,
            what: What::Delete,
        },
    )
}

/// The kind, record id and dispatch token for one write to a drop slot.
///
/// `bytes` is the hello to place, or `None` for an erasure — which is a write
/// of no bytes to that slot, because a world-writable record offers no delete.
/// The kind follows from the same choice, so a caller cannot label an erasure a
/// hello or the other way round.
fn drop_slot_write(
    owner_seed: &[u8; 32],
    subkeys: u16,
    slot: u16,
    bytes: Option<&[u8]>,
) -> core::result::Result<(DirectMessageWrite, [u8; 32], RecordWrite), RecordError> {
    let kind = match bytes {
        Some(_) => DirectMessageWrite::Hello,
        None => DirectMessageWrite::HelloErase,
    };
    let (record, write) = subkey_write(
        owner_seed,
        subkeys,
        u32::from(slot),
        bytes.unwrap_or_default(),
    )?;
    Ok((kind, record, write))
}

/// Which kind of write one subkey of a channel is.
///
/// A control write is [`DirectMessageWrite::ChannelOpening`] and never
/// [`DirectMessageWrite::Cursor`], and that is exact rather than a guess the
/// transport had no way to make. The control record carries the opening in
/// every state it is ever written in — a write that left it out would erase it,
/// and its signature is randomized, so it cannot be rebuilt to the same bytes —
/// so every control write publishes the opening, and a cursor is what rides
/// along with it.
fn channel_write_kind(subkey: u16) -> DirectMessageWrite {
    if subkey == CONTROL_SUBKEY {
        DirectMessageWrite::ChannelOpening
    } else {
        DirectMessageWrite::MessageSlot
    }
}

/// The shape, owner keypair and lookup key for the channel `owner_seed` owns.
///
/// The lookup key is the owner's public key and is therefore a one-way function
/// of the seed: a hello discloses it and discloses no write capability with it.
fn channel_open_plan(
    owner_seed: &[u8; 32],
    subkeys: u16,
) -> core::result::Result<(RecordShape, KeyPair, [u8; HELLO_LOOKUP_KEY_LEN]), RecordError> {
    let shape = shape_of(subkeys)?;
    let keypair = owner_keypair(owner_seed)?;
    Ok((shape, keypair, funnel_record_key(owner_seed)))
}

/// How many times a network call is attempted before its refusal is an error.
///
/// Eight, whose sleeps sum to two minutes under the cap below — comfortably
/// inside a step's budget for one hop, and far longer than the seconds a node
/// spends unroutable after an attach.
const TRANSIENT_ATTEMPTS: u32 = 8;

/// How long the first retry waits. Each later one waits twice the last, to
/// [`TRANSIENT_BACKOFF_MAX`].
const TRANSIENT_BACKOFF: Duration = Duration::from_secs(2);

/// The longest a retry waits, however many have gone before.
const TRANSIENT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Whether a failure is this node not being ready yet rather than an answer
/// about the record.
///
/// Matched on the message because that is where it survives: Veilid's
/// `TryAgain` reaches this crate as the text of a [`VeilidNetError::Routing`]
/// or [`VeilidNetError::Send`], the variant having been flattened at the
/// boundary. The three needles are the shapes veilid-core produces for an
/// operation issued before the node can route — `TryAgain`, an `offline`
/// qualifier, and a not-ready routing table — and nothing else is treated as
/// retryable, because retrying a real refusal wastes a hop and hides it.
fn is_transient(error: &VeilidNetError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("tryagain") || text.contains("offline") || text.contains("not ready")
}

/// Run `make`'s future, retrying while it refuses transiently.
///
/// `make` builds a fresh future per attempt because a future is consumed by
/// being awaited: a retry is a new call, not a second poll of the old one. The
/// last error is returned where every attempt refused, so a caller sees what
/// the transport actually said rather than a count.
async fn retry_transient<T, F, Fut>(what: &str, mut make: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: core::future::Future<Output = Result<T>>,
{
    let mut wait = TRANSIENT_BACKOFF;
    for attempt in 1..=TRANSIENT_ATTEMPTS {
        match make().await {
            Ok(value) => return Ok(value),
            Err(e) if is_transient(&e) && attempt < TRANSIENT_ATTEMPTS => {
                crate::vtrace!(
                    "{what}: {e} (attempt {attempt} of {TRANSIENT_ATTEMPTS}); retrying in {wait:?}"
                );
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(TRANSIENT_BACKOFF_MAX);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("the loop returns on its last attempt")
}

/// How soon a confirmation looks again after finding the write still queued.
///
/// Two seconds, doubling to [`CONFIRM_POLL_MAX`]. A write that went out inside
/// `set_value` is never queued and its first probe confirms it, so this is
/// only ever waited by a write the node could not put out at once; Veilid's
/// flush ticks every second, so a short first wait catches a gap that opens
/// soon after the write.
const CONFIRM_POLL_FIRST: Duration = Duration::from_secs(2);

/// The longest a confirmation waits between probes, however many have found
/// the write still queued.
///
/// Ten seconds: the flush runs whenever the node is online, so a value leaves
/// the queue within seconds of the node being able to put it out, and a poll
/// much faster than this for the rest of the budget would spend read permits
/// watching for nothing.
const CONFIRM_POLL_MAX: Duration = Duration::from_secs(10);

/// The longest a write waits for the network to hold it.
///
/// Five minutes: on a network that answers, the write went out inside
/// `set_value` and the first poll confirms it; on one that comes and goes, this
/// is how long a sender waits for a gap the flush can use before the write is
/// reported as not done. A step's budget for one hop is longer, so an honest
/// failure here still names the write rather than the hop.
const CONFIRM_BUDGET: Duration = Duration::from_secs(300);

/// One subkey out of a `Local` report: `(its local sequence number, whether it
/// is still queued for the flush)`, in the order [`on_network`] takes them.
///
/// A subkey past the end of the sequence list reads as no number. Veilid
/// reports on the range it covered, and a request with no range names the
/// whole record up to its 1024-subkey limit, above every record this layer
/// shapes, so a short list here is a subkey the report has no answer for — a
/// miss, to be asked again, never a hit.
fn pending_at(report: &rendezvous::LocalPending, subkey: u32) -> (ValueSeqNum, bool) {
    let local = report
        .seqs
        .get(subkey as usize)
        .copied()
        .unwrap_or(ValueSeqNum::NONE);
    (local, report.pending.contains(subkey))
}

/// Whether a write left this machine: the subkey has a local sequence number
/// and is not queued for the flush.
///
/// Both are needed. No local number is a subkey this node never wrote, whatever
/// the queue says; a number with the subkey queued is a value `set_value`
/// could only keep here. Neither says anything about a later writer on a slot
/// anyone may write — that is read back by the flow that wrote it.
fn on_network(local: ValueSeqNum, pending: bool) -> bool {
    local.is_some() && !pending
}

/// Whether a failure is a call that ran out of time rather than an answer.
///
/// `gated_bounded_get` and `gated_bounded_open` abandon a call that has not
/// answered within its bound, and Veilid answers some calls with `Timeout`;
/// each is [`VeilidNetError::TimedOut`]. To a retry that is a real refusal,
/// because the hop was spent, but to a confirmation it is a poll with no answer,
/// and the next poll is the answer.
fn is_unanswered(error: &VeilidNetError) -> bool {
    matches!(error, VeilidNetError::TimedOut(_))
}

/// One confirmation probe: `open` opens the written record without creating
/// it, then `inspect` reads this node's numbers from it, and the result is
/// taken at `subkey`.
///
/// The funnel opened this record to write it, so a record this node does not
/// hold is not a state a confirmation can wait out: something removed it, and
/// [`not_held_locally`] is the answer.
async fn confirm_probe<H, O, I, F>(subkey: u32, open: O, inspect: I) -> Result<(ValueSeqNum, bool)>
where
    O: core::future::Future<Output = Result<Option<H>>>,
    I: FnOnce(H) -> F,
    F: core::future::Future<Output = Result<rendezvous::LocalPending>>,
{
    let Some(handle) = open.await? else {
        return Err(not_held_locally(subkey));
    };
    let report = inspect(handle).await?;
    Ok(pending_at(&report, subkey))
}

/// Poll `probe`, which reports the subkey's local sequence number and whether
/// it is still queued, until [`on_network`] holds or `budget` is spent.
///
/// A probe that refuses transiently is a poll like any other — the node not
/// being routable for a moment is the very condition the write is waiting out
/// — and so is one that ran out of time without an answer, because an
/// `inspect` abandoned at its bound says nothing about the record either way.
/// One that refuses for any other reason ends the wait with that reason.
/// The budget is checked after each miss, so a probe that answers late still
/// counts, and the error names the write and the time so a failing step says
/// which of its writes the network never took. The wait between probes starts
/// at `poll.0` and doubles to `poll.1`: short at first, when the write is most
/// likely to have just landed, and no faster than the flush it may be waiting
/// on after that. Each probe runs under what is left of the budget, its waits
/// for the record's lock and for a read permit included, so a probe that cannot
/// start does not hold the confirmation past its budget.
async fn confirm_on_network<F, Fut>(
    what: &str,
    budget: Duration,
    poll: (Duration, Duration),
    mut probe: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: core::future::Future<Output = Result<(ValueSeqNum, bool)>>,
{
    let started = tokio::time::Instant::now();
    let (first, max) = poll;
    let mut wait = first;
    let mut answered = false;
    let mut last_unanswered = String::new();
    loop {
        let remaining = budget.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, probe()).await {
            Err(_elapsed) => {
                crate::vtrace!("{what}: a probe was still waiting when the budget ran out");
                last_unanswered = "a probe still waiting when the budget ran out".to_owned();
            }
            Ok(Ok((local, pending))) if on_network(local, pending) => {
                crate::vtrace!(
                    "{what}: on the network (local {local:?}) after {:.1}s",
                    started.elapsed().as_secs_f64()
                );
                return Ok(());
            }
            Ok(Ok((local, pending))) => {
                answered = true;
                crate::vtrace!(
                    "{what}: not on the network yet (local {local:?}, queued {pending}) at {:.1}s",
                    started.elapsed().as_secs_f64()
                )
            }
            Ok(Err(e)) if is_transient(&e) || is_unanswered(&e) => {
                crate::vtrace!("{what}: confirmation got no answer ({e}); polling on");
                last_unanswered = e.to_string();
            }
            Ok(Err(e)) => return Err(e),
        }
        if started.elapsed() >= budget {
            // Only a probe that answered said anything about the network; one
            // that never did leaves the write unchecked, not absent.
            return Err(VeilidNetError::TimedOut(if answered {
                format!("{what}: not on the network after {}s", budget.as_secs())
            } else {
                format!(
                    "{what}: could not be checked within {}s, no probe was answered \
                     (the last: {last_unanswered})",
                    budget.as_secs()
                )
            }));
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(max);
    }
}

/// Run a transport future to completion from a synchronous method.
///
/// The flavor is checked here and not only at construction: [`VeilidRecords`]
/// is [`Send`], so the thread that built it need not be the thread using it,
/// and `block_in_place` panics rather than erroring on the wrong one.
fn block<T>(fut: impl core::future::Future<Output = Result<T>>) -> Result<T> {
    require_multi_thread().map_err(|e| VeilidNetError::Local(e.to_string()))?;
    tokio::task::block_in_place(|| Handle::current().block_on(fut))
}

/// Whether this thread's runtime is one the synchronous bridge is sound on.
fn require_multi_thread() -> core::result::Result<(), RecordsError> {
    let handle = Handle::try_current().map_err(|_| RecordsError::NoRuntime)?;
    if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) {
        Ok(())
    } else {
        Err(RecordsError::NotMultiThread)
    }
}

/// The record shape for a subkey count the flows supplied.
///
/// [`RecordShape::new`] panics outside Veilid's accepted range, which is right
/// where the count is a compile-time constant and wrong here: this count
/// arrives from a caller, so an unusable one is an error to report rather than
/// an abort.
fn shape_of(subkeys: u16) -> core::result::Result<RecordShape, RecordError> {
    if !(1..=rendezvous::MAX_SUBKEY_COUNT).contains(&subkeys) {
        return Err(RecordError::new(RecordsError::SubkeyCount(subkeys)));
    }
    Ok(RecordShape::new(subkeys))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How a failure is classified, from the code that produces it rather than
    /// from its text: an open Veilid answers with `Timeout` (which is also what
    /// an open cut off at its bound returns), a write or a deletion Veilid
    /// answers with `Timeout`, a read cut off at its bound or answered with
    /// `Timeout`, and a write the network had not taken when its confirmation
    /// budget ran out are timeouts. Any other refusal from the same code is a
    /// refusal, and a call refused before it reached the network is local.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_failure_is_classified_from_the_code_that_produced_it() {
        use veilid_core::VeilidAPIError;
        let classify = |error: VeilidNetError| {
            <VeilidRecords as RunnerRecords>::classify(&RecordError::new(error))
        };
        let try_again = || VeilidAPIError::TryAgain {
            message: "offline".to_owned(),
        };

        assert_eq!(
            classify(rendezvous::open_failure(
                "open_only",
                VeilidAPIError::Timeout
            )),
            RecordFailure::TimedOut
        );
        assert_eq!(
            classify(rendezvous::open_failure("open_only", try_again())),
            RecordFailure::Refused
        );
        assert_eq!(
            classify(rendezvous::write_failure(
                "set_dht_value",
                VeilidAPIError::Timeout
            )),
            RecordFailure::TimedOut
        );
        assert_eq!(
            classify(rendezvous::write_failure("set_dht_value", try_again())),
            RecordFailure::Refused
        );
        for local in [
            rendezvous::open_failure("open_only", VeilidAPIError::Shutdown),
            rendezvous::write_failure("delete_dht_record", VeilidAPIError::NotInitialized),
            not_held_locally(3),
        ] {
            let shown = local.to_string();
            assert_eq!(
                classify(local),
                RecordFailure::Local,
                "{shown} never reached the network"
            );
        }
        let unbridged =
            block(async { Ok(()) }).expect_err("a current-thread runtime cannot carry the bridge");
        assert_eq!(classify(unbridged), RecordFailure::Local);

        let gate = crate::dht_gate::DhtGate::with_pools(2, 1, 2, 1);
        let never = std::future::pending::<std::result::Result<Option<Vec<u8>>, VeilidAPIError>>();
        let abandoned = gated_bounded_get(&gate, "dm records", never)
            .await
            .expect_err("a read that never answers is abandoned");
        assert_eq!(classify(abandoned), RecordFailure::TimedOut);
        let answered_timeout = gated_bounded_get(&gate, "dm records", async {
            Err::<Option<Vec<u8>>, _>(VeilidAPIError::Timeout)
        })
        .await
        .expect_err("a read Veilid answers with Timeout fails");
        assert_eq!(classify(answered_timeout), RecordFailure::TimedOut);
        let refused_read = gated_bounded_get(&gate, "dm records", async {
            Err::<Option<Vec<u8>>, _>(try_again())
        })
        .await
        .expect_err("a read Veilid refuses fails");
        assert_eq!(classify(refused_read), RecordFailure::Refused);

        let unconfirmed = confirm_on_network(
            "advert write to subkey 0",
            Duration::from_secs(30),
            (Duration::from_secs(2), Duration::from_secs(10)),
            || async { Ok((seq(0), true)) },
        )
        .await
        .expect_err("the budget ends the wait");
        assert_eq!(classify(unconfirmed), RecordFailure::TimedOut);

        let unusable = shape_of(0).expect_err("no record has no subkeys");
        assert_eq!(
            <VeilidRecords as RunnerRecords>::classify(&unusable),
            RecordFailure::Local
        );
        let unopened = RecordError::new(RecordsError::ChannelNotOpened);
        assert_eq!(
            <VeilidRecords as RunnerRecords>::classify(&unopened),
            RecordFailure::Local
        );
    }

    use std::sync::Mutex;

    use daemonseed_core::dm::drop::DROP_SUBKEYS;

    use crate::schedule::{
        DispatchFuture, DispatchLane, DispatchOutcome, SchedulerConfig, WriteScheduler, WriteSink,
    };

    /// An owner seed, fixed so a run replays from the source alone.
    const SEED: [u8; 32] = [0x4du8; 32];

    /// A subkey count Veilid accepts becomes a shape with that count.
    #[test]
    fn a_usable_subkey_count_becomes_a_shape() {
        for subkeys in [1u16, CHANNEL_SUBKEYS, rendezvous::MAX_SUBKEY_COUNT] {
            let shape = shape_of(subkeys).expect("an accepted count");
            assert_eq!(shape.o_cnt(), subkeys, "the shape carries the count given");
        }
    }

    /// A count Veilid would reject is an error rather than a panic.
    ///
    /// The control is the case above: without it a `shape_of` that returned an
    /// error for every input would pass this test.
    #[test]
    fn an_unusable_subkey_count_is_refused() {
        for subkeys in [0u16, rendezvous::MAX_SUBKEY_COUNT + 1] {
            assert!(
                shape_of(subkeys).is_err(),
                "{subkeys} is outside the accepted range and must not name a record"
            );
        }
    }

    /// The bridge refuses the two runtimes it would panic on and accepts the
    /// one it needs.
    ///
    /// The multi-thread case is the control: a check that refused everything
    /// would satisfy the two refusals alone.
    #[test]
    fn only_a_multi_thread_runtime_carries_the_bridge() {
        assert_eq!(
            require_multi_thread(),
            Err(RecordsError::NoRuntime),
            "a plain test runs on no runtime, and there is nothing to block on"
        );

        let current = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime builds");
        assert_eq!(
            current.block_on(async { require_multi_thread() }),
            Err(RecordsError::NotMultiThread),
            "block_in_place panics on a current-thread runtime, so it must be refused"
        );

        let multi = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .expect("a multi-thread runtime builds");
        assert_eq!(
            multi.block_on(async { require_multi_thread() }),
            Ok(()),
            "a multi-thread runtime is the one flavor the bridge is sound on"
        );
    }

    /// Each refusal says which of the two it is.
    ///
    /// The text is what a caller sees: the two are distinguished by the thing
    /// the caller has to change, so a message naming neither would leave them
    /// guessing.
    #[test]
    fn each_refusal_names_what_is_wrong_with_the_runtime() {
        assert!(
            RecordsError::NotMultiThread
                .to_string()
                .contains("multi-thread"),
            "the wrong-flavor refusal names the flavor needed: {}",
            RecordsError::NotMultiThread
        );
        assert!(
            RecordsError::NoRuntime.to_string().contains("runtime"),
            "the absent-runtime refusal names the runtime: {}",
            RecordsError::NoRuntime
        );
    }

    /// A hello is shaped to its slot with its own bytes; an erasure to the same
    /// slot with none, under the kind that says so.
    ///
    /// The empty value is what the design rests on: a drop's owner key is
    /// derived from public information, so the record cannot be deleted and
    /// emptying the subkey is the whole of an erasure. The hello is the
    /// control — without it a shaping step that dropped every value would
    /// satisfy the erase assertion alone.
    #[test]
    fn an_erase_shapes_an_empty_value_and_a_hello_does_not() {
        let (erase_kind, _, erase) =
            drop_slot_write(&SEED, DROP_SUBKEYS, 7, None).expect("the erase shapes");
        let (hello_kind, _, hello) =
            drop_slot_write(&SEED, DROP_SUBKEYS, 7, Some(&[1, 2, 3])).expect("the hello shapes");
        assert_eq!(erase_kind, DirectMessageWrite::HelloErase);
        assert_eq!(at_subkey(&erase), Some((7, 0)), "an erase writes no bytes");
        assert_eq!(hello_kind, DirectMessageWrite::Hello);
        assert_eq!(
            at_subkey(&hello),
            Some((7, 3)),
            "a hello writes its own bytes to its own slot"
        );
    }

    /// The control subkey is an opening and every ring slot is a message.
    #[test]
    fn a_channel_write_is_an_opening_only_at_the_control_subkey() {
        assert_eq!(
            channel_write_kind(CONTROL_SUBKEY),
            DirectMessageWrite::ChannelOpening
        );
        for subkey in [CONTROL_SUBKEY + 1, 7, CHANNEL_SUBKEYS - 1] {
            assert_eq!(
                channel_write_kind(subkey),
                DirectMessageWrite::MessageSlot,
                "subkey {subkey} is a message slot"
            );
        }
    }

    /// A channel is opened under the count it was given, and the lookup key it
    /// discloses is the owner's public key rather than the seed.
    ///
    /// The seed comparison is the one that matters: a hello carries the lookup
    /// key in the clear, so a lookup key that was the seed would publish the
    /// conversation's write capability to everyone holding the hello.
    #[test]
    fn a_channel_plan_discloses_a_public_key_and_never_the_seed() {
        let subkeys = CHANNEL_SUBKEYS + 1;
        let (shape, _, lookup_key) = channel_open_plan(&SEED, subkeys).expect("the plan shapes");
        assert_eq!(
            shape.o_cnt(),
            subkeys,
            "the shape carries the count the caller named, not a default"
        );
        assert_eq!(
            lookup_key,
            identity::rendezvous_owner_public_bytes(&SEED),
            "the lookup key is the owner's public key"
        );
        assert_ne!(lookup_key, SEED, "the lookup key must not be the seed");
    }

    /// A write is ordered on the record its owner's public key names, and
    /// addressed under the subkey count it was given.
    #[test]
    fn a_write_is_shaped_to_the_record_the_seed_owns() {
        let (record, write) = subkey_write(&SEED, DROP_SUBKEYS, 0, &[9]).expect("the write shapes");
        assert_eq!(
            record,
            funnel_record_key(&SEED),
            "the funnel orders on the owner's public key"
        );
        assert_eq!(
            write.shape.o_cnt(),
            DROP_SUBKEYS,
            "the shape carries the count the caller named"
        );
    }

    /// A subkey count the flows could not have meant is refused before a
    /// keypair is derived.
    #[test]
    fn an_unusable_count_shapes_no_write() {
        assert!(
            subkey_write(&SEED, 0, 0, &[]).is_err(),
            "a zero subkey count names no record"
        );
        assert!(drop_slot_write(&SEED, 0, 0, None).is_err());
        assert!(channel_open_plan(&SEED, 0).is_err());
    }

    /// A scan over a report naming two populated slots reads those two and no
    /// others.
    ///
    /// This is the whole of what makes a 256-slot collection affordable: one
    /// inspect, then a read per slot the network says holds something. The
    /// count is asserted rather than the flags, because the cost is the number
    /// of reads.
    #[test]
    fn a_scan_reads_only_the_slots_the_network_reports() {
        let mut seqs = vec![ValueSeqNum::NONE; usize::from(DROP_SUBKEYS)];
        seqs[3] = ValueSeqNum::ZERO;
        seqs[200] = ValueSeqNum::MAX;
        let scan = DropScan {
            owner: SEED,
            populated: populated_subkeys(&seqs, DROP_SUBKEYS),
        };
        let read: Vec<u16> = (0..DROP_SUBKEYS).filter(|s| scan.needs_get(*s)).collect();
        assert_eq!(read, vec![3, 200], "only the reported slots are read");
    }

    /// A report that does not cover the record leaves the rest readable.
    ///
    /// The control on the test above: a scan that skipped what it had not
    /// examined would hide every hello past the report's end, and the symptom
    /// would be a collection that silently found nothing.
    #[test]
    fn a_short_report_leaves_the_slots_it_missed_readable() {
        let scan = DropScan {
            owner: SEED,
            populated: populated_subkeys(&[ValueSeqNum::NONE, ValueSeqNum::NONE], DROP_SUBKEYS),
        };
        assert!(!scan.needs_get(0), "a reported empty slot is not read");
        assert!(
            scan.needs_get(2),
            "a slot past the report's end must still be read"
        );
    }

    /// A scan answers only for the drop it was taken of.
    #[test]
    fn a_scan_of_another_drop_is_not_consulted() {
        let scan = DropScan {
            owner: SEED,
            populated: vec![false; usize::from(DROP_SUBKEYS)],
        };
        assert!(scan.covers(&SEED));
        assert!(!scan.covers(&[0x11u8; 32]));
    }

    /// Every write kind lands on the counter its budget is measured in.
    #[test]
    fn each_write_kind_is_counted_under_its_own_budget() {
        let counts = WriteCounts::default();
        for kind in DirectMessageWrite::ALL {
            counts.charge(kind);
        }
        let snapshot = counts.snapshot();
        assert_eq!(snapshot.hello, 1, "Hello");
        assert_eq!(snapshot.erase, 2, "HelloErase and ChannelErase");
        assert_eq!(
            snapshot.control, 3,
            "ChannelOpening, Cursor and ClosedMarker"
        );
        assert_eq!(snapshot.ring, 2, "MessageSlot and SlotRepair");
        assert_eq!(snapshot.advert, 1, "Advert");
        assert_eq!(
            snapshot.flow_writes(),
            DirectMessageWrite::ALL.len() as u64 - 1,
            "every kind but the advert is a flow write"
        );
    }

    /// A sink that records what the scheduler dispatched, and reports success.
    struct Recording {
        seen: Arc<Mutex<Vec<DirectMessageWrite>>>,
        kind: DirectMessageWrite,
    }

    impl WriteSink for Recording {
        type Item = ProdWrite;

        fn dispatch(&self, _item: ProdWrite, _lane: DispatchLane) -> DispatchFuture {
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(self.kind);
            Box::pin(async { DispatchOutcome::bare(Ok(())) })
        }
    }

    /// One submitted write is one write on the funnel, and one charge against
    /// its budget.
    ///
    /// **This is what pins § Write budget.** The flows count writes by counting
    /// calls, so a submission that enqueued twice — a retry, a rewrite, a
    /// duplicate on a reply path — would put the layer over a ceiling the
    /// substrate enforces, and nothing else here would report it.
    #[test]
    fn one_submission_is_one_write_on_the_funnel() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a multi-thread runtime builds");
        runtime.block_on(async {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let sched = WriteScheduler::spawn(
                Arc::new(Recording {
                    seen: Arc::clone(&seen),
                    kind: DirectMessageWrite::Hello,
                }),
                SchedulerConfig::default(),
            );
            let writer = Writer::new(sched);
            let (kind, record, write) =
                drop_slot_write(&SEED, DROP_SUBKEYS, 5, Some(&[7, 7])).expect("the hello shapes");
            let target = write
                .confirm_target()
                .expect("a subkey write is confirmed after the funnel");
            assert_eq!(
                (target.subkey, target.shape.o_cnt()),
                (5, DROP_SUBKEYS),
                "at the slot it wrote, in the record it wrote"
            );
            writer
                .submit(record, kind, write)
                .expect("the funnel takes the write");

            assert_eq!(
                seen.lock().unwrap_or_else(|e| e.into_inner()).len(),
                1,
                "one submission dispatches exactly one write"
            );
            assert_eq!(
                writer.counts.snapshot(),
                WriteCountsSnapshot {
                    hello: 1,
                    ..WriteCountsSnapshot::default()
                },
                "and charges exactly one hello"
            );
        });
    }

    /// A node that is not routable yet is retried; a real refusal is not.
    ///
    /// The first case is the one the oracle hit: a step's first call after an
    /// attach is answered `TryAgain: offline, try again later`, which says
    /// nothing about the record. The refusals below it are the control — a
    /// classifier that retried everything would turn an absent record into two
    /// minutes of waiting and then the same error.
    #[test]
    fn only_a_node_that_is_not_ready_yet_is_retried() {
        for text in [
            "TryAgain: offline, try again later",
            "open_or_create reopen: TryAgain",
            "the routing table is not ready",
            "OFFLINE",
        ] {
            assert!(
                is_transient(&VeilidNetError::Routing(text.to_owned())),
                "{text:?} is this node not being ready, and must be retried"
            );
        }
        for text in [
            "KeyNotFound",
            "sealed 40000 bytes exceeds the 16384-byte subkey cap of dflt(64) (re-chunk)",
            "subkey 300 is outside dflt(256)",
            "GET exceeded 15s, abandoned",
        ] {
            assert!(
                !is_transient(&VeilidNetError::Send(text.to_owned())),
                "{text:?} is an answer about the record, and must not be retried"
            );
        }
    }

    /// A call that refuses transiently and then answers is retried exactly as
    /// many times as it refused.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_transient_refusal_is_retried_until_it_answers() {
        let attempts = AtomicU64::new(0);
        let answered = retry_transient("fake", || async {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            if attempt < 3 {
                Err(VeilidNetError::Routing("TryAgain: offline".to_owned()))
            } else {
                Ok(attempt)
            }
        })
        .await
        .expect("the call answers once the node is ready");
        assert_eq!(answered, 3, "the answer is the fourth attempt's");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            4,
            "three refusals cost three retries and no more"
        );
    }

    fn seq(n: u32) -> ValueSeqNum {
        (0..=n).fold(ValueSeqNum::NONE, |s, _| s.next().expect("below the max"))
    }

    /// A write left this machine once its subkey has a local sequence number
    /// and is no longer queued for the flush, and not before.
    ///
    /// Each miss below is a real state: a subkey nobody wrote, whether or not
    /// something is queued under it, and a value this node wrote and could only
    /// keep. The hit is the one shape that means the write went out.
    #[test]
    fn a_write_is_on_the_network_once_it_has_a_number_and_is_not_queued() {
        for (local, pending) in [
            (ValueSeqNum::NONE, false),
            (ValueSeqNum::NONE, true),
            (seq(0), true),
            (seq(3), true),
        ] {
            assert!(
                !on_network(local, pending),
                "local {local:?} queued {pending} is not on the network"
            );
        }
        for local in [seq(0), seq(3)] {
            assert!(
                on_network(local, false),
                "local {local:?} not queued is on the network"
            );
        }
    }

    /// A confirmation polls through a transient refusal, a read cut off at its
    /// bound, a subkey with no number yet and a subkey still queued, and ends
    /// at the first probe that finds the write on the network.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_confirmation_polls_until_the_network_holds_the_write() {
        let probes = AtomicU64::new(0);
        confirm_on_network(
            "fake",
            Duration::from_secs(300),
            (Duration::from_secs(2), Duration::from_secs(10)),
            || async {
                match probes.fetch_add(1, Ordering::Relaxed) {
                    0 => Err(VeilidNetError::Routing("TryAgain: offline".to_owned())),
                    1 => Err(VeilidNetError::TimedOut(
                        "inspect_local_pending: GET exceeded 15s, abandoned".to_owned(),
                    )),
                    2 => Ok((ValueSeqNum::NONE, false)),
                    3 => Ok((seq(0), true)),
                    _ => Ok((seq(0), false)),
                }
            },
        )
        .await
        .expect("the fifth probe finds it");
        assert_eq!(probes.load(Ordering::Relaxed), 5, "and no probe after that");
    }

    /// A write the network never takes is an error naming the write and the
    /// budget, after the budget and not before, with the probes close together
    /// at first and no closer than the cap after that.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_write_the_network_never_holds_is_reported_after_the_budget() {
        let probes = AtomicU64::new(0);
        let refused = confirm_on_network(
            "advert write to subkey 0",
            Duration::from_secs(30),
            (Duration::from_secs(2), Duration::from_secs(10)),
            || async {
                probes.fetch_add(1, Ordering::Relaxed);
                Ok((seq(0), true))
            },
        )
        .await
        .expect_err("the budget ends the wait");
        let text = refused.to_string();
        assert!(
            text.contains("advert write to subkey 0")
                && text.contains("not on the network after 30s"),
            "the error names the write and the budget: {text}"
        );
        assert_eq!(
            probes.load(Ordering::Relaxed),
            6,
            "probes at 0, 2, 6, 14, 24 and 34 seconds, then the budget is spent"
        );
    }

    /// A confirmation whose probes all run out of time without an answer polls
    /// through each of them, whatever the timeout's text, and once the budget is
    /// spent reports the write as not checked rather than as not on the network.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_confirmation_no_probe_answered_says_it_could_not_check() {
        let probes = AtomicU64::new(0);
        let unchecked = confirm_on_network(
            "advert write to subkey 0",
            Duration::from_secs(30),
            (Duration::from_secs(2), Duration::from_secs(10)),
            || async {
                probes.fetch_add(1, Ordering::Relaxed);
                Err::<(ValueSeqNum, bool), _>(VeilidNetError::TimedOut(
                    "open_only: Timeout".to_owned(),
                ))
            },
        )
        .await
        .expect_err("the budget ends the wait");
        let text = unchecked.to_string();
        assert!(matches!(unchecked, VeilidNetError::TimedOut(_)), "{text}");
        assert!(
            text.contains("could not be checked") && !text.contains("not on the network"),
            "the error says the write went unchecked: {text}"
        );
        assert!(
            text.contains("open_only: Timeout"),
            "the error carries the last unanswered probe's own text: {text}"
        );
        assert_eq!(
            probes.load(Ordering::Relaxed),
            6,
            "an open that runs out of time is polled through, at 0, 2, 6, 14, 24 and 34 seconds"
        );
    }

    /// A confirmation's probe whose open runs out of time, as the open reports it,
    /// is polled through until the budget is spent, for both opens a probe of
    /// this layer's records goes through.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_confirmation_whose_open_times_out_polls_on() {
        use veilid_core::VeilidAPIError;
        for what in ["open_only", "open_read_only"] {
            let probes = AtomicU64::new(0);
            let unchecked = confirm_on_network(
                "hello write to subkey 5",
                Duration::from_secs(30),
                (Duration::from_secs(2), Duration::from_secs(10)),
                || {
                    probes.fetch_add(1, Ordering::Relaxed);
                    confirm_probe(
                        5,
                        async {
                            rendezvous::open_outcome(
                                what,
                                Err::<(), _>(VeilidAPIError::Timeout),
                                (),
                            )
                        },
                        |()| async { Err(VeilidNetError::Routing("never inspected".to_owned())) },
                    )
                },
            )
            .await
            .expect_err("the budget ends the wait");
            let text = unchecked.to_string();
            assert!(
                text.contains("could not be checked") && text.contains(what),
                "{what}: an open that timed out leaves the write unchecked: {text}"
            );
            assert_eq!(
                probes.load(Ordering::Relaxed),
                6,
                "{what}: the timed-out open is polled through"
            );
        }
    }

    /// A confirmation's probe that finds the written record no longer held on
    /// this node ends the confirmation at once, as a local refusal.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_confirmation_of_a_record_no_longer_held_ends_at_once() {
        let probes = AtomicU64::new(0);
        let ended = confirm_on_network(
            "hello write to subkey 5",
            Duration::from_secs(300),
            (Duration::from_secs(2), Duration::from_secs(10)),
            || {
                probes.fetch_add(1, Ordering::Relaxed);
                confirm_probe(
                    5,
                    async { Ok::<Option<()>, VeilidNetError>(None) },
                    |()| async { Err(VeilidNetError::Routing("never inspected".to_owned())) },
                )
            },
        )
        .await
        .expect_err("a record no longer held ends the wait");
        assert_eq!(
            probes.load(Ordering::Relaxed),
            1,
            "no probe after the first"
        );
        assert!(matches!(ended, VeilidNetError::Local(_)), "{ended}");
        assert_eq!(
            <VeilidRecords as RunnerRecords>::classify(&RecordError::new(ended)),
            RecordFailure::Local
        );
    }

    /// A probe waiting on a lock another holder never releases does not hold the
    /// confirmation past its budget.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_probe_waiting_on_a_held_lock_does_not_outlast_the_budget() {
        let lock = tokio::sync::Mutex::new(());
        let _held = lock.lock().await;
        let started = tokio::time::Instant::now();
        let unchecked = tokio::time::timeout(
            Duration::from_secs(600),
            confirm_on_network(
                "hello write to subkey 5",
                Duration::from_secs(30),
                (Duration::from_secs(2), Duration::from_secs(10)),
                || async {
                    let _guard = lock.lock().await;
                    Ok((seq(0), false))
                },
            ),
        )
        .await
        .expect("the confirmation returns once its budget is spent")
        .expect_err("the probe never answered");
        assert!(
            started.elapsed() <= Duration::from_secs(31),
            "it returned at its budget: {:?}",
            started.elapsed()
        );
        assert!(
            unchecked.to_string().contains("could not be checked"),
            "{unchecked}"
        );
    }

    /// A sink whose dispatch panics.
    struct Panicking;

    impl WriteSink for Panicking {
        type Item = ProdWrite;

        fn dispatch(&self, _item: ProdWrite, _lane: DispatchLane) -> DispatchFuture {
            Box::pin(async { panic!("the sink panics mid-dispatch") })
        }
    }

    /// The write scheduler's failures reach the runner classed by when they can
    /// happen: a scheduler already gone never took the write, which is local; a
    /// reply it dropped unsent and a dispatch that panicked may follow the
    /// write's send, which are refusals.
    #[test]
    fn a_scheduler_failure_is_local_only_before_the_write_was_taken() {
        let recording = || {
            Arc::new(Recording {
                seen: Arc::new(Mutex::new(Vec::new())),
                kind: DirectMessageWrite::Hello,
            })
        };
        let hello =
            || drop_slot_write(&SEED, DROP_SUBKEYS, 5, Some(&[7, 7])).expect("the hello shapes");
        let never_driven = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a current-thread runtime builds")
        };

        let idle = never_driven();
        let gone =
            Writer::new(idle.block_on(async {
                WriteScheduler::spawn(recording(), SchedulerConfig::default())
            }));
        drop(idle);
        let (kind, record, write) = hello();
        let gone_reply = gone.send(record, kind, write);

        let stalled = never_driven();
        let dropping =
            Writer::new(stalled.block_on(async {
                WriteScheduler::spawn(recording(), SchedulerConfig::default())
            }));
        let (kind, record, write) = hello();
        let dropped_reply = dropping.send(record, kind, write);
        drop(stalled);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a multi-thread runtime builds");
        runtime.block_on(async {
            let classify =
                |failure: RecordError| <VeilidRecords as RunnerRecords>::classify(&failure);
            let failure = wait_for_reply(gone_reply).expect_err("a scheduler already gone");
            assert_eq!(
                classify(failure),
                RecordFailure::Local,
                "a scheduler already gone never took the write"
            );
            let failure = wait_for_reply(dropped_reply)
                .expect_err("a scheduler that stopped with the write queued");
            assert_eq!(
                classify(failure),
                RecordFailure::Refused,
                "a reply dropped unsent may follow the write's send"
            );
            let panicking = Writer::new(WriteScheduler::spawn(
                Arc::new(Panicking),
                SchedulerConfig::default(),
            ));
            let (kind, record, write) = hello();
            let failure = panicking
                .submit(record, kind, write)
                .expect_err("a dispatch that panics");
            assert_eq!(
                classify(failure),
                RecordFailure::Refused,
                "a dispatch that panicked may follow the write's send"
            );
        });
    }

    /// A refusal that is an answer about the record ends the wait at once.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_real_refusal_ends_a_confirmation_at_once() {
        let probes = AtomicU64::new(0);
        let refused = confirm_on_network(
            "fake",
            Duration::from_secs(300),
            (Duration::from_secs(2), Duration::from_secs(10)),
            || async {
                probes.fetch_add(1, Ordering::Relaxed);
                Err(VeilidNetError::Send("KeyNotFound".to_owned()))
            },
        )
        .await
        .expect_err("the refusal is returned");
        assert!(
            refused.to_string().contains("KeyNotFound"),
            "as itself: {refused}"
        );
        assert_eq!(probes.load(Ordering::Relaxed), 1, "with no further probe");
    }

    /// A call that never answers gives up with what the transport last said,
    /// after the bounded number of attempts.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_refusal_that_never_lifts_gives_up_with_its_own_error() {
        let attempts = AtomicU64::new(0);
        let refused = retry_transient::<(), _, _>("fake", || async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(VeilidNetError::Routing(format!(
                "TryAgain: offline, attempt {}",
                attempts.load(Ordering::Relaxed)
            )))
        })
        .await
        .expect_err("a node that never becomes ready is an error");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            u64::from(TRANSIENT_ATTEMPTS),
            "it gives up after a bounded number of attempts"
        );
        assert!(
            refused
                .to_string()
                .contains(&format!("attempt {TRANSIENT_ATTEMPTS}")),
            "the error returned is the last one the transport gave: {refused}"
        );
    }

    /// A refusal that is not transient costs one attempt.
    ///
    /// The control on both tests above: a helper that retried regardless would
    /// pass them and turn every real refusal into a two-minute wait.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_refusal_that_is_not_transient_is_not_retried() {
        let attempts = AtomicU64::new(0);
        let refused = retry_transient::<(), _, _>("fake", || async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(VeilidNetError::Send("KeyNotFound".to_owned()))
        })
        .await
        .expect_err("a real refusal is an error");
        assert_eq!(attempts.load(Ordering::Relaxed), 1, "attempted once");
        assert!(refused.to_string().contains("KeyNotFound"));
    }

    /// A channel erase removes the record and names no subkey.
    ///
    /// The contrast with a drop erase is the whole point: a drop slot is
    /// emptied because nobody owns the record, and a channel record is deleted
    /// because one party does.
    #[test]
    fn a_channel_erase_removes_the_record_rather_than_a_value_in_it() {
        let (shape, owner, _) = channel_open_plan(&SEED, CHANNEL_SUBKEYS).expect("the plan shapes");
        let (kind, write) = channel_erase_write(&OwnChannel { owner, shape });
        assert_eq!(kind, DirectMessageWrite::ChannelErase);
        assert_eq!(
            at_subkey(&write),
            None,
            "a delete writes no value at any subkey"
        );
        assert_eq!(write.shape.o_cnt(), CHANNEL_SUBKEYS);
        assert!(
            write.confirm_target().is_none(),
            "and has no network state to wait for"
        );
    }

    /// A channel whose erase failed stays held, so the delete can be retried,
    /// and one whose erase went through is released.
    #[test]
    fn a_failed_channel_erase_keeps_the_channel_and_a_successful_one_releases_it() {
        let (shape, owner, lookup_key) =
            channel_open_plan(&SEED, CHANNEL_SUBKEYS).expect("the plan shapes");
        let mut own = HashMap::from([(lookup_key, OwnChannel { owner, shape })]);
        let refused = Err(RecordError::new(RecordsError::ChannelNotOpened));
        release_erased(&mut own, &lookup_key, &refused);
        assert!(
            own.contains_key(&lookup_key),
            "a failed erase keeps the channel"
        );
        release_erased(&mut own, &lookup_key, &Ok(()));
        assert!(
            !own.contains_key(&lookup_key),
            "an erase that went through releases it"
        );
    }

    /// A report is read at the written subkey — its own number, and whether it
    /// is queued — and a subkey the report did not reach reads as no number.
    ///
    /// The subkey is the whole test: read at the wrong one, a queued value
    /// confirms on the first probe because its neighbour went out, and the
    /// confirmation checks nothing, with every other test here still green.
    #[test]
    fn a_report_is_read_at_the_written_subkey() {
        assert_eq!(seq(3).to_option(), Some(3), "the helper counts from zero");
        let report = rendezvous::LocalPending {
            seqs: vec![seq(1), seq(4)],
            pending: veilid_core::ValueSubkeyRangeSet::single(1),
        };
        assert_eq!(pending_at(&report, 0), (seq(1), false));
        assert_eq!(pending_at(&report, 1), (seq(4), true));
        assert!(
            !on_network(pending_at(&report, 1).0, pending_at(&report, 1).1),
            "subkey 1 is a value this node could only keep"
        );
        assert_eq!(
            pending_at(&report, 2),
            (ValueSeqNum::NONE, false),
            "past the report is no number, not a number of zero"
        );
    }

    /// The slot a [`RecordWrite`] writes and how many bytes it puts there, or
    /// `None` where it writes no subkey.
    fn at_subkey(write: &RecordWrite) -> Option<(u32, usize)> {
        match &write.what {
            What::Subkey { subkey, value } => Some((*subkey, value.len())),
            What::Delete => None,
        }
    }
}
