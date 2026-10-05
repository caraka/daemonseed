//! The transport half of push delivery: the `app_call` lane a runner pushes
//! over and is pushed to, and the record store wrapper that makes a push of
//! the bytes a flow writes.
//!
//! `docs/design/direct-messaging.md` § Delivery, *Push*. The runner reaches the
//! network through a [`PushTransport`]: an `app_call` to a correspondent's
//! private-route blob, the allocation of this node's own route, and the answer
//! to a call it received. Calls addressed to the runner arrive on the
//! [`PushParts::inbound`] queue, beside notice of this node's routes dying and
//! of changes to the channel records it watches ([`crate::dm::watch`]).
//! That queue admits a message push only for a channel the runner reads, and
//! at most [`PUSH_PER_CHANNEL`] per channel and [`PUSH_ACCEPTANCES`]
//! acceptances at a time; a sender's own route is not known to the receiver,
//! so the channel a push names is what it is counted against. Watched changes
//! hold at most [`CHANGES_PER_CHANNEL`] places per channel and
//! [`CHANGES_QUEUED`] in all, so a burst of them leaves the rest of the queue
//! to pushes; a change refused a place is kept as missed against its channel,
//! and the receiver reads the conversation instead.
//! Every push starts with [`daemonseed_core::dm::push::PUSH_TAG`], which is how
//! the actor tells one from every other `app_call` it serves.
//!
//! `Pushing` wraps the record store a send or an acceptance is written
//! through. Before a ring slot is written, or once an acceptance offers its
//! writes, it starts a push of the same bytes on its own task and lets the
//! write go ahead: the write does not wait for the push, and the push does not
//! wait for the write. An answer the correspondent can make only with the conversation's control key
//! ([`daemonseed_core::dm::push::answer`]) reports the message delivered; any
//! other outcome forgets the correspondent's route and changes nothing else.
//!
//! Serves FC1.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use daemonseed_core::dm::advert::AdvertOwnerSeed;
use daemonseed_core::dm::channel::{self, ChannelOwnerSeed};
use daemonseed_core::dm::drop::{DropOwnerSeed, HELLO_LOOKUP_KEY_LEN};
use daemonseed_core::dm::flows::{AcceptanceWrites, BatchWrite, RecordError, Records};
use daemonseed_core::dm::push::{answer_matches, AnswerKey, Push, ANSWER_LEN};
use daemonseed_core::storage::dm_store::CorrespondenceLabel;
use tokio::sync::mpsc;
use veilid_core::{OperationId, RouteId, RoutingContext, Target, VeilidAPI};

use crate::dm::runner::RunnerEvent;

/// A boxed future a [`PushTransport`] returns.
pub type PushFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// How long a push waits for its answer before it counts as unanswered.
pub const PUSH_CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// How long after a call arrives its answer is still taken. A call older than
/// this when the runner reaches it is dropped unanswered.
pub const PUSH_ANSWER_WINDOW: Duration = Duration::from_secs(5);

/// Calls held for the runner at most; one more is dropped unanswered.
pub const PUSH_QUEUE: usize = 64;

/// Why a push transport call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushError(pub String);

impl core::fmt::Display for PushError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "push: {}", self.0)
    }
}

impl core::error::Error for PushError {}

/// This node's own private route: an id to recognise its death by, and the
/// blob a correspondent addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnRoute {
    /// The route's id, as [`PushInbound::RoutesDied`] names routes.
    pub id: String,
    /// The route blob published in the control subkey.
    pub blob: Vec<u8>,
}

/// What a runner pushes over.
pub trait PushTransport: Send + Sync + 'static {
    /// Make one `app_call` to the private route `route` and return its answer.
    fn call(&self, route: Vec<u8>, request: Vec<u8>) -> PushFuture<Result<Vec<u8>, PushError>>;

    /// Allocate a new private route for this node, releasing the one this
    /// transport allocated before.
    fn new_route(&self) -> PushFuture<Result<OwnRoute, PushError>>;

    /// Answer the call `call` with `answer`.
    fn reply(&self, call: u64, answer: Vec<u8>) -> PushFuture<Result<(), PushError>>;

    /// Release whatever [`PushTransport::call`] holds for the private route
    /// `route`. A later call to it takes it up again.
    fn release(&self, route: &[u8]);
}

/// What reaches a runner from its push transport.
#[derive(Debug)]
pub enum PushInbound {
    /// An `app_call` that starts with the push tag.
    Call {
        /// The id to answer it under.
        id: u64,
        /// The call's bytes.
        message: Vec<u8>,
        /// When it arrived.
        received: Instant,
    },
    /// Private routes this node held have died, by id.
    RoutesDied(Vec<String>),
    /// A watched channel record this node reads changed, as Veilid reported
    /// the change.
    Changed {
        /// The lookup key the channel is read under.
        lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
        /// The first subkey that changed; 0 where none is named.
        first_subkey: u32,
        /// Whether exactly one subkey changed.
        single: bool,
        /// Whether the report says the watch died: no subkeys named, or no
        /// reports left on the watch.
        dead: bool,
        /// The sequence number and bytes of the first subkey, where Veilid
        /// carried them, which it does only where one subkey changed.
        value: Option<(u32, Vec<u8>)>,
    },
}

/// Everything a runner needs to push and be pushed to.
pub struct PushParts {
    /// The outbound half.
    pub transport: Arc<dyn PushTransport>,
    /// The inbound half.
    pub inbound: PushInbox,
}

/// Message pushes naming one channel held queued at most; one more is shed.
pub const PUSH_PER_CHANNEL: usize = 4;

/// Acceptance pushes held queued at most; one more is shed.
pub const PUSH_ACCEPTANCES: usize = 4;

/// Watched changes held queued at most, over every channel. The rest of
/// [`PUSH_QUEUE`] stays open to calls whatever the watches report.
pub const CHANGES_QUEUED: usize = 16;

/// Watched changes on one channel held queued at most.
pub const CHANGES_PER_CHANNEL: usize = 4;

/// What a queued entry is counted against.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Charge {
    Channel([u8; HELLO_LOOKUP_KEY_LEN]),
    Acceptance,
    Change([u8; HELLO_LOOKUP_KEY_LEN]),
}

/// The kind and channel a call's bytes name, read without decoding the rest.
fn charge_of(message: &[u8]) -> Option<Charge> {
    let rest = message.strip_prefix(daemonseed_core::dm::push::PUSH_TAG.as_slice())?;
    match rest.first()? {
        1 => Some(Charge::Channel(
            rest.get(1..1 + HELLO_LOOKUP_KEY_LEN)?.try_into().ok()?,
        )),
        2 => Some(Charge::Acceptance),
        _ => None,
    }
}

/// The admission state a queue's two ends share.
#[derive(Default)]
struct Admission {
    /// Channels this side reads, which a message push must name.
    known: std::collections::HashSet<[u8; HELLO_LOOKUP_KEY_LEN]>,
    queued: std::collections::HashMap<Charge, usize>,
    /// Watched changes queued, over every channel.
    changes: usize,
    /// Channels with a watched change that was not queued, and whether one of
    /// those reported the watch dead.
    missed: std::collections::BTreeMap<[u8; HELLO_LOOKUP_KEY_LEN], bool>,
    shed: u64,
}

impl Admission {
    fn cap(charge: Charge) -> usize {
        match charge {
            Charge::Channel(_) => PUSH_PER_CHANNEL,
            Charge::Acceptance => PUSH_ACCEPTANCES,
            Charge::Change(_) => CHANGES_PER_CHANNEL,
        }
    }

    /// Count `charge` as queued where it has room, `false` where it has none.
    fn take_place(&mut self, charge: Charge) -> bool {
        if matches!(charge, Charge::Change(_)) && self.changes >= CHANGES_QUEUED {
            return false;
        }
        let queued = self.queued.entry(charge).or_default();
        if *queued >= Self::cap(charge) {
            return false;
        }
        *queued += 1;
        if matches!(charge, Charge::Change(_)) {
            self.changes += 1;
        }
        true
    }

    /// Release the place [`Self::take_place`] counted for `charge`.
    fn free_place(&mut self, charge: Charge) {
        if let Some(queued) = self.queued.get_mut(&charge) {
            *queued = queued.saturating_sub(1);
        }
        if matches!(charge, Charge::Change(_)) {
            self.changes = self.changes.saturating_sub(1);
        }
    }

    /// Note a watched change on `lookup_key` that was not queued.
    fn miss(&mut self, lookup_key: [u8; HELLO_LOOKUP_KEY_LEN], dead: bool) {
        *self.missed.entry(lookup_key).or_default() |= dead;
    }
}

/// The sending end of a runner's inbound push queue. A message push naming a
/// channel the runner does not read, a push past its channel's or the
/// acceptances' share of the queue, and any call that is not a push, are shed
/// and counted rather than queued.
#[derive(Clone)]
pub struct PushOutbox {
    tx: mpsc::Sender<PushInbound>,
    admission: Arc<Mutex<Admission>>,
}

/// The receiving end of a runner's inbound push queue.
pub struct PushInbox {
    rx: mpsc::Receiver<PushInbound>,
    admission: Arc<Mutex<Admission>>,
}

/// A push queue of [`PUSH_QUEUE`] entries.
pub fn push_queue() -> (PushOutbox, PushInbox) {
    let (tx, rx) = mpsc::channel(PUSH_QUEUE);
    let admission = Arc::new(Mutex::new(Admission::default()));
    (
        PushOutbox {
            tx,
            admission: Arc::clone(&admission),
        },
        PushInbox { rx, admission },
    )
}

fn lock(admission: &Mutex<Admission>) -> std::sync::MutexGuard<'_, Admission> {
    admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl PushOutbox {
    /// Queue `inbound` where it is admitted; `false` where it was shed or the
    /// queue is full or gone. A route death is always offered. A watched
    /// channel's change is queued while its channel holds fewer than
    /// [`CHANGES_PER_CHANNEL`] and all channels fewer than [`CHANGES_QUEUED`];
    /// one that is not queued is kept as missed, by channel, for
    /// [`PushInbox::take_missed`], and is not counted as shed.
    pub fn offer(&self, inbound: PushInbound) -> bool {
        let charge = match &inbound {
            PushInbound::RoutesDied(_) => None,
            PushInbound::Changed {
                lookup_key, dead, ..
            } => {
                let mut admission = lock(&self.admission);
                if !admission.take_place(Charge::Change(*lookup_key)) {
                    admission.miss(*lookup_key, *dead);
                    return false;
                }
                Some(Charge::Change(*lookup_key))
            }
            PushInbound::Call { message, .. } => {
                let mut admission = lock(&self.admission);
                let charge = charge_of(message).filter(|charge| match charge {
                    Charge::Channel(key) => admission.known.contains(key),
                    Charge::Acceptance => true,
                    Charge::Change(_) => false,
                });
                let Some(charge) = charge else {
                    admission.shed += 1;
                    return false;
                };
                if !admission.take_place(charge) {
                    admission.shed += 1;
                    return false;
                }
                Some(charge)
            }
        };
        let missed = match &inbound {
            PushInbound::Changed {
                lookup_key, dead, ..
            } => Some((*lookup_key, *dead)),
            PushInbound::RoutesDied(_) | PushInbound::Call { .. } => None,
        };
        if self.tx.try_send(inbound).is_ok() {
            return true;
        }
        let mut admission = lock(&self.admission);
        if let Some(charge) = charge {
            admission.free_place(charge);
            match missed {
                Some((lookup_key, dead)) => admission.miss(lookup_key, dead),
                None => admission.shed += 1,
            }
        }
        false
    }
}

impl PushInbox {
    fn taken(&self, inbound: &PushInbound) {
        let charge = match inbound {
            PushInbound::Call { message, .. } => charge_of(message),
            PushInbound::Changed { lookup_key, .. } => Some(Charge::Change(*lookup_key)),
            PushInbound::RoutesDied(_) => None,
        };
        if let Some(charge) = charge {
            lock(&self.admission).free_place(charge);
        }
    }

    /// The next entry, waiting for one.
    pub async fn recv(&mut self) -> Option<PushInbound> {
        let inbound = self.rx.recv().await?;
        self.taken(&inbound);
        Some(inbound)
    }

    /// The next entry, where one is queued.
    pub fn try_recv(&mut self) -> Option<PushInbound> {
        let inbound = self.rx.try_recv().ok()?;
        self.taken(&inbound);
        Some(inbound)
    }

    /// Take `known` as the channels this side reads, which a message push must
    /// name to be queued.
    pub fn set_known(&self, known: impl IntoIterator<Item = [u8; HELLO_LOOKUP_KEY_LEN]>) {
        lock(&self.admission).known = known.into_iter().collect();
    }

    /// The channels with a watched change that was not queued since the last
    /// call, each once, with whether one of those changes reported the watch
    /// dead.
    ///
    /// A change is refused only while an entry it would have followed is still
    /// queued, so a receiver that calls this after taking each entry learns of
    /// every refused change.
    pub fn take_missed(&self) -> Vec<([u8; HELLO_LOOKUP_KEY_LEN], bool)> {
        std::mem::take(&mut lock(&self.admission).missed)
            .into_iter()
            .collect()
    }

    /// How many calls have been shed since the queue was made.
    pub fn shed(&self) -> u64 {
        lock(&self.admission).shed
    }

    /// A handle on this queue's admission, for a holder other than the one
    /// that receives from it.
    pub(crate) fn admission(&self) -> Admitting {
        Admitting(Arc::clone(&self.admission))
    }
}

/// [`PushInbox::set_known`] and [`PushInbox::shed`] over a queue received from
/// elsewhere.
#[derive(Clone)]
pub(crate) struct Admitting(Arc<Mutex<Admission>>);

impl Admitting {
    /// [`PushInbox::set_known`].
    pub(crate) fn set_known(&self, known: impl IntoIterator<Item = [u8; HELLO_LOOKUP_KEY_LEN]>) {
        lock(&self.0).known = known.into_iter().collect();
    }

    /// [`PushInbox::shed`].
    pub(crate) fn shed(&self) -> u64 {
        lock(&self.0).shed
    }
}

impl core::fmt::Debug for PushParts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PushParts")
    }
}

/// Where the actor hands a runner the calls and route deaths addressed to it:
/// the sending end of the most recently built [`PushParts`], or none.
pub(crate) type PushLane = Arc<Mutex<Option<PushOutbox>>>;

/// Offer `inbound` to the runner on `lane`, if one is listening. What the
/// queue does not admit goes unanswered.
pub(crate) fn offer(lane: &PushLane, inbound: PushInbound) {
    let outbox = lane
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(outbox) = outbox {
        if !outbox.offer(inbound) {
            crate::vtrace!("dm push: an inbound push was not admitted");
        }
    }
}

/// Build the parts a runner pushes with over the node the actor runs, and make
/// its inbound queue the one the actor hands calls to.
pub(crate) fn veilid_parts(api: VeilidAPI, rc: RoutingContext, lane: &PushLane) -> PushParts {
    let (outbox, inbox) = push_queue();
    *lane
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outbox);
    PushParts {
        transport: Arc::new(VeilidPush {
            api,
            rc,
            own: Arc::new(Mutex::new(None)),
            imported: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }),
        inbound: inbox,
    }
}

/// [`PushTransport`] over a Veilid node.
struct VeilidPush {
    api: VeilidAPI,
    rc: RoutingContext,
    own: Arc<Mutex<Option<RouteId>>>,
    /// Correspondents' routes imported, by blob, until released.
    imported: Arc<Mutex<std::collections::HashMap<Vec<u8>, RouteId>>>,
}

impl VeilidPush {
    /// The imported id of `route`, importing it where it is not held.
    fn imported(&self, route: &[u8]) -> Result<RouteId, PushError> {
        let mut imported = self
            .imported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(id) = imported.get(route) {
            return Ok(id.clone());
        }
        let id = self
            .api
            .import_remote_private_route(route.to_vec())
            .map_err(|e| PushError(e.to_string()))?;
        imported.insert(route.to_vec(), id.clone());
        Ok(id)
    }
}

impl PushTransport for VeilidPush {
    fn call(&self, route: Vec<u8>, request: Vec<u8>) -> PushFuture<Result<Vec<u8>, PushError>> {
        let imported = self.imported(&route);
        let rc = self.rc.clone();
        Box::pin(async move {
            let id = imported?;
            match tokio::time::timeout(PUSH_CALL_TIMEOUT, rc.app_call(Target::RouteId(id), request))
                .await
            {
                Ok(Ok(answer)) => Ok(answer),
                Ok(Err(e)) => Err(PushError(e.to_string())),
                Err(_) => Err(PushError("no answer in time".to_owned())),
            }
        })
    }

    fn new_route(&self) -> PushFuture<Result<OwnRoute, PushError>> {
        let api = self.api.clone();
        let own = Arc::clone(&self.own);
        Box::pin(async move {
            let blob = api
                .new_private_route()
                .await
                .map_err(|e| PushError(e.to_string()))?;
            let previous = own
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .replace(blob.route_id.clone());
            if let Some(previous) = previous {
                if let Err(e) = api.release_private_route(previous) {
                    crate::vtrace!("dm push: releasing the replaced route failed ({e})");
                }
            }
            Ok(OwnRoute {
                id: blob.route_id.to_string(),
                blob: blob.blob,
            })
        })
    }

    fn reply(&self, call: u64, answer: Vec<u8>) -> PushFuture<Result<(), PushError>> {
        let api = self.api.clone();
        Box::pin(async move {
            api.app_call_reply(OperationId::new(call), answer)
                .await
                .map_err(|e| PushError(e.to_string()))
        })
    }

    fn release(&self, route: &[u8]) {
        let id = self
            .imported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(route);
        if let Some(id) = id {
            if let Err(e) = self.api.release_private_route(id) {
                crate::vtrace!("dm push: releasing a correspondent's route failed ({e})");
            }
        }
    }
}

/// What a push is made with: the transport, the correspondent's route, and
/// where its outcome goes.
#[derive(Clone)]
/// A push that went unanswered: its correspondent, and the route it was made
/// on, so only that route is forgotten.
pub(crate) struct Unanswered {
    pub(crate) peer: CorrespondenceLabel,
    pub(crate) route: Vec<u8>,
}

pub(crate) struct Pusher {
    pub(crate) transport: Arc<dyn PushTransport>,
    pub(crate) route: Vec<u8>,
    pub(crate) events: mpsc::Sender<RunnerEvent>,
    pub(crate) unanswered: mpsc::UnboundedSender<Unanswered>,
    /// This side's control key for the conversation, which a message push's
    /// answer is checked under.
    pub(crate) answer_key: Option<Arc<AnswerKey>>,
}

impl Pusher {
    /// Push the ring slot `bytes`, written to `subkey` of the channel at
    /// `lookup_key`, on its own task, where it decodes as a message and this
    /// pusher holds the key its answer is checked under.
    pub(crate) fn push_slot(
        &self,
        peer: CorrespondenceLabel,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) {
        let expected = channel::MessageHeader::decode(bytes)
            .ok()
            .zip(self.answer_key.as_deref())
            .and_then(|((header, _), key)| {
                Some((header.seq, key.answer(lookup_key, header.seq).ok()?))
            });
        if let Some((seq, expected)) = expected {
            self.start(
                peer,
                seq,
                &Push::Message {
                    lookup_key: *lookup_key,
                    subkey,
                    slot: bytes.to_vec(),
                },
                expected,
            );
        }
    }

    /// Push `push` on its own task. An answer equal to `expected` is reported
    /// as [`RunnerEvent::Delivered`] through `seq`; any other outcome names
    /// `peer` on the unanswered queue.
    fn start(&self, peer: CorrespondenceLabel, seq: u64, push: &Push, expected: [u8; ANSWER_LEN]) {
        let Some(bytes) = push.encode() else {
            crate::vtrace!("dm push: too large to push, left to the record store");
            return;
        };
        let call = self.transport.call(self.route.clone(), bytes);
        let events = self.events.clone();
        let unanswered = self.unanswered.clone();
        let route = self.route.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            match call.await {
                Ok(answer) if answer_matches(&expected, &answer) => {
                    crate::vtrace!(
                        "dm push: sequence {seq} recorded after {} ms",
                        started.elapsed().as_millis()
                    );
                    let _ = events
                        .send(RunnerEvent::Delivered {
                            peer,
                            through_seq: seq,
                        })
                        .await;
                }
                outcome => {
                    crate::vtrace!(
                        "dm push: sequence {seq} not recorded after {} ms ({:?})",
                        started.elapsed().as_millis(),
                        outcome.err()
                    );
                    let _ = unanswered.send(Unanswered { peer, route });
                }
            }
        });
    }
}

/// A record store that pushes what a send or an acceptance writes, then writes
/// it through `inner` as it would have been written without a push.
pub(crate) struct Pushing<'a, R> {
    inner: &'a mut R,
    pusher: Option<Pusher>,
    peer: Option<CorrespondenceLabel>,
}

impl<'a, R: Records> Pushing<'a, R> {
    /// `inner`, pushing ring slots written for `peer` and any acceptance
    /// offered, where `pusher` is given.
    pub(crate) fn new(
        inner: &'a mut R,
        pusher: Option<Pusher>,
        peer: Option<CorrespondenceLabel>,
    ) -> Self {
        Self {
            inner,
            pusher,
            peer,
        }
    }
}

impl<R: Records> Records for Pushing<'_, R> {
    fn read_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.inner.read_advert(owner, subkeys)
    }

    fn read_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.inner.read_drop_slot(owner, subkeys, slot)
    }

    fn write_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        self.inner.write_drop_slot(owner, subkeys, slot, bytes)
    }

    fn erase_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<(), RecordError> {
        self.inner.erase_drop_slot(owner, subkeys, slot)
    }

    fn open_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        subkeys: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        self.inner.open_channel(owner, subkeys)
    }

    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.inner.read_channel(lookup_key, subkey)
    }

    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        if let (Some(pusher), Some(peer)) = (&self.pusher, self.peer) {
            if subkey != channel::CONTROL_SUBKEY {
                pusher.push_slot(peer, lookup_key, subkey, bytes);
            }
        }
        self.inner.write_channel(lookup_key, subkey, bytes)
    }

    fn write_batch(&mut self, writes: &[BatchWrite<'_>]) -> Vec<Result<(), RecordError>> {
        self.inner.write_batch(writes)
    }

    fn offer_acceptance(&mut self, writes: &AcceptanceWrites<'_>) {
        if let Some(pusher) = &self.pusher {
            if let Ok((header, _)) = channel::MessageHeader::decode(writes.reply) {
                pusher.start(
                    writes.peer,
                    header.seq,
                    &Push::Acceptance {
                        lookup_key: *writes.lookup_key,
                        hello_slot: writes.hello_slot,
                        hello: writes.hello.to_vec(),
                        control: writes.control.to_vec(),
                        reply_subkey: writes.reply_subkey,
                        reply: writes.reply.to_vec(),
                    },
                    writes.answer,
                );
            }
        }
        self.inner.offer_acceptance(writes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(key: u8) -> PushInbound {
        let mut bytes = daemonseed_core::dm::push::PUSH_TAG.to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&[key; HELLO_LOOKUP_KEY_LEN]);
        bytes.extend_from_slice(&[0; 16]);
        PushInbound::Call {
            id: 1,
            message: bytes,
            received: Instant::now(),
        }
    }

    fn acceptance() -> PushInbound {
        let mut bytes = daemonseed_core::dm::push::PUSH_TAG.to_vec();
        bytes.push(2);
        bytes.extend_from_slice(&[0; 64]);
        PushInbound::Call {
            id: 1,
            message: bytes,
            received: Instant::now(),
        }
    }

    /// One channel, or the acceptances together, cannot hold more than their
    /// share of the queue, a channel this side does not read holds none, and
    /// what is shed is counted.
    #[test]
    fn one_sender_cannot_fill_the_push_queue() {
        let (outbox, mut inbox) = push_queue();
        inbox.set_known([[1; HELLO_LOOKUP_KEY_LEN], [2; HELLO_LOOKUP_KEY_LEN]]);
        let admitted = (0..20).filter(|_| outbox.offer(message(1))).count();
        assert_eq!(admitted, PUSH_PER_CHANNEL);
        assert!(outbox.offer(message(2)), "another channel still has room");
        assert!(
            !outbox.offer(message(3)),
            "a channel this side does not read"
        );
        let accepted = (0..20).filter(|_| outbox.offer(acceptance())).count();
        assert_eq!(accepted, PUSH_ACCEPTANCES);
        assert_eq!(
            inbox.shed(),
            (20 - PUSH_PER_CHANNEL + 1 + 20 - PUSH_ACCEPTANCES) as u64
        );
        assert!(inbox.try_recv().is_some());
        assert!(outbox.offer(message(1)), "a taken push frees its place");
        assert!(outbox.offer(PushInbound::RoutesDied(Vec::new())));
    }

    fn changed(key: u8, dead: bool) -> PushInbound {
        PushInbound::Changed {
            lookup_key: [key; HELLO_LOOKUP_KEY_LEN],
            first_subkey: 1,
            single: true,
            dead,
            value: Some((1, vec![key; 8])),
        }
    }

    /// A burst of watched changes holds at most its share of the queue, so
    /// message pushes queued after it still get in; every change refused is
    /// handed back once as missed, a death as a death, and a taken change
    /// frees its place.
    #[test]
    fn a_burst_of_changes_leaves_room_for_pushes() {
        let (outbox, mut inbox) = push_queue();
        let channels: Vec<[u8; HELLO_LOOKUP_KEY_LEN]> =
            (1..=40u8).map(|key| [key; HELLO_LOOKUP_KEY_LEN]).collect();
        inbox.set_known(channels.iter().copied());
        let mut refused = std::collections::BTreeSet::new();
        let mut burst = 0;
        for key in (1..=40u8).flat_map(|key| [key; 3]) {
            if outbox.offer(changed(key, false)) {
                burst += 1;
            } else {
                refused.insert([key; HELLO_LOOKUP_KEY_LEN]);
            }
        }
        assert_eq!(burst, CHANGES_QUEUED, "the burst holds its share only");
        let pushed = (1..=40u8)
            .flat_map(|key| [key; PUSH_PER_CHANNEL])
            .filter(|key| outbox.offer(message(*key)))
            .count();
        assert_eq!(
            pushed,
            PUSH_QUEUE - CHANGES_QUEUED,
            "every place the burst left is open to pushes"
        );
        assert!(
            !outbox.offer(changed(1, true)),
            "a death in a full queue is refused"
        );
        refused.insert([1; HELLO_LOOKUP_KEY_LEN]);

        let missed = inbox.take_missed();
        assert!(!missed.is_empty());
        assert_eq!(
            missed.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            refused.iter().copied().collect::<Vec<_>>(),
            "one entry per channel with a refused change"
        );
        let dead: Vec<_> = missed.iter().filter(|(_, dead)| *dead).collect();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].0, [1; HELLO_LOOKUP_KEY_LEN], "the death is kept");
        assert!(inbox.take_missed().is_empty(), "missed is handed back once");
        assert_eq!(
            inbox.shed(),
            (40 * PUSH_PER_CHANNEL - pushed) as u64,
            "only the pushes refused are counted as shed"
        );

        let (mut changes, mut calls) = (0, 0);
        while let Some(inbound) = inbox.try_recv() {
            match inbound {
                PushInbound::Changed { .. } => changes += 1,
                PushInbound::Call { .. } => calls += 1,
                PushInbound::RoutesDied(_) => {}
            }
        }
        assert_eq!(
            (changes, calls),
            (CHANGES_QUEUED, PUSH_QUEUE - CHANGES_QUEUED)
        );
        assert!(
            outbox.offer(changed(1, false)),
            "a taken change frees its place"
        );
    }

    /// One channel cannot hold more than its share of the changes queued.
    #[test]
    fn one_channel_holds_its_share_of_changes() {
        let (outbox, inbox) = push_queue();
        let admitted = (0..10).filter(|_| outbox.offer(changed(7, false))).count();
        assert_eq!(admitted, CHANGES_PER_CHANNEL);
        assert!(outbox.offer(changed(8, false)), "another channel has room");
        assert_eq!(
            inbox.take_missed(),
            vec![([7; HELLO_LOOKUP_KEY_LEN], false)]
        );
    }
}
