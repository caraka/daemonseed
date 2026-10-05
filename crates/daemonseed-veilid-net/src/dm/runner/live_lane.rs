//! The live lane: a second task beside the runner that sends direct messages
//! and takes pushed ones in while the runner is inside a network call.
//!
//! `docs/design/direct-messaging.md` § Delivery, *Push*. The runner makes its
//! record-store calls one at a time, and a call can take tens of seconds, so
//! nothing that must happen within seconds waits for it here:
//!
//! - **Commands.** The lane is the only reader of the command queue a
//!   [`RunnerHandle`] feeds. A [`RunnerCommand::Send`] is served here: the
//!   message is sealed, its outbox entry persisted and the conversation record
//!   committed ([`flows::commit_message`]), and the slot pushed to the
//!   correspondent. The runner then writes the slot from the stored outbox
//!   bytes, the same write a launch or a repair makes for a committed entry,
//!   and reports [`RunnerEvent::Sent`] once that write completes; where that
//!   write fails, the send is answered once a repair writes the slot. A send on
//!   a conversation whose acceptance is still being finished is handed to the
//!   runner instead, behind the command finishing it, and so is every later
//!   send to that conversation until the runner has committed those before it.
//!   A block or unblock is applied to the stored list here, a delete's mark
//!   made here and a correspondent's handle recorded here, as each arrives;
//!   the runner then does its own part of a block and of a delete. Every other
//!   command is handed to the runner in the order it arrived. Commands the
//!   runner's queue has no room for wait in the lane, which reads no further
//!   commands once [`COMMAND_QUEUE`] of them wait.
//! - **Pushes.** A pushed message or acceptance is opened, persisted and
//!   answered here, while it is inside [`PUSH_ANSWER_WINDOW`], through
//!   [`daemonseed_core::dm::push`] with the block list read from the store. An
//!   acceptance is recognised from the pushed bytes alone, over
//!   [`core_push::NoNetwork`]. A route a message push carries replaces the
//!   one held for its correspondent once the message is recorded. A reach
//!   notice is opened under the conversation's control key and, where its
//!   reach is newer than the one applied, answered, and its reach and cursor
//!   handed to the runner as a watched control's are; any other is not
//!   answered. A route death is handed to the
//!   runner.
//! - **Watched changes.** A change Veilid reports on the correspondent's
//!   channel is applied from the bytes the report carries, with no read of the
//!   record store: a control subkey is opened under the conversation's
//!   control key and its reach and cursor handed to the runner, and a ring
//!   slot is taken as a pushed one is, with no answer to send. A change that
//!   carries no value, a slot past the next sequence, one that does not open,
//!   and a change the queue had no room for, have the runner collect that
//!   conversation instead. A dead watch is handed to the runner, which
//!   registers it again and collects the conversation. The conversation is
//!   found by the lookup key of the channel it reads, from an index of the
//!   conversations the roster last listed.
//!
//! The lane and the runner share the [`Store`], whose per-conversation lock
//! orders their writes. A flow that loads a conversation record, makes
//! network calls and then commits compares the stored record with the one it
//! loaded and discards its result where they differ ([`FlowError::Conflict`]),
//! so a send or a pushed message the lane committed meanwhile is never
//! overwritten, and no sequence is recorded twice; a collection instead opens
//! its slot again on the record as it stands and writes only the reading side.
//! Commits of sends, from the lane or the runner, are made one at a time.
//!
//! The lane ends when the runner's task ends, answering every command still
//! queued, and one it held for the runner, with [`Refusal::ShuttingDown`]; the
//! runner's task waits for it.
//!
//! Serves FC7.

use super::*;

use daemonseed_core::dm::channel::Reach;
use daemonseed_core::dm::push::{self as core_push, Push, Taken};
use tokio::sync::oneshot;

use super::push_hooks::PushShare;
use crate::dm::push::{PushInbound, PushInbox, PUSH_ANSWER_WINDOW};

/// How many times a send is committed where the conversation record changed
/// under it, before it is refused.
const COMMIT_ATTEMPTS: usize = 4;

/// What the lane hands the runner.
pub(super) enum LaneNote {
    /// A message committed and pushed, whose slot the runner writes before it
    /// answers `token`.
    Committed {
        token: CommandToken,
        peer: CorrespondenceLabel,
        seq: u64,
    },
    /// An acceptance taken from a push, persisted and reported, whose
    /// correspondent's reach and cursor the runner takes in.
    Accepted {
        peer: CorrespondenceLabel,
        reach: Reach,
        unopened: Option<flows::Unopened>,
    },
    /// Private routes of this node that died, by id.
    RoutesDied(Vec<String>),
    /// The watch on the correspondent's channel read under this lookup key
    /// died, and the runner registers it again and collects the conversation.
    WatchDied([u8; HELLO_LOOKUP_KEY_LEN]),
    /// The correspondent's control subkey, opened from a watched change: the
    /// runner takes in its reach and cursor as it does an acceptance's.
    PeerControl {
        peer: CorrespondenceLabel,
        reach: Reach,
        cursor: u64,
    },
    /// A watched change the lane could not apply from its bytes: the runner
    /// collects this conversation at its next wake.
    CollectNow(CorrespondenceLabel),
    /// A message recorded from a watched change, which sends no answer back:
    /// the runner publishes this conversation's cursor at its next wake.
    PublishCursor(CorrespondenceLabel),
    /// A block or unblock applied to the stored list, and what the store
    /// answered.
    Blocked {
        identity: IdentityPk,
        block: bool,
        updated: Result<BlockList, BlockListFailure>,
    },
}

/// What the runner and the lane both hold.
#[derive(Clone)]
pub(super) struct LaneShare {
    pub(super) store: Arc<Store>,
    signer: Arc<SignKeypair>,
    channel_root: Arc<DmChannelRootSecret>,
    events: mpsc::Sender<RunnerEvent>,
    push: PushShare,
    clock: Clock,
    /// Counters the lane moved and the runner has not yet taken.
    counts: Arc<std::sync::Mutex<HealthCounters>>,
    /// Held while a send is committed.
    commit: Arc<std::sync::Mutex<()>>,
    /// Sends handed to the runner and not yet committed there, per
    /// conversation.
    routed: Arc<std::sync::Mutex<HashMap<CorrespondenceLabel, usize>>>,
    /// Set once the event stream has no reader.
    events_gone: Arc<AtomicBool>,
    /// The conversation reading each incoming channel, by lookup key, as the
    /// roster last listed them.
    readers: Arc<std::sync::Mutex<HashMap<[u8; HELLO_LOOKUP_KEY_LEN], CorrespondenceLabel>>>,
    /// Commits refused as conflicting before any is attempted, for tests.
    #[cfg(test)]
    pub(super) forced_conflicts: Arc<std::sync::atomic::AtomicUsize>,
}

fn locked<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl LaneShare {
    pub(super) fn new(
        store: Arc<Store>,
        signer: Arc<SignKeypair>,
        channel_root: Arc<DmChannelRootSecret>,
        events: mpsc::Sender<RunnerEvent>,
        push: PushShare,
        clock: Clock,
    ) -> Self {
        Self {
            store,
            signer,
            channel_root,
            events,
            push,
            clock,
            counts: Arc::default(),
            commit: Arc::default(),
            routed: Arc::default(),
            events_gone: Arc::default(),
            readers: Arc::default(),
            #[cfg(test)]
            forced_conflicts: Arc::default(),
        }
    }

    #[cfg(test)]
    pub(super) fn with_forced_conflicts(
        mut self,
        forced: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.forced_conflicts = forced;
        self
    }

    /// The counters the lane moved since the last call.
    pub(super) fn take_counts(&self) -> HealthCounters {
        std::mem::take(&mut *locked(&self.counts))
    }

    fn count(&self, bump: impl FnOnce(&mut HealthCounters)) {
        bump(&mut locked(&self.counts));
    }

    /// Commit `body` as the next message to `peer` and push its slot where the
    /// correspondent's route is known. The slot is not written. A commit whose
    /// conversation record changed under it is made again from a fresh load,
    /// at most [`COMMIT_ATTEMPTS`] times in all.
    pub(super) fn commit_send(
        &self,
        peer: &CorrespondenceLabel,
        body: &[u8],
    ) -> Result<u64, FlowError> {
        let _one_at_a_time = locked(&self.commit);
        let mut attempts = 1;
        let committed = loop {
            #[cfg(test)]
            let forced = self
                .forced_conflicts
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok();
            #[cfg(not(test))]
            let forced = false;
            let attempt = if forced {
                Err(FlowError::Conflict)
            } else {
                flows::commit_message(&self.store, peer, body, os_fill, self.clock.now_secs())
            };
            match attempt {
                Err(FlowError::Conflict) if attempts < COMMIT_ATTEMPTS => attempts += 1,
                committed => break committed?,
            }
        };
        if let Some(pusher) = self.push.pusher_for(&self.store, peer, &self.events) {
            pusher.push_slot(
                *peer,
                &committed.lookup_key,
                committed.subkey,
                &committed.slot,
            );
        } else if !self.push.holds_route(peer) {
            crate::vtrace!(
                "dm lane: sequence {} on {} not pushed, no route held",
                committed.seq,
                tag(peer)
            );
        } else {
            crate::vtrace!(
                "dm lane: sequence {} on {} not pushed, no push transport or control key",
                committed.seq,
                tag(peer)
            );
        }
        Ok(committed.seq)
    }

    /// Emit `event`. A closed event stream has no reader left, and the lane
    /// stops at its next turn.
    async fn emit(&self, event: RunnerEvent) {
        if self.events.send(event).await.is_err() {
            self.events_gone.store(true, Ordering::Relaxed);
        }
    }

    fn events_gone(&self) -> bool {
        self.events_gone.load(Ordering::Relaxed)
    }

    /// One [`RunnerEvent::Message`] per message, numbered from `first`.
    async fn emit_bodies(
        &self,
        from: CorrespondenceLabel,
        first: u64,
        messages: Vec<ReceivedMessage>,
    ) {
        for (seq, message) in (first..).zip(messages) {
            self.emit(RunnerEvent::Message {
                from,
                seq,
                body: message.body,
                sent_at: message.sent_at_ms,
                received_at: self.clock.now_ms(),
            })
            .await;
        }
    }

    /// Whether a send to `peer` handed to the runner has not yet been
    /// committed there, so a later send to `peer` is handed to it too.
    fn routed(&self, peer: &CorrespondenceLabel) -> bool {
        locked(&self.routed).get(peer).is_some_and(|n| *n > 0)
    }

    fn route(&self, peer: &CorrespondenceLabel) {
        *locked(&self.routed).entry(*peer).or_default() += 1;
    }

    /// Take `convs` as the conversations reading their incoming channels.
    pub(super) fn set_readers(&self, convs: &[LoadedConv]) {
        *locked(&self.readers) = convs
            .iter()
            .filter(|conv| conv.state.incoming_lookup_key != NO_LOOKUP_KEY)
            .map(|conv| (conv.state.incoming_lookup_key, conv.peer))
            .collect();
    }

    /// Hold `route` as `peer`'s, and keep it beside the conversation.
    fn hold_route(&self, peer: &CorrespondenceLabel, route: &[u8]) {
        self.push.set_peer_route(peer, Some(route.to_vec()));
        match self.store.record_route(peer, route) {
            Ok(_) | Err(StoreError::MissingConversation) => {}
            Err(_) => self.count(|health| health.store_failures += 1),
        }
    }

    /// The conversation that reads the channel at `lookup_key`, and its stored
    /// state, loaded alone. A conversation the index names whose record no
    /// longer reads that channel is none.
    pub(super) fn reader_of(
        &self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    ) -> Option<(CorrespondenceLabel, ConvState)> {
        let peer = *locked(&self.readers).get(lookup_key)?;
        match self.store.load_conv(&peer) {
            Ok(Some(state)) if state.incoming_lookup_key == *lookup_key => Some((peer, state)),
            Ok(_) => None,
            Err(_) => {
                self.count(|health| health.store_failures += 1);
                None
            }
        }
    }

    /// A send to `peer` the lane handed the runner has been committed there,
    /// or refused.
    pub(super) fn routed_done(&self, peer: &CorrespondenceLabel) {
        let mut routed = locked(&self.routed);
        if let Some(n) = routed.get_mut(peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                routed.remove(peer);
            }
        }
    }
}

/// Whether `peer`'s conversation is an acceptance still being finished.
fn acceptance_pending(store: &Store, peer: &CorrespondenceLabel) -> bool {
    matches!(store.load_conv(peer), Ok(Some(state)) if state.acceptance_pending)
}

/// The lane's task.
pub(super) struct Lane {
    pub(super) share: LaneShare,
    pub(super) inbound: Option<PushInbox>,
    /// The queue a [`RunnerHandle`] feeds.
    pub(super) commands: CommandQueue,
    /// The runner's own queue.
    pub(super) to_runner: mpsc::Sender<RunnerCommand>,
    pub(super) notes: mpsc::UnboundedSender<LaneNote>,
    pub(super) stop: Arc<AtomicBool>,
    /// Completes when the runner's task ends.
    pub(super) runner_gone: oneshot::Receiver<()>,
}

/// What woke the lane.
enum LaneWake {
    Command(Option<RunnerCommand>),
    Push(Option<PushInbound>),
    RunnerHasRoom(mpsc::OwnedPermit<RunnerCommand>),
    RunnerGone,
}

async fn next_inbound(inbound: &mut Option<PushInbox>) -> Option<PushInbound> {
    match inbound {
        Some(inbound) => inbound.recv().await,
        None => std::future::pending().await,
    }
}

impl Lane {
    pub(super) async fn run(mut self) {
        // Commands for the runner that its queue had no room for yet, in the
        // order they arrived. Commands are read while fewer than
        // [`COMMAND_QUEUE`] wait here.
        let mut backlog: std::collections::VecDeque<RunnerCommand> =
            std::collections::VecDeque::new();
        // Whether the handle's queue closed or asked the runner to stop, after
        // which no command is read from it.
        let mut closed = false;
        loop {
            if self.share.events_gone() {
                break;
            }
            let reading = !closed && backlog.len() < COMMAND_QUEUE;
            let room = (!backlog.is_empty()).then(|| self.to_runner.clone());
            let wake = {
                let commands = Arc::clone(&self.commands);
                let mut queue = if reading {
                    Some(commands.lock().await)
                } else {
                    None
                };
                tokio::select! {
                    biased;
                    _ = &mut self.runner_gone => LaneWake::RunnerGone,
                    room = async { room?.reserve_owned().await.ok() }, if room.is_some() => {
                        match room {
                            Some(permit) => LaneWake::RunnerHasRoom(permit),
                            None => LaneWake::RunnerGone,
                        }
                    }
                    command = async { queue.as_mut()?.recv().await }, if reading => {
                        LaneWake::Command(command)
                    }
                    inbound = next_inbound(&mut self.inbound) => LaneWake::Push(inbound),
                }
            };
            match wake {
                LaneWake::RunnerGone => break,
                LaneWake::RunnerHasRoom(permit) => {
                    if let Some(command) = backlog.pop_front() {
                        permit.send(command);
                    }
                }
                LaneWake::Command(None) => {
                    closed = true;
                    backlog.push_back(RunnerCommand::Shutdown);
                }
                LaneWake::Command(Some(command)) => {
                    closed |= matches!(command, RunnerCommand::Shutdown);
                    if let Some(command) = self.serve_command(command).await {
                        backlog.push_back(command);
                    }
                }
                LaneWake::Push(None) => self.inbound = None,
                LaneWake::Push(Some(inbound)) => {
                    self.serve_push(inbound).await;
                    self.serve_missed();
                }
            }
        }
        for command in backlog {
            self.refuse(command.token()).await;
        }
        self.refuse_queued().await;
    }

    async fn refuse(&self, token: Option<CommandToken>) {
        if token.is_some() {
            self.share
                .emit(RunnerEvent::Refused {
                    token,
                    reason: Refusal::ShuttingDown,
                })
                .await;
        }
    }

    /// Answer every command still on the handle's queue with
    /// [`Refusal::ShuttingDown`], and close it.
    async fn refuse_queued(&self) {
        let tokens: Vec<CommandToken> = {
            let mut queue = self.commands.lock().await;
            queue.close();
            std::iter::from_fn(|| queue.try_recv().ok())
                .filter_map(|command| command.token())
                .collect()
        };
        for token in tokens {
            self.refuse(Some(token)).await;
        }
    }

    /// Serve what of `command` the lane serves, returning what the runner is
    /// to serve.
    ///
    /// A send is served here unless an earlier send to the same conversation
    /// is still the runner's to commit. A block or unblock is applied to the
    /// stored list here, and a delete marked here, so a push or a send that
    /// follows either is refused; the runner then does its own part. A handle
    /// note for a correspondent is recorded here; one for this node's own
    /// identity republishes, which is the runner's.
    async fn serve_command(&self, command: RunnerCommand) -> Option<RunnerCommand> {
        match command {
            RunnerCommand::Send { token, peer, body } => {
                if self.share.routed(&peer) {
                    self.share.route(&peer);
                    return Some(RunnerCommand::Send { token, peer, body });
                }
                self.send(token, peer, body).await
            }
            RunnerCommand::Block { peer } => {
                self.set_blocked(peer, true);
                None
            }
            RunnerCommand::Unblock { peer } => {
                self.set_blocked(peer, false);
                None
            }
            RunnerCommand::DeleteConversation { token, peer } => {
                match self.share.store.mark_delete_pending(&peer) {
                    Err(StoreError::MissingConversation) => {
                        self.share
                            .emit(RunnerEvent::Refused {
                                token: Some(token),
                                reason: Refusal::UnknownConversation,
                            })
                            .await;
                        None
                    }
                    // The runner marks it again, which changes nothing, or
                    // answers the store's refusal.
                    Ok(_) | Err(_) => Some(RunnerCommand::DeleteConversation { token, peer }),
                }
            }
            RunnerCommand::NoteHandle {
                peer_identity_pk,
                handle,
            } if peer_identity_pk.as_slice() != self.share.signer.public_key().as_slice() => {
                self.note_handle(&peer_identity_pk, &handle).await;
                None
            }
            other => Some(other),
        }
    }

    fn set_blocked(&self, identity: IdentityPk, block: bool) {
        let updated = update_block_list(&self.share.store, |list| {
            if block {
                list.block(&identity);
            } else {
                list.unblock(&identity);
            }
        });
        let _ = self.notes.send(LaneNote::Blocked {
            identity,
            block,
            updated,
        });
    }

    async fn note_handle(&self, identity: &[u8; IDENTITY_PK_LEN], handle: &str) {
        let store = &self.share.store;
        let Ok(loaded) = store.load() else {
            self.share.count(|health| health.store_failures += 1);
            return;
        };
        let Some(conv) = loaded
            .convs
            .iter()
            .find(|conv| conv.state.peer_identity_pk.as_slice() == identity.as_slice())
        else {
            return;
        };
        match store.record_handle(&conv.peer, handle) {
            Ok(true) => self.emit_roster().await,
            Ok(false) | Err(StoreError::MissingConversation) => {}
            Err(_) => self.share.count(|health| health.store_failures += 1),
        }
    }

    /// Report the roster, and admit pushes for the channels it reads.
    async fn emit_roster(&self) {
        match self.share.store.load() {
            Ok(loaded) => {
                self.share.set_readers(&loaded.convs);
                if let Some(inbound) = &self.inbound {
                    inbound.set_known(
                        loaded
                            .convs
                            .iter()
                            .map(|conv| conv.state.incoming_lookup_key)
                            .filter(|key| *key != NO_LOOKUP_KEY),
                    );
                }
                self.share
                    .emit(RunnerEvent::Roster(summaries(&loaded.convs)))
                    .await;
            }
            Err(_) => self.share.count(|health| health.store_failures += 1),
        }
    }

    /// Serve one send, returning it where it is the runner's to serve.
    async fn send(
        &self,
        token: CommandToken,
        peer: CorrespondenceLabel,
        body: Vec<u8>,
    ) -> Option<RunnerCommand> {
        if self.stop.load(Ordering::Relaxed) {
            self.refuse(Some(token)).await;
            return None;
        }
        crate::vtrace!("dm lane: send on {} starts", tag(&peer));
        match self.share.commit_send(&peer, &body) {
            Ok(seq) => {
                crate::vtrace!("dm lane: send on {} committed, seq {seq}", tag(&peer));
                let _ = self.notes.send(LaneNote::Committed { token, peer, seq });
                None
            }
            Err(FlowError::AwaitingAcceptance) if acceptance_pending(&self.share.store, &peer) => {
                crate::vtrace!(
                    "dm lane: send on {} waits for its acceptance to finish",
                    tag(&peer)
                );
                self.share.route(&peer);
                Some(RunnerCommand::Send { token, peer, body })
            }
            Err(e) => {
                let reason = refusal_for(&e);
                crate::vtrace!("dm lane: send on {} refused, {reason:?}", tag(&peer));
                if !matches!(
                    reason,
                    Refusal::UnknownConversation
                        | Refusal::AwaitingAcceptance
                        | Refusal::RingFull
                        | Refusal::TooLong
                ) {
                    self.share.count(|health| note_failure(health, &e));
                }
                self.share
                    .emit(RunnerEvent::Refused {
                        token: Some(token),
                        reason,
                    })
                    .await;
                None
            }
        }
    }

    /// Serve one thing the push transport handed over.
    async fn serve_push(&self, inbound: PushInbound) {
        match inbound {
            PushInbound::RoutesDied(dead) => {
                let _ = self.notes.send(LaneNote::RoutesDied(dead));
            }
            PushInbound::Changed {
                lookup_key,
                first_subkey,
                single,
                dead,
                value,
            } => {
                self.watch_changed(lookup_key, first_subkey, single, dead, value)
                    .await;
            }
            PushInbound::Call {
                id,
                message,
                received,
            } => {
                if received.elapsed() > PUSH_ANSWER_WINDOW {
                    crate::vtrace!(
                        "dm push: a push waited {} ms, past its answer window, dropped",
                        received.elapsed().as_millis()
                    );
                    self.share.count(|health| health.pushes_expired += 1);
                    return;
                }
                match Push::decode(&message) {
                    Some(push @ Push::Message { .. }) => self.take_message(id, &push).await,
                    Some(push @ Push::Acceptance { .. }) => self.take_acceptance(id, &push).await,
                    Some(Push::Reach {
                        lookup_key,
                        control,
                    }) => self.take_reach(id, &lookup_key, &control),
                    None => {
                        crate::vtrace!("dm push: a push that does not decode, dropped");
                        self.share.count(|health| health.pushes_dropped += 1);
                    }
                }
            }
        }
    }

    /// Take a change Veilid reported on a watched channel, from the bytes it
    /// carries, without reading the record store.
    async fn watch_changed(
        &self,
        lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
        first_subkey: u32,
        single: bool,
        dead: bool,
        value: Option<(u32, Vec<u8>)>,
    ) {
        let short = crate::dm::watch::channel_tag(&lookup_key);
        if dead {
            crate::vtrace!("dm watch: the watch on {short} died");
            let _ = self.notes.send(LaneNote::WatchDied(lookup_key));
            return;
        }
        let Some((peer, state)) = self.share.reader_of(&lookup_key) else {
            crate::vtrace!(
                "dm watch: change on {short}, a channel no conversation reads, subkey {first_subkey}, dropped"
            );
            return;
        };
        let applied = match value {
            Some((_, bytes)) if single && first_subkey == u32::from(channel::CONTROL_SUBKEY) => {
                self.control_changed(peer, &state, &bytes)
            }
            Some((_, bytes)) if single => match u16::try_from(first_subkey) {
                Ok(subkey) => self.slot_changed(peer, &lookup_key, subkey, &bytes).await,
                Err(_) => false,
            },
            Some(_) | None => false,
        };
        if !applied {
            crate::vtrace!(
                "dm watch: change {} subkey {first_subkey} not applied from its bytes, collecting",
                tag(&peer)
            );
            let _ = self.notes.send(LaneNote::CollectNow(peer));
        }
    }

    /// Open a changed control subkey of `peer`'s channel and hand its reach and
    /// cursor to the runner. `true` where nothing is left to collect for it:
    /// the control opened, or the conversation is not one that takes it.
    fn control_changed(&self, peer: CorrespondenceLabel, state: &ConvState, bytes: &[u8]) -> bool {
        if state.delete_pending || state.awaiting_acceptance || state.acceptance_pending {
            crate::vtrace!(
                "dm watch: control of {} changed while it is not established, ignored",
                tag(&peer)
            );
            return true;
        }
        let Some(blocked) = read_block_list(&self.share.store) else {
            return false;
        };
        if blocked.is_blocked(&state.peer_identity_pk) {
            crate::vtrace!(
                "dm watch: {} is blocked, its control is ignored",
                tag(&peer)
            );
            return true;
        }
        let Some(key) = state.peer_control_key.as_ref() else {
            return false;
        };
        match channel::open_control_with_key(key, bytes) {
            Ok(control) => {
                crate::vtrace!(
                    "dm watch: control of {} changed, cursor {}",
                    tag(&peer),
                    control.collected_cursor
                );
                let _ = self.notes.send(LaneNote::PeerControl {
                    peer,
                    reach: control.reach,
                    cursor: control.collected_cursor,
                });
                true
            }
            Err(_) => {
                crate::vtrace!("dm watch: control of {} does not open", tag(&peer));
                false
            }
        }
    }

    /// Take a changed ring slot of `peer`'s channel as a pushed one is, with
    /// no answer to send. `true` where nothing is left to collect for it.
    async fn slot_changed(
        &self,
        peer: CorrespondenceLabel,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> bool {
        let Some(blocked) = read_block_list(&self.share.store) else {
            return false;
        };
        let taken = core_push::take_message(
            &self.share.store,
            |identity| blocked.is_blocked(identity),
            lookup_key,
            subkey,
            bytes,
        );
        match taken {
            Ok(Taken::Recorded {
                peer, seq, message, ..
            }) => {
                crate::vtrace!("dm watch: {} sequence {seq} recorded", tag(&peer));
                self.share.emit_bodies(peer, seq, vec![message]).await;
                let _ = self.notes.send(LaneNote::PublishCursor(peer));
                true
            }
            Ok(Taken::Blocked { peer }) => {
                crate::vtrace!("dm watch: {} is blocked, its slot is ignored", tag(&peer));
                true
            }
            // Already recorded, by a push or a collection.
            Ok(Taken::Duplicate { .. }) => true,
            Ok(Taken::Ahead { .. } | Taken::Dropped) => false,
            Err(e) => {
                crate::vtrace!(
                    "dm watch: a slot of {} failed, {:?}",
                    tag(&peer),
                    refusal_for(&e)
                );
                self.share.count(|health| note_failure(health, &e));
                false
            }
        }
    }

    /// Hand the runner what the queue refused of the watched changes: a death
    /// to register again, and a conversation to collect for any other change.
    fn serve_missed(&self) {
        let Some(inbound) = &self.inbound else {
            return;
        };
        for (lookup_key, dead) in inbound.take_missed() {
            let short = crate::dm::watch::channel_tag(&lookup_key);
            if dead {
                crate::vtrace!("dm watch: the watch on {short} died, the report was not queued");
                let _ = self.notes.send(LaneNote::WatchDied(lookup_key));
            } else if let Some((peer, _)) = self.share.reader_of(&lookup_key) {
                crate::vtrace!(
                    "dm watch: a change on {} was not queued, collecting",
                    tag(&peer)
                );
                let _ = self.notes.send(LaneNote::CollectNow(peer));
            }
        }
    }

    fn failed(&self, error: &FlowError) {
        self.share.count(|health| {
            note_failure(health, error);
            health.pushes_dropped += 1;
        });
    }

    async fn take_message(&self, id: u64, push: &Push) {
        let Push::Message {
            lookup_key,
            subkey,
            slot,
            route,
        } = push
        else {
            return;
        };
        let Some(blocked) = read_block_list(&self.share.store) else {
            crate::vtrace!("dm push: the block list will not read, a message push is dropped");
            self.share.count(|health| health.pushes_dropped += 1);
            return;
        };
        let taken = core_push::take_message(
            &self.share.store,
            |identity| blocked.is_blocked(identity),
            lookup_key,
            *subkey,
            slot,
        );
        match taken {
            Ok(Taken::Recorded {
                peer,
                seq,
                message,
                answer,
            }) => {
                if let Some(route) = route {
                    self.share.hold_route(&peer, route);
                }
                self.share.push.answer(id, answer);
                crate::vtrace!("dm push: {} sequence {seq} recorded", tag(&peer));
                self.share.emit_bodies(peer, seq, vec![message]).await;
            }
            Ok(Taken::Blocked { peer }) => {
                crate::vtrace!("dm push: {} is blocked, its push is dropped", tag(&peer));
                self.share.count(|health| health.pushes_dropped += 1);
            }
            Ok(Taken::Duplicate { peer }) => {
                crate::vtrace!("dm push: {} duplicate ignored", tag(&peer));
            }
            Ok(Taken::Ahead { peer }) => {
                crate::vtrace!(
                    "dm push: {} ahead of sequence, left to the network",
                    tag(&peer)
                );
            }
            Ok(Taken::Dropped) => {
                crate::vtrace!(
                    "dm push: a message push names no conversation or does not open, dropped"
                );
                self.share.count(|health| health.pushes_dropped += 1);
            }
            Err(e) => {
                crate::vtrace!("dm push: a message push failed, {:?}", refusal_for(&e));
                self.failed(&e);
            }
        }
    }

    /// Take a reach notice: the correspondent's control subkey, opened under
    /// the conversation's control key. One that opens and carries a reach
    /// newer than the one applied is answered, its route held, and its reach
    /// and cursor handed to the runner; any other is dropped unanswered.
    fn take_reach(&self, id: u64, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN], control: &[u8]) {
        let Some(blocked) = read_block_list(&self.share.store) else {
            crate::vtrace!("dm push: the block list will not read, a reach notice is dropped");
            self.share.count(|health| health.pushes_dropped += 1);
            return;
        };
        let taken = core_push::take_reach(
            &self.share.store,
            |identity| blocked.is_blocked(identity),
            lookup_key,
            control,
        );
        match taken {
            Ok(core_push::ReachTaken::Applied {
                peer,
                control,
                answer,
            }) => {
                // Held before the answer, so a send made once the notice is
                // answered is pushed to the new route.
                if let Some(route) = &control.reach.route {
                    self.share.hold_route(&peer, route);
                }
                self.share.push.answer(id, answer);
                crate::vtrace!(
                    "dm push: reach notice of {} taken, cursor {}",
                    tag(&peer),
                    control.collected_cursor
                );
                let _ = self.notes.send(LaneNote::PeerControl {
                    peer,
                    reach: control.reach,
                    cursor: control.collected_cursor,
                });
            }
            Ok(core_push::ReachTaken::Blocked { peer }) => {
                crate::vtrace!(
                    "dm push: {} is blocked, its reach notice is dropped",
                    tag(&peer)
                );
                self.share.count(|health| health.pushes_dropped += 1);
            }
            Ok(core_push::ReachTaken::Dropped) => {
                crate::vtrace!(
                    "dm push: a reach notice names no conversation or does not open, dropped"
                );
                self.share.count(|health| health.pushes_dropped += 1);
            }
            Err(e) => {
                crate::vtrace!("dm push: a reach notice failed, {:?}", refusal_for(&e));
                self.failed(&e);
            }
        }
    }

    async fn take_acceptance(&self, id: u64, push: &Push) {
        let store = &self.share.store;
        let Some(blocked) = read_block_list(store) else {
            self.share.count(|health| health.pushes_dropped += 1);
            return;
        };
        let advert_keys = match store.load_advert_keys() {
            Ok(Some(snapshot)) => AdvertKeys::restore(snapshot),
            Ok(None) | Err(_) => {
                self.share.count(|health| health.pushes_dropped += 1);
                return;
            }
        };
        let me = Me {
            signer: &self.share.signer,
            channel_root: &self.share.channel_root,
        };
        let recognised = core_push::recognise_acceptance(
            store,
            &mut core_push::NoNetwork,
            &me,
            &advert_keys,
            |identity| blocked.is_blocked(identity),
            push,
        );
        let (acceptance, answer) = match recognised {
            Ok(Some(recognised)) => recognised,
            Ok(None) => {
                crate::vtrace!("dm push: an acceptance push did not verify, dropped");
                self.share.count(|health| health.pushes_dropped += 1);
                return;
            }
            Err(e) => {
                crate::vtrace!("dm push: an acceptance push failed, {:?}", refusal_for(&e));
                self.failed(&e);
                return;
            }
        };
        let peer = acceptance.peer;
        // The route is held before the answer and the event, so a send the
        // front end makes on `Accepted` is pushed. The runner notes the reach
        // again when it serves the note below, which changes nothing here.
        self.share
            .push
            .set_peer_route(&peer, acceptance.peer_reach.route.clone());
        self.share.push.answer(id, answer);
        crate::vtrace!("dm push: {} acceptance recognised", tag(&peer));
        self.share.emit(RunnerEvent::Accepted { peer }).await;
        match store.load_conv(&peer) {
            Ok(Some(state)) => {
                let first = state
                    .my_collected
                    .saturating_sub(acceptance.messages.len() as u64);
                self.share
                    .emit_bodies(peer, first, acceptance.messages)
                    .await;
            }
            Ok(None) | Err(_) => self.share.count(|health| health.store_failures += 1),
        }
        self.emit_roster().await;
        let _ = self.notes.send(LaneNote::Accepted {
            peer,
            reach: acceptance.peer_reach,
            unopened: acceptance.unopened,
        });
    }
}
