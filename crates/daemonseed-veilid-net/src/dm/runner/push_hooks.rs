//! The runner's side of push delivery: this node's route and handle, the
//! routes of its correspondents, and the pushes it is handed.
//!
//! `docs/design/direct-messaging.md` § Delivery, *Push*. The runner allocates a
//! private route at startup, sets it and its handle as the reach every control
//! record carries ([`Store::set_reach`]), and rewrites the control subkey of
//! every established conversation. It does so again whenever the route dies
//! or the handle changes. An allocation that fails is tried again from the
//! schedule, [`ROUTE_RETRY_FIRST`] after the failure and twice as long after
//! each further failure, up to [`ROUTE_RETRY_CAP`], for as long as the runner
//! runs without a route. A correspondent's route is learned from every
//! control subkey of theirs the runner opens, whether read from the record
//! store, handed over in a reach notice or carried by an acceptance, where the
//! reach serial that control carries is at or above the one applied: above
//! it, the route replaces the one kept; at it, the route is kept again where
//! none is. The route is kept beside the conversation in the same write as
//! that serial ([`Store::take_reach`]), and held in memory beside the same
//! serial from inside that write's critical section, so the copy in memory
//! moves in the order the record does and a late copy of an older control
//! cannot put back a route a newer one replaced. A forgotten route leaves its
//! serial behind in memory as on disk. The route a message push carries is
//! not taken: it has no serial. At launch, before any push, the runner reads
//! the control subkey of every established correspondent and holds the route
//! it names where its reach is newer than the one applied; where the read
//! fails or the reach is no newer, it holds the kept route, read with its
//! serial in one critical section ([`Store::with_route`]), so a route a reach
//! notice or an acceptance gave meanwhile is the one held. A held route is
//! only an address to try: a push on it that goes unanswered forgets it, in
//! memory and on disk, and the next collection of the conversation reads the
//! correspondent's control, whose route is kept again where its serial is the
//! one applied and taken where it is newer. Each time a reach notice or a
//! control read gives a route that replaces the route held, or one taken
//! after a route was forgotten, the messages committed to that correspondent
//! and not yet collected are pushed on it in sequence order, so a message
//! whose push failed on a route the correspondent no longer serves does not
//! wait for a collection of the record store. So is every route held at
//! launch, from the read of the correspondent's control or the route kept, so
//! a message committed before the launch is pushed too. The route a first
//! acceptance gives is held without such a push. Each run of these pushes is
//! made on the route that started it, from the cursor of the control that
//! gave the route where the store has not taken it yet, and a send made on
//! that route while the run lasts joins it.
//!
//! Once this node holds a route, at launch and whenever it is replaced, and
//! before the control subkeys are rewritten with it, the runner pushes a
//! reach notice to every correspondent whose route it holds: the control
//! subkey the rewrite is about to write, sealed as the record store will hold
//! it. A correspondent that takes it learns the new route without reading the
//! record store; one that does not answer has its route forgotten.
//!
//! Pushed messages and acceptances, and route deaths, are taken by the live
//! lane ([`super::live_lane`]), which hands the runner the route deaths and
//! what an acceptance leaves for it to do.
//!
//! Serves FC1.

use super::*;

use daemonseed_core::dm::channel::Reach;
use daemonseed_core::dm::push as core_push;

use crate::dm::push::{
    enter_run, Admitting, KeptUnanswered, OwnRoute, PushInbox, PushParts, PushTransport, Pusher,
    RunSlot, Runs, Unanswered,
};

/// How many unanswered pushes in a row on one route are kept because their
/// messages were collected. The next one drops the route, which is then taken
/// to answer nothing.
const KEPT_UNANSWERED_MAX: u32 = 2;

/// Hooks run where a take has learned a route, before the run of pushes it
/// starts, by correspondent.
#[cfg(test)]
#[allow(clippy::type_complexity)]
static BEFORE_RUN: std::sync::Mutex<
    Option<HashMap<CorrespondenceLabel, Box<dyn FnOnce() + Send>>>,
> = std::sync::Mutex::new(None);

/// Run `hook` once, where a take next learns a route for `peer`, before the
/// run of pushes it starts.
#[cfg(test)]
pub(super) fn before_run(peer: CorrespondenceLabel, hook: Box<dyn FnOnce() + Send>) {
    BEFORE_RUN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(peer, hook);
}

/// Correspondents whose next run reads its outbox as a store that will not
/// load does.
#[cfg(test)]
static FAILED_RUN_READS: std::sync::Mutex<Vec<CorrespondenceLabel>> =
    std::sync::Mutex::new(Vec::new());

/// Have the next run of pushes to `peer` find the store will not load its
/// outbox.
#[cfg(test)]
pub(super) fn fail_next_run_read(peer: CorrespondenceLabel) {
    FAILED_RUN_READS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(peer);
}

/// Whether a read [`fail_next_run_read`] set for `peer` is still to fail.
#[cfg(test)]
pub(super) fn run_read_left_to_fail(peer: &CorrespondenceLabel) -> bool {
    FAILED_RUN_READS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(peer)
}

/// Whether [`fail_next_run_read`] was set for `peer`, clearing it.
#[cfg(test)]
fn run_read_fails(peer: &CorrespondenceLabel) -> bool {
    let mut failing = FAILED_RUN_READS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let at = failing.iter().position(|failing| failing == peer);
    at.map(|at| failing.remove(at)).is_some()
}

/// Run the hook `before_run` set for `peer`, where one is set.
pub(super) fn run_before_run(peer: &CorrespondenceLabel) {
    #[cfg(test)]
    {
        let hook = BEFORE_RUN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .and_then(|hooks| hooks.remove(peer));
        if let Some(hook) = hook {
            hook();
        }
    }
    #[cfg(not(test))]
    let _ = peer;
}

/// How long after a failed route allocation the runner first tries again.
const ROUTE_RETRY_FIRST: Duration = Duration::from_secs(5);

/// The longest wait between two route allocation attempts.
const ROUTE_RETRY_CAP: Duration = Duration::from_secs(120);

/// The next route allocation attempt of a runner that holds no route.
#[derive(Clone, Copy)]
struct RouteRetry {
    /// When the attempt is due.
    due: Instant,
    /// How long the runner waited for it, which doubles after it fails.
    wait: Duration,
}

/// Each correspondent's route, where one is held, beside the highest reach
/// serial applied for it. A forgotten route leaves its serial behind, as the
/// floor below which no route is taken.
type PeerRoutes = HashMap<CorrespondenceLabel, (Option<Vec<u8>>, u64)>;

/// What the runner and the live lane both push with: the transport, the
/// routes of this side's correspondents, and where an unanswered push names
/// its correspondent.
#[derive(Clone)]
pub(super) struct PushShare {
    pub(super) transport: Option<Arc<dyn PushTransport>>,
    /// Each correspondent's route, beside the highest reach serial applied
    /// for it. Changed from inside the correspondence's critical section of
    /// the store ([`Store::take_reach`], [`Store::with_route`],
    /// [`Store::forget_route`]), so it moves in the order the route record
    /// does, with two exceptions outside any section: a conversation's
    /// teardown removes its entry ([`Self::forget_peer`]) once its records
    /// are deleted, and a route an unanswered push was made on is forgotten
    /// ([`Self::forget_route`]) where the store's call failed before its
    /// section forgot it.
    peer_routes: Arc<std::sync::Mutex<PeerRoutes>>,
    unanswered: mpsc::UnboundedSender<Unanswered>,
    kept: KeptUnanswered,
    runs: Runs,
}

impl PushShare {
    fn routes(&self) -> std::sync::MutexGuard<'_, PeerRoutes> {
        self.peer_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What an acceptance push is made with, where the correspondent's route
    /// is known. Its answer is checked against the one the acceptance offers.
    pub(super) fn pusher(
        &self,
        route: Option<&Vec<u8>>,
        events: &mpsc::Sender<RunnerEvent>,
    ) -> Option<Pusher> {
        Some(Pusher {
            transport: Arc::clone(self.transport.as_ref()?),
            route: route?.clone(),
            events: events.clone(),
            unanswered: self.unanswered.clone(),
            answer_key: None,
            own_route: None,
            kept: Arc::clone(&self.kept),
            runs: Arc::clone(&self.runs),
        })
    }

    /// Count `unanswered`, a push whose message was collected, as kept on its
    /// route, and say whether the route is kept: at most
    /// [`KEPT_UNANSWERED_MAX`] such pushes in a row on one route are. A route
    /// other than the one counted starts the count again.
    fn keep_unanswered(&self, unanswered: &Unanswered) -> bool {
        let mut kept = self
            .kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = kept
            .entry(unanswered.peer)
            .or_insert_with(|| (unanswered.route.clone(), 0));
        if count.0 != unanswered.route {
            *count = (unanswered.route.clone(), 0);
        }
        if count.1 < KEPT_UNANSWERED_MAX {
            count.1 += 1;
            true
        } else {
            kept.remove(&unanswered.peer);
            false
        }
    }

    /// What a message push to `peer` is made with, where its route and this
    /// side's control key for the conversation are known.
    pub(super) fn pusher_for(
        &self,
        store: &Store,
        peer: &CorrespondenceLabel,
        events: &mpsc::Sender<RunnerEvent>,
    ) -> Option<Pusher> {
        let route = self.routes().get(peer).and_then(|(route, _)| route.clone());
        self.pusher_on(store, peer, events, route.as_ref())
    }

    /// [`Self::pusher_for`] on `route` in place of the route held.
    fn pusher_on(
        &self,
        store: &Store,
        peer: &CorrespondenceLabel,
        events: &mpsc::Sender<RunnerEvent>,
        route: Option<&Vec<u8>>,
    ) -> Option<Pusher> {
        let state = store.load_conv(peer).ok()??;
        let key = state.own_control_key.as_ref()?;
        let mut pusher = self.pusher(route, events)?;
        pusher.answer_key = Some(Arc::new(core_push::AnswerKey::new(key)));
        pusher.own_route = store.reach().route;
        Some(pusher)
    }

    /// Whether a route is held for `peer`.
    pub(super) fn holds_route(&self, peer: &CorrespondenceLabel) -> bool {
        self.routes()
            .get(peer)
            .is_some_and(|(route, _)| route.is_some())
    }

    /// The route held for `peer` and the reach serial applied for it.
    #[cfg(test)]
    pub(super) fn route_of(&self, peer: &CorrespondenceLabel) -> Option<(Vec<u8>, u64)> {
        let routes = self.routes();
        let (route, serial) = routes.get(peer)?;
        Some((route.clone()?, *serial))
    }

    /// Answer the call `id` with `answer`, on its own task.
    pub(super) fn answer(&self, id: u64, answer: [u8; core_push::ANSWER_LEN]) {
        let Some(transport) = self.transport.clone() else {
            return;
        };
        tokio::spawn(async move {
            if let Err(e) = transport.reply(id, answer.to_vec()).await {
                crate::vtrace!("dm push: answer failed ({e})");
            }
        });
    }

    /// Hold `route`, issued at reach serial `serial`, as `peer`'s, and return
    /// the route held before where this replaced it, for the caller to
    /// [`Self::release`] once it has left the store's critical section,
    /// beside the run of pushes on `route` entered for `peer` ([`Run`]),
    /// where `route` was taken where none was held or replaced the one held,
    /// and `repush` asks for one. The run is entered before the route is held,
    /// under the same lock, so a send that finds the route joins the run. The
    /// caller starts it ([`Self::push_outstanding`]) once outside the store's
    /// section, or drops it, which leaves it.
    ///
    /// Called from inside the correspondence's critical section, with a reach
    /// [`Store::take_reach`] found applied, or with the route and serial
    /// [`Store::with_route`] read. A route replaces one held at a lower
    /// serial, and is taken at an equal serial only where no route is held: a
    /// route at an equal serial is the same reach. Nothing below the serial
    /// held is taken, including after the route was forgotten, whose serial
    /// stays as the floor. No route leaves the one held in place and raises
    /// the serial: a reach read without a route may be an older copy of the
    /// correspondent's control, and a held route is dropped only when a push
    /// on it goes unanswered ([`Self::forget_route`]).
    pub(super) fn hold_route(
        &self,
        peer: &CorrespondenceLabel,
        route: Option<Vec<u8>>,
        serial: u64,
        repush: Repush,
    ) -> (Option<Vec<u8>>, Option<Run>) {
        let (old, change, run) = {
            let mut routes = self.routes();
            let (held, floor) = match routes.get(peer) {
                Some((held, floor)) => (held.clone(), Some(*floor)),
                None => (None, None),
            };
            let newer = floor.is_none_or(|floor| serial > floor);
            let takes = newer || (floor == Some(serial) && held.is_none());
            let change = match route_change(held.as_ref(), route.as_ref()) {
                RouteChange::Replaced | RouteChange::Taken if !takes => RouteChange::Older,
                change => change,
            };
            let run = match (&route, change) {
                (Some(route), RouteChange::Taken | RouteChange::Replaced) => {
                    repush.wants(floor.is_some()).map(|collected| Run {
                        slot: enter_run(&self.runs, *peer, route.clone()),
                        collected,
                    })
                }
                _ => None,
            };
            let old = match route {
                Some(route) if takes => {
                    routes.insert(*peer, (Some(route.clone()), serial));
                    held.filter(|old| *old != route)
                }
                _ => {
                    if newer {
                        routes.insert(*peer, (held, serial));
                    }
                    None
                }
            };
            (old, change, run)
        };
        crate::vtrace!("{}", route_line(peer, change));
        (old, run)
    }

    /// [`Self::hold_route`], releasing the route it replaced, outside any
    /// critical section of the store.
    #[cfg(test)]
    pub(super) fn set_peer_route(
        &self,
        peer: &CorrespondenceLabel,
        route: Option<Vec<u8>>,
        serial: u64,
    ) {
        let (old, _) = self.hold_route(peer, route, serial, Repush::Renewed(0));
        self.release(old);
    }

    /// Release `route` on the transport, where one is given.
    pub(super) fn release(&self, route: Option<Vec<u8>>) {
        if let (Some(route), Some(transport)) = (route, &self.transport) {
            transport.release(&route);
        }
    }

    /// Start `run`: push every message of `peer`'s outstanding outbox whose
    /// sequence is at or above the run's `collected`, in sequence order, on
    /// the run's route ([`Pusher::push_slots`]), where the conversation is
    /// established and not being deleted, then every send that joined the
    /// run. The outbox the store loads holds only sequences at or above the
    /// collected position it has taken, so that position is left out too.
    /// `collected` is the cursor of the control that gave the route, which the
    /// store may not have taken yet; the receiver leaves a push of a sequence
    /// older than the last it collected unanswered, and that would end the
    /// run before the first message it has not collected. Where the store will
    /// not load the outbox, the run pushes only what joined it and does not
    /// take over the run before it.
    ///
    /// Called once for each route a take learned ([`Repush`]), outside any
    /// critical section of the store, so a message whose push failed on a
    /// route the correspondent no longer serves reaches it on the new one
    /// rather than waiting for a collection of the record store. The receiver
    /// takes only the sequence it expects next, so the pushes keep the order
    /// of the sequences.
    pub(super) fn push_outstanding(
        &self,
        store: &Store,
        peer: &CorrespondenceLabel,
        events: &mpsc::Sender<RunnerEvent>,
        run: Run,
    ) {
        let Run { slot, collected } = run;
        let route = slot.route().to_vec();
        // Enough for the pushes that joined the run, which come encoded. With
        // no transport no push can have joined.
        let Some(bare) = self.pusher(Some(&route), events) else {
            return;
        };
        let state = match store.load_conv(peer) {
            Ok(state) => state,
            Err(e) => {
                crate::vtrace!(
                    "dm push: outstanding messages of {} not pushed, the store would not load ({e})",
                    tag(peer)
                );
                None
            }
        };
        let full = state
            .as_ref()
            .and_then(|_| self.pusher_on(store, peer, events, Some(&route)));
        let (Some(state), Some(pusher)) = (state, full) else {
            // Nothing read to push: what joined the run is pushed all the
            // same, and the run before this one, which nothing here covers,
            // goes on.
            bare.push_slots(slot, &NO_LOOKUP_KEY, || None);
            return;
        };
        let pushes = !state.delete_pending
            && !state.awaiting_acceptance
            && !state.acceptance_pending
            && state.outgoing_lookup_key != NO_LOOKUP_KEY
            && state.peer_collected.max(collected) < state.send_seq;
        // Read once the run is entered, so a message committed meanwhile is
        // either among these or joins the run.
        let slots = || {
            if !pushes {
                return Some(Vec::new());
            }
            let loaded = store.load();
            #[cfg(test)]
            let loaded = if run_read_fails(peer) {
                Err(StoreError::MissingConversation)
            } else {
                loaded
            };
            let conv = match loaded {
                Ok(loaded) => loaded.convs.into_iter().find(|conv| conv.peer == *peer),
                Err(e) => {
                    crate::vtrace!(
                        "dm push: outstanding messages of {} not pushed, the store would not load ({e})",
                        tag(peer)
                    );
                    return None;
                }
            };
            let slots: Vec<(u16, Vec<u8>)> = conv
                .map(|conv| conv.outstanding_outbox)
                .unwrap_or_default()
                .into_iter()
                .filter(|entry| entry.seq >= collected)
                .map(|entry| (channel::slot_for(entry.seq), entry.ciphertext))
                .collect();
            crate::vtrace!(
                "dm push: {} outstanding messages of {} pushed on a route learned",
                slots.len(),
                tag(peer)
            );
            Some(slots)
        };
        pusher.push_slots(slot, &state.outgoing_lookup_key, slots);
    }

    /// Forget the route held for `peer`, and its serial, and release it, as a
    /// conversation's teardown does.
    pub(super) fn forget_peer(&self, peer: &CorrespondenceLabel) {
        let held = self.routes().remove(peer).and_then(|(route, _)| route);
        self.release(held);
    }

    /// Forget the route `unanswered` was pushed on, where it is still the one
    /// held for its correspondent, keeping the serial it was held at as the
    /// floor, and return it for the caller to [`Self::release`]. Called from
    /// inside the correspondence's critical section ([`Store::forget_route`]),
    /// and outside it where that call failed before its section forgot the
    /// route.
    pub(super) fn forget_route(&self, unanswered: &Unanswered) -> Option<Vec<u8>> {
        let held = {
            let mut routes = self.routes();
            match routes.get_mut(&unanswered.peer) {
                Some((route, _)) if route.as_deref() == Some(unanswered.route.as_slice()) => {
                    route.take()
                }
                _ => None,
            }
        };
        if held.is_some() {
            crate::vtrace!(
                "dm push: route of {} dropped, a push on it went unanswered",
                tag(&unanswered.peer)
            );
        }
        held
    }
}

/// What setting a correspondent's route did to the route held for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteChange {
    /// A route was given where none was held.
    Taken,
    /// A route was given that differs from the one held.
    Replaced,
    /// The route given is the one already held.
    Unchanged,
    /// No route was given, and the one held was kept.
    Kept,
    /// No route was given and none was held.
    NoneHeld,
    /// A route was given that differs from the one held, at a serial at or
    /// below the one held, or below the serial of a route forgotten, and was
    /// not taken.
    Older,
}

/// A run of pushes [`PushShare::hold_route`] entered on the route it took,
/// beside the cursor of the control that gave the route, for
/// [`PushShare::push_outstanding`] to start.
pub(super) struct Run {
    slot: RunSlot,
    collected: u64,
}

/// Whether a take that learns a route pushes the correspondent's outstanding
/// messages on it ([`PushShare::push_outstanding`]), and the cursor of the
/// control that gave the route, `0` where none came with it.
#[derive(Clone, Copy, Debug)]
pub(super) enum Repush {
    /// Only where an entry was held for the correspondent before: a route
    /// held, a route forgotten, or a reach applied without one. The first
    /// route of a correspondent, from an acceptance, comes with the
    /// correspondent's reply to what this side sent.
    Renewed(u64),
    /// Wherever a route is learned: a read at launch, where every route is
    /// the first, and a message committed before the launch may still wait
    /// for its push.
    Learned(u64),
}

impl Repush {
    /// The cursor to push from, where a route learned with an entry held
    /// before (`renewed`) or without one is pushed on.
    fn wants(self, renewed: bool) -> Option<u64> {
        match self {
            Repush::Renewed(collected) if renewed => Some(collected),
            Repush::Renewed(_) => None,
            Repush::Learned(collected) => Some(collected),
        }
    }
}

/// How a reach the runner or the lane handed to [`Store::take_reach`] fared.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Took {
    /// Above the serial applied: taken, and its serial is now the one applied.
    Newer,
    /// At the serial applied: the reach already applied, its route kept where
    /// none was.
    Same,
    /// Below the serial applied, or for a correspondence the store does not
    /// hold: nothing changed.
    Older,
    /// The store failed to answer: nothing is known to have changed.
    Failed,
}

impl Took {
    /// Whether the reach is the one applied now, so its route may be held and
    /// its handle kept.
    pub(super) fn applied(self) -> bool {
        matches!(self, Took::Newer | Took::Same)
    }
}

impl From<ReachTake> for Took {
    fn from(taken: ReachTake) -> Self {
        match taken {
            ReachTake::Newer => Took::Newer,
            ReachTake::Same => Took::Same,
            ReachTake::Older => Took::Older,
        }
    }
}

/// Whether startup reads the correspondent's control for `state` before it
/// holds a route: an established conversation, or one whose acceptance this
/// side has not finished, that is not being deleted and whose correspondent's
/// channel and control key this side holds.
fn reads_peer_control(state: &ConvState) -> bool {
    !state.delete_pending
        && !state.awaiting_acceptance
        && state.outgoing_lookup_key != NO_LOOKUP_KEY
        && state.incoming_lookup_key != NO_LOOKUP_KEY
        && state.peer_control_key.is_some()
}

/// What giving `route` for a correspondent holding `held` does.
pub(super) fn route_change(held: Option<&Vec<u8>>, route: Option<&Vec<u8>>) -> RouteChange {
    match (held, route) {
        (None, Some(_)) => RouteChange::Taken,
        (Some(held), Some(route)) if held == route => RouteChange::Unchanged,
        (Some(_), Some(_)) => RouteChange::Replaced,
        (Some(_), None) => RouteChange::Kept,
        (None, None) => RouteChange::NoneHeld,
    }
}

/// The trace line of a [`RouteChange`] for `peer`.
pub(super) fn route_line(peer: &CorrespondenceLabel, change: RouteChange) -> String {
    let peer = tag(peer);
    match change {
        RouteChange::Taken => format!("dm push: route of {peer} taken"),
        RouteChange::Replaced => format!("dm push: route of {peer} replaced"),
        RouteChange::Unchanged => format!("dm push: route of {peer} unchanged"),
        RouteChange::Kept => format!("dm push: no route of {peer} given, held route kept"),
        RouteChange::NoneHeld => format!("dm push: no route of {peer} given, none held"),
        RouteChange::Older => format!("dm push: an older route of {peer} given, held route kept"),
    }
}

/// Push state a runner holds between flow calls.
pub(super) struct PushState {
    pub(super) share: PushShare,
    admission: Option<Admitting>,
    own_route: Option<OwnRoute>,
    /// Where the last allocation failed, the next attempt.
    route_retry: Option<RouteRetry>,
    /// Where the reach serial of this node's current reach was not written,
    /// the next attempt to write it.
    reach_retry: Option<RouteRetry>,
    own_handle: Option<String>,
    unanswered_rx: mpsc::UnboundedReceiver<Unanswered>,
    /// A stored handle changed since the roster was last reported.
    roster_due: bool,
    /// How many of the queue's shed calls are counted in the health counters.
    shed_counted: u64,
}

impl PushState {
    /// The runner's push state and the inbound queue, which the live lane
    /// receives from.
    pub(super) fn new(parts: Option<PushParts>) -> (Self, Option<PushInbox>) {
        let (unanswered, unanswered_rx) = mpsc::unbounded_channel();
        let (transport, inbound) = match parts {
            Some(parts) => (Some(parts.transport), Some(parts.inbound)),
            None => (None, None),
        };
        let state = Self {
            share: PushShare {
                transport,
                peer_routes: Arc::default(),
                unanswered,
                kept: Arc::default(),
                runs: Arc::default(),
            },
            admission: inbound.as_ref().map(PushInbox::admission),
            own_route: None,
            route_retry: None,
            reach_retry: None,
            own_handle: None,
            unanswered_rx,
            roster_due: false,
            shed_counted: 0,
        };
        (state, inbound)
    }

    /// The next correspondent whose push went unanswered. The sender lives as
    /// long as this state, so this waits rather than ending.
    pub(super) async fn unanswered(&mut self) -> Option<Unanswered> {
        self.unanswered_rx.recv().await
    }

    /// [`PushShare::pusher`].
    pub(super) fn pusher(
        &self,
        route: Option<&Vec<u8>>,
        events: &mpsc::Sender<RunnerEvent>,
    ) -> Option<Pusher> {
        self.share.pusher(route, events)
    }

    /// When the next route allocation attempt is due, where one is.
    pub(super) fn route_retry_due(&self) -> Option<Instant> {
        self.route_retry.map(|retry| retry.due)
    }

    /// When the next attempt to write an owed reach serial is due, where one
    /// is owed.
    pub(super) fn reach_retry_due(&self) -> Option<Instant> {
        self.reach_retry.map(|retry| retry.due)
    }

    fn reach(&self) -> Reach {
        Reach {
            route: self.own_route.as_ref().map(|route| route.blob.clone()),
            handle: self.own_handle.clone(),
        }
    }
}

impl<R: RunnerRecords> Runner<R> {
    /// Admit message pushes from every established conversation, and, where
    /// this node has a push transport, allocate this node's route and then
    /// hold each correspondent's.
    ///
    /// The route held is the one the correspondent's control subkey names,
    /// read here once per established conversation, one at a time, where
    /// that control's reach is newer than the one applied; a newer reach
    /// naming no route forgets the route kept. Where the read fails, or the
    /// reach is not newer, the route kept is held with its own serial, the
    /// two read together inside the critical section the live lane's takes
    /// also run in. A read that failed on the local store counts one store
    /// failure, and the route kept is still held where it reads, as it does
    /// after a failed write; the pair's own failure is not counted again. A
    /// missing conversation holds nothing and is not a store failure. Nothing
    /// is written to the
    /// network, so none of this waits on a channel reopen:
    /// [`Self::publish_route`] publishes the route once the channels are open.
    pub(super) async fn start_push(&mut self) -> Result<(), Halt> {
        let convs = self.load_convs().ok();
        if let Some(convs) = &convs {
            self.admit_pushes_for(convs);
        }
        // This node's route does not wait on the reads, so it is ready once
        // they end.
        if let Some(transport) = self.push.share.transport.clone() {
            self.allocate_route(transport.as_ref(), ROUTE_RETRY_FIRST)
                .await;
        }
        if let Some(convs) = convs {
            let reads = self.push.share.transport.is_some();
            for conv in &convs {
                self.check_stop()?;
                let read = if reads && reads_peer_control(&conv.state) {
                    self.read_peer_control(&conv.peer, true)
                } else {
                    ControlRead::NotNewer
                };
                let counted = match read {
                    ControlRead::Newer => {
                        if let Some(kept) = &conv.route {
                            if !self.push.share.holds_route(&conv.peer)
                                && self.store.forget_route(&conv.peer, kept, || {}).is_err()
                            {
                                self.records.health.store_failures += 1;
                            }
                        }
                        continue;
                    }
                    // Counted once, by the read. A failed write leaves the
                    // record readable, so the pair below is still read; a
                    // failed read fails it again, and that is not counted.
                    ControlRead::StoreFailed => true,
                    ControlRead::NotNewer => false,
                };
                // The route kept and its serial are read as one pair, inside
                // the section every take of the live lane also runs in, so a
                // route the lane took meanwhile, from a reach notice or an
                // acceptance, is the one held, whichever lands first.
                // A route the read took is held already and gives none here.
                let share = &self.push.share;
                let mut released = None;
                let mut run = None;
                let seeded = self.store.with_route(&conv.peer, |route, serial| {
                    if route.is_some() {
                        (released, run) = share.hold_route(
                            &conv.peer,
                            route.map(<[u8]>::to_vec),
                            serial,
                            Repush::Learned(0),
                        );
                    }
                });
                share.release(released);
                if let Some(run) = run {
                    share.push_outstanding(&self.store, &conv.peer, &self.events, run);
                }
                match seeded {
                    Ok(()) | Err(StoreError::MissingConversation) => {}
                    Err(_) if counted => {}
                    Err(_) => self.records.health.store_failures += 1,
                }
            }
        }
        Ok(())
    }

    /// Publish the reach [`Self::start_push`] left in every established
    /// conversation's control subkey, where this node has a push transport.
    pub(super) async fn publish_route(&mut self) -> Result<(), Halt> {
        if self.push.share.transport.is_none() {
            return Ok(());
        }
        self.push_reach_notices();
        self.republish_controls().await
    }

    /// Replace this node's route, push it to every correspondent whose route
    /// is held, and republish every control subkey with it.
    async fn renew_route(&mut self) -> Result<(), Halt> {
        let Some(transport) = self.push.share.transport.clone() else {
            return Ok(());
        };
        self.allocate_route(transport.as_ref(), ROUTE_RETRY_FIRST)
            .await;
        self.push_reach_notices();
        self.republish_controls().await
    }

    /// Push a reach notice carrying this node's current route to every
    /// established conversation whose correspondent's route is held: the
    /// control subkey this side's channel is about to be rewritten with. Each
    /// is made on its own task; one that goes unanswered forgets the route it
    /// was made on. Nothing where this node holds no route.
    fn push_reach_notices(&mut self) {
        if self.push.own_route.is_none() {
            return;
        }
        self.set_own_reach();
        let Ok(convs) = self.load_convs() else {
            return;
        };
        for conv in convs {
            let state = &conv.state;
            if state.delete_pending
                || state.acceptance_pending
                || state.awaiting_acceptance
                || state.outgoing_lookup_key == NO_LOOKUP_KEY
                || !self.push.share.holds_route(&conv.peer)
            {
                continue;
            }
            let Some(control) = current_control(&self.store, state) else {
                continue;
            };
            let Some(pusher) = self
                .push
                .share
                .pusher_for(&self.store, &conv.peer, &self.events)
            else {
                continue;
            };
            crate::vtrace!("dm push: reach notice to {}", tag(&conv.peer));
            pusher.push_reach(conv.peer, &state.outgoing_lookup_key, &control);
        }
    }

    /// Try again to allocate this node's route, where an earlier allocation
    /// failed and the next attempt is due, and republish every control subkey
    /// once one is allocated.
    pub(super) async fn retry_route(&mut self) -> Result<(), Halt> {
        let Some(retry) = self.push.route_retry else {
            return Ok(());
        };
        if Instant::now() < retry.due {
            return Ok(());
        }
        self.check_stop()?;
        let Some(transport) = self.push.share.transport.clone() else {
            self.push.route_retry = None;
            return Ok(());
        };
        let wait = retry.wait.saturating_mul(2).min(ROUTE_RETRY_CAP);
        if self.allocate_route(transport.as_ref(), wait).await {
            self.push_reach_notices();
            self.republish_controls().await
        } else {
            Ok(())
        }
    }

    /// Ask `transport` for a route and hold it, or hold none and try again
    /// `wait` from now. Whether a route was allocated. The reach the store
    /// holds names the route from here on, and correspondents learn it from
    /// the reach notices and the control subkeys written with it.
    async fn allocate_route(&mut self, transport: &dyn PushTransport, wait: Duration) -> bool {
        let allocated = match transport.new_route().await {
            Ok(route) => {
                crate::vtrace!("dm push: route allocated, {} bytes", route.blob.len());
                self.push.own_route = Some(route);
                self.push.route_retry = None;
                true
            }
            Err(e) => {
                crate::vtrace!(
                    "dm push: no route, pushes to this node are off, next try in {} s ({e})",
                    wait.as_secs()
                );
                self.push.own_route = None;
                self.push.route_retry = Some(RouteRetry {
                    due: Instant::now() + wait,
                    wait,
                });
                false
            }
        };
        self.set_own_reach();
        allocated
    }

    /// Set the reach and rewrite the control subkey of every established
    /// conversation this side has written one for. What is queued is served
    /// before each rewrite, as a long pass serves it between its network
    /// calls, so a send the live lane committed meanwhile has its slot written
    /// without waiting for the remaining rewrites. That is the one place a
    /// command or lane note is served from inside another, and the exception
    /// is stated at [`Runner::serve_queued`].
    async fn republish_controls(&mut self) -> Result<(), Halt> {
        self.set_own_reach();
        let Ok(convs) = self.load_convs() else {
            return Ok(());
        };
        // What had been served when `convs` was loaded; anything served since
        // may have changed any conversation still to come.
        let loaded_at = self.served;
        for conv in convs {
            self.check_stop()?;
            // Served from inside the route death or own-handle command this
            // republish ends, as [`Runner::serve_queued`] states. A route death
            // served here republishes again, and that republish's serve does
            // nothing because `serving` is set, so the nesting stops at two
            // levels; the box gives the recursive future a fixed size. Where
            // this republish itself runs inside `serve_queued`, during a long
            // pass, nothing is served here and a committed send waits for the
            // whole republish.
            Box::pin(self.serve_queued()).await?;
            let reloaded;
            let conv = if self.served == loaded_at {
                &conv
            } else {
                // What was served may have deleted or changed the conversation.
                match self.load_one(&conv.peer) {
                    Ok(Some(conv)) => {
                        reloaded = conv;
                        &reloaded
                    }
                    Ok(None) => {
                        crate::vtrace!(
                            "dm push: control of {} not rewritten, deleted by a command",
                            tag(&conv.peer)
                        );
                        continue;
                    }
                    Err(()) => {
                        crate::vtrace!(
                            "dm push: control of {} not rewritten, the store would not load it",
                            tag(&conv.peer)
                        );
                        continue;
                    }
                }
            };
            let state = &conv.state;
            if state.delete_pending
                || state.acceptance_pending
                || state.outgoing_lookup_key == NO_LOOKUP_KEY
            {
                continue;
            }
            // A channel whose reopen failed is left to its scheduled reopen,
            // which rewrites the control subkey with the reach set here once
            // the channel opens, so a republish never waits out a failing open.
            if self
                .records
                .reopen_pending
                .contains_key(&state.outgoing_lookup_key)
            {
                crate::vtrace!(
                    "dm push: control of {} not rewritten, its channel is not open",
                    tag(&conv.peer)
                );
                continue;
            }
            let Some(control) = current_control(&self.store, state) else {
                continue;
            };
            if let Err(e) = self.records.write_channel(
                &state.outgoing_lookup_key,
                channel::CONTROL_SUBKEY,
                &control,
            ) {
                crate::vtrace!(
                    "dm push: control rewrite of {} failed ({e})",
                    tag(&conv.peer)
                );
            }
        }
        Ok(())
    }

    /// Take `handle` as this side's own, and republish where it changed.
    pub(super) async fn set_own_handle(&mut self, handle: &str) -> Result<(), Halt> {
        let verified = Reach {
            route: None,
            handle: Some(handle.to_owned()),
        }
        .verified_handle(self.signer.public_key());
        if verified.is_none() {
            crate::vtrace!("dm push: own handle does not name this identity, not published");
        }
        if verified == self.push.own_handle {
            return Ok(());
        }
        self.push.own_handle = verified;
        self.republish_controls().await
    }

    /// Admit message pushes for the channels of `convs` and no others, and
    /// have the live lane find each of `convs` by the channel it reads.
    pub(super) fn admit_pushes_for(&self, convs: &[LoadedConv]) {
        self.lane.set_readers(convs);
        if let Some(admission) = &self.push.admission {
            admission.set_known(
                convs
                    .iter()
                    .map(|conv| conv.state.incoming_lookup_key)
                    .filter(|key| *key != NO_LOOKUP_KEY),
            );
        }
    }

    /// Set this node's route and handle as the reach every control record
    /// written from now on carries ([`Store::set_reach`]). A serial that could
    /// not be written, or a reach-serial record overwritten because it did not
    /// read or decode, counts a store failure. A serial that could not be
    /// written is owed: control records carry the reach and serial held
    /// before until a later call writes it, and [`Self::retry_owed_reach`]
    /// makes that call from the schedule, [`ROUTE_RETRY_FIRST`] after the
    /// failure and twice as long after each further failure, up to
    /// [`ROUTE_RETRY_CAP`].
    fn set_own_reach(&mut self) {
        match self.store.set_reach(self.push.reach()) {
            Ok(SetReach::Unchanged | SetReach::Issued) => self.push.reach_retry = None,
            Ok(SetReach::IssuedOverUndecodable) => {
                self.push.reach_retry = None;
                crate::vtrace!("dm push: the reach-serial record did not read, overwritten");
                self.records.health.store_failures += 1;
            }
            Err(e) => {
                crate::vtrace!(
                    "dm push: the reach serial was not written ({e}), the reach held before stays"
                );
                self.records.health.store_failures += 1;
                if self.push.reach_retry.is_none() {
                    self.push.reach_retry = Some(RouteRetry {
                        due: Instant::now() + ROUTE_RETRY_FIRST,
                        wait: ROUTE_RETRY_FIRST,
                    });
                }
            }
        }
    }

    /// Write the reach serial owed since a [`Self::set_own_reach`] failed,
    /// where the attempt is due, and push and republish the reach once it is
    /// written. Nothing where none is owed.
    pub(super) async fn retry_owed_reach(&mut self) -> Result<(), Halt> {
        let Some(retry) = self.push.reach_retry else {
            return Ok(());
        };
        if Instant::now() < retry.due {
            return Ok(());
        }
        self.check_stop()?;
        self.push.reach_retry = None;
        self.set_own_reach();
        if self.push.reach_retry.is_some() {
            let wait = retry.wait.saturating_mul(2).min(ROUTE_RETRY_CAP);
            self.push.reach_retry = Some(RouteRetry {
                due: Instant::now() + wait,
                wait,
            });
            return Ok(());
        }
        crate::vtrace!("dm push: the owed reach serial was written, republishing");
        self.push_reach_notices();
        self.republish_controls().await
    }

    /// Take the reach a correspondent's control subkey gave at `serial`
    /// through [`Store::take_reach`]: in one critical section of the
    /// correspondence the serial is compared, the route and serial are
    /// written, the route is held in memory where the store took the reach
    /// ([`Took::Newer`] or [`Took::Same`]), and the handle is kept where it
    /// names the correspondent's identity. A route learned there has the
    /// messages outstanding to `peer` pushed on it once that section is left,
    /// where `repush` says so ([`PushShare::push_outstanding`]). A reach older than the one applied
    /// changes nothing. A handle kept has the roster reported. A take that
    /// stood while the handle record would not read or write counts one store
    /// failure
    /// ([`ReachApplied::faults`](daemonseed_core::dm::store::ReachApplied::faults));
    /// one the store refused counts one and answers [`Took::Failed`].
    ///
    /// A reach the live lane already took, handed over for its handle from
    /// an acceptance, a watched control or a reach notice, comes here without
    /// its route, and keeps its handle only while its serial is still the one
    /// applied.
    pub(super) fn take_reach(
        &mut self,
        peer: &CorrespondenceLabel,
        reach: &Reach,
        serial: u64,
        repush: Repush,
    ) -> Took {
        let share = &self.push.share;
        let mut released = None;
        let mut run = None;
        let taken = self.store.take_reach(peer, serial, reach, |take| {
            if take.applied() {
                (released, run) = share.hold_route(peer, reach.route.clone(), serial, repush);
            }
        });
        share.release(released);
        run_before_run(peer);
        if let Some(run) = run {
            share.push_outstanding(&self.store, peer, &self.events, run);
        }
        match taken {
            Ok(taken) => {
                self.push.roster_due |= taken.handle_changed;
                if let Some(e) = &taken.handle_error {
                    crate::vtrace!("dm push: handle of {} not kept ({e})", tag(peer));
                }
                self.records.health.store_failures += taken.faults();
                Took::from(taken.take)
            }
            Err(StoreError::MissingConversation) => Took::Older,
            Err(_) => {
                self.records.health.store_failures += 1;
                Took::Failed
            }
        }
    }

    /// The reach a held contact request's correspondent published, and the
    /// reach serial it published it at.
    pub(super) fn held_reach(&self, request: &ContactRequestId) -> Option<(Reach, u64)> {
        match self.requests.get(request).map(|entry| &entry.held) {
            Some(Held::Request(held)) => Some((held.reach.clone(), held.reach_serial)),
            _ => None,
        }
    }

    /// Forget, and release, the route an unanswered push was made on, in
    /// memory and where it is kept beside the conversation, so the next
    /// message to its correspondent is not pushed until the correspondent
    /// gives a route again. A route the correspondent has given since is kept,
    /// and nothing else of the conversation changes. The next collection of
    /// the conversation reads the correspondent's control, which gives the
    /// route back where its serial is the one applied, and a new one where it
    /// is newer.
    ///
    /// A push whose message the correspondent has since collected (for an
    /// acceptance push, its reply) keeps its route: the push reached the correspondent and only its answer was
    /// lost. At most [`KEPT_UNANSWERED_MAX`] such pushes in a row on one route
    /// keep it, so a route that answers nothing is dropped all the same.
    pub(super) fn forget_route(&mut self, unanswered: &Unanswered) {
        if self.unanswered_but_collected(unanswered) {
            if self.push.share.keep_unanswered(unanswered) {
                crate::vtrace!(
                    "dm push: a push on {} went unanswered, its message was collected, route kept",
                    tag(&unanswered.peer)
                );
                return;
            }
            crate::vtrace!(
                "dm push: a push on {} went unanswered, its message was collected, \
                 route dropped after {KEPT_UNANSWERED_MAX} kept in a row",
                tag(&unanswered.peer)
            );
        }
        // Forgotten in memory inside the correspondence's section, in the
        // order of every take, and outside it where the section failed.
        let share = &self.push.share;
        let mut released = None;
        let mut forgotten = false;
        let removed = self
            .store
            .forget_route(&unanswered.peer, &unanswered.route, || {
                released = share.forget_route(unanswered);
                forgotten = true;
            });
        if !forgotten {
            released = share.forget_route(unanswered);
        }
        share.release(released);
        match removed {
            Ok(true) => {
                crate::vtrace!("dm push: kept route of {} forgotten", tag(&unanswered.peer))
            }
            Ok(false) => {}
            Err(_) => self.records.health.store_failures += 1,
        }
    }

    /// Whether `unanswered` is a message or acceptance push whose message the
    /// correspondent has collected: the conversation's stored cursor is past
    /// its sequence.
    /// A reach notice, a conversation the store does not hold, and a store
    /// read that fails say no, the last counted where the store refused.
    fn unanswered_but_collected(&mut self, unanswered: &Unanswered) -> bool {
        let Some(seq) = unanswered.seq else {
            return false;
        };
        match self.store.load_conv(&unanswered.peer) {
            Ok(Some(state)) => state.peer_collected > seq,
            Ok(None) => false,
            Err(_) => {
                self.records.health.store_failures += 1;
                false
            }
        }
    }

    /// Report the roster where a stored handle changed, and forget the routes
    /// of correspondents whose pushes went unanswered.
    pub(super) async fn flush_push_notes(&mut self) -> Result<(), Halt> {
        while let Ok(unanswered) = self.push.unanswered_rx.try_recv() {
            self.forget_route(&unanswered);
        }
        self.records.health.absorb_lane(&self.lane.take_counts());
        if let Some(admission) = &self.push.admission {
            let shed = admission.shed();
            self.records.health.pushes_dropped += shed.saturating_sub(self.push.shed_counted);
            self.push.shed_counted = shed;
        }
        if std::mem::take(&mut self.push.roster_due) {
            self.emit_roster().await?;
        }
        Ok(())
    }

    /// The route deaths the live lane passed on: renew this node's route where
    /// it is among them.
    pub(super) async fn routes_died(&mut self, dead: &[String]) -> Result<(), Halt> {
        let own = self.push.own_route.as_ref().map(|route| route.id.clone());
        if own.is_some_and(|own| dead.contains(&own)) {
            crate::vtrace!("dm push: this node's route died, renewing");
            self.renew_route().await?;
        }
        Ok(())
    }
}
