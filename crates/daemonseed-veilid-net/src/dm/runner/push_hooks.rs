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
//! control subkey of theirs the runner opens, and held in memory only; a push
//! that goes unanswered forgets it until the next such read.
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
    Admitting, OwnRoute, PushInbox, PushParts, PushTransport, Pusher, Unanswered,
};

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

/// What the runner and the live lane both push with: the transport, the
/// routes of this side's correspondents, and where an unanswered push names
/// its correspondent.
#[derive(Clone)]
pub(super) struct PushShare {
    pub(super) transport: Option<Arc<dyn PushTransport>>,
    peer_routes: Arc<std::sync::Mutex<HashMap<CorrespondenceLabel, Vec<u8>>>>,
    unanswered: mpsc::UnboundedSender<Unanswered>,
}

impl PushShare {
    fn routes(&self) -> std::sync::MutexGuard<'_, HashMap<CorrespondenceLabel, Vec<u8>>> {
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
        })
    }

    /// What a message push to `peer` is made with, where its route and this
    /// side's control key for the conversation are known.
    pub(super) fn pusher_for(
        &self,
        store: &Store,
        peer: &CorrespondenceLabel,
        events: &mpsc::Sender<RunnerEvent>,
    ) -> Option<Pusher> {
        let state = store.load_conv(peer).ok()??;
        let key = state.own_control_key.as_ref()?;
        let route = self.routes().get(peer).cloned();
        let mut pusher = self.pusher(route.as_ref(), events)?;
        pusher.answer_key = Some(Arc::new(core_push::AnswerKey::new(key)));
        Some(pusher)
    }

    /// Whether a route is held for `peer`.
    pub(super) fn holds_route(&self, peer: &CorrespondenceLabel) -> bool {
        self.routes().contains_key(peer)
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

    /// Take `route` as `peer`'s, releasing the route held before where it
    /// changes. No route leaves the one held in place: a reach read without a
    /// route may be an older copy of the correspondent's control, and a held
    /// route is dropped only when a push on it goes unanswered
    /// ([`Self::forget_route`]).
    pub(super) fn set_peer_route(&self, peer: &CorrespondenceLabel, route: Option<Vec<u8>>) {
        let (old, change) = {
            let mut routes = self.routes();
            let change = route_change(routes.get(peer), route.as_ref());
            let old = match route {
                Some(route) => routes
                    .insert(*peer, route.clone())
                    .filter(|old| *old != route),
                None => None,
            };
            (old, change)
        };
        crate::vtrace!("{}", route_line(peer, change));
        if let (Some(old), Some(transport)) = (old, &self.transport) {
            transport.release(&old);
        }
    }

    /// Forget and release the route `unanswered` was pushed on, where it is
    /// still the one held for its correspondent.
    fn forget_route(&self, unanswered: &Unanswered) {
        let held = {
            let mut routes = self.routes();
            match routes.get(&unanswered.peer) {
                Some(route) if *route == unanswered.route => routes.remove(&unanswered.peer),
                _ => None,
            }
        };
        if held.is_some() {
            crate::vtrace!(
                "dm push: route of {} dropped, a push on it went unanswered",
                tag(&unanswered.peer)
            );
        }
        if let (Some(held), Some(transport)) = (held, &self.transport) {
            transport.release(&held);
        }
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
    }
}

/// Push state a runner holds between flow calls.
pub(super) struct PushState {
    pub(super) share: PushShare,
    admission: Option<Admitting>,
    own_route: Option<OwnRoute>,
    /// Where the last allocation failed, the next attempt.
    route_retry: Option<RouteRetry>,
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
            },
            admission: inbound.as_ref().map(PushInbox::admission),
            own_route: None,
            route_retry: None,
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

    fn reach(&self) -> Reach {
        Reach {
            route: self.own_route.as_ref().map(|route| route.blob.clone()),
            handle: self.own_handle.clone(),
        }
    }
}

impl<R: RunnerRecords> Runner<R> {
    /// Admit message pushes from every established conversation, and allocate
    /// this node's route where it has a push transport. Nothing is written to
    /// the network, so neither waits on a channel reopen:
    /// [`Self::publish_route`] publishes the route once the channels are open.
    pub(super) async fn start_push(&mut self) -> Result<(), Halt> {
        if let Ok(convs) = self.load_convs() {
            self.admit_pushes_for(&convs);
        }
        if let Some(transport) = self.push.share.transport.clone() {
            self.allocate_route(transport.as_ref(), ROUTE_RETRY_FIRST)
                .await;
        }
        Ok(())
    }

    /// Publish the reach [`Self::start_push`] left in every established
    /// conversation's control subkey, where this node has a push transport.
    pub(super) async fn publish_route(&mut self) -> Result<(), Halt> {
        if self.push.share.transport.is_none() {
            return Ok(());
        }
        self.republish_controls().await
    }

    /// Replace this node's route and republish every control subkey with it.
    async fn renew_route(&mut self) -> Result<(), Halt> {
        let Some(transport) = self.push.share.transport.clone() else {
            return Ok(());
        };
        self.allocate_route(transport.as_ref(), ROUTE_RETRY_FIRST)
            .await;
        self.republish_controls().await
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
            self.republish_controls().await
        } else {
            Ok(())
        }
    }

    /// Ask `transport` for a route and hold it, or hold none and try again
    /// `wait` from now. Whether a route was allocated.
    async fn allocate_route(&mut self, transport: &dyn PushTransport, wait: Duration) -> bool {
        match transport.new_route().await {
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
        }
    }

    /// Set the reach and rewrite the control subkey of every established
    /// conversation this side has written one for. What is queued is served
    /// before each rewrite, as a long pass serves it between its network
    /// calls, so a send the live lane committed meanwhile has its slot written
    /// without waiting for the remaining rewrites. That is the one place a
    /// command or lane note is served from inside another, and the exception
    /// is stated at [`Runner::serve_queued`].
    async fn republish_controls(&mut self) -> Result<(), Halt> {
        self.store.set_reach(self.push.reach());
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

    /// Admit message pushes for the channels of `convs` and no others.
    pub(super) fn admit_pushes_for(&self, convs: &[LoadedConv]) {
        if let Some(admission) = &self.push.admission {
            admission.set_known(
                convs
                    .iter()
                    .map(|conv| conv.state.incoming_lookup_key)
                    .filter(|key| *key != NO_LOOKUP_KEY),
            );
        }
    }

    /// Hold what a correspondent's control subkey said of how it is reached:
    /// its route, and its handle where the handle names its identity.
    pub(super) fn note_reach(&mut self, peer: &CorrespondenceLabel, reach: &Reach) {
        self.push.share.set_peer_route(peer, reach.route.clone());
        let Ok(Some(state)) = self.store.load_conv(peer) else {
            return;
        };
        if let Some(handle) = reach.verified_handle(state.peer_identity_pk.as_slice()) {
            match self.store.record_handle(peer, &handle) {
                Ok(changed) => self.push.roster_due |= changed,
                Err(_) => self.records.health.store_failures += 1,
            }
        }
    }

    /// The reach a held contact request's correspondent published.
    pub(super) fn held_reach(&self, request: &ContactRequestId) -> Option<Reach> {
        match self.requests.get(request).map(|entry| &entry.held) {
            Some(Held::Request(held)) => Some(held.reach.clone()),
            _ => None,
        }
    }

    /// Forget, and release, the route an unanswered push was made on, so the
    /// next message to its correspondent is not pushed until its control
    /// subkey names a route again. A route the correspondent has published
    /// since is kept.
    pub(super) fn forget_route(&self, unanswered: &Unanswered) {
        self.push.share.forget_route(unanswered);
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
