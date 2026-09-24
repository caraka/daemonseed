//! The runner's side of push delivery: this node's route and handle, the
//! routes of its correspondents, and the pushes it is handed.
//!
//! `docs/design/direct-messaging.md` § Delivery, *Push*. The runner allocates a
//! private route at startup, sets it and its handle as the reach every control
//! record carries ([`Store::set_reach`]), and rewrites the control subkey of
//! every established conversation. It does so again whenever the route dies
//! or the handle changes. A correspondent's route is learned from every
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

use crate::dm::push::{Admitting, OwnRoute, PushInbox, PushParts, PushTransport, Pusher};

/// What the runner and the live lane both push with: the transport, the
/// routes of this side's correspondents, and where an unanswered push names
/// its correspondent.
#[derive(Clone)]
pub(super) struct PushShare {
    pub(super) transport: Option<Arc<dyn PushTransport>>,
    peer_routes: Arc<std::sync::Mutex<HashMap<CorrespondenceLabel, Vec<u8>>>>,
    unanswered: mpsc::UnboundedSender<CorrespondenceLabel>,
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

    /// Take `route` as `peer`'s, or none, releasing the route held before
    /// where it changes.
    fn set_peer_route(&self, peer: &CorrespondenceLabel, route: Option<Vec<u8>>) {
        let old = match route {
            Some(route) => self
                .routes()
                .insert(*peer, route.clone())
                .filter(|old| *old != route),
            None => self.routes().remove(peer),
        };
        if let (Some(old), Some(transport)) = (old, &self.transport) {
            transport.release(&old);
        }
    }
}

/// Push state a runner holds between flow calls.
pub(super) struct PushState {
    pub(super) share: PushShare,
    admission: Option<Admitting>,
    own_route: Option<OwnRoute>,
    own_handle: Option<String>,
    unanswered_rx: mpsc::UnboundedReceiver<CorrespondenceLabel>,
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
            own_handle: None,
            unanswered_rx,
            roster_due: false,
            shed_counted: 0,
        };
        (state, inbound)
    }

    /// [`PushShare::pusher`].
    pub(super) fn pusher(
        &self,
        route: Option<&Vec<u8>>,
        events: &mpsc::Sender<RunnerEvent>,
    ) -> Option<Pusher> {
        self.share.pusher(route, events)
    }

    fn reach(&self) -> Reach {
        Reach {
            route: self.own_route.as_ref().map(|route| route.blob.clone()),
            handle: self.own_handle.clone(),
        }
    }
}

impl<R: RunnerRecords> Runner<R> {
    /// Allocate this node's route, where it has a push transport, and publish
    /// it in every established conversation's control subkey.
    pub(super) async fn start_push(&mut self) -> Result<(), Halt> {
        if let Ok(convs) = self.load_convs() {
            self.admit_pushes_for(&convs);
        }
        if self.push.share.transport.is_some() {
            self.renew_route().await?;
        }
        Ok(())
    }

    /// Replace this node's route and republish every control subkey with it.
    async fn renew_route(&mut self) -> Result<(), Halt> {
        let Some(transport) = self.push.share.transport.clone() else {
            return Ok(());
        };
        match transport.new_route().await {
            Ok(route) => {
                crate::vtrace!("dm push: route allocated, {} bytes", route.blob.len());
                self.push.own_route = Some(route);
            }
            Err(e) => {
                crate::vtrace!("dm push: no route, pushes to this node are off ({e})");
                self.push.own_route = None;
            }
        }
        self.republish_controls().await
    }

    /// Set the reach and rewrite the control subkey of every established
    /// conversation this side has written one for.
    async fn republish_controls(&mut self) -> Result<(), Halt> {
        self.store.set_reach(self.push.reach());
        let Ok(convs) = self.load_convs() else {
            return Ok(());
        };
        for conv in convs {
            self.check_stop()?;
            let state = &conv.state;
            if state.delete_pending
                || state.acceptance_pending
                || state.outgoing_lookup_key == NO_LOOKUP_KEY
            {
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

    /// Report the roster where a stored handle changed, and forget the routes
    /// of correspondents whose pushes went unanswered.
    pub(super) async fn flush_push_notes(&mut self) -> Result<(), Halt> {
        while let Ok(peer) = self.push.unanswered_rx.try_recv() {
            self.push.share.set_peer_route(&peer, None);
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
