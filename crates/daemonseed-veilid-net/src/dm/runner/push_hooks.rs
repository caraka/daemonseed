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
//! A pushed message or acceptance is served between two network calls, as a
//! queued command is, and only while it is still inside
//! [`PUSH_ANSWER_WINDOW`]. It is answered only once what it carried has been
//! persisted, through [`daemonseed_core::dm::push`].
//!
//! Serves FC1.

use super::*;

use daemonseed_core::dm::channel::Reach;
use daemonseed_core::dm::push::{self as core_push, Push, Taken, ANSWER_LEN};

use crate::dm::push::{
    OwnRoute, PushInbound, PushInbox, PushParts, PushTransport, Pusher, PUSH_ANSWER_WINDOW,
};

/// Push state a runner holds between flow calls.
pub(super) struct PushState {
    transport: Option<Arc<dyn PushTransport>>,
    inbound: Option<PushInbox>,
    own_route: Option<OwnRoute>,
    own_handle: Option<String>,
    peer_routes: HashMap<CorrespondenceLabel, Vec<u8>>,
    unanswered_tx: mpsc::UnboundedSender<CorrespondenceLabel>,
    unanswered_rx: mpsc::UnboundedReceiver<CorrespondenceLabel>,
    /// A stored handle changed since the roster was last reported.
    roster_due: bool,
    /// How many of the queue's shed calls are counted in the health counters.
    shed_counted: u64,
}

impl PushState {
    pub(super) fn new(parts: Option<PushParts>) -> Self {
        let (unanswered_tx, unanswered_rx) = mpsc::unbounded_channel();
        let (transport, inbound) = match parts {
            Some(parts) => (Some(parts.transport), Some(parts.inbound)),
            None => (None, None),
        };
        Self {
            transport,
            inbound,
            own_route: None,
            own_handle: None,
            peer_routes: HashMap::new(),
            unanswered_tx,
            unanswered_rx,
            roster_due: false,
            shed_counted: 0,
        }
    }

    /// The next thing the push transport hands the runner; pending for ever
    /// where there is no transport.
    pub(super) async fn next(&mut self) -> Option<PushInbound> {
        match &mut self.inbound {
            Some(inbound) => inbound.recv().await,
            None => std::future::pending().await,
        }
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
            unanswered: self.unanswered_tx.clone(),
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
        let mut pusher = self.pusher(self.peer_routes.get(peer), events)?;
        pusher.answer_key = Some(Arc::new(core_push::AnswerKey::new(key)));
        Some(pusher)
    }

    /// Take `route` as `peer`'s, or none, releasing the route held before
    /// where it changes.
    fn set_peer_route(&mut self, peer: &CorrespondenceLabel, route: Option<Vec<u8>>) {
        let old = match route {
            Some(route) => self
                .peer_routes
                .insert(*peer, route.clone())
                .filter(|old| *old != route),
            None => self.peer_routes.remove(peer),
        };
        if let (Some(old), Some(transport)) = (old, &self.transport) {
            transport.release(&old);
        }
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
        if self.push.transport.is_some() {
            self.renew_route().await?;
        }
        Ok(())
    }

    /// Replace this node's route and republish every control subkey with it.
    async fn renew_route(&mut self) -> Result<(), Halt> {
        let Some(transport) = self.push.transport.clone() else {
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
        if let Some(inbound) = &self.push.inbound {
            inbound.set_known(
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
        self.push.set_peer_route(peer, reach.route.clone());
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
            self.push.set_peer_route(&peer, None);
        }
        if let Some(inbound) = &self.push.inbound {
            let shed = inbound.shed();
            self.records.health.pushes_dropped += shed.saturating_sub(self.push.shed_counted);
            self.push.shed_counted = shed;
        }
        if std::mem::take(&mut self.push.roster_due) {
            self.emit_roster().await?;
        }
        Ok(())
    }

    /// Serve every push already queued. Nothing is served before startup
    /// finishes.
    pub(super) async fn serve_queued_pushes(&mut self) -> Result<(), Halt> {
        if !self.started {
            return Ok(());
        }
        loop {
            let next = match &mut self.push.inbound {
                Some(inbound) => inbound.try_recv(),
                None => None,
            };
            let Some(next) = next else {
                return Ok(());
            };
            self.serve_push(next).await?;
        }
    }

    /// Serve one thing the push transport handed the runner.
    pub(super) async fn serve_push(&mut self, inbound: PushInbound) -> Result<(), Halt> {
        match inbound {
            PushInbound::RoutesDied(dead) => {
                let own = self.push.own_route.as_ref().map(|route| route.id.clone());
                if own.is_some_and(|own| dead.contains(&own)) {
                    crate::vtrace!("dm push: this node's route died, renewing");
                    self.renew_route().await?;
                }
                Ok(())
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
                    self.records.health.pushes_expired += 1;
                    return Ok(());
                }
                match Push::decode(&message) {
                    Some(push @ Push::Message { .. }) => self.take_pushed_message(id, &push).await,
                    Some(push @ Push::Acceptance { .. }) => {
                        self.take_pushed_acceptance(id, &push).await
                    }
                    None => {
                        crate::vtrace!("dm push: a push that does not decode, dropped");
                        self.records.health.pushes_dropped += 1;
                        Ok(())
                    }
                }
            }
        }
    }

    fn answer_recorded(&self, id: u64, answer: [u8; ANSWER_LEN]) {
        let Some(transport) = self.push.transport.clone() else {
            return;
        };
        tokio::spawn(async move {
            if let Err(e) = transport.reply(id, answer.to_vec()).await {
                crate::vtrace!("dm push: answer failed ({e})");
            }
        });
    }

    async fn take_pushed_message(&mut self, id: u64, push: &Push) -> Result<(), Halt> {
        let Push::Message {
            lookup_key,
            subkey,
            slot,
        } = push
        else {
            return Ok(());
        };
        let Some(blocked) = self.readable_block_list() else {
            crate::vtrace!("dm push: the block list will not read, a message push is dropped");
            self.records.health.pushes_dropped += 1;
            return Ok(());
        };
        let taken = core_push::take_message(
            &self.store,
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
                self.answer_recorded(id, answer);
                crate::vtrace!("dm push: {} sequence {seq} recorded", tag(&peer));
                self.emit_bodies(peer, seq, vec![message]).await
            }
            Ok(Taken::Blocked { peer }) => {
                crate::vtrace!("dm push: {} is blocked, its push is dropped", tag(&peer));
                self.records.health.pushes_dropped += 1;
                Ok(())
            }
            Ok(Taken::Duplicate { peer }) => {
                crate::vtrace!("dm push: {} duplicate ignored", tag(&peer));
                Ok(())
            }
            Ok(Taken::Ahead { peer }) => {
                crate::vtrace!(
                    "dm push: {} ahead of sequence, left to the network",
                    tag(&peer)
                );
                Ok(())
            }
            Ok(Taken::Dropped) => {
                crate::vtrace!(
                    "dm push: a message push names no conversation or does not open, dropped"
                );
                self.records.health.pushes_dropped += 1;
                Ok(())
            }
            Err(e) => {
                crate::vtrace!("dm push: a message push failed, {:?}", refusal_for(&e));
                note_failure(&mut self.records.health, &e);
                self.records.health.pushes_dropped += 1;
                Ok(())
            }
        }
    }

    async fn take_pushed_acceptance(&mut self, id: u64, push: &Push) -> Result<(), Halt> {
        let Some(blocked) = self.readable_block_list() else {
            self.records.health.pushes_dropped += 1;
            return Ok(());
        };
        let me = Me {
            signer: &self.signer,
            channel_root: &self.channel_root,
        };
        let recognised = core_push::recognise_acceptance(
            &self.store,
            &mut self.records,
            &me,
            &self.advert_keys,
            |identity| blocked.is_blocked(identity),
            push,
        );
        match recognised {
            Ok(Some((acceptance, answer))) => {
                self.answer_recorded(id, answer);
                crate::vtrace!("dm push: {} acceptance recognised", tag(&acceptance.peer));
                self.surface(vec![Surfaced::Accepted(acceptance)], true)
                    .await
            }
            Ok(None) => {
                crate::vtrace!("dm push: an acceptance push did not verify, dropped");
                self.records.health.pushes_dropped += 1;
                Ok(())
            }
            Err(e) => {
                crate::vtrace!("dm push: an acceptance push failed, {:?}", refusal_for(&e));
                note_failure(&mut self.records.health, &e);
                self.records.health.pushes_dropped += 1;
                Ok(())
            }
        }
    }
}
