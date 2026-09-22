//! The direct-messaging view model a front end draws from.
//!
//! Serves FC1 and FC4.
//!
//! [`DmState`] folds the [`RunnerEvent`]s a [`runner`](super::runner) reports
//! into what a direct-message view shows: pending contact requests, the
//! conversations and their threads, and the commands sent and not yet
//! answered. It holds no decisions of its own; the runner owns every one.

use std::collections::{BTreeMap, BTreeSet};

use daemonseed_core::dm::drop::DROP_SUBKEYS;
use daemonseed_core::storage::dm_store::CorrespondenceLabel;

use super::runner::{
    CommandToken, ContactRequestId, ConversationState, HealthCounters, IdentityPk, Refusal,
    RunnerCommand, RunnerEvent,
};

/// A reply to a contact request, being written.
#[derive(Clone, PartialEq, Eq)]
pub struct DmAcceptDraft {
    /// The request the reply accepts.
    pub request: ContactRequestId,
    /// The identity that sent it.
    pub from: IdentityPk,
    /// The reply as edited so far.
    pub reply: String,
}

impl std::fmt::Debug for DmAcceptDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DmAcceptDraft {{ request: {:?}, from: ", self.request)?;
        redacted_pk(f)?;
        write!(f, ", reply_len: {} }}", self.reply.len())
    }
}

/// One conversation, as the runner has reported it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DmCorrespondence {
    /// The label the runner names this conversation by, once one is known.
    pub label: Option<CorrespondenceLabel>,
    /// What the runner's roster last said about this conversation, or `None`
    /// before a roster has named it.
    pub state: Option<ConversationState>,
    /// The correspondent's cursor over this side's messages, from the roster:
    /// every sequence below it has been collected.
    pub peer_collected: u64,
    /// The highest sequence of this side's the correspondent has collected, from
    /// the last delivery report.
    pub delivered_through: Option<u64>,
    /// The conversation's messages, in the order this session heard of them.
    pub thread: Vec<DmThreadRow>,
    /// The refusal that stopped the last send, held until a send goes through.
    pub refusal: Option<Refusal>,
    /// The value [`DmState::activity_seq`] had when an event last named this
    /// conversation: the key the roster is drawn by, newest first.
    ///
    /// A counter rather than a clock, because the order events arrived in
    /// is the only recency this state has.
    pub last_activity: u64,
}

impl std::fmt::Debug for DmCorrespondence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The label is left out: it names the conversation on disk.
        f.debug_struct("DmCorrespondence")
            .field("state", &self.state)
            .field("peer_collected", &self.peer_collected)
            .field("delivered_through", &self.delivered_through)
            .field("thread", &self.thread)
            .field("refusal", &self.refusal)
            .field("last_activity", &self.last_activity)
            .finish_non_exhaustive()
    }
}

impl DmCorrespondence {
    /// Whether the correspondent has collected this side's message `seq`, by
    /// the roster's cursor or by a later delivery report.
    pub fn delivered(&self, seq: u64) -> bool {
        seq < self.peer_collected || self.delivered_through.is_some_and(|through| seq <= through)
    }

    /// Record a thread row, replacing the row held at the same position.
    ///
    /// A sent row without a body never replaces one with a body: the body is
    /// what this session composed, and a later report of the same message does
    /// not carry it.
    fn record(&mut self, row: DmThreadRow) {
        match self.thread.iter_mut().find(|held| held.same_position(&row)) {
            Some(DmThreadRow::Sent { body: Some(_), .. })
                if matches!(row, DmThreadRow::Sent { body: None, .. }) => {}
            Some(held) => *held = row,
            None => self.thread.push(row),
        }
    }
}

/// One row of a conversation's thread.
#[derive(Clone, PartialEq, Eq)]
pub enum DmThreadRow {
    /// A message the correspondent wrote.
    Received {
        /// Its sequence number in the correspondent's direction.
        seq: u64,
        /// The message body.
        body: String,
        /// When this side collected it, in Unix milliseconds.
        received_at_ms: u64,
    },
    /// A message this side wrote, in the store and in its slot.
    Sent {
        /// Its sequence number in this side's direction.
        seq: u64,
        /// The body, or `None` for a message this session did not compose.
        body: Option<String>,
    },
}

impl DmThreadRow {
    /// Whether two rows stand for the same message: the same direction and the
    /// same sequence number.
    fn same_position(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Received { seq: a, .. }, Self::Received { seq: b, .. })
            | (Self::Sent { seq: a, .. }, Self::Sent { seq: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl std::fmt::Debug for DmThreadRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A body is plaintext a person wrote. Length only.
        match self {
            Self::Received {
                seq,
                body,
                received_at_ms,
            } => write!(
                f,
                "Received {{ seq: {seq}, body_len: {}, received_at_ms: {received_at_ms} }}",
                body.len()
            ),
            Self::Sent { seq, body } => write!(
                f,
                "Sent {{ seq: {seq}, body_len: {:?} }}",
                body.as_ref().map(String::len)
            ),
        }
    }
}

/// The most contact requests the pane holds: one per drop slot, which is the
/// most the runner holds at once. The oldest row is dropped to make room.
pub const DM_REQUEST_CAP: usize = DROP_SUBKEYS as usize;

/// The most collected messages held for labels no event has named yet. The
/// oldest is dropped to make room.
const DM_UNMAPPED_CAP: usize = 256;

/// The direct-messaging state one session has accumulated from runner events.
///
/// A record of what was said, not a model of the conversation: the runner owns
/// every decision, and this holds what the pane draws. Nothing here is
/// persisted, and a restart re-derives it from a fresh runner's events.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DmState {
    /// Whether a runner is reporting: false until one starts on a node, and
    /// again after it stops.
    pub running: bool,
    /// Contact requests awaiting an answer, one row per identity, oldest first.
    pub requests: Vec<DmContactRequest>,
    /// Conversations, keyed by the correspondent's identity public key.
    pub correspondences: BTreeMap<IdentityPk, DmCorrespondence>,
    /// The identity each label the runner has named belongs to.
    pub labels: BTreeMap<CorrespondenceLabel, IdentityPk>,
    /// Commands sent and not yet answered, by the token each carries.
    pub outstanding: BTreeMap<CommandToken, DmOutstanding>,
    /// Identities the runner has blocked.
    pub blocked: BTreeSet<IdentityPk>,
    /// Whether the runner could not read its block list since it last reported
    /// one. While true, who is blocked is unknown, no request arrives and no
    /// conversation is collected, and `blocked` holds only the last list read.
    pub block_list_unknown: bool,
    /// Identities this session has asked the runner to block that nothing has
    /// yet confirmed or refused. Their requests are held back meanwhile.
    pub blocking: BTreeSet<IdentityPk>,
    /// Identities whose requests this session has hidden.
    pub declined: BTreeSet<IdentityPk>,
    /// The last refusal of any command.
    pub last_refusal: Option<Refusal>,
    /// The runner's last health report.
    pub health: Option<HealthCounters>,
    /// A monotonic count of the events that named a conversation, stamped onto
    /// [`DmCorrespondence::last_activity`].
    pub activity_seq: u64,
    /// Collected messages whose label no event has named yet, held until one
    /// does. An accepted request's messages arrive before the answer that names
    /// their conversation.
    unmapped: Vec<(CorrespondenceLabel, DmThreadRow)>,
    /// First contacts the runner refused before any roster named their
    /// conversation: the body and the reason, by the correspondent's identity.
    /// A refusal part way leaves a pending conversation that the next roster
    /// names, and the pair goes onto it then. A roster that does not name the
    /// identity means no conversation was left, and the pair is dropped.
    refused_first_contacts: BTreeMap<IdentityPk, (String, Refusal)>,
    /// The last command token handed out.
    last_token: u64,
}

/// A command sent to the runner and not yet answered.
#[derive(Clone, PartialEq, Eq)]
pub enum DmOutstanding {
    /// The opening message to an identity with no conversation here.
    FirstContact {
        /// The correspondent.
        peer: IdentityPk,
        /// The body.
        body: String,
    },
    /// A message on an established conversation.
    Send {
        /// The correspondent.
        peer: IdentityPk,
        /// The body.
        body: String,
    },
    /// An acceptance of a contact request.
    Accept {
        /// The request.
        request: ContactRequestId,
        /// The identity that sent it.
        from: IdentityPk,
        /// The reply.
        reply: String,
    },
}

impl std::fmt::Debug for DmOutstanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstContact { body, .. } => {
                f.write_str("FirstContact { peer: ")?;
                redacted_pk(f)?;
                write!(f, ", body_len: {} }}", body.len())
            }
            Self::Send { body, .. } => {
                f.write_str("Send { peer: ")?;
                redacted_pk(f)?;
                write!(f, ", body_len: {} }}", body.len())
            }
            Self::Accept { request, reply, .. } => {
                write!(f, "Accept {{ request: {request:?}, from: ")?;
                redacted_pk(f)?;
                write!(f, ", reply_len: {} }}", reply.len())
            }
        }
    }
}

/// A correspondent's identity key, as a trace line may show it: the marker only.
/// The key itself is 2592 bytes and names a person.
fn redacted_pk(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("IdentityPk(..)")
}

/// A correspondent's identity key as the direct-message pane names it: the
/// first four bytes, hex.
///
/// Four bytes tell apart the handful of rows a roster holds and leave room on
/// an 80-column row. It is a label for a list, not a verification string.
pub fn dm_fingerprint(pk: &IdentityPk) -> String {
    pk.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

impl std::fmt::Debug for DmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because the derive would print every identity key in full.
        f.debug_struct("DmState")
            .field("running", &self.running)
            .field("requests", &self.requests)
            .field("correspondences", &self.correspondences.len())
            .field(
                "outstanding",
                &self.outstanding.values().collect::<Vec<_>>(),
            )
            .field("blocked", &self.blocked.len())
            .field("declined", &self.declined.len())
            .field("last_refusal", &self.last_refusal)
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

/// A contact request as the pane draws it.
#[derive(Clone, PartialEq, Eq)]
pub struct DmContactRequest {
    /// The id the runner holds the request under.
    pub request: ContactRequestId,
    /// The identity that signed its channel opening.
    pub from: IdentityPk,
    /// Whether the sender has an established conversation here and started
    /// over. Such a request cannot be accepted while that conversation remains.
    pub started_over: bool,
    /// When this session first held a request from this identity, in Unix
    /// milliseconds.
    pub held_at_ms: i64,
}

impl std::fmt::Debug for DmContactRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DmContactRequest {{ request: {:?}, from: ", self.request)?;
        redacted_pk(f)?;
        write!(
            f,
            ", started_over: {}, held_at_ms: {} }}",
            self.started_over, self.held_at_ms
        )
    }
}

/// Why [`DmState::first_contact`] issued no command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstContactBlocked {
    /// A conversation with the identity is already held, in any state. The
    /// runner resumes a held first contact without sealing a new body, so a
    /// second one would show a message the correspondent never receives.
    ExistingConversation,
    /// The identity has a contact request waiting here. Accepting it opens the
    /// conversation.
    PendingRequest(ContactRequestId),
    /// A first contact to the identity has been sent and not yet answered.
    InFlight,
}

/// What folding one runner event leaves the caller to act on.
pub struct DmFold {
    /// Whether the oldest pending request was dropped to make room, which moves
    /// every row below it up by one. `DmState` does not hold the cursor.
    pub evicted_oldest: bool,
    /// The reply of an acceptance the runner refused, with the reason.
    pub refused_accept: Option<(DmAcceptDraft, Refusal)>,
}

impl DmState {
    /// Advance [`Self::activity_seq`] and return its new value.
    fn next_activity(&mut self) -> u64 {
        self.activity_seq = self.activity_seq.saturating_add(1);
        self.activity_seq
    }

    /// A token no command of this session has carried.
    pub fn next_token(&mut self) -> CommandToken {
        self.last_token = self.last_token.wrapping_add(1);
        CommandToken(self.last_token)
    }

    /// Open a conversation with `peer`, carrying `body` as its first message.
    ///
    /// Records the command as outstanding under a fresh token and returns it for
    /// the caller to hand to the runner. The conversation appears when the
    /// runner reports the message sent.
    ///
    /// # Errors
    ///
    /// [`FirstContactBlocked`] names why no command was issued: a conversation
    /// with `peer` is already held, a request from `peer` is waiting, or a first
    /// contact to `peer` is already on its way. Nothing is recorded.
    pub fn first_contact(
        &mut self,
        peer: IdentityPk,
        body: String,
    ) -> Result<RunnerCommand, FirstContactBlocked> {
        if self.correspondences.contains_key(&peer) {
            return Err(FirstContactBlocked::ExistingConversation);
        }
        if let Some(request) = self.requests.iter().find(|request| request.from == peer) {
            return Err(FirstContactBlocked::PendingRequest(request.request));
        }
        if self.outstanding.values().any(
            |outstanding| matches!(outstanding, DmOutstanding::FirstContact { peer: to, .. } if *to == peer),
        ) {
            return Err(FirstContactBlocked::InFlight);
        }
        let token = self.next_token();
        let command = RunnerCommand::FirstContact {
            token,
            peer_identity_pk: peer.clone(),
            body: body.as_bytes().to_vec(),
        };
        self.outstanding
            .insert(token, DmOutstanding::FirstContact { peer, body });
        Ok(command)
    }

    /// Conversations newest first, by [`DmCorrespondence::last_activity`].
    ///
    /// Ties break on the identity key, which is total and stable, so the order
    /// is a function of the state alone.
    pub fn correspondences_newest_first(&self) -> Vec<(&IdentityPk, &DmCorrespondence)> {
        let mut rows: Vec<(&IdentityPk, &DmCorrespondence)> = self.correspondences.iter().collect();
        rows.sort_by(|(a_pk, a), (b_pk, b)| {
            b.last_activity.cmp(&a.last_activity).then(a_pk.cmp(b_pk))
        });
        rows
    }

    /// The bodies sent to `peer` that the runner has not answered, oldest first.
    pub fn composed_to(&self, peer: &IdentityPk) -> Vec<&str> {
        self.outstanding
            .values()
            .filter_map(|outstanding| match outstanding {
                DmOutstanding::FirstContact { peer: to, body }
                | DmOutstanding::Send { peer: to, body }
                    if to == peer =>
                {
                    Some(body.as_str())
                }
                _ => None,
            })
            .collect()
    }

    /// Whether an acceptance of `request` has been sent and not answered.
    pub fn accepting(&self, request: &ContactRequestId) -> bool {
        self.outstanding.values().any(|outstanding| {
            matches!(outstanding, DmOutstanding::Accept { request: r, .. } if r == request)
        })
    }

    /// Record that `label` names `peer`'s conversation, and move every message
    /// held for the label into its thread.
    fn map_label(&mut self, label: CorrespondenceLabel, peer: &IdentityPk) {
        self.labels.insert(label, peer.clone());
        let held = std::mem::take(&mut self.unmapped);
        let (mine, rest): (Vec<_>, Vec<_>) = held.into_iter().partition(|(l, _)| *l == label);
        self.unmapped = rest;
        let activity = if mine.is_empty() {
            None
        } else {
            Some(self.next_activity())
        };
        let entry = self.correspondences.entry(peer.clone()).or_default();
        entry.label = Some(label);
        if let Some(activity) = activity {
            entry.last_activity = activity;
        }
        for (_, row) in mine {
            entry.record(row);
        }
    }

    /// Hold a request, one row per identity. Returns whether the oldest row was
    /// dropped to make room.
    fn hold_request(
        &mut self,
        request: ContactRequestId,
        from: &IdentityPk,
        started_over: bool,
        now_ms: i64,
    ) -> bool {
        if self.declined.contains(from)
            || self.blocked.contains(from)
            || self.blocking.contains(from)
        {
            return false;
        }
        if let Some(row) = self.requests.iter_mut().find(|row| row.from == *from) {
            row.request = request;
            row.started_over = started_over;
            return false;
        }
        let evicted = self.requests.len() >= DM_REQUEST_CAP;
        if evicted {
            self.requests.remove(0);
        }
        self.requests.push(DmContactRequest {
            request,
            from: from.clone(),
            started_over,
            held_at_ms: now_ms,
        });
        evicted
    }

    /// The runner stopped: nothing is reporting, the requests it held are gone
    /// with it, and no command sent to it will be answered. Every message sent
    /// and not answered is marked not sent, and their count returned.
    pub fn stop(&mut self) -> usize {
        self.running = false;
        self.requests.clear();
        self.unmapped.clear();
        self.refused_first_contacts.clear();
        self.blocking.clear();
        let mut unsent = 0;
        for outstanding in std::mem::take(&mut self.outstanding).into_values() {
            if let DmOutstanding::FirstContact { peer, .. } | DmOutstanding::Send { peer, .. } =
                outstanding
            {
                unsent += 1;
                if let Some(entry) = self.correspondences.get_mut(&peer) {
                    entry.refusal = Some(Refusal::ShuttingDown);
                }
            }
        }
        unsent
    }

    /// Fold one runner event at `now_ms`, returning what the caller has to act
    /// on.
    pub fn fold(&mut self, event: &RunnerEvent, now_ms: i64) -> DmFold {
        let mut evicted_oldest = false;
        let mut refused_accept = None;
        match event {
            RunnerEvent::Roster(rows) => {
                self.running = true;
                let named: BTreeSet<IdentityPk> = rows
                    .iter()
                    .map(|row| row.peer_identity_pk.clone())
                    .collect();
                self.correspondences.retain(|pk, _| named.contains(pk));
                self.labels.retain(|_, pk| named.contains(pk));
                for row in rows {
                    let known = self.correspondences.get(&row.peer_identity_pk);
                    let new = known.is_none();
                    let changed = known.is_none_or(|entry| entry.state != Some(row.state));
                    let activity = if changed {
                        Some(self.next_activity())
                    } else {
                        None
                    };
                    self.map_label(row.peer, &row.peer_identity_pk);
                    let entry = self
                        .correspondences
                        .entry(row.peer_identity_pk.clone())
                        .or_default();
                    entry.state = Some(row.state);
                    entry.peer_collected = row.peer_collected;
                    if let Some(activity) = activity {
                        entry.last_activity = activity;
                    }
                    // The runner seals a first contact's body as sequence 0
                    // before it creates the conversation, so a conversation a
                    // refused first contact left behind holds that body.
                    if let Some((body, reason)) =
                        self.refused_first_contacts.remove(&row.peer_identity_pk)
                    {
                        entry.refusal = Some(reason);
                        if new {
                            entry.record(DmThreadRow::Sent {
                                seq: 0,
                                body: Some(body),
                            });
                        }
                    }
                }
                self.refused_first_contacts.clear();
                // A plain request from an identity the roster now names has been
                // answered by an acceptance.
                self.requests
                    .retain(|request| request.started_over || !named.contains(&request.from));
            }
            RunnerEvent::ContactRequest { request, from } => {
                evicted_oldest = self.hold_request(*request, from, false, now_ms);
            }
            RunnerEvent::StartedOver { request, from } => {
                evicted_oldest = self.hold_request(*request, from, true, now_ms);
            }
            RunnerEvent::Message {
                from,
                seq,
                body,
                received_at,
            } => {
                let row = DmThreadRow::Received {
                    seq: *seq,
                    body: String::from_utf8_lossy(body).into_owned(),
                    received_at_ms: *received_at,
                };
                match self.labels.get(from).cloned() {
                    Some(peer) => {
                        let activity = self.next_activity();
                        let entry = self.correspondences.entry(peer).or_default();
                        entry.last_activity = activity;
                        entry.record(row);
                    }
                    None => {
                        if self.unmapped.len() >= DM_UNMAPPED_CAP {
                            self.unmapped.remove(0);
                        }
                        self.unmapped.push((*from, row));
                    }
                }
            }
            RunnerEvent::Sent { token, peer, seq } => {
                let (identity, body) = match self.outstanding.remove(token) {
                    // A first contact to an identity whose conversation is
                    // already named resumed it, and the runner sealed no new
                    // body: message 0 is whatever the conversation holds.
                    Some(DmOutstanding::FirstContact {
                        peer: identity,
                        body,
                    }) => {
                        let resumed = self
                            .correspondences
                            .get(&identity)
                            .is_some_and(|entry| entry.label.is_some());
                        (Some(identity), (!resumed).then_some(body))
                    }
                    Some(DmOutstanding::Send {
                        peer: identity,
                        body,
                    }) => (Some(identity), Some(body)),
                    // Only the request accepted is answered: a start-over the
                    // same identity sent meanwhile replaced its id and still
                    // waits for its own answer.
                    Some(DmOutstanding::Accept {
                        request,
                        from,
                        reply,
                    }) => {
                        self.requests.retain(|held| held.request != request);
                        (Some(from), Some(reply))
                    }
                    None => (self.labels.get(peer).cloned(), None),
                };
                if let Some(identity) = identity {
                    self.map_label(*peer, &identity);
                    let activity = self.next_activity();
                    let entry = self.correspondences.entry(identity).or_default();
                    entry.last_activity = activity;
                    if body.is_some() {
                        entry.refusal = None;
                    }
                    entry.record(DmThreadRow::Sent { seq: *seq, body });
                }
            }
            RunnerEvent::Deleted { token, peer } => {
                self.outstanding.remove(token);
                if let Some(identity) = self.labels.remove(peer) {
                    self.correspondences.remove(&identity);
                }
            }
            RunnerEvent::Delivered { peer, through_seq } => {
                if let Some(entry) = self
                    .labels
                    .get(peer)
                    .and_then(|identity| self.correspondences.get_mut(identity))
                {
                    entry.delivered_through = Some(
                        entry
                            .delivered_through
                            .map_or(*through_seq, |through| through.max(*through_seq)),
                    );
                }
            }
            RunnerEvent::Accepted { peer } => {
                if let Some(identity) = self.labels.get(peer).cloned() {
                    let activity = self.next_activity();
                    let entry = self.correspondences.entry(identity).or_default();
                    entry.state = Some(ConversationState::Established);
                    entry.last_activity = activity;
                }
            }
            RunnerEvent::Refused { token, reason } => {
                self.last_refusal = Some(*reason);
                match token.and_then(|token| self.outstanding.remove(&token)) {
                    Some(DmOutstanding::FirstContact { peer, body }) => {
                        match self.correspondences.get_mut(&peer) {
                            Some(entry) => entry.refusal = Some(*reason),
                            None => {
                                self.refused_first_contacts.insert(peer, (body, *reason));
                            }
                        }
                    }
                    Some(DmOutstanding::Send { peer, .. }) => {
                        if let Some(entry) = self.correspondences.get_mut(&peer) {
                            entry.refusal = Some(*reason);
                        }
                    }
                    // A refused acceptance leaves its request listed, and its
                    // reply goes back to the caller so it can be sent again.
                    Some(DmOutstanding::Accept {
                        request,
                        from,
                        reply,
                    }) => {
                        refused_accept = Some((
                            DmAcceptDraft {
                                request,
                                from,
                                reply,
                            },
                            *reason,
                        ));
                    }
                    // A refusal without a token answers a block, which did not
                    // take effect.
                    None if token.is_none() => self.blocking.clear(),
                    None => {}
                }
            }
            RunnerEvent::BlockListUnreadable => self.block_list_unknown = true,
            RunnerEvent::BlockList(identities) => {
                self.block_list_unknown = false;
                self.blocked = identities.iter().cloned().collect();
                // A block the store accepted is now listed, so it is no longer
                // pending; one still unlisted stays pending until refused.
                self.blocking.retain(|pk| !self.blocked.contains(pk));
                self.requests
                    .retain(|request| !self.blocked.contains(&request.from));
            }
            RunnerEvent::Health(counters) => {
                self.running = true;
                self.health = Some(*counters);
            }
        }
        DmFold {
            evicted_oldest,
            refused_accept,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::runner::ConversationSummary;
    use daemonseed_core::identity::keys::IDENTITY_PK_LEN;

    /// An identity key made of one repeated byte.
    fn pk(tag: u8) -> IdentityPk {
        Box::new([tag; IDENTITY_PK_LEN])
    }

    /// A fresh label, as the runner names a conversation.
    fn label() -> CorrespondenceLabel {
        CorrespondenceLabel::mint().expect("a label mints")
    }

    /// A roster naming one conversation.
    fn roster(peer: CorrespondenceLabel, pk: &IdentityPk) -> RunnerEvent {
        RunnerEvent::Roster(vec![ConversationSummary {
            peer,
            peer_identity_pk: pk.clone(),
            state: ConversationState::Pending,
            peer_collected: 0,
            uncollected: 1,
        }])
    }

    /// The token a first contact carries.
    fn token_of(command: &Result<RunnerCommand, FirstContactBlocked>) -> CommandToken {
        match command {
            Ok(RunnerCommand::FirstContact { token, .. }) => *token,
            other => panic!("expected a first contact, got {other:?}"),
        }
    }

    #[test]
    fn first_contact_issues_one_command_with_the_key_and_body() {
        let mut dm = DmState::default();
        let command = dm
            .first_contact(pk(7), "hello".to_owned())
            .expect("a stranger takes a first contact");
        let RunnerCommand::FirstContact {
            token,
            peer_identity_pk,
            body,
        } = command
        else {
            panic!("expected a first contact, got {command:?}");
        };
        assert_eq!(peer_identity_pk, pk(7));
        assert_eq!(body, b"hello".to_vec());
        assert_eq!(dm.outstanding.len(), 1);
        assert_eq!(
            dm.outstanding.get(&token),
            Some(&DmOutstanding::FirstContact {
                peer: pk(7),
                body: "hello".to_owned(),
            })
        );
    }

    #[test]
    fn sent_first_contact_binds_the_label_and_records_one_sent_row() {
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        let peer = label();
        dm.fold(
            &RunnerEvent::Sent {
                token,
                peer,
                seq: 0,
            },
            0,
        );
        assert!(dm.outstanding.is_empty());
        assert_eq!(dm.labels.get(&peer), Some(&pk(7)));
        assert_eq!(dm.correspondences.len(), 1);
        let entry = &dm.correspondences[&pk(7)];
        assert_eq!(entry.label, Some(peer));
        assert_eq!(
            entry.thread,
            vec![DmThreadRow::Sent {
                seq: 0,
                body: Some("hello".to_owned()),
            }]
        );
        assert!(entry.last_activity > 0);
    }

    #[test]
    fn roster_after_a_sent_first_contact_does_not_duplicate_it() {
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        let peer = label();
        dm.fold(
            &RunnerEvent::Sent {
                token,
                peer,
                seq: 0,
            },
            0,
        );
        dm.fold(&roster(peer, &pk(7)), 0);
        assert_eq!(dm.correspondences.len(), 1);
        assert_eq!(dm.labels.len(), 1);
        let entry = &dm.correspondences[&pk(7)];
        assert_eq!(entry.state, Some(ConversationState::Pending));
        assert_eq!(
            entry.thread,
            vec![DmThreadRow::Sent {
                seq: 0,
                body: Some("hello".to_owned()),
            }]
        );
    }

    #[test]
    fn refused_first_contact_drops_the_outstanding_entry_and_records_the_refusal() {
        // A stranger: nothing to attach the refusal to but the last refusal.
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        dm.fold(
            &RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::NoAdvert,
            },
            0,
        );
        assert!(dm.outstanding.is_empty());
        assert_eq!(dm.last_refusal, Some(Refusal::NoAdvert));
        assert!(dm.correspondences.is_empty());

        // A roster naming the conversation before the refusal: the refusal lands
        // on it, where a refused send's does.
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        dm.fold(&roster(label(), &pk(7)), 0);
        dm.fold(
            &RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::AlreadyEstablished,
            },
            0,
        );
        assert!(dm.outstanding.is_empty());
        assert_eq!(
            dm.correspondences[&pk(7)].refusal,
            Some(Refusal::AlreadyEstablished)
        );
    }

    #[test]
    fn newest_first_puts_the_latest_activity_first() {
        let mut dm = DmState::default();
        let older = label();
        dm.fold(&roster(older, &pk(1)), 0);
        let token = token_of(&dm.first_contact(pk(2), "hello".to_owned()));
        let newer = label();
        dm.fold(
            &RunnerEvent::Sent {
                token,
                peer: newer,
                seq: 0,
            },
            0,
        );
        let order: Vec<&IdentityPk> = dm
            .correspondences_newest_first()
            .into_iter()
            .map(|(pk, _)| pk)
            .collect();
        assert_eq!(order, vec![&pk(2), &pk(1)]);

        dm.fold(
            &RunnerEvent::Message {
                from: older,
                seq: 0,
                body: b"back".to_vec(),
                received_at: 5,
            },
            0,
        );
        let order: Vec<&IdentityPk> = dm
            .correspondences_newest_first()
            .into_iter()
            .map(|(pk, _)| pk)
            .collect();
        assert_eq!(order, vec![&pk(1), &pk(2)]);
    }

    #[test]
    fn first_contact_to_a_held_conversation_is_blocked() {
        let mut dm = DmState::default();
        dm.fold(&roster(label(), &pk(7)), 0);
        assert_eq!(
            dm.first_contact(pk(7), "hello".to_owned()).err(),
            Some(FirstContactBlocked::ExistingConversation)
        );
        assert!(dm.outstanding.is_empty());
    }

    #[test]
    fn first_contact_to_a_requester_is_blocked_and_the_request_kept() {
        let mut dm = DmState::default();
        let request = ContactRequestId::for_test(1, 1);
        dm.fold(
            &RunnerEvent::ContactRequest {
                request,
                from: pk(7),
            },
            0,
        );
        assert_eq!(
            dm.first_contact(pk(7), "hello".to_owned()).err(),
            Some(FirstContactBlocked::PendingRequest(request))
        );
        assert!(dm.outstanding.is_empty());
        assert_eq!(dm.requests.len(), 1);
        assert_eq!(dm.requests[0].from, pk(7));
    }

    #[test]
    fn a_second_first_contact_while_one_is_on_its_way_is_blocked() {
        let mut dm = DmState::default();
        token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        assert_eq!(
            dm.first_contact(pk(7), "again".to_owned()).err(),
            Some(FirstContactBlocked::InFlight)
        );
        assert_eq!(dm.outstanding.len(), 1);
    }

    #[test]
    fn a_refusal_before_the_roster_reaches_the_conversation_with_its_body() {
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        dm.fold(
            &RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::Network,
            },
            0,
        );
        dm.fold(&roster(label(), &pk(7)), 0);
        let entry = &dm.correspondences[&pk(7)];
        assert_eq!(entry.refusal, Some(Refusal::Network));
        assert_eq!(
            entry.thread,
            vec![DmThreadRow::Sent {
                seq: 0,
                body: Some("hello".to_owned()),
            }]
        );

        // A roster that does not name the identity left no conversation, and
        // the held refusal goes with it.
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        dm.fold(
            &RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::NoAdvert,
            },
            0,
        );
        dm.fold(&RunnerEvent::Roster(Vec::new()), 0);
        dm.fold(&roster(label(), &pk(7)), 0);
        let entry = &dm.correspondences[&pk(7)];
        assert_eq!(entry.refusal, None);
        assert!(entry.thread.is_empty());
    }

    #[test]
    fn a_tokenless_report_of_message_zero_keeps_its_body() {
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        let peer = label();
        dm.fold(
            &RunnerEvent::Sent {
                token,
                peer,
                seq: 0,
            },
            0,
        );
        dm.fold(&roster(peer, &pk(7)), 0);
        dm.fold(
            &RunnerEvent::Sent {
                token: CommandToken(u64::MAX),
                peer,
                seq: 0,
            },
            0,
        );
        assert_eq!(
            dm.correspondences[&pk(7)].thread,
            vec![DmThreadRow::Sent {
                seq: 0,
                body: Some("hello".to_owned()),
            }]
        );
    }

    #[test]
    fn a_first_contact_answered_on_a_named_conversation_records_no_body() {
        let mut dm = DmState::default();
        let token = token_of(&dm.first_contact(pk(7), "new".to_owned()));
        let peer = label();
        dm.fold(&roster(peer, &pk(7)), 0);
        dm.fold(
            &RunnerEvent::Sent {
                token,
                peer,
                seq: 0,
            },
            0,
        );
        assert_eq!(
            dm.correspondences[&pk(7)].thread,
            vec![DmThreadRow::Sent { seq: 0, body: None }]
        );
    }

    #[test]
    fn an_unanswered_first_contact_is_composed_and_counted_unsent_at_stop() {
        let mut dm = DmState::default();
        token_of(&dm.first_contact(pk(7), "hello".to_owned()));
        assert_eq!(dm.composed_to(&pk(7)), vec!["hello"]);
        assert_eq!(dm.stop(), 1);
        assert!(dm.outstanding.is_empty());
    }

    #[test]
    fn first_contacts_to_two_peers_carry_distinct_tokens() {
        let mut dm = DmState::default();
        let a = token_of(&dm.first_contact(pk(1), "a".to_owned()));
        let b = token_of(&dm.first_contact(pk(2), "b".to_owned()));
        assert_ne!(a, b);
        assert_eq!(dm.outstanding.len(), 2);
    }

    #[test]
    fn equal_activity_breaks_the_tie_on_the_identity_key() {
        let mut dm = DmState::default();
        for tag in [2, 1, 3] {
            dm.correspondences.insert(
                pk(tag),
                DmCorrespondence {
                    last_activity: 4,
                    ..DmCorrespondence::default()
                },
            );
        }
        let order: Vec<&IdentityPk> = dm
            .correspondences_newest_first()
            .into_iter()
            .map(|(pk, _)| pk)
            .collect();
        assert_eq!(order, vec![&pk(1), &pk(2), &pk(3)]);
    }
}
