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
use super::unavailable::DmUnavailable;

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
    /// The conversation's messages, in conversation order: each direction's
    /// messages in sequence order, and the two directions interleaved by this
    /// side's clock, a received message by when it was collected and a sent
    /// one by when it was sent, a message heard of later going after one held
    /// at the same millisecond. The correspondent's clock places nothing.
    pub thread: Vec<DmThreadRow>,
    /// The refusal that stopped the last send, held until a send goes through.
    pub refusal: Option<Refusal>,
    /// The value [`DmState::activity_seq`] had when an event last named this
    /// conversation: the key the roster is drawn by, newest first.
    ///
    /// A counter rather than a clock, because the order events arrived in
    /// is the only recency this state has.
    pub last_activity: u64,
    /// The handle the runner's store last recorded for the correspondent, from
    /// the roster: the name to show once no room roster lists them.
    pub handle: Option<String>,
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
            .field("handle", &self.handle.is_some())
            .finish_non_exhaustive()
    }
}

impl DmCorrespondence {
    /// Whether the correspondent has collected this side's message `seq`, by
    /// the roster's cursor or by a later delivery report.
    pub fn delivered(&self, seq: u64) -> bool {
        seq < self.peer_collected || self.delivered_through.is_some_and(|through| seq <= through)
    }

    /// Record a thread row, replacing the row held at the same position, or
    /// placing a new one in conversation order (see [`Self::thread`]).
    ///
    /// A sent row without a body never replaces one with a body: the body is
    /// what this session composed, and a later report of the same message does
    /// not carry it. A row that replaces another keeps the earlier of the two
    /// times it is placed by.
    fn record(&mut self, row: DmThreadRow) {
        let Some(at) = self.thread.iter().position(|held| held.same_position(&row)) else {
            let at = self.conversation_position(&row);
            self.thread.insert(at, row);
            return;
        };
        let row = match (&self.thread[at], row) {
            (
                DmThreadRow::Sent {
                    body: kept_body,
                    sent_at_ms: kept,
                    ..
                },
                DmThreadRow::Sent {
                    seq,
                    body,
                    sent_at_ms,
                },
            ) => DmThreadRow::Sent {
                seq,
                body: body.or_else(|| kept_body.clone()),
                sent_at_ms: sent_at_ms.min(*kept),
            },
            (
                DmThreadRow::Received {
                    received_at_ms: kept,
                    ..
                },
                DmThreadRow::Received {
                    seq,
                    body,
                    sent_at_ms,
                    received_at_ms,
                },
            ) => {
                let received_at_ms = received_at_ms.min(*kept);
                DmThreadRow::Received {
                    seq,
                    body,
                    sent_at_ms: sent_at_ms.min(received_at_ms),
                    received_at_ms,
                }
            }
            (_, row) => row,
        };
        // An earlier time can move the row ahead of the other direction's.
        if row.order_ms() < self.thread[at].order_ms() {
            self.thread.remove(at);
            let to = self.conversation_position(&row);
            self.thread.insert(to, row);
        } else {
            self.thread[at] = row;
        }
    }

    /// Where a row not yet held goes: after every row of its own direction
    /// with a lower sequence and before every one with a higher, and between
    /// those, before the first row of the other direction placed at a later
    /// time (`order_ms`).
    fn conversation_position(&self, row: &DmThreadRow) -> usize {
        let same = |held: &DmThreadRow| held.outgoing() == row.outgoing();
        let lo = self
            .thread
            .iter()
            .rposition(|held| same(held) && held.seq() < row.seq())
            .map_or(0, |at| at + 1);
        let hi = self.thread[lo..]
            .iter()
            .position(|held| same(held) && held.seq() > row.seq())
            .map_or(self.thread.len(), |at| lo + at);
        (lo..hi)
            .find(|&at| self.thread[at].order_ms() > row.order_ms())
            .unwrap_or(hi)
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
        /// When the correspondent sent it, by the correspondent's clock, in
        /// Unix milliseconds — the time a person reads a message's age from.
        /// A clock ahead of this side's is held at [`Self::Received`]'s
        /// `received_at_ms`: a message is never shown as sent after it
        /// arrived. Only its age is read from this time, never its place.
        sent_at_ms: u64,
        /// When this side collected it, by this side's clock, in Unix
        /// milliseconds: the time its place in the thread is set by. For a
        /// message shown in a contact request's preview, when the preview
        /// was read.
        received_at_ms: u64,
    },
    /// A message this side wrote, in the store and in its slot.
    Sent {
        /// Its sequence number in this side's direction.
        seq: u64,
        /// The body, or `None` for a message this session did not compose.
        body: Option<String>,
        /// When this side sent it, by this side's clock, in Unix
        /// milliseconds: the commit time [`RunnerEvent::Sent`] reports, raised
        /// for an acceptance's reply to the latest time a row already in its
        /// thread is placed by, or, for the first message of a first contact
        /// that was refused and left a conversation, the time that
        /// conversation was first listed.
        sent_at_ms: u64,
    },
}

impl DmThreadRow {
    /// Whether this side wrote it.
    fn outgoing(&self) -> bool {
        matches!(self, Self::Sent { .. })
    }

    /// Its sequence number in its own direction.
    fn seq(&self) -> u64 {
        match self {
            Self::Received { seq, .. } | Self::Sent { seq, .. } => *seq,
        }
    }

    /// The time it is placed in the thread by, by this side's clock, in Unix
    /// milliseconds: when this side collected a received message, and when
    /// it sent a sent one. Two messages that crossed in flight go in the
    /// order they reached this side, and a correspondent's clock, right or
    /// wrong, moves no row.
    fn order_ms(&self) -> u64 {
        match self {
            Self::Received { received_at_ms, .. } => *received_at_ms,
            Self::Sent { sent_at_ms, .. } => *sent_at_ms,
        }
    }

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
                sent_at_ms,
                received_at_ms,
            } => write!(
                f,
                "Received {{ seq: {seq}, body_len: {}, sent_at_ms: {sent_at_ms}, \
                 received_at_ms: {received_at_ms} }}",
                body.len()
            ),
            Self::Sent {
                seq,
                body,
                sent_at_ms,
            } => write!(
                f,
                "Sent {{ seq: {seq}, body_len: {:?}, sent_at_ms: {sent_at_ms} }}",
                body.as_ref().map(String::len)
            ),
        }
    }
}

/// A signed Unix-millisecond clock value as a thread row's time, with a time
/// before the epoch held at it.
fn unix_ms(now_ms: i64) -> u64 {
    u64::try_from(now_ms).unwrap_or(0)
}

/// A correspondent's message as a thread row. A sender's clock ahead of this
/// side's is held at the time the message was collected.
fn received(seq: u64, body: &[u8], sent_at: u64, received_at: u64) -> DmThreadRow {
    DmThreadRow::Received {
        seq,
        body: String::from_utf8_lossy(body).into_owned(),
        sent_at_ms: sent_at.min(received_at),
        received_at_ms: received_at,
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
    /// Why direct messaging could not run on the current connection, where it
    /// could not: no runner started, or the last one ended with an error or
    /// panicked. Cleared by a runner's roster, the first event that marks a
    /// runner running. The runner's [`RunnerEvent::Health`] follows it.
    pub unavailable: Option<DmUnavailable>,
    /// Whether the runner's last advert pass found this side's advert not on
    /// the network, so nobody can send it a first contact yet.
    pub advert_unpublished: bool,
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

/// The name a front end gives a correspondent: `live`, the handle a room
/// roster lists for them now, else the handle the runner's store recorded for
/// their conversation, else [`dm_fingerprint`].
pub fn dm_name(
    live: Option<&str>,
    correspondence: Option<&DmCorrespondence>,
    pk: &IdentityPk,
) -> String {
    live.map(str::to_owned)
        .or_else(|| correspondence.and_then(|c| c.handle.clone()))
        .unwrap_or_else(|| dm_fingerprint(pk))
}

impl std::fmt::Debug for DmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because the derive would print every identity key in full.
        f.debug_struct("DmState")
            .field("running", &self.running)
            .field("unavailable", &self.unavailable)
            .field("advert_unpublished", &self.advert_unpublished)
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
    /// The requester's messages, as [`DmThreadRow::Received`] rows, once the
    /// runner has previewed the request; empty before then.
    pub preview: Vec<DmThreadRow>,
}

impl std::fmt::Debug for DmContactRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DmContactRequest {{ request: {:?}, from: ", self.request)?;
        redacted_pk(f)?;
        write!(
            f,
            ", started_over: {}, held_at_ms: {}, preview: {:?} }}",
            self.started_over, self.held_at_ms, self.preview
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
        let accepting = self.outstanding.values().any(
            |outstanding| matches!(outstanding, DmOutstanding::Accept { from: f, .. } if f == from),
        );
        if let Some(row) = self.requests.iter_mut().find(|row| row.from == *from) {
            // The messages an acceptance in flight replies to stay in view.
            if row.request != request && !accepting {
                row.preview.clear();
            }
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
            preview: Vec::new(),
        });
        evicted
    }

    /// The runner stopped: nothing is reporting, the requests it held are gone
    /// with it, and no command sent to it will be answered. Every message sent
    /// and not answered is marked not sent, and their count returned.
    pub fn stop(&mut self) -> usize {
        self.running = false;
        self.advert_unpublished = false;
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

    /// Direct messaging could not run on this connection, for the reason
    /// `why` gives: no runner started, or the last one ended with an error or
    /// panicked. Shown until a runner reports.
    pub fn mark_unavailable(&mut self, why: DmUnavailable) {
        self.unavailable = Some(why);
    }

    /// Fold one runner event at `now_ms`, returning what the caller has to act
    /// on.
    pub fn fold(&mut self, event: &RunnerEvent, now_ms: i64) -> DmFold {
        let mut evicted_oldest = false;
        let mut refused_accept = None;
        match event {
            RunnerEvent::Roster(rows) => {
                self.running = true;
                self.unavailable = None;
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
                    entry.handle.clone_from(&row.handle);
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
                                sent_at_ms: unix_ms(now_ms),
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
            RunnerEvent::RequestPreview {
                request,
                messages,
                read_at,
            } => {
                // A row whose sender's acceptance is in flight keeps the messages
                // that acceptance replies to.
                let accepting: BTreeSet<&IdentityPk> = self
                    .outstanding
                    .values()
                    .filter_map(|outstanding| match outstanding {
                        DmOutstanding::Accept { from, .. } => Some(from),
                        _ => None,
                    })
                    .collect();
                if let Some(row) = self
                    .requests
                    .iter_mut()
                    .find(|row| row.request == *request && !accepting.contains(&row.from))
                {
                    row.preview = (0..)
                        .zip(messages)
                        .map(|(seq, message)| {
                            received(seq, &message.body, message.sent_at_ms, *read_at)
                        })
                        .collect();
                }
            }
            RunnerEvent::Message {
                from,
                seq,
                body,
                sent_at,
                received_at,
            } => {
                let row = received(*seq, body, *sent_at, *received_at);
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
            RunnerEvent::Sent {
                token,
                peer,
                seq,
                sent_at,
            } => {
                let mut previewed = Vec::new();
                let accepts = matches!(
                    self.outstanding.get(token),
                    Some(DmOutstanding::Accept { .. })
                );
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
                    // The request accepted is answered, and so is a plain
                    // request the same identity sent again meanwhile. A
                    // start-over sent meanwhile replaced its id and still waits
                    // for its own answer.
                    Some(DmOutstanding::Accept {
                        request,
                        from,
                        reply,
                    }) => {
                        // The row may carry a later id from the same identity.
                        if let Some(held) = self
                            .requests
                            .iter_mut()
                            .find(|held| held.request == request || held.from == from)
                        {
                            previewed = std::mem::take(&mut held.preview);
                        }
                        self.requests.retain(|held| {
                            held.request != request && (held.started_over || held.from != from)
                        });
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
                    // The requester's messages precede the reply. A row the
                    // accept already reported holds its place.
                    for row in previewed {
                        if !entry.thread.iter().any(|held| held.same_position(&row)) {
                            entry.record(row);
                        }
                    }
                    // Placed by when the runner committed it, the clock its
                    // receipt times are read from, whenever the report arrives.
                    // An acceptance's reply answers every message of the request,
                    // which the runner reports just before it, so it goes after
                    // them however its commit time compares.
                    let mut sent_at_ms = *sent_at;
                    if accepts {
                        let latest = entry.thread.iter().map(DmThreadRow::order_ms).max();
                        sent_at_ms = sent_at_ms.max(latest.unwrap_or(0));
                    }
                    entry.record(DmThreadRow::Sent {
                        seq: *seq,
                        body,
                        sent_at_ms,
                    });
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
            RunnerEvent::Advert { published } => self.advert_unpublished = !published,
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
            handle: None,
        }])
    }

    /// An acceptance of `request` from `from` recorded as sent, the way a front
    /// end records one; its token.
    fn accept(dm: &mut DmState, request: ContactRequestId, from: &IdentityPk) -> CommandToken {
        let token = dm.next_token();
        dm.outstanding.insert(
            token,
            DmOutstanding::Accept {
                request,
                from: from.clone(),
                reply: "message accepted".to_owned(),
            },
        );
        token
    }

    /// An accepted request's `Sent` answers it and a plain request the same
    /// identity sent again meanwhile, and leaves a start-over sent meanwhile
    /// listed for its own answer.
    #[test]
    fn an_answered_acceptance_leaves_only_a_start_over_listed() {
        for (again, listed) in [
            (
                RunnerEvent::ContactRequest {
                    request: ContactRequestId::for_test(1, 9),
                    from: pk(3),
                },
                false,
            ),
            (
                RunnerEvent::StartedOver {
                    request: ContactRequestId::for_test(1, 9),
                    from: pk(3),
                },
                true,
            ),
        ] {
            let mut dm = DmState::default();
            dm.fold(
                &RunnerEvent::ContactRequest {
                    request: ContactRequestId::for_test(1, 7),
                    from: pk(3),
                },
                0,
            );
            let token = accept(&mut dm, ContactRequestId::for_test(1, 7), &pk(3));
            dm.fold(&again, 0);
            assert_eq!(dm.requests.len(), 1, "control: one row per identity");
            assert_eq!(dm.requests[0].request, ContactRequestId::for_test(1, 9));
            dm.fold(
                &RunnerEvent::Sent {
                    token,
                    peer: label(),
                    seq: 0,
                    sent_at: 0,
                },
                0,
            );
            assert_eq!(
                dm.requests
                    .iter()
                    .map(|r| r.started_over)
                    .collect::<Vec<_>>(),
                if listed { vec![true] } else { vec![] },
                "after {again:?}"
            );
        }
    }

    /// A preview puts the requester's messages on its request. The accept's
    /// answer moves them into the conversation ahead of the reply, and the
    /// same messages reported again by the accept, and one the preview did
    /// not see, each appear once.
    #[test]
    fn previewed_messages_precede_the_reply_once_each() {
        use daemonseed_core::dm::flows::ReceivedMessage;
        for reported in [false, true] {
            let mut dm = DmState::default();
            let request = ContactRequestId::for_test(1, 7);
            dm.fold(
                &RunnerEvent::ContactRequest {
                    request,
                    from: pk(3),
                },
                0,
            );
            dm.fold(
                &RunnerEvent::RequestPreview {
                    request,
                    messages: vec![ReceivedMessage {
                        sent_at_ms: 5,
                        body: b"hi, it's cora".to_vec(),
                    }],
                    read_at: 9,
                },
                0,
            );
            assert_eq!(dm.requests[0].preview.len(), 1, "the preview is held");
            let token = accept(&mut dm, request, &pk(3));
            let peer = label();
            if reported {
                for (seq, body) in [(0, "hi, it's cora"), (1, "and a second")] {
                    dm.fold(
                        &RunnerEvent::Message {
                            from: peer,
                            seq,
                            body: body.as_bytes().to_vec(),
                            sent_at: 5,
                            received_at: 10,
                        },
                        0,
                    );
                }
            }
            dm.fold(
                &RunnerEvent::Sent {
                    token,
                    peer,
                    seq: 0,
                    sent_at: 0,
                },
                0,
            );
            let thread: Vec<String> = dm.correspondences[&pk(3)]
                .thread
                .iter()
                .map(|row| match row {
                    DmThreadRow::Received { seq, body, .. } => format!("<{seq} {body}"),
                    DmThreadRow::Sent { seq, body, .. } => format!(">{seq} {body:?}"),
                })
                .collect();
            let mut expected = vec!["<0 hi, it's cora".to_owned()];
            if reported {
                expected.push("<1 and a second".to_owned());
            }
            expected.push(">0 Some(\"message accepted\")".to_owned());
            assert_eq!(thread, expected, "reported by the accept: {reported}");
        }
    }

    /// A preview of request `serial` holding one message.
    fn preview_of(serial: u64, body: &str) -> RunnerEvent {
        RunnerEvent::RequestPreview {
            request: ContactRequestId::for_test(1, serial),
            messages: vec![daemonseed_core::dm::flows::ReceivedMessage {
                sent_at_ms: 5,
                body: body.as_bytes().to_vec(),
            }],
            read_at: 9,
        }
    }

    /// The bodies of each request's preview, in request order.
    fn previews(dm: &DmState) -> Vec<Vec<String>> {
        dm.requests
            .iter()
            .map(|r| {
                r.preview
                    .iter()
                    .map(|row| match row {
                        DmThreadRow::Received { body, .. } => body.clone(),
                        DmThreadRow::Sent { .. } => "sent".to_owned(),
                    })
                    .collect()
            })
            .collect()
    }

    /// A second hello from the same identity while its acceptance is in flight
    /// leaves the message being replied to in view, and the acceptance's answer
    /// still places it above the reply. With no acceptance in flight the
    /// second hello, under a new id, clears the preview.
    #[test]
    fn a_second_hello_during_an_acceptance_keeps_the_preview() {
        for accepting in [false, true] {
            let mut dm = DmState::default();
            let first = ContactRequestId::for_test(1, 7);
            let second = ContactRequestId::for_test(1, 8);
            dm.fold(
                &RunnerEvent::ContactRequest {
                    request: first,
                    from: pk(3),
                },
                0,
            );
            dm.fold(&preview_of(7, "hi, it's cora"), 0);
            let token = accepting.then(|| accept(&mut dm, first, &pk(3)));
            dm.fold(
                &RunnerEvent::ContactRequest {
                    request: second,
                    from: pk(3),
                },
                0,
            );
            dm.fold(&preview_of(8, "a later hello"), 0);
            let expected = if accepting {
                vec![vec!["hi, it's cora".to_owned()]]
            } else {
                vec![vec!["a later hello".to_owned()]]
            };
            assert_eq!(previews(&dm), expected, "accepting: {accepting}");
            let Some(token) = token else { continue };
            dm.fold(
                &RunnerEvent::Sent {
                    token,
                    peer: label(),
                    seq: 0,
                    sent_at: 0,
                },
                0,
            );
            let thread: Vec<bool> = dm.correspondences[&pk(3)]
                .thread
                .iter()
                .map(|row| matches!(row, DmThreadRow::Received { body, .. } if body == "hi, it's cora"))
                .collect();
            assert_eq!(thread, [true, false], "the message, then the reply");
        }
    }

    /// Two identities' previews each land on their own request row.
    #[test]
    fn previews_of_two_identities_do_not_cross() {
        let mut dm = DmState::default();
        dm.fold(
            &RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(3),
            },
            0,
        );
        dm.fold(
            &RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 2),
                from: pk(4),
            },
            0,
        );
        dm.fold(&preview_of(2, "from four"), 0);
        dm.fold(&preview_of(1, "from three"), 0);
        assert_eq!(dm.requests[0].from, pk(3));
        assert_eq!(
            previews(&dm),
            [vec!["from three".to_owned()], vec!["from four".to_owned()]]
        );
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
                sent_at: 0,
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
                sent_at_ms: 0,
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
                sent_at: 0,
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
                sent_at_ms: 0,
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

    /// A thread is in conversation order by this side's clock: a reply the
    /// correspondent sent before this side's newer message, and collected
    /// after it, is placed below it, because messages that cross in flight
    /// go in the order they arrived; a message collected at the same
    /// millisecond as one already held goes after it; and each direction
    /// keeps its sequence order whatever the clocks say.
    #[test]
    fn a_thread_is_in_conversation_order() {
        let mut dm = DmState::default();
        let peer = label();
        dm.fold(&roster(peer, &pk(7)), 0);
        let received = |seq: u64, sent_at: u64, received_at: u64| RunnerEvent::Message {
            from: peer,
            seq,
            body: format!("r{seq}").into_bytes(),
            sent_at,
            received_at,
        };
        let sent = |seq: u64, sent_at: u64| RunnerEvent::Sent {
            token: CommandToken(1_000 + seq),
            peer,
            seq,
            sent_at,
        };
        dm.fold(&received(0, 10_000, 10_000), 10_000);
        dm.fold(&sent(0, 20_000), 20_000);
        // Sent before the local message, collected after it.
        dm.fold(&received(1, 15_000, 25_000), 25_000);
        // A correspondent's clock behind, collected after a restart with this
        // side's clock stepped back: still after its earlier message.
        dm.fold(&received(2, 5_000, 22_000), 30_000);
        // This side's clock behind: still after this side's earlier message.
        dm.fold(&sent(1, 1_000), 1_000);
        dm.fold(&sent(2, 40_200), 40_200);
        // Collected at the same millisecond as the send before it.
        dm.fold(&received(3, 40_000, 40_200), 41_000);
        let order: Vec<String> = dm.correspondences[&pk(7)]
            .thread
            .iter()
            .map(|row| match row {
                DmThreadRow::Received { seq, .. } => format!("r{seq}"),
                DmThreadRow::Sent { seq, .. } => format!("s{seq}"),
            })
            .collect();
        assert_eq!(order, ["r0", "s0", "s1", "r1", "r2", "s2", "r3"]);
    }

    /// A correspondent whose clock is an hour behind replies to this side's
    /// message: the reply goes after it here, though its stamp reads an hour
    /// earlier, and its age still reads from that stamp. On the
    /// correspondent's side, this side's replies stay in the order they were
    /// sent, each after the message it answers.
    #[test]
    fn a_reply_from_a_clock_an_hour_behind_goes_after_what_it_answers() {
        const HOUR: u64 = 60 * 60 * 1000;
        let t: u64 = 1_700_000_000_000;
        let at = |ms: u64| i64::try_from(ms).expect("a time in range");
        let order = |dm: &DmState, of: &IdentityPk| -> Vec<String> {
            dm.correspondences[of]
                .thread
                .iter()
                .map(|row| match row {
                    DmThreadRow::Received { seq, .. } => format!("r{seq}"),
                    DmThreadRow::Sent { seq, .. } => format!("s{seq}"),
                })
                .collect()
        };
        let message = |from, seq, sent_at, received_at| RunnerEvent::Message {
            from,
            seq,
            body: b"m".to_vec(),
            sent_at,
            received_at,
        };
        let sent = |peer, seq, sent_at| RunnerEvent::Sent {
            token: CommandToken(4_000 + seq),
            peer,
            seq,
            sent_at,
        };

        // This side, clock right.
        let mut mine = DmState::default();
        let theirs_here = label();
        mine.fold(&roster(theirs_here, &pk(2)), 0);
        mine.fold(&message(theirs_here, 0, t - HOUR, t), at(t));
        mine.fold(&sent(theirs_here, 0, t + 60_000), at(t + 60_000));
        mine.fold(
            &message(theirs_here, 1, t + 120_000 - HOUR, t + 120_000),
            at(t + 120_000),
        );
        mine.fold(&sent(theirs_here, 1, t + 180_000), at(t + 180_000));
        assert_eq!(order(&mine, &pk(2)), ["r0", "s0", "r1", "s1"]);
        assert!(matches!(
            mine.correspondences[&pk(2)].thread[2],
            DmThreadRow::Received { sent_at_ms, .. } if sent_at_ms == t + 120_000 - HOUR
        ));

        // The correspondent's side, every reading an hour behind.
        let mut theirs = DmState::default();
        let mine_there = label();
        theirs.fold(&roster(mine_there, &pk(1)), 0);
        theirs.fold(&sent(mine_there, 0, t - HOUR), at(t - HOUR));
        theirs.fold(
            &message(mine_there, 0, t + 60_000, t + 61_000 - HOUR),
            at(t + 61_000 - HOUR),
        );
        theirs.fold(
            &sent(mine_there, 1, t + 120_000 - HOUR),
            at(t + 120_000 - HOUR),
        );
        theirs.fold(
            &message(mine_there, 1, t + 180_000, t + 181_000 - HOUR),
            at(t + 181_000 - HOUR),
        );
        assert_eq!(order(&theirs, &pk(1)), ["s0", "r0", "s1", "r1"]);
    }

    /// A repeat report of a sent row that carries an earlier time moves the row
    /// to where that time places it.
    #[test]
    fn a_sent_row_reported_earlier_again_moves_up() {
        let mut dm = DmState::default();
        let peer = label();
        dm.fold(&roster(peer, &pk(7)), 0);
        let sent = |sent_at| RunnerEvent::Sent {
            token: CommandToken(3_001),
            peer,
            seq: 1,
            sent_at,
        };
        dm.fold(&sent(50_000), 50_000);
        dm.fold(
            &RunnerEvent::Message {
                from: peer,
                seq: 0,
                body: b"r0".to_vec(),
                sent_at: 30_000,
                received_at: 60_000,
            },
            60_000,
        );
        dm.fold(&sent(20_000), 20_000);
        let order: Vec<String> = dm.correspondences[&pk(7)]
            .thread
            .iter()
            .map(|row| match row {
                DmThreadRow::Received { seq, .. } => format!("r{seq}"),
                DmThreadRow::Sent { seq, .. } => format!("s{seq}"),
            })
            .collect();
        assert_eq!(order, ["s1", "r0"]);
    }

    /// A sent row reported with a time earlier than a lower sequence's, as after
    /// this side's clock stepped back, still goes after every lower sequence of
    /// its own direction.
    #[test]
    fn a_sent_row_reported_earlier_keeps_its_sequence_place() {
        let mut dm = DmState::default();
        let peer = label();
        dm.fold(&roster(peer, &pk(7)), 0);
        let sent = |seq: u64, sent_at: u64| RunnerEvent::Sent {
            token: CommandToken(2_000 + seq),
            peer,
            seq,
            sent_at,
        };
        dm.fold(&sent(3, 10_000), 10_000);
        dm.fold(
            &RunnerEvent::Message {
                from: peer,
                seq: 0,
                body: b"r0".to_vec(),
                sent_at: 20_000,
                received_at: 20_000,
            },
            20_000,
        );
        // Reported with a time earlier than sequence 3's.
        dm.fold(&sent(7, 5_000), 5_000);
        let order: Vec<String> = dm.correspondences[&pk(7)]
            .thread
            .iter()
            .map(|row| match row {
                DmThreadRow::Received { seq, .. } => format!("r{seq}"),
                DmThreadRow::Sent { seq, .. } => format!("s{seq}"),
            })
            .collect();
        assert_eq!(order, ["s3", "s7", "r0"]);
    }

    /// A reply collected before the report of the message it answers still goes
    /// below that message: the message is placed by the commit time the report
    /// carries, not by when the report arrived.
    #[test]
    fn a_reply_collected_before_its_question_is_reported_goes_below_it() {
        let mut dm = DmState::default();
        let peer = label();
        dm.fold(&roster(peer, &pk(7)), 0);
        let token = dm.next_token();
        dm.outstanding.insert(
            token,
            DmOutstanding::Send {
                peer: pk(7),
                body: "question".to_owned(),
            },
        );
        dm.fold(
            &RunnerEvent::Message {
                from: peer,
                seq: 0,
                body: b"answer".to_vec(),
                sent_at: 30_200,
                received_at: 30_500,
            },
            30_500,
        );
        dm.fold(
            &RunnerEvent::Sent {
                token,
                peer,
                seq: 0,
                sent_at: 30_000,
            },
            31_000,
        );
        let thread = &dm.correspondences[&pk(7)].thread;
        assert_eq!(
            thread,
            &vec![
                DmThreadRow::Sent {
                    seq: 0,
                    body: Some("question".to_owned()),
                    sent_at_ms: 30_000,
                },
                DmThreadRow::Received {
                    seq: 0,
                    body: "answer".to_owned(),
                    sent_at_ms: 30_200,
                    received_at_ms: 30_500,
                },
            ]
        );
    }

    /// A received message reported again keeps the place and the receipt time
    /// of its first report, and its send time is held at that receipt time.
    #[test]
    fn a_received_message_reported_again_keeps_its_first_receipt() {
        let mut dm = DmState::default();
        let peer = label();
        dm.fold(&roster(peer, &pk(7)), 0);
        let received = |received_at: u64| RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"r0".to_vec(),
            sent_at: 25_000,
            received_at,
        };
        dm.fold(&received(20_000), 20_000);
        dm.fold(
            &RunnerEvent::Sent {
                token: CommandToken(5_000),
                peer,
                seq: 0,
                sent_at: 30_000,
            },
            30_000,
        );
        dm.fold(&received(40_000), 40_000);
        let thread = &dm.correspondences[&pk(7)].thread;
        assert_eq!(thread.len(), 2, "{thread:?}");
        assert_eq!(
            thread[0],
            DmThreadRow::Received {
                seq: 0,
                body: "r0".to_owned(),
                sent_at_ms: 20_000,
                received_at_ms: 20_000,
            }
        );
        assert!(matches!(thread[1], DmThreadRow::Sent { seq: 0, .. }));
    }

    /// A received row keeps the correspondent's send time, and a send time
    /// ahead of the arrival is held at the arrival.
    #[test]
    fn a_received_row_carries_the_senders_time() {
        let mut dm = DmState::default();
        let from = label();
        dm.fold(&roster(from, &pk(1)), 0);
        for (seq, sent_at) in [(0, 1_000), (1, 9_000)] {
            dm.fold(
                &RunnerEvent::Message {
                    from,
                    seq,
                    body: b"hi".to_vec(),
                    sent_at,
                    received_at: 5_000,
                },
                0,
            );
        }
        let times: Vec<(u64, u64)> = dm.correspondences[&pk(1)]
            .thread
            .iter()
            .map(|row| match row {
                DmThreadRow::Received {
                    sent_at_ms,
                    received_at_ms,
                    ..
                } => (*sent_at_ms, *received_at_ms),
                DmThreadRow::Sent { .. } => panic!("no row was sent"),
            })
            .collect();
        assert_eq!(times, vec![(1_000, 5_000), (5_000, 5_000)]);
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
                sent_at: 0,
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
                sent_at: 5,
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
                sent_at_ms: 0,
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
                sent_at: 0,
            },
            0,
        );
        dm.fold(&roster(peer, &pk(7)), 0);
        dm.fold(
            &RunnerEvent::Sent {
                token: CommandToken(u64::MAX),
                peer,
                seq: 0,
                sent_at: 0,
            },
            0,
        );
        assert_eq!(
            dm.correspondences[&pk(7)].thread,
            vec![DmThreadRow::Sent {
                seq: 0,
                body: Some("hello".to_owned()),
                sent_at_ms: 0,
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
                sent_at: 0,
            },
            0,
        );
        assert_eq!(
            dm.correspondences[&pk(7)].thread,
            vec![DmThreadRow::Sent {
                seq: 0,
                body: None,
                sent_at_ms: 0,
            }]
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
