//! Direct messaging as the GUI holds it: the runner's reports, the commands
//! queued for the runner, and the rail's two sections with their selection.
//!
//! Slint-free like the rest of [`super`]. Every action here changes state and
//! queues [`RunnerCommand`]s; nothing waits on the runner. The binary drains the
//! queue with [`GuiState::take_pending_dm`] and forwards each command.
//!
//! **What the rail carries.** A rail row holds a label, an age and an unread
//! flag, plus the keys that identify it. It never holds a message body: a body
//! exists only in the thread of the selected conversation
//! ([`GuiState::dm_thread_view`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use daemonseed_veilid_net::dm::runner::{
    CommandToken, IdentityPk, Refusal, RunnerCommand, RunnerEvent,
};
use daemonseed_veilid_net::dm::view::{
    DmCorrespondence, DmOutstanding, DmState, DmThreadRow, FirstContactBlocked, dm_fingerprint,
    dm_name,
};

use super::{GuiState, now_unix_ms};

/// The reply an acceptance carries. Accepting is one action, so the reply is
/// fixed.
pub const DM_ACCEPT_REPLY: &str = "message accepted";

/// A one-line notice for the Direct messages area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmNotice {
    /// The runner cannot read its block list, so no request arrives and no
    /// conversation is collected until it reads again. Shown while it lasts.
    BlockListUnreadable,
    /// Messaging stopped with `count` messages unanswered, each now shown not
    /// sent.
    NotSent {
        /// How many messages did not go.
        count: usize,
    },
    /// A block did not take effect, for this reason; the request is listed
    /// again.
    BlockRefused(Refusal),
    /// A first message found a conversation already held with that person, so
    /// the draft was dropped and the conversation opened with the text kept.
    MovedToConversation,
    /// A first message found that person's request waiting, so the draft was
    /// dropped and the request opened; accepting it opens the conversation.
    MovedToRequest,
}

/// One of the rail's two sections. At most one is open at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailSection {
    /// The rooms: the Lobby and the circles.
    Chats,
    /// Direct messages: requests, conversations and drafts.
    DirectMessages,
}

/// What the main pane shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainPane {
    /// The active room's chat.
    Chat,
    /// "Choose a chat": the Chats section owns the pane and is collapsed.
    ChatPlaceholder,
    /// "Choose a conversation": the Direct messages section owns the pane and
    /// is collapsed or has nothing selected.
    DmPlaceholder,
    /// The selected direct-message item's thread.
    DmThread,
}

/// The kind of a direct-message rail item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DmItemKind {
    /// A contact request awaiting an answer.
    Request,
    /// A conversation the runner has reported.
    Conversation,
    /// A conversation started here whose first message has not yet been
    /// reported sent.
    Draft,
}

impl DmItemKind {
    /// The letter a [`DmRailRow::slot`] starts with.
    fn letter(self) -> char {
        match self {
            Self::Request => 'r',
            Self::Conversation => 'c',
            Self::Draft => 'd',
        }
    }
}

/// One direct-message rail item: its kind and the identity it concerns.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DmItemKey {
    /// Request, conversation or draft.
    pub kind: DmItemKind,
    /// The correspondent.
    pub peer: IdentityPk,
}

impl std::fmt::Debug for DmItemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is 2592 bytes and names a person; the fingerprint tells rows
        // apart in a failed assertion.
        write!(f, "{:?}({})", self.kind, dm_fingerprint(&self.peer))
    }
}

impl DmItemKey {
    fn new(kind: DmItemKind, peer: &IdentityPk) -> Self {
        Self {
            kind,
            peer: peer.clone(),
        }
    }
}

/// One direct-message rail row. No message body: see the module header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmRailRow {
    /// The item the row stands for.
    pub key: DmItemKey,
    /// A short text key for the row, stable for the session, that
    /// [`GuiState::dm_item_for_slot`] resolves back to [`Self::key`].
    pub slot: String,
    /// The handle a room roster lists for the correspondent, else the one
    /// the runner's store recorded, else its fingerprint.
    pub label: String,
    /// How long ago the item last changed: "now", "2m", "1h", "3d".
    pub age: String,
    /// Whether something arrived in the item that the user has not viewed.
    pub unread: bool,
    /// Whether the item is the selected one.
    pub selected: bool,
    /// A request whose block has been asked for and not yet confirmed.
    pub blocking: bool,
}

/// How far an outgoing message got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmMessageStatus {
    /// Handed to the runner and not yet answered.
    Pending,
    /// In the correspondent's slot.
    Sent,
    /// Collected by the correspondent.
    Delivered,
    /// The runner refused it; [`DmThreadView::refusal`] says why.
    Refused,
}

/// One message of the selected thread.
#[derive(Clone, PartialEq, Eq)]
pub struct DmMessageRow {
    /// Written on this side.
    pub outgoing: bool,
    /// The text.
    pub body: String,
    /// How far an outgoing message got; `None` on a received one.
    pub status: Option<DmMessageStatus>,
    /// The time the row's age is read from, in Unix milliseconds: the
    /// correspondent's send time on a received message, the time it was
    /// composed on one composed here, and `None` on a message this session
    /// did not compose.
    pub at_ms: Option<i64>,
}

impl std::fmt::Debug for DmMessageRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A body is plaintext a person wrote. Length only.
        f.debug_struct("DmMessageRow")
            .field("outgoing", &self.outgoing)
            .field("body_len", &self.body.len())
            .field("status", &self.status)
            .field("at_ms", &self.at_ms)
            .finish()
    }
}

/// The selected direct-message item, as the main pane draws it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmThreadView {
    /// The item shown.
    pub key: DmItemKey,
    /// The roster handle for the correspondent, or its fingerprint.
    pub header_label: String,
    /// The correspondent's fingerprint, always.
    pub fingerprint: String,
    /// A contact request: [`Self::rows`] holds the messages the runner's
    /// preview read from it, then at most this side's refused acceptance
    /// reply, and the actions are accept, decline, block.
    pub is_request: bool,
    /// The messages, oldest first.
    pub rows: Vec<DmMessageRow>,
    /// Whether a message can be sent here now.
    pub can_send: bool,
    /// The refusal of the last send here, or of the acceptance or block of a
    /// request.
    pub refusal: Option<Refusal>,
    /// A request whose block has been asked for and not yet confirmed: it
    /// takes no further answer.
    pub blocking: bool,
    /// The correspondent is blocked, which is why nothing can be sent.
    pub blocked: bool,
}

/// A message this session composed, from the moment it was queued.
#[derive(Clone)]
struct Composed {
    /// The token its command carried.
    token: CommandToken,
    /// The text.
    body: String,
    /// Whether it opened the conversation.
    first_contact: bool,
    /// Whether it is the reply of an acceptance. Until it is delivered it is
    /// drawn after the correspondent's messages (see
    /// [`GuiDm::settle_accept_replies`]).
    accept: bool,
    /// An acceptance reply sent when no conversation with that person was
    /// held, so a conversation the runner lists afterwards is the one it
    /// opened.
    opens_conversation: bool,
    /// How many thread rows not composed here the conversation held when it
    /// was composed: it is drawn after them.
    after: usize,
    /// Its sequence number, once the runner reports it held.
    seq: Option<u64>,
    /// Why it did not go.
    refusal: Option<Refusal>,
    /// When it was composed, by this side's clock (Unix ms).
    composed_at_ms: i64,
}

impl Composed {
    /// Still waiting on the runner's answer.
    fn pending(&self) -> bool {
        self.seq.is_none() && self.refusal.is_none()
    }
}

/// The direct-messaging half of [`GuiState`].
pub(super) struct GuiDm {
    /// What the runner has reported.
    state: DmState,
    /// Commands queued for the runner, oldest first.
    pending: Vec<RunnerCommand>,
    /// Whether the Chats section is unfolded.
    chats_open: bool,
    /// Whether the Direct messages section is unfolded.
    dms_open: bool,
    /// The section whose content the main pane shows.
    owner: RailSection,
    /// The selected direct-message item.
    selected: Option<DmItemKey>,
    /// Drafts, by correspondent, with the time each was started (Unix ms).
    drafts: BTreeMap<IdentityPk, i64>,
    /// Requests with something the user has not viewed.
    unread_requests: BTreeSet<IdentityPk>,
    /// Conversations with a message the user has not viewed.
    unread_conversations: BTreeSet<IdentityPk>,
    /// When each conversation last changed (Unix ms): the correspondent's
    /// send time of a message received, or this side's clock for any other
    /// change. The view model orders by a counter.
    active_at: BTreeMap<IdentityPk, i64>,
    /// Every message composed to each correspondent, in the order composed.
    composed: BTreeMap<IdentityPk, Vec<Composed>>,
    /// The reason the last acceptance of each requester's request was refused.
    accept_refused: BTreeMap<IdentityPk, Refusal>,
    /// The reason the last block of each requester was refused.
    block_refused: BTreeMap<IdentityPk, Refusal>,
    /// Blocks sent and not yet answered, oldest first. The runner answers them
    /// in order: a block list naming one confirms it, and a refusal without a
    /// token refuses the oldest.
    blocks_in_flight: VecDeque<IdentityPk>,
    /// The last notice an event or action left, until the next action.
    notice: Option<DmNotice>,
    /// A session-local number per identity, for [`DmRailRow::slot`].
    ids: BTreeMap<IdentityPk, u64>,
    /// The handle last sent to the runner for each correspondent, so a roster
    /// that names them again with the same handle sends nothing.
    noted_handles: BTreeMap<IdentityPk, String>,
}

impl Default for GuiDm {
    /// The Chats section open and showing the active room, as the GUI starts.
    fn default() -> Self {
        Self {
            state: DmState::default(),
            pending: Vec::new(),
            chats_open: true,
            dms_open: false,
            owner: RailSection::Chats,
            selected: None,
            drafts: BTreeMap::new(),
            unread_requests: BTreeSet::new(),
            unread_conversations: BTreeSet::new(),
            active_at: BTreeMap::new(),
            composed: BTreeMap::new(),
            accept_refused: BTreeMap::new(),
            block_refused: BTreeMap::new(),
            blocks_in_flight: VecDeque::new(),
            notice: None,
            ids: BTreeMap::new(),
            noted_handles: BTreeMap::new(),
        }
    }
}

impl GuiDm {
    /// A room was chosen: the Chats section is open and owns the main pane.
    pub(super) fn show_chats(&mut self) {
        self.chats_open = true;
        self.owner = RailSection::Chats;
    }

    /// Whether `section` is unfolded.
    fn is_open(&self, section: RailSection) -> bool {
        match section {
            RailSection::Chats => self.chats_open,
            RailSection::DirectMessages => self.dms_open,
        }
    }

    /// Whether `key` names an item the rail holds.
    fn exists(&self, key: &DmItemKey) -> bool {
        match key.kind {
            DmItemKind::Request => self.state.requests.iter().any(|r| r.from == key.peer),
            DmItemKind::Conversation => self.state.correspondences.contains_key(&key.peer),
            DmItemKind::Draft => self.drafts.contains_key(&key.peer),
        }
    }

    /// Whether the main pane shows a direct-message thread: the section owns
    /// the pane, is open, and has an item selected.
    fn thread_on_screen(&self) -> bool {
        self.owner == RailSection::DirectMessages && self.dms_open && self.selected.is_some()
    }

    /// Whether the user is looking at `key`: its thread is in the main pane.
    fn viewing(&self, key: &DmItemKey) -> bool {
        self.thread_on_screen() && self.selected.as_ref() == Some(key)
    }

    /// Clear the unread flag of the item whose thread is in the main pane.
    fn mark_viewed(&mut self) {
        if !self.thread_on_screen() {
            return;
        }
        let Some(key) = &self.selected else {
            return;
        };
        match key.kind {
            DmItemKind::Request => {
                self.unread_requests.remove(&key.peer);
            }
            DmItemKind::Conversation => {
                self.unread_conversations.remove(&key.peer);
            }
            DmItemKind::Draft => {}
        }
    }

    /// Select `key`, which unfolds Direct messages and shows its thread. Chats
    /// is left as it is.
    fn select(&mut self, key: DmItemKey) {
        self.selected = Some(key);
        self.dms_open = true;
        self.owner = RailSection::DirectMessages;
        self.mark_viewed();
    }

    /// The thread rows of `peer`'s conversation that no message composed here
    /// stands for.
    fn foreign_rows(&self, peer: &IdentityPk) -> usize {
        let Some(c) = self.state.correspondences.get(peer) else {
            return 0;
        };
        let mine: BTreeSet<u64> = self
            .composed
            .get(peer)
            .into_iter()
            .flatten()
            .filter_map(|m| m.seq)
            .collect();
        c.thread
            .iter()
            .filter(|row| !matches!(row, DmThreadRow::Sent { seq, .. } if mine.contains(seq)))
            .count()
    }

    /// The composed message that `token` answers.
    fn composed_mut(&mut self, token: CommandToken) -> Option<&mut Composed> {
        self.composed
            .values_mut()
            .flatten()
            .find(|m| m.token == token)
    }

    /// Record a composed message, queued under `token`.
    ///
    /// A first contact can open the conversation itself, so an acceptance reply
    /// to that person no longer [`Composed::opens_conversation`].
    fn compose(&mut self, peer: &IdentityPk, token: CommandToken, body: &str, first_contact: bool) {
        let after = self.foreign_rows(peer);
        let messages = self.composed.entry(peer.clone()).or_default();
        if first_contact {
            for m in messages.iter_mut() {
                m.opens_conversation = false;
            }
        }
        messages.push(Composed {
            token,
            body: body.to_owned(),
            first_contact,
            accept: false,
            opens_conversation: false,
            after,
            seq: None,
            refusal: None,
            composed_at_ms: now_unix_ms(),
        });
    }

    /// A refused first contact whose conversation the runner then listed holds
    /// that message as sequence 0: the composed message stands for that row,
    /// so it is drawn once.
    fn adopt_refused_first_contacts(&mut self) {
        for (peer, messages) in &mut self.composed {
            let Some(c) = self.state.correspondences.get(peer) else {
                continue;
            };
            for m in messages
                .iter_mut()
                .filter(|m| m.first_contact && m.seq.is_none() && m.refusal.is_some())
            {
                let held = c.thread.iter().any(|row| {
                    matches!(row, DmThreadRow::Sent { seq: 0, body: Some(body) } if *body == m.body)
                });
                if held {
                    m.seq = Some(0);
                }
            }
        }
    }

    /// Whether an acceptance of a request from `peer` is on its way. Keyed on
    /// the person, because a start-over from them replaces the request's id.
    fn accepting_from(&self, peer: &IdentityPk) -> bool {
        self.state
            .outstanding
            .values()
            .any(|o| matches!(o, DmOutstanding::Accept { from, .. } if from == peer))
    }

    /// The correspondent a composed message was written to.
    fn peer_of(&self, token: CommandToken) -> Option<IdentityPk> {
        self.composed
            .iter()
            .find(|(_, ms)| ms.iter().any(|m| m.token == token))
            .map(|(pk, _)| pk.clone())
    }

    /// Place every acceptance reply against the conversation it opened.
    ///
    /// A refused reply whose conversation the runner then lists was written:
    /// the runner creates the conversation with the reply as sequence 0 and
    /// finishes the acceptance from that record without reporting `Sent`. Only
    /// a reply that alone could have opened it is taken as written: one sent
    /// with no conversation and no first contact to that person, while no
    /// other message of theirs here holds sequence 0.
    /// Until a reply is delivered it is drawn after every message the
    /// correspondent's side holds, since they cannot write again before
    /// collecting it.
    fn settle_accept_replies(&mut self) {
        let peers: Vec<IdentityPk> = self.composed.keys().cloned().collect();
        for peer in peers {
            let Some(c) = self.state.correspondences.get(&peer) else {
                continue;
            };
            let zero_held = self
                .composed
                .get(&peer)
                .is_some_and(|ms| ms.iter().any(|m| m.seq == Some(0)));
            let mut open = false;
            for m in self.composed.get_mut(&peer).into_iter().flatten() {
                if !m.accept {
                    continue;
                }
                if !zero_held && m.opens_conversation && m.seq.is_none() && m.refusal.is_some() {
                    m.seq = Some(0);
                    m.refusal = None;
                }
                open |= m.seq.is_some_and(|seq| !c.delivered(seq));
            }
            if !open {
                continue;
            }
            let after = self.foreign_rows(&peer);
            let c = self.state.correspondences.get(&peer);
            for m in self.composed.get_mut(&peer).into_iter().flatten() {
                if m.accept
                    && m.seq
                        .is_some_and(|seq| !c.is_some_and(|c| c.delivered(seq)))
                {
                    m.after = after;
                }
            }
        }
    }

    /// Bring every derived set back in line with what the runner reports.
    ///
    /// A draft whose conversation now exists becomes that conversation, and a
    /// selection moves with it. A selected request that has gone moves to the
    /// conversation its acceptance opened, or to nothing.
    fn reconcile(&mut self) {
        let state = &self.state;
        let promoted: Vec<IdentityPk> = self
            .drafts
            .keys()
            .filter(|pk| state.correspondences.contains_key(*pk))
            .cloned()
            .collect();
        for pk in promoted {
            self.drafts.remove(&pk);
        }
        if let Some(key) = self.selected.clone()
            && !self.exists(&key)
        {
            let conversation = DmItemKey::new(DmItemKind::Conversation, &key.peer);
            self.selected = (key.kind != DmItemKind::Conversation && self.exists(&conversation))
                .then_some(conversation);
        }
        let requests: BTreeSet<&IdentityPk> = self.state.requests.iter().map(|r| &r.from).collect();
        self.unread_requests.retain(|pk| requests.contains(pk));
        self.accept_refused.retain(|pk, _| requests.contains(pk));
        self.block_refused.retain(|pk, _| requests.contains(pk));
        let conversations = &self.state.correspondences;
        self.unread_conversations
            .retain(|pk| conversations.contains_key(pk));
        self.active_at
            .retain(|pk, _| conversations.contains_key(pk));
        let drafts = &self.drafts;
        self.composed.retain(|pk, _| {
            conversations.contains_key(pk) || drafts.contains_key(pk) || requests.contains(pk)
        });
        let named: Vec<IdentityPk> = self
            .state
            .requests
            .iter()
            .map(|r| r.from.clone())
            .chain(self.state.correspondences.keys().cloned())
            .chain(self.drafts.keys().cloned())
            .collect();
        for pk in named {
            let next = self.ids.len() as u64 + 1;
            self.ids.entry(pk).or_insert(next);
        }
        self.mark_viewed();
    }

    /// The row for `key`, with its label.
    fn rail_row(
        &self,
        key: DmItemKey,
        label: String,
        at_ms: Option<i64>,
        now_ms: i64,
    ) -> DmRailRow {
        let unread = match key.kind {
            DmItemKind::Request => self.unread_requests.contains(&key.peer),
            DmItemKind::Conversation => self.unread_conversations.contains(&key.peer),
            DmItemKind::Draft => false,
        };
        let id = self.ids.get(&key.peer).copied().unwrap_or(0);
        DmRailRow {
            slot: format!("{}{id}", key.kind.letter()),
            label,
            age: at_ms.map_or_else(String::new, |at| dm_age_text(at, now_ms)),
            unread,
            selected: self.selected.as_ref() == Some(&key),
            blocking: key.kind == DmItemKind::Request && self.state.blocking.contains(&key.peer),
            key,
        }
    }
}

/// Past this many days an age is shown as the date instead.
const DM_AGE_DAYS_MAX: i64 = 30;

/// How long ago `then_ms` was at `now_ms`, as a rail row's age: "now" under a
/// minute, then whole minutes, hours or days ("2m", "1h", "3d"), and past
/// [`DM_AGE_DAYS_MAX`] days the UTC date ("2026-03-14"). A time in the future
/// reads as "now".
pub fn dm_age_text(then_ms: i64, now_ms: i64) -> String {
    let secs = now_ms.saturating_sub(then_ms).max(0) / 1000;
    match secs {
        0..60 => "now".to_owned(),
        60..3600 => format!("{}m", secs / 60),
        3600..86_400 => format!("{}h", secs / 3600),
        _ if secs / 86_400 <= DM_AGE_DAYS_MAX => format!("{}d", secs / 86_400),
        _ => crate::format_unix_ms(then_ms.max(1))
            .get(..10)
            .unwrap_or_default()
            .to_owned(),
    }
}

/// A Unix-millisecond time from the view model as the GUI's signed clock value,
/// saturating at the far future.
fn unix_ms_i64(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// The correspondent's send time of the last message received in `c`, if any.
fn last_sent_at(c: &DmCorrespondence) -> Option<i64> {
    c.thread.iter().rev().find_map(|row| match row {
        DmThreadRow::Received { sent_at_ms, .. } => Some(unix_ms_i64(*sent_at_ms)),
        DmThreadRow::Sent { .. } => None,
    })
}

/// Received-message counts and activity stamps per conversation, to tell what
/// one fold changed.
fn activity_marks(state: &DmState) -> BTreeMap<IdentityPk, (usize, u64)> {
    state
        .correspondences
        .iter()
        .map(|(pk, c)| {
            let received = c
                .thread
                .iter()
                .filter(|row| matches!(row, DmThreadRow::Received { .. }))
                .count();
            (pk.clone(), (received, c.last_activity))
        })
        .collect()
}

/// A thread row as the thread view draws it, `delivered` saying which of this
/// side's sequences the correspondent has collected.
fn thread_row(delivered: impl Fn(u64) -> bool) -> impl Fn(&DmThreadRow) -> DmMessageRow {
    move |row| match row {
        DmThreadRow::Received {
            body, sent_at_ms, ..
        } => DmMessageRow {
            outgoing: false,
            body: body.clone(),
            status: None,
            at_ms: Some(unix_ms_i64(*sent_at_ms)),
        },
        DmThreadRow::Sent { seq, body } => DmMessageRow {
            outgoing: true,
            body: body.clone().unwrap_or_else(|| format!("message {seq}")),
            status: Some(if delivered(*seq) {
                DmMessageStatus::Delivered
            } else {
                DmMessageStatus::Sent
            }),
            at_ms: None,
        },
    }
}

/// The status of a composed message.
fn composed_status(m: &Composed, delivered: impl Fn(u64) -> bool) -> DmMessageStatus {
    match (m.seq, m.refusal) {
        (Some(seq), _) if delivered(seq) => DmMessageStatus::Delivered,
        (_, Some(_)) => DmMessageStatus::Refused,
        (Some(_), None) => DmMessageStatus::Sent,
        (None, None) => DmMessageStatus::Pending,
    }
}

impl GuiState {
    /// Fold one direct-messaging runner event.
    ///
    /// A correspondent starting over is also appended to the trust log. A
    /// request or message arriving in an item the user is not viewing marks it
    /// unread, and a conversation's age restarts whenever the event names it:
    /// from the correspondent's send time where a message was received, and
    /// from this side's clock otherwise.
    pub fn on_dm_event(&mut self, event: &RunnerEvent) {
        if let RunnerEvent::StartedOver { .. } = event {
            self.log_dm_started_over();
        }
        let now = now_unix_ms();
        let dm = &mut self.dm;
        let before = activity_marks(&dm.state);
        let folded = dm.state.fold(event, now);
        match event {
            RunnerEvent::Sent { token, seq, .. } => {
                if let Some(m) = dm.composed_mut(*token) {
                    m.seq = Some(*seq);
                    m.refusal = None;
                }
            }
            RunnerEvent::Refused {
                token: Some(token),
                reason,
            } => {
                let mut accept = false;
                if let Some(m) = dm.composed_mut(*token) {
                    m.refusal = Some(*reason);
                    accept = m.accept;
                }
                // A refused acceptance leaves the request as the one item for
                // that person, its thread holding the reply not sent.
                // A draft that also holds a first contact stays: that message
                // is still on its way.
                if accept
                    && let Some(peer) = dm.peer_of(*token)
                    && dm.state.requests.iter().any(|r| r.from == peer)
                    && !dm
                        .composed
                        .get(&peer)
                        .is_some_and(|ms| ms.iter().any(|m| m.first_contact))
                {
                    dm.drafts.remove(&peer);
                    let draft = DmItemKey::new(DmItemKind::Draft, &peer);
                    if dm.selected.as_ref() == Some(&draft) {
                        dm.selected = Some(DmItemKey::new(DmItemKind::Request, &peer));
                    }
                }
            }
            RunnerEvent::Refused {
                token: None,
                reason,
            } => {
                if let Some(peer) = dm.blocks_in_flight.pop_front() {
                    dm.block_refused.insert(peer, *reason);
                    dm.notice = Some(DmNotice::BlockRefused(*reason));
                }
                // The fold forgets every pending block; only the oldest was
                // refused.
                for peer in &dm.blocks_in_flight {
                    dm.state.blocking.insert(peer.clone());
                }
            }
            RunnerEvent::BlockList(listed) => {
                dm.blocks_in_flight.retain(|peer| !listed.contains(peer));
            }
            // Requests and received messages are marked unread below, and a
            // start over is logged above.
            RunnerEvent::ContactRequest { .. }
            | RunnerEvent::RequestPreview { .. }
            | RunnerEvent::StartedOver { .. }
            | RunnerEvent::Message { .. } => {}
            // The fold keeps what these report; the thread view reads it there.
            RunnerEvent::Roster(_)
            | RunnerEvent::Deleted { .. }
            | RunnerEvent::Delivered { .. }
            | RunnerEvent::Accepted { .. }
            | RunnerEvent::BlockListUnreadable
            | RunnerEvent::Health(_) => {}
        }
        if let Some((draft, reason)) = folded.refused_accept {
            dm.accept_refused.insert(draft.from, reason);
        }
        dm.adopt_refused_first_contacts();
        dm.settle_accept_replies();
        if let RunnerEvent::ContactRequest { request, from }
        | RunnerEvent::StartedOver { request, from } = event
            && dm
                .state
                .requests
                .iter()
                .any(|r| r.from == *from && r.request == *request)
            && !dm.viewing(&DmItemKey::new(DmItemKind::Request, from))
        {
            dm.unread_requests.insert(from.clone());
        }
        for (pk, (received, activity)) in activity_marks(&dm.state) {
            let (was_received, was_activity) = before.get(&pk).copied().unwrap_or((0, 0));
            if activity != was_activity || !before.contains_key(&pk) {
                let at = if received > was_received {
                    dm.state
                        .correspondences
                        .get(&pk)
                        .and_then(last_sent_at)
                        .unwrap_or(now)
                } else {
                    now
                };
                dm.active_at.insert(pk.clone(), at);
            }
            if received > was_received
                && !dm.viewing(&DmItemKey::new(DmItemKind::Conversation, &pk))
            {
                dm.unread_conversations.insert(pk);
            }
        }
        dm.reconcile();
        self.note_roster_handles();
    }

    /// The runner stopped: every message still unanswered is shown not sent,
    /// the Direct messages area says how many, and the requests it held are
    /// gone.
    pub fn on_dm_stopped(&mut self) {
        let dm = &mut self.dm;
        let mut accepts = 0;
        for m in dm.composed.values_mut().flatten().filter(|m| m.pending()) {
            m.refusal = Some(Refusal::ShuttingDown);
            accepts += usize::from(m.accept);
        }
        let count = dm.state.stop() + accepts;
        dm.blocks_in_flight.clear();
        dm.noted_handles.clear();
        if count > 0 {
            dm.notice = Some(DmNotice::NotSent { count });
        }
        dm.reconcile();
    }

    /// Drain the commands queued for the runner, oldest first. The binary
    /// forwards each with `NetHandle::dm`.
    pub fn take_pending_dm(&mut self) -> Vec<RunnerCommand> {
        std::mem::take(&mut self.dm.pending)
    }

    /// What the runner has reported. Read-only; the window reads the view
    /// models instead.
    #[cfg(test)]
    pub fn dm_state(&self) -> &DmState {
        &self.dm.state
    }

    /// The notice the Direct messages area shows: the block list being
    /// unreadable while it lasts, else the last notice an event or action left.
    pub fn dm_notice(&self) -> Option<DmNotice> {
        if self.dm.state.block_list_unknown {
            Some(DmNotice::BlockListUnreadable)
        } else {
            self.dm.notice
        }
    }

    /// The name the rail and the thread header give `peer`: the handle any
    /// room roster lists for that key, else the handle the runner's store
    /// recorded for a correspondent no roster lists now, else its fingerprint.
    pub fn dm_label(&self, peer: &IdentityPk) -> String {
        dm_name(
            self.roster_handle_for_key(peer),
            self.dm.state.correspondences.get(peer),
            peer,
        )
    }

    /// Queue a [`RunnerCommand::NoteHandle`] for every correspondent a room
    /// roster names with a handle other than the one the runner's store
    /// recorded, once per handle. Called whenever a room roster or the runner's
    /// roster changes.
    pub fn note_roster_handles(&mut self) {
        let mut notes = Vec::new();
        for (pk, correspondence) in &self.dm.state.correspondences {
            let Some(live) = self.roster_handle_for_key(pk) else {
                continue;
            };
            if correspondence.handle.as_deref() == Some(live)
                || self.dm.noted_handles.get(pk).map(String::as_str) == Some(live)
            {
                continue;
            }
            notes.push((pk.clone(), live.to_owned()));
        }
        for (pk, handle) in notes {
            self.dm.noted_handles.insert(pk.clone(), handle.clone());
            self.dm.pending.push(RunnerCommand::NoteHandle {
                peer_identity_pk: pk,
                handle,
            });
        }
    }

    /// Start a direct message with `peer`, chosen from a roster.
    ///
    /// The caller passes the member's key as it read it when the roster menu
    /// opened, never a row index: the roster re-sorts on every presence update.
    ///
    /// A peer with a conversation selects it, and a peer with a pending request
    /// selects the request, which is answered by accepting it. Otherwise a draft
    /// opens; nothing is sent until its first message. Returns the item
    /// selected.
    pub fn start_dm_with(&mut self, peer: IdentityPk) -> DmItemKey {
        let dm = &mut self.dm;
        dm.notice = None;
        let key = if dm.state.correspondences.contains_key(&peer) {
            DmItemKey::new(DmItemKind::Conversation, &peer)
        } else if dm
            .state
            .requests
            .iter()
            .any(|r| r.from == peer && !dm.accepting_from(&peer))
        {
            DmItemKey::new(DmItemKind::Request, &peer)
        } else {
            dm.drafts.entry(peer.clone()).or_insert_with(now_unix_ms);
            DmItemKey::new(DmItemKind::Draft, &peer)
        };
        dm.reconcile();
        dm.select(key.clone());
        key
    }

    /// Send `body` in the selected thread: the first message of a draft, or a
    /// message on a conversation. Returns whether a command was queued.
    ///
    /// Nothing is queued for an empty body, a request, or a thread that cannot
    /// take a message now (see [`DmThreadView::can_send`]). A draft whose
    /// person turns out to hold a conversation or a request here is dropped for
    /// that item, which is selected, and [`GuiState::dm_notice`] says why; the
    /// text is not sent, so the caller keeps it in the composer.
    pub fn send_dm(&mut self, body: &str) -> bool {
        self.dm.notice = None;
        if body.trim().is_empty()
            || self.main_pane() != MainPane::DmThread
            || !self.dm_thread_view().is_some_and(|t| t.can_send)
        {
            return false;
        }
        let dm = &mut self.dm;
        let Some(key) = dm.selected.clone() else {
            return false;
        };
        match key.kind {
            DmItemKind::Draft => match dm.state.first_contact(key.peer.clone(), body.to_owned()) {
                Ok(command) => {
                    if let RunnerCommand::FirstContact { token, .. } = &command {
                        dm.compose(&key.peer, *token, body, true);
                    }
                    dm.pending.push(command);
                    true
                }
                Err(FirstContactBlocked::ExistingConversation) => {
                    dm.drafts.remove(&key.peer);
                    dm.select(DmItemKey::new(DmItemKind::Conversation, &key.peer));
                    dm.notice = Some(DmNotice::MovedToConversation);
                    dm.reconcile();
                    false
                }
                Err(FirstContactBlocked::PendingRequest(_)) => {
                    dm.drafts.remove(&key.peer);
                    dm.select(DmItemKey::new(DmItemKind::Request, &key.peer));
                    dm.notice = Some(DmNotice::MovedToRequest);
                    dm.reconcile();
                    false
                }
                Err(FirstContactBlocked::InFlight) => false,
            },
            DmItemKind::Conversation => {
                let Some(label) = dm
                    .state
                    .correspondences
                    .get(&key.peer)
                    .and_then(|c| c.label)
                else {
                    return false;
                };
                let token = dm.state.next_token();
                dm.pending.push(RunnerCommand::Send {
                    token,
                    peer: label,
                    body: body.as_bytes().to_vec(),
                });
                dm.compose(&key.peer, token, body, false);
                dm.state.outstanding.insert(
                    token,
                    DmOutstanding::Send {
                        peer: key.peer,
                        body: body.to_owned(),
                    },
                );
                true
            }
            DmItemKind::Request => false,
        }
    }

    /// The selected request's sender, while a request is selected and no block
    /// of it is on its way.
    fn selected_requester(&self) -> Option<IdentityPk> {
        self.dm
            .selected
            .as_ref()
            .filter(|key| key.kind == DmItemKind::Request && self.dm.exists(key))
            .filter(|key| !self.dm.state.blocking.contains(&key.peer))
            .map(|key| key.peer.clone())
    }

    /// Accept the selected request, replying [`DM_ACCEPT_REPLY`]. Returns
    /// whether a command was queued; an acceptance already on its way queues
    /// no second one.
    ///
    /// The request turns into its conversation at once: a draft is selected
    /// whose thread shows the reply as a message being sent, and the request
    /// leaves the rail while the acceptance is on its way. The runner's report
    /// moves the reply to sent, or to not sent with the reason; a refused
    /// acceptance lists the request again, and accepting it again replaces the
    /// refused reply.
    pub fn accept_dm_request(&mut self) -> bool {
        self.dm.notice = None;
        let Some(from) = self.selected_requester() else {
            return false;
        };
        let dm = &mut self.dm;
        let Some(request) = dm
            .state
            .requests
            .iter()
            .find(|r| r.from == from)
            .map(|r| r.request)
        else {
            return false;
        };
        if dm.accepting_from(&from) {
            return false;
        }
        // A first contact already sent to them may be what opens the
        // conversation instead.
        let opens_conversation = !dm.state.correspondences.contains_key(&from)
            && !dm
                .composed
                .get(&from)
                .is_some_and(|ms| ms.iter().any(|m| m.first_contact));
        let token = dm.state.next_token();
        dm.pending.push(RunnerCommand::Accept {
            token,
            request,
            reply: DM_ACCEPT_REPLY.as_bytes().to_vec(),
        });
        dm.accept_refused.remove(&from);
        dm.state.outstanding.insert(
            token,
            DmOutstanding::Accept {
                request,
                from: from.clone(),
                reply: DM_ACCEPT_REPLY.to_owned(),
            },
        );
        dm.drafts.entry(from.clone()).or_insert_with(now_unix_ms);
        if let Some(messages) = dm.composed.get_mut(&from) {
            messages.retain(|m| !(m.accept && m.refusal.is_some()));
        }
        dm.compose(&from, token, DM_ACCEPT_REPLY, false);
        if let Some(m) = dm.composed_mut(token) {
            m.accept = true;
            m.opens_conversation = opens_conversation;
        }
        dm.select(DmItemKey::new(DmItemKind::Draft, &from));
        dm.reconcile();
        true
    }

    /// Hide the selected request's sender for this session. Queues nothing.
    /// Returns whether a request was hidden.
    pub fn decline_dm_request(&mut self) -> bool {
        self.dm.notice = None;
        let Some(from) = self.selected_requester() else {
            return false;
        };
        let dm = &mut self.dm;
        dm.state.requests.retain(|r| r.from != from);
        dm.state.declined.insert(from);
        dm.reconcile();
        true
    }

    /// Block the selected request's sender. Returns whether a command was
    /// queued.
    ///
    /// The request stays listed, marked blocking, until the runner's block
    /// list names the sender. A refused block lists it as before, and the
    /// notice and the request's thread say why.
    pub fn block_dm_request(&mut self) -> bool {
        self.dm.notice = None;
        let Some(from) = self.selected_requester() else {
            return false;
        };
        let dm = &mut self.dm;
        dm.state.blocking.insert(from.clone());
        dm.block_refused.remove(&from);
        dm.blocks_in_flight.push_back(from.clone());
        dm.pending.push(RunnerCommand::Block { peer: from });
        dm.reconcile();
        true
    }

    /// Select a direct-message item, opening its section. Returns false, and
    /// changes nothing, for an item the rail does not hold.
    pub fn select_dm_item(&mut self, key: &DmItemKey) -> bool {
        if !self.dm.exists(key) {
            return false;
        }
        self.dm.notice = None;
        self.dm.select(key.clone());
        true
    }

    /// The item a [`DmRailRow::slot`] names, while the rail still holds it.
    pub fn dm_item_for_slot(&self, slot: &str) -> Option<DmItemKey> {
        let mut chars = slot.chars();
        let kind = match chars.next()? {
            'r' => DmItemKind::Request,
            'c' => DmItemKind::Conversation,
            'd' => DmItemKind::Draft,
            _ => return None,
        };
        let id: u64 = chars.as_str().parse().ok()?;
        let peer = self.dm.ids.iter().find(|(_, v)| **v == id)?.0;
        let key = DmItemKey::new(kind, peer);
        self.dm.exists(&key).then_some(key)
    }

    /// Open a section by its header: it opens and the other closes. Chats
    /// selects the Lobby; Direct messages selects nothing, so the main pane
    /// asks the user to choose a conversation.
    ///
    /// `live_draft` and `live_scroll` are the chat composer's text and scroll,
    /// kept for the active room when the main pane is showing it (as
    /// [`GuiState::switch_to`] takes them).
    pub fn open_rail_section(
        &mut self,
        section: RailSection,
        live_draft: String,
        live_scroll: f32,
    ) {
        match section {
            RailSection::Chats => {
                let (draft, scroll) = if self.main_pane() == MainPane::Chat {
                    (live_draft, live_scroll)
                } else {
                    let c = self.current();
                    (c.draft.clone(), c.scroll_y)
                };
                self.dm.dms_open = false;
                self.dm.selected = None;
                self.switch_to(0, draft, scroll);
            }
            RailSection::DirectMessages => {
                let dm = &mut self.dm;
                dm.notice = None;
                dm.dms_open = true;
                dm.chats_open = false;
                dm.owner = RailSection::DirectMessages;
                dm.selected = None;
            }
        }
    }

    /// Flip a section's chevron: fold it if unfolded, else unfold it. Only
    /// that section changes. Which section owns the main pane does not.
    ///
    /// Folding the section that owns the main pane shows its placeholder.
    /// Folding Direct messages then also clears its selection, so unfolding it
    /// again shows "Choose a conversation": a conversation is shown only when
    /// chosen. Unfolding Chats shows the active room again.
    pub fn toggle_rail_section(&mut self, section: RailSection) {
        let dm = &mut self.dm;
        let open = !dm.is_open(section);
        match section {
            RailSection::Chats => dm.chats_open = open,
            RailSection::DirectMessages => {
                dm.dms_open = open;
                if !open && dm.owner == RailSection::DirectMessages {
                    dm.selected = None;
                }
            }
        }
        dm.mark_viewed();
        if self.main_pane() == MainPane::Chat {
            self.mark_active_room_seen();
        }
    }

    /// Whether `section` is unfolded.
    pub fn rail_section_open(&self, section: RailSection) -> bool {
        self.dm.is_open(section)
    }

    /// Whether anything in `section` is unread: for Chats, any room's unread
    /// dot; for Direct messages, any request or conversation.
    pub fn rail_section_unread(&self, section: RailSection) -> bool {
        match section {
            RailSection::Chats => self.metas().iter().any(|c| c.unread),
            RailSection::DirectMessages => {
                !self.dm.unread_requests.is_empty() || !self.dm.unread_conversations.is_empty()
            }
        }
    }

    /// What the main pane shows.
    pub fn main_pane(&self) -> MainPane {
        let dm = &self.dm;
        match dm.owner {
            RailSection::Chats if dm.chats_open => MainPane::Chat,
            RailSection::Chats => MainPane::ChatPlaceholder,
            RailSection::DirectMessages if dm.thread_on_screen() => MainPane::DmThread,
            RailSection::DirectMessages => MainPane::DmPlaceholder,
        }
    }

    /// The Direct messages rail rows at `now_ms`: requests first, oldest first;
    /// then drafts, newest first; then conversations, newest first. A request
    /// whose acceptance is on its way is shown as its draft only; once the
    /// acceptance is answered, a start-over from that person made meanwhile is
    /// listed again for its own answer.
    pub fn dm_rail_rows(&self, now_ms: i64) -> Vec<DmRailRow> {
        let dm = &self.dm;
        let mut rows = Vec::new();
        for request in dm
            .state
            .requests
            .iter()
            .filter(|r| !dm.accepting_from(&r.from))
        {
            let key = DmItemKey::new(DmItemKind::Request, &request.from);
            let label = self.dm_label(&request.from);
            rows.push(dm.rail_row(key, label, Some(request.held_at_ms), now_ms));
        }
        let mut drafts: Vec<(&IdentityPk, &i64)> = dm.drafts.iter().collect();
        drafts.sort_by(|(a_pk, a), (b_pk, b)| b.cmp(a).then(a_pk.cmp(b_pk)));
        for (pk, at) in drafts {
            let key = DmItemKey::new(DmItemKind::Draft, pk);
            rows.push(dm.rail_row(key, self.dm_label(pk), Some(*at), now_ms));
        }
        for (pk, _) in dm.state.correspondences_newest_first() {
            let key = DmItemKey::new(DmItemKind::Conversation, pk);
            let at = dm.active_at.get(pk).copied();
            rows.push(dm.rail_row(key, self.dm_label(pk), at, now_ms));
        }
        rows
    }

    /// The selected item's thread, or `None` with nothing selected.
    ///
    /// Messages composed here are drawn in the order they were composed, each
    /// after the thread rows held when it was, whatever the runner answered.
    pub fn dm_thread_view(&self) -> Option<DmThreadView> {
        let dm = &self.dm;
        let key = dm.selected.clone().filter(|key| dm.exists(key))?;
        let peer = &key.peer;
        let header_label = self.dm_label(peer);
        let fingerprint = dm_fingerprint(peer);
        let blocked = dm.state.blocked.contains(peer);
        // The requester's previewed messages, until a conversation holds them.
        let mut rows: Vec<DmMessageRow> = if dm.state.correspondences.contains_key(peer) {
            Vec::new()
        } else {
            dm.state
                .requests
                .iter()
                .filter(|r| r.from == *peer)
                .flat_map(|r| &r.preview)
                .map(thread_row(|_| false))
                .collect()
        };
        if key.kind == DmItemKind::Request {
            // A refused acceptance reply stays with the request it answered,
            // unless a conversation with them holds it.
            if !dm.state.correspondences.contains_key(peer) {
                rows.extend(
                    dm.composed
                        .get(peer)
                        .into_iter()
                        .flatten()
                        .filter(|m| m.accept && m.refusal.is_some())
                        .map(|m| DmMessageRow {
                            outgoing: true,
                            body: m.body.clone(),
                            status: Some(DmMessageStatus::Refused),
                            at_ms: Some(m.composed_at_ms),
                        }),
                );
            }
            return Some(DmThreadView {
                refusal: dm
                    .block_refused
                    .get(peer)
                    .or_else(|| dm.accept_refused.get(peer))
                    .copied(),
                blocking: dm.state.blocking.contains(peer),
                key,
                header_label,
                fingerprint,
                is_request: true,
                rows,
                can_send: false,
                blocked,
            });
        }
        let correspondence = dm.state.correspondences.get(peer);
        let delivered = |seq: u64| correspondence.is_some_and(|c| c.delivered(seq));
        let composed: &[Composed] = dm.composed.get(peer).map_or(&[], Vec::as_slice);
        let mine: BTreeSet<u64> = composed.iter().filter_map(|m| m.seq).collect();
        let composed_row = |m: &Composed| DmMessageRow {
            outgoing: true,
            body: m.body.clone(),
            status: Some(composed_status(m, delivered)),
            at_ms: Some(m.composed_at_ms),
        };
        let draw = thread_row(delivered);
        let mut next = composed.iter().peekable();
        let mut foreign = 0usize;
        for row in correspondence.map_or(&[][..], |c| c.thread.as_slice()) {
            if let DmThreadRow::Sent { seq, .. } = row
                && mine.contains(seq)
            {
                continue;
            }
            while let Some(m) = next.next_if(|m| m.after <= foreign) {
                rows.push(composed_row(m));
            }
            rows.push(draw(row));
            foreign += 1;
        }
        rows.extend(next.map(composed_row));
        let can_send = !blocked
            && match key.kind {
                DmItemKind::Draft => !composed.iter().any(Composed::pending),
                _ => correspondence.is_some_and(|c| c.label.is_some()),
            };
        let refusal = composed
            .iter()
            .rev()
            .find(|m| composed_status(m, delivered) == DmMessageStatus::Refused)
            .and_then(|m| m.refusal)
            .or_else(|| correspondence.and_then(|c| c.refusal));
        Some(DmThreadView {
            refusal,
            key,
            header_label,
            fingerprint,
            is_request: false,
            rows,
            can_send,
            blocking: false,
            blocked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::RosterEntry;
    use daemonseed_core::dm::flows::ReceivedMessage;
    use daemonseed_core::identity::keys::IDENTITY_PK_LEN;
    use daemonseed_core::storage::dm_store::CorrespondenceLabel;
    use daemonseed_veilid_net::dm::runner::{
        CommandToken, ContactRequestId, ConversationState, ConversationSummary, HealthCounters,
    };

    fn pk(tag: u8) -> IdentityPk {
        Box::new([tag; IDENTITY_PK_LEN])
    }

    fn request_id(serial: u64) -> ContactRequestId {
        ContactRequestId::for_test(1, serial)
    }

    fn label() -> CorrespondenceLabel {
        CorrespondenceLabel::mint().expect("a label mints")
    }

    fn member(handle: &str, tag: u8) -> RosterEntry {
        RosterEntry {
            handle: handle.into(),
            fingerprint: "#000000000000".into(),
            pubkey: vec![tag; IDENTITY_PK_LEN],
        }
    }

    fn roster(rows: &[(CorrespondenceLabel, u8, ConversationState)]) -> RunnerEvent {
        RunnerEvent::Roster(
            rows.iter()
                .map(|(peer, tag, state)| ConversationSummary {
                    peer: *peer,
                    peer_identity_pk: pk(*tag),
                    state: *state,
                    peer_collected: 0,
                    uncollected: 0,
                    handle: None,
                })
                .collect(),
        )
    }

    /// A roster naming one established conversation with `tag`, carrying the
    /// handle the runner's store recorded for it.
    fn roster_with_handle(peer: CorrespondenceLabel, tag: u8, handle: Option<&str>) -> RunnerEvent {
        RunnerEvent::Roster(vec![ConversationSummary {
            peer,
            peer_identity_pk: pk(tag),
            state: ConversationState::Established,
            peer_collected: 0,
            uncollected: 0,
            handle: handle.map(str::to_owned),
        }])
    }

    /// The label of the one rail row and of the open thread's header.
    fn labels(st: &mut GuiState, tag: u8) -> (String, String) {
        st.select_dm_item(&conversation(tag));
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1, "one conversation row");
        let header = st
            .dm_thread_view()
            .expect("the thread is open")
            .header_label;
        (rows[0].label.clone(), header)
    }

    /// A conversation keeps its correspondent's handle once no room roster
    /// lists them, and across a restart, through the handle the runner's store
    /// records: a roster naming the key sends that handle to the runner once,
    /// and with none recorded and none listed the fingerprint is shown.
    #[test]
    fn a_conversation_keeps_its_handle_after_the_roster_drops_the_peer() {
        let (mut st, peer) = with_conversation(7);
        let fingerprint = dm_fingerprint(&pk(7));
        assert_eq!(
            labels(&mut st, 7),
            (fingerprint.clone(), fingerprint.clone())
        );
        assert!(st.take_pending_dm().is_empty(), "no handle to note yet");

        st.set_room_roster(None, vec![member("anna", 7)]);
        assert_eq!(labels(&mut st, 7), ("anna".to_owned(), "anna".to_owned()));
        let noted = st.take_pending_dm();
        assert!(
            matches!(noted.as_slice(), [RunnerCommand::NoteHandle { peer_identity_pk, handle }]
                if *peer_identity_pk == pk(7) && handle == "anna"),
            "the roster's handle goes to the runner once: {noted:?}"
        );
        st.set_room_roster(None, vec![member("anna", 7)]);
        assert!(
            st.take_pending_dm().is_empty(),
            "the same handle is not sent again"
        );

        // The runner stored it and reports the roster, and the room roster
        // then drops the peer.
        st.on_dm_event(&roster_with_handle(peer, 7, Some("anna")));
        st.set_room_roster(None, Vec::new());
        assert_eq!(labels(&mut st, 7), ("anna".to_owned(), "anna".to_owned()));

        // A restart: a fresh front end hears the stored handle from the
        // runner's first roster, with no room roster yet.
        let mut restarted = GuiState::lobby_only();
        restarted.on_dm_event(&roster_with_handle(peer, 7, Some("anna")));
        assert_eq!(
            labels(&mut restarted, 7),
            ("anna".to_owned(), "anna".to_owned())
        );
        assert!(restarted.take_pending_dm().is_empty());

        // A live roster handle wins over the stored one, and is noted.
        restarted.set_room_roster(None, vec![member("anna2", 7)]);
        assert_eq!(labels(&mut restarted, 7).0, "anna2");
        assert_eq!(restarted.take_pending_dm().len(), 1);
    }

    /// A state holding one conversation with `tag`, under the returned label.
    fn with_conversation(tag: u8) -> (GuiState, CorrespondenceLabel) {
        let mut st = GuiState::lobby_only();
        let peer = label();
        st.on_dm_event(&roster(&[(peer, tag, ConversationState::Established)]));
        (st, peer)
    }

    fn conversation(tag: u8) -> DmItemKey {
        DmItemKey::new(DmItemKind::Conversation, &pk(tag))
    }

    fn request(tag: u8) -> DmItemKey {
        DmItemKey::new(DmItemKind::Request, &pk(tag))
    }

    /// A roster row opens a draft and nothing is sent until its first
    /// message, which issues exactly one first contact carrying that member's
    /// key and the body.
    #[test]
    fn starting_from_a_roster_row_sends_nothing_until_the_first_message() {
        let mut st = GuiState::lobby_only();
        st.set_room_roster(None, vec![member("anna", 1), member("bert", 2)]);
        let key = st.active_roster_key(1).expect("row 1 has a key");
        let draft = st.start_dm_with(key);
        assert_eq!(draft, DmItemKey::new(DmItemKind::Draft, &pk(2)));
        assert!(
            st.take_pending_dm().is_empty(),
            "starting a draft sent something"
        );
        assert_eq!(st.main_pane(), MainPane::DmThread);
        assert!(st.dm_thread_view().is_some_and(|t| t.can_send));

        assert!(st.send_dm("hello bert"));
        let sent = st.take_pending_dm();
        assert_eq!(sent.len(), 1, "one first contact, got {sent:?}");
        let RunnerCommand::FirstContact {
            peer_identity_pk,
            body,
            ..
        } = &sent[0]
        else {
            panic!("expected a first contact, got {sent:?}");
        };
        assert_eq!(peer_identity_pk, &pk(2));
        assert_eq!(body, b"hello bert");
        assert!(!st.send_dm("again"), "a second first contact went out");
        assert!(st.take_pending_dm().is_empty());
    }

    /// The roster re-sorts between the menu opening and the action: the action
    /// goes to the member whose key was read when the menu opened.
    #[test]
    fn a_roster_reorder_before_the_action_keeps_the_chosen_member() {
        let mut st = GuiState::lobby_only();
        st.set_room_roster(None, vec![member("anna", 1), member("bert", 2)]);
        let chosen = st.active_roster_key(0).expect("row 0 has a key");
        st.set_room_roster(None, vec![member("bert", 2), member("anna", 1)]);
        assert_eq!(st.active_roster_key(0), Some(pk(2)), "the roster reordered");

        st.start_dm_with(chosen);
        assert!(st.send_dm("hi"));
        match st.take_pending_dm().as_slice() {
            [
                RunnerCommand::FirstContact {
                    peer_identity_pk, ..
                },
            ] => assert_eq!(peer_identity_pk, &pk(1)),
            other => panic!("expected one first contact, got {other:?}"),
        }
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "anna", "the roster handle labels the draft");
    }

    /// A draft becomes its conversation once the runner reports the first
    /// message sent.
    #[test]
    fn a_sent_first_contact_turns_the_draft_into_its_conversation() {
        let mut st = GuiState::lobby_only();
        st.start_dm_with(pk(4));
        assert!(st.send_dm("hello"));
        let [RunnerCommand::FirstContact { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one first contact");
        };
        let thread = st.dm_thread_view().expect("the draft is selected");
        assert_eq!(thread.rows[0].status, Some(DmMessageStatus::Pending));
        assert!(!thread.can_send, "a draft took a second first contact");

        st.on_dm_event(&RunnerEvent::Sent {
            token,
            peer: label(),
            seq: 0,
        });
        let thread = st.dm_thread_view().expect("the selection followed");
        assert_eq!(thread.key, conversation(4));
        assert_eq!(thread.rows.len(), 1);
        assert_eq!(thread.rows[0].body, "hello");
        assert_eq!(thread.rows[0].status, Some(DmMessageStatus::Sent));
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1, "the draft outlived its conversation");
        assert_eq!(rows[0].key.kind, DmItemKind::Conversation);
    }

    /// A peer with a conversation, or with a pending request, opens that item
    /// rather than a draft.
    #[test]
    fn starting_with_a_known_peer_selects_what_is_held() {
        let (mut st, _) = with_conversation(5);
        assert_eq!(st.start_dm_with(pk(5)), conversation(5));
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(6),
        });
        assert_eq!(st.start_dm_with(pk(6)), request(6));
        assert!(st.take_pending_dm().is_empty());
    }

    /// Accepting sends one Accept carrying "message accepted", and a second
    /// press sends nothing more. A request with no preview shows no message.
    #[test]
    fn accepting_a_request_sends_one_accept_with_the_fixed_reply() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(7),
            from: pk(3),
        });
        assert!(st.select_dm_item(&request(3)));
        let thread = st.dm_thread_view().expect("the request is selected");
        assert!(thread.is_request && thread.rows.is_empty() && !thread.can_send);

        assert!(st.accept_dm_request());
        assert!(!st.accept_dm_request(), "a second acceptance was queued");
        match st.take_pending_dm().as_slice() {
            [RunnerCommand::Accept { request, reply, .. }] => {
                assert_eq!(*request, request_id(7));
                assert_eq!(reply, DM_ACCEPT_REPLY.as_bytes());
                assert_eq!(DM_ACCEPT_REPLY, "message accepted");
            }
            other => panic!("expected one accept, got {other:?}"),
        }
    }

    /// Accepting turns the request into its conversation at once: before the
    /// runner answers, the rail holds one row that is not a request, and the
    /// thread shows the fixed reply as this side's message, sending. The
    /// runner's report moves it to sent, after the message the request carried.
    #[test]
    fn accepting_shows_the_conversation_and_the_reply_before_the_runner_answers() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(7),
            from: pk(3),
        });
        st.select_dm_item(&request(3));
        assert!(st.accept_dm_request());
        let [RunnerCommand::Accept { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one accept");
        };

        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(
            rows.len(),
            1,
            "the request and its conversation both listed"
        );
        assert_ne!(rows[0].key.kind, DmItemKind::Request);
        assert!(rows[0].selected);
        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert!(!thread.is_request);
        assert_eq!(thread.rows.len(), 1);
        assert!(thread.rows[0].outgoing);
        assert_eq!(thread.rows[0].body, DM_ACCEPT_REPLY);
        assert_eq!(thread.rows[0].status, Some(DmMessageStatus::Pending));
        assert!(
            !thread.can_send,
            "a message could be sent before acceptance"
        );
        assert!(!st.accept_dm_request(), "a second acceptance was queued");
        assert!(st.take_pending_dm().is_empty());
        // Choosing the person again finds the conversation, not the request.
        assert_eq!(
            st.start_dm_with(pk(3)),
            DmItemKey::new(DmItemKind::Draft, &pk(3))
        );

        // The request's own message arrives before the answer that names it.
        let peer = label();
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"hi, it's cora".to_vec(),
            sent_at: 1,
            received_at: 1,
        });
        st.on_dm_event(&RunnerEvent::Sent {
            token,
            peer,
            seq: 0,
        });
        let thread = st.dm_thread_view().expect("the selection followed");
        assert_eq!(thread.key, conversation(3));
        let bodies: Vec<(&str, Option<DmMessageStatus>)> = thread
            .rows
            .iter()
            .map(|row| (row.body.as_str(), row.status))
            .collect();
        assert_eq!(
            bodies,
            [
                ("hi, it's cora", None),
                (DM_ACCEPT_REPLY, Some(DmMessageStatus::Sent))
            ]
        );
        assert_eq!(st.dm_rail_rows(now_unix_ms()).len(), 1);
        st.on_dm_event(&RunnerEvent::Delivered {
            peer,
            through_seq: 0,
        });
        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert_eq!(thread.rows[1].status, Some(DmMessageStatus::Delivered));
    }

    /// A previewed request shows its message before it is accepted, the
    /// acceptance shows it above the reply while the runner works, and the
    /// runner's answer, which reports the message again, leaves it once, above
    /// the reply.
    #[test]
    fn a_previewed_message_shows_before_accept_and_once_above_the_reply() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(7),
            from: pk(3),
        });
        st.on_dm_event(&RunnerEvent::RequestPreview {
            request: request_id(7),
            messages: vec![ReceivedMessage {
                sent_at_ms: 1,
                body: b"hi, it's cora".to_vec(),
            }],
            read_at: 2,
        });
        st.select_dm_item(&request(3));
        let thread = st.dm_thread_view().expect("the request is selected");
        assert!(thread.is_request);
        assert_eq!(thread_rows(&st), [("hi, it's cora".to_owned(), None)]);

        assert!(st.accept_dm_request());
        let [RunnerCommand::Accept { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one accept");
        };
        assert_eq!(
            thread_rows(&st),
            [
                ("hi, it's cora".to_owned(), None),
                (DM_ACCEPT_REPLY.to_owned(), Some(DmMessageStatus::Pending)),
            ]
        );

        let peer = label();
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"hi, it's cora".to_vec(),
            sent_at: 1,
            received_at: 3,
        });
        st.on_dm_event(&RunnerEvent::Sent {
            token,
            peer,
            seq: 0,
        });
        let thread = st.dm_thread_view().expect("the selection followed");
        assert_eq!(thread.key, conversation(3));
        assert_eq!(
            thread_rows(&st),
            [
                ("hi, it's cora".to_owned(), None),
                (DM_ACCEPT_REPLY.to_owned(), Some(DmMessageStatus::Sent)),
            ]
        );
    }

    /// A received message's age, in its thread and on its conversation's rail
    /// row, is read from the correspondent's send time, not from when it
    /// arrived; a message composed here is aged from its composition, and a
    /// contact request from its arrival.
    #[test]
    fn a_received_message_is_aged_by_its_senders_time() {
        let (mut st, peer) = with_conversation(4);
        st.select_dm_item(&conversation(4));
        let now = now_unix_ms();
        let sent_at = now - 3 * 3_600_000;
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"from three hours ago".to_vec(),
            sent_at: u64::try_from(sent_at).expect("a positive time"),
            received_at: u64::try_from(now).expect("a positive time"),
        });

        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert_eq!(thread.rows.len(), 1);
        assert_eq!(thread.rows[0].at_ms, Some(sent_at));
        assert_eq!(dm_age_text(thread.rows[0].at_ms.unwrap(), now), "3h");
        let rail = st.dm_rail_rows(now);
        assert_eq!(rail.len(), 1);
        assert_eq!(rail[0].key, conversation(4));
        assert_eq!(
            rail[0].age, "3h",
            "the rail did not age it from the sender's time"
        );

        // A message composed here is aged from when it was composed.
        let before = now_unix_ms();
        assert!(st.send_dm("mine"), "the send was not queued");
        let after = now_unix_ms();
        let thread = st.dm_thread_view().expect("the conversation is selected");
        let mine = thread.rows[1].at_ms.expect("a composed row has a time");
        assert!(thread.rows[1].outgoing);
        assert!((before..=after).contains(&mine));

        // A contact request, which carries no message, keeps its arrival age.
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(5),
        });
        let rail = st.dm_rail_rows(now_unix_ms());
        let request_row = rail
            .iter()
            .find(|row| row.key == request(5))
            .expect("the request is listed");
        assert_eq!(request_row.age, "now");
    }

    /// A send time ahead of the arrival, from a correspondent whose clock runs
    /// fast, is held at the arrival rather than shown in the future.
    #[test]
    fn a_send_time_in_the_future_is_held_at_the_arrival() {
        let (mut st, peer) = with_conversation(4);
        st.select_dm_item(&conversation(4));
        let now = now_unix_ms();
        let received_at = now - 2 * 3_600_000;
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"from tomorrow".to_vec(),
            sent_at: u64::try_from(now + 86_400_000).expect("a positive time"),
            received_at: u64::try_from(received_at).expect("a positive time"),
        });
        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert_eq!(thread.rows[0].at_ms, Some(received_at));
        assert_eq!(st.dm_rail_rows(now)[0].age, "2h");
    }

    /// The request 3 sent, selected and accepted; the Accept's token.
    fn accepted_request() -> (GuiState, CommandToken) {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(7),
            from: pk(3),
        });
        st.select_dm_item(&request(3));
        assert!(st.accept_dm_request());
        let [RunnerCommand::Accept { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one accept");
        };
        (st, token)
    }

    /// A refusal the runner follows with the conversation it created: the reply
    /// was written as sequence 0, and the acceptance finishes with no `Sent`.
    /// The reply is sent, then delivered, after the message the request carried.
    #[test]
    fn a_refused_acceptance_whose_conversation_is_listed_was_sent() {
        let (mut st, token) = accepted_request();
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(token),
            reason: Refusal::Network,
        });
        let peer = label();
        st.on_dm_event(&roster(&[(peer, 3, ConversationState::Pending)]));
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"hi, it's cora".to_vec(),
            sent_at: 1,
            received_at: 1,
        });
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1, "listed twice: {rows:?}");
        let thread = st.dm_thread_view().expect("the selection followed");
        assert_eq!(thread.key, conversation(3));
        assert_eq!(thread.refusal, None);
        let bodies: Vec<(&str, Option<DmMessageStatus>)> = thread
            .rows
            .iter()
            .map(|row| (row.body.as_str(), row.status))
            .collect();
        assert_eq!(
            bodies,
            [
                ("hi, it's cora", None),
                (DM_ACCEPT_REPLY, Some(DmMessageStatus::Sent))
            ]
        );
        st.on_dm_event(&RunnerEvent::Delivered {
            peer,
            through_seq: 0,
        });
        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert_eq!(thread.rows[1].status, Some(DmMessageStatus::Delivered));
    }

    /// A start-over from the same person while the acceptance is on its way
    /// neither lists the request again nor takes a second acceptance, and is
    /// listed for its own answer once the first acceptance is sent.
    #[test]
    fn a_start_over_during_an_acceptance_waits_for_it() {
        let (mut st, token) = accepted_request();
        st.on_dm_event(&RunnerEvent::StartedOver {
            request: request_id(8),
            from: pk(3),
        });
        assert_eq!(st.dm_rail_rows(now_unix_ms()).len(), 1);
        assert!(st.select_dm_item(&request(3)));
        assert!(!st.accept_dm_request(), "a second acceptance was queued");
        assert!(st.take_pending_dm().is_empty());

        let peer = label();
        st.on_dm_event(&RunnerEvent::Sent {
            token,
            peer,
            seq: 0,
        });
        st.on_dm_event(&roster(&[(peer, 3, ConversationState::Pending)]));
        let kinds: Vec<DmItemKind> = st
            .dm_rail_rows(now_unix_ms())
            .iter()
            .map(|row| row.key.kind)
            .collect();
        assert_eq!(kinds, [DmItemKind::Request, DmItemKind::Conversation]);
        assert!(st.dm_state().requests[0].started_over);
    }

    /// A start-over accepted while the old conversation remains is refused, and
    /// the roster that still lists the old conversation does not make its reply
    /// sent.
    #[test]
    fn a_refused_start_over_acceptance_stays_not_sent() {
        let (mut st, peer) = with_conversation(3);
        st.on_dm_event(&RunnerEvent::StartedOver {
            request: request_id(8),
            from: pk(3),
        });
        assert!(st.select_dm_item(&request(3)));
        assert!(st.accept_dm_request());
        let [RunnerCommand::Accept { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one accept");
        };
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(token),
            reason: Refusal::StartedOverNotAcceptable,
        });
        st.on_dm_event(&roster(&[(peer, 3, ConversationState::Established)]));
        assert!(st.select_dm_item(&conversation(3)));
        let thread = st.dm_thread_view().expect("the conversation is selected");
        let statuses: Vec<_> = thread.rows.iter().map(|row| row.status).collect();
        assert_eq!(statuses, [Some(DmMessageStatus::Refused)]);
    }

    /// Our first contact crosses their request: the acceptance is refused and
    /// the conversation our first contact opened is listed and delivered. The
    /// reply was never written, so it stays not sent.
    #[test]
    fn a_crossing_first_contact_does_not_make_a_refused_reply_sent() {
        let mut st = GuiState::lobby_only();
        st.start_dm_with(pk(3));
        assert!(st.send_dm("hi cora"));
        let [RunnerCommand::FirstContact { token: first, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one first contact");
        };
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(7),
            from: pk(3),
        });
        assert!(st.select_dm_item(&request(3)));
        assert!(st.accept_dm_request());
        let [RunnerCommand::Accept { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one accept");
        };
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(token),
            reason: Refusal::AlreadyEstablished,
        });
        // The draft holding the first contact still on its way stays.
        assert!(st.select_dm_item(&DmItemKey::new(DmItemKind::Draft, &pk(3))));
        assert_eq!(
            thread_rows(&st)[0],
            ("hi cora".to_owned(), Some(DmMessageStatus::Pending))
        );
        let peer = label();
        st.on_dm_event(&roster(&[(peer, 3, ConversationState::Pending)]));
        st.on_dm_event(&RunnerEvent::Sent {
            token: first,
            peer,
            seq: 0,
        });
        st.on_dm_event(&RunnerEvent::Delivered {
            peer,
            through_seq: 0,
        });
        assert!(st.select_dm_item(&conversation(3)));
        assert_eq!(
            thread_rows(&st),
            [
                ("hi cora".to_owned(), Some(DmMessageStatus::Delivered)),
                (DM_ACCEPT_REPLY.to_owned(), Some(DmMessageStatus::Refused)),
            ]
        );
    }

    /// Messaging stops while an acceptance is on its way, leaving one item for
    /// that person; a first message from it then opens the conversation, and
    /// the reply that never went stays not sent.
    #[test]
    fn a_first_contact_after_a_stopped_acceptance_leaves_the_reply_not_sent() {
        let (mut st, _) = accepted_request();
        st.on_dm_stopped();
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1, "listed twice: {rows:?}");
        assert_eq!(rows[0].key.peer, pk(3));

        assert!(st.send_dm("trying again"));
        let [RunnerCommand::FirstContact { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one first contact");
        };
        let peer = label();
        st.on_dm_event(&roster(&[(peer, 3, ConversationState::Pending)]));
        st.on_dm_event(&RunnerEvent::Sent {
            token,
            peer,
            seq: 0,
        });
        st.on_dm_event(&RunnerEvent::Delivered {
            peer,
            through_seq: 0,
        });
        assert_eq!(
            thread_rows(&st),
            [
                (DM_ACCEPT_REPLY.to_owned(), Some(DmMessageStatus::Refused)),
                ("trying again".to_owned(), Some(DmMessageStatus::Delivered)),
            ]
        );
    }

    /// A roster that lists the conversation while the acceptance is still
    /// unanswered does not make its reply sent: only the runner's answer does.
    #[test]
    fn a_listed_conversation_leaves_an_unanswered_reply_sending() {
        let (mut st, _) = accepted_request();
        st.on_dm_event(&roster(&[(label(), 3, ConversationState::Pending)]));
        assert_eq!(
            thread_rows(&st),
            [(DM_ACCEPT_REPLY.to_owned(), Some(DmMessageStatus::Pending))]
        );
    }

    /// Messaging stopping with an acceptance on its way counts its reply among
    /// the messages not sent.
    #[test]
    fn a_stop_counts_an_acceptance_in_flight() {
        let (mut st, _) = accepted_request();
        st.on_dm_stopped();
        assert_eq!(st.dm_notice(), Some(DmNotice::NotSent { count: 1 }));
        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert_eq!(thread.rows[0].status, Some(DmMessageStatus::Refused));
    }

    /// A refused acceptance leaves the request as the one item for that
    /// person, its thread showing the reply not sent with the reason, and a
    /// second acceptance replaces that row rather than adding one.
    #[test]
    fn a_refused_acceptance_shows_the_reply_not_sent() {
        let (mut st, token) = accepted_request();
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(token),
            reason: Refusal::Network,
        });
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1, "listed twice: {rows:?}");
        assert_eq!(rows[0].key, request(3));
        assert!(rows[0].selected);
        let thread = st.dm_thread_view().expect("the request is selected");
        assert!(thread.is_request && !thread.can_send);
        assert_eq!(thread.rows.len(), 1);
        assert_eq!(thread.rows[0].body, DM_ACCEPT_REPLY);
        assert_eq!(thread.rows[0].status, Some(DmMessageStatus::Refused));
        assert_eq!(thread.refusal, Some(Refusal::Network));

        assert!(st.accept_dm_request());
        assert_eq!(st.dm_rail_rows(now_unix_ms()).len(), 1);
        let thread = st.dm_thread_view().expect("the conversation is selected");
        assert!(!thread.is_request);
        let statuses: Vec<_> = thread.rows.iter().map(|row| row.status).collect();
        assert_eq!(statuses, [Some(DmMessageStatus::Pending)]);
    }

    /// Blocking sends one Block for the requester and removes the request.
    #[test]
    fn blocking_a_request_sends_one_block() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(8),
        });
        st.select_dm_item(&request(8));
        assert!(st.block_dm_request());
        match st.take_pending_dm().as_slice() {
            [RunnerCommand::Block { peer }] => assert_eq!(peer, &pk(8)),
            other => panic!("expected one block, got {other:?}"),
        }
        // Listed as blocking until the runner's block list names the sender.
        let rows = st.dm_rail_rows(0);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].blocking);
        assert!(st.dm_thread_view().is_some_and(|t| t.blocking));
        assert!(!st.block_dm_request(), "a second block was queued");
        assert!(
            !st.accept_dm_request(),
            "a request being blocked was accepted"
        );
        assert!(st.take_pending_dm().is_empty());

        st.on_dm_event(&RunnerEvent::BlockList(vec![pk(8)]));
        assert!(st.dm_rail_rows(0).is_empty());
        assert_eq!(st.main_pane(), MainPane::DmPlaceholder);
    }

    /// Declining queues nothing and hides the request, and a repeat from the
    /// same identity stays hidden for the session.
    #[test]
    fn declining_a_request_sends_nothing_and_hides_it() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(8),
        });
        assert_eq!(
            st.dm_rail_rows(0).len(),
            1,
            "control: the request is listed"
        );
        st.select_dm_item(&request(8));
        assert!(st.decline_dm_request());
        assert!(st.take_pending_dm().is_empty(), "declining sent a command");
        assert!(st.dm_rail_rows(0).is_empty());
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(2),
            from: pk(8),
        });
        assert!(
            st.dm_rail_rows(0).is_empty(),
            "the declined sender came back"
        );
    }

    /// A message on a conversation sends one Send under its label.
    #[test]
    fn sending_on_a_conversation_sends_one_send() {
        let (mut st, peer) = with_conversation(2);
        assert!(!st.send_dm("nothing selected"));
        st.select_dm_item(&conversation(2));
        assert!(!st.send_dm("   "), "a blank message was sent");
        assert!(st.send_dm("how are you"));
        match st.take_pending_dm().as_slice() {
            [RunnerCommand::Send { peer: to, body, .. }] => {
                assert_eq!(*to, peer);
                assert_eq!(body, b"how are you");
            }
            other => panic!("expected one send, got {other:?}"),
        }
        let thread = st.dm_thread_view().expect("selected");
        assert_eq!(
            thread.rows.last().map(|r| r.status),
            Some(Some(DmMessageStatus::Pending))
        );
    }

    /// Every runner event folds, and a start-over still reaches the
    /// trust log.
    #[test]
    fn every_runner_event_folds_and_a_start_over_is_logged() {
        let (mut st, peer) = with_conversation(1);
        let events = vec![
            roster(&[(peer, 1, ConversationState::Pending)]),
            RunnerEvent::ContactRequest {
                request: request_id(1),
                from: pk(2),
            },
            RunnerEvent::StartedOver {
                request: request_id(2),
                from: pk(1),
            },
            RunnerEvent::Message {
                from: peer,
                seq: 0,
                body: b"hi".to_vec(),
                sent_at: 1,
                received_at: 1,
            },
            RunnerEvent::Sent {
                token: CommandToken(99),
                peer,
                seq: 0,
            },
            RunnerEvent::Delivered {
                peer,
                through_seq: 0,
            },
            RunnerEvent::Accepted { peer },
            RunnerEvent::Refused {
                token: None,
                reason: Refusal::Store,
            },
            RunnerEvent::BlockListUnreadable,
            RunnerEvent::BlockList(vec![pk(9)]),
            RunnerEvent::Health(HealthCounters::default()),
            RunnerEvent::Deleted {
                token: CommandToken(98),
                peer,
            },
        ];
        for event in &events {
            st.on_dm_event(event);
        }
        assert_eq!(events.len(), 12, "a runner event variant is missing");
        let logged = st
            .trust_log()
            .entries()
            .iter()
            .filter(|e| {
                e.key == daemonseed_core::trust_events::TrustEventKey::DmCorrespondentStateLost
            })
            .count();
        assert_eq!(logged, 1, "the start-over was not logged once");
        assert!(
            st.dm_state().correspondences.is_empty(),
            "the delete did not fold"
        );
        st.on_dm_stopped();
        assert!(!st.dm_state().running);
    }

    /// A rail row carries no message body, even for a conversation
    /// holding messages both ways; the selected thread does.
    #[test]
    fn rail_rows_never_carry_a_message_body() {
        let (mut st, peer) = with_conversation(3);
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"incoming secret words".to_vec(),
            sent_at: 1,
            received_at: 1,
        });
        st.select_dm_item(&conversation(3));
        assert!(st.send_dm("outgoing secret words"));
        let rows = st.dm_rail_rows(now_unix_ms());
        assert_eq!(rows.len(), 1);
        let drawn = format!("{rows:?}");
        assert!(
            !drawn.contains("secret"),
            "a rail row carries a body: {drawn}"
        );
        let thread = st.dm_thread_view().expect("selected");
        let bodies: Vec<&str> = thread.rows.iter().map(|r| r.body.as_str()).collect();
        assert_eq!(bodies, ["incoming secret words", "outgoing secret words"]);
    }

    /// Opening Direct messages by its header shows the placeholder until an
    /// item is chosen.
    #[test]
    fn opening_direct_messages_waits_for_a_choice() {
        let (mut st, _) = with_conversation(1);
        assert_eq!(st.main_pane(), MainPane::Chat);
        st.open_rail_section(RailSection::DirectMessages, String::new(), 0.0);
        assert!(st.rail_section_open(RailSection::DirectMessages));
        assert!(!st.rail_section_open(RailSection::Chats));
        assert_eq!(st.main_pane(), MainPane::DmPlaceholder);
        assert!(st.dm_thread_view().is_none());
        st.select_dm_item(&conversation(1));
        assert_eq!(st.main_pane(), MainPane::DmThread);
    }

    /// Collapsing the section that owns the main pane shows its placeholder;
    /// collapsing the other does not.
    #[test]
    fn collapsing_the_owning_section_shows_its_placeholder() {
        let (mut st, _) = with_conversation(1);
        st.toggle_rail_section(RailSection::Chats);
        assert_eq!(st.main_pane(), MainPane::ChatPlaceholder);
        assert!(!st.rail_section_open(RailSection::Chats));
        assert!(!st.rail_section_open(RailSection::DirectMessages));
        st.toggle_rail_section(RailSection::Chats);
        assert_eq!(
            st.main_pane(),
            MainPane::Chat,
            "unfolding Chats shows the room"
        );

        st.select_dm_item(&conversation(1));
        assert_eq!(st.main_pane(), MainPane::DmThread);
        st.toggle_rail_section(RailSection::DirectMessages);
        assert_eq!(st.main_pane(), MainPane::DmPlaceholder);
    }

    /// A chevron folds or unfolds its own section only, and never changes which
    /// section owns the main pane: both can be unfolded at once.
    #[test]
    fn a_chevron_changes_only_its_own_section() {
        let (mut st, _) = with_conversation(1);
        st.toggle_rail_section(RailSection::DirectMessages);
        assert!(st.rail_section_open(RailSection::Chats));
        assert!(st.rail_section_open(RailSection::DirectMessages));
        assert_eq!(st.main_pane(), MainPane::Chat);

        st.select_dm_item(&conversation(1));
        st.toggle_rail_section(RailSection::Chats);
        assert!(!st.rail_section_open(RailSection::Chats));
        assert_eq!(st.main_pane(), MainPane::DmThread);
        st.toggle_rail_section(RailSection::Chats);
        assert!(st.rail_section_open(RailSection::Chats));
        assert!(st.rail_section_open(RailSection::DirectMessages));
        assert_eq!(st.main_pane(), MainPane::DmThread);
    }

    /// Folding Direct messages while its thread is shown forgets the choice:
    /// unfolding it again shows "Choose a conversation", not the old thread.
    #[test]
    fn unfolding_direct_messages_does_not_reveal_the_last_thread() {
        let (mut st, _) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        assert_eq!(
            st.main_pane(),
            MainPane::DmThread,
            "control: the thread shows"
        );
        st.toggle_rail_section(RailSection::DirectMessages);
        st.toggle_rail_section(RailSection::DirectMessages);
        assert_eq!(st.main_pane(), MainPane::DmPlaceholder);
        assert!(st.dm_thread_view().is_none());
    }

    /// Opening Chats by its header selects the Lobby and shows the chat.
    #[test]
    fn opening_chats_selects_the_lobby() {
        let mut st = GuiState::demo();
        assert_ne!(st.active(), 0, "the fixture starts off the Lobby");
        st.open_rail_section(RailSection::DirectMessages, String::new(), 0.0);
        st.open_rail_section(RailSection::Chats, String::new(), 0.0);
        assert_eq!(st.active(), 0);
        assert_eq!(st.main_pane(), MainPane::Chat);
        assert!(!st.rail_section_open(RailSection::DirectMessages));
    }

    /// Unread is set on arrival in an item not being viewed and cleared by
    /// viewing it; a message into the viewed thread is never unread.
    #[test]
    fn unread_is_set_on_arrival_and_cleared_on_view() {
        let (mut st, peer) = with_conversation(1);
        let message = |seq| RunnerEvent::Message {
            from: peer,
            seq,
            body: b"x".to_vec(),
            sent_at: 1,
            received_at: 1,
        };
        assert!(!st.rail_section_unread(RailSection::DirectMessages));
        st.on_dm_event(&message(0));
        assert!(st.dm_rail_rows(0)[0].unread);
        assert!(st.rail_section_unread(RailSection::DirectMessages));
        st.select_dm_item(&conversation(1));
        assert!(!st.dm_rail_rows(0)[0].unread);
        assert!(!st.rail_section_unread(RailSection::DirectMessages));
        st.on_dm_event(&message(1));
        assert!(
            !st.dm_rail_rows(0)[0].unread,
            "the viewed thread went unread"
        );

        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(2),
        });
        assert!(st.dm_rail_rows(0)[0].unread, "a request arrived read");
        st.select_dm_item(&request(2));
        assert!(!st.rail_section_unread(RailSection::DirectMessages));
    }

    #[test]
    fn a_slot_resolves_back_to_its_item() {
        let (mut st, _) = with_conversation(1);
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(2),
        });
        for row in st.dm_rail_rows(0) {
            assert_eq!(st.dm_item_for_slot(&row.slot), Some(row.key));
        }
        assert_eq!(st.dm_item_for_slot("c999"), None);
        assert_eq!(st.dm_item_for_slot("x1"), None);
    }

    #[test]
    fn ages_read_in_whole_units() {
        let now = 10 * 86_400_000;
        assert_eq!(dm_age_text(now, now), "now");
        assert_eq!(dm_age_text(now + 5_000, now), "now");
        assert_eq!(dm_age_text(now - 125_000, now), "2m");
        assert_eq!(dm_age_text(now - 3_600_000, now), "1h");
        assert_eq!(dm_age_text(now - 3 * 86_400_000, now), "3d");
    }

    /// Past thirty days an age is the date it was sent, so a sender's clock
    /// near the epoch reads as a date rather than tens of thousands of days.
    #[test]
    fn an_age_past_thirty_days_is_a_date() {
        let now: i64 = 1_789_000_000_000; // 2026-09-10 UTC
        assert_eq!(dm_age_text(now - 30 * 86_400_000, now), "30d");
        assert_eq!(dm_age_text(now - 31 * 86_400_000, now), "2026-08-10");
        assert_eq!(dm_age_text(1_000, now), "1970-01-01");
        assert_eq!(dm_age_text(0, now), "1970-01-01");
    }

    /// A message this side sent that this session did not compose has no known
    /// time, so it carries no age, while a received one does.
    #[test]
    fn a_sent_message_not_composed_here_has_no_age() {
        let (mut st, peer) = with_conversation(4);
        st.select_dm_item(&conversation(4));
        st.on_dm_event(&RunnerEvent::Sent {
            token: CommandToken(999),
            peer,
            seq: 0,
        });
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"hello".to_vec(),
            sent_at: 1_000,
            received_at: 2_000,
        });
        let thread = st.dm_thread_view().expect("the conversation is selected");
        let times: Vec<(bool, Option<i64>)> =
            thread.rows.iter().map(|r| (r.outgoing, r.at_ms)).collect();
        assert_eq!(times, [(true, None), (false, Some(1_000))]);
    }

    /// The token and body of the one command `st` queued.
    fn only_token(st: &mut GuiState) -> CommandToken {
        match st.take_pending_dm().as_slice() {
            [RunnerCommand::Send { token, .. } | RunnerCommand::FirstContact { token, .. }] => {
                *token
            }
            other => panic!("expected one message command, got {other:?}"),
        }
    }

    /// The status of each row of the selected thread, with its body.
    fn thread_rows(st: &GuiState) -> Vec<(String, Option<DmMessageStatus>)> {
        st.dm_thread_view()
            .expect("a thread is selected")
            .rows
            .into_iter()
            .map(|r| (r.body, r.status))
            .collect()
    }

    /// Each refused message keeps its own row, a later sent message
    /// does not erase it, and a stop marks every unanswered one not sent and
    /// says how many.
    #[test]
    fn refused_messages_keep_their_rows_and_a_stop_counts_the_rest() {
        let (mut st, peer) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        assert!(st.send_dm("first"));
        let first = only_token(&mut st);
        assert!(st.send_dm("second"));
        let second = only_token(&mut st);
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(first),
            reason: Refusal::RingFull,
        });
        st.on_dm_event(&RunnerEvent::Sent {
            token: second,
            peer,
            seq: 0,
        });
        assert_eq!(
            thread_rows(&st),
            [
                ("first".to_owned(), Some(DmMessageStatus::Refused)),
                ("second".to_owned(), Some(DmMessageStatus::Sent)),
            ]
        );
        assert_eq!(
            st.dm_thread_view().and_then(|t| t.refusal),
            Some(Refusal::RingFull)
        );

        assert!(st.send_dm("third"));
        assert!(st.send_dm("fourth"));
        st.take_pending_dm();
        st.on_dm_stopped();
        let statuses: Vec<_> = thread_rows(&st).into_iter().map(|(_, s)| s).collect();
        assert_eq!(
            statuses,
            [
                Some(DmMessageStatus::Refused),
                Some(DmMessageStatus::Sent),
                Some(DmMessageStatus::Refused),
                Some(DmMessageStatus::Refused),
            ]
        );
        assert_eq!(st.dm_notice(), Some(DmNotice::NotSent { count: 2 }));
    }

    /// A refused block lists the request again and says why, and only
    /// the oldest block in flight is the one refused.
    #[test]
    fn a_refused_block_is_said_and_answers_the_oldest_block() {
        let mut st = GuiState::lobby_only();
        for (serial, tag) in [(1, 8), (2, 9)] {
            st.on_dm_event(&RunnerEvent::ContactRequest {
                request: request_id(serial),
                from: pk(tag),
            });
            st.select_dm_item(&request(tag));
            assert!(st.block_dm_request());
        }
        st.take_pending_dm();
        st.on_dm_event(&RunnerEvent::Refused {
            token: None,
            reason: Refusal::BlockListFull,
        });
        let rows = st.dm_rail_rows(0);
        let blocking: Vec<bool> = rows.iter().map(|r| r.blocking).collect();
        assert_eq!(
            blocking,
            [false, true],
            "the refusal answered the wrong block"
        );
        assert_eq!(
            st.dm_notice(),
            Some(DmNotice::BlockRefused(Refusal::BlockListFull))
        );
        st.select_dm_item(&request(8));
        let thread = st.dm_thread_view().expect("selected");
        assert!(!thread.blocking);
        assert_eq!(thread.refusal, Some(Refusal::BlockListFull));
    }

    /// A message into a conversation whose thread is selected but not
    /// on screen, because a room owns the main pane, is unread.
    #[test]
    fn a_selected_thread_behind_the_chat_is_not_viewed() {
        let (mut st, peer) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        st.switch_to(0, String::new(), 0.0);
        assert!(st.rail_section_open(RailSection::DirectMessages));
        assert_eq!(st.main_pane(), MainPane::Chat);
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"x".to_vec(),
            sent_at: 1,
            received_at: 1,
        });
        assert!(
            st.dm_rail_rows(0)[0].unread,
            "a message behind the chat read as seen"
        );
    }

    /// A first contact refused after the runner held it is one row.
    #[test]
    fn a_first_contact_refused_partway_is_one_row() {
        let mut st = GuiState::lobby_only();
        st.start_dm_with(pk(4));
        assert!(st.send_dm("hello"));
        let token = only_token(&mut st);
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(token),
            reason: Refusal::DropFull,
        });
        st.on_dm_event(&roster(&[(label(), 4, ConversationState::Pending)]));
        assert_eq!(
            thread_rows(&st),
            [("hello".to_owned(), Some(DmMessageStatus::Refused))]
        );
    }

    /// A first message to someone whose request is waiting drops the
    /// draft, opens the request and says why; nothing is sent.
    #[test]
    fn a_draft_meeting_a_request_opens_the_request_and_says_why() {
        let mut st = GuiState::lobby_only();
        st.start_dm_with(pk(5));
        st.on_dm_event(&RunnerEvent::ContactRequest {
            request: request_id(1),
            from: pk(5),
        });
        assert!(!st.send_dm("hi"));
        assert!(st.take_pending_dm().is_empty());
        let kinds: Vec<DmItemKind> = st.dm_rail_rows(0).iter().map(|r| r.key.kind).collect();
        assert_eq!(kinds, [DmItemKind::Request], "the draft lingered");
        assert_eq!(st.dm_thread_view().map(|t| t.key), Some(request(5)));
        assert_eq!(st.dm_notice(), Some(DmNotice::MovedToRequest));
    }

    /// Messages composed here keep the order they were composed in,
    /// among the messages received, whatever the runner answers.
    #[test]
    fn composed_messages_keep_their_order() {
        let (mut st, peer) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        assert!(st.send_dm("a"));
        let a = only_token(&mut st);
        st.on_dm_event(&RunnerEvent::Message {
            from: peer,
            seq: 0,
            body: b"b".to_vec(),
            sent_at: 1,
            received_at: 1,
        });
        assert!(st.send_dm("c"));
        let c = only_token(&mut st);
        st.on_dm_event(&RunnerEvent::Sent {
            token: c,
            peer,
            seq: 0,
        });
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(a),
            reason: Refusal::Network,
        });
        let bodies: Vec<String> = thread_rows(&st).into_iter().map(|(b, _)| b).collect();
        assert_eq!(bodies, ["a", "b", "c"]);
    }

    /// An unreadable block list is a notice while it lasts.
    #[test]
    fn an_unreadable_block_list_is_a_notice_while_it_lasts() {
        let mut st = GuiState::lobby_only();
        assert_eq!(st.dm_notice(), None);
        st.on_dm_event(&RunnerEvent::BlockListUnreadable);
        assert_eq!(st.dm_notice(), Some(DmNotice::BlockListUnreadable));
        st.on_dm_event(&RunnerEvent::BlockList(Vec::new()));
        assert_eq!(st.dm_notice(), None);
    }

    /// A draft to a blocked person cannot send, and says so.
    #[test]
    fn a_draft_to_a_blocked_person_cannot_send() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&RunnerEvent::BlockList(vec![pk(6)]));
        st.start_dm_with(pk(6));
        let thread = st.dm_thread_view().expect("the draft is selected");
        assert!(thread.blocked && !thread.can_send);
        assert!(!st.send_dm("hello"));
        assert!(st.take_pending_dm().is_empty());
    }

    /// A message into the active room while a direct message owns
    /// the main pane raises the room's dot; showing the chat again clears it.
    #[test]
    fn the_active_room_is_unread_while_a_thread_is_shown() {
        let (mut st, _) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        let out = st.push_message(0, "anna".into(), "hi".into(), false, now_unix_ms());
        assert!(out.unread_raised);
        assert!(st.rail_section_unread(RailSection::Chats));
        st.open_rail_section(RailSection::Chats, String::new(), 0.0);
        assert!(!st.rail_section_unread(RailSection::Chats));

        let out = st.push_message(0, "anna".into(), "again".into(), false, now_unix_ms() + 1);
        assert!(
            !out.unread_raised,
            "control: a message into the shown room is seen"
        );
    }

    /// A message is sent only from the thread on screen.
    #[test]
    fn a_message_is_sent_only_from_the_thread_on_screen() {
        let (mut st, _) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        st.switch_to(0, String::new(), 0.0);
        assert!(!st.send_dm("typed into the room"));
        assert!(st.take_pending_dm().is_empty());
        st.select_dm_item(&conversation(1));
        assert!(
            st.send_dm("typed into the thread"),
            "control: the shown thread sends"
        );
    }

    /// A thread's debug output carries no message body.
    #[test]
    fn a_thread_prints_no_body() {
        let (mut st, _) = with_conversation(1);
        st.select_dm_item(&conversation(1));
        assert!(st.send_dm("private words"));
        let thread = st.dm_thread_view().expect("selected");
        assert_eq!(
            thread.rows[0].body, "private words",
            "control: the body is held"
        );
        let printed = format!("{thread:?}");
        assert!(!printed.contains("private"), "{printed}");
    }
}
