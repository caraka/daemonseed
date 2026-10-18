//! The rail's two sections and the direct-message surfaces, as the window draws
//! them: the Slint models built from [`GuiState`]'s view models, the callbacks
//! that drive its direct-message actions, and the push that follows every
//! change.
//!
//! Every callback here calls one [`GuiState`] method and pushes the result back
//! with [`apply_dm`]. None waits on the runner: an action queues its commands,
//! and the drain timer forwards them on its next tick.

use std::cell::RefCell;
use std::rc::Rc;

use daemonseed_core::handle::strip_handle_hash;
use daemonseed_veilid_net::dm::runner::{IdentityPk, Refusal, RunnerCommand, RunnerEvent};
use daemonseed_veilid_net::dm::unavailable::DmUnavailableCause;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::state::GuiState;
use crate::state::dm::{
    DmMessageRow, DmMessageStatus, DmNotice, DmRailRow, DmThreadView, MainPane, RailSection,
    dm_age_text,
};
use crate::{AppWindow, DmMessageData, DmRailRowData, defer, now_unix_ms, refresh_active_room};

/// The Slint code for `section`: 0 Chats, 1 Direct messages.
fn section_from_code(code: i32) -> RailSection {
    if code == 1 {
        RailSection::DirectMessages
    } else {
        RailSection::Chats
    }
}

/// The Slint `main-pane` code for `pane`.
fn main_pane_code(pane: MainPane) -> i32 {
    match pane {
        MainPane::Chat => 0,
        MainPane::ChatPlaceholder => 1,
        MainPane::DmPlaceholder => 2,
        MainPane::DmThread => 3,
    }
}

/// How an outgoing message's status reads under it.
fn status_text(status: DmMessageStatus) -> &'static str {
    match status {
        DmMessageStatus::Pending => "sending…",
        DmMessageStatus::Sent => "sent",
        DmMessageStatus::Delivered => "delivered",
        DmMessageStatus::Refused => "not sent",
    }
}

/// Why a message or an acceptance did not go, in the words the thread shows.
pub fn refusal_text(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::UnknownConversation => "This conversation no longer exists.",
        Refusal::UnknownRequest => "This request is no longer available.",
        Refusal::StartedOverNotAcceptable => {
            "They started over, so this request can't be accepted."
        }
        Refusal::RingFull => "They have too many unread messages. Send again once they catch up.",
        Refusal::AwaitingAcceptance => "They haven't accepted your first message yet.",
        Refusal::AcceptanceUnfinished => {
            "Your acceptance is still going through. Try again shortly."
        }
        Refusal::AlreadyEstablished => "You already have a conversation with them.",
        Refusal::NoAdvert => "They can't be reached for direct messages.",
        Refusal::DropFull => "They couldn't be reached yet. It will be tried again.",
        Refusal::BlockListFull => "Your block list is full.",
        Refusal::Store => "This device couldn't save it.",
        Refusal::Network => "The network didn't take it. Try again.",
        Refusal::Flow => "It couldn't be sent.",
        Refusal::ShuttingDown => "Messaging stopped before it went.",
        Refusal::TooLong => "That message is too long to send.",
    }
}

/// What the line under the Direct messages header says while messaging is
/// unavailable for `cause`.
pub fn unavailable_text(cause: DmUnavailableCause) -> &'static str {
    match cause {
        DmUnavailableCause::NotConnected => "Direct messages will start once you're connected.",
        DmUnavailableCause::StoreUnopened => {
            "Direct messages couldn't start because your saved conversations couldn't be opened."
        }
        DmUnavailableCause::RunnerFailed => {
            "Direct messages stopped because of an error. Restart the app to try again."
        }
        DmUnavailableCause::Internal => {
            "Direct messages stopped because of an internal error. Restart the app to try again."
        }
    }
}

/// What the line under the Direct messages header says.
pub fn notice_text(notice: DmNotice) -> String {
    match notice {
        DmNotice::Unavailable(cause) => unavailable_text(cause).to_owned(),
        DmNotice::NotReachable => "Others can't reach you for direct messages yet.".to_owned(),
        DmNotice::BlockListUnreadable => {
            "Your block list can't be read, so requests and messages are paused.".to_owned()
        }
        DmNotice::NotSent { count: 1 } => "Messaging stopped. 1 message was not sent.".to_owned(),
        DmNotice::NotSent { count } => {
            format!("Messaging stopped. {count} messages were not sent.")
        }
        DmNotice::BlockRefused(reason) => {
            format!("The block didn't take effect. {}", refusal_text(reason))
        }
        DmNotice::MovedToConversation => {
            "You already have a conversation with them. Your message is still in the reply box."
                .to_owned()
        }
        DmNotice::MovedToRequest => {
            "They sent you a request first. Accept it to reply; your message is still in the reply box."
                .to_owned()
        }
    }
}

/// The line under the thread of a first contact this side sent, until the
/// correspondent accepts it.
const REQUEST_SENT_NOTE: &str =
    "Request sent. It may take a couple of minutes to reach them, or until they next come online.";

/// The line under the thread: why nothing can be sent to a blocked person, or
/// why the last message, acceptance or block did not go, or, failing both,
/// that this side's first contact awaits acceptance.
fn thread_note(thread: &DmThreadView) -> &'static str {
    if thread.blocked {
        "You blocked them, so you can't send them messages."
    } else if let Some(refusal) = thread.refusal {
        refusal_text(refusal)
    } else if thread.awaiting_acceptance {
        REQUEST_SENT_NOTE
    } else {
        ""
    }
}

/// A correspondent's label as the rail and the thread header show it: the name
/// alone, like the roster, with the fingerprint shown beside it in the header.
fn display_label(label: &str) -> SharedString {
    SharedString::from(strip_handle_hash(label))
}

/// The Direct messages rail model. Built from [`DmRailRow`]s, which hold no
/// message body, and carrying only their label, age and flags.
fn dm_rows_model(rows: &[DmRailRow]) -> ModelRc<DmRailRowData> {
    let rows: Vec<DmRailRowData> = rows
        .iter()
        .map(|row| DmRailRowData {
            slot: SharedString::from(row.slot.as_str()),
            label: display_label(&row.label),
            age: SharedString::from(if row.blocking {
                "blocking…"
            } else {
                row.age.as_str()
            }),
            unread: row.unread,
            selected: row.selected,
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

/// The selected thread's message model, each age read against `now_ms`.
fn dm_messages_model(rows: &[DmMessageRow], now_ms: i64) -> ModelRc<DmMessageData> {
    let rows: Vec<DmMessageData> = rows
        .iter()
        .map(|row| DmMessageData {
            outgoing: row.outgoing,
            body: SharedString::from(row.body.as_str()),
            status: SharedString::from(row.status.map_or("", status_text)),
            refused: row.status == Some(DmMessageStatus::Refused),
            caption: SharedString::from(message_caption(row, now_ms)),
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

/// The line under a message at `now_ms`: its age, then its status, joined by
/// " · ", either left out when there is none. A message whose time is not
/// known here has no age.
fn message_caption(row: &DmMessageRow, now_ms: i64) -> String {
    let age = row.at_ms.map(|at| dm_age_text(at, now_ms));
    let status = row.status.map(status_text);
    match (age, status) {
        (Some(age), Some(status)) => format!("{age} · {status}"),
        (Some(age), None) => age,
        (None, Some(status)) => status.to_owned(),
        (None, None) => String::new(),
    }
}

/// Push the section flags, the main pane mode and the Direct messages notice.
///
/// The circle details sheet belongs to the chat: when the main pane shows
/// anything else it closes and a revealed join phrase is hidden.
pub fn apply_rail_sections(ui: &AppWindow, st: &GuiState) {
    if st.main_pane() != MainPane::Chat && ui.get_sheet_open() {
        ui.set_sheet_open(false);
        ui.invoke_hide_phrase();
    }
    ui.set_dm_notice(SharedString::from(
        st.dm_notice().map(notice_text).unwrap_or_default(),
    ));
    ui.set_dm_notice_detail(SharedString::from(
        st.dm_notice_detail().unwrap_or_default(),
    ));
    ui.set_chats_open(st.rail_section_open(RailSection::Chats));
    ui.set_dms_open(st.rail_section_open(RailSection::DirectMessages));
    ui.set_chats_unread(st.rail_section_unread(RailSection::Chats));
    ui.set_dms_unread(st.rail_section_unread(RailSection::DirectMessages));
    ui.set_main_pane(main_pane_code(st.main_pane()));
}

/// Push the Direct messages rail rows, whose ages are read against now.
pub fn apply_dm_rows(ui: &AppWindow, st: &GuiState) {
    ui.set_dm_rows(dm_rows_model(&st.dm_rail_rows(now_unix_ms())));
}

/// Read every age direct messaging shows again at `now_ms`, with no event: the
/// rail rows, and the captions of the open thread's messages. The thread's
/// rows are updated in place where a caption changed, so its scroll stays.
pub fn refresh_dm_ages(ui: &AppWindow, st: &GuiState, now_ms: i64) {
    ui.set_dm_rows(dm_rows_model(&st.dm_rail_rows(now_ms)));
    let Some(thread) = st.dm_thread_view() else {
        return;
    };
    let shown = ui.get_dm_messages();
    if shown.row_count() != thread.rows.len() {
        ui.set_dm_messages(dm_messages_model(&thread.rows, now_ms));
        return;
    }
    for (i, row) in thread.rows.iter().enumerate() {
        let caption = SharedString::from(message_caption(row, now_ms));
        if let Some(mut data) = shown.row_data(i)
            && data.caption != caption
        {
            data.caption = caption;
            shown.set_row_data(i, data);
        }
    }
}

/// Push everything direct messaging shows: the sections, the main pane, the
/// rail rows and the selected thread.
pub fn apply_dm(ui: &AppWindow, st: &GuiState) {
    apply_rail_sections(ui, st);
    apply_dm_rows(ui, st);
    match st.dm_thread_view() {
        Some(thread) => {
            ui.set_dm_header_label(display_label(&thread.header_label));
            ui.set_dm_fingerprint(SharedString::from(thread.fingerprint.as_str()));
            ui.set_dm_is_request(thread.is_request);
            ui.set_dm_messages(dm_messages_model(&thread.rows, now_unix_ms()));
            ui.set_dm_can_send(thread.can_send);
            ui.set_dm_refusal(SharedString::from(thread_note(&thread)));
            ui.set_dm_blocking(thread.blocking);
        }
        None => {
            ui.set_dm_header_label(SharedString::new());
            ui.set_dm_fingerprint(SharedString::new());
            ui.set_dm_is_request(false);
            ui.set_dm_messages(dm_messages_model(&[], now_unix_ms()));
            ui.set_dm_can_send(false);
            ui.set_dm_refusal(SharedString::new());
            ui.set_dm_blocking(false);
        }
    }
}

/// Hand the commands the direct-message actions queued to the network thread,
/// oldest first, through `send`, which returns a command it could not hand
/// over.
///
/// A command bounced because the network thread is gone is answered
/// the way the runner answers one it stopped before serving, so its message
/// shows as not sent and a block as not taken effect.
pub fn forward_pending_dm(
    ui: &AppWindow,
    state: &Rc<RefCell<GuiState>>,
    send: impl Fn(RunnerCommand) -> Option<RunnerCommand>,
) {
    let pending = state.borrow_mut().take_pending_dm();
    let mut refused = false;
    for cmd in pending {
        if let Some(cmd) = send(cmd)
            && !matches!(cmd, RunnerCommand::Shutdown)
        {
            state.borrow_mut().on_dm_event(&RunnerEvent::Refused {
                token: crate::veilid_net::dm_command_token(&cmd),
                reason: Refusal::ShuttingDown,
            });
            refused = true;
        }
    }
    if refused {
        apply_dm(ui, &state.borrow());
    }
}

/// The network thread is gone, and the runner with it: every message it had
/// not answered shows as not sent, and the Direct messages area says how many.
pub fn on_net_gone(ui: &AppWindow, state: &Rc<RefCell<GuiState>>) {
    let mut st = state.borrow_mut();
    st.on_dm_stopped();
    apply_dm(ui, &st);
}

/// Move keyboard focus to the thread's reply box once the window has drawn it.
fn focus_dm_composer_later(ui: &AppWindow) {
    let w = ui.as_weak();
    defer(move || {
        if let Some(ui) = w.upgrade() {
            ui.invoke_focus_dm_composer();
        }
    });
}

/// Keep the room composer's live text and scroll in the active room before the
/// main pane may stop showing it, so reopening the room by its header restores
/// them.
fn keep_live_chat(ui: &AppWindow, st: &mut GuiState) {
    if st.main_pane() == MainPane::Chat {
        let active = st.active();
        st.set_draft(active, ui.get_draft().to_string());
        st.set_scroll(active, ui.get_scroll_y());
    }
}

/// The correspondent of the selected thread, if any.
fn selected_peer(st: &GuiState) -> Option<IdentityPk> {
    st.dm_thread_view().map(|thread| thread.key.peer)
}

/// Clear the reply box when the thread shown is now a different person's.
fn clear_draft_on_peer_change(ui: &AppWindow, before: Option<IdentityPk>, st: &GuiState) {
    if selected_peer(st) != before {
        ui.set_dm_draft(SharedString::new());
    }
}

/// The member a roster right-click was on, read when its menu opened.
#[derive(Default)]
pub struct RosterMenu {
    member: Option<IdentityPk>,
}

impl RosterMenu {
    /// The menu opened on roster row `row`: read that member's key now.
    pub fn opened(&mut self, st: &GuiState, row: usize) {
        self.member = st.active_roster_key(row);
    }

    /// The member the open menu was for, taken so a second activation does
    /// nothing.
    pub fn take(&mut self) -> Option<IdentityPk> {
        self.member.take()
    }
}

/// Wire the rail-section, direct-message and roster-menu callbacks, and push
/// the starting state.
pub fn wire_dm(ui: &AppWindow, state: &Rc<RefCell<GuiState>>) {
    ui.on_toggle_section({
        let weak = ui.as_weak();
        let state = state.clone();
        move |code| {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            let was_chat = st.main_pane() == MainPane::Chat;
            keep_live_chat(&ui, &mut st);
            st.toggle_rail_section(section_from_code(code));
            let now_chat = st.main_pane() == MainPane::Chat;
            if now_chat && !was_chat {
                // Unfolding Chats brought the room back: its dot cleared, and its
                // composer takes the keys again.
                crate::rebuild_rail(&ui, &st);
            }
            apply_dm(&ui, &st);
            drop(st);
            if now_chat && !was_chat {
                let w = ui.as_weak();
                defer(move || {
                    if let Some(ui) = w.upgrade() {
                        ui.invoke_focus_composer();
                    }
                });
            }
        }
    });

    ui.on_open_section({
        let weak = ui.as_weak();
        let state = state.clone();
        move |code| {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            keep_live_chat(&ui, &mut st);
            match section_from_code(code) {
                RailSection::Chats => {
                    let live_draft = ui.get_draft().to_string();
                    let live_scroll = ui.get_scroll_y();
                    st.open_rail_section(RailSection::Chats, live_draft, live_scroll);
                    let refresh_public_shares = refresh_active_room(&ui, &st);
                    drop(st);
                    // Deferred for the same reason as a rail switch: this can be
                    // key-triggered, and focusing inside a key handler breaks the next
                    // key's routing.
                    let w = ui.as_weak();
                    defer(move || {
                        if let Some(ui) = w.upgrade() {
                            if refresh_public_shares {
                                ui.invoke_shares_tab_opened();
                            }
                            ui.invoke_focus_composer();
                        }
                    });
                }
                RailSection::DirectMessages => {
                    st.open_rail_section(RailSection::DirectMessages, String::new(), 0.0);
                    apply_dm(&ui, &st);
                }
            }
        }
    });

    ui.on_select_dm({
        let weak = ui.as_weak();
        let state = state.clone();
        move |slot| {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            let before = selected_peer(&st);
            if let Some(key) = st.dm_item_for_slot(&slot) {
                keep_live_chat(&ui, &mut st);
                st.select_dm_item(&key);
            }
            clear_draft_on_peer_change(&ui, before, &st);
            apply_dm(&ui, &st);
            focus_dm_composer_later(&ui);
        }
    });

    ui.on_send_dm({
        let weak = ui.as_weak();
        let state = state.clone();
        move |body| {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            // Text that was not sent stays in the reply box.
            if st.send_dm(&body) {
                ui.set_dm_draft(SharedString::new());
            }
            apply_dm(&ui, &st);
            focus_dm_composer_later(&ui);
        }
    });

    ui.on_accept_dm({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            st.accept_dm_request();
            apply_dm(&ui, &st);
        }
    });

    ui.on_decline_dm({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            st.decline_dm_request();
            apply_dm(&ui, &st);
        }
    });

    ui.on_block_dm({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            st.block_dm_request();
            apply_dm(&ui, &st);
        }
    });

    let menu = Rc::new(RefCell::new(RosterMenu::default()));
    ui.on_roster_menu_opened({
        let state = state.clone();
        let menu = menu.clone();
        move |row| {
            let row = usize::try_from(row).unwrap_or(usize::MAX);
            menu.borrow_mut().opened(&state.borrow(), row);
        }
    });

    ui.on_roster_start_dm({
        let weak = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(member) = menu.borrow_mut().take() else {
                return;
            };
            let ui = weak.unwrap();
            let mut st = state.borrow_mut();
            let before = selected_peer(&st);
            keep_live_chat(&ui, &mut st);
            st.start_dm_with(member);
            clear_draft_on_peer_change(&ui, before, &st);
            apply_dm(&ui, &st);
            focus_dm_composer_later(&ui);
        }
    });

    apply_dm(ui, &state.borrow());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::Arc;

    use daemonseed_core::dm::flows::ReceivedMessage;
    use daemonseed_core::identity::keys::IDENTITY_PK_LEN;
    use daemonseed_core::storage::dm_store::CorrespondenceLabel;
    use daemonseed_veilid_net::dm::runner::{
        ContactRequestId, ConversationState, ConversationSummary, RunnerCommand, RunnerEvent,
    };
    use slint::Model;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
    use slint::platform::{Key, WindowEvent};

    use daemonseed_veilid_net::dm::unavailable::DmUnavailable;

    use super::*;
    use crate::net::{NetEvent, RosterEntry};
    use crate::share_browser::ShareBrowser;
    use crate::{GuiPlatform, H, W, apply_net_event, build_ui, render_png};

    /// This moment in Unix milliseconds, as a runner reports a send committed
    /// at.
    fn test_now_ms() -> u64 {
        u64::try_from(now_unix_ms()).expect("a clock past the epoch")
    }

    /// The window as production builds it, on the offscreen software platform,
    /// with the state it was built over.
    struct App {
        ui: AppWindow,
        state: Rc<RefCell<GuiState>>,
        browser: Rc<RefCell<ShareBrowser>>,
        window: Rc<MinimalSoftwareWindow>,
        net: Rc<RefCell<crate::net::NetHandle>>,
    }

    impl App {
        /// Fold `event` the way the drain does.
        fn dm_event(&self, event: RunnerEvent) {
            apply_net_event(
                &self.ui,
                &self.state,
                &self.browser,
                NetEvent::Dm(Arc::new(event)),
            );
        }

        /// The slot of the rail row labelled `label`.
        fn slot_of(&self, label: &str) -> SharedString {
            let rows = self.ui.get_dm_rows();
            rows.iter()
                .find(|r| r.label == label)
                .unwrap_or_else(|| panic!("no rail row labelled {label}"))
                .slot
        }
    }

    /// Run `f` against a window built by [`build_ui`], on a thread of its own with
    /// a stack large enough to build the window. The platform is per thread, so
    /// that thread installs its own. A panic in `f` is raised again here.
    fn with_app(f: impl FnOnce(&App) + Send + 'static) {
        let joined = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
                let _ = slint::platform::set_platform(Box::new(GuiPlatform {
                    window: window.clone(),
                }));
                let (ui, state, net, browser) = build_ui(None);
                ui.show().expect("show");
                window.set_size(slint::PhysicalSize::new(W, H));
                f(&App {
                    ui,
                    state,
                    browser,
                    window,
                    net,
                });
            })
            .expect("spawn the window thread")
            .join();
        if let Err(panic) = joined {
            std::panic::resume_unwind(panic);
        }
    }

    fn pk(tag: u8) -> IdentityPk {
        Box::new([tag; IDENTITY_PK_LEN])
    }

    fn member(handle: &str, tag: u8) -> RosterEntry {
        RosterEntry {
            handle: handle.into(),
            fingerprint: format!("#{}", hex::encode([tag; 6])),
            pubkey: vec![tag; IDENTITY_PK_LEN],
        }
    }

    fn label() -> CorrespondenceLabel {
        CorrespondenceLabel::mint().expect("a label mints")
    }

    fn established(peer: CorrespondenceLabel, tag: u8) -> RunnerEvent {
        RunnerEvent::Roster(vec![ConversationSummary {
            peer,
            peer_identity_pk: pk(tag),
            state: ConversationState::Established,
            peer_collected: 0,
            uncollected: 0,
            handle: None,
        }])
    }

    /// A state whose first contact to `tag` the runner reported sent, under the
    /// returned label, with its thread selected.
    fn sent_first_contact(tag: u8) -> (GuiState, CorrespondenceLabel) {
        let mut st = GuiState::lobby_only();
        st.start_dm_with(pk(tag));
        assert!(st.send_dm("hello"));
        let [RunnerCommand::FirstContact { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one first contact");
        };
        let peer = label();
        st.on_dm_event(&RunnerEvent::Sent {
            token,
            peer,
            seq: 0,
            sent_at: test_now_ms(),
        });
        (st, peer)
    }

    /// A roster listing the conversation with `tag` under `peer` in `state`.
    fn listed(peer: CorrespondenceLabel, tag: u8, state: ConversationState) -> RunnerEvent {
        RunnerEvent::Roster(vec![ConversationSummary {
            peer,
            peer_identity_pk: pk(tag),
            state,
            peer_collected: 0,
            uncollected: 1,
            handle: None,
        }])
    }

    /// The line under the selected thread.
    fn note_of(st: &GuiState) -> &'static str {
        thread_note(&st.dm_thread_view().expect("the thread is selected"))
    }

    /// The line under a sent first contact's thread says the request is on its
    /// way while the roster lists it pending, and says nothing once it is
    /// established or while the conversation is an acceptance under way; a
    /// refusal shown there wins over it.
    #[test]
    fn a_sent_first_contact_notes_the_request_until_it_is_established() {
        let (mut st, peer) = sent_first_contact(4);
        st.on_dm_event(&listed(peer, 4, ConversationState::Pending));
        assert_eq!(note_of(&st), REQUEST_SENT_NOTE);
        st.on_dm_event(&listed(peer, 4, ConversationState::Established));
        assert_eq!(note_of(&st), "");

        let (mut st, peer) = sent_first_contact(5);
        st.on_dm_event(&listed(peer, 5, ConversationState::Accepting));
        assert_eq!(note_of(&st), "");

        let (mut st, peer) = sent_first_contact(6);
        st.on_dm_event(&listed(peer, 6, ConversationState::Pending));
        assert!(st.send_dm("again"));
        let [RunnerCommand::Send { token, .. }] = st.take_pending_dm()[..] else {
            panic!("expected one send");
        };
        st.on_dm_event(&RunnerEvent::Refused {
            token: Some(token),
            reason: Refusal::AwaitingAcceptance,
        });
        assert_eq!(note_of(&st), refusal_text(Refusal::AwaitingAcceptance));
        assert_ne!(note_of(&st), REQUEST_SENT_NOTE);

        let (mut st, peer) = sent_first_contact(7);
        st.on_dm_event(&listed(peer, 7, ConversationState::Pending));
        assert_eq!(note_of(&st), REQUEST_SENT_NOTE);
        st.on_dm_event(&RunnerEvent::Accepted { peer });
        assert_eq!(note_of(&st), "", "the acceptance ends the note");

        let (mut st, peer) = sent_first_contact(8);
        st.on_dm_event(&listed(peer, 8, ConversationState::Pending));
        st.on_dm_event(&RunnerEvent::BlockList(vec![pk(8)]));
        assert_eq!(
            note_of(&st),
            "You blocked them, so you can't send them messages.",
            "a block wins over the note"
        );
    }

    /// A message sent five minutes ago and collected now.
    fn message(from: CorrespondenceLabel, seq: u64, body: &str) -> RunnerEvent {
        let now = u64::try_from(now_unix_ms()).expect("a clock after 1970");
        RunnerEvent::Message {
            from,
            seq,
            body: body.as_bytes().to_vec(),
            sent_at: now - 300_000,
            received_at: now,
        }
    }

    /// A preview of request `serial` holding one message, sent five minutes
    /// ago.
    fn preview(serial: u64, body: &str) -> RunnerEvent {
        let now = u64::try_from(now_unix_ms()).expect("a clock after 1970");
        RunnerEvent::RequestPreview {
            request: ContactRequestId::for_test(1, serial),
            messages: vec![ReceivedMessage {
                sent_at_ms: now - 300_000,
                body: body.as_bytes().to_vec(),
            }],
            read_at: now,
        }
    }

    /// Two circles beside the Lobby, and two established conversations, bert
    /// and cora, with the rail built over them.
    fn two_rooms_two_conversations(app: &App) -> (CorrespondenceLabel, CorrespondenceLabel) {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let phrase =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        {
            let mut st = app.state.borrow_mut();
            st.materialize_from_phrase(phrase)
                .expect("the first circle");
            st.materialize_from_phrase(phrase)
                .expect("the second circle");
        }
        crate::rebuild_rail(&app.ui, &app.state.borrow());
        let (bert, cora) = (label(), label());
        let summary = |peer, tag| ConversationSummary {
            peer,
            peer_identity_pk: pk(tag),
            state: ConversationState::Established,
            peer_collected: 0,
            uncollected: 0,
            handle: None,
        };
        app.dm_event(RunnerEvent::Roster(vec![
            summary(bert, 2),
            summary(cora, 3),
        ]));
        (bert, cora)
    }

    /// A message into room `circle_id` from someone else.
    fn room_message(app: &App, circle_id: u64) {
        apply_net_event(
            &app.ui,
            &app.state,
            &app.browser,
            NetEvent::CircleMessage {
                circle_id,
                who: "anna".into(),
                text: "hello".into(),
                mine: false,
                sent_unix_ms: now_unix_ms(),
            },
        );
    }

    /// Each room row's dot, in rail order.
    fn room_dots(app: &App) -> Vec<bool> {
        app.ui.get_circles().iter().map(|c| c.unread).collect()
    }

    /// Each direct-message row's dot, by label.
    fn dm_dots(app: &App) -> Vec<(SharedString, bool)> {
        app.ui
            .get_dm_rows()
            .iter()
            .map(|r| (r.label, r.unread))
            .collect()
    }

    /// With Chats unfolded, an unread message marks its own room's row, the
    /// header only summing it up: the active room's row too while a direct
    /// message has the main pane. Folded when the message arrives, the row is
    /// marked once Chats unfolds.
    #[test]
    fn an_unread_room_marks_its_own_row_with_chats_unfolded() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            assert!(app.ui.get_chats_open(), "control: Chats is unfolded");
            room_message(app, 2);
            assert_eq!(room_dots(app), [false, false, true]);
            assert!(app.ui.get_chats_unread());

            // A direct message takes the main pane with Chats still unfolded,
            // and the active room, the Lobby, is written to.
            app.ui.invoke_toggle_section(1);
            let first = app.ui.get_dm_rows().row_data(0).expect("a row").slot;
            app.ui.invoke_select_dm(first);
            assert_eq!(app.ui.get_main_pane(), 3, "control: a thread is shown");
            assert!(app.ui.get_chats_open(), "control: Chats is unfolded");
            apply_net_event(
                &app.ui,
                &app.state,
                &app.browser,
                NetEvent::Message {
                    who: "anna".into(),
                    text: "hello".into(),
                    mine: false,
                    sent_unix_ms: now_unix_ms(),
                },
            );
            assert_eq!(room_dots(app), [true, false, true]);

            // Folded at arrival: the row is marked once Chats unfolds.
            app.ui.invoke_toggle_section(0);
            assert!(!app.ui.get_chats_open(), "control: Chats is folded");
            room_message(app, 1);
            app.ui.invoke_toggle_section(0);
            assert_eq!(room_dots(app), [true, true, true]);
        });
    }

    /// The rail's unread dots with both sections unfolded, drawn to the same
    /// directory as [`screenshots`]: the active room's row marked while a
    /// direct message has the main pane, and the selected conversation's row
    /// marked while a room has it. Run with `--ignored`.
    #[test]
    #[ignore = "writes PNG files; run on demand with --ignored"]
    fn rail_unread_screenshots() {
        with_app(|app| {
            let dir = std::env::temp_dir().join("dm-shots");
            std::fs::create_dir_all(&dir).expect("create the shot directory");
            let shot = |name: &str| {
                let path = dir.join(name);
                render_png(&app.window, path.to_str().expect("a UTF-8 path"));
            };
            let (bert, cora) = two_rooms_two_conversations(app);
            app.ui.invoke_toggle_section(1);
            let first = app.ui.get_dm_rows().row_data(0).expect("a row").slot;
            app.ui.invoke_select_dm(first);
            room_message(app, 2);
            apply_net_event(
                &app.ui,
                &app.state,
                &app.browser,
                NetEvent::Message {
                    who: "anna".into(),
                    text: "hello".into(),
                    mine: false,
                    sent_unix_ms: now_unix_ms(),
                },
            );
            shot("14-rail-unread-rooms-while-dm.png");
            app.ui.invoke_switch_circle(1);
            app.dm_event(message(bert, 0, "from bert"));
            app.dm_event(message(cora, 0, "from cora"));
            let selected = app
                .ui
                .get_dm_rows()
                .iter()
                .find(|r| r.selected)
                .expect("a selected row");
            assert!(selected.unread, "the selected row is marked");
            shot("14-rail-unread-dms-while-room.png");
        });
    }

    /// With Direct messages unfolded, a message marks its own conversation's
    /// row: one not selected, and the selected one while a room has the main
    /// pane. Folded when the message arrives, the row is marked once the
    /// section unfolds.
    #[test]
    fn an_unread_conversation_marks_its_own_row_with_direct_messages_unfolded() {
        with_app(|app| {
            let (bert, cora) = two_rooms_two_conversations(app);
            app.ui.invoke_open_section(1);
            let rows = dm_dots(app);
            let cora_label = rows[0].0.clone();
            app.ui.invoke_select_dm(app.slot_of(&cora_label));
            assert_eq!(app.ui.get_main_pane(), 3, "control: cora's thread is shown");

            app.dm_event(message(bert, 0, "from bert"));
            let dots = dm_dots(app);
            assert!(
                dots.iter().any(|(l, dot)| *l != cora_label && *dot),
                "bert's row: {dots:?}"
            );
            assert!(
                dots.iter().any(|(l, dot)| *l == cora_label && !*dot),
                "cora's thread is on screen: {dots:?}"
            );
            assert!(app.ui.get_dms_unread());

            // A room takes the main pane with the section still unfolded, and
            // the selected conversation is written to.
            app.ui.invoke_toggle_section(0);
            app.ui.invoke_switch_circle(1);
            assert_eq!(app.ui.get_main_pane(), 0, "control: a room is shown");
            assert!(app.ui.get_dms_open(), "control: the section is unfolded");
            app.dm_event(message(cora, 0, "from cora"));
            assert_eq!(dm_dots(app).len(), 2, "both rows are listed");
            assert!(
                dm_dots(app).iter().all(|(_, dot)| *dot),
                "both rows: {:?}",
                dm_dots(app)
            );

            // Folded at arrival: the row is marked once the section unfolds.
            app.ui.invoke_toggle_section(1);
            assert!(!app.ui.get_dms_open(), "control: the section is folded");
            app.dm_event(message(bert, 1, "again"));
            app.ui.invoke_toggle_section(1);
            assert_eq!(dm_dots(app).len(), 2, "both rows are listed");
            assert!(
                dm_dots(app).iter().all(|(_, dot)| *dot),
                "both rows: {:?}",
                dm_dots(app)
            );
        });
    }

    /// The menu reads the member when it opens: a roster re-sort before the item
    /// is chosen does not change who the message is for.
    #[test]
    fn the_roster_menu_keeps_the_member_it_opened_on() {
        with_app(|app| {
            let st = &app.state;
            st.borrow_mut()
                .set_room_roster(None, vec![member("anna#aa", 1), member("bert#bb", 2)]);
            app.ui.invoke_roster_menu_opened(0);
            st.borrow_mut()
                .set_room_roster(None, vec![member("bert#bb", 2), member("anna#aa", 1)]);
            assert_eq!(
                st.borrow().active_roster_key(0),
                Some(pk(2)),
                "control: the roster re-sorted"
            );

            app.ui.invoke_roster_start_dm();
            assert_eq!(app.ui.get_main_pane(), 3, "the draft thread is not shown");
            // Choosing a thread unfolds Direct messages and leaves Chats as it was.
            assert!(app.ui.get_dms_open() && app.ui.get_chats_open());
            assert_eq!(app.ui.get_dm_header_label(), "anna");
            assert_eq!(app.ui.get_dm_rows().row_count(), 1);
            assert!(app.ui.get_dm_can_send());

            // The menu was used: a second activation starts nothing.
            st.borrow_mut()
                .open_rail_section(RailSection::Chats, String::new(), 0.0);
            app.ui.invoke_roster_start_dm();
            assert_eq!(st.borrow().main_pane(), MainPane::Chat);
        });
    }

    /// A rail row's slot selects its item and shows its thread.
    #[test]
    fn a_rail_row_slot_selects_its_item() {
        with_app(|app| {
            app.state
                .borrow_mut()
                .set_room_roster(None, vec![member("anna#aa", 1), member("bert#bb", 2)]);
            let bert = label();
            app.dm_event(established(bert, 2));
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(1),
            });
            app.ui.invoke_open_section(1);
            assert_eq!(app.ui.get_main_pane(), 2, "control: nothing is chosen");

            app.ui.invoke_select_dm(app.slot_of("bert"));
            assert_eq!(app.ui.get_main_pane(), 3);
            assert_eq!(app.ui.get_dm_header_label(), "bert");
            assert!(!app.ui.get_dm_is_request());
            let rows = app.ui.get_dm_rows();
            let selected: Vec<SharedString> = rows
                .iter()
                .filter(|r| r.selected)
                .map(|r| r.label)
                .collect();
            assert_eq!(selected, ["bert"]);

            app.ui.invoke_select_dm(app.slot_of("anna"));
            assert!(app.ui.get_dm_is_request());
            assert_eq!(app.ui.get_dm_header_label(), "anna");
        });
    }

    /// The rail model the window receives carries no message body, although the
    /// thread of the same conversation does.
    #[test]
    fn the_rail_model_carries_no_message_body() {
        with_app(|app| {
            let peer = label();
            app.dm_event(established(peer, 3));
            app.dm_event(message(peer, 0, "incoming secret words"));
            app.ui.invoke_open_section(1);
            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(3)));
            app.ui.invoke_send_dm("outgoing secret words".into());

            let bodies: Vec<SharedString> =
                app.ui.get_dm_messages().iter().map(|m| m.body).collect();
            assert_eq!(
                bodies,
                ["incoming secret words", "outgoing secret words"],
                "control: the thread holds both bodies"
            );
            let rows = app.ui.get_dm_rows();
            assert_eq!(rows.row_count(), 1);
            for row in rows.iter() {
                for field in [&row.slot, &row.label, &row.age] {
                    assert!(
                        !field.contains("secret"),
                        "a rail row carries a body: {row:?}"
                    );
                }
            }
        });
    }

    fn dm_fingerprint(tag: u8) -> String {
        daemonseed_veilid_net::dm::view::dm_fingerprint(&pk(tag))
    }

    /// A direct-message event reaching the drain is pushed to the window.
    #[test]
    fn a_direct_message_event_reaches_the_window() {
        with_app(|app| {
            assert_eq!(app.ui.get_dm_rows().row_count(), 0);
            assert!(!app.ui.get_dms_unread());
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(4),
            });
            assert_eq!(app.ui.get_dm_rows().row_count(), 1);
            assert!(app.ui.get_dms_unread());
        });
    }

    /// Accept pressed in the window turns the request into its conversation in
    /// the window's own models at once: one rail row, no request actions, and
    /// the reply as this side's message, sending, below the message the
    /// request's preview read.
    #[test]
    fn the_accept_button_shows_the_conversation_at_once() {
        with_app(|app| {
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(4),
            });
            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(4)));
            assert!(app.ui.get_dm_is_request(), "control: the request shows");
            assert_eq!(app.ui.get_dm_messages().row_count(), 0);
            app.dm_event(preview(1, "who is this?"));
            let bodies: Vec<SharedString> =
                app.ui.get_dm_messages().iter().map(|m| m.body).collect();
            assert_eq!(bodies, ["who is this?"], "the preview shows on the request");

            app.ui.invoke_accept_dm();
            assert!(!app.ui.get_dm_is_request(), "the request still shows");
            let rows = app.ui.get_dm_rows();
            assert_eq!(rows.row_count(), 1);
            let row = rows.row_data(0).unwrap();
            assert!(row.selected && row.slot.starts_with('d'), "{row:?}");
            let messages: Vec<(SharedString, SharedString)> = app
                .ui
                .get_dm_messages()
                .iter()
                .map(|m| (m.body, m.status))
                .collect();
            assert_eq!(
                messages,
                [
                    ("who is this?".into(), "".into()),
                    ("message accepted".into(), "sending…".into())
                ]
            );
            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                [RunnerCommand::Accept { token, .. }] => *token,
                other => panic!("expected one accept, got {other:?}"),
            };

            // Refused: the window shows the request again, its reply not sent,
            // and why.
            app.dm_event(RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::Network,
            });
            assert!(app.ui.get_dm_is_request(), "the request is not shown");
            assert_eq!(app.ui.get_dm_refusal(), refusal_text(Refusal::Network));
            assert_eq!(app.ui.get_dm_rows().row_count(), 1);
            let messages: Vec<(SharedString, SharedString)> = app
                .ui
                .get_dm_messages()
                .iter()
                .map(|m| (m.body, m.status))
                .collect();
            assert_eq!(
                messages,
                [
                    ("who is this?".into(), "".into()),
                    ("message accepted".into(), "not sent".into())
                ]
            );
        });
    }

    /// The window's message model carries each message's caption: its age by
    /// its sender's clock, or for a message sent from here by when the runner
    /// committed it, and its status. The captions age with time alone, with no
    /// new event.
    #[test]
    fn thread_captions_show_ages_and_advance_with_time() {
        with_app(|app| {
            let peer = label();
            app.dm_event(established(peer, 3));
            let now = now_unix_ms();
            app.dm_event(RunnerEvent::Message {
                from: peer,
                seq: 0,
                body: b"from three hours ago".to_vec(),
                sent_at: u64::try_from(now - 3 * 3_600_000).unwrap(),
                received_at: u64::try_from(now).unwrap(),
            });
            app.ui.invoke_open_section(1);
            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(3)));
            app.ui.invoke_send_dm("mine".into());
            let captions = |app: &App| -> Vec<SharedString> {
                app.ui.get_dm_messages().iter().map(|m| m.caption).collect()
            };
            assert_eq!(captions(app), ["3h", "now · sending…"]);

            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                [RunnerCommand::Send { token, .. }] => *token,
                other => panic!("expected one send, got {other:?}"),
            };
            app.dm_event(RunnerEvent::Sent {
                token,
                peer,
                seq: 1,
                sent_at: test_now_ms(),
            });
            // Sent from another session an hour ago: its age is read from the
            // commit time the runner reports.
            app.dm_event(RunnerEvent::Sent {
                token: daemonseed_veilid_net::dm::runner::CommandToken(999),
                peer,
                seq: 7,
                sent_at: u64::try_from(now - 3_600_000).unwrap(),
            });
            assert_eq!(captions(app), ["3h", "now · sent", "1h · sent"]);

            refresh_dm_ages(&app.ui, &app.state.borrow(), now + 2 * 3_600_000 + 60_000);
            assert_eq!(captions(app), ["5h", "2h · sent", "3h · sent"]);
            let rail: Vec<SharedString> = app.ui.get_dm_rows().iter().map(|r| r.age).collect();
            assert_eq!(rail, ["2h"]);
        });
    }

    /// Leaving the room for direct messages and coming back by the Chats header
    /// keeps what was being typed to the room.
    #[test]
    fn the_room_draft_survives_a_visit_to_direct_messages() {
        with_app(|app| {
            app.ui.set_draft("half a thought".into());
            app.ui.invoke_open_section(1);
            assert_eq!(app.ui.get_main_pane(), 2);
            app.ui.invoke_open_section(0);
            assert_eq!(app.ui.get_main_pane(), 0);
            assert_eq!(app.ui.get_draft(), "half a thought");
        });
    }

    /// Press and release one key in the window.
    fn press(app: &App, text: slint::SharedString) {
        let window = app.ui.window();
        window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        window.dispatch_event(WindowEvent::KeyReleased { text });
    }

    /// A command the network thread could not take shows as not sent,
    /// and the thread's loss says how many messages did not go.
    #[test]
    fn a_command_that_cannot_be_handed_over_shows_as_not_sent() {
        with_app(|app| {
            let peer = label();
            app.dm_event(established(peer, 3));
            app.ui.invoke_open_section(1);
            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(3)));
            app.ui.invoke_send_dm("lost words".into());
            forward_pending_dm(&app.ui, &app.state, Some);
            let statuses: Vec<SharedString> =
                app.ui.get_dm_messages().iter().map(|m| m.status).collect();
            assert_eq!(statuses, ["not sent"]);
            assert_eq!(app.ui.get_dm_refusal(), refusal_text(Refusal::ShuttingDown));

            app.ui.invoke_send_dm("also lost".into());
            on_net_gone(&app.ui, &app.state);
            assert_eq!(
                app.ui.get_dm_notice(),
                "Messaging stopped. 1 message was not sent."
            );
        });
    }

    /// Text typed to the room survives opening a request and coming
    /// back by the Chats header.
    #[test]
    fn the_room_draft_survives_opening_a_request() {
        with_app(|app| {
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(4),
            });
            app.ui.set_draft("typed in the Lobby".into());
            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(4)));
            assert_eq!(app.ui.get_main_pane(), 3, "control: the request shows");
            app.ui.invoke_open_section(0);
            assert_eq!(app.ui.get_main_pane(), 0);
            assert_eq!(app.ui.get_draft(), "typed in the Lobby");
        });
    }

    /// A first message that meets a waiting request stays in the reply
    /// box, and the notice says why it was not sent.
    #[test]
    fn a_redirected_first_message_stays_in_the_reply_box() {
        with_app(|app| {
            app.state
                .borrow_mut()
                .set_room_roster(None, vec![member("anna#aa", 1)]);
            app.ui.invoke_roster_menu_opened(0);
            app.ui.invoke_roster_start_dm();
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(1),
            });
            app.ui.set_dm_draft("hello anna".into());
            app.ui.invoke_send_dm("hello anna".into());
            assert!(app.ui.get_dm_is_request());
            assert_eq!(app.ui.get_dm_draft(), "hello anna");
            assert_eq!(
                app.ui.get_dm_notice(),
                notice_text(DmNotice::MovedToRequest)
            );
        });
    }

    /// The circle details sheet and a revealed join phrase close when
    /// the chat leaves the main pane, and Escape closes the sheet.
    #[test]
    fn the_details_sheet_closes_with_the_chat() {
        with_app(|app| {
            app.ui.set_sheet_open(true);
            app.ui
                .set_circle_phrase_revealed("join phrase words".into());
            app.ui.invoke_toggle_section(0);
            assert_eq!(app.ui.get_main_pane(), 1, "control: the chat folded away");
            assert!(!app.ui.get_sheet_open());
            assert_eq!(app.ui.get_circle_phrase_revealed(), "");

            app.ui.invoke_toggle_section(0);
            app.ui.set_sheet_open(true);
            press(app, Key::Escape.into());
            assert!(!app.ui.get_sheet_open(), "Escape left the sheet open");
        });
    }

    /// Once a thread is chosen, keys go to its reply box and never to
    /// the room composer that had focus.
    #[test]
    fn keys_reach_the_reply_box_not_the_hidden_room_composer() {
        with_app(|app| {
            let peer = label();
            app.dm_event(established(peer, 3));
            app.ui.invoke_focus_composer();
            press(app, "a".into());
            assert_eq!(
                app.ui.get_draft(),
                "a",
                "control: the room composer had focus"
            );

            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(3)));
            press(app, "b".into());
            assert_eq!(
                app.ui.get_draft(),
                "a",
                "a key went to the hidden room composer"
            );
            slint::platform::update_timers_and_animations();
            press(app, "c".into());
            assert_eq!(
                app.ui.get_dm_draft(),
                "c",
                "the reply box did not take focus"
            );
            assert_eq!(app.ui.get_draft(), "a");
        });
    }

    /// Unfolding Chats by its chevron gives the room composer the keys
    /// again.
    #[test]
    fn unfolding_chats_refocuses_the_room_composer() {
        with_app(|app| {
            app.ui.invoke_toggle_section(0);
            app.ui.invoke_toggle_section(0);
            assert_eq!(app.ui.get_main_pane(), 0);
            slint::platform::update_timers_and_animations();
            press(app, "z".into());
            assert_eq!(app.ui.get_draft(), "z");
        });
    }

    /// Ctrl+D opens Direct messages.
    #[test]
    fn ctrl_d_opens_direct_messages() {
        with_app(|app| {
            let window = app.ui.window();
            window.dispatch_event(WindowEvent::KeyPressed {
                text: Key::Control.into(),
            });
            window.dispatch_event(WindowEvent::KeyPressed { text: "d".into() });
            window.dispatch_event(WindowEvent::KeyReleased { text: "d".into() });
            window.dispatch_event(WindowEvent::KeyReleased {
                text: Key::Control.into(),
            });
            assert!(app.ui.get_dms_open());
            assert_eq!(app.ui.get_main_pane(), 2);
        });
    }

    /// Add 15 circles, and 25 conversations with members of the Lobby roster,
    /// which lists `others` first: both rail lists run past the window.
    fn fill_long_lists(app: &App, others: &[RosterEntry]) {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        {
            let mut st = app.state.borrow_mut();
            for i in 1..=15 {
                st.materialize_from_phrase(&format!(
                    "fixture circle {i:02} amber willow harbor lantern quiet meadow"
                ))
                .expect("a circle materializes");
            }
            let mut members = others.to_vec();
            members.extend(
                (0..25u8).map(|i| member(&format!("friend{:02}#{:012x}", i + 1, i + 1), 40 + i)),
            );
            st.set_room_roster(None, members);
        }
        crate::rebuild_rail(&app.ui, &app.state.borrow());
        app.dm_event(RunnerEvent::Roster(
            (0..25u8)
                .map(|i| ConversationSummary {
                    peer: label(),
                    peer_identity_pk: pk(40 + i),
                    state: ConversationState::Established,
                    peer_collected: 0,
                    uncollected: 0,
                    handle: None,
                })
                .collect(),
        ));
    }

    /// Turn the mouse wheel down over the rail at height `y`.
    fn wheel_down_at(app: &App, y: f32) {
        let at = slint::LogicalPosition::new(120.0, y);
        let window = app.ui.window();
        window.dispatch_event(WindowEvent::PointerMoved { position: at });
        window.dispatch_event(WindowEvent::PointerScrolled {
            position: at,
            delta_x: 0.0,
            delta_y: -400.0,
        });
    }

    /// The rooms list and the Direct messages list each scroll on their own
    /// once they run past the rail, far enough that their first row leaves the
    /// view and a row below the first screen comes into it.
    #[test]
    fn both_rail_lists_scroll_on_their_own() {
        with_app(|app| {
            fill_long_lists(app, &[]);
            app.ui.invoke_open_section(0);
            app.ui.invoke_toggle_section(1);
            assert!(app.ui.get_chats_open() && app.ui.get_dms_open());
            assert_eq!(app.ui.get_circles().row_count(), 16);
            assert_eq!(app.ui.get_dm_rows().row_count(), 25);
            assert_eq!(app.ui.get_chats_list_offset(), 0.0);
            assert_eq!(app.ui.get_dm_list_offset(), 0.0);

            wheel_down_at(app, 200.0);
            let rooms = app.ui.get_chats_list_offset();
            assert!(rooms <= -ROW_PX, "the rooms list did not scroll: {rooms}");
            assert_eq!(app.ui.get_dm_list_offset(), 0.0, "the wrong list scrolled");

            wheel_down_at(app, 560.0);
            let dms = app.ui.get_dm_list_offset();
            assert!(
                dms <= -ROW_PX,
                "the conversations list did not scroll: {dms}"
            );
            assert_eq!(
                app.ui.get_chats_list_offset(),
                rooms,
                "the wrong list scrolled"
            );
        });
    }

    /// The height of the tallest rail row: a list scrolled at least this far
    /// shows a row that was below its first screen.
    const ROW_PX: f32 = 58.0;

    /// Writes the direct-messaging screens to `dm-shots` under the temporary
    /// directory, from fixture state applied through the same glue the window
    /// uses. Run with `--ignored`.
    #[test]
    #[ignore = "writes PNG files; run on demand with --ignored"]
    fn screenshots() {
        with_app(|app| {
            let dir = std::env::temp_dir().join("dm-shots");
            std::fs::create_dir_all(&dir).expect("create the shot directory");
            let shot = |name: &str| {
                let path = dir.join(name);
                render_png(&app.window, path.to_str().expect("a UTF-8 path"));
            };
            let now = crate::now_unix_ms();
            {
                let mut st = app.state.borrow_mut();
                st.set_room_roster(
                    None,
                    vec![
                        member("anna#3f9c2a1b7d4e", 1),
                        member("bert#9a1c55e0b2f7", 2),
                        member("cora#51d0e8a4c3b6", 3),
                        member("dave#0c7e2f9b18a5", 4),
                    ],
                );
                st.push_message(
                    0,
                    "anna#3f9c2a1b7d4e".into(),
                    "Morning, all.".into(),
                    false,
                    now - 600_000,
                );
                st.push_message(
                    0,
                    "bert#9a1c55e0b2f7".into(),
                    "Is the relay up again?".into(),
                    false,
                    now - 300_000,
                );
                st.push_message(
                    0,
                    "me#000000000000".into(),
                    "Looks fine from here.".into(),
                    true,
                    now - 120_000,
                );
            }
            app.ui.invoke_switch_circle(0);

            // Bert: an established conversation.
            let bert = label();
            app.dm_event(established(bert, 2));

            // Cora: a draft from the roster, answered, then a refused second send.
            app.state.borrow_mut().set_room_roster(
                None,
                vec![
                    member("anna#3f9c2a1b7d4e", 1),
                    member("bert#9a1c55e0b2f7", 2),
                    member("cora#51d0e8a4c3b6", 3),
                    member("dave#0c7e2f9b18a5", 4),
                ],
            );
            app.ui.invoke_roster_menu_opened(2);
            app.ui.invoke_roster_start_dm();
            app.ui
                .invoke_send_dm("Hi Cora, it's me from the Lobby.".into());
            // The roster's handles are noted to the runner ahead of the send.
            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                [.., RunnerCommand::FirstContact { token, .. }] => *token,
                other => panic!("expected a first contact last, got {other:?}"),
            };
            let cora = label();
            app.dm_event(RunnerEvent::Sent {
                token,
                peer: cora,
                seq: 0,
                sent_at: test_now_ms(),
            });
            app.dm_event(RunnerEvent::Delivered {
                peer: cora,
                through_seq: 0,
            });
            app.dm_event(message(cora, 0, "Hello! Good to hear from you."));
            app.ui
                .invoke_send_dm("Are you coming to the meetup on Friday?".into());
            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                [.., RunnerCommand::Send { token, .. }] => *token,
                other => panic!("expected a send last, got {other:?}"),
            };
            app.dm_event(RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::AwaitingAcceptance,
            });

            // Dave: a request with its message previewed, looked at once, so
            // it is read.
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 1),
                from: pk(4),
            });
            app.dm_event(preview(1, "Hi, it's Dave from the Lobby."));
            app.ui.invoke_select_dm(app.slot_of("dave"));

            // Bert writes while another item is shown: the one unread row.
            app.dm_event(message(bert, 0, "See you there."));

            // (2) Direct messages open, nothing chosen.
            app.ui.invoke_open_section(1);
            let rows = app.ui.get_dm_rows();
            let labels: Vec<SharedString> = rows.iter().map(|r| r.label).collect();
            assert_eq!(labels, ["dave", "bert", "cora"]);
            let unread: Vec<bool> = rows.iter().map(|r| r.unread).collect();
            assert_eq!(unread, [false, true, false]);
            shot("2-dm-none-chosen.png");

            // (3) The request, its message shown before it is accepted.
            app.ui.invoke_select_dm(app.slot_of("dave"));
            assert!(app.ui.get_dm_is_request());
            assert_eq!(app.ui.get_dm_messages().row_count(), 1);
            shot("3-dm-request.png");

            // (4) Cora's conversation.
            app.ui.invoke_select_dm(app.slot_of("cora"));
            assert!(app.ui.get_dm_messages().iter().any(|m| m.refused));
            shot("4-dm-conversation.png");

            // (5) Both sections folded.
            app.ui.invoke_open_section(1);
            app.ui.invoke_toggle_section(1);
            assert!(!app.ui.get_chats_open() && !app.ui.get_dms_open());
            shot("5-both-folded.png");

            // (1) Chats open on the Lobby.
            app.ui.invoke_open_section(0);
            assert_eq!(app.ui.get_main_pane(), 0);
            shot("1-chats-lobby.png");

            // (6) The roster menu, opened by a right-press on the first member.
            let at = slint::LogicalPosition::new(960.0, 72.0);
            app.ui
                .window()
                .dispatch_event(WindowEvent::PointerMoved { position: at });
            app.ui.window().dispatch_event(WindowEvent::PointerPressed {
                position: at,
                button: slint::platform::PointerEventButton::Right,
            });
            shot("6-roster-menu.png");
            // The press read the member it landed on.
            app.ui.invoke_roster_start_dm();
            assert_eq!(app.ui.get_dm_header_label(), "anna");

            // (7) Both sections unfolded by their chevrons; the room stays shown.
            app.ui.invoke_open_section(0);
            app.ui.invoke_toggle_section(1);
            assert!(app.ui.get_chats_open() && app.ui.get_dms_open());
            assert_eq!(app.ui.get_main_pane(), 0);
            shot("7-both-open-by-chevron.png");

            // (8) The details sheet was open; folding Chats closed it.
            app.ui.set_sheet_open(true);
            app.ui.invoke_toggle_section(0);
            assert!(!app.ui.get_sheet_open());
            shot("8-sheet-closed-after-fold.png");

            // (9) Folding and unfolding Direct messages forgets the thread.
            app.ui.invoke_select_dm(app.slot_of("bert"));
            app.ui.invoke_toggle_section(1);
            app.ui.invoke_toggle_section(1);
            assert_eq!(app.ui.get_main_pane(), 2);
            shot("9-dm-unfolded-choose.png");

            // (10) A block that did not take effect.
            app.ui.invoke_select_dm(app.slot_of("dave"));
            app.ui.invoke_block_dm();
            app.state.borrow_mut().take_pending_dm();
            app.dm_event(RunnerEvent::Refused {
                token: None,
                reason: Refusal::BlockListFull,
            });
            assert!(!app.ui.get_dm_notice().is_empty());
            shot("10-dm-block-refused.png");

            // (11) Messaging stopped with a message unsent.
            app.ui.invoke_select_dm(app.slot_of("bert"));
            app.ui.invoke_send_dm("Did you get my note?".into());
            on_net_gone(&app.ui, &app.state);
            assert_eq!(
                app.ui.get_dm_notice(),
                "Messaging stopped. 1 message was not sent."
            );
            shot("11-dm-not-sent.png");

            // (12) Both lists longer than the rail, each scrolled: 15 circles
            // under Chats and 25 conversations under Direct messages. New circle
            // and Join stay below the rooms, whatever the scroll.
            fill_long_lists(app, &[member("anna#3f9c2a1b7d4e", 1)]);
            // Opening Direct messages by its label clears the last notice.
            app.ui.invoke_open_section(1);
            app.ui.invoke_open_section(0);
            app.ui.invoke_toggle_section(1);
            assert!(app.ui.get_chats_open() && app.ui.get_dms_open());
            assert_eq!(app.ui.get_dm_notice(), "");
            assert_eq!(app.ui.get_circles().row_count(), 16);
            assert_eq!(app.ui.get_dm_rows().row_count(), 26);
            // The pointer rests at one point off the rail for both shots, so no
            // row differs by being hovered.
            let rest = |app: &App| {
                app.ui.window().dispatch_event(WindowEvent::PointerMoved {
                    position: slint::LogicalPosition::new(560.0, 400.0),
                });
            };
            rest(app);
            shot("12-long-lists-top.png");
            wheel_down_at(app, 200.0);
            wheel_down_at(app, 560.0);
            assert!(app.ui.get_chats_list_offset() <= -ROW_PX);
            assert!(app.ui.get_dm_list_offset() <= -ROW_PX);
            rest(app);
            shot("12-long-lists-scrolled.png");
            // Each list's own region of the rail changed between the shots.
            let region = |name: &str, top: u32, bottom: u32| {
                let img = image::open(dir.join(name))
                    .expect("read the shot")
                    .to_rgb8();
                image::imageops::crop_imm(&img, 0, top, 256, bottom - top)
                    .to_image()
                    .into_raw()
            };
            for (list, top, bottom) in [("rooms", 100, 320), ("conversations", 420, 640)] {
                assert_ne!(
                    region("12-long-lists-top.png", top, bottom),
                    region("12-long-lists-scrolled.png", top, bottom),
                    "the {list} list looks the same scrolled"
                );
            }

            // (13) Accept shows the conversation with the reply sending; a
            // refusal leaves the request, its reply not sent and why.
            app.dm_event(RunnerEvent::ContactRequest {
                request: ContactRequestId::for_test(1, 2),
                from: pk(5),
            });
            app.ui.invoke_select_dm(app.slot_of(&dm_fingerprint(5)));
            app.ui.invoke_accept_dm();
            assert!(!app.ui.get_dm_is_request());
            shot("13-dm-accept-sending.png");
            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                // The send (11) queued is still in the queue ahead of it.
                [.., RunnerCommand::Accept { token, .. }] => *token,
                other => panic!("expected an accept last, got {other:?}"),
            };
            app.dm_event(RunnerEvent::Refused {
                token: Some(token),
                reason: Refusal::Network,
            });
            assert!(app.ui.get_dm_is_request());
            assert_eq!(app.ui.get_dm_refusal(), refusal_text(Refusal::Network));
            shot("13-dm-accept-refused.png");

            // (14) Messaging stopped with an error, its text selectable beneath,
            // with the conversations scrolled back to their first row so any
            // overlap of the box and the list would show.
            let unavailable = |detail: &str| {
                apply_net_event(
                    &app.ui,
                    &app.state,
                    &app.browser,
                    NetEvent::DmUnavailable(DmUnavailable::new(
                        DmUnavailableCause::RunnerFailed,
                        detail,
                    )),
                );
                let at = slint::LogicalPosition::new(120.0, 560.0);
                let window = app.ui.window();
                window.dispatch_event(WindowEvent::PointerMoved { position: at });
                window.dispatch_event(WindowEvent::PointerScrolled {
                    position: at,
                    delta_x: 0.0,
                    delta_y: 4000.0,
                });
                window.dispatch_event(WindowEvent::PointerMoved {
                    position: slint::LogicalPosition::new(560.0, 400.0),
                });
                assert_eq!(app.ui.get_dm_list_offset(), 0.0);
                assert_eq!(app.ui.get_dm_notice_detail(), detail);
            };
            unavailable(
                "direct-message store: dm store I/O failed on block-list.bin: \
                 permission denied (os error 13)",
            );
            shot("14-dm-unavailable-detail.png");

            // (15) A long error stays within five lines and scrolls in its box.
            unavailable(
                &"direct-message store: the conversation record did not decode. ".repeat(8),
            );
            shot("15-dm-unavailable-long-detail.png");
        });
    }

    /// Each cause of messaging being unavailable reaches the window as its own
    /// line, with the redacted error text beneath it for every cause but not
    /// being connected.
    #[test]
    fn each_unavailable_cause_shows_its_line_and_detail() {
        with_app(|app| {
            let cases = [
                (
                    DmUnavailableCause::NotConnected,
                    "no Veilid node",
                    "Direct messages will start once you're connected.",
                    "",
                ),
                (
                    DmUnavailableCause::StoreUnopened,
                    "refused locally: C:\\Users\\alice\\AppData\\dm",
                    "Direct messages couldn't start because your saved conversations couldn't be opened.",
                    "refused locally: <path>",
                ),
                (
                    DmUnavailableCause::RunnerFailed,
                    "direct-message store: /home/alice/dm/lock is a symlink",
                    "Direct messages stopped because of an error. Restart the app to try again.",
                    "direct-message store: <path> is a symlink",
                ),
                (
                    DmUnavailableCause::Internal,
                    "the runner panicked",
                    "Direct messages stopped because of an internal error. Restart the app to try again.",
                    "the runner panicked",
                ),
            ];
            for (cause, detail, line, shown) in cases {
                apply_net_event(
                    &app.ui,
                    &app.state,
                    &app.browser,
                    NetEvent::DmUnavailable(DmUnavailable::new(cause, detail)),
                );
                assert_eq!(app.ui.get_dm_notice(), line, "for {cause:?}");
                assert_eq!(app.ui.get_dm_notice_detail(), shown, "for {cause:?}");
            }
            // A runner that reports clears both.
            app.dm_event(RunnerEvent::Roster(Vec::new()));
            assert_eq!(app.ui.get_dm_notice(), "");
            assert_eq!(app.ui.get_dm_notice_detail(), "");
        });
    }

    /// Mark `room`'s record unreadable or readable again, the way the drain does.
    fn room_reach(app: &App, room: crate::net::RoomRecord, reachable: bool) {
        apply_net_event(
            &app.ui,
            &app.state,
            &app.browser,
            NetEvent::RoomReach { room, reachable },
        );
    }

    /// A circle that cannot be reached says so on its rail row and on its chat tab,
    /// under the label its row shows, and both clear once it is reachable again.
    #[test]
    fn an_unreachable_circle_shows_on_its_row_and_its_chat() {
        use crate::net::RoomRecord;
        with_app(|app| {
            two_rooms_two_conversations(app);
            circle_joined(app, 1);
            app.ui.invoke_switch_circle(1);
            let label = app
                .ui
                .get_circles()
                .row_data(1)
                .expect("the circle row")
                .name;
            assert_eq!(app.ui.get_reach_room(), "", "control: reachable at first");

            room_reach(app, RoomRecord::Circle(1), false);
            let rows: Vec<bool> = app.ui.get_circles().iter().map(|c| c.unreachable).collect();
            assert_eq!(rows, [false, true, false], "only that circle's row");
            assert_eq!(
                app.ui.get_reach_room(),
                format!("Can't reach {label} right now. Retrying.")
            );

            room_reach(app, RoomRecord::Circle(1), true);
            assert!(app.ui.get_circles().iter().all(|c| !c.unreachable));
            assert_eq!(app.ui.get_reach_room(), "");
        });
    }

    /// Draws a circle that cannot be reached, as its chat tab and rail row show it,
    /// to `reach-shots` under the temporary directory. Run with `--ignored`.
    #[test]
    #[ignore = "writes PNG files; run on demand with --ignored"]
    fn reach_screenshots() {
        use crate::net::RoomRecord;
        with_app(|app| {
            let dir = std::env::temp_dir().join("reach-shots");
            std::fs::create_dir_all(&dir).expect("create the shot directory");
            two_rooms_two_conversations(app);
            apply_net_event(
                &app.ui,
                &app.state,
                &app.browser,
                NetEvent::CircleJoined {
                    circle_id: 1,
                    asset_addr: daemonseed_core::cot::AssetAddr::from_bytes(
                        [7u8; daemonseed_core::cot::ASSET_ADDR_LEN],
                    ),
                },
            );
            app.ui.invoke_switch_circle(1);
            room_message(app, 1);
            room_reach(app, RoomRecord::Circle(1), false);
            let path = dir.join("reconnect-circle.png");
            render_png(&app.window, path.to_str().expect("a UTF-8 path"));
        });
    }

    /// Report that circle `circle_id` joined, the way the drain does.
    fn circle_joined(app: &App, circle_id: u64) {
        apply_net_event(
            &app.ui,
            &app.state,
            &app.browser,
            NetEvent::CircleJoined {
                circle_id,
                asset_addr: daemonseed_core::cot::AssetAddr::from_bytes(
                    [7u8; daemonseed_core::cot::ASSET_ADDR_LEN],
                ),
            },
        );
    }

    /// Report an error for circle `circle_id`, the way the drain does.
    fn circle_error(app: &App, circle_id: u64, reason: &str) {
        apply_net_event(
            &app.ui,
            &app.state,
            &app.browser,
            NetEvent::CircleError {
                circle_id,
                reason: reason.into(),
            },
        );
    }

    /// The label rail row `idx` shows.
    fn row_name(app: &App, idx: usize) -> SharedString {
        app.ui.get_circles().row_data(idx).expect("the row").name
    }

    /// Each room row's joining flag, in rail order.
    fn room_joining(app: &App) -> Vec<bool> {
        app.ui.get_circles().iter().map(|c| c.joining).collect()
    }

    /// An error for a circle that is not on screen names that circle on the status
    /// line, by the label its rail row shows. An id no circle has keeps the
    /// generic line.
    #[test]
    fn a_circle_error_names_the_circle_it_is_about() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            circle_joined(app, 2);
            app.ui.invoke_switch_circle(1);
            let other = row_name(app, 2);
            assert!(!other.starts_with('#'), "control: the joined label");

            circle_error(app, 2, "the network refused the subscribe");
            assert_eq!(
                app.ui.get_connection_status(),
                format!("circle {other}: the network refused the subscribe")
            );

            circle_error(app, 99, "no such circle");
            assert_eq!(app.ui.get_connection_status(), "circle: no such circle");
        });
    }

    /// The composer and Send stay closed while the active circle has not joined,
    /// and open once it has. The Lobby is always open.
    #[test]
    fn the_composer_opens_only_once_the_active_circle_has_joined() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            assert!(app.ui.get_can_send(), "control: the Lobby takes messages");
            app.ui.invoke_focus_composer();
            press(app, "a".into());
            assert_eq!(app.ui.get_draft(), "a", "control: the Lobby composer types");
            app.ui.set_draft("".into());

            app.ui.invoke_switch_circle(1);
            assert!(
                !app.ui.get_can_send(),
                "a circle still joining takes messages"
            );
            app.ui.invoke_focus_composer();
            press(app, "b".into());
            assert_eq!(app.ui.get_draft(), "", "a key reached a closed composer");
            app.ui.set_draft("held".into());
            app.ui.invoke_send_message("held".into());
            assert_eq!(
                app.ui.get_draft(),
                "held",
                "Send ran for a circle still joining"
            );
            app.ui.set_draft("".into());

            circle_joined(app, 1);
            assert!(app.ui.get_can_send(), "the joined circle stays closed");
            app.ui.invoke_focus_composer();
            press(app, "c".into());
            assert_eq!(
                app.ui.get_draft(),
                "c",
                "the joined circle's composer types"
            );
            app.ui.invoke_send_message("c".into());
            assert_eq!(app.ui.get_draft(), "", "a send clears the composer");

            app.ui.invoke_switch_circle(2);
            assert!(!app.ui.get_can_send(), "the other circle has not joined");
        });
    }

    /// A circle shows that it is joining from the moment it is added, still shows it
    /// after a join refused for a reason that may pass while the retry waits, and
    /// stops once it has joined. The join clears the circle's error from the status
    /// line, and only that circle's.
    #[test]
    fn a_circle_shows_it_is_joining_until_it_joins() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            assert_eq!(room_joining(app), [false, true, true], "both circles join");
            assert_eq!(
                app.ui.get_joining_room(),
                "",
                "control: the Lobby is joined"
            );

            app.ui.invoke_switch_circle(1);
            let pending = row_name(app, 1);
            assert_eq!(app.ui.get_joining_room(), format!("Joining {pending}…"));

            circle_error(app, 1, "the network refused the subscribe");
            assert_eq!(
                room_joining(app),
                [false, true, true],
                "a refusal keeps it joining"
            );
            assert_eq!(app.ui.get_joining_room(), format!("Joining {pending}…"));
            assert_eq!(
                app.ui.get_connection_status(),
                format!("circle {pending}: the network refused the subscribe")
            );

            circle_joined(app, 1);
            assert_eq!(room_joining(app), [false, false, true]);
            assert_eq!(app.ui.get_joining_room(), "");
            assert_eq!(
                app.ui.get_connection_status(),
                "connected · veilid",
                "the stale error stayed after the join"
            );

            // Another circle's error stays when this one joins again.
            circle_error(app, 2, "the network refused the subscribe");
            let other = app.ui.get_connection_status();
            circle_joined(app, 1);
            assert_eq!(app.ui.get_connection_status(), other);
        });
    }

    /// A circle that has never joined shows that it is joining, not that it cannot
    /// be reached. Once joined, the unreachable state it was given shows.
    #[test]
    fn joining_wins_over_unreachable() {
        use crate::net::RoomRecord;
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.invoke_switch_circle(1);
            room_reach(app, RoomRecord::Circle(1), false);
            let row = app.ui.get_circles().row_data(1).expect("the circle row");
            assert!(row.joining && !row.unreachable, "the row shows unreachable");
            assert_eq!(app.ui.get_reach_room(), "", "the chat shows unreachable");
            assert_ne!(app.ui.get_joining_room(), "");

            circle_joined(app, 1);
            let row = app.ui.get_circles().row_data(1).expect("the circle row");
            assert!(!row.joining && row.unreachable);
            assert_eq!(
                app.ui.get_reach_room(),
                format!("Can't reach {} right now. Retrying.", row.name)
            );
            assert_eq!(app.ui.get_joining_room(), "");
        });
    }

    /// Draws a circle still joining after a join refused for a reason that may pass,
    /// as its chat tab and rail row show it, to `joining-shots` under the temporary
    /// directory. Run with `--ignored`.
    #[test]
    #[ignore = "writes PNG files; run on demand with --ignored"]
    fn joining_screenshots() {
        with_app(|app| {
            let dir = std::env::temp_dir().join("joining-shots");
            std::fs::create_dir_all(&dir).expect("create the shot directory");
            two_rooms_two_conversations(app);
            circle_joined(app, 2);
            app.ui.invoke_switch_circle(1);
            circle_error(app, 1, "the network refused the subscribe");
            let path = dir.join("joining-circle.png");
            render_png(&app.window, path.to_str().expect("a UTF-8 path"));
        });
    }

    /// Report that the join of circle `circle_id` ended for good, the way the drain
    /// does.
    fn circle_join_failed(app: &App, circle_id: u64, reason: &str) {
        apply_net_event(
            &app.ui,
            &app.state,
            &app.browser,
            NetEvent::CircleJoinFailed {
                circle_id,
                reason: reason.into(),
            },
        );
    }

    /// Each room row's could-not-join flag, in rail order.
    fn room_join_failed(app: &App) -> Vec<bool> {
        app.ui.get_circles().iter().map(|c| c.join_failed).collect()
    }

    /// A circle whose join ended for good stops showing that it is joining: its row
    /// says it could not join, its chat names it and the reason, and its composer and
    /// Send stay closed. A later join clears all of it.
    #[test]
    fn a_circle_whose_join_ends_for_good_says_why_until_it_joins() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.invoke_switch_circle(1);
            let name = row_name(app, 1);
            assert_eq!(app.ui.get_joining_room(), format!("Joining {name}…"));
            assert!(
                !app.ui.get_joining_failed(),
                "control: joining is no failure"
            );

            circle_join_failed(app, 1, "subscribe failed: refused for good");
            assert_eq!(room_joining(app), [false, false, true]);
            assert_eq!(room_join_failed(app), [false, true, false]);
            assert_eq!(
                app.ui.get_joining_room(),
                format!("Couldn't join {name}: subscribe failed: refused for good")
            );
            assert!(app.ui.get_joining_failed());
            assert!(
                !app.ui.get_can_send(),
                "a circle that could not join takes messages"
            );
            app.ui.invoke_focus_composer();
            press(app, "a".into());
            assert_eq!(app.ui.get_draft(), "", "a key reached a closed composer");

            app.ui.invoke_switch_circle(2);
            assert_eq!(
                app.ui.get_joining_room(),
                format!("Joining {}…", row_name(app, 2)),
                "the failure followed the user to another circle"
            );
            assert!(!app.ui.get_joining_failed());
            app.ui.invoke_switch_circle(1);

            circle_joined(app, 1);
            assert_eq!(room_join_failed(app), [false, false, false]);
            assert_eq!(app.ui.get_joining_room(), "");
            assert!(!app.ui.get_joining_failed());
            assert!(app.ui.get_can_send(), "the joined circle stays closed");
        });
    }

    /// Joining a phrase whose circle is already in the rail switches to that circle
    /// and adds no row.
    #[test]
    fn joining_a_phrase_already_joined_switches_to_its_circle() {
        with_app(|app| {
            let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
            let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
            app.ui.invoke_submit_join(phrase.into());
            assert_eq!(
                app.ui.get_circles().row_count(),
                2,
                "control: the join adds a row"
            );
            assert_eq!(app.ui.get_active(), 1);
            app.ui.invoke_switch_circle(0);
            assert_eq!(app.ui.get_active(), 0);

            app.ui.invoke_open_join();
            app.ui.invoke_submit_join(format!(" {phrase} ").into());
            assert_eq!(
                app.ui.get_circles().row_count(),
                2,
                "the phrase added a second row for its circle"
            );
            assert_eq!(
                app.ui.get_active(),
                1,
                "the join did not switch to the circle"
            );
            assert!(!app.ui.get_join_open(), "the join overlay stayed open");
        });
    }

    /// When the active circle on the chat tab joins, its composer takes the keys. A
    /// circle already joined that reports joining again leaves the focus where it is.
    #[test]
    fn the_composer_takes_the_keys_when_the_active_circle_joins() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.invoke_switch_circle(1);
            slint::platform::update_timers_and_animations();
            press(app, "a".into());
            assert_eq!(
                app.ui.get_draft(),
                "",
                "control: the joining composer is closed"
            );

            circle_joined(app, 1);
            slint::platform::update_timers_and_animations();
            press(app, "b".into());
            assert_eq!(
                app.ui.get_draft(),
                "b",
                "the composer did not take the keys"
            );

            app.ui.invoke_open_join();
            slint::platform::update_timers_and_animations();
            press(app, "c".into());
            assert_eq!(
                app.ui.get_join_phrase(),
                "c",
                "control: the join field has the keys"
            );
            circle_joined(app, 1);
            slint::platform::update_timers_and_animations();
            press(app, "d".into());
            assert_eq!(
                app.ui.get_join_phrase(),
                "cd",
                "a repeated join took the keys from the join field"
            );
            assert_eq!(app.ui.get_draft(), "b");
        });
    }

    /// A circle that joins for the first time while a dialog or overlay is open
    /// leaves the keys where they are.
    #[test]
    fn a_first_join_under_an_overlay_leaves_the_focus_alone() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.invoke_switch_circle(1);
            slint::platform::update_timers_and_animations();
            app.ui.invoke_open_join();
            slint::platform::update_timers_and_animations();
            press(app, "c".into());
            assert_eq!(
                app.ui.get_join_phrase(),
                "c",
                "control: the join field has the keys"
            );

            circle_joined(app, 1);
            slint::platform::update_timers_and_animations();
            press(app, "d".into());
            assert_eq!(
                app.ui.get_join_phrase(),
                "cd",
                "the first join took the keys from the join field"
            );
            assert_eq!(app.ui.get_draft(), "");
        });
    }

    /// A circle that joins for the first time while the startup mask covers the
    /// window leaves the keys where they are, so typing under the mask goes into
    /// no hidden field.
    #[test]
    fn a_first_join_under_the_startup_mask_leaves_the_focus_alone() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.invoke_switch_circle(1);
            slint::platform::update_timers_and_animations();
            app.ui.set_startup_overlay_open(true);

            circle_joined(app, 1);
            slint::platform::update_timers_and_animations();
            press(app, "d".into());
            assert_eq!(
                app.ui.get_draft(),
                "",
                "the composer took the keys under the startup mask"
            );
        });
    }

    /// When the startup mask closes over the chat of a circle that joined beneath
    /// it, the composer takes the keys.
    #[test]
    fn the_composer_takes_the_keys_when_the_startup_mask_closes() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.invoke_switch_circle(1);
            slint::platform::update_timers_and_animations();
            app.ui.set_startup_overlay_open(true);
            circle_joined(app, 1);
            slint::platform::update_timers_and_animations();
            press(app, "d".into());
            assert_eq!(app.ui.get_draft(), "", "control: no field has the keys");

            app.ui.set_startup_overlay_open(false);
            slint::platform::update_timers_and_animations();
            press(app, "e".into());
            assert_eq!(
                app.ui.get_draft(),
                "e",
                "the composer did not take the keys when the mask closed"
            );
        });
    }

    /// A dialog open when the startup mask closes keeps the keys: the composer
    /// behind it does not take them. Each dialog is checked on its own.
    #[test]
    fn a_dialog_open_when_the_startup_mask_closes_keeps_the_keys() {
        let dialogs = [
            "new",
            "rename",
            "phrase-prompt",
            "leave-confirm",
            "palette",
            "about",
            "publish",
            "sheet",
            "desktop-prompt",
        ];
        for dialog in dialogs {
            with_app(move |app| {
                two_rooms_two_conversations(app);
                app.ui.invoke_switch_circle(1);
                slint::platform::update_timers_and_animations();
                app.ui.set_startup_overlay_open(true);
                circle_joined(app, 1);
                slint::platform::update_timers_and_animations();
                match dialog {
                    "new" => app.ui.set_new_open(true),
                    "rename" => app.ui.set_rename_open(true),
                    "phrase-prompt" => app.ui.set_phrase_prompt_open(true),
                    "leave-confirm" => app.ui.set_leave_confirm_open(true),
                    "palette" => app.ui.set_palette_open(true),
                    "about" => app.ui.set_about_open(true),
                    "publish" => app.ui.set_publish_open(true),
                    "sheet" => app.ui.set_sheet_open(true),
                    _ => app.ui.set_desktop_prompt_open(true),
                }
                slint::platform::update_timers_and_animations();

                app.ui.set_startup_overlay_open(false);
                slint::platform::update_timers_and_animations();
                press(app, "e".into());
                assert_eq!(
                    app.ui.get_draft(),
                    "",
                    "the composer took the keys from the {dialog} dialog when the mask closed"
                );
            });
        }
    }

    /// With the Join dialog and a dialog above it both open when the startup mask
    /// closes, the Join phrase field does not take the keys from the dialog above.
    #[test]
    fn the_join_field_does_not_take_the_keys_from_a_dialog_above_it() {
        with_app(|app| {
            two_rooms_two_conversations(app);
            app.ui.set_startup_overlay_open(true);
            app.ui.set_join_open(true);
            app.ui.set_desktop_prompt_open(true);
            slint::platform::update_timers_and_animations();

            app.ui.set_startup_overlay_open(false);
            slint::platform::update_timers_and_animations();
            press(app, "e".into());
            assert_eq!(
                app.ui.get_join_phrase(),
                "",
                "the Join field took the keys from the dialog above it"
            );
        });
    }

    /// Fold the next join failure the network thread reports, the way the drain
    /// does, and return the circle it names, or `None` if none arrives within five
    /// seconds.
    fn fold_next_join_failure(app: &App) -> Option<u64> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let event = app
                .net
                .borrow_mut()
                .try_recv()
                .expect("the network thread is running");
            match event {
                Some(NetEvent::CircleJoinFailed { circle_id, reason }) => {
                    circle_join_failed(app, circle_id, &reason);
                    return Some(circle_id);
                }
                Some(_) => {}
                None => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }

    /// Joining the phrase of a circle whose join ended for good starts its join
    /// again: the circle shows that it is joining, and its join is sent once more.
    /// With no connection, each join ends for good.
    #[test]
    fn joining_the_phrase_of_a_failed_circle_joins_it_again() {
        with_app(|app| {
            let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
            let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
            app.ui.invoke_submit_join(phrase.into());
            let circle_id = fold_next_join_failure(app).expect("a join failure arrived");
            assert_eq!(
                room_join_failed(app),
                [false, true],
                "control: the join with no connection ended for good"
            );
            app.ui.invoke_switch_circle(0);

            app.ui.invoke_open_join();
            app.ui.invoke_submit_join(phrase.into());
            assert_eq!(app.ui.get_circles().row_count(), 2);
            assert_eq!(app.ui.get_active(), 1);
            assert_eq!(room_join_failed(app), [false, false], "the failure stayed");
            assert_eq!(room_joining(app), [false, true]);
            assert_eq!(
                fold_next_join_failure(app),
                Some(circle_id),
                "the join was not sent again"
            );
            assert_eq!(room_join_failed(app), [false, true]);
        });
    }

    /// A new connection clears every room's reach state, through the event the
    /// drain folds: the chat line and the row both go.
    #[test]
    fn a_new_connection_clears_the_reach_state() {
        use crate::net::RoomRecord;
        with_app(|app| {
            two_rooms_two_conversations(app);
            circle_joined(app, 1);
            app.ui.invoke_switch_circle(1);
            room_reach(app, RoomRecord::Circle(1), false);
            assert_ne!(app.ui.get_reach_room(), "", "control: the line shows");
            let row = app.ui.get_circles().row_data(1).expect("the circle row");
            assert!(row.unreachable, "control: the row shows unreachable");

            apply_net_event(&app.ui, &app.state, &app.browser, NetEvent::Connected);
            assert_eq!(app.ui.get_reach_room(), "");
            assert_eq!(app.ui.get_circles().row_count(), 3);
            assert!(app.ui.get_circles().iter().all(|c| !c.unreachable));
        });
    }

    /// Draws a circle whose join ended for good, as its chat tab and rail row show
    /// it, to `joining-shots` under the temporary directory. Run with `--ignored`.
    #[test]
    #[ignore = "writes PNG files; run on demand with --ignored"]
    fn join_failed_screenshots() {
        with_app(|app| {
            let dir = std::env::temp_dir().join("joining-shots");
            std::fs::create_dir_all(&dir).expect("create the shot directory");
            two_rooms_two_conversations(app);
            circle_joined(app, 2);
            app.ui.invoke_switch_circle(1);
            circle_join_failed(
                app,
                1,
                "subscribe failed: the network refused the record for good",
            );
            let path = dir.join("join-failed.png");
            render_png(&app.window, path.to_str().expect("a UTF-8 path"));
        });
    }
}
