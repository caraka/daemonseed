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

/// What the line under the Direct messages header says.
pub fn notice_text(notice: DmNotice) -> String {
    match notice {
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

/// The line under the thread: why nothing can be sent to a blocked person, or
/// why the last message, acceptance or block did not go.
fn thread_note(thread: &DmThreadView) -> &'static str {
    if thread.blocked {
        "You blocked them, so you can't send them messages."
    } else {
        thread.refusal.map_or("", refusal_text)
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

    use super::*;
    use crate::net::{NetEvent, RosterEntry};
    use crate::share_browser::ShareBrowser;
    use crate::{GuiPlatform, H, W, apply_net_event, build_ui, render_png};

    /// The window as production builds it, on the offscreen software platform,
    /// with the state it was built over.
    struct App {
        ui: AppWindow,
        state: Rc<RefCell<GuiState>>,
        browser: Rc<RefCell<ShareBrowser>>,
        window: Rc<MinimalSoftwareWindow>,
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
                let (ui, state, _net, browser) = build_ui(None);
                ui.show().expect("show");
                window.set_size(slint::PhysicalSize::new(W, H));
                f(&App {
                    ui,
                    state,
                    browser,
                    window,
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
    /// its sender's clock and its status. The captions age with time alone,
    /// with no new event, and a row whose time is unknown has only its status.
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
            });
            // Sent from another session: no time is known here.
            app.dm_event(RunnerEvent::Sent {
                token: daemonseed_veilid_net::dm::runner::CommandToken(999),
                peer,
                seq: 7,
            });
            assert_eq!(captions(app), ["3h", "now · sent", "sent"]);

            refresh_dm_ages(&app.ui, &app.state.borrow(), now + 2 * 3_600_000 + 60_000);
            assert_eq!(captions(app), ["5h", "2h · sent", "sent"]);
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
            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                [RunnerCommand::FirstContact { token, .. }] => *token,
                other => panic!("expected one first contact, got {other:?}"),
            };
            let cora = label();
            app.dm_event(RunnerEvent::Sent {
                token,
                peer: cora,
                seq: 0,
            });
            app.dm_event(RunnerEvent::Delivered {
                peer: cora,
                through_seq: 0,
            });
            app.dm_event(message(cora, 0, "Hello! Good to hear from you."));
            app.ui
                .invoke_send_dm("Are you coming to the meetup on Friday?".into());
            let token = match app.state.borrow_mut().take_pending_dm().as_slice() {
                [RunnerCommand::Send { token, .. }] => *token,
                other => panic!("expected one send, got {other:?}"),
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
        });
    }
}
