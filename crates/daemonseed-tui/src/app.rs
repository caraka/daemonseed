//! The TUI screen state machine.
//!
//! [`App`] holds all interactive state and advances only through
//! [`App::on_key`]. It performs no terminal I/O, so it is fully unit-testable
//! and deterministically driveable by the PTY gate harness.

use daemonseed_core::first_start::SessionMaterials;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::profile::config::ArgonParams;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::net::NetEvent;
use crate::screens::first_start::{FirstStartOutcome, FirstStartUi};

/// Live connection state shown in the main view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// No connection attempted yet.
    Disconnected,
    /// A connect is in flight (the net actor is working).
    Connecting,
    /// Reached Authenticated (ISC-47).
    Connected {
        server: String,
        version: String,
        rotation_notice: Option<String>,
    },
    /// The connect attempt failed; carries a human-readable cause.
    Failed(String),
}

/// A queued request for the binary to hand to the network actor. Returned by
/// [`App::take_pending_connect`] so `App` itself never touches the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub server_id: String,
    pub address: String,
    pub trusted: bool,
}

/// The top-level screen the TUI is currently showing.
///
/// Sub-screens (first-start steps, main-view tabs) are modelled by the later
/// M11 workstreams; this scaffold establishes the outer navigation skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// Landing screen shown on launch.
    Welcome,
    /// Cold first-start flow (passphrase → mnemonic → recovery → name →
    /// bootstrap). Expanded by the M11 first-start workstream.
    FirstStart,
    /// Post-first-start main view (chat / circles / shares / trust / servers).
    /// Expanded by the later M11 workstreams.
    Main,
}

/// One rendered chat line in the joined circle (ISC-10). `sent_unix_ms` is the
/// sender's advisory timestamp (`0` for the local echo of a just-sent message,
/// which the relay never reflects back to its sender).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLine {
    pub sender: String,
    pub body: String,
    pub sent_unix_ms: i64,
}

/// Which input on the [`Screen::Main`] view has keyboard focus. `Tab` cycles
/// Chat → JoinCircle → Mute → Servers → Chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainFocus {
    /// The chat compose box (default): typing composes, Enter sends (ISC-14).
    Chat,
    /// The circle-join phrase box: typing builds the phrase, Enter joins
    /// (ISC-15/16).
    JoinCircle,
    /// The mute box: type a full `name#hash` handle, Enter toggles it in the
    /// client-local mute set (ISC-13 / C15). The set never leaves this client
    /// (ISC-A-C3).
    Mute,
    /// The server-management screen (F22): add servers, set per-server trust
    /// mode with the trusted/untrusted slider (C22), and connect to a selected
    /// one (ISC-21/26/27). The main area shows the server list instead of chat.
    Servers,
}

/// One managed federation server in the server-management screen (F22 / C22).
/// `trusted` is the slider position: trusted = TOFU-pin on first contact,
/// untrusted = require a pre-imported operator key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedServer {
    pub server_id: String,
    pub address: String,
    pub trusted: bool,
}

/// State of the circle subscription shown on the main view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircleStatus {
    /// No circle joined yet.
    NotJoined,
    /// A join is in flight (the net actor is subscribing).
    Joining,
    /// Subscribed; chat can flow (ISC-16).
    Joined,
    /// The join failed; carries a human-readable cause.
    Failed(String),
}

/// A queued chat send for the binary to forward to the network actor. `body` is
/// the typed text; `sender_handle` is the user's own display handle, sealed into
/// the message for the recipient's client-side mention/mute (never seen by the
/// relay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatSend {
    pub body: String,
    pub sender_handle: String,
}

/// Interactive application state.
///
/// Construct with [`App::new`], feed key events with [`App::on_key`], render
/// from [`crate::ui`]. The event loop stops when [`App::should_quit`] is true.
pub struct App {
    screen: Screen,
    should_quit: bool,
    /// Argon2 params used when the user starts first-start. Production uses
    /// [`ArgonParams::desktop_default`]; tests inject fast params.
    argon: ArgonParams,
    /// Active first-start flow, present while on [`Screen::FirstStart`].
    first_start: Option<FirstStartUi>,
    /// Materials produced by a completed first-start, awaiting the connect path.
    session: Option<SessionMaterials>,
    /// Live connection state shown on the main view.
    connection: ConnectionStatus,
    /// A connect the binary should hand to the network actor (drained once).
    pending_connect: Option<ConnectRequest>,
    /// Which main-view input has focus (Tab toggles).
    main_focus: MainFocus,
    /// The chat compose buffer (ISC-14).
    compose: String,
    /// The circle-join phrase buffer (ISC-15).
    circle_phrase: String,
    /// Received + locally-echoed chat lines, oldest first (ISC-10).
    messages: Vec<ChatLine>,
    /// Current circle subscription state.
    circle_status: CircleStatus,
    /// A transient status/error line (e.g. a failed send).
    status: Option<String>,
    /// The mute-box input buffer (ISC-13).
    mute_input: String,
    /// Client-local muted full wire handles (ISC-13 / C15). Never leaves the
    /// client (ISC-A-C3); applied as a render-time suppression filter.
    muted: std::collections::BTreeSet<String>,
    /// Managed federation servers shown on the server-management screen (F22).
    servers: Vec<ManagedServer>,
    /// The add-server input buffer (`server-id@host:port`) (ISC-26).
    server_input: String,
    /// Index of the selected server in [`Self::servers`] (Up/Down moves it).
    server_sel: usize,
    /// A circle-join the binary should forward to the net actor (drained once).
    pending_join: Option<String>,
    /// A chat send the binary should forward to the net actor (drained once).
    pending_chat: Option<ChatSend>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// A freshly-launched app sitting on the [`Screen::Welcome`] landing screen,
    /// using production-strength Argon2 params for first-start sealing.
    pub fn new() -> Self {
        Self::with_argon(ArgonParams::desktop_default())
    }

    /// Construct with explicit Argon2 params — the test/gate entry point that
    /// keeps first-start sealing fast.
    pub fn with_argon(argon: ArgonParams) -> Self {
        Self {
            screen: Screen::Welcome,
            should_quit: false,
            argon,
            first_start: None,
            session: None,
            connection: ConnectionStatus::Disconnected,
            pending_connect: None,
            main_focus: MainFocus::Chat,
            compose: String::new(),
            circle_phrase: String::new(),
            messages: Vec::new(),
            circle_status: CircleStatus::NotJoined,
            status: None,
            mute_input: String::new(),
            muted: std::collections::BTreeSet::new(),
            servers: Vec::new(),
            server_input: String::new(),
            server_sel: 0,
            pending_join: None,
            pending_chat: None,
        }
    }

    /// The screen currently being displayed.
    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    /// Whether the event loop should stop and the terminal be restored.
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// The active first-start flow, for rendering. `Some` only on
    /// [`Screen::FirstStart`].
    pub fn first_start(&self) -> Option<&FirstStartUi> {
        self.first_start.as_ref()
    }

    /// Whether a completed first-start has produced session materials (the
    /// connect path consumes these in a later workstream).
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// The live connection status, for rendering the main view.
    pub fn connection(&self) -> &ConnectionStatus {
        &self.connection
    }

    /// Take a queued connect request, if any — the binary forwards it to the
    /// network actor. Clears the slot so it is handed off exactly once.
    pub fn take_pending_connect(&mut self) -> Option<ConnectRequest> {
        self.pending_connect.take()
    }

    /// Take a queued circle-join phrase (drained once by the binary).
    pub fn take_pending_join(&mut self) -> Option<String> {
        self.pending_join.take()
    }

    /// Take a queued chat send (drained once by the binary).
    pub fn take_pending_chat(&mut self) -> Option<ChatSend> {
        self.pending_chat.take()
    }

    /// Which main-view input has focus, for rendering.
    pub fn main_focus(&self) -> MainFocus {
        self.main_focus
    }

    /// The current chat compose buffer, for rendering.
    pub fn compose(&self) -> &str {
        &self.compose
    }

    /// The current circle-join phrase buffer, for rendering.
    pub fn circle_phrase(&self) -> &str {
        &self.circle_phrase
    }

    /// The chat lines, oldest first, for rendering (ISC-10).
    pub fn messages(&self) -> &[ChatLine] {
        &self.messages
    }

    /// The circle subscription status, for rendering.
    pub fn circle_status(&self) -> &CircleStatus {
        &self.circle_status
    }

    /// A transient status/error line, for rendering.
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Fold a network-actor event into UI state.
    pub fn on_net_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::Connected {
                server,
                version,
                rotation_notice,
            } => {
                self.connection = ConnectionStatus::Connected {
                    server,
                    version,
                    rotation_notice,
                };
            }
            NetEvent::ConnectFailed { message } => {
                self.connection = ConnectionStatus::Failed(message);
            }
            NetEvent::CircleJoined => self.circle_status = CircleStatus::Joined,
            NetEvent::CircleJoinFailed { message } => {
                self.circle_status = CircleStatus::Failed(message);
            }
            NetEvent::ChatMessage {
                sender,
                body,
                sent_unix_ms,
            } => self.messages.push(ChatLine {
                sender,
                body,
                sent_unix_ms,
            }),
            NetEvent::ChatError { message } => self.status = Some(message),
        }
    }

    /// The user's own full wire handle (`name#hash`), sealed into outgoing chat
    /// as the sender so recipients can @mention / mute it (ISC-C17/C15). Falls
    /// back to `"anon"` only if there is no session (pre-first-start).
    fn own_handle(&self) -> String {
        self.session
            .as_ref()
            .map(|s| s.handle.to_string())
            .unwrap_or_else(|| "anon".to_owned())
    }

    /// The user's own handle as a typed [`Handle`], for self-@mention detection
    /// at render (ISC-C17). `None` before first-start completes.
    pub fn own_chat_handle(&self) -> Option<Handle> {
        self.session.as_ref().map(|s| s.handle.clone())
    }

    /// Whether `sender` (a full wire handle) is in the client-local mute set
    /// (ISC-13). The render layer suppresses muted senders.
    pub fn is_muted(&self, sender: &str) -> bool {
        self.muted.contains(sender)
    }

    /// The current mute-box input buffer, for rendering.
    pub fn mute_input(&self) -> &str {
        &self.mute_input
    }

    /// The muted handles, for rendering the mute-box list.
    pub fn muted(&self) -> impl Iterator<Item = &str> {
        self.muted.iter().map(String::as_str)
    }

    /// The managed servers, for rendering the server-management screen (F22).
    pub fn servers(&self) -> &[ManagedServer] {
        &self.servers
    }

    /// The add-server input buffer, for rendering.
    pub fn server_input(&self) -> &str {
        &self.server_input
    }

    /// The selected server index, for highlighting in the server list.
    pub fn server_sel(&self) -> usize {
        self.server_sel
    }

    /// @-mention autocomplete candidates for the current compose buffer
    /// (ISC-12 / C18). When composing and the buffer ends with a partial
    /// `@token` (no whitespace after the last `@`), returns the full wire
    /// handles of in-scope members whose friendly form prefix-matches the
    /// token — a bare `@` lists everyone in scope. Scope is the set of handles
    /// seen as chat senders (the relay never exposes a roster — ISC-A-S2), so
    /// autocomplete only knows who has spoken. Excludes the user's own handle
    /// and muted handles. Empty unless focus is Chat with a live `@token`.
    pub fn mention_autocomplete(&self) -> Vec<String> {
        if self.main_focus != MainFocus::Chat {
            return Vec::new();
        }
        let Some(at) = self.compose.rfind('@') else {
            return Vec::new();
        };
        let token = &self.compose[at + 1..];
        if token.contains(char::is_whitespace) {
            return Vec::new();
        }
        let own = self.own_handle();
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for m in &self.messages {
            if m.sender == own || self.muted.contains(&m.sender) || !seen.insert(&m.sender) {
                continue;
            }
            let Ok(handle) = m.sender.parse::<Handle>() else {
                continue;
            };
            let friendly = handle.format(DisplayMode::Default);
            if token.is_empty() || friendly.starts_with(token) {
                out.push(handle.to_string());
            }
        }
        out
    }

    /// Advance state in response to a key press.
    ///
    /// Only [`KeyEventKind::Press`] events drive state — `crossterm` on Windows
    /// also emits `Release` and `Repeat` events, which must not double-fire a
    /// transition.
    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match self.screen {
            Screen::Welcome => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                KeyCode::Enter => {
                    self.first_start = Some(FirstStartUi::new(self.argon));
                    self.screen = Screen::FirstStart;
                }
                _ => {}
            },
            Screen::FirstStart => {
                if let Some(fs) = self.first_start.as_mut() {
                    match fs.on_key(key) {
                        Some(FirstStartOutcome::Completed) => {
                            let session = fs.take_completed();
                            // Queue a trusted-mode connect to the chosen bootstrap
                            // relay (C37 + C22 default-trusted for the canonical
                            // anchor). The binary drains this and drives the net actor.
                            if let Some(s) = session.as_ref() {
                                self.pending_connect = Some(ConnectRequest {
                                    server_id: s.bootstrap.server_id.clone(),
                                    address: s.bootstrap.address.clone(),
                                    trusted: true,
                                });
                                self.connection = ConnectionStatus::Connecting;
                            }
                            self.session = session;
                            self.first_start = None;
                            self.screen = Screen::Main;
                        }
                        Some(FirstStartOutcome::Cancelled) => {
                            self.first_start = None;
                            self.screen = Screen::Welcome;
                        }
                        None => {}
                    }
                }
            }
            Screen::Main => self.on_key_main(key),
        }
    }

    /// Key handling for the post-first-start main view: `Tab` toggles focus
    /// between the chat compose box and the circle-join box, `Esc` leaves to
    /// Welcome, and printable keys / Enter drive whichever input has focus.
    fn on_key_main(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Welcome,
            KeyCode::Tab => {
                self.main_focus = match self.main_focus {
                    MainFocus::Chat => MainFocus::JoinCircle,
                    MainFocus::JoinCircle => MainFocus::Mute,
                    MainFocus::Mute => MainFocus::Servers,
                    MainFocus::Servers => MainFocus::Chat,
                };
            }
            _ => match self.main_focus {
                MainFocus::Chat => self.on_key_chat(key),
                MainFocus::JoinCircle => self.on_key_join(key),
                MainFocus::Mute => self.on_key_mute(key),
                MainFocus::Servers => self.on_key_servers(key),
            },
        }
    }

    /// Chat compose: printable chars append, Backspace deletes, Enter sends a
    /// non-empty message (queues it for the net actor and locally echoes it,
    /// since the relay fans out to *other* members, never the sender) (ISC-14).
    fn on_key_chat(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.compose.push(c),
            KeyCode::Backspace => {
                self.compose.pop();
            }
            KeyCode::Enter if !self.compose.is_empty() => {
                let body = std::mem::take(&mut self.compose);
                let sender = self.own_handle();
                // Local echo: the relay never reflects a frame to its sender, so
                // the author's own client must show it.
                self.messages.push(ChatLine {
                    sender: sender.clone(),
                    body: body.clone(),
                    sent_unix_ms: 0,
                });
                self.pending_chat = Some(ChatSend {
                    body,
                    sender_handle: sender,
                });
            }
            _ => {}
        }
    }

    /// Circle-join input: printable chars append, Backspace deletes, Enter
    /// queues a join for a non-empty phrase and returns focus to chat
    /// (ISC-15/16).
    fn on_key_join(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.circle_phrase.push(c),
            KeyCode::Backspace => {
                self.circle_phrase.pop();
            }
            KeyCode::Enter if !self.circle_phrase.is_empty() => {
                let phrase = std::mem::take(&mut self.circle_phrase);
                self.pending_join = Some(phrase);
                self.circle_status = CircleStatus::Joining;
                self.main_focus = MainFocus::Chat;
            }
            _ => {}
        }
    }

    /// Mute input: printable chars append, Backspace deletes, Enter toggles the
    /// typed full wire handle in the client-local mute set (ISC-13). Muting is
    /// unilateral and silent — nothing is sent to the peer or relay (A-C3).
    fn on_key_mute(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.mute_input.push(c),
            KeyCode::Backspace => {
                self.mute_input.pop();
            }
            KeyCode::Enter if !self.mute_input.is_empty() => {
                let handle = std::mem::take(&mut self.mute_input);
                // Toggle: a second Enter on the same handle unmutes it.
                if !self.muted.remove(&handle) {
                    self.muted.insert(handle);
                }
            }
            _ => {}
        }
    }

    /// Server-management screen (F22 / C22): printable chars build the
    /// add-server input; Enter either adds a server (when the input is
    /// non-empty, ISC-26) or connects to the selected one (when the input is
    /// empty); Up/Down moves the selection; Left/Right slides the selected
    /// server's trust mode (ISC-21/27). The trusted/untrusted slider and the
    /// connect both reuse the existing trust + connect plumbing.
    fn on_key_servers(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.server_input.push(c),
            KeyCode::Backspace => {
                self.server_input.pop();
            }
            KeyCode::Up => self.server_sel = self.server_sel.saturating_sub(1),
            KeyCode::Down if !self.servers.is_empty() => {
                self.server_sel = (self.server_sel + 1).min(self.servers.len() - 1);
            }
            // The trust slider (ISC-21/27): Left = untrusted, Right = trusted.
            KeyCode::Left => {
                if let Some(s) = self.servers.get_mut(self.server_sel) {
                    s.trusted = false;
                }
            }
            KeyCode::Right => {
                if let Some(s) = self.servers.get_mut(self.server_sel) {
                    s.trusted = true;
                }
            }
            KeyCode::Enter if !self.server_input.is_empty() => {
                // Add a server (ISC-26): `server-id@host:port`.
                let raw = std::mem::take(&mut self.server_input);
                match raw.split_once('@') {
                    Some((id, addr)) if !id.is_empty() && !addr.is_empty() => {
                        self.servers.push(ManagedServer {
                            server_id: id.to_owned(),
                            address: addr.to_owned(),
                            trusted: true, // default to trusted (TOFU); slider adjusts
                        });
                        self.server_sel = self.servers.len() - 1;
                    }
                    _ => {
                        self.status = Some("server format: <server-id>@<host:port>".to_owned());
                        self.server_input = raw; // keep what they typed to fix
                    }
                }
            }
            KeyCode::Enter => {
                // Empty input + a selected server → connect to it, reusing the
                // existing pending-connect path with the slider's trust mode.
                if let Some(s) = self.servers.get(self.server_sel) {
                    self.pending_connect = Some(ConnectRequest {
                        server_id: s.server_id.clone(),
                        address: s.address.clone(),
                        trusted: s.trusted,
                    });
                    self.connection = ConnectionStatus::Connecting;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, ratatui::crossterm::event::KeyModifiers::NONE)
    }

    #[test]
    fn new_app_starts_on_welcome_and_running() {
        let app = App::new();
        assert_eq!(app.screen(), &Screen::Welcome);
        assert!(!app.should_quit());
    }

    #[test]
    fn q_on_welcome_quits() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Char('q')));
        assert!(app.should_quit(), "pressing q should request quit");
    }

    #[test]
    fn esc_on_welcome_quits() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Esc));
        assert!(app.should_quit(), "Esc on the landing screen should quit");
    }

    #[test]
    fn enter_on_welcome_advances_to_first_start() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.screen(), &Screen::FirstStart);
        assert!(!app.should_quit());
    }

    #[test]
    fn release_events_do_not_drive_state() {
        let mut app = App::new();
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            ratatui::crossterm::event::KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        app.on_key(release);
        assert!(!app.should_quit(), "key Release must not trigger quit");
    }

    #[test]
    fn full_first_start_flow_reaches_main_with_session() {
        let _ = oxicrypt_module::initialize();
        let fast = daemonseed_core::profile::config::ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let mut app = App::with_argon(fast);
        app.on_key(press(KeyCode::Enter)); // Welcome → FirstStart
        assert_eq!(app.screen(), &Screen::FirstStart);

        // Type a strong passphrase and seal.
        for ch in "correct horse battery staple table mountain".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = app
            .first_start()
            .and_then(|fs| fs.mnemonic())
            .expect("mnemonic shown")
            .to_string();
        app.on_key(press(KeyCode::Enter)); // → VerifyRoundTrip
        for ch in phrase.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → DisplayName (default prefilled)
        app.on_key(press(KeyCode::Enter)); // accept name → Bootstrap
        for ch in "relay#aabbccddeeff@127.0.0.1:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // finalize → Main

        assert_eq!(app.screen(), &Screen::Main);
        assert!(
            app.has_session(),
            "completed first-start should stash session materials"
        );
        assert!(
            app.first_start().is_none(),
            "first-start component cleared on completion"
        );

        // Completing first-start queues a trusted-mode connect to the bootstrap
        // relay and shows Connecting until the net actor reports back.
        assert_eq!(app.connection(), &ConnectionStatus::Connecting);
        let req = app
            .take_pending_connect()
            .expect("connect queued on completion");
        assert_eq!(req.server_id, "relay#aabbccddeeff");
        assert_eq!(req.address, "127.0.0.1:443");
        assert!(req.trusted);
        assert!(
            app.take_pending_connect().is_none(),
            "connect handed off exactly once"
        );
    }

    #[test]
    fn net_event_connected_sets_connected_status() {
        let mut app = App::new();
        app.on_net_event(NetEvent::Connected {
            server: "relay#aabbccddeeff".to_owned(),
            version: "1.0".to_owned(),
            rotation_notice: None,
        });
        assert_eq!(
            app.connection(),
            &ConnectionStatus::Connected {
                server: "relay#aabbccddeeff".to_owned(),
                version: "1.0".to_owned(),
                rotation_notice: None,
            }
        );
    }

    #[test]
    fn net_event_failed_sets_failed_status() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ConnectFailed {
            message: "tcp connect refused".to_owned(),
        });
        assert_eq!(
            app.connection(),
            &ConnectionStatus::Failed("tcp connect refused".to_owned())
        );
    }

    #[test]
    fn cancelling_first_start_returns_to_welcome() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Enter)); // → FirstStart
        app.on_key(press(KeyCode::Esc)); // cancel
        assert_eq!(app.screen(), &Screen::Welcome);
        assert!(app.first_start().is_none());
    }

    // ── Main view: circle chat (ISC-10 / 14 / 15 / 16) ───────────────────

    /// Drive the full fast-Argon first-start flow to land on the Main view with
    /// session materials, so chat-behaviour tests start from a connected-style
    /// state. Mirrors `full_first_start_flow_reaches_main_with_session`.
    fn drive_to_main() -> App {
        let _ = oxicrypt_module::initialize();
        let fast = daemonseed_core::profile::config::ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let mut app = App::with_argon(fast);
        app.on_key(press(KeyCode::Enter)); // Welcome → FirstStart
        for ch in "correct horse battery staple table mountain".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = app
            .first_start()
            .and_then(|fs| fs.mnemonic())
            .expect("mnemonic shown")
            .to_string();
        app.on_key(press(KeyCode::Enter)); // → VerifyRoundTrip
        for ch in phrase.chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // → DisplayName (default prefilled)
        app.on_key(press(KeyCode::Enter)); // accept → Bootstrap
        for ch in "relay#aabbccddeeff@127.0.0.1:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // finalize → Main
        // Drain the auto-queued bootstrap connect so it doesn't confuse tests.
        let _ = app.take_pending_connect();
        assert_eq!(app.screen(), &Screen::Main);
        app
    }

    #[test]
    fn chat_message_event_appends_to_transcript() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ChatMessage {
            sender: "otter#aabbccddeeff".to_owned(),
            body: "hello circle".to_owned(),
            sent_unix_ms: 7,
        });
        assert_eq!(app.messages().len(), 1);
        assert_eq!(app.messages()[0].sender, "otter#aabbccddeeff");
        assert_eq!(app.messages()[0].body, "hello circle");
    }

    #[test]
    fn circle_join_events_update_status() {
        let mut app = App::new();
        assert_eq!(app.circle_status(), &CircleStatus::NotJoined);
        app.on_net_event(NetEvent::CircleJoined);
        assert_eq!(app.circle_status(), &CircleStatus::Joined);
        app.on_net_event(NetEvent::CircleJoinFailed {
            message: "subscribe refused".to_owned(),
        });
        assert_eq!(
            app.circle_status(),
            &CircleStatus::Failed("subscribe refused".to_owned())
        );
    }

    #[test]
    fn tab_cycles_main_focus() {
        let mut app = drive_to_main();
        assert_eq!(app.main_focus(), MainFocus::Chat);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::JoinCircle);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Mute);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Servers);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Chat);
    }

    #[test]
    fn composing_and_sending_queues_chat_and_local_echoes() {
        let mut app = drive_to_main();
        for ch in "hi there".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        assert_eq!(app.compose(), "hi there");
        app.on_key(press(KeyCode::Enter));
        // Compose cleared, message locally echoed, send queued exactly once.
        assert_eq!(app.compose(), "");
        assert_eq!(app.messages().len(), 1, "sender sees their own message");
        assert_eq!(app.messages()[0].body, "hi there");
        let send = app.take_pending_chat().expect("chat queued on Enter");
        assert_eq!(send.body, "hi there");
        assert!(!send.sender_handle.is_empty());
        assert!(app.take_pending_chat().is_none(), "queued exactly once");
    }

    #[test]
    fn empty_compose_enter_is_a_noop() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Enter));
        assert!(app.messages().is_empty(), "no empty message echoed");
        assert!(app.take_pending_chat().is_none(), "no empty send queued");
    }

    #[test]
    fn joining_a_circle_queues_phrase_and_marks_joining() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Tab)); // focus → JoinCircle
        for ch in "correct horse battery staple".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        assert_eq!(app.circle_phrase(), "correct horse battery staple");
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.circle_status(), &CircleStatus::Joining);
        assert_eq!(app.main_focus(), MainFocus::Chat, "focus returns to chat");
        let phrase = app.take_pending_join().expect("join queued");
        assert_eq!(phrase, "correct horse battery staple");
        assert_eq!(app.circle_phrase(), "", "phrase buffer cleared");
        assert!(app.take_pending_join().is_none(), "queued exactly once");
    }

    #[test]
    fn chat_error_event_sets_status_line() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ChatError {
            message: "join a circle before sending".to_owned(),
        });
        assert_eq!(app.status(), Some("join a circle before sending"));
    }

    /// Flatten a TestBackend buffer to a string for `.contains` assertions.
    fn buffer_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    /// The Main view actually renders (real render path via TestBackend): a
    /// folded chat message appears in the transcript, and the compose footer is
    /// shown. Catches layout panics on a realistic terminal size too.
    #[test]
    fn main_view_renders_chat_transcript_and_compose() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = drive_to_main();
        app.on_net_event(NetEvent::Connected {
            server: "relay#aabbccddeeff".to_owned(),
            version: "1.0".to_owned(),
            rotation_notice: None,
        });
        app.on_net_event(NetEvent::CircleJoined);
        app.on_net_event(NetEvent::ChatMessage {
            sender: "otter".to_owned(),
            body: "ping".to_owned(),
            sent_unix_ms: 1,
        });

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);

        assert!(text.contains("otter: ping"), "transcript line rendered");
        assert!(text.contains("circle joined"), "circle status shown");
        assert!(text.contains("compose"), "compose footer shown");
    }

    // ── @mention (ISC-11/12) + mute (ISC-13) ─────────────────────────────

    #[test]
    fn muting_a_handle_toggles() {
        let mut app = drive_to_main();
        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // JoinCircle → Mute
        assert_eq!(app.main_focus(), MainFocus::Mute);
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.is_muted("spammer#aabbccddeeff"), "muted after toggle");
        // Re-typing the same handle and Enter unmutes (toggle).
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(
            !app.is_muted("spammer#aabbccddeeff"),
            "unmuted on re-toggle"
        );
    }

    #[test]
    fn muted_sender_suppressed_in_transcript() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = drive_to_main();
        app.on_net_event(NetEvent::ChatMessage {
            sender: "spammer#aabbccddeeff".to_owned(),
            body: "BUYNOW spam".to_owned(),
            sent_unix_ms: 1,
        });
        app.on_net_event(NetEvent::ChatMessage {
            sender: "friend#ccddeeff0011".to_owned(),
            body: "genuine hello".to_owned(),
            sent_unix_ms: 2,
        });
        // Mute the spammer.
        app.on_key(press(KeyCode::Tab));
        app.on_key(press(KeyCode::Tab)); // → Mute focus
        for ch in "spammer#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);
        assert!(
            !text.contains("BUYNOW spam"),
            "muted sender suppressed (ISC-13)"
        );
        assert!(text.contains("genuine hello"), "non-muted message kept");
    }

    #[test]
    fn self_mention_is_highlighted() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use ratatui::style::Color;

        // One app / one identity throughout (separate drive_to_main calls each
        // generate a different mnemonic → different handle, which would not
        // match the mention).
        let mut app = drive_to_main();
        let own = app.own_chat_handle().expect("session handle").to_string();

        let yellow_cells = |app: &App| -> usize {
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| crate::ui::render(app, f)).unwrap();
            term.backend()
                .buffer()
                .content()
                .iter()
                .filter(|c| c.fg == Color::Yellow)
                .count()
        };

        // Baseline: a message that does NOT mention us (the connecting-status
        // line may already be yellow — we measure the delta, not absolute).
        app.on_net_event(NetEvent::ChatMessage {
            sender: "friend#ccddeeff0011".to_owned(),
            body: "nothing to see".to_owned(),
            sent_unix_ms: 1,
        });
        let baseline = yellow_cells(&app);

        // Now a message that mentions our own full handle.
        app.on_net_event(NetEvent::ChatMessage {
            sender: "friend#ccddeeff0011".to_owned(),
            body: format!("hey @{own} look here"),
            sent_unix_ms: 2,
        });
        assert!(
            yellow_cells(&app) > baseline,
            "a self-mention highlights its span yellow (ISC-11)"
        );
    }

    // ── server management + trust slider (ISC-21/26/27) ─────────────────

    /// Navigate to the Servers screen via the Tab cycle.
    fn to_servers(app: &mut App) {
        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // → Mute
        app.on_key(press(KeyCode::Tab)); // → Servers
        assert_eq!(app.main_focus(), MainFocus::Servers);
    }

    #[test]
    fn adding_a_server_appends_trusted_by_default() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@10.0.0.5:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // add (ISC-26)
        assert_eq!(app.servers().len(), 1);
        assert_eq!(app.servers()[0].server_id, "relay#aabbccddeeff");
        assert_eq!(app.servers()[0].address, "10.0.0.5:443");
        assert!(app.servers()[0].trusted, "new server defaults to trusted");
        assert_eq!(app.server_input(), "", "input cleared after add");
    }

    #[test]
    fn malformed_server_input_is_rejected_with_status() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "no-at-sign".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.servers().is_empty(), "malformed entry not added");
        assert!(app.status().is_some(), "error surfaced");
        assert_eq!(app.server_input(), "no-at-sign", "input kept to fix");
    }

    #[test]
    fn left_right_slider_sets_per_server_trust_mode() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@host:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // add (trusted by default)
        assert!(app.servers()[0].trusted);
        app.on_key(press(KeyCode::Left)); // slide → untrusted (ISC-21/27)
        assert!(!app.servers()[0].trusted);
        app.on_key(press(KeyCode::Right)); // slide → trusted
        assert!(app.servers()[0].trusted);
    }

    #[test]
    fn up_down_moves_server_selection() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for id in ["a#aabbccddeeff@h:1", "b#ccddeeff0011@h:2"] {
            for ch in id.chars() {
                app.on_key(press(KeyCode::Char(ch)));
            }
            app.on_key(press(KeyCode::Enter));
        }
        assert_eq!(app.server_sel(), 1, "selection follows the last-added");
        app.on_key(press(KeyCode::Up));
        assert_eq!(app.server_sel(), 0);
        app.on_key(press(KeyCode::Up)); // saturates
        assert_eq!(app.server_sel(), 0);
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.server_sel(), 1);
    }

    #[test]
    fn enter_on_selected_server_with_empty_input_connects() {
        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@10.0.0.5:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter)); // add (input now empty)
        let _ = app.take_pending_connect(); // ignore any prior
        app.on_key(press(KeyCode::Enter)); // empty input + selected → connect
        assert_eq!(app.connection(), &ConnectionStatus::Connecting);
        let req = app.take_pending_connect().expect("connect queued");
        assert_eq!(req.server_id, "relay#aabbccddeeff");
        assert_eq!(req.address, "10.0.0.5:443");
        assert!(req.trusted);
    }

    #[test]
    fn server_list_renders_with_slider_and_selection() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = drive_to_main();
        to_servers(&mut app);
        for ch in "relay#aabbccddeeff@10.0.0.5:443".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));

        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| crate::ui::render(&app, f)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("relay#aabbccddeeff"), "server id rendered");
        assert!(text.contains("TRUSTED"), "trust slider rendered");
    }

    #[test]
    fn mention_autocomplete_prefix_matches_seen_senders() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::ChatMessage {
            sender: "alice#aabbccddeeff".to_owned(),
            body: "hi".to_owned(),
            sent_unix_ms: 1,
        });
        app.on_net_event(NetEvent::ChatMessage {
            sender: "bob#ccddeeff0011".to_owned(),
            body: "yo".to_owned(),
            sent_unix_ms: 2,
        });
        // Compose a partial mention "@al".
        for ch in "@al".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        let suggestions = app.mention_autocomplete();
        assert!(
            suggestions.contains(&"alice#aabbccddeeff".to_owned()),
            "alice prefix-matches @al; got {suggestions:?}"
        );
        assert!(
            !suggestions.contains(&"bob#ccddeeff0011".to_owned()),
            "bob does not prefix-match @al"
        );
    }
}
