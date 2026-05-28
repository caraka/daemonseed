//! The TUI screen state machine.
//!
//! [`App`] holds all interactive state and advances only through
//! [`App::on_key`]. It performs no terminal I/O, so it is fully unit-testable
//! and deterministically driveable by the PTY gate harness.

use daemonseed_core::backoff::CloseCause;
use daemonseed_core::first_start::SessionMaterials;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::trust_events::{
    DismissalScope, TrustEvent, TrustEventClass, TrustEventKey, TrustEventLog, class_of,
};
use daemonseed_proto::v1 as wire;
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
/// Chat → JoinCircle → Mute → Shares → Hide → Servers → TrustHistory → Chat.
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
    /// The Shares view (ISC-17 / ISC-20): two panes — local files indexed by
    /// the user's own [`daemonseed_core::indexer::Indexer`] (My shares), and
    /// the remote [`wire::PublicShareListing`] snapshot fetched from the
    /// connected relay (Public shares). Up/Down navigates the public-shares
    /// rows, `r` requests a fresh snapshot, `f` (later) initiates a fetch
    /// (ISC-19). The indexer status line at the top of My-shares stays
    /// non-blocking during a cold scan (ISC-A-C7).
    Shares,
    /// The Hide box: type a full `name#hash` handle, Enter toggles it in the
    /// client-local hidden-shares set (ISC-18 / C16). The set never leaves
    /// this client (ISC-A-C3) — there is no wire field carrying it — and is
    /// applied as a render-time filter to the Public shares pane. Main area
    /// stays on the Shares view.
    Hide,
    /// The server-management screen (F22): add servers, set per-server trust
    /// mode with the trusted/untrusted slider (C22), and connect to a selected
    /// one (ISC-21/26/27). The main area shows the server list instead of chat.
    Servers,
    /// The Trust History view (ISC-C28 LogOnly surface, ISC-25): a scrollable
    /// list of every recorded trust event. Up/Down select, Enter dismisses the
    /// selected event's affordance per `(key, scope)` (ISC-A-C12 — no global
    /// dismissal). The main area shows the history instead of chat.
    TrustHistory,
}

/// One indexed file in the user's own share, as rendered in the My-shares
/// pane (ISC-17 / ISC-C21). A render-only projection of
/// [`daemonseed_core::storage::share_index::ShareEntry`] kept local to the
/// TUI so [`App`] does not depend on the redb-backed concrete type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalShareRow {
    /// Path relative to the share root.
    pub rel_path: String,
    /// File size in bytes.
    pub size: u64,
    /// Last-modified time, milliseconds since the Unix epoch.
    pub mtime_unix_ms: u64,
}

/// Indexer state as seen by the TUI (ISC-20 / ISC-A-C7). The line at the top
/// of the My-shares pane reflects whichever state the net actor last emitted;
/// transitions never gate user input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexerStatus {
    /// No share root configured, or the indexer has not started yet.
    Idle,
    /// A cold or incremental scan is in flight. `seen` is the running file
    /// count; `total` is `None` while the walk has not finished — the cold
    /// scan does not know the total ahead of time, by design (single-pass).
    Indexing { seen: u64, total: Option<u64> },
    /// The indexer is up-to-date with the last scan; `entries` is the size
    /// of the persisted index (ISC-C21 cross-launch persistence).
    Ready { entries: u64 },
}

/// A surfaced trust event awaiting user attention (ISC-C28). The `key` selects
/// the affordance class via [`class_of`]; `server_id` scopes dismissal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustItem {
    pub key: TrustEventKey,
    pub server_id: Option<String>,
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
    /// The bounded, per-session trust-event audit log (ISC-C28). Every recorded
    /// event surfaces in the Trust History view; Transient events are dropped by
    /// [`TrustEventLog::append`] (the ISC-A-C12 asymmetry).
    trust_log: TrustEventLog,
    /// The active Blocking trust event, shown as a modal that captures input
    /// until acknowledged (ISC-22 / C28 Blocking class).
    blocking: Option<TrustItem>,
    /// Undismissed PersistentNonBlocking trust events, shown as status-bar badges
    /// (ISC-23 / C28 Persistent class).
    persistent: Vec<TrustItem>,
    /// The most recent Transient trust event, shown as a toast until the next key
    /// press (ISC-24 / C28 Transient class).
    transient: Option<TrustItem>,
    /// The last observed connection close layer (ISC-28 / C26), for the distinct
    /// close-cause status rendering.
    close_cause: Option<CloseCause>,
    /// Selected row in the Trust History view (Up/Down moves it).
    history_sel: usize,
    /// Latest My-shares snapshot from the net actor (ISC-17).
    local_shares: Vec<LocalShareRow>,
    /// Latest Public-shares snapshot from the net actor (ISC-17 / ISC-18).
    /// Pre-filter; the hide set is applied at render time (ISC-A-C3 keeps the
    /// hide set off the wire — there is nothing for the relay to know).
    public_shares: Vec<wire::PublicShareListing>,
    /// Current indexer status, surfaced non-blocking at the top of the
    /// My-shares pane (ISC-20 / ISC-A-C7).
    indexer_status: IndexerStatus,
    /// Client-local hidden-share full wire handles (ISC-18 / C16). Applied as
    /// a render-time filter on [`Self::public_shares`] via
    /// [`daemonseed_cli::public_space::filter_shares_excluding_hidden`]. Never
    /// leaves the client (ISC-A-C3): no wire field carries it. The persisted
    /// home for this set is [`daemonseed_core::storage::seeds::Seeds::hidden_shares`];
    /// session-scoped here pending the .dseed write-through path (ISC-5 partial).
    hidden_shares: std::collections::BTreeSet<String>,
    /// The hide-box input buffer (ISC-18).
    hide_input: String,
    /// Selected row index in the Public-shares pane (Up/Down moves it). Will
    /// be the fetch target once ISC-19 lands.
    share_sel: usize,
    /// A queued shares-refresh the binary should forward to the net actor
    /// (drained once). `true` means "the user pressed R" or "the screen just
    /// opened"; the binary translates this into a `NetCommand::RefreshShares`.
    pending_share_refresh: bool,
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
            trust_log: TrustEventLog::default(),
            blocking: None,
            persistent: Vec::new(),
            transient: None,
            close_cause: None,
            history_sel: 0,
            local_shares: Vec::new(),
            public_shares: Vec::new(),
            indexer_status: IndexerStatus::Idle,
            hidden_shares: std::collections::BTreeSet::new(),
            hide_input: String::new(),
            share_sel: 0,
            pending_share_refresh: false,
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
            NetEvent::TrustEvent { key, server_id } => self.fold_trust_event(key, server_id),
            NetEvent::ConnectionClosed { cause } => self.close_cause = Some(cause),
            NetEvent::SharesSnapshot {
                local,
                remote,
                indexer_status,
            } => {
                self.local_shares = local;
                self.public_shares = remote;
                self.indexer_status = indexer_status;
                // Clamp the selection so it never points past the new list.
                let max_idx = self.public_shares.len().saturating_sub(1);
                if self.share_sel > max_idx {
                    self.share_sel = max_idx;
                }
            }
            NetEvent::SharesError { message } => self.status = Some(message),
        }
    }

    /// Route a trust event to its ISC-C28 affordance class and record it
    /// (Transient events are dropped from the log by [`TrustEventLog::append`] —
    /// the intentional A-C12 asymmetry — but still drive the toast slot).
    fn fold_trust_event(&mut self, key: TrustEventKey, server_id: Option<String>) {
        self.trust_log.append(TrustEvent::observed(
            now_unix_ms(),
            key,
            server_id.clone(),
            None,
        ));
        let item = TrustItem { key, server_id };
        match class_of(key) {
            TrustEventClass::Blocking => self.blocking = Some(item),
            TrustEventClass::PersistentNonBlocking => {
                if !self.persistent.contains(&item) {
                    self.persistent.push(item);
                }
            }
            TrustEventClass::Transient => self.transient = Some(item),
            // LogOnly surfaces only in the Trust History view (already logged).
            TrustEventClass::LogOnly => {}
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

    /// The active Blocking trust event, for rendering the modal (ISC-22).
    pub fn blocking_trust(&self) -> Option<&TrustItem> {
        self.blocking.as_ref()
    }

    /// Undismissed PersistentNonBlocking trust events, for the status-bar badges
    /// (ISC-23).
    pub fn persistent_trust(&self) -> &[TrustItem] {
        &self.persistent
    }

    /// The current Transient trust toast, if any (ISC-24).
    pub fn transient_trust(&self) -> Option<&TrustItem> {
        self.transient.as_ref()
    }

    /// The trust-event audit log, for the Trust History view (ISC-25).
    pub fn trust_log(&self) -> &TrustEventLog {
        &self.trust_log
    }

    /// The last observed connection-close layer, for the distinct close-cause
    /// status rendering (ISC-28).
    pub fn close_cause(&self) -> Option<CloseCause> {
        self.close_cause
    }

    /// The selected row in the Trust History view (newest-first index).
    pub fn history_sel(&self) -> usize {
        self.history_sel
    }

    /// Latest My-shares snapshot (ISC-17), oldest first.
    pub fn local_shares(&self) -> &[LocalShareRow] {
        &self.local_shares
    }

    /// Public-share rows after the hidden-shares filter (ISC-17 / ISC-18).
    /// Mirrors [`daemonseed_cli::public_space::filter_shares_excluding_hidden`]
    /// in the cli crate; duplicated here as a thin borrow-respecting helper so
    /// `App` does not depend on cli's public surface from its own renderer.
    /// Listings with an empty `sharer_handle` (legacy / operator-pinned) are
    /// always kept (no handle to filter against).
    pub fn visible_public_shares(&self) -> Vec<&wire::PublicShareListing> {
        self.public_shares
            .iter()
            .filter(|s| {
                s.sharer_handle.is_empty() || !self.hidden_shares.contains(&s.sharer_handle)
            })
            .collect()
    }

    /// Size of [`Self::visible_public_shares`] without materialising the Vec.
    fn visible_public_shares_count(&self) -> usize {
        self.public_shares
            .iter()
            .filter(|s| {
                s.sharer_handle.is_empty() || !self.hidden_shares.contains(&s.sharer_handle)
            })
            .count()
    }

    /// Raw public-share snapshot, pre-filter, for tests that need to assert on
    /// what arrived from the relay vs what renders.
    pub fn public_shares_raw(&self) -> &[wire::PublicShareListing] {
        &self.public_shares
    }

    /// Current indexer status (ISC-20), for the My-shares pane's status line.
    pub fn indexer_status(&self) -> &IndexerStatus {
        &self.indexer_status
    }

    /// Whether `sharer` (a full wire handle) is on the client-local hide set
    /// (ISC-18 / C16).
    pub fn is_share_hidden(&self, sharer: &str) -> bool {
        self.hidden_shares.contains(sharer)
    }

    /// The hide-box input buffer, for rendering.
    pub fn hide_input(&self) -> &str {
        &self.hide_input
    }

    /// The hidden-share handles, for rendering the hide-box list.
    pub fn hidden_shares(&self) -> impl Iterator<Item = &str> {
        self.hidden_shares.iter().map(String::as_str)
    }

    /// The selected public-share row index, for highlighting.
    pub fn share_sel(&self) -> usize {
        self.share_sel
    }

    /// Take a queued shares-refresh request (drained once by the binary, which
    /// translates it into a `NetCommand::RefreshShares`).
    pub fn take_pending_share_refresh(&mut self) -> bool {
        std::mem::replace(&mut self.pending_share_refresh, false)
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
        // A Transient trust toast auto-dismisses on the next interaction
        // (ISC-24 / C28 Transient class).
        self.transient = None;
        // A Blocking trust event captures all input on the main view until the
        // user acknowledges it (ISC-22 / C28 Blocking class — "prevents the
        // affected functional path until the user acts"). Acknowledgement
        // records a per-`(key, scope)` dismissal (ISC-A-C12).
        if self.screen == Screen::Main && self.blocking.is_some() {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                let item = self.blocking.take().expect("checked is_some");
                self.trust_log.dismiss(
                    item.key,
                    &DismissalScope {
                        server_id: item.server_id,
                        suite_id: None,
                    },
                    now_unix_ms(),
                );
            }
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
                    MainFocus::Mute => MainFocus::Shares,
                    MainFocus::Shares => MainFocus::Hide,
                    MainFocus::Hide => MainFocus::Servers,
                    MainFocus::Servers => MainFocus::TrustHistory,
                    MainFocus::TrustHistory => MainFocus::Chat,
                };
                // Opening the Shares pane requests a fresh snapshot — the
                // alpha gate harness drives this through `RefreshShares` so
                // the screen is never accidentally empty on first view.
                if matches!(self.main_focus, MainFocus::Shares | MainFocus::Hide) {
                    self.pending_share_refresh = true;
                }
            }
            _ => match self.main_focus {
                MainFocus::Chat => self.on_key_chat(key),
                MainFocus::JoinCircle => self.on_key_join(key),
                MainFocus::Mute => self.on_key_mute(key),
                MainFocus::Shares => self.on_key_shares(key),
                MainFocus::Hide => self.on_key_hide(key),
                MainFocus::Servers => self.on_key_servers(key),
                MainFocus::TrustHistory => self.on_key_history(key),
            },
        }
    }

    /// Shares-pane key handling (read-only display, ISC-17 / ISC-20).
    ///
    /// `Up` / `Down` move the public-shares selection (clamped to the visible,
    /// hide-filtered subset so a hidden row can never be highlighted); `r`
    /// requests a fresh snapshot. Fetch (`f`) is wired by ISC-19 in a later
    /// commit.
    fn on_key_shares(&mut self, key: KeyEvent) {
        let visible = self.visible_public_shares_count();
        match key.code {
            KeyCode::Up => {
                self.share_sel = self.share_sel.saturating_sub(1);
            }
            KeyCode::Down => {
                let max = visible.saturating_sub(1);
                if self.share_sel < max {
                    self.share_sel += 1;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.pending_share_refresh = true;
            }
            _ => {}
        }
    }

    /// Hide-box key handling (ISC-18 / C16). Typing edits [`Self::hide_input`];
    /// Enter on a non-empty buffer toggles the handle in
    /// [`Self::hidden_shares`] (set membership), then clears the input. The
    /// set is session-scoped here pending the .dseed write-through (ISC-5
    /// partial); on toggle, render-time filtering picks the change up
    /// immediately because [`Self::visible_public_shares`] reads
    /// [`Self::hidden_shares`] each time.
    fn on_key_hide(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => self.hide_input.push(c),
            KeyCode::Backspace => {
                self.hide_input.pop();
            }
            KeyCode::Enter if !self.hide_input.is_empty() => {
                let handle = std::mem::take(&mut self.hide_input);
                // Reject line-breaks for parity with `Seeds::add_hidden_share`
                // (blob-integrity guard); a well-formed wire handle never has
                // one, but a paste of "garbage\nmore" must not corrupt the
                // future seeds-blob round-trip.
                if handle.contains(['\n', '\r']) {
                    self.status = Some("hide handle rejected: line break".to_owned());
                    return;
                }
                if !self.hidden_shares.remove(&handle) {
                    self.hidden_shares.insert(handle);
                }
                // Re-clamp selection — the visible subset may have shrunk.
                let max = self.visible_public_shares_count().saturating_sub(1);
                if self.share_sel > max {
                    self.share_sel = max;
                }
            }
            _ => {}
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

    /// Trust History view (ISC-25 / C28): Up/Down move the selection (rows render
    /// newest-first), Enter dismisses the selected event's affordance per
    /// `(key, scope)` (ISC-A-C12 — dismissal is scoped, never global, and never
    /// removes the log entry).
    fn on_key_history(&mut self, key: KeyEvent) {
        let rows = self.trust_log.len();
        match key.code {
            KeyCode::Up => self.history_sel = self.history_sel.saturating_sub(1),
            KeyCode::Down if rows > 0 => {
                self.history_sel = (self.history_sel + 1).min(rows - 1);
            }
            KeyCode::Enter if rows > 0 => {
                // Map the newest-first selection back to the log entry, then
                // release the immutable borrow before the mutable dismiss.
                let (dkey, scope) = {
                    let entries = self.trust_log.entries();
                    let idx = rows - 1 - self.history_sel.min(rows - 1);
                    let e = &entries[idx];
                    (
                        e.key,
                        DismissalScope {
                            server_id: e.server_id.clone(),
                            suite_id: e.suite_id,
                        },
                    )
                };
                self.trust_log.dismiss(dkey, &scope, now_unix_ms());
                self.persistent
                    .retain(|it| !(it.key == dkey && it.server_id == scope.server_id));
            }
            _ => {}
        }
    }
}

/// Wall-clock now in unix milliseconds, for trust-event log timestamps. The
/// Trust History view renders stable key strings, not raw timestamps, so this
/// does not affect render determinism.
fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
        assert_eq!(app.main_focus(), MainFocus::Shares);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Hide);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Servers);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::TrustHistory);
        app.on_key(press(KeyCode::Tab));
        assert_eq!(app.main_focus(), MainFocus::Chat);
    }

    // ── C28 trust-event affordance routing (ISC-22..25 / 28) ─────────────

    /// A Blocking trust event populates the modal slot, captures input until
    /// acknowledged, and Enter records a dismissal without removing the log
    /// entry (ISC-22 / A-C12).
    #[test]
    fn blocking_trust_event_modal_captures_then_dismisses() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyMismatch,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert!(
            app.blocking_trust().is_some(),
            "blocking modal set (ISC-22)"
        );
        // While the modal is up, a chat keystroke must NOT compose.
        app.on_key(press(KeyCode::Char('x')));
        assert_eq!(app.compose(), "", "modal captures input until acknowledged");
        assert!(app.blocking_trust().is_some(), "non-ack key keeps modal up");
        // Enter acknowledges and clears the modal; the log entry survives.
        app.on_key(press(KeyCode::Enter));
        assert!(app.blocking_trust().is_none(), "Enter dismisses the modal");
        assert_eq!(app.trust_log().len(), 1, "dismissal keeps the log entry");
        assert!(
            app.trust_log().entries()[0].dismissed_at_unix_ms.is_some(),
            "entry marked dismissed"
        );
    }

    /// A PersistentNonBlocking event appears as a status badge and is logged
    /// (ISC-23).
    #[test]
    fn persistent_trust_event_badges_and_logs() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert_eq!(app.persistent_trust().len(), 1, "badge surfaced (ISC-23)");
        assert_eq!(app.trust_log().len(), 1, "persistent event is logged");
        // The same event again does not duplicate the badge.
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert_eq!(app.persistent_trust().len(), 1, "no duplicate badge");
    }

    /// A Transient event is a toast that is NOT logged (the A-C12 asymmetry) and
    /// auto-dismisses on the next key press (ISC-24).
    #[test]
    fn transient_trust_event_toasts_then_clears_and_is_not_logged() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ConnectionRateLimited,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert!(app.transient_trust().is_some(), "toast surfaced (ISC-24)");
        assert_eq!(app.trust_log().len(), 0, "transient is not logged (A-C12)");
        app.on_key(press(KeyCode::Char('a')));
        assert!(
            app.transient_trust().is_none(),
            "toast auto-dismisses on key"
        );
    }

    /// A LogOnly event surfaces only in the audit log — no modal, badge, or toast
    /// (ISC-25, the Trust History surface).
    #[test]
    fn logonly_trust_event_only_in_history() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerSourceUnverified,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert!(app.blocking_trust().is_none());
        assert!(app.persistent_trust().is_empty());
        assert!(app.transient_trust().is_none());
        assert_eq!(
            app.trust_log().len(),
            1,
            "recorded in Trust History (ISC-25)"
        );
    }

    /// A ConnectionClosed event records its observable close layer (ISC-28).
    #[test]
    fn connection_closed_sets_close_cause() {
        let mut app = App::new();
        app.on_net_event(NetEvent::ConnectionClosed {
            cause: CloseCause::RefusedBeforeHelloAck,
        });
        assert_eq!(app.close_cause(), Some(CloseCause::RefusedBeforeHelloAck));
    }

    /// Trust History selection moves with Up/Down and Enter dismisses the
    /// selected event's persistent badge per scope (ISC-25 / A-C12).
    #[test]
    fn trust_history_enter_dismisses_selected_persistent_badge() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        assert_eq!(app.persistent_trust().len(), 1);
        // Tab to the Trust History view and dismiss the selected (only) row.
        app.on_key(press(KeyCode::Tab)); // → JoinCircle
        app.on_key(press(KeyCode::Tab)); // → Mute
        app.on_key(press(KeyCode::Tab)); // → Shares
        app.on_key(press(KeyCode::Tab)); // → Hide
        app.on_key(press(KeyCode::Tab)); // → Servers
        app.on_key(press(KeyCode::Tab)); // → TrustHistory
        assert_eq!(app.main_focus(), MainFocus::TrustHistory);
        app.on_key(press(KeyCode::Enter));
        assert!(
            app.persistent_trust().is_empty(),
            "dismissing clears the badge"
        );
        assert_eq!(app.trust_log().len(), 1, "log entry survives dismissal");
    }

    // ── C28 render paths (ISC-22..25 / 28), real ui::render via TestBackend ──

    fn render_text(app: &App, w: u16, h: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::render(app, f)).unwrap();
        buffer_text(&term)
    }

    /// ISC-22: a Blocking trust event renders as a modal overlay.
    #[test]
    fn blocking_trust_renders_modal() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyMismatch,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        let text = render_text(&app, 80, 24);
        assert!(text.contains("security warning"), "modal title rendered");
        assert!(
            text.contains("Server key does not match"),
            "modal body rendered"
        );
    }

    /// ISC-23: a PersistentNonBlocking event renders as a status-bar badge.
    #[test]
    fn persistent_trust_renders_status_badge() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerKeyRotated,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        let text = render_text(&app, 120, 24);
        assert!(
            text.contains("server-key-rotated"),
            "badge rendered in status"
        );
    }

    /// ISC-24: a Transient event renders as a toast.
    #[test]
    fn transient_trust_renders_toast() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ConnectionRateLimited,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        let text = render_text(&app, 80, 24);
        assert!(text.contains("backing off"), "toast rendered");
    }

    /// ISC-25: a LogOnly event renders in the scrollable Trust History view.
    #[test]
    fn logonly_trust_renders_in_history_view() {
        let mut app = drive_to_main();
        app.on_net_event(NetEvent::TrustEvent {
            key: TrustEventKey::ServerSourceUnverified,
            server_id: Some("relay#aabbccddeeff".to_owned()),
        });
        // Tab to the Trust History view (6 hops past Chat → … → TrustHistory).
        for _ in 0..6 {
            app.on_key(press(KeyCode::Tab));
        }
        assert_eq!(app.main_focus(), MainFocus::TrustHistory);
        let text = render_text(&app, 80, 24);
        assert!(text.contains("trust history"), "history view titled");
        assert!(
            text.contains("server-source-unverified"),
            "LogOnly event listed (ISC-25)"
        );
    }

    /// ISC-28: each of the three close-cause layers renders a distinct message.
    #[test]
    fn close_cause_renders_three_distinct_states() {
        let causes = [
            (CloseCause::NetworkFailure, "Unable to reach server"),
            (
                CloseCause::RefusedBeforeHelloAck,
                "Server refused the connection",
            ),
            (
                CloseCause::ClosedAfterAuth,
                "Server closed the connection unexpectedly",
            ),
        ];
        for (cause, msg) in causes {
            let mut app = drive_to_main();
            app.on_net_event(NetEvent::ConnectionClosed { cause });
            let text = render_text(&app, 120, 24);
            assert!(text.contains(msg), "{cause:?} renders its distinct message");
        }
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
        app.on_key(press(KeyCode::Tab)); // → Shares
        app.on_key(press(KeyCode::Tab)); // → Hide
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

    // ── Shares pane (ISC-17 / ISC-18 / ISC-20) ─────────────────────────────

    fn listing(share_id: &str, name: &str, rating: &str, sharer: &str) -> wire::PublicShareListing {
        wire::PublicShareListing {
            share_id: share_id.to_owned(),
            name: name.to_owned(),
            rating: rating.to_owned(),
            sharer_handle: sharer.to_owned(),
        }
    }

    fn to_shares(app: &mut App) {
        app.on_key(press(KeyCode::Tab)); // Chat → JoinCircle
        app.on_key(press(KeyCode::Tab)); // → Mute
        app.on_key(press(KeyCode::Tab)); // → Shares
        assert_eq!(app.main_focus(), MainFocus::Shares);
    }

    /// ISC-17: a `SharesSnapshot` lands in App state, both panes are queryable,
    /// and the render shows the local entry + the indexer status line.
    #[test]
    fn shares_snapshot_lands_and_renders_both_panes() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: vec![LocalShareRow {
                rel_path: "notes/recipe.md".to_owned(),
                size: 4096,
                mtime_unix_ms: 1,
            }],
            remote: vec![listing("s1", "Alice's notes", "PG13", "alice#aabbccddeeff")],
            indexer_status: IndexerStatus::Ready { entries: 1 },
        });
        assert_eq!(app.local_shares().len(), 1);
        assert_eq!(app.public_shares_raw().len(), 1);
        assert_eq!(app.visible_public_shares().len(), 1);
        let text = render_text(&app, 120, 28);
        assert!(text.contains("my shares"), "My shares pane titled");
        assert!(text.contains("public shares"), "Public shares pane titled");
        assert!(text.contains("notes/recipe.md"), "local entry rendered");
        assert!(text.contains("Alice's notes"), "remote listing rendered");
        assert!(text.contains("indexer: ready"), "indexer status line shown");
    }

    /// ISC-20: indexer status surfaces in distinct strings per state (Idle /
    /// Indexing / Ready). The line is purely informational — no state machinery
    /// gates user input on it (ISC-A-C7).
    #[test]
    fn indexer_status_renders_three_distinct_states() {
        let mut app = drive_to_main();
        to_shares(&mut app);

        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Idle,
        });
        assert!(render_text(&app, 100, 24).contains("indexer: idle"));

        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Indexing {
                seen: 17,
                total: None,
            },
        });
        assert!(render_text(&app, 100, 24).contains("indexer: indexing 17"));

        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: Vec::new(),
            indexer_status: IndexerStatus::Ready { entries: 42 },
        });
        assert!(render_text(&app, 100, 24).contains("indexer: ready (42 entries)"));
    }

    /// ISC-18 / C16: a `SharesSnapshot` carrying a `sharer_handle` matching an
    /// entry in `hidden_shares` does NOT render that row. The raw snapshot still
    /// holds the row (the relay sent it); only the visible projection drops it.
    #[test]
    fn hide_toggle_filters_public_shares_render() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![
                listing("s1", "Alice notes", "", "alice#aabbccddeeff"),
                listing("s2", "Bob notes", "", "bob#001122334455"),
            ],
            indexer_status: IndexerStatus::Idle,
        });
        assert!(render_text(&app, 120, 24).contains("Alice notes"));

        // Move to the Hide box and toggle alice's handle into the hide set.
        app.on_key(press(KeyCode::Tab)); // → Hide
        assert_eq!(app.main_focus(), MainFocus::Hide);
        for ch in "alice#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.is_share_hidden("alice#aabbccddeeff"));

        let after = render_text(&app, 120, 24);
        assert!(
            !after.contains("Alice notes"),
            "alice's listing suppressed (ISC-18)"
        );
        assert!(after.contains("Bob notes"), "bob's listing still shown");
        // The raw snapshot is unchanged: the filter is purely render-time.
        assert_eq!(app.public_shares_raw().len(), 2);
    }

    /// ISC-18: the Enter-on-input toggle is idempotent (Enter again on the same
    /// handle removes it) — same shape as the chat-mute toggle. Mirrors the
    /// semantics of `Seeds::add_hidden_share` / `remove_hidden_share`.
    #[test]
    fn hide_toggle_is_idempotent() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_key(press(KeyCode::Tab)); // → Hide
        for ch in "alice#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(app.is_share_hidden("alice#aabbccddeeff"));
        // Re-type the same handle and toggle off.
        for ch in "alice#aabbccddeeff".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(!app.is_share_hidden("alice#aabbccddeeff"));
    }

    /// Blob-integrity parity with `Seeds::add_hidden_share`: a paste containing
    /// `\n` or `\r` is refused so the future at-rest blob stays line-safe.
    #[test]
    fn hide_toggle_refuses_line_break_handle() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_key(press(KeyCode::Tab)); // → Hide
        for ch in "garbage\nmore".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert!(!app.is_share_hidden("garbage\nmore"), "rejected");
        assert!(
            app.status().is_some(),
            "status surfaces the rejection cause"
        );
    }

    /// Tabbing into the Shares (or Hide) focus drains a pending share refresh
    /// so the screen is never silently empty on first view. The binary turns
    /// this into a `NetCommand::RefreshShares`.
    #[test]
    fn tab_to_shares_or_hide_queues_a_refresh() {
        let mut app = drive_to_main();
        // Pre-condition: nothing queued from a fresh drive_to_main.
        let _ = app.take_pending_share_refresh();
        to_shares(&mut app); // Tab → … → Shares
        assert!(
            app.take_pending_share_refresh(),
            "tabbing into Shares queues a refresh"
        );
        app.on_key(press(KeyCode::Tab)); // → Hide
        assert!(
            app.take_pending_share_refresh(),
            "tabbing into Hide queues a refresh"
        );
    }

    /// `r` on the Shares pane queues a fresh refresh (the user-facing
    /// counterpart to the auto-queue on entry).
    #[test]
    fn r_key_on_shares_queues_a_refresh() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        let _ = app.take_pending_share_refresh();
        app.on_key(press(KeyCode::Char('r')));
        assert!(app.take_pending_share_refresh());
    }

    /// Selection in the public-shares pane clamps to the *visible* subset, so a
    /// hidden row can never be silently highlighted.
    #[test]
    fn share_selection_clamps_to_visible_subset_after_hide() {
        let mut app = drive_to_main();
        to_shares(&mut app);
        app.on_net_event(NetEvent::SharesSnapshot {
            local: Vec::new(),
            remote: vec![
                listing("s1", "Alice notes", "", "alice#aabbccddeeff"),
                listing("s2", "Bob notes", "", "bob#001122334455"),
            ],
            indexer_status: IndexerStatus::Idle,
        });
        // Move selection to the second row.
        app.on_key(press(KeyCode::Down));
        assert_eq!(app.share_sel(), 1);
        // Hide bob — the visible subset shrinks to 1, so the sel must clamp.
        app.on_key(press(KeyCode::Tab)); // → Hide
        for ch in "bob#001122334455".chars() {
            app.on_key(press(KeyCode::Char(ch)));
        }
        app.on_key(press(KeyCode::Enter));
        assert_eq!(app.share_sel(), 0, "clamped after hide");
    }
}
