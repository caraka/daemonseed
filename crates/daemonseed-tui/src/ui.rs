//! Pure render functions.
//!
//! Each function takes the immutable [`App`] state and a [`ratatui::Frame`] and
//! draws the current screen. No state mutation happens here — rendering is a
//! pure function of `App`, which is what makes the PTY gate harness'
//! screen-scraping assertions deterministic.

use core::str::FromStr;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Wrap};

use daemonseed_core::backoff::CloseCause;
use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::mention::find_self_mentions;
use daemonseed_core::passphrase::strength::SESSION_PASSPHRASE_MIN_BITS;
use daemonseed_core::trust_events::{TrustEventKey, event_key_string};

use crate::app::{
    App, ChatLine, CircleStatus, ConnectionStatus, IndexerStatus, MainFocus, Screen, TrustItem,
};
use crate::screens::first_start::{FirstStartUi, FsStep};

/// Draw the current screen.
pub fn render(app: &App, frame: &mut Frame) {
    match app.screen() {
        Screen::Welcome => render_welcome(frame),
        Screen::FirstStart => match app.first_start() {
            Some(fs) => render_first_start(fs, frame),
            None => render_placeholder(frame, "First start"),
        },
        Screen::Main => render_main(app, frame),
    }
}

/// The post-first-start main view: a connection/circle status bar, the circle
/// chat transcript, and the focused input (chat compose or circle-join). Trust /
/// share / server tabs grow here in the later workstreams.
fn render_main(app: &App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // status bar
            Constraint::Min(3),    // chat transcript
            Constraint::Length(3), // focused input
        ])
        .split(frame.area());

    render_status_bar(app, frame, chunks[0]);
    // The main area shows the server-management list, Trust History, or Shares
    // pane while those screens have focus, otherwise the chat transcript.
    match app.main_focus() {
        MainFocus::Servers => render_server_list(app, frame, chunks[1]),
        MainFocus::TrustHistory => render_trust_history(app, frame, chunks[1]),
        MainFocus::Shares | MainFocus::Hide => render_shares(app, frame, chunks[1]),
        _ => render_chat_transcript(app, frame, chunks[1]),
    }
    render_main_input(app, frame, chunks[2]);

    // C28 overlays, drawn last so they sit on top: a Transient toast (ISC-24),
    // then a Blocking modal (ISC-22) which takes visual precedence.
    if let Some(item) = app.transient_trust() {
        render_transient_toast(item, frame, frame.area());
    }
    if let Some(item) = app.blocking_trust() {
        render_blocking_modal(item, frame, frame.area());
    }
}

/// The Trust History view (ISC-25 / C28 LogOnly surface): every recorded trust
/// event, newest first, with its stable key, scope, and dismissed/resolved
/// markers. The selected row is highlighted; Enter dismisses it.
fn render_trust_history(app: &App, frame: &mut Frame, area: Rect) {
    let entries = app.trust_log().entries();
    let lines: Vec<Line> = if entries.is_empty() {
        vec![
            Line::from("no trust events recorded".to_owned())
                .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        // Newest first; the selection index is over this reversed view.
        entries
            .iter()
            .rev()
            .enumerate()
            .map(|(i, e)| {
                let marker = if i == app.history_sel() { "▶ " } else { "  " };
                let scope = e.server_id.as_deref().unwrap_or("-");
                let dismissed = if e.dismissed_at_unix_ms.is_some() {
                    "  [dismissed]"
                } else {
                    ""
                };
                let line = format!("{marker}{}  @{scope}{dismissed}", event_key_string(e.key));
                let style = if i == app.history_sel() {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default()
                };
                Line::from(line).style(style)
            })
            .collect()
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" trust history ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// A Transient trust toast (ISC-24): a small box at the top-right that the next
/// key press dismisses. Informational; never blocks.
fn render_transient_toast(item: &TrustItem, frame: &mut Frame, area: Rect) {
    let text = trust_toast_text(item.key);
    let width = (text.len() as u16 + 4).min(area.width);
    let toast = Rect {
        x: area.x + area.width.saturating_sub(width),
        y: area.y,
        width,
        height: 3.min(area.height),
    };
    if toast.height < 3 {
        return;
    }
    let widget = Paragraph::new(text).style(Style::default().fg(Color::Black).bg(Color::Yellow));
    frame.render_widget(Clear, toast);
    frame.render_widget(widget, toast);
}

/// A Blocking trust modal (ISC-22): a centered box that captures input until the
/// user acknowledges. Reserved for security decisions the user MUST make.
fn render_blocking_modal(item: &TrustItem, frame: &mut Frame, area: Rect) {
    let popup = centered_rect(60, 30, area);
    let scope = item.server_id.as_deref().unwrap_or("this connection");
    let body = format!(
        "{}\n\nserver: {scope}\n\n[Enter] acknowledge   [Esc] dismiss",
        trust_blocking_message(item.key)
    );
    let widget = Paragraph::new(body)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(Color::White).bg(Color::Red).bold())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::White))
                .title(" ⚠ security warning "),
        );
    frame.render_widget(Clear, popup);
    frame.render_widget(widget, popup);
}

/// A short toast string for a Transient trust key (ISC-24).
fn trust_toast_text(key: TrustEventKey) -> String {
    match key {
        TrustEventKey::ConnectionRateLimited => "server busy — backing off".to_owned(),
        TrustEventKey::UpdateRelayFallbackUsed => "update via fallback relay".to_owned(),
        other => event_key_string(other).to_owned(),
    }
}

/// A one-line modal headline for a Blocking trust key (ISC-22). MUST NOT
/// speculate about server-side causes (ISC-A-S12).
fn trust_blocking_message(key: TrustEventKey) -> &'static str {
    match key {
        TrustEventKey::ServerKeyMismatch => "Server key does not match — possible impersonation.",
        TrustEventKey::NoCommonVersion => "No common protocol version with this server.",
        TrustEventKey::SuiteDeprecationCutoffHit => "A cipher suite in use is past its cutoff.",
        TrustEventKey::CircleContentBelowMinSuite => "Circle content is below its minimum suite.",
        TrustEventKey::UpdateVerificationFailed => "An update failed signature verification.",
        TrustEventKey::EmergencySecurityUpdateAvailable => {
            "An emergency security update is available."
        }
        TrustEventKey::UnsupportedIdentityProofSuite => "Peer identity-proof suite is unsupported.",
        TrustEventKey::ServerDeprecationPolicyRollback => {
            "Server served an older deprecation policy."
        }
        other => event_key_string(other),
    }
}

/// A centered rectangle `pct_x`%×`pct_y`% of `area`, for modal overlays.
fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vert[1])[1]
}

/// The server-management list (F22 / C22): each managed server with its
/// trusted/untrusted slider position; the selected row is highlighted (ISC-21).
fn render_server_list(app: &App, frame: &mut Frame, area: Rect) {
    let lines: Vec<Line> = if app.servers().is_empty() {
        vec![
            Line::from(
                "no servers — type <server-id>@<host:port> below and Enter to add".to_owned(),
            )
            .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        app.servers()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // The slider: ◄trusted● / ●untrusted► style two-position toggle.
                let slider = if s.trusted {
                    "[ untrusted  ◄●  TRUSTED ]"
                } else {
                    "[ UNTRUSTED  ●►  trusted ]"
                };
                let marker = if i == app.server_sel() { "▶ " } else { "  " };
                let line = format!("{marker}{slider}  {} ({})", s.server_id, s.address);
                let style = if i == app.server_sel() {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default()
                };
                Line::from(line).style(style)
            })
            .collect()
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" servers ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// The Shares pane (ISC-17 / ISC-18 / ISC-20): two stacked sub-panes —
/// My-shares (the user's own indexed files, with the non-blocking indexer
/// status line) and Public-shares (the connected relay's `ListPublicShares`
/// snapshot, after the client-local hidden-shares filter is applied).
///
/// The Public-shares pane is **post-filter**: rows whose `sharer_handle` is
/// in `app.hidden_shares()` never appear. The hide set is client-private
/// (ISC-A-C3) — there is no wire field for it — so suppression is purely a
/// render concern.
fn render_shares(app: &App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_my_shares_pane(app, frame, chunks[0]);
    render_public_shares_pane(app, frame, chunks[1]);
}

/// My-shares: the user's own [`daemonseed_core::storage::share_index::ShareIndex`]
/// entries, preceded by the indexer status line. The status line is
/// information-only and never blocks input (ISC-A-C7) — even mid-cold-scan,
/// the user can press Tab to leave the pane.
fn render_my_shares_pane(app: &App, frame: &mut Frame, area: Rect) {
    let status = match app.indexer_status() {
        IndexerStatus::Idle => "indexer: idle (no share root configured)".to_owned(),
        IndexerStatus::Indexing { seen, total } => match total {
            Some(t) => format!("indexer: indexing {seen}/{t} files…"),
            None => format!("indexer: indexing {seen} files…"),
        },
        IndexerStatus::Ready { entries } => format!("indexer: ready ({entries} entries)"),
    };
    let status_color = match app.indexer_status() {
        IndexerStatus::Idle => Color::DarkGray,
        IndexerStatus::Indexing { .. } => Color::Yellow,
        IndexerStatus::Ready { .. } => Color::Green,
    };

    let mut lines: Vec<Line> = Vec::with_capacity(1 + app.local_shares().len());
    lines.push(Line::from(status).style(Style::default().fg(status_color)));

    if app.local_shares().is_empty() {
        lines.push(
            Line::from("(no local shares)".to_owned()).style(Style::default().fg(Color::DarkGray)),
        );
    } else {
        for entry in app.local_shares() {
            lines.push(Line::from(format!(
                "  {}   {} bytes",
                entry.rel_path, entry.size
            )));
        }
    }
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" my shares ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// Public-shares: the relay-published listing after the client-local
/// hidden-shares filter (ISC-18 / C16). Selected row highlighted; rows whose
/// `sharer_handle` is in the hide set are absent (ISC-A-C3 by construction
/// — no wire field carries the hide set).
fn render_public_shares_pane(app: &App, frame: &mut Frame, area: Rect) {
    let visible = app.visible_public_shares();
    let lines: Vec<Line> = if visible.is_empty() {
        let msg = if app.public_shares_raw().is_empty() {
            "(no public shares published by this relay)"
        } else {
            "(all public shares filtered by your hide list)"
        };
        vec![Line::from(msg.to_owned()).style(Style::default().fg(Color::DarkGray))]
    } else {
        visible
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let marker = if i == app.share_sel() { "▶ " } else { "  " };
                let sharer = if s.sharer_handle.is_empty() {
                    "(operator)".to_owned()
                } else {
                    s.sharer_handle.clone()
                };
                let rating = if s.rating.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", s.rating)
                };
                let line = format!("{marker}{}{rating}    by {sharer}", s.name);
                let style = if i == app.share_sel() {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default()
                };
                Line::from(line).style(style)
            })
            .collect()
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" public shares ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// Top bar: connection state, circle state, persistent trust badges (ISC-23),
/// and — when a close was observed — a distinct close-cause segment (ISC-28).
fn render_status_bar(app: &App, frame: &mut Frame, area: Rect) {
    let (conn, color) = match app.connection() {
        ConnectionStatus::Disconnected => ("disconnected".to_owned(), Color::Gray),
        ConnectionStatus::Connecting => ("connecting…".to_owned(), Color::Yellow),
        ConnectionStatus::Connected {
            server,
            version,
            rotation_notice,
        } => {
            let mut s = format!("connected to {server} (wire {version})");
            if let Some(fp) = rotation_notice {
                s.push_str(&format!("  [key rotated: {fp}]"));
            }
            (s, Color::Green)
        }
        ConnectionStatus::Failed(msg) => (format!("connection failed: {msg}"), Color::Red),
    };
    let circle = match app.circle_status() {
        CircleStatus::NotJoined => "no circle".to_owned(),
        CircleStatus::Joining => "joining circle…".to_owned(),
        CircleStatus::Joined => "circle joined".to_owned(),
        CircleStatus::Failed(m) => format!("circle join failed: {m}"),
    };

    let mut spans = vec![
        Span::styled(conn, Style::default().fg(color)),
        Span::raw("    │    "),
        Span::raw(circle),
    ];

    // PersistentNonBlocking trust badges (ISC-23): one ⚠ chip per undismissed
    // event, surfaced until the user dismisses it from Trust History.
    for item in app.persistent_trust() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("⚠ {}", event_key_string(item.key)),
            Style::default().fg(Color::Yellow).bold(),
        ));
    }

    // The distinct close-cause segment (ISC-28 / C26): each of the three
    // observable layers gets its own glyph, message, and colour.
    if let Some(cause) = app.close_cause() {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("{} {}", close_cause_glyph(cause), cause.user_message()),
            Style::default().fg(close_cause_color(cause)).bold(),
        ));
    }

    let body = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" daemonseed ")
            .title_alignment(Alignment::Center),
    );
    frame.render_widget(body, area);
}

/// A distinct glyph per close-cause layer (ISC-28), so the three states are
/// visually distinguishable at a glance.
fn close_cause_glyph(cause: CloseCause) -> &'static str {
    match cause {
        CloseCause::NetworkFailure => "⚡",
        CloseCause::RefusedBeforeHelloAck => "⛔",
        CloseCause::ClosedAfterAuth => "✕",
    }
}

/// A distinct colour per close-cause layer (ISC-28).
fn close_cause_color(cause: CloseCause) -> Color {
    match cause {
        CloseCause::NetworkFailure => Color::Magenta,
        CloseCause::RefusedBeforeHelloAck => Color::Red,
        CloseCause::ClosedAfterAuth => Color::LightRed,
    }
}

/// The circle chat transcript, oldest at the top (ISC-10). Muted senders are
/// suppressed (ISC-13); the sender shows as its friendly handle form; mentions
/// of the user's own handle are highlighted (ISC-11).
fn render_chat_transcript(app: &App, frame: &mut Frame, area: Rect) {
    let own = app.own_chat_handle();
    let visible: Vec<&ChatLine> = app
        .messages()
        .iter()
        .filter(|m| !app.is_muted(&m.sender)) // ISC-13
        .collect();
    let lines: Vec<Line> = if visible.is_empty() {
        vec![
            Line::from("no messages yet — Tab to join a circle, then type to chat".to_owned())
                .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        visible.iter().map(|m| chat_line(m, own.as_ref())).collect()
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" chat ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// Build one transcript line: a friendly `sender:` prefix plus the body, with
/// any `@own-handle` mention spans highlighted (ISC-11/C17). An unparseable
/// sender renders raw.
fn chat_line(m: &ChatLine, own: Option<&Handle>) -> Line<'static> {
    let sender_label = Handle::from_str(&m.sender)
        .map(|h| h.format(DisplayMode::Default))
        .unwrap_or_else(|_| m.sender.clone());
    let mut spans = vec![Span::styled(
        format!("{sender_label}: "),
        Style::default().fg(Color::Cyan),
    )];

    let mentions = own
        .map(|h| find_self_mentions(&m.body, h))
        .unwrap_or_default();
    if mentions.is_empty() {
        spans.push(Span::raw(m.body.clone()));
    } else {
        let mut idx = 0;
        for span in mentions {
            if span.start > idx {
                spans.push(Span::raw(m.body[idx..span.start].to_string()));
            }
            spans.push(Span::styled(
                m.body[span.clone()].to_string(),
                Style::default().fg(Color::Yellow).bold(),
            ));
            idx = span.end;
        }
        if idx < m.body.len() {
            spans.push(Span::raw(m.body[idx..].to_string()));
        }
    }
    Line::from(spans)
}

/// The bottom input line: the chat compose box, circle-join box, mute box,
/// shares status, hide box, or server-management input, depending on focus
/// (Tab cycles Chat → JoinCircle → Mute → Shares → Hide → Servers →
/// TrustHistory). When composing a partial `@token`, a mention-autocomplete
/// popup floats above (ISC-12).
fn render_main_input(app: &App, frame: &mut Frame, area: Rect) {
    let (title, text): (&str, String) = match app.main_focus() {
        MainFocus::Chat => (
            "compose  [Enter] send  [Tab] join-circle  [Esc] back",
            app.compose().to_owned(),
        ),
        MainFocus::JoinCircle => (
            "circle phrase  [Enter] join  [Tab] mute  [Esc] back",
            app.circle_phrase().to_owned(),
        ),
        MainFocus::Mute => {
            let muted: Vec<&str> = app.muted().collect();
            let suffix = if muted.is_empty() {
                String::new()
            } else {
                format!("   muted: {}", muted.join(", "))
            };
            (
                "mute handle  [Enter] toggle  [Tab] shares  [Esc] back",
                format!("{}{suffix}", app.mute_input()),
            )
        }
        MainFocus::Shares => (
            "shares  [↑/↓] select  [r] refresh  [Tab] hide  [Esc] back",
            String::new(),
        ),
        MainFocus::Hide => {
            let hidden: Vec<&str> = app.hidden_shares().collect();
            let suffix = if hidden.is_empty() {
                String::new()
            } else {
                format!("   hidden: {}", hidden.join(", "))
            };
            (
                "hide sharer-handle  [Enter] toggle  [Tab] servers  [Esc] back",
                format!("{}{suffix}", app.hide_input()),
            )
        }
        MainFocus::Servers => (
            "add server-id@host:port  [Enter] add / connect-selected  [←/→] trust  [↑/↓] select  [Tab] trust-history",
            app.server_input().to_owned(),
        ),
        MainFocus::TrustHistory => (
            "trust history  [↑/↓] select  [Enter] dismiss selected  [Tab] chat  [Esc] back",
            String::new(),
        ),
    };
    // A status/error line (e.g. a failed send) is appended briefly when present.
    let shown = match app.status() {
        Some(s) => format!("{text}    ! {s}"),
        None => text,
    };
    let body = Paragraph::new(shown).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(title),
    );
    frame.render_widget(body, area);

    render_mention_popup(app, frame, area);
}

/// A mention-autocomplete popup floating just above the compose box (ISC-12).
/// Shown only while composing a partial `@token` with in-scope candidates.
fn render_mention_popup(app: &App, frame: &mut Frame, input_area: Rect) {
    let candidates = app.mention_autocomplete();
    if candidates.is_empty() {
        return;
    }
    let shown: Vec<&String> = candidates.iter().take(5).collect();
    let height = (shown.len() as u16) + 2; // + borders
    let width = shown
        .iter()
        .map(|c| c.len() as u16)
        .max()
        .unwrap_or(10)
        .clamp(10, input_area.width.saturating_sub(2))
        + 2;
    // Anchor the popup directly above the input box.
    let y = input_area.y.saturating_sub(height);
    let popup = Rect {
        x: input_area.x,
        y,
        width: width.min(input_area.width),
        height: height.min(input_area.y),
    };
    if popup.height < 3 {
        return; // no room
    }
    let lines: Vec<Line> = shown.iter().map(|c| Line::from((*c).clone())).collect();
    let widget = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title("@mention"),
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(widget, popup);
}

fn render_welcome(frame: &mut Frame) {
    let body = Paragraph::new(
        "daemonseed\n\nA federated, end-to-end-encrypted communication and\n\
         file-sharing client.\n\n[Enter] begin first-start    [q] quit",
    )
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" daemonseed ")
            .title_alignment(Alignment::Center),
    );
    frame.render_widget(body, frame.area());
}

fn render_placeholder(frame: &mut Frame, label: &str) {
    let body = Paragraph::new(format!("{label}\n\n[Esc] back"))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(label.bold()));
    frame.render_widget(body, frame.area());
}

/// Render the active first-start step: a titled body, an optional input field
/// (or strength meter / mnemonic), and an error/footer line.
fn render_first_start(fs: &FirstStartUi, frame: &mut Frame) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(5),    // body
            Constraint::Length(3), // footer / error
        ])
        .split(area);

    let (title, footer) = match fs.step() {
        FsStep::Passphrase => (
            "First start — choose a passphrase",
            "[Enter] continue   [Esc] cancel",
        ),
        FsStep::ShowMnemonic => (
            "First start — recovery phrase",
            "[Enter] I've written it down   [s] skip (type-back)   [Esc] cancel",
        ),
        FsStep::VerifyRoundTrip => (
            "First start — confirm recovery phrase",
            "[Enter] verify   [Esc] cancel",
        ),
        FsStep::VerifyTypeBack => (
            "First start — type-back challenge",
            "[Enter] verify   [Esc] cancel",
        ),
        FsStep::DisplayName => (
            "First start — display name",
            "[Enter] accept   [Esc] cancel",
        ),
        FsStep::Bootstrap => (
            "First start — bootstrap relay",
            "[Enter] finish   [Esc] cancel",
        ),
        FsStep::Complete => ("First start — complete", ""),
    };

    frame.render_widget(
        Paragraph::new(title.bold()).block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );
    render_first_start_body(fs, frame, chunks[1]);

    let footer_line: Line = match fs.error() {
        Some(err) => Line::from(err.to_string()).style(Style::default().fg(Color::Red)),
        None => Line::from(footer),
    };
    frame.render_widget(
        Paragraph::new(footer_line).block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}

fn render_first_start_body(fs: &FirstStartUi, frame: &mut Frame, area: Rect) {
    match fs.step() {
        FsStep::Passphrase => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Length(3)])
                .split(area);
            // Masked passphrase field.
            let masked: String = "*".repeat(fs.input().chars().count());
            frame.render_widget(
                Paragraph::new(masked)
                    .block(Block::default().borders(Borders::ALL).title("passphrase")),
                rows[0],
            );
            // Color-coded strength meter against the C12 session floor.
            let bits = fs.strength().map(|s| s.bits).unwrap_or(0.0);
            let ratio = (bits / (SESSION_PASSPHRASE_MIN_BITS * 1.5)).clamp(0.0, 1.0);
            let color = if fs.passphrase_is_green() {
                Color::Green
            } else if bits >= SESSION_PASSPHRASE_MIN_BITS * 0.66 {
                Color::Yellow
            } else {
                Color::Red
            };
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title("strength"))
                .gauge_style(Style::default().fg(color))
                .ratio(ratio)
                .label(format!(
                    "{bits:.0} / {floor:.0} bits min",
                    floor = SESSION_PASSPHRASE_MIN_BITS
                ));
            frame.render_widget(gauge, rows[1]);
        }
        FsStep::ShowMnemonic => {
            let phrase = fs.mnemonic().unwrap_or("");
            frame.render_widget(
                Paragraph::new(phrase).wrap(Wrap { trim: true }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("write these 24 words down"),
                ),
                area,
            );
        }
        FsStep::VerifyRoundTrip => {
            frame.render_widget(
                Paragraph::new(fs.input()).wrap(Wrap { trim: true }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("re-type all 24 words"),
                ),
                area,
            );
        }
        FsStep::VerifyTypeBack => {
            let positions = fs
                .challenge_positions()
                .map(|p| {
                    p.iter()
                        .map(|i| (i + 1).to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Length(3)])
                .split(area);
            frame.render_widget(
                Paragraph::new(format!("enter words at positions: {positions}"))
                    .block(Block::default().borders(Borders::ALL).title("challenge")),
                rows[0],
            );
            frame.render_widget(
                Paragraph::new(fs.input()).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("answers (space-separated)"),
                ),
                rows[1],
            );
        }
        FsStep::DisplayName => {
            frame.render_widget(
                Paragraph::new(fs.input()).block(Block::default().borders(Borders::ALL).title(
                    format!(
                        "display name (default {}; leave blank for floor handle)",
                        fs.name_default()
                    ),
                )),
                area,
            );
        }
        FsStep::Bootstrap => {
            frame.render_widget(
                Paragraph::new(fs.input()).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("bootstrap <server-id>@<host:port>"),
                ),
                area,
            );
        }
        FsStep::Complete => {
            frame.render_widget(
                Paragraph::new("first-start complete — connecting…")
                    .block(Block::default().borders(Borders::ALL)),
                area,
            );
        }
    }
}
