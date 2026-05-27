//! Pure render functions.
//!
//! Each function takes the immutable [`App`] state and a [`ratatui::Frame`] and
//! draws the current screen. No state mutation happens here — rendering is a
//! pure function of `App`, which is what makes the PTY gate harness'
//! screen-scraping assertions deterministic.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Wrap};

use daemonseed_core::passphrase::strength::SESSION_PASSPHRASE_MIN_BITS;

use crate::app::{App, CircleStatus, ConnectionStatus, MainFocus, Screen};
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
    render_chat_transcript(app, frame, chunks[1]);
    render_main_input(app, frame, chunks[2]);
}

/// Top bar: connection state on the left, circle state on the right.
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
    let body = Paragraph::new(format!("{conn}    │    {circle}"))
        .style(Style::default().fg(color))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" daemonseed ")
                .title_alignment(Alignment::Center),
        );
    frame.render_widget(body, area);
}

/// The circle chat transcript, oldest at the top (ISC-10). Each line is
/// `sender: body`; a just-sent local echo carries the user's own handle.
fn render_chat_transcript(app: &App, frame: &mut Frame, area: Rect) {
    let lines: Vec<Line> = if app.messages().is_empty() {
        vec![
            Line::from("no messages yet — Tab to join a circle, then type to chat".to_owned())
                .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        app.messages()
            .iter()
            .map(|m| Line::from(format!("{}: {}", m.sender, m.body)))
            .collect()
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" chat ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// The bottom input line: the chat compose box or the circle-join box,
/// depending on focus (Tab toggles). A focused box is highlighted.
fn render_main_input(app: &App, frame: &mut Frame, area: Rect) {
    let (title, text, focused) = match app.main_focus() {
        MainFocus::Chat => (
            "compose  [Enter] send  [Tab] join-circle  [Esc] back",
            app.compose(),
            true,
        ),
        MainFocus::JoinCircle => (
            "circle phrase  [Enter] join  [Tab] chat  [Esc] back",
            app.circle_phrase(),
            true,
        ),
    };
    let style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    // A status/error line (e.g. a failed send) replaces the input text briefly
    // when present, so the user sees why nothing happened.
    let shown = match app.status() {
        Some(s) => format!("{text}    ⚠ {s}"),
        None => text.to_owned(),
    };
    let body = Paragraph::new(shown).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(style)
            .title(title),
    );
    frame.render_widget(body, area);
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
