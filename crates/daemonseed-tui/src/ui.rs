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
    App, ChatLine, ChatSurface, CircleStatus, ConnectionStatus, FetchStatus, FetchUi,
    IndexerStatus, MainFocus, Screen, Surface, TrustItem,
};
use crate::screens::first_start::{FirstStartUi, FsStep};

/// Draw the current screen.
pub fn render(app: &App, frame: &mut Frame) {
    match app.screen() {
        Screen::Welcome => render_welcome(frame),
        Screen::Unlock => render_unlock(app, frame),
        Screen::FirstStart => match app.first_start() {
            Some(fs) => render_first_start(fs, frame),
            None => render_placeholder(frame, "First start"),
        },
        Screen::Main => render_main(app, frame),
        Screen::LoggedInMenu => {
            // Draw Main underneath, then the menu overlay on top.
            render_main(app, frame);
            render_logged_in_menu(frame);
        }
    }
}

/// Daily-login Unlock screen (ISC-C3 / Item E): a masked passphrase field and
/// any error. An existing profile blob was found, so this is daily login — not
/// the enrollment wizard.
fn render_unlock(app: &App, frame: &mut Frame) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(3),    // passphrase field
            Constraint::Length(3), // footer / error
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new("Welcome back — unlock your identity".bold())
            .block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );
    let masked: String = "*".repeat(app.unlock_input().chars().count());
    frame.render_widget(
        Paragraph::new(masked).block(Block::default().borders(Borders::ALL).title("passphrase")),
        chunks[1],
    );
    let footer: Line = match app.unlock_error() {
        Some(err) => Line::from(err.to_string()).style(Style::default().fg(Color::Red)),
        None => Line::from("[Enter] unlock   [Esc] quit"),
    };
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}

/// The logged-in "back" menu (Item E / ISC-A-C27): a centered overlay offering
/// disconnect / quit, never the enrollment wizard. Esc returns to Main.
fn render_logged_in_menu(frame: &mut Frame) {
    let area = centered_rect(50, 30, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(
            "You are logged in.\n\n\
             [d] disconnect (re-login)\n\
             [q] quit\n\
             [Esc] back to the app",
        )
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(" menu ")),
        area,
    );
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
        MainFocus::PublicSpace => render_public_space(app, frame, chunks[1]),
        MainFocus::Deprecation => render_deprecation(app, frame, chunks[1]),
        MainFocus::Fetched => render_fetched(app, frame, chunks[1]),
        _ => render_chat_transcript(app, frame, chunks[1]),
    }
    render_main_input(app, frame, chunks[2]);

    // C28 overlays, drawn last so they sit on top: a Transient toast (ISC-24),
    // then a Blocking modal (ISC-22) which takes visual precedence. The fetch
    // overlay (ISC-19) sits between them — above the chat/shares view but
    // below a security event.
    if let Some(item) = app.transient_trust() {
        render_transient_toast(item, frame, frame.area());
    }
    if let Some(f) = app.fetch() {
        render_fetch_overlay(f, frame, frame.area());
    }
    if let Some(item) = app.blocking_trust() {
        render_blocking_modal(item, frame, frame.area());
    }
}

/// The active share-fetch overlay (ISC-19, F23 unified mechanism): a centered
/// box showing the share id, sharer handle, current phase, and N-of-M chunk
/// progress. While present, [`App::on_key`] routes input here (Esc cancels;
/// Enter on a terminal state dismisses).
/// Compact, display-only byte-size formatting for the fetch preview (binary
/// units; one decimal above bytes). Not security-sensitive — purely cosmetic.
fn human_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let f = n as f64;
    if f < KB {
        format!("{n} B")
    } else if f < KB * KB {
        format!("{:.1} KB", f / KB)
    } else if f < KB * KB * KB {
        format!("{:.1} MB", f / (KB * KB))
    } else {
        format!("{:.1} GB", f / (KB * KB * KB))
    }
}

fn render_fetch_overlay(f: &FetchUi, frame: &mut Frame, area: Rect) {
    let popup = centered_rect(62, 50, area);
    let (phase, color) = match &f.status {
        FetchStatus::RequestingManifest => ("requesting manifest…".to_owned(), Color::Yellow),
        FetchStatus::Preview(_) => ("preview — review before download".to_owned(), Color::Cyan),
        FetchStatus::Receiving => ("receiving chunks…".to_owned(), Color::Cyan),
        FetchStatus::Complete => ("complete".to_owned(), Color::Green),
        FetchStatus::Failed(m) => (format!("failed: {m}"), Color::Red),
    };
    let total = match f.total_chunks {
        Some(n) => n.to_string(),
        None => "?".to_owned(),
    };
    let sharer = if f.sharer_handle.is_empty() {
        "(operator)".to_owned()
    } else {
        f.sharer_handle.clone()
    };
    let footer = match f.status {
        FetchStatus::Complete | FetchStatus::Failed(_) => "[Enter] dismiss   [Esc] dismiss",
        // A3: while editing the destination, the keys mean something else, so
        // advertise the edit-mode controls instead of the selection ones.
        FetchStatus::Preview(_) if f.editing_dest => "editing destination — [Enter/Esc] done",
        FetchStatus::Preview(_) => {
            "[↑/↓] move  [space] toggle  [a] all  [d] dest  [Enter] download  [Esc] cancel"
        }
        _ => "[Esc] cancel",
    };

    frame.render_widget(Clear, popup);
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(" share fetch ");
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // info
            Constraint::Length(3), // progress gauge
            Constraint::Length(1), // footer
        ])
        .split(inner);

    let info = match &f.status {
        // A1 preview: list the share's contents (names + sizes) so the user
        // sees exactly what a download would pull before committing.
        FetchStatus::Preview(entries) => {
            let total_bytes: u64 = entries.iter().map(|e| e.size).sum();
            let sel_count = f.preview_checked.iter().filter(|&&c| c).count();
            let sel_bytes: u64 = entries
                .iter()
                .enumerate()
                .filter(|(i, _)| f.preview_checked.get(*i).copied().unwrap_or(false))
                .map(|(_, e)| e.size)
                .sum();
            // A3 (ISC-C68): the download destination line. Empty `dest` means
            // the default Downloads dir; in edit mode a trailing cursor block
            // marks the field as the one capturing input.
            let dest_line = if f.editing_dest {
                format!("dest: {}\u{2588}", f.dest)
            } else if f.dest.is_empty() {
                "dest: (default Downloads folder)".to_owned()
            } else {
                format!("dest: {}", f.dest)
            };
            let mut s = format!(
                "share: {}\nby: {sharer}\n\n{sel_count}/{} selected · {} of {}\n{dest_line}\n\n",
                f.share_id,
                entries.len(),
                human_bytes(sel_bytes),
                human_bytes(total_bytes),
            );
            // A2: each row shows a checkbox; `>` marks the cursor.
            for (i, e) in entries.iter().enumerate() {
                let checked = f.preview_checked.get(i).copied().unwrap_or(true);
                let mark = if checked { "[x]" } else { "[ ]" };
                let cursor = if i == f.preview_cursor { ">" } else { " " };
                s.push_str(&format!(
                    "{cursor}{mark} {}  ({})\n",
                    e.rel_path,
                    human_bytes(e.size)
                ));
            }
            s
        }
        _ => format!(
            "share: {}\nby: {sharer}\n\nphase: {phase}\nchunks: {}/{total}\nbytes:  {}",
            f.share_id, f.chunks_received, f.bytes_received,
        ),
    };
    frame.render_widget(
        Paragraph::new(info)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(color)),
        rows[0],
    );

    // A real progress bar so the user sees movement, not just red→green
    // (M15). Ratio by chunks once the manifest's total is known.
    let ratio = match f.status {
        FetchStatus::Complete => 1.0,
        _ => match f.total_chunks {
            Some(t) if t > 0 => (f.chunks_received as f64 / t as f64).clamp(0.0, 1.0),
            _ => 0.0,
        },
    };
    let gauge_label = match &f.status {
        FetchStatus::Complete => "done".to_owned(),
        FetchStatus::Failed(_) => "failed".to_owned(),
        FetchStatus::Preview(entries) => {
            let sel = f.preview_checked.iter().filter(|&&c| c).count();
            format!("{sel}/{} selected — Enter to download", entries.len())
        }
        _ if f.total_chunks.is_none() => "waiting for manifest…".to_owned(),
        _ => format!(
            "{}/{total} chunks · {}%",
            f.chunks_received,
            (ratio * 100.0) as u16
        ),
    };
    frame.render_widget(
        Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" progress "))
            .gauge_style(Style::default().fg(color))
            .ratio(ratio)
            .label(gauge_label),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new(footer)
            .alignment(Alignment::Center)
            .style(Style::default().fg(color)),
        rows[2],
    );
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

/// The Fetched-downloads browse pane (M15 C; ISC-C64). Lists each share fetched
/// this profile — its name, download folder, file count, and total size; the
/// selected row is highlighted and its files (real names + sizes) are listed
/// beneath. Read-only: the files already live on disk under their real names in
/// the named folder, so there is nothing to extract.
fn render_fetched(app: &App, frame: &mut Frame, area: Rect) {
    let shares = app.fetched_shares();
    let lines: Vec<Line> = if shares.is_empty() {
        vec![
            Line::from("no downloads yet — fetch a share from the Shares pane")
                .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        let mut out: Vec<Line> = Vec::new();
        for (i, s) in shares.iter().enumerate() {
            let selected = i == app.fetched_sel();
            let marker = if selected { "▶ " } else { "  " };
            let header = format!(
                "{marker}{}  ({} file(s), {} bytes)",
                if s.name.is_empty() {
                    "(unnamed)"
                } else {
                    &s.name
                },
                s.files.len(),
                s.total_bytes(),
            );
            let style = if selected {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default()
            };
            out.push(Line::from(header).style(style));
            // Show the download folder + the files (real names) for the selected
            // share, so the user knows where the files landed and what they are.
            if selected {
                out.push(
                    Line::from(format!("      ↳ downloads/{}/", s.folder))
                        .style(Style::default().fg(Color::Green)),
                );
                for f in &s.files {
                    out.push(
                        Line::from(format!("        {}  ({} bytes)", f.rel_path, f.size))
                            .style(Style::default().fg(Color::DarkGray)),
                    );
                }
            }
        }
        out
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" downloads ")
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
    let mut lines: Vec<Line> = if app.servers().is_empty() {
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

    // The "Discovered (introducer)" sub-section (M12 gate step 6, ISC-C22 /
    // ISC-S6 / ISC-A-C19): peers the connected relay's introducer reported that
    // are NOT in the active trust set — candidates only, never auto-trusted. We
    // render the server-id and the address ONLY; the introducer response carries
    // no key material (ISC-S6), so neither does this list. Each candidate's
    // server-id (`name#hex`) and address (`host:port`) are single-token, so each
    // renders as a contiguous run in the raw PTY byte stream (a multi-word phrase
    // would be split by ratatui's per-word cursor moves — these are not).
    lines.push(Line::from(String::new()));
    lines.push(
        Line::from("── Discovered (introducer) ──".to_owned())
            .style(Style::default().fg(Color::Magenta)),
    );
    if app.discovered_peers().is_empty() {
        lines.push(
            Line::from("(no peers discovered — none, or all already configured)".to_owned())
                .style(Style::default().fg(Color::DarkGray)),
        );
    } else {
        for (server_id, address) in app.discovered_peers() {
            // server-id then address, each a contiguous token; "candidate"
            // labels it as not-yet-trusted (promotion is an explicit action).
            lines.push(
                Line::from(format!("  candidate {server_id} at {address}"))
                    .style(Style::default().fg(Color::Yellow)),
            );
        }
    }

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

/// The Public Space view (ISC-25 / ISC-S7 / ISC-A-S3): the connected relay's
/// MOTD (rendered inert) stacked above its announcement posts. A read-only
/// surface over already-shipped server APIs — there is no publish affordance on
/// this client (publishing is operator-side).
fn render_public_space(app: &App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(3)])
        .split(area);

    render_motd_pane(app, frame, chunks[0]);
    render_announcements_pane(app, frame, chunks[1]);
}

/// The MOTD pane (ISC-25): the relay's message of the day, already rendered
/// inert by the net actor ([`daemonseed_cli::public_space::render_motd`] strips
/// terminal control sequences). A `None` MOTD shows its own distinct line so
/// the empty state is unambiguous (ISC-S9 — hide the MOTD area when unset).
fn render_motd_pane(app: &App, frame: &mut Frame, area: Rect) {
    let (text, color) = match app.public_motd() {
        Some(motd) => (motd.to_owned(), Color::White),
        None => ("(no message of the day)".to_owned(), Color::DarkGray),
    };
    let body = Paragraph::new(text).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" message of the day ")
            .title_alignment(Alignment::Left)
            .style(Style::default().fg(color)),
    );
    frame.render_widget(body, area);
}

/// The announcements pane (ISC-S7): the relay's posts, each prefixed with its
/// client-side verification verdict (ISC-A-S3). An unverifiable post is flagged
/// red as `⚠ unverified` rather than presented as authentic; the selected row
/// is highlighted.
fn render_announcements_pane(app: &App, frame: &mut Frame, area: Rect) {
    let posts = app.public_posts();
    let lines: Vec<Line> = if posts.is_empty() {
        vec![
            Line::from("(no announcements published by this relay)".to_owned())
                .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        posts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let marker = if i == app.post_sel() { "▶ " } else { "  " };
                let mut spans = vec![Span::raw(marker.to_owned())];
                if p.verified {
                    spans.push(Span::styled(
                        "✓ ".to_owned(),
                        Style::default().fg(Color::Green),
                    ));
                } else {
                    spans.push(Span::styled(
                        "⚠ unverified ".to_owned(),
                        Style::default().fg(Color::Red).bold(),
                    ));
                }
                let row_style = if i == app.post_sel() {
                    Style::default().fg(Color::Cyan).bold()
                } else {
                    Style::default()
                };
                spans.push(Span::styled(format!("[{}] {}", p.topic, p.body), row_style));
                Line::from(spans)
            })
            .collect()
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" announcements ")
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// The deprecation pane (ISC-C25 / ISC-A-S11 / ISC-C28): the connected relay's
/// verified suite-deprecation policy, surfaced as one warning row per in-use
/// suite scheduled for retirement. Each row leads with a single hyphenated
/// status token — `suite-deprecation-cutoff-hit` (blocking, already refused) or
/// `suite-deprecation-pending` (still advisory) — matching the frozen stable
/// trust-event strings, so a PTY scrape can match the token without a
/// space-split breaking it. A `None` / unaffected / no-policy state shows its
/// own distinct line so the empty case is unambiguous.
fn render_deprecation(app: &App, frame: &mut Frame, area: Rect) {
    let warnings = app.deprecation_warnings();
    let header = match app.deprecation_policy_version() {
        Some(v) => format!("deprecation policy v{v}"),
        None => "deprecation policy (none fetched)".to_owned(),
    };

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(header, Style::default().fg(Color::Gray))),
        Line::from(String::new()),
    ];

    if warnings.is_empty() {
        let empty = if app.deprecation_had_policy() {
            "(no in-use suite is scheduled for deprecation)"
        } else {
            "(this relay serves no deprecation policy)"
        };
        lines.push(Line::from(empty).style(Style::default().fg(Color::DarkGray)));
    } else {
        for (i, w) in warnings.iter().enumerate() {
            let marker = if i == app.dep_sel() { "▶ " } else { "  " };
            let (token, color) = if w.past_cutoff {
                ("suite-deprecation-cutoff-hit", Color::Red)
            } else {
                ("suite-deprecation-pending", Color::Yellow)
            };
            let row_style = if i == app.dep_sel() {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::raw(marker.to_owned()),
                Span::styled(format!("⚠ {token} "), Style::default().fg(color).bold()),
                Span::styled(
                    format!(
                        "suite-{:#06x} cutoff-unix-ms={} recommended-suite-{:#06x}",
                        w.suite_id, w.cutoff_unix_ms, w.recommended_suite_id
                    ),
                    row_style,
                ),
            ]));
        }
    }

    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" suite deprecation ")
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
    // The circle summary reflects the membership set (ISC-C59): the joined count
    // plus the most-recent join attempt's status. A failed/joining attempt is
    // surfaced even while other circles remain joined.
    let n = app.circles().len();
    let circle = match app.circle_status() {
        CircleStatus::Joining => format!("joining circle… ({n} joined)"),
        CircleStatus::Failed(m) => format!("circle join failed: {m} ({n} joined)"),
        CircleStatus::NotJoined if n == 0 => "no circles".to_owned(),
        // Joined, or a stale NotJoined with a live set: report the count.
        _ => match n {
            0 => "no circles".to_owned(),
            1 => "1 circle joined".to_owned(),
            _ => format!("{n} circles joined"),
        },
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

/// The split chat view (ISC-C61): the lobby pane (always present) on top, the
/// active-circle pane (the carousel slot) on the bottom — mirroring the Shares
/// two-pane split. Each pane renders ONLY its own surface's lines (ISC-A-C29: no
/// cross-surface bleed). With no circle joined, the bottom pane shows the join
/// prompt (ISC-C48 narrowed to the circle pane; the lobby pane is always live).
fn render_chat_transcript(app: &App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_lobby_pane(app, frame, chunks[0]);
    render_circle_pane(app, frame, chunks[1]);
}

/// The lobby pane (ISC-C61, top): renders only `Surface::Lobby` lines (ISC-A-C29).
/// Always present — the auto-joined public room (ISC-C56) is always postable, so
/// this pane never shows a join prompt.
fn render_lobby_pane(app: &App, frame: &mut Frame, area: Rect) {
    let own = app.own_chat_handle();
    let visible: Vec<&ChatLine> = app
        .messages_on(Surface::Lobby)
        .filter(|m| !app.is_muted(&m.sender)) // ISC-13
        .collect();
    let lines: Vec<Line> = if visible.is_empty() {
        let msg = if app.public_room().is_some() {
            "no lobby messages yet — type to chat"
        } else {
            "lobby not joined yet"
        };
        vec![Line::from(msg.to_owned()).style(Style::default().fg(Color::DarkGray))]
    } else {
        visible.iter().map(|m| chat_line(m, own.as_ref())).collect()
    };
    let title = match app.public_room() {
        Some(room) => format!(" lobby (# {room}) "),
        None => " lobby ".to_owned(),
    };
    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_alignment(Alignment::Left),
    );
    frame.render_widget(body, area);
}

/// The active-circle pane (ISC-C61, bottom carousel slot): renders only the
/// active circle's `Surface::Circle(id)` lines (ISC-A-C29). The header names the
/// active circle's label and carousel position (ISC-C60 / ISC-C62), e.g.
/// "circle 2/3: able-otter". With an empty membership set the pane shows the join
/// prompt (ISC-C48 narrowed here).
fn render_circle_pane(app: &App, frame: &mut Frame, area: Rect) {
    let own = app.own_chat_handle();
    let total = app.circles().len();

    let (title, lines): (String, Vec<Line>) =
        match (app.active_circle_label(), app.active_circle_index()) {
            (Some((id, label)), Some(idx)) => {
                let title = format!(" circle {}/{}: {label}  [←/→] cycle ", idx + 1, total);
                let visible: Vec<&ChatLine> = app
                    .messages_on(Surface::Circle(id))
                    .filter(|m| !app.is_muted(&m.sender)) // ISC-13
                    .collect();
                let lines: Vec<Line> = if visible.is_empty() {
                    vec![
                        Line::from("no messages yet — type to chat this circle".to_owned())
                            .style(Style::default().fg(Color::DarkGray)),
                    ]
                } else {
                    visible.iter().map(|m| chat_line(m, own.as_ref())).collect()
                };
                (title, lines)
            }
            // Empty membership set (ISC-C61): the join prompt lives here; the lobby
            // pane above stays live.
            _ => (
                " circle (none joined) ".to_owned(),
                vec![
                    Line::from(
                        "join a circle to chat — Tab to the circle-join box, enter a phrase"
                            .to_owned(),
                    )
                    .style(Style::default().fg(Color::DarkGray)),
                ],
            ),
        };

    let body = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
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
    let (title, text): (String, String) = match app.main_focus() {
        MainFocus::Chat if !app.can_chat() => (
            // Item F / ISC-C48: greyed/disabled compose until a circle is joined
            // — the title states the requirement and Enter is a no-op.
            "compose (disabled — join a public room or circle to chat)  [Tab] join-circle  [Esc] back"
                .to_owned(),
            app.compose().to_owned(),
        ),
        MainFocus::Chat => {
            // The surface indicator (v0.15.1): the title names where Enter posts,
            // resolved through the same precedence the handler uses
            // ([`App::active_chat_surface`]) so the label can never lie about the
            // destination. A joined circle wins over the auto-joined lobby.
            let surface = match app.active_chat_surface() {
                // Name the active circle's client-local label (ISC-C62) so the
                // post destination is never ambiguous across the carousel
                // (ISC-C60).
                Some(ChatSurface::Circle { label, .. }) => format!("🔒 {label}"),
                Some(ChatSurface::PublicRoom(room)) => format!("# {room} (public)"),
                // Unreachable while `can_chat()` holds (this arm requires it),
                // but kept total rather than panicking.
                None => "no surface".to_owned(),
            };
            (
                format!("compose → {surface}  [Enter] send  [Tab] join-circle  [Esc] back"),
                app.compose().to_owned(),
            )
        }
        MainFocus::JoinCircle => {
            // ISC-C9 strength indicator: a red→yellow→green tier (border below
            // matches), driven by the M15 word+charset key-space estimate. Green
            // at the real ≥128-bit floor; a below-floor phrase is blocked at Enter
            // (App::on_key_join, Fork 4). The bits/128 readout tells the user how
            // much further to go — "keep adding until green" (caraka 2026-06-05).
            let s = app.circle_phrase_strength();
            let tier = if s.is_circle_green() {
                "strong ✓"
            } else if s.bits >= SESSION_PASSPHRASE_MIN_BITS {
                "fair ⚠"
            } else {
                "weak ⚠"
            };
            (
                format!(
                    "circle phrase · {tier} {bits:.0}/128 bits  [Enter] join  [Ctrl-G] generate  [Tab] mute  [Esc] back",
                    bits = s.bits
                ),
                app.circle_phrase().to_owned(),
            )
        }
        MainFocus::Mute => {
            let muted: Vec<&str> = app.muted().collect();
            let suffix = if muted.is_empty() {
                String::new()
            } else {
                format!("   muted: {}", muted.join(", "))
            };
            (
                "mute handle  [Enter] toggle  [Tab] shares  [Esc] back".to_owned(),
                format!("{}{suffix}", app.mute_input()),
            )
        }
        MainFocus::Shares => {
            // M15 cleanup: publishing is `[p]` on the defined share (define once,
            // then publish) — no separate Publish pane. Show what's defined +
            // what's serving so the action is obvious.
            let defined = app
                .active_defined_share()
                .map(|(_, name)| format!("   defined: {name} · [p] publish"))
                .unwrap_or_else(|| "   (Tab → define-share first)".to_owned());
            let serving = app.published().len();
            let serving_hint = if serving > 0 {
                format!(" · serving {serving} · [u] unpublish")
            } else {
                String::new()
            };
            (
                format!(
                    "shares  [↑/↓] select  [f] fetch  [r] refresh  [Tab] define-share  [Esc] back{defined}{serving_hint}"
                ),
                String::new(),
            )
        }
        MainFocus::DefineShare => (
            // Fork 1 (caraka 2026-06-05): an input box like JoinCircle, with an
            // example path as the hint so the expected format is obvious.
            "share a directory · e.g. /home/you/Shared  (path or path|label)  [Enter] add  [Tab] hide  ([p] in Shares to publish)  [Esc] back"
                .to_owned(),
            app.share_input().to_owned(),
        ),
        MainFocus::Hide => {
            let hidden: Vec<&str> = app.hidden_shares().collect();
            let suffix = if hidden.is_empty() {
                String::new()
            } else {
                format!("   hidden: {}", hidden.join(", "))
            };
            (
                "hide sharer-handle  [Enter] toggle  [Tab] servers  [Esc] back".to_owned(),
                format!("{}{suffix}", app.hide_input()),
            )
        }
        MainFocus::Servers => (
            "add server-id@host:port  [Enter] add / connect-selected  [←/→] trust  [↑/↓] select  [Tab] trust-history"
                .to_owned(),
            app.server_input().to_owned(),
        ),
        MainFocus::TrustHistory => (
            "trust history  [↑/↓] select  [Enter] dismiss selected  [Tab] public-space  [Esc] back"
                .to_owned(),
            String::new(),
        ),
        MainFocus::PublicSpace => (
            "public space  [↑/↓] select  [r] refresh  [Tab] deprecation  [Esc] back".to_owned(),
            String::new(),
        ),
        MainFocus::Deprecation => (
            "suite deprecation  [↑/↓] select  [r] refresh  [Tab] fetched  [Esc] back".to_owned(),
            String::new(),
        ),
        MainFocus::Fetched => (
            // M15 C: read-only browse of downloads (files already on disk under
            // their real names in each share's folder — no extract step).
            "downloads  [↑/↓] select  [Tab] chat  [Esc] back".to_owned(),
            String::new(),
        ),
    };
    // A status/error line (e.g. a failed send) is appended briefly when present.
    let shown = match app.status() {
        Some(s) => format!("{text}    ! {s}"),
        None => text,
    };
    // The join box gets a strength-driven border (ISC-C9): red below 60 bits,
    // yellow approaching the floor, green at/above the ≥128-bit floor — the
    // red→green indicator the spec calls for, within the single-line input. An
    // empty phrase stays neutral cyan like every other focus.
    let border_color = match app.main_focus() {
        MainFocus::JoinCircle if !app.circle_phrase().is_empty() => {
            let s = app.circle_phrase_strength();
            if s.is_circle_green() {
                Color::Green
            } else if s.bits >= SESSION_PASSPHRASE_MIN_BITS {
                Color::Yellow
            } else {
                Color::Red
            }
        }
        _ => Color::Cyan,
    };
    let body = Paragraph::new(shown).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
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
         file-sharing client.\n\n[Enter] new identity    [r] recover identity    [q] quit",
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
            "[Enter] confirm (3 words)   [f] re-type all 24   [Esc] cancel",
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
        FsStep::RecoverChoose => (
            "Recover identity — choose input",
            "[m] type mnemonic   [f] load .dseed file   [Esc] cancel",
        ),
        FsStep::RecoverMnemonic => (
            "Recover identity — recovery phrase",
            "[Enter] continue   [Esc] cancel",
        ),
        FsStep::RecoverDseedPath => (
            "Recover identity — .dseed file",
            "[Enter] continue   [Esc] cancel",
        ),
        FsStep::RecoverPassphrase => (
            "Recover identity — passphrase",
            "[Enter] recover   [Esc] cancel",
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
        FsStep::RecoverChoose => {
            frame.render_widget(
                Paragraph::new(
                    "Recover your identity on this device.\n\n\
                     [m] type your 24-word recovery phrase\n\
                     [f] load an identity.dseed recovery file\n\n\
                     Recovery restores your identity, not your circles —\n\
                     re-enter circle passphrases to rejoin them.",
                )
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title("recover")),
                area,
            );
        }
        FsStep::RecoverMnemonic => {
            frame.render_widget(
                Paragraph::new(fs.input()).wrap(Wrap { trim: true }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("type all 24 words"),
                ),
                area,
            );
        }
        FsStep::RecoverDseedPath => {
            frame.render_widget(
                Paragraph::new(fs.input()).wrap(Wrap { trim: true }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("path to identity.dseed"),
                ),
                area,
            );
        }
        FsStep::RecoverPassphrase => {
            let masked: String = "*".repeat(fs.input().chars().count());
            frame.render_widget(
                Paragraph::new(masked)
                    .block(Block::default().borders(Borders::ALL).title("passphrase")),
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
