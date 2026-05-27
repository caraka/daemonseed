//! Pure render functions.
//!
//! Each function takes the immutable [`App`] state and a [`ratatui::Frame`] and
//! draws the current screen. No state mutation happens here — rendering is a
//! pure function of `App`, which is what makes the PTY gate harness'
//! screen-scraping assertions deterministic.

use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::style::{Style, Stylize};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, Screen};

/// Draw the current screen.
pub fn render(app: &App, frame: &mut Frame) {
    match app.screen() {
        Screen::Welcome => render_welcome(frame),
        Screen::FirstStart => render_placeholder(frame, "First start"),
        Screen::Main => render_placeholder(frame, "Main view"),
    }
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
        .style(Style::default())
        .block(Block::default().borders(Borders::ALL).title(label.bold()));
    frame.render_widget(body, frame.area());
}
