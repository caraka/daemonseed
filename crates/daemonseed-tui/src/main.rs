//! daemonseed-tui binary — terminal lifecycle + event loop.
//!
//! This is the thin terminal driver around the testable state machine in
//! [`daemonseed_tui::app`]. It owns raw-mode / alternate-screen setup and
//! teardown and the blocking event loop; all interactive logic lives in the
//! library so it can be unit-tested and PTY-driven without a terminal.

#![forbid(unsafe_code)]

use std::io;
use std::time::Duration;

use daemonseed_tui::app::App;
use daemonseed_tui::ui;
use ratatui::crossterm::event::{self, Event};

/// Event-loop poll interval. Bounds redraw latency for time-driven UI (toasts,
/// indexer-progress ticks) without busy-spinning.
const TICK: Duration = Duration::from_millis(100);

fn main() -> io::Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal) -> io::Result<()> {
    let mut app = App::new();
    while !app.should_quit() {
        terminal.draw(|frame| ui::render(&app, frame))?;
        if event::poll(TICK)?
            && let Event::Key(key) = event::read()?
        {
            app.on_key(key);
        }
    }
    Ok(())
}
