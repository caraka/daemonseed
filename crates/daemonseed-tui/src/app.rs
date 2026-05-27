//! The TUI screen state machine.
//!
//! [`App`] holds all interactive state and advances only through
//! [`App::on_key`]. It performs no terminal I/O, so it is fully unit-testable
//! and deterministically driveable by the PTY gate harness.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

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

/// Interactive application state.
///
/// Construct with [`App::new`], feed key events with [`App::on_key`], render
/// from [`crate::ui`]. The event loop stops when [`App::should_quit`] is true.
#[derive(Debug)]
pub struct App {
    screen: Screen,
    should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// A freshly-launched app sitting on the [`Screen::Welcome`] landing screen.
    pub fn new() -> Self {
        Self {
            screen: Screen::Welcome,
            should_quit: false,
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
                KeyCode::Enter => self.screen = Screen::FirstStart,
                _ => {}
            },
            // Sub-screen navigation is filled in by the later M11 workstreams.
            // For now Esc steps back toward Welcome so the scaffold is navigable.
            Screen::FirstStart | Screen::Main => {
                if key.code == KeyCode::Esc {
                    self.screen = Screen::Welcome;
                }
            }
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
}
