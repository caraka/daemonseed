//! The TUI screen state machine.
//!
//! [`App`] holds all interactive state and advances only through
//! [`App::on_key`]. It performs no terminal I/O, so it is fully unit-testable
//! and deterministically driveable by the PTY gate harness.

use daemonseed_core::first_start::SessionMaterials;
use daemonseed_core::profile::config::ArgonParams;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::screens::first_start::{FirstStartOutcome, FirstStartUi};

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
                            self.session = fs.take_completed();
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
            // The main view's tabs are filled in by the later M11 workstreams.
            Screen::Main => {
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
    }

    #[test]
    fn cancelling_first_start_returns_to_welcome() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Enter)); // → FirstStart
        app.on_key(press(KeyCode::Esc)); // cancel
        assert_eq!(app.screen(), &Screen::Welcome);
        assert!(app.first_start().is_none());
    }
}
