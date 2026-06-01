//! First-start flow component (ISC-C29 family).
//!
//! Drives the core type-state machine
//! [`daemonseed_core::first_start::orchestrator::FirstStart`] through the cold
//! first-start: passphrase (with a live C12 strength meter) → 24-word mnemonic
//! display → backup verification (re-type round-trip C33, or a 3-word type-back
//! fallback C34) → adj-noun display name (C4b) → bootstrap relay (C37) →
//! [`SessionMaterials`]. No network connection happens until the flow completes
//! (A-C15 is structural: the connect path only receives `SessionMaterials`,
//! which only [`FirstStartUi::take_completed`] produces).
//!
//! The component is terminal-free: state advances only through
//! [`FirstStartUi::on_key`], so the PTY gate harness can drive it
//! deterministically and the transitions are unit-testable.
//!
//! A second entry path, [`FirstStartUi::new_recovery`], drives clean-device
//! recovery (gate step 8 / ISC-A-C2): the user supplies a mnemonic they already
//! hold — typed 24 words or an `identity.dseed` file — plus the passphrase, and
//! the core [`FirstStart::recover`] re-derives the *same* identity on this
//! device. The recover steps converge on the shared display-name → bootstrap
//! tail, so completion is byte-for-byte identical to cold enrollment.

use daemonseed_core::bootstrap::{BootstrapAnchor, bundled};
use daemonseed_core::first_start::{
    BackupVerified, FirstStart, Sealed, SessionMaterials, TypeBackChallenge, Welcome,
};
use daemonseed_core::handle::display_name::{OsRng, generate_display_name, is_valid_display_name};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::passphrase::strength::{Strength, estimate};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::storage::recovery_file;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

/// Which step of the first-start flow is on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsStep {
    /// Choose a session passphrase; a live strength meter gates advance (C12).
    Passphrase,
    /// Display the generated 24-word mnemonic for the user to write down (C31).
    ShowMnemonic,
    /// Re-type the full phrase (round-trip verify, C33).
    VerifyRoundTrip,
    /// Answer a 3-word type-back challenge (skip-recovery fallback, C34).
    VerifyTypeBack,
    /// Choose a display name; defaults to a generated adj-noun handle (C4b).
    DisplayName,
    /// Choose / confirm the bootstrap relay (C37).
    Bootstrap,
    /// Recovery entry: choose typed-mnemonic or `.dseed`-file input (step 8).
    RecoverChoose,
    /// Recovery: type the 24-word mnemonic.
    RecoverMnemonic,
    /// Recovery: enter the filesystem path to an `identity.dseed` file.
    RecoverDseedPath,
    /// Recovery: enter the passphrase — the new local seal credential, which
    /// on the `.dseed` path is also the credential that opens the file (C30).
    RecoverPassphrase,
    /// Flow complete — `SessionMaterials` are ready for the connect path.
    Complete,
}

/// The consuming type-state machine, held between event-loop iterations.
///
/// Each phase is a distinct type, so the machine lives behind an enum that
/// [`Option::take`] lets us advance across the borrow boundary of `on_key`.
enum Phase {
    Welcome(FirstStart<Welcome>),
    Sealed(FirstStart<Sealed>),
    Verified(FirstStart<BackupVerified>),
}

/// Where a recovery's mnemonic comes from. Both variants converge on a phrase
/// string fed to [`FirstStart::recover`], keeping the core flow source-agnostic.
enum RecoverSource {
    /// 24 words typed directly by the user.
    Typed(String),
    /// Path to an `identity.dseed` file, decrypted with the passphrase.
    Dseed(String),
}

/// Outcome of feeding a key to the first-start flow.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstStartOutcome {
    /// The flow completed; the caller takes [`SessionMaterials`] via
    /// [`FirstStartUi::take_completed`] and proceeds to connect.
    Completed,
    /// The user backed out of first-start (Esc on the first step).
    Cancelled,
}

/// Interactive first-start state.
pub struct FirstStartUi {
    step: FsStep,
    phase: Option<Phase>,
    argon: ArgonParams,
    /// Current text field buffer (passphrase, re-typed phrase, name, address).
    input: String,
    /// Live strength estimate while typing the passphrase.
    strength: Option<Strength>,
    /// The generated mnemonic phrase — shown on [`FsStep::ShowMnemonic`] and
    /// echoed for the round-trip prompt. Cleared once backup is verified.
    mnemonic: Option<String>,
    /// Active type-back challenge (positions to answer), when on
    /// [`FsStep::VerifyTypeBack`].
    challenge: Option<TypeBackChallenge>,
    /// Default adj-noun display name, prefilled on [`FsStep::DisplayName`].
    name_default: String,
    /// The display name the user settled on (None → floor handle, C4b).
    chosen_name: Option<String>,
    /// Last error message to surface (weak passphrase, mismatch, etc.).
    error: Option<String>,
    /// Completed session materials, taken by the caller after `Complete`.
    materials: Option<SessionMaterials>,
    /// The chosen recovery input source, set on the recover flow only.
    recover_source: Option<RecoverSource>,
}

impl FirstStartUi {
    /// Start a fresh first-start flow.
    ///
    /// `argon` is injected so production uses [`ArgonParams::desktop_default`]
    /// while tests pass fast params. The oxicrypt module must already be
    /// initialized (the binary does this at startup).
    pub fn new(argon: ArgonParams) -> Self {
        Self {
            step: FsStep::Passphrase,
            phase: Some(Phase::Welcome(FirstStart::<Welcome>::new())),
            argon,
            input: String::new(),
            strength: None,
            mnemonic: None,
            challenge: None,
            name_default: generate_display_name(&mut OsRng),
            chosen_name: None,
            error: None,
            materials: None,
            recover_source: None,
        }
    }

    /// Start a clean-device recovery flow (gate step 8 / ISC-A-C2).
    ///
    /// Unlike [`Self::new`], which generates a fresh identity, this drives the
    /// user through supplying a mnemonic they already hold — typed 24 words or
    /// an `identity.dseed` file — plus the passphrase, then re-derives the same
    /// identity on this device via [`FirstStart::recover`]. It rejoins the
    /// shared display-name → bootstrap → [`SessionMaterials`] tail, so the
    /// caller's completion path is identical to cold enrollment.
    pub fn new_recovery(argon: ArgonParams) -> Self {
        Self {
            step: FsStep::RecoverChoose,
            phase: Some(Phase::Welcome(FirstStart::<Welcome>::new())),
            argon,
            input: String::new(),
            strength: None,
            mnemonic: None,
            challenge: None,
            name_default: generate_display_name(&mut OsRng),
            chosen_name: None,
            error: None,
            materials: None,
            recover_source: None,
        }
    }

    /// The step currently on screen.
    pub fn step(&self) -> FsStep {
        self.step
    }

    /// The current text-input buffer (for rendering the active field).
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Live passphrase strength, when on the passphrase step.
    pub fn strength(&self) -> Option<&Strength> {
        self.strength.as_ref()
    }

    /// The generated mnemonic phrase, when it should be shown.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// The active type-back challenge positions (1-based word indices), if any.
    pub fn challenge_positions(&self) -> Option<Vec<usize>> {
        self.challenge.as_ref().map(|c| c.positions().to_vec())
    }

    /// The prefilled default display name.
    pub fn name_default(&self) -> &str {
        &self.name_default
    }

    /// Last error to surface to the user, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Whether the passphrase currently meets the C12 session floor.
    pub fn passphrase_is_green(&self) -> bool {
        self.strength
            .as_ref()
            .is_some_and(Strength::is_session_green)
    }

    /// Take the completed materials once the flow reached [`FsStep::Complete`].
    pub fn take_completed(&mut self) -> Option<SessionMaterials> {
        self.materials.take()
    }

    /// Advance the flow in response to a key press. Returns `Some` when the
    /// flow terminates (completed or cancelled).
    ///
    /// Esc aborts the whole flow from any step (returns
    /// [`FirstStartOutcome::Cancelled`]); the in-memory sealed state is dropped.
    pub fn on_key(&mut self, key: KeyEvent) -> Option<FirstStartOutcome> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        if key.code == KeyCode::Esc {
            return Some(FirstStartOutcome::Cancelled);
        }
        match self.step {
            FsStep::Passphrase => self.on_passphrase(key.code),
            FsStep::ShowMnemonic => self.on_show_mnemonic(key.code),
            FsStep::VerifyRoundTrip => self.on_verify_round_trip(key.code),
            FsStep::VerifyTypeBack => self.on_verify_type_back(key.code),
            FsStep::DisplayName => self.on_display_name(key.code),
            FsStep::Bootstrap => self.on_bootstrap(key.code),
            FsStep::RecoverChoose => self.on_recover_choose(key.code),
            FsStep::RecoverMnemonic => self.on_recover_mnemonic(key.code),
            FsStep::RecoverDseedPath => self.on_recover_dseed_path(key.code),
            FsStep::RecoverPassphrase => self.on_recover_passphrase(key.code),
            FsStep::Complete => None,
        }
    }

    /// Apply a text-editing key to [`Self::input`]; returns true if handled.
    /// Editing clears any stale error so it doesn't linger past a correction.
    fn edit_input(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char(c) => {
                self.input.push(c);
                self.error = None;
                true
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.error = None;
                true
            }
            _ => false,
        }
    }

    fn on_passphrase(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            self.strength = (!self.input.is_empty()).then(|| estimate(&self.input));
            return None;
        }
        if code == KeyCode::Enter {
            if !self.passphrase_is_green() {
                self.error = Some("passphrase too weak — add more words".to_owned());
                return None;
            }
            // Take the Welcome phase and seal. On the (unreachable-if-green)
            // error path, surface it and stay.
            let Some(Phase::Welcome(fs)) = self.phase.take() else {
                self.error = Some("internal: first-start phase lost".to_owned());
                return None;
            };
            match fs.initialize(&self.input, self.argon) {
                Ok(sealed) => {
                    self.mnemonic = Some(sealed.display_phrase());
                    self.phase = Some(Phase::Sealed(sealed));
                    self.input.clear();
                    self.strength = None;
                    self.error = None;
                    self.step = FsStep::ShowMnemonic;
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        None
    }

    fn on_show_mnemonic(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        match code {
            KeyCode::Enter => {
                self.input.clear();
                self.error = None;
                self.step = FsStep::VerifyRoundTrip;
            }
            KeyCode::Char('s') => {
                // Skip-recovery path: issue a 3-word type-back challenge.
                if let Some(Phase::Sealed(s)) = &self.phase {
                    self.challenge = Some(s.issue_type_back_challenge(&mut OsRng));
                    self.input.clear();
                    self.error = None;
                    self.step = FsStep::VerifyTypeBack;
                }
            }
            _ => {}
        }
        None
    }

    fn on_verify_round_trip(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code == KeyCode::Enter {
            // Local pre-check against the held mnemonic. The core
            // `verify_round_trip` CONSUMES the Sealed state, dropping it on
            // mismatch — so we only invoke it once a normalized compare proves
            // it will succeed. Otherwise a mistyped phrase would destroy the
            // session and force restarting the whole first-start.
            let matches = self
                .mnemonic
                .as_deref()
                .is_some_and(|m| norm_words(m) == norm_words(&self.input));
            if !matches {
                self.error = Some("phrase does not match — try again".to_owned());
                return None;
            }
            let Some(Phase::Sealed(s)) = self.phase.take() else {
                self.error = Some("internal: sealed phase lost".to_owned());
                return None;
            };
            match s.verify_round_trip(&self.input) {
                Ok(v) => self.enter_display_name(v),
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        None
    }

    fn on_verify_type_back(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code == KeyCode::Enter {
            // Same consuming-API guard as round-trip: compute the expected
            // answers from the held mnemonic + challenge positions and only
            // invoke the consuming `verify_type_back` when they match.
            let answers: Vec<String> = self.input.split_whitespace().map(str::to_owned).collect();
            let expected: Option<Vec<String>> = self.mnemonic.as_deref().and_then(|m| {
                let words: Vec<&str> = m.split_whitespace().collect();
                self.challenge
                    .as_ref()
                    .map(|c| c.positions().iter().map(|p| words[*p].to_owned()).collect())
            });
            let ok = expected.is_some_and(|exp| {
                exp.len() == answers.len()
                    && exp
                        .iter()
                        .zip(&answers)
                        .all(|(e, a)| e.eq_ignore_ascii_case(a))
            });
            if !ok {
                self.error = Some("type-back answers incorrect — try again".to_owned());
                return None;
            }
            let (Some(Phase::Sealed(s)), Some(challenge)) =
                (self.phase.take(), self.challenge.take())
            else {
                self.error = Some("internal: sealed phase or challenge lost".to_owned());
                return None;
            };
            match s.verify_type_back(challenge, &answers) {
                Ok(v) => self.enter_display_name(v),
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        None
    }

    fn on_display_name(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code == KeyCode::Enter {
            let trimmed = self.input.trim();
            let chosen = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
            // Pre-validate so we don't consume the verified phase on a bad name
            // (finalize consumes self on the InvalidDisplayName error path).
            if let Some(name) = chosen.as_deref()
                && !is_valid_display_name(name)
            {
                self.error = Some("invalid name — no '#', not empty, within length".to_owned());
                return None;
            }
            self.chosen_name = chosen;
            self.error = None;
            // Prefill the bootstrap field with the bundled canonical anchor if
            // present, in `<server-id>@<host:port>` form.
            self.input = bundled()
                .canonical
                .as_ref()
                .map(|a| format!("{}@{}", a.server_id, a.address))
                .unwrap_or_default();
            self.step = FsStep::Bootstrap;
        }
        None
    }

    fn on_bootstrap(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code == KeyCode::Enter {
            let anchor = match parse_anchor(&self.input) {
                Some(a) => a,
                None => {
                    self.error = Some("bootstrap format: <server-id>@<host:port>".to_owned());
                    return None;
                }
            };
            let Some(Phase::Verified(v)) = self.phase.take() else {
                self.error = Some("internal: verified phase lost".to_owned());
                return None;
            };
            match v.finalize(self.chosen_name.clone(), anchor) {
                Ok(ready) => {
                    self.materials = Some(ready.into_session_materials());
                    self.error = None;
                    self.step = FsStep::Complete;
                    return Some(FirstStartOutcome::Completed);
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        None
    }

    // ── recovery flow (gate step 8) ────────────────────────────────────────

    /// Pick the recovery input method: `m` types a mnemonic, `f` loads a
    /// `.dseed` file. Esc (handled in `on_key`) cancels back to Welcome.
    fn on_recover_choose(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        match code {
            KeyCode::Char('m') | KeyCode::Char('M') => {
                self.input.clear();
                self.error = None;
                self.step = FsStep::RecoverMnemonic;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                self.input.clear();
                self.error = None;
                self.step = FsStep::RecoverDseedPath;
            }
            _ => {}
        }
        None
    }

    /// Accept a typed 24-word phrase. The BIP-39 checksum is validated here for
    /// immediate feedback; the authoritative re-check happens in `recover` once
    /// the passphrase is supplied.
    fn on_recover_mnemonic(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code == KeyCode::Enter {
            if let Err(e) = Mnemonic::from_phrase(self.input.trim()) {
                self.error = Some(format!("invalid phrase: {e}"));
                return None;
            }
            self.recover_source = Some(RecoverSource::Typed(self.input.trim().to_owned()));
            self.input.clear();
            self.error = None;
            self.step = FsStep::RecoverPassphrase;
        }
        None
    }

    /// Accept a filesystem path to an `identity.dseed`. The file is not read
    /// until the passphrase step (decryption needs the passphrase).
    fn on_recover_dseed_path(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code == KeyCode::Enter {
            let path = self.input.trim();
            if path.is_empty() {
                self.error = Some("enter the path to an identity.dseed file".to_owned());
                return None;
            }
            self.recover_source = Some(RecoverSource::Dseed(path.to_owned()));
            self.input.clear();
            self.error = None;
            self.step = FsStep::RecoverPassphrase;
        }
        None
    }

    /// Resolve the recovery phrase from the chosen source and re-derive the
    /// identity. On the `.dseed` path the passphrase first opens the file; on
    /// either path it then seals the fresh local artifacts. A fresh `Welcome`
    /// is used per attempt, so a wrong passphrase costs nothing but a retry.
    fn on_recover_passphrase(&mut self, code: KeyCode) -> Option<FirstStartOutcome> {
        if self.edit_input(code) {
            return None;
        }
        if code != KeyCode::Enter {
            return None;
        }
        let phrase = match self.recover_source.as_ref() {
            Some(RecoverSource::Typed(p)) => p.clone(),
            Some(RecoverSource::Dseed(path)) => {
                let bytes = match std::fs::read(path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.error = Some(format!("cannot read .dseed: {e}"));
                        return None;
                    }
                };
                match recovery_file::open(&bytes, &self.input) {
                    Ok(contents) => contents.mnemonic.to_phrase(),
                    Err(e) => {
                        self.error = Some(format!(".dseed: {e}"));
                        return None;
                    }
                }
            }
            None => {
                self.error = Some("internal: recovery source lost".to_owned());
                return None;
            }
        };
        let Some(Phase::Welcome(fs)) = self.phase.take() else {
            self.error = Some("internal: first-start phase lost".to_owned());
            return None;
        };
        match fs.recover(&phrase, &self.input, self.argon) {
            Ok(v) => self.enter_display_name(v),
            Err(e) => {
                // Re-seat a fresh Welcome so the user can correct and retry.
                self.phase = Some(Phase::Welcome(FirstStart::<Welcome>::new()));
                self.error = Some(e.to_string());
            }
        }
        None
    }

    /// Common transition into the display-name step: stash the verified phase,
    /// drop the now-unneeded mnemonic, and prefill the adj-noun default.
    fn enter_display_name(&mut self, verified: FirstStart<BackupVerified>) {
        self.phase = Some(Phase::Verified(verified));
        self.mnemonic = None;
        self.challenge = None;
        self.input = self.name_default.clone();
        self.error = None;
        self.step = FsStep::DisplayName;
    }
}

/// Normalize a mnemonic phrase to a word vector for comparison: split on
/// whitespace, lowercase each word. Mirrors the core orchestrator's private
/// `phrases_match` so the TUI's pre-check agrees with the authoritative verify.
fn norm_words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_lowercase).collect()
}

/// Parse a `<server-id>@<host:port>` bootstrap string into a [`BootstrapAnchor`].
/// Returns `None` when either side is empty or the `@` separator is missing.
fn parse_anchor(s: &str) -> Option<BootstrapAnchor> {
    let (server_id, address) = s.trim().split_once('@')?;
    if server_id.is_empty() || address.is_empty() {
        return None;
    }
    Some(BootstrapAnchor {
        server_id: server_id.to_owned(),
        address: address.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;

    fn fast_argon() -> ArgonParams {
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn ui() -> FirstStartUi {
        let _ = oxicrypt_module::initialize();
        FirstStartUi::new(fast_argon())
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_str(ui: &mut FirstStartUi, s: &str) {
        for ch in s.chars() {
            ui.on_key(press(KeyCode::Char(ch)));
        }
    }

    const STRONG: &str = "correct horse battery staple table mountain";

    #[test]
    fn starts_on_passphrase_step() {
        let ui = ui();
        assert_eq!(ui.step(), FsStep::Passphrase);
    }

    #[test]
    fn typing_updates_strength_and_input() {
        let mut ui = ui();
        type_str(&mut ui, STRONG);
        assert_eq!(ui.input(), STRONG);
        assert!(ui.strength().is_some());
        assert!(
            ui.passphrase_is_green(),
            "{STRONG:?} should clear the floor"
        );
    }

    #[test]
    fn weak_passphrase_does_not_advance() {
        let mut ui = ui();
        type_str(&mut ui, "password");
        ui.on_key(press(KeyCode::Enter));
        assert_eq!(
            ui.step(),
            FsStep::Passphrase,
            "weak passphrase must not advance"
        );
        assert!(ui.error().is_some(), "should surface a too-weak error");
    }

    #[test]
    fn strong_passphrase_advances_to_mnemonic() {
        let mut ui = ui();
        type_str(&mut ui, STRONG);
        ui.on_key(press(KeyCode::Enter));
        assert_eq!(ui.step(), FsStep::ShowMnemonic);
        let phrase = ui.mnemonic().expect("mnemonic shown");
        assert_eq!(
            phrase.split_whitespace().count(),
            24,
            "BIP-39 24-word phrase"
        );
    }

    #[test]
    fn round_trip_mismatch_shows_error_and_stays() {
        let mut ui = ui();
        type_str(&mut ui, STRONG);
        ui.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        ui.on_key(press(KeyCode::Enter)); // → VerifyRoundTrip
        assert_eq!(ui.step(), FsStep::VerifyRoundTrip);
        type_str(
            &mut ui,
            "wrong words that are not the phrase at all here ok",
        );
        ui.on_key(press(KeyCode::Enter));
        assert_eq!(
            ui.step(),
            FsStep::VerifyRoundTrip,
            "mismatch must not advance"
        );
        assert!(ui.error().is_some());
    }

    #[test]
    fn full_round_trip_happy_path_completes() {
        let mut ui = ui();
        type_str(&mut ui, STRONG);
        ui.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = ui.mnemonic().expect("mnemonic").to_string();
        ui.on_key(press(KeyCode::Enter)); // → VerifyRoundTrip
        type_str(&mut ui, &phrase);
        ui.on_key(press(KeyCode::Enter)); // → DisplayName
        assert_eq!(ui.step(), FsStep::DisplayName);
        assert!(!ui.name_default().is_empty(), "adj-noun default prefilled");
        ui.on_key(press(KeyCode::Enter)); // accept default name → Bootstrap
        assert_eq!(ui.step(), FsStep::Bootstrap);
        // Provide an explicit bootstrap address (bundled anchor is empty in this build).
        type_str(&mut ui, "relay#aabbccddeeff@127.0.0.1:443");
        let outcome = ui.on_key(press(KeyCode::Enter));
        assert_eq!(outcome, Some(FirstStartOutcome::Completed));
        assert_eq!(ui.step(), FsStep::Complete);
        let materials = ui.take_completed().expect("materials ready");
        assert!(!materials.at_rest_blob_bytes.is_empty());
        assert!(!materials.recovery_file_bytes.is_empty());
    }

    #[test]
    fn esc_on_passphrase_cancels() {
        let mut ui = ui();
        let outcome = ui.on_key(press(KeyCode::Esc));
        assert_eq!(outcome, Some(FirstStartOutcome::Cancelled));
    }

    #[test]
    fn type_back_fallback_completes() {
        let mut ui = ui();
        type_str(&mut ui, STRONG);
        ui.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = ui.mnemonic().expect("mnemonic").to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        // 's' chooses the skip/type-back path.
        ui.on_key(press(KeyCode::Char('s')));
        assert_eq!(ui.step(), FsStep::VerifyTypeBack);
        let positions = ui.challenge_positions().expect("challenge issued");
        // Answer each asked position (positions are 0-based word indices).
        for (i, pos) in positions.iter().enumerate() {
            if i > 0 {
                ui.on_key(press(KeyCode::Char(' ')));
            }
            type_str(&mut ui, words[*pos]);
        }
        ui.on_key(press(KeyCode::Enter)); // → DisplayName
        assert_eq!(ui.step(), FsStep::DisplayName);
    }

    // ── recovery flow (gate step 8) ────────────────────────────────────────

    /// Drive a full cold enrollment and return its materials + the 24-word
    /// phrase shown — the "original device" the recovery tests reconstruct.
    fn enroll() -> (SessionMaterials, String) {
        let mut ui = ui();
        type_str(&mut ui, STRONG);
        ui.on_key(press(KeyCode::Enter)); // → ShowMnemonic
        let phrase = ui.mnemonic().expect("mnemonic").to_string();
        ui.on_key(press(KeyCode::Enter)); // → VerifyRoundTrip
        type_str(&mut ui, &phrase);
        ui.on_key(press(KeyCode::Enter)); // → DisplayName (default prefilled)
        ui.on_key(press(KeyCode::Enter)); // accept default → Bootstrap
        type_str(&mut ui, "relay#aabbccddeeff@127.0.0.1:443");
        ui.on_key(press(KeyCode::Enter)); // → Completed
        let m = ui.take_completed().expect("materials");
        (m, phrase)
    }

    /// Drive a recover UI sitting on DisplayName through to Completed, accepting
    /// the default name and a fixed bootstrap. Returns the recovered materials.
    fn finish_after_verify(ui: &mut FirstStartUi) -> SessionMaterials {
        assert_eq!(ui.step(), FsStep::DisplayName);
        ui.on_key(press(KeyCode::Enter)); // accept default name → Bootstrap
        type_str(ui, "relay#aabbccddeeff@127.0.0.1:443");
        let outcome = ui.on_key(press(KeyCode::Enter));
        assert_eq!(outcome, Some(FirstStartOutcome::Completed));
        ui.take_completed().expect("materials")
    }

    #[test]
    fn new_recovery_starts_on_recover_choose() {
        let _ = oxicrypt_module::initialize();
        let ui = FirstStartUi::new_recovery(fast_argon());
        assert_eq!(ui.step(), FsStep::RecoverChoose);
    }

    #[test]
    fn recover_choose_routes_to_both_inputs() {
        let _ = oxicrypt_module::initialize();
        let mut ui = FirstStartUi::new_recovery(fast_argon());
        ui.on_key(press(KeyCode::Char('m')));
        assert_eq!(ui.step(), FsStep::RecoverMnemonic);
        let mut ui = FirstStartUi::new_recovery(fast_argon());
        ui.on_key(press(KeyCode::Char('f')));
        assert_eq!(ui.step(), FsStep::RecoverDseedPath);
    }

    #[test]
    fn recover_typed_invalid_mnemonic_stays() {
        let _ = oxicrypt_module::initialize();
        let mut ui = FirstStartUi::new_recovery(fast_argon());
        ui.on_key(press(KeyCode::Char('m')));
        type_str(&mut ui, "abandon abandon abandon"); // bad word count / checksum
        ui.on_key(press(KeyCode::Enter));
        assert_eq!(
            ui.step(),
            FsStep::RecoverMnemonic,
            "bad phrase must not advance"
        );
        assert!(ui.error().is_some());
    }

    #[test]
    fn recover_typed_happy_path_matches_identity() {
        let (enrolled, phrase) = enroll();
        let mut ui = FirstStartUi::new_recovery(fast_argon());
        ui.on_key(press(KeyCode::Char('m')));
        type_str(&mut ui, &phrase);
        ui.on_key(press(KeyCode::Enter)); // → RecoverPassphrase
        assert_eq!(ui.step(), FsStep::RecoverPassphrase);
        type_str(&mut ui, STRONG);
        ui.on_key(press(KeyCode::Enter)); // recover → DisplayName
        let recovered = finish_after_verify(&mut ui);
        assert_eq!(
            recovered.handle.hash_prefix(),
            enrolled.handle.hash_prefix(),
            "typed recovery reaches the same identity"
        );
        assert!(!recovered.at_rest_blob_bytes.is_empty());
    }

    #[test]
    fn recover_dseed_happy_path_matches_identity() {
        let (enrolled, _phrase) = enroll();
        let path = std::env::temp_dir().join("ds-tui-recover-dseed-happy.dseed");
        std::fs::write(&path, &enrolled.recovery_file_bytes).unwrap();

        let mut ui = FirstStartUi::new_recovery(fast_argon());
        ui.on_key(press(KeyCode::Char('f')));
        type_str(&mut ui, path.to_str().unwrap());
        ui.on_key(press(KeyCode::Enter)); // → RecoverPassphrase
        assert_eq!(ui.step(), FsStep::RecoverPassphrase);
        type_str(&mut ui, STRONG); // the passphrase that sealed the .dseed
        ui.on_key(press(KeyCode::Enter)); // open + recover → DisplayName
        let recovered = finish_after_verify(&mut ui);

        let _ = std::fs::remove_file(&path);
        assert_eq!(
            recovered.handle.hash_prefix(),
            enrolled.handle.hash_prefix(),
            ".dseed recovery reaches the same identity"
        );
    }

    #[test]
    fn recover_dseed_wrong_passphrase_stays() {
        let (enrolled, _phrase) = enroll();
        let path = std::env::temp_dir().join("ds-tui-recover-dseed-wrong.dseed");
        std::fs::write(&path, &enrolled.recovery_file_bytes).unwrap();

        let mut ui = FirstStartUi::new_recovery(fast_argon());
        ui.on_key(press(KeyCode::Char('f')));
        type_str(&mut ui, path.to_str().unwrap());
        ui.on_key(press(KeyCode::Enter)); // → RecoverPassphrase
        type_str(&mut ui, "wrong horse battery staple table mountain");
        ui.on_key(press(KeyCode::Enter)); // open fails closed → stay

        let _ = std::fs::remove_file(&path);
        assert_eq!(
            ui.step(),
            FsStep::RecoverPassphrase,
            "wrong .dseed passphrase must not advance"
        );
        assert!(ui.error().is_some());
    }
}
